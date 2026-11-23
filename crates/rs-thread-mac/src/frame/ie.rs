//! Information Elements (IEEE 802.15.4-2015 section 7.4).
//!
//! Header IE: 16-bit little-endian descriptor, bits 0..6 content length,
//! bits 7..14 element ID, bit 15 type (0). Payload IE: bits 0..10 length,
//! bits 11..14 group ID, bit 15 type (1).

use rs_thread_core::bytes::{Reader, Writer};
use rs_thread_core::{Error, Result};

/// Element ID of the Vendor Specific header IE.
pub const IE_ID_VENDOR: u8 = 0x00;
/// Element ID of the CSL header IE.
pub const IE_ID_CSL: u8 = 0x1a;
/// Element ID of the Rendezvous Time header IE.
pub const IE_ID_RENDEZVOUS_TIME: u8 = 0x1d;
/// Element ID of Header Termination 1 (payload IEs follow).
pub const IE_ID_HEADER_TERMINATION_1: u8 = 0x7e;
/// Element ID of Header Termination 2 (payload follows, no payload IEs).
pub const IE_ID_HEADER_TERMINATION_2: u8 = 0x7f;

/// Thread Group vendor OUI (`0xeab89b`) used in Vendor Specific IEs.
pub const THREAD_OUI: u32 = 0xea_b8_9b;
/// Thread vendor IE sub-type: Enhanced-ACK probing (link metrics).
pub const THREAD_IE_ENH_ACK_PROBING: u8 = 0x00;
/// Thread vendor IE sub-type: Connection IE (wake-up frames).
pub const THREAD_IE_CONNECTION: u8 = 0x01;
/// Nest vendor OUI (`0x18b430`) used by the OpenThread Time IE.
pub const NEST_OUI: u32 = 0x18_b4_30;
/// Nest vendor IE sub-type: Time IE (time sync).
pub const NEST_IE_TIME: u8 = 0x01;

/// A raw header IE: element ID and content bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct HeaderIe<'a> {
    /// Element ID.
    pub id: u8,
    /// Content (without the 2-byte descriptor).
    pub content: &'a [u8],
}

impl<'a> HeaderIe<'a> {
    /// Parse one header IE from `r`. A descriptor with the type bit set is
    /// a payload IE and rejected.
    pub fn parse(r: &mut Reader<'a>) -> Result<Self> {
        let d = r.read_u16_le()?;
        if d & 0x8000 != 0 {
            return Err(Error::Parse);
        }
        let len = usize::from(d & 0x7f);
        Ok(Self {
            id: ((d >> 7) & 0xff) as u8,
            content: r.read_slice(len)?,
        })
    }

    /// `true` for Header Termination 1 or 2.
    pub const fn is_termination(&self) -> bool {
        self.id == IE_ID_HEADER_TERMINATION_1 || self.id == IE_ID_HEADER_TERMINATION_2
    }

    /// Encoded size (descriptor + content).
    pub const fn encoded_len(&self) -> usize {
        2 + self.content.len()
    }

    /// Write descriptor and content. [`Error::InvalidArgs`] if the content
    /// exceeds 127 bytes.
    pub fn write(&self, w: &mut Writer<'_>) -> Result<()> {
        write_descriptor(w, self.id, self.content.len())?;
        w.write_slice(self.content)
    }

    /// Typed view as a CSL IE (`None` if another IE or malformed).
    pub fn csl(&self) -> Option<CslIe> {
        (self.id == IE_ID_CSL)
            .then(|| CslIe::parse_content(self.content).ok())
            .flatten()
    }

    /// Typed view as a Rendezvous Time IE.
    pub fn rendezvous_time(&self) -> Option<RendezvousTimeIe> {
        (self.id == IE_ID_RENDEZVOUS_TIME)
            .then(|| RendezvousTimeIe::parse_content(self.content).ok())
            .flatten()
    }

    /// Typed view as a Vendor Specific IE.
    pub fn vendor(&self) -> Option<VendorIe<'a>> {
        (self.id == IE_ID_VENDOR)
            .then(|| VendorIe::parse_content(self.content).ok())
            .flatten()
    }

    /// Typed view as the Thread Connection IE.
    pub fn connection(&self) -> Option<ConnectionIe> {
        self.vendor().and_then(|v| ConnectionIe::from_vendor(&v))
    }

    /// Typed view as the Nest Time IE.
    pub fn time(&self) -> Option<TimeIe> {
        self.vendor().and_then(|v| TimeIe::from_vendor(&v))
    }
}

fn write_descriptor(w: &mut Writer<'_>, id: u8, len: usize) -> Result<()> {
    if len > 0x7f {
        return Err(Error::InvalidArgs);
    }
    w.write_u16_le((u16::from(id) << 7) | len as u16)
}

/// Iterator over the header IEs in a byte region. Yields `Err` once and
/// stops if the region is malformed.
#[derive(Debug, Clone)]
pub struct HeaderIeIter<'a> {
    r: Reader<'a>,
}

impl<'a> HeaderIeIter<'a> {
    /// Iterate over IEs encoded back to back in `bytes`.
    pub fn new(bytes: &'a [u8]) -> Self {
        Self {
            r: Reader::new(bytes),
        }
    }
}

impl<'a> Iterator for HeaderIeIter<'a> {
    type Item = Result<HeaderIe<'a>>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.r.is_empty() {
            return None;
        }
        let item = HeaderIe::parse(&mut self.r);
        if item.is_err() {
            self.r.read_rest();
        }
        Some(item)
    }
}

/// CSL IE content (802.15.4-2015 7.4.2.3): phase and period in units of
/// 10 symbols, optionally followed by a rendezvous time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct CslIe {
    /// CSL phase (10-symbol units).
    pub phase: u16,
    /// CSL period (10-symbol units).
    pub period: u16,
    /// Rendezvous time, if present (6-byte form).
    pub rendezvous_time: Option<u16>,
}

impl CslIe {
    /// Parse the content (4 or 6 bytes).
    pub fn parse_content(content: &[u8]) -> Result<Self> {
        let mut r = Reader::new(content);
        let phase = r.read_u16_le()?;
        let period = r.read_u16_le()?;
        let rendezvous_time = match r.remaining() {
            0 => None,
            2 => Some(r.read_u16_le()?),
            _ => return Err(Error::Parse),
        };
        Ok(Self {
            phase,
            period,
            rendezvous_time,
        })
    }

    /// Content length in bytes.
    pub const fn content_len(&self) -> usize {
        if self.rendezvous_time.is_some() { 6 } else { 4 }
    }

    fn write_content(&self, w: &mut Writer<'_>) -> Result<()> {
        w.write_u16_le(self.phase)?;
        w.write_u16_le(self.period)?;
        match self.rendezvous_time {
            Some(t) => w.write_u16_le(t),
            None => Ok(()),
        }
    }
}

/// Rendezvous Time IE content as used by Thread (10-symbol units; the
/// optional wake-up interval is not used).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct RendezvousTimeIe {
    /// Rendezvous time (10-symbol units).
    pub rendezvous_time: u16,
}

impl RendezvousTimeIe {
    /// Parse the 2-byte content.
    pub fn parse_content(content: &[u8]) -> Result<Self> {
        let mut r = Reader::new(content);
        let rendezvous_time = r.read_u16_le()?;
        if !r.is_empty() {
            return Err(Error::Parse);
        }
        Ok(Self { rendezvous_time })
    }
}

/// Vendor Specific IE content: 3-byte OUI (little-endian on air), a
/// vendor sub-type byte (as used by all Thread / OpenThread vendor IEs)
/// and vendor data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct VendorIe<'a> {
    /// Vendor OUI.
    pub oui: u32,
    /// Vendor sub-type.
    pub subtype: u8,
    /// Data following the sub-type.
    pub data: &'a [u8],
}

impl<'a> VendorIe<'a> {
    /// Thread Enhanced-ACK probing IE (link metrics data in `data`).
    pub const fn thread_enh_ack_probing(data: &'a [u8]) -> Self {
        Self {
            oui: THREAD_OUI,
            subtype: THREAD_IE_ENH_ACK_PROBING,
            data,
        }
    }

    /// `true` if this is the given Thread sub-type.
    pub const fn is_thread(&self, subtype: u8) -> bool {
        self.oui == THREAD_OUI && self.subtype == subtype
    }

    /// Parse the content (at least 4 bytes).
    pub fn parse_content(content: &'a [u8]) -> Result<Self> {
        let mut r = Reader::new(content);
        let oui = r.read_array::<3>()?;
        Ok(Self {
            oui: u32::from_le_bytes([oui[0], oui[1], oui[2], 0]),
            subtype: r.read_u8()?,
            data: r.read_rest(),
        })
    }

    /// Content length in bytes.
    pub const fn content_len(&self) -> usize {
        4 + self.data.len()
    }

    fn write_content(&self, w: &mut Writer<'_>) -> Result<()> {
        w.write_slice(&self.oui.to_le_bytes()[..3])?;
        w.write_u8(self.subtype)?;
        w.write_slice(self.data)
    }
}

/// Thread Connection IE (Thread 1.4 wake-up frames).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct ConnectionIe {
    /// Retry interval in wake-up intervals (2 bits).
    pub retry_interval: u8,
    /// Retry count (4 bits).
    pub retry_count: u8,
}

impl ConnectionIe {
    /// Interpret a Vendor IE as a Connection IE.
    pub fn from_vendor(v: &VendorIe<'_>) -> Option<Self> {
        if !v.is_thread(THREAD_IE_CONNECTION) || v.data.len() != 1 {
            return None;
        }
        Some(Self {
            retry_interval: (v.data[0] >> 4) & 0x3,
            retry_count: v.data[0] & 0xf,
        })
    }

    const fn window(&self) -> u8 {
        ((self.retry_interval & 0x3) << 4) | (self.retry_count & 0xf)
    }
}

/// OpenThread Time IE (network time synchronization).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct TimeIe {
    /// Time sync sequence.
    pub sequence: u8,
    /// Network time in microseconds.
    pub time: u64,
}

impl TimeIe {
    /// Interpret a Vendor IE as a Time IE.
    pub fn from_vendor(v: &VendorIe<'_>) -> Option<Self> {
        if v.oui != NEST_OUI || v.subtype != NEST_IE_TIME || v.data.len() != 9 {
            return None;
        }
        let mut t = [0u8; 8];
        t.copy_from_slice(&v.data[1..]);
        Some(Self {
            sequence: v.data[0],
            time: u64::from_le_bytes(t),
        })
    }

    const CONTENT_LEN: usize = 4 + 1 + 8;
}

/// A header IE to write with [`FrameBuilder`](super::FrameBuilder).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum HeaderIeValue<'a> {
    /// CSL IE.
    Csl(CslIe),
    /// Rendezvous Time IE.
    RendezvousTime(RendezvousTimeIe),
    /// Generic Vendor Specific IE (e.g. Thread Enh-ACK probing).
    Vendor(VendorIe<'a>),
    /// Thread Connection IE.
    Connection(ConnectionIe),
    /// OpenThread Time IE.
    Time(TimeIe),
    /// Any other IE as raw bytes.
    Raw(HeaderIe<'a>),
    /// Header Termination 1.
    Termination1,
    /// Header Termination 2.
    Termination2,
}

impl HeaderIeValue<'_> {
    /// Element ID.
    pub const fn id(&self) -> u8 {
        match self {
            Self::Csl(_) => IE_ID_CSL,
            Self::RendezvousTime(_) => IE_ID_RENDEZVOUS_TIME,
            Self::Vendor(_) | Self::Connection(_) | Self::Time(_) => IE_ID_VENDOR,
            Self::Raw(r) => r.id,
            Self::Termination1 => IE_ID_HEADER_TERMINATION_1,
            Self::Termination2 => IE_ID_HEADER_TERMINATION_2,
        }
    }

    /// `true` for Header Termination 1/2.
    pub const fn is_termination(&self) -> bool {
        matches!(self, Self::Termination1 | Self::Termination2)
            || matches!(self, Self::Raw(r) if r.is_termination())
    }

    /// Encoded size (descriptor + content).
    pub const fn encoded_len(&self) -> usize {
        2 + match self {
            Self::Csl(c) => c.content_len(),
            Self::RendezvousTime(_) => 2,
            Self::Vendor(v) => v.content_len(),
            Self::Connection(_) => 5,
            Self::Time(_) => TimeIe::CONTENT_LEN,
            Self::Raw(r) => r.content.len(),
            Self::Termination1 | Self::Termination2 => 0,
        }
    }

    /// Write descriptor and content.
    pub fn write(&self, w: &mut Writer<'_>) -> Result<()> {
        write_descriptor(w, self.id(), self.encoded_len() - 2)?;
        match self {
            Self::Csl(c) => c.write_content(w),
            Self::RendezvousTime(t) => w.write_u16_le(t.rendezvous_time),
            Self::Vendor(v) => v.write_content(w),
            Self::Connection(c) => {
                w.write_slice(&THREAD_OUI.to_le_bytes()[..3])?;
                w.write_u8(THREAD_IE_CONNECTION)?;
                w.write_u8(c.window())
            }
            Self::Time(t) => {
                w.write_slice(&NEST_OUI.to_le_bytes()[..3])?;
                w.write_u8(NEST_IE_TIME)?;
                w.write_u8(t.sequence)?;
                w.write_u64_le(t.time)
            }
            Self::Raw(r) => w.write_slice(r.content),
            Self::Termination1 | Self::Termination2 => Ok(()),
        }
    }
}

macro_rules! from_ie {
    ($t:ty, $v:ident) => {
        impl<'a> From<$t> for HeaderIeValue<'a> {
            fn from(v: $t) -> Self {
                Self::$v(v)
            }
        }
    };
}
from_ie!(CslIe, Csl);
from_ie!(RendezvousTimeIe, RendezvousTime);
from_ie!(ConnectionIe, Connection);
from_ie!(TimeIe, Time);
from_ie!(VendorIe<'a>, Vendor);
from_ie!(HeaderIe<'a>, Raw);

/// A raw payload IE.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct PayloadIe<'a> {
    /// Group ID (4 bits); `0xf` is the Payload Termination IE.
    pub group_id: u8,
    /// Content.
    pub content: &'a [u8],
}

/// Group ID of the Payload Termination IE.
pub const PAYLOAD_IE_GROUP_TERMINATION: u8 = 0xf;

/// Iterator over payload IEs in a byte region (e.g. the frame payload after
/// Header Termination 1, once decrypted). Stops after the termination IE;
/// the remaining bytes are available from [`PayloadIeIter::rest`].
#[derive(Debug, Clone)]
pub struct PayloadIeIter<'a> {
    r: Reader<'a>,
    done: bool,
}

impl<'a> PayloadIeIter<'a> {
    /// Iterate over payload IEs starting at the beginning of `bytes`.
    pub fn new(bytes: &'a [u8]) -> Self {
        Self {
            r: Reader::new(bytes),
            done: false,
        }
    }

    /// Bytes not consumed yet (the MAC payload after the termination IE).
    pub fn rest(&self) -> &'a [u8] {
        self.r.rest()
    }
}

impl<'a> Iterator for PayloadIeIter<'a> {
    type Item = Result<PayloadIe<'a>>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done || self.r.is_empty() {
            return None;
        }
        let res = (|| {
            let d = self.r.read_u16_le()?;
            if d & 0x8000 == 0 {
                return Err(Error::Parse);
            }
            Ok(PayloadIe {
                group_id: ((d >> 11) & 0xf) as u8,
                content: self.r.read_slice(usize::from(d & 0x7ff))?,
            })
        })();
        match res {
            Ok(ie) if ie.group_id == PAYLOAD_IE_GROUP_TERMINATION => self.done = true,
            Err(_) => self.done = true,
            _ => {}
        }
        Some(res)
    }
}
