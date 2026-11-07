//! Frame Control Field, addressing modes and addresses.

use opentrust_core::bytes::{Reader, Writer};
use opentrust_core::types::{ExtAddress, ShortAddress};
use opentrust_core::{Error, Result};

/// Length in bytes of the (CRC-16) frame check sequence.
pub const FCS_LEN: usize = 2;

/// IEEE 802.15.4 frame type (Frame Control bits 0..2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum FrameType {
    /// Beacon frame.
    Beacon,
    /// Data frame.
    Data,
    /// Acknowledgment (immediate or enhanced).
    Ack,
    /// MAC command frame.
    MacCmd,
    /// Multipurpose frame (used by Thread 1.4 wake-up frames).
    Multipurpose,
}

impl FrameType {
    /// The 3-bit wire value.
    pub const fn bits(self) -> u8 {
        match self {
            Self::Beacon => 0,
            Self::Data => 1,
            Self::Ack => 2,
            Self::MacCmd => 3,
            Self::Multipurpose => 5,
        }
    }

    /// Decode the 3-bit wire value; `None` for types Thread does not use.
    pub const fn from_bits(bits: u8) -> Option<Self> {
        match bits & 7 {
            0 => Some(Self::Beacon),
            1 => Some(Self::Data),
            2 => Some(Self::Ack),
            3 => Some(Self::MacCmd),
            5 => Some(Self::Multipurpose),
            _ => None,
        }
    }
}

/// IEEE 802.15.4 frame version (Frame Control bits 12..13).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum FrameVersion {
    /// IEEE 802.15.4-2003.
    V2003,
    /// IEEE 802.15.4-2006.
    V2006,
    /// IEEE 802.15.4-2015 (CSL, enhanced ACK, header IEs).
    V2015,
}

impl FrameVersion {
    /// The 2-bit wire value.
    pub const fn bits(self) -> u8 {
        match self {
            Self::V2003 => 0,
            Self::V2006 => 1,
            Self::V2015 => 2,
        }
    }

    /// Decode the 2-bit wire value; `None` for the reserved value 3.
    pub const fn from_bits(bits: u8) -> Option<Self> {
        match bits & 3 {
            0 => Some(Self::V2003),
            1 => Some(Self::V2006),
            2 => Some(Self::V2015),
            _ => None,
        }
    }
}

/// Addressing mode of the source or destination address field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum AddressMode {
    /// No address present.
    None,
    /// 16-bit short address.
    Short,
    /// 64-bit extended address.
    Extended,
}

impl AddressMode {
    /// The 2-bit wire value.
    pub const fn bits(self) -> u8 {
        match self {
            Self::None => 0,
            Self::Short => 2,
            Self::Extended => 3,
        }
    }

    /// Decode the 2-bit wire value; `None` for the reserved value 1.
    pub const fn from_bits(bits: u8) -> Option<Self> {
        match bits & 3 {
            0 => Some(Self::None),
            2 => Some(Self::Short),
            3 => Some(Self::Extended),
            _ => None,
        }
    }

    /// Size of the address field in bytes.
    pub const fn field_len(self) -> usize {
        match self {
            Self::None => 0,
            Self::Short => 2,
            Self::Extended => 8,
        }
    }
}

/// A MAC address. Extended addresses are held in canonical (big-endian)
/// order; on air they are transmitted reversed (little-endian).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Address {
    /// No address.
    None,
    /// Short address.
    Short(ShortAddress),
    /// Extended address.
    Extended(ExtAddress),
}

impl Address {
    /// The addressing mode of this address.
    pub const fn mode(&self) -> AddressMode {
        match self {
            Self::None => AddressMode::None,
            Self::Short(_) => AddressMode::Short,
            Self::Extended(_) => AddressMode::Extended,
        }
    }

    /// `true` if no address is present.
    pub const fn is_none(&self) -> bool {
        matches!(self, Self::None)
    }

    /// `true` for the short broadcast address `0xffff`.
    pub fn is_broadcast(&self) -> bool {
        *self == Self::Short(ShortAddress::BROADCAST)
    }

    /// `true` for the "no short address assigned" value `0xfffe`.
    pub fn is_short_invalid(&self) -> bool {
        *self == Self::Short(ShortAddress::INVALID)
    }

    /// Read an address of the given mode from its on-air encoding.
    pub fn read(r: &mut Reader<'_>, mode: AddressMode) -> Result<Self> {
        Ok(match mode {
            AddressMode::None => Self::None,
            AddressMode::Short => Self::Short(ShortAddress(r.read_u16_le()?)),
            AddressMode::Extended => {
                let mut a = r.read_array::<8>()?;
                a.reverse();
                Self::Extended(ExtAddress(a))
            }
        })
    }

    /// Write the on-air encoding (nothing for [`Address::None`]).
    pub fn write(&self, w: &mut Writer<'_>) -> Result<()> {
        match self {
            Self::None => Ok(()),
            Self::Short(s) => w.write_u16_le(s.0),
            Self::Extended(e) => {
                let mut a = e.0;
                a.reverse();
                w.write_slice(&a)
            }
        }
    }
}

// General frame control bits.
const SEC: u16 = 1 << 3;
const PEND: u16 = 1 << 4;
const ACKREQ: u16 = 1 << 5;
const PANCOMP: u16 = 1 << 6;
const SEQSUP: u16 = 1 << 8;
const IEP: u16 = 1 << 9;
// Multipurpose frame control bits.
const MP_LONG: u16 = 1 << 3;
const MP_PAN: u16 = 1 << 8;
const MP_SEC: u16 = 1 << 9;
const MP_SEQSUP: u16 = 1 << 10;
const MP_PEND: u16 = 1 << 11;
const MP_ACKREQ: u16 = 1 << 14;
const MP_IEP: u16 = 1 << 15;

/// Decoded Frame Control Field (general and multipurpose formats).
///
/// Only constructible through [`FrameControl::parse`] /
/// [`FrameControl::from_bits`], which reject frame types, versions and
/// address modes Thread does not use, so all accessors are infallible.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct FrameControl {
    raw: u16,
    frame_type: FrameType,
    version: FrameVersion,
    dst_mode: AddressMode,
    src_mode: AddressMode,
}

impl FrameControl {
    /// Decode and validate a raw FCF value. For a short multipurpose FCF
    /// (one byte on air) the high byte must be zero.
    pub fn from_bits(raw: u16) -> Result<Self> {
        let frame_type = FrameType::from_bits(raw as u8).ok_or(Error::Parse)?;
        let (version, dst, src) = if frame_type == FrameType::Multipurpose {
            (FrameVersion::V2015, (raw >> 4) as u8, (raw >> 6) as u8)
        } else {
            (
                FrameVersion::from_bits((raw >> 12) as u8).ok_or(Error::Parse)?,
                (raw >> 10) as u8,
                (raw >> 14) as u8,
            )
        };
        let fc = Self {
            raw,
            frame_type,
            version,
            dst_mode: AddressMode::from_bits(dst).ok_or(Error::Parse)?,
            src_mode: AddressMode::from_bits(src).ok_or(Error::Parse)?,
        };
        if fc.is_short() && raw > 0xff {
            return Err(Error::Parse);
        }
        Ok(fc)
    }

    /// Read the FCF (one or two bytes) from `r`.
    pub fn parse(r: &mut Reader<'_>) -> Result<Self> {
        let b0 = u16::from(r.peek_u8()?);
        let raw = if (b0 & 7) == 5 && (b0 & MP_LONG) == 0 {
            u16::from(r.read_u8()?)
        } else {
            r.read_u16_le()?
        };
        Self::from_bits(raw)
    }

    /// The raw FCF value.
    pub const fn bits(&self) -> u16 {
        self.raw
    }

    /// Frame type.
    pub const fn frame_type(&self) -> FrameType {
        self.frame_type
    }

    /// Frame version (multipurpose frames report 2015).
    pub const fn version(&self) -> FrameVersion {
        self.version
    }

    /// `true` for the multipurpose format.
    pub const fn is_multipurpose(&self) -> bool {
        matches!(self.frame_type, FrameType::Multipurpose)
    }

    /// `true` for a multipurpose frame with the one-byte FCF.
    pub const fn is_short(&self) -> bool {
        self.is_multipurpose() && (self.raw & MP_LONG) == 0
    }

    /// Encoded FCF length: 1 (short multipurpose) or 2 bytes.
    pub const fn encoded_len(&self) -> usize {
        if self.is_short() { 1 } else { 2 }
    }

    /// Write the FCF.
    pub fn write(&self, w: &mut Writer<'_>) -> Result<()> {
        if self.is_short() {
            w.write_u8(self.raw as u8)
        } else {
            w.write_u16_le(self.raw)
        }
    }

    const fn pick(&self, general: u16, mp: u16) -> bool {
        self.raw & (if self.is_multipurpose() { mp } else { general }) != 0
    }

    /// Security Enabled bit.
    pub const fn security_enabled(&self) -> bool {
        self.pick(SEC, MP_SEC)
    }

    /// Frame Pending bit.
    pub const fn frame_pending(&self) -> bool {
        self.pick(PEND, MP_PEND)
    }

    /// Acknowledgment Request bit.
    pub const fn ack_request(&self) -> bool {
        self.pick(ACKREQ, MP_ACKREQ)
    }

    /// PAN ID Compression bit (always `false` for multipurpose frames).
    pub const fn pan_id_compression(&self) -> bool {
        !self.is_multipurpose() && self.raw & PANCOMP != 0
    }

    /// `true` if the sequence number is present. Sequence number
    /// suppression only exists in 2015 frames; the bit is reserved
    /// (ignored) in 2003/2006 frames.
    pub const fn sequence_present(&self) -> bool {
        !(matches!(self.version, FrameVersion::V2015) && self.pick(SEQSUP, MP_SEQSUP))
    }

    /// `true` if header IEs are present (2015 and multipurpose frames only;
    /// the bit is reserved in 2003/2006 frames).
    pub const fn ie_present(&self) -> bool {
        matches!(self.version, FrameVersion::V2015) && self.pick(IEP, MP_IEP)
    }

    /// Destination addressing mode.
    pub const fn dst_mode(&self) -> AddressMode {
        self.dst_mode
    }

    /// Source addressing mode.
    pub const fn src_mode(&self) -> AddressMode {
        self.src_mode
    }

    /// `true` if the Destination PAN ID field is present.
    ///
    /// Implements IEEE 802.15.4-2015 Table 7-2 for 2015 frames and the
    /// 2003/2006 rules otherwise.
    pub const fn dst_pan_present(&self) -> bool {
        if self.is_multipurpose() {
            return self.raw & MP_PAN != 0;
        }
        if matches!(self.version, FrameVersion::V2015) {
            use AddressMode::{Extended as E, None as N, Short as S};
            let comp = self.pan_id_compression();
            return !matches!(
                (self.dst_mode, self.src_mode, comp),
                (N, N, false) | (S | E, N, true) | (N, S | E, _) | (E, E, true)
            );
        }
        !matches!(self.dst_mode, AddressMode::None)
    }

    /// `true` if the Source PAN ID field is present.
    pub const fn src_pan_present(&self) -> bool {
        if self.is_multipurpose() {
            return false;
        }
        if matches!(self.version, FrameVersion::V2015)
            && matches!(self.dst_mode, AddressMode::Extended)
            && matches!(self.src_mode, AddressMode::Extended)
        {
            return false;
        }
        !matches!(self.src_mode, AddressMode::None) && !self.pan_id_compression()
    }

    /// Length of FCF + sequence number + PAN IDs + addresses.
    pub const fn addressing_len(&self) -> usize {
        self.encoded_len()
            + self.sequence_present() as usize
            + 2 * self.dst_pan_present() as usize
            + self.dst_mode.field_len()
            + 2 * self.src_pan_present() as usize
            + self.src_mode.field_len()
    }

    /// Bit mask of the Ack Request flag in this format.
    pub(crate) const fn ack_request_mask(&self) -> u16 {
        if self.is_multipurpose() {
            MP_ACKREQ
        } else {
            ACKREQ
        }
    }

    /// Bit mask of the Frame Pending flag in this format.
    pub(crate) const fn frame_pending_mask(&self) -> u16 {
        if self.is_multipurpose() {
            MP_PEND
        } else {
            PEND
        }
    }
}

/// Flag bits for [`assemble_fcf`]; for multipurpose frames
/// `pan_compression` means "PAN ID present".
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct Flags {
    pub pan_compression: bool,
    pub security: bool,
    pub seq_suppress: bool,
    pub pending: bool,
    pub ack_request: bool,
    pub ie: bool,
}

/// Assemble FCF bits (multipurpose frames use the two-byte format).
pub(crate) fn assemble_fcf(
    frame_type: FrameType,
    version: FrameVersion,
    dst: AddressMode,
    src: AddressMode,
    f: Flags,
) -> u16 {
    let bit = |c: bool, m: u16| if c { m } else { 0 };
    let t = u16::from(frame_type.bits());
    let (d, s) = (u16::from(dst.bits()), u16::from(src.bits()));
    if frame_type == FrameType::Multipurpose {
        t | MP_LONG
            | d << 4
            | s << 6
            | bit(f.pan_compression, MP_PAN)
            | bit(f.security, MP_SEC)
            | bit(f.seq_suppress, MP_SEQSUP)
            | bit(f.pending, MP_PEND)
            | bit(f.ack_request, MP_ACKREQ)
            | bit(f.ie, MP_IEP)
    } else {
        t | u16::from(version.bits()) << 12
            | d << 10
            | s << 14
            | bit(f.pan_compression, PANCOMP)
            | bit(f.security, SEC)
            | bit(f.seq_suppress, SEQSUP)
            | bit(f.pending, PEND)
            | bit(f.ack_request, ACKREQ)
            | bit(f.ie, IEP)
    }
}
