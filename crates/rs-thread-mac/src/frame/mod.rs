//! IEEE 802.15.4 frame parsing and building (2003/2006/2015 versions) as
//! used by Thread 1.4.
//!
//! # PSDU convention
//!
//! All APIs work on the PSDU **without the FCS**: `Frame::parse(psdu)`
//! expects the bytes from the Frame Control Field up to and including the
//! MIC (if any). OpenThread's `mPsdu`/`mLength` *include* the 2-byte FCS;
//! use [`Frame::parse_with_fcs`] for such buffers. Built frames also exclude
//! the FCS and carry a zero-filled MIC placeholder for the security layer.
//!
//! # Parsing
//!
//! [`Frame::parse`] validates the whole header once (addressing, auxiliary
//! security header, header IEs, MIC) and returns an immutable zero-copy
//! view; every malformed or truncated input yields [`Error::Parse`], it
//! never panics.
//!
//! ```
//! use rs_thread_mac::frame::{Address, Frame, FrameType, FrameVersion};
//!
//! // 802.15.4-2006 data frame, short addresses, PAN ID compression.
//! let psdu = [0x61, 0x98, 0x07, 0xce, 0xfa, 0x34, 0x12, 0x78, 0x56, 0xaa, 0xbb];
//! let f = Frame::parse(&psdu).unwrap();
//! assert_eq!(f.frame_type(), FrameType::Data);
//! assert_eq!(f.version(), FrameVersion::V2006);
//! assert_eq!(f.sequence(), Some(7));
//! assert_eq!(f.payload(), &[0xaa, 0xbb]);
//! assert!(matches!(f.src_address(), Address::Short(_)));
//! ```
//!
//! # Security layer hooks
//!
//! [`Frame::security_header`] gives level, frame counter and key
//! identifier. [`Frame::header_len`] / [`Frame::header`] (the CCM* `a` data,
//! including the auxiliary security header), [`Frame::payload_range`] and
//! [`Frame::mic_range`] locate the pieces; [`FrameMut::parts_mut`] splits a
//! mutable PSDU into `(header, payload, mic)` ready for
//! `rs_thread_core::crypto::ccm::seal_frame` / `open_frame`.
//! For MAC command frames older than 2015, the command ID counts as header
//! (as in OpenThread); in 2015 frames it is the first payload byte.
//!
//! # Building
//!
//! ```
//! use rs_thread_core::crypto::SecurityLevel;
//! use rs_thread_core::types::{PanId, ShortAddress};
//! use rs_thread_mac::frame::{
//!     Address, CslIe, Frame, FrameBuilder, FrameType, FrameVersion, KeyIdentifier,
//!     SecurityHeader,
//! };
//!
//! let mut buf = [0u8; 127];
//! let len = FrameBuilder::new(&mut buf)
//!     .frame_type(FrameType::Data)
//!     .version(FrameVersion::V2015)
//!     .sequence(42)
//!     .pan_id(PanId(0xface))
//!     .dst(Address::Short(ShortAddress(0x2400)))
//!     .src(Address::Short(ShortAddress(0x0800)))
//!     .security(SecurityHeader::new(SecurityLevel::EncMic32, 7, KeyIdentifier::Index(1)))
//!     .header_ie(CslIe { phase: 100, period: 3125, rendezvous_time: None })
//!     .payload(b"hello")
//!     .build()
//!     .unwrap();
//! // `len` covers header, payload and a zeroed 4-byte MIC (no FCS).
//! let f = Frame::parse(&buf[..len]).unwrap();
//! assert_eq!(f.payload(), b"hello");
//! assert_eq!(f.mic_range().len(), 4);
//! assert_eq!(f.csl_ie().unwrap().period, 3125);
//! ```

mod beacon;
mod builder;
mod control;
mod ie;
mod security;

#[cfg(test)]
mod tests;

use core::ops::Range;

use rs_thread_core::bytes::Reader;
use rs_thread_core::types::PanId;
use rs_thread_core::{Error, Result};

pub use beacon::{Beacon, SuperframeSpec, ThreadBeaconPayload};
pub use builder::{FrameBuilder, MAX_HEADER_IES};
pub use control::{Address, AddressMode, FCS_LEN, FrameControl, FrameType, FrameVersion};
pub use ie::{
    ConnectionIe, CslIe, HeaderIe, HeaderIeIter, HeaderIeValue, IE_ID_CSL,
    IE_ID_HEADER_TERMINATION_1, IE_ID_HEADER_TERMINATION_2, IE_ID_RENDEZVOUS_TIME, IE_ID_VENDOR,
    NEST_IE_TIME, NEST_OUI, PAYLOAD_IE_GROUP_TERMINATION, PayloadIe, PayloadIeIter,
    RendezvousTimeIe, THREAD_IE_CONNECTION, THREAD_IE_ENH_ACK_PROBING, THREAD_OUI, TimeIe,
    VendorIe,
};
pub use security::{KeyIdMode, KeyIdentifier, SecurityHeader};

/// MAC command identifiers (IEEE 802.15.4 Table 7-49) used by Thread.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum MacCommand {
    /// Association request (0x01).
    AssociationRequest,
    /// Association response (0x02).
    AssociationResponse,
    /// Disassociation notification (0x03).
    DisassociationNotification,
    /// Data request (0x04), used for polling by sleepy children.
    DataRequest,
    /// PAN ID conflict notification (0x05).
    PanIdConflictNotification,
    /// Orphan notification (0x06).
    OrphanNotification,
    /// Beacon request (0x07), used for active scan.
    BeaconRequest,
    /// Coordinator realignment (0x08).
    CoordinatorRealignment,
    /// GTS request (0x09).
    GtsRequest,
}

impl MacCommand {
    /// The command identifier byte.
    pub const fn id(self) -> u8 {
        match self {
            Self::AssociationRequest => 1,
            Self::AssociationResponse => 2,
            Self::DisassociationNotification => 3,
            Self::DataRequest => 4,
            Self::PanIdConflictNotification => 5,
            Self::OrphanNotification => 6,
            Self::BeaconRequest => 7,
            Self::CoordinatorRealignment => 8,
            Self::GtsRequest => 9,
        }
    }

    /// Decode a command identifier byte.
    pub const fn from_id(id: u8) -> Option<Self> {
        Some(match id {
            1 => Self::AssociationRequest,
            2 => Self::AssociationResponse,
            3 => Self::DisassociationNotification,
            4 => Self::DataRequest,
            5 => Self::PanIdConflictNotification,
            6 => Self::OrphanNotification,
            7 => Self::BeaconRequest,
            8 => Self::CoordinatorRealignment,
            9 => Self::GtsRequest,
            _ => return None,
        })
    }
}

/// Zero-copy parsed view of an IEEE 802.15.4 frame (PSDU without FCS).
#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Frame<'a> {
    psdu: &'a [u8],
    fcf: FrameControl,
    seq: Option<u8>,
    dst_pan: Option<PanId>,
    dst: Address,
    src_pan: Option<PanId>,
    src: Address,
    security: Option<SecurityHeader>,
    /// Offset of the first header IE (== `ie_end` if none).
    ie_start: usize,
    /// Offset just past the header IEs.
    ie_end: usize,
    /// Offset of the first payload byte (== `header_len`).
    payload_start: usize,
    /// Offset of the MIC (== end of payload).
    payload_end: usize,
}

impl<'a> Frame<'a> {
    /// Parse and validate a PSDU **without** FCS.
    pub fn parse(psdu: &'a [u8]) -> Result<Self> {
        let mut r = Reader::new(psdu);
        let fcf = FrameControl::parse(&mut r)?;
        let seq = if fcf.sequence_present() {
            Some(r.read_u8()?)
        } else {
            None
        };
        let dst_pan = if fcf.dst_pan_present() {
            Some(PanId(r.read_u16_le()?))
        } else {
            None
        };
        let dst = Address::read(&mut r, fcf.dst_mode())?;
        let src_pan = if fcf.src_pan_present() {
            Some(PanId(r.read_u16_le()?))
        } else {
            None
        };
        let src = Address::read(&mut r, fcf.src_mode())?;

        let security = if fcf.security_enabled() {
            Some(SecurityHeader::parse(&mut r)?)
        } else {
            None
        };
        let mic_len = security.map_or(0, |s| s.mic_len());
        let payload_end = psdu.len().checked_sub(mic_len).ok_or(Error::Parse)?;
        if r.position() > payload_end {
            return Err(Error::Parse);
        }

        let ie_start = r.position();
        if fcf.ie_present() {
            // At least one IE; stop at a termination IE or at the end of
            // the frame (termination is optional if no payload follows).
            loop {
                if payload_end - r.position() < 2 {
                    return Err(Error::Parse);
                }
                let ie = HeaderIe::parse(&mut r)?;
                if r.position() > payload_end {
                    return Err(Error::Parse);
                }
                if ie.is_termination() || r.position() == payload_end {
                    break;
                }
            }
        }
        let ie_end = r.position();

        let mut payload_start = ie_end;
        if fcf.frame_type() == FrameType::MacCmd {
            if fcf.version() == FrameVersion::V2015 {
                // Command ID is the first payload byte.
                if payload_start >= payload_end {
                    return Err(Error::Parse);
                }
            } else {
                payload_start += 1;
                if payload_start > payload_end {
                    return Err(Error::Parse);
                }
            }
        }

        Ok(Self {
            psdu,
            fcf,
            seq,
            dst_pan,
            dst,
            src_pan,
            src,
            security,
            ie_start,
            ie_end,
            payload_start,
            payload_end,
        })
    }

    /// Parse a PSDU that still carries its 2-byte FCS (OpenThread style).
    /// The FCS is not checked.
    pub fn parse_with_fcs(psdu: &'a [u8]) -> Result<Self> {
        let n = psdu.len().checked_sub(FCS_LEN).ok_or(Error::Parse)?;
        Self::parse(&psdu[..n])
    }

    /// The whole PSDU (without FCS).
    pub const fn psdu(&self) -> &'a [u8] {
        self.psdu
    }

    /// The decoded Frame Control Field.
    pub const fn frame_control(&self) -> FrameControl {
        self.fcf
    }

    /// Frame type.
    pub const fn frame_type(&self) -> FrameType {
        self.fcf.frame_type()
    }

    /// Frame version (multipurpose frames report 2015).
    pub const fn version(&self) -> FrameVersion {
        self.fcf.version()
    }

    /// `true` for an acknowledgment frame.
    pub const fn is_ack(&self) -> bool {
        matches!(self.fcf.frame_type(), FrameType::Ack)
    }

    /// Security Enabled bit.
    pub const fn security_enabled(&self) -> bool {
        self.fcf.security_enabled()
    }

    /// Frame Pending bit.
    pub const fn frame_pending(&self) -> bool {
        self.fcf.frame_pending()
    }

    /// Ack Request bit.
    pub const fn ack_request(&self) -> bool {
        self.fcf.ack_request()
    }

    /// IE Present bit (effective: only 2015/multipurpose frames).
    pub const fn ie_present(&self) -> bool {
        self.fcf.ie_present()
    }

    /// Sequence number, `None` if suppressed.
    pub const fn sequence(&self) -> Option<u8> {
        self.seq
    }

    /// Destination PAN ID if present on air.
    pub const fn dst_pan_id(&self) -> Option<PanId> {
        self.dst_pan
    }

    /// Destination address.
    pub const fn dst_address(&self) -> Address {
        self.dst
    }

    /// Source PAN ID if present on air.
    pub const fn src_pan_id(&self) -> Option<PanId> {
        self.src_pan
    }

    /// Source address.
    pub const fn src_address(&self) -> Address {
        self.src
    }

    /// The PAN ID the frame refers to: the source PAN ID if present,
    /// otherwise the destination PAN ID (as used for the PAN ID of an
    /// enhanced ACK's destination).
    pub const fn pan_id(&self) -> Option<PanId> {
        match self.src_pan {
            Some(p) => Some(p),
            None => self.dst_pan,
        }
    }

    /// The auxiliary security header, if security is enabled.
    pub const fn security_header(&self) -> Option<&SecurityHeader> {
        self.security.as_ref()
    }

    /// Length of the MAC header: everything before the payload, including
    /// auxiliary security header and header IEs (and the command ID for
    /// pre-2015 MAC commands).
    pub const fn header_len(&self) -> usize {
        self.payload_start
    }

    /// The MAC header bytes (the CCM* authenticated data `a`).
    pub fn header(&self) -> &'a [u8] {
        &self.psdu[..self.payload_start]
    }

    /// Byte range of the MAC payload within the PSDU.
    pub const fn payload_range(&self) -> Range<usize> {
        self.payload_start..self.payload_end
    }

    /// The MAC payload (ciphertext if the frame is still encrypted).
    pub fn payload(&self) -> &'a [u8] {
        &self.psdu[self.payload_start..self.payload_end]
    }

    /// Length of the MIC footer (0 without security).
    pub const fn mic_len(&self) -> usize {
        self.psdu.len() - self.payload_end
    }

    /// Byte range of the MIC within the PSDU.
    pub const fn mic_range(&self) -> Range<usize> {
        self.payload_end..self.psdu.len()
    }

    /// The MIC bytes.
    pub fn mic(&self) -> &'a [u8] {
        &self.psdu[self.payload_end..]
    }

    /// Iterator over the header IEs (including a termination IE).
    pub fn header_ies(&self) -> HeaderIeIter<'a> {
        HeaderIeIter::new(&self.psdu[self.ie_start..self.ie_end])
    }

    /// First header IE with the given element ID.
    pub fn find_header_ie(&self, id: u8) -> Option<HeaderIe<'a>> {
        self.header_ies().flatten().find(|ie| ie.id == id)
    }

    /// First Thread vendor IE with the given sub-type.
    pub fn find_thread_ie(&self, subtype: u8) -> Option<VendorIe<'a>> {
        self.header_ies()
            .flatten()
            .filter_map(|ie| ie.vendor())
            .find(|v| v.is_thread(subtype))
    }

    /// The CSL IE, if present.
    pub fn csl_ie(&self) -> Option<CslIe> {
        self.find_header_ie(IE_ID_CSL).and_then(|ie| ie.csl())
    }

    /// The Rendezvous Time IE, if present.
    pub fn rendezvous_time_ie(&self) -> Option<RendezvousTimeIe> {
        self.find_header_ie(IE_ID_RENDEZVOUS_TIME)
            .and_then(|ie| ie.rendezvous_time())
    }

    /// The Thread Connection IE, if present.
    pub fn connection_ie(&self) -> Option<ConnectionIe> {
        self.header_ies().flatten().find_map(|ie| ie.connection())
    }

    /// The Nest Time IE, if present.
    pub fn time_ie(&self) -> Option<TimeIe> {
        self.header_ies().flatten().find_map(|ie| ie.time())
    }

    /// The raw MAC command ID byte (`None` unless a MAC command frame).
    /// In 2015 frames this is the first payload byte, which is ciphertext
    /// while the frame is encrypted.
    pub fn command_id(&self) -> Option<u8> {
        if self.frame_type() != FrameType::MacCmd {
            return None;
        }
        if self.version() == FrameVersion::V2015 {
            self.psdu.get(self.payload_start).copied()
        } else {
            self.psdu.get(self.payload_start - 1).copied()
        }
    }

    /// The decoded MAC command (`None` for other frames/unknown IDs).
    pub fn command(&self) -> Option<MacCommand> {
        self.command_id().and_then(MacCommand::from_id)
    }

    /// `true` for a MAC Data Request command.
    pub fn is_data_request(&self) -> bool {
        self.command() == Some(MacCommand::DataRequest)
    }

    /// Thread 1.4 wake-up frame: multipurpose, no ack request, extended
    /// source, key ID mode 2, exactly a Rendezvous Time IE and a
    /// Connection IE, and no payload.
    pub fn is_wakeup_frame(&self) -> bool {
        if self.frame_type() != FrameType::Multipurpose
            || self.ack_request()
            || !matches!(self.src, Address::Extended(_))
            || self.security.map(|s| s.key_id_mode()) != Some(KeyIdMode::Source4)
            || !self.payload().is_empty()
        {
            return false;
        }
        let (mut rv, mut conn, mut n) = (false, false, 0);
        for ie in self.header_ies() {
            let Ok(ie) = ie else { return false };
            n += 1;
            rv |= ie.rendezvous_time().is_some();
            conn |= ie.connection().is_some();
        }
        n == 2 && rv && conn
    }
}

/// Mutable pieces of a secured frame for in-place CCM*; see
/// [`FrameMut::parts_mut`].
#[derive(Debug)]
pub struct FrameParts<'a> {
    /// MAC header including auxiliary security header (authenticated data).
    pub header: &'a [u8],
    /// MAC payload (encrypted/decrypted in place).
    pub payload: &'a mut [u8],
    /// MIC area (written when sealing, read when opening).
    pub mic: &'a mut [u8],
}

/// Mutable view of a built or received PSDU (without FCS) that allows
/// patching header fields without re-serializing, as the MAC needs to at
/// transmit time (sequence number, frame counter, CSL phase, flags).
#[derive(Debug)]
pub struct FrameMut<'a> {
    psdu: &'a mut [u8],
}

impl<'a> FrameMut<'a> {
    /// Wrap `psdu`, validating it as [`Frame::parse`] does.
    pub fn new(psdu: &'a mut [u8]) -> Result<Self> {
        Frame::parse(psdu)?;
        Ok(Self { psdu })
    }

    /// Immutable parsed view.
    pub fn frame(&self) -> Result<Frame<'_>> {
        Frame::parse(self.psdu)
    }

    /// The PSDU bytes.
    pub fn psdu(&self) -> &[u8] {
        self.psdu
    }

    /// Split into header, payload and MIC for in-place CCM*.
    pub fn parts_mut(&mut self) -> Result<FrameParts<'_>> {
        let f = Frame::parse(self.psdu)?;
        let (hl, pe) = (f.header_len(), f.payload_range().end);
        let (head, rest) = self.psdu.split_at_mut(hl);
        let (payload, mic) = rest.split_at_mut(pe - hl);
        Ok(FrameParts {
            header: head,
            payload,
            mic,
        })
    }

    /// Mutable payload bytes.
    pub fn payload_mut(&mut self) -> Result<&mut [u8]> {
        let r = Frame::parse(self.psdu)?.payload_range();
        Ok(&mut self.psdu[r])
    }

    /// Set the sequence number. [`Error::InvalidState`] if suppressed.
    pub fn set_sequence(&mut self, seq: u8) -> Result<()> {
        let f = Frame::parse(self.psdu)?;
        if f.sequence().is_none() {
            return Err(Error::InvalidState);
        }
        self.psdu[f.fcf.encoded_len()] = seq;
        Ok(())
    }

    fn set_fcf_bit(&mut self, mask_of: fn(&FrameControl) -> u16, on: bool) -> Result<()> {
        let fcf = Frame::parse(self.psdu)?.fcf;
        let mask = mask_of(&fcf);
        if fcf.is_short() && mask > 0xff {
            return Err(Error::InvalidState);
        }
        let bits = if on {
            fcf.bits() | mask
        } else {
            fcf.bits() & !mask
        };
        self.psdu[0] = bits as u8;
        if !fcf.is_short() {
            self.psdu[1] = (bits >> 8) as u8;
        }
        Ok(())
    }

    /// Set or clear the Ack Request bit.
    pub fn set_ack_request(&mut self, on: bool) -> Result<()> {
        self.set_fcf_bit(FrameControl::ack_request_mask, on)
    }

    /// Set or clear the Frame Pending bit.
    pub fn set_frame_pending(&mut self, on: bool) -> Result<()> {
        self.set_fcf_bit(FrameControl::frame_pending_mask, on)
    }

    /// Set the frame counter in the auxiliary security header.
    /// [`Error::InvalidState`] if unsecured or the counter is suppressed.
    pub fn set_frame_counter(&mut self, counter: u32) -> Result<()> {
        let f = Frame::parse(self.psdu)?;
        match f.security {
            Some(s) if s.frame_counter.is_some() => {
                let at = f.fcf.addressing_len() + 1;
                self.psdu[at..at + 4].copy_from_slice(&counter.to_le_bytes());
                Ok(())
            }
            _ => Err(Error::InvalidState),
        }
    }

    /// Set the key index of a frame with key ID mode 1 (an implicit-key or
    /// source-addressed key identifier is left alone).
    /// [`Error::InvalidState`] if the frame has no mode 1 key identifier.
    pub fn set_key_index(&mut self, index: u8) -> Result<()> {
        let f = Frame::parse(self.psdu)?;
        match f.security {
            Some(s) if matches!(s.key, KeyIdentifier::Index(_)) => {
                let at = f.fcf.addressing_len() + 1 + 4 * s.frame_counter.is_some() as usize;
                self.psdu[at] = index;
                Ok(())
            }
            _ => Err(Error::InvalidState),
        }
    }

    /// Update phase and period of an existing CSL IE in place (keeps the
    /// rendezvous time, if any). [`Error::NotFound`] if there is no CSL IE.
    pub fn set_csl_ie(&mut self, phase: u16, period: u16) -> Result<()> {
        let f = Frame::parse(self.psdu)?;
        let mut off = f.ie_start;
        let mut found = None;
        for ie in f.header_ies() {
            let ie = ie?;
            if ie.id == IE_ID_CSL && ie.content.len() >= 4 {
                found = Some(off);
                break;
            }
            off += ie.encoded_len();
        }
        let off = found.ok_or(Error::NotFound)?;
        self.psdu[off + 2..off + 4].copy_from_slice(&phase.to_le_bytes());
        self.psdu[off + 4..off + 6].copy_from_slice(&period.to_le_bytes());
        Ok(())
    }
}
