//! Frame builder writing into a caller-provided buffer.

use opentrust_core::bytes::Writer;
use opentrust_core::crypto::SecurityLevel;
use opentrust_core::types::PanId;
use opentrust_core::{Error, Result};

use super::control::{Flags, assemble_fcf};
use super::ie::{ConnectionIe, HeaderIeValue, RendezvousTimeIe};
use super::security::SecurityHeader;
use super::{Address, AddressMode, Frame, FrameType, FrameVersion, MacCommand};

/// Maximum number of typed header IEs a [`FrameBuilder`] can carry
/// (additional pre-encoded IEs can be added with
/// [`FrameBuilder::raw_header_ies`]).
pub const MAX_HEADER_IES: usize = 6;

/// Builder for IEEE 802.15.4 frames.
///
/// Defaults: data frame, version 2006, sequence number 0, no addresses, no
/// security, no IEs, empty payload; the Ack Request bit is set automatically
/// for unicast destinations of non-ACK frames (as OpenThread does) unless
/// [`ack_request`](Self::ack_request) is given.
///
/// [`build`](Self::build) returns the frame length **without FCS**. The MIC
/// area (for secured frames) is zero-filled; header IEs get a Header
/// Termination 2 IE appended automatically when a payload (or a MAC command
/// ID) follows. Errors found while chaining are reported by `build`.
#[derive(Debug)]
pub struct FrameBuilder<'a> {
    buf: &'a mut [u8],
    frame_type: FrameType,
    version: FrameVersion,
    seq: Option<u8>,
    dst_pan: Option<PanId>,
    dst: Address,
    src_pan: Option<PanId>,
    src: Address,
    ack_request: Option<bool>,
    pending: bool,
    security: Option<SecurityHeader>,
    ies: [Option<HeaderIeValue<'a>>; MAX_HEADER_IES],
    n_ies: usize,
    raw_ies: &'a [u8],
    command: Option<u8>,
    payload: &'a [u8],
    err: Option<Error>,
}

impl<'a> FrameBuilder<'a> {
    /// Start building into `buf`.
    pub fn new(buf: &'a mut [u8]) -> Self {
        Self {
            buf,
            frame_type: FrameType::Data,
            version: FrameVersion::V2006,
            seq: Some(0),
            dst_pan: None,
            dst: Address::None,
            src_pan: None,
            src: Address::None,
            ack_request: None,
            pending: false,
            security: None,
            ies: [None; MAX_HEADER_IES],
            n_ies: 0,
            raw_ies: &[],
            command: None,
            payload: &[],
            err: None,
        }
    }

    /// Immediate ACK (2003/2006 style: FCF + sequence number only).
    /// Returns the length (3, without FCS).
    pub fn imm_ack(
        buf: &mut [u8],
        version: FrameVersion,
        sequence: u8,
        frame_pending: bool,
    ) -> Result<usize> {
        let fcf = assemble_fcf(
            FrameType::Ack,
            version,
            AddressMode::None,
            AddressMode::None,
            Flags {
                pending: frame_pending,
                ..Flags::default()
            },
        );
        let mut w = Writer::new(buf);
        w.write_u16_le(fcf)?;
        w.write_u8(sequence)?;
        Ok(w.len())
    }

    /// Immediate ACK for a received frame, in the version of that frame
    /// (OpenThread `GenerateImmAck`).
    pub fn imm_ack_for(buf: &mut [u8], rx: &Frame<'_>, frame_pending: bool) -> Result<usize> {
        let seq = rx.sequence().ok_or(Error::InvalidArgs)?;
        Self::imm_ack(buf, rx.version(), seq, frame_pending)
    }

    /// Enhanced ACK (2015) for a received frame, as a builder to which
    /// header IEs can be added (OpenThread `GenerateEnhAck`).
    ///
    /// The ACK is addressed to the sender of `rx` (no source address),
    /// copies sequence number and, if `rx` was secured, key identifier
    /// (frame counter is 0 and must be set before sealing). Fails with
    /// [`Error::Parse`] if `rx` is not a 2015 frame requesting an ACK for a
    /// unicast destination from a known source, or is secured with a level
    /// other than `EncMic32`.
    pub fn enh_ack(buf: &'a mut [u8], rx: &Frame<'_>, frame_pending: bool) -> Result<Self> {
        if rx.version() != FrameVersion::V2015
            || !rx.ack_request()
            || rx.dst_address().is_none()
            || rx.dst_address().is_broadcast()
            || rx.src_address().is_none()
        {
            return Err(Error::Parse);
        }
        let security = match rx.security_header() {
            None => None,
            Some(s) if s.level == SecurityLevel::EncMic32 => {
                Some(SecurityHeader::new(s.level, 0, s.key))
            }
            Some(_) => return Err(Error::Parse),
        };
        let mut b = Self::new(buf);
        b.frame_type = FrameType::Ack;
        b.version = FrameVersion::V2015;
        b.seq = rx.sequence();
        b.dst = rx.src_address();
        b.dst_pan = rx.pan_id();
        b.ack_request = Some(false);
        b.pending = frame_pending;
        b.security = security;
        Ok(b)
    }

    /// Thread 1.4 wake-up frame: multipurpose, both addresses required, no
    /// sequence number, no ack request, secured with `security` (Thread
    /// uses `EncMic32` with key ID mode 2), Rendezvous Time IE and
    /// Connection IE, no payload.
    pub fn wakeup(
        buf: &'a mut [u8],
        pan: PanId,
        dst: Address,
        src: Address,
        rendezvous_time: u16,
        connection: ConnectionIe,
        security: SecurityHeader,
    ) -> Self {
        let mut b = Self::new(buf)
            .frame_type(FrameType::Multipurpose)
            .version(FrameVersion::V2015)
            .suppress_sequence()
            .dst_pan(pan)
            .dst(dst)
            .src(src)
            .ack_request(false)
            .security(security)
            .header_ie(RendezvousTimeIe { rendezvous_time })
            .header_ie(connection);
        if dst.is_none() || src.is_none() {
            b.err = Some(Error::InvalidArgs);
        }
        b
    }

    /// Set the frame type.
    pub fn frame_type(mut self, t: FrameType) -> Self {
        self.frame_type = t;
        self
    }

    /// Set the frame version (ignored for multipurpose frames, which are
    /// always 2015-style).
    pub fn version(mut self, v: FrameVersion) -> Self {
        self.version = v;
        self
    }

    /// Set the sequence number.
    pub fn sequence(mut self, s: u8) -> Self {
        self.seq = Some(s);
        self
    }

    /// Suppress the sequence number (2015 and multipurpose frames only).
    pub fn suppress_sequence(mut self) -> Self {
        self.seq = None;
        self
    }

    /// Set the destination PAN ID.
    pub fn dst_pan(mut self, p: PanId) -> Self {
        self.dst_pan = Some(p);
        self
    }

    /// Set the source PAN ID.
    pub fn src_pan(mut self, p: PanId) -> Self {
        self.src_pan = Some(p);
        self
    }

    /// Set both PAN IDs (intra-PAN frame); the encoder omits whichever
    /// the PAN ID compression rules allow.
    pub fn pan_id(self, p: PanId) -> Self {
        self.dst_pan(p).src_pan(p)
    }

    /// Set the destination address.
    pub fn dst(mut self, a: Address) -> Self {
        self.dst = a;
        self
    }

    /// Set the source address.
    pub fn src(mut self, a: Address) -> Self {
        self.src = a;
        self
    }

    /// Force the Ack Request bit on or off.
    pub fn ack_request(mut self, on: bool) -> Self {
        self.ack_request = Some(on);
        self
    }

    /// Set the Frame Pending bit.
    pub fn frame_pending(mut self, on: bool) -> Self {
        self.pending = on;
        self
    }

    /// Enable security with the given auxiliary security header. The MIC
    /// area is reserved but left zero; encryption is done by the security
    /// layer.
    pub fn security(mut self, s: SecurityHeader) -> Self {
        self.security = Some(s);
        self
    }

    /// Remove all typed header IEs added so far.
    pub fn clear_header_ies(mut self) -> Self {
        self.ies = [None; MAX_HEADER_IES];
        self.n_ies = 0;
        self
    }

    /// Append a header IE (at most [`MAX_HEADER_IES`]).
    pub fn header_ie(mut self, ie: impl Into<HeaderIeValue<'a>>) -> Self {
        if self.n_ies < MAX_HEADER_IES {
            self.ies[self.n_ies] = Some(ie.into());
            self.n_ies += 1;
        } else {
            self.err = Some(Error::NoBufs);
        }
        self
    }

    /// Append already-encoded header IEs (after the typed ones).
    pub fn raw_header_ies(mut self, bytes: &'a [u8]) -> Self {
        self.raw_ies = bytes;
        self
    }

    /// Set the MAC command (required for, and only valid on,
    /// [`FrameType::MacCmd`]).
    pub fn command(mut self, c: MacCommand) -> Self {
        self.command = Some(c.id());
        self
    }

    /// Set a raw MAC command ID.
    pub fn command_id(mut self, id: u8) -> Self {
        self.command = Some(id);
        self
    }

    /// Set the MAC payload (copied into the buffer; for secured frames it
    /// is the plaintext the security layer will encrypt in place).
    pub fn payload(mut self, p: &'a [u8]) -> Self {
        self.payload = p;
        self
    }

    /// Serialize the frame, returning its length (without FCS).
    ///
    /// Errors: [`Error::NoBufs`] if the buffer is too small or too many IEs
    /// were added; [`Error::InvalidArgs`] for inconsistent settings (a PAN
    /// ID required by the addressing mode is missing, sequence suppression
    /// or IEs on a pre-2015 frame, security level 0, MAC command mismatch).
    pub fn build(self) -> Result<usize> {
        if let Some(e) = self.err {
            return Err(e);
        }
        let mp = self.frame_type == FrameType::Multipurpose;
        let version = if mp {
            FrameVersion::V2015
        } else {
            self.version
        };
        let is_2015 = version == FrameVersion::V2015;
        let has_ies = self.n_ies > 0 || !self.raw_ies.is_empty();
        if (self.seq.is_none() || has_ies) && !is_2015 {
            return Err(Error::InvalidArgs);
        }
        if (self.frame_type == FrameType::MacCmd) != self.command.is_some() {
            return Err(Error::InvalidArgs);
        }
        if self
            .security
            .is_some_and(|s| s.level == SecurityLevel::None)
        {
            return Err(Error::InvalidArgs);
        }

        let compress = if mp {
            self.dst_pan.is_some()
        } else {
            pan_id_compression(version, &self.dst, &self.src, self.dst_pan, self.src_pan)
        };
        let ack_request = self.ack_request.unwrap_or(
            !self.dst.is_none() && !self.dst.is_broadcast() && self.frame_type != FrameType::Ack,
        );
        let raw = assemble_fcf(
            self.frame_type,
            version,
            self.dst.mode(),
            self.src.mode(),
            Flags {
                pan_compression: compress,
                security: self.security.is_some(),
                seq_suppress: self.seq.is_none(),
                pending: self.pending,
                ack_request,
                ie: has_ies,
            },
        );
        let fcf = super::FrameControl::from_bits(raw)?;

        let mut w = Writer::new(self.buf);
        fcf.write(&mut w)?;
        if let Some(s) = self.seq {
            w.write_u8(s)?;
        }
        if fcf.dst_pan_present() {
            w.write_u16_le(self.dst_pan.ok_or(Error::InvalidArgs)?.0)?;
        }
        self.dst.write(&mut w)?;
        if fcf.src_pan_present() {
            w.write_u16_le(self.src_pan.ok_or(Error::InvalidArgs)?.0)?;
        }
        self.src.write(&mut w)?;
        if let Some(s) = &self.security {
            s.write(&mut w)?;
        }

        let mut last_is_termination = false;
        for ie in self.ies[..self.n_ies].iter().flatten() {
            ie.write(&mut w)?;
            last_is_termination = ie.is_termination();
        }
        if !self.raw_ies.is_empty() {
            w.write_slice(self.raw_ies)?;
            // Check the pre-encoded IEs for a trailing termination IE.
            for ie in super::HeaderIeIter::new(self.raw_ies) {
                last_is_termination = ie?.is_termination();
            }
        }
        let payload_follows = self.frame_type == FrameType::MacCmd || !self.payload.is_empty();
        if has_ies && payload_follows && !last_is_termination {
            HeaderIeValue::Termination2.write(&mut w)?;
        }
        if let Some(c) = self.command {
            w.write_u8(c)?;
        }
        w.write_slice(self.payload)?;
        if let Some(s) = &self.security {
            w.reserve(s.mic_len())?;
        }
        Ok(w.len())
    }
}

/// PAN ID compression decision (802.15.4-2015 Table 7-2 / OpenThread
/// `TxFrame::Info::PrepareHeadersIn`).
fn pan_id_compression(
    version: FrameVersion,
    dst: &Address,
    src: &Address,
    dst_pan: Option<PanId>,
    src_pan: Option<PanId>,
) -> bool {
    if version != FrameVersion::V2015 {
        return !src.is_none() && !dst.is_none() && (src_pan.is_none() || src_pan == dst_pan);
    }
    match (dst.is_none(), src.is_none()) {
        // Rows 1, 2.
        (true, true) => dst_pan.is_some(),
        // Rows 5, 6.
        (true, false) => src_pan.is_none(),
        // Rows 3, 4.
        (false, true) => dst_pan.is_none(),
        (false, false) => {
            if matches!(dst, Address::Extended(_)) && matches!(src, Address::Extended(_)) {
                // Rows 7, 8.
                dst_pan.is_none()
            } else {
                // Rows 9-14.
                src_pan.is_none() || src_pan == dst_pan
            }
        }
    }
}
