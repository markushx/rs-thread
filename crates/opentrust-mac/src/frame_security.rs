//! Contract between the MAC data path and MAC frame security.
//!
//! The MAC state machine ([`crate`]'s `mac` module) calls a [`FrameSecurity`]
//! implementation to secure outgoing frames and to verify/decrypt incoming
//! frames in place. The real implementation (key management, key ID modes
//! 1/2, outgoing frame counter, CCM*) lives in the `security` module;
//! [`NoSecurity`] is a pass-through for tests and unsecured operation.
//!
//! Replay protection is *not* part of this contract: per-neighbor link frame
//! counters belong to the neighbor table (MLE). Implementations report the
//! received key sequence and frame counter in [`RxSecurityInfo`] so the
//! caller can check and update the neighbor's counters.

use opentrust_core::crypto::SecurityLevel;
use opentrust_core::types::ExtAddress;
use opentrust_core::{Error, Result};
use opentrust_platform::radio::{AckSecurity, MacKeys};

use crate::frame::{Frame, KeyIdMode};

/// Security parameters of a successfully verified incoming frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct RxSecurityInfo {
    /// Security level from the auxiliary security header.
    pub level: SecurityLevel,
    /// Key identifier mode used by the sender.
    pub key_id_mode: KeyIdMode,
    /// Thread key sequence the frame was secured with (key ID mode 1: derived
    /// from the key index relative to the current key sequence; mode 2: none).
    pub key_sequence: Option<u32>,
    /// Frame counter from the auxiliary security header.
    pub frame_counter: u32,
}

/// Secures and unsecures IEEE 802.15.4 frames in place.
///
/// `psdu` is always the frame **without FCS** (see [`crate::frame`]), as
/// produced by [`crate::frame::FrameBuilder`] (with a zero MIC placeholder)
/// or received from the radio.
pub trait FrameSecurity {
    /// Secure an outgoing frame whose security-enabled bit is set: fill in the
    /// frame counter (and key index for key ID mode 1), encrypt and write the
    /// MIC. `src_ext` is this device's extended address (CCM* nonce source).
    ///
    /// Frames without the security-enabled bit must be left unchanged
    /// (`Ok(())`).
    fn secure_tx(&mut self, psdu: &mut [u8], src_ext: &ExtAddress) -> Result<()>;

    /// Verify and decrypt an incoming frame in place. `src_ext` is the
    /// sender's extended address (from the frame or resolved from its short
    /// address via the neighbor table).
    ///
    /// Returns `Ok(None)` for frames without security, `Ok(Some(info))` on
    /// success, and [`Error::Security`] if the key is unknown or the MIC does
    /// not verify (the payload must then not be used).
    fn unsecure_rx(
        &mut self,
        psdu: &mut [u8],
        src_ext: &ExtAddress,
    ) -> Result<Option<RxSecurityInfo>>;

    /// The keys a radio that secures frames or enhanced ACKs itself needs
    /// (`Radio::set_mac_keys`); `None` if there are none (the default). The
    /// MAC compares it with what it last pushed and pushes changes.
    fn radio_keys(&self) -> Option<MacKeys> {
        None
    }

    /// The next outgoing MAC frame counter, for `Radio::set_mac_frame_counter`.
    fn current_frame_counter(&self) -> u32 {
        0
    }

    /// A radio secured a frame with `frame_counter` and key index
    /// `key_index` itself: move the outgoing counter past it.
    fn frame_counter_used(&mut self, frame_counter: u32, key_index: u8) {
        let _ = (frame_counter, key_index);
    }

    /// A radio secured an enhanced ACK itself (see
    /// [`PsduRxInfo::ack_security`](opentrust_platform::radio::PsduRxInfo::ack_security)).
    fn ack_frame_counter_used(&mut self, ack: &AckSecurity) {
        self.frame_counter_used(ack.frame_counter, ack.key_id);
    }

    /// Secure an enhanced ACK in software. The default is
    /// [`secure_tx`](Self::secure_tx); implementations that must keep the key
    /// index of the acked frame override it. Returns the security material
    /// used, if the implementation reports it.
    fn secure_enh_ack(
        &mut self,
        ack: &mut [u8],
        src_ext: &ExtAddress,
    ) -> Result<Option<AckSecurity>> {
        self.secure_tx(ack, src_ext).map(|()| None)
    }
}

impl<T: FrameSecurity + ?Sized> FrameSecurity for &mut T {
    fn secure_tx(&mut self, psdu: &mut [u8], src_ext: &ExtAddress) -> Result<()> {
        (**self).secure_tx(psdu, src_ext)
    }

    fn unsecure_rx(
        &mut self,
        psdu: &mut [u8],
        src_ext: &ExtAddress,
    ) -> Result<Option<RxSecurityInfo>> {
        (**self).unsecure_rx(psdu, src_ext)
    }

    fn radio_keys(&self) -> Option<MacKeys> {
        (**self).radio_keys()
    }

    fn current_frame_counter(&self) -> u32 {
        (**self).current_frame_counter()
    }

    fn frame_counter_used(&mut self, frame_counter: u32, key_index: u8) {
        (**self).frame_counter_used(frame_counter, key_index);
    }

    fn ack_frame_counter_used(&mut self, ack: &AckSecurity) {
        (**self).ack_frame_counter_used(ack);
    }

    fn secure_enh_ack(
        &mut self,
        ack: &mut [u8],
        src_ext: &ExtAddress,
    ) -> Result<Option<AckSecurity>> {
        (**self).secure_enh_ack(ack, src_ext)
    }
}

/// Pass-through security: unsecured frames are accepted unchanged, frames
/// with the security-enabled bit are rejected with [`Error::Security`].
#[derive(Debug, Default, Clone, Copy)]
pub struct NoSecurity;

impl FrameSecurity for NoSecurity {
    fn secure_tx(&mut self, psdu: &mut [u8], _src_ext: &ExtAddress) -> Result<()> {
        if Frame::parse(psdu)?.security_enabled() {
            return Err(Error::Security);
        }
        Ok(())
    }

    fn unsecure_rx(
        &mut self,
        psdu: &mut [u8],
        _src_ext: &ExtAddress,
    ) -> Result<Option<RxSecurityInfo>> {
        if Frame::parse(psdu)?.security_enabled() {
            return Err(Error::Security);
        }
        Ok(None)
    }
}
