//! MAC frame security (Thread 1.4.1 §7.1.3–§7.2, IEEE 802.15.4-2015 §9).
//!
//! - [`KeyManager`]: network key, key sequence (`thrKeySequenceCounter`),
//!   cached MAC/MLE keys of the previous/current/next key sequence, the
//!   outgoing MAC frame counter (with "store ahead" persistence signalling),
//!   key rotation and the key switch guard (sans-IO: time is passed in as
//!   [`Instant`](rs_thread_core::time::Instant)). It implements
//!   [`FrameSecurity`](crate::frame_security::FrameSecurity) for key ID mode 1
//!   (network-key derived MAC key), key ID mode 2 (the well-known
//!   filtering key) and key ID mode 0 (the single-use KEK of the Joiner
//!   Entrust exchange, [`KeyManager::set_kek`]), and secures/verifies
//!   enhanced ACKs.
//! - [`LinkFrameCounters`]: per-neighbor replay protection (incoming key
//!   sequence, link frame counter, enhanced-ACK frame counter) for the
//!   neighbor table.
//! - [`seal_psdu`] / [`open_psdu`]: the CCM* step on a whole PSDU for a given
//!   key and nonce source, as used by [`KeyManager`].
//!
//! # Data path
//!
//! Transmit: build the frame with a [`SecurityHeader`](crate::frame::SecurityHeader)
//! (any frame counter / key index; they are overwritten) and call
//! [`FrameSecurity::secure_tx`](crate::frame_security::FrameSecurity::secure_tx).
//! Every call consumes a fresh frame counter. A plain MAC retransmission
//! resends the already secured PSDU unchanged (as OpenThread does for a
//! frame whose header is "updated"); a CSL receiver that updates the CSL IE
//! of a retransmission re-secures the *unsecured* frame again, which gives it
//! a new frame counter as required by Thread §3.2.6.3.7.
//!
//! Receive: [`FrameSecurity::unsecure_rx`](crate::frame_security::FrameSecurity::unsecure_rx),
//! then, for a frame from a valid neighbor, [`LinkFrameCounters::check_and_update`]
//! and, if that succeeded and the frame's key sequence is newer than ours,
//! [`KeyManager::on_rx_key_sequence`] (OpenThread `Mac::ProcessReceiveSecurity`).
//!
//! # Radios with transmit security
//!
//! A radio with `Capabilities::TRANSMIT_SEC` (or one that secures enhanced
//! ACKs itself) needs the keys: push [`KeyManager::mac_keys`] with
//! `Radio::set_mac_keys` and [`KeyManager::frame_counter`] with
//! `Radio::set_mac_frame_counter(.., false)` after every key change (the
//! methods that change keys return `true`), and report the counters the
//! radio consumed with [`KeyManager::frame_counter_used`] /
//! [`KeyManager::ack_frame_counter_used`].

mod key_manager;
mod replay;

#[cfg(test)]
mod tests;

pub use key_manager::{
    DEFAULT_KEY_ROTATION_HOURS, DEFAULT_STORE_FRAME_COUNTER_AHEAD, KEY_ID_MODE2_INDEX,
    KEY_ID_MODE2_SOURCE, KEY_SWITCH_GUARD_PERCENT, KeyManager, KeySeqUpdate,
    MIN_KEY_ROTATION_HOURS, RxLevelPolicy,
};
pub use replay::LinkFrameCounters;

use rs_thread_core::crypto::Aes128;
use rs_thread_core::crypto::ccm::{open_frame, seal_frame};
use rs_thread_core::crypto::nonce::mac_nonce;
use rs_thread_core::types::ExtAddress;
use rs_thread_core::{Error, Result};

use crate::frame::{Frame, FrameMut, KeyIdentifier};

/// Secure `psdu` (without FCS) in place with `cipher`, using the security
/// level and frame counter already in its auxiliary security header and
/// `nonce_source` as the CCM* nonce address. Encrypting levels encrypt the
/// payload; all levels except `Enc` write the MIC.
///
/// [`Error::InvalidArgs`] if the frame is not secured or its frame counter
/// is suppressed (the 802.15.4 TSCH ASN nonce is not supported).
pub fn seal_psdu<A: Aes128>(cipher: &A, psdu: &mut [u8], nonce_source: &ExtAddress) -> Result<()> {
    let (level, fc) = {
        let f = Frame::parse(psdu)?;
        let s = f.security_header().ok_or(Error::InvalidArgs)?;
        if s.asn_in_nonce {
            return Err(Error::InvalidArgs);
        }
        (s.level, s.frame_counter.ok_or(Error::InvalidArgs)?)
    };
    let nonce = mac_nonce(nonce_source, fc, level);
    let mut fm = FrameMut::new(psdu)?;
    let p = fm.parts_mut()?;
    seal_frame(cipher, &nonce, level, p.header, p.payload, p.mic)
}

/// Verify (and decrypt) `psdu` (without FCS) in place: inverse of
/// [`seal_psdu`].
///
/// [`Error::Security`] if the frame is not secured, has no frame counter,
/// or the MIC does not verify; an encrypted payload is wiped in the latter
/// case, so no unauthenticated plaintext is left behind.
pub fn open_psdu<A: Aes128>(cipher: &A, psdu: &mut [u8], nonce_source: &ExtAddress) -> Result<()> {
    let (level, fc) = {
        let f = Frame::parse(psdu)?;
        let s = f.security_header().ok_or(Error::Security)?;
        if s.asn_in_nonce {
            return Err(Error::Security);
        }
        (s.level, s.frame_counter.ok_or(Error::Security)?)
    };
    let nonce = mac_nonce(nonce_source, fc, level);
    let mut fm = FrameMut::new(psdu)?;
    let p = fm.parts_mut()?;
    open_frame(cipher, &nonce, level, p.header, p.payload, p.mic).map_err(|_| Error::Security)
}

/// Overwrite frame counter and key identifier of the auxiliary security
/// header of an already validated `psdu` (without FCS). The key identifier
/// must have the mode already present in the frame; [`Error::InvalidArgs`]
/// otherwise or for a frame without security.
pub fn write_aux_header(psdu: &mut [u8], frame_counter: u32, key: &KeyIdentifier) -> Result<()> {
    let f = Frame::parse(psdu)?;
    let s = f.security_header().ok_or(Error::InvalidArgs)?;
    if s.frame_counter.is_none() || s.key.mode() != key.mode() {
        return Err(Error::InvalidArgs);
    }
    // Auxiliary security header: control (1) | frame counter (4) | key id.
    let at = f.frame_control().addressing_len() + 1;
    psdu[at..at + 4].copy_from_slice(&frame_counter.to_le_bytes());
    let at = at + 4;
    let src = key.source();
    psdu[at..at + src.len()].copy_from_slice(src);
    if let Some(i) = key.index() {
        psdu[at + src.len()] = i;
    }
    Ok(())
}
