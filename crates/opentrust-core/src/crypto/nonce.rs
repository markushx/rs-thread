//! CCM* nonce construction for MAC frames and MLE messages.
//!
//! Both use the IEEE 802.15.4 CCM* nonce (802.15.4-2015 §9.3.2.2):
//! `source extended address (8, big-endian) || frame counter (4, big-endian)
//! || security level (1)`.
//!
//! - MAC (Thread §7.2): the extended address of the originating node; for
//!   Key ID Mode 2 frames the fixed [`KEY_ID_MODE2_EXT_ADDRESS`] instead
//!   (§7.2.1.3).
//! - MLE (Thread §7.3, OpenThread `Mle::ProcessMessageSecurity`): the
//!   extended address derived from the sender's link-local IID
//!   ([`crate::types::Iid::to_ext_address`]), the MLE frame counter and
//!   security level 5 ([`SecurityLevel::EncMic32`]).
//!
//! DTLS record nonces (§7.4.7.10.1, RFC 6655) are not built here.

use super::ccm::{NONCE_LEN, SecurityLevel};
use crate::types::{ExtAddress, MacKey};

/// Extended address used in the nonce of MAC Key ID Mode 2 frames
/// (Thread §7.2.1.3, Table 7-16: `0x3506feb823d48712`).
pub const KEY_ID_MODE2_EXT_ADDRESS: ExtAddress =
    ExtAddress([0x35, 0x06, 0xfe, 0xb8, 0x23, 0xd4, 0x87, 0x12]);

/// The well-known MAC Key ID Mode 2 key (Key Source `0xffffffff`, Key Index
/// `0xff`; Thread §7.2.2.2.1). It provides filtering, not security.
pub const KEY_ID_MODE2_KEY: MacKey = MacKey([
    0x78, 0x58, 0x16, 0x86, 0xfd, 0xb4, 0x58, 0x0f, 0xb0, 0x92, 0x54, 0x6a, 0xec, 0xbd, 0x15, 0x66,
]);

/// Security level of secured MLE messages.
pub const MLE_SECURITY_LEVEL: SecurityLevel = SecurityLevel::EncMic32;

/// Build an 802.15.4 CCM* nonce.
pub fn ccm_nonce(source: &ExtAddress, frame_counter: u32, level: SecurityLevel) -> [u8; NONCE_LEN] {
    let mut n = [0u8; NONCE_LEN];
    n[..8].copy_from_slice(source.as_bytes());
    n[8..12].copy_from_slice(&frame_counter.to_be_bytes());
    n[12] = level.value();
    n
}

/// Nonce for a MAC frame from `source` (Key ID Mode 0/1).
pub fn mac_nonce(source: &ExtAddress, frame_counter: u32, level: SecurityLevel) -> [u8; NONCE_LEN] {
    ccm_nonce(source, frame_counter, level)
}

/// Nonce for a MAC Key ID Mode 2 frame.
pub fn mac_mode2_nonce(frame_counter: u32, level: SecurityLevel) -> [u8; NONCE_LEN] {
    ccm_nonce(&KEY_ID_MODE2_EXT_ADDRESS, frame_counter, level)
}

/// Nonce for a secured MLE message sent by `sender`.
pub fn mle_nonce(sender: &ExtAddress, frame_counter: u32) -> [u8; NONCE_LEN] {
    ccm_nonce(sender, frame_counter, MLE_SECURITY_LEVEL)
}
