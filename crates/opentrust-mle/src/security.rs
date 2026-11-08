//! MLE message security (Thread 1.4.1 §4.2, §7.3; OpenThread
//! `Mle::ProcessMessageSecurity`, `Mle::HandleUdpReceive`,
//! `Mle::TxMessage::SendTo`).
//!
//! Secured MLE messages use security suite 0 ("802.15.4 security"), an
//! auxiliary security header and AES-CCM with a 4-byte MIC (security level 5,
//! encrypting command and TLVs):
//!
//! - **Aux header** (10 bytes): security control `0x15` (level 5, key ID mode
//!   2), frame counter (little endian), key source = key sequence (big
//!   endian), key index = `(key_sequence & 0x7f) + 1`.
//! - **Key**: the MLE key of the key sequence in the header.
//! - **Nonce**: extended address derived from the *sender's* link-local IID,
//!   frame counter (big endian), level 5
//!   ([`opentrust_core::crypto::nonce::mle_nonce`]).
//! - **AAD**: source IPv6 address || destination IPv6 address || aux header.
//!
//! [`secure`] and [`unsecure`] work in place on the UDP payload. The replay
//! and key-sequence policy of the *receiver* (OT `HandleUdpReceive`:
//! per-neighbor key sequence / MLE frame counter checks, `on_rx_key_sequence`)
//! is applied by the caller (see `neighbor::MleReplay`) using the values
//! reported in [`RxSecurity`].

use core::net::Ipv6Addr;

use opentrust_core::crypto::CryptoBackend;
use opentrust_core::crypto::ccm::{self, NONCE_LEN};
use opentrust_core::crypto::nonce::mle_nonce;
use opentrust_core::types::{MleKey, ipv6};
use opentrust_core::{Error, Result};
use opentrust_mac::security::KeyManager;

use crate::message::Command;
use crate::tlv::Tlvs;

/// Security suite byte: MLE security with 802.15.4-style aux header.
pub const SECURITY_SUITE_154: u8 = 0;
/// Security suite byte: no security (Discovery Request/Response).
pub const NO_SECURITY: u8 = 255;
/// Security control byte of the aux header: level 5, key ID mode 2.
pub const SECURITY_CONTROL: u8 = 0x15;
/// Length of the auxiliary security header.
pub const AUX_HEADER_LEN: usize = 10;
/// Length of the MIC.
pub const TAG_LEN: usize = 4;
/// Offset of the command byte in a secured message (suite + aux header).
pub const SECURED_PAYLOAD_OFFSET: usize = 1 + AUX_HEADER_LEN;
/// Default distance between the used and the persisted MLE frame counter
/// (OT `kStoreFrameCounterAhead`, shared with the MAC counter).
pub const DEFAULT_STORE_FRAME_COUNTER_AHEAD: u32 = 1000;

/// Auxiliary security header of a secured MLE message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct AuxHeader {
    /// MLE frame counter of the sender.
    pub frame_counter: u32,
    /// Key sequence the message is secured with.
    pub key_sequence: u32,
}

impl AuxHeader {
    /// Encode (10 bytes).
    pub fn to_bytes(&self) -> [u8; AUX_HEADER_LEN] {
        let mut b = [0u8; AUX_HEADER_LEN];
        b[0] = SECURITY_CONTROL;
        b[1..5].copy_from_slice(&self.frame_counter.to_le_bytes());
        b[5..9].copy_from_slice(&self.key_sequence.to_be_bytes());
        b[9] = ((self.key_sequence & 0x7f) as u8) + 1;
        b
    }

    /// Decode. [`Error::Parse`] if too short or the security control is not
    /// `0x15` (OT `IsSecurityControlValid`). The key index byte is not
    /// checked (OT ignores it too: the key source carries the sequence).
    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        let b: &[u8; AUX_HEADER_LEN] = b
            .get(..AUX_HEADER_LEN)
            .and_then(|s| s.try_into().ok())
            .ok_or(Error::Parse)?;
        if b[0] != SECURITY_CONTROL {
            return Err(Error::Parse);
        }
        Ok(Self {
            frame_counter: u32::from_le_bytes([b[1], b[2], b[3], b[4]]),
            key_sequence: u32::from_be_bytes([b[5], b[6], b[7], b[8]]),
        })
    }
}

/// Outgoing MLE frame counter with store-ahead persistence (OT
/// `KeyManager::mMleFrameCounter` / `MleFrameCounterUsed`).
///
/// Unlike the MAC counter it does not restart on a key sequence change. The
/// value `0xffffffff` is never used; once reached, [`take`](Self::take)
/// fails with [`Error::InvalidState`].
///
/// Persistence mirrors `KeyManager`: when [`needs_store`](Self::needs_store)
/// is `true`, write [`to_store`](Self::to_store) to
/// `NetworkInfo::mle_frame_counter` and call [`stored`](Self::stored). After
/// a reset, [`restore`](Self::restore) with the stored value so no counter
/// is ever reused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct MleFrameCounter {
    next: u32,
    stored: u32,
    ahead: u32,
}

impl Default for MleFrameCounter {
    fn default() -> Self {
        Self::new()
    }
}

impl MleFrameCounter {
    /// Counter 0, nothing persisted yet (so [`needs_store`](Self::needs_store)
    /// is `true`).
    pub const fn new() -> Self {
        Self {
            next: 0,
            stored: 0,
            ahead: DEFAULT_STORE_FRAME_COUNTER_AHEAD,
        }
    }

    /// Continue from a persisted value (which was stored ahead of use).
    pub fn restore(&mut self, stored: u32) {
        self.next = stored;
        self.stored = stored;
    }

    /// Set the store-ahead distance.
    pub fn set_store_ahead(&mut self, ahead: u32) {
        self.ahead = ahead;
    }

    /// The next counter to be used.
    pub const fn current(&self) -> u32 {
        self.next
    }

    /// `true` if no counter is left.
    pub const fn exhausted(&self) -> bool {
        self.next == u32::MAX
    }

    /// Use the next counter value.
    pub fn take(&mut self) -> Result<u32> {
        if self.exhausted() {
            return Err(Error::InvalidState);
        }
        let c = self.next;
        self.next += 1;
        Ok(c)
    }

    /// `true` if the counter must be persisted now: nothing is stored yet, or
    /// the counter reached the persisted value.
    pub const fn needs_store(&self) -> bool {
        self.next >= self.stored
    }

    /// Value to persist: next counter plus the store-ahead distance
    /// (saturating).
    pub const fn to_store(&self) -> u32 {
        self.next.saturating_add(self.ahead)
    }

    /// The caller persisted `value` (normally [`to_store`](Self::to_store)).
    pub fn stored(&mut self, value: u32) {
        self.stored = value;
    }
}

/// Security metadata of a successfully verified secured message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct RxSecurity {
    /// Key sequence from the aux header (the key used).
    pub key_sequence: u32,
    /// Sender's MLE frame counter.
    pub frame_counter: u32,
}

/// A decrypted, authenticated (or, for Discovery, unsecured) MLE message.
#[derive(Debug, Clone, Copy)]
pub struct RxMessage<'a> {
    /// `Some` for secured messages, `None` for suite 255.
    pub security: Option<RxSecurity>,
    /// Command.
    pub command: Command,
    /// The TLVs following the command byte.
    pub tlvs: Tlvs<'a>,
}

fn ccm_nonce(src: &Ipv6Addr, frame_counter: u32) -> [u8; NONCE_LEN] {
    mle_nonce(&ipv6::iid(src).to_ext_address(), frame_counter)
}

fn aad(src: &Ipv6Addr, dst: &Ipv6Addr, aux: &[u8; AUX_HEADER_LEN]) -> [u8; 42] {
    let mut a = [0u8; 42];
    a[..16].copy_from_slice(&src.octets());
    a[16..32].copy_from_slice(&dst.octets());
    a[32..].copy_from_slice(aux);
    a
}

/// Secure an MLE message in place.
///
/// `buf[..len]` is a message laid out by [`MleBuilder`](crate::message::MleBuilder):
/// suite byte, (for secured messages) a 10-byte header placeholder, command
/// and TLVs; `buf[len..len + 4]` must be available for the MIC. `src` is this
/// node's link-local address (it determines the nonce) and `dst` the
/// destination address of the UDP datagram. Takes the next counter from
/// `counter`, the key and key sequence from `keys`. Returns the final message
/// length (`len + 4`, or `len` for suite 255, which is left untouched).
///
/// The counter is consumed only after all argument checks passed.
pub fn secure<B: CryptoBackend>(
    keys: &KeyManager<B>,
    counter: &mut MleFrameCounter,
    buf: &mut [u8],
    len: usize,
    src: &Ipv6Addr,
    dst: &Ipv6Addr,
) -> Result<usize> {
    let msg = buf.get(..len).ok_or(Error::InvalidArgs)?;
    match msg.first() {
        Some(&NO_SECURITY) => return Ok(len),
        Some(&SECURITY_SUITE_154) => {}
        _ => return Err(Error::InvalidArgs),
    }
    // suite + aux + at least the command byte, and room for the MIC.
    if len < SECURED_PAYLOAD_OFFSET + 1 || buf.len() < len + TAG_LEN {
        return Err(Error::NoBufs);
    }
    let frame_counter = counter.take()?;
    let hdr = AuxHeader {
        frame_counter,
        key_sequence: keys.key_sequence(),
    }
    .to_bytes();
    buf[1..SECURED_PAYLOAD_OFFSET].copy_from_slice(&hdr);
    let (head, rest) = buf.split_at_mut(len);
    let payload = &mut head[SECURED_PAYLOAD_OFFSET..];
    let cipher = keys.backend().aes128(&keys.mle_key().0);
    ccm::encrypt(
        &cipher,
        &ccm_nonce(src, frame_counter),
        &aad(src, dst, &hdr),
        payload,
        &mut rest[..TAG_LEN],
    )?;
    Ok(len + TAG_LEN)
}

/// Verify and decrypt a received MLE message in place.
///
/// `buf` is the UDP payload; `src`/`dst` are the IPv6 source and destination
/// of the datagram (the caller has already checked the hop limit, see
/// [`MLE_HOP_LIMIT`](crate::consts::MLE_HOP_LIMIT)). The MLE key is chosen by
/// the key sequence in the aux header: the current one, a cached
/// previous/next one, or a temporarily derived one (OT
/// `GetTemporaryMleKey`; one HMAC per such message).
///
/// - suite 255: only Discovery Request/Response are accepted, anything else
///   is [`Error::Drop`]; `security` is `None`.
/// - any other suite than 0: [`Error::Parse`].
/// - [`Error::Parse`] if shorter than suite + aux + command + MIC or the
///   aux header is invalid; [`Error::Security`] on MIC mismatch (the
///   payload is zeroed); [`Error::Drop`] for an unassigned command.
///
/// Replay protection and key-sequence adoption are the caller's job; see the
/// module docs.
pub fn unsecure<'a, B: CryptoBackend>(
    keys: &KeyManager<B>,
    buf: &'a mut [u8],
    src: &Ipv6Addr,
    dst: &Ipv6Addr,
) -> Result<RxMessage<'a>> {
    let (&suite, rest) = buf.split_first().ok_or(Error::Parse)?;
    if suite == NO_SECURITY {
        let (&cmd, _) = rest.split_first().ok_or(Error::Parse)?;
        let command = Command::from_u8(cmd)
            .filter(|c| c.is_unsecured())
            .ok_or(Error::Drop)?;
        return Ok(RxMessage {
            security: None,
            command,
            tlvs: Tlvs::new(&buf[2..]),
        });
    }
    if suite != SECURITY_SUITE_154 {
        return Err(Error::Parse);
    }
    // aux header + command + tag
    if buf.len() < SECURED_PAYLOAD_OFFSET + 1 + TAG_LEN {
        return Err(Error::Parse);
    }
    let hdr_bytes: [u8; AUX_HEADER_LEN] = buf[1..SECURED_PAYLOAD_OFFSET]
        .try_into()
        .map_err(|_| Error::Parse)?;
    let hdr = AuxHeader::from_bytes(&hdr_bytes)?;
    let total = buf.len();
    let (body, tag) = buf.split_at_mut(total - TAG_LEN);
    let payload = &mut body[SECURED_PAYLOAD_OFFSET..];
    let nonce = ccm_nonce(src, hdr.frame_counter);
    let aad = aad(src, dst, &hdr_bytes);
    match keys.cached_keys(hdr.key_sequence) {
        Some(k) => open(keys.backend(), &k.mle_key, &nonce, &aad, payload, tag)?,
        None => {
            let k = keys.derive_keys(hdr.key_sequence);
            open(keys.backend(), &k.mle_key, &nonce, &aad, payload, tag)?
        }
    }
    let payload: &'a [u8] = payload;
    let command = Command::from_u8(payload[0]).ok_or(Error::Drop)?;
    Ok(RxMessage {
        security: Some(RxSecurity {
            key_sequence: hdr.key_sequence,
            frame_counter: hdr.frame_counter,
        }),
        command,
        tlvs: Tlvs::new(&payload[1..]),
    })
}

fn open<B: CryptoBackend>(
    backend: &B,
    key: &MleKey,
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    payload: &mut [u8],
    tag: &[u8],
) -> Result<()> {
    let cipher = backend.aes128(&key.0);
    ccm::decrypt(&cipher, nonce, aad, payload, tag)
}

#[cfg(test)]
#[path = "security_tests.rs"]
mod tests;
