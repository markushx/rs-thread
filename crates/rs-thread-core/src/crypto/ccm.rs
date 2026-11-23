//! AES-128-CCM* (IEEE 802.15.4-2015 Annex B, RFC 3610) with L = 2 and a
//! 13-byte nonce ([`Ccm::new`]), or any nonce length from 7 to 13 bytes
//! ([`Ccm::with_nonce`], e.g. the 12-byte RFC 6655 nonce of DTLS
//! `AES_128_CCM_8`, L = 3).
//!
//! CCM* extends CCM with an authentication-tag length M = 0 (encryption
//! only). Supported tag lengths are 0, 4, 6, 8, 10, 12, 14 and 16 bytes;
//! Thread uses 0/4/8/16 for MAC frames (security levels 4/5/6/7 and the
//! MIC-only levels 1/2/3), 4 for MLE and 8 for DTLS (`AES_128_CCM_8`).
//!
//! [`Ccm`] is incremental, so the authenticated data and the payload may be
//! fed in several pieces (e.g. MLE's `src IPv6 || dst IPv6 || aux header`,
//! or a message stored in chunks); the total lengths must be known up front.
//! [`encrypt`] / [`decrypt`] are one-shot helpers, and [`seal_frame`] /
//! [`open_frame`] apply an 802.15.4 [`SecurityLevel`].
//!
//! With M = 0 no CBC-MAC is computed: there is nothing to authenticate, and
//! the additional data is ignored (only its length is checked).

use core::fmt;

use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use super::backend::{AES_BLOCK_LEN, Aes128};
use crate::error::{Error, Result};

/// Nonce length in bytes (15 - L with L = 2).
pub const NONCE_LEN: usize = 13;
/// Maximum tag (MIC) length in bytes.
pub const MAX_TAG_LEN: usize = 16;
/// Maximum payload length in bytes (L = 2).
pub const MAX_MESSAGE_LEN: usize = 0xffff;

/// Minimum nonce length accepted by [`Ccm::with_nonce`] (L = 8).
pub const MIN_NONCE_LEN: usize = 7;

/// IEEE 802.15.4 security level (Auxiliary Security Header, bits 0..2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(u8)]
pub enum SecurityLevel {
    /// No security.
    None = 0,
    /// Authentication only, 4-byte MIC.
    Mic32 = 1,
    /// Authentication only, 8-byte MIC.
    Mic64 = 2,
    /// Authentication only, 16-byte MIC.
    Mic128 = 3,
    /// Encryption only (deprecated in 802.15.4-2015).
    Enc = 4,
    /// Encryption and 4-byte MIC (used by Thread MAC and MLE).
    EncMic32 = 5,
    /// Encryption and 8-byte MIC.
    EncMic64 = 6,
    /// Encryption and 16-byte MIC.
    EncMic128 = 7,
}

impl SecurityLevel {
    /// Decode from the low three bits of a security control field.
    pub const fn from_bits(bits: u8) -> Self {
        match bits & 0x07 {
            0 => Self::None,
            1 => Self::Mic32,
            2 => Self::Mic64,
            3 => Self::Mic128,
            4 => Self::Enc,
            5 => Self::EncMic32,
            6 => Self::EncMic64,
            _ => Self::EncMic128,
        }
    }

    /// The numeric level (0..=7).
    pub const fn value(self) -> u8 {
        self as u8
    }

    /// Length of the MIC (CCM* M) in bytes.
    pub const fn mic_len(self) -> usize {
        match self.value() & 0x03 {
            0 => 0,
            1 => 4,
            2 => 8,
            _ => 16,
        }
    }

    /// `true` if the payload is encrypted.
    pub const fn is_encrypted(self) -> bool {
        self.value() & 0x04 != 0
    }
}

/// Which way [`Ccm::process`] runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Direction {
    Encrypt,
    Decrypt,
}

/// Incremental CCM* computation for one message.
///
/// Call [`aad`](Self::aad) until all additional data is absorbed, then
/// [`encrypt`](Self::encrypt) or [`decrypt`](Self::decrypt) the payload
/// (possibly in pieces), then [`finish`](Self::finish) (sender) or
/// [`verify`](Self::verify) (receiver).
///
/// When decrypting incrementally, the plaintext is produced before the tag
/// is checked: discard it unless [`verify`](Self::verify) succeeds.
pub struct Ccm<'a, A: Aes128> {
    cipher: &'a A,
    /// CBC-MAC state.
    mac: [u8; AES_BLOCK_LEN],
    /// Bytes XORed into `mac` since the last block encryption (1..=16 once
    /// data has been absorbed; the block is encrypted lazily).
    mac_pos: usize,
    /// Counter block A_i.
    ctr: [u8; AES_BLOCK_LEN],
    /// Key stream block S_i.
    pad: [u8; AES_BLOCK_LEN],
    pad_pos: usize,
    aad_left: usize,
    msg_left: usize,
    tag_len: usize,
}

impl<'a, A: Aes128> Ccm<'a, A> {
    /// Start a CCM* computation.
    ///
    /// Fails with [`Error::InvalidArgs`] for an unsupported `tag_len` or a
    /// payload longer than [`MAX_MESSAGE_LEN`].
    pub fn new(
        cipher: &'a A,
        nonce: &[u8; NONCE_LEN],
        aad_len: usize,
        msg_len: usize,
        tag_len: usize,
    ) -> Result<Self> {
        Self::init(cipher, nonce, aad_len, msg_len, tag_len)
    }

    /// Start a CCM* computation with a nonce of [`MIN_NONCE_LEN`] to
    /// [`NONCE_LEN`] bytes (L = 15 - nonce length). The payload is still
    /// limited to [`MAX_MESSAGE_LEN`] bytes.
    pub fn with_nonce(
        cipher: &'a A,
        nonce: &[u8],
        aad_len: usize,
        msg_len: usize,
        tag_len: usize,
    ) -> Result<Self> {
        if !(MIN_NONCE_LEN..=NONCE_LEN).contains(&nonce.len()) {
            return Err(Error::InvalidArgs);
        }
        Self::init(cipher, nonce, aad_len, msg_len, tag_len)
    }

    fn init(
        cipher: &'a A,
        nonce: &[u8],
        aad_len: usize,
        msg_len: usize,
        tag_len: usize,
    ) -> Result<Self> {
        // Size of the length field L.
        let l = (15 - nonce.len()) as u8;
        let tag_ok = tag_len == 0 || (tag_len % 2 == 0 && (4..=MAX_TAG_LEN).contains(&tag_len));
        if !tag_ok || msg_len > MAX_MESSAGE_LEN || u32::try_from(aad_len).is_err() {
            return Err(Error::InvalidArgs);
        }

        let mut this = Self {
            cipher,
            mac: [0; AES_BLOCK_LEN],
            mac_pos: 0,
            ctr: [0; AES_BLOCK_LEN],
            pad: [0; AES_BLOCK_LEN],
            pad_pos: AES_BLOCK_LEN,
            aad_left: aad_len,
            msg_left: msg_len,
            tag_len,
        };

        // A_0 = flags(L-1) || nonce || 0
        this.ctr[0] = l - 1;
        this.ctr[1..=nonce.len()].copy_from_slice(nonce);

        if this.authenticates() {
            // B_0 = flags || nonce || l(m)
            let m_prime = ((tag_len - 2) / 2) as u8;
            let adata = u8::from(aad_len > 0);
            this.mac[0] = (adata << 6) | (m_prime << 3) | (l - 1);
            this.mac[1..=nonce.len()].copy_from_slice(nonce);
            // l(m) in the last L bytes: msg_len <= 0xffff, so any length
            // bytes above the last two stay zero.
            this.mac[14..].copy_from_slice(&(msg_len as u16).to_be_bytes());
            cipher.encrypt_block(&mut this.mac);

            // l(a) encoding (RFC 3610 §2.2).
            if aad_len > 0 {
                if aad_len < 0xff00 {
                    let l = (aad_len as u16).to_be_bytes();
                    this.mac[0] ^= l[0];
                    this.mac[1] ^= l[1];
                    this.mac_pos = 2;
                } else {
                    this.mac[0] ^= 0xff;
                    this.mac[1] ^= 0xfe;
                    for (m, l) in this.mac[2..6]
                        .iter_mut()
                        .zip((aad_len as u32).to_be_bytes())
                    {
                        *m ^= l;
                    }
                    this.mac_pos = 6;
                }
            }
        }
        Ok(this)
    }

    fn authenticates(&self) -> bool {
        self.tag_len > 0
    }

    fn absorb(&mut self, data: &[u8]) {
        for &b in data {
            if self.mac_pos == AES_BLOCK_LEN {
                self.cipher.encrypt_block(&mut self.mac);
                self.mac_pos = 0;
            }
            self.mac[self.mac_pos] ^= b;
            self.mac_pos += 1;
        }
    }

    /// Zero-pad and encrypt the current partial CBC-MAC block, if any.
    fn close_mac_block(&mut self) {
        if self.mac_pos != 0 {
            self.cipher.encrypt_block(&mut self.mac);
            self.mac_pos = 0;
        }
    }

    /// Absorb additional authenticated data.
    pub fn aad(&mut self, data: &[u8]) -> Result<()> {
        if data.len() > self.aad_left {
            return Err(Error::InvalidArgs);
        }
        self.aad_left -= data.len();
        if self.authenticates() {
            self.absorb(data);
            if self.aad_left == 0 {
                self.close_mac_block();
            }
        }
        Ok(())
    }

    fn process(&mut self, data: &mut [u8], dir: Direction) -> Result<()> {
        if self.aad_left != 0 {
            return Err(Error::InvalidState);
        }
        if data.len() > self.msg_left {
            return Err(Error::InvalidArgs);
        }
        self.msg_left -= data.len();
        let auth = self.authenticates();
        for b in data.iter_mut() {
            if self.pad_pos == AES_BLOCK_LEN {
                // Increment the 16-bit counter. msg_len <= 0xffff bytes means
                // at most 4096 blocks, so it never wraps.
                let c = u16::from_be_bytes([self.ctr[14], self.ctr[15]]).wrapping_add(1);
                self.ctr[14..].copy_from_slice(&c.to_be_bytes());
                self.pad = self.ctr;
                self.cipher.encrypt_block(&mut self.pad);
                self.pad_pos = 0;
            }
            let ks = self.pad[self.pad_pos];
            self.pad_pos += 1;
            let plain = match dir {
                Direction::Encrypt => {
                    let p = *b;
                    *b = p ^ ks;
                    p
                }
                Direction::Decrypt => {
                    *b ^= ks;
                    *b
                }
            };
            if auth {
                self.absorb(&[plain]);
            }
        }
        if auth && self.msg_left == 0 {
            self.close_mac_block();
        }
        Ok(())
    }

    /// Encrypt (and authenticate) payload bytes in place.
    pub fn encrypt(&mut self, data: &mut [u8]) -> Result<()> {
        self.process(data, Direction::Encrypt)
    }

    /// Decrypt (and authenticate) payload bytes in place.
    pub fn decrypt(&mut self, data: &mut [u8]) -> Result<()> {
        self.process(data, Direction::Decrypt)
    }

    /// Compute the tag U = T xor first-M-bytes(S_0).
    fn tag(&mut self) -> Result<[u8; MAX_TAG_LEN]> {
        if self.aad_left != 0 || self.msg_left != 0 {
            return Err(Error::InvalidState);
        }
        let mut s0 = self.ctr;
        s0[14] = 0;
        s0[15] = 0;
        self.cipher.encrypt_block(&mut s0);
        let mut tag = [0u8; MAX_TAG_LEN];
        for ((t, m), s) in tag.iter_mut().zip(&self.mac).zip(&s0).take(self.tag_len) {
            *t = m ^ s;
        }
        s0.zeroize();
        Ok(tag)
    }

    /// Finish and write the tag (exactly the configured tag length) to `tag`.
    pub fn finish(mut self, tag: &mut [u8]) -> Result<()> {
        if tag.len() != self.tag_len {
            return Err(Error::InvalidArgs);
        }
        let t = self.tag()?;
        tag.copy_from_slice(&t[..self.tag_len]);
        Ok(())
    }

    /// Finish and compare the computed tag with `tag` in constant time.
    ///
    /// Returns [`Error::Security`] on mismatch.
    pub fn verify(mut self, tag: &[u8]) -> Result<()> {
        if tag.len() != self.tag_len {
            return Err(Error::InvalidArgs);
        }
        let t = self.tag()?;
        if bool::from(t[..self.tag_len].ct_eq(tag)) {
            Ok(())
        } else {
            Err(Error::Security)
        }
    }
}

impl<A: Aes128> Drop for Ccm<'_, A> {
    fn drop(&mut self) {
        self.mac.zeroize();
        self.pad.zeroize();
    }
}

impl<A: Aes128> fmt::Debug for Ccm<'_, A> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ccm")
            .field("aad_left", &self.aad_left)
            .field("msg_left", &self.msg_left)
            .field("tag_len", &self.tag_len)
            .finish_non_exhaustive()
    }
}

/// One-shot CCM* encryption: encrypts `data` in place and writes a tag of
/// `tag.len()` bytes.
pub fn encrypt<A: Aes128>(
    cipher: &A,
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    data: &mut [u8],
    tag: &mut [u8],
) -> Result<()> {
    let mut ccm = Ccm::new(cipher, nonce, aad.len(), data.len(), tag.len())?;
    ccm.aad(aad)?;
    ccm.encrypt(data)?;
    ccm.finish(tag)
}

/// One-shot CCM* decryption: decrypts `data` in place and verifies `tag`.
///
/// On [`Error::Security`] the contents of `data` are wiped (zeroed) so that
/// unauthenticated plaintext cannot be used by mistake.
pub fn decrypt<A: Aes128>(
    cipher: &A,
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    data: &mut [u8],
    tag: &[u8],
) -> Result<()> {
    let mut ccm = Ccm::new(cipher, nonce, aad.len(), data.len(), tag.len())?;
    ccm.aad(aad)?;
    ccm.decrypt(data)?;
    ccm.verify(tag).inspect_err(|_| data.zeroize())
}

/// Secure an IEEE 802.15.4 frame (outgoing frame security, CCM* part).
///
/// `header` is the MAC header including the auxiliary security header,
/// `payload` the MAC payload (private payload field). For encrypting levels
/// the payload is encrypted in place and `header` is the authenticated data;
/// for MIC-only levels `header || payload` is authenticated and the payload
/// stays in clear. `mic` must be [`SecurityLevel::mic_len`] bytes long.
/// [`SecurityLevel::None`] is rejected with [`Error::InvalidArgs`].
pub fn seal_frame<A: Aes128>(
    cipher: &A,
    nonce: &[u8; NONCE_LEN],
    level: SecurityLevel,
    header: &[u8],
    payload: &mut [u8],
    mic: &mut [u8],
) -> Result<()> {
    if level == SecurityLevel::None || mic.len() != level.mic_len() {
        return Err(Error::InvalidArgs);
    }
    if level.is_encrypted() {
        encrypt(cipher, nonce, header, payload, mic)
    } else {
        let mut ccm = Ccm::new(cipher, nonce, header.len() + payload.len(), 0, mic.len())?;
        ccm.aad(header)?;
        ccm.aad(payload)?;
        ccm.finish(mic)
    }
}

/// Unsecure an IEEE 802.15.4 frame (incoming frame security, CCM* part).
///
/// Inverse of [`seal_frame`]. Returns [`Error::Security`] if the MIC does not
/// match (an encrypted payload is wiped in that case).
pub fn open_frame<A: Aes128>(
    cipher: &A,
    nonce: &[u8; NONCE_LEN],
    level: SecurityLevel,
    header: &[u8],
    payload: &mut [u8],
    mic: &[u8],
) -> Result<()> {
    if level == SecurityLevel::None || mic.len() != level.mic_len() {
        return Err(Error::InvalidArgs);
    }
    if level.is_encrypted() {
        decrypt(cipher, nonce, header, payload, mic)
    } else {
        let mut ccm = Ccm::new(cipher, nonce, header.len() + payload.len(), 0, mic.len())?;
        ccm.aad(header)?;
        ccm.aad(payload)?;
        ccm.verify(mic)
    }
}
