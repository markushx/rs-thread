//! DTLS 1.2 record layer (RFC 6347 §4.1): header codec, anti-replay window
//! and `AES_128_CCM_8` record protection (RFC 6655 / RFC 5288 §3).

use rs_thread_core::crypto::backend::Aes128;
use rs_thread_core::crypto::ccm::Ccm;
use rs_thread_core::{Error, Result};

/// `change_cipher_spec` content type.
pub const CT_CHANGE_CIPHER_SPEC: u8 = 20;
/// `alert` content type.
pub const CT_ALERT: u8 = 21;
/// `handshake` content type.
pub const CT_HANDSHAKE: u8 = 22;
/// `application_data` content type.
pub const CT_APPLICATION_DATA: u8 = 23;

/// DTLS 1.2 protocol version on the wire.
pub const DTLS_1_2: [u8; 2] = [0xfe, 0xfd];
/// DTLS 1.0 protocol version on the wire (accepted on epoch-0 records).
pub const DTLS_1_0: [u8; 2] = [0xfe, 0xff];

/// Record header length.
pub const HEADER_LEN: usize = 13;
/// Explicit nonce carried in each protected record.
pub const EXPLICIT_NONCE_LEN: usize = 8;
/// `AES_128_CCM_8` tag length.
pub const TAG_LEN: usize = 8;
/// Expansion of a protected record over its plaintext.
pub const AEAD_OVERHEAD: usize = EXPLICIT_NONCE_LEN + TAG_LEN;
/// Largest 48-bit record sequence number.
pub const MAX_SEQ: u64 = (1 << 48) - 1;
/// Largest record fragment (RFC 6347: 2^14 plus expansion).
pub const MAX_FRAGMENT_LEN: usize = (1 << 14) + 2048;

/// A parsed record header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    /// Content type.
    pub content_type: u8,
    /// Protocol version.
    pub version: [u8; 2],
    /// Epoch.
    pub epoch: u16,
    /// 48-bit sequence number.
    pub seq: u64,
    /// Length of the fragment.
    pub len: u16,
}

impl Header {
    /// `epoch || seq` as 8 bytes (the AEAD `seq_num`).
    pub fn seq_num(&self) -> [u8; 8] {
        seq_num(self.epoch, self.seq)
    }
}

/// `epoch(16) || sequence_number(48)`.
pub fn seq_num(epoch: u16, seq: u64) -> [u8; 8] {
    let mut out = seq.to_be_bytes();
    out[..2].copy_from_slice(&epoch.to_be_bytes());
    out
}

/// Split the first record off `datagram`: `(header, fragment, rest)`.
/// `None` if the header or fragment is truncated.
pub fn parse(datagram: &[u8]) -> Option<(Header, &[u8], &[u8])> {
    if datagram.len() < HEADER_LEN {
        return None;
    }
    let mut seq = [0u8; 8];
    seq[2..].copy_from_slice(&datagram[5..11]);
    let h = Header {
        content_type: datagram[0],
        version: [datagram[1], datagram[2]],
        epoch: u16::from_be_bytes([datagram[3], datagram[4]]),
        seq: u64::from_be_bytes(seq),
        len: u16::from_be_bytes([datagram[11], datagram[12]]),
    };
    let end = HEADER_LEN + h.len as usize;
    if datagram.len() < end {
        return None;
    }
    Some((h, &datagram[HEADER_LEN..end], &datagram[end..]))
}

/// Write a record header for a fragment of `len` bytes into `out[..13]`.
pub fn write_header(out: &mut [u8], content_type: u8, epoch: u16, seq: u64, len: usize) {
    out[0] = content_type;
    out[1..3].copy_from_slice(&DTLS_1_2);
    out[3..11].copy_from_slice(&seq_num(epoch, seq));
    out[11..13].copy_from_slice(&(len as u16).to_be_bytes());
}

/// Sliding anti-replay window of 64 records (RFC 6347 §4.1.2.6, as mbedTLS
/// `MBEDTLS_SSL_DTLS_ANTI_REPLAY`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ReplayWindow {
    /// Highest sequence number accepted so far (valid if `bitmap != 0`).
    top: u64,
    /// Bit `i` set: `top - i` was accepted.
    bitmap: u64,
}

impl ReplayWindow {
    /// An empty window.
    pub const fn new() -> Self {
        Self { top: 0, bitmap: 0 }
    }

    /// `true` if `seq` is new and not too old (call before authenticating;
    /// [`update`](Self::update) only after the record authenticated).
    pub fn check(&self, seq: u64) -> bool {
        if self.bitmap == 0 || seq > self.top {
            return true;
        }
        let off = self.top - seq;
        off < 64 && self.bitmap & (1 << off) == 0
    }

    /// Mark `seq` as received.
    pub fn update(&mut self, seq: u64) {
        if self.bitmap == 0 {
            self.top = seq;
            self.bitmap = 1;
        } else if seq > self.top {
            let shift = seq - self.top;
            self.bitmap = if shift >= 64 { 0 } else { self.bitmap << shift };
            self.bitmap |= 1;
            self.top = seq;
        } else {
            let off = self.top - seq;
            if off < 64 {
                self.bitmap |= 1 << off;
            }
        }
    }
}

/// `AES_128_CCM_8` record protection for one direction: the write key and
/// the 4-byte implicit IV (salt) from the key block.
pub struct RecordCipher<A: Aes128> {
    aes: A,
    salt: [u8; 4],
}

impl<A: Aes128> core::fmt::Debug for RecordCipher<A> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("RecordCipher")
    }
}

impl<A: Aes128> RecordCipher<A> {
    /// Cipher from an expanded key and the implicit IV.
    pub fn new(aes: A, salt: [u8; 4]) -> Self {
        Self { aes, salt }
    }

    fn nonce(&self, explicit: &[u8]) -> [u8; 12] {
        let mut n = [0u8; 12];
        n[..4].copy_from_slice(&self.salt);
        n[4..].copy_from_slice(explicit);
        n
    }

    fn aad(seq_num: &[u8; 8], content_type: u8, version: [u8; 2], len: usize) -> [u8; 13] {
        let mut a = [0u8; 13];
        a[..8].copy_from_slice(seq_num);
        a[8] = content_type;
        a[9..11].copy_from_slice(&version);
        a[11..].copy_from_slice(&(len as u16).to_be_bytes());
        a
    }

    /// Protect `plaintext` as a complete record (header included) into
    /// `out`; returns the record length. The explicit nonce is
    /// `epoch || seq`, as mbedTLS (unique per key since the sequence
    /// number never repeats within an epoch).
    pub fn seal(
        &self,
        content_type: u8,
        epoch: u16,
        seq: u64,
        plaintext: &[u8],
        out: &mut [u8],
    ) -> Result<usize> {
        let total = HEADER_LEN + AEAD_OVERHEAD + plaintext.len();
        if out.len() < total {
            return Err(Error::NoBufs);
        }
        let sn = seq_num(epoch, seq);
        write_header(out, content_type, epoch, seq, total - HEADER_LEN);
        out[HEADER_LEN..HEADER_LEN + EXPLICIT_NONCE_LEN].copy_from_slice(&sn);
        let body = &mut out[HEADER_LEN + EXPLICIT_NONCE_LEN..total];
        let (data, tag) = body.split_at_mut(plaintext.len());
        data.copy_from_slice(plaintext);
        let aad = Self::aad(&sn, content_type, DTLS_1_2, plaintext.len());
        let mut ccm = Ccm::with_nonce(&self.aes, &self.nonce(&sn), aad.len(), data.len(), TAG_LEN)?;
        ccm.aad(&aad)?;
        ccm.encrypt(data)?;
        ccm.finish(tag)?;
        Ok(total)
    }

    /// Authenticate and decrypt the fragment of a record with header `h`
    /// into `out`; returns the plaintext length. [`Error::Security`] if the
    /// tag does not verify (`out` is wiped then), [`Error::Parse`] if the
    /// fragment is too short, [`Error::NoBufs`] if `out` is too small.
    pub fn open(&self, h: &Header, fragment: &[u8], out: &mut [u8]) -> Result<usize> {
        if fragment.len() < AEAD_OVERHEAD {
            return Err(Error::Parse);
        }
        let len = fragment.len() - AEAD_OVERHEAD;
        if out.len() < len {
            return Err(Error::NoBufs);
        }
        let (explicit, rest) = fragment.split_at(EXPLICIT_NONCE_LEN);
        let (ct, tag) = rest.split_at(len);
        let data = &mut out[..len];
        data.copy_from_slice(ct);
        let aad = Self::aad(&h.seq_num(), h.content_type, h.version, len);
        let mut ccm = Ccm::with_nonce(&self.aes, &self.nonce(explicit), aad.len(), len, TAG_LEN)?;
        ccm.aad(&aad)?;
        ccm.decrypt(data)?;
        match ccm.verify(tag) {
            Ok(()) => Ok(len),
            Err(e) => {
                zeroize::Zeroize::zeroize(data);
                Err(e)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rs_thread_core::crypto::{CryptoBackend, SoftCrypto};

    #[test]
    fn replay_window() {
        let mut w = ReplayWindow::new();
        assert!(w.check(5));
        w.update(5);
        assert!(!w.check(5));
        assert!(w.check(4));
        assert!(w.check(6));
        w.update(100);
        assert!(!w.check(5)); // too old (100 - 5 >= 64)
        assert!(w.check(37));
        assert!(!w.check(36));
        w.update(37);
        assert!(!w.check(37));
        assert!(!w.check(100));
        w.update(200);
        assert!(w.check(199));
        assert!(!w.check(100));
    }

    #[test]
    fn header_roundtrip() {
        let mut b = [0u8; 20];
        write_header(&mut b, CT_HANDSHAKE, 1, 0x0102_0304_0506, 7);
        let (h, frag, rest) = parse(&b).unwrap();
        assert_eq!(h.content_type, CT_HANDSHAKE);
        assert_eq!(h.epoch, 1);
        assert_eq!(h.seq, 0x0102_0304_0506);
        assert_eq!(frag.len(), 7);
        assert!(rest.is_empty());
        assert!(parse(&b[..19]).is_none());
        assert!(parse(&b[..12]).is_none());
    }

    #[test]
    fn seal_open() {
        let aes = SoftCrypto.aes128(&[7; 16]);
        let c = RecordCipher::new(aes, [1, 2, 3, 4]);
        let mut rec = [0u8; 64];
        let n = c
            .seal(CT_APPLICATION_DATA, 1, 9, b"hello", &mut rec)
            .unwrap();
        assert_eq!(n, HEADER_LEN + AEAD_OVERHEAD + 5);
        assert_eq!(&rec[HEADER_LEN..HEADER_LEN + 8], &seq_num(1, 9));
        let (h, frag, _) = parse(&rec[..n]).unwrap();
        let mut out = [0u8; 32];
        assert_eq!(c.open(&h, frag, &mut out).unwrap(), 5);
        assert_eq!(&out[..5], b"hello");
        // Header fields are authenticated.
        let mut h2 = h;
        h2.seq = 10;
        assert_eq!(c.open(&h2, frag, &mut out), Err(Error::Security));
        let mut h3 = h;
        h3.content_type = CT_HANDSHAKE;
        assert_eq!(c.open(&h3, frag, &mut out), Err(Error::Security));
        // Wrong key.
        let other = RecordCipher::new(SoftCrypto.aes128(&[8; 16]), [1, 2, 3, 4]);
        assert_eq!(other.open(&h, frag, &mut out), Err(Error::Security));
        assert_eq!(&out[..5], &[0; 5]);
        assert_eq!(c.open(&h, &frag[..15], &mut out), Err(Error::Parse));
    }
}
