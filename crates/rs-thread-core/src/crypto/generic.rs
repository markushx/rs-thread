//! HMAC-SHA256 and AES-CMAC built from the [`Sha256`] / [`Aes128`]
//! primitives, for backends whose hardware only offers those.

use core::fmt;

use zeroize::Zeroize;

use super::backend::{AES_BLOCK_LEN, Aes128, AesCmac, HmacSha256, SHA256_LEN, Sha256};

const SHA256_BLOCK_LEN: usize = 64;
const IPAD: u8 = 0x36;
const OPAD: u8 = 0x5c;

/// HMAC-SHA256 (RFC 2104) over any [`Sha256`] implementation.
pub struct GenericHmac<S: Sha256> {
    hasher: S,
    /// Key padded to the block length (K0 in FIPS 198-1).
    key: [u8; SHA256_BLOCK_LEN],
}

impl<S: Sha256> GenericHmac<S> {
    /// Key a new HMAC. `hasher` must be freshly started (empty).
    pub fn new(mut hasher: S, key: &[u8]) -> Self {
        let mut k0 = [0u8; SHA256_BLOCK_LEN];
        if key.len() > SHA256_BLOCK_LEN {
            hasher.update(key);
            let mut h = hasher.finalize_reset();
            k0[..SHA256_LEN].copy_from_slice(&h);
            h.zeroize();
        } else {
            k0[..key.len()].copy_from_slice(key);
        }
        let mut this = Self { hasher, key: k0 };
        k0.zeroize();
        this.start();
        this
    }

    fn absorb_padded_key(&mut self, pad: u8) {
        let mut block = self.key;
        for b in &mut block {
            *b ^= pad;
        }
        self.hasher.update(&block);
        block.zeroize();
    }

    fn start(&mut self) {
        self.absorb_padded_key(IPAD);
    }
}

impl<S: Sha256> HmacSha256 for GenericHmac<S> {
    fn update(&mut self, data: &[u8]) {
        self.hasher.update(data);
    }

    fn finalize_reset(&mut self) -> [u8; SHA256_LEN] {
        let mut inner = self.hasher.finalize_reset();
        self.absorb_padded_key(OPAD);
        self.hasher.update(&inner);
        inner.zeroize();
        let out = self.hasher.finalize_reset();
        self.start();
        out
    }
}

impl<S: Sha256> Drop for GenericHmac<S> {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

impl<S: Sha256> fmt::Debug for GenericHmac<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("GenericHmac(<redacted>)")
    }
}

/// AES-128-CMAC (RFC 4493 / NIST SP 800-38B) over any [`Aes128`].
pub struct GenericCmac<A: Aes128> {
    cipher: A,
    k1: [u8; AES_BLOCK_LEN],
    k2: [u8; AES_BLOCK_LEN],
    /// CBC chaining value.
    x: [u8; AES_BLOCK_LEN],
    /// Pending (not yet processed) bytes; the last block is held back
    /// until more data arrives, because it is treated specially.
    buf: [u8; AES_BLOCK_LEN],
    buf_len: usize,
}

/// Doubling in GF(2^128) as used for CMAC subkey generation.
fn dbl(b: &[u8; AES_BLOCK_LEN]) -> [u8; AES_BLOCK_LEN] {
    let v = u128::from_be_bytes(*b);
    // Constant time: the reduction mask is derived arithmetically.
    let msb = (v >> 127) as u8;
    let r = (v << 1) ^ u128::from(0x87u8 & msb.wrapping_neg());
    r.to_be_bytes()
}

impl<A: Aes128> GenericCmac<A> {
    /// Key a new CMAC with an expanded AES-128 cipher.
    pub fn new(cipher: A) -> Self {
        let mut l = [0u8; AES_BLOCK_LEN];
        cipher.encrypt_block(&mut l);
        let k1 = dbl(&l);
        let k2 = dbl(&k1);
        l.zeroize();
        Self {
            cipher,
            k1,
            k2,
            x: [0; AES_BLOCK_LEN],
            buf: [0; AES_BLOCK_LEN],
            buf_len: 0,
        }
    }

    fn process_buf(&mut self) {
        for (x, b) in self.x.iter_mut().zip(&self.buf) {
            *x ^= b;
        }
        self.cipher.encrypt_block(&mut self.x);
        self.buf_len = 0;
    }
}

impl<A: Aes128> AesCmac for GenericCmac<A> {
    fn update(&mut self, mut data: &[u8]) {
        while !data.is_empty() {
            if self.buf_len == AES_BLOCK_LEN {
                self.process_buf();
            }
            let n = (AES_BLOCK_LEN - self.buf_len).min(data.len());
            self.buf[self.buf_len..self.buf_len + n].copy_from_slice(&data[..n]);
            self.buf_len += n;
            data = &data[n..];
        }
    }

    fn finalize_reset(&mut self) -> [u8; AES_BLOCK_LEN] {
        let subkey = if self.buf_len == AES_BLOCK_LEN {
            &self.k1
        } else {
            self.buf[self.buf_len] = 0x80;
            self.buf[self.buf_len + 1..].fill(0);
            &self.k2
        };
        for ((x, b), k) in self.x.iter_mut().zip(&self.buf).zip(subkey) {
            *x ^= b ^ k;
        }
        self.cipher.encrypt_block(&mut self.x);
        let out = self.x;
        self.x.zeroize();
        self.buf.zeroize();
        self.buf_len = 0;
        out
    }
}

impl<A: Aes128> Drop for GenericCmac<A> {
    fn drop(&mut self) {
        self.k1.zeroize();
        self.k2.zeroize();
        self.x.zeroize();
        self.buf.zeroize();
    }
}

impl<A: Aes128> fmt::Debug for GenericCmac<A> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("GenericCmac(<redacted>)")
    }
}
