//! Software crypto backend on the RustCrypto crates (`aes`, `sha2`, `hmac`,
//! `cmac`). Enabled by the `soft-crypto` feature (on by default).
//!
//! The `aes` crate uses constant-time bitsliced software AES on targets
//! without AES instructions (Cortex-M, RISC-V) and AES-NI/ARMv8 crypto
//! extensions on hosts where available.

use core::fmt;

use aes::cipher::{BlockCipherEncrypt, KeyInit};
use hmac::Mac;
use sha2::Digest;

use super::backend::{
    AES_BLOCK_LEN, AES128_KEY_LEN, Aes128, AesCmac, CryptoBackend, HmacSha256, SHA256_LEN, Sha256,
};

/// Software [`CryptoBackend`] based on RustCrypto.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SoftCrypto;

/// Software AES-128 (key schedule is zeroized on drop).
#[derive(Clone)]
pub struct SoftAes128(aes::Aes128);

/// Software SHA-256.
#[derive(Clone, Default)]
pub struct SoftSha256(sha2::Sha256);

/// Software HMAC-SHA256.
#[derive(Clone)]
pub struct SoftHmacSha256(hmac::HmacReset<sha2::Sha256>);

/// Software AES-128-CMAC.
#[derive(Clone)]
pub struct SoftAesCmac(cmac::Cmac<aes::Aes128>);

macro_rules! redacted_debug {
    ($($t:ty),*) => {$(
        impl fmt::Debug for $t {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(concat!(stringify!($t), "(<redacted>)"))
            }
        }
    )*};
}
redacted_debug!(SoftAes128, SoftSha256, SoftHmacSha256, SoftAesCmac);

impl Aes128 for SoftAes128 {
    fn encrypt_block(&self, block: &mut [u8; AES_BLOCK_LEN]) {
        self.0.encrypt_block(block.into());
    }
}

impl Sha256 for SoftSha256 {
    fn update(&mut self, data: &[u8]) {
        Digest::update(&mut self.0, data);
    }

    fn finalize_reset(&mut self) -> [u8; SHA256_LEN] {
        self.0.finalize_reset().into()
    }
}

impl HmacSha256 for SoftHmacSha256 {
    fn update(&mut self, data: &[u8]) {
        Mac::update(&mut self.0, data);
    }

    fn finalize_reset(&mut self) -> [u8; SHA256_LEN] {
        self.0.finalize_reset().into_bytes().into()
    }
}

impl AesCmac for SoftAesCmac {
    fn update(&mut self, data: &[u8]) {
        Mac::update(&mut self.0, data);
    }

    fn finalize_reset(&mut self) -> [u8; AES_BLOCK_LEN] {
        self.0.finalize_reset().into_bytes().into()
    }
}

impl CryptoBackend for SoftCrypto {
    type Aes128 = SoftAes128;
    type Sha256 = SoftSha256;
    type HmacSha256 = SoftHmacSha256;
    type AesCmac = SoftAesCmac;

    fn aes128(&self, key: &[u8; AES128_KEY_LEN]) -> SoftAes128 {
        SoftAes128(aes::Aes128::new(key.into()))
    }

    fn sha256(&self) -> SoftSha256 {
        SoftSha256::default()
    }

    fn hmac_sha256(&self, key: &[u8]) -> SoftHmacSha256 {
        // HMAC accepts keys of any length; `new_from_slice` cannot fail.
        match <hmac::HmacReset<sha2::Sha256> as KeyInit>::new_from_slice(key) {
            Ok(h) => SoftHmacSha256(h),
            Err(_) => unreachable!("HMAC accepts any key length"),
        }
    }

    fn aes_cmac(&self, key: &[u8; AES128_KEY_LEN]) -> SoftAesCmac {
        SoftAesCmac(<cmac::Cmac<aes::Aes128> as KeyInit>::new(key.into()))
    }
}
