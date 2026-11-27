//! ESP32-C6 crypto backend for rs-thread.
//!
//! # `EspCrypto`
//!
//! A [`rs_thread_core::crypto::CryptoBackend`] that uses the ESP32-C6 AES
//! hardware accelerator for all AES-128 block operations (CCM*, CMAC) and the
//! RustCrypto software backend for SHA-256 and HMAC-SHA256:
//!
//! | Operation  | Backend  |
//! |------------|----------|
//! | AES-128    | HW (`esp-hal::aes::Aes`)             |
//! | AES-CMAC   | HW AES block + software CMAC driver  |
//! | SHA-256    | Software (`sha2`)                    |
//! | HMAC-SHA256| Software (`hmac`)                    |
//!
//! Call [`EspCrypto::init`] once at boot to hand the AES peripheral to the
//! global driver.  After that, `EspCrypto` is a zero-size copyable token.
//!
//! # `EspP256`
//!
//! A [`rs_thread_core::crypto::ecjpake::curve::P256`] implementation for
//! EC-JPAKE and ECDSA P-256.  Currently delegates to `SoftP256` (RustCrypto
//! `p256`).  A future revision will use the ESP32-C6 RSA/MPI accelerator for
//! P-256 field multiplication (2–3× speedup over software).

use core::cell::RefCell;

use critical_section::Mutex;
use esp_hal::aes::{Aes, Mode};
use rs_thread_core::crypto::{
    backend::{AES_BLOCK_LEN, AES128_KEY_LEN, CryptoBackend},
    ecjpake::{P256, POINT_LEN, SCALAR_LEN, SoftP256},
    generic::GenericCmac,
    soft::{SoftCrypto, SoftHmacSha256, SoftSha256},
};

// --- AES hardware peripheral storage ---

static AES_HW: Mutex<RefCell<Option<Aes<'static>>>> = Mutex::new(RefCell::new(None));

// --- EspAes128 ---

/// AES-128 key holder backed by the ESP32-C6 AES hardware.
///
/// Created by `EspCrypto::aes128`; holds the 16-byte expanded key.
#[derive(Clone, Copy)]
pub struct EspAes128([u8; AES128_KEY_LEN]);

impl core::fmt::Debug for EspAes128 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("EspAes128(<redacted>)")
    }
}

impl rs_thread_core::crypto::Aes128 for EspAes128 {
    fn encrypt_block(&self, block: &mut [u8; AES_BLOCK_LEN]) {
        critical_section::with(|cs| {
            if let Some(hw) = AES_HW.borrow(cs).borrow_mut().as_mut() {
                hw.process(block, Mode::Encryption128, self.0);
            }
        });
    }
}

// --- EspCrypto ---

/// ESP32-C6 [`CryptoBackend`]: hardware AES-128, software SHA-256 / HMAC.
///
/// Zero-size; call [`EspCrypto::init`] once before using any `EspCrypto` or
/// `EspAes128` instance.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct EspCrypto;

impl EspCrypto {
    /// Store the AES peripheral in the global driver.
    ///
    /// Call once at board init before constructing any `EspCrypto` instance.
    pub fn init(aes: Aes<'static>) {
        critical_section::with(|cs| {
            *AES_HW.borrow(cs).borrow_mut() = Some(aes);
        });
    }
}

impl CryptoBackend for EspCrypto {
    type Aes128 = EspAes128;
    // SHA-256 and HMAC-SHA256 stay on software; the ESP32-C6 SHA accelerator
    // has no blocking synchronous API in esp-hal 0.23 without DMA.
    type Sha256 = SoftSha256;
    type HmacSha256 = SoftHmacSha256;
    // CMAC is built from the hardware AES block cipher.
    type AesCmac = GenericCmac<EspAes128>;

    fn aes128(&self, key: &[u8; AES128_KEY_LEN]) -> EspAes128 {
        EspAes128(*key)
    }

    fn sha256(&self) -> SoftSha256 {
        SoftCrypto.sha256()
    }

    fn hmac_sha256(&self, key: &[u8]) -> SoftHmacSha256 {
        SoftCrypto.hmac_sha256(key)
    }

    fn aes_cmac(&self, key: &[u8; AES128_KEY_LEN]) -> GenericCmac<EspAes128> {
        GenericCmac::new(self.aes128(key))
    }
}

// --- EcdsaP256 for EspCrypto ---

#[cfg(feature = "ecdsa")]
use rs_thread_core::crypto::ecdsa::{PUBLIC_KEY_LEN, SIGNATURE_LEN};

#[cfg(feature = "ecdsa")]
impl rs_thread_core::crypto::ecdsa::EcdsaP256 for EspCrypto {
    fn public_key(
        &self,
        key: &rs_thread_core::crypto::ecdsa::SecretKey,
    ) -> rs_thread_core::error::Result<[u8; PUBLIC_KEY_LEN]> {
        SoftCrypto.public_key(key)
    }

    fn sign_digest(
        &self,
        key: &rs_thread_core::crypto::ecdsa::SecretKey,
        digest: &[u8; 32],
    ) -> rs_thread_core::error::Result<[u8; SIGNATURE_LEN]> {
        SoftCrypto.sign_digest(key, digest)
    }

    fn verify_digest(
        &self,
        public_key: &[u8; PUBLIC_KEY_LEN],
        digest: &[u8; 32],
        signature: &[u8; SIGNATURE_LEN],
    ) -> rs_thread_core::error::Result<()> {
        SoftCrypto.verify_digest(public_key, digest, signature)
    }
}

// --- EspP256 ---

/// P-256 for EC-JPAKE and ECDSA on the ESP32-C6.
///
/// Delegates all group arithmetic to [`SoftP256`] (RustCrypto `p256`).
/// A future revision will use the ESP32-C6 RSA/MPI accelerator for P-256
/// field multiplication via [`RsaModularMultiplication`].
///
/// [`RsaModularMultiplication`]: esp_hal::rsa::RsaModularMultiplication
#[cfg(feature = "ecdsa")]
#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub struct EspP256(SoftP256);

#[cfg(feature = "ecdsa")]
impl core::fmt::Debug for EspP256 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("EspP256")
    }
}

#[cfg(feature = "ecdsa")]
impl P256 for EspP256 {
    type Scalar = <SoftP256 as P256>::Scalar;
    type Point = <SoftP256 as P256>::Point;

    fn scalar_from_be(&self, bytes: &[u8; SCALAR_LEN]) -> Option<Self::Scalar> {
        self.0.scalar_from_be(bytes)
    }
    fn scalar_reduce(&self, bytes: &[u8; SCALAR_LEN]) -> Self::Scalar {
        self.0.scalar_reduce(bytes)
    }
    fn scalar_to_be(&self, s: &Self::Scalar) -> [u8; SCALAR_LEN] {
        self.0.scalar_to_be(s)
    }
    fn scalar_is_zero(&self, s: &Self::Scalar) -> bool {
        self.0.scalar_is_zero(s)
    }
    fn scalar_mul(&self, a: &Self::Scalar, b: &Self::Scalar) -> Self::Scalar {
        self.0.scalar_mul(a, b)
    }
    fn scalar_sub(&self, a: &Self::Scalar, b: &Self::Scalar) -> Self::Scalar {
        self.0.scalar_sub(a, b)
    }
    fn generator(&self) -> Self::Point {
        self.0.generator()
    }
    fn mul_base(&self, k: &Self::Scalar) -> Self::Point {
        self.0.mul_base(k)
    }
    fn mul(&self, p: &Self::Point, k: &Self::Scalar) -> Self::Point {
        self.0.mul(p, k)
    }
    fn add(&self, p: &Self::Point, q: &Self::Point) -> Self::Point {
        self.0.add(p, q)
    }
    fn sub(&self, p: &Self::Point, q: &Self::Point) -> Self::Point {
        self.0.sub(p, q)
    }
    fn neg(&self, p: &Self::Point) -> Self::Point {
        self.0.neg(p)
    }
    fn is_identity(&self, p: &Self::Point) -> bool {
        self.0.is_identity(p)
    }
    fn point_eq(&self, p: &Self::Point, q: &Self::Point) -> bool {
        self.0.point_eq(p, q)
    }
    fn encode(&self, p: &Self::Point) -> Option<[u8; POINT_LEN]> {
        self.0.encode(p)
    }
    fn decode(&self, bytes: &[u8]) -> Option<Self::Point> {
        self.0.decode(bytes)
    }
}
