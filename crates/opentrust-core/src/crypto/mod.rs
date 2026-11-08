//! Thread cryptography (Thread 1.4.1 chapter 7, §8.4.1.2).
//!
//! - [`backend`]: the primitive traits ([`CryptoBackend`] = AES-128 block,
//!   SHA-256, HMAC-SHA256, AES-CMAC) a platform implements.
//! - [`generic`]: HMAC/CMAC built from SHA-256/AES for minimal backends.
//! - [`ccm`]: AES-CCM* (802.15.4 MAC frames, MLE, DTLS `AES_128_CCM_8`).
//! - [`nonce`]: CCM* nonces for MAC and MLE.
//! - [`kdf`]: MAC/MLE key derivation, TREL key, HKDF, TLS 1.2 PRF, KEK.
//! - [`pskc`]: PBKDF2-AES-CMAC-PRF-128 and PSKc derivation.
//! - `soft`: RustCrypto software backend `SoftCrypto` (feature `soft-crypto`).
//! - `ecjpake`: EC-JPAKE on P-256 for DTLS `TLS_ECJPAKE_WITH_AES_128_CCM_8`
//!   (feature `ecjpake`, RustCrypto `p256`; ADR
//!   `docs/decisions/0001-ecjpake-dtls.md`).
//!
//! # Key hygiene
//!
//! Intermediate secrets (HMAC/CMAC state, derived blocks, decrypted payloads
//! that fail authentication) are wiped with `zeroize`. The key newtypes in
//! [`crate::types`] ([`NetworkKey`](crate::types::NetworkKey),
//! [`MacKey`](crate::types::MacKey), ...) implement
//! [`Zeroize`](zeroize::Zeroize) but are `Copy`, so they are not wiped on
//! drop; [`ThreadKeys`](kdf::ThreadKeys) is.

pub mod backend;
pub mod ccm;
#[cfg(feature = "ecjpake")]
pub mod ecjpake;
pub mod generic;
pub mod kdf;
pub mod nonce;
pub mod pskc;
#[cfg(feature = "soft-crypto")]
pub mod soft;

#[cfg(all(test, feature = "soft-crypto"))]
mod tests;

pub use backend::{Aes128, AesCmac, CryptoBackend, HmacSha256, Sha256};
pub use ccm::SecurityLevel;
#[cfg(feature = "soft-crypto")]
pub use soft::SoftCrypto;
