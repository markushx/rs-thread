//! Crypto backend traits: the primitives a platform must provide.
//!
//! Everything Thread needs on the symmetric side (CCM*, key derivation, PSKc,
//! TLS PRF, KEK) is built in this crate on top of four primitives:
//!
//! | Trait          | Used for                                              |
//! |----------------|-------------------------------------------------------|
//! | [`Aes128`]     | CCM* (MAC/MLE/DTLS record protection), CMAC           |
//! | [`Sha256`]     | KEK, Joiner ID, hashing in EC-JPAKE                   |
//! | [`HmacSha256`] | Thread key derivation, HKDF (TREL), TLS 1.2 PRF       |
//! | [`AesCmac`]    | PBKDF2-AES-CMAC-PRF-128 (PSKc)                        |
//!
//! # Design
//!
//! - **Synchronous.** Hardware AES engines (nRF ECB/CCM, CryptoCell, CRACEN,
//!   ESP AES) finish a block in well under a microsecond, so an async API would
//!   only add overhead. Backends wrapping slower engines should block.
//! - **Generic, not `dyn`.** Protocol code is generic over `B: CryptoBackend`,
//!   so a software backend inlines fully (zero-cost). The primitive traits are
//!   still object safe apart from the `Sized` defaults, should a `dyn` wrapper
//!   ever be needed.
//! - **Infallible.** A hardware backend that hits a driver error must handle it
//!   internally (retry, or panic). Producing wrong output is never silent in
//!   practice: it surfaces as MIC failures at the peer.
//! - **`&self` constructors.** Backends that own a peripheral use interior
//!   mutability (e.g. a critical-section mutex) and can hand out handles.
//! - **Minimal hardware surface.** A backend that only has an AES block engine
//!   can use [`GenericCmac`](super::generic::GenericCmac) and
//!   [`GenericHmac`](super::generic::GenericHmac) for the derived primitives.
//!
//! # rs-matter
//!
//! rs-matter's `Crypto` trait (`rs-matter-crypto`) exposes SHA-256, HMAC-SHA256
//! (fixed key length), HKDF, PBKDF2-HMAC, AES-128-CCM (16-byte tag only) and
//! P-256 point/scalar arithmetic, but neither a raw AES block cipher nor
//! AES-CMAC. An adapter from rs-matter's `Crypto` can therefore provide
//! [`Sha256`] and [`HmacSha256`], but [`Aes128`] (needed for CCM* with M=0/4/8
//! and CMAC) must come from elsewhere. Both stacks use the same RustCrypto
//! release line (aes 0.9, hmac 0.13, sha2 0.11, p256 0.14), so in practice
//! the software backends share code; for EC-JPAKE, rs-matter's `EcPoint` /
//! `EcScalar` traits could be reused (see `docs/decisions/0001-ecjpake-dtls.md`).

/// AES block length in bytes.
pub const AES_BLOCK_LEN: usize = 16;
/// AES-128 key length in bytes.
pub const AES128_KEY_LEN: usize = 16;
/// SHA-256 digest length in bytes.
pub const SHA256_LEN: usize = 32;

/// AES-128 block cipher with an expanded key (encryption direction only;
/// CCM* and CMAC never use the inverse cipher).
pub trait Aes128 {
    /// Encrypt one 16-byte block in place.
    fn encrypt_block(&self, block: &mut [u8; AES_BLOCK_LEN]);
}

/// Incremental SHA-256.
pub trait Sha256 {
    /// Absorb `data`.
    fn update(&mut self, data: &[u8]);

    /// Return the digest of everything absorbed and reset to the empty state.
    fn finalize_reset(&mut self) -> [u8; SHA256_LEN];

    /// Return the digest of everything absorbed.
    fn finalize(mut self) -> [u8; SHA256_LEN]
    where
        Self: Sized,
    {
        self.finalize_reset()
    }
}

/// Incremental HMAC-SHA256 with a fixed key (RFC 2104).
pub trait HmacSha256 {
    /// Absorb `data`.
    fn update(&mut self, data: &[u8]);

    /// Return the MAC of everything absorbed and reset to the keyed initial
    /// state (same key).
    fn finalize_reset(&mut self) -> [u8; SHA256_LEN];

    /// Return the MAC of everything absorbed.
    fn finalize(mut self) -> [u8; SHA256_LEN]
    where
        Self: Sized,
    {
        self.finalize_reset()
    }
}

/// Incremental AES-128-CMAC with a fixed key (RFC 4493).
pub trait AesCmac {
    /// Absorb `data`.
    fn update(&mut self, data: &[u8]);

    /// Return the MAC of everything absorbed and reset to the keyed initial
    /// state (same key).
    fn finalize_reset(&mut self) -> [u8; AES_BLOCK_LEN];

    /// Return the MAC of everything absorbed.
    fn finalize(mut self) -> [u8; AES_BLOCK_LEN]
    where
        Self: Sized,
    {
        self.finalize_reset()
    }
}

/// A provider of the symmetric primitives used by Thread.
///
/// Implemented by `soft::SoftCrypto` (feature
/// `soft-crypto`) and, later, by hardware backends.
pub trait CryptoBackend {
    /// AES-128 block cipher handle.
    type Aes128: Aes128;
    /// SHA-256 hasher.
    type Sha256: Sha256;
    /// HMAC-SHA256 instance.
    type HmacSha256: HmacSha256;
    /// AES-CMAC instance.
    type AesCmac: AesCmac;

    /// Expand `key` into an AES-128 cipher.
    fn aes128(&self, key: &[u8; AES128_KEY_LEN]) -> Self::Aes128;

    /// Start a SHA-256 computation.
    fn sha256(&self) -> Self::Sha256;

    /// Start an HMAC-SHA256 computation. `key` may have any length (keys
    /// longer than 64 bytes are hashed first, per RFC 2104).
    fn hmac_sha256(&self, key: &[u8]) -> Self::HmacSha256;

    /// Start an AES-128-CMAC computation.
    fn aes_cmac(&self, key: &[u8; AES128_KEY_LEN]) -> Self::AesCmac;
}

impl<T: CryptoBackend + ?Sized> CryptoBackend for &T {
    type Aes128 = T::Aes128;
    type Sha256 = T::Sha256;
    type HmacSha256 = T::HmacSha256;
    type AesCmac = T::AesCmac;

    fn aes128(&self, key: &[u8; AES128_KEY_LEN]) -> Self::Aes128 {
        (**self).aes128(key)
    }
    fn sha256(&self) -> Self::Sha256 {
        (**self).sha256()
    }
    fn hmac_sha256(&self, key: &[u8]) -> Self::HmacSha256 {
        (**self).hmac_sha256(key)
    }
    fn aes_cmac(&self, key: &[u8; AES128_KEY_LEN]) -> Self::AesCmac {
        (**self).aes_cmac(key)
    }
}

impl<T: Aes128 + ?Sized> Aes128 for &T {
    fn encrypt_block(&self, block: &mut [u8; AES_BLOCK_LEN]) {
        (**self).encrypt_block(block)
    }
}
