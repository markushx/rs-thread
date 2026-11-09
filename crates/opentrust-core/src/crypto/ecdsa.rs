//! ECDSA on P-256 with SHA-256 (RFC 6605), as used for SRP SIG(0) (RFC 2931,
//! Thread 1.3 SRP client).
//!
//! [`EcdsaP256`] is the backend trait (a platform with a hardware ECDSA
//! engine implements it); `SoftEcdsaP256` is the software implementation
//! on RustCrypto `p256` (feature `ecdsa`). Signing is deterministic
//! (RFC 6979) and takes the already computed SHA-256 digest, like OT's
//! `Crypto::Ecdsa::P256::KeyPair::Sign(const Sha256::Hash &, Signature &)`.
//!
//! Private keys are plain 32-byte big-endian scalars ([`SecretKey`], wiped
//! on drop). OT persists the key as an mbedTLS DER blob; the raw scalar is
//! used here (see `OPENTRUST-OPENTHREAD-DIFFERENCES.md`).

use zeroize::Zeroize;

use crate::error::Result;

/// Length of a private scalar.
pub const SECRET_KEY_LEN: usize = 32;
/// Length of a public key (uncompressed point without the `0x04` prefix,
/// `X || Y`), as carried in a DNS KEY record.
pub const PUBLIC_KEY_LEN: usize = 64;
/// Length of a signature (`r || s`).
pub const SIGNATURE_LEN: usize = 64;

/// A P-256 private key (big-endian scalar). Zeroized on drop.
#[derive(Clone, PartialEq, Eq)]
pub struct SecretKey(pub [u8; SECRET_KEY_LEN]);

impl Drop for SecretKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl core::fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SecretKey(..)")
    }
}

/// ECDSA P-256 backend.
pub trait EcdsaP256 {
    /// The public key (`X || Y`) of `key`; fails with
    /// [`Error::InvalidArgs`](crate::Error::InvalidArgs) if `key` is not a
    /// valid scalar (zero or not below the group order).
    fn public_key(&self, key: &SecretKey) -> Result<[u8; PUBLIC_KEY_LEN]>;

    /// Sign the SHA-256 `digest` (`r || s`).
    fn sign_digest(&self, key: &SecretKey, digest: &[u8; 32]) -> Result<[u8; SIGNATURE_LEN]>;
}

/// Software [`EcdsaP256`] on RustCrypto `p256`.
#[cfg(feature = "ecdsa")]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SoftEcdsaP256;

#[cfg(feature = "ecdsa")]
impl EcdsaP256 for SoftEcdsaP256 {
    fn public_key(&self, key: &SecretKey) -> Result<[u8; PUBLIC_KEY_LEN]> {
        let sk =
            p256::ecdsa::SigningKey::from_slice(&key.0).map_err(|_| crate::Error::InvalidArgs)?;
        let point = sk.verifying_key().to_sec1_point(false);
        let bytes = point.as_bytes();
        let mut out = [0u8; PUBLIC_KEY_LEN];
        out.copy_from_slice(bytes.get(1..=PUBLIC_KEY_LEN).ok_or(crate::Error::Parse)?);
        Ok(out)
    }

    fn sign_digest(&self, key: &SecretKey, digest: &[u8; 32]) -> Result<[u8; SIGNATURE_LEN]> {
        use p256::ecdsa::signature::hazmat::PrehashSigner;
        let sk =
            p256::ecdsa::SigningKey::from_slice(&key.0).map_err(|_| crate::Error::InvalidArgs)?;
        let sig: p256::ecdsa::Signature = sk
            .sign_prehash(digest)
            .map_err(|_| crate::Error::Security)?;
        let mut out = [0u8; SIGNATURE_LEN];
        out.copy_from_slice(&sig.to_bytes());
        Ok(out)
    }
}

#[cfg(all(feature = "ecdsa", feature = "soft-crypto"))]
impl EcdsaP256 for super::soft::SoftCrypto {
    fn public_key(&self, key: &SecretKey) -> Result<[u8; PUBLIC_KEY_LEN]> {
        SoftEcdsaP256.public_key(key)
    }

    fn sign_digest(&self, key: &SecretKey, digest: &[u8; 32]) -> Result<[u8; SIGNATURE_LEN]> {
        SoftEcdsaP256.sign_digest(key, digest)
    }
}

#[cfg(all(test, feature = "ecdsa"))]
mod tests {
    use super::*;
    use p256::ecdsa::signature::hazmat::PrehashVerifier;

    #[test]
    fn sign_verify_roundtrip() {
        let key = SecretKey([7u8; 32]);
        let pk = SoftEcdsaP256.public_key(&key).unwrap();
        let digest = [0x5au8; 32];
        let sig = SoftEcdsaP256.sign_digest(&key, &digest).unwrap();
        let mut sec1 = [0u8; 65];
        sec1[0] = 4;
        sec1[1..].copy_from_slice(&pk);
        let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(&sec1).unwrap();
        let sig = p256::ecdsa::Signature::from_slice(&sig).unwrap();
        vk.verify_prehash(&digest, &sig).unwrap();
        assert!(SoftEcdsaP256.public_key(&SecretKey([0; 32])).is_err());
    }
}
