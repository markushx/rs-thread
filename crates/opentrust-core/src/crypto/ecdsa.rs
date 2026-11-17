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

    /// Verify `signature` (`r || s`) over the SHA-256 `digest` with
    /// `public_key` (`X || Y`). [`Error::Security`](crate::Error::Security)
    /// if the key is not a point of the curve or the signature does not
    /// match. Backends that only sign return
    /// [`Error::NotImplemented`](crate::Error::NotImplemented) (the default).
    fn verify_digest(
        &self,
        public_key: &[u8; PUBLIC_KEY_LEN],
        digest: &[u8; 32],
        signature: &[u8; SIGNATURE_LEN],
    ) -> Result<()> {
        let _ = (public_key, digest, signature);
        Err(crate::Error::NotImplemented)
    }
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

    fn verify_digest(
        &self,
        public_key: &[u8; PUBLIC_KEY_LEN],
        digest: &[u8; 32],
        signature: &[u8; SIGNATURE_LEN],
    ) -> Result<()> {
        use p256::ecdsa::signature::hazmat::PrehashVerifier;
        let mut sec1 = [0u8; PUBLIC_KEY_LEN + 1];
        sec1[0] = 0x04;
        sec1[1..].copy_from_slice(public_key);
        let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(&sec1)
            .map_err(|_| crate::Error::Security)?;
        let sig =
            p256::ecdsa::Signature::from_slice(signature).map_err(|_| crate::Error::Security)?;
        vk.verify_prehash(digest, &sig)
            .map_err(|_| crate::Error::Security)
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

    fn verify_digest(
        &self,
        public_key: &[u8; PUBLIC_KEY_LEN],
        digest: &[u8; 32],
        signature: &[u8; SIGNATURE_LEN],
    ) -> Result<()> {
        SoftEcdsaP256.verify_digest(public_key, digest, signature)
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

    fn hex<const N: usize>(s: &str) -> [u8; N] {
        let mut out = [0u8; N];
        for (i, b) in out.iter_mut().enumerate() {
            *b = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
        }
        out
    }

    /// OpenThread `tests/unit/test_ecdsa.cpp` `TestEcdsaVector`
    /// (RFC 6979 A.2.5, NIST P-256 / SHA-256, message "sample").
    #[test]
    fn test_ecdsa_vector() {
        use crate::crypto::backend::Sha256 as _;
        let key = SecretKey(hex(
            "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721",
        ));
        let expected_pk: [u8; 64] = hex(
            "60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6\
             7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299",
        );
        let expected_sig: [u8; 64] = hex(
            "efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716\
             f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8",
        );
        assert_eq!(SoftEcdsaP256.public_key(&key).unwrap(), expected_pk);

        let mut sha = crate::crypto::soft::SoftSha256::default();
        sha.update(b"sample");
        let digest: [u8; 32] = sha.finalize();
        let sig = SoftEcdsaP256.sign_digest(&key, &digest).unwrap();
        assert_eq!(sig, expected_sig);
        SoftEcdsaP256
            .verify_digest(&expected_pk, &digest, &sig)
            .unwrap();
        let mut bad = digest;
        bad[0] ^= 1;
        assert!(
            SoftEcdsaP256
                .verify_digest(&expected_pk, &bad, &sig)
                .is_err()
        );
        let mut bad_key = expected_pk;
        bad_key[0] ^= 1;
        assert!(
            SoftEcdsaP256
                .verify_digest(&bad_key, &digest, &sig)
                .is_err()
        );

        let mut sec1 = [0u8; 65];
        sec1[0] = 4;
        sec1[1..].copy_from_slice(&expected_pk);
        let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(&sec1).unwrap();
        let sig = p256::ecdsa::Signature::from_slice(&sig).unwrap();
        vk.verify_prehash(&digest, &sig).unwrap();
    }

    /// OpenThread `test_ecdsa.cpp` `TestEcdsaKeyGenerationSignAndVerify`:
    /// a signature must not verify against a different hash.
    #[test]
    fn test_ecdsa_key_generation_sign_and_verify() {
        let key = SecretKey([0x42u8; 32]);
        let pk = SoftEcdsaP256.public_key(&key).unwrap();
        let d1 = [1u8; 32];
        let d2 = [2u8; 32];
        let sig = SoftEcdsaP256.sign_digest(&key, &d1).unwrap();
        let mut sec1 = [0u8; 65];
        sec1[0] = 4;
        sec1[1..].copy_from_slice(&pk);
        let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(&sec1).unwrap();
        let sig = p256::ecdsa::Signature::from_slice(&sig).unwrap();
        vk.verify_prehash(&d1, &sig).unwrap();
        assert!(vk.verify_prehash(&d2, &sig).is_err());
    }
}
