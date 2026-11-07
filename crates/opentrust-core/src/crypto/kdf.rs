//! Key derivation: Thread MAC/MLE keys, TREL key, HKDF-SHA256, the TLS 1.2
//! PRF and the commissioning KEK.

use zeroize::Zeroize;

use super::backend::{CryptoBackend, HmacSha256, SHA256_LEN, Sha256};
use crate::error::{Error, Result};
use crate::types::{Kek, MacKey, MleKey, NetworkKey};

/// The byte string `"Thread"` appended to the key sequence (§7.1.4).
const THREAD_STRING: &[u8] = b"Thread";
/// HKDF salt suffix for the TREL key (OpenThread `KeyManager`).
const TREL_SALT_STRING: &[u8] = b"ThreadSequenceMasterKey";
/// HKDF info for the TREL key (OpenThread `KeyManager`).
const TREL_INFO_STRING: &[u8] = b"ThreadOverInfraKey";

/// Length of the TLS 1.2 key block for `TLS_ECJPAKE_WITH_AES_128_CCM_8`
/// (2 × 16-byte write keys + 2 × 4-byte implicit IVs).
pub const KEY_BLOCK_LEN: usize = 40;
/// TLS 1.2 master secret length.
pub const MASTER_SECRET_LEN: usize = 48;
/// TLS client/server random length.
pub const TLS_RANDOM_LEN: usize = 32;

/// MLE and MAC keys for one key sequence.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct ThreadKeys {
    /// Key for MLE message security.
    pub mle_key: MleKey,
    /// Key for MAC frame security (Key ID Mode 1).
    pub mac_key: MacKey,
}

impl Zeroize for ThreadKeys {
    fn zeroize(&mut self) {
        self.mle_key.zeroize();
        self.mac_key.zeroize();
    }
}

impl Drop for ThreadKeys {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Derive the MLE and MAC keys for `key_sequence` (Thread §7.1.4):
/// `HMAC-SHA256(networkKey, BE32(keySequence) || "Thread")`.
///
/// The **first** 16 bytes of the HMAC output are the MLE key and the **last**
/// 16 bytes the MAC key. This follows the spec's test vectors and Python
/// test program (§7.1.4.1–7.1.4.4) and OpenThread (`KeyManager::ComputeKeys`,
/// `HashKeys { mMleKey; mMacKey; }`). The §7.1.4 prose ("the MAC key is the
/// upper 16 bytes ... the MLE key is the lower 16 bytes") is ambiguous and
/// reads as the opposite assignment if "lower" means the first bytes; the
/// vectors are normative in practice.
pub fn thread_keys<B: CryptoBackend>(
    backend: &B,
    network_key: &NetworkKey,
    key_sequence: u32,
) -> ThreadKeys {
    let mut hmac = backend.hmac_sha256(network_key.as_bytes());
    hmac.update(&key_sequence.to_be_bytes());
    hmac.update(THREAD_STRING);
    let mut h = hmac.finalize();
    let mut keys = ThreadKeys {
        mle_key: MleKey([0; 16]),
        mac_key: MacKey([0; 16]),
    };
    keys.mle_key.0.copy_from_slice(&h[..16]);
    keys.mac_key.0.copy_from_slice(&h[16..]);
    h.zeroize();
    keys
}

/// Key Index for `key_sequence` (§7.1.5): `(keySequence & 0x7f) + 1`.
pub const fn key_index(key_sequence: u32) -> u8 {
    (key_sequence & 0x7f) as u8 + 1
}

/// TREL (Thread Radio Encapsulation Link) frame key for `key_sequence`, as
/// derived by OpenThread (`KeyManager::ComputeTrelKey`):
/// `HKDF-SHA256(salt = BE32(keySequence) || "ThreadSequenceMasterKey",
/// ikm = networkKey, info = "ThreadOverInfraKey", L = 16)`.
pub fn trel_key<B: CryptoBackend>(
    backend: &B,
    network_key: &NetworkKey,
    key_sequence: u32,
) -> MacKey {
    let mut salt = [0u8; 4 + TREL_SALT_STRING.len()];
    salt[..4].copy_from_slice(&key_sequence.to_be_bytes());
    salt[4..].copy_from_slice(TREL_SALT_STRING);
    let mut key = MacKey([0; 16]);
    // Cannot fail: 16 <= 255 * 32.
    let _ = hkdf_sha256(
        backend,
        &salt,
        network_key.as_bytes(),
        TREL_INFO_STRING,
        &mut key.0,
    );
    key
}

/// HKDF-Extract (RFC 5869 §2.2). An empty `salt` is equivalent to the
/// RFC's default of `HashLen` zero bytes.
pub fn hkdf_sha256_extract<B: CryptoBackend>(
    backend: &B,
    salt: &[u8],
    ikm: &[u8],
) -> [u8; SHA256_LEN] {
    let mut hmac = backend.hmac_sha256(salt);
    hmac.update(ikm);
    hmac.finalize()
}

/// HKDF-Expand (RFC 5869 §2.3). `okm` may be up to 255 × 32 bytes.
pub fn hkdf_sha256_expand<B: CryptoBackend>(
    backend: &B,
    prk: &[u8],
    info: &[u8],
    okm: &mut [u8],
) -> Result<()> {
    if okm.len() > 255 * SHA256_LEN {
        return Err(Error::InvalidArgs);
    }
    let mut hmac = backend.hmac_sha256(prk);
    let mut t = [0u8; SHA256_LEN];
    for (i, chunk) in okm.chunks_mut(SHA256_LEN).enumerate() {
        if i > 0 {
            hmac.update(&t);
        }
        hmac.update(info);
        hmac.update(&[(i + 1) as u8]);
        t = hmac.finalize_reset();
        chunk.copy_from_slice(&t[..chunk.len()]);
    }
    t.zeroize();
    Ok(())
}

/// HKDF-SHA256 (RFC 5869): extract then expand into `okm`.
pub fn hkdf_sha256<B: CryptoBackend>(
    backend: &B,
    salt: &[u8],
    ikm: &[u8],
    info: &[u8],
    okm: &mut [u8],
) -> Result<()> {
    let mut prk = hkdf_sha256_extract(backend, salt, ikm);
    let r = hkdf_sha256_expand(backend, &prk, info, okm);
    prk.zeroize();
    r
}

/// TLS 1.2 PRF with SHA-256 (RFC 5246 §5): `P_SHA256(secret, label || seed)`
/// where `seed` is the concatenation of `seed_parts`.
pub fn tls12_prf_sha256<B: CryptoBackend>(
    backend: &B,
    secret: &[u8],
    label: &[u8],
    seed_parts: &[&[u8]],
    out: &mut [u8],
) {
    let mut hmac = backend.hmac_sha256(secret);
    // A(1) = HMAC(secret, label || seed)
    hmac.update(label);
    for s in seed_parts {
        hmac.update(s);
    }
    let mut a = hmac.finalize_reset();
    let mut block = [0u8; SHA256_LEN];
    for chunk in out.chunks_mut(SHA256_LEN) {
        hmac.update(&a);
        hmac.update(label);
        for s in seed_parts {
            hmac.update(s);
        }
        block = hmac.finalize_reset();
        chunk.copy_from_slice(&block[..chunk.len()]);
        // A(i+1) = HMAC(secret, A(i))
        hmac.update(&a);
        a = hmac.finalize_reset();
    }
    a.zeroize();
    block.zeroize();
}

/// KEK from a TLS key block (Thread §7.4.7.8/§7.4.7.9):
/// `KEK = SHA-256(key_block)[0..16]`.
pub fn kek_from_key_block<B: CryptoBackend>(backend: &B, key_block: &[u8]) -> Kek {
    let mut sha = backend.sha256();
    sha.update(key_block);
    let mut h = sha.finalize();
    let mut kek = Kek([0; 16]);
    kek.0.copy_from_slice(&h[..16]);
    h.zeroize();
    kek
}

/// KEK from the DTLS master secret of a `TLS_ECJPAKE_WITH_AES_128_CCM_8`
/// session: computes the RFC 5246 §6.3 key block
/// (`PRF(master_secret, "key expansion", server_random || client_random)`,
/// [`KEY_BLOCK_LEN`] bytes) and hashes it with [`kek_from_key_block`].
/// Matches OpenThread `SecureTransport::HandleMbedtlsExportKeys`.
pub fn kek_from_master_secret<B: CryptoBackend>(
    backend: &B,
    master_secret: &[u8; MASTER_SECRET_LEN],
    client_random: &[u8; TLS_RANDOM_LEN],
    server_random: &[u8; TLS_RANDOM_LEN],
) -> Kek {
    let mut key_block = [0u8; KEY_BLOCK_LEN];
    tls12_prf_sha256(
        backend,
        master_secret,
        b"key expansion",
        &[server_random, client_random],
        &mut key_block,
    );
    let kek = kek_from_key_block(backend, &key_block);
    key_block.zeroize();
    kek
}
