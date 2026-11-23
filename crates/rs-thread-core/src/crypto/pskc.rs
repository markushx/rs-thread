//! PSKc derivation (Thread §8.4.1.2.1): PBKDF2 (RFC 2898 / RFC 8018) with
//! AES-CMAC-PRF-128 (RFC 4615) as the PRF.

use zeroize::Zeroize;

use super::backend::{AES_BLOCK_LEN, AES128_KEY_LEN, AesCmac, CryptoBackend};
use crate::error::{Error, Result};
use crate::types::{ExtPanId, NetworkName, Pskc};

/// PBKDF2 iteration count for the PSKc.
pub const PSKC_ITERATIONS: u32 = 16384;
/// Minimum commissioning passphrase length in bytes (OpenThread
/// `OT_COMMISSIONING_PASSPHRASE_MIN_SIZE`).
pub const PASSPHRASE_MIN_LEN: usize = 6;
/// Maximum commissioning passphrase length in bytes (OpenThread
/// `OT_COMMISSIONING_PASSPHRASE_MAX_SIZE`).
pub const PASSPHRASE_MAX_LEN: usize = 255;

/// The RFC 4615 key: `key` itself if it is 16 bytes, else
/// `AES-CMAC(0^128, key)`.
fn prf_key<B: CryptoBackend>(backend: &B, key: &[u8]) -> [u8; AES128_KEY_LEN] {
    match <[u8; AES128_KEY_LEN]>::try_from(key) {
        Ok(k) => k,
        Err(_) => {
            let mut cmac = backend.aes_cmac(&[0; AES128_KEY_LEN]);
            cmac.update(key);
            cmac.finalize()
        }
    }
}

/// AES-CMAC-PRF-128 (RFC 4615) for a key of any length.
pub fn aes_cmac_prf_128<B: CryptoBackend>(
    backend: &B,
    key: &[u8],
    message: &[u8],
) -> [u8; AES_BLOCK_LEN] {
    let mut k = prf_key(backend, key);
    let mut cmac = backend.aes_cmac(&k);
    k.zeroize();
    cmac.update(message);
    cmac.finalize()
}

/// PBKDF2 with AES-CMAC-PRF-128 as the PRF; fills `out` (any length).
///
/// Fails with [`Error::InvalidArgs`] if `iterations` is 0.
pub fn pbkdf2_aes_cmac_prf_128<B: CryptoBackend>(
    backend: &B,
    password: &[u8],
    salt: &[u8],
    iterations: u32,
    out: &mut [u8],
) -> Result<()> {
    if iterations == 0 {
        return Err(Error::InvalidArgs);
    }
    // The RFC 4615 key derivation is independent of the message, so do it
    // (and the key schedule) once.
    let mut k = prf_key(backend, password);
    let mut prf = backend.aes_cmac(&k);
    k.zeroize();

    let mut u = [0u8; AES_BLOCK_LEN];
    let mut t = [0u8; AES_BLOCK_LEN];
    for (i, chunk) in out.chunks_mut(AES_BLOCK_LEN).enumerate() {
        // U_1 = PRF(P, S || INT(i)), 1-based block index.
        let block_index = u32::try_from(i + 1).map_err(|_| Error::InvalidArgs)?;
        prf.update(salt);
        prf.update(&block_index.to_be_bytes());
        u = prf.finalize_reset();
        t = u;
        for _ in 1..iterations {
            prf.update(&u);
            u = prf.finalize_reset();
            for (t, u) in t.iter_mut().zip(&u) {
                *t ^= u;
            }
        }
        chunk.copy_from_slice(&t[..chunk.len()]);
    }
    u.zeroize();
    t.zeroize();
    Ok(())
}

/// Derive the PSKc from a commissioning passphrase (Thread §8.4.1.2.1):
///
/// `PBKDF2(AES-CMAC-PRF-128, P = passphrase, S = "Thread" || extPanId ||
/// networkName, c = 16384, dkLen = 16)`.
///
/// The passphrase must be valid UTF-8 of [`PASSPHRASE_MIN_LEN`] ..=
/// [`PASSPHRASE_MAX_LEN`] bytes (as enforced by OpenThread
/// `MeshCoP::GeneratePskc`), otherwise [`Error::InvalidArgs`].
pub fn pskc<B: CryptoBackend>(
    backend: &B,
    passphrase: &[u8],
    network_name: &NetworkName,
    ext_pan_id: &ExtPanId,
) -> Result<Pskc> {
    if !(PASSPHRASE_MIN_LEN..=PASSPHRASE_MAX_LEN).contains(&passphrase.len())
        || core::str::from_utf8(passphrase).is_err()
    {
        return Err(Error::InvalidArgs);
    }
    const PREFIX: &[u8] = b"Thread";
    let mut salt = [0u8; PREFIX.len() + ExtPanId::LEN + NetworkName::MAX_LEN];
    let name = network_name.as_bytes();
    let salt_len = PREFIX.len() + ExtPanId::LEN + name.len();
    salt[..PREFIX.len()].copy_from_slice(PREFIX);
    salt[PREFIX.len()..PREFIX.len() + ExtPanId::LEN].copy_from_slice(ext_pan_id.as_bytes());
    salt[PREFIX.len() + ExtPanId::LEN..salt_len].copy_from_slice(name);

    let mut pskc = Pskc([0; Pskc::LEN]);
    pbkdf2_aes_cmac_prf_128(
        backend,
        passphrase,
        &salt[..salt_len],
        PSKC_ITERATIONS,
        &mut pskc.0,
    )?;
    Ok(pskc)
}
