//! EC-JPAKE on P-256 with SHA-256, as used by Thread commissioning
//! (`TLS_ECJPAKE_WITH_AES_128_CCM_8`, Thread 1.4.1 §8.2, draft-cragie-tls-ecjpake-01,
//! RFC 8236). Feature `ecjpake`.
//!
//! This is a port of mbedTLS `library/ecjpake.c` (3.6, the implementation
//! every certified Thread device runs) and reproduces its wire format byte
//! for byte:
//!
//! - Points are TLS `ECPoint`s: a length byte and the uncompressed SEC1
//!   encoding (`0x41 0x04 X Y`). Only the uncompressed format is supported
//!   (OpenThread never negotiates compressed points).
//! - `ECSchnorrZKP { ECPoint V; opaque r<1..2^8-1>; }` with `r` in its
//!   minimal big-endian length (mbedTLS `mbedtls_mpi_size`).
//! - ZKP challenge `h = SHA-256(len(G) G || len(V) V || len(X) X ||
//!   len(id) id) mod n`, lengths as 32-bit big-endian, points uncompressed
//!   and `id` the prover's role name `"client"` / `"server"`.
//! - Round one: `ECJPAKEKeyKPPairList` (two `ECJPAKEKeyKP { ECPoint X;
//!   ECSchnorrZKP zkp; }`), the TLS `ecjpake_key_kp_pair` extension body.
//! - Round two: `ECJPAKEKeyKP` with generator `G = Xm1 + Xp1 + Xp2` and key
//!   `xm2 * s`; the server's message (ServerKeyExchange) is prefixed with
//!   `ECParameters` (`03 00 17`, named curve secp256r1), the client's
//!   (ClientKeyExchange) is not.
//! - Premaster secret: `PMS = SHA-256(x(K))` with
//!   `K = (Xp - Xp2 * xm2 * s) * xm2`.
//!
//! The password `s` is the PSKd (Joiner) or PSKc (Commissioner) bytes read
//! as a big-endian integer (reduced modulo `n`), as mbedTLS
//! `mbedtls_ecjpake_setup` does.
//!
//! # Validation (all of mbedTLS's checks, plus some stricter ones)
//!
//! Every received point is decoded with full validation (on curve,
//! coordinates `< p`, not the identity); every ZKP is verified
//! (`V == r * G + h * X`, `r < n`); the peer generator in round two must
//! not be the identity; trailing bytes are rejected. Deviations from
//! mbedTLS are listed in `OPENTRUST-OPENTHREAD-DIFFERENCES.md`
//! ("DTLS / EC-JPAKE").
//!
//! # Secrets
//!
//! The private keys, the password scalar and all intermediate secret
//! scalars are wiped on drop; they only flow through the constant-time
//! [`P256`] operations. Public values (points, `h`, `r`) are not secret.

mod curve;
#[cfg(all(test, feature = "soft-crypto"))]
mod tests;

pub use curve::{P256, POINT_LEN, SCALAR_LEN, SoftP256};

use core::fmt;

use rand_core::CryptoRng;
use zeroize::Zeroize;

use super::backend::{CryptoBackend, SHA256_LEN, Sha256};
use crate::error::{Error, Result};

/// Length of a TLS `ECPoint` holding an uncompressed point.
pub const ECPOINT_LEN: usize = 1 + POINT_LEN;
/// Maximum length of an `ECJPAKEKeyKP` (`X`, `V`, `r`).
pub const KKP_MAX_LEN: usize = 2 * ECPOINT_LEN + 1 + SCALAR_LEN;
/// Maximum length of the round-one message (`ecjpake_key_kp_pair_list`).
pub const ROUND_ONE_MAX_LEN: usize = 2 * KKP_MAX_LEN;
/// `ECParameters` for named curve secp256r1 (RFC 8422 §5.4).
pub const CURVE_PARAMS: [u8; 3] = [0x03, 0x00, 0x17];
/// Maximum length of a round-two message (server: including
/// [`CURVE_PARAMS`]).
pub const ROUND_TWO_MAX_LEN: usize = CURVE_PARAMS.len() + KKP_MAX_LEN;
/// Length of the premaster secret.
pub const PMS_LEN: usize = SHA256_LEN;
/// Maximum password length (OpenThread `kPskMaxLength`; mbedTLS in
/// OpenThread's configuration is limited to 32-byte integers as well).
pub const MAX_PASSWORD_LEN: usize = 32;

/// Number of attempts to draw a scalar in `[1, n-1]` (mbedTLS
/// `mbedtls_mpi_random` uses 30 as well).
const KEYGEN_ATTEMPTS: usize = 30;

/// The EC-JPAKE role; selects the ZKP identities.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Role {
    /// TLS client (Joiner, Commissioner towards the Border Agent).
    Client,
    /// TLS server (Joiner Router / Border Agent).
    Server,
}

impl Role {
    /// The ZKP identity of this role (mbedTLS `ecjpake_id`).
    pub const fn id(self) -> &'static [u8] {
        match self {
            Role::Client => b"client",
            Role::Server => b"server",
        }
    }

    /// The other role.
    pub const fn peer(self) -> Role {
        match self {
            Role::Client => Role::Server,
            Role::Server => Role::Client,
        }
    }
}

/// One EC-JPAKE key exchange (mbedTLS `mbedtls_ecjpake_context`).
///
/// Call order (both roles): [`write_round_one`](Self::write_round_one) and
/// [`read_round_one`](Self::read_round_one) (any order), then
/// [`write_round_two`](Self::write_round_two) and
/// [`read_round_two`](Self::read_round_two) (any order, both need both
/// round-one messages), then [`derive_secret`](Self::derive_secret).
/// Out-of-order calls fail with [`Error::InvalidState`].
pub struct EcJpake<C: P256> {
    curve: C,
    role: Role,
    /// Password scalar.
    s: C::Scalar,
    /// Own round-one private keys.
    xm1: C::Scalar,
    xm2: C::Scalar,
    /// Own round-one public keys.
    xm1_pub: Option<C::Point>,
    xm2_pub: Option<C::Point>,
    /// Peer round-one public keys.
    xp1: Option<C::Point>,
    xp2: Option<C::Point>,
    /// Peer round-two public key.
    xp: Option<C::Point>,
}

impl<C: P256> fmt::Debug for EcJpake<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EcJpake")
            .field("role", &self.role)
            .field("round_one_written", &self.xm1_pub.is_some())
            .field("round_one_read", &self.xp1.is_some())
            .field("round_two_read", &self.xp.is_some())
            .finish_non_exhaustive()
    }
}

impl<C: P256> Drop for EcJpake<C> {
    fn drop(&mut self) {
        self.s.zeroize();
        self.xm1.zeroize();
        self.xm2.zeroize();
    }
}

/// A cursor over a received message.
struct Reader<'a> {
    buf: &'a [u8],
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.buf.len() < n {
            return Err(Error::Parse);
        }
        let (head, tail) = self.buf.split_at(n);
        self.buf = tail;
        Ok(head)
    }

    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    /// `opaque <1..2^8-1>` (mbedTLS rejects a zero length for both
    /// `ECPoint` and `r`).
    fn vec8(&mut self) -> Result<&'a [u8]> {
        let len = self.u8()? as usize;
        if len == 0 {
            return Err(Error::Parse);
        }
        self.take(len)
    }

    fn finish(&self) -> Result<()> {
        if self.buf.is_empty() {
            Ok(())
        } else {
            Err(Error::Parse)
        }
    }
}

/// A cursor over an output buffer.
struct Writer<'a> {
    buf: &'a mut [u8],
    pos: usize,
}

impl Writer<'_> {
    fn put(&mut self, data: &[u8]) -> Result<()> {
        let end = self.pos.checked_add(data.len()).ok_or(Error::NoBufs)?;
        self.buf
            .get_mut(self.pos..end)
            .ok_or(Error::NoBufs)?
            .copy_from_slice(data);
        self.pos = end;
        Ok(())
    }
}

impl<C: P256> EcJpake<C> {
    /// Set up an exchange (mbedTLS `mbedtls_ecjpake_setup` with SHA-256 and
    /// secp256r1). `password` must be 1..=[`MAX_PASSWORD_LEN`] bytes and
    /// must not be a multiple of `n` as an integer (else
    /// [`Error::InvalidArgs`]).
    pub fn new(curve: C, role: Role, password: &[u8]) -> Result<Self> {
        if password.is_empty() || password.len() > MAX_PASSWORD_LEN {
            return Err(Error::InvalidArgs);
        }
        let mut padded = [0u8; SCALAR_LEN];
        padded[SCALAR_LEN - password.len()..].copy_from_slice(password);
        let s = curve.scalar_reduce(&padded);
        padded.zeroize();
        let zero = curve.scalar_reduce(&[0; SCALAR_LEN]);
        let this = Self {
            curve,
            role,
            s,
            xm1: zero,
            xm2: zero,
            xm1_pub: None,
            xm2_pub: None,
            xp1: None,
            xp2: None,
            xp: None,
        };
        if this.curve.scalar_is_zero(&this.s) {
            return Err(Error::InvalidArgs);
        }
        Ok(this)
    }

    /// Our role.
    pub fn role(&self) -> Role {
        self.role
    }

    /// Write the round-one message (`ECJPAKEKeyKPPairList`: our two keys
    /// with ZKPs) to `out`; returns its length (at most
    /// [`ROUND_ONE_MAX_LEN`]). Generates the round-one key pairs, so it can
    /// be called only once per exchange (a DTLS client re-sending its
    /// ClientHello after a HelloVerifyRequest must re-use the bytes, as
    /// mbedTLS does with its `ecjpake_cache`).
    pub fn write_round_one<B, R>(
        &mut self,
        crypto: &B,
        rng: &mut R,
        out: &mut [u8],
    ) -> Result<usize>
    where
        B: CryptoBackend,
        R: CryptoRng + ?Sized,
    {
        if self.xm1_pub.is_some() {
            return Err(Error::InvalidState);
        }
        let mut xm1 = self.random_scalar(rng)?;
        let mut xm2 = self.random_scalar(rng)?;
        let r = self.write_round_one_with_keys(crypto, rng, &xm1, &xm2, out);
        xm1.zeroize();
        xm2.zeroize();
        r
    }

    /// [`write_round_one`](Self::write_round_one) with given private keys
    /// (known-answer tests, mbedTLS `ecjpake_test_load`).
    fn write_round_one_with_keys<B, R>(
        &mut self,
        crypto: &B,
        rng: &mut R,
        xm1: &C::Scalar,
        xm2: &C::Scalar,
        out: &mut [u8],
    ) -> Result<usize>
    where
        B: CryptoBackend,
        R: CryptoRng + ?Sized,
    {
        let x1 = self.curve.mul_base(xm1);
        let x2 = self.curve.mul_base(xm2);
        let id = self.role.id();
        let mut w = Writer { buf: out, pos: 0 };
        let g = self.curve.generator();
        self.write_kkp(crypto, rng, &g, xm1, &x1, id, &mut w)?;
        self.write_kkp(crypto, rng, &g, xm2, &x2, id, &mut w)?;
        self.xm1 = *xm1;
        self.xm2 = *xm2;
        self.xm1_pub = Some(x1);
        self.xm2_pub = Some(x2);
        Ok(w.pos)
    }

    /// Set our round-one keys without writing (tests only: mbedTLS
    /// `ecjpake_test_load`).
    #[cfg(test)]
    fn load_keys(&mut self, xm1: &[u8; SCALAR_LEN], xm2: &[u8; SCALAR_LEN]) {
        self.xm1 = self.curve.scalar_from_be(xm1).unwrap();
        self.xm2 = self.curve.scalar_from_be(xm2).unwrap();
        self.xm1_pub = Some(self.curve.mul_base(&self.xm1));
        self.xm2_pub = Some(self.curve.mul_base(&self.xm2));
    }

    /// Read and verify the peer's round-one message.
    pub fn read_round_one<B: CryptoBackend>(&mut self, crypto: &B, data: &[u8]) -> Result<()> {
        if self.xp1.is_some() {
            return Err(Error::InvalidState);
        }
        let g = self.curve.generator();
        let id = self.role.peer().id();
        let mut r = Reader { buf: data };
        let xp1 = self.read_kkp(crypto, &g, id, &mut r)?;
        let xp2 = self.read_kkp(crypto, &g, id, &mut r)?;
        r.finish()?;
        self.xp1 = Some(xp1);
        self.xp2 = Some(xp2);
        Ok(())
    }

    /// Write our round-two message (server: `ServerECJPAKEParams` incl.
    /// [`CURVE_PARAMS`]; client: `ClientECJPAKEParams`); returns its length
    /// (at most [`ROUND_TWO_MAX_LEN`]).
    pub fn write_round_two<B, R>(
        &mut self,
        crypto: &B,
        rng: &mut R,
        out: &mut [u8],
    ) -> Result<usize>
    where
        B: CryptoBackend,
        R: CryptoRng + ?Sized,
    {
        let (Some(xm1), Some(xp1), Some(xp2)) = (self.xm1_pub, self.xp1, self.xp2) else {
            return Err(Error::InvalidState);
        };
        // G = Xm1 + Xp1 + Xp2, xm = xm2 * s, Xm = xm * G.
        let c = &self.curve;
        let g = c.add(&c.add(&xp1, &xp2), &xm1);
        if c.is_identity(&g) {
            return Err(Error::Security);
        }
        let mut xm = c.scalar_mul(&self.xm2, &self.s);
        let xm_pub = c.mul(&g, &xm);
        let mut w = Writer { buf: out, pos: 0 };
        let r = (|| {
            if self.role == Role::Server {
                w.put(&CURVE_PARAMS)?;
            }
            self.write_kkp(crypto, rng, &g, &xm, &xm_pub, self.role.id(), &mut w)
        })();
        xm.zeroize();
        r.map(|()| w.pos)
    }

    /// Read and verify the peer's round-two message.
    pub fn read_round_two<B: CryptoBackend>(&mut self, crypto: &B, data: &[u8]) -> Result<()> {
        let (Some(xm1), Some(xm2), Some(xp1)) = (self.xm1_pub, self.xm2_pub, self.xp1) else {
            return Err(Error::InvalidState);
        };
        if self.xp.is_some() {
            return Err(Error::InvalidState);
        }
        // Peer generator G = Xm1 + Xm2 + Xp1.
        let c = &self.curve;
        let g = c.add(&c.add(&xm1, &xm2), &xp1);
        if c.is_identity(&g) {
            return Err(Error::Security);
        }
        let mut r = Reader { buf: data };
        if self.role == Role::Client {
            // mbedtls_ecp_tls_read_group: named curve, must be secp256r1.
            if r.take(CURVE_PARAMS.len())? != CURVE_PARAMS {
                return Err(Error::Parse);
            }
        }
        let xp = self.read_kkp(crypto, &g, self.role.peer().id(), &mut r)?;
        r.finish()?;
        self.xp = Some(xp);
        Ok(())
    }

    /// The shared point `K = (Xp - Xp2 * xm2 * s) * xm2`.
    fn derive_k(&self) -> Result<C::Point> {
        let (Some(xp), Some(xp2)) = (self.xp, self.xp2) else {
            return Err(Error::InvalidState);
        };
        let c = &self.curve;
        let mut t = c.scalar_mul(&self.xm2, &self.s);
        let k = c.mul(&c.sub(&xp, &c.mul(&xp2, &t)), &self.xm2);
        t.zeroize();
        if c.is_identity(&k) {
            return Err(Error::Security);
        }
        Ok(k)
    }

    /// The premaster secret `SHA-256(x(K))` (mbedTLS
    /// `mbedtls_ecjpake_derive_secret`). Both sides get the same value iff
    /// they used the same password.
    pub fn derive_secret<B: CryptoBackend>(&self, crypto: &B) -> Result<[u8; PMS_LEN]> {
        let k = self.derive_k()?;
        let mut enc = self.curve.encode(&k).ok_or(Error::Security)?;
        let mut sha = crypto.sha256();
        sha.update(&enc[1..1 + SCALAR_LEN]);
        enc.zeroize();
        Ok(sha.finalize())
    }

    /// The shared point `K`, uncompressed (mbedTLS
    /// `mbedtls_ecjpake_write_shared_key`; for tests and diagnostics, TLS
    /// uses [`derive_secret`](Self::derive_secret)).
    pub fn shared_key(&self) -> Result<[u8; POINT_LEN]> {
        let k = self.derive_k()?;
        self.curve.encode(&k).ok_or(Error::Security)
    }

    /// A uniformly random scalar in `[1, n-1]` by rejection sampling of 32
    /// big-endian random bytes (mbedTLS `mbedtls_ecp_gen_privkey_sw`).
    fn random_scalar<R: CryptoRng + ?Sized>(&self, rng: &mut R) -> Result<C::Scalar> {
        let mut bytes = [0u8; SCALAR_LEN];
        for _ in 0..KEYGEN_ATTEMPTS {
            rng.fill_bytes(&mut bytes);
            let s = self.curve.scalar_from_be(&bytes);
            bytes.zeroize();
            if let Some(mut s) = s {
                if !self.curve.scalar_is_zero(&s) {
                    return Ok(s);
                }
                s.zeroize();
            }
        }
        Err(Error::Platform)
    }

    /// ZKP challenge `h = SHA-256(G, V, X, id) mod n` (mbedTLS
    /// `ecjpake_hash`).
    fn zkp_hash<B: CryptoBackend>(
        &self,
        crypto: &B,
        g: &[u8; POINT_LEN],
        v: &[u8; POINT_LEN],
        x: &[u8; POINT_LEN],
        id: &[u8],
    ) -> C::Scalar {
        let mut sha = crypto.sha256();
        for p in [g, v, x] {
            sha.update(&(POINT_LEN as u32).to_be_bytes());
            sha.update(p);
        }
        sha.update(&(id.len() as u32).to_be_bytes());
        sha.update(id);
        self.curve.scalar_reduce(&sha.finalize())
    }

    fn encode(&self, p: &C::Point) -> Result<[u8; POINT_LEN]> {
        // Only the identity has no encoding; callers never produce it for
        // valid inputs.
        self.curve.encode(p).ok_or(Error::Security)
    }

    /// Write `ECJPAKEKeyKP { ECPoint X; ECSchnorrZKP zkp; }` for the key
    /// pair `(x, X = x * G)`.
    #[allow(clippy::too_many_arguments)]
    fn write_kkp<B, R>(
        &self,
        crypto: &B,
        rng: &mut R,
        g: &C::Point,
        x: &C::Scalar,
        x_pub: &C::Point,
        id: &[u8],
        w: &mut Writer<'_>,
    ) -> Result<()>
    where
        B: CryptoBackend,
        R: CryptoRng + ?Sized,
    {
        let c = &self.curve;
        let g_enc = self.encode(g)?;
        let x_enc = self.encode(x_pub)?;
        // Schnorr NIZK: V = v * G, r = v - x * h. mbedTLS writes r with its
        // minimal length and cannot encode r = 0 (the peer rejects an empty
        // r), so such an (astronomically unlikely) v is drawn again.
        let (v_enc, r) = loop {
            let mut v = self.random_scalar(rng)?;
            let v_pub = c.mul(g, &v);
            let v_enc = self.encode(&v_pub)?;
            let h = self.zkp_hash(crypto, &g_enc, &v_enc, &x_enc, id);
            let mut xh = c.scalar_mul(x, &h);
            let r = c.scalar_sub(&v, &xh);
            v.zeroize();
            xh.zeroize();
            if !c.scalar_is_zero(&r) {
                break (v_enc, r);
            }
        };
        w.put(&[POINT_LEN as u8])?;
        w.put(&x_enc)?;
        w.put(&[POINT_LEN as u8])?;
        w.put(&v_enc)?;
        let r_be = c.scalar_to_be(&r);
        let skip = r_be.iter().take_while(|&&b| b == 0).count();
        w.put(&[(SCALAR_LEN - skip) as u8])?;
        w.put(&r_be[skip..])
    }

    /// Read and verify `ECJPAKEKeyKP` with generator `g` and prover
    /// identity `id`; returns `X`.
    fn read_kkp<B: CryptoBackend>(
        &self,
        crypto: &B,
        g: &C::Point,
        id: &[u8],
        rd: &mut Reader<'_>,
    ) -> Result<C::Point> {
        let c = &self.curve;
        let x_enc = rd.vec8()?;
        let x = c.decode(x_enc).ok_or(Error::Parse)?;
        let v_enc = rd.vec8()?;
        let v = c.decode(v_enc).ok_or(Error::Parse)?;
        let r_bytes = rd.vec8()?;
        // r as an integer (leading zeros allowed, as mbedTLS); must be < n
        // (mbedTLS: mbedtls_ecp_check_privkey in the multiplication).
        let skip = r_bytes.iter().take_while(|&&b| b == 0).count();
        let r_min = &r_bytes[skip..];
        if r_min.len() > SCALAR_LEN {
            return Err(Error::Security);
        }
        let mut r_be = [0u8; SCALAR_LEN];
        r_be[SCALAR_LEN - r_min.len()..].copy_from_slice(r_min);
        let r = c.scalar_from_be(&r_be).ok_or(Error::Security)?;

        let mut x_arr = [0u8; POINT_LEN];
        x_arr.copy_from_slice(x_enc);
        let mut v_arr = [0u8; POINT_LEN];
        v_arr.copy_from_slice(v_enc);
        let g_enc = self.encode(g)?;
        let h = self.zkp_hash(crypto, &g_enc, &v_arr, &x_arr, id);
        let vv = c.mul_add(&h, &x, &r, g);
        if !c.point_eq(&vv, &v) {
            return Err(Error::Security);
        }
        Ok(x)
    }
}
