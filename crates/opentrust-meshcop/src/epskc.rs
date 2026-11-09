//! The Ephemeral Pre-Shared Key for the Commissioner (ePSKc), Thread 1.4.1
//! sections 8.4.1.2.3 and 8.4.9 (OT `BorderAgent::EphemeralKeyManager`,
//! `Utils::VerhoeffChecksum`).
//!
//! An ePSKc is a single-use, short-lived EC-JPAKE password of
//! [`MIN_LEN`]..=[`MAX_LEN`] octets that a Border Agent accepts on a
//! separate DTLS port (see `border_agent`, feature `border-agent`). Like
//! OpenThread, the key octets are used directly as the EC-JPAKE password
//! (there is no derivation step as for the PSKc). In Thread 1.4.1 an ePSKc
//! is always derived from a Thread Administration One-Time Passcode of
//! [`PASSCODE_LENGTH`] decimal digits, the last one a Verhoeff check
//! digit: the ePSKc is the passcode's US-ASCII digits
//! ([`EphemeralKey::generate_passcode`]).
//!
//! [`EphemeralKey`] is a secret: it is wiped when dropped or replaced, its
//! `Debug` output is redacted, and equality is constant-time.

use core::fmt;

use opentrust_core::time::Duration;
use opentrust_core::{Error, Result};
use rand_core::CryptoRng;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Minimum ePSKc length in octets (`MIN_EPSKC_LENGTH`, OT
/// `OT_BORDER_AGENT_MIN_EPHEMERAL_KEY_LENGTH`).
pub const MIN_LEN: usize = 6;
/// Maximum ePSKc length in octets (`MAX_EPSKC_LENGTH`, OT
/// `OT_BORDER_AGENT_MAX_EPHEMERAL_KEY_LENGTH`; also the EC-JPAKE password
/// limit).
pub const MAX_LEN: usize = 32;
/// Digits of a Thread Administration One-Time Passcode
/// (`PASSCODE_LENGTH`), including the Verhoeff check digit.
pub const PASSCODE_LENGTH: usize = 9;
/// How long an ePSKc is accepted when the caller does not say (OT
/// `OT_BORDER_AGENT_DEFAULT_EPHEMERAL_KEY_TIMEOUT`).
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(2 * 60);
/// The longest an ePSKc may be retained (`TIMEOUT_EPSKC`, OT
/// `OT_BORDER_AGENT_MAX_EPHEMERAL_KEY_TIMEOUT`); longer requests are
/// clamped.
pub const MAX_TIMEOUT: Duration = Duration::from_secs(10 * 60);
/// DTLS connection attempts before the ePSKc is discarded
/// (`MAX_EPSKC_CONN_ATTEMPTS`, OT `kMaxConnectionAttempts`).
pub const MAX_CONNECTION_ATTEMPTS: u16 = 10;
/// DNS-SD service type of the MeshCoP-ePSKc service (section 8.4.9.4.4).
pub const SERVICE_TYPE: &str = "_meshcop-e._udp";
/// The ePSKc Support flag of the MeshCoP service's State Bitmap (`sb`)
/// TXT record (bit 11, OT `StateBitmap::kFlagEpskcSupported`).
pub const STATE_BITMAP_EPSKC_SUPPORTED: u32 = 1 << 11;

/// The timeout an ePSKc is used with: [`DEFAULT_TIMEOUT`] for zero,
/// clamped to [`MAX_TIMEOUT`] (OT `EphemeralKeyManager::Start`).
pub fn effective_timeout(requested: Duration) -> Duration {
    let t = if requested.is_zero() {
        DEFAULT_TIMEOUT
    } else {
        requested
    };
    if t > MAX_TIMEOUT { MAX_TIMEOUT } else { t }
}

/// A validated ePSKc.
#[derive(Clone)]
pub struct EphemeralKey {
    buf: [u8; MAX_LEN],
    len: u8,
}

impl EphemeralKey {
    /// Validate and copy `key`: [`MIN_LEN`]..=[`MAX_LEN`] octets without
    /// a NUL octet (OT takes the key as a C string; any other octet is
    /// accepted). [`Error::InvalidArgs`] otherwise.
    pub fn new(key: &[u8]) -> Result<Self> {
        if !(MIN_LEN..=MAX_LEN).contains(&key.len()) || key.contains(&0) {
            return Err(Error::InvalidArgs);
        }
        let mut buf = [0u8; MAX_LEN];
        buf[..key.len()].copy_from_slice(key);
        Ok(Self {
            buf,
            len: key.len() as u8,
        })
    }

    /// A new Thread Administration One-Time Passcode (section 8.4.9.7):
    /// [`PASSCODE_LENGTH`] - 1 cryptographically random decimal digits and
    /// a Verhoeff check digit, as the ePSKc (its US-ASCII digits). The
    /// passcode shown to the user is [`as_bytes`](Self::as_bytes).
    pub fn generate_passcode<R: CryptoRng + ?Sized>(rng: &mut R) -> Self {
        let mut buf = [0u8; MAX_LEN];
        let mut i = 0;
        let mut pool = [0u8; 16];
        while i < PASSCODE_LENGTH - 1 {
            rng.fill_bytes(&mut pool);
            for &b in &pool {
                // Rejection sampling: 250 = 25 * 10 keeps the digits uniform.
                if b < 250 && i < PASSCODE_LENGTH - 1 {
                    buf[i] = b'0' + b % 10;
                    i += 1;
                }
            }
        }
        pool.zeroize();
        // The digits are valid, so the check digit always exists.
        buf[PASSCODE_LENGTH - 1] =
            verhoeff_check_digit(&buf[..PASSCODE_LENGTH - 1]).unwrap_or(b'0');
        Self {
            buf,
            len: PASSCODE_LENGTH as u8,
        }
    }

    /// The key octets (the EC-JPAKE password).
    pub fn as_bytes(&self) -> &[u8] {
        &self.buf[..usize::from(self.len)]
    }

    /// Length in octets.
    pub fn len(&self) -> usize {
        usize::from(self.len)
    }

    /// Always `false` for a validated key.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl fmt::Debug for EphemeralKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("EphemeralKey(<redacted>)")
    }
}

#[cfg(feature = "defmt")]
impl defmt::Format for EphemeralKey {
    fn format(&self, f: defmt::Formatter<'_>) {
        defmt::write!(f, "EphemeralKey(<redacted>)")
    }
}

/// Constant-time comparison (the length is not secret).
impl PartialEq for EphemeralKey {
    fn eq(&self, other: &Self) -> bool {
        bool::from(self.buf.ct_eq(&other.buf) & self.len.ct_eq(&other.len))
    }
}

impl Eq for EphemeralKey {}

impl Zeroize for EphemeralKey {
    fn zeroize(&mut self) {
        self.buf.zeroize();
        self.len.zeroize();
    }
}

impl Drop for EphemeralKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for EphemeralKey {}

// Verhoeff dihedral group D5 tables (multiplication, permutation,
// inverse).
const D: [[u8; 10]; 10] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
    [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
    [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
    [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
    [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
    [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
    [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
    [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
    [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
];
const P: [[u8; 10]; 8] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
    [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
    [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
    [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
    [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
    [7, 0, 4, 2, 9, 5, 3, 1, 8, 6],
];
const INV: [u8; 10] = [0, 4, 3, 2, 1, 5, 6, 7, 8, 9];

/// The Verhoeff code of ASCII `digits` with the digit positions shifted by
/// `offset` (1 when computing a check digit); `None` for a non-digit.
fn verhoeff_code(digits: &[u8], offset: usize) -> Option<u8> {
    let mut c = 0u8;
    for (i, &d) in digits.iter().rev().enumerate() {
        if !d.is_ascii_digit() {
            return None;
        }
        c = D[usize::from(c)][usize::from(P[(i + offset) % 8][usize::from(d - b'0')])];
    }
    Some(c)
}

/// The Verhoeff check digit (as an ASCII digit) to append to the ASCII
/// decimal string `digits` (OT `VerhoeffChecksum::Calculate`); `None` if
/// it holds a non-digit.
pub fn verhoeff_check_digit(digits: &[u8]) -> Option<u8> {
    verhoeff_code(digits, 1).map(|c| b'0' + INV[usize::from(c)])
}

/// Does the ASCII decimal string `digits` end in a valid Verhoeff check
/// digit (OT `VerhoeffChecksum::Validate`)?
pub fn verhoeff_is_valid(digits: &[u8]) -> bool {
    !digits.is_empty() && verhoeff_code(digits, 0) == Some(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_rng::TestRng;

    #[test]
    fn validation_follows_ot() {
        for ok in [&b"123456"[..], b"903723159", b"abc DEF", &[0xff; 32]] {
            assert_eq!(EphemeralKey::new(ok).unwrap().as_bytes(), ok);
        }
        for bad in [&b""[..], b"12345", &[b'1'; 33], b"123\x00456"] {
            assert_eq!(EphemeralKey::new(bad).unwrap_err(), Error::InvalidArgs);
        }
    }

    #[test]
    fn timeouts_follow_ot() {
        assert_eq!(effective_timeout(Duration::ZERO), DEFAULT_TIMEOUT);
        assert_eq!(
            effective_timeout(Duration::from_secs(5)),
            Duration::from_secs(5)
        );
        assert_eq!(effective_timeout(Duration::from_secs(3600)), MAX_TIMEOUT);
    }

    #[test]
    fn verhoeff_vectors() {
        // OT CLI README (`verhoeff calculate 30731842` -> 1), Thread 1.4.1
        // section 8.4.9.7 example, and the classic `236` -> 3.
        assert_eq!(verhoeff_check_digit(b"30731842"), Some(b'1'));
        assert!(verhoeff_is_valid(b"307318421"));
        assert!(!verhoeff_is_valid(b"307318425"));
        assert!(verhoeff_is_valid(b"903723159"));
        assert_eq!(verhoeff_check_digit(b"236"), Some(b'3'));
        assert_eq!(verhoeff_check_digit(b"12a"), None);
        assert!(!verhoeff_is_valid(b""));
        // Every single-digit substitution is detected.
        let mut s = *b"903723159";
        for i in 0..s.len() {
            let orig = s[i];
            for d in b'0'..=b'9' {
                s[i] = d;
                assert_eq!(verhoeff_is_valid(&s), d == orig);
            }
            s[i] = orig;
        }
    }

    #[test]
    fn passcode() {
        let mut rng = TestRng(5);
        let a = EphemeralKey::generate_passcode(&mut rng);
        let b = EphemeralKey::generate_passcode(&mut rng);
        assert_eq!(a.len(), PASSCODE_LENGTH);
        assert!(a.as_bytes().iter().all(u8::is_ascii_digit));
        assert!(verhoeff_is_valid(a.as_bytes()));
        assert!(verhoeff_is_valid(b.as_bytes()));
        assert_ne!(a, b);
    }

    #[test]
    fn secret_hygiene() {
        let a = EphemeralKey::new(b"903723159").unwrap();
        assert_eq!(std::format!("{a:?}"), "EphemeralKey(<redacted>)");
        assert_eq!(a, EphemeralKey::new(b"903723159").unwrap());
        assert_ne!(a, EphemeralKey::new(b"903723158").unwrap());
        assert_ne!(a, EphemeralKey::new(b"9037231590").unwrap());
        let mut b = a.clone();
        b.zeroize();
        assert!(b.is_empty());
        assert_eq!(b.buf, [0; MAX_LEN]);
        fn zod<T: ZeroizeOnDrop>() {}
        zod::<EphemeralKey>();
    }
}
