//! The Joiner's Pre-Shared Key for Device (PSKd), Thread 1.4.1 section
//! 8.2 (OT `MeshCoP::JoinerPskd`).
//!
//! A PSKd is 6 to 32 characters of uppercase alphanumerics excluding `I`,
//! `O`, `Q` and `Z` (to avoid confusion with `1`, `0`, `2`). It is the
//! EC-JPAKE password of the Joiner's DTLS session.
//!
//! [`JoinerPskd`] is a secret: it is wiped when dropped or replaced, its
//! `Debug` output is redacted, and equality is constant-time.

use core::fmt;

use opentrust_core::{Error, Result};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Minimum PSKd length (OT `JoinerPskd::kMinLength`).
pub const MIN_LEN: usize = 6;
/// Maximum PSKd length (OT `OT_JOINER_MAX_PSKD_LENGTH`).
pub const MAX_LEN: usize = 32;

/// Is `c` an allowed PSKd character (digits and uppercase letters except
/// `I`, `O`, `Q`, `Z`; OT `JoinerPskd::IsPskdValid`)?
pub const fn is_valid_char(c: u8) -> bool {
    c.is_ascii_digit() || (c.is_ascii_uppercase() && !matches!(c, b'I' | b'O' | b'Q' | b'Z'))
}

/// Is `pskd` a valid PSKd (length and characters)?
pub fn is_valid(pskd: &str) -> bool {
    let b = pskd.as_bytes();
    (MIN_LEN..=MAX_LEN).contains(&b.len()) && b.iter().all(|&c| is_valid_char(c))
}

/// A validated PSKd.
#[derive(Clone)]
pub struct JoinerPskd {
    buf: [u8; MAX_LEN],
    len: u8,
}

impl JoinerPskd {
    /// Validate and copy `pskd` ([`Error::InvalidArgs`] if it is not a
    /// valid PSKd, see [`is_valid`]).
    pub fn new(pskd: &str) -> Result<Self> {
        if !is_valid(pskd) {
            return Err(Error::InvalidArgs);
        }
        let mut buf = [0u8; MAX_LEN];
        buf[..pskd.len()].copy_from_slice(pskd.as_bytes());
        Ok(Self {
            buf,
            len: pskd.len() as u8,
        })
    }

    /// The PSKd bytes (the EC-JPAKE password).
    pub fn as_bytes(&self) -> &[u8] {
        &self.buf[..usize::from(self.len)]
    }

    /// Length in characters.
    pub fn len(&self) -> usize {
        usize::from(self.len)
    }

    /// Always `false` for a validated PSKd.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl fmt::Debug for JoinerPskd {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("JoinerPskd(<redacted>)")
    }
}

#[cfg(feature = "defmt")]
impl defmt::Format for JoinerPskd {
    fn format(&self, f: defmt::Formatter<'_>) {
        defmt::write!(f, "JoinerPskd(<redacted>)")
    }
}

/// Constant-time comparison (the length is not secret).
impl PartialEq for JoinerPskd {
    fn eq(&self, other: &Self) -> bool {
        bool::from(self.buf.ct_eq(&other.buf) & self.len.ct_eq(&other.len))
    }
}

impl Eq for JoinerPskd {}

impl Zeroize for JoinerPskd {
    fn zeroize(&mut self) {
        self.buf.zeroize();
        self.len.zeroize();
    }
}

impl Drop for JoinerPskd {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for JoinerPskd {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validation_follows_ot() {
        for ok in [
            "J01NME",
            "ABCDEF",
            "123456",
            "J01NU5",
            "0123456789ABCDEFGHJKLMNPRSTUVWXY",
        ] {
            assert!(is_valid(ok), "{ok}");
            assert_eq!(JoinerPskd::new(ok).unwrap().as_bytes(), ok.as_bytes());
        }
        for bad in [
            "",
            "ABCDE",
            "0123456789ABCDEFGHJKLMNPRSTUVWXY0",
            "J01NMe",
            "JOINME",
            "QWERTY",
            "ABCDEI",
            "ZZZZZZ",
            "ABC DEF",
            "ABC-DEF",
            "ÄBCDEF",
        ] {
            assert!(!is_valid(bad), "{bad}");
            assert_eq!(JoinerPskd::new(bad).unwrap_err(), Error::InvalidArgs);
        }
    }

    #[test]
    fn secret_hygiene() {
        let a = JoinerPskd::new("J01NME").unwrap();
        assert_eq!(std::format!("{a:?}"), "JoinerPskd(<redacted>)");
        assert_eq!(a, JoinerPskd::new("J01NME").unwrap());
        assert_ne!(a, JoinerPskd::new("J01NMF").unwrap());
        assert_ne!(a, JoinerPskd::new("J01NME1").unwrap());
        let mut b = a.clone();
        b.zeroize();
        assert!(b.is_empty());
        assert_eq!(b.buf, [0; MAX_LEN]);
        fn zod<T: ZeroizeOnDrop>() {}
        zod::<JoinerPskd>();
    }
}
