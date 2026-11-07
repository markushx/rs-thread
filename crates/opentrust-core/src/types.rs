//! Fundamental Thread identifiers and parameters.

use core::fmt;
use core::net::Ipv6Addr;

use crate::error::{Error, Result};

fn write_hex(f: &mut fmt::Formatter<'_>, bytes: &[u8]) -> fmt::Result {
    for b in bytes {
        write!(f, "{b:02x}")?;
    }
    Ok(())
}

/// Defines a fixed-size byte-array newtype.
///
/// `public` types are `Copy` and get a hex `Debug`/`Display`.
/// `secret` types are deliberately not `Copy` (copies must be explicit via
/// `clone()`), redact their contents in `Debug`/`defmt`, compare in
/// constant time, and wipe their bytes on drop.
macro_rules! byte_array_type {
    ($(#[$m:meta])* $name:ident, $n:expr, public) => {
        byte_array_type!(@common $(#[$m])* #[derive(Clone, Copy, PartialEq, Eq, Hash, Default)] $name, $n);
        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write_hex(f, &self.0)
            }
        }
        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, concat!(stringify!($name), "("))?;
                write_hex(f, &self.0)?;
                f.write_str(")")
            }
        }
        #[cfg(feature = "defmt")]
        impl defmt::Format for $name {
            fn format(&self, f: defmt::Formatter<'_>) {
                defmt::write!(f, "{=str}({=[u8]:02x})", stringify!($name), &self.0[..])
            }
        }
    };
    ($(#[$m:meta])* $name:ident, $n:expr, secret) => {
        byte_array_type!(@common $(#[$m])* #[derive(Clone, Default)] $name, $n);
        /// Constant-time comparison.
        impl PartialEq for $name {
            fn eq(&self, other: &Self) -> bool {
                use subtle::ConstantTimeEq;
                self.0.ct_eq(&other.0).into()
            }
        }
        impl Eq for $name {}
        impl Drop for $name {
            fn drop(&mut self) {
                zeroize::Zeroize::zeroize(&mut self.0);
            }
        }
        impl zeroize::ZeroizeOnDrop for $name {}
        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(concat!(stringify!($name), "(<redacted>)"))
            }
        }
        /// Wipes the key bytes (also done automatically on drop).
        impl zeroize::Zeroize for $name {
            fn zeroize(&mut self) {
                self.0.zeroize();
            }
        }
        #[cfg(feature = "defmt")]
        impl defmt::Format for $name {
            fn format(&self, f: defmt::Formatter<'_>) {
                defmt::write!(f, "{=str}(<redacted>)", stringify!($name))
            }
        }
    };
    (@common $(#[$m:meta])* $name:ident, $n:expr) => {
        $(#[$m])*
        pub struct $name(pub [u8; $n]);

        impl $name {
            /// Length in bytes.
            pub const LEN: usize = $n;

            /// Construct from a slice of exactly [`Self::LEN`] bytes.
            pub fn from_slice(s: &[u8]) -> Result<Self> {
                s.try_into().map(Self).map_err(|_| Error::InvalidArgs)
            }

            /// The raw bytes.
            pub const fn as_bytes(&self) -> &[u8; $n] {
                &self.0
            }
        }

        impl From<[u8; $n]> for $name {
            fn from(b: [u8; $n]) -> Self {
                Self(b)
            }
        }

        impl AsRef<[u8]> for $name {
            fn as_ref(&self) -> &[u8] {
                &self.0
            }
        }
    };
}

byte_array_type!(
    /// IEEE 802.15.4 extended (EUI-64 style) address, in big-endian (canonical) byte order.
    ExtAddress, 8, public
);
byte_array_type!(
    /// Extended PAN ID.
    ExtPanId, 8, public
);
byte_array_type!(
    /// IPv6 interface identifier (lower 64 bits of an address).
    Iid, 8, public
);
byte_array_type!(
    /// Thread Network Key (128-bit master key).
    NetworkKey, 16, secret
);
byte_array_type!(
    /// Pre-Shared Key for the Commissioner (PSKc).
    Pskc, 16, secret
);
byte_array_type!(
    /// IEEE 802.15.4 MAC frame-security key (AES-128), derived from the
    /// [`NetworkKey`] (see [`crate::crypto::kdf::thread_keys`]).
    MacKey, 16, secret
);
byte_array_type!(
    /// MLE message-security key (AES-128), derived from the [`NetworkKey`]
    /// (see [`crate::crypto::kdf::thread_keys`]).
    MleKey, 16, secret
);
byte_array_type!(
    /// Key Encryption Key used for the Joiner Entrust message (Thread §7.4.7.8).
    Kek, 16, secret
);

impl ExtAddress {
    /// Toggle the IEEE U/L bit to derive a modified EUI-64 IID (RFC 4291).
    pub const fn to_iid(&self) -> Iid {
        let mut b = self.0;
        b[0] ^= 0x02;
        Iid(b)
    }
}

impl Iid {
    /// Prefix of the RLOC/ALOC interface identifier: `0000:00ff:fe00:xxxx`.
    pub const LOCATOR_PREFIX: [u8; 6] = [0x00, 0x00, 0x00, 0xff, 0xfe, 0x00];

    /// Locator IID `0000:00ff:fe00:<locator>`.
    pub const fn from_locator(locator: u16) -> Self {
        let l = locator.to_be_bytes();
        Iid([0, 0, 0, 0xff, 0xfe, 0, l[0], l[1]])
    }

    /// `true` if this is a RLOC or ALOC IID.
    pub fn is_locator(&self) -> bool {
        self.0[..6] == Self::LOCATOR_PREFIX
    }

    /// The 16-bit locator, if this is a locator IID.
    pub fn locator(&self) -> Option<u16> {
        self.is_locator()
            .then(|| u16::from_be_bytes([self.0[6], self.0[7]]))
    }

    /// `true` if this is an Anycast Locator IID (`0xfc00..=0xfcff`).
    pub fn is_aloc(&self) -> bool {
        matches!(self.locator(), Some(0xfc00..=0xfcff))
    }

    /// `true` if this is a Routing Locator IID (locator outside the ALOC range).
    pub fn is_rloc(&self) -> bool {
        matches!(self.locator(), Some(l) if !(0xfc00..=0xfcff).contains(&l))
    }

    /// Extended address from a link-local IID (inverse of [`ExtAddress::to_iid`]).
    pub const fn to_ext_address(&self) -> ExtAddress {
        let mut b = self.0;
        b[0] ^= 0x02;
        ExtAddress(b)
    }
}

/// IEEE 802.15.4 short address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct ShortAddress(pub u16);

impl ShortAddress {
    /// Broadcast short address.
    pub const BROADCAST: Self = Self(0xffff);
    /// "No short address" (use extended addressing).
    pub const INVALID: Self = Self(0xfffe);
}

/// Routing Locator (RLOC16): Router ID (bits 15..10) and Child ID (bits 8..0).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Rloc16(pub u16);

impl Rloc16 {
    /// Invalid RLOC16.
    pub const INVALID: Self = Self(0xfffe);
    /// Highest valid Router ID.
    pub const MAX_ROUTER_ID: u8 = 62;
    /// Highest Child ID (9 bits).
    pub const MAX_CHILD_ID: u16 = 0x1ff;
    const ROUTER_SHIFT: u16 = 10;

    /// Build from Router ID and Child ID.
    pub fn new(router_id: u8, child_id: u16) -> Result<Self> {
        if router_id > Self::MAX_ROUTER_ID || child_id > Self::MAX_CHILD_ID {
            return Err(Error::InvalidArgs);
        }
        Ok(Self(
            (u16::from(router_id) << Self::ROUTER_SHIFT) | child_id,
        ))
    }

    /// RLOC16 of a router (Child ID 0).
    pub fn from_router_id(router_id: u8) -> Result<Self> {
        Self::new(router_id, 0)
    }

    /// Router ID part.
    pub const fn router_id(self) -> u8 {
        (self.0 >> Self::ROUTER_SHIFT) as u8
    }

    /// Child ID part.
    pub const fn child_id(self) -> u16 {
        self.0 & Self::MAX_CHILD_ID
    }

    /// `true` if this RLOC16 identifies a router (Child ID 0).
    pub const fn is_router(self) -> bool {
        self.child_id() == 0
    }

    /// RLOC16 of the parent router.
    pub const fn parent(self) -> Self {
        Self(self.0 & !Self::MAX_CHILD_ID & !(1 << 9))
    }
}

impl From<Rloc16> for ShortAddress {
    fn from(r: Rloc16) -> Self {
        ShortAddress(r.0)
    }
}

/// IEEE 802.15.4 PAN ID.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct PanId(pub u16);

impl PanId {
    /// Broadcast PAN ID.
    pub const BROADCAST: Self = Self(0xffff);
}

/// IEEE 802.15.4 channel on page 0 (2.4 GHz O-QPSK, channels 11–26).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Channel(u8);

impl Channel {
    /// Lowest 2.4 GHz channel.
    pub const MIN: u8 = 11;
    /// Highest 2.4 GHz channel.
    pub const MAX: u8 = 26;

    /// Validate and wrap a channel number.
    pub const fn new(ch: u8) -> Result<Self> {
        if ch >= Self::MIN && ch <= Self::MAX {
            Ok(Self(ch))
        } else {
            Err(Error::InvalidArgs)
        }
    }

    /// Channel number.
    pub const fn get(self) -> u8 {
        self.0
    }

    /// Bit for this channel in a page-0 channel mask.
    pub const fn mask_bit(self) -> u32 {
        1 << self.0
    }
}

/// Thread network name: 1–16 bytes of UTF-8.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct NetworkName {
    buf: [u8; Self::MAX_LEN],
    len: u8,
}

impl NetworkName {
    /// Maximum length in bytes.
    pub const MAX_LEN: usize = 16;

    /// Validate and copy a network name.
    pub fn new(name: &str) -> Result<Self> {
        Self::from_bytes(name.as_bytes())
    }

    /// Validate (length, UTF-8) and copy a network name from raw bytes.
    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        if b.is_empty() || b.len() > Self::MAX_LEN || core::str::from_utf8(b).is_err() {
            return Err(Error::InvalidArgs);
        }
        let mut buf = [0u8; Self::MAX_LEN];
        buf[..b.len()].copy_from_slice(b);
        Ok(Self {
            buf,
            len: b.len() as u8,
        })
    }

    /// The name as raw bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.buf[..usize::from(self.len)]
    }

    /// The name as a string.
    pub fn as_str(&self) -> &str {
        // Validated on construction.
        core::str::from_utf8(self.as_bytes()).unwrap_or_default()
    }
}

impl fmt::Debug for NetworkName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "NetworkName({:?})", self.as_str())
    }
}

#[cfg(feature = "defmt")]
impl defmt::Format for NetworkName {
    fn format(&self, f: defmt::Formatter<'_>) {
        defmt::write!(f, "NetworkName({=str})", self.as_str())
    }
}

/// 64-bit IPv6 prefix (mesh-local prefix, on-mesh prefixes).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Prefix64(pub [u8; 8]);

/// Mesh-Local Prefix (`fdxx:xxxx:xxxx:xxxx::/64`).
pub type MeshLocalPrefix = Prefix64;

impl Prefix64 {
    /// Combine this prefix with an interface identifier.
    pub fn with_iid(&self, iid: &Iid) -> Ipv6Addr {
        let mut a = [0u8; 16];
        a[..8].copy_from_slice(&self.0);
        a[8..].copy_from_slice(&iid.0);
        Ipv6Addr::from(a)
    }

    /// `true` if `addr` lies within this /64 prefix.
    pub fn contains(&self, addr: &Ipv6Addr) -> bool {
        addr.octets()[..8] == self.0
    }

    /// Routing Locator address for `rloc16`.
    pub fn rloc(&self, rloc16: Rloc16) -> Ipv6Addr {
        self.with_iid(&Iid::from_locator(rloc16.0))
    }

    /// Anycast Locator address; `aloc16` must be in `0xfc00..=0xfcff`.
    pub fn aloc(&self, aloc16: u16) -> Result<Ipv6Addr> {
        if !(0xfc00..=0xfcff).contains(&aloc16) {
            return Err(Error::InvalidArgs);
        }
        Ok(self.with_iid(&Iid::from_locator(aloc16)))
    }
}

impl fmt::Debug for Prefix64 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut a = [0u8; 16];
        a[..8].copy_from_slice(&self.0);
        write!(f, "{}/64", Ipv6Addr::from(a))
    }
}

#[cfg(feature = "defmt")]
impl defmt::Format for Prefix64 {
    fn format(&self, f: defmt::Formatter<'_>) {
        defmt::write!(f, "Prefix64({=[u8]:02x})", &self.0[..])
    }
}

/// IPv6 address helpers.
pub mod ipv6 {
    use super::*;

    /// `fe80::/64`.
    pub const LINK_LOCAL_PREFIX: Prefix64 = Prefix64([0xfe, 0x80, 0, 0, 0, 0, 0, 0]);
    /// Link-local all-nodes `ff02::1`.
    pub const LINK_LOCAL_ALL_NODES: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1);
    /// Link-local all-routers `ff02::2`.
    pub const LINK_LOCAL_ALL_ROUTERS: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 2);
    /// Realm-local all-nodes `ff03::1`.
    pub const REALM_LOCAL_ALL_NODES: Ipv6Addr = Ipv6Addr::new(0xff03, 0, 0, 0, 0, 0, 0, 1);
    /// Realm-local all-routers `ff03::2`.
    pub const REALM_LOCAL_ALL_ROUTERS: Ipv6Addr = Ipv6Addr::new(0xff03, 0, 0, 0, 0, 0, 0, 2);
    /// Realm-local all-MPL-forwarders `ff03::fc`.
    pub const REALM_LOCAL_ALL_MPL_FORWARDERS: Ipv6Addr =
        Ipv6Addr::new(0xff03, 0, 0, 0, 0, 0, 0, 0xfc);

    /// Link-local address derived from an extended address.
    pub fn link_local(ext: &ExtAddress) -> Ipv6Addr {
        LINK_LOCAL_PREFIX.with_iid(&ext.to_iid())
    }

    /// Interface identifier (lower 64 bits) of an address.
    pub fn iid(addr: &Ipv6Addr) -> Iid {
        let mut b = [0u8; 8];
        b.copy_from_slice(&addr.octets()[8..]);
        Iid(b)
    }

    /// `true` for `fe80::/10`.
    pub fn is_link_local(addr: &Ipv6Addr) -> bool {
        addr.is_unicast_link_local()
    }

    /// Multicast scope (4 bits), if `addr` is multicast.
    pub fn multicast_scope(addr: &Ipv6Addr) -> Option<u8> {
        addr.is_multicast().then(|| addr.octets()[1] & 0x0f)
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::format;

    #[test]
    fn rloc16_parts() {
        let r = Rloc16::new(5, 3).unwrap();
        assert_eq!(r.0, 0x1403);
        assert_eq!(r.router_id(), 5);
        assert_eq!(r.child_id(), 3);
        assert!(!r.is_router());
        assert_eq!(r.parent(), Rloc16(0x1400));
        assert!(Rloc16::from_router_id(5).unwrap().is_router());
        assert_eq!(Rloc16::new(63, 0), Err(Error::InvalidArgs));
        assert_eq!(Rloc16::new(0, 0x200), Err(Error::InvalidArgs));
    }

    #[test]
    fn locator_addresses() {
        let mlp = Prefix64([0xfd, 0xde, 0xad, 0x00, 0xbe, 0xef, 0x00, 0x00]);
        let rloc = mlp.rloc(Rloc16(0x0400));
        assert_eq!(
            rloc,
            "fdde:ad00:beef:0:0:ff:fe00:400"
                .parse::<Ipv6Addr>()
                .unwrap()
        );
        let iid = ipv6::iid(&rloc);
        assert!(iid.is_rloc() && !iid.is_aloc());
        assert_eq!(iid.locator(), Some(0x0400));
        let aloc = mlp.aloc(0xfc00).unwrap();
        assert!(ipv6::iid(&aloc).is_aloc());
        assert!(mlp.contains(&aloc));
        assert_eq!(mlp.aloc(0x1234), Err(Error::InvalidArgs));
    }

    #[test]
    fn link_local_from_ext() {
        let ext = ExtAddress([0x18, 0xb4, 0x30, 0x00, 0x00, 0x00, 0x00, 0x01]);
        let ll = ipv6::link_local(&ext);
        assert_eq!(ll, "fe80::1ab4:3000:0:1".parse::<Ipv6Addr>().unwrap());
        assert_eq!(ipv6::iid(&ll).to_ext_address(), ext);
        assert!(ipv6::is_link_local(&ll));
        assert_eq!(ipv6::multicast_scope(&ipv6::REALM_LOCAL_ALL_NODES), Some(3));
    }

    #[test]
    fn channel_and_name() {
        assert!(Channel::new(10).is_err() && Channel::new(27).is_err());
        assert_eq!(Channel::new(11).unwrap().mask_bit(), 1 << 11);
        let n = NetworkName::new("OpenThread").unwrap();
        assert_eq!(n.as_str(), "OpenThread");
        assert!(NetworkName::new("").is_err());
        assert!(NetworkName::new("12345678901234567").is_err());
        assert!(NetworkName::from_bytes(&[0xff]).is_err());
    }

    #[test]
    fn secrets_redacted() {
        let k = NetworkKey([0xaa; 16]);
        assert_eq!(format!("{k:?}"), "NetworkKey(<redacted>)");
        let e = ExtAddress([1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(format!("{e}"), "0102030405060708");
        assert_eq!(ExtAddress::from_slice(&[0; 7]), Err(Error::InvalidArgs));
    }

    #[test]
    fn secrets_zeroize_and_compare() {
        fn zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}
        zeroize_on_drop::<NetworkKey>();
        zeroize_on_drop::<Pskc>();
        zeroize_on_drop::<MacKey>();
        zeroize_on_drop::<MleKey>();
        zeroize_on_drop::<Kek>();

        let a = NetworkKey([0x11; 16]);
        let mut b = a.clone();
        assert_eq!(a, b);
        zeroize::Zeroize::zeroize(&mut b);
        assert_eq!(b.0, [0; 16]);
        assert_ne!(a, b);
    }
}
