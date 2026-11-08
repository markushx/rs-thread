//! IPv6 address helpers: scopes, prefix matching, reserved IIDs and the
//! Thread-specific multicast groups (Thread 1.4.1 section 5.2).

use core::net::Ipv6Addr;

use opentrust_core::types::{Iid, Prefix64};

/// Node-local scope.
pub const SCOPE_NODE_LOCAL: u8 = 0x1;
/// Link-local scope.
pub const SCOPE_LINK_LOCAL: u8 = 0x2;
/// Realm-local scope.
pub const SCOPE_REALM_LOCAL: u8 = 0x3;
/// Admin-local scope.
pub const SCOPE_ADMIN_LOCAL: u8 = 0x4;
/// Site-local scope.
pub const SCOPE_SITE_LOCAL: u8 = 0x5;
/// Organization-local scope.
pub const SCOPE_ORG_LOCAL: u8 = 0x8;
/// Global scope (OT uses 0xe for all non-link-local unicast).
pub const SCOPE_GLOBAL: u8 = 0xe;

/// Scope of an address as OpenThread's `Address::GetScope()` defines it:
/// multicast scope nibble, link-local unicast, loopback (node-local), and
/// otherwise global.
pub fn scope(addr: &Ipv6Addr) -> u8 {
    if addr.is_multicast() {
        addr.octets()[1] & 0x0f
    } else if addr.is_unicast_link_local() {
        SCOPE_LINK_LOCAL
    } else if addr.is_loopback() {
        SCOPE_NODE_LOCAL
    } else {
        SCOPE_GLOBAL
    }
}

/// Number of leading bits shared by `a` and `b` (OT `Address::PrefixMatch`).
pub fn prefix_match_len(a: &Ipv6Addr, b: &Ipv6Addr) -> u8 {
    let (a, b) = (a.octets(), b.octets());
    let mut n = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        let d = x ^ y;
        if d == 0 {
            n += 8;
        } else {
            n += d.leading_zeros() as u8;
            break;
        }
    }
    n
}

/// `true` if the first `len` bits of `addr` equal those of `prefix`.
pub fn matches_prefix(addr: &Ipv6Addr, prefix: &Ipv6Addr, len: u8) -> bool {
    prefix_match_len(addr, prefix) >= len.min(128)
}

/// `true` for a multicast address with scope greater than realm-local.
pub fn is_multicast_larger_than_realm_local(addr: &Ipv6Addr) -> bool {
    addr.is_multicast() && scope(addr) > SCOPE_REALM_LOCAL
}

/// `true` for a multicast address with realm-local scope.
pub fn is_realm_local_multicast(addr: &Ipv6Addr) -> bool {
    addr.is_multicast() && scope(addr) == SCOPE_REALM_LOCAL
}

/// `true` for a link-local multicast address.
pub fn is_link_local_multicast(addr: &Ipv6Addr) -> bool {
    addr.is_multicast() && scope(addr) == SCOPE_LINK_LOCAL
}

/// `true` if `addr` lies in the mesh-local /64.
pub fn is_mesh_local(addr: &Ipv6Addr, mlp: &Prefix64) -> bool {
    mlp.contains(addr)
}

/// `true` if `addr` is a mesh-local RLOC.
pub fn is_routing_locator(addr: &Ipv6Addr, mlp: &Prefix64) -> bool {
    mlp.contains(addr) && opentrust_core::types::ipv6::iid(addr).is_rloc()
}

/// `true` if `addr` is a mesh-local ALOC.
pub fn is_anycast_locator(addr: &Ipv6Addr, mlp: &Prefix64) -> bool {
    mlp.contains(addr) && opentrust_core::types::ipv6::iid(addr).is_aloc()
}

/// IIDs that must not be assigned by SLAAC (OT `InterfaceIdentifier::IsReserved`):
/// the subnet-router anycast IID (all zero), the reserved subnet anycast IIDs
/// (RFC 2526, `fdff:ffff:ffff:ff80`-`ff`) and anycast-locator IIDs.
pub fn iid_is_reserved(iid: &Iid) -> bool {
    let b = &iid.0;
    let subnet_router_anycast = b.iter().all(|&x| x == 0);
    let reserved_subnet_anycast =
        b[..7] == [0xfd, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff] && b[7] >= 0x80;
    subnet_router_anycast || reserved_subnet_anycast || iid.is_aloc()
}

/// Link-local all-Thread-nodes `ff32:40:<mlp>::1` (RFC 3306 network-prefix
/// multicast, scope 2, plen 0x40, group ID 1).
pub fn link_local_all_thread_nodes(mlp: &Prefix64) -> Ipv6Addr {
    thread_nodes(mlp, SCOPE_LINK_LOCAL)
}

/// Realm-local all-Thread-nodes `ff33:40:<mlp>::1`.
pub fn realm_local_all_thread_nodes(mlp: &Prefix64) -> Ipv6Addr {
    thread_nodes(mlp, SCOPE_REALM_LOCAL)
}

fn thread_nodes(mlp: &Prefix64, scope: u8) -> Ipv6Addr {
    let mut a = [0u8; 16];
    a[0] = 0xff;
    a[1] = 0x30 | scope;
    a[3] = 0x40;
    a[4..12].copy_from_slice(&mlp.0);
    a[15] = 1;
    Ipv6Addr::from(a)
}

#[cfg(test)]
mod tests {
    use super::*;
    use opentrust_core::types::Rloc16;

    const MLP: Prefix64 = Prefix64([0xfd, 0xde, 0xad, 0x00, 0xbe, 0xef, 0x00, 0x00]);

    #[test]
    fn scopes() {
        assert_eq!(scope(&"ff02::1".parse().unwrap()), SCOPE_LINK_LOCAL);
        assert_eq!(scope(&"ff03::fc".parse().unwrap()), SCOPE_REALM_LOCAL);
        assert_eq!(scope(&"ff0e::1".parse().unwrap()), SCOPE_GLOBAL);
        assert_eq!(scope(&"fe80::1".parse().unwrap()), SCOPE_LINK_LOCAL);
        assert_eq!(scope(&"::1".parse().unwrap()), SCOPE_NODE_LOCAL);
        assert_eq!(scope(&"fd00::1".parse().unwrap()), SCOPE_GLOBAL);
        assert!(is_realm_local_multicast(&"ff03::1".parse().unwrap()));
        assert!(is_multicast_larger_than_realm_local(
            &"ff04::1".parse().unwrap()
        ));
        assert!(!is_multicast_larger_than_realm_local(
            &"ff03::1".parse().unwrap()
        ));
        assert!(is_link_local_multicast(&"ff02::2".parse().unwrap()));
        assert!(!is_realm_local_multicast(&"fd00::3".parse().unwrap()));
    }

    #[test]
    fn prefix_matching() {
        let a: Ipv6Addr = "2001:db8::1".parse().unwrap();
        assert_eq!(prefix_match_len(&a, &a), 128);
        assert_eq!(prefix_match_len(&a, &"2001:db8::3".parse().unwrap()), 126);
        assert_eq!(prefix_match_len(&a, &"2001:db9::1".parse().unwrap()), 31);
        assert_eq!(prefix_match_len(&a, &"a001:db8::1".parse().unwrap()), 0);
        assert!(matches_prefix(&a, &"2001:db8:1::".parse().unwrap(), 32));
        assert!(!matches_prefix(&a, &"2001:db8:1::".parse().unwrap(), 48));
        assert!(matches_prefix(&a, &Ipv6Addr::UNSPECIFIED, 0));
    }

    #[test]
    fn thread_multicast_groups() {
        // Thread 1.4.1 section 5.2: ff32:40:<prefix>::1 and ff33:40:<prefix>::1
        let ll = link_local_all_thread_nodes(&MLP);
        let rl = realm_local_all_thread_nodes(&MLP);
        assert_eq!(
            ll,
            "ff32:40:fdde:ad00:beef:0:0:1".parse::<Ipv6Addr>().unwrap()
        );
        assert_eq!(
            rl,
            "ff33:40:fdde:ad00:beef:0:0:1".parse::<Ipv6Addr>().unwrap()
        );
    }

    #[test]
    fn locators() {
        let rloc = MLP.rloc(Rloc16(0x0400));
        let aloc = MLP.aloc(0xfc00).unwrap();
        assert!(is_routing_locator(&rloc, &MLP));
        assert!(!is_routing_locator(&aloc, &MLP));
        assert!(is_anycast_locator(&aloc, &MLP));
        assert!(is_mesh_local(&rloc, &MLP));
        assert!(!is_routing_locator(
            &"fd00::ff:fe00:400".parse().unwrap(),
            &MLP
        ));
    }

    #[test]
    fn reserved_iids() {
        assert!(iid_is_reserved(&Iid([0; 8])));
        assert!(iid_is_reserved(&Iid([
            0xfd, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x80
        ])));
        assert!(iid_is_reserved(&Iid([
            0xfd, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
        ])));
        assert!(!iid_is_reserved(&Iid([
            0xfd, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f
        ])));
        assert!(iid_is_reserved(&Iid::from_locator(0xfc10)));
        assert!(!iid_is_reserved(&Iid::from_locator(0x0400)));
        assert!(!iid_is_reserved(&Iid([1, 2, 3, 4, 5, 6, 7, 8])));
    }
}
