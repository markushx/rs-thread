//! Codec tests; the vectors are those of OT `tests/unit/test_network_data.cpp`
//! (`TestNetworkDataIterator`).

use std::vec::Vec;

use opentrust_core::bytes::Writer;

use super::tlv::*;
use super::*;

fn p64(b: [u8; 8]) -> NetPrefix {
    NetPrefix::new(&b, 64).unwrap()
}

fn route(prefix: NetPrefix, rloc16: u16, preference: i8, nat64: bool, stable: bool) -> RouteEntry {
    RouteEntry {
        prefix,
        rloc16,
        preference,
        nat64,
        adv_pio: false,
        stable,
    }
}

/// Invalid TLV type, invalid prefixes (length 129, short, empty), then a
/// valid Prefix TLV with two Has Route sub-TLVs.
const DATA1: &[u8] = &[
    0xff, 0x03, 0x01, 0x02, 0x03, 0x03, 0x1D, 0x00, 0x81, 0xFD, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
    0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x00, 0x03, 0xb8, 0x00, 0x40, 0x01,
    0x03, 0x14, 0x00, 0x00, 0x03, 0x01, 0x00, 0x03, 0x02, 0x00, 0x40, 0x03, 0x14, 0x00, 0x40, 0xFD,
    0x00, 0x12, 0x34, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0xC8, 0x00, 0x40, 0x01, 0x03, 0x54, 0x00,
    0x00,
];

const DATA2: &[u8] = &[
    0x08, 0x04, 0x0B, 0x02, 0x00, 0x00, 0x03, 0x1E, 0x00, 0x40, 0xFD, 0x00, 0x12, 0x34, 0x56, 0x78,
    0x00, 0x00, 0x07, 0x02, 0x11, 0x40, 0x00, 0x03, 0x10, 0x00, 0x40, 0x01, 0x03, 0x54, 0x00, 0x00,
    0x05, 0x04, 0x54, 0x00, 0x31, 0x00, 0x02, 0x0F, 0x00, 0x40, 0xFD, 0x00, 0xAB, 0xBA, 0xCD, 0xDC,
    0x00, 0x00, 0x00, 0x03, 0x10, 0x00, 0x20, 0x03, 0x0E, 0x00, 0x20, 0xFD, 0x00, 0xAB, 0xBA, 0x01,
    0x06, 0x54, 0x00, 0x00, 0x04, 0x01, 0x00,
];

const DATA3: &[u8] = &[
    0x08, 0x04, 0x0b, 0x02, 0x36, 0xcc, 0x03, 0x1c, 0x00, 0x40, 0xfd, 0x00, 0xbe, 0xef, 0xca, 0xfe,
    0x00, 0x00, 0x05, 0x0c, 0x28, 0x00, 0x33, 0x00, 0x28, 0x01, 0x33, 0x00, 0x4c, 0x00, 0x31, 0x00,
    0x07, 0x02, 0x11, 0x40, 0x03, 0x14, 0x00, 0x40, 0xfd, 0x00, 0x22, 0x22, 0x00, 0x00, 0x00, 0x00,
    0x05, 0x04, 0x28, 0x00, 0x73, 0x00, 0x07, 0x02, 0x12, 0x40, 0x03, 0x12, 0x00, 0x40, 0xfd, 0x00,
    0x33, 0x33, 0x00, 0x00, 0x00, 0x00, 0x01, 0x06, 0xec, 0x00, 0x00, 0x28, 0x01, 0xc0,
];

#[test]
fn iterator_vector_1() {
    let nd = NetworkData::<256>::from_slice(DATA1).unwrap();
    assert!(!nd.is_empty());
    let v = NetworkDataView(DATA1);
    let p = p64([0xfd, 0, 0x12, 0x34, 0, 0, 0, 0]);
    let routes: Vec<_> = v.external_routes().collect();
    assert_eq!(
        routes,
        [
            route(p, 0xc800, 1, false, false),
            route(p, 0x5400, 0, false, true)
        ]
    );
    assert!(v.contains_rloc16(0xc800));
    assert!(v.contains_rloc16(0x5400));
    assert!(!v.contains_rloc16(0xc700));
    assert!(!v.contains_rloc16(0x5401));
}

#[test]
fn iterator_vector_2() {
    let v = NetworkDataView(DATA2);
    let a = p64([0xfd, 0, 0x12, 0x34, 0x56, 0x78, 0, 0]);
    let b = p64([0xfd, 0, 0xab, 0xba, 0xcd, 0xdc, 0, 0]);
    let c = NetPrefix::new(&[0xfd, 0, 0xab, 0xba], 32).unwrap();
    let routes: Vec<_> = v.external_routes().collect();
    assert_eq!(
        routes,
        [
            route(a, 0x1000, 1, false, false),
            route(a, 0x5400, 0, false, true),
            route(b, 0x1000, 0, true, false),
            route(c, 0x5400, 0, false, true),
            route(c, 0x0401, 0, false, true),
        ]
    );
    // The Commissioning Data TLV is skipped by the typed iterators.
    assert_eq!(v.commissioning_data(), Some(&[0x0b, 0x02, 0x00, 0x00][..]));
    assert!(v.contains_rloc16(0x0401));
    assert!(!v.contains_rloc16(0x6000));
    // Context ID 1 belongs to fd00:1234:5678::/64 and allows compression.
    let ctx: Vec<_> = v.contexts().collect();
    assert_eq!(ctx.len(), 1);
    assert_eq!((ctx[0].id, ctx[0].compress, ctx[0].prefix), (1, true, a));
}

#[test]
fn iterator_vector_3() {
    let v = NetworkDataView(DATA3);
    let beef = p64([0xfd, 0, 0xbe, 0xef, 0xca, 0xfe, 0, 0]);
    let p3333 = p64([0xfd, 0, 0x33, 0x33, 0, 0, 0, 0]);
    let routes: Vec<_> = v.external_routes().collect();
    assert_eq!(
        routes,
        [
            route(p3333, 0xec00, 0, false, true),
            route(p3333, 0x2801, -1, false, true)
        ]
    );
    let prefixes: Vec<_> = v.on_mesh_prefixes().collect();
    assert_eq!(prefixes.len(), 4);
    let p = prefixes[0];
    assert_eq!((p.prefix, p.rloc16, p.stable), (beef, 0x2800, true));
    assert_eq!(p.flags.preference(), 0);
    assert!(p.flags.has(BrFlags::PREFERRED));
    assert!(p.flags.has(BrFlags::SLAAC));
    assert!(p.flags.has(BrFlags::DEFAULT_ROUTE));
    assert!(p.flags.has(BrFlags::ON_MESH));
    assert!(!p.flags.has(BrFlags::DHCP));
    assert_eq!(prefixes[2].rloc16, 0x4c00);
    assert!(!prefixes[2].flags.has(BrFlags::DEFAULT_ROUTE));
    assert!(v.is_on_mesh(&"fd00:beef:cafe::1".parse().unwrap()));
    assert!(!v.is_on_mesh(&"fd00:3333::1".parse().unwrap()));
    // Two contexts; lookup by address and by ID.
    assert_eq!(v.contexts().count(), 2);
    let addr = "fd00:beef:cafe:0:1:2:3:4".parse().unwrap();
    assert_eq!(v.context_for_address(&addr).unwrap().id, 1);
    assert_eq!(
        v.context_by_id(2).unwrap().prefix,
        p64([0xfd, 0, 0x22, 0x22, 0, 0, 0, 0])
    );
    assert!(v.context_by_id(3).is_none());
}

#[test]
fn stable_copy_replaces_rlocs_and_drops_temporary_data() {
    let nd = NetworkData::<256>::from_slice(DATA3).unwrap();
    let mut out = [0u8; 256];
    let n = nd.copy_stable(&mut out).unwrap();
    let stable = NetworkDataView(&out[..n]);
    assert_eq!(stable.commissioning_data(), None);
    assert_eq!(stable.contexts().count(), 2);
    // BR / HR entries lost their RLOC16.
    assert!(stable.on_mesh_prefixes().all(|e| e.rloc16 == 0xfffe));
    assert_eq!(stable.external_routes().count(), 2);
    assert!(stable.external_routes().all(|e| e.rloc16 == 0xfffe));
    // Flags and preference survive.
    let r: Vec<_> = stable.external_routes().map(|r| r.preference).collect();
    assert_eq!(r, [0, -1]);
    // Idempotent.
    let mut out2 = [0u8; 256];
    let n2 = stable.copy_stable(&mut out2).unwrap();
    assert_eq!(out[..n], out2[..n2]);
}

#[test]
fn stable_copy_drops_prefix_without_stable_sub_tlvs() {
    // Prefix fd00:1234::/64 (stable) with only a temporary Has Route.
    let mut buf = [0u8; 64];
    let mut w = Writer::new(&mut buf);
    let p = p64([0xfd, 0, 0x12, 0x34, 0, 0, 0, 0]);
    write_prefix(&mut w, false, 0, &p, |w| {
        write_has_route(
            w,
            false,
            &[HasRouteEntry {
                rloc16: 0x0400,
                preference: 0,
                nat64: false,
                adv_pio: false,
            }],
        )
    })
    .unwrap();
    let n = w.len();
    let mut out = [0u8; 64];
    assert_eq!(NetworkDataView(&buf[..n]).copy_stable(&mut out).unwrap(), 0);
}

#[test]
fn writers_reproduce_the_vector() {
    let mut buf = [0u8; 64];
    let mut w = Writer::new(&mut buf);
    let p = p64([0xfd, 0, 0x33, 0x33, 0, 0, 0, 0]);
    write_prefix(&mut w, true, 0, &p, |w| {
        write_has_route(
            w,
            true,
            &[
                HasRouteEntry {
                    rloc16: 0xec00,
                    preference: 0,
                    nat64: false,
                    adv_pio: false,
                },
                HasRouteEntry {
                    rloc16: 0x2801,
                    preference: -1,
                    nat64: false,
                    adv_pio: false,
                },
            ],
        )
    })
    .unwrap();
    assert_eq!(w.written(), &DATA3[DATA3.len() - 20..]);
}

#[test]
fn service_round_trip() {
    let mut buf = [0u8; 64];
    let mut w = Writer::new(&mut buf);
    write_service(&mut w, true, 5, THREAD_ENTERPRISE_NUMBER, &[0x5d, 1], |w| {
        write_server(w, true, 0x0800, &[9, 9])
    })
    .unwrap();
    write_service(&mut w, false, 6, 1234, &[7], |w| {
        write_server(w, false, 0x0c00, &[])
    })
    .unwrap();
    let n = w.len();
    let nd = NetworkData::<64>::from_slice(&buf[..n]).unwrap();
    let s: Vec<_> = nd.view().services().collect();
    assert_eq!(s.len(), 2);
    assert_eq!(
        (
            s[0].service_id,
            s[0].enterprise_number,
            s[0].service_data,
            s[0].rloc16,
            s[0].server_data,
            s[0].stable
        ),
        (
            5,
            THREAD_ENTERPRISE_NUMBER,
            &[0x5d, 1][..],
            0x0800,
            &[9, 9][..],
            true
        )
    );
    assert_eq!(s[0].aloc16(), 0xfc15);
    assert_eq!(
        (s[1].enterprise_number, s[1].stable, s[1].aloc16()),
        (1234, false, 0xfc16)
    );
    // Stable copy keeps only the first service, with its ALOC as server.
    let mut out = [0u8; 64];
    let m = nd.copy_stable(&mut out).unwrap();
    let st: Vec<_> = NetworkDataView(&out[..m]).services().collect();
    assert_eq!(st.len(), 1);
    assert_eq!(st[0].rloc16, 0xfc15);
}

#[test]
fn prefix_matching() {
    let p = NetPrefix::new(&[0xfd, 0xf0], 12).unwrap();
    assert_eq!(p.as_bytes(), &[0xfd, 0xf0]);
    assert!(p.contains(&"fdff::1".parse().unwrap()));
    assert!(!p.contains(&"fd0f::1".parse().unwrap()));
    assert!(NetPrefix::new(&[0], 129).is_err());
    assert!(NetPrefix::new(&[0], 16).is_err());
    let default = NetPrefix::new(&[], 0).unwrap();
    assert!(default.contains(&"2001:db8::1".parse().unwrap()));
    assert!(default.contains_prefix(&p));
}

#[test]
fn rejects_malformed() {
    assert!(NetworkData::<8>::from_slice(&[0x02, 0x05, 1]).is_err());
    assert!(NetworkData::<4>::from_slice(&[0x02, 0x04, 1, 2, 3, 4]).is_err());
}

/// OpenThread `tests/unit/test_serial_number.cpp` `TestPreference`
/// (2-bit route preference encoding).
#[test]
fn test_preference() {
    assert_eq!(preference_to_bits(1), 0x1);
    assert_eq!(preference_to_bits(0), 0x0);
    assert_eq!(preference_to_bits(-1), 0x3);
    assert_eq!(preference_to_bits(2), 0x1);
    assert_eq!(preference_to_bits(-2), 0x3);
    assert_eq!(preference_to_bits(127), 0x1);
    assert_eq!(preference_to_bits(-128), 0x3);
    for hi in [0u8, 4, 0xfc] {
        assert_eq!(preference_from_bits(0x1 | hi), 1);
        assert_eq!(preference_from_bits(hi), 0);
        assert_eq!(preference_from_bits(0x3 | hi), -1);
        // The reserved value reads as medium.
        assert_eq!(preference_from_bits(0x2 | hi), 0);
    }
}

/// OpenThread `tests/unit/test_ip_address.cpp` `TestIp6Prefix` (the
/// matching and containment part; OT's ordering and `IsLinkLocal()` style
/// helpers have no counterpart).
#[test]
fn test_ip6_prefix() {
    use core::net::Ipv6Addr;
    let prefixes: [[u8; 16]; 3] = [
        [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
            0xcd, 0xef,
        ],
        [
            0xaa, 0x55, 0xaa, 0x55, 0xaa, 0x55, 0xaa, 0x55, 0xaa, 0x55, 0xaa, 0x55, 0xaa, 0x55,
            0xaa, 0x55,
        ],
        [0xff; 16],
    ];
    for bytes in prefixes {
        let a1 = Ipv6Addr::from(bytes);
        let mut b2 = bytes;
        b2[0] ^= 0x80;
        let a2 = Ipv6Addr::from(b2);
        for len in 1..=128u8 {
            let p = NetPrefix::from_addr(&a1, len).unwrap();
            assert_eq!(p.len(), len);
            assert!(p.contains(&a1));
            assert!(!p.contains(&a2));
            for sub_len in 1..=len {
                let sub = NetPrefix::from_addr(&a1, sub_len).unwrap();
                // OT `prefix.ContainsPrefix(sub)` is `sub.contains_prefix(&prefix)`
                // here (the receiver is the shorter prefix).
                assert!(sub.contains_prefix(&p));
                assert_eq!(p == sub, sub_len == len);
                if sub_len < len {
                    assert!(!p.contains_prefix(&sub));
                }
            }
            for bit in 0..len {
                let mut b = bytes;
                b[usize::from(bit / 8)] ^= 0x80 >> (bit & 7);
                let p2 = NetPrefix::from_addr(&Ipv6Addr::from(b), len).unwrap();
                assert_ne!(p, p2);
            }
        }
    }
}
