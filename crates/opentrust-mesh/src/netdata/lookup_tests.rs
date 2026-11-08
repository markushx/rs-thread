//! Route lookup, anycast lookup and consumer adapter tests.

use std::vec::Vec;

use core::net::Ipv6Addr;
use opentrust_core::Error;
use opentrust_core::bytes::Writer;
use opentrust_core::time::Instant;
use opentrust_core::types::{Iid, Prefix64};
use opentrust_lowpan::iphc::ContextProvider;
use opentrust_net::netif::Netif;

use super::aloc::*;
use super::consumers::*;
use super::leader::Leader;
use super::local::*;
use super::lookup::*;
use super::tlv::*;
use super::view::NetworkDataView;

struct Mesh {
    own: u16,
    costs: Vec<(u16, u8)>,
}

impl MeshInfo for Mesh {
    fn path_cost(&self, r: u16) -> u8 {
        self.costs
            .iter()
            .find(|(x, _)| *x == r)
            .map_or(16, |(_, c)| *c)
    }
    fn leader_rloc16(&self) -> u16 {
        0x0000
    }
    fn has_rloc16(&self, r: u16) -> bool {
        r == self.own
    }
}

fn mesh() -> Mesh {
    Mesh {
        own: 0x2000,
        costs: std::vec![(0x0000, 2), (0x0400, 1), (0x0800, 3), (0x0c00, 1)],
    }
}

fn a(s: &str) -> Ipv6Addr {
    s.parse().unwrap()
}

fn pfx(s: &str, len: u8) -> NetPrefix {
    NetPrefix::from_addr(&a(s), len).unwrap()
}

fn hr(rloc16: u16, preference: i8) -> HasRouteEntry {
    HasRouteEntry {
        rloc16,
        preference,
        nat64: false,
        adv_pio: false,
    }
}

/// On-mesh prefix `fd00:1::/64` from 0x0400 (stable, context 1), external
/// routes `2001:db8::/32` from 0x0400 (pref 0) and 0x0800 (pref 1),
/// `2001:db8:1::/48` from 0x0c00 (pref -1), all in domain 0.
fn data() -> Vec<u8> {
    let mut b = [0u8; 256];
    let mut w = Writer::new(&mut b);
    write_prefix(&mut w, true, 0, &pfx("fd00:1::", 64), |w| {
        write_border_router(
            w,
            true,
            &[BorderRouterEntry {
                rloc16: 0x0400,
                flags: BrFlags::default()
                    .with(BrFlags::ON_MESH, true)
                    .with(BrFlags::SLAAC, true)
                    .with(BrFlags::PREFERRED, true),
            }],
        )?;
        write_context(w, true, 1, true, 64)
    })
    .unwrap();
    write_prefix(&mut w, true, 0, &pfx("2001:db8::", 32), |w| {
        write_has_route(w, true, &[hr(0x0400, 0), hr(0x0800, 1)])
    })
    .unwrap();
    write_prefix(&mut w, true, 0, &pfx("2001:db8:1::", 48), |w| {
        write_has_route(w, true, &[hr(0x0c00, -1)])
    })
    .unwrap();
    let n = w.len();
    b[..n].to_vec()
}

fn br(rloc16: u16, flags: BrFlags) -> BorderRouterEntry {
    BorderRouterEntry { rloc16, flags }
}

#[test]
fn external_routes_prefer_longest_prefix_then_preference_then_cost() {
    let d = data();
    let v = NetworkDataView(&d);
    let m = mesh();
    let src = a("fd00:1::1234");
    // Longest prefix wins, even with a worse preference.
    assert_eq!(
        route_lookup(&v, &m, &src, &a("2001:db8:1::5")),
        Some(0x0c00)
    );
    // Same prefix: the higher preference.
    assert_eq!(
        route_lookup(&v, &m, &src, &a("2001:db8:2::5")),
        Some(0x0800)
    );
    // Equal preference: the cheaper path.
    let mut b = [0u8; 128];
    let mut w = Writer::new(&mut b);
    write_prefix(&mut w, true, 0, &pfx("fd00:1::", 64), |w| {
        write_border_router(
            w,
            true,
            &[br(0x0400, BrFlags::default().with(BrFlags::ON_MESH, true))],
        )
    })
    .unwrap();
    write_prefix(&mut w, true, 0, &pfx("2001:db8::", 32), |w| {
        write_has_route(w, true, &[hr(0x0800, 0), hr(0x0c00, 0)])
    })
    .unwrap();
    let n = w.len();
    let v2 = NetworkDataView(&b[..n]);
    assert_eq!(route_lookup(&v2, &m, &src, &a("2001:db8::9")), Some(0x0c00));
    // No route for other destinations, nor for a source outside any
    // on-mesh prefix.
    assert_eq!(route_lookup(&v, &m, &src, &a("2002::1")), None);
    assert_eq!(
        route_lookup(&v, &m, &a("2001:db8::1"), &a("2001:db8::2")),
        None
    );
}

#[test]
fn default_route_border_router() {
    let mut b = [0u8; 128];
    let mut w = Writer::new(&mut b);
    let f = BrFlags::default()
        .with(BrFlags::ON_MESH, true)
        .with(BrFlags::DEFAULT_ROUTE, true);
    write_prefix(&mut w, true, 0, &pfx("fd00:2::", 64), |w| {
        write_border_router(w, true, &[br(0x0800, f)])?;
        write_border_router(w, false, &[br(0x0400, f)])
    })
    .unwrap();
    let n = w.len();
    let v = NetworkDataView(&b[..n]);
    // 0x0400 is closer (cost 1 vs 3) at equal preference.
    assert_eq!(
        route_lookup(&v, &mesh(), &a("fd00:2::7"), &a("2001::1")),
        Some(0x0400)
    );
    assert!(v.is_on_mesh(&a("fd00:2::9")));
    assert_eq!(
        on_mesh_prefix_of(&v, &a("fd00:2::9")),
        Some(pfx("fd00:2::", 64))
    );
}

fn leader_with_service(servers: &[u16]) -> Leader<256> {
    let mut l = LocalData::<1, 1, 2>::new();
    l.add_service(ServiceConfig::new(THREAD_ENTERPRISE_NUMBER, &[1], &[], true).unwrap())
        .unwrap();
    let mut leader = Leader::<256>::new();
    for r in servers {
        let mut p = [0u8; 64];
        let k = l.encode(*r, &mut p).unwrap();
        leader
            .register(*r, &p[..k], |_| true, Instant::from_secs(1))
            .unwrap();
    }
    leader
}

#[test]
fn anycast_lookup_cases() {
    let m = mesh();
    // Service 0 with servers 0x0800 (router, cost 3) and 0x0c01 (child of
    // 0x0c00, cost 16 for the child RLOC16): the cheaper router wins.
    let leader = leader_with_service(&[0x0800, 0x0c01]);
    let v = leader.data().view();
    assert_eq!(anycast_lookup(&v, &m, 0xfc10), Ok(0x0800));
    assert_eq!(anycast_lookup(&v, &m, 0xfc11), Err(Error::NotFound));
    assert_eq!(anycast_lookup(&v, &m, 0xfc00), Ok(0x0000));
    assert_eq!(anycast_lookup(&v, &m, 0xfc50), Err(Error::Drop));
    // A lone child server resolves to its parent.
    let one = leader_with_service(&[0x0c01]);
    assert_eq!(anycast_lookup(&one.data().view(), &m, 0xfc10), Ok(0x0c00));
}

#[test]
fn commissioner_aloc_uses_border_agent_locator() {
    let mut b = [0u8; 32];
    // Commissioning Data TLV: Border Agent Locator (9), Commissioner
    // Session ID (11).
    let mut w = Writer::new(&mut b);
    write_tlv(
        &mut w,
        ty::COMMISSIONING,
        false,
        &[9, 2, 0x04, 0x00, 11, 2, 0x12, 0x34],
    )
    .unwrap();
    let n = w.len();
    let v = NetworkDataView(&b[..n]);
    assert_eq!(border_agent_locator(&v), Some(0x0400));
    assert_eq!(
        anycast_lookup(&v, &mesh(), commissioner_aloc16(0x1234)),
        Ok(0x0400)
    );
    assert_eq!(commissioner_aloc16(0x1234), 0xfc34);
}

#[test]
fn slaac_prefixes_and_contexts() {
    let d = data();
    let v = NetworkDataView(&d);
    let p = slaac_prefixes::<4>(&v);
    assert_eq!(p.len(), 1);
    assert!(p[0].is_slaac() && p[0].on_mesh && p[0].preferred);
    assert_eq!(p[0].prefix, Prefix64([0xfd, 0, 0, 1, 0, 0, 0, 0]));
    let mlp = Prefix64([0xfd, 0xaa, 0, 0, 0, 0, 0, 1]);
    let c = NetDataContexts {
        view: v,
        mesh_local_prefix: mlp,
    };
    assert_eq!(c.by_id(0).unwrap().prefix[..8], mlp.0);
    assert_eq!(c.by_id(1).unwrap().prefix_len, 64);
    assert!(c.by_id(2).is_none());
    assert_eq!(c.for_address(&a("fd00:1::5")).unwrap().id, 1);
    assert!(c.for_address(&a("fd00:9::5")).is_none());
    assert_eq!(c.for_address(&mlp.with_iid(&Iid([1; 8]))).unwrap().id, 0);
    assert_eq!(
        context_prefix64(&v, 1),
        Some(Prefix64([0xfd, 0, 0, 1, 0, 0, 0, 0]))
    );
    assert_eq!(context_prefix64(&v, 0), None);
    assert_eq!(context_id_for(&v, &a("fd00:1::77")), Some(1));
    assert_eq!(context_id_for(&v, &a("fd00:9::77")), None);
}

#[test]
fn alocs_follow_services_and_leader() {
    let mlp = Prefix64([0xfd, 0xaa, 0, 0, 0, 0, 0, 1]);
    let mut netif: Netif<8, 4> = Netif::new();
    netif.set_mesh_local_prefix(mlp).unwrap();
    let leader = leader_with_service(&[0x0800]);
    let mut set = AlocSet::new();
    let want = desired_alocs(true, &leader.data().view(), Some(0x0800), None);
    assert_eq!(&want[..], &[0xfc00, 0xfc10]);
    set.update(&mut netif, &want).unwrap();
    assert!(netif.has_unicast(&mlp.aloc(0xfc00).unwrap()));
    assert!(netif.has_unicast(&mlp.aloc(0xfc10).unwrap()));
    // Stops being the leader, gets a commissioner ALOC.
    let want = desired_alocs(false, &leader.data().view(), Some(0x0800), Some(0xfc33));
    set.update(&mut netif, &want).unwrap();
    assert!(!netif.has_unicast(&mlp.aloc(0xfc00).unwrap()));
    assert!(netif.has_unicast(&mlp.aloc(0xfc33).unwrap()));
    // Another router's service does not count; no RLOC16 means no ALOCs.
    assert_eq!(
        desired_alocs(true, &leader.data().view(), Some(0x0400), None).len(),
        1
    );
    set.update(
        &mut netif,
        &desired_alocs(true, &leader.data().view(), None, None),
    )
    .unwrap();
    assert!(set.active().is_empty());
    assert!(!netif.has_unicast(&mlp.aloc(0xfc10).unwrap()));
}
