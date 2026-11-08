//! Mesh forwarding scenarios on a line of routers 0 (leader) - 1 - 2 - 3
//! with a minimal end device (4) attached to router 3: routing over
//! several hops with the mesh header, address resolution and held
//! datagrams, loops, hop limit, security and ICMPv6 destination unreachable.

use core::net::Ipv6Addr;

use opentrust_core::time::Duration;
use opentrust_core::types::{Prefix64, Rloc16, ipv6};
use opentrust_lowpan::forward::{LowpanFrame, parse_frame};
use opentrust_lowpan::frag::Fragmenter;
use opentrust_lowpan::ip6::{Ipv6Header, UdpHeader};
use opentrust_lowpan::iphc::NoContexts;
use opentrust_lowpan::mesh::MeshHeader;
use opentrust_mac::frame::Address;
use opentrust_mle::Role;
use opentrust_mle::test_support::MLP;
use opentrust_mle::tlv::DeviceMode;
use opentrust_net::resolver::{EntryState, ResolverEvent};

use crate::forwarder::{DropReason, MacDest, Route, SendResult};
use crate::sim::MeshSim;

fn secs(s: u64) -> Duration {
    Duration::from_secs(s)
}

fn line_with_child() -> MeshSim {
    let ftd = DeviceMode::new(true, true, true);
    let med = DeviceMode::new(true, false, true);
    let mut m = MeshSim::with_modes(&[ftd, ftd, ftd, ftd, med]);
    for (a, b) in [(0, 1), (1, 2), (2, 3), (3, 4)] {
        m.connect(a, b, -60);
    }
    m.start(0);
    assert!(m.run_until(secs(60), |s| s.sim.role(0) == Role::Leader));
    for i in 1..4 {
        m.start(i);
        assert!(m.run_until(secs(60), |s| s.sim.role(i) == Role::Child));
        assert!(m.run_until(secs(300), |s| s.sim.role(i) == Role::Router));
    }
    // Routes converge over the advertisements.
    let r3 = m.sim.nodes[3].mle.rloc16();
    let r0 = m.sim.nodes[0].mle.rloc16();
    assert!(m.run_until(secs(600), |s| {
        s.sim.nodes[0].mle.next_hop_and_path_cost(r3).0.is_some()
            && s.sim.nodes[3].mle.next_hop_and_path_cost(r0).0.is_some()
    }));
    m.start(4);
    assert!(m.run_until(secs(60), |s| s.sim.role(4) == Role::Child));
    m
}

fn rloc(m: &MeshSim, i: usize) -> Ipv6Addr {
    m.rloc(i)
}

/// Mesh header of a logged frame, if it has one.
fn mesh_of(f: &[u8]) -> Option<MeshHeader> {
    match parse_frame(f) {
        Ok(LowpanFrame::Mesh { header, .. }) => Some(header),
        _ => None,
    }
}

fn udp_payload(d: &[u8]) -> &[u8] {
    &d[48..]
}

#[test]
fn datagram_to_an_rloc_travels_three_hops_with_a_mesh_header() {
    let mut m = line_with_child();
    let dst = rloc(&m, 3);
    assert_eq!(m.send_udp(0, dst, b"hello"), SendResult::Sent);
    // Delivered once, intact, to the destination router.
    assert_eq!(m.tmf[3].delivered.len(), 1);
    assert_eq!(udp_payload(&m.tmf[3].delivered[0]), b"hello");
    // Three frames: 0->1, 1->2, 2->3, each with a mesh header (source
    // router 0, destination router 3) and one hop less left.
    let frames: std::vec::Vec<_> = m
        .frame_log
        .iter()
        .filter(|(_, _, f)| mesh_of(f).is_some())
        .collect();
    assert_eq!(frames.len(), 3);
    let (r0, r3) = (m.sim.nodes[0].mle.rloc16(), m.sim.nodes[3].mle.rloc16());
    for (k, (from, to, f)) in frames.iter().enumerate() {
        assert_eq!((*from, *to), (k, k + 1));
        let h = mesh_of(f).unwrap();
        assert_eq!((h.source, h.destination), (r0.0, r3.0));
        assert_eq!(h.hops_left, 19 - k as u8);
    }
    assert_eq!(m.tmf[1].forwarded, 1);
    assert_eq!(m.tmf[2].forwarded, 1);
    assert_eq!(m.tmf[0].forwarded, 0);
}

#[test]
fn neighbor_gets_the_datagram_without_mesh_header() {
    let mut m = line_with_child();
    let dst = rloc(&m, 1);
    m.frame_log.clear();
    assert_eq!(m.send_udp(0, dst, b"x"), SendResult::Sent);
    assert_eq!(m.frame_log.len(), 1);
    assert!(mesh_of(&m.frame_log[0].2).is_none());
    assert_eq!(m.tmf[1].delivered.len(), 1);
}

#[test]
fn large_datagram_is_fragmented_and_reassembled_at_the_destination() {
    let mut m = line_with_child();
    let dst = rloc(&m, 3);
    let payload = [0x5a; 200];
    assert_eq!(m.send_udp(0, dst, &payload), SendResult::Sent);
    let n = m.frame_log.iter().filter(|(f, _, _)| *f == 0).count();
    assert!(n >= 3, "{n} frames");
    // The intermediate routers forward fragment by fragment.
    assert_eq!(m.tmf[1].forwarded as usize, n);
    assert_eq!(m.tmf[3].delivered.len(), 1);
    assert_eq!(udp_payload(&m.tmf[3].delivered[0]), &payload[..]);
}

#[test]
fn eid_is_resolved_with_a_query_and_the_held_datagram_follows() {
    let mut m = line_with_child();
    let dst = m.ml_eid(3);
    assert_eq!(m.send_udp(0, dst, b"query me"), SendResult::Held);
    // Held while the query is out; then resolved and sent.
    assert!(m.run_until(secs(10), |s| s.tmf[3].delivered.len() == 1));
    assert_eq!(udp_payload(&m.tmf[3].delivered[0]), b"query me");
    assert_eq!(m.tmf[0].fwd.held_count(), 0);
    assert_eq!(
        m.tmf[0].resolver.info(&dst).unwrap().rloc16,
        m.sim.nodes[3].mle.rloc16()
    );
    // The second datagram needs no query.
    let queries = m.tmf[3].rx[&opentrust_coap::uri::Uri::AddressQuery.id()];
    assert_eq!(m.send_udp(0, dst, b"again"), SendResult::Sent);
    assert_eq!(m.tmf[3].delivered.len(), 2);
    assert_eq!(
        m.tmf[3].rx[&opentrust_coap::uri::Uri::AddressQuery.id()],
        queries
    );
}

#[test]
fn eid_of_a_child_behind_another_router_is_delivered_through_its_parent() {
    let mut m = line_with_child();
    let child_eid = m.ml_eid(4);
    assert_eq!(m.send_udp(0, child_eid, b"to the child"), SendResult::Held);
    assert!(m.run_until(secs(10), |s| s.tmf[4].delivered.len() == 1));
    assert_eq!(udp_payload(&m.tmf[4].delivered[0]), b"to the child");
    // Three mesh hops to the parent router 3, then a plain frame to the
    // child.
    let r3 = m.sim.nodes[3].mle.rloc16();
    assert_eq!(m.tmf[0].resolver.info(&child_eid).unwrap().rloc16, r3);
    let last = m
        .frame_log
        .iter()
        .rfind(|(f, t, _)| *f == 3 && *t == 4)
        .unwrap();
    assert!(mesh_of(&last.2).is_none());
}

#[test]
fn unknown_eid_fails_to_resolve_and_the_datagram_is_dropped() {
    let mut m = line_with_child();
    let unknown: Ipv6Addr = MLP.with_iid(&opentrust_core::types::Iid([0xde; 8]));
    assert_eq!(m.send_udp(0, unknown, b"nobody"), SendResult::Held);
    assert_eq!(m.tmf[0].fwd.held_count(), 1);
    assert!(m.run_until(secs(20), |s| {
        s.tmf[0]
            .resolved
            .contains(&ResolverEvent::ResolutionFailed { eid: unknown })
    }));
    assert_eq!(m.tmf[0].fwd.held_count(), 0);
    // The datagram originated here: no ICMP error to ourselves.
    assert!(m.tmf[0].delivered.is_empty());
    assert_eq!(
        m.tmf[0].resolver.info(&unknown).unwrap().state,
        EntryState::QueryRetry
    );
}

fn udp_datagram(src: Ipv6Addr, dst: Ipv6Addr, payload: &[u8]) -> std::vec::Vec<u8> {
    let mut buf = std::vec![0u8; 48 + payload.len()];
    let mut h = Ipv6Header::new(17, 64, src, dst);
    h.payload_len = (UdpHeader::LEN + payload.len()) as u16;
    h.write(&mut buf).unwrap();
    UdpHeader {
        src_port: 1,
        dst_port: 2,
        length: h.payload_len,
        checksum: 0x1234,
    }
    .write(&mut buf[40..])
    .unwrap();
    buf[48..].copy_from_slice(payload);
    buf
}

/// A frame with mesh header from `src` towards `dest`, as a neighbor of
/// `src` would have sent it.
fn mesh_frame(src: Rloc16, dest: Rloc16, hops: u8, datagram: &[u8]) -> std::vec::Vec<u8> {
    let mut f = Fragmenter::new(
        &NoContexts,
        Address::Short(src.into()),
        Address::Short(dest.into()),
        datagram,
        1,
        Some(MeshHeader::new(src.0, dest.0, hops)),
        94,
    );
    let mut out = [0u8; 127];
    let n = f.next_frame(&mut out).unwrap().unwrap();
    out[..n].to_vec()
}

#[test]
fn forwarding_stops_when_no_hops_are_left_or_link_security_is_missing() {
    let mut m = line_with_child();
    let (r0, r3) = (m.sim.nodes[0].mle.rloc16(), m.sim.nodes[3].mle.rloc16());
    let d = udp_datagram(m.ml_eid(0), rloc(&m, 3), b"x");
    let f = mesh_frame(r0, r3, 0, &d);
    m.inject_frame(0, 1, MacDest::Short(m.sim.nodes[1].mle.rloc16()), &f, true);
    assert_eq!(m.tmf[1].dropped, [DropReason::HopsExhausted]);
    assert_eq!(m.tmf[2].forwarded, 0);

    let f = mesh_frame(r0, r3, 5, &d);
    m.inject_frame(0, 1, MacDest::Short(m.sim.nodes[1].mle.rloc16()), &f, false);
    assert_eq!(m.tmf[1].dropped[1], DropReason::Security);
    assert!(m.tmf[3].delivered.is_empty());

    // With security and hops it is forwarded and arrives.
    m.inject_frame(0, 1, MacDest::Short(m.sim.nodes[1].mle.rloc16()), &f, true);
    assert_eq!(m.tmf[3].delivered.len(), 1);
    assert_eq!(m.tmf[1].forwarded, 1);
}

#[test]
fn a_frame_that_would_go_back_is_a_routing_loop_and_invalidates_the_route() {
    let mut m = line_with_child();
    let (r0, r3) = (m.sim.nodes[0].mle.rloc16(), m.sim.nodes[3].mle.rloc16());
    let r2 = m.sim.nodes[2].mle.rloc16();
    assert_eq!(m.sim.nodes[1].mle.next_hop_and_path_cost(r3).0, Some(r2));
    // Router 2 hands router 1 a frame for router 3: 2 thinks 1 is the next
    // hop, 1 thinks 2 is.
    let d = udp_datagram(m.ml_eid(0), rloc(&m, 3), b"loop");
    let f = mesh_frame(r0, r3, 10, &d);
    m.inject_frame(2, 1, MacDest::Short(m.sim.nodes[1].mle.rloc16()), &f, true);
    assert_eq!(m.tmf[1].dropped, [DropReason::RoutingLoop]);
    assert_eq!(m.tmf[1].forwarded, 0);
    assert_eq!(m.sim.nodes[1].mle.next_hop_and_path_cost(r3).0, None);
}

#[test]
fn unreachable_destination_gets_an_icmp_error_from_the_forwarding_router() {
    let mut m = line_with_child();
    let r0 = m.sim.nodes[0].mle.rloc16();
    // Router ID 40 is not allocated: no route.
    let ghost = Rloc16::from_router_id(40).unwrap();
    let ghost_addr = MLP.rloc(ghost);
    // Locally originated: dropped.
    assert_eq!(
        m.send_udp(0, ghost_addr, b"nowhere"),
        SendResult::Dropped(DropReason::NoRoute)
    );
    // Forwarded by router 1: it answers with ICMPv6 destination unreachable
    // (no route) to the source, resolving the source's ML-EID first.
    let d = udp_datagram(m.ml_eid(0), ghost_addr, b"nowhere");
    let f = mesh_frame(r0, ghost, 10, &d);
    m.inject_frame(0, 1, MacDest::Short(m.sim.nodes[1].mle.rloc16()), &f, true);
    assert_eq!(m.tmf[1].dropped, [DropReason::NoRoute]);
    assert!(m.run_until(secs(10), |s| !s.tmf[0].delivered.is_empty()));
    let e = &m.tmf[0].delivered[0];
    let h = Ipv6Header::parse(e).unwrap();
    assert_eq!(h.next_header, 58);
    assert_eq!(h.dst, m.ml_eid(0));
    // ICMPv6 type 1 (destination unreachable), code 0 (no route).
    assert_eq!(e[40], 1);
    assert_eq!(e[41], 0);
    // The quoted datagram header is the offending one.
    assert_eq!(&e[48..48 + 40], &d[..40]);
}

#[test]
fn failed_resolution_of_a_foreign_datagram_is_answered_with_an_icmp_error() {
    let mut m = line_with_child();
    let unknown: Ipv6Addr = MLP.with_iid(&opentrust_core::types::Iid([0xde; 8]));
    // A datagram from node 0's EID arrives at router 1 (as if forwarded
    // from the Thread network) for an unknown on-link address.
    let d = udp_datagram(m.ml_eid(0), unknown, b"lost");
    assert_eq!(m.send_ip6(1, &d), SendResult::Held);
    assert!(m.run_until(secs(20), |s| !s.tmf[0].delivered.is_empty()));
    let e = &m.tmf[0].delivered[0];
    assert_eq!((e[40], e[41]), (1, 0));
    assert_eq!(m.tmf[1].fwd.held_count(), 0);
}

#[test]
fn forwarded_datagrams_teach_routers_the_eid_to_rloc_mapping() {
    let mut m = line_with_child();
    let prefix = Prefix64([0x20, 0x01, 0x0d, 0xb8, 0, 1, 0, 0]);
    m.nd.on_mesh = Some(prefix);
    let gua = prefix.with_iid(&opentrust_core::types::Iid([0, 0, 0, 0, 0, 0, 0, 0x22]));
    // The child sends from its global address to router 0, through its
    // parent 3 and routers 2 and 1. Only the destination learns the
    // mapping (OT snoops for datagrams addressed to itself or to its
    // minimal children, so that the reply finds the way back).
    let r3 = m.sim.nodes[3].mle.rloc16();
    let d = udp_datagram(gua, rloc(&m, 0), b"snoop");
    assert_eq!(m.send_ip6(4, &d), SendResult::Sent);
    assert_eq!(m.tmf[0].delivered.len(), 1);
    let e = m.tmf[0].resolver.info(&gua).expect("snooped");
    assert_eq!(e.state, EntryState::Snooped);
    assert_eq!(e.rloc16, r3);
    for i in [1, 2] {
        assert!(m.tmf[i].resolver.info(&gua).is_none());
    }
    let _ = ipv6::iid(&gua);
}

#[test]
fn route_rules_follow_ot() {
    use crate::forwarder::{MeshForwarder, NoNetworkData, Routing};
    use opentrust_net::resolver::AddressResolver;
    let m = line_with_child();
    let route = |i: usize, src: Ipv6Addr, dst: Ipv6Addr| {
        let n = &m.sim.nodes[i];
        let routing = Routing {
            mle: &n.mle,
            netif: &m.tmf[i].ip6.netif,
            contexts: &NoContexts,
            nd: &NoNetworkData,
            ext: n.env.ext,
        };
        let mut resolver = AddressResolver::<4>::new();
        MeshForwarder::<2, 2>::route(
            m.sim.now,
            &routing,
            &mut resolver,
            &src,
            &dst,
            true,
            &mut |_| {},
        )
    };
    let ll = |i: usize| ipv6::link_local(&m.sim.nodes[i].env.ext);
    let all_nodes: Ipv6Addr = "ff02::1".parse().unwrap();
    let r = |i: usize| m.sim.nodes[i].mle.rloc16();
    // Routers broadcast multicast and use the extended address of
    // link-local unicasts.
    assert_eq!(
        route(1, ll(1), all_nodes),
        Ok(Route::Direct {
            dst: MacDest::Broadcast
        })
    );
    assert_eq!(
        route(1, ll(1), ll(2)),
        Ok(Route::Direct {
            dst: MacDest::Extended(m.sim.nodes[2].env.ext)
        })
    );
    // A multicast source is never routed.
    assert_eq!(
        route(1, all_nodes, ll(2)),
        Err(crate::forwarder::RouteError::Drop)
    );
    // Neighbor: direct; far router: mesh header via the next hop.
    assert_eq!(
        route(1, m.ml_eid(1), rloc(&m, 2)),
        Ok(Route::Direct {
            dst: MacDest::Short(r(2))
        })
    );
    assert_eq!(
        route(1, m.ml_eid(1), rloc(&m, 3)),
        Ok(Route::Mesh {
            next_hop: r(2),
            mesh_dest: r(3)
        })
    );
    // An RLOC with an invalid router ID, an unknown router, an anycast
    // locator without Network Data, an external address without a route.
    assert!(route(1, m.ml_eid(1), MLP.rloc(Rloc16(63 << 10))).is_err());
    assert_eq!(
        route(
            1,
            m.ml_eid(1),
            MLP.rloc(Rloc16::from_router_id(40).unwrap())
        ),
        Err(crate::forwarder::RouteError::NoRoute)
    );
    assert_eq!(
        route(1, m.ml_eid(1), MLP.aloc(0xfc00).unwrap()),
        Err(crate::forwarder::RouteError::NoRoute)
    );
    assert_eq!(
        route(1, m.ml_eid(1), "2001:db8::1".parse().unwrap()),
        Err(crate::forwarder::RouteError::NoRoute)
    );
    // An unresolved on-link address asks the address cache.
    assert_eq!(
        route(1, m.ml_eid(1), m.ml_eid(3)),
        Err(crate::forwarder::RouteError::AddressQuery)
    );
    // The child of router 3 is reached directly by its parent, through the
    // registered ML-EID; the minimal end device itself sends everything to
    // its parent.
    assert_eq!(
        route(3, m.ml_eid(3), m.ml_eid(4)),
        Ok(Route::Direct {
            dst: MacDest::Short(r(4))
        })
    );
    assert_eq!(
        route(4, m.ml_eid(4), m.ml_eid(0)),
        Ok(Route::Direct {
            dst: MacDest::Short(r(3))
        })
    );
    // An end device unicasts multicast to its parent, too.
    assert_eq!(
        route(4, m.ml_eid(4), "ff03::1".parse().unwrap()),
        Ok(Route::Direct {
            dst: MacDest::Short(r(3))
        })
    );
}

#[test]
fn detached_devices_only_use_link_local_destinations() {
    use crate::forwarder::{MeshForwarder, NoNetworkData, Routing};
    use opentrust_net::resolver::AddressResolver;
    let m = MeshSim::new(2);
    let n = &m.sim.nodes[0];
    let routing = Routing {
        mle: &n.mle,
        netif: &m.tmf[0].ip6.netif,
        contexts: &NoContexts,
        nd: &NoNetworkData,
        ext: n.env.ext,
    };
    let mut resolver = AddressResolver::<4>::new();
    let ll = ipv6::link_local(&m.sim.nodes[1].env.ext);
    let mut route = |dst: &str| {
        MeshForwarder::<2, 2>::route(
            m.sim.now,
            &routing,
            &mut resolver,
            &ll,
            &dst.parse().unwrap(),
            true,
            &mut |_| {},
        )
    };
    assert_eq!(
        route("ff02::1"),
        Ok(Route::Direct {
            dst: MacDest::Broadcast
        })
    );
    assert!(matches!(
        route("fe80::1"),
        Ok(Route::Direct {
            dst: MacDest::Extended(_)
        })
    ));
    assert_eq!(route("fd00::1"), Err(crate::forwarder::RouteError::Drop));
    assert_eq!(route("ff03::1"), Err(crate::forwarder::RouteError::Drop));
}
