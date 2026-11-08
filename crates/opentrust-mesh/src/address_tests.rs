//! Address resolution over TMF: codecs and multi-node scenarios (a router
//! asking for the address of a sleepy child behind another router).

use core::net::Ipv6Addr;

use opentrust_coap::message::{Code, Type};
use opentrust_coap::uri::Uri;
use opentrust_core::time::Duration;
use opentrust_core::types::{Iid, Rloc16, ipv6};
use opentrust_mle::Role;
use opentrust_mle::neighbor::StateFilter;
use opentrust_mle::test_support::MLP;
use opentrust_mle::tlv::DeviceMode;
use opentrust_net::netif::UnicastAddress;
use opentrust_net::resolver::{EntryState, Resolution, ResolverEvent};

use crate::address::*;
use crate::sim::MeshSim;

fn secs(s: u64) -> Duration {
    Duration::from_secs(s)
}

const GUA: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 1, 0, 0, 0, 0, 0x22);

#[test]
fn codecs() {
    let target: Ipv6Addr = "fd00:1::1234".parse().unwrap();
    let mut buf = [0u8; 64];
    let n = build_address_query(&target, &mut buf).unwrap();
    assert_eq!(n, 18);
    assert_eq!(&buf[..2], &[0, 16]);
    assert_eq!(parse_address_query(&buf[..n]).unwrap(), target);
    assert!(parse_address_query(&[0, 3, 1, 2, 3]).is_err());
    assert!(parse_address_query(&[]).is_err());

    let notify = AddressNotify {
        target,
        ml_eid_iid: Iid([1, 2, 3, 4, 5, 6, 7, 8]),
        rloc16: Rloc16(0x5c00),
        last_transaction_time: Some(77),
    };
    let n = build_address_notify(&notify, &mut buf).unwrap();
    // Target, ML-EID, RLOC16, Last Transaction Time in OT's order.
    assert_eq!(buf[0], 0);
    assert_eq!(buf[18], 3);
    assert_eq!(buf[28], 2);
    assert_eq!(buf[32], 6);
    assert_eq!(parse_address_notify(&buf[..n]).unwrap(), notify);
    let without = AddressNotify {
        last_transaction_time: None,
        ..notify
    };
    let n2 = build_address_notify(&without, &mut buf).unwrap();
    assert_eq!(n2, n - 6);
    assert_eq!(parse_address_notify(&buf[..n2]).unwrap(), without);
    // Missing TLVs / malformed Last Transaction Time.
    assert!(parse_address_notify(&buf[..28]).is_err());
    buf[n2] = 6;
    buf[n2 + 1] = 2;
    assert!(parse_address_notify(&buf[..n2 + 4]).is_err());

    let n = build_address_error(&target, &Iid([9; 8]), &mut buf).unwrap();
    assert_eq!(
        parse_address_error(&buf[..n]).unwrap(),
        (target, Iid([9; 8]))
    );
    assert!(parse_address_error(&buf[..18]).is_err());
}

/// Leader (0), router (1), MED child of router 1 with a GUA (2).
fn mesh_with_child() -> MeshSim {
    let ftd = DeviceMode::new(true, true, true);
    let med = DeviceMode::new(true, false, true);
    let mut m = MeshSim::with_modes(&[ftd, ftd, med]);
    m.connect(0, 1, -60);
    m.connect(1, 2, -60);
    m.sim.nodes[2].env.extra_addrs.push(GUA).unwrap();
    m.start(0);
    assert!(m.run_until(secs(60), |s| s.sim.role(0) == Role::Leader));
    m.start(1);
    assert!(m.run_until(secs(30), |s| s.sim.role(1) == Role::Child));
    assert!(m.run_until(secs(300), |s| s.sim.role(1) == Role::Router));
    // The routers see each other.
    assert!(m.run_until(secs(120), |s| {
        s.sim.nodes[0].mle.router_table().count(StateFilter::Valid) == 1
    }));
    m.start(2);
    assert!(m.run_until(secs(60), |s| s.sim.role(2) == Role::Child));
    assert!(m.run_until(secs(10), |s| {
        s.sim.nodes[1]
            .mle
            .children()
            .find_by_address(&MLP, &GUA, StateFilter::Valid)
            .is_some()
    }));
    m
}

fn resolved(m: &MeshSim, node: usize, eid: &Ipv6Addr) -> bool {
    m.tmf[node]
        .resolved
        .contains(&ResolverEvent::Resolved { eid: *eid })
}

#[test]
fn query_for_a_sleepy_childs_addresses_is_answered_by_its_parent() {
    let mut m = mesh_with_child();
    let parent = m.sim.nodes[1].mle.rloc16();
    for eid in [m.ml_eid(2), GUA] {
        assert_eq!(m.resolve(0, &eid), Ok(Resolution::QueryPending));
        assert!(m.run_until(secs(10), |s| resolved(s, 0, &eid)));
        let info = m.tmf[0].resolver.info(&eid).unwrap();
        assert_eq!(info.state, EntryState::Cached);
        assert_eq!(info.rloc16, parent);
        // Now resolution is immediate.
        assert_eq!(m.resolve(0, &eid), Ok(Resolution::Resolved(parent)));
    }
    // The query was a multicast (one datagram, every router got it) and the
    // answers were acknowledged confirmable notifications.
    assert_eq!(m.tmf[1].rx[&Uri::AddressQuery.id()], 2);
    assert_eq!(m.tmf[0].rx[&Uri::AddressNotify.id()], 2);
    assert_eq!(m.tmf[0].agent.endpoint().pending_len(), 0);
    assert_eq!(m.tmf[1].agent.endpoint().pending_len(), 0);
}

#[test]
fn router_answers_for_its_own_address_and_ignores_ftd_children() {
    let mut m = mesh_with_child();
    let own = m.ml_eid(1);
    assert_eq!(m.resolve(0, &own), Ok(Resolution::QueryPending));
    assert!(m.run_until(secs(10), |s| resolved(s, 0, &own)));
    assert_eq!(
        m.tmf[0].resolver.info(&own).unwrap().rloc16,
        m.sim.nodes[1].mle.rloc16()
    );
    // Nobody has this address: the query fails after the timeout.
    let unknown: Ipv6Addr = "fd00:dead::beef".parse().unwrap();
    assert_eq!(m.resolve(0, &unknown), Ok(Resolution::QueryPending));
    assert!(m.run_until(secs(20), |s| {
        s.tmf[0]
            .resolved
            .contains(&ResolverEvent::ResolutionFailed { eid: unknown })
    }));
    assert_eq!(
        m.tmf[0].resolver.info(&unknown).unwrap().state,
        EntryState::QueryRetry
    );
}

#[test]
fn queries_and_notifications_must_have_the_right_message_type() {
    let mut m = mesh_with_child();
    let mut buf = [0u8; 64];
    let n = build_address_query(&GUA, &mut buf).unwrap();
    // A confirmable query is not answered.
    let before = m.tmf[1].sink.out.len();
    m.raw_request(0, 1, "a/aq", Type::Con, Code::POST, &buf[..n]);
    assert_eq!(m.tmf[1].sink.out.len(), before);
    assert_eq!(m.tmf[0].rx.get(&Uri::AddressNotify.id()), None);
    // A non-confirmable notification does not update the cache.
    assert_eq!(m.resolve(0, &GUA), Ok(Resolution::QueryPending));
    m.tmf[0].sink.out.clear();
    let notify = AddressNotify {
        target: GUA,
        ml_eid_iid: ipv6::iid(&m.ml_eid(2)),
        rloc16: Rloc16(0x0400),
        last_transaction_time: Some(1),
    };
    let n = build_address_notify(&notify, &mut buf).unwrap();
    assert!(
        m.raw_request(1, 0, "a/an", Type::Non, Code::POST, &buf[..n])
            .is_none()
    );
    assert_eq!(
        m.tmf[0].resolver.info(&GUA).unwrap().state,
        EntryState::Query
    );
    // The confirmable one does, and is acknowledged.
    let (code, body) = m
        .raw_request(1, 0, "a/an", Type::Con, Code::POST, &buf[..n])
        .unwrap();
    assert_eq!(code, Code::EMPTY);
    assert!(body.is_empty());
    assert_eq!(m.tmf[0].resolver.info(&GUA).unwrap().rloc16, Rloc16(0x0400));
}

#[test]
fn duplicate_address_is_resolved_with_address_error() {
    let mut m = mesh_with_child();
    // The child really has the address on its interface.
    m.tmf[2]
        .ip6
        .netif
        .add_unicast(UnicastAddress::manual(GUA))
        .unwrap();
    assert_eq!(m.resolve(0, &GUA), Ok(Resolution::QueryPending));
    assert!(m.run_until(secs(10), |s| resolved(s, 0, &GUA)));
    // A second device with another ML-EID answers for the same address.
    let mut buf = [0u8; 64];
    let other = AddressNotify {
        target: GUA,
        ml_eid_iid: Iid([0x77; 8]),
        rloc16: Rloc16(0x0800),
        last_transaction_time: Some(0),
    };
    let n = build_address_notify(&other, &mut buf).unwrap();
    // The cache entry from the child (notification with a transaction time)
    // exists; a notification with a different ML-EID is refused, no ACK.
    m.inject(1, 0, "a/an", Type::Con, Code::POST, &buf[..n]);
    // No acknowledgement, but an Address Error to all routers.
    assert_eq!(
        m.tmf[0].resolver.info(&GUA).unwrap().rloc16,
        m.sim.nodes[1].mle.rloc16()
    );
    // Router 1 got the multicast, removed GUA from its child's list and
    // told the child, which removed the address from its interface.
    assert_eq!(m.tmf[1].rx[&Uri::AddressError.id()], 1);
    assert!(
        m.sim.nodes[1]
            .mle
            .children()
            .find_by_address(&MLP, &GUA, StateFilter::Valid)
            .is_none()
    );
    assert_eq!(m.tmf[2].rx[&Uri::AddressError.id()], 1);
    assert_eq!(m.tmf[2].errors_seen, 1);
    assert!(!m.tmf[2].ip6.netif.has_unicast(&GUA));
    // The child keeps its ML-EID.
    assert!(m.tmf[2].ip6.netif.has_unicast(&m.ml_eid(2)));
}

#[test]
fn address_error_with_own_ml_eid_is_ignored() {
    let mut m = mesh_with_child();
    m.tmf[2]
        .ip6
        .netif
        .add_unicast(UnicastAddress::manual(GUA))
        .unwrap();
    let mut buf = [0u8; 64];
    // Same ML-EID IID as the child: the report is about another device.
    let n = build_address_error(&GUA, &ipv6::iid(&m.ml_eid(2)), &mut buf).unwrap();
    m.raw_request(0, 2, "a/ae", Type::Con, Code::POST, &buf[..n]);
    assert_eq!(m.tmf[2].errors_seen, 0);
    assert!(m.tmf[2].ip6.netif.has_unicast(&GUA));
    // A router ignores an Address Error that is not about its children.
    let n = build_address_error(&GUA, &Iid([0x55; 8]), &mut buf).unwrap();
    let (code, _) = m
        .raw_request(0, 1, "a/ae", Type::Con, Code::POST, &buf[..n])
        .unwrap();
    // ... but the child registered GUA with another ML-EID, so it is removed
    // and the child is told (the first datagram of the router is the ACK).
    assert_eq!(code, Code::EMPTY);
    assert!(
        m.sim.nodes[1]
            .mle
            .children()
            .find_by_address(&MLP, &GUA, StateFilter::Valid)
            .is_none()
    );
}
