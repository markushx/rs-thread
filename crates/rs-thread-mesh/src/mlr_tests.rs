//! MLR client through the mesh simulator with a fake Primary Backbone Router
//! node that answers `/n/mr`.

use core::net::Ipv6Addr;

use rs_thread_mle::neighbor::{MlrState, StateFilter};

use crate::dua_tests::{bbr, bring_up, secs, serve, serve_bbr};
use crate::mlr::{build_mlr_response, parse_mlr_response};
use crate::sim::MeshSim;
use crate::tlv::mlr_status;

fn g(s: &str) -> Ipv6Addr {
    s.parse().unwrap()
}

fn seen_from(m: &MeshSim, node: usize, group: &Ipv6Addr) -> usize {
    m.fake_bbr
        .mlr_seen
        .iter()
        .filter(|(_, from, gs)| *from == m.rloc(node) && gs.contains(group))
        .count()
}

fn local_state(m: &MeshSim, i: usize, group: &Ipv6Addr) -> Option<MlrState> {
    m.tmf[i]
        .bbrn
        .mlr
        .local_groups()
        .iter()
        .find(|(a, _)| a == group)
        .map(|(_, s)| *s)
}

#[test]
fn response_codec() {
    let mut buf = [0u8; 64];
    let n = build_mlr_response(mlr_status::SUCCESS, &[], &mut buf).unwrap();
    let r = parse_mlr_response(&buf[..n]).unwrap();
    assert_eq!(r.status, 0);
    assert!(r.failed.is_empty());
    let n = build_mlr_response(mlr_status::NO_RESOURCES, &[g("ff05::1")], &mut buf).unwrap();
    let r = parse_mlr_response(&buf[..n]).unwrap();
    assert_eq!(r.status, mlr_status::NO_RESOURCES);
    assert_eq!(r.failed.as_slice(), [g("ff05::1")]);
    // Failed addresses with a success are malformed, as is a missing status.
    let n = build_mlr_response(mlr_status::SUCCESS, &[g("ff05::1")], &mut buf).unwrap();
    assert!(parse_mlr_response(&buf[..n]).is_err());
    assert!(parse_mlr_response(&[]).is_err());
}

#[test]
fn subscribed_groups_are_registered_with_the_primary_bbr() {
    let mut m = bring_up();
    m.fake_bbr.node = Some(1);
    let big = g("ff05::1234");
    let realm = g("ff03::1234");
    m.tmf[2].ip6.netif.subscribe_external(big).unwrap();
    m.tmf[2].ip6.netif.subscribe_external(realm).unwrap();
    m.run(secs(5));
    // No Primary Backbone Router yet.
    assert!(m.fake_bbr.mlr_seen.is_empty());
    assert_eq!(local_state(&m, 2, &big), Some(MlrState::ToRegister));
    assert_eq!(local_state(&m, 2, &realm), None);
    serve_bbr(&mut m, 1, 1, true);
    assert!(m.run_until(secs(60), |s| local_state(s, 2, &big)
        == Some(MlrState::Registered)));
    assert_eq!(seen_from(&m, 2, &big), 1);
    assert_eq!(seen_from(&m, 2, &realm), 0);
    // A group subscribed later is registered on its own.
    let later = g("ff0e::77");
    m.tmf[0].ip6.netif.subscribe_external(later).unwrap();
    assert!(m.run_until(secs(60), |s| seen_from(s, 0, &later) == 1));
    // Unsubscribing drops it.
    m.tmf[2].ip6.netif.unsubscribe_external(&big).unwrap();
    m.run(secs(5));
    assert_eq!(local_state(&m, 2, &big), None);
}

#[test]
fn child_groups_are_registered_by_the_parent() {
    let mut m = bring_up();
    m.fake_bbr.node = Some(1);
    serve_bbr(&mut m, 1, 1, true);
    m.run(secs(30));
    let group = g("ff05::abcd");
    m.tmf[3].ip6.netif.subscribe_external(group).unwrap();
    assert!(m.run_until(secs(120), |s| seen_from(s, 2, &group) >= 1));
    assert_eq!(seen_from(&m, 3, &group), 0, "the child does not register");
    m.run(secs(2));
    let child = m.sim.nodes[2]
        .mle
        .children()
        .iter(StateFilter::Valid)
        .next()
        .unwrap();
    assert_eq!(child.multicast_listeners().len(), 1);
    assert_eq!(child.multicast_listeners()[0].addr, group);
    assert_eq!(child.multicast_listeners()[0].mlr, MlrState::Registered);
    // The parent subscribing to the same group needs no second request.
    let n = m.fake_bbr.mlr_seen.len();
    m.tmf[2].ip6.netif.subscribe_external(group).unwrap();
    m.run(secs(20));
    assert_eq!(m.fake_bbr.mlr_seen.len(), n);
    assert_eq!(local_state(&m, 2, &group), Some(MlrState::Registered));
}

#[test]
fn failed_addresses_are_retried() {
    let mut m = bring_up();
    m.fake_bbr.node = Some(1);
    let a = g("ff05::1");
    let b = g("ff05::2");
    m.tmf[2].ip6.netif.subscribe_external(a).unwrap();
    m.tmf[2].ip6.netif.subscribe_external(b).unwrap();
    m.fake_bbr
        .mlr_script
        .push_back((mlr_status::NO_RESOURCES, std::vec![b]));
    serve_bbr(&mut m, 1, 1, true);
    assert!(m.run_until(secs(120), |s| local_state(s, 2, &a)
        == Some(MlrState::Registered)
        && local_state(s, 2, &b) == Some(MlrState::Registered)));
    // `b` was refused once and registered by the retry; `a` once.
    assert_eq!(seen_from(&m, 2, &a), 1);
    assert_eq!(seen_from(&m, 2, &b), 2);
}

#[test]
fn unanswered_request_is_retried() {
    let mut m = bring_up();
    m.fake_bbr.node = Some(1);
    m.fake_bbr.silent = true;
    let a = g("ff05::9");
    m.tmf[2].ip6.netif.subscribe_external(a).unwrap();
    serve_bbr(&mut m, 1, 1, true);
    m.run(secs(300));
    assert!(seen_from(&m, 2, &a) >= 1);
    m.fake_bbr.silent = false;
    assert!(m.run_until(secs(400), |s| local_state(s, 2, &a)
        == Some(MlrState::Registered)));
}

#[test]
fn sequence_change_and_timeout_trigger_reregistration() {
    let mut m = bring_up();
    m.fake_bbr.node = Some(1);
    let a = g("ff05::5");
    m.tmf[2].ip6.netif.subscribe_external(a).unwrap();
    let r1 = m.sim.nodes[1].mle.rloc16().0;
    let mut c = bbr(r1, 1);
    c.mlr_timeout = 300;
    serve(&mut m, 1, Some(c), true);
    assert!(m.run_until(secs(60), |s| local_state(s, 2, &a)
        == Some(MlrState::Registered)));
    assert_eq!(seen_from(&m, 2, &a), 1);
    // A new sequence number: reregistration within the reregistration delay.
    c.sequence_number = 2;
    serve(&mut m, 1, Some(c), true);
    assert!(m.run_until(secs(30), |s| seen_from(s, 2, &a) == 2));
    // Without changes the registration is renewed before the MLR timeout
    // (151 s to 291 s after the last renewal timer was armed).
    assert!(m.run_until(secs(400), |s| seen_from(s, 2, &a) == 3));
}

#[test]
fn losing_the_primary_bbr_stops_registrations() {
    let mut m = bring_up();
    m.fake_bbr.node = Some(1);
    let a = g("ff05::6");
    m.tmf[2].ip6.netif.subscribe_external(a).unwrap();
    serve_bbr(&mut m, 1, 1, true);
    assert!(m.run_until(secs(60), |s| seen_from(s, 2, &a) == 1));
    serve(&mut m, 1, None, true);
    m.run(secs(30));
    let n = m.fake_bbr.mlr_seen.len();
    m.run(secs(4000));
    assert_eq!(m.fake_bbr.mlr_seen.len(), n);
    // A new Primary Backbone Router gets the registration.
    m.fake_bbr.node = Some(2);
    let r2 = m.sim.nodes[2].mle.rloc16().0;
    serve(&mut m, 2, Some(bbr(r2, 1)), true);
    assert!(m.run_until(secs(60), |s| {
        s.fake_bbr
            .mlr_seen
            .iter()
            .any(|(at, _, gs)| *at == 2 && gs.contains(&a))
    }));
}
