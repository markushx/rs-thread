//! DUA client through the mesh simulator with a fake Primary Backbone Router
//! node that answers `/n/dr`.

use core::net::Ipv6Addr;

use rs_thread_coap::message::{Code, Type};
use rs_thread_core::time::Duration;
use rs_thread_core::types::ipv6;
use rs_thread_mle::Role;
use rs_thread_mle::tlv::DeviceMode;

use crate::address::build_address_error;
use crate::dua::DuaState;
use crate::netdata::backbone::BbrConfig;
use crate::netdata::local::{OnMeshPrefixConfig, ServiceConfig};
use crate::netdata::tlv::{BrFlags, NetPrefix, THREAD_ENTERPRISE_NUMBER};
use crate::sim::MeshSim;
use crate::tlv::dua_status;

pub(crate) fn secs(s: u64) -> Duration {
    Duration::from_secs(s)
}

pub(crate) const FTD: DeviceMode = DeviceMode::new(true, true, true);
pub(crate) const SED: DeviceMode = DeviceMode::new(false, false, false);

fn domain_prefix() -> NetPrefix {
    NetPrefix::from_addr(&"fd00:7d03:7d03:7d03::".parse::<Ipv6Addr>().unwrap(), 64).unwrap()
}

pub(crate) fn bbr(server16: u16, seq: u8) -> BbrConfig {
    BbrConfig {
        server16,
        sequence_number: seq,
        reregistration_delay: 5,
        mlr_timeout: 3600,
    }
}

/// Leader (0), routers 1 and 2 in a triangle, and a sleepy child 3 of
/// router 2.
pub(crate) fn bring_up() -> MeshSim {
    let modes = [FTD, FTD, FTD, SED];
    let mut m = MeshSim::with_modes(&modes);
    for (x, y) in [(0, 1), (0, 2), (1, 2), (2, 3)] {
        m.connect(x, y, -60);
    }
    m.start(0);
    assert!(m.run_until(secs(60), |s| s.sim.role(0) == Role::Leader));
    for (i, mode) in modes.iter().enumerate().skip(1) {
        m.start(i);
        assert!(m.run_until(secs(60), |s| s.sim.role(i) == Role::Child));
        if mode.full_thread_device() {
            assert!(m.run_until(secs(300), |s| s.sim.role(i) == Role::Router));
        }
    }
    m
}

/// Node `i` serves the Backbone Router service `cfg` (removing it with
/// `None`) and the Domain Prefix (`dp`).
pub(crate) fn serve(m: &mut MeshSim, i: usize, cfg: Option<BbrConfig>, dp: bool) {
    m.set_local(i, |l| {
        let _ = l.remove_service(THREAD_ENTERPRISE_NUMBER, &[1]);
        if let Some(c) = cfg {
            l.add_service(
                ServiceConfig::new(THREAD_ENTERPRISE_NUMBER, &[1], &c.server_data(), true).unwrap(),
            )
            .unwrap();
        }
        let _ = l.remove_on_mesh_prefix(&domain_prefix());
        if dp {
            l.add_on_mesh_prefix(OnMeshPrefixConfig {
                prefix: domain_prefix(),
                flags: BrFlags::default()
                    .with(BrFlags::ON_MESH, true)
                    .with(BrFlags::DP, true)
                    .with(BrFlags::PREFERRED, true),
                stable: true,
            })
            .unwrap();
        }
    });
}

/// Node `i` serves a Backbone Router with sequence number `seq`.
pub(crate) fn serve_bbr(m: &mut MeshSim, i: usize, seq: u8, dp: bool) {
    let r = m.sim.nodes[i].mle.rloc16().0;
    serve(m, i, Some(bbr(r, seq)), dp);
}

fn dua_of(m: &MeshSim, i: usize) -> Option<Ipv6Addr> {
    m.tmf[i].bbrn.dua.domain_unicast_address()
}

fn on_netif(m: &MeshSim, i: usize, a: &Ipv6Addr) -> bool {
    m.tmf[i].ip6.netif.has_unicast(a)
}

fn state(m: &MeshSim, i: usize) -> DuaState {
    m.tmf[i].bbrn.dua.state()
}

#[test]
fn dua_is_generated_and_registered_with_the_primary_bbr() {
    let mut m = bring_up();
    m.fake_bbr.node = Some(1);
    serve_bbr(&mut m, 1, 1, true);
    assert!(m.run_until(secs(120), |s| {
        (0..3).all(|i| s.tmf[i].bbrn.dua.state() == DuaState::Registered)
    }));
    for i in 0..3 {
        let dua = dua_of(&m, i).unwrap();
        assert!(domain_prefix().contains(&dua));
        assert!(on_netif(&m, i, &dua));
        // Not the ML-EID's IID, and not preferred before the DAD period.
        assert_ne!(ipv6::iid(&dua), ipv6::iid(&m.ml_eid(i)));
        assert!(!m.tmf[i].ip6.netif.find_unicast(&dua).unwrap().preferred);
        let seen: std::vec::Vec<_> = m
            .fake_bbr
            .dua_seen
            .iter()
            .filter(|s| s.target == dua)
            .collect();
        assert_eq!(seen.len(), 1, "node {i}");
        assert_eq!(seen[0].at, 1);
        assert_eq!(seen[0].ml_eid_iid, ipv6::iid(&m.ml_eid(i)));
        assert_eq!(seen[0].last_transaction_time, None);
        assert_eq!(seen[0].from, m.rloc(i));
        assert!(m.tmf[i].bbrn.dad_stored.is_empty());
    }
    // The DUA becomes preferred after the DAD period.
    m.run(secs(110));
    for i in 0..3 {
        let dua = dua_of(&m, i).unwrap();
        assert!(m.tmf[i].ip6.netif.find_unicast(&dua).unwrap().preferred);
    }
    // The SLAAC logic leaves the Domain Prefix alone.
    assert_eq!(
        m.tmf[0]
            .ip6
            .netif
            .unicast_addresses()
            .filter(|u| domain_prefix().contains(&u.addr))
            .count(),
        1
    );
}

#[test]
fn no_dua_without_domain_prefix_or_primary_bbr() {
    let mut m = bring_up();
    m.fake_bbr.node = Some(1);
    // Domain Prefix only: DUA formed but nobody to register with.
    serve(&mut m, 1, None, true);
    m.run(secs(60));
    assert!(dua_of(&m, 2).is_some());
    assert!(m.fake_bbr.dua_seen.is_empty());
    assert_eq!(state(&m, 2), DuaState::ToRegister);
    // The Backbone Router appears: registration follows.
    serve_bbr(&mut m, 1, 1, true);
    assert!(m.run_until(secs(120), |s| state(s, 2) == DuaState::Registered));
    // Domain Prefix gone: the DUA is removed everywhere.
    let dua = dua_of(&m, 2).unwrap();
    serve_bbr(&mut m, 1, 1, false);
    assert!(m.run_until(secs(60), |s| state(s, 2) == DuaState::NotExist));
    assert!(!on_netif(&m, 2, &dua));
}

#[test]
fn duplicate_response_makes_the_device_generate_a_new_dua() {
    let mut m = bring_up();
    m.fake_bbr.node = Some(1);
    let ml = ipv6::iid(&m.ml_eid(2));
    m.fake_bbr.dua_by_ml_eid.push((ml, dua_status::DUPLICATE));
    serve_bbr(&mut m, 1, 1, true);
    assert!(m.run_until(secs(120), |s| {
        (0..3).all(|i| s.tmf[i].bbrn.dua.state() == DuaState::Registered)
    }));
    let first: std::vec::Vec<_> = m
        .fake_bbr
        .dua_seen
        .iter()
        .filter(|s| s.ml_eid_iid == ml)
        .collect();
    assert_eq!(first.len(), 2);
    assert_ne!(first[0].target, first[1].target);
    assert_eq!(dua_of(&m, 2), Some(first[1].target));
    assert!(!on_netif(&m, 2, &first[0].target));
    assert_eq!(m.tmf[2].bbrn.dua.dad_counter(), 1);
    assert_eq!(m.tmf[2].bbrn.dad_stored, [1]);
}

#[test]
fn address_error_for_the_dua_is_a_duplicate_report() {
    let mut m = bring_up();
    m.fake_bbr.node = Some(1);
    serve_bbr(&mut m, 1, 1, true);
    assert!(m.run_until(secs(120), |s| state(s, 2) == DuaState::Registered));
    let old = dua_of(&m, 2).unwrap();
    let mut buf = [0u8; 40];
    // Another device with another ML-EID IID claims the address.
    let other = rs_thread_core::types::Iid([9; 8]);
    let n = build_address_error(&old, &other, &mut buf).unwrap();
    m.inject(0, 2, "a/ae", Type::Non, Code::POST, &buf[..n]);
    m.run(secs(1));
    let new = dua_of(&m, 2).unwrap();
    assert_ne!(new, old);
    assert!(!on_netif(&m, 2, &old));
    assert!(on_netif(&m, 2, &new));
    assert_eq!(m.tmf[2].bbrn.dad_stored, [1]);
    // Not removed like an ordinary address: and registered again.
    assert!(m.run_until(secs(60), |s| state(s, 2) == DuaState::Registered));
    // An error naming our own ML-EID is no conflict.
    let own = ipv6::iid(&m.ml_eid(2));
    let n = build_address_error(&new, &own, &mut buf).unwrap();
    m.inject(0, 2, "a/ae", Type::Non, Code::POST, &buf[..n]);
    assert_eq!(dua_of(&m, 2), Some(new));
}

#[test]
fn child_dua_is_registered_by_its_parent() {
    let mut m = bring_up();
    m.fake_bbr.node = Some(1);
    serve_bbr(&mut m, 1, 1, true);
    assert!(m.run_until(secs(120), |s| {
        (0..3).all(|i| s.tmf[i].bbrn.dua.state() == DuaState::Registered)
    }));
    let child_dua = dua_of(&m, 3).expect("the child forms a DUA");
    // The child does not register itself; its parent (node 2) does.
    assert_eq!(m.tmf[3].bbrn.dua_requests_sent, 0);
    assert!(m.run_until(secs(120), |s| {
        s.fake_bbr.dua_seen.iter().any(|x| x.target == child_dua)
    }));
    let seen = m
        .fake_bbr
        .dua_seen
        .iter()
        .find(|x| x.target == child_dua)
        .unwrap()
        .clone();
    assert_eq!(seen.from, m.rloc(2));
    assert_eq!(seen.ml_eid_iid, ipv6::iid(&m.ml_eid(3)));
    assert!(seen.last_transaction_time.is_some());
    assert_eq!(m.tmf[2].bbrn.dua.child_counts(), (1, 1));
    // The parent knows the DUA as an address of the child.
    let child = m.sim.nodes[2]
        .mle
        .children()
        .iter(rs_thread_mle::neighbor::StateFilter::Valid)
        .next()
        .unwrap();
    assert!(child.addresses().contains(&child_dua));
}

#[test]
fn child_dua_duplicate_is_reported_to_the_child() {
    let mut m = bring_up();
    m.fake_bbr.node = Some(1);
    let child_ml = ipv6::iid(&m.ml_eid(3));
    m.fake_bbr
        .dua_by_ml_eid
        .push((child_ml, dua_status::DUPLICATE));
    serve_bbr(&mut m, 1, 1, true);
    assert!(m.run_until(secs(300), |s| {
        s.fake_bbr
            .dua_seen
            .iter()
            .filter(|x| x.ml_eid_iid == child_ml)
            .count()
            >= 2
    }));
    // The parent sent a DUA.ntf, removed the address and the child formed a
    // new DUA with the next DAD counter.
    assert_eq!(m.tmf[2].bbrn.child_notifications.len(), 1);
    assert_eq!(
        m.tmf[2].bbrn.child_notifications[0].status,
        dua_status::DUPLICATE
    );
    let kids: std::vec::Vec<_> = m
        .fake_bbr
        .dua_seen
        .iter()
        .filter(|x| x.ml_eid_iid == child_ml)
        .map(|x| x.target)
        .collect();
    assert_ne!(kids[0], kids[1]);
    assert_eq!(dua_of(&m, 3), Some(kids[1]));
    assert_eq!(m.tmf[3].bbrn.dad_stored, [1]);
    let child = m.sim.nodes[2]
        .mle
        .children()
        .iter(rs_thread_mle::neighbor::StateFilter::Valid)
        .next()
        .unwrap();
    assert!(!child.addresses().contains(&kids[0]));
    assert!(child.addresses().contains(&kids[1]));
}

#[test]
fn sequence_number_change_triggers_reregistration() {
    let mut m = bring_up();
    m.fake_bbr.node = Some(1);
    let r1 = m.sim.nodes[1].mle.rloc16().0;
    serve(&mut m, 1, Some(bbr(r1, 1)), true);
    assert!(m.run_until(secs(120), |s| {
        (0..3).all(|i| s.tmf[i].bbrn.dua.state() == DuaState::Registered)
    }));
    let before = m.fake_bbr.dua_seen.len();
    // Refreshing the delay only does not reregister.
    let mut c = bbr(r1, 1);
    c.reregistration_delay = 9;
    serve(&mut m, 1, Some(c), true);
    m.run(secs(60));
    assert_eq!(m.fake_bbr.dua_seen.len(), before);
    // A new sequence number does, after a random delay up to the
    // reregistration delay.
    c.sequence_number = 2;
    serve(&mut m, 1, Some(c), true);
    assert!(m.run_until(secs(60), |s| s.fake_bbr.dua_seen.len() >= before + 3));
    m.run(secs(30));
    assert_eq!(m.fake_bbr.dua_seen.len(), before + 3 + 1); // + the child
    assert!((0..3).all(|i| state(&m, i) == DuaState::Registered));
}

#[test]
fn primary_bbr_loss_stops_and_switch_redirects_registrations() {
    let mut m = bring_up();
    m.fake_bbr.node = Some(1);
    let r1 = m.sim.nodes[1].mle.rloc16().0;
    let r2 = m.sim.nodes[2].mle.rloc16().0;
    serve(&mut m, 1, Some(bbr(r1, 1)), true);
    assert!(m.run_until(secs(120), |s| {
        (0..3).all(|i| s.tmf[i].bbrn.dua.state() == DuaState::Registered)
    }));
    // The Backbone Router goes away: no Primary, the DUAs stay, nothing is
    // sent.
    serve(&mut m, 1, None, true);
    assert!(m.run_until(secs(60), |s| {
        (0..3).all(|i| !s.tmf[i].bbrn.bbr.has_primary())
    }));
    let n = m.fake_bbr.dua_seen.len();
    m.run(secs(300));
    assert_eq!(m.fake_bbr.dua_seen.len(), n);
    assert!(dua_of(&m, 0).is_some());
    // Another node takes over: everybody registers with it.
    m.fake_bbr.node = Some(2);
    serve(&mut m, 2, Some(bbr(r2, 1)), true);
    assert!(m.run_until(
        secs(120),
        |s| s.fake_bbr.dua_seen.iter().filter(|x| x.at == 2).count() >= 3
    ));
    assert!(m.fake_bbr.dua_seen[n..].iter().all(|x| x.at == 2));
}

#[test]
fn unanswered_registration_is_retried() {
    let mut m = bring_up();
    m.fake_bbr.node = Some(1);
    m.fake_bbr.silent = true;
    let r1 = m.sim.nodes[1].mle.rloc16().0;
    serve(&mut m, 1, Some(bbr(r1, 1)), true);
    m.run(secs(400));
    let from2 = |s: &MeshSim| {
        s.fake_bbr
            .dua_seen
            .iter()
            .filter(|x| x.from == s.rloc(2))
            .count()
    };
    assert!(from2(&m) >= 2, "retried after the timeout");
    m.fake_bbr.silent = false;
    assert!(m.run_until(secs(300), |s| state(s, 2) == DuaState::Registered));
}

#[test]
fn failure_statuses_back_off_and_retry() {
    let mut m = bring_up();
    m.fake_bbr.node = Some(1);
    let ml = ipv6::iid(&m.ml_eid(2));
    for st in [dua_status::NO_RESOURCES, dua_status::NOT_PRIMARY] {
        m.fake_bbr.dua_by_ml_eid.push((ml, st));
    }
    // Only the first of the two entries is used per request.
    let r1 = m.sim.nodes[1].mle.rloc16().0;
    serve(&mut m, 1, Some(bbr(r1, 1)), true);
    assert!(m.run_until(secs(200), |s| state(s, 2) == DuaState::Registered));
    let n = m
        .fake_bbr
        .dua_seen
        .iter()
        .filter(|x| x.ml_eid_iid == ml)
        .count();
    assert_eq!(n, 3, "two refusals and the accepted request");
    // Invalid removes the DUA.
    m.fake_bbr.dua_by_ml_eid.push((ml, dua_status::INVALID));
    serve(&mut m, 1, Some(bbr(r1, 2)), true);
    assert!(m.run_until(secs(60), |s| state(s, 2) == DuaState::NotExist));
}
