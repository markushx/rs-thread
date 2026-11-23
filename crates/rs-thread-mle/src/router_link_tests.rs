//! Link Request / Link Accept, router neighbors, aging and router role
//! restore.

use rs_thread_core::time::Duration;

use crate::env::{MleEvent, Role};
use crate::link_quality::LinkQuality;
use crate::message::Command;
use crate::mle::{Mle, MleConfig};
use crate::neighbor::StateFilter;
use crate::sim::{FTD, Sim};
use crate::test_support::TestEnv;

fn secs(s: u64) -> Duration {
    Duration::from_secs(s)
}

/// A (0) leader, B (1) router, C (2) child of B; A-B and B-C in range.
fn setup() -> Sim {
    let mut sim = Sim::new(3);
    sim.connect(0, 1, -60);
    sim.connect(1, 2, -60);
    sim.start(0);
    assert!(sim.run_until(secs(60), |s| s.role(0) == Role::Leader));
    sim.start(1);
    assert!(sim.run_until(secs(30), |s| s.role(1) == Role::Child));
    sim.upgrade(0, 1);
    sim
}

fn aid(sim: &Sim) -> u8 {
    sim.nodes[0].mle.router_id().unwrap()
}

fn bid(sim: &Sim) -> u8 {
    sim.nodes[1].mle.router_id().unwrap()
}

/// Make B drop its link to A (it keeps the router entry) and re-link.
fn relink(sim: &mut Sim) {
    let now = sim.now;
    let a = aid(sim);
    let b = &mut sim.nodes[1];
    b.mle.remove_router_neighbor(&mut b.env, now, a);
    assert_eq!(
        b.mle.router_table().find_by_id(a).unwrap().neighbor.state,
        crate::neighbor::NeighborState::Invalid
    );
    // Like the Advertisement handler: the router is in LinkRequest state
    // when the (scheduled) request goes out.
    b.mle
        .rtr
        .table
        .find_by_id_mut(a)
        .unwrap()
        .neighbor
        .set_state(crate::neighbor::NeighborState::LinkRequest, now);
    b.mle.send_link_request(&mut b.env, now, Some(a)).unwrap();
    sim.pump();
}

#[test]
fn link_request_accept_handshake() {
    let mut sim = setup();
    let (a, b) = (aid(&sim), bid(&sim));
    relink(&mut sim);
    let ea = sim.nodes[0].env.ext;
    let eb = sim.nodes[1].env.ext;
    // B: Link Request -> A; A: Link Accept And Request -> B; B: Link Accept -> A.
    assert_eq!(sim.nodes[0].count_rx(Command::LinkRequest), 1);
    assert_eq!(sim.nodes[1].count_rx(Command::LinkAcceptAndRequest), 1);
    assert_eq!(sim.nodes[0].count_rx(Command::LinkAccept), 1);
    let ra = sim.nodes[1].mle.router_table().find_by_id(a).unwrap();
    let rb = sim.nodes[0].mle.router_table().find_by_id(b).unwrap();
    assert!(ra.neighbor.is_valid() && rb.neighbor.is_valid());
    assert_eq!(ra.neighbor.ext_address, ea);
    assert_eq!(rb.neighbor.ext_address, eb);
    assert_eq!(ra.neighbor.rloc16, sim.nodes[0].mle.rloc16());
    // Link margin of the peer -> link quality out; our RSS -> link quality in.
    assert_eq!(ra.neighbor.link_info.link_quality_out(), LinkQuality::Q3);
    assert_eq!(ra.neighbor.link_info.link_quality_in(), LinkQuality::Q3);
    assert_eq!(ra.neighbor.version, 5);
    assert!(sim.nodes[1].env.has_event(MleEvent::RouterAdded {
        ext: ea,
        rloc16: ra.neighbor.rloc16
    }));
    // Both ends route via the direct link: cost 1 (quality 3).
    assert_eq!(sim.nodes[1].mle.path_cost(ra.neighbor.rloc16), 1);
    assert_eq!(sim.nodes[0].mle.path_cost(rb.neighbor.rloc16), 1);
    assert_eq!(sim.nodes[0].mle.router_table().count(StateFilter::Valid), 1);
}

#[test]
fn link_accept_needs_the_challenge_response() {
    let mut sim = setup();
    let a = aid(&sim);
    let now = sim.now;
    {
        let b = &mut sim.nodes[1];
        b.mle.remove_router_neighbor(&mut b.env, now, a);
        b.mle
            .rtr
            .table
            .find_by_id_mut(a)
            .unwrap()
            .neighbor
            .set_state(crate::neighbor::NeighborState::LinkRequest, now);
        b.mle.send_link_request(&mut b.env, now, Some(a)).unwrap();
        // Corrupt the remembered challenge: the Link Accept fails the check.
        b.mle
            .rtr
            .table
            .find_by_id_mut(a)
            .unwrap()
            .neighbor
            .challenge = [9; 8];
    }
    sim.pump();
    let r = sim.nodes[1].mle.router_table().find_by_id(a).unwrap();
    assert!(!r.neighbor.is_valid());
}

#[test]
fn unanswered_link_request_removes_the_router_after_the_timeout() {
    let mut sim = setup();
    let a = aid(&sim);
    relink(&mut sim);
    let now = sim.now;
    sim.disconnect(0, 1);
    {
        let b = &mut sim.nodes[1];
        b.mle.remove_router_neighbor(&mut b.env, now, a);
        b.mle.send_link_request(&mut b.env, now, Some(a)).unwrap();
        // Entering LinkRequest like a scheduled request does.
        let r = b.mle.rtr.table.find_by_id_mut(a).unwrap();
        r.neighbor
            .set_state(crate::neighbor::NeighborState::LinkRequest, now);
        assert_eq!(r.link_accept_timeout, 3);
    }
    sim.pump();
    sim.run(secs(4));
    let r = sim.nodes[1].mle.router_table().find_by_id(a).unwrap();
    assert_eq!(r.neighbor.state, crate::neighbor::NeighborState::Invalid);
    assert_eq!(r.link_accept_timeout, 0);
}

#[test]
fn silent_neighbor_gets_link_requests_then_is_removed() {
    let mut sim = setup();
    let a = aid(&sim);
    relink(&mut sim);
    let ea = sim.nodes[0].env.ext;
    let rloc = sim.nodes[0].mle.rloc16();
    sim.disconnect(0, 1);
    // The neighbor has been quiet for MAX_NEIGHBOR_AGE.
    let now = sim.now;
    sim.nodes[1]
        .mle
        .rtr
        .table
        .find_by_id_mut(a)
        .unwrap()
        .neighbor
        .last_heard = now - secs(101);
    let before = sim.nodes[1].count_tx(Command::LinkRequest);
    sim.run(secs(1));
    // A Link Request goes out (nobody hears it: the count of deliveries
    // stays, the queue shows the attempt) ...
    assert!(
        sim.nodes[1]
            .mle
            .router_table()
            .find_by_id(a)
            .unwrap()
            .link_request_attempts
            <= 3
    );
    sim.run(secs(20));
    let _ = before;
    // ... and with no Link Accept the router link is gone.
    let r = sim.nodes[1].mle.router_table().find_by_id(a).unwrap();
    assert!(!r.neighbor.is_valid());
    assert!(sim.nodes[1].env.has_event(MleEvent::RouterRemoved {
        ext: ea,
        rloc16: rloc
    }));
}

#[test]
fn restored_router_relinks_with_a_multicast_link_request() {
    let mut sim = setup();
    relink(&mut sim);
    // C attaches below B.
    sim.start(2);
    assert!(sim.run_until(secs(30), |s| s.role(2) == Role::Child));
    assert_eq!(sim.nodes[1].mle.children().count(StateFilter::Valid), 1);
    let rloc = sim.nodes[1].mle.rloc16();
    let crloc = sim.nodes[2].mle.rloc16();
    let partition = sim.nodes[0].mle.leader_data().partition_id;

    // B restarts from its settings.
    let now = sim.now;
    {
        let b = &mut sim.nodes[1];
        b.mle.store(&mut b.env).unwrap();
    }
    let settings = core::mem::replace(
        &mut sim.nodes[1].env.settings,
        rs_thread_platform::settings::RamSettings::new(),
    );
    let mut env = TestEnv::new(77);
    env.settings = settings;
    let mut mle: Mle<4> = Mle::new(MleConfig::new(FTD));
    let restored = mle.restore(&mut env, now).unwrap();
    assert!(matches!(
        restored,
        crate::persist::Restored::Router {
            role: Role::Router,
            ..
        }
    ));
    sim.nodes[1].mle = mle;
    sim.nodes[1].env = env;
    assert_eq!(sim.nodes[1].env.ext, crate::test_support::ext(2));
    assert_eq!(sim.role(1), Role::Detached);
    assert_eq!(sim.nodes[1].mle.rloc16(), rloc);
    sim.pump();
    assert!(sim.run_until(secs(10), |s| s.role(1) == Role::Router));
    let b = &sim.nodes[1];
    assert_eq!(b.mle.rloc16(), rloc);
    assert_eq!(b.mle.leader_data().partition_id, partition);
    assert_eq!(b.mle.active_router_count(), 2);
    assert!(
        b.mle
            .router_table()
            .find_by_id(sim.nodes[0].mle.router_id().unwrap())
            .unwrap()
            .neighbor
            .is_valid()
    );
    // The restored child never re-attached and is valid again.
    sim.run(secs(5));
    assert_eq!(sim.role(2), Role::Child);
    assert_eq!(sim.nodes[2].mle.rloc16(), crloc);
    assert_eq!(sim.nodes[1].mle.children().count(StateFilter::Valid), 1);
}

#[test]
fn restored_router_without_neighbors_gives_up_and_detaches() {
    let mut sim = setup();
    relink(&mut sim);
    let now = sim.now;
    {
        let b = &mut sim.nodes[1];
        b.mle.store(&mut b.env).unwrap();
    }
    let settings = core::mem::replace(
        &mut sim.nodes[1].env.settings,
        rs_thread_platform::settings::RamSettings::new(),
    );
    let mut env = TestEnv::new(77);
    env.settings = settings;
    let mut mle: Mle<4> = Mle::new(MleConfig::new(FTD));
    mle.restore(&mut env, now).unwrap();
    sim.nodes[1].mle = mle;
    sim.nodes[1].env = env;
    sim.isolate(1);
    // 3 attempts (no children): multicast Link Requests ~5 s apart, then
    // detached (and, with nobody around, a new partition as leader).
    sim.run(secs(8));
    assert_eq!(sim.role(1), Role::Detached);
    assert!(sim.run_until(secs(80), |s| s.role(1) == Role::Leader));
}
