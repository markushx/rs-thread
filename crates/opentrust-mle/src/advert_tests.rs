//! Advertisements: Trickle schedule, content, router neighbor discovery,
//! route cost propagation, Leader Data change detection.

use opentrust_core::time::Duration;

use crate::env::{MleEvent, Role};
use crate::link_quality::LinkQuality;
use crate::message::Command;
use crate::neighbor::StateFilter;
use crate::sim::Sim;

fn secs(s: u64) -> Duration {
    Duration::from_secs(s)
}

fn start_leader(sim: &mut Sim) {
    sim.start(0);
    assert!(sim.run_until(secs(60), |s| s.role(0) == Role::Leader));
}

/// A (0) leader and one more node (1) in range, upgraded to a router.
fn leader_and_router() -> Sim {
    let mut sim = Sim::new(2);
    sim.connect(0, 1, -60);
    start_leader(&mut sim);
    sim.start(1);
    assert!(sim.run_until(secs(30), |s| s.role(1) == Role::Child));
    sim.upgrade(0, 1);
    sim
}

#[test]
fn advertisement_trickle_backs_off_and_resets_on_changes() {
    let mut sim = Sim::new(2);
    sim.connect(0, 1, -60);
    start_leader(&mut sim);
    sim.start(1);
    assert!(sim.run_until(secs(30), |s| s.role(1) == Role::Child));
    // Count the leader's multicast Advertisements (received by node 1).
    let base = sim.nodes[1].count_rx(Command::Advertisement);
    sim.run(secs(300));
    let steady = sim.nodes[1].count_rx(Command::Advertisement) - base;
    // Imax is 12..32 s: between 300/32 and 300/12 + slack.
    assert!(
        (8..=30).contains(&steady),
        "{steady} advertisements in 300 s"
    );
    // Imax follows the number of router neighbors; with none it is 12 s.
    assert_eq!(sim.nodes[0].mle.advertise_interval_max(), secs(12));
    // A router ID change restarts the timer at Imin = 1 s: several
    // Advertisements within a few seconds.
    sim.upgrade(0, 1);
    let before = sim.nodes[1].count_rx(Command::Advertisement)
        + sim.nodes[0].count_rx(Command::Advertisement);
    sim.run(secs(6));
    let after = sim.nodes[1].count_rx(Command::Advertisement)
        + sim.nodes[0].count_rx(Command::Advertisement);
    assert!(
        after - before >= 3,
        "{} advertisements after the change",
        after - before
    );
}

#[test]
fn router_and_leader_become_neighbors_and_exchange_routes() {
    let mut sim = leader_and_router();
    sim.run(secs(60));
    let (a, b) = (
        sim.nodes[0].mle.router_id().unwrap(),
        sim.nodes[1].mle.router_id().unwrap(),
    );
    // The former child is a router neighbor on both sides.
    let ra = sim.nodes[1].mle.router_table().find_by_id(a).unwrap();
    let rb = sim.nodes[0].mle.router_table().find_by_id(b).unwrap();
    assert!(ra.neighbor.is_valid() && rb.neighbor.is_valid());
    assert_eq!(rb.neighbor.link_info.link_quality_out(), LinkQuality::Q3);
    assert_eq!(ra.neighbor.link_info.link_quality_out(), LinkQuality::Q3);
    assert_eq!(sim.nodes[0].mle.children().count(StateFilter::Valid), 0);
    // Both ends agree on the router ID set and sequence.
    assert_eq!(
        sim.nodes[0].mle.router_id_mask(),
        sim.nodes[1].mle.router_id_mask()
    );
    assert_eq!(sim.nodes[1].mle.path_cost_to_leader(), 1);
    assert_eq!(sim.nodes[0].mle.path_cost(sim.nodes[1].mle.rloc16()), 1);
    // Connectivity as sent in Parent Responses.
    let conn = sim.nodes[0].mle.fill_connectivity();
    assert_eq!(conn.active_routers, 2);
    assert_eq!(conn.leader_cost, 0);
    assert_eq!(conn.link_quality_3, 1);
}

#[test]
fn two_routers_find_each_other_through_advertisements() {
    // B and C hear A and each other; both join as routers.
    let mut sim = Sim::new(3);
    sim.connect(0, 1, -60);
    sim.connect(0, 2, -60);
    sim.connect(1, 2, -60);
    start_leader(&mut sim);
    sim.start(1);
    assert!(sim.run_until(secs(30), |s| s.role(1) == Role::Child));
    sim.upgrade(0, 1);
    sim.start(2);
    assert!(sim.run_until(secs(30), |s| s.role(2) == Role::Child));
    sim.upgrade(0, 2);
    assert!(
        sim.run_until(secs(120), |s| {
            s.nodes
                .iter()
                .all(|n| n.mle.router_table().count(StateFilter::Valid) == 2)
        }),
        "all three routers should be pairwise neighbors"
    );
    // The B-C link was set up with a Link Request / Accept exchange.
    let total = |c: Command| sim.nodes.iter().map(|n| n.count_rx(c)).sum::<u32>();
    assert!(total(Command::LinkRequest) >= 1);
    assert!(total(Command::LinkAcceptAndRequest) >= 1);
    for n in &sim.nodes {
        assert_eq!(n.mle.active_router_count(), 3);
        assert_eq!(n.mle.router_id_mask(), sim.nodes[0].mle.router_id_mask());
    }
}

#[test]
fn weak_advertisements_do_not_start_a_link() {
    let mut sim = Sim::new(3);
    sim.connect(0, 1, -60);
    sim.connect(0, 2, -60);
    // B and C hear each other at the edge: margin 5 dB < 10 dB.
    sim.connect(1, 2, -95);
    start_leader(&mut sim);
    for i in [1, 2] {
        sim.start(i);
        assert!(sim.run_until(secs(30), |s| s.role(i) == Role::Child));
        sim.upgrade(0, i);
    }
    sim.run(secs(120));
    let c = sim.nodes[2].mle.router_id().unwrap();
    let b = sim.nodes[1].mle.router_id().unwrap();
    assert!(
        !sim.nodes[1]
            .mle
            .router_table()
            .find_by_id(c)
            .unwrap()
            .neighbor
            .is_valid()
    );
    assert!(
        !sim.nodes[2]
            .mle
            .router_table()
            .find_by_id(b)
            .unwrap()
            .neighbor
            .is_valid()
    );
}

#[test]
fn route_cost_over_two_hops() {
    // A - B - C in a line; C is a child of B first, then a router.
    let mut sim = Sim::new(3);
    sim.connect(0, 1, -60);
    sim.connect(1, 2, -60);
    start_leader(&mut sim);
    sim.start(1);
    assert!(sim.run_until(secs(30), |s| s.role(1) == Role::Child));
    sim.upgrade(0, 1);
    sim.start(2);
    assert!(sim.run_until(secs(30), |s| s.role(2) == Role::Child));
    sim.upgrade(0, 2);
    sim.run(secs(120));
    let (arloc, brloc, crloc) = (
        sim.nodes[0].mle.rloc16(),
        sim.nodes[1].mle.rloc16(),
        sim.nodes[2].mle.rloc16(),
    );
    assert_eq!(sim.nodes[0].mle.path_cost(brloc), 1);
    assert_eq!(sim.nodes[0].mle.path_cost(crloc), 2);
    assert_eq!(
        sim.nodes[0].mle.next_hop_and_path_cost(crloc),
        (Some(brloc), 2)
    );
    assert_eq!(sim.nodes[2].mle.path_cost(arloc), 2);
    assert_eq!(
        sim.nodes[2].mle.next_hop_and_path_cost(arloc),
        (Some(brloc), 2)
    );
    assert_eq!(sim.nodes[1].mle.path_cost(arloc), 1);
    assert_eq!(sim.nodes[1].mle.path_cost(crloc), 1);
    // The leader cost in Connectivity reflects the path.
    assert_eq!(sim.nodes[2].mle.fill_connectivity().leader_cost, 2);
    // Route64 sent by C has a route of cost 2 to A and 1 to B.
    let (_, mask, entries) = sim.nodes[2].mle.fill_route64(None);
    let ids: heapless::Vec<u8, 4> = mask.iter().collect();
    assert_eq!(ids.len(), 3);
    let cost_of = |rloc: opentrust_core::types::Rloc16| {
        let i = mask.index_of(rloc.router_id()).unwrap();
        entries[i].cost
    };
    assert_eq!(cost_of(arloc), 2);
    assert_eq!(cost_of(brloc), 1);
    assert_eq!(cost_of(crloc), 1, "own entry: cost 1, link quality 0");
    // Losing B (silent) makes the path to A infinite after the link ages out.
    sim.isolate(1);
    sim.run(secs(400));
    assert_eq!(sim.nodes[0].mle.path_cost(crloc), 16);
    assert!(sim.nodes[0].env.has_event(MleEvent::RouterRemoved {
        ext: sim.nodes[1].env.ext,
        rloc16: brloc
    }));
}

#[test]
fn child_follows_leader_data_changes_announced_by_its_parent() {
    let mut sim = Sim::new(2);
    sim.connect(0, 1, -60);
    start_leader(&mut sim);
    sim.start(1);
    assert!(sim.run_until(secs(30), |s| s.role(1) == Role::Child));
    sim.run(secs(60));
    // The leader publishes new Network Data (opentrust-mesh does this via TMF).
    let mut ld = *sim.nodes[0].mle.leader_data();
    ld.data_version = ld.data_version.wrapping_add(1);
    ld.stable_data_version = ld.stable_data_version.wrapping_add(1);
    sim.nodes[0].env.provided_nd =
        heapless::Vec::from_slice(&[0x08, 0x04, 0x01, 0x02, 0x03, 0x04]).unwrap();
    sim.nodes[0].mle.set_leader_data(ld);
    {
        let now = sim.now;
        let a = &mut sim.nodes[0];
        a.mle.reset_advertise_interval(&mut a.env, now);
    }
    assert!(
        sim.run_until(secs(40), |s| s.nodes[1].mle.leader_data().data_version
            == ld.data_version)
    );
    assert_eq!(sim.nodes[1].env.nd_leader, Some(ld));
    assert_eq!(
        &sim.nodes[1].env.nd[..],
        &[0x08, 0x04, 0x01, 0x02, 0x03, 0x04]
    );
}

#[test]
fn reed_advertises_on_a_slow_plain_timer() {
    let mut sim = Sim::new(2);
    sim.connect(0, 1, -60);
    start_leader(&mut sim);
    sim.start(1);
    assert!(sim.run_until(secs(30), |s| s.role(1) == Role::Child));
    // Make the router upgrade impossible so the node stays a REED.
    sim.nodes[1].env.solicit_fails = true;
    let before = sim.nodes[0].count_rx(Command::Advertisement);
    sim.run(secs(200));
    // The REED sent its first Advertisement when its transition delay ended
    // (at most 121 s) and none since (plain timer 570..630 s).
    let got = sim.nodes[0].count_rx(Command::Advertisement) - before;
    assert_eq!(got, 1);
    assert!(sim.nodes[1].mle.rtr.advert.is_running());
    let interval = sim.nodes[1].mle.rtr.advert.interval().unwrap();
    assert!(interval >= secs(570) && interval <= secs(630));
}
