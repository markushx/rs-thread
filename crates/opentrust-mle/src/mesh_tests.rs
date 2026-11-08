//! End-to-end scenarios of several cores with fake environments and
//! deterministic time: leader start, attach, router upgrade (the Address
//! Solicit exchange stubbed by the test), router links, Advertisements,
//! route costs, leader loss, restart.

use opentrust_core::time::Duration;

use crate::env::{MleEvent, Role};
use crate::message::Command;
use crate::mle::{Mle, MleConfig};
use crate::neighbor::StateFilter;
use crate::sim::{FTD, Sim};
use crate::test_support::TestEnv;

fn secs(s: u64) -> Duration {
    Duration::from_secs(s)
}

#[test]
fn leader_child_router_lifecycle() {
    // A, B and C all hear each other.
    let mut sim = Sim::new(3);
    for (a, b) in [(0, 1), (0, 2), (1, 2)] {
        sim.connect(a, b, -60);
    }

    // A starts alone and becomes the leader.
    sim.start(0);
    assert!(sim.run_until(secs(60), |s| s.role(0) == Role::Leader));
    let partition = sim.nodes[0].mle.leader_data().partition_id;

    // B attaches as a child (a REED: it is a full thread device).
    sim.start(1);
    assert!(sim.run_until(secs(30), |s| s.role(1) == Role::Child));
    assert_eq!(sim.nodes[1].mle.leader_data().partition_id, partition);
    assert_eq!(
        sim.nodes[1].mle.parent().unwrap().router.neighbor.rloc16,
        sim.nodes[0].mle.rloc16()
    );

    // C too; both ask for a router ID after their selection jitter, the
    // test plays the leader's TMF handler.
    sim.start(2);
    assert!(sim.run_until(secs(30), |s| s.role(2) == Role::Child));
    sim.upgrade(0, 1);
    sim.upgrade(0, 2);
    assert_eq!(sim.nodes[0].mle.active_router_count(), 3);

    // Link Requests / Accepts and Advertisements make them neighbors.
    assert!(sim.run_until(secs(120), |s| {
        s.nodes
            .iter()
            .all(|n| n.mle.router_table().count(StateFilter::Valid) == 2)
    }));
    for n in &sim.nodes {
        assert!(n.count_rx(Command::Advertisement) >= 2);
        assert_eq!(n.mle.router_id_mask(), sim.nodes[0].mle.router_id_mask());
        assert_eq!(n.mle.leader_data().partition_id, partition);
    }
    let total = |c: Command| sim.nodes.iter().map(|n| n.count_rx(c)).sum::<u32>();
    assert!(total(Command::LinkRequest) >= 1);
    assert!(total(Command::LinkAccept) >= 1);

    // Route costs: every router reaches every other one over one hop (the
    // outgoing link quality arrives with the neighbor's next Route64).
    let converged = |s: &Sim| {
        (0..3).all(|i| {
            (0..3).all(|j| s.nodes[i].mle.path_cost(s.nodes[j].mle.rloc16()) == u8::from(i != j))
        })
    };
    assert!(sim.run_until(secs(120), converged));
    assert_eq!(sim.nodes[1].mle.fill_connectivity().leader_cost, 1);

    // The leader disappears: both routers notice after NETWORK_ID_TIMEOUT
    // and end up in one new partition with exactly one leader.
    sim.isolate(0);
    assert!(sim.run_until(secs(600), |s| {
        let (b, c) = (&s.nodes[1].mle, &s.nodes[2].mle);
        b.leader_data().partition_id != partition
            && b.leader_data().partition_id == c.leader_data().partition_id
            && (s.role(1) == Role::Leader) != (s.role(2) == Role::Leader)
    }));
    let new_partition = sim.nodes[1].mle.leader_data().partition_id;
    for i in [1, 2] {
        assert!(sim.nodes[i].env.has_event(MleEvent::PartitionChanged {
            partition_id: new_partition
        }));
    }
    // The lone old leader still believes in its old partition.
    assert_eq!(sim.role(0), Role::Leader);
    assert_eq!(sim.nodes[0].mle.leader_data().partition_id, partition);
}

#[test]
fn leader_restart_resumes_the_partition_with_the_help_of_a_router() {
    let mut sim = Sim::new(2);
    sim.connect(0, 1, -60);
    sim.start(0);
    assert!(sim.run_until(secs(60), |s| s.role(0) == Role::Leader));
    sim.start(1);
    assert!(sim.run_until(secs(30), |s| s.role(1) == Role::Child));
    sim.upgrade(0, 1);
    sim.run(secs(60));
    let ld = *sim.nodes[0].mle.leader_data();
    let rloc = sim.nodes[0].mle.rloc16();

    // The leader restarts from its settings.
    let now = sim.now;
    {
        let a = &mut sim.nodes[0];
        a.mle.store(&mut a.env).unwrap();
    }
    let settings = core::mem::replace(
        &mut sim.nodes[0].env.settings,
        opentrust_platform::settings::RamSettings::new(),
    );
    let mut env = TestEnv::new(99);
    env.settings = settings;
    let mut mle: Mle<4> = Mle::new(MleConfig::new(FTD));
    mle.restore(&mut env, now).unwrap();
    sim.nodes[0].mle = mle;
    sim.nodes[0].env = env;
    assert!(sim.run_until(secs(20), |s| s.role(0) == Role::Leader));
    let a = &sim.nodes[0];
    assert_eq!(a.mle.rloc16(), rloc);
    assert_eq!(a.mle.leader_data().partition_id, ld.partition_id);
    assert_eq!(a.mle.leader_data().leader_router_id, ld.leader_router_id);
    assert_eq!(a.mle.active_router_count(), 2);
    // Both sides keep working: the router still follows the same leader.
    sim.run(secs(200));
    assert_eq!(sim.role(1), Role::Router);
    assert_eq!(sim.nodes[1].mle.leader_data().partition_id, ld.partition_id);
    assert_eq!(sim.nodes[1].mle.router_table().count(StateFilter::Valid), 1);
}

#[test]
fn line_of_four_routers_has_hop_count_costs() {
    // 0 - 1 - 2 - 3, each router joins through its predecessor.
    let mut sim = Sim::new(4);
    for i in 0..3 {
        sim.connect(i, i + 1, -60);
    }
    sim.start(0);
    assert!(sim.run_until(secs(60), |s| s.role(0) == Role::Leader));
    for i in 1..4 {
        sim.start(i);
        assert!(sim.run_until(secs(60), |s| s.role(i) == Role::Child));
        sim.upgrade(0, i);
        sim.run(secs(60));
    }
    sim.run(secs(300));
    for i in 0..4 {
        for j in 0..4 {
            let cost = sim.nodes[i].mle.path_cost(sim.nodes[j].mle.rloc16());
            assert_eq!(cost as usize, i.abs_diff(j), "{i} -> {j}");
        }
    }
    // The far end sees the leader three hops away.
    assert_eq!(sim.nodes[3].mle.fill_connectivity().leader_cost, 3);
    assert_eq!(sim.nodes[3].mle.active_router_count(), 4);
}

#[test]
fn graceful_detach_of_a_router_releases_its_id() {
    let mut sim = Sim::new(2);
    sim.connect(0, 1, -60);
    sim.start(0);
    assert!(sim.run_until(secs(60), |s| s.role(0) == Role::Leader));
    sim.start(1);
    assert!(sim.run_until(secs(30), |s| s.role(1) == Role::Child));
    sim.upgrade(0, 1);
    let rloc = sim.nodes[1].mle.rloc16();
    let now = sim.now;
    let n = &mut sim.nodes[1];
    n.mle.detach_gracefully(&mut n.env, now).unwrap();
    assert_eq!(n.env.released.as_slice(), &[rloc]);
    sim.run(Duration::from_millis(1100));
    assert_eq!(sim.role(1), Role::Disabled);
    assert!(sim.nodes[1].env.has_event(MleEvent::DetachedGracefully));
}
