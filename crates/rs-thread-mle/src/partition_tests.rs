//! Partitions: comparison, leader loss, merging, previous-partition
//! avoidance.

use rs_thread_core::time::Duration;

use crate::advert::compare_partitions;
use crate::attach::AttachMode;
use crate::env::{MleEvent, Role};
use crate::sim::Sim;
use crate::test_support::TestEnv;
use crate::tlv::LeaderData;

fn secs(s: u64) -> Duration {
    Duration::from_secs(s)
}

fn ld(weight: u8, id: u32) -> LeaderData {
    LeaderData {
        partition_id: id,
        weighting: weight,
        data_version: 1,
        stable_data_version: 1,
        leader_router_id: 0,
    }
}

#[test]
fn partition_comparison_order() {
    // Weight first.
    assert!(compare_partitions(true, &ld(65, 1), false, &ld(64, 9)) > 0);
    assert!(compare_partitions(false, &ld(63, 9), true, &ld(64, 1)) < 0);
    // Then: not being a singleton is better.
    assert!(compare_partitions(false, &ld(64, 1), true, &ld(64, 9)) > 0);
    assert!(compare_partitions(true, &ld(64, 9), false, &ld(64, 1)) < 0);
    // Then the partition ID.
    assert!(compare_partitions(true, &ld(64, 9), true, &ld(64, 1)) > 0);
    assert!(compare_partitions(false, &ld(64, 1), false, &ld(64, 9)) < 0);
    assert_eq!(compare_partitions(false, &ld(64, 5), false, &ld(64, 5)), 0);
}

fn two_leaders(rss: i8, weight_a: u8) -> Sim {
    let mut sim = Sim::new(2);
    sim.nodes[0].mle.cfg.router.leader_weight = weight_a;
    for i in 0..2 {
        sim.start(i);
        assert!(sim.run_until(secs(60), |s| s.role(i) == Role::Leader));
    }
    assert_ne!(
        sim.nodes[0].mle.leader_data().partition_id,
        sim.nodes[1].mle.leader_data().partition_id
    );
    sim.connect(0, 1, rss);
    sim
}

#[test]
fn two_partitions_merge_the_worse_one_reattaches() {
    let mut sim = two_leaders(-60, 64);
    let (pa, pd) = (
        sim.nodes[0].mle.leader_data().partition_id,
        sim.nodes[1].mle.leader_data().partition_id,
    );
    let (win, lose) = if pa > pd { (0, 1) } else { (1, 0) };
    let (pwin, plose) = (pa.max(pd), pa.min(pd));
    assert!(
        sim.run_until(secs(300), |s| {
            s.nodes[lose].mle.leader_data().partition_id == pwin && s.role(lose) == Role::Child
        }),
        "the worse partition should join the better one"
    );
    assert_eq!(sim.role(win), Role::Leader);
    assert_eq!(sim.nodes[win].mle.leader_data().partition_id, pwin);
    assert_eq!(
        sim.nodes[lose].mle.leader_data(),
        sim.nodes[win].mle.leader_data()
    );
    // The loser remembers where it came from and learned the winner's routers.
    assert_eq!(sim.nodes[lose].mle.previous_partition_id(), plose);
    assert!(
        sim.nodes[lose]
            .env
            .has_event(MleEvent::PartitionChanged { partition_id: pwin })
    );
    assert_eq!(sim.nodes[lose].mle.active_router_count(), 1);
    assert_eq!(
        sim.nodes[lose].mle.router_id_mask(),
        sim.nodes[win].mle.router_id_mask()
    );
    assert_eq!(
        sim.nodes[win]
            .mle
            .children()
            .count(crate::neighbor::StateFilter::Valid),
        1
    );
    // Later the loser (a REED) asks for a router ID and joins as router.
    assert!(
        sim.run_until(secs(200), |s| !s.nodes[lose].env.solicits.is_empty()),
        "REED asks for a router ID"
    );
    sim.grant_router(win, lose);
    assert_eq!(sim.role(lose), Role::Router);
    sim.run(secs(60));
    assert_eq!(sim.nodes[win].mle.active_router_count(), 2);
}

#[test]
fn heavier_partition_wins_whatever_its_id() {
    let mut sim = two_leaders(-60, 90);
    assert!(sim.run_until(secs(300), |s| s.role(1) == Role::Child));
    assert_eq!(sim.role(0), Role::Leader);
    assert_eq!(sim.nodes[0].mle.leader_data().weighting, 90);
    assert_eq!(
        sim.nodes[1].mle.leader_data().partition_id,
        sim.nodes[0].mle.leader_data().partition_id
    );
}

#[test]
fn weak_link_does_not_merge_partitions() {
    // 5 dB margin < PARTITION_MERGE_MIN_MARGIN.
    let mut sim = two_leaders(-95, 64);
    sim.run(secs(400));
    assert_eq!(sim.role(0), Role::Leader);
    assert_eq!(sim.role(1), Role::Leader);
    assert_ne!(
        sim.nodes[0].mle.leader_data().partition_id,
        sim.nodes[1].mle.leader_data().partition_id
    );
}

#[test]
fn leader_loss_makes_a_router_start_a_new_partition() {
    let mut sim = Sim::new(2);
    sim.connect(0, 1, -60);
    sim.start(0);
    assert!(sim.run_until(secs(60), |s| s.role(0) == Role::Leader));
    sim.start(1);
    assert!(sim.run_until(secs(30), |s| s.role(1) == Role::Child));
    sim.upgrade(0, 1);
    sim.run(secs(60));
    let old = sim.nodes[1].mle.leader_data().partition_id;
    assert_eq!(
        sim.nodes[1].mle.leader_age(sim.now).map(|a| a < secs(15)),
        Some(true)
    );
    // The leader disappears.
    sim.isolate(0);
    // Not yet: NETWORK_ID_TIMEOUT is 120 s.
    sim.run(secs(100));
    assert_eq!(sim.role(1), Role::Router);
    assert_eq!(sim.nodes[1].mle.leader_data().partition_id, old);
    // After the timeout the router first looks for its partition (same
    // partition attach) and then starts a new one.
    assert!(sim.run_until(secs(60), |s| s.nodes[1].mle.is_attaching()));
    assert_eq!(sim.nodes[1].mle.attach.mode, AttachMode::SamePartition);
    assert!(
        sim.run_until(secs(60), |s| s.role(1) == Role::Leader
            && s.nodes[1].mle.leader_data().partition_id != old),
        "router should become leader of a new partition"
    );
    let n = &sim.nodes[1];
    assert_eq!(n.mle.previous_partition_id(), old);
    assert_eq!(n.mle.leader_data().weighting, 64);
    assert_eq!(
        n.mle.router_id(),
        n.mle.leader_data().leader_router_id.into()
    );
    assert_eq!(n.mle.active_router_count(), 1);
    // The old leader (alone, still leader of the old partition) and the new
    // leader meet again: the old partition has the same weight and is also a
    // singleton, so the partition ID decides; one of the two gives in.
    sim.connect(0, 1, -60);
    assert!(sim.run_until(secs(400), |s| {
        s.nodes[0].mle.leader_data().partition_id == s.nodes[1].mle.leader_data().partition_id
    }));
    let leaders = sim
        .nodes
        .iter()
        .filter(|n| n.mle.role() == Role::Leader)
        .count();
    assert_eq!(leaders, 1);
}

#[test]
fn advertisements_of_the_previous_partition_are_ignored_for_a_while() {
    // A (leader) and D (leader of another partition) are in range of each
    // other but have not merged: build the Advertisement of D by hand.
    let mut sim = Sim::new(2);
    sim.nodes[1].mle.cfg.router.leader_weight = 70; // D is the better one
    for i in 0..2 {
        sim.start(i);
        assert!(sim.run_until(secs(60), |s| s.role(i) == Role::Leader));
    }
    let now = sim.now;
    let d_partition = sim.nodes[1].mle.leader_data().partition_id;
    let d_sequence = sim.nodes[1].mle.router_id_sequence();
    let adv = {
        let d = &mut sim.nodes[1];
        let dst = rs_thread_core::types::ipv6::LINK_LOCAL_ALL_NODES;
        d.mle.send_advertisement(&mut d.env, now, dst).unwrap();
        d.env.take_out().pop().unwrap()
    };
    // A "was in" D's partition a moment ago and remembers D's sequence.
    {
        let a = &mut sim.nodes[0];
        a.mle.previous_partition_id = d_partition;
        a.mle.rtr.previous_partition_timeout = 100;
        a.mle.rtr.previous_partition_id_sequence = d_sequence;
    }
    // The sequence in D's Advertisement is not newer: ignored.
    let a = &mut sim.nodes[0];
    assert!(TestEnv::deliver(&adv, &mut a.mle, &mut a.env, now, -60).is_err());
    assert!(!a.mle.is_attaching());
    // A newer one is believed: A goes for the better partition.
    a.mle.rtr.previous_partition_id_sequence = d_sequence.wrapping_sub(1);
    let _ = TestEnv::deliver(&adv, &mut a.mle, &mut a.env, now, -60);
    assert!(a.mle.is_attaching());
    assert_eq!(a.mle.attach.mode, AttachMode::BetterPartition);
    // After the timeout the old partition no longer matters.
    let mut sim2 = Sim::new(1);
    sim2.start(0);
    assert!(sim2.run_until(secs(60), |s| s.role(0) == Role::Leader));
    let n = &mut sim2.nodes[0];
    n.mle.previous_partition_id = d_partition;
    n.mle.rtr.previous_partition_timeout = 2;
    sim2.run(secs(3));
    assert_eq!(sim2.nodes[0].mle.rtr.previous_partition_timeout, 0);
}

#[test]
fn network_key_change_resets_neighbor_frame_counters() {
    // OT `KeyManager::ResetFrameCounters`: after a network key change the
    // peers count from 0 again, so the parent's, routers' and children's
    // incoming key sequence and counters are forgotten.
    let mut sim = Sim::new(2);
    sim.connect(0, 1, -60);
    sim.start(0);
    assert!(sim.run_until(secs(60), |s| s.role(0) == Role::Leader));
    sim.start(1);
    assert!(sim.run_until(secs(30), |s| s.role(1) == Role::Child));
    sim.run(secs(30));
    {
        let n = sim.nodes[1].mle.neighbor_mut(crate::mle::NbRef::Parent);
        n.link_counters.set(3, 100);
        n.mle_replay = crate::neighbor::MleReplay::with(50);
        assert_ne!(
            n.link_counters,
            rs_thread_mac::security::LinkFrameCounters::new()
        );
    }
    sim.nodes[0].mle.reset_frame_counters();
    sim.nodes[1].mle.reset_frame_counters();
    let after = &sim.nodes[1].mle.parent().unwrap().router.neighbor;
    assert_eq!(
        after.link_counters,
        rs_thread_mac::security::LinkFrameCounters::new()
    );
    assert_eq!(after.mle_replay.frame_counter(), Some(0));
    let child_of_leader = sim.nodes[0]
        .mle
        .children()
        .iter(crate::neighbor::StateFilter::Valid)
        .next()
        .unwrap();
    assert_eq!(child_of_leader.neighbor.mle_replay.frame_counter(), Some(0));
}
