mod common;

use common::*;
use rs_thread_instance::Role;
use rs_thread_sim::{Kind, Network};

fn chain() -> Network {
    router_chain(7)
}

#[test]
fn ping_over_three_hops_with_mesh_header() {
    let mut net = chain();
    let dst = net.node(2).rloc().unwrap();
    assert!(ping(&mut net, 0, dst, 8, 1), "no reply");
    // The frames of the exchange went 0 -> 1 -> 2 and back, never 0 -> 2.
    assert!(
        net.tx_log
            .iter()
            .all(|t| !(t.from == 0 && t.received_by.contains(&2)))
    );
}

#[test]
fn fragmented_ping_over_multiple_hops() {
    let mut net = chain();
    let dst = net.node(2).rloc().unwrap();
    assert!(ping(&mut net, 0, dst, 600, 2), "no reply");
}

#[test]
fn ml_eid_is_resolved_with_an_address_query() {
    let mut net = chain();
    let dst = net.node(2).ml_eid();
    assert!(net.node(0).address_cache().next().is_none());
    assert!(ping(&mut net, 0, dst, 16, 3), "no reply");
    let cached: Vec<_> = net.node(0).address_cache().collect();
    assert!(!cached.is_empty(), "no cache entry after resolution");
}

#[test]
fn sleepy_end_device_attaches_and_polls() {
    let mut net = Network::new(&[Kind::Router, Kind::Sleepy], 11);
    net.medium.connect(0, 1, -60);
    let ds = dataset(&mut net);
    start(&mut net, 0, &ds);
    assert!(net.run_until(secs(60), |n| role(n, 0) == Role::Leader));
    start(&mut net, 1, &ds);
    assert!(
        net.run_until(secs(120), |n| role(n, 1) == Role::Child),
        "sed role {:?}",
        net.node(1).role()
    );
    net.with(1, |n, _| {
        n.set_poll_period(Some(rs_thread_core::time::Duration::from_secs(1)))
    });
    // The leader reaches the sleepy child (indirect, on its polls).
    let dst = net.node(1).ml_eid();
    assert!(ping(&mut net, 0, dst, 20, 4), "sed did not answer");
}

#[test]
fn lossy_links_still_form_a_mesh_and_carry_traffic() {
    let mut net = Network::routers(3, 77);
    net.medium.connect(0, 1, -70);
    net.medium.connect(1, 2, -70);
    for (a, b) in [(0, 1), (1, 0), (1, 2), (2, 1)] {
        net.medium.set_loss(a, b, 0.3);
    }
    let ds = dataset(&mut net);
    start(&mut net, 0, &ds);
    assert!(net.run_until(secs(60), |n| role(n, 0) == Role::Leader));
    for i in 1..3 {
        start(&mut net, i, &ds);
        assert!(
            net.run_until(secs(600), |n| role(n, i) == Role::Router),
            "node {i} role {:?}",
            net.node(i).role()
        );
    }
    let r2 = net.node(2).rloc16();
    assert!(net.run_until(secs(900), |n| {
        n.inst(0).mle().next_hop_and_path_cost(r2).0.is_some()
    }));
    let dst = net.node(2).rloc().unwrap();
    let mut ok = false;
    for seq in 0..5 {
        ok |= ping(&mut net, 0, dst, 40, 100 + seq);
    }
    assert!(ok, "none of five pings over 30% loss links got through");
}

#[test]
fn leader_loss_elects_a_new_leader_and_the_old_one_rejoins() {
    let mut net = chain();
    let old_partition = net.node(0).partition_id();
    net.medium.isolate(0);
    assert!(
        net.run_until(secs(900), |n| (1..3).any(|i| role(n, i) == Role::Leader)),
        "roles {:?}",
        (0..3).map(|i| net.inst(i).role()).collect::<Vec<_>>()
    );
    // Both routers end up in the new partition.
    assert!(net.run_until(secs(600), |n| {
        let p1 = n.inst(1).partition_id();
        p1 != old_partition && p1 == n.inst(2).partition_id()
    }));
    // The old leader reconnects and merges into the partition that won.
    net.medium.connect(0, 1, -60);
    assert!(
        net.run_until(secs(1200), |n| {
            let p = n.inst(1).partition_id();
            n.inst(0).partition_id() == p && n.inst(0).role() != Role::Detached
        }),
        "old leader: {:?} partition {:x} vs {:x}",
        net.inst(0).role(),
        net.inst(0).partition_id(),
        net.inst(1).partition_id()
    );
}

#[test]
fn sleepy_end_device_with_default_poll_period_stays_attached() {
    let mut net = Network::new(&[Kind::Router, Kind::Sleepy], 11);
    net.medium.connect(0, 1, -60);
    let ds = dataset(&mut net);
    start(&mut net, 0, &ds);
    assert!(net.run_until(secs(60), |n| role(n, 0) == Role::Leader));
    start(&mut net, 1, &ds);
    assert!(net.run_until(secs(120), |n| role(n, 1) == Role::Child));
    net.take_events(1);
    // Several child timeouts (default 240 s) without touching the poll period.
    for t in 0..12 {
        net.run_for(secs(100));
        assert_eq!(
            role(&mut net, 1),
            Role::Child,
            "after {} s events {:?}",
            t * 100 + 100,
            net.take_events(1)
        );
    }
    let ev = net.take_events(1);
    assert!(
        !ev.iter()
            .any(|e| matches!(e, rs_thread_instance::Event::RoleChanged { .. })),
        "{ev:?}"
    );
}
