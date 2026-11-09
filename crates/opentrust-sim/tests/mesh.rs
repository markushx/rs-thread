mod common;

use common::*;
use opentrust_instance::Role;
use opentrust_sim::{Kind, Network};

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
        n.set_poll_period(Some(opentrust_core::time::Duration::from_secs(1)))
    });
    // The leader reaches the sleepy child (indirect, on its polls).
    let dst = net.node(1).ml_eid();
    assert!(ping(&mut net, 0, dst, 20, 4), "sed did not answer");
}
