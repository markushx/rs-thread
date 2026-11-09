mod common;

use common::*;
use opentrust_instance::Role;
use opentrust_sim::Network;

#[test]
fn leader_forms_from_a_dataset() {
    let mut net = Network::routers(1, 1);
    let ds = dataset(&mut net);
    start(&mut net, 0, &ds);
    assert!(
        net.run_until(secs(60), |n| role(n, 0) == Role::Leader),
        "role {:?}",
        net.node(0).role()
    );
    let n = net.node(0);
    assert_ne!(n.rloc16().0, 0xfffe);
    assert!(n.rloc().is_some());
}

#[test]
fn second_node_attaches_as_child_then_becomes_router() {
    let mut net = Network::routers(2, 2);
    net.medium.connect(0, 1, -60);
    let ds = dataset(&mut net);
    start(&mut net, 0, &ds);
    assert!(net.run_until(secs(60), |n| role(n, 0) == Role::Leader));
    start(&mut net, 1, &ds);
    assert!(
        net.run_until(secs(120), |n| role(n, 1) == Role::Child),
        "node 1 role {:?}",
        net.node(1).role()
    );
    assert_eq!(net.node(1).partition_id(), net.node(0).partition_id());
    assert!(
        net.run_until(secs(300), |n| role(n, 1) == Role::Router),
        "node 1 role {:?}",
        net.node(1).role()
    );
}
