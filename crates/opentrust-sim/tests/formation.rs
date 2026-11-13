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

/// A node configured with only the credentials a user knows (channel, PAN
/// ID, extended PAN ID, network name, network key: no mesh-local prefix,
/// timestamp, PSKc, channel mask or security policy) attaches, as with
/// OpenThread, and learns the rest of the Active Dataset from its parent.
#[test]
fn attaches_with_a_partial_dataset_and_learns_the_rest() {
    use opentrust_meshcop::tlv::ty as t;

    let mut net = Network::routers(2, 3);
    net.medium.connect(0, 1, -60);
    let full = dataset(&mut net);
    start(&mut net, 0, &full);
    assert!(net.run_until(secs(60), |n| role(n, 0) == Role::Leader));

    let mut partial = full.clone();
    for ty in [
        t::ACTIVE_TIMESTAMP,
        t::MESH_LOCAL_PREFIX,
        t::PSKC,
        t::CHANNEL_MASK,
        t::SECURITY_POLICY,
    ] {
        partial.remove(ty);
    }
    assert!(!partial.contains(t::MESH_LOCAL_PREFIX));
    start(&mut net, 1, &partial);
    assert!(
        net.run_until(secs(180), |n| matches!(
            role(n, 1),
            Role::Child | Role::Router
        )),
        "node 1 role {:?}",
        net.node(1).role()
    );
    assert_eq!(net.node(1).partition_id(), net.node(0).partition_id());
    // The rest of the dataset arrived, including the mesh-local prefix.
    let learned = net.with(1, |n, now| n.active_dataset(now)).unwrap();
    assert!(learned.contains(t::MESH_LOCAL_PREFIX));
    assert!(learned.contains(t::ACTIVE_TIMESTAMP));
    assert!(learned.contains(t::PSKC));
}
