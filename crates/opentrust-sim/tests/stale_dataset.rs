mod common;

use common::*;
use opentrust_core::types::{Prefix64, Pskc};
use opentrust_instance::{Dataset, Role};
use opentrust_sim::{Kind, Network};

/// The dataset of a restarted border router that ran `dataset init new`
/// again: same key, channel, PAN ID, ext PAN ID and timestamp, but a new
/// mesh-local prefix and PSKc.
fn renewed(ds: &Dataset) -> Dataset {
    let mut d = ds.clone();
    d.set_mesh_local_prefix(&Prefix64([0xfd, 0x51, 0xc0, 0x17, 0xfa, 0x9d, 0, 0]))
        .unwrap();
    d.set_pskc(&Pskc([0x77; 16])).unwrap();
    d
}

/// Node 0 leads dataset A with node 1 attached (as `kind`); then the whole
/// network goes down, node 2 starts as leader of A' on the same channel and
/// node 1 reboots with its stored network information.
fn run(kind: Kind, want_router_first: bool) -> Network {
    let mut net = Network::new(&[Kind::Router, kind, Kind::Router], 7);
    net.medium.connect(0, 1, -60);
    net.medium.connect(1, 2, -60);
    let a = dataset(&mut net);
    start(&mut net, 0, &a);
    assert!(net.run_until(secs(60), |n| role(n, 0) == Role::Leader));
    start(&mut net, 1, &a);
    assert!(net.run_until(secs(120), |n| role(n, 1) == Role::Child));
    if want_router_first {
        assert!(net.run_until(secs(300), |n| role(n, 1) == Role::Router));
    }
    net.run_for(secs(60));
    net.with(0, |n, _| n.thread_stop());
    net.with(1, |n, _| n.thread_stop());
    net.reset_node(1);
    let b = renewed(&a);
    start(&mut net, 2, &b);
    assert!(net.run_until(secs(60), |n| role(n, 2) == Role::Leader));
    net.with(1, |n, now| {
        n.ip6_set_enabled(true);
        n.thread_start(now).unwrap();
    });
    net
}

#[test]
fn restored_child_attaches_to_leader_with_renewed_dataset() {
    let mut net = run(Kind::EndDevice, false);
    assert!(
        net.run_until(secs(60), |n| role(n, 1) == Role::Child),
        "role {:?}",
        net.node(1).role()
    );
    assert_eq!(net.node(1).partition_id(), net.node(2).partition_id());
}

#[test]
fn restored_router_attaches_to_leader_with_renewed_dataset() {
    let mut net = run(Kind::Router, true);
    assert!(
        net.run_until(secs(60), |n| matches!(
            role(n, 1),
            Role::Child | Role::Router
        )),
        "role {:?}",
        net.node(1).role()
    );
    assert_eq!(net.node(1).partition_id(), net.node(2).partition_id());
}
