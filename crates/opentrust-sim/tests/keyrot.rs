//! Key rotation: the leader rotates the key every hour, the neighbors follow
//! and the mesh stays connected.

mod common;

use common::*;
use opentrust_instance::{Event, Role, SecurityPolicy};
use opentrust_sim::Network;

#[test]
fn key_rotation_is_followed_by_all_nodes() {
    let mut net = Network::routers(2, 9);
    net.medium.connect(0, 1, -60);
    let mut ds = dataset(&mut net);
    let policy = SecurityPolicy {
        rotation_time: 1,
        ..SecurityPolicy::default()
    };
    ds.set_security_policy(&policy).unwrap();
    start(&mut net, 0, &ds);
    assert!(net.run_until(secs(60), |n| role(n, 0) == Role::Leader));
    start(&mut net, 1, &ds);
    assert!(net.run_until(secs(300), |n| role(n, 1) == Role::Router));
    net.take_events(0);
    net.take_events(1);
    net.run_for(secs(2 * 3600 + 600));
    for i in 0..2 {
        let ev = net.take_events(i);
        assert!(
            ev.iter().any(|e| matches!(e, Event::KeySequenceChanged(_))),
            "node {i} saw no key rotation: {ev:?}"
        );
        let want = if i == 0 { Role::Leader } else { Role::Router };
        assert_eq!(role(&mut net, i), want);
    }
    let dst = net.node(1).ml_eid();
    assert!(ping(&mut net, 0, dst, 20, 1), "no traffic after rotation");
}
