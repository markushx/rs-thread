#![allow(dead_code)]

use rs_thread_core::time::Duration;
use rs_thread_instance::{Dataset, Role};
use rs_thread_sim::Network;

pub fn secs(s: u64) -> Duration {
    Duration::from_secs(s)
}

/// A dataset made by node 0.
pub fn dataset(net: &mut Network) -> Dataset {
    net.node(0).create_dataset(15).unwrap()
}

/// Bring node `i` up with `ds` and start Thread.
pub fn start(net: &mut Network, i: usize, ds: &Dataset) {
    net.with(i, |n, now| {
        n.set_active_dataset(ds, now).unwrap();
        n.ip6_set_enabled(true);
        n.thread_start(now).unwrap();
    });
}

pub fn role(net: &mut Network, i: usize) -> Role {
    net.node(i).role()
}

/// Leader 0 - router 1 - router 2 (no link 0 - 2), all attached as
/// routers with converged routes.
pub fn router_chain(seed: u64) -> Network {
    let mut net = Network::routers(3, seed);
    net.medium.connect(0, 1, -60);
    net.medium.connect(1, 2, -60);
    let ds = dataset(&mut net);
    start(&mut net, 0, &ds);
    assert!(net.run_until(secs(60), |n| role(n, 0) == Role::Leader));
    for i in 1..3 {
        start(&mut net, i, &ds);
        assert!(
            net.run_until(secs(120), |n| role(n, i) == Role::Child),
            "node {i} role {:?}",
            net.node(i).role()
        );
        assert!(
            net.run_until(secs(300), |n| role(n, i) == Role::Router),
            "node {i} role {:?}",
            net.node(i).role()
        );
    }
    let r2 = net.node(2).rloc16();
    let r0 = net.node(0).rloc16();
    assert!(net.run_until(secs(600), |n| {
        n.node(0).mle().next_hop_and_path_cost(r2).0.is_some()
            && n.node(2).mle().next_hop_and_path_cost(r0).0.is_some()
    }));
    net
}

/// Ping `dst` from node `from` and wait for the reply.
#[cfg(feature = "ping")]
pub fn ping(
    net: &mut Network,
    from: usize,
    dst: core::net::Ipv6Addr,
    len: usize,
    seq: u16,
) -> bool {
    let payload = vec![0x5a; len];
    net.with(from, |n, now| {
        n.ping(dst, None, 0x1234, seq, &payload, now).unwrap();
    });
    net.run_until(secs(30), |n| {
        n.node(from)
            .take_ping_reply()
            .is_some_and(|r| r.seq == seq && r.payload_len == len)
    })
}
