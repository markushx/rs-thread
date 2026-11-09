#![allow(dead_code)]

use opentrust_core::time::Duration;
use opentrust_instance::{Dataset, Role};
use opentrust_sim::Network;

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
