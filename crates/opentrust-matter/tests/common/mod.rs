//! Shared helpers of the opentrust-matter tests: a two-node Thread network in
//! virtual time (`opentrust_sim::testing`).
#![allow(dead_code, unused_imports)]

pub use opentrust_sim::testing::*;

use core::cell::Cell;

use opentrust_core::time::Duration;
use opentrust_instance::{Dataset, Role};
use opentrust_platform::time::MockClock;

pub fn limit() -> Duration {
    Duration::from_secs(1200)
}

pub fn make_dataset(ot: Ot<'_, '_>) -> Dataset {
    ot.with(|i, _| i.create_dataset(15).unwrap())
}

pub fn start_with(ot: Ot<'_, '_>, ds: &Dataset, leader: bool) {
    ot.set_active_dataset(ds).unwrap();
    if leader {
        ot.become_leader().unwrap();
    } else {
        ot.thread_start().unwrap();
    }
}

pub async fn wait_role(ot: Ot<'_, '_>, role: Role) {
    loop {
        let g = ot.generation();
        if ot.role() == role {
            return;
        }
        ot.wait_changed_after(g).await;
    }
}

pub async fn wait_attached(ot: Ot<'_, '_>) {
    loop {
        let g = ot.generation();
        if matches!(ot.role(), Role::Child | Role::Router | Role::Leader) {
            return;
        }
        ot.wait_changed_after(g).await;
    }
}

/// Bring up a leader (node 0) and attach node 1 to it.
pub async fn form_network(ots: &[Ot<'_, '_>; 2], ds: &Dataset) {
    start_with(ots[0], ds, true);
    wait_role(ots[0], Role::Leader).await;
    start_with(ots[1], ds, false);
    wait_attached(ots[1]).await;
}
