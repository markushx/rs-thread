//! Discovery, active and energy scans.

mod common;

use common::*;
use opentrust_core::Error;
use opentrust_core::time::Duration;
use opentrust_instance::{Event, Role};
use opentrust_sim::Network;

/// Leader 0 on channel 15, factory-new node 1 in range.
fn network(seed: u64) -> Network {
    let mut net = Network::routers(2, seed);
    net.medium.connect(0, 1, -60);
    let ds = dataset(&mut net);
    start(&mut net, 0, &ds);
    assert!(net.run_until(secs(60), |n| role(n, 0) == Role::Leader));
    net.with(1, |n, _| n.ip6_set_enabled(true));
    net.take_events(1);
    net
}

fn done(net: &Network, i: usize, f: fn(&Event) -> bool) -> bool {
    net.nodes[i].events.iter().any(f)
}

#[test]
fn discovery_scan_finds_the_leader() {
    let mut net = network(5);
    let leader_ext = net.node(0).ext_address();
    net.with(1, |n, now| n.discover_start(0, 0xffff, false, now).unwrap());
    assert!(net.node(1).discover_is_active());
    assert!(net.run_until(secs(30), |n| done(n, 1, |e| matches!(
        e,
        Event::DiscoverDone
    ))));
    assert!(!net.node(1).discover_is_active());
    let found: Vec<_> = net
        .take_events(1)
        .into_iter()
        .filter_map(|e| match e {
            Event::DiscoverResult(r) => Some(r),
            _ => None,
        })
        .collect();
    assert_eq!(found.len(), 1, "{found:?}");
    let r = &found[0];
    assert_eq!(r.ext_address, leader_ext);
    assert_eq!(r.channel, 15);
    assert_eq!(r.network_name.unwrap().as_str(), "OpenTrust");
    // A second scan can start, a running one is busy.
    net.with(1, |n, now| {
        n.discover_start(1 << 15, 0xffff, true, now).unwrap();
        assert_eq!(n.discover_start(0, 0xffff, true, now), Err(Error::Busy));
    });
    assert!(net.run_until(secs(30), |n| done(n, 1, |e| matches!(
        e,
        Event::DiscoverDone
    ))));
    // The joiner flag: no Steering Data, so the leader does not answer.
    assert!(
        !done(&net, 1, |e| matches!(e, Event::DiscoverResult(_))),
        "{:?}",
        net.nodes[1].events
    );
}

#[test]
fn active_scan_hears_the_leader_beacon() {
    let mut net = network(6);
    let leader_ext = net.node(0).ext_address();
    net.with(1, |n, now| {
        n.active_scan_start(0, Duration::from_millis(100), now)
            .unwrap();
    });
    assert!(net.run_until(secs(30), |n| done(n, 1, |e| matches!(
        e,
        Event::ActiveScanDone
    ))));
    let beacons: Vec<_> = net
        .take_events(1)
        .into_iter()
        .filter_map(|e| match e {
            Event::ActiveScanResult(r) => Some(r),
            _ => None,
        })
        .collect();
    assert_eq!(beacons.len(), 1, "{beacons:?}");
    assert_eq!(beacons[0].ext_addr, leader_ext);
    assert_eq!(beacons[0].channel, 15);
    let p = beacons[0].thread.expect("Thread beacon payload");
    assert_eq!(&p.network_name[..9], b"OpenTrust");
}

#[test]
fn energy_scan_reports_every_channel() {
    let mut net = network(7);
    net.with(1, |n, now| {
        n.energy_scan_start(1 << 11 | 1 << 15 | 1 << 26, Duration::from_millis(50), now)
            .unwrap();
        assert_eq!(
            n.energy_scan_start(0, Duration::from_millis(50), now),
            Err(Error::Busy)
        );
    });
    assert!(net.run_until(secs(10), |n| done(n, 1, |e| matches!(
        e,
        Event::EnergyScanDone
    ))));
    let ch: Vec<_> = net
        .take_events(1)
        .into_iter()
        .filter_map(|e| match e {
            Event::EnergyScanResult { channel, max_rssi } => Some((channel, max_rssi)),
            _ => None,
        })
        .collect();
    assert_eq!(ch, vec![(11, -100), (15, -100), (26, -100)]);
}
