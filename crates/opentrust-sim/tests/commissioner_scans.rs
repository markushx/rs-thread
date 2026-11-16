//! The Commissioner's Energy Scan, PAN ID Query and Announce Begin requests
//! (`/c/es`, `/c/pq`, `/c/ab`) against an OpenTrust device, with the answers
//! (`/c/er`, `/c/pc`) at the Commissioner.

mod common;

use core::net::Ipv6Addr;

use common::*;
use opentrust_core::types::PanId;
use opentrust_instance::{Event, Role};
use opentrust_mac::frame::{Frame, KeyIdMode};
use opentrust_meshcop::commissioner::CommissionerState;
use opentrust_sim::{Kind, Network};

/// Leader 0 (Commissioner) - router 1.
fn network(seed: u64) -> Network {
    let mut net = Network::new(&[Kind::Router, Kind::Router], seed);
    net.medium.connect(0, 1, -60);
    let ds = dataset(&mut net);
    start(&mut net, 0, &ds);
    assert!(net.run_until(secs(60), |n| role(n, 0) == Role::Leader));
    start(&mut net, 1, &ds);
    assert!(net.run_until(secs(300), |n| role(n, 1) == Role::Router));
    net.with(0, |n, now| {
        n.commissioner_start("opentrust", None, now).unwrap()
    });
    assert!(net.run_until(secs(30), |n| n.node(0).commissioner_state()
        == CommissionerState::Active));
    net.take_events(0);
    net
}

fn ml_eid(net: &mut Network, i: usize) -> Ipv6Addr {
    net.node(i).ml_eid()
}

#[test]
fn energy_scan_query_returns_an_energy_report() {
    let mut net = network(11);
    let dst = ml_eid(&mut net, 1);
    // Channels 15 and 20, two rounds, 32 ms apart, 50 ms per channel.
    let mask = (1 << 15) | (1 << 20);
    net.with(0, |n, now| {
        n.commissioner_energy_scan(mask, 2, 32, 50, dst, now)
            .unwrap()
    });
    assert!(net.run_until(secs(20), |n| {
        n.nodes[0]
            .events
            .iter()
            .any(|e| matches!(e, Event::EnergyReport))
    }));
    let (m, list) = net.node(0).take_energy_report().unwrap();
    assert_eq!(m, mask);
    // One value per channel and round.
    assert_eq!(list.len(), 4, "{list:?}");
    assert!(list.iter().all(|b| (*b as i8) <= 0));
}

#[test]
fn energy_scan_query_needs_an_active_commissioner() {
    let mut net = network(12);
    let dst = ml_eid(&mut net, 0);
    net.with(1, |n, now| {
        assert!(
            n.commissioner_energy_scan(1 << 15, 1, 32, 50, dst, now)
                .is_err()
        );
    });
}

#[test]
fn pan_id_query_reports_the_conflicting_channel() {
    let mut net = network(13);
    let dst = ml_eid(&mut net, 1);
    // The network's own PAN ID is heard on its channel by the scanning
    // router: node 0 beacons it.
    let now = net.now;
    let pan = net
        .node(0)
        .active_dataset(now)
        .and_then(|d| d.tlvs().pan_id().ok())
        .unwrap();
    net.with(0, |n, now| {
        n.commissioner_pan_id_query(pan, 1 << 15, dst, now).unwrap()
    });
    assert!(net.run_until(secs(20), |n| {
        n.nodes[0]
            .events
            .iter()
            .any(|e| matches!(e, Event::PanIdConflict { .. }))
    }));
    let (p, m) = net
        .take_events(0)
        .into_iter()
        .find_map(|e| match e {
            Event::PanIdConflict {
                pan_id,
                channel_mask,
            } => Some((pan_id, channel_mask)),
            _ => None,
        })
        .unwrap();
    assert_eq!(p, pan);
    assert_eq!(m, 1 << 15);
}

#[test]
fn announce_begin_makes_the_device_send_announces() {
    let mut net = network(14);
    let dst = ml_eid(&mut net, 1);
    let before = net.tx_log.len();
    // Channel 20, one cycle.
    net.with(0, |n, now| {
        n.commissioner_announce_begin(1 << 20, 1, 100, dst, now)
            .unwrap()
    });
    net.run_until(secs(5), |_| false);
    // An Announce goes to the broadcast PAN ID, secured with key ID mode 2.
    let announces = net.tx_log[before..]
        .iter()
        .filter(|t| t.from == 1)
        .filter_map(|t| Frame::parse_with_fcs(&t.psdu).ok())
        .filter(|f| {
            f.dst_pan_id() == Some(PanId::BROADCAST)
                && f.security_header()
                    .is_some_and(|s| s.key_id_mode() == KeyIdMode::Source4)
        })
        .count();
    assert!(announces >= 1, "no Announce from node 1");
}
