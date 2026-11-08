//! Discovery and Announce through the MLE simulator.

extern crate std;

use opentrust_core::time::Duration;

use crate::env::{MleEvent, Role};
use crate::message::Command;
use crate::sim::Sim;
use crate::tlv::Timestamp;

fn ms(v: u64) -> Duration {
    Duration::from_millis(v)
}

/// Leader (node 0) and a child (node 1) that hear each other; node 2 is a
/// disabled scanner that hears node 0.
fn setup() -> Sim {
    let mut sim = Sim::new(3);
    sim.connect(0, 1, -60);
    sim.connect(0, 2, -60);
    sim.start(0);
    assert!(sim.run_until(Duration::from_secs(60), |s| s.role(0) == Role::Leader));
    sim.start(1);
    assert!(sim.run_until(Duration::from_secs(30), |s| s.role(1) == Role::Child));
    sim
}

fn scan(sim: &mut Sim, tlv: &[u8]) {
    let n = &mut sim.nodes[2];
    n.mle
        .send_discovery_request(&mut n.env, 0xffff, Some(20), tlv)
        .unwrap();
    sim.pump();
    sim.run(ms(300));
}

#[test]
fn discovery_request_is_answered_with_jitter() {
    let mut sim = setup();
    sim.nodes[0].env.discovery_tlvs = std::vec![0x81, 0x02, 0x50, 0x00, 0x03, 0x01, b'x'];
    // The disabled scanner sends the request on channel 20 with the
    // broadcast PAN ID.
    let n = &mut sim.nodes[2];
    n.mle
        .send_discovery_request(&mut n.env, 0xffff, Some(20), &[0x80, 0x02, 0x58, 0x00])
        .unwrap();
    sim.pump();
    assert_eq!(sim.nodes[0].count_rx(Command::DiscoveryRequest), 1);
    assert_eq!(sim.nodes[0].env.discovery_requests.len(), 1);
    let info = sim.nodes[0].env.discovery_requests[0];
    assert_eq!((info.version, info.joiner), (5, true));
    assert_eq!(info.pan_id, Some(0xffff));
    // No answer yet: random delay of 1..=250 ms.
    assert!(sim.nodes[2].env.discovery_responses.is_empty());
    sim.run(ms(300));
    let rx = &sim.nodes[2].env.discovery_responses;
    assert_eq!(rx.len(), 1);
    assert_eq!(rx[0].1, [0x81, 0x02, 0x50, 0x00, 0x03, 0x01, b'x']);
    assert_eq!(rx[0].0.ext_address, sim.nodes[0].env.ext);
    assert_eq!(rx[0].0.pan_id, Some(0xffff));
    assert_eq!(rx[0].0.rss, Some(-60));
    assert_eq!(sim.nodes[0].count_tx(Command::DiscoveryResponse), 1);
}

#[test]
fn discovery_request_filters() {
    let mut sim = setup();
    sim.nodes[0].env.discovery_tlvs = std::vec![0x81, 0x02, 0x50, 0x00];
    // The Extended PAN ID of the request equals ours: dropped.
    sim.nodes[0].env.mac_ext_pan_id = Some(opentrust_core::types::ExtPanId([7; 8]));
    let mut tlv = std::vec![0x80, 0x02, 0x58, 0x00, 0x02, 0x08];
    tlv.extend_from_slice(&[7; 8]);
    scan(&mut sim, &tlv);
    assert!(sim.nodes[2].env.discovery_responses.is_empty());
    assert!(sim.nodes[0].env.discovery_requests.is_empty());

    // The environment refuses (joiner without steering data).
    sim.nodes[0].env.discovery_accept = false;
    scan(&mut sim, &[0x80, 0x02, 0x58, 0x00]);
    assert!(sim.nodes[2].env.discovery_responses.is_empty());
    assert_eq!(sim.nodes[0].env.discovery_requests.len(), 1);

    // Without response content nothing is sent.
    sim.nodes[0].env.discovery_accept = true;
    sim.nodes[0].env.discovery_tlvs.clear();
    scan(&mut sim, &[0x80, 0x02, 0x58, 0x00]);
    assert!(sim.nodes[2].env.discovery_responses.is_empty());
}

fn ts(s: u64) -> Timestamp {
    Timestamp {
        seconds: s,
        ticks: 0,
        authoritative: false,
    }
}

#[test]
fn announce_older_network_is_answered_newer_raises_event() {
    let mut sim = setup();
    sim.nodes[0].env.active_ts = Some(ts(10));
    sim.nodes[1].env.active_ts = Some(ts(5));
    sim.nodes[1].env.mac_channel = 20;
    sim.nodes[1].env.mac_pan_id = 0x1111;
    sim.nodes[0].env.events.clear();
    sim.nodes[1].env.events.clear();

    // Node 1 (older dataset) announces itself; node 0 answers with its own
    // Announce, which raises the event at node 1.
    let n = &mut sim.nodes[1];
    n.mle.send_announce(&mut n.env, 15, false, None).unwrap();
    sim.pump();
    assert_eq!(sim.nodes[0].count_rx(Command::Announce), 1);
    assert_eq!(sim.nodes[1].count_rx(Command::Announce), 1);
    assert!(
        sim.nodes[1]
            .env
            .has_event(MleEvent::AnnounceFromNewerNetwork {
                channel: 15,
                pan_id: 0xface,
                timestamp: ts(10),
            })
    );
    assert!(
        sim.nodes[0]
            .env
            .events
            .iter()
            .all(|e| !matches!(e, MleEvent::AnnounceFromNewerNetwork { .. }))
    );

    // Equal timestamps: nothing happens.
    sim.nodes[1].env.active_ts = Some(ts(10));
    let before = sim.nodes[1].count_rx(Command::Announce);
    let n = &mut sim.nodes[1];
    n.mle.send_announce(&mut n.env, 15, false, None).unwrap();
    sim.pump();
    assert_eq!(sim.nodes[1].count_rx(Command::Announce), before);

    // An orphan Announce from another PAN is answered, from our own PAN
    // ignored.
    let n = &mut sim.nodes[1];
    n.mle.send_announce(&mut n.env, 15, true, None).unwrap();
    sim.pump();
    assert_eq!(sim.nodes[1].count_rx(Command::Announce), before + 1);
    sim.nodes[1].env.mac_channel = 15;
    sim.nodes[1].env.mac_pan_id = 0xface;
    let n = &mut sim.nodes[1];
    n.mle.send_announce(&mut n.env, 15, true, None).unwrap();
    sim.pump();
    assert_eq!(sim.nodes[1].count_rx(Command::Announce), before + 1);
}

#[test]
fn announce_without_active_timestamp_is_dropped_and_args_checked() {
    let mut sim = setup();
    let n = &mut sim.nodes[1];
    assert!(n.mle.send_announce(&mut n.env, 5, false, None).is_err());
    assert!(n.mle.send_announce(&mut n.env, 27, false, None).is_err());
    // No Active Timestamp TLV: the receiver drops it.
    n.mle.send_announce(&mut n.env, 15, false, None).unwrap();
    sim.pump();
    assert_eq!(sim.nodes[0].count_rx(Command::Announce), 0);
}
