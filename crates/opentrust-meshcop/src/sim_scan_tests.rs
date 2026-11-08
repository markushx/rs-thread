//! Discovery, Energy Scan, PAN ID Query and Announce Begin through the
//! multi-node harness.

use opentrust_coap::uri::Uri;
use opentrust_core::crypto::SoftCrypto;
use opentrust_core::time::Duration;
use opentrust_core::types::ExtAddress;
use opentrust_mle::Role;
use opentrust_mle::test_support::MLP;

use crate::dataset::Dataset;
use crate::discovery::{
    DEFAULT_JOINER_UDP_PORT, DiscoverScanner, ScanResult, ScanStep, build_request_tlv,
};
use crate::net_sim::Net;
use crate::scan;
use crate::sim_tests::{dataset, form, keep, leader_aloc, payload, petition, secs, state_of};
use crate::steering::{HashBitIndexes, SteeringData, compute_joiner_id};
use crate::tlv::{PAGE0_CHANNELS, State, Tlvs, WriterExt};

/// `form` plus a disabled scanner (node 3) that hears nodes 0 and 1.
fn form_with_scanner(initial: &Dataset) -> Net {
    let mut net = Net::ftds(4);
    for (a, b) in [(0, 1), (0, 2), (1, 2), (3, 0), (3, 1)] {
        net.connect(a, b);
    }
    net.start_with(0, initial);
    assert!(net.run_until(secs(60), |n| n.role(0) == Role::Leader));
    net.sim.start(1);
    assert!(net.run_until(secs(30), |n| n.role(1) == Role::Child));
    net.sim.upgrade(0, 1);
    net.sim.start(2);
    assert!(net.run_until(secs(30), |n| n.role(2) == Role::Child));
    net.run(secs(5));
    net
}

/// Scan channels 14..=16 from `scanner` like a Joiner or a commissioner.
fn discover(
    net: &mut Net,
    scanner: usize,
    joiner: bool,
    filter: Option<HashBitIndexes>,
) -> std::vec::Vec<ScanResult> {
    let mut sc = DiscoverScanner::new();
    sc.start(
        PAGE0_CHANNELS,
        (1 << 14) | (1 << 15) | (1 << 16),
        0xffff,
        joiner,
        filter,
    )
    .unwrap();
    assert!(sc.start(PAGE0_CHANNELS, 0, 0xffff, false, None).is_err());
    let mut results = std::vec::Vec::new();
    let mut channel = 0;
    for _ in 0..100 {
        let now = net.now();
        match sc.poll(now) {
            Some(ScanStep::Request {
                channel: c,
                pan_id,
                joiner,
            }) => {
                channel = c;
                let mut b = [0u8; 16];
                let n = build_request_tlv(joiner, &mut b).unwrap();
                let node = &mut net.sim.nodes[scanner];
                node.mle
                    .send_discovery_request(&mut node.env, pan_id, Some(c), &b[..n])
                    .unwrap();
                net.pump();
            }
            Some(ScanStep::Done) => break,
            None => {}
        }
        net.run(Duration::from_millis(50));
        for (mut info, tlvs) in core::mem::take(&mut net.sim.nodes[scanner].env.discovery_responses)
        {
            info.channel = Some(channel);
            results.extend(sc.handle_response(&info, &tlvs));
        }
    }
    assert!(!sc.is_scanning());
    results
}

#[test]
fn discovery_scan_finds_routers_and_honours_steering_data() {
    let d = dataset(1, 15, 0x1234, 0x42, "OpenTrust");
    let mut net = form_with_scanner(&d);

    // A plain scan finds both routers in range, on every scanned channel.
    let r = discover(&mut net, 3, false, None);
    let who: std::collections::BTreeSet<_> = r.iter().map(|x| x.ext_address.0).collect();
    assert_eq!(who.len(), 2);
    for x in &r {
        assert_eq!(x.network_name.as_ref().unwrap().as_str(), "OpenTrust");
        assert_eq!(x.ext_pan_id.unwrap().0[0], 0xde);
        assert_eq!(x.pan_id, 0xffff);
        assert_eq!(x.version, 5);
        assert!(!x.is_native);
        assert_eq!(x.joiner_udp_port, Some(DEFAULT_JOINER_UDP_PORT));
        assert!(x.steering_data.unwrap().is_empty());
        assert_eq!(x.rssi, -60);
    }

    // A Joiner is not answered while no commissioner allows joining.
    let eui = ExtAddress([0x18, 0xb4, 0x30, 0, 0, 1, 2, 3]);
    let joiner_id = compute_joiner_id(&SoftCrypto, &eui);
    let filter = HashBitIndexes::of_joiner_id(&joiner_id);
    assert!(discover(&mut net, 3, true, Some(filter)).is_empty());

    // A commissioner petitions and permits this Joiner.
    petition(&mut net, 2, "comm");
    let (_, body) = net.nodes[2].responses.pop().unwrap();
    let session = Tlvs(&body).commissioner_session_id().unwrap();
    let mut sd = SteeringData::new(16);
    sd.add_joiner_id(&joiner_id).unwrap();
    let set = payload(|w| {
        w.commissioner_session_id(session).unwrap();
        w.steering_data(&sd).unwrap();
        w.joiner_udp_port(1234).unwrap();
    });
    net.post(2, leader_aloc(), Uri::CommissionerSet, &set);
    assert_eq!(state_of(&mut net, 2), State::Accept);
    keep(&mut net, 2, session);
    net.run(secs(20));

    // The Joiner finds the network, with the Steering Data and the port of
    // the Commissioning Data.
    let r = discover(&mut net, 3, true, Some(filter));
    assert!(!r.is_empty());
    for x in &r {
        assert_eq!(x.steering_data, Some(sd));
        assert_eq!(x.joiner_udp_port, Some(1234));
    }
    // Another Joiner is filtered out by the bloom filter, a non-joiner scan
    // without filter still sees it.
    let other = compute_joiner_id(&SoftCrypto, &ExtAddress([0x18, 0xb4, 0x30, 0, 0, 9, 9, 9]));
    assert!(!sd.contains_joiner_id(&other));
    assert!(
        discover(
            &mut net,
            3,
            true,
            Some(HashBitIndexes::of_joiner_id(&other))
        )
        .is_empty()
    );
    assert!(!discover(&mut net, 3, false, None).is_empty());
}

#[test]
fn energy_scan_round_trip() {
    let d = dataset(1, 15, 0x1234, 0x42, "OpenTrust");
    let mut net = form(&d);
    net.nodes[2].srv.rf_energy[15] = -60;
    net.nodes[2].srv.rf_energy[16] = -70;
    let now = net.now();
    let (a, b) = (net.rloc(2), net.sim.nodes[1].mle.rloc16());
    let node = &mut net.nodes[1];
    scan::send_energy_scan_query(
        &mut node.agent,
        now,
        &mut node.rng,
        &mut node.sink,
        &MLP,
        b,
        a,
        0x4321,
        (1 << 15) | (1 << 16),
        2,
        500,
        100,
    )
    .unwrap();
    net.pump();
    assert!(net.nodes[2].srv.energy.is_active());
    // Nothing for the first second, then scans, then the report.
    net.run(secs(1));
    assert!(net.nodes[1].srv.energy_reports.is_empty());
    net.run(secs(5));
    let rep = &net.nodes[1].srv.energy_reports;
    assert_eq!(rep.len(), 1);
    assert_eq!(rep[0].0, (1 << 15) | (1 << 16));
    assert_eq!(
        rep[0]
            .1
            .iter()
            .map(|&b| scan::energy_dbm(b))
            .collect::<std::vec::Vec<_>>(),
        [-60, -70, -60, -70]
    );
    assert!(!net.nodes[2].srv.energy.is_active());

    // A request without all TLVs is ignored.
    let bad = payload(|w| w.count(2).unwrap());
    let dst = net.rloc(2);
    net.post(1, dst, Uri::EnergyScan, &bad);
    assert!(!net.nodes[2].srv.energy.is_active());
}

#[test]
fn pan_id_query_round_trip() {
    let d = dataset(1, 15, 0x1234, 0x42, "OpenTrust");
    let mut net = form(&d);
    net.nodes[2].srv.rf_beacons = std::vec![(0x1234, 17), (0x9999, 18), (0x1234, 25)];
    let (a, b) = (net.rloc(2), net.sim.nodes[1].mle.rloc16());
    let now = net.now();
    let node = &mut net.nodes[1];
    // Channels 15..=20: the conflict on 17 is reported, the one on 25 is
    // outside the mask.
    scan::send_pan_id_query(
        &mut node.agent,
        now,
        &mut node.rng,
        &mut node.sink,
        &MLP,
        b,
        a,
        0x4321,
        0x1234,
        0x001f_8000,
    )
    .unwrap();
    net.pump();
    net.run(secs(3));
    let c = &net.nodes[1].srv.conflicts;
    assert_eq!(c.len(), 1);
    assert_eq!((c[0].pan_id, c[0].channel_mask), (0x1234, 1 << 17));

    // No conflict: nothing is reported.
    let now = net.now();
    let node = &mut net.nodes[1];
    scan::send_pan_id_query(
        &mut node.agent,
        now,
        &mut node.rng,
        &mut node.sink,
        &MLP,
        b,
        a,
        0x4321,
        0x4321,
        0x001f_8000,
    )
    .unwrap();
    net.pump();
    net.run(secs(3));
    assert_eq!(net.nodes[1].srv.conflicts.len(), 1);
}

#[test]
fn announce_begin_makes_the_device_announce_on_each_channel() {
    use opentrust_mle::message::Command;
    let d = dataset(1, 15, 0x1234, 0x42, "OpenTrust");
    let mut net = form(&d);
    let before: u32 = net.sim.nodes[0].count_rx(Command::Announce);
    let (a, b) = (net.rloc(2), net.sim.nodes[1].mle.rloc16());
    let now = net.now();
    let node = &mut net.nodes[1];
    scan::send_announce_begin(
        &mut node.agent,
        now,
        &mut node.rng,
        &mut node.sink,
        &MLP,
        b,
        a,
        0x4321,
        (1 << 15) | (1 << 16) | (1 << 17),
        2,
        100,
    )
    .unwrap();
    net.pump();
    assert!(net.nodes[2].srv.ab.is_running());
    net.run(secs(2));
    // 2 rounds over 3 channels.
    assert_eq!(net.sim.nodes[0].count_rx(Command::Announce) - before, 6);
    assert!(!net.nodes[2].srv.ab.is_running());
}
