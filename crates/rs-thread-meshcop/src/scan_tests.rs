//! State machine tests of the scanner and the scan servers (no TMF).

use core::net::Ipv6Addr;

use rs_thread_core::time::{Duration, Instant};
use rs_thread_mle::env::DiscoveryResponseInfo;

use crate::discovery::{
    DiscoverScanner, ResponseContent, SCAN_DURATION, ScanStep, build_response_tlv, parse_response,
};
use crate::scan::{AnnounceBeginServer, EnergyAction, EnergyScanServer, PanIdQueryServer};
use crate::steering::{HashBitIndexes, SteeringData};
use crate::tlv::PAGE0_CHANNELS;
use rs_thread_core::types::{ExtAddress, ExtPanId, NetworkName};

const T0: Instant = Instant::from_secs(10);

#[test]
fn scanner_steps_through_channels() {
    let mut s = DiscoverScanner::new();
    assert_eq!(s.poll(T0), None);
    s.start(PAGE0_CHANNELS, (1 << 11) | (1 << 13), 0xffff, true, None)
        .unwrap();
    assert!(s.is_scanning());
    assert_eq!(
        s.poll(T0),
        Some(ScanStep::Request {
            channel: 11,
            pan_id: 0xffff,
            joiner: true
        })
    );
    // Listening for 300 ms.
    assert_eq!(s.poll(T0 + Duration::from_millis(299)), None);
    assert_eq!(s.next_deadline(), Some(T0 + SCAN_DURATION));
    let t1 = T0 + SCAN_DURATION;
    assert!(matches!(
        s.poll(t1),
        Some(ScanStep::Request { channel: 13, .. })
    ));
    assert_eq!(s.poll(t1 + SCAN_DURATION), Some(ScanStep::Done));
    assert!(!s.is_scanning());

    // Unsupported / empty selection: done at once.
    s.start(1 << 11, 1 << 20, 0xffff, false, None).unwrap();
    assert_eq!(s.poll(T0), Some(ScanStep::Done));
}

fn info() -> DiscoveryResponseInfo {
    DiscoveryResponseInfo {
        ext_address: ExtAddress([1; 8]),
        pan_id: Some(0x1234),
        channel: Some(17),
        rss: Some(-50),
        lqi: Some(3),
    }
}

#[test]
fn response_round_trip_and_filter() {
    let ext = ExtPanId([9; 8]);
    let name = NetworkName::new("net").unwrap();
    let mut sd = SteeringData::new(8);
    let id = ExtAddress([2, 0, 0, 0, 0, 0, 0, 5]);
    sd.add_joiner_id(&id).unwrap();
    let mut b = [0u8; 120];
    let n = build_response_tlv(
        &ResponseContent {
            ext_pan_id: &ext,
            network_name: &name,
            steering_data: Some(&sd),
            joiner_udp_port: 1000,
            native_commissioner: Some(49191),
            commercial_commissioning: true,
            domain_name: Some("Domain"),
        },
        &mut b,
    )
    .unwrap();
    let r = parse_response(&info(), &b[..n], None).unwrap();
    assert!(r.is_native && r.steering_data == Some(sd));
    assert_eq!((r.pan_id, r.channel, r.rssi, r.lqi), (0x1234, 17, -50, 3));
    assert_eq!(r.network_name.unwrap().as_str(), "net");
    // Filter hit and miss.
    assert!(parse_response(&info(), &b[..n], Some(&HashBitIndexes::of_joiner_id(&id))).is_ok());
    let other = ExtAddress([2, 0, 0, 0, 0, 0, 7, 7]);
    assert!(!sd.contains_joiner_id(&other));
    assert!(
        parse_response(
            &info(),
            &b[..n],
            Some(&HashBitIndexes::of_joiner_id(&other))
        )
        .is_err()
    );
    // Filtering requires Steering Data.
    let n2 = build_response_tlv(
        &ResponseContent {
            ext_pan_id: &ext,
            network_name: &name,
            steering_data: None,
            joiner_udp_port: 1000,
            native_commissioner: None,
            commercial_commissioning: false,
            domain_name: None,
        },
        &mut b,
    )
    .unwrap();
    assert!(parse_response(&info(), &b[..n2], None).is_ok());
    assert!(parse_response(&info(), &b[..n2], Some(&HashBitIndexes([0, 0]))).is_err());
}

#[test]
fn energy_server_cycles_channels() {
    let mut s = EnergyScanServer::new();
    s.start(T0, Ipv6Addr::LOCALHOST, (1 << 11) | (1 << 12), 2, 200, 50);
    assert_eq!(s.poll(T0), None);
    let t = T0 + Duration::from_secs(1);
    let mut now = t;
    let mut scans = std::vec::Vec::new();
    loop {
        match s.poll(now) {
            Some(EnergyAction::Scan {
                channel,
                duration_ms,
            }) => {
                assert_eq!(duration_ms, 50);
                scans.push(channel);
                s.scan_result(now, Some(-(channel as i8)));
                s.scan_result(now, None);
            }
            Some(EnergyAction::Report) => break,
            None => now = s.next_deadline().unwrap(),
        }
    }
    assert_eq!(scans, [11, 12, 11, 12]);
    let mut out = [0u8; 64];
    let (_, n) = s.report(&mut out).unwrap();
    let t = crate::tlv::Tlvs(&out[..n]);
    assert_eq!(t.energy_list().unwrap(), [245, 244, 245, 244]);
    assert!(!s.is_active());
}

#[test]
fn pan_id_server_collects_conflicts() {
    let mut s = PanIdQueryServer::new();
    s.start(T0, Ipv6Addr::LOCALHOST, 0x1234, 0x000f_f800);
    assert_eq!(s.poll(T0), None);
    assert!(s.poll(T0 + Duration::from_secs(1)).is_some());
    assert!(!s.scan_result(Some((0x1234, 13))));
    assert!(!s.scan_result(Some((0x4321, 14))));
    assert!(s.scan_result(None));
    let mut b = [0u8; 32];
    let (_, n) = s.conflict(&mut b).unwrap();
    let t = crate::tlv::Tlvs(&b[..n]);
    assert_eq!(t.channel_mask().unwrap(), 1 << 13);
    assert_eq!(t.pan_id().unwrap(), 0x1234);
}

#[test]
fn announce_sender_rounds_and_extension() {
    let mut a = AnnounceBeginServer::new();
    a.start(T0, (1 << 20) | (1 << 12), 2, 100);
    let mut now = T0;
    let mut ch = std::vec::Vec::new();
    while let Some(c) = a.poll(now) {
        ch.push(c);
        match a.next_deadline() {
            Some(d) => now = d,
            None => break,
        }
    }
    assert_eq!(ch, [12, 20, 12, 20]);
    assert!(!a.is_running());
    // Another request while running adds rounds.
    a.start(T0, 1 << 12, 1, 100);
    a.start(T0, 1 << 12, 2, 100);
    let mut n = 0;
    let mut now = T0;
    while a.poll(now).is_some() {
        n += 1;
        match a.next_deadline() {
            Some(d) => now = d,
            None => break,
        }
    }
    assert_eq!(n, 3);
    // Invalid requests do not start anything.
    a.start(T0, 0, 3, 100);
    a.start(T0, 1 << 12, 3, 0);
    assert!(!a.is_running());
}
