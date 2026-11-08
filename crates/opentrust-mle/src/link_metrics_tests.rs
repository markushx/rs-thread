//! Link Metrics: codecs, series state and the Initiator / Subject exchange.
//! (OpenThread has no unit vectors for these; the Thread certification
//! scripts `v1_2_LowPower_7_1_0x` / `7_2_01` describe the exchanges.)

use opentrust_core::time::Duration;
use opentrust_core::types::{ExtAddress, ipv6};
use opentrust_mac::mac::LinkMetricsFlags;

use crate::env::Role;
use crate::link_metrics::*;
use crate::sim::Sim;

fn all_but_pdu() -> Metrics {
    Metrics {
        lqi: true,
        link_margin: true,
        rssi: true,
        ..Metrics::NONE
    }
}

#[test]
fn type_ids_and_scaling() {
    let m = Metrics {
        pdu_count: true,
        lqi: true,
        link_margin: true,
        rssi: true,
        reserved: false,
    };
    let mut ids = [0u8; MAX_TYPE_IDS];
    assert_eq!(m.to_type_ids(&mut ids), 4);
    assert_eq!(ids, [0x40, 0x09, 0x0a, 0x0b]);
    assert_eq!(Metrics::from_type_ids(&ids).unwrap(), m);
    // A duplicate is an error, an unknown plain ID marks `reserved`, an
    // extended ID skips its second byte.
    assert!(Metrics::from_type_ids(&[0x09, 0x09]).is_err());
    assert!(Metrics::from_type_ids(&[0x12]).unwrap().reserved);
    assert_eq!(
        Metrics::from_type_ids(&[0x80, 0x09, 0x0b]).unwrap(),
        Metrics {
            rssi: true,
            ..Metrics::NONE
        }
    );
    assert_eq!(type_id_value_len(0x40), 4);
    assert_eq!(type_id_value_len(0x09), 1);

    assert_eq!(scale_link_margin_to_raw(0), 0);
    assert_eq!(scale_link_margin_to_raw(130), 255);
    assert_eq!(scale_link_margin_to_raw(200), 255);
    assert_eq!(scale_link_margin_to_raw(65), 128);
    assert_eq!(scale_raw_to_link_margin(255), 130);
    assert_eq!(scale_raw_to_link_margin(128), 65);
    assert_eq!(scale_rssi_to_raw(i8::MIN), 4);
    assert_eq!(scale_rssi_to_raw(0), 255);
    assert_eq!(scale_rssi_to_raw(-65), 128);
    // -130 dBm does not fit an i8: clamped.
    assert_eq!(scale_raw_to_rssi(0), i8::MIN);
    assert_eq!(scale_raw_to_rssi(255), 0);
    for rssi in [-120, -90, -65, -30, -1] {
        let back = scale_raw_to_rssi(scale_rssi_to_raw(rssi));
        assert!(
            (i16::from(back) - i16::from(rssi)).abs() <= 1,
            "{rssi} {back}"
        );
    }
}

#[test]
fn series_flags_masks() {
    let f = SeriesFlags {
        link_probe: true,
        mac_data_request: true,
        ..Default::default()
    };
    assert_eq!(f.to_mask(), 0b0101);
    assert_eq!(SeriesFlags::from_mask(0b1010).to_mask(), 0b1010);
}

#[test]
fn sub_tlv_codecs() {
    let mut b = [0u8; 32];
    // Query: Query ID 0 with options.
    let n = write_query(&mut b, 0, &all_but_pdu()).unwrap();
    assert_eq!(&b[..n], &[1, 1, 0, 2, 3, 0x09, 0x0a, 0x0b]);
    assert_eq!(parse_query(&b[..n]).unwrap(), (0, all_but_pdu()));
    // Series report query without options.
    let n = write_query(&mut b, 7, &Metrics::NONE).unwrap();
    assert_eq!(&b[..n], &[1, 1, 7]);
    assert!(parse_query(&[2, 1, 0x09]).is_err());

    // Forward Probing Registration.
    let flags = SeriesFlags {
        mac_data: true,
        ..Default::default()
    };
    let n = write_fwd_probing_reg(&mut b, 5, &flags, &all_but_pdu()).unwrap();
    assert_eq!(&b[..n], &[3, 5, 5, 2, 0x09, 0x0a, 0x0b]);
    assert_eq!(
        parse_management_request(&b[..n]).unwrap(),
        ManagementRequest::ForwardTracking {
            series_id: 5,
            flags_mask: 2,
            metrics: all_but_pdu()
        }
    );
    // Enhanced ACK Configuration.
    let m = Metrics {
        lqi: true,
        ..Metrics::NONE
    };
    let n = write_enh_ack_config(&mut b, EnhAckFlags::Register, &m).unwrap();
    assert_eq!(&b[..n], &[7, 2, 1, 0x09]);
    assert_eq!(
        parse_management_request(&b[..n]).unwrap(),
        ManagementRequest::EnhAck {
            flags: 1,
            metrics: m
        }
    );
    // Both at once, or truncated ones, are errors.
    assert!(parse_management_request(&[3, 1, 1, 7, 1, 0]).is_err());
    assert!(parse_management_request(&[3, 1, 1]).is_err());
    assert_eq!(
        parse_management_request(&[]).unwrap(),
        ManagementRequest::Empty
    );

    // Status.
    let n = write_status(&mut b, Status::SeriesIdNotRecognized).unwrap();
    assert_eq!(&b[..n], &[5, 1, 3]);
    assert_eq!(parse_management_response(&b[..n]).unwrap(), 3);
    assert!(parse_management_response(&[5, 1, 0, 5, 1, 0]).is_err());

    // Report with all four metrics.
    let v = MetricsValues {
        metrics: Metrics {
            pdu_count: true,
            lqi: true,
            link_margin: true,
            rssi: true,
            reserved: false,
        },
        pdu_count: 0x0102_0304,
        lqi: 200,
        link_margin: 65,
        rssi: -65,
    };
    let n = write_report(&mut b, &v).unwrap();
    assert_eq!(
        &b[..n],
        &[
            0, 5, 0x40, 1, 2, 3, 4, 0, 2, 0x09, 200, 0, 2, 0x0a, 128, 0, 2, 0x0b, 128
        ]
    );
    assert_eq!(parse_report(&b[..n]).unwrap(), Report::Values(v));
    // Status report; Status and Report sub-TLVs together are dropped.
    assert_eq!(parse_report(&[5, 1, 4]).unwrap(), Report::Status(4));
    assert!(parse_report(&[5, 1, 4, 0, 2, 9, 1]).is_err());
    assert!(parse_report(&[0, 2, 9, 1, 5, 1, 4]).is_err());
    assert!(parse_report(&[]).is_err());
    assert!(parse_report(&[0, 1, 9]).is_err());
}

#[test]
fn enh_ack_ie_data_decoding() {
    let cfg = LinkMetricsFlags {
        lqi: false,
        link_margin: true,
        rssi: true,
    };
    let v = parse_enh_ack_ie_data(&cfg, &[255, 0]);
    assert!(v.metrics.link_margin && v.metrics.rssi && !v.metrics.lqi);
    assert_eq!((v.link_margin, v.rssi), (130, i8::MIN));
    // Short data leaves the rest at zero.
    let v = parse_enh_ack_ie_data(&cfg, &[255]);
    assert_eq!(v.link_margin, 130);
}

#[test]
fn series_table_state() {
    let a = ExtAddress([1; 8]);
    let b = ExtAddress([2; 8]);
    let mut t = SeriesTable::<2>::new();
    assert_eq!(t.configure(&a, 0, 1, Metrics::NONE), Status::OtherError);
    assert_eq!(t.configure(&a, 3, 0b0010, all_but_pdu()), Status::Success);
    assert_eq!(
        t.configure(&a, 3, 0b0010, all_but_pdu()),
        Status::SeriesIdAlreadyRegistered
    );
    assert_eq!(t.configure(&b, 3, 0b0001, Metrics::NONE), Status::Success);
    assert_eq!(
        t.configure(&b, 4, 0b0001, Metrics::NONE),
        Status::CannotSupportNewSeries
    );
    // MAC data frames count, link probes only for series without MAC data.
    t.aggregate(&a, 0, FrameKind::MacData, 100, -60);
    t.aggregate(&a, 0, FrameKind::MacData, 120, -70);
    t.aggregate(&a, 0, FrameKind::LinkProbe, 1, -1);
    t.aggregate(&a, 0, FrameKind::MacAck, 1, -1);
    let s = t.find(&a, 3).unwrap();
    assert_eq!(s.pdu_count(), 2);
    assert_eq!(s.average_lqi(), 110);
    assert!((-66..=-64).contains(&s.average_rss()));
    // Link probes of series 3 of b; a probe with a series ID only counts there.
    t.aggregate(&b, 3, FrameKind::LinkProbe, 50, -50);
    t.aggregate(&b, 9, FrameKind::LinkProbe, 50, -50);
    assert_eq!(t.find(&b, 3).unwrap().pdu_count(), 1);
    // Removal.
    assert_eq!(
        t.configure(&a, 4, 0, Metrics::NONE),
        Status::SeriesIdNotRecognized
    );
    assert_eq!(t.configure(&a, 3, 0, Metrics::NONE), Status::Success);
    assert!(t.find(&a, 3).is_none());
    assert_eq!(
        t.configure(&b, SERIES_ID_ALL_SERIES, 0, Metrics::NONE),
        Status::Success
    );
    assert!(t.is_empty());
}

/// Leader (node 0) and an FTD child (node 1), attached.
fn pair() -> Sim {
    let mut sim = Sim::new(2);
    sim.connect(0, 1, -60);
    sim.start(0);
    assert!(sim.run_until(Duration::from_secs(60), |s| s.role(0) == Role::Leader));
    sim.start(1);
    assert!(sim.run_until(Duration::from_secs(30), |s| s.role(1) == Role::Child));
    sim
}

fn to_node(sim: &Sim, i: usize) -> core::net::Ipv6Addr {
    ipv6::link_local(&sim.nodes[i].env.ext)
}

#[test]
fn single_probe_is_answered_with_a_report() {
    let mut sim = pair();
    let dst = to_node(&sim, 0);
    let n = &mut sim.nodes[1];
    n.mle
        .link_metrics_query(&mut n.env, &dst, 0, Some(&all_but_pdu()))
        .unwrap();
    sim.pump();
    let (v, status) = sim.nodes[1].env.lm.reports.pop().expect("report");
    assert_eq!(status, Status::Success);
    let v = v.unwrap();
    assert!(v.metrics.lqi && v.metrics.link_margin && v.metrics.rssi && !v.metrics.pdu_count);
    assert_eq!(v.lqi, 200);
    // RSS -60 dBm seen by the Subject, through the 0..255 scaling.
    assert!((i16::from(v.rssi) + 60).abs() <= 1, "{}", v.rssi);
    assert!(v.link_margin > 0);
    // Unknown destination / argument errors.
    let n = &mut sim.nodes[1];
    let stranger = ipv6::link_local(&ExtAddress([9; 8]));
    assert!(
        n.mle
            .link_metrics_query(&mut n.env, &stranger, 0, None)
            .is_err()
    );
    assert!(
        n.mle
            .link_metrics_query(&mut n.env, &dst, 4, Some(&all_but_pdu()))
            .is_err()
    );
}

#[test]
fn forward_tracking_series_lifecycle() {
    let mut sim = pair();
    let dst = to_node(&sim, 0);
    let flags = SeriesFlags {
        link_probe: true,
        ..Default::default()
    };
    let m = Metrics {
        pdu_count: true,
        lqi: true,
        rssi: true,
        ..Metrics::NONE
    };
    // Register series 5.
    let n = &mut sim.nodes[1];
    n.mle
        .link_metrics_forward_series(&mut n.env, &dst, 5, &flags, Some(&m))
        .unwrap();
    sim.pump();
    assert_eq!(sim.nodes[1].env.lm.management.pop(), Some(Status::Success));
    assert_eq!(sim.nodes[0].mle.link_metrics_series().len(), 1);
    // The same ID again.
    let n = &mut sim.nodes[1];
    n.mle
        .link_metrics_forward_series(&mut n.env, &dst, 5, &flags, Some(&m))
        .unwrap();
    sim.pump();
    assert_eq!(
        sim.nodes[1].env.lm.management.pop(),
        Some(Status::SeriesIdAlreadyRegistered)
    );
    // No frames yet.
    let n = &mut sim.nodes[1];
    n.mle.link_metrics_query(&mut n.env, &dst, 5, None).unwrap();
    sim.pump();
    assert_eq!(
        sim.nodes[1].env.lm.reports.pop(),
        Some((None, Status::NoMatchingFramesReceived))
    );
    // Three probes, then the report counts them.
    for _ in 0..3 {
        let n = &mut sim.nodes[1];
        n.mle.link_metrics_probe(&mut n.env, &dst, 5, 10).unwrap();
        sim.pump();
    }
    let n = &mut sim.nodes[1];
    n.mle.link_metrics_query(&mut n.env, &dst, 5, None).unwrap();
    sim.pump();
    let (v, status) = sim.nodes[1].env.lm.reports.pop().expect("report");
    assert_eq!(status, Status::Success);
    let v = v.unwrap();
    assert!(v.metrics.pdu_count && v.metrics.lqi && v.metrics.rssi && !v.metrics.link_margin);
    assert_eq!((v.pdu_count, v.lqi), (3, 200));
    // Unknown series, probe argument checks, then removal.
    let n = &mut sim.nodes[1];
    n.mle.link_metrics_query(&mut n.env, &dst, 6, None).unwrap();
    sim.pump();
    assert_eq!(
        sim.nodes[1].env.lm.reports.pop(),
        Some((None, Status::SeriesIdNotRecognized))
    );
    let n = &mut sim.nodes[1];
    assert!(n.mle.link_metrics_probe(&mut n.env, &dst, 0, 1).is_err());
    assert!(n.mle.link_metrics_probe(&mut n.env, &dst, 255, 1).is_err());
    assert!(n.mle.link_metrics_probe(&mut n.env, &dst, 5, 65).is_err());
    assert!(
        n.mle
            .link_metrics_forward_series(&mut n.env, &dst, 0, &flags, None)
            .is_err()
    );
    n.mle
        .link_metrics_forward_series(&mut n.env, &dst, 5, &SeriesFlags::default(), None)
        .unwrap();
    sim.pump();
    assert_eq!(sim.nodes[1].env.lm.management.pop(), Some(Status::Success));
    assert!(sim.nodes[0].mle.link_metrics_series().is_empty());
}

#[test]
fn enh_ack_probing_configuration() {
    let mut sim = pair();
    let dst = to_node(&sim, 0);
    let m = Metrics {
        lqi: true,
        rssi: true,
        ..Metrics::NONE
    };
    let n = &mut sim.nodes[1];
    n.mle
        .link_metrics_enh_ack(&mut n.env, &dst, EnhAckFlags::Register, Some(&m))
        .unwrap();
    sim.pump();
    assert_eq!(sim.nodes[1].env.lm.management.pop(), Some(Status::Success));
    assert_eq!(
        sim.nodes[0].env.lm.configured.pop(),
        Some(LinkMetricsFlags {
            lqi: true,
            link_margin: false,
            rssi: true
        })
    );
    // The Initiator decodes the IE data of the Enhanced ACKs.
    let ext0 = sim.nodes[0].env.ext;
    let n = &mut sim.nodes[1];
    n.mle
        .process_enh_ack_ie_data(&mut n.env, &ext0, &[200, 128]);
    let v = n.env.lm.enh_ack.pop().expect("report");
    assert_eq!((v.lqi, v.rssi), (200, scale_raw_to_rssi(128)));
    assert!(v.metrics.lqi && v.metrics.rssi && !v.metrics.link_margin);
    // Invalid combinations are refused by the Subject: all three metrics, a
    // PDU count, Clear with metrics (also locally).
    for bad in [
        Metrics {
            lqi: true,
            link_margin: true,
            rssi: true,
            ..Metrics::NONE
        },
        Metrics {
            pdu_count: true,
            lqi: true,
            ..Metrics::NONE
        },
        Metrics::NONE,
    ] {
        let n = &mut sim.nodes[1];
        n.mle
            .link_metrics_enh_ack(&mut n.env, &dst, EnhAckFlags::Register, Some(&bad))
            .unwrap();
        sim.pump();
        assert_eq!(
            sim.nodes[1].env.lm.management.pop(),
            Some(Status::OtherError)
        );
    }
    let n = &mut sim.nodes[1];
    assert!(
        n.mle
            .link_metrics_enh_ack(&mut n.env, &dst, EnhAckFlags::Clear, Some(&m))
            .is_err()
    );
    n.mle
        .link_metrics_enh_ack(&mut n.env, &dst, EnhAckFlags::Clear, None)
        .unwrap();
    sim.pump();
    assert_eq!(sim.nodes[1].env.lm.management.pop(), Some(Status::Success));
    assert_eq!(
        sim.nodes[0].env.lm.configured.pop(),
        Some(LinkMetricsFlags::NONE)
    );
}

#[test]
fn mac_frames_feed_series_and_removed_child_drops_them() {
    let mut sim = pair();
    let dst = to_node(&sim, 0);
    let flags = SeriesFlags {
        mac_data: true,
        ..Default::default()
    };
    let n = &mut sim.nodes[1];
    n.mle
        .link_metrics_forward_series(
            &mut n.env,
            &dst,
            2,
            &flags,
            Some(&Metrics {
                pdu_count: true,
                ..Metrics::NONE
            }),
        )
        .unwrap();
    sim.pump();
    let child_ext = sim.nodes[1].env.ext;
    for _ in 0..4 {
        sim.nodes[0]
            .mle
            .aggregate_link_metrics(&child_ext, FrameKind::MacData, 100, -50);
    }
    assert_eq!(
        sim.nodes[0]
            .mle
            .link_metrics_series()
            .find(&child_ext, 2)
            .unwrap()
            .pdu_count(),
        4
    );
    let n = &mut sim.nodes[1];
    n.mle.link_metrics_query(&mut n.env, &dst, 2, None).unwrap();
    sim.pump();
    let (v, _) = sim.nodes[1].env.lm.reports.pop().unwrap();
    assert_eq!(v.unwrap().pdu_count, 4);
    // Stopping the child removes its series at the parent.
    let n = &mut sim.nodes[1];
    n.mle.stop(&mut n.env);
    sim.run(Duration::from_secs(300));
    assert!(sim.nodes[0].mle.link_metrics_series().is_empty());
}
