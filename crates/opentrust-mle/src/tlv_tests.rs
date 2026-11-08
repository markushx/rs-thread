use super::*;

fn ml_addr() -> Ipv6Addr {
    Ipv6Addr::new(0xfd00, 0xdb8, 0, 0, 0, 0, 0, 0x1234)
}

fn full_message(buf: &mut [u8]) -> usize {
    let mut w = TlvWriter::new(buf);
    let mut mask = RouterIdMask::new();
    for id in [1u8, 9, 62] {
        mask.insert(id).unwrap();
    }
    w.source_address(Rloc16(0x4400)).unwrap();
    w.mode(DeviceMode::new(true, true, true)).unwrap();
    w.timeout(240).unwrap();
    w.challenge(&[1, 2, 3, 4, 5, 6, 7, 8]).unwrap();
    w.response(&[9, 8, 7, 6]).unwrap();
    w.link_frame_counter(0x01020304).unwrap();
    w.mle_frame_counter(0x0a0b0c0d).unwrap();
    w.route64(
        7,
        &mask,
        &[
            RouteEntry {
                link_quality_out: LinkQuality::Q3,
                link_quality_in: LinkQuality::Q2,
                cost: 1,
            },
            RouteEntry::default(),
            RouteEntry::from_byte(0x5f),
        ],
    )
    .unwrap();
    w.address16(Rloc16(0x0801)).unwrap();
    w.leader_data(&LeaderData {
        partition_id: 0x11223344,
        weighting: 64,
        data_version: 3,
        stable_data_version: 4,
        leader_router_id: 5,
    })
    .unwrap();
    w.network_data(&[0x08, 0x04, 0x0b, 0x02, 0xaa, 0xbb])
        .unwrap();
    w.tlv_request(&[ty::ROUTE64, ty::NETWORK_DATA]).unwrap();
    w.scan_mask(SCAN_MASK_ROUTER | SCAN_MASK_END_DEVICE)
        .unwrap();
    w.connectivity(&Connectivity {
        parent_priority: ParentPriority::High,
        link_quality_3: 2,
        link_quality_2: 1,
        link_quality_1: 0,
        leader_cost: 3,
        id_sequence: 9,
        active_routers: 4,
        sed_buffer_size: Some(1280),
        sed_datagram_count: Some(1),
    })
    .unwrap();
    w.link_margin(40).unwrap();
    w.status(STATUS_ERROR).unwrap();
    w.version(5).unwrap();
    w.address_registration(&[
        AddressEntry::Compressed {
            context_id: 2,
            iid: [1, 2, 3, 4, 5, 6, 7, 8],
        },
        AddressEntry::Uncompressed(ml_addr()),
    ])
    .unwrap();
    w.channel(ChannelValue::new(Channel::new(15).unwrap()))
        .unwrap();
    w.pan_id(PanId(0xface)).unwrap();
    let ts = Timestamp {
        seconds: 0x0000_1234_5678,
        ticks: 0x1abc,
        authoritative: true,
    };
    w.active_timestamp(&ts).unwrap();
    w.pending_timestamp(&ts).unwrap();
    w.active_dataset(&[0x0e, 0x08, 0, 0, 0, 0, 0, 1, 0, 0])
        .unwrap();
    w.pending_dataset(&[0x33, 0x04, 0, 0, 0, 1]).unwrap();
    w.discovery(&[0x80, 0x00]).unwrap();
    w.supervision_interval(129).unwrap();
    w.wakeup_channel(ChannelValue::new(Channel::new(20).unwrap()))
        .unwrap();
    w.csl_channel(ChannelValue::new(Channel::new(11).unwrap()))
        .unwrap();
    w.csl_timeout(100).unwrap();
    w.csl_clock_accuracy(CslClockAccuracy {
        accuracy_ppm: 20,
        uncertainty_10us: 4,
    })
    .unwrap();
    w.link_metrics_query(&[link_metrics::SUB_QUERY_ID, 1, 7])
        .unwrap();
    w.link_metrics_management(&[link_metrics::SUB_ENH_ACK_CONFIG, 2, 1, 9])
        .unwrap();
    w.link_metrics_report(&[link_metrics::SUB_REPORT, 2, link_metrics::METRIC_LQI, 200])
        .unwrap();
    w.link_probe(3, 4).unwrap();
    w.time_parameter(TimeParameter {
        period: 300,
        xtal_threshold: 300,
    })
    .unwrap();
    w.xtal_accuracy(40).unwrap();
    w.len()
}

/// Calls every getter, ignoring results: must never panic.
fn exercise(t: &Tlvs<'_>) {
    let _ = t.validate();
    let _ = t.source_address();
    let _ = t.mode();
    let _ = t.timeout();
    let _ = t.challenge();
    let _ = t.response();
    let _ = t.link_frame_counter();
    let _ = t.mle_frame_counter();
    if let Ok(r) = t.route64() {
        let _ = r.entries().count();
        let _ = r.entry_for_router(62);
        let _ = r.is_singleton();
    }
    let _ = t.address16();
    let _ = t.leader_data();
    let _ = t.network_data();
    let _ = t.tlv_request();
    let _ = t.scan_mask();
    let _ = t.connectivity();
    let _ = t.link_margin();
    let _ = t.status();
    let _ = t.version();
    if let Ok(a) = t.address_registration() {
        let _ = a.count();
    }
    let _ = t.channel().and_then(|c| c.to_channel());
    let _ = t.pan_id();
    let _ = t.active_timestamp();
    let _ = t.pending_timestamp();
    let _ = t.active_dataset();
    let _ = t.pending_dataset();
    let _ = t.discovery();
    let _ = t.supervision_interval();
    let _ = t.wakeup_channel();
    let _ = t.csl_channel();
    let _ = t.csl_timeout();
    let _ = t.csl_clock_accuracy();
    let _ = t.link_metrics_query().map(|s| s.validate());
    let _ = t.link_metrics_management();
    let _ = t.link_metrics_report();
    let _ = t.link_probe();
    let _ = t.time_parameter();
    let _ = t.xtal_accuracy();
}

#[test]
fn all_tlvs_roundtrip() {
    let mut buf = [0u8; 600];
    let n = full_message(&mut buf);
    let t = Tlvs::new(&buf[..n]);
    t.validate().unwrap();

    assert_eq!(t.source_address().unwrap(), Rloc16(0x4400));
    let m = t.mode().unwrap();
    assert!(m.rx_on_when_idle() && m.full_thread_device() && m.full_network_data());
    assert!(!m.is_minimal_end_device());
    assert_eq!(t.timeout().unwrap(), 240);
    assert_eq!(t.challenge().unwrap(), &[1, 2, 3, 4, 5, 6, 7, 8]);
    assert_eq!(t.response().unwrap(), &[9, 8, 7, 6]);
    assert_eq!(t.link_frame_counter().unwrap(), 0x01020304);
    assert_eq!(t.mle_frame_counter().unwrap(), 0x0a0b0c0d);
    let r = t.route64().unwrap();
    assert_eq!(r.id_sequence, 7);
    assert_eq!(r.router_count(), 3);
    let e = r.entry_for_router(1).unwrap();
    assert_eq!(
        (e.link_quality_out, e.link_quality_in, e.cost),
        (LinkQuality::Q3, LinkQuality::Q2, 1)
    );
    assert_eq!(r.entry_for_router(9).unwrap(), RouteEntry::default());
    assert_eq!(r.entry_for_router(62).unwrap().cost, 15);
    assert!(r.entry_for_router(2).is_none());
    assert_eq!(
        r.entries().map(|(i, _)| i).collect::<heapless::Vec<_, 4>>(),
        [1, 9, 62]
    );
    assert_eq!(t.address16().unwrap(), Rloc16(0x0801));
    let ld = t.leader_data().unwrap();
    assert_eq!(
        (ld.partition_id, ld.weighting, ld.leader_router_id),
        (0x11223344, 64, 5)
    );
    assert_eq!(t.network_data().unwrap().len(), 6);
    assert_eq!(t.tlv_request().unwrap(), &[9, 12]);
    assert_eq!(t.scan_mask().unwrap(), 0xc0);
    let c = t.connectivity().unwrap();
    assert_eq!(c.parent_priority, ParentPriority::High);
    assert_eq!(
        (c.sed_buffer_size, c.sed_datagram_count),
        (Some(1280), Some(1))
    );
    assert_eq!(t.link_margin().unwrap(), 40);
    assert_eq!(t.status().unwrap(), 1);
    assert_eq!(t.version().unwrap(), 5);
    let regs: heapless::Vec<_, 4> = t.address_registration().unwrap().collect();
    assert_eq!(regs.len(), 2);
    assert_eq!(
        regs[0],
        Ok(AddressEntry::Compressed {
            context_id: 2,
            iid: [1, 2, 3, 4, 5, 6, 7, 8]
        })
    );
    assert_eq!(regs[1], Ok(AddressEntry::Uncompressed(ml_addr())));
    assert_eq!(t.channel().unwrap().to_channel().unwrap().get(), 15);
    assert_eq!(t.pan_id().unwrap(), PanId(0xface));
    let ts = t.active_timestamp().unwrap();
    assert_eq!(
        (ts.seconds, ts.ticks, ts.authoritative),
        (0x1234_5678, 0x1abc, true)
    );
    assert_eq!(t.pending_timestamp().unwrap(), ts);
    assert_eq!(t.active_dataset().unwrap().len(), 10);
    assert_eq!(t.pending_dataset().unwrap().len(), 6);
    assert_eq!(t.discovery().unwrap(), &[0x80, 0]);
    assert_eq!(t.supervision_interval().unwrap(), 129);
    assert_eq!(t.wakeup_channel().unwrap().channel, 20);
    assert_eq!(t.csl_channel().unwrap().channel, 11);
    assert_eq!(t.csl_timeout().unwrap(), 100);
    assert_eq!(t.csl_clock_accuracy().unwrap().accuracy_ppm, 20);
    let q = t.link_metrics_query().unwrap();
    assert_eq!(
        q.find(link_metrics::SUB_QUERY_ID)
            .unwrap()
            .read_u8()
            .unwrap(),
        7
    );
    assert!(t.link_metrics_management().is_ok());
    let rep = t.link_metrics_report().unwrap();
    assert_eq!(
        rep.find(link_metrics::SUB_REPORT).unwrap().value(),
        &[link_metrics::METRIC_LQI, 200]
    );
    assert_eq!(t.link_probe().unwrap(), (3, &[0u8; 4][..]));
    assert_eq!(t.time_parameter().unwrap().period, 300);
    assert_eq!(t.xtal_accuracy().unwrap(), 40);
}

#[test]
fn truncation_never_panics() {
    let mut buf = [0u8; 600];
    let n = full_message(&mut buf);
    for len in 0..=n {
        exercise(&Tlvs::new(&buf[..len]));
    }
    // Every TLV value individually truncated to every length.
    for t in Tlvs::new(&buf[..n]).iter() {
        let t = t.unwrap();
        for len in 0..=t.value().len() {
            let mut one = [0u8; 300];
            let mut w = TlvWriter::new(&mut one);
            w.raw(t.ty(), &t.value()[..len]).unwrap();
            exercise(&Tlvs::new(w.written()));
        }
    }
    // Garbage.
    let mut x = 0x1234_5678u32;
    for _ in 0..2000 {
        let mut g = [0u8; 40];
        for b in &mut g {
            x = x.wrapping_mul(1664525).wrapping_add(1013904223);
            *b = (x >> 24) as u8;
        }
        exercise(&Tlvs::new(&g));
    }
}

#[test]
fn missing_and_malformed() {
    let t = Tlvs::new(&[]);
    assert_eq!(t.mode(), Err(Error::NotFound));
    let t = Tlvs::new(&[ty::TIMEOUT, 2, 0, 1]);
    assert_eq!(t.timeout(), Err(Error::Parse));
    let t = Tlvs::new(&[ty::CHALLENGE, 3, 1, 2, 3]);
    assert_eq!(t.challenge(), Err(Error::Parse));
    let t = Tlvs::new(&[ty::CHALLENGE, 9, 1, 2, 3, 4, 5, 6, 7, 8, 9]);
    assert_eq!(t.challenge(), Err(Error::Parse));
    // Route64 with a mask bit set but no route data.
    let mut v = [0u8; 12];
    v[0] = ty::ROUTE64;
    v[1] = 9;
    v[3] = 0x80;
    assert_eq!(Tlvs::new(&v[..11]).route64(), Err(Error::Parse));
    // Reserved parent priority.
    let mut c = [0u8; 9];
    c[0] = ty::CONNECTIVITY;
    c[1] = 7;
    c[2] = 2 << 6;
    assert_eq!(Tlvs::new(&c).connectivity(), Err(Error::Parse));
}

#[test]
fn route64_known_bytes() {
    // Router ids {0, 2}; seq 5; route data: LQout=3 LQin=3 cost=1 -> 0xf1,
    // LQout=1 LQin=0 cost=15 -> 0x4f.
    let tlv = [ty::ROUTE64, 11, 5, 0xa0, 0, 0, 0, 0, 0, 0, 0, 0xf1, 0x4f];
    let r = Tlvs::new(&tlv).route64().unwrap();
    assert_eq!(r.id_sequence, 5);
    assert!(r.id_mask.contains(0) && r.id_mask.contains(2) && !r.id_mask.contains(1));
    assert_eq!(r.entry_for_router(0).unwrap().to_byte(), 0xf1);
    assert_eq!(r.entry_for_router(2).unwrap().cost, 15);
    let mut buf = [0u8; 16];
    let mut w = TlvWriter::new(&mut buf);
    w.route64(5, &r.id_mask, &[r.entry(0).unwrap(), r.entry(1).unwrap()])
        .unwrap();
    assert_eq!(w.written(), &tlv);
    // Mismatched entry count.
    let mut w = TlvWriter::new(&mut buf);
    assert_eq!(w.route64(5, &r.id_mask, &[]), Err(Error::InvalidArgs));
    let mut m = RouterIdMask::new();
    assert_eq!(m.insert(63), Err(Error::InvalidArgs));
}

#[test]
fn mode_bits() {
    // OT: mode 0x0f = rx-on + FTD + full network data (+reserved).
    let m = DeviceMode::new(true, true, true);
    assert_eq!(m.to_bits(), 0x0f);
    assert_eq!(DeviceMode::from_bits(0x0f), m);
    // MTD sleepy with stable data only: 0x04 on the wire.
    let s = DeviceMode::new(false, false, false);
    assert_eq!(s.to_bits(), 0x04);
    assert!(s.is_sleepy() && s.is_minimal_end_device());
    // FTD that sleeps is still "minimal" in OT's definition.
    assert!(DeviceMode::new(false, true, true).is_minimal_end_device());
}

#[test]
fn timestamp_encoding() {
    let t = Timestamp {
        seconds: 1,
        ticks: 0,
        authoritative: false,
    };
    assert_eq!(t.to_bytes(), [0, 0, 0, 0, 0, 1, 0, 0]);
    let t = Timestamp {
        seconds: 0,
        ticks: 0x7fff,
        authoritative: true,
    };
    assert_eq!(t.to_bytes(), [0, 0, 0, 0, 0, 0, 0xff, 0xff]);
    assert_eq!(Timestamp::from_bytes(&t.to_bytes()).unwrap(), t);
}

#[test]
fn connectivity_base_form() {
    let c = Connectivity {
        leader_cost: 2,
        ..Connectivity::default()
    };
    let mut b = [0u8; 10];
    let n = c.encode(&mut b);
    assert_eq!(n, 7);
    assert_eq!(Connectivity::from_bytes(&b[..n]).unwrap(), c);
    let mut c2 = Connectivity::default();
    c2.increment_link_quality(LinkQuality::Q3);
    c2.increment_link_quality(LinkQuality::Q0);
    assert_eq!((c2.link_quality_3, c2.link_quality_1), (1, 0));
}

#[test]
fn extended_length_network_data() {
    let data = [0x5au8; 300];
    let mut buf = [0u8; 320];
    let mut w = TlvWriter::new(&mut buf);
    w.network_data(&data).unwrap();
    assert_eq!(&w.written()[..4], &[ty::NETWORK_DATA, 0xff, 0x01, 0x2c]);
    let n = w.len();
    assert_eq!(Tlvs::new(&buf[..n]).network_data().unwrap(), &data[..]);
}

#[test]
fn writer_no_bufs() {
    let mut buf = [0u8; 3];
    let mut w = TlvWriter::new(&mut buf);
    assert_eq!(w.timeout(1), Err(Error::NoBufs));
    assert_eq!(w.challenge(&[1, 2]), Err(Error::InvalidArgs));
}
