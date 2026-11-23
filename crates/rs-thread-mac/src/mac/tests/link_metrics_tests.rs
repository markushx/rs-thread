//! Enhanced-ACK based Link Metrics probing: IE data encoding, and the
//! subject / initiator flow between two MACs.

extern crate std;

use std::vec;
use std::vec::Vec;

use rs_thread_core::Error;
use rs_thread_core::types::ExtAddress;
use rs_thread_platform::radio::PsduRxInfo;

use super::util::*;
use crate::frame::{
    Address, Frame, FrameBuilder, FrameType, FrameVersion, THREAD_IE_ENH_ACK_PROBING, THREAD_OUI,
};
use crate::frame_security::NoSecurity;
use crate::mac::*;

const LQI_MARGIN: LinkMetricsFlags = LinkMetricsFlags {
    lqi: true,
    link_margin: true,
    rssi: false,
};
const MARGIN_RSSI: LinkMetricsFlags = LinkMetricsFlags {
    lqi: false,
    link_margin: true,
    rssi: true,
};
const LQI_RSSI: LinkMetricsFlags = LinkMetricsFlags {
    lqi: true,
    link_margin: false,
    rssi: true,
};
const ALL: LinkMetricsFlags = LinkMetricsFlags {
    lqi: true,
    link_margin: true,
    rssi: true,
};

#[test]
fn scaling() {
    // Link margin 0..=130 dB <-> 0..=255, rounded to the closest value.
    assert_eq!(scale_link_margin_to_raw(0), 0);
    assert_eq!(scale_link_margin_to_raw(40), 78);
    assert_eq!(scale_link_margin_to_raw(130), 255);
    assert_eq!(scale_link_margin_to_raw(200), 255);
    assert_eq!(scale_raw_to_link_margin(78), 40);
    assert_eq!(scale_raw_to_link_margin(255), 130);
    // RSSI -130..=0 dBm <-> 0..=255.
    assert_eq!(scale_rssi_to_raw(i8::MIN), 4);
    assert_eq!(scale_rssi_to_raw(-60), 137);
    assert_eq!(scale_rssi_to_raw(0), 255);
    assert_eq!(scale_rssi_to_raw(10), 255);
    assert_eq!(scale_raw_to_rssi(137), -60);
    assert_eq!(scale_raw_to_rssi(255), 0);
    assert_eq!(scale_raw_to_rssi(0), i8::MIN);
    // Link margin over the noise floor, never negative.
    assert_eq!(compute_link_margin(-100, -60), 40);
    assert_eq!(compute_link_margin(-100, -120), 0);
}

#[test]
fn ie_data_order_and_limits() {
    let enc = |f, lqi, rssi| {
        let mut out = [0u8; ENH_ACK_PROBING_MAX_DATA];
        encode_enh_ack_data(f, lqi, rssi, -100, &mut out).map(|n| out[..n].to_vec())
    };
    // Order: LQI, link margin, RSSI.
    assert_eq!(enc(LQI_MARGIN, Some(200), Some(-60)), Some(vec![200, 78]));
    assert_eq!(enc(MARGIN_RSSI, Some(200), Some(-60)), Some(vec![78, 137]));
    assert_eq!(enc(LQI_RSSI, Some(200), Some(-60)), Some(vec![200, 137]));
    // One metric.
    assert_eq!(
        enc(
            LinkMetricsFlags {
                rssi: true,
                ..LinkMetricsFlags::NONE
            },
            None,
            Some(-60)
        ),
        Some(vec![137])
    );
    // Never more than two bytes.
    assert_eq!(enc(ALL, Some(200), Some(-60)), Some(vec![200, 78]));
    // A metric the radio did not report: nothing to send.
    assert_eq!(enc(LQI_MARGIN, None, Some(-60)), None);
    assert_eq!(enc(MARGIN_RSSI, Some(1), None), None);

    // Decoding follows the same order; short data leaves metrics unset.
    let v = decode_enh_ack_data(LQI_MARGIN, &[200, 78]);
    assert_eq!(
        v,
        EnhAckProbingValues {
            lqi: Some(200),
            link_margin: Some(40),
            rssi: None
        }
    );
    let v = decode_enh_ack_data(MARGIN_RSSI, &[78, 137]);
    assert_eq!((v.link_margin, v.rssi), (Some(40), Some(-60)));
    let v = decode_enh_ack_data(LQI_RSSI, &[7]);
    assert_eq!((v.lqi, v.rssi), (Some(7), None));
}

// ------------------------------------------------------------ MAC flow

fn frame_2015(seq: u8, dst: Address, src: Address) -> Vec<u8> {
    let mut buf = [0u8; 127];
    let n = FrameBuilder::new(&mut buf)
        .frame_type(FrameType::Data)
        .version(FrameVersion::V2015)
        .sequence(seq)
        .pan_id(PAN)
        .dst(dst)
        .src(src)
        .ack_request(true)
        .payload(b"probe me")
        .build()
        .unwrap();
    buf[..n].to_vec()
}

/// A MAC for `short` / `ext` (bare PHY: it sends the ACKs itself).
fn node(short: rs_thread_core::types::ShortAddress, ext: ExtAddress) -> TestMac {
    let mut m = Mac::new(bare_caps(), ext, NoSecurity, FakeRng::new(0));
    m.set_pan_id(PAN);
    m.set_short_address(short);
    m.set_channel(CH).unwrap();
    m.config_mut().noise_floor = -100;
    m
}

fn rx_info(lqi: Option<u8>, rssi: Option<i8>) -> PsduRxInfo {
    let mut i = info(CH);
    i.lqi = lqi;
    i.rssi = rssi;
    i
}

/// `a` sends `frame` to `b`, which receives it with `rx`; returns the ACK
/// frame `b` sent (after `a` processed it).
fn exchange(a: &mut TestMac, b: &mut TestMac, frame: &[u8], rx: PsduRxInfo, now: u64) -> Vec<u8> {
    actions(a, t(now));
    actions(b, t(now));
    a.transmit(TxHandle(1), frame).unwrap();
    let data = tx_of(&actions(a, t(now))).unwrap();
    a.on_tx_done(TxOutcome::Sent, t(now + 1));
    b.on_rx(&data.psdu, &rx, t(now + 1));
    let ack = tx_of(&actions(b, t(now + 2))).expect("ACK");
    b.on_tx_done(TxOutcome::Sent, t(now + 3));
    a.on_rx(&ack.psdu, &info(CH), t(now + 4));
    frame_of(&ack).to_vec()
}

fn probe_ie(ack: &[u8]) -> Option<Vec<u8>> {
    let f = Frame::parse(ack).unwrap();
    f.find_thread_ie(THREAD_IE_ENH_ACK_PROBING).map(|ie| {
        assert_eq!(ie.oui, THREAD_OUI);
        ie.data.to_vec()
    })
}

#[test]
fn enh_ack_carries_link_metrics_only_for_configured_initiators() {
    let mut a = node(OWN_SHORT, OWN_EXT);
    let mut b = node(PEER_SHORT, PEER_EXT);
    let f = frame_2015(1, short(PEER_SHORT), short(OWN_SHORT));
    let rx = rx_info(Some(200), Some(-60));

    // Not configured: a plain enhanced ACK.
    let ack = exchange(&mut a, &mut b, &f, rx, 0);
    assert_eq!(Frame::parse(&ack).unwrap().version(), FrameVersion::V2015);
    assert_eq!(probe_ie(&ack), None);
    assert!(
        events(&mut a)
            .iter()
            .all(|e| !matches!(e, Event::EnhAckLinkMetrics { .. }))
    );

    // Subject configures A for LQI + link margin; initiator A tracks B.
    b.configure_enh_ack_probing(OWN_SHORT, OWN_EXT, LQI_MARGIN)
        .unwrap();
    a.track_enh_ack_probing(PEER_SHORT, PEER_EXT, LQI_MARGIN)
        .unwrap();
    let ack = exchange(&mut a, &mut b, &f, rx, 100);
    // IE: Thread OUI, sub-type 0, [LQI, scaled margin of -60 over -100 dBm].
    assert_eq!(probe_ie(&ack), Some(vec![200, 78]));
    let ev = events(&mut a);
    assert!(
        ev.contains(&Event::EnhAckLinkMetrics {
            neighbor: short(PEER_SHORT),
            values: EnhAckProbingValues {
                lqi: Some(200),
                link_margin: Some(40),
                rssi: None
            }
        }),
        "{ev:?}"
    );

    // A frame from the extended address of the same initiator matches, too.
    let f = frame_2015(2, ext(PEER_EXT), ext(OWN_EXT));
    let ack = exchange(&mut a, &mut b, &f, rx, 200);
    assert_eq!(probe_ie(&ack), Some(vec![200, 78]));

    // Someone else gets none.
    let mut c = node(
        rs_thread_core::types::ShortAddress(0x4000),
        ExtAddress([0x44; 8]),
    );
    let fc = frame_2015(
        3,
        short(PEER_SHORT),
        short(rs_thread_core::types::ShortAddress(0x4000)),
    );
    let ack = exchange(&mut c, &mut b, &fc, rx, 300);
    assert_eq!(probe_ie(&ack), None);

    // An immediate (2006) ACK cannot carry it.
    let f = data_frame(4, short(PEER_SHORT), short(OWN_SHORT), true, b"x");
    let ack = exchange(&mut a, &mut b, &f, rx, 400);
    assert_eq!(ack.len(), 3);

    // Update to margin + RSSI, then clear.
    b.configure_enh_ack_probing(OWN_SHORT, OWN_EXT, MARGIN_RSSI)
        .unwrap();
    let f = frame_2015(5, short(PEER_SHORT), short(OWN_SHORT));
    let ack = exchange(&mut a, &mut b, &f, rx, 500);
    assert_eq!(probe_ie(&ack), Some(vec![78, 137]));
    b.configure_enh_ack_probing(OWN_SHORT, OWN_EXT, LinkMetricsFlags::NONE)
        .unwrap();
    let f = frame_2015(6, short(PEER_SHORT), short(OWN_SHORT));
    let ack = exchange(&mut a, &mut b, &f, rx, 600);
    assert_eq!(probe_ie(&ack), None);

    // Radio without RSSI: nothing to report.
    b.configure_enh_ack_probing(OWN_SHORT, OWN_EXT, LQI_MARGIN)
        .unwrap();
    let f = frame_2015(7, short(PEER_SHORT), short(OWN_SHORT));
    let ack = exchange(&mut a, &mut b, &f, rx_info(Some(1), None), 700);
    assert_eq!(probe_ie(&ack), None);

    // Reset forgets everyone.
    b.reset_enh_ack_probing();
    let f = frame_2015(8, short(PEER_SHORT), short(OWN_SHORT));
    let ack = exchange(&mut a, &mut b, &f, rx, 800);
    assert_eq!(probe_ie(&ack), None);
}

#[test]
fn configuration_errors() {
    let mut m = node(OWN_SHORT, OWN_EXT);
    assert_eq!(
        m.configure_enh_ack_probing(PEER_SHORT, PEER_EXT, ALL),
        Err(Error::InvalidArgs)
    );
    assert_eq!(
        m.configure_enh_ack_probing(PEER_SHORT, PEER_EXT, LinkMetricsFlags::NONE),
        Err(Error::NotFound)
    );
    for i in 0..ENH_ACK_PROBING_LEN as u16 {
        m.configure_enh_ack_probing(
            rs_thread_core::types::ShortAddress(0x5000 + i),
            ExtAddress([i as u8; 8]),
            LQI_MARGIN,
        )
        .unwrap();
    }
    assert_eq!(
        m.configure_enh_ack_probing(PEER_SHORT, PEER_EXT, LQI_MARGIN),
        Err(Error::NoBufs)
    );
}
