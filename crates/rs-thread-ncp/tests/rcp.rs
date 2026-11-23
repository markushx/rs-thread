//! The RCP against the in-memory test radio: what an OpenThread host sees.

use core::task::Poll;
use std::collections::VecDeque;
use std::vec::Vec;

use embassy_futures::block_on;
use rs_thread_core::crypto::soft::SoftCrypto;
use rs_thread_ncp::rcp::{Rcp, RcpInfo, Transport};
use rs_thread_platform::radio::sim::{RadioState, TestRadio, rx_info};
use rs_thread_platform::radio::{MacCapabilities, RadioErrorKind};
use rs_thread_spinel::codec::{Reader, Writer};
use rs_thread_spinel::consts::{cap, cmd, prop, scan_state, status};
use rs_thread_spinel::frame::{self, Frame, Header};
use rs_thread_spinel::hdlc;

#[derive(Debug)]
struct Closed;

/// Scripted host: feeds queued frames, collects what the RCP sends and ends
/// the run once `goal` frames were sent.
struct Host {
    input: VecDeque<Vec<u8>>,
    dec: hdlc::Decoder<512>,
    frames: Vec<Vec<u8>>,
    goal: usize,
}

impl Host {
    fn new(goal: usize) -> Self {
        Self {
            input: VecDeque::new(),
            dec: hdlc::Decoder::new(),
            frames: Vec::new(),
            goal,
        }
    }

    fn push(&mut self, payload: &[u8]) {
        let mut out = std::vec![0u8; hdlc::max_encoded_len(payload.len())];
        let n = hdlc::encode(payload, &mut out).unwrap();
        out.truncate(n);
        self.input.push_back(out);
    }
}

impl Transport for Host {
    type Error = Closed;

    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, Closed> {
        core::future::poll_fn(|cx| {
            if let Some(c) = self.input.pop_front() {
                buf[..c.len()].copy_from_slice(&c);
                return Poll::Ready(Ok(c.len()));
            }
            if self.frames.len() >= self.goal {
                return Poll::Ready(Err(Closed));
            }
            cx.waker().wake_by_ref();
            Poll::Pending
        })
        .await
    }

    async fn write_all(&mut self, data: &[u8]) -> Result<(), Closed> {
        for &b in data {
            if let Some(Ok(f)) = self.dec.feed(b) {
                self.frames.push(f.to_vec());
            }
        }
        Ok(())
    }
}

fn info() -> RcpInfo {
    RcpInfo {
        version: "OPENTRUST/test; RCP",
        eui64: [1, 2, 3, 4, 5, 6, 7, 8],
        now_us: || 1234,
    }
}

type TestRcp = Rcp<TestRadio, SoftCrypto>;

fn new_rcp() -> TestRcp {
    block_on(Rcp::new(TestRadio::new(), SoftCrypto, info())).unwrap()
}

fn run(rcp: &mut TestRcp, host: &mut Host) {
    let r = block_on(rcp.run(host));
    assert!(r.is_err());
}

fn req(tid: u8, command: u32, key: u32, value: impl FnOnce(&mut Writer<'_>)) -> Vec<u8> {
    let mut buf = [0u8; 300];
    let mut w = Writer::new(&mut buf);
    frame::begin_property(&mut w, Header::new(0, tid), command, key).unwrap();
    value(&mut w);
    w.as_slice().to_vec()
}

fn get(tid: u8, key: u32) -> Vec<u8> {
    req(tid, cmd::PROP_VALUE_GET, key, |_| {})
}

/// Parses a frame into (tid, command, key, value).
fn parsed(f: &[u8]) -> (u8, u32, u32, Vec<u8>) {
    let fr = Frame::parse(f).unwrap();
    let (key, v) = fr.property().unwrap();
    (fr.header.tid, fr.command, key, v.to_vec())
}

#[test]
fn boot_notification_and_identity() {
    let mut rcp = new_rcp();
    let mut host = Host::new(8);
    host.push(&get(1, prop::PROTOCOL_VERSION));
    host.push(&get(2, prop::NCP_VERSION));
    host.push(&get(3, prop::INTERFACE_TYPE));
    host.push(&get(4, prop::CAPS));
    host.push(&get(5, prop::HWADDR));
    host.push(&get(6, prop::RCP_API_VERSION));
    host.push(&get(7, prop::RADIO_CAPS));
    run(&mut rcp, &mut host);
    let f = &host.frames;
    // Unsolicited power-on reset notification.
    assert_eq!(f[0], [0x80, 0x06, 0x00, 112]);
    assert_eq!(f[1], [0x81, 0x06, 0x01, 4, 3]);
    let (tid, c, k, v) = parsed(&f[2]);
    assert_eq!((tid, c, k), (2, cmd::PROP_VALUE_IS, prop::NCP_VERSION));
    assert_eq!(v, b"OPENTRUST/test; RCP\0");
    assert_eq!(f[3], [0x83, 0x06, 0x03, 3]);
    let (_, _, _, caps) = parsed(&f[4]);
    let mut r = Reader::new(&caps);
    let mut list = Vec::new();
    while !r.is_empty() {
        list.push(r.packed().unwrap());
    }
    assert!(list.contains(&cap::CONFIG_RADIO) && list.contains(&cap::MAC_RAW));
    let (_, _, _, hw) = parsed(&f[5]);
    assert_eq!(hw, [1, 2, 3, 4, 5, 6, 7, 8]);
    assert_eq!(parsed(&f[6]).3, [11]);
    // Radio caps: the PHY capability bits of the radio (energy scan) plus the
    // frame retries the RCP does itself.
    assert_eq!(parsed(&f[7]).3, [0x26]);
}

#[test]
fn config_and_receive() {
    let mut rcp = new_rcp();
    let mut host = Host::new(7);
    host.push(&req(1, cmd::PROP_VALUE_SET, prop::MAC_15_4_PANID, |w| {
        w.u16(0xface).unwrap()
    }));
    host.push(&req(2, cmd::PROP_VALUE_SET, prop::MAC_15_4_SADDR, |w| {
        w.u16(0x1c00).unwrap()
    }));
    host.push(&req(3, cmd::PROP_VALUE_SET, prop::MAC_15_4_LADDR, |w| {
        w.array(&[0xde, 0xad, 0, 0, 0xbe, 0xef, 0, 1]).unwrap()
    }));
    host.push(&req(4, cmd::PROP_VALUE_SET, prop::PHY_ENABLED, |w| {
        w.bool(true).unwrap()
    }));
    host.push(&req(5, cmd::PROP_VALUE_SET, prop::PHY_CHAN, |w| {
        w.u8(15).unwrap()
    }));
    host.push(&req(
        6,
        cmd::PROP_VALUE_SET,
        prop::MAC_RAW_STREAM_ENABLED,
        |w| w.bool(true).unwrap(),
    ));
    run(&mut rcp, &mut host);
    // The set is answered with the new value.
    assert_eq!(host.frames[1], [0x81, 0x06, 0x36, 0xce, 0xfa]);
    let cfg = rcp.radio().config().clone();
    assert_eq!(cfg.pan_id, Some(0xface));
    assert_eq!(cfg.short_addr, Some(0x1c00));
    assert_eq!(cfg.ext_addr, Some(0xdead_0000_beef_0001));
    assert_eq!(rcp.radio().state(), RadioState::Receive { channel: 15 });

    // A received frame is reported as unsolicited STREAM_RAW.
    let psdu = [
        0x41, 0x88, 0x07, 0xce, 0xfa, 0x00, 0x1c, 0x01, 0x02, 0xaa, 0xbb,
    ];
    let mut ri = rx_info(15);
    ri.rssi = Some(-60);
    ri.lqi = Some(200);
    ri.timestamp_us = Some(0x1_0000_0001);
    assert!(rcp.radio().inject_rx(&psdu, ri));
    let mut host = Host::new(2);
    run(&mut rcp, &mut host);
    let (tid, c, k, v) = parsed(&host.frames[1]);
    assert_eq!((tid, c, k), (0, cmd::PROP_VALUE_IS, prop::STREAM_RAW));
    let mut r = Reader::new(&v);
    assert_eq!(r.data().unwrap(), psdu);
    assert_eq!(r.i8().unwrap(), -60);
    assert_eq!(r.i8().unwrap(), -128);
    assert_eq!(r.u16().unwrap(), 0);
    let mut phy = r.structure().unwrap();
    assert_eq!(phy.u8().unwrap(), 15);
    assert_eq!(phy.u8().unwrap(), 200);
    assert_eq!(phy.u64().unwrap(), 0x1_0000_0001);
    let mut vendor = r.structure().unwrap();
    assert_eq!(vendor.packed().unwrap(), 0);
    assert_eq!(r.structure().unwrap().remaining(), 5);
}

fn tx_request(psdu: &[u8], channel: u8, csma: bool) -> impl FnOnce(&mut Writer<'_>) + '_ {
    tx_request_retries(psdu, channel, csma, 15)
}

fn tx_request_retries(
    psdu: &[u8],
    channel: u8,
    csma: bool,
    retries: u8,
) -> impl FnOnce(&mut Writer<'_>) + '_ {
    move |w| {
        w.data(psdu).unwrap();
        w.u8(channel).unwrap();
        w.u8(4).unwrap(); // max CSMA backoffs
        w.u8(retries).unwrap(); // max retries
        w.bool(csma).unwrap();
        w.bool(false).unwrap(); // header updated
        w.bool(false).unwrap(); // retransmission
        w.bool(true).unwrap(); // security processed
        w.u32(0).unwrap();
        w.u32(0).unwrap();
        w.u8(channel).unwrap();
        w.i8(5).unwrap();
    }
}

fn enable(host: &mut Host) {
    host.push(&req(1, cmd::PROP_VALUE_SET, prop::PHY_ENABLED, |w| {
        w.bool(true).unwrap()
    }));
    host.push(&req(2, cmd::PROP_VALUE_SET, prop::PHY_CHAN, |w| {
        w.u8(15).unwrap()
    }));
    host.push(&req(
        3,
        cmd::PROP_VALUE_SET,
        prop::MAC_RAW_STREAM_ENABLED,
        |w| w.bool(true).unwrap(),
    ));
    host.push(&req(4, cmd::PROP_VALUE_SET, prop::PHY_CCA_THRESHOLD, |w| {
        w.i8(-70).unwrap()
    }));
}

#[test]
fn transmit_with_ack_and_failure() {
    let mut rcp = new_rcp();
    let psdu = [
        0x61, 0x88, 0x09, 0xce, 0xfa, 0x01, 0x00, 0x02, 0x00, 0x11, 0x22, 0, 0,
    ];
    let mut ack = rx_info(15);
    ack.rssi = Some(-50);
    // Immediate ACK with the frame pending bit set.
    assert!(rcp.radio().queue_ack(&[0x12, 0x00, 0x09, 0, 0], ack));
    let mut host = Host::new(6);
    enable(&mut host);
    host.push(&req(
        9,
        cmd::PROP_VALUE_SET,
        prop::STREAM_RAW,
        tx_request(&psdu, 15, true),
    ));
    run(&mut rcp, &mut host);
    let rec = rcp.radio().pop_tx().unwrap();
    assert_eq!(rec.psdu.as_slice(), psdu);
    assert_eq!(
        (rec.channel, rec.power, rec.cca_threshold),
        (15, 5, Some(-70))
    );
    assert!(rec.info.security_processed);
    let (tid, c, k, v) = parsed(host.frames.last().unwrap());
    assert_eq!((tid, c, k), (9, cmd::PROP_VALUE_IS, prop::LAST_STATUS));
    let mut r = Reader::new(&v);
    assert_eq!(r.packed().unwrap(), status::OK);
    assert!(r.bool().unwrap(), "frame pending");
    assert!(!r.bool().unwrap(), "header updated");
    assert_eq!(r.data().unwrap(), [0x12, 0x00, 0x09, 0, 0]);
    assert_eq!(r.i8().unwrap(), -50);

    // A missing ACK is retried by the RCP (the test radio does not retry).
    rcp.radio().fail_next_tx(RadioErrorKind::TxAckTimeout);
    assert!(
        rcp.radio()
            .queue_ack(&[0x02, 0x00, 0x09, 0, 0], rx_info(15))
    );
    let mut host = Host::new(2);
    host.push(&req(
        11,
        cmd::PROP_VALUE_SET,
        prop::STREAM_RAW,
        tx_request(&psdu, 15, true),
    ));
    run(&mut rcp, &mut host);
    assert_eq!(parsed(&host.frames[1]).3[0], status::OK as u8);

    // No ACK in 1 + 15 attempts is not testable with a single injected
    // failure; with retries exhausted (max retries 0): NO_ACK, no frame.
    rcp.radio().fail_next_tx(RadioErrorKind::TxAckTimeout);
    let mut host = Host::new(2);
    host.push(&req(
        10,
        cmd::PROP_VALUE_SET,
        prop::STREAM_RAW,
        tx_request_retries(&psdu, 15, false, 0),
    ));
    run(&mut rcp, &mut host);
    let (tid, _, k, v) = parsed(&host.frames[1]);
    assert_eq!((tid, k), (10, prop::LAST_STATUS));
    assert_eq!(v[..], [status::NO_ACK as u8, 0, 0]);
    // Without CSMA no CCA is requested.
    let mut last = None;
    while let Some(r) = rcp.radio().pop_tx() {
        last = Some(r);
    }
    assert_eq!(last.unwrap().cca_threshold, None);
}

#[test]
fn source_match_keys_scan_and_errors() {
    let mut rcp = new_rcp();
    let mut host = Host::new(15);
    host.push(&req(
        1,
        cmd::PROP_VALUE_SET,
        prop::MAC_SRC_MATCH_ENABLED,
        |w| w.bool(true).unwrap(),
    ));
    host.push(&req(
        2,
        cmd::PROP_VALUE_INSERT,
        prop::MAC_SRC_MATCH_SHORT_ADDRESSES,
        |w| w.u16(0x1c01).unwrap(),
    ));
    host.push(&req(
        3,
        cmd::PROP_VALUE_INSERT,
        prop::MAC_SRC_MATCH_SHORT_ADDRESSES,
        |w| w.u16(0x1c02).unwrap(),
    ));
    host.push(&req(
        4,
        cmd::PROP_VALUE_REMOVE,
        prop::MAC_SRC_MATCH_SHORT_ADDRESSES,
        |w| w.u16(0x1c01).unwrap(),
    ));
    host.push(&req(
        5,
        cmd::PROP_VALUE_INSERT,
        prop::MAC_SRC_MATCH_EXTENDED_ADDRESSES,
        |w| w.array(&[0, 0, 0, 0, 0, 0, 0, 9]).unwrap(),
    ));
    host.push(&req(6, cmd::PROP_VALUE_SET, prop::RCP_MAC_KEY, |w| {
        w.u8(8).unwrap();
        w.u8(7).unwrap();
        for k in [1u8, 2, 3] {
            w.data(&[k; 16]).unwrap();
        }
    }));
    host.push(&req(
        7,
        cmd::PROP_VALUE_SET,
        prop::RCP_MAC_FRAME_COUNTER,
        |w| {
            w.u32(77).unwrap();
            w.bool(false).unwrap();
        },
    ));
    host.push(&get(8, 0x7777));
    host.push(&req(9, cmd::PROP_VALUE_SET, prop::MAC_SCAN_MASK, |w| {
        w.bytes(&[11, 12]).unwrap()
    }));
    host.push(&req(10, cmd::PROP_VALUE_SET, prop::MAC_SCAN_PERIOD, |w| {
        w.u16(10).unwrap()
    }));
    host.push(&req(11, cmd::PROP_VALUE_SET, prop::MAC_SCAN_STATE, |w| {
        w.u8(scan_state::ENERGY).unwrap()
    }));
    run(&mut rcp, &mut host);
    let sm = rcp.radio().src_match().clone();
    assert!(sm.enabled);
    assert_eq!(sm.short_addrs.as_slice(), [0x1c02]);
    assert_eq!(sm.ext_addrs.as_slice(), [9]);
    let keys = rcp.radio().mac_keys().unwrap();
    assert_eq!((keys.key_id_mode, keys.key_id, keys.curr[0]), (1, 7, 2));
    assert_eq!(rcp.radio().mac_frame_counter(), 77);
    let f = &host.frames;
    // INSERT is answered with INSERTED.
    assert_eq!(parsed(&f[2]).1, cmd::PROP_VALUE_INSERTED);
    assert_eq!(parsed(&f[4]).1, cmd::PROP_VALUE_REMOVED);
    // Properties without getter: LAST_STATUS OK.
    assert_eq!(f[6], [0x86, 0x06, 0x00, 0]);
    assert_eq!(f[7], [0x87, 0x06, 0x00, 0]);
    // Unknown property.
    assert_eq!(f[8], [0x88, 0x06, 0x00, status::PROP_NOT_FOUND as u8]);
    // Energy scan results of channels 11 and 12 and the idle state.
    let results: Vec<_> = f[f.len() - 3..].iter().map(|x| parsed(x)).collect();
    assert_eq!(results[0].2, prop::MAC_ENERGY_SCAN_RESULT);
    assert_eq!(results[0].3, [11, (-90i8) as u8]);
    assert_eq!(results[1].3, [12, (-90i8) as u8]);
    assert_eq!(results[2].2, prop::MAC_SCAN_STATE);
    assert_eq!(results[2].3, [scan_state::IDLE]);
}

#[test]
fn reset_and_noop() {
    let mut rcp = new_rcp();
    let _ = MacCapabilities::all();
    let mut host = Host::new(4);
    host.push(&req(1, cmd::PROP_VALUE_SET, prop::PHY_ENABLED, |w| {
        w.bool(true).unwrap()
    }));
    host.push(&[0x82, 0x00]);
    host.push(&[0x80, 0x01, 0x02]);
    run(&mut rcp, &mut host);
    assert_eq!(host.frames[2], [0x82, 0x06, 0x00, 0]);
    // After the reset: software reset notification, radio asleep, state cleared.
    assert_eq!(host.frames[3], [0x80, 0x06, 0x00, 114]);
    assert_eq!(rcp.radio().state(), RadioState::Sleep);
    let mut host = Host::new(2);
    host.push(&get(1, prop::PHY_ENABLED));
    run(&mut rcp, &mut host);
    assert_eq!(host.frames[1][3..], [0]);
}

/// A radio without `TRANSMIT_SEC` gets frames the RCP secured: frame counter
/// and key index assigned, payload encrypted with the current key.
#[test]
fn software_transmit_security() {
    use rs_thread_core::crypto::CryptoBackend;
    use rs_thread_core::types::ExtAddress;
    use rs_thread_mac::security::open_psdu;

    let mut rcp = new_rcp();
    let mut host = Host::new(9);
    enable(&mut host);
    host.push(&req(5, cmd::PROP_VALUE_SET, prop::MAC_15_4_LADDR, |w| {
        w.array(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88])
            .unwrap()
    }));
    host.push(&req(6, cmd::PROP_VALUE_SET, prop::RCP_MAC_KEY, |w| {
        w.u8(8).unwrap();
        w.u8(5).unwrap();
        for k in [1u8, 2, 3] {
            w.data(&[k; 16]).unwrap();
        }
    }));
    host.push(&req(
        7,
        cmd::PROP_VALUE_SET,
        prop::RCP_MAC_FRAME_COUNTER,
        |w| w.u32(100).unwrap(),
    ));
    // Secured data frame: header (15 bytes, ENC-MIC-32, key ID mode 1),
    // payload, room for the MIC and the FCS.
    let mut psdu = std::vec![
        0x49, 0x98, 0x18, 0x08, 0xa3, 0xff, 0xff, 0x00, 0xe8, 0x0d, 0, 0, 0, 0, 0,
    ];
    psdu.extend([0xaa, 0xbb, 0xcc]);
    psdu.extend([0; 4 + 2]);
    host.push(&req(9, cmd::PROP_VALUE_SET, prop::STREAM_RAW, |w| {
        w.data(&psdu).unwrap();
        w.u8(15).unwrap();
        w.u8(4).unwrap();
        w.u8(15).unwrap();
        w.bool(true).unwrap();
        w.bool(false).unwrap(); // header not updated
        w.bool(false).unwrap();
        w.bool(false).unwrap(); // security not processed
    }));
    run(&mut rcp, &mut host);
    let mut rec = None;
    while let Some(r) = rcp.radio().pop_tx() {
        rec = Some(r);
    }
    let rec = rec.unwrap();
    assert!(rec.info.header_updated && rec.info.security_processed);
    let mut sealed = rec.psdu.to_vec();
    let n = sealed.len() - 2;
    assert_eq!(&sealed[10..14], &100u32.to_le_bytes());
    assert_eq!(sealed[14], 5);
    assert_ne!(&sealed[15..18], &[0xaa, 0xbb, 0xcc]);
    let cipher = SoftCrypto.aes128(&[2; 16]);
    let source = ExtAddress([0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]);
    open_psdu(&cipher, &mut sealed[..n], &source).unwrap();
    assert_eq!(&sealed[15..18], &[0xaa, 0xbb, 0xcc]);
    // The transmit-done carries the assigned key ID and frame counter.
    let (_, _, _, v) = parsed(host.frames.last().unwrap());
    let mut r = Reader::new(&v);
    assert_eq!(r.packed().unwrap(), status::OK);
    assert!(!r.bool().unwrap());
    assert!(r.bool().unwrap(), "header updated");
    let _ack = (
        r.data().unwrap(),
        r.i8().unwrap(),
        r.i8().unwrap(),
        r.u16().unwrap(),
    );
    r.structure().unwrap();
    r.structure().unwrap();
    r.structure().unwrap();
    assert_eq!(r.u8().unwrap(), 5);
    assert_eq!(r.u32().unwrap(), 100);
}
