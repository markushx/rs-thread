//! The MAC core driven directly (no executor).

extern crate std;

use std::vec::Vec;

use opentrust_core::Error;
use opentrust_core::types::{ExtAddress, PanId, ShortAddress};
use opentrust_platform::radio::{Capabilities, MacCapabilities, RSSI_INVALID, RadioErrorKind};

use super::util::*;
use crate::frame::{
    Address, Frame, FrameBuilder, FrameType, FrameVersion, MacCommand, ThreadBeaconPayload,
};
use crate::frame_security::NoSecurity;
use crate::mac::*;

const MAX: u32 = u32::MAX;

fn unicast(seq: u8) -> Vec<u8> {
    data_frame(seq, short(PEER_SHORT), short(OWN_SHORT), true, b"hi")
}

/// Run the MAC from `now` until it emits a transmit, advancing to each
/// deadline. Returns the transmit and the time it was emitted.
fn run_to_tx<S: crate::frame_security::FrameSecurity>(
    m: &mut TestMac<S>,
    mut now: opentrust_core::time::Instant,
) -> (TxAction, opentrust_core::time::Instant) {
    for _ in 0..64 {
        let acts = actions(m, now);
        if let Some(tx) = tx_of(&acts) {
            return (tx, now);
        }
        now = m.next_deadline().expect("MAC idle without transmit");
    }
    panic!("no transmit");
}

// ---------------------------------------------------------------------------
// CSMA-CA, retries, ACK timeout
// ---------------------------------------------------------------------------

#[test]
fn csma_backoff_exponents_and_cca_retries() {
    let mut m = mac(bare_caps(), MAX);
    m.config_mut().max_frame_retries_direct = 2;
    m.transmit(TxHandle(1), &unicast(0)).unwrap();

    let acts = actions(&mut m, t(0));
    assert!(matches!(acts[0], RadioAction::Configure(_)));
    assert_eq!(acts[1], RadioAction::Receive { channel: CH });
    assert_eq!(acts.len(), 2);

    // r = 2^BE - 1 with BE = min(3 + NB, 5); after the CSMA attempts are
    // exhausted a retransmission starts over at BE = 3.
    let expect_be = [3u32, 4, 5, 5, 5];
    let mut now = t(0);
    let mut attempts = 0;
    for _retry in 0..3 {
        for be in expect_be {
            let dl = m.next_deadline().unwrap();
            assert_eq!(
                dl,
                now + UNIT_BACKOFF_PERIOD.saturating_mul((1u64 << be) - 1)
            );
            assert!(
                actions(&mut m, dl - opentrust_core::time::Duration::from_micros(1)).is_empty()
            );
            let acts = actions(&mut m, dl);
            let tx = tx_of(&acts).unwrap();
            assert_eq!(tx.cca_threshold, Some(m.config().cca_threshold));
            assert_eq!(tx.info.max_csma_backoffs, Some(0));
            assert!(!tx.wait_ack);
            attempts += 1;
            now = dl;
            m.on_tx_done(TxOutcome::Failed(RadioErrorKind::TxFailed), now);
        }
    }
    assert_eq!(attempts, 15); // (1 + 2 retries) * (1 + 4 backoffs)
    let ev = events(&mut m);
    assert_eq!(
        ev,
        [Event::TxDone {
            handle: TxHandle(1),
            result: Err(TxError::ChannelAccessFailure)
        }]
    );
    assert_eq!(m.counters().tx_err_cca, 15);
    assert_eq!(m.counters().tx_retry, 2);
    assert_eq!(m.operation(), Operation::Idle);
}

#[test]
fn zero_backoff_transmits_immediately() {
    let mut m = mac(bare_caps(), 0);
    m.transmit(TxHandle(1), &unicast(0)).unwrap();
    let acts = actions(&mut m, t(0));
    assert!(tx_of(&acts).is_some());
}

#[test]
fn ack_timeout_retry_then_no_ack() {
    let mut m = mac(bare_caps(), 0);
    m.config_mut().max_frame_retries_direct = 3;
    m.transmit(TxHandle(7), &unicast(0)).unwrap();
    let mut now = t(0);
    let mut seqs = Vec::new();
    for i in 0..4 {
        let (tx, at) = run_to_tx(&mut m, now);
        assert_eq!(tx.info.retransmission, i > 0);
        seqs.push(seq_of(&tx));
        m.on_tx_done(TxOutcome::Sent, at);
        // Software ACK wait.
        assert_eq!(m.next_deadline(), Some(at + ACK_TIMEOUT));
        assert!(actions(&mut m, at + ms(15)).is_empty());
        now = at + ACK_TIMEOUT;
    }
    actions(&mut m, now);
    // Same sequence number for every retransmission.
    assert!(seqs.iter().all(|s| *s == seqs[0]));
    assert_eq!(
        events(&mut m),
        [Event::TxDone {
            handle: TxHandle(7),
            result: Err(TxError::NoAck)
        }]
    );
    assert_eq!(m.counters().tx_retry, 3);
}

#[test]
fn no_ack_retransmission_delay_grows() {
    // BENA 0, 1, 2 with r = 2^BENA - 1 (the CSMA backoff after it is 0
    // because there is none: max_csma_backoffs = 0).
    let mut m = mac(bare_caps(), MAX);
    m.config_mut().max_csma_backoffs_direct = 0;
    m.transmit(TxHandle(1), &unicast(0)).unwrap();
    let tx = tx_of(&actions(&mut m, t(0))).unwrap();
    assert_eq!(tx.cca_threshold, None);
    let mut now = t(0);
    for be in [0u32, 1, 2, 3] {
        m.on_tx_done(TxOutcome::Sent, now);
        now += ACK_TIMEOUT;
        let acts = actions(&mut m, now);
        let delay = UNIT_BACKOFF_PERIOD.saturating_mul((1u64 << be) - 1);
        if delay.is_zero() {
            assert!(tx_of(&acts).is_some());
        } else {
            assert!(tx_of(&acts).is_none());
            assert_eq!(m.next_deadline(), Some(now + delay));
            now += delay;
            assert!(tx_of(&actions(&mut m, now)).is_some());
        }
    }
}

#[test]
fn software_ack_match_with_frame_pending() {
    let mut m = mac(bare_caps(), 0);
    m.transmit(TxHandle(3), &unicast(0)).unwrap();
    let (tx, at) = run_to_tx(&mut m, t(0));
    let seq = seq_of(&tx);
    m.on_tx_done(TxOutcome::Sent, at);
    // A wrong sequence number is ignored.
    m.on_rx(&psdu(&imm_ack(seq.wrapping_add(1), true)), &info(CH), at);
    assert!(events(&mut m).is_empty());
    assert_eq!(m.counters().rx_ack_unmatched, 1);
    m.on_rx(&psdu(&imm_ack(seq, true)), &info(CH), at + ms(1));
    assert_eq!(
        events(&mut m),
        [Event::TxDone {
            handle: TxHandle(3),
            result: Ok(TxSuccess {
                frame_pending: true,
                retries: 0
            })
        }]
    );
    assert_eq!(m.next_deadline(), None);
}

#[test]
fn dsn_increments_per_frame() {
    let mut m = mac(bare_caps(), 0);
    m.transmit(
        TxHandle(1),
        &data_frame(
            0,
            Address::Short(ShortAddress::BROADCAST),
            short(OWN_SHORT),
            false,
            b"a",
        ),
    )
    .unwrap();
    m.transmit(
        TxHandle(2),
        &data_frame(
            0,
            Address::Short(ShortAddress::BROADCAST),
            short(OWN_SHORT),
            false,
            b"b",
        ),
    )
    .unwrap();
    let (tx1, at) = run_to_tx(&mut m, t(0));
    m.on_tx_done(TxOutcome::Sent, at);
    let (tx2, at) = run_to_tx(&mut m, at);
    m.on_tx_done(TxOutcome::Sent, at);
    assert_eq!(seq_of(&tx2), seq_of(&tx1).wrapping_add(1));
    assert_eq!(events(&mut m).len(), 2);
}

#[test]
fn full_offload_radio_single_transmit() {
    let mut m = mac(full_caps(), MAX);
    m.transmit(TxHandle(1), &unicast(0)).unwrap();
    let acts = actions(&mut m, t(0));
    let tx = tx_of(&acts).unwrap();
    assert!(tx.wait_ack);
    assert_eq!(tx.abort_at, None);
    assert_eq!(tx.info.max_csma_backoffs, Some(MAX_CSMA_BACKOFFS_DIRECT));
    assert_eq!(m.next_deadline(), None); // no software timers
    let ack = psdu(&imm_ack(seq_of(&tx), false));
    m.on_tx_done(
        TxOutcome::Acked {
            ack: &ack,
            info: info(CH),
        },
        t(10),
    );
    assert!(matches!(
        events(&mut m)[..],
        [Event::TxDone { result: Ok(_), .. }]
    ));
    // A radio-reported failure is final (the radio retried already).
    m.transmit(TxHandle(2), &unicast(0)).unwrap();
    let _ = tx_of(&actions(&mut m, t(20))).unwrap();
    m.on_tx_done(TxOutcome::Failed(RadioErrorKind::TxAckTimeout), t(30));
    assert_eq!(
        events(&mut m),
        [Event::TxDone {
            handle: TxHandle(2),
            result: Err(TxError::NoAck)
        }]
    );
}

#[test]
fn tx_ack_without_ack_timeout_sets_abort_deadline() {
    let mut caps = bare_caps();
    caps.mac = MacCapabilities::TX_ACK;
    let mut m = mac(caps, 0);
    m.config_mut().max_frame_retries_direct = 1;
    m.transmit(TxHandle(1), &unicast(0)).unwrap();
    let (tx, at) = run_to_tx(&mut m, t(0));
    assert!(tx.wait_ack);
    let abort = tx.abort_at.unwrap();
    assert!(abort > at + ACK_TIMEOUT);
    // The driver aborts at the deadline: NO_ACK, retransmitted in software.
    m.on_tx_done(TxOutcome::AckTimeout, abort);
    let (tx2, at2) = run_to_tx(&mut m, abort);
    assert!(tx2.info.retransmission);
    m.on_tx_done(TxOutcome::AckTimeout, at2);
    assert_eq!(
        events(&mut m),
        [Event::TxDone {
            handle: TxHandle(1),
            result: Err(TxError::NoAck)
        }]
    );
}

#[test]
fn late_tx_done_is_ignored() {
    let mut m = mac(bare_caps(), 0);
    m.on_tx_done(TxOutcome::Sent, t(0));
    assert!(events(&mut m).is_empty());
}

// ---------------------------------------------------------------------------
// Software ACK generation
// ---------------------------------------------------------------------------

#[test]
fn software_imm_ack_generation() {
    let mut m = mac(bare_caps(), 0);
    actions(&mut m, t(0));
    let f = data_frame(0x42, short(OWN_SHORT), short(PEER_SHORT), true, b"x");
    m.on_rx(&psdu(&f), &info(CH), t(1));
    let acts = actions(&mut m, t(2));
    let tx = tx_of(&acts).unwrap();
    assert_eq!(frame_of(&tx), [0x02, 0x10, 0x42]);
    assert_eq!(tx.psdu.len(), 5);
    assert_eq!(tx.cca_threshold, None);
    assert_eq!(tx.channel, CH);
    m.on_tx_done(TxOutcome::Sent, t(3));
    assert_eq!(m.counters().tx_soft_ack, 1);
    let ev = events(&mut m);
    let [Event::Received(rx)] = &ev[..] else {
        panic!("{ev:?}")
    };
    assert!(!rx.acked_with_frame_pending);
    assert_eq!(rx.parse().unwrap().payload(), b"x");
    // Nothing else to do (radio stays in receive).
    assert!(actions(&mut m, t(4)).is_empty());
}

#[test]
fn software_ack_frame_pending_from_src_match() {
    let mut m = mac(bare_caps(), 0);
    actions(&mut m, t(0));
    m.src_match_add(short(PEER_SHORT)).unwrap();
    let f = data_request(9, short(OWN_SHORT), short(PEER_SHORT));
    m.on_rx(&psdu(&f), &info(CH), t(1));
    let tx = tx_of(&actions(&mut m, t(2))).unwrap();
    // Frame Pending bit (0x10) set; version 2006 like the polled frame.
    assert_eq!(frame_of(&tx), [0x12, 0x10, 9]);
    m.on_tx_done(TxOutcome::Sent, t(3));
    let ev = events(&mut m);
    assert_eq!(
        ev[0],
        Event::DataPollReceived {
            src: short(PEER_SHORT),
            frame_pending: true
        }
    );
    // Not in the table: FP = 0.
    let mut m = mac(bare_caps(), 0);
    actions(&mut m, t(0));
    m.on_rx(&psdu(&f), &info(CH), t(1));
    let tx = tx_of(&actions(&mut m, t(2))).unwrap();
    assert_eq!(frame_of(&tx), [0x02, 0x10, 9]);
}

#[test]
fn software_enh_ack_for_2015_frames() {
    let mut m = mac(bare_caps(), 0);
    actions(&mut m, t(0));
    let mut buf = [0u8; 127];
    let n = FrameBuilder::new(&mut buf)
        .frame_type(FrameType::Data)
        .version(FrameVersion::V2015)
        .sequence(5)
        .pan_id(PAN)
        .dst(short(OWN_SHORT))
        .src(ext(PEER_EXT))
        .payload(b"z")
        .build()
        .unwrap();
    m.on_rx(&psdu(&buf[..n]), &info(CH), t(1));
    let tx = tx_of(&actions(&mut m, t(2))).unwrap();
    let ack = Frame::parse(frame_of(&tx)).unwrap();
    assert!(ack.is_ack());
    assert_eq!(ack.version(), FrameVersion::V2015);
    assert_eq!(ack.sequence(), Some(5));
    assert_eq!(ack.dst_address(), ext(PEER_EXT));
}

#[test]
fn no_ack_for_broadcast_or_hw_ack_radio() {
    let mut m = mac(bare_caps(), 0);
    actions(&mut m, t(0));
    let f = data_frame(
        1,
        Address::Short(ShortAddress::BROADCAST),
        short(PEER_SHORT),
        false,
        b"b",
    );
    m.on_rx(&psdu(&f), &info(CH), t(1));
    assert!(tx_of(&actions(&mut m, t(2))).is_none());
    assert_eq!(events(&mut m).len(), 1);

    let mut m = mac(full_caps(), 0);
    actions(&mut m, t(0));
    let mut i = info(CH);
    i.acked_with_frame_pending = Some(true);
    m.on_rx(&psdu(&unicast_to_us(2)), &i, t(1));
    assert!(tx_of(&actions(&mut m, t(2))).is_none());
    let ev = events(&mut m);
    let [Event::Received(rx)] = &ev[..] else {
        panic!()
    };
    assert!(rx.acked_with_frame_pending);
}

fn unicast_to_us(seq: u8) -> Vec<u8> {
    data_frame(seq, short(OWN_SHORT), short(PEER_SHORT), true, b"u")
}

// ---------------------------------------------------------------------------
// RX filtering
// ---------------------------------------------------------------------------

#[test]
fn rx_filter_matrix() {
    let p = FilterParams {
        pan_id: PAN,
        short: OWN_SHORT,
        alt_short: Some(ShortAddress(0x1001)),
        ext: OWN_EXT,
        rx_on_when_idle: true,
    };
    let bcast = Address::Short(ShortAddress::BROADCAST);
    let other = ExtAddress([9; 8]);
    let mk = |pan: PanId, dst: Address, src: Address| {
        let mut buf = [0u8; 127];
        let n = FrameBuilder::new(&mut buf)
            .frame_type(FrameType::Data)
            .dst_pan(pan)
            .src_pan(pan)
            .dst(dst)
            .src(src)
            .payload(b"p")
            .build()
            .unwrap();
        buf[..n].to_vec()
    };
    let cases: &[(PanId, Address, Address, Result<(), FilterError>)] = &[
        (PAN, short(OWN_SHORT), short(PEER_SHORT), Ok(())),
        (PAN, short(ShortAddress(0x1001)), short(PEER_SHORT), Ok(())),
        (PAN, bcast, short(PEER_SHORT), Ok(())),
        (PAN, ext(OWN_EXT), ext(PEER_EXT), Ok(())),
        (
            PAN,
            short(ShortAddress(0x1234)),
            short(PEER_SHORT),
            Err(FilterError::DstAddress),
        ),
        (PAN, ext(other), ext(PEER_EXT), Err(FilterError::DstAddress)),
        (
            PanId(0x1234),
            short(OWN_SHORT),
            short(PEER_SHORT),
            Err(FilterError::DstPan),
        ),
        (
            PanId::BROADCAST,
            short(OWN_SHORT),
            short(PEER_SHORT),
            Ok(()),
        ),
        (
            PAN,
            short(OWN_SHORT),
            ext(OWN_EXT),
            Err(FilterError::SrcIsSelf),
        ),
        (
            PAN,
            short(ShortAddress::INVALID),
            short(PEER_SHORT),
            Err(FilterError::DstAddress),
        ),
    ];
    for (i, (pan, dst, src, want)) in cases.iter().enumerate() {
        let f = mk(*pan, *dst, *src);
        assert_eq!(p.check(&Frame::parse(&f).unwrap()), *want, "case {i}");
    }
    // A sleepy device drops broadcasts (OpenThread FilterDestShortAddress).
    let sed = FilterParams {
        rx_on_when_idle: false,
        ..p
    };
    let f = mk(PAN, bcast, short(PEER_SHORT));
    assert_eq!(
        sed.check(&Frame::parse(&f).unwrap()),
        Err(FilterError::DstAddress)
    );
    // No destination at all (e.g. beacons) passes.
    let mut buf = [0u8; 127];
    let n = FrameBuilder::new(&mut buf)
        .frame_type(FrameType::Data)
        .src_pan(PAN)
        .src(ext(PEER_EXT))
        .payload(b"p")
        .build()
        .unwrap();
    assert_eq!(p.check(&Frame::parse(&buf[..n]).unwrap()), Ok(()));
}

#[test]
fn rx_filter_through_mac_and_versions() {
    let mut m = mac(full_caps(), 0);
    actions(&mut m, t(0));
    // Accepted.
    m.on_rx(&psdu(&unicast_to_us(1)), &info(CH), t(1));
    // Wrong destination.
    m.on_rx(
        &psdu(&data_frame(
            2,
            short(ShortAddress(0x3333)),
            short(PEER_SHORT),
            true,
            b"x",
        )),
        &info(CH),
        t(2),
    );
    // Reserved frame version (3): does not parse.
    let mut bad = unicast_to_us(3);
    bad[1] |= 0x30;
    m.on_rx(&psdu(&bad), &info(CH), t(3));
    // Truncated.
    m.on_rx(&[0x41], &info(CH), t(4));
    // 2003 and 2015 versions are accepted.
    let mut buf = [0u8; 127];
    for v in [FrameVersion::V2003, FrameVersion::V2015] {
        let n = FrameBuilder::new(&mut buf)
            .frame_type(FrameType::Data)
            .version(v)
            .pan_id(PAN)
            .dst(short(OWN_SHORT))
            .src(short(PEER_SHORT))
            .payload(b"v")
            .build()
            .unwrap();
        m.on_rx(&psdu(&buf[..n]), &info(CH), t(5));
    }
    assert_eq!(events(&mut m).len(), 3);
    let c = m.counters();
    assert_eq!(c.rx_dest_addr_filtered, 1);
    assert_eq!(c.rx_err_no_frame, 2);
    assert_eq!(c.rx_data, 3);
}

#[test]
fn promiscuous_delivers_everything_raw() {
    let mut m = mac(bare_caps(), 0);
    m.set_promiscuous(true);
    let acts = actions(&mut m, t(0));
    let RadioAction::Configure(cfg) = &acts[0] else {
        panic!()
    };
    assert!(cfg.promiscuous);
    let f = data_frame(
        2,
        short(ShortAddress(0x3333)),
        short(PEER_SHORT),
        true,
        b"x",
    );
    m.on_rx(&psdu(&f), &info(CH), t(1));
    assert!(tx_of(&actions(&mut m, t(2))).is_none()); // no ACK
    let ev = events(&mut m);
    let [Event::Received(rx)] = &ev[..] else {
        panic!()
    };
    assert!(rx.promiscuous);
}

// ---------------------------------------------------------------------------
// Data polling (sleepy end device)
// ---------------------------------------------------------------------------

fn sed() -> TestMac {
    let mut m = mac(full_caps(), 0);
    m.set_rx_on_when_idle(false);
    m.set_poll_security(false);
    m
}

#[test]
fn data_poll_frame_pending_then_data() {
    let mut m = sed();
    let parent = short(ShortAddress(0x0400));
    m.start_polling(parent, t(0));
    m.set_poll_period(ms(1000), t(0));
    let acts = actions(&mut m, t(0));
    assert_eq!(*acts.last().unwrap(), RadioAction::Sleep);
    assert_eq!(m.next_deadline(), Some(t(0) + ms(1000)));

    let now = t(0) + ms(1000);
    let acts = actions(&mut m, now);
    assert_eq!(acts[0], RadioAction::Receive { channel: CH }); // wake to transmit
    let tx = tx_of(&acts).unwrap();
    let f = Frame::parse(frame_of(&tx)).unwrap();
    assert_eq!(f.command(), Some(MacCommand::DataRequest));
    assert_eq!(f.dst_address(), parent);
    assert_eq!(f.src_address(), short(OWN_SHORT));
    assert!(f.ack_request());
    let ack = psdu(&imm_ack(f.sequence().unwrap(), true));
    m.on_tx_done(
        TxOutcome::Acked {
            ack: &ack,
            info: info(CH),
        },
        now,
    );
    assert_eq!(
        events(&mut m),
        [Event::DataPollSent(Ok(TxSuccess {
            frame_pending: true,
            retries: 0
        }))]
    );
    // Receiver stays on, waiting for data.
    assert!(actions(&mut m, now).is_empty());
    assert_eq!(m.operation(), Operation::WaitingForData);
    assert_eq!(m.next_deadline(), Some(now + DATA_POLL_TIMEOUT));

    let d = data_frame(1, short(OWN_SHORT), parent, true, b"data");
    m.on_rx(&psdu(&d), &info(CH), now + ms(5));
    assert!(matches!(events(&mut m)[..], [Event::Received(_)]));
    assert_eq!(actions(&mut m, now + ms(5)), [RadioAction::Sleep]);
    assert_eq!(m.operation(), Operation::Idle);
    // Next poll one period after the last one.
    assert_eq!(m.next_deadline(), Some(now + ms(1000)));
}

#[test]
fn data_poll_timeout_triggers_quick_poll() {
    let mut m = sed();
    m.start_polling(short(ShortAddress(0x0400)), t(0));
    m.send_data_poll(t(0)).unwrap();
    assert_eq!(m.send_data_poll(t(0)), Err(Error::Already));
    let tx = tx_of(&actions(&mut m, t(0))).unwrap();
    let ack = psdu(&imm_ack(seq_of(&tx), true));
    m.on_tx_done(
        TxOutcome::Acked {
            ack: &ack,
            info: info(CH),
        },
        t(0),
    );
    events(&mut m);
    actions(&mut m, t(0));
    let to = t(0) + DATA_POLL_TIMEOUT;
    let acts = actions(&mut m, to);
    assert_eq!(events(&mut m), [Event::DataPollTimeout]);
    // A quick re-poll goes out right away.
    let tx = tx_of(&acts).unwrap();
    assert_eq!(
        Frame::parse(frame_of(&tx)).unwrap().command(),
        Some(MacCommand::DataRequest)
    );
}

#[test]
fn data_poll_without_frame_pending_sleeps() {
    let mut m = sed();
    m.start_polling(short(ShortAddress(0x0400)), t(0));
    m.send_data_poll(t(0)).unwrap();
    let tx = tx_of(&actions(&mut m, t(0))).unwrap();
    let ack = psdu(&imm_ack(seq_of(&tx), false));
    m.on_tx_done(
        TxOutcome::Acked {
            ack: &ack,
            info: info(CH),
        },
        t(0),
    );
    assert_eq!(actions(&mut m, t(0)), [RadioAction::Sleep]);
    assert_eq!(m.operation(), Operation::Idle);
}

#[test]
fn failed_polls_switch_to_retx_period() {
    let mut m = sed();
    m.start_polling(short(ShortAddress(0x0400)), t(0));
    m.set_poll_period(ms(30_000), t(0));
    m.send_data_poll(t(0)).unwrap();
    let _ = tx_of(&actions(&mut m, t(0))).unwrap();
    m.on_tx_done(TxOutcome::Failed(RadioErrorKind::TxAckTimeout), t(0));
    assert_eq!(events(&mut m), [Event::DataPollSent(Err(TxError::NoAck))]);
    assert_eq!(m.poll_period(), RETX_POLL_PERIOD);
    m.send_fast_polls(0, t(0));
    assert_eq!(m.poll_period(), FAST_POLL_PERIOD);
}

#[test]
fn polling_requires_rx_off() {
    let mut m = mac(full_caps(), 0);
    m.start_polling(short(ShortAddress(0x0400)), t(0));
    assert_eq!(m.send_data_poll(t(0)), Err(Error::InvalidState));
    assert!(!m.is_polling());
}

// ---------------------------------------------------------------------------
// Indirect transmission (parent)
// ---------------------------------------------------------------------------

const CHILD: ShortAddress = ShortAddress(0x1001);

fn child_frame(payload: &[u8]) -> Vec<u8> {
    data_frame(0, short(CHILD), short(OWN_SHORT), true, payload)
}

/// Deliver a poll from the child and return the ACK the MAC sent.
fn child_polls(m: &mut TestMac, now: opentrust_core::time::Instant) -> TxAction {
    let p = data_request(0x33, short(OWN_SHORT), short(CHILD));
    m.on_rx(&psdu(&p), &info(CH), now);
    let ack = tx_of(&actions(m, now)).unwrap();
    m.on_tx_done(TxOutcome::Sent, now);
    ack
}

#[test]
fn indirect_queue_and_frame_pending() {
    let mut m = mac(bare_caps(), 0);
    actions(&mut m, t(0));
    m.transmit_indirect(TxHandle(1), short(CHILD), &child_frame(b"one"))
        .unwrap();
    m.transmit_indirect(TxHandle(2), short(CHILD), &child_frame(b"two"))
        .unwrap();
    assert_eq!(m.src_match_table().short_addrs.as_slice(), &[CHILD.0]);
    // Nothing is sent before the child polls.
    assert!(tx_of(&actions(&mut m, t(1))).is_none());

    let ack = child_polls(&mut m, t(10));
    assert!(Frame::parse(frame_of(&ack)).unwrap().frame_pending());
    assert_eq!(
        events(&mut m),
        [Event::DataPollReceived {
            src: short(CHILD),
            frame_pending: true
        }]
    );
    // First frame, with Frame Pending (one more queued).
    let tx = tx_of(&actions(&mut m, t(11))).unwrap();
    let f = Frame::parse(frame_of(&tx)).unwrap();
    assert_eq!(f.payload(), b"one");
    assert!(f.frame_pending());
    m.on_tx_done(TxOutcome::Sent, t(12));
    m.on_rx(
        &psdu(&imm_ack(f.sequence().unwrap(), false)),
        &info(CH),
        t(13),
    );
    assert_eq!(
        events(&mut m),
        [Event::TxDone {
            handle: TxHandle(1),
            result: Ok(TxSuccess {
                frame_pending: false,
                retries: 0
            })
        }]
    );

    // Second poll: last frame, no Frame Pending; table empties.
    child_polls(&mut m, t(20));
    events(&mut m);
    let tx = tx_of(&actions(&mut m, t(21))).unwrap();
    let f = Frame::parse(frame_of(&tx)).unwrap();
    assert_eq!(f.payload(), b"two");
    assert!(!f.frame_pending());
    m.on_tx_done(TxOutcome::Sent, t(22));
    m.on_rx(
        &psdu(&imm_ack(f.sequence().unwrap(), false)),
        &info(CH),
        t(23),
    );
    assert!(matches!(
        events(&mut m)[..],
        [Event::TxDone {
            handle: TxHandle(2),
            result: Ok(_)
        }]
    ));
    assert!(m.src_match_table().short_addrs.is_empty());

    // A poll now is acked without Frame Pending and gets nothing.
    let ack = child_polls(&mut m, t(30));
    assert!(!Frame::parse(frame_of(&ack)).unwrap().frame_pending());
    assert!(tx_of(&actions(&mut m, t(31))).is_none());
}

#[test]
fn indirect_frame_fails_after_max_poll_attempts() {
    let mut m = mac(bare_caps(), 0);
    actions(&mut m, t(0));
    m.transmit_indirect(TxHandle(5), short(CHILD), &child_frame(b"x"))
        .unwrap();
    let mut now = t(100);
    let mut seqs = Vec::new();
    for attempt in 0..MAX_TX_ATTEMPTS_INDIRECT_POLLS {
        child_polls(&mut m, now);
        events(&mut m);
        let tx = tx_of(&actions(&mut m, now)).unwrap();
        assert_eq!(tx.info.retransmission, attempt > 0);
        seqs.push(seq_of(&tx));
        m.on_tx_done(TxOutcome::Sent, now);
        now += ACK_TIMEOUT;
        // No retries within a poll (max_frame_retries_indirect = 0).
        assert!(tx_of(&actions(&mut m, now)).is_none());
        now += ms(100);
    }
    assert!(seqs.iter().all(|s| *s == seqs[0]));
    // The TxDone was queued after the last ACK timeout.
    let ev = events(&mut m);
    assert_eq!(
        ev,
        [Event::TxDone {
            handle: TxHandle(5),
            result: Err(TxError::NoAck)
        }]
    );
    assert_eq!(m.indirect_len(), 0);
}

#[test]
fn pinned_entry_without_frame_gets_empty_frame() {
    let mut m = mac(bare_caps(), 0);
    actions(&mut m, t(0));
    m.src_match_add(short(CHILD)).unwrap();
    child_polls(&mut m, t(1));
    let tx = tx_of(&actions(&mut m, t(2))).unwrap();
    let f = Frame::parse(frame_of(&tx)).unwrap();
    assert_eq!(f.frame_type(), FrameType::Data);
    assert!(f.payload().is_empty());
    assert_eq!(f.dst_address(), short(CHILD));
}

#[test]
fn purge_and_hw_src_match_updates() {
    let mut m = mac(full_caps(), 0);
    let acts = actions(&mut m, t(0));
    assert!(
        acts.iter()
            .any(|a| matches!(a, RadioAction::SetSrcMatch(_)))
    );
    m.transmit_indirect(TxHandle(1), ext(PEER_EXT), &child_frame(b"x"))
        .unwrap();
    let acts = actions(&mut m, t(1));
    let Some(RadioAction::SetSrcMatch(cfg)) = acts.first() else {
        panic!("{acts:?}")
    };
    assert_eq!(cfg.ext_addrs.as_slice(), &[ext_to_u64(&PEER_EXT)]);
    assert!(cfg.enabled);
    assert_eq!(m.purge_indirect(ext(PEER_EXT)), 1);
    assert_eq!(
        events(&mut m),
        [Event::TxDone {
            handle: TxHandle(1),
            result: Err(TxError::Abort)
        }]
    );
    let acts = actions(&mut m, t(2));
    let Some(RadioAction::SetSrcMatch(cfg)) = acts.first() else {
        panic!()
    };
    assert!(cfg.ext_addrs.is_empty());
}

#[test]
fn poll_by_ext_address_matches_short_queue_entry() {
    let mut m = mac(bare_caps(), 0);
    actions(&mut m, t(0));
    m.set_neighbor(CHILD, PEER_EXT).unwrap();
    m.transmit_indirect(TxHandle(1), short(CHILD), &child_frame(b"x"))
        .unwrap();
    let p = data_request(1, short(OWN_SHORT), ext(PEER_EXT));
    m.on_rx(&psdu(&p), &info(CH), t(1));
    let ack = tx_of(&actions(&mut m, t(1))).unwrap();
    assert!(Frame::parse(frame_of(&ack)).unwrap().frame_pending());
    m.on_tx_done(TxOutcome::Sent, t(1));
    let tx = tx_of(&actions(&mut m, t(2))).unwrap();
    assert_eq!(Frame::parse(frame_of(&tx)).unwrap().payload(), b"x");
}

// ---------------------------------------------------------------------------
// Scans and beacons
// ---------------------------------------------------------------------------

fn beacon(seq: u8, src: ExtAddress, pan: PanId, name: &[u8]) -> Vec<u8> {
    let mut network_name = [0u8; 16];
    network_name[..name.len()].copy_from_slice(name);
    let pl = ThreadBeaconPayload {
        version: 2,
        native: false,
        joining_permitted: true,
        network_name,
        ext_pan_id: [0xde; 8],
    };
    let mut p = [0u8; 30];
    let n = {
        let mut w = opentrust_core::bytes::Writer::new(&mut p);
        crate::frame::Beacon::write_thread_header(&mut w).unwrap();
        pl.write(&mut w).unwrap();
        w.len()
    };
    let mut buf = [0u8; 127];
    let len = FrameBuilder::new(&mut buf)
        .frame_type(FrameType::Beacon)
        .version(FrameVersion::V2003)
        .sequence(seq)
        .src_pan(pan)
        .src(ext(src))
        .payload(&p[..n])
        .build()
        .unwrap();
    buf[..len].to_vec()
}

#[test]
fn active_scan_three_channels() {
    let mut m = mac(bare_caps(), 0);
    actions(&mut m, t(0));
    let mask = (1 << 11) | (1 << 12) | (1 << 13);
    m.active_scan(mask, ms(300)).unwrap();
    assert_eq!(m.active_scan(mask, ms(300)), Err(Error::Busy));
    let mut now = t(10);
    let mut results = Vec::new();
    for ch in [11u8, 12, 13] {
        let acts = actions(&mut m, now);
        if ch == 11 {
            let RadioAction::Configure(cfg) = &acts[0] else {
                panic!("{acts:?}")
            };
            assert_eq!(cfg.pan_id, Some(0xffff));
        }
        assert!(acts.contains(&RadioAction::Receive { channel: ch }));
        let tx = tx_of(&acts).unwrap();
        assert_eq!(tx.channel, ch);
        let f = Frame::parse(frame_of(&tx)).unwrap();
        assert_eq!(f.command(), Some(MacCommand::BeaconRequest));
        assert_eq!(f.dst_address(), Address::Short(ShortAddress::BROADCAST));
        assert!(!f.ack_request());
        m.on_tx_done(TxOutcome::Sent, now);
        assert_eq!(m.next_deadline(), Some(now + ms(300)));
        // Two beacons on channel 12 (one from another PAN), none elsewhere.
        if ch == 12 {
            m.on_rx(
                &psdu(&beacon(1, PEER_EXT, PAN, b"net")),
                &info(12),
                now + ms(5),
            );
            m.on_rx(
                &psdu(&beacon(2, ExtAddress([7; 8]), PanId(0x1234), b"other")),
                &info(12),
                now + ms(6),
            );
        }
        // A data frame for us while scanning off-channel is dropped.
        m.on_rx(&psdu(&unicast_to_us(9)), &info(ch), now + ms(7));
        tx_of(&actions(&mut m, now + ms(7))); // flush a possible soft ACK
        if m.is_in_flight() {
            m.on_tx_done(TxOutcome::Sent, now + ms(7));
        }
        results.extend(events(&mut m));
        now += ms(300);
    }
    let acts = actions(&mut m, now);
    let RadioAction::Configure(cfg) = &acts[0] else {
        panic!("{acts:?}")
    };
    assert_eq!(cfg.pan_id, Some(PAN.0));
    assert!(acts.contains(&RadioAction::Receive { channel: CH }));
    results.extend(events(&mut m));
    assert_eq!(results.len(), 3, "{results:?}");
    let Event::ActiveScanResult(r) = &results[0] else {
        panic!()
    };
    assert_eq!(r.channel, 12);
    assert_eq!(r.ext_addr, PEER_EXT);
    assert_eq!(r.pan_id, PAN);
    let th = r.thread.unwrap();
    assert_eq!(th.network_name_bytes(), b"net");
    assert!(th.joining_permitted);
    let Event::ActiveScanResult(r2) = &results[1] else {
        panic!()
    };
    assert_eq!(r2.pan_id, PanId(0x1234));
    assert_eq!(results[2], Event::ActiveScanDone);
    assert_eq!(m.operation(), Operation::Idle);
}

#[test]
fn energy_scan_per_channel() {
    let mut m = mac(full_caps(), 0);
    actions(&mut m, t(0));
    m.energy_scan((1 << 20) | (1 << 21) | (1 << 22), ms(10))
        .unwrap();
    let mut got = Vec::new();
    for (ch, rssi) in [(20u8, -70i8), (21, RSSI_INVALID), (22, -40)] {
        let acts = actions(&mut m, t(1));
        assert_eq!(
            *acts.last().unwrap(),
            RadioAction::EnergyScan {
                channel: ch,
                duration_ms: 10
            }
        );
        assert!(actions(&mut m, t(1)).is_empty()); // waits for completion
        m.on_energy_scan_done(rssi, t(2));
        got.extend(events(&mut m));
    }
    assert_eq!(
        got,
        [
            Event::EnergyScanResult {
                channel: 20,
                max_rssi: -70
            },
            Event::EnergyScanResult {
                channel: 22,
                max_rssi: -40
            },
            Event::EnergyScanDone
        ]
    );
    // Back to receive on the PAN channel.
    assert_eq!(
        actions(&mut m, t(3)),
        [RadioAction::Receive { channel: CH }]
    );

    let mut m = mac(bare_caps(), 0);
    assert_eq!(m.energy_scan(0, ms(10)), Err(Error::NotImplemented));
}

#[test]
fn beacon_request_answered_when_beacon_enabled() {
    let mut m = mac(bare_caps(), 0);
    actions(&mut m, t(0));
    let mut buf = [0u8; 32];
    let n = FrameBuilder::new(&mut buf)
        .frame_type(FrameType::MacCmd)
        .version(FrameVersion::V2003)
        .dst_pan(PanId::BROADCAST)
        .dst(Address::Short(ShortAddress::BROADCAST))
        .command(MacCommand::BeaconRequest)
        .build()
        .unwrap();
    m.on_rx(&psdu(&buf[..n]), &info(CH), t(1));
    assert!(tx_of(&actions(&mut m, t(1))).is_none());
    // Enabled without a payload (the Thread 1.2.1+ default): a bare beacon.
    m.set_beacon_enabled(true);
    m.on_rx(&psdu(&buf[..n]), &info(CH), t(1));
    let tx = tx_of(&actions(&mut m, t(1))).unwrap();
    let f = Frame::parse(frame_of(&tx)).unwrap();
    assert_eq!(f.frame_type(), FrameType::Beacon);
    assert!(
        crate::frame::Beacon::parse(f.payload())
            .unwrap()
            .payload
            .is_empty()
    );
    m.on_tx_done(TxOutcome::Sent, t(1));
    m.set_beacon_payload(Some(ThreadBeaconPayload {
        version: 2,
        native: false,
        joining_permitted: false,
        network_name: [b'x'; 16],
        ext_pan_id: [1; 8],
    }));
    m.on_rx(&psdu(&buf[..n]), &info(CH), t(2));
    let tx = tx_of(&actions(&mut m, t(2))).unwrap();
    let f = Frame::parse(frame_of(&tx)).unwrap();
    assert_eq!(f.frame_type(), FrameType::Beacon);
    assert_eq!(f.src_address(), ext(OWN_EXT));
    assert_eq!(f.src_pan_id(), Some(PAN));
    let b = crate::frame::Beacon::parse(f.payload()).unwrap();
    assert_eq!(
        ThreadBeaconPayload::parse(b.payload).unwrap().ext_pan_id,
        [1; 8]
    );
    m.on_tx_done(TxOutcome::Sent, t(3));
    assert_eq!(m.counters().tx_beacon, 2);
}

// ---------------------------------------------------------------------------
// Security hooks
// ---------------------------------------------------------------------------

#[test]
fn security_applied_once_on_tx_and_on_rx() {
    let mut m = mac_with(bare_caps(), RecordingSecurity::default(), 0);
    actions(&mut m, t(0));
    m.transmit(
        TxHandle(1),
        &secured_data_frame(0, short(PEER_SHORT), short(OWN_SHORT), b"plain"),
    )
    .unwrap();
    let (tx, at) = run_to_tx(&mut m, t(0));
    assert_eq!(m.security().tx_calls.as_slice(), &[OWN_EXT]);
    let f = Frame::parse(frame_of(&tx)).unwrap();
    assert_eq!(
        f.payload(),
        &[
            b'p' ^ 0x5a,
            b'l' ^ 0x5a,
            b'a' ^ 0x5a,
            b'i' ^ 0x5a,
            b'n' ^ 0x5a
        ]
    );
    assert_eq!(f.mic(), &[0xaa; 4]);
    assert!(tx.info.security_processed);
    // A retransmission is not secured again (same frame counter / bytes).
    m.on_tx_done(TxOutcome::Sent, at);
    let (tx2, _) = run_to_tx(&mut m, at + ACK_TIMEOUT);
    assert_eq!(tx2.psdu, tx.psdu);
    assert_eq!(m.security().tx_calls.len(), 1);

    // RX from an extended source: unsecured with that address.
    let mut sec = secured_data_frame(4, short(OWN_SHORT), ext(PEER_EXT), b"abc");
    {
        let mut tmp = RecordingSecurity::default();
        use crate::frame_security::FrameSecurity;
        tmp.secure_tx(&mut sec, &PEER_EXT).unwrap();
    }
    m.on_rx(&psdu(&sec), &info(CH), t(1_000_000));
    assert_eq!(m.security().rx_calls.as_slice(), &[PEER_EXT]);
    let ev = events(&mut m);
    let Some(Event::Received(rx)) = ev.iter().find(|e| matches!(e, Event::Received(_))) else {
        panic!("{ev:?}")
    };
    assert_eq!(rx.parse().unwrap().payload(), b"abc");
    assert_eq!(rx.security.unwrap().frame_counter, 0);

    // RX from a short source: needs the neighbor map.
    let mut sec = secured_data_frame(5, short(OWN_SHORT), short(PEER_SHORT), b"def");
    {
        let mut tmp = RecordingSecurity::default();
        use crate::frame_security::FrameSecurity;
        tmp.secure_tx(&mut sec, &PEER_EXT).unwrap();
    }
    m.on_rx(&psdu(&sec), &info(CH), t(1_000_001));
    assert_eq!(m.counters().rx_err_unknown_neighbor, 1);
    m.set_neighbor(PEER_SHORT, PEER_EXT).unwrap();
    m.on_rx(&psdu(&sec), &info(CH), t(1_000_002));
    assert_eq!(m.security().rx_calls.len(), 2);
    assert_eq!(m.security().rx_calls[1], PEER_EXT);

    // A bad MIC is dropped.
    let mut bad = sec.clone();
    let l = bad.len();
    bad[l - 1] = 0;
    m.on_rx(&psdu(&bad), &info(CH), t(1_000_003));
    assert_eq!(m.counters().rx_err_sec, 1);
}

#[test]
fn no_security_rejects_secured_tx() {
    let mut m = mac_with(bare_caps(), NoSecurity, 0);
    m.transmit(
        TxHandle(9),
        &secured_data_frame(0, short(PEER_SHORT), short(OWN_SHORT), b"x"),
    )
    .unwrap();
    actions(&mut m, t(0));
    assert_eq!(
        events(&mut m),
        [Event::TxDone {
            handle: TxHandle(9),
            result: Err(TxError::Security)
        }]
    );
}

#[test]
fn radio_tx_security_leaves_frame_to_radio() {
    let mut caps = bare_caps();
    caps.phy = Capabilities::TRANSMIT_SEC;
    let mut m = mac_with(caps, RecordingSecurity::default(), 0);
    m.transmit(
        TxHandle(1),
        &secured_data_frame(0, short(PEER_SHORT), short(OWN_SHORT), b"p"),
    )
    .unwrap();
    let (tx, _) = run_to_tx(&mut m, t(0));
    assert!(!tx.info.security_processed);
    assert!(m.security().tx_calls.is_empty());
}

// ---------------------------------------------------------------------------
// Operation ordering
// ---------------------------------------------------------------------------

#[test]
fn poll_and_direct_alternate() {
    let mut m = sed();
    m.start_polling(short(ShortAddress(0x0400)), t(0));
    m.transmit(TxHandle(1), &unicast(0)).unwrap();
    m.send_data_poll(t(0)).unwrap();
    m.transmit(TxHandle(2), &unicast(0)).unwrap();
    // Direct first (it was queued first and no poll-before-data yet), then
    // the poll is prioritised over the next direct frame.
    let mut kinds = Vec::new();
    for _ in 0..3 {
        let tx = tx_of(&actions(&mut m, t(1))).unwrap();
        let f = Frame::parse(frame_of(&tx)).unwrap();
        kinds.push(f.frame_type());
        let ack = psdu(&imm_ack(f.sequence().unwrap(), false));
        m.on_tx_done(
            TxOutcome::Acked {
                ack: &ack,
                info: info(CH),
            },
            t(1),
        );
    }
    assert_eq!(kinds, [FrameType::Data, FrameType::MacCmd, FrameType::Data]);
}

#[test]
fn custom_queue_capacities() {
    use crate::frame_security::NoSecurity;
    // direct 1, indirect 2, events 2, polls 1, neighbors 1.
    let mut m: Mac<NoSecurity, FakeRng, 1, 2, 2, 1, 1> =
        Mac::with_capacities(bare_caps(), OWN_EXT, NoSecurity, FakeRng::new(0));
    let f = data_frame(0, short(PEER_SHORT), short(OWN_SHORT), true, b"x");
    m.transmit(TxHandle(1), &f).unwrap();
    assert_eq!(
        m.transmit(TxHandle(2), &f),
        Err(opentrust_core::Error::NoBufs)
    );
    let child = short(ShortAddress(0x3000));
    m.transmit_indirect(TxHandle(3), child, &f).unwrap();
    m.transmit_indirect(TxHandle(4), child, &f).unwrap();
    assert_eq!(
        m.transmit_indirect(TxHandle(5), child, &f),
        Err(opentrust_core::Error::NoBufs)
    );
    m.set_neighbor(PEER_SHORT, PEER_EXT).unwrap();
    assert!(m.set_neighbor(ShortAddress(0x3000), PEER_EXT).is_err());
}
