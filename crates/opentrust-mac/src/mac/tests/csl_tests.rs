//! CSL receiver and transmitter: phase math, sample windows, scheduling,
//! guard times, CSL IE refresh on retransmission, enhanced ACK CSL IE.

extern crate std;

use core::cell::Cell;
use std::vec::Vec;

use opentrust_core::crypto::{SecurityLevel, SoftCrypto};
use opentrust_core::time::Instant;
use opentrust_core::types::{ExtAddress, NetworkKey, ShortAddress};
use opentrust_platform::radio::{
    Capabilities, CslConfig, PsduRxInfo, RadioCaps, RadioClock, RadioErrorKind,
};

use super::util::*;
use crate::frame::{
    Address, CslIe, Frame, FrameBuilder, FrameType, FrameVersion, KeyIdentifier, SecurityHeader,
};
use crate::mac::*;
use crate::security::KeyManager;

std::thread_local! {
    static RADIO_US: Cell<u64> = const { Cell::new(0) };
}

fn radio_us() -> u64 {
    RADIO_US.with(Cell::get)
}

fn set_radio(us: u64) {
    RADIO_US.with(|c| c.set(us));
}

const PARENT_EXT: ExtAddress = ExtAddress([0x30; 8]);
const PARENT_SHORT: ShortAddress = ShortAddress(0x3000);
const CHILD_EXT: ExtAddress = ExtAddress([0x40; 8]);
const NK: [u8; 16] = [7; 16];
/// 500 ms.
const PERIOD: u16 = 3125;

fn clock_caps(extra: Capabilities) -> RadioCaps {
    let mut c = bare_caps();
    c.phy |= extra;
    c.clock = Some(RadioClock(radio_us));
    c.csl_accuracy_ppm = 20;
    c.csl_uncertainty = 5;
    c
}

type SecMac = Mac<KeyManager<SoftCrypto>, FakeRng>;

fn sec_mac(caps: RadioCaps, ext: ExtAddress) -> SecMac {
    let km = KeyManager::new(SoftCrypto, NetworkKey(NK));
    let mut m = Mac::new(caps, ext, km, FakeRng::new(0));
    m.set_pan_id(PAN);
    m.set_channel(CH).unwrap();
    m
}

fn plain_mac(caps: RadioCaps) -> TestMac {
    mac(caps, 0)
}

// ---------------------------------------------------------------- math

#[test]
fn csl_phase_math() {
    // Next sample 8 ms after the frame, period 16 ms: 50 units of 160 us.
    assert_eq!(csl_phase(10_000, 2_000, 100), 50);
    // Wrapping 32-bit radio clock.
    assert_eq!(csl_phase(1_000, u32::MAX - 999, 100), 2_000 / 160);
    // Exactly one period away is phase 0, just short of it the maximum.
    assert_eq!(csl_phase(16_000, 0, 100), 0);
    assert_eq!(csl_phase(15_999, 0, 100), 99);
}

#[test]
fn csl_window_edges_math() {
    // Period 500 ms (semi period 250 ms), 10 s since the last sync, own
    // 20 ppm + parent 30 ppm = 500 us drift; parent uncertainty 100 us, own
    // 50 us.
    let parent = CslAccuracy {
        clock_ppm: 30,
        uncertainty_10us: 10,
    };
    let (ahead, after) = window_edges(PERIOD, 10_000_000, 20, 5, parent);
    let semi_window = 500 + 100 + 50;
    assert_eq!(
        ahead,
        semi_window + MIN_RECEIVE_ON_AHEAD + CSL_RECEIVE_TIME_AHEAD
    );
    assert_eq!(ahead, 1162);
    assert_eq!(after, semi_window + MIN_RECEIVE_ON_AFTER);
    assert_eq!(after, 6154);
    // Never wider than half a period.
    let (ahead, after) = window_edges(100, u32::MAX, 20, 5, CslAccuracy::WORST);
    assert_eq!((ahead, after), (8_000, 8_000));
    // Right after a sync only the uncertainties count.
    let (ahead, _) = window_edges(PERIOD, 0, 20, 5, parent);
    assert_eq!(ahead, 100 + 50 + 192 + 320);
}

#[test]
fn csl_next_tx_window_math() {
    // Child windows at last_rx + phase*160 + n*500 ms: 250 ms + 160 ms.
    let w = |now, ahead| next_tx_window(now, PERIOD, 1000, 250_000, ahead);
    assert_eq!(w(1_000_000, 2_000), (1_410_000, 1_160_000, 408_000));
    // Window already passed in this period: the next one.
    assert_eq!(w(1_450_000, 2_000).0, 1_910_000);
    // Too close for the lead time: the next one, too.
    assert_eq!(w(1_409_000, 2_000).0, 1_910_000);
    assert_eq!(w(1_407_000, 2_000).0, 1_410_000);
    // No lead time: still reachable.
    assert_eq!(w(1_409_000, 0), (1_410_000, 1_160_000, 1_000));
}

// ------------------------------------------------------------ receiver

fn csl_actions(m: &mut TestMac, now: Instant) -> Vec<RadioAction> {
    actions(m, now)
        .into_iter()
        .filter(|a| {
            !matches!(
                a,
                RadioAction::SetMacKeys(_) | RadioAction::SetMacFrameCounter { .. }
            )
        })
        .collect()
}

#[test]
fn csl_receiver_hw_window_lead() {
    // A radio that needs its windows handed over early: the window timer
    // fires `receive_at_lead_us` before the window start, the window itself
    // (radio time) stays where it is.
    set_radio(1_000_000);
    let mut caps = clock_caps(Capabilities::RECEIVE_TIMING);
    caps.receive_at_lead_us = 3000;
    let mut m = plain_mac(caps);
    m.set_rx_on_when_idle(false);
    m.set_csl(PERIOD, 0, PARENT_SHORT, PARENT_EXT, t(0))
        .unwrap();
    let ahead = 250_000 - CSL_RECEIVE_TIME_AHEAD;
    let acts = csl_actions(&mut m, t(0));
    let win = RadioAction::ReceiveAt {
        channel: CH,
        start_us: 1_000_000 - u64::from(ahead),
        duration_us: ahead + 250_000,
    };
    assert!(acts.contains(&win), "{acts:?}");
    assert_eq!(m.next_deadline(), Some(t(500_000 - 250_000 - 3000)));
}

#[test]
fn csl_receiver_hw_windows() {
    set_radio(1_000_000);
    let mut m = plain_mac(clock_caps(Capabilities::RECEIVE_TIMING));
    m.set_rx_on_when_idle(false);
    assert_eq!(
        m.set_csl(10, 0, PARENT_SHORT, PARENT_EXT, t(0)),
        Err(opentrust_core::Error::InvalidArgs)
    );
    m.set_csl(PERIOD, 0, PARENT_SHORT, PARENT_EXT, t(0))
        .unwrap();
    let acts = csl_actions(&mut m, t(0));
    // Never synchronized: the window is half a period on each side.
    let expect_cfg = |sample| {
        RadioAction::SetCsl(CslConfig {
            period: u32::from(PERIOD),
            short_addr: PARENT_SHORT.0,
            ext_addr: ext_to_u64(&PARENT_EXT),
            sample_time_us: sample,
        })
    };
    assert!(acts.contains(&expect_cfg(1_500_000)), "{acts:?}");
    assert!(acts.contains(&RadioAction::Sleep));
    // The window is handed over once the radio sleeps.
    let ahead = 250_000 - CSL_RECEIVE_TIME_AHEAD;
    let win = RadioAction::ReceiveAt {
        channel: CH,
        start_us: 1_000_000 - u64::from(ahead),
        duration_us: ahead + 250_000,
    };
    assert!(acts.contains(&win), "{acts:?}");
    // Next timer: one period after the sample, `ahead` earlier.
    assert_eq!(m.next_deadline(), Some(t(500_000 - 250_000)));

    // Parent frame acked by the radio with a secured enhanced ACK at
    // radio time 1_100_000 synchronizes: the next window is tight.
    set_radio(1_100_000);
    let mut i = info(CH);
    i.timestamp_us = Some(1_100_000);
    i.ack_security = Some(opentrust_platform::radio::AckSecurity {
        frame_counter: 0,
        key_id: 1,
    });
    let f = data_frame(0, short(OWN_SHORT), ext(PARENT_EXT), false, b"x");
    m.on_rx(&psdu(&f), &i, t(100_000));
    set_radio(1_250_000);
    let acts = csl_actions(&mut m, t(250_000));
    // Elapsed 150 ms: drift 150000 * (20 + 255) / 1e6 = 41 us.
    let semi_window = 41 + 2550 + 50;
    let ahead = semi_window + MIN_RECEIVE_ON_AHEAD; // minus CSL_RECEIVE_TIME_AHEAD + that
    let after = semi_window + MIN_RECEIVE_ON_AFTER;
    let win = RadioAction::ReceiveAt {
        channel: CH,
        start_us: 1_500_000 - u64::from(ahead),
        duration_us: ahead + after,
    };
    assert!(acts.contains(&win), "{acts:?}");
    assert!(acts.contains(&expect_cfg(2_000_000)), "{acts:?}");

    // Off again.
    m.set_csl(0, 0, PARENT_SHORT, PARENT_EXT, t(250_001))
        .unwrap();
    let acts = csl_actions(&mut m, t(250_001));
    assert!(
        acts.iter()
            .any(|a| matches!(a, RadioAction::SetCsl(c) if !c.enabled()))
    );
    assert_eq!(m.next_deadline(), None);
}

#[test]
fn csl_receiver_software_sampling() {
    set_radio(0);
    let mut m = plain_mac(clock_caps(Capabilities::empty()));
    m.set_rx_on_when_idle(false);
    m.set_csl(PERIOD, 22, PARENT_SHORT, PARENT_EXT, t(0))
        .unwrap();
    // Unsynchronized: sampling starts right away, on the CSL channel, for
    // `after` (half a period) after the first sample time.
    let acts = csl_actions(&mut m, t(0));
    assert!(
        acts.contains(&RadioAction::Receive { channel: 22 }),
        "{acts:?}"
    );
    assert!(!acts.iter().any(|a| matches!(a, RadioAction::SetCsl(_))));
    assert_eq!(m.next_deadline(), Some(t(250_000)));

    // The parent's frame acked with a secured enhanced ACK at 100 ms
    // synchronizes.
    set_radio(100_000);
    let mut i = info(22);
    i.timestamp_us = Some(100_000);
    i.ack_security = Some(opentrust_platform::radio::AckSecurity {
        frame_counter: 0,
        key_id: 1,
    });
    let f = data_frame(0, short(OWN_SHORT), ext(PARENT_EXT), false, b"x");
    m.on_rx(&psdu(&f), &i, t(100_000));

    // Window over at half a period (timer armed unsynchronized): sleep until
    // `ahead` before the next sample time (500 ms): drift of 150 ms with
    // 20 + 255 ppm is 41 us, plus 2550 + 50 us uncertainty.
    set_radio(250_000);
    let acts = csl_actions(&mut m, t(250_000));
    assert_eq!(acts, [RadioAction::Sleep]);
    let ahead = 41 + 2550 + 50 + MIN_RECEIVE_ON_AHEAD + CSL_RECEIVE_TIME_AHEAD;
    assert_eq!(m.next_deadline(), Some(t(500_000 - u64::from(ahead))));
    // Wake up: listen on the CSL channel until `after` the sample time.
    let wake = 500_000 - u64::from(ahead);
    set_radio(wake);
    let acts = csl_actions(&mut m, t(wake));
    assert_eq!(acts, [RadioAction::Receive { channel: 22 }]);
    let drift = (wake - 100_000) * 275 / 1_000_000;
    let after = drift + 2550 + 50 + u64::from(MIN_RECEIVE_ON_AFTER);
    assert_eq!(m.next_deadline(), Some(t(500_000 + after)));
    set_radio(500_000 + after);
    let acts = csl_actions(&mut m, t(500_000 + after));
    assert_eq!(acts, [RadioAction::Sleep]);
}

// ------------------------------------------------ CSL IE in own frames

/// 2015 secured data frame to the parent with a CSL IE placeholder.
fn csl_frame(seq: u8) -> Vec<u8> {
    let mut buf = [0u8; 127];
    let n = FrameBuilder::new(&mut buf)
        .frame_type(FrameType::Data)
        .version(FrameVersion::V2015)
        .sequence(seq)
        .pan_id(PAN)
        .dst(Address::Extended(PARENT_EXT))
        .src(Address::Extended(CHILD_EXT))
        .ack_request(true)
        .security(SecurityHeader::new(
            SecurityLevel::EncMic32,
            0,
            KeyIdentifier::Index(1),
        ))
        .header_ie(CslIe {
            phase: 0,
            period: 0,
            rendezvous_time: None,
        })
        .payload(b"csl payload")
        .build()
        .unwrap();
    buf[..n].to_vec()
}

#[test]
fn csl_ie_updated_and_resecured_on_retransmission_software() {
    set_radio(5_000);
    let mut child = sec_mac(clock_caps(Capabilities::RECEIVE_TIMING), CHILD_EXT);
    child.set_rx_on_when_idle(false);
    child
        .set_csl(PERIOD, 0, PARENT_SHORT, PARENT_EXT, t(0))
        .unwrap();
    let mut parent_sec = KeyManager::new(SoftCrypto, NetworkKey(NK));

    let f = csl_frame(0);
    child.transmit(TxHandle(1), &f).unwrap();
    set_radio(10_000);
    let mut sent = Vec::new();
    let mut acts = actions_sec(&mut child, t(10_000));
    let mut seqs = Vec::new();
    for round in 0..2u64 {
        let tx = tx_of(&acts).expect("transmit");
        assert!(tx.info.security_processed);
        // The frame as it goes out: CSL IE with the phase of the next
        // sample as of ~now + CCA + SHR, secured with a fresh counter.
        let fr = Frame::parse(frame_of(&tx)).unwrap();
        let ie = fr.csl_ie().unwrap();
        assert_eq!(ie.period, PERIOD);
        let sfd = (radio_us() as u32) + CCA_SAMPLE_INTERVAL + SHR_DURATION;
        assert_eq!(ie.phase, csl_phase(child.csl_sample_time(), sfd, PERIOD));
        let fc = fr.security_header().unwrap().frame_counter.unwrap();
        seqs.push(fr.sequence().unwrap());
        sent.push((ie.phase, fc, frame_of(&tx).to_vec()));
        // No ACK: the software ACK timeout, then the retransmission delay.
        child.on_tx_done(TxOutcome::Sent, t(10_000 + round * 100_000 + 1));
        set_radio(radio_us() + 100_000);
        acts = actions_sec(&mut child, t(10_000 + (round + 1) * 100_000));
    }
    // Same sequence number, new frame counter, new phase.
    assert_eq!(seqs[0], seqs[1]);
    assert_eq!(sent[1].1, sent[0].1 + 1);
    assert_ne!(sent[0].0, sent[1].0);
    // Both verify with the parent's key manager.
    for (_, _, mut fr) in sent {
        use crate::frame_security::FrameSecurity;
        let rx = parent_sec
            .unsecure_rx(&mut fr, &CHILD_EXT)
            .unwrap()
            .unwrap();
        assert_eq!(rx.level, SecurityLevel::EncMic32);
        assert_eq!(Frame::parse(&fr).unwrap().payload()[..11], *b"csl payload");
    }
}

fn actions_sec(m: &mut SecMac, now: Instant) -> Vec<RadioAction> {
    let mut v = Vec::new();
    while let Some(a) = m.poll_action(now) {
        let stop = matches!(a, RadioAction::Transmit(_));
        v.push(a);
        if stop {
            break;
        }
    }
    v
}

#[test]
fn csl_ie_filled_by_radio_with_transmit_sec() {
    set_radio(5_000);
    let mut child = sec_mac(
        clock_caps(Capabilities::RECEIVE_TIMING | Capabilities::TRANSMIT_SEC),
        CHILD_EXT,
    );
    child.set_rx_on_when_idle(false);
    child
        .set_csl(PERIOD, 0, PARENT_SHORT, PARENT_EXT, t(0))
        .unwrap();
    let f = csl_frame(0);
    child.transmit(TxHandle(1), &f).unwrap();
    let acts = actions_sec(&mut child, t(1_000));
    let tx = tx_of(&acts).unwrap();
    // The radio does it all: IE and security.
    assert!(tx.info.csl_present);
    assert!(!tx.info.security_processed);
    assert!(!tx.info.header_updated);
    assert!(!tx.info.retransmission);
    // After a failed attempt the retransmission is flagged; the radio tells
    // what it assigned (header updated, not secured in the buffer).
    let mut psdu_after = tx.psdu.clone();
    let n = psdu_after.len() - 2;
    crate::frame::FrameMut::new(&mut psdu_after[..n])
        .unwrap()
        .set_csl_ie(77, PERIOD)
        .unwrap();
    child.on_tx_frame_updated(
        &psdu_after,
        &opentrust_platform::radio::PsduTxInfo {
            header_updated: true,
            csl_present: true,
            ..tx.info
        },
    );
    child.on_tx_done(TxOutcome::Sent, t(1_001));
    let acts = actions_sec(&mut child, t(20_000));
    let acts2 = actions_sec(&mut child, t(20_000));
    let all: Vec<_> = acts.into_iter().chain(acts2).collect();
    let tx = tx_of(&all).expect("retransmission");
    assert!(tx.info.csl_present);
    assert!(tx.info.retransmission);
    assert!(tx.info.header_updated);
}

// ---------------------------------------------------- enhanced ACK IE

#[test]
fn enh_ack_to_parent_carries_csl_ie() {
    set_radio(1_000_000);
    let mut child = sec_mac(clock_caps(Capabilities::RECEIVE_TIMING), CHILD_EXT);
    child.set_rx_on_when_idle(false);
    child
        .set_csl(PERIOD, 0, PARENT_SHORT, PARENT_EXT, t(0))
        .unwrap();
    actions_sec(&mut child, t(0));
    let mut parent = sec_mac(bare_caps(), PARENT_EXT);
    // Parent -> child: secured 2015 frame requesting an ACK.
    let mut buf = [0u8; 127];
    let n = FrameBuilder::new(&mut buf)
        .frame_type(FrameType::Data)
        .version(FrameVersion::V2015)
        .sequence(5)
        .pan_id(PAN)
        .dst(Address::Extended(CHILD_EXT))
        .src(Address::Extended(PARENT_EXT))
        .ack_request(true)
        .security(SecurityHeader::new(
            SecurityLevel::EncMic32,
            0,
            KeyIdentifier::Index(1),
        ))
        .payload(b"hi")
        .build()
        .unwrap();
    parent.transmit(TxHandle(1), &buf[..n]).unwrap();
    let tx = tx_of(&actions_sec(&mut parent, t(0))).unwrap();
    let mut i: PsduRxInfo = info(CH);
    i.timestamp_us = Some(1_300_000);
    set_radio(1_300_500);
    child.on_rx(&tx.psdu, &i, t(300_000));
    let ack = tx_of(&actions_sec(&mut child, t(300_001))).expect("enh-ACK");
    child.on_tx_done(TxOutcome::Sent, t(300_002));
    let fr = Frame::parse(frame_of(&ack)).unwrap();
    assert_eq!(fr.frame_type(), FrameType::Ack);
    assert!(fr.security_enabled());
    // ACK SFD: frame end (PHR + PSDU) + 192 us turnaround + 160 us SHR.
    let sfd = 1_300_000u32 + (tx.psdu.len() as u32 + 1) * 32 + TURNAROUND_TIME + SHR_DURATION;
    let ie = fr.csl_ie().unwrap();
    assert_eq!(ie.period, PERIOD);
    assert_eq!(ie.phase, csl_phase(child.csl_sample_time(), sfd, PERIOD));
    // The parent can use it: verify and read it.
    let mut ackf = frame_of(&ack).to_vec();
    use crate::frame_security::FrameSecurity;
    parent
        .security_mut()
        .unsecure_rx(&mut ackf, &CHILD_EXT)
        .unwrap();

    // An ACK to anybody else has none.
    let mut buf2 = [0u8; 127];
    let n = FrameBuilder::new(&mut buf2)
        .frame_type(FrameType::Data)
        .version(FrameVersion::V2015)
        .sequence(6)
        .pan_id(PAN)
        .dst(Address::Extended(CHILD_EXT))
        .src(Address::Extended(ExtAddress([0x55; 8])))
        .ack_request(true)
        .payload(b"hi")
        .build()
        .unwrap();
    let mut p = Psdu::from_slice(&buf2[..n]).unwrap();
    p.extend_from_slice(&fcs(&buf2[..n])).unwrap();
    child.on_rx(&p, &i, t(300_100));
    let ack = tx_of(&actions_sec(&mut child, t(300_101))).expect("ACK");
    assert!(Frame::parse(frame_of(&ack)).unwrap().csl_ie().is_none());
}

// -------------------------------------------------------- transmitter

fn child_frame_with_csl(km: &mut KeyManager<SoftCrypto>, phase: u16) -> Psdu {
    use crate::frame_security::FrameSecurity;
    let mut buf = [0u8; 127];
    let n = FrameBuilder::new(&mut buf)
        .frame_type(FrameType::Data)
        .version(FrameVersion::V2015)
        .sequence(1)
        .pan_id(PAN)
        .dst(Address::Extended(PARENT_EXT))
        .src(Address::Extended(CHILD_EXT))
        .ack_request(false)
        .security(SecurityHeader::new(
            SecurityLevel::EncMic32,
            0,
            KeyIdentifier::Index(1),
        ))
        .header_ie(CslIe {
            phase,
            period: PERIOD,
            rendezvous_time: None,
        })
        .payload(b"up")
        .build()
        .unwrap();
    km.secure_tx(&mut buf[..n], &CHILD_EXT).unwrap();
    let mut p = Psdu::from_slice(&buf[..n]).unwrap();
    p.extend_from_slice(&fcs(&buf[..n])).unwrap();
    p
}

fn parent_caps(timing: bool) -> RadioCaps {
    let mut c = full_caps();
    if timing {
        c.phy |= Capabilities::TRANSMIT_TIMING;
    }
    c.clock = Some(RadioClock(radio_us));
    c
}

fn parent_mac(timing: bool) -> SecMac {
    let mut m = sec_mac(parent_caps(timing), PARENT_EXT);
    m.set_short_address(PARENT_SHORT);
    m
}

fn queue_downlink(m: &mut SecMac, handle: u16) {
    let mut buf = [0u8; 127];
    let n = FrameBuilder::new(&mut buf)
        .frame_type(FrameType::Data)
        .version(FrameVersion::V2015)
        .sequence(0)
        .pan_id(PAN)
        .dst(Address::Extended(CHILD_EXT))
        .src(Address::Extended(PARENT_EXT))
        .ack_request(true)
        .security(SecurityHeader::new(
            SecurityLevel::EncMic32,
            0,
            KeyIdentifier::Index(1),
        ))
        .payload(b"down")
        .build()
        .unwrap();
    m.transmit_indirect(TxHandle(handle), Address::Extended(CHILD_EXT), &buf[..n])
        .unwrap();
}

fn sync_child(m: &mut SecMac, at_us: u64, phase: u16) {
    let mut child_km = KeyManager::new(SoftCrypto, NetworkKey(NK));
    let p = child_frame_with_csl(&mut child_km, phase);
    let mut i = info(CH);
    i.timestamp_us = Some(at_us);
    m.on_rx(&p, &i, t(0));
}

#[test]
fn csl_tx_scheduling_with_timed_transmit() {
    set_radio(1_000_000);
    let mut m = parent_mac(true);
    let child = Address::Extended(CHILD_EXT);
    m.csl_add_child(child).unwrap();
    queue_downlink(&mut m, 9);
    // Not synchronized: nothing is scheduled; the frame waits for a poll.
    actions_sec(&mut m, t(0));
    assert_eq!(m.next_deadline(), None);

    // The child's frame (CSL IE: phase 1000 = 160 ms) was received at radio
    // time 250 ms: its windows are 410 ms + n * 500 ms.
    sync_child(&mut m, 250_000, 1000);
    let c = *m.csl_child(child).unwrap();
    assert!(c.synchronized);
    assert_eq!(
        (c.period, c.phase, c.last_rx_timestamp_us),
        (PERIOD, 1000, 250_000)
    );
    let _ = events(&mut m);
    let acts = actions_sec(&mut m, t(0));
    assert!(tx_of(&acts).is_none());
    // Next window 1_410_000; the frame is requested 2 ms ahead: in 408 ms.
    assert_eq!(m.csl_request_ahead_us(), 2_000);
    assert_eq!(m.next_deadline(), Some(t(408_000)));

    // At that time the transmit goes to the radio, timed for the window.
    set_radio(1_408_000);
    let acts = actions_sec(&mut m, t(408_000));
    let tx = tx_of(&acts).expect("csl tx");
    assert_eq!(tx.info.tx_at_us, Some(1_410_000));
    assert_eq!(tx.info.max_csma_backoffs, Some(0));
    assert_eq!(tx.cca_threshold, Some(m.config().cca_threshold));
    assert_eq!(m.operation(), Operation::TransmitDataCsl);
    // ACKed: done, nothing left to schedule.
    m.on_tx_done(
        TxOutcome::Acked {
            ack: &psdu(&imm_ack(seq_of(&tx), false)),
            info: info(CH),
        },
        t(408_500),
    );
    let ev = events(&mut m);
    assert!(matches!(
        &ev[..],
        [Event::TxDone {
            handle: TxHandle(9),
            result: Ok(_)
        }]
    ));
    assert_eq!(m.indirect_len(), 0);
    actions_sec(&mut m, t(409_000));
    assert_eq!(m.next_deadline(), None);
}

#[test]
fn csl_tx_software_timing_without_transmit_timing() {
    set_radio(1_000_000);
    let mut m = parent_mac(false);
    m.csl_add_child(Address::Extended(CHILD_EXT)).unwrap();
    queue_downlink(&mut m, 1);
    sync_child(&mut m, 250_000, 1000);
    actions_sec(&mut m, t(0));
    assert_eq!(m.next_deadline(), Some(t(408_000)));
    set_radio(1_408_000);
    let acts = actions_sec(&mut m, t(408_000));
    // The MAC waits itself: transmit at window - (CCA + 40 + SHR) = 328 us
    // before the SFD time, i.e. 1672 us from now.
    assert!(tx_of(&acts).is_none());
    assert_eq!(m.next_deadline(), Some(t(408_000 + 2_000 - 328)));
    set_radio(1_409_672);
    let acts = actions_sec(&mut m, t(409_672));
    let tx = tx_of(&acts).expect("tx");
    assert_eq!(tx.info.tx_at_us, None);
}

#[test]
fn csl_tx_guard_time_skips_missed_window() {
    set_radio(1_000_000);
    let mut m = parent_mac(true);
    m.csl_add_child(Address::Extended(CHILD_EXT)).unwrap();
    queue_downlink(&mut m, 1);
    sync_child(&mut m, 250_000, 1000);
    actions_sec(&mut m, t(0));
    assert_eq!(m.next_deadline(), Some(t(408_000)));
    // The MAC was busy: it is called 3.6 ms late, 400 us past the window
    // (late by more than the request lead time + guard (2000 + 1500): the
    // next window is 497 ms away).
    set_radio(1_410_400);
    let acts = actions_sec(&mut m, t(410_400));
    assert!(tx_of(&acts).is_none());
    assert_eq!(m.operation(), Operation::Idle);
    assert_eq!(m.indirect_len(), 1);
    // Rescheduled for the window after: 1_910_000 - 2 ms.
    assert_eq!(
        m.next_deadline(),
        Some(t(410_400 + (1_910_000 - 2_000 - 1_410_400)))
    );

    // Late, but the window is still ahead: it goes.
    let mut m = parent_mac(true);
    set_radio(1_000_000);
    m.csl_add_child(Address::Extended(CHILD_EXT)).unwrap();
    queue_downlink(&mut m, 1);
    sync_child(&mut m, 250_000, 1000);
    actions_sec(&mut m, t(0));
    set_radio(1_409_000); // 1 ms late, the window is still 1 ms ahead
    let acts = actions_sec(&mut m, t(409_000));
    assert!(tx_of(&acts).is_some());
}

#[test]
fn csl_tx_failures_desync_child_and_keep_frame() {
    set_radio(1_000_000);
    let mut m = parent_mac(true);
    let child = Address::Extended(CHILD_EXT);
    m.csl_add_child(child).unwrap();
    queue_downlink(&mut m, 4);
    sync_child(&mut m, 250_000, 1000);
    let mut seqs = Vec::new();
    let mut counters = Vec::new();
    assert!(tx_of(&at(&mut m, 0)).is_none()); // arms the timer
    for attempt in 1..=MAX_CSL_TX_ATTEMPTS {
        // Next window: the same frame goes out again.
        let dl = m.next_deadline().unwrap().as_micros();
        let acts = at(&mut m, dl);
        let tx = tx_of(&acts).unwrap_or_else(|| panic!("attempt {attempt}: {acts:?}"));
        let fr = Frame::parse(frame_of(&tx)).unwrap();
        seqs.push(fr.sequence().unwrap());
        counters.push(fr.security_header().unwrap().frame_counter.unwrap());
        assert_eq!(tx.info.retransmission, attempt > 1);
        m.on_tx_done(TxOutcome::Failed(RadioErrorKind::TxAckTimeout), t(dl + 1));
        assert_eq!(m.indirect_len(), 1, "frame stays queued");
        at(&mut m, dl + 2); // arms the next window
    }
    // Same sequence number and frame counter for every attempt (OT keeps
    // them for CSL retransmissions).
    assert!(seqs.iter().all(|s| *s == seqs[0]));
    assert!(counters.iter().all(|c| *c == counters[0]));
    let ev = events(&mut m);
    assert!(ev.contains(&Event::CslChildOutOfSync(child)), "{ev:?}");
    assert!(!m.csl_child(child).unwrap().synchronized);
    // Out of sync: nothing scheduled any more; the frame waits for a poll.
    at(&mut m, 2_000_000);
    assert_eq!(m.next_deadline(), None);
    assert_eq!(m.indirect_len(), 1);
}

/// Poll at local time `us` with the radio clock 1 s ahead of it.
fn at(m: &mut SecMac, us: u64) -> Vec<RadioAction> {
    set_radio(1_000_000 + us);
    actions_sec(m, t(us))
}

#[test]
fn csl_child_table() {
    set_radio(0);
    let mut m = plain_mac(parent_caps(false));
    let a = Address::Extended(CHILD_EXT);
    m.csl_add_child(a).unwrap();
    m.csl_add_child(a).unwrap(); // idempotent
    assert_eq!(m.csl_children().len(), 1);
    m.csl_set_child_channel(a, 20).unwrap();
    assert_eq!(m.csl_child(a).unwrap().channel, 20);
    assert!(m.csl_remove_child(a));
    assert!(!m.csl_remove_child(a));
    assert_eq!(
        m.csl_set_child_channel(a, 20),
        Err(opentrust_core::Error::NotFound)
    );
    // Without a radio clock CSL is not possible.
    let mut m = plain_mac(bare_caps());
    assert_eq!(
        m.csl_add_child(a),
        Err(opentrust_core::Error::NotImplemented)
    );
    assert_eq!(
        m.set_csl(PERIOD, 0, PARENT_SHORT, PARENT_EXT, t(0)),
        Err(opentrust_core::Error::NotImplemented)
    );
}

#[test]
fn data_poll_of_csl_receiver_carries_csl_ie_and_is_not_retried() {
    set_radio(5_000);
    let mut child = sec_mac(clock_caps(Capabilities::RECEIVE_TIMING), CHILD_EXT);
    child.set_rx_on_when_idle(false);
    child
        .set_csl(PERIOD, 0, PARENT_SHORT, PARENT_EXT, t(0))
        .unwrap();
    child.start_polling(Address::Short(PARENT_SHORT), t(0));
    child.send_data_poll(t(10)).unwrap();
    set_radio(10_000);
    let acts = actions_sec(&mut child, t(10));
    let tx = tx_of(&acts).expect("poll");
    let fr = Frame::parse(frame_of(&tx)).unwrap();
    assert_eq!(fr.version(), FrameVersion::V2015);
    assert_eq!(fr.csl_ie().unwrap().period, PERIOD);
    // No ACK: no retransmission, the poll fails at once.
    child.on_tx_done(TxOutcome::AckTimeout, t(12));
    let _ = actions_sec(&mut child, t(30));
    assert!(
        events(&mut child)
            .iter()
            .any(|e| matches!(e, Event::DataPollSent(Err(_)))),
    );
}

#[test]
fn csl_tx_window_follows_resynchronization_after_drift() {
    set_radio(1_000_000);
    let mut m = parent_mac(true);
    let child = Address::Extended(CHILD_EXT);
    m.csl_add_child(child).unwrap();
    queue_downlink(&mut m, 1);
    // First sync: frame at 250 ms, phase 160 ms: windows 410 ms + n * 500 ms.
    sync_child(&mut m, 250_000, 1000);
    actions_sec(&mut m, t(0));
    assert_eq!(m.next_deadline(), Some(t(408_000)));
    // The child's clock drifted: a later poll with a CSL IE (received at
    // 700 ms, phase 100 ms) moves the windows to 800 ms + n * 500 ms; the
    // frame is requested 2 ms before the next one after "now" (1.0 s).
    sync_child(&mut m, 700_000, 625);
    let c = *m.csl_child(child).unwrap();
    assert_eq!((c.phase, c.last_rx_timestamp_us), (625, 700_000));
    actions_sec(&mut m, t(0));
    assert_eq!(m.next_deadline(), Some(t(298_000)));
    // A child that stops sending CSL IEs is desynchronized by MLE: back to
    // data polls, no CSL timer.
    m.csl_child_desync(child);
    actions_sec(&mut m, t(0));
    assert_eq!(m.next_deadline(), None);
    assert!(!m.csl_child(child).unwrap().synchronized);
    // The next CSL IE synchronizes it again.
    sync_child(&mut m, 1_700_000, 625);
    assert!(m.csl_child(child).unwrap().synchronized);
}

#[test]
fn csl_child_sample_tracks_an_unknown_child_from_its_ie() {
    set_radio(1_000_000);
    let mut m = parent_mac(true);
    let child = Address::Extended(CHILD_EXT);
    assert!(m.csl_child(child).is_none());
    let ie = crate::frame::CslIe {
        phase: 1000,
        period: PERIOD,
        rendezvous_time: None,
    };
    // A poll from a child the upper layer has not announced: the upper layer
    // hands over its CSL IE, the MAC tracks the child from then on.
    m.csl_child_sample(child, 0, ie, Some(250_000), t(0))
        .unwrap();
    let c = *m.csl_child(child).unwrap();
    assert!(c.synchronized);
    assert_eq!(
        (c.period, c.phase, c.last_rx_timestamp_us),
        (PERIOD, 1000, 250_000)
    );
    // Again: only the phase moves, nothing is tracked twice.
    let ie2 = crate::frame::CslIe { phase: 1200, ..ie };
    m.csl_child_sample(child, 0, ie2, Some(750_000), t(1))
        .unwrap();
    assert_eq!(m.csl_children().len(), 1);
    assert_eq!(m.csl_child(child).unwrap().phase, 1200);
    // A period below the minimum does not synchronize a new child.
    let other = Address::Extended(ExtAddress([9; 8]));
    let bad = crate::frame::CslIe { period: 1, ..ie };
    m.csl_child_sample(other, 0, bad, Some(1), t(2)).unwrap();
    assert!(!m.csl_child(other).unwrap().synchronized);
}
