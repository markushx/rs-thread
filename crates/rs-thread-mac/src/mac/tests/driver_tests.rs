//! End-to-end tests of `MacDriver` with `TestRadio` and `MockClock`.

extern crate std;

use core::pin::pin;

use embassy_futures::{block_on, poll_once};
use rs_thread_core::time::Duration;
use rs_thread_platform::radio::RadioCaps;
use rs_thread_platform::radio::sim::{RadioState, TestRadio};
use rs_thread_platform::time::{MockAlarm, MockClock};

use super::util::*;
use crate::frame::Frame;
use crate::frame_security::NoSecurity;
use crate::mac::*;

type Driver<'a> = MacDriver<TestRadio, &'a MockClock, MockAlarm<'a>, NoSecurity, FakeRng>;

fn driver<'a>(clock: &'a MockClock, radio: TestRadio, rng: u32) -> Driver<'a> {
    let mut d = block_on(MacDriver::init(
        radio,
        clock,
        clock.alarm(),
        OWN_EXT,
        NoSecurity,
        FakeRng::new(rng),
    ))
    .unwrap();
    d.mac().set_pan_id(PAN);
    d.mac().set_short_address(OWN_SHORT);
    d.mac().set_channel(CH).unwrap();
    d
}

#[test]
fn offload_radio_transmit_and_receive() {
    let clock = MockClock::new();
    // TestRadio::new(): full MAC offload but no PHY CSMA/ACK timeout: with a
    // zero backoff nothing needs time to pass, so block_on suffices.
    let mut d = driver(&clock, TestRadio::new(), 0);
    let f = data_frame(0, short(PEER_SHORT), short(OWN_SHORT), true, b"hello");
    d.mac().transmit(TxHandle(1), &f).unwrap();
    d.radio().queue_ack(&psdu(&imm_ack(0, true)), info(CH));

    let ev = block_on(d.next_event());
    assert_eq!(
        ev,
        Event::TxDone {
            handle: TxHandle(1),
            result: Ok(TxSuccess {
                frame_pending: true,
                retries: 0
            })
        }
    );
    let rec = d.radio().pop_tx().unwrap();
    assert_eq!(rec.channel, CH);
    let sent = Frame::parse_with_fcs(&rec.psdu).unwrap();
    assert_eq!(sent.payload(), b"hello");
    assert_eq!(d.radio().config().pan_id, Some(PAN.0));
    assert_eq!(d.radio().config().short_addr, Some(OWN_SHORT.0));
    assert_eq!(d.radio().state(), RadioState::Receive { channel: CH });

    // Receive a frame.
    let rx = data_frame(3, short(OWN_SHORT), short(PEER_SHORT), true, b"in");
    assert!(d.radio().inject_rx(&psdu(&rx), info(CH)));
    let Event::Received(r) = block_on(d.next_event()) else {
        panic!()
    };
    assert_eq!(r.parse().unwrap().payload(), b"in");
    // The radio acks in hardware: nothing was transmitted.
    assert_eq!(d.radio().tx_pending(), 0);
}

#[test]
fn wake_future_returns_when_idle() {
    let clock = MockClock::new();
    let mut d = driver(&clock, TestRadio::new(), 0);
    let r = block_on(d.run_until(core::future::ready(42)));
    assert_eq!(r, RunResult::Woken(42));
    // Configuration was applied before idling.
    assert_eq!(d.radio().state(), RadioState::Receive { channel: CH });
}

#[test]
fn bare_phy_csma_backoff_and_software_ack_timing() {
    let clock = MockClock::new();
    let mut d = driver(&clock, TestRadio::with_caps(RadioCaps::default()), u32::MAX);
    d.mac().config_mut().max_frame_retries_direct = 1;
    let f = data_frame(0, short(PEER_SHORT), short(OWN_SHORT), true, b"x");
    d.mac().transmit(TxHandle(1), &f).unwrap();

    let backoff = UNIT_BACKOFF_PERIOD.saturating_mul(7); // BE 3, r = 7
    {
        let mut fut = pin!(d.next_event());
        assert!(poll_once(fut.as_mut()).is_pending());
        clock.advance(backoff - Duration::from_micros(1));
        assert!(poll_once(fut.as_mut()).is_pending());
        clock.advance(Duration::from_micros(1));
        // Transmitted; now waiting for the ACK in software.
        assert!(poll_once(fut.as_mut()).is_pending());
    } // dropped while idle: cancellation-safe
    let rec = d.radio().pop_tx().unwrap();
    assert!(rec.cca_threshold.is_some());
    let seq = Frame::parse_with_fcs(&rec.psdu)
        .unwrap()
        .sequence()
        .unwrap();

    // No ACK: after 16 ms a retransmission after the (zero) NO_ACK delay
    // and a fresh CSMA backoff.
    {
        let mut fut = pin!(d.next_event());
        assert!(poll_once(fut.as_mut()).is_pending());
        clock.advance(ACK_TIMEOUT);
        assert!(poll_once(fut.as_mut()).is_pending());
        clock.advance(backoff);
        assert!(poll_once(fut.as_mut()).is_pending());
    }
    let rec = d.radio().pop_tx().unwrap();
    assert!(rec.info.retransmission);

    // The ACK arrives through receive().
    assert!(d.radio().inject_rx(&psdu(&imm_ack(seq, false)), info(CH)));
    let ev = block_on(d.next_event());
    assert_eq!(
        ev,
        Event::TxDone {
            handle: TxHandle(1),
            result: Ok(TxSuccess {
                frame_pending: false,
                retries: 1
            })
        }
    );
}

#[test]
fn bare_phy_sends_software_ack() {
    let clock = MockClock::new();
    let mut d = driver(&clock, TestRadio::with_caps(RadioCaps::default()), 0);
    // Bring the radio into receive.
    let _ = block_on(d.run_until(core::future::ready(())));
    let rx = data_frame(0x55, short(OWN_SHORT), short(PEER_SHORT), true, b"q");
    assert!(d.radio().inject_rx(&psdu(&rx), info(CH)));
    let Event::Received(_) = block_on(d.next_event()) else {
        panic!()
    };
    let ack = d.radio().pop_tx().unwrap();
    assert_eq!(&ack.psdu[..3], &[0x02, 0x10, 0x55]);
    assert_eq!(ack.cca_threshold, None);
}

#[test]
fn energy_scan_through_driver() {
    let clock = MockClock::new();
    let mut d = driver(&clock, TestRadio::new(), 0);
    d.radio().set_energy_rssi(-63);
    d.mac()
        .energy_scan((1 << 11) | (1 << 26), Duration::from_millis(5))
        .unwrap();
    assert_eq!(
        block_on(d.next_event()),
        Event::EnergyScanResult {
            channel: 11,
            max_rssi: -63
        }
    );
    assert_eq!(
        block_on(d.next_event()),
        Event::EnergyScanResult {
            channel: 26,
            max_rssi: -63
        }
    );
    assert_eq!(block_on(d.next_event()), Event::EnergyScanDone);
}
