use embassy_futures::{block_on, poll_once};

use super::sim::{RadioState, TestRadio, rx_info};
use super::*;

const DATA_NO_AR: [u8; 3] = [0x01, 0x80, 0x07];
const DATA_AR: [u8; 3] = [0x21, 0x80, 0x08];
const ACK: [u8; 3] = [0x02, 0x00, 0x08];

fn up(radio: &mut TestRadio, channel: u8) {
    block_on(async {
        radio.init().await.unwrap();
        radio.set_receive(channel).await.unwrap();
    });
}

#[test]
fn init_reports_caps_and_sleeps() {
    let mut r = TestRadio::new();
    assert_eq!(r.state(), RadioState::Uninit);
    let caps = block_on(r.init()).unwrap();
    assert_eq!(r.state(), RadioState::Sleep);
    assert!(caps.mac.contains(MacCapabilities::REQUIRED));
    assert!(caps.mac.missing_required().is_empty());
    assert!(caps.soft_mac_needs().contains(SoftMacNeeds::CSL));
}

#[test]
fn rx_inject_and_receive() {
    let mut r = TestRadio::new();
    up(&mut r, 15);
    assert!(r.inject_rx(&DATA_NO_AR, rx_info(15)));
    let mut buf = [0u8; 127];
    let info = block_on(r.receive(&mut buf)).unwrap();
    assert_eq!(info.len, 3);
    assert_eq!(info.channel, 15);
    assert_eq!(&buf[..3], &DATA_NO_AR);
    assert_eq!(r.rx_pending(), 0);
}

#[test]
fn receive_waits_and_is_cancellation_safe() {
    let mut r = TestRadio::new();
    up(&mut r, 11);
    let mut buf = [0u8; 127];
    {
        let mut fut = core::pin::pin!(r.receive(&mut buf));
        assert!(poll_once(fut.as_mut()).is_pending());
    } // cancelled
    assert!(r.inject_rx(&DATA_NO_AR, rx_info(11)));
    // A cancelled receive after injection must not lose the frame.
    {
        let mut fut = core::pin::pin!(r.receive(&mut buf));
        assert!(poll_once(fut.as_mut()).is_ready());
    }
    assert!(r.inject_rx(&DATA_AR, rx_info(11)));
    assert_eq!(r.rx_pending(), 1);
}

#[test]
fn sleeping_radio_drops_frames() {
    let mut r = TestRadio::new();
    up(&mut r, 11);
    assert!(r.inject_rx(&DATA_NO_AR, rx_info(11)));
    block_on(r.set_sleep()).unwrap();
    assert_eq!(r.rx_pending(), 0, "queued frames are not delivered late");
    assert!(!r.inject_rx(&DATA_NO_AR, rx_info(11)));
    let mut buf = [0u8; 127];
    let mut fut = core::pin::pin!(r.receive(&mut buf));
    assert!(poll_once(fut.as_mut()).is_pending());
}

#[test]
fn rx_queue_overflow_drops() {
    let mut r = TestRadio::new();
    up(&mut r, 11);
    for _ in 0..sim::QUEUE_LEN {
        assert!(r.inject_rx(&DATA_NO_AR, rx_info(11)));
    }
    assert!(!r.inject_rx(&DATA_NO_AR, rx_info(11)));
    assert_eq!(r.dropped_rx(), 1);
}

#[test]
fn receive_buffer_too_small() {
    let mut r = TestRadio::new();
    up(&mut r, 11);
    r.inject_rx(&DATA_NO_AR, rx_info(11));
    let mut buf = [0u8; 2];
    assert_eq!(
        block_on(r.receive(&mut buf)).unwrap_err(),
        RadioErrorKind::RxInvalid
    );
}

#[test]
fn transmit_records_frame_and_returns_to_receive() {
    let mut r = TestRadio::new();
    block_on(r.init()).unwrap();
    let mut psdu = DATA_NO_AR;
    let mut tx = PsduTxInfo::default();
    let ack = block_on(r.transmit(&mut psdu, &mut tx, 20, 5, Some(-70), None)).unwrap();
    assert!(ack.is_none());
    assert_eq!(r.state(), RadioState::Receive { channel: 20 });
    let rec = r.pop_tx().unwrap();
    assert_eq!(rec.psdu.as_slice(), &DATA_NO_AR);
    assert_eq!(
        (rec.channel, rec.power, rec.cca_threshold),
        (20, 5, Some(-70))
    );
    assert!(r.pop_tx().is_none());
}

#[test]
fn transmit_returns_queued_ack() {
    let mut r = TestRadio::new();
    up(&mut r, 11);
    assert!(r.queue_ack(&ACK, rx_info(11)));
    let mut psdu = DATA_AR;
    let mut tx = PsduTxInfo::default();
    let mut ack_buf = [0u8; 127];
    let info = block_on(r.transmit(&mut psdu, &mut tx, 11, 0, None, Some(&mut ack_buf)))
        .unwrap()
        .unwrap();
    assert_eq!(info.len, 3);
    assert_eq!(&ack_buf[..3], &ACK);
    // No ACK queued: ack timeout.
    let err =
        block_on(r.transmit(&mut psdu, &mut tx, 11, 0, None, Some(&mut ack_buf))).unwrap_err();
    assert_eq!(err, RadioErrorKind::RxAckTimeout);
    // Frames without AR never wait for an ACK.
    let mut psdu = DATA_NO_AR;
    assert!(
        block_on(r.transmit(&mut psdu, &mut tx, 11, 0, None, Some(&mut ack_buf)))
            .unwrap()
            .is_none()
    );
}

#[test]
fn transmit_failure_injection_and_invalid() {
    let mut r = TestRadio::new();
    up(&mut r, 11);
    r.fail_next_tx(RadioErrorKind::TxFailed);
    let mut psdu = DATA_NO_AR;
    let mut tx = PsduTxInfo::default();
    assert_eq!(
        block_on(r.transmit(&mut psdu, &mut tx, 11, 0, None, None)).unwrap_err(),
        RadioErrorKind::TxFailed
    );
    assert_eq!(r.tx_pending(), 1);
    assert!(block_on(r.transmit(&mut psdu, &mut tx, 11, 0, None, None)).is_ok());
    let mut empty: [u8; 0] = [];
    assert_eq!(
        block_on(r.transmit(&mut empty, &mut tx, 11, 0, None, None)).unwrap_err(),
        RadioErrorKind::TxInvalid
    );
}

#[test]
fn config_is_recorded() {
    let mut r = TestRadio::new();
    let cfg = Config {
        pan_id: Some(0xface),
        short_addr: Some(0x1234),
        ..Config::new()
    };
    let mut sm = SrcMatchConfig::new();
    sm.enabled = true;
    sm.short_addrs.push(0x1235).unwrap();
    let keys = MacKeys {
        key_id_mode: 1,
        key_id: 128,
        prev: [1; 16],
        curr: [2; 16],
        next: [3; 16],
    };
    block_on(async {
        r.set_config(&cfg).await.unwrap();
        r.set_src_match_config(&sm).await.unwrap();
        r.set_mac_keys(Some(&keys)).await.unwrap();
        r.set_mac_frame_counter(10, false).await.unwrap();
        r.set_mac_frame_counter(5, true).await.unwrap();
    });
    assert_eq!(r.config(), &cfg);
    assert!(r.src_match().ack_frame_pending(0x1235, 0));
    assert!(!r.src_match().ack_frame_pending(0x9999, 0));
    assert_eq!(r.mac_keys(), Some(&keys));
    assert_eq!(keys.next_key_id(), 1);
    assert_eq!(keys.prev_key_id(), 127);
    assert_eq!(r.mac_frame_counter(), 10);
}

#[test]
fn timed_receive_window_is_not_left_by_set_receive() {
    let mut r = TestRadio::new();
    block_on(async {
        r.init().await.unwrap();
        r.set_receive_at(11, 1000, 500).await.unwrap();
        r.set_receive(11).await.unwrap();
    });
    assert!(matches!(r.state(), RadioState::ReceiveAt { .. }));
}

#[test]
fn energy_scan_depends_on_caps() {
    let mut r = TestRadio::new();
    r.set_energy_rssi(-42);
    assert_eq!(block_on(r.energy_scan(11, 10)).unwrap(), -42);
    let mut bare = TestRadio::with_caps(RadioCaps::default());
    assert_eq!(block_on(bare.energy_scan(11, 10)).unwrap(), RSSI_INVALID);
}

#[test]
fn soft_mac_needs_follow_caps() {
    let bare = RadioCaps::default();
    assert_eq!(bare.soft_mac_needs(), SoftMacNeeds::all());
    let full = RadioCaps {
        phy: Capabilities::all(),
        mac: MacCapabilities::all(),
        ..RadioCaps::default()
    };
    assert!(full.soft_mac_needs().is_empty());
    let hw_ack_only = RadioCaps {
        mac: MacCapabilities::TX_ACK | MacCapabilities::RX_ACK,
        ..RadioCaps::default()
    };
    let n = hw_ack_only.soft_mac_needs();
    assert!(!n.contains(SoftMacNeeds::SEND_ACK) && !n.contains(SoftMacNeeds::MATCH_ACK));
    assert!(n.contains(SoftMacNeeds::CSMA | SoftMacNeeds::RETRANSMIT));
}

#[test]
fn capability_bits_match_openthread() {
    assert_eq!(Capabilities::ACK_TIMEOUT.bits(), 1);
    assert_eq!(Capabilities::ENERGY_SCAN.bits(), 2);
    assert_eq!(Capabilities::TRANSMIT_SEC.bits(), 1 << 5);
    assert_eq!(Capabilities::AUTO_SLEEP.bits(), 1 << 8);
    assert_eq!(Capabilities::ALT_SHORT_ADDR.bits(), 1 << 10);
}

/// A driver as written for esp-rs/openthread: only the required methods,
/// everything else defaulted. Compile-level check that adapting one works.
struct ForeignDriver {
    sent: u32,
}

impl Radio for ForeignDriver {
    type Error = RadioErrorKind;

    async fn init(&mut self) -> Result<RadioCaps, Self::Error> {
        Ok(RadioCaps::default())
    }
    async fn set_config(&mut self, _config: &Config) -> Result<(), Self::Error> {
        Ok(())
    }
    async fn set_src_match_config(&mut self, _c: &SrcMatchConfig) -> Result<(), Self::Error> {
        Ok(())
    }
    async fn set_receive(&mut self, _channel: u8) -> Result<(), Self::Error> {
        Ok(())
    }
    async fn set_sleep(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }
    async fn transmit(
        &mut self,
        _psdu: &mut [u8],
        _psdu_tx: &mut PsduTxInfo,
        _channel: u8,
        _power: i8,
        _cca_threshold: Option<i8>,
        _ack_psdu_buf: Option<&mut [u8]>,
    ) -> Result<Option<PsduRxInfo>, Self::Error> {
        self.sent += 1;
        Ok(None)
    }
    async fn receive(&mut self, _psdu_buf: &mut [u8]) -> Result<PsduRxInfo, Self::Error> {
        core::future::pending().await
    }
}

async fn generic_user<R: Radio>(mut radio: R) -> Result<(), R::Error> {
    let _caps = radio.init().await?;
    radio.set_receive(11).await?;
    radio.set_csl(&CslConfig::new()).await?; // defaulted
    radio.set_mac_keys(None).await?; // defaulted
    let mut psdu = [0u8; 3];
    radio
        .transmit(&mut psdu, &mut PsduTxInfo::default(), 11, 0, None, None)
        .await?;
    Ok(())
}

#[test]
fn foreign_driver_adapts_and_blanket_ref_impl_works() {
    let mut d = ForeignDriver { sent: 0 };
    block_on(generic_user(&mut d)).unwrap(); // `&mut T: Radio`
    assert_eq!(d.sent, 1);
    assert_eq!(
        block_on(d.energy_scan(11, 1)).unwrap(),
        RSSI_INVALID,
        "default energy scan reports no measurement"
    );
    block_on(generic_user(TestRadio::new())).unwrap();
}
