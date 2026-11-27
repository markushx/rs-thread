//! [`Radio`] over the `esp-ieee802154` crate.
//!
//! # Capabilities
//!
//! `EspRadio` reports no MAC-offload capabilities (`MacCapabilities::empty()`),
//! so the rs-thread soft-MAC layer handles address filtering, software ACK,
//! CSMA-CA backoff, retransmissions and transmit security entirely in software.
//! This is the same level as the `radio-embassy` nRF backend.
//!
//! The esp-ieee802154 0.8 driver does perform hardware CSMA-CA internally
//! before every transmission, but it does not expose the result (success vs.
//! CCA failure) through its callback API, so the soft-MAC keeps its own retry
//! loop on top.
//!
//! Energy scan is not exposed by the esp-ieee802154 public API; `energy_scan`
//! uses the default no-op implementation (returns `RSSI_INVALID`).
//!
//! Sleep mode is not exposed; `set_sleep` is a no-op. Without `AUTO_SLEEP`
//! the MAC drives sleep/wake explicitly through `set_sleep` / `set_receive`,
//! but the receiver simply stays on until another channel or stop is requested.
//!
//! # ISR-to-async bridging
//!
//! The driver fires `fn()` callbacks from its interrupt handler. Two module-
//! level `Signal` values bridge those callbacks to the async `transmit` and
//! `receive` futures. Only one `EspRadio` instance may exist at a time (a
//! constraint the firmware naturally satisfies).
//!
//! # Note on BLE coexistence
//!
//! esp-ieee802154 0.8.0 does not support Wi-Fi/BLE coexistence. The Matter
//! light firmware (Phase 17d) requires a different radio path that integrates
//! with the ESP coexistence framework.

use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::signal::Signal;
use esp_ieee802154::{CcaMode, Config, Ieee802154};
use rs_thread_platform::radio::{
    Capabilities, Config as RadioConfig, MacCapabilities, PsduRxInfo, PsduTxInfo, RadioCaps,
    RadioError, RadioErrorKind, SrcMatchConfig,
};

// Module-level signals: safe because there is exactly one EspRadio at a time.
static TX_DONE: Signal<CriticalSectionRawMutex, ()> = Signal::new();
static RX_AVAIL: Signal<CriticalSectionRawMutex, ()> = Signal::new();

fn on_tx_done() {
    TX_DONE.signal(());
}

fn on_rx_avail() {
    RX_AVAIL.signal(());
}

/// ESP32-C6/H2 IEEE 802.15.4 radio.
///
/// Reports no MAC-offload capabilities (see the crate docs). The hardware
/// channel, PAN ID, short address and extended address are configured via
/// [`set_config`](rs_thread_platform::radio::Radio::set_config); the radio
/// is kept in continuous-receive mode between transmissions (no hardware
/// sleep).
pub struct EspRadio<'d> {
    hw: Ieee802154<'d>,
    /// The last config pushed to the hardware, to detect changes.
    cfg: Config,
    /// Whether the receiver is currently on (`start_receive` was called).
    receiving: bool,
}

impl core::fmt::Debug for EspRadio<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("EspRadio")
            .field("channel", &self.cfg.channel)
            .field("receiving", &self.receiving)
            .finish_non_exhaustive()
    }
}

impl<'d> EspRadio<'d> {
    /// Create an `EspRadio` from an initialised `esp-ieee802154` driver.
    ///
    /// Registers the TX-done and RX-available callbacks immediately.
    pub fn new(mut hw: Ieee802154<'d>) -> Self {
        hw.set_tx_done_callback_fn(on_tx_done);
        hw.set_rx_available_callback_fn(on_rx_avail);
        // Start with a known config: promiscuous (the soft-MAC filters),
        // no hardware ACK (the soft-MAC ACKs in software), channel 11.
        let cfg = Config {
            promiscuous: true,
            auto_ack_tx: false,
            auto_ack_rx: false,
            enhance_ack_tx: false,
            coordinator: false,
            rx_when_idle: false,
            txpower: RadioCaps::DEFAULT_TX_POWER,
            channel: 11,
            cca_threshold: RadioCaps::DEFAULT_CCA_THRESHOLD,
            cca_mode: CcaMode::Carrier,
            pan_id: None,
            short_addr: None,
            ext_addr: None,
        };
        hw.set_config(cfg);
        Self {
            hw,
            cfg,
            receiving: false,
        }
    }
}

/// Error type for `EspRadio`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EspRadioError(RadioErrorKind);

impl RadioError for EspRadioError {
    fn kind(&self) -> RadioErrorKind {
        self.0
    }
}

impl rs_thread_platform::radio::Radio for EspRadio<'_> {
    type Error = EspRadioError;

    async fn init(&mut self) -> Result<RadioCaps, Self::Error> {
        Ok(RadioCaps {
            // No PHY capabilities beyond the basics: no energy scan, no timed
            // TX/RX, no auto-sleep, no transmit security offload.
            phy: Capabilities::TRANSMIT_FRAME_POWER,
            // No MAC offload: the soft-MAC handles all ACK, filtering, CSMA.
            mac: MacCapabilities::empty(),
            // ESP32-C6 802.15.4 receiver sensitivity (datasheet: −100 dBm typ.).
            receive_sensitivity: -100,
            default_tx_power: RadioCaps::DEFAULT_TX_POWER,
            default_cca_threshold: RadioCaps::DEFAULT_CCA_THRESHOLD,
            clock: None,
            csl_accuracy_ppm: u8::MAX,
            csl_uncertainty: u8::MAX,
            receive_at_lead_us: 0,
            bus_speed: 0,
            bus_latency_us: 0,
            csl_receive_on_after_us: RadioCaps::DEFAULT_CSL_RECEIVE_ON_AFTER_US,
        })
    }

    async fn set_config(&mut self, config: &RadioConfig) -> Result<(), Self::Error> {
        self.cfg.pan_id = config.pan_id;
        self.cfg.short_addr = config.short_addr;
        self.cfg.ext_addr = config.ext_addr;
        // The soft-MAC handles filtering and promiscuous mode; keep the radio
        // in promiscuous mode so the soft-MAC sees every frame.
        self.hw.set_config(self.cfg);
        Ok(())
    }

    async fn set_src_match_config(&mut self, _config: &SrcMatchConfig) -> Result<(), Self::Error> {
        // No hardware source-match table; the soft-MAC manages Frame Pending.
        Ok(())
    }

    async fn set_receive(&mut self, channel: u8) -> Result<(), Self::Error> {
        self.cfg.channel = channel;
        self.hw.set_config(self.cfg);
        if !self.receiving {
            self.hw.start_receive();
            self.receiving = true;
        }
        Ok(())
    }

    async fn set_sleep(&mut self) -> Result<(), Self::Error> {
        // esp-ieee802154 has no explicit sleep; the receiver stays on.
        // The MAC will call `set_receive` when it wants frames again.
        self.receiving = false;
        Ok(())
    }

    async fn transmit(
        &mut self,
        psdu: &mut [u8],
        _psdu_tx: &mut PsduTxInfo,
        channel: u8,
        power: i8,
        cca_threshold: Option<i8>,
        _ack_psdu_buf: Option<&mut [u8]>,
    ) -> Result<Option<PsduRxInfo>, Self::Error> {
        // Switch channel and power if needed.
        let cca_mode = if cca_threshold.is_some() {
            CcaMode::Ed
        } else {
            CcaMode::Carrier
        };
        if self.cfg.channel != channel || self.cfg.txpower != power || self.cfg.cca_mode != cca_mode
        {
            self.cfg.channel = channel;
            self.cfg.txpower = power;
            self.cfg.cca_mode = cca_mode;
            self.hw.set_config(self.cfg);
        }

        // Build the raw frame: data[0] = PSDU length + 2 (for 2-byte FCS),
        // data[1..] = PSDU bytes. The hardware appends the FCS.
        let mut raw = [0u8; 129];
        let frame_len = psdu.len() + 2;
        if frame_len > 129 {
            return Err(EspRadioError(RadioErrorKind::TxInvalid));
        }
        raw[0] = frame_len as u8;
        raw[1..1 + psdu.len()].copy_from_slice(psdu);

        // Clear any stale TX-done signal from a previous transmit.
        TX_DONE.reset();

        // Hand the frame to the driver. The driver always returns Ok(()).
        // A panic from transmit_raw means the frame was too long (> 128 bytes
        // body) — guarded by the check above.
        self.hw
            .transmit_raw(&raw[..1 + psdu.len()])
            .map_err(|_| EspRadioError(RadioErrorKind::TxFailed))?;

        // Wait for the TX-done ISR callback.
        TX_DONE.wait().await;

        // Restart receive on the same channel (the driver stops RX during TX).
        if self.receiving {
            self.hw.start_receive();
        }

        // Return None: no ACK received by this driver (the soft-MAC layer
        // handles the ACK wait by calling `receive` after `transmit` returns).
        Ok(None)
    }

    async fn receive(&mut self, psdu_buf: &mut [u8]) -> Result<PsduRxInfo, Self::Error> {
        loop {
            if let Some(raw) = self.hw.raw_received() {
                // raw.data[0] = frame length including 2-byte FCS.
                let frame_len = raw.data[0] as usize;
                // Guard against a malformed length byte from the hardware.
                if !(2..=129).contains(&frame_len) {
                    continue;
                }
                let psdu_len = frame_len - 2;
                if psdu_len > psdu_buf.len() {
                    // Frame larger than provided buffer; discard.
                    rs_thread_core::warn!(
                        "EspRadio: received frame too large ({} bytes)",
                        psdu_len
                    );
                    continue;
                }
                psdu_buf[..psdu_len].copy_from_slice(&raw.data[1..1 + psdu_len]);
                // esp-ieee802154 stores the RSSI byte just after the PSDU (at
                // the position where the hardware would place FCS byte 0).
                // This matches how `Ieee802154::received()` extracts RSSI:
                //   raw.data[raw.data[0] as usize - 1]  =  raw.data[frame_len-1]
                //                                       =  raw.data[psdu_len+1]
                let rssi = raw.data[psdu_len + 1] as i8;
                return Ok(PsduRxInfo {
                    len: psdu_len,
                    channel: raw.channel,
                    rssi: Some(rssi),
                    lqi: None,
                    timestamp_us: None,
                    ack_security: None,
                    acked_with_frame_pending: None,
                });
            }
            // With rx_when_idle=false (the esp-ieee802154 default) the hardware
            // goes IDLE after each received frame via next_operation().  Restart
            // reception so the radio is not stuck IDLE between frames.
            // ieee802154_receive() is a no-op when the state is already Receive.
            if self.receiving {
                self.hw.start_receive();
            }
            // No frame ready; wait for the RX-available ISR callback.
            // Reset first so a signal fired after the raw_received() check
            // but before wait() does not get lost (Signal holds one slot).
            RX_AVAIL.reset();
            // Check one more time after reset to close the race window.
            if self.hw.raw_received().is_none() {
                RX_AVAIL.wait().await;
            }
        }
    }
}
