//! [`Radio`] over the sysgrok `nrf-802154` crate: Nordic's 802.15.4 radio
//! driver (C) and MPSL (prebuilt library).
//!
//! The mapping from the `Radio` trait to the driver is ported from
//! `nrf_802154::OpenThreadRadio` (sysgrok/nrf-802154, MIT OR Apache-2.0),
//! which implements esp-rs/openthread's `Radio` trait, the trait OpenTrust's
//! is modelled on. The esp-rs `openthread` crate itself is not used.
//!
//! Peripherals taken by this backend (nRF52840): `RADIO`, `EGU0`, `TIMER2`,
//! `RTC2` (the driver), `RTC0`, `TIMER0`, `TEMP`, `PPI_CH19`, `PPI_CH30`,
//! `PPI_CH31` (MPSL). `RTC1` stays with the embassy time driver, `RNG` with
//! [`NrfRng`](crate::NrfRng): neither MPSL nor the driver uses the RNG
//! peripheral (the driver's CSMA backoff draws from a xorshift seeded from
//! the device ID).

// The only unsafe code of the crate: three plain calls into Nordic's C driver
// (clock read, RSSI measurement) that `nrf-802154` does not wrap.
#![allow(unsafe_code)]

use embassy_nrf::{Peri, bind_interrupts, peripherals};
use nrf_802154::{
    Cca, Error, MAX_PSDU_SIZE, MacKey, PsduMeta, Radio as HwRadio, RadioPeripherals, TxError, raw,
};
use nrf_mpsl::MultiprotocolServiceLayer;
use opentrust_platform::radio::{
    AckSecurity, Capabilities, Config, CslConfig, MacCapabilities, MacKeys, PsduRxInfo, PsduTxInfo,
    RSSI_INVALID, Radio, RadioCaps, RadioClock, RadioErrorKind, SrcMatchConfig,
};

bind_interrupts!(
    /// Interrupt bindings of MPSL and the 802.15.4 driver. Pass this to
    /// [`init_mpsl`]; it is the only owner of these vectors.
    pub struct Irqs {
        // MPSL's low-priority handler and the driver's notification handler
        // share the EGU0/SWI0 line.
        EGU0_SWI0 => nrf_mpsl::LowPrioInterruptHandler, nrf_802154::EguInterruptHandler;
        RADIO => nrf_mpsl::HighPrioInterruptHandler;
        TIMER0 => nrf_mpsl::HighPrioInterruptHandler;
        RTC0 => nrf_mpsl::HighPrioInterruptHandler;
        CLOCK_POWER => nrf_mpsl::ClockInterruptHandler;
        // The driver's low-power timer.
        RTC2 => nrf_802154::LpTimerInterruptHandler;
    }
);

/// The multiprotocol service layer. Create it with [`init_mpsl`] in a static,
/// and run [`MultiprotocolServiceLayer::run`] on an executor for as long as the
/// radio is in use.
pub type Mpsl = MultiprotocolServiceLayer<'static>;

/// Accuracy of the LF clock (the DK's 32.768 kHz crystal), in ppm.
const LFCLK_ACCURACY_PPM: u8 = 20;

/// Initialise MPSL with the 32.768 kHz crystal as the LF clock source (as on
/// the nRF52840 DK and most modules), with one timeslot session for the flash
/// driver ([`take_flash`](crate::take_flash)).
///
/// MPSL manages the HF and LF clocks from here on; the application must not
/// stop them. `embassy_nrf::init` is expected to run before with its default
/// clock configuration (internal RC for the time driver); MPSL switches the LF
/// source over.
pub fn init_mpsl(
    rtc0: Peri<'static, peripherals::RTC0>,
    timer0: Peri<'static, peripherals::TIMER0>,
    temp: Peri<'static, peripherals::TEMP>,
    ppi_ch19: Peri<'static, peripherals::PPI_CH19>,
    ppi_ch30: Peri<'static, peripherals::PPI_CH30>,
    ppi_ch31: Peri<'static, peripherals::PPI_CH31>,
) -> Result<Mpsl, nrf_802154::MpslError> {
    let lfclk = nrf_mpsl::raw::mpsl_clock_lfclk_cfg_t {
        source: nrf_mpsl::raw::MPSL_CLOCK_LF_SRC_XTAL as u8,
        rc_ctiv: 0,
        rc_temp_ctiv: 0,
        accuracy_ppm: u16::from(LFCLK_ACCURACY_PPM),
        skip_wait_lfclk_started: nrf_mpsl::raw::MPSL_DEFAULT_SKIP_WAIT_LFCLK_STARTED != 0,
    };
    let p = nrf_mpsl::Peripherals::new(rtc0, timer0, temp, ppi_ch19, ppi_ch30, ppi_ch31);
    // One timeslot session: `nrf_mpsl::Flash` (the settings store) runs its
    // erases and writes in MPSL timeslots between radio activity.
    static SESSIONS: static_cell::StaticCell<nrf_mpsl::SessionMem<1>> =
        static_cell::StaticCell::new();
    let sessions = SESSIONS.init(nrf_mpsl::SessionMem::new());
    MultiprotocolServiceLayer::with_timeslots(p, Irqs, lfclk, sessions)
}

/// Time to let one RSSI measurement of the energy scan settle (the hardware
/// averages over 8 symbols = 128 us).
const RSSI_SETTLE_US: u64 = 150;

fn radio_now_us() -> u64 {
    // SAFETY: plain read of the driver's time base.
    unsafe { raw::nrf_802154_time_get() }
}

/// Failed transmissions by cause, since boot. The MAC folds busy channel,
/// ended and denied timeslots into one failure kind; this tells them apart.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TxErrorStats {
    /// The channel stayed busy through all CSMA-CA backoffs (or CCA failed).
    pub busy_channel: u32,
    /// The radio timeslot ended during the transmission.
    pub timeslot_ended: u32,
    /// The timeslot request for the transmission was denied.
    pub timeslot_denied: u32,
    /// The frame could not be handed to the driver.
    pub schedule: u32,
    /// The frame went out but no ACK came back.
    pub no_ack: u32,
    /// The driver had no receive buffer for the ACK.
    pub no_mem: u32,
    /// The procedure was aborted by another operation.
    pub aborted: u32,
    /// The ACK was not the expected one.
    pub invalid_ack: u32,
    /// Anything else.
    pub other: u32,
}

const TX_ERR_KINDS: usize = 9;
static TX_ERR: [core::sync::atomic::AtomicU32; TX_ERR_KINDS] =
    [const { core::sync::atomic::AtomicU32::new(0) }; TX_ERR_KINDS];

/// The cause of the last failure counted as "other": the driver's code for an
/// unknown transmit error, `0x100 + n` for a non-transmit error variant.
static LAST_OTHER: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

/// See [`TxErrorStats::other`]: the cause of the last such failure.
pub fn last_other_tx_error() -> u32 {
    LAST_OTHER.load(core::sync::atomic::Ordering::Relaxed)
}

fn count_tx_error(e: &Error) {
    if let Error::Transmit(TxError::Unknown(c)) = e {
        LAST_OTHER.store(*c as u32, core::sync::atomic::Ordering::Relaxed);
    } else if !matches!(
        e,
        Error::ScheduleTransmit
            | Error::Transmit(
                TxError::BusyChannel
                    | TxError::TimeslotEnded
                    | TxError::TimeslotDenied
                    | TxError::NoAck
                    | TxError::NoMem
                    | TxError::Aborted
                    | TxError::InvalidAck
            )
    ) {
        let n = match e {
            Error::TransmitDataTooLarge => 1,
            Error::ReceiveBufTooSmall => 2,
            Error::EnterReceive => 3,
            Error::EnterSleep => 4,
            Error::Receive => 5,
            _ => 6,
        };
        LAST_OTHER.store(0x100 + n, core::sync::atomic::Ordering::Relaxed);
    }
    let i = match e {
        Error::Transmit(TxError::BusyChannel) => 0,
        Error::Transmit(TxError::TimeslotEnded) => 1,
        Error::Transmit(TxError::TimeslotDenied) => 2,
        Error::ScheduleTransmit => 3,
        Error::Transmit(TxError::NoAck) => 4,
        Error::Transmit(TxError::NoMem) => 5,
        Error::Transmit(TxError::Aborted) => 6,
        Error::Transmit(TxError::InvalidAck) => 7,
        _ => 8,
    };
    TX_ERR[i].fetch_add(1, core::sync::atomic::Ordering::Relaxed);
}

static RX_FRAMES: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
static TX_FRAMES: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

/// Frames received and frames handed to the driver for transmission, since
/// boot (diagnostics).
pub fn frame_counts() -> (u32, u32) {
    (
        RX_FRAMES.load(core::sync::atomic::Ordering::Relaxed),
        TX_FRAMES.load(core::sync::atomic::Ordering::Relaxed),
    )
}

/// The transmit failure counts by cause.
pub fn tx_error_stats() -> TxErrorStats {
    let g = |i: usize| TX_ERR[i].load(core::sync::atomic::Ordering::Relaxed);
    TxErrorStats {
        busy_channel: g(0),
        timeslot_ended: g(1),
        timeslot_denied: g(2),
        schedule: g(3),
        no_ack: g(4),
        no_mem: g(5),
        aborted: g(6),
        invalid_ack: g(7),
        other: g(8),
    }
}

fn error_kind(e: &Error) -> RadioErrorKind {
    match e {
        Error::TransmitDataTooLarge => RadioErrorKind::TxInvalid,
        Error::ReceiveBufTooSmall => RadioErrorKind::RxInvalid,
        // The frame could not even be handed to the driver, or the channel
        // stayed busy through all backoffs: a channel-access failure.
        Error::ScheduleTransmit => RadioErrorKind::TxFailed,
        Error::Transmit(e) => match e {
            TxError::BusyChannel | TxError::TimeslotEnded | TxError::TimeslotDenied => {
                RadioErrorKind::TxFailed
            }
            // The frame went out but no valid ACK came back.
            TxError::NoAck => RadioErrorKind::RxAckTimeout,
            TxError::InvalidAck => RadioErrorKind::RxAckInvalid,
            _ => RadioErrorKind::Other,
        },
        Error::EnterReceive | Error::Receive | Error::ScheduleReceive => RadioErrorKind::RxFailed,
        _ => RadioErrorKind::Other,
    }
}

fn rx_info(meta: &PsduMeta, channel: u8) -> PsduRxInfo {
    PsduRxInfo {
        // The PSDU including its two FCS bytes.
        len: usize::from(meta.len) + 2,
        channel,
        rssi: Some(meta.power),
        lqi: meta.lqi,
        timestamp_us: meta.phr_time(),
        ack_security: meta.ack_security.map(|s| AckSecurity {
            frame_counter: s.frame_counter,
            key_id: s.key_id,
        }),
        acked_with_frame_pending: Some(meta.acked_frame_pending),
    }
}

fn write_crc(meta: &PsduMeta, buf: &mut [u8]) {
    let len = usize::from(meta.len);
    buf[len..len + 2].copy_from_slice(&meta.crc.to_le_bytes());
}

/// nRF52840 802.15.4 radio on Nordic's driver.
///
/// Reports the offloads the driver implements (see the crate docs). The
/// driver's hardware address filter matches one short address only, so
/// `Config::alt_short_addr` is ignored.
pub struct NrfRadio<'d> {
    hw: HwRadio<'d>,
    config: Config,
    power: i8,
    cca_threshold: Option<i8>,
    /// CSMA-CA backoff limit last applied (`None` = the driver's default).
    csma_max_backoffs: Option<u8>,
    /// The receiver is commanded by a timed window rather than by
    /// `set_receive` / `set_sleep`.
    timed_rx: bool,
    /// Channel of the last timed window.
    window_channel: u8,
    csl: CslConfig,
    csl_accuracy_ppm: u8,
    csl_uncertainty: u8,
}

impl core::fmt::Debug for NrfRadio<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("NrfRadio")
            .field("channel", &self.hw.channel())
            .field("timed_rx", &self.timed_rx)
            .finish_non_exhaustive()
    }
}

impl<'d> NrfRadio<'d> {
    /// A timed receive window must be handed to the driver this far ahead of
    /// its start: the driver reserves a timeslot for it and refuses a window
    /// that starts within about a millisecond.
    pub const RECEIVE_AT_LEAD_US: u32 = 3000;

    /// Default clock accuracy reported to a CSL parent: the 32.768 kHz
    /// crystal MPSL is configured with by [`init_mpsl`].
    pub const DEFAULT_CSL_ACCURACY_PPM: u8 = LFCLK_ACCURACY_PPM;

    /// Default timed-receive uncertainty reported to a CSL parent, in units of
    /// 10 us: the jitter of the driver's receive-window start (SL timer
    /// granularity plus ramp-up), a conservative +-120 us. Not verified
    /// against a peer here.
    pub const DEFAULT_CSL_UNCERTAINTY: u8 = 12;

    /// Take the radio and the driver's peripherals. `mpsl` must be running
    /// (see [`Mpsl`]).
    pub fn new(
        radio: Peri<'d, peripherals::RADIO>,
        egu0: Peri<'d, peripherals::EGU0>,
        timer2: Peri<'d, peripherals::TIMER2>,
        rtc2: Peri<'d, peripherals::RTC2>,
        mpsl: &'d Mpsl,
    ) -> Self {
        let mut hw = HwRadio::new(radio, RadioPeripherals::new(egu0, timer2, rtc2), Irqs, mpsl);
        let config = Config::new();
        Self::apply_config(&mut hw, &config);
        let power = hw.tx_power();
        Self {
            hw,
            config,
            power,
            // The driver's default CCA: energy detection at -75 dBm.
            cca_threshold: Some(-75),
            csma_max_backoffs: None,
            timed_rx: false,
            window_channel: 0,
            csl: CslConfig::new(),
            csl_accuracy_ppm: Self::DEFAULT_CSL_ACCURACY_PPM,
            csl_uncertainty: Self::DEFAULT_CSL_UNCERTAINTY,
        }
    }

    /// Set the CSL timing figures reported to a CSL parent (clock accuracy in
    /// ppm, timed-receive uncertainty in 10 us units).
    #[must_use]
    pub const fn with_csl_timing(mut self, accuracy_ppm: u8, uncertainty: u8) -> Self {
        self.csl_accuracy_ppm = accuracy_ppm;
        self.csl_uncertainty = uncertainty;
        self
    }

    fn apply_config(hw: &mut HwRadio<'_>, config: &Config) {
        hw.set_promiscuous(config.promiscuous);
        hw.set_pan_id(config.pan_id);
        hw.set_short_addr(config.short_addr);
        hw.set_ext_addr(config.ext_addr);
        // The trait says "may power down when idle", the driver "keep the
        // receiver on when idle".
        hw.set_rx_when_idle(!config.auto_sleep);
    }
}

impl Radio for NrfRadio<'_> {
    type Error = RadioErrorKind;

    async fn init(&mut self) -> Result<RadioCaps, Self::Error> {
        Ok(RadioCaps {
            phy: Capabilities::ACK_TIMEOUT
                | Capabilities::CSMA_BACKOFF
                | Capabilities::AUTO_SLEEP
                | Capabilities::TRANSMIT_FRAME_POWER
                | Capabilities::RECEIVE_TIMING
                | Capabilities::TRANSMIT_SEC
                | Capabilities::TRANSMIT_TIMING
                // Sampled from the driver's RSSI measurement.
                | Capabilities::ENERGY_SCAN,
            mac: MacCapabilities::all(),
            receive_sensitivity: -100,
            default_tx_power: self.hw.tx_power(),
            default_cca_threshold: -75,
            clock: Some(RadioClock(radio_now_us)),
            csl_accuracy_ppm: self.csl_accuracy_ppm,
            csl_uncertainty: self.csl_uncertainty,
            receive_at_lead_us: Self::RECEIVE_AT_LEAD_US,
            ..RadioCaps::default()
        })
    }

    async fn set_config(&mut self, config: &Config) -> Result<(), Self::Error> {
        if self.config != *config {
            let to_auto_sleep = config.auto_sleep && !self.config.auto_sleep;
            self.config = config.clone();
            Self::apply_config(&mut self.hw, &self.config);
            // The driver applies the new idle behaviour after the operation in
            // progress: put an idle receiver to sleep right away.
            if to_auto_sleep {
                self.hw.sleep_if_idle();
            }
        }
        Ok(())
    }

    async fn set_src_match_config(&mut self, config: &SrcMatchConfig) -> Result<(), Self::Error> {
        // Small and rarely changing: rebuild the driver's lists wholesale.
        self.hw.clear_pending();
        for &addr in &config.short_addrs {
            self.hw.set_pending_short(addr, true);
        }
        for &addr in &config.ext_addrs {
            self.hw.set_pending_ext(addr, true);
        }
        // Disabled matching = Frame Pending set in every ACK.
        self.hw.set_src_match_enabled(config.enabled);
        Ok(())
    }

    async fn set_receive(&mut self, channel: u8) -> Result<(), Self::Error> {
        self.timed_rx = false;
        if self.hw.channel() != channel {
            self.hw.set_channel(channel);
        }
        if !self.hw.enter_receive() {
            return Err(RadioErrorKind::RxFailed);
        }
        Ok(())
    }

    async fn set_receive_at(
        &mut self,
        channel: u8,
        start_us: u64,
        duration_us: u32,
    ) -> Result<(), Self::Error> {
        // The window carries its own channel; the driver's channel stays so
        // that a window still running is not aborted.
        self.window_channel = channel;

        // The driver wants the start `RECEIVE_AT_LEAD_US` ahead of its clock:
        // trim a window whose start is nearer (the first one after CSL was
        // switched on starts "now") rather than lose it.
        const MIN_LEAD_US: u64 = NrfRadio::RECEIVE_AT_LEAD_US as u64;
        let now = self.hw.now_us();
        let end_us = start_us + u64::from(duration_us);
        let start_us = start_us.max(now + MIN_LEAD_US);
        if end_us <= start_us + 250 {
            opentrust_core::debug!("timed receive window missed");
            return Err(RadioErrorKind::RxFailed);
        }
        if !self
            .hw
            .receive_at(start_us, (end_us - start_us) as u32, channel)
        {
            return Err(RadioErrorKind::RxFailed);
        }
        // `receive` only drains the queue until the next `set_sleep` /
        // `set_receive`: the window runs the receiver.
        self.timed_rx = true;
        Ok(())
    }

    async fn set_sleep(&mut self) -> Result<(), Self::Error> {
        if core::mem::take(&mut self.timed_rx) || self.hw.has_pending_window() {
            // The driver sleeps by itself between and after windows, and a
            // frame may be arriving: do not abort it.
            self.hw.sleep_if_idle();
            return Ok(());
        }
        if !self.hw.sleep() {
            return Err(RadioErrorKind::Other);
        }
        Ok(())
    }

    async fn set_csl(&mut self, csl: &CslConfig) -> Result<(), Self::Error> {
        let peer_changed =
            self.csl.short_addr != csl.short_addr || self.csl.ext_addr != csl.ext_addr;

        // The parent learns this node's receive schedule from the CSL IE in the
        // enhanced ACKs: inject it for exactly the current parent.
        if self.csl.enabled() && (!csl.enabled() || peer_changed) {
            self.hw
                .clear_csl_ie_peer(Some(self.csl.short_addr), Some(self.csl.ext_addr));
        }

        if !csl.enabled() {
            let in_window = self.timed_rx;
            self.hw.receive_at_cancel();
            if in_window {
                self.hw.sleep_if_idle();
            }
        }

        if self.csl.period != csl.period {
            self.hw
                .set_csl_period(csl.period.min(u32::from(u16::MAX)) as u16);
        }

        if csl.enabled()
            && (!self.csl.enabled() || peer_changed)
            && !self
                .hw
                .set_csl_ie_peer(Some(csl.short_addr), Some(csl.ext_addr))
        {
            opentrust_core::warn!("CSL IE not injected into enhanced ACKs: ACK data table full");
        }

        if csl.enabled() && (self.csl.sample_time_us != csl.sample_time_us || !self.csl.enabled()) {
            // The stack hands out the low 32 bits of the radio clock: widen it
            // against the current time.
            let now = self.hw.now_us();
            let offset = csl.sample_time_us.wrapping_sub(now as u32);
            let sample_time = if offset < 0x8000_0000 {
                now + u64::from(offset)
            } else {
                now.saturating_sub(u64::from(u32::MAX - offset) + 1)
            };
            self.hw.set_csl_anchor_time(sample_time);
        }

        self.csl = *csl;
        Ok(())
    }

    async fn set_mac_keys(&mut self, keys: Option<&MacKeys>) -> Result<(), Self::Error> {
        match keys {
            Some(keys) => self
                .hw
                .set_mac_keys(
                    keys.key_id_mode,
                    &[
                        MacKey {
                            key_id: keys.prev_key_id(),
                            key: keys.prev,
                        },
                        MacKey {
                            key_id: keys.key_id,
                            key: keys.curr,
                        },
                        MacKey {
                            key_id: keys.next_key_id(),
                            key: keys.next,
                        },
                    ],
                )
                .map_err(|e| error_kind(&e)),
            None => {
                self.hw.clear_mac_keys();
                Ok(())
            }
        }
    }

    async fn set_mac_frame_counter(
        &mut self,
        frame_counter: u32,
        if_larger: bool,
    ) -> Result<(), Self::Error> {
        self.hw.set_frame_counter(frame_counter, if_larger);
        Ok(())
    }

    async fn energy_scan(&mut self, channel: u8, duration_millis: u16) -> Result<i8, Self::Error> {
        if !(11..=26).contains(&channel) {
            return Err(RadioErrorKind::Other);
        }
        // Whatever timed window is pending is stale from here on.
        self.hw.receive_at_cancel();
        self.timed_rx = false;
        if self.hw.channel() != channel {
            self.hw.set_channel(channel);
        }
        if !self.hw.enter_receive() {
            return Err(RadioErrorKind::RxFailed);
        }
        let end = embassy_time::Instant::now()
            + embassy_time::Duration::from_millis(u64::from(duration_millis.max(1)));
        let mut max = i8::MIN;
        loop {
            // SAFETY: plain driver calls; the radio is in the receive state.
            let started = unsafe { raw::nrf_802154_rssi_measure_begin() };
            embassy_time::Timer::after_micros(RSSI_SETTLE_US).await;
            if started {
                // SAFETY: as above.
                let dbm = unsafe { raw::nrf_802154_rssi_last_get() };
                if dbm != RSSI_INVALID {
                    max = max.max(dbm);
                }
            }
            if embassy_time::Instant::now() >= end {
                break;
            }
        }
        Ok(if max == i8::MIN { RSSI_INVALID } else { max })
    }

    async fn transmit(
        &mut self,
        psdu: &mut [u8],
        psdu_tx: &mut PsduTxInfo,
        channel: u8,
        power: i8,
        cca_threshold: Option<i8>,
        mut ack_psdu_buf: Option<&mut [u8]>,
    ) -> Result<Option<PsduRxInfo>, Self::Error> {
        // + 2: the FCS the driver adds.
        if psdu.len() < 2 || psdu.len() > MAX_PSDU_SIZE + 2 {
            return Err(RadioErrorKind::TxInvalid);
        }
        if let Some(buf) = ack_psdu_buf.as_ref() {
            if buf.len() < MAX_PSDU_SIZE + 2 {
                return Err(RadioErrorKind::RxInvalid);
            }
        }

        // The frame goes out on its own channel; the driver's channel (what it
        // receives on, and returns to) stays, so a timed window is not aborted.
        if self.power != power {
            self.power = power;
            self.hw.set_tx_power(power);
        }

        TX_FRAMES.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        let len = psdu.len();
        let data = &mut psdu[..len - 2];
        let ack = ack_psdu_buf.as_mut().map(|buf| {
            let len = buf.len();
            &mut buf[..len - 2]
        });

        // What the driver still has to do to the frame (TRANSMIT_SEC): assign
        // the frame counter and CSL IE unless the header is final, and secure
        // it unless it is secured already.
        let props = nrf_802154::FrameProps {
            is_secured: psdu_tx.security_processed,
            dynamic_data_is_set: psdu_tx.header_updated,
        };

        if let Some(threshold) = cca_threshold {
            if self.cca_threshold != Some(threshold) {
                self.cca_threshold = Some(threshold);
                self.hw.set_cca(Cca::ed_from_dbm(threshold));
            }
        }
        let cca = cca_threshold.is_some();

        // A timed frame: its SHR starts 10 symbols before the end of the SFD
        // it is timed by, and the driver wants that comfortably ahead of its
        // clock. A frame that is too late goes out right away.
        const SHR_US: u64 = 10 * 16;
        const MIN_LEAD_US: u64 = 400;
        let tx_start_us = psdu_tx
            .tx_at_us
            .map(|t| t.saturating_sub(SHR_US))
            .filter(|start| *start >= self.hw.now_us() + MIN_LEAD_US);

        let result = if let Some(start_us) = tx_start_us {
            HwRadio::transmit_at_with(&mut self.hw, data, props, start_us, channel, cca, ack).await
        } else if cca
            && psdu_tx.tx_at_us.is_none()
            && psdu_tx.max_csma_backoffs.is_none_or(|b| b > 0)
        {
            // CSMA_BACKOFF is reported: the driver does the channel access.
            if let Some(backoffs) = psdu_tx.max_csma_backoffs {
                if self.csma_max_backoffs != Some(backoffs) {
                    self.csma_max_backoffs = Some(backoffs);
                    self.hw.set_csma_ca_max_backoffs(backoffs);
                }
            }
            HwRadio::transmit_csma_ca_with(&mut self.hw, data, props, channel, ack).await
        } else {
            HwRadio::transmit_with(&mut self.hw, data, props, channel, cca, ack).await
        };

        // The driver finished the frame whether or not it got through; a
        // retransmission must repeat its frame counter.
        if let Some(done) = self.hw.last_tx_frame_props() {
            psdu_tx.header_updated |= done.dynamic_data_is_set;
            psdu_tx.security_processed |= done.is_secured;
        }

        let meta = result.map_err(|e| {
            count_tx_error(&e);
            error_kind(&e)
        })?;
        Ok(meta.map(|meta| {
            if let Some(buf) = ack_psdu_buf {
                write_crc(&meta, buf);
            }
            rx_info(&meta, channel)
        }))
    }

    async fn receive(&mut self, psdu_buf: &mut [u8]) -> Result<PsduRxInfo, Self::Error> {
        if psdu_buf.len() < MAX_PSDU_SIZE + 2 {
            return Err(RadioErrorKind::RxInvalid);
        }
        let len = psdu_buf.len();
        let window = self.timed_rx;
        let meta = if window {
            // Inside a timed window the receiver is the driver's to run.
            HwRadio::wait_window_frame(&mut self.hw, &mut psdu_buf[..len - 2]).await
        } else {
            HwRadio::wait_frame(&mut self.hw, &mut psdu_buf[..len - 2]).await
        };
        write_crc(&meta, psdu_buf);
        RX_FRAMES.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        let channel = if window {
            self.window_channel
        } else {
            self.hw.channel()
        };
        // The stack never commands sleep after a receive window: the receiver
        // goes off once the window's frame (and its ACK) is out.
        if window {
            self.hw.sleep_if_idle();
        }
        Ok(rx_info(&meta, channel))
    }
}
