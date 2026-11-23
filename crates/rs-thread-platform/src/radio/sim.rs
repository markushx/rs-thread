//! An in-memory [`Radio`] for tests and simulation.
//!
//! [`TestRadio`] records every transmitted frame and lets the test (or a
//! simulated medium) inject received frames. It needs no executor beyond a
//! trivial `block_on` / `poll_once` (e.g. `embassy_futures`), allocates
//! nothing (fixed-capacity queues, drop on overflow) and honours the radio
//! contract: a sleeping radio drops injected frames, `receive` is
//! cancellation-safe, `transmit` returns to receive mode and, if the radio
//! advertises `MacCapabilities::TX_ACK`, consumes a queued ACK for frames that
//! request one.

use heapless::{Deque, Vec};

use super::{
    Capabilities, Config, CslConfig, MacCapabilities, MacKeys, PsduRxInfo, PsduTxInfo, Radio,
    RadioCaps, RadioErrorKind, SrcMatchConfig,
};
use core::task::Waker;

/// Maximum 802.15.4 PSDU length (`aMaxPHYPacketSize`).
pub const MAX_PSDU_LEN: usize = 127;
/// Capacity of the TX log and of the RX / ACK injection queues.
pub const QUEUE_LEN: usize = 8;

/// Frame Control "AR" (acknowledgment request) bit in the first FCF octet.
const FCF_ACK_REQUEST: u8 = 0x20;

/// Minimal [`PsduRxInfo`] for injection: `channel`, no RSSI/LQI/timestamp
/// (`len` is filled in by [`TestRadio::inject_rx`]).
pub const fn rx_info(channel: u8) -> PsduRxInfo {
    PsduRxInfo {
        len: 0,
        channel,
        rssi: None,
        lqi: None,
        timestamp_us: None,
        ack_security: None,
        acked_with_frame_pending: None,
    }
}

/// The state the radio was last commanded into.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum RadioState {
    /// Powered but `init` not yet called.
    Uninit,
    /// Sleeping: injected frames are dropped.
    Sleep,
    /// Receiving on a channel.
    Receive {
        /// Channel.
        channel: u8,
    },
    /// In (or waiting for) a timed receive window.
    ReceiveAt {
        /// Channel.
        channel: u8,
        /// Window start, radio clock microseconds.
        start_us: u64,
        /// Window length in microseconds.
        duration_us: u32,
    },
}

/// A frame the radio was asked to transmit.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TxRecord {
    /// The PSDU as handed to `transmit` (after any in-place finishing).
    pub psdu: Vec<u8, MAX_PSDU_LEN>,
    /// The `PsduTxInfo` as passed in.
    pub info: PsduTxInfo,
    /// Channel.
    pub channel: u8,
    /// Transmit power in dBm.
    pub power: i8,
    /// CCA threshold, `None` if no CCA was requested.
    pub cca_threshold: Option<i8>,
}

/// A frame (received frame or ACK) to be delivered by the radio.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct RxRecord {
    /// The PSDU.
    pub psdu: Vec<u8, MAX_PSDU_LEN>,
    /// Its meta-data (`len` is kept in sync with `psdu`).
    pub info: PsduRxInfo,
}

/// An in-memory radio; see the [module docs](self).
#[derive(Debug)]
pub struct TestRadio {
    caps: RadioCaps,
    state: RadioState,
    config: Config,
    src_match: SrcMatchConfig,
    csl: CslConfig,
    mac_keys: Option<MacKeys>,
    mac_frame_counter: u32,
    energy_rssi: i8,
    fail_next_tx: Option<RadioErrorKind>,
    tx_log: Deque<TxRecord, QUEUE_LEN>,
    rx_queue: Deque<RxRecord, QUEUE_LEN>,
    ack_queue: Deque<RxRecord, QUEUE_LEN>,
    rx_waker: Option<Waker>,
    dropped_rx: u32,
}

impl TestRadio {
    /// A radio with a full MAC offload (`MacCapabilities::all()`) and energy
    /// scan, i.e. one that needs no software MAC.
    pub fn new() -> Self {
        Self::with_caps(RadioCaps {
            phy: Capabilities::ENERGY_SCAN,
            mac: MacCapabilities::all(),
            ..RadioCaps::default()
        })
    }

    /// A radio advertising `caps` (e.g. [`RadioCaps::default()`] for a bare PHY).
    pub fn with_caps(caps: RadioCaps) -> Self {
        Self {
            caps,
            state: RadioState::Uninit,
            config: Config::new(),
            src_match: SrcMatchConfig::new(),
            csl: CslConfig::new(),
            mac_keys: None,
            mac_frame_counter: 0,
            energy_rssi: -90,
            fail_next_tx: None,
            tx_log: Deque::new(),
            rx_queue: Deque::new(),
            ack_queue: Deque::new(),
            rx_waker: None,
            dropped_rx: 0,
        }
    }

    // ---- test-side API: injection ----

    /// Inject a frame as if received over the air. `rssi`/`lqi` etc. can be set in
    /// `info`; `info.len` is overwritten with `psdu.len()`.
    ///
    /// Returns `false` (and drops the frame) if the radio is not receiving
    /// (uninitialised or sleeping), the PSDU is too long, or the queue is full.
    pub fn inject_rx(&mut self, psdu: &[u8], mut info: PsduRxInfo) -> bool {
        if matches!(self.state, RadioState::Uninit | RadioState::Sleep) {
            return false;
        }
        info.len = psdu.len();
        let Some(rec) = Self::record(psdu, info) else {
            return false;
        };
        if self.rx_queue.push_back(rec).is_err() {
            self.dropped_rx += 1;
            return false;
        }
        if let Some(w) = self.rx_waker.take() {
            w.wake();
        }
        true
    }

    /// Queue the ACK that the next ack-requesting `transmit` will return
    /// (only used if the radio advertises `MacCapabilities::TX_ACK`).
    pub fn queue_ack(&mut self, psdu: &[u8], mut info: PsduRxInfo) -> bool {
        info.len = psdu.len();
        match Self::record(psdu, info) {
            Some(rec) => self.ack_queue.push_back(rec).is_ok(),
            None => false,
        }
    }

    /// Make the next `transmit` fail with `kind` (the frame is still logged).
    pub fn fail_next_tx(&mut self, kind: RadioErrorKind) {
        self.fail_next_tx = Some(kind);
    }

    /// Set the RSSI returned by `energy_scan`.
    pub fn set_energy_rssi(&mut self, rssi: i8) {
        self.energy_rssi = rssi;
    }

    // ---- test-side API: inspection ----

    /// Pop the oldest transmitted frame.
    pub fn pop_tx(&mut self) -> Option<TxRecord> {
        self.tx_log.pop_front()
    }

    /// Number of transmitted frames not yet popped.
    pub fn tx_pending(&self) -> usize {
        self.tx_log.len()
    }

    /// Number of injected frames not yet received.
    pub fn rx_pending(&self) -> usize {
        self.rx_queue.len()
    }

    /// Number of frames dropped because the RX queue was full.
    pub fn dropped_rx(&self) -> u32 {
        self.dropped_rx
    }

    /// The state the radio was last commanded into.
    pub fn state(&self) -> RadioState {
        self.state
    }

    /// The last configuration set.
    pub fn config(&self) -> &Config {
        &self.config
    }

    /// The last source-match table set.
    pub fn src_match(&self) -> &SrcMatchConfig {
        &self.src_match
    }

    /// The last CSL schedule set.
    pub fn csl(&self) -> &CslConfig {
        &self.csl
    }

    /// The MAC keys set, if any.
    pub fn mac_keys(&self) -> Option<&MacKeys> {
        self.mac_keys.as_ref()
    }

    /// The MAC frame counter set.
    pub fn mac_frame_counter(&self) -> u32 {
        self.mac_frame_counter
    }

    /// Mutable access to the advertised capabilities (takes effect for
    /// behaviour immediately; `init` returns the current value).
    pub fn caps_mut(&mut self) -> &mut RadioCaps {
        &mut self.caps
    }

    fn record(psdu: &[u8], info: PsduRxInfo) -> Option<RxRecord> {
        Some(RxRecord {
            psdu: Vec::from_slice(psdu).ok()?,
            info,
        })
    }
}

impl Default for TestRadio {
    fn default() -> Self {
        Self::new()
    }
}

impl Radio for TestRadio {
    type Error = RadioErrorKind;

    async fn init(&mut self) -> Result<RadioCaps, Self::Error> {
        if self.state == RadioState::Uninit {
            self.state = RadioState::Sleep;
        }
        Ok(self.caps)
    }

    async fn set_config(&mut self, config: &Config) -> Result<(), Self::Error> {
        self.config = config.clone();
        Ok(())
    }

    async fn set_src_match_config(&mut self, config: &SrcMatchConfig) -> Result<(), Self::Error> {
        self.src_match = config.clone();
        Ok(())
    }

    async fn set_receive(&mut self, channel: u8) -> Result<(), Self::Error> {
        // A timed window is cancelled by `set_receive`, but the MAC keeps
        // calling it while a window runs (contract C9): do not leave the window.
        if !matches!(self.state, RadioState::ReceiveAt { .. }) {
            self.state = RadioState::Receive { channel };
        }
        Ok(())
    }

    async fn set_receive_at(
        &mut self,
        channel: u8,
        start_us: u64,
        duration_us: u32,
    ) -> Result<(), Self::Error> {
        self.state = RadioState::ReceiveAt {
            channel,
            start_us,
            duration_us,
        };
        Ok(())
    }

    async fn set_sleep(&mut self) -> Result<(), Self::Error> {
        self.state = RadioState::Sleep;
        // Frames received while asleep are dropped, and so are any that were
        // queued but never read (C6: no late delivery).
        self.rx_queue.clear();
        Ok(())
    }

    async fn set_csl(&mut self, csl: &CslConfig) -> Result<(), Self::Error> {
        self.csl = *csl;
        Ok(())
    }

    async fn set_mac_keys(&mut self, keys: Option<&MacKeys>) -> Result<(), Self::Error> {
        self.mac_keys = keys.copied();
        Ok(())
    }

    async fn set_mac_frame_counter(
        &mut self,
        frame_counter: u32,
        if_larger: bool,
    ) -> Result<(), Self::Error> {
        if !if_larger || frame_counter > self.mac_frame_counter {
            self.mac_frame_counter = frame_counter;
        }
        Ok(())
    }

    async fn energy_scan(
        &mut self,
        _channel: u8,
        _duration_millis: u16,
    ) -> Result<i8, Self::Error> {
        if self.caps.hw_energy_scan() {
            Ok(self.energy_rssi)
        } else {
            Ok(super::RSSI_INVALID)
        }
    }

    async fn transmit(
        &mut self,
        psdu: &mut [u8],
        psdu_tx: &mut PsduTxInfo,
        channel: u8,
        power: i8,
        cca_threshold: Option<i8>,
        ack_psdu_buf: Option<&mut [u8]>,
    ) -> Result<Option<PsduRxInfo>, Self::Error> {
        if psdu.is_empty() || psdu.len() > MAX_PSDU_LEN {
            return Err(RadioErrorKind::TxInvalid);
        }
        let record = TxRecord {
            psdu: Vec::from_slice(psdu).map_err(|_| RadioErrorKind::TxInvalid)?,
            info: *psdu_tx,
            channel,
            power,
            cca_threshold,
        };
        // Like a real log with bounded storage: the oldest entry makes room.
        if self.tx_log.is_full() {
            self.tx_log.pop_front();
        }
        let _ = self.tx_log.push_back(record);

        // The transmit sequence ends back in receive mode (C4).
        self.state = RadioState::Receive { channel };

        if let Some(kind) = self.fail_next_tx.take() {
            return Err(kind);
        }

        let wants_ack = psdu[0] & FCF_ACK_REQUEST != 0;
        match ack_psdu_buf {
            Some(buf) if wants_ack && self.caps.hw_tx_ack() => {
                let ack = self
                    .ack_queue
                    .pop_front()
                    .ok_or(RadioErrorKind::RxAckTimeout)?;
                let dst = buf
                    .get_mut(..ack.psdu.len())
                    .ok_or(RadioErrorKind::RxAckInvalid)?;
                dst.copy_from_slice(&ack.psdu);
                Ok(Some(ack.info))
            }
            _ => Ok(None),
        }
    }

    async fn receive(&mut self, psdu_buf: &mut [u8]) -> Result<PsduRxInfo, Self::Error> {
        core::future::poll_fn(|cx| {
            // Peek first, pop only on success: cancellation-safe.
            let Some(front) = self.rx_queue.front() else {
                self.rx_waker = Some(cx.waker().clone());
                return core::task::Poll::Pending;
            };
            let len = front.psdu.len();
            let Some(dst) = psdu_buf.get_mut(..len) else {
                self.rx_queue.pop_front();
                return core::task::Poll::Ready(Err(RadioErrorKind::RxInvalid));
            };
            dst.copy_from_slice(&front.psdu);
            let info = front.info;
            self.rx_queue.pop_front();
            core::task::Poll::Ready(Ok(info))
        })
        .await
    }
}
