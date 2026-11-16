//! The sans-IO MAC state machine. See the [module docs](super) for the
//! interface contract.

use heapless::{Deque, Vec};
use opentrust_core::bytes::Writer;
use opentrust_core::crypto::SecurityLevel;
use opentrust_core::time::{Duration, Instant};
use opentrust_core::timer::TimerQueue;
use opentrust_core::types::{Channel, ExtAddress, PanId, ShortAddress};
use opentrust_core::{Error, Result};
use opentrust_platform::radio::{
    Capabilities, Config, MacCapabilities, PsduRxInfo, PsduTxInfo, RSSI_INVALID, RadioCaps,
    RadioErrorKind, SoftMacNeeds, SrcMatchConfig,
};
use opentrust_platform::radio::{CslConfig, MacKeys};
use rand_core::Rng;

use super::consts::*;
use super::csl::*;
use super::fcs::fcs;
use super::filter::{FilterError, FilterParams};
use super::indirect::{IndirectQueue, NeighborMap, SrcMatch, ext_to_u64};
use super::link_metrics::*;
use super::poll::PollSender;
use super::sub_mac::{
    TxKind, TxOp, TxState, air_time, csma_backoff_exponent, max_csma_duration, random_backoff,
};
use super::types::*;
use crate::frame::{
    Address, Beacon, CslIe, FCS_LEN, Frame, FrameBuilder, FrameMut, FrameType, FrameVersion,
    KeyIdMode, KeyIdentifier, MacCommand, SecurityHeader, THREAD_IE_ENH_ACK_PROBING,
    ThreadBeaconPayload, VendorIe,
};
use crate::frame_security::{FrameSecurity, RxSecurityInfo};

/// Tunable MAC parameters (defaults: Thread / OpenThread values from
/// the constants of this module).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct MacConfig {
    /// Retries of a direct frame (`macMaxFrameRetries`).
    pub max_frame_retries_direct: u8,
    /// Retries of an indirect frame within one poll.
    pub max_frame_retries_indirect: u8,
    /// `macMaxCSMABackoffs` for direct frames.
    pub max_csma_backoffs_direct: u8,
    /// `macMaxCSMABackoffs` for indirect frames.
    pub max_csma_backoffs_indirect: u8,
    /// Polls an indirect frame is offered to before it fails.
    pub max_tx_attempts_indirect_polls: u8,
    /// Software ACK timeout.
    pub ack_timeout: Duration,
    /// Receive window after a poll ACK with Frame Pending.
    pub data_poll_timeout: Duration,
    /// Transmit power in dBm.
    pub tx_power: i8,
    /// CCA (energy detect) threshold in dBm.
    pub cca_threshold: i8,
    /// Channels scans may use.
    pub supported_channels: u32,
    /// Noise floor in dBm for link margins reported in enhanced ACKs
    /// (OpenThread `SubMac::GetNoiseFloor`).
    pub noise_floor: i8,
}

impl MacConfig {
    /// Defaults for a radio with the given capabilities.
    pub const fn for_radio(caps: &RadioCaps) -> Self {
        Self {
            max_frame_retries_direct: MAX_FRAME_RETRIES_DIRECT,
            max_frame_retries_indirect: MAX_FRAME_RETRIES_INDIRECT,
            max_csma_backoffs_direct: MAX_CSMA_BACKOFFS_DIRECT,
            max_csma_backoffs_indirect: MAX_CSMA_BACKOFFS_INDIRECT,
            max_tx_attempts_indirect_polls: MAX_TX_ATTEMPTS_INDIRECT_POLLS,
            ack_timeout: ACK_TIMEOUT,
            data_poll_timeout: DATA_POLL_TIMEOUT,
            tx_power: caps.default_tx_power,
            cca_threshold: caps.default_cca_threshold,
            supported_channels: SUPPORTED_CHANNEL_MASK,
            noise_floor: caps.receive_sensitivity,
        }
    }
}

/// The MAC operation in progress (OpenThread `Mac::Operation`). One radio
/// operation runs at a time; pending ones start in priority order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Operation {
    /// Nothing; the radio receives (rx-on-when-idle) or sleeps.
    Idle,
    /// Beacon Request + listening, channel by channel.
    ActiveScan,
    /// Energy detection, channel by channel.
    EnergyScan,
    /// Sending a beacon.
    TransmitBeacon,
    /// Sending a frame to a polling child.
    TransmitDataIndirect,
    /// Sending a frame to a CSL synchronized child at its sample window.
    TransmitDataCsl,
    /// Sending a data poll.
    TransmitPoll,
    /// Sending a direct frame.
    TransmitDataDirect,
    /// Receiver on after a poll ACK with Frame Pending.
    WaitingForData,
}

const P_WAIT_DATA: u8 = 1 << 0;
const P_ACTIVE_SCAN: u8 = 1 << 1;
const P_ENERGY_SCAN: u8 = 1 << 2;
const P_BEACON: u8 = 1 << 3;
const P_POLL: u8 = 1 << 4;
const P_CSL_TX: u8 = 1 << 5;

/// What the MAC believes the radio is doing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RadioMode {
    Unknown,
    Sleep,
    Receive(u8),
}

/// A radio action awaiting its completion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InFlight {
    Ack(u8),
    Frame,
    EnergyScan,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TimerId {
    /// Backoff / ACK wait / retransmission delay.
    SubMac,
    /// Scan dwell time / data poll receive window.
    Operation,
    /// CSL receiver: next sample window / window end.
    CslRx,
    /// CSL transmitter: time to hand the next child frame to the radio.
    CslTx,
}

#[derive(Debug, Default)]
struct ScanState {
    channels: u32,
    channel: u8,
    duration: Duration,
    energy_pending: bool,
}

/// Header facts of a received frame, taken before it is decrypted.
#[derive(Debug, Clone, Copy)]
struct RxMeta {
    ftype: FrameType,
    version: FrameVersion,
    ack_request: bool,
    frame_pending: bool,
    security: bool,
    seq: Option<u8>,
    src: Address,
    dst: Address,
    is_data_request: bool,
}

impl RxMeta {
    fn of(f: &Frame<'_>) -> Self {
        Self {
            ftype: f.frame_type(),
            version: f.version(),
            ack_request: f.ack_request(),
            frame_pending: f.frame_pending(),
            security: f.security_enabled(),
            seq: f.sequence(),
            src: f.src_address(),
            dst: f.dst_address(),
            is_data_request: f.is_data_request(),
        }
    }
}

/// What was pushed to a radio that secures frames or enhanced ACKs itself.
#[derive(Debug, Default)]
struct HwSecurity {
    /// The radio needs keys and counters (`TRANSMIT_SEC` / `RECEIVE_TIMING`).
    enabled: bool,
    keys_sent: bool,
    keys: Option<MacKeys>,
    /// Frame counter pushed to the radio / reported back by it.
    counter: u32,
    /// A `SetMacFrameCounter` is due (`if_larger` flag).
    counter_due: Option<bool>,
}

enum AttemptNext {
    Csma,
    RetxDelay(Duration),
    Done,
}

/// The sans-IO IEEE 802.15.4 MAC; see the [module docs](super).
///
/// `S` secures/unsecures frames, `G` supplies the CSMA-CA / retransmission
/// backoff randomness (non-cryptographic use).
pub struct Mac<
    S,
    G,
    const TXQ: usize = TX_QUEUE_LEN,
    const IND: usize = INDIRECT_QUEUE_LEN,
    const EVQ: usize = EVENT_QUEUE_LEN,
    const POLLQ: usize = POLL_REQUEST_QUEUE_LEN,
    const NBQ: usize = NEIGHBOR_MAP_LEN,
    const CSLQ: usize = CSL_CHILD_LEN,
> {
    caps: RadioCaps,
    needs: SoftMacNeeds,
    config: MacConfig,
    security: S,
    rng: G,

    pan_id: PanId,
    short: ShortAddress,
    alt_short: Option<ShortAddress>,
    ext: ExtAddress,
    channel: u8,
    rx_on_when_idle: bool,
    /// Poll although the receiver is on when idle (attach, see
    /// [`Mac::set_poll_while_rx_on`]).
    poll_while_rx_on: bool,
    promiscuous: bool,
    beacon_enabled: bool,
    beacon: Option<ThreadBeaconPayload>,
    dsn: u8,
    bsn: u8,

    radio_mode: RadioMode,
    config_dirty: bool,
    src_match_dirty: bool,
    pending_ack: Option<(FrameBuf, u8)>,
    in_flight: Option<InFlight>,

    operation: Operation,
    pending: u8,
    tx_poll_before_data: bool,
    tx: Option<TxOp>,
    direct: Deque<(TxHandle, FrameBuf, Option<u8>), TXQ>,
    indirect: IndirectQueue<IND>,
    poll_requests: Deque<Address, POLLQ>,
    src_match: SrcMatch,
    neighbors: NeighborMap<NBQ>,
    scan: ScanState,
    poll: PollSender,
    timers: TimerQueue<TimerId, 4>,
    events: Deque<Event, EVQ>,
    counters: MacCounters,
    hw_sec: HwSecurity,
    csl: CslReceiver,
    csl_children: Vec<CslChild, CSLQ>,
    csl_tx_child: Option<Address>,
    csl_dirty: bool,
    probe_subject: ProbeTable<ENH_ACK_PROBING_LEN>,
    probe_initiator: ProbeTable<ENH_ACK_PROBING_LEN>,
    /// SFD time for the frame the next `start_frame` creates (CSL tx).
    next_tx_timed: Option<u64>,
}

impl<
    S,
    G,
    const TXQ: usize,
    const IND: usize,
    const EVQ: usize,
    const POLLQ: usize,
    const NBQ: usize,
    const CSLQ: usize,
> core::fmt::Debug for Mac<S, G, TXQ, IND, EVQ, POLLQ, NBQ, CSLQ>
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Mac")
            .field("operation", &self.operation)
            .field("pan_id", &self.pan_id)
            .field("short", &self.short)
            .field("channel", &self.channel)
            .field("rx_on_when_idle", &self.rx_on_when_idle)
            .field("radio_mode", &self.radio_mode)
            .field("in_flight", &self.in_flight)
            .finish_non_exhaustive()
    }
}

fn next_channel(mask: &mut u32) -> Option<u8> {
    if *mask == 0 {
        return None;
    }
    let ch = mask.trailing_zeros() as u8;
    *mask &= !(1u32 << ch);
    Some(ch)
}

fn map_radio_error(kind: RadioErrorKind) -> TxError {
    match kind {
        RadioErrorKind::TxAckTimeout
        | RadioErrorKind::RxAckTimeout
        | RadioErrorKind::TxAckFailed
        | RadioErrorKind::RxAckFailed
        | RadioErrorKind::RxAckInvalid => TxError::NoAck,
        RadioErrorKind::TxInvalid => TxError::Abort,
        RadioErrorKind::TxFailed
        | RadioErrorKind::RxFailed
        | RadioErrorKind::RxInvalid
        | RadioErrorKind::Other => TxError::ChannelAccessFailure,
    }
}

impl<S: FrameSecurity, G: Rng> Mac<S, G> {
    /// A MAC with the default queue capacities ([`TX_QUEUE_LEN`],
    /// [`INDIRECT_QUEUE_LEN`], [`EVENT_QUEUE_LEN`], [`POLL_REQUEST_QUEUE_LEN`],
    /// [`NEIGHBOR_MAP_LEN`]); see [`Mac::with_capacities`] for others.
    pub fn new(caps: RadioCaps, ext: ExtAddress, security: S, rng: G) -> Self {
        Self::with_capacities(caps, ext, security, rng)
    }
}

impl<
    S: FrameSecurity,
    G: Rng,
    const TXQ: usize,
    const IND: usize,
    const EVQ: usize,
    const POLLQ: usize,
    const NBQ: usize,
    const CSLQ: usize,
> Mac<S, G, TXQ, IND, EVQ, POLLQ, NBQ, CSLQ>
{
    /// A MAC with explicit queue capacities (const generics: direct
    /// transmit queue `TXQ`, indirect queue `IND`, upward events `EVQ`,
    /// received data polls awaiting service `POLLQ`, short -> extended
    /// address map `NBQ`), for a radio with capabilities `caps` (from
    /// [`Radio::init`](opentrust_platform::Radio::init)), extended address
    /// `ext`, frame security `security` and backoff RNG `rng`.
    ///
    /// Initial state: PAN ID and short address unset (0xffff / 0xfffe),
    /// channel 11, receiver on when idle.
    pub fn with_capacities(caps: RadioCaps, ext: ExtAddress, security: S, mut rng: G) -> Self {
        let dsn = rng.next_u32() as u8;
        let bsn = rng.next_u32() as u8;
        let hw_src_match = caps.mac.contains(MacCapabilities::SRC_MATCH);
        Self {
            needs: caps.soft_mac_needs(),
            config: MacConfig::for_radio(&caps),
            caps,
            security,
            rng,
            pan_id: PanId::BROADCAST,
            short: ShortAddress::INVALID,
            alt_short: None,
            ext,
            channel: Channel::MIN,
            rx_on_when_idle: true,
            poll_while_rx_on: false,
            promiscuous: false,
            beacon_enabled: false,
            beacon: None,
            dsn,
            bsn,
            radio_mode: RadioMode::Unknown,
            config_dirty: true,
            src_match_dirty: hw_src_match,
            pending_ack: None,
            in_flight: None,
            operation: Operation::Idle,
            pending: 0,
            tx_poll_before_data: false,
            tx: None,
            direct: Deque::new(),
            indirect: IndirectQueue::default(),
            poll_requests: Deque::new(),
            src_match: SrcMatch::default(),
            neighbors: NeighborMap::default(),
            scan: ScanState::default(),
            poll: PollSender::default(),
            timers: TimerQueue::new(),
            events: Deque::new(),
            counters: MacCounters::default(),
            csl: CslReceiver::new(),
            csl_children: Vec::new(),
            csl_tx_child: None,
            csl_dirty: false,
            probe_subject: ProbeTable::default(),
            probe_initiator: ProbeTable::default(),
            next_tx_timed: None,
            hw_sec: HwSecurity {
                enabled: caps
                    .phy
                    .intersects(Capabilities::TRANSMIT_SEC | Capabilities::RECEIVE_TIMING),
                ..HwSecurity::default()
            },
        }
    }

    // ------------------------------------------------------------------
    // Configuration
    // ------------------------------------------------------------------

    /// The radio capabilities the MAC was created for.
    pub fn caps(&self) -> &RadioCaps {
        &self.caps
    }

    /// The MAC functions done in software for this radio.
    pub fn soft_mac_needs(&self) -> SoftMacNeeds {
        self.needs
    }

    /// Tunable parameters.
    pub fn config(&self) -> &MacConfig {
        &self.config
    }

    /// Mutable tunable parameters (take effect for the next frame).
    pub fn config_mut(&mut self) -> &mut MacConfig {
        &mut self.config
    }

    /// The frame security implementation.
    pub fn security(&self) -> &S {
        &self.security
    }

    /// Mutable frame security (key updates).
    pub fn security_mut(&mut self) -> &mut S {
        &mut self.security
    }

    /// Counters.
    pub fn counters(&self) -> &MacCounters {
        &self.counters
    }

    /// Reset all counters (OT `otLinkResetCounters`).
    pub fn reset_counters(&mut self) {
        self.counters = MacCounters::default();
    }

    /// Current operation.
    pub fn operation(&self) -> Operation {
        self.operation
    }

    /// PAN ID.
    pub fn pan_id(&self) -> PanId {
        self.pan_id
    }

    /// Set the PAN ID.
    pub fn set_pan_id(&mut self, pan_id: PanId) {
        if self.pan_id != pan_id {
            self.pan_id = pan_id;
            self.config_dirty = true;
        }
    }

    /// Short address ([`ShortAddress::INVALID`] if none).
    pub fn short_address(&self) -> ShortAddress {
        self.short
    }

    /// Set the short address.
    pub fn set_short_address(&mut self, short: ShortAddress) {
        if self.short != short {
            self.short = short;
            self.config_dirty = true;
        }
    }

    /// Set (or clear) the alternate short address (FTD role transition).
    pub fn set_alternate_short_address(&mut self, short: Option<ShortAddress>) {
        if self.alt_short != short {
            self.alt_short = short;
            self.config_dirty = true;
        }
    }

    /// Extended address.
    pub fn ext_address(&self) -> ExtAddress {
        self.ext
    }

    /// Set the extended address.
    pub fn set_ext_address(&mut self, ext: ExtAddress) {
        if self.ext != ext {
            self.ext = ext;
            self.config_dirty = true;
        }
    }

    /// PAN channel.
    pub fn channel(&self) -> u8 {
        self.channel
    }

    /// Set the PAN channel (11..=26).
    pub fn set_channel(&mut self, channel: u8) -> Result<()> {
        Channel::new(channel)?;
        self.channel = channel;
        Ok(())
    }

    /// Receiver on when idle?
    pub fn rx_on_when_idle(&self) -> bool {
        self.rx_on_when_idle
    }

    /// Set rx-on-when-idle (`false` for a sleepy end device).
    pub fn set_rx_on_when_idle(&mut self, on: bool) {
        self.rx_on_when_idle = on;
    }

    /// Let the data poll sender poll while the receiver is on when idle.
    /// A device attaching as a sleepy child polls its parent candidate for
    /// the Child ID Response but keeps listening, so that a parent sending
    /// the response directly is heard as well. Cleared by
    /// [`stop_polling`](Self::stop_polling).
    pub fn set_poll_while_rx_on(&mut self, on: bool) {
        self.poll_while_rx_on = on;
    }

    /// Promiscuous mode: every frame is delivered unfiltered and
    /// unprocessed (no ACKs, no security), flagged [`RxFrame::promiscuous`].
    pub fn set_promiscuous(&mut self, on: bool) {
        if self.promiscuous != on {
            self.promiscuous = on;
            self.config_dirty = true;
        }
    }

    /// Answer Beacon Requests with a beacon (OT `Mac::SetBeaconEnabled`;
    /// MLE enables it while the device is router eligible and attached).
    pub fn set_beacon_enabled(&mut self, enabled: bool) {
        self.beacon_enabled = enabled;
    }

    /// The Thread beacon payload sent in beacons (`None`: a beacon without
    /// payload). Thread 1.2.1 removed beacon payloads; OpenThread sends
    /// them only with `OPENTHREAD_CONFIG_MAC_OUTGOING_BEACON_PAYLOAD_ENABLE`.
    pub fn set_beacon_payload(&mut self, payload: Option<ThreadBeaconPayload>) {
        self.beacon = payload;
    }

    /// Register the extended address behind a short address (neighbor table
    /// mirror, needed to unsecure frames sent from short addresses and to
    /// match polls by either address).
    pub fn set_neighbor(&mut self, short: ShortAddress, ext: ExtAddress) -> Result<()> {
        self.neighbors.set(short, ext)?;
        self.update_src_match();
        Ok(())
    }

    /// Forget a short → extended mapping.
    pub fn remove_neighbor(&mut self, short: ShortAddress) -> bool {
        let r = self.neighbors.remove(short);
        self.update_src_match();
        r
    }

    /// Forget all short → extended mappings.
    pub fn clear_neighbors(&mut self) {
        self.neighbors.clear();
        self.update_src_match();
    }

    // ------------------------------------------------------------------
    // CSL (Thread 1.2+): receiver (SSED) and transmitter (parent)
    // ------------------------------------------------------------------

    /// The radio clock in microseconds, if the radio has one
    /// ([`RadioCaps::clock`]); CSL needs it.
    fn radio_now_us(&self) -> Option<u64> {
        self.caps.clock.map(|c| c.now_us())
    }

    fn csl_rx_channel(&self) -> u8 {
        if self.csl.channel == 0 {
            self.channel
        } else {
            self.csl.channel
        }
    }

    /// Configure CSL reception (OpenThread `SubMac::SetCslParams`): sample
    /// the channel every `period` (units of 10 symbols, [`MIN_CSL_PERIOD`]
    /// or more; 0 turns CSL off) on `channel` (0 = the PAN channel), the
    /// parent being `parent_short` / `parent_ext` (the peer the CSL IE in
    /// enhanced ACKs is for). The first sample time is `now`.
    ///
    /// Radios with `Capabilities::RECEIVE_TIMING` get one timed receive
    /// window per period ([`RadioAction::ReceiveAt`]) and the schedule for
    /// their enhanced ACKs ([`RadioAction::SetCsl`]); without it the MAC
    /// turns the receiver on and off itself. The radio needs a clock
    /// ([`RadioCaps::clock`]): [`Error::NotImplemented`] without.
    /// [`Error::InvalidArgs`] for a period shorter than the minimum.
    pub fn set_csl(
        &mut self,
        period: u16,
        channel: u8,
        parent_short: ShortAddress,
        parent_ext: ExtAddress,
        now: Instant,
    ) -> Result<()> {
        if period != 0 {
            if period < MIN_CSL_PERIOD {
                return Err(Error::InvalidArgs);
            }
            if self.caps.clock.is_none() {
                return Err(Error::NotImplemented);
            }
        }
        self.poll.set_csl_period(
            Duration::from_micros(u64::from(period) * u64::from(US_PER_TEN_SYMBOLS)),
            now,
        );
        let diff_period = period != self.csl.period;
        let diff_peer = parent_short != self.csl.peer_short || parent_ext != self.csl.peer_ext;
        self.csl.channel = channel;
        if !(diff_period || diff_peer) {
            return Ok(());
        }
        self.csl.peer_short = parent_short;
        self.csl.peer_ext = parent_ext;
        self.csl.period = period;
        self.csl.sampling = false;
        self.csl.window = None;
        self.csl.last_sync = None;
        self.timers.stop(TimerId::CslRx);
        self.csl.radio_dirty = self.caps.hw_csl();
        if period != 0 {
            self.csl.sample_radio = self.radio_now_us().unwrap_or(0) as u32;
            self.csl.sample_local = now;
            self.csl_timer();
        }
        Ok(())
    }

    /// CSL period in units of 10 symbols (0 = off).
    pub fn csl_period(&self) -> u16 {
        self.csl.period
    }

    /// The CSL channel (0 = the PAN channel).
    pub fn csl_channel(&self) -> u8 {
        self.csl.channel
    }

    /// The parent's CSL accuracy (MLE CSL Accuracy TLV); until it is known
    /// the worst case is assumed ([`CslAccuracy::WORST`]).
    pub fn set_csl_parent_accuracy(&mut self, accuracy: CslAccuracy) {
        opentrust_core::trace!(
            "mac: CSL parent accuracy {} ppm, uncertainty {} x 10 us",
            accuracy.clock_ppm,
            accuracy.uncertainty_10us
        );
        self.csl.parent = accuracy;
    }

    /// The next sample time (low 32 bits of the radio clock, microseconds).
    pub fn csl_sample_time(&self) -> u32 {
        self.csl.sample_radio
    }

    /// The time the receiver listens before / after the sample time at
    /// radio time `radio_now_us` (see [`window_edges`]); `None` if CSL is
    /// off.
    pub fn csl_window_edges(&self, radio_now_us: u64) -> Option<(u32, u32)> {
        self.csl.enabled().then(|| {
            let elapsed = self
                .csl
                .last_sync
                .map_or(u32::MAX, |s| (radio_now_us as u32).wrapping_sub(s));
            window_edges(
                self.csl.period,
                elapsed,
                self.caps.csl_accuracy_ppm,
                self.caps.csl_uncertainty,
                self.csl.parent,
                self.caps.csl_receive_on_after_us,
            )
        })
    }

    /// The CSL timer (OpenThread `SubMac::HandleCslTimer`): arm the next
    /// sample window.
    fn csl_timer(&mut self) {
        if !self.csl.enabled() {
            return;
        }
        let Some(radio_now) = self.radio_now_us() else {
            return;
        };
        let Some((ahead, after)) = self.csl_window_edges(radio_now) else {
            return;
        };
        let period_us = self.csl.period_us();
        let period = Duration::from_micros(u64::from(period_us));
        if self.caps.hw_csl() {
            // One call per period: the timer fires `ahead` before the next
            // sample, the radio listens in the window by itself.
            let lead = self.caps.receive_at_lead_us.min(period_us / 2);
            let at = (self.csl.sample_local + period)
                .saturating_sub(Duration::from_micros(u64::from(ahead) + u64::from(lead)));
            let _ = self.timers.start(TimerId::CslRx, at);
            let ahead = ahead.saturating_sub(CSL_RECEIVE_TIME_AHEAD);
            let start32 = self.csl.sample_radio.wrapping_sub(ahead);
            let delta = start32.wrapping_sub(radio_now as u32) as i32;
            let start = (radio_now as i64 + i64::from(delta)).max(0) as u64;
            self.csl.sample_radio = self.csl.sample_radio.wrapping_add(period_us);
            self.csl.sample_local += period;
            self.csl.radio_dirty = true;
            self.csl.window = Some((self.csl_rx_channel(), start, ahead + after));
        } else if self.csl.sampling {
            self.csl.sampling = false;
            let at = self
                .csl
                .sample_local
                .saturating_sub(Duration::from_micros(ahead.into()));
            let _ = self.timers.start(TimerId::CslRx, at);
        } else {
            // Listen from now until `after` the sample time.
            let at = self.csl.sample_local + Duration::from_micros(after.into());
            let _ = self.timers.start(TimerId::CslRx, at);
            self.csl.sampling = true;
            self.csl.sample_radio = self.csl.sample_radio.wrapping_add(period_us);
            self.csl.sample_local += period;
        }
    }

    /// Set the CSL IE phase of the frame about to be sent and secure it
    /// again (new frame counter), for a software-secured CSL frame
    /// (Thread §3.2.6.3.7); the radio does this itself with
    /// `Capabilities::TRANSMIT_SEC`. The SFD time is estimated as now plus
    /// the CCA and the SHR (OpenThread leaves the exact moment to the radio).
    /// Returns `false` if the frame failed and the attempt was completed.
    fn refresh_soft_csl(&mut self, now: Instant) -> bool {
        let Some(mut frame) = self.tx.as_ref().and_then(|t| t.csl_plain.clone()) else {
            return true;
        };
        if self.csl.enabled() {
            let sfd = (self.radio_now_us().unwrap_or(0) as u32)
                .wrapping_add(CCA_SAMPLE_INTERVAL + SHR_DURATION);
            let phase = csl_phase(self.csl.sample_radio, sfd, self.csl.period);
            let set =
                FrameMut::new(&mut frame).and_then(|mut m| m.set_csl_ie(phase, self.csl.period));
            if set.is_err() {
                self.attempt_done(Err(TxError::Abort), now);
                return false;
            }
        }
        if self.security.secure_tx(&mut frame, &self.ext).is_err() {
            self.attempt_done(Err(TxError::Security), now);
            return false;
        }
        if let Some(tx) = self.tx.as_mut() {
            tx.frame = frame;
        }
        true
    }

    /// Track `child` for CSL transmissions (parent side). Its CSL IEs (in
    /// secured 2015 frames and enhanced ACKs from it) then synchronize it,
    /// and indirect frames queued for it
    /// ([`transmit_indirect`](Self::transmit_indirect)) are sent into its
    /// sample windows instead of waiting for a data poll. Needs a radio
    /// clock ([`Error::NotImplemented`]); [`Error::NoBufs`] if the table is
    /// full.
    pub fn csl_add_child(&mut self, child: Address) -> Result<()> {
        if child.is_none() || child.is_broadcast() {
            return Err(Error::InvalidArgs);
        }
        if self.caps.clock.is_none() {
            return Err(Error::NotImplemented);
        }
        if self
            .csl_children
            .iter()
            .any(|c| self.neighbors.same_device(c.addr, child))
        {
            return Ok(());
        }
        self.csl_children
            .push(CslChild::new(child))
            .map_err(|_| Error::NoBufs)
    }

    /// Stop CSL tracking of `child`.
    pub fn csl_remove_child(&mut self, child: Address) -> bool {
        let Some(i) = self
            .csl_children
            .iter()
            .position(|c| self.neighbors.same_device(c.addr, child))
        else {
            return false;
        };
        self.csl_children.remove(i);
        self.csl_dirty = true;
        true
    }

    /// The CSL state of `child`.
    pub fn csl_child(&self, child: Address) -> Option<&CslChild> {
        self.csl_children
            .iter()
            .find(|c| self.neighbors.same_device(c.addr, child))
    }

    /// All tracked CSL children.
    pub fn csl_children(&self) -> &[CslChild] {
        &self.csl_children
    }

    /// Set the CSL channel of `child` (MLE CSL Channel TLV; 0 = the PAN
    /// channel). [`Error::NotFound`] if it is not tracked.
    pub fn csl_set_child_channel(&mut self, child: Address, channel: u8) -> Result<()> {
        let i = self
            .csl_children
            .iter()
            .position(|c| self.neighbors.same_device(c.addr, child))
            .ok_or(Error::NotFound)?;
        self.csl_children[i].channel = channel;
        Ok(())
    }

    /// Mark `child` as not synchronized (CSL synchronized timeout expired,
    /// child detached): frames wait for its data polls.
    pub fn csl_child_desync(&mut self, child: Address) {
        if let Some(i) = self
            .csl_children
            .iter()
            .position(|c| self.neighbors.same_device(c.addr, child))
        {
            self.csl_children[i].synchronized = false;
            self.csl_children[i].tx_attempts = 0;
            self.csl_dirty = true;
        }
    }

    /// Microseconds before a CSL window the MAC takes the frame
    /// (`CslTxScheduler::mCslFrameRequestAheadUs`).
    pub fn csl_request_ahead_us(&self) -> u32 {
        let mut bus = self.caps.bus_latency_us;
        if self.caps.bus_speed != 0 {
            bus += (u64::from(CSL_BUS_FRAME_SIZE) * 8 * 1_000_000)
                .div_ceil(u64::from(self.caps.bus_speed)) as u32;
        }
        CSL_REQUEST_AHEAD + bus
    }

    /// Start tracking the sender of a received frame or poll as a CSL child
    /// and take its CSL IE (the first frame of a child that is not tracked
    /// yet reached the MAC before the upper layer knew it sends CSL IEs).
    /// The upper layer calls it for a secured 2015 frame with a CSL IE from
    /// one of its children, with `channel` the child's CSL channel (0 = the
    /// PAN channel). `ts` is the frame's radio timestamp (`None`: the radio
    /// clock now). Only the IE is applied for a child that is tracked
    /// already; fails like [`csl_add_child`](Self::csl_add_child).
    pub fn csl_child_sample(
        &mut self,
        src: Address,
        channel: u8,
        ie: CslIe,
        ts: Option<u64>,
        now: Instant,
    ) -> Result<()> {
        if !self
            .csl_children
            .iter()
            .any(|c| self.neighbors.same_device(c.addr, src))
        {
            self.csl_add_child(src)?;
            self.csl_set_child_channel(src, channel)?;
        }
        self.csl_apply_ie(src, ie, ts, now);
        Ok(())
    }

    /// The CSL IE of a received frame or ACK from a tracked child
    /// (OpenThread `Mac::ProcessCsl`).
    fn csl_update_child(&mut self, f: &Frame<'_>, src: Address, ts: Option<u64>, now: Instant) {
        if self.csl_children.is_empty() || f.version() != FrameVersion::V2015 {
            return;
        }
        if !f.security_enabled() {
            return;
        }
        let Some(ie) = f.csl_ie() else {
            return;
        };
        self.csl_apply_ie(src, ie, ts, now);
    }

    /// Take the CSL IE `ie` of a frame from `src`, if it is a tracked child.
    fn csl_apply_ie(&mut self, src: Address, ie: CslIe, ts: Option<u64>, now: Instant) {
        let Some(i) = self
            .csl_children
            .iter()
            .position(|c| self.neighbors.same_device(c.addr, src))
        else {
            return;
        };
        if ie.period < MIN_CSL_IE_PERIOD {
            return;
        }
        // Without a timestamp the frame's SFD is taken to be one CCA and SHR
        // after the radio time it was handed over at: what the sender
        // assumes when it puts the phase into the IE (`refresh_soft_csl`; no
        // air time, as on a simulated medium).
        let Some(ts) = ts.or_else(|| {
            self.radio_now_us()
                .map(|n| n + u64::from(CCA_SAMPLE_INTERVAL + SHR_DURATION))
        }) else {
            return;
        };
        let c = &mut self.csl_children[i];
        c.period = ie.period;
        c.phase = ie.phase;
        c.synchronized = true;
        c.last_heard = Some(now);
        c.last_rx_timestamp_us = ts;
        self.csl_dirty = true;
    }

    /// Pick the child whose next window is first and arm the timer that
    /// hands its frame to the radio `csl_request_ahead_us` before it
    /// (`CslTxScheduler::RescheduleCslTx`).
    fn csl_reschedule(&mut self, now: Instant) {
        self.csl_dirty = false;
        if self.operation == Operation::TransmitDataCsl || self.pending & P_CSL_TX != 0 {
            return; // rescheduled when that transmission is done
        }
        self.timers.stop(TimerId::CslTx);
        self.csl_tx_child = None;
        let Some(radio_now) = self.radio_now_us() else {
            return;
        };
        let ahead = self.csl_request_ahead_us();
        let mut best: Option<(Address, u32)> = None;
        for c in self.csl_children.iter() {
            if !c.synchronized
                || c.period == 0
                || self.indirect.count_for(c.addr, &self.neighbors) == 0
            {
                continue;
            }
            let (_, _, delay) =
                next_tx_window(radio_now, c.period, c.phase, c.last_rx_timestamp_us, ahead);
            if best.is_none_or(|(_, d)| delay < d) {
                best = Some((c.addr, delay));
            }
        }
        if let Some((addr, delay)) = best {
            self.csl_tx_child = Some(addr);
            let _ = self
                .timers
                .start(TimerId::CslTx, now + Duration::from_micros(delay.into()));
        }
    }

    /// Start the CSL transmission to the chosen child
    /// (`CslTxScheduler::HandleFrameRequest`).
    fn start_csl_tx(&mut self, now: Instant) {
        let child = self
            .csl_tx_child
            .take()
            .and_then(|a| self.csl_children.iter().find(|c| c.addr == a).copied());
        let radio_now = self.radio_now_us();
        let (Some(child), Some(radio_now)) = (child, radio_now) else {
            self.finish_operation();
            self.csl_dirty = true;
            return;
        };
        let i = self.indirect.find_for(child.addr, &self.neighbors);
        let Some(i) = i.filter(|_| child.synchronized && child.period != 0) else {
            self.finish_operation();
            self.csl_dirty = true;
            return;
        };
        let (window, _, delay) = next_tx_window(
            radio_now,
            child.period,
            child.phase,
            child.last_rx_timestamp_us,
            0,
        );
        // Busy with something else and late: this window is gone.
        if delay > self.csl_request_ahead_us() + FRAME_PREPARATION_GUARD {
            self.finish_operation();
            self.csl_dirty = true;
            return;
        }
        if !self.prepare_indirect_frame(i) {
            self.csl_dirty = true;
            return;
        }
        let f = &self.indirect.frames[i];
        let (handle, frame, processed, retx) =
            (f.handle, f.frame.clone(), f.security_processed, f.sent);
        let channel = if child.channel == 0 {
            self.channel
        } else {
            child.channel
        };
        self.next_tx_timed = Some(window);
        self.start_frame(
            TxKind::Indirect(Some(handle)),
            frame,
            channel,
            true,
            processed,
            now,
        );
        if let Some(tx) = self.tx.as_mut() {
            tx.retransmission = retx;
        }
    }

    /// Completion of a CSL transmission (`CslTxScheduler::HandleSentFrame`):
    /// success completes the frame; a failure leaves it queued (with the
    /// frame counter and sequence number it was sent with), and after
    /// [`MAX_CSL_TX_ATTEMPTS`] failures without ACK the child is out of sync.
    fn csl_tx_done(&mut self, i: usize, handle: TxHandle, tx: TxOp, res: TxResult) {
        let ci = self
            .csl_children
            .iter()
            .position(|c| c.addr == tx.dst || self.neighbors.same_device(c.addr, tx.dst));
        match res {
            Ok(_) => {
                if let Some(ci) = ci {
                    self.csl_children[ci].tx_attempts = 0;
                }
                self.indirect.remove(i);
                self.update_src_match();
                self.push_event(Event::TxDone {
                    handle,
                    result: res,
                });
            }
            Err(e) => {
                let f = &mut self.indirect.frames[i];
                f.frame = tx.frame;
                f.security_processed = tx.security_processed;
                f.prepared = true;
                f.sent = true;
                if e == TxError::NoAck {
                    if let Some(ci) = ci {
                        let c = &mut self.csl_children[ci];
                        c.tx_attempts += 1;
                        if c.tx_attempts >= MAX_CSL_TX_ATTEMPTS {
                            c.synchronized = false;
                            c.tx_attempts = 0;
                            let addr = c.addr;
                            self.push_event(Event::CslChildOutOfSync(addr));
                        }
                    }
                }
            }
        }
    }

    // ------------------------------------------------------------------
    // Enhanced-ACK based Link Metrics probing (MAC part)
    // ------------------------------------------------------------------

    /// Subject side: report `flags` (at most two metrics, LQI / link margin /
    /// RSSI) of every frame from the probing initiator (`short`, `ext`) in the
    /// Thread vendor IE of the enhanced ACKs sent for it. Empty `flags` clear
    /// the configuration ([`Error::NotFound`] if there was none). The call
    /// the MLE Link Metrics Management handler makes for Enh-ACK Flags 1 / 0.
    /// [`Error::InvalidArgs`] for more than two metrics, [`Error::NoBufs`] if
    /// the table ([`ENH_ACK_PROBING_LEN`]) is full.
    ///
    /// Only the MAC's own (software) enhanced ACKs carry the IE; a radio
    /// that acknowledges in hardware does not know the configuration.
    pub fn configure_enh_ack_probing(
        &mut self,
        short: ShortAddress,
        ext: ExtAddress,
        flags: LinkMetricsFlags,
    ) -> Result<()> {
        self.probe_subject.configure(short, ext, flags)
    }

    /// Subject side: forget all initiators (`otLinkMetricsResetEnhAckProbing`).
    pub fn reset_enh_ack_probing(&mut self) {
        self.probe_subject.clear();
    }

    /// Initiator side: the subject (`short`, `ext`) was configured (through
    /// MLE) to report `flags` in its enhanced ACKs: decode its probing IEs
    /// and report them as [`Event::EnhAckLinkMetrics`]. Empty `flags` stop it.
    pub fn track_enh_ack_probing(
        &mut self,
        short: ShortAddress,
        ext: ExtAddress,
        flags: LinkMetricsFlags,
    ) -> Result<()> {
        self.probe_initiator.configure(short, ext, flags)
    }

    /// Initiator side: stop tracking all subjects.
    pub fn reset_tracked_enh_ack_probing(&mut self) {
        self.probe_initiator.clear();
    }

    /// The probing IE data for the enhanced ACK of `rx`, if its sender is a
    /// configured initiator and the metrics are known; bytes used.
    fn enh_ack_probe_data(
        &self,
        rx: &Frame<'_>,
        info: &PsduRxInfo,
        out: &mut [u8; ENH_ACK_PROBING_MAX_DATA],
    ) -> usize {
        if rx.version() != FrameVersion::V2015 {
            return 0;
        }
        let Some(e) = self.probe_subject.find(rx.src_address()) else {
            return 0;
        };
        let rssi = info.rssi.filter(|r| *r != RSSI_INVALID);
        encode_enh_ack_data(e.flags, info.lqi, rssi, self.config.noise_floor, out).unwrap_or(0)
    }

    /// An ACK from `peer` for our frame: decode its probing IE
    /// (OpenThread `Mac::ProcessEnhAckProbing`).
    fn process_enh_ack_probing(&mut self, ack: &Frame<'_>, peer: Address) {
        let Some(e) = self.probe_initiator.find(peer) else {
            return;
        };
        let flags = e.flags;
        let Some(ie) = ack.find_thread_ie(THREAD_IE_ENH_ACK_PROBING) else {
            return;
        };
        if ie.data.len() > ENH_ACK_PROBING_MAX_DATA {
            return;
        }
        let values = decode_enh_ack_data(flags, ie.data);
        self.push_event(Event::EnhAckLinkMetrics {
            neighbor: peer,
            values,
        });
    }

    // ------------------------------------------------------------------
    // Upper-layer requests
    // ------------------------------------------------------------------

    fn validate_frame(frame: &[u8]) -> Result<FrameBuf> {
        let f = Frame::parse(frame)?;
        if f.is_ack() {
            return Err(Error::InvalidArgs);
        }
        FrameBuf::from_slice(frame).map_err(|_| Error::NoBufs)
    }

    /// Queue a direct frame (without FCS, as built by
    /// [`FrameBuilder`]). The MAC assigns the sequence number and secures it
    /// (if the security-enabled bit is set); completion is reported as
    /// [`Event::TxDone`] with `handle`.
    pub fn transmit(&mut self, handle: TxHandle, frame: &[u8]) -> Result<()> {
        self.transmit_on(handle, frame, None)
    }

    /// [`transmit`](Self::transmit) on `channel` instead of the PAN channel
    /// (MLE Discovery and Announce messages, OT `Message::SetChannel`).
    pub fn transmit_on(
        &mut self,
        handle: TxHandle,
        frame: &[u8],
        channel: Option<u8>,
    ) -> Result<()> {
        let buf = Self::validate_frame(frame)?;
        self.direct
            .push_back((handle, buf, channel))
            .map_err(|_| Error::NoBufs)
    }

    /// Queue a frame for a sleepy child at `dst` until it polls (parent
    /// side). Its address enters the source-match table, so the child's
    /// poll is acked with Frame Pending.
    pub fn transmit_indirect(
        &mut self,
        handle: TxHandle,
        dst: Address,
        frame: &[u8],
    ) -> Result<()> {
        let buf = Self::validate_frame(frame)?;
        self.indirect.push(handle, dst, buf)?;
        self.update_src_match();
        self.csl_dirty = true;
        Ok(())
    }

    /// Drop all indirect frames for the device at `dst` (child removed),
    /// reporting them as [`TxError::Abort`]. Returns how many were dropped.
    pub fn purge_indirect(&mut self, dst: Address) -> usize {
        let mut n = 0;
        while let Some(i) = self.indirect.find_for(dst, &self.neighbors) {
            let f = self.indirect.remove(i);
            self.push_event(Event::TxDone {
                handle: f.handle,
                result: Err(TxError::Abort),
            });
            n += 1;
        }
        self.update_src_match();
        self.csl_dirty = true;
        n
    }

    /// Drop one indirect frame, reporting it as [`TxError::Abort`].
    pub fn cancel_indirect(&mut self, handle: TxHandle) -> bool {
        let Some(i) = self.indirect.position(handle) else {
            return false;
        };
        let f = self.indirect.remove(i);
        self.push_event(Event::TxDone {
            handle: f.handle,
            result: Err(TxError::Abort),
        });
        self.update_src_match();
        self.csl_dirty = true;
        true
    }

    /// Number of frames in the indirect queue.
    pub fn indirect_len(&self) -> usize {
        self.indirect.frames.len()
    }

    /// Mark `addr` as having pending data although no frame is queued in
    /// the MAC (e.g. data held by MLE), so its polls are acked with Frame
    /// Pending. Frames queued with [`transmit_indirect`](Self::transmit_indirect)
    /// are matched automatically.
    pub fn src_match_add(&mut self, addr: Address) -> Result<()> {
        self.src_match.pin(addr)?;
        self.update_src_match();
        Ok(())
    }

    /// Undo [`src_match_add`](Self::src_match_add).
    pub fn src_match_remove(&mut self, addr: Address) -> bool {
        let r = self.src_match.unpin(addr);
        self.update_src_match();
        r
    }

    /// Remove all pinned source-match entries.
    pub fn src_match_clear(&mut self) {
        self.src_match.clear_pins();
        self.update_src_match();
    }

    /// The effective source-match table.
    pub fn src_match_table(&self) -> &SrcMatchConfig {
        self.src_match.table()
    }

    fn update_src_match(&mut self) {
        if self.src_match.rebuild(&self.indirect)
            && self.caps.mac.contains(MacCapabilities::SRC_MATCH)
        {
            self.src_match_dirty = true;
        }
    }

    /// Start polling `parent` (sleepy end device; requires
    /// rx-on-when-idle off).
    pub fn start_polling(&mut self, parent: Address, now: Instant) {
        self.poll.start(parent, now);
    }

    /// Stop polling.
    pub fn stop_polling(&mut self) {
        self.poll_while_rx_on = false;
        self.poll.stop();
    }

    /// Is the data poll sender enabled?
    pub fn is_polling(&self) -> bool {
        self.poll.enabled
    }

    /// Set the default poll period (MLE derives it from the child timeout).
    pub fn set_poll_period(&mut self, period: Duration, now: Instant) {
        self.poll.set_default_period(period, now);
    }

    /// The poll period currently in use.
    pub fn poll_period(&self) -> Duration {
        self.poll.period()
    }

    /// The parent supports the enhanced keep-alive (Thread 1.2 and later, OT
    /// `Neighbor::IsEnhancedKeepAliveSupported`).
    pub fn set_parent_enhanced_keep_alive(&mut self, on: bool) {
        self.poll.parent_enhanced_keep_alive = on;
    }

    /// Secure data polls (default `true`, as Thread requires).
    pub fn set_poll_security(&mut self, on: bool) {
        self.poll.secure = on;
    }

    /// Attach mode: poll every 100 ms until turned off (OT
    /// `DataPollSender::SetAttachMode`).
    pub fn set_poll_attach_mode(&mut self, on: bool, now: Instant) {
        self.poll.set_attach_mode(on, now);
    }

    /// Poll `n` times at the fast poll period (`0`: default count).
    pub fn send_fast_polls(&mut self, n: u8, now: Instant) {
        self.poll.send_fast_polls(n, now);
    }

    /// Send a data poll now (OpenThread `DataPollSender::SendDataPoll`).
    ///
    /// [`Error::InvalidState`] (and polling stops) if polling is not enabled
    /// or the receiver is on when idle; [`Error::Already`] if a poll is
    /// already pending.
    pub fn send_data_poll(&mut self, now: Instant) -> Result<()> {
        if !self.poll.enabled || (self.rx_on_when_idle && !self.poll_while_rx_on) {
            self.poll.stop();
            return Err(Error::InvalidState);
        }
        self.poll.stop_timer();
        if self.pending & P_POLL != 0 || self.operation == Operation::TransmitPoll {
            self.poll.schedule(true, now);
            return Err(Error::Already);
        }
        self.pending |= P_POLL;
        self.poll.schedule(false, now);
        Ok(())
    }

    fn scan_busy(&self) -> bool {
        self.pending & (P_ACTIVE_SCAN | P_ENERGY_SCAN) != 0
            || matches!(
                self.operation,
                Operation::ActiveScan | Operation::EnergyScan
            )
    }

    fn scan_mask(&self, channels: u32) -> Result<u32> {
        let mask = if channels == 0 {
            self.config.supported_channels
        } else {
            channels & self.config.supported_channels
        };
        if mask == 0 {
            return Err(Error::InvalidArgs);
        }
        Ok(mask)
    }

    /// Active scan: send a Beacon Request on each channel of `channels` (bit
    /// n = channel n, `0` = all supported) and listen for `duration`.
    /// Beacons are reported as [`Event::ActiveScanResult`], the end as
    /// [`Event::ActiveScanDone`].
    pub fn active_scan(&mut self, channels: u32, duration: Duration) -> Result<()> {
        if self.scan_busy() {
            return Err(Error::Busy);
        }
        self.scan = ScanState {
            channels: self.scan_mask(channels)?,
            channel: 0,
            duration,
            energy_pending: false,
        };
        self.pending |= P_ACTIVE_SCAN;
        Ok(())
    }

    /// Energy scan of `channels` for `duration` each, reported as
    /// [`Event::EnergyScanResult`] / [`Event::EnergyScanDone`].
    ///
    /// [`Error::NotImplemented`] if the radio cannot energy-scan: the
    /// [`Radio`](opentrust_platform::Radio) trait has no synchronous RSSI
    /// read for OpenThread's software sampling fallback.
    pub fn energy_scan(&mut self, channels: u32, duration: Duration) -> Result<()> {
        if !self.caps.phy.contains(Capabilities::ENERGY_SCAN) {
            return Err(Error::NotImplemented);
        }
        if self.scan_busy() {
            return Err(Error::Busy);
        }
        self.scan = ScanState {
            channels: self.scan_mask(channels)?,
            channel: 0,
            duration,
            energy_pending: false,
        };
        self.pending |= P_ENERGY_SCAN;
        Ok(())
    }

    /// Apply a [`Request`].
    pub fn submit(&mut self, request: Request, now: Instant) -> Result<()> {
        match request {
            Request::Transmit { handle, frame } => self.transmit(handle, &frame),
            Request::TransmitIndirect { handle, dst, frame } => {
                self.transmit_indirect(handle, dst, &frame)
            }
            Request::PurgeIndirect(dst) => {
                self.purge_indirect(dst);
                Ok(())
            }
            Request::DataPoll => self.send_data_poll(now),
            Request::ActiveScan { channels, duration } => self.active_scan(channels, duration),
            Request::EnergyScan { channels, duration } => self.energy_scan(channels, duration),
        }
    }

    /// Next upward event, if any.
    pub fn poll_event(&mut self) -> Option<Event> {
        self.events.pop_front()
    }

    fn push_event(&mut self, ev: Event) {
        if self.events.push_back(ev).is_err() {
            opentrust_core::warn!("mac: event queue full, event dropped");
        }
    }

    // ------------------------------------------------------------------
    // Radio side
    // ------------------------------------------------------------------

    /// When [`poll_action`](Self::poll_action) must be called again at the
    /// latest (if nothing else happens before).
    pub fn next_deadline(&self) -> Option<Instant> {
        match (self.timers.next_deadline(), self.poll.deadline()) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        }
    }

    /// Is a `Transmit` / `EnergyScan` action awaiting its completion?
    pub fn is_in_flight(&self) -> bool {
        self.in_flight.is_some()
    }

    /// Run expired timers, start pending operations and return the next
    /// radio command, or `None` when the radio has nothing to do until the
    /// next received frame, [`next_deadline`](Self::next_deadline) or
    /// upper-layer request.
    ///
    /// After a [`RadioAction::Transmit`] / [`RadioAction::EnergyScan`] it
    /// returns `None` until [`on_tx_done`](Self::on_tx_done) /
    /// [`on_energy_scan_done`](Self::on_energy_scan_done) was called.
    pub fn poll_action(&mut self, now: Instant) -> Option<RadioAction> {
        if self.in_flight.is_some() {
            return None;
        }
        self.process_timers(now);
        if self.csl_dirty {
            self.csl_reschedule(now);
        }
        self.schedule_operations(now);
        if self.csl_dirty {
            self.csl_reschedule(now); // an operation may have ended
        }

        if let Some((ack, channel)) = self.pending_ack.take() {
            self.in_flight = Some(InFlight::Ack(channel));
            self.counters.tx_attempts += 1;
            self.counters.tx_soft_ack += 1;
            return Some(RadioAction::Transmit(TxAction {
                psdu: Self::with_fcs(&ack),
                info: PsduTxInfo {
                    security_processed: true,
                    header_updated: true,
                    max_csma_backoffs: Some(0),
                    ..PsduTxInfo::default()
                },
                channel,
                power: self.config.tx_power,
                cca_threshold: None,
                wait_ack: false,
                abort_at: None,
            }));
        }
        if self.config_dirty {
            self.config_dirty = false;
            return Some(RadioAction::Configure(self.radio_config()));
        }
        if self.src_match_dirty {
            self.src_match_dirty = false;
            return Some(RadioAction::SetSrcMatch(self.src_match.table().clone()));
        }
        if let Some(a) = self.poll_hw_security() {
            return Some(a);
        }
        if self.csl.radio_dirty {
            self.csl.radio_dirty = false;
            return Some(RadioAction::SetCsl(CslConfig {
                period: u32::from(self.csl.period),
                short_addr: self.csl.peer_short.0,
                ext_addr: ext_to_u64(&self.csl.peer_ext),
                sample_time_us: self.csl.sample_radio,
            }));
        }
        let ready_channel = match &self.tx {
            Some(tx) if tx.state == TxState::Ready => Some(tx.channel),
            _ => None,
        };
        if let Some(ch) = ready_channel {
            // Transmit is only legal from Receive (radio contract C3) unless
            // the radio can go from sleep to transmit.
            let ok = match self.radio_mode {
                RadioMode::Receive(c) => c == ch,
                RadioMode::Sleep => self.caps.phy.contains(Capabilities::SLEEP_TO_TX),
                RadioMode::Unknown => false,
            };
            if !ok {
                self.radio_mode = RadioMode::Receive(ch);
                return Some(RadioAction::Receive { channel: ch });
            }
            return self.begin_transmit(now);
        }
        if self.operation == Operation::EnergyScan && self.scan.energy_pending {
            self.scan.energy_pending = false;
            self.in_flight = Some(InFlight::EnergyScan);
            let ms = self.scan.duration.as_millis().min(u64::from(u16::MAX)) as u16;
            return Some(RadioAction::EnergyScan {
                channel: self.scan.channel,
                duration_ms: ms,
            });
        }
        let desired = self.desired_mode();
        if let Some((channel, start_us, duration_us)) = self.csl.window {
            let stale = self
                .radio_now_us()
                .is_none_or(|n| start_us + u64::from(duration_us) <= n);
            if stale || (self.rx_on_when_idle && desired != RadioMode::Sleep) {
                self.csl.window = None;
            } else if desired == RadioMode::Sleep && self.radio_mode == RadioMode::Sleep {
                // The radio sleeps and wakes up for this window by itself.
                self.csl.window = None;
                return Some(RadioAction::ReceiveAt {
                    channel,
                    start_us,
                    duration_us,
                });
            }
        }
        if desired != self.radio_mode && desired != RadioMode::Unknown {
            self.radio_mode = desired;
            return Some(match desired {
                RadioMode::Receive(channel) => RadioAction::Receive { channel },
                _ => RadioAction::Sleep,
            });
        }
        None
    }

    /// Keys / frame counter for a radio that secures frames or enhanced ACKs
    /// itself. Keys are compared with what was pushed last, so every change
    /// made through [`security_mut`](Self::security_mut) (key sequence
    /// switch, network key change) reaches the radio. A key change resets
    /// the radio's counter (`if_larger = false`, the KeyManager restarts at
    /// 0); otherwise the counter is only ever raised.
    fn poll_hw_security(&mut self) -> Option<RadioAction> {
        if !self.hw_sec.enabled {
            return None;
        }
        let keys = self.security.radio_keys();
        if !self.hw_sec.keys_sent || keys != self.hw_sec.keys {
            self.hw_sec.keys_sent = true;
            self.hw_sec.keys = keys;
            self.hw_sec.counter_due = Some(false);
            self.hw_sec.counter = self.security.current_frame_counter();
            return Some(RadioAction::SetMacKeys(keys));
        }
        let fc = self.security.current_frame_counter();
        if self.hw_sec.counter_due.is_none() && fc > self.hw_sec.counter {
            self.hw_sec.counter_due = Some(true);
            self.hw_sec.counter = fc;
        }
        let if_larger = self.hw_sec.counter_due.take()?;
        Some(RadioAction::SetMacFrameCounter {
            frame_counter: self.hw_sec.counter,
            if_larger,
        })
    }

    /// The radio finished the frame of the last [`RadioAction::Transmit`]
    /// (`TRANSMIT_SEC`: frame counter, key index, CSL IE and possibly the
    /// MIC were assigned in place). Call it with the PSDU and info as the
    /// radio left them, before [`on_tx_done`](Self::on_tx_done). The frame
    /// counter used is fed back to the key manager and the updated frame
    /// replaces the one retransmissions use.
    pub fn on_tx_frame_updated(&mut self, psdu: &[u8], info: &PsduTxInfo) {
        if self.in_flight != Some(InFlight::Frame) || !self.hw_sec.enabled {
            return;
        }
        let Some(n) = psdu.len().checked_sub(FCS_LEN) else {
            return;
        };
        let Some(tx) = self.tx.as_mut() else {
            return;
        };
        let Ok(f) = Frame::parse(&psdu[..n]) else {
            return;
        };
        if let Some(s) = f.security_header() {
            if let (Some(fc), KeyIdentifier::Index(i)) = (s.frame_counter, s.key) {
                self.security.frame_counter_used(fc, i);
                self.hw_sec.counter = self
                    .hw_sec
                    .counter
                    .max(self.security.current_frame_counter());
            }
        }
        if info.header_updated {
            if let Ok(buf) = FrameBuf::from_slice(&psdu[..n]) {
                tx.frame = buf;
            }
            tx.header_updated = true;
            tx.security_processed = info.security_processed;
        }
    }

    fn radio_config(&self) -> Config {
        let mut c = Config::new();
        c.promiscuous = self.promiscuous;
        c.pan_id = Some(if self.operation == Operation::ActiveScan {
            PanId::BROADCAST.0
        } else {
            self.pan_id.0
        });
        c.short_addr = Some(self.short.0);
        c.alt_short_addr = self.alt_short.map(|s| s.0);
        c.ext_addr = Some(ext_to_u64(&self.ext));
        c
    }

    fn desired_mode(&self) -> RadioMode {
        let idle_rx = self.rx_on_when_idle || self.promiscuous;
        if let Some(tx) = &self.tx {
            return match tx.state {
                TxState::Backoff | TxState::RetxDelay if !idle_rx => RadioMode::Sleep,
                _ => RadioMode::Receive(tx.channel),
            };
        }
        match self.operation {
            Operation::ActiveScan => RadioMode::Receive(self.scan.channel),
            Operation::WaitingForData => RadioMode::Receive(self.channel),
            Operation::EnergyScan => self.radio_mode,
            _ if idle_rx => RadioMode::Receive(self.channel),
            _ if self.csl.sampling && !self.caps.hw_csl() => {
                RadioMode::Receive(self.csl_rx_channel())
            }
            _ => RadioMode::Sleep,
        }
    }

    fn with_fcs(frame: &[u8]) -> Psdu {
        let mut p = Psdu::new();
        // Frames are at most MAX_FRAME_LEN long, so this cannot fail.
        let _ = p.extend_from_slice(frame);
        let _ = p.extend_from_slice(&fcs(frame));
        p
    }

    fn begin_transmit(&mut self, now: Instant) -> Option<RadioAction> {
        if !self.refresh_soft_csl(now) {
            return None;
        }
        let hw_timing = self.caps.phy.contains(Capabilities::TRANSMIT_TIMING);
        let soft_csma = self.needs.contains(SoftMacNeeds::CSMA);
        let hw_tx_ack = self.caps.hw_tx_ack();
        let abortable = hw_tx_ack && !self.caps.hw_ack_timeout() && !self.caps.hw_retransmit();
        // A radio that secures the frame itself finds the key by the index in
        // the frame: queued frames were built before a key sequence switch,
        // so the index is brought up to date for every attempt (OpenThread
        // `SubMac::ProcessTransmitSecurity` does the same).
        let radio_key_index = self.hw_sec.keys.map(|k| k.key_id);
        let tx = self.tx.as_mut()?;
        tx.state = TxState::InFlight;
        self.in_flight = Some(InFlight::Frame);
        self.counters.tx_attempts += 1;
        if let Some(index) = radio_key_index {
            if !tx.security_processed {
                let _ = FrameMut::new(&mut tx.frame).and_then(|mut m| m.set_key_index(index));
            }
        }
        let csma = tx.max_csma_backoffs > 0 || tx.tx_at_us.is_some();
        let psdu = Self::with_fcs(&tx.frame);
        let wait_ack = tx.ack_request && hw_tx_ack;
        let abort_at = (wait_ack && abortable).then(|| {
            let mut t = now + air_time(psdu.len()) + self.config.ack_timeout;
            if !soft_csma {
                t += max_csma_duration(tx.max_csma_backoffs);
            }
            t
        });
        Some(RadioAction::Transmit(TxAction {
            info: PsduTxInfo {
                security_processed: tx.security_processed,
                header_updated: tx.header_updated
                    || tx.security_processed
                    || tx.retries > 0
                    || tx.retransmission,
                csl_present: tx.csl_ie && self.csl.enabled(),
                retransmission: tx.retries > 0 || tx.retransmission,
                tx_at_us: if hw_timing { tx.tx_at_us } else { None },
                // With software CSMA the backoff is done: a single CCA.
                max_csma_backoffs: Some(if soft_csma || tx.tx_at_us.is_some() {
                    0
                } else {
                    tx.max_csma_backoffs
                }),
            },
            psdu,
            channel: tx.channel,
            power: self.config.tx_power,
            cca_threshold: csma.then_some(self.config.cca_threshold),
            wait_ack,
            abort_at,
        }))
    }

    /// Complete a [`RadioAction::Transmit`].
    pub fn on_tx_done(&mut self, outcome: TxOutcome<'_>, now: Instant) {
        match self.in_flight {
            Some(InFlight::Ack(ch)) => {
                self.in_flight = None;
                self.radio_mode = RadioMode::Receive(ch);
                return;
            }
            Some(InFlight::Frame) => self.in_flight = None,
            // A late completion after an abort (contract C5) or a mismatch.
            _ => {
                opentrust_core::warn!("mac: unexpected tx completion ignored");
                return;
            }
        }
        let soft_match = self.needs.contains(SoftMacNeeds::MATCH_ACK);
        let Some(tx) = self.tx.as_mut() else {
            return;
        };
        // The radio is back in receive on the transmit channel (C4).
        self.radio_mode = RadioMode::Receive(tx.channel);
        let result = match outcome {
            TxOutcome::Sent => {
                if tx.ack_request && soft_match {
                    tx.state = TxState::WaitAck;
                    let _ = self
                        .timers
                        .start(TimerId::SubMac, now + self.config.ack_timeout);
                    return;
                }
                Ok(false)
            }
            TxOutcome::Acked { ack, info } => {
                let dst = tx.dst;
                match ack
                    .len()
                    .checked_sub(FCS_LEN)
                    .and_then(|n| FrameBuf::from_slice(&ack[..n]).ok())
                {
                    Some(mut buf) => match self.check_ack(&mut buf, dst, &info, now) {
                        Some(fp) => Ok(fp),
                        None => Err(TxError::NoAck),
                    },
                    None => Err(TxError::NoAck),
                }
            }
            TxOutcome::Failed(kind) => Err(map_radio_error(kind)),
            TxOutcome::AckTimeout => Err(TxError::NoAck),
            TxOutcome::Aborted => Err(TxError::Abort),
        };
        self.attempt_done(result, now);
    }

    /// The driver lost the completion of the in-flight `Transmit` /
    /// `EnergyScan` (its future was dropped, which aborts it): treat it as
    /// aborted.
    pub fn abort_in_flight(&mut self, now: Instant) {
        match self.in_flight {
            Some(InFlight::Ack(_) | InFlight::Frame) => self.on_tx_done(TxOutcome::Aborted, now),
            Some(InFlight::EnergyScan) => self.on_energy_scan_done(RSSI_INVALID, now),
            None => {}
        }
    }

    /// Validate an ACK (unsecuring an enhanced ACK); its Frame Pending bit.
    fn check_ack(
        &mut self,
        buf: &mut FrameBuf,
        peer: Address,
        info: &PsduRxInfo,
        now: Instant,
    ) -> Option<bool> {
        let (fp, secured) = {
            let f = Frame::parse(buf).ok()?;
            if !f.is_ack() {
                return None;
            }
            (f.frame_pending(), f.security_enabled())
        };
        if secured {
            let ext = self.neighbors.resolve(peer)?;
            if self.security.unsecure_rx(buf, &ext).is_err() {
                self.counters.rx_err_sec += 1;
                return None;
            }
        }
        if self.tx.as_ref().is_some_and(|tx| tx.csl_ie) {
            // Our frame carried a CSL IE and was acknowledged: the parent is
            // synchronized to us as of now (OpenThread
            // `UpdateCslLastSyncTimestamp`).
            self.csl.last_sync = self.radio_now_us().map(|n| n as u32);
        }
        if let Ok(f) = Frame::parse(buf) {
            self.csl_update_child(&f, peer, info.timestamp_us, now);
            self.process_enh_ack_probing(&f, peer);
        }
        Some(fp)
    }

    /// Complete a [`RadioAction::EnergyScan`] with the maximum RSSI
    /// ([`RSSI_INVALID`] if the scan failed).
    pub fn on_energy_scan_done(&mut self, max_rssi: i8, _now: Instant) {
        if self.in_flight != Some(InFlight::EnergyScan) {
            return;
        }
        self.in_flight = None;
        self.radio_mode = RadioMode::Unknown;
        if max_rssi != RSSI_INVALID {
            self.push_event(Event::EnergyScanResult {
                channel: self.scan.channel,
                max_rssi,
            });
        }
        self.perform_energy_scan();
    }

    // ------------------------------------------------------------------
    // Timers and operation scheduling
    // ------------------------------------------------------------------

    fn process_timers(&mut self, now: Instant) {
        while let Some(id) = self.timers.poll_expired(now) {
            match id {
                TimerId::SubMac => self.sub_mac_timer(now),
                TimerId::Operation => self.operation_timer(now),
                TimerId::CslRx => self.csl_timer(),
                TimerId::CslTx => self.pending |= P_CSL_TX,
            }
        }
        if self.poll.take_expired(now) {
            let _ = self.send_data_poll(now);
        }
    }

    fn sub_mac_timer(&mut self, now: Instant) {
        let Some(tx) = self.tx.as_mut() else {
            return;
        };
        match tx.state {
            TxState::Backoff => tx.state = TxState::Ready,
            TxState::RetxDelay => self.start_csma_backoff(now),
            TxState::WaitAck => self.attempt_done(Err(TxError::NoAck), now),
            TxState::Ready | TxState::InFlight => {}
        }
    }

    fn operation_timer(&mut self, now: Instant) {
        match self.operation {
            Operation::ActiveScan if self.tx.is_none() => self.perform_active_scan(now),
            Operation::WaitingForData => {
                self.operation = Operation::Idle;
                self.push_event(Event::DataPollTimeout);
                if self.poll.handle_timeout() {
                    let _ = self.send_data_poll(now);
                }
            }
            _ => {}
        }
    }

    fn schedule_operations(&mut self, now: Instant) {
        // Starting an operation may finish it right away (nothing to send),
        // so try a few times.
        for _ in 0..8 {
            if self.operation != Operation::Idle {
                return;
            }
            let p = self.pending;
            let next = if p & P_WAIT_DATA != 0 {
                Operation::WaitingForData
            } else if p & P_ACTIVE_SCAN != 0 {
                Operation::ActiveScan
            } else if p & P_ENERGY_SCAN != 0 {
                Operation::EnergyScan
            } else if p & P_BEACON != 0 {
                Operation::TransmitBeacon
            } else if p & P_CSL_TX != 0 {
                Operation::TransmitDataCsl
            } else if !self.poll_requests.is_empty() {
                Operation::TransmitDataIndirect
            } else if p & P_POLL != 0 && (self.direct.is_empty() || self.tx_poll_before_data) {
                Operation::TransmitPoll
            } else if !self.direct.is_empty() {
                if p & P_POLL != 0 {
                    self.tx_poll_before_data = true;
                }
                Operation::TransmitDataDirect
            } else {
                return;
            };
            self.pending &= !match next {
                Operation::WaitingForData => P_WAIT_DATA,
                Operation::ActiveScan => P_ACTIVE_SCAN,
                Operation::EnergyScan => P_ENERGY_SCAN,
                Operation::TransmitBeacon => P_BEACON,
                Operation::TransmitPoll => P_POLL,
                Operation::TransmitDataCsl => P_CSL_TX,
                _ => 0,
            };
            if next == Operation::TransmitPoll {
                self.tx_poll_before_data = false;
            }
            self.timers.stop(TimerId::Operation);
            self.operation = next;
            self.start_operation(next, now);
        }
    }

    fn start_operation(&mut self, op: Operation, now: Instant) {
        match op {
            Operation::Idle => {}
            Operation::WaitingForData => {
                let _ = self
                    .timers
                    .start(TimerId::Operation, now + self.config.data_poll_timeout);
            }
            Operation::ActiveScan => {
                // Accept beacons from any PAN while scanning.
                self.config_dirty = true;
                self.perform_active_scan(now);
            }
            Operation::EnergyScan => self.perform_energy_scan(),
            Operation::TransmitBeacon => match self.build_beacon() {
                Ok(frame) => {
                    self.start_frame(TxKind::Beacon, frame, self.channel, false, true, now)
                }
                Err(_) => self.operation = Operation::Idle,
            },
            Operation::TransmitDataIndirect => self.start_indirect(now),
            Operation::TransmitDataCsl => self.start_csl_tx(now),
            Operation::TransmitPoll => self.start_poll(now),
            Operation::TransmitDataDirect => self.start_direct(now),
        }
    }

    fn finish_operation(&mut self) {
        self.operation = Operation::Idle;
    }

    fn perform_active_scan(&mut self, now: Instant) {
        match next_channel(&mut self.scan.channels) {
            None => {
                self.finish_operation();
                self.config_dirty = true; // restore the PAN ID filter
                self.push_event(Event::ActiveScanDone);
            }
            Some(ch) => {
                self.scan.channel = ch;
                match self.build_beacon_request() {
                    Ok(frame) => {
                        self.start_frame(TxKind::BeaconRequest, frame, ch, false, true, now)
                    }
                    Err(_) => {
                        let _ = self
                            .timers
                            .start(TimerId::Operation, now + self.scan.duration);
                    }
                }
            }
        }
    }

    fn perform_energy_scan(&mut self) {
        match next_channel(&mut self.scan.channels) {
            None => {
                self.finish_operation();
                self.push_event(Event::EnergyScanDone);
            }
            Some(ch) => {
                self.scan.channel = ch;
                self.scan.energy_pending = true;
            }
        }
    }

    // ------------------------------------------------------------------
    // Frame preparation
    // ------------------------------------------------------------------

    fn next_dsn(&mut self) -> u8 {
        let s = self.dsn;
        self.dsn = self.dsn.wrapping_add(1);
        s
    }

    /// Assign the sequence number (if present and `assign_seq`) and secure
    /// the frame unless the radio does it. Returns whether security is
    /// processed (or not needed).
    fn prepare_frame(
        &mut self,
        frame: &mut FrameBuf,
        assign_seq: bool,
    ) -> core::result::Result<bool, TxError> {
        let (has_seq, secured, key_mode1) = {
            let f = Frame::parse(frame).map_err(|_| TxError::Abort)?;
            (
                f.sequence().is_some(),
                f.security_enabled(),
                f.security_header()
                    .is_some_and(|s| s.key_id_mode() == KeyIdMode::Index),
            )
        };
        if has_seq && assign_seq {
            let seq = self.next_dsn();
            FrameMut::new(frame)
                .and_then(|mut m| m.set_sequence(seq))
                .map_err(|_| TxError::Abort)?;
        }
        if !secured {
            return Ok(true);
        }
        // A radio that secures frames itself knows the key ID mode 1 keys
        // only; frames with another key ID mode (mode 2: MLE messages before
        // a link exists) are secured here, as OpenThread's `Mac` does.
        if self.caps.hw_tx_security() && key_mode1 {
            return Ok(false);
        }
        if self.csl.enabled() && Self::has_csl_ie(frame) {
            // CSL IE: phase and frame counter are set per attempt
            // (`refresh_soft_csl`).
            return Ok(true);
        }
        self.security
            .secure_tx(frame, &self.ext)
            .map_err(|_| TxError::Security)?;
        Ok(true)
    }

    fn has_csl_ie(frame: &[u8]) -> bool {
        Frame::parse(frame).is_ok_and(|f| f.csl_ie().is_some())
    }

    fn start_frame(
        &mut self,
        kind: TxKind,
        frame: FrameBuf,
        channel: u8,
        indirect: bool,
        security_processed: bool,
        now: Instant,
    ) {
        let (ack_request, seq, dst) = match Frame::parse(&frame) {
            Ok(f) => (f.ack_request(), f.sequence(), f.dst_address()),
            Err(_) => (false, None, Address::None),
        };
        let (max_csma_backoffs, max_frame_retries) = if indirect {
            (
                self.config.max_csma_backoffs_indirect,
                self.config.max_frame_retries_indirect,
            )
        } else {
            (
                self.config.max_csma_backoffs_direct,
                self.config.max_frame_retries_direct,
            )
        };
        let timed = self.next_tx_timed.take();
        let csl_ie = self.csl.enabled() && Self::has_csl_ie(&frame);
        let secured = Frame::parse(&frame).is_ok_and(|f| f.security_enabled());
        let csl_plain = (csl_ie && secured && !self.caps.hw_tx_security()).then(|| frame.clone());
        // A poll with a CSL IE is not retransmitted: the next poll carries a
        // fresh phase (OpenThread `DataPollSender::PrepareDataRequest`).
        let max_frame_retries = if csl_ie && matches!(kind, TxKind::Poll) {
            0
        } else {
            max_frame_retries
        };
        let max_csma_backoffs = if timed.is_some() {
            0
        } else {
            max_csma_backoffs
        };
        self.tx = Some(TxOp {
            csl_ie,
            csl_plain,
            csl_tx: timed.is_some(),
            tx_at_us: timed,
            kind,
            frame,
            channel,
            dst,
            ack_request,
            seq,
            security_processed,
            retransmission: false,
            header_updated: false,
            max_csma_backoffs,
            max_frame_retries,
            csma_backoffs: 0,
            retries: 0,
            retx_be: RETX_INIT_BACKOFF_EXPONENT,
            state: TxState::Backoff,
        });
        self.start_csma_backoff(now);
    }

    fn start_csma_backoff(&mut self, now: Instant) {
        let soft = self.needs.contains(SoftMacNeeds::CSMA);
        let hw_timing = self.caps.phy.contains(Capabilities::TRANSMIT_TIMING);
        let radio_now = self.radio_now_us();
        let Some(tx) = self.tx.as_mut() else {
            return;
        };
        if let Some(at) = tx.tx_at_us {
            // Timed (CSL) frame: no random backoff, a single CCA. A radio
            // without timed transmit gets it in time by the MAC
            // (OpenThread `SubMac::StartCsmaBackoff`, kStateCslTransmit).
            let ahead = u64::from(CCA_SAMPLE_INTERVAL + CSL_TRANSMIT_TIME_AHEAD + SHR_DURATION);
            let wait = match radio_now {
                Some(n) if !hw_timing => at.saturating_sub(ahead).saturating_sub(n),
                _ => 0,
            };
            if wait == 0 {
                tx.state = TxState::Ready;
            } else {
                tx.state = TxState::Backoff;
                let _ = self
                    .timers
                    .start(TimerId::SubMac, now + Duration::from_micros(wait));
            }
            return;
        }
        if tx.max_csma_backoffs > 0 && soft {
            let be = csma_backoff_exponent(tx.csma_backoffs);
            let d = random_backoff(&mut self.rng, be);
            if d.is_zero() {
                tx.state = TxState::Ready;
            } else {
                tx.state = TxState::Backoff;
                let _ = self.timers.start(TimerId::SubMac, now + d);
            }
        } else {
            tx.state = TxState::Ready;
        }
    }

    fn start_direct(&mut self, now: Instant) {
        let Some((handle, mut frame, channel)) = self.direct.pop_front() else {
            self.finish_operation();
            return;
        };
        match self.prepare_frame(&mut frame, true) {
            Ok(processed) => self.start_frame(
                TxKind::Direct(handle),
                frame,
                channel.unwrap_or(self.channel),
                false,
                processed,
                now,
            ),
            Err(e) => {
                self.finish_operation();
                self.push_event(Event::TxDone {
                    handle,
                    result: Err(e),
                });
            }
        }
    }

    fn start_poll(&mut self, now: Instant) {
        let res = self
            .build_data_request()
            .map_err(|_| TxError::Abort)
            .and_then(|mut f| self.prepare_frame(&mut f, true).map(|p| (f, p)));
        match res {
            Ok((frame, processed)) => {
                self.start_frame(TxKind::Poll, frame, self.channel, false, processed, now)
            }
            Err(e) => {
                self.finish_operation();
                let r = Err(e);
                self.poll.handle_sent(&r, false, now);
                self.push_event(Event::DataPollSent(r));
            }
        }
    }

    fn start_indirect(&mut self, now: Instant) {
        let Some(src) = self.poll_requests.pop_front() else {
            self.finish_operation();
            return;
        };
        let Some(i) = self.indirect.find_for(src, &self.neighbors) else {
            // Polled with Frame Pending but nothing queued (src-match
            // overflow or a pinned entry): answer with an empty frame so the
            // child can go back to sleep (OpenThread `PrepareEmptyFrame`).
            // Secured when the device has keys, as OT does; without keys
            // (no network key yet) the frame goes out unsecured.
            let prepared = [true, false].into_iter().find_map(|secured| {
                let mut frame = self.build_empty_frame(src, secured).ok()?;
                let p = self.prepare_frame(&mut frame, true).ok()?;
                Some((frame, p))
            });
            match prepared {
                Some((frame, p)) => {
                    self.start_frame(TxKind::Indirect(None), frame, self.channel, true, p, now);
                }
                None => self.finish_operation(),
            }
            return;
        };
        if !self.prepare_indirect_frame(i) {
            return;
        }
        let f = &self.indirect.frames[i];
        let (handle, frame, processed, retx) = (
            f.handle,
            f.frame.clone(),
            f.security_processed,
            f.attempts > 0,
        );
        self.start_frame(
            TxKind::Indirect(Some(handle)),
            frame,
            self.channel,
            true,
            processed,
            now,
        );
        if let Some(tx) = self.tx.as_mut() {
            tx.retransmission = retx;
        }
    }

    /// Sequence number, Frame Pending and security of the queued frame `i`
    /// before its first attempt. `false` if that failed: the frame was
    /// dropped and reported, the operation finished.
    fn prepare_indirect_frame(&mut self, i: usize) -> bool {
        if !self.indirect.frames[i].prepared {
            // A caller that fragments a message sets Frame Pending itself
            // (more fragments follow); it is kept.
            let preset = Frame::parse(&self.indirect.frames[i].frame)
                .map(|f| f.frame_pending())
                .unwrap_or(false);
            let more = preset
                || self
                    .indirect
                    .count_for(self.indirect.frames[i].dst, &self.neighbors)
                    > 1;
            let mut frame = self.indirect.frames[i].frame.clone();
            // Frame Pending tells the child to poll again; it is covered by
            // the MIC, so it is fixed now for all attempts.
            let fp_ok = FrameMut::new(&mut frame)
                .and_then(|mut m| m.set_frame_pending(more))
                .is_ok();
            let res = if fp_ok {
                self.prepare_frame(&mut frame, true)
            } else {
                Err(TxError::Abort)
            };
            match res {
                Ok(processed) => {
                    let f = &mut self.indirect.frames[i];
                    f.frame = frame;
                    f.prepared = true;
                    f.security_processed = processed;
                }
                Err(e) => {
                    let f = self.indirect.remove(i);
                    self.update_src_match();
                    self.finish_operation();
                    self.push_event(Event::TxDone {
                        handle: f.handle,
                        result: Err(e),
                    });
                    return false;
                }
            }
        }
        true
    }

    fn own_src_for(&self, dst: Address) -> Address {
        match dst {
            Address::Short(_) if self.short != ShortAddress::INVALID => Address::Short(self.short),
            _ => Address::Extended(self.ext),
        }
    }

    fn build_data_request(&self) -> Result<FrameBuf> {
        opentrust_core::trace!("mac: data request");
        let parent = self.poll.parent;
        if parent.is_none() || parent.is_broadcast() {
            return Err(Error::InvalidState);
        }
        let mut buf = [0u8; MAX_FRAME_LEN];
        // A CSL receiver puts its CSL IE into the poll (a 2015 frame), which
        // resynchronizes the parent (OpenThread `DataPollSender` CSL rules).
        let csl = self.csl.enabled();
        let mut b = FrameBuilder::new(&mut buf)
            .frame_type(FrameType::MacCmd)
            .version(if csl {
                FrameVersion::V2015
            } else {
                FrameVersion::V2006
            })
            .pan_id(self.pan_id)
            .dst(parent)
            .src(self.own_src_for(parent))
            .ack_request(true)
            .command(MacCommand::DataRequest);
        if csl {
            b = b.header_ie(CslIe {
                phase: 0,
                period: self.csl.period,
                rendezvous_time: None,
            });
        }
        if self.poll.secure {
            b = b.security(SecurityHeader::new(
                SecurityLevel::EncMic32,
                0,
                KeyIdentifier::Index(0),
            ));
        }
        let n = b.build()?;
        FrameBuf::from_slice(&buf[..n]).map_err(|_| Error::NoBufs)
    }

    fn build_empty_frame(&self, dst: Address, secured: bool) -> Result<FrameBuf> {
        let mut buf = [0u8; MAX_FRAME_LEN];
        let mut b = FrameBuilder::new(&mut buf)
            .frame_type(FrameType::Data)
            .version(FrameVersion::V2006)
            .pan_id(self.pan_id)
            .dst(dst)
            .src(self.own_src_for(dst))
            .ack_request(true);
        // Secured like OT `PrepareEmptyFrame`: a sleepy child counts the
        // frame as a sign of life of its parent (supervision listener).
        if secured {
            b = b.security(SecurityHeader::new(
                SecurityLevel::EncMic32,
                0,
                KeyIdentifier::Index(0),
            ));
        }
        let n = b.build()?;
        FrameBuf::from_slice(&buf[..n]).map_err(|_| Error::NoBufs)
    }

    fn build_beacon_request(&self) -> Result<FrameBuf> {
        let mut buf = [0u8; MAX_FRAME_LEN];
        let n = FrameBuilder::new(&mut buf)
            .frame_type(FrameType::MacCmd)
            .version(FrameVersion::V2003)
            .sequence(0)
            .dst_pan(PanId::BROADCAST)
            .dst(Address::Short(ShortAddress::BROADCAST))
            .command(MacCommand::BeaconRequest)
            .build()?;
        FrameBuf::from_slice(&buf[..n]).map_err(|_| Error::NoBufs)
    }

    fn build_beacon(&mut self) -> Result<FrameBuf> {
        if !self.beacon_enabled {
            return Err(Error::InvalidState);
        }
        let mut pl = [0u8; 4 + ThreadBeaconPayload::LEN];
        let n = {
            let mut w = Writer::new(&mut pl);
            Beacon::write_thread_header(&mut w)?;
            if let Some(payload) = self.beacon {
                payload.write(&mut w)?;
            }
            w.len()
        };
        let mut buf = [0u8; MAX_FRAME_LEN];
        let len = FrameBuilder::new(&mut buf)
            .frame_type(FrameType::Beacon)
            .version(FrameVersion::V2003)
            .sequence(self.bsn)
            .src_pan(self.pan_id)
            .src(Address::Extended(self.ext))
            .payload(&pl[..n])
            .build()?;
        self.bsn = self.bsn.wrapping_add(1);
        FrameBuf::from_slice(&buf[..len]).map_err(|_| Error::NoBufs)
    }

    // ------------------------------------------------------------------
    // Transmission completion
    // ------------------------------------------------------------------

    /// One transmit attempt ended (`Ok(frame_pending)` or an error): CSMA
    /// retry, retransmission or completion (OpenThread
    /// `SubMac::HandleTransmitDone`).
    fn attempt_done(&mut self, result: core::result::Result<bool, TxError>, now: Instant) {
        let needs = self.needs;
        let Some(tx) = self.tx.as_mut() else {
            return;
        };
        let cca_fail = result == Err(TxError::ChannelAccessFailure);
        if cca_fail {
            self.counters.tx_err_cca += 1;
        }
        opentrust_core::trace!(
            "mac: tx attempt {} ({} bytes, ack {}) done: ok {} cca_fail {} csl_ie {}",
            tx.retries,
            tx.frame.len(),
            tx.ack_request,
            result.is_ok(),
            cca_fail,
            tx.csl_ie
        );
        // A retransmission of a frame with a CSL IE (the parent did not
        // acknowledge the first attempt, so its idea of our phase may be
        // wrong): a data poll with the CSL IE resynchronizes it (OpenThread
        // `DataPollSender::ProcessTxDone`, `mIsARetx`).
        let resync = tx.csl_ie && tx.retries > 0 && matches!(tx.kind, TxKind::Direct(_));
        let next = if cca_fail
            && needs.contains(SoftMacNeeds::CSMA)
            && tx.csma_backoffs < tx.max_csma_backoffs
        {
            tx.csma_backoffs += 1;
            AttemptNext::Csma
        } else {
            tx.csma_backoffs = 0;
            let retx = matches!(result, Err(TxError::NoAck | TxError::ChannelAccessFailure))
                && needs.contains(SoftMacNeeds::RETRANSMIT)
                && tx.retries < tx.max_frame_retries;
            if !retx {
                AttemptNext::Done
            } else {
                tx.retries += 1;
                self.counters.tx_retry += 1;
                if result == Err(TxError::NoAck) {
                    // Thread §3.2.x: random delay before retransmitting
                    // after NO_ACK, exponent BENA growing per failure.
                    let be = tx.retx_be;
                    tx.retx_be = (be + 1).min(RETX_MAX_BACKOFF_EXPONENT);
                    tx.state = TxState::RetxDelay;
                    AttemptNext::RetxDelay(random_backoff(&mut self.rng, be))
                } else {
                    AttemptNext::Csma
                }
            }
        };
        match next {
            AttemptNext::Csma => self.start_csma_backoff(now),
            AttemptNext::RetxDelay(d) if d.is_zero() => self.start_csma_backoff(now),
            AttemptNext::RetxDelay(d) => {
                let _ = self.timers.start(TimerId::SubMac, now + d);
            }
            AttemptNext::Done => {
                if let Some(tx) = self.tx.take() {
                    let res = result.map(|frame_pending| TxSuccess {
                        frame_pending,
                        retries: tx.retries,
                    });
                    self.tx_complete(tx, res, now);
                }
            }
        }
        if resync && self.poll.enabled {
            let _ = self.send_data_poll(now);
        }
    }

    fn tx_complete(&mut self, tx: TxOp, res: TxResult, now: Instant) {
        let c = &mut self.counters;
        c.tx_total += 1;
        if tx.ack_request {
            c.tx_ack_requested += 1;
            if res.is_ok() {
                c.tx_acked += 1;
            }
        }
        if res == Err(TxError::Abort) {
            c.tx_err_abort += 1;
        }
        match tx.kind {
            TxKind::BeaconRequest => {
                c.tx_beacon_request += 1;
                if self.operation == Operation::ActiveScan {
                    let _ = self
                        .timers
                        .start(TimerId::Operation, now + self.scan.duration);
                }
            }
            TxKind::Beacon => {
                c.tx_beacon += 1;
                self.finish_operation();
            }
            TxKind::Poll => {
                c.tx_data_poll += 1;
                if matches!(res, Ok(s) if s.frame_pending) {
                    self.pending |= P_WAIT_DATA;
                }
                self.finish_operation();
                self.poll.handle_sent(&res, tx.csl_ie, now);
                self.push_event(Event::DataPollSent(res));
            }
            TxKind::Direct(handle) => {
                c.tx_data += 1;
                if tx.csl_ie && res.is_ok() && tx.ack_request {
                    // A secure frame with a CSL IE acknowledged by the parent
                    // resynchronizes it: it replaces the next keep-alive
                    // poll (OpenThread `Mac::ResetKeepAliveTimer`).
                    self.poll.reset_keep_alive(now);
                } else if let (Ok(s), true) = (&res, tx.ack_request) {
                    // Thread 1.2 enhanced keep-alive: a secured data frame
                    // that the parent acknowledged does the poll's job.
                    if tx.frame.first().is_some_and(|b| b & 0x08 != 0) {
                        self.poll.handle_acked_data(s.frame_pending, now);
                    }
                }
                if res.is_err() {
                    c.tx_direct_max_retry_expiry += 1;
                }
                self.finish_operation();
                self.push_event(Event::TxDone {
                    handle,
                    result: res,
                });
                // A sleepy child's ACK with Frame Pending: fetch the data
                // (OpenThread `DataPollSender::ProcessTxDone`).
                if self.poll.enabled && matches!(res, Ok(s) if s.frame_pending) {
                    let _ = self.send_data_poll(now);
                }
            }
            TxKind::Indirect(handle) => {
                c.tx_data += 1;
                self.finish_operation();
                let Some(handle) = handle else {
                    return;
                };
                self.csl_dirty = true;
                let Some(i) = self.indirect.position(handle) else {
                    return; // purged meanwhile
                };
                if tx.csl_tx {
                    self.csl_tx_done(i, handle, tx, res);
                    return;
                }
                let done = match res {
                    Ok(_) => true,
                    Err(_) => {
                        let f = &mut self.indirect.frames[i];
                        f.attempts += 1;
                        let exhausted = f.attempts >= self.config.max_tx_attempts_indirect_polls;
                        if exhausted {
                            self.counters.tx_indirect_max_retry_expiry += 1;
                        }
                        exhausted
                    }
                };
                if done {
                    self.indirect.remove(i);
                    self.update_src_match();
                    self.push_event(Event::TxDone {
                        handle,
                        result: res,
                    });
                }
            }
        }
    }

    // ------------------------------------------------------------------
    // Reception
    // ------------------------------------------------------------------

    fn filter_params(&self) -> FilterParams {
        FilterParams {
            pan_id: self.pan_id,
            short: self.short,
            alt_short: self.alt_short,
            ext: self.ext,
            rx_on_when_idle: self.rx_on_when_idle,
        }
    }

    /// Frame Pending for the ACK of a frame (OpenThread simulation radio
    /// `radioSendAck`: data frames, data requests and 2015 commands, from a
    /// source in the source-match table).
    fn ack_frame_pending(&self, m: &RxMeta) -> bool {
        let eligible = (m.version == FrameVersion::V2015 && m.ftype == FrameType::MacCmd)
            || m.ftype == FrameType::Data
            || m.is_data_request;
        eligible && self.src_match.frame_pending(m.src, &self.neighbors)
    }

    fn queue_soft_ack(&mut self, buf: &FrameBuf, frame_pending: bool, info: &PsduRxInfo) {
        let channel = info.channel;
        let mut out = [0u8; MAX_FRAME_LEN];
        let len = {
            let Ok(f) = Frame::parse(buf) else {
                return;
            };
            let csl_ie = self.csl_ack_ie(&f, info, buf.len() + FCS_LEN);
            let mut probe = [0u8; ENH_ACK_PROBING_MAX_DATA];
            let probe_len = self.enh_ack_probe_data(&f, info, &mut probe);
            let r = if f.version() == FrameVersion::V2015 {
                FrameBuilder::enh_ack(&mut out, &f, frame_pending)
                    .map(|b| match csl_ie {
                        Some(ie) => b.header_ie(ie),
                        None => b,
                    })
                    .map(|b| match probe_len {
                        0 => b,
                        n => b.header_ie(VendorIe::thread_enh_ack_probing(&probe[..n])),
                    })
                    .and_then(FrameBuilder::build)
            } else {
                FrameBuilder::imm_ack_for(&mut out, &f, frame_pending)
            };
            match r {
                Ok(n) => n,
                Err(_) => return,
            }
        };
        let Ok(mut ack) = FrameBuf::from_slice(&out[..len]) else {
            return;
        };
        let secured = Frame::parse(&ack).is_ok_and(|f| f.security_enabled());
        if secured {
            let r = match self.security.secure_enh_ack(&mut ack, &self.ext) {
                Err(Error::InvalidArgs) => {
                    self.security.secure_tx(&mut ack, &self.ext).map(|()| None)
                }
                r => r,
            };
            if r.is_err() {
                return;
            }
        }
        if secured && self.csl.enabled() && Self::has_csl_ie(&ack) {
            // Acked with a secured enhanced ACK carrying our CSL IE.
            self.csl.last_sync = info
                .timestamp_us
                .or_else(|| self.radio_now_us())
                .map(|t| t as u32);
        }
        self.pending_ack = Some((ack, channel));
    }

    /// The CSL IE for the enhanced ACK of `rx`, if it comes from our CSL
    /// parent: the phase to our next sample at the time the ACK's SFD is on
    /// the air (frame end + turnaround + SHR).
    fn csl_ack_ie(&self, rx: &Frame<'_>, info: &PsduRxInfo, psdu_len: usize) -> Option<CslIe> {
        if !self.csl.enabled() || rx.version() != FrameVersion::V2015 {
            return None;
        }
        if !self.csl.is_peer(rx.src_address()) {
            return None;
        }
        let sfd = match info.timestamp_us {
            Some(ts) => (ts as u32)
                .wrapping_add((psdu_len as u32 + 1) * 32)
                .wrapping_add(TURNAROUND_TIME + SHR_DURATION),
            None => (self.radio_now_us()? as u32).wrapping_add(TURNAROUND_TIME + SHR_DURATION),
        };
        Some(CslIe {
            phase: csl_phase(self.csl.sample_radio, sfd, self.csl.period),
            period: self.csl.period,
            rendezvous_time: None,
        })
    }

    /// A frame from [`Radio::receive`](opentrust_platform::Radio::receive):
    /// `psdu` is the PSDU **including** the FCS (`info.len` octets).
    pub fn on_rx(&mut self, psdu: &[u8], info: &PsduRxInfo, now: Instant) {
        self.counters.rx_total += 1;
        opentrust_core::trace!(
            "mac: rx {} bytes, ts {:?}, enh-ack sec {}",
            psdu.len(),
            info.timestamp_us,
            info.ack_security.is_some()
        );
        if self.csl.enabled() && info.ack_security.is_some() {
            // Acked with a secured enhanced ACK by the radio.
            self.csl.last_sync = info
                .timestamp_us
                .or_else(|| self.radio_now_us())
                .map(|t| t as u32);
        }
        if let Some(a) = &info.ack_security {
            self.security.ack_frame_counter_used(a);
            self.hw_sec.counter = self
                .hw_sec
                .counter
                .max(self.security.current_frame_counter());
        }
        let buf = psdu
            .len()
            .checked_sub(FCS_LEN)
            .filter(|n| *n > 0)
            .and_then(|n| FrameBuf::from_slice(&psdu[..n]).ok());
        let Some(mut buf) = buf else {
            self.counters.rx_err_no_frame += 1;
            return;
        };
        let meta = match Frame::parse(&buf) {
            Ok(f) => RxMeta::of(&f),
            Err(_) => {
                self.counters.rx_err_no_frame += 1;
                return;
            }
        };
        if meta.ftype == FrameType::Ack {
            self.handle_ack(&mut buf, &meta, info, now);
            return;
        }
        if self.promiscuous {
            self.push_rx(buf, info, None, false, true);
            return;
        }

        let params = self.filter_params();
        let unicast = {
            let Ok(f) = Frame::parse(&buf) else {
                return;
            };
            if let Err(e) = params.check(&f) {
                match e {
                    FilterError::DstAddress | FilterError::DstPan => {
                        self.counters.rx_dest_addr_filtered += 1
                    }
                    FilterError::SrcIsSelf => self.counters.rx_err_invalid_src_addr += 1,
                }
                return;
            }
            params.is_unicast_to_us(&f)
        };

        // ACK first: it is time critical and does not depend on security
        // (a hardware ACK is sent before the MIC is checked, too).
        let acked_fp = if meta.ack_request && unicast {
            if self.needs.contains(SoftMacNeeds::SEND_ACK) {
                let fp = self.ack_frame_pending(&meta);
                self.queue_soft_ack(&buf, fp, info);
                fp
            } else {
                info.acked_with_frame_pending
                    .unwrap_or_else(|| self.ack_frame_pending(&meta))
            }
        } else {
            false
        };

        let security: Option<RxSecurityInfo> = if meta.security {
            let Some(src_ext) = self.neighbors.resolve(meta.src) else {
                self.counters.rx_err_unknown_neighbor += 1;
                return;
            };
            match self.security.unsecure_rx(&mut buf, &src_ext) {
                Ok(s) => s,
                Err(_) => {
                    self.counters.rx_err_sec += 1;
                    return;
                }
            }
        } else {
            None
        };

        match self.operation {
            Operation::ActiveScan => {
                if meta.ftype == FrameType::Beacon {
                    self.report_beacon(&buf, info);
                    return;
                }
                if self.scan.channel != self.channel {
                    self.counters.rx_other += 1;
                    return;
                }
            }
            Operation::EnergyScan if self.scan.channel != self.channel => {
                self.counters.rx_other += 1;
                return;
            }
            Operation::WaitingForData if !meta.dst.is_none() => {
                self.timers.stop(TimerId::Operation);
                self.finish_operation();
            }
            _ => {}
        }

        if self.poll.handle_rx(meta.frame_pending) {
            let _ = self.send_data_poll(now);
        }

        if let Ok(f) = Frame::parse(&buf) {
            self.csl_update_child(&f, meta.src, info.timestamp_us, now);
        }

        match meta.ftype {
            FrameType::MacCmd => {
                let cmd = Frame::parse(&buf).ok().and_then(|f| f.command());
                match cmd {
                    Some(MacCommand::BeaconRequest) => {
                        self.counters.rx_beacon_request += 1;
                        if self.beacon_enabled {
                            self.pending |= P_BEACON;
                        }
                    }
                    Some(MacCommand::DataRequest) => {
                        self.counters.rx_data_poll += 1;
                        let csl = Frame::parse(&buf).ok().and_then(|f| {
                            (f.version() == FrameVersion::V2015 && f.security_enabled())
                                .then(|| f.csl_ie())
                                .flatten()
                                .map(|ie| (ie, info.timestamp_us))
                        });
                        self.push_event(Event::DataPollReceived {
                            src: meta.src,
                            frame_pending: acked_fp,
                            csl,
                        });
                        if acked_fp && !self.poll_requests.iter().any(|a| *a == meta.src) {
                            let _ = self.poll_requests.push_back(meta.src);
                        }
                    }
                    _ => self.counters.rx_other += 1,
                }
            }
            FrameType::Data => {
                self.counters.rx_data += 1;
                self.push_rx(buf, info, security, acked_fp, false);
            }
            FrameType::Beacon => self.counters.rx_beacon += 1,
            _ => self.counters.rx_other += 1,
        }
    }

    fn handle_ack(&mut self, buf: &mut FrameBuf, meta: &RxMeta, info: &PsduRxInfo, now: Instant) {
        let peer = match &self.tx {
            Some(tx) if tx.state == TxState::WaitAck && tx.seq.is_some() && tx.seq == meta.seq => {
                tx.dst
            }
            _ => {
                self.counters.rx_ack_unmatched += 1;
                return;
            }
        };
        let Some(fp) = self.check_ack(buf, peer, info, now) else {
            return; // keep waiting for a valid ACK
        };
        self.timers.stop(TimerId::SubMac);
        self.attempt_done(Ok(fp), now);
    }

    fn report_beacon(&mut self, buf: &FrameBuf, info: &PsduRxInfo) {
        let Ok(f) = Frame::parse(buf) else {
            return;
        };
        let Address::Extended(ext_addr) = f.src_address() else {
            self.counters.rx_other += 1;
            return;
        };
        self.counters.rx_beacon += 1;
        let result = ScanResult {
            channel: info.channel,
            rssi: info.rssi,
            lqi: info.lqi,
            ext_addr,
            pan_id: f.pan_id().unwrap_or(PanId::BROADCAST),
            thread: Beacon::parse(f.payload())
                .ok()
                .and_then(|b| ThreadBeaconPayload::parse(b.payload).ok()),
        };
        self.push_event(Event::ActiveScanResult(result));
    }

    fn push_rx(
        &mut self,
        frame: FrameBuf,
        info: &PsduRxInfo,
        security: Option<RxSecurityInfo>,
        acked_with_frame_pending: bool,
        promiscuous: bool,
    ) {
        // Keep one slot for completions (TxDone etc.), which must not be lost.
        if self.events.len() + 1 >= self.events.capacity() {
            self.counters.rx_err_queue_full += 1;
            return;
        }
        self.push_event(Event::Received(RxFrame {
            frame,
            channel: info.channel,
            rssi: info.rssi,
            lqi: info.lqi,
            timestamp_us: info.timestamp_us,
            security,
            acked_with_frame_pending,
            promiscuous,
        }));
    }
}
