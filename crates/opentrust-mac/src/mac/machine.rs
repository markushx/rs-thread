//! The sans-IO MAC state machine. See the [module docs](super) for the
//! interface contract.

use heapless::Deque;
use opentrust_core::bytes::Writer;
use opentrust_core::crypto::SecurityLevel;
use opentrust_core::time::{Duration, Instant};
use opentrust_core::timer::TimerQueue;
use opentrust_core::types::{Channel, ExtAddress, PanId, ShortAddress};
use opentrust_core::{Error, Result};
use opentrust_platform::radio::MacKeys;
use opentrust_platform::radio::{
    Capabilities, Config, MacCapabilities, PsduRxInfo, PsduTxInfo, RSSI_INVALID, RadioCaps,
    RadioErrorKind, SoftMacNeeds, SrcMatchConfig,
};
use rand_core::Rng;

use super::consts::*;
use super::fcs::fcs;
use super::filter::{FilterError, FilterParams};
use super::indirect::{IndirectQueue, NeighborMap, SrcMatch, ext_to_u64};
use super::poll::PollSender;
use super::sub_mac::{
    TxKind, TxOp, TxState, air_time, csma_backoff_exponent, max_csma_duration, random_backoff,
};
use super::types::*;
use crate::frame::{
    Address, Beacon, FCS_LEN, Frame, FrameBuilder, FrameMut, FrameType, FrameVersion,
    KeyIdentifier, MacCommand, SecurityHeader, ThreadBeaconPayload,
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
    promiscuous: bool,
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
    direct: Deque<(TxHandle, FrameBuf), TXQ>,
    indirect: IndirectQueue<IND>,
    poll_requests: Deque<Address, POLLQ>,
    src_match: SrcMatch,
    neighbors: NeighborMap<NBQ>,
    scan: ScanState,
    poll: PollSender,
    timers: TimerQueue<TimerId, 2>,
    events: Deque<Event, EVQ>,
    counters: MacCounters,
    hw_sec: HwSecurity,
}

impl<
    S,
    G,
    const TXQ: usize,
    const IND: usize,
    const EVQ: usize,
    const POLLQ: usize,
    const NBQ: usize,
> core::fmt::Debug for Mac<S, G, TXQ, IND, EVQ, POLLQ, NBQ>
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
> Mac<S, G, TXQ, IND, EVQ, POLLQ, NBQ>
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
            promiscuous: false,
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

    /// Promiscuous mode: every frame is delivered unfiltered and
    /// unprocessed (no ACKs, no security), flagged [`RxFrame::promiscuous`].
    pub fn set_promiscuous(&mut self, on: bool) {
        if self.promiscuous != on {
            self.promiscuous = on;
            self.config_dirty = true;
        }
    }

    /// Answer Beacon Requests with a beacon carrying `payload` (`None`:
    /// ignore Beacon Requests). OpenThread sends beacons when joinable or
    /// router-capable; MLE/MeshCoP decide and set the payload.
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
        let buf = Self::validate_frame(frame)?;
        self.direct
            .push_back((handle, buf))
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

    /// Secure data polls (default `true`, as Thread requires).
    pub fn set_poll_security(&mut self, on: bool) {
        self.poll.secure = on;
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
        if !self.poll.enabled || self.rx_on_when_idle {
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
        self.schedule_operations(now);

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
        let soft_csma = self.needs.contains(SoftMacNeeds::CSMA);
        let hw_tx_ack = self.caps.hw_tx_ack();
        let abortable = hw_tx_ack && !self.caps.hw_ack_timeout() && !self.caps.hw_retransmit();
        let tx = self.tx.as_mut()?;
        tx.state = TxState::InFlight;
        self.in_flight = Some(InFlight::Frame);
        self.counters.tx_attempts += 1;
        let csma = tx.max_csma_backoffs > 0;
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
                csl_present: false,
                retransmission: tx.retries > 0 || tx.retransmission,
                tx_at_us: None,
                // With software CSMA the backoff is done: a single CCA.
                max_csma_backoffs: Some(if soft_csma { 0 } else { tx.max_csma_backoffs }),
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
            TxOutcome::Acked { ack, .. } => {
                let dst = tx.dst;
                match ack
                    .len()
                    .checked_sub(FCS_LEN)
                    .and_then(|n| FrameBuf::from_slice(&ack[..n]).ok())
                {
                    Some(mut buf) => match self.check_ack(&mut buf, dst) {
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
    fn check_ack(&mut self, buf: &mut FrameBuf, peer: Address) -> Option<bool> {
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
        let (has_seq, secured) = {
            let f = Frame::parse(frame).map_err(|_| TxError::Abort)?;
            (f.sequence().is_some(), f.security_enabled())
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
        if self.caps.hw_tx_security() {
            return Ok(false);
        }
        self.security
            .secure_tx(frame, &self.ext)
            .map_err(|_| TxError::Security)?;
        Ok(true)
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
        self.tx = Some(TxOp {
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
        let Some(tx) = self.tx.as_mut() else {
            return;
        };
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
        let Some((handle, mut frame)) = self.direct.pop_front() else {
            self.finish_operation();
            return;
        };
        match self.prepare_frame(&mut frame, true) {
            Ok(processed) => self.start_frame(
                TxKind::Direct(handle),
                frame,
                self.channel,
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
                self.poll.handle_sent(&r, now);
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
            match self.build_empty_frame(src) {
                Ok(mut frame) => match self.prepare_frame(&mut frame, true) {
                    Ok(p) => {
                        self.start_frame(TxKind::Indirect(None), frame, self.channel, true, p, now)
                    }
                    Err(_) => self.finish_operation(),
                },
                Err(_) => self.finish_operation(),
            }
            return;
        };
        if !self.indirect.frames[i].prepared {
            let more = self
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
                    return;
                }
            }
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

    fn own_src_for(&self, dst: Address) -> Address {
        match dst {
            Address::Short(_) if self.short != ShortAddress::INVALID => Address::Short(self.short),
            _ => Address::Extended(self.ext),
        }
    }

    fn build_data_request(&self) -> Result<FrameBuf> {
        let parent = self.poll.parent;
        if parent.is_none() || parent.is_broadcast() {
            return Err(Error::InvalidState);
        }
        let mut buf = [0u8; MAX_FRAME_LEN];
        let mut b = FrameBuilder::new(&mut buf)
            .frame_type(FrameType::MacCmd)
            .version(FrameVersion::V2006)
            .pan_id(self.pan_id)
            .dst(parent)
            .src(self.own_src_for(parent))
            .ack_request(true)
            .command(MacCommand::DataRequest);
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

    fn build_empty_frame(&self, dst: Address) -> Result<FrameBuf> {
        let mut buf = [0u8; MAX_FRAME_LEN];
        let n = FrameBuilder::new(&mut buf)
            .frame_type(FrameType::Data)
            .version(FrameVersion::V2006)
            .pan_id(self.pan_id)
            .dst(dst)
            .src(self.own_src_for(dst))
            .ack_request(true)
            .build()?;
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
        let payload = self.beacon.ok_or(Error::InvalidState)?;
        let mut pl = [0u8; 4 + ThreadBeaconPayload::LEN];
        let n = {
            let mut w = Writer::new(&mut pl);
            Beacon::write_thread_header(&mut w)?;
            payload.write(&mut w)?;
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
                self.poll.handle_sent(&res, now);
                self.push_event(Event::DataPollSent(res));
            }
            TxKind::Direct(handle) => {
                c.tx_data += 1;
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
                let Some(i) = self.indirect.position(handle) else {
                    return; // purged meanwhile
                };
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

    fn queue_soft_ack(&mut self, buf: &FrameBuf, frame_pending: bool, channel: u8) {
        let mut out = [0u8; MAX_FRAME_LEN];
        let len = {
            let Ok(f) = Frame::parse(buf) else {
                return;
            };
            let r = if f.version() == FrameVersion::V2015 {
                FrameBuilder::enh_ack(&mut out, &f, frame_pending).and_then(FrameBuilder::build)
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
        self.pending_ack = Some((ack, channel));
    }

    /// A frame from [`Radio::receive`](opentrust_platform::Radio::receive):
    /// `psdu` is the PSDU **including** the FCS (`info.len` octets).
    pub fn on_rx(&mut self, psdu: &[u8], info: &PsduRxInfo, now: Instant) {
        self.counters.rx_total += 1;
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
            self.handle_ack(&mut buf, &meta, now);
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
                self.queue_soft_ack(&buf, fp, info.channel);
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

        match meta.ftype {
            FrameType::MacCmd => {
                let cmd = Frame::parse(&buf).ok().and_then(|f| f.command());
                match cmd {
                    Some(MacCommand::BeaconRequest) => {
                        self.counters.rx_beacon_request += 1;
                        if self.beacon.is_some() {
                            self.pending |= P_BEACON;
                        }
                    }
                    Some(MacCommand::DataRequest) => {
                        self.counters.rx_data_poll += 1;
                        self.push_event(Event::DataPollReceived {
                            src: meta.src,
                            frame_pending: acked_fp,
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

    fn handle_ack(&mut self, buf: &mut FrameBuf, meta: &RxMeta, now: Instant) {
        let peer = match &self.tx {
            Some(tx) if tx.state == TxState::WaitAck && tx.seq.is_some() && tx.seq == meta.seq => {
                tx.dst
            }
            _ => {
                self.counters.rx_ack_unmatched += 1;
                return;
            }
        };
        let Some(fp) = self.check_ack(buf, peer) else {
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
