//! Energy Scan, PAN ID Query and Announce Begin (Thread 1.4.1 section
//! 8.7, OT `thread/energy_scan_server.cpp`, `panid_query_server.cpp`,
//! `announce_begin_server.cpp`, `announce_sender.cpp`, and the
//! `meshcop/*_client.cpp` request builders).
//!
//! # Servers
//!
//! Each server is a sans-IO state machine fed by its TMF request handler
//! (`/c/es`, `/c/pq`, `/c/ab`) and by the results of the MAC scan:
//!
//! - [`EnergyScanServer`]: after a 1 s delay it asks for one energy scan per
//!   channel ([`EnergyAction::Scan`]), `count` rounds with `period` between
//!   them; deliver each result with [`EnergyScanServer::scan_result`] (`Some`
//!   RSSI, then `None` when the channel is done). The report goes to the
//!   requester as `/c/er` ([`send_energy_report`]).
//! - [`PanIdQueryServer`]: after 1 s an active scan of the channel mask
//!   ([`PanIdAction::ActiveScan`]); [`PanIdQueryServer::scan_result`]
//!   collects the channels where the queried PAN ID was heard and tells to
//!   send `/c/pc` ([`send_pan_id_conflict`]).
//! - [`AnnounceBeginServer`]: sends MLE Announces
//!   ([`Mle::send_announce`](opentrust_mle::Mle::send_announce)) on the
//!   channels of the mask, `count` times, `period` ms apart.
//!
//! # Clients
//!
//! [`send_energy_scan_query`], [`send_pan_id_query`] and
//! [`send_announce_begin`] build and send the requests of a commissioner
//! (the caller supplies the Commissioner Session ID);
//! [`parse_energy_report`] and [`parse_pan_id_conflict`] decode the
//! answers (`/c/er`, `/c/pc`).

use core::net::Ipv6Addr;

use heapless::Vec;
use opentrust_coap::endpoint::Request;
use opentrust_coap::message::{Code, Type};
use opentrust_coap::tmf::{Agent, Responder, UdpSink};
use opentrust_coap::uri::Uri;
use opentrust_core::Result;
use opentrust_core::bytes::Writer;
use opentrust_core::message::Priority;
use opentrust_core::time::{Duration, Instant};
use opentrust_core::types::{Prefix64, Rloc16};
use rand_core::Rng;

use crate::tlv::{CHANNEL_MAX, CHANNEL_MIN, PAGE0_CHANNELS, Tlvs, WriterExt};

/// Delay before the first scan of an Energy Scan / PAN ID Query request
/// (`kScanDelay`).
pub const SCAN_DELAY: Duration = Duration::from_millis(1000);
/// Delay before the Energy Scan report is sent (`kReportDelay`).
pub const REPORT_DELAY: Duration = Duration::from_millis(500);
/// Most energy values an Energy List TLV holds.
pub const MAX_ENERGY_RESULTS: usize = 255;

fn is_post(req: &Request<'_>) -> bool {
    req.msg.code() == Code::POST
}

/// OT `SendEmptyAck` for a confirmable, non-multicast request.
fn ack_if_confirmable(req: &Request<'_>, rsp: &mut dyn Responder) {
    if req.msg.ty() == Type::Con && !req.ctx.dst.is_multicast() {
        let _ = rsp.respond(Code::CHANGED, &[]);
    }
}

fn lowest_bit(mask: u32) -> u32 {
    mask & mask.wrapping_neg()
}

// ---------------------------------------------------------------- energy scan

/// What the Energy Scan server wants done.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnergyAction {
    /// Run an energy scan on `channel` for `duration_ms` and report the
    /// result with [`EnergyScanServer::scan_result`].
    Scan {
        /// Channel.
        channel: u8,
        /// Scan duration in milliseconds per channel.
        duration_ms: u16,
    },
    /// Send the report ([`EnergyScanServer::report`], [`send_energy_report`]).
    Report,
}

/// The Energy Scan server (OT `EnergyScanServer`).
#[derive(Debug, Clone)]
pub struct EnergyScanServer {
    active: bool,
    requester: Ipv6Addr,
    mask: u32,
    mask_current: u32,
    count: u8,
    period: u16,
    duration: u16,
    results: Vec<i8, MAX_ENERGY_RESULTS>,
    deadline: Option<Instant>,
}

impl Default for EnergyScanServer {
    fn default() -> Self {
        Self::new()
    }
}

impl EnergyScanServer {
    /// Idle server.
    pub const fn new() -> Self {
        Self {
            active: false,
            requester: Ipv6Addr::UNSPECIFIED,
            mask: 0,
            mask_current: 0,
            count: 0,
            period: 0,
            duration: 0,
            results: Vec::new(),
            deadline: None,
        }
    }

    /// A request is being served.
    pub fn is_active(&self) -> bool {
        self.active
    }

    /// `/c/es` (OT `HandleTmf<kUriEnergyScan>`): a POST with Count, Period,
    /// Scan Duration and Channel Mask TLVs starts (or restarts) a scan; a
    /// confirmable unicast request is acknowledged.
    pub fn handle_request(&mut self, now: Instant, req: &Request<'_>, rsp: &mut dyn Responder) {
        if !is_post(req) {
            return;
        }
        let t = Tlvs(req.msg.payload());
        let (Ok(count), Ok(period), Ok(duration), Ok(mask)) =
            (t.count(), t.period(), t.scan_duration(), t.channel_mask())
        else {
            return;
        };
        self.start(now, req.ctx.peer.addr, mask, count, period, duration);
        ack_if_confirmable(req, rsp);
    }

    /// Start (or restart) a scan for `requester`: `count` rounds over the
    /// channels of `mask`, `period` ms apart, `duration` ms per channel.
    pub fn start(
        &mut self,
        now: Instant,
        requester: Ipv6Addr,
        mask: u32,
        count: u8,
        period: u16,
        duration: u16,
    ) {
        self.active = true;
        self.results.clear();
        self.mask = mask;
        self.mask_current = mask;
        self.count = count;
        self.period = period;
        self.duration = duration;
        self.requester = requester;
        self.deadline = Some(now.saturating_add(SCAN_DELAY));
    }

    /// Timer expiry: the next action, if due.
    pub fn poll(&mut self, now: Instant) -> Option<EnergyAction> {
        if !self.active || self.deadline.is_none_or(|d| d > now) {
            return None;
        }
        self.deadline = None;
        if self.count > 0 {
            let bit = lowest_bit(self.mask_current);
            if bit == 0 {
                self.count = 0;
                return Some(EnergyAction::Report);
            }
            Some(EnergyAction::Scan {
                channel: bit.trailing_zeros() as u8,
                duration_ms: self.duration,
            })
        } else {
            Some(EnergyAction::Report)
        }
    }

    /// When [`poll`](Self::poll) next has work.
    pub fn next_deadline(&self) -> Option<Instant> {
        self.deadline
    }

    /// Result of the scan requested by [`EnergyAction::Scan`] (OT
    /// `HandleScanResult`): `Some(max_rssi)` for the channel, `None` when the
    /// scan of the channel is complete.
    pub fn scan_result(&mut self, now: Instant, rssi: Option<i8>) {
        if !self.active {
            return;
        }
        match rssi {
            Some(r) => {
                if self.results.push(r).is_err() {
                    // Does not fit the Energy List: drop the request.
                    self.cancel();
                    return;
                }
                if self.results.len() == MAX_ENERGY_RESULTS {
                    // Report what we have.
                    self.count = 0;
                    self.deadline = Some(now.saturating_add(REPORT_DELAY));
                }
            }
            None => {
                self.mask_current &= self.mask_current.wrapping_sub(1);
                if self.mask_current == 0 {
                    self.mask_current = self.mask;
                    self.count = self.count.saturating_sub(1);
                }
                self.deadline = Some(now.saturating_add(if self.count > 0 {
                    Duration::from_millis(u64::from(self.period))
                } else {
                    REPORT_DELAY
                }));
            }
        }
    }

    /// The report payload (Channel Mask and Energy List TLVs) and the
    /// requester to send it to. Ends the request.
    pub fn report(&mut self, out: &mut [u8]) -> Result<(Ipv6Addr, usize)> {
        let mut w = Writer::new(out);
        w.channel_mask(self.mask)?;
        w.energy_list_bytes(&self.results)?;
        let n = w.written().len();
        let dst = self.requester;
        self.cancel();
        Ok((dst, n))
    }

    /// Drop the request (OT: Network Data lost the Border Agent).
    pub fn cancel(&mut self) {
        self.active = false;
        self.deadline = None;
        self.results.clear();
    }
}

trait EnergyListExt {
    fn energy_list_bytes(&mut self, v: &[i8]) -> Result<()>;
}

impl EnergyListExt for Writer<'_> {
    fn energy_list_bytes(&mut self, v: &[i8]) -> Result<()> {
        let mut b = [0u8; MAX_ENERGY_RESULTS];
        for (d, s) in b.iter_mut().zip(v) {
            *d = *s as u8;
        }
        self.energy_list(&b[..v.len()])
    }
}

// ---------------------------------------------------------------- PAN ID query

/// What the PAN ID Query server wants done.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PanIdAction {
    /// Active scan of these channels (bit `n` = channel `n`); deliver the
    /// beacons / the end with [`PanIdQueryServer::scan_result`].
    ActiveScan {
        /// Channel mask.
        channel_mask: u32,
    },
}

/// The PAN ID Query server (OT `PanIdQueryServer`).
#[derive(Debug, Clone)]
pub struct PanIdQueryServer {
    requester: Ipv6Addr,
    pan_id: u16,
    scan_mask: u32,
    conflict_mask: u32,
    deadline: Option<Instant>,
}

impl Default for PanIdQueryServer {
    fn default() -> Self {
        Self::new()
    }
}

impl PanIdQueryServer {
    /// Idle server.
    pub const fn new() -> Self {
        Self {
            requester: Ipv6Addr::UNSPECIFIED,
            pan_id: 0,
            scan_mask: 0,
            conflict_mask: 0,
            deadline: None,
        }
    }

    /// `/c/pq`: Channel Mask and PAN ID TLVs.
    pub fn handle_request(&mut self, now: Instant, req: &Request<'_>, rsp: &mut dyn Responder) {
        if !is_post(req) {
            return;
        }
        let t = Tlvs(req.msg.payload());
        let (Ok(mask), Ok(pan_id)) = (t.channel_mask(), t.pan_id()) else {
            return;
        };
        self.start(now, req.ctx.peer.addr, pan_id, mask);
        ack_if_confirmable(req, rsp);
    }

    /// Start a query for `pan_id` on the channels of `mask`.
    pub fn start(&mut self, now: Instant, requester: Ipv6Addr, pan_id: u16, mask: u32) {
        self.scan_mask = mask;
        self.pan_id = pan_id;
        self.requester = requester;
        self.deadline = Some(now.saturating_add(SCAN_DELAY));
    }

    /// Timer expiry: start the scan.
    pub fn poll(&mut self, now: Instant) -> Option<PanIdAction> {
        if self.deadline.is_none_or(|d| d > now) {
            return None;
        }
        self.deadline = None;
        self.conflict_mask = 0;
        Some(PanIdAction::ActiveScan {
            channel_mask: self.scan_mask,
        })
    }

    /// When [`poll`](Self::poll) next has work.
    pub fn next_deadline(&self) -> Option<Instant> {
        self.deadline
    }

    /// A beacon `(pan_id, channel)` of the scan, or `None` at the end of
    /// the scan. Returns `true` when a conflict report should be sent
    /// ([`conflict`](Self::conflict)).
    pub fn scan_result(&mut self, beacon: Option<(u16, u8)>) -> bool {
        match beacon {
            Some((pan_id, channel)) => {
                if pan_id == self.pan_id && (CHANNEL_MIN..=CHANNEL_MAX).contains(&channel) {
                    self.conflict_mask |= 1 << channel;
                }
                false
            }
            None => self.conflict_mask != 0,
        }
    }

    /// The `/c/pc` payload (Channel Mask and PAN ID) and the requester.
    pub fn conflict(&self, out: &mut [u8]) -> Result<(Ipv6Addr, usize)> {
        let mut w = Writer::new(out);
        w.channel_mask(self.conflict_mask)?;
        w.pan_id(self.pan_id)?;
        Ok((self.requester, w.written().len()))
    }
}

// ---------------------------------------------------------------- announce begin

/// Default number of Announce rounds / period (`kDefaultCount`,
/// `kDefaultPeriod`) of the Announce sender.
pub const DEFAULT_ANNOUNCE_COUNT: u8 = 3;
/// See [`DEFAULT_ANNOUNCE_COUNT`].
pub const DEFAULT_ANNOUNCE_PERIOD_MS: u16 = 1000;

/// The Announce Begin server / Announce sender base (OT
/// `AnnounceBeginServer`, `AnnounceSenderBase`; jitter is 0 as in the
/// server).
#[derive(Debug, Clone)]
pub struct AnnounceBeginServer {
    mask: u32,
    period: u16,
    count: u8,
    channel: u8,
    starting: u8,
    deadline: Option<Instant>,
}

impl Default for AnnounceBeginServer {
    fn default() -> Self {
        Self::new()
    }
}

impl AnnounceBeginServer {
    /// Idle sender.
    pub const fn new() -> Self {
        Self {
            mask: 0,
            period: 0,
            count: 0,
            channel: 0,
            starting: 0,
            deadline: None,
        }
    }

    /// A sequence is running.
    pub fn is_running(&self) -> bool {
        self.deadline.is_some()
    }

    /// `/c/ab`: Channel Mask, Count and Period TLVs.
    pub fn handle_request(&mut self, now: Instant, req: &Request<'_>, rsp: &mut dyn Responder) {
        if !is_post(req) {
            return;
        }
        let t = Tlvs(req.msg.payload());
        let (Ok(mask), Ok(count), Ok(period)) = (t.channel_mask(), t.count(), t.period()) else {
            return;
        };
        self.start(now, mask, count, period);
        ack_if_confirmable(req, rsp);
    }

    /// OT `SendAnnounce(mask, count, period)`: if a sequence runs, `count`
    /// more rounds are added; otherwise one starts with the lowest channel
    /// of `mask & supported`.
    pub fn start(&mut self, now: Instant, mask: u32, count: u8, period: u16) {
        if self.is_running() {
            self.count = self.count.saturating_add(count);
            return;
        }
        let mask = mask & PAGE0_CHANNELS;
        if period == 0 || mask == 0 {
            return;
        }
        self.mask = mask;
        self.period = period;
        self.starting = lowest_bit(mask).trailing_zeros() as u8;
        self.channel = self.starting;
        self.count = count;
        self.deadline = Some(now);
    }

    /// Stop the sequence.
    pub fn stop(&mut self) {
        self.deadline = None;
        self.count = 0;
    }

    /// Timer expiry: the channel to announce on, if due (OT
    /// `HandleTimer`).
    pub fn poll(&mut self, now: Instant) -> Option<u8> {
        if self.deadline.is_none_or(|d| d > now) {
            return None;
        }
        let announce = self.channel;
        // Next channel of the mask, wrapping around.
        let mut next = (self.channel + 1..=CHANNEL_MAX).find(|&c| self.mask & (1 << c) != 0);
        if next.is_none() {
            next = (CHANNEL_MIN..=CHANNEL_MAX).find(|&c| self.mask & (1 << c) != 0);
        }
        self.channel = next.unwrap_or(self.starting);
        if self.channel == self.starting && self.count != 0 {
            self.count -= 1;
            if self.count == 0 {
                self.deadline = None;
                return Some(announce);
            }
        }
        self.deadline = Some(now.saturating_add(Duration::from_millis(u64::from(self.period))));
        Some(announce)
    }

    /// When [`poll`](Self::poll) next has work.
    pub fn next_deadline(&self) -> Option<Instant> {
        self.deadline
    }
}

// ---------------------------------------------------------------- reports (server -> requester)

#[allow(clippy::too_many_arguments)]
fn post_rloc<
    R: Rng + ?Sized,
    S: UdpSink + ?Sized,
    const A: usize,
    const B: usize,
    const C: usize,
    const D: usize,
>(
    agent: &mut Agent<A, B, C, D>,
    now: Instant,
    rng: &mut R,
    sink: &mut S,
    mlp: &Prefix64,
    own_rloc16: Rloc16,
    dst: Ipv6Addr,
    uri: Uri,
    payload: &[u8],
    user: u32,
) -> Result<()> {
    agent.post(
        now,
        rng,
        sink,
        dst,
        Some(mlp.rloc(own_rloc16)),
        Priority::Net,
        uri,
        payload,
        Some(user),
    )
}

/// `user` of an Energy Report.
pub const USER_ENERGY_REPORT: u32 = 0x0e53_0001;
/// `user` of a PAN ID Conflict report.
pub const USER_PAN_ID_CONFLICT: u32 = 0x0e53_0002;
/// `user` of an Energy Scan query.
pub const USER_ENERGY_SCAN: u32 = 0x0e53_0003;
/// `user` of a PAN ID Query.
pub const USER_PAN_ID_QUERY: u32 = 0x0e53_0004;
/// `user` of an Announce Begin request.
pub const USER_ANNOUNCE_BEGIN: u32 = 0x0e53_0005;

/// Send `/c/er` with `payload` (from [`EnergyScanServer::report`]) to
/// `dst`.
#[allow(clippy::too_many_arguments)]
pub fn send_energy_report<
    R: Rng + ?Sized,
    S: UdpSink + ?Sized,
    const A: usize,
    const B: usize,
    const C: usize,
    const D: usize,
>(
    agent: &mut Agent<A, B, C, D>,
    now: Instant,
    rng: &mut R,
    sink: &mut S,
    mlp: &Prefix64,
    own_rloc16: Rloc16,
    dst: Ipv6Addr,
    payload: &[u8],
) -> Result<()> {
    post_rloc(
        agent,
        now,
        rng,
        sink,
        mlp,
        own_rloc16,
        dst,
        Uri::EnergyReport,
        payload,
        USER_ENERGY_REPORT,
    )
}

/// Send `/c/pc` with `payload` (from [`PanIdQueryServer::conflict`]) to
/// `dst`.
#[allow(clippy::too_many_arguments)]
pub fn send_pan_id_conflict<
    R: Rng + ?Sized,
    S: UdpSink + ?Sized,
    const A: usize,
    const B: usize,
    const C: usize,
    const D: usize,
>(
    agent: &mut Agent<A, B, C, D>,
    now: Instant,
    rng: &mut R,
    sink: &mut S,
    mlp: &Prefix64,
    own_rloc16: Rloc16,
    dst: Ipv6Addr,
    payload: &[u8],
) -> Result<()> {
    post_rloc(
        agent,
        now,
        rng,
        sink,
        mlp,
        own_rloc16,
        dst,
        Uri::PanIdConflict,
        payload,
        USER_PAN_ID_CONFLICT,
    )
}

// ---------------------------------------------------------------- clients (commissioner -> devices)

/// Send an Energy Scan query (OT `EnergyScanClient::SendQuery`) to `dst`
/// (a device RLOC / ALOC or the realm-local multicast address).
#[allow(clippy::too_many_arguments)]
pub fn send_energy_scan_query<
    R: Rng + ?Sized,
    S: UdpSink + ?Sized,
    const A: usize,
    const B: usize,
    const C: usize,
    const D: usize,
>(
    agent: &mut Agent<A, B, C, D>,
    now: Instant,
    rng: &mut R,
    sink: &mut S,
    mlp: &Prefix64,
    own_rloc16: Rloc16,
    dst: Ipv6Addr,
    session_id: u16,
    channel_mask: u32,
    count: u8,
    period: u16,
    scan_duration: u16,
) -> Result<()> {
    let mut b = [0u8; 48];
    let mut w = Writer::new(&mut b);
    w.commissioner_session_id(session_id)?;
    w.channel_mask(channel_mask)?;
    w.count(count)?;
    w.period(period)?;
    w.scan_duration(scan_duration)?;
    post_rloc(
        agent,
        now,
        rng,
        sink,
        mlp,
        own_rloc16,
        dst,
        Uri::EnergyScan,
        w.written(),
        USER_ENERGY_SCAN,
    )
}

/// Send a PAN ID Query (OT `PanIdQueryClient::SendQuery`).
#[allow(clippy::too_many_arguments)]
pub fn send_pan_id_query<
    R: Rng + ?Sized,
    S: UdpSink + ?Sized,
    const A: usize,
    const B: usize,
    const C: usize,
    const D: usize,
>(
    agent: &mut Agent<A, B, C, D>,
    now: Instant,
    rng: &mut R,
    sink: &mut S,
    mlp: &Prefix64,
    own_rloc16: Rloc16,
    dst: Ipv6Addr,
    session_id: u16,
    pan_id: u16,
    channel_mask: u32,
) -> Result<()> {
    let mut b = [0u8; 32];
    let mut w = Writer::new(&mut b);
    w.commissioner_session_id(session_id)?;
    w.channel_mask(channel_mask)?;
    w.pan_id(pan_id)?;
    post_rloc(
        agent,
        now,
        rng,
        sink,
        mlp,
        own_rloc16,
        dst,
        Uri::PanIdQuery,
        w.written(),
        USER_PAN_ID_QUERY,
    )
}

/// Send an Announce Begin request (OT `AnnounceBeginClient::SendRequest`).
#[allow(clippy::too_many_arguments)]
pub fn send_announce_begin<
    R: Rng + ?Sized,
    S: UdpSink + ?Sized,
    const A: usize,
    const B: usize,
    const C: usize,
    const D: usize,
>(
    agent: &mut Agent<A, B, C, D>,
    now: Instant,
    rng: &mut R,
    sink: &mut S,
    mlp: &Prefix64,
    own_rloc16: Rloc16,
    dst: Ipv6Addr,
    session_id: u16,
    channel_mask: u32,
    count: u8,
    period: u16,
) -> Result<()> {
    let mut b = [0u8; 40];
    let mut w = Writer::new(&mut b);
    w.commissioner_session_id(session_id)?;
    w.channel_mask(channel_mask)?;
    w.count(count)?;
    w.period(period)?;
    post_rloc(
        agent,
        now,
        rng,
        sink,
        mlp,
        own_rloc16,
        dst,
        Uri::AnnounceBegin,
        w.written(),
        USER_ANNOUNCE_BEGIN,
    )
}

/// A decoded `/c/er` Energy Report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnergyReport<'a> {
    /// The channel mask that was scanned.
    pub channel_mask: u32,
    /// One RSSI byte (dBm, signed) per scanned channel and round.
    pub energy_list: &'a [u8],
}

/// Handle `/c/er` at the commissioner (OT `HandleTmf<kUriEnergyReport>`):
/// a confirmable POST with Channel Mask and Energy List TLVs is
/// acknowledged and returned.
pub fn parse_energy_report<'a>(
    req: &Request<'a>,
    rsp: &mut dyn Responder,
) -> Option<EnergyReport<'a>> {
    if !(is_post(req) && req.msg.ty() == Type::Con) {
        return None;
    }
    let t = Tlvs(req.msg.payload());
    let channel_mask = t.channel_mask().ok()?;
    let energy_list = t.energy_list().ok()?;
    let _ = rsp.respond(Code::CHANGED, &[]);
    Some(EnergyReport {
        channel_mask,
        energy_list,
    })
}

/// A decoded `/c/pc` PAN ID Conflict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PanIdConflict {
    /// The channels on which the PAN ID was heard.
    pub channel_mask: u32,
    /// The conflicting PAN ID.
    pub pan_id: u16,
}

/// Handle `/c/pc` at the commissioner (OT `PanIdQueryClient`).
pub fn parse_pan_id_conflict(req: &Request<'_>, rsp: &mut dyn Responder) -> Option<PanIdConflict> {
    if !(is_post(req) && req.msg.ty() == Type::Con) {
        return None;
    }
    let t = Tlvs(req.msg.payload());
    let channel_mask = t.channel_mask().ok()?;
    let pan_id = t.pan_id().ok()?;
    let _ = rsp.respond(Code::CHANGED, &[]);
    Some(PanIdConflict {
        channel_mask,
        pan_id,
    })
}

/// Convert an energy list byte to dBm.
pub const fn energy_dbm(b: u8) -> i8 {
    b as i8
}
