//! Child-side attach (Thread 1.4.1 §4.5.1, §4.7.1; OpenThread `Mle::Attach`,
//! `HandleAttachTimer`, `SendParentRequest`, `HandleParentResponse`,
//! `IsBetterParent`, `SendChildIdRequest`, `HandleChildIdResponse`).
//!
//! ```text
//! attach_begin --(delay)--> Start --> ParentRequest (x N, routers only first,
//!   then routers+REEDs) --(collect Parent Responses, keep the best)-->
//!   acceptable candidate? --> ChildIdRequest --(Child ID Response)--> Child
//!                      \-- none after all requests: Reattach() -> Detached + backoff
//! ```
//!
//! Timing follows OT: first attach attempt starts after 1..750 ms, further
//! attempts after `251 ms << (n-1)` (+0..50 ms jitter) up to 20 min
//! (+-2 s); a Parent Request to routers waits 750 ms, to routers and REEDs
//! 1250 ms; a Child ID Response is awaited 1250 ms; the attach counter is
//! reset 20 s after becoming a child. 4+2 Parent Requests (2 to routers,
//! 4 to routers and REEDs) in the first cycle, 1+1 in later ones.
//!
//! An FTD adds partition logic: while attached it only accepts parents that
//! fit the attach mode (a different partition, a newer router ID sequence of
//! the same one, or a strictly better partition: weight, then not being a
//! singleton, then partition ID), prefers the better partition among
//! several candidates, and starts a partition of its own (becomes leader)
//! when an attach to any partition finds none.
//!
//! Deviations from OT: no Announce attach state (an Announce from a newer
//! network only raises an event, see [`crate::discovery`]), no
//! "reattach with stored Active/Pending dataset" sequence. A
//! Parent Response is only accepted while Parent Requests are being sent.

use opentrust_core::time::{Duration, Instant};
use opentrust_core::types::{Rloc16, ipv6};
use opentrust_core::{Error, Result};
use opentrust_mac::security::LinkFrameCounters;

use crate::consts::{PARENT_REQ_SCANMASK_R_TIMEOUT, PARENT_REQ_SCANMASK_RE_TIMEOUT};
use crate::endpoint::MleRx;
use crate::env::{MleEnv, MleEvent, Role};
use crate::link_quality::{INVALID_RSSI, LinkQuality, compute_link_margin};
use crate::message::Command;
use crate::mle::{Mle, NbRef, RxClass};
use crate::neighbor::{MleReplay, Neighbor, NeighborState, Parent, Router};
use crate::tlv::{
    Connectivity, DeviceMode, LeaderData, ParentPriority, SCAN_MASK_END_DEVICE, SCAN_MASK_ROUTER,
    ty,
};

/// Child ID Response wait time (OT `kChildIdResponseTimeout`).
pub const CHILD_ID_RESPONSE_TIMEOUT: Duration = Duration::from_millis(1250);
/// Max jitter added to the start of an attach (OT `kAttachStartJitter`).
pub const ATTACH_START_JITTER_MS: u32 = 50;
/// First attach backoff interval (OT `kAttachBackoffMinInterval`).
pub const ATTACH_BACKOFF_MIN_MS: u32 = 251;
/// Maximum attach backoff interval (OT `kAttachBackoffMaxInterval`, 20 min).
pub const ATTACH_BACKOFF_MAX_MS: u32 = 1_200_000;
/// Jitter of the maximum backoff (OT `kAttachBackoffJitter`).
pub const ATTACH_BACKOFF_JITTER_MS: u32 = 2000;
/// Idle time as a child after which the attach counter is reset (OT
/// `kAttachBackoffDelayToResetCounter`).
pub const ATTACH_BACKOFF_RESET: Duration = Duration::from_secs(20);

/// Parent Requests in the first attach cycle / of those to routers only.
const FIRST_CYCLE_TOTAL: u8 = 6;
const FIRST_CYCLE_ROUTERS: u8 = 2;
/// Parent Requests in later cycles / of those to routers only.
const NEXT_CYCLE_TOTAL: u8 = 2;
const NEXT_CYCLE_ROUTERS: u8 = 1;

/// SED buffer size / datagram count assumed if the Connectivity TLV has none
/// (OT `kDefaultSedBufferSize`, `kDefaultSedDatagramCount`).
const DEFAULT_SED_BUFFER_SIZE: u16 = 1280;
const DEFAULT_SED_DATAGRAM_COUNT: u8 = 1;

/// Why we attach (OT `AttachMode`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum AttachMode {
    /// Any partition (detached device).
    AnyPartition,
    /// Only the partition we are in (leader lost; router id sequence must
    /// advance).
    SamePartition,
    /// A partition better than ours (heard in an Advertisement).
    BetterPartition,
    /// A better parent in the same partition (child only).
    BetterParent,
    /// Downgrade a router to a REED (same partition, no newer sequence).
    DowngradeToReed,
    /// A specific parent chosen by parent search.
    SelectedParent,
}

/// Phase of the attach procedure (OT `AttachState`, without Announce).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum AttachState {
    /// Not attaching.
    Idle,
    /// Waiting for the (jittered / backed-off) start.
    Start,
    /// Sending Parent Requests and collecting Parent Responses.
    ParentRequest,
    /// Child ID Request sent, waiting for the Child ID Response.
    ChildIdRequest,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ParentRequestType {
    ToRouters,
    ToRoutersAndReeds,
}

/// A parent that answered a Parent Request (OT `mParentCandidate`).
#[derive(Debug, Clone)]
pub(crate) struct Candidate {
    pub parent: Parent,
    pub rx_challenge: [u8; 8],
    pub rx_challenge_len: usize,
    pub priority: ParentPriority,
    pub lq3: u8,
    pub lq2: u8,
    pub lq1: u8,
    #[cfg_attr(not(feature = "ftd"), allow(dead_code))]
    pub leader_data: LeaderData,
    #[cfg_attr(not(feature = "ftd"), allow(dead_code))]
    pub singleton: bool,
    /// Two-way link margin in dB.
    pub link_margin: u8,
}

impl Candidate {
    fn two_way_quality(&self) -> LinkQuality {
        self.parent.router.neighbor.link_info.two_way_quality()
    }
}

/// Attach bookkeeping inside [`Mle`].
#[derive(Debug)]
pub(crate) struct AttachCtx {
    pub state: AttachState,
    pub mode: AttachMode,
    pub counter: u16,
    pub parent_request_counter: u8,
    pub challenge: [u8; 8],
    pub received_response_from_parent: bool,
    pub deadline: Option<Instant>,
    pub candidate: Option<Candidate>,
}

impl AttachCtx {
    pub const fn new() -> Self {
        Self {
            state: AttachState::Idle,
            mode: AttachMode::AnyPartition,
            counter: 0,
            parent_request_counter: 0,
            challenge: [0; 8],
            received_response_from_parent: false,
            deadline: None,
            candidate: None,
        }
    }

    pub fn is_attaching(&self) -> bool {
        self.state != AttachState::Idle
    }

    /// Forget the attempt (keeps the attempt counter).
    pub fn reset(&mut self) {
        self.state = AttachState::Idle;
        self.deadline = None;
        self.candidate = None;
        self.received_response_from_parent = false;
    }
}

fn quality_for_margin(m: u8) -> LinkQuality {
    LinkQuality::for_margin(m)
}

fn priority_rank(p: ParentPriority) -> i8 {
    match p {
        ParentPriority::Low => -1,
        ParentPriority::Medium => 0,
        ParentPriority::High => 1,
    }
}

impl<const C: usize> Mle<C> {
    /// Start an attach attempt (OT `Mle::Attach`). Ignored if one is running.
    pub fn attach_begin<E: MleEnv>(&mut self, env: &mut E, now: Instant, mode: AttachMode) {
        if self.role == Role::Disabled || self.attach.is_attaching() {
            return;
        }
        if self.role != Role::Detached {
            self.attach.counter = 0;
        }
        self.attach.candidate = None;
        self.attach.state = AttachState::Start;
        self.attach.mode = mode;
        let delay = self.attach_start_delay(env);
        self.attach.deadline = Some(now.saturating_add(delay));
        if self.role == Role::Detached {
            self.attach.counter = self.attach.counter.saturating_add(1);
        }
    }

    /// Ask for a new parent while attached as a child (OT
    /// `SearchForBetterParent`).
    pub fn search_for_better_parent<E: MleEnv>(&mut self, env: &mut E, now: Instant) -> Result<()> {
        if self.role != Role::Child {
            return Err(Error::InvalidState);
        }
        self.attach_begin(env, now, AttachMode::BetterParent);
        Ok(())
    }

    /// OT `GetAttachStartDelay`.
    fn attach_start_delay<E: MleEnv>(&self, env: &mut E) -> Duration {
        if self.role != Role::Detached {
            return Duration::from_millis(1);
        }
        let counter = self.attach.counter;
        if counter == 0 {
            let r = Self::rand_range(env, 0, PARENT_REQ_SCANMASK_R_TIMEOUT.as_millis() as u32);
            return Duration::from_millis(1 + u64::from(r));
        }
        let c = u32::from(counter - 1);
        let ratio = ATTACH_BACKOFF_MAX_MS / ATTACH_BACKOFF_MIN_MS;
        let mut delay = if c < 32 && (1u32 << c) <= ratio {
            ATTACH_BACKOFF_MIN_MS << c
        } else {
            // AddJitter(max, jitter): max +- jitter
            let j = Self::rand_range(env, 0, 2 * ATTACH_BACKOFF_JITTER_MS + 1);
            ATTACH_BACKOFF_MAX_MS - ATTACH_BACKOFF_JITTER_MS + j
        };
        delay += Self::rand_range(env, 0, ATTACH_START_JITTER_MS);
        Duration::from_millis(u64::from(delay))
    }

    /// OT `DetermineParentRequestType`; `None` once all requests were sent.
    fn determine_parent_request_type(&self) -> Option<ParentRequestType> {
        let n = self.attach.parent_request_counter;
        let (total, routers) =
            if self.attach.counter <= 1 && self.attach.mode != AttachMode::BetterParent {
                let routers = if self.attach.mode != AttachMode::SamePartition {
                    FIRST_CYCLE_ROUTERS
                } else {
                    0
                };
                (FIRST_CYCLE_TOTAL, routers)
            } else {
                (NEXT_CYCLE_TOTAL, NEXT_CYCLE_ROUTERS)
            };
        if n > total {
            return None;
        }
        Some(if n <= routers {
            ParentRequestType::ToRouters
        } else {
            ParentRequestType::ToRoutersAndReeds
        })
    }

    /// OT `HasAcceptableParentCandidate`.
    fn has_acceptable_parent_candidate(&self) -> bool {
        let Some(c) = &self.attach.candidate else {
            return false;
        };
        if c.parent.router.neighbor.state != NeighborState::ParentResponse {
            return false;
        }
        match self.attach.state {
            AttachState::ParentRequest => {
                if self.determine_parent_request_type() == Some(ParentRequestType::ToRouters)
                    && c.two_way_quality() != LinkQuality::Q3
                {
                    return false;
                }
            }
            _ => return false,
        }
        if self.role == Role::Child {
            match self.attach.mode {
                AttachMode::BetterPartition => {}
                _ => {
                    if !self.attach.received_response_from_parent {
                        return false;
                    }
                }
            }
        }
        true
    }

    /// The attach timer fired (OT `HandleAttachTimer`).
    pub(crate) fn handle_attach_timer<E: MleEnv>(&mut self, env: &mut E, now: Instant) {
        let mut delay = Duration::ZERO;
        if self.has_acceptable_parent_candidate() && self.send_child_id_request(env).is_ok() {
            self.attach.state = AttachState::ChildIdRequest;
            self.attach.deadline = Some(now.saturating_add(CHILD_ID_RESPONSE_TIMEOUT));
            return;
        }
        match self.attach.state {
            AttachState::Idle => {
                self.attach.counter = 0;
            }
            AttachState::Start | AttachState::ParentRequest => {
                if self.attach.state == AttachState::Start {
                    self.attach.state = AttachState::ParentRequest;
                    self.attach.candidate = None;
                    self.attach.received_response_from_parent = false;
                    self.attach.parent_request_counter = 0;
                    env.set_rx_on_when_idle(true);
                }
                self.attach.parent_request_counter += 1;
                if let Some(t) = self.determine_parent_request_type() {
                    let _ = self.send_parent_request(env, t);
                    delay = match t {
                        ParentRequestType::ToRouters => PARENT_REQ_SCANMASK_R_TIMEOUT,
                        ParentRequestType::ToRoutersAndReeds => PARENT_REQ_SCANMASK_RE_TIMEOUT,
                    };
                } else {
                    // No Announce attach state: the attempt is over.
                    self.attach.state = AttachState::Idle;
                    self.attach.candidate = None;
                    self.reattach(env, now);
                }
            }
            AttachState::ChildIdRequest => {
                self.attach.state = AttachState::Idle;
                self.attach.candidate = None;
                self.reattach(env, now);
            }
        }
        if !delay.is_zero() {
            self.attach.deadline = Some(now.saturating_add(delay));
        }
    }

    /// OT `Reattach` after the dataset-reattach steps (not implemented).
    fn reattach<E: MleEnv>(&mut self, env: &mut E, now: Instant) {
        match self.attach.mode {
            AttachMode::AnyPartition | AttachMode::BetterParent | AttachMode::SelectedParent => {
                if self.role != Role::Child {
                    // No partition found: an FTD starts its own.
                    #[cfg(feature = "ftd")]
                    if self.is_full_thread_device() && self.become_leader(env, now, false).is_ok() {
                        return;
                    }
                    self.become_detached(env, now);
                } else if !self.is_rx_on_when_idle() {
                    env.set_poll_attach_mode(false);
                    env.set_rx_on_when_idle(false);
                }
            }
            AttachMode::SamePartition | AttachMode::DowngradeToReed => {
                self.attach_begin(env, now, AttachMode::AnyPartition);
            }
            AttachMode::BetterPartition => {}
        }
    }

    /// OT `BecomeDetached`: drop the parent and start over with backoff.
    pub fn become_detached<E: MleEnv>(&mut self, env: &mut E, now: Instant) {
        if self.role == Role::Disabled {
            return;
        }
        if self.role == Role::Detached && self.attach.state == AttachState::Start {
            return;
        }
        let had_parent = self.parent.is_some();
        self.reset_to_detached(env);
        if had_parent {
            env.event(MleEvent::ParentLost);
        }
        self.attach.state = AttachState::Idle;
        self.attach_begin(env, now, AttachMode::AnyPartition);
    }

    fn send_parent_request<E: MleEnv>(&mut self, env: &mut E, t: ParentRequestType) -> Result<()> {
        self.attach.challenge = Self::new_challenge(env);
        let scan = match t {
            ParentRequestType::ToRouters => SCAN_MASK_ROUTER,
            ParentRequestType::ToRoutersAndReeds => SCAN_MASK_ROUTER | SCAN_MASK_END_DEVICE,
        };
        let mode = self.cfg.mode;
        let challenge = self.attach.challenge;
        self.send(
            env,
            ipv6::LINK_LOCAL_ALL_ROUTERS,
            Command::ParentRequest,
            |w| {
                w.mode(mode)?;
                w.challenge(&challenge)?;
                w.scan_mask(scan)?;
                w.version(Self::VERSION)
            },
        )
    }

    /// OT `IsBetterParent`.
    fn is_better_parent(
        cand: &Candidate,
        rloc: Rloc16,
        two_way_margin: u8,
        conn: &Connectivity,
        version: u16,
    ) -> bool {
        let new_sed_size = conn.sed_buffer_size.unwrap_or(DEFAULT_SED_BUFFER_SIZE);
        let new_sed_count = conn
            .sed_datagram_count
            .unwrap_or(DEFAULT_SED_DATAGRAM_COUNT);
        let cmp = |a: i32, b: i32| a.cmp(&b);
        let steps = [
            cmp(
                i32::from(quality_for_margin(two_way_margin).as_u8()),
                i32::from(cand.two_way_quality().as_u8()),
            ),
            cmp(
                i32::from(rloc.is_router()),
                i32::from(cand.parent.router.neighbor.rloc16.is_router()),
            ),
            cmp(
                i32::from(priority_rank(conn.parent_priority)),
                i32::from(priority_rank(cand.priority)),
            ),
            cmp(i32::from(conn.link_quality_3), i32::from(cand.lq3)),
            cmp(
                i32::from(version),
                i32::from(cand.parent.router.neighbor.version),
            ),
            cmp(
                i32::from(new_sed_size),
                i32::from(cand.parent.sed_buffer_size),
            ),
            cmp(
                i32::from(new_sed_count),
                i32::from(cand.parent.sed_datagram_count),
            ),
            cmp(i32::from(conn.link_quality_2), i32::from(cand.lq2)),
            cmp(i32::from(conn.link_quality_1), i32::from(cand.lq1)),
            // CSL accuracy comparison (sleepy children with CSL) is not
            // implemented; see deviations.
            cmp(i32::from(two_way_margin), i32::from(cand.link_margin)),
        ];
        for s in steps {
            if s != core::cmp::Ordering::Equal {
                return s == core::cmp::Ordering::Greater;
            }
        }
        false
    }

    /// OT `HandleParentResponse`.
    pub(crate) fn handle_parent_response<E: MleEnv>(
        &mut self,
        env: &mut E,
        now: Instant,
        rx: &MleRx<'_>,
        _nb: Option<NbRef>,
    ) -> Result<RxClass> {
        if self.attach.state != AttachState::ParentRequest {
            return Err(Error::Drop);
        }
        let t = &rx.tlvs;
        let source = t.source_address()?;
        let version = t.version()?;
        let response = t.response()?;
        if response != self.attach.challenge {
            return Err(Error::Security);
        }
        let ext = rx.meta.sender_ext_address();
        if self.role == Role::Child
            && self
                .parent
                .as_ref()
                .is_some_and(|p| p.router.neighbor.ext_address == ext)
        {
            self.attach.received_response_from_parent = true;
        }
        let leader_data = t.leader_data()?;
        let margin_out = t.link_margin()?;
        let rss = rx.meta.link.rss.unwrap_or(INVALID_RSSI);
        let two_way_margin = compute_link_margin(env.noise_floor(), rss).min(margin_out);
        let conn = t.connectivity()?;
        #[cfg(feature = "ftd")]
        if self.is_full_thread_device() && self.role != Role::Detached {
            let same = leader_data.partition_id == self.leader_data.partition_id;
            let seq_same = conn.id_sequence == self.router_id_sequence();
            let seq_greater =
                crate::child_rx::serial_greater(conn.id_sequence, self.router_id_sequence());
            let fits = match self.attach.mode {
                AttachMode::AnyPartition => !same || seq_greater,
                AttachMode::SamePartition => same && seq_greater,
                AttachMode::DowngradeToReed => same && (seq_same || seq_greater),
                AttachMode::BetterPartition => {
                    !same
                        && crate::advert::compare_partitions(
                            conn.is_singleton(),
                            &leader_data,
                            self.is_singleton(),
                            &self.leader_data,
                        ) > 0
                }
                AttachMode::BetterParent | AttachMode::SelectedParent => true,
            };
            if !fits {
                return Ok(RxClass::Authoritative);
            }
        }

        if let Some(c) = &self.attach.candidate {
            if c.parent.router.neighbor.state == NeighborState::ParentResponse
                && c.parent.router.neighbor.ext_address != ext
            {
                // Only consider partitions that are the same or better; among
                // parents of the same partition the better parent wins.
                #[cfg(feature = "ftd")]
                let compare = if self.is_full_thread_device() {
                    crate::advert::compare_partitions(
                        conn.is_singleton(),
                        &leader_data,
                        c.singleton,
                        &c.leader_data,
                    )
                } else {
                    0
                };
                #[cfg(not(feature = "ftd"))]
                let compare = 0;
                if compare < 0 {
                    return Ok(RxClass::Authoritative);
                }
                if compare == 0
                    && !Self::is_better_parent(c, source, two_way_margin, &conn, version)
                {
                    return Ok(RxClass::Authoritative);
                }
            }
        }
        let link_fc = t.link_frame_counter()?;
        let mle_fc = t.mle_frame_counter()?;
        let ch = t.challenge()?;
        let mut rx_challenge = [0u8; 8];
        let n = ch.len().min(8);
        rx_challenge[..n].copy_from_slice(&ch[..n]);

        let sec = rx.meta.security.ok_or(Error::Security)?;
        let mut nbr = Neighbor::new(ext, now);
        if let Some(rss) = rx.meta.link.rss {
            nbr.link_info.add_rss(env.noise_floor(), rss);
        }
        nbr.rloc16 = source;
        nbr.link_counters = LinkFrameCounters::with(sec.key_sequence, link_fc);
        nbr.mle_replay = MleReplay::with(mle_fc);
        nbr.version = version;
        nbr.mode = DeviceMode::new(true, true, true);
        nbr.link_info
            .set_link_quality_out(quality_for_margin(margin_out));
        nbr.state = NeighborState::ParentResponse;
        let mut router = Router::new(source.router_id(), ext, now);
        router.neighbor = nbr;
        router.neighbor.rloc16 = source;
        self.attach.candidate = Some(Candidate {
            parent: Parent {
                router,
                leader_cost: conn.leader_cost,
                sed_buffer_size: conn.sed_buffer_size.unwrap_or(DEFAULT_SED_BUFFER_SIZE),
                sed_datagram_count: conn
                    .sed_datagram_count
                    .unwrap_or(DEFAULT_SED_DATAGRAM_COUNT),
            },
            rx_challenge,
            rx_challenge_len: n,
            priority: conn.parent_priority,
            lq3: conn.link_quality_3,
            lq2: conn.link_quality_2,
            lq1: conn.link_quality_1,
            leader_data,
            singleton: conn.is_singleton(),
            link_margin: two_way_margin,
        });
        Ok(RxClass::Authoritative)
    }

    /// OT `SendChildIdRequest`.
    fn send_child_id_request<E: MleEnv>(&mut self, env: &mut E) -> Result<()> {
        let cand = self.attach.candidate.as_ref().ok_or(Error::NotFound)?;
        let cand_ext = cand.parent.router.neighbor.ext_address;
        if let Some(p) = &self.parent {
            if p.router.neighbor.ext_address == cand_ext {
                if self.role == Role::Child {
                    return Err(Error::Already);
                }
                self.parent = None;
            }
        }
        let cand = self.attach.candidate.as_ref().ok_or(Error::NotFound)?;
        let mut rx_challenge = [0u8; 8];
        let clen = cand.rx_challenge_len;
        rx_challenge[..clen].copy_from_slice(&cand.rx_challenge[..clen]);
        let mode = self.cfg.mode;
        let ftd = mode.full_thread_device();
        let link_fc = env.keys().frame_counter();
        let mle_fc = self.mle_counter.current();
        let timeout = self.cfg.timeout_secs;
        let sup = (mode.is_sleepy() && self.cfg.supervision_interval != 0)
            .then_some(self.cfg.supervision_interval);
        let addrs = Self::address_entries(env, false);
        let active_ts = env.active_timestamp();
        let pending_ts = env.pending_timestamp();
        let tlvs: &[u8] = if ftd {
            &[ty::ADDRESS16, ty::NETWORK_DATA, ty::ROUTE64]
        } else {
            &[ty::ADDRESS16, ty::NETWORK_DATA]
        };
        let dst = ipv6::link_local(&cand_ext);
        self.send(env, dst, Command::ChildIdRequest, |w| {
            w.response(&rx_challenge[..clen])?;
            w.link_frame_counter(link_fc)?;
            w.mle_frame_counter(mle_fc)?;
            w.mode(mode)?;
            w.timeout(timeout)?;
            w.version(Self::VERSION)?;
            if let Some(s) = sup {
                w.supervision_interval(s)?;
            }
            if !ftd {
                w.address_registration(&addrs)?;
            }
            w.tlv_request(tlvs)?;
            if let Some(t) = &active_ts {
                w.active_timestamp(t)?;
            }
            if let Some(t) = &pending_ts {
                w.pending_timestamp(t)?;
            }
            Ok(())
        })?;
        if let Some(c) = self.attach.candidate.as_mut() {
            c.parent.router.neighbor.state = NeighborState::Valid;
        }
        Ok(())
    }

    /// OT `HandleChildIdResponse`.
    pub(crate) fn handle_child_id_response<E: MleEnv>(
        &mut self,
        env: &mut E,
        now: Instant,
        rx: &MleRx<'_>,
        nb: Option<NbRef>,
    ) -> Result<RxClass> {
        let t = &rx.tlvs;
        let source = t.source_address()?;
        if nb != Some(NbRef::Candidate) {
            return Err(Error::Security);
        }
        if self.attach.state != AttachState::ChildIdRequest {
            return Err(Error::Drop);
        }
        let address = t.address16()?;
        if source.router_id() != address.router_id() {
            return Err(Error::Drop);
        }
        let leader = t.leader_data()?;
        let nd = t.network_data()?;
        let active = match t.active_timestamp() {
            Ok(ts) => Some((ts, t.active_dataset().ok())),
            Err(Error::NotFound) => None,
            Err(e) => return Err(e),
        };
        let pending = match t.pending_timestamp() {
            Ok(ts) => Some((ts, t.pending_dataset().ok())),
            Err(Error::NotFound) => None,
            Err(e) => return Err(e),
        };
        env.dataset_received(now, active, pending);

        let cand = self.attach.candidate.take().ok_or(Error::InvalidState)?;
        // OT SetStateDetached(): leaves the old attachment.
        self.attach.reset();
        self.child.reset();
        #[cfg(feature = "ftd")]
        if self.role.is_router_or_leader() {
            self.router_left_router_role(env);
        }
        self.update_leader_data(env, leader);
        #[cfg(feature = "ftd")]
        if self.is_full_thread_device() {
            if let Err(e) =
                self.read_and_process_route_on_ftd_child(env, now, &rx.tlvs, source.router_id())
            {
                self.become_detached(env, now);
                return Err(e);
            }
        }
        let mut parent = cand.parent;
        parent.router.neighbor.rloc16 = source;
        parent.router.neighbor.state = NeighborState::Valid;
        parent.router.neighbor.last_heard = now;
        parent.router.neighbor.connection_start = Some(now);
        let ext = parent.router.neighbor.ext_address;
        self.parent = Some(parent);
        env.set_network_data(&leader, nd);
        env.event(MleEvent::NetworkDataChanged);
        self.set_state_child(env, now, address);
        env.event(MleEvent::Attached {
            parent: ext,
            parent_rloc16: source,
        });
        Ok(RxClass::Peer)
    }
}
