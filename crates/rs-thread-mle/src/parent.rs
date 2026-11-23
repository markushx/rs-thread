//! Parent-side attach handling for a router (feature `ftd`; Thread 1.4.1
//! §4.5.1, §4.6; OpenThread `MleRouter::HandleParentRequest`,
//! `SendParentResponse`, `HandleChildIdRequest`, `SendChildIdResponse`,
//! `HandleChildUpdateRequestOnParent`, `HandleChildUpdateResponseOnParent`,
//! `HandleDataRequest`, child timeout in `HandleTimeTick`,
//! `ChildSupervisor`).
//!
//! The router role itself (becoming router/leader, router IDs, routing,
//! Advertisements) lives in [`router`](crate::router) and friends. This
//! module only needs the [`RouterInfo`] (Connectivity TLV, Route64 value
//! for Child ID Responses), which the router state machine recomputes
//! from the live router table. [`Mle::enter_router_role`] bypasses that
//! state machine and supplies a static [`RouterInfo`]: used by unit tests
//! of this module.
//!
//! ```text
//! Parent Request --(1..500/1000 ms jitter)--> Parent Response (challenge echo,
//!   own challenge, link margin, connectivity) ; child: ParentRequest state
//! Child ID Request (Response check, counters, mode, timeout, TLV request,
//!   address registration) -> allocate child RLOC16 -> Child ID Response ;
//!   child: ChildIdRequest -> Valid (stored in settings, indirect for SEDs)
//! Child Update Request/Response, Data Request, timeouts, supervision
//! ```
//!
//! Deviations from OT: a child in `Restored`/`ChildUpdateRequest` state may
//! itself start the exchange with a Child Update Request (fast re-attach
//! after the *child* restarts; OT drops it until its own Child Update
//! Request restored the child).

use core::net::Ipv6Addr;

use heapless::Vec;
use rs_thread_core::settings::ChildInfo;
use rs_thread_core::time::{Duration, Instant};
use rs_thread_core::types::{Rloc16, ipv6};
use rs_thread_core::{Error, Result};
use rs_thread_mac::security::LinkFrameCounters;

use crate::consts::{
    CHILD_MAX_REQUEST_TLVS, MAX_ROUTE_COST, PARENT_RSP_REED_JITTER, PARENT_RSP_ROUTER_JITTER,
    THREAD_VERSION_1_3,
};
use crate::endpoint::MleRx;
use crate::env::{MleEnv, MleEvent, Role, RouterRequestReason};
use crate::message::Command;
use crate::mle::{Mle, NbRef, RxClass};
use crate::neighbor::{Child, MleReplay, NeighborState, StateFilter};
use crate::tlv::{
    AddressEntry, Connectivity, DeviceMode, LeaderData, SCAN_MASK_END_DEVICE, SCAN_MASK_ROUTER, ty,
};

/// Child timeout while a child is in `ParentRequest` state: it must send
/// its Child ID Request within this time (OT `kChildIdRequestTimeout`).
pub const CHILD_ID_REQUEST_TIMEOUT_SECS: u32 = 5;
/// Parent Requests from the same child closer than this are duplicates
/// (OT `kParentRequestRouterTimeout - kParentRequestDuplicateMargin`).
const DUPLICATE_PARENT_REQUEST: Duration = Duration::from_millis(700);
/// Default supervision interval for children of version <= 1.3 that did not
/// send one (OT `kChildSupervisionDefaultIntervalForOlderVersion`).
pub const SUPERVISION_DEFAULT_FOR_OLDER_VERSION: u16 = 129;
/// Child IDs are 1..=511 (OT `kMinChildId`, `kMaxChildId`).
const MAX_CHILD_ID: u16 = 511;
/// Parent Responses waiting for their jitter delay.
const PENDING_RESPONSES: usize = 4;

/// What the router role tells the parent-side code.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RouterInfo {
    /// Connectivity TLV sent in Parent Responses (leader cost, ID sequence,
    /// active routers, link quality counts, parent priority, SED buffer).
    pub connectivity: Connectivity,
    /// Value of the Route64 TLV for Child ID Responses that ask for it
    /// (empty: not provided).
    pub route64: Vec<u8, 72>,
    /// The router can take children: attached to the leader, leader age and
    /// path cost acceptable. Parent Requests are dropped while `false`.
    pub accepting_children: bool,
}

#[derive(Debug, Clone, Copy)]
struct PendingParentResponse {
    child: rs_thread_core::types::ExtAddress,
    challenge: [u8; 8],
    challenge_len: usize,
    due: Instant,
}

/// Parent-side bookkeeping inside [`Mle`].
#[derive(Debug)]
pub(crate) struct ParentSide {
    pending: Vec<PendingParentResponse, PENDING_RESPONSES>,
    next_child_id: u16,
    pub(crate) info: RouterInfo,
    /// Next per-second tick (child supervision).
    pub(crate) tick: Option<Instant>,
    /// Restored children still need their Child Update Request.
    restored_update_due: Option<Instant>,
}

impl ParentSide {
    pub const fn new() -> Self {
        Self {
            pending: Vec::new(),
            next_child_id: 0,
            info: RouterInfo {
                connectivity: Connectivity {
                    parent_priority: crate::tlv::ParentPriority::Medium,
                    link_quality_3: 0,
                    link_quality_2: 0,
                    link_quality_1: 0,
                    leader_cost: 0,
                    id_sequence: 0,
                    active_routers: 0,
                    sed_buffer_size: None,
                    sed_datagram_count: None,
                },
                route64: Vec::new(),
                accepting_children: false,
            },
            tick: None,
            restored_update_due: None,
        }
    }
}

fn add_unique(list: &mut Vec<u8, 16>, v: u8) {
    if !list.contains(&v) {
        let _ = list.push(v);
    }
}

impl<const C: usize> Mle<C> {
    // ------------------------------------------------------------ static role entry (tests)

    /// Take the router (or leader) role with the given RLOC16 and Leader
    /// Data with a static [`RouterInfo`], bypassing the router state machine
    /// (no router table, Advertisements or links): for tests of the
    /// parent-side code. The real transitions are
    /// [`become_leader`](Mle::become_leader) and
    /// [`address_solicit_reply`](Mle::address_solicit_reply).
    pub fn enter_router_role<E: MleEnv>(
        &mut self,
        env: &mut E,
        now: Instant,
        role: Role,
        rloc16: Rloc16,
        leader: LeaderData,
        info: RouterInfo,
    ) -> Result<()> {
        if !role.is_router_or_leader() || !rloc16.is_router() || !self.is_full_thread_device() {
            return Err(Error::InvalidArgs);
        }
        self.attach.reset();
        self.child.reset();
        self.parent = None;
        env.set_parent(None);
        env.set_poll_period(None);
        env.set_rx_on_when_idle(true);
        self.set_rloc16(env, rloc16);
        self.leader_data = leader;
        self.parent_side.info = info;
        self.rtr.managed = false;
        self.parent_side.tick = Some(now.saturating_add(Duration::from_secs(1)));
        self.set_role(env, role);
        Ok(())
    }

    /// Update the router information (connectivity, route TLV).
    pub fn set_router_info(&mut self, info: RouterInfo) {
        self.parent_side.info = info;
    }

    /// Update the Leader Data (a new Network Data version): children are
    /// informed through their next Child Update / Data Request.
    pub fn set_leader_data(&mut self, leader: LeaderData) {
        self.leader_data = leader;
    }

    /// The Network Data of this partition changed (the leader registered
    /// new Server Data, or a router stored a newer copy): a leader
    /// advertises soon so that routers pull the new data, and sleepy
    /// children whose Network Data version is behind get a Child Update
    /// Request carrying the data (OT `HandleNetworkDataUpdateRouter`
    /// without the multicast Data Response).
    pub fn network_data_updated<E: MleEnv>(&mut self, env: &mut E, now: Instant) {
        if !self.role.is_router_or_leader() {
            return;
        }
        if self.role == Role::Leader {
            self.reset_advertise_interval(env, now);
            let _ = self.send_multicast_data_response(env, now);
        } else if !self.rtr.delayed.iter().any(|d| {
            matches!(
                d.kind,
                crate::router_link::DelayedKind::MulticastDataResponse
            )
        }) {
            let jitter =
                Self::rand_range(env, 0, crate::consts::UNSOLICITED_DATA_RESPONSE_JITTER_MS);
            self.schedule_delayed(
                now.saturating_add(Duration::from_millis(1 + u64::from(jitter))),
                crate::router_link::DelayedKind::MulticastDataResponse,
            );
        }
        let mut behind: heapless::Vec<usize, C> = heapless::Vec::new();
        for (idx, c) in self.children.iter_indexed(StateFilter::Valid) {
            if !c.neighbor.is_rx_on_when_idle()
                && c.network_data_version != self.network_data_version_for(c.neighbor.mode)
            {
                let _ = behind.push(idx);
            }
        }
        for idx in behind {
            let _ = self.send_child_update_request_to_child(env, now, idx);
        }
    }

    pub(crate) fn parent_side_reset<E: MleEnv>(&mut self, env: &mut E) {
        self.parent_side.pending.clear();
        self.parent_side.tick = None;
        self.parent_side.restored_update_due = None;
        for c in self.children.iter(StateFilter::AnyExceptInvalid) {
            if c.neighbor.is_valid() && !c.neighbor.is_rx_on_when_idle() {
                env.indirect_remove_child(&c.neighbor.ext_address, c.neighbor.rloc16);
            }
        }
        self.children.clear();
    }

    /// A frame with a CSL IE from `child` was received (the MAC's CSL
    /// table updated its phase): the child is CSL synchronized (OT
    /// `Mac::ProcessCsl`). Returns `false` for an unknown child.
    pub fn child_csl_synchronized(&mut self, child: Rloc16, now: Instant) -> bool {
        match self
            .children
            .find_by_rloc_mut(child, StateFilter::AnyExceptInvalid)
        {
            Some(c) => {
                c.csl_synchronized = true;
                c.csl_last_heard = now;
                if c.csl_timeout_secs == 0 {
                    // Until the child announces its timeout, use its child
                    // timeout.
                    c.csl_timeout_secs = c.timeout_secs;
                }
                true
            }
            None => false,
        }
    }

    /// The CSL channel a child announced (0 = the PAN channel).
    pub fn child_csl_channel(&mut self, child: Rloc16) -> Option<u8> {
        self.children
            .find_by_rloc_mut(child, StateFilter::AnyExceptInvalid)
            .map(|c| c.csl_channel)
    }

    /// The RLOC16 of the child with extended address `ext`.
    pub fn child_rloc_by_ext(&self, ext: &rs_thread_core::types::ExtAddress) -> Option<Rloc16> {
        self.children
            .find_by_ext(ext, StateFilter::AnyExceptInvalid)
            .map(|c| c.neighbor.rloc16)
    }

    /// The MAC lost the child's CSL synchronization (frames to it failed in
    /// its windows): data polls serve it again until it sends a CSL IE.
    pub fn child_csl_desynchronized(&mut self, child: Rloc16) {
        if let Some(c) = self
            .children
            .find_by_rloc_mut(child, StateFilter::AnyExceptInvalid)
        {
            c.csl_synchronized = false;
        }
    }

    // ------------------------------------------------------------ timers

    pub(crate) fn parent_deadline(&self) -> Option<Instant> {
        if !(self.role.is_router_or_leader() || (self.rtr.managed && self.role == Role::Child)) {
            return None;
        }
        let ps = &self.parent_side;
        let mut d = ps.tick;
        d = min_opt(d, ps.restored_update_due);
        for p in &ps.pending {
            d = min_opt(d, Some(p.due));
        }
        for c in self.children.iter(StateFilter::AnyExceptInvalid) {
            if let Some(t) = child_expiry(c) {
                d = min_opt(d, Some(t));
            }
            d = min_opt(d, c.csl_expiry());
        }
        d
    }

    pub(crate) fn poll_parent<E: MleEnv>(&mut self, env: &mut E, now: Instant) {
        // A REED answers Parent Requests and times out its candidates too.
        if !(self.role.is_router_or_leader() || (self.rtr.managed && self.role == Role::Child)) {
            return;
        }
        // Delayed Parent Responses.
        let mut i = 0;
        while i < self.parent_side.pending.len() {
            if now >= self.parent_side.pending[i].due {
                let p = self.parent_side.pending.swap_remove(i);
                let _ = self.send_parent_response(env, &p);
            } else {
                i += 1;
            }
        }
        // Restored children get a Child Update Request.
        if self
            .parent_side
            .restored_update_due
            .is_some_and(|d| now >= d)
        {
            self.parent_side.restored_update_due = None;
            let restored: Vec<usize, C> = self
                .children
                .iter_indexed(StateFilter::AnyExceptInvalid)
                .filter(|(_, c)| c.neighbor.state == NeighborState::Restored)
                .map(|(i, _)| i)
                .collect();
            for idx in restored {
                let _ = self.send_child_update_request_to_child(env, now, idx);
            }
        }
        // Child timeouts (OT HandleTimeTick).
        let expired: Vec<usize, C> = self
            .children
            .iter_indexed(StateFilter::AnyExceptInvalid)
            .filter(|(_, c)| child_expiry(c).is_some_and(|t| now >= t))
            .map(|(i, _)| i)
            .collect();
        for idx in expired {
            self.remove_child(env, idx);
        }
        // CSL synchronization of a child that stopped sending CSL IEs
        // expires: back to data polls (OT `HandleTimeTick`).
        for c in self.children.iter_mut(StateFilter::AnyExceptInvalid) {
            #[cfg(feature = "csl")]
            if c.csl_expiry().is_some_and(|t| now >= t) {
                c.csl_synchronized = false;
                env.csl_child_desync(&c.neighbor.ext_address, c.neighbor.rloc16);
            }
            #[cfg(not(feature = "csl"))]
            let _ = c;
        }
        // Child supervision, once a second.
        if self.parent_side.tick.is_some_and(|t| now >= t) {
            self.parent_side.tick = Some(now.saturating_add(Duration::from_secs(1)));
            self.supervision_tick(env);
        }
    }

    /// OT `ChildSupervisor::CheckState`: a sleepy child that was not sent
    /// anything for its supervision interval gets a supervision message.
    fn supervision_tick<E: MleEnv>(&mut self, env: &mut E) {
        for c in self.children.iter_mut(StateFilter::Valid) {
            if c.neighbor.is_rx_on_when_idle() || c.supervision_interval == 0 {
                continue;
            }
            c.seconds_since_supervision = c.seconds_since_supervision.saturating_add(1);
            if c.seconds_since_supervision >= c.supervision_interval {
                c.seconds_since_supervision = 0;
                env.send_child_supervision(&c.neighbor.ext_address, c.neighbor.rloc16);
            }
        }
    }

    /// A data poll from the child at `rloc16` (or at `ext` while it has no
    /// RLOC16 confirmed yet) arrived: the child is alive (OT
    /// `DataPollHandler::HandleDataPoll` `SetLastHeard`).
    pub fn child_polled(
        &mut self,
        rloc16: Option<Rloc16>,
        ext: Option<&rs_thread_core::types::ExtAddress>,
        now: Instant,
    ) {
        let c = match (rloc16, ext) {
            (Some(r), _) => self
                .children
                .find_by_rloc_mut(r, StateFilter::AnyExceptInvalid),
            (None, Some(e)) => self
                .children
                .find_by_ext_mut(e, StateFilter::AnyExceptInvalid),
            (None, None) => None,
        };
        if let Some(c) = c {
            c.neighbor.last_heard = now;
        }
    }

    /// Something other than a supervision message was queued for the child
    /// (resets its supervision counter; OT
    /// `ChildSupervisor::UpdateOnSend`).
    pub fn child_message_sent(&mut self, rloc16: Rloc16) {
        if let Some(c) = self.children.find_by_rloc_mut(rloc16, StateFilter::Valid) {
            c.seconds_since_supervision = 0;
        }
    }

    /// OT `UpdateEidRlocCacheAndStaleChild`, second half: a mesh-forwarded
    /// datagram from `src` arrived with mesh source `mesh_src`. If `src` is
    /// the address of one of our minimal (non-FTD) children but `mesh_src`
    /// belongs to another router, the child has moved to a new parent and is
    /// removed. Returns whether a child was removed. The forwarder calls this
    /// for every unicast mesh-header frame with a short mesh source.
    pub fn remove_child_that_moved<E: MleEnv>(
        &mut self,
        env: &mut E,
        src: &Ipv6Addr,
        mesh_src: Rloc16,
    ) -> bool {
        if !self.role.is_router_or_leader() || mesh_src.router_id() == self.rloc16.router_id() {
            return false;
        }
        let prefix = env.mesh_local_prefix();
        let found = self
            .children
            .iter_indexed(StateFilter::ValidOrRestoring)
            .find(|(_, c)| !c.neighbor.mode.full_thread_device() && c.has_address(&prefix, src))
            .map(|(i, _)| i);
        match found {
            Some(i) => {
                self.remove_child(env, i);
                true
            }
            None => false,
        }
    }

    /// Remove a child: notify, drop its indirect state and its settings
    /// record (OT `RemoveNeighbor(child)` + `ChildTable` removal).
    pub(crate) fn remove_child<E: MleEnv>(&mut self, env: &mut E, idx: usize) {
        let Some(c) = self.children.remove(idx) else {
            return;
        };
        if c.neighbor.is_valid() || c.neighbor.state.is_restoring() {
            env.event(MleEvent::ChildRemoved {
                ext: c.neighbor.ext_address,
                rloc16: c.neighbor.rloc16,
            });
        }
        if !c.neighbor.is_rx_on_when_idle() {
            #[cfg(feature = "csl")]
            if c.csl_synchronized {
                env.csl_child_desync(&c.neighbor.ext_address, c.neighbor.rloc16);
            }
            env.indirect_remove_child(&c.neighbor.ext_address, c.neighbor.rloc16);
        }
        let _ = env.delete_child_info(&c.neighbor.ext_address);
        #[cfg(feature = "link-metrics")]
        self.link_metrics.remove_neighbor(&c.neighbor.ext_address);
    }

    fn child_to_valid<E: MleEnv>(&mut self, env: &mut E, now: Instant, idx: usize) {
        let Some(c) = self.children.get_mut(idx) else {
            return;
        };
        let was_valid = c.neighbor.is_valid();
        c.neighbor.set_state(NeighborState::Valid, now);
        c.neighbor.last_heard = now;
        let (ext, rloc, rx_on) = (
            c.neighbor.ext_address,
            c.neighbor.rloc16,
            c.neighbor.is_rx_on_when_idle(),
        );
        let info = c.to_child_info();
        if !was_valid {
            if !rx_on {
                env.indirect_add_child(&ext, rloc);
            }
            env.event(MleEvent::ChildAdded { ext, rloc16: rloc });
        }
        let _ = env.store_child_info(&info);
    }

    // ------------------------------------------------------------ Parent Request / Response

    /// OT `HandleParentRequest`.
    pub(crate) fn handle_parent_request<E: MleEnv>(
        &mut self,
        env: &mut E,
        now: Instant,
        rx: &MleRx<'_>,
    ) -> Result<RxClass> {
        let reed = self.rtr.managed && self.role == Role::Child;
        if !(self.role.is_router_or_leader() || reed) || !self.parent_side.info.accepting_children {
            return Err(Error::InvalidState);
        }
        if self.rtr.managed {
            // A router / REED MUST NOT answer while detached or attaching
            // elsewhere, or when disconnected from its partition (§4.5.1).
            if !self.is_router_eligible() {
                return Err(Error::InvalidState);
            }
            if self.attach.is_attaching() {
                return Err(Error::Drop);
            }
            let timeout = Duration::from_secs(u64::from(self.cfg.router.network_id_timeout_secs));
            if self.leader_age(now).is_none_or(|a| a >= timeout) {
                return Err(Error::Drop);
            }
        }
        if self.parent_side.info.connectivity.leader_cost >= MAX_ROUTE_COST {
            return Err(Error::Drop);
        }
        let t = &rx.tlvs;
        let ext = rx.meta.sender_ext_address();
        let version = t.version()?;
        let scan = t.scan_mask()?;
        if reed {
            // A REED answers requests to routers and REEDs only while the
            // leader would still grant a router ID.
            if scan & SCAN_MASK_END_DEVICE == 0
                || usize::from(self.active_router_count()) >= crate::consts::MAX_ROUTERS
            {
                return Err(Error::Drop);
            }
        } else if scan & SCAN_MASK_ROUTER == 0 {
            // A router answers requests to routers only.
            return Err(Error::Drop);
        }
        let challenge = t.challenge()?;
        let mut ch = [0u8; 8];
        let n = challenge.len().min(8);
        ch[..n].copy_from_slice(&challenge[..n]);

        let idx = match self
            .children
            .index_by_ext(&ext, StateFilter::AnyExceptInvalid)
        {
            Some(i) => {
                let c = self.children.get(i).ok_or(Error::NotFound)?;
                if now.saturating_duration_since(c.neighbor.last_heard) < DUPLICATE_PARENT_REQUEST {
                    return Err(Error::Drop);
                }
                i
            }
            None => {
                let c = self.children.add(ext, now)?;
                if let Some(rss) = rx.meta.link.rss {
                    c.neighbor.link_info.add_rss(env.noise_floor(), rss);
                }
                c.neighbor.set_state(NeighborState::ParentRequest, now);
                if let Ok(mode) = t.mode() {
                    c.neighbor.mode = mode;
                    c.neighbor.version = version;
                }
                self.children
                    .index_by_ext(&ext, StateFilter::AnyExceptInvalid)
                    .ok_or(Error::NotFound)?
            }
        };
        if let Some(c) = self.children.get_mut(idx) {
            if !c.neighbor.state.is_valid_or_restoring() {
                c.neighbor.last_heard = now;
                c.timeout_secs = CHILD_ID_REQUEST_TIMEOUT_SECS;
            }
        }
        let max = if scan & SCAN_MASK_END_DEVICE == 0 {
            PARENT_RSP_ROUTER_JITTER
        } else {
            PARENT_RSP_REED_JITTER
        };
        let delay = Duration::from_millis(1).saturating_add(Self::rand_duration(env, max));
        // A repeated request replaces the pending response.
        self.parent_side.pending.retain(|p| p.child != ext);
        self.parent_side
            .pending
            .push(PendingParentResponse {
                child: ext,
                challenge: ch,
                challenge_len: n,
                due: now.saturating_add(delay),
            })
            .map_err(|_| Error::NoBufs)?;
        Ok(RxClass::Peer)
    }

    /// OT `SendParentResponse`.
    fn send_parent_response<E: MleEnv>(
        &mut self,
        env: &mut E,
        p: &PendingParentResponse,
    ) -> Result<()> {
        let idx = self
            .children
            .index_by_ext(&p.child, StateFilter::AnyExceptInvalid)
            .ok_or(Error::NotFound)?;
        let mut mine = [0u8; 8];
        env.fill_random(&mut mine);
        let (margin, csl_capable) = {
            let nf = env.noise_floor();
            let c = self.children.get_mut(idx).ok_or(Error::NotFound)?;
            c.neighbor.challenge = mine;
            (c.neighbor.link_info.link_margin(nf), c.is_csl_capable())
        };
        #[cfg(not(feature = "csl"))]
        let _ = csl_capable;
        #[cfg(feature = "csl")]
        let csl_accuracy = if csl_capable {
            env.csl_clock_accuracy()
        } else {
            None
        };
        #[cfg(not(feature = "csl"))]
        let csl_accuracy: Option<crate::tlv::CslClockAccuracy> = None;
        let rloc = self.rloc16;
        let leader = self.leader_data;
        let link_fc = env.keys().frame_counter();
        let mle_fc = self.mle_counter.current_for(env.keys().key_epoch());
        let conn = self.parent_side.info.connectivity;
        let dst = ipv6::link_local(&p.child);
        self.send(env, dst, Command::ParentResponse, |w| {
            w.source_address(rloc)?;
            w.leader_data(&leader)?;
            w.link_frame_counter(link_fc)?;
            w.mle_frame_counter(mle_fc)?;
            w.response(&p.challenge[..p.challenge_len])?;
            w.challenge(&mine)?;
            w.link_margin(margin)?;
            w.connectivity(&conn)?;
            if let Some(a) = csl_accuracy {
                w.csl_clock_accuracy(a)?;
            }
            w.version(Self::VERSION)
        })
    }

    // ------------------------------------------------------------ Child ID Request / Response

    /// OT `ProcessAddressRegistrationTlv`: replace the child's registered
    /// addresses. [`Error::NotFound`] if the TLV is absent, [`Error::Parse`]
    /// if it holds no usable address.
    fn process_address_registration<E: MleEnv>(
        env: &E,
        child: &mut Child,
        rx: &MleRx<'_>,
    ) -> Result<()> {
        let reg = rx.tlvs.address_registration()?;
        let ml = env.mesh_local_prefix();
        // Groups keep their registration state across a re-registration.
        let old: Vec<
            crate::neighbor::MulticastListener,
            { crate::consts::CHILD_MAX_MULTICAST_ADDRESSES },
        > = Vec::from_slice(child.multicast_listeners()).unwrap_or_default();
        child.clear_addresses();
        child.clear_multicast_listeners();
        child.set_ml_eid_iid(None);
        let mut stored = 0;
        for e in reg {
            let addr: Ipv6Addr = match e? {
                AddressEntry::Uncompressed(a) => a,
                AddressEntry::Compressed { context_id, iid } => {
                    let prefix = if context_id == 0 {
                        Some(ml)
                    } else {
                        env.lowpan_context(context_id)
                    };
                    match prefix {
                        Some(p) => p.with_iid(&rs_thread_core::types::Iid(iid)),
                        None => continue,
                    }
                }
            };
            if ml.contains(&addr) {
                // The ML-EID (only the first mesh-local entry counts; RLOC
                // and ALOC addresses are never registered).
                if child.ml_eid_iid().is_none() {
                    child.set_ml_eid_iid(Some(ipv6::iid(&addr)));
                    stored += 1;
                }
                continue;
            }
            if addr.is_multicast() {
                // Only groups larger than realm-local are registered with
                // the Primary Backbone Router; the others are not kept.
                if rs_thread_net::addr::is_multicast_larger_than_realm_local(&addr)
                    && child.add_multicast_listener(addr).is_ok()
                {
                    if let Some(o) = old.iter().find(|o| o.addr == addr)
                        && let Some(m) = child
                            .multicast_listeners_mut()
                            .iter_mut()
                            .find(|m| m.addr == addr)
                    {
                        m.mlr = o.mlr;
                    }
                    stored += 1;
                }
                continue;
            }
            if addr.is_unicast_link_local() || addr.is_unspecified() {
                continue;
            }
            if child.add_address(addr).is_ok() {
                stored += 1;
            }
        }
        if stored == 0 {
            return Err(Error::Parse);
        }
        Ok(())
    }

    fn network_data_version_for(&self, mode: DeviceMode) -> u8 {
        if mode.full_network_data() {
            self.leader_data.data_version
        } else {
            self.leader_data.stable_data_version
        }
    }

    /// OT `HandleChildIdRequest`.
    pub(crate) fn handle_child_id_request<E: MleEnv>(
        &mut self,
        env: &mut E,
        now: Instant,
        rx: &MleRx<'_>,
        _nb: Option<NbRef>,
    ) -> Result<RxClass> {
        let reed = self.rtr.managed && self.role == Role::Child && self.is_router_eligible();
        if !(self.role.is_router_or_leader() || reed) {
            return Err(Error::InvalidState);
        }
        let t = &rx.tlvs;
        let sec = rx.meta.security.ok_or(Error::Security)?;
        let ext = rx.meta.sender_ext_address();
        let idx = self
            .children
            .index_by_ext(&ext, StateFilter::AnyExceptInvalid)
            .ok_or(Error::Already)?;
        let version = t.version()?;
        let response = t.response()?;
        if self
            .children
            .get(idx)
            .ok_or(Error::NotFound)?
            .neighbor
            .challenge[..]
            != *response
        {
            return Err(Error::Security);
        }
        let link_fc = t.link_frame_counter()?;
        let mle_fc = t.mle_frame_counter()?;
        let mode = t.mode()?;
        let timeout = t.timeout()?;
        let mut list = Vec::<u8, 16>::new();
        for &r in t.tlv_request()? {
            add_unique(&mut list, r);
        }
        let supervision = match t.supervision_interval() {
            Ok(s) => {
                add_unique(&mut list, ty::SUPERVISION_INTERVAL);
                s
            }
            Err(Error::NotFound) => {
                if version <= THREAD_VERSION_1_3 {
                    SUPERVISION_DEFAULT_FOR_OLDER_VERSION
                } else {
                    0
                }
            }
            Err(e) => return Err(e),
        };
        match t.active_timestamp() {
            Ok(ts) if env.active_timestamp() == Some(ts) => {}
            Ok(_) | Err(Error::NotFound) => add_unique(&mut list, ty::ACTIVE_DATASET),
            Err(e) => return Err(e),
        }
        match t.pending_timestamp() {
            Ok(ts) if env.pending_timestamp() == Some(ts) => {}
            Ok(_) | Err(Error::NotFound) => add_unique(&mut list, ty::PENDING_DATASET),
            Err(e) => return Err(e),
        }
        if list.len() > CHILD_MAX_REQUEST_TLVS {
            return Err(Error::Parse);
        }
        let nd_version = self.network_data_version_for(mode);
        let c = self.children.get_mut(idx).ok_or(Error::NotFound)?;
        if !mode.full_thread_device() {
            Self::process_address_registration(env, c, rx)?;
        }
        let was_valid = c.neighbor.is_valid();
        if was_valid && !c.neighbor.is_rx_on_when_idle() {
            env.indirect_remove_child(&c.neighbor.ext_address, c.neighbor.rloc16);
        }
        c.neighbor.state = NeighborState::ChildIdRequest;
        c.neighbor.connection_start = None;
        c.neighbor.last_heard = now;
        c.neighbor.link_counters = LinkFrameCounters::with(sec.key_sequence, link_fc);
        c.neighbor.mle_replay = MleReplay::with(mle_fc);
        c.neighbor.mode = mode;
        c.neighbor.version = version;
        if let Some(rss) = rx.meta.link.rss {
            c.neighbor.link_info.add_rss(env.noise_floor(), rss);
        }
        c.timeout_secs = timeout;
        c.supervision_interval = supervision;
        c.network_data_version = nd_version;
        c.set_request_tlvs(&list);
        if reed {
            // The child needs a router parent: ask for a router ID first;
            // the Child ID Response follows once it is granted.
            if self
                .become_router(env, now, RouterRequestReason::HaveChildIdRequest)
                .is_err()
            {
                self.remove_child(env, idx);
            }
            return Ok(RxClass::Authoritative);
        }
        self.send_child_id_response(env, now, idx)?;
        Ok(RxClass::Authoritative)
    }

    /// Allocate a child RLOC16 (OT `SendChildIdResponse`: next free child
    /// ID under our router ID).
    fn allocate_child_rloc(&mut self) -> Result<Rloc16> {
        for _ in 0..MAX_CHILD_ID {
            self.parent_side.next_child_id += 1;
            if self.parent_side.next_child_id > MAX_CHILD_ID {
                self.parent_side.next_child_id = 1;
            }
            let rloc = Rloc16::new(self.rloc16.router_id(), self.parent_side.next_child_id)?;
            if self
                .children
                .index_by_rloc(rloc, StateFilter::AnyExceptInvalid)
                .is_none()
            {
                return Ok(rloc);
            }
        }
        Err(Error::NoBufs)
    }

    /// OT `SendChildIdResponse`.
    pub(crate) fn send_child_id_response<E: MleEnv>(
        &mut self,
        env: &mut E,
        now: Instant,
        idx: usize,
    ) -> Result<()> {
        let cur = self
            .children
            .get(idx)
            .ok_or(Error::NotFound)?
            .neighbor
            .rloc16;
        let child_rloc = if cur == Rloc16::INVALID
            || cur.child_id() == 0
            || cur.router_id() != self.rloc16.router_id()
        {
            let r = self.allocate_child_rloc()?;
            if let Some(c) = self.children.get_mut(idx) {
                c.neighbor.rloc16 = r;
            }
            r
        } else {
            cur
        };
        let (ext, mode, requested, sup, addrs) = {
            let c = self.children.get(idx).ok_or(Error::NotFound)?;
            let mut entries = Vec::<AddressEntry, 10>::new();
            // The ML-EID is not echoed (OT `AppendAddressRegistrationTlv`).
            for a in c.addresses() {
                let e = match env.lowpan_context_for(a) {
                    Some(context_id) => AddressEntry::Compressed {
                        context_id,
                        iid: ipv6::iid(a).0,
                    },
                    None => AddressEntry::Uncompressed(*a),
                };
                let _ = entries.push(e);
            }
            for m in c.multicast_listeners() {
                let _ = entries.push(AddressEntry::Uncompressed(m.addr));
            }
            let mut req = Vec::<u8, CHILD_MAX_REQUEST_TLVS>::new();
            let _ = req.extend_from_slice(c.request_tlvs());
            (
                c.neighbor.ext_address,
                c.neighbor.mode,
                req,
                c.supervision_interval,
                entries,
            )
        };
        let rloc = self.rloc16;
        let leader = self.leader_data;
        let active_ts = env.active_timestamp();
        let pending_ts = env.pending_timestamp();
        let mut nd = [0u8; 400];
        let nd_len = env.network_data(!mode.full_network_data(), &mut nd)?;
        let mut active = [0u8; 256];
        let mut pending = [0u8; 256];
        let active_len = env.active_dataset(now, &mut active).unwrap_or(0);
        let pending_len = env.pending_dataset(now, &mut pending).unwrap_or(0);
        let route = self.parent_side.info.route64.clone();
        let dst = ipv6::link_local(&ext);
        self.send(env, dst, Command::ChildIdResponse, |w| {
            w.source_address(rloc)?;
            w.leader_data(&leader)?;
            if let Some(t) = &active_ts {
                w.active_timestamp(t)?;
            }
            if let Some(t) = &pending_ts {
                w.pending_timestamp(t)?;
            }
            w.address16(child_rloc)?;
            for &r in &requested {
                match r {
                    ty::NETWORK_DATA => w.network_data(&nd[..nd_len])?,
                    ty::ROUTE64 if !route.is_empty() => w.raw(ty::ROUTE64, &route)?,
                    ty::ACTIVE_DATASET if active_len > 0 => {
                        w.active_dataset(&active[..active_len])?;
                    }
                    ty::PENDING_DATASET if pending_len > 0 => {
                        w.pending_dataset(&pending[..pending_len])?;
                    }
                    ty::SUPERVISION_INTERVAL => w.supervision_interval(sup)?,
                    _ => {}
                }
            }
            if !mode.full_thread_device() {
                w.address_registration(&addrs)?;
            }
            Ok(())
        })?;
        self.child_to_valid(env, now, idx);
        Ok(())
    }

    // ------------------------------------------------------------ Child Update

    /// OT `SendChildUpdateRequestToChild`: sent to restored children (and
    /// when a child needs its Network Data version refreshed).
    pub fn send_child_update_request_to_child<E: MleEnv>(
        &mut self,
        env: &mut E,
        now: Instant,
        idx: usize,
    ) -> Result<()> {
        let _ = now;
        let c = self.children.get_mut(idx).ok_or(Error::NotFound)?;
        let valid = c.neighbor.is_valid();
        let ext = c.neighbor.ext_address;
        let mode = c.neighbor.mode;
        let margin_nf = env.noise_floor();
        let margin = c.neighbor.link_info.link_margin(margin_nf);
        let restored = c.neighbor.state == NeighborState::Restored;
        let mut challenge = c.neighbor.challenge;
        if !valid && !restored {
            env.fill_random(&mut challenge);
            c.neighbor.challenge = challenge;
        }
        c.network_data_version = if mode.full_network_data() {
            self.leader_data.data_version
        } else {
            self.leader_data.stable_data_version
        };
        let rloc = self.rloc16;
        let leader = self.leader_data;
        let active_ts = env.active_timestamp();
        let pending_ts = env.pending_timestamp();
        let mut nd = [0u8; 400];
        let nd_len = env.network_data(!mode.full_network_data(), &mut nd)?;
        let dst = ipv6::link_local(&ext);
        self.send(env, dst, Command::ChildUpdateRequest, |w| {
            w.source_address(rloc)?;
            w.leader_data(&leader)?;
            w.network_data(&nd[..nd_len])?;
            if let Some(t) = &active_ts {
                w.active_timestamp(t)?;
            }
            if let Some(t) = &pending_ts {
                w.pending_timestamp(t)?;
            }
            if valid {
                w.link_margin(margin)?;
            } else {
                w.tlv_request(&[ty::TIMEOUT, ty::ADDRESS_REGISTRATION])?;
                w.challenge(&challenge)?;
            }
            Ok(())
        })?;
        if let Some(c) = self.children.get_mut(idx) {
            if c.neighbor.state == NeighborState::Restored {
                c.neighbor.state = NeighborState::ChildUpdateRequest;
            }
        }
        Ok(())
    }

    /// OT `HandleChildUpdateRequestOnParent`.
    pub(crate) fn handle_child_update_request_on_parent<E: MleEnv>(
        &mut self,
        env: &mut E,
        now: Instant,
        rx: &MleRx<'_>,
    ) -> Result<RxClass> {
        let t = &rx.tlvs;
        let mode = t.mode()?;
        let mut list = Vec::<u8, 16>::new();
        let challenge = match t.challenge() {
            Ok(c) => {
                add_unique(&mut list, ty::RESPONSE);
                Some(c)
            }
            Err(Error::NotFound) => None,
            Err(e) => return Err(e),
        };
        add_unique(&mut list, ty::SOURCE_ADDRESS);
        let ext = rx.meta.sender_ext_address();
        let Some(idx) = self
            .children
            .index_by_ext(&ext, StateFilter::AnyExceptInvalid)
        else {
            if mode.rx_on_when_idle() {
                add_unique(&mut list, ty::STATUS);
                let _ = self.send_child_update_response_to_child(
                    env,
                    None,
                    &list,
                    challenge,
                    rx.meta.src,
                );
            }
            return Ok(RxClass::Unknown);
        };
        if !self
            .children
            .get(idx)
            .is_some_and(|c| c.neighbor.state.is_valid_or_restoring())
        {
            return Ok(RxClass::Unknown);
        }
        if let Some(c) = self.children.get_mut(idx) {
            c.confirmed = true;
        }
        add_unique(&mut list, ty::MODE);
        add_unique(&mut list, ty::LINK_MARGIN);
        add_unique(&mut list, ty::LEADER_DATA);
        if challenge.is_some() {
            add_unique(&mut list, ty::MLE_FRAME_COUNTER);
            add_unique(&mut list, ty::LINK_FRAME_COUNTER);
        }
        let mut changed = false;
        let nd_ver = t
            .leader_data()
            .map(|l| {
                if mode.full_network_data() {
                    l.data_version
                } else {
                    l.stable_data_version
                }
            })
            .ok();
        let timeout = match t.timeout() {
            Ok(v) => Some(v),
            Err(Error::NotFound) => None,
            Err(e) => return Err(e),
        };
        let sup = match t.supervision_interval() {
            Ok(s) => {
                add_unique(&mut list, ty::SUPERVISION_INTERVAL);
                Some(s)
            }
            Err(Error::NotFound) => None,
            Err(e) => return Err(e),
        };
        match t.tlv_request() {
            Ok(req) => {
                for &r in req {
                    add_unique(&mut list, r);
                }
            }
            Err(Error::NotFound) => {}
            Err(e) => return Err(e),
        }
        let csl_timeout = match t.csl_timeout() {
            Ok(v) => Some(v),
            Err(Error::NotFound) => None,
            Err(e) => return Err(e),
        };
        let csl_channel = t
            .csl_channel()
            .ok()
            .and_then(|c| u8::try_from(c.channel).ok());
        let noise = env.noise_floor();
        let c = self.children.get_mut(idx).ok_or(Error::NotFound)?;
        let old_mode = c.neighbor.mode;
        c.neighbor.mode = mode;
        // OT: CSL parameters are only taken from a child that is already
        // CSL synchronized (the request itself carried a CSL IE).
        if c.csl_synchronized {
            if let Some(secs) = csl_timeout {
                c.csl_timeout_secs = secs;
                // The answer must include our CSL accuracy.
                add_unique(&mut list, ty::CSL_CLOCK_ACCURACY);
            }
            if let Some(ch) = csl_channel {
                c.csl_channel = ch;
            }
        }
        match Self::process_address_registration(env, c, rx) {
            Ok(()) => add_unique(&mut list, ty::ADDRESS_REGISTRATION),
            Err(Error::NotFound) => {}
            Err(e) => return Err(e),
        }
        if let Some(v) = nd_ver {
            c.network_data_version = v;
        }
        if let Some(secs) = timeout {
            if c.timeout_secs != secs {
                c.timeout_secs = secs;
                changed = true;
            }
            add_unique(&mut list, ty::TIMEOUT);
        }
        c.supervision_interval = sup.unwrap_or(if c.neighbor.version <= THREAD_VERSION_1_3 {
            SUPERVISION_DEFAULT_FOR_OLDER_VERSION
        } else {
            0
        });
        if let Some(rss) = rx.meta.link.rss {
            c.neighbor.link_info.add_rss(noise, rss);
        }
        c.neighbor.last_heard = now;
        let (ext, rloc, new_rx_on) = (
            c.neighbor.ext_address,
            c.neighbor.rloc16,
            c.neighbor.is_rx_on_when_idle(),
        );
        let restoring = c.neighbor.state.is_restoring();
        #[cfg(feature = "csl")]
        let csl_update = c.csl_synchronized.then_some(c.csl_channel);
        if old_mode != mode {
            changed = true;
            #[cfg(feature = "csl")]
            if new_rx_on && c.csl_synchronized {
                c.csl_synchronized = false;
                env.csl_child_desync(&ext, rloc);
            }
            // OT IndirectSender::HandleChildModeChange.
            if !old_mode.rx_on_when_idle() && new_rx_on {
                env.indirect_remove_child(&ext, rloc);
            } else if old_mode.rx_on_when_idle() && !new_rx_on {
                env.indirect_add_child(&ext, rloc);
            }
        }
        #[cfg(feature = "csl")]
        if let Some(ch) = csl_update.filter(|_| !new_rx_on) {
            env.csl_child_update(&ext, rloc, ch);
        }
        if restoring {
            self.child_to_valid(env, now, idx);
        } else if changed {
            if let Some(c) = self.children.get(idx) {
                let _ = env.store_child_info(&c.to_child_info());
            }
        }
        self.send_child_update_response_to_child(env, Some(idx), &list, challenge, rx.meta.src)?;
        Ok(RxClass::Peer)
    }

    /// OT `SendChildUpdateResponseToChild`.
    fn send_child_update_response_to_child<E: MleEnv>(
        &mut self,
        env: &mut E,
        idx: Option<usize>,
        list: &[u8],
        challenge: Option<&[u8]>,
        dst: Ipv6Addr,
    ) -> Result<()> {
        let rloc = self.rloc16;
        let leader = self.leader_data;
        let link_fc = env.keys().frame_counter();
        let mle_fc = self.mle_counter.current_for(env.keys().key_epoch());
        let mut ch = [0u8; 8];
        let clen = challenge.map_or(0, |c| {
            let n = c.len().min(8);
            ch[..n].copy_from_slice(&c[..n]);
            n
        });
        let noise = env.noise_floor();
        #[cfg(feature = "csl")]
        let csl_accuracy = env.csl_clock_accuracy();
        #[cfg(not(feature = "csl"))]
        let _csl_accuracy: Option<crate::tlv::CslClockAccuracy> = None;
        let (mode, margin, timeout, sup, addrs) = match idx.and_then(|i| self.children.get(i)) {
            Some(c) => {
                let mut entries = Vec::<AddressEntry, 10>::new();
                // The ML-EID is not echoed (OT `AppendAddressRegistrationTlv`).
                for a in c.addresses() {
                    let _ = entries.push(match env.lowpan_context_for(a) {
                        Some(context_id) => AddressEntry::Compressed {
                            context_id,
                            iid: ipv6::iid(a).0,
                        },
                        None => AddressEntry::Uncompressed(*a),
                    });
                }
                for m in c.multicast_listeners() {
                    let _ = entries.push(AddressEntry::Uncompressed(m.addr));
                }
                (
                    c.neighbor.mode,
                    c.neighbor.link_info.link_margin(noise),
                    c.timeout_secs,
                    c.supervision_interval,
                    entries,
                )
            }
            None => (DeviceMode::default(), 0, 0, 0, Vec::new()),
        };
        let mut nd = [0u8; 400];
        let nd_len = if list.contains(&ty::NETWORK_DATA) {
            env.network_data(!mode.full_network_data(), &mut nd)?
        } else {
            0
        };
        self.send(env, dst, Command::ChildUpdateResponse, |w| {
            for &tlv in list {
                match tlv {
                    ty::SOURCE_ADDRESS => w.source_address(rloc)?,
                    ty::LEADER_DATA => w.leader_data(&leader)?,
                    ty::MODE => w.mode(mode)?,
                    ty::LINK_MARGIN => w.link_margin(margin)?,
                    ty::MLE_FRAME_COUNTER => w.mle_frame_counter(mle_fc)?,
                    ty::LINK_FRAME_COUNTER => w.link_frame_counter(link_fc)?,
                    ty::ADDRESS_REGISTRATION => w.address_registration(&addrs)?,
                    ty::TIMEOUT => w.timeout(timeout)?,
                    ty::SUPERVISION_INTERVAL => w.supervision_interval(sup)?,
                    ty::STATUS => w.status(crate::tlv::STATUS_ERROR)?,
                    ty::RESPONSE => w.response(&ch[..clen])?,
                    ty::NETWORK_DATA => w.network_data(&nd[..nd_len])?,
                    #[cfg(feature = "csl")]
                    ty::CSL_CLOCK_ACCURACY if !mode.rx_on_when_idle() => {
                        if let Some(a) = csl_accuracy {
                            w.csl_clock_accuracy(a)?;
                        }
                    }
                    _ => {}
                }
            }
            Ok(())
        })
    }

    /// OT `HandleChildUpdateResponseOnParent`.
    pub(crate) fn handle_child_update_response_on_parent<E: MleEnv>(
        &mut self,
        env: &mut E,
        now: Instant,
        rx: &MleRx<'_>,
        nb: Option<NbRef>,
    ) -> Result<RxClass> {
        let Some(NbRef::Child(idx)) = nb else {
            return Err(Error::NotFound);
        };
        let t = &rx.tlvs;
        let response = match t.response() {
            Ok(r) => Some(r),
            Err(Error::NotFound) => None,
            Err(e) => return Err(e),
        };
        {
            let c = self.children.get(idx).ok_or(Error::NotFound)?;
            match response {
                Some(r) => {
                    if c.neighbor.challenge[..] != *r {
                        return Err(Error::Security);
                    }
                }
                None => {
                    if !c.neighbor.is_valid() {
                        return Err(Error::Security);
                    }
                }
            }
        }
        match t.source_address() {
            Ok(s) => {
                if self.children.get(idx).map(|c| c.neighbor.rloc16) != Some(s) {
                    self.remove_child(env, idx);
                    return Ok(RxClass::Unknown);
                }
            }
            Err(Error::NotFound) => {}
            Err(e) => return Err(e),
        }
        match t.status() {
            Ok(s) if s == crate::tlv::STATUS_ERROR => {
                self.remove_child(env, idx);
                return Ok(RxClass::Unknown);
            }
            Ok(_) | Err(Error::NotFound) => {}
            Err(e) => return Err(e),
        }
        let sec = rx.meta.security.ok_or(Error::Security)?;
        let link_fc = t.link_frame_counter().ok();
        let mle_fc = t.mle_frame_counter().ok();
        let timeout = t.timeout().ok();
        let leader = t.leader_data().ok();
        let mut changed = false;
        {
            let c = self.children.get_mut(idx).ok_or(Error::NotFound)?;
            if let Some(f) = link_fc {
                c.neighbor.link_counters = LinkFrameCounters::with(sec.key_sequence, f);
            }
            if let Some(f) = mle_fc {
                c.neighbor.mle_replay = MleReplay::with(f);
            }
            if let Some(secs) = timeout {
                if c.timeout_secs != secs {
                    c.timeout_secs = secs;
                    changed = true;
                }
            }
            if let Some(l) = leader {
                c.network_data_version = if c.neighbor.mode.full_network_data() {
                    l.data_version
                } else {
                    l.stable_data_version
                };
            }
            match Self::process_address_registration(env, c, rx) {
                Ok(()) | Err(Error::NotFound) => {}
                Err(e) => return Err(e),
            }
            c.neighbor.last_heard = now;
        }
        let restoring = self
            .children
            .get(idx)
            .is_some_and(|c| c.neighbor.state.is_restoring());
        if restoring {
            self.child_to_valid(env, now, idx);
        } else if changed {
            if let Some(c) = self.children.get(idx) {
                let _ = env.store_child_info(&c.to_child_info());
            }
        }
        Ok(if response.is_some() {
            RxClass::Authoritative
        } else {
            RxClass::Peer
        })
    }

    // ------------------------------------------------------------ Data Request / Response

    /// OT `SendMulticastDataResponse`: the Network Data (full) with the
    /// Leader Data to the link-local all-nodes address, when it changed.
    pub(crate) fn send_multicast_data_response<E: MleEnv>(
        &mut self,
        env: &mut E,
        _now: Instant,
    ) -> Result<()> {
        if !self.role.is_attached() {
            return Err(Error::InvalidState);
        }
        let rloc = self.rloc16;
        let leader = self.leader_data;
        let (active_ts, pending_ts) = (env.active_timestamp(), env.pending_timestamp());
        let mut nd = [0u8; 400];
        let n = env.network_data(false, &mut nd)?;
        self.send(
            env,
            ipv6::LINK_LOCAL_ALL_NODES,
            Command::DataResponse,
            |w| {
                w.source_address(rloc)?;
                w.leader_data(&leader)?;
                // The timestamps let receivers notice a newer dataset.
                if let Some(t) = &active_ts {
                    w.active_timestamp(t)?;
                }
                if let Some(t) = &pending_ts {
                    w.pending_timestamp(t)?;
                }
                w.network_data(&nd[..n])
            },
        )
    }

    /// OT `HandleDataRequest` + `SendDataResponse` (unicast to a child).
    pub(crate) fn handle_data_request<E: MleEnv>(
        &mut self,
        env: &mut E,
        now: Instant,
        rx: &MleRx<'_>,
        nb: Option<NbRef>,
    ) -> Result<RxClass> {
        // Children and (neighboring) routers may ask for Network Data.
        let idx = match nb {
            Some(NbRef::Child(idx)) => Some(idx),
            Some(NbRef::Router(_)) => None,
            _ => return Err(Error::Security),
        };
        if !self.role.is_router_or_leader() || !self.neighbor_is_valid(nb) {
            return Err(Error::Security);
        }
        let t = &rx.tlvs;
        let mut list = Vec::<u8, 16>::new();
        for &r in t.tlv_request()? {
            add_unique(&mut list, r);
        }
        match t.active_timestamp() {
            Ok(ts) if env.active_timestamp() == Some(ts) => {}
            Ok(_) | Err(Error::NotFound) => add_unique(&mut list, ty::ACTIVE_DATASET),
            Err(e) => return Err(e),
        }
        match t.pending_timestamp() {
            Ok(ts) if env.pending_timestamp() == Some(ts) => {}
            Ok(_) | Err(Error::NotFound) => add_unique(&mut list, ty::PENDING_DATASET),
            Err(e) => return Err(e),
        }
        if let Some(sec) = rx.meta.security {
            self.process_key_sequence(env, now, RxClass::Peer, sec, nb);
        }
        let mode = match idx {
            Some(idx) => self.children.get(idx).ok_or(Error::NotFound)?.neighbor.mode,
            None => DeviceMode::new(true, true, true),
        };
        let ver = self.network_data_version_for(mode);
        if let Some(c) = idx.and_then(|i| self.children.get_mut(i)) {
            c.network_data_version = ver;
            c.neighbor.last_heard = now;
        }
        let rloc = self.rloc16;
        let leader = self.leader_data;
        let active_ts = env.active_timestamp();
        let pending_ts = env.pending_timestamp();
        let mut nd = [0u8; 400];
        let mut active = [0u8; 256];
        let mut pending = [0u8; 256];
        let nd_len = if list.contains(&ty::NETWORK_DATA) {
            env.network_data(!mode.full_network_data(), &mut nd)?
        } else {
            0
        };
        let active_len = env.active_dataset(now, &mut active).unwrap_or(0);
        let pending_len = env.pending_dataset(now, &mut pending).unwrap_or(0);
        let route = self.parent_side.info.route64.clone();
        #[cfg(feature = "link-metrics")]
        let mut lm = [0u8; 32];
        #[cfg(feature = "link-metrics")]
        let mut lm_len = 0usize;
        #[cfg(feature = "link-metrics")]
        if list.contains(&ty::LINK_METRICS_REPORT) {
            let query = t.link_metrics_query()?;
            let ext = rx.meta.sender_ext_address();
            lm_len = crate::link_metrics::report_for_query(
                &self.link_metrics,
                &ext,
                query.as_bytes(),
                rx.meta.link.lqi.unwrap_or(0),
                rx.meta
                    .link
                    .rss
                    .unwrap_or(crate::link_quality::INVALID_RSSI),
                env.noise_floor(),
                &mut lm,
            )?;
        }
        self.send(env, rx.meta.src, Command::DataResponse, |w| {
            w.source_address(rloc)?;
            w.leader_data(&leader)?;
            for &r in &list {
                match r {
                    ty::NETWORK_DATA => w.network_data(&nd[..nd_len])?,
                    ty::ROUTE64 if !route.is_empty() => w.raw(ty::ROUTE64, &route)?,
                    #[cfg(feature = "link-metrics")]
                    ty::LINK_METRICS_REPORT => w.link_metrics_report(&lm[..lm_len])?,
                    ty::ACTIVE_DATASET if active_len > 0 => {
                        if let Some(t) = &active_ts {
                            w.active_timestamp(t)?;
                        }
                        w.active_dataset(&active[..active_len])?;
                    }
                    ty::PENDING_DATASET if pending_len > 0 => {
                        if let Some(t) = &pending_ts {
                            w.pending_timestamp(t)?;
                        }
                        w.pending_dataset(&pending[..pending_len])?;
                    }
                    _ => {}
                }
            }
            Ok(())
        })?;
        Ok(RxClass::Peer)
    }

    /// Restore the child table from persisted [`ChildInfo`] records (OT
    /// `ChildTable::Restore`): children come back `Restored`, with
    /// `last_heard = now`, and receive a Child Update Request shortly after.
    pub(crate) fn restore_children_from<E: MleEnv>(&mut self, env: &mut E, now: Instant) {
        let mut i = 0;
        while let Some(info) = env.load_child_info(i) {
            i += 1;
            let ChildInfo { rloc16, .. } = info;
            if rloc16.router_id() != self.rloc16.router_id() {
                continue;
            }
            let c = Child::from_child_info(&info, now);
            if self.children.insert(c).is_err() {
                break;
            }
        }
        if self.children.has_children(StateFilter::AnyExceptInvalid) {
            self.parent_side.restored_update_due = Some(now);
        }
    }
}

fn min_opt(a: Option<Instant>, b: Option<Instant>) -> Option<Instant> {
    match (a, b) {
        (Some(x), Some(y)) => Some(x.min(y)),
        (x, None) => x,
        (None, y) => y,
    }
}

/// When the child times out (None while it is in `ChildIdRequest` state).
fn child_expiry(c: &Child) -> Option<Instant> {
    match c.neighbor.state {
        NeighborState::Invalid
        | NeighborState::ChildIdRequest
        | NeighborState::ParentResponse
        | NeighborState::LinkRequest => None,
        _ => Some(c.neighbor.last_heard.saturating_add(c.timeout())),
    }
}
