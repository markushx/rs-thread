//! The router and leader role (feature `ftd`; Thread 1.4.1 §5.9, §5.16,
//! §4.7; OpenThread `Mle::BecomeRouter`, `BecomeLeader`, `SetStateRouter`,
//! `SetStateLeader`, `HandleTimeTick`, `HandleAddressSolicitResponse`,
//! `RouterRoleTransition`, `FillConnectivityTlv`, `RouterTable`).
//!
//! ```text
//!            start                      no partition found
//! Disabled ---------> Detached --attach--------------------------> Leader
//!                        |  ^                                        ^  |
//!              Child ID  |  | parent lost                  new      |  |
//!              Response  v  |                        partition      |  |
//!                      Child (REED when FTD) --Address Solicit--> Router
//!                        ^                                          |
//!                        +------- downgrade (Attach DowngradeToReed)+
//! ```
//!
//! # Router IDs
//!
//! The leader owns the router ID space. The device that wants a router ID
//! (a REED, see below) cannot ask the leader itself: the Address Solicit
//! (`/a/as`) is a TMF/CoAP exchange (Phase 7). The core calls
//! [`MleEnv::request_router_id`] and later expects
//! [`Mle::address_solicit_reply`]. On the leader's side the TMF handler
//! calls [`Mle::handle_address_solicit`] / [`Mle::handle_address_release`],
//! which do the allocation (random free ID, preferring the requested one,
//! `ID_REUSE_DELAY`) and bump the ID sequence.
//!
//! # REED
//!
//! An FTD attached as a child is a REED. Once a second it checks (after a
//! random `ROUTER_SELECTION_JITTER` delay that restarts whenever its parent
//! advertises fewer than `ROUTER_UPGRADE_THRESHOLD` routers) whether it
//! should request the router role: fewer than `ROUTER_UPGRADE_THRESHOLD`
//! active routers and a neighbor with a good link margin. A Child ID Request
//! it receives also makes it ask for a router ID right away.
//!
//! # Deviations from OT
//!
//! - No "alternate RLOC16" after a REED becomes router (the former child
//!   address is not kept for forwarding; Phase 7 mesh forwarding).
//! - The security policy (`routers_enabled`, version threshold) is not
//!   evaluated in [`Mle::is_router_eligible`]; the caller turns
//!   `RouterConfig::eligible` off.
//! - No Border Router specific upgrade (`BorderRouterRequest`) and no
//!   reference-device router ID range.

use heapless::Vec;
use opentrust_core::time::{Duration, Instant};
use opentrust_core::types::{ExtAddress, Rloc16};
use opentrust_core::{Error, Result};

use crate::attach::AttachMode;
use crate::consts::{
    ADVERTISEMENT_I_MAX_PER_NEIGHBOR, ID_REUSE_DELAY_SECS, ID_SEQUENCE_PERIOD, INVALID_ROUTER_ID,
    LINK_REQUEST_MIN_MARGIN, MAX_ROUTE_COST, MAX_ROUTER_ID, MAX_ROUTERS,
};
use crate::env::{MleEnv, MleEvent, Role, RouterIdRequest, RouterRequestReason};
use crate::link_quality::LinkQuality;
use crate::mle::Mle;
use crate::neighbor::{NeighborState, Router, RouterTable, StateFilter};
use crate::tlv::{
    Connectivity, LeaderData, ParentPriority, Route64, RouteEntry, RouterIdMask, Tlvs,
};

/// Outcome of an Address Solicit, as delivered by the environment to
/// [`Mle::address_solicit_reply`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouterIdReply {
    /// The leader assigned a router ID (Status success, RLOC16 TLV, Router
    /// Mask TLV).
    Granted {
        /// The new RLOC16 (router ID, child ID 0).
        rloc16: Rloc16,
        /// Router ID sequence of the mask.
        id_sequence: u8,
        /// Assigned router IDs.
        mask: RouterIdMask,
    },
    /// The leader answered with a status other than success.
    Rejected,
    /// No answer (timeout, transport error).
    Failed,
}

/// A router ID granted by the leader (also the payload of the Address
/// Solicit response the TMF layer sends).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RouterIdGrant {
    /// Assigned RLOC16.
    pub rloc16: Rloc16,
    /// Router ID sequence number.
    pub id_sequence: u8,
    /// All currently assigned router IDs.
    pub mask: RouterIdMask,
}

/// Why the leader refused an Address Solicit (Status TLV of the response).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SolicitRejection {
    /// No router ID available, or the request is not justified
    /// (`NO_ADDRESS_AVAILABLE`).
    NoAddressAvailable,
    /// Unknown Status value (`UNRECOGNIZED_STATUS`).
    UnrecognizedStatus,
}

/// Router state inside [`Mle`].
#[derive(Debug)]
pub(crate) struct RouterCtx {
    /// The router state machine owns the parent-side data (router, leader
    /// or REED entered through it); `false` for tests that use
    /// [`Mle::enter_router_role`].
    pub managed: bool,
    pub table: RouterTable<MAX_ROUTERS>,
    pub allocated: RouterIdMask,
    /// Remaining reuse delay (seconds) per unallocated router ID.
    reuse: [u8; MAX_ROUTER_ID as usize + 1],
    pub id_sequence: u8,
    pub id_sequence_updated: Instant,
    /// Own router ID ([`INVALID_ROUTER_ID`] if none).
    pub router_id: u8,
    pub previous_router_id: u8,
    /// Per-second tick.
    pub tick: Option<Instant>,
    /// Seconds until the pending role transition check (0 = none pending).
    pub transition: u8,
    pub solicit_pending: bool,
    /// Partition we were last router in (OT `mPreviousPartitionIdRouter`).
    pub partition_id_router: u32,
    pub previous_partition_timeout: u8,
    pub previous_partition_id_sequence: u8,
    pub delayed: Vec<crate::router_link::Delayed, { crate::router_link::DELAYED_CAPACITY }>,
    pub restorer: crate::router_link::Restorer,
    /// Advertisement timer (Trickle for routers, plain for REEDs).
    pub advert: opentrust_core::trickle::Trickle,
}

impl RouterCtx {
    pub const fn new() -> Self {
        Self {
            managed: false,
            table: RouterTable::new(),
            allocated: RouterIdMask::new(),
            reuse: [0; MAX_ROUTER_ID as usize + 1],
            id_sequence: 0,
            id_sequence_updated: Instant::ZERO,
            router_id: INVALID_ROUTER_ID,
            previous_router_id: INVALID_ROUTER_ID,
            tick: None,
            transition: 0,
            solicit_pending: false,
            partition_id_router: 0,
            previous_partition_timeout: 0,
            previous_partition_id_sequence: 0,
            delayed: Vec::new(),
            restorer: crate::router_link::Restorer::new(),
            advert: crate::advert::initial_trickle(),
        }
    }
}

/// Update next hop and cost of `r`; `true` if something changed (OT
/// `Router::SetNextHopAndCost`).
fn set_next_hop_and_cost(r: &mut Router, next_hop: Option<u8>, cost: u8) -> bool {
    if r.next_hop == next_hop && r.cost == cost {
        return false;
    }
    r.next_hop = next_hop;
    r.cost = cost;
    true
}

fn set_next_hop_invalid(r: &mut Router) -> bool {
    set_next_hop_and_cost(r, None, 0)
}

impl<const C: usize> Mle<C> {
    // ------------------------------------------------------------ accessors

    /// The device may take the router role (OT `IsRouterEligible`, without
    /// the security policy).
    pub fn is_router_eligible(&self) -> bool {
        self.cfg.router.eligible && self.is_full_thread_device()
    }

    /// Change router eligibility. Becoming ineligible while router or
    /// leader detaches (OT `SetRouterEligible`).
    pub fn set_router_eligible<E: MleEnv>(&mut self, env: &mut E, now: Instant, eligible: bool) {
        self.cfg.router.eligible = eligible;
        if !eligible && self.role.is_router_or_leader() {
            self.become_detached(env, now);
        }
    }

    /// The router table (all routers of the partition, with links, next
    /// hops and costs).
    pub fn router_table(&self) -> &RouterTable<MAX_ROUTERS> {
        &self.rtr.table
    }

    /// Own router ID (router / leader).
    pub fn router_id(&self) -> Option<u8> {
        (self.rtr.router_id != INVALID_ROUTER_ID).then_some(self.rtr.router_id)
    }

    /// Router ID this device held last (asked for again on upgrade).
    pub fn previous_router_id(&self) -> Option<u8> {
        (self.rtr.previous_router_id != INVALID_ROUTER_ID).then_some(self.rtr.previous_router_id)
    }

    /// Prefer this router ID in the next Address Solicit / leader start
    /// (OT `SetPreferredRouterId`); only while detached or disabled.
    pub fn set_preferred_router_id(&mut self, id: u8) -> Result<()> {
        if !matches!(self.role, Role::Disabled | Role::Detached) {
            return Err(Error::InvalidState);
        }
        self.rtr.previous_router_id = id.min(INVALID_ROUTER_ID);
        Ok(())
    }

    /// Router ID sequence number.
    pub fn router_id_sequence(&self) -> u8 {
        self.rtr.id_sequence
    }

    /// Assigned router IDs.
    pub fn router_id_mask(&self) -> RouterIdMask {
        self.rtr.allocated
    }

    /// Number of active routers (assigned router IDs).
    pub fn active_router_count(&self) -> u8 {
        self.rtr.allocated.count() as u8
    }

    /// Time since the router ID sequence was last updated (OT
    /// `GetLeaderAge`); `None` without any router.
    pub fn leader_age(&self, now: Instant) -> Option<Duration> {
        (self.active_router_count() > 0)
            .then(|| now.saturating_duration_since(self.rtr.id_sequence_updated))
    }

    /// Router ID of the leader.
    pub fn leader_router_id(&self) -> u8 {
        self.leader_data.leader_router_id
    }

    /// RLOC16 of the leader.
    pub fn leader_rloc16(&self) -> Rloc16 {
        Rloc16::from_router_id(self.leader_data.leader_router_id).unwrap_or(Rloc16::INVALID)
    }

    /// `true` if attached, router eligible and at most one router is
    /// active (OT `IsSingleton`).
    pub fn is_singleton(&self) -> bool {
        if !(self.role.is_attached() && self.is_router_eligible()) {
            return true;
        }
        self.active_router_count() <= 1
    }

    pub(crate) fn has_rloc16(&self, r: Rloc16) -> bool {
        self.rloc16 == r
    }

    pub(crate) fn has_children_attaching(&self) -> bool {
        self.children.has_children(StateFilter::ValidOrAttaching)
    }

    pub(crate) fn remove_all_children<E: MleEnv>(&mut self, env: &mut E) {
        let all: Vec<usize, C> = self
            .children
            .iter_indexed(StateFilter::AnyExceptInvalid)
            .map(|(i, _)| i)
            .collect();
        for i in all {
            self.remove_child(env, i);
        }
    }

    // ------------------------------------------------------------ leader data / partition

    /// A partition change (OT `HandlePartitionChange`): the router table of
    /// the old partition is void and a pending Address Solicit is dropped.
    pub(crate) fn handle_partition_change<E: MleEnv>(&mut self, env: &mut E) {
        self.previous_partition_id = self.leader_data.partition_id;
        self.rtr.previous_partition_id_sequence = self.rtr.id_sequence;
        self.rtr.previous_partition_timeout = self.cfg.router.network_id_timeout_secs;
        self.rtr.solicit_pending = false;
        self.clear_router_table(env);
    }

    pub(crate) fn clear_router_table<E: MleEnv>(&mut self, env: &mut E) {
        self.clear_router_neighbors(env);
        self.rtr.table.clear();
        self.rtr.allocated = RouterIdMask::new();
        self.rtr.reuse = [0; MAX_ROUTER_ID as usize + 1];
        env.event(MleEvent::RouterTableChanged);
    }

    /// Mark all router links invalid (OT `RouterTable::ClearNeighbors`).
    pub(crate) fn clear_router_neighbors<E: MleEnv>(&mut self, env: &mut E) {
        for r in self.rtr.table.iter_mut(StateFilter::Any) {
            if r.neighbor.is_valid() {
                env.event(MleEvent::RouterRemoved {
                    ext: r.neighbor.ext_address,
                    rloc16: r.neighbor.rloc16,
                });
            }
            r.neighbor.state = NeighborState::Invalid;
            r.neighbor.connection_start = None;
        }
    }

    // ------------------------------------------------------------ Route64 on an FTD child

    /// OT `ProcessRouteTlv`: adopt the ID set; a router whose own ID is not
    /// in it any more detaches.
    pub(crate) fn process_route_tlv<E: MleEnv>(
        &mut self,
        env: &mut E,
        now: Instant,
        route: &Route64<'_>,
    ) -> Result<()> {
        self.update_router_id_set(env, now, route.id_sequence, &route.id_mask);
        if self.role == Role::Router && !self.rtr.allocated.contains(self.rtr.router_id) {
            self.become_detached(env, now);
            return Err(Error::Drop);
        }
        Ok(())
    }

    /// OT `RouterTable::UpdateRouterOnFtdChild`: the parent is the next hop
    /// towards every router it has a route to.
    pub(crate) fn update_router_on_ftd_child<E: MleEnv>(
        &mut self,
        env: &mut E,
        now: Instant,
        route: &Route64<'_>,
        parent_id: u8,
    ) {
        let mut changed = false;
        for (id, e) in route.entries() {
            if id == parent_id {
                continue;
            }
            let next = (e.cost != 0).then_some(parent_id);
            changed |= self.set_route(id, next, e.cost);
        }
        if changed {
            self.table_changed(env, now);
        }
    }

    /// OT `ReadAndProcessRouteTlvOnFtdChild`: for a message from our parent.
    pub(crate) fn read_and_process_route_on_ftd_child<E: MleEnv>(
        &mut self,
        env: &mut E,
        now: Instant,
        tlvs: &Tlvs<'_>,
        parent_id: u8,
    ) -> Result<()> {
        if !self.is_full_thread_device() {
            return Ok(());
        }
        match tlvs.route64() {
            Ok(route) => {
                self.process_route_tlv(env, now, &route)?;
                self.update_router_on_ftd_child(env, now, &route, parent_id);
                self.child.request_route_tlv = false;
                Ok(())
            }
            Err(Error::NotFound) => Ok(()),
            Err(_) => Err(Error::Parse),
        }
    }

    /// The router role ends (attach to another partition as a child).
    pub(crate) fn router_left_router_role<E: MleEnv>(&mut self, env: &mut E) {
        self.clear_router_neighbors(env);
        self.stop_advertising();
    }

    // ------------------------------------------------------------ router ID set

    fn add_router_entry(&mut self, id: u8, ext: ExtAddress, now: Instant) -> Result<()> {
        self.rtr.table.add(id, ext, now)?.next_hop = None;
        self.rtr.allocated.insert(id)?;
        self.rtr.reuse[usize::from(id)] = 0;
        Ok(())
    }

    fn remove_router_entry<E: MleEnv>(&mut self, env: &mut E, id: u8) {
        if let Some(r) = self.rtr.table.remove(id) {
            if r.neighbor.is_valid() {
                env.event(MleEvent::RouterRemoved {
                    ext: r.neighbor.ext_address,
                    rloc16: r.neighbor.rloc16,
                });
            }
        }
        self.rtr.allocated.remove(id);
        self.rtr.reuse[usize::from(id)] = ID_REUSE_DELAY_SECS;
    }

    /// OT `RouterTable::UpdateRouterIdSet`: adopt the router ID set of a
    /// Route64 / Router Mask TLV.
    pub(crate) fn update_router_id_set<E: MleEnv>(
        &mut self,
        env: &mut E,
        now: Instant,
        sequence: u8,
        mask: &RouterIdMask,
    ) {
        self.rtr.id_sequence = sequence;
        self.rtr.id_sequence_updated = now;
        let mut changed = false;
        for id in 0..=MAX_ROUTER_ID {
            if self.rtr.allocated.contains(id) && !mask.contains(id) {
                // The ID is gone: no next hop may point to it any more.
                self.remove_router_entry(env, id);
                for r in self.rtr.table.iter_mut(StateFilter::Any) {
                    if r.next_hop == Some(id) {
                        set_next_hop_invalid(r);
                    }
                }
                changed = true;
            }
        }
        for id in 0..=MAX_ROUTER_ID {
            if !self.rtr.allocated.contains(id)
                && mask.contains(id)
                && self.add_router_entry(id, ExtAddress([0; 8]), now).is_ok()
            {
                changed = true;
            }
        }
        if changed {
            self.table_changed(env, now);
            self.reset_advertise_interval(env, now);
        }
    }

    pub(crate) fn table_changed<E: MleEnv>(&mut self, env: &mut E, now: Instant) {
        env.event(MleEvent::RouterTableChanged);
        self.update_advertise_interval(env, now);
    }

    // ------------------------------------------------------------ link / route cost

    /// Link cost to router `id` (OT `RouterTable::GetLinkCost`).
    pub(crate) fn link_cost(&self, id: u8) -> u8 {
        match self.rtr.table.find_by_id(id) {
            Some(r) => self.link_cost_of(r),
            None => MAX_ROUTE_COST,
        }
    }

    fn link_cost_of(&self, r: &Router) -> u8 {
        if self.has_rloc16(r.neighbor.rloc16) || !r.neighbor.is_valid() {
            return MAX_ROUTE_COST;
        }
        r.neighbor.link_info.two_way_quality().cost()
    }

    /// Next hop and path cost towards `dest` (OT
    /// `RouterTable::GetNextHopAndPathCost`).
    pub fn next_hop_and_path_cost(&self, dest: Rloc16) -> (Option<Rloc16>, u8) {
        let mut next_hop = None;
        let mut cost = MAX_ROUTE_COST;
        if !self.role.is_attached() {
            return (next_hop, cost);
        }
        if self.has_rloc16(dest) {
            return (Some(dest), 0);
        }
        let router = self.rtr.table.find_by_id(dest.router_id());
        let hop = router.and_then(|r| r.next_hop.and_then(|h| self.rtr.table.find_by_id(h)));
        if self.role == Role::Child {
            let Some(parent) = &self.parent else {
                return (next_hop, cost);
            };
            let p = &parent.router.neighbor;
            if p.is_valid() {
                next_hop = Some(p.rloc16);
            }
            let dest_is_parent_or_sibling = dest.router_id() == p.rloc16.router_id();
            if !(dest_is_parent_or_sibling || hop.is_some()) {
                return (next_hop, cost);
            }
            cost = p.link_info.link_quality_in().cost();
            if !dest_is_parent_or_sibling {
                if let Some(r) = router {
                    cost = cost.saturating_add(r.cost);
                }
            }
        } else {
            if self.rtr.router_id == dest.router_id() {
                // One of our children.
                return match self
                    .children
                    .find_by_rloc(dest, StateFilter::AnyExceptInvalid)
                {
                    Some(c) => (Some(dest), c.neighbor.link_info.link_quality_in().cost()),
                    None => (None, MAX_ROUTE_COST),
                };
            }
            let Some(r) = router else {
                return (next_hop, cost);
            };
            cost = self.link_cost_of(r);
            if cost < MAX_ROUTE_COST {
                next_hop = Some(r.neighbor.rloc16);
            }
            if let Some(h) = hop {
                let via = r.cost.saturating_add(self.link_cost_of(h));
                if via < cost {
                    cost = via;
                    next_hop = Some(h.neighbor.rloc16);
                }
            }
        }
        if dest.child_id() != 0 {
            // A child: assume the best link between it and its parent.
            cost = cost.saturating_add(LinkQuality::Q3.cost());
        }
        (next_hop, cost)
    }

    /// Path cost towards `dest` ([`MAX_ROUTE_COST`] if unreachable).
    pub fn path_cost(&self, dest: Rloc16) -> u8 {
        self.next_hop_and_path_cost(dest).1
    }

    /// Path cost to the leader.
    pub fn path_cost_to_leader(&self) -> u8 {
        self.path_cost(self.leader_rloc16())
    }

    // ------------------------------------------------------------ Connectivity / Route64 content

    /// Connectivity TLV for Parent Responses (OT `FillConnectivityTlv`).
    pub(crate) fn fill_connectivity(&self) -> Connectivity {
        let max = C as u16;
        let n = self.children.count(StateFilter::Valid) as u16;
        let parent_priority = if max.saturating_sub(n) < max / 3 {
            ParentPriority::Low
        } else {
            ParentPriority::Medium
        };
        let mut c = Connectivity {
            parent_priority,
            ..Connectivity::default()
        };
        if self.role == Role::Child {
            if let Some(p) = &self.parent {
                c.increment_link_quality(p.router.neighbor.link_info.link_quality_in());
            }
        }
        for r in self.rtr.table.iter(StateFilter::Valid) {
            if self.has_rloc16(r.neighbor.rloc16) {
                continue;
            }
            c.increment_link_quality(r.neighbor.link_info.two_way_quality());
        }
        c.active_routers = self.active_router_count();
        c.leader_cost = self.path_cost_to_leader().min(MAX_ROUTE_COST);
        c.id_sequence = self.rtr.id_sequence;
        c.sed_buffer_size = Some(1280);
        c.sed_datagram_count = Some(1);
        c
    }

    /// Route data for the Route64 TLV: sequence, mask and one entry per
    /// router. With `for_neighbor` (a Link Accept to a router) the TLV is
    /// truncated like OT `FillRouteTlv`.
    pub(crate) fn fill_route64(
        &self,
        for_neighbor: Option<u8>,
    ) -> (u8, RouterIdMask, Vec<RouteEntry, MAX_ROUTERS>) {
        let mut sequence = self.rtr.id_sequence;
        let mut mask = self.rtr.allocated;
        if let Some(nid) = for_neighbor {
            let mut count = mask.count();
            if count > crate::consts::MAX_ROUTERS_IN_LINK_ACCEPT_ROUTE {
                for id in 0..=MAX_ROUTER_ID {
                    if count <= crate::consts::MAX_ROUTERS_IN_LINK_ACCEPT_ROUTE {
                        break;
                    }
                    if id == self.rtr.router_id
                        || id == nid
                        || id == self.leader_data.leader_router_id
                    {
                        continue;
                    }
                    if mask.contains(id) {
                        mask.remove(id);
                        count -= 1;
                    }
                }
                sequence = sequence.wrapping_sub(crate::consts::LINK_ACCEPT_SEQUENCE_ROLLBACK);
            }
        }
        let mut entries = Vec::new();
        for id in mask.iter() {
            let e = if id == self.rtr.router_id {
                RouteEntry {
                    link_quality_out: LinkQuality::Q0,
                    link_quality_in: LinkQuality::Q0,
                    cost: 1,
                }
            } else {
                let r = self.rtr.table.find_by_id(id);
                let rloc = Rloc16::from_router_id(id).unwrap_or(Rloc16::INVALID);
                let mut cost = self.path_cost(rloc);
                if cost >= MAX_ROUTE_COST {
                    cost = 0;
                }
                RouteEntry {
                    link_quality_in: r
                        .map_or(LinkQuality::Q0, |r| r.neighbor.link_info.link_quality_in()),
                    link_quality_out: r
                        .map_or(LinkQuality::Q0, |r| r.neighbor.link_info.link_quality_out()),
                    cost,
                }
            };
            let _ = entries.push(e);
        }
        (sequence, mask, entries)
    }

    /// Route64 TLV *value* (for Child ID / Data Response).
    pub(crate) fn route64_value(&self) -> Vec<u8, 72> {
        let (seq, mask, entries) = self.fill_route64(None);
        let mut v = Vec::new();
        let _ = v.push(seq);
        let _ = v.extend_from_slice(&mask.0);
        for e in &entries {
            let _ = v.push(e.to_byte());
        }
        v
    }

    /// Recompute what the parent-side code sends from the live router state.
    pub(crate) fn refresh_router_info(&mut self) {
        if !self.rtr.managed {
            return;
        }
        let conn = self.fill_connectivity();
        let accepting = self.role.is_router_or_leader() || self.role == Role::Child;
        let route = if self.role.is_router_or_leader() {
            self.route64_value()
        } else {
            Vec::new()
        };
        let info = &mut self.parent_side.info;
        info.connectivity = conn;
        info.route64 = route;
        info.accepting_children = accepting;
    }

    // ------------------------------------------------------------ role transitions

    /// Start a new partition as its leader (OT `BecomeLeader`). With
    /// `check_weight` and an attached device the call fails unless the local
    /// leader weight beats the current partition's. The caller must only
    /// start Thread with a complete Active Operational Dataset.
    pub fn become_leader<E: MleEnv>(
        &mut self,
        env: &mut E,
        now: Instant,
        check_weight: bool,
    ) -> Result<()> {
        if self.role == Role::Disabled {
            return Err(Error::InvalidState);
        }
        if self.role == Role::Leader {
            return Ok(());
        }
        if !self.is_router_eligible() {
            return Err(Error::InvalidState);
        }
        if check_weight
            && self.role.is_attached()
            && self.cfg.router.leader_weight <= self.leader_data.weighting
        {
            return Err(Error::InvalidState);
        }
        self.clear_router_table(env);
        let partition_id = {
            let mut b = [0u8; 4];
            env.fill_random(&mut b);
            u32::from_le_bytes(b)
        };
        let leader_id = if self.rtr.previous_router_id <= MAX_ROUTER_ID {
            self.rtr.previous_router_id
        } else {
            Self::rand_range(env, 0, u32::from(MAX_ROUTER_ID) + 1) as u8
        };
        let mut v = [0u8; 2];
        env.fill_random(&mut v);
        let ld = LeaderData {
            partition_id,
            weighting: self.cfg.router.leader_weight,
            data_version: v[0],
            stable_data_version: v[1],
            leader_router_id: leader_id,
        };
        self.update_leader_data(env, ld);
        let ext = env.ext_address();
        self.add_router_entry(leader_id, ext, now)?;
        self.rtr.id_sequence = self.rtr.id_sequence.wrapping_add(1);
        self.rtr.id_sequence_updated = now;
        self.set_router_id(leader_id);
        env.set_network_data(&ld, &[]);
        let rloc = Rloc16::from_router_id(leader_id)?;
        self.set_state_router_or_leader(env, now, Role::Leader, rloc);
        env.event(MleEvent::LeaderStarted { partition_id });
        Ok(())
    }

    fn set_router_id(&mut self, id: u8) {
        self.rtr.router_id = id;
        self.rtr.previous_router_id = id;
    }

    /// OT `SetStateRouterOrLeader`.
    pub(crate) fn set_state_router_or_leader<E: MleEnv>(
        &mut self,
        env: &mut E,
        now: Instant,
        role: Role,
        rloc16: Rloc16,
    ) {
        self.parent = None;
        env.set_parent(None);
        env.set_poll_period(None);
        env.set_rx_on_when_idle(true);
        self.set_rloc16(env, rloc16);
        self.set_role(env, role);
        self.attach.reset();
        self.attach.counter = 0;
        self.child.reset();
        self.rtr.managed = true;
        self.rtr.partition_id_router = self.leader_data.partition_id;
        self.rtr.tick = Some(now.saturating_add(Duration::from_secs(1)));
        self.parent_side.tick = Some(now.saturating_add(Duration::from_secs(1)));
        self.router_role_entered(env, now);
        // Children that do not belong to our router ID.
        let stale: Vec<usize, C> = self
            .children
            .iter_indexed(StateFilter::ValidOrRestoring)
            .filter(|(_, c)| c.neighbor.rloc16.router_id() != self.rtr.router_id)
            .map(|(i, _)| i)
            .collect();
        for i in stale {
            self.remove_child(env, i);
        }
        self.refresh_router_info();
    }

    /// OT `BecomeRouter`: ask the leader for a router ID (REED) or restore
    /// the router role after a reset (detached).
    pub fn become_router<E: MleEnv>(
        &mut self,
        env: &mut E,
        now: Instant,
        reason: RouterRequestReason,
    ) -> Result<()> {
        let _ = now;
        if self.role == Role::Disabled {
            return Err(Error::InvalidState);
        }
        if self.role.is_router_or_leader() {
            return Ok(());
        }
        if !self.is_router_eligible() {
            return Err(Error::InvalidState);
        }
        env.set_rx_on_when_idle(true);
        self.rtr.transition = 0;
        match self.role {
            Role::Child => self.send_address_solicit(env, reason),
            _ => Err(Error::InvalidState),
        }
    }

    fn send_address_solicit<E: MleEnv>(
        &mut self,
        env: &mut E,
        reason: RouterRequestReason,
    ) -> Result<()> {
        if self.rtr.solicit_pending {
            return Ok(());
        }
        let req = RouterIdRequest {
            previous_router_id: self.previous_router_id(),
            reason,
        };
        env.request_router_id(&req)?;
        self.rtr.solicit_pending = true;
        Ok(())
    }

    /// `true` while an Address Solicit is outstanding.
    pub fn is_address_solicit_pending(&self) -> bool {
        self.rtr.solicit_pending
    }

    /// The answer to [`MleEnv::request_router_id`] (OT
    /// `HandleAddressSolicitResponse`).
    pub fn address_solicit_reply<E: MleEnv>(
        &mut self,
        env: &mut E,
        now: Instant,
        reply: RouterIdReply,
    ) {
        if !self.rtr.solicit_pending {
            return;
        }
        self.rtr.solicit_pending = false;
        match reply {
            RouterIdReply::Failed => self.drop_children_waiting_for_router(env),
            RouterIdReply::Rejected => {
                if self.previous_router_id().is_some() {
                    self.remove_all_children(env);
                    self.set_router_id(INVALID_ROUTER_ID);
                }
                self.drop_children_waiting_for_router(env);
            }
            RouterIdReply::Granted {
                rloc16,
                id_sequence,
                mask,
            } => {
                if self.role != Role::Child || !mask.contains(rloc16.router_id()) {
                    return;
                }
                let parent = self.parent.clone();
                let id = rloc16.router_id();
                self.set_router_id(id);
                self.set_state_router_or_leader(env, now, Role::Router, rloc16);
                self.clear_router_neighbors(env);
                self.update_router_id_set(env, now, id_sequence, &mask);
                let ext = env.ext_address();
                if let Some(r) = self.rtr.table.find_by_id_mut(id) {
                    r.neighbor.ext_address = ext;
                    set_next_hop_invalid(r);
                }
                // Our former parent is a neighboring router now.
                if let Some(p) = parent {
                    let pid = p.router.neighbor.rloc16.router_id();
                    if let Some(r) = self.rtr.table.find_by_id_mut(pid) {
                        r.neighbor = p.router.neighbor.clone();
                        r.neighbor.state = NeighborState::Valid;
                        set_next_hop_invalid(r);
                        env.event(MleEvent::RouterAdded {
                            ext: r.neighbor.ext_address,
                            rloc16: r.neighbor.rloc16,
                        });
                    }
                    if self.path_cost_to_leader() >= MAX_ROUTE_COST {
                        let lid = self.leader_data.leader_router_id;
                        if let Some(l) = self.rtr.table.find_by_id_mut(lid) {
                            set_next_hop_and_cost(l, Some(pid), p.leader_cost);
                        }
                    }
                    self.router_became_from_child(env, now, &p);
                }
                self.table_changed(env, now);
                self.refresh_router_info();
                // Children waiting for a router parent.
                let waiting: Vec<usize, C> = self
                    .children
                    .iter_indexed(StateFilter::ChildIdRequest)
                    .map(|(i, _)| i)
                    .collect();
                for i in waiting {
                    let _ = self.send_child_id_response(env, now, i);
                }
            }
        }
    }

    /// Children that sent a Child ID Request to this REED cannot be served
    /// without a router role: forget them so they attach elsewhere.
    fn drop_children_waiting_for_router<E: MleEnv>(&mut self, env: &mut E) {
        let waiting: Vec<usize, C> = self
            .children
            .iter_indexed(StateFilter::ChildIdRequest)
            .map(|(i, _)| i)
            .collect();
        for i in waiting {
            self.remove_child(env, i);
        }
    }

    // ------------------------------------------------------------ leader side of the router ID exchange

    /// Pick and assign a router ID (OT `RouterTable::Allocate`): the
    /// `requested` one if it is free, otherwise a random free one.
    fn allocate_router_id<E: MleEnv>(
        &mut self,
        env: &mut E,
        now: Instant,
        requested: Option<u8>,
        ext: ExtAddress,
    ) -> Result<u8> {
        if self.rtr.table.count(StateFilter::Any) >= MAX_ROUTERS {
            return Err(Error::NoBufs);
        }
        let can =
            |s: &Self, id: u8| !s.rtr.allocated.contains(id) && s.rtr.reuse[usize::from(id)] == 0;
        let id = match requested.filter(|&id| id <= MAX_ROUTER_ID && can(self, id)) {
            Some(id) => id,
            None => {
                // Reservoir sampling over the free IDs.
                let mut chosen = None;
                let mut n = 0u32;
                for id in 0..=MAX_ROUTER_ID {
                    if can(self, id) {
                        n += 1;
                        if Self::rand_range(env, 0, n) == 0 {
                            chosen = Some(id);
                        }
                    }
                }
                chosen.ok_or(Error::NoBufs)?
            }
        };
        self.add_router_entry(id, ext, now)?;
        if let Some(r) = self.rtr.table.find_by_id_mut(id) {
            r.neighbor.last_heard = now;
        }
        self.rtr.id_sequence = self.rtr.id_sequence.wrapping_add(1);
        self.rtr.id_sequence_updated = now;
        self.table_changed(env, now);
        self.reset_advertise_interval(env, now);
        Ok(id)
    }

    /// Leader side of the Address Solicit (`/a/as`, OT
    /// `HandleTmf<kUriAddressSolicit>`): `ext` is the requester's
    /// ML-EUI64, `previous` its previous RLOC16 and `status` the Status TLV
    /// value. The TMF layer builds the response from the result.
    pub fn handle_address_solicit<E: MleEnv>(
        &mut self,
        env: &mut E,
        now: Instant,
        ext: ExtAddress,
        previous: Option<Rloc16>,
        status: u8,
    ) -> core::result::Result<RouterIdGrant, SolicitRejection> {
        if self.role != Role::Leader {
            return Err(SolicitRejection::NoAddressAvailable);
        }
        let grant = |s: &Self, id: u8| RouterIdGrant {
            rloc16: Rloc16::from_router_id(id).unwrap_or(Rloc16::INVALID),
            id_sequence: s.rtr.id_sequence,
            mask: s.rtr.allocated,
        };
        // A known router gets its ID again.
        if let Some(r) = self
            .rtr
            .table
            .iter(StateFilter::Any)
            .find(|r| r.neighbor.ext_address == ext)
        {
            let id = r.router_id;
            return Ok(grant(self, id));
        }
        let Some(reason) = RouterRequestReason::from_u8(status) else {
            return Err(SolicitRejection::UnrecognizedStatus);
        };
        if reason == RouterRequestReason::TooFewRouters
            && self.active_router_count() >= self.cfg.router.upgrade_threshold
        {
            return Err(SolicitRejection::NoAddressAvailable);
        }
        let id = self
            .allocate_router_id(env, now, previous.map(Rloc16::router_id), ext)
            .map_err(|_| SolicitRejection::NoAddressAvailable)?;
        Ok(grant(self, id))
    }

    /// Leader side of the Address Release (`/a/ar`): free the router ID of
    /// `rloc16` if `ext` is its holder.
    pub fn handle_address_release<E: MleEnv>(
        &mut self,
        env: &mut E,
        now: Instant,
        rloc16: Rloc16,
        ext: ExtAddress,
    ) -> Result<()> {
        let id = rloc16.router_id();
        match self.rtr.table.find_by_id(id) {
            Some(r) if r.neighbor.ext_address == ext => self.release_router_id(env, now, id),
            _ => Err(Error::NotFound),
        }
    }

    /// Free router ID `id` (leader only; OT `RouterTable::Release`).
    pub fn release_router_id<E: MleEnv>(
        &mut self,
        env: &mut E,
        now: Instant,
        id: u8,
    ) -> Result<()> {
        if self.role != Role::Leader {
            return Err(Error::InvalidState);
        }
        if self.rtr.table.find_by_id(id).is_none() {
            return Err(Error::NotFound);
        }
        self.remove_router_entry(env, id);
        for r in self.rtr.table.iter_mut(StateFilter::Any) {
            if r.next_hop == Some(id) {
                set_next_hop_invalid(r);
            }
        }
        self.rtr.id_sequence = self.rtr.id_sequence.wrapping_add(1);
        self.rtr.id_sequence_updated = now;
        self.table_changed(env, now);
        self.reset_advertise_interval(env, now);
        Ok(())
    }

    // ------------------------------------------------------------ REED / role transition timer

    /// OT `HandleChildStart`: an FTD became a child.
    pub(crate) fn handle_child_start<E: MleEnv>(&mut self, env: &mut E, now: Instant) {
        if !self.is_full_thread_device() {
            return;
        }
        self.rtr.managed = true;
        self.start_role_transition(env);
        self.stop_advertising();
        self.rtr.tick = Some(now.saturating_add(Duration::from_secs(1)));
        if self.previous_router_id().is_some() && self.is_router_eligible() {
            let has_children = self.has_children_attaching();
            match self.attach.mode {
                AttachMode::DowngradeToReed => {
                    if let Some(id) = self.previous_router_id() {
                        env.release_router_id(
                            Rloc16::from_router_id(id).unwrap_or(Rloc16::INVALID),
                        );
                    }
                    self.remove_all_children(env);
                    self.set_router_id(INVALID_ROUTER_ID);
                }
                AttachMode::SamePartition => {
                    if has_children {
                        let _ =
                            self.become_router(env, now, RouterRequestReason::HaveChildIdRequest);
                    }
                }
                _ => {
                    if has_children && self.rtr.partition_id_router != self.leader_data.partition_id
                    {
                        let _ = self.become_router(
                            env,
                            now,
                            RouterRequestReason::ParentPartitionChange,
                        );
                    }
                }
            }
        }
        if self.active_router_count() >= self.cfg.router.upgrade_threshold
            && (self.previous_router_id().is_none() || !self.has_children_attaching())
        {
            self.set_router_id(INVALID_ROUTER_ID);
        }
        self.refresh_router_info();
    }

    /// OT `RouterRoleTransition::StartTimeout`: 1 + random(0, jitter) seconds.
    pub(crate) fn start_role_transition<E: MleEnv>(&mut self, env: &mut E) {
        let j = Self::rand_range(env, 0, u32::from(self.cfg.router.selection_jitter_secs)) as u8;
        self.rtr.transition = 1 + j;
    }

    /// Forget the router state when leaving the attached state.
    pub(crate) fn router_reset_on_detach<E: MleEnv>(&mut self, env: &mut E) {
        self.clear_router_neighbors(env);
        self.rtr.tick = None;
        self.rtr.transition = 0;
        self.rtr.solicit_pending = false;
        self.rtr.managed = false;
        self.rtr.delayed.clear();
        self.stop_advertising();
    }

    // ------------------------------------------------------------ per-second tick

    pub(crate) fn router_deadline(&self) -> Option<Instant> {
        [
            self.rtr.tick,
            self.router_link_deadline(),
            self.advert_deadline(),
        ]
        .into_iter()
        .flatten()
        .min()
    }

    /// OT `HandleTimeTick` for the router / REED parts (child timeouts live
    /// in `poll_parent`).
    pub(crate) fn router_tick<E: MleEnv>(&mut self, env: &mut E, now: Instant) {
        if !self.is_full_thread_device() || !self.role.is_attached() {
            self.rtr.tick = None;
            return;
        }
        self.rtr.tick = Some(now.saturating_add(Duration::from_secs(1)));
        if self.rtr.previous_partition_timeout > 0 {
            self.rtr.previous_partition_timeout -= 1;
        }
        let mut expired = false;
        if self.rtr.transition > 0 {
            self.rtr.transition -= 1;
            expired = self.rtr.transition == 0;
        }
        let mut skip_tables = false;
        let mut check_leader = true;
        if self.role == Role::Child && expired {
            skip_tables = true;
            check_leader = false;
            if self.active_router_count() < self.cfg.router.upgrade_threshold
                && self.has_neighbor_with_good_link_quality(env)
            {
                let _ = self.become_router(env, now, RouterRequestReason::TooFewRouters);
            }
            self.start_reed_advertising(env, now);
        }
        if check_leader && matches!(self.role, Role::Child | Role::Router) {
            let timeout = Duration::from_secs(u64::from(self.cfg.router.network_id_timeout_secs));
            if self.leader_age(now).is_some_and(|a| a >= timeout) {
                self.attach_begin(env, now, AttachMode::SamePartition);
            }
            if expired && self.active_router_count() > self.cfg.router.downgrade_threshold {
                self.attach_begin(env, now, AttachMode::DowngradeToReed);
            }
        }
        if !skip_tables {
            if expired && !self.is_router_eligible() && self.role.is_attached() {
                self.become_detached(env, now);
                return;
            }
            self.router_table_tick(env, now);
        }
    }

    /// OT `Mle::HasNeighborWithGoodLinkQuality`.
    fn has_neighbor_with_good_link_quality<E: MleEnv>(&self, env: &E) -> bool {
        let nf = env.noise_floor();
        let good = |n: &crate::neighbor::Neighbor| {
            crate::link_quality::compute_link_margin(nf, n.link_info.last_rss())
                >= LINK_REQUEST_MIN_MARGIN
        };
        if self
            .parent
            .as_ref()
            .is_some_and(|p| good(&p.router.neighbor))
        {
            return true;
        }
        self.rtr
            .table
            .iter(StateFilter::Valid)
            .any(|r| good(&r.neighbor))
    }

    /// Router table maintenance (OT `HandleTimeTick` "Update RouterTable"
    /// and `RouterTable::HandleTimeTick`).
    fn router_table_tick<E: MleEnv>(&mut self, env: &mut E, now: Instant) {
        self.router_neighbors_tick(env, now);
        for r in self.rtr.reuse.iter_mut() {
            if *r > 0 {
                *r -= 1;
            }
        }
        if self.role == Role::Leader
            && now.saturating_duration_since(self.rtr.id_sequence_updated) >= ID_SEQUENCE_PERIOD
        {
            self.rtr.id_sequence = self.rtr.id_sequence.wrapping_add(1);
            self.rtr.id_sequence_updated = now;
        }
    }

    /// Advertisement interval maximum from the neighbor count (OT
    /// `DetermineAdvertiseIntervalMax`).
    pub(crate) fn advertise_interval_max(&self) -> Duration {
        let n = self
            .rtr
            .table
            .iter(StateFilter::Valid)
            .filter(|r| r.neighbor.link_info.link_quality_in() >= LinkQuality::Q2)
            .count() as u64;
        let i = ADVERTISEMENT_I_MAX_PER_NEIGHBOR.saturating_mul(n + 1);
        i.max(crate::consts::ADVERTISEMENT_I_MAX_LOW)
            .min(crate::consts::ADVERTISEMENT_I_MAX)
    }

    /// Set the next hop and cost of a router (shared with the routing code).
    pub(crate) fn set_route(&mut self, id: u8, next: Option<u8>, cost: u8) -> bool {
        self.rtr
            .table
            .find_by_id_mut(id)
            .is_some_and(|r| set_next_hop_and_cost(r, next, cost))
    }

    /// Resolve a 2-hop routing loop (OT `MeshForwarder::ResolveRoutingLoops`):
    /// a frame for `dest` arrived from `from`, which is the next hop towards
    /// `dest`. The route to `dest` is invalidated and the Advertisement
    /// interval reset so that the routers converge again.
    pub fn resolve_routing_loop<E: MleEnv>(
        &mut self,
        env: &mut E,
        now: Instant,
        from: Rloc16,
        dest: Rloc16,
    ) {
        if self.next_hop_and_path_cost(dest).0 != Some(from) || self.has_rloc16(dest) {
            return;
        }
        if self.invalidate_route(dest.router_id()) {
            self.table_changed(env, now);
        }
        self.reset_advertise_interval(env, now);
    }

    pub(crate) fn invalidate_route(&mut self, id: u8) -> bool {
        self.rtr
            .table
            .find_by_id_mut(id)
            .is_some_and(set_next_hop_invalid)
    }
}
