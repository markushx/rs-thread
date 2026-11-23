//! Router links (feature `ftd`; Thread 1.4.1 §4.7, §4.6.3; OpenThread
//! `Mle::SendLinkRequest`, `HandleLinkRequest`, `SendLinkAccept`,
//! `HandleLinkAccept(AndRequest)`, `RouterTable::UpdateRoutes`,
//! `RouterRoleRestorer`, the router part of `HandleTimeTick`).
//!
//! ```text
//!  A                                B
//!  |--- Link Request (challenge a) -->|   multicast: B answers after 1..1000 ms
//!  |<-- Link Accept And Request ------|   response a, counters, margin, B's
//!  |       (response a, challenge b)  |   challenge b; B: A is in LinkRequest
//!  |--- Link Accept (response b) ---->|   A and B are Valid neighbors
//! ```
//!
//! A router sends a unicast Link Request to a router it hears advertise
//! (see [`advert`](crate::advert)), re-sends one when the neighbor has been
//! silent for `MAX_NEIGHBOR_AGE`, and removes it if no Link Accept arrives
//! within 3 s. A router that was reset restores its role with a multicast
//! Link Request asking for Address16 and Route64 (the "router role
//! restorer"); an accepting neighbor's Link Accept carries both.
//!
//! Link quality: the incoming quality of a neighbor comes from our RSS
//! measurements, the outgoing one from the neighbor's Route64 entry for our
//! router ID; the link cost uses the two-way minimum.

use heapless::Vec;
use rs_thread_core::time::{Duration, Instant};
use rs_thread_core::types::{ExtAddress, Rloc16, ipv6};
use rs_thread_core::{Error, Result};
use rs_thread_mac::security::LinkFrameCounters;

use crate::consts::{
    LINK_ACCEPT_TIMEOUT_SECS, LINK_REQUEST_TIMEOUT, MAX_ROUTE_COST, MAX_ROUTER_ID, MAX_ROUTERS,
    MIN_CRITICAL_CHILDREN_COUNT, MULTICAST_RETRANSMISSION_DELAY, THREAD_VERSION_1_3,
};
use crate::endpoint::MleRx;
use crate::env::{MleEnv, MleEvent, Role};
use crate::link_quality::{LinkQuality, compute_link_margin};
use crate::message::Command;
use crate::mle::{Mle, NbRef, RxClass};
use crate::neighbor::{MleReplay, Neighbor, NeighborState, Parent, StateFilter};
use crate::tlv::{DeviceMode, Route64, ty};

/// What a delayed Link Accept needs (OT `LinkAcceptInfo`).
#[derive(Debug, Clone)]
pub(crate) struct LinkAcceptInfo {
    pub ext: ExtAddress,
    pub challenge: [u8; 8],
    pub challenge_len: usize,
    pub requested: Vec<u8, 4>,
    pub link_margin: u8,
}

/// A message waiting for its random delay (OT `DelayedSender`).
#[derive(Debug, Clone)]
pub(crate) enum DelayedKind {
    LinkRequest(u8),
    LinkAccept(LinkAcceptInfo),
    Advertisement(core::net::Ipv6Addr),
    DataRequest(core::net::Ipv6Addr),
    /// Unsolicited Data Response to the link-local all-nodes address.
    MulticastDataResponse,
}

#[derive(Debug, Clone)]
pub(crate) struct Delayed {
    pub due: Instant,
    pub kind: DelayedKind,
}

/// Router role restore after a reset (OT `RouterRoleRestorer`).
#[derive(Debug)]
pub(crate) struct Restorer {
    pub active: bool,
    pub attempts: u8,
    pub challenge: [u8; 8],
    pub deadline: Option<Instant>,
}

impl Restorer {
    pub const fn new() -> Self {
        Self {
            active: false,
            attempts: 0,
            challenge: [0; 8],
            deadline: None,
        }
    }
}

/// Capacity of the delayed-message queue.
pub(crate) const DELAYED_CAPACITY: usize = 12;

/// Reset a router entry for a (new) link with `ext`, keeping the routing
/// data (OT `InitNeighbor`).
fn init_router_neighbor(
    n: &mut Neighbor,
    ext: ExtAddress,
    rloc16: Rloc16,
    noise_floor: i8,
    rss: Option<i8>,
    now: Instant,
) {
    *n = Neighbor::new(ext, now);
    n.rloc16 = rloc16;
    if let Some(rss) = rss {
        n.link_info.add_rss(noise_floor, rss);
    }
}

impl<const C: usize> Mle<C> {
    // ------------------------------------------------------------ delayed sender

    pub(crate) fn schedule_delayed(&mut self, due: Instant, kind: DelayedKind) {
        let _ = self.rtr.delayed.push(Delayed { due, kind });
    }

    pub(crate) fn link_request_scheduled(&self, id: u8) -> bool {
        self.rtr
            .delayed
            .iter()
            .any(|d| matches!(d.kind, DelayedKind::LinkRequest(i) if i == id))
    }

    /// Queue a Link Request to router `id` after `delay` unless one is
    /// already queued (OT `ScheduleLinkRequest`).
    pub(crate) fn schedule_link_request(&mut self, id: u8, now: Instant, delay: Duration) {
        if !self.link_request_scheduled(id) {
            self.schedule_delayed(now.saturating_add(delay), DelayedKind::LinkRequest(id));
        }
    }

    pub(crate) fn remove_scheduled_link_request(&mut self, id: u8) {
        self.rtr
            .delayed
            .retain(|d| !matches!(d.kind, DelayedKind::LinkRequest(i) if i == id));
    }

    pub(crate) fn router_link_deadline(&self) -> Option<Instant> {
        let d = self.rtr.delayed.iter().map(|d| d.due).min();
        match (d, self.rtr.restorer.deadline) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, None) => a,
            (None, b) => b,
        }
    }

    /// Run delayed messages and the restorer timer that are due.
    pub(crate) fn poll_router_link<E: MleEnv>(&mut self, env: &mut E, now: Instant) {
        if self.rtr.restorer.deadline.is_some_and(|d| now >= d) {
            self.rtr.restorer.deadline = None;
            self.restorer_timer(env, now);
        }
        let mut i = 0;
        while i < self.rtr.delayed.len() {
            if now >= self.rtr.delayed[i].due {
                let d = self.rtr.delayed.swap_remove(i);
                self.execute_delayed(env, now, d.kind);
            } else {
                i += 1;
            }
        }
    }

    fn execute_delayed<E: MleEnv>(&mut self, env: &mut E, now: Instant, kind: DelayedKind) {
        match kind {
            DelayedKind::LinkRequest(id) => {
                if self.rtr.table.find_by_id(id).is_some() {
                    let _ = self.send_link_request(env, now, Some(id));
                }
            }
            DelayedKind::LinkAccept(info) => {
                let _ = self.send_link_accept(env, &info);
            }
            DelayedKind::Advertisement(dst) => {
                let _ = self.send_advertisement(env, now, dst);
            }
            DelayedKind::DataRequest(dst) => {
                let _ = self.send_data_request_to(env, dst);
            }
            DelayedKind::MulticastDataResponse => {
                let _ = self.send_multicast_data_response(env, now);
            }
        }
    }

    // ------------------------------------------------------------ Link Request

    /// OT `SendLinkRequest`. `router = None` is the multicast request of the
    /// router role restorer.
    pub(crate) fn send_link_request<E: MleEnv>(
        &mut self,
        env: &mut E,
        now: Instant,
        router: Option<u8>,
    ) -> Result<()> {
        let _ = now;
        let role = self.role;
        if role == Role::Disabled {
            return Err(Error::InvalidState);
        }
        let valid = router
            .and_then(|id| self.rtr.table.find_by_id(id))
            .is_some_and(|r| r.neighbor.is_valid());
        let challenge = Self::new_challenge(env);
        let (dst, challenge) = match router {
            None => {
                self.rtr.restorer.challenge = challenge;
                (ipv6::LINK_LOCAL_ALL_ROUTERS, challenge)
            }
            Some(id) => {
                let r = self.rtr.table.find_by_id_mut(id).ok_or(Error::NotFound)?;
                if !r.neighbor.is_valid() {
                    r.neighbor.challenge = challenge;
                }
                r.link_accept_timeout = LINK_ACCEPT_TIMEOUT_SECS;
                (ipv6::link_local(&r.neighbor.ext_address), challenge)
            }
        };
        let rloc = self.rloc16;
        let leader = self.leader_data;
        self.send(env, dst, Command::LinkRequest, |w| {
            w.version(Self::VERSION)?;
            match role {
                Role::Detached => w.tlv_request(&[ty::ADDRESS16, ty::ROUTE64])?,
                Role::Child => {
                    w.source_address(rloc)?;
                    w.leader_data(&leader)?;
                }
                _ => {
                    if valid {
                        w.tlv_request(&[ty::LINK_MARGIN, ty::ROUTE64])?;
                    } else {
                        w.tlv_request(&[ty::LINK_MARGIN])?;
                    }
                    w.source_address(rloc)?;
                    w.leader_data(&leader)?;
                }
            }
            w.challenge(&challenge)
        })
    }

    /// OT `HandleLinkRequest`.
    pub(crate) fn handle_link_request<E: MleEnv>(
        &mut self,
        env: &mut E,
        now: Instant,
        rx: &MleRx<'_>,
        nb: Option<NbRef>,
    ) -> Result<RxClass> {
        if !self.role.is_router_or_leader() || self.attach.is_attaching() {
            return Err(Error::InvalidState);
        }
        let t = &rx.tlvs;
        let ch = t.challenge()?;
        let mut info = LinkAcceptInfo {
            ext: rx.meta.sender_ext_address(),
            challenge: [0; 8],
            challenge_len: ch.len().min(8),
            requested: Vec::new(),
            link_margin: compute_link_margin(
                env.noise_floor(),
                rx.meta
                    .link
                    .rss
                    .unwrap_or(crate::link_quality::INVALID_RSSI),
            ),
        };
        info.challenge[..info.challenge_len].copy_from_slice(&ch[..info.challenge_len]);
        let _version = t.version()?;
        match t.leader_data() {
            Ok(ld) => {
                if ld.partition_id != self.leader_data.partition_id {
                    return Err(Error::InvalidState);
                }
            }
            Err(Error::NotFound) => {}
            Err(_) => return Err(Error::Parse),
        }
        match t.source_address() {
            Ok(src) => {
                if src.is_router() {
                    let id = src.router_id();
                    let nf = env.noise_floor();
                    let rss = rx.meta.link.rss;
                    let r = self.rtr.table.find_by_id_mut(id).ok_or(Error::Parse)?;
                    if !r.neighbor.is_valid() {
                        init_router_neighbor(&mut r.neighbor, info.ext, src, nf, rss, now);
                        r.neighbor.set_state(NeighborState::LinkRequest, now);
                        r.link_accept_timeout = 0;
                    } else if r.neighbor.ext_address != info.ext {
                        return Err(Error::Drop);
                    }
                }
            }
            Err(Error::NotFound) => {
                // A missing source address indicates that the router was
                // recently reset.
                let ok = matches!(nb, Some(NbRef::Router(_))) && self.neighbor_is_valid(nb);
                if !ok {
                    return Err(Error::Drop);
                }
            }
            Err(_) => return Err(Error::Parse),
        }
        match t.tlv_request() {
            Ok(req) => {
                for &r in req {
                    if !info.requested.contains(&r) {
                        let _ = info.requested.push(r);
                    }
                }
            }
            Err(Error::NotFound) => {}
            Err(_) => return Err(Error::Parse),
        }
        if let Some(sec) = rx.meta.security {
            self.process_key_sequence(env, now, RxClass::Peer, sec, nb);
        }
        if rx.meta.dst.is_multicast() {
            let delay = Duration::from_millis(
                1 + u64::from(Self::rand_range(
                    env,
                    0,
                    crate::consts::MAX_LINK_ACCEPT_DELAY.as_millis() as u32,
                )),
            );
            // A newer request from the same router replaces the older one.
            self.rtr
                .delayed
                .retain(|d| !matches!(&d.kind, DelayedKind::LinkAccept(i) if i.ext == info.ext));
            self.schedule_delayed(now.saturating_add(delay), DelayedKind::LinkAccept(info));
        } else {
            self.send_link_accept(env, &info)?;
        }
        Ok(RxClass::Unknown)
    }

    // ------------------------------------------------------------ Link Accept

    /// OT `SendLinkAccept`.
    pub(crate) fn send_link_accept<E: MleEnv>(
        &mut self,
        env: &mut E,
        info: &LinkAcceptInfo,
    ) -> Result<()> {
        if !self.role.is_attached() {
            return Err(Error::InvalidState);
        }
        let router = self
            .rtr
            .table
            .iter(StateFilter::Any)
            .find(|r| r.neighbor.ext_address == info.ext)
            .map(|r| r.router_id);
        let mut command = Command::LinkAccept;
        if let Some(id) = router {
            let r = self.rtr.table.find_by_id_mut(id).ok_or(Error::NotFound)?;
            if r.neighbor.state == NeighborState::LinkRequest {
                command = Command::LinkAcceptAndRequest;
            } else if !r.neighbor.is_valid() {
                return Err(Error::InvalidState);
            }
        }
        let own_challenge = Self::new_challenge(env);
        if command == Command::LinkAcceptAndRequest
            && let Some(r) = router.and_then(|id| self.rtr.table.find_by_id_mut(id))
        {
            r.neighbor.challenge = own_challenge;
        }
        let rloc = self.rloc16;
        let leader = self.leader_data;
        let link_fc = env.keys().frame_counter();
        let mle_fc = self.mle_counter.current_for(env.keys().key_epoch());
        let (seq, mask, entries) = self.fill_route64(router);
        let router_rloc =
            router.and_then(|id| self.rtr.table.find_by_id(id).map(|r| r.neighbor.rloc16));
        let dst = ipv6::link_local(&info.ext);
        self.send(env, dst, command, |w| {
            w.version(Self::VERSION)?;
            w.source_address(rloc)?;
            w.response(&info.challenge[..info.challenge_len])?;
            w.link_frame_counter(link_fc)?;
            w.mle_frame_counter(mle_fc)?;
            w.link_margin(info.link_margin)?;
            if router.is_some() {
                w.leader_data(&leader)?;
            }
            for &tlv in &info.requested {
                match tlv {
                    ty::ROUTE64 => w.route64(seq, &mask, &entries)?,
                    ty::ADDRESS16 => w.address16(router_rloc.ok_or(Error::Drop)?)?,
                    ty::LINK_MARGIN => {}
                    _ => return Err(Error::Drop),
                }
            }
            if command == Command::LinkAcceptAndRequest {
                w.challenge(&own_challenge)?;
                w.tlv_request(&[ty::LINK_MARGIN])?;
            }
            Ok(())
        })
    }

    /// OT `HandleLinkAcceptVariant` for Link Accept and Link Accept And
    /// Request.
    pub(crate) fn handle_link_accept<E: MleEnv>(
        &mut self,
        env: &mut E,
        now: Instant,
        rx: &MleRx<'_>,
        nb: Option<NbRef>,
        and_request: bool,
    ) -> Result<RxClass> {
        let t = &rx.tlvs;
        let source = t.source_address()?;
        if !source.is_router() {
            return Err(Error::Parse);
        }
        let router_id = source.router_id();
        let state = self
            .rtr
            .table
            .find_by_id(router_id)
            .map_or(NeighborState::Invalid, |r| r.neighbor.state);
        let response = t.response()?;
        match state {
            NeighborState::LinkRequest => {
                let r = self
                    .rtr
                    .table
                    .find_by_id(router_id)
                    .ok_or(Error::NotFound)?;
                if r.neighbor.challenge[..] != *response {
                    return Err(Error::Security);
                }
            }
            NeighborState::Invalid => {
                if !(self.rtr.restorer.active && self.rtr.restorer.challenge[..] == *response) {
                    return Err(Error::Security);
                }
            }
            NeighborState::Valid => {}
            _ => return Err(Error::Security),
        }
        // Remove a stale neighbor entry with another RLOC16.
        if let Some(NbRef::Router(old)) = nb
            && self
                .rtr
                .table
                .find_by_id(old)
                .is_some_and(|r| r.neighbor.rloc16 != source)
        {
            self.remove_router_neighbor(env, now, old);
        }
        let version = t.version()?;
        let link_fc = t.link_frame_counter()?;
        let mle_fc = t.mle_frame_counter()?;
        let sec = rx.meta.security.ok_or(Error::Security)?;
        let link_margin = match t.link_margin() {
            Ok(m) => m,
            Err(Error::NotFound) => {
                // After a reset the margin may be omitted: wait for
                // Advertisements to establish the cost.
                if self.role != Role::Detached {
                    return Err(Error::NotFound);
                }
                0
            }
            Err(_) => return Err(Error::Parse),
        };
        let mut route: Option<Route64<'_>> = None;
        let mut update_routes = false;
        match self.role {
            Role::Detached => {
                let addr = t.address16()?;
                if addr != self.rloc16 {
                    return Err(Error::Drop);
                }
                let ld = t.leader_data()?;
                self.update_leader_data(env, ld);
                self.clear_router_table(env);
                let r = t.route64()?;
                self.process_route_tlv(env, now, &r)?;
                if self.rtr.table.find_by_id(router_id).is_none() {
                    return Ok(RxClass::Unknown);
                }
                route = Some(r);
                let own = self.rloc16;
                if self.leader_rloc16() == own {
                    self.set_state_router_or_leader(env, now, Role::Leader, own);
                } else {
                    self.set_state_router_or_leader(env, now, Role::Router, own);
                }
                self.rtr.restorer.active = false;
                self.rtr.restorer.deadline = None;
                self.child.retrieve_new_network_data = true;
                let _ = self.send_data_request_to(env, rx.meta.src);
                update_routes = true;
            }
            Role::Child => {
                if self.rtr.table.find_by_id(router_id).is_none() {
                    return Ok(RxClass::Unknown);
                }
            }
            Role::Router | Role::Leader => {
                if self.rtr.table.find_by_id(router_id).is_none() {
                    return Ok(RxClass::Unknown);
                }
                let ld = t.leader_data()?;
                if ld.partition_id != self.leader_data.partition_id {
                    return Ok(RxClass::Unknown);
                }
                if self.child.retrieve_new_network_data
                    || crate::child_rx::serial_greater(
                        ld.data_version,
                        self.leader_data.data_version,
                    )
                {
                    let _ = self.send_data_request_to(env, rx.meta.src);
                }
                match t.route64() {
                    Ok(r) => {
                        if !r.id_mask.contains(router_id) {
                            return Err(Error::Parse);
                        }
                        if self.active_router_count() == 0
                            || crate::child_rx::serial_greater(r.id_sequence, self.rtr.id_sequence)
                        {
                            self.process_route_tlv(env, now, &r)?;
                        }
                        route = Some(r);
                        update_routes = true;
                    }
                    Err(Error::NotFound) => {}
                    Err(_) => return Err(Error::Parse),
                }
                let no_route = self
                    .rtr
                    .table
                    .find_by_id(router_id)
                    .is_some_and(|r| r.next_hop.is_none());
                if router_id != self.rtr.router_id && no_route {
                    self.reset_advertise_interval(env, now);
                }
            }
            Role::Disabled => return Err(Error::InvalidState),
        }
        let nf = env.noise_floor();
        let ext = rx.meta.sender_ext_address();
        let r = self
            .rtr
            .table
            .find_by_id_mut(router_id)
            .ok_or(Error::NotFound)?;
        init_router_neighbor(&mut r.neighbor, ext, source, nf, rx.meta.link.rss, now);
        r.neighbor.link_counters = LinkFrameCounters::with(sec.key_sequence, link_fc);
        r.neighbor.mle_replay = MleReplay::with(mle_fc);
        r.neighbor.version = version;
        r.neighbor.mode = DeviceMode::new(true, true, true);
        r.neighbor
            .link_info
            .set_link_quality_out(LinkQuality::for_margin(link_margin));
        r.neighbor.set_state(NeighborState::Valid, now);
        r.link_accept_timeout = 0;
        env.event(MleEvent::RouterAdded {
            ext,
            rloc16: source,
        });
        self.remove_scheduled_link_request(router_id);
        if update_routes && let Some(route) = &route {
            self.update_routes(env, now, route, router_id);
        }
        self.table_changed(env, now);
        self.process_key_sequence(
            env,
            now,
            RxClass::Authoritative,
            sec,
            Some(NbRef::Router(router_id)),
        );
        if and_request {
            let ch = t.challenge()?;
            let mut info = LinkAcceptInfo {
                ext,
                challenge: [0; 8],
                challenge_len: ch.len().min(8),
                requested: Vec::new(),
                link_margin: compute_link_margin(
                    nf,
                    rx.meta
                        .link
                        .rss
                        .unwrap_or(crate::link_quality::INVALID_RSSI),
                ),
            };
            info.challenge[..info.challenge_len].copy_from_slice(&ch[..info.challenge_len]);
            match t.tlv_request() {
                Ok(req) => {
                    for &q in req {
                        if !info.requested.contains(&q) {
                            let _ = info.requested.push(q);
                        }
                    }
                }
                Err(Error::NotFound) => {}
                Err(_) => return Err(Error::Parse),
            }
            self.send_link_accept(env, &info)?;
        }
        Ok(RxClass::Authoritative)
    }

    // ------------------------------------------------------------ routes

    /// OT `RouterTable::UpdateRoutes`: take the neighbor's view of our link
    /// quality and its route costs into our table.
    pub(crate) fn update_routes<E: MleEnv>(
        &mut self,
        env: &mut E,
        now: Instant,
        route: &Route64<'_>,
        neighbor_id: u8,
    ) {
        if self.rtr.table.find_by_id(neighbor_id).is_none() {
            return;
        }
        let finite_before = self.finite_path_cost_ids();
        let mut changed = false;
        let own = self.rtr.router_id;
        if let Some(e) = route
            .entry_for_router(own)
            .filter(|_| self.router_id().is_some())
        {
            if let Some(n) = self.rtr.table.find_by_id_mut(neighbor_id)
                && n.neighbor.link_info.link_quality_out() != e.link_quality_in
            {
                n.neighbor.link_info.set_link_quality_out(e.link_quality_in);
                changed = true;
            }
            self.neighbor_reports_no_link(env, now, neighbor_id, e.link_quality_out);
        }
        let link_cost_to_neighbor = self.link_cost(neighbor_id);
        for (id, e) in route.entries() {
            let Some(r) = self.rtr.table.find_by_id(id) else {
                continue;
            };
            if self.has_rloc16(r.neighbor.rloc16) || id == neighbor_id {
                continue;
            }
            let next_hop = r.next_hop;
            let cur_cost = r.cost;
            let cost = if e.cost == 0 { MAX_ROUTE_COST } else { e.cost };
            if next_hop.is_none() || next_hop == Some(neighbor_id) {
                if u16::from(cost) + u16::from(link_cost_to_neighbor) < u16::from(MAX_ROUTE_COST) {
                    changed |= self.set_route(id, Some(neighbor_id), cost);
                } else if next_hop == Some(neighbor_id) {
                    self.invalidate_route(id);
                    if let Some(r) = self.rtr.table.find_by_id_mut(id) {
                        r.neighbor.last_heard = now;
                    }
                    changed = true;
                }
            } else {
                let cur = u16::from(cur_cost)
                    + u16::from(next_hop.map_or(MAX_ROUTE_COST, |h| self.link_cost(h)));
                let new = u16::from(cost) + u16::from(link_cost_to_neighbor);
                if new < cur {
                    changed |= self.set_route(id, Some(neighbor_id), cost);
                }
            }
        }
        if self.finite_path_cost_ids() != finite_before {
            self.reset_advertise_interval(env, now);
        }
        if changed {
            self.table_changed(env, now);
        }
    }

    /// Router IDs with a finite path cost (to detect reachability changes).
    fn finite_path_cost_ids(&self) -> crate::tlv::RouterIdMask {
        let mut m = crate::tlv::RouterIdMask::new();
        for id in 0..=MAX_ROUTER_ID {
            if let Ok(r) = Rloc16::from_router_id(id)
                && self.path_cost(r) < MAX_ROUTE_COST
            {
                let _ = m.insert(id);
            }
        }
        m
    }

    // ------------------------------------------------------------ removing links

    /// OT `RouterTable::RemoveRouterLink` + `Mle::RemoveNeighbor` for a
    /// router.
    pub(crate) fn remove_router_neighbor<E: MleEnv>(&mut self, env: &mut E, now: Instant, id: u8) {
        let Some(r) = self.rtr.table.find_by_id_mut(id) else {
            return;
        };
        if r.neighbor.state == NeighborState::Invalid {
            return;
        }
        let was_valid = r.neighbor.is_valid();
        let (ext, rloc16) = (r.neighbor.ext_address, r.neighbor.rloc16);
        let mut changed = false;
        if r.neighbor.link_info.link_quality_out() != LinkQuality::Q0 {
            r.neighbor.link_info.set_link_quality_out(LinkQuality::Q0);
            r.neighbor.last_heard = now;
            changed = true;
        }
        let no_next_hop = r.next_hop.is_none();
        let ids: Vec<u8, MAX_ROUTERS> = self
            .rtr
            .table
            .iter(StateFilter::Any)
            .filter(|o| o.next_hop == Some(id))
            .map(|o| o.router_id)
            .collect();
        let mut reset_adv = no_next_hop;
        for o in ids {
            self.invalidate_route(o);
            changed = true;
            if self.link_cost(o) >= MAX_ROUTE_COST {
                reset_adv = true;
            }
        }
        if let Some(r) = self.rtr.table.find_by_id_mut(id) {
            r.neighbor.link_info.clear();
            r.neighbor.set_state(NeighborState::Invalid, now);
            r.link_accept_timeout = 0;
            r.link_request_attempts = 0;
        }
        if was_valid {
            env.event(MleEvent::RouterRemoved { ext, rloc16 });
        }
        if reset_adv {
            self.reset_advertise_interval(env, now);
        }
        if changed {
            self.table_changed(env, now);
        }
    }

    // ------------------------------------------------------------ per-second maintenance

    /// The "Update RouterTable" part of OT `HandleTimeTick`.
    pub(crate) fn router_neighbors_tick<E: MleEnv>(&mut self, env: &mut E, now: Instant) {
        let ids: Vec<u8, MAX_ROUTERS> = self
            .rtr
            .table
            .iter(StateFilter::Any)
            .map(|r| r.router_id)
            .collect();
        let many_links =
            self.neighbor_count(LinkQuality::Q1) > usize::from(crate::consts::CHILD_ROUTER_LINKS);
        for id in ids {
            let Some(r) = self.rtr.table.find_by_id_mut(id) else {
                continue;
            };
            if self.rloc16 == r.neighbor.rloc16 {
                r.neighbor.last_heard = now;
                continue;
            }
            let age = now.saturating_duration_since(r.neighbor.last_heard);
            let valid = r.neighbor.is_valid();
            let state = r.neighbor.state;
            if valid {
                if self.role == Role::Child && many_links {
                    if age >= crate::consts::MAX_NEIGHBOR_AGE_ON_CHILD {
                        self.remove_scheduled_link_request(id);
                        self.remove_router_neighbor(env, now, id);
                        continue;
                    }
                } else if age >= crate::consts::MAX_NEIGHBOR_AGE {
                    let scheduled = self.link_request_scheduled(id);
                    let Some(r) = self.rtr.table.find_by_id_mut(id) else {
                        continue;
                    };
                    if !scheduled && r.link_accept_timeout == 0 {
                        r.link_request_attempts = crate::consts::MAX_LINK_REQUEST_ATTEMPTS;
                    }
                    if r.link_request_attempts > 0 {
                        r.link_request_attempts -= 1;
                        let d = Duration::from_millis(u64::from(Self::rand_range(
                            env,
                            0,
                            crate::consts::MAX_LINK_REQUEST_DELAY_ON_ROUTER.as_millis() as u32,
                        )));
                        self.schedule_link_request(id, now, d);
                    }
                }
            }
            let scheduled = self.link_request_scheduled(id);
            let Some(r) = self.rtr.table.find_by_id_mut(id) else {
                continue;
            };
            if state == NeighborState::LinkRequest && !scheduled && r.link_accept_timeout == 0 {
                self.remove_router_neighbor(env, now, id);
                continue;
            }
            if r.link_accept_timeout > 0 {
                r.link_accept_timeout -= 1;
                if r.link_accept_timeout == 0 {
                    self.remove_router_neighbor(env, now, id);
                    continue;
                }
            }
            if self.role == Role::Leader {
                let no_route = self
                    .rtr
                    .table
                    .find_by_id(id)
                    .is_some_and(|r| r.next_hop.is_none());
                if no_route
                    && self.link_cost(id) >= MAX_ROUTE_COST
                    && age >= crate::consts::MAX_LEADER_TO_ROUTER_TIMEOUT
                {
                    let _ = self.release_router_id(env, now, id);
                }
            }
        }
    }

    /// Valid router neighbors whose incoming link quality is at least `lq`
    /// (OT `RouterTable::GetNeighborCount`).
    pub(crate) fn neighbor_count(&self, lq: LinkQuality) -> usize {
        self.rtr
            .table
            .iter(StateFilter::Valid)
            .filter(|r| r.neighbor.link_info.link_quality_in() >= lq)
            .count()
    }

    /// A REED became router: a former parent of version < 1.3 may ignore
    /// Advertisements of a former child, so it gets a Link Request.
    pub(crate) fn router_became_from_child<E: MleEnv>(
        &mut self,
        env: &mut E,
        now: Instant,
        former_parent: &Parent,
    ) {
        if former_parent.router.neighbor.version < THREAD_VERSION_1_3 {
            let id = former_parent.router.neighbor.rloc16.router_id();
            let _ = self.send_link_request(env, now, Some(id));
        }
    }

    // ------------------------------------------------------------ router role restore

    /// Restore the router (or leader) role after a reset: multicast Link
    /// Requests until a neighbor answers with our Address16 and the Route64
    /// TLV (OT `RouterRoleRestorer`). Called by [`Mle::restore`](Mle::restore).
    pub(crate) fn start_router_restore<E: MleEnv>(
        &mut self,
        env: &mut E,
        now: Instant,
        previous: Role,
    ) {
        let attempts = match previous {
            Role::Router
                if self.children.count(StateFilter::ValidOrRestoring)
                    < MIN_CRITICAL_CHILDREN_COUNT =>
            {
                crate::consts::MAX_TRANSMISSION_COUNT
            }
            Role::Router | Role::Leader => crate::consts::MAX_CRITICAL_TRANSMISSION_COUNT,
            _ => 0,
        };
        self.rtr.restorer.active = true;
        self.rtr.restorer.attempts = attempts;
        self.restorer_send(env, now);
    }

    /// `Mle::restore` of a saved router / leader: keep the RLOC16 and start
    /// the restorer; the children come back `Restored` once the router role
    /// is entered.
    pub(crate) fn restore_router<E: MleEnv>(
        &mut self,
        env: &mut E,
        now: Instant,
        role: Role,
        rloc16: Rloc16,
    ) {
        self.rtr.router_id = rloc16.router_id();
        self.rtr.previous_router_id = rloc16.router_id();
        self.restore_children_from(env, now);
        self.start_router_restore(env, now, role);
    }

    fn restorer_timer<E: MleEnv>(&mut self, env: &mut E, now: Instant) {
        if self.rtr.restorer.attempts > 0 {
            self.rtr.restorer.attempts -= 1;
        }
        self.restorer_send(env, now);
    }

    fn restorer_send<E: MleEnv>(&mut self, env: &mut E, now: Instant) {
        if self.role != Role::Detached {
            self.rtr.restorer.attempts = 0;
            self.rtr.restorer.active = false;
            return;
        }
        if self.rtr.restorer.attempts == 0 {
            self.rtr.restorer.active = false;
            self.become_detached(env, now);
            return;
        }
        let _ = self.send_link_request(env, now, None);
        let delay = if self.rtr.restorer.attempts == 1 {
            LINK_REQUEST_TIMEOUT
        } else {
            let base = MULTICAST_RETRANSMISSION_DELAY.as_millis() as u32;
            Duration::from_millis(u64::from(Self::rand_range(
                env,
                base * 9 / 10,
                base * 11 / 10,
            )))
        };
        self.rtr.restorer.deadline = Some(now.saturating_add(delay));
    }
}
