//! MLE Advertisements (feature `ftd`; Thread 1.4.1 §4.6.2, §5.9.2, §5.16;
//! OpenThread `Mle::SendAdvertisement`, `HandleAdvertisement`,
//! `HandleAdvertisementOnFtd`, `EstablishRouterLinkOnFtdChild`,
//! `ShouldDowngrade`, `AdvertiseTrickleTimer`).
//!
//! Routers and the leader send a multicast Advertisement (Source Address,
//! Leader Data, Route64) on a Trickle timer
//! ([`opentrust_core::trickle`], `Imin` 1 s, `Imax` = 4 s per router
//! neighbor with incoming link quality >= 2, clamped to 12..32 s, redundancy
//! constant 0 = never suppressed). The timer restarts at `Imin`
//! ("inconsistent") whenever the router ID set or a route changes. A REED
//! advertises on a plain timer every 570..630 s (Source Address and Leader
//! Data only).
//!
//! Receiving an Advertisement:
//!
//! | situation | action |
//! |-----------|--------|
//! | other partition, margin >= 10 dB | better partition (weight, then non-singleton, then partition ID)? Attach(BetterPartition) |
//! | leader router ID mismatch (router) | detach |
//! | router, no link yet, our ID in its Route64 | Link Request after 0..1 s |
//! | router link valid | refresh age, take its Route64 into the routes |
//! | FTD child, not the parent | maybe a Link Request (first 3 quick, 32 more gradually) |
//! | parent (child) | partition / leader change detection, Route64 into the routes |
//! | newer Network Data version | Data Request after 1..1000 ms |

use core::convert::Infallible;
use core::net::Ipv6Addr;

use opentrust_core::time::{Duration, Instant};
use opentrust_core::trickle::{Trickle, TrickleConfig, TrickleEvent, TrickleMode};
use opentrust_core::types::{Rloc16, ipv6};
use opentrust_core::{Error, Result};

use crate::attach::AttachMode;
use crate::child_rx::serial_greater;
use crate::consts::{
    ADVERTISEMENT_I_MIN, CHILD_ROUTER_LINKS, EXTRA_CHILD_ROUTER_LINKS, GRADUAL_LINK_MAX_DELAY,
    GRADUAL_LINK_MIN_DELAY, GRADUAL_LINK_PROBABILITY_PERCENT, GRADUAL_LINK_WAIT_AFTER_ATTACH,
    LINK_REQUEST_MIN_MARGIN, MAX_LINK_REQUEST_DELAY_ON_CHILD, MAX_LINK_REQUEST_DELAY_ON_ROUTER,
    MAX_ROUTER_ID, MAX_UNICAST_ADVERTISEMENT_DELAY, MIN_DOWNGRADE_NEIGHBORS,
    MIN_LINK_REQUEST_DELAY_ON_CHILD, PARTITION_MERGE_MIN_MARGIN, REED_ADVERTISEMENT_MAX,
    REED_ADVERTISEMENT_MIN,
};
use crate::endpoint::MleRx;
use crate::env::{MleEnv, Role};
use crate::link_quality::{LinkQuality, compute_link_margin};
use crate::message::Command;
use crate::mle::{Mle, NbRef};
use crate::neighbor::{NeighborState, StateFilter};
use crate::router_link::DelayedKind;
use crate::tlv::{DeviceMode, LeaderData, Route64};

/// Adapter that lets the [`Trickle`] timer draw from the environment's
/// random source.
pub(crate) struct EnvRng<'a, E: MleEnv>(pub &'a mut E);

impl<E: MleEnv> rand_core::TryRng for EnvRng<'_, E> {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> core::result::Result<u32, Infallible> {
        let mut b = [0u8; 4];
        self.0.fill_random(&mut b);
        Ok(u32::from_le_bytes(b))
    }

    fn try_next_u64(&mut self) -> core::result::Result<u64, Infallible> {
        let mut b = [0u8; 8];
        self.0.fill_random(&mut b);
        Ok(u64::from_le_bytes(b))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> core::result::Result<(), Infallible> {
        self.0.fill_random(dst);
        Ok(())
    }
}

/// The initial (stopped) Advertisement timer.
pub(crate) const fn initial_trickle() -> Trickle {
    match TrickleConfig::new(
        ADVERTISEMENT_I_MIN,
        crate::consts::ADVERTISEMENT_I_MAX,
        0,
        TrickleMode::Trickle,
    ) {
        Ok(c) => Trickle::new(c),
        Err(_) => panic!("invalid Advertisement trickle configuration"),
    }
}

/// OT `Mle::ComparePartitions`: positive if partition A is better than B.
pub fn compare_partitions(
    singleton_a: bool,
    a: &LeaderData,
    singleton_b: bool,
    b: &LeaderData,
) -> i32 {
    use core::cmp::Ordering;
    let ord = a
        .weighting
        .cmp(&b.weighting)
        // Not being a singleton is better.
        .then((!singleton_a).cmp(&!singleton_b))
        .then(a.partition_id.cmp(&b.partition_id));
    match ord {
        Ordering::Less => -1,
        Ordering::Equal => 0,
        Ordering::Greater => 1,
    }
}

impl<const C: usize> Mle<C> {
    // ------------------------------------------------------------ trickle timer

    /// OT `SetStateRouterOrLeader`: (re)start the Advertisement timer.
    pub(crate) fn router_role_entered<E: MleEnv>(&mut self, env: &mut E, now: Instant) {
        self.rtr.advert.stop();
        self.reset_advertise_interval(env, now);
    }

    fn start_advert_timer<E: MleEnv>(&mut self, env: &mut E, now: Instant, reed: bool) {
        let cfg = if reed {
            TrickleConfig::new(
                REED_ADVERTISEMENT_MIN,
                REED_ADVERTISEMENT_MAX,
                0,
                TrickleMode::Plain,
            )
        } else {
            TrickleConfig::new(
                ADVERTISEMENT_I_MIN,
                self.advertise_interval_max(),
                0,
                TrickleMode::Trickle,
            )
        };
        if let Ok(cfg) = cfg {
            self.rtr.advert = Trickle::new(cfg);
            self.rtr.advert.start(now, &mut EnvRng(env));
        }
    }

    /// OT `ResetAdvertiseInterval`: the router ID set or a route changed;
    /// advertise again soon.
    pub(crate) fn reset_advertise_interval<E: MleEnv>(&mut self, env: &mut E, now: Instant) {
        if !self.role.is_router_or_leader() {
            return;
        }
        if !self.rtr.advert.is_running() {
            self.start_advert_timer(env, now, false);
        }
        self.rtr.advert.inconsistent(now, &mut EnvRng(env));
    }

    /// OT `UpdateAdvertiseInterval`: neighbors changed `Imax`.
    pub(crate) fn update_advertise_interval<E: MleEnv>(&mut self, env: &mut E, now: Instant) {
        if self.role.is_router_or_leader() && self.rtr.advert.is_running() {
            let imax = self.advertise_interval_max();
            self.rtr.advert.set_imax(imax, now, &mut EnvRng(env));
        }
    }

    pub(crate) fn stop_advertising(&mut self) {
        self.rtr.advert.stop();
    }

    /// A REED starts advertising (every 570..630 s) when its router role
    /// transition delay expired.
    pub(crate) fn start_reed_advertising<E: MleEnv>(&mut self, env: &mut E, now: Instant) {
        if self.rtr.advert.is_running() {
            return;
        }
        let _ = self.send_advertisement(env, now, ipv6::LINK_LOCAL_ALL_NODES);
        self.start_advert_timer(env, now, true);
    }

    pub(crate) fn advert_deadline(&self) -> Option<Instant> {
        self.rtr.advert.next_deadline()
    }

    pub(crate) fn poll_advert<E: MleEnv>(&mut self, env: &mut E, now: Instant) {
        let mut fire = false;
        while let Some(TrickleEvent::Transmit) = self.rtr.advert.poll(now, &mut EnvRng(env)) {
            fire = true;
        }
        if fire {
            if self.is_router_eligible() {
                let _ = self.send_advertisement(env, now, ipv6::LINK_LOCAL_ALL_NODES);
            } else {
                self.rtr.advert.stop();
            }
        }
    }

    /// OT `ScheduleUnicastAdvertisementTo`.
    pub(crate) fn schedule_unicast_advertisement<E: MleEnv>(
        &mut self,
        env: &mut E,
        now: Instant,
        router_id: u8,
    ) {
        let Some(r) = self.rtr.table.find_by_id(router_id) else {
            return;
        };
        let dst = ipv6::link_local(&r.neighbor.ext_address);
        let exists = self
            .rtr
            .delayed
            .iter()
            .any(|d| matches!(&d.kind, DelayedKind::Advertisement(a) if *a == dst));
        if !exists {
            let d = Duration::from_millis(u64::from(Self::rand_range(
                env,
                0,
                MAX_UNICAST_ADVERTISEMENT_DELAY.as_millis() as u32,
            )));
            self.schedule_delayed(now.saturating_add(d), DelayedKind::Advertisement(dst));
        }
    }

    /// `update_routes` found that `neighbor` reports no link to us although
    /// ours is good: advertise to it right away (OT `UpdateRoutes`).
    pub(crate) fn neighbor_reports_no_link<E: MleEnv>(
        &mut self,
        env: &mut E,
        now: Instant,
        id: u8,
        reported_out: LinkQuality,
    ) {
        let good = self.rtr.table.find_by_id(id).is_some_and(|r| {
            r.neighbor.is_valid() && r.neighbor.link_info.two_way_quality() >= LinkQuality::Q2
        });
        if good && reported_out == LinkQuality::Q0 {
            self.schedule_unicast_advertisement(env, now, id);
        }
    }

    // ------------------------------------------------------------ send

    /// OT `SendAdvertisement`.
    pub(crate) fn send_advertisement<E: MleEnv>(
        &mut self,
        env: &mut E,
        _now: Instant,
        dst: Ipv6Addr,
    ) -> Result<()> {
        // Suppressed while attaching elsewhere (a candidate parent might
        // read the router Source Address as a reason to reject us) and
        // while an Address Solicit is outstanding (existing children might
        // detach).
        if self.attach.is_attaching() || self.rtr.solicit_pending {
            return Ok(());
        }
        let rloc = self.rloc16;
        let leader = self.leader_data;
        let router = match self.role {
            Role::Router | Role::Leader => true,
            Role::Child => false,
            _ => return Err(Error::InvalidState),
        };
        let (seq, mask, entries) = self.fill_route64(None);
        self.send(env, dst, Command::Advertisement, |w| {
            w.source_address(rloc)?;
            w.leader_data(&leader)?;
            if router {
                w.route64(seq, &mask, &entries)?;
            }
            Ok(())
        })
    }

    // ------------------------------------------------------------ receive (FTD part)

    /// OT `HandleAdvertisementOnFtd`; `Ok` lets [`handle_advertisement`]
    /// (child_rx) continue with the generic child / router processing.
    pub(crate) fn handle_advertisement_on_ftd<E: MleEnv>(
        &mut self,
        env: &mut E,
        now: Instant,
        rx: &MleRx<'_>,
        nb: Option<NbRef>,
        source: Rloc16,
        leader: &LeaderData,
    ) -> Result<()> {
        let r = self.advertisement_on_ftd(env, now, rx, nb, source, leader);
        // A neighbor entry whose RLOC16 differs from the sender's is stale.
        match nb {
            Some(NbRef::Router(id))
                if self
                    .rtr
                    .table
                    .find_by_id(id)
                    .is_some_and(|r| r.neighbor.rloc16 != source) =>
            {
                self.remove_router_neighbor(env, now, id);
            }
            Some(NbRef::Child(i))
                if self
                    .children
                    .get(i)
                    .is_some_and(|c| c.neighbor.rloc16 != source) =>
            {
                self.remove_child(env, i);
            }
            _ => {}
        }
        r
    }

    fn advertisement_on_ftd<E: MleEnv>(
        &mut self,
        env: &mut E,
        now: Instant,
        rx: &MleRx<'_>,
        nb: Option<NbRef>,
        source: Rloc16,
        leader: &LeaderData,
    ) -> Result<()> {
        let margin = compute_link_margin(
            env.noise_floor(),
            rx.meta
                .link
                .rss
                .unwrap_or(crate::link_quality::INVALID_RSSI),
        );
        let route = match rx.tlvs.route64() {
            Ok(r) => Some(r),
            Err(Error::NotFound) => None,
            Err(_) => return Err(Error::Parse),
        };
        let nb_valid = self.neighbor_is_valid(nb);

        // ---- other partition
        if leader.partition_id != self.leader_data.partition_id {
            if margin < PARTITION_MERGE_MIN_MARGIN {
                return Err(Error::Drop);
            }
            if let Some(r) = &route {
                if self.rtr.previous_partition_timeout > 0
                    && leader.partition_id == self.previous_partition_id
                    && !serial_greater(r.id_sequence, self.rtr.previous_partition_id_sequence)
                {
                    return Err(Error::Drop);
                }
            }
            if self.role == Role::Child && nb == Some(NbRef::Parent) {
                // The parent moved to another partition: follow it.
                return Ok(());
            }
            let singleton = route.as_ref().is_none_or(|r| r.is_singleton());
            if compare_partitions(singleton, leader, self.is_singleton(), &self.leader_data) > 0 {
                self.attach_begin(env, now, AttachMode::BetterPartition);
            }
            return Err(Error::Drop);
        }

        // ---- leader router ID mismatch
        if leader.leader_router_id != self.leader_data.leader_router_id {
            if !nb_valid {
                return Ok(());
            }
            if self.role != Role::Child {
                self.become_detached(env, now);
                return Err(Error::Drop);
            }
            return Ok(());
        }

        let Some(route) = route.filter(|_| source.is_router()) else {
            return Ok(());
        };
        let router_id = source.router_id();

        // ---- Route64
        if nb_valid
            && (self.active_router_count() == 0
                || serial_greater(route.id_sequence, self.rtr.id_sequence))
        {
            self.process_route_tlv(env, now, &route)?;
        }

        // ---- as a child
        if self.role == Role::Child {
            if nb == Some(NbRef::Parent) {
                let parent_rloc = self.parent.as_ref().map(|p| p.router.neighbor.rloc16);
                if parent_rloc != Some(source) {
                    self.become_detached(env, now);
                    return Err(Error::Drop);
                }
                if self.rtr.transition == 0
                    && self.active_router_count() < self.cfg.router.upgrade_threshold
                {
                    self.start_role_transition(env);
                }
                self.update_router_on_ftd_child(env, now, &route, router_id);
            } else {
                if self.rtr.table.find_by_id(router_id).is_none() {
                    return Ok(());
                }
                self.establish_router_link_on_ftd_child(env, now, rx, router_id, margin);
                if let Some(r) = self.rtr.table.find_by_id_mut(router_id) {
                    r.neighbor.last_heard = now;
                }
            }
            return Ok(());
        }

        // ---- as a router or the leader
        if self.role == Role::Router && self.should_downgrade(router_id, &route) {
            self.start_role_transition(env);
        }
        let Some(r) = self.rtr.table.find_by_id(router_id) else {
            return Ok(());
        };
        let (r_valid, r_state) = (r.neighbor.is_valid(), r.neighbor.state);
        if !r_valid {
            if let Some(NbRef::Child(i)) = nb.filter(|_| nb_valid) {
                // A former child that now acts as a router: take over the
                // child's link data.
                if let Some(c) = self.children.get(i) {
                    let mut n = c.neighbor.clone();
                    n.rloc16 = source;
                    n.mode = DeviceMode::new(true, true, true);
                    let (ext, rloc16) = (n.ext_address, n.rloc16);
                    if let Some(r) = self.rtr.table.find_by_id_mut(router_id) {
                        r.neighbor = n;
                    }
                    env.event(crate::env::MleEvent::RouterAdded { ext, rloc16 });
                }
            }
        }
        let r_valid = self
            .rtr
            .table
            .find_by_id(router_id)
            .is_some_and(|r| r.neighbor.is_valid());
        // Link Request if there is no link and no request in progress.
        if !r_valid
            && r_state != NeighborState::LinkRequest
            && margin >= LINK_REQUEST_MIN_MARGIN
            && self
                .router_id()
                .is_some_and(|me| route.id_mask.contains(me))
        {
            let nf = env.noise_floor();
            let ext = rx.meta.sender_ext_address();
            if let Some(r) = self.rtr.table.find_by_id_mut(router_id) {
                r.neighbor = crate::neighbor::Neighbor::new(ext, now);
                r.neighbor.rloc16 = source;
                if let Some(rss) = rx.meta.link.rss {
                    r.neighbor.link_info.add_rss(nf, rss);
                }
                r.neighbor.set_state(NeighborState::LinkRequest, now);
                r.link_accept_timeout = 0;
            }
            let d = Duration::from_millis(u64::from(Self::rand_range(
                env,
                0,
                MAX_LINK_REQUEST_DELAY_ON_ROUTER.as_millis() as u32,
            )));
            self.schedule_link_request(router_id, now, d);
            return Err(Error::Drop);
        }
        if let Some(r) = self.rtr.table.find_by_id_mut(router_id) {
            r.neighbor.last_heard = now;
        }
        self.update_routes(env, now, &route, router_id);
        Ok(())
    }

    /// OT `EstablishRouterLinkOnFtdChild`.
    fn establish_router_link_on_ftd_child<E: MleEnv>(
        &mut self,
        env: &mut E,
        now: Instant,
        rx: &MleRx<'_>,
        id: u8,
        margin: u8,
    ) {
        let Some(r) = self.rtr.table.find_by_id(id) else {
            return;
        };
        if r.neighbor.is_valid() || r.neighbor.state == NeighborState::LinkRequest {
            return;
        }
        let count = self.neighbor_count(LinkQuality::Q1);
        let quick = usize::from(CHILD_ROUTER_LINKS);
        let (min, max) = if count < quick {
            (
                MIN_LINK_REQUEST_DELAY_ON_CHILD,
                MAX_LINK_REQUEST_DELAY_ON_CHILD,
            )
        } else {
            // The extra links are established slowly: only with a good
            // link, long after attaching, and with a small probability.
            let attached_for = self
                .parent
                .as_ref()
                .map_or(0, |p| p.router.neighbor.connection_time_secs(now));
            if count >= quick + usize::from(EXTRA_CHILD_ROUTER_LINKS)
                || LinkQuality::for_margin(margin) < LinkQuality::Q2
                || attached_for <= GRADUAL_LINK_WAIT_AFTER_ATTACH.as_secs()
                || Self::rand_range(env, 0, 100) >= u32::from(GRADUAL_LINK_PROBABILITY_PERCENT)
            {
                return;
            }
            (GRADUAL_LINK_MIN_DELAY, GRADUAL_LINK_MAX_DELAY)
        };
        let nf = env.noise_floor();
        let ext = rx.meta.sender_ext_address();
        let src = rx.tlvs.source_address().unwrap_or(Rloc16::INVALID);
        if let Some(r) = self.rtr.table.find_by_id_mut(id) {
            r.neighbor = crate::neighbor::Neighbor::new(ext, now);
            r.neighbor.rloc16 = src;
            if let Some(rss) = rx.meta.link.rss {
                r.neighbor.link_info.add_rss(nf, rss);
            }
            r.neighbor.set_state(NeighborState::LinkRequest, now);
            r.link_accept_timeout = 0;
        }
        let d = Duration::from_millis(u64::from(Self::rand_range(
            env,
            min.as_millis() as u32,
            max.as_millis() as u32,
        )));
        self.schedule_link_request(id, now, d);
    }

    // ------------------------------------------------------------ downgrade decision

    /// OT `ShouldDowngrade`: after a neighboring router's Route64, are all
    /// conditions for this router to give up its role satisfied?
    fn should_downgrade(&self, neighbor_id: u8, route: &Route64<'_>) -> bool {
        let active = self.active_router_count();
        if self.role != Role::Router
            || !self.rtr.allocated.contains(neighbor_id)
            || self.rtr.transition > 0
            || active <= self.cfg.router.downgrade_threshold
        {
            return false;
        }
        // At least MIN_DOWNGRADE_NEIGHBORS router neighbors with two-way
        // link quality >= 2.
        let good = self
            .rtr
            .table
            .iter(StateFilter::Valid)
            .filter(|r| r.neighbor.link_info.two_way_quality() >= LinkQuality::Q2)
            .count();
        if good < usize::from(MIN_DOWNGRADE_NEIGHBORS) {
            return false;
        }
        // Fewer children than three times the number of excess routers.
        let excess = usize::from(active - self.cfg.router.downgrade_threshold);
        if self.children.count(StateFilter::Valid) >= excess * 3 {
            return false;
        }
        self.neighbor_has_comparable_connectivity(route, neighbor_id)
    }

    /// OT `NeighborHasComparableConnectivity`.
    fn neighbor_has_comparable_connectivity(&self, route: &Route64<'_>, neighbor_id: u8) -> bool {
        for id in 0..=MAX_ROUTER_ID {
            if id == self.rtr.router_id || id == neighbor_id {
                continue;
            }
            let Some(r) = self
                .rtr
                .table
                .find_by_id(id)
                .filter(|r| r.neighbor.is_valid())
            else {
                continue;
            };
            let local = r.neighbor.link_info.two_way_quality();
            if local < LinkQuality::Q2 {
                continue;
            }
            let Some(e) = route.entry_for_router(id) else {
                return false;
            };
            if e.link_quality_in.min(e.link_quality_out) < local {
                return false;
            }
        }
        true
    }
}
