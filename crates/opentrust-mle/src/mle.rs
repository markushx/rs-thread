//! The MLE core: [`Mle`], the sans-IO state machine of Thread attach, child
//! operation and (with the `ftd` feature) parent-side child handling.
//!
//! See [`env`](crate::env) for how the core reaches the key manager, MAC,
//! netif, settings and the network, and for the time / randomness model.
//!
//! # Driving the core
//!
//! ```text
//! rx:    UdpRx::Receiver -> Mle::receive(env, now, meta, link, payload, scratch)
//!                           (parse+decrypt, neighbor replay check, dispatch,
//!                            key sequence adoption)
//! time:  Mle::poll(env, now) whenever now >= Mle::next_deadline()
//! start: Mle::start(env, now) / Mle::restore(env, now) / Mle::stop(env)
//! ```
//!
//! Handlers send answers synchronously through [`MleEnv::send`]; delayed
//! sends (Parent Response jitter) are kept as deadlines inside the core.
//!
//! # Module layout
//!
//! - [`attach`](crate::attach): child-side attach (Parent Request phases,
//!   Parent Response collection and selection, Child ID Request/Response).
//! - [`child`](crate::child): child role operation (Child Update, keep
//!   alive, supervision, parent loss, Data Request/Response, poll period).
//! - `parent` (feature `ftd`): Parent Request, Child ID Request, Child
//!   Update handling and child timeouts for a router.
//! - [`persist`](crate::persist): `NetworkInfo` / `ParentInfo` / `ChildInfo`
//!   save and restore.
//! - `router`, `router_link`, `advert` (feature `ftd`): the router and
//!   leader role, router links, Advertisements, partitions.
//!
//! Discovery and Announce transport is in [`crate::discovery`]. Not part of
//! the MLE core: the Address Solicit exchange over TMF (`opentrust-mesh`, hook:
//! [`MleEnv::request_router_id`]).

use core::net::Ipv6Addr;

use heapless::Vec;
use opentrust_core::time::{Duration, Instant};
use opentrust_core::types::{Rloc16, ipv6};
use opentrust_core::{Error, Result};
use opentrust_net::udp::UdpMeta;

use crate::attach::AttachCtx;
use crate::child::ChildCtx;
use crate::consts::THREAD_VERSION;
use crate::endpoint::{self, LinkRxInfo, MleRx};
use crate::env::{MleEnv, MleEvent, Role, TxOptions};
use crate::message::{Command, MleBuilder};
use crate::neighbor::{ChildTable, Neighbor, NeighborState, Parent};
use crate::router_config::RouterConfig;
use crate::security::{self, MleFrameCounter, RxSecurity};
use crate::tlv::{AddressEntry, DeviceMode, LeaderData, TlvWriter};

/// Largest MLE message the core builds (UDP payload; 6LoWPAN fragments it).
pub const MAX_MLE_LEN: usize = 1024;

/// Static configuration of the MLE core.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MleConfig {
    /// Device mode advertised to the parent. A sleepy end device has
    /// `rx_on_when_idle == false`.
    pub mode: DeviceMode,
    /// Child timeout in seconds (Timeout TLV; OT `mTimeout`, default
    /// [`END_DEVICE_TIMEOUT_SECS`](crate::consts::END_DEVICE_TIMEOUT_SECS)).
    pub timeout_secs: u32,
    /// Supervision interval a sleepy child asks of its parent (seconds,
    /// 0 = none; OT default 129).
    pub supervision_interval: u16,
    /// Seconds without a secure frame from the parent after which a sleepy
    /// child probes it (OT default 190, 0 = disabled).
    pub supervision_check_timeout: u16,
    /// CSL period of a sleepy child in units of 10 symbols (160 microseconds;
    /// 0 = no CSL, the default).
    pub csl_period: u16,
    /// CSL channel of a sleepy child (0 = the PAN channel).
    pub csl_channel: u8,
    /// CSL synchronized timeout in seconds (OT default 100; 0 = use the child
    /// timeout).
    pub csl_timeout_secs: u32,
    /// Router role configuration (eligibility, thresholds, leader weight).
    pub router: RouterConfig,
}

/// How long a graceful detach waits for the parent / leader (OT
/// `kDetachGracefullyTimeout`).
pub const DETACH_GRACEFULLY_TIMEOUT: Duration = Duration::from_secs(1);

impl MleConfig {
    /// Defaults of OpenThread for the given mode.
    pub const fn new(mode: DeviceMode) -> Self {
        Self {
            mode,
            timeout_secs: crate::consts::END_DEVICE_TIMEOUT_SECS,
            supervision_interval: 129,
            supervision_check_timeout: 190,
            csl_period: 0,
            csl_channel: 0,
            csl_timeout_secs: crate::csl::DEFAULT_CSL_TIMEOUT_SECS,
            router: RouterConfig::new(),
        }
    }
}

/// How a received message affects key sequence adoption (OT
/// `RxInfo::Class`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RxClass {
    /// Not (successfully) classified: never adopt.
    Unknown,
    /// From a known neighbor: adopt only the next sequence.
    Peer,
    /// Proves the sender's authority: always adopt.
    Authoritative,
}

/// Which neighbor a message came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NbRef {
    Parent,
    Candidate,
    Child(usize),
    /// A router link, by router ID.
    #[cfg(feature = "ftd")]
    Router(u8),
}

/// The MLE state machine. `C` is the child table capacity (0 for end
/// devices).
#[derive(Debug)]
pub struct Mle<const C: usize> {
    pub(crate) cfg: MleConfig,
    pub(crate) role: Role,
    pub(crate) rloc16: Rloc16,
    pub(crate) mle_counter: MleFrameCounter,
    pub(crate) leader_data: LeaderData,
    pub(crate) parent: Option<Parent>,
    pub(crate) attach: AttachCtx,
    pub(crate) announce: crate::discovery::AnnounceCtx,
    pub(crate) announce_sender: crate::announce_sender::AnnounceSender,
    pub(crate) link_metrics: crate::link_metrics::SeriesTable<{ crate::link_metrics::MAX_SERIES }>,
    pub(crate) child: ChildCtx,
    pub(crate) csl_applied: Option<crate::csl::CslApplied>,
    pub(crate) children: ChildTable<C>,
    pub(crate) previous_partition_id: u32,
    pub(crate) store_pending: bool,
    #[cfg(feature = "ftd")]
    pub(crate) parent_side: crate::parent::ParentSide,
    #[cfg(feature = "ftd")]
    pub(crate) rtr: crate::router::RouterCtx,
    #[cfg(feature = "ftd")]
    pub(crate) discovery_out: heapless::Vec<crate::discovery::DiscoveryOut, 2>,
}

impl<const C: usize> Mle<C> {
    /// A stopped core ([`Role::Disabled`]).
    pub fn new(cfg: MleConfig) -> Self {
        Self {
            cfg,
            role: Role::Disabled,
            rloc16: Rloc16::INVALID,
            mle_counter: MleFrameCounter::new(),
            leader_data: LeaderData {
                partition_id: 0,
                weighting: 0,
                data_version: 0,
                stable_data_version: 0,
                leader_router_id: 0,
            },
            parent: None,
            attach: AttachCtx::new(),
            announce: crate::discovery::AnnounceCtx::new(),
            announce_sender: crate::announce_sender::AnnounceSender::new(),
            link_metrics: crate::link_metrics::SeriesTable::new(),
            child: ChildCtx::new(),
            csl_applied: None,
            children: ChildTable::new(),
            previous_partition_id: 0,
            store_pending: false,
            #[cfg(feature = "ftd")]
            parent_side: crate::parent::ParentSide::new(),
            #[cfg(feature = "ftd")]
            rtr: crate::router::RouterCtx::new(),
            #[cfg(feature = "ftd")]
            discovery_out: heapless::Vec::new(),
        }
    }

    // ------------------------------------------------------------ accessors

    /// Current role.
    pub fn role(&self) -> Role {
        self.role
    }

    /// Current RLOC16 ([`Rloc16::INVALID`] if none).
    pub fn rloc16(&self) -> Rloc16 {
        self.rloc16
    }

    /// The attached (or restored) parent, if any.
    pub fn parent(&self) -> Option<&Parent> {
        self.parent.as_ref()
    }

    /// Leader Data of the partition we are attached to.
    pub fn leader_data(&self) -> &LeaderData {
        &self.leader_data
    }

    /// The configuration (the device mode may be changed with
    /// [`set_device_mode`](Self::set_device_mode)).
    pub fn config(&self) -> &MleConfig {
        &self.cfg
    }

    /// The router configuration (eligibility, thresholds, jitter, leader
    /// weight) for changes by the application.
    pub fn router_config_mut(&mut self) -> &mut crate::router_config::RouterConfig {
        &mut self.cfg.router
    }

    /// Outgoing MLE frame counter (for persistence, see
    /// [`MleFrameCounter::needs_store`]).
    pub fn mle_frame_counter(&self) -> &MleFrameCounter {
        &self.mle_counter
    }

    /// Mutable outgoing MLE frame counter (restore / `stored`).
    pub fn mle_frame_counter_mut(&mut self) -> &mut MleFrameCounter {
        &mut self.mle_counter
    }

    /// Router ID of the leader.
    pub fn leader_router_id(&self) -> u8 {
        self.leader_data.leader_router_id
    }

    /// RLOC16 of the leader.
    pub fn leader_rloc16(&self) -> Rloc16 {
        Rloc16::from_router_id(self.leader_data.leader_router_id).unwrap_or(Rloc16::INVALID)
    }

    /// Path cost towards `dest` (`MAX_ROUTE_COST` if unreachable).
    pub fn path_cost(&self, dest: Rloc16) -> u8 {
        self.next_hop_and_path_cost(dest).1
    }

    /// Next hop and path cost towards `dest` for an end-device-only build
    /// (OT `RouterTable::GetNextHopAndPathCost` with no routing table: the
    /// only neighbor with a route is the parent).
    #[cfg(not(feature = "ftd"))]
    pub fn next_hop_and_path_cost(&self, dest: Rloc16) -> (Option<Rloc16>, u8) {
        use crate::consts::MAX_ROUTE_COST;
        if !self.role.is_attached() {
            return (None, MAX_ROUTE_COST);
        }
        if self.rloc16 == dest {
            return (Some(dest), 0);
        }
        let Some(parent) = &self.parent else {
            return (None, MAX_ROUTE_COST);
        };
        let p = &parent.router.neighbor;
        if !p.is_valid() || dest.router_id() != p.rloc16.router_id() {
            return (None, MAX_ROUTE_COST);
        }
        (Some(p.rloc16), p.link_info.link_quality_in().cost())
    }

    /// The child table (parent side).
    pub fn children(&self) -> &ChildTable<C> {
        &self.children
    }

    /// Mutable child table, for the layers that maintain registered
    /// addresses (Address Error handling removes a duplicate address).
    pub fn children_mut(&mut self) -> &mut ChildTable<C> {
        &mut self.children
    }

    /// `true` while an attach attempt is in progress.
    pub fn is_attaching(&self) -> bool {
        self.attach.is_attaching()
    }

    /// The device mode.
    pub fn device_mode(&self) -> crate::tlv::DeviceMode {
        self.cfg.mode
    }

    /// `true` if the device mode has the receiver on when idle.
    pub fn is_rx_on_when_idle(&self) -> bool {
        self.cfg.mode.rx_on_when_idle()
    }

    /// `true` for a full thread device.
    pub fn is_full_thread_device(&self) -> bool {
        self.cfg.mode.full_thread_device()
    }

    // ------------------------------------------------------------ life cycle

    /// Start Thread as a fresh device: detached, no RLOC16, attach as child
    /// (OT `Mle::Start` with an invalid RLOC16).
    pub fn start<E: MleEnv>(&mut self, env: &mut E, now: Instant) -> Result<()> {
        if self.role != Role::Disabled {
            return Err(Error::Already);
        }
        self.set_role(env, Role::Detached);
        self.set_rloc16(env, Rloc16::INVALID);
        self.attach.counter = 0;
        self.attach.reattach = crate::attach::ReattachState::Start;
        env.keys_mut().start(now);
        #[cfg(feature = "ftd")]
        {
            let mut b = [0u8; 1];
            env.fill_random(&mut b);
            self.rtr.id_sequence = b[0];
        }
        self.attach_begin(env, now, crate::attach::AttachMode::AnyPartition);
        Ok(())
    }

    /// Stop Thread: forget parent, children and timers, release the short
    /// address (OT `Mle::Stop`).
    pub fn stop<E: MleEnv>(&mut self, env: &mut E) {
        if self.role == Role::Disabled {
            return;
        }
        let detaching = core::mem::take(&mut self.attach.detaching);
        self.reset_to_detached(env);
        self.announce = crate::discovery::AnnounceCtx::new();
        self.announce_sender = crate::announce_sender::AnnounceSender::new();
        self.attach.reattach = crate::attach::ReattachState::Stop;
        env.keys_mut().stop();
        self.children.clear();
        self.set_role(env, Role::Disabled);
        if detaching {
            env.event(MleEvent::DetachedGracefully);
        }
    }

    /// Leave the network politely, then stop (OT `Mle::DetachGracefully`):
    /// a child sends a Child Update Request with timeout 0 to its parent, a
    /// router releases its router ID ([`MleEnv::release_router_id`]); after
    /// [`DETACH_GRACEFULLY_TIMEOUT`] (or as soon as the parent confirms the
    /// zero timeout) the device stops and raises
    /// [`MleEvent::DetachedGracefully`]. A device that is detached already
    /// stops at the next poll; a disabled one reports at once.
    pub fn detach_gracefully<E: MleEnv>(&mut self, env: &mut E, now: Instant) -> Result<()> {
        if self.attach.detaching {
            return Err(Error::Busy);
        }
        let mut timeout = DETACH_GRACEFULLY_TIMEOUT;
        match self.role {
            Role::Disabled => {
                env.event(MleEvent::DetachedGracefully);
                return Ok(());
            }
            Role::Leader => {}
            Role::Router =>
            {
                #[cfg(feature = "ftd")]
                if let Some(id) = self.router_id() {
                    env.release_router_id(Rloc16::from_router_id(id).unwrap_or(Rloc16::INVALID));
                }
            }
            Role::Child => {
                let _ = self.send_child_update_request_with(
                    env,
                    now,
                    crate::child::ChildUpdateMode::ZeroTimeout,
                );
            }
            Role::Detached => timeout = Duration::ZERO,
        }
        // A failed Child Update Request may have detached us already.
        self.attach.detaching = true;
        self.attach.deadline = Some(now.saturating_add(timeout));
        Ok(())
    }

    /// Change the device mode. A change between rx-on and sleepy takes
    /// effect through a Child Update Request when attached as a child.
    pub fn set_device_mode<E: MleEnv>(
        &mut self,
        env: &mut E,
        now: Instant,
        mode: DeviceMode,
    ) -> Result<()> {
        if mode == self.cfg.mode {
            return Ok(());
        }
        let ftd_changed = mode.full_thread_device() != self.cfg.mode.full_thread_device();
        self.cfg.mode = mode;
        if ftd_changed && self.role.is_attached() {
            // Switching between FTD and MTD needs a re-attach; becoming
            // detached drops the children and the router state (OT
            // `SetDeviceMode`).
            self.attach.counter = 0;
            self.become_detached(env, now);
            return Ok(());
        }
        if self.role == Role::Child {
            self.apply_rx_mode(env);
            self.sync_csl(env, now, false);
            self.recalculate_poll_period(env);
            let _ = self.send_child_update_request(env, now);
        }
        Ok(())
    }

    // ------------------------------------------------------------ role / address

    pub(crate) fn set_role<E: MleEnv>(&mut self, env: &mut E, role: Role) {
        if self.role != role {
            let old = self.role;
            self.role = role;
            self.store_pending |= role.is_attached();
            if role != Role::Child && self.csl_applied.is_some() {
                self.csl_applied = None;
                env.set_csl(0, 0, None);
            }
            env.event(MleEvent::RoleChanged { old, new: role });
        }
    }

    pub(crate) fn set_rloc16<E: MleEnv>(&mut self, env: &mut E, rloc16: Rloc16) {
        if self.rloc16 != rloc16 {
            self.rloc16 = rloc16;
            self.store_pending |= self.role.is_attached();
            env.set_short_address(rloc16);
            env.event(MleEvent::Rloc16Changed(rloc16));
        }
    }

    /// OT `SetStateDetached` + invalidating the parent: forget everything
    /// tied to the current attachment. Does not start an attach.
    pub(crate) fn reset_to_detached<E: MleEnv>(&mut self, env: &mut E) {
        self.set_role(env, Role::Detached);
        self.link_metrics.clear();
        self.attach.reset();
        self.child.reset();
        self.parent = None;
        env.set_parent(None);
        env.set_poll_period(None);
        env.set_rx_on_when_idle(true);
        self.set_rloc16(env, Rloc16::INVALID);
        #[cfg(feature = "ftd")]
        {
            self.parent_side_reset(env);
            self.router_reset_on_detach(env);
        }
    }

    /// Adopt Leader Data; a changed partition ID is a partition change (OT
    /// `SetLeaderData`): the router table of the old partition is void.
    pub(crate) fn update_leader_data<E: MleEnv>(&mut self, env: &mut E, ld: LeaderData) {
        if ld.partition_id != self.leader_data.partition_id {
            #[cfg(feature = "ftd")]
            self.handle_partition_change(env);
            self.leader_data = ld;
            env.event(MleEvent::PartitionChanged {
                partition_id: ld.partition_id,
            });
        } else {
            self.leader_data = ld;
        }
    }

    // ------------------------------------------------------------ timers

    /// The earliest instant at which [`poll`](Self::poll) has work to do.
    pub fn next_deadline(&self) -> Option<Instant> {
        let d = [
            self.attach.deadline,
            self.announce.deadline,
            self.announce_sender.deadline(),
            self.child.tx_deadline,
            self.child.supervision_deadline,
            self.child.update_deadline,
        ]
        .into_iter()
        .flatten()
        .min();
        #[cfg(feature = "ftd")]
        let d = [
            d,
            self.parent_deadline(),
            self.router_deadline(),
            self.discovery_deadline(),
        ]
        .into_iter()
        .flatten()
        .min();
        d
    }

    /// Run everything that is due at `now`.
    pub fn poll<E: MleEnv>(&mut self, env: &mut E, now: Instant) {
        if self.role == Role::Disabled {
            return;
        }
        if self.attach.deadline.is_some_and(|d| now >= d) {
            self.attach.deadline = None;
            self.handle_attach_timer(env, now);
        }
        self.poll_announce(env, now);
        self.poll_announce_sender(env, now);
        if self.child.tx_deadline.is_some_and(|d| now >= d) {
            self.child.tx_deadline = None;
            self.handle_message_tx_timer(env, now);
        }
        if self.child.supervision_deadline.is_some_and(|d| now >= d) {
            self.handle_supervision_timer(env, now);
        }
        self.poll_child_update_request(env, now);
        #[cfg(feature = "ftd")]
        {
            self.poll_parent(env, now);
            self.poll_router_link(env, now);
            self.poll_advert(env, now);
            self.poll_discovery(env, now);
            if self.rtr.tick.is_some_and(|t| now >= t) {
                self.router_tick(env, now);
            }
        }
        self.store_if_needed(env);
    }

    // ------------------------------------------------------------ receive

    /// Parse, authenticate and handle a datagram delivered to the MLE
    /// receiver. `scratch` receives the decrypted copy (at least as long as
    /// `payload`). Returns the dispatched command.
    pub fn receive<E: MleEnv>(
        &mut self,
        env: &mut E,
        now: Instant,
        meta: &UdpMeta,
        link: LinkRxInfo,
        payload: &[u8],
        scratch: &mut [u8],
    ) -> Result<Command> {
        let rx = match MleRx::parse(env.keys(), meta, link, payload, scratch) {
            Ok(rx) => rx,
            Err(e) => {
                let o = meta.peer.ip().octets();
                let iid: [u8; 8] = [o[8], o[9], o[10], o[11], o[12], o[13], o[14], o[15]];
                opentrust_core::warn!(
                    "MLE rx: parse/security failed: {:?} (peer iid {:x})",
                    e,
                    iid
                );
                return Err(e);
            }
        };
        // Discovery Responses are accepted while disabled (a scanner is
        // not attached).
        if self.role == Role::Disabled && rx.meta.security.is_some() {
            return Err(Error::InvalidState);
        }
        self.handle_rx(env, now, &rx)
    }

    /// Handle an already parsed message (OT `HandleUdpReceive` after
    /// decryption): neighbor lookup, replay protection, dispatch by command,
    /// key sequence adoption. Unsecured Discovery messages are ignored here.
    pub fn handle_rx<E: MleEnv>(
        &mut self,
        env: &mut E,
        now: Instant,
        rx: &MleRx<'_>,
    ) -> Result<Command> {
        let r = self.handle_rx_inner(env, now, rx);
        let attach_msg = matches!(
            rx.command,
            Command::ParentResponse | Command::ChildIdResponse
        );
        match &r {
            Err(e) => opentrust_core::warn!(
                "MLE rx: {:?} from {:x} dropped: {:?}",
                rx.command,
                rx.meta.sender_ext_address().0,
                e
            ),
            Ok(_) if attach_msg => opentrust_core::info!(
                "MLE rx: {:?} from {:x} handled",
                rx.command,
                rx.meta.sender_ext_address().0
            ),
            Ok(_) => {}
        }
        r
    }

    fn handle_rx_inner<E: MleEnv>(
        &mut self,
        env: &mut E,
        now: Instant,
        rx: &MleRx<'_>,
    ) -> Result<Command> {
        let Some(sec) = rx.meta.security else {
            return self.handle_unsecured(env, now, rx);
        };
        if self.role == Role::Disabled {
            return Err(Error::InvalidState);
        }
        #[cfg(feature = "ftd")]
        self.refresh_router_info();
        let ext = rx.meta.sender_ext_address();
        let nb = self.find_neighbor(&ext, rx.command == Command::ChildIdResponse);
        if let Some(r) = nb {
            let nf = env.noise_floor();
            let n = self.neighbor_mut(r);
            if n.is_valid() {
                n.mle_replay.check_and_update(&mut n.link_counters, &sec)?;
            }
            if let Some(rss) = rx.meta.link.rss {
                n.link_info.add_rss(nf, rss);
            }
        }
        let class = match rx.command {
            Command::ParentResponse => self.handle_parent_response(env, now, rx, nb)?,
            Command::ChildIdResponse => self.handle_child_id_response(env, now, rx, nb)?,
            Command::ChildUpdateRequest => self.handle_child_update_request(env, now, rx, nb)?,
            Command::ChildUpdateResponse => self.handle_child_update_response(env, now, rx, nb)?,
            Command::DataResponse => self.handle_data_response(env, now, rx, nb)?,
            Command::Advertisement => self.handle_advertisement(env, now, rx, nb)?,
            Command::Announce => self.handle_announce(env, now, rx)?,
            Command::LinkMetricsManagementRequest => {
                self.handle_link_metrics_management_request(env, rx, nb)?
            }
            Command::LinkMetricsManagementResponse => {
                self.handle_link_metrics_management_response(env, rx, nb)?
            }
            Command::LinkProbe => self.handle_link_probe(rx, nb)?,
            #[cfg(feature = "ftd")]
            Command::LinkRequest => self.handle_link_request(env, now, rx, nb)?,
            #[cfg(feature = "ftd")]
            Command::LinkAccept => self.handle_link_accept(env, now, rx, nb, false)?,
            #[cfg(feature = "ftd")]
            Command::LinkAcceptAndRequest => self.handle_link_accept(env, now, rx, nb, true)?,
            #[cfg(feature = "ftd")]
            Command::ParentRequest => self.handle_parent_request(env, now, rx)?,
            #[cfg(feature = "ftd")]
            Command::ChildIdRequest => self.handle_child_id_request(env, now, rx, nb)?,
            #[cfg(feature = "ftd")]
            Command::DataRequest => self.handle_data_request(env, now, rx, nb)?,
            _ => return Err(Error::Drop),
        };
        self.process_key_sequence(env, now, class, sec, nb);
        self.update_announce_sender(env, now);
        self.store_if_needed(env);
        Ok(rx.command)
    }

    /// Neighbor lookup for the replay check and handlers (OT
    /// `NeighborTable::FindNeighbor` / `FindParent`): the attached parent,
    /// the parent candidate once a Child ID Request went out, or a child,
    /// in state valid or restoring.
    pub(crate) fn find_neighbor(
        &self,
        ext: &opentrust_core::types::ExtAddress,
        parent_only: bool,
    ) -> Option<NbRef> {
        if let Some(p) = &self.parent {
            if p.router.neighbor.ext_address == *ext
                && p.router.neighbor.state.is_valid_or_restoring()
            {
                return Some(NbRef::Parent);
            }
        }
        if let Some(c) = &self.attach.candidate {
            if c.parent.router.neighbor.ext_address == *ext
                && c.parent.router.neighbor.state == NeighborState::Valid
            {
                return Some(NbRef::Candidate);
            }
        }
        if parent_only {
            return None;
        }
        #[cfg(feature = "ftd")]
        if let Some(r) = self
            .rtr
            .table
            .find_by_ext(ext, crate::neighbor::StateFilter::ValidOrRestoring)
        {
            return Some(NbRef::Router(r.router_id));
        }
        self.children
            .index_by_ext(ext, crate::neighbor::StateFilter::ValidOrRestoring)
            .map(NbRef::Child)
    }

    /// Replay protection for a received secured data frame (OT
    /// `MeshForwarder::HandleReceivedFrame` / `Mac::ProcessReceiveSecurity`):
    /// the key sequence and frame counter must not be older than the last
    /// ones accepted from the neighbor with MAC source address `src`, which
    /// are updated. Frames from addresses that are not a (valid or
    /// restoring) neighbor pass: MLE messages of attaching devices have
    /// their own replay protection.
    ///
    /// [`Error::Security`] for an older key sequence or a replayed
    /// counter, [`Error::Drop`] for an exact duplicate.
    pub fn check_link_frame(
        &mut self,
        src: opentrust_mac::frame::Address,
        key_sequence: u32,
        frame_counter: u32,
    ) -> Result<()> {
        use opentrust_mac::frame::Address;
        let nb = match src {
            Address::Extended(e) => self.find_neighbor(&e, false),
            Address::Short(s) => {
                let rloc = Rloc16(s.0);
                let f = crate::neighbor::StateFilter::ValidOrRestoring;
                if self.parent.as_ref().is_some_and(|p| {
                    p.router.neighbor.rloc16 == rloc
                        && p.router.neighbor.state.is_valid_or_restoring()
                }) {
                    Some(NbRef::Parent)
                } else {
                    #[cfg(feature = "ftd")]
                    let r = self
                        .rtr
                        .table
                        .find_by_rloc(rloc, f)
                        .map(|r| NbRef::Router(r.router_id));
                    #[cfg(not(feature = "ftd"))]
                    let r = None;
                    r.or_else(|| self.children.index_by_rloc(rloc, f).map(NbRef::Child))
                }
            }
            Address::None => None,
        };
        let Some(nb) = nb else { return Ok(()) };
        let n = self.neighbor_mut(nb);
        n.link_counters.check(key_sequence, frame_counter)?;
        n.link_counters.update(key_sequence, frame_counter);
        Ok(())
    }

    /// The network key changed: the key sequence restarts at 0 and the
    /// peers' outgoing frame counters restart with it, so forget the
    /// incoming key sequence and frame counters of the parent, the routers
    /// and the children (OT `KeyManager::ResetFrameCounters`).
    pub fn reset_frame_counters(&mut self) {
        let reset = |n: &mut Neighbor| {
            n.link_counters.reset();
            n.mle_replay.reset();
        };
        if let Some(p) = self.parent.as_mut() {
            reset(&mut p.router.neighbor);
        }
        #[cfg(feature = "ftd")]
        for r in self
            .rtr
            .table
            .iter_mut(crate::neighbor::StateFilter::AnyExceptInvalid)
        {
            reset(&mut r.neighbor);
        }
        for c in self
            .children
            .iter_mut(crate::neighbor::StateFilter::AnyExceptInvalid)
        {
            reset(&mut c.neighbor);
        }
    }

    pub(crate) fn neighbor_mut(&mut self, r: NbRef) -> &mut Neighbor {
        match r {
            NbRef::Parent => &mut self.parent.as_mut().expect("parent").router.neighbor,
            NbRef::Candidate => {
                &mut self
                    .attach
                    .candidate
                    .as_mut()
                    .expect("candidate")
                    .parent
                    .router
                    .neighbor
            }
            NbRef::Child(i) => &mut self.children.get_mut(i).expect("child").neighbor,
            #[cfg(feature = "ftd")]
            NbRef::Router(id) => &mut self.rtr.table.find_by_id_mut(id).expect("router").neighbor,
        }
    }

    pub(crate) fn neighbor_is_valid(&self, r: Option<NbRef>) -> bool {
        match r {
            None => false,
            Some(NbRef::Parent) => self
                .parent
                .as_ref()
                .is_some_and(|p| p.router.neighbor.is_valid()),
            Some(NbRef::Candidate) => self
                .attach
                .candidate
                .as_ref()
                .is_some_and(|c| c.parent.router.neighbor.is_valid()),
            Some(NbRef::Child(i)) => self.children.get(i).is_some_and(|c| c.neighbor.is_valid()),
            #[cfg(feature = "ftd")]
            Some(NbRef::Router(id)) => self
                .rtr
                .table
                .find_by_id(id)
                .is_some_and(|r| r.neighbor.is_valid()),
        }
    }

    /// OT `Mle::ProcessKeySequence`.
    pub(crate) fn process_key_sequence<E: MleEnv>(
        &mut self,
        env: &mut E,
        now: Instant,
        class: RxClass,
        sec: RxSecurity,
        nb: Option<NbRef>,
    ) {
        use opentrust_mac::security::KeySeqUpdate;
        let cur = env.keys().key_sequence();
        if sec.key_sequence <= cur {
            return;
        }
        let is_next = sec.key_sequence - cur == 1;
        let update = match class {
            RxClass::Unknown => return,
            RxClass::Authoritative => {
                if is_next {
                    KeySeqUpdate::FORCE_RESET_GUARD
                } else {
                    KeySeqUpdate::FORCE
                }
            }
            RxClass::Peer => {
                if !self.neighbor_is_valid(nb) {
                    return;
                }
                if !is_next {
                    // Large jump from a peer: do not adopt, re-sync the link.
                    self.reestablish_link(env, now, nb);
                    return;
                }
                KeySeqUpdate::GUARDED
            }
        };
        let _ = env
            .keys_mut()
            .set_key_sequence(sec.key_sequence, update, now);
    }

    /// OT `ReestablishLinkWithNeighbor`: probe the parent with a Child
    /// Update Request carrying a Challenge, a router neighbor with a Link
    /// Request and a child with a Child Update Request that carries a
    /// Challenge, so that the answer is an authoritative message.
    #[allow(clippy::needless_return)] // the FTD part follows
    fn reestablish_link<E: MleEnv>(&mut self, env: &mut E, now: Instant, nb: Option<NbRef>) {
        if nb == Some(NbRef::Parent) && self.role == Role::Child {
            let _ = self.send_child_update_request_with(
                env,
                now,
                crate::child::ChildUpdateMode::Challenge,
            );
            return;
        }
        #[cfg(feature = "ftd")]
        if self.is_full_thread_device() {
            match nb {
                Some(NbRef::Router(id)) => {
                    let _ = self.send_link_request(env, now, Some(id));
                }
                Some(NbRef::Child(i)) => {
                    // The state change makes the request carry a challenge
                    // (the child is no longer valid).
                    if let Some(c) = self.children.get_mut(i) {
                        c.neighbor.state = crate::neighbor::NeighborState::ChildUpdateRequest;
                    }
                    let _ = self.send_child_update_request_to_child(env, now, i);
                }
                _ => {}
            }
        }
    }

    // ------------------------------------------------------------ helpers

    pub(crate) fn rand_range<E: MleEnv>(env: &mut E, lo: u32, hi: u32) -> u32 {
        if hi <= lo {
            return lo;
        }
        let mut b = [0u8; 4];
        env.fill_random(&mut b);
        lo + u32::from_le_bytes(b) % (hi - lo)
    }

    #[cfg(feature = "ftd")]
    pub(crate) fn rand_duration<E: MleEnv>(
        env: &mut E,
        max: opentrust_core::time::Duration,
    ) -> opentrust_core::time::Duration {
        let ms = Self::rand_range(env, 0, max.as_millis().min(u64::from(u32::MAX)) as u32);
        opentrust_core::time::Duration::from_millis(u64::from(ms))
    }

    pub(crate) fn new_challenge<E: MleEnv>(env: &mut E) -> [u8; 8] {
        let mut c = [0u8; 8];
        env.fill_random(&mut c);
        c
    }

    /// Like [`send`](Self::send) with MAC-level options.
    pub(crate) fn send_with<E: MleEnv>(
        &mut self,
        env: &mut E,
        dst: Ipv6Addr,
        cmd: Command,
        opts: &TxOptions,
        build: impl FnOnce(&mut TlvWriter<'_>) -> Result<()>,
    ) -> Result<()> {
        tx_with(env, &mut self.mle_counter, dst, cmd, opts, build)
    }

    /// Build, secure and send one MLE message to `dst`.
    pub(crate) fn send<E: MleEnv>(
        &mut self,
        env: &mut E,
        dst: Ipv6Addr,
        cmd: Command,
        build: impl FnOnce(&mut TlvWriter<'_>) -> Result<()>,
    ) -> Result<()> {
        tx(env, &mut self.mle_counter, dst, cmd, build)
    }

    /// Address Registration entries: the ML-EID (compressed with context 0)
    /// and, unless `mesh_local_only`, the other registered addresses.
    pub(crate) fn address_entries<E: MleEnv>(
        env: &E,
        mesh_local_only: bool,
    ) -> Vec<
        AddressEntry,
        {
            1 + crate::env::MAX_REGISTERED_ADDRESSES
                + crate::env::MAX_REGISTERED_MULTICAST_ADDRESSES
        },
    > {
        let mut v = Vec::new();
        let _ = v.push(AddressEntry::Compressed {
            context_id: 0,
            iid: ipv6::iid(&env.ml_eid()).0,
        });
        if !mesh_local_only {
            env.registered_addresses(&mut |a| {
                let e = match env.lowpan_context_for(&a) {
                    Some(context_id) => AddressEntry::Compressed {
                        context_id,
                        iid: ipv6::iid(&a).0,
                    },
                    None => AddressEntry::Uncompressed(a),
                };
                let _ = v.push(e);
            });
            env.registered_multicast_addresses(&mut |a| {
                let _ = v.push(AddressEntry::Uncompressed(a));
            });
        }
        v
    }

    /// Our Thread version.
    pub(crate) const VERSION: u16 = THREAD_VERSION;
}

/// Build, secure (with `counter`) and send an MLE message.
pub(crate) fn tx<E: MleEnv>(
    env: &mut E,
    counter: &mut MleFrameCounter,
    dst: Ipv6Addr,
    cmd: Command,
    build: impl FnOnce(&mut TlvWriter<'_>) -> Result<()>,
) -> Result<()> {
    tx_with(env, counter, dst, cmd, &TxOptions::default(), build)
}

/// [`tx`] with MAC-level options.
pub(crate) fn tx_with<E: MleEnv>(
    env: &mut E,
    counter: &mut MleFrameCounter,
    dst: Ipv6Addr,
    cmd: Command,
    opts: &TxOptions,
    build: impl FnOnce(&mut TlvWriter<'_>) -> Result<()>,
) -> Result<()> {
    if !endpoint::is_valid_tx_destination(&dst) {
        return Err(Error::InvalidArgs);
    }
    let mut buf = [0u8; MAX_MLE_LEN];
    let mut b = MleBuilder::new(&mut buf, cmd)?;
    build(b.tlvs())?;
    let len = b.finish();
    let src = ipv6::link_local(&env.ext_address());
    let n = security::secure(env.keys(), counter, &mut buf, len, &src, &dst)?;
    if *opts == TxOptions::default() {
        env.send(src, dst, &buf[..n])
    } else {
        env.send_with(opts, src, dst, &buf[..n])
    }
}
