//! Domain Unicast Address (DUA) client, Thread 1.2 (OT `DuaManager`,
//! `thread/dua_manager.cpp`).
//!
//! A device in a Thread Domain (the Network Data has a Domain Prefix, see
//! [`BackboneRouterLeader`]) forms a Domain Unicast Address from the Domain
//! Prefix and a semantically opaque IID (RFC 7217 with a persisted DAD
//! counter) and registers it with the Primary Backbone Router with a
//! confirmable `/n/dr` DUA.req (Target and ML-EID IID TLVs). The response
//! (a piggybacked `/n/dr` answer or a later `/n/dn` DUA.ntf) carries a status:
//!
//! | status | action |
//! |---|---|
//! | success | the DUA is registered |
//! | re-register | remove and add the DUA again |
//! | invalid | remove the DUA |
//! | duplicate | increment the DAD counter and generate a new DUA |
//! | no resources, not primary, general failure | retry after a random delay up to the BBR's reregistration delay |
//!
//! A router that is the parent of end devices registers their DUAs on their
//! behalf ([`DuaManager::sync_children`], feature `ftd`): the child sends the
//! DUA in its Address Registration TLV, the parent sends the DUA.req with the
//! child's ML-EID IID and the Last Transaction Time and reports failures with
//! a DUA.ntf to the child.
//!
//! The manager is sans-IO. Feed it events (`handle_*`) and the current state
//! with [`DuaManager::poll`]; it adds and removes the DUA on the [`Netif`],
//! and returns the requests to send ([`DuaRequest`], [`ChildNotification`])
//! that [`send_dua_request`] and [`send_child_notification`] turn into TMF
//! messages. [`DuaManager::next_deadline`] says when to poll next.
//!
//! Differences from OT are listed in `OPENTRUST-OPENTHREAD-DIFFERENCES.md`.

use core::net::Ipv6Addr;

#[cfg(feature = "ftd")]
use heapless::Vec;
use rs_thread_coap::message::Code;
use rs_thread_coap::tmf::{Agent, UdpSink};
use rs_thread_coap::uri::Uri;
use rs_thread_core::bytes::Writer;
use rs_thread_core::crypto::CryptoBackend;
use rs_thread_core::message::Priority;
use rs_thread_core::time::{Duration, Instant};
use rs_thread_core::types::{ExtAddress, Iid, Prefix64, Rloc16};
use rs_thread_core::{Error, Result};
use rs_thread_net::netif::{AddressOrigin, Netif, UnicastAddress};
use rs_thread_net::slaac::{self, IidParams};
use rand_core::Rng;

use crate::netdata::NetworkDataView;
#[cfg(feature = "ftd")]
use crate::netdata::backbone::PARENT_AGGREGATE_DELAY;
use crate::netdata::backbone::{BackboneRouterLeader, DomainPrefixEvent};
use crate::netdata::notifier::DELAY_ROUTER_TRANSITION;
use crate::tlv::{ThreadTlv, ThreadTlvs, dua_status};

/// `user` value of the DUA.req in [`Agent::post`] and in the TMF responses /
/// failures.
pub const USER_DUA_REGISTRATION: u32 = 0x0a53_0010;
/// `user` value of the DUA.ntf a parent sends to a child.
pub const USER_DUA_NOTIFY: u32 = 0x0a53_0011;

/// Delay before registering a new router's DUA, to let it establish its
/// links (`kNewRouterRegistrationDelay`).
pub const NEW_ROUTER_REGISTRATION_DELAY: Duration = Duration::from_secs(3);
/// Delay before registering a newly added DUA (`kNewDuaRegistrationDelay`).
pub const NEW_DUA_REGISTRATION_DELAY: Duration = Duration::from_secs(1);
/// Time the DUA stays tentative before it becomes preferred
/// (`kDuaDadPeriod`).
pub const DUA_DAD_PERIOD: Duration = Duration::from_secs(100);
/// Retry delay when no message buffer was available (`kNoBufDelay`).
pub const NO_BUF_DELAY: Duration = Duration::from_secs(5);
/// Retry delay after the DUA.req timed out (`KResponseTimeoutDelay`).
pub const RESPONSE_TIMEOUT_DELAY: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
/// Registration state of this device's own DUA (OT `DuaState`).
pub enum DuaState {
    /// There is no DUA.
    NotExist,
    /// The DUA is to be registered.
    ToRegister,
    /// A DUA.req for the DUA is outstanding.
    Registering,
    /// The Primary Backbone Router accepted the DUA.
    Registered,
}

/// The device's situation, as far as the DUA manager needs it.
#[derive(Debug, Clone, Copy)]
pub struct DuaContext<'a> {
    /// Current time.
    pub now: Instant,
    /// Attached to a partition.
    pub attached: bool,
    /// The device is a router or leader.
    pub router_or_leader: bool,
    /// The device is a full Thread device (sends the DUA.req itself; an end
    /// device registers through its parent).
    pub full_thread_device: bool,
    /// A REED that is about to become a router (registration waits).
    pub expected_to_become_router: bool,
    /// An end device whose parent is a Thread 1.1 device: it registers its
    /// DUA itself, through the service ALOC of the Backbone Router service.
    pub parent_1p1: bool,
    /// Backbone Router state of the Network Data.
    pub bbr: &'a BackboneRouterLeader,
    /// Network Data (the DUA needs a 6LoWPAN context).
    pub netdata: NetworkDataView<'a>,
    /// IID of this device's ML-EID.
    pub ml_eid_iid: Iid,
}

/// A DUA.req to send to the Primary Backbone Router.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DuaRequest {
    /// RLOC16 of the Primary Backbone Router.
    pub server16: u16,
    /// Send to the service ALOC of this Backbone Router service ID instead.
    pub service_id: Option<u8>,
    /// Target EID TLV: the DUA.
    pub target: Ipv6Addr,
    /// ML-EID TLV: IID of the ML-EID of the DUA's owner.
    pub ml_eid_iid: Iid,
    /// Last Transaction Time TLV: seconds since a child was last heard
    /// (`None` for this device's own DUA).
    pub last_transaction_time: Option<u32>,
}

/// A DUA.ntf to send to a child whose DUA registration failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChildNotification {
    /// RLOC16 of the child.
    pub child: Rloc16,
    /// Extended address of the child.
    pub ext: ExtAddress,
    /// The child's DUA.
    pub target: Ipv6Addr,
    /// Status TLV ([`dua_status`]).
    pub status: u8,
    /// The status is fatal for the address (invalid, duplicate): the
    /// caller removes `target` from the child's addresses
    /// ([`Child::remove_address`](rs_thread_mle::neighbor::Child::remove_address)).
    pub remove_address: bool,
}

/// How a DUA.req ended.
#[derive(Debug, Clone, Copy)]
pub enum DuaResult<'a> {
    /// No answer in time.
    Timeout,
    /// The exchange failed otherwise (reset, no buffers).
    Failed,
    /// An answer arrived.
    Response {
        /// CoAP code.
        code: Code,
        /// Payload (Status and Target EID TLVs).
        payload: &'a [u8],
    },
}

#[cfg(feature = "ftd")]
#[derive(Debug, Clone, Copy)]
struct ChildDua {
    ext: ExtAddress,
    rloc16: Rloc16,
    dua: Ipv6Addr,
    ml_eid_iid: Iid,
    last_heard: Instant,
    registered: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Pending {
    No,
    Own,
    #[cfg(feature = "ftd")]
    Child(ExtAddress),
}

/// Keep the earliest of `slot` and `t`.
fn earliest(slot: &mut Option<Instant>, t: Instant) {
    if slot.is_none_or(|s| t < s) {
        *slot = Some(t);
    }
}

/// Random delay in `1..=max` seconds.
fn random_secs<R: Rng + ?Sized>(rng: &mut R, max: u32) -> Duration {
    Duration::from_secs(u64::from(1 + rng.next_u32() % max.max(1)))
}

/// The DUA manager (OT `DuaManager`); `CH` bounds the children whose DUAs
/// are registered by proxy.
#[derive(Debug)]
pub struct DuaManager<const CH: usize = 8> {
    state: DuaState,
    dua: Option<(Ipv6Addr, u8)>,
    dad_counter: u8,
    dad_counter_changed: bool,
    fixed_iid: Option<Iid>,
    last_registration: Instant,
    preferred: bool,
    registration_delay: Option<Instant>,
    reregistration_delay: Option<Instant>,
    check_delay: Option<Instant>,
    task_pending: bool,
    pending: Pending,
    registering_dua: Option<Ipv6Addr>,
    #[cfg(feature = "ftd")]
    children: Vec<ChildDua, CH>,
}

impl<const CH: usize> Default for DuaManager<CH> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const CH: usize> DuaManager<CH> {
    /// A manager without DUA and with DAD counter 0.
    pub const fn new() -> Self {
        Self {
            state: DuaState::NotExist,
            dua: None,
            dad_counter: 0,
            dad_counter_changed: false,
            fixed_iid: None,
            last_registration: Instant::from_millis(0),
            preferred: false,
            registration_delay: None,
            reregistration_delay: None,
            check_delay: None,
            task_pending: false,
            pending: Pending::No,
            registering_dua: None,
            #[cfg(feature = "ftd")]
            children: Vec::new(),
        }
    }

    /// Restore the DAD counter from settings (OT `Restore`).
    pub fn restore(&mut self, dad_counter: u8) {
        self.dad_counter = dad_counter;
    }

    /// The DAD counter.
    pub const fn dad_counter(&self) -> u8 {
        self.dad_counter
    }

    /// The DAD counter if it changed since the last call, for the caller to
    /// persist (OT `Store`).
    pub fn take_dad_counter_update(&mut self) -> Option<u8> {
        core::mem::take(&mut self.dad_counter_changed).then_some(self.dad_counter)
    }

    /// Registration state of this device's DUA.
    pub const fn state(&self) -> DuaState {
        self.state
    }

    /// This device's DUA, if there is one.
    pub fn domain_unicast_address(&self) -> Option<Ipv6Addr> {
        self.dua.map(|d| d.0)
    }

    /// The fixed IID, if one is set.
    pub const fn fixed_iid(&self) -> Option<&Iid> {
        self.fixed_iid.as_ref()
    }

    /// The DUA IID of `addr` is the fixed one.
    fn dua_has_fixed_iid(&self) -> bool {
        match (self.dua, self.fixed_iid) {
            (Some((a, _)), Some(f)) => rs_thread_core::types::ipv6::iid(&a) == f,
            _ => false,
        }
    }

    // --------------------------------------------------------------- DUA

    fn generate<B: CryptoBackend, const U: usize, const M: usize>(
        &mut self,
        prefix: &crate::netdata::tlv::NetPrefix,
        params: &IidParams<'_, B>,
    ) -> Result<(Ipv6Addr, u8)> {
        if prefix.len() > 64 {
            return Err(Error::InvalidArgs);
        }
        let mut p = [0u8; 8];
        p.copy_from_slice(&prefix.octets()[..8]);
        let p = Prefix64(p);
        let iid = if let Some(f) = self.fixed_iid {
            f
        } else {
            let mut counter = self.dad_counter;
            let iid = slaac::generate_iid(
                params.backend,
                &p,
                prefix.len(),
                params.network_id,
                &mut counter,
                params.secret,
            )?;
            if counter != self.dad_counter {
                self.dad_counter = counter;
                self.dad_counter_changed = true;
            }
            iid
        };
        Ok((p.with_iid(&iid), prefix.len()))
    }

    fn generate_and_add<B: CryptoBackend, const U: usize, const M: usize>(
        &mut self,
        ctx: &DuaContext<'_>,
        netif: &mut Netif<U, M>,
        params: &IidParams<'_, B>,
    ) {
        let Some(prefix) = ctx.bbr.domain_prefix() else {
            return;
        };
        if let Ok(d) = self.generate::<B, U, M>(prefix, params) {
            self.dua = Some(d);
            self.add_dua(ctx.now, netif);
        }
    }

    fn add_dua<const U: usize, const M: usize>(&mut self, now: Instant, netif: &mut Netif<U, M>) {
        let Some((addr, prefix_len)) = self.dua else {
            return;
        };
        self.state = DuaState::ToRegister;
        self.last_registration = now;
        self.preferred = false;
        let ua = UnicastAddress {
            addr,
            prefix_len,
            origin: AddressOrigin::Thread,
            preferred: false,
            valid: true,
            scope_override: None,
            rloc: false,
            mesh_local: false,
        };
        if netif.add_unicast(ua).is_err() && !netif.has_unicast(&addr) {
            self.state = DuaState::NotExist;
            return;
        }
        // OT: `kEventIp6AddressAdded` -> `UpdateRegistrationDelay`.
        earliest(
            &mut self.registration_delay,
            now + NEW_DUA_REGISTRATION_DELAY,
        );
    }

    fn remove_dua<const U: usize, const M: usize>(&mut self, netif: &mut Netif<U, M>) {
        if self.state == DuaState::Registering && self.pending == Pending::Own {
            // The late answer is dropped: the address is gone.
            self.pending = Pending::No;
        }
        self.state = DuaState::NotExist;
        self.preferred = false;
        if let Some((addr, _)) = self.dua {
            let _ = netif.remove_unicast(&addr);
        }
    }

    /// The Domain Prefix changed (OT `HandleDomainPrefixUpdate`): a removed
    /// or changed prefix drops the DUA (and the proxied children), an added
    /// or changed one forms a new DUA and puts it on the interface.
    pub fn handle_domain_prefix_event<B: CryptoBackend, const U: usize, const M: usize>(
        &mut self,
        event: DomainPrefixEvent,
        ctx: &DuaContext<'_>,
        netif: &mut Netif<U, M>,
        params: &IidParams<'_, B>,
    ) {
        if matches!(
            event,
            DomainPrefixEvent::Removed | DomainPrefixEvent::Refreshed
        ) {
            if self.pending != Pending::No {
                self.pending = Pending::No;
            }
            self.remove_dua(netif);
            #[cfg(feature = "ftd")]
            self.children.clear();
        }
        let have = self.dua.is_some_and(|(a, _)| netif.has_unicast(&a));
        match event {
            DomainPrefixEvent::Unchanged if have => {}
            DomainPrefixEvent::Unchanged
            | DomainPrefixEvent::Refreshed
            | DomainPrefixEvent::Added => self.generate_and_add(ctx, netif, params),
            DomainPrefixEvent::Removed | DomainPrefixEvent::None => {}
        }
    }

    /// The Network Data changed: a DUA without a 6LoWPAN context in Network
    /// Data is removed (OT `HandleNotifierEvents`). It is formed again with
    /// the next [`DomainPrefixEvent::Unchanged`] / `Refreshed`.
    pub fn handle_netdata_changed<const U: usize, const M: usize>(
        &mut self,
        netdata: &NetworkDataView<'_>,
        netif: &mut Netif<U, M>,
    ) {
        if let Some((a, _)) = self.dua
            && netif.has_unicast(&a)
            && netdata.context_for_address(&a).is_none()
        {
            self.remove_dua(netif);
        }
    }

    /// The Primary Backbone Router changed (OT
    /// `HandleBackboneRouterPrimaryUpdate`): a new or moved one makes the
    /// device reregister after a random delay.
    pub fn handle_backbone_router_update<R: Rng + ?Sized>(
        &mut self,
        state: crate::netdata::backbone::BbrState,
        ctx: &DuaContext<'_>,
        rng: &mut R,
    ) {
        use crate::netdata::backbone::BbrState;
        if matches!(state, BbrState::Added | BbrState::ToTriggerRereg)
            && (ctx.full_thread_device || ctx.parent_1p1)
        {
            self.update_reregistration_delay(ctx, rng);
        }
    }

    /// The Thread role changed (OT `HandleNotifierEvents`, role event).
    /// `restored`: the device came back from a reset with its state
    /// restored.
    pub fn handle_role_changed<R: Rng + ?Sized>(
        &mut self,
        ctx: &DuaContext<'_>,
        restored: bool,
        rng: &mut R,
    ) {
        if !ctx.attached {
            self.clear_delays();
            return;
        }
        if restored {
            self.update_reregistration_delay(ctx, rng);
        } else if ctx.full_thread_device && ctx.router_or_leader {
            earliest(
                &mut self.registration_delay,
                ctx.now + NEW_ROUTER_REGISTRATION_DELAY,
            );
        } else if ctx.full_thread_device && ctx.expected_to_become_router {
            earliest(
                &mut self.registration_delay,
                ctx.now + DELAY_ROUTER_TRANSITION + NEW_ROUTER_REGISTRATION_DELAY,
            );
        }
    }

    fn clear_delays(&mut self) {
        self.registration_delay = None;
        self.reregistration_delay = None;
        self.check_delay = None;
    }

    fn update_reregistration_delay<R: Rng + ?Sized>(&mut self, ctx: &DuaContext<'_>, rng: &mut R) {
        let Some(c) = ctx.bbr.config() else {
            return;
        };
        let secs = if c.reregistration_delay > 1 {
            random_secs(rng, u32::from(c.reregistration_delay))
        } else {
            Duration::from_secs(1)
        };
        earliest(&mut self.reregistration_delay, ctx.now + secs);
    }

    /// Replace the fixed DUA IID (OT `SetFixedDuaInterfaceIdentifier`);
    /// [`Error::InvalidArgs`] for a reserved IID.
    pub fn set_fixed_iid<B: CryptoBackend, const U: usize, const M: usize>(
        &mut self,
        iid: Iid,
        ctx: &DuaContext<'_>,
        netif: &mut Netif<U, M>,
        params: &IidParams<'_, B>,
    ) -> Result<()> {
        if rs_thread_net::addr::iid_is_reserved(&iid) {
            return Err(Error::InvalidArgs);
        }
        if self.fixed_iid == Some(iid) {
            return Ok(());
        }
        self.fixed_iid = Some(iid);
        if self.dua.is_some_and(|(a, _)| netif.has_unicast(&a)) {
            self.remove_dua(netif);
            self.generate_and_add(ctx, netif, params);
        }
        Ok(())
    }

    /// Go back to generated IIDs (OT `ClearFixedDuaInterfaceIdentifier`).
    pub fn clear_fixed_iid<B: CryptoBackend, const U: usize, const M: usize>(
        &mut self,
        ctx: &DuaContext<'_>,
        netif: &mut Netif<U, M>,
        params: &IidParams<'_, B>,
    ) {
        if self.fixed_iid.is_none() {
            return;
        }
        let using =
            self.dua_has_fixed_iid() && self.dua.is_some_and(|(a, _)| netif.has_unicast(&a));
        self.fixed_iid = None;
        if using {
            self.remove_dua(netif);
            self.generate_and_add(ctx, netif, params);
        }
    }

    /// The DUA is reported as a duplicate (a DUA.rsp with status duplicate,
    /// or an Address Error for it): form a new one with the next DAD counter
    /// (OT `NotifyDuplicateDomainUnicastAddress`).
    pub fn notify_duplicate<B: CryptoBackend, const U: usize, const M: usize>(
        &mut self,
        ctx: &DuaContext<'_>,
        netif: &mut Netif<U, M>,
        params: &IidParams<'_, B>,
    ) {
        self.remove_dua(netif);
        self.dad_counter = self.dad_counter.wrapping_add(1);
        self.dad_counter_changed = true;
        self.generate_and_add(ctx, netif, params);
    }

    // ---------------------------------------------------------- children

    /// Take over the DUAs of the valid children `children` (OT
    /// `HandleChildDuaAddressEvent`, driven by the Address Registration of
    /// the children): a new or changed DUA is registered after a random
    /// aggregation delay.
    #[cfg(feature = "ftd")]
    pub fn sync_children<'a, R: Rng + ?Sized>(
        &mut self,
        ctx: &DuaContext<'_>,
        children: impl Iterator<Item = &'a rs_thread_mle::neighbor::Child>,
        rng: &mut R,
    ) {
        let mut seen: Vec<ExtAddress, CH> = Vec::new();
        for c in children {
            let ext = c.neighbor.ext_address;
            let _ = seen.push(ext);
            let dua = c
                .addresses()
                .iter()
                .copied()
                .find(|a| ctx.bbr.is_domain_unicast(a));
            let idx = self.children.iter().position(|e| e.ext == ext);
            match (idx, dua, c.ml_eid_iid()) {
                (Some(i), Some(d), Some(_)) if self.children[i].dua == d => {
                    self.children[i].rloc16 = c.neighbor.rloc16;
                    self.children[i].last_heard = c.neighbor.last_heard;
                }
                (old, new, iid) => {
                    if old.is_some() {
                        self.remove_child(ext);
                    }
                    if let (Some(d), Some(iid)) = (new, iid) {
                        let all_registered = self.children.iter().all(|e| e.registered);
                        let e = ChildDua {
                            ext,
                            rloc16: c.neighbor.rloc16,
                            dua: d,
                            ml_eid_iid: *iid,
                            last_heard: c.neighbor.last_heard,
                            registered: false,
                        };
                        if self.children.push(e).is_ok() && all_registered {
                            let d = random_secs(rng, u32::from(PARENT_AGGREGATE_DELAY));
                            earliest(&mut self.check_delay, ctx.now + d);
                        }
                    }
                }
            }
        }
        // Children that are gone.
        let gone: Vec<ExtAddress, CH> = self
            .children
            .iter()
            .map(|e| e.ext)
            .filter(|e| !seen.contains(e))
            .collect();
        for e in gone {
            self.remove_child(e);
        }
    }

    #[cfg(feature = "ftd")]
    fn remove_child(&mut self, ext: ExtAddress) {
        if self.pending == Pending::Child(ext) {
            self.pending = Pending::No;
        }
        self.children.retain(|e| e.ext != ext);
    }

    /// Number of children whose DUA is tracked, and how many of them are
    /// registered.
    #[cfg(feature = "ftd")]
    pub fn child_counts(&self) -> (usize, usize) {
        (
            self.children.len(),
            self.children.iter().filter(|c| c.registered).count(),
        )
    }

    // ------------------------------------------------------------- timers

    /// The next time [`poll`](Self::poll) has something to do.
    pub fn next_deadline(&self) -> Option<Instant> {
        let dad = (self.state != DuaState::NotExist && !self.preferred)
            .then(|| self.last_registration + DUA_DAD_PERIOD);
        [
            self.registration_delay,
            self.reregistration_delay,
            self.check_delay,
            dad,
        ]
        .into_iter()
        .flatten()
        .min()
    }

    /// `true` if [`poll`](Self::poll) should be called now without waiting
    /// for a deadline (a response was handled).
    pub const fn needs_poll(&self) -> bool {
        self.task_pending
    }

    /// Run the timers and, if one expired or an answer was handled, start the
    /// next registration (OT `HandleTimeTick` and `PerformNextRegistration`).
    /// Returns the DUA.req to send; the manager then waits for
    /// [`handle_result`](Self::handle_result).
    pub fn poll<const U: usize, const M: usize>(
        &mut self,
        ctx: &DuaContext<'_>,
        netif: &mut Netif<U, M>,
    ) -> Option<DuaRequest> {
        let now = ctx.now;
        if !ctx.attached {
            self.clear_delays();
            self.task_pending = false;
            return None;
        }
        if self.state != DuaState::NotExist
            && !self.preferred
            && now > self.last_registration + DUA_DAD_PERIOD
        {
            self.preferred = true;
            if let Some((a, _)) = self.dua {
                let _ = netif.set_preferred(&a, true);
            }
        }
        let expired = |slot: &mut Option<Instant>| {
            if slot.is_some_and(|t| now >= t) {
                *slot = None;
                true
            } else {
                false
            }
        };
        let mut attempt = core::mem::take(&mut self.task_pending);
        attempt |= expired(&mut self.registration_delay);
        attempt |= expired(&mut self.check_delay);
        if expired(&mut self.reregistration_delay) {
            if self.state != DuaState::NotExist {
                self.state = DuaState::ToRegister;
            }
            #[cfg(feature = "ftd")]
            for c in &mut self.children {
                c.registered = false;
            }
            attempt = true;
        }
        if !attempt {
            return None;
        }
        self.perform_next_registration(ctx)
    }

    fn perform_next_registration(&mut self, ctx: &DuaContext<'_>) -> Option<DuaRequest> {
        let now = ctx.now;
        let bbr = ctx.bbr.config()?;
        if self.pending != Pending::No {
            return None;
        }
        if ctx.expected_to_become_router && !ctx.router_or_leader {
            earliest(
                &mut self.registration_delay,
                now + DELAY_ROUTER_TRANSITION + NEW_ROUTER_REGISTRATION_DELAY,
            );
            return None;
        }
        if !ctx.full_thread_device && !ctx.parent_1p1 {
            return None;
        }
        let service_id = if ctx.full_thread_device {
            None
        } else {
            Some(crate::netdata::backbone::backbone_router_service_id(
                &ctx.netdata,
            )?)
        };
        let req = if self.state == DuaState::ToRegister && self.registration_delay.is_none() {
            let (target, _) = self.dua?;
            self.state = DuaState::Registering;
            self.last_registration = now;
            self.pending = Pending::Own;
            DuaRequest {
                server16: bbr.server16,
                service_id,
                target,
                ml_eid_iid: ctx.ml_eid_iid,
                last_transaction_time: None,
            }
        } else {
            self.next_child_request(now, bbr.server16)?
        };
        self.registering_dua = Some(req.target);
        if req.last_transaction_time.is_none() {
            self.clear_delays();
        } else {
            // OT clears the other delays as well, which loses a pending
            // retry of this device's own DUA while a child is registered.
            self.check_delay = None;
        }
        Some(req)
    }

    #[cfg(feature = "ftd")]
    fn next_child_request(&mut self, now: Instant, server16: u16) -> Option<DuaRequest> {
        let c = self.children.iter().find(|c| !c.registered)?;
        self.pending = Pending::Child(c.ext);
        Some(DuaRequest {
            server16,
            service_id: None,
            target: c.dua,
            ml_eid_iid: c.ml_eid_iid,
            last_transaction_time: Some(
                u32::try_from(now.saturating_duration_since(c.last_heard).as_secs())
                    .unwrap_or(u32::MAX),
            ),
        })
    }

    #[cfg(not(feature = "ftd"))]
    fn next_child_request(&mut self, _now: Instant, _server16: u16) -> Option<DuaRequest> {
        None
    }

    /// The DUA.req could not be sent (no buffers): retry soon (OT
    /// `kNoBufDelay`).
    pub fn request_not_sent(&mut self, now: Instant) {
        self.pending = Pending::No;
        if self.state == DuaState::Registering {
            self.state = DuaState::ToRegister;
        }
        earliest(&mut self.check_delay, now + NO_BUF_DELAY);
    }

    // ---------------------------------------------------------- responses

    /// The outcome of the DUA.req started by [`poll`](Self::poll) (OT
    /// `HandleDuaResponse`). Returns the notification to send to a child
    /// whose registration failed.
    pub fn handle_result<B: CryptoBackend, R: Rng + ?Sized, const U: usize, const M: usize>(
        &mut self,
        ctx: &DuaContext<'_>,
        result: DuaResult<'_>,
        rng: &mut R,
        netif: &mut Netif<U, M>,
        params: &IidParams<'_, B>,
    ) -> Option<ChildNotification> {
        let was_pending = self.pending;
        self.pending = Pending::No;
        let (status, target) = match result {
            DuaResult::Timeout => {
                // The DUA stays "registering" until the retry.
                if self.state == DuaState::Registering && was_pending == Pending::Own {
                    self.state = DuaState::ToRegister;
                }
                earliest(&mut self.check_delay, ctx.now + RESPONSE_TIMEOUT_DELAY);
                return None;
            }
            DuaResult::Failed => {
                self.task_pending = true;
                return None;
            }
            DuaResult::Response { code, payload } => {
                if code != Code::CHANGED && code.class() < 4 {
                    self.task_pending = true;
                    return None;
                }
                match Self::parse_status(code, payload, self.registering_dua) {
                    Some(v) => v,
                    None => {
                        self.task_pending = true;
                        return None;
                    }
                }
            }
        };
        self.task_pending = true;
        self.process(ctx, status, target, rng, netif, params)
    }

    fn parse_status(
        code: Code,
        payload: &[u8],
        registering: Option<Ipv6Addr>,
    ) -> Option<(u8, Ipv6Addr)> {
        if code.class() >= 4 {
            return Some((dua_status::GENERAL_FAILURE, registering?));
        }
        let t = ThreadTlvs::new(payload);
        Some((t.status().ok()?, t.target().ok()?))
    }

    /// A DUA.ntf (`/n/dn`) arrived (OT `HandleTmf<kUriDuaRegistrationNotify>`):
    /// the Primary Backbone Router or our parent reports the status of a
    /// registration. The caller acknowledges a confirmable request.
    pub fn handle_notify<B: CryptoBackend, R: Rng + ?Sized, const U: usize, const M: usize>(
        &mut self,
        ctx: &DuaContext<'_>,
        payload: &[u8],
        rng: &mut R,
        netif: &mut Netif<U, M>,
        params: &IidParams<'_, B>,
    ) -> Option<ChildNotification> {
        let (status, target) = Self::parse_status(Code::CHANGED, payload, None)?;
        self.process(ctx, status, target, rng, netif, params)
    }

    fn process<B: CryptoBackend, R: Rng + ?Sized, const U: usize, const M: usize>(
        &mut self,
        ctx: &DuaContext<'_>,
        status: u8,
        target: Ipv6Addr,
        rng: &mut R,
        netif: &mut Netif<U, M>,
        params: &IidParams<'_, B>,
    ) -> Option<ChildNotification> {
        if !ctx.bbr.is_domain_unicast(&target) {
            return None;
        }
        if netif.has_unicast(&target) {
            match status {
                dua_status::SUCCESS => {
                    self.last_registration = ctx.now;
                    self.state = DuaState::Registered;
                }
                dua_status::RE_REGISTER => {
                    self.remove_dua(netif);
                    self.add_dua(ctx.now, netif);
                }
                dua_status::INVALID => self.remove_dua(netif),
                dua_status::DUPLICATE => self.notify_duplicate(ctx, netif, params),
                _ => self.update_reregistration_delay(ctx, rng),
            }
            return None;
        }
        self.process_child(ctx, status, target, rng)
    }

    #[cfg(feature = "ftd")]
    fn process_child<R: Rng + ?Sized>(
        &mut self,
        ctx: &DuaContext<'_>,
        status: u8,
        target: Ipv6Addr,
        rng: &mut R,
    ) -> Option<ChildNotification> {
        let i = self.children.iter().position(|c| c.dua == target)?;
        let c = self.children[i];
        let mut remove_address = false;
        match status {
            dua_status::SUCCESS => self.children[i].registered = true,
            dua_status::RE_REGISTER => {
                self.children.swap_remove(i);
            }
            dua_status::INVALID | dua_status::DUPLICATE => {
                remove_address = true;
                self.children.swap_remove(i);
            }
            _ => self.update_reregistration_delay(ctx, rng),
        }
        (status != dua_status::SUCCESS).then_some(ChildNotification {
            child: c.rloc16,
            ext: c.ext,
            target,
            status,
            remove_address,
        })
    }

    #[cfg(not(feature = "ftd"))]
    fn process_child<R: Rng + ?Sized>(
        &mut self,
        _ctx: &DuaContext<'_>,
        _status: u8,
        _target: Ipv6Addr,
        _rng: &mut R,
    ) -> Option<ChildNotification> {
        None
    }
}

/// Encode the payload of a DUA.req.
pub fn build_dua_request(req: &DuaRequest, out: &mut [u8]) -> Result<usize> {
    let mut w = Writer::new(out);
    ThreadTlv::Target(req.target).write(&mut w)?;
    ThreadTlv::MeshLocalEid(req.ml_eid_iid).write(&mut w)?;
    if let Some(t) = req.last_transaction_time {
        ThreadTlv::LastTransactionTime(t).write(&mut w)?;
    }
    Ok(w.len())
}

/// Encode the payload of a DUA.ntf / DUA.rsp: Status and Target EID TLVs.
pub fn build_dua_status(status: u8, target: &Ipv6Addr, out: &mut [u8]) -> Result<usize> {
    let mut w = Writer::new(out);
    ThreadTlv::Status(status).write(&mut w)?;
    ThreadTlv::Target(*target).write(&mut w)?;
    Ok(w.len())
}

/// Send a DUA.req to the Primary Backbone Router's RLOC: confirmable, net
/// priority, from our RLOC (OT `PerformNextRegistration`).
#[allow(clippy::too_many_arguments)]
pub fn send_dua_request<
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
    mesh_local_prefix: &Prefix64,
    own_rloc16: Rloc16,
    req: &DuaRequest,
) -> Result<()> {
    let mut buf = [0u8; 48];
    let n = build_dua_request(req, &mut buf)?;
    agent.post(
        now,
        rng,
        sink,
        match req.service_id {
            Some(id) => mesh_local_prefix.aloc(0xfc10 + u16::from(id))?,
            None => mesh_local_prefix.rloc(Rloc16(req.server16)),
        },
        Some(mesh_local_prefix.rloc(own_rloc16)),
        Priority::Net,
        Uri::DuaRegistrationRequest,
        &buf[..n],
        Some(USER_DUA_REGISTRATION),
    )
}

/// Send a DUA.ntf to a child (OT `SendAddressNotification`).
pub fn send_child_notification<
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
    mesh_local_prefix: &Prefix64,
    own_rloc16: Rloc16,
    n: &ChildNotification,
) -> Result<()> {
    let mut buf = [0u8; 32];
    let len = build_dua_status(n.status, &n.target, &mut buf)?;
    agent.post(
        now,
        rng,
        sink,
        mesh_local_prefix.rloc(n.child),
        Some(mesh_local_prefix.rloc(own_rloc16)),
        Priority::Net,
        Uri::DuaRegistrationNotify,
        &buf[..len],
        Some(USER_DUA_NOTIFY),
    )
}
