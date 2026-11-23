//! Backbone Router service of this device, Thread 1.2 (OT
//! `BackboneRouter::Local`, the `/n/dr` and `/n/mr` handlers of
//! `BackboneRouter::Manager`, `MulticastListenersTable`, `NdProxyTable`).
//!
//! A device with the Backbone Router role registers the BBR service in the
//! Network Data and, once the Leader picks it, becomes the Primary Backbone
//! Router: it answers the Domain Unicast Address registrations (`/n/dr`) and
//! Multicast Listener registrations (`/n/mr`) of the Thread network and
//! answers on the Backbone anycast locator address `0xfc38`.
//!
//! The Backbone Link is not implemented: there is no DAD on the link, no
//! ND proxying of the registered Domain Unicast Addresses, no Backbone
//! Query / Answer and no multicast routing to the link; the registrations
//! are answered from the local tables.
//!
//! The state is sans-IO: the Network Data and time go in, the
//! [`ServiceAction`] to apply to the local Network Data comes out.

use core::net::Ipv6Addr;

use heapless::Vec;
use rand_core::Rng;
use rs_thread_core::time::{Duration, Instant};
use rs_thread_core::types::Iid;
use rs_thread_core::{Error, Result};

use crate::dua::build_dua_status;
use crate::mlr::{MAX_MLR_ADDRESSES, build_mlr_response};
use crate::netdata::backbone::{
    BackboneRouterLeader, BbrConfig, DEFAULT_MLR_TIMEOUT, DEFAULT_REGISTRATION_DELAY,
    MAX_MLR_TIMEOUT,
};
use crate::tlv::{ThreadTlvs, dua_status, mlr_status};

/// Default registration jitter, seconds (`kDefaultRegistrationJitter`).
pub const DEFAULT_REGISTRATION_JITTER: u8 = 5;
/// Anycast locator of the Primary Backbone Router (`kAloc16BackboneRouterPrimary`).
pub const ALOC16_PRIMARY_BBR: u16 = 0xfc38;
/// Multicast listeners of the table (OT: 75).
pub const MAX_LISTENERS: usize = 75;
/// Registered DUAs of the ND proxy table (OT: 64).
pub const MAX_PROXIES: usize = 8;

/// State of the Backbone Router service (OT `BackboneRouter::State`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum LocalState {
    /// Not a Backbone Router.
    Disabled,
    /// Backbone Router, not the Primary.
    Secondary,
    /// The Primary Backbone Router.
    Primary,
}

/// What to do with the local Network Data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum ServiceAction {
    /// Nothing.
    None,
    /// Add (or replace) the BBR service with this dataset and register it.
    Add(BbrConfig),
    /// Remove the BBR service and register.
    Remove,
}

/// What the server needs to know about the device.
#[derive(Debug, Clone, Copy)]
pub struct BbrContext<'a> {
    /// Attached to a partition.
    pub attached: bool,
    /// Leader role.
    pub is_leader: bool,
    /// Own RLOC16.
    pub rloc16: u16,
    /// The Primary Backbone Router as seen in the Network Data.
    pub leader: &'a BackboneRouterLeader,
}

/// Multicast listeners (OT `MulticastListenersTable`).
#[derive(Debug, Default, Clone)]
pub struct MulticastListeners {
    v: Vec<(Ipv6Addr, Instant), MAX_LISTENERS>,
}

impl MulticastListeners {
    /// Empty table.
    pub const fn new() -> Self {
        Self { v: Vec::new() }
    }

    /// `true` for a multicast address with a scope larger than realm-local.
    pub fn is_valid(a: &Ipv6Addr) -> bool {
        a.is_multicast() && (a.octets()[1] & 0x0f) > 3
    }

    /// Add or refresh a listener: [`Error::InvalidArgs`] for an address that
    /// cannot be registered, [`Error::NoBufs`] if the table is full.
    pub fn add(&mut self, a: Ipv6Addr, expire: Instant) -> Result<()> {
        if !Self::is_valid(&a) {
            return Err(Error::InvalidArgs);
        }
        if let Some(e) = self.v.iter_mut().find(|e| e.0 == a) {
            e.1 = expire;
            return Ok(());
        }
        self.v.push((a, expire)).map_err(|_| Error::NoBufs)
    }

    /// Remove a listener.
    pub fn remove(&mut self, a: &Ipv6Addr) {
        self.v.retain(|e| e.0 != *a);
    }

    /// Remove everything.
    pub fn clear(&mut self) {
        self.v.clear();
    }

    /// Drop expired listeners.
    pub fn expire(&mut self, now: Instant) {
        self.v.retain(|e| e.1 > now);
    }

    /// The listeners with their expiry time.
    pub fn iter(&self) -> impl Iterator<Item = &(Ipv6Addr, Instant)> {
        self.v.iter()
    }

    /// Earliest expiry.
    pub fn next_expiry(&self) -> Option<Instant> {
        self.v.iter().map(|e| e.1).min()
    }
}

/// A registered DUA (OT `NdProxyTable::NdProxy`, without DAD).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NdProxy {
    /// Interface identifier of the DUA.
    pub address_iid: Iid,
    /// Mesh-local IID of the registering device.
    pub ml_iid: Iid,
    /// RLOC16 of the registering router or parent.
    pub rloc16: u16,
}

/// Registered DUAs.
#[derive(Debug, Default, Clone)]
pub struct NdProxyTable {
    v: Vec<NdProxy, MAX_PROXIES>,
}

impl NdProxyTable {
    /// Empty table.
    pub const fn new() -> Self {
        Self { v: Vec::new() }
    }

    /// Register a DUA (OT `Register`): [`Error::Already`] if another
    /// device uses it, [`Error::NoBufs`] if the table is full.
    pub fn register(&mut self, address_iid: Iid, ml_iid: Iid, rloc16: u16) -> Result<()> {
        if let Some(p) = self.v.iter_mut().find(|p| p.address_iid == address_iid) {
            if p.ml_iid != ml_iid {
                return Err(Error::Already);
            }
            p.rloc16 = rloc16;
            return Ok(());
        }
        // A device has one DUA: a new one replaces the old.
        self.v.retain(|p| p.ml_iid != ml_iid);
        self.v
            .push(NdProxy {
                address_iid,
                ml_iid,
                rloc16,
            })
            .map_err(|_| Error::NoBufs)
    }

    /// `true` if the DUA with this IID is registered.
    pub fn is_registered(&self, address_iid: &Iid) -> bool {
        self.v.iter().any(|p| p.address_iid == *address_iid)
    }

    /// The entries.
    pub fn iter(&self) -> impl Iterator<Item = &NdProxy> {
        self.v.iter()
    }

    /// Remove everything.
    pub fn clear(&mut self) {
        self.v.clear();
    }
}

/// The reply to a registration.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::large_enum_variant)] // no allocation
pub enum Reply {
    /// No response.
    Drop,
    /// A 2.04 response with this payload.
    Payload(Vec<u8, 256>),
    /// An empty acknowledgment with this CoAP code (reference device test
    /// hook `bbr mgmt dua <code>` with a code of 128 or more).
    Empty(u8),
}

/// The Backbone Router service of this device.
#[derive(Debug, Clone)]
pub struct BbrServer {
    state: LocalState,
    seqno: u8,
    seeded: bool,
    jitter: u8,
    delay: u16,
    mlr_timeout: u32,
    service_added: bool,
    registration_at: Option<Instant>,
    /// Multicast listeners registered with this device.
    pub listeners: MulticastListeners,
    /// DUAs registered with this device.
    pub proxies: NdProxyTable,
    next_dua: Option<(u8, Option<Iid>)>,
    next_mlr: Option<u8>,
}

impl BbrServer {
    /// A disabled server; [`seed`](Self::seed) picks the sequence number.
    pub const fn new() -> Self {
        Self {
            state: LocalState::Disabled,
            seqno: 0,
            seeded: false,
            jitter: DEFAULT_REGISTRATION_JITTER,
            delay: DEFAULT_REGISTRATION_DELAY,
            mlr_timeout: DEFAULT_MLR_TIMEOUT,
            service_added: false,
            registration_at: None,
            listeners: MulticastListeners::new(),
            proxies: NdProxyTable::new(),
            next_dua: None,
            next_mlr: None,
        }
    }

    /// Pick a random initial sequence number (0..127), as OT does at boot;
    /// only the first call does (a configured number stays).
    pub fn seed<R: Rng + ?Sized>(&mut self, rng: &mut R) {
        if !core::mem::replace(&mut self.seeded, true) {
            self.seqno = (rng.next_u32() % 127) as u8;
        }
    }

    /// Current state.
    pub const fn state(&self) -> LocalState {
        self.state
    }

    #[cfg(test)]
    pub(crate) fn force_state(&mut self, s: LocalState) {
        self.state = s;
    }

    /// `true` unless disabled.
    pub const fn is_enabled(&self) -> bool {
        !matches!(self.state, LocalState::Disabled)
    }

    /// `true` for the Primary Backbone Router.
    pub const fn is_primary(&self) -> bool {
        matches!(self.state, LocalState::Primary)
    }

    /// The configured dataset (the server field is unused).
    pub const fn config(&self) -> BbrConfig {
        BbrConfig {
            server16: 0,
            sequence_number: self.seqno,
            reregistration_delay: self.delay,
            mlr_timeout: self.mlr_timeout,
        }
    }

    /// Registration jitter, seconds.
    pub const fn jitter(&self) -> u8 {
        self.jitter
    }

    /// Set the registration jitter (reference device).
    pub fn set_jitter(&mut self, j: u8) {
        self.jitter = j;
    }

    /// `true` if the service is in the local Network Data.
    pub const fn is_service_added(&self) -> bool {
        self.service_added
    }

    fn increment_seqno(&mut self) {
        self.seqno = match self.seqno {
            126 | 127 => 0,
            254 | 255 => 128,
            n => n + 1,
        };
    }

    fn add_service(&mut self, force: bool, ctx: &BbrContext<'_>) -> ServiceAction {
        if !self.is_enabled() || !ctx.attached {
            return ServiceAction::None;
        }
        if !force {
            let ok = match ctx.leader.config() {
                None => true,
                Some(c) => c.server16 == ctx.rloc16,
            };
            if !ok {
                return ServiceAction::None;
            }
        }
        self.service_added = true;
        ServiceAction::Add(self.config())
    }

    fn remove_service(&mut self) -> ServiceAction {
        if core::mem::take(&mut self.service_added) {
            ServiceAction::Remove
        } else {
            ServiceAction::None
        }
    }

    /// Enable or disable the role (OT `SetEnabled`).
    pub fn set_enabled(&mut self, enable: bool, ctx: &BbrContext<'_>) -> ServiceAction {
        if enable == self.is_enabled() {
            return ServiceAction::None;
        }
        if enable {
            self.state = LocalState::Secondary;
            self.add_service(false, ctx)
        } else {
            self.state = LocalState::Disabled;
            self.registration_at = None;
            self.listeners.clear();
            self.proxies.clear();
            self.remove_service()
        }
    }

    /// Reset after losing the Primary role (OT `Reset`).
    pub fn reset(&mut self) -> ServiceAction {
        if !self.is_enabled() {
            return ServiceAction::None;
        }
        let a = self.remove_service();
        if self.state == LocalState::Primary {
            self.increment_seqno();
            self.state = LocalState::Secondary;
        }
        a
    }

    /// Set the dataset (OT `SetConfig`, reference device rules: a delay of
    /// at least 1 s, twice the delay below the timeout).
    pub fn set_config(
        &mut self,
        seqno: Option<u8>,
        delay: Option<u16>,
        timeout: Option<u32>,
        ctx: &BbrContext<'_>,
    ) -> Result<ServiceAction> {
        let d = delay.unwrap_or(self.delay);
        let t = timeout.unwrap_or(self.mlr_timeout);
        if d < 1 || u32::from(d) * 2 >= t || t > MAX_MLR_TIMEOUT {
            return Err(Error::InvalidArgs);
        }
        let s = seqno.unwrap_or(self.seqno);
        let update = d != self.delay || t != self.mlr_timeout || s != self.seqno;
        self.delay = d;
        self.mlr_timeout = t;
        self.seqno = s;
        Ok(if update {
            self.add_service(false, ctx)
        } else {
            ServiceAction::None
        })
    }

    /// The Network Data changed (OT `HandleBackboneRouterPrimaryUpdate`).
    pub fn handle_primary_update<R: Rng + ?Sized>(
        &mut self,
        ctx: &BbrContext<'_>,
        now: Instant,
        rng: &mut R,
    ) -> ServiceAction {
        if !self.is_enabled() || !ctx.attached {
            return ServiceAction::None;
        }
        match ctx.leader.config() {
            None => {
                let mut secs = 1u64;
                if !ctx.is_leader {
                    secs += u64::from(rng.next_u32() % (u32::from(self.jitter) + 1));
                }
                self.registration_at = Some(now + Duration::from_secs(secs));
                ServiceAction::None
            }
            Some(c) if c.server16 != ctx.rloc16 => self.reset(),
            Some(c) if !self.service_added => {
                self.seqno = c.sequence_number;
                self.delay = c.reregistration_delay;
                self.mlr_timeout = c.mlr_timeout;
                self.increment_seqno();
                self.add_service(true, ctx)
            }
            Some(_) => {
                self.state = LocalState::Primary;
                ServiceAction::None
            }
        }
    }

    /// Timers: the delayed registration and the listener expiry.
    pub fn poll(&mut self, now: Instant, ctx: &BbrContext<'_>) -> ServiceAction {
        self.listeners.expire(now);
        match self.registration_at {
            Some(t) if now >= t => {
                self.registration_at = None;
                self.add_service(false, ctx)
            }
            _ => ServiceAction::None,
        }
    }

    /// Earliest time [`poll`](Self::poll) has something to do.
    pub fn next_poll(&self) -> Option<Instant> {
        [self.registration_at, self.listeners.next_expiry()]
            .into_iter()
            .flatten()
            .min()
    }

    /// Reference device `bbr register`: register the service now.
    pub fn register(&mut self, ctx: &BbrContext<'_>) -> Result<ServiceAction> {
        if !self.is_enabled() || !ctx.attached {
            return Err(Error::InvalidState);
        }
        Ok(self.add_service(true, ctx))
    }

    /// The response of the next DUA.req (reference device `bbr mgmt dua`):
    /// a status below 128, or an empty acknowledgment with that CoAP code;
    /// for the device with this mesh-local IID, or any.
    pub fn set_next_dua_response(&mut self, status: u8, ml_iid: Option<Iid>) {
        self.next_dua = Some((status, ml_iid));
    }

    /// The status of the next MLR.req (reference device `bbr mgmt mlr response`).
    pub fn set_next_mlr_response(&mut self, status: u8) {
        self.next_mlr = Some(status);
    }

    /// Handle a DUA.req from `peer_rloc16` (`None` if the source is not an
    /// RLOC); OT `HandleDuaRegistration`.
    pub fn handle_dua_request(
        &mut self,
        payload: &[u8],
        peer_rloc16: Option<u16>,
        ctx: &BbrContext<'_>,
    ) -> Reply {
        let Some(peer) = peer_rloc16 else {
            return Reply::Drop;
        };
        let t = ThreadTlvs::new(payload);
        let (Ok(target), Ok(ml_iid)) = (t.target(), t.ml_eid()) else {
            return Reply::Drop;
        };
        let reply = |status: u8| {
            let mut buf = [0u8; 40];
            match build_dua_status(status, &target, &mut buf) {
                Ok(n) => {
                    let mut v = Vec::new();
                    let _ = v.extend_from_slice(&buf[..n]);
                    Reply::Payload(v)
                }
                Err(_) => Reply::Drop,
            }
        };
        if let Some((s, iid)) = self.next_dua
            && iid.is_none_or(|i| i == ml_iid)
        {
            self.next_dua = None;
            return if s >= 128 { Reply::Empty(s) } else { reply(s) };
        }
        let status = if !self.is_primary() {
            dua_status::NOT_PRIMARY
        } else if !ctx.leader.has_domain_prefix() {
            dua_status::GENERAL_FAILURE
        } else if !ctx.leader.is_domain_unicast(&target) {
            dua_status::INVALID
        } else {
            let mut iid = [0u8; 8];
            iid.copy_from_slice(&target.octets()[8..]);
            match self.proxies.register(Iid(iid), ml_iid, peer) {
                Ok(()) => dua_status::SUCCESS,
                Err(Error::Already) => dua_status::DUPLICATE,
                Err(Error::NoBufs) => dua_status::NO_RESOURCES,
                Err(_) => dua_status::GENERAL_FAILURE,
            }
        };
        reply(status)
    }

    /// Handle an MLR.req (OT `HandleMulticastListenerRegistration`).
    /// `commissioner_session_id` is the Commissioner Session ID of the
    /// Network Data, if a Commissioner is active.
    pub fn handle_mlr_request(
        &mut self,
        payload: &[u8],
        now: Instant,
        commissioner_session_id: Option<u16>,
        ctx: &BbrContext<'_>,
    ) -> Reply {
        let t = ThreadTlvs::new(payload);
        let mut status = mlr_status::SUCCESS;
        let mut failed: Vec<Ipv6Addr, MAX_MLR_ADDRESSES> = Vec::new();
        'done: {
            if let Some(s) = self.next_mlr.take() {
                status = s;
                break 'done;
            }
            if !self.is_primary() {
                status = mlr_status::BBR_NOT_PRIMARY;
                break 'done;
            }
            let has_session = match t.commissioner_session_id() {
                Ok(id) => {
                    if commissioner_session_id != Some(id) {
                        status = mlr_status::GENERAL_FAILURE;
                        break 'done;
                    }
                    true
                }
                Err(_) => false,
            };
            let Ok(raw) = t.ip6_addresses() else {
                return Reply::Drop;
            };
            if raw.len() % 16 != 0 || raw.len() / 16 > MAX_MLR_ADDRESSES {
                status = mlr_status::GENERAL_FAILURE;
                break 'done;
            }
            let mut timeout = ctx
                .leader
                .config()
                .map_or(self.mlr_timeout, |c| c.mlr_timeout);
            if has_session && let Ok(to) = t.timeout() {
                if to == u32::MAX {
                    status = mlr_status::NO_PERSISTENT;
                    break 'done;
                }
                timeout = to.min(MAX_MLR_TIMEOUT);
            }
            let expire = now + Duration::from_secs(u64::from(timeout));
            for c in raw.chunks_exact(16) {
                let mut o = [0u8; 16];
                o.copy_from_slice(c);
                let a = Ipv6Addr::from(o);
                if timeout == 0 {
                    self.listeners.remove(&a);
                    continue;
                }
                if let Err(e) = self.listeners.add(a, expire) {
                    if status == mlr_status::SUCCESS {
                        status = if e == Error::InvalidArgs {
                            mlr_status::INVALID
                        } else {
                            mlr_status::NO_RESOURCES
                        };
                    }
                    let _ = failed.push(a);
                }
            }
        }
        let mut buf = [0u8; 8 + MAX_MLR_ADDRESSES * 16];
        match build_mlr_response(status, &failed, &mut buf) {
            Ok(n) => {
                let mut v = Vec::new();
                if v.extend_from_slice(&buf[..n]).is_err() {
                    return Reply::Drop;
                }
                Reply::Payload(v)
            }
            Err(_) => Reply::Drop,
        }
    }
}

impl Default for BbrServer {
    fn default() -> Self {
        Self::new()
    }
}
