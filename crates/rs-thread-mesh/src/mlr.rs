//! Multicast Listener Registration (MLR) client, Thread 1.2 (OT
//! `MlrManager`, `thread/mlr_manager.cpp`).
//!
//! Multicast groups with a scope larger than realm-local that this device
//! subscribes to (external subscriptions on the [`Netif`]) and, on a router,
//! those its children registered in their Address Registration TLV
//! ([`Child::multicast_listeners`](rs_thread_mle::neighbor::Child::multicast_listeners))
//! are registered with the Primary Backbone Router with a confirmable
//! `/n/mr` MLR.req (IPv6 Addresses TLV). The answer carries a status and,
//! on failure, the addresses that failed.
//!
//! Every group has a [`MlrState`]: `ToRegister`, `Registering`, `Registered`.
//! The state of device groups is kept here, that of child groups in the
//! `Child`. Registrations are renewed before the MLR timeout of the BBR
//! Dataset runs out (a random time between half the timeout and 9 s before
//! it); a new or moved Primary Backbone Router, or a sequence number change,
//! makes everything register again after a random delay up to the
//! reregistration delay.
//!
//! The manager is sans-IO: feed it events and call [`MlrManager::poll`]
//! with the current state; it returns the [`MlrRequest`] to send with
//! [`send_mlr_request`]; the outcome goes to [`MlrManager::handle_result`].
//! A registration requested by the application (`mlr reg`, OT
//! `otIp6RegisterMulticastListeners`) carries the Commissioner Session ID
//! and Timeout TLVs; see [`send_mlr_registration`].

use core::net::Ipv6Addr;

use heapless::Vec;
use rs_thread_coap::message::Code;
use rs_thread_coap::tmf::{Agent, UdpSink};
use rs_thread_coap::uri::Uri;
use rs_thread_core::bytes::Writer;
use rs_thread_core::message::Priority;
use rs_thread_core::time::{Duration, Instant};
use rs_thread_core::types::{Prefix64, Rloc16};
use rs_thread_core::{Error, Result};
use rs_thread_mle::neighbor::{MlrState, MulticastListener};
use rs_thread_net::netif::Netif;
use rand_core::Rng;

use crate::netdata::backbone::{
    BackboneRouterLeader, BbrState, MIN_MLR_TIMEOUT, PARENT_AGGREGATE_DELAY,
};
use crate::tlv::{ThreadTlv, ThreadTlvs, mlr_status};

/// `user` value of the MLR.req in [`Agent::post`] and in the TMF responses /
/// failures.
pub const USER_MLR: u32 = 0x0a53_0012;
/// `user` value of an MLR.req requested by the application.
pub const USER_MLR_REGISTER: u32 = 0x0a53_0013;
/// Most addresses in one MLR.req (`OT_IP6_MAX_MLR_ADDRESSES`).
pub const MAX_MLR_ADDRESSES: usize = 15;
/// Smallest random renewal margin below the MLR timeout, seconds.
const RENEW_MARGIN: u32 = 9;

/// The children whose multicast groups the manager registers (implemented
/// for the MLE child table with feature `ftd`; `()` for none).
pub trait MlrChildren {
    /// Call `f` for the multicast listeners of every valid child.
    fn for_each_listener(&mut self, f: &mut dyn FnMut(&mut MulticastListener));
}

impl MlrChildren for () {
    fn for_each_listener(&mut self, _f: &mut dyn FnMut(&mut MulticastListener)) {}
}

#[cfg(feature = "ftd")]
impl<const C: usize> MlrChildren for rs_thread_mle::neighbor::ChildTable<C> {
    fn for_each_listener(&mut self, f: &mut dyn FnMut(&mut MulticastListener)) {
        for c in self.iter_mut(rs_thread_mle::neighbor::StateFilter::Valid) {
            for m in c.multicast_listeners_mut() {
                f(m);
            }
        }
    }
}

/// The device's situation, as far as the MLR manager needs it.
#[derive(Debug, Clone, Copy)]
pub struct MlrContext<'a> {
    /// Current time.
    pub now: Instant,
    /// Attached to a partition.
    pub attached: bool,
    /// The device is a full Thread device (sends the MLR.req itself; an end
    /// device registers through its parent).
    pub full_thread_device: bool,
    /// The device is in the child role.
    pub is_child: bool,
    /// The device is an end device whose parent is a Thread 1.1 device: it
    /// sends the MLR.req itself, to the service ALOC.
    pub parent_1p1: bool,
    /// Service ID of the Backbone Router service (for `parent_1p1`).
    pub service_id: Option<u8>,
    /// Backbone Router state of the Network Data.
    pub bbr: &'a BackboneRouterLeader,
}

/// An MLR.req to send to the Primary Backbone Router.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MlrRequest {
    /// RLOC16 of the Primary Backbone Router.
    pub server16: u16,
    /// Send to the service ALOC with this ID instead (an end device with a
    /// Thread 1.1 parent).
    pub service_id: Option<u8>,
    /// The groups to register.
    pub addresses: Vec<Ipv6Addr, MAX_MLR_ADDRESSES>,
}

/// How an MLR.req ended.
#[derive(Debug, Clone, Copy)]
pub enum MlrResult<'a> {
    /// No answer in time.
    Timeout,
    /// The exchange failed otherwise.
    Failed,
    /// An answer arrived.
    Response {
        /// CoAP code.
        code: Code,
        /// Payload (Status TLV, optional IPv6 Addresses TLV of failures).
        payload: &'a [u8],
    },
}

/// A parsed MLR.rsp (OT `ParseMlrResponse`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MlrResponse {
    /// Status TLV ([`mlr_status`]).
    pub status: u8,
    /// Addresses that failed (only with a failure status).
    pub failed: Vec<Ipv6Addr, MAX_MLR_ADDRESSES>,
}

/// Parse an MLR.rsp payload; [`Error::Parse`] if the Status TLV is missing,
/// the address list is malformed or too long, or addresses are listed for a
/// success.
pub fn parse_mlr_response(payload: &[u8]) -> Result<MlrResponse> {
    let t = ThreadTlvs::new(payload);
    let status = t.status().map_err(|_| Error::Parse)?;
    let mut failed = Vec::new();
    match t.ip6_addresses() {
        Ok(a) => {
            if a.len() % 16 != 0 || a.len() / 16 > MAX_MLR_ADDRESSES {
                return Err(Error::Parse);
            }
            for c in a.chunks_exact(16) {
                let mut o = [0u8; 16];
                o.copy_from_slice(c);
                let _ = failed.push(Ipv6Addr::from(o));
            }
        }
        Err(Error::NotFound) => {}
        Err(_) => return Err(Error::Parse),
    }
    if !failed.is_empty() && status == mlr_status::SUCCESS {
        return Err(Error::Parse);
    }
    Ok(MlrResponse { status, failed })
}

/// Encode the payload of an MLR.req: the IPv6 Addresses TLV.
pub fn build_mlr_request(addresses: &[Ipv6Addr], out: &mut [u8]) -> Result<usize> {
    let mut b = [0u8; MAX_MLR_ADDRESSES * 16];
    for (i, a) in addresses.iter().enumerate() {
        b.get_mut(i * 16..i * 16 + 16)
            .ok_or(Error::NoBufs)?
            .copy_from_slice(&a.octets());
    }
    let mut w = Writer::new(out);
    ThreadTlv::Ip6Addresses(&b[..addresses.len() * 16]).write(&mut w)?;
    Ok(w.len())
}

/// Parse an MLR.req payload: the IPv6 Addresses TLV ([`Error::Parse`] if it
/// is missing or malformed).
pub fn parse_mlr_request(payload: &[u8]) -> Result<Vec<Ipv6Addr, MAX_MLR_ADDRESSES>> {
    let a = ThreadTlvs::new(payload).ip6_addresses()?;
    if a.len() % 16 != 0 || a.len() / 16 > MAX_MLR_ADDRESSES {
        return Err(Error::Parse);
    }
    let mut v = Vec::new();
    for c in a.chunks_exact(16) {
        let mut o = [0u8; 16];
        o.copy_from_slice(c);
        let _ = v.push(Ipv6Addr::from(o));
    }
    Ok(v)
}

/// Encode the payload of an MLR.rsp: Status and, for failures, the failed
/// addresses.
pub fn build_mlr_response(status: u8, failed: &[Ipv6Addr], out: &mut [u8]) -> Result<usize> {
    let mut w = Writer::new(out);
    ThreadTlv::Status(status).write(&mut w)?;
    if !failed.is_empty() {
        let mut b = [0u8; MAX_MLR_ADDRESSES * 16];
        for (i, a) in failed.iter().enumerate() {
            b.get_mut(i * 16..i * 16 + 16)
                .ok_or(Error::NoBufs)?
                .copy_from_slice(&a.octets());
        }
        ThreadTlv::Ip6Addresses(&b[..failed.len() * 16]).write(&mut w)?;
    }
    Ok(w.len())
}

/// Send an MLR.req to the Primary Backbone Router's RLOC (confirmable, from
/// our RLOC).
pub fn send_mlr_request<
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
    req: &MlrRequest,
) -> Result<()> {
    let mut buf = [0u8; MAX_MLR_ADDRESSES * 16 + 4];
    let n = build_mlr_request(&req.addresses, &mut buf)?;
    let dst = match req.service_id {
        Some(id) => mesh_local_prefix.aloc(0xfc10 + u16::from(id))?,
        None => mesh_local_prefix.rloc(Rloc16(req.server16)),
    };
    agent.post(
        now,
        rng,
        sink,
        dst,
        Some(mesh_local_prefix.rloc(own_rloc16)),
        Priority::Normal,
        Uri::Mlr,
        &buf[..n],
        Some(USER_MLR),
    )
}

/// An MLR.req requested by the application.
#[derive(Debug, Clone)]
pub struct MlrRegistration<'a> {
    /// Destination: the Primary Backbone Router's RLOC or, for a child of a
    /// Thread 1.1 parent, its service ALOC.
    pub dst: Ipv6Addr,
    /// Source (our RLOC).
    pub src: Ipv6Addr,
    /// The groups.
    pub addresses: &'a [Ipv6Addr],
    /// Commissioner Session ID TLV, while a Commissioner is active.
    pub session_id: Option<u16>,
    /// Timeout TLV, seconds.
    pub timeout: Option<u32>,
}

/// Send an MLR.req requested by the application (OT
/// `MlrManager::RegisterMulticastListeners`): the IPv6 Addresses TLV, the
/// Commissioner Session ID TLV if given and the Timeout TLV if given.
pub fn send_mlr_registration<
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
    reg: &MlrRegistration<'_>,
) -> Result<()> {
    let mut buf = [0u8; MAX_MLR_ADDRESSES * 16 + 16];
    let mut n = build_mlr_request(reg.addresses, &mut buf)?;
    let mut w = Writer::new(&mut buf[n..]);
    if let Some(s) = reg.session_id {
        ThreadTlv::CommissionerSessionId(s).write(&mut w)?;
    }
    if let Some(t) = reg.timeout {
        ThreadTlv::Timeout(t).write(&mut w)?;
    }
    n += w.len();
    agent.post(
        now,
        rng,
        sink,
        reg.dst,
        Some(reg.src),
        Priority::Normal,
        Uri::Mlr,
        &buf[..n],
        Some(USER_MLR_REGISTER),
    )
}

/// Keep the earliest of `slot` and `t`.
fn earliest(slot: &mut Option<Instant>, t: Instant) {
    if slot.is_none_or(|s| t < s) {
        *slot = Some(t);
    }
}

/// Random number of seconds in `lo..=hi`.
fn random_secs<R: Rng + ?Sized>(rng: &mut R, lo: u32, hi: u32) -> Duration {
    let span = hi.saturating_sub(lo) + 1;
    Duration::from_secs(u64::from(lo + rng.next_u32() % span))
}

/// The MLR manager (OT `MlrManager`); `N` bounds the device's own groups.
#[derive(Debug)]
pub struct MlrManager<const N: usize = 8> {
    local: Vec<(Ipv6Addr, MlrState), N>,
    send_delay: Option<Instant>,
    reregistration_delay: Option<Instant>,
    pending: bool,
}

impl<const N: usize> Default for MlrManager<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> MlrManager<N> {
    /// A manager without groups.
    pub const fn new() -> Self {
        Self {
            local: Vec::new(),
            send_delay: None,
            reregistration_delay: None,
            pending: false,
        }
    }

    /// The device's own groups with their state.
    pub fn local_groups(&self) -> &[(Ipv6Addr, MlrState)] {
        &self.local
    }

    /// `true` while an MLR.req is outstanding.
    pub const fn is_pending(&self) -> bool {
        self.pending
    }

    fn can_send(ctx: &MlrContext<'_>) -> bool {
        ctx.attached && (ctx.full_thread_device || ctx.parent_1p1) && ctx.bbr.has_primary()
    }

    fn schedule_send(&mut self, now: Instant, delay: Duration) {
        if self.pending {
            return;
        }
        if delay.is_zero() {
            self.send_delay = Some(now);
        } else {
            earliest(&mut self.send_delay, now + delay);
        }
    }

    fn update_reregistration_delay<R: Rng + ?Sized>(
        &mut self,
        ctx: &MlrContext<'_>,
        rereg: bool,
        rng: &mut R,
    ) {
        let Some(c) = ctx.bbr.config().filter(|_| Self::can_send(ctx)) else {
            self.reregistration_delay = None;
            return;
        };
        let secs = if rereg {
            if c.reregistration_delay > 1 {
                random_secs(rng, 1, u32::from(c.reregistration_delay))
            } else {
                Duration::from_secs(1)
            }
        } else {
            let t = c.mlr_timeout.max(MIN_MLR_TIMEOUT);
            random_secs(rng, (t >> 1) + 1, t - RENEW_MARGIN)
        };
        earliest(&mut self.reregistration_delay, ctx.now + secs);
    }

    /// The Primary Backbone Router changed (OT
    /// `HandleBackboneRouterPrimaryUpdate`).
    pub fn handle_backbone_router_update<R: Rng + ?Sized>(
        &mut self,
        state: BbrState,
        ctx: &MlrContext<'_>,
        rng: &mut R,
    ) {
        let rereg = matches!(state, BbrState::Added | BbrState::ToTriggerRereg);
        self.update_reregistration_delay(ctx, rereg, rng);
    }

    /// The Thread role changed: a device that became a child registers
    /// again (OT `HandleNotifierEvents`).
    pub fn handle_role_changed<R: Rng + ?Sized>(&mut self, ctx: &MlrContext<'_>, rng: &mut R) {
        if ctx.is_child {
            self.update_reregistration_delay(ctx, true, rng);
        }
    }

    /// Take over the device's external multicast subscriptions and the
    /// children's groups (OT `UpdateLocalSubscriptions`,
    /// `UpdateProxiedSubscriptions`): new groups are to be registered unless
    /// someone else registered them already. Call after the subscriptions or
    /// the children's Address Registration changed.
    pub fn update<R: Rng + ?Sized, const U: usize, const M: usize>(
        &mut self,
        ctx: &MlrContext<'_>,
        rng: &mut R,
        netif: &Netif<U, M>,
        children: &mut dyn MlrChildren,
    ) {
        // Groups of the device.
        self.local.retain(|(a, _)| {
            netif
                .external_multicast_larger_than_realm_local()
                .any(|x| x == *a)
        });
        for a in netif.external_multicast_larger_than_realm_local() {
            if !self.local.iter().any(|(x, _)| *x == a) {
                let _ = self.local.push((a, MlrState::ToRegister));
            }
        }
        // Registered by any child?
        let mut by_child: Vec<Ipv6Addr, 16> = Vec::new();
        children.for_each_listener(&mut |m| {
            if m.mlr == MlrState::Registered {
                let _ = by_child.push(m.addr);
            }
        });
        for (a, s) in &mut self.local {
            if *s == MlrState::ToRegister && by_child.contains(a) {
                *s = MlrState::Registered;
            }
        }
        // Children's groups: registered by the device or another child
        // already?
        let local = &self.local;
        let mut child_to_register = false;
        children.for_each_listener(&mut |m| {
            if m.mlr == MlrState::ToRegister {
                if local
                    .iter()
                    .any(|(a, s)| *a == m.addr && *s == MlrState::Registered)
                    || by_child.contains(&m.addr)
                {
                    m.mlr = MlrState::Registered;
                } else {
                    child_to_register = true;
                }
            }
        });
        if self.local.iter().any(|(_, s)| *s == MlrState::ToRegister) {
            self.schedule_send(ctx.now, Duration::from_secs(0));
        }
        if child_to_register {
            let d = random_secs(rng, 1, u32::from(PARENT_AGGREGATE_DELAY));
            self.schedule_send(ctx.now, d);
        }
    }

    /// The next time [`poll`](Self::poll) has something to do.
    pub fn next_deadline(&self) -> Option<Instant> {
        [self.send_delay, self.reregistration_delay]
            .into_iter()
            .flatten()
            .min()
    }

    /// Run the timers and start a registration if one is due (OT
    /// `HandleTimeTick`, `SendMlr`, `Reregister`). Returns the MLR.req to
    /// send; the manager then waits for [`handle_result`](Self::handle_result).
    pub fn poll<R: Rng + ?Sized>(
        &mut self,
        ctx: &MlrContext<'_>,
        rng: &mut R,
        children: &mut dyn MlrChildren,
    ) -> Option<MlrRequest> {
        let now = ctx.now;
        if !ctx.attached {
            self.send_delay = None;
            self.reregistration_delay = None;
            return None;
        }
        if self.reregistration_delay.is_some_and(|t| now >= t) {
            self.reregistration_delay = None;
            for (_, s) in &mut self.local {
                if *s == MlrState::Registered {
                    *s = MlrState::ToRegister;
                }
            }
            children.for_each_listener(&mut |m| {
                if m.mlr == MlrState::Registered {
                    m.mlr = MlrState::ToRegister;
                }
            });
            self.send_delay = Some(now);
            self.update_reregistration_delay(ctx, false, rng);
        }
        if self.send_delay.is_none_or(|t| now < t) {
            return None;
        }
        self.send_delay = None;
        if self.pending || !Self::can_send(ctx) {
            return None;
        }
        let server16 = ctx.bbr.config()?.server16;
        let mut addresses: Vec<Ipv6Addr, MAX_MLR_ADDRESSES> = Vec::new();
        for (a, s) in &mut self.local {
            if *s == MlrState::ToRegister && !addresses.is_full() {
                if !addresses.contains(a) {
                    let _ = addresses.push(*a);
                }
                *s = MlrState::Registering;
            }
        }
        children.for_each_listener(&mut |m| {
            if m.mlr == MlrState::ToRegister && !addresses.is_full() {
                if !addresses.contains(&m.addr) {
                    let _ = addresses.push(m.addr);
                }
                m.mlr = MlrState::Registering;
            }
        });
        if addresses.is_empty() {
            return None;
        }
        self.pending = true;
        let service_id = if ctx.full_thread_device {
            None
        } else {
            Some(ctx.service_id?)
        };
        Some(MlrRequest {
            server16,
            service_id,
            addresses,
        })
    }

    /// The MLR.req could not be sent: register again soon.
    pub fn request_not_sent(&mut self, now: Instant, children: &mut dyn MlrChildren) {
        self.pending = false;
        self.set_state(MlrState::Registering, MlrState::ToRegister, children);
        self.schedule_send(now, Duration::from_secs(1));
    }

    fn set_state(&mut self, from: MlrState, to: MlrState, children: &mut dyn MlrChildren) {
        for (_, s) in &mut self.local {
            if *s == from {
                *s = to;
            }
        }
        children.for_each_listener(&mut |m| {
            if m.mlr == from {
                m.mlr = to;
            }
        });
    }

    /// The outcome of the MLR.req started by [`poll`](Self::poll) (OT
    /// `HandleMlrResponse`, `FinishMlr`). Returns the parsed response if
    /// there was one.
    pub fn handle_result<R: Rng + ?Sized>(
        &mut self,
        ctx: &MlrContext<'_>,
        result: MlrResult<'_>,
        rng: &mut R,
        children: &mut dyn MlrChildren,
    ) -> Option<MlrResponse> {
        let parsed = match result {
            MlrResult::Response { code, payload } if code == Code::CHANGED => {
                parse_mlr_response(payload).ok()
            }
            _ => None,
        };
        let success = parsed
            .as_ref()
            .is_some_and(|r| r.status == mlr_status::SUCCESS);
        let failed: &[Ipv6Addr] = parsed.as_ref().map_or(&[], |r| &r.failed);
        // FinishMlr: a registering group is registered unless the answer
        // lists failures that include it.
        self.pending = false;
        let ok_for = |a: &Ipv6Addr| success || !(failed.is_empty() || failed.contains(a));
        for (a, s) in &mut self.local {
            if *s == MlrState::Registering {
                *s = if ok_for(a) {
                    MlrState::Registered
                } else {
                    MlrState::ToRegister
                };
            }
        }
        children.for_each_listener(&mut |m| {
            if m.mlr == MlrState::Registering {
                m.mlr = if ok_for(&m.addr) {
                    MlrState::Registered
                } else {
                    MlrState::ToRegister
                };
            }
        });
        if success {
            self.schedule_send(ctx.now, Duration::from_secs(0));
        } else if let Some(c) = ctx.bbr.config() {
            let d = if c.reregistration_delay > 1 {
                random_secs(rng, 1, u32::from(c.reregistration_delay))
            } else {
                Duration::from_secs(1)
            };
            self.schedule_send(ctx.now, d);
        }
        parsed
    }
}
