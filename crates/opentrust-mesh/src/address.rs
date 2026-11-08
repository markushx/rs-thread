//! Address resolution over TMF: Address Query (`/a/aq`), Address
//! Notification (`/a/an`) and Address Error (`/a/ae`), OT
//! `AddressResolver::{SendAddressQuery, HandleTmf<kUriAddressNotify>,
//! SendAddressError, HandleTmf<kUriAddressError>, HandleTmf<kUriAddressQuery>,
//! SendAddressQueryResponse}`.
//!
//! The cache and its timers are [`opentrust_net::resolver::AddressResolver`];
//! this module is the CoAP side:
//!
//! - [`send_resolver_event`] turns the [`ResolverEvent`]s of the cache into
//!   TMF messages (`SendQuery` -> NON `/a/aq` to the realm-local all-routers
//!   address, `SendAddressError` -> NON `/a/ae` to all routers) and passes
//!   `Resolved` / `ResolutionFailed` on to the forwarder;
//! - [`handle_address_notify`] feeds a received `/a/an` to the cache and
//!   acknowledges it;
//! - [`handle_address_error`] removes a duplicated address from this device
//!   and, on a router, from its sleepy children (the child lookup uses the
//!   MLE child table);
//! - [`handle_address_query`] (feature `ftd`) answers queries for the
//!   router's own addresses and for the registered addresses of its
//!   non-FTD children.
//!
//! The handlers cannot send other messages from inside the TMF handler
//! callback, so they return an [`AddressAction`] that the caller executes
//! with [`send_action`].

use core::net::Ipv6Addr;

use opentrust_coap::endpoint::Request;
use opentrust_coap::message::{Code, Type};
use opentrust_coap::tmf::{Agent, Responder, UdpSink};
use opentrust_coap::uri::Uri;
use opentrust_core::bytes::Writer;
use opentrust_core::message::Priority;
use opentrust_core::time::Instant;
use opentrust_core::types::{Iid, Rloc16, ipv6};
use opentrust_core::{Error, Result};
use opentrust_mle::MleEnv;
use opentrust_net::netif::Netif;
use opentrust_net::resolver::{AddressResolver, NotifyOutcome, ResolverEvent};
use rand_core::Rng;

use crate::tlv::{ThreadTlv, ThreadTlvs};

/// Payload of an Address Query: the Target EID TLV.
pub fn build_address_query(target: &Ipv6Addr, out: &mut [u8]) -> Result<usize> {
    let mut w = Writer::new(out);
    ThreadTlv::Target(*target).write(&mut w)?;
    Ok(w.len())
}

/// Parse an Address Query payload (the Target EID).
pub fn parse_address_query(payload: &[u8]) -> Result<Ipv6Addr> {
    ThreadTlvs::new(payload).target().map_err(|_| Error::Parse)
}

/// A parsed Address Notification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AddressNotify {
    /// The EID that was queried.
    pub target: Ipv6Addr,
    /// ML-EID interface identifier of the device that owns it.
    pub ml_eid_iid: Iid,
    /// RLOC16 of the router that answers (the one to route to).
    pub rloc16: Rloc16,
    /// Seconds since the owner was last heard (children only).
    pub last_transaction_time: Option<u32>,
}

/// Encode an Address Notification: Target, ML-EID, RLOC16 and, for a
/// child, Last Transaction Time.
pub fn build_address_notify(n: &AddressNotify, out: &mut [u8]) -> Result<usize> {
    let mut w = Writer::new(out);
    ThreadTlv::Target(n.target).write(&mut w)?;
    ThreadTlv::MeshLocalEid(n.ml_eid_iid).write(&mut w)?;
    ThreadTlv::Rloc16(n.rloc16).write(&mut w)?;
    if let Some(t) = n.last_transaction_time {
        ThreadTlv::LastTransactionTime(t).write(&mut w)?;
    }
    Ok(w.len())
}

/// Parse an Address Notification (a malformed Last Transaction Time TLV
/// invalidates the message like in OT; an absent one is `None`).
pub fn parse_address_notify(payload: &[u8]) -> Result<AddressNotify> {
    let t = ThreadTlvs::new(payload);
    let target = t.target().map_err(|_| Error::Parse)?;
    let ml_eid_iid = t.ml_eid().map_err(|_| Error::Parse)?;
    let rloc16 = t.rloc16().map_err(|_| Error::Parse)?;
    let last_transaction_time = match t.last_transaction_time() {
        Ok(v) => Some(v),
        Err(Error::NotFound) => None,
        Err(_) => return Err(Error::Parse),
    };
    Ok(AddressNotify {
        target,
        ml_eid_iid,
        rloc16,
        last_transaction_time,
    })
}

/// Payload of an Address Error: Target and ML-EID TLVs.
pub fn build_address_error(target: &Ipv6Addr, iid: &Iid, out: &mut [u8]) -> Result<usize> {
    let mut w = Writer::new(out);
    ThreadTlv::Target(*target).write(&mut w)?;
    ThreadTlv::MeshLocalEid(*iid).write(&mut w)?;
    Ok(w.len())
}

/// Parse an Address Error payload: the duplicated address and the ML-EID
/// IID of the device that reported it.
pub fn parse_address_error(payload: &[u8]) -> Result<(Ipv6Addr, Iid)> {
    let t = ThreadTlvs::new(payload);
    Ok((
        t.target().map_err(|_| Error::Parse)?,
        t.ml_eid().map_err(|_| Error::Parse)?,
    ))
}

/// A TMF message the caller must send after a handler ran.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressAction {
    /// Answer an Address Query with a confirmable Address Notification to
    /// `dest` (the querying router's RLOC).
    SendNotify {
        /// Querying router's RLOC address.
        dest: Ipv6Addr,
        /// Content.
        notify: AddressNotify,
    },
    /// Send an Address Error: multicast to all routers if `dest` is `None`,
    /// else confirmable to `dest` (a child's RLOC).
    SendError {
        /// The duplicated address.
        target: Ipv6Addr,
        /// ML-EID IID that conflicts.
        ml_eid_iid: Iid,
        /// Unicast destination, `None` for all routers.
        dest: Option<Ipv6Addr>,
    },
}

fn src_rloc<E: MleEnv>(rloc16: Rloc16, env: &E) -> Option<Ipv6Addr> {
    (rloc16 != Rloc16::INVALID).then(|| env.mesh_local_prefix().rloc(rloc16))
}

/// Send an Address Query for `eid` (non-confirmable, to the realm-local
/// all-routers multicast address, from our RLOC).
#[allow(clippy::too_many_arguments)]
pub fn send_address_query<
    R: Rng + ?Sized,
    S: UdpSink + ?Sized,
    E: MleEnv,
    const REQ: usize,
    const RES: usize,
    const CACHE: usize,
    const MSG: usize,
>(
    agent: &mut Agent<REQ, RES, CACHE, MSG>,
    now: Instant,
    rng: &mut R,
    sink: &mut S,
    own_rloc16: Rloc16,
    env: &E,
    eid: &Ipv6Addr,
) -> Result<()> {
    let mut buf = [0u8; 24];
    let n = build_address_query(eid, &mut buf)?;
    agent.post(
        now,
        rng,
        sink,
        ipv6::REALM_LOCAL_ALL_ROUTERS,
        src_rloc(own_rloc16, env),
        Priority::Net,
        Uri::AddressQuery,
        &buf[..n],
        None,
    )
}

/// Send `action` (see [`AddressAction`]).
#[allow(clippy::too_many_arguments)]
pub fn send_action<
    R: Rng + ?Sized,
    S: UdpSink + ?Sized,
    E: MleEnv,
    const REQ: usize,
    const RES: usize,
    const CACHE: usize,
    const MSG: usize,
>(
    agent: &mut Agent<REQ, RES, CACHE, MSG>,
    now: Instant,
    rng: &mut R,
    sink: &mut S,
    own_rloc16: Rloc16,
    env: &E,
    action: &AddressAction,
) -> Result<()> {
    let mut buf = [0u8; 64];
    match action {
        AddressAction::SendNotify { dest, notify } => {
            let n = build_address_notify(notify, &mut buf)?;
            agent.post(
                now,
                rng,
                sink,
                *dest,
                src_rloc(own_rloc16, env),
                Priority::Net,
                Uri::AddressNotify,
                &buf[..n],
                None,
            )
        }
        AddressAction::SendError {
            target,
            ml_eid_iid,
            dest,
        } => {
            let n = build_address_error(target, ml_eid_iid, &mut buf)?;
            agent.post(
                now,
                rng,
                sink,
                dest.unwrap_or(ipv6::REALM_LOCAL_ALL_ROUTERS),
                src_rloc(own_rloc16, env),
                Priority::Normal,
                Uri::AddressError,
                &buf[..n],
                None,
            )
        }
    }
}

/// Act on one event of the address cache. `SendQuery` and
/// `SendAddressError` are sent (a query that cannot be sent is dropped from
/// the cache, OT `SendAddressQuery` failure path); `Resolved` and
/// `ResolutionFailed` are returned for the forwarder.
#[allow(clippy::too_many_arguments)]
pub fn send_resolver_event<
    R: Rng + ?Sized,
    S: UdpSink + ?Sized,
    E: MleEnv,
    const REQ: usize,
    const RES: usize,
    const CACHE: usize,
    const MSG: usize,
    const N: usize,
>(
    event: ResolverEvent,
    resolver: &mut AddressResolver<N>,
    agent: &mut Agent<REQ, RES, CACHE, MSG>,
    now: Instant,
    rng: &mut R,
    sink: &mut S,
    own_rloc16: Rloc16,
    env: &E,
) -> Option<ResolverEvent> {
    match event {
        ResolverEvent::SendQuery { eid } => {
            if send_address_query(agent, now, rng, sink, own_rloc16, env, &eid).is_err() {
                resolver.abort_query(&eid);
            }
            None
        }
        ResolverEvent::SendAddressError {
            target,
            mesh_local_iid,
        } => {
            let a = AddressAction::SendError {
                target,
                ml_eid_iid: mesh_local_iid,
                dest: None,
            };
            let _ = send_action(agent, now, rng, sink, own_rloc16, env, &a);
            None
        }
        other => Some(other),
    }
}

/// `/a/an` (OT `HandleTmf<kUriAddressNotify>`): update the cache; an
/// accepted notification is acknowledged. Anything but a confirmable POST
/// with Target, ML-EID and RLOC16 TLVs is ignored. Cache events (`Resolved`,
/// or `SendAddressError` for a conflicting ML-EID) go to `sink`.
pub fn handle_address_notify<const N: usize>(
    resolver: &mut AddressResolver<N>,
    now: Instant,
    req: &Request<'_>,
    rsp: &mut dyn Responder,
    sink: &mut impl FnMut(ResolverEvent),
) -> Option<NotifyOutcome> {
    if req.msg.ty() != Type::Con || req.msg.code() != Code::POST {
        return None;
    }
    let n = parse_address_notify(req.msg.payload()).ok()?;
    let outcome = resolver.handle_notify(
        now,
        &n.target,
        n.ml_eid_iid,
        n.rloc16,
        n.last_transaction_time,
        sink,
    );
    if outcome == NotifyOutcome::Updated {
        let _ = rsp.ack_empty();
    }
    Some(outcome)
}

/// Result of [`handle_address_error`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressErrorOutcome {
    /// Nothing to do (malformed, or the address is unknown here).
    Ignored,
    /// The address is ours and the reporter's ML-EID differs: it was
    /// removed from the interface.
    AddressRemoved,
    /// A sleepy child registered the address with another ML-EID: it was
    /// removed from the child and an Address Error to the child's RLOC16
    /// follows (the contained action).
    ChildAddressRemoved(AddressAction),
}

/// `/a/ae` (OT `HandleTmf<kUriAddressError>`). A confirmable request
/// that was not multicast is acknowledged first. `own_ml_eid_iid` is this
/// device's ML-EID IID.
pub fn handle_address_error<const U: usize, const M: usize, const C: usize>(
    netif: &mut Netif<U, M>,
    mle: &mut opentrust_mle::Mle<C>,
    own_ml_eid_iid: &Iid,
    req: &Request<'_>,
    rsp: &mut dyn Responder,
) -> AddressErrorOutcome {
    if req.msg.code() != Code::POST {
        return AddressErrorOutcome::Ignored;
    }
    if req.msg.ty() == Type::Con && !req.ctx.dst.is_multicast() {
        let _ = rsp.ack_empty();
    }
    let Ok((target, iid)) = parse_address_error(req.msg.payload()) else {
        return AddressErrorOutcome::Ignored;
    };
    if opentrust_net::resolver::address_error_conflict(netif, &target, &iid, own_ml_eid_iid) {
        let _ = netif.remove_unicast(&target);
        return AddressErrorOutcome::AddressRemoved;
    }
    #[cfg(feature = "ftd")]
    {
        use opentrust_mle::neighbor::StateFilter;
        let ext = iid.to_ext_address();
        let mlp = *netif.mesh_local_prefix();
        for child in mle.children_mut().iter_mut(StateFilter::Valid) {
            if child.neighbor.mode.full_thread_device() || child.neighbor.ext_address == ext {
                continue;
            }
            // The ML-EID differs, so the target is a duplicate of a
            // registered address of this child.
            if child.remove_address(&target).is_ok() {
                return AddressErrorOutcome::ChildAddressRemoved(AddressAction::SendError {
                    target,
                    ml_eid_iid: iid,
                    dest: Some(mlp.rloc(child.neighbor.rloc16)),
                });
            }
        }
    }
    #[cfg(not(feature = "ftd"))]
    let _ = mle;
    AddressErrorOutcome::Ignored
}

/// The MLE child table as the child lookup of an Address Query.
#[cfg(feature = "ftd")]
#[derive(Debug)]
pub struct MleChildren<'a, const C: usize> {
    /// Child table.
    pub children: &'a opentrust_mle::neighbor::ChildTable<C>,
    /// Mesh-local prefix (the ML-EID of a child is its IID with it).
    pub mesh_local_prefix: opentrust_core::types::Prefix64,
    /// Current time.
    pub now: Instant,
}

#[cfg(feature = "ftd")]
impl<const C: usize> opentrust_net::resolver::ChildLookup for MleChildren<'_, C> {
    fn child_with_address(&self, target: &Ipv6Addr) -> Option<(Iid, u32)> {
        use opentrust_mle::consts::FAILED_CHILD_TRANSMISSIONS;
        use opentrust_mle::neighbor::StateFilter;
        self.children
            .iter(StateFilter::Valid)
            .find(|c| {
                !c.neighbor.mode.full_thread_device()
                    && c.neighbor.link_failures < FAILED_CHILD_TRANSMISSIONS
                    && c.has_address(&self.mesh_local_prefix, target)
            })
            .and_then(|c| {
                let secs = (self.now - c.neighbor.last_heard).as_secs();
                Some((*c.ml_eid_iid()?, u32::try_from(secs).unwrap_or(u32::MAX)))
            })
    }
}

/// `/a/aq` on a router (OT `HandleTmf<kUriAddressQuery>`): a non-confirmable
/// POST with a Target TLV. The answer is an Address Notification to the
/// querying router (the request's source RLOC) for an address of this
/// device or of a valid non-FTD child; `None` if there is nothing to say.
#[cfg(feature = "ftd")]
pub fn handle_address_query<const U: usize, const M: usize, const C: usize>(
    netif: &Netif<U, M>,
    mle: &opentrust_mle::Mle<C>,
    own_ml_eid_iid: &Iid,
    now: Instant,
    req: &Request<'_>,
) -> Option<AddressAction> {
    if req.msg.ty() != Type::Non || req.msg.code() != Code::POST {
        return None;
    }
    let target = parse_address_query(req.msg.payload()).ok()?;
    let children = MleChildren {
        children: mle.children(),
        mesh_local_prefix: *netif.mesh_local_prefix(),
        now,
    };
    let r =
        opentrust_net::resolver::address_query_response(netif, own_ml_eid_iid, &children, &target)?;
    Some(AddressAction::SendNotify {
        dest: req.ctx.peer.addr,
        notify: AddressNotify {
            target,
            ml_eid_iid: r.mesh_local_iid,
            rloc16: mle.rloc16(),
            last_transaction_time: r.last_transaction_time,
        },
    })
}
