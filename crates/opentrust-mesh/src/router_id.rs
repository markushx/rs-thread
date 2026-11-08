//! Router ID assignment over TMF: Address Solicit (`/a/as`) and Address
//! Release (`/a/ar`), OT `Mle::SendAddressSolicit`, `HandleTmf<kUriAddressSolicit>`,
//! `HandleAddressSolicitResponse`, `SendAddressRelease`,
//! `HandleTmf<kUriAddressRelease>`.
//!
//! The allocation itself is in `opentrust-mle`
//! ([`Mle::handle_address_solicit`], [`Mle::handle_address_release`],
//! [`Mle::address_solicit_reply`]); this module is the CoAP side.
//!
//! # Leader side
//!
//! Feed the `/a/as` and `/a/ar` requests from the TMF agent to
//! [`handle_address_solicit`] and [`handle_address_release`]. As in OT
//! nothing is answered if this device is not the leader or the request is
//! malformed; a refused solicit is answered with a Status TLV only.
//!
//! # Client side
//!
//! Implement [`MleEnv::request_router_id`] and [`MleEnv::release_router_id`]
//! on [`RouterIdOutbox`] (they only queue) and call
//! [`RouterIdOutbox::flush`] after every call into the MLE core; it sends
//! the CoAP requests. Responses and failures of requests sent with the
//! users [`USER_ADDRESS_SOLICIT`] / [`USER_ADDRESS_RELEASE`] are turned
//! into a [`RouterIdReply`] by [`client_response`] and [`client_failure`],
//! which go to [`Mle::address_solicit_reply`]. A device that does not get an
//! answer (the CoAP exchange times out) stays a REED.

use heapless::Vec;
use opentrust_coap::endpoint::Request;
use opentrust_coap::message::{Code, Message, Type};
use opentrust_coap::tmf::{Agent, Responder, UdpSink};
use opentrust_coap::uri::Uri;
use opentrust_core::bytes::Writer;
use opentrust_core::message::Priority;
use opentrust_core::time::Instant;
use opentrust_core::types::{ExtAddress, Rloc16};
use opentrust_core::{Error, Result};
use opentrust_mle::env::{MleEnv, RouterIdRequest};
use opentrust_mle::router::{RouterIdGrant, RouterIdReply, SolicitRejection};
use opentrust_mle::{Mle, Role};
use rand_core::Rng;

use crate::tlv::{ThreadTlv, ThreadTlvs, status};

/// `user` value of the Address Solicit request in [`Agent::send_request`]
/// and in the TMF responses / failures.
pub const USER_ADDRESS_SOLICIT: u32 = 0x0a53_0001;
/// `user` value of the Address Release request.
pub const USER_ADDRESS_RELEASE: u32 = 0x0a53_0002;

/// A parsed Address Solicit request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AddressSolicit {
    /// Extended MAC address (ML-EUI64) of the requester.
    pub ext: ExtAddress,
    /// Previously held RLOC16, if the TLV is present.
    pub previous: Option<Rloc16>,
    /// Status TLV: why the router ID is requested.
    pub status: u8,
}

/// Encode the payload of an Address Solicit (Extended MAC Address, RLOC16
/// of the previous router ID if any, Status).
pub fn build_address_solicit(
    ext: ExtAddress,
    request: &RouterIdRequest,
    out: &mut [u8],
) -> Result<usize> {
    let mut w = Writer::new(out);
    ThreadTlv::ExtMacAddress(ext).write(&mut w)?;
    if let Some(id) = request.previous_router_id {
        ThreadTlv::Rloc16(Rloc16::from_router_id(id)?).write(&mut w)?;
    }
    ThreadTlv::Status(request.reason as u8).write(&mut w)?;
    Ok(w.len())
}

/// Parse an Address Solicit payload ([`Error::Parse`] if the Extended MAC
/// Address or Status TLV is missing or a TLV is malformed).
pub fn parse_address_solicit(payload: &[u8]) -> Result<AddressSolicit> {
    let t = ThreadTlvs::new(payload);
    let ext = t.ext_mac_address().map_err(|_| Error::Parse)?;
    let status = t.status().map_err(|_| Error::Parse)?;
    let previous = match t.rloc16() {
        Ok(r) => Some(r),
        Err(Error::NotFound) => None,
        Err(_) => return Err(Error::Parse),
    };
    Ok(AddressSolicit {
        ext,
        previous,
        status,
    })
}

/// Encode the payload of an Address Solicit response: Status, and for a
/// grant the RLOC16 and Router Mask TLVs.
pub fn build_address_solicit_response(
    result: core::result::Result<RouterIdGrant, SolicitRejection>,
    out: &mut [u8],
) -> Result<usize> {
    let mut w = Writer::new(out);
    match result {
        Ok(g) => {
            ThreadTlv::Status(status::SUCCESS).write(&mut w)?;
            ThreadTlv::Rloc16(g.rloc16).write(&mut w)?;
            ThreadTlv::RouterMask {
                id_sequence: g.id_sequence,
                mask: g.mask,
            }
            .write(&mut w)?;
        }
        Err(SolicitRejection::NoAddressAvailable) => {
            ThreadTlv::Status(status::NO_ADDRESS_AVAILABLE).write(&mut w)?;
        }
        Err(SolicitRejection::UnrecognizedStatus) => {
            ThreadTlv::Status(status::UNRECOGNIZED_STATUS).write(&mut w)?;
        }
    }
    Ok(w.len())
}

/// Interpret an Address Solicit response (OT `HandleAddressSolicitResponse`):
/// anything but a 2.04 with a Status TLV is a failure; a non-success status
/// is a rejection; a success without RLOC16 or Router Mask TLV is a
/// failure.
pub fn parse_address_solicit_response(msg: &Message<'_>) -> RouterIdReply {
    if msg.code() != Code::CHANGED {
        return RouterIdReply::Failed;
    }
    let t = ThreadTlvs::new(msg.payload());
    match t.status() {
        Ok(status::SUCCESS) => {}
        Ok(_) => return RouterIdReply::Rejected,
        Err(_) => return RouterIdReply::Failed,
    }
    match (t.rloc16(), t.router_mask()) {
        (Ok(rloc16), Ok((id_sequence, mask))) => RouterIdReply::Granted {
            rloc16,
            id_sequence,
            mask,
        },
        _ => RouterIdReply::Failed,
    }
}

/// Encode the payload of an Address Release (RLOC16, Extended MAC Address).
pub fn build_address_release(rloc16: Rloc16, ext: ExtAddress, out: &mut [u8]) -> Result<usize> {
    let mut w = Writer::new(out);
    ThreadTlv::Rloc16(rloc16).write(&mut w)?;
    ThreadTlv::ExtMacAddress(ext).write(&mut w)?;
    Ok(w.len())
}

/// What the leader did for an Address Solicit that it answered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SolicitHandled {
    /// The grant, `None` if the request was refused.
    pub granted: Option<Rloc16>,
    /// RLOC16 the requester used before (from the request's source RLOC
    /// address) if the grant changes it and it is not served by this
    /// leader's own router ID: cached EID mappings to it are stale (OT
    /// `AddressResolver::RemoveEntriesForRloc16`).
    pub stale_rloc16: Option<Rloc16>,
}

fn is_confirmable_post(req: &Request<'_>) -> bool {
    req.msg.ty() == Type::Con && req.msg.code() == Code::POST
}

/// Leader side of `/a/as` (OT `HandleTmf<kUriAddressSolicit>`). Returns
/// `None` if the request was not answered (not the leader, not a
/// confirmable POST, malformed).
pub fn handle_address_solicit<E: MleEnv, const C: usize>(
    mle: &mut Mle<C>,
    env: &mut E,
    now: Instant,
    req: &Request<'_>,
    rsp: &mut dyn Responder,
) -> Option<SolicitHandled> {
    if mle.role() != Role::Leader || !is_confirmable_post(req) {
        return None;
    }
    let sol = parse_address_solicit(req.msg.payload()).ok()?;
    let result = mle.handle_address_solicit(env, now, sol.ext, sol.previous, sol.status);
    let mut buf = [0u8; 32];
    let n = build_address_solicit_response(result, &mut buf).ok()?;
    rsp.respond(Code::CHANGED, &buf[..n]).ok()?;
    let granted = result.ok().map(|g| g.rloc16);
    let mlp = env.mesh_local_prefix();
    let stale_rloc16 = granted.and_then(|new| {
        let peer = req.ctx.peer.addr;
        if !opentrust_net::addr::is_routing_locator(&peer, &mlp) {
            return None;
        }
        let old = Rloc16(opentrust_core::types::ipv6::iid(&peer).locator()?);
        (old != new && old.router_id() != mle.rloc16().router_id()).then_some(old)
    });
    Some(SolicitHandled {
        granted,
        stale_rloc16,
    })
}

/// Leader side of `/a/ar` (OT `HandleTmf<kUriAddressRelease>`): on success
/// the router ID is released and the request acknowledged with an empty
/// ACK; the released RLOC16 is returned. Nothing is sent if the request is
/// invalid, the ID is unknown or its holder differs.
pub fn handle_address_release<E: MleEnv, const C: usize>(
    mle: &mut Mle<C>,
    env: &mut E,
    now: Instant,
    req: &Request<'_>,
    rsp: &mut dyn Responder,
) -> Option<Rloc16> {
    if mle.role() != Role::Leader || !is_confirmable_post(req) {
        return None;
    }
    let t = ThreadTlvs::new(req.msg.payload());
    let rloc16 = t.rloc16().ok()?;
    let ext = t.ext_mac_address().ok()?;
    mle.handle_address_release(env, now, rloc16, ext).ok()?;
    rsp.respond(Code::CHANGED, &[]).ok()?;
    Some(rloc16)
}

/// `Some(reply)` if a TMF response to the request with `user` is the
/// answer to an Address Solicit, for [`Mle::address_solicit_reply`].
pub fn client_response(user: u32, msg: &Message<'_>) -> Option<RouterIdReply> {
    (user == USER_ADDRESS_SOLICIT).then(|| parse_address_solicit_response(msg))
}

/// `Some(Failed)` if the failed or timed out request with `user` was an
/// Address Solicit.
pub fn client_failure(user: u32) -> Option<RouterIdReply> {
    (user == USER_ADDRESS_SOLICIT).then_some(RouterIdReply::Failed)
}

/// Send an Address Solicit to the leader's RLOC (OT `SendAddressSolicit`):
/// confirmable, net priority, from our RLOC.
pub fn send_address_solicit<
    R: Rng + ?Sized,
    S: UdpSink + ?Sized,
    E: MleEnv,
    const REQ: usize,
    const RES: usize,
    const CACHE: usize,
    const MSG: usize,
    const C: usize,
>(
    agent: &mut Agent<REQ, RES, CACHE, MSG>,
    now: Instant,
    rng: &mut R,
    sink: &mut S,
    mle: &Mle<C>,
    env: &E,
    request: &RouterIdRequest,
) -> Result<()> {
    let mut buf = [0u8; 32];
    let n = build_address_solicit(env.ext_address(), request, &mut buf)?;
    let mlp = env.mesh_local_prefix();
    agent.post(
        now,
        rng,
        sink,
        mlp.rloc(mle.leader_rloc16()),
        Some(mlp.rloc(mle.rloc16())),
        Priority::Net,
        Uri::AddressSolicit,
        &buf[..n],
        Some(USER_ADDRESS_SOLICIT),
    )
}

/// Send an Address Release for `rloc16` to the leader (OT
/// `SendAddressRelease`).
pub fn send_address_release<
    R: Rng + ?Sized,
    S: UdpSink + ?Sized,
    E: MleEnv,
    const REQ: usize,
    const RES: usize,
    const CACHE: usize,
    const MSG: usize,
    const C: usize,
>(
    agent: &mut Agent<REQ, RES, CACHE, MSG>,
    now: Instant,
    rng: &mut R,
    sink: &mut S,
    mle: &Mle<C>,
    env: &E,
    rloc16: Rloc16,
) -> Result<()> {
    let mut buf = [0u8; 16];
    let n = build_address_release(rloc16, env.ext_address(), &mut buf)?;
    let mlp = env.mesh_local_prefix();
    // The device may already be a child with another RLOC16 or none.
    let src = if mle.rloc16() == Rloc16::INVALID {
        rloc16
    } else {
        mle.rloc16()
    };
    agent.post(
        now,
        rng,
        sink,
        mlp.rloc(mle.leader_rloc16()),
        Some(mlp.rloc(src)),
        Priority::Net,
        Uri::AddressRelease,
        &buf[..n],
        Some(USER_ADDRESS_RELEASE),
    )
}

/// Queue between the MLE core's [`MleEnv::request_router_id`] /
/// [`MleEnv::release_router_id`] callbacks and the TMF agent: the callbacks
/// only record the request, [`RouterIdOutbox::flush`] sends it.
#[derive(Debug, Default)]
pub struct RouterIdOutbox {
    solicit: Option<RouterIdRequest>,
    release: Vec<Rloc16, 2>,
}

impl RouterIdOutbox {
    /// Empty outbox.
    pub const fn new() -> Self {
        Self {
            solicit: None,
            release: Vec::new(),
        }
    }

    /// For [`MleEnv::request_router_id`]: [`Error::Busy`] if a request is
    /// already queued.
    pub fn request_router_id(&mut self, request: &RouterIdRequest) -> Result<()> {
        if self.solicit.is_some() {
            return Err(Error::Busy);
        }
        self.solicit = Some(*request);
        Ok(())
    }

    /// For [`MleEnv::release_router_id`]. The oldest entry is dropped if
    /// the queue is full.
    pub fn release_router_id(&mut self, rloc16: Rloc16) {
        if self.release.push(rloc16).is_err() {
            self.release.remove(0);
            let _ = self.release.push(rloc16);
        }
    }

    /// `true` if [`RouterIdOutbox::flush`] has something to send.
    pub fn is_pending(&self) -> bool {
        self.solicit.is_some() || !self.release.is_empty()
    }

    /// Send the queued requests. An Address Solicit that cannot be sent is
    /// reported to the MLE core as [`RouterIdReply::Failed`].
    #[allow(clippy::too_many_arguments)]
    pub fn flush<
        R: Rng + ?Sized,
        S: UdpSink + ?Sized,
        E: MleEnv,
        const REQ: usize,
        const RES: usize,
        const CACHE: usize,
        const MSG: usize,
        const C: usize,
    >(
        &mut self,
        agent: &mut Agent<REQ, RES, CACHE, MSG>,
        now: Instant,
        rng: &mut R,
        sink: &mut S,
        mle: &mut Mle<C>,
        env: &mut E,
    ) {
        for rloc16 in core::mem::take(&mut self.release) {
            // Like OT the failure is only logged.
            let _ = send_address_release(agent, now, rng, sink, mle, env, rloc16);
        }
        if let Some(req) = self.solicit.take() {
            if send_address_solicit(agent, now, rng, sink, mle, env, &req).is_err() {
                mle.address_solicit_reply(env, now, RouterIdReply::Failed);
            }
        }
    }
}
