//! Thread Management Framework agent (OT `thread/tmf.{hpp,cpp}`).
//!
//! A CoAP [`Endpoint`] bound to UDP port 61631 on top of
//! `rs-thread-net`:
//!
//! ```text
//!  Ip6::handle -> UdpSockets::handle_datagram -> UdpRx::Receiver{ReceiverId::TMF, meta, payload}
//!       -> Agent::handle_receiver / handle_dispatch  (filter, CoAP, URI routing)
//!       -> Handler::handle(uri, request, responder)  (MLE/MeshCoP/Network Data/... code)
//!  Agent::{post, send_request, respond via Responder, poll}
//!       -> UdpSink::send(SendInfo, src_port, dst_port, payload) -> Ip6::send
//! ```
//!
//! # Filtering (OT `Agent::IsTmfMessage` / `Filter`)
//!
//! A received message is TMF only if the destination port is 61631 and
//! - the source is link-local unicast and the destination is link-local
//!   unicast or multicast; or
//! - the source is a mesh-local address and the destination is mesh-local,
//!   link-local multicast or realm-local multicast.
//!
//! Everything else is dropped ([`TmfRx::Dropped`]). Additionally datagrams
//! without link-layer security are dropped unless
//! [`Agent::require_link_security`] is cleared (OT enforces this in the
//! mesh forwarder instead).
//!
//! # Priority and DSCP
//!
//! TMF messages carry a TMF-specific DSCP (`0x07` net, `0x0f` normal, `0x17`
//! low); [`priority_to_dscp`] / [`dscp_to_priority`] mirror OT, where an
//! unknown DSCP maps to net priority (older firmware).

use core::net::Ipv6Addr;

use rs_thread_core::message::Priority;
use rs_thread_core::time::Instant;
use rs_thread_core::{Error, Result};
use rs_thread_net::ip6::{SendInfo, TMF_UDP_PORT};
use rs_thread_net::netif::Netif;
use rs_thread_net::udp::{ReceiverId, UdpMeta, UdpSockets};
use rand_core::Rng;

use crate::endpoint::{
    Endpoint, Event, Peer, Request, RequestCtx, ResourceId, Rx, RxInfo, SendOpts, Transport,
    TxParams,
};
use crate::message::{Code, MessageBuilder, Type};
pub use crate::uri::Uri;

/// TMF UDP port.
pub const UDP_PORT: u16 = TMF_UDP_PORT;
/// DSCP of net-priority TMF messages.
pub const DSCP_NET: u8 = 0x07;
/// DSCP of normal-priority TMF messages.
pub const DSCP_NORMAL: u8 = 0x0f;
/// DSCP of low-priority TMF messages.
pub const DSCP_LOW: u8 = 0x17;

/// OT `Agent::PriorityToDscp` (high maps to the normal DSCP).
pub const fn priority_to_dscp(p: Priority) -> u8 {
    match p {
        Priority::Net => DSCP_NET,
        Priority::High | Priority::Normal => DSCP_NORMAL,
        Priority::Low => DSCP_LOW,
    }
}

/// OT `Agent::DscpToPriority`: unknown values are net priority.
pub const fn dscp_to_priority(dscp: u8) -> Priority {
    match dscp {
        DSCP_NORMAL => Priority::Normal,
        DSCP_LOW => Priority::Low,
        _ => Priority::Net,
    }
}

/// Network state the TMF filter needs.
pub trait TmfEnv {
    /// `true` if `addr` is in the mesh-local prefix.
    fn is_mesh_local(&self, addr: &Ipv6Addr) -> bool;
}

impl<const U: usize, const M: usize> TmfEnv for Netif<U, M> {
    fn is_mesh_local(&self, addr: &Ipv6Addr) -> bool {
        rs_thread_net::addr::is_mesh_local(addr, self.mesh_local_prefix())
    }
}

/// OT `Agent::IsTmfMessage`.
pub fn is_tmf_message<E: TmfEnv + ?Sized>(
    env: &E,
    src: &Ipv6Addr,
    dst: &Ipv6Addr,
    dst_port: u16,
) -> bool {
    use rs_thread_net::addr::{is_link_local_multicast, is_realm_local_multicast};
    if dst_port != UDP_PORT {
        return false;
    }
    if src.is_unicast_link_local() {
        return dst.is_unicast_link_local() || is_link_local_multicast(dst);
    }
    env.is_mesh_local(src)
        && (env.is_mesh_local(dst) || is_link_local_multicast(dst) || is_realm_local_multicast(dst))
}

/// Receives the UDP datagrams the agent sends (the caller forwards them to
/// `Ip6::send` after writing a UDP header, e.g. with `UdpHeader`).
pub trait UdpSink {
    /// Send `payload` from `src_port` to `dst_port` using `info`
    /// (addresses, DSCP, link security, loopback).
    fn send(&mut self, info: &SendInfo, src_port: u16, dst_port: u16, payload: &[u8])
    -> Result<()>;
}

struct SinkTransport<'a, S: UdpSink + ?Sized>(&'a mut S);

impl<S: UdpSink + ?Sized> Transport for SinkTransport<'_, S> {
    fn send(&mut self, peer: &Peer, opts: &SendOpts, data: &[u8]) -> Result<()> {
        let info = SendInfo {
            src: opts.src,
            dst: peer.addr,
            hop_limit: 0,
            dscp: priority_to_dscp(opts.priority),
            ecn: 0,
            multicast_loop: opts.multicast_loop,
            link_security: true,
        };
        self.0.send(&info, UDP_PORT, peer.port, data)
    }
}

/// Answers the request being handled.
pub trait Responder {
    /// Send a response with `code` and `payload` (piggybacked ACK for CON,
    /// NON for NON). A handler that must not answer simply does not call it.
    fn respond(&mut self, code: Code, payload: &[u8]) -> Result<()>;
    /// Empty ACK now, answer later (see [`Agent::respond_separate`]).
    fn ack_empty(&mut self) -> Result<()>;
    /// Context to answer later.
    fn ctx(&self) -> RequestCtx;
}

/// Application side of the dispatcher: one implementation routes all URIs.
pub trait Handler {
    /// Handle a request for `uri`. Respond through `rsp` (or not at all).
    fn handle(&mut self, uri: Uri, req: &Request<'_>, rsp: &mut dyn Responder);
}

/// Result of [`Agent::handle_receiver`].
#[derive(Debug, Clone, Copy)]
pub enum TmfRx<'a> {
    /// Filtered out (not a TMF message by [`is_tmf_message`], or insecure).
    Dropped,
    /// Consumed by the endpoint.
    Handled,
    /// A request for a registered URI.
    Request {
        /// Resource.
        uri: Uri,
        /// Request (use [`Agent::respond`]).
        req: Request<'a>,
    },
    /// Response to a request from [`Agent::send_request`].
    Response {
        /// Caller's id.
        user: u32,
        /// Response message.
        msg: crate::message::Message<'a>,
        /// Sender.
        peer: Peer,
    },
    /// Request `user` failed.
    Failed {
        /// Caller's id.
        user: u32,
        /// Reason.
        error: Error,
    },
}

/// The TMF agent.
#[derive(Debug)]
pub struct Agent<const REQ: usize, const RES: usize, const CACHE: usize, const MSG: usize> {
    ep: Endpoint<REQ, RES, CACHE, MSG>,
    /// Drop datagrams that were not link-layer secured (default `true`).
    pub require_link_security: bool,
    /// Priority of responses sent by [`Responder`] (default net, as OT
    /// treats TMF without a TMF DSCP).
    pub response_priority: Priority,
}

struct Reply<
    'a,
    S: UdpSink + ?Sized,
    const REQ: usize,
    const RES: usize,
    const CACHE: usize,
    const MSG: usize,
> {
    ep: &'a mut Endpoint<REQ, RES, CACHE, MSG>,
    sink: &'a mut S,
    now: Instant,
    ctx: RequestCtx,
    priority: Priority,
}

impl<S: UdpSink + ?Sized, const REQ: usize, const RES: usize, const CACHE: usize, const MSG: usize>
    Responder for Reply<'_, S, REQ, RES, CACHE, MSG>
{
    fn respond(&mut self, code: Code, payload: &[u8]) -> Result<()> {
        let opts = SendOpts {
            priority: self.priority,
            ..SendOpts::default()
        };
        self.ep.respond_payload(
            self.now,
            &mut SinkTransport(&mut *self.sink),
            &self.ctx,
            &opts,
            code,
            payload,
        )
    }
    fn ack_empty(&mut self) -> Result<()> {
        self.ep
            .ack_empty(&mut SinkTransport(&mut *self.sink), &self.ctx)
    }
    fn ctx(&self) -> RequestCtx {
        self.ctx
    }
}

impl<const REQ: usize, const RES: usize, const CACHE: usize, const MSG: usize>
    Agent<REQ, RES, CACHE, MSG>
{
    /// New agent with OT's default CoAP parameters. `first_message_id`
    /// should be random.
    pub const fn new(first_message_id: u16) -> Self {
        Self::with_params(first_message_id, TxParams::DEFAULT)
    }

    /// New agent with custom retransmission parameters.
    pub const fn with_params(first_message_id: u16, params: TxParams) -> Self {
        Self {
            ep: Endpoint::new(first_message_id, params),
            require_link_security: true,
            response_priority: Priority::Net,
        }
    }

    /// Claim port 61631 in the UDP table (OT `Agent::Start`).
    pub fn register_receiver<
        const N: usize,
        const Q: usize,
        const BUF: usize,
        const R: usize,
        const P: usize,
    >(
        udp: &mut UdpSockets<N, Q, BUF, R, P>,
    ) -> Result<()> {
        udp.register_receiver(UDP_PORT, ReceiverId::TMF)
    }

    /// Release the port.
    pub fn unregister_receiver<
        const N: usize,
        const Q: usize,
        const BUF: usize,
        const R: usize,
        const P: usize,
    >(
        udp: &mut UdpSockets<N, Q, BUF, R, P>,
    ) -> Result<()> {
        udp.unregister_receiver(ReceiverId::TMF)
    }

    /// Underlying endpoint.
    pub fn endpoint(&self) -> &Endpoint<REQ, RES, CACHE, MSG> {
        &self.ep
    }

    /// Underlying endpoint (mutable).
    pub fn endpoint_mut(&mut self) -> &mut Endpoint<REQ, RES, CACHE, MSG> {
        &mut self.ep
    }

    /// Serve requests for `uri` (`RES` bounds the number).
    pub fn register(&mut self, uri: Uri) -> Result<()> {
        self.ep.add_resource(uri.path(), ResourceId(uri.id()))
    }

    /// Stop serving `uri`.
    pub fn unregister(&mut self, uri: Uri) -> Result<()> {
        self.ep.remove_resource(uri.path())
    }

    /// Process the payload of a [`rs_thread_net::udp::UdpRx::Receiver`]
    /// with [`ReceiverId::TMF`].
    pub fn handle_receiver<'a, E: TmfEnv + ?Sized, S: UdpSink + ?Sized>(
        &mut self,
        now: Instant,
        sink: &mut S,
        env: &E,
        meta: &UdpMeta,
        payload: &'a [u8],
    ) -> TmfRx<'a> {
        if !is_tmf_message(env, meta.peer.ip(), meta.local.ip(), meta.local.port())
            || (self.require_link_security && !meta.link_security)
        {
            return TmfRx::Dropped;
        }
        let info = RxInfo {
            peer: Peer::new(*meta.peer.ip(), meta.peer.port()),
            dst: *meta.local.ip(),
        };
        match self
            .ep
            .handle_datagram(now, &mut SinkTransport(sink), &info, payload)
        {
            Rx::Handled => TmfRx::Handled,
            Rx::Request(req) => match Uri::from_id(req.resource.0) {
                Some(uri) => TmfRx::Request { uri, req },
                None => TmfRx::Handled,
            },
            Rx::Response { user, msg, peer } => TmfRx::Response { user, msg, peer },
            Rx::Failed { user, error } => TmfRx::Failed { user, error },
        }
    }

    /// [`Agent::handle_receiver`] plus routing: requests go to `handler`
    /// (and yield [`TmfRx::Handled`]); everything else is returned.
    pub fn handle_dispatch<'a, E, S, H>(
        &mut self,
        now: Instant,
        sink: &mut S,
        env: &E,
        meta: &UdpMeta,
        payload: &'a [u8],
        handler: &mut H,
    ) -> TmfRx<'a>
    where
        E: TmfEnv + ?Sized,
        S: UdpSink + ?Sized,
        H: Handler + ?Sized,
    {
        match self.handle_receiver(now, sink, env, meta, payload) {
            TmfRx::Request { uri, req } => {
                let mut reply = Reply {
                    ep: &mut self.ep,
                    sink,
                    now,
                    ctx: req.ctx,
                    priority: self.response_priority,
                };
                handler.handle(uri, &req, &mut reply);
                TmfRx::Handled
            }
            other => other,
        }
    }

    /// Answer a request with a custom-built message (options, TLVs).
    pub fn respond<S, F>(
        &mut self,
        now: Instant,
        sink: &mut S,
        ctx: &RequestCtx,
        code: Code,
        build: F,
    ) -> Result<()>
    where
        S: UdpSink + ?Sized,
        F: FnOnce(MessageBuilder<'_>) -> Result<usize>,
    {
        let opts = SendOpts {
            priority: self.response_priority,
            ..SendOpts::default()
        };
        self.ep
            .respond(now, &mut SinkTransport(sink), ctx, &opts, code, build)
    }

    /// Send a separate response (after `ack_empty`).
    #[allow(clippy::too_many_arguments)]
    pub fn respond_separate<R, S, F>(
        &mut self,
        now: Instant,
        rng: &mut R,
        sink: &mut S,
        ctx: &RequestCtx,
        code: Code,
        build: F,
    ) -> Result<()>
    where
        R: Rng + ?Sized,
        S: UdpSink + ?Sized,
        F: FnOnce(MessageBuilder<'_>) -> Result<usize>,
    {
        let opts = SendOpts {
            priority: self.response_priority,
            ..SendOpts::default()
        };
        self.ep
            .respond_separate(now, rng, &mut SinkTransport(sink), ctx, &opts, code, build)
    }

    /// POST `payload` to `uri` at `dst` (port 61631): CON for unicast, NON
    /// for multicast; `src` is the source address (e.g. the RLOC for TMF
    /// toward the leader). `user` identifies the outcome in
    /// [`TmfRx::Response`] / [`TmfRx::Failed`] / [`Event::Timeout`].
    #[allow(clippy::too_many_arguments)]
    pub fn post<R, S>(
        &mut self,
        now: Instant,
        rng: &mut R,
        sink: &mut S,
        dst: Ipv6Addr,
        src: Option<Ipv6Addr>,
        priority: Priority,
        uri: Uri,
        payload: &[u8],
        user: Option<u32>,
    ) -> Result<()>
    where
        R: Rng + ?Sized,
        S: UdpSink + ?Sized,
    {
        let opts = SendOpts {
            src,
            priority,
            multicast_loop: false,
        };
        self.ep.post(
            now,
            rng,
            &mut SinkTransport(sink),
            &Peer::new(dst, UDP_PORT),
            &opts,
            uri.path(),
            payload,
            user,
        )
    }

    /// General request (custom options/TLV building).
    #[allow(clippy::too_many_arguments)]
    pub fn send_request<R, S, F>(
        &mut self,
        now: Instant,
        rng: &mut R,
        sink: &mut S,
        dst: Ipv6Addr,
        opts: &SendOpts,
        ty: Type,
        code: Code,
        user: Option<u32>,
        build: F,
    ) -> Result<()>
    where
        R: Rng + ?Sized,
        S: UdpSink + ?Sized,
        F: FnOnce(MessageBuilder<'_>) -> Result<usize>,
    {
        self.ep.send_request(
            now,
            rng,
            &mut SinkTransport(sink),
            &Peer::new(dst, UDP_PORT),
            opts,
            ty,
            code,
            user,
            build,
        )
    }

    /// Next retransmission/timeout/expiry deadline.
    pub fn next_deadline(&self) -> Option<Instant> {
        self.ep.next_deadline()
    }

    /// Run due timers; call until `None`.
    pub fn poll<S: UdpSink + ?Sized>(&mut self, now: Instant, sink: &mut S) -> Option<Event> {
        self.ep.poll(now, &mut SinkTransport(sink))
    }
}

#[cfg(test)]
mod tests;
