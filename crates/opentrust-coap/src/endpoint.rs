//! Sans-IO CoAP endpoint (client and server; OT `coap/coap.{hpp,cpp}`).
//!
//! The endpoint owns no socket and no clock. The caller feeds it received
//! datagrams ([`Endpoint::handle_datagram`]) and time ([`Endpoint::poll`],
//! [`Endpoint::next_deadline`]); everything it wants to put on the wire goes
//! through a [`Transport`]. Plain UDP, the TMF agent and a DTLS session
//! (`opentrust_dtls::coaps::Coaps`) are different `Transport`s over the same endpoint - see
//! [`SecureTransport`].
//!
//! # Behaviour (follows OT; RFC 7252 section 4)
//!
//! Client:
//! - CON requests are stored and retransmitted with exponential back-off
//!   (initial timeout random in `[ACK_TIMEOUT, ACK_TIMEOUT * factor]`,
//!   doubled each time, `max_retransmit` times). [`TxParams::default`] is
//!   OT's `kDefault*` (2 s, 3/2, 4 retransmissions) which TMF uses.
//! - An empty ACK stops retransmission and waits for a separate response;
//!   a piggybacked ACK, or a CON/NON response with the request's token
//!   completes the request ([`Rx::Response`]); CON responses are ACKed.
//! - RST completes the request with [`Error::Abort`] ([`Rx::Failed`]).
//! - No response in time yields [`Event::Timeout`] from [`Endpoint::poll`].
//! - Requests to a multicast address are NON, are kept for
//!   `max_transmit_wait`, may produce any number of [`Rx::Response`]s and
//!   end with [`Event::Timeout`] (as OT).
//! - An unmatched CON response is answered with RST.
//!
//! Server:
//! - Requests are matched by Uri-Path against the resource table; the
//!   application gets [`Rx::Request`] and answers with
//!   [`Endpoint::respond`] (piggybacked ACK for CON, NON for NON). Unknown
//!   path: 4.04 (not for multicast). Unparseable CON: RST (not for
//!   multicast).
//! - Duplicate detection: sent piggybacked responses are cached for
//!   `exchange_lifetime` keyed by (message id, peer); a duplicate request
//!   is answered from the cache without involving the application. (As in
//!   OT, only requests that already have a *cached response* are
//!   recognised as duplicates.)
//! - Separate responses: [`Endpoint::ack_empty`] now, then
//!   [`Endpoint::respond_separate`] (CON, retransmitted like a request).
//!
//! Not implemented (disabled in OT's default config): block-wise transfer
//! and Observe. [`crate::message::BlockOption`] is provided for later.

use core::net::Ipv6Addr;

use opentrust_core::bufpool::{BufPool, Chain, POOL_BUF_SIZE};
use opentrust_core::message::Priority;
use opentrust_core::time::{Duration, Instant};
use opentrust_core::{Error, Result};
use rand_core::Rng;

use crate::message::{
    Code, MAX_TOKEN_LEN, MAX_URI_PATH_LEN, Message, MessageBuilder, Type, VERSION,
};

/// Token length used for requests (OT `OT_COAP_DEFAULT_TOKEN_LENGTH`).
pub const DEFAULT_TOKEN_LEN: usize = 2;
/// OT `kDefaultMaxLatency` (ms), part of the exchange lifetime.
pub const MAX_LATENCY_MS: u64 = 100_000;

/// A UDP peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Peer {
    /// Address.
    pub addr: Ipv6Addr,
    /// Port.
    pub port: u16,
}

impl Peer {
    /// New peer.
    pub const fn new(addr: Ipv6Addr, port: u16) -> Self {
        Self { addr, port }
    }
}

/// Per-datagram send options handed to the [`Transport`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SendOpts {
    /// Source address (`None`: transport chooses).
    pub src: Option<Ipv6Addr>,
    /// Message priority (TMF maps it to DSCP).
    pub priority: Priority,
    /// Loop multicast back to local sockets.
    pub multicast_loop: bool,
}

impl Default for SendOpts {
    fn default() -> Self {
        Self {
            src: None,
            priority: Priority::Normal,
            multicast_loop: false,
        }
    }
}

/// Where the endpoint puts datagrams (a UDP socket, the TMF agent, a DTLS
/// session, a test recorder). Errors are reported to the caller of the
/// operation that triggered the send, except for retransmissions, whose
/// errors are ignored like in OT.
pub trait Transport {
    /// Send one CoAP datagram.
    fn send(&mut self, peer: &Peer, opts: &SendOpts, data: &[u8]) -> Result<()>;
}

/// Seam for CoAPS (DTLS 1.2 + EC-JPAKE), implemented by
/// `opentrust_dtls::coaps::Coaps`.
///
/// A secure session is a [`Transport`] whose `send` encrypts, plus an
/// inbound path that turns received records into CoAP plaintext for
/// [`Endpoint::handle_datagram`]. Because the endpoint only sees
/// `Transport::send` and plaintext datagrams, no CoAP code changes when
/// DTLS arrives: the DTLS layer owns handshake state, timers and the
/// ciphertext socket, and exposes this trait.
pub trait SecureTransport: Transport {
    /// `true` once the handshake with `peer` completed (requests are
    /// refused with [`Error::InvalidState`] before).
    fn is_connected(&self, peer: &Peer) -> bool;

    /// Decrypt one received record into `plaintext`. `Ok(Some(len))` yields
    /// an application-data CoAP message to feed to the endpoint,
    /// `Ok(None)` means a handshake/alert record was consumed internally.
    fn decrypt(
        &mut self,
        now: Instant,
        peer: &Peer,
        record: &[u8],
        plaintext: &mut [u8],
    ) -> Result<Option<usize>>;

    /// Close the session with `peer`.
    fn close(&mut self, peer: &Peer);
}

/// Retransmission parameters (OT `TxParameters`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct TxParams {
    /// ACK_TIMEOUT in ms.
    pub ack_timeout_ms: u32,
    /// ACK_RANDOM_FACTOR numerator.
    pub random_factor_num: u8,
    /// ACK_RANDOM_FACTOR denominator.
    pub random_factor_den: u8,
    /// MAX_RETRANSMIT.
    pub max_retransmit: u8,
}

impl Default for TxParams {
    /// 2000 ms, 3/2, 4 (OT `kDefault*`).
    fn default() -> Self {
        Self::DEFAULT
    }
}

impl TxParams {
    /// OT defaults: 2000 ms, 3/2, 4 retransmissions.
    pub const DEFAULT: TxParams = TxParams {
        ack_timeout_ms: 2000,
        random_factor_num: 3,
        random_factor_den: 2,
        max_retransmit: 4,
    };

    /// OT `TxParameters::IsValid` (without the overflow check, which `u64`
    /// arithmetic makes unnecessary).
    pub const fn is_valid(&self) -> bool {
        self.random_factor_den > 0
            && self.random_factor_num >= self.random_factor_den
            && self.ack_timeout_ms >= 1000
            && self.max_retransmit <= 20
    }

    /// Random initial retransmission timeout in `[ACK_TIMEOUT,
    /// ACK_TIMEOUT * factor]` (OT `CalculateInitialRetransmissionTimeout`).
    pub fn initial_timeout<R: Rng + ?Sized>(&self, rng: &mut R) -> Duration {
        let lo = self.ack_timeout_ms as u64;
        let hi = lo * self.random_factor_num as u64 / self.random_factor_den.max(1) as u64 + 1;
        let span = (hi - lo).max(1);
        Duration::from_millis(lo + rng.next_u32() as u64 % span)
    }

    fn span_ms(&self, retx: u8) -> u64 {
        (self.ack_timeout_ms as u64 * ((1u64 << retx.min(40)) - 1)
            / self.random_factor_den.max(1) as u64)
            * self.random_factor_num as u64
    }

    /// EXCHANGE_LIFETIME (response cache lifetime).
    pub fn exchange_lifetime(&self) -> Duration {
        Duration::from_millis(
            self.span_ms(self.max_retransmit) + 2 * MAX_LATENCY_MS + self.ack_timeout_ms as u64,
        )
    }

    /// MAX_TRANSMIT_WAIT (how long a NON request awaits responses).
    pub fn max_transmit_wait(&self) -> Duration {
        Duration::from_millis(self.span_ms(self.max_retransmit.saturating_add(1)))
    }
}

/// Handler id of a registered resource (the application's own numbering).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct ResourceId(pub u16);

/// Addressing of a received datagram.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RxInfo {
    /// Sender.
    pub peer: Peer,
    /// Local destination address the datagram was sent to (may be multicast).
    pub dst: Ipv6Addr,
}

/// What the application needs to answer a request later (no borrow of the
/// datagram buffer).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RequestCtx {
    /// Requester.
    pub peer: Peer,
    /// Local address the request was sent to.
    pub dst: Ipv6Addr,
    /// Request type (CON/NON).
    pub ty: Type,
    /// Request message id.
    pub message_id: u16,
    token: [u8; MAX_TOKEN_LEN],
    token_len: u8,
}

impl RequestCtx {
    fn from_msg(info: &RxInfo, msg: &Message<'_>) -> Self {
        let mut ctx = RequestCtx {
            peer: info.peer,
            dst: info.dst,
            ty: msg.ty(),
            message_id: msg.message_id(),
            token: [0; MAX_TOKEN_LEN],
            token_len: msg.token().len() as u8,
        };
        ctx.token[..msg.token().len()].copy_from_slice(msg.token());
        ctx
    }

    /// Request token.
    pub fn token(&self) -> &[u8] {
        &self.token[..self.token_len as usize]
    }

    /// `true` if the request was sent to a multicast address.
    pub fn is_multicast(&self) -> bool {
        self.dst.is_multicast()
    }
}

/// A request for a registered resource.
#[derive(Debug, Clone, Copy)]
pub struct Request<'a> {
    /// Which resource matched.
    pub resource: ResourceId,
    /// The parsed message.
    pub msg: Message<'a>,
    /// Context for [`Endpoint::respond`].
    pub ctx: RequestCtx,
}

/// Result of [`Endpoint::handle_datagram`].
#[derive(Debug, Clone, Copy)]
pub enum Rx<'a> {
    /// Fully handled inside the endpoint (ACK/RST processing, duplicate
    /// answered from cache, 4.04, dropped, ...).
    Handled,
    /// A request for a registered resource: call [`Endpoint::respond`].
    Request(Request<'a>),
    /// A response to a request sent with `user`. For multicast requests it
    /// may be delivered several times.
    Response {
        /// `user` value given to [`Endpoint::send_request`].
        user: u32,
        /// The response.
        msg: Message<'a>,
        /// Sender.
        peer: Peer,
    },
    /// The request `user` failed ([`Error::Abort`] after a RST).
    Failed {
        /// `user` value given to [`Endpoint::send_request`].
        user: u32,
        /// Reason.
        error: Error,
    },
}

/// Time-driven event from [`Endpoint::poll`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Event {
    /// No (further) response for the request sent with `user`
    /// ([`Error::ResponseTimeout`]).
    Timeout {
        /// `user` value given to [`Endpoint::send_request`].
        user: u32,
    },
}

#[derive(Debug)]
struct Pending {
    peer: Peer,
    opts: SendOpts,
    mid: u16,
    token: [u8; MAX_TOKEN_LEN],
    token_len: u8,
    confirmable: bool,
    multicast: bool,
    acknowledged: bool,
    retx_left: u8,
    timeout: Duration,
    next: Instant,
    user: Option<u32>,
    len: usize,
    buf: Chain,
}

#[derive(Debug)]
struct Cached {
    peer: Peer,
    opts: SendOpts,
    mid: u16,
    expires: Instant,
    len: usize,
    buf: Chain,
}

/// Sans-IO CoAP endpoint.
///
/// `REQ`: concurrent outstanding requests, `RES`: resources, `CACHE`: cached
/// responses (OT default 10), `MSG`: maximum encoded message size (each
/// pending request and cached response stores a copy).
#[derive(Debug)]
pub struct Endpoint<
    const REQ: usize,
    const RES: usize,
    const CACHE: usize,
    const MSG: usize,
    const POOL: usize = 16,
> {
    params: TxParams,
    next_mid: u16,
    resources: [Option<(&'static str, ResourceId)>; RES],
    pending: [Option<Pending>; REQ],
    cache: [Option<Cached>; CACHE],
    pool: BufPool<POOL, POOL_BUF_SIZE>,
    scratch: [u8; MSG],
}

fn is_anycast_locator(a: &Ipv6Addr) -> bool {
    opentrust_core::types::ipv6::iid(a).is_aloc()
}

impl<const REQ: usize, const RES: usize, const CACHE: usize, const MSG: usize, const POOL: usize>
    Endpoint<REQ, RES, CACHE, MSG, POOL>
{
    /// Create an endpoint. `first_message_id` should be random (OT seeds
    /// the counter with a random `u16`).
    pub const fn new(first_message_id: u16, params: TxParams) -> Self {
        Self {
            params,
            next_mid: first_message_id,
            resources: [None; RES],
            pending: [const { None }; REQ],
            cache: [const { None }; CACHE],
            pool: BufPool::new(),
            scratch: [0; MSG],
        }
    }

    /// Transmission parameters.
    pub const fn params(&self) -> &TxParams {
        &self.params
    }

    /// Register a resource by Uri-Path (`"a/aq"`; at most
    /// [`MAX_URI_PATH_LEN`] bytes). [`Error::Already`] if the
    /// path exists, [`Error::NoBufs`] if the table is full.
    pub fn add_resource(&mut self, path: &'static str, id: ResourceId) -> Result<()> {
        if path.len() > MAX_URI_PATH_LEN {
            return Err(Error::InvalidArgs);
        }
        if self.resources.iter().flatten().any(|(p, _)| *p == path) {
            return Err(Error::Already);
        }
        let slot = self
            .resources
            .iter_mut()
            .find(|s| s.is_none())
            .ok_or(Error::NoBufs)?;
        *slot = Some((path, id));
        Ok(())
    }

    /// Remove a resource. [`Error::NotFound`] if absent.
    pub fn remove_resource(&mut self, path: &str) -> Result<()> {
        let slot = self
            .resources
            .iter_mut()
            .find(|s| matches!(s, Some((p, _)) if *p == path))
            .ok_or(Error::NotFound)?;
        *slot = None;
        Ok(())
    }

    /// Number of outstanding requests (including separate responses
    /// awaiting their ACK).
    pub fn pending_len(&self) -> usize {
        self.pending.iter().flatten().count()
    }

    /// Number of cached responses.
    pub fn cached_len(&self) -> usize {
        self.cache.iter().flatten().count()
    }

    /// Drop all requests, cached responses (OT `ClearAllRequestsAndResponses`).
    /// Resources stay registered.
    pub fn clear(&mut self) {
        for i in 0..REQ {
            self.release_pending(i);
        }
        for i in 0..CACHE {
            self.release_cached(i);
        }
    }

    /// Empty request slot `i` and return its buffers to the pool.
    fn release_pending(&mut self, i: usize) {
        if let Some(p) = self.pending[i].take() {
            self.pool.free(p.buf);
        }
    }

    /// Empty cache slot `i` and return its buffers to the pool.
    fn release_cached(&mut self, i: usize) {
        if let Some(c) = self.cache[i].take() {
            self.pool.free(c.buf);
        }
    }

    /// Drop the requests sent to `addr` without notification
    /// (OT `ClearRequests`).
    pub fn clear_requests(&mut self, addr: &Ipv6Addr) {
        for i in 0..REQ {
            if matches!(&self.pending[i], Some(x) if x.peer.addr == *addr) {
                self.release_pending(i);
            }
        }
    }

    /// Cancel the request sent with `user` (OT `AbortTransaction`); no
    /// event is generated. `true` if one was pending.
    pub fn cancel(&mut self, user: u32) -> bool {
        let mut found = false;
        for i in 0..REQ {
            if matches!(&self.pending[i], Some(x) if x.user == Some(user)) {
                self.release_pending(i);
                found = true;
            }
        }
        found
    }

    fn alloc_mid(&mut self) -> u16 {
        let m = self.next_mid;
        self.next_mid = self.next_mid.wrapping_add(1);
        m
    }

    // ---------------------------------------------------------- client

    /// Send a request. `build` receives a [`MessageBuilder`] (header and a
    /// fresh random token already written) to add options and payload and
    /// returns the encoded length (`finish_with_payload`).
    ///
    /// `ty` should be [`Type::Con`] for unicast and [`Type::Non`] for
    /// multicast ([`Endpoint::post`] chooses). CON requests are
    /// retransmitted by [`Endpoint::poll`]; with `user = Some(id)` the
    /// outcome is reported as [`Rx::Response`] / [`Rx::Failed`] /
    /// [`Event::Timeout`], with `None` it is fire-and-forget (a CON is still
    /// retransmitted until acknowledged; a NON with `None` is not stored).
    ///
    /// [`Error::NoBufs`] if all `REQ` slots are used or the message does
    /// not fit `MSG`; [`Error::InvalidArgs`] for a non-request-capable type.
    #[allow(clippy::too_many_arguments)]
    pub fn send_request<R, T, F>(
        &mut self,
        now: Instant,
        rng: &mut R,
        tr: &mut T,
        peer: &Peer,
        opts: &SendOpts,
        ty: Type,
        code: Code,
        user: Option<u32>,
        build: F,
    ) -> Result<()>
    where
        R: Rng + ?Sized,
        T: Transport + ?Sized,
        F: FnOnce(MessageBuilder<'_>) -> Result<usize>,
    {
        if !matches!(ty, Type::Con | Type::Non) {
            return Err(Error::InvalidArgs);
        }
        let mut token = [0u8; MAX_TOKEN_LEN];
        rng.fill_bytes(&mut token[..DEFAULT_TOKEN_LEN]);
        let mid = self.alloc_mid();
        self.send_tracked(
            now,
            rng,
            tr,
            peer,
            opts,
            ty,
            code,
            mid,
            &token[..DEFAULT_TOKEN_LEN],
            user,
            build,
        )
    }

    /// Convenience: POST to `uri_path` with `payload`; CON for unicast, NON
    /// for multicast destinations (OT `InitAsPost`).
    #[allow(clippy::too_many_arguments)]
    pub fn post<R, T>(
        &mut self,
        now: Instant,
        rng: &mut R,
        tr: &mut T,
        peer: &Peer,
        opts: &SendOpts,
        uri_path: &str,
        payload: &[u8],
        user: Option<u32>,
    ) -> Result<()>
    where
        R: Rng + ?Sized,
        T: Transport + ?Sized,
    {
        let ty = if peer.addr.is_multicast() {
            Type::Non
        } else {
            Type::Con
        };
        self.send_request(now, rng, tr, peer, opts, ty, Code::POST, user, |mut b| {
            b.uri_path(uri_path)?;
            b.finish_with_payload(payload)
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn send_tracked<R, T, F>(
        &mut self,
        now: Instant,
        rng: &mut R,
        tr: &mut T,
        peer: &Peer,
        opts: &SendOpts,
        ty: Type,
        code: Code,
        mid: u16,
        token: &[u8],
        user: Option<u32>,
        build: F,
    ) -> Result<()>
    where
        R: Rng + ?Sized,
        T: Transport + ?Sized,
        F: FnOnce(MessageBuilder<'_>) -> Result<usize>,
    {
        let confirmable = ty == Type::Con;
        // A NON message is only tracked when somebody waits for responses.
        let track = confirmable || user.is_some();
        let idx = if track {
            Some(
                self.pending
                    .iter()
                    .position(|p| p.is_none())
                    .ok_or(Error::NoBufs)?,
            )
        } else {
            None
        };
        let b = MessageBuilder::new(&mut self.scratch, ty, code, mid, token)?;
        let len = build(b)?;
        let data = self.scratch.get(..len).ok_or(Error::NoBufs)?;
        if let Some(idx) = idx {
            let timeout = self.params.initial_timeout(rng);
            let multicast = peer.addr.is_multicast();
            let mut p = Pending {
                peer: *peer,
                opts: *opts,
                mid,
                token: [0; MAX_TOKEN_LEN],
                token_len: token.len() as u8,
                confirmable,
                multicast,
                acknowledged: false,
                retx_left: self.params.max_retransmit,
                timeout,
                next: now.saturating_add(if confirmable {
                    timeout
                } else {
                    self.params.max_transmit_wait()
                }),
                user,
                len,
                buf: self.pool.alloc(data)?,
            };
            p.token[..token.len()].copy_from_slice(token);
            self.pending[idx] = Some(p);
            let r = tr.send(peer, opts, &self.scratch[..len]);
            if r.is_err() {
                self.release_pending(idx);
            }
            r
        } else {
            tr.send(peer, opts, data)
        }
    }

    // ---------------------------------------------------------- server

    /// Answer a request. For a CON request this is a piggybacked ACK that
    /// is also cached for duplicate detection; for a NON request a NON
    /// response with a fresh message id. `build` adds options/payload to the
    /// [`MessageBuilder`] (header + token pre-filled) as in
    /// [`Endpoint::send_request`]. The source address defaults to the
    /// address the request was sent to (unless it was multicast).
    pub fn respond<T, F>(
        &mut self,
        now: Instant,
        tr: &mut T,
        ctx: &RequestCtx,
        opts: &SendOpts,
        code: Code,
        build: F,
    ) -> Result<()>
    where
        T: Transport + ?Sized,
        F: FnOnce(MessageBuilder<'_>) -> Result<usize>,
    {
        let mut opts = *opts;
        if opts.src.is_none() && !ctx.is_multicast() {
            opts.src = Some(ctx.dst);
        }
        let (ty, mid) = match ctx.ty {
            Type::Con => (Type::Ack, ctx.message_id),
            _ => (Type::Non, self.alloc_mid()),
        };
        let b = MessageBuilder::new(&mut self.scratch, ty, code, mid, ctx.token())?;
        let len = build(b)?;
        if ty == Type::Ack {
            self.cache_response(now, &ctx.peer, &opts, mid, len);
        }
        tr.send(&ctx.peer, &opts, &self.scratch[..len])
    }

    /// [`Endpoint::respond`] with only a payload.
    pub fn respond_payload<T>(
        &mut self,
        now: Instant,
        tr: &mut T,
        ctx: &RequestCtx,
        opts: &SendOpts,
        code: Code,
        payload: &[u8],
    ) -> Result<()>
    where
        T: Transport + ?Sized,
    {
        self.respond(now, tr, ctx, opts, code, |b| b.finish_with_payload(payload))
    }

    /// Send an empty ACK for a CON request (the real answer follows via
    /// [`Endpoint::respond_separate`]). [`Error::InvalidArgs`] unless the
    /// request was CON.
    pub fn ack_empty<T: Transport + ?Sized>(&mut self, tr: &mut T, ctx: &RequestCtx) -> Result<()> {
        if ctx.ty != Type::Con {
            return Err(Error::InvalidArgs);
        }
        self.send_empty(tr, &ctx.peer, Type::Ack, ctx.message_id)
    }

    /// Send a separate response (after [`Endpoint::ack_empty`]): CON for a
    /// CON request, NON otherwise, with the request's token and a new
    /// message id. CON responses are retransmitted until ACKed.
    #[allow(clippy::too_many_arguments)]
    pub fn respond_separate<R, T, F>(
        &mut self,
        now: Instant,
        rng: &mut R,
        tr: &mut T,
        ctx: &RequestCtx,
        opts: &SendOpts,
        code: Code,
        build: F,
    ) -> Result<()>
    where
        R: Rng + ?Sized,
        T: Transport + ?Sized,
        F: FnOnce(MessageBuilder<'_>) -> Result<usize>,
    {
        let ty = if ctx.ty == Type::Con {
            Type::Con
        } else {
            Type::Non
        };
        let mid = self.alloc_mid();
        let mut o = *opts;
        if o.src.is_none() && !ctx.is_multicast() {
            o.src = Some(ctx.dst);
        }
        let token = ctx.token;
        let tl = ctx.token_len as usize;
        self.send_tracked(
            now,
            rng,
            tr,
            &ctx.peer,
            &o,
            ty,
            code,
            mid,
            &token[..tl],
            None,
            build,
        )
    }

    fn send_empty<T: Transport + ?Sized>(
        &mut self,
        tr: &mut T,
        peer: &Peer,
        ty: Type,
        mid: u16,
    ) -> Result<()> {
        let b = MessageBuilder::new(&mut self.scratch, ty, Code::EMPTY, mid, &[])?;
        let len = b.finish()?;
        tr.send(peer, &SendOpts::default(), &self.scratch[..len])
    }

    fn cache_response(&mut self, now: Instant, peer: &Peer, opts: &SendOpts, mid: u16, len: usize) {
        if self
            .cache
            .iter()
            .flatten()
            .any(|c| c.mid == mid && c.peer == *peer)
        {
            return;
        }
        // Free slot, else evict the earliest-expiring entry (OT UpdateQueue).
        let idx = match self.cache.iter().position(|c| c.is_none()) {
            Some(i) => i,
            None => {
                let mut best = 0;
                let mut best_t = Instant::MAX;
                for (i, c) in self.cache.iter().enumerate() {
                    if let Some(c) = c
                        && c.expires < best_t
                    {
                        best = i;
                        best_t = c.expires;
                    }
                }
                best
            }
        };
        if idx >= CACHE {
            return;
        }
        self.release_cached(idx);
        let Ok(buf) = self.pool.alloc(&self.scratch[..len]) else {
            return;
        };
        let c = Cached {
            peer: *peer,
            opts: *opts,
            mid,
            expires: now.saturating_add(self.params.exchange_lifetime()),
            len,
            buf,
        };
        self.cache[idx] = Some(c);
    }

    // --------------------------------------------------------- receive

    /// Process one received datagram.
    ///
    /// Replies the endpoint can produce on its own (ACK for a separate
    /// response, RST, 4.04, cached response for a duplicate) are sent via
    /// `tr`; everything the application must act on is returned.
    pub fn handle_datagram<'a, T: Transport + ?Sized>(
        &mut self,
        now: Instant,
        tr: &mut T,
        info: &RxInfo,
        data: &'a [u8],
    ) -> Rx<'a> {
        let multicast = info.dst.is_multicast();
        let msg = match Message::parse(data) {
            Ok(m) => m,
            Err(_) => {
                // Unknown version: ignore (RFC 7252 section 3). Other format
                // errors on a CON: RST (OT `Receive`).
                if data.len() >= 4
                    && data[0] >> 6 == VERSION
                    && (data[0] >> 4) & 3 == Type::Con as u8
                    && !multicast
                {
                    let mid = u16::from_be_bytes([data[2], data[3]]);
                    let _ = self.send_empty(tr, &info.peer, Type::Rst, mid);
                }
                return Rx::Handled;
            }
        };
        if msg.is_request() {
            self.process_request(now, tr, info, msg)
        } else {
            self.process_response(tr, info, msg)
        }
    }

    fn process_request<'a, T: Transport + ?Sized>(
        &mut self,
        now: Instant,
        tr: &mut T,
        info: &RxInfo,
        msg: Message<'a>,
    ) -> Rx<'a> {
        let multicast = info.dst.is_multicast();
        // Duplicate: resend the cached response.
        let hit = self
            .cache
            .iter()
            .flatten()
            .find(|c| c.mid == msg.message_id() && c.peer == info.peer);
        if let Some(c) = hit {
            let n = self.pool.read(&c.buf, &mut self.scratch[..c.len]);
            let _ = tr.send(&c.peer, &c.opts, &self.scratch[..n]);
            return Rx::Handled;
        }
        let mut pathbuf = [0u8; MAX_URI_PATH_LEN + 1];
        let Ok(path) = msg.uri_path(&mut pathbuf) else {
            return Rx::Handled;
        };
        let found = self
            .resources
            .iter()
            .flatten()
            .find(|(p, _)| *p == path)
            .map(|(_, id)| *id);
        match found {
            Some(resource) => {
                let ctx = RequestCtx::from_msg(info, &msg);
                Rx::Request(Request { resource, msg, ctx })
            }
            None => {
                if !multicast {
                    let ctx = RequestCtx::from_msg(info, &msg);
                    let _ =
                        self.respond(now, tr, &ctx, &SendOpts::default(), Code::NOT_FOUND, |b| {
                            b.finish()
                        });
                }
                Rx::Handled
            }
        }
    }

    fn find_pending(&self, msg: &Message<'_>, peer: &Peer) -> Option<usize> {
        self.pending.iter().position(|p| {
            let Some(p) = p else { return false };
            let addr_ok = (p.peer == *peer) || p.multicast || is_anycast_locator(&p.peer.addr);
            addr_ok
                && match msg.ty() {
                    Type::Rst | Type::Ack => msg.message_id() == p.mid,
                    Type::Con | Type::Non => msg.token() == &p.token[..p.token_len as usize],
                }
        })
    }

    fn process_response<'a, T: Transport + ?Sized>(
        &mut self,
        tr: &mut T,
        info: &RxInfo,
        msg: Message<'a>,
    ) -> Rx<'a> {
        let Some(i) = self.find_pending(&msg, &info.peer) else {
            // Unmatched CON: reject with RST (OT; NON cannot be reset).
            if msg.is_confirmable() {
                let _ = self.send_empty(tr, &info.peer, Type::Rst, msg.message_id());
            }
            return Rx::Handled;
        };
        let Some(p) = self.pending[i].as_mut() else {
            return Rx::Handled;
        };
        let user = p.user;
        let multicast = p.multicast;
        let token_match = msg.token() == &p.token[..p.token_len as usize];
        let deliver = |user: Option<u32>, msg, peer| match user {
            Some(user) => Rx::Response { user, msg, peer },
            None => Rx::Handled,
        };
        match msg.ty() {
            Type::Rst => {
                if msg.is_empty() {
                    self.release_pending(i);
                    if let Some(user) = user {
                        return Rx::Failed {
                            user,
                            error: Error::Abort,
                        };
                    }
                }
                Rx::Handled
            }
            Type::Ack => {
                if msg.is_empty() {
                    if p.confirmable {
                        p.acknowledged = true;
                    }
                    if user.is_none() {
                        self.release_pending(i);
                    }
                    Rx::Handled
                } else if msg.is_response() && token_match {
                    self.release_pending(i);
                    deliver(user, msg, info.peer)
                } else {
                    // ACK carrying a request or with a token mismatch.
                    Rx::Handled
                }
            }
            Type::Con | Type::Non => {
                if msg.ty() == Type::Con {
                    let _ = self.send_empty(tr, &info.peer, Type::Ack, msg.message_id());
                }
                if user.is_some() && !multicast {
                    self.release_pending(i);
                }
                deliver(user, msg, info.peer)
            }
        }
    }

    // ------------------------------------------------------------ time

    /// Earliest instant at which [`Endpoint::poll`] has work (retransmission,
    /// timeout, cache expiry).
    pub fn next_deadline(&self) -> Option<Instant> {
        let a = self.pending.iter().flatten().map(|p| p.next).min();
        let b = self.cache.iter().flatten().map(|c| c.expires).min();
        match (a, b) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        }
    }

    /// Run due retransmissions and expiries. Returns the next [`Event`];
    /// call repeatedly until it returns `None`.
    pub fn poll<T: Transport + ?Sized>(&mut self, now: Instant, tr: &mut T) -> Option<Event> {
        for i in 0..CACHE {
            if matches!(&self.cache[i], Some(x) if x.expires <= now) {
                self.release_cached(i);
            }
        }
        for i in 0..REQ {
            let Some(p) = self.pending[i].as_mut() else {
                continue;
            };
            if now < p.next {
                continue;
            }
            if !p.confirmable || p.retx_left == 0 {
                let user = p.user;
                self.release_pending(i);
                if let Some(user) = user {
                    return Some(Event::Timeout { user });
                }
                continue;
            }
            p.retx_left -= 1;
            p.timeout = p.timeout.saturating_mul(2);
            p.next = now.saturating_add(p.timeout);
            if !p.acknowledged {
                let n = self.pool.read(&p.buf, &mut self.scratch[..p.len]);
                let _ = tr.send(&p.peer, &p.opts, &self.scratch[..n]);
            }
        }
        None
    }
}

#[cfg(test)]
mod tests;
