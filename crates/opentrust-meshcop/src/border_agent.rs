//! The Border Agent and the client side of an external Commissioner
//! (Thread 1.4.1 sections 8.4.1 / 8.4.2, OT `meshcop/border_agent.cpp`).
//!
//! [`BorderAgent`] runs on a Thread device with an external interface. An
//! external Commissioner Candidate connects with DTLS (EC-JPAKE with the
//! PSKc of the Active Dataset) to the Border Agent's UDP port. Over the
//! session:
//!
//! - `/c/cp` (COMM_PET) and `/c/ca` (COMM_KA) are forwarded to the Leader
//!   ALOC as `/c/lp` / `/c/la`, answered with an empty ACK first and the
//!   Leader's answer later as a separate NON response (OT
//!   `ForwardToLeader`). An accepted petition makes the session the active
//!   Commissioner: the Commissioner ALOC is configured on the Border Agent
//!   and Relay Receive / UDP proxy traffic is forwarded to it.
//! - `/c/tx` (RLY_TX) goes to the Joiner Router named in the Joiner Router
//!   Locator TLV as TMF.
//! - `/c/cg`, `/c/ag`, `/c/pg` are answered locally (the Border Agent's
//!   non-authoritative view; the Network Key is included, OT
//!   `kIgnoreSecurityPolicyFlags`, the Commissioner is authenticated with
//!   the PSKc).
//! - `/c/ut` (UDP_TX) sends the encapsulated UDP payload from the
//!   Commissioner ALOC; UDP datagrams to the Commissioner ALOC come back as
//!   `/c/ur` (UDP_RX). Management SET requests travel this way to the
//!   Leader ALOC (Thread 1.4.1 section 8.4.2.2).
//!
//! One Commissioner session at a time; the session is closed after
//! [`KEEP_ALIVE_TIMEOUT`] without COMM_KA, and a new one is accepted only
//! [`GUARD_TIME`] after the previous one ended (OT
//! `kGuardTimeNewConnectionMilli`). The number of connection attempts can
//! be limited ([`BorderAgent::set_max_connection_attempts`]).
//!
//! [`BorderAgentClient`] is the external Commissioner's end: the DTLS
//! client to a Border Agent and a [`CommissionerIo`] for the
//! [`Commissioner`] core
//! ([`ExternalTransport`]).
//!
//! Feature `border-agent`.

use core::net::{Ipv6Addr, SocketAddrV6};

use heapless::{Deque, Vec};
use opentrust_coap::endpoint::{
    Endpoint, Event, Peer, RequestCtx, ResourceId, Rx, RxInfo, SendOpts, Transport,
};
use opentrust_coap::message::{Code, MessageBuilder, Type};
use opentrust_coap::tmf::UDP_PORT as TMF_PORT;
use opentrust_coap::uri::Uri;
use opentrust_core::bytes::Writer;
use opentrust_core::crypto::backend::CryptoBackend;
use opentrust_core::crypto::ecjpake::P256;
use opentrust_core::time::{Duration, Instant};
use opentrust_core::types::{Prefix64, Pskc, Rloc16};
use opentrust_core::{Error, Result};
use opentrust_dtls::{Config, Session, State as DtlsState};
use rand_core::CryptoRng;

use crate::commissioner::{Commissioner, CommissionerIo, LEADER_ALOC16, commissioner_aloc16};
use crate::dataset::DatasetType;
use crate::leader::commissioner_get_payload;
use crate::manager::Datasets;
use crate::mgmt::get_payload;
use crate::secure::{self, DtlsTx, MAX_CONTENT_LEN};
use crate::tlv::{State, Tlvs, WriterExt};

/// Close a Commissioner session without COMM_KA for this long
/// (`BorderAgent::kKeepAliveTimeout`).
pub const KEEP_ALIVE_TIMEOUT: Duration = Duration::from_secs(50);
/// No new session for this long after one ended
/// (`SecureSession::kGuardTimeNewConnectionMilli`).
pub const GUARD_TIME: Duration = Duration::from_millis(2000);
/// Requests forwarded to the Leader and waiting for its answer.
pub const MAX_FORWARDS: usize = 4;

const USER_BASE: u32 = 0xba00_0000;

/// Is `user` the tag of a Border Agent forward (to route TMF responses to
/// [`BorderAgent::handle_tmf_response`])?
pub const fn is_border_agent_user(user: u32) -> bool {
    user & 0xffff_0000 == USER_BASE
}

const RESOURCES: [Uri; 7] = [
    Uri::CommissionerPetition,
    Uri::CommissionerKeepAlive,
    Uri::RelayTx,
    Uri::CommissionerGet,
    Uri::ActiveGet,
    Uri::PendingGet,
    Uri::ProxyTx,
];

/// What the Border Agent needs from the stack.
pub trait BorderAgentIo {
    /// Send a DTLS datagram to the Commissioner on the external interface
    /// (from the Border Agent UDP port).
    fn send_to_commissioner(&mut self, peer: &Peer, data: &[u8]) -> Result<()>;
    /// Send a TMF POST for `uri` to `dst` from our RLOC; `confirmable`
    /// selects CON / NON; the response to a CON is fed back through
    /// [`BorderAgent::handle_tmf_response`] with `user`.
    fn tmf_post(
        &mut self,
        now: Instant,
        dst: Ipv6Addr,
        uri: Uri,
        payload: &[u8],
        confirmable: bool,
        user: Option<u32>,
    ) -> Result<()>;
    /// Send a UDP datagram on the Thread interface (UDP proxy, `src` is
    /// the Commissioner ALOC).
    fn send_udp(&mut self, src: &SocketAddrV6, dst: &SocketAddrV6, payload: &[u8]) -> Result<()>;
    /// Add (`Some`) or remove (`None`) the Commissioner ALOC16 on the
    /// Thread interface; while set, UDP datagrams to it go to
    /// [`BorderAgent::handle_proxy_rx`].
    fn set_commissioner_aloc(&mut self, aloc16: Option<u16>);
}

/// The local state the Border Agent answers from.
#[derive(Debug, Clone, Copy)]
pub struct BorderAgentView<'a> {
    /// The dataset managers (`/c/ag`, `/c/pg`).
    pub datasets: &'a Datasets,
    /// The Commissioning Data of the Network Data (`/c/cg`).
    pub commissioning_data: Option<&'a [u8]>,
    /// Mesh-local prefix.
    pub mesh_local_prefix: Prefix64,
}

/// Notification of the Border Agent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BorderAgentEvent {
    /// A Commissioner Candidate completed the DTLS handshake.
    Connected(Peer),
    /// The session ended (closed by either side, failed or timed out).
    Disconnected(Peer),
    /// The Leader accepted the Candidate's petition (session ID).
    PetitionAccepted(u16),
    /// The connection attempts are used up; the Border Agent refuses new
    /// sessions until [`BorderAgent::set_max_connection_attempts`].
    AttemptsExhausted,
}

#[derive(Debug, Clone, Copy)]
struct Forward {
    user: u32,
    ctx: RequestCtx,
    petition: bool,
}

struct BaSession<B: CryptoBackend, C: P256> {
    dtls: Session<B, C>,
    peer: Peer,
    connected: bool,
    aloc16: Option<u16>,
    keep_alive_deadline: Option<Instant>,
}

/// The Border Agent (OT `MeshCoP::BorderAgent`).
pub struct BorderAgent<B: CryptoBackend, C: P256> {
    crypto: B,
    curve: C,
    id: [u8; 16],
    pskc: Option<Pskc>,
    session: Option<BaSession<B, C>>,
    guard_until: Option<Instant>,
    max_attempts: u16,
    remaining_attempts: u16,
    coap: Endpoint<2, 7, 2, MAX_CONTENT_LEN>,
    forwards: Vec<Forward, MAX_FORWARDS>,
    next_user: u16,
    events: Deque<BorderAgentEvent, 4>,
}

impl<B: CryptoBackend, C: P256> core::fmt::Debug for BorderAgent<B, C> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("BorderAgent")
            .field("id", &self.id)
            .field("session", &self.session.as_ref().map(|s| s.peer))
            .finish_non_exhaustive()
    }
}

impl<B, C> BorderAgent<B, C>
where
    B: CryptoBackend + Clone,
    B::Sha256: Clone,
    C: P256 + Clone,
{
    /// A Border Agent with the Border Agent ID `id` (OT generates it
    /// randomly once and stores it). No PSKc yet: sessions are refused.
    pub fn new(crypto: B, curve: C, id: [u8; 16]) -> Self {
        let mut coap = Endpoint::new(0, Default::default());
        for u in RESOURCES {
            let _ = coap.add_resource(u.path(), ResourceId(u.id()));
        }
        Self {
            crypto,
            curve,
            id,
            pskc: None,
            session: None,
            guard_until: None,
            max_attempts: 0,
            remaining_attempts: 0,
            coap,
            forwards: Vec::new(),
            next_user: 0,
            events: Deque::new(),
        }
    }

    /// The Border Agent ID.
    pub fn id(&self) -> &[u8; 16] {
        &self.id
    }

    /// Set the PSKc (from the Active Dataset); the old one is wiped.
    pub fn set_pskc(&mut self, pskc: Option<Pskc>) {
        self.pskc = pskc;
    }

    /// Limit the number of DTLS connection attempts (`0`: unlimited; OT
    /// `SetMaxConnectionAttempts`); resets the remaining count.
    pub fn set_max_connection_attempts(&mut self, n: u16) {
        self.max_attempts = n;
        self.remaining_attempts = n;
    }

    /// A Commissioner session is connected.
    pub fn is_connected(&self) -> bool {
        self.session.as_ref().is_some_and(|s| s.connected)
    }

    /// The active Commissioner's ALOC16, if its petition was accepted.
    pub fn commissioner_aloc16(&self) -> Option<u16> {
        self.session.as_ref().and_then(|s| s.aloc16)
    }

    /// The next notification.
    pub fn pop_event(&mut self) -> Option<BorderAgentEvent> {
        self.events.pop_front()
    }

    fn event(&mut self, e: BorderAgentEvent) {
        if self.events.is_full() {
            self.events.pop_front();
        }
        let _ = self.events.push_back(e);
    }

    /// A UDP datagram from the external interface to the Border Agent
    /// port.
    pub fn handle_udp<R: CryptoRng + ?Sized, I: BorderAgentIo + ?Sized>(
        &mut self,
        now: Instant,
        rng: &mut R,
        io: &mut I,
        view: &BorderAgentView<'_>,
        peer: &Peer,
        datagram: &[u8],
    ) {
        if self.session.is_none() && !self.accept_session(now, rng, peer) {
            return;
        }
        if self.session.as_ref().is_some_and(|s| s.peer != *peer) {
            // One Commissioner session at a time.
            return;
        }
        let mut rest = datagram;
        let mut app = [0u8; MAX_CONTENT_LEN];
        while let Some(s) = self.session.as_mut() {
            let got = secure::next_app_data(&mut s.dtls, now, rng, &mut rest, &mut app);
            let p = s.peer;
            let _ = secure::flush(&mut s.dtls, |d| io.send_to_commissioner(&p, d));
            self.check_session(now, io);
            let Some(n) = got else { break };
            self.handle_coap(now, io, view, &app[..n]);
        }
    }

    fn accept_session<R: CryptoRng + ?Sized>(
        &mut self,
        now: Instant,
        rng: &mut R,
        peer: &Peer,
    ) -> bool {
        if self.guard_until.is_some_and(|g| now < g) {
            return false;
        }
        let Some(pskc) = self.pskc.as_ref() else {
            return false;
        };
        if self.max_attempts > 0 {
            if self.remaining_attempts == 0 {
                return false;
            }
            self.remaining_attempts -= 1;
        }
        let mut id = [0u8; 18];
        id[..16].copy_from_slice(&peer.addr.octets());
        id[16..].copy_from_slice(&peer.port.to_be_bytes());
        let Ok(dtls) = Session::server(
            self.crypto.clone(),
            self.curve.clone(),
            &pskc.0,
            Config::default(),
            &id,
            rng,
        ) else {
            return false;
        };
        self.coap.clear();
        self.coap = Endpoint::new(rng.next_u32() as u16, Default::default());
        for u in RESOURCES {
            let _ = self.coap.add_resource(u.path(), ResourceId(u.id()));
        }
        self.session = Some(BaSession {
            dtls,
            peer: *peer,
            connected: false,
            aloc16: None,
            keep_alive_deadline: None,
        });
        true
    }

    fn check_session<I: BorderAgentIo + ?Sized>(&mut self, now: Instant, io: &mut I) {
        let Some(s) = self.session.as_mut() else {
            return;
        };
        match s.dtls.state() {
            DtlsState::Connected if !s.connected => {
                s.connected = true;
                s.keep_alive_deadline = Some(now.saturating_add(KEEP_ALIVE_TIMEOUT));
                let p = s.peer;
                self.event(BorderAgentEvent::Connected(p));
            }
            DtlsState::Closed(_) => self.end_session(now, io),
            _ => {}
        }
    }

    /// Drop the session: ALOC removed, forwards forgotten, guard time.
    fn end_session<I: BorderAgentIo + ?Sized>(&mut self, now: Instant, io: &mut I) {
        let Some(mut s) = self.session.take() else {
            return;
        };
        if !matches!(s.dtls.state(), DtlsState::Closed(_)) {
            s.dtls.close();
            let p = s.peer;
            let _ = secure::flush(&mut s.dtls, |d| io.send_to_commissioner(&p, d));
        }
        if s.aloc16.is_some() {
            io.set_commissioner_aloc(None);
        }
        self.forwards.clear();
        self.coap.clear();
        self.guard_until = Some(now.saturating_add(GUARD_TIME));
        self.event(BorderAgentEvent::Disconnected(s.peer));
        if self.max_attempts > 0 && self.remaining_attempts == 0 {
            self.event(BorderAgentEvent::AttemptsExhausted);
        }
    }

    fn handle_coap<I: BorderAgentIo + ?Sized>(
        &mut self,
        now: Instant,
        io: &mut I,
        view: &BorderAgentView<'_>,
        data: &[u8],
    ) {
        let Some(s) = self.session.as_mut() else {
            return;
        };
        let p = s.peer;
        let info = RxInfo {
            peer: p,
            dst: Ipv6Addr::UNSPECIFIED,
        };
        let req = {
            let mut tx = DtlsTx {
                session: &mut s.dtls,
                out: |d: &[u8]| io.send_to_commissioner(&p, d),
            };
            match self.coap.handle_datagram(now, &mut tx, &info, data) {
                Rx::Request(r) => r,
                _ => return,
            }
        };
        let Some(uri) = Uri::from_id(req.resource.0) else {
            return;
        };
        let payload = req.msg.payload();
        let mlp = view.mesh_local_prefix;
        match uri {
            Uri::CommissionerPetition => {
                self.forward_to_leader(now, io, &mlp, &req.ctx, Uri::LeaderPetition, payload, true);
            }
            Uri::CommissionerKeepAlive if s_active(&self.session) => {
                if let Some(s) = self.session.as_mut() {
                    s.keep_alive_deadline = Some(now.saturating_add(KEEP_ALIVE_TIMEOUT));
                }
                self.forward_to_leader(
                    now,
                    io,
                    &mlp,
                    &req.ctx,
                    Uri::LeaderKeepAlive,
                    payload,
                    false,
                );
            }
            Uri::RelayTx => {
                // OT `HandleTmfRelayTx`: NON only, to the Joiner Router.
                if req.msg.ty() != Type::Non {
                    return;
                }
                if let Ok(jr) = Tlvs(payload).joiner_router_locator() {
                    let _ = io.tmf_post(
                        now,
                        mlp.rloc(Rloc16(jr)),
                        Uri::RelayTx,
                        payload,
                        false,
                        None,
                    );
                }
            }
            Uri::CommissionerGet | Uri::ActiveGet | Uri::PendingGet => {
                let mut buf = [0u8; 300];
                let n = match uri {
                    Uri::CommissionerGet => {
                        commissioner_get_payload(view.commissioning_data, payload, &mut buf)
                    }
                    Uri::ActiveGet => get_payload(
                        view.datasets,
                        now,
                        DatasetType::Active,
                        payload,
                        false,
                        &mut buf,
                    ),
                    _ => get_payload(
                        view.datasets,
                        now,
                        DatasetType::Pending,
                        payload,
                        false,
                        &mut buf,
                    ),
                };
                let code = if n.is_some() {
                    Code::CHANGED
                } else {
                    Code::BAD_REQUEST
                };
                self.respond(now, io, &req.ctx, code, &buf[..n.unwrap_or(0)]);
                // The answer may hold the Network Key.
                zeroize::Zeroize::zeroize(&mut buf);
            }
            Uri::ProxyTx => {
                // OT `HandleTmfProxyTx`, only for the active Commissioner
                // (the source is its ALOC).
                let Some(aloc16) = self.session.as_ref().and_then(|s| s.aloc16) else {
                    return;
                };
                let t = Tlvs(payload);
                let (Ok((sp, dp, data)), Ok(dst)) = (t.udp_encapsulation(), t.ipv6_address())
                else {
                    return;
                };
                if sp == 0 || dp == 0 {
                    return;
                }
                let Ok(src) = mlp.aloc(aloc16) else { return };
                let _ = io.send_udp(
                    &SocketAddrV6::new(src, sp, 0, 0),
                    &SocketAddrV6::new(dst, dp, 0, 0),
                    data,
                );
            }
            _ => {}
        }
    }

    fn respond<I: BorderAgentIo + ?Sized>(
        &mut self,
        now: Instant,
        io: &mut I,
        ctx: &RequestCtx,
        code: Code,
        payload: &[u8],
    ) {
        let Some(s) = self.session.as_mut() else {
            return;
        };
        let p = s.peer;
        let mut tx = DtlsTx {
            session: &mut s.dtls,
            out: |d: &[u8]| io.send_to_commissioner(&p, d),
        };
        let _ = self
            .coap
            .respond_payload(now, &mut tx, ctx, &SendOpts::default(), code, payload);
    }

    /// OT `ForwardToLeader` (separate response).
    #[allow(clippy::too_many_arguments)]
    fn forward_to_leader<I: BorderAgentIo + ?Sized>(
        &mut self,
        now: Instant,
        io: &mut I,
        mlp: &Prefix64,
        ctx: &RequestCtx,
        uri: Uri,
        payload: &[u8],
        petition: bool,
    ) {
        if let Some(s) = self.session.as_mut() {
            let p = s.peer;
            let mut tx = DtlsTx {
                session: &mut s.dtls,
                out: |d: &[u8]| io.send_to_commissioner(&p, d),
            };
            if ctx.ty == Type::Con {
                let _ = self.coap.ack_empty(&mut tx, ctx);
            }
        }
        self.next_user = self.next_user.wrapping_add(1);
        let user = USER_BASE | u32::from(self.next_user);
        let mut sep = *ctx;
        sep.ty = Type::Non;
        let r = if self.forwards.is_full() {
            Err(Error::NoBufs)
        } else {
            mlp.aloc(LEADER_ALOC16)
                .and_then(|dst| io.tmf_post(now, dst, uri, payload, true, Some(user)))
        };
        match r {
            Ok(()) => {
                let _ = self.forwards.push(Forward {
                    user,
                    ctx: sep,
                    petition,
                });
            }
            Err(e) => self.respond(now, io, &sep, error_code(e), &[]),
        }
    }

    /// The Leader's answer to a forwarded request (`user` tagged with
    /// [`is_border_agent_user`]): relayed to the Commissioner; an accepted
    /// petition makes it the active Commissioner (OT `HandleCoapResponse`).
    pub fn handle_tmf_response<I: BorderAgentIo + ?Sized>(
        &mut self,
        now: Instant,
        io: &mut I,
        user: u32,
        result: core::result::Result<(Code, &[u8]), Error>,
    ) {
        let Some(i) = self.forwards.iter().position(|f| f.user == user) else {
            return;
        };
        let f = self.forwards.swap_remove(i);
        let (code, payload) = match result {
            Ok(r) => r,
            Err(e) => {
                self.respond(now, io, &f.ctx, error_code(e), &[]);
                return;
            }
        };
        if f.petition && code == Code::CHANGED {
            let t = Tlvs(payload);
            if t.state() == Ok(State::Accept)
                && let Ok(sid) = t.commissioner_session_id()
                && let Some(s) = self.session.as_mut()
            {
                let aloc = commissioner_aloc16(sid);
                s.aloc16 = Some(aloc);
                io.set_commissioner_aloc(Some(aloc));
                self.event(BorderAgentEvent::PetitionAccepted(sid));
            }
        }
        self.respond(now, io, &f.ctx, code, payload);
    }

    /// `/c/rx` from a Joiner Router (OT `HandleTmf<kUriRelayRx>`): to the
    /// active Commissioner over DTLS (NON only).
    pub fn handle_relay_rx<R: CryptoRng + ?Sized, I: BorderAgentIo + ?Sized>(
        &mut self,
        now: Instant,
        rng: &mut R,
        io: &mut I,
        confirmable: bool,
        payload: &[u8],
    ) -> Result<()> {
        if confirmable {
            return Err(Error::Drop);
        }
        self.send_to_active(now, rng, io, Uri::RelayRx, |w| w.write_slice(payload))
    }

    /// A UDP datagram on the Thread interface to the Commissioner ALOC
    /// (OT `HandleUdpReceive`): to the Commissioner as `/c/ur`.
    pub fn handle_proxy_rx<R: CryptoRng + ?Sized, I: BorderAgentIo + ?Sized>(
        &mut self,
        now: Instant,
        rng: &mut R,
        io: &mut I,
        src: &SocketAddrV6,
        dst_port: u16,
        payload: &[u8],
    ) -> Result<()> {
        if payload.is_empty() {
            return Err(Error::Drop);
        }
        self.send_to_active(now, rng, io, Uri::ProxyRx, |w| {
            w.udp_encapsulation(src.port(), dst_port, payload)?;
            w.ipv6_address(src.ip())
        })
    }

    fn send_to_active<R, I, F>(
        &mut self,
        now: Instant,
        rng: &mut R,
        io: &mut I,
        uri: Uri,
        f: F,
    ) -> Result<()>
    where
        R: CryptoRng + ?Sized,
        I: BorderAgentIo + ?Sized,
        F: FnOnce(&mut Writer<'_>) -> Result<()>,
    {
        let s = self
            .session
            .as_mut()
            .filter(|s| s.aloc16.is_some())
            .ok_or(Error::InvalidState)?;
        let p = s.peer;
        let mut tx = DtlsTx {
            session: &mut s.dtls,
            out: |d: &[u8]| io.send_to_commissioner(&p, d),
        };
        self.coap.send_request(
            now,
            rng,
            &mut tx,
            &p,
            &SendOpts::default(),
            Type::Non,
            Code::POST,
            None,
            |mut b| {
                b.uri_path(uri.path())?;
                b.finish_with(f)
            },
        )
    }

    /// When [`poll`](Self::poll) must be called next.
    pub fn next_deadline(&self) -> Option<Instant> {
        let s = self.session.as_ref().and_then(|s| {
            [s.dtls.next_timeout(), s.keep_alive_deadline]
                .into_iter()
                .flatten()
                .min()
        });
        [s, self.coap.next_deadline()].into_iter().flatten().min()
    }

    /// Run timers: DTLS / CoAP retransmissions and the keep-alive timeout.
    pub fn poll<I: BorderAgentIo + ?Sized>(&mut self, now: Instant, io: &mut I) {
        let Some(s) = self.session.as_mut() else {
            return;
        };
        if s.keep_alive_deadline.is_some_and(|d| d <= now) {
            self.end_session(now, io);
            return;
        }
        s.dtls.handle_timeout(now);
        let p = s.peer;
        let _ = secure::flush(&mut s.dtls, |d| io.send_to_commissioner(&p, d));
        let mut tx = DtlsTx {
            session: &mut s.dtls,
            out: |d: &[u8]| io.send_to_commissioner(&p, d),
        };
        while let Some(Event::Timeout { .. }) = self.coap.poll(now, &mut tx) {}
        self.check_session(now, io);
    }

    /// Close the Commissioner session (e.g. the partition changed, Thread
    /// 1.4.1 section 8.4.1.4).
    pub fn disconnect<I: BorderAgentIo + ?Sized>(&mut self, now: Instant, io: &mut I) {
        self.end_session(now, io);
    }
}

fn s_active<B: CryptoBackend, C: P256>(s: &Option<BaSession<B, C>>) -> bool {
    s.as_ref().is_some_and(|s| s.aloc16.is_some())
}

/// OT `CoapCodeFromError`.
fn error_code(e: Error) -> Code {
    match e {
        Error::Parse => Code::BAD_REQUEST,
        _ => Code::INTERNAL_ERROR,
    }
}

// ------------------------------------------------------------------ client

/// Source port of the UDP-proxied TMF requests of an external
/// Commissioner (any non-zero port works; the Border Agent answers to it).
pub const PROXY_PORT: u16 = 49191;

const RES_RELAY_RX: ResourceId = ResourceId(Uri::RelayRx.id());
const RES_PROXY_RX: ResourceId = ResourceId(Uri::ProxyRx.id());

/// The external Commissioner's DTLS client to a Border Agent.
pub struct BorderAgentClient<B: CryptoBackend, C: P256> {
    dtls: Option<Session<B, C>>,
    peer: Peer,
    mlp: Prefix64,
    coap: Endpoint<4, 2, 2, MAX_CONTENT_LEN>,
    proxy: Endpoint<2, 1, 1, MAX_CONTENT_LEN>,
    ut_mid: u16,
    tokens: TokenRng,
}

/// CoAP token source of the client (seeded from the caller's RNG; tokens
/// only match responses, they are not secrets).
#[derive(Debug)]
struct TokenRng(u64);

impl rand_core::TryRng for TokenRng {
    type Error = core::convert::Infallible;
    fn try_next_u32(&mut self) -> core::result::Result<u32, Self::Error> {
        Ok((self.try_next_u64()? >> 32) as u32)
    }
    fn try_next_u64(&mut self) -> core::result::Result<u64, Self::Error> {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        Ok(self.0.wrapping_mul(0x2545_F491_4F6C_DD1D))
    }
    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> core::result::Result<(), Self::Error> {
        for chunk in dst.chunks_mut(8) {
            let v = self.try_next_u64()?.to_le_bytes();
            chunk.copy_from_slice(&v[..chunk.len()]);
        }
        Ok(())
    }
}

impl<B: CryptoBackend, C: P256> core::fmt::Debug for BorderAgentClient<B, C> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("BorderAgentClient")
            .field("peer", &self.peer)
            .finish_non_exhaustive()
    }
}

impl<B, C> BorderAgentClient<B, C>
where
    B: CryptoBackend + Clone,
    B::Sha256: Clone,
    C: P256 + Clone,
{
    /// Start the DTLS handshake with the Border Agent at `peer` using the
    /// PSKc; `mlp` is the network's mesh-local prefix (for the Leader ALOC
    /// of proxied requests). Datagrams go to `out`.
    #[allow(clippy::too_many_arguments)]
    pub fn connect<R: CryptoRng + ?Sized>(
        crypto: B,
        curve: C,
        pskc: &Pskc,
        peer: Peer,
        mlp: Prefix64,
        now: Instant,
        rng: &mut R,
        out: &mut dyn FnMut(&[u8]) -> Result<()>,
    ) -> Result<Self> {
        let mut dtls = Session::client(crypto, curve, &pskc.0, Config::default(), now, rng)?;
        secure::flush(&mut dtls, &mut *out)?;
        let mut coap = Endpoint::new(rng.next_u32() as u16, Default::default());
        coap.add_resource(Uri::RelayRx.path(), RES_RELAY_RX)?;
        coap.add_resource(Uri::ProxyRx.path(), RES_PROXY_RX)?;
        Ok(Self {
            dtls: Some(dtls),
            peer,
            mlp,
            coap,
            proxy: Endpoint::new(rng.next_u32() as u16, Default::default()),
            ut_mid: rng.next_u32() as u16,
            tokens: TokenRng(rng.next_u64() | 1),
        })
    }

    /// DTLS state.
    pub fn state(&self) -> DtlsState {
        self.dtls
            .as_ref()
            .map_or(DtlsState::Closed(opentrust_dtls::CloseReason::Local), |s| {
                s.state()
            })
    }

    /// Close the session (close_notify).
    pub fn close(&mut self, out: &mut dyn FnMut(&[u8]) -> Result<()>) {
        if let Some(s) = self.dtls.as_mut() {
            s.close();
            let _ = secure::flush(s, &mut *out);
        }
    }

    /// When [`poll`](Self::poll) must be called next.
    pub fn next_deadline(&self) -> Option<Instant> {
        [
            self.dtls.as_ref().and_then(|s| s.next_timeout()),
            self.coap.next_deadline(),
            self.proxy.next_deadline(),
        ]
        .into_iter()
        .flatten()
        .min()
    }

    /// Run DTLS and CoAP timers and the Commissioner core's timers
    /// ([`Commissioner::poll`]); request timeouts are reported to the core.
    pub fn poll<const J: usize>(
        &mut self,
        now: Instant,
        out: &mut dyn FnMut(&[u8]) -> Result<()>,
        comm: &mut Commissioner<B, C, J>,
    ) {
        let Some(s) = self.dtls.as_mut() else { return };
        s.handle_timeout(now);
        let _ = secure::flush(s, &mut *out);
        let mut timeouts: Vec<u32, 4> = Vec::new();
        {
            let mut tx = DtlsTx {
                session: s,
                out: &mut *out,
            };
            while let Some(Event::Timeout { user }) = self.coap.poll(now, &mut tx) {
                let _ = timeouts.push(user);
            }
        }
        {
            let mut ptx = ProxyTx {
                dtls: self.dtls.as_mut(),
                ut_mid: &mut self.ut_mid,
                out: &mut *out,
            };
            while let Some(Event::Timeout { user }) = self.proxy.poll(now, &mut ptx) {
                let _ = timeouts.push(user);
            }
        }
        for user in timeouts {
            let mut t = ExternalTransport {
                client: self,
                out: &mut *out,
            };
            let _ = comm.handle_response(now, &mut t, user, Err(Error::ResponseTimeout));
        }
        let mut t = ExternalTransport {
            client: self,
            out: &mut *out,
        };
        comm.poll(now, &mut t);
    }

    /// A datagram from the Border Agent: DTLS records; responses and
    /// `/c/rx` / `/c/ur` go to the Commissioner core.
    pub fn handle_datagram<R, const J: usize>(
        &mut self,
        now: Instant,
        rng: &mut R,
        out: &mut dyn FnMut(&[u8]) -> Result<()>,
        comm: &mut Commissioner<B, C, J>,
        datagram: &[u8],
    ) where
        R: CryptoRng + ?Sized,
    {
        let mut rest = datagram;
        let mut app = [0u8; MAX_CONTENT_LEN];
        loop {
            let Some(s) = self.dtls.as_mut() else { return };
            let got = secure::next_app_data(s, now, rng, &mut rest, &mut app);
            let _ = secure::flush(s, &mut *out);
            let Some(n) = got else { return };
            self.handle_coap(now, rng, out, comm, &app[..n]);
        }
    }

    fn handle_coap<R, const J: usize>(
        &mut self,
        now: Instant,
        rng: &mut R,
        out: &mut dyn FnMut(&[u8]) -> Result<()>,
        comm: &mut Commissioner<B, C, J>,
        data: &[u8],
    ) where
        R: CryptoRng + ?Sized,
    {
        let info = RxInfo {
            peer: self.peer,
            dst: Ipv6Addr::UNSPECIFIED,
        };
        let Some(s) = self.dtls.as_mut() else { return };
        let rx = {
            let mut tx = DtlsTx {
                session: s,
                out: &mut *out,
            };
            self.coap.handle_datagram(now, &mut tx, &info, data)
        };
        match rx {
            Rx::Response { user, msg, .. } => {
                let mut t = ExternalTransport { client: self, out };
                let _ = comm.handle_response(now, &mut t, user, Ok((msg.code(), msg.payload())));
            }
            Rx::Failed { user, error } => {
                let mut t = ExternalTransport { client: self, out };
                let _ = comm.handle_response(now, &mut t, user, Err(error));
            }
            Rx::Request(req) if req.resource == RES_RELAY_RX => {
                let confirmable = req.msg.ty() == Type::Con;
                let mut t = ExternalTransport { client: self, out };
                let _ = comm.handle_relay_rx(now, rng, &mut t, confirmable, req.msg.payload());
            }
            Rx::Request(req) if req.resource == RES_PROXY_RX => {
                let t = Tlvs(req.msg.payload());
                let (Ok((sp, dp, payload)), Ok(src)) = (t.udp_encapsulation(), t.ipv6_address())
                else {
                    return;
                };
                if dp != PROXY_PORT {
                    return;
                }
                let pinfo = RxInfo {
                    peer: Peer::new(src, sp),
                    dst: Ipv6Addr::UNSPECIFIED,
                };
                let prx = {
                    let mut ptx = ProxyTx {
                        dtls: self.dtls.as_mut(),
                        ut_mid: &mut self.ut_mid,
                        out: &mut *out,
                    };
                    self.proxy.handle_datagram(now, &mut ptx, &pinfo, payload)
                };
                let r = match prx {
                    Rx::Response { user, msg, .. } => Some((user, Ok((msg.code(), msg.payload())))),
                    Rx::Failed { user, error } => Some((user, Err(error))),
                    _ => None,
                };
                if let Some((user, res)) = r {
                    let mut t = ExternalTransport { client: self, out };
                    let _ = comm.handle_response(now, &mut t, user, res);
                }
            }
            _ => {}
        }
    }
}

/// Encapsulate proxied TMF in `/c/ut` (NON, built by hand so the proxy
/// endpoint's transport needs no RNG).
struct ProxyTx<'a, B: CryptoBackend, C: P256> {
    dtls: Option<&'a mut Session<B, C>>,
    ut_mid: &'a mut u16,
    out: &'a mut dyn FnMut(&[u8]) -> Result<()>,
}

impl<B, C> Transport for ProxyTx<'_, B, C>
where
    B: CryptoBackend,
    B::Sha256: Clone,
    C: P256,
{
    fn send(&mut self, peer: &Peer, _opts: &SendOpts, data: &[u8]) -> Result<()> {
        let s = self.dtls.as_mut().ok_or(Error::InvalidState)?;
        *self.ut_mid = self.ut_mid.wrapping_add(1);
        let mid = *self.ut_mid;
        let mut b = [0u8; MAX_CONTENT_LEN];
        let mut m = MessageBuilder::new(&mut b, Type::Non, Code::POST, mid, &mid.to_be_bytes())?;
        m.uri_path(Uri::ProxyTx.path())?;
        let n = m.finish_with(|w| {
            w.udp_encapsulation(PROXY_PORT, peer.port, data)?;
            w.ipv6_address(&peer.addr)
        })?;
        let mut rec = [0u8; opentrust_dtls::coaps::MAX_DATAGRAM_LEN];
        let r = s.send(&b[..n], &mut rec)?;
        (self.out)(&rec[..r])
    }
}

/// [`CommissionerIo`] of an external Commissioner over a
/// [`BorderAgentClient`]: COMM_PET / COMM_KA / `/c/cg` / `/c/ag` / `/c/pg`
/// and `/c/tx` over DTLS to the Border Agent, all other management requests
/// (`/c/cs`, `/c/as`, `/c/ps`, ...) to the Leader ALOC through the UDP
/// proxy.
pub struct ExternalTransport<'a, B: CryptoBackend, C: P256> {
    /// The client.
    pub client: &'a mut BorderAgentClient<B, C>,
    /// Datagrams to the Border Agent.
    pub out: &'a mut dyn FnMut(&[u8]) -> Result<()>,
}

impl<B: CryptoBackend, C: P256> core::fmt::Debug for ExternalTransport<'_, B, C> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("ExternalTransport")
    }
}

impl<B, C> CommissionerIo for ExternalTransport<'_, B, C>
where
    B: CryptoBackend + Clone,
    B::Sha256: Clone,
    C: P256 + Clone,
{
    fn request(&mut self, now: Instant, uri: Uri, payload: &[u8], user: u32) -> Result<()> {
        let c = &mut *self.client;
        let direct = match uri {
            Uri::LeaderPetition => Some(Uri::CommissionerPetition),
            Uri::LeaderKeepAlive => Some(Uri::CommissionerKeepAlive),
            Uri::CommissionerGet | Uri::ActiveGet | Uri::PendingGet => Some(uri),
            _ => None,
        };
        match direct {
            Some(u) => {
                let s = c.dtls.as_mut().ok_or(Error::InvalidState)?;
                let mut tx = DtlsTx {
                    session: s,
                    out: &mut *self.out,
                };
                c.coap.post(
                    now,
                    &mut c.tokens,
                    &mut tx,
                    &c.peer,
                    &SendOpts::default(),
                    u.path(),
                    payload,
                    Some(user),
                )
            }
            None => {
                let dst = c.mlp.aloc(LEADER_ALOC16)?;
                let mut ptx = ProxyTx {
                    dtls: c.dtls.as_mut(),
                    ut_mid: &mut c.ut_mid,
                    out: &mut *self.out,
                };
                c.proxy.post(
                    now,
                    &mut c.tokens,
                    &mut ptx,
                    &Peer::new(dst, TMF_PORT),
                    &SendOpts::default(),
                    uri.path(),
                    payload,
                    Some(user),
                )
            }
        }
    }

    fn relay_tx(&mut self, now: Instant, _joiner_router: u16, payload: &[u8]) -> Result<()> {
        let c = &mut *self.client;
        let s = c.dtls.as_mut().ok_or(Error::InvalidState)?;
        let mut tx = DtlsTx {
            session: s,
            out: &mut *self.out,
        };
        c.coap.send_request(
            now,
            &mut c.tokens,
            &mut tx,
            &c.peer,
            &SendOpts::default(),
            Type::Non,
            Code::POST,
            None,
            |mut b| {
                b.uri_path(Uri::RelayTx.path())?;
                b.finish_with_payload(payload)
            },
        )
    }
}
