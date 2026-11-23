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
//! One Commissioner session at a time per listener; the session is closed
//! after [`KEEP_ALIVE_TIMEOUT`] without COMM_KA, and a new one is accepted
//! only [`GUARD_TIME`] after the previous one ended (OT
//! `kGuardTimeNewConnectionMilli`). The number of connection attempts can
//! be limited ([`BorderAgent::set_max_connection_attempts`]).
//!
//! # Ephemeral key (ePSKc)
//!
//! Besides the PSKc listener, a second, independent DTLS listener accepts
//! one Candidate authenticated with an ephemeral key
//! ([`BorderAgent::start_ephemeral_key`], [`epskc`], Thread 1.4.1
//! sections 8.4.1.2.3 and 8.4.9.4, OT `EphemeralKeyManager`). The key
//! octets are the EC-JPAKE password. The key is single-use and
//! short-lived: it is discarded when its session ends, when its timeout
//! expires (the session is closed), or after
//! [`epskc::MAX_CONNECTION_ATTEMPTS`] connection attempts. Its session is
//! served like a PSKc session (petition, keep-alive, gets with the Network
//! Key). While a key is set, the MeshCoP-ePSKc DNS-SD service is
//! advertised through [`BorderAgentIo::ephemeral_service`].
//!
//! [`BorderAgentClient`] is the external Commissioner's end: the DTLS
//! client to a Border Agent and a [`CommissionerIo`] for the
//! [`Commissioner`] core
//! ([`ExternalTransport`]).
//!
//! Feature `border-agent`.

use core::net::{Ipv6Addr, SocketAddrV6};

use heapless::{Deque, Vec};
use rand_core::CryptoRng;
use rs_thread_coap::endpoint::{
    Endpoint, Event, Peer, RequestCtx, ResourceId, Rx, RxInfo, SendOpts, Transport,
};
use rs_thread_coap::message::{Code, MessageBuilder, Type};
use rs_thread_coap::tmf::UDP_PORT as TMF_PORT;
use rs_thread_coap::uri::Uri;
use rs_thread_core::bytes::Writer;
use rs_thread_core::crypto::backend::CryptoBackend;
use rs_thread_core::crypto::ecjpake::P256;
use rs_thread_core::time::{Duration, Instant};
use rs_thread_core::types::{Prefix64, Pskc, Rloc16};
use rs_thread_core::{Error, Result};
use rs_thread_dtls::{CloseReason, Config, Session, State as DtlsState};

use crate::commissioner::{Commissioner, CommissionerIo, LEADER_ALOC16, commissioner_aloc16};
use crate::dataset::DatasetType;
use crate::epskc::{self, EphemeralKey};
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

/// The DTLS listener (UDP port) a Border Agent session belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Listener {
    /// The Border Agent port (PSKc; DNS-SD `_meshcop._udp`).
    Pskc,
    /// The ePSKc port (DNS-SD `_meshcop-e._udp`), open while an ephemeral
    /// key is set ([`BorderAgent::start_ephemeral_key`]).
    Ephemeral,
}

impl Listener {
    const fn idx(self) -> usize {
        match self {
            Listener::Pskc => 0,
            Listener::Ephemeral => 1,
        }
    }
}

const LISTENERS: [Listener; 2] = [Listener::Pskc, Listener::Ephemeral];

/// What the Border Agent needs from the stack.
pub trait BorderAgentIo {
    /// Send a DTLS datagram to the Commissioner on the external interface
    /// from the UDP port of `listener` (the Border Agent port, or the
    /// ePSKc port given to [`BorderAgent::start_ephemeral_key`]).
    fn send_to_commissioner(&mut self, listener: Listener, peer: &Peer, data: &[u8]) -> Result<()>;
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
    /// Register (`Some(port)`) or unregister (`None`) the MeshCoP-ePSKc
    /// DNS-SD service ([`epskc::SERVICE_TYPE`], same instance name as the
    /// MeshCoP service, SRV port `port`); OT
    /// `EphemeralKeyManager::RegisterOrUnregisterService`. The default
    /// does nothing (no DNS-SD on this device).
    fn ephemeral_service(&mut self, port: Option<u16>) {
        let _ = port;
    }
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

/// State of the ephemeral key (OT `EphemeralKeyManager::State`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum EphemeralKeyState {
    /// The ePSKc feature is disabled.
    Disabled,
    /// Enabled, no key set.
    Stopped,
    /// A key is set; the ePSKc port accepts a connection.
    Started,
    /// A Candidate is connected with the key (not petitioned).
    Connected,
    /// The connected Candidate is the active Commissioner.
    Accepted,
}

impl EphemeralKeyState {
    /// Is the MeshCoP-ePSKc service advertised in this state (OT
    /// `ShouldRegisterService`)?
    pub const fn is_active(self) -> bool {
        matches!(self, Self::Started | Self::Connected | Self::Accepted)
    }
}

/// Why the ephemeral key was discarded (OT `DeactivationReason`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum EphemeralKeyStopReason {
    /// [`BorderAgent::stop_ephemeral_key`], the feature was disabled, or
    /// the Border Agent closed the session.
    Local,
    /// The Candidate closed the session.
    PeerDisconnect,
    /// The session failed (fatal alert).
    SessionError,
    /// The session ended for lack of keep-alives.
    SessionTimeout,
    /// The connection attempts are used up
    /// ([`epskc::MAX_CONNECTION_ATTEMPTS`]).
    MaxAttempts,
    /// The key's timeout expired.
    Timeout,
}

/// Notification of the Border Agent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BorderAgentEvent {
    /// A Commissioner Candidate completed the DTLS handshake.
    Connected(Listener, Peer),
    /// The session ended (closed by either side, failed or timed out).
    Disconnected(Listener, Peer),
    /// The Leader accepted the Candidate's petition (session ID).
    PetitionAccepted(u16),
    /// The PSKc connection attempts are used up; the Border Agent refuses
    /// new PSKc sessions until [`BorderAgent::set_max_connection_attempts`].
    AttemptsExhausted,
    /// The ephemeral key state changed (OT ephemeral key callback).
    EphemeralKeyState(EphemeralKeyState),
    /// The ephemeral key was discarded.
    EphemeralKeyStopped(EphemeralKeyStopReason),
}

#[derive(Debug, Clone, Copy)]
struct Forward {
    user: u32,
    listener: Listener,
    ctx: RequestCtx,
    petition: bool,
}

type BaCoap = Endpoint<2, 7, 2, MAX_CONTENT_LEN, 8>;

struct BaSession<B: CryptoBackend, C: P256> {
    dtls: Session<B, C>,
    peer: Peer,
    connected: bool,
    aloc16: Option<u16>,
    keep_alive_deadline: Option<Instant>,
    coap: BaCoap,
}

/// Why a session ends.
#[derive(Debug, Clone, Copy)]
enum End {
    Dtls(CloseReason),
    KeepAlive,
    Local,
}

/// The ephemeral key and its listener's bookkeeping.
struct Ephemeral {
    state: EphemeralKeyState,
    key: Option<EphemeralKey>,
    port: u16,
    deadline: Option<Instant>,
    remaining_attempts: u16,
}

/// The Border Agent (OT `MeshCoP::BorderAgent`).
pub struct BorderAgent<B: CryptoBackend, C: P256> {
    crypto: B,
    curve: C,
    id: [u8; 16],
    pskc: Option<Pskc>,
    sessions: [Option<BaSession<B, C>>; 2],
    guard_until: [Option<Instant>; 2],
    max_attempts: u16,
    remaining_attempts: u16,
    eph: Ephemeral,
    forwards: Vec<Forward, MAX_FORWARDS>,
    next_user: u16,
    events: Deque<BorderAgentEvent, 8>,
}

impl<B: CryptoBackend, C: P256> core::fmt::Debug for BorderAgent<B, C> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("BorderAgent")
            .field("id", &self.id)
            .field("session", &self.sessions[0].as_ref().map(|s| s.peer))
            .field(
                "ephemeral_session",
                &self.sessions[1].as_ref().map(|s| s.peer),
            )
            .field("ephemeral_key_state", &self.eph.state)
            .finish_non_exhaustive()
    }
}

fn new_coap(mid: u16) -> BaCoap {
    let mut coap = Endpoint::new(mid, Default::default());
    for u in RESOURCES {
        let _ = coap.add_resource(u.path(), ResourceId(u.id()));
    }
    coap
}

impl<B, C> BorderAgent<B, C>
where
    B: CryptoBackend + Clone,
    B::Sha256: Clone,
    C: P256 + Clone,
{
    /// A Border Agent with the Border Agent ID `id` (OT generates it
    /// randomly once and stores it). No PSKc yet: PSKc sessions are
    /// refused. The ephemeral key feature is enabled (Thread 1.4, OT
    /// `OPENTHREAD_CONFIG_BORDER_AGENT_EPHEMERAL_KEY_FEATURE_ENABLED_BY_DEFAULT`)
    /// with no key set.
    pub fn new(crypto: B, curve: C, id: [u8; 16]) -> Self {
        Self {
            crypto,
            curve,
            id,
            pskc: None,
            sessions: [None, None],
            guard_until: [None, None],
            max_attempts: 0,
            remaining_attempts: 0,
            eph: Ephemeral {
                state: EphemeralKeyState::Stopped,
                key: None,
                port: 0,
                deadline: None,
                remaining_attempts: 0,
            },
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

    /// Limit the number of PSKc DTLS connection attempts (`0`: unlimited;
    /// OT `SetMaxConnectionAttempts`); resets the remaining count. The
    /// ePSKc listener has its own fixed limit
    /// ([`epskc::MAX_CONNECTION_ATTEMPTS`]).
    pub fn set_max_connection_attempts(&mut self, n: u16) {
        self.max_attempts = n;
        self.remaining_attempts = n;
    }

    /// A Commissioner session (on either listener) is connected.
    pub fn is_connected(&self) -> bool {
        self.sessions.iter().flatten().any(|s| s.connected)
    }

    /// The session of `listener` is connected.
    pub fn is_connected_on(&self, listener: Listener) -> bool {
        self.sessions[listener.idx()]
            .as_ref()
            .is_some_and(|s| s.connected)
    }

    /// The active Commissioner's ALOC16, if its petition was accepted.
    pub fn commissioner_aloc16(&self) -> Option<u16> {
        self.sessions.iter().flatten().find_map(|s| s.aloc16)
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

    // ------------------------------------------------------- ephemeral key

    /// State of the ephemeral key (OT `GetState`).
    pub fn ephemeral_key_state(&self) -> EphemeralKeyState {
        self.eph.state
    }

    /// Is the ePSKc feature enabled? The MeshCoP service's State Bitmap
    /// then carries [`epskc::STATE_BITMAP_EPSKC_SUPPORTED`].
    pub fn ephemeral_key_supported(&self) -> bool {
        self.eph.state != EphemeralKeyState::Disabled
    }

    /// The ePSKc UDP port while the MeshCoP-ePSKc service is advertised
    /// (a key is set).
    pub fn ephemeral_port(&self) -> Option<u16> {
        self.eph.state.is_active().then_some(self.eph.port)
    }

    /// Enable or disable the ePSKc feature (OT `SetEnabled`); disabling
    /// discards a key in use and closes its session.
    pub fn set_ephemeral_key_enabled<I: BorderAgentIo + ?Sized>(
        &mut self,
        now: Instant,
        io: &mut I,
        enabled: bool,
    ) {
        match (enabled, self.eph.state) {
            (true, EphemeralKeyState::Disabled) => {
                self.set_eph_state(io, EphemeralKeyState::Stopped);
            }
            (false, s) if s != EphemeralKeyState::Disabled => {
                self.stop_ephemeral(now, io, EphemeralKeyStopReason::Local);
                self.set_eph_state(io, EphemeralKeyState::Disabled);
            }
            _ => {}
        }
    }

    /// Accept `key` on the ePSKc listener at UDP `port` for `timeout`
    /// (zero: [`epskc::DEFAULT_TIMEOUT`], clamped to
    /// [`epskc::MAX_TIMEOUT`]); returns the effective timeout (OT
    /// `EphemeralKeyManager::Start`).
    ///
    /// The key is single-use: it is discarded when its session ends, when
    /// the timeout expires (closing its session), after
    /// [`epskc::MAX_CONNECTION_ATTEMPTS`] connection attempts, or by
    /// [`stop_ephemeral_key`](Self::stop_ephemeral_key). The caller binds
    /// the UDP socket (a port other than the Border Agent's) and passes
    /// the bound, non-zero `port`; datagrams to it go to
    /// [`handle_ephemeral_udp`](Self::handle_ephemeral_udp). The PSKc
    /// listener is unaffected (both can be used in parallel, as in OT).
    ///
    /// [`Error::InvalidState`] if a key is already in use or the feature is
    /// disabled, [`Error::InvalidArgs`] for port `0`.
    pub fn start_ephemeral_key<I: BorderAgentIo + ?Sized>(
        &mut self,
        now: Instant,
        io: &mut I,
        key: EphemeralKey,
        timeout: Duration,
        port: u16,
    ) -> Result<Duration> {
        if self.eph.state != EphemeralKeyState::Stopped {
            return Err(Error::InvalidState);
        }
        if port == 0 {
            return Err(Error::InvalidArgs);
        }
        let timeout = epskc::effective_timeout(timeout);
        self.eph.key = Some(key);
        self.eph.port = port;
        self.eph.deadline = Some(now.saturating_add(timeout));
        self.eph.remaining_attempts = epskc::MAX_CONNECTION_ATTEMPTS;
        self.guard_until[Listener::Ephemeral.idx()] = None;
        self.set_eph_state(io, EphemeralKeyState::Started);
        Ok(timeout)
    }

    /// Discard the ephemeral key and close its session (OT `Stop`); no
    /// effect without a key.
    pub fn stop_ephemeral_key<I: BorderAgentIo + ?Sized>(&mut self, now: Instant, io: &mut I) {
        self.stop_ephemeral(now, io, EphemeralKeyStopReason::Local);
    }

    fn stop_ephemeral<I: BorderAgentIo + ?Sized>(
        &mut self,
        now: Instant,
        io: &mut I,
        reason: EphemeralKeyStopReason,
    ) {
        if !self.eph.state.is_active() {
            return;
        }
        // State first: ending the session below must not recurse.
        self.set_eph_state(io, EphemeralKeyState::Stopped);
        self.eph.key = None;
        self.eph.deadline = None;
        self.eph.remaining_attempts = 0;
        self.end_session(Listener::Ephemeral, now, io, End::Local);
        self.event(BorderAgentEvent::EphemeralKeyStopped(reason));
    }

    fn set_eph_state<I: BorderAgentIo + ?Sized>(&mut self, io: &mut I, state: EphemeralKeyState) {
        let old = self.eph.state;
        if old == state {
            return;
        }
        self.eph.state = state;
        self.event(BorderAgentEvent::EphemeralKeyState(state));
        if old.is_active() != state.is_active() {
            io.ephemeral_service(state.is_active().then_some(self.eph.port));
        }
    }

    // ------------------------------------------------------------ sessions

    /// A UDP datagram from the external interface to the Border Agent
    /// port (PSKc).
    pub fn handle_udp<R: CryptoRng + ?Sized, I: BorderAgentIo + ?Sized>(
        &mut self,
        now: Instant,
        rng: &mut R,
        io: &mut I,
        view: &BorderAgentView<'_>,
        peer: &Peer,
        datagram: &[u8],
    ) {
        self.handle_listener_udp(Listener::Pskc, now, rng, io, view, peer, datagram);
    }

    /// A UDP datagram from the external interface to the ePSKc port
    /// ([`ephemeral_port`](Self::ephemeral_port)); ignored while no
    /// ephemeral key is set.
    pub fn handle_ephemeral_udp<R: CryptoRng + ?Sized, I: BorderAgentIo + ?Sized>(
        &mut self,
        now: Instant,
        rng: &mut R,
        io: &mut I,
        view: &BorderAgentView<'_>,
        peer: &Peer,
        datagram: &[u8],
    ) {
        if !self.eph.state.is_active() {
            return;
        }
        self.handle_listener_udp(Listener::Ephemeral, now, rng, io, view, peer, datagram);
    }

    #[allow(clippy::too_many_arguments)]
    fn handle_listener_udp<R: CryptoRng + ?Sized, I: BorderAgentIo + ?Sized>(
        &mut self,
        l: Listener,
        now: Instant,
        rng: &mut R,
        io: &mut I,
        view: &BorderAgentView<'_>,
        peer: &Peer,
        datagram: &[u8],
    ) {
        let i = l.idx();
        if self.sessions[i].is_none() && !self.accept_session(l, now, rng, io, peer) {
            return;
        }
        if self.sessions[i].as_ref().is_some_and(|s| s.peer != *peer) {
            // One session per listener at a time (at most one ePSKc
            // session, Thread 1.4.1 section 8.4.9.4.1.4).
            return;
        }
        let mut rest = datagram;
        let mut app = [0u8; MAX_CONTENT_LEN];
        while let Some(s) = self.sessions[i].as_mut() {
            let got = secure::next_app_data(&mut s.dtls, now, rng, &mut rest, &mut app);
            let p = s.peer;
            let _ = secure::flush(&mut s.dtls, |d| io.send_to_commissioner(l, &p, d));
            self.check_session(l, now, io);
            let Some(n) = got else { break };
            self.handle_coap(l, now, io, view, &app[..n]);
        }
        // Decrypted requests may hold the Network Key (`/c/as`, ...).
        zeroize::Zeroize::zeroize(&mut app);
    }

    fn accept_session<R: CryptoRng + ?Sized, I: BorderAgentIo + ?Sized>(
        &mut self,
        l: Listener,
        now: Instant,
        rng: &mut R,
        io: &mut I,
        peer: &Peer,
    ) -> bool {
        if self.guard_until[l.idx()].is_some_and(|g| now < g) {
            return false;
        }
        match l {
            Listener::Pskc => {
                if self.pskc.is_none() {
                    return false;
                }
                if self.max_attempts > 0 {
                    if self.remaining_attempts == 0 {
                        return false;
                    }
                    self.remaining_attempts -= 1;
                }
            }
            Listener::Ephemeral => {
                if self.eph.state != EphemeralKeyState::Started
                    || self.eph.key.is_none()
                    || self.eph.remaining_attempts == 0
                {
                    return false;
                }
                // Every new session counts (OT `SecureSession::Setup`);
                // a successful one ends the key's use anyway.
                self.eph.remaining_attempts -= 1;
            }
        }
        let password: &[u8] = match l {
            Listener::Pskc => self.pskc.as_ref().map_or(&[], |p| &p.0),
            Listener::Ephemeral => self.eph.key.as_ref().map_or(&[], |k| k.as_bytes()),
        };
        let mut id = [0u8; 18];
        id[..16].copy_from_slice(&peer.addr.octets());
        id[16..].copy_from_slice(&peer.port.to_be_bytes());
        let dtls = Session::server(
            self.crypto.clone(),
            self.curve.clone(),
            password,
            Config::default(),
            &id,
            rng,
        );
        let Ok(dtls) = dtls else {
            self.check_ephemeral_attempts(now, io, l);
            return false;
        };
        self.sessions[l.idx()] = Some(BaSession {
            dtls,
            peer: *peer,
            connected: false,
            aloc16: None,
            keep_alive_deadline: None,
            coap: new_coap(rng.next_u32() as u16),
        });
        true
    }

    /// The ePSKc listener closes once its attempts are used up and no
    /// session is left (OT `HandleUpdateTask` auto-close).
    fn check_ephemeral_attempts<I: BorderAgentIo + ?Sized>(
        &mut self,
        now: Instant,
        io: &mut I,
        l: Listener,
    ) {
        if l == Listener::Ephemeral
            && self.eph.state == EphemeralKeyState::Started
            && self.eph.remaining_attempts == 0
            && self.sessions[l.idx()].is_none()
        {
            self.stop_ephemeral(now, io, EphemeralKeyStopReason::MaxAttempts);
        }
    }

    fn check_session<I: BorderAgentIo + ?Sized>(&mut self, l: Listener, now: Instant, io: &mut I) {
        let Some(s) = self.sessions[l.idx()].as_mut() else {
            return;
        };
        match s.dtls.state() {
            DtlsState::Connected if !s.connected => {
                s.connected = true;
                s.keep_alive_deadline = Some(now.saturating_add(KEEP_ALIVE_TIMEOUT));
                let p = s.peer;
                self.event(BorderAgentEvent::Connected(l, p));
                if l == Listener::Ephemeral {
                    self.set_eph_state(io, EphemeralKeyState::Connected);
                }
            }
            DtlsState::Closed(r) => self.end_session(l, now, io, End::Dtls(r)),
            _ => {}
        }
    }

    /// Drop the session of `l`: ALOC removed, forwards forgotten, guard
    /// time; an ePSKc session that was connected discards the key.
    fn end_session<I: BorderAgentIo + ?Sized>(
        &mut self,
        l: Listener,
        now: Instant,
        io: &mut I,
        end: End,
    ) {
        let Some(mut s) = self.sessions[l.idx()].take() else {
            return;
        };
        if !matches!(s.dtls.state(), DtlsState::Closed(_)) {
            s.dtls.close();
            let p = s.peer;
            let _ = secure::flush(&mut s.dtls, |d| io.send_to_commissioner(l, &p, d));
        }
        if s.aloc16.is_some() {
            io.set_commissioner_aloc(None);
        }
        self.forwards.retain(|f| f.listener != l);
        s.coap.clear();
        self.guard_until[l.idx()] = Some(now.saturating_add(GUARD_TIME));
        self.event(BorderAgentEvent::Disconnected(l, s.peer));
        match l {
            Listener::Pskc => {
                if self.max_attempts > 0 && self.remaining_attempts == 0 {
                    self.event(BorderAgentEvent::AttemptsExhausted);
                }
            }
            Listener::Ephemeral if s.connected => {
                // Single use (Thread 1.4.1 sections 8.4.1.2.3, 8.4.9.4.1.5).
                let reason = match end {
                    End::Dtls(CloseReason::Peer) => EphemeralKeyStopReason::PeerDisconnect,
                    End::Dtls(CloseReason::Local) | End::Local => EphemeralKeyStopReason::Local,
                    End::Dtls(_) => EphemeralKeyStopReason::SessionError,
                    End::KeepAlive => EphemeralKeyStopReason::SessionTimeout,
                };
                self.stop_ephemeral(now, io, reason);
            }
            Listener::Ephemeral => self.check_ephemeral_attempts(now, io, l),
        }
    }

    fn handle_coap<I: BorderAgentIo + ?Sized>(
        &mut self,
        l: Listener,
        now: Instant,
        io: &mut I,
        view: &BorderAgentView<'_>,
        data: &[u8],
    ) {
        let Some(s) = self.sessions[l.idx()].as_mut() else {
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
                out: |d: &[u8]| io.send_to_commissioner(l, &p, d),
            };
            match s.coap.handle_datagram(now, &mut tx, &info, data) {
                Rx::Request(r) => r,
                _ => return,
            }
        };
        let active = s.aloc16.is_some();
        let Some(uri) = Uri::from_id(req.resource.0) else {
            return;
        };
        let payload = req.msg.payload();
        let mlp = view.mesh_local_prefix;
        match uri {
            Uri::CommissionerPetition => {
                self.forward_to_leader(
                    l,
                    now,
                    io,
                    &mlp,
                    &req.ctx,
                    Uri::LeaderPetition,
                    payload,
                    true,
                );
            }
            Uri::CommissionerKeepAlive if active => {
                if let Some(s) = self.sessions[l.idx()].as_mut() {
                    s.keep_alive_deadline = Some(now.saturating_add(KEEP_ALIVE_TIMEOUT));
                }
                self.forward_to_leader(
                    l,
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
                // Also for an ePSKc Candidate that did not petition, with
                // the Network Key regardless of the Security Policy O-bit
                // (Thread 1.4.1 section 8.4.9.4.1.4).
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
                self.respond(l, now, io, &req.ctx, code, &buf[..n.unwrap_or(0)]);
                // The answer may hold the Network Key.
                zeroize::Zeroize::zeroize(&mut buf);
            }
            Uri::ProxyTx => {
                // OT `HandleTmfProxyTx`, only for the active Commissioner
                // (the source is its ALOC).
                let Some(aloc16) = self.sessions[l.idx()].as_ref().and_then(|s| s.aloc16) else {
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
        l: Listener,
        now: Instant,
        io: &mut I,
        ctx: &RequestCtx,
        code: Code,
        payload: &[u8],
    ) {
        let Some(s) = self.sessions[l.idx()].as_mut() else {
            return;
        };
        let p = s.peer;
        let mut tx = DtlsTx {
            session: &mut s.dtls,
            out: |d: &[u8]| io.send_to_commissioner(l, &p, d),
        };
        let _ = s
            .coap
            .respond_payload(now, &mut tx, ctx, &SendOpts::default(), code, payload);
    }

    /// OT `ForwardToLeader` (separate response).
    #[allow(clippy::too_many_arguments)]
    fn forward_to_leader<I: BorderAgentIo + ?Sized>(
        &mut self,
        l: Listener,
        now: Instant,
        io: &mut I,
        mlp: &Prefix64,
        ctx: &RequestCtx,
        uri: Uri,
        payload: &[u8],
        petition: bool,
    ) {
        if let Some(s) = self.sessions[l.idx()].as_mut() {
            let p = s.peer;
            let mut tx = DtlsTx {
                session: &mut s.dtls,
                out: |d: &[u8]| io.send_to_commissioner(l, &p, d),
            };
            if ctx.ty == Type::Con {
                let _ = s.coap.ack_empty(&mut tx, ctx);
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
                    listener: l,
                    ctx: sep,
                    petition,
                });
            }
            Err(e) => self.respond(l, now, io, &sep, error_code(e), &[]),
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
        let l = f.listener;
        let (code, payload) = match result {
            Ok(r) => r,
            Err(e) => {
                self.respond(l, now, io, &f.ctx, error_code(e), &[]);
                return;
            }
        };
        if f.petition && code == Code::CHANGED {
            let t = Tlvs(payload);
            if t.state() == Ok(State::Accept)
                && let Ok(sid) = t.commissioner_session_id()
                && let Some(s) = self.sessions[l.idx()].as_mut()
            {
                let aloc = commissioner_aloc16(sid);
                s.aloc16 = Some(aloc);
                io.set_commissioner_aloc(Some(aloc));
                self.event(BorderAgentEvent::PetitionAccepted(sid));
                if l == Listener::Ephemeral {
                    self.set_eph_state(io, EphemeralKeyState::Accepted);
                }
            }
        }
        self.respond(l, now, io, &f.ctx, code, payload);
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
        let l = LISTENERS
            .into_iter()
            .find(|l| {
                self.sessions[l.idx()]
                    .as_ref()
                    .is_some_and(|s| s.aloc16.is_some())
            })
            .ok_or(Error::InvalidState)?;
        let s = self.sessions[l.idx()].as_mut().ok_or(Error::InvalidState)?;
        let p = s.peer;
        let mut tx = DtlsTx {
            session: &mut s.dtls,
            out: |d: &[u8]| io.send_to_commissioner(l, &p, d),
        };
        s.coap.send_request(
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
        self.sessions
            .iter()
            .flatten()
            .flat_map(|s| {
                [
                    s.dtls.next_timeout(),
                    s.keep_alive_deadline,
                    s.coap.next_deadline(),
                ]
            })
            .chain([self.eph.deadline])
            .flatten()
            .min()
    }

    /// Run timers: DTLS / CoAP retransmissions, the keep-alive timeout and
    /// the ephemeral key's timeout.
    pub fn poll<I: BorderAgentIo + ?Sized>(&mut self, now: Instant, io: &mut I) {
        if self.eph.deadline.is_some_and(|d| d <= now) {
            // Closes a session using the key (Thread 1.4.1 section
            // 8.4.9.4.1.5).
            self.stop_ephemeral(now, io, EphemeralKeyStopReason::Timeout);
        }
        for l in LISTENERS {
            let Some(s) = self.sessions[l.idx()].as_mut() else {
                continue;
            };
            if s.keep_alive_deadline.is_some_and(|d| d <= now) {
                self.end_session(l, now, io, End::KeepAlive);
                continue;
            }
            s.dtls.handle_timeout(now);
            let p = s.peer;
            let _ = secure::flush(&mut s.dtls, |d| io.send_to_commissioner(l, &p, d));
            let mut tx = DtlsTx {
                session: &mut s.dtls,
                out: |d: &[u8]| io.send_to_commissioner(l, &p, d),
            };
            while let Some(Event::Timeout { .. }) = s.coap.poll(now, &mut tx) {}
            self.check_session(l, now, io);
        }
    }

    /// Close the Commissioner sessions of both listeners (e.g. the
    /// partition changed, Thread 1.4.1 section 8.4.1.4); a connected ePSKc
    /// session discards its key.
    pub fn disconnect<I: BorderAgentIo + ?Sized>(&mut self, now: Instant, io: &mut I) {
        for l in LISTENERS {
            self.end_session(l, now, io, End::Local);
        }
    }
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
    coap: Endpoint<4, 2, 2, MAX_CONTENT_LEN, 8>,
    proxy: Endpoint<2, 1, 1, MAX_CONTENT_LEN, 6>,
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
        Self::connect_with(crypto, curve, &pskc.0, peer, mlp, now, rng, out)
    }

    /// Like [`connect`](Self::connect), with an ephemeral key (ePSKc) to
    /// the Border Agent's ePSKc port (Thread 1.4.1 section 8.4.9.3): the
    /// key octets are the EC-JPAKE password.
    #[allow(clippy::too_many_arguments)]
    pub fn connect_ephemeral<R: CryptoRng + ?Sized>(
        crypto: B,
        curve: C,
        key: &EphemeralKey,
        peer: Peer,
        mlp: Prefix64,
        now: Instant,
        rng: &mut R,
        out: &mut dyn FnMut(&[u8]) -> Result<()>,
    ) -> Result<Self> {
        Self::connect_with(crypto, curve, key.as_bytes(), peer, mlp, now, rng, out)
    }

    #[allow(clippy::too_many_arguments)]
    fn connect_with<R: CryptoRng + ?Sized>(
        crypto: B,
        curve: C,
        password: &[u8],
        peer: Peer,
        mlp: Prefix64,
        now: Instant,
        rng: &mut R,
        out: &mut dyn FnMut(&[u8]) -> Result<()>,
    ) -> Result<Self> {
        let mut dtls = Session::client(crypto, curve, password, Config::default(), now, rng)?;
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
            .map_or(DtlsState::Closed(rs_thread_dtls::CloseReason::Local), |s| {
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
        let mut rec = [0u8; rs_thread_dtls::coaps::MAX_DATAGRAM_LEN];
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
