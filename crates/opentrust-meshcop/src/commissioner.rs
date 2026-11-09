//! The Commissioner (Thread 1.4.1 sections 8.4.1 / 8.4.2 / 8.4.4, OT
//! `meshcop/commissioner.cpp`).
//!
//! The same core serves an on-mesh Commissioner and an external one that
//! reaches the network through a Border Agent; only the
//! [`CommissionerIo`] differs ([`MeshTransport`] for on-mesh,
//! `border_agent::BorderAgentClient` for external):
//!
//! - **Petition / keep-alive**: `/c/lp` with the Commissioner ID; on
//!   Accept the Commissioner becomes active with the session ID and the
//!   Commissioner ALOC; `/c/la` every 25 s (half of `TIMEOUT_COMM_PET`). A
//!   failed petition is retried after `COMM_PET_RETRY_DELAY` up to
//!   `COMM_PET_RETRY_COUNT` attempts. A rejected or failed keep-alive stops
//!   the Commissioner. [`Commissioner::stop`] can resign with a keep-alive
//!   carrying State Reject.
//! - **Joiner list**: any Joiner, an EUI-64 or a Joiner Discerner, each
//!   with a PSKd and an expiry. Every change recomputes the Steering Data
//!   and sends `/c/cs` with the session ID.
//! - **Joiner sessions**: Relay Receive (`/c/rx`) records start a DTLS
//!   server session (EC-JPAKE with the PSKd of the best matching Joiner
//!   entry for the Joiner IID, OT `FindBestMatchingJoinerEntry`). One
//!   session at a time (as OT), torn down after
//!   [`JOINER_SESSION_TIMEOUT`]. JOIN_FIN (`/c/jf`) is answered with Accept
//!   unless the Provisioning URL differs from ours; the Relay Transmit
//!   carrying that answer includes the Joiner Router KEK TLV. A Joiner
//!   (other than "any") is removed [`REMOVE_JOINER_DELAY`] after it was
//!   finalized.
//! - **Management**: MGMT_COMMISSIONER_GET / SET and generic requests to
//!   the Leader ([`Commissioner::send_mgmt`]).
//!
//! Notifications are queued ([`Commissioner::pop_event`]).
//!
//! # Secrets
//!
//! PSKds live in [`JoinerPskd`] (wiped on drop, never exposed or logged).
//! The KEK is read from the DTLS session only to build the Relay Transmit
//! TLV, which travels under the network key (Thread 1.4.1 section 8.4.4).

use heapless::{Deque, String};
use opentrust_coap::endpoint::{Endpoint, Peer, ResourceId, Rx, RxInfo, SendOpts};
use opentrust_coap::message::{Code, Type};
use opentrust_coap::tmf::{Agent, UdpSink};
use opentrust_coap::uri::Uri;
use opentrust_core::bytes::Writer;
use opentrust_core::crypto::backend::CryptoBackend;
use opentrust_core::crypto::ecjpake::P256;
use opentrust_core::message::Priority;
use opentrust_core::time::{Duration, Instant};
use opentrust_core::types::{ExtAddress, Iid, Kek, Prefix64, Rloc16};
use opentrust_core::{Error, Result};
use opentrust_dtls::{Config, Session, State as DtlsState};
use rand_core::{CryptoRng, Rng};

use crate::pskd::JoinerPskd;
use crate::secure::{self, DtlsTx, MAX_CONTENT_LEN};
use crate::steering::{JoinerDiscerner, SteeringData, compute_joiner_id};
use crate::tlv::{MAX_COMMISSIONER_ID_LEN, MAX_PROVISIONING_URL_LEN, State, Tlvs, WriterExt};

/// `COMM_PET_RETRY_COUNT`.
pub const PETITION_RETRY_COUNT: u8 = 2;
/// `COMM_PET_RETRY_DELAY`.
pub const PETITION_RETRY_DELAY: Duration = Duration::from_secs(1);
/// `TIMEOUT_COMM_PET`; keep-alives are sent at half of it.
pub const KEEP_ALIVE_TIMEOUT: Duration = Duration::from_secs(50);
/// Delay before a finalized Joiner is removed (`kRemoveJoinerDelay`).
pub const REMOVE_JOINER_DELAY: Duration = Duration::from_secs(20);
/// Lifetime of a Joiner session
/// (`OPENTHREAD_CONFIG_COMMISSIONER_JOINER_SESSION_TIMEOUT`).
pub const JOINER_SESSION_TIMEOUT: Duration = Duration::from_secs(30);
/// Default number of Joiner entries
/// (`OPENTHREAD_CONFIG_COMMISSIONER_MAX_JOINER_ENTRIES`).
pub const DEFAULT_MAX_JOINERS: usize = 2;

/// Response tags of the Commissioner's requests (`user` of the CoAP
/// layer); [`is_commissioner_user`] recognizes them.
pub const USER_PETITION: u32 = 0xc0aa_0001;
/// Keep-alive response tag.
pub const USER_KEEP_ALIVE: u32 = 0xc0aa_0002;
/// Commissioner Set (from the Steering Data updates) response tag.
pub const USER_COMMISSIONER_SET: u32 = 0xc0aa_0003;
/// MGMT_COMMISSIONER_GET response tag.
pub const USER_COMMISSIONER_GET: u32 = 0xc0aa_0004;
/// [`Commissioner::send_mgmt`] response tag.
pub const USER_MGMT: u32 = 0xc0aa_0005;

/// Is `user` one of the Commissioner's response tags?
pub const fn is_commissioner_user(user: u32) -> bool {
    user & !0xff == 0xc0aa_0000 && user & 0xff >= 1 && user & 0xff <= 5
}

const RES_JOINER_FINALIZE: ResourceId = ResourceId(Uri::JoinerFinalize.id());

/// Commissioner state (OT `Commissioner::State`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum CommissionerState {
    /// Not petitioning.
    Disabled,
    /// Petition sent.
    Petition,
    /// Accepted by the Leader.
    Active,
}

/// Which Joiners an entry admits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum JoinerKind {
    /// Any Joiner (Steering Data "permit all").
    Any,
    /// The Joiner with this EUI-64.
    Eui64(ExtAddress),
    /// Joiners whose Joiner ID matches the discerner.
    Discerner(JoinerDiscerner),
}

/// A Joiner entry as reported (the PSKd is not exposed).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JoinerInfo {
    /// Which Joiners.
    pub kind: JoinerKind,
    /// When the entry expires.
    pub expires: Instant,
}

/// Notification of the Commissioner (OT state and joiner callbacks).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommissionerEvent {
    /// The state changed.
    State(CommissionerState),
    /// A Joiner session started for this entry (Joiner ID from the IID).
    JoinerStart(JoinerKind, ExtAddress),
    /// The DTLS handshake with the Joiner completed.
    JoinerConnected(ExtAddress),
    /// JOIN_FIN answered (`true`: Accept).
    JoinerFinalize(ExtAddress, bool),
    /// The Joiner session ended (closed, failed or timed out).
    JoinerEnd(ExtAddress),
    /// A Joiner entry was removed (expired or after finalization).
    JoinerRemoved(JoinerKind),
    /// The Leader sent `/c/dc` (the datasets changed).
    DatasetChanged,
}

/// A management answer handed back by [`Commissioner::handle_response`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MgmtResponse<'a> {
    /// Answer to the Commissioner's own `/c/cs` (State).
    CommissionerSet(core::result::Result<State, Error>),
    /// Answer to [`Commissioner::send_commissioner_get`]: the TLVs.
    CommissionerGet(core::result::Result<&'a [u8], Error>),
    /// Answer to [`Commissioner::send_mgmt`]: code and payload.
    Mgmt(core::result::Result<(Code, &'a [u8]), Error>),
}

/// How the Commissioner reaches the Leader and the Joiner Routers.
pub trait CommissionerIo {
    /// Send a confirmable request for `uri` with `payload` (TLVs) to the
    /// Leader (`LeaderPetition`, `LeaderKeepAlive`, `CommissionerSet`,
    /// `CommissionerGet`, dataset requests). The outcome comes back through
    /// [`Commissioner::handle_response`] with `user`.
    fn request(&mut self, now: Instant, uri: Uri, payload: &[u8], user: u32) -> Result<()>;
    /// Send a Relay Transmit (NON `/c/tx`, `payload` = TLVs) toward the
    /// Joiner Router `joiner_router` (RLOC16).
    fn relay_tx(&mut self, now: Instant, joiner_router: u16, payload: &[u8]) -> Result<()>;
    /// Add (`Some`) or remove (`None`) the Commissioner ALOC16 (on-mesh;
    /// an external Commissioner's ALOC lives on the Border Agent).
    fn set_commissioner_aloc(&mut self, _aloc16: Option<u16>) {}
}

struct Entry {
    kind: JoinerKind,
    pskd: JoinerPskd,
    expires: Instant,
}

struct JoinerSession<B: CryptoBackend, C: P256> {
    dtls: Session<B, C>,
    iid: Iid,
    port: u16,
    rloc: u16,
    deadline: Instant,
    connected: bool,
}

impl<B: CryptoBackend, C: P256> JoinerSession<B, C> {
    fn id(&self) -> ExtAddress {
        self.iid.to_ext_address()
    }
}

/// The Commissioner (OT `MeshCoP::Commissioner`) with up to `J` Joiner
/// entries.
pub struct Commissioner<B: CryptoBackend, C: P256, const J: usize = DEFAULT_MAX_JOINERS> {
    crypto: B,
    curve: C,
    state: CommissionerState,
    id: String<MAX_COMMISSIONER_ID_LEN>,
    provisioning_url: String<MAX_PROVISIONING_URL_LEN>,
    session_id: u16,
    attempts: u8,
    timer: Option<Instant>,
    joiners: [Option<Entry>; J],
    session: Option<JoinerSession<B, C>>,
    coap: Endpoint<1, 1, 2, MAX_CONTENT_LEN>,
    events: Deque<CommissionerEvent, 8>,
}

impl<B: CryptoBackend, C: P256, const J: usize> core::fmt::Debug for Commissioner<B, C, J> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Commissioner")
            .field("state", &self.state)
            .field("session_id", &self.session_id)
            .finish_non_exhaustive()
    }
}

impl<B, C, const J: usize> Commissioner<B, C, J>
where
    B: CryptoBackend + Clone,
    B::Sha256: Clone,
    C: P256 + Clone,
{
    /// A disabled Commissioner with ID "OpenTrust Commissioner".
    pub fn new(crypto: B, curve: C) -> Self {
        let mut id = String::new();
        let _ = id.push_str("OpenTrust Commissioner");
        let mut coap = Endpoint::new(0, Default::default());
        let _ = coap.add_resource(Uri::JoinerFinalize.path(), RES_JOINER_FINALIZE);
        Self {
            crypto,
            curve,
            state: CommissionerState::Disabled,
            id,
            provisioning_url: String::new(),
            session_id: 0,
            attempts: 0,
            timer: None,
            joiners: core::array::from_fn(|_| None),
            session: None,
            coap,
            events: Deque::new(),
        }
    }

    /// Current state.
    pub fn state(&self) -> CommissionerState {
        self.state
    }

    /// The Commissioner Session ID (valid while active).
    pub fn session_id(&self) -> u16 {
        self.session_id
    }

    /// The Commissioner ID.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Set the Commissioner ID (at most 64 bytes; only while disabled).
    pub fn set_id(&mut self, id: &str) -> Result<()> {
        if self.state != CommissionerState::Disabled {
            return Err(Error::InvalidState);
        }
        let mut s = String::new();
        s.push_str(id).map_err(|_| Error::InvalidArgs)?;
        self.id = s;
        Ok(())
    }

    /// Set the Provisioning URL that Joiners must present (if they send
    /// one); at most 64 bytes.
    pub fn set_provisioning_url(&mut self, url: &str) -> Result<()> {
        let mut s = String::new();
        s.push_str(url).map_err(|_| Error::InvalidArgs)?;
        self.provisioning_url = s;
        Ok(())
    }

    /// The next notification.
    pub fn pop_event(&mut self) -> Option<CommissionerEvent> {
        self.events.pop_front()
    }

    fn event(&mut self, e: CommissionerEvent) {
        if self.events.is_full() {
            self.events.pop_front();
        }
        let _ = self.events.push_back(e);
    }

    fn set_state(&mut self, s: CommissionerState) {
        if self.state != s {
            self.state = s;
            self.event(CommissionerEvent::State(s));
        }
    }

    /// Petition the Leader (OT `Commissioner::Start`). [`Error::Already`]
    /// unless disabled. The device must be attached.
    pub fn start<I: CommissionerIo + ?Sized, R: Rng + ?Sized>(
        &mut self,
        now: Instant,
        rng: &mut R,
        io: &mut I,
    ) -> Result<()> {
        if self.state != CommissionerState::Disabled {
            return Err(Error::Already);
        }
        self.coap = Endpoint::new(rng.next_u32() as u16, Default::default());
        self.coap
            .add_resource(Uri::JoinerFinalize.path(), RES_JOINER_FINALIZE)?;
        self.attempts = 0;
        self.send_petition(now, io)?;
        self.set_state(CommissionerState::Petition);
        Ok(())
    }

    /// Stop (OT `Commissioner::Stop`): end the Joiner session, clear the
    /// Joiners (sending the empty Steering Data), drop the ALOC and, with
    /// `resign`, send a keep-alive with State Reject.
    pub fn stop<I: CommissionerIo + ?Sized>(&mut self, now: Instant, io: &mut I, resign: bool) {
        if self.state == CommissionerState::Disabled {
            return;
        }
        self.end_session(now, io);
        let was_active = self.state == CommissionerState::Active;
        if was_active {
            io.set_commissioner_aloc(None);
            self.joiners = core::array::from_fn(|_| None);
            let _ = self.send_commissioner_set(now, io);
        }
        self.attempts = 0;
        self.timer = None;
        self.set_state(CommissionerState::Disabled);
        if was_active && resign {
            let _ = self.send_keep_alive(now, io, self.session_id);
        }
    }

    fn send_petition<I: CommissionerIo + ?Sized>(
        &mut self,
        now: Instant,
        io: &mut I,
    ) -> Result<()> {
        self.attempts = self.attempts.saturating_add(1);
        let mut b = [0u8; 70];
        let mut w = Writer::new(&mut b);
        w.commissioner_id(&self.id)?;
        io.request(now, Uri::LeaderPetition, w.written(), USER_PETITION)
    }

    fn send_keep_alive<I: CommissionerIo + ?Sized>(
        &mut self,
        now: Instant,
        io: &mut I,
        session_id: u16,
    ) -> Result<()> {
        let mut b = [0u8; 8];
        let mut w = Writer::new(&mut b);
        w.state(if self.state == CommissionerState::Active {
            State::Accept
        } else {
            State::Reject
        })?;
        w.commissioner_session_id(session_id)?;
        io.request(now, Uri::LeaderKeepAlive, w.written(), USER_KEEP_ALIVE)
    }

    /// The outcome of a request tagged with one of the `USER_*` values:
    /// `Ok((code, payload))` for a response, `Err` for a failure or
    /// timeout. Management answers are returned.
    pub fn handle_response<'a, I: CommissionerIo + ?Sized>(
        &mut self,
        now: Instant,
        io: &mut I,
        user: u32,
        result: core::result::Result<(Code, &'a [u8]), Error>,
    ) -> Option<MgmtResponse<'a>> {
        match user {
            USER_PETITION => {
                self.petition_response(now, io, result);
                None
            }
            USER_KEEP_ALIVE => {
                if self.state != CommissionerState::Active {
                    return None;
                }
                match result {
                    Ok((Code::CHANGED, p)) if Tlvs(p).state() == Ok(State::Accept) => {
                        self.timer = Some(now.saturating_add(half(KEEP_ALIVE_TIMEOUT)));
                    }
                    Ok((Code::CHANGED, p)) if Tlvs(p).state().is_err() => {}
                    _ => self.stop(now, io, false),
                }
                None
            }
            USER_COMMISSIONER_SET => Some(MgmtResponse::CommissionerSet(result.and_then(
                |(code, p)| {
                    if code != Code::CHANGED {
                        return Err(Error::Parse);
                    }
                    Tlvs(p).state()
                },
            ))),
            USER_COMMISSIONER_GET => Some(MgmtResponse::CommissionerGet(result.and_then(
                |(code, p)| {
                    if code == Code::CHANGED {
                        Ok(p)
                    } else {
                        Err(Error::Parse)
                    }
                },
            ))),
            USER_MGMT => Some(MgmtResponse::Mgmt(result)),
            _ => None,
        }
    }

    /// OT `HandleLeaderPetitionResponse`.
    fn petition_response<I: CommissionerIo + ?Sized>(
        &mut self,
        now: Instant,
        io: &mut I,
        result: core::result::Result<(Code, &[u8]), Error>,
    ) {
        if self.state == CommissionerState::Active {
            return;
        }
        let p = match result {
            Ok((Code::CHANGED, p)) => p,
            _ => {
                if self.state == CommissionerState::Petition {
                    if self.attempts >= PETITION_RETRY_COUNT {
                        self.stop(now, io, false);
                    } else {
                        self.timer = Some(now.saturating_add(PETITION_RETRY_DELAY));
                    }
                }
                return;
            }
        };
        let t = Tlvs(p);
        match t.state() {
            Ok(State::Accept) => {}
            Ok(_) => {
                self.stop(now, io, false);
                return;
            }
            Err(_) => return,
        }
        let Ok(session_id) = t.commissioner_session_id() else {
            return;
        };
        self.session_id = session_id;
        if self.state == CommissionerState::Disabled {
            // Stopped meanwhile: give the session back right away.
            let _ = self.send_keep_alive(now, io, session_id);
            return;
        }
        io.set_commissioner_aloc(Some(commissioner_aloc16(session_id)));
        self.set_state(CommissionerState::Active);
        self.attempts = 0;
        self.timer = Some(now.saturating_add(half(KEEP_ALIVE_TIMEOUT)));
    }

    /// When [`poll`](Self::poll) must be called next.
    pub fn next_deadline(&self) -> Option<Instant> {
        let expiry = self.joiners.iter().flatten().map(|e| e.expires).min();
        let session = self.session.as_ref().and_then(|s| {
            [Some(s.deadline), s.dtls.next_timeout()]
                .into_iter()
                .flatten()
                .min()
        });
        [self.timer, expiry, session, self.coap.next_deadline()]
            .into_iter()
            .flatten()
            .min()
    }

    /// Run timers: petition retry, keep-alive, Joiner expiry, Joiner
    /// session timeout and DTLS / CoAP retransmissions.
    pub fn poll<I: CommissionerIo + ?Sized>(&mut self, now: Instant, io: &mut I) {
        if self.timer.is_some_and(|t| t <= now) {
            self.timer = None;
            match self.state {
                CommissionerState::Petition => {
                    let _ = self.send_petition(now, io);
                }
                CommissionerState::Active => {
                    let _ = self.send_keep_alive(now, io, self.session_id);
                }
                CommissionerState::Disabled => {}
            }
        }
        let mut removed = false;
        for i in 0..J {
            if self.joiners[i].as_ref().is_some_and(|e| e.expires <= now)
                && let Some(e) = self.joiners[i].take()
            {
                self.event(CommissionerEvent::JoinerRemoved(e.kind));
                removed = true;
            }
        }
        if removed {
            let _ = self.send_commissioner_set(now, io);
        }
        if self.session.as_ref().is_some_and(|s| s.deadline <= now) {
            // OT `HandleJoinerSessionTimer`: disconnect.
            self.end_session(now, io);
        }
        if let Some(s) = self.session.as_mut() {
            s.dtls.handle_timeout(now);
            let (iid, port, rloc) = (s.iid, s.port, s.rloc);
            let _ = secure::flush(&mut s.dtls, |d| relay(io, now, &iid, port, rloc, None, d));
            let mut tx = DtlsTx {
                session: &mut s.dtls,
                out: |d: &[u8]| relay(io, now, &iid, port, rloc, None, d),
            };
            while self.coap.poll(now, &mut tx).is_some() {}
            self.check_session();
        }
    }

    // ------------------------------------------------------------ joiners

    /// Add (or replace) a Joiner entry (OT `AddJoiner`): only while
    /// active; `pskd` is validated; the entry expires after `timeout`.
    pub fn add_joiner<I: CommissionerIo + ?Sized>(
        &mut self,
        now: Instant,
        io: &mut I,
        kind: JoinerKind,
        pskd: &str,
        timeout: Duration,
    ) -> Result<()> {
        if self.state != CommissionerState::Active {
            return Err(Error::InvalidState);
        }
        if let JoinerKind::Discerner(d) = kind
            && !d.is_valid()
        {
            return Err(Error::InvalidArgs);
        }
        let pskd = JoinerPskd::new(pskd)?;
        let slot = self
            .find(&kind)
            .or_else(|| self.joiners.iter().position(Option::is_none))
            .ok_or(Error::NoBufs)?;
        self.joiners[slot] = Some(Entry {
            kind,
            pskd,
            expires: now.saturating_add(timeout),
        });
        let _ = self.send_commissioner_set(now, io);
        Ok(())
    }

    /// Remove a Joiner entry, after `delay` if non-zero (OT
    /// `RemoveJoiner`). [`Error::NotFound`] if there is none.
    pub fn remove_joiner<I: CommissionerIo + ?Sized>(
        &mut self,
        now: Instant,
        io: &mut I,
        kind: &JoinerKind,
        delay: Duration,
    ) -> Result<()> {
        if self.state != CommissionerState::Active {
            return Err(Error::InvalidState);
        }
        let i = self.find(kind).ok_or(Error::NotFound)?;
        self.remove_at(now, io, i, delay);
        Ok(())
    }

    fn remove_at<I: CommissionerIo + ?Sized>(
        &mut self,
        now: Instant,
        io: &mut I,
        i: usize,
        delay: Duration,
    ) {
        if delay.is_zero() {
            if let Some(e) = self.joiners[i].take() {
                self.event(CommissionerEvent::JoinerRemoved(e.kind));
                let _ = self.send_commissioner_set(now, io);
            }
        } else if let Some(e) = self.joiners[i].as_mut() {
            e.expires = e.expires.min(now.saturating_add(delay));
        }
    }

    fn find(&self, kind: &JoinerKind) -> Option<usize> {
        self.joiners
            .iter()
            .position(|e| e.as_ref().is_some_and(|e| e.kind == *kind))
    }

    /// The Joiner entries.
    pub fn joiners(&self) -> impl Iterator<Item = JoinerInfo> + '_ {
        self.joiners.iter().flatten().map(|e| JoinerInfo {
            kind: e.kind,
            expires: e.expires,
        })
    }

    /// OT `FindBestMatchingJoinerEntry`: the EUI-64 entry whose Joiner ID
    /// matches, else the longest matching discerner, else "any".
    fn best_match(&self, joiner_id: &ExtAddress) -> Option<usize> {
        let mut best: Option<usize> = None;
        for (i, e) in self.joiners.iter().enumerate() {
            let Some(e) = e else { continue };
            match e.kind {
                JoinerKind::Eui64(eui) if compute_joiner_id(&self.crypto, &eui) == *joiner_id => {
                    return Some(i);
                }
                JoinerKind::Discerner(d) if d.matches(joiner_id) => {
                    let better = match best.and_then(|b| self.joiners[b].as_ref()) {
                        None => true,
                        Some(Entry {
                            kind: JoinerKind::Discerner(bd),
                            ..
                        }) => bd.length < d.length,
                        Some(_) => true,
                    };
                    if better {
                        best = Some(i);
                    }
                }
                JoinerKind::Any if best.is_none() => best = Some(i),
                _ => {}
            }
        }
        best
    }

    /// The Steering Data of the Joiner entries (OT `ComputeBloomFilter`).
    pub fn steering_data(&self) -> SteeringData {
        let mut s = SteeringData::new(SteeringData::MAX_LENGTH);
        for e in self.joiners.iter().flatten() {
            match e.kind {
                JoinerKind::Any => {
                    s.set_permit_all();
                    break;
                }
                JoinerKind::Eui64(eui) => {
                    let _ = s.add_joiner_id(&compute_joiner_id(&self.crypto, &eui));
                }
                JoinerKind::Discerner(d) => {
                    let _ = s.add_discerner(&d);
                }
            }
        }
        s
    }

    /// OT `SendCommissionerSet`: Session ID and Steering Data to the
    /// Leader (active only).
    fn send_commissioner_set<I: CommissionerIo + ?Sized>(
        &mut self,
        now: Instant,
        io: &mut I,
    ) -> Result<()> {
        if self.state != CommissionerState::Active {
            return Err(Error::InvalidState);
        }
        let mut b = [0u8; 32];
        let mut w = Writer::new(&mut b);
        w.commissioner_session_id(self.session_id)?;
        w.steering_data(&self.steering_data())?;
        io.request(
            now,
            Uri::CommissionerSet,
            w.written(),
            USER_COMMISSIONER_SET,
        )
    }

    /// MGMT_COMMISSIONER_GET (OT `SendMgmtCommissionerGetRequest`) for the
    /// TLV `types` (empty: all); the answer is
    /// [`MgmtResponse::CommissionerGet`].
    pub fn send_commissioner_get<I: CommissionerIo + ?Sized>(
        &mut self,
        now: Instant,
        io: &mut I,
        types: &[u8],
    ) -> Result<()> {
        let mut b = [0u8; 64];
        let mut w = Writer::new(&mut b);
        if !types.is_empty() {
            w.get_list(types)?;
        }
        io.request(
            now,
            Uri::CommissionerGet,
            w.written(),
            USER_COMMISSIONER_GET,
        )
    }

    /// MGMT_COMMISSIONER_SET with `tlvs` (OT
    /// `SendMgmtCommissionerSetRequest`); the Session ID is added. The
    /// answer is [`MgmtResponse::Mgmt`].
    pub fn send_commissioner_set_tlvs<I: CommissionerIo + ?Sized>(
        &mut self,
        now: Instant,
        io: &mut I,
        tlvs: &[u8],
    ) -> Result<()> {
        if self.state != CommissionerState::Active {
            return Err(Error::InvalidState);
        }
        let mut b = [0u8; 255];
        let mut w = Writer::new(&mut b);
        w.commissioner_session_id(self.session_id)?;
        w.write_slice(tlvs)?;
        io.request(now, Uri::CommissionerSet, w.written(), USER_MGMT)
    }

    /// Any other management request to the Leader (MGMT_ACTIVE_GET / SET,
    /// MGMT_PENDING_GET / SET, ...); the answer is [`MgmtResponse::Mgmt`].
    /// The caller includes the Commissioner Session ID where required.
    pub fn send_mgmt<I: CommissionerIo + ?Sized>(
        &mut self,
        now: Instant,
        io: &mut I,
        uri: Uri,
        payload: &[u8],
    ) -> Result<()> {
        io.request(now, uri, payload, USER_MGMT)
    }

    /// `/c/dc` from the Leader (OT `HandleTmf<kUriDatasetChanged>`):
    /// acknowledged while active. Returns whether to answer with an empty
    /// 2.04 (the caller answers through its TMF responder).
    pub fn handle_dataset_changed(&mut self, confirmable_post: bool) -> bool {
        if self.state != CommissionerState::Active || !confirmable_post {
            return false;
        }
        self.event(CommissionerEvent::DatasetChanged);
        true
    }

    // --------------------------------------------------- joiner sessions

    /// `/c/rx` Relay Receive (OT `HandleTmf<kUriRelayRx>`): `payload` is
    /// the TLVs of a NON request (`confirmable` ones are dropped).
    pub fn handle_relay_rx<R: CryptoRng + ?Sized, I: CommissionerIo + ?Sized>(
        &mut self,
        now: Instant,
        rng: &mut R,
        io: &mut I,
        confirmable: bool,
        payload: &[u8],
    ) -> Result<()> {
        if self.state != CommissionerState::Active {
            return Err(Error::InvalidState);
        }
        if confirmable {
            return Err(Error::Drop);
        }
        let t = Tlvs(payload);
        let port = t.joiner_udp_port()?;
        let iid = t.joiner_iid()?;
        let rloc = t.joiner_router_locator()?;
        let records = t.joiner_dtls_encapsulation()?;
        match self.session.as_ref() {
            Some(s) if s.iid != iid => return Err(Error::Busy),
            Some(_) => {}
            None => {
                let joiner_id = iid.to_ext_address();
                let i = self.best_match(&joiner_id).ok_or(Error::NotFound)?;
                let Some(e) = self.joiners[i].as_ref() else {
                    return Err(Error::NotFound);
                };
                let kind = e.kind;
                let mut client_id = [0u8; 10];
                client_id[..8].copy_from_slice(&iid.0);
                client_id[8..].copy_from_slice(&port.to_be_bytes());
                let dtls = Session::server(
                    self.crypto.clone(),
                    self.curve.clone(),
                    e.pskd.as_bytes(),
                    Config::default(),
                    &client_id,
                    rng,
                )?;
                self.coap.clear();
                self.session = Some(JoinerSession {
                    dtls,
                    iid,
                    port,
                    rloc,
                    deadline: now.saturating_add(JOINER_SESSION_TIMEOUT),
                    connected: false,
                });
                self.event(CommissionerEvent::JoinerStart(kind, joiner_id));
            }
        }
        if let Some(s) = self.session.as_mut() {
            s.port = port;
            s.rloc = rloc;
        }
        let mut rest = records;
        let mut app = [0u8; MAX_CONTENT_LEN];
        while let Some(s) = self.session.as_mut() {
            let got = secure::next_app_data(&mut s.dtls, now, rng, &mut rest, &mut app);
            let (iid, port, rloc) = (s.iid, s.port, s.rloc);
            let _ = secure::flush(&mut s.dtls, |d| relay(io, now, &iid, port, rloc, None, d));
            self.check_session();
            let Some(n) = got else { break };
            self.handle_coap(now, io, &app[..n]);
        }
        if self
            .session
            .as_ref()
            .is_some_and(|s| matches!(s.dtls.state(), DtlsState::Closed(_)))
        {
            self.end_session(now, io);
        }
        Ok(())
    }

    fn check_session(&mut self) {
        let Some(s) = self.session.as_mut() else {
            return;
        };
        if !s.connected && s.dtls.is_connected() {
            s.connected = true;
            let id = s.id();
            self.event(CommissionerEvent::JoinerConnected(id));
        }
    }

    fn handle_coap<I: CommissionerIo + ?Sized>(&mut self, now: Instant, io: &mut I, data: &[u8]) {
        let Some(s) = self.session.as_mut() else {
            return;
        };
        let (iid, port, rloc) = (s.iid, s.port, s.rloc);
        let joiner_id = s.id();
        let peer = Peer::new(core::net::Ipv6Addr::UNSPECIFIED, port);
        let info = RxInfo {
            peer,
            dst: core::net::Ipv6Addr::UNSPECIFIED,
        };
        let req = {
            let mut tx = DtlsTx {
                session: &mut s.dtls,
                out: |d: &[u8]| relay(io, now, &iid, port, rloc, None, d),
            };
            match self.coap.handle_datagram(now, &mut tx, &info, data) {
                Rx::Request(req) if req.resource == RES_JOINER_FINALIZE => req,
                _ => return,
            }
        };
        // OT `HandleTmf<kUriJoinerFinalize>`.
        let state = match Tlvs(req.msg.payload()).provisioning_url() {
            Ok(url) if url != self.provisioning_url.as_str() => State::Reject,
            Ok(_) | Err(Error::NotFound) => State::Accept,
            Err(_) => return,
        };
        if req.msg.ty() != Type::Con || req.msg.code() != Code::POST {
            return;
        }
        let mut p = [0u8; 4];
        let mut w = Writer::new(&mut p);
        if w.state(state).is_err() {
            return;
        }
        let Some(s) = self.session.as_mut() else {
            return;
        };
        // The record carrying an accepting JOIN_FIN.rsp goes out with the
        // KEK (OT `kSubTypeJoinerFinalizeResponse`); a rejected Joiner gets
        // no KEK, so no Joiner Router sends it the Joiner Entrust.
        let kek = if state == State::Accept {
            s.dtls.kek().cloned()
        } else {
            None
        };
        let mut tx = DtlsTx {
            session: &mut s.dtls,
            out: |d: &[u8]| relay(io, now, &iid, port, rloc, kek.as_ref(), d),
        };
        if self
            .coap
            .respond_payload(
                now,
                &mut tx,
                &req.ctx,
                &SendOpts::default(),
                Code::CHANGED,
                w.written(),
            )
            .is_err()
        {
            return;
        }
        self.event(CommissionerEvent::JoinerFinalize(
            joiner_id,
            state == State::Accept,
        ));
        if let Some(i) = self.best_match(&joiner_id)
            && self.joiners[i]
                .as_ref()
                .is_some_and(|e| e.kind != JoinerKind::Any)
        {
            self.remove_at(now, io, i, REMOVE_JOINER_DELAY);
        }
    }

    /// Close the Joiner session (close_notify relayed) and report it.
    fn end_session<I: CommissionerIo + ?Sized>(&mut self, now: Instant, io: &mut I) {
        let Some(mut s) = self.session.take() else {
            return;
        };
        s.dtls.close();
        let (iid, port, rloc) = (s.iid, s.port, s.rloc);
        let _ = secure::flush(&mut s.dtls, |d| relay(io, now, &iid, port, rloc, None, d));
        self.coap.clear();
        self.event(CommissionerEvent::JoinerEnd(s.id()));
    }
}

const fn half(d: Duration) -> Duration {
    Duration::from_millis(d.as_millis() / 2)
}

/// The Commissioner ALOC16 of a session (`0xfc30 + session_id % 8`).
pub fn commissioner_aloc16(session_id: u16) -> u16 {
    opentrust_mesh::netdata::aloc::commissioner_aloc16(session_id)
}

/// OT `SendRelayTransmit`: wrap a DTLS record into `/c/tx` TLVs.
fn relay<I: CommissionerIo + ?Sized>(
    io: &mut I,
    now: Instant,
    iid: &Iid,
    port: u16,
    rloc: u16,
    kek: Option<&Kek>,
    record: &[u8],
) -> Result<()> {
    let mut b = [0u8; MAX_CONTENT_LEN + 64];
    let mut w = Writer::new(&mut b);
    w.joiner_udp_port(port)?;
    w.joiner_iid(iid)?;
    w.joiner_router_locator(rloc)?;
    if let Some(k) = kek {
        w.joiner_router_kek(k)?;
    }
    w.joiner_dtls_encapsulation(record)?;
    let n = w.written().len();
    let r = io.relay_tx(now, rloc, &b[..n]);
    // The buffer held the KEK.
    zeroize::Zeroize::zeroize(&mut b);
    r
}

/// [`CommissionerIo`] of an on-mesh Commissioner: TMF through the agent,
/// requests to the Leader ALOC and Relay Transmit to the Joiner Router's
/// RLOC, both from our RLOC.
#[derive(Debug)]
pub struct MeshTransport<
    'a,
    R: ?Sized,
    S: ?Sized,
    const REQ: usize,
    const RES: usize,
    const CACHE: usize,
    const MSG: usize,
> {
    /// The TMF agent.
    pub agent: &'a mut Agent<REQ, RES, CACHE, MSG>,
    /// Random numbers (CoAP message IDs, tokens).
    pub rng: &'a mut R,
    /// The UDP output.
    pub sink: &'a mut S,
    /// Mesh-local prefix.
    pub mlp: Prefix64,
    /// Our RLOC16.
    pub rloc16: Rloc16,
    /// The Commissioner ALOC16 to configure on the interface.
    pub aloc16: &'a mut Option<u16>,
}

impl<R, S, const REQ: usize, const RES: usize, const CACHE: usize, const MSG: usize> CommissionerIo
    for MeshTransport<'_, R, S, REQ, RES, CACHE, MSG>
where
    R: Rng + ?Sized,
    S: UdpSink + ?Sized,
{
    fn request(&mut self, now: Instant, uri: Uri, payload: &[u8], user: u32) -> Result<()> {
        self.agent.post(
            now,
            self.rng,
            self.sink,
            self.mlp.aloc(LEADER_ALOC16)?,
            Some(self.mlp.rloc(self.rloc16)),
            Priority::Net,
            uri,
            payload,
            Some(user),
        )
    }

    fn relay_tx(&mut self, now: Instant, joiner_router: u16, payload: &[u8]) -> Result<()> {
        self.agent.send_request(
            now,
            self.rng,
            self.sink,
            self.mlp.rloc(Rloc16(joiner_router)),
            &SendOpts {
                src: Some(self.mlp.rloc(self.rloc16)),
                priority: Priority::Net,
                multicast_loop: false,
            },
            Type::Non,
            Code::POST,
            None,
            |mut b| {
                b.uri_path(Uri::RelayTx.path())?;
                b.finish_with_payload(payload)
            },
        )
    }

    fn set_commissioner_aloc(&mut self, aloc16: Option<u16>) {
        *self.aloc16 = aloc16;
    }
}

/// The Leader ALOC16.
pub const LEADER_ALOC16: u16 = 0xfc00;
