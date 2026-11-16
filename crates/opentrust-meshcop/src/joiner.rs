//! The Joiner (Thread 1.4.1 sections 8.4.3 / 8.4.4, OT
//! `meshcop/joiner.cpp`).
//!
//! A device without network credentials joins in four steps:
//!
//! 1. **Discovery**: MLE Discovery Requests with the Joiner flag on every
//!    channel ([`DiscoverScanner`]), filtered by the Steering Data bloom
//!    filter for our Joiner ID (or Joiner Discerner). Responding Joiner
//!    Routers are ranked by OT `Joiner::CalculatePriority` (Steering Data
//!    that names us beats "allow any", then RSSI); the best
//!    [`MAX_CANDIDATES`] are kept.
//! 2. **DTLS**: the MAC extended address becomes the Joiner ID, and a DTLS
//!    client (`TLS_ECJPAKE_WITH_AES_128_CCM_8`, password = PSKd) connects
//!    from [`JOINER_UDP_PORT`] to the Joiner Router's link-local address and
//!    Joiner UDP port, without link-layer security. A failed handshake
//!    moves on to the next candidate.
//! 3. **JOIN_FIN**: over the session, `/c/jf` with State, Vendor Name /
//!    Model / SW Version / Stack Version, optional Vendor Data and
//!    Provisioning URL. An Accept answer moves to the Entrust state, the
//!    session is closed; the KEK of the session is kept for key ID mode 0.
//! 4. **JOIN_ENT**: the Joiner Router sends `/c/je` secured with the KEK
//!    (key ID mode 0); the Network Key (with the channel and PAN ID of the
//!    Joiner Router) is saved as the local Active Dataset, the empty
//!    response goes back under the KEK, and after 100 ms the MAC address is
//!    randomized again and the Joiner reports success. The caller then
//!    starts MLE (attach), which fetches the full Active Dataset.
//!
//! # Wiring
//!
//! Sans-IO: everything the Joiner needs from the stack is [`JoinerIo`].
//! Call [`Joiner::poll`] at [`Joiner::next_deadline`], feed Discovery
//! Responses to [`Joiner::handle_discovery_response`], UDP datagrams to
//! [`JOINER_UDP_PORT`] to [`Joiner::handle_udp`], and TMF datagrams that
//! the MAC accepted under key ID mode 0 to [`Joiner::handle_kek_datagram`]
//! (never to the regular TMF agent).
//!
//! # Secrets
//!
//! The PSKd ([`JoinerPskd`]) and the KEK are wiped when the Joiner finishes
//! or is dropped (the DTLS session wipes its own secrets); they are never
//! logged. The Network Key is only handed to [`JoinerIo::save_dataset`].

use core::net::Ipv6Addr;

use heapless::Vec;
use opentrust_coap::endpoint::{Endpoint, Peer, ResourceId, Rx, RxInfo, SendOpts, Transport};
use opentrust_coap::message::{Code, Type};
use opentrust_coap::tmf::UDP_PORT as TMF_PORT;
use opentrust_coap::uri::Uri;
use opentrust_core::bytes::Writer;
use opentrust_core::crypto::backend::CryptoBackend;
use opentrust_core::crypto::ecjpake::P256;
use opentrust_core::time::{Duration, Instant};
use opentrust_core::types::{ExtAddress, Kek, ipv6};
use opentrust_core::{Error, Result};
use opentrust_dtls::{Config, Session, State as DtlsState};
use opentrust_mle::env::DiscoveryResponseInfo;
use rand_core::CryptoRng;

use crate::dataset::Dataset;
use crate::discovery::{DiscoverScanner, ScanResult, ScanStep, build_request_tlv};
use crate::pskd::JoinerPskd;
use crate::secure::{self, DtlsTx, LinkSecurity, MAX_CONTENT_LEN};
use crate::steering::{HashBitIndexes, JoinerDiscerner, compute_joiner_id};
use crate::tlv::{
    MAX_PROVISIONING_URL_LEN, MAX_VENDOR_DATA_LEN, MAX_VENDOR_MODEL_LEN, MAX_VENDOR_NAME_LEN,
    MAX_VENDOR_SW_VERSION_LEN, PAGE0_CHANNELS, State, Tlvs, VENDOR_STACK_VERSION_LEN, WriterExt,
};

/// The Joiner's own UDP port (`OPENTHREAD_CONFIG_JOINER_UDP_PORT`).
pub const JOINER_UDP_PORT: u16 = 1000;
/// Joiner Router candidates kept from the discovery
/// (`OPENTHREAD_CONFIG_JOINER_MAX_CANDIDATES`).
pub const MAX_CANDIDATES: usize = 2;
/// Wait for the JOIN_FIN response and for the Joiner Entrust
/// (`Joiner::kResponseTimeout`).
pub const RESPONSE_TIMEOUT: Duration = Duration::from_millis(4000);
/// Delay between sending the Joiner Entrust response and randomizing the
/// MAC address (`Joiner::kConfigExtAddressDelay`).
pub const CONFIG_EXT_ADDRESS_DELAY: Duration = Duration::from_millis(100);

/// CoAP message size of the Joiner's endpoints (JOIN_FIN.req is at most
/// about 240 bytes).
const COAP_MSG: usize = 320;
const USER_JOIN_FIN: u32 = 0x4a46_0001;
const RES_JOINER_ENTRUST: ResourceId = ResourceId(Uri::JoinerEntrust.id());

/// Joiner state (OT `Joiner::State`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum JoinerState {
    /// Not joining.
    Idle,
    /// Discovering Joiner Routers.
    Discover,
    /// DTLS handshake with a Joiner Router in progress.
    Connect,
    /// Session established, JOIN_FIN.req sent.
    Connected,
    /// JOIN_FIN accepted, waiting for the Joiner Entrust.
    Entrust,
    /// Joiner Entrust received and answered.
    Joined,
}

/// Notification of the Joiner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum JoinerEvent {
    /// The state changed.
    State(JoinerState),
    /// Joining ended (OT joiner callback): `Ok` after the Joiner Entrust,
    /// else [`Error::NotFound`] (no Joiner Router), [`Error::Security`]
    /// (DTLS handshake failed with every candidate, or JOIN_FIN rejected),
    /// [`Error::ResponseTimeout`] or [`Error::Abort`] ([`Joiner::stop`]).
    Done(core::result::Result<(), Error>),
}

/// What the Joiner needs from the stack.
pub trait JoinerIo {
    /// Send an MLE Discovery Request carrying the Discovery TLV value `tlv`
    /// on `channel` to `pan_id` (`Mle::send_discovery_request`).
    fn send_discovery_request(&mut self, channel: u8, pan_id: u16, tlv: &[u8]) -> Result<()>;
    /// Set the MAC extended address (and the link-local address derived
    /// from it).
    fn set_ext_address(&mut self, ext: &ExtAddress);
    /// Tune the MAC to `channel` and `pan_id`.
    fn set_pan(&mut self, channel: u8, pan_id: u16) -> Result<()>;
    /// Accept (`true`) or stop accepting unsecured frames for UDP `port`
    /// (OT `Ip6::Filter::AddUnsecurePort`).
    fn set_unsecure_port(&mut self, port: u16, allow: bool);
    /// Send a UDP datagram from our link-local address and `src_port` to
    /// `dst` without link-layer security.
    fn send_unsecured(&mut self, src_port: u16, dst: &Peer, payload: &[u8]) -> Result<()>;
    /// Install (`Some`) or discard (`None`) the KEK of key ID mode 0 in the
    /// MAC (`KeyManager::set_kek`).
    fn set_kek(&mut self, kek: Option<&Kek>);
    /// Send a UDP datagram from our link-local address and `src_port` to
    /// `dst` secured with key ID mode 0 (the KEK).
    fn send_kek(&mut self, src_port: u16, dst: &Peer, payload: &[u8]) -> Result<()>;
    /// Save the credentials of the Joiner Entrust as the local Active
    /// Dataset (`ActiveDatasetManager::SaveLocal`).
    fn save_dataset(&mut self, dataset: &Dataset);
    /// Notification.
    fn event(&mut self, _event: JoinerEvent) {}
}

/// Vendor information sent in JOIN_FIN.req (OT `Joiner::Start` arguments).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct JoinerConfig<'a> {
    /// Provisioning URL (at most 64 bytes); the Commissioner rejects a
    /// URL other than its own.
    pub provisioning_url: Option<&'a str>,
    /// Vendor Name (at most 32 bytes).
    pub vendor_name: &'a str,
    /// Vendor Model (at most 32 bytes).
    pub vendor_model: &'a str,
    /// Vendor SW Version (at most 16 bytes).
    pub vendor_sw_version: &'a str,
    /// Vendor Data (at most 64 bytes).
    pub vendor_data: Option<&'a str>,
    /// Vendor Stack Version TLV value (OUI, build, revision, major/minor).
    pub vendor_stack_version: [u8; VENDOR_STACK_VERSION_LEN],
}

/// A discovered Joiner Router (OT `Joiner::JoinerRouter`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Candidate {
    /// Extended address of the Joiner Router.
    pub ext_address: ExtAddress,
    /// PAN ID.
    pub pan_id: u16,
    /// Joiner UDP port.
    pub joiner_udp_port: u16,
    /// Channel.
    pub channel: u8,
    /// OT `CalculatePriority`.
    pub priority: u8,
}

/// OT `Joiner::CalculatePriority`: RSSI clamped to -127..=-1, plus 256 if
/// the Steering Data names this Joiner, 128 if it allows any Joiner
/// (truncated to 8 bits as in OT).
pub fn calculate_priority(rssi: i8, steering_allows_any: bool) -> u8 {
    let rssi = if rssi == 127 {
        -127
    } else {
        rssi.clamp(-127, -1)
    };
    let p = i16::from(rssi) + if steering_allows_any { 128 } else { 256 };
    p as u8
}

/// The Joiner (OT `MeshCoP::Joiner`).
pub struct Joiner<B: CryptoBackend, C: P256> {
    crypto: B,
    curve: C,
    state: JoinerState,
    /// Joiner ID (from the EUI-64 or the discerner).
    id: ExtAddress,
    discerner: Option<JoinerDiscerner>,
    pskd: Option<JoinerPskd>,
    /// Prepared JOIN_FIN.req payload.
    finalize: Vec<u8, 240>,
    candidates: [Option<Candidate>; MAX_CANDIDATES],
    next_candidate: usize,
    current: Option<Candidate>,
    scanner: DiscoverScanner,
    scan_channel: u8,
    dtls: Option<Session<B, C>>,
    peer: Option<Peer>,
    coap: Endpoint<1, 1, 1, COAP_MSG, 4>,
    entrust_ep: Endpoint<1, 1, 1, COAP_MSG, 4>,
    kek: Option<Kek>,
    timer: Option<Instant>,
}

impl<B: CryptoBackend, C: P256> core::fmt::Debug for Joiner<B, C> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Joiner")
            .field("state", &self.state)
            .field("id", &self.id)
            .field("candidates", &self.candidates)
            .finish_non_exhaustive()
    }
}

impl<B, C> Joiner<B, C>
where
    B: CryptoBackend + Clone,
    B::Sha256: Clone,
    C: P256 + Clone,
{
    /// An idle Joiner using `crypto` and `curve` for the DTLS session.
    pub fn new(crypto: B, curve: C) -> Self {
        let mut entrust_ep = Endpoint::new(0, Default::default());
        // Cannot fail: one resource slot.
        let _ = entrust_ep.add_resource(Uri::JoinerEntrust.path(), RES_JOINER_ENTRUST);
        Self {
            crypto,
            curve,
            state: JoinerState::Idle,
            id: ExtAddress([0; 8]),
            discerner: None,
            pskd: None,
            finalize: Vec::new(),
            candidates: [None; MAX_CANDIDATES],
            next_candidate: 0,
            current: None,
            scanner: DiscoverScanner::new(),
            scan_channel: 0,
            dtls: None,
            peer: None,
            coap: Endpoint::new(0, Default::default()),
            entrust_ep,
            kek: None,
            timer: None,
        }
    }

    /// Current state.
    pub fn state(&self) -> JoinerState {
        self.state
    }

    /// The Joiner ID in use (valid once started, or after
    /// [`set_discerner`](Self::set_discerner)).
    pub fn id(&self) -> &ExtAddress {
        &self.id
    }

    /// The Joiner Discerner, if set.
    pub fn discerner(&self) -> Option<&JoinerDiscerner> {
        self.discerner.as_ref()
    }

    /// The Joiner Router being joined through (from the DTLS connection
    /// until the Joiner finishes).
    pub fn joiner_router(&self) -> Option<&Candidate> {
        self.current.as_ref()
    }

    /// The ranked Joiner Router candidates of the last discovery.
    pub fn candidates(&self) -> impl Iterator<Item = &Candidate> {
        self.candidates.iter().flatten()
    }

    /// Use a Joiner Discerner instead of the EUI-64 derived Joiner ID (OT
    /// `SetDiscerner`): the Joiner ID becomes random with the discerner in
    /// its low bits. Only while idle.
    pub fn set_discerner<R: CryptoRng + ?Sized>(
        &mut self,
        rng: &mut R,
        d: JoinerDiscerner,
    ) -> Result<()> {
        if !d.is_valid() {
            return Err(Error::InvalidArgs);
        }
        if self.state != JoinerState::Idle {
            return Err(Error::InvalidState);
        }
        self.id = random_ext_address(rng);
        d.copy_to(&mut self.id);
        self.discerner = Some(d);
        Ok(())
    }

    /// Go back to the EUI-64 derived Joiner ID (OT `ClearDiscerner`).
    pub fn clear_discerner(&mut self) -> Result<()> {
        if self.state != JoinerState::Idle {
            return Err(Error::InvalidState);
        }
        self.discerner = None;
        Ok(())
    }

    /// Start joining (OT `Joiner::Start`): validate the PSKd and the vendor
    /// strings, prepare JOIN_FIN.req, pick a random MAC address and start
    /// the discovery on `scan_channels` (bit `n` = channel `n`, `0` = all
    /// page 0 channels). The device must not be attached (MLE disabled).
    ///
    /// [`Error::Busy`] unless idle, [`Error::InvalidArgs`] for an invalid
    /// PSKd or an over-long string.
    #[allow(clippy::too_many_arguments)]
    pub fn start<R: CryptoRng + ?Sized, I: JoinerIo + ?Sized>(
        &mut self,
        now: Instant,
        rng: &mut R,
        io: &mut I,
        eui64: &ExtAddress,
        pskd: &str,
        cfg: &JoinerConfig<'_>,
        scan_channels: u32,
    ) -> Result<()> {
        if self.state != JoinerState::Idle {
            return Err(Error::Busy);
        }
        let pskd = JoinerPskd::new(pskd)?;
        self.finalize = build_finalize(cfg)?;
        self.pskd = Some(pskd);
        self.candidates = [None; MAX_CANDIDATES];
        self.next_candidate = 0;
        self.current = None;
        let filter = match &self.discerner {
            Some(d) => HashBitIndexes::of_discerner(d),
            None => {
                self.id = compute_joiner_id(&self.crypto, eui64);
                HashBitIndexes::of_joiner_id(&self.id)
            }
        };
        self.coap = Endpoint::new(rng.next_u32() as u16, Default::default());
        let mid = rng.next_u32() as u16;
        self.entrust_ep = Endpoint::new(mid, Default::default());
        self.entrust_ep
            .add_resource(Uri::JoinerEntrust.path(), RES_JOINER_ENTRUST)?;
        io.set_ext_address(&random_ext_address(rng));
        if let Err(e) =
            self.scanner
                .start(PAGE0_CHANNELS, scan_channels, 0xffff, true, Some(filter))
        {
            self.pskd = None;
            return Err(e);
        }
        self.set_state(io, JoinerState::Discover);
        let _ = now;
        Ok(())
    }

    /// Abort joining (OT `Joiner::Stop`): reported as
    /// [`JoinerEvent::Done`] with [`Error::Abort`].
    pub fn stop<I: JoinerIo + ?Sized>(&mut self, io: &mut I) {
        self.finish(io, Err(Error::Abort));
    }

    /// When [`poll`](Self::poll) must be called next.
    pub fn next_deadline(&self) -> Option<Instant> {
        [
            self.scanner.next_deadline(),
            self.dtls.as_ref().and_then(|s| s.next_timeout()),
            self.coap.next_deadline(),
            self.entrust_ep.next_deadline(),
            self.timer,
        ]
        .into_iter()
        .flatten()
        .min()
        // A discovery step (the next Discovery Request) is due right away.
        .or_else(|| self.scanner.is_scanning().then_some(Instant::ZERO))
    }

    /// Run timers: discovery steps, DTLS retransmissions, CoAP
    /// retransmissions and the response / entrust timeouts.
    pub fn poll<R: CryptoRng + ?Sized, I: JoinerIo + ?Sized>(
        &mut self,
        now: Instant,
        rng: &mut R,
        io: &mut I,
    ) {
        if self.state == JoinerState::Discover {
            match self.scanner.poll(now) {
                Some(ScanStep::Request {
                    channel,
                    pan_id,
                    joiner,
                }) => {
                    self.scan_channel = channel;
                    let mut b = [0u8; 8];
                    if let Ok(n) = build_request_tlv(joiner, &mut b) {
                        let _ = io.send_discovery_request(channel, pan_id, &b[..n]);
                    }
                }
                Some(ScanStep::Done) => self.discovery_done(now, rng, io),
                None => {}
            }
        }
        if let (Some(s), Some(peer)) = (self.dtls.as_mut(), self.peer) {
            s.handle_timeout(now);
            let _ = secure::flush(s, |d| io.send_unsecured(JOINER_UDP_PORT, &peer, d));
            if let Some(s) = self.dtls.as_mut() {
                let mut tx = DtlsTx {
                    session: s,
                    out: |d: &[u8]| io.send_unsecured(JOINER_UDP_PORT, &peer, d),
                };
                while self.coap.poll(now, &mut tx).is_some() {}
            }
            self.check_session(now, rng, io);
        }
        {
            let mut tx = KekTx(io);
            while self.entrust_ep.poll(now, &mut tx).is_some() {}
        }
        if self.timer.is_some_and(|t| t <= now) {
            self.timer = None;
            match self.state {
                JoinerState::Connected | JoinerState::Entrust => {
                    self.finish(io, Err(Error::ResponseTimeout));
                }
                JoinerState::Joined => {
                    io.set_ext_address(&random_ext_address(rng));
                    self.finish(io, Ok(()));
                }
                _ => {}
            }
        }
    }

    /// A Discovery Response arrived (from
    /// `MleEnv::discovery_response_received`). The channel of the response
    /// defaults to the channel being scanned.
    pub fn handle_discovery_response(&mut self, info: &DiscoveryResponseInfo, tlvs: &[u8]) {
        if self.state != JoinerState::Discover {
            return;
        }
        let mut info = *info;
        if info.channel.is_none() {
            info.channel = Some(self.scan_channel);
        }
        if let Some(r) = self.scanner.handle_response(&info, tlvs) {
            self.save_candidate(&r);
        }
    }

    /// OT `SaveDiscoveredJoinerRouter`: insert by priority.
    fn save_candidate(&mut self, r: &ScanResult) {
        let Some(port) = r.joiner_udp_port.filter(|&p| p > 0) else {
            return;
        };
        let allows_any = r.steering_data.is_some_and(|s| s.permits_all());
        let c = Candidate {
            ext_address: r.ext_address,
            pan_id: r.pan_id,
            joiner_udp_port: port,
            channel: r.channel,
            priority: calculate_priority(r.rssi, allows_any),
        };
        let Some(pos) = self
            .candidates
            .iter()
            .position(|e| e.is_none_or(|e| c.priority > e.priority))
        else {
            return;
        };
        for i in (pos + 1..MAX_CANDIDATES).rev() {
            self.candidates[i] = self.candidates[i - 1];
        }
        self.candidates[pos] = Some(c);
    }

    /// OT `HandleDiscoverResult(nullptr)`: switch to the Joiner ID and try
    /// the candidates.
    fn discovery_done<R: CryptoRng + ?Sized, I: JoinerIo + ?Sized>(
        &mut self,
        now: Instant,
        rng: &mut R,
        io: &mut I,
    ) {
        io.set_ext_address(&self.id);
        self.next_candidate = 0;
        self.try_next(now, rng, io, None);
    }

    /// OT `TryNextJoinerRouter`.
    fn try_next<R: CryptoRng + ?Sized, I: JoinerIo + ?Sized>(
        &mut self,
        now: Instant,
        rng: &mut R,
        io: &mut I,
        mut prev: Option<Error>,
    ) {
        while self.next_candidate < MAX_CANDIDATES {
            let Some(c) = self.candidates[self.next_candidate] else {
                break;
            };
            self.next_candidate += 1;
            match self.connect(now, rng, io, &c) {
                Ok(()) => return,
                Err(e) => {
                    prev.get_or_insert(e);
                }
            }
        }
        self.finish(io, Err(prev.unwrap_or(Error::NotFound)));
    }

    /// OT `Joiner::Connect`.
    fn connect<R: CryptoRng + ?Sized, I: JoinerIo + ?Sized>(
        &mut self,
        now: Instant,
        rng: &mut R,
        io: &mut I,
        c: &Candidate,
    ) -> Result<()> {
        let pskd = self.pskd.as_ref().ok_or(Error::InvalidState)?;
        io.set_pan(c.channel, c.pan_id)?;
        io.set_unsecure_port(JOINER_UDP_PORT, true);
        let peer = Peer::new(ipv6::link_local(&c.ext_address), c.joiner_udp_port);
        // Replacing an earlier session wipes it.
        self.dtls = None;
        let mut s = Session::client(
            self.crypto.clone(),
            self.curve.clone(),
            pskd.as_bytes(),
            Config::default(),
            now,
            rng,
        )?;
        let _ = secure::flush(&mut s, |d| io.send_unsecured(JOINER_UDP_PORT, &peer, d));
        self.dtls = Some(s);
        self.peer = Some(peer);
        self.current = Some(*c);
        self.set_state(io, JoinerState::Connect);
        Ok(())
    }

    /// A UDP datagram to [`JOINER_UDP_PORT`] from `src` (the Joiner Router,
    /// normally without link security; the DTLS records authenticate
    /// themselves). Datagrams from anyone but the Joiner Router being
    /// connected to are dropped.
    pub fn handle_udp<R: CryptoRng + ?Sized, I: JoinerIo + ?Sized>(
        &mut self,
        now: Instant,
        rng: &mut R,
        io: &mut I,
        src: &Peer,
        payload: &[u8],
    ) {
        if !matches!(self.state, JoinerState::Connect | JoinerState::Connected)
            || self.peer != Some(*src)
        {
            return;
        }
        let peer = *src;
        if self.dtls.is_none() {
            return;
        }
        let mut rest = payload;
        let mut app = [0u8; MAX_CONTENT_LEN];
        while let Some(s) = self.dtls.as_mut() {
            let got = secure::next_app_data(s, now, rng, &mut rest, &mut app);
            let _ = secure::flush(s, |d| io.send_unsecured(JOINER_UDP_PORT, &peer, d));
            self.check_session(now, rng, io);
            let Some(n) = got else { break };
            self.handle_coap(now, io, &peer, &app[..n]);
        }
    }

    /// React to DTLS state changes (OT `HandleSecureCoapClientConnect`).
    fn check_session<R: CryptoRng + ?Sized, I: JoinerIo + ?Sized>(
        &mut self,
        now: Instant,
        rng: &mut R,
        io: &mut I,
    ) {
        let Some(st) = self.dtls.as_ref().map(|s| s.state()) else {
            return;
        };
        match (self.state, st) {
            (JoinerState::Connect, DtlsState::Connected) => {
                self.kek = self.dtls.as_ref().and_then(|s| s.kek().cloned());
                io.set_kek(self.kek.as_ref());
                self.set_state(io, JoinerState::Connected);
                self.send_finalize(now, rng, io);
                self.timer = Some(now.saturating_add(RESPONSE_TIMEOUT));
            }
            (JoinerState::Connect, DtlsState::Closed(_)) => {
                self.dtls = None;
                self.try_next(now, rng, io, Some(Error::Security));
            }
            _ => {}
        }
    }

    /// OT `SendJoinerFinalize`.
    fn send_finalize<R: CryptoRng + ?Sized, I: JoinerIo + ?Sized>(
        &mut self,
        now: Instant,
        rng: &mut R,
        io: &mut I,
    ) {
        let (Some(s), Some(peer)) = (self.dtls.as_mut(), self.peer) else {
            return;
        };
        let mut tx = DtlsTx {
            session: s,
            out: |d: &[u8]| io.send_unsecured(JOINER_UDP_PORT, &peer, d),
        };
        crate::cert_log::cert_log(true, crate::cert_log::Msg::FinReq, &self.finalize);
        let _ = self.coap.post(
            now,
            rng,
            &mut tx,
            &peer,
            &SendOpts::default(),
            Uri::JoinerFinalize.path(),
            &self.finalize,
            Some(USER_JOIN_FIN),
        );
    }

    fn handle_coap<I: JoinerIo + ?Sized>(
        &mut self,
        now: Instant,
        io: &mut I,
        peer: &Peer,
        data: &[u8],
    ) {
        let Some(s) = self.dtls.as_mut() else { return };
        let mut tx = DtlsTx {
            session: s,
            out: |d: &[u8]| io.send_unsecured(JOINER_UDP_PORT, peer, d),
        };
        let info = RxInfo {
            peer: *peer,
            dst: Ipv6Addr::UNSPECIFIED,
        };
        let accepted = match self.coap.handle_datagram(now, &mut tx, &info, data) {
            Rx::Response {
                user: USER_JOIN_FIN,
                msg,
                ..
            } => {
                // OT `HandleJoinerFinalizeResponse`: a piggybacked 2.04
                // with a State TLV.
                if self.state != JoinerState::Connected
                    || msg.ty() != Type::Ack
                    || msg.code() != Code::CHANGED
                {
                    return;
                }
                if Tlvs(msg.payload()).state().is_ok() {
                    crate::cert_log::cert_log(false, crate::cert_log::Msg::FinRsp, msg.payload());
                }
                Tlvs(msg.payload()).state().ok()
            }
            _ => return,
        };
        // OT disconnects after any JOIN_FIN response.
        self.close_dtls(io);
        io.set_unsecure_port(JOINER_UDP_PORT, false);
        // OT `HandleJoinerFinalizeResponse` goes to the Entrust state for
        // any State value and waits for the Joiner Entrust: the Commissioner
        // relays the KEK with a Reject as well.
        if accepted.is_some() {
            self.set_state(io, JoinerState::Entrust);
            self.timer = Some(now.saturating_add(RESPONSE_TIMEOUT));
        }
    }

    /// A datagram to the TMF port that the MAC accepted with `link`
    /// security. Only key ID mode 0 ([`LinkSecurity::Kek`]) datagrams are
    /// considered, and only while waiting for the Joiner Entrust (OT
    /// `HandleTmf<kUriJoinerEntrust>`): the Network Key is saved with the
    /// channel and PAN ID of the Joiner Router, the empty 2.04 response is
    /// sent back under the KEK.
    pub fn handle_kek_datagram<I: JoinerIo + ?Sized>(
        &mut self,
        now: Instant,
        io: &mut I,
        link: LinkSecurity,
        src: &Peer,
        dst: &Ipv6Addr,
        payload: &[u8],
    ) {
        if link != LinkSecurity::Kek || self.kek.is_none() {
            return;
        }
        if !matches!(self.state, JoinerState::Entrust | JoinerState::Joined) {
            return;
        }
        let info = RxInfo {
            peer: *src,
            dst: *dst,
        };
        let Rx::Request(req) =
            self.entrust_ep
                .handle_datagram(now, &mut KekTx(&mut *io), &info, payload)
        else {
            return;
        };
        // A retransmission after we answered is served from the cache.
        if self.state != JoinerState::Entrust
            || req.msg.ty() != Type::Con
            || req.msg.code() != Code::POST
        {
            return;
        }
        let Ok(key) = Tlvs(req.msg.payload()).network_key() else {
            return;
        };
        crate::cert_log::cert_log(false, crate::cert_log::Msg::EntNtf, &[]);
        let Some(c) = self.current else { return };
        let mut ds = Dataset::new();
        if ds.set_network_key(&key).is_err()
            || ds.set_channel(c.channel).is_err()
            || ds.set_pan_id(c.pan_id).is_err()
        {
            return;
        }
        io.save_dataset(&ds);
        drop(ds);
        crate::cert_log::cert_log(true, crate::cert_log::Msg::EntRsp, &[]);
        let opts = SendOpts::default();
        let _ = self.entrust_ep.respond_payload(
            now,
            &mut KekTx(&mut *io),
            &req.ctx,
            &opts,
            Code::CHANGED,
            &[],
        );
        self.set_state(io, JoinerState::Joined);
        self.timer = Some(now.saturating_add(CONFIG_EXT_ADDRESS_DELAY));
    }

    fn close_dtls<I: JoinerIo + ?Sized>(&mut self, io: &mut I) {
        if let (Some(mut s), Some(peer)) = (self.dtls.take(), self.peer) {
            s.close();
            let _ = secure::flush(&mut s, |d| io.send_unsecured(JOINER_UDP_PORT, &peer, d));
        }
        self.coap.clear();
    }

    /// OT `Joiner::Finish`.
    fn finish<I: JoinerIo + ?Sized>(&mut self, io: &mut I, result: Result<()>) {
        if self.state == JoinerState::Idle {
            return;
        }
        if self.state != JoinerState::Discover {
            self.close_dtls(io);
            io.set_unsecure_port(JOINER_UDP_PORT, false);
        }
        self.dtls = None;
        self.peer = None;
        self.timer = None;
        self.scanner = DiscoverScanner::new();
        self.coap.clear();
        self.entrust_ep.clear();
        // Single-use secrets.
        self.kek = None;
        io.set_kek(None);
        self.pskd = None;
        self.finalize.clear();
        self.set_state(io, JoinerState::Idle);
        io.event(JoinerEvent::Done(result));
    }

    fn set_state<I: JoinerIo + ?Sized>(&mut self, io: &mut I, s: JoinerState) {
        if self.state != s {
            self.state = s;
            io.event(JoinerEvent::State(s));
        }
    }
}

/// JOIN_ENT response transport: key ID mode 0 from the TMF port.
struct KekTx<'a, I: ?Sized>(&'a mut I);

impl<I: JoinerIo + ?Sized> Transport for KekTx<'_, I> {
    fn send(&mut self, peer: &Peer, _opts: &SendOpts, data: &[u8]) -> Result<()> {
        self.0.send_kek(TMF_PORT, peer, data)
    }
}

/// A random extended address with the local bit set and the group bit
/// clear (OT `ExtAddress::GenerateRandom`).
fn random_ext_address<R: CryptoRng + ?Sized>(rng: &mut R) -> ExtAddress {
    let mut a = [0u8; 8];
    rng.fill_bytes(&mut a);
    a[0] = (a[0] | 0x02) & !0x01;
    ExtAddress(a)
}

/// OT `PrepareJoinerFinalizeMessage`: State Accept, Vendor Name, Model, SW
/// Version, Stack Version, optional Vendor Data and Provisioning URL.
fn build_finalize(cfg: &JoinerConfig<'_>) -> Result<Vec<u8, 240>> {
    let too_long = cfg.vendor_name.len() > MAX_VENDOR_NAME_LEN
        || cfg.vendor_model.len() > MAX_VENDOR_MODEL_LEN
        || cfg.vendor_sw_version.len() > MAX_VENDOR_SW_VERSION_LEN
        || cfg
            .vendor_data
            .is_some_and(|d| d.len() > MAX_VENDOR_DATA_LEN)
        || cfg
            .provisioning_url
            .is_some_and(|u| u.len() > MAX_PROVISIONING_URL_LEN);
    if too_long {
        return Err(Error::InvalidArgs);
    }
    let mut buf = [0u8; 240];
    let mut w = Writer::new(&mut buf);
    w.state(State::Accept)?;
    w.vendor_name(cfg.vendor_name)?;
    w.vendor_model(cfg.vendor_model)?;
    w.vendor_sw_version(cfg.vendor_sw_version)?;
    w.vendor_stack_version(&cfg.vendor_stack_version)?;
    if let Some(d) = cfg.vendor_data {
        w.vendor_data(d)?;
    }
    if let Some(u) = cfg.provisioning_url {
        w.provisioning_url(u)?;
    }
    Vec::from_slice(w.written()).map_err(|_| Error::NoBufs)
}
