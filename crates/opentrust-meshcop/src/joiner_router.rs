//! The Joiner Router (Thread 1.4.1 sections 8.4.3.2 / 8.4.4, OT
//! `meshcop/joiner_router.cpp`).
//!
//! While the Commissioning Data allows joining (non-empty Steering Data) a
//! Full Thread Device opens the Joiner UDP port (configured, else the
//! Joiner UDP Port of the Commissioning Data, else 1000) for unsecured
//! frames and relays the Joiner's DTLS records:
//!
//! - **Relay Receive** ([`JoinerRouter::handle_joiner_datagram`]): a
//!   datagram from a Joiner (link-local source) becomes a NON `/c/rx` to
//!   the Border Agent Locator of the Commissioning Data, with the Joiner
//!   UDP Port, Joiner IID, Joiner Router Locator and Joiner DTLS
//!   Encapsulation TLVs.
//! - **Relay Transmit** ([`JoinerRouter::handle_relay_tx`]): the records of
//!   a `/c/tx` go back to the Joiner unsecured. A Joiner Router KEK TLV
//!   (attached by the Commissioner to the JOIN_FIN response) schedules the
//!   Joiner Entrust [`JOINER_ENTRUST_TX_DELAY`] later.
//! - **Joiner Entrust** ([`JoinerRouter::poll`]): a CON `/c/je` to the
//!   Joiner's link-local address with the Network Key, Mesh-Local Prefix,
//!   Extended PAN ID, Network Name, Active Timestamp, Channel Mask, PSKc and
//!   Security Policy of the Active Dataset and the Network Key Sequence,
//!   secured at the MAC with the KEK in key ID mode 0 (OT
//!   `kSubTypeJoinerEntrust`). Its retransmissions and the Joiner's
//!   response use the KEK as well; the response is fed to
//!   [`JoinerRouter::handle_kek_datagram`]. One Joiner Entrust is in flight
//!   at a time; the KEK is discarded once it is answered or timed out.
//!
//! Feature `ftd`.

use core::net::Ipv6Addr;

use heapless::Vec;
use opentrust_coap::endpoint::{Endpoint, Event, Peer, Rx, RxInfo, SendOpts, Transport};
use opentrust_coap::message::{Code, Type};
use opentrust_coap::tmf::{Agent, UDP_PORT as TMF_PORT, UdpSink};
use opentrust_coap::uri::Uri;
use opentrust_core::bytes::Writer;
use opentrust_core::message::Priority;
use opentrust_core::time::{Duration, Instant};
use opentrust_core::types::{Kek, Prefix64, Rloc16, ipv6};
use opentrust_core::{Error, Result, tlv};
use rand_core::Rng;

use crate::dataset::Dataset;
use crate::discovery::{DEFAULT_JOINER_UDP_PORT, joining_allowed};
use crate::secure::LinkSecurity;
use crate::tlv::{Tlvs, WriterExt, ty};

/// Delay between the Relay Transmit carrying the KEK and the Joiner
/// Entrust (`JoinerRouter::kJoinerEntrustTxDelay`).
pub const JOINER_ENTRUST_TX_DELAY: Duration = Duration::from_millis(50);
/// Joiner Entrust messages that can wait for their turn.
pub const MAX_DELAYED_ENTRUST: usize = 2;

/// Active Dataset TLVs of the Joiner Entrust, in OT's order
/// (`PrepareJoinerEntrustMessage`).
pub const ENTRUST_TLVS: [u8; 8] = [
    ty::NETWORK_KEY,
    ty::MESH_LOCAL_PREFIX,
    ty::EXT_PAN_ID,
    ty::NETWORK_NAME,
    ty::ACTIVE_TIMESTAMP,
    ty::CHANNEL_MASK,
    ty::PSKC,
    ty::SECURITY_POLICY,
];

const ENTRUST_MSG: usize = 192;
const USER_JOINER_ENTRUST: u32 = 0x4a45_0001;

/// What the Joiner Router needs from the stack besides the TMF agent.
pub trait JoinerRouterIo {
    /// Open the Joiner UDP port for unsecured frames (`Some(port)`), or
    /// close it (`None`) (OT `mSocket.Bind` + `Ip6::Filter::AddUnsecurePort`).
    fn set_joiner_port(&mut self, port: Option<u16>);
    /// Send a UDP datagram from our link-local address and `src_port` to
    /// a Joiner without link-layer security.
    fn send_unsecured(&mut self, src_port: u16, dst: &Peer, payload: &[u8]) -> Result<()>;
    /// Install (`Some`) or discard (`None`) the KEK of key ID mode 0 in the
    /// MAC (`KeyManager::set_kek`).
    fn set_kek(&mut self, kek: Option<&Kek>);
    /// Send a UDP datagram from our link-local address and `src_port`
    /// secured with key ID mode 0 under the installed KEK.
    fn send_kek(&mut self, src_port: u16, dst: &Peer, payload: &[u8]) -> Result<()>;
}

#[derive(Debug)]
struct Delayed {
    joiner: Ipv6Addr,
    send_at: Instant,
    kek: Kek,
}

/// Notification of [`JoinerRouter::poll`] / [`JoinerRouter::handle_kek_datagram`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JoinerRouterEvent {
    /// A Joiner Entrust was sent to this Joiner.
    EntrustSent(Ipv6Addr),
    /// The Joiner answered the Joiner Entrust.
    EntrustAcknowledged(Ipv6Addr),
    /// No answer to the Joiner Entrust.
    EntrustTimeout(Ipv6Addr),
}

/// The Joiner Router (OT `MeshCoP::JoinerRouter`).
#[derive(Debug)]
pub struct JoinerRouter {
    configured_port: Option<u16>,
    open_port: Option<u16>,
    delayed: Vec<Delayed, MAX_DELAYED_ENTRUST>,
    ep: Endpoint<1, 1, 1, ENTRUST_MSG, 4>,
    in_flight: Option<Ipv6Addr>,
}

impl Default for JoinerRouter {
    fn default() -> Self {
        Self::new()
    }
}

impl JoinerRouter {
    /// Joiner port closed, nothing pending.
    pub const fn new() -> Self {
        Self {
            configured_port: None,
            open_port: None,
            delayed: Vec::new(),
            ep: Endpoint::new(0, opentrust_coap::endpoint::TxParams::DEFAULT),
            in_flight: None,
        }
    }

    /// The Joiner UDP port: the configured one, else the Commissioning
    /// Data's, else 1000 (OT `GetJoinerUdpPort`).
    pub fn joiner_udp_port(&self, commissioning_data: Option<&[u8]>) -> u16 {
        self.configured_port
            .or_else(|| commissioning_data.and_then(|c| Tlvs(c).joiner_udp_port().ok()))
            .unwrap_or(DEFAULT_JOINER_UDP_PORT)
    }

    /// Override the Joiner UDP port (OT `SetJoinerUdpPort`); call
    /// [`update`](Self::update) afterwards.
    pub fn set_joiner_udp_port(&mut self, port: u16) {
        self.configured_port = Some(port);
    }

    /// The link-local address of the Joiner whose Joiner Entrust is in
    /// flight (the only peer of key ID mode 0 frames).
    pub fn entrust_in_flight(&self) -> Option<Ipv6Addr> {
        self.in_flight
    }

    /// The open Joiner port, if any.
    pub fn open_port(&self) -> Option<u16> {
        self.open_port
    }

    /// The Network Data changed (OT `HandleNotifierEvents` /
    /// `JoinerRouter::Start`): open the Joiner port while joining is
    /// allowed and this is a Full Thread Device, close it otherwise. A
    /// changed port is re-opened.
    pub fn update<I: JoinerRouterIo + ?Sized>(
        &mut self,
        is_ftd: bool,
        commissioning_data: Option<&[u8]>,
        io: &mut I,
    ) {
        let want = (is_ftd && joining_allowed(commissioning_data))
            .then(|| self.joiner_udp_port(commissioning_data));
        if want != self.open_port {
            if self.open_port.is_some() {
                io.set_joiner_port(None);
            }
            if want.is_some() {
                io.set_joiner_port(want);
            }
            self.open_port = want;
        }
    }

    /// A datagram from a Joiner to the open Joiner port (OT
    /// `HandleUdpReceive`): relay it to the Border Agent as `/c/rx` (NON,
    /// from our RLOC). Only datagrams from a link-local source are relayed.
    /// [`Error::NotFound`] without a Border Agent Locator,
    /// [`Error::Drop`] for a datagram that is not for the Joiner port.
    #[allow(clippy::too_many_arguments)]
    pub fn handle_joiner_datagram<
        R: Rng + ?Sized,
        S: UdpSink + ?Sized,
        const REQ: usize,
        const RES: usize,
        const CACHE: usize,
        const MSG: usize,
    >(
        &mut self,
        agent: &mut Agent<REQ, RES, CACHE, MSG>,
        now: Instant,
        rng: &mut R,
        sink: &mut S,
        mlp: &Prefix64,
        own_rloc16: Rloc16,
        border_agent_locator: Option<u16>,
        src: &Peer,
        dst_port: u16,
        payload: &[u8],
    ) -> Result<()> {
        if self.open_port != Some(dst_port) || !ipv6::is_link_local(&src.addr) || payload.is_empty()
        {
            return Err(Error::Drop);
        }
        let ba = border_agent_locator.ok_or(Error::NotFound)?;
        let rloc = mlp.rloc(own_rloc16);
        agent.send_request(
            now,
            rng,
            sink,
            mlp.rloc(Rloc16(ba)),
            &SendOpts {
                src: Some(rloc),
                priority: Priority::Net,
                multicast_loop: false,
            },
            Type::Non,
            Code::POST,
            None,
            |mut b| {
                b.uri_path(Uri::RelayRx.path())?;
                b.finish_with(|w| {
                    w.joiner_udp_port(src.port)?;
                    w.joiner_iid(&ipv6::iid(&src.addr))?;
                    w.joiner_router_locator(own_rloc16.0)?;
                    w.joiner_dtls_encapsulation(payload)
                })
            },
        )
    }

    /// `/c/tx` Relay Transmit (OT `HandleTmf<kUriRelayTx>`): send the
    /// encapsulated records to the Joiner (unsecured, from the Joiner
    /// port); with a Joiner Router KEK TLV, schedule the Joiner Entrust.
    /// The payload is the request's TLVs; `confirmable` requests are
    /// dropped as in OT.
    pub fn handle_relay_tx<I: JoinerRouterIo + ?Sized>(
        &mut self,
        now: Instant,
        io: &mut I,
        confirmable: bool,
        payload: &[u8],
    ) -> Result<()> {
        if confirmable {
            return Err(Error::Drop);
        }
        let port = self.open_port.ok_or(Error::InvalidState)?;
        let t = Tlvs(payload);
        let joiner_port = t.joiner_udp_port()?;
        let iid = t.joiner_iid()?;
        let records = t.joiner_dtls_encapsulation()?;
        let joiner = ipv6::LINK_LOCAL_PREFIX.with_iid(&iid);
        io.send_unsecured(port, &Peer::new(joiner, joiner_port), records)?;
        match t.joiner_router_kek() {
            Ok(kek) => {
                if self.delayed.is_full() {
                    return Err(Error::NoBufs);
                }
                let _ = self.delayed.push(Delayed {
                    joiner,
                    send_at: now.saturating_add(JOINER_ENTRUST_TX_DELAY),
                    kek,
                });
                Ok(())
            }
            Err(Error::NotFound) => Ok(()),
            Err(e) => Err(e),
        }
    }

    /// When [`poll`](Self::poll) must be called next.
    pub fn next_deadline(&self) -> Option<Instant> {
        let next_entrust = if self.in_flight.is_none() {
            self.delayed.iter().map(|d| d.send_at).min()
        } else {
            None
        };
        [next_entrust, self.ep.next_deadline()]
            .into_iter()
            .flatten()
            .min()
    }

    /// Send a due Joiner Entrust and drive its retransmissions. `active`
    /// is the Active Dataset (all of [`ENTRUST_TLVS`] are required; a
    /// Joiner Entrust that cannot be built is dropped), `key_sequence` the
    /// current key sequence.
    pub fn poll<R: Rng + ?Sized, I: JoinerRouterIo + ?Sized>(
        &mut self,
        now: Instant,
        rng: &mut R,
        io: &mut I,
        active: Option<&Dataset>,
        key_sequence: u32,
    ) -> Option<JoinerRouterEvent> {
        if let Some(Event::Timeout { .. }) = self.ep.poll(now, &mut KekTx(io)) {
            let j = self.in_flight.take()?;
            io.set_kek(None);
            return Some(JoinerRouterEvent::EntrustTimeout(j));
        }
        if self.in_flight.is_some() {
            return None;
        }
        let i = self
            .delayed
            .iter()
            .enumerate()
            .filter(|(_, d)| d.send_at <= now)
            .min_by_key(|(_, d)| d.send_at)
            .map(|(i, _)| i)?;
        let d = self.delayed.swap_remove(i);
        let mut buf = [0u8; ENTRUST_MSG];
        let n = active.and_then(|ds| build_entrust(ds, key_sequence, &mut buf).ok())?;
        io.set_kek(Some(&d.kek));
        self.ep.clear();
        let r = self.ep.post(
            now,
            rng,
            &mut KekTx(io),
            &Peer::new(d.joiner, TMF_PORT),
            &SendOpts {
                src: None,
                priority: Priority::Net,
                multicast_loop: false,
            },
            Uri::JoinerEntrust.path(),
            &buf[..n],
            Some(USER_JOINER_ENTRUST),
        );
        // `buf` holds the Network Key and PSKc.
        zeroize::Zeroize::zeroize(&mut buf);
        if r.is_err() {
            io.set_kek(None);
            return None;
        }
        self.in_flight = Some(d.joiner);
        Some(JoinerRouterEvent::EntrustSent(d.joiner))
    }

    /// A datagram to the TMF port that the MAC accepted with `link`
    /// security: the Joiner's response to the Joiner Entrust (only key ID
    /// mode 0 is considered). The KEK is discarded afterwards.
    pub fn handle_kek_datagram<I: JoinerRouterIo + ?Sized>(
        &mut self,
        now: Instant,
        io: &mut I,
        link: LinkSecurity,
        src: &Peer,
        dst: &Ipv6Addr,
        payload: &[u8],
    ) -> Option<JoinerRouterEvent> {
        if link != LinkSecurity::Kek || self.in_flight != Some(src.addr) {
            return None;
        }
        let info = RxInfo {
            peer: *src,
            dst: *dst,
        };
        match self.ep.handle_datagram(now, &mut KekTx(io), &info, payload) {
            Rx::Response {
                user: USER_JOINER_ENTRUST,
                ..
            }
            | Rx::Failed {
                user: USER_JOINER_ENTRUST,
                ..
            } => {
                io.set_kek(None);
                self.in_flight
                    .take()
                    .map(JoinerRouterEvent::EntrustAcknowledged)
            }
            _ => None,
        }
    }
}

/// OT `PrepareJoinerEntrustMessage`: the Active Dataset TLVs of
/// [`ENTRUST_TLVS`] and the Network Key Sequence TLV.
pub fn build_entrust(active: &Dataset, key_sequence: u32, out: &mut [u8]) -> Result<usize> {
    let mut w = Writer::new(out);
    let t = active.tlvs();
    for ty in ENTRUST_TLVS {
        let v = t.value(ty).map_err(|_| Error::InvalidState)?;
        tlv::write(&mut w, ty, v)?;
    }
    w.network_key_sequence(key_sequence)?;
    Ok(w.written().len())
}

/// The Joiner Entrust exchange: key ID mode 0 from the TMF port.
struct KekTx<'a, I: ?Sized>(&'a mut I);

impl<I: JoinerRouterIo + ?Sized> Transport for KekTx<'_, I> {
    fn send(&mut self, peer: &Peer, _opts: &SendOpts, data: &[u8]) -> Result<()> {
        self.0.send_kek(TMF_PORT, peer, data)
    }
}
