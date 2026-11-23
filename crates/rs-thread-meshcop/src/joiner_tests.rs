//! Joiner state machine against a scripted Joiner Router / Commissioner
//! (a DTLS server session in the test).

use std::vec::Vec;

use rs_thread_coap::endpoint::Peer;
use rs_thread_coap::message::{Code, Message, MessageBuilder, Type};
use rs_thread_core::Error;
use rs_thread_core::bytes::Writer;
use rs_thread_core::crypto::SoftCrypto;
use rs_thread_core::crypto::ecjpake::SoftP256;
use rs_thread_core::time::{Duration, Instant};
use rs_thread_core::types::{ExtAddress, Kek, NetworkKey, ipv6};
use rs_thread_dtls::{Config, Session, State as DtlsState};
use rs_thread_mle::env::DiscoveryResponseInfo;

use crate::dataset::Dataset;
use crate::discovery::{ResponseContent, build_response_tlv};
use crate::joiner::{
    CONFIG_EXT_ADDRESS_DELAY, Candidate, JOINER_UDP_PORT, Joiner, JoinerConfig, JoinerEvent,
    JoinerIo, JoinerState, RESPONSE_TIMEOUT, calculate_priority,
};
use crate::secure::LinkSecurity;
use crate::steering::{JoinerDiscerner, SteeringData, compute_joiner_id};
use crate::test_rng::TestRng;
use crate::tlv::{State, Tlvs, WriterExt, ty};

const PSKD: &str = "J01NME";
const EUI64: ExtAddress = ExtAddress([0x18, 0xb4, 0x30, 0, 0, 0, 0, 1]);

#[derive(Default)]
struct Io {
    discovery: Vec<(u8, u16)>,
    ext: Option<ExtAddress>,
    pan: Option<(u8, u16)>,
    unsecure_ports: Vec<u16>,
    unsecured: Vec<(Peer, Vec<u8>)>,
    kek: Option<Kek>,
    kek_sent: Vec<(Peer, Vec<u8>)>,
    saved: Option<Dataset>,
    events: Vec<JoinerEvent>,
}

impl JoinerIo for Io {
    fn send_discovery_request(
        &mut self,
        channel: u8,
        pan_id: u16,
        _tlv: &[u8],
    ) -> rs_thread_core::Result<()> {
        self.discovery.push((channel, pan_id));
        Ok(())
    }
    fn set_ext_address(&mut self, ext: &ExtAddress) {
        self.ext = Some(*ext);
    }
    fn set_pan(&mut self, channel: u8, pan_id: u16) -> rs_thread_core::Result<()> {
        self.pan = Some((channel, pan_id));
        Ok(())
    }
    fn set_unsecure_port(&mut self, port: u16, allow: bool) {
        if allow {
            if !self.unsecure_ports.contains(&port) {
                self.unsecure_ports.push(port);
            }
        } else {
            self.unsecure_ports.retain(|&p| p != port);
        }
    }
    fn send_unsecured(
        &mut self,
        src_port: u16,
        dst: &Peer,
        payload: &[u8],
    ) -> rs_thread_core::Result<()> {
        assert_eq!(src_port, JOINER_UDP_PORT);
        self.unsecured.push((*dst, payload.to_vec()));
        Ok(())
    }
    fn set_kek(&mut self, kek: Option<&Kek>) {
        self.kek = kek.cloned();
    }
    fn send_kek(
        &mut self,
        src_port: u16,
        dst: &Peer,
        payload: &[u8],
    ) -> rs_thread_core::Result<()> {
        assert_eq!(src_port, 61631);
        assert!(self.kek.is_some(), "key ID mode 0 needs the KEK");
        self.kek_sent.push((*dst, payload.to_vec()));
        Ok(())
    }
    fn save_dataset(&mut self, dataset: &Dataset) {
        self.saved = Some(dataset.clone());
    }
    fn event(&mut self, e: JoinerEvent) {
        self.events.push(e);
    }
}

fn router_ext(n: u8) -> ExtAddress {
    ExtAddress([0x12, 0x34, 0, 0, 0, 0, 0, n])
}

fn router_peer(n: u8, port: u16) -> Peer {
    Peer::new(ipv6::link_local(&router_ext(n)), port)
}

/// A Discovery Response from router `n` with `steering`.
fn response(steering: &SteeringData, port: u16) -> Vec<u8> {
    let mut b = [0u8; 128];
    let ext_pan = rs_thread_core::types::ExtPanId([0xde, 0xad, 0, 0xbe, 0xef, 0, 0xca, 0xfe]);
    let name = rs_thread_core::types::NetworkName::new("RsThread").unwrap();
    let n = build_response_tlv(
        &ResponseContent {
            ext_pan_id: &ext_pan,
            network_name: &name,
            steering_data: Some(steering),
            joiner_udp_port: port,
            native_commissioner: None,
            commercial_commissioning: false,
            domain_name: None,
        },
        &mut b,
    )
    .unwrap();
    b[..n].to_vec()
}

fn info(n: u8, rss: i8) -> DiscoveryResponseInfo {
    DiscoveryResponseInfo {
        ext_address: router_ext(n),
        pan_id: Some(0x1234),
        channel: Some(15),
        rss: Some(rss),
        lqi: Some(255),
    }
}

fn steering_for(id: &ExtAddress) -> SteeringData {
    let mut s = SteeringData::new(16);
    s.add_joiner_id(id).unwrap();
    s
}

struct Fx {
    j: Joiner<SoftCrypto, SoftP256>,
    io: Io,
    rng: TestRng,
    now: Instant,
}

impl Fx {
    fn new() -> Self {
        Self {
            j: Joiner::new(SoftCrypto, SoftP256),
            io: Io::default(),
            rng: TestRng(0x5eed),
            now: Instant::from_secs(10),
        }
    }

    fn start(&mut self, pskd: &str, url: Option<&str>) -> rs_thread_core::Result<()> {
        let cfg = JoinerConfig {
            provisioning_url: url,
            vendor_name: "RsThread",
            vendor_model: "Sim",
            vendor_sw_version: "0.1",
            vendor_data: None,
            vendor_stack_version: [0, 0, 0, 0, 1, 0x40],
        };
        self.j.start(
            self.now,
            &mut self.rng,
            &mut self.io,
            &EUI64,
            pskd,
            &cfg,
            1 << 15,
        )
    }

    fn advance(&mut self, d: Duration) {
        let end = self.now + d;
        loop {
            let next = self.j.next_deadline().unwrap_or(end).max(self.now);
            if next > end {
                break;
            }
            self.now = next;
            self.j.poll(self.now, &mut self.rng, &mut self.io);
            if self.j.next_deadline().is_none_or(|d| d > end) {
                break;
            }
        }
        self.now = end;
        self.j.poll(self.now, &mut self.rng, &mut self.io);
    }

    /// Discovery on channel 15 with the given responses.
    fn discover(&mut self, responses: &[(u8, i8, SteeringData)]) {
        self.j.poll(self.now, &mut self.rng, &mut self.io);
        assert_eq!(self.io.discovery, [(15, 0xffff)]);
        for (n, rss, s) in responses {
            self.j
                .handle_discovery_response(&info(*n, *rss), &response(s, 1000 + u16::from(*n)));
        }
        self.advance(Duration::from_millis(400));
    }

    fn done(&self) -> Option<Result<(), Error>> {
        self.io.events.iter().find_map(|e| match e {
            JoinerEvent::Done(r) => Some(*r),
            _ => None,
        })
    }
}

/// The far end: DTLS server with a PSKd, CoAP on top.
struct Server {
    s: Session<SoftCrypto, SoftP256>,
    rng: TestRng,
}

impl Server {
    fn new(pskd: &str) -> Self {
        let mut rng = TestRng(0xabcd);
        let s = Session::server(
            SoftCrypto,
            SoftP256,
            pskd.as_bytes(),
            Config::default(),
            b"joiner",
            &mut rng,
        )
        .unwrap();
        Self { s, rng }
    }

    /// Exchange datagrams until quiet; returns application data received.
    fn pump(&mut self, fx: &mut Fx, from: Peer) -> Vec<Vec<u8>> {
        let mut app = Vec::new();
        for _ in 0..20 {
            let (out, other): (Vec<_>, Vec<_>) = core::mem::take(&mut fx.io.unsecured)
                .into_iter()
                .partition(|(dst, _)| *dst == from);
            fx.io.unsecured = other;
            if out.is_empty() {
                break;
            }
            for (_, d) in out {
                let mut rest = &d[..];
                while !rest.is_empty() {
                    let mut buf = [0u8; 800];
                    let rx = self
                        .s
                        .handle_datagram(fx.now, &mut self.rng, rest, &mut buf)
                        .unwrap();
                    if let Some(n) = rx.app_data {
                        app.push(buf[..n].to_vec());
                    }
                    rest = &rest[rx.consumed..];
                }
            }
            let mut buf = [0u8; 1024];
            while let Some(n) = self.s.poll_transmit(&mut buf) {
                fx.j.handle_udp(fx.now, &mut fx.rng, &mut fx.io, &from, &buf[..n]);
            }
        }
        app
    }

    /// Answer the JOIN_FIN.req in `req` with `state`.
    fn answer(&mut self, fx: &mut Fx, from: Peer, req: &[u8], state: State) {
        let m = Message::parse(req).unwrap();
        assert!(m.uri_path_is("c/jf"));
        assert_eq!(m.ty(), Type::Con);
        let mut p = [0u8; 8];
        let mut w = Writer::new(&mut p);
        w.state(state).unwrap();
        let mut b = [0u8; 64];
        let n = MessageBuilder::new(&mut b, Type::Ack, Code::CHANGED, m.message_id(), m.token())
            .unwrap()
            .finish_with_payload(w.written())
            .unwrap();
        let mut rec = [0u8; 128];
        let r = self.s.send(&b[..n], &mut rec).unwrap();
        fx.j.handle_udp(fx.now, &mut fx.rng, &mut fx.io, &from, &rec[..r]);
    }
}

/// The JOIN_ENT.ntf (CON POST /c/je) with `key`.
fn entrust(key: &NetworkKey) -> Vec<u8> {
    let mut p = [0u8; 64];
    let mut w = Writer::new(&mut p);
    w.network_key(key).unwrap();
    w.network_key_sequence(0).unwrap();
    let mut b = [0u8; 128];
    let mut m = MessageBuilder::new(&mut b, Type::Con, Code::POST, 0x77, &[1, 2]).unwrap();
    m.uri_path("c/je").unwrap();
    let n = m.finish_with_payload(w.written()).unwrap();
    b[..n].to_vec()
}

#[test]
fn invalid_start_arguments() {
    let mut fx = Fx::new();
    assert_eq!(fx.start("J01NMe", None), Err(Error::InvalidArgs));
    assert_eq!(
        fx.start("JOINME", None),
        Err(Error::InvalidArgs),
        "letter O"
    );
    assert_eq!(fx.start("ABC", None), Err(Error::InvalidArgs));
    let long = "U".repeat(65);
    assert_eq!(fx.start(PSKD, Some(&long)), Err(Error::InvalidArgs));
    assert_eq!(fx.j.state(), JoinerState::Idle);
    assert!(fx.io.events.is_empty());
    fx.start(PSKD, None).unwrap();
    assert_eq!(fx.j.state(), JoinerState::Discover);
    assert_eq!(fx.start(PSKD, None), Err(Error::Busy));
}

#[test]
fn priority_and_candidate_ranking() {
    // OT `CalculatePriority`.
    assert_eq!(calculate_priority(-60, false), 196);
    assert_eq!(calculate_priority(-60, true), 68);
    assert_eq!(calculate_priority(127, false), 129);
    assert_eq!(calculate_priority(0, false), 255);
    assert!(calculate_priority(-90, false) > calculate_priority(-20, true));

    let mut fx = Fx::new();
    fx.start(PSKD, None).unwrap();
    let id = compute_joiner_id(&SoftCrypto, &EUI64);
    let mut any = SteeringData::new(1);
    any.set_permit_all();
    let other = steering_for(&ExtAddress([9; 8]));
    // Router 3 is filtered (Steering Data without us), router 1 allows any,
    // router 2 names us (beats router 1 despite weaker signal), router 4 has
    // the strongest signal but only "any" and is dropped (two slots).
    fx.discover(&[
        (1, -40, any),
        (3, -20, other),
        (2, -80, steering_for(&id)),
        (4, -30, any),
    ]);
    let c: Vec<Candidate> = fx.j.candidates().copied().collect();
    assert_eq!(c.len(), 2);
    assert_eq!(c[0].ext_address, router_ext(2));
    assert_eq!(c[0].joiner_udp_port, 1002);
    assert_eq!(c[1].ext_address, router_ext(4));
    // Connecting to the best one: Joiner ID as MAC address, channel/PAN of
    // the router, unsecured joiner port, ClientHello to its link-local
    // address and Joiner UDP port.
    assert_eq!(fx.j.state(), JoinerState::Connect);
    assert_eq!(fx.io.ext, Some(id));
    assert_eq!(fx.io.pan, Some((15, 0x1234)));
    assert_eq!(fx.io.unsecure_ports, [JOINER_UDP_PORT]);
    assert_eq!(fx.io.unsecured[0].0, router_peer(2, 1002));
}

#[test]
fn no_joiner_router_found() {
    let mut fx = Fx::new();
    fx.start(PSKD, None).unwrap();
    fx.discover(&[(3, -20, steering_for(&ExtAddress([9; 8])))]);
    assert_eq!(fx.done(), Some(Err(Error::NotFound)));
    assert_eq!(fx.j.state(), JoinerState::Idle);
}

/// The whole exchange: handshake, JOIN_FIN accepted, Joiner Entrust under
/// the KEK, dataset saved, MAC address randomized, success.
#[test]
fn join_success() {
    let mut fx = Fx::new();
    fx.start(PSKD, Some("https://example.com/p")).unwrap();
    let id = compute_joiner_id(&SoftCrypto, &EUI64);
    fx.discover(&[(2, -50, steering_for(&id))]);
    let peer = router_peer(2, 1002);
    let mut srv = Server::new(PSKD);
    let app = srv.pump(&mut fx, peer);
    assert_eq!(srv.s.state(), DtlsState::Connected);
    assert_eq!(fx.j.state(), JoinerState::Connected);
    // The joiner installed the session's KEK for key ID mode 0.
    assert_eq!(fx.io.kek.as_ref(), srv.s.kek());
    assert_eq!(app.len(), 1);
    let m = Message::parse(&app[0]).unwrap();
    let t = Tlvs(m.payload());
    assert_eq!(t.state(), Ok(State::Accept));
    assert_eq!(t.vendor_name(), Ok("RsThread"));
    assert_eq!(t.vendor_model(), Ok("Sim"));
    assert_eq!(t.vendor_sw_version(), Ok("0.1"));
    assert_eq!(t.value(ty::VENDOR_STACK_VERSION).unwrap().len(), 6);
    assert_eq!(t.provisioning_url(), Ok("https://example.com/p"));

    srv.answer(&mut fx, peer, &app[0], State::Accept);
    assert_eq!(fx.j.state(), JoinerState::Entrust);
    assert!(fx.io.unsecure_ports.is_empty(), "joiner port closed");
    // close_notify went to the router.
    assert!(!fx.io.unsecured.is_empty());
    srv.pump(&mut fx, peer);
    assert!(matches!(srv.s.state(), DtlsState::Closed(_)));

    // A Joiner Entrust that did not come under the KEK is ignored.
    let key = NetworkKey([0x42; 16]);
    let ll_src = Peer::new(peer.addr, 61631);
    let me = ipv6::link_local(&id);
    for link in [LinkSecurity::None, LinkSecurity::Network] {
        fx.j.handle_kek_datagram(fx.now, &mut fx.io, link, &ll_src, &me, &entrust(&key));
    }
    assert!(fx.io.saved.is_none());
    fx.j.handle_kek_datagram(
        fx.now,
        &mut fx.io,
        LinkSecurity::Kek,
        &ll_src,
        &me,
        &entrust(&key),
    );
    let saved = fx.io.saved.take().unwrap();
    assert_eq!(saved.tlvs().network_key(), Ok(key.clone()));
    assert_eq!(saved.tlvs().channel().unwrap().channel, 15);
    assert_eq!(saved.tlvs().pan_id(), Ok(0x1234));
    // The empty 2.04 ACK went back under the KEK.
    let (dst, rsp) = fx.io.kek_sent.pop().unwrap();
    assert_eq!(dst, ll_src);
    let m = Message::parse(&rsp).unwrap();
    assert_eq!(
        (m.ty(), m.code(), m.message_id()),
        (Type::Ack, Code::CHANGED, 0x77)
    );
    assert_eq!(fx.j.state(), JoinerState::Joined);
    // A retransmitted entrust is answered from the cache, not re-applied.
    fx.j.handle_kek_datagram(
        fx.now,
        &mut fx.io,
        LinkSecurity::Kek,
        &ll_src,
        &me,
        &entrust(&key),
    );
    assert!(fx.io.saved.is_none());
    assert_eq!(fx.io.kek_sent.len(), 1);

    fx.advance(CONFIG_EXT_ADDRESS_DELAY);
    assert_eq!(fx.done(), Some(Ok(())));
    assert_eq!(fx.j.state(), JoinerState::Idle);
    assert_ne!(fx.io.ext, Some(id), "MAC address randomized again");
    assert!(fx.io.kek.is_none(), "single-use KEK discarded");
}

/// A wrong PSKd fails the handshake with the first router; the Joiner tries
/// the second and then gives up with a security error.
#[test]
fn wrong_pskd_tries_next_router_then_fails() {
    let mut fx = Fx::new();
    fx.start(PSKD, None).unwrap();
    let id = compute_joiner_id(&SoftCrypto, &EUI64);
    fx.discover(&[(1, -40, steering_for(&id)), (2, -60, steering_for(&id))]);
    for n in [1, 2] {
        let peer = router_peer(n, 1000 + u16::from(n));
        assert_eq!(fx.io.unsecured[0].0, peer);
        let mut srv = Server::new("WR0NGPSKD");
        srv.pump(&mut fx, peer);
        assert!(matches!(srv.s.state(), DtlsState::Closed(_)));
        assert!(fx.io.kek.is_none());
        if n == 1 {
            assert_eq!(fx.j.state(), JoinerState::Connect);
            assert!(fx.done().is_none());
        }
    }
    assert_eq!(fx.done(), Some(Err(Error::Security)));
    assert!(fx.io.unsecure_ports.is_empty());
}

#[test]
fn join_fin_rejected() {
    let mut fx = Fx::new();
    fx.start(PSKD, None).unwrap();
    let id = compute_joiner_id(&SoftCrypto, &EUI64);
    fx.discover(&[(2, -50, steering_for(&id))]);
    let peer = router_peer(2, 1002);
    let mut srv = Server::new(PSKD);
    let app = srv.pump(&mut fx, peer);
    srv.answer(&mut fx, peer, &app[0], State::Reject);
    // As in OpenThread the Joiner still waits for the Joiner Entrust.
    assert_eq!(fx.j.state(), JoinerState::Entrust);
    assert!(fx.done().is_none());
    fx.advance(RESPONSE_TIMEOUT);
    assert_eq!(fx.done(), Some(Err(Error::ResponseTimeout)));
}

/// No Joiner Entrust (or only one without the KEK): response timeout.
#[test]
fn entrust_timeout() {
    let mut fx = Fx::new();
    fx.start(PSKD, None).unwrap();
    let id = compute_joiner_id(&SoftCrypto, &EUI64);
    fx.discover(&[(2, -50, steering_for(&id))]);
    let peer = router_peer(2, 1002);
    let mut srv = Server::new(PSKD);
    let app = srv.pump(&mut fx, peer);
    srv.answer(&mut fx, peer, &app[0], State::Accept);
    fx.advance(RESPONSE_TIMEOUT - Duration::from_millis(1));
    assert!(fx.done().is_none());
    fx.advance(Duration::from_millis(1));
    assert_eq!(fx.done(), Some(Err(Error::ResponseTimeout)));
    assert!(fx.io.saved.is_none());
}

/// Datagrams from anyone but the connected Joiner Router are ignored.
#[test]
fn foreign_datagrams_ignored() {
    let mut fx = Fx::new();
    fx.start(PSKD, None).unwrap();
    let id = compute_joiner_id(&SoftCrypto, &EUI64);
    fx.discover(&[(2, -50, steering_for(&id))]);
    fx.io.unsecured.clear();
    let mut buf = [0u8; 1024];
    // A ClientHello replayed from another address yields nothing.
    let mut client = Session::client(
        SoftCrypto,
        SoftP256,
        PSKD.as_bytes(),
        Config::default(),
        fx.now,
        &mut TestRng(9),
    )
    .unwrap();
    let n = client.poll_transmit(&mut buf).unwrap();
    let other = router_peer(7, 1002);
    fx.j.handle_udp(fx.now, &mut fx.rng, &mut fx.io, &other, &buf[..n]);
    assert!(fx.io.unsecured.is_empty());
    assert_eq!(fx.j.state(), JoinerState::Connect);
}

#[test]
fn discerner_and_stop() {
    let mut fx = Fx::new();
    let d = JoinerDiscerner {
        value: 0xabc,
        length: 12,
    };
    assert_eq!(
        fx.j.set_discerner(
            &mut fx.rng,
            JoinerDiscerner {
                value: 1,
                length: 0
            }
        ),
        Err(Error::InvalidArgs)
    );
    fx.j.set_discerner(&mut fx.rng, d).unwrap();
    let id = *fx.j.id();
    assert!(d.matches(&id));
    fx.start(PSKD, None).unwrap();
    assert_eq!(*fx.j.id(), id, "the discerner-based ID is kept");
    assert_eq!(fx.j.set_discerner(&mut fx.rng, d), Err(Error::InvalidState));
    let mut s = SteeringData::new(16);
    s.add_discerner(&d).unwrap();
    fx.discover(&[(2, -50, s)]);
    assert_eq!(fx.j.state(), JoinerState::Connect);
    assert_eq!(fx.io.ext, Some(id));
    fx.j.stop(&mut fx.io);
    assert_eq!(fx.done(), Some(Err(Error::Abort)));
    assert!(fx.io.unsecure_ports.is_empty());
}
