//! Commissioner: petition / keep-alive, Joiner list and Steering Data, and
//! a real Joiner joining through the Relay Receive / Transmit path.

use std::vec::Vec;

use rs_thread_coap::endpoint::Peer;
use rs_thread_coap::message::Code;
use rs_thread_coap::uri::Uri;
use rs_thread_core::bytes::Writer;
use rs_thread_core::crypto::SoftCrypto;
use rs_thread_core::crypto::ecjpake::SoftP256;
use rs_thread_core::time::{Duration, Instant};
use rs_thread_core::types::{ExtAddress, Kek, ipv6};
use rs_thread_core::{Error, Result};
use rs_thread_mle::env::DiscoveryResponseInfo;

use crate::commissioner::{
    Commissioner, CommissionerEvent, CommissionerIo, CommissionerState, JOINER_SESSION_TIMEOUT,
    JoinerKind, MgmtResponse, REMOVE_JOINER_DELAY, USER_COMMISSIONER_GET, USER_KEEP_ALIVE,
    USER_PETITION, is_commissioner_user,
};
use crate::dataset::Dataset;
use crate::discovery::{ResponseContent, build_response_tlv};
use crate::joiner::{Joiner, JoinerConfig, JoinerEvent, JoinerIo, JoinerState};
use crate::steering::{JoinerDiscerner, SteeringData, compute_joiner_id};
use crate::test_rng::TestRng;
use crate::tlv::{State, Tlvs, WriterExt, ty};

const EUI64: ExtAddress = ExtAddress([0x18, 0xb4, 0x30, 0, 0, 0, 0, 1]);
const PSKD: &str = "J01NME";
const ROUTER: ExtAddress = ExtAddress([0x12, 0x34, 0, 0, 0, 0, 0, 2]);
const ROUTER_RLOC: u16 = 0x0800;

#[derive(Default)]
struct CIo {
    requests: Vec<(Uri, Vec<u8>, u32)>,
    relays: Vec<(u16, Vec<u8>)>,
    aloc: Option<u16>,
}

impl CommissionerIo for CIo {
    fn request(&mut self, _now: Instant, uri: Uri, payload: &[u8], user: u32) -> Result<()> {
        assert!(is_commissioner_user(user));
        self.requests.push((uri, payload.to_vec(), user));
        Ok(())
    }
    fn relay_tx(&mut self, _now: Instant, jr: u16, payload: &[u8]) -> Result<()> {
        self.relays.push((jr, payload.to_vec()));
        Ok(())
    }
    fn set_commissioner_aloc(&mut self, aloc16: Option<u16>) {
        self.aloc = aloc16;
    }
}

#[derive(Default)]
struct JIo {
    unsecured: Vec<Vec<u8>>,
    kek: Option<Kek>,
    events: Vec<JoinerEvent>,
}

impl JoinerIo for JIo {
    fn send_discovery_request(&mut self, _c: u8, _p: u16, _t: &[u8]) -> Result<()> {
        Ok(())
    }
    fn set_ext_address(&mut self, _ext: &ExtAddress) {}
    fn set_pan(&mut self, _c: u8, _p: u16) -> Result<()> {
        Ok(())
    }
    fn set_unsecure_port(&mut self, _port: u16, _allow: bool) {}
    fn send_unsecured(&mut self, _sp: u16, _dst: &Peer, payload: &[u8]) -> Result<()> {
        self.unsecured.push(payload.to_vec());
        Ok(())
    }
    fn set_kek(&mut self, kek: Option<&Kek>) {
        self.kek = kek.cloned();
    }
    fn send_kek(&mut self, _sp: u16, _dst: &Peer, _p: &[u8]) -> Result<()> {
        Ok(())
    }
    fn save_dataset(&mut self, _d: &Dataset) {}
    fn event(&mut self, e: JoinerEvent) {
        self.events.push(e);
    }
}

type C = Commissioner<SoftCrypto, SoftP256>;

struct Fx {
    c: C,
    io: CIo,
    rng: TestRng,
    now: Instant,
}

impl Fx {
    fn active() -> Self {
        let mut fx = Self {
            c: Commissioner::new(SoftCrypto, SoftP256),
            io: CIo::default(),
            rng: TestRng(77),
            now: Instant::from_secs(100),
        };
        fx.c.set_id("test").unwrap();
        fx.c.start(fx.now, &mut fx.rng, &mut fx.io).unwrap();
        assert_eq!(fx.c.state(), CommissionerState::Petition);
        let (uri, p, user) = fx.io.requests.pop().unwrap();
        assert_eq!((uri, user), (Uri::LeaderPetition, USER_PETITION));
        assert_eq!(Tlvs(&p).commissioner_id(), Ok("test"));
        fx.respond(USER_PETITION, &accept(Some(0x1235)));
        assert_eq!(fx.c.state(), CommissionerState::Active);
        assert_eq!(fx.c.session_id(), 0x1235);
        assert_eq!(fx.io.aloc, Some(0xfc35));
        fx
    }

    fn respond(&mut self, user: u32, payload: &[u8]) {
        let _ = self
            .c
            .handle_response(self.now, &mut self.io, user, Ok((Code::CHANGED, payload)));
    }

    fn advance(&mut self, d: Duration) {
        self.now += d;
        self.c.poll(self.now, &mut self.io);
    }

    fn events(&mut self) -> Vec<CommissionerEvent> {
        core::iter::from_fn(|| self.c.pop_event()).collect()
    }
}

fn accept(session: Option<u16>) -> Vec<u8> {
    let mut b = [0u8; 16];
    let mut w = Writer::new(&mut b);
    w.state(State::Accept).unwrap();
    if let Some(s) = session {
        w.commissioner_session_id(s).unwrap();
    }
    w.written().to_vec()
}

fn reject() -> Vec<u8> {
    let mut b = [0u8; 4];
    let mut w = Writer::new(&mut b);
    w.state(State::Reject).unwrap();
    w.written().to_vec()
}

fn relay_rx(iid_of: &ExtAddress, records: &[u8]) -> Vec<u8> {
    let mut b = [0u8; 1100];
    let mut w = Writer::new(&mut b);
    w.joiner_udp_port(1000).unwrap();
    w.joiner_iid(&iid_of.to_iid()).unwrap();
    w.joiner_router_locator(ROUTER_RLOC).unwrap();
    w.joiner_dtls_encapsulation(records).unwrap();
    w.written().to_vec()
}

/// A Joiner (PSKd `pskd`) that has discovered `ROUTER` and sent its
/// ClientHello.
fn joiner(
    pskd: &str,
    steering: &SteeringData,
    url: Option<&str>,
) -> (Joiner<SoftCrypto, SoftP256>, JIo, TestRng) {
    let mut j = Joiner::new(SoftCrypto, SoftP256);
    let mut io = JIo::default();
    let mut rng = TestRng(1234);
    let now = Instant::from_secs(100);
    j.start(
        now,
        &mut rng,
        &mut io,
        &EUI64,
        pskd,
        &JoinerConfig {
            provisioning_url: url,
            vendor_name: "V",
            vendor_model: "M",
            vendor_sw_version: "1",
            ..Default::default()
        },
        1 << 15,
    )
    .unwrap();
    j.poll(now, &mut rng, &mut io);
    let ext_pan = rs_thread_core::types::ExtPanId([1; 8]);
    let name = rs_thread_core::types::NetworkName::new("RsThread").unwrap();
    let mut b = [0u8; 128];
    let n = build_response_tlv(
        &ResponseContent {
            ext_pan_id: &ext_pan,
            network_name: &name,
            steering_data: Some(steering),
            joiner_udp_port: 1000,
            native_commissioner: None,
            commercial_commissioning: false,
            domain_name: None,
        },
        &mut b,
    )
    .unwrap();
    j.handle_discovery_response(
        &DiscoveryResponseInfo {
            ext_address: ROUTER,
            pan_id: Some(0x1234),
            channel: Some(15),
            rss: Some(-50),
            lqi: None,
        },
        &b[..n],
    );
    j.poll(now + Duration::from_millis(400), &mut rng, &mut io);
    assert_eq!(j.state(), JoinerState::Connect);
    (j, io, rng)
}

/// Shuttle datagrams Joiner <-> Commissioner through the relay TLVs (the
/// Joiner Router's job). Returns the KEKs seen in Relay Transmits.
fn relay(
    fx: &mut Fx,
    j: &mut Joiner<SoftCrypto, SoftP256>,
    jio: &mut JIo,
    jrng: &mut TestRng,
    id: &ExtAddress,
) -> Vec<Kek> {
    let mut keks = Vec::new();
    let router = Peer::new(ipv6::link_local(&ROUTER), 1000);
    for _ in 0..30 {
        let up = core::mem::take(&mut jio.unsecured);
        let down = core::mem::take(&mut fx.io.relays);
        if up.is_empty() && down.is_empty() {
            break;
        }
        for d in up {
            let _ =
                fx.c.handle_relay_rx(fx.now, &mut fx.rng, &mut fx.io, false, &relay_rx(id, &d));
        }
        for (jr, p) in down {
            assert_eq!(jr, ROUTER_RLOC);
            let t = Tlvs(&p);
            assert_eq!(t.joiner_udp_port(), Ok(1000));
            assert_eq!(t.joiner_iid(), Ok(id.to_iid()));
            assert_eq!(t.joiner_router_locator(), Ok(ROUTER_RLOC));
            if let Ok(k) = t.joiner_router_kek() {
                keks.push(k);
            }
            j.handle_udp(
                fx.now,
                jrng,
                jio,
                &router,
                t.joiner_dtls_encapsulation().unwrap(),
            );
        }
    }
    keks
}

#[test]
fn user_tags() {
    assert!(is_commissioner_user(USER_PETITION));
    assert!(is_commissioner_user(USER_COMMISSIONER_GET));
    assert!(!is_commissioner_user(0xc0aa_0000));
    assert!(!is_commissioner_user(0xc0aa_0006));
    assert!(!is_commissioner_user(0x7e57));
}

#[test]
fn petition_retry_and_failure() {
    let mut fx = Fx {
        c: Commissioner::new(SoftCrypto, SoftP256),
        io: CIo::default(),
        rng: TestRng(1),
        now: Instant::from_secs(1),
    };
    fx.c.start(fx.now, &mut fx.rng, &mut fx.io).unwrap();
    assert_eq!(
        fx.c.start(fx.now, &mut fx.rng, &mut fx.io),
        Err(Error::Already)
    );
    // Timeout: retried after 1 s, then the second failure stops.
    let _ = fx.c.handle_response(
        fx.now,
        &mut fx.io,
        USER_PETITION,
        Err(Error::ResponseTimeout),
    );
    fx.advance(Duration::from_millis(999));
    assert_eq!(fx.io.requests.len(), 1);
    fx.advance(Duration::from_millis(1));
    assert_eq!(fx.io.requests.len(), 2);
    let _ =
        fx.c.handle_response(fx.now, &mut fx.io, USER_PETITION, Err(Error::Abort));
    assert_eq!(fx.c.state(), CommissionerState::Disabled);
    // A Reject stops right away.
    fx.c.start(fx.now, &mut fx.rng, &mut fx.io).unwrap();
    fx.respond(USER_PETITION, &reject());
    assert_eq!(fx.c.state(), CommissionerState::Disabled);
    assert_eq!(fx.io.aloc, None);
}

#[test]
fn keep_alive_and_resign() {
    let mut fx = Fx::active();
    fx.advance(Duration::from_secs(24));
    assert!(fx.io.requests.is_empty());
    fx.advance(Duration::from_secs(1));
    let (uri, p, user) = fx.io.requests.pop().unwrap();
    assert_eq!((uri, user), (Uri::LeaderKeepAlive, USER_KEEP_ALIVE));
    assert_eq!(Tlvs(&p).state(), Ok(State::Accept));
    assert_eq!(Tlvs(&p).commissioner_session_id(), Ok(0x1235));
    fx.respond(USER_KEEP_ALIVE, &accept(None));
    fx.advance(Duration::from_secs(25));
    assert_eq!(fx.io.requests.pop().unwrap().0, Uri::LeaderKeepAlive);
    // The Leader rejects (session gone): stop, ALOC removed.
    fx.respond(USER_KEEP_ALIVE, &reject());
    assert_eq!(fx.c.state(), CommissionerState::Disabled);
    assert_eq!(fx.io.aloc, None);

    // Resign: keep-alive with State Reject after the Joiners are cleared.
    let mut fx = Fx::active();
    fx.c.stop(fx.now, &mut fx.io, true);
    let (uri, p, _) = fx.io.requests.pop().unwrap();
    assert_eq!(uri, Uri::LeaderKeepAlive);
    assert_eq!(Tlvs(&p).state(), Ok(State::Reject));
    assert_eq!(fx.io.requests.pop().unwrap().0, Uri::CommissionerSet);
    assert!(
        fx.events()
            .contains(&CommissionerEvent::State(CommissionerState::Disabled))
    );
}

#[test]
fn joiner_list_and_steering_data() {
    let mut fx = Fx::active();
    assert_eq!(
        fx.c.add_joiner(
            fx.now,
            &mut fx.io,
            JoinerKind::Eui64(EUI64),
            "bad pskd",
            Duration::from_secs(60)
        ),
        Err(Error::InvalidArgs)
    );
    fx.c.add_joiner(
        fx.now,
        &mut fx.io,
        JoinerKind::Eui64(EUI64),
        PSKD,
        Duration::from_secs(60),
    )
    .unwrap();
    let (uri, p, _) = fx.io.requests.pop().unwrap();
    assert_eq!(uri, Uri::CommissionerSet);
    let t = Tlvs(&p);
    assert_eq!(t.commissioner_session_id(), Ok(0x1235));
    let sd = t.steering_data().unwrap();
    assert!(sd.contains_joiner_id(&compute_joiner_id(&SoftCrypto, &EUI64)));
    assert_eq!(sd.len(), 16);
    let d = JoinerDiscerner {
        value: 0x55,
        length: 8,
    };
    fx.c.add_joiner(
        fx.now,
        &mut fx.io,
        JoinerKind::Discerner(d),
        PSKD,
        Duration::from_secs(10),
    )
    .unwrap();
    assert!(fx.c.steering_data().contains_discerner(&d));
    // Two entries (the default): full.
    assert_eq!(
        fx.c.add_joiner(
            fx.now,
            &mut fx.io,
            JoinerKind::Any,
            PSKD,
            Duration::from_secs(10)
        ),
        Err(Error::NoBufs)
    );
    // Replacing an entry is allowed.
    fx.c.add_joiner(
        fx.now,
        &mut fx.io,
        JoinerKind::Eui64(EUI64),
        "N3WPSKD",
        Duration::from_secs(60),
    )
    .unwrap();
    assert_eq!(fx.c.joiners().count(), 2);
    // The discerner entry expires after 10 s.
    fx.io.requests.clear();
    fx.advance(Duration::from_secs(10));
    assert_eq!(fx.c.joiners().count(), 1);
    assert_eq!(fx.io.requests.pop().unwrap().0, Uri::CommissionerSet);
    assert!(
        fx.events()
            .contains(&CommissionerEvent::JoinerRemoved(JoinerKind::Discerner(d)))
    );
    fx.c.remove_joiner(
        fx.now,
        &mut fx.io,
        &JoinerKind::Eui64(EUI64),
        Duration::ZERO,
    )
    .unwrap();
    assert!(fx.c.steering_data().is_empty());
    // "Any": permit all.
    fx.c.add_joiner(
        fx.now,
        &mut fx.io,
        JoinerKind::Any,
        PSKD,
        Duration::from_secs(10),
    )
    .unwrap();
    assert!(fx.c.steering_data().permits_all());
    // MGMT_COMMISSIONER_GET.
    fx.c.send_commissioner_get(fx.now, &mut fx.io, &[ty::STEERING_DATA])
        .unwrap();
    let (uri, p, user) = fx.io.requests.pop().unwrap();
    assert_eq!((uri, user), (Uri::CommissionerGet, USER_COMMISSIONER_GET));
    assert_eq!(Tlvs(&p).get_list(), Ok(&[ty::STEERING_DATA][..]));
    let r = fx.c.handle_response(
        fx.now,
        &mut fx.io,
        USER_COMMISSIONER_GET,
        Ok((Code::CHANGED, &[8, 1, 0xff])),
    );
    assert_eq!(
        r,
        Some(MgmtResponse::CommissionerGet(Ok(&[8, 1, 0xff][..])))
    );
}

/// A real Joiner completes EC-JPAKE with the Commissioner through relay
/// TLVs, JOIN_FIN is accepted and the Relay Transmit with the answer
/// carries the KEK of the session (the Joiner's KEK).
#[test]
fn joiner_through_relay() {
    let mut fx = Fx::active();
    fx.c.set_provisioning_url("https://p").unwrap();
    fx.c.add_joiner(
        fx.now,
        &mut fx.io,
        JoinerKind::Eui64(EUI64),
        PSKD,
        Duration::from_secs(120),
    )
    .unwrap();
    fx.events();
    let id = compute_joiner_id(&SoftCrypto, &EUI64);
    let (mut j, mut jio, mut jrng) = joiner(PSKD, &fx.c.steering_data(), None);
    let keks = relay(&mut fx, &mut j, &mut jio, &mut jrng, &id);
    assert_eq!(j.state(), JoinerState::Entrust);
    assert_eq!(keks.len(), 1);
    assert_eq!(Some(&keks[0]), jio.kek.as_ref());
    let ev = fx.events();
    assert!(ev.contains(&CommissionerEvent::JoinerStart(
        JoinerKind::Eui64(EUI64),
        id
    )));
    assert!(ev.contains(&CommissionerEvent::JoinerConnected(id)));
    assert!(ev.contains(&CommissionerEvent::JoinerFinalize(id, true)));
    // The Joiner closed the session.
    assert!(ev.contains(&CommissionerEvent::JoinerEnd(id)));
    // The joined entry is removed 20 s later.
    fx.io.requests.clear();
    fx.advance(REMOVE_JOINER_DELAY);
    assert_eq!(fx.c.joiners().count(), 0);
    assert_eq!(fx.io.requests.pop().unwrap().0, Uri::CommissionerSet);
}

/// The Provisioning URL must match ours.
#[test]
fn provisioning_url_mismatch_rejected() {
    let mut fx = Fx::active();
    fx.c.add_joiner(
        fx.now,
        &mut fx.io,
        JoinerKind::Any,
        PSKD,
        Duration::from_secs(120),
    )
    .unwrap();
    let id = compute_joiner_id(&SoftCrypto, &EUI64);
    let mut any = SteeringData::new(1);
    any.set_permit_all();
    // Matching URL: accepted, "any" stays in the list.
    fx.c.set_provisioning_url("https://p").unwrap();
    let (mut j, mut jio, mut jrng) = joiner(PSKD, &any, Some("https://p"));
    relay(&mut fx, &mut j, &mut jio, &mut jrng, &id);
    assert_eq!(j.state(), JoinerState::Entrust);
    assert!(
        fx.events()
            .contains(&CommissionerEvent::JoinerFinalize(id, true))
    );
    assert_eq!(fx.c.joiners().count(), 1, "\"any\" is not removed");
    // Another URL: rejected, but the KEK is relayed as well (OT, Thread
    // 1.4.1 8.9.2.2) and the Joiner waits for the Joiner Entrust.
    let (mut j, mut jio, mut jrng) = joiner(PSKD, &any, Some("https://other"));
    let keks = relay(&mut fx, &mut j, &mut jio, &mut jrng, &id);
    assert!(!keks.is_empty(), "KEK relayed with a Reject");
    assert!(
        fx.events()
            .contains(&CommissionerEvent::JoinerFinalize(id, false))
    );
    assert_eq!(j.state(), JoinerState::Entrust);
}

/// Wrong PSKd: the handshake fails, the session ends; an unknown Joiner
/// gets no session; a second Joiner waits while a session runs; the
/// session times out after 30 s.
#[test]
fn joiner_session_failures() {
    let mut fx = Fx::active();
    fx.c.add_joiner(
        fx.now,
        &mut fx.io,
        JoinerKind::Eui64(EUI64),
        PSKD,
        Duration::from_secs(300),
    )
    .unwrap();
    let id = compute_joiner_id(&SoftCrypto, &EUI64);
    let (mut j, mut jio, mut jrng) = joiner("WR0NGPSK", &fx.c.steering_data(), None);
    relay(&mut fx, &mut j, &mut jio, &mut jrng, &id);
    assert!(matches!(
        jio.events.last(),
        Some(JoinerEvent::Done(Err(Error::Security)))
    ));
    let ev = fx.events();
    assert!(ev.contains(&CommissionerEvent::JoinerEnd(id)));
    assert!(!ev.contains(&CommissionerEvent::JoinerConnected(id)));

    // Unknown Joiner ID.
    let stranger = ExtAddress([0x22; 8]);
    assert_eq!(
        fx.c.handle_relay_rx(
            fx.now,
            &mut fx.rng,
            &mut fx.io,
            false,
            &relay_rx(&stranger, b"\x16\xfe\xff")
        ),
        Err(Error::NotFound)
    );
    // Confirmable Relay Receive is dropped.
    assert_eq!(
        fx.c.handle_relay_rx(fx.now, &mut fx.rng, &mut fx.io, true, &relay_rx(&id, b"x")),
        Err(Error::Drop)
    );

    // A session in progress: other Joiners are ignored; timeout after 30 s.
    let (_j, mut jio, _r) = joiner(PSKD, &fx.c.steering_data(), None);
    let hello = jio.unsecured.pop().unwrap();
    fx.c.handle_relay_rx(
        fx.now,
        &mut fx.rng,
        &mut fx.io,
        false,
        &relay_rx(&id, &hello),
    )
    .unwrap();
    fx.c.add_joiner(
        fx.now,
        &mut fx.io,
        JoinerKind::Any,
        PSKD,
        Duration::from_secs(300),
    )
    .unwrap();
    assert_eq!(
        fx.c.handle_relay_rx(
            fx.now,
            &mut fx.rng,
            &mut fx.io,
            false,
            &relay_rx(&stranger, &hello)
        ),
        Err(Error::Busy)
    );
    fx.events();
    fx.advance(JOINER_SESSION_TIMEOUT);
    assert!(fx.events().contains(&CommissionerEvent::JoinerEnd(id)));
}
