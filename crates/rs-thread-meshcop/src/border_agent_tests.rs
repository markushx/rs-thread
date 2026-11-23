//! Border Agent with an external Commissioner (client + Commissioner core)
//! and a real Joiner, the Leader and the Joiner Router scripted by the test.

use core::net::{Ipv6Addr, SocketAddrV6};
use std::vec::Vec;

use rs_thread_coap::endpoint::Peer;
use rs_thread_coap::message::{Code, Message, MessageBuilder, Type};
use rs_thread_coap::uri::Uri;
use rs_thread_core::bytes::Writer;
use rs_thread_core::crypto::SoftCrypto;
use rs_thread_core::crypto::ecjpake::SoftP256;
use rs_thread_core::time::{Duration, Instant};
use rs_thread_core::types::{ExtAddress, Kek, Pskc, ipv6};
use rs_thread_core::{Error, Result};
use rs_thread_mle::test_support::MLP;

use crate::border_agent::{
    BorderAgent, BorderAgentClient, BorderAgentEvent, BorderAgentIo, BorderAgentView, GUARD_TIME,
    KEEP_ALIVE_TIMEOUT, Listener, PROXY_PORT, is_border_agent_user,
};
use crate::border_agent::{EphemeralKeyState, EphemeralKeyStopReason};
use crate::commissioner::{
    Commissioner, CommissionerEvent, CommissionerState, JoinerKind, USER_COMMISSIONER_SET,
};
use crate::epskc::{self, EphemeralKey};
use crate::manager::Datasets;
use crate::test_rng::TestRng;
use crate::tlv::{State, Tlvs, WriterExt, ty};

const PSKC: Pskc = Pskc([0x3a; 16]);
const EPSKC: &[u8] = b"903723159";
const EPSKC_PORT: u16 = 49155;

type Tmf = (Ipv6Addr, Uri, Vec<u8>, bool, Option<u32>);

#[derive(Default)]
struct BaIo {
    to_comm: Vec<Vec<u8>>,
    listeners: Vec<Listener>,
    eph_service: Vec<Option<u16>>,
    tmf: Vec<Tmf>,
    udp: Vec<(SocketAddrV6, SocketAddrV6, Vec<u8>)>,
    aloc: Option<u16>,
}

impl BorderAgentIo for BaIo {
    fn send_to_commissioner(&mut self, l: Listener, _peer: &Peer, data: &[u8]) -> Result<()> {
        self.to_comm.push(data.to_vec());
        self.listeners.push(l);
        Ok(())
    }
    fn ephemeral_service(&mut self, port: Option<u16>) {
        self.eph_service.push(port);
    }
    fn tmf_post(
        &mut self,
        _now: Instant,
        dst: Ipv6Addr,
        uri: Uri,
        payload: &[u8],
        confirmable: bool,
        user: Option<u32>,
    ) -> Result<()> {
        self.tmf
            .push((dst, uri, payload.to_vec(), confirmable, user));
        Ok(())
    }
    fn send_udp(&mut self, src: &SocketAddrV6, dst: &SocketAddrV6, payload: &[u8]) -> Result<()> {
        self.udp.push((*src, *dst, payload.to_vec()));
        Ok(())
    }
    fn set_commissioner_aloc(&mut self, aloc16: Option<u16>) {
        self.aloc = aloc16;
    }
}

type Ba = BorderAgent<SoftCrypto, SoftP256>;
type Client = BorderAgentClient<SoftCrypto, SoftP256>;
type Comm = Commissioner<SoftCrypto, SoftP256>;

struct Fx {
    ba: Ba,
    io: BaIo,
    ds: Datasets,
    cd: Vec<u8>,
    client: Option<Client>,
    comm: Comm,
    up: Vec<Vec<u8>>,
    now: Instant,
    rng: TestRng,
    crng: TestRng,
    peer: Peer,
    listener: Listener,
}

impl Fx {
    fn new() -> Self {
        let mut ba = BorderAgent::new(SoftCrypto, SoftP256, [7; 16]);
        ba.set_pskc(Some(PSKC));
        let mut cd = [0u8; 16];
        let mut w = Writer::new(&mut cd);
        w.commissioner_session_id(9).unwrap();
        let cd = w.written().to_vec();
        Self {
            ba,
            io: BaIo::default(),
            ds: Datasets::new(),
            cd,
            client: None,
            comm: Commissioner::new(SoftCrypto, SoftP256),
            up: Vec::new(),
            now: Instant::from_secs(50),
            rng: TestRng(11),
            crng: TestRng(22),
            peer: Peer::new("fd00:aa::5".parse().unwrap(), 49200),
            listener: Listener::Pskc,
        }
    }

    fn connect(&mut self, pskc: &Pskc) {
        self.listener = Listener::Pskc;
        let up = &mut self.up;
        let c = BorderAgentClient::connect(
            SoftCrypto,
            SoftP256,
            pskc,
            Peer::new("fd00:aa::1".parse().unwrap(), 49191),
            MLP,
            self.now,
            &mut self.crng,
            &mut |d: &[u8]| {
                up.push(d.to_vec());
                Ok(())
            },
        )
        .unwrap();
        self.client = Some(c);
        self.pump();
    }

    /// Connect a new client to the ePSKc port with `key`.
    fn connect_ephemeral(&mut self, key: &[u8]) {
        self.listener = Listener::Ephemeral;
        let up = &mut self.up;
        let c = BorderAgentClient::connect_ephemeral(
            SoftCrypto,
            SoftP256,
            &EphemeralKey::new(key).unwrap(),
            Peer::new("fd00:aa::1".parse().unwrap(), EPSKC_PORT),
            MLP,
            self.now,
            &mut self.crng,
            &mut |d: &[u8]| {
                up.push(d.to_vec());
                Ok(())
            },
        )
        .unwrap();
        self.client = Some(c);
        self.pump();
    }

    /// Move datagrams between client and Border Agent until quiet.
    fn pump(&mut self) {
        for _ in 0..30 {
            let up = core::mem::take(&mut self.up);
            let down = core::mem::take(&mut self.io.to_comm);
            for l in core::mem::take(&mut self.io.listeners) {
                assert_eq!(l, self.listener, "sent from the session's port");
            }
            if up.is_empty() && down.is_empty() {
                return;
            }
            let view = BorderAgentView {
                datasets: &self.ds,
                commissioning_data: Some(&self.cd),
                mesh_local_prefix: MLP,
            };
            for d in up {
                let (now, rng, io, peer) = (self.now, &mut self.rng, &mut self.io, &self.peer);
                match self.listener {
                    Listener::Pskc => self.ba.handle_udp(now, rng, io, &view, peer, &d),
                    Listener::Ephemeral => {
                        self.ba.handle_ephemeral_udp(now, rng, io, &view, peer, &d);
                    }
                }
            }
            if let Some(c) = self.client.as_mut() {
                let upq = &mut self.up;
                for d in down {
                    c.handle_datagram(
                        self.now,
                        &mut self.crng,
                        &mut |x: &[u8]| {
                            upq.push(x.to_vec());
                            Ok(())
                        },
                        &mut self.comm,
                        &d,
                    );
                }
            }
        }
    }

    fn with_transport<T>(
        &mut self,
        f: impl FnOnce(
            &mut Comm,
            &mut crate::border_agent::ExternalTransport<'_, SoftCrypto, SoftP256>,
            Instant,
            &mut TestRng,
        ) -> T,
    ) -> T {
        let up = &mut self.up;
        let mut out = |d: &[u8]| {
            up.push(d.to_vec());
            Ok(())
        };
        let mut t = crate::border_agent::ExternalTransport {
            client: self.client.as_mut().unwrap(),
            out: &mut out,
        };
        let r = f(&mut self.comm, &mut t, self.now, &mut self.crng);
        self.pump();
        r
    }

    fn advance(&mut self, d: Duration) {
        self.now += d;
        self.ba.poll(self.now, &mut self.io);
        if let Some(c) = self.client.as_mut() {
            let upq = &mut self.up;
            c.poll(
                self.now,
                &mut |x: &[u8]| {
                    upq.push(x.to_vec());
                    Ok(())
                },
                &mut self.comm,
            );
        }
        self.pump();
    }

    /// Answer the forwarded TMF request `i` like the Leader.
    fn leader_answers(&mut self, payload: &[u8]) {
        let (dst, _uri, _p, con, user) = self.io.tmf.remove(0);
        assert_eq!(dst, MLP.aloc(0xfc00).unwrap());
        assert!(con);
        let user = user.unwrap();
        assert!(is_border_agent_user(user));
        self.ba
            .handle_tmf_response(self.now, &mut self.io, user, Ok((Code::CHANGED, payload)));
        self.pump();
    }

    fn ba_events(&mut self) -> Vec<BorderAgentEvent> {
        core::iter::from_fn(|| self.ba.pop_event()).collect()
    }

    fn comm_events(&mut self) -> Vec<CommissionerEvent> {
        core::iter::from_fn(|| self.comm.pop_event()).collect()
    }

    /// Connect, petition and get accepted with session 9.
    fn active() -> Self {
        let mut fx = Self::new();
        fx.connect(&PSKC);
        assert!(fx.ba.is_connected());
        fx.with_transport(|c, t, now, rng| c.start(now, rng, t).unwrap());
        let (_, uri, p, _, _) = &fx.io.tmf[0];
        assert_eq!(*uri, Uri::LeaderPetition);
        assert!(Tlvs(p).commissioner_id().is_ok());
        let mut b = [0u8; 16];
        let mut w = Writer::new(&mut b);
        w.state(State::Accept).unwrap();
        w.commissioner_session_id(9).unwrap();
        let a = w.written().to_vec();
        fx.leader_answers(&a);
        assert_eq!(fx.comm.state(), CommissionerState::Active);
        assert_eq!(fx.io.aloc, Some(0xfc31));
        assert_eq!(fx.ba.commissioner_aloc16(), Some(0xfc31));
        assert!(
            fx.ba_events()
                .contains(&BorderAgentEvent::PetitionAccepted(9))
        );
        fx
    }
}

fn accept_body() -> Vec<u8> {
    let mut b = [0u8; 4];
    let mut w = Writer::new(&mut b);
    w.state(State::Accept).unwrap();
    w.written().to_vec()
}

#[test]
fn petition_get_and_proxied_set() {
    let mut fx = Fx::active();
    // MGMT_COMMISSIONER_GET answered by the Border Agent itself.
    fx.with_transport(|c, t, now, _| c.send_commissioner_get(now, t, &[]).unwrap());
    assert!(fx.io.tmf.is_empty(), "answered locally");
    assert!(fx.comm_events().contains(&CommissionerEvent::MgmtResponse(
        crate::commissioner::USER_COMMISSIONER_GET,
        Some(Code::CHANGED)
    )));
    // Adding a Joiner sends /c/cs through the UDP proxy to the Leader ALOC
    // from the Commissioner ALOC.
    fx.with_transport(|c, t, now, _| {
        c.add_joiner(now, t, JoinerKind::Any, "J01NME", Duration::from_secs(120))
            .unwrap()
    });
    let (src, dst, tmf) = fx.io.udp.pop().unwrap();
    assert_eq!(*src.ip(), MLP.aloc(0xfc31).unwrap());
    assert_eq!(src.port(), PROXY_PORT);
    assert_eq!((*dst.ip(), dst.port()), (MLP.aloc(0xfc00).unwrap(), 61631));
    let m = Message::parse(&tmf).unwrap();
    assert!(m.uri_path_is("c/cs"));
    assert_eq!(m.ty(), Type::Con);
    let t = Tlvs(m.payload());
    assert_eq!(t.commissioner_session_id(), Ok(9));
    assert!(t.steering_data().unwrap().permits_all());
    // The Leader's answer comes back as UDP to the ALOC -> /c/ur.
    let mut b = [0u8; 32];
    let n = MessageBuilder::new(&mut b, Type::Ack, Code::CHANGED, m.message_id(), m.token())
        .unwrap()
        .finish_with_payload(&accept_body())
        .unwrap();
    fx.ba
        .handle_proxy_rx(
            fx.now,
            &mut fx.rng,
            &mut fx.io,
            &SocketAddrV6::new(MLP.aloc(0xfc00).unwrap(), 61631, 0, 0),
            PROXY_PORT,
            &b[..n],
        )
        .unwrap();
    fx.pump();
    assert!(fx.comm_events().contains(&CommissionerEvent::MgmtResponse(
        USER_COMMISSIONER_SET,
        Some(Code::CHANGED)
    )));
    // Keep-alives are forwarded and keep the session open past 50 s.
    for _ in 0..3 {
        fx.advance(Duration::from_secs(25));
        let (_, uri, p, _, _) = &fx.io.tmf[0];
        assert_eq!(*uri, Uri::LeaderKeepAlive);
        assert_eq!(Tlvs(p).state(), Ok(State::Accept));
        fx.leader_answers(&accept_body());
    }
    assert!(fx.ba.is_connected());
    assert_eq!(fx.comm.state(), CommissionerState::Active);
}

/// A Joiner joins through Joiner Router (test) -> Border Agent -> external
/// Commissioner; the KEK arrives at the Joiner Router in the Relay
/// Transmit.
#[test]
fn joiner_through_border_agent() {
    use crate::joiner_fx::JoinerFx;
    let mut fx = Fx::active();
    fx.with_transport(|c, t, now, _| {
        c.add_joiner(
            now,
            t,
            JoinerKind::Eui64(ExtAddress([0x18, 0xb4, 0x30, 0, 0, 0, 0, 1])),
            "J01NME",
            Duration::from_secs(120),
        )
        .unwrap()
    });
    let sd = fx.comm.steering_data();
    let mut j = JoinerFx::new("J01NME", &sd);
    let mut kek: Option<Kek> = None;
    for _ in 0..30 {
        let up = core::mem::take(&mut j.io.unsecured);
        let tx: Vec<_> = fx
            .io
            .tmf
            .drain(..)
            .filter(|(_, u, _, _, _)| *u == Uri::RelayTx)
            .collect();
        if up.is_empty() && tx.is_empty() {
            break;
        }
        for d in up {
            let p = j.relay_rx(&d);
            fx.ba
                .handle_relay_rx(fx.now, &mut fx.rng, &mut fx.io, false, &p)
                .unwrap();
            fx.pump();
        }
        for (dst, _, p, con, _) in tx {
            assert!(!con);
            assert_eq!(dst, MLP.rloc(rs_thread_core::types::Rloc16(0x0800)));
            if let Ok(k) = Tlvs(&p).joiner_router_kek() {
                kek = Some(k);
            }
            j.deliver(&p);
        }
    }
    assert_eq!(j.j.state(), crate::joiner::JoinerState::Entrust);
    assert_eq!(kek.as_ref(), j.io.kek.as_ref());
    assert!(kek.is_some());
}

/// Datasets with an Active Dataset whose Security Policy O-bit is 0.
fn datasets_without_obit() -> Datasets {
    use crate::dataset::{Dataset, DatasetType};
    use crate::manager::{Configuration, CurrentConfig, DatasetEnv};
    struct E;
    impl DatasetEnv for E {
        fn current(&self) -> CurrentConfig {
            CurrentConfig {
                channel: 15,
                pan_id: 1,
                mesh_local_prefix: MLP,
                network_key: rs_thread_core::types::NetworkKey([0; 16]),
            }
        }
        fn apply(&mut self, _c: &Configuration) -> Result<()> {
            Ok(())
        }
        fn role(&self) -> rs_thread_mle::Role {
            rs_thread_mle::Role::Router
        }
    }
    let mut ds = Datasets::new();
    let mut d = Dataset::new();
    d.set_network_key(&rs_thread_core::types::NetworkKey([0x42; 16]))
        .unwrap();
    let p = crate::tlv::SecurityPolicy {
        obtain_network_key: false,
        ..Default::default()
    };
    d.set_security_policy(&p).unwrap();
    d.set_timestamp(
        DatasetType::Active,
        &crate::timestamp::Timestamp {
            seconds: 1,
            ticks: 0,
            authoritative: false,
        },
    )
    .unwrap();
    ds.save_local(&mut E, Instant::ZERO, DatasetType::Active, &d)
        .unwrap();
    ds
}

/// Local MGMT_ACTIVE_GET includes the Network Key regardless of the
/// Security Policy (authenticated with the PSKc).
#[test]
fn active_get_ignores_policy() {
    use crate::dataset::DatasetType;
    let ds = datasets_without_obit();
    let mut b = [0u8; 100];
    let n = crate::mgmt::get_payload(&ds, Instant::ZERO, DatasetType::Active, &[], true, &mut b)
        .unwrap();
    assert!(!Tlvs(&b[..n]).contains(ty::NETWORK_KEY));
    let n = crate::mgmt::get_payload(&ds, Instant::ZERO, DatasetType::Active, &[], false, &mut b)
        .unwrap();
    assert!(Tlvs(&b[..n]).contains(ty::NETWORK_KEY));
}

/// No keep-alive: the session is closed after 50 s, the ALOC removed; a
/// new session is refused during the guard time.
#[test]
fn keep_alive_timeout_and_guard_time() {
    let mut fx = Fx::active();
    // The Commissioner stops polling (its keep-alives never come).
    fx.client = None;
    fx.now += KEEP_ALIVE_TIMEOUT;
    fx.ba.poll(fx.now, &mut fx.io);
    assert!(!fx.ba.is_connected());
    assert_eq!(fx.io.aloc, None);
    assert!(
        fx.ba_events()
            .iter()
            .any(|e| matches!(e, BorderAgentEvent::Disconnected(..)))
    );
    // Guard time: a ClientHello is ignored.
    fx.io.to_comm.clear();
    fx.connect(&PSKC);
    assert!(!fx.ba.is_connected());
    fx.now += GUARD_TIME;
    fx.client = None;
    fx.up.clear();
    fx.connect(&PSKC);
    assert!(fx.ba.is_connected());
}

/// Wrong PSKc fails; with one connection attempt allowed, the next try is
/// refused even with the right PSKc.
#[test]
fn wrong_pskc_and_attempt_limit() {
    let mut fx = Fx::new();
    fx.ba.set_max_connection_attempts(1);
    fx.connect(&Pskc([0x3b; 16]));
    assert!(!fx.ba.is_connected());
    assert!(matches!(
        fx.client.as_ref().unwrap().state(),
        rs_thread_dtls::State::Closed(_)
    ));
    let ev = fx.ba_events();
    assert!(ev.contains(&BorderAgentEvent::AttemptsExhausted));
    fx.now += GUARD_TIME;
    fx.connect(&PSKC);
    assert!(!fx.ba.is_connected());
    fx.ba.set_max_connection_attempts(0);
    fx.connect(&PSKC);
    assert!(fx.ba.is_connected());
    let _ = Error::Drop;
}

/// Relay Receive is only forwarded to an active Commissioner; requests of
/// a Candidate that did not petition are not proxied.
#[test]
fn candidate_restrictions() {
    let mut fx = Fx::new();
    assert_eq!(
        fx.ba
            .handle_relay_rx(fx.now, &mut fx.rng, &mut fx.io, false, &[1, 2, 3]),
        Err(Error::InvalidState)
    );
    fx.connect(&PSKC);
    assert_eq!(
        fx.ba
            .handle_relay_rx(fx.now, &mut fx.rng, &mut fx.io, false, &[1, 2, 3]),
        Err(Error::InvalidState)
    );
    assert_eq!(
        fx.ba.handle_proxy_rx(
            fx.now,
            &mut fx.rng,
            &mut fx.io,
            &SocketAddrV6::new(Ipv6Addr::LOCALHOST, 1, 0, 0),
            PROXY_PORT,
            &[1]
        ),
        Err(Error::InvalidState)
    );
    let _ = ipv6::LINK_LOCAL_PREFIX;
}

// ------------------------------------------------------------------ ePSKc

impl Fx {
    fn start_ephemeral(&mut self, timeout: Duration) -> Duration {
        let key = EphemeralKey::new(EPSKC).unwrap();
        self.ba
            .start_ephemeral_key(self.now, &mut self.io, key, timeout, EPSKC_PORT)
            .unwrap()
    }

    fn eph_stopped(&mut self) -> Option<EphemeralKeyStopReason> {
        self.ba_events().into_iter().find_map(|e| match e {
            BorderAgentEvent::EphemeralKeyStopped(r) => Some(r),
            _ => None,
        })
    }

    fn client_closed(&self) -> bool {
        matches!(
            self.client.as_ref().unwrap().state(),
            rs_thread_dtls::State::Closed(_)
        )
    }
}

/// A Candidate connects with the ephemeral key, reads the Active Dataset
/// without petitioning (Network Key included although the O-bit is 0),
/// petitions, and disconnects: the key is gone, a second use fails.
#[test]
fn ephemeral_session_end_to_end() {
    let mut fx = Fx::new();
    fx.ds = datasets_without_obit();
    assert!(fx.ba.ephemeral_key_supported());
    assert_eq!(fx.ba.ephemeral_key_state(), EphemeralKeyState::Stopped);
    assert_eq!(fx.ba.ephemeral_port(), None);
    // Nothing is accepted on the ePSKc port without a key.
    fx.connect_ephemeral(EPSKC);
    assert!(!fx.ba.is_connected());
    assert_eq!(fx.start_ephemeral(Duration::ZERO), epskc::DEFAULT_TIMEOUT);
    assert_eq!(fx.ba.ephemeral_key_state(), EphemeralKeyState::Started);
    assert_eq!(fx.ba.ephemeral_port(), Some(EPSKC_PORT));
    assert_eq!(fx.io.eph_service, [Some(EPSKC_PORT)]);
    // A second key while one is in use is refused.
    assert_eq!(
        fx.ba.start_ephemeral_key(
            fx.now,
            &mut fx.io,
            EphemeralKey::new(b"123456").unwrap(),
            Duration::ZERO,
            EPSKC_PORT
        ),
        Err(Error::InvalidState)
    );

    fx.client = None;
    fx.up.clear();
    fx.connect_ephemeral(EPSKC);
    assert!(fx.ba.is_connected_on(Listener::Ephemeral));
    assert!(!fx.ba.is_connected_on(Listener::Pskc));
    assert_eq!(fx.ba.ephemeral_key_state(), EphemeralKeyState::Connected);
    assert!(
        fx.ba_events()
            .contains(&BorderAgentEvent::EphemeralKeyState(
                EphemeralKeyState::Connected
            ))
    );

    // MGMT_ACTIVE_GET as a Candidate, answered locally.
    fx.with_transport(|c, t, now, _| c.send_mgmt(now, t, Uri::ActiveGet, &[]).unwrap());
    assert!(fx.io.tmf.is_empty());
    assert!(fx.comm_events().contains(&CommissionerEvent::MgmtResponse(
        crate::commissioner::USER_MGMT,
        Some(Code::CHANGED)
    )));

    // Petition: accepted.
    fx.with_transport(|c, t, now, rng| c.start(now, rng, t).unwrap());
    let (_, uri, _, _, _) = &fx.io.tmf[0];
    assert_eq!(*uri, Uri::LeaderPetition);
    let mut b = [0u8; 16];
    let mut w = Writer::new(&mut b);
    w.state(State::Accept).unwrap();
    w.commissioner_session_id(9).unwrap();
    let a = w.written().to_vec();
    fx.leader_answers(&a);
    assert_eq!(fx.comm.state(), CommissionerState::Active);
    assert_eq!(fx.ba.ephemeral_key_state(), EphemeralKeyState::Accepted);
    assert_eq!(fx.io.aloc, Some(0xfc31));

    // The Candidate closes the session: the key is discarded.
    let up = &mut fx.up;
    fx.client.as_mut().unwrap().close(&mut |d: &[u8]| {
        up.push(d.to_vec());
        Ok(())
    });
    fx.pump();
    assert!(!fx.ba.is_connected());
    assert_eq!(fx.io.aloc, None);
    assert_eq!(fx.ba.ephemeral_key_state(), EphemeralKeyState::Stopped);
    assert_eq!(fx.ba.ephemeral_port(), None);
    assert_eq!(fx.io.eph_service, [Some(EPSKC_PORT), None]);
    assert_eq!(
        fx.eph_stopped(),
        Some(EphemeralKeyStopReason::PeerDisconnect)
    );

    // Not usable twice.
    fx.now += GUARD_TIME;
    fx.client = None;
    fx.connect_ephemeral(EPSKC);
    assert!(!fx.ba.is_connected());
    assert_eq!(
        fx.client.as_ref().unwrap().state(),
        rs_thread_dtls::State::Handshaking,
        "no answer on the ePSKc port"
    );
}

/// The key's timeout closes its session and discards it; a key that is
/// never used is discarded at its timeout too.
#[test]
fn ephemeral_timeout_clears_key() {
    let mut fx = Fx::new();
    assert_eq!(
        fx.start_ephemeral(Duration::from_secs(3600)),
        epskc::MAX_TIMEOUT
    );
    fx.ba.stop_ephemeral_key(fx.now, &mut fx.io);
    assert_eq!(fx.eph_stopped(), Some(EphemeralKeyStopReason::Local));

    fx.start_ephemeral(Duration::from_secs(30));
    fx.connect_ephemeral(EPSKC);
    assert!(fx.ba.is_connected());
    fx.advance(Duration::from_secs(29));
    assert!(fx.ba.is_connected());
    assert!(
        fx.ba
            .next_deadline()
            .is_some_and(|d| d <= fx.now + Duration::from_secs(1))
    );
    fx.advance(Duration::from_secs(1));
    assert!(!fx.ba.is_connected());
    assert!(fx.client_closed(), "close_notify sent");
    assert_eq!(fx.ba.ephemeral_key_state(), EphemeralKeyState::Stopped);
    assert_eq!(fx.eph_stopped(), Some(EphemeralKeyStopReason::Timeout));

    // Unused key.
    fx.start_ephemeral(Duration::ZERO);
    fx.client = None;
    fx.advance(epskc::DEFAULT_TIMEOUT);
    assert_eq!(fx.ba.ephemeral_key_state(), EphemeralKeyState::Stopped);
    assert_eq!(fx.eph_stopped(), Some(EphemeralKeyStopReason::Timeout));
    assert_eq!(fx.ba.next_deadline(), None);
    fx.connect_ephemeral(EPSKC);
    assert!(!fx.ba.is_connected());
}

/// A wrong key fails without discarding the key; the right one then
/// connects. The ePSKc does not open the PSKc port.
#[test]
fn ephemeral_wrong_key() {
    let mut fx = Fx::new();
    fx.start_ephemeral(Duration::ZERO);
    fx.connect_ephemeral(b"903723158");
    assert!(!fx.ba.is_connected());
    assert!(fx.client_closed());
    assert_eq!(fx.ba.ephemeral_key_state(), EphemeralKeyState::Started);
    assert_eq!(fx.eph_stopped(), None);
    // The ePSKc on the PSKc port.
    fx.now += GUARD_TIME;
    let up = &mut fx.up;
    let c = BorderAgentClient::connect_ephemeral(
        SoftCrypto,
        SoftP256,
        &EphemeralKey::new(EPSKC).unwrap(),
        Peer::new("fd00:aa::1".parse().unwrap(), 49191),
        MLP,
        fx.now,
        &mut fx.crng,
        &mut |d: &[u8]| {
            up.push(d.to_vec());
            Ok(())
        },
    )
    .unwrap();
    fx.client = Some(c);
    fx.listener = Listener::Pskc;
    fx.pump();
    assert!(!fx.ba.is_connected());
    fx.connect_ephemeral(EPSKC);
    assert!(fx.ba.is_connected_on(Listener::Ephemeral));
    assert_eq!(fx.ba.ephemeral_key_state(), EphemeralKeyState::Connected);
}

/// After `MAX_CONNECTION_ATTEMPTS` failed attempts the key is discarded;
/// the right key no longer connects.
#[test]
fn ephemeral_attempt_limit_clears_key() {
    let mut fx = Fx::new();
    fx.start_ephemeral(Duration::ZERO);
    for i in 0..epskc::MAX_CONNECTION_ATTEMPTS {
        assert_eq!(fx.ba.ephemeral_key_state(), EphemeralKeyState::Started);
        fx.connect_ephemeral(b"000000000");
        assert!(!fx.ba.is_connected());
        if i + 1 < epskc::MAX_CONNECTION_ATTEMPTS {
            assert_eq!(fx.eph_stopped(), None);
        }
        fx.now += GUARD_TIME;
    }
    assert_eq!(fx.ba.ephemeral_key_state(), EphemeralKeyState::Stopped);
    assert_eq!(fx.eph_stopped(), Some(EphemeralKeyStopReason::MaxAttempts));
    assert_eq!(fx.io.eph_service.last(), Some(&None));
    fx.connect_ephemeral(EPSKC);
    assert!(!fx.ba.is_connected());
}

/// Start rules, disabling, and the keep-alive timeout of an ePSKc session.
#[test]
fn ephemeral_start_rules_and_disable() {
    let mut fx = Fx::new();
    let key = || EphemeralKey::new(EPSKC).unwrap();
    assert_eq!(
        fx.ba
            .start_ephemeral_key(fx.now, &mut fx.io, key(), Duration::ZERO, 0),
        Err(Error::InvalidArgs)
    );
    fx.ba.set_ephemeral_key_enabled(fx.now, &mut fx.io, false);
    assert!(!fx.ba.ephemeral_key_supported());
    assert_eq!(
        fx.ba
            .start_ephemeral_key(fx.now, &mut fx.io, key(), Duration::ZERO, EPSKC_PORT),
        Err(Error::InvalidState)
    );
    fx.ba.set_ephemeral_key_enabled(fx.now, &mut fx.io, true);
    fx.start_ephemeral(Duration::ZERO);
    fx.connect_ephemeral(EPSKC);
    assert!(fx.ba.is_connected());
    // Disabling closes the session and discards the key.
    fx.ba.set_ephemeral_key_enabled(fx.now, &mut fx.io, false);
    fx.pump();
    assert!(!fx.ba.is_connected());
    assert!(fx.client_closed());
    assert_eq!(fx.ba.ephemeral_key_state(), EphemeralKeyState::Disabled);
    assert_eq!(fx.eph_stopped(), Some(EphemeralKeyStopReason::Local));

    // No keep-alive: the session (and the key) end after 50 s.
    fx.ba.set_ephemeral_key_enabled(fx.now, &mut fx.io, true);
    fx.now += GUARD_TIME;
    fx.start_ephemeral(Duration::ZERO);
    fx.connect_ephemeral(EPSKC);
    assert!(fx.ba.is_connected());
    fx.client = None;
    fx.now += KEEP_ALIVE_TIMEOUT;
    fx.ba.poll(fx.now, &mut fx.io);
    assert!(!fx.ba.is_connected());
    assert_eq!(
        fx.eph_stopped(),
        Some(EphemeralKeyStopReason::SessionTimeout)
    );
}

/// The PSKc and ePSKc listeners are independent: an active PSKc
/// Commissioner stays while an ePSKc Candidate connects and leaves.
#[test]
fn ephemeral_parallel_to_pskc_session() {
    let mut fx = Fx::active();
    fx.start_ephemeral(Duration::ZERO);
    fx.connect_ephemeral(EPSKC);
    assert!(fx.ba.is_connected_on(Listener::Pskc));
    assert!(fx.ba.is_connected_on(Listener::Ephemeral));
    fx.ba.stop_ephemeral_key(fx.now, &mut fx.io);
    fx.pump();
    assert!(fx.client_closed());
    assert!(!fx.ba.is_connected_on(Listener::Ephemeral));
    assert!(fx.ba.is_connected_on(Listener::Pskc));
    assert_eq!(fx.ba.commissioner_aloc16(), Some(0xfc31));
}
