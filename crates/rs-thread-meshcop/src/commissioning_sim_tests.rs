//! End-to-end commissioning through the meshcop simulator: Leader (node
//! 0), Joiner Router (router, node 1), on-mesh Commissioner (node 2) and a
//! Joiner (node 3) that only hears node 1 (and node 0 where noted).

use std::boxed::Box;
use std::vec::Vec;

use rs_thread_coap::endpoint::Peer;
use rs_thread_coap::message::{Code, MessageBuilder, Type};
use rs_thread_core::Error;
use rs_thread_core::bytes::Writer;
use rs_thread_core::crypto::SoftCrypto;
use rs_thread_core::crypto::ecjpake::SoftP256;
use rs_thread_core::time::Duration;
use rs_thread_core::types::{ExtAddress, Kek, NetworkKey, Pskc, ipv6};
use rs_thread_mle::Role;
use rs_thread_mle::test_support::MLP;

use crate::border_agent::{BorderAgent, BorderAgentClient};
use crate::commissioner::{Commissioner, CommissionerEvent, CommissionerState, JoinerKind};
use crate::dataset::DatasetType;
use crate::joiner::{JoinerEvent, JoinerState};
use crate::joiner_router::JoinerRouterEvent;
use crate::net_sim::{Net, XRng};
use crate::net_sim_commissioning::{External, Ll};
use crate::secure::LinkSecurity;
use crate::sim_tests::{dataset, secs};
use crate::steering::compute_joiner_id;
use crate::tlv::{Tlvs, WriterExt};

const EUI64: ExtAddress = ExtAddress([0x18, 0xb4, 0x30, 0, 0, 0, 0, 0x42]);
const PSKD: &str = "J01NME";

/// Leader 0, router 1, child 2; node 3 (the Joiner) hears node 1, and
/// node 0 with `hears_leader`.
fn network(hears_leader: bool) -> Net {
    let d = dataset(1, 15, 0x1234, 0x42, "RsThread");
    let mut net = Net::ftds(4);
    for (a, b) in [(0, 1), (0, 2), (1, 2), (3, 1)] {
        net.connect(a, b);
    }
    if hears_leader {
        net.connect(3, 0);
    }
    net.start_with(0, &d);
    assert!(net.run_until(secs(60), |n| n.role(0) == Role::Leader));
    net.sim.start(1);
    assert!(net.run_until(secs(30), |n| n.role(1) == Role::Child));
    net.sim.upgrade(0, 1);
    net.sim.start(2);
    assert!(net.run_until(secs(30), |n| n.role(2) == Role::Child));
    net.run(secs(5));
    assert_eq!(net.role(1), Role::Router);
    net
}

/// Node 2 becomes the on-mesh Commissioner and admits `kind`.
fn commissioner(net: &mut Net, kind: JoinerKind) {
    net.nodes[2].cm.comm = Some(Box::new(Commissioner::new(SoftCrypto, SoftP256)));
    net.with_commissioner(2, |c, t, now, rng| c.start(now, rng, t).unwrap());
    net.run(secs(3));
    assert_eq!(
        net.nodes[2].cm.comm.as_ref().unwrap().state(),
        CommissionerState::Active
    );
    assert_eq!(net.commissioner, Some(2));
    net.with_commissioner(2, |c, t, now, _| {
        c.add_joiner(now, t, kind, PSKD, Duration::from_secs(300))
            .unwrap()
    });
    net.run(secs(3));
}

fn comm_events(net: &mut Net, i: usize) -> Vec<CommissionerEvent> {
    let c = net.nodes[i].cm.comm.as_mut().unwrap();
    core::iter::from_fn(|| c.pop_event()).collect()
}

fn run_until_done(net: &mut Net, j: usize) -> Result<(), Error> {
    assert!(net.run_until(secs(60), |n| n.joiner_done(j).is_some()));
    net.joiner_done(j).unwrap()
}

/// The Joiner node's local Active Dataset network key.
fn joiner_key(net: &Net, j: usize) -> Option<NetworkKey> {
    let now = net.now();
    net.nodes[j]
        .shared
        .borrow()
        .ds
        .read(DatasetType::Active, now)
        .and_then(|d| d.tlvs().network_key().ok())
}

#[test]
fn joiner_joins_through_joiner_router_and_attaches() {
    let mut net = network(false);
    commissioner(&mut net, JoinerKind::Eui64(EUI64));
    // The Commissioning Data now allows joining: node 1 opens the port.
    let cd = net.commissioning_data_of(1).unwrap();
    let sd = Tlvs(&cd).steering_data().unwrap();
    let id = compute_joiner_id(&SoftCrypto, &EUI64);
    assert!(sd.contains_joiner_id(&id));
    assert_eq!(net.nodes[1].cm.jr_port, Some(1000));

    net.start_joiner(3, &EUI64, PSKD).unwrap();
    assert_eq!(run_until_done(&mut net, 3), Ok(()));
    // Credentials: the network key of the network.
    assert_eq!(joiner_key(&net, 3), Some(NetworkKey([0x42; 16])));
    let ev = comm_events(&mut net, 2);
    assert!(ev.contains(&CommissionerEvent::JoinerConnected(id)));
    assert!(ev.contains(&CommissionerEvent::JoinerFinalize(id, true)));
    assert!(
        net.nodes[1]
            .cm
            .jr_events
            .iter()
            .any(|e| matches!(e, JoinerRouterEvent::EntrustAcknowledged(_)))
    );
    // DTLS between Joiner and Joiner Router without link security; the
    // Joiner Entrust and its answer under the KEK (key ID mode 0).
    let joiner_ll = ipv6::link_local(&id);
    let log = &net.cx.log;
    assert!(
        log.iter()
            .any(|d| d.from == 3 && d.dst.port == 1000 && d.link == LinkSecurity::None)
    );
    let entrust: Vec<&Ll> = log.iter().filter(|d| d.dst.port == 61631).collect();
    assert_eq!(entrust.len(), 2, "JOIN_ENT.ntf and its response");
    assert!(entrust.iter().all(|d| d.link == LinkSecurity::Kek));
    assert_eq!(entrust[0].dst.addr, joiner_ll);
    assert_eq!(net.cx.kek_drops, 0);
    // Single-use KEK discarded on both ends.
    assert!(net.nodes[1].cm.kek.is_none());
    assert!(net.nodes[3].cm.kek.is_none());

    // The Joiner attaches with the received credentials.
    net.sim.start(3);
    assert!(net.run_until(secs(60), |n| n.role(3) == Role::Child
        || n.role(3) == Role::Router));
    assert_eq!(
        net.sim.nodes[3].env.keys.network_key(),
        &NetworkKey([0x42; 16])
    );
    // The joined Joiner is removed 20 s after JOIN_FIN.
    net.run(secs(25));
    assert_eq!(net.nodes[2].cm.comm.as_ref().unwrap().joiners().count(), 0);
}

/// A wrong PSKd fails the handshake with both Joiner Routers in range; the
/// Joiner gives up with a security error and never sees the network key.
#[test]
fn wrong_pskd_tries_next_router_then_gives_up() {
    let mut net = network(true);
    commissioner(&mut net, JoinerKind::Eui64(EUI64));
    net.start_joiner(3, &EUI64, "WR0NGPSKD").unwrap();
    assert_eq!(run_until_done(&mut net, 3), Err(Error::Security));
    let routers: std::collections::BTreeSet<_> = net
        .cx
        .log
        .iter()
        .filter(|d| d.from == 3 && d.dst.port == 1000)
        .map(|d| d.dst.addr)
        .collect();
    assert_eq!(routers.len(), 2, "both Joiner Routers tried");
    assert_ne!(joiner_key(&net, 3), Some(NetworkKey([0x42; 16])));
    assert!(!net.cx.log.iter().any(|d| d.link == LinkSecurity::Kek));
    assert!(
        comm_events(&mut net, 2)
            .iter()
            .all(|e| !matches!(e, CommissionerEvent::JoinerFinalize(..)))
    );
}

/// A Joiner that the Steering Data does not name finds no Joiner Router.
#[test]
fn joiner_not_in_steering_data_is_filtered() {
    let mut net = network(false);
    commissioner(
        &mut net,
        JoinerKind::Eui64(ExtAddress([0x18, 0xb4, 0x30, 0, 0, 0, 0, 7])),
    );
    net.start_joiner(3, &EUI64, PSKD).unwrap();
    assert_eq!(run_until_done(&mut net, 3), Err(Error::NotFound));
    assert!(!net.cx.log.iter().any(|d| d.from == 3));
}

/// A Commissioner that stops sending keep-alives loses its session: the
/// Leader resigns it, the Commissioning Data is reduced to the session ID
/// and the Joiner Router closes the Joiner port.
#[test]
fn commissioner_keep_alive_timeout_removes_session() {
    let mut net = network(false);
    commissioner(&mut net, JoinerKind::Any);
    assert!(net.nodes[0].leader_state.is_active());
    net.run(secs(60));
    assert!(net.nodes[0].leader_state.is_active(), "keep-alives sent");
    // The Commissioner goes silent.
    net.nodes[2].cm.comm = None;
    net.run(secs(60));
    assert!(!net.nodes[0].leader_state.is_active());
    let cd = net.commissioning_data_of(1).unwrap();
    assert!(Tlvs(&cd).border_agent_locator().is_err());
    assert!(Tlvs(&cd).steering_data().is_err());
    assert_eq!(net.nodes[1].cm.jr_port, None);
}

/// An external Commissioner connects to the Border Agent on node 1 with
/// the PSKc, petitions, sets the Commissioner Dataset through the UDP
/// proxy, and a Joiner joins through Joiner Router -> Border Agent ->
/// external Commissioner.
#[test]
fn external_commissioner_via_border_agent() {
    let mut net = network(false);
    let mut ba = BorderAgent::new(SoftCrypto, SoftP256, [0xba; 16]);
    ba.set_pskc(Some(Pskc([7; 16])));
    net.nodes[1].cm.ba = Some(Box::new(ba));
    let now = net.now();
    let mut rng = XRng(0xe7);
    let mut up = Vec::new();
    let client = BorderAgentClient::connect(
        SoftCrypto,
        SoftP256,
        &Pskc([7; 16]),
        Peer::new("fd00:e::1".parse().unwrap(), 49191),
        MLP,
        now,
        &mut rng,
        &mut |d: &[u8]| {
            up.push(d.to_vec());
            Ok(())
        },
    )
    .unwrap();
    net.cx.ext = Some(External {
        client: Some(client),
        comm: Commissioner::new(SoftCrypto, SoftP256),
        rng,
        up,
        ba: 1,
        peer: Peer::new("fd00:e::2".parse().unwrap(), 49200),
    });
    net.pump();
    assert!(net.nodes[1].cm.ba.as_ref().unwrap().is_connected());
    net.with_external(|c, t, now, rng| c.start(now, rng, t).unwrap());
    net.run(secs(3));
    let e = net.cx.ext.as_ref().unwrap();
    assert_eq!(e.comm.state(), CommissionerState::Active);
    let session = e.comm.session_id();
    // The Leader names the Border Agent (node 1) in the Commissioning Data.
    let cd = net.commissioning_data_of(0).unwrap();
    assert_eq!(
        Tlvs(&cd).border_agent_locator(),
        Ok(net.sim.nodes[1].mle.rloc16().0)
    );
    assert_eq!(Tlvs(&cd).commissioner_session_id(), Ok(session));
    // Commissioner Dataset (Steering Data) via the UDP proxy.
    net.with_external(|c, t, now, _| {
        c.add_joiner(
            now,
            t,
            JoinerKind::Eui64(EUI64),
            PSKD,
            Duration::from_secs(300),
        )
        .unwrap()
    });
    net.run(secs(3));
    let cd = net.commissioning_data_of(1).unwrap();
    let id = compute_joiner_id(&SoftCrypto, &EUI64);
    assert!(Tlvs(&cd).steering_data().unwrap().contains_joiner_id(&id));
    let e = net.cx.ext.as_mut().unwrap();
    let ev: Vec<_> = core::iter::from_fn(|| e.comm.pop_event()).collect();
    assert!(ev.contains(&CommissionerEvent::MgmtResponse(
        crate::commissioner::USER_COMMISSIONER_SET,
        Some(Code::CHANGED)
    )));

    net.start_joiner(3, &EUI64, PSKD).unwrap();
    assert_eq!(run_until_done(&mut net, 3), Ok(()));
    assert_eq!(joiner_key(&net, 3), Some(NetworkKey([0x42; 16])));
    // Keep-alives through the Border Agent keep the session.
    net.run(secs(80));
    assert!(net.nodes[0].leader_state.is_active());
    assert!(net.nodes[1].cm.ba.as_ref().unwrap().is_connected());
}

/// The Joiner Entrust: a forged one under another KEK fails the (emulated)
/// MAC check, one under the network key or without security is ignored by
/// the Joiner; only the genuine one is applied.
#[test]
fn tampered_joiner_entrust_rejected() {
    let mut net = network(false);
    commissioner(&mut net, JoinerKind::Eui64(EUI64));
    net.start_joiner(3, &EUI64, PSKD).unwrap();
    // Step until JOIN_FIN is accepted (the genuine Joiner Entrust follows
    // 50 ms later).
    for _ in 0..20_000 {
        if net.nodes[3].cm.joiner.as_ref().unwrap().state() == JoinerState::Entrust {
            break;
        }
        net.run(Duration::from_millis(2));
    }
    assert_eq!(
        net.nodes[3].cm.joiner.as_ref().unwrap().state(),
        JoinerState::Entrust
    );
    let id = compute_joiner_id(&SoftCrypto, &EUI64);
    let forged = entrust(&NetworkKey([0x66; 16]));
    let router = Peer::new(ipv6::link_local(&net.sim.nodes[1].env.ext), 61631);
    let joiner = Peer::new(ipv6::link_local(&id), 61631);
    for (link, kek) in [
        (LinkSecurity::Kek, Some(Kek([9; 16]))),
        (LinkSecurity::Network, None),
        (LinkSecurity::None, None),
    ] {
        net.cx.ll.push(Ll {
            from: 1,
            src: router,
            dst: joiner,
            link,
            kek,
            payload: forged.clone(),
        });
    }
    net.pump();
    assert_eq!(net.cx.kek_drops, 1);
    assert_eq!(run_until_done(&mut net, 3), Ok(()));
    assert_eq!(joiner_key(&net, 3), Some(NetworkKey([0x42; 16])));
}

/// A Joiner Entrust before any KEK exists is dropped (MAC: no key; Joiner:
/// not waiting); the Joiner Router ignores answers without a Joiner
/// Entrust in flight.
#[test]
fn joiner_entrust_without_kek_is_dropped() {
    let mut net = network(false);
    commissioner(&mut net, JoinerKind::Eui64(EUI64));
    net.start_joiner(3, &EUI64, PSKD).unwrap();
    net.run(Duration::from_millis(10));
    assert_eq!(
        net.nodes[3].cm.joiner.as_ref().unwrap().state(),
        JoinerState::Discover
    );
    let joiner = Peer::new(ipv6::link_local(&net.sim.nodes[3].env.ext), 61631);
    let router = Peer::new(ipv6::link_local(&net.sim.nodes[1].env.ext), 61631);
    net.cx.ll.push(Ll {
        from: 1,
        src: router,
        dst: joiner,
        link: LinkSecurity::Kek,
        kek: Some(Kek([1; 16])),
        payload: entrust(&NetworkKey([0x66; 16])),
    });
    net.cx.ll.push(Ll {
        from: 1,
        src: router,
        dst: joiner,
        link: LinkSecurity::Network,
        kek: None,
        payload: entrust(&NetworkKey([0x66; 16])),
    });
    net.pump();
    assert_eq!(net.cx.kek_drops, 1);
    assert!(joiner_key(&net, 3).is_none_or(|k| k != NetworkKey([0x66; 16])));
    assert!(net.nodes[1].cm.jr_events.is_empty());
    assert!(
        !net.nodes[3]
            .cm
            .joiner_events
            .iter()
            .any(|e| matches!(e, JoinerEvent::State(JoinerState::Joined)))
    );
}

/// Relay Receive that does not come from a valid Joiner Router exchange:
/// confirmable, or for a Joiner the Commissioner does not know.
#[test]
fn unexpected_relay_rx_is_refused() {
    let mut net = network(false);
    commissioner(&mut net, JoinerKind::Eui64(EUI64));
    let mut b = [0u8; 64];
    let mut w = Writer::new(&mut b);
    w.joiner_udp_port(1000).unwrap();
    w.joiner_iid(&ExtAddress([0x22; 8]).to_iid()).unwrap();
    w.joiner_router_locator(net.sim.nodes[1].mle.rloc16().0)
        .unwrap();
    w.joiner_dtls_encapsulation(&[0x16, 0xfe, 0xff, 0, 0])
        .unwrap();
    let p = w.written().to_vec();
    // CON from the leader.
    let dst = net.rloc(2);
    net.post(0, dst, rs_thread_coap::uri::Uri::RelayRx, &p);
    // NON with an unknown Joiner IID.
    {
        let now = net.now();
        let src = net.rloc(0);
        let node = &mut net.nodes[0];
        node.agent
            .send_request(
                now,
                &mut node.rng,
                &mut node.sink,
                dst,
                &rs_thread_coap::endpoint::SendOpts {
                    src: Some(src),
                    priority: rs_thread_core::message::Priority::Net,
                    multicast_loop: false,
                },
                Type::Non,
                Code::POST,
                None,
                |mut m| {
                    m.uri_path("c/rx")?;
                    m.finish_with_payload(&p)
                },
            )
            .unwrap();
    }
    net.pump();
    assert_eq!(
        net.nodes[2].cm.relay_rx_refused,
        [Error::Drop, Error::NotFound]
    );
    assert!(
        !comm_events(&mut net, 2)
            .iter()
            .any(|e| matches!(e, CommissionerEvent::JoinerStart(..)))
    );
}

/// PSKds with invalid characters are refused by the Joiner and the
/// Commissioner.
#[test]
fn invalid_pskd_characters() {
    let mut net = network(false);
    commissioner(&mut net, JoinerKind::Any);
    for bad in ["J01NMe", "JOINME", "J01-NM", "Q1Z2I3"] {
        assert_eq!(net.start_joiner(3, &EUI64, bad), Err(Error::InvalidArgs));
        net.with_commissioner(2, |c, t, now, _| {
            assert_eq!(
                c.add_joiner(now, t, JoinerKind::Eui64(EUI64), bad, secs(10)),
                Err(Error::InvalidArgs)
            )
        });
    }
}

fn entrust(key: &NetworkKey) -> Vec<u8> {
    let mut p = [0u8; 64];
    let mut w = Writer::new(&mut p);
    w.network_key(key).unwrap();
    let mut b = [0u8; 128];
    let mut m = MessageBuilder::new(&mut b, Type::Con, Code::POST, 0x99, &[7, 7]).unwrap();
    m.uri_path("c/je").unwrap();
    let n = m.finish_with_payload(w.written()).unwrap();
    b[..n].to_vec()
}
