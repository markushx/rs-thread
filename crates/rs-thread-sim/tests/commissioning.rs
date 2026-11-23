//! Commissioning over the real MAC: a factory-new node joins through a
//! Joiner Router with EC-JPAKE relayed to an on-mesh or external
//! Commissioner and receives the network key in a key ID mode 0 frame.

mod common;

use common::*;
use rs_thread_coap::endpoint::Peer;
use rs_thread_core::crypto::SoftCrypto;
use rs_thread_core::crypto::ecjpake::SoftP256;
use rs_thread_instance::{Event, PsduRxInfo, Role};
use rs_thread_mac::frame::{Frame, KeyIdMode};
use rs_thread_meshcop::border_agent::BorderAgentClient;
use rs_thread_meshcop::commissioner::{
    Commissioner, CommissionerEvent, CommissionerState, JoinerKind,
};
use rs_thread_meshcop::joiner::JoinerConfig;
use rs_thread_sim::{Kind, Network};

const PSKD: &str = "J01NME";
const JOINER: usize = 2;
const BA_PORT: u16 = 49191;

fn vendor() -> JoinerConfig<'static> {
    JoinerConfig {
        vendor_name: "RsThread",
        vendor_model: "Sim",
        vendor_sw_version: "1",
        ..Default::default()
    }
}

/// Leader 0 - router 1 (Joiner Router) - factory-new node 2 (hears only 1).
fn network(seed: u64) -> Network {
    let mut net = Network::new(&[Kind::Router, Kind::Router, Kind::Router], seed);
    net.medium.connect(0, 1, -60);
    net.medium.connect(1, 2, -60);
    let ds = dataset(&mut net);
    start(&mut net, 0, &ds);
    assert!(net.run_until(secs(60), |n| role(n, 0) == Role::Leader));
    start(&mut net, 1, &ds);
    assert!(net.run_until(secs(300), |n| role(n, 1) == Role::Router));
    // Both routers know each other (link established, routes converged).
    let (r0, r1) = (net.node(0).rloc16(), net.node(1).rloc16());
    assert!(net.run_until(secs(600), |n| {
        n.node(0).mle().next_hop_and_path_cost(r1).0.is_some()
            && n.node(1).mle().next_hop_and_path_cost(r0).0.is_some()
    }));
    net.take_events(JOINER);
    net
}

fn network_key(net: &mut Network, i: usize) -> Option<[u8; 16]> {
    let now = net.now;
    net.node(i)
        .active_dataset(now)
        .and_then(|d| d.tlvs().network_key().ok())
        .map(|k| k.0)
}

fn on_mesh_commissioner(net: &mut Network, kind: JoinerKind, pskd: &str) {
    net.with(0, |n, now| {
        n.commissioner_start("rs-thread", None, now).unwrap()
    });
    assert!(net.run_until(secs(30), |n| n.node(0).commissioner_state()
        == CommissionerState::Active));
    net.with(0, |n, now| {
        n.commissioner_add_joiner(kind, pskd, secs(600), now)
            .unwrap();
    });
    // The Steering Data reaches the Joiner Router.
    assert!(net.run_until(secs(30), |n| {
        n.node(1)
            .network_data()
            .commissioning_data()
            .is_some_and(|c| rs_thread_meshcop::discovery::joining_allowed(Some(c)))
    }));
}

fn start_joiner(net: &mut Network, pskd: &str) {
    net.with(JOINER, |n, now| {
        n.ip6_set_enabled(true);
        n.joiner_start(pskd, &vendor(), 1 << 15, now).unwrap();
    });
}

fn joiner_result(net: &mut Network) -> Option<Result<(), rs_thread_core::Error>> {
    net.nodes[JOINER].events.iter().find_map(|e| match e {
        Event::JoinerResult(r) => Some(*r),
        _ => None,
    })
}

/// Key ID mode 0 frames on the air.
fn kek_frames(net: &Network) -> Vec<(usize, Vec<u8>)> {
    net.tx_log
        .iter()
        .filter(|t| {
            Frame::parse_with_fcs(&t.psdu).is_ok_and(|f| {
                f.security_header()
                    .is_some_and(|s| s.key_id_mode() == KeyIdMode::Implicit)
            })
        })
        .map(|t| (t.from, t.psdu.clone()))
        .collect()
}

/// The network key never appears in a frame payload in the clear.
fn assert_key_never_in_clear(net: &Network, key: &[u8; 16]) {
    for t in &net.tx_log {
        assert!(
            !t.psdu.windows(16).any(|w| w == key),
            "network key in the clear in a frame of node {}",
            t.from
        );
    }
}

fn rx_info(len: usize) -> PsduRxInfo {
    PsduRxInfo {
        len,
        channel: 15,
        rssi: Some(-60),
        lqi: Some(200),
        timestamp_us: None,
        ack_security: None,
        acked_with_frame_pending: None,
    }
}

#[test]
fn joiner_joins_through_joiner_router_and_attaches() {
    let mut net = network(81);
    on_mesh_commissioner(&mut net, JoinerKind::Any, PSKD);
    start_joiner(&mut net, PSKD);
    assert!(net.run_until(secs(60), |n| joiner_result(n).is_some()));
    assert_eq!(joiner_result(&mut net), Some(Ok(())));
    // The Joiner Entrust travelled in key ID mode 0 from the Joiner Router.
    let kek = kek_frames(&net);
    assert!(kek.iter().any(|(from, _)| *from == 1), "{kek:?}");
    assert!(kek.iter().any(|(from, _)| *from == JOINER));
    // The new device attaches with the received credentials.
    assert!(net.run_until(secs(120), |n| n.node(JOINER).role().is_attached()));
    let key = network_key(&mut net, 0).unwrap();
    assert_eq!(network_key(&mut net, JOINER), Some(key));
    // The rest of the Active Dataset comes from the parent.
    let lead_ds = net.inst(0).active_dataset(net.now).unwrap();
    let mlp = lead_ds.tlvs().mesh_local_prefix().unwrap();
    assert!(net.run_until(secs(120), |n| {
        let now = n.now;
        n.node(JOINER)
            .active_dataset(now)
            .and_then(|d| d.tlvs().mesh_local_prefix().ok())
            == Some(mlp)
    }));
    let now = net.now;
    let join_ds = net.node(JOINER).active_dataset(now).unwrap();
    assert_eq!(join_ds.tlvs().ext_pan_id(), lead_ds.tlvs().ext_pan_id());
    assert_eq!(join_ds.tlvs().network_name(), lead_ds.tlvs().network_name());
    assert_eq!(join_ds.tlvs().channel(), lead_ds.tlvs().channel());
    assert_eq!(join_ds.tlvs().pan_id(), lead_ds.tlvs().pan_id());
    // It reaches the leader over the mesh by RLOC while still a child.
    let leader = net.inst(0).rloc().unwrap();
    assert!(ping(&mut net, JOINER, leader, 16, 1));
    // A router-capable child is not resolvable by ML-EID (OT address query
    // skips full-function children); once it is a router with converged
    // routes, address queries work in both directions.
    assert!(net.run_until(secs(300), |n| n.node(JOINER).role() == Role::Router));
    let t = net.now + secs(60);
    net.run_until(secs(60), |n| n.now >= t);
    let leader_eid = net.node(0).ml_eid();
    assert!(
        ping(&mut net, JOINER, leader_eid, 16, 3),
        "joiner -> leader"
    );
    let joiner_eid = net.node(JOINER).ml_eid();
    assert!(ping(&mut net, 0, joiner_eid, 16, 3), "leader -> joiner");
    assert_key_never_in_clear(&net, &key);
    let events = net.take_events(0);
    assert!(events.iter().any(|e| matches!(
        e,
        Event::Commissioner(CommissionerEvent::JoinerFinalize(_, true))
    )));

    // A replayed Joiner Entrust frame reaches nobody: the KEK is gone on
    // both sides (the MAC drops it) and the joined node is unaffected.
    let (_, entrust) = kek.iter().find(|(f, _)| *f == 1).unwrap().clone();
    let now = net.now;
    net.node(JOINER)
        .handle_radio_rx(&entrust, &rx_info(entrust.len()), now);
    net.settle();
    assert!(net.node(JOINER).role().is_attached());
    assert_eq!(network_key(&mut net, JOINER), Some(key));
}

#[test]
fn wrong_pskd_fails_and_the_key_stays_off_the_air() {
    let mut net = network(82);
    on_mesh_commissioner(&mut net, JoinerKind::Any, PSKD);
    start_joiner(&mut net, "WR0NGPSKD");
    assert!(net.run_until(secs(120), |n| joiner_result(n).is_some()));
    assert!(matches!(joiner_result(&mut net), Some(Err(_))));
    assert!(kek_frames(&net).is_empty());
    assert_eq!(net.node(JOINER).role(), Role::Disabled);
    let key = network_key(&mut net, 0).unwrap();
    assert_ne!(network_key(&mut net, JOINER), Some(key));
    assert_key_never_in_clear(&net, &key);
}

#[test]
fn key_id_mode_0_frames_without_an_exchange_are_dropped() {
    let mut net = network(83);
    on_mesh_commissioner(&mut net, JoinerKind::Any, PSKD);
    start_joiner(&mut net, PSKD);
    assert!(net.run_until(secs(60), |n| joiner_result(n).is_some()));
    let kek = kek_frames(&net);
    // The Joiner's answer, replayed to the Joiner Router after the
    // exchange: no KEK any more, nothing reaches the commissioning code.
    let (_, answer) = kek.iter().find(|(f, _)| *f == JOINER).unwrap().clone();
    let before = net.inst(1).mac().counters().rx_err_sec + net.inst(1).kek_drops();
    let now = net.now;
    net.node(1)
        .handle_radio_rx(&answer, &rx_info(answer.len()), now);
    net.settle();
    assert_eq!(
        net.inst(1).mac().counters().rx_err_sec + net.inst(1).kek_drops(),
        before + 1
    );
    assert_eq!(net.node(1).role(), Role::Router);
}

/// An external Commissioner of node 0's Border Agent (PSKc or ePSKc).
struct External {
    client: BorderAgentClient<SoftCrypto, SoftP256>,
    comm: Commissioner<SoftCrypto, SoftP256>,
    rng: rs_thread_sim::SimRng,
    up: Vec<Vec<u8>>,
    ephemeral: bool,
}

const EXT_PEER: core::net::Ipv6Addr = core::net::Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0x99);

impl External {
    fn connect(net: &mut Network, epskc: Option<&[u8]>) -> Self {
        let now = net.now;
        let mut rng = rs_thread_sim::SimRng::new(4711);
        let mlp = net
            .node(0)
            .active_dataset(now)
            .unwrap()
            .tlvs()
            .mesh_local_prefix()
            .unwrap();
        let mut up = Vec::new();
        let mut out = |d: &[u8]| {
            up.push(d.to_vec());
            Ok(())
        };
        let peer = Peer::new(EXT_PEER, BA_PORT);
        let client = match epskc {
            Some(k) => BorderAgentClient::connect_ephemeral(
                SoftCrypto,
                SoftP256,
                &rs_thread_meshcop::epskc::EphemeralKey::new(k).unwrap(),
                peer,
                mlp,
                now,
                &mut rng,
                &mut out,
            ),
            None => {
                let pskc = net
                    .node(0)
                    .active_dataset(now)
                    .unwrap()
                    .tlvs()
                    .pskc()
                    .unwrap();
                BorderAgentClient::connect(
                    SoftCrypto, SoftP256, &pskc, peer, mlp, now, &mut rng, &mut out,
                )
            }
        }
        .unwrap();
        Self {
            client,
            comm: Commissioner::new(SoftCrypto, SoftP256),
            rng,
            up,
            ephemeral: epskc.is_some(),
        }
    }

    /// Move datagrams between the external Commissioner and node 0.
    fn pump(&mut self, net: &mut Network) -> bool {
        let now = net.now;
        let peer = Peer::new(EXT_PEER, 5683);
        let mut moved = false;
        for d in core::mem::take(&mut self.up) {
            moved = true;
            net.node(0)
                .border_agent_receive(self.ephemeral, &peer, &d, now);
        }
        net.settle();
        let mut up = Vec::new();
        let mut out = |d: &[u8]| {
            up.push(d.to_vec());
            Ok(())
        };
        while let Some(d) = net.node(0).border_agent_take_datagram() {
            moved = true;
            self.client
                .handle_datagram(now, &mut self.rng, &mut out, &mut self.comm, &d.data);
        }
        self.client.poll(now, &mut out, &mut self.comm);
        self.up.extend(up);
        moved
    }

    fn run_until(
        &mut self,
        net: &mut Network,
        max: u64,
        mut f: impl FnMut(&mut Self, &mut Network) -> bool,
    ) -> bool {
        let end = net.now + secs(max);
        while net.now < end {
            while self.pump(net) {}
            if f(self, net) {
                return true;
            }
            net.run_for(rs_thread_core::time::Duration::from_millis(50));
        }
        false
    }

    fn with<T>(
        &mut self,
        net: &mut Network,
        f: impl FnOnce(
            &mut Commissioner<SoftCrypto, SoftP256>,
            &mut rs_thread_meshcop::border_agent::ExternalTransport<'_, SoftCrypto, SoftP256>,
            rs_thread_core::time::Instant,
            &mut rs_thread_sim::SimRng,
        ) -> T,
    ) -> T {
        let now = net.now;
        let up = &mut self.up;
        let mut out = |d: &[u8]| {
            up.push(d.to_vec());
            Ok(())
        };
        let mut t = rs_thread_meshcop::border_agent::ExternalTransport {
            client: &mut self.client,
            out: &mut out,
        };
        f(&mut self.comm, &mut t, now, &mut self.rng)
    }
}

fn external_commissioner_admits_a_joiner(seed: u64, epskc: Option<&[u8]>) {
    let mut net = network(seed);
    net.with(0, |n, now| {
        n.border_agent_start(BA_PORT).unwrap();
        if let Some(k) = epskc {
            n.border_agent_set_ephemeral_key(k, secs(0), BA_PORT + 1, now)
                .unwrap();
        }
    });
    let mut ext = External::connect(&mut net, epskc);
    assert!(ext.run_until(&mut net, 30, |e, _| matches!(
        e.client.state(),
        rs_thread_dtls::State::Connected
    )));
    ext.with(&mut net, |c, t, now, rng| {
        c.set_id("external").unwrap();
        c.start(now, rng, t).unwrap();
    });
    assert!(ext.run_until(&mut net, 30, |e, _| e.comm.state()
        == CommissionerState::Active));
    let eui64 = net.node(JOINER).ext_address();
    ext.with(&mut net, |c, t, now, _| {
        c.add_joiner(now, t, JoinerKind::Eui64(eui64), PSKD, secs(600))
            .unwrap();
    });
    assert!(ext.run_until(&mut net, 30, |_, n| {
        n.node(1)
            .network_data()
            .commissioning_data()
            .is_some_and(|c| rs_thread_meshcop::discovery::joining_allowed(Some(c)))
    }));
    start_joiner(&mut net, PSKD);
    assert!(ext.run_until(&mut net, 60, |_, n| joiner_result(n).is_some()));
    assert_eq!(joiner_result(&mut net), Some(Ok(())));
    assert!(net.run_until(secs(120), |n| n.node(JOINER).role().is_attached()));
    let key = network_key(&mut net, 0).unwrap();
    assert_eq!(network_key(&mut net, JOINER), Some(key));
}

#[test]
fn external_commissioner_via_border_agent() {
    external_commissioner_admits_a_joiner(84, None);
}

#[test]
fn external_commissioner_via_ephemeral_key() {
    external_commissioner_admits_a_joiner(85, Some(b"123456789"));
}
