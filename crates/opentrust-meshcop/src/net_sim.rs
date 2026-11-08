//! Test harness: several MLE cores (`opentrust_mle::sim::Sim`) with one TMF
//! agent, dataset managers and, on the leader, the Network Data store and
//! the commissioner session state per node. TMF datagrams travel over an
//! ideal network (unicast by RLOC / ALOC owner, realm-local multicast to
//! every router); MLE traffic is carried by the MLE simulator.
//!
//! Router IDs are granted through `Sim::upgrade` (the Address Solicit
//! exchange is covered in `opentrust-mesh`).

use core::cell::RefCell;
use core::net::{Ipv6Addr, SocketAddrV6};
use std::rc::Rc;

use opentrust_coap::endpoint::{Event, Request};
use opentrust_coap::tmf::{Agent, Handler, Responder, TmfEnv, TmfRx, UdpSink};
use opentrust_coap::uri::Uri;
use opentrust_core::Result;
use opentrust_core::time::{Duration, Instant};
use opentrust_core::types::{NetworkKey, Prefix64, Rloc16};
use opentrust_mesh::netdata::leader::Leader;
use opentrust_mle::sim::Sim;
use opentrust_mle::test_support::{DatasetBridge, MLP};
use opentrust_mle::tlv::{DeviceMode, Timestamp};
use opentrust_mle::{Mle, Role};
use opentrust_net::ip6::SendInfo;
use opentrust_net::udp::UdpMeta;

use crate::dataset::{Dataset, DatasetType};
use crate::manager::{Configuration, CurrentConfig, DatasetEnv, DatasetEvent, Datasets};
use crate::mgmt::{self, MgmtCommand};
use crate::scan::{
    self, AnnounceBeginServer, EnergyAction, EnergyScanServer, PanIdAction, PanIdConflict,
    PanIdQueryServer,
};

pub type TmfAgent = Agent<4, 16, 4, 512>;

pub struct Datagram {
    pub src: Option<Ipv6Addr>,
    pub dst: Ipv6Addr,
    pub dst_port: u16,
    pub payload: std::vec::Vec<u8>,
}

#[derive(Default)]
pub struct Sink {
    pub out: std::vec::Vec<Datagram>,
}

impl UdpSink for Sink {
    fn send(&mut self, info: &SendInfo, _sp: u16, dp: u16, payload: &[u8]) -> Result<()> {
        self.out.push(Datagram {
            src: info.src,
            dst: info.dst,
            dst_port: dp,
            payload: payload.to_vec(),
        });
        Ok(())
    }
}

pub struct XRng(pub u64);

impl rand_core::TryRng for XRng {
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

struct MlTmfEnv(Prefix64);

impl TmfEnv for MlTmfEnv {
    fn is_mesh_local(&self, a: &Ipv6Addr) -> bool {
        opentrust_net::addr::is_mesh_local(a, &self.0)
    }
}

/// The dataset environment of one node.
pub struct NodeEnv {
    pub cur: CurrentConfig,
    pub role: Role,
    pub session: Option<u16>,
    pub applied: std::vec::Vec<Configuration>,
    pub events: std::vec::Vec<DatasetEvent>,
    pub bumps: u32,
    pub stored: [Option<std::vec::Vec<u8>>; 2],
    /// Security policy received through the Active Dataset, not yet handed
    /// to the MLE core.
    pub policy: Option<crate::tlv::SecurityPolicy>,
}

impl DatasetEnv for NodeEnv {
    fn current(&self) -> CurrentConfig {
        self.cur.clone()
    }
    fn apply(&mut self, cfg: &Configuration) -> Result<()> {
        if let Some(c) = cfg.channel {
            self.cur.channel = c;
        }
        if let Some(p) = cfg.pan_id {
            self.cur.pan_id = p;
        }
        if let Some(k) = &cfg.network_key {
            self.cur.network_key = k.clone();
        }
        if let Some(m) = &cfg.mesh_local_prefix {
            self.cur.mesh_local_prefix = *m;
        }
        if cfg.security_policy.is_some() {
            self.policy = cfg.security_policy;
        }
        self.applied.push(cfg.clone());
        Ok(())
    }
    fn role(&self) -> Role {
        self.role
    }
    fn store(&mut self, t: DatasetType, tlvs: &[u8]) -> Result<()> {
        self.stored[t.index()] = Some(tlvs.to_vec());
        Ok(())
    }
    fn load(&self, t: DatasetType, out: &mut [u8]) -> Option<usize> {
        let s = self.stored[t.index()].as_ref()?;
        out[..s.len()].copy_from_slice(s);
        Some(s.len())
    }
    fn delete(&mut self, t: DatasetType) {
        self.stored[t.index()] = None;
    }
    fn event(&mut self, e: DatasetEvent) {
        self.events.push(e);
    }
    fn commissioning_session_id(&self) -> Option<u16> {
        self.session
    }
    fn network_data_changed(&mut self) {
        self.bumps += 1;
    }
}

pub struct Shared {
    pub ds: Datasets,
    pub env: NodeEnv,
}

struct Bridge(Rc<RefCell<Shared>>);

impl DatasetBridge for Bridge {
    fn active_timestamp(&self) -> Option<Timestamp> {
        self.0.borrow().ds.timestamp(DatasetType::Active)
    }
    fn pending_timestamp(&self) -> Option<Timestamp> {
        self.0.borrow().ds.timestamp(DatasetType::Pending)
    }
    fn dataset(&self, active: bool, now: Instant, out: &mut [u8]) -> Result<usize> {
        let t = if active {
            DatasetType::Active
        } else {
            DatasetType::Pending
        };
        self.0.borrow().ds.mle_dataset(t, now, out)
    }
    fn received(
        &mut self,
        now: Instant,
        active: Option<(Timestamp, Option<&[u8]>)>,
        pending: Option<(Timestamp, Option<&[u8]>)>,
    ) {
        let s = &mut *self.0.borrow_mut();
        s.ds.dataset_received(&mut s.env, now, active, pending);
    }
}

/// Scan servers of a node and the radio environment they observe.
pub struct Servers {
    pub energy: EnergyScanServer,
    pub panq: PanIdQueryServer,
    pub ab: AnnounceBeginServer,
    /// Max RSSI per channel (index = channel).
    pub rf_energy: [i8; 27],
    /// Beacons heard by an active scan: (PAN ID, channel).
    pub rf_beacons: std::vec::Vec<(u16, u8)>,
    /// Energy reports received: (channel mask, energy list).
    pub energy_reports: std::vec::Vec<(u32, std::vec::Vec<u8>)>,
    pub conflicts: std::vec::Vec<PanIdConflict>,
}

pub struct Node {
    pub srv: Servers,
    pub shared: Rc<RefCell<Shared>>,
    pub agent: TmfAgent,
    pub sink: Sink,
    pub rng: XRng,
    /// Network Data store, used while the node is the leader.
    pub nd: Leader<512>,
    pub leader_state: crate::commissioner::LeaderState,
    /// Requests received, by URI id.
    pub rx: std::collections::BTreeMap<u16, u32>,
    pub comm_aloc: Option<u16>,
    /// Number of `/c/dc` notifications received.
    pub dataset_changed_rx: u32,
    /// Responses to MGMT_SET requests of this node.
    pub set_results: std::vec::Vec<mgmt::MgmtResult>,
    /// Responses to other requests: (user, code, payload).
    pub responses: std::vec::Vec<(u32, std::vec::Vec<u8>)>,
    /// Extra handler for URIs the harness does not know (used by tests).
    was_leader: bool,
}

pub struct Net {
    pub sim: Sim,
    pub nodes: std::vec::Vec<Node>,
    /// Node index acting as commissioner (owner of the commissioner ALOC).
    pub commissioner: Option<usize>,
}

fn initial_cur() -> CurrentConfig {
    CurrentConfig {
        channel: 11,
        pan_id: 0xffff,
        mesh_local_prefix: MLP,
        network_key: NetworkKey([0x42; 16]),
    }
}

struct H<'a> {
    shared: &'a mut Shared,
    nd: &'a mut Leader<512>,
    ls: &'a mut crate::commissioner::LeaderState,
    srv: &'a mut Servers,
    rx: &'a mut std::collections::BTreeMap<u16, u32>,
    now: Instant,
    outcomes: std::vec::Vec<mgmt::SetOutcome>,
    dc_rx: &'a mut u32,
    nd_changed: bool,
}

impl Handler for H<'_> {
    fn handle(&mut self, uri: Uri, req: &Request<'_>, rsp: &mut dyn Responder) {
        *self.rx.entry(uri.id()).or_default() += 1;
        self.shared.env.session = crate::commissioner::session_id(self.nd);
        let now = self.now;
        let s = &mut *self.shared;
        match uri {
            Uri::ActiveGet => mgmt::handle_get(&s.ds, now, DatasetType::Active, req, rsp),
            Uri::PendingGet => mgmt::handle_get(&s.ds, now, DatasetType::Pending, req, rsp),
            Uri::ActiveSet | Uri::PendingSet | Uri::ActiveReplace => {
                let (t, cmd) = match uri {
                    Uri::ActiveSet => (DatasetType::Active, MgmtCommand::Set),
                    Uri::ActiveReplace => (DatasetType::Active, MgmtCommand::Replace),
                    _ => (DatasetType::Pending, MgmtCommand::Set),
                };
                let o = mgmt::handle_set(&mut s.ds, &mut s.env, now, t, cmd, req, rsp);
                self.outcomes.push(o);
            }
            Uri::DatasetChanged => {
                *self.dc_rx += 1;
                let _ = rsp.respond(opentrust_coap::message::Code::CHANGED, &[]);
            }
            Uri::LeaderPetition => {
                self.nd_changed |= crate::commissioner::handle_petition(
                    self.ls,
                    self.nd,
                    s.env.role == Role::Leader,
                    &MLP,
                    now,
                    req,
                    rsp,
                );
            }
            Uri::LeaderKeepAlive => {
                self.nd_changed |= crate::commissioner::handle_keep_alive(
                    self.ls,
                    self.nd,
                    s.env.role == Role::Leader,
                    now,
                    req,
                    rsp,
                );
            }
            Uri::CommissionerSet => {
                self.nd_changed |= crate::commissioner::handle_commissioner_set(
                    self.nd,
                    s.env.role == Role::Leader,
                    req,
                    rsp,
                );
            }
            Uri::CommissionerGet => {
                crate::commissioner::handle_commissioner_get(
                    self.nd,
                    s.env.role == Role::Leader,
                    req,
                    rsp,
                );
            }
            Uri::EnergyScan => self.srv.energy.handle_request(now, req, rsp),
            Uri::PanIdQuery => self.srv.panq.handle_request(now, req, rsp),
            Uri::AnnounceBegin => self.srv.ab.handle_request(now, req, rsp),
            Uri::EnergyReport => {
                if let Some(r) = scan::parse_energy_report(req, rsp) {
                    self.srv
                        .energy_reports
                        .push((r.channel_mask, r.energy_list.to_vec()));
                }
            }
            Uri::PanIdConflict => {
                if let Some(c) = scan::parse_pan_id_conflict(req, rsp) {
                    self.srv.conflicts.push(c);
                }
            }
            _ => {}
        }
    }
}

impl Net {
    /// `modes.len()` nodes, none started. Node 0's TMF agent registers the
    /// dataset and commissioner URIs.
    pub fn new(modes: &[DeviceMode]) -> Self {
        let sim = Sim::with_modes(modes);
        let mut nodes = std::vec::Vec::new();
        for i in 0..modes.len() {
            let shared = Rc::new(RefCell::new(Shared {
                ds: Datasets::new(),
                env: NodeEnv {
                    cur: initial_cur(),
                    role: Role::Disabled,
                    session: None,
                    applied: std::vec::Vec::new(),
                    events: std::vec::Vec::new(),
                    bumps: 0,
                    stored: [None, None],
                    policy: None,
                },
            }));
            let mut agent = TmfAgent::new(0x100 * (i as u16 + 1));
            for u in [
                Uri::ActiveGet,
                Uri::PendingGet,
                Uri::ActiveSet,
                Uri::PendingSet,
                Uri::ActiveReplace,
                Uri::DatasetChanged,
                Uri::LeaderPetition,
                Uri::LeaderKeepAlive,
                Uri::CommissionerSet,
                Uri::CommissionerGet,
                Uri::EnergyScan,
                Uri::EnergyReport,
                Uri::PanIdQuery,
                Uri::PanIdConflict,
                Uri::AnnounceBegin,
            ] {
                agent.register(u).unwrap();
            }
            nodes.push(Node {
                shared,
                srv: Servers {
                    energy: EnergyScanServer::new(),
                    panq: PanIdQueryServer::new(),
                    ab: AnnounceBeginServer::new(),
                    rf_energy: [-100; 27],
                    rf_beacons: std::vec::Vec::new(),
                    energy_reports: std::vec::Vec::new(),
                    conflicts: std::vec::Vec::new(),
                },
                agent,
                sink: Sink::default(),
                rng: XRng(0x1357_9bdf ^ (i as u64 + 1)),
                nd: Leader::new(),
                leader_state: crate::commissioner::LeaderState::new(0x1234),
                rx: Default::default(),
                comm_aloc: None,
                dataset_changed_rx: 0,
                set_results: std::vec::Vec::new(),
                responses: std::vec::Vec::new(),
                was_leader: false,
            });
        }
        let mut net = Self {
            sim,
            nodes,
            commissioner: None,
        };
        for i in 0..net.nodes.len() {
            let b = Bridge(net.nodes[i].shared.clone());
            net.sim.nodes[i].env.dataset_bridge = Some(std::boxed::Box::new(b));
        }
        net
    }

    pub fn ftds(n: usize) -> Self {
        Self::new(&std::vec![DeviceMode::new(true, true, true); n])
    }

    pub fn now(&self) -> Instant {
        self.sim.now
    }

    pub fn connect(&mut self, a: usize, b: usize) {
        self.sim.connect(a, b, -60);
    }

    pub fn shared(&self, i: usize) -> core::cell::RefMut<'_, Shared> {
        self.nodes[i].shared.borrow_mut()
    }

    pub fn rloc(&self, i: usize) -> Ipv6Addr {
        MLP.rloc(self.sim.nodes[i].mle.rloc16())
    }

    /// Save `d` as the local Active Dataset of node `i` and start it.
    pub fn start_with(&mut self, i: usize, d: &Dataset) {
        let now = self.sim.now;
        {
            let s = &mut *self.nodes[i].shared.borrow_mut();
            s.ds.save_local(&mut s.env, now, DatasetType::Active, d)
                .unwrap();
        }
        self.sim.start(i);
        self.pump();
    }

    /// Hand the node's applied settings to the MLE core: network key and
    /// routing policy.
    fn sync_node(&mut self, i: usize) {
        let role = self.sim.nodes[i].mle.role();
        let now = self.sim.now;
        let (key, policy) = {
            let mut s = self.nodes[i].shared.borrow_mut();
            s.env.role = role;
            (s.env.cur.network_key.clone(), s.env.policy.take())
        };
        let n = &mut self.sim.nodes[i];
        if n.env.keys.network_key() != &key {
            n.env.keys.set_network_key(key);
        }
        if let Some(p) = policy {
            n.mle
                .set_routing_policy(&mut n.env, now, p.routing_policy());
        }
        // The leader's Network Data store follows the MLE role.
        let is_leader = role == Role::Leader;
        let node = &mut self.nodes[i];
        if is_leader && !node.was_leader {
            let ld = *n.mle.leader_data();
            node.nd.start(ld.data_version, ld.stable_data_version);
            node.leader_state = crate::commissioner::LeaderState::new(0x1234 + i as u16);
        }
        node.was_leader = is_leader;

        // What this node would answer to a Discovery Request.
        let cd: Option<std::vec::Vec<u8>> = if is_leader {
            node.nd.commissioning_data().map(<[u8]>::to_vec)
        } else {
            opentrust_mesh::netdata::NetworkDataView(&n.env.nd)
                .commissioning_data()
                .map(<[u8]>::to_vec)
        };
        n.env.discovery_accept = crate::discovery::joining_allowed(cd.as_deref());
        let ds = node.shared.borrow().ds.read(DatasetType::Active, now);
        n.env.discovery_tlvs.clear();
        if let Some(ds) = ds {
            let mut b = [0u8; 200];
            if let Ok(len) =
                crate::discovery::build_response_from_dataset(&ds, cd.as_deref(), &mut b)
            {
                n.env.discovery_tlvs.extend_from_slice(&b[..len]);
            }
            n.env.mac_ext_pan_id = ds.tlvs().ext_pan_id().ok();
        }
        let cur = node.shared.borrow().env.cur.clone();
        n.env.mac_pan_id = cur.pan_id;
        n.env.mac_channel = cur.channel;
    }

    fn publish_nd(&mut self, i: usize) {
        let now = self.sim.now;
        let n = &mut self.sim.nodes[i];
        let node = &self.nodes[i];
        n.env.provided_nd.clear();
        let _ = n
            .env
            .provided_nd
            .extend_from_slice(node.nd.data().as_bytes());
        let mut b = [0u8; 512];
        let len = node.nd.data().copy_stable(&mut b).unwrap_or(0);
        n.env.provided_nd_stable = heapless::Vec::from_slice(&b[..len]).ok();
        node.nd.publish(&mut n.mle, &mut n.env, now);
    }

    /// Non-leader nodes serve the Network Data they received.
    fn mirror_nd(&mut self, i: usize) {
        let n = &mut self.sim.nodes[i];
        if n.mle.role() == Role::Leader {
            return;
        }
        n.env.provided_nd = n.env.nd.clone();
        n.env.provided_nd_stable = None;
    }

    fn owner_of(&self, dst: &Ipv6Addr) -> Option<usize> {
        let leader_aloc = MLP.aloc(0xfc00).unwrap();
        if *dst == leader_aloc {
            return (0..self.nodes.len()).find(|&i| self.sim.nodes[i].mle.role() == Role::Leader);
        }
        if let Some(c) = self.commissioner
            && let Some(a) = self.nodes[c].comm_aloc
            && *dst == MLP.aloc(a).unwrap()
        {
            return Some(c);
        }
        (0..self.nodes.len()).find(|&i| {
            let r = self.sim.nodes[i].mle.rloc16();
            r != Rloc16::INVALID && self.rloc(i) == *dst
        })
    }

    fn deliver(&mut self, to: usize, src: Ipv6Addr, d: &Datagram) {
        let now = self.sim.now;
        let meta = UdpMeta {
            peer: SocketAddrV6::new(src, 61631, 0, 0),
            local: SocketAddrV6::new(d.dst, d.dst_port, 0, 0),
            hop_limit: 64,
            ecn: 0,
            link_security: true,
        };
        let node = &mut self.nodes[to];
        let mut shared = node.shared.borrow_mut();
        let mut h = H {
            shared: &mut shared,
            nd: &mut node.nd,
            ls: &mut node.leader_state,
            srv: &mut node.srv,
            rx: &mut node.rx,
            now,
            outcomes: std::vec::Vec::new(),
            dc_rx: &mut node.dataset_changed_rx,
            nd_changed: false,
        };
        let env = MlTmfEnv(MLP);
        let r = node
            .agent
            .handle_dispatch(now, &mut node.sink, &env, &meta, &d.payload, &mut h);
        let outcomes = core::mem::take(&mut h.outcomes);
        let nd_changed = h.nd_changed;
        drop(h);
        let bumps = core::mem::take(&mut shared.env.bumps);
        drop(shared);
        match r {
            TmfRx::Response { user, msg, .. } => {
                if let Some(t) = mgmt::set_user_type(user) {
                    let res = mgmt::set_response(&msg);
                    node.set_results.push(res);
                    node.shared.borrow_mut().ds.mgmt_set_finished(now, t);
                } else {
                    node.responses.push((user, msg.payload().to_vec()));
                }
            }
            TmfRx::Failed { user, .. } => {
                if let Some(t) = mgmt::set_user_type(user) {
                    node.set_results
                        .push(mgmt::MgmtResult::Failed(opentrust_core::Error::Abort));
                    node.shared.borrow_mut().ds.mgmt_set_finished(now, t);
                }
            }
            _ => {}
        }
        // Leader: dataset changes bump the Network Data versions; the
        // commissioner session may have changed the Commissioning Data.
        let is_leader = self.sim.nodes[to].mle.role() == Role::Leader;
        if is_leader && (bumps > 0 || nd_changed) {
            if bumps > 0 {
                self.nodes[to].nd.increment_version_and_stable();
            }
            self.publish_nd(to);
        }
        // /c/dc to the commissioner.
        for o in outcomes {
            if let Some(session) = o.notify_commissioner {
                let node = &mut self.nodes[to];
                let rloc = self.sim.nodes[to].mle.rloc16();
                let _ = mgmt::send_dataset_changed(
                    &mut node.agent,
                    now,
                    &mut node.rng,
                    &mut node.sink,
                    &MLP,
                    rloc,
                    session,
                );
            }
        }
    }

    /// Move TMF requests and datasets between the nodes until quiet.
    pub fn pump(&mut self) {
        for _ in 0..100 {
            let mut moved = false;
            self.sim.pump();
            let now = self.sim.now;
            for i in 0..self.nodes.len() {
                self.sync_node(i);
                self.mirror_nd(i);
                // Timers and requests of the dataset managers.
                {
                    let role = self.sim.nodes[i].mle.role();
                    let rloc = self.sim.nodes[i].mle.rloc16();
                    let node = &mut self.nodes[i];
                    {
                        let s = &mut *node.shared.borrow_mut();
                        s.ds.poll(&mut s.env, now);
                    }
                    let sent = {
                        let mut s = node.shared.borrow_mut();
                        mgmt::flush_set_requests(
                            &mut s.ds,
                            &mut node.agent,
                            now,
                            &mut node.rng,
                            &mut node.sink,
                            role,
                            &MLP,
                            rloc,
                        )
                    };
                    moved |= sent > 0;
                    while let Some(ev) = node.agent.poll(now, &mut node.sink) {
                        if let Event::Timeout { user } = ev
                            && let Some(t) = mgmt::set_user_type(user)
                        {
                            node.set_results
                                .push(mgmt::MgmtResult::Failed(opentrust_core::Error::Abort));
                            node.shared.borrow_mut().ds.mgmt_set_finished(now, t);
                        }
                    }
                }
                {
                    let is_leader = self.sim.nodes[i].mle.role() == Role::Leader;
                    let node = &mut self.nodes[i];
                    if node.leader_state.poll(now, is_leader, &mut node.nd) {
                        self.publish_nd(i);
                        moved = true;
                    }
                }
                moved |= self.run_scan_servers(i);
                let bumps = core::mem::take(&mut self.nodes[i].shared.borrow_mut().env.bumps);
                if self.sim.nodes[i].mle.role() == Role::Leader && bumps > 0 {
                    self.nodes[i].nd.increment_version_and_stable();
                    self.publish_nd(i);
                    moved = true;
                }
            }
            for i in 0..self.nodes.len() {
                let out = core::mem::take(&mut self.nodes[i].sink.out);
                for d in out {
                    moved = true;
                    let src = d.src.unwrap_or_else(|| self.rloc(i));
                    let Some(dst) = self.owner_of(&d.dst) else {
                        continue;
                    };
                    self.deliver(dst, src, &d);
                }
            }
            if !moved {
                return;
            }
        }
        panic!("TMF storm");
    }

    /// Drive the scan servers of node `i` against its radio environment.
    fn run_scan_servers(&mut self, i: usize) -> bool {
        let now = self.sim.now;
        let rloc = self.sim.nodes[i].mle.rloc16();
        let node = &mut self.nodes[i];
        let mut moved = false;
        let mut buf = [0u8; 300];
        while let Some(a) = node.srv.energy.poll(now) {
            moved = true;
            match a {
                EnergyAction::Scan { channel, .. } => {
                    let r = node.srv.rf_energy[usize::from(channel)];
                    node.srv.energy.scan_result(now, Some(r));
                    node.srv.energy.scan_result(now, None);
                }
                EnergyAction::Report => {
                    if let Ok((dst, n)) = node.srv.energy.report(&mut buf) {
                        scan::send_energy_report(
                            &mut node.agent,
                            now,
                            &mut node.rng,
                            &mut node.sink,
                            &MLP,
                            rloc,
                            dst,
                            &buf[..n],
                        )
                        .unwrap();
                    }
                }
            }
        }
        if let Some(PanIdAction::ActiveScan { channel_mask }) = node.srv.panq.poll(now) {
            moved = true;
            let beacons = node.srv.rf_beacons.clone();
            for (pan, ch) in beacons {
                if channel_mask & (1 << ch) != 0 {
                    node.srv.panq.scan_result(Some((pan, ch)));
                }
            }
            if node.srv.panq.scan_result(None) {
                let (dst, n) = node.srv.panq.conflict(&mut buf).unwrap();
                scan::send_pan_id_conflict(
                    &mut node.agent,
                    now,
                    &mut node.rng,
                    &mut node.sink,
                    &MLP,
                    rloc,
                    dst,
                    &buf[..n],
                )
                .unwrap();
            }
        }
        if let Some(ch) = node.srv.ab.poll(now) {
            moved = true;
            let n = &mut self.sim.nodes[i];
            let _ = n.mle.send_announce(&mut n.env, ch, false, None);
        }
        moved
    }

    fn next_tmf_deadline(&self) -> Option<Instant> {
        self.nodes
            .iter()
            .flat_map(|n| {
                [
                    n.agent.next_deadline(),
                    n.shared.borrow().ds.next_deadline(),
                    n.leader_state.next_deadline(),
                    n.srv.energy.next_deadline(),
                    n.srv.panq.next_deadline(),
                    n.srv.ab.next_deadline(),
                ]
            })
            .flatten()
            .min()
    }

    /// Advance time by `d`.
    pub fn run(&mut self, d: Duration) {
        let end = self.sim.now + d;
        loop {
            let step = (self.sim.now + Duration::from_millis(50)).min(end);
            let mut t = step;
            if let Some(x) = self.next_tmf_deadline()
                && x > self.sim.now
            {
                t = t.min(x);
            }
            self.sim.run(t - self.sim.now);
            self.pump();
            if self.sim.now >= end {
                break;
            }
        }
    }

    pub fn run_until(&mut self, max: Duration, mut f: impl FnMut(&Self) -> bool) -> bool {
        let end = self.sim.now + max;
        while self.sim.now < end {
            if f(self) {
                return true;
            }
            self.run(Duration::from_millis(100));
        }
        f(self)
    }

    pub fn role(&self, i: usize) -> Role {
        self.sim.nodes[i].mle.role()
    }

    /// Send a hand-made TMF request from node `from` (as the commissioner
    /// or a Thread device) to `dst` and run until quiet.
    pub fn post(&mut self, from: usize, dst: Ipv6Addr, uri: Uri, payload: &[u8]) {
        let now = self.sim.now;
        let node = &mut self.nodes[from];
        let rloc = MLP.rloc(self.sim.nodes[from].mle.rloc16());
        node.agent
            .post(
                now,
                &mut node.rng,
                &mut node.sink,
                dst,
                Some(rloc),
                opentrust_core::message::Priority::Net,
                uri,
                payload,
                Some(0x7e57),
            )
            .unwrap();
        self.pump();
    }

    /// The active Mle of node `i`.
    pub fn mle(&self, i: usize) -> &Mle<4> {
        &self.sim.nodes[i].mle
    }
}
