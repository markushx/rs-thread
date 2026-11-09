//! Test-only mesh simulator: the MLE simulator of `opentrust-mle` (links,
//! deterministic time, MLE message delivery) plus one TMF agent, interface
//! and address cache per node. TMF datagrams travel between nodes over an
//! ideal network (unicast to the node that owns the destination RLOC,
//! realm-local all-routers multicast to every router); frame-level
//! forwarding is tested separately.

#![allow(dead_code, missing_debug_implementations)]

extern crate std;

use core::net::{Ipv6Addr, SocketAddrV6};

use heapless::Vec;
use opentrust_coap::endpoint::Request;
use opentrust_coap::message::{Code, Type};
use opentrust_coap::tmf::{Agent, Handler, Responder, TmfEnv, TmfRx, UdpSink};
use opentrust_coap::uri::Uri;
use opentrust_core::Result;
use opentrust_core::time::{Duration, Instant};
use opentrust_core::types::{Prefix64, Rloc16, ipv6};
use opentrust_mle::env::MleEnv;
use opentrust_mle::sim::Sim;
use opentrust_mle::test_support::MLP;
use opentrust_mle::tlv::DeviceMode;
use opentrust_mle::{Mle, Role};
use opentrust_net::ip6::SendInfo;
use opentrust_net::netif::Netif;
use opentrust_net::resolver::{AddressResolver, Resolution, ResolverEnv, ResolverEvent};
use opentrust_net::udp::UdpMeta;

use opentrust_mac::frame::Address;
use opentrust_net::ip6::Ip6;
use opentrust_net::slaac::{IidParams, Slaac};

use crate::netdata::aloc::{AlocSet, desired_alocs};
use crate::netdata::anycast;
use crate::netdata::consumers::{NetDataContexts, slaac_prefixes};
use crate::netdata::leader::{Changed, Leader};
use crate::netdata::local::LocalData;
use crate::netdata::lookup::Lookup;
use crate::netdata::notifier::{Notifier, NotifierEvent, SyncInput, find_stale_child};
use crate::netdata::publisher::{PublishContext, Publisher, PublisherEvent};
use crate::netdata::server_data::{self, USER_SERVER_DATA};
use crate::netdata::{NetworkData as NetData, NetworkDataView};

use crate::address::{self, AddressAction};
use crate::bbr_sim::{self, BbrNode, FakeBbr, Outcome};
use crate::forwarder::{
    DropReason, FrameSink, MacDest, MeshForwarder, NetworkData, Routing, Rx, SendResult, TxFrame,
};
use crate::router_id::{self, RouterIdOutbox};

pub type TmfAgent = Agent<4, 16, 4, 256>;
pub type SimNetif = Netif<8, 8>;

pub struct Datagram {
    pub src: Option<Ipv6Addr>,
    pub dst: Ipv6Addr,
    pub dst_port: u16,
    pub payload: Vec<u8, 256>,
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
            payload: Vec::from_slice(payload).unwrap(),
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

pub struct MlTmfEnv(pub Prefix64);

impl TmfEnv for MlTmfEnv {
    fn is_mesh_local(&self, a: &Ipv6Addr) -> bool {
        opentrust_net::addr::is_mesh_local(a, &self.0)
    }
}

/// Routing answers for the address cache.
pub struct SimResolverEnv<'a>(pub &'a Mle<4>);

impl ResolverEnv for SimResolverEnv<'_> {
    fn has_route_to(&self, rloc16: Rloc16) -> bool {
        self.0.next_hop_and_path_cost(rloc16).0.is_some()
    }
    fn is_ftd(&self) -> bool {
        true
    }
    fn is_own_rloc16(&self, rloc16: Rloc16) -> bool {
        self.0.rloc16() == rloc16
    }
    fn is_minimal_child(&self, rloc16: Rloc16) -> bool {
        use opentrust_mle::neighbor::StateFilter;
        self.0
            .children()
            .find_by_rloc(rloc16, StateFilter::Valid)
            .is_some_and(|c| !c.neighbor.mode.full_thread_device())
    }
}

pub struct TmfNode {
    pub agent: TmfAgent,
    pub outbox: RouterIdOutbox,
    pub sink: Sink,
    pub rng: XRng,
    pub ip6: Ip6,
    pub resolver: AddressResolver<8>,
    /// Requests received, by URI id.
    pub rx: std::collections::BTreeMap<u16, u32>,
    /// `Resolved` / `ResolutionFailed` events, for the tests.
    pub resolved: std::vec::Vec<ResolverEvent>,
    /// Addresses removed after an Address Error.
    pub errors_seen: u32,
    pub fwd: MeshForwarder<2, 2>,
    pub fsink: FwdSink,
    /// IPv6 datagrams delivered to this node by the forwarder.
    pub delivered: std::vec::Vec<std::vec::Vec<u8>>,
    pub dropped: std::vec::Vec<DropReason>,
    /// Mesh frames forwarded to a next hop.
    pub forwarded: u32,
    /// Indirect list of the MLE environment at the last look.
    pub indirect_seen: std::vec::Vec<Rloc16>,
    /// Network Data as this node has it (the leader's own store on the
    /// leader, the copy received through MLE elsewhere).
    pub netdata: NetData<512>,
    /// Leader store, in use while this node is the leader.
    pub leader: Leader<512>,
    /// Network Data this node serves.
    pub local: LocalData,
    pub notifier: Notifier,
    /// Network Data Publisher; polled with the node's Network Data.
    pub publisher: Publisher<3>,
    /// Publisher events, for the tests.
    pub publisher_events: std::vec::Vec<PublisherEvent>,
    pub alocs: AlocSet,
    pub slaac: Slaac<4>,
    pub commissioner_aloc: Option<u16>,
    was_leader: bool,
    nd_role: Role,
    nd_seen: std::vec::Vec<u8>,
    /// `/a/sd` requests sent.
    pub server_data_sent: u32,
    /// Datagrams this node, as the border router chosen by Network Data
    /// route lookup, would hand to its external interface.
    pub egress: std::vec::Vec<std::vec::Vec<u8>>,
    /// Located devices (`/a/yl` answers).
    pub located: std::vec::Vec<anycast::Located>,
    /// Backbone Router client state (DUA).
    pub bbrn: BbrNode,
}

/// The simulator-wide on-mesh prefix plus the node's Network Data.
pub struct NdAdapter<'a> {
    sim: &'a SimNd,
    lookup: Lookup<'a, Mle<4>>,
}

impl NetworkData for NdAdapter<'_> {
    fn route_lookup(&self, src: &Ipv6Addr, dst: &Ipv6Addr) -> Option<Rloc16> {
        self.lookup.route_lookup(src, dst)
    }
    fn is_on_mesh(&self, addr: &Ipv6Addr) -> bool {
        self.sim.is_on_mesh(addr) || self.lookup.is_on_mesh(addr)
    }
    fn anycast_lookup(&self, aloc16: u16) -> Option<Rloc16> {
        self.lookup.anycast_lookup(aloc16)
    }
}

fn with_routing<R>(
    mle: &Mle<4>,
    ext: opentrust_core::types::ExtAddress,
    ip6: &Ip6,
    netdata: &NetData<512>,
    simnd: &SimNd,
    f: impl FnOnce(&Routing<'_, 4, 8, 8, NetDataContexts<'_>, NdAdapter<'_>>) -> R,
) -> R {
    let view = NetworkDataView(netdata.as_bytes());
    let contexts = NetDataContexts {
        view,
        mesh_local_prefix: *ip6.netif.mesh_local_prefix(),
    };
    let nd = NdAdapter {
        sim: simnd,
        lookup: Lookup::new(view, mle),
    };
    let routing = Routing {
        mle,
        netif: &ip6.netif,
        contexts: &contexts,
        nd: &nd,
        ext,
    };
    f(&routing)
}

/// Network Data of the simulator: one optional on-mesh prefix.
#[derive(Default)]
pub struct SimNd {
    pub on_mesh: Option<Prefix64>,
}

impl NetworkData for SimNd {
    fn is_on_mesh(&self, addr: &Ipv6Addr) -> bool {
        self.on_mesh.is_some_and(|p| p.contains(addr))
    }
}

/// Frames and notifications of the forwarder.
#[derive(Default)]
pub struct FwdSink {
    pub frames: std::vec::Vec<(MacDest, std::vec::Vec<u8>, bool)>,
    /// Frame Pending bit of every indirect frame sent.
    pub pending_log: std::vec::Vec<bool>,
    pub unreachable: std::vec::Vec<std::vec::Vec<u8>>,
    pub loops: std::vec::Vec<(Rloc16, Rloc16)>,
}

impl FrameSink for FwdSink {
    fn transmit(&mut self, f: &TxFrame<'_>) -> Result<()> {
        self.frames.push((f.dst, f.payload.to_vec(), f.indirect));
        if f.indirect {
            self.pending_log.push(f.frame_pending);
        }
        Ok(())
    }
    fn dest_unreachable(&mut self, invoking: &[u8]) {
        self.unreachable.push(invoking.to_vec());
    }
    fn routing_loop(&mut self, from: Rloc16, dest: Rloc16) {
        self.loops.push((from, dest));
    }
}

/// Make the MLE environment serve `data` (full, and its stable subset for
/// sleepy children).
fn refresh_provided(env: &mut opentrust_mle::test_support::TestEnv, data: &NetData<512>) {
    env.provided_nd.clear();
    let _ = env.provided_nd.extend_from_slice(data.as_bytes());
    let mut b = [0u8; 512];
    let n = data.copy_stable(&mut b).unwrap_or(0);
    env.provided_nd_stable = Vec::from_slice(&b[..n]).ok();
}

pub struct MeshSim {
    pub sim: Sim,
    pub tmf: std::vec::Vec<TmfNode>,
    /// Drop datagrams from node `a` to node `b` (indices), for tests.
    pub blocked: std::vec::Vec<(usize, usize)>,
    pub nd: SimNd,
    /// Answers `/n/dr` as the Primary Backbone Router.
    pub fake_bbr: FakeBbr,
    /// Every frame on the air: sender, receiver, payload.
    pub frame_log: std::vec::Vec<(usize, usize, std::vec::Vec<u8>)>,
    next_mid: u16,
}

/// The TMF handler of one node.
struct NodeHandler<'a> {
    env: &'a mut opentrust_mle::test_support::TestEnv,
    mle: &'a mut Mle<4>,
    now: Instant,
    rx: &'a mut std::collections::BTreeMap<u16, u32>,
    netif: &'a mut SimNetif,
    resolver: &'a mut AddressResolver<8>,
    actions: std::vec::Vec<AddressAction>,
    events: std::vec::Vec<ResolverEvent>,
    errors_seen: &'a mut u32,
    leader: &'a mut Leader<512>,
    sd_changed: Changed,
    idx: usize,
    fake_bbr: &'a mut FakeBbr,
    bbrn: &'a mut BbrNode,
}

impl Handler for NodeHandler<'_> {
    fn handle(&mut self, uri: Uri, req: &Request<'_>, rsp: &mut dyn Responder) {
        *self.rx.entry(uri.id()).or_default() += 1;
        let iid = ipv6::iid(&self.env.ml_eid());
        match uri {
            Uri::AddressSolicit => {
                if let Some(h) =
                    router_id::handle_address_solicit(self.mle, self.env, self.now, req, rsp)
                    && let Some(old) = h.stale_rloc16
                {
                    self.resolver.remove_entries_for_rloc16(old);
                }
            }
            Uri::AddressRelease => {
                router_id::handle_address_release(self.mle, self.env, self.now, req, rsp);
            }
            Uri::AddressQuery => {
                if let Some(a) =
                    address::handle_address_query(self.netif, self.mle, &iid, self.now, req)
                {
                    self.actions.push(a);
                }
            }
            Uri::AddressNotify => {
                let events = &mut self.events;
                address::handle_address_notify(self.resolver, self.now, req, rsp, &mut |e| {
                    events.push(e)
                });
            }
            Uri::AddressError => {
                match address::handle_address_error(
                    self.netif,
                    self.mle,
                    &iid,
                    &self.bbrn.bbr,
                    req,
                    rsp,
                ) {
                    address::AddressErrorOutcome::Ignored => {}
                    address::AddressErrorOutcome::DuplicateDomainUnicast => {
                        self.bbrn.duplicate_flag = true
                    }
                    address::AddressErrorOutcome::AddressRemoved => *self.errors_seen += 1,
                    address::AddressErrorOutcome::ChildAddressRemoved(a) => self.actions.push(a),
                }
            }
            Uri::ServerData => {
                if let Some(c) = server_data::handle_server_data(
                    self.leader,
                    self.mle,
                    self.env,
                    self.now,
                    req,
                    rsp,
                ) {
                    self.sd_changed.any |= c.any;
                    self.sd_changed.stable |= c.stable;
                }
            }
            Uri::DuaRegistrationRequest => self.fake_bbr.handle_dua(self.idx, req, rsp),
            Uri::Mlr => self.fake_bbr.handle_mlr(self.idx, req, rsp),
            Uri::DuaRegistrationNotify => {
                if req.msg.ty() == Type::Con {
                    let _ = rsp.respond(Code::CHANGED, &[]);
                }
                self.bbrn.ntf_inbox.push(req.msg.payload().to_vec());
            }
            Uri::AnycastLocate => {
                anycast::handle_anycast_locate(iid, self.mle.rloc16(), req, rsp);
            }
            _ => {}
        }
    }
}

impl MeshSim {
    pub fn new(n: u8) -> Self {
        Self::with_modes(&[DeviceMode::new(true, true, true); 5][..usize::from(n)])
    }

    pub fn with_modes(modes: &[DeviceMode]) -> Self {
        let sim = Sim::with_modes(modes);
        let tmf = (0..modes.len() as u8)
            .map(|i| {
                let mut agent = TmfAgent::new(0x100 * u16::from(i + 1));
                for u in [
                    Uri::AddressSolicit,
                    Uri::AddressRelease,
                    Uri::AddressQuery,
                    Uri::AddressNotify,
                    Uri::AddressError,
                    Uri::ServerData,
                    Uri::AnycastLocate,
                    Uri::DuaRegistrationRequest,
                    Uri::DuaRegistrationNotify,
                    Uri::Mlr,
                ] {
                    agent.register(u).unwrap();
                }
                TmfNode {
                    agent,
                    outbox: RouterIdOutbox::new(),
                    sink: Sink::default(),
                    rng: XRng(0x1357_9bdf ^ u64::from(i + 1)),
                    ip6: Ip6::new(),
                    fwd: MeshForwarder::new(7),
                    fsink: FwdSink::default(),
                    delivered: std::vec::Vec::new(),
                    dropped: std::vec::Vec::new(),
                    forwarded: 0,
                    indirect_seen: std::vec::Vec::new(),
                    resolver: AddressResolver::new(),
                    rx: Default::default(),
                    resolved: std::vec::Vec::new(),
                    errors_seen: 0,
                    netdata: NetData::new(),
                    leader: Leader::new(),
                    local: LocalData::new(),
                    notifier: Notifier::new(),
                    publisher: Publisher::new(),
                    publisher_events: std::vec::Vec::new(),
                    alocs: AlocSet::new(),
                    slaac: Slaac::new(),
                    commissioner_aloc: None,
                    was_leader: false,
                    nd_role: Role::Disabled,
                    nd_seen: std::vec::Vec::new(),
                    server_data_sent: 0,
                    egress: std::vec::Vec::new(),
                    located: std::vec::Vec::new(),
                    bbrn: BbrNode::new(),
                }
            })
            .collect();
        Self {
            sim,
            tmf,
            blocked: std::vec::Vec::new(),
            nd: SimNd::default(),
            fake_bbr: FakeBbr::default(),
            frame_log: std::vec::Vec::new(),
            next_mid: 0x7000,
        }
    }

    pub fn connect(&mut self, a: usize, b: usize, rss: i8) {
        self.sim.connect(a, b, rss);
    }

    pub fn start(&mut self, i: usize) {
        self.sim.start(i);
        self.pump();
    }

    /// Address of node `i`'s RLOC.
    pub fn rloc(&self, i: usize) -> Ipv6Addr {
        MLP.rloc(self.sim.nodes[i].mle.rloc16())
    }

    pub fn ml_eid(&self, i: usize) -> Ipv6Addr {
        self.sim.nodes[i].env.ml_eid()
    }

    /// Bring the interface of node `i` in line with the MLE state.
    fn sync_netif(&mut self, i: usize) {
        let n = &self.sim.nodes[i];
        let nif = &mut self.tmf[i].ip6.netif;
        let _ = nif.set_mesh_local_prefix(MLP);
        let _ = nif.set_mesh_local_eid(&ipv6::iid(&n.env.ml_eid()));
        let r = n.mle.rloc16();
        let _ = nif.set_rloc16((r != Rloc16::INVALID).then_some(r));
    }

    fn owner_of(&self, dst: &Ipv6Addr) -> Option<usize> {
        (0..self.sim.nodes.len())
            .find(|&i| {
                let n = &self.sim.nodes[i];
                n.mle.rloc16() != Rloc16::INVALID && self.rloc(i) == *dst
            })
            // An anycast locator: a node that answers to it.
            .or_else(|| {
                opentrust_net::addr::is_anycast_locator(dst, &MLP)
                    .then(|| {
                        (0..self.sim.nodes.len()).find(|&i| self.tmf[i].ip6.netif.has_unicast(dst))
                    })
                    .flatten()
            })
    }

    /// Replace the Network Data node `i` serves itself and let its
    /// notifier register it.
    pub fn set_local(&mut self, i: usize, f: impl FnOnce(&mut LocalData)) {
        f(&mut self.tmf[i].local);
        self.tmf[i].notifier.event(NotifierEvent::LocalChanged);
        self.pump();
    }

    /// Send an anycast locate request from node `from` (source: `src`).
    pub fn locate(&mut self, from: usize, src: Ipv6Addr, anycast: Ipv6Addr) {
        let now = self.sim.now;
        let t = &mut self.tmf[from];
        anycast::send_anycast_locate(&mut t.agent, now, &mut t.rng, &mut t.sink, src, anycast)
            .unwrap();
        self.pump();
    }

    /// Node `i`'s Network Data.
    pub fn netdata(&self, i: usize) -> NetworkDataView<'_> {
        self.tmf[i].netdata.view()
    }

    /// One round of the Network Data glue of node `i`: the glue a real
    /// device does on the MLE events (the simulator polls the state: the
    /// event buffer of the test environment is small).
    fn netdata_step(&mut self, i: usize) -> bool {
        self.sync_netif(i);
        let now = self.sim.now;
        let mut moved = false;
        let n = &mut self.sim.nodes[i];
        let t = &mut self.tmf[i];
        let role = n.mle.role();
        if role != t.nd_role {
            t.nd_role = role;
            t.notifier.event(NotifierEvent::RoleChanged);
        }
        if role == Role::Leader {
            if !t.was_leader {
                let ld = *n.mle.leader_data();
                t.leader.start(ld.data_version, ld.stable_data_version);
                moved = true;
            }
            let mask = n.mle.router_id_mask();
            let mut ch = t
                .leader
                .remove_stale_router_ids(|id| mask.contains(id), now);
            let c2 = t.leader.handle_timer(now);
            ch.any |= c2.any;
            ch.stable |= c2.stable;
            if ch.any {
                refresh_provided(&mut n.env, t.leader.data());
                t.leader.publish(&mut n.mle, &mut n.env, now);
                moved = true;
            }
            if t.netdata != *t.leader.data() {
                t.netdata = t.leader.data().clone();
                t.notifier.event(NotifierEvent::NetworkDataChanged);
                moved = true;
            }
        } else if n.env.nd_leader.is_some() && t.nd_seen[..] != n.env.nd[..] {
            t.nd_seen = n.env.nd.to_vec();
            if t.netdata.set(&n.env.nd).is_ok() {
                refresh_provided(&mut n.env, &t.netdata);
                n.mle.network_data_updated(&mut n.env, now);
                t.notifier.event(NotifierEvent::NetworkDataChanged);
                moved = true;
            }
        }
        t.was_leader = role == Role::Leader;
        refresh_provided(&mut n.env, &t.netdata);

        let attached = role.is_attached();
        let rloc = n.mle.rloc16();
        let view = t.netdata.view();
        // SLAAC and ALOCs follow Network Data and role.
        t.slaac.set_enabled(true, &mut t.ip6.netif);
        let prefixes = if attached {
            slaac_prefixes::<4>(&view)
        } else {
            heapless::Vec::new()
        };
        let secret = [i as u8 + 1; 32];
        let params = IidParams {
            backend: &opentrust_core::crypto::soft::SoftCrypto,
            secret: &secret,
            network_id: None,
        };
        t.slaac
            .update(&params, &mut t.ip6.netif, &prefixes, None, now);
        let want = desired_alocs(
            role == Role::Leader,
            &view,
            attached.then_some(rloc.0),
            t.commissioner_aloc,
        );
        let _ = t.alocs.update(&mut t.ip6.netif, &want);

        // Published entries follow the Network Data.
        if attached {
            let ctx = PublishContext {
                attached,
                router_or_leader: role.is_router_or_leader(),
                rloc16: rloc,
                leader: view,
                ml_eid: n.env.ml_eid(),
            };
            t.publisher
                .poll(now, &ctx, &mut t.local, &mut t.rng, &mut |e| {
                    t.publisher_events.push(e)
                });
            if t.publisher.take_local_changed() {
                t.notifier.event(NotifierEvent::LocalChanged);
                moved = true;
            }
        }

        // Server Data notifications.
        if attached {
            let mut local_buf = [0u8; 256];
            let ln = t.local.encode(rloc.0, &mut local_buf).unwrap_or(0);
            let input = SyncInput {
                attached,
                router_or_leader: role.is_router_or_leader(),
                expected_to_become_router: false,
                rloc16: rloc,
                local: NetworkDataView(&local_buf[..ln]),
                leader: view,
                stale_child: find_stale_child(&view, &n.mle),
            };
            if let Some(req) = t.notifier.poll(now, &input) {
                let mut payload = [0u8; 300];
                let data = req.include_local.then_some(&local_buf[..ln]);
                let k =
                    server_data::build_server_data(req.old_rloc16, data, &mut payload).unwrap_or(0);
                match server_data::send_server_data(
                    &mut t.agent,
                    now,
                    &mut t.rng,
                    &mut t.sink,
                    &n.mle,
                    &n.env,
                    &payload[..k],
                ) {
                    Ok(()) => t.server_data_sent += 1,
                    Err(_) => t.notifier.response(now, true),
                }
                moved = true;
            }
        }
        moved
    }

    /// Start resolving `eid` at node `i` (queries allowed).
    pub fn resolve(&mut self, i: usize, eid: &Ipv6Addr) -> opentrust_core::Result<Resolution> {
        self.sync_netif(i);
        let now = self.sim.now;
        let mut ev = std::vec::Vec::new();
        let n = &self.sim.nodes[i];
        let t = &mut self.tmf[i];
        let r = t
            .resolver
            .resolve(now, eid, true, &SimResolverEnv(&n.mle), &mut |e| ev.push(e));
        self.handle_events(i, ev);
        r
    }

    fn handle_events(&mut self, i: usize, events: std::vec::Vec<ResolverEvent>) {
        let mut finished = std::vec::Vec::new();
        let now = self.sim.now;
        let n = &self.sim.nodes[i];
        let t = &mut self.tmf[i];
        for e in events {
            if let Some(p) = address::send_resolver_event(
                e,
                &mut t.resolver,
                &mut t.agent,
                now,
                &mut t.rng,
                &mut t.sink,
                n.mle.rloc16(),
                &n.env,
            ) {
                t.resolved.push(p);
                finished.push(p);
            }
        }
        for p in finished {
            self.resolution_finished(i, p);
        }
    }

    fn resolution_finished(&mut self, i: usize, p: ResolverEvent) {
        let (eid, ok) = match p {
            ResolverEvent::Resolved { eid } => (eid, true),
            ResolverEvent::ResolutionFailed { eid } => (eid, false),
            _ => return,
        };
        let now = self.sim.now;
        let mut events = std::vec::Vec::new();
        {
            let n = &self.sim.nodes[i];
            let TmfNode {
                fwd,
                resolver,
                fsink,
                ip6,
                netdata,
                ..
            } = &mut self.tmf[i];
            with_routing(&n.mle, n.env.ext, ip6, netdata, &self.nd, |routing| {
                fwd.handle_resolved(
                    now,
                    &eid,
                    ok,
                    routing,
                    resolver,
                    &mut |e| events.push(e),
                    fsink,
                );
            });
        }
        self.handle_events(i, events);
    }

    /// Build the destination unreachable errors the forwarder asked for
    /// and send them.
    fn flush_unreachable(&mut self, i: usize) {
        let now = self.sim.now;
        let pending = core::mem::take(&mut self.tmf[i].fsink.unreachable);
        for inv in pending {
            let mut out = [0u8; 256];
            let t = &mut self.tmf[i];
            if let Ok(n) = t.ip6.build_error(
                now,
                &inv,
                (
                    opentrust_net::icmp6::TYPE_DST_UNREACH,
                    opentrust_net::icmp6::CODE_DST_UNREACH_NO_ROUTE,
                    0,
                ),
                &mut out,
            ) {
                self.send_ip6(i, &out[..n]);
            }
        }
    }

    /// Hand an IPv6 datagram to node `i`'s forwarder.
    pub fn send_ip6(&mut self, i: usize, datagram: &[u8]) -> SendResult {
        self.sync_netif(i);
        let now = self.sim.now;
        let mut events = std::vec::Vec::new();
        let r = {
            let n = &self.sim.nodes[i];
            let TmfNode {
                fwd,
                resolver,
                fsink,
                ip6,
                netdata,
                ..
            } = &mut self.tmf[i];
            with_routing(&n.mle, n.env.ext, ip6, netdata, &self.nd, |routing| {
                fwd.send_datagram(
                    now,
                    datagram,
                    true,
                    routing,
                    resolver,
                    &mut |e| events.push(e),
                    fsink,
                )
            })
        };
        if let SendResult::Dropped(d) = r {
            self.tmf[i].dropped.push(d);
        }
        self.handle_events(i, events);
        self.pump();
        r
    }

    /// A UDP datagram from node `from` (source: its ML-EID) to `dst`.
    pub fn send_udp(&mut self, from: usize, dst: Ipv6Addr, payload: &[u8]) -> SendResult {
        let src = self.ml_eid(from);
        self.send_udp_from(from, src, dst, payload)
    }

    /// Like [`MeshSim::send_udp`] with an explicit source address.
    pub fn send_udp_from(
        &mut self,
        from: usize,
        src: Ipv6Addr,
        dst: Ipv6Addr,
        payload: &[u8],
    ) -> SendResult {
        use opentrust_lowpan::ip6::{Ipv6Header, UdpHeader};
        let mut buf = [0u8; 256];
        let mut h = Ipv6Header::new(17, 64, src, dst);
        h.payload_len = (UdpHeader::LEN + payload.len()) as u16;
        h.write(&mut buf).unwrap();
        let udp = UdpHeader {
            src_port: 1234,
            dst_port: 5678,
            length: h.payload_len,
            checksum: 0xbeef,
        };
        udp.write(&mut buf[40..]).unwrap();
        buf[48..48 + payload.len()].copy_from_slice(payload);
        self.send_ip6(from, &buf[..48 + payload.len()])
    }

    /// Deliver the frames of all forwarders over the link matrix.
    fn pump_frames(&mut self) -> bool {
        let mut moved = false;
        for i in 0..self.tmf.len() {
            let out = core::mem::take(&mut self.tmf[i].fsink.frames);
            for (dst, payload, indirect) in out {
                moved = true;
                let _ = indirect;
                for j in 0..self.tmf.len() {
                    if j == i || self.sim.link(i, j).is_none() || self.blocked.contains(&(i, j)) {
                        continue;
                    }
                    let for_j = match dst {
                        MacDest::Broadcast => true,
                        MacDest::Short(r) => self.sim.nodes[j].mle.rloc16() == r,
                        MacDest::Extended(e) => self.sim.nodes[j].env.ext == e,
                    };
                    let asleep = !self.sim.nodes[j].env.rx_on;
                    if for_j && (indirect || !asleep) {
                        self.frame_log.push((i, j, payload.clone()));
                        self.deliver_frame(i, j, dst, &payload);
                    }
                }
            }
            if !self.tmf[i].fsink.unreachable.is_empty() {
                moved = true;
                self.flush_unreachable(i);
            }
            let loops = core::mem::take(&mut self.tmf[i].fsink.loops);
            for (from, dest) in loops {
                let now = self.sim.now;
                let n = &mut self.sim.nodes[i];
                n.mle.resolve_routing_loop(&mut n.env, now, from, dest);
            }
        }
        moved
    }

    /// A data poll of sleepy node `child` to its parent: the Frame Pending
    /// bit of the ACK and what the parent sent in answer.
    pub fn data_poll(
        &mut self,
        child: usize,
    ) -> (bool, opentrust_core::Result<crate::indirect::PollOutcome>) {
        let (_, parent_rloc) = self.sim.nodes[child].env.parent.expect("attached");
        let p = (0..self.tmf.len())
            .find(|&i| self.sim.nodes[i].mle.rloc16() == parent_rloc)
            .expect("parent node");
        let child_rloc = Address::Short(self.sim.nodes[child].mle.rloc16().into());
        self.sync_netif(p);
        let (pending, outcome) = {
            let n = &self.sim.nodes[p];
            let TmfNode {
                fwd,
                fsink,
                ip6,
                netdata,
                ..
            } = &mut self.tmf[p];
            with_routing(&n.mle, n.env.ext, ip6, netdata, &self.nd, |routing| {
                let pending = fwd.data_poll_frame_pending(&child_rloc, routing);
                (pending, fwd.handle_data_poll(&child_rloc, routing, fsink))
            })
        };
        while let Some(c) = self.tmf[p].fwd.take_child_message_sent() {
            self.sim.nodes[p].mle.child_message_sent(c);
        }
        self.pump();
        (pending, outcome)
    }

    /// Deliver a hand-made frame as if `from` had sent it to `to`.
    pub fn inject_frame(
        &mut self,
        from: usize,
        to: usize,
        dst: MacDest,
        payload: &[u8],
        link_security: bool,
    ) {
        self.deliver_frame_sec(from, to, dst, payload, link_security);
        self.pump();
    }

    fn deliver_frame(&mut self, from: usize, to: usize, dst: MacDest, payload: &[u8]) {
        self.deliver_frame_sec(from, to, dst, payload, true);
    }

    fn deliver_frame_sec(
        &mut self,
        from: usize,
        to: usize,
        dst: MacDest,
        payload: &[u8],
        link_security: bool,
    ) {
        self.sync_netif(to);
        let now = self.sim.now;
        let src = Address::Short(self.sim.nodes[from].mle.rloc16().into());
        let mac_dst = match dst {
            MacDest::Short(r) => Address::Short(r.into()),
            MacDest::Extended(e) => Address::Extended(e),
            MacDest::Broadcast => Address::Short(opentrust_core::types::ShortAddress::BROADCAST),
        };
        let mut events = std::vec::Vec::new();
        let mut forward = None;
        {
            let n = &self.sim.nodes[to];
            let TmfNode {
                fwd,
                resolver,
                ip6,
                fsink,
                delivered,
                dropped,
                forwarded,
                netdata,
                egress,
                ..
            } = &mut self.tmf[to];
            with_routing(
                &n.mle,
                n.env.ext,
                ip6,
                netdata,
                &self.nd,
                |routing| match fwd.receive_frame(
                    now,
                    payload,
                    src,
                    mac_dst,
                    link_security,
                    routing,
                    resolver,
                    &mut |e| events.push(e),
                    fsink,
                ) {
                    Rx::Datagram(d) => {
                        let hdr = opentrust_lowpan::ip6::Ipv6Header::parse(d);
                        match hdr {
                            Ok(h)
                                if !h.dst.is_multicast() && !routing.netif.has_unicast(&h.dst) =>
                            {
                                if routing.nd.route_lookup(&h.src, &h.dst)
                                    == Some(routing.mle.rloc16())
                                {
                                    egress.push(d.to_vec());
                                } else {
                                    forward = Some(d.to_vec());
                                }
                            }
                            _ => delivered.push(d.to_vec()),
                        }
                    }
                    Rx::Dropped(r) => dropped.push(r),
                    Rx::Forwarded => *forwarded += 1,
                    Rx::Consumed => {}
                },
            );
        }
        self.handle_events(to, events);
        if let Some(f) = forward {
            self.send_ip6(to, &f);
        }
    }

    /// Move TMF requests out of the cores into the agents and deliver
    /// datagrams until quiet.
    pub fn pump(&mut self) {
        for _ in 0..100 {
            let mut moved = false;
            let now = self.sim.now;
            for i in 0..self.tmf.len() {
                moved |= self.netdata_step(i);
                {
                    let n = &mut self.sim.nodes[i];
                    moved |= bbr_sim::step(i, now, &mut n.mle, &mut n.env, &mut self.tmf[i]);
                }
                let n = &mut self.sim.nodes[i];
                while let Some(r) = n.env.solicits.pop() {
                    moved = true;
                    let _ = self.tmf[i].outbox.request_router_id(&r);
                }
                while let Some(r) = n.env.released.pop() {
                    moved = true;
                    self.tmf[i].outbox.release_router_id(r);
                }
                // The indirect hooks of the MLE core.
                {
                    let t = &mut self.tmf[i];
                    while let Some((_, rloc)) = n.env.supervised.pop() {
                        moved = true;
                        t.fwd.send_child_supervision(rloc);
                    }
                    let now_list: std::vec::Vec<Rloc16> =
                        n.env.indirect.iter().map(|(_, r)| *r).collect();
                    let gone_list: std::vec::Vec<Rloc16> = t
                        .indirect_seen
                        .iter()
                        .filter(|r| !now_list.contains(r))
                        .copied()
                        .collect();
                    for gone in &gone_list {
                        // A child that is still valid and no longer sleeps
                        // gets its messages sent directly.
                        let rx_on = n
                            .mle
                            .children()
                            .find_by_rloc(*gone, opentrust_mle::neighbor::StateFilter::Valid)
                            .is_some_and(|c| c.neighbor.is_rx_on_when_idle());
                        if rx_on {
                            moved = true;
                            let TmfNode {
                                fwd,
                                fsink,
                                ip6,
                                netdata,
                                ..
                            } = &mut *t;
                            with_routing(&n.mle, n.env.ext, ip6, netdata, &self.nd, |routing| {
                                fwd.child_became_rx_on(*gone, routing, fsink);
                            });
                        } else {
                            t.fwd.child_removed(*gone);
                        }
                    }
                    t.indirect_seen = now_list;
                }
                let t = &mut self.tmf[i];
                if t.outbox.is_pending() {
                    t.outbox.flush(
                        &mut t.agent,
                        now,
                        &mut t.rng,
                        &mut t.sink,
                        &mut n.mle,
                        &mut n.env,
                    );
                }
                // Timeouts.
                while let Some(opentrust_coap::endpoint::Event::Timeout { user }) =
                    t.agent.poll(now, &mut t.sink)
                {
                    if let Some(r) = router_id::client_failure(user) {
                        n.mle.address_solicit_reply(&mut n.env, now, r);
                    } else if user == USER_SERVER_DATA {
                        t.notifier.response(now, false);
                    } else {
                        bbr_sim::queue_outcome(t, user, Outcome::Timeout);
                    }
                }
                // Address cache timers.
                let mut ev = std::vec::Vec::new();
                t.resolver.poll(now, &mut |e| ev.push(e));
                if !ev.is_empty() {
                    moved = true;
                    self.handle_events(i, ev);
                }
            }
            for i in 0..self.tmf.len() {
                let out = core::mem::take(&mut self.tmf[i].sink.out);
                for d in out {
                    moved = true;
                    let src = d.src.unwrap_or_else(|| self.rloc(i));
                    if d.dst.is_multicast() {
                        for j in 0..self.tmf.len() {
                            if j != i
                                && self.sim.nodes[j].mle.role().is_router_or_leader()
                                && !self.blocked.contains(&(i, j))
                            {
                                self.deliver(j, src, &d);
                            }
                        }
                        continue;
                    }
                    let Some(dst) = self.owner_of(&d.dst) else {
                        continue;
                    };
                    if self.blocked.contains(&(i, dst)) {
                        continue;
                    }
                    self.deliver(dst, src, &d);
                }
            }
            moved |= self.pump_frames();
            if !moved {
                return;
            }
        }
        panic!("TMF storm");
    }

    fn deliver(&mut self, to: usize, src: Ipv6Addr, d: &Datagram) {
        self.sync_netif(to);
        let now = self.sim.now;
        let meta = UdpMeta {
            peer: SocketAddrV6::new(src, 61631, 0, 0),
            local: SocketAddrV6::new(d.dst, d.dst_port, 0, 0),
            hop_limit: 64,
            ecn: 0,
            link_security: true,
        };
        let n = &mut self.sim.nodes[to];
        let t = &mut self.tmf[to];
        let env = MlTmfEnv(n.env.mesh_local_prefix());
        let mut h = NodeHandler {
            env: &mut n.env,
            mle: &mut n.mle,
            now,
            rx: &mut t.rx,
            netif: &mut t.ip6.netif,
            resolver: &mut t.resolver,
            actions: std::vec::Vec::new(),
            events: std::vec::Vec::new(),
            errors_seen: &mut t.errors_seen,
            leader: &mut t.leader,
            sd_changed: Changed::default(),
            idx: to,
            fake_bbr: &mut self.fake_bbr,
            bbrn: &mut t.bbrn,
        };
        let r = t
            .agent
            .handle_dispatch(now, &mut t.sink, &env, &meta, &d.payload, &mut h);
        let actions = core::mem::take(&mut h.actions);
        let events = core::mem::take(&mut h.events);
        let sd_changed = h.sd_changed;
        if sd_changed.any {
            // The leader's data changed: make the MLE core serve it and
            // advertise the new versions.
            refresh_provided(&mut n.env, t.leader.data());
            t.leader.publish(&mut n.mle, &mut n.env, now);
        }
        match r {
            TmfRx::Response { user, msg, .. } => {
                if let Some(rep) = router_id::client_response(user, &msg) {
                    n.mle.address_solicit_reply(&mut n.env, now, rep);
                } else if user == USER_SERVER_DATA {
                    t.notifier.response(now, true);
                } else if user == anycast::USER_ANYCAST_LOCATE
                    && let Ok(l) = anycast::parse_response(&msg, n.env.mesh_local_prefix())
                {
                    t.located.push(l);
                } else {
                    bbr_sim::queue_outcome(
                        t,
                        user,
                        Outcome::Response(msg.code(), msg.payload().to_vec()),
                    );
                }
            }
            TmfRx::Failed { user, .. } => {
                if let Some(rep) = router_id::client_failure(user) {
                    n.mle.address_solicit_reply(&mut n.env, now, rep);
                } else if user == USER_SERVER_DATA {
                    t.notifier.response(now, false);
                } else {
                    bbr_sim::queue_outcome(t, user, Outcome::Failed);
                }
            }
            _ => {}
        }
        for a in actions {
            let n = &self.sim.nodes[to];
            let t = &mut self.tmf[to];
            let _ = address::send_action(
                &mut t.agent,
                now,
                &mut t.rng,
                &mut t.sink,
                n.mle.rloc16(),
                &n.env,
                &a,
            );
        }
        self.handle_events(to, events);
    }

    /// Send a hand-made CoAP request from node `from` to node `to`'s RLOC
    /// and return the code and payload of the immediate answer, if any.
    pub fn raw_request(
        &mut self,
        from: usize,
        to: usize,
        path: &str,
        ty: opentrust_coap::message::Type,
        code: opentrust_coap::message::Code,
        payload: &[u8],
    ) -> Option<(opentrust_coap::message::Code, std::vec::Vec<u8>)> {
        use opentrust_coap::message::{Message, MessageBuilder};
        let mut b = [0u8; 256];
        self.next_mid += 1;
        let mut m = MessageBuilder::new(&mut b, ty, code, self.next_mid, &[0xab]).unwrap();
        m.uri_path(path).unwrap();
        let n = m.finish_with_payload(payload).unwrap();
        let d = Datagram {
            src: None,
            dst: self.rloc(to),
            dst_port: 61631,
            payload: Vec::from_slice(&b[..n]).unwrap(),
        };
        let src = self.rloc(from);
        self.tmf[to].sink.out.clear();
        self.deliver(to, src, &d);
        let out = core::mem::take(&mut self.tmf[to].sink.out);
        let r = out.first()?;
        let msg = Message::parse(&r.payload).ok()?;
        Some((msg.code(), msg.payload().to_vec()))
    }

    /// Like [`MeshSim::raw_request`] but deliver whatever the receiver
    /// sends in turn (answers, follow-up messages).
    pub fn inject(
        &mut self,
        from: usize,
        to: usize,
        path: &str,
        ty: opentrust_coap::message::Type,
        code: opentrust_coap::message::Code,
        payload: &[u8],
    ) {
        use opentrust_coap::message::MessageBuilder;
        let mut b = [0u8; 256];
        self.next_mid += 1;
        let mut m = MessageBuilder::new(&mut b, ty, code, self.next_mid, &[0xcd]).unwrap();
        m.uri_path(path).unwrap();
        let n = m.finish_with_payload(payload).unwrap();
        let d = Datagram {
            src: None,
            dst: self.rloc(to),
            dst_port: 61631,
            payload: Vec::from_slice(&b[..n]).unwrap(),
        };
        let src = self.rloc(from);
        self.deliver(to, src, &d);
        self.pump();
    }

    fn next_tmf_deadline(&self) -> Option<Instant> {
        self.tmf
            .iter()
            .flat_map(|t| {
                [
                    t.agent.next_deadline(),
                    t.resolver.next_deadline(),
                    t.publisher.next_deadline(),
                    bbr_sim::next_deadline(t),
                ]
            })
            .flatten()
            .min()
    }

    /// Advance time by `d`: MLE deadlines and TMF deadlines in order.
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

    /// Roles of all nodes, for assertion messages.
    pub fn roles(&self) -> std::vec::Vec<Role> {
        self.sim.nodes.iter().map(|n| n.mle.role()).collect()
    }
}
