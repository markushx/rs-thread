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

use crate::address::{self, AddressAction};
use crate::router_id::{self, RouterIdOutbox};

pub type TmfAgent = Agent<4, 16, 4, 256>;
pub type SimNetif = Netif<8, 4>;

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
    pub netif: SimNetif,
    pub resolver: AddressResolver<8>,
    /// Requests received, by URI id.
    pub rx: std::collections::BTreeMap<u16, u32>,
    /// `Resolved` / `ResolutionFailed` events, for the tests.
    pub resolved: std::vec::Vec<ResolverEvent>,
    /// Addresses removed after an Address Error.
    pub errors_seen: u32,
}

pub struct MeshSim {
    pub sim: Sim,
    pub tmf: std::vec::Vec<TmfNode>,
    /// Drop datagrams from node `a` to node `b` (indices), for tests.
    pub blocked: std::vec::Vec<(usize, usize)>,
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
                match address::handle_address_error(self.netif, self.mle, &iid, req, rsp) {
                    address::AddressErrorOutcome::Ignored => {}
                    address::AddressErrorOutcome::AddressRemoved => *self.errors_seen += 1,
                    address::AddressErrorOutcome::ChildAddressRemoved(a) => self.actions.push(a),
                }
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
                ] {
                    agent.register(u).unwrap();
                }
                TmfNode {
                    agent,
                    outbox: RouterIdOutbox::new(),
                    sink: Sink::default(),
                    rng: XRng(0x1357_9bdf ^ u64::from(i + 1)),
                    netif: SimNetif::new(),
                    resolver: AddressResolver::new(),
                    rx: Default::default(),
                    resolved: std::vec::Vec::new(),
                    errors_seen: 0,
                }
            })
            .collect();
        Self {
            sim,
            tmf,
            blocked: std::vec::Vec::new(),
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
        let nif = &mut self.tmf[i].netif;
        let _ = nif.set_mesh_local_prefix(MLP);
        let _ = nif.set_mesh_local_eid(&ipv6::iid(&n.env.ml_eid()));
        let r = n.mle.rloc16();
        let _ = nif.set_rloc16((r != Rloc16::INVALID).then_some(r));
    }

    fn owner_of(&self, dst: &Ipv6Addr) -> Option<usize> {
        (0..self.sim.nodes.len()).find(|&i| {
            let n = &self.sim.nodes[i];
            n.mle.rloc16() != Rloc16::INVALID && self.rloc(i) == *dst
        })
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
            }
        }
    }

    /// Move TMF requests out of the cores into the agents and deliver
    /// datagrams until quiet.
    pub fn pump(&mut self) {
        for _ in 0..100 {
            let mut moved = false;
            let now = self.sim.now;
            for i in 0..self.tmf.len() {
                let n = &mut self.sim.nodes[i];
                while let Some(r) = n.env.solicits.pop() {
                    moved = true;
                    let _ = self.tmf[i].outbox.request_router_id(&r);
                }
                while let Some(r) = n.env.released.pop() {
                    moved = true;
                    self.tmf[i].outbox.release_router_id(r);
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
            netif: &mut t.netif,
            resolver: &mut t.resolver,
            actions: std::vec::Vec::new(),
            events: std::vec::Vec::new(),
            errors_seen: &mut t.errors_seen,
        };
        let r = t
            .agent
            .handle_dispatch(now, &mut t.sink, &env, &meta, &d.payload, &mut h);
        let actions = core::mem::take(&mut h.actions);
        let events = core::mem::take(&mut h.events);
        match r {
            TmfRx::Response { user, msg, .. } => {
                if let Some(rep) = router_id::client_response(user, &msg) {
                    n.mle.address_solicit_reply(&mut n.env, now, rep);
                }
            }
            TmfRx::Failed { user, .. } => {
                if let Some(rep) = router_id::client_failure(user) {
                    n.mle.address_solicit_reply(&mut n.env, now, rep);
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
            .flat_map(|t| [t.agent.next_deadline(), t.resolver.next_deadline()])
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
