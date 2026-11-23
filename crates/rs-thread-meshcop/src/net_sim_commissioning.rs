//! Test harness, commissioning part: Joiner, Joiner Router, Commissioner
//! and Border Agent on the nodes of [`Net`], link-local datagrams between
//! radio neighbors with an emulated MAC security class, and an external
//! Commissioner talking to a Border Agent node.
//!
//! MAC emulation: a datagram sent with [`LinkSecurity::Kek`] carries the
//! sender's KEK and is delivered only to a neighbor whose installed KEK is
//! the same (key ID mode 0 decryption); [`LinkSecurity::None`] datagrams
//! are delivered as such (the receiver's unsecure-port filter is the
//! Joiner / Joiner Router logic itself).

use core::net::{Ipv6Addr, SocketAddrV6};
use std::boxed::Box;
use std::vec::Vec;

use rs_thread_coap::endpoint::Peer;
use rs_thread_coap::message::{Code, Type};
use rs_thread_coap::tmf::UdpSink;
use rs_thread_coap::uri::Uri;
use rs_thread_core::crypto::SoftCrypto;
use rs_thread_core::crypto::ecjpake::SoftP256;
use rs_thread_core::message::Priority;
use rs_thread_core::time::Instant;
use rs_thread_core::types::{ExtAddress, Kek, ipv6};
use rs_thread_core::{Error, Result};
use rs_thread_mle::Role;
use rs_thread_mle::test_support::MLP;
use rs_thread_net::ip6::SendInfo;

use crate::border_agent::{
    BorderAgent, BorderAgentClient, BorderAgentEvent, BorderAgentIo, BorderAgentView,
    ExternalTransport, Listener, is_border_agent_user,
};
use crate::commissioner::{Commissioner, MeshTransport, is_commissioner_user};
use crate::dataset::{Dataset, DatasetType};
use crate::joiner::{JOINER_UDP_PORT, Joiner, JoinerEvent, JoinerIo};
use crate::joiner_router::{JoinerRouter, JoinerRouterEvent, JoinerRouterIo};
use crate::net_sim::{Net, Sink, TmfAgent, XRng};
use crate::secure::LinkSecurity;

pub type SimJoiner = Joiner<SoftCrypto, SoftP256>;
pub type SimCommissioner = Commissioner<SoftCrypto, SoftP256>;
pub type SimBorderAgent = BorderAgent<SoftCrypto, SoftP256>;

/// Response tags routed to the commissioning roles.
pub fn is_cm_user(user: u32) -> bool {
    is_commissioner_user(user) || is_border_agent_user(user)
}

/// The commissioning roles of one node.
#[derive(Default)]
pub struct Roles {
    pub joiner: Option<Box<SimJoiner>>,
    pub joiner_events: Vec<JoinerEvent>,
    pub jr: JoinerRouter,
    pub jr_events: Vec<JoinerRouterEvent>,
    pub jr_port: Option<u16>,
    pub comm: Option<Box<SimCommissioner>>,
    pub ba: Option<Box<SimBorderAgent>>,
    pub ba_events: Vec<BorderAgentEvent>,
    /// DTLS datagrams of the Border Agent to the external Commissioner.
    pub ba_down: Vec<Vec<u8>>,
    /// The KEK installed in the MAC (key ID mode 0).
    pub kek: Option<Kek>,
    /// Relay TMF requests to process after dispatch: (uri, CON, payload).
    pub deferred: Vec<(Uri, bool, Vec<u8>)>,
    /// Relay Receive messages refused by the Commissioner / Border Agent.
    pub relay_rx_refused: Vec<Error>,
}

impl Roles {
    pub fn next_deadline(&self) -> Option<Instant> {
        [
            self.joiner.as_ref().and_then(|j| j.next_deadline()),
            self.jr.next_deadline(),
            self.comm.as_ref().and_then(|c| c.next_deadline()),
            self.ba.as_ref().and_then(|b| b.next_deadline()),
        ]
        .into_iter()
        .flatten()
        .filter(|&t| t > Instant::ZERO)
        .min()
    }
}

/// A link-local datagram on the air.
#[derive(Debug, Clone)]
pub struct Ll {
    pub from: usize,
    pub src: Peer,
    pub dst: Peer,
    pub link: LinkSecurity,
    pub kek: Option<Kek>,
    pub payload: Vec<u8>,
}

/// An external Commissioner (outside the mesh) of a Border Agent node.
pub struct External {
    pub client: Option<BorderAgentClient<SoftCrypto, SoftP256>>,
    pub comm: SimCommissioner,
    pub rng: XRng,
    pub up: Vec<Vec<u8>>,
    pub ba: usize,
    pub peer: Peer,
}

#[derive(Default)]
pub struct Air {
    pub ll: Vec<Ll>,
    /// Every link-local datagram sent, for assertions.
    pub log: Vec<Ll>,
    /// Key ID mode 0 frames dropped because the receiver's KEK differs.
    pub kek_drops: u32,
    pub ext: Option<External>,
}

impl Air {
    pub fn next_deadline(&self) -> Option<Instant> {
        let e = self.ext.as_ref()?;
        [
            e.client.as_ref().and_then(|c| c.next_deadline()),
            e.comm.next_deadline(),
        ]
        .into_iter()
        .flatten()
        .min()
    }
}

enum JAction {
    Discovery(u8, u16, Vec<u8>),
    Ext(ExtAddress),
    Save(Box<Dataset>),
}

struct JIoSim<'a> {
    from: usize,
    ext: ExtAddress,
    ll: &'a mut Vec<Ll>,
    kek: &'a mut Option<Kek>,
    events: &'a mut Vec<JoinerEvent>,
    actions: Vec<JAction>,
}

impl JIoSim<'_> {
    fn push(&mut self, src_port: u16, dst: &Peer, link: LinkSecurity, payload: &[u8]) {
        self.ll.push(Ll {
            from: self.from,
            src: Peer::new(ipv6::link_local(&self.ext), src_port),
            dst: *dst,
            link,
            kek: if link == LinkSecurity::Kek {
                self.kek.clone()
            } else {
                None
            },
            payload: payload.to_vec(),
        });
    }
}

impl JoinerIo for JIoSim<'_> {
    fn send_discovery_request(&mut self, channel: u8, pan_id: u16, tlv: &[u8]) -> Result<()> {
        self.actions
            .push(JAction::Discovery(channel, pan_id, tlv.to_vec()));
        Ok(())
    }
    fn set_ext_address(&mut self, ext: &ExtAddress) {
        self.ext = *ext;
        self.actions.push(JAction::Ext(*ext));
    }
    fn set_pan(&mut self, _channel: u8, _pan_id: u16) -> Result<()> {
        Ok(())
    }
    fn set_unsecure_port(&mut self, _port: u16, _allow: bool) {}
    fn send_unsecured(&mut self, src_port: u16, dst: &Peer, payload: &[u8]) -> Result<()> {
        self.push(src_port, dst, LinkSecurity::None, payload);
        Ok(())
    }
    fn set_kek(&mut self, kek: Option<&Kek>) {
        *self.kek = kek.cloned();
    }
    fn send_kek(&mut self, src_port: u16, dst: &Peer, payload: &[u8]) -> Result<()> {
        if self.kek.is_none() {
            return Err(Error::InvalidState);
        }
        self.push(src_port, dst, LinkSecurity::Kek, payload);
        Ok(())
    }
    fn save_dataset(&mut self, dataset: &Dataset) {
        self.actions.push(JAction::Save(Box::new(dataset.clone())));
    }
    fn event(&mut self, e: JoinerEvent) {
        self.events.push(e);
    }
}

struct JrIo<'a> {
    from: usize,
    src: Ipv6Addr,
    ll: &'a mut Vec<Ll>,
    kek: &'a mut Option<Kek>,
    port: &'a mut Option<u16>,
}

impl JoinerRouterIo for JrIo<'_> {
    fn set_joiner_port(&mut self, port: Option<u16>) {
        *self.port = port;
    }
    fn send_unsecured(&mut self, src_port: u16, dst: &Peer, payload: &[u8]) -> Result<()> {
        self.ll.push(Ll {
            from: self.from,
            src: Peer::new(self.src, src_port),
            dst: *dst,
            link: LinkSecurity::None,
            kek: None,
            payload: payload.to_vec(),
        });
        Ok(())
    }
    fn set_kek(&mut self, kek: Option<&Kek>) {
        *self.kek = kek.cloned();
    }
    fn send_kek(&mut self, src_port: u16, dst: &Peer, payload: &[u8]) -> Result<()> {
        let kek = self.kek.clone().ok_or(Error::InvalidState)?;
        self.ll.push(Ll {
            from: self.from,
            src: Peer::new(self.src, src_port),
            dst: *dst,
            link: LinkSecurity::Kek,
            kek: Some(kek),
            payload: payload.to_vec(),
        });
        Ok(())
    }
}

struct BaIoSim<'a> {
    now: Instant,
    agent: &'a mut TmfAgent,
    rng: &'a mut XRng,
    sink: &'a mut Sink,
    rloc: Ipv6Addr,
    down: &'a mut Vec<Vec<u8>>,
    aloc: &'a mut Option<u16>,
}

impl BorderAgentIo for BaIoSim<'_> {
    fn send_to_commissioner(&mut self, _l: Listener, _peer: &Peer, data: &[u8]) -> Result<()> {
        self.down.push(data.to_vec());
        Ok(())
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
        if confirmable {
            self.agent.post(
                self.now,
                self.rng,
                self.sink,
                dst,
                Some(self.rloc),
                Priority::Net,
                uri,
                payload,
                user,
            )
        } else {
            self.agent.send_request(
                self.now,
                self.rng,
                self.sink,
                dst,
                &rs_thread_coap::endpoint::SendOpts {
                    src: Some(self.rloc),
                    priority: Priority::Net,
                    multicast_loop: false,
                },
                Type::Non,
                Code::POST,
                None,
                |mut b| {
                    b.uri_path(uri.path())?;
                    b.finish_with_payload(payload)
                },
            )
        }
    }
    fn send_udp(&mut self, src: &SocketAddrV6, dst: &SocketAddrV6, payload: &[u8]) -> Result<()> {
        let mut info = SendInfo::new(*dst.ip());
        info.src = Some(*src.ip());
        self.sink.send(&info, src.port(), dst.port(), payload)
    }
    fn set_commissioner_aloc(&mut self, aloc16: Option<u16>) {
        *self.aloc = aloc16;
    }
}

macro_rules! mesh_transport {
    ($net:expr, $i:expr) => {{
        let rloc16 = $net.sim.nodes[$i].mle.rloc16();
        let node = &mut $net.nodes[$i];
        (
            &mut node.cm,
            MeshTransport {
                agent: &mut node.agent,
                rng: &mut node.rng,
                sink: &mut node.sink,
                mlp: MLP,
                rloc16,
                aloc16: &mut node.comm_aloc,
            },
        )
    }};
}

macro_rules! ba_io {
    ($net:expr, $i:expr, $now:expr) => {{
        let rloc = MLP.rloc($net.sim.nodes[$i].mle.rloc16());
        let node = &mut $net.nodes[$i];
        let io = BaIoSim {
            now: $now,
            agent: &mut node.agent,
            rng: &mut node.rng,
            sink: &mut node.sink,
            rloc,
            down: &mut node.cm.ba_down,
            aloc: &mut node.comm_aloc,
        };
        (&mut node.cm.ba, &mut node.cm.ba_events, &node.shared, io)
    }};
}

impl Net {
    /// The Commissioning Data node `i` sees.
    pub fn commissioning_data_of(&self, i: usize) -> Option<Vec<u8>> {
        if self.sim.nodes[i].mle.role() == Role::Leader {
            self.nodes[i].nd.commissioning_data().map(<[u8]>::to_vec)
        } else {
            rs_thread_mesh::netdata::NetworkDataView(&self.sim.nodes[i].env.nd)
                .commissioning_data()
                .map(<[u8]>::to_vec)
        }
    }

    pub(crate) fn cm_response(
        &mut self,
        i: usize,
        user: u32,
        res: core::result::Result<(Code, Vec<u8>), Error>,
    ) {
        let now = self.sim.now;
        let r = res.as_ref().map(|(c, p)| (*c, &p[..])).map_err(|e| *e);
        if is_commissioner_user(user) {
            let (cm, mut t) = mesh_transport!(self, i);
            if let Some(c) = cm.comm.as_mut() {
                let _ = c.handle_response(now, &mut t, user, r);
            }
        } else {
            let (ba, _, _, mut io) = ba_io!(self, i, now);
            if let Some(b) = ba.as_mut() {
                b.handle_tmf_response(now, &mut io, user, r);
            }
        }
    }

    pub(crate) fn deliver_proxy(&mut self, to: usize, src: Ipv6Addr, d: &crate::net_sim::Datagram) {
        let now = self.sim.now;
        let (ba, _, _, mut io) = ba_io!(self, to, now);
        let aloc = *io.aloc;
        let Some(b) = ba.as_mut() else { return };
        if aloc.and_then(|a| MLP.aloc(a).ok()) != Some(d.dst) {
            return;
        }
        let mut rng = XRng(now.as_micros() | 1);
        let _ = b.handle_proxy_rx(
            now,
            &mut rng,
            &mut io,
            &SocketAddrV6::new(src, d.src_port, 0, 0),
            d.dst_port,
            &d.payload,
        );
    }

    /// Drive the commissioning roles of node `i`. Returns whether anything
    /// was sent.
    pub(crate) fn run_commissioning(&mut self, i: usize) -> bool {
        let now = self.sim.now;
        let before = (self.cx.ll.len(), self.nodes[i].sink.out.len());
        // Relay messages received by the TMF agent.
        for (uri, con, payload) in core::mem::take(&mut self.nodes[i].cm.deferred) {
            match uri {
                Uri::RelayRx => self.relay_rx(i, con, &payload),
                Uri::RelayTx => {
                    let src = ipv6::link_local(&self.sim.nodes[i].env.ext);
                    let cm = &mut self.nodes[i].cm;
                    let mut io = JrIo {
                        from: i,
                        src,
                        ll: &mut self.cx.ll,
                        kek: &mut cm.kek,
                        port: &mut cm.jr_port,
                    };
                    let _ = cm.jr.handle_relay_tx(now, &mut io, con, &payload);
                }
                _ => {}
            }
        }
        // Joiner Router.
        let cd = self.commissioning_data_of(i);
        let role = self.sim.nodes[i].mle.role();
        let is_ftd = !matches!(role, Role::Disabled | Role::Detached)
            && self.sim.nodes[i].mle.is_full_thread_device();
        let active = self.nodes[i]
            .shared
            .borrow()
            .ds
            .read(DatasetType::Active, now);
        {
            let src = ipv6::link_local(&self.sim.nodes[i].env.ext);
            let node = &mut self.nodes[i];
            let cm = &mut node.cm;
            let mut io = JrIo {
                from: i,
                src,
                ll: &mut self.cx.ll,
                kek: &mut cm.kek,
                port: &mut cm.jr_port,
            };
            cm.jr.update(is_ftd, cd.as_deref(), &mut io);
            while let Some(e) = cm.jr.poll(now, &mut node.rng, &mut io, active.as_ref(), 0) {
                cm.jr_events.push(e);
            }
        }
        // Joiner.
        if self.nodes[i].cm.joiner.is_some() {
            let responses = core::mem::take(&mut self.sim.nodes[i].env.discovery_responses);
            let ext = self.sim.nodes[i].env.ext;
            let node = &mut self.nodes[i];
            let cm = &mut node.cm;
            let j = cm.joiner.as_mut().unwrap();
            let mut io = JIoSim {
                from: i,
                ext,
                ll: &mut self.cx.ll,
                kek: &mut cm.kek,
                events: &mut cm.joiner_events,
                actions: Vec::new(),
            };
            for (info, tlvs) in responses {
                j.handle_discovery_response(&info, &tlvs);
            }
            j.poll(now, &mut node.rng, &mut io);
            let actions = core::mem::take(&mut io.actions);
            self.apply_joiner_actions(i, actions);
        }
        // Commissioner.
        {
            let (cm, mut t) = mesh_transport!(self, i);
            if let Some(c) = cm.comm.as_mut() {
                c.poll(now, &mut t);
            }
        }
        // Border Agent.
        {
            let (ba, events, _, mut io) = ba_io!(self, i, now);
            if let Some(b) = ba.as_mut() {
                b.poll(now, &mut io);
                while let Some(e) = b.pop_event() {
                    events.push(e);
                }
            }
        }
        if self.nodes[i].comm_aloc.is_some() {
            self.commissioner = Some(i);
        }
        let after = (self.cx.ll.len(), self.nodes[i].sink.out.len());
        before != after || !self.nodes[i].cm.ba_down.is_empty()
    }

    fn relay_rx(&mut self, i: usize, con: bool, payload: &[u8]) {
        let now = self.sim.now;
        let mut rng = XRng(now.as_micros() ^ 0x5151);
        let r = if self.nodes[i].cm.ba.is_some() {
            let (ba, _, _, mut io) = ba_io!(self, i, now);
            ba.as_mut()
                .map(|b| b.handle_relay_rx(now, &mut rng, &mut io, con, payload))
        } else {
            let (cm, mut t) = mesh_transport!(self, i);
            cm.comm
                .as_mut()
                .map(|c| c.handle_relay_rx(now, &mut rng, &mut t, con, payload))
        };
        if let Some(Err(e)) = r {
            self.nodes[i].cm.relay_rx_refused.push(e);
        }
    }

    fn apply_joiner_actions(&mut self, i: usize, actions: Vec<JAction>) {
        let now = self.sim.now;
        for a in actions {
            match a {
                JAction::Discovery(ch, pan, tlv) => {
                    let n = &mut self.sim.nodes[i];
                    let _ = n
                        .mle
                        .send_discovery_request(&mut n.env, pan, Some(ch), &tlv);
                }
                JAction::Ext(e) => self.sim.nodes[i].env.ext = e,
                JAction::Save(d) => {
                    let s = &mut *self.nodes[i].shared.borrow_mut();
                    let _ = s.ds.save_local(&mut s.env, now, DatasetType::Active, &d);
                }
            }
        }
    }

    /// Deliver the link-local datagrams and the external Commissioner's
    /// traffic. Returns whether anything moved.
    pub(crate) fn move_air(&mut self) -> bool {
        let mut moved = false;
        let now = self.sim.now;
        for d in core::mem::take(&mut self.cx.ll) {
            moved = true;
            self.cx.log.push(d.clone());
            let Some(to) = (0..self.nodes.len()).find(|&j| {
                j != d.from
                    && self.sim.link(d.from, j).is_some()
                    && ipv6::link_local(&self.sim.nodes[j].env.ext) == d.dst.addr
            }) else {
                continue;
            };
            if d.link == LinkSecurity::Kek && self.nodes[to].cm.kek != d.kek {
                // Key ID mode 0 with another key: the MIC fails.
                self.cx.kek_drops += 1;
                continue;
            }
            self.deliver_ll(to, &d);
        }
        // External Commissioner <-> Border Agent.
        if let Some(mut e) = self.cx.ext.take() {
            let ba = e.ba;
            for d in core::mem::take(&mut e.up) {
                moved = true;
                let ds = self.nodes[ba].shared.clone();
                let cd = self.commissioning_data_of(ba);
                let peer = e.peer;
                let ds = ds.borrow();
                let (b, _, _, mut io) = ba_io!(self, ba, now);
                if let Some(b) = b.as_mut() {
                    let view = BorderAgentView {
                        datasets: &ds.ds,
                        commissioning_data: cd.as_deref(),
                        mesh_local_prefix: MLP,
                    };
                    b.handle_udp(now, &mut e.rng, &mut io, &view, &peer, &d);
                }
            }
            let down = core::mem::take(&mut self.nodes[ba].cm.ba_down);
            if let Some(c) = e.client.as_mut() {
                let up = &mut e.up;
                let mut out = |x: &[u8]| {
                    up.push(x.to_vec());
                    Ok(())
                };
                for d in down {
                    moved = true;
                    c.handle_datagram(now, &mut e.rng, &mut out, &mut e.comm, &d);
                }
                c.poll(now, &mut out, &mut e.comm);
            }
            moved |= !e.up.is_empty();
            self.cx.ext = Some(e);
        }
        moved
    }

    fn deliver_ll(&mut self, to: usize, d: &Ll) {
        let now = self.sim.now;
        if self.nodes[to].cm.joiner.is_some() {
            let ext = self.sim.nodes[to].env.ext;
            let node = &mut self.nodes[to];
            let cm = &mut node.cm;
            let j = cm.joiner.as_mut().unwrap();
            let mut io = JIoSim {
                from: to,
                ext,
                ll: &mut self.cx.ll,
                kek: &mut cm.kek,
                events: &mut cm.joiner_events,
                actions: Vec::new(),
            };
            if d.dst.port == rs_thread_coap::tmf::UDP_PORT {
                j.handle_kek_datagram(now, &mut io, d.link, &d.src, &d.dst.addr, &d.payload);
            } else if d.dst.port == JOINER_UDP_PORT && d.link == LinkSecurity::None {
                j.handle_udp(now, &mut node.rng, &mut io, &d.src, &d.payload);
            }
            let actions = core::mem::take(&mut io.actions);
            self.apply_joiner_actions(to, actions);
            return;
        }
        if d.dst.port == rs_thread_coap::tmf::UDP_PORT {
            let src = ipv6::link_local(&self.sim.nodes[to].env.ext);
            let cm = &mut self.nodes[to].cm;
            let mut io = JrIo {
                from: to,
                src,
                ll: &mut self.cx.ll,
                kek: &mut cm.kek,
                port: &mut cm.jr_port,
            };
            if let Some(e) =
                cm.jr
                    .handle_kek_datagram(now, &mut io, d.link, &d.src, &d.dst.addr, &d.payload)
            {
                cm.jr_events.push(e);
            }
            return;
        }
        if d.link != LinkSecurity::None {
            return;
        }
        let cd = self.commissioning_data_of(to);
        let ba = cd
            .as_deref()
            .and_then(|c| crate::tlv::Tlvs(c).border_agent_locator().ok());
        let rloc16 = self.sim.nodes[to].mle.rloc16();
        let node = &mut self.nodes[to];
        let _ = node.cm.jr.handle_joiner_datagram(
            &mut node.agent,
            now,
            &mut node.rng,
            &mut node.sink,
            &MLP,
            rloc16,
            ba,
            &d.src,
            d.dst.port,
            &d.payload,
        );
    }

    // ----------------------------------------------------------- helpers

    /// Run `f` with the on-mesh Commissioner of node `i` and its transport.
    pub fn with_commissioner<T>(
        &mut self,
        i: usize,
        f: impl FnOnce(
            &mut SimCommissioner,
            &mut dyn crate::commissioner::CommissionerIo,
            Instant,
            &mut XRng,
        ) -> T,
    ) -> T {
        let now = self.sim.now;
        let mut rng = XRng(now.as_micros() ^ 0x77);
        let (cm, mut t) = mesh_transport!(self, i);
        let c = cm.comm.as_mut().expect("commissioner");
        let r = f(c, &mut t, now, &mut rng);
        self.pump();
        r
    }

    /// Run `f` with the external Commissioner and its transport.
    pub fn with_external<T>(
        &mut self,
        f: impl FnOnce(
            &mut SimCommissioner,
            &mut ExternalTransport<'_, SoftCrypto, SoftP256>,
            Instant,
            &mut XRng,
        ) -> T,
    ) -> T {
        let now = self.sim.now;
        let mut e = self.cx.ext.take().expect("external commissioner");
        let up = &mut e.up;
        let mut out = |x: &[u8]| {
            up.push(x.to_vec());
            Ok(())
        };
        let mut t = ExternalTransport {
            client: e.client.as_mut().expect("connected"),
            out: &mut out,
        };
        let mut rng = XRng(now.as_micros() ^ 0x99);
        let r = f(&mut e.comm, &mut t, now, &mut rng);
        self.cx.ext = Some(e);
        self.pump();
        r
    }
}

impl Net {
    /// Make node `i` a Joiner (fresh network key so that a successful join
    /// is visible) and start it with `pskd` on channel 15.
    pub fn start_joiner(&mut self, i: usize, eui64: &ExtAddress, pskd: &str) -> Result<()> {
        let now = self.sim.now;
        self.nodes[i].shared.borrow_mut().env.cur.network_key =
            rs_thread_core::types::NetworkKey([0; 16]);
        let mut j = Box::new(Joiner::new(SoftCrypto, SoftP256));
        let ext = self.sim.nodes[i].env.ext;
        let node = &mut self.nodes[i];
        let cm = &mut node.cm;
        let mut io = JIoSim {
            from: i,
            ext,
            ll: &mut self.cx.ll,
            kek: &mut cm.kek,
            events: &mut cm.joiner_events,
            actions: Vec::new(),
        };
        let r = j.start(
            now,
            &mut node.rng,
            &mut io,
            eui64,
            pskd,
            &crate::joiner::JoinerConfig {
                vendor_name: "RsThread",
                vendor_model: "Sim",
                vendor_sw_version: "1",
                ..Default::default()
            },
            1 << 15,
        );
        let actions = core::mem::take(&mut io.actions);
        cm.joiner = Some(j);
        self.apply_joiner_actions(i, actions);
        r
    }

    /// The Joiner's final result, if done.
    pub fn joiner_done(&self, i: usize) -> Option<core::result::Result<(), Error>> {
        self.nodes[i].cm.joiner_events.iter().find_map(|e| match e {
            JoinerEvent::Done(r) => Some(*r),
            _ => None,
        })
    }
}
