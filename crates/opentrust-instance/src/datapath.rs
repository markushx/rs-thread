//! The data path: MAC frames in, 6LoWPAN / mesh forwarding, IPv6, UDP and
//! ICMPv6 delivery; and back out: queued UDP datagrams, IPv6, forwarder,
//! MAC frames.

use heapless::Vec;
use opentrust_core::Result;
use opentrust_core::crypto::{CryptoBackend, SecurityLevel};
use opentrust_core::time::Instant;
use opentrust_core::types::{Rloc16, ShortAddress};
use opentrust_mac::frame::{
    Address, FrameBuilder, FrameType, FrameVersion, KeyIdentifier, SecurityHeader,
};
use opentrust_mac::mac::{Event as MacEvent, FrameBuf, RxFrame, TxHandle};
pub(crate) use opentrust_mesh::forwarder::Routing;
use opentrust_mesh::forwarder::{DropReason, FrameSink, MacDest, Rx, SendResult, TxFrame};
pub(crate) use opentrust_mesh::netdata::consumers::NetDataContexts;
pub(crate) use opentrust_mesh::netdata::lookup::Lookup;
use opentrust_mesh::netdata::lookup::NetDataIp6Env;
use opentrust_mle::endpoint::LinkRxInfo;
use opentrust_mle::neighbor::StateFilter;
use opentrust_net::header::{Ipv6Header, PROTO_ICMP6, PROTO_UDP, UdpHeader};
use opentrust_net::ip6::{Ctx, Delivery, RxMeta, RxOutcome, Scratch, SendInfo};
use opentrust_net::resolver::ResolverEvent;
use opentrust_net::udp::{ReceiverId, UdpMeta, UdpRx, UdpRxInfo};
use opentrust_platform::SettingsStore;
use rand_core::Rng;

use crate::stack::{MacTx, StackMac};
use crate::{Event, Instance, UdpSocket};

/// Builds 802.15.4 data frames from the forwarder's [`TxFrame`]s and hands
/// them to the MAC.
pub(crate) struct MacSink<'a, C: CryptoBackend> {
    pub mac: &'a mut StackMac<C>,
    pub tx: &'a mut MacTx,
}

const fn mac_address(d: MacDest) -> Address {
    match d {
        MacDest::Short(r) => Address::Short(ShortAddress(r.0)),
        MacDest::Extended(e) => Address::Extended(e),
        MacDest::Broadcast => Address::Short(ShortAddress::BROADCAST),
    }
}

impl<C: CryptoBackend> FrameSink for MacSink<'_, C> {
    fn transmit(&mut self, f: &TxFrame<'_>) -> Result<()> {
        let mut buf = [0u8; 127];
        let mut b = FrameBuilder::new(&mut buf)
            .frame_type(FrameType::Data)
            .version(FrameVersion::V2006)
            .sequence(0)
            .pan_id(self.mac.pan_id())
            .dst(mac_address(f.dst))
            .src(f.src)
            .frame_pending(f.frame_pending)
            .payload(f.payload);
        if f.link_security {
            // Frame counter and key index are filled in by the key manager.
            b = b.security(SecurityHeader::new(
                SecurityLevel::EncMic32,
                0,
                KeyIdentifier::Index(1),
            ));
        }
        let n = b.build()?;
        let frame = FrameBuf::from_slice(&buf[..n]).map_err(|_| opentrust_core::Error::NoBufs)?;
        // Keep the order: nothing overtakes frames that wait for the MAC.
        if self.tx.pending.is_empty() {
            self.tx.handle = self.tx.handle.wrapping_add(1);
            match self.mac.transmit(TxHandle(self.tx.handle), &frame) {
                Err(opentrust_core::Error::NoBufs) => {}
                r => return r,
            }
        }
        self.tx
            .pending
            .push_back(frame)
            .map_err(|_| opentrust_core::Error::NoBufs)
    }

    fn dest_unreachable(&mut self, _invoking: &[u8]) {}
}

/// Collects what the forwarder asks for besides frames, so it can be done
/// after the forwarder call (it needs the whole instance).
#[derive(Default)]
pub(crate) struct FwdNotes {
    pub unreachable: Vec<Vec<u8, 48>, 2>,
    pub loops: Vec<(Rloc16, Rloc16), 2>,
}

pub(crate) struct Sink<'a, 'b, C: CryptoBackend> {
    mac: MacSink<'a, C>,
    notes: &'b mut FwdNotes,
}

impl<C: CryptoBackend> FrameSink for Sink<'_, '_, C> {
    fn transmit(&mut self, f: &TxFrame<'_>) -> Result<()> {
        self.mac.transmit(f)
    }
    fn dest_unreachable(&mut self, invoking: &[u8]) {
        if let Ok(v) = Vec::from_slice(invoking) {
            let _ = self.notes.unreachable.push(v);
        }
    }
    fn routing_loop(&mut self, from: Rloc16, dest: Rloc16) {
        let _ = self.notes.loops.push((from, dest));
    }
}

pub(crate) fn sink<'a, 'b, C: CryptoBackend>(
    mac: &'a mut StackMac<C>,
    tx: &'a mut MacTx,
    notes: &'b mut FwdNotes,
) -> Sink<'a, 'b, C> {
    Sink {
        mac: MacSink { mac, tx },
        notes,
    }
}

/// Build the forwarder's view of the stack from disjoint fields (a macro:
/// a closure or function would borrow the whole instance).
macro_rules! with_routing {
    ($self:ident, |$r:ident| $body:expr) => {{
        let view = $self.core.netdata.view();
        let contexts = $crate::datapath::NetDataContexts {
            view,
            mesh_local_prefix: *$self.core.ip6.netif.mesh_local_prefix(),
        };
        let nd = $crate::datapath::Lookup::new(view, &$self.mle);
        let $r = $crate::datapath::Routing {
            mle: &$self.mle,
            netif: &$self.core.ip6.netif,
            contexts: &contexts,
            nd: &nd,
            ext: $self.core.ext,
        };
        $body
    }};
}
pub(crate) use with_routing;

impl<S: SettingsStore, C: CryptoBackend + Clone, R: Rng> Instance<S, C, R> {
    // ------------------------------------------------------------ MAC events

    /// Handle the MAC's events (received frames, data polls, results).
    pub(crate) fn service_mac(&mut self, now: Instant) -> bool {
        let mut busy = self.flush_mac_queue();
        while let Some(ev) = self.core.mac.poll_event() {
            busy = true;
            match ev {
                MacEvent::Received(rx) => self.handle_frame(now, rx),
                MacEvent::DataPollReceived { src, .. } => self.handle_poll(now, src),
                MacEvent::DataPollTimeout | MacEvent::DataPollSent(_) => {}
                MacEvent::TxDone { .. } => {}
                _ => {}
            }
        }
        busy
    }

    /// Hand waiting frames to the MAC as room frees up.
    pub(crate) fn flush_mac_queue(&mut self) -> bool {
        let mut busy = false;
        while let Some(f) = self.core.mactx.pending.front() {
            self.core.mactx.handle = self.core.mactx.handle.wrapping_add(1);
            match self.core.mac.transmit(TxHandle(self.core.mactx.handle), f) {
                Err(opentrust_core::Error::NoBufs) => break,
                _ => {
                    self.core.mactx.pending.pop_front();
                    busy = true;
                }
            }
        }
        busy
    }

    /// A data poll from a sleepy child: release its next frame.
    fn handle_poll(&mut self, _now: Instant, src: Address) {
        let mut notes = FwdNotes::default();
        let _ = with_routing!(self, |r| {
            let mut sink = Sink {
                mac: MacSink {
                    mac: &mut self.core.mac,
                    tx: &mut self.core.mactx,
                },
                notes: &mut notes,
            };
            self.fwd.handle_data_poll(&src, &r, &mut sink)
        });
        while let Some(c) = self.fwd.take_child_message_sent() {
            self.mle.child_message_sent(c);
        }
        self.sync_src_match();
    }

    /// Process a received data frame.
    fn handle_frame(&mut self, now: Instant, rx: RxFrame) {
        let Ok(f) = rx.parse() else { return };
        let src = f.src_address();
        let dst = f.dst_address();
        let payload = f.payload();
        let link_security = rx.security.is_some();
        // Link-layer replay protection (Thread 1.4.1 section 7.2.1.2).
        if let Some(sec) = &rx.security
            && let Some(ks) = sec.key_sequence
            && self
                .mle
                .check_link_frame(src, ks, sec.frame_counter)
                .is_err()
        {
            self.glue.replay_drops = self.glue.replay_drops.wrapping_add(1);
            return;
        }
        self.core.rx_link = LinkRxInfo {
            rss: rx.rssi,
            lqi: rx.lqi,
            pan_id: f.pan_id().map(|p| p.0),
            channel: Some(rx.channel),
        };
        // Any secure frame from the parent is a sign of life.
        if link_security
            && let (Address::Short(s), Some(p)) = (src, self.mle.parent())
            && s.0 == p.router.neighbor.rloc16.0
        {
            self.mle.parent_frame_received(now);
        }
        // The mesh source of a mesh header frame, to find children that
        // moved (OT `UpdateEidRlocCacheAndStaleChild`).
        let mesh_src = match opentrust_lowpan::forward::parse_frame(payload) {
            Ok(opentrust_lowpan::forward::LowpanFrame::Mesh { header, .. })
                if !dst.is_broadcast() =>
            {
                Some(Rloc16(header.source))
            }
            _ => None,
        };
        let mut dg = [0u8; opentrust_mesh::forwarder::MTU];
        let mut dg_len = 0usize;
        let mut events: Vec<ResolverEvent, 4> = Vec::new();
        let mut notes = FwdNotes::default();
        let mut forwarded = false;
        with_routing!(self, |r| {
            let mut sink = Sink {
                mac: MacSink {
                    mac: &mut self.core.mac,
                    tx: &mut self.core.mactx,
                },
                notes: &mut notes,
            };
            match self.fwd.receive_frame(
                now,
                payload,
                src,
                dst,
                link_security,
                &r,
                &mut self.resolver,
                &mut |e| {
                    let _ = events.push(e);
                },
                &mut sink,
            ) {
                Rx::Datagram(d) => {
                    dg[..d.len()].copy_from_slice(d);
                    dg_len = d.len();
                }
                Rx::Forwarded => forwarded = true,
                Rx::Dropped(_) | Rx::Consumed => {}
            }
        });
        let _ = forwarded;
        self.after_forwarder(now, events, notes);
        if dg_len > 0 {
            if let (Some(ms), Ok(h)) = (mesh_src, Ipv6Header::parse(&dg[..dg_len])) {
                self.mle.remove_child_that_moved(&mut self.core, &h.src, ms);
            }
            self.receive_datagram(now, &mut dg[..dg_len], link_security);
        }
    }

    /// Follow up on what a forwarder call asked for.
    pub(crate) fn after_forwarder(
        &mut self,
        now: Instant,
        events: Vec<ResolverEvent, 4>,
        notes: FwdNotes,
    ) {
        for e in events {
            self.handle_resolver_event(now, e);
        }
        for inv in notes.unreachable {
            let mut out = [0u8; 256];
            if let Ok(n) = self.core.ip6.build_error(
                now,
                &inv,
                (
                    opentrust_net::icmp6::TYPE_DST_UNREACH,
                    opentrust_net::icmp6::CODE_DST_UNREACH_NO_ROUTE,
                    0,
                ),
                &mut out,
            ) {
                self.send_ip6(now, &out[..n], true);
            }
        }
        for (from, dest) in notes.loops {
            self.mle
                .resolve_routing_loop(&mut self.core, now, from, dest);
        }
        while let Some(c) = self.fwd.take_child_message_sent() {
            self.mle.child_message_sent(c);
        }
    }

    // ------------------------------------------------------------ IPv6 in

    /// A complete datagram from the Thread network.
    fn receive_datagram(&mut self, now: Instant, dg: &mut [u8], link_security: bool) {
        if !link_security && !self.unsecure_allowed(dg) {
            return;
        }
        let mut scratch = Scratch::new();
        let out = {
            let env = NetDataIp6Env {
                view: self.core.netdata.view(),
                mle: &self.mle,
            };
            let mut ctx = Ctx {
                now,
                rng: &mut self.prng,
                env: &env,
            };
            self.core
                .ip6
                .handle(&mut ctx, RxMeta::thread(link_security), dg, &mut scratch)
        };
        if let Ok(out) = out {
            self.ip6_outcome(now, dg, &scratch, out, link_security);
        }
    }

    /// OT `Ip6::Filter`: datagrams without link security are only accepted
    /// for MLE and for the unsecure UDP ports the application opened.
    fn unsecure_allowed(&self, dg: &[u8]) -> bool {
        let Ok(h) = Ipv6Header::parse(dg) else {
            return false;
        };
        if h.next_header != PROTO_UDP {
            return false;
        }
        let Ok(u) = UdpHeader::parse(&dg[Ipv6Header::LEN.min(dg.len())..]) else {
            return false;
        };
        u.dst_port == opentrust_net::udp::MLE_UDP_PORT
            || self.glue.unsecure_ports.contains(&u.dst_port)
    }

    /// Act on the result of [`opentrust_net::ip6::Ip6::handle`] / `send`.
    pub(crate) fn ip6_outcome(
        &mut self,
        now: Instant,
        dg: &[u8],
        scratch: &Scratch,
        out: RxOutcome,
        link_security: bool,
    ) {
        if let Some(d) = out.deliver {
            let bytes = d.bytes(dg, scratch);
            self.deliver(now, &d, bytes);
        }
        if out.forward_thread {
            self.send_ip6(now, dg, link_security);
        }
        if out.inner_forward_thread {
            let mut inner = [0u8; opentrust_mesh::forwarder::MTU];
            let src = scratch.inner();
            if let Ok(h) = Ipv6Header::parse(src) {
                let n = (Ipv6Header::LEN + usize::from(h.payload_len)).min(inner.len());
                inner[..n].copy_from_slice(&src[..n]);
                self.send_ip6(now, &inner[..n], link_security);
            }
        }
        if let Some(reply) = out.reply(scratch) {
            self.send_ip6(now, reply, true);
        }
    }

    /// Local delivery of a UDP or ICMPv6 payload.
    fn deliver(&mut self, now: Instant, d: &Delivery, bytes: &[u8]) {
        match d.proto {
            PROTO_UDP => match self.udp.handle_datagram(&UdpRxInfo::from(d), bytes) {
                UdpRx::Receiver { id, meta, payload } => {
                    self.dispatch_receiver(now, id, &meta, payload);
                }
                UdpRx::Queued(h) => self.core.push_event(Event::UdpReadable(UdpSocket(h))),
                UdpRx::Dropped(_) => {}
            },
            PROTO_ICMP6 => self.handle_icmp(now, d, bytes),
            _ => {}
        }
    }

    fn dispatch_receiver(&mut self, now: Instant, id: ReceiverId, meta: &UdpMeta, payload: &[u8]) {
        if id == ReceiverId::MLE {
            let link = self.core.rx_link;
            let mut scratch = [0u8; 1280];
            let _ = self
                .mle
                .receive(&mut self.core, now, meta, link, payload, &mut scratch);
        } else if id == ReceiverId::TMF {
            self.handle_tmf(now, meta, payload);
        }
    }

    // ------------------------------------------------------------ IPv6 out

    /// Drain the queues of outgoing UDP datagrams.
    pub(crate) fn service_outbox(&mut self, now: Instant) -> bool {
        let mut busy = false;
        loop {
            let next = self
                .core
                .mle_out
                .q
                .pop_front()
                .or_else(|| self.sink.q.pop_front());
            let Some(o) = next else { break };
            busy = true;
            let _ = self.send_udp_datagram(now, &o.info, o.src_port, o.dst_port, &o.payload);
        }
        // MPL retransmissions.
        let mut out = [0u8; opentrust_net::header::MAX_DATAGRAM_LEN];
        loop {
            let env = NetDataIp6Env {
                view: self.core.netdata.view(),
                mle: &self.mle,
            };
            let mut ctx = Ctx {
                now,
                rng: &mut self.prng,
                env: &env,
            };
            let Some(tx) = self.core.ip6.poll(&mut ctx, &mut out) else {
                break;
            };
            busy = true;
            let len = tx.len;
            self.send_ip6_mpl(now, &out[..len]);
        }
        busy
    }

    /// Build the UDP header and send through IPv6.
    pub(crate) fn send_udp_datagram(
        &mut self,
        now: Instant,
        info: &SendInfo,
        src_port: u16,
        dst_port: u16,
        payload: &[u8],
    ) -> Result<()> {
        let mut buf = [0u8; opentrust_net::header::MAX_DATAGRAM_LEN];
        let total = UdpHeader::LEN + payload.len();
        let o = buf.get_mut(..total).ok_or(opentrust_core::Error::NoBufs)?;
        UdpHeader {
            src_port,
            dst_port,
            length: total as u16,
            checksum: 0,
        }
        .write(o)?;
        o[UdpHeader::LEN..].copy_from_slice(payload);
        self.ip6_send(now, info, PROTO_UDP, &buf[..total])
    }

    /// `Ip6::send` and the follow-up (local delivery, forwarding).
    pub(crate) fn ip6_send(
        &mut self,
        now: Instant,
        info: &SendInfo,
        proto: u8,
        payload: &[u8],
    ) -> Result<()> {
        let mut out = [0u8; opentrust_net::header::MAX_DATAGRAM_LEN];
        let mut scratch = Scratch::new();
        let sent = {
            let env = NetDataIp6Env {
                view: self.core.netdata.view(),
                mle: &self.mle,
            };
            let mut ctx = Ctx {
                now,
                rng: &mut self.prng,
                env: &env,
            };
            self.core
                .ip6
                .send(&mut ctx, info, proto, payload, &mut out, &mut scratch)?
        };
        self.ip6_outcome(now, &out[..sent.len], &scratch, sent.rx, info.link_security);
        Ok(())
    }

    /// Send a datagram (already processed by IPv6) through the forwarder.
    pub(crate) fn send_ip6(&mut self, now: Instant, dg: &[u8], link_security: bool) -> SendResult {
        self.send_ip6_with(now, dg, link_security, false)
    }

    fn send_ip6_mpl(&mut self, now: Instant, dg: &[u8]) {
        let _ = self.send_ip6_with(now, dg, true, true);
    }

    fn send_ip6_with(
        &mut self,
        now: Instant,
        dg: &[u8],
        link_security: bool,
        mpl: bool,
    ) -> SendResult {
        let mut events: Vec<ResolverEvent, 4> = Vec::new();
        let mut notes = FwdNotes::default();
        let r = with_routing!(self, |r| {
            let mut sink = Sink {
                mac: MacSink {
                    mac: &mut self.core.mac,
                    tx: &mut self.core.mactx,
                },
                notes: &mut notes,
            };
            self.fwd.send_datagram_with(
                now,
                dg,
                link_security,
                mpl,
                &r,
                &mut self.resolver,
                &mut |e| {
                    let _ = events.push(e);
                },
                &mut sink,
            )
        });
        if let SendResult::Dropped(d) = r {
            self.glue.last_drop = Some(d);
        }
        self.after_forwarder(now, events, notes);
        self.sync_src_match();
        r
    }

    // ------------------------------------------------------------ resolver

    /// Act on one event of the address cache.
    pub(crate) fn handle_resolver_event(&mut self, now: Instant, e: ResolverEvent) {
        let own = self.mle.rloc16();
        let Some(p) = opentrust_mesh::address::send_resolver_event(
            e,
            &mut self.resolver,
            &mut self.agent,
            now,
            &mut self.prng,
            &mut self.sink,
            own,
            &self.core,
        ) else {
            return;
        };
        self.resolution_finished(now, p);
    }

    fn resolution_finished(&mut self, now: Instant, p: ResolverEvent) {
        let (eid, ok) = match p {
            ResolverEvent::Resolved { eid } => (eid, true),
            ResolverEvent::ResolutionFailed { eid } => (eid, false),
            _ => return,
        };
        let mut events: Vec<ResolverEvent, 4> = Vec::new();
        let mut notes = FwdNotes::default();
        with_routing!(self, |r| {
            let mut sink = Sink {
                mac: MacSink {
                    mac: &mut self.core.mac,
                    tx: &mut self.core.mactx,
                },
                notes: &mut notes,
            };
            self.fwd.handle_resolved(
                now,
                &eid,
                ok,
                &r,
                &mut self.resolver,
                &mut |e| {
                    let _ = events.push(e);
                },
                &mut sink,
            );
        });
        self.after_forwarder(now, events, notes);
    }

    // ------------------------------------------------------------ MAC glue

    /// Keep the MAC's short -> extended address map and the source match
    /// table in line with the neighbor tables and the indirect queues.
    pub(crate) fn sync_mac_neighbors(&mut self) {
        let mut want: Vec<(u16, [u8; 8]), 40> = Vec::new();
        if let Some(p) = self.mle.parent() {
            let n = &p.router.neighbor;
            let _ = want.push((n.rloc16.0, n.ext_address.0));
        }
        for c in self.mle.children().iter(StateFilter::AnyExceptInvalid) {
            let n = &c.neighbor;
            if n.rloc16 != Rloc16::INVALID {
                let _ = want.push((n.rloc16.0, n.ext_address.0));
            }
        }
        #[cfg(feature = "ftd")]
        for r in self.mle.router_table().iter(StateFilter::AnyExceptInvalid) {
            let n = &r.neighbor;
            if n.rloc16 != Rloc16::INVALID {
                let _ = want.push((n.rloc16.0, n.ext_address.0));
            }
        }
        if want == self.glue.neighbors {
            return;
        }
        self.core.mac.clear_neighbors();
        for (s, e) in &want {
            let _ = self
                .core
                .mac
                .set_neighbor(ShortAddress(*s), opentrust_core::types::ExtAddress(*e));
        }
        self.glue.neighbors = want;
        self.sync_src_match();
    }

    /// The source match table follows the children with queued messages.
    pub(crate) fn sync_src_match(&mut self) {
        let mut want: Vec<Rloc16, 16> = Vec::new();
        for c in self.fwd.indirect.src_match_children() {
            let _ = want.push(c);
        }
        for old in &self.glue.src_match {
            if !want.contains(old) {
                self.core
                    .mac
                    .src_match_remove(Address::Short(ShortAddress(old.0)));
            }
        }
        for new in &want {
            if !self.glue.src_match.contains(new) {
                let _ = self
                    .core
                    .mac
                    .src_match_add(Address::Short(ShortAddress(new.0)));
            }
        }
        self.glue.src_match = want;
    }

    /// An echo reply or other ICMPv6 message for the application.
    fn handle_icmp(&mut self, now: Instant, d: &Delivery, bytes: &[u8]) {
        self.ping_received(now, d, bytes);
    }

    /// Frames dropped by link-layer replay protection so far.
    pub fn replay_drops(&self) -> u32 {
        self.glue.replay_drops
    }

    /// Reason of the last dropped datagram, for diagnostics.
    pub fn last_drop(&self) -> Option<DropReason> {
        self.glue.last_drop
    }
}
