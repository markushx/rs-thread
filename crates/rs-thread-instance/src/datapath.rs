//! The data path: MAC frames in, 6LoWPAN / mesh forwarding, IPv6, UDP and
//! ICMPv6 delivery; and back out: queued UDP datagrams, IPv6, forwarder,
//! MAC frames.

use heapless::Vec;
use rand_core::{CryptoRng, Rng};
use rs_thread_core::Result;
use rs_thread_core::crypto::{CryptoBackend, SecurityLevel};
use rs_thread_core::time::Instant;
use rs_thread_core::types::{LinkSecurity, Rloc16, ShortAddress};
#[cfg(feature = "csl")]
use rs_thread_mac::frame::CslIe;
use rs_thread_mac::frame::{
    Address, FrameBuilder, FrameType, FrameVersion, KeyIdMode, KeyIdentifier, SecurityHeader,
};
use rs_thread_mac::mac::{Event as MacEvent, FrameBuf, RxFrame, TxHandle};
pub(crate) use rs_thread_mesh::forwarder::Routing;
use rs_thread_mesh::forwarder::{DropReason, FrameSink, MacDest, Rx, SendResult, TxFrame};
pub(crate) use rs_thread_mesh::netdata::consumers::NetDataContexts;
pub(crate) use rs_thread_mesh::netdata::lookup::Lookup;
use rs_thread_mesh::netdata::lookup::NetDataIp6Env;
use rs_thread_mle::endpoint::LinkRxInfo;
use rs_thread_mle::neighbor::StateFilter;
use rs_thread_net::header::{Ipv6Header, PROTO_ICMP6, PROTO_UDP, UdpHeader};
use rs_thread_net::ip6::{Ctx, Delivery, RxMeta, RxOutcome, Scratch, SendInfo};
use rs_thread_net::resolver::ResolverEvent;
use rs_thread_net::udp::{ReceiverId, UdpMeta, UdpRx, UdpRxInfo};
use rs_thread_platform::SettingsStore;

use crate::InstanceCrypto;

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
        // A CSL synchronized sleepy child puts a CSL IE (the MAC fills in
        // the phase) in every frame it sends (Thread section 3.2.6.3).
        #[cfg(feature = "csl")]
        let csl_period = self.mac.csl_period();
        #[cfg(not(feature = "csl"))]
        let csl_period: u16 = 0;
        let csl = csl_period != 0 && f.dst != MacDest::Broadcast;
        let mut b = FrameBuilder::new(&mut buf)
            .frame_type(FrameType::Data)
            .version(
                if csl || f.csl || {
                    #[cfg(feature = "link-metrics")]
                    {
                        self.mac.enh_ack_probing_tracked(mac_address(f.dst))
                    }
                    #[cfg(not(feature = "link-metrics"))]
                    {
                        false
                    }
                } {
                    FrameVersion::V2015
                } else {
                    FrameVersion::V2006
                },
            )
            .sequence(0)
            // Another destination PAN (Discovery Response to a scanner) keeps
            // our own PAN ID as the source PAN ID (OT `SetSource` /
            // `SetDestination`); the scanner learns the PAN from it.
            .dst_pan(rs_thread_core::types::PanId(
                self.tx.pan_id.unwrap_or(self.mac.pan_id().0),
            ))
            .src_pan(self.mac.pan_id())
            .dst(mac_address(f.dst))
            .src(f.src)
            .frame_pending(f.frame_pending)
            .payload(f.payload);
        #[cfg(feature = "csl")]
        if csl {
            b = b.header_ie(CslIe {
                phase: 0,
                period: csl_period,
                rendezvous_time: None,
            });
        }
        // Frame counter and key identifier are filled in by the key manager.
        let key = match f.security {
            LinkSecurity::None => None,
            LinkSecurity::Network => Some(KeyIdentifier::Index(1)),
            LinkSecurity::Mode2 => Some(KeyIdentifier::Source4 {
                source: [0xff; 4],
                index: 0xff,
            }),
            LinkSecurity::Kek => {
                // Key ID mode 0 only to one neighbor by extended address
                // (the CCM* nonce is bound to the extended addresses).
                if !matches!(f.dst, MacDest::Extended(_)) || !matches!(f.src, Address::Extended(_))
                {
                    return Err(rs_thread_core::Error::InvalidArgs);
                }
                Some(KeyIdentifier::Implicit)
            }
        };
        if let Some(key) = key {
            b = b.security(SecurityHeader::new(SecurityLevel::EncMic32, 0, key));
        }
        let n = b.build()?;
        let frame = FrameBuf::from_slice(&buf[..n]).map_err(|_| rs_thread_core::Error::NoBufs)?;
        // A frame for a sleepy child waits in the MAC for the child's poll
        // (the source match table answers the poll with Frame Pending);
        // without this the frame would be sent directly to a sleeping radio.
        // (A frame for a CSL synchronized child waits there as well: the MAC
        // sends it in the child's next sample window.)
        if f.indirect && f.dst != MacDest::Broadcast {
            if f.payload.is_empty() {
                // An empty answer to a poll (nothing queued, or a
                // supervision message): the MAC sends its own empty frame
                // to a poll acknowledged with Frame Pending.
                return Ok(());
            }
            self.tx.handle = self.tx.handle.wrapping_add(1);
            return self.mac.transmit_indirect(
                TxHandle(self.tx.handle),
                mac_address(f.dst),
                &frame,
            );
        }
        // Keep the order: nothing overtakes frames that wait for the MAC.
        if self.tx.pending.is_empty() {
            self.tx.handle = self.tx.handle.wrapping_add(1);
            match self
                .mac
                .transmit_on(TxHandle(self.tx.handle), &frame, self.tx.channel)
            {
                Err(rs_thread_core::Error::NoBufs) => {}
                r => return r,
            }
        }
        self.tx
            .pending
            .push_back((frame, self.tx.channel))
            .map_err(|_| rs_thread_core::Error::NoBufs)
    }

    fn dest_unreachable(&mut self, _invoking: &[u8]) {}
}

#[cfg(all(test, feature = "ftd"))]
pub(crate) fn sink_for_tests<S, C: CryptoBackend, R>(
    core: &mut crate::stack::Core<S, C, R>,
) -> MacSink<'_, C> {
    MacSink {
        mac: &mut core.mac,
        tx: &mut core.mactx,
    }
}

/// Collects what the forwarder asks for besides frames, so it can be done
/// after the forwarder call (it needs the whole instance).
#[derive(Default)]
pub(crate) struct FwdNotes {
    pub unreachable: Vec<Vec<u8, 48>, 2>,
    pub loops: Vec<(Rloc16, Rloc16), 2>,
    /// Datagrams handed to the MAC: the first 48 bytes, the MAC destination
    /// and whether link security was used.
    #[cfg(feature = "history-tracker")]
    pub sent: Vec<(Vec<u8, 48>, MacDest, bool), 4>,
}

pub(crate) struct Sink<'a, 'b, C: CryptoBackend> {
    mac: MacSink<'a, C>,
    notes: &'b mut FwdNotes,
}

impl<C: CryptoBackend> FrameSink for Sink<'_, '_, C> {
    fn transmit(&mut self, f: &TxFrame<'_>) -> Result<()> {
        self.mac.transmit(f)
    }
    #[cfg(feature = "history-tracker")]
    fn datagram_sent(&mut self, head: &[u8], dst: MacDest, security: LinkSecurity) {
        if let Ok(h) = Vec::from_slice(head) {
            let _ = self
                .notes
                .sent
                .push((h, dst, security != LinkSecurity::None));
        }
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

impl<S: SettingsStore, C: InstanceCrypto, R: Rng + CryptoRng> Instance<S, C, R> {
    // ------------------------------------------------------------ MAC events

    /// Handle the MAC's events (received frames, data polls, results).
    #[inline(never)]
    pub(crate) fn service_mac(&mut self, now: Instant) -> bool {
        let mut busy = self.flush_mac_queue();
        while let Some(ev) = self.core.mac.poll_event() {
            busy = true;
            match ev {
                MacEvent::Received(rx) => self.handle_frame(now, rx),
                #[cfg(all(feature = "ftd", feature = "csl"))]
                MacEvent::DataPollReceived {
                    src,
                    csl,
                    secured,
                    lqi,
                    rssi,
                    ..
                } => self.handle_poll(now, src, csl, secured.then_some((lqi, rssi))),
                #[cfg(all(feature = "ftd", not(feature = "csl")))]
                MacEvent::DataPollReceived {
                    src,
                    secured,
                    lqi,
                    rssi,
                    ..
                } => self.handle_poll(now, src, secured.then_some((lqi, rssi))),
                #[cfg(all(feature = "ftd", feature = "csl"))]
                MacEvent::CslChildOutOfSync(Address::Short(s)) => {
                    self.mle.child_csl_desynchronized(Rloc16(s.0));
                }
                #[cfg(feature = "link-metrics")]
                MacEvent::EnhAckLinkMetrics { neighbor, values } => {
                    let ext = self.neighbor_ext(neighbor);
                    #[cfg(feature = "link-metrics-manager")]
                    self.core
                        .lmm
                        .on_enh_ack(&ext, values.link_margin, values.rssi, now);
                    self.core.push_event(Event::EnhAckLinkMetrics {
                        rloc16: match neighbor {
                            Address::Short(s) => Rloc16(s.0),
                            _ => Rloc16::INVALID,
                        },
                        ext,
                        lqi: values.lqi,
                        link_margin: values.link_margin,
                        rssi: values.rssi,
                    });
                }
                MacEvent::ActiveScanResult(r) => {
                    #[cfg(feature = "scan-servers")]
                    if self.beacon_to_server(now, Some((r.pan_id.0, r.channel))) {
                        continue;
                    }
                    self.core.push_event(Event::ActiveScanResult(r));
                }
                MacEvent::ActiveScanDone => {
                    #[cfg(feature = "scan-servers")]
                    if self.beacon_to_server(now, None) {
                        continue;
                    }
                    self.core.push_event(Event::ActiveScanDone);
                }
                MacEvent::EnergyScanResult { channel, max_rssi } => {
                    #[cfg(feature = "scan-servers")]
                    if self.energy_result_to_server(now, Some(max_rssi)) {
                        continue;
                    }
                    self.core
                        .push_event(Event::EnergyScanResult { channel, max_rssi });
                }
                MacEvent::EnergyScanDone => {
                    #[cfg(feature = "scan-servers")]
                    if self.energy_result_to_server(now, None) {
                        continue;
                    }
                    self.core.push_event(Event::EnergyScanDone);
                }
                MacEvent::DataPollSent(res) => {
                    let acked = match res {
                        Ok(_) => Some(true),
                        Err(rs_thread_mac::mac::TxError::NoAck) => Some(false),
                        Err(_) => None,
                    };
                    self.mle.parent_poll_result(&mut self.core, now, acked);
                }
                MacEvent::DataPollTimeout => {}
                MacEvent::TxDone { .. } => {}
                #[allow(unreachable_patterns)]
                _ => {}
            }
        }
        busy
    }

    /// Hand waiting frames to the MAC as room frees up.
    pub(crate) fn flush_mac_queue(&mut self) -> bool {
        let mut busy = false;
        while let Some((f, ch)) = self.core.mactx.pending.front() {
            self.core.mactx.handle = self.core.mactx.handle.wrapping_add(1);
            match self
                .core
                .mac
                .transmit_on(TxHandle(self.core.mactx.handle), f, *ch)
            {
                Err(rs_thread_core::Error::NoBufs) => break,
                _ => {
                    self.core.mactx.pending.pop_front();
                    busy = true;
                }
            }
        }
        busy
    }

    /// A data poll from a sleepy child: release its next frame.
    #[cfg(feature = "ftd")]
    #[cfg(feature = "csl")]
    fn handle_poll(
        &mut self,
        now: Instant,
        src: Address,
        csl: Option<(CslIe, Option<u64>)>,
        link: Option<(Option<u8>, Option<i8>)>,
    ) {
        // Link metrics of the polling child (OT `Neighbor::AggregateLinkMetrics`).
        // A radio without LQI reports 0 (`OT_RADIO_LQI_NONE`).
        #[cfg(feature = "link-metrics")]
        if let Some((lqi, Some(rss))) = link
            && let Some(ext) = self.neighbor_ext_opt(src)
        {
            self.mle.aggregate_link_metrics(
                &ext,
                rs_thread_mle::link_metrics::FrameKind::MacDataRequest,
                lqi.unwrap_or(0),
                rss,
            );
        }
        // A poll with a CSL IE synchronizes the child (OT `Mac::ProcessCsl`).
        #[cfg(feature = "ftd")]
        if let (Some((ie, ts)), Address::Short(s)) = (csl, src)
            && self.mle.child_csl_synchronized(Rloc16(s.0), now)
        {
            let ch = self.mle.child_csl_channel(Rloc16(s.0)).unwrap_or(0);
            let _ = self.core.mac.csl_child_sample(src, ch, ie, ts, now);
        }
        #[cfg(not(feature = "ftd"))]
        let _ = csl;
        #[cfg(feature = "ftd")]
        match src {
            Address::Short(s) => self.mle.child_polled(Some(Rloc16(s.0)), None, now),
            Address::Extended(e) => self.mle.child_polled(None, Some(&e), now),
            Address::None => {}
        }
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
        #[cfg(feature = "ftd")]
        while let Some(c) = self.fwd.take_child_message_sent() {
            self.mle.child_message_sent(c);
        }
        self.sync_src_match();
    }

    #[cfg(not(feature = "csl"))]
    #[cfg_attr(not(feature = "link-metrics"), allow(unused_variables))]
    fn handle_poll(&mut self, now: Instant, src: Address, link: Option<(Option<u8>, Option<i8>)>) {
        // Link metrics of the polling child (OT `Neighbor::AggregateLinkMetrics`).
        #[cfg(feature = "link-metrics")]
        if let Some((lqi, Some(rss))) = link
            && let Some(ext) = self.neighbor_ext_opt(src)
        {
            self.mle.aggregate_link_metrics(
                &ext,
                rs_thread_mle::link_metrics::FrameKind::MacDataRequest,
                lqi.unwrap_or(0),
                rss,
            );
        }
        #[cfg(feature = "ftd")]
        match src {
            Address::Short(s) => self.mle.child_polled(Some(Rloc16(s.0)), None, now),
            Address::Extended(e) => self.mle.child_polled(None, Some(&e), now),
            Address::None => {}
        }
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
        #[cfg(feature = "ftd")]
        while let Some(c) = self.fwd.take_child_message_sent() {
            self.mle.child_message_sent(c);
        }
        self.sync_src_match();
    }

    /// Extended address of a neighbor known by short or extended address.
    #[cfg(any(feature = "csl", feature = "link-metrics"))]
    fn neighbor_ext_opt(&self, a: Address) -> Option<rs_thread_core::types::ExtAddress> {
        match a {
            Address::Extended(e) => Some(e),
            Address::Short(s) => self
                .glue
                .neighbors
                .iter()
                .find(|(r, _)| *r == s.0)
                .map(|(_, e)| rs_thread_core::types::ExtAddress(*e)),
            _ => None,
        }
    }

    #[cfg(feature = "link-metrics")]
    fn neighbor_ext(&self, a: Address) -> rs_thread_core::types::ExtAddress {
        self.neighbor_ext_opt(a)
            .unwrap_or(rs_thread_core::types::ExtAddress([0; 8]))
    }

    /// Hand the frames queued for CSL synchronized children to the MAC.
    #[cfg(all(feature = "ftd", feature = "csl"))]
    fn csl_flush_children(&mut self) {
        let mut notes = FwdNotes::default();
        with_routing!(self, |r| {
            let mut sink = Sink {
                mac: MacSink {
                    mac: &mut self.core.mac,
                    tx: &mut self.core.mactx,
                },
                notes: &mut notes,
            };
            self.fwd.csl_flush(&r, &mut sink);
        });
    }

    /// Process a received data frame.
    fn handle_frame(&mut self, now: Instant, rx: RxFrame) {
        let Ok(f) = rx.parse() else { return };
        let src = f.src_address();
        let dst = f.dst_address();
        let payload = f.payload();
        // The security class: only key ID mode 1 counts as link-layer
        // secured above the MAC; mode 2 uses a public key; mode 0 (the KEK)
        // is only for the Joiner Entrust exchange (`commissioning`).
        let security = match rx.security.as_ref().map(|s| s.key_id_mode) {
            None => LinkSecurity::None,
            Some(KeyIdMode::Index) => LinkSecurity::Network,
            Some(KeyIdMode::Implicit) => LinkSecurity::Kek,
            Some(KeyIdMode::Source4) => LinkSecurity::Mode2,
            Some(KeyIdMode::Source8) => return,
        };
        let link_security = security.is_network();
        if security == LinkSecurity::Kek
            && !self.accept_kek_frame(src, dst, rx.security.as_ref().map(|s| s.frame_counter))
        {
            return;
        }
        // Link-layer replay protection (Thread 1.4.1 section 7.2.1.2).
        self.sync_key_reset();
        if let Some(sec) = &rx.security
            && let Some(ks) = sec.key_sequence
        {
            match self.mle.check_link_frame(src, ks, sec.frame_counter) {
                Err(_) => {
                    self.glue.replay_drops = self.glue.replay_drops.wrapping_add(1);
                    return;
                }
                // A frame from a neighbor with a newer key sequence moves
                // this device to it, subject to the key switch guard (OT
                // `Mac::ProcessReceiveSecurity`).
                Ok(true) if link_security => {
                    self.core.mac.security_mut().on_rx_key_sequence(ks, now);
                }
                Ok(_) => {}
            }
        }
        if link_security {
            self.mle.data_frame_received(src, now);
        }
        self.core.rx_link = LinkRxInfo {
            rss: rx.rssi,
            lqi: rx.lqi,
            pan_id: f.pan_id().map(|p| p.0),
            channel: Some(rx.channel),
        };
        // Link metrics of the sender (OT `Neighbor::AggregateLinkMetrics`).
        #[cfg(feature = "link-metrics")]
        if link_security
            && let Some(rss) = rx.rssi
            && let Some(ext) = self.neighbor_ext_opt(src)
        {
            self.mle.aggregate_link_metrics(
                &ext,
                rs_thread_mle::link_metrics::FrameKind::MacData,
                rx.lqi.unwrap_or(0),
                rss,
            );
        }
        // A frame with a CSL IE synchronizes the sending child (OT
        // `Mac::ProcessCsl`).
        #[cfg(all(feature = "ftd", feature = "csl"))]
        let csl_child = match src {
            Address::Short(s) => Some(Rloc16(s.0)),
            // A child that has no short address in the frame (a Child Update
            // Request goes out with the extended source address).
            Address::Extended(e) => self.mle.child_rloc_by_ext(&e),
            Address::None => None,
        };
        #[cfg(all(feature = "ftd", feature = "csl"))]
        if link_security
            && let Some(ie) = f.csl_ie()
            && let Some(child) = csl_child
            && self.mle.child_csl_synchronized(child, now)
        {
            // The MAC starts tracking the child with this frame.
            let ch = self.mle.child_csl_channel(child).unwrap_or(0);
            let _ = self.core.mac.csl_child_sample(
                Address::Short(ShortAddress(child.0)),
                ch,
                ie,
                rx.timestamp_us,
                now,
            );
            self.csl_flush_children();
        }
        // Any secure frame from the parent is a sign of life.
        if link_security
            && let (Address::Short(s), Some(p)) = (src, self.mle.parent())
            && s.0 == p.router.neighbor.rloc16.0
        {
            self.mle.parent_frame_received(now);
        }
        // The mesh source of a mesh header frame (the short MAC source
        // otherwise), to find children that moved (OT
        // `UpdateEidRlocCacheAndStaleChild`).
        let mesh_src = match rs_thread_lowpan::forward::parse_frame(payload) {
            Ok(rs_thread_lowpan::forward::LowpanFrame::Mesh { header, .. })
                if !dst.is_broadcast() =>
            {
                Some(Rloc16(header.source))
            }
            Ok(rs_thread_lowpan::forward::LowpanFrame::Mesh { .. }) => None,
            _ => match src {
                Address::Short(s) if !dst.is_broadcast() => Some(Rloc16(s.0)),
                _ => None,
            },
        };
        let mut dg = [0u8; rs_thread_mesh::forwarder::MTU];
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
                security,
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
            #[cfg(feature = "history-tracker")]
            {
                let neighbor = match src {
                    Address::Short(s) => s.0,
                    Address::Extended(e) => self
                        .glue
                        .neighbors
                        .iter()
                        .find(|(_, x)| *x == e.0)
                        .map_or(0xfffe, |(r, _)| *r),
                    Address::None => 0xfffe,
                };
                self.glue.history.record_message(
                    now,
                    false,
                    &dg[..dg_len],
                    neighbor,
                    rx.rssi,
                    link_security,
                );
            }
            #[cfg(feature = "ftd")]
            if let (Some(ms), Ok(h)) = (mesh_src, Ipv6Header::parse(&dg[..dg_len])) {
                self.mle.remove_child_that_moved(&mut self.core, &h.src, ms);
            }
            #[cfg(not(feature = "ftd"))]
            let _ = mesh_src;
            if security == LinkSecurity::Kek {
                self.receive_kek_datagram(now, src, &dg[..dg_len]);
                return;
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
        #[cfg(feature = "history-tracker")]
        for (head, dst, secure) in &notes.sent {
            let neighbor = match dst {
                MacDest::Short(s) => s.0,
                MacDest::Broadcast => 0xffff,
                MacDest::Extended(e) => self
                    .glue
                    .neighbors
                    .iter()
                    .find(|(_, x)| *x == e.0)
                    .map_or(0xfffe, |(r, _)| *r),
            };
            self.glue
                .history
                .record_message(now, true, head, neighbor, None, *secure);
        }
        for inv in notes.unreachable {
            let mut out = [0u8; 256];
            if let Ok(n) = self.core.ip6.build_error(
                now,
                &inv,
                (
                    rs_thread_net::icmp6::TYPE_DST_UNREACH,
                    rs_thread_net::icmp6::CODE_DST_UNREACH_NO_ROUTE,
                    0,
                ),
                &mut out,
            ) {
                self.send_ip6(now, &out[..n], true);
            }
        }
        #[cfg(feature = "ftd")]
        {
            for (from, dest) in notes.loops {
                self.mle
                    .resolve_routing_loop(&mut self.core, now, from, dest);
            }
            while let Some(c) = self.fwd.take_child_message_sent() {
                self.mle.child_message_sent(c);
            }
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
        if self.cm.joiner_port == Some(u.dst_port) {
            // Joiner DTLS records: only between link-local neighbors.
            return h.src.is_unicast_link_local() && h.dst.is_unicast_link_local();
        }
        u.dst_port == rs_thread_net::udp::MLE_UDP_PORT
            || self.glue.unsecure_ports.contains(&u.dst_port)
    }

    /// Act on the result of [`rs_thread_net::ip6::Ip6::handle`] / `send`.
    pub(crate) fn ip6_outcome(
        &mut self,
        now: Instant,
        dg: &[u8],
        scratch: &Scratch,
        out: RxOutcome,
        link_security: impl Into<LinkSecurity>,
    ) {
        let link_security = link_security.into();
        if let Some(d) = out.deliver {
            let bytes = d.bytes(dg, scratch);
            self.deliver(now, &d, bytes);
        }
        if out.forward_thread {
            self.send_ip6(now, dg, link_security);
        }
        if out.inner_forward_thread {
            let mut inner = [0u8; rs_thread_mesh::forwarder::MTU];
            let src = scratch.inner();
            if let Ok(h) = Ipv6Header::parse(src) {
                let n = (Ipv6Header::LEN + usize::from(h.payload_len)).min(inner.len());
                inner[..n].copy_from_slice(&src[..n]);
                self.send_ip6(now, &inner[..n], link_security);
            }
        }
        if let Some(reply) = out.reply(scratch) {
            let own =
                Ipv6Header::parse(reply).is_ok_and(|h| self.core.ip6.netif.has_unicast(&h.dst));
            if own {
                self.ip6_loopback(now, reply);
            } else {
                self.send_ip6(now, reply, true);
            }
        }
    }

    /// Process a datagram this device sent to one of its own addresses (the
    /// echo reply to a ping of an own address): it never leaves the device.
    fn ip6_loopback(&mut self, now: Instant, dg: &[u8]) {
        let mut buf = [0u8; rs_thread_net::header::MAX_DATAGRAM_LEN];
        let Some(b) = buf.get_mut(..dg.len()) else {
            return;
        };
        b.copy_from_slice(dg);
        let mut scratch = Scratch::new();
        let rx = {
            let env = NetDataIp6Env {
                view: self.core.netdata.view(),
                mle: &self.mle,
            };
            let mut ctx = Ctx {
                now,
                rng: &mut self.prng,
                env: &env,
            };
            let meta = RxMeta {
                origin: rs_thread_core::message::Origin::HostTrusted,
                link_security: true,
                multicast_loop: false,
            };
            self.core.ip6.handle(&mut ctx, meta, b, &mut scratch)
        };
        if let Ok(rx) = rx {
            if let Some(d) = rx.deliver {
                let bytes = d.bytes(&buf[..dg.len()], &scratch);
                self.deliver(now, &d, bytes);
            }
        }
    }

    /// Local delivery of a UDP or ICMPv6 payload.
    fn deliver(&mut self, now: Instant, d: &Delivery, bytes: &[u8]) {
        match d.proto {
            PROTO_UDP => match self.udp.handle_datagram(&UdpRxInfo::from(d), bytes) {
                UdpRx::Receiver { id, meta, payload } => {
                    self.dispatch_receiver(now, id, &meta, payload);
                }
                UdpRx::Queued(h) => {
                    #[cfg(feature = "border-router")]
                    let dhcp6_handled = self.dhcp6_rx(now, h);
                    #[cfg(not(feature = "border-router"))]
                    let dhcp6_handled = false;
                    if !dhcp6_handled && !self.dns_srp_rx(now, h) {
                        self.core.push_event(Event::UdpReadable(UdpSocket(h)));
                    }
                }
                UdpRx::Dropped(_) => {}
            },
            PROTO_ICMP6 => self.handle_icmp(now, d, bytes),
            _ => {}
        }
    }

    fn dispatch_receiver(&mut self, now: Instant, id: ReceiverId, meta: &UdpMeta, payload: &[u8]) {
        if id == crate::cm_io::JOINER_RECEIVER {
            self.receive_joiner_port(now, meta, payload);
            return;
        }
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
    #[inline(never)]
    pub(crate) fn service_outbox(&mut self, now: Instant) -> bool {
        let mut busy = false;
        {
            let mut payload = [0u8; crate::MAX_UDP_PAYLOAD];
            loop {
                let next = match self.core.mle_out.pop_front(&mut payload) {
                    Some(n) => Some(n),
                    None => self.sink.pop_front(&mut payload),
                };
                let Some((o, len)) = next else { break };
                busy = true;
                self.core.mactx.channel = o.tx.0;
                self.core.mactx.pan_id = o.tx.1;
                let security = o.security.unwrap_or(o.info.link_security.into());
                let _ = self.send_udp_datagram(
                    now,
                    &o.info,
                    security,
                    o.src_port,
                    o.dst_port,
                    &payload[..len],
                );
                self.core.mactx.channel = None;
                self.core.mactx.pan_id = None;
            }
        }
        // MPL retransmissions.
        let mut out = [0u8; rs_thread_net::header::MAX_DATAGRAM_LEN];
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
            self.send_ip6_mpl(now, &out[..len], tx.retransmission);
        }
        busy
    }

    /// Build the UDP header and send through IPv6.
    pub(crate) fn send_udp_datagram(
        &mut self,
        now: Instant,
        info: &SendInfo,
        security: LinkSecurity,
        src_port: u16,
        dst_port: u16,
        payload: &[u8],
    ) -> Result<()> {
        let mut buf = [0u8; rs_thread_net::header::MAX_DATAGRAM_LEN];
        let total = UdpHeader::LEN + payload.len();
        let o = buf.get_mut(..total).ok_or(rs_thread_core::Error::NoBufs)?;
        UdpHeader {
            src_port,
            dst_port,
            length: total as u16,
            checksum: 0,
        }
        .write(o)?;
        o[UdpHeader::LEN..].copy_from_slice(payload);
        self.ip6_send_sec(now, info, security, PROTO_UDP, &buf[..total])
    }

    /// `Ip6::send` and the follow-up (local delivery, forwarding).
    pub(crate) fn ip6_send(
        &mut self,
        now: Instant,
        info: &SendInfo,
        proto: u8,
        payload: &[u8],
    ) -> Result<()> {
        self.ip6_send_sec(now, info, info.link_security.into(), proto, payload)
    }

    /// [`ip6_send`](Self::ip6_send) with the link-layer security of the
    /// frames (key ID mode 0 / 2 for the Joiner Entrust / MLE Announce).
    pub(crate) fn ip6_send_sec(
        &mut self,
        now: Instant,
        info: &SendInfo,
        security: LinkSecurity,
        proto: u8,
        payload: &[u8],
    ) -> Result<()> {
        let mut out = [0u8; rs_thread_net::header::MAX_DATAGRAM_LEN];
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
        self.ip6_outcome(now, &out[..sent.len], &scratch, sent.rx, security);
        Ok(())
    }

    /// Send a datagram (already processed by IPv6) through the forwarder.
    pub(crate) fn send_ip6(
        &mut self,
        now: Instant,
        dg: &[u8],
        security: impl Into<LinkSecurity>,
    ) -> SendResult {
        self.send_ip6_with(now, dg, security.into(), false)
    }

    fn send_ip6_mpl(&mut self, now: Instant, dg: &[u8], retransmission: bool) {
        let _ = self.send_ip6_with(now, dg, LinkSecurity::Network, retransmission);
    }

    fn send_ip6_with(
        &mut self,
        now: Instant,
        dg: &[u8],
        link_security: LinkSecurity,
        mpl: bool,
    ) -> SendResult {
        // A datagram longer than the IPv6 minimum MTU leaves as fragments
        // (OT `FragmentDatagram`).
        #[cfg(feature = "ip6-fragmentation")]
        if dg.len() > rs_thread_net::header::MIN_MTU {
            let id = self.prng.next_u32();
            let mut result = SendResult::Sent;
            let r = rs_thread_net::fragment::fragment_datagram(dg, id, |f| {
                let r = self.send_ip6_with(now, f, link_security, mpl);
                if !matches!(result, SendResult::Dropped(_)) {
                    result = r;
                }
                Ok(())
            });
            return match r {
                Ok(()) => result,
                Err(_) => SendResult::Dropped(DropReason::Invalid),
            };
        }
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
        #[cfg(feature = "history-tracker")]
        if let SendResult::Indirect(c) = r {
            self.glue.history.record_message(
                now,
                true,
                dg,
                c.0,
                None,
                link_security != LinkSecurity::None,
            );
        }
        self.after_forwarder(now, events, notes);
        self.sync_src_match();
        r
    }

    /// Send an empty data frame (acknowledged, link-secured) to the parent
    /// (OT `otLinkSendEmptyData`, reference device feature). Errors:
    /// [`rs_thread_core::Error::InvalidState`] unless this is a sleepy child
    /// with a parent.
    pub fn send_mac_empty_data(&mut self, now: Instant) -> Result<()> {
        if self.mle.is_rx_on_when_idle() {
            return Err(rs_thread_core::Error::InvalidState);
        }
        let parent = self
            .mle
            .parent()
            .map(|p| p.router.neighbor.rloc16)
            .filter(|r| *r != Rloc16::INVALID)
            .ok_or(rs_thread_core::Error::InvalidState)?;
        let src = Address::Short(self.core.mac.short_address());
        let mut notes = FwdNotes::default();
        let mut sink = Sink {
            mac: MacSink {
                mac: &mut self.core.mac,
                tx: &mut self.core.mactx,
            },
            notes: &mut notes,
        };
        let r = sink.transmit(&TxFrame {
            src,
            dst: MacDest::Short(parent),
            payload: &[],
            security: LinkSecurity::Network,
            frame_pending: false,
            indirect: false,
            csl: false,
            radio: rs_thread_mesh::radio::RadioLink::Ieee802154,
        });
        self.poll(now);
        r
    }

    /// Send a data poll now (OT `otLinkSendDataRequest`).
    pub fn send_mac_data_request(&mut self, now: Instant) -> Result<()> {
        self.core.mac.send_data_poll(now)?;
        self.poll(now);
        Ok(())
    }

    // ------------------------------------------------------------ resolver

    /// Act on one event of the address cache.
    pub(crate) fn handle_resolver_event(&mut self, now: Instant, e: ResolverEvent) {
        let own = self.mle.rloc16();
        let Some(p) = rs_thread_mesh::address::send_resolver_event(
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
        let keep_alive = self.mle.parent().is_some_and(|p| {
            p.router.neighbor.version >= rs_thread_mle::consts::THREAD_VERSION_1_2
        });
        self.core.mac.set_parent_enhanced_keep_alive(keep_alive);
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
                .set_neighbor(ShortAddress(*s), rs_thread_core::types::ExtAddress(*e));
        }
        self.glue.neighbors = want;
        self.sync_src_match();
    }

    /// The source match table follows the children with queued messages.
    pub(crate) fn sync_src_match(&mut self) {
        // A child is matched by its short address and by its extended one (a
        // child polls its parent by extended address until it has attached).
        let mut want: Vec<(Rloc16, Option<rs_thread_core::types::ExtAddress>), 16> = Vec::new();
        for c in self.fwd.indirect.src_match_children() {
            let ext = self
                .mle
                .children()
                .find_by_rloc(c, StateFilter::AnyExceptInvalid)
                .map(|ch| ch.neighbor.ext_address);
            let _ = want.push((c, ext));
        }
        for old in &self.glue.src_match {
            if !want.contains(old) {
                self.core
                    .mac
                    .src_match_remove(Address::Short(ShortAddress(old.0.0)));
                if let Some(e) = old.1 {
                    self.core.mac.src_match_remove(Address::Extended(e));
                }
            }
        }
        for new in &want {
            if !self.glue.src_match.contains(new) {
                let _ = self
                    .core
                    .mac
                    .src_match_add(Address::Short(ShortAddress(new.0.0)));
                if let Some(e) = new.1 {
                    let _ = self.core.mac.src_match_add(Address::Extended(e));
                }
            }
        }
        self.glue.src_match = want;
    }

    /// An echo reply or other ICMPv6 message for the application.
    fn handle_icmp(&mut self, now: Instant, d: &Delivery, bytes: &[u8]) {
        #[cfg(feature = "ping")]
        self.ping_received(now, d, bytes);
        #[cfg(not(feature = "ping"))]
        let _ = (now, d, bytes);
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
