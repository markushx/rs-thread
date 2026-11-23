//! Driving the commissioning roles: timers, the Joiner UDP port, key ID
//! mode 0 (KEK) frames and the relay messages of the TMF agent.

use rand_core::{CryptoRng, Rng};
use rs_thread_coap::endpoint::Peer;
use rs_thread_core::time::Instant;
use rs_thread_core::types::{ExtAddress, LinkSecurity, ipv6};
use rs_thread_mac::frame::Address;
use rs_thread_meshcop::dataset::DatasetType;
use rs_thread_meshcop::joiner::{JOINER_UDP_PORT, JoinerState};
use rs_thread_net::header::{Ipv6Header, PROTO_UDP, UdpHeader};
use rs_thread_net::udp::UdpMeta;
use rs_thread_platform::SettingsStore;

use crate::cm_io::JoinerAction;
use crate::{Instance, InstanceCrypto};

/// Build a `LinkIo` from disjoint fields of the instance.
macro_rules! link_io {
    ($self:ident) => {
        $crate::cm_io::LinkIo {
            mac: &mut $self.core.mac,
            ip6: &mut $self.core.ip6,
            ext: &mut $self.core.ext,
            out: &mut $self.sink,
            udp: &mut $self.udp,
            joiner_port: &mut $self.cm.joiner_port,
            kek_rx_fc: &mut $self.cm.kek_rx_fc,
            actions: &mut $self.cm.actions,
        }
    };
}
#[allow(unused_imports)]
pub(crate) use link_io;

impl<S: SettingsStore, C: InstanceCrypto, R: Rng + CryptoRng> Instance<S, C, R> {
    /// Timers and pending work of the commissioning roles.
    #[inline(never)]
    pub(crate) fn service_commissioning(&mut self, now: Instant) -> bool {
        let before = self.sink.len();
        // Joiner.
        let joining = self.cm.joiner.state() != JoinerState::Idle;
        self.core.joiner_discovering = self.cm.joiner.state() == JoinerState::Discover;
        if joining {
            while let Some((info, tlvs)) = self.core.disc_rx.pop_front() {
                self.cm.joiner.handle_discovery_response(&info, &tlvs);
            }
            let mut io = link_io!(self);
            self.cm.joiner.poll(now, &mut self.core.rng, &mut io);
        } else {
            self.core.disc_rx.clear();
        }
        let mut busy = self.apply_joiner_actions(now);
        #[cfg(feature = "ftd")]
        self.service_joiner_router(now);
        self.service_commissioner_roles(now);
        busy |= self.sink.len() != before;
        busy
    }

    /// Carry out what the Joiner asked for.
    pub(crate) fn apply_joiner_actions(&mut self, now: Instant) -> bool {
        let mut busy = false;
        while let Some(a) = self.cm.actions.pop_front() {
            busy = true;
            match a {
                JoinerAction::Discovery(ch, pan, tlv) => {
                    // Listen on the scanned channel for the responses (OT
                    // `DiscoverScanner` tunes the MAC).
                    let _ = self.core.mac.set_channel(ch);
                    let _ = self
                        .mle
                        .send_discovery_request(&mut self.core, pan, Some(ch), &tlv);
                }
                JoinerAction::Save(ds) => {
                    let (m, mut env) = self.core.ds();
                    let _ = m.save_local(&mut env, now, DatasetType::Active, &ds);
                    self.sync_key_reset();
                }
                JoinerAction::Event(e) => self.joiner_event(now, e),
            }
        }
        busy
    }

    #[cfg(feature = "ftd")]
    fn service_joiner_router(&mut self, now: Instant) {
        let role = self.mle.role();
        let is_ftd = role.is_attached() && self.mle.is_full_thread_device();
        {
            let cd = self.core.netdata.view().commissioning_data();
            let mut io = crate::cm_io::LinkIo {
                mac: &mut self.core.mac,
                ip6: &mut self.core.ip6,
                ext: &mut self.core.ext,
                out: &mut self.sink,
                udp: &mut self.udp,
                joiner_port: &mut self.cm.joiner_port,
                kek_rx_fc: &mut self.cm.kek_rx_fc,
                actions: &mut self.cm.actions,
            };
            // A Joiner owns the port while joining.
            if self.cm.joiner.state() == JoinerState::Idle {
                self.cm.jr.update(is_ftd, cd, &mut io);
            }
        }
        if self.cm.jr.next_deadline().is_some_and(|d| d <= now) {
            let active = self.core.datasets.read(DatasetType::Active, now);
            let ks = self.core.mac.security().key_sequence();
            let mut io = link_io!(self);
            while self
                .cm
                .jr
                .poll(now, &mut self.prng, &mut io, active.as_ref(), ks)
                .is_some()
            {}
        }
    }

    /// Should a key ID mode 0 frame from `src` to `dst` with `fc` reach the
    /// commissioning code? Only from the one peer of a running KEK
    /// exchange (the Joiner Router of our Joiner in the Entrust state, or
    /// the Joiner whose Joiner Entrust we sent), addressed to us by
    /// extended address, with a frame counter above the last accepted one
    /// under the current KEK (OT checks no counter for key ID mode 0).
    pub(crate) fn accept_kek_frame(&mut self, src: Address, dst: Address, fc: Option<u32>) -> bool {
        let ok = match (src, dst, fc) {
            (Address::Extended(s), Address::Extended(d), Some(fc)) => {
                d == self.core.ext
                    && self.core.mac.security().kek().is_some()
                    && self.kek_peer() == Some(s)
                    && self.cm.kek_rx_fc.is_none_or(|last| fc > last)
                    && {
                        self.cm.kek_rx_fc = Some(fc);
                        true
                    }
            }
            _ => false,
        };
        if !ok {
            self.cm.kek_drops = self.cm.kek_drops.wrapping_add(1);
        }
        ok
    }

    /// The extended address of the only peer key ID mode 0 frames are
    /// accepted from.
    fn kek_peer(&self) -> Option<ExtAddress> {
        if matches!(
            self.cm.joiner.state(),
            JoinerState::Entrust | JoinerState::Joined
        ) {
            return self.cm.joiner.joiner_router().map(|c| c.ext_address);
        }
        #[cfg(feature = "ftd")]
        if let Some(j) = self.cm.jr.entrust_in_flight() {
            return Some(ipv6::iid(&j).to_ext_address());
        }
        None
    }

    /// A reassembled datagram received with key ID mode 0 from `mac_src`:
    /// only UDP from the sender's link-local address (bound to its MAC
    /// address) to our link-local address and the TMF port, with a valid
    /// checksum, goes to the Joiner / Joiner Router; everything else is
    /// dropped.
    #[cfg_attr(not(feature = "ftd"), allow(clippy::needless_return))]
    pub(crate) fn receive_kek_datagram(&mut self, now: Instant, mac_src: Address, dg: &[u8]) {
        let Address::Extended(src_ext) = mac_src else {
            return;
        };
        let Ok(h) = Ipv6Header::parse(dg) else { return };
        let body = &dg[Ipv6Header::LEN.min(dg.len())..];
        let len = usize::from(h.payload_len);
        let ok_hdr = h.next_header == PROTO_UDP
            && body.len() >= len
            && h.src == ipv6::link_local(&src_ext)
            && h.dst == ipv6::link_local(&self.core.ext);
        if !ok_hdr {
            self.cm.kek_drops = self.cm.kek_drops.wrapping_add(1);
            return;
        }
        let udp = &body[..len];
        let Ok(u) = UdpHeader::parse(udp) else { return };
        if u.dst_port != rs_thread_coap::tmf::UDP_PORT
            || !rs_thread_net::checksum::verify(&h.src, &h.dst, PROTO_UDP, udp)
        {
            self.cm.kek_drops = self.cm.kek_drops.wrapping_add(1);
            return;
        }
        let payload = &udp[UdpHeader::LEN..];
        let peer = Peer::new(h.src, u.src_port);
        if matches!(
            self.cm.joiner.state(),
            JoinerState::Entrust | JoinerState::Joined
        ) {
            let mut io = link_io!(self);
            self.cm.joiner.handle_kek_datagram(
                now,
                &mut io,
                LinkSecurity::Kek,
                &peer,
                &h.dst,
                payload,
            );
            self.apply_joiner_actions(now);
            return;
        }
        #[cfg(feature = "ftd")]
        {
            let mut io = link_io!(self);
            let _ = self.cm.jr.handle_kek_datagram(
                now,
                &mut io,
                LinkSecurity::Kek,
                &peer,
                &h.dst,
                payload,
            );
        }
    }

    /// A datagram for the Joiner UDP port (accepted without link security
    /// from a link-local source only, see `unsecure_allowed`).
    #[cfg_attr(not(feature = "ftd"), allow(clippy::needless_return))]
    pub(crate) fn receive_joiner_port(&mut self, now: Instant, meta: &UdpMeta, payload: &[u8]) {
        let peer = Peer::new(*meta.peer.ip(), meta.peer.port());
        if self.cm.joiner.state() != JoinerState::Idle {
            if meta.local.port() == JOINER_UDP_PORT {
                let mut io = link_io!(self);
                self.cm
                    .joiner
                    .handle_udp(now, &mut self.core.rng, &mut io, &peer, payload);
                self.apply_joiner_actions(now);
            }
            return;
        }
        #[cfg(feature = "ftd")]
        {
            let ba = self
                .core
                .netdata
                .view()
                .commissioning_data()
                .and_then(|c| rs_thread_meshcop::tlv::Tlvs(c).border_agent_locator().ok());
            let mlp = self.core.cfg.cur.mesh_local_prefix;
            let own = self.mle.rloc16();
            let _ = self.cm.jr.handle_joiner_datagram(
                &mut self.agent,
                now,
                &mut self.prng,
                &mut self.sink,
                &mlp,
                own,
                ba,
                &peer,
                meta.local.port(),
                payload,
            );
        }
    }

    /// A Joiner notification: report the result; after a successful join
    /// the credentials of the Joiner Entrust are the Active Dataset and
    /// Thread is started (attach with the received network key).
    fn joiner_event(&mut self, now: Instant, e: rs_thread_meshcop::joiner::JoinerEvent) {
        use rs_thread_meshcop::joiner::JoinerEvent;
        match e {
            JoinerEvent::State(s) => {
                self.core.joiner_discovering = s == JoinerState::Discover;
                self.core.push_event(crate::Event::JoinerState(s));
            }
            JoinerEvent::Done(r) => {
                self.core.joiner_discovering = false;
                self.core.push_event(crate::Event::JoinerResult(r));
                if r.is_ok() && self.ip6_enabled && self.mle.role() == rs_thread_mle::Role::Disabled
                {
                    let _ = self.thread_start(now);
                }
            }
        }
    }

    /// Key ID mode 0 frames dropped so far (wrong peer, replayed, no KEK
    /// exchange running, or not a Joiner Entrust datagram).
    pub fn kek_drops(&self) -> u32 {
        self.cm.kek_drops
    }
}
