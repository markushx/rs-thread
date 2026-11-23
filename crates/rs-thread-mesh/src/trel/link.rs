//! The TREL link (OT `Trel::Link` and `Trel::Interface`): encapsulates MAC
//! frames in UDP packets for the peers of the peer table, answers unicast
//! packets with acks and tracks pending acks (the "deferred ack" model: the
//! MAC sees a transmission as done at once, the ack comes later).

use core::net::SocketAddrV6;

use rs_thread_core::time::{Duration, Instant};
use rs_thread_core::types::{ExtAddress, ExtPanId};
use rs_thread_core::{Error, Result};

use super::packet::{Header, PacketType, UNICAST_HEADER_LEN};
use super::peer::{PeerTable, write_txt};

/// Largest encapsulated frame (the IPv6 minimum MTU).
pub const MAX_FRAME_LEN: usize = 1280;
/// How long an ack may take; two windows are kept (OT `kAckWaitWindow`).
pub const ACK_WAIT_WINDOW: Duration = Duration::from_millis(750);
/// RSSI reported for frames received over TREL (OT `kRxRssi`).
pub const RX_RSSI: i8 = -20;

/// What the platform provides to the TREL link: the UDP socket and
/// DNS-SD service registration (OT `otPlatTrel*`). Peer discovery results
/// are fed back with [`Trel::peer_discovered`] / [`Trel::peer_removed`].
pub trait TrelPlatform {
    /// UDP port of the local TREL socket (advertised in the service).
    fn local_port(&self) -> u16;
    /// Send one UDP datagram to `dst` on the infrastructure link.
    fn send(&mut self, dst: SocketAddrV6, packet: &[u8]) -> Result<()>;
    /// Start (`true`) or stop DNS-SD browsing for `_trel._udp` and the
    /// receiving of datagrams.
    fn set_enabled(&mut self, _enabled: bool) {}
    /// Register (or re-register) the `_trel._udp` service on `port` with
    /// the given TXT data.
    fn register_service(&mut self, _port: u16, _txt: &[u8]) {}
}

/// Destination of a transmitted frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Dest {
    /// All peers (no ack).
    Broadcast,
    /// One peer (acked).
    Unicast(ExtAddress),
}

/// A received packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rx<'a> {
    /// A frame for the MAC (PSDU without FCS). Report
    /// [`Trel::peer_address_verified`] with `source` and `sender` once the
    /// frame passed link security.
    Frame {
        /// Extended address of the sending peer.
        source: ExtAddress,
        /// UDP address it came from.
        sender: SocketAddrV6,
        /// Channel the sender used.
        channel: u8,
        /// Sent to all peers.
        broadcast: bool,
        /// The 802.15.4 frame.
        frame: &'a [u8],
    },
    /// An ack for a unicast packet sent to `source`.
    Ack {
        /// The acknowledging peer.
        source: ExtAddress,
    },
}

/// Notifications of [`Trel::poll`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Event {
    /// A unicast packet to `peer` was not acknowledged in time (OT deferred
    /// ack timeout); feeds the radio selection.
    AckTimeout {
        /// The peer.
        peer: ExtAddress,
    },
}

/// TREL link state with room for `PEERS` peers.
#[derive(Debug)]
pub struct Trel<const PEERS: usize = 16> {
    ext_address: ExtAddress,
    ext_pan_id: ExtPanId,
    pan_id: u16,
    rx_channel: u8,
    enabled: bool,
    peers: PeerTable<PEERS>,
    broadcast_packet_number: u32,
    ack_deadline: Option<Instant>,
}

impl<const PEERS: usize> Trel<PEERS> {
    /// A disabled link of the device with extended address `ext_address`.
    pub const fn new(ext_address: ExtAddress) -> Self {
        Self {
            ext_address,
            ext_pan_id: ExtPanId([0; 8]),
            pan_id: 0xffff,
            rx_channel: 0,
            enabled: false,
            peers: PeerTable::new(),
            broadcast_packet_number: 0,
            ack_deadline: None,
        }
    }

    /// The peer table.
    pub fn peers(&self) -> &PeerTable<PEERS> {
        &self.peers
    }

    /// `true` while enabled.
    pub const fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Network identity: PAN ID (`0xffff`: accept any) and extended PAN ID
    /// (peers of other networks are ignored). Re-registers the service
    /// when enabled.
    pub fn set_network<P: TrelPlatform>(
        &mut self,
        platform: &mut P,
        pan_id: u16,
        ext_pan_id: ExtPanId,
    ) {
        self.pan_id = pan_id;
        if ext_pan_id != self.ext_pan_id {
            self.ext_pan_id = ext_pan_id;
            // Peers of the old network are stale.
            self.peers.clear();
            if self.enabled {
                self.register(platform);
            }
        }
    }

    /// The channel the MAC receives on (OT `Link::SetRxChannel`).
    pub fn set_rx_channel(&mut self, channel: u8) {
        self.rx_channel = channel;
    }

    fn register<P: TrelPlatform>(&self, platform: &mut P) {
        let mut txt = [0u8; 32];
        if let Ok(n) = write_txt(&self.ext_address, &self.ext_pan_id, &mut txt) {
            platform.register_service(platform.local_port(), &txt[..n]);
        }
    }

    /// Enable the link: start browsing and advertise our service.
    pub fn enable<P: TrelPlatform>(&mut self, platform: &mut P, now: Instant) {
        if !self.enabled {
            self.enabled = true;
            platform.set_enabled(true);
            self.register(platform);
            self.ack_deadline = Some(now.saturating_add(ACK_WAIT_WINDOW));
        }
    }

    /// Disable the link and forget the peers.
    pub fn disable<P: TrelPlatform>(&mut self, platform: &mut P) {
        if self.enabled {
            self.enabled = false;
            platform.set_enabled(false);
            self.peers.clear();
            self.ack_deadline = None;
        }
    }

    /// A peer was discovered (or its service changed). Peers of another
    /// extended PAN ID and ourselves are ignored (`Ok(false)`); `Ok(true)`
    /// if the table changed, [`Error::NoBufs`] if it is full.
    pub fn peer_discovered(
        &mut self,
        ext_address: ExtAddress,
        ext_pan_id: ExtPanId,
        addr: SocketAddrV6,
    ) -> Result<bool> {
        if !self.enabled || ext_address == self.ext_address || ext_pan_id != self.ext_pan_id {
            return Ok(false);
        }
        self.peers.add_or_update(ext_address, ext_pan_id, addr)
    }

    /// A peer's service disappeared.
    pub fn peer_removed(&mut self, ext_address: &ExtAddress) -> bool {
        self.peers.remove(ext_address)
    }

    /// A frame from `source` passed link security: its UDP address is now
    /// trusted and replaces the one from discovery (OT
    /// `CheckPeerAddrOnRxSuccess`).
    pub fn peer_address_verified(&mut self, source: &ExtAddress, sender: SocketAddrV6) {
        if let Some(p) = self.peers.find_mut(source) {
            p.addr = sender;
        }
    }

    /// Transmit `frame` (an 802.15.4 PSDU without FCS) on `channel` with
    /// destination PAN `pan_id`: broadcasts go to every peer, a unicast to
    /// its peer with an ack request. [`Error::InvalidState`] if disabled,
    /// [`Error::NotFound`] for an unknown unicast peer, [`Error::NoBufs`]
    /// for an oversized frame, [`Error::Abort`] if the platform send failed
    /// (broadcast: for every peer).
    pub fn transmit<P: TrelPlatform>(
        &mut self,
        platform: &mut P,
        dest: Dest,
        channel: u8,
        pan_id: u16,
        frame: &[u8],
    ) -> Result<()> {
        if !self.enabled {
            return Err(Error::InvalidState);
        }
        if frame.len() > MAX_FRAME_LEN {
            return Err(Error::NoBufs);
        }
        let mut buf = [0u8; UNICAST_HEADER_LEN + MAX_FRAME_LEN];
        match dest {
            Dest::Unicast(ext) => {
                let peer = self.peers.find_mut(&ext).ok_or(Error::NotFound)?;
                let h = Header {
                    ty: PacketType::Unicast,
                    ack_requested: true,
                    channel,
                    pan_id,
                    packet_number: peer.tx_packet_number,
                    source: self.ext_address,
                    destination: Some(ext),
                };
                peer.tx_packet_number = peer.tx_packet_number.wrapping_add(1);
                let n = h.write(&mut buf)?;
                buf[n..n + frame.len()].copy_from_slice(frame);
                platform
                    .send(peer.addr, &buf[..n + frame.len()])
                    .map_err(|_| Error::Abort)?;
                peer.pending_current = peer.pending_current.saturating_add(1);
                Ok(())
            }
            Dest::Broadcast => {
                let h = Header {
                    ty: PacketType::Broadcast,
                    ack_requested: false,
                    channel,
                    pan_id,
                    packet_number: self.broadcast_packet_number,
                    source: self.ext_address,
                    destination: None,
                };
                self.broadcast_packet_number = self.broadcast_packet_number.wrapping_add(1);
                let n = h.write(&mut buf)?;
                buf[n..n + frame.len()].copy_from_slice(frame);
                let mut ok = self.peers.is_empty();
                for p in self.peers.iter() {
                    ok |= platform.send(p.addr, &buf[..n + frame.len()]).is_ok();
                }
                if ok { Ok(()) } else { Err(Error::Abort) }
            }
        }
    }

    /// A UDP datagram arrived from `sender` (OT `ProcessReceivedPacket`).
    /// Acks are consumed here; unicast packets with an ack request are
    /// acknowledged through `platform`. [`Error::Drop`] for packets that
    /// are not for us (wrong channel, PAN, destination, own packets, disabled
    /// link), [`Error::Parse`] for malformed ones.
    pub fn handle_received<'a, P: TrelPlatform>(
        &mut self,
        platform: &mut P,
        datagram: &'a [u8],
        sender: SocketAddrV6,
    ) -> Result<Rx<'a>> {
        if !self.enabled {
            return Err(Error::Drop);
        }
        let (h, payload) = Header::parse(datagram)?;
        // An ack may come late, on another channel.
        if h.ty != PacketType::Ack && h.channel != self.rx_channel {
            return Err(Error::Drop);
        }
        if self.pan_id != 0xffff && h.pan_id != self.pan_id && h.pan_id != 0xffff {
            return Err(Error::Drop);
        }
        if h.source == self.ext_address {
            return Err(Error::Drop);
        }
        if h.ty != PacketType::Broadcast && h.destination != Some(self.ext_address) {
            return Err(Error::Drop);
        }
        if h.ty == PacketType::Ack {
            let peer = self.peers.find_mut(&h.source).ok_or(Error::Drop)?;
            if peer.pending_previous > 0 {
                peer.pending_previous -= 1;
            } else if peer.pending_current > 0 {
                peer.pending_current -= 1;
            } else {
                return Err(Error::Drop);
            }
            return Ok(Rx::Ack { source: h.source });
        }
        if h.ack_requested {
            let ack = Header {
                ty: PacketType::Ack,
                ack_requested: false,
                channel: h.channel,
                pan_id: h.pan_id,
                packet_number: h.packet_number,
                source: self.ext_address,
                destination: Some(h.source),
            };
            let mut b = [0u8; UNICAST_HEADER_LEN];
            let n = ack.write(&mut b)?;
            let to = self.peers.find(&h.source).map_or(sender, |p| p.addr);
            let _ = platform.send(to, &b[..n]);
        }
        Ok(Rx::Frame {
            source: h.source,
            sender,
            channel: h.channel,
            broadcast: h.ty == PacketType::Broadcast,
            frame: payload,
        })
    }

    /// When [`Trel::poll`] needs to run next.
    pub fn next_deadline(&self) -> Option<Instant> {
        self.ack_deadline
    }

    /// Age the pending acks (OT `Link::HandleTimer`): acks still missing
    /// after two windows are reported as [`Event::AckTimeout`].
    pub fn poll(&mut self, now: Instant, events: &mut impl FnMut(Event)) {
        if self.ack_deadline.is_none_or(|d| now < d) {
            return;
        }
        self.ack_deadline = Some(now.saturating_add(ACK_WAIT_WINDOW));
        for p in self.peers.iter_mut() {
            for _ in 0..p.pending_previous {
                events(Event::AckTimeout {
                    peer: p.ext_address,
                });
            }
            p.pending_previous = p.pending_current;
            p.pending_current = 0;
        }
    }
}
