//! UDP (RFC 768 over IPv6): a fixed-capacity socket table and the hooks for
//! internal receivers (OT `net/udp6.cpp`).
//!
//! # Sans-IO shape
//!
//! [`UdpSockets`] never touches the network. Both directions go through
//! [`crate::ip6::Ip6`]:
//!
//! - **Receive:** pass the UDP bytes of an [`crate::ip6::Delivery`] to
//!   [`UdpSockets::handle_datagram`]. The result is either
//!   [`UdpRx::Receiver`] (an internal receiver such as MLE or TMF claimed the
//!   port; the payload is returned for the caller to dispatch),
//!   [`UdpRx::Queued`] (copied into a socket's bounded receive queue) or
//!   [`UdpRx::Dropped`].
//! - **Send:** [`UdpSockets::build_send`] applies OT's `Udp::SendTo` rules
//!   (peer/source defaults from the socket, implicit bind to an ephemeral
//!   port) and writes `[UDP header | payload]`; hand the bytes and the
//!   returned [`crate::ip6::SendInfo`] to [`crate::ip6::Ip6::send`].
//!
//! # Mapping to `edge-nal` (async facade)
//!
//! The facade owns a `UdpSockets` (behind a blocking mutex) next to the
//! stack and wakes tasks whenever [`UdpSockets::rx_epoch`] changes after a
//! `handle_datagram` call:
//!
//! | edge-nal                              | this module                                   |
//! |---------------------------------------|-----------------------------------------------|
//! | `UdpBind::bind(local)`                | [`UdpSockets::open`] + [`UdpSockets::bind`]   |
//! | `UdpConnect::connect(local, remote)`  | `open` + `bind` + [`UdpSockets::connect`]     |
//! | `UdpReceive::receive(buf)`            | loop { [`UdpSockets::recv`]; wait for epoch } |
//! | `Readable::readable()`                | wait until [`UdpSockets::has_data`]           |
//! | `UdpSend::send(remote, data)`         | `build_send` + `Ip6::send` + mesh forwarder   |
//! | `MulticastV6::join/leave`             | `Netif::subscribe_external/unsubscribe_external` (socket independent, as in OT) |
//! | `UdpSplit`                            | two views of one [`SocketHandle`]             |
//! | socket drop                           | [`UdpSockets::close`]                         |
//!
//! `recv` reports the local (destination) address, the peer, the hop limit
//! and the link-security flag in [`UdpMeta`], matching what
//! `edge_nal_openthread::OtUdpSocket::receive` returns (`(len, remote)`)
//! plus the extra metadata rs-matter does not need but the stack does.
//! `rs-matter-embassy` allocates one UDP socket on Thread, so a facade
//! with `N = 1..2` suffices.

use core::net::{Ipv6Addr, SocketAddrV6};

use opentrust_core::{Error, Result};

use crate::header::{PROTO_UDP, UdpHeader};
use crate::ip6::{SendInfo, TMF_UDP_PORT};
use crate::netif::Netif;

/// First ephemeral port (OT `kDynamicPortMin`).
pub const EPHEMERAL_PORT_MIN: u16 = 49152;
/// Last ephemeral port (OT `kDynamicPortMax`).
pub const EPHEMERAL_PORT_MAX: u16 = 65535;
/// Lowest SRP server port (never handed out as ephemeral port).
pub const SRP_SERVER_PORT_MIN: u16 = 53535;
/// Highest SRP server port.
pub const SRP_SERVER_PORT_MAX: u16 = 53554;
/// MLE UDP port.
pub const MLE_UDP_PORT: u16 = 19788;

/// A socket in a [`UdpSockets`] table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct SocketHandle(u8);

/// Identifier of an internal receiver, chosen by the registrant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct ReceiverId(pub u8);

impl ReceiverId {
    /// Conventional id for the MLE receiver (port [`MLE_UDP_PORT`]).
    pub const MLE: Self = Self(0);
    /// Conventional id for the TMF receiver (port [`TMF_UDP_PORT`]).
    pub const TMF: Self = Self(1);
}

/// Per-packet metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UdpMeta {
    /// The sender (address and port).
    pub peer: SocketAddrV6,
    /// The local address the datagram was sent to (may be multicast) and the
    /// destination port.
    pub local: SocketAddrV6,
    /// Hop limit of the datagram.
    pub hop_limit: u8,
    /// ECN bits.
    pub ecn: u8,
    /// Whether link-layer security protected the datagram.
    pub link_security: bool,
}

/// Addressing of a received datagram (from [`crate::ip6::Delivery`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UdpRxInfo {
    /// IPv6 source.
    pub src: Ipv6Addr,
    /// IPv6 destination.
    pub dst: Ipv6Addr,
    /// Hop limit.
    pub hop_limit: u8,
    /// ECN bits.
    pub ecn: u8,
    /// Link security flag.
    pub link_security: bool,
}

impl From<&crate::ip6::Delivery> for UdpRxInfo {
    fn from(d: &crate::ip6::Delivery) -> Self {
        Self {
            src: d.src,
            dst: d.dst,
            hop_limit: d.hop_limit,
            ecn: d.ecn,
            link_security: d.link_security,
        }
    }
}

/// Why a datagram was not queued.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum DropReason {
    /// Malformed UDP header or length mismatch.
    Malformed,
    /// No socket or receiver matches.
    NoSocket,
    /// The socket's receive queue is full.
    QueueFull,
}

/// Result of [`UdpSockets::handle_datagram`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UdpRx<'a> {
    /// An internal receiver claimed the port: dispatch `payload`.
    Receiver {
        /// The registered receiver.
        id: ReceiverId,
        /// Packet metadata.
        meta: UdpMeta,
        /// UDP payload (without header).
        payload: &'a [u8],
    },
    /// Copied into the receive queue of this socket.
    Queued(SocketHandle),
    /// Dropped.
    Dropped(DropReason),
}

/// Result of [`UdpSockets::recv`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecvInfo {
    /// Bytes copied into the caller's buffer.
    pub len: usize,
    /// `true` if the packet was longer than the buffer (the rest is lost).
    pub truncated: bool,
    /// Packet metadata.
    pub meta: UdpMeta,
}

/// Per-send options.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UdpSendOpts {
    /// Hop limit; 0 selects the default (64).
    pub hop_limit: u8,
    /// Loop multicast back to local sockets.
    pub multicast_loop: bool,
    /// Link-layer security.
    pub link_security: bool,
    /// DSCP.
    pub dscp: u8,
    /// Source address override (e.g. when replying from the address the
    /// request was sent to); `None` uses the socket's local address, or
    /// source selection if that is unspecified.
    pub src: Option<Ipv6Addr>,
}

impl Default for UdpSendOpts {
    fn default() -> Self {
        Self {
            hop_limit: 0,
            multicast_loop: false,
            link_security: true,
            dscp: 0,
            src: None,
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct Packet<const BUF: usize> {
    len: usize,
    full_len: usize,
    meta: UdpMeta,
    data: [u8; BUF],
}

#[derive(Debug, Clone)]
struct Socket<const Q: usize, const BUF: usize> {
    /// Bound local address and port (port 0 = not bound yet).
    local: SocketAddrV6,
    /// Connected peer (port 0 = not connected).
    peer: SocketAddrV6,
    /// Open order, newest wins on overlapping matches (OT list head).
    seq: u32,
    queue: [Option<Packet<BUF>>; Q],
    head: usize,
    count: usize,
    dropped: u32,
}

const fn any(port: u16) -> SocketAddrV6 {
    SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, port, 0, 0)
}

/// Fixed-capacity UDP socket table: `N` sockets, each with a receive queue
/// of `Q` packets of at most `BUF` payload bytes, and `R` internal receiver
/// registrations.
#[derive(Debug, Clone)]
pub struct UdpSockets<
    const N: usize,
    const Q: usize = 2,
    const BUF: usize = 1280,
    const R: usize = 4,
> {
    sockets: [Option<Socket<Q, BUF>>; N],
    receivers: [Option<(u16, ReceiverId)>; R],
    next_ephemeral: u16,
    open_seq: u32,
    epoch: u32,
}

impl<const N: usize, const Q: usize, const BUF: usize, const R: usize> Default
    for UdpSockets<N, Q, BUF, R>
{
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize, const Q: usize, const BUF: usize, const R: usize> UdpSockets<N, Q, BUF, R> {
    /// An empty table.
    pub const fn new() -> Self {
        Self {
            sockets: [const { None }; N],
            receivers: [None; R],
            next_ephemeral: EPHEMERAL_PORT_MIN,
            open_seq: 0,
            epoch: 0,
        }
    }

    fn sock(&self, h: SocketHandle) -> Result<&Socket<Q, BUF>> {
        self.sockets
            .get(usize::from(h.0))
            .and_then(Option::as_ref)
            .ok_or(Error::InvalidArgs)
    }

    fn sock_mut(&mut self, h: SocketHandle) -> Result<&mut Socket<Q, BUF>> {
        self.sockets
            .get_mut(usize::from(h.0))
            .and_then(Option::as_mut)
            .ok_or(Error::InvalidArgs)
    }

    // -------------------------------------------------------- receivers

    /// Register an internal receiver for `port` (MLE 19788, TMF 61631, ...).
    /// Receivers are consulted before sockets (OT `Udp::AddReceiver`).
    /// [`Error::Already`] if the port is taken, [`Error::NoBufs`] if full.
    pub fn register_receiver(&mut self, port: u16, id: ReceiverId) -> Result<()> {
        if self.receivers.iter().flatten().any(|(p, _)| *p == port) {
            return Err(Error::Already);
        }
        let slot = self
            .receivers
            .iter_mut()
            .find(|s| s.is_none())
            .ok_or(Error::NoBufs)?;
        *slot = Some((port, id));
        Ok(())
    }

    /// Remove a receiver. [`Error::NotFound`] if absent.
    pub fn unregister_receiver(&mut self, id: ReceiverId) -> Result<()> {
        let slot = self
            .receivers
            .iter_mut()
            .find(|s| matches!(s, Some((_, i)) if *i == id))
            .ok_or(Error::NotFound)?;
        *slot = None;
        Ok(())
    }

    // ---------------------------------------------------------- sockets

    /// Allocate an unbound socket. [`Error::NoBufs`] if the table is full.
    pub fn open(&mut self) -> Result<SocketHandle> {
        let idx = self
            .sockets
            .iter()
            .position(Option::is_none)
            .ok_or(Error::NoBufs)?;
        self.open_seq = self.open_seq.wrapping_add(1);
        self.sockets[idx] = Some(Socket {
            local: any(0),
            peer: any(0),
            seq: self.open_seq,
            queue: [const { None }; Q],
            head: 0,
            count: 0,
            dropped: 0,
        });
        Ok(SocketHandle(idx as u8))
    }

    /// Close a socket, dropping queued packets.
    pub fn close(&mut self, h: SocketHandle) -> Result<()> {
        self.sock(h)?;
        self.sockets[usize::from(h.0)] = None;
        self.epoch = self.epoch.wrapping_add(1);
        Ok(())
    }

    fn is_reserved_port(port: u16) -> bool {
        port == TMF_UDP_PORT || (SRP_SERVER_PORT_MIN..=SRP_SERVER_PORT_MAX).contains(&port)
    }

    fn port_in_use(&self, port: u16) -> bool {
        self.sockets
            .iter()
            .flatten()
            .any(|s| s.local.port() == port)
            || self.receivers.iter().flatten().any(|(p, _)| *p == port)
    }

    /// OT `Udp::GetEphemeralPort`: next port in the dynamic range, skipping
    /// reserved ones (and, unlike OT, ports already in use).
    fn ephemeral_port(&mut self) -> Result<u16> {
        for _ in 0..=(EPHEMERAL_PORT_MAX - EPHEMERAL_PORT_MIN) {
            self.next_ephemeral = if self.next_ephemeral < EPHEMERAL_PORT_MAX {
                self.next_ephemeral + 1
            } else {
                EPHEMERAL_PORT_MIN
            };
            let p = self.next_ephemeral;
            if !Self::is_reserved_port(p) && !self.port_in_use(p) {
                return Ok(p);
            }
        }
        Err(Error::NoBufs)
    }

    /// Bind to `local`. The address must be unspecified or one of the
    /// interface's unicast addresses ([`Error::InvalidArgs`]); port 0 picks
    /// an ephemeral port; binding an in-use port with an overlapping address
    /// is [`Error::Already`]. Re-binding a bound socket changes its address
    /// only (OT `Udp::Bind` keeps the port of a bound socket).
    pub fn bind<const U: usize, const M: usize>(
        &mut self,
        h: SocketHandle,
        local: SocketAddrV6,
        netif: &Netif<U, M>,
    ) -> Result<()> {
        self.sock(h)?;
        let ip = *local.ip();
        if !ip.is_unspecified() && !netif.has_unicast(&ip) {
            return Err(Error::InvalidArgs);
        }
        let bound_port = self.sock(h)?.local.port();
        let port = if bound_port != 0 {
            bound_port
        } else if local.port() == 0 {
            self.ephemeral_port()?
        } else {
            let port = local.port();
            let clash = self.receivers.iter().flatten().any(|(p, _)| *p == port)
                || self.sockets.iter().enumerate().any(|(i, s)| {
                    i != usize::from(h.0)
                        && s.as_ref().is_some_and(|s| {
                            s.local.port() == port
                                && (s.local.ip().is_unspecified()
                                    || ip.is_unspecified()
                                    || *s.local.ip() == ip)
                        })
                });
            if clash {
                return Err(Error::Already);
            }
            port
        };
        self.sock_mut(h)?.local = SocketAddrV6::new(ip, port, 0, 0);
        Ok(())
    }

    /// Set the default peer (a "connected" socket filters received packets
    /// by peer). Binds to an ephemeral port first if needed.
    pub fn connect<const U: usize, const M: usize>(
        &mut self,
        h: SocketHandle,
        peer: SocketAddrV6,
        netif: &Netif<U, M>,
    ) -> Result<()> {
        if self.sock(h)?.local.port() == 0 {
            self.bind(h, any(0), netif)?;
        }
        self.sock_mut(h)?.peer = SocketAddrV6::new(*peer.ip(), peer.port(), 0, 0);
        Ok(())
    }

    /// Local address and port (port 0 if not bound).
    pub fn local_addr(&self, h: SocketHandle) -> Result<SocketAddrV6> {
        Ok(self.sock(h)?.local)
    }

    /// Connected peer, if any.
    pub fn peer_addr(&self, h: SocketHandle) -> Result<Option<SocketAddrV6>> {
        let p = self.sock(h)?.peer;
        Ok((p.port() != 0).then_some(p))
    }

    /// Number of packets dropped because the queue was full.
    pub fn dropped(&self, h: SocketHandle) -> Result<u32> {
        Ok(self.sock(h)?.dropped)
    }

    /// Counter that changes whenever a packet is queued or a socket closed;
    /// async facades wake waiters when it changes.
    pub const fn rx_epoch(&self) -> u32 {
        self.epoch
    }

    // ------------------------------------------------------------ receive

    /// OT `SocketHandle::Matches`.
    fn matches(s: &Socket<Q, BUF>, info: &UdpRxInfo, dst_port: u16, src_port: u16) -> bool {
        if s.local.port() == 0 || s.local.port() != dst_port {
            return false;
        }
        if !(info.dst.is_multicast() || s.local.ip().is_unspecified() || *s.local.ip() == info.dst)
        {
            return false;
        }
        if s.peer.port() != 0 {
            if s.peer.port() != src_port {
                return false;
            }
            if !(s.peer.ip().is_unspecified() || *s.peer.ip() == info.src) {
                return false;
            }
        }
        true
    }

    /// Process the UDP bytes (header + payload) of a delivered datagram.
    ///
    /// The IPv6 layer has already verified the checksum; this checks the
    /// header and length again so it is safe to call on any bytes.
    pub fn handle_datagram<'a>(&mut self, info: &UdpRxInfo, udp: &'a [u8]) -> UdpRx<'a> {
        let Ok(h) = UdpHeader::parse(udp) else {
            return UdpRx::Dropped(DropReason::Malformed);
        };
        if usize::from(h.length) != udp.len() {
            return UdpRx::Dropped(DropReason::Malformed);
        }
        let payload = &udp[UdpHeader::LEN..];
        let meta = UdpMeta {
            peer: SocketAddrV6::new(info.src, h.src_port, 0, 0),
            local: SocketAddrV6::new(info.dst, h.dst_port, 0, 0),
            hop_limit: info.hop_limit,
            ecn: info.ecn,
            link_security: info.link_security,
        };
        if let Some((_, id)) = self
            .receivers
            .iter()
            .flatten()
            .find(|(p, _)| *p == h.dst_port)
        {
            return UdpRx::Receiver {
                id: *id,
                meta,
                payload,
            };
        }
        let best = self
            .sockets
            .iter()
            .enumerate()
            .filter_map(|(i, s)| s.as_ref().map(|s| (i, s)))
            .filter(|(_, s)| Self::matches(s, info, h.dst_port, h.src_port))
            .max_by_key(|(_, s)| s.seq)
            .map(|(i, _)| i);
        let Some(i) = best else {
            return UdpRx::Dropped(DropReason::NoSocket);
        };
        let Some(s) = self.sockets[i].as_mut() else {
            return UdpRx::Dropped(DropReason::NoSocket);
        };
        if s.count == Q {
            s.dropped = s.dropped.saturating_add(1);
            return UdpRx::Dropped(DropReason::QueueFull);
        }
        let n = payload.len().min(BUF);
        let mut data = [0u8; BUF];
        data[..n].copy_from_slice(&payload[..n]);
        let tail = (s.head + s.count) % Q;
        s.queue[tail] = Some(Packet {
            len: n,
            full_len: payload.len(),
            meta,
            data,
        });
        s.count += 1;
        self.epoch = self.epoch.wrapping_add(1);
        UdpRx::Queued(SocketHandle(i as u8))
    }

    /// `true` if a packet is queued.
    pub fn has_data(&self, h: SocketHandle) -> Result<bool> {
        Ok(self.sock(h)?.count > 0)
    }

    /// Length of the next queued packet's payload, if any.
    pub fn peek_len(&self, h: SocketHandle) -> Result<Option<usize>> {
        let s = self.sock(h)?;
        Ok(s.queue[s.head].as_ref().map(|p| p.full_len))
    }

    /// Dequeue the next packet into `buf` (`None` if the queue is empty).
    pub fn recv(&mut self, h: SocketHandle, buf: &mut [u8]) -> Result<Option<RecvInfo>> {
        let s = self.sock_mut(h)?;
        if s.count == 0 {
            return Ok(None);
        }
        let p = s.queue[s.head].take().ok_or(Error::InvalidState)?;
        s.head = (s.head + 1) % Q;
        s.count -= 1;
        let len = p.len.min(buf.len());
        buf[..len].copy_from_slice(&p.data[..len]);
        Ok(Some(RecvInfo {
            len,
            truncated: len < p.full_len,
            meta: p.meta,
        }))
    }

    // --------------------------------------------------------------- send

    /// Prepare a send (OT `Udp::SendTo`): fill peer and source defaults,
    /// bind implicitly, write `[UDP header | payload]` (checksum zero; the
    /// IPv6 layer fills it) into `out` and return the [`SendInfo`] for
    /// [`crate::ip6::Ip6::send`] with the UDP length.
    ///
    /// `dst` of `None` (or an unspecified address / port 0) falls back to the
    /// connected peer; [`Error::InvalidArgs`] if there is none.
    pub fn build_send<const U: usize, const M: usize>(
        &mut self,
        h: SocketHandle,
        dst: Option<SocketAddrV6>,
        opts: &UdpSendOpts,
        payload: &[u8],
        out: &mut [u8],
        netif: &Netif<U, M>,
    ) -> Result<(SendInfo, usize)> {
        let (peer_ip, peer_port) = {
            let s = self.sock(h)?;
            let (ip, port) = match dst {
                Some(d) => (*d.ip(), d.port()),
                None => (Ipv6Addr::UNSPECIFIED, 0),
            };
            let ip = if ip.is_unspecified() {
                *s.peer.ip()
            } else {
                ip
            };
            let port = if port == 0 { s.peer.port() } else { port };
            (ip, port)
        };
        if peer_ip.is_unspecified() || peer_port == 0 {
            return Err(Error::InvalidArgs);
        }
        if self.sock(h)?.local.port() == 0 {
            let local = self.sock(h)?.local;
            self.bind(h, local, netif)?;
        }
        let local = self.sock(h)?.local;
        let total = UdpHeader::LEN + payload.len();
        let o = out.get_mut(..total).ok_or(Error::NoBufs)?;
        UdpHeader {
            src_port: local.port(),
            dst_port: peer_port,
            length: u16::try_from(total).map_err(|_| Error::NoBufs)?,
            checksum: 0,
        }
        .write(o)?;
        o[UdpHeader::LEN..].copy_from_slice(payload);
        let src = opts
            .src
            .or_else(|| (!local.ip().is_unspecified()).then(|| *local.ip()));
        let info = SendInfo {
            src,
            dst: peer_ip,
            hop_limit: opts.hop_limit,
            dscp: opts.dscp,
            ecn: 0,
            multicast_loop: opts.multicast_loop,
            link_security: opts.link_security,
        };
        Ok((info, total))
    }

    /// The protocol number to pass to [`crate::ip6::Ip6::send`].
    pub const PROTO: u8 = PROTO_UDP;
}

#[cfg(test)]
mod tests;
