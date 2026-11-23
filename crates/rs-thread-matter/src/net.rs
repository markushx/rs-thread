//! The rs-matter network stack over the UDP sockets of a node
//! (`rs_matter::stack::net::{NetStack, NetSocket}` and the transport's
//! `NetworkSend` / `NetworkReceive` / `NetworkMulticast`).
//!
//! rs-matter binds one socket on `[::]:5540` for Matter (`run_oper_net`);
//! the builtin mDNS responder, which would bind a second one on 5353, is not
//! used on Thread ([`crate::mdns`] registers with SRP instead). IPv4 binds,
//! peers and groups are rejected with `ErrorCode::NoNetworkInterface` /
//! `InvalidPeerAddr`: a Thread interface has no IPv4.

use core::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV6};

use embassy_sync::blocking_mutex::raw::RawMutex;
use rs_thread_embassy::{RsThread, UdpSocket};
use rs_thread_instance::InstanceCrypto;
use rs_thread_platform::{Clock, SettingsStore};
use rand_core::{CryptoRng, Rng};
use rs_matter::error::{Error, ErrorCode};
use rs_matter::stack::net::{NetSocket, NetStack};
use rs_matter::transport::network::{Address, NetworkMulticast, NetworkReceive, NetworkSend};

use crate::error::map_err;

fn v6(a: SocketAddr) -> Result<SocketAddrV6, Error> {
    match a {
        SocketAddr::V6(a) => Ok(a),
        SocketAddr::V4(_) => Err(ErrorCode::NoNetworkInterface.into()),
    }
}

/// The rs-matter `NetStack` of a node: binds [`MatterSocket`]s.
pub struct MatterNetStack<'a, M, K, S, C, R>
where
    M: RawMutex,
    C: InstanceCrypto,
{
    ot: RsThread<'a, M, K, S, C, R>,
}

impl<M: RawMutex, K, S, C: InstanceCrypto, R> core::fmt::Debug
    for MatterNetStack<'_, M, K, S, C, R>
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MatterNetStack").finish_non_exhaustive()
    }
}

impl<'a, M: RawMutex, K, S, C: InstanceCrypto, R> MatterNetStack<'a, M, K, S, C, R> {
    /// The network stack of the node behind `ot`.
    pub const fn new(ot: RsThread<'a, M, K, S, C, R>) -> Self {
        Self { ot }
    }
}

impl<'a, M, K, S, C, R> NetStack for MatterNetStack<'a, M, K, S, C, R>
where
    M: RawMutex,
    K: Clock,
    S: SettingsStore,
    C: InstanceCrypto,
    R: Rng + CryptoRng,
{
    type Socket<'b>
        = MatterSocket<'a, M, K, S, C, R>
    where
        Self: 'b;

    async fn bind(
        &self,
        addr: SocketAddr,
        _ipv4_interface: Ipv4Addr,
        _ipv6_interface: u32,
    ) -> Result<Self::Socket<'_>, Error> {
        let sock = UdpSocket::bind(self.ot, v6(addr)?).map_err(map_err)?;
        Ok(MatterSocket { ot: self.ot, sock })
    }
}

/// A bound rs-matter socket (`NetSocket`); dropping it closes the socket.
pub struct MatterSocket<'a, M, K, S, C, R>
where
    M: RawMutex,
    K: Clock,
    S: SettingsStore,
    C: InstanceCrypto,
    R: Rng + CryptoRng,
{
    ot: RsThread<'a, M, K, S, C, R>,
    sock: UdpSocket<'a, M, K, S, C, R>,
}

impl<M, K, S, C, R> core::fmt::Debug for MatterSocket<'_, M, K, S, C, R>
where
    M: RawMutex,
    K: Clock,
    S: SettingsStore,
    C: InstanceCrypto,
    R: Rng + CryptoRng,
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MatterSocket")
            .field("sock", &self.sock)
            .finish_non_exhaustive()
    }
}

impl<'a, M, K, S, C, R> MatterSocket<'a, M, K, S, C, R>
where
    M: RawMutex,
    K: Clock,
    S: SettingsStore,
    C: InstanceCrypto,
    R: Rng + CryptoRng,
{
    /// The underlying socket.
    pub fn socket(&self) -> &UdpSocket<'a, M, K, S, C, R> {
        &self.sock
    }
}

impl<'a, M, K, S, C, R> NetSocket for MatterSocket<'a, M, K, S, C, R>
where
    M: RawMutex,
    K: Clock,
    S: SettingsStore,
    C: InstanceCrypto,
    R: Rng + CryptoRng,
{
    type Send<'b>
        = SocketHalf<'b, 'a, M, K, S, C, R>
    where
        Self: 'b;
    type Receive<'b>
        = SocketHalf<'b, 'a, M, K, S, C, R>
    where
        Self: 'b;
    type Multicast<'b>
        = SocketHalf<'b, 'a, M, K, S, C, R>
    where
        Self: 'b;

    fn split(&mut self) -> (Self::Send<'_>, Self::Receive<'_>, Self::Multicast<'_>) {
        let half = || SocketHalf {
            ot: self.ot,
            sock: &self.sock,
        };
        (half(), half(), half())
    }
}

/// One half of a split [`MatterSocket`]: implements all three transport
/// traits (a socket can be used from any number of halves at once).
pub struct SocketHalf<'b, 'a, M, K, S, C, R>
where
    M: RawMutex,
    K: Clock,
    S: SettingsStore,
    C: InstanceCrypto,
    R: Rng + CryptoRng,
{
    ot: RsThread<'a, M, K, S, C, R>,
    sock: &'b UdpSocket<'a, M, K, S, C, R>,
}

impl<M, K, S, C, R> core::fmt::Debug for SocketHalf<'_, '_, M, K, S, C, R>
where
    M: RawMutex,
    K: Clock,
    S: SettingsStore,
    C: InstanceCrypto,
    R: Rng + CryptoRng,
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SocketHalf")
            .field("sock", self.sock)
            .finish_non_exhaustive()
    }
}

impl<M, K, S, C, R> NetworkSend for SocketHalf<'_, '_, M, K, S, C, R>
where
    M: RawMutex,
    K: Clock,
    S: SettingsStore,
    C: InstanceCrypto,
    R: Rng + CryptoRng,
{
    async fn send_to(&mut self, data: &[u8], addr: Address) -> Result<(), Error> {
        match addr {
            Address::Udp(SocketAddr::V6(dst)) => {
                self.sock.send(data, None, dst).await.map_err(map_err)
            }
            _ => Err(ErrorCode::InvalidPeerAddr.into()),
        }
    }
}

impl<M, K, S, C, R> NetworkReceive for SocketHalf<'_, '_, M, K, S, C, R>
where
    M: RawMutex,
    K: Clock,
    S: SettingsStore,
    C: InstanceCrypto,
    R: Rng + CryptoRng,
{
    async fn wait_available(&mut self) -> Result<(), Error> {
        self.sock.wait_recv_available().await.map_err(map_err)
    }

    async fn recv_from(&mut self, buffer: &mut [u8]) -> Result<(usize, Address), Error> {
        let (n, _local, peer) = self.sock.recv(buffer).await.map_err(map_err)?;
        Ok((n, Address::Udp(SocketAddr::V6(peer))))
    }
}

impl<M, K, S, C, R> NetworkMulticast for SocketHalf<'_, '_, M, K, S, C, R>
where
    M: RawMutex,
    K: Clock,
    S: SettingsStore,
    C: InstanceCrypto,
    R: Rng + CryptoRng,
{
    async fn join(&mut self, addr: IpAddr) -> Result<(), Error> {
        match addr {
            IpAddr::V6(a) => self.ot.join_multicast(a).map_err(map_err),
            IpAddr::V4(_) => Err(ErrorCode::NoNetworkInterface.into()),
        }
    }

    async fn leave(&mut self, addr: IpAddr) -> Result<(), Error> {
        match addr {
            IpAddr::V6(a) => self.ot.leave_multicast(a).map_err(map_err),
            IpAddr::V4(_) => Err(ErrorCode::NoNetworkInterface.into()),
        }
    }
}
