//! `edge-nal` UDP traits over [`UdpSocket`].

use core::net::SocketAddr;

use edge_nal::io::{Error as IoError, ErrorKind, ErrorType};
use edge_nal::{
    MulticastV4, MulticastV6, Readable, UdpBind, UdpConnect, UdpReceive, UdpSend, UdpSplit,
    UdpSplitMulticast,
};
use embassy_sync::blocking_mutex::raw::RawMutex;
use rs_thread_instance::InstanceCrypto;
use rs_thread_platform::{Clock, SettingsStore};
use rand_core::{CryptoRng, Rng};

use crate::state::RsThread;
use crate::udp::UdpSocket;

/// Error of the `edge-nal` traits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EdgeError {
    /// IPv4 addresses and multicast groups are not supported (Thread is
    /// IPv6 only).
    Unsupported,
    /// The stack reported an error.
    Stack(rs_thread_core::Error),
}

impl core::fmt::Display for EdgeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Unsupported => f.write_str("unsupported (IPv4)"),
            Self::Stack(e) => core::fmt::Display::fmt(e, f),
        }
    }
}

impl core::error::Error for EdgeError {}

impl From<rs_thread_core::Error> for EdgeError {
    fn from(e: rs_thread_core::Error) -> Self {
        Self::Stack(e)
    }
}

impl IoError for EdgeError {
    fn kind(&self) -> ErrorKind {
        use rs_thread_core::Error as E;
        match self {
            Self::Unsupported => ErrorKind::Unsupported,
            Self::Stack(E::NoBufs) => ErrorKind::OutOfMemory,
            Self::Stack(E::InvalidArgs | E::Parse) => ErrorKind::InvalidInput,
            Self::Stack(E::NotFound) => ErrorKind::NotFound,
            Self::Stack(E::ResponseTimeout) => ErrorKind::TimedOut,
            Self::Stack(E::Already) => ErrorKind::AddrInUse,
            Self::Stack(_) => ErrorKind::Other,
        }
    }
}

/// The `edge-nal` UDP stack of a node: `UdpBind` and `UdpConnect`.
pub struct UdpStack<'a, M, K, S, C, R>(RsThread<'a, M, K, S, C, R>)
where
    M: RawMutex,
    C: InstanceCrypto;

impl<M: RawMutex, K, S, C: InstanceCrypto, R> core::fmt::Debug for UdpStack<'_, M, K, S, C, R> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("UdpStack").finish_non_exhaustive()
    }
}

impl<'a, M: RawMutex, K, S, C: InstanceCrypto, R> UdpStack<'a, M, K, S, C, R> {
    /// The UDP stack of the node behind `ot`.
    pub fn new(ot: RsThread<'a, M, K, S, C, R>) -> Self {
        Self(ot)
    }
}

fn v6(a: SocketAddr) -> Result<core::net::SocketAddrV6, EdgeError> {
    match a {
        SocketAddr::V6(a) => Ok(a),
        SocketAddr::V4(_) => Err(EdgeError::Unsupported),
    }
}

impl<'a, M, K, S, C, R> UdpBind for UdpStack<'a, M, K, S, C, R>
where
    M: RawMutex,
    K: Clock,
    S: SettingsStore,
    C: InstanceCrypto,
    R: Rng + CryptoRng,
{
    type Error = EdgeError;
    type Socket<'b>
        = UdpSocket<'a, M, K, S, C, R>
    where
        Self: 'b;

    async fn bind(&self, local: SocketAddr) -> Result<Self::Socket<'_>, Self::Error> {
        Ok(UdpSocket::bind(self.0, v6(local)?)?)
    }
}

impl<'a, M, K, S, C, R> UdpConnect for UdpStack<'a, M, K, S, C, R>
where
    M: RawMutex,
    K: Clock,
    S: SettingsStore,
    C: InstanceCrypto,
    R: Rng + CryptoRng,
{
    type Error = EdgeError;
    type Socket<'b>
        = UdpSocket<'a, M, K, S, C, R>
    where
        Self: 'b;

    async fn connect(
        &self,
        local: SocketAddr,
        remote: SocketAddr,
    ) -> Result<Self::Socket<'_>, Self::Error> {
        let s = UdpSocket::bind(self.0, v6(local)?)?;
        s.connect(v6(remote)?);
        Ok(s)
    }
}

/// The traits for the socket itself and for `&UdpSocket` (the halves of a
/// split socket).
macro_rules! socket_impls {
    ($ty:ty, [$($lt:lifetime),*], |$s:ident| $get:expr) => {
        impl<$($lt,)* 'a, M, K, S, C, R> ErrorType for $ty
        where
            M: RawMutex,
            K: Clock,
            S: SettingsStore,
            C: InstanceCrypto,
            R: Rng + CryptoRng,
        {
            type Error = EdgeError;
        }

        impl<$($lt,)* 'a, M, K, S, C, R> UdpReceive for $ty
        where
            M: RawMutex,
            K: Clock,
            S: SettingsStore,
            C: InstanceCrypto,
            R: Rng + CryptoRng,
        {
            async fn receive(
                &mut self,
                buffer: &mut [u8],
            ) -> Result<(usize, SocketAddr), Self::Error> {
                let $s = self;
                let (n, _local, remote) = $get.recv(buffer).await?;
                Ok((n, SocketAddr::V6(remote)))
            }
        }

        impl<$($lt,)* 'a, M, K, S, C, R> UdpSend for $ty
        where
            M: RawMutex,
            K: Clock,
            S: SettingsStore,
            C: InstanceCrypto,
            R: Rng + CryptoRng,
        {
            async fn send(&mut self, remote: SocketAddr, data: &[u8]) -> Result<(), Self::Error> {
                let $s = self;
                Ok($get.send(data, None, v6(remote)?).await?)
            }
        }

        impl<$($lt,)* 'a, M, K, S, C, R> Readable for $ty
        where
            M: RawMutex,
            K: Clock,
            S: SettingsStore,
            C: InstanceCrypto,
            R: Rng + CryptoRng,
        {
            async fn readable(&mut self) -> Result<(), Self::Error> {
                let $s = self;
                Ok($get.wait_recv_available().await?)
            }
        }

        impl<$($lt,)* 'a, M, K, S, C, R> MulticastV6 for $ty
        where
            M: RawMutex,
            K: Clock,
            S: SettingsStore,
            C: InstanceCrypto,
            R: Rng + CryptoRng,
        {
            async fn join_v6(
                &mut self,
                multicast_addr: core::net::Ipv6Addr,
                _interface: u32,
            ) -> Result<(), Self::Error> {
                let $s = self;
                Ok($get.ot.join_multicast(multicast_addr)?)
            }

            async fn leave_v6(
                &mut self,
                multicast_addr: core::net::Ipv6Addr,
                _interface: u32,
            ) -> Result<(), Self::Error> {
                let $s = self;
                Ok($get.ot.leave_multicast(multicast_addr)?)
            }
        }

        impl<$($lt,)* 'a, M, K, S, C, R> MulticastV4 for $ty
        where
            M: RawMutex,
            K: Clock,
            S: SettingsStore,
            C: InstanceCrypto,
            R: Rng + CryptoRng,
        {
            async fn join_v4(
                &mut self,
                _multicast_addr: core::net::Ipv4Addr,
                _interface: core::net::Ipv4Addr,
            ) -> Result<(), Self::Error> {
                Err(EdgeError::Unsupported)
            }

            async fn leave_v4(
                &mut self,
                _multicast_addr: core::net::Ipv4Addr,
                _interface: core::net::Ipv4Addr,
            ) -> Result<(), Self::Error> {
                Err(EdgeError::Unsupported)
            }
        }
    };
}

socket_impls!(UdpSocket<'a, M, K, S, C, R>, [], |s| &*s);
socket_impls!(&'b UdpSocket<'a, M, K, S, C, R>, ['b], |s| &**s);

impl<M, K, S, C, R> UdpSplit for UdpSocket<'_, M, K, S, C, R>
where
    M: RawMutex,
    K: Clock,
    S: SettingsStore,
    C: InstanceCrypto,
    R: Rng + CryptoRng,
{
    type Receive<'b>
        = &'b Self
    where
        Self: 'b;
    type Send<'b>
        = &'b Self
    where
        Self: 'b;

    fn split(&mut self) -> (Self::Receive<'_>, Self::Send<'_>) {
        (&*self, &*self)
    }
}

impl<M, K, S, C, R> UdpSplitMulticast for UdpSocket<'_, M, K, S, C, R>
where
    M: RawMutex,
    K: Clock,
    S: SettingsStore,
    C: InstanceCrypto,
    R: Rng + CryptoRng,
{
    type MulticastV4<'b>
        = &'b Self
    where
        Self: 'b;
    type MulticastV6<'b>
        = &'b Self
    where
        Self: 'b;

    fn split_multicast(
        &mut self,
    ) -> (
        Self::Receive<'_>,
        Self::Send<'_>,
        Self::MulticastV4<'_>,
        Self::MulticastV6<'_>,
    ) {
        (&*self, &*self, &*self, &*self)
    }
}
