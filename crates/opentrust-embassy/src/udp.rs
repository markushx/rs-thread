//! Async UDP socket over the instance's sockets.

use core::cell::Cell;
use core::future::poll_fn;
use core::net::{Ipv6Addr, SocketAddrV6};
use core::task::{Context, Poll};

use embassy_sync::blocking_mutex::raw::RawMutex;
use opentrust_core::Error;
use opentrust_instance::{InstanceCrypto, UdpSendOpts, UdpSocket as RawUdpSocket};
use opentrust_platform::{Clock, SettingsStore};
use rand_core::{CryptoRng, Rng};

use crate::state::{OpenTrust, State};

/// An async UDP socket (OpenThread `otUdpSocket`, esp-rs `UdpSocket`).
/// Dropping it closes the socket.
pub struct UdpSocket<'a, M, K, S, C, R>
where
    M: RawMutex,
    K: Clock,
    S: SettingsStore,
    C: InstanceCrypto,
    R: Rng + CryptoRng,
{
    ot: OpenTrust<'a, M, K, S, C, R>,
    raw: RawUdpSocket,
    remote: Cell<Option<SocketAddrV6>>,
}

impl<M, K, S, C, R> core::fmt::Debug for UdpSocket<'_, M, K, S, C, R>
where
    M: RawMutex,
    K: Clock,
    S: SettingsStore,
    C: InstanceCrypto,
    R: Rng + CryptoRng,
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("UdpSocket")
            .field("remote", &self.remote.get())
            .finish_non_exhaustive()
    }
}

impl<'a, M, K, S, C, R> UdpSocket<'a, M, K, S, C, R>
where
    M: RawMutex,
    K: Clock,
    S: SettingsStore,
    C: InstanceCrypto,
    R: Rng + CryptoRng,
{
    /// Open a socket and bind it to `local` (port 0: ephemeral port).
    ///
    /// [`Error::NoBufs`] if the instance has no free socket.
    pub fn bind(ot: OpenTrust<'a, M, K, S, C, R>, local: SocketAddrV6) -> Result<Self, Error> {
        let raw = ot.res.lock(|s| {
            let Some(slot) = s.udp.iter().position(|u| u.sock.is_none()) else {
                return Err(Error::NoBufs);
            };
            let raw = s.inst.udp_open()?;
            if let Err(e) = s.inst.udp_bind(raw, local) {
                let _ = s.inst.udp_close(raw);
                return Err(e);
            }
            s.udp[slot].sock = Some(raw);
            Ok(raw)
        })?;
        Ok(Self {
            ot,
            raw,
            remote: Cell::new(None),
        })
    }

    /// Restrict the socket to `remote`: [`recv`](Self::recv) drops datagrams
    /// from other peers and [`send_connected`](Self::send_connected) sends to
    /// it.
    pub fn connect(&self, remote: SocketAddrV6) {
        self.remote.set(Some(remote));
    }

    /// The local address (with the port chosen for port 0).
    pub fn local_addr(&self) -> Result<SocketAddrV6, Error> {
        self.ot.res.lock(|s| s.inst.udp_local_addr(self.raw))
    }

    fn register(&self, s: &mut State<S, C, R>, cx: &Context<'_>) {
        if let Some(slot) = s.udp.iter_mut().find(|u| u.sock == Some(self.raw)) {
            slot.waker.register(cx.waker());
        }
    }

    /// Wait until a datagram is queued (it stays queued).
    pub async fn wait_recv_available(&self) -> Result<(), Error> {
        poll_fn(|cx| {
            self.ot.res.lock(|s| match s.inst.udp_has_data(self.raw) {
                Ok(true) => Poll::Ready(Ok(())),
                Ok(false) => {
                    self.register(s, cx);
                    Poll::Pending
                }
                Err(e) => Poll::Ready(Err(e)),
            })
        })
        .await
    }

    /// Receive the next datagram into `buf`: its length, the local address
    /// it was sent to (may be multicast) and the sender. A datagram longer
    /// than `buf` is truncated.
    pub async fn recv(&self, buf: &mut [u8]) -> Result<(usize, SocketAddrV6, SocketAddrV6), Error> {
        poll_fn(|cx| {
            self.ot.res.lock(|s| {
                loop {
                    match s.inst.udp_recv(self.raw, buf) {
                        Ok(Some(info)) => {
                            if self.remote.get().is_some_and(|r| r != info.meta.peer) {
                                continue;
                            }
                            return Poll::Ready(Ok((info.len, info.meta.local, info.meta.peer)));
                        }
                        Ok(None) => {
                            self.register(s, cx);
                            return Poll::Pending;
                        }
                        Err(e) => return Poll::Ready(Err(e)),
                    }
                }
            })
        })
        .await
    }

    /// Send `data` to `dst`, with `src` as the source address (`None`: the
    /// socket's address or source selection).
    ///
    /// Completes once the datagram is queued in the stack; if the stack has
    /// no room, it waits for the driver to make progress and retries.
    pub async fn send(
        &self,
        data: &[u8],
        src: Option<Ipv6Addr>,
        dst: SocketAddrV6,
    ) -> Result<(), Error> {
        let opts = UdpSendOpts {
            src,
            ..UdpSendOpts::default()
        };
        let r = poll_fn(|cx| {
            let now = self.ot.now();
            self.ot.res.lock(
                |s| match s.inst.udp_send_to(self.raw, dst, data, &opts, now) {
                    Err(Error::NoBufs) => {
                        s.tx_waiters.register(cx.waker());
                        Poll::Pending
                    }
                    r => {
                        s.drain();
                        Poll::Ready(r)
                    }
                },
            )
        })
        .await;
        self.ot.res.kick().signal(());
        r
    }

    /// [`send`](Self::send) to the peer set with [`connect`](Self::connect)
    /// ([`Error::InvalidState`] if none).
    pub async fn send_connected(&self, data: &[u8], src: Option<Ipv6Addr>) -> Result<(), Error> {
        match self.remote.get() {
            Some(dst) => self.send(data, src, dst).await,
            None => Err(Error::InvalidState),
        }
    }
}

impl<M, K, S, C, R> Drop for UdpSocket<'_, M, K, S, C, R>
where
    M: RawMutex,
    K: Clock,
    S: SettingsStore,
    C: InstanceCrypto,
    R: Rng + CryptoRng,
{
    fn drop(&mut self) {
        self.ot.res.lock(|s| {
            let _ = s.inst.udp_close(self.raw);
            if let Some(slot) = s.udp.iter_mut().find(|u| u.sock == Some(self.raw)) {
                slot.sock = None;
                slot.waker.wake();
            }
        });
    }
}
