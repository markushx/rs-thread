#![no_std]
//! Executor-agnostic async facade (embassy-sync) for the rs-thread Thread stack.
//!
//! Part of rs-thread, a pure Rust implementation of the Thread 1.4.1 protocol.
//!
//! # Async facade
//!
//! The sans-IO [`Instance`] has no radio, clock or executor. This crate runs
//! it over an [`rs_thread_platform::Radio`], [`Clock`](rs_thread_platform::Clock)
//! and [`Alarm`](rs_thread_platform::Alarm) and gives the application async
//! access to it, in the shape of the esp-rs `openthread` crate:
//!
//! - [`Resources`] owns the instance and the shared notification state. Put
//!   it in a `static` / `StaticCell` or on the stack; it is created once per
//!   node and holds no global state, so several nodes (simulation) and a
//!   restart with new resources work.
//! - [`RsThread`] is a `Copy` handle on the resources. Hand copies to every
//!   task.
//! - [`RsThread::run`] is the driver future. Race it with the application
//!   (`select`, a spawned task, ...); it never returns. It is drop-safe at
//!   every await point: if it is dropped while a transmission or an energy
//!   scan is in flight, the next call to `run` reports that operation as
//!   aborted to the MAC.
//! - [`RsThread::wait_changed`] wakes any number of waiters when the node's
//!   state changes; [`RsThread::next_event`] is a bounded event stream.
//! - [`RsThread::with`] gives synchronous access to the whole [`Instance`]
//!   API (and wakes the driver afterwards); [`UdpSocket`] is an async UDP
//!   socket.
//!
//! # Request wrappers
//!
//! [`RsThread::ping`], [`RsThread::joiner_start`],
//! [`RsThread::srp_wait_host_registered`] /
//! [`RsThread::srp_wait_service_registered`] and
//! [`RsThread::dns_resolve_address`] / [`RsThread::dns_browse`] /
//! [`RsThread::dns_resolve_service`], [`RsThread::scan`] (MLE discovery)
//! and [`RsThread::energy_scan`] issue a request and await its result
//! without taking events from [`RsThread::next_event`] (see the
//! `requests` module docs of the source for the rules). Timeouts are driven
//! by `run`. Not wrapped: the MAC beacon active scan (use
//! [`Instance::active_scan_start`] and `Event::ActiveScanResult` through
//! [`RsThread::with`] / [`RsThread::next_event`]) and the Thread network
//! diagnostic requests.
//!
//! # esp-rs `openthread` surface
//!
//! With the `openthread-compat` feature, the `compat` module has
//! `OpenThread`, `DeviceRole`, `NetStatus`, `Channels`, `ScanResult`,
//! `NeighborInfo`, `RouteInfo`, the counters, `SrpConf` / `SrpService` and
//! the methods `rs-matter-embassy` uses, with the esp-rs signatures where the
//! instance has the data (see the module docs for the differences).
//!
//! # edge-nal
//!
//! With the `edge-nal` feature, `UdpStack` implements the `edge-nal`
//! `UdpBind` / `UdpConnect` traits and [`UdpSocket`] the socket traits
//! (`UdpReceive`, `UdpSend`, `Readable`, `MulticastV6`, `UdpSplit`; IPv4
//! is rejected). `edge-nal` 0.7 requires Rust 1.88 (the workspace MSRV).
//!
//! The crate uses no executor and no timer crate: time comes from the `Clock`
//! stored in the resources and the `Alarm` passed to `run`. Locking is
//! generic over `embassy_sync::blocking_mutex::raw::RawMutex`
//! (`NoopRawMutex` for a single executor, `CriticalSectionRawMutex` across
//! interrupts or cores). The instance is only ever borrowed inside short
//! synchronous sections, never across an `.await`; calling a handle method
//! from inside a [`with`](RsThread::with) closure panics.
//!
//! ```no_run
//! use core::net::{Ipv6Addr, SocketAddrV6};
//! use embassy_futures::select::select;
//! use embassy_sync::blocking_mutex::raw::NoopRawMutex;
//! use rs_thread_core::crypto::soft::SoftCrypto;
//! use rs_thread_embassy::{rs-thread, Resources, UdpSocket};
//! use rs_thread_instance::{Config, Instance, Role};
//! use rs_thread_platform::radio::sim::TestRadio;
//! use rs_thread_platform::time::MockClock;
//! use rs_thread_platform::{Radio, RamSettings};
//!
//! # struct Rng; // a CSPRNG in real code
//! # impl rand_core::TryRng for Rng {
//! #     type Error = core::convert::Infallible;
//! #     fn try_next_u32(&mut self) -> Result<u32, Self::Error> { Ok(4) }
//! #     fn try_next_u64(&mut self) -> Result<u64, Self::Error> { Ok(4) }
//! #     fn try_fill_bytes(&mut self, _: &mut [u8]) -> Result<(), Self::Error> { Ok(()) }
//! # }
//! # impl rand_core::TryCryptoRng for Rng {}
//! # async fn demo() {
//! let clock = MockClock::new();
//! let mut radio = TestRadio::new();
//! let caps = radio.init().await.unwrap();
//! let ext = rs_thread_instance::ExtAddress([2, 0, 0, 0, 0, 0, 0, 1]);
//! let instance = Instance::new(
//!     Config::router(ext, caps),
//!     RamSettings::<4096>::new(),
//!     SoftCrypto,
//!     Rng,
//! );
//! let resources: Resources<NoopRawMutex, _, _, _, _> = Resources::new(instance, &clock);
//! let ot = RsThread::new(&resources);
//!
//! let app = async {
//!     ot.with(|i, now| {
//!         let ds = i.create_dataset(15).unwrap();
//!         i.set_active_dataset(&ds, now).unwrap();
//!         i.ip6_set_enabled(true);
//!         i.become_leader(now).unwrap();
//!     });
//!     while ot.role() != Role::Leader {
//!         ot.wait_changed().await;
//!     }
//!     let local = SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 1234, 0, 0);
//!     let socket = UdpSocket::bind(ot, local).unwrap();
//!     let mut buf = [0u8; 128];
//!     let (len, _local, _remote) = socket.recv(&mut buf).await.unwrap();
//!     let _ = &buf[..len];
//! };
//! select(ot.run(radio, clock.alarm()), app).await;
//! # }
//! ```

#[cfg(feature = "openthread-compat")]
pub mod compat;
#[cfg(feature = "edge-nal")]
mod edge;
mod requests;
mod run;
mod state;
mod udp;

#[cfg(feature = "dns-client")]
pub use requests::DnsClientError;
pub use rs_thread_instance::DiscoverResult;
#[cfg(feature = "ping")]
pub use rs_thread_instance::PingReply;
#[cfg(feature = "srp-client")]
pub use rs_thread_instance::ServiceId;
#[cfg(feature = "dns-client")]
pub use rs_thread_instance::{DnsError, QueryConfig, ResolvedAddresses, ResolvedService};
pub use rs_thread_instance::{Event, Instance};
pub use rs_thread_meshcop::joiner::JoinerConfig;
pub use state::{EVENT_QUEUE_LEN, Resources, RsThread, WAITERS};
pub use udp::UdpSocket;

#[cfg(feature = "edge-nal")]
pub use edge::{EdgeError, UdpStack};
