#![no_std]
//! Executor-agnostic async facade (embassy-sync) for the OpenTrust Thread stack.
//!
//! Part of OpenTrust, a pure Rust implementation of the Thread 1.4.1 protocol.
//!
//! # Async facade
//!
//! The sans-IO [`Instance`] has no radio, clock or executor. This crate runs
//! it over an [`opentrust_platform::Radio`], [`Clock`](opentrust_platform::Clock)
//! and [`Alarm`](opentrust_platform::Alarm) and gives the application async
//! access to it, in the shape of the esp-rs `openthread` crate:
//!
//! - [`Resources`] owns the instance and the shared notification state. Put
//!   it in a `static` / `StaticCell` or on the stack; it is created once per
//!   node and holds no global state, so several nodes (simulation) and a
//!   restart with new resources work.
//! - [`OpenTrust`] is a `Copy` handle on the resources. Hand copies to every
//!   task.
//! - [`OpenTrust::run`] is the driver future. Race it with the application
//!   (`select`, a spawned task, ...); it never returns. It is drop-safe at
//!   every await point: if it is dropped while a transmission or an energy
//!   scan is in flight, the next call to `run` reports that operation as
//!   aborted to the MAC.
//! - [`OpenTrust::wait_changed`] wakes any number of waiters when the node's
//!   state changes; [`OpenTrust::next_event`] is a bounded event stream.
//! - [`OpenTrust::with`] gives synchronous access to the whole [`Instance`]
//!   API (and wakes the driver afterwards); [`UdpSocket`] is an async UDP
//!   socket.
//!
//! # Request wrappers
//!
//! [`OpenTrust::ping`], [`OpenTrust::joiner_start`],
//! [`OpenTrust::srp_wait_host_registered`] /
//! [`OpenTrust::srp_wait_service_registered`] and
//! [`OpenTrust::dns_resolve_address`] / [`OpenTrust::dns_browse`] /
//! [`OpenTrust::dns_resolve_service`], [`OpenTrust::scan`] (MLE discovery)
//! and [`OpenTrust::energy_scan`] issue a request and await its result
//! without taking events from [`OpenTrust::next_event`] (see the
//! `requests` module docs of the source for the rules). Timeouts are driven
//! by `run`. Not wrapped: the MAC beacon active scan (use
//! [`Instance::active_scan_start`] and `Event::ActiveScanResult` through
//! [`OpenTrust::with`] / [`OpenTrust::next_event`]) and the Thread network
//! diagnostic requests.
//!
//! # edge-nal
//!//!
//! With the `edge-nal` feature, [`UdpStack`] implements the `edge-nal`
//! `UdpBind` / `UdpConnect` traits and [`UdpSocket`] the socket traits
//! (`UdpReceive`, `UdpSend`, `Readable`, `MulticastV6`, `UdpSplit`; IPv4
//! is rejected). `edge-nal` 0.7 needs Rust 1.88, so the feature raises the
//! MSRV of the crate from 1.85 to 1.88; without it the MSRV is unchanged.
//!
//! The crate uses no executor and no timer crate: time comes from the `Clock`
//! stored in the resources and the `Alarm` passed to `run`. Locking is
//! generic over `embassy_sync::blocking_mutex::raw::RawMutex`
//! (`NoopRawMutex` for a single executor, `CriticalSectionRawMutex` across
//! interrupts or cores). The instance is only ever borrowed inside short
//! synchronous sections, never across an `.await`; calling a handle method
//! from inside a [`with`](OpenTrust::with) closure panics.
//!
//! ```no_run
//! use core::net::{Ipv6Addr, SocketAddrV6};
//! use embassy_futures::select::select;
//! use embassy_sync::blocking_mutex::raw::NoopRawMutex;
//! use opentrust_core::crypto::soft::SoftCrypto;
//! use opentrust_embassy::{OpenTrust, Resources, UdpSocket};
//! use opentrust_instance::{Config, Instance, Role};
//! use opentrust_platform::radio::sim::TestRadio;
//! use opentrust_platform::time::MockClock;
//! use opentrust_platform::{Radio, RamSettings};
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
//! let ext = opentrust_instance::ExtAddress([2, 0, 0, 0, 0, 0, 0, 1]);
//! let instance = Instance::new(
//!     Config::router(ext, caps),
//!     RamSettings::<4096>::new(),
//!     SoftCrypto,
//!     Rng,
//! );
//! let resources: Resources<NoopRawMutex, _, _, _, _> = Resources::new(instance, &clock);
//! let ot = OpenTrust::new(&resources);
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

#[cfg(feature = "edge-nal")]
mod edge;
mod requests;
mod run;
mod state;
mod udp;

pub use opentrust_instance::{
    DiscoverResult, DnsError, PingReply, QueryConfig, ResolvedAddresses, ResolvedService, ServiceId,
};
pub use opentrust_instance::{Event, Instance};
pub use opentrust_meshcop::joiner::JoinerConfig;
pub use requests::DnsClientError;
pub use state::{EVENT_QUEUE_LEN, OpenTrust, Resources, WAITERS};
pub use udp::UdpSocket;

#[cfg(feature = "edge-nal")]
pub use edge::{EdgeError, UdpStack};
