#![no_std]
//! rs-matter integration for the rs-thread Thread stack (Matter over Thread).
//!
//! Part of rs-thread, a pure Rust implementation of the Thread 1.4.1 protocol.
//!
//! This crate implements the traits `rs-matter-stack` needs from a Thread
//! transport on top of the native async facade of
//! [`rs_thread_embassy`] (the [`RsThread`](rs_thread_embassy::RsThread)
//! handle), in the place where `rs-matter-embassy` puts its adapters for the
//! esp-rs `openthread` crate:
//!
//! | rs-matter trait | This crate | Backed by |
//! |---|---|---|
//! | `rs_matter::stack::net::{NetStack, NetSocket}` + `NetworkSend` / `NetworkReceive` / `NetworkMulticast` | [`net::MatterNetStack`] / [`net::MatterSocket`] | `UdpSocket` (one socket for Matter port 5540) |
//! | `rs_matter::stack::mdns::Mdns` | [`mdns::SrpMdns`] | SRP client (registration) + DNS-SD client (resolve / browse) |
//! | `NetifDiag` + `NetChangeNotif` | [`netif::ThreadNetif`] | address list, `wait_changed` (any number of waiters) |
//! | `NetCtl` + `NetCtlStatus` (Thread Network Commissioning) | [`netctl::ThreadNetCtl`] | MLE discovery scan, dataset TLVs, `thread_start`, role wait with a timeout |
//! | `WirelessDiag` + `ThreadDiag` (Thread Network Diagnostics) | [`netctl::ThreadNetCtl`] (impl in [`threaddiag`]) | role, dataset, leader data, neighbor / route tables, MAC counters |
//! | ICD network parameters (`Icd::net_params`) | [`icd::IcdFollower`] | data poll period, link mode |
//! | `ThreadDriver` / `ThreadCoexDriver` | [`driver::ThreadRunner`] / [`driver::ThreadCoexRunner`] | `RsThread::run` + [`persist::ThreadPersist`] (settings in a `KvBlobStore` blob) + ICD follower |
//!
//! # rs-matter revision
//!
//! rs-matter is pinned in the workspace `Cargo.toml` to revision
//! `95e41108f0a0e6ac896f0e7be3f4eecb951ed10a` of
//! <https://github.com/project-chip/rs-matter> (workspace version 0.4.1,
//! `main` of 2026-11): the 0.4 crates are split (`rs-matter-stack`,
//! `-transport`, `-dm`, ...) and `rs-matter-stack` of that line is not on
//! crates.io yet (crates.io has 0.3.1, which belongs to the old
//! `sysgrok/rs-matter-stack` repository and the 0.3 API). The facade crate
//! `rs-matter` re-exports every sub-crate (`rs_matter::stack`,
//! `rs_matter::transport`, `rs_matter::dm`, ...), so this crate depends on
//! the facade only. rs-matter needs Rust 1.92, hence `rust-version = "1.92"`
//! for this crate (the workspace MSRV stays 1.85), and `heapless >= 0.9.2`
//! (through `domain`), which moved the lockfile to 0.9.3 (rustc 1.87) for the
//! whole workspace.
//!
//! Not covered yet: the ICD child timeout / CSL / supervision (the
//! `Instance` has none of them).
//! Known limits of what is there: the `Instance` SRP client has four
//! service slots (the commissionable service plus three fabrics), lease and
//! TTL are the client defaults, and a browse request is answered with one
//! DNS-SD query per window.
//!
//! # Threading model
//!
//! Everything is executor-agnostic and single-threaded: the futures are not
//! `Send` (the rs-matter `send-sync` feature is not supported, the sockets
//! use `Cell`s), which matches `rs-matter-embassy` on the same targets.
//! Locking is the `RawMutex` of the [`Resources`](rs_thread_embassy::Resources).
//! Timeouts inside this crate use rs-matter's timers (`embassy-time`), which
//! the target provides for rs-matter anyway; the Thread node itself keeps
//! its own clock.
//!
//! # Test harness
//!
//! The tests run two or more nodes on an in-memory medium in virtual time,
//! including the `embassy-time` timers of rs-matter
//! (`rs_thread_sim::testing`, feature `testing`), with a fake SRP / DNS-SD
//! server on the leader.

mod fmt;

#[cfg(feature = "ble-trouble")]
pub mod ble;

pub mod driver;
pub mod error;
pub mod flash_kv;
pub mod icd;
pub mod mdns;
pub mod net;
pub mod netctl;
pub mod netif;
pub mod persist;
pub mod threaddiag;

pub use rs_thread_embassy::{RsThread, Resources};
pub use rs_matter;
