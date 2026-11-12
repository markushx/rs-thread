#![no_std]
//! rs-matter integration for the OpenTrust Thread stack (Matter over Thread).
//!
//! Part of OpenTrust, a pure Rust implementation of the Thread 1.4.1 protocol.
//!
//! This crate implements the traits `rs-matter-stack` needs from a Thread
//! transport on top of the native async facade of
//! [`opentrust_embassy`] (the [`OpenTrust`](opentrust_embassy::OpenTrust)
//! handle), in the place where `rs-matter-embassy` puts its adapters for the
//! esp-rs `openthread` crate:
//!
//! | rs-matter trait | This crate | Backed by |
//! |---|---|---|
//! | `rs_matter::stack::net::{NetStack, NetSocket}` + `NetworkSend` / `NetworkReceive` / `NetworkMulticast` | [`net::MatterNetStack`] / [`net::MatterSocket`] | `UdpSocket` (one socket for Matter port 5540) |
//! | `rs_matter::stack::mdns::Mdns` | [`mdns::SrpMdns`] | SRP client (registration) + DNS-SD client (resolve / browse) |
//! | `NetifDiag` + `NetChangeNotif` | [`netif::ThreadNetif`] | address list, `wait_changed` (any number of waiters) |
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
//! Not covered yet: `NetCtl` (Thread Network Commissioning), `ThreadDiag`,
//! the `ThreadDriver` runner with settings persistence, and the ICD hooks.
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
//! Locking is the `RawMutex` of the [`Resources`](opentrust_embassy::Resources).
//! Timeouts inside this crate use rs-matter's timers (`embassy-time`), which
//! the target provides for rs-matter anyway; the Thread node itself keeps
//! its own clock.
//!
//! # Test harness
//!
//! The tests run two or more nodes on an in-memory medium in virtual time,
//! including the `embassy-time` timers of rs-matter
//! (`opentrust_sim::testing`, feature `testing`), with a fake SRP / DNS-SD
//! server on the leader.

mod fmt;

pub mod error;
pub mod mdns;
pub mod net;
pub mod netctl;
pub mod netif;

pub use opentrust_embassy::{OpenTrust, Resources};
pub use rs_matter;
