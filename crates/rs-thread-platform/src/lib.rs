#![no_std]
//! Platform abstraction traits (radio, clock/alarm, entropy, settings) for rs-thread.
//!
//! Part of rs-thread, a pure Rust implementation of the Thread 1.4.1 protocol.
//!
//! Currently provided:
//! - [`settings`]: the blocking [`SettingsStore`] trait (analogue of
//!   `otPlatSettings*`) and an in-memory [`RamSettings`] for tests/simulation.
//! - [`Entropy`]: the entropy source type (a re-export of
//!   [`rand_core::CryptoRng`]).
//!
//! - [`radio`]: the async IEEE 802.15.4 [`Radio`] trait and its types, mirroring
//!   esp-rs/openthread's `Radio` (see `docs/radio-contract.md`), the
//!   [`SoftMacNeeds`] capability summary for the software MAC, and an in-memory
//!   [`radio::sim::TestRadio`].
//! - [`time`]: the monotonic [`Clock`] and async [`Alarm`] traits for the async
//!   facade (executor-agnostic; no `embassy-time` dependency) and a
//!   [`time::MockClock`].

pub mod radio;
pub mod settings;
pub mod time;

pub use radio::{Radio, SoftMacNeeds};
pub use time::{Alarm, Clock};

pub use settings::{RamSettings, SettingsStore};

/// Cryptographically secure entropy source (true random number generator).
///
/// This is [`rand_core::CryptoRng`] re-exported rather than a new trait, so
/// that platform RNGs (e.g. `esp-hal`, `embassy-nrf` `Rng`, `OsRng`) can be
/// plugged in directly. It replaces OpenThread's `otPlatEntropyGet`.
pub use rand_core::CryptoRng as Entropy;
