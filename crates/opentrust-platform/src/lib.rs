#![no_std]
//! Platform abstraction traits (radio, clock/alarm, entropy, settings) for OpenTrust.
//!
//! Part of OpenTrust, a pure Rust implementation of the Thread 1.4.1 protocol.
//!
//! Currently provided:
//! - [`settings`]: the blocking [`SettingsStore`] trait (analogue of
//!   `otPlatSettings*`) and an in-memory [`RamSettings`] for tests/simulation.
//! - [`Entropy`]: the entropy source type (a re-export of
//!   [`rand_core::CryptoRng`]).
//!
//! The Radio trait (Phase 2) and the Clock/Alarm traits (async facade) will be
//! added here as separate modules (`radio`, `time`) later.

pub mod settings;

pub use settings::{RamSettings, SettingsStore};

/// Cryptographically secure entropy source (true random number generator).
///
/// This is [`rand_core::CryptoRng`] re-exported rather than a new trait, so
/// that platform RNGs (e.g. `esp-hal`, `embassy-nrf` `Rng`, `OsRng`) can be
/// plugged in directly. It replaces OpenThread's `otPlatEntropyGet`.
pub use rand_core::CryptoRng as Entropy;
