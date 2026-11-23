//! Persistent settings in NOR flash.
//!
//! Two halves with a clean split, so the node never waits for flash:
//!
//! - [`Shared`] holds the settings in RAM ([`Image`]). [`Settings`] is a
//!   [`SettingsStore`](rs_thread_platform::SettingsStore) over it for the
//!   Thread node; reads and writes are synchronous and cost a short critical
//!   section. Every write marks the key dirty and bumps the change counter.
//! - [`FlashWriter`] owns the flash and keeps it in step: [`mount`] loads the
//!   image at boot, [`flush`] writes the dirty keys. It is async, so it works
//!   with flash drivers that need the radio's cooperation (nrf-mpsl's `Flash`
//!   schedules erases and writes into timeslots) and with plain NVMC alike;
//!   any `embedded_storage_async::nor_flash::NorFlash` will do.
//!
//! The application runs `flush` from a task, typically after the node's
//! `wait_changed` (the Thread stack bumps the change counter for each
//! settings write) with a short debounce, or on a timer for the Matter
//! key-value store.
//!
//! # What a power cut loses
//!
//! A cut leaves flash at the last completed entry: older values are never
//! corrupted (see [`FlashWriter`]). Changes made after the last completed
//! flush are lost, at most the debounce interval plus one flash operation
//! (milliseconds; a page erase takes about 85 ms on the nRF52840). The
//! Thread stack persists its MAC and MLE frame counters ahead of use
//! (1000 frames, as OpenThread), so a flash write that lags by a few hundred
//! milliseconds cannot make a counter go backwards after reboot unless the
//! node sent a thousand frames in that time.
//!
//! [`mount`]: FlashWriter::mount
//! [`flush`]: FlashWriter::flush
//!
//! # Differences from OpenThread
//!
//! See `OPENTRUST-OPENTHREAD-DIFFERENCES.md`: OpenThread's reference
//! platform writes synchronously, one record per `otPlatSettings*` call; here
//! writes are deferred and merged per key.

#![no_std]

mod image;
mod writer;

pub use image::{Image, Settings, Shared};
pub use writer::{FlashError, FlashWriter};

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests;
