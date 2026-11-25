//! ESP32-C6/H2 platform drivers for rs-thread.
//!
//! - `EspRadio`: an [`rs_thread_platform::Radio`] over the ESP32-C6/H2
//!   IEEE 802.15.4 radio peripheral, via the `esp-ieee802154` crate (0.5.x).
//! - `EmbassyClock` / `EmbassyAlarm`: [`rs_thread_platform::Clock`] and
//!   [`rs_thread_platform::Alarm`] over `embassy-time`.
//! - `EspRng`: the ESP32-C6 `Rng` peripheral as a `rand_core` 0.10
//!   `CryptoRng` entropy source.
//! - `EspFlash` / `Flash`: async `NorFlash` wrapper over `esp-storage`
//!   for the `rs-thread-flash` settings log.
//!
//! # Target
//!
//! The hardware drivers are only compiled for `target_arch = "riscv32"` (the
//! ESP32-C6 and ESP32-H2 targets). On the host (x86-64, aarch64) this crate
//! is empty so the workspace builds and tests there.
//!
//! # Radio capabilities
//!
//! `EspRadio` reports no MAC-offload capabilities (`MacCapabilities::empty()`),
//! so the rs-thread soft-MAC layer handles address filtering, software ACK,
//! CSMA-CA backoff, retransmissions and transmit security entirely in Rust.
//! This is the same level as the `radio-embassy` nRF backend.
//!
//! Energy scan is not exposed by esp-ieee802154 0.8's public API; the trait's
//! default implementation returns `RSSI_INVALID` and energy scans report no
//! results rather than fake readings. Full energy scan support requires a
//! future esp-ieee802154 release or a direct HAL extension.
//!
//! # BLE coexistence
//!
//! esp-ieee802154 0.8.0 does not support Wi-Fi/BLE coexistence. The Matter
//! light firmware (Phase 17d) requires a separate path that integrates with
//! the ESP coexistence framework.
//!
//! # Firmware requirements
//!
//! The firmware crate must:
//! - Provide an `embassy-time` driver compatible with version 0.5 (e.g. via
//!   the `esp-hal-embassy` integration crate).
//! - Enable `esp-hal/unstable` (required by `esp-ieee802154`).
//! - Provide a `critical-section` implementation (normally via
//!   `esp-hal`'s default features or `critical-section/restore-state-bool`).
//!
//! # Build commands
//!
//! ```text
//! cd examples/esp32c6-leader
//! cargo build --release
//! cargo clippy --release -- -D warnings
//! ```
//!
//! `cargo run --release` flashes and runs through `probe-rs` (or `espflash`,
//! configured in the firmware's `.cargo/config.toml`).

#![no_std]

#[cfg(target_arch = "riscv32")]
mod clock;
#[cfg(target_arch = "riscv32")]
mod flash;
#[cfg(target_arch = "riscv32")]
mod radio;

#[cfg(target_arch = "riscv32")]
pub use clock::{EmbassyAlarm, EmbassyClock};
#[cfg(target_arch = "riscv32")]
pub use flash::{EspFlash, Flash};
#[cfg(target_arch = "riscv32")]
pub use radio::{EspRadio, EspRadioError};

/// The ESP32-C6 RNG peripheral as a `rand_core` `CryptoRng` entropy source
/// (`rs_thread_platform::Entropy`).
///
/// In esp-hal 0.23, obtain one with `esp_hal::rng::Rng::new(peripherals.RNG)`.
#[cfg(target_arch = "riscv32")]
pub type EspRng = esp_hal::rng::Rng;
