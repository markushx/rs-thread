//! nRF52840 platform drivers for OpenTrust.
//!
//! - [`NrfRadio`]: an [`opentrust_platform::Radio`] over the 802.15.4 mode of
//!   the nRF52840 RADIO peripheral, wrapping `embassy-nrf`'s
//!   `radio::ieee802154` driver.
//! - [`EmbassyClock`] / [`EmbassyAlarm`]: [`opentrust_platform::Clock`] and
//!   [`opentrust_platform::Alarm`] over `embassy-time`.
//! - [`NrfRng`]: the RNG peripheral as a `rand_core` 0.10 `CryptoRng`
//!   (re-exported from `embassy-nrf`, which implements the trait).
//!
//! # Backends
//!
//! The radio is selected by cargo feature (exactly one; both is a compile
//! error); either exports the same `NrfRadio` name. The clock/alarm and RNG
//! glue is backend-independent.
//!
//! | Feature | Radio code | Build needs |
//! |---|---|---|
//! | `radio-embassy` (default) | pure Rust (`embassy-nrf` `radio::ieee802154`) | Rust only |
//! | `radio-nrf802154` | Nordic 802.15.4 driver (C) + MPSL (prebuilt), via the sysgrok `nrf-802154` crate | `clang`, `cmake`, Rust 1.93 |
//!
//! The hardware drivers only exist when compiling for an ARM target; on the
//! host this crate is empty so that the workspace builds and tests there.
//!
//! Build commands (the firmware has its own workspace and target directory;
//! `unset CARGO_TARGET_DIR` first):
//!
//! ```text
//! cd examples/nrf52840-leader
//! cargo build --release                                              # radio-nrf802154 (default)
//! cargo build --release --no-default-features --features radio-embassy
//! cargo build --release --bin scan                                   # likewise for the scan binary
//! cargo clippy --release -- -D warnings                              # both backends are checked this way
//! ```
//!
//! `cargo run --release` flashes and runs through `probe-rs` (see the
//! firmware's `.cargo/config.toml`).
//!
//! On macOS the `radio-nrf802154` build needs `ar` / `ranlib` / `clang` shims
//! (llvm-ar instead of Apple's `ar`): `examples/nrf52840-leader/tools/mkshims.sh`
//! creates them under `target/fw/shims` and prints the directory, so
//! `export PATH="$(examples/nrf52840-leader/tools/mkshims.sh):$PATH"`.
//!
//! `examples/nrf52840-light` (own workspace, same build commands) runs the
//! `opentrust-matter` on-off light on the DK; it uses the leader firmware's
//! board bring-up.
//!
//! # Radio capabilities
//!
//! ## `radio-embassy`
//!
//! The `embassy-nrf` driver has no MAC offload, so [`NrfRadio`] reports no MAC
//! capabilities: the OpenTrust MAC does address filtering, software ACK, ACK
//! matching, ACK timeout, retries, CSMA backoff and transmit security itself.
//! The radio does CCA before a transmission (`transmit` fails with `TxFailed`
//! when the channel is busy), and supports energy scan (RSSI sampling).
//!
//! ## `radio-nrf802154`
//!
//! Nordic's driver implements the MAC functions below the `Radio` trait, so
//! the backend reports all `MacCapabilities` (hardware ACK in both directions,
//! address filtering, source-match table for Frame Pending) and the PHY
//! capabilities `ACK_TIMEOUT`, `CSMA_BACKOFF`, `AUTO_SLEEP`,
//! `TRANSMIT_FRAME_POWER`, `RECEIVE_TIMING`, `TRANSMIT_TIMING`,
//! `TRANSMIT_SEC` (frame counter, CSL IE and AES-CCM\* at transmit time,
//! secured enhanced ACKs) and `ENERGY_SCAN`. The driver does not retransmit
//! (`TRANSMIT_RETRIES` is not reported), so the MAC keeps the retry loop and
//! `SoftMacNeeds` is `RETRANSMIT` only. The mapping is ported from
//! `nrf_802154::OpenThreadRadio`, without the esp-rs `openthread` crate.
//!
//! MPSL (clocks, timeslots, BLE coexistence) must be initialised before the
//! radio: [`init_mpsl`] with the 32.768 kHz crystal as LF clock source (the
//! nRF52840 DK has one), then `MultiprotocolServiceLayer::run` on an
//! executor. MPSL requires its own critical-section implementation (enabled
//! by the feature, so the application must not enable
//! `cortex-m/critical-section-single-core`) and owns these peripherals:
//! `RTC0`, `TIMER0`, `TEMP`, `PPI_CH19`, `PPI_CH30`, `PPI_CH31`; the driver
//! uses `RADIO`, `EGU0`, `TIMER2`, `RTC2`. `RTC1` (the embassy time driver)
//! and `RNG` stay with the application: neither MPSL nor the driver uses the
//! RNG peripheral.
//!
//! # Licensing
//!
//! The project's goal is pure Rust; `radio-nrf802154` is the exception and
//! stays behind its feature (nothing below is linked with `radio-embassy`).
//! Checked against the crate sources (`nrf-802154` commit 012c01c,
//! `nrf-802154-sys` 0.1.0, `nrf-mpsl-sys` 0.3.0):
//!
//! - The Rust crates `nrf-802154`, `nrf-802154-sys`, `nrf-mpsl` and
//!   `nrf-mpsl-sys`'s Rust part: MIT OR Apache-2.0.
//! - Nordic's `nrf_802154` driver and common code are **C source**, compiled
//!   by `nrf-802154-sys` with `clang` and `cmake`; the files carry
//!   `SPDX-License-Identifier: BSD-3-Clause`.
//! - `libnrf-802154-sl.a` (Nordic's 802.15.4 service layer, about 54 kB for
//!   the nRF52840) is a **prebuilt binary**, and so is `libmpsl.a` (MPSL,
//!   about 88 kB, shipped in `nrf-mpsl-sys`). Both are covered by
//!   `LicenseRef-Nordic-5-Clause`: a BSD-style licence that additionally
//!   requires the software to be used only with a Nordic Semiconductor
//!   integrated circuit, and forbids reverse engineering, decompiling,
//!   modifying or disassembling the binaries. `nrf-mpsl-sys` declares exactly
//!   this licence as its `license-file`. MPSL also uses a few functions covered by
//!   ARM Ltd's BSD-3-Clause (its attribution file).
//! - The nrfx register headers (BSD-3-Clause) and ARM CMSIS headers
//!   (Apache-2.0) are compile-time inputs only.
//!
//! So firmware with this backend contains closed-source Nordic binaries
//! under a Nordic-only licence: it cannot be used on non-Nordic silicon and
//! its redistribution must follow Nordic's terms. The source of MPSL is not
//! available, so this part cannot be made pure Rust.
//!
//! # Build requirements of `radio-nrf802154`
//!
//! `clang` (target `thumbv7em-none-eabihf`), `cmake` and Rust 1.93 or newer.
//! The first build fetches the git submodules of `nrf-802154` (about 1 GB of
//! nrfxlib, nrfx and CMSIS history) into cargo's git cache. On macOS, Apple's
//! `ar` silently drops ELF objects and the driver archive comes out empty (the
//! link then fails with undefined `nrf_802154_*` symbols): put `llvm-ar`
//! (`rustup component add llvm-tools`) as `ar`, a no-op as `ranlib` and a
//! symlink to `/usr/bin/clang` into one directory, and put that first in
//! `PATH` (CMake takes `ar` from the compiler's directory). The C driver is
//! built once per target directory.

#![no_std]

#[cfg(all(feature = "radio-embassy", feature = "radio-nrf802154"))]
compile_error!("features `radio-embassy` and `radio-nrf802154` are mutually exclusive");

#[cfg(target_arch = "arm")]
mod clock;
#[cfg(target_arch = "arm")]
mod flash;
#[cfg(all(target_arch = "arm", feature = "radio-embassy"))]
mod radio_embassy;
#[cfg(all(target_arch = "arm", feature = "radio-nrf802154"))]
mod radio_nrf802154;

#[cfg(target_arch = "arm")]
pub use clock::{EmbassyAlarm, EmbassyClock};
#[cfg(target_arch = "arm")]
pub use flash::{Flash, NvmcAsync, take_flash};
/// The radio of the selected backend (feature `radio-embassy`).
#[cfg(all(target_arch = "arm", feature = "radio-embassy"))]
pub use radio_embassy::NrfRadio;
/// The radio of the selected backend (feature `radio-nrf802154`), with the
/// MPSL setup it needs.
#[cfg(all(target_arch = "arm", feature = "radio-nrf802154"))]
pub use radio_nrf802154::{
    Irqs, Mpsl, NrfRadio, TxErrorStats, frame_counts, init_mpsl, last_other_tx_error,
    tx_error_stats,
};

/// The nRF52840 RNG peripheral, usable as the stack's entropy source
/// (`opentrust_platform::Entropy`).
#[cfg(target_arch = "arm")]
pub type NrfRng<'d> = embassy_nrf::rng::Rng<'d, embassy_nrf::mode::Blocking>;

#[cfg(target_arch = "arm")]
const _: () = {
    const fn assert_entropy<T: opentrust_platform::Entropy>() {}
    assert_entropy::<NrfRng<'static>>();
};
