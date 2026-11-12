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
//! The radio is selected by cargo feature; the clock/alarm and RNG glue is
//! backend-independent. `radio-embassy` (default) is the only backend today.
//! A second backend over the sysgrok `nrf-802154` crate (Nordic's C driver
//! with MPSL: hardware ACK, CSL, BLE coexistence) is planned behind its own
//! feature, exporting the same `NrfRadio` name.
//!
//! The hardware drivers only exist when compiling for an ARM target; on the
//! host this crate is empty so that the workspace builds and tests there.
//!
//! # Radio capabilities
//!
//! The nRF52840 radio has no MAC offload that `embassy-nrf` exposes, so
//! [`NrfRadio`] reports no MAC capabilities: the OpenTrust MAC does
//! address filtering, software ACK, ACK matching, ACK timeout, retries, CSMA
//! backoff and transmit security itself. The radio does CCA before a
//! transmission (`transmit` fails with `TxFailed` when the channel is busy),
//! and supports energy scan (RSSI sampling).

#![no_std]

#[cfg(target_arch = "arm")]
mod clock;
#[cfg(all(target_arch = "arm", feature = "radio-embassy"))]
mod radio_embassy;

#[cfg(target_arch = "arm")]
pub use clock::{EmbassyAlarm, EmbassyClock};
/// The radio of the selected backend (feature `radio-embassy`).
#[cfg(all(target_arch = "arm", feature = "radio-embassy"))]
pub use radio_embassy::NrfRadio;

/// The nRF52840 RNG peripheral, usable as the stack's entropy source
/// (`opentrust_platform::Entropy`).
#[cfg(target_arch = "arm")]
pub type NrfRng<'d> = embassy_nrf::rng::Rng<'d, embassy_nrf::mode::Blocking>;

#[cfg(target_arch = "arm")]
const _: () = {
    const fn assert_entropy<T: opentrust_platform::Entropy>() {}
    assert_entropy::<NrfRng<'static>>();
};
