//! Flash access for the settings store, per radio backend.

use embassy_nrf::Peri;
use embassy_nrf::nvmc::{Error, Nvmc};
use embassy_nrf::peripherals::NVMC;
use embedded_storage::nor_flash::{ErrorType, NorFlash, ReadNorFlash};

/// The embassy-nrf [`Nvmc`] as an async `NorFlash` (the operations are
/// blocking: the CPU stalls during a write and an erase, which is fine when
/// the radio is the pure-Rust backend and nothing else needs the flash).
pub struct NvmcAsync<'d>(Nvmc<'d>);

impl core::fmt::Debug for NvmcAsync<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("NvmcAsync")
    }
}

impl<'d> NvmcAsync<'d> {
    /// Take the NVMC peripheral.
    pub fn new(nvmc: Peri<'d, NVMC>) -> Self {
        Self(Nvmc::new(nvmc))
    }
}

impl ErrorType for NvmcAsync<'_> {
    type Error = Error;
}

impl embedded_storage_async::nor_flash::ReadNorFlash for NvmcAsync<'_> {
    const READ_SIZE: usize = <Nvmc<'_> as ReadNorFlash>::READ_SIZE;
    async fn read(&mut self, offset: u32, bytes: &mut [u8]) -> Result<(), Self::Error> {
        self.0.read(offset, bytes)
    }
    fn capacity(&self) -> usize {
        self.0.capacity()
    }
}

impl embedded_storage_async::nor_flash::NorFlash for NvmcAsync<'_> {
    const WRITE_SIZE: usize = <Nvmc<'_> as NorFlash>::WRITE_SIZE;
    const ERASE_SIZE: usize = <Nvmc<'_> as NorFlash>::ERASE_SIZE;
    async fn erase(&mut self, from: u32, to: u32) -> Result<(), Self::Error> {
        self.0.erase(from, to)
    }
    async fn write(&mut self, offset: u32, bytes: &[u8]) -> Result<(), Self::Error> {
        self.0.write(offset, bytes)
    }
}

/// The flash driver of the selected radio backend (async `NorFlash`):
/// `nrf_mpsl::Flash` with `radio-nrf802154` (erases and writes are scheduled
/// into MPSL timeslots between radio activity), [`NvmcAsync`] with
/// `radio-embassy`.
#[cfg(feature = "radio-nrf802154")]
pub type Flash = nrf_mpsl::Flash<'static>;
/// The flash driver of the selected radio backend (async `NorFlash`).
#[cfg(feature = "radio-embassy")]
pub type Flash = NvmcAsync<'static>;

/// The flash driver for `radio-nrf802154`: it must go through MPSL, or flash
/// operations would collide with radio timeslots. Call once, after
/// [`init_mpsl`](crate::init_mpsl).
#[cfg(feature = "radio-nrf802154")]
pub fn take_flash(mpsl: &'static crate::Mpsl, nvmc: Peri<'static, NVMC>) -> Flash {
    nrf_mpsl::Flash::take(mpsl, nvmc)
}

/// The flash driver for `radio-embassy`.
#[cfg(feature = "radio-embassy")]
pub fn take_flash(nvmc: Peri<'static, NVMC>) -> Flash {
    NvmcAsync::new(nvmc)
}
