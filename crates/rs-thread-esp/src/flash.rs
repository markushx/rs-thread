//! Flash access for the settings store.
//!
//! [`EspFlash`] wraps `esp-storage`'s synchronous `FlashStorage` in the
//! `embedded-storage-async` async `NorFlash` interface that `rs-thread-flash`
//! expects. The operations are blocking: the CPU stalls during a write or
//! erase, which is acceptable for the firmware (there is no radio timeslot
//! scheduler like MPSL to work around on ESP32).
//!
//! The firmware must partition flash so that the Thread settings region does
//! not overlap any other use (application image, NVS, SPIFFS, …). Pass the
//! region's offset and length to [`EspFlash::new`]. A typical layout reserves
//! the last 24 KiB of the 4 MiB flash for Thread settings (offset
//! `0x003F4000`, length `0x6000`).

use embedded_storage::nor_flash::{ErrorType, NorFlash, ReadNorFlash};
use esp_storage::FlashStorage;

/// Async wrapper around `esp-storage`'s synchronous `FlashStorage`.
///
/// All operations translate directly to the underlying blocking implementation;
/// the `async` qualifier simply satisfies the `embedded-storage-async` trait
/// bound that `rs-thread-flash` requires.
pub struct EspFlash {
    storage: FlashStorage,
    offset: u32,
}

impl core::fmt::Debug for EspFlash {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("EspFlash")
            .field("offset", &self.offset)
            .finish_non_exhaustive()
    }
}

impl EspFlash {
    /// Create a flash accessor for the region starting at `offset` (absolute
    /// byte address in flash). The firmware is responsible for ensuring the
    /// region is free of other data.
    pub fn new(offset: u32) -> Self {
        Self {
            storage: FlashStorage::new(),
            offset,
        }
    }
}

impl ErrorType for EspFlash {
    type Error = esp_storage::FlashStorageError;
}

impl embedded_storage_async::nor_flash::ReadNorFlash for EspFlash {
    const READ_SIZE: usize = <FlashStorage as ReadNorFlash>::READ_SIZE;

    async fn read(&mut self, offset: u32, bytes: &mut [u8]) -> Result<(), Self::Error> {
        self.storage.read(self.offset + offset, bytes)
    }

    fn capacity(&self) -> usize {
        self.storage.capacity()
    }
}

impl embedded_storage_async::nor_flash::NorFlash for EspFlash {
    const WRITE_SIZE: usize = <FlashStorage as NorFlash>::WRITE_SIZE;
    const ERASE_SIZE: usize = <FlashStorage as NorFlash>::ERASE_SIZE;

    async fn erase(&mut self, from: u32, to: u32) -> Result<(), Self::Error> {
        self.storage.erase(self.offset + from, self.offset + to)
    }

    async fn write(&mut self, offset: u32, bytes: &[u8]) -> Result<(), Self::Error> {
        self.storage.write(self.offset + offset, bytes)
    }
}

/// The flash driver type for use with `rs-thread-flash`.
pub type Flash = EspFlash;
