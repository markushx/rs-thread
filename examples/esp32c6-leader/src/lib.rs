//! Board bring-up for ESP32-C6-DevKitC-1 and M5Stack NanoC6.
//!
//! Both boards carry the same ESP32-C6 SoC; they differ only in the GPIO
//! assignment of the WS2812 LED.  Select the board via the `board-devkitc1`
//! (default) or `board-nanoc6` Cargo feature.

#![no_std]

pub mod time_driver;

use embassy_executor::Spawner;
use esp_hal::{
    gpio::{Input, Pull},
    rng::Rng,
    uart::Uart,
};
use rs_thread_esp::{EspFlash, EspRadio, EspRng};

/// GPIO pin for the boot / factory-reset button (active low, pulled up).
/// GPIO9 is the standard BOOT button on both DevKitC-1 and NanoC6.
pub const BOOT_BUTTON_GPIO: u8 = 9;

/// GPIO pin for the addressable WS2812 LED data line.
#[cfg(feature = "board-devkitc1")]
pub const LED_GPIO: u8 = 8;
#[cfg(feature = "board-nanoc6")]
pub const LED_GPIO: u8 = 7;

/// Flash layout for the Thread settings store.
/// The ESP32-C6-DevKitC-1 and NanoC6 ship with 4 MiB (0x40_0000 bytes) of
/// flash.  The last 48 KiB is reserved for the Thread settings log.
pub mod flash {
    use embedded_storage_async::nor_flash::NorFlash;

    /// Start offset in flash for the Thread settings region.
    /// Must not overlap the application image.  Adjust if you change the
    /// partition table.
    pub const THREAD_START: u32 = 0x003F_4000;

    /// Size of the Thread settings region in bytes (48 KiB).
    pub const THREAD_LEN: u32 = 0xC000;

    /// End of the Thread settings region.
    pub const THREAD_END: u32 = THREAD_START + THREAD_LEN;

    /// Whether the BOOT button is held at startup (factory reset requested).
    ///
    /// Call after a short debounce delay, before mounting the settings store.
    pub async fn factory_reset_requested(boot: &esp_hal::gpio::Input<'_>) -> bool {
        embassy_time::Timer::after_millis(20).await;
        cfg!(feature = "test-factory-reset") || boot.is_low()
    }

    /// Erase the Thread settings region.
    pub async fn erase_all(
        flash: &mut rs_thread_esp::EspFlash,
    ) -> Result<(), <rs_thread_esp::EspFlash as embedded_storage::nor_flash::ErrorType>::Error>
    {
        flash.erase(0, THREAD_LEN).await
    }
}

/// Peripherals ready for use by the firmware binaries.
pub struct Board {
    /// IEEE 802.15.4 radio driver (rs-thread soft-MAC backend).
    pub radio: EspRadio<'static>,
    /// Random number generator (implements `rand_core 0.10` `CryptoRng`).
    pub rng: EspRng,
    /// Flash accessor for the Thread settings region.
    pub flash: EspFlash,
    /// BOOT button (GPIO9, active low, internal pull-up).
    pub boot_button: Input<'static>,
    /// UART0 for a serial console (optional; also used by the CLI binary).
    pub uart: Uart<'static, esp_hal::Blocking>,
}

/// Initialise clocks, the embassy-time driver, radio, RNG, flash and peripherals.
///
/// Must be called once at the start of `main` (or the first `async fn`).
pub fn init(_spawner: &Spawner) -> Board {
    let p = esp_hal::init(esp_hal::Config::default());

    // Set up the embassy-time 0.5 driver (SYSTIMER UNIT0 + COMP0).
    time_driver::init(p.SYSTIMER);

    // 802.15.4 radio: esp-ieee802154 wraps the IEEE802154 and RADIO_CLK peripherals.
    let ieee = esp_ieee802154::Ieee802154::new(p.IEEE802154, p.RADIO_CLK);
    let radio = EspRadio::new(ieee);

    // Flash accessor: points at the reserved settings region at the end of flash.
    let flash = EspFlash::new(flash::THREAD_START);

    // UART0 on the standard pins (TX=GPIO16, RX=GPIO17 on DevKitC-1 and NanoC6).
    let uart = Uart::new(p.UART0, esp_hal::uart::Config::default())
        .expect("UART0 config failed")
        .with_tx(p.GPIO16)
        .with_rx(p.GPIO17);

    // Boot / factory-reset button (GPIO9, pulled up, low-active).
    let boot_button = Input::new(p.GPIO9, Pull::Up);

    Board {
        radio,
        rng: EspRng::new(Rng::new(p.RNG)),
        flash,
        boot_button,
        uart,
    }
}

/// EUI-64 derived from the ESP32-C6 eFuse MAC address.
///
/// Converts the 6-byte MAC to a locally administered, unicast EUI-64 by
/// inserting 0xFF 0xFE in the middle (the standard expansion) and setting
/// the LA bit.
pub fn ext_address() -> rs_thread_instance::ExtAddress {
    let mac = esp_hal::efuse::Efuse::mac_address();
    let mut a = [0u8; 8];
    a[0] = (mac[0] | 0x02) & !0x01; // LA bit set, multicast bit cleared
    a[1] = mac[1];
    a[2] = mac[2];
    a[3] = 0xFF;
    a[4] = 0xFE;
    a[5] = mac[3];
    a[6] = mac[4];
    a[7] = mac[5];
    rs_thread_instance::ExtAddress(a)
}

/// Active Dataset (TLV encoded) shared by the binaries and the OT interop tests.
///
/// Channel 15, PAN ID 0x1234, network name "rs-thread",
/// extended PAN ID dead00beef00cafe, mesh-local prefix fddead00beef::/64,
/// network key 00112233445566778899aabbccddeeff.
///
/// Channel 15 avoids overlap with the nRF default (channel 25) when both
/// boards run simultaneously.
pub const DATASET_TLVS: [u8; 100] = [
    0x00, 0x03, 0x00, 0x00, 0x0F, // channel 15
    0x35, 0x06, 0x00, 0x04, 0x00, 0x1f, 0xff, 0xe0, // channel mask (11..=26)
    0x02, 0x08, 0xde, 0xad, 0x00, 0xbe, 0xef, 0x00, 0xca, 0xfe, // ext PAN ID
    0x03, 0x09, b'r', b's', b'-', b't', b'h', b'r', b'e', b'a', b'd', // name
    0x04, 0x10, 0x3a, 0xa5, 0x5f, 0x91, 0xca, 0x47, 0xd1, 0xe4, 0xe7, 0x1a, 0x08, 0xcb, 0x35, 0xe9,
    0x15, 0x91, // PSKc (same as nRF interop tests)
    0x05, 0x10, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
    0xee, 0xff, // network key
    0x07, 0x08, 0xfd, 0xde, 0xad, 0x00, 0xbe, 0xef, 0x00, 0x00, // mesh-local prefix
    0x0c, 0x04, 0x02, 0xa0, 0xf7, 0xf8, // security policy
    0x0e, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, // active timestamp
    0x01, 0x02, 0x12, 0x34, // PAN ID
];

/// [`DATASET_TLVS`] as the hex string for `dataset set active` in the OT CLI.
pub const DATASET_HEX: &str = "000300000f35060004001fffe00208dead00beef00cafe030972732d7468726561640410\
3aa55f91ca47d1e4e71a08cb35e9159105100011223344556677889\
9aabbccddeeff0708fddead00beef00000c0402a0f7f80e08000000000001000001021234";
