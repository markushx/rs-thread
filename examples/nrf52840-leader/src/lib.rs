//! Board bring-up shared by the firmware binaries: the radio backend is chosen
//! by cargo feature (`radio-nrf802154`, the default, or `radio-embassy`).

#![no_std]

use embassy_executor::Spawner;
use embassy_nrf::gpio::{Input, Level, Output, OutputDrive, Pull};
use opentrust_nrf::{NrfRadio, NrfRng};

/// Peripherals and radio of the board, ready for the stack.
pub struct Board {
    pub rng: NrfRng<'static>,
    /// A second handle on the RNG peripheral for application use (the
    /// blocking driver has no state beyond the peripheral, and the executor
    /// is single threaded, so both handles are used one call at a time).
    pub rng2: NrfRng<'static>,
    /// LED1 of the DK (P0.13, active low), initially off.
    pub led1: Output<'static>,
    pub radio: NrfRadio<'static>,
    /// The flash driver of the backend (through MPSL with `radio-nrf802154`).
    /// Only the regions of the [`flash`] module may be written.
    pub flash: opentrust_nrf::Flash,
    /// Button 1 of the DK (P0.11, active low): held at boot it requests a
    /// factory reset, see [`flash::factory_reset_requested`].
    pub button1: Input<'static>,
    /// What the BLE stack needs next to the 802.15.4 radio: the MPSL handle
    /// and the PPI channels of the SoftDevice Controller.
    #[cfg(feature = "ble")]
    pub ble: Ble,
}

/// The MPSL instance (already running on the executor) and the peripherals
/// the SoftDevice Controller takes (PPI channels 17, 18 and 20..=29).
#[cfg(feature = "ble")]
pub struct Ble {
    pub mpsl: &'static opentrust_nrf::Mpsl,
    pub sdc: nrf_sdc::Peripherals<'static>,
}

/// Where the persistent settings live in flash (see `memory.x`).
pub mod flash {
    /// Start of the reserved area (the linker symbol `__nvm_start`).
    pub const NVM_START: u32 = 0x000F_A000;
    /// Erase page size of the nRF52840.
    pub const PAGE: u32 = 4096;
    /// Thread settings: start offset and pages per bank (two banks).
    pub const THREAD_START: u32 = NVM_START;
    pub const THREAD_PAGES: u32 = 1;
    /// Key-value store of the Matter light: start offset and pages per bank.
    pub const KV_START: u32 = THREAD_START + 2 * THREAD_PAGES * PAGE;
    pub const KV_PAGES: u32 = 2;
    /// End of the reserved area: the end of flash.
    pub const NVM_END: u32 = KV_START + 2 * KV_PAGES * PAGE;

    unsafe extern "C" {
        static __nvm_start: u8;
    }

    /// Whether Button 1 is held (sampled after the pull-up settled). Call it
    /// at boot, before mounting the stores.
    pub async fn factory_reset_requested(button1: &embassy_nrf::gpio::Input<'_>) -> bool {
        embassy_time::Timer::after_millis(20).await;
        cfg!(feature = "test-factory-reset") || button1.is_low()
    }

    /// Erase the whole settings area (both stores). The next mount formats
    /// fresh banks.
    pub async fn erase_all<F: embedded_storage_async::nor_flash::NorFlash>(
        flash: &mut F,
    ) -> Result<(), F::Error> {
        flash.erase(NVM_START, NVM_END).await
    }

    /// Check that the constants agree with the linker script and the flash
    /// size, so the program image cannot overlap the settings.
    pub fn check() {
        let linker = core::ptr::addr_of!(__nvm_start) as u32;
        assert_eq!(linker, NVM_START);
        assert_eq!(NVM_END, 0x0010_0000);
    }
}

/// Initialise clocks, the RNG and the selected radio backend.
#[cfg(feature = "radio-embassy")]
pub fn init(_spawner: &Spawner) -> Board {
    use embassy_nrf::config::{Config, HfclkSource};
    use embassy_nrf::radio::ieee802154::Radio as HwRadio;
    use embassy_nrf::{bind_interrupts, peripherals, radio};

    bind_interrupts!(struct Irqs {
        RADIO => radio::InterruptHandler<peripherals::RADIO>;
    });

    let mut config = Config::default();
    // The 802.15.4 radio needs the crystal oscillator.
    config.hfclk_source = HfclkSource::ExternalXtal;
    let p = embassy_nrf::init(config);
    Board {
        // SAFETY: see `Board::rng2`.
        rng2: NrfRng::new_blocking(unsafe { p.RNG.clone_unchecked() }),
        rng: NrfRng::new_blocking(p.RNG),
        led1: Output::new(p.P0_13, Level::High, OutputDrive::Standard),
        radio: NrfRadio::new(HwRadio::new(p.RADIO, Irqs)),
        flash: opentrust_nrf::take_flash(p.NVMC),
        button1: Input::new(p.P0_11, Pull::Up),
    }
}

#[cfg(feature = "radio-nrf802154")]
#[embassy_executor::task]
async fn mpsl_task(mpsl: &'static opentrust_nrf::Mpsl) -> ! {
    mpsl.run().await
}

/// Initialise clocks, the RNG and the selected radio backend.
///
/// MPSL owns the HF and LF clocks, so embassy keeps its default clock
/// configuration here.
#[cfg(feature = "radio-nrf802154")]
pub fn init(spawner: &Spawner) -> Board {
    use static_cell::StaticCell;

    static MPSL: StaticCell<opentrust_nrf::Mpsl> = StaticCell::new();

    let p = embassy_nrf::init(embassy_nrf::config::Config::default());
    let mpsl =
        opentrust_nrf::init_mpsl(p.RTC0, p.TIMER0, p.TEMP, p.PPI_CH19, p.PPI_CH30, p.PPI_CH31)
            .unwrap();
    let mpsl: &'static opentrust_nrf::Mpsl = MPSL.init(mpsl);
    spawner.spawn(mpsl_task(mpsl).unwrap());
    Board {
        // SAFETY: see `Board::rng2`.
        rng2: NrfRng::new_blocking(unsafe { p.RNG.clone_unchecked() }),
        rng: NrfRng::new_blocking(p.RNG),
        led1: Output::new(p.P0_13, Level::High, OutputDrive::Standard),
        radio: NrfRadio::new(p.RADIO, p.EGU0, p.TIMER2, p.RTC2, mpsl),
        flash: opentrust_nrf::take_flash(mpsl, p.NVMC),
        button1: Input::new(p.P0_11, Pull::Up),
        #[cfg(feature = "ble")]
        ble: Ble {
            mpsl,
            sdc: nrf_sdc::Peripherals::new(
                p.PPI_CH17, p.PPI_CH18, p.PPI_CH20, p.PPI_CH21, p.PPI_CH22, p.PPI_CH23,
                p.PPI_CH24, p.PPI_CH25, p.PPI_CH26, p.PPI_CH27, p.PPI_CH28, p.PPI_CH29,
            ),
        },
    }
}

/// The Active Dataset (TLV encoded) shared by the firmware binaries and the
/// OpenThread peer in the interoperability tests: channel 25, PAN ID 0x1234,
/// network name "OpenTrust", extended PAN ID dead00beef00cafe, mesh-local
/// prefix fddead00beef::/64, network key 00112233445566778899aabbccddeeff.
/// The same bytes, hex encoded, are [`DATASET_HEX`].
pub const DATASET_TLVS: [u8; 100] = [
    0x00, 0x03, 0x00, 0x00, 0x19, // channel 25
    0x35, 0x06, 0x00, 0x04, 0x00, 0x1f, 0xff, 0xe0, // channel mask (11..=26)
    0x02, 0x08, 0xde, 0xad, 0x00, 0xbe, 0xef, 0x00, 0xca, 0xfe, // ext PAN ID
    0x03, 0x09, b'O', b'p', b'e', b'n', b'T', b'r', b'u', b's', b't', // name
    0x04, 0x10, 0x3a, 0xa5, 0x5f, 0x91, 0xca, 0x47, 0xd1, 0xe4, 0xe7, 0x1a, 0x08, 0xcb, 0x35, 0xe9,
    0x15, 0x91, // PSKc
    0x05, 0x10, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
    0xee, 0xff, // network key
    0x07, 0x08, 0xfd, 0xde, 0xad, 0x00, 0xbe, 0xef, 0x00, 0x00, // mesh-local prefix
    0x0c, 0x04, 0x02, 0xa0, 0xf7, 0xf8, // security policy
    0x0e, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, // active timestamp
    0x01, 0x02, 0x12, 0x34, // PAN ID
];

/// [`DATASET_TLVS`] as the hex string for `dataset set active` of the
/// OpenThread CLI.
pub const DATASET_HEX: &str = "000300001935060004001fffe00208dead00beef00cafe03094f70656e547275737404103aa55f91ca47d1e4e71a08cb35e91591051000112233445566778899aabbccddeeff0708fddead00beef00000c0402a0f7f80e08000000000001000001021234";
