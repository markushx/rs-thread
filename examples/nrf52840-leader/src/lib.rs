//! Board bring-up shared by the firmware binaries: the radio backend is chosen
//! by cargo feature (`radio-nrf802154`, the default, or `radio-embassy`).

#![no_std]

use embassy_executor::Spawner;
use embassy_nrf::gpio::{Level, Output, OutputDrive};
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
