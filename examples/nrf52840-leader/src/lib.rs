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
