//! Board bring-up shared by the firmware binaries: the radio backend is chosen
//! by cargo feature (`radio-nrf802154`, the default, or `radio-embassy`).

#![no_std]

use embassy_executor::Spawner;
use opentrust_nrf::{NrfRadio, NrfRng};

/// Peripherals and radio of the board, ready for the stack.
pub struct Board {
    pub rng: NrfRng<'static>,
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
        rng: NrfRng::new_blocking(p.RNG),
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
        rng: NrfRng::new_blocking(p.RNG),
        radio: NrfRadio::new(p.RADIO, p.EGU0, p.TIMER2, p.RTC2, mpsl),
    }
}
