//! OpenThread-compatible CLI firmware over USB-Serial-JTAG (or UART0).
//!
//! Flash and run:
//! ```text
//! cargo run --release --features cli-all --bin cli
//! ```
//! Then connect to the USB-Serial-JTAG port that appears on the host.

#![no_std]
#![no_main]

use defmt_rtt as _;
use embassy_executor::Spawner;
use esp_backtrace as _;
use esp32c6_leader::{Board, ext_address, flash};
use rs_thread_core::crypto::soft::SoftCrypto;
use rs_thread_embassy::{Resources, RsThread};
use rs_thread_esp::{EmbassyAlarm, EmbassyClock};
use rs_thread_instance::Instance;
use rs_thread_platform::{Radio, RamSettings};
use static_cell::StaticCell;

defmt::timestamp!("{=u64:us}", embassy_time::Instant::now().as_micros());

type Res = Resources<
    embassy_sync::blocking_mutex::raw::NoopRawMutex,
    EmbassyClock,
    RamSettings<4096>,
    SoftCrypto,
    rs_thread_esp::EspRng,
>;
static RES: StaticCell<Res> = StaticCell::new();

#[embassy_executor::main]
async fn main(spawner: Spawner) {
    let Board {
        mut radio,
        rng,
        mut flash,
        boot_button,
        uart: _uart,
    } = esp32c6_leader::init(&spawner);

    if flash::factory_reset_requested(&boot_button).await {
        defmt::info!("factory reset requested");
        flash::erase_all(&mut flash)
            .await
            .expect("flash erase failed");
    }

    let caps = radio.init().await.unwrap();
    let ext = ext_address();
    let config = rs_thread_instance::Config::router(ext, caps);
    let res: &'static Res = Resources::init(RES.uninit(), EmbassyClock, |slot| {
        Instance::init(slot, config, RamSettings::<4096>::new(), SoftCrypto, rng);
    });
    let ot = RsThread::new(res);

    // TODO(17b): wire up the UART/USB-Serial-JTAG async driver and pass it to
    // rs_thread_cli::run(). Until then, the CLI binary panics with an unimplemented message.
    let _ = ot.run(radio, EmbassyAlarm);
    panic!("CLI UART driver not yet implemented; see Phase 17b TODO");
}
