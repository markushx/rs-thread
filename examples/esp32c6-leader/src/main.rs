//! rs-thread FTD leader on the ESP32-C6: forms a Thread network with a fixed
//! test dataset (channel 15, PAN ID 0x1234, name "rs-thread") and logs the
//! role, RLOC16, ML-EID and MAC counters over RTT / defmt.

#![no_std]
#![no_main]

use defmt::info;
use defmt_rtt as _;
use esp_println::println;
use embassy_executor::Spawner;
use embassy_futures::select::select;
use embassy_sync::blocking_mutex::raw::NoopRawMutex;
use embassy_time::Timer;
use esp_backtrace as _;
use esp32c6_leader::{Board, ext_address, flash};
use rs_thread_core::crypto::soft::SoftCrypto;
use rs_thread_embassy::{Resources, RsThread};
use rs_thread_esp::{EmbassyAlarm, EmbassyClock};
use rs_thread_instance::Instance;
use rs_thread_platform::{Radio, RamSettings};
use static_cell::StaticCell;

defmt::timestamp!("{=u64:us}", embassy_time::Instant::now().as_micros());

#[defmt::panic_handler]
fn defmt_panic() -> ! {
    core::panic!("defmt panic")
}

type Res =
    Resources<NoopRawMutex, EmbassyClock, RamSettings<4096>, SoftCrypto, rs_thread_esp::EspRng>;
static RES: StaticCell<Res> = StaticCell::new();

#[embassy_executor::main]
async fn main(spawner: Spawner) {
    println!("rs-thread: board init start");
    let Board {
        mut radio,
        rng,
        mut flash,
        boot_button,
        ..
    } = esp32c6_leader::init(&spawner);
    println!("rs-thread: board init done, MAC={:02X?}", esp_hal::efuse::Efuse::mac_address());

    // Factory reset if BOOT button is held at startup.
    if flash::factory_reset_requested(&boot_button).await {
        info!("factory reset requested — erasing Thread settings");
        flash::erase_all(&mut flash)
            .await
            .expect("flash erase failed");
    }

    println!("rs-thread: radio init start");
    let caps = radio.init().await.unwrap();
    info!("radio caps: {:?}", caps);
    info!("soft MAC needs: {:?}", caps.soft_mac_needs());

    let ext = ext_address();
    info!("ext address {:x}", ext.0);

    let config = rs_thread_instance::Config::router(ext, caps);
    let res: &'static Res = Resources::init(RES.uninit(), EmbassyClock, |slot| {
        Instance::init(slot, config, RamSettings::<4096>::new(), SoftCrypto, rng);
    });
    let ot = RsThread::new(res);

    println!("rs-thread leader: radio init ok, starting Thread stack");

    let app = async {
        ot.with(|i, now| {
            let ds = rs_thread_instance::Dataset::from_tlvs(&esp32c6_leader::DATASET_TLVS).unwrap();
            i.set_active_dataset(&ds, now).unwrap();
            i.ip6_set_enabled(true);

            #[cfg(feature = "leader")]
            i.become_leader(now).unwrap();
        });

        let mut last_role = None;
        loop {
            let role = ot.role();
            if last_role != Some(role) {
                info!("role: {:?}", defmt::Debug2Format(&role));
                println!("rs-thread role: {:?}", role);
                last_role = Some(role);
            }
            let (rloc, eid, c) = ot.with(|i, _| (i.rloc16(), i.ml_eid(), *i.mac_counters()));
            info!(
                "rloc16 {:#06x} ml-eid {}",
                rloc.0,
                defmt::Display2Format(&eid)
            );
            println!("rs-thread rloc16={:#06x} tx={} rx={}", rloc.0, c.tx_total, c.rx_total);
            info!(
                "mac: tx_total {} tx_beacon {} tx_data {} tx_err_cca {} rx_total {} rx_beacon_req {}",
                c.tx_total, c.tx_beacon, c.tx_data, c.tx_err_cca, c.rx_total, c.rx_beacon_request,
            );
            select(ot.wait_changed(), Timer::after_secs(5)).await;
        }
    };
    select(ot.run(radio, EmbassyAlarm), app).await;
}
