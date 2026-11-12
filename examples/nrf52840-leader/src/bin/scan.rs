//! nRF52840 DK: energy scan of all 2.4 GHz channels and a MAC beacon active
//! scan, logged over RTT. Shows that receive and transmit work with real RF:
//! Wi-Fi energy shows up on the channels it overlaps, other Thread networks
//! answer the beacon request.

#![no_std]
#![no_main]

use defmt::info;
use defmt_rtt as _;
use embassy_executor::Spawner;
use embassy_futures::select::select;
use embassy_sync::blocking_mutex::raw::NoopRawMutex;
use embassy_time::Timer;
use nrf52840_leader::Board;
use opentrust_core::crypto::soft::SoftCrypto;
use opentrust_core::time::{Duration, Instant};
use opentrust_embassy::{Event, OpenTrust, Resources};
use opentrust_instance::{ExtAddress, Instance};
use opentrust_nrf::{EmbassyAlarm, EmbassyClock, NrfRng};
use opentrust_platform::{Radio, RamSettings};
use panic_probe as _;
use static_cell::StaticCell;

defmt::timestamp!("{=u64:us}", embassy_time::Instant::now().as_micros());

type Res = Resources<NoopRawMutex, EmbassyClock, RamSettings<4096>, SoftCrypto, NrfRng<'static>>;
static RES: StaticCell<Res> = StaticCell::new();

fn ext_address() -> ExtAddress {
    let ficr = embassy_nrf::pac::FICR;
    let lo = ficr.deviceid(0).read();
    let hi = ficr.deviceid(1).read();
    let mut a = [0u8; 8];
    a[..4].copy_from_slice(&hi.to_be_bytes());
    a[4..].copy_from_slice(&lo.to_be_bytes());
    a[0] = (a[0] | 0x02) & !0x01;
    ExtAddress(a)
}

#[embassy_executor::main]
async fn main(spawner: Spawner) {
    let Board { rng, mut radio, .. } = nrf52840_leader::init(&spawner);
    let caps = radio.init().await.unwrap();
    let instance = Instance::new(
        opentrust_instance::Config::router(ext_address(), caps),
        RamSettings::<4096>::new(),
        SoftCrypto,
        rng,
    );
    let res: &'static Res = RES.init(Resources::new(instance, EmbassyClock));
    let ot = OpenTrust::new(res);

    let app = async {
        for round in 0..3u8 {
            info!("round {}: energy scan, 100 ms per channel", round);
            let r = ot
                .energy_scan(0, Duration::from_millis(100), |ch, dbm| {
                    info!("  channel {} max RSSI {} dBm", ch, dbm);
                })
                .await;
            info!("energy scan done: {}", r.is_ok());

            info!("round {}: active scan, 300 ms per channel", round);
            let started =
                ot.with(|i, now: Instant| i.active_scan_start(0, Duration::from_millis(300), now));
            if started.is_err() {
                info!("active scan did not start");
                continue;
            }
            let mut beacons = 0u32;
            loop {
                match ot.next_event().await {
                    Event::ActiveScanResult(b) => {
                        beacons += 1;
                        info!(
                            "  beacon: channel {} rssi {} lqi {} pan {:#06x} src {:x} thread {}",
                            b.channel,
                            b.rssi,
                            b.lqi,
                            b.pan_id.0,
                            b.ext_addr.0,
                            defmt::Debug2Format(&b.thread)
                        );
                    }
                    Event::ActiveScanDone => break,
                    _ => {}
                }
            }
            let c = ot.with(|i, _| *i.mac_counters());
            info!(
                "active scan done: {} beacons; mac tx_beacon_request {} tx_err_cca {} rx_total {} rx_beacon {}",
                beacons, c.tx_beacon_request, c.tx_err_cca, c.rx_total, c.rx_beacon
            );
            Timer::after_secs(1).await;
        }
        info!("done");
        loop {
            Timer::after_secs(60).await;
        }
    };
    select(ot.run(radio, EmbassyAlarm), app).await;
}
