//! OpenTrust leader on the nRF52840 DK: forms a Thread network with a fixed
//! test dataset (channel 15, PAN ID 0x1234, name "OpenTrust") and logs the
//! role, RLOC16, ML-EID and MAC counters over RTT.

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
use opentrust_embassy::{OpenTrust, Resources};
use opentrust_instance::{ExtAddress, Instance};
use opentrust_nrf::{EmbassyAlarm, EmbassyClock, NrfRng};
use opentrust_platform::{Radio, RamSettings};
use panic_probe as _;
use static_cell::StaticCell;

defmt::timestamp!("{=u64:us}", embassy_time::Instant::now().as_micros());

type Res = Resources<NoopRawMutex, EmbassyClock, RamSettings<4096>, SoftCrypto, NrfRng<'static>>;
static RES: StaticCell<Res> = StaticCell::new();

const PAINT: u32 = 0xDEAD_BEEF;

unsafe extern "C" {
    static mut __sheap: u32;
    static _stack_start: u32;
}

/// Fill the unused stack area with a pattern (call early in `main`).
fn paint_stack() {
    let sp = cortex_m::register::msp::read() as usize;
    let mut p = core::ptr::addr_of_mut!(__sheap);
    // SAFETY: everything between the end of .bss and the stack pointer is
    // unused (no heap); 256 bytes of margin below the live frames.
    unsafe {
        while (p as usize) < sp - 256 {
            p.write_volatile(PAINT);
            p = p.add(1);
        }
    }
}

/// Bytes of stack used so far (deepest point reached).
fn stack_high_water() -> usize {
    let mut p = core::ptr::addr_of!(__sheap);
    let top = core::ptr::addr_of!(_stack_start) as usize;
    // SAFETY: reads RAM words between the end of .bss and the stack top.
    unsafe {
        while (p as usize) < top && p.read_volatile() == PAINT {
            p = p.add(1);
        }
    }
    top - p as usize
}

/// EUI-64 from the factory-programmed device ID (locally administered,
/// unicast).
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
    paint_stack();
    let Board { rng, mut radio, .. } = nrf52840_leader::init(&spawner);
    let caps = radio.init().await.unwrap();
    info!("radio caps: {:?}", caps);
    info!("soft MAC needs: {:?}", caps.soft_mac_needs());

    let ext = ext_address();
    info!("ext address {:x}", ext.0);
    let config = opentrust_instance::Config::router(ext, caps);
    // Built in place in static memory: the instance is ~100 kB, it never
    // lives on the stack.
    let res: &'static Res = Resources::init(RES.uninit(), EmbassyClock, |slot| {
        Instance::init(slot, config, RamSettings::<4096>::new(), SoftCrypto, rng);
    });
    info!("stack peak during init {} bytes", stack_high_water());
    // Steady state from here on: measure again from a clean pattern.
    paint_stack();
    let ot = OpenTrust::new(res);

    let app = async {
        ot.with(|i, now| {
            let ds =
                opentrust_instance::Dataset::from_tlvs(&nrf52840_leader::DATASET_TLVS).unwrap();
            i.set_active_dataset(&ds, now).unwrap();
            i.ip6_set_enabled(true);
            i.become_leader(now).unwrap();
        });
        let mut last_role = None;
        loop {
            let role = ot.role();
            if last_role != Some(role) {
                info!("role: {:?}", defmt::Debug2Format(&role));
                last_role = Some(role);
            }
            let (rloc, eid, c) = ot.with(|i, _| (i.rloc16(), i.ml_eid(), *i.mac_counters()));
            info!(
                "rloc16 {:#06x} ml-eid {}",
                rloc.0,
                defmt::Display2Format(&eid)
            );
            info!(
                "mac: tx_total {} tx_beacon {} tx_data {} tx_err_cca {} tx_err_abort {} rx_total {} rx_beacon_req {} rx_other {}",
                c.tx_total,
                c.tx_beacon,
                c.tx_data,
                c.tx_err_cca,
                c.tx_err_abort,
                c.rx_total,
                c.rx_beacon_request,
                c.rx_other
            );
            info!("stack high-water {} bytes", stack_high_water());
            select(ot.wait_changed(), Timer::after_secs(5)).await;
        }
    };
    select(ot.run(radio, EmbassyAlarm), app).await;
}
