//! OpenTrust node for interoperability tests against OpenThread on the
//! nRF52840 DK. It takes the shared test dataset
//! ([`nrf52840_leader::DATASET_TLVS`]) and starts Thread: it attaches to the
//! network of the peer (it only forms a partition of its own if nobody
//! answers). Role changes, RLOC16, addresses, neighbors, MAC counters and
//! ping results are logged over RTT. Echo requests are answered by the
//! stack; every `PING_PERIOD_SECS` it pings `PEER` (default: the Leader ALOC
//! of the shared mesh-local prefix, reachable whichever device leads).
//!
//! Features: `child-only` keeps the node a child (router upgrade disabled),
//! otherwise it is router eligible.

#![no_std]
#![no_main]

use core::cell::Cell;
use core::net::Ipv6Addr;

use defmt::info;
use defmt_rtt as _;
use embassy_executor::Spawner;
use embassy_futures::select::select;
use embassy_sync::blocking_mutex::raw::NoopRawMutex;
use embassy_time::Timer;
use nrf52840_leader::Board;
use opentrust_core::crypto::soft::SoftCrypto;
use opentrust_embassy::{OpenTrust, Resources};
use opentrust_instance::{Dataset, ExtAddress, Instance};
use opentrust_nrf::{EmbassyAlarm, EmbassyClock, NrfRng};
use opentrust_platform::{Radio, RamSettings};
use panic_probe as _;
use static_cell::StaticCell;

defmt::timestamp!("{=u64:us}", embassy_time::Instant::now().as_micros());

type Res = Resources<NoopRawMutex, EmbassyClock, RamSettings<4096>, SoftCrypto, NrfRng<'static>>;
static RES: StaticCell<Res> = StaticCell::new();

/// Address pinged periodically: the Leader ALOC (`<prefix>:0:ff:fe00:fc00`).
/// Edit to a peer ML-EID or RLOC address for other scenarios.
const PEER: Ipv6Addr = Ipv6Addr::new(0xfdde, 0xad00, 0xbeef, 0, 0, 0xff, 0xfe00, 0xfc00);
const PING_PERIOD_SECS: u64 = 5;
const STATUS_PERIOD_SECS: u64 = 10;
const PING_PAYLOAD: usize = 32;

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
    let ext = ext_address();
    info!("ext address {:x}", ext.0);
    let mut config = opentrust_instance::Config::router(ext, caps);
    config.mle.router.eligible = !cfg!(feature = "child-only");
    info!("router eligible: {}", config.mle.router.eligible);
    let res: &'static Res = Resources::init(RES.uninit(), EmbassyClock, |slot| {
        Instance::init(slot, config, RamSettings::<4096>::new(), SoftCrypto, rng);
    });
    let ot = OpenTrust::new(res);

    let app = async {
        ot.with(|i, now| {
            let ds = Dataset::from_tlvs(&nrf52840_leader::DATASET_TLVS).unwrap();
            i.set_active_dataset(&ds, now).unwrap();
            i.ip6_set_enabled(true);
            i.thread_start(now).unwrap();
        });
        let started = embassy_time::Instant::now();
        let mut last_role = None;
        let mut seq = 0u16;
        let (mut sent, mut got) = (0u32, 0u32);
        // Send times (microseconds) of the last 8 pings, by sequence number.
        let sent_at: Cell<[(u16, u64); 8]> = Cell::new([(0, 0); 8]);
        let mut next_ping = embassy_time::Instant::now();
        let mut next_status = embassy_time::Instant::now();
        loop {
            let role = ot.role();
            if last_role != Some(role) {
                info!(
                    "role: {:?} after {} ms",
                    defmt::Debug2Format(&role),
                    started.elapsed().as_millis()
                );
                last_role = Some(role);
            }
            while let Some(r) = ot.with(|i, _| i.take_ping_reply()) {
                got += 1;
                let (s, t) = sent_at.get()[r.seq as usize % 8];
                let rtt = if s == r.seq {
                    r.at.as_micros().saturating_sub(t)
                } else {
                    0
                };
                info!(
                    "ping reply from {} seq {} len {} hlim {}: {} us (replies {})",
                    defmt::Display2Format(&r.src),
                    r.seq,
                    r.payload_len,
                    r.hop_limit,
                    rtt,
                    got
                );
            }
            let now = embassy_time::Instant::now();
            if now >= next_ping {
                next_ping = now + embassy_time::Duration::from_secs(PING_PERIOD_SECS);
                if role.is_attached() {
                    seq = seq.wrapping_add(1);
                    let payload = [0x55u8; PING_PAYLOAD];
                    let r = ot.with(|i, now| {
                        let mut a = sent_at.get();
                        a[seq as usize % 8] = (seq, now.as_micros());
                        sent_at.set(a);
                        i.ping(PEER, None, 0x4f54, seq, &payload, now)
                    });
                    sent += 1;
                    info!(
                        "ping {} -> {}: {} (sent {})",
                        seq,
                        defmt::Display2Format(&PEER),
                        r.is_ok(),
                        sent
                    );
                }
            }
            if now >= next_status {
                next_status = now + embassy_time::Duration::from_secs(STATUS_PERIOD_SECS);
                ot.with(|i, _| {
                    info!(
                        "status: role {:?} rloc16 {:#06x} partition {:#x} ml-eid {}",
                        defmt::Debug2Format(&i.role()),
                        i.rloc16().0,
                        i.partition_id(),
                        defmt::Display2Format(&i.ml_eid())
                    );
                    for a in i.unicast_addresses() {
                        info!("  addr {}", defmt::Debug2Format(a));
                    }
                    for n in i.neighbor_table() {
                        info!(
                            "  neighbor {:#06x} {:x} child {} lqi_in {} rssi {} ftd {} rxon {}",
                            n.rloc16.0,
                            n.ext.0,
                            n.is_child,
                            n.link_quality_in,
                            n.average_rssi,
                            n.full_thread_device,
                            n.rx_on_when_idle
                        );
                    }
                    #[cfg(feature = "radio-nrf802154")]
                    {
                        let e = opentrust_nrf::tx_error_stats();
                        info!(
                            "  tx errors: busy {} slot_ended {} slot_denied {} schedule {} no_ack {} other {}",
                            e.busy_channel, e.timeslot_ended, e.timeslot_denied, e.schedule, e.no_ack, e.other
                        );
                    }
                    let c = i.mac_counters();
                    info!(
                        "  mac tx {} ack_req {} acked {} data {} retry {} cca {} abort {} maxretry {} rx {} data {} sec_err {} unk_nbr {} dest_filt {} no_frame {} ack_unmatched {} soft_ack {}",
                        c.tx_total,
                        c.tx_ack_requested,
                        c.tx_acked,
                        c.tx_data,
                        c.tx_retry,
                        c.tx_err_cca,
                        c.tx_err_abort,
                        c.tx_direct_max_retry_expiry,
                        c.rx_total,
                        c.rx_data,
                        c.rx_err_sec,
                        c.rx_err_unknown_neighbor,
                        c.rx_dest_addr_filtered,
                        c.rx_err_no_frame,
                        c.rx_ack_unmatched,
                        c.tx_soft_ack
                    );
                });
            }
            select(ot.wait_changed(), Timer::after_millis(500)).await;
        }
    };
    select(ot.run(radio, EmbassyAlarm), app).await;
}
