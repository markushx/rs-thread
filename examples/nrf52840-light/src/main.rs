//! Matter on-off light over rs-thread Thread on the nRF52840 DK.
//!
//! RAM sizing firmware. With the `ble` feature (default) an unprovisioned
//! light (nothing stored, no `RSTHREAD_DATASET`) keeps Thread off, advertises
//! the Matter BLE service and is commissioned with `chip-tool pairing
//! ble-thread` (BTP over the Nordic SoftDevice Controller and trouble-host,
//! `ble.rs`; `run_thread` with `ThreadCoexRunner`), after which BLE stops.
//! Without a stored dataset and without BLE (`--no-default-features`) the node
//! forms a Thread network with a preset dataset (channel 15, PAN ID 0x1234,
//! network name "rs-thread", as the leader firmware); with a build-time
//! dataset it attaches to that network. It runs rs-matter's on-off light over
//! Thread (`rs_thread_matter::driver::ThreadRunner`). rs-matter
//! uses its test device attestation credentials and the RustCrypto backend
//! (pure Rust, no hardware crypto). Everything rs-matter persists (fabrics,
//! ACLs, counters, ...) lives in a key-value store in flash and the Thread
//! settings (dataset, network info, ...) in a second region
//! (`rs-thread-flash`, regions in `memory.x`), so the light keeps its fabrics,
//! its Thread network and its role over a reset. Button 1 held at boot erases the store (factory reset). LED1
//! follows the On/Off attribute. The pairing code and discriminator are
//! logged at start-up.
//!
//! Static RAM, stack high-water and heap use are logged over RTT.

#![no_std]
#![no_main]

#[cfg(feature = "ble")]
mod ble;

use core::mem::size_of_val;

use defmt::info;
use defmt_rtt as _;
use embassy_executor::Spawner;
use embassy_futures::select::select;
use embassy_nrf::gpio::Level;
use embassy_sync::blocking_mutex::raw::NoopRawMutex;
use embassy_time::Timer;
use nrf52840_leader::Board;
use rs_thread_core::crypto::soft::SoftCrypto;
use rs_thread_core::settings::SettingsKey;
use rs_thread_embassy::{RsThread, Resources};
use embassy_embedded_hal::flash::partition::Partition;
use embassy_sync::mutex::Mutex as AsyncMutex;
use rs_thread_flash::{FlashWriter, Settings, Shared};
use rs_thread_instance::{ExtAddress, Instance};
#[cfg(feature = "ble")]
use rs_thread_matter::ble::TroubleBtpGattContext;
#[cfg(feature = "ble")]
use rs_thread_matter::driver::ThreadCoexRunner;
use rs_thread_matter::driver::ThreadRunner;
use rs_thread_matter::flash_kv::FlashKv;
use rs_thread_nrf::{EmbassyAlarm, EmbassyClock, NrfRng};
use rs_thread_platform::{Radio, SettingsStore};
use panic_probe as _;
use rs_matter::crypto::{Crypto, default_crypto};
use rs_matter::dm::clusters::app::level_control::LevelControlHooks;
use rs_matter::dm::clusters::app::on_off::{self, OnOffHooks, test::TestOnOffDeviceLogic};
use rs_matter::dm::clusters::desc::{self, ClusterHandler as _};
use rs_matter::dm::devices::DEV_TYPE_ON_OFF_LIGHT;
use rs_matter::dm::devices::test::{DAC_PRIVKEY, TEST_DEV_ATT, TEST_DEV_COMM, TEST_DEV_DET};
use rs_matter::dm::networks::wireless::ThreadNetworks;
use rs_matter::dm::{Async, DataModel, Dataver, EmptyHandler, Endpoint, Node, ROOT_ENDPOINT_ID};
use rs_matter::persist::SharedKvBlobStore;
use rs_matter::stack::MatterStack;
use rs_matter::utils::cell::RefCell;
use rs_matter::utils::init::InitMaybeUninit;
use rs_matter::utils::sync::blocking::Mutex;
use rs_matter::{Matter, clusters, devices};
use static_cell::StaticCell;

defmt::timestamp!("{=u64:us}", embassy_time::Instant::now().as_micros());

#[global_allocator]
static HEAP: embedded_alloc::LlffHeap = embedded_alloc::LlffHeap::empty();
const HEAP_SIZE: usize = 4096;

/// rs-matter's bump area (transaction and crypto scratch); see
/// docs/memory-budget.md. With BLE the BTP engine and the BLE commissioning
/// futures live in it too (34012 bytes used, measured).
const BUMP: usize = if cfg!(feature = "ble") {
    36 * 1024
} else {
    28 * 1024
};

type Res =
    Resources<NoopRawMutex, EmbassyClock, Settings<'static, 1536, 16>, SoftCrypto, NrfRng<'static>>;
static RES: StaticCell<Res> = StaticCell::new();

type LightStack = MatterStack<'static, BUMP, ThreadNetworks>;
static STACK: StaticCell<LightStack> = StaticCell::new();

/// RAM image of the Thread settings (bytes) and the number of distinct keys
/// tracked; the Thread region of flash holds it.
type ThreadStore = Shared<1536, 16>;
static THREAD_STORE: ThreadStore = ThreadStore::new();
/// Largest Thread settings entry the flash entry buffer takes.
const THREAD_ENTRY_BUF: usize = 512;

/// RAM image of the key-value store (all rs-matter blobs) and the number of
/// dirty keys tracked between flushes.
type KvImage = Shared<4096, 32>;
static KV_IMAGE: KvImage = KvImage::new();
/// Largest blob the flash entry buffer takes (rs-matter's 2048 byte blob
/// buffer plus entry framing).
const FLASH_ENTRY_BUF: usize = 2048 + 32;

type Kv = SharedKvBlobStore<'static, FlashKv<'static, 4096, 32>, 2048>;
static KV_BUF: StaticCell<Mutex<RefCell<[u8; 2048]>>> = StaticCell::new();
static KV: StaticCell<Kv> = StaticCell::new();

/// BLE host resources of the BTP GATT peripheral.
#[cfg(feature = "ble")]
static BTP_CTX: StaticCell<TroubleBtpGattContext> = StaticCell::new();
/// Memory of the SoftDevice Controller.
#[cfg(feature = "ble")]
static SDC_MEM: StaticCell<nrf_sdc::Mem<{ ble::SDC_MEM }>> = StaticCell::new();

static LOGIC_CELL: StaticCell<LightLogic> = StaticCell::new();

/// The light itself: the OnOff cluster switches LED1 (P0.13, active low) in
/// the same call that changes the attribute, so the LED follows a Matter
/// command at once (and the restored state at startup).
struct LightLogic {
    led: rs_matter::utils::sync::blocking::Mutex<
        rs_matter::utils::cell::RefCell<embassy_nrf::gpio::Output<'static>>,
    >,
    on: core::sync::atomic::AtomicBool,
}

impl LightLogic {
    fn new(led: embassy_nrf::gpio::Output<'static>) -> Self {
        Self {
            led: rs_matter::utils::sync::blocking::Mutex::new(
                rs_matter::utils::cell::RefCell::new(led),
            ),
            on: core::sync::atomic::AtomicBool::new(false),
        }
    }

    /// Whether the light is on.
    fn is_on(&self) -> bool {
        self.on.load(core::sync::atomic::Ordering::Relaxed)
    }
}

impl OnOffHooks for LightLogic {
    // The On/Off Light cluster set (Lighting feature) of rs-matter's test logic.
    const CLUSTER: rs_matter::dm::Cluster<'static> = <TestOnOffDeviceLogic as OnOffHooks>::CLUSTER;
    // Persist a change at once, as the test logic did before.
    const PERSIST_DELAY_MS: u32 = 0;

    fn set_on_off(&self, on: bool) {
        self.on.store(on, core::sync::atomic::Ordering::Relaxed);
        self.led.lock(|led| {
            led.borrow_mut()
                .set_level(if on { Level::Low } else { Level::High })
        });
    }

    async fn handle_off_with_effect(&self, _effect: on_off::EffectVariantEnum) {
        // No dimming: the effect ends with the light off, which
        // `set_on_off` already did.
    }
}

const NODE: Node<'static> = Node {
    endpoints: &[
        LightStack::thread_root_endpoint(),
        Endpoint::new(
            1,
            devices!(DEV_TYPE_ON_OFF_LIGHT),
            clusters!(desc::DescHandler::CLUSTER, LightLogic::CLUSTER),
        ),
    ],
};

fn data_model<'a, OH: OnOffHooks, LH: LevelControlHooks>(
    matter: &'a Matter<'a>,
    mut rand: impl rand_core::Rng + Copy,
    on_off: &'a on_off::OnOffHandler<'a, OH, LH>,
) -> impl DataModel + 'a {
    (
        NODE,
        EmptyHandler
            .chain(
                |e, _| e == ROOT_ENDPOINT_ID,
                Async(LightStack::root_handler(matter, &(), rand)),
            )
            .chain(
                |e, c| e == 1 && c == desc::DescHandler::CLUSTER.id,
                Async(desc::DescHandler::new(Dataver::new_rand(&mut rand)).adapt()),
            )
            .chain(
                |e, c| e == 1 && c == TestOnOffDeviceLogic::CLUSTER.id,
                Async(on_off::HandlerAdaptor(on_off)),
            ),
    )
}

/// The Active Dataset (TLVs) the light was built with (`RSTHREAD_DATASET`,
/// see build.rs); empty for a standalone light that forms its own network.
const BUILD_DATASET: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/dataset.bin"));

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
    // unused (the heap is a static array in .bss); 256 bytes of margin below
    // the live frames.
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

/// KV key of the persisted MAC extended address.
const EXT_ADDRESS_KEY: u16 = rs_matter::persist::VENDOR_KEYS_START + 0x11;

/// The MAC extended address: random, generated when none is stored (first
/// start, after a factory reset) and kept in the KV store afterwards.
///
/// A fixed address derived from the device ID would stay the same across a
/// factory reset, while the MLE and link frame counters restart at zero; a
/// peer that still holds the device as a neighbor then drops its frames as
/// replays (OpenThread picks a random extended address as well).
fn ext_address(rng: &mut impl rand_core::Rng) -> ExtAddress {
    let stored = KV_IMAGE.with(|i| {
        let mut a = [0u8; 8];
        match i.get(EXT_ADDRESS_KEY, 0, &mut a) {
            Ok(8) => Some(a),
            _ => None,
        }
    });
    if let Some(a) = stored {
        return ExtAddress(a);
    }
    let mut a = [0u8; 8];
    rng.fill_bytes(&mut a);
    // Locally administered, unicast.
    a[0] = (a[0] | 0x02) & !0x01;
    if KV_IMAGE.with(|i| i.set(EXT_ADDRESS_KEY, &a)).is_err() {
        defmt::warn!("cannot store the extended address");
    }
    ExtAddress(a)
}

#[embassy_executor::main]
async fn main(spawner: Spawner) {
    paint_stack();
    {
        static mut HEAP_MEM: [core::mem::MaybeUninit<u8>; HEAP_SIZE] =
            [core::mem::MaybeUninit::uninit(); HEAP_SIZE];
        // SAFETY: called once, before any allocation; the array is only used
        // by the heap.
        unsafe { HEAP.init(core::ptr::addr_of_mut!(HEAP_MEM) as usize, HEAP_SIZE) }
    }
    let Board {
        mut rng,
        rng2,
        led1,
        mut radio,
        mut flash,
        button1,
        #[cfg(feature = "ble")]
        ble,
        ..
    } = nrf52840_leader::init(&spawner);
    nrf52840_leader::flash::check();
    if nrf52840_leader::flash::factory_reset_requested(&button1).await {
        info!("factory reset: erasing the key-value store");
        nrf52840_leader::flash::erase_all(&mut flash).await.unwrap();
    }
    // Two regions of the one flash device: the Thread settings and the
    // key-value store, each a partition (offset 0 inside its partition).
    let flash = AsyncMutex::<NoopRawMutex, _>::new(flash);
    const BANKS: u32 = 2 * nrf52840_leader::flash::PAGE;
    let mut thread_writer = FlashWriter::<_, THREAD_ENTRY_BUF>::mount(
        Partition::new(
            &flash,
            nrf52840_leader::flash::THREAD_START,
            BANKS * nrf52840_leader::flash::THREAD_PAGES,
        ),
        0,
        nrf52840_leader::flash::THREAD_PAGES,
        &THREAD_STORE,
    )
    .await
    .unwrap();
    let mut writer = FlashWriter::<_, FLASH_ENTRY_BUF>::mount(
        Partition::new(
            &flash,
            nrf52840_leader::flash::KV_START,
            BANKS * nrf52840_leader::flash::KV_PAGES,
        ),
        0,
        nrf52840_leader::flash::KV_PAGES,
        &KV_IMAGE,
    )
    .await
    .unwrap();
    KV_IMAGE.with(|i| {
        info!("kv store: {} bytes loaded", i.used());
        let mut key = None;
        let mut buf = [0u8; 1];
        while let Some(k) = i.next_key(key) {
            let len = i.get(k, 0, &mut buf).unwrap_or(0);
            info!("  key {:#06x}: {} bytes", k, len);
            key = Some(k);
        }
    });
    let caps = radio.init().await.unwrap();
    let ext = ext_address(&mut rng);
    info!("ext address {:x}", ext.0);

    // Thread: built in place in static memory.
    #[cfg(not(feature = "med"))]
    let config = rs_thread_instance::Config::router(ext, caps);
    // Minimal end device: attaches as a child and never becomes a router.
    #[cfg(feature = "med")]
    let config = rs_thread_instance::Config::end_device(ext, caps);
    let res: &'static Res = Resources::init(RES.uninit(), EmbassyClock, |slot| {
        Instance::init(slot, config, THREAD_STORE.settings(), SoftCrypto, rng);
    });
    let ot = RsThread::new(res);
    info!("stack peak after Thread init {} bytes", stack_high_water());

    // Matter: the stack is built in place too.
    let stack: &'static LightStack = STACK.uninit().init_with(LightStack::init(
        &TEST_DEV_DET,
        TEST_DEV_COMM,
        &TEST_DEV_ATT,
    ));
    let kv: &'static Kv = KV.init(SharedKvBlobStore::new(
        FlashKv::new(&KV_IMAGE),
        KV_BUF.init(Mutex::new(RefCell::new([0u8; 2048]))),
    ));
    let crypto = default_crypto(rng2, DAC_PRIVKEY);
    let mut rand = crypto.rand().unwrap();
    let logic: &'static LightLogic = LOGIC_CELL.init(LightLogic::new(led1));
    let on_off_handler = on_off::OnOffHandler::new_standalone(
        Dataver::new_rand(&mut rand),
        1,
        rs_matter::persist::VENDOR_KEYS_START + 0x10,
        logic,
    );
    info!("stack peak after Matter init {} bytes", stack_high_water());

    stack.matter().startup(kv).unwrap();
    if !stack.matter().has_fabrics() {
        stack.open_basic_comm_window(&crypto, &()).unwrap();
    }
    info!(
        "pairing: discriminator {} passcode {} (rs-matter test device, vendor 0xFFF1 product 0x8000)",
        TEST_DEV_COMM.discriminator, 20202021u32
    );
    info!(
        "manual pairing code {}",
        TEST_DEV_COMM.compute_pretty_pairing_code().as_str()
    );
    // Logs `SetupQRCode: [MT:...]`.
    #[cfg(feature = "ble")]
    let discovery = rs_matter::pairing::DiscoveryCapabilities::BLE
        | rs_matter::pairing::DiscoveryCapabilities::IP;
    #[cfg(not(feature = "ble"))]
    let discovery = rs_matter::pairing::DiscoveryCapabilities::IP;
    if let Err(e) = stack.matter().print_standard_qr_text(discovery) {
        defmt::warn!("QR code text failed: {}", e.code());
    }

    // The Thread settings were loaded from flash at mount; the app below
    // tells from them whether the node has a network to restore.
    let (have_dataset, have_network) = ot.with(|i, _| {
        (
            i.settings()
                .get(SettingsKey::ActiveDataset, 0, &mut [])
                .is_ok(),
            i.settings()
                .get(SettingsKey::NetworkInfo, 0, &mut [])
                .is_ok(),
        )
    });
    info!(
        "network: build-time dataset {} bytes, stored dataset {}",
        BUILD_DATASET.len(),
        have_dataset
    );
    info!(
        "thread settings: {} bytes loaded, dataset {} network info {}",
        THREAD_STORE.with(|i| i.used()),
        have_dataset,
        have_network
    );
    // An unprovisioned light (no stored network, no build-time dataset) waits
    // for its Thread network over BLE; the commissioner hands it the dataset
    // (`ThreadNetCtl`).
    let ble_commissioning = cfg!(feature = "ble") && !have_dataset && BUILD_DATASET.is_empty();
    let runner = ThreadRunner::new(ot, radio, EmbassyAlarm, kv);
    #[cfg(feature = "ble")]
    let fut = {
        let gatt = ble::SdcGatt::new(
            ble.mpsl,
            ble.sdc,
            SDC_MEM.init(nrf_sdc::Mem::new()),
            BTP_CTX.uninit().init_with(TroubleBtpGattContext::init()),
            rand,
        );
        stack.run_thread(
            ThreadCoexRunner::new(runner, gatt),
            &crypto,
            data_model(stack.matter(), rand, &on_off_handler),
            kv,
            (),
        )
    };
    #[cfg(not(feature = "ble"))]
    let fut = stack.run_thread_oper(
        runner,
        &crypto,
        data_model(stack.matter(), rand, &on_off_handler),
        kv,
        (),
    );
    info!(
        "sizes: Resources {} MatterStack {} (Matter {}) run future {} handler {}",
        size_of_val(res),
        size_of_val(stack),
        size_of_val(stack.matter()),
        size_of_val(&fut),
        size_of_val(&on_off_handler),
    );
    // Steady state from here on: measure again from a clean pattern.
    paint_stack();

    let app = async {
        if ble_commissioning {
            info!("no Thread network: waiting for BLE commissioning");
        } else {
            ot.with(|i, now| {
                // A stored dataset (flash) wins over the build-time one; both win
                // over forming a standalone network.
                if !have_dataset {
                    if BUILD_DATASET.is_empty() {
                        let mut ds = i.create_dataset(15).unwrap();
                        ds.set_pan_id(0x1234).unwrap();
                        i.set_active_dataset(&ds, now).unwrap();
                    } else {
                        let ds = rs_thread_instance::Dataset::from_tlvs(BUILD_DATASET)
                            .expect("RSTHREAD_DATASET is not a complete Active Dataset");
                        i.set_active_dataset(&ds, now).unwrap();
                    }
                }
                i.ip6_set_enabled(true);
                // With stored network info, or an external dataset, the node
                // restores its role or attaches (and forms a partition itself
                // only when no router answers, as OpenThread does); a standalone
                // light forms its network at once.
                //
                // With a Thread network stored by Matter commissioning, the
                // Matter network manager (`ThreadNetCtl` connect) may start
                // Thread first; both mean the same network, so start only if
                // it is still off.
                if have_network || !BUILD_DATASET.is_empty() {
                    if i.role() == rs_thread_instance::Role::Disabled {
                        i.thread_start(now).unwrap();
                    }
                } else {
                    i.become_leader(now).unwrap();
                }
            });
        }
        let mut last_role = None;
        let mut last_on = None;
        loop {
            let role = ot.role();
            if last_role != Some(role) {
                info!("role: {:?}", defmt::Debug2Format(&role));
                last_role = Some(role);
            }
            let on = logic.is_on();
            if last_on != Some(on) {
                info!("on-off: {}", on);
                last_on = Some(on);
            }
            {
                let (rx, tx) = rs_thread_nrf::frame_counts();
                let e = rs_thread_nrf::tx_error_stats();
                info!(
                    "radio: rx {} tx {} busy {} ended {} denied {} sched {} noack {} abort {} other {}",
                    rx,
                    tx,
                    e.busy_channel,
                    e.timeslot_ended,
                    e.timeslot_denied,
                    e.schedule,
                    e.no_ack,
                    e.aborted,
                    e.other
                );
            }
            info!(
                "stack high-water {} bytes, heap used {} free {}",
                stack_high_water(),
                HEAP.used(),
                HEAP.free()
            );
            select(ot.wait_changed(), Timer::after_secs(2)).await;
        }
    };
    // Writes the Thread settings and the key-value store to flash a moment
    // after the node or rs-matter changed them.
    let persist_task = async {
        loop {
            Timer::after_millis(250).await;
            if THREAD_STORE.is_dirty() {
                match thread_writer.flush(&THREAD_STORE).await {
                    Ok(()) => info!("thread settings written to flash"),
                    Err(e) => defmt::warn!("flash write failed: {}", e),
                }
            }
            if KV_IMAGE.is_dirty() {
                match writer.flush(&KV_IMAGE).await {
                    Ok(()) => info!("kv store written to flash"),
                    Err(e) => defmt::warn!("flash write failed: {}", e),
                }
            }
        }
    };
    let r = select(fut, select(app, persist_task)).await;
    let _ = r;
    panic!("the light stopped");
}
