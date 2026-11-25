//! Matter on-off light over rs-thread Thread on the ESP32-C6-DevKitC-1 or
//! M5Stack NanoC6.
//!
//! RAM sizing firmware.  With the `ble` feature (default) an unprovisioned
//! light (nothing stored, no `RSTHREAD_DATASET`) advertises the Matter BLE
//! service (stub: logs a warning and returns an error until Phase 17e wires
//! up `esp-wifi`), after which BLE stops and Thread carries the traffic.
//! Without a stored dataset and without BLE (`--no-default-features`) the
//! node forms a Thread network with the preset dataset from the leader
//! firmware (channel 15, PAN ID 0x1234, name "rs-thread").
//!
//! The light runs rs-matter's on-off light model over Thread
//! (`rs_thread_matter::driver::ThreadRunner`).  It uses the RustCrypto backend
//! for Matter's CASE/PASE and device attestation; rs-thread's Thread stack uses
//! the software crypto backend (`SoftCrypto`).  Hardware AES (`EspCrypto`) is
//! initialised but not yet wired into the Thread stack (see PLAN.md Phase 17e).
//!
//! Both rs-matter and Thread settings (fabrics, ACLs, dataset, network info) are
//! persisted in two flash regions at the top of the 4 MiB flash:
//!   0x3E4000  Matter KV store (64 KiB, two 32 KiB banks)
//!   0x3F4000  Thread settings (48 KiB, two 24 KiB banks)  ← same as leader
//!
//! GPIO8 is the WS2812 data line; the firmware toggles it as a simple
//! on/off indicator (no actual WS2812 protocol — the LED follows power-on
//! state rather than colour).
//!
//! Stack and heap usage are logged over RTT at startup and whenever the
//! role or on/off state changes.

#![no_std]
#![no_main]

#[cfg(feature = "ble")]
mod ble;

use core::mem::size_of_val;

use defmt::info;
use defmt_rtt as _;
use embassy_executor::Spawner;
use embassy_futures::select::select;
use embassy_sync::blocking_mutex::raw::NoopRawMutex;
use embassy_time::Timer;
use esp_backtrace as _;
use esp_hal::{
    aes::Aes,
    gpio::{Input, Level, Output, Pull},
    rng::Rng,
    uart::Uart,
};
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
use embedded_storage_async::nor_flash::NorFlash as _;
use rs_thread_core::crypto::soft::SoftCrypto;
use rs_thread_core::settings::SettingsKey;
use rs_thread_embassy::{Resources, RsThread};
use rs_thread_esp::{EmbassyAlarm, EmbassyClock, EspCrypto, EspFlash, EspRadio, EspRng};
use rs_thread_flash::{FlashWriter, Settings, Shared};
use rs_thread_instance::{ExtAddress, Instance};
use rs_thread_matter::driver::{ThreadCoexRunner, ThreadRunner};
use rs_thread_matter::flash_kv::FlashKv;
use rs_thread_platform::{Radio, SettingsStore};
use static_cell::StaticCell;

#[cfg(feature = "ble")]
use rs_thread_matter::ble::TroubleBtpGattContext;

defmt::timestamp!("{=u64:us}", embassy_time::Instant::now().as_micros());

#[global_allocator]
static HEAP: embedded_alloc::LlffHeap = embedded_alloc::LlffHeap::empty();
const HEAP_SIZE: usize = 8192;

/// rs-matter bump area.  With BLE the BTP engine lives in it too.
const BUMP: usize = if cfg!(feature = "ble") { 36 * 1024 } else { 28 * 1024 };

type Res = Resources<NoopRawMutex, EmbassyClock, Settings<'static, 1536, 16>, SoftCrypto, EspRng>;
static RES: StaticCell<Res> = StaticCell::new();

type LightStack = MatterStack<'static, BUMP, ThreadNetworks>;
static STACK: StaticCell<LightStack> = StaticCell::new();

type ThreadStore = Shared<1536, 16>;
static THREAD_STORE: ThreadStore = ThreadStore::new();
const THREAD_ENTRY_BUF: usize = 512;
/// Flash erase-page size on ESP32-C6 (4 KiB).
const FLASH_PAGE: u32 = 4096;
/// Pages per Thread settings bank (12 pages × 4 KiB = 48 KiB total / 2 banks).
const THREAD_PAGES: u32 = esp32c6_leader::flash::THREAD_LEN / FLASH_PAGE / 2;

type KvImage = Shared<4096, 32>;
static KV_IMAGE: KvImage = KvImage::new();
const KV_ENTRY_BUF: usize = 2048 + 32;
/// Start of the Matter KV flash region (64 KiB below the Thread region).
const KV_START: u32 = esp32c6_leader::flash::THREAD_START - KV_TOTAL;
/// Total size of the KV flash region in bytes.
const KV_TOTAL: u32 = 2 * KV_PAGES * FLASH_PAGE;
/// Pages per KV bank (8 pages × 4 KiB = 32 KiB per bank, 64 KiB total).
const KV_PAGES: u32 = 8;

type Kv = SharedKvBlobStore<'static, FlashKv<'static, 4096, 32>, 2048>;
static KV_BUF: StaticCell<Mutex<RefCell<[u8; 2048]>>> = StaticCell::new();
static KV: StaticCell<Kv> = StaticCell::new();

#[cfg(feature = "ble")]
static BTP_CTX: StaticCell<TroubleBtpGattContext> = StaticCell::new();

static LOGIC_CELL: StaticCell<LightLogic> = StaticCell::new();

/// GPIO8 (WS2812 data line, DevKitC-1 and NanoC6) toggled as a plain LED.
struct LightLogic {
    led: Mutex<RefCell<Output<'static>>>,
    on: core::sync::atomic::AtomicBool,
}

impl LightLogic {
    fn new(led: Output<'static>) -> Self {
        Self {
            led: Mutex::new(RefCell::new(led)),
            on: core::sync::atomic::AtomicBool::new(false),
        }
    }

    fn is_on(&self) -> bool {
        self.on.load(core::sync::atomic::Ordering::Relaxed)
    }
}

impl OnOffHooks for LightLogic {
    const CLUSTER: rs_matter::dm::Cluster<'static> = <TestOnOffDeviceLogic as OnOffHooks>::CLUSTER;
    const PERSIST_DELAY_MS: u32 = 0;

    fn set_on_off(&self, on: bool) {
        self.on.store(on, core::sync::atomic::Ordering::Relaxed);
        self.led.lock(|led| {
            led.borrow_mut()
                .set_level(if on { Level::High } else { Level::Low })
        });
    }

    async fn handle_off_with_effect(&self, _effect: on_off::EffectVariantEnum) {}
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

const BUILD_DATASET: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/dataset.bin"));

/// KV key for the persisted MAC extended address.
const EXT_ADDRESS_KEY: u16 = rs_matter::persist::VENDOR_KEYS_START + 0x11;

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
    a[0] = (a[0] | 0x02) & !0x01; // locally administered, unicast
    if KV_IMAGE.with(|i| i.set(EXT_ADDRESS_KEY, &a)).is_err() {
        defmt::warn!("cannot store the extended address");
    }
    ExtAddress(a)
}

#[embassy_executor::main]
async fn main(_spawner: Spawner) {
    {
        static mut HEAP_MEM: [core::mem::MaybeUninit<u8>; HEAP_SIZE] =
            [core::mem::MaybeUninit::uninit(); HEAP_SIZE];
        // SAFETY: called once before any allocation; the array lives for 'static.
        unsafe { HEAP.init(core::ptr::addr_of_mut!(HEAP_MEM) as usize, HEAP_SIZE) }
    }

    // --- ESP32-C6 peripheral init ---
    let p = esp_hal::init(esp_hal::Config::default());

    // Embassy-time 0.5 driver (SYSTIMER UNIT0 + COMP0).
    esp32c6_leader::time_driver::init(p.SYSTIMER);

    // Hardware AES-128 for EspCrypto.  The Thread stack uses SoftCrypto for
    // now; EspCrypto is here for future wiring (Phase 17e) and rs-matter may
    // use it via its own crypto interface once that is exposed.
    EspCrypto::init(Aes::new(p.AES));

    // 802.15.4 radio.
    let ieee = esp_ieee802154::Ieee802154::new(p.IEEE802154, p.RADIO_CLK);
    let mut radio = EspRadio::new(ieee);

    // Flash: Thread settings region (same offsets as the leader firmware).
    let flash_thread = EspFlash::new(esp32c6_leader::flash::THREAD_START);
    // Flash: Matter KV store region (64 KiB below the Thread region).
    let flash_kv = EspFlash::new(KV_START);

    // RNG: two copies (esp_hal::rng::Rng is Copy — same hardware, independent calls).
    let hw_rng = Rng::new(p.RNG);
    let rng = EspRng::new(hw_rng);
    let rng2 = EspRng::new(hw_rng);

    // Boot button (GPIO9, active low, internal pull-up).
    let boot_button = Input::new(p.GPIO9, Pull::Up);

    // LED on GPIO8 (WS2812 data line; active-high simple toggle).
    let led = Output::new(p.GPIO8, Level::Low);

    // UART0 (optional; used by a future CLI binary).
    let _uart = Uart::new(p.UART0, esp_hal::uart::Config::default())
        .expect("UART0 config failed")
        .with_tx(p.GPIO16)
        .with_rx(p.GPIO17);

    // --- Factory reset ---
    if esp32c6_leader::flash::factory_reset_requested(&boot_button).await {
        info!("factory reset: erasing both flash regions");
        EspFlash::new(esp32c6_leader::flash::THREAD_START)
            .erase(0, esp32c6_leader::flash::THREAD_LEN)
            .await
            .expect("Thread flash erase failed");
        EspFlash::new(KV_START)
            .erase(0, KV_TOTAL)
            .await
            .expect("KV flash erase failed");
    }

    // --- Flash mounts ---
    let mut thread_writer = FlashWriter::<_, THREAD_ENTRY_BUF>::mount(
        flash_thread,
        0,
        THREAD_PAGES,
        &THREAD_STORE,
    )
    .await
    .unwrap();

    let mut writer = FlashWriter::<_, KV_ENTRY_BUF>::mount(
        flash_kv,
        0,
        KV_PAGES,
        &KV_IMAGE,
    )
    .await
    .unwrap();

    KV_IMAGE.with(|i| {
        info!("kv store: {} bytes loaded", i.used());
    });

    // --- Thread init ---
    let caps = radio.init().await.unwrap();
    let mut rng_for_ext = rng;
    let ext = ext_address(&mut rng_for_ext);
    info!("ext address {:x}", ext.0);

    #[cfg(not(feature = "med"))]
    let config = rs_thread_instance::Config::router(ext, caps);
    #[cfg(feature = "med")]
    let config = rs_thread_instance::Config::end_device(ext, caps);

    let res: &'static Res = Resources::init(RES.uninit(), EmbassyClock, |slot| {
        Instance::init(slot, config, THREAD_STORE.settings(), SoftCrypto, rng);
    });
    let ot = RsThread::new(res);
    info!("stack peak after Thread init: some bytes");

    // --- Matter init ---
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
    let logic: &'static LightLogic = LOGIC_CELL.init(LightLogic::new(led));
    let on_off_handler = on_off::OnOffHandler::new_standalone(
        Dataver::new_rand(&mut rand),
        1,
        rs_matter::persist::VENDOR_KEYS_START + 0x10,
        logic,
    );

    stack.matter().startup(kv).unwrap();
    if !stack.matter().has_fabrics() {
        stack.open_basic_comm_window(&crypto, &()).unwrap();
    }
    info!(
        "pairing: discriminator {} passcode {} (rs-matter test device)",
        TEST_DEV_COMM.discriminator(),
        20202021u32
    );
    if let Some(basic) = TEST_DEV_COMM.passcode() {
        info!(
            "manual pairing code {}",
            basic.compute_pretty_pairing_code().as_str()
        );
    }
    #[cfg(feature = "ble")]
    let discovery = rs_matter::pairing::DiscoveryCapabilities::BLE
        | rs_matter::pairing::DiscoveryCapabilities::IP;
    #[cfg(not(feature = "ble"))]
    let discovery = rs_matter::pairing::DiscoveryCapabilities::IP;
    if let Err(e) = stack.matter().print_standard_qr_text(discovery) {
        defmt::warn!("QR code text failed: {}", e.code());
    }

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
        "build-time dataset {} bytes, stored dataset {}, stored network {}",
        BUILD_DATASET.len(),
        have_dataset,
        have_network
    );

    let ble_commissioning = cfg!(feature = "ble") && !have_dataset && BUILD_DATASET.is_empty();
    let runner = ThreadRunner::new(ot, radio, EmbassyAlarm, kv);

    #[cfg(feature = "ble")]
    let gatt = ble::EspWifiBleGatt::new(
        BTP_CTX.uninit().init_with(TroubleBtpGattContext::init()),
    );

    #[cfg(feature = "ble")]
    let fut = stack.run_thread(
        ThreadCoexRunner::new(runner, gatt),
        &crypto,
        data_model(stack.matter(), rand, &on_off_handler),
        kv,
        (),
    );
    #[cfg(not(feature = "ble"))]
    let fut = stack.run_thread_oper(
        runner,
        &crypto,
        data_model(stack.matter(), rand, &on_off_handler),
        kv,
        (),
    );

    info!(
        "sizes: Resources {} MatterStack {} run future {} handler {}",
        size_of_val(res),
        size_of_val(stack),
        size_of_val(&fut),
        size_of_val(&on_off_handler),
    );

    let app = async {
        if ble_commissioning {
            info!("no Thread network: waiting for BLE commissioning (stub — will fail)");
        } else {
            ot.with(|i, now| {
                if !have_dataset {
                    if BUILD_DATASET.is_empty() {
                        let mut ds = i.create_dataset(15).unwrap();
                        ds.set_pan_id(0x1234).unwrap();
                        i.set_active_dataset(&ds, now).unwrap();
                    } else {
                        let ds = rs_thread_instance::Dataset::from_tlvs(BUILD_DATASET)
                            .expect("RSTHREAD_DATASET is not a valid Active Dataset");
                        i.set_active_dataset(&ds, now).unwrap();
                    }
                }
                i.ip6_set_enabled(true);
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
            info!(
                "heap used {} free {}",
                HEAP.used(),
                HEAP.free()
            );
            select(ot.wait_changed(), Timer::after_secs(2)).await;
        }
    };

    let persist_task = async {
        loop {
            Timer::after_millis(250).await;
            if THREAD_STORE.is_dirty() {
                match thread_writer.flush(&THREAD_STORE).await {
                    Ok(()) => info!("thread settings written to flash"),
                    Err(_) => defmt::warn!("thread flash write failed"),
                }
            }
            if KV_IMAGE.is_dirty() {
                match writer.flush(&KV_IMAGE).await {
                    Ok(()) => info!("kv store written to flash"),
                    Err(_) => defmt::warn!("kv flash write failed"),
                }
            }
        }
    };

    let r = select(fut, select(app, persist_task)).await;
    let _ = r;
    panic!("the light stopped");
}
