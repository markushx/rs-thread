//! Matter on-off light over OpenTrust Thread on the nRF52840 DK.
//!
//! RAM sizing firmware: the node forms a Thread network with a preset
//! dataset (channel 15, PAN ID 0x1234, network name "OpenTrust", as the
//! leader firmware) and runs rs-matter's on-off light over it
//! (`opentrust_matter::driver::ThreadRunner`, Thread only, no BLE). rs-matter
//! uses its test device attestation credentials and the RustCrypto backend
//! (pure Rust, no hardware crypto). Everything rs-matter persists (fabrics,
//! ACLs, counters, ...) and the Thread settings blob of `ThreadPersist` live
//! in one key-value store in flash (`opentrust-flash`, region in `memory.x`),
//! so the light keeps its fabrics, its Thread network and its role over a
//! reset. Button 1 held at boot erases the store (factory reset). LED1
//! follows the On/Off attribute. The pairing code and discriminator are
//! logged at start-up.
//!
//! Static RAM, stack high-water and heap use are logged over RTT.

#![no_std]
#![no_main]

use core::mem::size_of_val;

use defmt::info;
use defmt_rtt as _;
use embassy_executor::Spawner;
use embassy_futures::select::select;
use embassy_nrf::gpio::Level;
use embassy_sync::blocking_mutex::raw::NoopRawMutex;
use embassy_time::Timer;
use nrf52840_leader::Board;
use opentrust_core::crypto::soft::SoftCrypto;
use opentrust_core::settings::SettingsKey;
use opentrust_embassy::{OpenTrust, Resources};
use opentrust_flash::{FlashWriter, Shared};
use opentrust_instance::{ExtAddress, Instance};
use opentrust_matter::driver::ThreadRunner;
use opentrust_matter::flash_kv::FlashKv;
use opentrust_matter::persist::{THREAD_SETTINGS_KEY, ThreadPersist};
use opentrust_nrf::{EmbassyAlarm, EmbassyClock, NrfRng};
use opentrust_platform::{Radio, RamSettings, SettingsStore};
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
/// docs/memory-budget.md.
const BUMP: usize = 28 * 1024;

type Res = Resources<NoopRawMutex, EmbassyClock, RamSettings<4096>, SoftCrypto, NrfRng<'static>>;
static RES: StaticCell<Res> = StaticCell::new();

type LightStack = MatterStack<'static, BUMP, ThreadNetworks>;
static STACK: StaticCell<LightStack> = StaticCell::new();

/// RAM image of the key-value store (all rs-matter blobs plus the Thread
/// settings blob) and the number of dirty keys tracked between flushes.
type KvImage = Shared<4096, 32>;
static KV_IMAGE: KvImage = KvImage::new();
/// Largest blob the flash entry buffer takes (rs-matter's 2048 byte blob
/// buffer plus entry framing).
const FLASH_ENTRY_BUF: usize = 2048 + 32;

type Kv = SharedKvBlobStore<'static, FlashKv<'static, 4096, 32>, 2048>;
static KV_BUF: StaticCell<Mutex<RefCell<[u8; 2048]>>> = StaticCell::new();
static KV: StaticCell<Kv> = StaticCell::new();

static LOGIC_CELL: StaticCell<TestOnOffDeviceLogic> = StaticCell::new();

const NODE: Node<'static> = Node {
    endpoints: &[
        LightStack::thread_root_endpoint(),
        Endpoint::new(
            1,
            devices!(DEV_TYPE_ON_OFF_LIGHT),
            clusters!(desc::DescHandler::CLUSTER, TestOnOffDeviceLogic::CLUSTER),
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
    {
        static mut HEAP_MEM: [core::mem::MaybeUninit<u8>; HEAP_SIZE] =
            [core::mem::MaybeUninit::uninit(); HEAP_SIZE];
        // SAFETY: called once, before any allocation; the array is only used
        // by the heap.
        unsafe { HEAP.init(core::ptr::addr_of_mut!(HEAP_MEM) as usize, HEAP_SIZE) }
    }
    let Board {
        rng,
        rng2,
        mut led1,
        mut radio,
        mut flash,
        button1,
    } = nrf52840_leader::init(&spawner);
    nrf52840_leader::flash::check();
    if nrf52840_leader::flash::factory_reset_requested(&button1).await {
        info!("factory reset: erasing the key-value store");
        nrf52840_leader::flash::erase_all(&mut flash).await.unwrap();
    }
    let mut writer = FlashWriter::<_, FLASH_ENTRY_BUF>::mount(
        flash,
        nrf52840_leader::flash::KV_START,
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
    let ext = ext_address();
    info!("ext address {:x}", ext.0);

    // Thread: built in place in static memory.
    let config = opentrust_instance::Config::router(ext, caps);
    let res: &'static Res = Resources::init(RES.uninit(), EmbassyClock, |slot| {
        Instance::init(slot, config, RamSettings::<4096>::new(), SoftCrypto, rng);
    });
    let ot = OpenTrust::new(res);
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
    let logic: &'static TestOnOffDeviceLogic = LOGIC_CELL.init(TestOnOffDeviceLogic::new(false));
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

    // Load the persisted Thread settings now, so the app below can tell
    // whether the node has a network to restore.
    let mut persist = ThreadPersist::new(ot, kv);
    let restored = persist.load().unwrap();
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
        "thread settings: {} values restored (blob key {:#06x}), dataset {} network info {}",
        restored, THREAD_SETTINGS_KEY, have_dataset, have_network
    );
    let runner = ThreadRunner::new(ot, radio, EmbassyAlarm, kv).with_persist(persist);
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
        ot.with(|i, now| {
            if !have_dataset {
                let mut ds = i.create_dataset(15).unwrap();
                ds.set_pan_id(0x1234).unwrap();
                i.set_active_dataset(&ds, now).unwrap();
            }
            i.ip6_set_enabled(true);
            // With stored network info the node restores its role instead of
            // forming a new network.
            if have_network {
                i.thread_start(now).unwrap();
            } else {
                i.become_leader(now).unwrap();
            }
        });
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
                led1.set_level(if on { Level::Low } else { Level::High });
                last_on = Some(on);
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
    // Writes the key-value store to flash a moment after rs-matter or the
    // Thread persistence changed it.
    let persist_task = async {
        loop {
            Timer::after_millis(250).await;
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
