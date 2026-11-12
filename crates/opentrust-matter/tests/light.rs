//! An rs-matter On/Off light over Thread, end to end in virtual time.
//!
//! Node 0 is the Thread leader: it hosts the fake SRP / DNS-SD server and
//! runs rs-matter in the controller role (PASE, commissioning with
//! `rs_matter::onboard::Commissioner`, CASE, then Interaction Model
//! operations) over its own `MatterNetStack`. Node 1 is a Thread child
//! running a full `rs_matter::stack::MatterStack` with an On/Off light through
//! [`ThreadRunner`]; its Thread dataset is preset (no BLE).
mod common;

use core::cell::{Cell, RefCell};
use core::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6};
use core::num::NonZeroU8;
use core::pin::pin;

use common::kv::MemKv;
use common::srp::Registered;
use common::*;
use embassy_futures::select::{Either, Either3, select, select3};
use opentrust_matter::driver::ThreadRunner;
use opentrust_matter::net::MatterNetStack;
use rand_core::Rng as _;
use rs_matter::cert::r#gen::VALID_FOREVER;
use rs_matter::cert::{MAX_CERT_TLV_AND_ASN1_LEN, MAX_CERT_TLV_LEN};
use rs_matter::crypto::{
    CanonAeadKey, CanonPkcSecretKey, Crypto, SecretKey, SigningSecretKey, default_crypto,
};
use rs_matter::dm::ROOT_ENDPOINT_ID;
use rs_matter::dm::clusters::app::level_control::LevelControlHooks;
use rs_matter::dm::clusters::app::on_off::{
    self, OnOffClient, OnOffHooks, test::TestOnOffDeviceLogic,
};
use rs_matter::dm::clusters::desc::{self, ClusterHandler as _};
use rs_matter::dm::devices::DEV_TYPE_ON_OFF_LIGHT;
use rs_matter::dm::devices::test::{DAC_PRIVKEY, TEST_DEV_ATT, TEST_DEV_COMM, TEST_DEV_DET};
use rs_matter::dm::networks::wireless::ThreadNetworks;
use rs_matter::dm::{Async, DataModel, Dataver, EmptyHandler, Endpoint, Node};
use rs_matter::error::Error;
use rs_matter::onboard::cac::{IcacGenerator, RcacGenerator};
use rs_matter::onboard::noc::NocGenerator;
use rs_matter::onboard::{CommissionOptions, Commissioner};
use rs_matter::sc::ExchangeInitiator as _;
use rs_matter::stack::MatterStack;
use rs_matter::stack::net::{NetSocket, NetStack};
use rs_matter::transport::exchange::Exchange;
use rs_matter::transport::network::mdns::{DottedName, MdnsRemoteService};
use rs_matter::transport::network::{Address, IpAddr, MatterRemoteService, NoNetwork};
use rs_matter::utils::init::InitMaybeUninit;
use rs_matter::utils::storage::String as MString;
use rs_matter::utils::timers::{Duration as TDuration, Timer};
use rs_matter::{Matter, clusters, devices};

const MATTER_PORT: u16 = 5540;
const PASSCODE: u32 = 20202021;
const FABRIC_ID: u64 = 1;
const CONTROLLER_NODE_ID: u64 = 112233;
const DEVICE_NODE_ID: u64 = 112234;
const BUMP: usize = 64 * 1024;

type LightStack = MatterStack<'static, BUMP, ThreadNetworks>;

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

fn any(port: u16) -> SocketAddr {
    SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, port, 0, 0))
}

/// Answers the controller's operational resolve requests with the address of
/// the light.
async fn resolver(matter: &Matter<'_>, node: u64, addr: SocketAddrV6) -> ! {
    let responder = matter.transport().mdns_responder();
    loop {
        let service = responder.wait_resolve_request().await;
        let MatterRemoteService::Operational { node_id, .. } = &service else {
            continue;
        };
        if *node_id != node {
            continue;
        }
        let mut name = MString::<128>::new();
        service.instance_name(&mut name);
        matter.transport().try_deposit_mdns_resolve(
            &MdnsRemoteService {
                instance_name: DottedName(name.as_str()),
                port: Some(addr.port()),
                addrs: core::iter::once(IpAddr::V6(*addr.ip())),
                txt: core::iter::empty::<(&str, &str)>(),
                scope_id: 0,
            },
            &[],
        );
    }
}

/// Install the controller's fabric (its NOC is signed by `noc_generator`).
fn controller_fabric<C: Crypto>(
    matter: &Matter<'_>,
    crypto: &C,
    noc_generator: &mut NocGenerator<'_>,
    rcac: &[u8],
    icac: &[u8],
) -> Result<NonZeroU8, Error> {
    let sk = crypto.generate_secret_key()?;
    let mut csr_buf = [0u8; 256];
    let csr = sk.csr(&mut csr_buf)?;
    let mut canon = CanonPkcSecretKey::new();
    sk.write_canon(&mut canon)?;
    let noc = noc_generator.generate(crypto, csr, CONTROLLER_NODE_ID, &[], VALID_FOREVER)?;
    let mut ipk = CanonAeadKey::new();
    crypto.rand()?.fill_bytes(ipk.access_mut());
    matter.with_state(|state| {
        state
            .fabrics
            .add(
                crypto,
                canon.reference(),
                rcac,
                noc,
                icac,
                Some(ipk.reference()),
                0xFFF1,
                CONTROLLER_NODE_ID,
            )
            .map(|f| f.fab_idx())
    })
}

async fn read_onoff(matter: &Matter<'_>, fab: NonZeroU8, node: u64) -> Result<bool, Error> {
    let exchange =
        Exchange::initiate(matter, default_crypto(rand::rng(), DAC_PRIVKEY), fab, node).await?;
    match select(
        pin!(exchange.on_off().on_off_read(1)),
        Timer::after(TDuration::from_secs(10)),
    )
    .await
    {
        Either::First(r) => r,
        Either::Second(()) => Err(rs_matter::error::ErrorCode::RxTimeout.into()),
    }
}

async fn toggle(matter: &Matter<'_>, fab: NonZeroU8, node: u64) -> Result<(), Error> {
    let exchange =
        Exchange::initiate(matter, default_crypto(rand::rng(), DAC_PRIVKEY), fab, node).await?;
    match select(
        pin!(exchange.on_off().toggle(1)),
        Timer::after(TDuration::from_secs(10)),
    )
    .await
    {
        Either::First(r) => r,
        Either::Second(()) => Err(rs_matter::error::ErrorCode::RxTimeout.into()),
    }
}

/// Wait (polling in virtual time) until `cond` holds on the SRP registry.
async fn wait_registry(reg: &RefCell<Registered>, mut cond: impl FnMut(&Registered) -> bool) {
    while !cond(&reg.borrow()) {
        Timer::after(TDuration::from_millis(250)).await;
    }
}

fn run_light() {
    let kv = MemKv::new();
    let clks = [clock(), clock()];
    let air = Air::new(2);
    let pend = [Cell::new(None), Cell::new(None)];
    let res0: Res<'_> = Res::new(instance(1), &clks[0]);
    let res1: Res<'_> = Res::new(instance(2), &clks[1]);
    let ots = [Ot::new(&res0), Ot::new(&res1)];
    let ds = make_dataset(ots[0]);
    // The dataset is preset on both nodes (no BLE commissioning).
    start_with(ots[0], &ds, true);
    start_with(ots[1], &ds, false);

    let reg = RefCell::new(Registered::default());

    // The light.
    let stack: &'static LightStack = Box::leak(Box::<LightStack>::new_uninit()).init_with(
        LightStack::init(&TEST_DEV_DET, TEST_DEV_COMM, &TEST_DEV_ATT),
    );
    let light_crypto = default_crypto(rand::rng(), DAC_PRIVKEY);
    let mut rand = light_crypto.rand().unwrap();
    let on_off_handler = on_off::OnOffHandler::new_standalone(
        Dataver::new_rand(&mut rand),
        1,
        rs_matter::persist::VENDOR_KEYS_START + 0x10,
        TestOnOffDeviceLogic::new(false),
    );
    let light = async {
        let kv = &kv;
        stack.matter().startup(kv).unwrap();
        if !stack.matter().has_fabrics() {
            stack.open_basic_comm_window(&light_crypto, &()).unwrap();
        }
        let runner = ThreadRunner::new(
            ots[1],
            AirRadio { air: &air, id: 1 },
            TestAlarm::new(&clks[1], &pend[1]),
            kv,
        );
        let runner_size = core::mem::size_of_val(&runner);
        let fut = stack.run_thread_oper(
            runner,
            &light_crypto,
            data_model(stack.matter(), rand, &on_off_handler),
            kv,
            (),
        );
        // RAM of the light node (x86_64, debug build): see docs/memory-budget.md.
        eprintln!(
            "light RAM: Resources (Instance, state, wakers) {} + ThreadRunner {} + MatterStack {} \
             (of which Matter {}, bump {}) + run future {} + OnOffHandler {}",
            core::mem::size_of_val(&res1),
            runner_size,
            core::mem::size_of_val(stack),
            core::mem::size_of_val(stack.matter()),
            BUMP,
            core::mem::size_of_val(&fut),
            core::mem::size_of_val(&on_off_handler),
        );
        let r = fut.await;
        panic!("the light stopped: {r:?}");
    };

    // The controller.
    let ctrl_matter: &Matter<'_> = Box::leak(Box::<Matter<'_>>::new_uninit())
        .init_with(Matter::init(&TEST_DEV_DET, TEST_DEV_COMM, &TEST_DEV_ATT, 0));
    let ctrl_crypto = default_crypto(rand::rng(), DAC_PRIVKEY);

    let tasks = vec![
        run_task(ots[0], &air, 0, &clks[0], &pend[0]),
        Box::pin(light),
    ];
    drive(
        &[&clks[0], &clks[1]],
        &[&pend[0], &pend[1]],
        tasks,
        async {
            wait_role(ots[0], opentrust_instance::Role::Leader).await;
            let server = common::srp::serve(ots[0], &reg);
            let ctrl_stack = MatterNetStack::new(ots[0]);
            let mut sock = ctrl_stack
                .bind(any(MATTER_PORT), Ipv4Addr::UNSPECIFIED, 0)
                .await
                .unwrap();
            let (tx, rx, _mc) = sock.split();
            let ctrl_run = ctrl_matter.run(&ctrl_crypto, tx, rx, NoNetwork);
            let flow = async {
                wait_attached(ots[1]).await;
                let light_addr =
                    SocketAddrV6::new(ots[1].with(|i, _| i.ml_eid()), MATTER_PORT, 0, 0);

                // 1. The commissionable service shows up at the SRP server.
                wait_registry(&reg, |r| {
                    r.instance("").is_some_and(|i| {
                        i.name.to_ascii_uppercase().contains("._MATTERC._UDP.")
                            && i.port == MATTER_PORT
                    })
                })
                .await;
                assert!(reg.borrow().addrs.contains(light_addr.ip()));

                // 2. PASE over the Thread mesh, commissioning, CASE.
                let mut rcac_buf = [0u8; MAX_CERT_TLV_AND_ASN1_LEN];
                let mut rcac_gen = RcacGenerator::new(&mut rcac_buf);
                let (rcac_priv, rcac) = rcac_gen
                    .generate(&ctrl_crypto, FABRIC_ID, VALID_FOREVER)
                    .unwrap();
                let mut icac_buf = [0u8; MAX_CERT_TLV_AND_ASN1_LEN];
                let mut icac_gen = IcacGenerator::new(&mut icac_buf);
                let (icac_priv, icac) = icac_gen
                    .generate(&ctrl_crypto, rcac_priv.reference(), rcac, VALID_FOREVER)
                    .unwrap();
                drop(rcac_priv);
                let mut noc_buf = [0u8; MAX_CERT_TLV_AND_ASN1_LEN];
                let mut noc_gen =
                    NocGenerator::create(icac_priv.reference(), rcac, icac, &mut noc_buf).unwrap();
                let fab =
                    controller_fabric(ctrl_matter, &ctrl_crypto, &mut noc_gen, rcac, icac).unwrap();
                let mut cbuf = [0u8; MAX_CERT_TLV_LEN];
                let mut commissioner =
                    Commissioner::new(ctrl_matter, &ctrl_crypto, fab, &mut noc_gen, &mut cbuf);
                let opts = CommissionOptions {
                    allow_test_attestation: true,
                    ..CommissionOptions::default()
                };
                let peer = Address::Udp(SocketAddr::V6(light_addr));
                let result = commissioner
                    .commission(peer, PASSCODE, &opts, DEVICE_NODE_ID, VALID_FOREVER)
                    .await
                    .expect("PASE and commissioning over Thread");
                match select(
                    pin!(commissioner.complete_via_case(&result)),
                    pin!(resolver(ctrl_matter, DEVICE_NODE_ID, light_addr)),
                )
                .await
                {
                    Either::First(r) => r.expect("CASE and CommissioningComplete"),
                    Either::Second(_) => unreachable!(),
                }

                // 3. The operational service is registered too.
                wait_registry(&reg, |r| {
                    r.instances.iter().any(|i| {
                        i.name.to_ascii_uppercase().contains("._MATTER._TCP.")
                            && i.port == MATTER_PORT
                    })
                })
                .await;

                // 4. On/Off over CASE.
                match select(
                    pin!(read_onoff(ctrl_matter, fab, DEVICE_NODE_ID)),
                    pin!(resolver(ctrl_matter, DEVICE_NODE_ID, light_addr)),
                )
                .await
                {
                    Either::First(r) => assert!(!r.unwrap(), "the light starts off"),
                    Either::Second(_) => unreachable!(),
                }
                match select(
                    pin!(toggle(ctrl_matter, fab, DEVICE_NODE_ID)),
                    pin!(resolver(ctrl_matter, DEVICE_NODE_ID, light_addr)),
                )
                .await
                {
                    Either::First(r) => r.unwrap(),
                    Either::Second(_) => unreachable!(),
                }
                match select(
                    pin!(read_onoff(ctrl_matter, fab, DEVICE_NODE_ID)),
                    pin!(resolver(ctrl_matter, DEVICE_NODE_ID, light_addr)),
                )
                .await
                {
                    Either::First(r) => assert!(r.unwrap(), "the light is on after Toggle"),
                    Either::Second(_) => unreachable!(),
                }
            };
            match select3(pin!(server), pin!(ctrl_run), pin!(flow)).await {
                Either3::Third(()) => {}
                Either3::First(()) => unreachable!(),
                Either3::Second(r) => panic!("the controller stopped: {r:?}"),
            }
        },
        limit(),
    );
}

#[test]
fn on_off_light_is_commissioned_and_toggled_over_thread() {
    let _serial = serial();
    // The rs-matter futures are big in a debug build.
    std::thread::Builder::new()
        .stack_size(64 << 20)
        .spawn(run_light)
        .unwrap()
        .join()
        .unwrap();
}
