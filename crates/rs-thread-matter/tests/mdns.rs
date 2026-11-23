//! `SrpMdns`: a Matter node registers its commissionable service with the
//! SRP server of the leader and resolves an operational peer through DNS-SD;
//! `ThreadNetif` reports the interface and wakes several waiters.
mod common;

use core::cell::{Cell, RefCell};
use core::net::{Ipv4Addr, SocketAddr};

use common::srp::{Instance as SrpInstance, Registered};
use common::*;
use embassy_futures::join::join;
use embassy_futures::select::{Either, select};
use rs_thread_core::time::Duration;
use rs_thread_instance::{BrFlags, NetPrefix, OnMeshPrefixConfig, Role};
use rs_thread_matter::mdns::SrpMdns;
use rs_thread_matter::net::MatterNetStack;
use rs_thread_matter::netif::{NETIF_NAME, ThreadNetif};
use rs_matter::Matter;
use rs_matter::crypto::default_crypto;
use rs_matter::dm::clusters::gen_diag::{InterfaceTypeEnum, NetifDiag};
use rs_matter::dm::devices::test::{DAC_PRIVKEY, TEST_DEV_ATT, TEST_DEV_COMM, TEST_DEV_DET};
use rs_matter::dm::networks::NetChangeNotif;
use rs_matter::dm::{AttrChangeNotifier, AttrId, ClusterId, EndptId};
use rs_matter::stack::mdns::Mdns;
use rs_matter::transport::network::MatterRemoteService;
use rs_matter::utils::init::InitMaybeUninit;

const MATTER_PORT: u16 = 5540;

struct NoNotify;

impl AttrChangeNotifier for NoNotify {
    fn notify_attr_changed(&self, _: EndptId, _: ClusterId, _: AttrId) {}
    fn notify_cluster_changed(&self, _: EndptId, _: ClusterId) {}
    fn notify_endpoint_changed(&self, _: EndptId) {}
    fn notify_all_changed(&self) {}
}

#[test]
fn registers_with_srp_and_resolves_with_dns_sd() {
    let _g = serial();
    let clks = [clock(), clock()];
    let air = Air::new(2);
    let pend = [Cell::new(None), Cell::new(None)];
    let res0: Res<'_> = Res::new(instance(1), &clks[0]);
    let res1: Res<'_> = Res::new(instance(2), &clks[1]);
    let ots = [Ot::new(&res0), Ot::new(&res1)];
    let ds = make_dataset(ots[0]);
    let tasks = vec![
        run_task(ots[0], &air, 0, &clks[0], &pend[0]),
        run_task(ots[1], &air, 1, &clks[1], &pend[1]),
    ];
    let reg = RefCell::new(Registered::default());
    let mut matter_cell = Box::<Matter<'_>>::new_uninit();
    let matter = matter_cell.init_with(Matter::init(
        &TEST_DEV_DET,
        TEST_DEV_COMM,
        &TEST_DEV_ATT,
        MATTER_PORT,
    ));
    let crypto = default_crypto(rand::rng(), DAC_PRIVKEY);

    drive(
        &[&clks[0], &clks[1]],
        &[&pend[0], &pend[1]],
        tasks,
        async {
            form_network(&ots, &ds).await;
            let server = async {
                common::srp::serve(ots[0], &reg).await;
            };
            let node = async {
                // A commissioning window: rs-matter advertises `_matterc._udp`.
                matter
                    .open_basic_comm_window(300, &crypto, &NoNotify)
                    .unwrap();
                let netif = ThreadNetif::new(ots[1]);
                let mut mdns = SrpMdns::new(ots[1]);
                let stack = MatterNetStack::new(ots[1]);
                let mac = ots[1].with(|i, _| i.ext_address().0);
                let addrs = netif.addresses();
                let run = mdns.run(
                    matter,
                    &crypto,
                    &stack,
                    &mac,
                    Ipv4Addr::UNSPECIFIED,
                    &addrs,
                    1,
                );
                let check = async {
                    // 1. The commissionable service is registered with its
                    //    subtypes and TXT entries.
                    let inst = loop {
                        if let Some(i) = reg.borrow().instance("")
                            && i.port != 0
                            && !i.txt.is_empty()
                            && !i.subtypes.is_empty()
                        {
                            break i.clone();
                        }
                        ots[1].wait_changed().await;
                    };
                    assert!(
                        inst.name
                            .to_ascii_uppercase()
                            .ends_with("._MATTERC._UDP.DEFAULT.SERVICE.ARPA"),
                        "{}",
                        inst.name
                    );
                    assert_eq!(inst.port, MATTER_PORT);
                    let subs: Vec<String> = inst
                        .subtypes
                        .iter()
                        .map(|s| s.split("._sub.").next().unwrap().to_string())
                        .collect();
                    let d = TEST_DEV_COMM.discriminator;
                    assert!(subs.contains(&format!("_L{d}")), "{subs:?}");
                    assert!(subs.contains(&format!("_S{}", d >> 8)), "{subs:?}");
                    assert!(
                        subs.contains(&format!("_V{}", TEST_DEV_DET.vid)),
                        "{subs:?}"
                    );
                    assert!(subs.contains(&"_CM".to_string()), "{subs:?}");
                    let txt = String::from_utf8_lossy(&inst.txt).to_string();
                    assert!(txt.contains(&format!("D={d}")), "{txt}");
                    assert!(txt.contains("CM=1"), "{txt}");
                    assert!(
                        txt.contains(&format!("VP={}+{}", TEST_DEV_DET.vid, TEST_DEV_DET.pid)),
                        "{txt}"
                    );
                    {
                        let r = reg.borrow();
                        assert_eq!(r.host.len(), 16 + 1 + 20, "{}", r.host);
                        assert!(r.addrs.contains(&ots[1].with(|i, _| i.ml_eid())));
                    }

                    // 2. An operational peer (registered out of band) is
                    //    resolved through the DNS-SD client.
                    reg.borrow_mut().instances.push(SrpInstance {
                        name: "0123456789ABCDEF-0000000000000001._matter._tcp.default.service.arpa"
                            .into(),
                        port: 5541,
                        txt: b"\x08SII=5000\x07SAI=300".to_vec(),
                        subtypes: Vec::new(),
                    });
                    let resolved = matter
                        .transport()
                        .resolve(
                            MatterRemoteService::Operational {
                                compressed_fabric_id: 0x0123_4567_89AB_CDEF,
                                node_id: 1,
                            },
                            10_000,
                        )
                        .await
                        .unwrap();
                    // The server's own addresses answer (the fake host is the
                    // registered one, so its AAAA is the ML-EID of node 1).
                    assert!(
                        resolved
                            .addrs
                            .iter()
                            .all(|a| matches!(a, SocketAddr::V6(v6) if v6.port() == 5541)),
                        "{resolved:?}"
                    );
                    assert_eq!(resolved.sii, Some(5000));
                    assert!(reg.borrow().queries >= 1);

                    // 3. Closing the window removes the service.
                    matter.transport().notify_mdns_changed();
                };
                match select(run, check).await {
                    Either::First(r) => panic!("mdns run ended: {r:?}"),
                    Either::Second(()) => {}
                }
                // Dropping `run` removed the registrations (an SRP update
                // with deletes follows).
                loop {
                    let done = {
                        let r = reg.borrow();
                        r.updates >= 2 && !r.instances.iter().any(|i| i.name.contains("_matterc"))
                    };
                    if done {
                        break;
                    }
                    ots[1].wait_changed().await;
                }
            };
            let netif_checks = async {
                let netif = ThreadNetif::new(ots[1]);
                let mut seen = Vec::new();
                netif
                    .netifs(&mut |ni| {
                        seen.push((
                            ni.name.to_string(),
                            ni.operational,
                            *ni.hw_addr,
                            ni.ipv6_addrs.to_vec(),
                            ni.netif_type,
                        ));
                        Ok(())
                    })
                    .unwrap();
                assert_eq!(seen.len(), 1);
                let (name, operational, hw, addrs, ty) = &seen[0];
                assert_eq!(name, NETIF_NAME);
                assert!(*operational);
                assert_eq!(*hw, ots[1].with(|i, _| i.ext_address().0));
                assert_eq!(*ty, InterfaceTypeEnum::Thread);
                assert!(addrs[0].is_unicast_link_local(), "{addrs:?}");
                assert!(addrs.contains(&ots[1].with(|i, _| i.ml_eid())), "{addrs:?}");
                let rloc = ots[1].with(|i, _| i.rloc()).unwrap();
                assert!(!addrs.contains(&rloc), "{addrs:?}");
                // Two waiters on the same change (the REED becomes a router).
                let woken = Cell::new(0);
                let waiter = || async {
                    while ots[1].role() != Role::Router {
                        netif.wait_changed().await;
                    }
                    woken.set(woken.get() + 1);
                };
                join(waiter(), waiter()).await;
                assert_eq!(woken.get(), 2);
            };
            match select(server, join(node, netif_checks)).await {
                Either::First(()) => unreachable!(),
                Either::Second(_) => {}
            }
        },
        Duration::from_secs(1800),
    );
}

/// A border router publishes an on-mesh SLAAC prefix and the SRP server: the
/// node configures a prefix address, and the SRP client registers that
/// address (not the mesh-local ML-EID, which is only the fallback) together
/// with the commissionable service, as OpenThread's auto host address mode
/// does.
#[test]
fn registers_the_slaac_address_of_a_border_router_prefix() {
    let _g = serial();
    let clks = [clock(), clock()];
    let air = Air::new(2);
    let pend = [Cell::new(None), Cell::new(None)];
    let res0: Res<'_> = Res::new(instance(1), &clks[0]);
    let res1: Res<'_> = Res::new(instance(2), &clks[1]);
    let ots = [Ot::new(&res0), Ot::new(&res1)];
    let ds = make_dataset(ots[0]);
    let tasks = vec![
        run_task(ots[0], &air, 0, &clks[0], &pend[0]),
        run_task(ots[1], &air, 1, &clks[1], &pend[1]),
    ];
    let reg = RefCell::new(Registered::default());
    let mut matter_cell = Box::<Matter<'_>>::new_uninit();
    let matter = matter_cell.init_with(Matter::init(
        &TEST_DEV_DET,
        TEST_DEV_COMM,
        &TEST_DEV_ATT,
        MATTER_PORT,
    ));
    let crypto = default_crypto(rand::rng(), DAC_PRIVKEY);
    let prefix = [0xfd, 0x11, 0x00, 0x22, 0, 0, 0, 0];

    drive(
        &[&clks[0], &clks[1]],
        &[&pend[0], &pend[1]],
        tasks,
        async {
            ots[0].with(|i, _| {
                i.add_on_mesh_prefix(OnMeshPrefixConfig {
                    prefix: NetPrefix::new(&prefix, 64).unwrap(),
                    flags: BrFlags(BrFlags::PREFERRED | BrFlags::SLAAC | BrFlags::ON_MESH),
                    stable: true,
                })
                .unwrap();
            });
            form_network(&ots, &ds).await;
            let server = async {
                common::srp::serve(ots[0], &reg).await;
            };
            let node = async {
                matter
                    .open_basic_comm_window(300, &crypto, &NoNotify)
                    .unwrap();
                let netif = ThreadNetif::new(ots[1]);
                let mut mdns = SrpMdns::new(ots[1]);
                let stack = MatterNetStack::new(ots[1]);
                let mac = ots[1].with(|i, _| i.ext_address().0);
                let addrs = netif.addresses();
                let run = mdns.run(
                    matter,
                    &crypto,
                    &stack,
                    &mac,
                    Ipv4Addr::UNSPECIFIED,
                    &addrs,
                    1,
                );
                let check = async {
                    loop {
                        if reg
                            .borrow()
                            .instance("")
                            .is_some_and(|i| i.port != 0 && !i.subtypes.is_empty())
                        {
                            break;
                        }
                        ots[1].wait_changed().await;
                    }
                    let r = reg.borrow();
                    assert!(!r.addrs.is_empty());
                    assert!(
                        r.addrs.iter().all(|a| a.octets()[..8] == prefix),
                        "host addresses: {:?}",
                        r.addrs
                    );
                    assert!(!r.addrs.contains(&ots[1].with(|i, _| i.ml_eid())));
                    let inst = r.instance("").unwrap();
                    let subs: Vec<String> = inst
                        .subtypes
                        .iter()
                        .map(|s| s.split("._sub.").next().unwrap().to_string())
                        .collect();
                    let d = TEST_DEV_COMM.discriminator;
                    for want in [format!("_L{d}"), format!("_S{}", d >> 8), "_CM".to_string()] {
                        assert!(subs.contains(&want), "{subs:?}");
                    }
                };
                match select(run, check).await {
                    Either::First(r) => panic!("mdns run ended: {r:?}"),
                    Either::Second(()) => {}
                }
            };
            match select(server, node).await {
                Either::First(()) => unreachable!(),
                Either::Second(()) => {}
            }
        },
        Duration::from_secs(1800),
    );
}

/// The network interface restarting the mDNS future (here: a second `run`
/// right after the first was dropped, as when the mesh-local prefix changes
/// after attaching with a partial dataset) must not leave the service
/// unregistered while the SRP client still holds the removal of the old one.
#[test]
fn registers_again_after_the_mdns_future_restarted() {
    let _g = serial();
    let clks = [clock(), clock()];
    let air = Air::new(2);
    let pend = [Cell::new(None), Cell::new(None)];
    let res0: Res<'_> = Res::new(instance(1), &clks[0]);
    let res1: Res<'_> = Res::new(instance(2), &clks[1]);
    let ots = [Ot::new(&res0), Ot::new(&res1)];
    let ds = make_dataset(ots[0]);
    let tasks = vec![
        run_task(ots[0], &air, 0, &clks[0], &pend[0]),
        run_task(ots[1], &air, 1, &clks[1], &pend[1]),
    ];
    let reg = RefCell::new(Registered::default());
    let mut matter_cell = Box::<Matter<'_>>::new_uninit();
    let matter = matter_cell.init_with(Matter::init(
        &TEST_DEV_DET,
        TEST_DEV_COMM,
        &TEST_DEV_ATT,
        MATTER_PORT,
    ));
    let crypto = default_crypto(rand::rng(), DAC_PRIVKEY);

    drive(
        &[&clks[0], &clks[1]],
        &[&pend[0], &pend[1]],
        tasks,
        async {
            form_network(&ots, &ds).await;
            let server = async {
                common::srp::serve(ots[0], &reg).await;
            };
            let node = async {
                matter
                    .open_basic_comm_window(300, &crypto, &NoNotify)
                    .unwrap();
                let netif = ThreadNetif::new(ots[1]);
                let stack = MatterNetStack::new(ots[1]);
                let mac = ots[1].with(|i, _| i.ext_address().0);
                let addrs = netif.addresses();
                let registered = || {
                    reg.borrow()
                        .instance("")
                        .is_some_and(|i| i.port != 0 && !i.subtypes.is_empty())
                };
                // First future: register, then drop it.
                {
                    let mut mdns = SrpMdns::new(ots[1]);
                    let run = mdns.run(
                        matter,
                        &crypto,
                        &stack,
                        &mac,
                        Ipv4Addr::UNSPECIFIED,
                        &addrs,
                        1,
                    );
                    let check = async {
                        while !registered() {
                            ots[1].wait_changed().await;
                        }
                    };
                    match select(run, check).await {
                        Either::First(r) => panic!("mdns run ended: {r:?}"),
                        Either::Second(()) => {}
                    }
                }
                // Second future at once: the removal is still pending.
                let updates = reg.borrow().updates;
                let mut mdns = SrpMdns::new(ots[1]);
                let run = mdns.run(
                    matter,
                    &crypto,
                    &stack,
                    &mac,
                    Ipv4Addr::UNSPECIFIED,
                    &addrs,
                    1,
                );
                let check = async {
                    // The removal and the new registration both reach the server.
                    while !(reg.borrow().updates > updates + 1 && registered()) {
                        ots[1].wait_changed().await;
                    }
                };
                match select(run, check).await {
                    Either::First(r) => panic!("mdns run ended: {r:?}"),
                    Either::Second(()) => {}
                }
            };
            match select(server, node).await {
                Either::First(()) => unreachable!(),
                Either::Second(()) => {}
            }
        },
        Duration::from_secs(1800),
    );
}

/// The SRP server holds the host name for another key (as after a factory
/// reset of the node, for the key lease): the update is answered with
/// YXDOMAIN and the node registers under `<name>-1` instead.
#[test]
fn moves_to_another_host_name_on_a_name_conflict() {
    let _g = serial();
    let clks = [clock(), clock()];
    let air = Air::new(2);
    let pend = [Cell::new(None), Cell::new(None)];
    let res0: Res<'_> = Res::new(instance(1), &clks[0]);
    let res1: Res<'_> = Res::new(instance(2), &clks[1]);
    let ots = [Ot::new(&res0), Ot::new(&res1)];
    let ds = make_dataset(ots[0]);
    let tasks = vec![
        run_task(ots[0], &air, 0, &clks[0], &pend[0]),
        run_task(ots[1], &air, 1, &clks[1], &pend[1]),
    ];
    let mac = ots[1].with(|i, _| i.ext_address().0);
    let plain: String = mac.iter().map(|b| format!("{b:02X}")).collect();
    let reg = RefCell::new(Registered {
        conflict_host: Some(plain.clone()),
        ..Registered::default()
    });
    let mut matter_cell = Box::<Matter<'_>>::new_uninit();
    let matter = matter_cell.init_with(Matter::init(
        &TEST_DEV_DET,
        TEST_DEV_COMM,
        &TEST_DEV_ATT,
        MATTER_PORT,
    ));
    let crypto = default_crypto(rand::rng(), DAC_PRIVKEY);

    drive(
        &[&clks[0], &clks[1]],
        &[&pend[0], &pend[1]],
        tasks,
        async {
            form_network(&ots, &ds).await;
            let server = async {
                common::srp::serve(ots[0], &reg).await;
            };
            let node = async {
                matter
                    .open_basic_comm_window(300, &crypto, &NoNotify)
                    .unwrap();
                let netif = ThreadNetif::new(ots[1]);
                let mut mdns = SrpMdns::new(ots[1]);
                let stack = MatterNetStack::new(ots[1]);
                let addrs = netif.addresses();
                let run = mdns.run(
                    matter,
                    &crypto,
                    &stack,
                    &mac,
                    Ipv4Addr::UNSPECIFIED,
                    &addrs,
                    1,
                );
                let check = async {
                    loop {
                        if reg.borrow().instance("").is_some() {
                            break;
                        }
                        ots[1].wait_changed().await;
                    }
                    let r = reg.borrow();
                    assert!(r.conflicts >= 1);
                    assert!(
                        r.host
                            .to_ascii_uppercase()
                            .starts_with(&format!("{plain}-1.")),
                        "host {}",
                        r.host
                    );
                };
                match select(run, check).await {
                    Either::First(r) => panic!("mdns run ended: {r:?}"),
                    Either::Second(()) => {}
                }
            };
            match select(server, node).await {
                Either::First(()) => unreachable!(),
                Either::Second(()) => {}
            }
        },
        Duration::from_secs(1800),
    );
}
