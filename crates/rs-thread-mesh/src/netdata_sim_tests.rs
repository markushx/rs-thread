//! Network Data through the mesh simulator: registration with the leader
//! over TMF, distribution through MLE, and the consumers (SLAAC, route
//! lookup, services, 6LoWPAN contexts, sleepy children).

use core::net::Ipv6Addr;

use rs_thread_core::time::Duration;
use rs_thread_mle::Role;
use rs_thread_mle::tlv::DeviceMode;

use crate::forwarder::SendResult;
use crate::netdata::local::{ExternalRouteConfig, OnMeshPrefixConfig, ServiceConfig};
use crate::netdata::tlv::{BrFlags, NetPrefix, THREAD_ENTERPRISE_NUMBER};
use crate::sim::MeshSim;

fn secs(s: u64) -> Duration {
    Duration::from_secs(s)
}

const FTD: DeviceMode = DeviceMode::new(true, true, true);
const SED: DeviceMode = DeviceMode::new(false, false, false);

fn a(s: &str) -> Ipv6Addr {
    s.parse().unwrap()
}

fn prefix(s: &str, len: u8) -> NetPrefix {
    NetPrefix::from_addr(&a(s), len).unwrap()
}

/// Node 0 becomes the leader, the others attach and the FTDs become
/// routers.
fn bring_up(modes: &[DeviceMode], links: &[(usize, usize)]) -> MeshSim {
    let mut m = MeshSim::with_modes(modes);
    for &(x, y) in links {
        m.connect(x, y, -60);
    }
    m.start(0);
    assert!(m.run_until(secs(60), |s| s.sim.role(0) == Role::Leader));
    for (i, mode) in modes.iter().enumerate().skip(1) {
        m.start(i);
        assert!(m.run_until(secs(60), |s| s.sim.role(i) == Role::Child));
        if mode.full_thread_device() {
            assert!(m.run_until(secs(300), |s| s.sim.role(i) == Role::Router));
        }
    }
    m
}

fn slaac_flags() -> BrFlags {
    BrFlags::default()
        .with(BrFlags::ON_MESH, true)
        .with(BrFlags::SLAAC, true)
        .with(BrFlags::PREFERRED, true)
}

fn versions(m: &MeshSim, i: usize) -> (u8, u8) {
    let l = m.sim.nodes[i].mle.leader_data();
    (l.data_version, l.stable_data_version)
}

fn has_addr_in(m: &MeshSim, i: usize, p: &NetPrefix) -> Option<Ipv6Addr> {
    m.tmf[i]
        .ip6
        .netif
        .unicast_addresses()
        .map(|u| u.addr)
        .find(|x| p.contains(x))
}

fn published_entries(m: &MeshSim, p: &NetPrefix) -> usize {
    m.netdata(0)
        .on_mesh_prefixes()
        .filter(|e| e.prefix == *p)
        .count()
}

#[test]
fn publishers_keep_the_desired_number_of_entries() {
    let links: std::vec::Vec<(usize, usize)> = (0..5)
        .flat_map(|a| ((a + 1)..5).map(move |b| (a, b)))
        .collect();
    let mut m = bring_up(&[FTD; 5], &links);
    let p = prefix("fd00:beef::", 64);
    let cfg = OnMeshPrefixConfig {
        prefix: p,
        flags: slaac_flags().with(BrFlags::DEFAULT_ROUTE, true),
        stable: true,
    };
    let now = m.sim.now;
    for i in 0..5 {
        let t = &mut m.tmf[i];
        t.publisher
            .publish_on_mesh_prefix(cfg, &mut t.local, now, &mut |_| {})
            .unwrap();
    }
    // Everybody wants to publish, the entries settle at the desired number
    // (three), seen by all nodes.
    assert!(m.run_until(secs(300), |s| published_entries(s, &p) == 3));
    m.run(secs(120));
    assert_eq!(published_entries(&m, &p), 3);
    for i in 0..5 {
        assert_eq!(
            m.netdata(i)
                .on_mesh_prefixes()
                .filter(|e| e.prefix == p)
                .count(),
            3,
            "node {i}"
        );
    }
    // The device holding an entry stops publishing: another one takes over.
    let holder = (0..5)
        .find(|&i| m.tmf[i].publisher.is_prefix_added(&p))
        .unwrap();
    {
        let t = &mut m.tmf[holder];
        t.publisher
            .unpublish_prefix(&p, &mut t.local, &mut |_| {})
            .unwrap();
        assert!(t.publisher.take_local_changed());
        t.notifier
            .event(crate::netdata::notifier::NotifierEvent::LocalChanged);
    }
    m.pump();
    assert!(m.run_until(secs(300), |s| {
        published_entries(s, &p) == 3 && !s.tmf[holder].publisher.is_prefix_added(&p)
    }));
}

#[test]
fn prefix_and_route_registration_reaches_all_nodes() {
    let mut m = bring_up(&[FTD, FTD, FTD], &[(0, 1), (0, 2), (1, 2)]);
    let (v0, sv0) = versions(&m, 0);
    let on_mesh = prefix("fd00:abcd::", 64);
    m.set_local(1, |l| {
        l.add_on_mesh_prefix(OnMeshPrefixConfig {
            prefix: on_mesh,
            flags: slaac_flags().with(BrFlags::DEFAULT_ROUTE, true),
            stable: true,
        })
        .unwrap();
        l.add_external_route(ExternalRouteConfig {
            prefix: prefix("2001:db8::", 32),
            preference: 0,
            nat64: false,
            adv_pio: false,
            stable: true,
        })
        .unwrap();
    });
    assert!(
        m.run_until(secs(60), |s| (0..3).all(|i| s
            .netdata(i)
            .on_mesh_prefixes()
            .count()
            == 1
            && s.netdata(i).external_routes().count() == 1)),
        "Network Data did not reach all nodes"
    );
    // The leader merged the registration and bumped both versions; the
    // other nodes carry the same Leader Data version.
    let (v1, sv1) = versions(&m, 0);
    assert_eq!(v1, v0.wrapping_add(1));
    assert_eq!(sv1, sv0.wrapping_add(1));
    assert_eq!(m.tmf[0].leader.version(), v1);
    for i in 1..3 {
        assert_eq!(versions(&m, i), (v1, sv1), "node {i}");
        assert_eq!(m.tmf[i].netdata, m.tmf[0].netdata);
    }
    // The registration came from the BR's RLOC16 and got a context.
    let br_rloc = m.sim.nodes[1].mle.rloc16().0;
    assert!(m.netdata(0).on_mesh_prefixes().all(|e| e.rloc16 == br_rloc));
    let ctx: std::vec::Vec<_> = m.netdata(2).contexts().collect();
    assert_eq!((ctx.len(), ctx[0].id, ctx[0].prefix), (1, 1, on_mesh));
    // SLAAC derived an address on every node.
    for i in 0..3 {
        assert!(has_addr_in(&m, i, &on_mesh).is_some(), "SLAAC on node {i}");
    }
    // The notifier stays quiet once the data is consistent.
    let sent = m.tmf[1].server_data_sent;
    m.run(secs(120));
    assert_eq!(m.tmf[1].server_data_sent, sent);
}

#[test]
fn unchanged_local_data_is_not_registered_twice() {
    let mut m = bring_up(&[FTD, FTD], &[(0, 1)]);
    let cfg = ExternalRouteConfig {
        prefix: prefix("2001:db8::", 32),
        preference: 1,
        nat64: false,
        adv_pio: false,
        stable: false,
    };
    m.set_local(1, |l| l.add_external_route(cfg).unwrap());
    assert!(
        m.run_until(secs(30), |s| s.netdata(0).external_routes().count() == 1
            && s.netdata(1).external_routes().count() == 1)
    );
    let v = versions(&m, 0);
    // The same data again: the notifier finds it consistent.
    m.set_local(1, |l| l.add_external_route(cfg).unwrap());
    m.run(secs(10));
    assert_eq!(versions(&m, 0), v);
    assert_eq!(m.tmf[1].server_data_sent, 1);
}

#[test]
fn datagram_to_external_route_goes_to_the_border_router() {
    // 2 - 0 - 1: the sender reaches the border router (1) through the leader.
    let mut m = bring_up(&[FTD, FTD, FTD], &[(0, 1), (0, 2)]);
    let on_mesh = prefix("fd00:abcd::", 64);
    m.set_local(1, |l| {
        l.add_on_mesh_prefix(OnMeshPrefixConfig {
            prefix: on_mesh,
            flags: slaac_flags(),
            stable: true,
        })
        .unwrap();
        l.add_external_route(ExternalRouteConfig {
            prefix: prefix("2001:db8::", 32),
            preference: 0,
            nat64: false,
            adv_pio: false,
            stable: true,
        })
        .unwrap();
    });
    assert!(m.run_until(secs(60), |s| (0..3).all(
        |i| s.netdata(i).contexts().count() == 1
            && s.netdata(i).external_routes().count() == 1
            && has_addr_in(s, i, &on_mesh).is_some()
    )));
    // The routers need each other's routes.
    let r1 = m.sim.nodes[1].mle.rloc16();
    assert!(m.run_until(secs(600), |s| {
        s.sim.nodes[2].mle.next_hop_and_path_cost(r1).0.is_some()
    }));
    let src = has_addr_in(&m, 2, &on_mesh).unwrap();
    m.frame_log.clear();
    let r = m.send_udp_from(2, src, a("2001:db8::77"), b"out");
    assert!(matches!(r, SendResult::Sent), "{r:?}");
    assert!(m.run_until(secs(10), |s| !s.tmf[1].egress.is_empty()));
    assert_eq!(&m.tmf[1].egress[0][48..], b"out");
    // It crossed the leader as a mesh frame.
    assert!(m.tmf[0].forwarded >= 1);
    // A destination without a route is not sent; so is a source outside
    // every on-mesh prefix.
    let r = m.send_udp_from(2, src, a("2002::1"), b"x");
    assert!(matches!(r, SendResult::Dropped(_)), "{r:?}");
    let r = m.send_udp(2, a("2001:db8::77"), b"x");
    assert!(matches!(r, SendResult::Dropped(_)), "{r:?}");
}

#[test]
fn router_removal_clears_its_entries() {
    let mut m = bring_up(&[FTD, FTD, FTD], &[(0, 1), (0, 2), (1, 2)]);
    m.set_local(1, |l| {
        l.add_external_route(ExternalRouteConfig {
            prefix: prefix("2001:db8::", 32),
            preference: 0,
            nat64: false,
            adv_pio: false,
            stable: true,
        })
        .unwrap();
    });
    m.set_local(2, |l| {
        l.add_on_mesh_prefix(OnMeshPrefixConfig {
            prefix: prefix("fd00:beef::", 64),
            flags: slaac_flags(),
            stable: true,
        })
        .unwrap();
    });
    assert!(m.run_until(secs(60), |s| (0..3).all(|i| {
        s.netdata(i).external_routes().count() == 1 && s.netdata(i).on_mesh_prefixes().count() == 1
    })));
    let before = versions(&m, 0);
    // The leader releases router 1 (e.g. it timed out).
    let id = m.sim.nodes[1].mle.rloc16().router_id();
    let now = m.sim.now;
    {
        let n = &mut m.sim.nodes[0];
        n.mle.release_router_id(&mut n.env, now, id).unwrap();
    }
    // Router 1 is a child now and would register its route again: keep its
    // TMF requests away so that the removal stays visible.
    m.blocked.push((1, 0));
    m.blocked.push((1, 2));
    assert!(m.run_until(secs(60), |s| {
        (0..3)
            .filter(|&i| i != 1)
            .all(|i| s.netdata(i).external_routes().count() == 0)
    }));
    // Only the entries of the released router are gone.
    assert_eq!(m.netdata(0).on_mesh_prefixes().count(), 1);
    assert_eq!(m.netdata(2).on_mesh_prefixes().count(), 1);
    let after = versions(&m, 0);
    assert_ne!(before, after);
    assert!(m.run_until(secs(30), |s| versions(s, 2) == after));
}

#[test]
fn service_registration_and_service_aloc_routing() {
    // 1 - 0 - 2: the service sits on 2, the client on 1.
    let mut m = bring_up(&[FTD, FTD, FTD], &[(0, 1), (0, 2)]);
    m.set_local(2, |l| {
        l.add_service(
            ServiceConfig::new(THREAD_ENTERPRISE_NUMBER, &[0x5d, 0x01], &[0xaa], true).unwrap(),
        )
        .unwrap();
    });
    assert!(m.run_until(secs(60), |s| {
        (0..3).all(|i| s.netdata(i).services().count() == 1)
    }));
    let svc = m.netdata(1).services().next().unwrap();
    assert_eq!(svc.rloc16, m.sim.nodes[2].mle.rloc16().0);
    assert_eq!(svc.service_data, [0x5d, 0x01]);
    let aloc = svc.aloc16();
    // The server answers to the service ALOC.
    let mlp = rs_thread_mle::test_support::MLP;
    assert!(m.run_until(secs(10), |s| {
        s.tmf[2].ip6.netif.has_unicast(&mlp.aloc(aloc).unwrap())
    }));
    assert!(!m.tmf[1].ip6.netif.has_unicast(&mlp.aloc(aloc).unwrap()));
    // The leader answers to its ALOC.
    assert!(m.tmf[0].ip6.netif.has_unicast(&mlp.aloc(0xfc00).unwrap()));
    // Route a datagram to the service ALOC across the mesh.
    let r2 = m.sim.nodes[2].mle.rloc16();
    assert!(m.run_until(secs(600), |s| {
        s.sim.nodes[1].mle.next_hop_and_path_cost(r2).0.is_some()
    }));
    let r = m.send_udp(1, mlp.aloc(aloc).unwrap(), b"svc");
    assert!(matches!(r, SendResult::Sent), "{r:?}");
    assert!(m.run_until(secs(10), |s| !s.tmf[2].delivered.is_empty()));
    assert_eq!(&m.tmf[2].delivered[0][48..], b"svc");
    // Unknown service ALOCs have no route.
    let r = m.send_udp(1, mlp.aloc(0xfc1f).unwrap(), b"x");
    assert!(matches!(r, SendResult::Dropped(_)), "{r:?}");
    // The service disappears with its registration.
    let sent = m.tmf[2].server_data_sent;
    m.set_local(2, |l| {
        l.remove_service(THREAD_ENTERPRISE_NUMBER, &[0x5d, 0x01])
            .unwrap()
    });
    assert!(m.run_until(secs(10), |s| s.tmf[2].server_data_sent > sent));
    assert!(m.run_until(secs(60), |s| {
        (0..3).all(|i| s.netdata(i).services().count() == 0)
    }));
    assert!(m.run_until(secs(10), |s| {
        !s.tmf[2].ip6.netif.has_unicast(&mlp.aloc(aloc).unwrap())
    }));
}

#[test]
fn context_ids_compress_addresses_end_to_end() {
    let mut m = bring_up(&[FTD, FTD, FTD], &[(0, 1), (0, 2), (1, 2)]);
    let on_mesh = prefix("fd00:abcd::", 64);
    m.set_local(1, |l| {
        l.add_on_mesh_prefix(OnMeshPrefixConfig {
            prefix: on_mesh,
            flags: slaac_flags(),
            stable: true,
        })
        .unwrap();
    });
    assert!(
        m.run_until(secs(60), |s| has_addr_in(s, 1, &on_mesh).is_some()
            && has_addr_in(s, 2, &on_mesh).is_some())
    );
    let src = has_addr_in(&m, 2, &on_mesh).unwrap();
    let dst = has_addr_in(&m, 1, &on_mesh).unwrap();
    let r1 = m.sim.nodes[1].mle.rloc16();
    assert!(m.run_until(secs(600), |s| {
        s.sim.nodes[2].mle.next_hop_and_path_cost(r1).0.is_some()
    }));
    m.frame_log.clear();
    let r = m.send_udp_from(2, src, dst, b"ctx");
    assert!(matches!(r, SendResult::Held | SendResult::Sent), "{r:?}");
    assert!(m.run_until(secs(10), |s| !s.tmf[1].delivered.is_empty()));
    // Delivered with the original addresses ...
    let d = &m.tmf[1].delivered[0];
    let h = rs_thread_lowpan::ip6::Ipv6Header::parse(d).unwrap();
    assert_eq!((h.src, h.dst), (src, dst));
    assert_eq!(&d[48..], b"ctx");
    // ... and on the air the datagram used context 1 for both: the
    // frame carrying it has CID, SAC and DAC set and SCI = DCI = 1.
    let frame = m
        .frame_log
        .iter()
        .find(|(from, to, p)| *from == 2 && *to == 1 && p.len() > 20 && p[0] & 0xe0 == 0x60)
        .expect("compressed data frame");
    let p = &frame.2;
    assert_eq!(p[1] & 0xc4, 0xc4, "CID/SAC/DAC: {p:02x?}");
    assert_eq!(p[2], 0x11, "SCI/DCI: {p:02x?}");
}

#[test]
fn sleepy_children_get_stable_data_only() {
    // 0 - 1, sleepy child 2 of router 1.
    let mut m = bring_up(&[FTD, FTD, SED], &[(0, 1), (1, 2)]);
    let stable_prefix = prefix("fd00:abcd::", 64);
    m.set_local(1, |l| {
        l.add_on_mesh_prefix(OnMeshPrefixConfig {
            prefix: stable_prefix,
            flags: slaac_flags(),
            stable: true,
        })
        .unwrap();
        l.add_external_route(ExternalRouteConfig {
            prefix: prefix("2001:db8::", 32),
            preference: 0,
            nat64: false,
            adv_pio: false,
            stable: false,
        })
        .unwrap();
    });
    assert!(
        m.run_until(secs(60), |s| s.netdata(0).external_routes().count() == 1
            && s.netdata(1).external_routes().count() == 1)
    );
    // The child receives the stable subset: the prefix, no route, and no
    // RLOC16 of the border router.
    assert!(m.run_until(secs(60), |s| s.netdata(2).on_mesh_prefixes().count() == 1));
    assert_eq!(m.netdata(2).external_routes().count(), 0);
    assert!(m.netdata(2).on_mesh_prefixes().all(|e| e.rloc16 == 0xfffe));
    assert_eq!(m.netdata(2).contexts().count(), 1);
    let (_, sv) = versions(&m, 0);
    assert_eq!(versions(&m, 2).1, sv);
    // A change in temporary data moves only the full version: the sleepy
    // child is left alone.
    let (v_before, sv_before) = versions(&m, 0);
    let child_before = m.tmf[2].netdata.clone();
    m.set_local(1, |l| {
        l.add_external_route(ExternalRouteConfig {
            prefix: prefix("2001:db8::", 32),
            preference: 1,
            nat64: false,
            adv_pio: false,
            stable: false,
        })
        .unwrap();
    });
    assert!(m.run_until(secs(60), |s| versions(s, 0).0 != v_before));
    assert_eq!(versions(&m, 0).1, sv_before);
    m.run(secs(5));
    assert_eq!(versions(&m, 2).1, sv_before);
    assert_eq!(m.tmf[2].netdata, child_before);
    assert_eq!(m.netdata(0).external_routes().next().unwrap().preference, 1);
}

#[test]
fn anycast_locator_finds_the_service_server() {
    let mut m = bring_up(&[FTD, FTD], &[(0, 1)]);
    m.set_local(1, |l| {
        l.add_service(ServiceConfig::new(THREAD_ENTERPRISE_NUMBER, &[1], &[], true).unwrap())
            .unwrap();
    });
    assert!(m.run_until(secs(60), |s| s.netdata(0).services().count() == 1));
    let mlp = rs_thread_mle::test_support::MLP;
    let aloc = mlp.aloc(0xfc10).unwrap();
    assert!(m.run_until(secs(10), |s| s.tmf[1].ip6.netif.has_unicast(&aloc)));
    let src = m.rloc(0);
    m.locate(0, src, aloc);
    assert!(m.run_until(secs(10), |s| !s.tmf[0].located.is_empty()));
    let l = m.tmf[0].located[0];
    assert_eq!(l.rloc16, m.sim.nodes[1].mle.rloc16());
    assert_eq!(l.ml_eid, m.ml_eid(1));
}

#[test]
fn server_data_is_only_accepted_by_the_leader_for_the_sender() {
    use crate::netdata::local::LocalData;
    use crate::netdata::server_data::build_server_data;
    use rs_thread_coap::message::{Code, Type};
    let mut m = bring_up(&[FTD, FTD, FTD], &[(0, 1), (0, 2), (1, 2)]);
    let mk = |rloc: u16| {
        let mut l = LocalData::<2, 2, 1>::new();
        l.add_external_route(ExternalRouteConfig {
            prefix: prefix("2001:db8::", 32),
            preference: 0,
            nat64: false,
            adv_pio: false,
            stable: true,
        })
        .unwrap();
        let mut nd = [0u8; 64];
        let n = l.encode(rloc, &mut nd).unwrap();
        let mut p = [0u8; 80];
        let k = build_server_data(None, Some(&nd[..n]), &mut p).unwrap();
        p[..k].to_vec()
    };
    let r1 = m.sim.nodes[1].mle.rloc16().0;
    // A router that is not the leader does not answer.
    assert!(
        m.raw_request(1, 2, "a/sd", Type::Con, Code::POST, &mk(r1))
            .is_none()
    );
    // The leader answers with an ACK carrying 2.04 ...
    let (code, body) = m
        .raw_request(1, 0, "a/sd", Type::Con, Code::POST, &mk(r1))
        .unwrap();
    assert_eq!((code, body.len()), (Code::CHANGED, 0));
    assert_eq!(m.tmf[0].leader.data().view().external_routes().count(), 1);
    // ... also when the entries do not carry the sender's RLOC16, but the
    // data is not taken over.
    let v = versions(&m, 0);
    let wrong = m.sim.nodes[2].mle.rloc16().0;
    let (code, _) = m
        .raw_request(1, 0, "a/sd", Type::Con, Code::POST, &mk(wrong))
        .unwrap();
    assert_eq!(code, Code::CHANGED);
    assert_eq!(m.tmf[0].leader.data().view().external_routes().count(), 1);
    assert_eq!(
        m.tmf[0]
            .leader
            .data()
            .view()
            .external_routes()
            .next()
            .unwrap()
            .rloc16,
        r1
    );
    assert_eq!(versions(&m, 0), v);
}
