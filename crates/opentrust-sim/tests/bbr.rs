//! DUA, MLR and Backbone Router client: a fake Backbone Router (a TMF
//! extension of node 0) answers `/n/dr` and `/n/mr`.

mod common;

use core::net::Ipv6Addr;
use std::sync::Mutex;

use common::*;
use opentrust_instance::{BrFlags, CoapCode, NetPrefix, OnMeshPrefixConfig, Role, TmfUri};
use opentrust_mesh::dua::build_dua_status;
use opentrust_mesh::mlr::{build_mlr_response, parse_mlr_request};
use opentrust_mesh::netdata::backbone::BbrConfig;
use opentrust_mesh::netdata::local::ServiceConfig;
use opentrust_mesh::netdata::tlv::THREAD_ENTERPRISE_NUMBER;
use opentrust_mesh::tlv::ThreadTlvs;
use opentrust_sim::{Kind, Network};

static DUA_TARGETS: Mutex<Vec<Ipv6Addr>> = Mutex::new(Vec::new());
static MLR_GROUPS: Mutex<Vec<Ipv6Addr>> = Mutex::new(Vec::new());

fn fake_bbr(uri: TmfUri, payload: &[u8]) -> Option<(CoapCode, heapless::Vec<u8, 64>)> {
    let mut out = [0u8; 64];
    match uri {
        TmfUri::DuaRegistrationRequest => {
            let target = ThreadTlvs::new(payload).target().ok()?;
            DUA_TARGETS.lock().unwrap().push(target);
            let n = build_dua_status(0, &target, &mut out).ok()?;
            Some((
                CoapCode::CHANGED,
                heapless::Vec::from_slice(&out[..n]).ok()?,
            ))
        }
        TmfUri::Mlr => {
            for a in parse_mlr_request(payload).ok()? {
                MLR_GROUPS.lock().unwrap().push(a);
            }
            let n = build_mlr_response(0, &[], &mut out).ok()?;
            Some((
                CoapCode::CHANGED,
                heapless::Vec::from_slice(&out[..n]).ok()?,
            ))
        }
        _ => None,
    }
}

#[test]
fn dua_and_mlr_registration_with_a_fake_backbone_router() {
    let mut net = Network::new(&[Kind::Router, Kind::Router, Kind::EndDevice], 5);
    net.medium.connect(0, 1, -60);
    net.medium.connect(1, 2, -60);
    net.medium.connect(0, 2, -60);
    let ds = dataset(&mut net);
    start(&mut net, 0, &ds);
    assert!(net.run_until(secs(60), |n| role(n, 0) == Role::Leader));
    start(&mut net, 1, &ds);
    assert!(net.run_until(secs(300), |n| role(n, 1) == Role::Router));
    start(&mut net, 2, &ds);
    assert!(net.run_until(secs(300), |n| role(n, 2) == Role::Child));

    // Node 0: Backbone Router service, Domain Prefix, the TMF side.
    let rloc = net.node(0).rloc16();
    let cfg = BbrConfig {
        server16: rloc.0,
        sequence_number: 1,
        reregistration_delay: 5,
        mlr_timeout: 3600,
    };
    let mut p = [0u8; 8];
    p[..4].copy_from_slice(&[0xfd, 0x00, 0xab, 0xcd]);
    let domain = NetPrefix::new(&p, 64).unwrap();
    net.with(0, |n, _| {
        n.set_tmf_extension(&[TmfUri::DuaRegistrationRequest, TmfUri::Mlr], fake_bbr);
        n.add_service(
            ServiceConfig::new(THREAD_ENTERPRISE_NUMBER, &[1], &cfg.server_data(), true).unwrap(),
        )
        .unwrap();
        n.add_on_mesh_prefix(OnMeshPrefixConfig {
            prefix: domain,
            flags: BrFlags::default()
                .with(BrFlags::ON_MESH, true)
                .with(BrFlags::DP, true)
                .with(BrFlags::PREFERRED, true),
            stable: true,
        })
        .unwrap();
    });
    // A multicast group of the child (larger than realm-local).
    let group: Ipv6Addr = "ff05::1234".parse().unwrap();
    net.with(2, |n, _| n.subscribe_multicast(group).unwrap());

    let ok = net.run_until(secs(600), |n| {
        let t = DUA_TARGETS.lock().unwrap();
        let reg = |i: usize, n: &mut Network| {
            n.node(i)
                .domain_unicast_address()
                .is_some_and(|a| t.contains(&a))
        };
        reg(1, n) && reg(2, n) && MLR_GROUPS.lock().unwrap().contains(&group)
    });
    let d1 = net.node(1).domain_unicast_address();
    let d2 = net.node(2).domain_unicast_address();
    assert!(
        ok,
        "dua1 {d1:?} dua2 {d2:?} targets {:?} groups {:?}",
        DUA_TARGETS.lock().unwrap(),
        MLR_GROUPS.lock().unwrap()
    );
    let t = DUA_TARGETS.lock().unwrap();
    assert!(t.contains(&d1.unwrap()), "router DUA registered");
    assert!(
        t.contains(&d2.unwrap()),
        "child DUA registered by its parent"
    );
    assert_eq!(net.node(1).primary_backbone_router(), Some(cfg));
}
