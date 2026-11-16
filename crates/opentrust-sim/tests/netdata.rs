mod common;

use common::*;
use opentrust_instance::{BrFlags, ExternalRouteConfig, NetPrefix, OnMeshPrefixConfig};

fn prefix() -> NetPrefix {
    NetPrefix::new(&[0x20, 0x01, 0x0d, 0xb8, 0, 1, 0, 0], 64).unwrap()
}

fn has_prefix(n: &opentrust_sim::SimInstance) -> bool {
    n.unicast_addresses()
        .any(|a| a.addr.octets()[..8] == [0x20, 0x01, 0x0d, 0xb8, 0, 1, 0, 0])
}

#[test]
fn border_router_prefix_gives_slaac_addresses_everywhere() {
    let mut net = router_chain(21);
    net.with(2, |n, _| {
        n.add_on_mesh_prefix(OnMeshPrefixConfig {
            prefix: prefix(),
            flags: BrFlags(
                BrFlags::PREFERRED | BrFlags::SLAAC | BrFlags::ON_MESH | BrFlags::DEFAULT_ROUTE,
            ),
            stable: true,
        })
        .unwrap();
        n.add_external_route(ExternalRouteConfig {
            prefix: NetPrefix::new(&[0x20, 0x01, 0x0d, 0xb8, 0xff, 0xff], 48).unwrap(),
            preference: 0,
            nat64: false,
            adv_pio: false,
            stable: true,
        })
        .unwrap();
    });
    assert!(
        net.run_until(secs(300), |n| (0..3).all(|i| has_prefix(n.inst(i)))),
        "SLAAC addresses: {:?}",
        (0..3).map(|i| has_prefix(net.inst(i))).collect::<Vec<_>>()
    );
    // The Network Data reached everyone with the on-mesh prefix and route.
    for i in 0..3 {
        let v = net.inst(i).network_data();
        assert_eq!(v.on_mesh_prefixes().count(), 1, "node {i}");
        assert_eq!(v.external_routes().count(), 1, "node {i}");
    }
    // An on-mesh address is resolved with an address query and answered.
    let dst = net
        .inst(1)
        .unicast_addresses()
        .find(|a| a.addr.octets()[..8] == [0x20, 0x01, 0x0d, 0xb8, 0, 1, 0, 0])
        .unwrap()
        .addr;
    assert!(ping(&mut net, 0, dst, 12, 9), "no reply from {dst}");
}

#[test]
fn end_device_registers_its_slaac_address_with_the_parent() {
    use opentrust_core::time::Duration;
    use opentrust_instance::Role;
    use opentrust_sim::{Kind, Network};

    let mut net = Network::new(&[Kind::Router, Kind::EndDevice], 61);
    net.medium.connect(0, 1, -60);
    let ds = dataset(&mut net);
    start(&mut net, 0, &ds);
    assert!(net.run_until(secs(60), |n| role(n, 0) == Role::Leader));
    // The leader is the border router.
    net.with(0, |n, _| {
        n.add_on_mesh_prefix(OnMeshPrefixConfig {
            prefix: prefix(),
            flags: BrFlags(BrFlags::PREFERRED | BrFlags::SLAAC | BrFlags::ON_MESH),
            stable: true,
        })
        .unwrap();
    });
    start(&mut net, 1, &ds);
    assert!(net.run_until(secs(120), |n| role(n, 1) == Role::Child));
    assert!(net.run_until(secs(300), |n| has_prefix(n.inst(1))));
    // The parent learns the new address with a Child Update Request, and
    // delivers to it directly (no address query).
    net.run_for(Duration::from_secs(20));
    let dst = net
        .inst(1)
        .unicast_addresses()
        .find(|a| a.addr.octets()[..8] == [0x20, 0x01, 0x0d, 0xb8, 0, 1, 0, 0])
        .unwrap()
        .addr;
    assert!(ping(&mut net, 0, dst, 12, 3), "no reply from {dst}");
    assert!(net.inst(0).address_cache().next().is_none());
}

#[test]
fn ping_of_a_service_aloc_is_answered() {
    let mut net = router_chain(23);
    net.with(1, |n, _| {
        n.add_service(
            opentrust_mesh::netdata::local::ServiceConfig::new(
                123,
                &[0x01, 0x23],
                &[0x0a, 0xbc],
                true,
            )
            .unwrap(),
        )
        .unwrap();
    });
    net.run_until(secs(30), |_| false);
    let aloc = net
        .inst(1)
        .unicast_addresses()
        .map(|a| a.addr)
        .find(|a| a.octets()[8..14] == [0, 0, 0, 0xff, 0xfe, 0] && a.octets()[14] == 0xfc)
        .expect("service ALOC");
    for from in [0usize, 1, 2] {
        assert!(
            ping(&mut net, from, aloc, 8, 5 + from as u16),
            "ping from {from} to {aloc}"
        );
    }
}
