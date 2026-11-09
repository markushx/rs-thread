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
