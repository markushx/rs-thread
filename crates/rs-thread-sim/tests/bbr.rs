//! The Backbone Router role: service registration, Primary selection, DUA
//! and MLR registrations answered by the Primary Backbone Router.

mod common;

use core::net::Ipv6Addr;

use common::*;
use rs_thread_instance::{BrFlags, NetPrefix, OnMeshPrefixConfig, Role};
use rs_thread_mesh::bbr_server::LocalState;
use rs_thread_sim::{Kind, Network};

fn domain_prefix_config() -> OnMeshPrefixConfig {
    let mut p = [0u8; 8];
    p[..4].copy_from_slice(&[0xfd, 0x00, 0xab, 0xcd]);
    OnMeshPrefixConfig {
        prefix: NetPrefix::new(&p, 64).unwrap(),
        flags: BrFlags::default()
            .with(BrFlags::ON_MESH, true)
            .with(BrFlags::DP, true)
            .with(BrFlags::PREFERRED, true),
        stable: true,
    }
}

/// A device that enables the role before it is attached (and becomes a
/// router after being a child) is the Primary Backbone Router within a few
/// seconds, whatever the registration jitter draws.
#[test]
fn backbone_router_becomes_primary_soon_after_start() {
    for seed in 0..30 {
        let mut net = Network::new(&[Kind::Router, Kind::Router], seed);
        net.medium.connect(0, 1, -60);
        let ds = dataset(&mut net);
        start(&mut net, 0, &ds);
        assert!(net.run_until(secs(60), |n| role(n, 0) == Role::Leader));
        net.with(1, |n, _| {
            n.bbr_server().set_jitter(2);
            n.router_config_mut().selection_jitter_secs = 1;
            n.bbr_set_enabled(true);
        });
        start(&mut net, 1, &ds);
        net.run_for(secs(10));
        assert_eq!(
            net.node(1).bbr_state(),
            LocalState::Primary,
            "seed {seed}: role {:?}",
            role(&mut net, 1)
        );
    }
}

#[test]
fn dua_and_mlr_registration_with_a_backbone_router_role() {
    let mut net = Network::new(&[Kind::Router, Kind::Router, Kind::EndDevice], 6);
    net.medium.connect(0, 1, -60);
    net.medium.connect(1, 2, -60);
    net.medium.connect(0, 2, -60);
    let ds = dataset(&mut net);
    // The role can be enabled before the network is up; the Domain Prefix
    // is in the Network Data only while it is.
    net.with(1, |n, _| {
        n.add_on_mesh_prefix(domain_prefix_config()).unwrap();
        n.bbr_set_enabled(true);
    });
    start(&mut net, 0, &ds);
    assert!(net.run_until(secs(60), |n| role(n, 0) == Role::Leader));
    start(&mut net, 1, &ds);
    assert!(net.run_until(secs(300), |n| role(n, 1) == Role::Router));
    // The service follows the RLOC16 of the device (it was a child first).
    let rloc = net.node(1).rloc16();
    assert!(
        net.run_until(secs(120), |n| {
            n.node(1).bbr_state() == LocalState::Primary
                && n.node(0).primary_backbone_router().map(|c| c.server16) == Some(rloc.0)
        }),
        "state {:?} primary {:?}",
        net.node(1).bbr_state(),
        net.node(0).primary_backbone_router()
    );

    start(&mut net, 2, &ds);
    assert!(net.run_until(secs(300), |n| role(n, 2) == Role::Child));
    let group: Ipv6Addr = "ff05::1234".parse().unwrap();
    net.with(2, |n, _| n.subscribe_multicast(group).unwrap());
    let ok = net.run_until(secs(600), |n| {
        n.node(1).bbr_server().proxies.iter().count() >= 2
            && n.node(1).bbr_server().listeners.iter().count() == 1
    });
    assert!(
        ok,
        "proxies {} listeners {}",
        net.node(1).bbr_server().proxies.iter().count(),
        net.node(1).bbr_server().listeners.iter().count()
    );
    assert!(net.node(0).domain_unicast_address().is_some());

    // Disabling the role takes the service away.
    net.with(1, |n, _| n.bbr_set_enabled(false));
    assert!(net.run_until(secs(60), |n| {
        n.node(0).primary_backbone_router().is_none()
    }));
    assert_eq!(net.node(1).bbr_state(), LocalState::Disabled);
}
