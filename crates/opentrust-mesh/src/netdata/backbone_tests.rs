//! Backbone Router client view: Primary Backbone Router selection and
//! events, Domain Prefix events.

use super::backbone::*;
use super::local::{LocalData, OnMeshPrefixConfig, ServiceConfig};
use super::tlv::{BrFlags, NetPrefix, THREAD_ENTERPRISE_NUMBER};
use super::view::NetworkDataView;

const LEADER: u16 = 0x0000;

fn cfg(server16: u16, seq: u8, delay: u16, timeout: u32) -> BbrConfig {
    BbrConfig {
        server16,
        sequence_number: seq,
        reregistration_delay: delay,
        mlr_timeout: timeout,
    }
}

/// Network Data holding the given BBR servers (each as served by its own
/// RLOC16) and an optional Domain Prefix.
fn data(bbrs: &[BbrConfig], dp: Option<NetPrefix>) -> std::vec::Vec<u8> {
    let mut out = std::vec::Vec::new();
    for b in bbrs {
        let mut l: LocalData = LocalData::new();
        l.add_service(
            ServiceConfig::new(
                THREAD_ENTERPRISE_NUMBER,
                &[BACKBONE_ROUTER_SERVICE_NUMBER],
                &b.server_data(),
                true,
            )
            .unwrap(),
        )
        .unwrap();
        let mut buf = [0u8; 128];
        let n = l.encode(b.server16, &mut buf).unwrap();
        out.extend_from_slice(&buf[..n]);
    }
    if let Some(p) = dp {
        let mut l: LocalData = LocalData::new();
        l.add_on_mesh_prefix(OnMeshPrefixConfig {
            prefix: p,
            flags: BrFlags::default()
                .with(BrFlags::ON_MESH, true)
                .with(BrFlags::DP, true),
            stable: true,
        })
        .unwrap();
        let mut buf = [0u8; 128];
        let n = l.encode(0x0400, &mut buf).unwrap();
        out.extend_from_slice(&buf[..n]);
    }
    out
}

fn dp() -> NetPrefix {
    NetPrefix::new(&[0xfd, 0, 0xca, 0xfe, 0, 0, 0, 0], 64).unwrap()
}

#[test]
fn server_data_roundtrip() {
    let c = cfg(0x0800, 7, 5, 3600);
    assert_eq!(c.server_data(), [7, 0, 5, 0, 0, 0x0e, 0x10]);
    assert_eq!(
        BbrConfig::from_server_data(0x0800, &c.server_data()),
        Some(c)
    );
    // Extra bytes are ignored, short data is not a Backbone Router.
    let mut long = [0u8; 9];
    long[..7].copy_from_slice(&c.server_data());
    assert_eq!(BbrConfig::from_server_data(0x0800, &long), Some(c));
    assert_eq!(BbrConfig::from_server_data(0x0800, &long[..6]), None);
}

#[test]
fn primary_selection() {
    let a = cfg(0x0800, 3, 5, 3600);
    let b = cfg(0x0c00, 3, 5, 3600);
    let c = cfg(0x1000, 2, 5, 3600);
    let d = data(&[a, b, c], None);
    // Same sequence number: higher RLOC16 wins.
    assert_eq!(
        primary_backbone_router(&NetworkDataView(&d), LEADER),
        Some(b)
    );
    // Higher sequence number wins over a higher RLOC16.
    let hi = cfg(0x0400, 9, 5, 3600);
    let d = data(&[a, b, hi], None);
    assert_eq!(
        primary_backbone_router(&NetworkDataView(&d), LEADER),
        Some(hi)
    );
    // The BBR on the leader wins over everything.
    let on_leader = cfg(0x0000, 0, 5, 3600);
    let d = data(&[a, hi, on_leader], None);
    assert_eq!(
        primary_backbone_router(&NetworkDataView(&d), LEADER),
        Some(on_leader)
    );
    assert_eq!(primary_backbone_router(&NetworkDataView(&[]), LEADER), None);
}

#[test]
fn other_services_are_ignored() {
    let mut l: LocalData = LocalData::new();
    // Wrong enterprise number, wrong service number.
    l.add_service(ServiceConfig::new(1234, &[1], &[0; 7], true).unwrap())
        .unwrap();
    l.add_service(ServiceConfig::new(THREAD_ENTERPRISE_NUMBER, &[0x5d], &[0; 7], true).unwrap())
        .unwrap();
    let mut buf = [0u8; 128];
    let n = l.encode(0x0800, &mut buf).unwrap();
    assert_eq!(
        primary_backbone_router(&NetworkDataView(&buf[..n]), LEADER),
        None
    );
    // Server data too short.
    let mut l: LocalData = LocalData::new();
    l.add_service(ServiceConfig::new(THREAD_ENTERPRISE_NUMBER, &[1], &[0; 6], true).unwrap())
        .unwrap();
    let n = l.encode(0x0800, &mut buf).unwrap();
    assert_eq!(
        primary_backbone_router(&NetworkDataView(&buf[..n]), LEADER),
        None
    );
}

#[test]
fn state_transitions() {
    let mut l = BackboneRouterLeader::new();
    let a = cfg(0x0800, 1, 5, 3600);
    let none = data(&[], None);
    let with_a = data(&[a], None);

    assert_eq!(
        l.update_primary(&NetworkDataView(&none), LEADER),
        BbrState::None
    );
    assert!(!l.has_primary());
    assert_eq!(
        l.update_primary(&NetworkDataView(&with_a), LEADER),
        BbrState::Added
    );
    assert_eq!(l.config(), Some(&a));
    assert_eq!(
        l.update_primary(&NetworkDataView(&with_a), LEADER),
        BbrState::Unchanged
    );
    // Sequence number change and RLOC16 change trigger reregistration.
    let seq = data(&[cfg(0x0800, 2, 5, 3600)], None);
    assert_eq!(
        l.update_primary(&NetworkDataView(&seq), LEADER),
        BbrState::ToTriggerRereg
    );
    let moved = data(&[cfg(0x0c00, 2, 5, 3600)], None);
    assert_eq!(
        l.update_primary(&NetworkDataView(&moved), LEADER),
        BbrState::ToTriggerRereg
    );
    // Delay / timeout change only refreshes.
    let delay = data(&[cfg(0x0c00, 2, 9, 3600)], None);
    assert_eq!(
        l.update_primary(&NetworkDataView(&delay), LEADER),
        BbrState::Refreshed
    );
    let timeout = data(&[cfg(0x0c00, 2, 9, 7200)], None);
    assert_eq!(
        l.update_primary(&NetworkDataView(&timeout), LEADER),
        BbrState::Refreshed
    );
    assert_eq!(l.config().unwrap().mlr_timeout, 7200);
    assert_eq!(
        l.update_primary(&NetworkDataView(&none), LEADER),
        BbrState::Removed
    );
    assert!(!l.has_primary());
}

#[test]
fn mlr_timeout_is_clamped() {
    let mut l = BackboneRouterLeader::new();
    let d = data(&[cfg(0x0800, 1, 5, 10)], None);
    l.update_primary(&NetworkDataView(&d), LEADER);
    assert_eq!(l.config().unwrap().mlr_timeout, MIN_MLR_TIMEOUT);
    let d = data(&[cfg(0x0800, 1, 5, u32::MAX)], None);
    l.update_primary(&NetworkDataView(&d), LEADER);
    assert_eq!(l.config().unwrap().mlr_timeout, MAX_MLR_TIMEOUT);
}

#[test]
fn domain_prefix_events() {
    let mut l = BackboneRouterLeader::new();
    let none = data(&[], None);
    let with = data(&[], Some(dp()));
    let other = data(
        &[],
        Some(NetPrefix::new(&[0xfd, 0, 0xbe, 0xef, 0, 0, 0, 0], 64).unwrap()),
    );
    assert_eq!(
        l.update_domain_prefix(&NetworkDataView(&none)),
        DomainPrefixEvent::None
    );
    assert_eq!(
        l.update_domain_prefix(&NetworkDataView(&with)),
        DomainPrefixEvent::Added
    );
    assert!(l.has_domain_prefix());
    assert_eq!(l.domain_prefix(), Some(&dp()));
    assert!(l.is_domain_unicast(&"fd00:cafe::1234".parse().unwrap()));
    assert!(!l.is_domain_unicast(&"fd00:beef::1".parse().unwrap()));
    assert_eq!(
        l.update_domain_prefix(&NetworkDataView(&with)),
        DomainPrefixEvent::Unchanged
    );
    assert_eq!(
        l.update_domain_prefix(&NetworkDataView(&other)),
        DomainPrefixEvent::Refreshed
    );
    assert_eq!(
        l.update_domain_prefix(&NetworkDataView(&none)),
        DomainPrefixEvent::Removed
    );
    assert!(!l.is_domain_unicast(&"fd00:beef::1".parse().unwrap()));
}

#[test]
fn service_id_and_update_pair() {
    let mut l = BackboneRouterLeader::new();
    let a = cfg(0x0800, 1, 5, 3600);
    let d = data(&[a], Some(dp()));
    let v = NetworkDataView(&d);
    assert_eq!(backbone_router_service_id(&v), Some(0));
    assert_eq!(
        l.update(&v, LEADER),
        (BbrState::Added, DomainPrefixEvent::Added)
    );
    l.reset();
    assert!(!l.has_primary() && !l.has_domain_prefix());
}
