//! Local data and notifier tests.

use opentrust_core::time::{Duration, Instant};
use opentrust_core::types::Rloc16;

use super::local::*;
use super::notifier::*;
use super::tlv::*;
use super::view::NetworkDataView;

const T0: Instant = Instant::from_secs(100);

fn local_with_route() -> LocalData {
    let mut l = LocalData::new();
    l.add_external_route(ExternalRouteConfig {
        prefix: NetPrefix::new(&[0x20, 1, 0xd, 0xb8], 32).unwrap(),
        preference: 1,
        nat64: false,
        adv_pio: false,
        stable: true,
    })
    .unwrap();
    l
}

fn input<'a>(rloc: u16, local: &'a [u8], leader: &'a [u8], stale: Option<Rloc16>) -> SyncInput<'a> {
    SyncInput {
        attached: true,
        router_or_leader: true,
        expected_to_become_router: false,
        rloc16: Rloc16(rloc),
        local: NetworkDataView(local),
        leader: NetworkDataView(leader),
        stale_child: stale,
    }
}

#[test]
fn local_data_encoding() {
    let mut l = local_with_route();
    l.add_on_mesh_prefix(OnMeshPrefixConfig {
        prefix: NetPrefix::new(&[0xfd, 0, 0, 0, 0, 0, 0, 1], 64).unwrap(),
        flags: BrFlags::default().with(BrFlags::ON_MESH, true),
        stable: false,
    })
    .unwrap();
    l.add_service(ServiceConfig::new(THREAD_ENTERPRISE_NUMBER, &[0x5d], &[9], true).unwrap())
        .unwrap();
    let mut b = [0u8; 128];
    let n = l.encode(0x0c00, &mut b).unwrap();
    let v = NetworkDataView(&b[..n]);
    assert_eq!(v.external_routes().count(), 1);
    assert_eq!(v.on_mesh_prefixes().count(), 1);
    assert_eq!(v.services().count(), 1);
    assert!(
        v.external_routes()
            .all(|e| e.rloc16 == 0x0c00 && e.preference == 1)
    );
    assert!(
        v.services()
            .all(|e| e.rloc16 == 0x0c00 && e.server_data == [9])
    );
    assert!(contains_entries_from(&v, &v, 0x0c00));
    assert!(contains_entries_from(
        &NetworkDataView(&[]),
        &NetworkDataView(&[]),
        0x0c00
    ));
    assert!(!contains_entries_from(&NetworkDataView(&[]), &v, 0x0c00));
    // Entries of other RLOC16s are not considered.
    assert!(contains_entries_from(&NetworkDataView(&[]), &v, 0x1000));
    l.remove_external_route(&NetPrefix::new(&[0x20, 1, 0xd, 0xb8], 32).unwrap())
        .unwrap();
    assert!(
        l.remove_external_route(&NetPrefix::new(&[0x20], 8).unwrap())
            .is_err()
    );
    assert_eq!(l.external_routes().len(), 0);
}

#[test]
fn notifier_sends_registers_and_rechecks() {
    let mut n = Notifier::new();
    let mut b = [0u8; 64];
    let len = local_with_route().encode(0x0400, &mut b).unwrap();
    let local = &b[..len];
    // Nothing happens before an event.
    assert_eq!(n.poll(T0, &input(0x0400, local, &[], None)), None);
    n.event(NotifierEvent::LocalChanged);
    let req = n.poll(T0, &input(0x0400, local, &[], None)).unwrap();
    assert_eq!(
        req,
        ServerDataRequest {
            old_rloc16: None,
            include_local: true
        }
    );
    // No second request while waiting.
    n.event(NotifierEvent::NetworkDataChanged);
    assert_eq!(n.poll(T0, &input(0x0400, local, &[], None)), None);
    // Acknowledged: re-check in 300 s; consistent now.
    n.response(T0, true);
    assert_eq!(
        n.next_deadline(),
        Some(T0 + DELAY_SYNCHRONIZE_SERVER_DATA + Duration::from_millis(1))
    );
    n.event(NotifierEvent::NetworkDataChanged);
    assert_eq!(n.poll(T0, &input(0x0400, local, local, None)), None);
    // The leader lost our data: the periodic check registers it again.
    let t = T0 + DELAY_SYNCHRONIZE_SERVER_DATA + Duration::from_secs(1);
    assert_eq!(
        n.poll(t, &input(0x0400, local, &[], None))
            .map(|r| r.include_local),
        Some(true)
    );
}

#[test]
fn notifier_retries_after_timeout_and_reports_old_rloc() {
    let mut n = Notifier::new();
    let mut b = [0u8; 64];
    let len = local_with_route().encode(0x0400, &mut b).unwrap();
    let local = &b[..len];
    n.event(NotifierEvent::LocalChanged);
    assert!(n.poll(T0, &input(0x0400, local, &[], None)).is_some());
    n.response(T0, false);
    assert!(n.has_pending_work());
    // The retry is sent at once, now with the RLOC16 we already used.
    let mut b2 = [0u8; 64];
    let len2 = local_with_route().encode(0x0800, &mut b2).unwrap();
    let r = n.poll(T0, &input(0x0800, &b2[..len2], &[], None)).unwrap();
    assert_eq!(r.old_rloc16, Some(Rloc16(0x0400)));
}

#[test]
fn notifier_removes_stale_children_first() {
    let mut n = Notifier::new();
    n.event(NotifierEvent::ChildRemoved);
    let r = n
        .poll(T0, &input(0x0400, &[], &[], Some(Rloc16(0x0402))))
        .unwrap();
    assert_eq!(
        r,
        ServerDataRequest {
            old_rloc16: Some(Rloc16(0x0402)),
            include_local: false
        }
    );
    n.response(T0, true);
    // Re-check after 5 s.
    assert_eq!(
        n.next_deadline(),
        Some(T0 + DELAY_REMOVE_STALE_CHILDREN + Duration::from_millis(1))
    );
}

#[test]
fn notifier_waits_while_detached_or_upgrading() {
    let mut n = Notifier::new();
    n.event(NotifierEvent::LocalChanged);
    let mut i = input(0x0400, &[], &[], None);
    i.attached = false;
    assert_eq!(n.poll(T0, &i), None);
    n.event(NotifierEvent::LocalChanged);
    let mut b = [0u8; 64];
    let len = local_with_route().encode(0x0400, &mut b).unwrap();
    let mut i = input(0x0400, &b[..len], &[], None);
    i.expected_to_become_router = true;
    assert_eq!(n.poll(T0, &i), None);
    assert_eq!(n.next_deadline(), Some(T0 + DELAY_ROUTER_TRANSITION));
    i.expected_to_become_router = false;
    assert!(n.poll(T0 + DELAY_ROUTER_TRANSITION, &i).is_some());
}
