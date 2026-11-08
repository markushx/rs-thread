//! Leader store tests.

use std::vec::Vec;

use opentrust_core::Error;
use opentrust_core::time::{Duration, Instant};

use super::leader::*;
use super::local::*;
use super::tlv::*;

const T0: Instant = Instant::from_secs(1000);

fn all_routers(_: u8) -> bool {
    true
}

fn prefix(b: &[u8], len: u8) -> NetPrefix {
    NetPrefix::new(b, len).unwrap()
}

fn mesh_prefix() -> NetPrefix {
    prefix(&[0xfd, 0, 0xca, 0xfe, 0, 0, 0, 1], 64)
}

fn route_prefix() -> NetPrefix {
    prefix(&[0x20, 0x01, 0x0d, 0xb8], 32)
}

fn flags() -> BrFlags {
    BrFlags::default()
        .with(BrFlags::PREFERRED, true)
        .with(BrFlags::SLAAC, true)
        .with(BrFlags::ON_MESH, true)
}

fn payload(rloc16: u16, f: impl FnOnce(&mut LocalData)) -> Vec<u8> {
    let mut l = LocalData::<4, 4, 2>::new();
    f(&mut l);
    let mut b = [0u8; 256];
    let n = l.encode(rloc16, &mut b).unwrap();
    b[..n].to_vec()
}

fn on_mesh_payload(rloc16: u16) -> Vec<u8> {
    payload(rloc16, |l| {
        l.add_on_mesh_prefix(OnMeshPrefixConfig {
            prefix: mesh_prefix(),
            flags: flags(),
            stable: true,
        })
        .unwrap()
    })
}

fn route_payload(rloc16: u16, stable: bool, pref: i8) -> Vec<u8> {
    payload(rloc16, |l| {
        l.add_external_route(ExternalRouteConfig {
            prefix: route_prefix(),
            preference: pref,
            nat64: false,
            adv_pio: false,
            stable,
        })
        .unwrap()
    })
}

fn service_payload(rloc16: u16, data: &[u8], stable: bool) -> Vec<u8> {
    payload(rloc16, |l| {
        l.add_service(ServiceConfig::new(THREAD_ENTERPRISE_NUMBER, data, &[1, 2], stable).unwrap())
            .unwrap()
    })
}

fn leader() -> Leader<256> {
    let mut l = Leader::new();
    l.start(10, 20);
    l
}

#[test]
fn register_on_mesh_prefix_allocates_a_context() {
    let mut l = leader();
    let ch = l
        .register(0x0400, &on_mesh_payload(0x0400), all_routers, T0)
        .unwrap();
    assert_eq!(
        ch,
        Changed {
            any: true,
            stable: true
        }
    );
    assert_eq!((l.version(), l.stable_version()), (11, 21));
    let v = l.data().view();
    let e: Vec<_> = v.on_mesh_prefixes().collect();
    assert_eq!(e.len(), 1);
    assert_eq!(
        (e[0].prefix, e[0].rloc16, e[0].stable),
        (mesh_prefix(), 0x0400, true)
    );
    let c: Vec<_> = v.contexts().collect();
    assert_eq!(c.len(), 1);
    assert_eq!(
        (c[0].id, c[0].compress, c[0].prefix, c[0].stable),
        (1, true, mesh_prefix(), true)
    );
}

#[test]
fn unchanged_registration_keeps_versions() {
    let mut l = leader();
    let p = on_mesh_payload(0x0400);
    l.register(0x0400, &p, all_routers, T0).unwrap();
    let before = l.data().clone();
    let ch = l.register(0x0400, &p, all_routers, T0).unwrap();
    assert_eq!(ch, Changed::default());
    assert_eq!((l.version(), l.stable_version()), (11, 21));
    assert_eq!(*l.data(), before);
}

#[test]
fn temporary_data_bumps_only_the_version() {
    let mut l = leader();
    let ch = l
        .register(0x0400, &route_payload(0x0400, false, 0), all_routers, T0)
        .unwrap();
    assert_eq!(
        ch,
        Changed {
            any: true,
            stable: false
        }
    );
    assert_eq!((l.version(), l.stable_version()), (11, 20));
    // A route alone does not need a context.
    assert_eq!(l.data().view().contexts().count(), 0);
    let r: Vec<_> = l.data().view().external_routes().collect();
    assert_eq!((r.len(), r[0].rloc16, r[0].stable), (1, 0x0400, false));
}

#[test]
fn reregistration_replaces_the_entries_of_that_rloc() {
    let mut l = leader();
    l.register(0x0400, &route_payload(0x0400, true, 0), all_routers, T0)
        .unwrap();
    l.register(0x0800, &route_payload(0x0800, true, 1), all_routers, T0)
        .unwrap();
    assert_eq!(l.data().view().external_routes().count(), 2);
    // 0x0400 registers a different preference: only its entry changes.
    let ch = l
        .register(0x0400, &route_payload(0x0400, true, -1), all_routers, T0)
        .unwrap();
    assert!(ch.any && ch.stable);
    let r: Vec<_> = l.data().view().external_routes().collect();
    assert_eq!(r.len(), 2);
    let a = r.iter().find(|e| e.rloc16 == 0x0400).unwrap();
    let b = r.iter().find(|e| e.rloc16 == 0x0800).unwrap();
    assert_eq!((a.preference, b.preference), (-1, 1));
    // Registering nothing removes the rest of 0x0400; the prefix survives.
    l.register(0x0400, &[], all_routers, T0).unwrap();
    let r: Vec<_> = l.data().view().external_routes().collect();
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].rloc16, 0x0800);
    // Removing the last entry removes the Prefix TLV.
    l.register(0x0800, &[], all_routers, T0).unwrap();
    assert!(l.data().is_empty());
}

#[test]
fn two_border_routers_share_prefix_and_context() {
    let mut l = leader();
    l.register(0x0400, &on_mesh_payload(0x0400), all_routers, T0)
        .unwrap();
    l.register(0x0800, &on_mesh_payload(0x0800), all_routers, T0)
        .unwrap();
    let v = l.data().view();
    assert_eq!(v.on_mesh_prefixes().count(), 2);
    assert_eq!(v.prefixes().count(), 1);
    assert_eq!(v.contexts().count(), 1);
    assert_eq!(v.contexts().next().unwrap().id, 1);
}

#[test]
fn context_id_is_reused_only_after_the_delay() {
    let mut l = leader();
    l.register(0x0400, &on_mesh_payload(0x0400), all_routers, T0)
        .unwrap();
    assert_eq!(l.next_deadline(), None);
    // The last border router goes away: compression is switched off but the
    // context stays for the reuse delay.
    let ch = l.remove_rloc(0x0400, MatchMode::Rloc16, T0);
    assert_eq!(
        ch,
        Changed {
            any: true,
            stable: true
        }
    );
    let c: Vec<_> = l.data().view().contexts().collect();
    assert_eq!(c.len(), 1);
    assert!(!c[0].compress);
    assert_eq!(l.next_deadline(), Some(T0 + CONTEXT_ID_REUSE_DELAY));
    // A new prefix cannot take context 1 yet.
    let other = payload(0x0800, |lo| {
        lo.add_on_mesh_prefix(OnMeshPrefixConfig {
            prefix: prefix(&[0xfd, 0, 0xbe, 0xef, 0, 0, 0, 2], 64),
            flags: flags(),
            stable: true,
        })
        .unwrap()
    });
    l.register(0x0800, &other, all_routers, T0).unwrap();
    let ids: Vec<_> = l
        .data()
        .view()
        .contexts()
        .map(|c| (c.id, c.compress))
        .collect();
    assert!(ids.contains(&(2, true)));
    assert!(ids.contains(&(1, false)));
    // Not yet.
    let (v, sv) = (l.version(), l.stable_version());
    assert_eq!(
        l.handle_timer(T0 + CONTEXT_ID_REUSE_DELAY - Duration::from_secs(1)),
        Changed::default()
    );
    assert_eq!((l.version(), l.stable_version()), (v, sv));
    // Delay over: the context disappears, both versions move.
    let ch = l.handle_timer(T0 + CONTEXT_ID_REUSE_DELAY);
    assert!(ch.any && ch.stable);
    assert_eq!(
        (l.version(), l.stable_version()),
        (v.wrapping_add(1), sv.wrapping_add(1))
    );
    let ids: Vec<_> = l.data().view().contexts().map(|c| c.id).collect();
    assert_eq!(ids, [2]);
    assert_eq!(l.next_deadline(), None);
    // ID 1 is allocatable again, and a returning border router revives
    // a pending context instead of allocating.
    let third = payload(0x0c00, |lo| {
        lo.add_on_mesh_prefix(OnMeshPrefixConfig {
            prefix: prefix(&[0xfd, 0, 0x11, 0x11, 0, 0, 0, 3], 64),
            flags: flags(),
            stable: false,
        })
        .unwrap()
    });
    l.register(0x0c00, &third, all_routers, T0).unwrap();
    assert!(l.data().view().contexts().any(|c| c.id == 1));
}

#[test]
fn returning_border_router_cancels_context_removal() {
    let mut l = leader();
    l.register(0x0400, &on_mesh_payload(0x0400), all_routers, T0)
        .unwrap();
    l.remove_rloc(0x0400, MatchMode::Rloc16, T0);
    assert!(l.next_deadline().is_some());
    l.register(0x0800, &on_mesh_payload(0x0800), all_routers, T0)
        .unwrap();
    let c: Vec<_> = l.data().view().contexts().collect();
    assert_eq!((c.len(), c[0].id, c[0].compress), (1, 1, true));
    assert_eq!(l.next_deadline(), None);
}

#[test]
fn context_ids_run_out() {
    let mut l: Leader<1024> = Leader::new();
    l.start(0, 0);
    for i in 0..15u8 {
        let rloc = 0x0400 + u16::from(i) * 0x400;
        let p = payload(rloc, |lo| {
            lo.add_on_mesh_prefix(OnMeshPrefixConfig {
                prefix: prefix(&[0xfd, i, 0, 0, 0, 0, 0, 0], 64),
                flags: flags(),
                stable: true,
            })
            .unwrap()
        });
        l.register(rloc, &p, all_routers, T0).unwrap();
    }
    assert_eq!(l.data().view().contexts().count(), 15);
    let before = l.data().clone();
    let extra = payload(0x4000, |lo| {
        lo.add_on_mesh_prefix(OnMeshPrefixConfig {
            prefix: prefix(&[0xfd, 0xff, 0, 0, 0, 0, 0, 0], 64),
            flags: flags(),
            stable: true,
        })
        .unwrap()
    });
    assert_eq!(
        l.register(0x4000, &extra, all_routers, T0),
        Err(Error::NoBufs)
    );
    assert_eq!(*l.data(), before);
}

#[test]
fn service_ids_are_allocated_and_shared_by_servers() {
    let mut l = leader();
    l.register(
        0x0400,
        &service_payload(0x0400, &[0x5d], true),
        all_routers,
        T0,
    )
    .unwrap();
    l.register(
        0x0800,
        &service_payload(0x0800, &[0x5d], true),
        all_routers,
        T0,
    )
    .unwrap();
    l.register(
        0x0800,
        &{
            let mut p = service_payload(0x0800, &[0x5d], true);
            p.extend(service_payload(0x0800, &[0x5e], false));
            p
        },
        all_routers,
        T0,
    )
    .unwrap();
    let s: Vec<_> = l.data().view().services().collect();
    assert_eq!(s.len(), 3);
    let id_5d = s
        .iter()
        .find(|e| e.service_data == [0x5d] && e.rloc16 == 0x0400)
        .unwrap()
        .service_id;
    assert!(
        s.iter()
            .filter(|e| e.service_data == [0x5d])
            .all(|e| e.service_id == id_5d)
    );
    let e5e = s.iter().find(|e| e.service_data == [0x5e]).unwrap();
    assert_ne!(e5e.service_id, id_5d);
    assert!(!e5e.stable);
    // Dropping the service of 0x0800 keeps the other server.
    l.register(0x0800, &[], all_routers, T0).unwrap();
    assert_eq!(l.data().view().services().count(), 1);
}

#[test]
fn rejects_invalid_registrations() {
    let mut l = leader();
    let p = on_mesh_payload(0x0400);
    // RLOC16 inside the entries differs from the registering RLOC16.
    assert_eq!(l.register(0x0800, &p, all_routers, T0), Err(Error::Parse));
    // Router ID not allocated.
    assert_eq!(
        l.register(0x0400, &p, |id| id != 1, T0),
        Err(Error::NotFound)
    );
    // Malformed.
    assert_eq!(
        l.register(0x0400, &p[..p.len() - 1], all_routers, T0),
        Err(Error::Parse)
    );
    // Duplicate prefix.
    let mut dup = p.clone();
    dup.extend_from_slice(&p);
    assert_eq!(l.register(0x0400, &dup, all_routers, T0), Err(Error::Parse));
    // Prefix without Border Router / Has Route.
    let mut b = [0u8; 32];
    let mut w = opentrust_core::bytes::Writer::new(&mut b);
    write_prefix(&mut w, true, 0, &mesh_prefix(), |w| {
        write_context(w, true, 3, true, 64)
    })
    .unwrap();
    let n = w.len();
    assert_eq!(
        l.register(0x0400, &b[..n], all_routers, T0),
        Err(Error::Parse)
    );
    assert!(l.data().is_empty());
    assert_eq!((l.version(), l.stable_version()), (10, 20));
}

#[test]
fn removing_unallocated_router_ids_clears_their_entries() {
    let mut l = leader();
    l.register(0x0400, &on_mesh_payload(0x0400), all_routers, T0)
        .unwrap();
    l.register(0x0800, &route_payload(0x0800, true, 0), all_routers, T0)
        .unwrap();
    // A child of router 2 (0x0801) registered too.
    l.register(
        0x0801,
        &service_payload(0x0801, &[1], true),
        all_routers,
        T0,
    )
    .unwrap();
    let v = l.version();
    // Router 2 is released: its own and its children's entries go.
    let ch = l.remove_stale_router_ids(|id| id != 2, T0);
    assert!(ch.any && ch.stable);
    let d = l.data().view();
    assert_eq!(d.external_routes().count(), 0);
    assert_eq!(d.services().count(), 0);
    assert_eq!(d.on_mesh_prefixes().count(), 1);
    assert_ne!(l.version(), v);
    // Nothing left to do.
    assert_eq!(
        l.remove_stale_router_ids(|id| id != 2, T0),
        Changed::default()
    );
}

#[test]
fn start_resets_everything() {
    let mut l = leader();
    l.register(0x0400, &on_mesh_payload(0x0400), all_routers, T0)
        .unwrap();
    l.start(7, 8);
    assert!(l.data().is_empty());
    assert_eq!((l.version(), l.stable_version()), (7, 8));
    assert_eq!(l.next_deadline(), None);
    l.register(0x0400, &on_mesh_payload(0x0400), all_routers, T0)
        .unwrap();
    assert_eq!(l.data().view().contexts().next().unwrap().id, 1);
}

#[test]
fn stable_copy_of_leader_data_masks_rlocs() {
    let mut l = leader();
    l.register(0x0400, &on_mesh_payload(0x0400), all_routers, T0)
        .unwrap();
    l.register(0x0800, &route_payload(0x0800, false, 0), all_routers, T0)
        .unwrap();
    let mut out = [0u8; 256];
    let n = l.copy_to(true, &mut out).unwrap();
    let s = super::NetworkDataView(&out[..n]);
    assert_eq!(s.external_routes().count(), 0);
    assert!(
        s.on_mesh_prefixes()
            .all(|e| e.rloc16 == 0xfffe || e.rloc16 & 0xfc00 == 0xfc00)
    );
    let m = l.copy_to(false, &mut out).unwrap();
    assert_eq!(&out[..m], l.data().as_bytes());
}

#[test]
fn commissioning_data_set_replace_remove() {
    let mut l = Leader::<256>::new();
    l.start(3, 7);
    let ch = l.set_commissioning_data(&[9, 2, 0x04, 0x00]).unwrap();
    assert!(ch.any && !ch.stable);
    assert_eq!((l.version(), l.stable_version()), (4, 7));
    assert_eq!(l.commissioning_data(), Some(&[9, 2, 0x04, 0x00][..]));
    // The TLV is not stable.
    let mut out = [0u8; 64];
    assert_eq!(l.copy_to(true, &mut out).unwrap(), 0);
    assert_eq!(l.copy_to(false, &mut out).unwrap(), 6);
    // Replacing keeps other TLVs and moves it last.
    l.set_commissioning_data(&[11, 2, 0, 5]).unwrap();
    assert_eq!(l.commissioning_data(), Some(&[11, 2, 0, 5][..]));
    assert_eq!(l.version(), 5);
    // Empty removes it.
    l.set_commissioning_data(&[]).unwrap();
    assert_eq!(l.commissioning_data(), None);
    assert_eq!(l.version(), 6);
    // Too big: unchanged.
    let big = [0u8; 255];
    assert!(l.set_commissioning_data(&big).is_err());
    assert_eq!(l.version(), 6);
    let ch = l.increment_version_and_stable();
    assert!(ch.stable);
    assert_eq!((l.version(), l.stable_version()), (7, 8));
}
