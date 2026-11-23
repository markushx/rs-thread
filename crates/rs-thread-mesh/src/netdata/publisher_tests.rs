//! Publisher tests: several devices publish the same entry against one
//! leader store (the notifier / `/a/sd` path is replaced by registering the
//! encoded local data directly).

use core::net::Ipv6Addr;
use std::vec::Vec;

use rs_thread_core::time::{Duration, Instant};
use rs_thread_core::types::Rloc16;

use super::leader::Leader;
use super::local::*;
use super::notifier::{Notifier, NotifierEvent, UpgradeInput};
use super::publisher::*;
use super::tlv::*;
use super::view::NetworkDataView;
use crate::sim::XRng;

const T0: Instant = Instant::from_secs(1000);

fn prefix() -> NetPrefix {
    NetPrefix::new(&[0xfd, 0, 0xca, 0xfe, 0, 0, 0, 7], 64).unwrap()
}

fn route_prefix() -> NetPrefix {
    NetPrefix::new(&[0x20, 0x01, 0x0d, 0xb8], 32).unwrap()
}

fn on_mesh(pref: i8) -> OnMeshPrefixConfig {
    OnMeshPrefixConfig {
        prefix: prefix(),
        flags: BrFlags::default()
            .with(BrFlags::ON_MESH, true)
            .with(BrFlags::SLAAC, true)
            .with(BrFlags::DEFAULT_ROUTE, true)
            .with_preference(pref),
        stable: true,
    }
}

fn route(pref: i8) -> ExternalRouteConfig {
    ExternalRouteConfig {
        prefix: route_prefix(),
        preference: pref,
        nat64: false,
        adv_pio: false,
        stable: true,
    }
}

struct Dev {
    rloc: u16,
    ml_eid: Ipv6Addr,
    publisher: Publisher<3>,
    local: LocalData<4, 4, 2>,
    events: Vec<PublisherEvent>,
}

impl Dev {
    fn new(rloc: u16) -> Self {
        Self {
            rloc,
            ml_eid: Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, rloc),
            publisher: Publisher::new(),
            local: LocalData::new(),
            events: Vec::new(),
        }
    }
}

struct Net {
    leader: Leader<512>,
    devs: Vec<Dev>,
    rng: XRng,
    now: Instant,
}

impl Net {
    fn new(rlocs: &[u16]) -> Self {
        let mut leader = Leader::new();
        leader.start(1, 1);
        Self {
            leader,
            devs: rlocs.iter().map(|&r| Dev::new(r)).collect(),
            rng: XRng(0x1234_5678_9abc_def1),
            now: T0,
        }
    }

    /// One second: every device polls the publisher, changed local data is
    /// registered at the leader.
    fn step(&mut self) {
        self.now += Duration::from_secs(1);
        for i in 0..self.devs.len() {
            let data = self.leader.data().clone();
            let d = &mut self.devs[i];
            let ctx = PublishContext {
                attached: true,
                router_or_leader: Rloc16(d.rloc).is_router(),
                rloc16: Rloc16(d.rloc),
                leader: data.view(),
                ml_eid: d.ml_eid,
            };
            let Dev {
                publisher,
                local,
                events,
                ..
            } = d;
            publisher.poll(self.now, &ctx, local, &mut self.rng, &mut |e| {
                events.push(e)
            });
            if d.publisher.take_local_changed() {
                let mut buf = [0u8; 256];
                let n = d.local.encode(d.rloc, &mut buf).unwrap();
                self.leader
                    .register(d.rloc, &buf[..n], |_| true, self.now)
                    .unwrap();
            }
        }
    }

    fn run(&mut self, secs: u64) {
        for _ in 0..secs {
            self.step();
        }
    }

    fn on_mesh_count(&self) -> usize {
        self.leader
            .data()
            .view()
            .on_mesh_prefixes()
            .filter(|e| e.prefix == prefix())
            .count()
    }
}

fn publish_on_mesh(net: &mut Net, i: usize, cfg: OnMeshPrefixConfig) {
    let now = net.now;
    let d = &mut net.devs[i];
    let Dev {
        publisher,
        local,
        events,
        ..
    } = d;
    publisher
        .publish_on_mesh_prefix(cfg, local, now, &mut |e| events.push(e))
        .unwrap();
}

#[test]
fn only_the_desired_number_of_entries_stays() {
    // Six border routers publish the same prefix: three entries remain.
    let mut net = Net::new(&[0x0400, 0x0800, 0x0c00, 0x1000, 0x1400, 0x1800]);
    for i in 0..6 {
        publish_on_mesh(&mut net, i, on_mesh(0));
    }
    net.run(120);
    assert_eq!(net.on_mesh_count(), usize::from(DESIRED_NUM_ON_MESH_PREFIX));
    // Stable: no flapping afterwards.
    let v = net.leader.version();
    net.run(120);
    assert_eq!(net.on_mesh_count(), 3);
    assert_eq!(net.leader.version(), v);
    // The added devices know it; the others wait to add.
    let added = net
        .devs
        .iter()
        .filter(|d| d.publisher.is_prefix_added(&prefix()))
        .count();
    assert_eq!(added, 3);
    assert!(
        net.devs
            .iter()
            .filter(|d| !d.publisher.is_prefix_added(&prefix()))
            .all(|d| d.publisher.prefix_state(&prefix()) == Some(EntryState::ToAdd))
    );
}

#[test]
fn a_removed_entry_is_replaced_by_a_waiting_device() {
    let mut net = Net::new(&[0x0400, 0x0800, 0x0c00, 0x1000]);
    for i in 0..4 {
        publish_on_mesh(&mut net, i, on_mesh(0));
    }
    net.run(120);
    assert_eq!(net.on_mesh_count(), 3);
    // One of the publishing devices unpublishes: the waiting one adds its.
    let gone = net
        .devs
        .iter()
        .position(|d| d.publisher.is_prefix_added(&prefix()))
        .unwrap();
    let rloc = net.devs[gone].rloc;
    {
        let d = &mut net.devs[gone];
        let Dev {
            publisher,
            local,
            events,
            ..
        } = d;
        publisher
            .unpublish_prefix(&prefix(), local, &mut |e| events.push(e))
            .unwrap();
        assert!(publisher.take_local_changed());
        assert!(events.contains(&PublisherEvent::PrefixRemoved(prefix())));
    }
    net.leader.register(rloc, &[], |_| true, net.now).unwrap();
    assert_eq!(net.on_mesh_count(), 2);
    net.run(30);
    assert_eq!(net.on_mesh_count(), 3);
}

#[test]
fn higher_preference_entries_push_out_lower_ones() {
    // Entries of a lower preference are not counted by a device with a
    // higher preference, so it publishes even if three others exist.
    let mut net = Net::new(&[0x0400, 0x0800, 0x0c00, 0x1000]);
    for i in 0..3 {
        publish_on_mesh(&mut net, i, on_mesh(-1));
    }
    net.run(60);
    assert_eq!(net.on_mesh_count(), 3);
    publish_on_mesh(&mut net, 3, on_mesh(1));
    net.run(60);
    assert!(net.devs[3].publisher.is_prefix_added(&prefix()));
}

#[test]
fn external_routes_use_their_own_desired_count() {
    let mut net = Net::new(&[0x0400, 0x0800]);
    let now = net.now;
    for d in &mut net.devs {
        let Dev {
            publisher,
            local,
            events,
            ..
        } = d;
        publisher
            .publish_external_route(route(0), local, now, &mut |e| events.push(e))
            .unwrap();
    }
    net.run(30);
    let n = net.leader.data().view().external_routes().count();
    assert_eq!(n, 2);
    // Unstable entries and a full table are refused.
    let mut unstable = route(0);
    unstable.stable = false;
    let d = &mut net.devs[0];
    assert_eq!(
        d.publisher
            .publish_external_route(unstable, &mut d.local, now, &mut |_| {}),
        Err(rs_thread_core::Error::InvalidArgs)
    );
}

#[test]
fn nothing_changes_while_detached() {
    let mut net = Net::new(&[0x0400]);
    publish_on_mesh(&mut net, 0, on_mesh(0));
    let d = &mut net.devs[0];
    let ctx = PublishContext {
        attached: false,
        router_or_leader: true,
        rloc16: Rloc16(0x0400),
        leader: NetworkDataView(&[]),
        ml_eid: Ipv6Addr::LOCALHOST,
    };
    d.publisher.poll(
        T0 + Duration::from_secs(100),
        &ctx,
        &mut d.local,
        &mut net.rng,
        &mut |_| {},
    );
    assert_eq!(d.publisher.prefix_state(&prefix()), Some(EntryState::ToAdd));
    assert!(d.local.is_empty());
}

#[test]
fn dns_srp_anycast_and_unicast_entries() {
    let mut net = Net::new(&[0x0400, 0x0800, 0x0c00]);
    let mls: Vec<Ipv6Addr> = net.devs.iter().map(|d| d.ml_eid).collect();
    let ml = |i: usize| mls[i];
    let now = net.now;
    // Two devices publish the unicast service with the ML-EID, one the
    // anycast one: the ML-EID entries are withdrawn once an anycast entry
    // exists (desired count 0).
    for i in 0..2 {
        let data = net.leader.data().clone();
        let d = &mut net.devs[i];
        let ctx = PublishContext {
            attached: true,
            router_or_leader: true,
            rloc16: Rloc16(d.rloc),
            leader: data.view(),
            ml_eid: ml(i),
        };
        let Dev {
            publisher,
            local,
            events,
            ..
        } = d;
        publisher.publish_dns_srp(
            DnsSrpService::UnicastMlEid {
                port: 53,
                version: 0,
            },
            &ctx,
            local,
            now,
            &mut |e| events.push(e),
        );
    }
    net.run(60);
    let services = |net: &Net| net.leader.data().view().services().count();
    assert_eq!(services(&net), 2);
    {
        let s = net
            .leader
            .data()
            .view()
            .services()
            .find(|s| s.rloc16 == 0x0400)
            .unwrap();
        assert_eq!(s.service_data, [0x5d]);
        assert_eq!(&s.server_data[..16], &ml(0).octets());
        assert_eq!(&s.server_data[16..], &53u16.to_be_bytes());
    }
    let data = net.leader.data().clone();
    let now = net.now;
    {
        let d = &mut net.devs[2];
        let ctx = PublishContext {
            attached: true,
            router_or_leader: true,
            rloc16: Rloc16(d.rloc),
            leader: data.view(),
            ml_eid: ml(2),
        };
        d.publisher.publish_dns_srp(
            DnsSrpService::Anycast {
                sequence_number: 3,
                version: 1,
            },
            &ctx,
            &mut d.local,
            now,
            &mut |_| {},
        );
    }
    net.run(120);
    let svc: Vec<_> = net.leader.data().view().services().collect();
    assert_eq!(svc.len(), 1, "{svc:?}");
    assert_eq!(svc[0].service_data, [0x5c, 3]);
    assert_eq!(svc[0].server_data, [1]);
    assert_eq!(svc[0].rloc16, 0x0c00);
    assert_eq!(net.devs[0].publisher.dns_srp_state(), EntryState::ToAdd);
}

fn ctx_for(data: &super::NetworkData<512>, ml: Ipv6Addr) -> PublishContext<'_> {
    PublishContext {
        attached: true,
        router_or_leader: true,
        rloc16: Rloc16(0x0400),
        leader: data.view(),
        ml_eid: ml,
    }
}

#[test]
fn unicast_with_address_in_service_data_and_ml_eid_change() {
    let mut net = Net::new(&[0x0400]);
    let addr = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 9);

    let data = net.leader.data().clone();
    let now = net.now;
    let d = &mut net.devs[0];
    d.publisher.publish_dns_srp(
        DnsSrpService::Unicast {
            address: addr,
            port: 5353,
            version: 2,
        },
        &ctx_for(&data, Ipv6Addr::LOCALHOST),
        &mut d.local,
        now,
        &mut |_| {},
    );
    net.run(10);
    let svc: Vec<_> = net.leader.data().view().services().collect();
    assert_eq!(svc.len(), 1);
    assert_eq!(svc[0].service_data[0], 0x5d);
    assert_eq!(&svc[0].service_data[1..17], &addr.octets());
    assert_eq!(svc[0].service_data[19], 2);
    assert!(svc[0].server_data.is_empty());

    // Replace by the ML-EID flavour and change the address.
    let data = net.leader.data().clone();
    let now = net.now;
    let new = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0x22);
    let d = &mut net.devs[0];
    d.publisher.publish_dns_srp(
        DnsSrpService::UnicastMlEid {
            port: 53,
            version: 0,
        },
        &ctx_for(&data, Ipv6Addr::LOCALHOST),
        &mut d.local,
        now,
        &mut |_| {},
    );
    assert!(d.publisher.take_local_changed());
    assert!(d.local.services().is_empty());
    // The removal reaches the leader.
    net.leader.register(0x0400, &[], |_| true, net.now).unwrap();
    net.run(10);
    assert_eq!(d_state(&net), EntryState::Added);
    {
        let d = &mut net.devs[0];
        d.publisher
            .mesh_local_eid_changed(new, &mut d.local, &mut |_| {});
        assert!(d.local.services()[0].server_data.starts_with(&new.octets()));
        d.publisher.unpublish_dns_srp(&mut d.local, &mut |_| {});
        assert!(d.local.services().is_empty());
        assert_eq!(d.publisher.dns_srp_state(), EntryState::NoEntry);
    }
}

fn d_state(net: &Net) -> EntryState {
    net.devs[0].publisher.dns_srp_state()
}

// ---------------------------------------------------------------------
// Border Router router role upgrade (notifier)

fn br_data(rlocs: &[u16]) -> Vec<u8> {
    let mut l = Leader::<512>::new();
    l.start(1, 1);
    for &r in rlocs {
        let mut local = LocalData::<4, 4, 2>::new();
        local.add_on_mesh_prefix(on_mesh(0)).unwrap();
        let mut b = [0u8; 128];
        let n = local.encode(r, &mut b).unwrap();
        l.register(r, &b[..n], |_| true, T0).unwrap();
    }
    let mut out = std::vec![0u8; 512];
    let n = l.copy_to(false, &mut out).unwrap();
    out.truncate(n);
    out
}

fn upgrade_input<'a>(
    is_child: bool,
    routers: u8,
    local: &'a [u8],
    leader: &'a [u8],
) -> UpgradeInput<'a> {
    UpgradeInput {
        is_child,
        rloc16: Rloc16(0x0c05),
        local: NetworkDataView(local),
        leader: NetworkDataView(leader),
        active_router_count: routers,
        router_upgrade_threshold: 16,
        max_routers: 32,
    }
}

#[test]
fn border_router_child_asks_for_the_router_role_once() {
    let leader_data = br_data(&[0x0c05]);
    let mut b = [0u8; 128];
    let mut local = LocalData::<4, 4, 2>::new();
    local.add_on_mesh_prefix(on_mesh(0)).unwrap();
    let n = local.encode(0x0c05, &mut b).unwrap();

    let mut rng = XRng(77);
    let mut nt = Notifier::new();
    // Too few routers for the normal upgrade: not eligible below the
    // threshold.
    nt.schedule_router_upgrade(&upgrade_input(true, 5, &b[..n], &leader_data), &mut rng);
    assert!(!nt.router_upgrade_pending());
    // Eligible: a random wait of 1..=10 s, then the request, once.
    nt.schedule_router_upgrade(&upgrade_input(true, 20, &b[..n], &leader_data), &mut rng);
    assert!(nt.router_upgrade_pending());
    let mut ticks = 0;
    while !nt.router_upgrade_tick(&upgrade_input(true, 20, &b[..n], &leader_data)) {
        ticks += 1;
        assert!(ticks < 10);
    }
    nt.schedule_router_upgrade(&upgrade_input(true, 20, &b[..n], &leader_data), &mut rng);
    assert!(!nt.router_upgrade_pending());
    // New local data allows another request.
    nt.event(NotifierEvent::LocalChanged);
    nt.schedule_router_upgrade(&upgrade_input(true, 20, &b[..n], &leader_data), &mut rng);
    assert!(nt.router_upgrade_pending());
    // Not a child any more when the wait is over: no request.
    for _ in 0..10 {
        assert!(!nt.router_upgrade_tick(&upgrade_input(false, 20, &b[..n], &leader_data)));
    }
    // Two Border Routers with router RLOC16s already: not eligible.
    nt.event(NotifierEvent::PartitionChanged);
    let two = br_data(&[0x0c05, 0x0400, 0x0800]);
    nt.schedule_router_upgrade(&upgrade_input(true, 20, &b[..n], &two), &mut rng);
    assert!(!nt.router_upgrade_pending());
}
