mod common;

use core::net::{Ipv6Addr, SocketAddrV6};

use common::*;
use rs_thread_core::types::{Prefix64, Pskc};
use rs_thread_instance::{Dataset, Event, Role, UdpSendOpts};
use rs_thread_sim::{Kind, Network};

/// The dataset of a restarted border router that ran `dataset init new`
/// again: same key, channel, PAN ID, ext PAN ID and timestamp, but a new
/// mesh-local prefix and PSKc.
fn renewed(ds: &Dataset) -> Dataset {
    let mut d = ds.clone();
    d.set_mesh_local_prefix(&Prefix64([0xfd, 0x51, 0xc0, 0x17, 0xfa, 0x9d, 0, 0]))
        .unwrap();
    d.set_pskc(&Pskc([0x77; 16])).unwrap();
    d
}

/// Node 0 leads dataset A with node 1 attached (as `kind`); then the whole
/// network goes down, node 2 starts as leader of A' on the same channel and
/// node 1 reboots with its stored network information.
fn run(kind: Kind, want_router_first: bool) -> Network {
    let mut net = Network::new(&[Kind::Router, kind, Kind::Router], 7);
    net.medium.connect(0, 1, -60);
    net.medium.connect(1, 2, -60);
    let a = dataset(&mut net);
    start(&mut net, 0, &a);
    assert!(net.run_until(secs(60), |n| role(n, 0) == Role::Leader));
    start(&mut net, 1, &a);
    assert!(net.run_until(secs(120), |n| role(n, 1) == Role::Child));
    if want_router_first {
        assert!(net.run_until(secs(300), |n| role(n, 1) == Role::Router));
    }
    net.run_for(secs(60));
    net.with(0, |n, _| n.thread_stop());
    net.with(1, |n, _| n.thread_stop());
    net.reset_node(1);
    let b = renewed(&a);
    start(&mut net, 2, &b);
    assert!(net.run_until(secs(60), |n| role(n, 2) == Role::Leader));
    net.with(1, |n, now| {
        n.ip6_set_enabled(true);
        n.thread_start(now).unwrap();
    });
    net
}

#[test]
fn restored_child_attaches_to_leader_with_renewed_dataset() {
    let mut net = run(Kind::EndDevice, false);
    assert!(
        net.run_until(secs(60), |n| role(n, 1) == Role::Child),
        "role {:?}",
        net.node(1).role()
    );
    assert_eq!(net.node(1).partition_id(), net.node(2).partition_id());
}

#[test]
fn restored_router_attaches_to_leader_with_renewed_dataset() {
    let mut net = run(Kind::Router, true);
    assert!(
        net.run_until(secs(60), |n| matches!(
            role(n, 1),
            Role::Child | Role::Router
        )),
        "role {:?}",
        net.node(1).role()
    );
    assert_eq!(net.node(1).partition_id(), net.node(2).partition_id());
}

/// With a mesh-local prefix that differs from the parent's, the Address
/// Queries of an FTD child are dropped by the leader (their source is not
/// mesh-local there). Datagrams to on-mesh addresses then go through the
/// parent, as for an MTD child.
#[test]
fn child_with_a_renewed_prefix_reaches_on_mesh_addresses_via_its_parent() {
    use rs_thread_instance::{BrFlags, NetPrefix, OnMeshPrefixConfig};
    let mut net = run(Kind::Router, false);
    let mut p = [0u8; 8];
    p[..4].copy_from_slice(&[0xfd, 0x11, 0x00, 0x69]);
    net.with(2, |n, _| {
        n.add_on_mesh_prefix(OnMeshPrefixConfig {
            prefix: NetPrefix::new(&p, 64).unwrap(),
            flags: BrFlags::default()
                .with(BrFlags::ON_MESH, true)
                .with(BrFlags::SLAAC, true)
                .with(BrFlags::PREFERRED, true)
                .with(BrFlags::DEFAULT_ROUTE, true),
            stable: true,
        })
        .unwrap();
    });
    assert!(net.run_until(secs(60), |n| role(n, 1) == Role::Child));
    let omr = |net: &mut Network, i: usize| {
        net.node(i)
            .unicast_addresses()
            .map(|u| u.addr)
            .find(|a| a.octets()[..4] == [0xfd, 0x11, 0x00, 0x69])
    };
    assert!(net.run_until(secs(120), |n| omr(n, 1).is_some() && omr(n, 2).is_some()));
    let dst = omr(&mut net, 2).unwrap();
    // A datagram from the child to the leader's OMR address (the reverse
    // direction needs the leader to resolve the child, which an FTD child
    // with another mesh-local prefix does not answer either).
    let port = 4321;
    let rx = net.node(2).udp_open().unwrap();
    net.node(2)
        .udp_bind(rx, SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, port, 0, 0))
        .unwrap();
    let tx = net.node(1).udp_open().unwrap();
    let mut got = false;
    for _ in 0..8 {
        if role(&mut net, 1) != Role::Child {
            break;
        }
        net.with(1, |n, now| {
            n.udp_send_to(
                tx,
                SocketAddrV6::new(dst, port, 0, 0),
                b"hello",
                &UdpSendOpts::default(),
                now,
            )
            .unwrap();
        });
        if net.run_until(secs(20), |n| {
            n.nodes[2]
                .events
                .iter()
                .any(|e| matches!(e, Event::UdpReadable(_)))
        }) {
            got = true;
            break;
        }
    }
    assert!(got, "no datagram at the leader");
    let mut buf = [0u8; 16];
    let r = net.node(2).udp_recv(rx, &mut buf).unwrap().unwrap();
    assert_eq!(&buf[..r.len], b"hello");
}
