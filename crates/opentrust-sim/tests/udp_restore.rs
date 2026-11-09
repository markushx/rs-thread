mod common;

use core::net::{Ipv6Addr, SocketAddrV6};

use common::*;
use opentrust_instance::{Event, Role, UdpSendOpts};

#[test]
fn udp_ping_pong_across_the_mesh() {
    let mut net = router_chain(31);
    let port = 4321;
    let sock0 = net
        .node(0)
        .udp_open()
        .and_then(|s| {
            net.node(0)
                .udp_bind(s, SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, port, 0, 0))?;
            Ok(s)
        })
        .unwrap();
    let sock2 = net.node(2).udp_open().unwrap();
    net.node(2)
        .udp_bind(sock2, SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, port, 0, 0))
        .unwrap();

    // Node 0 -> node 2 (ML-EID: address resolution on the way).
    let dst2 = net.node(2).ml_eid();
    net.with(0, |n, now| {
        n.udp_send_to(
            sock0,
            SocketAddrV6::new(dst2, port, 0, 0),
            b"ping",
            &UdpSendOpts::default(),
            now,
        )
        .unwrap();
    });
    assert!(net.run_until(secs(30), |n| {
        n.nodes[2]
            .events
            .iter()
            .any(|e| matches!(e, Event::UdpReadable(_)))
    }));
    let mut buf = [0u8; 64];
    let rx = net.node(2).udp_recv(sock2, &mut buf).unwrap().unwrap();
    assert_eq!(&buf[..rx.len], b"ping");
    assert_eq!(*rx.meta.peer.ip(), net.node(0).ml_eid());
    assert!(rx.meta.link_security);

    // And back.
    net.with(2, |n, now| {
        n.udp_send_to(sock2, rx.meta.peer, b"pong", &UdpSendOpts::default(), now)
            .unwrap();
    });
    assert!(net.run_until(secs(30), |n| {
        n.node(0).udp_recv(sock0, &mut buf).unwrap().is_some()
    }));
    assert_eq!(&buf[..4], b"pong");
}

#[test]
fn restarted_leader_restores_its_role_from_settings() {
    let mut net = router_chain(41);
    let partition = net.node(0).partition_id();
    let rloc0 = net.node(0).rloc16();
    // Let the settings catch up (counters are stored ahead).
    net.run_for(secs(60));

    net.reset_node(0);
    assert_eq!(net.node(0).role(), Role::Disabled);
    net.with(0, |n, now| {
        n.ip6_set_enabled(true);
        n.thread_start(now).unwrap();
    });
    assert!(
        net.run_until(secs(300), |n| n.node(0).role() == Role::Leader),
        "role after restart: {:?}",
        net.node(0).role()
    );
    assert_eq!(net.node(0).rloc16(), rloc0);
    assert_eq!(net.node(0).partition_id(), partition);
    // The others never left the partition and the mesh still carries traffic.
    assert_eq!(net.node(1).partition_id(), partition);
    assert_eq!(net.node(2).partition_id(), partition);
    let dst = net.node(2).rloc().unwrap();
    let r2 = net.node(2).rloc16();
    // The routes of the restored router converge over advertisements.
    assert!(net.run_until(secs(600), |n| {
        n.inst(0).mle().next_hop_and_path_cost(r2).0.is_some()
    }));
    assert!(ping(&mut net, 0, dst, 8, 77), "no ping after the restart");
}
