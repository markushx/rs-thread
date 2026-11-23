#![cfg(feature = "edge-nal")]

mod common;

use core::cell::Cell;
use core::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6};

use common::*;
use edge_nal::{
    MulticastV6, Readable, UdpBind, UdpConnect, UdpReceive, UdpSend, UdpSplit, UdpSplitMulticast,
};
use embassy_futures::join::join;
use rs_thread_core::time::Duration;
use rs_thread_embassy::{EdgeError, UdpStack};
use rs_thread_instance::Role;

async fn wait_role(ot: Ot<'_, '_>, role: Role) {
    loop {
        let g = ot.generation();
        if ot.role() == role {
            return;
        }
        ot.wait_changed_after(g).await;
    }
}

/// Round trip through the generic traits only.
async fn server<S: UdpBind>(stack: &S, port: u16) {
    let any = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, port, 0, 0));
    let mut sock = stack.bind(any).await.unwrap();
    let (mut rx, mut tx) = sock.split();
    rx.readable().await.unwrap();
    let mut buf = [0u8; 64];
    let (n, remote) = rx.receive(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"ping");
    tx.send(remote, b"pong").await.unwrap();
}

#[test]
fn udp_round_trip_through_edge_nal() {
    let clks = [clock(), clock()];
    let air = Air::new(2);
    let pend = [Cell::new(None), Cell::new(None)];
    let res0: Res<'_> = Res::new(instance(1), &clks[0]);
    let res1: Res<'_> = Res::new(instance(2), &clks[1]);
    let ots = [Ot::new(&res0), Ot::new(&res1)];
    let ds = ots[0].with(|i, _| i.create_dataset(15).unwrap());
    let tasks = vec![
        run_task(ots[0], &air, 0, &clks[0], &pend[0]),
        run_task(ots[1], &air, 1, &clks[1], &pend[1]),
    ];
    let reply = drive(
        &[&clks[0], &clks[1]],
        &[&pend[0], &pend[1]],
        tasks,
        async {
            ots[0].set_active_dataset(&ds).unwrap();
            ots[0].become_leader().unwrap();
            wait_role(ots[0], Role::Leader).await;
            ots[1].set_active_dataset(&ds).unwrap();
            ots[1].thread_start().unwrap();
            wait_role(ots[1], Role::Child).await;
            let rloc1 = ots[1].with(|i, _| i.rloc()).unwrap();

            let stack0 = UdpStack::new(ots[0]);
            let stack1 = UdpStack::new(ots[1]);
            let local = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 5000, 0, 0));
            let remote = SocketAddr::V6(SocketAddrV6::new(rloc1, 6000, 0, 0));
            let client = async {
                let mut s = stack0.connect(local, remote).await.unwrap();
                UdpSend::send(&mut s, remote, b"ping").await.unwrap();
                let mut buf = [0u8; 64];
                let (n, from) = UdpReceive::receive(&mut s, &mut buf).await.unwrap();
                assert_eq!(from, remote);
                buf[..n].to_vec()
            };
            let ((), reply) = join(server(&stack1, 6000), client).await;

            // IPv4 is rejected, multicast join / leave work.
            let v4 = SocketAddr::from((Ipv4Addr::LOCALHOST, 1));
            assert_eq!(stack0.bind(v4).await.err(), Some(EdgeError::Unsupported));
            let mut s = stack0.bind(local).await.unwrap();
            let group: Ipv6Addr = "ff03::1234".parse().unwrap();
            s.join_v6(group, 0).await.unwrap();
            s.leave_v6(group, 0).await.unwrap();
            let (_rx, _tx, _m4, mut m6) = s.split_multicast();
            m6.join_v6(group, 0).await.unwrap();
            reply
        },
        Duration::from_secs(1200),
    );
    assert_eq!(reply, b"pong");
}
