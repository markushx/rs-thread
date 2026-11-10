//! Two OpenTrust nodes exchange datagrams through the rs-matter network
//! traits (`NetStack` / `NetSocket` / `NetworkSend` / `NetworkReceive` /
//! `NetworkMulticast`).
mod common;

use core::cell::Cell;
use core::net::{IpAddr, Ipv6Addr, SocketAddr, SocketAddrV6};

use common::*;
use embassy_futures::join::join;
use opentrust_matter::net::MatterNetStack;
use rs_matter::error::ErrorCode;
use rs_matter::stack::net::{NetSocket, NetStack};
use rs_matter::transport::network::{Address, NetworkMulticast, NetworkReceive, NetworkSend};

const MATTER_PORT: u16 = 5540;
const MDNS_GROUP: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0xfb);

fn any(port: u16) -> SocketAddr {
    SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, port, 0, 0))
}

#[test]
fn unicast_and_multicast_through_the_rs_matter_traits() {
    let clks = [clock(), clock()];
    let air = Air::new(2);
    let pend = [Cell::new(None), Cell::new(None)];
    let res0: Res<'_> = Res::new(instance(1), &clks[0]);
    let res1: Res<'_> = Res::new(instance(2), &clks[1]);
    let ots = [Ot::new(&res0), Ot::new(&res1)];
    let ds = make_dataset(ots[0]);
    let tasks = vec![
        run_task(ots[0], &air, 0, &clks[0], &pend[0]),
        run_task(ots[1], &air, 1, &clks[1], &pend[1]),
    ];
    let (reply, mcast_from) = drive(
        &[&clks[0], &clks[1]],
        &[&pend[0], &pend[1]],
        tasks,
        async {
            form_network(&ots, &ds).await;
            // The child is a REED: its ML-EID is resolved with an Address Query.
            let ml_eid1 = ots[1].with(|i, _| i.ml_eid());

            let stack0 = MatterNetStack::new(ots[0]);
            let stack1 = MatterNetStack::new(ots[1]);
            // IPv4 is not a thing on Thread.
            let v4 = SocketAddr::V4(core::net::SocketAddrV4::new(
                core::net::Ipv4Addr::UNSPECIFIED,
                1,
            ));
            assert_eq!(
                stack0
                    .bind(v4, core::net::Ipv4Addr::UNSPECIFIED, 0)
                    .await
                    .err()
                    .map(|e| e.code()),
                Some(ErrorCode::NoNetworkInterface)
            );
            let mut s0 = stack0
                .bind(any(MATTER_PORT), core::net::Ipv4Addr::UNSPECIFIED, 0)
                .await
                .unwrap();
            let mut s1 = stack1
                .bind(any(MATTER_PORT), core::net::Ipv4Addr::UNSPECIFIED, 0)
                .await
                .unwrap();
            let (mut tx0, mut rx0, mut mc0) = s0.split();
            let (mut tx1, mut rx1, mut mc1) = s1.split();
            mc1.join(IpAddr::V6(MDNS_GROUP)).await.unwrap();
            assert_eq!(
                mc0.join(IpAddr::V4(core::net::Ipv4Addr::new(224, 0, 0, 251)))
                    .await
                    .err()
                    .map(|e| e.code()),
                Some(ErrorCode::NoNetworkInterface)
            );

            let server = async {
                let mut buf = [0u8; 64];
                rx1.wait_available().await.unwrap();
                let (n, from) = rx1.recv_from(&mut buf).await.unwrap();
                assert_eq!(&buf[..n], b"ping");
                tx1.send_to(b"pong", from).await.unwrap();
                // A link-local multicast datagram reaches the joined group.
                let (n, from) = rx1.recv_from(&mut buf).await.unwrap();
                assert_eq!(&buf[..n], b"hello group");
                from
            };
            let client = async {
                let dst = Address::Udp(SocketAddr::V6(SocketAddrV6::new(
                    ml_eid1,
                    MATTER_PORT,
                    0,
                    0,
                )));
                tx0.send_to(b"ping", dst).await.unwrap();
                let mut buf = [0u8; 64];
                let (n, from) = rx0.recv_from(&mut buf).await.unwrap();
                assert_eq!(from, dst);
                let group = Address::Udp(SocketAddr::V6(SocketAddrV6::new(
                    MDNS_GROUP,
                    MATTER_PORT,
                    0,
                    0,
                )));
                tx0.send_to(b"hello group", group).await.unwrap();
                let v4 = Address::Udp(SocketAddr::V4(core::net::SocketAddrV4::new(
                    core::net::Ipv4Addr::LOCALHOST,
                    1,
                )));
                assert!(tx0.send_to(b"x", v4).await.is_err());
                buf[..n].to_vec()
            };
            let (mcast_from, reply) = join(server, client).await;
            mc1.leave(IpAddr::V6(MDNS_GROUP)).await.unwrap();
            (reply, mcast_from)
        },
        limit(),
    );
    assert_eq!(reply, b"pong");
    let Address::Udp(SocketAddr::V6(from)) = mcast_from else {
        panic!("not UDP: {mcast_from:?}");
    };
    assert_eq!(from.port(), MATTER_PORT);
    assert!(
        from.ip().segments()[0] == 0xfe80
            || from.ip().segments()[0] == 0xfd00
            || from.ip().segments()[0] & 0xfe00 == 0xfc00
    );
}
