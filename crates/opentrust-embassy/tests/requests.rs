mod common;

use core::cell::Cell;
use core::net::{Ipv6Addr, SocketAddrV6};

use common::*;
use embassy_futures::join::join;
use opentrust_core::Error;
use opentrust_core::time::Duration;
use opentrust_dns::wire::{Header, Parser, Writer, opcode, rcode, rtype};
use opentrust_embassy::{DnsClientError, JoinerConfig, QueryConfig, ServiceId, UdpSocket};
use opentrust_instance::{Dataset, ItemState, Role, ServiceConfig};
use opentrust_meshcop::commissioner::{CommissionerState, JoinerKind};

fn secs(s: u64) -> Duration {
    Duration::from_secs(s)
}

async fn start(ot: Ot<'_, '_>, ds: &Dataset, leader: bool) {
    ot.set_active_dataset(ds).unwrap();
    if leader {
        ot.become_leader().unwrap();
    } else {
        ot.thread_start().unwrap();
    }
}

async fn role(ot: Ot<'_, '_>, role: Role) {
    wait_until(ot, |i| i.role() == role).await;
}

fn any(port: u16) -> SocketAddrV6 {
    SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, port, 0, 0)
}

#[test]
fn ping_reply_and_timeout() {
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
    drive(
        &[&clks[0], &clks[1]],
        &[&pend[0], &pend[1]],
        tasks,
        async {
            start(ots[0], &ds, true).await;
            role(ots[0], Role::Leader).await;
            start(ots[1], &ds, false).await;
            role(ots[1], Role::Child).await;
            let rloc1 = ots[1].with(|i, _| i.rloc()).unwrap();

            let r = ots[0].ping(rloc1, None, b"hello", secs(5)).await.unwrap();
            assert_eq!(r.src, rloc1);
            assert_eq!(r.payload_len, 5);

            // Two concurrent pings do not steal each other's replies.
            let (a, b) = join(
                ots[0].ping(rloc1, None, b"a", secs(5)),
                ots[0].ping(rloc1, None, b"bbb", secs(5)),
            )
            .await;
            assert_eq!(a.unwrap().payload_len, 1);
            assert_eq!(b.unwrap().payload_len, 3);

            // No reply: the timeout fires (the driver wakes at the deadline).
            let before = ots[0].now();
            air.borrow_mut().block(0, 1);
            let r = ots[0].ping(rloc1, None, b"x", secs(3)).await;
            assert_eq!(r, Err(Error::ResponseTimeout));
            assert!(ots[0].now() >= before.saturating_add(secs(3)));
        },
        secs(1200),
    );
}

#[test]
fn joiner_joins_through_a_joiner_router() {
    let clks = [clock(), clock(), clock()];
    let air = Air::new(3);
    // The joiner hears only the Joiner Router (node 1).
    air.borrow_mut().block(0, 2);
    let pend = [Cell::new(None), Cell::new(None), Cell::new(None)];
    let res0: Res<'_> = Res::new(instance(1), &clks[0]);
    let res1: Res<'_> = Res::new(instance(2), &clks[1]);
    let res2: Res<'_> = Res::new(instance(3), &clks[2]);
    let ots = [Ot::new(&res0), Ot::new(&res1), Ot::new(&res2)];
    let ds = ots[0].with(|i, _| i.create_dataset(15).unwrap());
    let tasks = (0..3)
        .map(|n| run_task(ots[n], &air, n, &clks[n], &pend[n]))
        .collect();
    drive(
        &[&clks[0], &clks[1], &clks[2]],
        &[&pend[0], &pend[1], &pend[2]],
        tasks,
        async {
            start(ots[0], &ds, true).await;
            role(ots[0], Role::Leader).await;
            start(ots[1], &ds, false).await;
            role(ots[1], Role::Router).await;

            ots[0].with(|i, now| i.commissioner_start("opentrust", None, now).unwrap());
            wait_until(ots[0], |i| {
                i.commissioner_state() == CommissionerState::Active
            })
            .await;
            ots[0].with(|i, now| {
                i.commissioner_add_joiner(JoinerKind::Any, "J01NME", secs(600), now)
                    .unwrap();
            });
            // The Steering Data reaches the Joiner Router.
            wait_until(ots[1], |i| {
                i.network_data()
                    .commissioning_data()
                    .is_some_and(|c| opentrust_meshcop::discovery::joining_allowed(Some(c)))
            })
            .await;

            ots[2].with(|i, _| i.ip6_set_enabled(true));
            let cfg = JoinerConfig {
                vendor_name: "OpenTrust",
                vendor_model: "Test",
                vendor_sw_version: "1",
                ..Default::default()
            };
            ots[2].joiner_start("J01NME", &cfg, 1 << 15).await.unwrap();
            wait_until(ots[2], |i| i.role().is_attached()).await;
        },
        secs(1800),
    );
}

#[test]
fn joiner_with_a_wrong_pskd_fails() {
    let clks = [clock(), clock(), clock()];
    let air = Air::new(3);
    air.borrow_mut().block(0, 2);
    let pend = [Cell::new(None), Cell::new(None), Cell::new(None)];
    let res0: Res<'_> = Res::new(instance(1), &clks[0]);
    let res1: Res<'_> = Res::new(instance(2), &clks[1]);
    let res2: Res<'_> = Res::new(instance(3), &clks[2]);
    let ots = [Ot::new(&res0), Ot::new(&res1), Ot::new(&res2)];
    let ds = ots[0].with(|i, _| i.create_dataset(15).unwrap());
    let tasks = (0..3)
        .map(|n| run_task(ots[n], &air, n, &clks[n], &pend[n]))
        .collect();
    drive(
        &[&clks[0], &clks[1], &clks[2]],
        &[&pend[0], &pend[1], &pend[2]],
        tasks,
        async {
            start(ots[0], &ds, true).await;
            role(ots[0], Role::Leader).await;
            start(ots[1], &ds, false).await;
            role(ots[1], Role::Router).await;
            ots[0].with(|i, now| i.commissioner_start("opentrust", None, now).unwrap());
            wait_until(ots[0], |i| {
                i.commissioner_state() == CommissionerState::Active
            })
            .await;
            ots[0].with(|i, now| {
                i.commissioner_add_joiner(JoinerKind::Any, "J01NME", secs(600), now)
                    .unwrap();
            });
            wait_until(ots[1], |i| {
                i.network_data()
                    .commissioning_data()
                    .is_some_and(|c| opentrust_meshcop::discovery::joining_allowed(Some(c)))
            })
            .await;
            ots[2].with(|i, _| i.ip6_set_enabled(true));
            let cfg = JoinerConfig {
                vendor_name: "OpenTrust",
                ..Default::default()
            };
            assert!(
                ots[2]
                    .joiner_start("WR0NGPSKD", &cfg, 1 << 15)
                    .await
                    .is_err()
            );
        },
        secs(1800),
    );
}

type Sock<'a, 'c> = UdpSocket<
    'a,
    embassy_sync::blocking_mutex::raw::NoopRawMutex,
    &'c opentrust_platform::time::MockClock,
    opentrust_sim::SimSettings,
    opentrust_core::crypto::soft::SoftCrypto,
    opentrust_sim::SimRng,
>;

const HOST_ADDR: Ipv6Addr = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0x1234);

/// A minimal DNS / SRP server: acknowledges every SRP update (the signature
/// is not checked), answers every address query with `HOST_ADDR`.
async fn serve(sock: &Sock<'_, '_>, updates: &Cell<u32>) {
    let mut buf = [0u8; 1280];
    loop {
        let (n, local, peer) = sock.recv(&mut buf).await.unwrap();
        let msg = buf[..n].to_vec();
        let (mut p, h) = Parser::new(&msg).unwrap();
        let mut out = [0u8; 512];
        let mut w = Writer::new(&mut out).unwrap();
        if h.opcode == opcode::UPDATE {
            updates.set(updates.get() + 1);
            w.write_opt(
                1232,
                false,
                Some(opentrust_dns::rdata::LeaseOption {
                    lease: 7200,
                    key_lease: 1_209_600,
                }),
            )
            .unwrap();
            w.set_header(&Header {
                id: h.id,
                response: true,
                opcode: opcode::UPDATE,
                rcode: rcode::SUCCESS,
                ar: 1,
                ..Header::default()
            });
        } else {
            let q = p.question().unwrap();
            let mut name = String::new();
            q.name.fmt_dotted(&mut name).unwrap();
            w.write_question(&name, q.qtype, q.qclass).unwrap();
            w.write_name(&name).unwrap();
            w.write_aaaa(120, &HOST_ADDR).unwrap();
            w.set_header(&Header {
                id: h.id,
                response: true,
                opcode: opcode::QUERY,
                rd: h.rd,
                ra: true,
                rcode: rcode::SUCCESS,
                qd: 1,
                an: 1,
                ..Header::default()
            });
        }
        let _ = rtype::AAAA;
        sock.send(w.as_bytes(), Some(*local.ip()), peer)
            .await
            .unwrap();
    }
}

#[test]
fn dns_resolution_and_srp_registration() {
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
    let updates = Cell::new(0);
    drive(
        &[&clks[0], &clks[1]],
        &[&pend[0], &pend[1]],
        tasks,
        async {
            start(ots[0], &ds, true).await;
            role(ots[0], Role::Leader).await;
            start(ots[1], &ds, false).await;
            role(ots[1], Role::Router).await;
            let rloc0 = ots[0].with(|i, _| i.rloc()).unwrap();
            let server = SocketAddrV6::new(rloc0, 53, 0, 0);
            let sock = UdpSocket::bind(ots[0], any(53)).unwrap();

            let client = async {
                // DNS: an address query through the server.
                let a = ots[1]
                    .dns_resolve_address(
                        "host.default.service.arpa",
                        Some(QueryConfig::new(server)),
                    )
                    .await
                    .unwrap();
                assert_eq!(a.addrs[0].addr, HOST_ADDR);

                // Without a server the request is rejected.
                let e = ots[1]
                    .dns_resolve_address("host.default.service.arpa", None)
                    .await;
                assert!(matches!(e, Err(DnsClientError::Request(_))), "{e:?}");

                // SRP: register a service and wait for it.
                let id: ServiceId = ots[1].with(|i, now| {
                    i.srp_set_host_name("host", now).unwrap();
                    i.srp_set_host_addresses(&[HOST_ADDR], now).unwrap();
                    let cfg = ServiceConfig::new("_matter._tcp", "ABCD-0001", 5540).unwrap();
                    let id = i.srp_add_service(cfg, now).unwrap();
                    i.srp_start(server, now).unwrap();
                    id
                });
                ots[1]
                    .srp_wait_service_registered(id, Some(secs(120)))
                    .await
                    .unwrap();
                ots[1]
                    .srp_wait_host_registered(Some(secs(1)))
                    .await
                    .unwrap();
                assert_eq!(
                    ots[1].with(|i, _| i.srp_host_state()),
                    ItemState::Registered
                );
            };
            // The server runs until the client is done.
            embassy_futures::select::select(serve(&sock, &updates), client).await;
        },
        secs(1800),
    );
    assert_eq!(updates.get(), 1);
}

#[test]
fn scan_finds_the_leader_and_energy_scan_reports_each_channel() {
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
    drive(
        &[&clks[0], &clks[1]],
        &[&pend[0], &pend[1]],
        tasks,
        async {
            start(ots[0], &ds, true).await;
            role(ots[0], Role::Leader).await;
            // The scanner is factory new with the interface up.
            ots[1].with(|i, _| i.ip6_set_enabled(true));

            let leader_ext = ots[0].with(|i, _| i.ext_address());
            let mut found = Vec::new();
            let mut ended = false;
            ots[1]
                .scan(0, |r| match r {
                    Some(r) => found.push(*r),
                    None => ended = true,
                })
                .await
                .unwrap();
            assert!(ended);
            assert_eq!(found.len(), 1, "{found:?}");
            assert_eq!(found[0].ext_address, leader_ext);
            assert_eq!(found[0].channel, 15);
            assert_eq!(found[0].network_name.unwrap().as_str(), "OpenTrust");

            let mut rssi = Vec::new();
            ots[1]
                .energy_scan(1 << 11 | 1 << 15 | 1 << 20, secs(0), |c, r| {
                    rssi.push((c, r))
                })
                .await
                .unwrap();
            assert_eq!(rssi, vec![(11, -100), (15, -100), (20, -100)]);
        },
        secs(1800),
    );
}
