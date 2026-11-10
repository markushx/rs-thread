mod common;

use core::cell::Cell;
use core::net::{Ipv6Addr, SocketAddrV6};

use common::*;
use embassy_futures::join::{join, join3};
use opentrust_core::time::{Duration, Instant};
use opentrust_instance::{Dataset, Event, Role};
use opentrust_platform::time::MockClock;

fn limit() -> Duration {
    Duration::from_secs(900)
}

fn make_dataset(ot: Ot<'_, '_>) -> Dataset {
    ot.with(|i, _| i.create_dataset(15).unwrap())
}

async fn start_with(ot: Ot<'_, '_>, ds: &Dataset, leader: bool) {
    ot.set_active_dataset(ds).unwrap();
    if leader {
        ot.become_leader().unwrap();
    } else {
        ot.thread_start().unwrap();
    }
}

async fn wait_role(ot: Ot<'_, '_>, role: Role) {
    loop {
        let g = ot.generation();
        if ot.role() == role {
            return;
        }
        ot.wait_changed_after(g).await;
    }
}

#[test]
fn leader_role_wakes_all_waiters() {
    let clk = clock();
    let air = Air::new(1);
    let pend = Cell::new(None);
    let res: Res<'_> = Res::new(instance(1), &clk);
    let ot = Ot::new(&res);
    let ds = make_dataset(ot);

    let woken = Cell::new(0u32);
    let waiter = || async {
        // Registered before the change is made (see the trigger below).
        while ot.role() != Role::Leader {
            ot.wait_changed().await;
        }
        woken.set(woken.get() + 1);
    };
    let trigger = async {
        yield_once().await;
        start_with(ot, &ds, true).await;
    };
    drive(
        &[&clk],
        &[&pend],
        vec![run_task(ot, &air, 0, &clk, &pend)],
        join3(waiter(), waiter(), trigger),
        limit(),
    );
    assert_eq!(woken.get(), 2);
    assert_eq!(ot.role(), Role::Leader);
}

#[test]
fn event_stream_reports_the_role_change() {
    let clk = clock();
    let air = Air::new(1);
    let pend = Cell::new(None);
    let res: Res<'_> = Res::new(instance(1), &clk);
    let ot = Ot::new(&res);
    let ds = make_dataset(ot);
    let got = drive(
        &[&clk],
        &[&pend],
        vec![run_task(ot, &air, 0, &clk, &pend)],
        async {
            start_with(ot, &ds, true).await;
            loop {
                if let Event::RoleChanged {
                    new: Role::Leader, ..
                } = ot.next_event().await
                {
                    return true;
                }
            }
        },
        limit(),
    );
    assert!(got);
}

#[test]
fn child_attaches_and_udp_round_trips() {
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
    let reply = drive(
        &[&clks[0], &clks[1]],
        &[&pend[0], &pend[1]],
        tasks,
        async {
            start_with(ots[0], &ds, true).await;
            wait_role(ots[0], Role::Leader).await;
            start_with(ots[1], &ds, false).await;
            wait_role(ots[1], Role::Child).await;
            assert_eq!(
                ots[1].with(|i, _| i.partition_id()),
                ots[0].with(|i, _| i.partition_id())
            );
            let rloc1 = ots[1].with(|i, _| i.rloc()).expect("child RLOC");

            let any = |port| SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, port, 0, 0);
            let s0 = opentrust_embassy::UdpSocket::bind(ots[0], any(5000)).unwrap();
            let s1 = opentrust_embassy::UdpSocket::bind(ots[1], any(6000)).unwrap();
            let server = async {
                let mut buf = [0u8; 64];
                s1.wait_recv_available().await.unwrap();
                let (n, local, remote) = s1.recv(&mut buf).await.unwrap();
                assert_eq!(&buf[..n], b"ping");
                s1.send(b"pong", Some(*local.ip()), remote).await.unwrap();
            };
            let client = async {
                let dst = SocketAddrV6::new(rloc1, 6000, 0, 0);
                s0.send(b"ping", None, dst).await.unwrap();
                let mut buf = [0u8; 64];
                let (n, _, remote) = s0.recv(&mut buf).await.unwrap();
                assert_eq!(*remote.ip(), rloc1);
                buf[..n].to_vec()
            };
            let ((), reply) = join(server, client).await;

            // The child becomes a router meanwhile.
            wait_role(ots[1], Role::Router).await;
            reply
        },
        Duration::from_secs(1200),
    );
    assert_eq!(reply, b"pong");
}

#[test]
fn dropping_run_mid_transmit_keeps_the_node_working() {
    let clks = [clock(), clock()];
    let air = Air::new(2);
    let pend = [Cell::new(None), Cell::new(None)];
    let res0: Res<'_> = Res::new(instance(1), &clks[0]);
    let res1: Res<'_> = Res::new(instance(2), &clks[1]);
    let ots = [Ot::new(&res0), Ot::new(&res1)];
    let ds = make_dataset(ots[0]);
    let clk_refs = [&clks[0], &clks[1]];
    let pend_refs = [&pend[0], &pend[1]];
    let tasks = || {
        vec![
            run_task(ots[0], &air, 0, &clks[0], &pend[0]),
            run_task(ots[1], &air, 1, &clks[1], &pend[1]),
        ]
    };

    // Phase 1: stop while node 1 is on the air.
    drive(
        &clk_refs,
        &pend_refs,
        tasks(),
        async {
            start_with(ots[0], &ds, true).await;
            wait_role(ots[0], Role::Leader).await;
            start_with(ots[1], &ds, false).await;
            // The driver polls the body after every round; no wake-up needed.
            core::future::poll_fn(|_| {
                if air.borrow().in_tx(1) {
                    core::task::Poll::Ready(())
                } else {
                    core::task::Poll::Pending
                }
            })
            .await;
        },
        limit(),
    );
    assert!(!air.borrow().in_tx(1), "the transmit future was dropped");

    // Phase 2: a new `run` on the same resources.
    drive(
        &clk_refs,
        &pend_refs,
        tasks(),
        async {
            wait_role(ots[1], Role::Child).await;
            wait_role(ots[1], Role::Router).await;
        },
        Duration::from_secs(1200),
    );
    assert_eq!(ots[1].role(), Role::Router);
}

fn lone_leader(seed: u8) -> Role {
    let clk: MockClock = clock();
    let air = Air::new(1);
    let pend: Cell<Option<Instant>> = Cell::new(None);
    let res: Res<'_> = Res::new(instance(seed), &clk);
    let ot = Ot::new(&res);
    let ds = make_dataset(ot);
    drive(
        &[&clk],
        &[&pend],
        vec![run_task(ot, &air, 0, &clk, &pend)],
        async {
            start_with(ot, &ds, true).await;
            wait_role(ot, Role::Leader).await;
            let any = SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 4000, 0, 0);
            // The socket is closed on drop: binding again works.
            for _ in 0..2 {
                let s = opentrust_embassy::UdpSocket::bind(ot, any).unwrap();
                drop(s);
            }
        },
        limit(),
    );
    ot.role()
}

#[test]
fn resources_can_be_recreated_after_a_drop() {
    // No global state: the same code twice in one process, then a node
    // restarted from the instance of a dropped one.
    assert_eq!(lone_leader(1), Role::Leader);
    assert_eq!(lone_leader(1), Role::Leader);

    let clk = clock();
    let res: Res<'_> = Res::new(instance(3), &clk);
    let inst = res.into_instance();
    let res2: Res<'_> = Res::new(inst, &clk);
    assert_eq!(Ot::new(&res2).role(), Role::Disabled);
}
