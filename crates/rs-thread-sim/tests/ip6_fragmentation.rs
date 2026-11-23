//! A UDP datagram of 1952 bytes (a 2000 byte IPv6 datagram) goes through the
//! mesh as two IPv6 fragments and is reassembled by the receiver, between
//! rs-thread nodes and between rs-thread and OpenThread (which has
//! `OPENTHREAD_CONFIG_IP6_FRAGMENTATION_ENABLE` in the reference build).
//! Skipped (passes) when a node binary is not built.

#![allow(clippy::std_instead_of_core)]

mod vt_common;

use vt_common::{Kind, env, ok, state};

fn run(name: &str, k1: Kind, k2: Kind) {
    let Some(mut e) = env(name, &[(1, k1), (2, k2)]) else {
        return;
    };
    let sim = &mut e.sim;
    ok(sim, 1, "dataset init new");
    ok(sim, 1, "dataset commit active");
    ok(sim, 1, "ifconfig up");
    ok(sim, 1, "thread start");
    sim.run(20.0);
    assert_eq!(state(sim, 1), "leader");
    let tlv = ok(sim, 1, "dataset active -x")[0].clone();
    ok(sim, 2, &format!("dataset set active {tlv}"));
    ok(sim, 2, "ifconfig up");
    ok(sim, 2, "thread start");
    sim.run(120.0);
    assert_eq!(state(sim, 2), "router");
    let m1 = ok(sim, 1, "ipaddr mleid")[0].clone();
    let m2 = ok(sim, 2, "ipaddr mleid")[0].clone();
    for id in [1, 2] {
        ok(sim, id, "udp open");
        ok(sim, id, "udp bind :: 12345");
    }
    sim.drain(1);
    sim.drain(2);
    ok(sim, 1, &format!("udp send {m2} 12345 -s 1952"));
    sim.run(5.0);
    assert!(
        sim.drain(2)
            .iter()
            .any(|l| l.starts_with("1952 bytes from")),
        "{name}: router received the datagram"
    );
    ok(sim, 2, &format!("udp send {m1} 12345 -s 1831"));
    sim.run(5.0);
    assert!(
        sim.drain(1)
            .iter()
            .any(|l| l.starts_with("1831 bytes from")),
        "{name}: leader received the datagram"
    );
}

#[test]
fn fragmented_udp_between_rs_thread_nodes() {
    run("frag-rust", Kind::Rust, Kind::Rust);
}

#[test]
fn fragmented_udp_with_openthread_leader() {
    run("frag-ot-leader", Kind::Ot, Kind::Rust);
}

#[test]
fn fragmented_udp_with_openthread_router() {
    run("frag-ot-router", Kind::Rust, Kind::Ot);
}
