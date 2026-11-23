//! CSL (Thread 1.2 synchronized sleepy end devices) between OpenThread's
//! `ot-cli-ftd` and the rs-thread node `rs-thread-cli-vt` in virtual time.
//! Skipped (passes) when `ot-cli-ftd` is not built.

#![allow(clippy::std_instead_of_core)]

mod vt_common;

use rs_thread_sim::vtsim::VtSim;
use vt_common::{Env, env, mesh_local, ok, state};

/// Value of a `Name: <n>` line of `counters mac`.
fn counter(sim: &mut VtSim, id: u16, name: &str) -> u64 {
    let out = ok(sim, id, "counters mac");
    out.iter()
        .find_map(|l| {
            let l = l.trim();
            l.strip_prefix(name)
                .and_then(|r| r.trim_start_matches(':').trim().parse().ok())
        })
        .unwrap_or_else(|| panic!("node {id}: no counter {name}: {out:?}"))
}

/// Round-trip time of the echo reply to one `ping`, milliseconds.
fn ping_rtt(sim: &mut VtSim, from: u16, to: &str) -> Option<u32> {
    sim.send(from, &format!("ping {to}"));
    sim.run(4.0);
    sim.drain(from).iter().find_map(|l| {
        l.contains("bytes from")
            .then(|| l.split("time=").nth(1))
            .flatten()
            .and_then(|r| r.split("ms").next())
            .and_then(|r| r.trim().parse().ok())
    })
}

/// CSL period of the tests: 500 ms in units of 10 symbols (160 us).
const PERIOD_US: u32 = 500_000;

/// Form with the leader `1`; node `2` is a CSL SSED (`mode -`) that attaches
/// with the leader's dataset. Returns once node 2 is a child.
fn csl_attach(e: &mut Env) {
    let sim = &mut e.sim;
    ok(sim, 1, "dataset init new");
    ok(sim, 1, "dataset commit active");
    ok(sim, 1, "ifconfig up");
    ok(sim, 1, "thread start");
    sim.run(25.0);
    assert_eq!(state(sim, 1), "leader");
    let tlv = ok(sim, 1, "dataset active -x")[0].clone();
    ok(sim, 2, "mode -");
    ok(sim, 2, &format!("csl period {PERIOD_US}"));
    ok(sim, 2, "csl timeout 20");
    ok(sim, 2, &format!("dataset set active {tlv}"));
    ok(sim, 2, "ifconfig up");
    ok(sim, 2, "thread start");
    sim.run(20.0);
    assert_eq!(state(sim, 2), "child");
}

/// The parent's `child 1` shows whether it considers the child CSL
/// synchronized.
fn child_synchronized(sim: &mut VtSim) -> bool {
    sim.cmd(1, "child 1")
        .iter()
        .any(|l| l.starts_with("CSL Synchronized: 1"))
}

/// Pings both ways between parent (1) and CSL child (2): delivered by CSL
/// windows (a round trip is bounded by the period plus the answer, with the
/// child's own transmission immediate), without the child polling.
fn csl_pings(e: &mut Env, ot_parent: bool) {
    let sim = &mut e.sim;
    assert!(
        !ot_parent || child_synchronized(sim),
        "child not CSL synchronized"
    );
    let child = sim.cmd(2, "csl");
    assert!(
        child.iter().any(|l| l == "period: 500000us"),
        "csl: {child:?}"
    );
    let a2 = mesh_local(sim, 2);
    let a1 = mesh_local(sim, 1);
    let polls = counter(sim, 2, "TxDataPoll");
    let mut rtts = Vec::new();
    for _ in 0..4 {
        rtts.push(ping_rtt(sim, 1, &a2).expect("ping parent -> CSL child"));
        rtts.push(ping_rtt(sim, 2, &a1).expect("ping CSL child -> parent"));
        sim.run(1.3);
    }
    // The child did not poll for these pings (the poll that follows a frame
    // with Frame Pending below is its answer to more fragments).
    let after = counter(sim, 2, "TxDataPoll");
    // Fragmented datagrams: each fragment of the request waits for a window
    // of the child (one per period), the reply's fragments go out at once.
    for (from, to) in [(1, &a2), (2, &a1)] {
        sim.send(from, &format!("ping {to} 128 1 1 64 8"));
        sim.run(10.0);
        let out = sim.drain(from);
        assert!(
            out.iter().any(|l| l.contains("1 packets received")),
            "fragmented ping from node {from}: {out:?}"
        );
    }
    // The request waits for the child's window (up to one period), the
    // reply is sent at once; the other way the request is immediate and the
    // reply waits for the next window.
    let bound = PERIOD_US / 1000 + 40;
    assert!(
        rtts.iter().all(|r| *r <= bound),
        "round trips {rtts:?} exceed one period ({bound} ms)"
    );
    assert!(
        !ot_parent || child_synchronized(sim),
        "child lost CSL synchronization: {:?}",
        sim.cmd(1, "child 1")
    );
    assert!(
        after <= polls + 1,
        "the CSL child polled {} times for 8 pings",
        after - polls
    );
    eprintln!("CSL round trips (ms): {rtts:?}, polls {polls} -> {after}");
}

/// An rs-thread SSED with CSL attaches to an OpenThread parent, synchronizes
/// (the parent's child table shows it) and is reached by CSL transmissions.
#[test]
fn rs_thread_csl_child_of_ot_parent() {
    let Some(mut e) = env("csl-a", &[(1, false), (2, true)]) else {
        return;
    };
    csl_attach(&mut e);
    csl_pings(&mut e, true);
}

/// The CSL channel moves and comes back, then CSL is turned off: the SSED is
/// a plain sleepy child again, which polls only at its (long) poll period,
/// so a ping from the parent right afterwards is not answered (the
/// OpenThread child behaves like that, too: `csl period 0` sends no Child
/// Update Request and starts no poll).
fn csl_off(parent_rust: bool, child_rust: bool) {
    let Some(mut e) = env("csl-off", &[(1, parent_rust), (2, child_rust)]) else {
        return;
    };
    csl_attach(&mut e);
    let sim = &mut e.sim;
    let a2 = mesh_local(sim, 2);
    assert!(ping_rtt(sim, 1, &a2).is_some(), "ping with CSL on");
    // The PAN channel is not 12.
    ok(sim, 2, "csl channel 12");
    sim.run(1.0);
    assert!(ping_rtt(sim, 1, &a2).is_some(), "ping on CSL channel 12");
    sim.run(5.0);
    ok(sim, 2, "csl channel 0");
    sim.run(1.0);
    assert!(ping_rtt(sim, 1, &a2).is_some(), "ping on the PAN channel");
    sim.run(5.0);
    ok(sim, 2, "csl period 0");
    assert!(
        ping_rtt(sim, 1, &a2).is_none(),
        "the child answered without CSL and without a poll"
    );
}

#[test]
fn csl_off_rs_thread_child_of_ot_parent() {
    csl_off(false, true);
}

#[test]
fn csl_off_ot_child_of_rs_thread_parent() {
    csl_off(true, false);
}

/// Both ends are rs-thread.
#[test]
fn rs_thread_csl_child_of_rs_thread_parent() {
    let Some(mut e) = env("csl-c", &[(1, true), (2, true)]) else {
        return;
    };
    csl_attach(&mut e);
    csl_pings(&mut e, false);
}

/// An OpenThread SSED with CSL attaches to an rs-thread parent, which sends
/// to it by CSL transmissions.
#[test]
fn ot_csl_child_of_rs_thread_parent() {
    let Some(mut e) = env("csl-b", &[(1, true), (2, false)]) else {
        return;
    };
    csl_attach(&mut e);
    csl_pings(&mut e, false);
}

/// The parent goes away: the SSED's CSL data polls get no ACK, and after
/// OpenThread's limit (15 in a row) it gives its parent up, detaches and
/// attaches anew when the parent is back (the last step of the thread-cert case
/// `v1_2_test_csl_transmission`, which then sees a Child Update Request).
fn parent_away_longer_than_timeout(child_rust: bool) {
    let Some(mut e) = env("csl-away", &[(1, false), (2, child_rust)]) else {
        return;
    };
    csl_attach(&mut e);
    let sim = &mut e.sim;
    ok(sim, 2, "csl timeout 8");
    ok(sim, 2, "childtimeout 10");
    sim.run(2.0);
    ok(sim, 1, "thread stop");
    ok(sim, 1, "ifconfig down");
    // 15 failed polls, 0.5 s apart after the first fast ones, within 25 s.
    sim.run(25.0);
    let s = state(sim, 2);
    assert_ne!(s, "child", "the SSED kept its parent for 25 s");
    ok(sim, 1, "ifconfig up");
    ok(sim, 1, "thread start");
    sim.run(90.0);
    assert_eq!(state(sim, 1), "leader");
    assert_eq!(state(sim, 2), "child", "the SSED did not attach again");
    let a2 = mesh_local(sim, 2);
    assert!(ping_rtt(sim, 1, &a2).is_some(), "ping after the attach");
}

#[test]
fn parent_away_rs_thread_ssed() {
    parent_away_longer_than_timeout(true);
}

#[test]
fn parent_away_ot_ssed() {
    parent_away_longer_than_timeout(false);
}

/// The parent's `counters mac` of the frames it sent: how many asked for an
/// ACK and how many were not acknowledged (attempts, retries included).
fn parent_tx_stats(sim: &mut VtSim) -> (u64, u64) {
    let requested = counter(sim, 1, "TxAckRequested");
    (requested, requested - counter(sim, 1, "TxAcked"))
}

/// Change the CSL period of an attached SSED (`from` -> `to` microseconds)
/// and check that the parent keeps reaching it: pings both ways, the child
/// stays CSL synchronized and (almost) none of the parent's frames goes
/// unacknowledged.
fn period_change(parent_rust: bool, child_rust: bool, to: u32) {
    let Some(mut e) = env("csl-period", &[(1, parent_rust), (2, child_rust)]) else {
        return;
    };
    csl_attach(&mut e);
    let sim = &mut e.sim;
    let a2 = mesh_local(sim, 2);
    let a1 = mesh_local(sim, 1);
    assert!(ping_rtt(sim, 1, &a2).is_some(), "ping before the change");
    let (req0, noack0) = parent_tx_stats(sim);
    ok(sim, 2, &format!("csl period {to}"));
    let mut sync_lost = false;
    let mut lost = 0;
    let mut rtts = Vec::new();
    for _ in 0..12 {
        match ping_rtt(sim, 1, &a2) {
            Some(r) => rtts.push(r),
            None => lost += 1,
        }
        if ping_rtt(sim, 2, &a1).is_none() {
            lost += 1;
        }
        sync_lost |= !parent_rust && !child_synchronized(sim);
        sim.run(0.7);
    }
    let (req1, noack1) = parent_tx_stats(sim);
    eprintln!(
        "{PERIOD_US} -> {to} us: lost {lost}, rtts {rtts:?}, parent frames with ACK request {}, no ACK {}",
        req1 - req0,
        noack1 - noack0
    );
    assert_eq!(lost, 0, "pings lost after {PERIOD_US} -> {to}");
    assert!(!sync_lost, "the parent marked the child unsynchronized");
    let child = sim.cmd(2, "csl");
    assert!(
        child.iter().any(|l| l == &format!("period: {to}us")),
        "csl: {child:?}"
    );
    // CSL frames of the parent are acknowledged: no more than a stray few.
    assert!(
        noack1 - noack0 <= 2,
        "{} of {} frames of the parent unacknowledged",
        noack1 - noack0,
        req1 - req0
    );
}

/// The period changes while the parent sends a datagram every 150 ms: the
/// frames in flight during the change are reacknowledged by the child's next
/// windows, and the child stays synchronized.
fn period_change_under_traffic(parent_rust: bool, child_rust: bool, to: u32) {
    let Some(mut e) = env("csl-period-traffic", &[(1, parent_rust), (2, child_rust)]) else {
        return;
    };
    csl_attach(&mut e);
    let sim = &mut e.sim;
    let a2 = mesh_local(sim, 2);
    let (req0, noack0) = parent_tx_stats(sim);
    sim.send(1, &format!("ping {a2} 16 60 0.15 64 1"));
    sim.run(3.0);
    ok(sim, 2, &format!("csl period {to}"));
    sim.run(12.0);
    let out = sim.drain(1);
    let received = out.iter().filter(|l| l.contains("bytes from")).count();
    let (req1, noack1) = parent_tx_stats(sim);
    eprintln!(
        "under traffic {PERIOD_US} -> {to} us: {received} of 60 echo replies, parent frames with ACK request {}, no ACK {}",
        req1 - req0,
        noack1 - noack0
    );
    assert!(received >= 57, "only {received} of 60 echo replies");
    assert!(
        parent_rust || child_synchronized(sim),
        "the parent marked the child unsynchronized"
    );
    assert!(
        noack1 - noack0 <= 4,
        "{} of {} frames of the parent unacknowledged",
        noack1 - noack0,
        req1 - req0
    );
}

#[test]
fn csl_period_change_under_traffic_rs_thread_child_of_ot_parent() {
    period_change_under_traffic(false, true, 100_000);
    period_change_under_traffic(false, true, 200_000);
}

#[test]
fn csl_period_change_under_traffic_ot_child_of_rs_thread_parent() {
    period_change_under_traffic(true, false, 100_000);
}

#[test]
fn csl_period_change_rs_thread_child_of_ot_parent() {
    period_change(false, true, 100_000);
}

#[test]
fn csl_period_change_up_rs_thread_child_of_ot_parent() {
    period_change(false, true, 1_000_000);
}

#[test]
fn csl_period_change_ot_child_of_rs_thread_parent() {
    period_change(true, false, 100_000);
}

#[test]
fn csl_period_change_rs_thread_child_of_rs_thread_parent() {
    period_change(true, true, 100_000);
}
