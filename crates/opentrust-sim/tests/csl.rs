//! CSL (Thread 1.2 synchronized sleepy end devices) between OpenThread's
//! `ot-cli-ftd` and the OpenTrust node `opentrust-cli-vt` in virtual time.
//! Skipped (passes) when `ot-cli-ftd` is not built.

#![allow(clippy::std_instead_of_core)]

use std::path::PathBuf;
use std::sync::atomic::{AtomicU16, Ordering};

use opentrust_sim::vtsim::{VtSim, opentrust_cli_vt, ot_cli_ftd};

static NEXT: AtomicU16 = AtomicU16::new(0);

struct Env {
    sim: VtSim,
    dir: PathBuf,
}

fn env(name: &str, kinds: &[(u16, bool)]) -> Option<Env> {
    let ot = ot_cli_ftd().or_else(|| {
        eprintln!("skipping {name}: no ot-cli-ftd (cargo build -p openthread-sys)");
        None
    })?;
    let rust = opentrust_cli_vt().or_else(|| {
        eprintln!("skipping {name}: opentrust-cli-vt not available");
        None
    })?;
    let offset = (std::process::id() % 250) as u16 + 100 + NEXT.fetch_add(1, Ordering::SeqCst) * 7;
    let offset = 1 + offset % 250;
    let mut sim = VtSim::new(offset).expect("simulator socket");
    let dir = std::env::temp_dir().join(format!("opentrust-csl-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    for &(id, is_rust) in kinds {
        let exe = if is_rust { &rust } else { &ot };
        sim.spawn(id, exe, &dir.join(format!("n{id}")))
            .expect("spawn node");
    }
    Some(Env { sim, dir })
}

impl Drop for Env {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn ok(sim: &mut VtSim, id: u16, cmd: &str) -> Vec<String> {
    let out = sim.cmd(id, cmd);
    assert_eq!(
        out.last().map(String::as_str),
        Some("Done"),
        "node {id}: {cmd}: {out:?}"
    );
    out
}

fn state(sim: &mut VtSim, id: u16) -> String {
    sim.cmd(id, "state").first().cloned().unwrap_or_default()
}

fn mesh_local(sim: &mut VtSim, id: u16) -> String {
    let out = ok(sim, id, "ipaddr");
    out.iter()
        .find(|l| !l.starts_with("fe80") && !l.contains("ff:fe00") && l.starts_with("fd"))
        .cloned()
        .expect("mesh-local address")
}

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

/// An OpenTrust SSED with CSL attaches to an OpenThread parent, synchronizes
/// (the parent's child table shows it) and is reached by CSL transmissions.
#[test]
fn opentrust_csl_child_of_ot_parent() {
    let Some(mut e) = env("csl-a", &[(1, false), (2, true)]) else {
        return;
    };
    csl_attach(&mut e);
    csl_pings(&mut e, true);
}

/// Turning CSL off makes the SSED a plain sleepy child again: it polls only
/// at its (long) poll period, so a ping from the parent in the meantime is
/// not answered.
#[test]
fn csl_off_makes_the_child_unreachable_between_polls() {
    let Some(mut e) = env("csl-off", &[(1, false), (2, true)]) else {
        return;
    };
    csl_attach(&mut e);
    let sim = &mut e.sim;
    let a2 = mesh_local(sim, 2);
    assert!(ping_rtt(sim, 1, &a2).is_some(), "ping with CSL on");
    // The CSL channel moves and comes back (the PAN channel is not 12).
    ok(sim, 2, "csl channel 12");
    sim.run(1.0);
    assert!(ping_rtt(sim, 1, &a2).is_some(), "ping on CSL channel 12");
    sim.run(5.0);
    ok(sim, 2, "csl channel 0");
    sim.run(1.0);
    assert!(ping_rtt(sim, 1, &a2).is_some(), "ping on the PAN channel");
    sim.run(5.0);
    ok(sim, 2, "csl period 0");
    sim.run(2.0);
    assert!(
        ping_rtt(sim, 1, &a2).is_none(),
        "the child answered without CSL and without a poll"
    );
}

/// Both ends are OpenTrust.
#[test]
fn opentrust_csl_child_of_opentrust_parent() {
    let Some(mut e) = env("csl-c", &[(1, true), (2, true)]) else {
        return;
    };
    csl_attach(&mut e);
    csl_pings(&mut e, false);
}

/// An OpenThread SSED with CSL attaches to an OpenTrust parent, which sends
/// to it by CSL transmissions.
#[test]
fn ot_csl_child_of_opentrust_parent() {
    let Some(mut e) = env("csl-b", &[(1, true), (2, false)]) else {
        return;
    };
    csl_attach(&mut e);
    csl_pings(&mut e, false);
}
