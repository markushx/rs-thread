//! Mixed networks of OpenThread's `ot-cli-ftd` and the OpenTrust node
//! (`opentrust-cli-vt`) in virtual time, driven by the Rust port of the
//! `thread-cert` simulator. Skipped (passes) when `ot-cli-ftd` is not built:
//! `cargo build -p openthread-sys` puts it into `<target dir>/ot-sim/`
//! (or set `OT_CLI_PATH`).

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
    let offset = (std::process::id() % 250) as u16 + NEXT.fetch_add(1, Ordering::SeqCst) * 7;
    let offset = 1 + offset % 250;
    let mut sim = VtSim::new(offset).expect("simulator socket");
    let dir = std::env::temp_dir().join(format!("opentrust-mixed-{}-{name}", std::process::id()));
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

fn pings(sim: &mut VtSim, from: u16, to: &str) -> bool {
    sim.send(from, &format!("ping {to}"));
    sim.run(4.0);
    sim.drain(from).iter().any(|l| l.contains("bytes from"))
}

/// Form with `leader`, let `other` join with its dataset.
fn form_and_join(e: &mut Env, leader: u16, other: u16) {
    let sim = &mut e.sim;
    ok(sim, leader, "dataset init new");
    ok(sim, leader, "dataset commit active");
    ok(sim, leader, "ifconfig up");
    ok(sim, leader, "thread start");
    sim.run(40.0);
    assert_eq!(state(sim, leader), "leader");
    let tlv = ok(sim, leader, "dataset active -x")[0].clone();
    ok(sim, other, &format!("dataset set active {tlv}"));
    ok(sim, other, "ifconfig up");
    ok(sim, other, "thread start");
    sim.run(20.0);
    let s = state(sim, other);
    assert!(s == "child" || s == "router", "node {other} state {s}");
    // Becomes a router by itself (OpenThread: router selection jitter 120 s).
    sim.run(150.0);
    assert_eq!(
        state(sim, other),
        "router",
        "node {other} did not become a router"
    );
}

fn mesh_local(sim: &mut VtSim, id: u16) -> String {
    let out = ok(sim, id, "ipaddr");
    // The ML-EID is the address that is neither a link-local, nor an RLOC / ALOC.
    out.iter()
        .find(|l| !l.starts_with("fe80") && !l.contains("ff:fe00") && l.starts_with("fd"))
        .cloned()
        .expect("mesh-local address")
}

fn router_ids(sim: &mut VtSim, id: u16) -> usize {
    ok(sim, id, "router table")
        .iter()
        .filter(|l| {
            l.split('|')
                .nth(1)
                .is_some_and(|f| f.trim().parse::<u32>().is_ok())
        })
        .count()
}

fn run_case(name: &str, leader_rust: bool) {
    let Some(mut e) = env(name, &[(1, leader_rust), (2, !leader_rust)]) else {
        return;
    };
    form_and_join(&mut e, 1, 2);
    let sim = &mut e.sim;
    assert_eq!(router_ids(sim, 1), 2, "router table of the leader");
    assert_eq!(router_ids(sim, 2), 2, "router table of the router");
    let a1 = mesh_local(sim, 1);
    let a2 = mesh_local(sim, 2);
    assert!(pings(sim, 2, &a1), "ping {a1} from node 2");
    assert!(pings(sim, 1, &a2), "ping {a2} from node 1");
}

#[test]
fn ot_leader_opentrust_router() {
    run_case("ot-leader", false);
}

#[test]
fn opentrust_leader_ot_router() {
    run_case("rust-leader", true);
}

/// A sleepy OpenTrust child attaches to an OpenThread parent, which sends the
/// Child ID Response indirectly.
#[test]
fn opentrust_sleepy_child_attaches_to_ot_router() {
    let Some(mut e) = env("sed", &[(1, false), (2, true)]) else {
        return;
    };
    let sim = &mut e.sim;
    ok(sim, 1, "dataset init new");
    ok(sim, 1, "dataset commit active");
    ok(sim, 1, "ifconfig up");
    ok(sim, 1, "thread start");
    sim.run(25.0);
    assert_eq!(state(sim, 1), "leader");
    let tlv = ok(sim, 1, "dataset active -x")[0].clone();
    ok(sim, 2, "mode -");
    ok(sim, 2, "childtimeout 6");
    ok(sim, 2, &format!("dataset set active {tlv}"));
    ok(sim, 2, "ifconfig up");
    ok(sim, 2, "thread start");
    let mut attached = None;
    for t in 1..=30 {
        sim.run(0.5);
        let s = state(sim, 2);
        if s == "child" {
            attached = Some(t);
            break;
        }
    }
    // The SED polls its candidate parent for the Child ID Response: it is
    // attached within a few seconds although its timeout is 6 s.
    assert!(
        attached.is_some_and(|t| t <= 14),
        "attached at {attached:?} half seconds"
    );
}

/// An OpenTrust leader pings a sleepy OpenThread child of an OpenThread
/// router with datagrams up to the IPv6 minimum MTU (fragmented, forwarded
/// and queued indirectly).
#[test]
fn opentrust_leader_pings_ot_sleepy_child_with_large_datagrams() {
    let Some(mut e) = env("big", &[(1, true), (2, false), (3, false)]) else {
        return;
    };
    form_and_join(&mut e, 1, 2);
    let sim = &mut e.sim;
    let tlv = ok(sim, 1, "dataset active -x")[0].clone();
    let ext1 = ok(sim, 1, "extaddr")[0].clone();
    let ext2 = ok(sim, 2, "extaddr")[0].clone();
    let ext3 = ok(sim, 3, "extaddr")[0].clone();
    ok(sim, 3, &format!("macfilter addr add {ext2}"));
    ok(sim, 3, "macfilter addr allowlist");
    ok(sim, 1, &format!("macfilter addr add {ext2}"));
    ok(sim, 1, "macfilter addr allowlist");
    ok(sim, 2, &format!("macfilter addr add {ext1}"));
    ok(sim, 2, &format!("macfilter addr add {ext3}"));
    ok(sim, 2, "macfilter addr allowlist");
    ok(sim, 3, "mode -");
    ok(sim, 3, "childtimeout 6");
    ok(sim, 3, &format!("dataset set active {tlv}"));
    ok(sim, 3, "ifconfig up");
    ok(sim, 3, "thread start");
    sim.run(30.0);
    assert_eq!(state(sim, 3), "child");
    let a3 = ok(sim, 3, "ipaddr mleid")[0].clone();
    for size in [8, 100, 400, 800, 1232] {
        sim.send(1, &format!("ping {a3} {size} 1 1 64 5"));
        sim.run(8.0);
        let out = sim.drain(1);
        assert!(
            out.iter().any(|l| l.contains("1 packets received")),
            "ping of {size} bytes: {out:?}"
        );
    }
}
