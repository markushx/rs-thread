//! Commissioning between OpenThread's `ot-cli-ftd` and the OpenTrust nodes
//! (`opentrust-cli-vt`, `opentrust-cli-vt-mtd`) in virtual time: the
//! Commissioner, the Joiner and the Joiner Router are each played by either
//! implementation. Skipped (passes) when a node binary is not built.

#![allow(clippy::std_instead_of_core)]

mod vt_common;

use opentrust_sim::vtsim::VtSim;
use vt_common::{Kind, env, mesh_local, ok, state};

use Kind::{Mtd, Ot, Rust};

const PSKD: &str = "J01NME";

fn pings(sim: &mut VtSim, from: u16, to: &str) -> bool {
    sim.send(from, &format!("ping {to}"));
    sim.run(4.0);
    sim.drain(from).iter().any(|l| l.contains("bytes from"))
}

/// Node `id` forms a network and returns its dataset.
fn form(sim: &mut VtSim, id: u16) -> String {
    ok(sim, id, "dataset init new");
    ok(sim, id, "dataset commit active");
    ok(sim, id, "ifconfig up");
    ok(sim, id, "thread start");
    sim.run(40.0);
    assert_eq!(state(sim, id), "leader");
    ok(sim, id, "dataset active -x")[0].clone()
}

/// Node `id` joins with the dataset and becomes a router.
fn join_as_router(sim: &mut VtSim, id: u16, tlv: &str) {
    ok(sim, id, &format!("dataset set active {tlv}"));
    ok(sim, id, "ifconfig up");
    ok(sim, id, "thread start");
    sim.run(20.0);
    sim.run(150.0);
    assert_eq!(state(sim, id), "router", "node {id}");
}

/// `commissioner start`, then waits for the petition to be accepted.
fn start_commissioner(sim: &mut VtSim, id: u16) {
    ok(sim, id, "commissioner start");
    sim.run(8.0);
    assert_eq!(
        sim.cmd(id, "commissioner state")
            .first()
            .map(String::as_str),
        Some("active"),
        "commissioner on node {id}"
    );
}

fn eui64(sim: &mut VtSim, id: u16) -> String {
    ok(sim, id, "eui64")[0].clone()
}

/// The joiner runs `joiner start` with `pskd`; returns what it printed.
fn joiner_start(sim: &mut VtSim, joiner: u16, pskd: &str) -> Vec<String> {
    ok(sim, joiner, "ifconfig up");
    sim.send(joiner, &format!("joiner start {pskd}"));
    sim.run(40.0);
    sim.drain(joiner)
}

/// The joined node starts Thread and attaches (as a child), and the network
/// key is the one of the commissioner.
fn attach_and_ping(sim: &mut VtSim, joiner: u16, leader: u16) {
    ok(sim, joiner, "thread start");
    sim.run(30.0);
    let s = state(sim, joiner);
    assert!(s == "child" || s == "router", "joiner state {s}");
    assert_eq!(
        ok(sim, joiner, "networkkey")[0],
        ok(sim, leader, "networkkey")[0],
        "network key of the joiner"
    );
    let a = mesh_local(sim, leader);
    assert!(pings(sim, joiner, &a), "ping {a} from the joiner");
}

fn joined(out: &[String]) -> bool {
    out.iter().any(|l| l.contains("Join success"))
}

fn failed(out: &[String]) -> bool {
    out.iter().any(|l| l.contains("Join failed"))
}

/// Joiner of kind `joiner` is in range of the leader (parent and Joiner
/// Router at once), the leader (kind `leader`) is the commissioner.
fn direct(name: &str, leader: Kind, joiner: Kind) {
    let Some(mut e) = env(name, &[(1, leader), (2, joiner)]) else {
        return;
    };
    let sim = &mut e.sim;
    form(sim, 1);
    start_commissioner(sim, 1);
    let eui = eui64(sim, 2);
    ok(sim, 1, &format!("commissioner joiner add {eui} {PSKD}"));
    let out = joiner_start(sim, 2, PSKD);
    assert!(joined(&out), "joiner output {out:?}");
    attach_and_ping(sim, 2, 1);
}

#[test]
fn ot_commissioner_opentrust_joiner() {
    direct("ot-comm-rust-joiner", Ot, Rust);
}

#[test]
fn ot_commissioner_opentrust_mtd_joiner() {
    direct("ot-comm-mtd-joiner", Ot, Mtd);
}

#[test]
fn opentrust_commissioner_ot_joiner() {
    direct("rust-comm-ot-joiner", Rust, Ot);
}

#[test]
fn opentrust_commissioner_opentrust_joiner_wildcard() {
    let Some(mut e) = env("rust-comm-wildcard", &[(1, Rust), (2, Ot)]) else {
        return;
    };
    let sim = &mut e.sim;
    form(sim, 1);
    start_commissioner(sim, 1);
    ok(sim, 1, &format!("commissioner joiner add * {PSKD}"));
    let out = joiner_start(sim, 2, PSKD);
    assert!(joined(&out), "joiner output {out:?}");
    attach_and_ping(sim, 2, 1);
}

/// Leader and commissioner are node 1, node 2 the Joiner Router, node 3 the
/// Joiner which only hears node 2.
fn via_joiner_router(name: &str, leader: Kind, jr: Kind, joiner: Kind) {
    let Some(mut e) = env(name, &[(1, leader), (2, jr), (3, joiner)]) else {
        return;
    };
    let sim = &mut e.sim;
    let tlv = form(sim, 1);
    join_as_router(sim, 2, &tlv);
    let ext2 = ok(sim, 2, "extaddr")[0].clone();
    ok(sim, 3, &format!("macfilter addr add {ext2}"));
    ok(sim, 3, "macfilter addr allowlist");
    start_commissioner(sim, 1);
    let eui = eui64(sim, 3);
    ok(sim, 1, &format!("commissioner joiner add {eui} {PSKD}"));
    // The steering data reaches the Joiner Router with the network data.
    sim.run(3.0);
    let out = joiner_start(sim, 3, PSKD);
    assert!(joined(&out), "joiner output {out:?}");
    attach_and_ping(sim, 3, 1);
}

#[test]
fn ot_joiner_router_opentrust_commissioner_and_joiner() {
    via_joiner_router("ot-jr", Rust, Ot, Rust);
}

#[test]
fn opentrust_joiner_router_ot_commissioner_and_joiner() {
    via_joiner_router("rust-jr", Ot, Rust, Ot);
}

#[test]
fn ot_joiner_router_opentrust_mtd_joiner() {
    via_joiner_router("ot-jr-mtd", Ot, Ot, Mtd);
}

#[test]
fn opentrust_joiner_router_opentrust_commissioner_ot_joiner() {
    via_joiner_router("rust-jr-rust-comm", Rust, Rust, Ot);
}

fn wrong_pskd(name: &str, leader: Kind, joiner: Kind) {
    let Some(mut e) = env(name, &[(1, leader), (2, joiner)]) else {
        return;
    };
    let sim = &mut e.sim;
    form(sim, 1);
    start_commissioner(sim, 1);
    let eui = eui64(sim, 2);
    ok(sim, 1, &format!("commissioner joiner add {eui} {PSKD}"));
    let out = joiner_start(sim, 2, "J01NMX");
    assert!(failed(&out), "joiner output {out:?}");
    assert!(!joined(&out), "joiner output {out:?}");
    // The key was not handed out: the joiner does not attach.
    assert_ne!(
        ok(sim, 2, "networkkey")[0],
        ok(sim, 1, "networkkey")[0],
        "network key leaked"
    );
    // A correct PSKd afterwards still works.
    let out = joiner_start(sim, 2, PSKD);
    assert!(joined(&out), "second attempt {out:?}");
    attach_and_ping(sim, 2, 1);
}

#[test]
fn wrong_pskd_ot_commissioner_opentrust_joiner() {
    wrong_pskd("wrong-ot-comm", Ot, Rust);
}

#[test]
fn wrong_pskd_opentrust_commissioner_ot_joiner() {
    wrong_pskd("wrong-rust-comm", Rust, Ot);
}

/// A Commissioner on node 2 petitions the leader (node 1), stays active
/// through the keep-alives, a second Commissioner (node 3) is refused while
/// it is active and succeeds once the first resigned.
fn petition(name: &str, leader: Kind, commissioner: Kind, second: Kind) {
    let Some(mut e) = env(name, &[(1, leader), (2, commissioner), (3, second)]) else {
        return;
    };
    let sim = &mut e.sim;
    let tlv = form(sim, 1);
    join_as_router(sim, 2, &tlv);
    join_as_router(sim, 3, &tlv);
    start_commissioner(sim, 2);
    let id = sim.cmd(2, "commissioner sessionid");
    assert!(id.len() > 1, "session id {id:?}");
    // Several keep-alive periods.
    sim.run(200.0);
    assert_eq!(
        sim.cmd(2, "commissioner state").first().map(String::as_str),
        Some("active"),
        "after the keep-alives"
    );
    // The Leader replaces a petition with the same Commissioner ID and
    // refuses one with another ID while a session is running.
    ok(sim, 3, "commissioner id OtherCommissioner");
    ok(sim, 3, "commissioner start");
    sim.run(10.0);
    assert_ne!(
        sim.cmd(3, "commissioner state").first().map(String::as_str),
        Some("active"),
        "second commissioner accepted"
    );
    ok(sim, 2, "commissioner stop");
    sim.run(5.0);
    assert_ne!(
        sim.cmd(2, "commissioner state").first().map(String::as_str),
        Some("active")
    );
    // Already stopped after the refusal (OpenThread answers `Already`).
    let _ = sim.cmd(3, "commissioner stop");
    sim.run(2.0);
    start_commissioner(sim, 3);
}

#[test]
fn petition_ot_leader_opentrust_commissioner() {
    petition("petition-ot-leader", Ot, Rust, Ot);
}

#[test]
fn petition_opentrust_leader_ot_commissioner() {
    petition("petition-rust-leader", Rust, Ot, Rust);
}
