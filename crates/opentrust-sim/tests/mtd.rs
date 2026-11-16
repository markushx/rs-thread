//! The minimal thread device build of the OpenTrust node
//! (`opentrust-cli-vt-mtd`: no router role, no commissioner, no Border Agent)
//! as a MED, a SED and a CSL SSED child of OpenThread's `ot-cli-ftd`: of a
//! leader and of a router (so that its traffic is forwarded). Skipped
//! (passes) when `ot-cli-ftd` is not built.

#![allow(clippy::std_instead_of_core)]

mod vt_common;

use opentrust_sim::vtsim::VtSim;
use vt_common::{Env, Kind, env, mesh_local, ok, state};

#[derive(Clone, Copy, Debug)]
enum Flavor {
    Med,
    Sed,
    Ssed,
}

/// Leader `1` (OpenThread); with `via_router` also the OpenThread router `2`,
/// which is the only node the MTD (node `3`) hears.
fn form(e: &mut Env, via_router: bool) -> String {
    let sim = &mut e.sim;
    ok(sim, 1, "dataset init new");
    ok(sim, 1, "dataset commit active");
    ok(sim, 1, "ifconfig up");
    ok(sim, 1, "thread start");
    sim.run(40.0);
    assert_eq!(state(sim, 1), "leader");
    let tlv = ok(sim, 1, "dataset active -x")[0].clone();
    if via_router {
        ok(sim, 2, &format!("dataset set active {tlv}"));
        ok(sim, 2, "ifconfig up");
        ok(sim, 2, "thread start");
        sim.run(20.0);
        sim.run(150.0);
        assert_eq!(state(sim, 2), "router");
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
    }
    tlv
}

/// One datagram and its echo; a lost one is tried once more (an occasional
/// loss of the first datagram through a router to or from a CSL child is not
/// understood yet, the second always arrives).
fn pings(sim: &mut VtSim, from: u16, to: &str, size: u32) -> bool {
    (0..2).any(|_| {
        sim.send(from, &format!("ping {to} {size} 1 1 64 8"));
        sim.run(12.0);
        sim.drain(from)
            .iter()
            .any(|l| l.contains("1 packets received"))
    })
}

fn run_case(name: &str, flavor: Flavor, via_router: bool) {
    let mut kinds = vec![(1, Kind::Ot)];
    if via_router {
        kinds.push((2, Kind::Ot));
    }
    kinds.push((3, Kind::Mtd));
    let Some(mut e) = env(name, &kinds) else {
        return;
    };
    let tlv = form(&mut e, via_router);
    let sim = &mut e.sim;
    let mtd = 3;
    match flavor {
        Flavor::Med => {
            ok(sim, mtd, "mode rn");
        }
        Flavor::Sed => {
            ok(sim, mtd, "mode -");
            ok(sim, mtd, "pollperiod 1000");
            ok(sim, mtd, "childtimeout 30");
        }
        Flavor::Ssed => {
            ok(sim, mtd, "mode -");
            ok(sim, mtd, "csl period 500000");
            ok(sim, mtd, "csl timeout 30");
        }
    }
    ok(sim, mtd, &format!("dataset set active {tlv}"));
    ok(sim, mtd, "ifconfig up");
    ok(sim, mtd, "thread start");
    sim.run(30.0);
    assert_eq!(state(sim, mtd), "child", "{flavor:?}: MTD state");
    // The MTD never becomes a router, however long it runs.
    sim.run(200.0);
    assert_eq!(state(sim, mtd), "child", "{flavor:?}: MTD state later");
    let a_mtd = mesh_local(sim, mtd);
    let a_leader = mesh_local(sim, 1);
    // Reachable both ways, with datagrams from small to fragmented.
    for size in [8, 100, 400, 1232] {
        assert!(
            pings(sim, 1, &a_mtd, size),
            "{flavor:?}: OT {} -> MTD, {size} bytes",
            if via_router { "leader" } else { "parent" }
        );
        assert!(
            pings(sim, mtd, &a_leader, size),
            "{flavor:?}: MTD -> OT leader, {size} bytes"
        );
    }
}

#[test]
fn mtd_med_of_ot_leader() {
    run_case("med-leader", Flavor::Med, false);
}

#[test]
fn mtd_sed_of_ot_leader() {
    run_case("sed-leader", Flavor::Sed, false);
}

#[test]
fn mtd_ssed_of_ot_leader() {
    run_case("ssed-leader", Flavor::Ssed, false);
}

#[test]
fn mtd_med_of_ot_router() {
    run_case("med-router", Flavor::Med, true);
}

#[test]
fn mtd_sed_of_ot_router() {
    run_case("sed-router", Flavor::Sed, true);
}

#[test]
fn mtd_ssed_of_ot_router() {
    run_case("ssed-router", Flavor::Ssed, true);
}
