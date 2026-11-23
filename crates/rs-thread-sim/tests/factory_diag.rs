//! `diag` (factory diagnostics) answers as OpenThread's does. Skipped
//! (passes) when a node binary is not built.

#![allow(clippy::std_instead_of_core)]

mod vt_common;

use vt_common::{Kind, env};

#[test]
fn factory_diag_commands() {
    let Some(mut e) = env("factory-diag", &[(1, Kind::Rust)]) else {
        return;
    };
    let sim = &mut e.sim;
    let run = |sim: &mut rs_thread_sim::vtsim::VtSim, c: &str| sim.cmd(1, c);
    assert_eq!(run(sim, "diag"), ["diagnostics mode is disabled", "Done"]);
    assert_eq!(run(sim, "diag send 10 100"), ["Error 13: InvalidState"]);
    assert_eq!(run(sim, "diag start"), ["Done"]);
    assert_eq!(run(sim, "diag channel 10"), ["Error 7: InvalidArgs"]);
    assert_eq!(run(sim, "diag channel 12"), ["Done"]);
    assert_eq!(run(sim, "diag channel"), ["12", "Done"]);
    assert_eq!(run(sim, "diag power -10"), ["Done"]);
    assert_eq!(run(sim, "diag power"), ["-10", "Done"]);
    assert_eq!(run(sim, "diag send 20 100"), ["Done"]);
    let stats = run(sim, "diag stats");
    assert_eq!(stats[1], "sent success packets: 20", "{stats:?}");
    assert_eq!(run(sim, "diag stop"), ["Done"]);
    let many = (1..=32)
        .map(|i| i.to_string())
        .collect::<Vec<_>>()
        .join(" ");
    assert_eq!(run(sim, &format!("diag {many}")), ["Error 7: InvalidArgs"]);
}
