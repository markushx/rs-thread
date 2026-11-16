//! Child supervision between an OpenTrust parent and a sleepy child: with the
//! parent sending supervision messages, the child's check timeout never
//! expires. Skipped (passes) when the simulator binaries are not built.

#![allow(clippy::std_instead_of_core)]

mod vt_common;

use vt_common::{Kind, env, ok, state};

#[test]
fn parent_supervision_keeps_the_check_timeout_quiet() {
    let Some(mut e) = env("supervision", &[(1, Kind::Rust), (2, Kind::Rust)]) else {
        return;
    };
    let sim = &mut e.sim;
    ok(sim, 1, "dataset init new");
    ok(sim, 1, "dataset commit active");
    ok(sim, 1, "ifconfig up");
    ok(sim, 1, "thread start");
    sim.run(40.0);
    assert_eq!(state(sim, 1), "leader");
    let tlv = ok(sim, 1, "dataset active -x")[0].clone();
    ok(sim, 2, "mode -");
    ok(sim, 2, &format!("dataset set active {tlv}"));
    ok(sim, 2, "ifconfig up");
    ok(sim, 2, "thread start");
    sim.run(10.0);
    assert_eq!(state(sim, 2), "child");
    ok(sim, 2, "pollperiod 500");
    ok(sim, 2, "childsupervision interval 20");
    sim.run(2.0);
    ok(sim, 2, "childsupervision checktimeout 25");
    sim.run(110.0);
    assert_eq!(state(sim, 2), "child");
    assert_eq!(ok(sim, 2, "childsupervision failcounter")[0], "0");
}
