//! A child that attaches to a new parent tells the previous parent, which
//! then drops it from its child table; `counters mle` counts the parent
//! change. Skipped (passes) when a node binary is not built.

#![allow(clippy::std_instead_of_core)]

mod vt_common;

use vt_common::{Kind, env, ok, state};

fn ext(sim: &mut rs_thread_sim::vtsim::VtSim, id: u16) -> String {
    ok(sim, id, "extaddr")[0].clone()
}

#[test]
fn previous_parent_drops_the_child() {
    let Some(mut e) = env(
        "inform-previous-parent",
        &[(1, Kind::Rust), (2, Kind::Rust), (3, Kind::Mtd)],
    ) else {
        return;
    };
    let sim = &mut e.sim;
    let (e1, e2, e3) = (ext(sim, 1), ext(sim, 2), ext(sim, 3));
    for (id, peers) in [(1, [&e2, &e3]), (2, [&e1, &e1]), (3, [&e1, &e1])] {
        ok(sim, id, "macfilter addr allowlist");
        ok(sim, id, &format!("macfilter addr add {}", peers[0]));
        if peers[0] != peers[1] {
            ok(sim, id, &format!("macfilter addr add {}", peers[1]));
        }
    }
    ok(sim, 1, "dataset init new");
    ok(sim, 1, "dataset commit active");
    ok(sim, 1, "ifconfig up");
    ok(sim, 1, "thread start");
    sim.run(20.0);
    assert_eq!(state(sim, 1), "leader");
    let tlv = ok(sim, 1, "dataset active -x")[0].clone();
    for id in [2, 3] {
        ok(sim, id, &format!("dataset set active {tlv}"));
        ok(sim, id, "ifconfig up");
    }
    ok(sim, 2, "thread start");
    sim.run(30.0);
    assert_eq!(state(sim, 2), "router");
    ok(sim, 3, "mode rn");
    ok(sim, 3, "childtimeout 120");
    ok(sim, 3, "thread start");
    sim.run(10.0);
    assert_eq!(state(sim, 3), "child");
    assert!(ok(sim, 1, "child table").iter().any(|l| l.contains(&e3)));

    let id = ok(sim, 1, "child list")[0].trim().to_string();
    let info = ok(sim, 1, &format!("child {id}"));
    assert_eq!(info[0], format!("Child ID: {id}"));
    assert!(info.contains(&"Mode: r".to_string()), "{info:?}");
    assert!(info.iter().any(|l| l.starts_with("Ext Addr: ")), "{info:?}");

    // Switch the MED over to the router.
    ok(sim, 1, &format!("macfilter addr remove {e3}"));
    ok(sim, 3, &format!("macfilter addr remove {e1}"));
    ok(sim, 2, &format!("macfilter addr add {e3}"));
    ok(sim, 3, &format!("macfilter addr add {e2}"));
    ok(sim, 3, "childtimeout 6");
    sim.run(40.0);
    assert!(
        ok(sim, 2, "child table").iter().any(|l| l.contains(&e3)),
        "child of the router"
    );
    assert!(
        !ok(sim, 1, "child table").iter().any(|l| l.contains(&e3)),
        "the leader dropped the child"
    );
    let c = ok(sim, 3, "counters mle");
    assert!(c.contains(&"Parent Changes: 1".to_string()), "{c:?}");
}
