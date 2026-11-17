//! `history netinfo|rx|tx|rxtx` print the lists in OpenThread's formats.
//! Skipped (passes) when a node binary is not built.

#![allow(clippy::std_instead_of_core)]

mod vt_common;

use vt_common::{Kind, env, ok, state};

#[test]
fn history_lists_and_tables() {
    let Some(mut e) = env("history", &[(1, Kind::Rust), (2, Kind::Rust)]) else {
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
    sim.run(60.0);
    assert_eq!(state(sim, 2), "router");

    let l = ok(sim, 1, "history netinfo list");
    assert!(l.len() >= 3, "{l:?}");
    assert!(l[0].contains("-> role:leader mode:rdn rloc16:0x"), "{l:?}");
    let t = ok(sim, 2, "history netinfo");
    assert!(t[0].starts_with("| Age"), "{t:?}");
    assert!(t[1].starts_with("+-----"), "{t:?}");
    assert!(t[2].contains("| router   | rdn  | 0x"), "{t:?}");

    let m2 = ok(sim, 2, "ipaddr mleid")[0].clone();
    let _ = sim.cmd(1, &format!("ping {m2} 10"));
    sim.run(2.0);
    let tx = ok(sim, 1, "history tx list");
    let i = tx
        .iter()
        .position(|l| l.contains("type:ICMP6(EchoReqst) len:18"))
        .unwrap_or_else(|| panic!("{tx:?}"));
    assert!(
        tx[i].contains("sec:yes prio:norm tx-success:yes to:0x"),
        "{tx:?}"
    );
    assert!(tx[i + 1].starts_with("    src:["), "{tx:?}");
    let rxtx = ok(sim, 1, "history rxtx");
    assert!(rxtx[0].starts_with("| Age"), "{rxtx:?}");
    assert!(
        rxtx.iter()
            .any(|l| l.contains("| ICMP6(EchoReply) ") && l.contains("| RX ")),
        "{rxtx:?}"
    );
    assert!(
        rxtx.iter()
            .any(|l| l.contains("| ICMP6(EchoReqst) ") && l.contains(" NA  | TX ")),
        "{rxtx:?}"
    );
}
