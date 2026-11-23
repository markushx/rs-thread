//! A sleepy end device that sets `mode -` before `thread start` attaches to an
//! OpenThread leader like an OpenThread sleepy device does: Parent Request
//! rounds at the OpenThread pace, every broadcast frame sent once, the
//! receiver on while the Parent and Child ID Responses are awaited. Skipped
//! (passes) when `ot-cli-ftd` is not built.

#![allow(clippy::std_instead_of_core)]

mod vt_common;

use vt_common::{Kind, env, ok, state};

/// What node 2 sent while attaching to the leader `1`.
struct Attach {
    /// Seconds from `thread start` until the state is `child`.
    attached_at: f64,
    /// Broadcast frames (destination 0xffff) of node 2: `(seconds, sequence
    /// number, length)`.
    broadcasts: Vec<(f64, u8, usize)>,
}

fn attach(kind: Kind, name: &str, csl: bool) -> Option<Attach> {
    let mut e = env(name, &[(1, Kind::Ot), (2, kind)])?;
    let sim = &mut e.sim;
    ok(sim, 1, "dataset init new");
    ok(sim, 1, "dataset commit active");
    ok(sim, 1, "ifconfig up");
    ok(sim, 1, "thread start");
    sim.run(40.0);
    assert_eq!(state(sim, 1), "leader");
    let tlv = ok(sim, 1, "dataset active -x")[0].clone();
    ok(sim, 2, "mode -");
    if csl {
        ok(sim, 2, "csl period 500000");
    }
    ok(sim, 2, &format!("dataset set active {tlv}"));
    ok(sim, 2, "ifconfig up");
    let t0 = sim.now_us();
    let first = sim.sniffed.len();
    ok(sim, 2, "thread start");
    let mut attached_at = None;
    for _ in 0..600 {
        sim.run(0.1);
        if state(sim, 2) == "child" {
            attached_at = Some((sim.now_us() - t0) as f64 / 1e6);
            break;
        }
    }
    let broadcasts = sim.sniffed[first..]
        .iter()
        .filter(|f| f.node == 2)
        .filter(|f| {
            // Short destination 0xffff after PAN ID, no ack request.
            let p = &f.psdu;
            p.len() > 8 && p[5..7] == [0xff, 0xff] && p[1] & 0x20 == 0
        })
        .map(|f| ((f.time - t0) as f64 / 1e6, f.psdu[2], f.psdu.len()))
        .collect();
    Some(Attach {
        attached_at: attached_at.expect("attached within 60 s"),
        broadcasts,
    })
}

fn report(label: &str, a: &Attach) {
    eprintln!(
        "{label}: attached after {:.2} s, {} broadcasts",
        a.attached_at,
        a.broadcasts.len()
    );
    for (t, seq, len) in &a.broadcasts {
        eprintln!("  {t:8.3} s seq {seq:3} len {len}");
    }
}

#[test]
fn sleepy_attach_is_as_quick_as_openthread() {
    let Some(ot) = attach(Kind::Ot, "sleepy-attach-ot", false) else {
        return;
    };
    let Some(rust) = attach(Kind::Rust, "sleepy-attach-rust", false) else {
        return;
    };
    report("OpenThread", &ot);
    report("RsThread", &rust);
    assert!(
        rust.attached_at <= ot.attached_at + 3.0,
        "RsThread attached after {:.2} s, OpenThread after {:.2} s",
        rust.attached_at,
        ot.attached_at
    );
    // A broadcast is sent once: no two frames of node 2 share a sequence
    // number.
    let mut seqs: Vec<u8> = rust.broadcasts.iter().map(|b| b.1).collect();
    seqs.sort_unstable();
    let n = seqs.len();
    seqs.dedup();
    assert_eq!(seqs.len(), n, "a broadcast was repeated");
}

/// Without a parent the Parent Request rounds of a sleepy device follow
/// OpenThread's: the same number of frames in the same time, each sent once.
#[test]
fn sleepy_parent_request_rounds_follow_openthread() {
    let mut rounds = Vec::new();
    for (kind, name) in [(Kind::Ot, "rounds-ot"), (Kind::Rust, "rounds-rust")] {
        let Some(mut e) = env(name, &[(1, Kind::Ot), (2, kind)]) else {
            return;
        };
        let sim = &mut e.sim;
        // A dataset of a network that is not there.
        ok(sim, 1, "dataset init new");
        ok(sim, 1, "dataset commit active");
        let tlv = ok(sim, 1, "dataset active -x")[0].clone();
        ok(sim, 2, "mode -");
        ok(sim, 2, &format!("dataset set active {tlv}"));
        ok(sim, 2, "ifconfig up");
        let t0 = sim.now_us();
        ok(sim, 2, "thread start");
        sim.run(40.0);
        let b: Vec<(f64, u8)> = sim
            .sniffed
            .iter()
            .filter(|f| f.node == 2)
            .map(|f| ((f.time - t0) as f64 / 1e6, f.psdu[2]))
            .collect();
        eprintln!("{name}: {b:.3?}");
        rounds.push(b);
    }
    let (ot, rust) = (&rounds[0], &rounds[1]);
    let mut seqs: Vec<u8> = rust.iter().map(|b| b.1).collect();
    let n = seqs.len();
    seqs.sort_unstable();
    seqs.dedup();
    assert_eq!(seqs.len(), n, "a frame was repeated");
    // The rounds of the two are offset by their random start: the last one may
    // fall inside the 40 s or not.
    assert!(
        rust.len().abs_diff(ot.len()) <= 2,
        "frames in 40 s: {} / {}",
        rust.len(),
        ot.len()
    );
}

/// The same with the CSL period set before the attach.
#[test]
fn sleepy_attach_with_csl_set_first() {
    let Some(rust) = attach(Kind::Rust, "sleepy-attach-csl", true) else {
        return;
    };
    report("RsThread, CSL first", &rust);
    assert!(
        rust.attached_at <= 5.0,
        "attached after {:.2} s",
        rust.attached_at
    );
}
