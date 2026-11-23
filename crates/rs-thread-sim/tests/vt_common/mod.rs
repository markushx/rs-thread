//! Shared set-up of the mixed-network tests: a simulator on a free port range
//! and one working directory per node of every test.

#![allow(dead_code, clippy::std_instead_of_core)]

use std::path::PathBuf;
use std::sync::atomic::{AtomicU16, Ordering};

use rs_thread_sim::vtsim::{VtSim, ot_cli_ftd, rs_thread_cli_vt, rs_thread_cli_vt_mtd};

/// Which node binary runs a node ID.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Kind {
    /// OpenThread's `ot-cli-ftd`.
    Ot,
    /// `rs-thread-cli-vt` (FTD build).
    Rust,
    /// `rs-thread-cli-vt-mtd` (MTD build).
    Mtd,
}

impl From<bool> for Kind {
    fn from(is_rust: bool) -> Self {
        if is_rust { Kind::Rust } else { Kind::Ot }
    }
}

static NEXT: AtomicU16 = AtomicU16::new(0);

pub struct Env {
    pub sim: VtSim,
    dir: PathBuf,
}

/// A simulator with the given nodes, or `None` (the test passes) when a node
/// binary is not available. Every call gets its own port range and its own
/// directory, whatever its `name`.
pub fn env<K: Into<Kind> + Copy>(name: &str, kinds: &[(u16, K)]) -> Option<Env> {
    let ot = ot_cli_ftd().or_else(|| {
        eprintln!("skipping {name}: no ot-cli-ftd (cargo build -p openthread-sys)");
        None
    })?;
    let rust = rs_thread_cli_vt().or_else(|| {
        eprintln!("skipping {name}: rs-thread-cli-vt not available");
        None
    })?;
    let mtd = if kinds.iter().any(|(_, k)| (*k).into() == Kind::Mtd) {
        Some(rs_thread_cli_vt_mtd().or_else(|| {
            eprintln!("skipping {name}: rs-thread-cli-vt-mtd not available");
            None
        })?)
    } else {
        None
    };
    let n = NEXT.fetch_add(1, Ordering::SeqCst);
    let hint = (std::process::id() % 250) as u16 + n * 7;
    let mut sim = VtSim::new_free(hint).expect("simulator socket");
    let dir = std::env::temp_dir().join(format!(
        "rs-thread-vt-{}-{n}-{}",
        std::process::id(),
        name.replace(['/', ' '], "_")
    ));
    let _ = std::fs::remove_dir_all(&dir);
    for &(id, k) in kinds {
        let exe = match k.into() {
            Kind::Ot => &ot,
            Kind::Rust => &rust,
            Kind::Mtd => mtd.as_ref().expect("mtd binary"),
        };
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

pub fn ok(sim: &mut VtSim, id: u16, cmd: &str) -> Vec<String> {
    let out = sim.cmd(id, cmd);
    assert_eq!(
        out.last().map(String::as_str),
        Some("Done"),
        "node {id}: {cmd}: {out:?}"
    );
    out
}

pub fn state(sim: &mut VtSim, id: u16) -> String {
    sim.cmd(id, "state").first().cloned().unwrap_or_default()
}

pub fn mesh_local(sim: &mut VtSim, id: u16) -> String {
    let out = ok(sim, id, "ipaddr");
    out.iter()
        .find(|l| !l.starts_with("fe80") && !l.contains("ff:fe00") && l.starts_with("fd"))
        .cloned()
        .expect("mesh-local address")
}
