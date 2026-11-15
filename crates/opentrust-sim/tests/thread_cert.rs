//! Runs OpenThread's `thread-cert` cases (`tests/scripts/thread-cert/Cert_5_*`)
//! with `opentrust-cli-vt` standing in for `ot-cli-ftd` on some or all nodes,
//! in virtual time, and reports pass / fail per case and per configuration.
//!
//! Custom harness (`harness = false`). Heavy, so it does nothing unless
//! `OPENTRUST_CERT=1` is set (`cargo test -p opentrust-sim --test thread_cert`
//! passes and prints how to run it). Environment:
//!
//! - `OPENTRUST_CERT=1`: run.
//! - `OPENTRUST_CERT_CASES`: comma-separated substrings of case file names
//!   (default: `Cert_5_1_`, `Cert_5_2_`, `Cert_5_3_`).
//! - `OPENTRUST_CERT_CONFIGS`: which nodes are OpenTrust, comma-separated:
//!   `ot` (all OpenThread, the baseline), `each` (one run per node of the
//!   case with only that node OpenTrust), `all` (all OpenTrust). Default
//!   `ot,each`.
//! - `OPENTRUST_CERT_TIMEOUT`: seconds per run (default 300).
//! - `OPENTRUST_CERT_ALLOW_FAIL=1`: report failures but exit 0.
//! - `OPENTRUST_CERT_REPORT=<file>`: write the result table (markdown) there.
//! - `OPENTRUST_VENV`: Python virtual environment (default `<repo>/.venv`,
//!   created with `python3 -m venv` and `pip install` if missing).
//! - `OPENTHREAD_SRC`: OpenThread source tree (default the vendored one).
//! - `OT_CLI_PATH`: `ot-cli-ftd` (default `<target dir>/ot-sim/ot-cli-ftd`,
//!   built by `cargo build -p openthread-sys` when missing).
//!
//! Packet verification (`PACKET_VERIFICATION`, needs `tshark`) is off: the
//! cases run their CLI based checks only.

#![allow(clippy::std_instead_of_core)]

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use opentrust_sim::vtsim::{opentrust_cli_vt, ot_cli_ftd};

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// The checkout that owns the `.git` directory (the main one for a worktree).
fn main_checkout() -> Option<PathBuf> {
    let out = Command::new("git")
        .args(["rev-parse", "--path-format=absolute", "--git-common-dir"])
        .current_dir(root())
        .output()
        .ok()?;
    let p = PathBuf::from(String::from_utf8(out.stdout).ok()?.trim());
    p.parent().map(Path::to_path_buf)
}

fn openthread_src() -> Option<PathBuf> {
    if let Some(p) = std::env::var_os("OPENTHREAD_SRC") {
        return Some(p.into());
    }
    let rel = "tools/openthread-sys/vendor/openthread";
    [Some(root()), main_checkout()]
        .into_iter()
        .flatten()
        .map(|r| r.join(rel))
        .find(|p| p.join("tests/scripts/thread-cert").is_dir())
}

fn python_ok(py: &Path) -> bool {
    Command::new(py)
        .args(["-c", "import pexpect, Crypto, pyshark"])
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

/// A Python with the modules `thread-cert` imports; sets up the venv if
/// there is none.
fn python() -> Option<PathBuf> {
    let mut venvs: Vec<PathBuf> = Vec::new();
    if let Some(v) = std::env::var_os("OPENTRUST_VENV") {
        venvs.push(v.into());
    }
    venvs.push(root().join(".venv"));
    if let Some(m) = main_checkout() {
        venvs.push(m.join(".venv"));
    }
    for v in &venvs {
        let py = v.join("bin/python");
        if python_ok(&py) {
            return Some(py);
        }
    }
    // Create / complete the first venv candidate.
    let venv = &venvs[0];
    let py = venv.join("bin/python");
    if !py.is_file() {
        let ok = Command::new("python3")
            .args(["-m", "venv"])
            .arg(venv)
            .status()
            .is_ok_and(|s| s.success());
        if !ok {
            return None;
        }
    }
    // pyshark 0.4.6 is the API pktverify imports.
    let ok = Command::new(&py)
        .args(["-m", "pip", "install", "-q", "pexpect", "pycryptodome"])
        .args(["lxml", "pyshark==0.4.6"])
        .status()
        .is_ok_and(|s| s.success());
    (ok && python_ok(&py)).then_some(py)
}

fn ensure_ot_cli(src: &Path) -> Option<PathBuf> {
    if let Some(p) = ot_cli_ftd() {
        return Some(p);
    }
    eprintln!("building ot-cli-ftd (cargo build -p openthread-sys)");
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let ok = Command::new(cargo)
        .args(["build", "-q", "-p", "openthread-sys"])
        .env("OPENTHREAD_SRC", src)
        .current_dir(root())
        .status()
        .is_ok_and(|s| s.success());
    if ok { ot_cli_ftd() } else { None }
}

/// Nodes of a case (the keys of `TOPOLOGY`).
fn topology(py: &Path, cert_dir: &Path, case: &str) -> Vec<u32> {
    let code = "import sys, importlib\n\
        m = importlib.import_module(sys.argv[1])\n\
        c = [c for c in vars(m).values() if isinstance(c, type) and hasattr(c, 'TOPOLOGY') and c.__module__ == m.__name__][0]\n\
        print(' '.join(str(k) for k in c.TOPOLOGY))\n";
    let out = Command::new(py)
        .args(["-c", code, case])
        .env("PYTHONPATH", cert_dir)
        .stderr(Stdio::null())
        .output();
    out.ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| {
            s.split_whitespace()
                .filter_map(|n| n.parse().ok())
                .collect()
        })
        .unwrap_or_default()
}

struct Setup {
    py: PathBuf,
    cert_dir: PathBuf,
    ot: PathBuf,
    rust: PathBuf,
    work: PathBuf,
    timeout: Duration,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Outcome {
    Pass,
    Fail,
    Timeout,
}

/// Run one case; `rust_nodes` are the node IDs run by OpenTrust.
fn run_case(
    s: &Setup,
    case: &str,
    rust_nodes: &[u32],
    offset: u32,
    tag: &str,
) -> (Outcome, String) {
    let dir = s.work.join(format!("{case}-{tag}"));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("tmp")).unwrap();
    // `node.py` starts `$OT_CLI_PATH <node id>`: pick the program per node.
    let wrapper = dir.join("ot-cli-ftd");
    std::fs::write(
        &wrapper,
        "#!/bin/sh\ncase \",$OPENTRUST_NODES,\" in\n  *\",$1,\"*) exec \"$OPENTRUST_CLI_VT\" \"$1\" ;;\n  *) exec \"$OT_CLI_FTD\" \"$1\" ;;\nesac\n",
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut p = std::fs::metadata(&wrapper).unwrap().permissions();
        p.set_mode(0o755);
        std::fs::set_permissions(&wrapper, p).unwrap();
    }
    let nodes: Vec<String> = rust_nodes.iter().map(u32::to_string).collect();
    let mut child = Command::new(&s.py)
        .arg(s.cert_dir.join(format!("{case}.py")))
        .current_dir(&dir)
        .env("PYTHONPATH", &s.cert_dir)
        .env("PYTHONUNBUFFERED", "1")
        .env("OT_CLI_PATH", &wrapper)
        .env("OT_CLI_FTD", &s.ot)
        .env("OPENTRUST_CLI_VT", &s.rust)
        .env("OPENTRUST_NODES", nodes.join(","))
        .env("THREAD_VERSION", "1.4")
        .env("VIRTUAL_TIME", "1")
        .env("PORT_OFFSET", offset.to_string())
        .env("TEST_NAME", format!("{case}-{tag}"))
        .env_remove("PACKET_VERIFICATION")
        .stdin(Stdio::null())
        .stdout(Stdio::from(
            std::fs::File::create(dir.join("out.log")).unwrap(),
        ))
        .stderr(Stdio::from(
            std::fs::File::create(dir.join("err.log")).unwrap(),
        ))
        .spawn()
        .expect("python");
    let start = Instant::now();
    let outcome = loop {
        match child.try_wait() {
            Ok(Some(st)) => {
                break if st.success() {
                    Outcome::Pass
                } else {
                    Outcome::Fail
                };
            }
            Ok(None) if start.elapsed() > s.timeout => {
                let _ = child.kill();
                let _ = child.wait();
                break Outcome::Timeout;
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(50)),
            Err(_) => break Outcome::Fail,
        }
    };
    // The reason: the last error line of the log.
    let err = std::fs::read_to_string(dir.join("err.log")).unwrap_or_default();
    let reason = err
        .lines()
        .rev()
        .find(|l| {
            l.contains("Error")
                || l.contains("Exception")
                || l.contains("FAILED")
                || l.contains("assert")
        })
        .unwrap_or("")
        .trim()
        .chars()
        .take(160)
        .collect::<String>();
    (outcome, reason)
}

fn main() {
    if std::env::var("OPENTRUST_CERT").as_deref() != Ok("1") {
        println!("thread-cert run skipped: set OPENTRUST_CERT=1 (see the header of this file)");
        return;
    }
    let skip = |why: &str| {
        println!("thread-cert run skipped: {why}");
    };
    let Some(src) = openthread_src() else {
        return skip("OpenThread source tree not found (git submodule update --init)");
    };
    let cert_dir = src.join("tests/scripts/thread-cert");
    let Some(py) = python() else {
        return skip("no Python with pexpect, pycryptodome and pyshark");
    };
    let Some(ot) = ensure_ot_cli(&src) else {
        return skip("no ot-cli-ftd (cargo build -p openthread-sys needs cmake and ninja)");
    };
    let Some(rust) = opentrust_cli_vt() else {
        return skip("cannot build opentrust-cli-vt");
    };
    let work = std::env::temp_dir().join(format!("opentrust-cert-{}", std::process::id()));
    let setup = Setup {
        py,
        cert_dir: cert_dir.clone(),
        ot,
        rust,
        work: work.clone(),
        timeout: Duration::from_secs(
            std::env::var("OPENTRUST_CERT_TIMEOUT")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(300),
        ),
    };
    let patterns: Vec<String> = std::env::var("OPENTRUST_CERT_CASES")
        .unwrap_or_else(|_| "Cert_5_1_,Cert_5_2_,Cert_5_3_".into())
        .split(',')
        .map(str::to_string)
        .collect();
    let configs: Vec<String> = std::env::var("OPENTRUST_CERT_CONFIGS")
        .unwrap_or_else(|_| "ot,each".into())
        .split(',')
        .map(str::to_string)
        .collect();
    let mut cases: Vec<String> = std::fs::read_dir(&cert_dir)
        .unwrap()
        .filter_map(|e| e.ok()?.file_name().into_string().ok())
        .filter_map(|n| n.strip_suffix(".py").map(str::to_string))
        .filter(|n| patterns.iter().any(|p| n.contains(p.as_str())))
        .collect();
    cases.sort();

    let mut table = String::from("| case | run | result | reason |\n|---|---|---|---|\n");
    let (mut pass, mut fail) = (0, 0);
    // The simulator treats ports of 18000 and above as non-radio: 1..=250.
    let mut offset = 1 + std::process::id() % 250;
    for case in &cases {
        let nodes = topology(&setup.py, &cert_dir, case);
        let mut runs: Vec<(String, Vec<u32>)> = Vec::new();
        for c in &configs {
            match c.as_str() {
                "ot" => runs.push(("all OT".into(), vec![])),
                "all" => runs.push(("all OpenTrust".into(), nodes.clone())),
                "each" => {
                    for &n in &nodes {
                        runs.push((format!("node {n} OpenTrust"), vec![n]));
                    }
                }
                _ => {}
            }
        }
        for (label, rust_nodes) in runs {
            offset = 1 + offset % 250;
            let tag = label.replace(' ', "-");
            let (o, reason) = run_case(&setup, case, &rust_nodes, offset, &tag);
            let name = match o {
                Outcome::Pass => "pass",
                Outcome::Fail => "FAIL",
                Outcome::Timeout => "TIMEOUT",
            };
            println!("{case} [{label}]: {name} {reason}");
            if o == Outcome::Pass {
                pass += 1;
            } else {
                fail += 1;
            }
            table.push_str(&format!(
                "| {case} | {label} | {name} | {} |\n",
                reason.replace('|', "/")
            ));
        }
    }
    println!(
        "\n{table}\nthread-cert: {pass} passed, {fail} failed (logs in {})",
        work.display()
    );
    if let Some(p) = std::env::var_os("OPENTRUST_CERT_REPORT") {
        let _ = std::fs::write(p, &table);
    }
    if fail > 0 && std::env::var("OPENTRUST_CERT_ALLOW_FAIL").as_deref() != Ok("1") {
        std::process::exit(1);
    }
}
