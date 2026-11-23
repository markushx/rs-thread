//! Runs OpenThread's `thread-cert` cases (`tests/scripts/thread-cert/Cert_5_*`)
//! with `rs-thread-cli-vt` standing in for `ot-cli-ftd` on some or all nodes,
//! in virtual time, and reports pass / fail per case and per configuration.
//!
//! Custom harness (`harness = false`). Heavy, so it does nothing unless
//! `RSTHREAD_CERT=1` is set (`cargo test -p rs-thread-sim --test thread_cert`
//! passes and prints how to run it). Environment:
//!
//! - `RSTHREAD_CERT=1`: run.
//! - `RSTHREAD_CERT_CASES`: comma-separated substrings of case file names
//!   (default: `Cert_5_1_`, `Cert_5_2_`, `Cert_5_3_`; the commissioning and
//!   dataset cases are `Cert_8_`, `Cert_9_2_`). The cases read the `[THCI]`
//!   commissioning lines from the CLI output, so `ot-cli-ftd` must log
//!   through the CLI (`openthread-sys` builds it with `OT_LOG_OUTPUT=APP`).
//! - `RSTHREAD_CERT_CONFIGS`: which nodes are rs-thread, comma-separated:
//!   `ot` (all OpenThread, the baseline), `each` (one run per node of the
//!   case with only that node rs-thread), `all` (all rs-thread), `mtd:3`
//!   or `mtd:3+4` (those nodes run `rs-thread-cli-vt-mtd`, the build without
//!   router, commissioner and Border Agent; OpenThread for the others),
//!   `set:2+4` (exactly those nodes rs-thread, the others OpenThread),
//!   `half` (every other node of the case rs-thread, starting with the first:
//!   about 50 %), `half2` (the other half).
//!   Default `ot,half,all` (0 %, 50 %, 100 % rs-thread).
//! - `RSTHREAD_CERT_TIMEOUT`: seconds per run (default 300).
//! - `RSTHREAD_CERT_ALLOW_FAIL=1`: report failures but exit 0.
//! - `RSTHREAD_CERT_REPORT=<file>`: write the result table (markdown) there.
//! - `RSTHREAD_VENV`: Python virtual environment (default `<repo>/.venv`,
//!   created with `python3 -m venv` and `pip install` if missing).
//! - `OPENTHREAD_SRC`: OpenThread source tree (default the vendored one).
//! - `OT_CLI_PATH`: `ot-cli-ftd` (default `<target dir>/ot-sim/ot-cli-ftd`,
//!   built by `cargo build -p openthread-sys` when missing). Nodes with
//!   `'version': '1.1'` run `ot-cli-ftd-1.1` (a Thread 1.1 build next to it)
//!   in every configuration.
//!
//! Packet verification (`PACKET_VERIFICATION`, needs `tshark`) is off unless
//! `RSTHREAD_CERT_PKTVERIFY=1`: the cases then also verify the captured packets.
//! `tshark` is linked into `/tmp/thread-wireshark` (where `pktverify` looks).
//! On macOS `tests/cert_pyshim/sitecustomize.py` makes `os.uname()` report
//! Linux, which `thread_cert.py` insists on, and adapts `pktverify` and
//! `pyshark` to Python 3.14 and `tshark` 4.6.

#![allow(clippy::std_instead_of_core)]

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use rs_thread_sim::vtsim::{rs_thread_cli_vt, rs_thread_cli_vt_mtd, ot_cli_ftd};

/// Packet verification with `tshark`: `RSTHREAD_CERT_PKTVERIFY=1`.
fn pktverify() -> bool {
    std::env::var("RSTHREAD_CERT_PKTVERIFY").as_deref() == Ok("1")
}

/// `PYTHONPATH` of a run: the `thread-cert` directory, plus a
/// `sitecustomize` that makes `os.uname()` report Linux on macOS, where
/// `thread_cert.py` would refuse to verify packets.
fn python_path(cert_dir: &Path) -> std::ffi::OsString {
    let shim = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/cert_pyshim");
    std::env::join_paths([shim.as_path(), cert_dir]).unwrap_or_else(|_| cert_dir.into())
}

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
    if let Some(v) = std::env::var_os("RSTHREAD_VENV") {
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
    mtd: Option<PathBuf>,
    work: PathBuf,
    timeout: Duration,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Outcome {
    Pass,
    Fail,
    Timeout,
}

/// Run one case; `rust_nodes` are the node IDs run by rs-thread, `mtd_nodes`
/// those run by its MTD build (`rs-thread-cli-vt-mtd`).
fn run_case(
    s: &Setup,
    case: &str,
    rust_nodes: &[u32],
    mtd_nodes: &[u32],
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
        "#!/bin/sh\ncase \",$RSTHREAD_MTD_NODES,\" in\n  *\",$1,\"*) exec \"$RSTHREAD_CLI_VT_MTD\" \"$1\" ;;\nesac\ncase \",$RSTHREAD_NODES,\" in\n  *\",$1,\"*) exec \"$RSTHREAD_CLI_VT\" \"$1\" ;;\n  *) exec \"$OT_CLI_FTD\" \"$1\" ;;\nesac\n",
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut p = std::fs::metadata(&wrapper).unwrap().permissions();
        p.set_mode(0o755);
        std::fs::set_permissions(&wrapper, p).unwrap();
    }
    // Thread 1.1 nodes of the interoperability cases (`'version': '1.1'`)
    // always run OpenThread's Thread 1.1 build, next to `ot-cli-ftd`.
    let wrapper11 = dir.join("ot-cli-ftd-1.1");
    let ot11 = s.ot.with_file_name("ot-cli-ftd-1.1");
    std::fs::write(
        &wrapper11,
        format!("#!/bin/sh\nexec \"{}\" \"$1\"\n", ot11.display()),
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut p = std::fs::metadata(&wrapper11).unwrap().permissions();
        p.set_mode(0o755);
        std::fs::set_permissions(&wrapper11, p).unwrap();
    }
    let nodes: Vec<String> = rust_nodes.iter().map(u32::to_string).collect();
    let mtd: Vec<String> = mtd_nodes.iter().map(u32::to_string).collect();
    let mut child = Command::new(&s.py)
        .arg(s.cert_dir.join(format!("{case}.py")))
        .current_dir(&dir)
        .env("PYTHONPATH", python_path(&s.cert_dir))
        .env("PYTHONUNBUFFERED", "1")
        .env(
            "RSTHREAD_FAKE_LINUX_UNAME",
            if cfg!(target_os = "macos") { "1" } else { "0" },
        )
        .env("OT_CLI_PATH", &wrapper)
        .env("OT_CLI_PATH_1_1", &wrapper11)
        .env("OT_CLI_FTD", &s.ot)
        .env("RSTHREAD_CLI_VT", &s.rust)
        .env("RSTHREAD_NODES", nodes.join(","))
        .env("RSTHREAD_CLI_VT_MTD", s.mtd.as_deref().unwrap_or(&s.rust))
        .env("RSTHREAD_MTD_NODES", mtd.join(","))
        .env("THREAD_VERSION", "1.4")
        .env("VIRTUAL_TIME", "1")
        .env("PORT_OFFSET", offset.to_string())
        .env("TEST_NAME", format!("{case}-{tag}"))
        .env("PACKET_VERIFICATION", if pktverify() { "1" } else { "0" })
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

/// `pktverify` looks for `tshark`, `dumpcap` and `mergecap` in the fixed
/// directory `/tmp/thread-wireshark`: link the installed ones there.
fn link_wireshark() {
    let dir = Path::new("/tmp/thread-wireshark");
    if dir.join("tshark").exists() {
        return;
    }
    let _ = std::fs::create_dir_all(dir);
    let path = std::env::var_os("PATH").unwrap_or_default();
    let mut search: Vec<PathBuf> = std::env::split_paths(&path).collect();
    search.push("/opt/homebrew/bin".into());
    search.push("/usr/local/bin".into());
    for tool in ["tshark", "dumpcap", "mergecap"] {
        if let Some(found) = search.iter().map(|d| d.join(tool)).find(|p| p.exists()) {
            #[cfg(unix)]
            let _ = std::os::unix::fs::symlink(found, dir.join(tool));
        }
    }
}

fn main() {
    if std::env::var("RSTHREAD_CERT").as_deref() != Ok("1") {
        println!("thread-cert run skipped: set RSTHREAD_CERT=1 (see the header of this file)");
        return;
    }
    if pktverify() {
        link_wireshark();
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
    let Some(rust) = rs_thread_cli_vt() else {
        return skip("cannot build rs-thread-cli-vt");
    };
    let mtd = rs_thread_cli_vt_mtd();
    let work = std::env::temp_dir().join(format!("rs-thread-cert-{}", std::process::id()));
    let setup = Setup {
        py,
        cert_dir: cert_dir.clone(),
        ot,
        rust,
        mtd,
        work: work.clone(),
        timeout: Duration::from_secs(
            std::env::var("RSTHREAD_CERT_TIMEOUT")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(300),
        ),
    };
    let patterns: Vec<String> = std::env::var("RSTHREAD_CERT_CASES")
        .unwrap_or_else(|_| "Cert_5_1_,Cert_5_2_,Cert_5_3_".into())
        .split(',')
        .map(str::to_string)
        .collect();
    let configs: Vec<String> = std::env::var("RSTHREAD_CERT_CONFIGS")
        .unwrap_or_else(|_| "ot,half,all".into())
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
        let mut runs: Vec<(String, Vec<u32>, Vec<u32>)> = Vec::new();
        for c in &configs {
            match c.as_str() {
                "ot" => runs.push(("all OT".into(), vec![], vec![])),
                "all" => runs.push(("all RsThread".into(), nodes.clone(), vec![])),
                // About 50 % rs-thread: every other node (and its complement).
                "half" | "half2" => {
                    let first = usize::from(c == "half2");
                    let ids: Vec<u32> = nodes.iter().copied().skip(first).step_by(2).collect();
                    if !ids.is_empty() {
                        let label = ids.iter().map(u32::to_string).collect::<Vec<_>>().join("+");
                        runs.push((format!("nodes {label} RsThread"), ids, vec![]));
                    }
                }
                "each" => {
                    for &n in &nodes {
                        runs.push((format!("node {n} RsThread"), vec![n], vec![]));
                    }
                }
                // `set:2+4`: exactly those nodes are rs-thread.
                m if m.starts_with("set:") => {
                    let ids: Vec<u32> = m[4..].split('+').filter_map(|v| v.parse().ok()).collect();
                    if ids.iter().all(|i| nodes.contains(i)) {
                        runs.push((format!("nodes {} RsThread", &m[4..]), ids, vec![]));
                    }
                }
                // `mtd:3` or `mtd:3+4`: those nodes run the MTD build.
                m if m.starts_with("mtd:") => {
                    let ids: Vec<u32> = m[4..].split('+').filter_map(|v| v.parse().ok()).collect();
                    if ids.iter().all(|i| nodes.contains(i)) {
                        runs.push((format!("node {} RsThread MTD", &m[4..]), vec![], ids));
                    }
                }
                _ => {}
            }
        }
        for (label, rust_nodes, mtd_nodes) in runs {
            offset = 1 + offset % 250;
            let tag = label.replace(' ', "-");
            let (o, reason) = run_case(&setup, case, &rust_nodes, &mtd_nodes, offset, &tag);
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
    if let Some(p) = std::env::var_os("RSTHREAD_CERT_REPORT") {
        let _ = std::fs::write(p, &table);
    }
    if fail > 0 && std::env::var("RSTHREAD_CERT_ALLOW_FAIL").as_deref() != Ok("1") {
        std::process::exit(1);
    }
}
