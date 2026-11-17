//! Interoperability: the OpenThread posix host (`ot-cli-posix`) running on
//! `opentrust-rcp-sim` as its RCP, together with an OpenThread simulation
//! node (`ot-cli-ftd-rt`) on the same real-time simulation radio.
//!
//! The OpenThread binaries come from `cargo build -p openthread-sys --features
//! posix-host` (installed in `<target>/ot-sim/`), or `OT_CLI_POSIX` /
//! `OT_CLI_FTD_RT` / `OT_RCP_RT`. The tests skip (with a message) when they
//! are not there. The simulation is in real time, so a test takes a while.

#![allow(clippy::std_instead_of_core, clippy::print_stderr)]

use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{Receiver, RecvTimeoutError, channel};
use std::time::{Duration, Instant};

fn target_dir() -> PathBuf {
    let exe = PathBuf::from(env!("CARGO_BIN_EXE_opentrust-rcp-sim"));
    exe.ancestors().nth(2).unwrap().to_path_buf()
}

fn tool(env: &str, name: &str) -> Option<PathBuf> {
    let p = std::env::var_os(env)
        .map(PathBuf::from)
        .unwrap_or_else(|| target_dir().join("ot-sim").join(name));
    p.is_file().then_some(p)
}

struct Node {
    child: Child,
    stdin: ChildStdin,
    lines: Receiver<String>,
}

impl Node {
    fn spawn(mut cmd: Command, port_offset: u16, dir: &std::path::Path) -> Self {
        let mut child = cmd
            .env("PORT_OFFSET", port_offset.to_string())
            .current_dir(dir)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("cannot start node");
        let stdin = child.stdin.take().unwrap();
        let stdout = child.stdout.take().unwrap();
        let (tx, lines) = channel();
        std::thread::spawn(move || {
            for l in BufReader::new(stdout).split(b'\n').map_while(Result::ok) {
                let l = String::from_utf8_lossy(&l)
                    .trim()
                    .trim_start_matches("> ")
                    .to_string();
                if tx.send(l).is_err() {
                    break;
                }
            }
        });
        Self {
            child,
            stdin,
            lines,
        }
    }

    /// Runs a CLI command; returns its output lines up to `Done` (or the
    /// `Error` line).
    fn cmd(&mut self, line: &str, timeout: Duration) -> Result<Vec<String>, String> {
        writeln!(self.stdin, "{line}").unwrap();
        let mut out = Vec::new();
        let end = Instant::now() + timeout;
        loop {
            let left = end.saturating_duration_since(Instant::now());
            match self.lines.recv_timeout(left) {
                Ok(l) if l == "Done" => return Ok(out),
                Ok(l) if l.starts_with("Error") => return Err(l),
                Ok(l) if l.is_empty() || l == line => {}
                Ok(l) => out.push(l),
                Err(RecvTimeoutError::Timeout) => return Err(format!("timeout: {out:?}")),
                Err(RecvTimeoutError::Disconnected) => return Err("node exited".into()),
            }
        }
    }

    /// Waits until the node's CLI answers (the posix host first starts and
    /// resets its RCP).
    fn wait_ready(&mut self) {
        let end = Instant::now() + Duration::from_secs(20);
        while Instant::now() < end {
            if self.cmd("version", Duration::from_secs(1)).is_ok() {
                return;
            }
        }
        panic!("the node's CLI does not answer");
    }

    fn ok(&mut self, line: &str) -> Vec<String> {
        self.cmd(line, Duration::from_secs(10))
            .unwrap_or_else(|e| panic!("`{line}`: {e}"))
    }

    fn wait_state(&mut self, wanted: &[&str], secs: u64) -> String {
        let end = Instant::now() + Duration::from_secs(secs);
        let mut last = String::new();
        while Instant::now() < end {
            std::thread::sleep(Duration::from_millis(500));
            last = self.ok("state").join("");
            if wanted.contains(&last.as_str()) {
                return last;
            }
        }
        panic!("state `{last}`, wanted one of {wanted:?}");
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

struct Tools {
    posix: PathBuf,
    ftd: PathBuf,
    rcp: PathBuf,
}

fn tools(rcp: PathBuf) -> Option<Tools> {
    let posix = tool("OT_CLI_POSIX", "ot-cli-posix");
    let ftd = tool("OT_CLI_FTD_RT", "ot-cli-ftd-rt");
    match (posix, ftd) {
        (Some(posix), Some(ftd)) => Some(Tools { posix, ftd, rcp }),
        _ => {
            eprintln!(
                "skipped: ot-cli-posix / ot-cli-ftd-rt not found \
                 (cargo build -p openthread-sys --features posix-host)"
            );
            None
        }
    }
}

fn work_dir(name: &str) -> PathBuf {
    let d = target_dir()
        .join("tmp")
        .join(format!("rcp-sim-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn mleid(n: &mut Node) -> String {
    n.ok("ipaddr mleid").into_iter().next().expect("no ML-EID")
}

/// Forms a network on `leader`, attaches `follower`, pings both ways.
fn network_and_pings(leader: &mut Node, follower: &mut Node) {
    leader.ok("dataset init new");
    leader.ok("dataset commit active");
    leader.ok("ifconfig up");
    leader.ok("thread start");
    leader.wait_state(&["leader"], 40);
    let dataset = leader.ok("dataset active -x").into_iter().next().unwrap();
    follower.ok(&format!("dataset set active {dataset}"));
    follower.ok("ifconfig up");
    follower.ok("thread start");
    follower.wait_state(&["child", "router"], 40);
    let (l, f) = (mleid(leader), mleid(follower));
    for (from, to, name) in [
        (&mut *leader, &f, "leader to follower"),
        (&mut *follower, &l, "follower to leader"),
    ] {
        let out = from
            .cmd(&format!("ping {to}"), Duration::from_secs(15))
            .unwrap_or_else(|e| panic!("ping {name}: {e}"));
        assert!(
            out.iter().any(|l| l.contains("1 packets received")),
            "ping {name}: {out:?}"
        );
    }
}

/// The posix host with the OpenTrust RCP forms the network, an OpenThread
/// simulation FTD joins it, and both ping each other.
#[test]
fn opentrust_rcp_leader_with_ot_ftd_child() {
    let rcp = PathBuf::from(env!("CARGO_BIN_EXE_opentrust-rcp-sim"));
    let Some(t) = tools(rcp) else { return };
    let dir = work_dir("leader");
    let offset = 60 + (std::process::id() % 500) as u16;
    let mut host_cmd = Command::new(&t.posix);
    host_cmd.arg(format!(
        "spinel+hdlc+forkpty://{}?forkpty-arg=1",
        t.rcp.display()
    ));
    let mut host = Node::spawn(host_cmd, offset, &dir);
    let mut ftd_cmd = Command::new(&t.ftd);
    ftd_cmd.arg("2");
    let mut ftd = Node::spawn(ftd_cmd, offset, &dir);
    host.wait_ready();
    ftd.wait_ready();
    network_and_pings(&mut host, &mut ftd);
    drop((host, ftd));
    let _ = std::fs::remove_dir_all(dir);
}

/// An OpenThread simulation FTD leads, the posix host with the OpenTrust RCP
/// attaches to it.
#[test]
fn opentrust_rcp_child_of_ot_ftd_leader() {
    let rcp = PathBuf::from(env!("CARGO_BIN_EXE_opentrust-rcp-sim"));
    let Some(t) = tools(rcp) else { return };
    let dir = work_dir("child");
    let offset = 560 + (std::process::id() % 500) as u16;
    let mut ftd_cmd = Command::new(&t.ftd);
    ftd_cmd.arg("2");
    let mut ftd = Node::spawn(ftd_cmd, offset, &dir);
    let mut host_cmd = Command::new(&t.posix);
    host_cmd.arg(format!(
        "spinel+hdlc+forkpty://{}?forkpty-arg=1",
        t.rcp.display()
    ));
    let mut host = Node::spawn(host_cmd, offset, &dir);
    host.wait_ready();
    ftd.wait_ready();
    network_and_pings(&mut ftd, &mut host);
    drop((host, ftd));
    let _ = std::fs::remove_dir_all(dir);
}
