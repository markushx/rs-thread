//! A Rust port of the virtual-time simulator of OpenThread's `thread-cert`
//! suite (`simulator.py`, class `VirtualTime`) and a driver for node
//! processes behind it: OpenThread's `ot-cli-ftd` (simulation platform,
//! virtual time) and the OpenTrust node `opentrust-cli-vt`, in any mix. It
//! lets `cargo test` run mixed networks without Python.
//!
//! The simulator owns the virtual clock. A node process reports the time of
//! its next alarm and blocks; the simulator advances to the earliest event of
//! all nodes, hands it to the node and waits until that node reports its next
//! alarm again (see [`crate::vt`] for the wire format). Frames sent by a node
//! are queued for all other nodes at the same time (and echoed to the sender
//! as the transmit-done); ACK frames only go to the nodes that sent the
//! frame with that sequence number.

#![allow(clippy::std_instead_of_core)]

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::io::{self, BufRead, Write};
use std::net::{SocketAddr, UdpSocket};
use std::path::Path;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{Receiver, channel};
use std::time::Duration as StdDuration;

use crate::vt::{EV_ALARM, EV_RADIO};

const MAX_NODES: u16 = 33;

/// Held while a simulator probes for free node ports ([`VtSim::new_free`]) and
/// while a node starts ([`VtSim::spawn`]): the probe binds the node ports for a
/// moment, and a node that starts then finds its port taken and exits.
static PORT_CLAIM: std::sync::Mutex<()> = std::sync::Mutex::new(());
const END_OF_TIME: u64 = u64::MAX;

#[derive(Debug, Clone)]
struct Ev {
    time: u64,
    seq: u64,
    port: u16,
    kind: u8,
    data: Vec<u8>,
}

#[derive(Debug)]
struct Dev {
    alarm: Option<u64>,
    time: u64,
}

/// A frame seen on the air.
#[derive(Debug, Clone)]
pub struct Sniffed {
    /// Virtual time in microseconds.
    pub time: u64,
    /// Sender node ID.
    pub node: u16,
    /// Channel.
    pub channel: u8,
    /// PSDU with FCS.
    pub psdu: Vec<u8>,
}

#[derive(Debug)]
struct Proc {
    child: Child,
    stdin: ChildStdin,
    lines: Receiver<String>,
}

/// The simulator and its node processes.
#[derive(Debug)]
pub struct VtSim {
    sock: UdpSocket,
    port: u16,
    devices: BTreeMap<u16, Dev>,
    queue: Vec<Ev>,
    seq: u64,
    current_time: u64,
    pause_time: u64,
    current_event: Option<(u16, u64)>,
    awake: BTreeSet<u16>,
    nodes_by_ack_seq: HashMap<u8, BTreeSet<u16>>,
    node_ack_seq: HashMap<u16, u8>,
    procs: BTreeMap<u16, Proc>,
    /// Every frame sent so far.
    pub sniffed: Vec<Sniffed>,
    offset: u16,
}

struct FrameInfo {
    ack: bool,
    seq: u8,
    broadcast: bool,
}

fn dissect(data: &[u8]) -> Option<FrameInfo> {
    if data.len() < 4 {
        return None;
    }
    let fcf = u16::from_le_bytes([data[1], data[2]]);
    let dst_mode = (fcf & 0x0c00) >> 10;
    let mut dst_short = None;
    if dst_mode == 2 || dst_mode == 3 {
        let mut off = 4;
        let pan_present = if fcf & 0x3000 == 0x2000 {
            let v = fcf & (0x0c00 | 0xc000 | 0x0040);
            ![
                0,
                0x0c00 | 0x0040,
                0x0800 | 0x0040,
                0xc000,
                0x8000,
                0xc000 | 0x0040,
                0x8000 | 0x0040,
                0x0c00 | 0xc000 | 0x0040,
            ]
            .contains(&v)
        } else {
            true
        };
        if pan_present {
            off += 2;
        }
        if dst_mode == 2 {
            dst_short = data
                .get(off..off + 2)
                .map(|b| u16::from_le_bytes([b[0], b[1]]));
        }
    }
    Some(FrameInfo {
        ack: fcf & 7 == 2,
        seq: data[3],
        broadcast: dst_mode == 2 && dst_short == Some(0xffff),
    })
}

impl VtSim {
    /// A simulator on `PORT_BASE` (9000) + `offset` * 34. Child processes
    /// get the same `PORT_OFFSET`.
    pub fn new(offset: u16) -> io::Result<Self> {
        let port = 9000 + offset * (MAX_NODES + 1);
        let sock = UdpSocket::bind(("127.0.0.1", port))?;
        Ok(Self {
            sock,
            port,
            devices: BTreeMap::new(),
            queue: Vec::new(),
            seq: 0,
            current_time: 0,
            pause_time: 0,
            current_event: None,
            awake: BTreeSet::new(),
            nodes_by_ack_seq: HashMap::new(),
            node_ack_seq: HashMap::new(),
            procs: BTreeMap::new(),
            sniffed: Vec::new(),
            offset,
        })
    }

    /// A simulator on the first free `PORT_OFFSET`, searching from `hint`
    /// (modulo the 250 offsets whose ports stay below the ephemeral range).
    /// Free means that the simulator port can be bound and that none of the
    /// ports of the 33 nodes of that offset is in use, so simulators of
    /// parallel tests (or of several test processes) never share a port.
    /// The bound socket of the simulator keeps its offset claimed.
    pub fn new_free(hint: u16) -> io::Result<Self> {
        let _claim = PORT_CLAIM.lock().unwrap_or_else(|e| e.into_inner());
        let mut last = None;
        for k in 0..250 {
            let offset = 1 + (hint + k) % 250;
            let port = 9000 + offset * (MAX_NODES + 1);
            let nodes_free =
                (1..=MAX_NODES).all(|n| UdpSocket::bind(("0.0.0.0", port + n)).is_ok());
            if !nodes_free {
                continue;
            }
            match Self::new(offset) {
                Ok(sim) => return Ok(sim),
                Err(e) => last = Some(e),
            }
        }
        Err(last.unwrap_or_else(|| io::Error::other("no free PORT_OFFSET")))
    }

    /// Virtual time in microseconds.
    pub fn now_us(&self) -> u64 {
        self.current_time
    }

    /// Start node `id` with `exe` (`ot-cli-ftd` or `opentrust-cli-vt`) in
    /// `cwd`; returns when the node has reported its first alarm.
    pub fn spawn(&mut self, id: u16, exe: &Path, cwd: &Path) -> io::Result<()> {
        let _claim = PORT_CLAIM.lock().unwrap_or_else(|e| e.into_inner());
        std::fs::create_dir_all(cwd)?;
        let mut child = Command::new(exe)
            .arg(id.to_string())
            .current_dir(cwd)
            .env("PORT_OFFSET", self.offset.to_string())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()?;
        let stdin = child.stdin.take().unwrap();
        let stdout = child.stdout.take().unwrap();
        let (tx, lines) = channel();
        std::thread::spawn(move || {
            // Prompts have no line end: a line ends at CR LF; "> " in front
            // of a line is the prompt of the previous command.
            let mut r = io::BufReader::new(stdout);
            let mut buf = Vec::new();
            while let Ok(n) = r.read_until(b'\n', &mut buf) {
                if n == 0 {
                    break;
                }
                let mut s = String::from_utf8_lossy(&buf).into_owned();
                buf.clear();
                while s.ends_with(['\r', '\n']) {
                    s.pop();
                }
                while let Some(rest) = s.strip_prefix("> ") {
                    s = rest.to_string();
                }
                if tx.send(s).is_err() {
                    break;
                }
            }
        });
        self.procs.insert(
            id,
            Proc {
                child,
                stdin,
                lines,
            },
        );
        self.go(0, Some(id));
        Ok(())
    }

    /// Stop node `id`.
    pub fn kill(&mut self, id: u16) {
        if let Some(mut p) = self.procs.remove(&id) {
            let _ = p.child.kill();
            let _ = p.child.wait();
        }
        let port = self.port + id;
        self.devices.remove(&port);
        self.awake.remove(&port);
        self.queue.retain(|e| e.port != port);
    }

    /// Send `line` to node `id` and let the node process it (virtual time
    /// does not advance); the output is read with [`drain`](Self::drain).
    pub fn send(&mut self, id: u16, line: &str) {
        {
            let p = self.procs.get_mut(&id).expect("node not running");
            while p.lines.try_recv().is_ok() {}
            p.stdin
                .write_all(format!("{line}\n").as_bytes())
                .expect("write to node");
            p.stdin.flush().ok();
        }
        self.go(0, Some(id));
    }

    /// Run `line` on node `id` and collect its output up to and including
    /// `Done` or `Error ...` (the echo of the command is dropped). For
    /// commands that complete at once; `ping` and `scan` need
    /// [`send`](Self::send), [`run`](Self::run) and [`drain`](Self::drain).
    pub fn cmd(&mut self, id: u16, line: &str) -> Vec<String> {
        self.send(id, line);
        let mut out = Vec::new();
        let p = &self.procs[&id];
        while let Ok(l) = p.lines.recv_timeout(StdDuration::from_secs(10)) {
            if out.is_empty() && l == line {
                continue;
            }
            let done = l == "Done" || l.starts_with("Error ");
            out.push(l);
            if done {
                break;
            }
        }
        out
    }

    /// Output lines a node printed on its own (ping replies, scan results) since
    /// the last call.
    pub fn drain(&mut self, id: u16) -> Vec<String> {
        let p = &self.procs[&id];
        let mut v = Vec::new();
        while let Ok(l) = p.lines.try_recv() {
            if !l.is_empty() {
                v.push(l);
            }
        }
        v
    }

    /// Advance virtual time by `secs` seconds.
    pub fn run(&mut self, secs: f64) {
        self.go((secs * 1_000_000.0) as u64, None);
    }

    fn next_event_time(&self) -> u64 {
        self.queue.first().map_or(END_OF_TIME, |e| e.time)
    }

    fn insert(&mut self, e: Ev) {
        let pos = self
            .queue
            .partition_point(|x| (x.time, x.seq) <= (e.time, e.seq));
        self.queue.insert(pos, e);
    }

    fn new_seq(&mut self) -> u64 {
        self.seq += 1;
        self.seq
    }

    fn receive(&mut self, blocking: bool) -> Option<(Vec<u8>, u16)> {
        let mut buf = [0u8; 2048];
        if blocking {
            self.sock.set_nonblocking(false).ok()?;
            self.sock
                .set_read_timeout(Some(StdDuration::from_secs(10)))
                .ok()?;
        } else {
            self.sock.set_nonblocking(true).ok()?;
        }
        match self.sock.recv_from(&mut buf) {
            Ok((n, SocketAddr::V4(a))) => Some((buf[..n].to_vec(), a.port())),
            _ => None,
        }
    }

    fn process_events(&mut self) {
        let mut idle_rounds = 0;
        loop {
            let blocking = self.current_event.is_some() || !self.awake.is_empty();
            match self.receive(blocking) {
                Some((msg, port)) => {
                    idle_rounds = 0;
                    if !self.devices.contains_key(&port) {
                        self.devices.insert(
                            port,
                            Dev {
                                alarm: None,
                                time: self.current_time,
                            },
                        );
                        self.awake.remove(&port);
                    }
                    self.process_event(&msg, port);
                }
                None if blocking => {
                    idle_rounds += 1;
                    assert!(
                        idle_rounds < 6,
                        "simulator: no node answers (awake {:?}, current event {:?})",
                        self.awake,
                        self.current_event
                    );
                }
                None => return,
            }
        }
    }

    fn process_event(&mut self, msg: &[u8], port: u16) {
        if msg.len() < 11 {
            return;
        }
        let delay = u64::from_ne_bytes(msg[..8].try_into().unwrap());
        let kind = msg[8];
        if std::env::var_os("VTS_TRACE").is_some() {
            eprintln!(
                "VTS off{} t={} node {} kind {} delay {} pause {}",
                self.offset,
                self.current_time,
                port - self.port,
                kind,
                delay,
                self.pause_time
            );
        }
        let data = msg[11..].to_vec();
        let event_time = self.current_time.saturating_add(delay);
        match kind {
            EV_ALARM => {
                if let Some(old) = self.devices.get_mut(&port).and_then(|d| d.alarm.take()) {
                    self.queue.retain(|e| e.seq != old);
                }
                let seq = self.new_seq();
                self.insert(Ev {
                    time: event_time,
                    seq,
                    port,
                    kind,
                    data: Vec::new(),
                });
                self.devices.get_mut(&port).unwrap().alarm = Some(seq);
                self.awake.remove(&port);
                if self.current_event.is_some_and(|(p, _)| p == port) {
                    self.current_event = None;
                }
            }
            EV_RADIO => {
                let info = dissect(&data);
                let mut recv: Option<BTreeSet<u16>> = None;
                if let Some(i) = &info
                    && i.ack
                {
                    recv = self.nodes_by_ack_seq.get(&i.seq).cloned();
                }
                let recv = recv.unwrap_or_else(|| self.devices.keys().copied().collect());
                for d in recv {
                    if d != port {
                        let seq = self.new_seq();
                        self.insert(Ev {
                            time: event_time,
                            seq,
                            port: d,
                            kind,
                            data: data.clone(),
                        });
                    }
                }
                self.sniffed.push(Sniffed {
                    time: event_time,
                    node: port - self.port,
                    channel: data.first().copied().unwrap_or(0),
                    psdu: data.get(1..).unwrap_or(&[]).to_vec(),
                });
                let seq = self.new_seq();
                self.insert(Ev {
                    time: event_time,
                    seq,
                    port,
                    kind,
                    data: data.clone(),
                });
                if let Some(i) = info
                    && !i.ack
                    && !i.broadcast
                {
                    if let Some(old) = self.node_ack_seq.remove(&port)
                        && let Some(s) = self.nodes_by_ack_seq.get_mut(&old)
                    {
                        s.remove(&port);
                    }
                    self.node_ack_seq.insert(port, i.seq);
                    self.nodes_by_ack_seq.entry(i.seq).or_default().insert(port);
                }
                self.awake.insert(port);
            }
            _ => {}
        }
    }

    fn process_next_event(&mut self) {
        let e = self.queue.remove(0);
        self.current_event = Some((e.port, e.seq));
        assert!(e.time >= self.current_time);
        self.current_time = e.time;
        let dev = self.devices.get_mut(&e.port).unwrap();
        let elapsed = e.time - dev.time;
        dev.time = e.time;
        if e.kind == EV_ALARM {
            dev.alarm = None;
        }
        let mut m = Vec::with_capacity(11 + e.data.len());
        m.extend_from_slice(&elapsed.to_ne_bytes());
        m.push(e.kind);
        m.extend_from_slice(&(e.data.len() as u16).to_ne_bytes());
        m.extend_from_slice(&e.data);
        let _ = self.sock.send_to(&m, ("127.0.0.1", e.port));
    }

    fn sync_devices(&mut self) {
        self.current_time = self.pause_time;
        let ports: Vec<u16> = self.devices.keys().copied().collect();
        for port in ports {
            let dev = self.devices.get_mut(&port).unwrap();
            let elapsed = self.current_time - dev.time;
            if elapsed == 0 {
                continue;
            }
            dev.time = self.current_time;
            let mut m = Vec::new();
            m.extend_from_slice(&elapsed.to_ne_bytes());
            m.push(EV_ALARM);
            m.extend_from_slice(&0u16.to_ne_bytes());
            let _ = self.sock.send_to(&m, ("127.0.0.1", port));
            self.awake.insert(port);
            self.process_events();
        }
        self.awake.clear();
    }

    /// Take in the events nodes sent that are still on their way. After a
    /// console command a node may send a second sleep event (OpenThread's
    /// main loop sends one per iteration) after the first one ended the wait
    /// in [`go`](Self::go); its delay is relative to the time of the command, so
    /// it must be read before virtual time moves on, or the node's next alarm
    /// lands too late (a leader that starts seconds after `thread start`).
    fn settle(&mut self) {
        let mut buf = [0u8; 2048];
        self.sock.set_nonblocking(false).ok();
        self.sock
            .set_read_timeout(Some(StdDuration::from_millis(4)))
            .ok();
        while let Ok((n, SocketAddr::V4(a))) = self.sock.recv_from(&mut buf) {
            let (msg, port) = (buf[..n].to_vec(), a.port());
            if self.devices.contains_key(&port) {
                self.process_event(&msg, port);
            }
        }
        self.sock.set_nonblocking(true).ok();
    }

    fn go(&mut self, duration_us: u64, node: Option<u16>) {
        if duration_us > 0 {
            self.settle();
        }
        assert_eq!(self.current_time, self.pause_time);
        self.pause_time += duration_us;
        if let Some(n) = node {
            self.awake.insert(self.port + n);
        }
        self.process_events();
        while self.next_event_time() <= self.pause_time {
            self.process_next_event();
            self.process_events();
        }
        if duration_us > 0 {
            self.sync_devices();
        }
    }
}

impl Drop for VtSim {
    fn drop(&mut self) {
        for (_, mut p) in std::mem::take(&mut self.procs) {
            let _ = p.child.kill();
            let _ = p.child.wait();
        }
    }
}

/// The target directory of the running test binary.
fn target_dir() -> std::path::PathBuf {
    if let Some(t) = std::env::var_os("CARGO_TARGET_DIR") {
        return t.into();
    }
    std::env::current_exe()
        .ok()
        .and_then(|e| e.ancestors().nth(3).map(Path::to_path_buf))
        .unwrap_or_else(|| "target".into())
}

/// OpenThread's `ot-cli-ftd` of the simulation platform (virtual time):
/// `$OT_CLI_PATH`, else `<target dir>/ot-sim/ot-cli-ftd` as built by
/// `cargo build -p openthread-sys`. `None` if there is none.
pub fn ot_cli_ftd() -> Option<std::path::PathBuf> {
    let p = std::env::var_os("OT_CLI_PATH")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| target_dir().join("ot-sim/ot-cli-ftd"));
    p.is_file().then_some(p)
}

/// The OpenTrust node `opentrust-cli-vt`: `$OPENTRUST_CLI_VT`, else built
/// with `cargo build -p opentrust-cli --features sim` into the target
/// directory (once per process). `None` if that fails.
pub fn opentrust_cli_vt() -> Option<std::path::PathBuf> {
    use std::sync::OnceLock;
    static BIN: OnceLock<Option<std::path::PathBuf>> = OnceLock::new();
    BIN.get_or_init(|| {
        build_vt(
            "OPENTRUST_CLI_VT",
            "opentrust-cli-vt",
            &["--features", "sim"],
        )
    })
    .clone()
}

/// The minimal thread device build of the OpenTrust node,
/// `opentrust-cli-vt-mtd` (no `ftd`, commissioner or Border Agent code):
/// `$OPENTRUST_CLI_VT_MTD`, else built with `cargo build -p opentrust-cli
/// --no-default-features --features sim-mtd` (once per process).
pub fn opentrust_cli_vt_mtd() -> Option<std::path::PathBuf> {
    use std::sync::OnceLock;
    static BIN: OnceLock<Option<std::path::PathBuf>> = OnceLock::new();
    BIN.get_or_init(|| {
        build_vt(
            "OPENTRUST_CLI_VT_MTD",
            "opentrust-cli-vt-mtd",
            &["--no-default-features", "--features", "sim-mtd"],
        )
    })
    .clone()
}

fn build_vt(env: &str, bin: &str, args: &[&str]) -> Option<std::path::PathBuf> {
    if let Some(p) = std::env::var_os(env) {
        return Some(p.into());
    }
    let dir = target_dir();
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let ok = Command::new(cargo)
        .args(["build", "-q", "-p", "opentrust-cli"])
        .args(args)
        .args(["--bin", bin])
        .env("CARGO_TARGET_DIR", &dir)
        .status()
        .is_ok_and(|s| s.success());
    let p = dir.join("debug").join(bin);
    (ok && p.is_file()).then_some(p)
}
