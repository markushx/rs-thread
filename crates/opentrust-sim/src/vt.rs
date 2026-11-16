//! OpenThread's simulation platform protocol in virtual-time mode, so that an
//! OpenTrust node process can join a network of `ot-cli-ftd` processes driven
//! by the `thread-cert` simulator (`tests/scripts/thread-cert/simulator.py`).
//!
//! Every node process is one UDP socket. All nodes talk to the simulator on
//! `127.0.0.1:<PORT_BASE + PORT_OFFSET * 34>` and listen on that port plus
//! their node ID. A message is an event: `u64` delay in microseconds (native
//! byte order), `u8` type, `u16` data length, data. A node reports the time
//! of its next alarm with an [`EV_ALARM`] event ("sleep") and then blocks; the
//! simulator answers with the elapsed time and the event that woke it up.
//! Transmitted frames go to the simulator as [`EV_RADIO`] events (channel
//! byte, PSDU with FCS) which it relays to every other node, and echoes back
//! to the sender as the transmit-done notification.
//!
//! [`VtLink`] is the socket, [`VtRadio`] the radio behind the Instance
//! (receive, transmit, energy scan; the stack builds the ACKs, enhanced ones
//! with the CSL IE for CSL children, and samples CSL windows itself, see
//! [`set_clock`]), [`FileSettings`] the
//! settings file of a node and [`new_instance`] builds the node.

#![allow(clippy::std_instead_of_core)]

use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::path::{Path, PathBuf};

use opentrust_core::crypto::soft::SoftCrypto;
use opentrust_core::settings::SettingsKey;
use opentrust_core::time::Instant;
use opentrust_core::{Error, Result as CoreResult};
use opentrust_instance::{Config, ExtAddress, Instance, RadioAction, TxOutcome};
use opentrust_mac::frame::{Address, Frame, FrameBuilder};
use opentrust_mac::mac::{ext_to_u64, fcs};
use opentrust_platform::SettingsStore;
use opentrust_platform::radio::{
    Capabilities, Config as RadioConfig, MacCapabilities, PsduRxInfo, RadioCaps, RadioClock,
    SrcMatchConfig,
};

use crate::rng::SimRng;

/// Alarm event: the node sleeps until its next alarm / the simulator tells
/// that the alarm fired.
pub const EV_ALARM: u8 = 0;
/// A radio frame (to the simulator: transmit; from it: receive or echo).
pub const EV_RADIO: u8 = 1;
/// UART data (only with the virtual-time UART, not used).
pub const EV_UART: u8 = 2;

/// Largest node ID of the simulator (`VirtualTime.MAX_NODES`).
const MAX_NODES: u16 = 33;

/// Offset of the virtual time of the node's instance: the stack never sees
/// time zero.
const TIME_BASE: u64 = 1_000_000_000;

/// The stack's time for `now_us` microseconds of virtual time.
pub fn instant(now_us: u64) -> Instant {
    Instant::from_micros(TIME_BASE.saturating_add(now_us))
}

thread_local! {
    static CLOCK_US: core::cell::Cell<u64> = const { core::cell::Cell::new(0) };
}

/// Set the radio clock of this thread's node to `now_us` virtual
/// microseconds (the stack reads it through [`RadioClock`] for CSL timing).
pub fn set_clock(now_us: u64) {
    CLOCK_US.with(|c| c.set(now_us));
}

/// `VT_TRACE=1`: print the radio actions and the frames received to stderr.
fn trace() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| std::env::var_os("VT_TRACE").is_some())
}

fn radio_clock() -> u64 {
    CLOCK_US.with(core::cell::Cell::get)
}

/// An event of the simulation protocol.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VtEvent {
    /// Time since the last event of this node in microseconds.
    pub delay: u64,
    /// Event type.
    pub kind: u8,
    /// Payload.
    pub data: Vec<u8>,
}

/// The socket to the simulator.
#[derive(Debug)]
pub struct VtLink {
    sock: UdpSocket,
    server: SocketAddr,
}

fn env_u16(name: &str, default: u16) -> u16 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(default)
}

impl VtLink {
    /// Bind the socket of node `node_id` (1 to 33). `PORT_BASE` (default
    /// 9000) and `PORT_OFFSET` (default 0) select the simulator as in
    /// OpenThread.
    pub fn connect(node_id: u16) -> io::Result<Self> {
        let base = env_u16("PORT_BASE", 9000);
        let offset = env_u16("PORT_OFFSET", 0) * (MAX_NODES + 1);
        Self::connect_at(node_id, base + offset)
    }

    /// Bind the socket of node `node_id` for the simulator listening on
    /// `127.0.0.1:<server_port>`.
    pub fn connect_at(node_id: u16, server_port: u16) -> io::Result<Self> {
        let sock = UdpSocket::bind(("127.0.0.1", server_port + node_id))?;
        let server = SocketAddr::from(([127, 0, 0, 1], server_port));
        Ok(Self { sock, server })
    }

    /// A second handle on the socket (for a reader thread).
    pub fn try_clone(&self) -> io::Result<Self> {
        Ok(Self {
            sock: self.sock.try_clone()?,
            server: self.server,
        })
    }

    /// Send an event to the simulator.
    pub fn send(&self, delay: u64, kind: u8, data: &[u8]) -> io::Result<()> {
        let mut m = Vec::with_capacity(11 + data.len());
        m.extend_from_slice(&delay.to_ne_bytes());
        m.push(kind);
        m.extend_from_slice(&(data.len() as u16).to_ne_bytes());
        m.extend_from_slice(data);
        self.sock.send_to(&m, self.server).map(|_| ())
    }

    /// Block until the simulator sends an event.
    pub fn recv(&self) -> io::Result<VtEvent> {
        let mut buf = [0u8; 2048];
        loop {
            let n = self.sock.recv(&mut buf)?;
            if n < 11 {
                continue;
            }
            let len = u16::from_ne_bytes([buf[9], buf[10]]) as usize;
            let data = buf[11..n.min(11 + len)].to_vec();
            return Ok(VtEvent {
                delay: u64::from_ne_bytes(buf[..8].try_into().unwrap()),
                kind: buf[8],
                data,
            });
        }
    }
}

/// Settings of a node kept in a file (the simulation platform keeps them in
/// `tmp/<PORT_OFFSET>_<node id>.flash`), so a restarted process finds its
/// network again.
#[derive(Debug, Default)]
pub struct FileSettings {
    recs: Vec<(u16, Vec<u8>)>,
    changes: u32,
    path: Option<PathBuf>,
}

impl FileSettings {
    /// Settings that are not written anywhere.
    pub fn memory() -> Self {
        Self::default()
    }

    /// Settings stored in `path`; loads what is there.
    pub fn open(path: impl AsRef<Path>) -> Self {
        let path = path.as_ref().to_path_buf();
        let mut s = Self {
            path: Some(path.clone()),
            ..Self::default()
        };
        if let Ok(data) = std::fs::read(&path) {
            let mut p = 0;
            while p + 4 <= data.len() {
                let key = u16::from_le_bytes([data[p], data[p + 1]]);
                let len = u16::from_le_bytes([data[p + 2], data[p + 3]]) as usize;
                if p + 4 + len > data.len() {
                    break;
                }
                s.recs.push((key, data[p + 4..p + 4 + len].to_vec()));
                p += 4 + len;
            }
        }
        s
    }

    fn save(&mut self) {
        self.changes = self.changes.wrapping_add(1);
        let Some(path) = &self.path else { return };
        let mut out = Vec::new();
        for (k, v) in &self.recs {
            out.extend_from_slice(&k.to_le_bytes());
            out.extend_from_slice(&(v.len() as u16).to_le_bytes());
            out.extend_from_slice(v);
        }
        if let Some(dir) = path.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        let _ = std::fs::write(path, out);
    }

    /// The settings file of node `node_id` below `dir`.
    pub fn node_path(dir: impl AsRef<Path>, node_id: u16) -> PathBuf {
        let offset = std::env::var("PORT_OFFSET").unwrap_or_else(|_| "0".into());
        dir.as_ref().join(format!("{offset}_{node_id}.flash"))
    }
}

impl SettingsStore for FileSettings {
    fn get(&self, key: SettingsKey, index: usize, buf: &mut [u8]) -> CoreResult<usize> {
        let (_, v) = self
            .recs
            .iter()
            .filter(|(k, _)| *k == key.as_u16())
            .nth(index)
            .ok_or(Error::NotFound)?;
        let n = v.len().min(buf.len());
        buf[..n].copy_from_slice(&v[..n]);
        Ok(v.len())
    }

    fn set(&mut self, key: SettingsKey, value: &[u8]) -> CoreResult<()> {
        self.recs.retain(|(k, _)| *k != key.as_u16());
        self.recs.push((key.as_u16(), value.to_vec()));
        self.save();
        Ok(())
    }

    fn add(&mut self, key: SettingsKey, value: &[u8]) -> CoreResult<()> {
        self.recs.push((key.as_u16(), value.to_vec()));
        self.save();
        Ok(())
    }

    fn delete(&mut self, key: SettingsKey, index: Option<usize>) -> CoreResult<()> {
        let k = key.as_u16();
        let found = match index {
            Some(i) => {
                let pos = self
                    .recs
                    .iter()
                    .enumerate()
                    .filter(|(_, (rk, _))| *rk == k)
                    .nth(i)
                    .map(|(p, _)| p);
                match pos {
                    Some(p) => {
                        self.recs.remove(p);
                        true
                    }
                    None => false,
                }
            }
            None => {
                let before = self.recs.len();
                self.recs.retain(|(rk, _)| *rk != k);
                self.recs.len() != before
            }
        };
        self.save();
        if found { Ok(()) } else { Err(Error::NotFound) }
    }

    fn wipe(&mut self) {
        self.recs.clear();
        self.save();
    }

    fn change_count(&self) -> u32 {
        self.changes
    }
}

/// The instance type of a simulated OpenThread-compatible node.
pub type VtInstance = Instance<FileSettings, SoftCrypto, SimRng>;

/// What the radio behind a node reports to the stack: the OpenThread
/// simulation radio does CSMA, ACK timeout and retries in the core, the radio
/// only sends and matches ACKs. Like OpenThread's simulation radio it has no
/// timed receive or transmit: the MAC samples CSL windows and times CSL
/// transmissions with the radio clock (virtual microseconds, see
/// [`set_clock`]) and builds the (enhanced) ACKs itself.
pub fn caps() -> RadioCaps {
    RadioCaps {
        phy: Capabilities::ENERGY_SCAN | Capabilities::SLEEP_TO_TX,
        mac: MacCapabilities::TX_ACK | MacCapabilities::SRC_MATCH,
        clock: Some(RadioClock(radio_clock)),
        csl_accuracy_ppm: 0,
        csl_uncertainty: 0,
        ..RadioCaps::default()
    }
}

/// The extended address OpenTrust nodes use: derived from the node ID.
pub fn node_ext_address(node_id: u16) -> ExtAddress {
    let h = node_id.to_be_bytes();
    ExtAddress([0x1a, 0xb4, 0x31, 0x00, 0x00, 0x00, h[0], h[1]])
}

/// A new node: an FTD (router capable, rx-on-when-idle) with the `ftd`
/// feature, else a minimal thread device (rx-on-when-idle, no routing).
pub fn new_instance(node_id: u16, settings: FileSettings, seed: u64) -> Box<VtInstance> {
    #[cfg(feature = "ftd")]
    let cfg = Config::router(node_ext_address(node_id), caps());
    #[cfg(not(feature = "ftd"))]
    let cfg = Config::end_device(node_ext_address(node_id), caps());
    Box::new(Instance::new(
        cfg,
        settings,
        SoftCrypto,
        SimRng::new(seed ^ (u64::from(node_id) << 16) ^ 0x5eed),
    ))
}

/// OpenThread's MAC filter (`macfilter`): which source addresses are heard and
/// with which fixed RSS. The thread-cert scripts build their topologies with
/// it. OpenThread applies it in the MAC after the radio ACKed the frame
/// and to the ACKs of the frames it sends; here it sits in the radio.
#[derive(Debug, Default)]
pub struct MacFilter {
    mode: FilterMode,
    entries: Vec<FilterEntry>,
    default_rss: Option<i8>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
enum FilterMode {
    #[default]
    Disabled,
    Allowlist,
    Denylist,
}

#[derive(Debug, Clone)]
struct FilterEntry {
    ext: [u8; 8],
    filtered: bool,
    rss: Option<i8>,
}

/// Noise floor OpenThread's filter commands use to convert link quality to RSS.
const NOISE_FLOOR: i8 = -100;

fn lq_to_rss(lq: u8) -> i8 {
    NOISE_FLOOR
        + match lq {
            3 => 50,
            2 => 15,
            1 => 5,
            _ => 0,
        }
}

fn rss_to_lq(rss: i8) -> u8 {
    match i16::from(rss) - i16::from(NOISE_FLOOR) {
        21.. => 3,
        11..=20 => 2,
        3..=10 => 1,
        _ => 0,
    }
}

/// OpenThread error codes the filter commands answer with.
const E_INVALID_ARGS: u8 = 7;
const E_NOT_FOUND: u8 = 23;
const E_INVALID_COMMAND: u8 = 35;

fn parse_ext(s: &str) -> Option<[u8; 8]> {
    if s.len() != 16 {
        return None;
    }
    let mut b = [0u8; 8];
    for (i, o) in b.iter_mut().enumerate() {
        *o = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(b)
}

fn hex8(b: &[u8; 8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

impl MacFilter {
    /// Apply the filter to a frame from `ext`: `None` if it is filtered
    /// out, else the fixed RSS to use, if any.
    pub fn apply(&self, ext: &[u8; 8]) -> Option<Option<i8>> {
        let e = self.entries.iter().find(|e| &e.ext == ext);
        let listed = e.is_some_and(|e| e.filtered);
        match self.mode {
            FilterMode::Disabled => {}
            FilterMode::Allowlist if !listed => return None,
            FilterMode::Denylist if listed => return None,
            _ => {}
        }
        Some(e.and_then(|e| e.rss).or(self.default_rss))
    }

    fn entry(&mut self, ext: [u8; 8]) -> &mut FilterEntry {
        if let Some(p) = self.entries.iter().position(|e| e.ext == ext) {
            return &mut self.entries[p];
        }
        self.entries.push(FilterEntry {
            ext,
            filtered: false,
            rss: None,
        });
        self.entries.last_mut().unwrap()
    }

    fn print_entry(out: &mut String, e: &FilterEntry) {
        out.push_str(&hex8(&e.ext));
        if let Some(r) = e.rss {
            out.push_str(&format!(" : rss {r} (lqi {})", rss_to_lq(r)));
        }
        out.push_str("\r\n");
    }

    fn print_addr(&self, out: &mut String, header: bool) {
        if header {
            out.push_str("Address Mode: ");
        }
        out.push_str(match self.mode {
            FilterMode::Disabled => "Disabled\r\n",
            FilterMode::Allowlist => "Allowlist\r\n",
            FilterMode::Denylist => "Denylist\r\n",
        });
        for e in self.entries.iter().filter(|e| e.filtered) {
            Self::print_entry(out, e);
        }
    }

    fn print_rss(&self, out: &mut String, header: bool) {
        if header {
            out.push_str("RssIn List:\r\n");
        }
        for e in self.entries.iter().filter(|e| e.rss.is_some()) {
            Self::print_entry(out, e);
        }
        if let Some(r) = self.default_rss {
            out.push_str(&format!("Default rss: {r} (lqi {})\r\n", rss_to_lq(r)));
        }
    }

    /// Run `macfilter <args>`; prints the output and returns the OpenThread
    /// error code on failure.
    pub fn command(&mut self, args: &[&str], out: &mut String) -> Result<(), u8> {
        let a = |i: usize| args.get(i).copied().unwrap_or("");
        match a(0) {
            "" => {
                self.print_addr(out, true);
                self.print_rss(out, true);
                Ok(())
            }
            "addr" => match a(1) {
                "" => {
                    self.print_addr(out, false);
                    Ok(())
                }
                "add" => {
                    let ext = parse_ext(a(2)).ok_or(E_INVALID_ARGS)?;
                    self.entry(ext).filtered = true;
                    if !a(3).is_empty() {
                        let rss: i8 = a(3).parse().map_err(|_| E_INVALID_ARGS)?;
                        self.entry(ext).rss = Some(rss);
                    }
                    Ok(())
                }
                "remove" => {
                    let ext = parse_ext(a(2)).ok_or(E_INVALID_ARGS)?;
                    if let Some(p) = self.entries.iter().position(|e| e.ext == ext) {
                        if self.entries[p].rss.is_some() {
                            self.entries[p].filtered = false;
                        } else {
                            self.entries.remove(p);
                        }
                    }
                    Ok(())
                }
                "clear" => {
                    self.entries.retain_mut(|e| {
                        e.filtered = false;
                        e.rss.is_some()
                    });
                    Ok(())
                }
                m @ ("disable" | "allowlist" | "denylist") => {
                    if !a(2).is_empty() {
                        return Err(E_INVALID_ARGS);
                    }
                    self.mode = match m {
                        "allowlist" => FilterMode::Allowlist,
                        "denylist" => FilterMode::Denylist,
                        _ => FilterMode::Disabled,
                    };
                    Ok(())
                }
                _ => Err(E_INVALID_COMMAND),
            },
            "rss" => match a(1) {
                "" => {
                    self.print_rss(out, false);
                    Ok(())
                }
                c @ ("add" | "add-lqi") => {
                    let rss: i8 = if c == "add" {
                        a(3).parse().map_err(|_| E_INVALID_ARGS)?
                    } else {
                        let lq: u8 = a(3).parse().map_err(|_| E_INVALID_ARGS)?;
                        if lq > 3 {
                            return Err(E_INVALID_ARGS);
                        }
                        lq_to_rss(lq)
                    };
                    if a(2) == "*" {
                        self.default_rss = Some(rss);
                    } else {
                        let ext = parse_ext(a(2)).ok_or(E_INVALID_ARGS)?;
                        self.entry(ext).rss = Some(rss);
                    }
                    Ok(())
                }
                "remove" => {
                    if a(2) == "*" {
                        self.default_rss = None;
                        return Ok(());
                    }
                    let ext = parse_ext(a(2)).ok_or(E_INVALID_ARGS)?;
                    let Some(p) = self.entries.iter().position(|e| e.ext == ext) else {
                        return Err(E_NOT_FOUND);
                    };
                    if self.entries[p].filtered {
                        self.entries[p].rss = None;
                    } else {
                        self.entries.remove(p);
                    }
                    Ok(())
                }
                "clear" => {
                    self.default_rss = None;
                    self.entries.retain_mut(|e| {
                        e.rss = None;
                        e.filtered
                    });
                    Ok(())
                }
                _ => Err(E_INVALID_COMMAND),
            },
            _ => Err(E_INVALID_COMMAND),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RxState {
    Sleep,
    Receive(u8),
}

#[derive(Debug)]
struct PendingTx {
    psdu: Vec<u8>,
    seq: u8,
    wait_ack: bool,
    echoed: bool,
    abort_at: Option<u64>,
    dst: Address,
}

/// The radio of one node: state set by the stack, transmit and receive over
/// the simulation protocol.
#[derive(Debug)]
pub struct VtRadio {
    link: VtLink,
    state: RxState,
    config: RadioConfig,
    src_match: SrcMatchConfig,
    tx: Option<PendingTx>,
    scan: Option<(u64, u8)>,
    /// The MAC filter (`macfilter`).
    pub filter: MacFilter,
    neighbors: Vec<(u16, [u8; 8])>,
    /// The ACK the stack sent last (its echo is not a frame to handle).
    last_ack: Vec<u8>,
}

/// RSSI the simulation platform reports for every frame.
const RX_RSSI: i8 = -20;

impl VtRadio {
    /// A radio over `link`, asleep.
    pub fn new(link: VtLink) -> Self {
        Self {
            link,
            state: RxState::Sleep,
            config: RadioConfig::new(),
            src_match: SrcMatchConfig::new(),
            tx: None,
            scan: None,
            filter: MacFilter::default(),
            neighbors: Vec::new(),
            last_ack: Vec::new(),
        }
    }

    /// The link (for sleep events).
    pub fn link(&self) -> &VtLink {
        &self.link
    }

    /// Tell the radio the neighbors (RLOC16 and extended address) the stack
    /// knows, so that the MAC filter can resolve short source addresses.
    pub fn set_neighbors(&mut self, n: Vec<(u16, [u8; 8])>) {
        self.neighbors = n;
    }

    /// The extended address (as `extaddr` prints it) behind a MAC address.
    fn ext_of(&self, a: Address) -> Option<[u8; 8]> {
        match a {
            Address::Extended(e) => Some(e.0),
            Address::Short(s) => self
                .neighbors
                .iter()
                .find(|(r, _)| *r == s.0)
                .map(|(_, e)| *e),
            _ => None,
        }
    }

    /// The next time the radio has work (ACK wait abort, energy scan end),
    /// in virtual microseconds.
    pub fn next_deadline(&self) -> Option<u64> {
        let a = self.tx.as_ref().and_then(|t| t.abort_at);
        let s = self.scan.map(|(t, _)| t);
        match (a, s) {
            (Some(a), Some(s)) => Some(a.min(s)),
            (a, s) => a.or(s),
        }
    }

    /// Run the radio timers due at `now_us`.
    pub fn on_timer(&mut self, inst: &mut VtInstance, now_us: u64) {
        set_clock(now_us);
        let t = instant(now_us);
        if let Some(tx) = &self.tx
            && tx.abort_at.is_some_and(|a| a <= now_us)
        {
            self.tx = None;
            inst.handle_radio_tx_done(TxOutcome::AckTimeout, t);
        }
        if let Some((end, _)) = self.scan
            && end <= now_us
        {
            self.scan = None;
            inst.handle_radio_energy_scan_done(-100, t);
        }
    }

    /// Execute a command of the stack.
    pub fn exec(&mut self, inst: &mut VtInstance, now_us: u64, a: RadioAction) {
        set_clock(now_us);
        let t = instant(now_us);
        if trace() {
            match &a {
                RadioAction::Transmit(tx) => eprintln!(
                    "[{now_us}] TX ch{} {:02x?}",
                    tx.channel,
                    &tx.psdu[..tx.psdu.len().min(24)]
                ),
                o => eprintln!("[{now_us}] {o:?}"),
            }
        }
        match a {
            RadioAction::Configure(c) => self.config = c,
            RadioAction::SetSrcMatch(c) => self.src_match = c,
            RadioAction::SetMacKeys(_)
            | RadioAction::SetMacFrameCounter { .. }
            | RadioAction::SetCsl(_) => {}
            RadioAction::ReceiveAt { channel, .. } | RadioAction::Receive { channel } => {
                self.state = RxState::Receive(channel);
            }
            RadioAction::Sleep => self.state = RxState::Sleep,
            RadioAction::EnergyScan {
                channel,
                duration_ms,
            } => {
                self.scan = Some((now_us + u64::from(duration_ms) * 1000, channel));
            }
            RadioAction::Transmit(tx) => {
                let psdu = tx.psdu.to_vec();
                let Ok(frame) = Frame::parse_with_fcs(&psdu) else {
                    inst.handle_radio_tx_done(
                        TxOutcome::Failed(opentrust_platform::radio::RadioErrorKind::TxInvalid),
                        t,
                    );
                    return;
                };
                if psdu.first().is_some_and(|b| b & 7 == 2) {
                    // An ACK built by the stack: on the air at once.
                    let mut m = Vec::with_capacity(1 + psdu.len());
                    m.push(tx.channel);
                    m.extend_from_slice(&psdu);
                    let sent = self.link.send(1, EV_RADIO, &m).is_ok();
                    self.last_ack = psdu;
                    inst.handle_radio_tx_done(
                        if sent {
                            TxOutcome::Sent
                        } else {
                            TxOutcome::Failed(opentrust_platform::radio::RadioErrorKind::TxFailed)
                        },
                        t,
                    );
                    return;
                }
                let dst = frame.dst_address();
                let dst_addr = dst;
                let unicast = !dst.is_none() && !dst.is_broadcast();
                let wait_ack = tx.wait_ack && frame.frame_control().ack_request() && unicast;
                let seq = psdu.get(2).copied().unwrap_or(0);
                let mut m = Vec::with_capacity(1 + psdu.len());
                m.push(tx.channel);
                m.extend_from_slice(&psdu);
                if self.link.send(1, EV_RADIO, &m).is_err() {
                    inst.handle_radio_tx_done(
                        TxOutcome::Failed(opentrust_platform::radio::RadioErrorKind::TxFailed),
                        t,
                    );
                    return;
                }
                // The radio is in receive on the transmit channel afterwards,
                // also when it transmitted from sleep.
                self.state = RxState::Receive(tx.channel);
                self.tx = Some(PendingTx {
                    psdu,
                    seq,
                    wait_ack,
                    echoed: false,
                    dst: dst_addr,
                    abort_at: tx.abort_at.map(|i| i.as_micros().saturating_sub(TIME_BASE)),
                });
            }
        }
    }

    /// A radio event from the simulator: a frame of another node, or the echo
    /// of the node's own transmission.
    pub fn on_radio(&mut self, inst: &mut VtInstance, now_us: u64, data: &[u8]) {
        set_clock(now_us);
        let t = instant(now_us);
        let Some((&channel, psdu)) = data.split_first() else {
            return;
        };
        if self.state != RxState::Receive(channel) || psdu.len() < 3 {
            return;
        }
        if trace() {
            eprintln!(
                "[{now_us}] RX {:?} len{} {:02x?}",
                self.state,
                psdu.len(),
                &psdu[..psdu.len().min(24)]
            );
        }
        let is_ack = psdu[0] & 7 == 2;
        if is_ack && psdu == self.last_ack.as_slice() {
            self.last_ack.clear();
            return;
        }
        if is_ack {
            // Only the ACK of the transmission in flight is of interest.
            if let Some(tx) = &self.tx
                && tx.wait_ack
                && tx.echoed
                && psdu[2] == tx.seq
            {
                // The filter drops the ACKs of filtered neighbors, too.
                let mut rssi = RX_RSSI;
                if let Some(ext) = self.ext_of(tx.dst) {
                    match self.filter.apply(&ext) {
                        None => return,
                        Some(r) => rssi = r.unwrap_or(rssi),
                    }
                }
                self.tx = None;
                let info = PsduRxInfo {
                    len: psdu.len(),
                    channel,
                    rssi: Some(rssi),
                    lqi: None,
                    // Frames take no time in the simulation: the ACK's SFD
                    // is where the sender of a CSL IE assumed it, one
                    // turnaround and SHR after the frame it acknowledges (an
                    // OpenThread sender's phase refers to the ACK's own time,
                    // which this lets a parent transmit later by that much,
                    // still inside the child's sample window).
                    timestamp_us: Some(
                        now_us
                            + u64::from(
                                opentrust_mac::mac::TURNAROUND_TIME
                                    + opentrust_mac::mac::SHR_DURATION,
                            ),
                    ),
                    ack_security: None,
                    acked_with_frame_pending: None,
                };
                inst.handle_radio_tx_done(TxOutcome::Acked { ack: psdu, info }, t);
            }
            return;
        }
        if let Some(tx) = &mut self.tx
            && !tx.echoed
            && tx.psdu == psdu
        {
            // The echo of the own frame: the transmission is on the air.
            tx.echoed = true;
            if !tx.wait_ack {
                self.tx = None;
                inst.handle_radio_tx_done(TxOutcome::Sent, t);
            }
            return;
        }
        let Ok(frame) = Frame::parse_with_fcs(psdu) else {
            return;
        };
        let dst = frame.dst_address();
        let ack_request = frame.frame_control().ack_request();
        let unicast = !dst.is_none() && !dst.is_broadcast();
        let mut fp = false;
        let mut will_ack = false;
        if ack_request && unicast {
            let cfg = &self.config;
            let pan_ok = frame
                .pan_id()
                .is_none_or(|p| cfg.pan_id.is_none_or(|c| c == p.0 || p.0 == 0xffff));
            let addr_ok = match dst {
                Address::Short(s) => cfg.short_addr == Some(s.0) || cfg.alt_short_addr == Some(s.0),
                Address::Extended(e) => cfg.ext_addr == Some(ext_to_u64(&e)),
                _ => false,
            };
            will_ack = pan_ok && addr_ok;
            if will_ack && frame.is_data_request() {
                let (s, e) = match frame.src_address() {
                    Address::Short(s) => (s.0, 0),
                    Address::Extended(e) => (0xfffe, ext_to_u64(&e)),
                    _ => (0xfffe, 0),
                };
                fp = self.src_match.ack_frame_pending(s, e);
            }
        }
        let mut rssi = RX_RSSI;
        if let Some(ext) = self.ext_of(frame.src_address()) {
            match self.filter.apply(&ext) {
                None => {
                    // OpenThread's radio ACKs the frame before its MAC
                    // filter drops it; the stack never sees it, so the
                    // radio sends the ACK.
                    if will_ack {
                        let mut buf = [0u8; 16];
                        if let Ok(n) = FrameBuilder::imm_ack_for(&mut buf, &frame, fp) {
                            let f = fcs(&buf[..n]);
                            let mut a = Vec::with_capacity(n + 3);
                            a.push(channel);
                            a.extend_from_slice(&buf[..n]);
                            a.extend_from_slice(&f);
                            let _ = self.link.send(1, EV_RADIO, &a);
                        }
                    }
                    return;
                }
                Some(r) => rssi = r.unwrap_or(rssi),
            }
        }
        let info = PsduRxInfo {
            len: psdu.len(),
            channel,
            rssi: Some(rssi),
            lqi: None,
            timestamp_us: None,
            ack_security: None,
            // The stack builds the ACK (enhanced for 2015 frames).
            acked_with_frame_pending: None,
        };
        inst.handle_radio_rx(psdu, &info, t);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use opentrust_mac::mac::{Psdu, TxAction};
    use opentrust_platform::radio::PsduTxInfo;

    /// A node on a private simulator port with the simulator's socket.
    fn node(port: u16) -> (UdpSocket, VtRadio, Box<VtInstance>) {
        let server = UdpSocket::bind(("127.0.0.1", port)).expect("simulator socket");
        server
            .set_read_timeout(Some(std::time::Duration::from_secs(2)))
            .unwrap();
        let radio = VtRadio::new(VtLink::connect_at(1, port).expect("node socket"));
        let inst = new_instance(1, FileSettings::memory(), 7);
        (server, radio, inst)
    }

    fn broadcast_data() -> Vec<u8> {
        let mut buf = [0u8; 64];
        let n = FrameBuilder::new(&mut buf)
            .frame_type(opentrust_mac::frame::FrameType::Data)
            .sequence(5)
            .dst_pan(opentrust_core::types::PanId(0xffff))
            .dst(Address::Short(
                opentrust_core::types::ShortAddress::BROADCAST,
            ))
            .src(Address::Short(opentrust_core::types::ShortAddress(0x1234)))
            .payload(&[1, 2, 3])
            .build()
            .unwrap();
        let mut v = buf[..n].to_vec();
        let f = fcs(&v);
        v.extend_from_slice(&f);
        v
    }

    #[test]
    fn caps_have_the_virtual_clock_and_no_hardware_ack() {
        let c = caps();
        let clock = c.clock.expect("clock");
        set_clock(123_456);
        assert_eq!(clock.now_us(), 123_456);
        set_clock(1_000_000);
        assert_eq!(clock.now_us(), 1_000_000);
        assert!(!c.mac.contains(MacCapabilities::RX_ACK));
        assert!(!c.phy.contains(Capabilities::RECEIVE_TIMING));
    }

    #[test]
    fn sleeping_radio_hears_no_frames() {
        let (_srv, mut radio, mut inst) = node(24_100);
        let mut rx = vec![11u8];
        rx.extend_from_slice(&broadcast_data());
        // Asleep: not a single frame reaches the stack.
        radio.exec(&mut inst, 1_000, RadioAction::Sleep);
        radio.on_radio(&mut inst, 2_000, &rx);
        assert_eq!(inst.mac().counters().rx_total, 0);
        // Awake on another channel it does not hear it either.
        radio.exec(&mut inst, 3_000, RadioAction::Receive { channel: 12 });
        radio.on_radio(&mut inst, 4_000, &rx);
        assert_eq!(inst.mac().counters().rx_total, 0);
        radio.exec(&mut inst, 5_000, RadioAction::Receive { channel: 11 });
        radio.on_radio(&mut inst, 6_000, &rx);
        assert_eq!(inst.mac().counters().rx_total, 1);
        // Asleep again (a CSL window ended).
        radio.exec(&mut inst, 7_000, RadioAction::Sleep);
        radio.on_radio(&mut inst, 8_000, &rx);
        assert_eq!(inst.mac().counters().rx_total, 1);
    }

    #[test]
    fn an_ack_built_by_the_stack_goes_on_the_air_at_once() {
        let (srv, mut radio, mut inst) = node(24_140);
        radio.exec(&mut inst, 1_000, RadioAction::Receive { channel: 15 });
        // An enhanced ACK (2015 frame version, CSL IE) as the MAC builds it.
        let mut buf = [0u8; 32];
        let n = FrameBuilder::new(&mut buf)
            .frame_type(opentrust_mac::frame::FrameType::Ack)
            .version(opentrust_mac::frame::FrameVersion::V2015)
            .sequence(9)
            .dst_pan(opentrust_core::types::PanId(0xface))
            .dst(Address::Short(opentrust_core::types::ShortAddress(0x0400)))
            .header_ie(opentrust_mac::frame::CslIe {
                phase: 100,
                period: 3125,
                rendezvous_time: None,
            })
            .build()
            .unwrap();
        let mut psdu = Psdu::new();
        psdu.extend_from_slice(&buf[..n]).unwrap();
        psdu.extend_from_slice(&fcs(&buf[..n])).unwrap();
        let sent = psdu.to_vec();
        radio.exec(
            &mut inst,
            2_000,
            RadioAction::Transmit(TxAction {
                psdu,
                info: PsduTxInfo::default(),
                channel: 15,
                power: 0,
                cca_threshold: None,
                wait_ack: false,
                abort_at: None,
            }),
        );
        let mut m = [0u8; 256];
        let len = srv.recv(&mut m).expect("frame at the simulator");
        assert_eq!(m[8], EV_RADIO);
        assert_eq!(m[11], 15);
        assert_eq!(&m[12..len], sent.as_slice());
        // The echo of the ACK is not handled as a received frame.
        let mut echo = vec![15u8];
        echo.extend_from_slice(&sent);
        radio.on_radio(&mut inst, 2_001, &echo);
        assert_eq!(inst.mac().counters().rx_total, 0);
    }
}
