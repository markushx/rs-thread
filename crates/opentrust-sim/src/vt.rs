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
//! (receive, transmit, ACK in the radio, energy scan), [`FileSettings`] the
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
    Capabilities, Config as RadioConfig, MacCapabilities, PsduRxInfo, RadioCaps, SrcMatchConfig,
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
        let sock = UdpSocket::bind(("127.0.0.1", base + offset + node_id))?;
        let server = SocketAddr::from(([127, 0, 0, 1], base + offset));
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
/// only sends and matches ACKs.
pub fn caps() -> RadioCaps {
    RadioCaps {
        phy: Capabilities::ENERGY_SCAN,
        mac: MacCapabilities::TX_ACK | MacCapabilities::RX_ACK | MacCapabilities::SRC_MATCH,
        ..RadioCaps::default()
    }
}

/// The extended address OpenTrust nodes use: derived from the node ID.
pub fn node_ext_address(node_id: u16) -> ExtAddress {
    let h = node_id.to_be_bytes();
    ExtAddress([0x1a, 0xb4, 0x31, 0x00, 0x00, 0x00, h[0], h[1]])
}

/// A new FTD node (router capable, rx-on-when-idle).
pub fn new_instance(node_id: u16, settings: FileSettings, seed: u64) -> Box<VtInstance> {
    let cfg = Config::router(node_ext_address(node_id), caps());
    Box::new(Instance::new(
        cfg,
        settings,
        SoftCrypto,
        SimRng::new(seed ^ (u64::from(node_id) << 16) ^ 0x5eed),
    ))
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
}

fn lqi_of(rssi: i8) -> u8 {
    (i32::from(rssi) + 100).clamp(0, 100) as u8 * 2 + 50
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
        }
    }

    /// The link (for sleep events).
    pub fn link(&self) -> &VtLink {
        &self.link
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
        let t = instant(now_us);
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
                let dst = frame.dst_address();
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
                self.tx = Some(PendingTx {
                    psdu,
                    seq,
                    wait_ack,
                    echoed: false,
                    abort_at: tx.abort_at.map(|i| i.as_micros().saturating_sub(TIME_BASE)),
                });
            }
        }
    }

    /// A radio event from the simulator: a frame of another node, or the echo
    /// of the node's own transmission.
    pub fn on_radio(
        &mut self,
        inst: &mut VtInstance,
        now_us: u64,
        data: &[u8],
        filter: &mut dyn FnMut(&Frame<'_>) -> bool,
    ) {
        let t = instant(now_us);
        let Some((&channel, psdu)) = data.split_first() else {
            return;
        };
        if self.state != RxState::Receive(channel) || psdu.len() < 3 {
            return;
        }
        let is_ack = psdu[0] & 7 == 2;
        if is_ack {
            // Only the ACK of the transmission in flight is of interest.
            if let Some(tx) = &self.tx
                && tx.wait_ack
                && tx.echoed
                && psdu[2] == tx.seq
            {
                self.tx = None;
                let info = PsduRxInfo {
                    len: psdu.len(),
                    channel,
                    rssi: Some(RX_RSSI),
                    lqi: Some(lqi_of(RX_RSSI)),
                    timestamp_us: None,
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
        if !filter(&frame) {
            return;
        }
        let info = PsduRxInfo {
            len: psdu.len(),
            channel,
            rssi: Some(RX_RSSI),
            lqi: Some(lqi_of(RX_RSSI)),
            timestamp_us: None,
            ack_security: None,
            acked_with_frame_pending: will_ack.then_some(fp),
        };
        inst.handle_radio_rx(psdu, &info, t);
    }
}
