use rs_thread_core::crypto::soft::SoftCrypto;
use rs_thread_core::time::{Duration, Instant};
use rs_thread_instance::{Config, Event, Instance, RadioAction, TxOutcome};
use rs_thread_mac::frame::{Address, Frame, FrameBuilder};
use rs_thread_mac::mac::{TxAction, ext_to_u64, fcs};
use rs_thread_platform::RamSettings;
use rs_thread_platform::radio::{PsduRxInfo, RadioErrorKind};

use crate::radio::{Medium, RadioState, SimRadio};
use crate::rng::SimRng;

/// Settings storage of the simulated nodes.
pub type SimSettings = RamSettings<4096>;

/// The instance type of the simulator.
pub type SimInstance = Instance<SimSettings, SoftCrypto, SimRng>;

/// One simulated node.
pub struct SimNode {
    /// The Thread node.
    pub inst: Box<SimInstance>,
    /// Its radio.
    pub radio: SimRadio,
    /// Events collected so far (drained by the tests).
    pub events: Vec<Event>,
    kind: Kind,
    ext: rs_thread_instance::ExtAddress,
}

/// Device type of a node.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// FTD: router eligible.
    Router,
    /// Minimal end device, rx-on-when-idle.
    EndDevice,
    /// Sleepy end device.
    Sleepy,
}

/// A transmission on the medium.
#[derive(Debug, Clone)]
pub struct TxRecord {
    /// Time of the transmission.
    pub at: Instant,
    /// Transmitting node.
    pub from: usize,
    /// The PSDU (with FCS).
    pub psdu: Vec<u8>,
    /// Nodes that received it.
    pub received_by: Vec<usize>,
    /// Whether an ACK came back.
    pub acked: bool,
}

/// N instances over a simulated medium with virtual time.
pub struct Network {
    /// The nodes.
    pub nodes: Vec<SimNode>,
    /// Links, loss, jamming.
    pub medium: Medium,
    /// Virtual time.
    pub now: Instant,
    /// Every transmission so far (disable with `log_tx = false`).
    pub tx_log: Vec<TxRecord>,
    /// Record transmissions.
    pub log_tx: bool,
    sched: Vec<Sched>,
    seq: u64,
    seed: u64,
}

/// Something that happens at a later virtual time: a frame arrives or a
/// transmission completes (the radio is busy for the air time).
enum Ev {
    Rx {
        node: usize,
        psdu: Vec<u8>,
        info: PsduRxInfo,
    },
    TxDone {
        node: usize,
        ack: Option<(Vec<u8>, PsduRxInfo)>,
        expected_ack: bool,
    },
}

struct Sched {
    at: Instant,
    seq: u64,
    ev: Ev,
}

/// Air time of a PSDU: SHR + PHR + payload at 250 kbit/s.
fn air_time(len: usize) -> Duration {
    Duration::from_micros((len as u64 + 6) * 32)
}

/// RX-to-TX turnaround before an ACK (aTurnaroundTime) and the wait for it
/// to arrive when it does not.
const TURNAROUND: Duration = Duration::from_micros(192);
const ACK_WAIT: Duration = Duration::from_micros(864);

fn build_instance(
    kind: Kind,
    ext: rs_thread_instance::ExtAddress,
    settings: SimSettings,
    seed: u64,
) -> Box<SimInstance> {
    let caps = SimRadio::caps();
    let cfg = match kind {
        Kind::Router => Config::router(ext, caps),
        Kind::EndDevice => Config::end_device(ext, caps),
        Kind::Sleepy => Config::sleepy_end_device(ext, caps),
    };
    Box::new(Instance::new(cfg, settings, SoftCrypto, SimRng::new(seed)))
}

impl Network {
    /// `kinds.len()` nodes with extended addresses `02:..:n` (n from 1),
    /// no links.
    pub fn new(kinds: &[Kind], seed: u64) -> Self {
        let nodes = kinds
            .iter()
            .enumerate()
            .map(|(i, k)| {
                let ext = crate::ext_address(i as u8 + 1);
                SimNode {
                    inst: build_instance(*k, ext, SimSettings::new(), seed ^ (i as u64 + 1) << 8),
                    radio: SimRadio::new(),
                    events: Vec::new(),
                    kind: *k,
                    ext,
                }
            })
            .collect();
        Self {
            nodes,
            medium: Medium::new(kinds.len(), seed ^ 0xdead_beef),
            now: Instant::from_secs(1000),
            tx_log: Vec::new(),
            log_tx: true,
            sched: Vec::new(),
            seq: 0,
            seed,
        }
    }

    /// `n` routers.
    pub fn routers(n: usize, seed: u64) -> Self {
        Self::new(&vec![Kind::Router; n], seed)
    }

    /// Node `i`.
    pub fn node(&mut self, i: usize) -> &mut SimInstance {
        &mut self.nodes[i].inst
    }

    /// Node `i`, read-only.
    pub fn inst(&self, i: usize) -> &SimInstance {
        &self.nodes[i].inst
    }

    /// Run `f` on node `i` with the current time, then let the network
    /// settle.
    pub fn with<T>(&mut self, i: usize, f: impl FnOnce(&mut SimInstance, Instant) -> T) -> T {
        let now = self.now;
        let r = f(&mut self.nodes[i].inst, now);
        self.settle();
        r
    }

    /// Events of node `i` collected so far; clears them.
    pub fn take_events(&mut self, i: usize) -> Vec<Event> {
        core::mem::take(&mut self.nodes[i].events)
    }

    /// Power-cycle node `i`: a new instance with the settings of the old
    /// one (and the same extended address).
    pub fn reset_node(&mut self, i: usize) {
        let n = &mut self.nodes[i];
        let placeholder = build_instance(n.kind, n.ext, SimSettings::new(), 1);
        let old = core::mem::replace(&mut n.inst, placeholder);
        let settings = old.into_settings();
        n.inst = build_instance(
            n.kind,
            n.ext,
            settings,
            self.seed ^ (i as u64 + 1) << 8 ^ self.now.as_secs(),
        );
        n.radio = SimRadio::new();
    }

    /// Process everything due at the current time until nothing happens.
    pub fn settle(&mut self) {
        for _ in 0..10_000 {
            let mut did = self.run_scheduled();
            for i in 0..self.nodes.len() {
                self.nodes[i].inst.poll(self.now);
                while let Some(a) = self.nodes[i].inst.poll_radio_action(self.now) {
                    did = true;
                    self.exec(i, a);
                }
                while let Some(e) = self.nodes[i].inst.poll_event() {
                    self.nodes[i].events.push(e);
                }
            }
            if !did {
                return;
            }
        }
        panic!("the network does not settle (radio activity storm)");
    }

    fn schedule(&mut self, at: Instant, ev: Ev) {
        self.seq += 1;
        self.sched.push(Sched {
            at,
            seq: self.seq,
            ev,
        });
    }

    /// Apply the scheduled events that are due, in order.
    fn run_scheduled(&mut self) -> bool {
        let mut did = false;
        loop {
            let Some(idx) = self
                .sched
                .iter()
                .enumerate()
                .filter(|(_, s)| s.at <= self.now)
                .min_by_key(|(_, s)| (s.at, s.seq))
                .map(|(i, _)| i)
            else {
                return did;
            };
            let s = self.sched.remove(idx);
            did = true;
            match s.ev {
                Ev::Rx { node, psdu, info } => {
                    // A radio that went to sleep meanwhile misses the frame.
                    if self.nodes[node].radio.state == RadioState::Receive(info.channel) {
                        self.nodes[node]
                            .inst
                            .handle_radio_rx(&psdu, &info, self.now);
                    }
                }
                Ev::TxDone {
                    node,
                    ack,
                    expected_ack,
                } => {
                    let outcome = match (&ack, expected_ack) {
                        (Some((a, info)), _) => TxOutcome::Acked {
                            ack: a,
                            info: *info,
                        },
                        (None, true) => TxOutcome::Failed(RadioErrorKind::RxAckTimeout),
                        (None, false) => TxOutcome::Sent,
                    };
                    self.nodes[node]
                        .inst
                        .handle_radio_tx_done(outcome, self.now);
                }
            }
        }
    }

    /// Advance virtual time by `d`.
    pub fn run_for(&mut self, d: Duration) {
        let end = self.now + d;
        self.run_to(end, |_| false);
    }

    /// Advance until `f` is true (checked after every step) or `max`
    /// virtual time has passed.
    pub fn run_until(&mut self, max: Duration, f: impl FnMut(&mut Self) -> bool) -> bool {
        let end = self.now + max;
        self.run_to(end, f)
    }

    fn run_to(&mut self, end: Instant, mut f: impl FnMut(&mut Self) -> bool) -> bool {
        self.settle();
        loop {
            if f(self) {
                return true;
            }
            if self.now >= end {
                return false;
            }
            let next = self
                .nodes
                .iter()
                .filter_map(|n| n.inst.next_deadline())
                .chain(self.sched.iter().map(|s| s.at))
                .min();
            let step = Duration::from_micros(100);
            let t = next.unwrap_or(end).max(self.now + step).min(end);
            self.now = t;
            self.settle();
        }
    }

    fn exec(&mut self, i: usize, a: RadioAction) {
        let now = self.now;
        match a {
            RadioAction::Configure(c) => self.nodes[i].radio.config = c,
            RadioAction::SetSrcMatch(c) => self.nodes[i].radio.src_match = c,
            RadioAction::SetMacKeys(_) | RadioAction::SetMacFrameCounter { .. } => {}
            #[cfg(feature = "csl")]
            RadioAction::SetCsl(_) => {}
            #[cfg(feature = "csl")]
            RadioAction::ReceiveAt { channel, .. } => {
                self.nodes[i].radio.state = RadioState::Receive(channel);
            }
            RadioAction::Receive { channel } => {
                self.nodes[i].radio.state = RadioState::Receive(channel);
            }
            RadioAction::Sleep => self.nodes[i].radio.state = RadioState::Sleep,
            RadioAction::EnergyScan { .. } => {
                self.nodes[i].inst.handle_radio_energy_scan_done(-100, now);
            }
            RadioAction::Transmit(tx) => self.transmit(i, tx),
        }
    }

    fn transmit(&mut self, i: usize, tx: TxAction) {
        let now = self.now;
        let psdu = tx.psdu.to_vec();
        if tx.cca_threshold.is_some() && self.medium.is_jammed(tx.channel, now) {
            self.nodes[i]
                .inst
                .handle_radio_tx_done(TxOutcome::Failed(RadioErrorKind::TxFailed), now);
            return;
        }
        let Ok(frame) = Frame::parse_with_fcs(&psdu) else {
            self.nodes[i]
                .inst
                .handle_radio_tx_done(TxOutcome::Failed(RadioErrorKind::TxInvalid), now);
            return;
        };
        let dst = frame.dst_address();
        let dst_pan = frame.pan_id();
        let ack_request = frame.frame_control().ack_request();
        let unicast = !dst.is_none() && !dst.is_broadcast();
        let is_poll = frame.is_data_request();
        let src = frame.src_address();
        let tries = if tx.wait_ack && ack_request && unicast {
            self.medium.max_tries
        } else {
            1
        };
        let mut received_by = Vec::new();
        let mut acked: Option<(Vec<u8>, PsduRxInfo)> = None;
        let expect_ack = tx.wait_ack && ack_request && unicast;
        let mut t = now;
        for _ in 0..tries {
            let on_air_until = t + air_time(psdu.len());
            for j in 0..self.nodes.len() {
                if j == i || self.nodes[j].radio.state != RadioState::Receive(tx.channel) {
                    continue;
                }
                let Some(rssi) = self.medium.delivered(i, j) else {
                    continue;
                };
                // Does the radio acknowledge it?
                let mut fp = false;
                let mut will_ack = false;
                if ack_request && unicast {
                    let cfg = &self.nodes[j].radio.config;
                    let pan_ok = dst_pan
                        .is_none_or(|p| cfg.pan_id.is_none_or(|c| c == p.0 || p.0 == 0xffff));
                    let addr_ok = match dst {
                        Address::Short(s) => {
                            cfg.short_addr == Some(s.0) || cfg.alt_short_addr == Some(s.0)
                        }
                        Address::Extended(e) => cfg.ext_addr == Some(ext_to_u64(&e)),
                        _ => false,
                    };
                    will_ack = pan_ok && addr_ok;
                    if will_ack && is_poll {
                        let (s, e) = match src {
                            Address::Short(s) => (s.0, 0),
                            Address::Extended(e) => (0xfffe, ext_to_u64(&e)),
                            _ => (0xfffe, 0),
                        };
                        fp = self.nodes[j].radio.src_match.ack_frame_pending(s, e);
                    }
                }
                let info = PsduRxInfo {
                    len: psdu.len(),
                    channel: tx.channel,
                    rssi: Some(rssi),
                    lqi: Some(lqi_of(rssi)),
                    timestamp_us: None,
                    ack_security: None,
                    acked_with_frame_pending: will_ack.then_some(fp),
                };
                self.schedule(
                    on_air_until,
                    Ev::Rx {
                        node: j,
                        psdu: psdu.clone(),
                        info,
                    },
                );
                if !received_by.contains(&j) {
                    received_by.push(j);
                }
                if will_ack
                    && acked.is_none()
                    && let Some(r2) = self.medium.delivered(j, i)
                {
                    let mut buf = [0u8; 16];
                    let n = FrameBuilder::imm_ack_for(&mut buf, &frame, fp).expect("ack");
                    let f = fcs(&buf[..n]);
                    let mut a = buf[..n].to_vec();
                    a.extend_from_slice(&f);
                    let info = PsduRxInfo {
                        len: a.len(),
                        channel: tx.channel,
                        rssi: Some(r2),
                        lqi: Some(lqi_of(r2)),
                        timestamp_us: None,
                        ack_security: None,
                        acked_with_frame_pending: None,
                    };
                    acked = Some((a, info));
                }
            }
            if acked.is_some() {
                t = on_air_until + TURNAROUND + air_time(5);
                break;
            }
            t = on_air_until + if expect_ack { ACK_WAIT } else { Duration::ZERO };
        }
        if self.log_tx {
            self.tx_log.push(TxRecord {
                at: now,
                from: i,
                psdu: psdu.clone(),
                received_by,
                acked: acked.is_some(),
            });
        }
        self.schedule(
            t,
            Ev::TxDone {
                node: i,
                ack: acked,
                expected_ack: expect_ack,
            },
        );
    }
}

fn lqi_of(rssi: i8) -> u8 {
    (i32::from(rssi) + 100).clamp(0, 100) as u8 * 2 + 50
}

impl core::fmt::Debug for Network {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Network")
            .field("now", &self.now)
            .field("nodes", &self.nodes.len())
            .finish()
    }
}

impl core::fmt::Debug for SimNode {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SimNode")
            .field("inst", &self.inst)
            .finish_non_exhaustive()
    }
}
