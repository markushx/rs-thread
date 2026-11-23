use rs_thread_platform::radio::{Capabilities, Config, MacCapabilities, RadioCaps, SrcMatchConfig};

use crate::rng::SimRng;

/// What the simulated radio is doing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RadioState {
    /// Sleeping: nothing is received.
    Sleep,
    /// Receiving on a channel.
    Receive(u8),
}

/// The state of one simulated radio (what the stack configured).
#[derive(Debug, Clone)]
pub struct SimRadio {
    /// Current state.
    pub state: RadioState,
    /// PAN ID / address filter.
    pub config: Config,
    /// Source match table (Frame Pending of data poll ACKs).
    pub src_match: SrcMatchConfig,
}

impl SimRadio {
    pub(crate) fn new() -> Self {
        Self {
            state: RadioState::Sleep,
            config: Config::new(),
            src_match: SrcMatchConfig::new(),
        }
    }

    /// Capabilities the simulated radio reports: retries, CSMA backoff,
    /// ACK timeout and energy scan; automatic ACK reception and sending
    /// with a source match table. Address filtering is left to the MAC.
    pub fn caps() -> RadioCaps {
        RadioCaps {
            phy: Capabilities::ACK_TIMEOUT
                | Capabilities::TRANSMIT_RETRIES
                | Capabilities::CSMA_BACKOFF
                | Capabilities::ENERGY_SCAN,
            mac: MacCapabilities::TX_ACK | MacCapabilities::RX_ACK | MacCapabilities::SRC_MATCH,
            ..RadioCaps::default()
        }
    }
}

/// Parameters of one directed link.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Link {
    /// Received signal strength in dBm.
    pub rssi: i8,
    /// Probability that a frame on this link is lost.
    pub loss: f64,
}

/// Link matrix, jamming and randomness of the medium.
#[derive(Debug, Clone)]
pub struct Medium {
    links: Vec<Vec<Option<Link>>>,
    jammed: Vec<(u8, rs_thread_core::time::Instant)>,
    rng: SimRng,
    /// Number of transmissions attempted by a radio per frame
    /// (OpenThread `kMaxFrameRetriesDirect` + 1).
    pub max_tries: u8,
}

impl Medium {
    pub(crate) fn new(n: usize, seed: u64) -> Self {
        Self {
            links: vec![vec![None; n]; n],
            jammed: Vec::new(),
            rng: SimRng::new(seed),
            max_tries: 16,
        }
    }

    /// Symmetric link between `a` and `b`.
    pub fn connect(&mut self, a: usize, b: usize, rssi: i8) {
        let l = Some(Link { rssi, loss: 0.0 });
        self.links[a][b] = l;
        self.links[b][a] = l;
    }

    /// Remove the link between `a` and `b`.
    pub fn disconnect(&mut self, a: usize, b: usize) {
        self.links[a][b] = None;
        self.links[b][a] = None;
    }

    /// Remove all links of `a`.
    pub fn isolate(&mut self, a: usize) {
        for b in 0..self.links.len() {
            self.disconnect(a, b);
        }
    }

    /// Loss probability from `a` to `b` (the link must exist).
    pub fn set_loss(&mut self, a: usize, b: usize, loss: f64) {
        if let Some(l) = &mut self.links[a][b] {
            l.loss = loss;
        }
    }

    /// The link from `a` to `b`.
    pub fn link(&self, a: usize, b: usize) -> Option<Link> {
        self.links[a][b]
    }

    /// Make CCA on `channel` fail until `until`.
    pub fn jam(&mut self, channel: u8, until: rs_thread_core::time::Instant) {
        self.jammed.push((channel, until));
    }

    pub(crate) fn is_jammed(&self, channel: u8, now: rs_thread_core::time::Instant) -> bool {
        self.jammed.iter().any(|(c, t)| *c == channel && now < *t)
    }

    /// Does a frame from `a` reach `b` (draws the loss)?
    pub(crate) fn delivered(&mut self, a: usize, b: usize) -> Option<i8> {
        let l = self.links[a][b]?;
        if l.loss > 0.0 && self.rng.unit() < l.loss {
            return None;
        }
        Some(l.rssi)
    }
}
