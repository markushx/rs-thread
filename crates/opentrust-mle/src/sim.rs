//! Multi-node simulation harness for the router / leader tests: N cores
//! with fake environments, a link matrix (RSS or no link) and deterministic
//! time. Test-only.

#![allow(dead_code)] // a test toolbox: not every helper is used by every test

use heapless::Vec;
use opentrust_core::time::{Duration, Instant};

use crate::env::Role;
use crate::message::Command;
use crate::mle::{Mle, MleConfig};
use crate::test_support::TestEnv;
use crate::tlv::DeviceMode;

pub(crate) const T0: Instant = Instant::from_secs(1000);
pub(crate) const FTD: DeviceMode = DeviceMode::new(true, true, true);
pub(crate) const MAX_NODES: usize = 5;

pub(crate) struct Node {
    pub mle: Mle<4>,
    pub env: TestEnv,
    /// Messages received, by command number.
    pub rx: [u32; 24],
    /// Messages sent that reached at least one receiver, by command number.
    pub tx: [u32; 24],
}

impl Node {
    pub fn count_rx(&self, c: Command) -> u32 {
        self.rx[c.as_u8() as usize]
    }
    pub fn count_tx(&self, c: Command) -> u32 {
        self.tx[c.as_u8() as usize]
    }
}

pub(crate) struct Sim {
    pub nodes: Vec<Node, MAX_NODES>,
    pub now: Instant,
    link: [[Option<i8>; MAX_NODES]; MAX_NODES],
}

impl Sim {
    /// `n` FTD nodes with ext addresses `ext(1)..=ext(n)`, no links.
    pub fn new(n: u8) -> Self {
        let mut nodes = Vec::new();
        for i in 1..=n {
            let _ = nodes.push(Node {
                mle: Mle::new(MleConfig::new(FTD)),
                env: TestEnv::new(i),
                rx: [0; 24],
                tx: [0; 24],
            });
        }
        Self {
            nodes,
            now: T0,
            link: [[None; MAX_NODES]; MAX_NODES],
        }
    }

    /// Symmetric link between nodes `a` and `b` (indices) with `rss`.
    pub fn connect(&mut self, a: usize, b: usize, rss: i8) {
        self.link[a][b] = Some(rss);
        self.link[b][a] = Some(rss);
    }

    pub fn disconnect(&mut self, a: usize, b: usize) {
        self.link[a][b] = None;
        self.link[b][a] = None;
    }

    /// Cut every link of node `a`.
    pub fn isolate(&mut self, a: usize) {
        for b in 0..MAX_NODES {
            self.link[a][b] = None;
            self.link[b][a] = None;
        }
    }

    pub fn start(&mut self, i: usize) {
        let now = self.now;
        let n = &mut self.nodes[i];
        n.mle.start(&mut n.env, now).unwrap();
        self.pump();
    }

    /// Deliver queued messages until all outputs are consumed.
    pub fn pump(&mut self) {
        for _ in 0..200 {
            let mut moved = false;
            for src in 0..self.nodes.len() {
                let outs = self.nodes[src].env.take_out();
                for o in outs {
                    moved = true;
                    for dst in 0..self.nodes.len() {
                        let Some(rss) = self.link[src][dst] else {
                            continue;
                        };
                        if dst == src {
                            continue;
                        }
                        let now = self.now;
                        let n = &mut self.nodes[dst];
                        if let Ok(cmd) = TestEnv::deliver(&o, &mut n.mle, &mut n.env, now, rss) {
                            n.rx[cmd.as_u8() as usize] += 1;
                            self.nodes[src].tx[cmd.as_u8() as usize] += 1;
                        }
                    }
                }
            }
            if !moved {
                return;
            }
        }
        panic!("message storm");
    }

    fn next_deadline(&self) -> Option<Instant> {
        self.nodes
            .iter()
            .filter_map(|n| n.mle.next_deadline())
            .min()
    }

    /// Advance time by `d`, polling every core at the earliest deadline.
    pub fn run(&mut self, d: Duration) {
        let end = self.now + d;
        for _ in 0..2_000_000 {
            match self.next_deadline() {
                Some(t) if t <= end => {
                    self.now = self.now.max(t);
                    let now = self.now;
                    for n in self.nodes.iter_mut() {
                        n.mle.poll(&mut n.env, now);
                    }
                    self.pump();
                }
                _ => break,
            }
        }
        self.now = end;
    }

    /// Run in 100 ms steps until `f` holds (or `max` elapsed); returns `f`.
    pub fn run_until(&mut self, max: Duration, mut f: impl FnMut(&Self) -> bool) -> bool {
        let end = self.now + max;
        while self.now < end {
            if f(self) {
                return true;
            }
            self.run(Duration::from_millis(100));
        }
        f(self)
    }

    pub fn role(&self, i: usize) -> Role {
        self.nodes[i].mle.role()
    }
}
