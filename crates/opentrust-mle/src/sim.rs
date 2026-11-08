//! Multi-node simulation harness for the router / leader tests: N cores
//! with fake environments, a link matrix (RSS or no link) and deterministic
//! time. Test-only.

#![allow(dead_code, missing_docs, missing_debug_implementations)] // a test toolbox: not every helper is used by every test

extern crate std;

use heapless::Vec;
use opentrust_core::time::{Duration, Instant};

use crate::env::Role;
use crate::message::Command;
use crate::mle::{Mle, MleConfig};
use crate::test_support::TestEnv;
use crate::tlv::DeviceMode;

pub const T0: Instant = Instant::from_secs(1000);
pub const FTD: DeviceMode = DeviceMode::new(true, true, true);
pub const MAX_NODES: usize = 5;

pub struct Node {
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

pub struct Sim {
    pub nodes: Vec<Node, MAX_NODES>,
    pub now: Instant,
    link: [[Option<i8>; MAX_NODES]; MAX_NODES],
}

impl Sim {
    /// `n` FTD nodes with ext addresses `ext(1)..=ext(n)`, no links.
    pub fn new(n: u8) -> Self {
        Self::with_modes(&[FTD; MAX_NODES][..usize::from(n)])
    }

    /// One node per entry of `modes`, ext addresses `ext(1)..`.
    pub fn with_modes(modes: &[DeviceMode]) -> Self {
        let mut nodes = Vec::new();
        for (i, mode) in (1u8..).zip(modes) {
            let _ = nodes.push(Node {
                mle: Mle::new(MleConfig::new(*mode)),
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

    /// RSS of the link from `a` to `b`, if any.
    pub fn link(&self, a: usize, b: usize) -> Option<i8> {
        self.link[a][b]
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
                        match TestEnv::deliver(&o, &mut n.mle, &mut n.env, now, rss) {
                            Ok(cmd) => {
                                n.rx[cmd.as_u8() as usize] += 1;
                                self.nodes[src].tx[cmd.as_u8() as usize] += 1;
                            }
                            Err(e) => {
                                if std::env::var_os("MLE_SIM_TRACE").is_some() {
                                    std::eprintln!("{src}->{dst} dropped: {e:?}");
                                }
                            }
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

    /// Phase 7 stand-in: let node `idx` (a REED that asked for a router ID)
    /// get one from the leader at node `leader`; node `idx` becomes router.
    pub fn grant_router(&mut self, leader: usize, idx: usize) {
        let now = self.now;
        let req = self.nodes[idx]
            .env
            .solicits
            .pop()
            .expect("no Address Solicit");
        let ext = self.nodes[idx].env.ext;
        let previous = self.nodes[idx]
            .mle
            .previous_router_id()
            .map(|i| opentrust_core::types::Rloc16(u16::from(i) << 10));
        let grant = {
            let a = &mut self.nodes[leader];
            a.mle
                .handle_address_solicit(&mut a.env, now, ext, previous, req.reason as u8)
                .expect("grant")
        };
        let b = &mut self.nodes[idx];
        b.mle.address_solicit_reply(
            &mut b.env,
            now,
            crate::router::RouterIdReply::Granted {
                rloc16: grant.rloc16,
                id_sequence: grant.id_sequence,
                mask: grant.mask,
            },
        );
        self.pump();
    }

    /// Make node `idx` a router: wait for its Address Solicit and grant it.
    pub fn upgrade(&mut self, leader: usize, idx: usize) {
        assert!(
            self.run_until(Duration::from_secs(200), |s| !s.nodes[idx]
                .env
                .solicits
                .is_empty()),
            "no Address Solicit"
        );
        self.grant_router(leader, idx);
        assert_eq!(self.role(idx), Role::Router);
    }

    /// Make router `idx` see more active routers than the downgrade
    /// threshold, so that after the role transition delay it re-attaches
    /// as a REED and releases its router ID.
    pub fn force_downgrade(&mut self, idx: usize) {
        let now = self.now;
        let n = &mut self.nodes[idx];
        n.mle.cfg.router.downgrade_threshold = 1;
        n.mle.cfg.router.selection_jitter_secs = 3;
        n.mle.start_role_transition(&mut n.env);
        let mut mask = n.mle.router_id_mask();
        for id in [50, 51] {
            mask.insert(id).unwrap();
        }
        let seq = n.mle.router_id_sequence();
        n.mle.update_router_id_set(&mut n.env, now, seq, &mask);
    }
}
