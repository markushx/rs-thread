//! Parent-side support for sleepy children: the indirect frame queue, the
//! source-match table that decides the Frame Pending bit of data poll ACKs,
//! and the short → extended address map.
//!
//! The queue is deliberately minimal: frames are kept per destination
//! address in arrival order until the child polls; the child table (and
//! with it child supervision, CSL and message-level queueing of IPv6
//! datagrams) lives in MLE. OpenThread's `SourceMatchController` keeps a
//! per-child message count; here the table is derived from the queue
//! contents plus explicitly pinned addresses ([`SrcMatch::pin`]), so it can
//! never go out of sync.

use heapless::Vec;
use opentrust_core::types::{ExtAddress, ShortAddress};
use opentrust_core::{Error, Result};
use opentrust_platform::radio::SrcMatchConfig;

use super::consts::SRC_MATCH_CAPACITY;
use super::types::{FrameBuf, TxHandle};
use crate::frame::Address;

/// `u64` form of an extended address for [`SrcMatchConfig`] / radio
/// [`Config`](opentrust_platform::radio::Config): the canonical (big-endian)
/// byte order read as a big-endian integer.
pub fn ext_to_u64(e: &ExtAddress) -> u64 {
    u64::from_be_bytes(e.0)
}

/// Short → extended address map (the subset of the neighbor table the MAC
/// needs to build CCM* nonces for frames sent from a short address).
#[derive(Debug, Default)]
pub(crate) struct NeighborMap<const N: usize> {
    entries: Vec<(ShortAddress, ExtAddress), N>,
}

impl<const N: usize> NeighborMap<N> {
    pub fn set(&mut self, short: ShortAddress, ext: ExtAddress) -> Result<()> {
        if let Some(e) = self.entries.iter_mut().find(|(s, _)| *s == short) {
            e.1 = ext;
            return Ok(());
        }
        self.entries.push((short, ext)).map_err(|_| Error::NoBufs)
    }

    pub fn remove(&mut self, short: ShortAddress) -> bool {
        match self.entries.iter().position(|(s, _)| *s == short) {
            Some(i) => {
                self.entries.swap_remove(i);
                true
            }
            None => false,
        }
    }

    pub fn clear(&mut self) {
        self.entries.clear();
    }

    pub fn ext_of(&self, short: ShortAddress) -> Option<ExtAddress> {
        self.entries
            .iter()
            .find(|(s, _)| *s == short)
            .map(|(_, e)| *e)
    }

    /// The extended address behind `a`, if known.
    pub fn resolve(&self, a: Address) -> Option<ExtAddress> {
        match a {
            Address::Extended(e) => Some(e),
            Address::Short(s) => self.ext_of(s),
            Address::None => None,
        }
    }

    /// Do `a` and `b` name the same device (directly or via the map)?
    pub fn same_device(&self, a: Address, b: Address) -> bool {
        if a == b {
            return !a.is_none();
        }
        match (a, b) {
            (Address::Short(s), Address::Extended(e))
            | (Address::Extended(e), Address::Short(s)) => self.ext_of(s) == Some(e),
            _ => false,
        }
    }
}

/// A frame waiting for its sleepy destination to poll.
#[derive(Debug, Clone)]
pub(crate) struct IndirectFrame {
    pub handle: TxHandle,
    pub dst: Address,
    /// The frame without FCS; secured in place on the first attempt.
    pub frame: FrameBuf,
    /// Polls this frame was offered to.
    pub attempts: u8,
    /// Set once sequence number, Frame Pending bit and security are applied
    /// (later attempts resend the identical bytes).
    pub prepared: bool,
    /// Security done by the MAC or not needed (else left to the radio).
    pub security_processed: bool,
    /// Sent at least once in a CSL window (a retransmission is flagged).
    #[cfg(feature = "csl")]
    pub sent: bool,
}

/// The parent's indirect queue.
#[derive(Debug, Default)]
pub(crate) struct IndirectQueue<const N: usize> {
    pub frames: Vec<IndirectFrame, N>,
}

impl<const N: usize> IndirectQueue<N> {
    pub fn push(&mut self, handle: TxHandle, dst: Address, frame: FrameBuf) -> Result<()> {
        if dst.is_none() || dst.is_broadcast() {
            return Err(Error::InvalidArgs);
        }
        self.frames
            .push(IndirectFrame {
                handle,
                dst,
                frame,
                attempts: 0,
                prepared: false,
                security_processed: false,
                #[cfg(feature = "csl")]
                sent: false,
            })
            .map_err(|_| Error::NoBufs)
    }

    /// Index of the oldest frame for the device polling from `src`.
    pub fn find_for<const M: usize>(&self, src: Address, map: &NeighborMap<M>) -> Option<usize> {
        self.frames.iter().position(|f| map.same_device(f.dst, src))
    }

    /// Number of frames queued for the device at `dst`.
    pub fn count_for<const M: usize>(&self, dst: Address, map: &NeighborMap<M>) -> usize {
        self.frames
            .iter()
            .filter(|f| map.same_device(f.dst, dst))
            .count()
    }

    pub fn position(&self, handle: TxHandle) -> Option<usize> {
        self.frames.iter().position(|f| f.handle == handle)
    }

    /// Remove (keeping order) and return the frame at `i`.
    pub fn remove(&mut self, i: usize) -> IndirectFrame {
        self.frames.remove(i)
    }
}

/// Source-match table: which polling children get Frame Pending = 1.
///
/// The effective table is the union of the destinations in the indirect
/// queue and the pinned addresses. If it does not fit
/// [`SRC_MATCH_CAPACITY`], matching is disabled, which answers every poll
/// with Frame Pending = 1 (OpenThread's overflow fallback; the child then
/// receives an empty frame).
#[derive(Debug)]
pub(crate) struct SrcMatch {
    pinned: Vec<Address, SRC_MATCH_CAPACITY>,
    table: SrcMatchConfig,
}

impl Default for SrcMatch {
    fn default() -> Self {
        let mut table = SrcMatchConfig::new();
        // Deviation from OpenThread (which starts disabled, i.e. Frame
        // Pending for everybody until the first entry): start with an empty,
        // enabled table so polls are answered "nothing pending".
        table.enabled = true;
        Self {
            pinned: Vec::new(),
            table,
        }
    }
}

impl SrcMatch {
    pub fn pin(&mut self, a: Address) -> Result<()> {
        if a.is_none() || a.is_broadcast() {
            return Err(Error::InvalidArgs);
        }
        if self.pinned.contains(&a) {
            return Ok(());
        }
        self.pinned.push(a).map_err(|_| Error::NoBufs)
    }

    pub fn unpin(&mut self, a: Address) -> bool {
        match self.pinned.iter().position(|p| *p == a) {
            Some(i) => {
                self.pinned.swap_remove(i);
                true
            }
            None => false,
        }
    }

    pub fn clear_pins(&mut self) {
        self.pinned.clear();
    }

    pub fn table(&self) -> &SrcMatchConfig {
        &self.table
    }

    /// Recompute from the pins and the queue; `true` if the table changed.
    pub fn rebuild<const M: usize>(&mut self, queue: &IndirectQueue<M>) -> bool {
        let mut t = SrcMatchConfig::new();
        t.enabled = true;
        let addrs = self
            .pinned
            .iter()
            .copied()
            .chain(queue.frames.iter().map(|f| f.dst));
        for a in addrs {
            let ok = match a {
                Address::Short(s) => {
                    t.short_addrs.contains(&s.0) || t.short_addrs.push(s.0).is_ok()
                }
                Address::Extended(e) => {
                    let v = ext_to_u64(&e);
                    t.ext_addrs.contains(&v) || t.ext_addrs.push(v).is_ok()
                }
                Address::None => true,
            };
            if !ok {
                t.enabled = false;
            }
        }
        let changed = t != self.table;
        self.table = t;
        changed
    }

    /// The Frame Pending answer for a frame from `src`.
    pub fn frame_pending<const M: usize>(&self, src: Address, map: &NeighborMap<M>) -> bool {
        if !self.table.enabled {
            return true;
        }
        let short_hit = |s: ShortAddress| self.table.short_addrs.contains(&s.0);
        let ext_hit = |e: &ExtAddress| self.table.ext_addrs.contains(&ext_to_u64(e));
        match src {
            Address::Short(s) => short_hit(s) || map.ext_of(s).is_some_and(|e| ext_hit(&e)),
            Address::Extended(e) => {
                ext_hit(&e) || map.entries.iter().any(|(s, x)| *x == e && short_hit(*s))
            }
            Address::None => false,
        }
    }
}
