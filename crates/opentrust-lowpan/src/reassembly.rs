//! Fragment reassembly (RFC 4944 §5.3) with OpenThread's semantics.
//!
//! The table has a fixed number of slots, each able to hold one datagram of
//! up to `MAX_DATAGRAM` bytes. It is sans-IO: the caller passes `now` and
//! polls [`Reassembler::next_deadline`] / [`Reassembler::expire`].
//!
//! Behaviour (as OpenThread's `MeshForwarder::HandleFragment`):
//!
//! - a first fragment (FRAG1, or FRAGN with offset 0) is decompressed using
//!   the datagram size from its header and starts a new reassembly;
//! - a next fragment must have the same (originator, size, tag) as a pending
//!   reassembly and arrive *in order* (its offset equals the number of bytes
//!   received so far) with matching link security; anything else is dropped
//!   (duplicates, gaps, overlaps), leaving the pending reassembly untouched;
//! - every accepted fragment restarts the reassembly timeout
//!   ([`REASSEMBLY_TIMEOUT`]).
//!
//! Unlike OpenThread, the originator address is part of the match key, and a
//! repeated FRAG1 for a pending (originator, size, tag) is dropped instead
//! of starting a second reassembly.

use opentrust_core::time::{Duration, Instant};
use opentrust_core::{Error, Result};
use opentrust_mac::frame::Address;

use crate::frag::FragmentHeader;
use crate::iphc::{ContextProvider, decompress};

/// Reassembly timeout (OpenThread `OPENTHREAD_CONFIG_6LOWPAN_REASSEMBLY_TIMEOUT`).
pub const REASSEMBLY_TIMEOUT: Duration = Duration::from_secs(2);

/// Largest datagram a Thread device must handle (IPv6 minimum MTU).
pub const THREAD_MTU: usize = 1280;

/// Outcome of feeding a fragment to the [`Reassembler`].
#[derive(Debug, PartialEq, Eq)]
pub enum Reassembled<'a> {
    /// Fragment accepted; the datagram is not complete yet.
    Incomplete,
    /// The datagram is complete (uncompressed IPv6 packet). The slot is
    /// already free again; the data stays valid until the next call.
    Complete(&'a [u8]),
}

#[derive(Debug)]
struct Slot<const MAX: usize> {
    used: bool,
    origin: Address,
    size: u16,
    tag: u16,
    filled: usize,
    secure: bool,
    deadline: Instant,
    buf: [u8; MAX],
}

impl<const MAX: usize> Slot<MAX> {
    const fn empty() -> Self {
        Self {
            used: false,
            origin: Address::None,
            size: 0,
            tag: 0,
            filled: 0,
            secure: false,
            deadline: Instant::ZERO,
            buf: [0; MAX],
        }
    }
}

/// Fixed-capacity reassembly table: `SLOTS` datagrams of up to
/// `MAX_DATAGRAM` bytes each.
#[derive(Debug)]
pub struct Reassembler<const SLOTS: usize, const MAX_DATAGRAM: usize = THREAD_MTU> {
    slots: [Slot<MAX_DATAGRAM>; SLOTS],
    timeout: Duration,
}

impl<const SLOTS: usize, const MAX_DATAGRAM: usize> Default for Reassembler<SLOTS, MAX_DATAGRAM> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const SLOTS: usize, const MAX_DATAGRAM: usize> Reassembler<SLOTS, MAX_DATAGRAM> {
    /// An empty table with the default timeout.
    pub fn new() -> Self {
        Self {
            slots: core::array::from_fn(|_| Slot::empty()),
            timeout: REASSEMBLY_TIMEOUT,
        }
    }

    /// Override the reassembly timeout.
    pub fn set_timeout(&mut self, timeout: Duration) {
        self.timeout = timeout;
    }

    /// Number of reassemblies in progress.
    pub fn pending(&self) -> usize {
        self.slots.iter().filter(|s| s.used).count()
    }

    /// Drop all pending reassemblies (e.g. a sleepy device on a new
    /// secure first fragment, or on role change).
    pub fn clear(&mut self) {
        for s in &mut self.slots {
            s.used = false;
        }
    }

    /// The earliest deadline among pending reassemblies.
    pub fn next_deadline(&self) -> Option<Instant> {
        self.slots
            .iter()
            .filter(|s| s.used)
            .map(|s| s.deadline)
            .min()
    }

    /// Drop reassemblies whose deadline has passed; returns how many.
    pub fn expire(&mut self, now: Instant) -> usize {
        let mut n = 0;
        for s in &mut self.slots {
            if s.used && now >= s.deadline {
                s.used = false;
                n += 1;
            }
        }
        n
    }

    /// Process one fragment frame.
    ///
    /// - `src` / `dst`: the originator and final destination of the
    ///   datagram as used for IPHC (the mesh header addresses if the frame
    ///   had one, else the MAC addresses); `src` is part of the match key,
    /// - `link_security`: whether the frame was secured at the link layer,
    /// - `payload`: the MAC payload after any mesh header, starting with
    ///   the FRAG1/FRAGN header.
    ///
    /// Errors: [`Error::Parse`] for malformed fragments, [`Error::NoBufs`]
    /// if the datagram is too large or the table is full, [`Error::Drop`]
    /// for fragments without a matching reassembly (or duplicates / out of
    /// order). Expired reassemblies are discarded first.
    pub fn handle_fragment<C: ContextProvider + ?Sized>(
        &mut self,
        now: Instant,
        ctxs: &C,
        src: &Address,
        dst: &Address,
        link_security: bool,
        payload: &[u8],
    ) -> Result<Reassembled<'_>> {
        self.expire(now);
        let (hdr, hlen) = FragmentHeader::parse(payload)?;
        let data = &payload[hlen..];
        let size = usize::from(hdr.datagram_size);
        if size == 0 {
            return Err(Error::Parse);
        }
        let matches = |s: &Slot<MAX_DATAGRAM>| {
            s.used && s.origin == *src && s.size == hdr.datagram_size && s.tag == hdr.datagram_tag
        };

        let idx = if hdr.datagram_offset == 0 {
            if size > MAX_DATAGRAM {
                return Err(Error::NoBufs);
            }
            if self.slots.iter().any(matches) {
                return Err(Error::Drop);
            }
            let idx = self
                .slots
                .iter()
                .position(|s| !s.used)
                .ok_or(Error::NoBufs)?;
            let slot = &mut self.slots[idx];
            let d = decompress(
                ctxs,
                src,
                dst,
                data,
                Some(hdr.datagram_size),
                &mut slot.buf[..size],
            )
            // Headers larger than the announced datagram are malformed.
            .map_err(|e| if e == Error::NoBufs { Error::Parse } else { e })?;
            let rest = &data[d.consumed..];
            let filled = d.written + rest.len();
            if filled > size {
                return Err(Error::Parse);
            }
            slot.buf[d.written..filled].copy_from_slice(rest);
            slot.used = true;
            slot.origin = *src;
            slot.size = hdr.datagram_size;
            slot.tag = hdr.datagram_tag;
            slot.filled = filled;
            slot.secure = link_security;
            idx
        } else {
            let off = usize::from(hdr.datagram_offset);
            let idx = self
                .slots
                .iter()
                .position(|s| {
                    matches(s)
                        && s.filled == off
                        && off + data.len() <= size
                        && s.secure == link_security
                })
                .ok_or(Error::Drop)?;
            let slot = &mut self.slots[idx];
            slot.buf[off..off + data.len()].copy_from_slice(data);
            slot.filled += data.len();
            idx
        };

        let slot = &mut self.slots[idx];
        if slot.filled >= size {
            slot.used = false;
            return Ok(Reassembled::Complete(&slot.buf[..size]));
        }
        slot.deadline = now.saturating_add(self.timeout);
        Ok(Reassembled::Incomplete)
    }
}
