//! Indirect transmission to sleepy children (OT `IndirectSender`,
//! `SourceMatchController`, `DataPollHandler`).
//!
//! A sleepy end device only listens right after it sent a data poll. The
//! parent therefore queues the IPv6 datagrams (and supervision messages)
//! for it in an [`IndirectQueue`] and releases one frame per data poll:
//!
//! - the Frame Pending bit in the ACK of a data poll is
//!   [`IndirectQueue::frame_pending`] (OT source match table:
//!   [`IndirectQueue::src_match_children`] lists the children the radio's
//!   source match table must contain; it is derived from the queue and
//!   cannot get out of sync);
//! - on a data poll [`IndirectQueue::next_frame`] builds the next frame of
//!   the child's oldest message (or an empty frame if there is none);
//!   [`IndirectQueue::frame_result`] reports the transmission result, and
//!   [`IndirectQueue::handle_data_poll`] does both through a
//!   [`FrameSink`];
//! - a datagram larger than one frame is fragmented and sent over several
//!   polls; every frame but the last carries Frame Pending so the child
//!   polls again at once;
//! - [`IndirectQueue::remove_child`] purges a child (timeout, detach, mode
//!   change to rx-on-when-idle).
//!
//! Supervision messages (an empty data frame) keep the child's data poll
//! meaningful: [`IndirectQueue::enqueue_supervision`] adds one unless the
//! child has other messages, and enqueuing a datagram drops a queued
//! supervision message (OT `AddMessageForSleepyChild`).

use opentrust_core::types::Rloc16;
use opentrust_core::{Error, Result};
use opentrust_lowpan::frag::Fragmenter;
use opentrust_lowpan::iphc::ContextProvider;
use opentrust_mac::frame::Address;

use crate::forwarder::{FrameSink, MacDest, TxFrame};
use crate::radio::RadioLink;

/// Largest datagram that is queued (IPv6 minimum MTU).
pub const MAX_DATAGRAM: usize = 1280;

/// Failed transmissions of one message after which it is dropped (OT
/// `OPENTHREAD_CONFIG_MAC_MAX_TX_ATTEMPTS_INDIRECT_POLLS`).
pub const MAX_POLL_TX_ATTEMPTS: u8 = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Datagram,
    Supervision,
}

#[derive(Debug)]
struct Entry {
    child: Rloc16,
    kind: Kind,
    order: u32,
    tag: u16,
    len: usize,
    /// Frames of this message that were acknowledged.
    frames_done: u16,
    /// Failed attempts of the frame in flight.
    attempts: u8,
    datagram: [u8; MAX_DATAGRAM],
}

/// A frame for a child produced by [`IndirectQueue::next_frame`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IndirectFrame {
    /// Length of the frame payload written to the output buffer (0 for an
    /// empty frame).
    pub len: usize,
    /// More frames (fragments or further messages) follow for this child:
    /// set Frame Pending.
    pub frame_pending: bool,
    /// `true` if this is an empty frame (supervision message, or no message
    /// queued).
    pub empty: bool,
    /// The frame belongs to a queued message: report the result with
    /// [`IndirectQueue::frame_result`].
    pub message: bool,
}

/// What [`IndirectQueue::handle_data_poll`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PollOutcome {
    /// A frame was sent and acknowledged.
    Sent {
        /// The frame carried Frame Pending.
        frame_pending: bool,
    },
    /// The transmission failed; the frame stays queued (until
    /// [`MAX_POLL_TX_ATTEMPTS`]).
    Failed,
}

/// Per-child message queue with room for `N` messages in total.
#[derive(Debug)]
pub struct IndirectQueue<const N: usize> {
    slots: [Option<Entry>; N],
    next_order: u32,
    tags: opentrust_lowpan::frag::TagCounter,
    dirty: bool,
}

impl<const N: usize> Default for IndirectQueue<N> {
    fn default() -> Self {
        Self::new(1)
    }
}

impl<const N: usize> IndirectQueue<N> {
    /// Empty queue; `tag_seed` seeds the datagram tag counter.
    pub const fn new(tag_seed: u16) -> Self {
        Self {
            slots: [const { None }; N],
            next_order: 0,
            tags: opentrust_lowpan::frag::TagCounter::new(tag_seed),
            dirty: false,
        }
    }

    /// Drop everything (role change).
    pub fn clear(&mut self) {
        if !self.is_empty() {
            self.dirty = true;
        }
        for s in &mut self.slots {
            *s = None;
        }
    }

    /// Number of messages queued for `child`.
    pub fn count(&self, child: Rloc16) -> usize {
        self.slots
            .iter()
            .flatten()
            .filter(|e| e.child == child)
            .count()
    }

    /// Total number of queued messages.
    pub fn len(&self) -> usize {
        self.slots.iter().flatten().count()
    }

    /// `true` if nothing is queued.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The Frame Pending bit for the ACK of a data poll from `child`.
    pub fn frame_pending(&self, child: Rloc16) -> bool {
        self.count(child) > 0
    }

    /// Children with queued messages, i.e. the contents of the radio's
    /// source match table (each child once, oldest message first).
    pub fn src_match_children(&self) -> impl Iterator<Item = Rloc16> + '_ {
        self.slots.iter().flatten().filter_map(move |e| {
            let first = self
                .slots
                .iter()
                .flatten()
                .filter(|o| o.child == e.child)
                .map(|o| o.order)
                .min();
            (first == Some(e.order)).then_some(e.child)
        })
    }

    /// `true` once since the last call if the source match table content
    /// changed (a child got its first message or lost its last one).
    pub fn take_src_match_changed(&mut self) -> bool {
        core::mem::take(&mut self.dirty)
    }

    fn head(&self, child: Rloc16) -> Option<usize> {
        self.slots
            .iter()
            .enumerate()
            .filter_map(|(i, e)| {
                e.as_ref()
                    .filter(|e| e.child == child)
                    .map(|e| (i, e.order))
            })
            .min_by_key(|&(_, o)| o)
            .map(|(i, _)| i)
    }

    fn free_slot(&self) -> Result<usize> {
        self.slots
            .iter()
            .position(Option::is_none)
            .ok_or(Error::NoBufs)
    }

    fn insert(&mut self, child: Rloc16, kind: Kind, datagram: &[u8]) -> Result<()> {
        let i = self.free_slot()?;
        let had = self.count(child) > 0;
        let order = self.next_order;
        self.next_order = self.next_order.wrapping_add(1);
        let tag = self.tags.next_tag();
        let mut e = Entry {
            child,
            kind,
            order,
            tag,
            len: datagram.len(),
            frames_done: 0,
            attempts: 0,
            datagram: [0; MAX_DATAGRAM],
        };
        e.datagram[..datagram.len()].copy_from_slice(datagram);
        self.slots[i] = Some(e);
        self.dirty |= !had;
        Ok(())
    }

    /// Queue `datagram` (uncompressed IPv6) for `child` (OT
    /// `AddMessageForSleepyChild`). A queued supervision message of the
    /// child is dropped. [`Error::NoBufs`] if the queue is full,
    /// [`Error::InvalidArgs`] if the datagram is too large.
    pub fn enqueue(&mut self, child: Rloc16, datagram: &[u8]) -> Result<()> {
        if datagram.len() > MAX_DATAGRAM {
            return Err(Error::InvalidArgs);
        }
        // A real message makes the supervision message superfluous.
        self.drop_supervision(child);
        self.insert(child, Kind::Datagram, datagram)
    }

    fn drop_supervision(&mut self, child: Rloc16) {
        for s in &mut self.slots {
            if s.as_ref()
                .is_some_and(|e| e.child == child && e.kind == Kind::Supervision)
            {
                *s = None;
            }
        }
    }

    /// Queue a supervision message for `child` unless it has messages
    /// already (they make the poll worthwhile). Returns `true` if queued.
    pub fn enqueue_supervision(&mut self, child: Rloc16) -> bool {
        if self.count(child) > 0 {
            return false;
        }
        self.insert(child, Kind::Supervision, &[]).is_ok()
    }

    /// Drop everything queued for `child` (OT
    /// `ClearAllMessagesForSleepyChild`); returns how many messages.
    pub fn remove_child(&mut self, child: Rloc16) -> usize {
        let mut n = 0;
        for s in &mut self.slots {
            if s.as_ref().is_some_and(|e| e.child == child) {
                *s = None;
                n += 1;
            }
        }
        if n > 0 {
            self.dirty = true;
        }
        n
    }

    /// Remove the oldest queued datagram of `child` and copy it to `out`
    /// (supervision messages are dropped); `None` if there is none. Used
    /// to convert indirect messages to direct ones when the child stops
    /// sleeping (OT `IndirectSender::HandleChildModeChange`).
    pub fn take_datagram(&mut self, child: Rloc16, out: &mut [u8; MAX_DATAGRAM]) -> Option<usize> {
        self.drop_supervision(child);
        let i = self.head(child)?;
        let e = self.slots[i].take()?;
        out[..e.len].copy_from_slice(&e.datagram[..e.len]);
        self.dirty |= self.count(child) == 0;
        Some(e.len)
    }

    /// Build the frame to send to `child` after its data poll into `out`
    /// (at most `max_payload` bytes): the next frame of its oldest message,
    /// or an empty frame. Nothing is consumed until
    /// [`IndirectQueue::frame_result`].
    pub fn next_frame<C: ContextProvider + ?Sized>(
        &self,
        child: Rloc16,
        own_rloc16: Rloc16,
        contexts: &C,
        max_payload: usize,
        out: &mut [u8],
    ) -> Result<IndirectFrame> {
        let Some(i) = self.head(child) else {
            return Ok(IndirectFrame {
                len: 0,
                frame_pending: false,
                empty: true,
                message: false,
            });
        };
        let e = self.slots[i].as_ref().ok_or(Error::NotFound)?;
        if e.kind == Kind::Supervision {
            return Ok(IndirectFrame {
                len: 0,
                frame_pending: self.count(child) > 1,
                empty: true,
                message: true,
            });
        }
        let mut f = Fragmenter::new(
            contexts,
            Address::Short(own_rloc16.into()),
            Address::Short(child.into()),
            &e.datagram[..e.len],
            e.tag,
            None,
            max_payload,
        );
        for _ in 0..e.frames_done {
            f.next_frame(out)?;
        }
        let len = f.next_frame(out)?.ok_or(Error::NotFound)?;
        Ok(IndirectFrame {
            len,
            frame_pending: !f.is_done() || self.count(child) > 1,
            empty: false,
            message: true,
        })
    }

    /// Result of transmitting the frame from [`IndirectQueue::next_frame`]:
    /// on success the message advances (and is removed after its last
    /// frame); on failure it is retried at the next poll until
    /// [`MAX_POLL_TX_ATTEMPTS`] attempts failed, then dropped.
    pub fn frame_result<C: ContextProvider + ?Sized>(
        &mut self,
        child: Rloc16,
        own_rloc16: Rloc16,
        contexts: &C,
        max_payload: usize,
        ok: bool,
    ) {
        let Some(i) = self.head(child) else { return };
        let mut scratch = [0u8; 128];
        let done = {
            let Some(e) = self.slots[i].as_mut() else {
                return;
            };
            if !ok {
                e.attempts += 1;
                e.attempts >= MAX_POLL_TX_ATTEMPTS
            } else if e.kind == Kind::Supervision {
                true
            } else {
                e.attempts = 0;
                e.frames_done += 1;
                let mut f = Fragmenter::new(
                    contexts,
                    Address::Short(own_rloc16.into()),
                    Address::Short(child.into()),
                    &e.datagram[..e.len],
                    e.tag,
                    None,
                    max_payload,
                );
                for _ in 0..e.frames_done {
                    if f.next_frame(&mut scratch).ok().flatten().is_none() {
                        break;
                    }
                }
                f.is_done()
            }
        };
        if done {
            self.slots[i] = None;
            self.dirty |= self.count(child) == 0;
        }
    }

    /// Hand every queued frame of `child` to `sink` as CSL frames (the
    /// child is CSL synchronized): the messages are consumed as the sink
    /// accepts their frames. A frame the sink refuses (MAC queue full) stays
    /// queued, counts as a failed attempt (the message is dropped after
    /// [`MAX_POLL_TX_ATTEMPTS`]) and stops the flush; the child's data poll
    /// or the next flush picks it up. Returns the number of frames accepted.
    pub fn flush_csl<C: ContextProvider + ?Sized, S: FrameSink + ?Sized>(
        &mut self,
        child: Rloc16,
        own_rloc16: Rloc16,
        contexts: &C,
        max_payload: usize,
        sink: &mut S,
    ) -> usize {
        let mut buf = [0u8; 128];
        let mut sent = 0;
        while self.count(child) > 0 {
            let Ok(f) = self.next_frame(child, own_rloc16, contexts, max_payload, &mut buf) else {
                break;
            };
            let ok = sink
                .transmit(&TxFrame {
                    src: Address::Short(own_rloc16.into()),
                    dst: MacDest::Short(child),
                    payload: &buf[..f.len],
                    link_security: true,
                    frame_pending: false,
                    indirect: true,
                    csl: true,
                    radio: RadioLink::Ieee802154,
                })
                .is_ok();
            if f.message {
                self.frame_result(child, own_rloc16, contexts, max_payload, ok);
            }
            if !ok {
                break;
            }
            sent += 1;
        }
        sent
    }

    /// Answer a data poll from `child`: send its next frame (an empty
    /// frame if nothing is queued) through `sink` and record the result.
    pub fn handle_data_poll<C: ContextProvider + ?Sized, S: FrameSink + ?Sized>(
        &mut self,
        child: Rloc16,
        own_rloc16: Rloc16,
        contexts: &C,
        max_payload: usize,
        sink: &mut S,
    ) -> Result<PollOutcome> {
        let mut buf = [0u8; 128];
        let f = self.next_frame(child, own_rloc16, contexts, max_payload, &mut buf)?;
        let ok = sink
            .transmit(&TxFrame {
                src: Address::Short(own_rloc16.into()),
                dst: MacDest::Short(child),
                payload: &buf[..f.len],
                link_security: true,
                frame_pending: f.frame_pending,
                indirect: true,
                csl: false,
                radio: RadioLink::Ieee802154,
            })
            .is_ok();
        if f.message {
            self.frame_result(child, own_rloc16, contexts, max_payload, ok);
        }
        Ok(if ok {
            PollOutcome::Sent {
                frame_pending: f.frame_pending,
            }
        } else {
            PollOutcome::Failed
        })
    }
}
