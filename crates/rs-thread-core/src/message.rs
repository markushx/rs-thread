//! Fixed-capacity, allocation-free message buffers.
//!
//! This is the Rust analogue of OpenThread's `MessagePool`, `Message` and
//! `PriorityQueue` (`src/core/common/message.hpp`). A [`MessagePool`] owns `N`
//! slots of `SIZE` bytes each (Thread needs `SIZE >= 1280` for full-MTU IPv6
//! datagrams, but smaller configurations are fine for constrained devices or
//! tests). [`MessagePool::alloc`] returns an owned [`Message`] handle that
//! returns its slot to the pool when dropped, so slots cannot leak.
//!
//! # Layout and headroom
//!
//! Each slot is a flat byte array. A message occupies `[start, start + len)`
//! inside it. On allocation `headroom` bytes are reserved in front of the
//! (empty) payload so lower layers can [`Message::prepend`] headers (6LoWPAN,
//! MAC, ...) without copying the payload.
//!
//! # Threading model
//!
//! Like OpenThread, the pool is single-threaded. It uses [`Cell`] / [`RefCell`]
//! for interior mutability and is therefore `!Sync`; a [`Message`] borrows the
//! pool (`&'a MessagePool`) and is `!Send`. This lets many messages and queues
//! coexist while all mutation goes through safe interior mutability.
//!
//! # Soundness notes
//!
//! A slot is handed out to exactly one owner at a time: either a [`Message`]
//! handle or a [`PriorityQueue`] (which took ownership of the handle). The
//! payload bytes live in a per-slot [`RefCell`], and the borrow-returning
//! accessors ([`Message::data`], [`Message::data_mut`]) tie the guard's lifetime
//! to `&self` / `&mut self` of the unique handle, so borrow-check panics are
//! impossible in safe use. No `unsafe` code is used.

use core::cell::{Cell, Ref, RefCell, RefMut};
use core::fmt;

use crate::error::{Error, Result};

/// Number of distinct [`Priority`] levels.
pub const NUM_PRIORITIES: usize = 4;

/// Message priority, matching OpenThread's `Message::Priority` values.
///
/// Ordering follows urgency: `Low < Normal < High < Net`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Priority {
    /// Low priority.
    Low = 0,
    /// Normal priority (default).
    Normal = 1,
    /// High priority.
    High = 2,
    /// Network control priority (MLE, routing, ...).
    Net = 3,
}

/// Where an IPv6 message originated (OpenThread `Message::Origin`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Origin {
    /// From the Thread network interface.
    ThreadNetif,
    /// From a trusted source on the host.
    HostTrusted,
    /// From an untrusted source on the host.
    HostUntrusted,
}

/// Message sub-type (subset of OpenThread's `Message::SubType`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[non_exhaustive]
pub enum SubType {
    /// No particular sub-type.
    None,
    /// MLE message.
    Mle,
    /// MPL next retransmission message.
    MplRetransmission,
    /// Joiner Entrust message.
    JoinerEntrust,
    /// Joiner Finalize Response message.
    JoinerFinalizeResponse,
}

/// Per-message metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct MessageMeta {
    /// Queueing / forwarding priority.
    pub priority: Priority,
    /// Whether link-layer security applies when sending.
    pub link_security: bool,
    /// Origin of the message.
    pub origin: Origin,
    /// Message sub-type.
    pub sub_type: SubType,
    /// Cursor into the payload, relative to the message start (OpenThread's
    /// message "offset"); used by parsers to remember how much is consumed.
    pub offset: usize,
}

impl MessageMeta {
    const fn new(priority: Priority) -> Self {
        Self {
            priority,
            link_security: true,
            origin: Origin::ThreadNetif,
            sub_type: SubType::None,
            offset: 0,
        }
    }
}

impl Default for MessageMeta {
    /// Normal priority, link security enabled, from the Thread netif.
    fn default() -> Self {
        Self::new(Priority::Normal)
    }
}

#[derive(Clone, Copy)]
struct SlotState {
    in_use: bool,
    start: usize,
    len: usize,
    meta: MessageMeta,
    /// Next slot in the queue this slot is linked into.
    next: Option<usize>,
}

struct Slot<const SIZE: usize> {
    state: Cell<SlotState>,
    buf: RefCell<[u8; SIZE]>,
}

impl<const SIZE: usize> Slot<SIZE> {
    const fn new() -> Self {
        Self {
            state: Cell::new(SlotState {
                in_use: false,
                start: 0,
                len: 0,
                meta: MessageMeta::new(Priority::Normal),
                next: None,
            }),
            buf: RefCell::new([0; SIZE]),
        }
    }
}

/// A statically sized pool of `N` message buffers of `SIZE` bytes each.
///
/// Single-threaded (`!Sync`); see the [module docs](self).
pub struct MessagePool<const N: usize, const SIZE: usize> {
    slots: [Slot<SIZE>; N],
}

impl<const N: usize, const SIZE: usize> fmt::Debug for MessagePool<N, SIZE> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MessagePool")
            .field("capacity", &N)
            .field("slot_size", &SIZE)
            .field("free", &self.free_count())
            .finish()
    }
}

impl<const N: usize, const SIZE: usize> Default for MessagePool<N, SIZE> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize, const SIZE: usize> MessagePool<N, SIZE> {
    /// Create an empty pool with all slots free (usable in `const` contexts).
    pub const fn new() -> Self {
        Self {
            slots: [const { Slot::new() }; N],
        }
    }

    /// Total number of slots.
    pub const fn capacity(&self) -> usize {
        N
    }

    /// Size in bytes of each slot.
    pub const fn slot_size(&self) -> usize {
        SIZE
    }

    /// Number of currently free slots.
    pub fn free_count(&self) -> usize {
        self.slots.iter().filter(|s| !s.state.get().in_use).count()
    }

    /// Allocate an empty message with default metadata and the given priority,
    /// reserving `headroom` bytes in front of the payload for later
    /// [`Message::prepend`] calls.
    ///
    /// Returns [`Error::NoBufs`] if the pool is exhausted and
    /// [`Error::InvalidArgs`] if `headroom > SIZE`.
    pub fn alloc(&self, priority: Priority, headroom: usize) -> Result<Message<'_, N, SIZE>> {
        if headroom > SIZE {
            return Err(Error::InvalidArgs);
        }
        let idx = self
            .slots
            .iter()
            .position(|s| !s.state.get().in_use)
            .ok_or(Error::NoBufs)?;
        self.slots[idx].state.set(SlotState {
            in_use: true,
            start: headroom,
            len: 0,
            meta: MessageMeta::new(priority),
            next: None,
        });
        Ok(Message { pool: self, idx })
    }

    /// Create a [`PriorityQueue`] bound to this pool.
    pub fn new_queue(&self) -> PriorityQueue<'_, N, SIZE> {
        PriorityQueue {
            pool: self,
            head: [None; NUM_PRIORITIES],
            tail: [None; NUM_PRIORITIES],
            len: 0,
        }
    }

    fn free(&self, idx: usize) {
        let slot = &self.slots[idx];
        let mut st = slot.state.get();
        st.in_use = false;
        st.next = None;
        slot.state.set(st);
    }
}

/// An owned message buffer handle. Returns its slot to the pool on drop.
pub struct Message<'a, const N: usize, const SIZE: usize> {
    pool: &'a MessagePool<N, SIZE>,
    idx: usize,
}

impl<const N: usize, const SIZE: usize> fmt::Debug for Message<'_, N, SIZE> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Message")
            .field("slot", &self.idx)
            .field("len", &self.len())
            .field("headroom", &self.headroom())
            .field("meta", &self.meta())
            .finish()
    }
}

impl<const N: usize, const SIZE: usize> Drop for Message<'_, N, SIZE> {
    fn drop(&mut self) {
        self.pool.free(self.idx);
    }
}

impl<const N: usize, const SIZE: usize> Message<'_, N, SIZE> {
    fn slot(&self) -> &Slot<SIZE> {
        &self.pool.slots[self.idx]
    }

    fn update(&self, f: impl FnOnce(&mut SlotState)) {
        let mut st = self.slot().state.get();
        f(&mut st);
        self.slot().state.set(st);
    }

    /// Payload length in bytes.
    pub fn len(&self) -> usize {
        self.slot().state.get().len
    }

    /// Whether the payload is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Bytes available in front of the payload for [`Self::prepend`].
    pub fn headroom(&self) -> usize {
        self.slot().state.get().start
    }

    /// Bytes available behind the payload for [`Self::append`].
    pub fn tailroom(&self) -> usize {
        let st = self.slot().state.get();
        SIZE - st.start - st.len
    }

    /// Copy of the message metadata.
    pub fn meta(&self) -> MessageMeta {
        self.slot().state.get().meta
    }

    /// Message priority.
    pub fn priority(&self) -> Priority {
        self.meta().priority
    }

    /// Set the message priority.
    pub fn set_priority(&mut self, priority: Priority) {
        self.update(|s| s.meta.priority = priority);
    }

    /// Whether link-layer security is requested.
    pub fn link_security(&self) -> bool {
        self.meta().link_security
    }

    /// Set whether link-layer security is requested.
    pub fn set_link_security(&mut self, enabled: bool) {
        self.update(|s| s.meta.link_security = enabled);
    }

    /// Message origin.
    pub fn origin(&self) -> Origin {
        self.meta().origin
    }

    /// Set the message origin.
    pub fn set_origin(&mut self, origin: Origin) {
        self.update(|s| s.meta.origin = origin);
    }

    /// Message sub-type.
    pub fn sub_type(&self) -> SubType {
        self.meta().sub_type
    }

    /// Set the message sub-type.
    pub fn set_sub_type(&mut self, sub_type: SubType) {
        self.update(|s| s.meta.sub_type = sub_type);
    }

    /// The payload cursor (see [`MessageMeta::offset`]).
    pub fn offset(&self) -> usize {
        self.meta().offset
    }

    /// Set the payload cursor; must be `<= len()`.
    pub fn set_offset(&mut self, offset: usize) -> Result<()> {
        if offset > self.len() {
            return Err(Error::InvalidArgs);
        }
        self.update(|s| s.meta.offset = offset);
        Ok(())
    }

    /// Append `data` to the end of the payload. All-or-nothing: returns
    /// [`Error::NoBufs`] without modifying the message if it does not fit.
    pub fn append(&mut self, data: &[u8]) -> Result<()> {
        if data.len() > self.tailroom() {
            return Err(Error::NoBufs);
        }
        let st = self.slot().state.get();
        let at = st.start + st.len;
        self.slot().buf.borrow_mut()[at..at + data.len()].copy_from_slice(data);
        self.update(|s| s.len += data.len());
        Ok(())
    }

    /// Prepend `data` in front of the payload using the reserved headroom.
    /// All-or-nothing: returns [`Error::NoBufs`] if the headroom is too small.
    ///
    /// The cursor ([`Self::offset`]) keeps pointing at the same payload byte.
    pub fn prepend(&mut self, data: &[u8]) -> Result<()> {
        if data.len() > self.headroom() {
            return Err(Error::NoBufs);
        }
        let st = self.slot().state.get();
        let new_start = st.start - data.len();
        self.slot().buf.borrow_mut()[new_start..st.start].copy_from_slice(data);
        self.update(|s| {
            s.start = new_start;
            s.len += data.len();
            s.meta.offset += data.len();
        });
        Ok(())
    }

    /// Remove `n` bytes from the front of the payload (the removed bytes
    /// become headroom again). The cursor is adjusted (saturating at 0).
    pub fn remove_header(&mut self, n: usize) -> Result<()> {
        if n > self.len() {
            return Err(Error::InvalidArgs);
        }
        self.update(|s| {
            s.start += n;
            s.len -= n;
            s.meta.offset = s.meta.offset.saturating_sub(n);
        });
        Ok(())
    }

    /// Shorten the payload to `len` bytes (no-op if already shorter).
    pub fn truncate(&mut self, len: usize) {
        self.update(|s| {
            if len < s.len {
                s.len = len;
                s.meta.offset = s.meta.offset.min(len);
            }
        });
    }

    /// Borrow the payload bytes.
    pub fn data(&self) -> Ref<'_, [u8]> {
        let st = self.slot().state.get();
        Ref::map(self.slot().buf.borrow(), |b| {
            &b[st.start..st.start + st.len]
        })
    }

    /// Mutably borrow the payload bytes.
    pub fn data_mut(&mut self) -> RefMut<'_, [u8]> {
        let st = self.slot().state.get();
        RefMut::map(self.slot().buf.borrow_mut(), |b| {
            &mut b[st.start..st.start + st.len]
        })
    }

    /// Copy payload bytes starting at `offset` into `out`. Returns the number
    /// of bytes copied (limited by the payload length).
    pub fn read(&self, offset: usize, out: &mut [u8]) -> usize {
        let data = self.data();
        if offset >= data.len() {
            return 0;
        }
        let n = out.len().min(data.len() - offset);
        out[..n].copy_from_slice(&data[offset..offset + n]);
        n
    }

    /// Overwrite existing payload bytes at `offset`. Returns
    /// [`Error::InvalidArgs`] if the range exceeds the payload length.
    pub fn write(&mut self, offset: usize, bytes: &[u8]) -> Result<()> {
        let end = offset.checked_add(bytes.len()).ok_or(Error::InvalidArgs)?;
        if end > self.len() {
            return Err(Error::InvalidArgs);
        }
        self.data_mut()[offset..end].copy_from_slice(bytes);
        Ok(())
    }
}

/// A set of FIFO queues, one per [`Priority`]; dequeues the highest priority
/// first and FIFO within a priority (OpenThread `PriorityQueue`).
///
/// Queued messages are linked intrusively through their pool slots, so no
/// extra memory is needed. The queue owns the messages it holds; dropping the
/// queue frees them.
pub struct PriorityQueue<'a, const N: usize, const SIZE: usize> {
    pool: &'a MessagePool<N, SIZE>,
    head: [Option<usize>; NUM_PRIORITIES],
    tail: [Option<usize>; NUM_PRIORITIES],
    len: usize,
}

impl<const N: usize, const SIZE: usize> fmt::Debug for PriorityQueue<'_, N, SIZE> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PriorityQueue")
            .field("len", &self.len)
            .finish()
    }
}

impl<const N: usize, const SIZE: usize> Drop for PriorityQueue<'_, N, SIZE> {
    fn drop(&mut self) {
        while self.dequeue().is_some() {}
    }
}

impl<'a, const N: usize, const SIZE: usize> PriorityQueue<'a, N, SIZE> {
    /// Number of queued messages.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Whether the queue is empty.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Number of queued messages with the given priority.
    pub fn len_at(&self, priority: Priority) -> usize {
        let mut n = 0;
        let mut cur = self.head[priority as usize];
        while let Some(i) = cur {
            n += 1;
            cur = self.pool.slots[i].state.get().next;
        }
        n
    }

    /// Enqueue `msg` (taking ownership) behind all messages of the same
    /// priority. The message's current priority decides the lane.
    ///
    /// Returns [`Error::InvalidArgs`] (and frees the message) if it belongs to
    /// a different pool.
    pub fn enqueue(&mut self, msg: Message<'a, N, SIZE>) -> Result<()> {
        if !core::ptr::eq(msg.pool, self.pool) {
            return Err(Error::InvalidArgs);
        }
        let idx = msg.idx;
        let lane = msg.priority() as usize;
        // Ownership of the slot moves to the queue: skip the handle's Drop.
        core::mem::forget(msg);
        match self.tail[lane] {
            Some(t) => {
                let slot = &self.pool.slots[t];
                slot.state.set(SlotState {
                    next: Some(idx),
                    ..slot.state.get()
                });
            }
            None => self.head[lane] = Some(idx),
        }
        self.tail[lane] = Some(idx);
        self.len += 1;
        Ok(())
    }

    /// Priority of the message [`Self::dequeue`] would return next.
    pub fn peek_priority(&self) -> Option<Priority> {
        self.highest_lane().map(|p| match p {
            0 => Priority::Low,
            1 => Priority::Normal,
            2 => Priority::High,
            _ => Priority::Net,
        })
    }

    fn highest_lane(&self) -> Option<usize> {
        (0..NUM_PRIORITIES).rev().find(|&p| self.head[p].is_some())
    }

    /// Remove and return the oldest message of the highest non-empty priority.
    pub fn dequeue(&mut self) -> Option<Message<'a, N, SIZE>> {
        let lane = self.highest_lane()?;
        self.pop_lane(lane)
    }

    /// Remove and return the oldest message of exactly the given priority.
    pub fn dequeue_priority(&mut self, priority: Priority) -> Option<Message<'a, N, SIZE>> {
        self.pop_lane(priority as usize)
    }

    fn pop_lane(&mut self, lane: usize) -> Option<Message<'a, N, SIZE>> {
        let idx = self.head[lane]?;
        let slot = &self.pool.slots[idx];
        let st = slot.state.get();
        self.head[lane] = st.next;
        if st.next.is_none() {
            self.tail[lane] = None;
        }
        slot.state.set(SlotState { next: None, ..st });
        self.len -= 1;
        Some(Message {
            pool: self.pool,
            idx,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type Pool = MessagePool<3, 64>;

    #[test]
    fn exhaustion_and_return_on_drop() {
        let pool = Pool::new();
        assert_eq!(pool.free_count(), 3);
        let a = pool.alloc(Priority::Normal, 0).unwrap();
        let b = pool.alloc(Priority::Normal, 0).unwrap();
        let c = pool.alloc(Priority::Normal, 0).unwrap();
        assert_eq!(pool.free_count(), 0);
        assert_eq!(pool.alloc(Priority::Normal, 0).unwrap_err(), Error::NoBufs);
        drop(b);
        assert_eq!(pool.free_count(), 1);
        let d = pool.alloc(Priority::High, 0).unwrap();
        assert_eq!(pool.free_count(), 0);
        drop((a, c, d));
        assert_eq!(pool.free_count(), 3);
    }

    #[test]
    fn headroom_too_large() {
        let pool = Pool::new();
        assert_eq!(
            pool.alloc(Priority::Low, 65).unwrap_err(),
            Error::InvalidArgs
        );
        assert!(pool.alloc(Priority::Low, 64).is_ok());
    }

    #[test]
    fn append_prepend_headroom() {
        let pool = Pool::new();
        let mut m = pool.alloc(Priority::Normal, 10).unwrap();
        assert_eq!(m.headroom(), 10);
        assert_eq!(m.tailroom(), 54);
        m.append(b"payload").unwrap();
        m.set_offset(3).unwrap();
        m.prepend(b"IP6:").unwrap();
        m.prepend(b"MAC").unwrap();
        assert_eq!(&*m.data(), b"MACIP6:payload");
        assert_eq!(m.headroom(), 3);
        assert_eq!(m.offset(), 3 + 7);
        // Not enough headroom: unchanged.
        assert_eq!(m.prepend(b"toolong").unwrap_err(), Error::NoBufs);
        assert_eq!(m.len(), 14);
        m.remove_header(3).unwrap();
        assert_eq!(&*m.data(), b"IP6:payload");
        assert_eq!(m.headroom(), 6);
        m.truncate(4);
        assert_eq!(&*m.data(), b"IP6:");
    }

    #[test]
    fn append_overflow_is_atomic() {
        let pool = MessagePool::<1, 8>::new();
        let mut m = pool.alloc(Priority::Normal, 2).unwrap();
        m.append(&[1; 5]).unwrap();
        assert_eq!(m.append(&[2; 2]).unwrap_err(), Error::NoBufs);
        assert_eq!(m.len(), 5);
        m.append(&[3]).unwrap();
        assert_eq!(m.tailroom(), 0);
        assert_eq!(&*m.data(), &[1, 1, 1, 1, 1, 3]);
    }

    #[test]
    fn read_write() {
        let pool = Pool::new();
        let mut m = pool.alloc(Priority::Normal, 0).unwrap();
        m.append(&[1, 2, 3, 4]).unwrap();
        m.write(1, &[9, 9]).unwrap();
        assert_eq!(m.write(3, &[0, 0]).unwrap_err(), Error::InvalidArgs);
        let mut out = [0u8; 8];
        assert_eq!(m.read(1, &mut out), 3);
        assert_eq!(&out[..3], &[9, 9, 4]);
        assert_eq!(m.read(4, &mut out), 0);
        m.data_mut()[0] = 7;
        assert_eq!(m.data()[0], 7);
        assert_eq!(m.set_offset(5).unwrap_err(), Error::InvalidArgs);
    }

    #[test]
    fn metadata() {
        let pool = Pool::new();
        let mut m = pool.alloc(Priority::High, 0).unwrap();
        assert_eq!(m.priority(), Priority::High);
        assert!(m.link_security());
        assert_eq!(m.origin(), Origin::ThreadNetif);
        assert_eq!(m.sub_type(), SubType::None);
        m.set_link_security(false);
        m.set_origin(Origin::HostUntrusted);
        m.set_sub_type(SubType::Mle);
        m.set_priority(Priority::Net);
        assert!(!m.link_security());
        assert_eq!(m.origin(), Origin::HostUntrusted);
        assert_eq!(m.sub_type(), SubType::Mle);
        assert_eq!(m.priority(), Priority::Net);
        drop(m);
        // Metadata is reset on reuse.
        let m = pool.alloc(Priority::Low, 0).unwrap();
        assert!(m.link_security());
        assert_eq!(m.sub_type(), SubType::None);
    }

    #[test]
    fn priority_ordering_and_fifo() {
        let pool = MessagePool::<8, 16>::new();
        let mut q = pool.new_queue();
        let mk = |p: Priority, tag: u8| {
            let mut m = pool.alloc(p, 0).unwrap();
            m.append(&[tag]).unwrap();
            m
        };
        q.enqueue(mk(Priority::Low, 1)).unwrap();
        q.enqueue(mk(Priority::Normal, 2)).unwrap();
        q.enqueue(mk(Priority::Normal, 3)).unwrap();
        q.enqueue(mk(Priority::Net, 4)).unwrap();
        q.enqueue(mk(Priority::High, 5)).unwrap();
        q.enqueue(mk(Priority::Net, 6)).unwrap();
        assert_eq!(q.len(), 6);
        assert_eq!(q.len_at(Priority::Normal), 2);
        assert_eq!(q.peek_priority(), Some(Priority::Net));
        let mut order = [0u8; 6];
        for o in order.iter_mut() {
            *o = q.dequeue().unwrap().data()[0];
        }
        assert_eq!(order, [4, 6, 5, 2, 3, 1]);
        assert!(q.is_empty());
        assert!(q.dequeue().is_none());
        assert_eq!(pool.free_count(), 8);
    }

    #[test]
    fn dequeue_priority_and_reenqueue() {
        let pool = Pool::new();
        let mut q = pool.new_queue();
        q.enqueue(pool.alloc(Priority::Low, 0).unwrap()).unwrap();
        q.enqueue(pool.alloc(Priority::High, 0).unwrap()).unwrap();
        assert!(q.dequeue_priority(Priority::Normal).is_none());
        let low = q.dequeue_priority(Priority::Low).unwrap();
        assert_eq!(q.len(), 1);
        // Slot stays allocated while held, then can be re-queued.
        assert_eq!(pool.free_count(), 1);
        q.enqueue(low).unwrap();
        assert_eq!(q.len(), 2);
        assert_eq!(q.dequeue().unwrap().priority(), Priority::High);
    }

    #[test]
    fn queue_drop_frees_messages() {
        let pool = Pool::new();
        {
            let mut q = pool.new_queue();
            q.enqueue(pool.alloc(Priority::Low, 0).unwrap()).unwrap();
            q.enqueue(pool.alloc(Priority::Net, 0).unwrap()).unwrap();
            assert_eq!(pool.free_count(), 1);
        }
        assert_eq!(pool.free_count(), 3);
    }

    #[test]
    fn enqueue_wrong_pool_rejected() {
        let p1 = Pool::new();
        let p2 = Pool::new();
        let mut q = p1.new_queue();
        let m = p2.alloc(Priority::Normal, 0).unwrap();
        assert_eq!(q.enqueue(m).unwrap_err(), Error::InvalidArgs);
        assert_eq!(p2.free_count(), 3);
        assert!(q.is_empty());
    }
}
