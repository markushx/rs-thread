//! Fixed-capacity, allocation-free timer queue.
//!
//! The queue is sans-IO: it stores deadlines and, given the current
//! [`Instant`], hands back expired keys. The caller sleeps until
//! [`TimerQueue::next_deadline`] and then drains with
//! [`TimerQueue::poll_expired`].

use crate::error::{Error, Result};
use crate::time::Instant;

/// A set of up to `N` one-shot timers identified by caller-defined keys.
///
/// Each key has at most one pending deadline; starting a running key replaces
/// its deadline.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct TimerQueue<K, const N: usize> {
    slots: [Option<(K, Instant)>; N],
}

impl<K: Copy + Eq, const N: usize> Default for TimerQueue<K, N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<K: Copy + Eq, const N: usize> TimerQueue<K, N> {
    /// Creates an empty queue.
    pub const fn new() -> Self {
        TimerQueue { slots: [None; N] }
    }

    /// Returns the number of running timers.
    pub fn len(&self) -> usize {
        self.slots.iter().filter(|s| s.is_some()).count()
    }

    /// Returns true if no timer is running.
    pub fn is_empty(&self) -> bool {
        self.slots.iter().all(|s| s.is_none())
    }

    /// Returns the maximum number of timers.
    pub const fn capacity(&self) -> usize {
        N
    }

    /// Starts the timer `key` to expire at `deadline`, replacing any existing
    /// deadline for the same key.
    ///
    /// Returns [`Error::NoBufs`] if `key` is not running and the queue is full.
    pub fn start(&mut self, key: K, deadline: Instant) -> Result<()> {
        if let Some(slot) = self.slots.iter_mut().flatten().find(|(k, _)| *k == key) {
            slot.1 = deadline;
            return Ok(());
        }
        match self.slots.iter_mut().find(|s| s.is_none()) {
            Some(free) => {
                *free = Some((key, deadline));
                Ok(())
            }
            None => Err(Error::NoBufs),
        }
    }

    /// Stops the timer `key`. Returns true if it was running.
    pub fn stop(&mut self, key: K) -> bool {
        for s in self.slots.iter_mut() {
            if matches!(s, Some((k, _)) if *k == key) {
                *s = None;
                return true;
            }
        }
        false
    }

    /// Returns true if the timer `key` is running.
    pub fn is_running(&self, key: K) -> bool {
        self.deadline(key).is_some()
    }

    /// Returns the deadline of `key`, if running.
    pub fn deadline(&self, key: K) -> Option<Instant> {
        self.slots
            .iter()
            .flatten()
            .find(|(k, _)| *k == key)
            .map(|(_, d)| *d)
    }

    /// Returns the earliest deadline of any running timer.
    pub fn next_deadline(&self) -> Option<Instant> {
        self.slots.iter().flatten().map(|(_, d)| *d).min()
    }

    /// Removes and returns the earliest timer whose deadline is `<= now`.
    ///
    /// Call repeatedly until it returns `None` to drain all expired timers.
    /// Ties are broken by slot order.
    pub fn poll_expired(&mut self, now: Instant) -> Option<K> {
        let mut best: Option<(usize, Instant)> = None;
        for (i, s) in self.slots.iter().enumerate() {
            if let Some((_, d)) = s
                && *d <= now
                && best.is_none_or(|(_, bd)| *d < bd)
            {
                best = Some((i, *d));
            }
        }
        let (i, _) = best?;
        self.slots[i].take().map(|(k, _)| k)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum K {
        A,
        B,
        C,
        D,
    }

    fn t(ms: u64) -> Instant {
        Instant::from_millis(ms)
    }

    #[test]
    fn empty() {
        let mut q = TimerQueue::<K, 3>::new();
        assert!(q.is_empty());
        assert_eq!(q.capacity(), 3);
        assert_eq!(q.next_deadline(), None);
        assert_eq!(q.poll_expired(t(1000)), None);
        assert!(!q.stop(K::A));
    }

    #[test]
    fn earliest_first() {
        let mut q = TimerQueue::<K, 4>::new();
        q.start(K::A, t(30)).unwrap();
        q.start(K::B, t(10)).unwrap();
        q.start(K::C, t(20)).unwrap();
        assert_eq!(q.len(), 3);
        assert_eq!(q.next_deadline(), Some(t(10)));
        assert_eq!(q.poll_expired(t(5)), None);
        assert_eq!(q.poll_expired(t(100)), Some(K::B));
        assert_eq!(q.poll_expired(t(100)), Some(K::C));
        assert_eq!(q.poll_expired(t(100)), Some(K::A));
        assert_eq!(q.poll_expired(t(100)), None);
        assert!(q.is_empty());
    }

    #[test]
    fn expiry_at_exact_deadline() {
        let mut q = TimerQueue::<K, 2>::new();
        q.start(K::A, t(10)).unwrap();
        assert_eq!(q.poll_expired(Instant::from_micros(9_999)), None);
        assert_eq!(q.poll_expired(t(10)), Some(K::A));
    }

    #[test]
    fn restart_replaces_deadline() {
        let mut q = TimerQueue::<K, 2>::new();
        q.start(K::A, t(10)).unwrap();
        q.start(K::A, t(50)).unwrap();
        assert_eq!(q.len(), 1);
        assert_eq!(q.deadline(K::A), Some(t(50)));
        assert_eq!(q.poll_expired(t(20)), None);
        assert_eq!(q.poll_expired(t(50)), Some(K::A));
    }

    #[test]
    fn full_queue() {
        let mut q = TimerQueue::<K, 2>::new();
        q.start(K::A, t(1)).unwrap();
        q.start(K::B, t(2)).unwrap();
        assert_eq!(q.start(K::C, t(3)), Err(Error::NoBufs));
        // Restarting an existing key still works when full.
        q.start(K::A, t(9)).unwrap();
        // Freeing a slot lets a new key in.
        assert!(q.stop(K::B));
        q.start(K::C, t(3)).unwrap();
        assert_eq!(q.start(K::D, t(3)), Err(Error::NoBufs));
    }

    #[test]
    fn stop_and_query() {
        let mut q = TimerQueue::<K, 2>::new();
        q.start(K::A, t(1)).unwrap();
        assert!(q.is_running(K::A));
        assert!(!q.is_running(K::B));
        assert!(q.stop(K::A));
        assert!(!q.is_running(K::A));
        assert_eq!(q.deadline(K::A), None);
        assert_eq!(q.poll_expired(t(100)), None);
    }

    #[test]
    fn zero_capacity() {
        let mut q = TimerQueue::<K, 0>::new();
        assert_eq!(q.start(K::A, t(1)), Err(Error::NoBufs));
    }
}
