//! Shared state of one node: the instance, the notification state and the
//! cheap `Copy` handle.

use core::cell::RefCell;
use core::future::poll_fn;
use core::task::Poll;

use embassy_sync::blocking_mutex::Mutex;
use embassy_sync::blocking_mutex::raw::RawMutex;
use embassy_sync::signal::Signal;
use embassy_sync::waitqueue::{MultiWakerRegistration, WakerRegistration};
use heapless::Deque;
use opentrust_core::time::Instant;
use opentrust_instance::{
    Event, Instance, InstanceCrypto, Rloc16, Role, UDP_SOCKETS, UdpSocket as RawUdpSocket,
};
use opentrust_platform::{Clock, SettingsStore};
use rand_core::{CryptoRng, Rng};

/// Capacity of the application event queue ([`OpenTrust::next_event`]).
pub const EVENT_QUEUE_LEN: usize = 16;

/// Number of tasks that can wait on one notification at the same time
/// without a spurious wake-up of the others: if more register, every
/// registered waiter is woken (it re-checks its condition and registers
/// again), so waiting stays correct for any number of tasks.
pub const WAITERS: usize = 8;

pub(crate) struct UdpSlot {
    pub(crate) sock: Option<RawUdpSocket>,
    pub(crate) waker: WakerRegistration,
}

pub(crate) struct State<S, C: InstanceCrypto, R> {
    pub(crate) inst: Instance<S, C, R>,
    generation: u32,
    changed: MultiWakerRegistration<WAITERS>,
    events: Deque<Event, EVENT_QUEUE_LEN>,
    event_waiters: MultiWakerRegistration<WAITERS>,
    pub(crate) tx_waiters: MultiWakerRegistration<WAITERS>,
    pub(crate) udp: [UdpSlot; UDP_SOCKETS],
    /// Waiters of the async request wrappers ([`crate::requests`]): woken on
    /// every state event and when `req_deadline` passes.
    pub(crate) req_waiters: MultiWakerRegistration<WAITERS>,
    /// The earliest timeout of a pending request (`run` wakes at it).
    pub(crate) req_deadline: Option<Instant>,
    /// The last Joiner result, `None` while joining or before a join.
    pub(crate) joiner_result: Option<Result<(), opentrust_core::Error>>,
    pub(crate) ping_seq: u16,
    /// A transmit / energy scan was started by `run` but its future was
    /// dropped before the result was reported.
    pub(crate) interrupted: bool,
}

impl<S: SettingsStore, C: InstanceCrypto, R: Rng + CryptoRng> State<S, C, R> {
    /// Move the instance events into the notification state and wake the
    /// waiters.
    pub(crate) fn drain(&mut self) {
        let mut changed = false;
        while let Some(ev) = self.inst.poll_event() {
            if let Event::JoinerResult(r) = ev {
                self.joiner_result = Some(r);
            }
            if matches!(ev, Event::UdpReadable(_)) {
                // Handled by the per-socket wakers below (the instance
                // queue may drop events, the sockets' queues do not).
                continue;
            }
            changed = true;
            if self.events.is_full() {
                let _ = self.events.pop_front();
            }
            let _ = self.events.push_back(ev);
        }
        if changed {
            self.generation = self.generation.wrapping_add(1);
            self.changed.wake();
            self.event_waiters.wake();
            self.req_waiters.wake();
        }
        for slot in &mut self.udp {
            if let Some(s) = slot.sock
                && self.inst.udp_has_data(s).unwrap_or(false)
            {
                slot.waker.wake();
            }
        }
    }
}

/// The storage of one Thread node: the [`Instance`], the clock and the
/// notification state. Create it once (in a `static`, `StaticCell` or on the
/// stack), then make an [`OpenTrust`] handle with [`OpenTrust::new`].
///
/// Type parameters: `M` the raw mutex, `K` the [`Clock`], `S` / `C` / `R` as
/// in [`Instance`].
pub struct Resources<M: RawMutex, K, S, C: InstanceCrypto, R> {
    clock: K,
    state: Mutex<M, RefCell<State<S, C, R>>>,
    kick: Signal<M, ()>,
}

impl<M: RawMutex, K, S, C: InstanceCrypto, R> core::fmt::Debug for Resources<M, K, S, C, R> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Resources").finish_non_exhaustive()
    }
}

impl<M: RawMutex, K: Clock, S, C: InstanceCrypto, R> Resources<M, K, S, C, R> {
    /// Wrap an initialized instance. `clock` is the time source for the API
    /// calls (the driver's [`Alarm`](opentrust_platform::Alarm) must run on
    /// the same time base).
    pub fn new(instance: Instance<S, C, R>, clock: K) -> Self {
        Self {
            clock,
            state: Mutex::new(RefCell::new(State {
                inst: instance,
                generation: 0,
                changed: MultiWakerRegistration::new(),
                events: Deque::new(),
                event_waiters: MultiWakerRegistration::new(),
                tx_waiters: MultiWakerRegistration::new(),
                udp: core::array::from_fn(|_| UdpSlot {
                    sock: None,
                    waker: WakerRegistration::new(),
                }),
                req_waiters: MultiWakerRegistration::new(),
                req_deadline: None,
                joiner_result: None,
                ping_seq: 0,
                interrupted: false,
            })),
            kick: Signal::new(),
        }
    }

    /// Take the instance back (e.g. to reuse its settings for a restart).
    pub fn into_instance(self) -> Instance<S, C, R> {
        self.state.into_inner().into_inner().inst
    }

    pub(crate) fn clock(&self) -> &K {
        &self.clock
    }

    pub(crate) fn kick(&self) -> &Signal<M, ()> {
        &self.kick
    }

    pub(crate) fn lock<T>(&self, f: impl FnOnce(&mut State<S, C, R>) -> T) -> T {
        self.state.lock(|c| f(&mut c.borrow_mut()))
    }
}

/// A cheap `Copy` handle on a [`Resources`].
pub struct OpenTrust<'a, M: RawMutex, K, S, C: InstanceCrypto, R> {
    pub(crate) res: &'a Resources<M, K, S, C, R>,
}

impl<M: RawMutex, K, S, C: InstanceCrypto, R> Clone for OpenTrust<'_, M, K, S, C, R> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<M: RawMutex, K, S, C: InstanceCrypto, R> Copy for OpenTrust<'_, M, K, S, C, R> {}

impl<M: RawMutex, K, S, C: InstanceCrypto, R> core::fmt::Debug for OpenTrust<'_, M, K, S, C, R> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("OpenTrust").finish_non_exhaustive()
    }
}

impl<'a, M, K, S, C, R> OpenTrust<'a, M, K, S, C, R>
where
    M: RawMutex,
    K: Clock,
    S: SettingsStore,
    C: InstanceCrypto,
    R: Rng + CryptoRng,
{
    /// A handle on `resources`.
    pub fn new(resources: &'a Resources<M, K, S, C, R>) -> Self {
        Self { res: resources }
    }

    /// The current time of the node's clock.
    pub fn now(&self) -> Instant {
        self.res.clock.now()
    }

    /// Synchronous access to the whole [`Instance`] API, with the current
    /// time. The driver is woken afterwards (so a new deadline or a queued
    /// transmission is picked up) and the instance events are published to
    /// the waiters.
    ///
    /// Keep `f` short: it runs with the node locked (in a critical section
    /// for `CriticalSectionRawMutex`). Calling another method of the handle
    /// from inside `f` panics.
    pub fn with<T>(&self, f: impl FnOnce(&mut Instance<S, C, R>, Instant) -> T) -> T {
        let now = self.res.clock.now();
        let out = self.res.lock(|s| {
            let out = f(&mut s.inst, now);
            s.drain();
            out
        });
        self.res.kick.signal(());
        out
    }

    /// Start Thread (see [`Instance::thread_start`]); enables the IPv6
    /// interface first.
    pub fn thread_start(&self) -> opentrust_core::Result<()> {
        self.with(|i, now| {
            i.ip6_set_enabled(true);
            i.thread_start(now)
        })
    }

    /// Start Thread and become the leader of a new partition at once (see
    /// [`Instance::become_leader`]); enables the IPv6 interface first.
    #[cfg(feature = "ftd")]
    pub fn become_leader(&self) -> opentrust_core::Result<()> {
        self.with(|i, now| {
            i.ip6_set_enabled(true);
            i.become_leader(now)
        })
    }

    /// Stop Thread (see [`Instance::thread_stop`]).
    pub fn thread_stop(&self) {
        self.with(|i, _| i.thread_stop());
    }

    /// Set the Active Dataset (see [`Instance::set_active_dataset`]).
    pub fn set_active_dataset(
        &self,
        dataset: &opentrust_instance::Dataset,
    ) -> opentrust_core::Result<()> {
        self.with(|i, now| i.set_active_dataset(dataset, now))
    }

    /// Subscribe to a multicast address (see
    /// [`Instance::subscribe_multicast`]); already subscribed is not an error.
    pub fn join_multicast(&self, addr: core::net::Ipv6Addr) -> opentrust_core::Result<()> {
        match self.with(|i, _| i.subscribe_multicast(addr)) {
            Err(opentrust_core::Error::Already) => Ok(()),
            r => r,
        }
    }

    /// Leave a multicast address (see [`Instance::unsubscribe_multicast`]).
    pub fn leave_multicast(&self, addr: core::net::Ipv6Addr) -> opentrust_core::Result<()> {
        self.with(|i, _| i.unsubscribe_multicast(addr))
    }

    /// The current Thread role.
    pub fn role(&self) -> Role {
        self.res.lock(|s| s.inst.role())
    }

    /// The current RLOC16.
    pub fn rloc16(&self) -> Rloc16 {
        self.res.lock(|s| s.inst.rloc16())
    }

    /// The notification generation: incremented on every state event. Use
    /// with [`wait_changed_after`](Self::wait_changed_after) for a loop
    /// without a lost wake-up.
    pub fn generation(&self) -> u32 {
        self.res.lock(|s| s.generation)
    }

    /// Wait until the node's state changes (role, RLOC16, partition,
    /// addresses, Network Data, datasets, child / router table, joiner,
    /// clients, ...: any [`Event`] except UDP readiness).
    ///
    /// Any number of tasks can wait at once; all are woken. Changes before
    /// the first poll of the returned future are not reported: check the
    /// state, then wait (or use [`wait_changed_after`](Self::wait_changed_after)
    /// with a generation read before the check).
    pub async fn wait_changed(&self) {
        let g = self.generation();
        self.wait_changed_after(g).await;
    }

    /// Wait until [`generation`](Self::generation) differs from `generation`.
    pub async fn wait_changed_after(&self, generation: u32) {
        poll_fn(|cx| {
            self.res.lock(|s| {
                if s.generation != generation {
                    Poll::Ready(())
                } else {
                    s.changed.register(cx.waker());
                    Poll::Pending
                }
            })
        })
        .await;
    }

    /// The next application [`Event`] (OpenThread: the state-changed, UDP
    /// excluded, ICMP, joiner and client result callbacks).
    ///
    /// The queue holds [`EVENT_QUEUE_LEN`] events. If the application falls
    /// behind, the oldest events are dropped (the instance queue behaves the
    /// same and coalesces its own events). Several tasks may call this; each
    /// event goes to one of them. Use [`wait_changed`](Self::wait_changed)
    /// when only "something changed" matters.
    pub async fn next_event(&self) -> Event {
        poll_fn(|cx| {
            self.res.lock(|s| match s.events.pop_front() {
                Some(e) => Poll::Ready(e),
                None => {
                    s.event_waiters.register(cx.waker());
                    Poll::Pending
                }
            })
        })
        .await
    }
}
