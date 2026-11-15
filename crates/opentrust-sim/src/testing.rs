//! Async test harness (feature `testing`): a small in-memory medium, a
//! lock-step virtual-time driver for the [`OpenTrust::run`] futures of several
//! nodes and a virtual `embassy-time` driver.
//!
//! - [`Air`] / [`AirRadio`]: all nodes hear each other (full mesh, no loss,
//!   no air time); pairs can be [blocked](Air::block). Unicast frames with the
//!   AR bit are acknowledged by the receiving radio if it matches the frame.
//! - [`TestAlarm`]: an alarm on a [`MockClock`] that publishes the deadline it
//!   waits for, so the driver knows how far to jump.
//! - [`drive`]: polls the node tasks and a test body until the body
//!   completes; when nothing is runnable, virtual time jumps to the earliest
//!   pending alarm (all clocks together), including `embassy-time` timers.
//! - The `embassy-time` driver of the test binary is virtual: `Instant::now()`
//!   follows the clocks given to [`drive`]. There can be only one time driver
//!   per binary, so a test binary that links this feature must not enable
//!   `embassy-time/std`. With no `drive` running the time stands still.
//!
//! Dropping the `run` futures (returning from `drive`) is safe at every
//! await point, like on a real target.

use core::cell::{Cell, RefCell};
use core::future::{Future, poll_fn};
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use core::task::{Context, Poll, Waker};
use std::collections::VecDeque;
use std::sync::Arc;
use std::task::Wake;

use embassy_sync::blocking_mutex::raw::NoopRawMutex;
use embassy_time_queue_utils::Queue;
use opentrust_core::crypto::soft::SoftCrypto;
use opentrust_core::time::{Duration, Instant};
use opentrust_embassy::{OpenTrust, Resources};
use opentrust_instance::{Config, Instance};
use opentrust_mac::frame::{Address, Frame, FrameBuilder};
use opentrust_mac::mac::{ext_to_u64, fcs};
use opentrust_platform::radio::{PsduRxInfo, PsduTxInfo, RadioCaps, RadioErrorKind};
use opentrust_platform::time::{MockAlarm, MockClock};
use opentrust_platform::{Alarm, Clock, Radio};

use crate::{SimInstance, SimRng, SimSettings, ext_address};

/// The resources of a test node (single executor, mock clock, RAM settings).
pub type Res<'c> = Resources<NoopRawMutex, &'c MockClock, SimSettings, SoftCrypto, SimRng>;
/// The handle of a test node.
pub type Ot<'a, 'c> = OpenTrust<'a, NoopRawMutex, &'c MockClock, SimSettings, SoftCrypto, SimRng>;

/// The time the clocks of [`clock`] start at.
pub fn start_time() -> Instant {
    Instant::from_secs(1000)
}

/// A router-capable instance for node `n` (seeded RNG, empty settings).
pub fn instance(n: u8) -> SimInstance {
    instance_with(n, Config::router(ext_address(n), crate::SimRadio::caps()))
}

/// An instance for node `n` with `cfg`.
pub fn instance_with(n: u8, cfg: Config) -> SimInstance {
    Instance::new(
        cfg,
        SimSettings::new(),
        SoftCrypto,
        SimRng::new(u64::from(n) * 77),
    )
}

/// A clock set to [`start_time`].
pub fn clock() -> MockClock {
    let c = MockClock::new();
    c.set(start_time());
    c
}

// ---------------------------------------------------------------- medium

struct AirNode {
    sleeping: bool,
    channel: u8,
    config: opentrust_platform::radio::Config,
    src_match: opentrust_platform::radio::SrcMatchConfig,
    rx: VecDeque<(Vec<u8>, PsduRxInfo)>,
    waker: Option<Waker>,
    in_tx: bool,
}

/// All nodes hear each other (full mesh, no loss, no air time).
pub struct Air {
    nodes: Vec<AirNode>,
    blocked: Vec<(usize, usize)>,
}

impl core::fmt::Debug for Air {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Air")
            .field("nodes", &self.nodes.len())
            .field("blocked", &self.blocked)
            .finish()
    }
}

impl Air {
    /// A medium with `n` nodes.
    pub fn new(n: usize) -> RefCell<Self> {
        RefCell::new(Self {
            blocked: Vec::new(),
            nodes: (0..n)
                .map(|_| AirNode {
                    sleeping: true,
                    channel: 0,
                    config: opentrust_platform::radio::Config::new(),
                    src_match: opentrust_platform::radio::SrcMatchConfig::new(),
                    rx: VecDeque::new(),
                    waker: None,
                    in_tx: false,
                })
                .collect(),
        })
    }

    /// Nodes `a` and `b` do not hear each other.
    pub fn block(&mut self, a: usize, b: usize) {
        self.blocked.push((a, b));
    }

    /// Whether node `id` has a transmission in flight.
    pub fn in_tx(&self, id: usize) -> bool {
        self.nodes[id].in_tx
    }
}

/// The radio of node `id` on an [`Air`].
#[derive(Debug)]
pub struct AirRadio<'a> {
    /// The medium.
    pub air: &'a RefCell<Air>,
    /// The node index on the medium.
    pub id: usize,
}

struct TxGuard<'a>(&'a RefCell<Air>, usize);

impl Drop for TxGuard<'_> {
    fn drop(&mut self) {
        self.0.borrow_mut().nodes[self.1].in_tx = false;
    }
}

async fn yield_now() {
    let mut yielded = false;
    poll_fn(|cx| {
        if yielded {
            Poll::Ready(())
        } else {
            yielded = true;
            cx.waker().wake_by_ref();
            Poll::Pending
        }
    })
    .await;
}

/// Yield to the other tasks once.
pub async fn yield_once() {
    yield_now().await;
}

impl Radio for AirRadio<'_> {
    type Error = RadioErrorKind;

    async fn init(&mut self) -> Result<RadioCaps, Self::Error> {
        Ok(crate::SimRadio::caps())
    }

    async fn set_config(
        &mut self,
        config: &opentrust_platform::radio::Config,
    ) -> Result<(), Self::Error> {
        self.air.borrow_mut().nodes[self.id].config = config.clone();
        Ok(())
    }

    async fn set_src_match_config(
        &mut self,
        c: &opentrust_platform::radio::SrcMatchConfig,
    ) -> Result<(), Self::Error> {
        self.air.borrow_mut().nodes[self.id].src_match = c.clone();
        Ok(())
    }

    async fn set_receive(&mut self, channel: u8) -> Result<(), Self::Error> {
        let mut a = self.air.borrow_mut();
        let n = &mut a.nodes[self.id];
        n.sleeping = false;
        n.channel = channel;
        Ok(())
    }

    async fn set_receive_at(&mut self, channel: u8, _: u64, _: u32) -> Result<(), Self::Error> {
        self.set_receive(channel).await
    }

    async fn set_sleep(&mut self) -> Result<(), Self::Error> {
        self.air.borrow_mut().nodes[self.id].sleeping = true;
        Ok(())
    }

    async fn energy_scan(&mut self, _: u8, _: u16) -> Result<i8, Self::Error> {
        yield_now().await;
        Ok(-100)
    }

    async fn transmit(
        &mut self,
        psdu: &mut [u8],
        _info: &mut PsduTxInfo,
        channel: u8,
        _power: i8,
        _cca: Option<i8>,
        ack_buf: Option<&mut [u8]>,
    ) -> Result<Option<PsduRxInfo>, Self::Error> {
        self.air.borrow_mut().nodes[self.id].in_tx = true;
        let _g = TxGuard(self.air, self.id);
        // The frame is on the air only after this point: dropping the future
        // before aborts the transmission.
        yield_now().await;
        let frame = Frame::parse_with_fcs(psdu).map_err(|_| RadioErrorKind::TxInvalid)?;
        let dst = frame.dst_address();
        let dst_pan = frame.pan_id();
        let ack_request = frame.frame_control().ack_request();
        let unicast = !dst.is_none() && !dst.is_broadcast();
        let is_poll = frame.is_data_request();
        let src = frame.src_address();
        let mut air = self.air.borrow_mut();
        let mut ack: Option<Vec<u8>> = None;
        for j in 0..air.nodes.len() {
            if j == self.id
                || air.blocked.contains(&(self.id, j))
                || air.blocked.contains(&(j, self.id))
                || air.nodes[j].sleeping
                || air.nodes[j].channel != channel
            {
                continue;
            }
            let mut will_ack = false;
            let mut fp = false;
            if ack_request && unicast {
                let cfg = &air.nodes[j].config;
                let pan_ok =
                    dst_pan.is_none_or(|p| cfg.pan_id.is_none_or(|c| c == p.0 || p.0 == 0xffff));
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
                    fp = air.nodes[j].src_match.ack_frame_pending(s, e);
                }
            }
            let info = PsduRxInfo {
                len: psdu.len(),
                channel,
                rssi: Some(-60),
                lqi: Some(150),
                timestamp_us: None,
                ack_security: None,
                acked_with_frame_pending: will_ack.then_some(fp),
            };
            air.nodes[j].rx.push_back((psdu.to_vec(), info));
            if let Some(w) = air.nodes[j].waker.take() {
                w.wake();
            }
            if will_ack && ack.is_none() {
                let mut buf = [0u8; 16];
                let n = FrameBuilder::imm_ack_for(&mut buf, &frame, fp).expect("ack");
                let mut a = buf[..n].to_vec();
                a.extend_from_slice(&fcs(&buf[..n]));
                ack = Some(a);
            }
        }
        if !(ack_request && unicast) {
            return Ok(None);
        }
        match (ack, ack_buf) {
            (Some(a), Some(buf)) => {
                buf[..a.len()].copy_from_slice(&a);
                Ok(Some(PsduRxInfo {
                    len: a.len(),
                    channel,
                    rssi: Some(-60),
                    lqi: Some(150),
                    timestamp_us: None,
                    ack_security: None,
                    acked_with_frame_pending: None,
                }))
            }
            (Some(_), None) => Ok(None),
            (None, _) => Err(RadioErrorKind::RxAckTimeout),
        }
    }

    async fn receive(&mut self, psdu_buf: &mut [u8]) -> Result<PsduRxInfo, Self::Error> {
        poll_fn(|cx| {
            let mut a = self.air.borrow_mut();
            let n = &mut a.nodes[self.id];
            if let Some((p, mut info)) = n.rx.pop_front() {
                psdu_buf[..p.len()].copy_from_slice(&p);
                info.len = p.len();
                Poll::Ready(Ok(info))
            } else {
                n.waker = Some(cx.waker().clone());
                Poll::Pending
            }
        })
        .await
    }
}

// ---------------------------------------------------------------- alarm

/// An alarm on a [`MockClock`] that publishes the deadline it waits for.
#[derive(Debug)]
pub struct TestAlarm<'a> {
    inner: MockAlarm<'a>,
    pending: &'a Cell<Option<Instant>>,
}

impl<'a> TestAlarm<'a> {
    /// An alarm on `clock` publishing its deadline in `pending`.
    pub fn new(clock: &'a MockClock, pending: &'a Cell<Option<Instant>>) -> Self {
        Self {
            inner: clock.alarm(),
            pending,
        }
    }
}

struct Clear<'a>(&'a Cell<Option<Instant>>);

impl Drop for Clear<'_> {
    fn drop(&mut self) {
        self.0.set(None);
    }
}

impl Alarm for TestAlarm<'_> {
    async fn wait_until(&mut self, at: Instant) {
        if self.inner.now() >= at {
            return;
        }
        self.pending.set(Some(at));
        let _g = Clear(self.pending);
        self.inner.wait_until(at).await;
    }
}

// ---------------------------------------------------------------- embassy-time

/// The virtual `embassy-time` driver: `now` is set by [`drive`]; timers are
/// kept in a generic queue and fired when the driver advances time.
struct VirtualTime {
    now: AtomicU64,
    queue: critical_section::Mutex<RefCell<Queue>>,
}

embassy_time_driver::time_driver_impl!(static VIRTUAL_TIME: VirtualTime = VirtualTime {
    now: AtomicU64::new(0),
    queue: critical_section::Mutex::new(RefCell::new(Queue::new())),
});

impl embassy_time_driver::Driver for VirtualTime {
    fn now(&self) -> u64 {
        self.now.load(Ordering::SeqCst)
    }

    fn schedule_wake(&self, at: u64, waker: &Waker) {
        critical_section::with(|cs| {
            self.queue.borrow_ref_mut(cs).schedule_wake(at, waker);
        });
    }
}

impl VirtualTime {
    /// Set the time (ticks are microseconds), wake the expired timers and
    /// return the next expiration.
    fn set(&self, now: Instant) -> Option<Instant> {
        self.now.store(now.as_micros(), Ordering::SeqCst);
        let next = critical_section::with(|cs| {
            self.queue
                .borrow_ref_mut(cs)
                .next_expiration(now.as_micros())
        });
        (next != u64::MAX).then(|| Instant::from_micros(next))
    }
}

/// Set the `embassy-time` clock of the binary to `now` (ticks are
/// microseconds, like [`Instant`]) and fire the timers due by then. [`drive`]
/// does this on every jump.
pub fn set_embassy_time(now: Instant) -> Option<Instant> {
    VIRTUAL_TIME.set(now)
}

// ---------------------------------------------------------------- driver

struct Flag(AtomicBool);

impl Wake for Flag {
    fn wake(self: Arc<Self>) {
        self.0.store(true, Ordering::SeqCst);
    }
    fn wake_by_ref(self: &Arc<Self>) {
        self.0.store(true, Ordering::SeqCst);
    }
}

/// A boxed task of the driver.
pub type Task<'f> = Pin<Box<dyn Future<Output = ()> + 'f>>;

/// A node's `run` future as a task.
pub fn run_task<'f>(
    ot: Ot<'f, 'f>,
    air: &'f RefCell<Air>,
    id: usize,
    clock: &'f MockClock,
    pending: &'f Cell<Option<Instant>>,
) -> Task<'f> {
    Box::pin(async move {
        ot.run(AirRadio { air, id }, TestAlarm::new(clock, pending))
            .await;
    })
}

/// Poll the node tasks and `body` until `body` completes. When nothing is
/// runnable, virtual time jumps to the earliest pending alarm or
/// `embassy-time` timer (all clocks together). The node tasks are dropped on
/// return. Panics if nothing is runnable and no alarm is pending (deadlock)
/// or when `limit` of virtual time has passed.
pub fn drive<T>(
    clocks: &[&MockClock],
    pendings: &[&Cell<Option<Instant>>],
    mut tasks: Vec<Task<'_>>,
    body: impl Future<Output = T>,
    limit: Duration,
) -> T {
    let mut body = Box::pin(body);
    let flag = Arc::new(Flag(AtomicBool::new(true)));
    let waker = Waker::from(flag.clone());
    let mut cx = Context::from_waker(&waker);
    let end = clocks[0].now() + limit;
    let _ = VIRTUAL_TIME.set(clocks[0].now());
    loop {
        flag.0.store(false, Ordering::SeqCst);
        if let Poll::Ready(v) = body.as_mut().poll(&mut cx) {
            return v;
        }
        for t in &mut tasks {
            let _ = t.as_mut().poll(&mut cx);
        }
        let now = clocks[0].now();
        // Timers scheduled for a time that has already passed fire now.
        let next_timer = VIRTUAL_TIME.set(now);
        if flag.0.load(Ordering::SeqCst) {
            continue;
        }
        let next_alarm = pendings.iter().filter_map(|p| p.get()).min();
        let t = match (next_alarm, next_timer) {
            (Some(a), Some(b)) => a.min(b),
            (a, b) => a
                .or(b)
                .expect("deadlock: nothing runnable and no alarm pending"),
        };
        assert!(t < end, "virtual time limit exceeded");
        let t = t.max(now);
        for c in clocks {
            c.set(t);
        }
        let _ = VIRTUAL_TIME.set(t);
    }
}

/// Wait until `cond` holds for the instance of `ot` (checked after every
/// state change of the node).
pub async fn wait_until(ot: Ot<'_, '_>, mut cond: impl FnMut(&mut SimInstance) -> bool) {
    loop {
        let g = ot.generation();
        if ot.with(|i, _| cond(i)) {
            return;
        }
        ot.wait_changed_after(g).await;
    }
}
