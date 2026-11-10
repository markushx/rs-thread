//! A small async test medium and a lock-step virtual-time driver.
#![allow(dead_code)]

use core::cell::{Cell, RefCell};
use core::future::{Future, poll_fn};
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, Ordering};
use core::task::{Context, Poll, Waker};
use std::collections::VecDeque;
use std::sync::Arc;
use std::task::Wake;

use embassy_sync::blocking_mutex::raw::NoopRawMutex;
use opentrust_core::crypto::soft::SoftCrypto;
use opentrust_core::time::{Duration, Instant};
use opentrust_embassy::{OpenTrust, Resources};
use opentrust_instance::{Config, Instance};
use opentrust_mac::frame::{Address, Frame, FrameBuilder};
use opentrust_mac::mac::{ext_to_u64, fcs};
use opentrust_platform::radio::{PsduRxInfo, PsduTxInfo, RadioCaps, RadioErrorKind};
use opentrust_platform::time::{MockAlarm, MockClock};
use opentrust_platform::{Alarm, Clock, Radio};
use opentrust_sim::{SimInstance, SimRng, SimSettings, ext_address};

pub type Res<'c> = Resources<NoopRawMutex, &'c MockClock, SimSettings, SoftCrypto, SimRng>;
pub type Ot<'a, 'c> = OpenTrust<'a, NoopRawMutex, &'c MockClock, SimSettings, SoftCrypto, SimRng>;

pub fn start_time() -> Instant {
    Instant::from_secs(1000)
}

pub fn instance(n: u8) -> SimInstance {
    let cfg = Config::router(ext_address(n), opentrust_sim::SimRadio::caps());
    Instance::new(
        cfg,
        SimSettings::new(),
        SoftCrypto,
        SimRng::new(u64::from(n) * 77),
    )
}

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
    rx: VecDeque<(Vec<u8>, PsduRxInfo)>,
    waker: Option<Waker>,
    in_tx: bool,
}

/// All nodes hear each other (full mesh, no loss, no air time).
pub struct Air {
    nodes: Vec<AirNode>,
}

impl Air {
    pub fn new(n: usize) -> RefCell<Self> {
        RefCell::new(Self {
            nodes: (0..n)
                .map(|_| AirNode {
                    sleeping: true,
                    channel: 0,
                    config: opentrust_platform::radio::Config::new(),
                    rx: VecDeque::new(),
                    waker: None,
                    in_tx: false,
                })
                .collect(),
        })
    }

    pub fn in_tx(&self, id: usize) -> bool {
        self.nodes[id].in_tx
    }
}

pub struct AirRadio<'a> {
    pub air: &'a RefCell<Air>,
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

pub async fn yield_once() {
    yield_now().await;
}

impl Radio for AirRadio<'_> {
    type Error = RadioErrorKind;

    async fn init(&mut self) -> Result<RadioCaps, Self::Error> {
        Ok(opentrust_sim::SimRadio::caps())
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
        _: &opentrust_platform::radio::SrcMatchConfig,
    ) -> Result<(), Self::Error> {
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
        let mut air = self.air.borrow_mut();
        let mut ack: Option<Vec<u8>> = None;
        for j in 0..air.nodes.len() {
            if j == self.id || air.nodes[j].sleeping || air.nodes[j].channel != channel {
                continue;
            }
            let mut will_ack = false;
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
            }
            let info = PsduRxInfo {
                len: psdu.len(),
                channel,
                rssi: Some(-60),
                lqi: Some(150),
                timestamp_us: None,
                ack_security: None,
                acked_with_frame_pending: will_ack.then_some(false),
            };
            air.nodes[j].rx.push_back((psdu.to_vec(), info));
            if let Some(w) = air.nodes[j].waker.take() {
                w.wake();
            }
            if will_ack && ack.is_none() {
                let mut buf = [0u8; 16];
                let n = FrameBuilder::imm_ack_for(&mut buf, &frame, false).expect("ack");
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
pub struct TestAlarm<'a> {
    inner: MockAlarm<'a>,
    pending: &'a Cell<Option<Instant>>,
}

impl<'a> TestAlarm<'a> {
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
/// runnable, virtual time jumps to the earliest pending alarm (all clocks
/// together). The node tasks are dropped on return.
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
    loop {
        flag.0.store(false, Ordering::SeqCst);
        if let Poll::Ready(v) = body.as_mut().poll(&mut cx) {
            return v;
        }
        for t in &mut tasks {
            let _ = t.as_mut().poll(&mut cx);
        }
        if flag.0.load(Ordering::SeqCst) {
            continue;
        }
        let next = pendings.iter().filter_map(|p| p.get()).min();
        let now = clocks[0].now();
        let t = next.expect("deadlock: nothing runnable and no alarm pending");
        assert!(t < end, "virtual time limit exceeded");
        let t = t.max(now);
        for c in clocks {
            c.set(t);
        }
    }
}
