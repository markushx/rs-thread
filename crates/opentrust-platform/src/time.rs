//! Time sources for the async facade: a monotonic [`Clock`] and an [`Alarm`].
//!
//! # Design decision
//!
//! esp-rs/openthread takes time from `embassy-time` (its `run_alarm` task
//! drives `otPlatAlarmMilli*` with `embassy_time::Timer`), which ties it to an
//! `embassy-time` driver. OpenTrust instead defines two minimal traits here:
//!
//! - the sans-IO core (`opentrust-core`, `-mac`, ...) never reads a clock; it
//!   takes `now: Instant` as an argument and returns the next deadline;
//! - the async facade (`opentrust-embassy`) needs only "what time is
//!   it" ([`Clock::now`]) and "wake me at time T" ([`Alarm::wait_until`]),
//!   which is a few lines to implement over any executor's timer (embassy-time,
//!   a hardware compare register, tokio, a simulator's virtual clock).
//!
//! This keeps `opentrust-platform` free of an `embassy-time` dependency (and of
//! its driver/`critical-section`/tick-rate feature selection) and the facade
//! executor-agnostic. An `embassy-time` adapter (`EmbassyClock`/`EmbassyAlarm`
//! over `embassy_time::Instant::now()` / `Timer::at`) belongs in
//! `opentrust-embassy`, behind the application's choice of tick rate;
//! rs-matter integration is unaffected because that crate already depends on
//! `embassy-time`. The time base is [`opentrust_core::time::Instant`]
//! (microseconds, monotonic), as required for CSL.
//!
//! Mapping to OpenThread: [`Clock::now`] is `otPlatAlarmMicroGetNow`
//! (milliseconds are `now().as_millis()`); [`Alarm::wait_until`] covers both
//! `otPlatAlarmMilli/MicroStartAt` (the caller owns the deadline and re-arms by
//! dropping the future and calling again). A radio with its own clock
//! ([`RadioCaps::clock`](crate::radio::RadioCaps::clock)) can implement
//! [`Clock`] on top of it so CSL arithmetic is in a single time base.

#[cfg(any(feature = "testing", test))]
use core::cell::Cell;
#[cfg(any(feature = "testing", test))]
use core::task::Waker;

use opentrust_core::time::{Duration, Instant};

/// A monotonic clock with microsecond resolution.
pub trait Clock {
    /// The current time. Must never go backwards.
    fn now(&self) -> Instant;
}

/// An asynchronous one-shot alarm.
///
/// Dropping the returned future cancels the wait (cancellation-safe), so
/// re-arming is "drop and call `wait_until` again".
#[allow(async_fn_in_trait)] // single-task use, no `Send` bound needed
pub trait Alarm {
    /// Completes once the clock has reached `at` (immediately if it already has).
    async fn wait_until(&mut self, at: Instant);

    /// Completes after `d` has elapsed, measured from the call of this method.
    ///
    /// Not an `async fn`: the deadline is computed when called, before the
    /// future is first polled.
    fn wait_for(
        &mut self,
        clock: &impl Clock,
        d: Duration,
    ) -> impl core::future::Future<Output = ()> {
        let at = clock.now().saturating_add(d);
        self.wait_until(at)
    }
}

impl<T: Clock + ?Sized> Clock for &T {
    fn now(&self) -> Instant {
        (**self).now()
    }
}

impl<T: Alarm + ?Sized> Alarm for &mut T {
    async fn wait_until(&mut self, at: Instant) {
        (**self).wait_until(at).await
    }
}

/// A manually advanced clock for tests and simulation.
///
/// Shared by reference: it implements [`Clock`], and [`alarm`](Self::alarm)
/// hands out an [`Alarm`] whose `wait_until` completes once
/// [`advance`](Self::advance) / [`set`](Self::set) moves time to the deadline.
/// Single-threaded (`Cell`-based); it holds one waker, so it supports one
/// pending `wait_until` at a time.
#[cfg(any(feature = "testing", test))]
#[derive(Default)]
pub struct MockClock {
    now: Cell<Instant>,
    waker: Cell<Option<Waker>>,
}

#[cfg(any(feature = "testing", test))]
impl core::fmt::Debug for MockClock {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MockClock")
            .field("now", &self.now.get())
            .finish_non_exhaustive()
    }
}

#[cfg(any(feature = "testing", test))]
impl MockClock {
    /// A clock at [`Instant::ZERO`].
    pub const fn new() -> Self {
        Self {
            now: Cell::new(Instant::ZERO),
            waker: Cell::new(None),
        }
    }

    /// Jump to `t` (must not be before the current time; ignored otherwise,
    /// to keep the clock monotonic) and wake the pending alarm, if any.
    pub fn set(&self, t: Instant) {
        if t > self.now.get() {
            self.now.set(t);
        }
        if let Some(w) = self.waker.take() {
            w.wake();
        }
    }

    /// Advance by `d` (saturating) and wake the pending alarm, if any.
    pub fn advance(&self, d: Duration) {
        self.set(self.now.get().saturating_add(d));
    }
}

#[cfg(any(feature = "testing", test))]
impl Clock for MockClock {
    fn now(&self) -> Instant {
        self.now.get()
    }
}

#[cfg(any(feature = "testing", test))]
impl MockClock {
    /// An [`Alarm`] (and [`Clock`]) handle on this clock. The handle borrows
    /// the clock shared, so the test can keep advancing time while an alarm
    /// future is pending.
    pub const fn alarm(&self) -> MockAlarm<'_> {
        MockAlarm(self)
    }
}

/// An [`Alarm`] on a [`MockClock`]; see [`MockClock::alarm`].
#[cfg(any(feature = "testing", test))]
#[derive(Debug, Clone, Copy)]
pub struct MockAlarm<'a>(&'a MockClock);

#[cfg(any(feature = "testing", test))]
impl Clock for MockAlarm<'_> {
    fn now(&self) -> Instant {
        self.0.now()
    }
}

#[cfg(any(feature = "testing", test))]
impl Alarm for MockAlarm<'_> {
    async fn wait_until(&mut self, at: Instant) {
        let clock = self.0;
        core::future::poll_fn(|cx| {
            if clock.now.get() >= at {
                core::task::Poll::Ready(())
            } else {
                clock.waker.set(Some(cx.waker().clone()));
                core::task::Poll::Pending
            }
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use embassy_futures::{block_on, poll_once};

    #[test]
    fn clock_is_monotonic() {
        let c = MockClock::new();
        assert_eq!(c.now(), Instant::ZERO);
        c.advance(Duration::from_millis(5));
        assert_eq!(c.now(), Instant::from_micros(5_000));
        c.set(Instant::from_micros(1));
        assert_eq!(c.now(), Instant::from_micros(5_000));
        c.set(Instant::from_secs(1));
        assert_eq!(c.now(), Instant::from_secs(1));
    }

    #[test]
    fn alarm_fires_when_time_reached() {
        let clock = MockClock::new();
        let mut alarm = clock.alarm();
        // A deadline that has passed completes immediately.
        block_on(alarm.wait_until(Instant::ZERO));

        let mut fut = core::pin::pin!(alarm.wait_until(Instant::from_millis(10)));
        assert!(poll_once(fut.as_mut()).is_pending());
        clock.advance(Duration::from_millis(9));
        assert!(poll_once(fut.as_mut()).is_pending());
        clock.advance(Duration::from_millis(1));
        assert!(poll_once(fut.as_mut()).is_ready());
    }

    #[test]
    fn alarm_is_cancellable_and_rearmable() {
        let clock = MockClock::new();
        let mut alarm = clock.alarm();
        {
            let mut fut = core::pin::pin!(alarm.wait_until(Instant::from_secs(1)));
            assert!(poll_once(fut.as_mut()).is_pending());
        } // dropped
        let mut fut = core::pin::pin!(alarm.wait_until(Instant::from_millis(1)));
        assert!(poll_once(fut.as_mut()).is_pending());
        clock.advance(Duration::from_millis(1));
        assert!(poll_once(fut.as_mut()).is_ready());
    }

    #[test]
    fn wait_for_is_relative_to_call_time() {
        let clock = MockClock::new();
        clock.advance(Duration::from_secs(5));
        let mut alarm = clock.alarm();
        let mut fut = core::pin::pin!(alarm.wait_for(&clock, Duration::from_millis(2)));
        assert!(poll_once(fut.as_mut()).is_pending());
        clock.advance(Duration::from_millis(2));
        assert!(poll_once(fut.as_mut()).is_ready());
    }
}
