//! Trickle timer (RFC 6206), sans-IO.
//!
//! Used by Thread for MLE Advertisements and MPL multicast forwarding. The
//! behaviour follows OpenThread's `TrickleTimer`, including its "plain timer"
//! mode in which transmissions are never suppressed.
//!
//! The timer holds no clock: callers pass `now` to every operation and sleep
//! until [`Trickle::next_deadline`].

use rand_core::Rng;

use crate::error::{Error, Result};
use crate::time::{Duration, Instant};

/// Operating mode of a [`Trickle`] timer (cf. OpenThread `kModeTrickle` /
/// `kModePlainTimer`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum TrickleMode {
    /// Normal RFC 6206 behaviour: interval doubling, redundancy suppression
    /// and reset on inconsistency.
    Trickle,
    /// Plain periodic timer: every interval is chosen uniformly in
    /// `[Imin, Imax]`, a transmit event fires at the end of each interval, and
    /// neither suppression nor `inconsistent()` has any effect.
    Plain,
}

/// Parameters of a [`Trickle`] timer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct TrickleConfig {
    imin: Duration,
    imax: Duration,
    k: u16,
    mode: TrickleMode,
}

impl TrickleConfig {
    /// Creates a configuration from absolute `imin` and `imax`.
    ///
    /// `k` is the redundancy constant; `0` means infinite (never suppress).
    /// Returns [`Error::InvalidArgs`] unless `0 < imin <= imax`.
    pub const fn new(imin: Duration, imax: Duration, k: u16, mode: TrickleMode) -> Result<Self> {
        if imin.is_zero() || imin.as_micros() > imax.as_micros() {
            return Err(Error::InvalidArgs);
        }
        Ok(TrickleConfig {
            imin,
            imax,
            k,
            mode,
        })
    }

    /// Creates a configuration with `Imax = Imin * 2^doublings` (RFC 6206
    /// section 4.1).
    ///
    /// Returns [`Error::InvalidArgs`] if `imin` is zero or the result overflows.
    pub fn with_doublings(
        imin: Duration,
        doublings: u8,
        k: u16,
        mode: TrickleMode,
    ) -> Result<Self> {
        let factor = 1u64
            .checked_shl(doublings.into())
            .ok_or(Error::InvalidArgs)?;
        let imax = imin.checked_mul(factor).ok_or(Error::InvalidArgs)?;
        Self::new(imin, imax, k, mode)
    }

    /// Minimum interval size `Imin`.
    pub const fn imin(&self) -> Duration {
        self.imin
    }

    /// Maximum interval size `Imax`.
    pub const fn imax(&self) -> Duration {
        self.imax
    }

    /// Redundancy constant `k` (`0` means infinite).
    pub const fn k(&self) -> u16 {
        self.k
    }

    /// Operating mode.
    pub const fn mode(&self) -> TrickleMode {
        self.mode
    }
}

/// Event produced by [`Trickle::poll`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[non_exhaustive]
pub enum TrickleEvent {
    /// The caller should transmit now.
    Transmit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
enum Phase {
    /// Waiting for the transmission point `t` within the interval.
    BeforeT,
    /// `t` has passed; waiting for the interval to end.
    AfterT,
}

#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
struct Running {
    interval: Duration,
    interval_start: Instant,
    /// Offset of `t` from `interval_start`.
    t: Duration,
    counter: u16,
    phase: Phase,
}

/// A Trickle timer instance.
#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Trickle {
    config: TrickleConfig,
    state: Option<Running>,
}

/// Uniform value in `[lo, hi)` without modulo bias (rejection sampling).
/// Returns `lo` if the range is empty.
fn uniform<R: Rng + ?Sized>(rng: &mut R, lo: u64, hi: u64) -> u64 {
    if hi <= lo {
        return lo;
    }
    let span = hi - lo;
    // Largest multiple of `span` that fits in the u64 domain.
    let zone = u64::MAX - (u64::MAX - span + 1) % span;
    loop {
        let v = rng.next_u64();
        if v <= zone {
            return lo + v % span;
        }
    }
}

impl Trickle {
    /// Creates a stopped timer with the given configuration.
    pub const fn new(config: TrickleConfig) -> Self {
        Trickle {
            config,
            state: None,
        }
    }

    /// Returns the configuration.
    pub const fn config(&self) -> &TrickleConfig {
        &self.config
    }

    /// Returns true if the timer is running.
    pub const fn is_running(&self) -> bool {
        self.state.is_some()
    }

    /// Returns the current interval size `I`, if running.
    pub fn interval(&self) -> Option<Duration> {
        self.state.map(|s| s.interval)
    }

    /// Returns the current counter `c`, if running (trickle mode).
    pub fn counter(&self) -> Option<u16> {
        self.state.map(|s| s.counter)
    }

    fn random_interval<R: Rng + ?Sized>(&self, rng: &mut R) -> Duration {
        Duration::from_micros(uniform(
            rng,
            self.config.imin.as_micros(),
            self.config.imax.as_micros().saturating_add(1),
        ))
    }

    fn begin_interval<R: Rng + ?Sized>(&mut self, start: Instant, interval: Duration, rng: &mut R) {
        let t = match self.config.mode {
            TrickleMode::Plain => interval,
            TrickleMode::Trickle => {
                let half = interval.as_micros() / 2;
                Duration::from_micros(uniform(rng, half, interval.as_micros()))
            }
        };
        self.state = Some(Running {
            interval,
            interval_start: start,
            t,
            counter: 0,
            phase: Phase::BeforeT,
        });
    }

    /// Starts (or restarts) the timer at `now`.
    ///
    /// As in OpenThread (and RFC 6206 section 4.2), the first interval is
    /// chosen uniformly in `[Imin, Imax]`.
    pub fn start<R: Rng + ?Sized>(&mut self, now: Instant, rng: &mut R) {
        let interval = self.random_interval(rng);
        self.begin_interval(now, interval, rng);
    }

    /// Changes `Imax` (OpenThread `TrickleTimer::SetIntervalMax`), e.g. when
    /// the number of neighbors changes. Values below `Imin` are raised to
    /// `Imin`. If the running interval is longer than the new `Imax`, a new
    /// interval of `Imax` starts at `now`; otherwise the running interval
    /// continues.
    pub fn set_imax<R: Rng + ?Sized>(&mut self, imax: Duration, now: Instant, rng: &mut R) {
        let imax = imax.max(self.config.imin);
        if imax == self.config.imax {
            return;
        }
        self.config.imax = imax;
        if let Some(s) = self.state
            && s.interval > imax
        {
            self.begin_interval(now, imax, rng);
        }
    }

    /// Stops the timer.
    pub fn stop(&mut self) {
        self.state = None;
    }

    /// Records a "consistent" transmission heard from a neighbour
    /// (increments the counter `c`). No effect when stopped.
    pub fn consistent(&mut self) {
        if let Some(s) = &mut self.state {
            s.counter = s.counter.saturating_add(1);
        }
    }

    /// Records an "inconsistent" event.
    ///
    /// In trickle mode, if `I > Imin` this resets `I = Imin` and starts a new
    /// interval at `now`; if `I == Imin` it does nothing (RFC 6206 section
    /// 4.2 rule 6). No effect in plain mode or when stopped.
    pub fn inconsistent<R: Rng + ?Sized>(&mut self, now: Instant, rng: &mut R) {
        if self.config.mode != TrickleMode::Trickle {
            return;
        }
        if let Some(s) = self.state
            && s.interval != self.config.imin
        {
            self.begin_interval(now, self.config.imin, rng);
        }
    }

    /// Returns the instant at which [`Trickle::poll`] next has work to do.
    pub fn next_deadline(&self) -> Option<Instant> {
        self.state.map(|s| match s.phase {
            Phase::BeforeT => s.interval_start.saturating_add(s.t),
            Phase::AfterT => s.interval_start.saturating_add(s.interval),
        })
    }

    /// Advances the timer to `now` and returns the next event, if any.
    ///
    /// Call repeatedly until it returns `None`. Interval boundaries are
    /// processed internally (doubling `I` up to `Imax` in trickle mode, or
    /// picking a fresh random interval in plain mode); a new interval begins
    /// exactly at the previous interval's end, so there is no drift.
    pub fn poll<R: Rng + ?Sized>(&mut self, now: Instant, rng: &mut R) -> Option<TrickleEvent> {
        loop {
            let s = self.state?;
            let deadline = self.next_deadline()?;
            if deadline > now {
                return None;
            }
            match (self.config.mode, s.phase) {
                (TrickleMode::Plain, _) => {
                    let interval = self.random_interval(rng);
                    self.begin_interval(deadline, interval, rng);
                    return Some(TrickleEvent::Transmit);
                }
                (TrickleMode::Trickle, Phase::BeforeT) => {
                    if let Some(st) = &mut self.state {
                        st.phase = Phase::AfterT;
                    }
                    let k = self.config.k;
                    if k == 0 || s.counter < k {
                        return Some(TrickleEvent::Transmit);
                    }
                }
                (TrickleMode::Trickle, Phase::AfterT) => {
                    let imax = self.config.imax;
                    let next = s.interval.saturating_mul(2).min(imax);
                    self.begin_interval(deadline, next, rng);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Deterministic xorshift64* test RNG.
    struct TestRng(u64);

    impl rand_core::TryRng for TestRng {
        type Error = core::convert::Infallible;
        fn try_next_u32(&mut self) -> core::result::Result<u32, Self::Error> {
            Ok((self.try_next_u64()? >> 32) as u32)
        }
        fn try_next_u64(&mut self) -> core::result::Result<u64, Self::Error> {
            self.0 ^= self.0 >> 12;
            self.0 ^= self.0 << 25;
            self.0 ^= self.0 >> 27;
            Ok(self.0.wrapping_mul(0x2545_F491_4F6C_DD1D))
        }
        fn try_fill_bytes(&mut self, dst: &mut [u8]) -> core::result::Result<(), Self::Error> {
            for chunk in dst.chunks_mut(8) {
                let v = self.try_next_u64()?.to_le_bytes();
                chunk.copy_from_slice(&v[..chunk.len()]);
            }
            Ok(())
        }
    }

    fn rng() -> TestRng {
        TestRng(0x1234_5678_9abc_def1)
    }

    fn ms(v: u64) -> Duration {
        Duration::from_millis(v)
    }

    fn at(v: u64) -> Instant {
        Instant::from_millis(v)
    }

    fn cfg(k: u16, mode: TrickleMode) -> TrickleConfig {
        // Imin = 100 ms, Imax = 800 ms (3 doublings).
        TrickleConfig::with_doublings(ms(100), 3, k, mode).unwrap()
    }

    /// Runs the timer to `until`, collecting transmit times (ms) by stepping to
    /// each deadline.
    fn run(t: &mut Trickle, r: &mut TestRng, until: Instant, out: &mut [u64]) -> usize {
        let mut n = 0;
        while let Some(d) = t.next_deadline() {
            if d > until {
                break;
            }
            if let Some(TrickleEvent::Transmit) = t.poll(d, r) {
                out[n] = d.as_millis();
                n += 1;
            }
        }
        n
    }

    #[test]
    fn config_validation() {
        assert_eq!(
            TrickleConfig::new(Duration::ZERO, ms(1), 1, TrickleMode::Trickle),
            Err(Error::InvalidArgs)
        );
        assert_eq!(
            TrickleConfig::new(ms(2), ms(1), 1, TrickleMode::Trickle),
            Err(Error::InvalidArgs)
        );
        assert_eq!(
            TrickleConfig::with_doublings(ms(1), 64, 1, TrickleMode::Trickle),
            Err(Error::InvalidArgs)
        );
        let c = cfg(2, TrickleMode::Trickle);
        assert_eq!(c.imax(), ms(800));
        assert_eq!(c.imin(), ms(100));
        assert_eq!(c.k(), 2);
    }

    #[test]
    fn uniform_in_range_and_unbiased_edges() {
        let mut r = rng();
        let mut seen = [false; 5];
        for _ in 0..1000 {
            let v = uniform(&mut r, 10, 15);
            assert!((10..15).contains(&v));
            seen[(v - 10) as usize] = true;
        }
        assert!(seen.iter().all(|s| *s));
        assert_eq!(uniform(&mut r, 7, 7), 7);
        assert_eq!(uniform(&mut r, 0, 1), 0);
        // Full-width span must terminate.
        let _ = uniform(&mut r, 0, u64::MAX);
    }

    #[test]
    fn stopped_timer_is_inert() {
        let mut r = rng();
        let mut t = Trickle::new(cfg(1, TrickleMode::Trickle));
        assert!(!t.is_running());
        assert_eq!(t.next_deadline(), None);
        assert_eq!(t.poll(at(10_000), &mut r), None);
        t.consistent();
        t.inconsistent(at(0), &mut r);
        assert!(!t.is_running());
    }

    #[test]
    fn start_picks_interval_in_range_and_t_in_second_half() {
        for seed in 1..50u64 {
            let mut r = TestRng(seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1);
            let mut t = Trickle::new(cfg(1, TrickleMode::Trickle));
            t.start(at(1000), &mut r);
            let i = t.interval().unwrap();
            assert!(i >= ms(100) && i <= ms(800));
            let d = t.next_deadline().unwrap() - at(1000);
            assert!(d >= Duration::from_micros(i.as_micros() / 2) && d < i);
        }
    }

    #[test]
    fn doubles_up_to_imax() {
        let mut r = rng();
        let mut t = Trickle::new(cfg(0, TrickleMode::Trickle));
        t.start(at(0), &mut r);
        let mut prev = t.interval().unwrap();
        let mut now = at(0);
        let mut saw_max = false;
        for _ in 0..20 {
            // Step to the end of the current interval.
            let end = now + prev;
            let mut n = 0;
            while let Some(d) = t.next_deadline() {
                if d > end {
                    break;
                }
                if t.poll(d, &mut r).is_some() {
                    n += 1;
                }
            }
            assert_eq!(n, 1, "one transmit per interval when k is infinite");
            let cur = t.interval().unwrap();
            assert_eq!(cur, prev.saturating_mul(2).min(ms(800)));
            if cur == ms(800) {
                saw_max = true;
            }
            now = end;
            prev = cur;
        }
        assert!(saw_max);
        assert_eq!(t.interval(), Some(ms(800)));
    }

    #[test]
    fn transmit_not_before_t_and_only_once_per_interval() {
        let mut r = rng();
        let mut t = Trickle::new(cfg(1, TrickleMode::Trickle));
        t.start(at(0), &mut r);
        let tx = t.next_deadline().unwrap();
        assert_eq!(t.poll(tx - Duration::from_micros(1), &mut r), None);
        assert_eq!(t.poll(tx, &mut r), Some(TrickleEvent::Transmit));
        assert_eq!(t.poll(tx, &mut r), None);
        // Next deadline is the interval end.
        let end = t.next_deadline().unwrap();
        assert_eq!(end.as_micros(), t.interval().unwrap().as_micros());
    }

    #[test]
    fn suppression_when_counter_reaches_k() {
        let mut r = rng();
        let mut t = Trickle::new(cfg(2, TrickleMode::Trickle));
        t.start(at(0), &mut r);
        t.consistent();
        t.consistent();
        assert_eq!(t.counter(), Some(2));
        let d = t.next_deadline().unwrap();
        assert_eq!(t.poll(d, &mut r), None, "c >= k suppresses");
        // Counter resets in the next interval and transmit resumes.
        let end = t.next_deadline().unwrap();
        assert_eq!(t.poll(end, &mut r), None);
        assert_eq!(t.counter(), Some(0));
        let d2 = t.next_deadline().unwrap();
        assert_eq!(t.poll(d2, &mut r), Some(TrickleEvent::Transmit));
    }

    #[test]
    fn counter_below_k_does_not_suppress() {
        let mut r = rng();
        let mut t = Trickle::new(cfg(2, TrickleMode::Trickle));
        t.start(at(0), &mut r);
        t.consistent();
        let d = t.next_deadline().unwrap();
        assert_eq!(t.poll(d, &mut r), Some(TrickleEvent::Transmit));
    }

    #[test]
    fn infinite_k_never_suppresses() {
        let mut r = rng();
        let mut t = Trickle::new(cfg(0, TrickleMode::Trickle));
        t.start(at(0), &mut r);
        for _ in 0..100 {
            t.consistent();
        }
        let d = t.next_deadline().unwrap();
        assert_eq!(t.poll(d, &mut r), Some(TrickleEvent::Transmit));
    }

    #[test]
    fn inconsistent_resets_to_imin() {
        let mut r = rng();
        let mut t = Trickle::new(cfg(0, TrickleMode::Trickle));
        t.start(at(0), &mut r);
        let mut out = [0u64; 64];
        run(&mut t, &mut r, at(10_000), &mut out);
        assert_eq!(t.interval(), Some(ms(800)));
        t.inconsistent(at(10_000), &mut r);
        assert_eq!(t.interval(), Some(ms(100)));
        let d = t.next_deadline().unwrap() - at(10_000);
        assert!(d >= ms(50) && d < ms(100));
        assert_eq!(t.counter(), Some(0));
    }

    #[test]
    fn inconsistent_is_noop_at_imin() {
        let mut r = rng();
        // Imin == Imax forces I == Imin deterministically.
        let mut t =
            Trickle::new(TrickleConfig::new(ms(100), ms(100), 0, TrickleMode::Trickle).unwrap());
        t.start(at(0), &mut r);
        t.consistent();
        let before = t.next_deadline();
        t.inconsistent(at(30), &mut r);
        assert_eq!(t.next_deadline(), before);
        assert_eq!(t.counter(), Some(1), "state untouched");
    }

    #[test]
    fn catches_up_over_missed_intervals_without_drift() {
        let mut r = rng();
        let mut t = Trickle::new(cfg(0, TrickleMode::Trickle));
        t.start(at(0), &mut r);
        // Poll only once, long after many intervals elapsed.
        let mut n = 0;
        while t.poll(at(60_000), &mut r).is_some() {
            n += 1;
            assert!(n < 1000);
        }
        assert!(n > 10);
        assert_eq!(t.interval(), Some(ms(800)));
        assert!(t.next_deadline().unwrap() > at(60_000));
    }

    #[test]
    fn stop_and_restart() {
        let mut r = rng();
        let mut t = Trickle::new(cfg(1, TrickleMode::Trickle));
        t.start(at(0), &mut r);
        t.stop();
        assert!(!t.is_running());
        assert_eq!(t.poll(at(100_000), &mut r), None);
        t.start(at(5), &mut r);
        assert!(t.next_deadline().unwrap() > at(5));
    }

    #[test]
    fn plain_mode_never_suppresses_and_ignores_inconsistent() {
        let mut r = rng();
        let mut t = Trickle::new(cfg(1, TrickleMode::Plain));
        t.start(at(0), &mut r);
        let first = t.interval().unwrap();
        for _ in 0..5 {
            t.consistent();
        }
        t.inconsistent(at(1), &mut r);
        assert_eq!(t.interval(), Some(first));
        // Fires at the end of the interval, then starts another one in range.
        let mut now = at(0);
        for _ in 0..50 {
            let i = t.interval().unwrap();
            assert!(i >= ms(100) && i <= ms(800));
            let d = t.next_deadline().unwrap();
            assert_eq!(d, now + i);
            assert_eq!(t.poll(d - Duration::from_micros(1), &mut r), None);
            for _ in 0..3 {
                t.consistent();
            }
            assert_eq!(t.poll(d, &mut r), Some(TrickleEvent::Transmit));
            assert_eq!(t.poll(d, &mut r), None);
            now = d;
        }
    }

    #[test]
    fn plain_mode_intervals_vary() {
        let mut r = rng();
        let mut t = Trickle::new(cfg(0, TrickleMode::Plain));
        t.start(at(0), &mut r);
        let mut out = [0u64; 128];
        let n = run(&mut t, &mut r, at(20_000), &mut out);
        assert!(n >= 20000 / 800);
        assert!(out[..n].windows(2).any(|w| w[1] - w[0] != out[1] - out[0]));
    }
    #[test]
    fn set_imax_shortens_running_interval() {
        let mut r = rng();
        let mut t = Trickle::new(cfg(0, TrickleMode::Trickle));
        t.start(at(0), &mut r);
        // Grow to Imax.
        let mut now = at(0);
        while t.interval() != Some(ms(800)) {
            let d = t.next_deadline().unwrap();
            t.poll(d, &mut r);
            now = d;
        }
        t.set_imax(ms(300), now, &mut r);
        assert_eq!(t.config().imax(), ms(300));
        assert_eq!(t.interval(), Some(ms(300)));
        // A larger Imax lets the interval keep running.
        t.set_imax(ms(2000), now, &mut r);
        assert_eq!(t.interval(), Some(ms(300)));
        // Below Imin raises to Imin.
        t.set_imax(ms(1), now, &mut r);
        assert_eq!(t.config().imax(), ms(100));
    }
}
