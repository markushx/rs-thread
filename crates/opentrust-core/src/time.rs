//! Monotonic time types with microsecond resolution.
//!
//! The core is sans-IO: it never reads a clock. Callers pass the current
//! [`Instant`] into every time-dependent operation. Microsecond resolution is
//! required for Thread CSL (coordinated sampled listening) scheduling.

use core::ops::{Add, AddAssign, Sub, SubAssign};

const US_PER_MS: u64 = 1_000;
const US_PER_S: u64 = 1_000_000;

/// A span of time in microseconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Duration(u64);

impl Duration {
    /// Zero-length duration.
    pub const ZERO: Duration = Duration(0);
    /// Largest representable duration.
    pub const MAX: Duration = Duration(u64::MAX);

    /// Creates a duration from microseconds.
    pub const fn from_micros(us: u64) -> Self {
        Duration(us)
    }

    /// Creates a duration from milliseconds, saturating on overflow.
    pub const fn from_millis(ms: u64) -> Self {
        Duration(ms.saturating_mul(US_PER_MS))
    }

    /// Creates a duration from seconds, saturating on overflow.
    pub const fn from_secs(s: u64) -> Self {
        Duration(s.saturating_mul(US_PER_S))
    }

    /// Returns the duration in microseconds.
    pub const fn as_micros(self) -> u64 {
        self.0
    }

    /// Returns the duration in whole milliseconds (truncated).
    pub const fn as_millis(self) -> u64 {
        self.0 / US_PER_MS
    }

    /// Returns the duration in whole seconds (truncated).
    pub const fn as_secs(self) -> u64 {
        self.0 / US_PER_S
    }

    /// Returns true if the duration is zero.
    pub const fn is_zero(self) -> bool {
        self.0 == 0
    }

    /// Adds two durations, returning `None` on overflow.
    pub const fn checked_add(self, rhs: Duration) -> Option<Duration> {
        match self.0.checked_add(rhs.0) {
            Some(v) => Some(Duration(v)),
            None => None,
        }
    }

    /// Subtracts `rhs`, returning `None` if `rhs > self`.
    pub const fn checked_sub(self, rhs: Duration) -> Option<Duration> {
        match self.0.checked_sub(rhs.0) {
            Some(v) => Some(Duration(v)),
            None => None,
        }
    }

    /// Multiplies by a scalar, returning `None` on overflow.
    pub const fn checked_mul(self, rhs: u64) -> Option<Duration> {
        match self.0.checked_mul(rhs) {
            Some(v) => Some(Duration(v)),
            None => None,
        }
    }

    /// Adds two durations, saturating at [`Duration::MAX`].
    pub const fn saturating_add(self, rhs: Duration) -> Duration {
        Duration(self.0.saturating_add(rhs.0))
    }

    /// Subtracts `rhs`, saturating at zero.
    pub const fn saturating_sub(self, rhs: Duration) -> Duration {
        Duration(self.0.saturating_sub(rhs.0))
    }

    /// Multiplies by a scalar, saturating at [`Duration::MAX`].
    pub const fn saturating_mul(self, rhs: u64) -> Duration {
        Duration(self.0.saturating_mul(rhs))
    }
}

impl Add for Duration {
    type Output = Duration;
    /// Saturating addition.
    fn add(self, rhs: Duration) -> Duration {
        self.saturating_add(rhs)
    }
}

impl AddAssign for Duration {
    fn add_assign(&mut self, rhs: Duration) {
        *self = *self + rhs;
    }
}

impl Sub for Duration {
    type Output = Duration;
    /// Saturating subtraction.
    fn sub(self, rhs: Duration) -> Duration {
        self.saturating_sub(rhs)
    }
}

impl SubAssign for Duration {
    fn sub_assign(&mut self, rhs: Duration) {
        *self = *self - rhs;
    }
}

/// A point in monotonic time, in microseconds since an arbitrary epoch.
///
/// The epoch is chosen by the platform; only differences are meaningful.
/// A `u64` of microseconds does not wrap in practice (> 500,000 years).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Instant(u64);

impl Instant {
    /// The epoch (time zero).
    pub const ZERO: Instant = Instant(0);
    /// The largest representable instant.
    pub const MAX: Instant = Instant(u64::MAX);

    /// Creates an instant from microseconds since the epoch.
    pub const fn from_micros(us: u64) -> Self {
        Instant(us)
    }

    /// Creates an instant from milliseconds since the epoch, saturating.
    pub const fn from_millis(ms: u64) -> Self {
        Instant(ms.saturating_mul(US_PER_MS))
    }

    /// Creates an instant from seconds since the epoch, saturating.
    pub const fn from_secs(s: u64) -> Self {
        Instant(s.saturating_mul(US_PER_S))
    }

    /// Returns microseconds since the epoch.
    pub const fn as_micros(self) -> u64 {
        self.0
    }

    /// Returns whole milliseconds since the epoch (truncated).
    pub const fn as_millis(self) -> u64 {
        self.0 / US_PER_MS
    }

    /// Returns whole seconds since the epoch (truncated).
    pub const fn as_secs(self) -> u64 {
        self.0 / US_PER_S
    }

    /// Returns `self + d`, or `None` on overflow.
    pub const fn checked_add(self, d: Duration) -> Option<Instant> {
        match self.0.checked_add(d.0) {
            Some(v) => Some(Instant(v)),
            None => None,
        }
    }

    /// Returns `self - d`, or `None` if it would precede the epoch.
    pub const fn checked_sub(self, d: Duration) -> Option<Instant> {
        match self.0.checked_sub(d.0) {
            Some(v) => Some(Instant(v)),
            None => None,
        }
    }

    /// Returns `self + d`, saturating at [`Instant::MAX`].
    pub const fn saturating_add(self, d: Duration) -> Instant {
        Instant(self.0.saturating_add(d.0))
    }

    /// Returns `self - d`, saturating at the epoch.
    pub const fn saturating_sub(self, d: Duration) -> Instant {
        Instant(self.0.saturating_sub(d.0))
    }

    /// Returns the time elapsed from `earlier` to `self`, or `None` if
    /// `earlier` is later than `self`.
    pub const fn checked_duration_since(self, earlier: Instant) -> Option<Duration> {
        match self.0.checked_sub(earlier.0) {
            Some(v) => Some(Duration(v)),
            None => None,
        }
    }

    /// Returns the time elapsed from `earlier` to `self`, or zero if
    /// `earlier` is later than `self`.
    pub const fn saturating_duration_since(self, earlier: Instant) -> Duration {
        Duration(self.0.saturating_sub(earlier.0))
    }
}

impl Add<Duration> for Instant {
    type Output = Instant;
    /// Saturating addition.
    fn add(self, rhs: Duration) -> Instant {
        self.saturating_add(rhs)
    }
}

impl AddAssign<Duration> for Instant {
    fn add_assign(&mut self, rhs: Duration) {
        *self = *self + rhs;
    }
}

impl Sub<Duration> for Instant {
    type Output = Instant;
    /// Saturating subtraction.
    fn sub(self, rhs: Duration) -> Instant {
        self.saturating_sub(rhs)
    }
}

impl SubAssign<Duration> for Instant {
    fn sub_assign(&mut self, rhs: Duration) {
        *self = *self - rhs;
    }
}

impl Sub<Instant> for Instant {
    type Output = Duration;
    /// Saturating difference (zero if `rhs` is later than `self`).
    fn sub(self, rhs: Instant) -> Duration {
        self.saturating_duration_since(rhs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constructors_and_accessors() {
        assert_eq!(Duration::from_millis(3).as_micros(), 3_000);
        assert_eq!(Duration::from_secs(2).as_millis(), 2_000);
        assert_eq!(Duration::from_micros(2_999_999).as_secs(), 2);
        assert_eq!(Instant::from_secs(1).as_micros(), 1_000_000);
        assert_eq!(Instant::from_millis(1_500).as_secs(), 1);
        assert!(Duration::ZERO.is_zero());
        assert_eq!(Duration::from_secs(u64::MAX), Duration::MAX);
    }

    #[test]
    fn duration_arithmetic() {
        let a = Duration::from_millis(5);
        let b = Duration::from_millis(2);
        assert_eq!(a + b, Duration::from_millis(7));
        assert_eq!(a - b, Duration::from_millis(3));
        assert_eq!(b - a, Duration::ZERO);
        assert_eq!(b.checked_sub(a), None);
        assert_eq!(Duration::MAX.checked_add(b), None);
        assert_eq!(Duration::MAX + b, Duration::MAX);
        assert_eq!(a.checked_mul(2), Some(Duration::from_millis(10)));
        assert_eq!(Duration::MAX.checked_mul(2), None);
        assert_eq!(Duration::MAX.saturating_mul(2), Duration::MAX);
        let mut c = a;
        c += b;
        c -= a;
        assert_eq!(c, b);
    }

    #[test]
    fn instant_arithmetic() {
        let t0 = Instant::from_millis(10);
        let t1 = t0 + Duration::from_millis(5);
        assert_eq!(t1 - t0, Duration::from_millis(5));
        assert_eq!(t0 - t1, Duration::ZERO);
        assert_eq!(t0.checked_duration_since(t1), None);
        assert_eq!(
            t1.checked_duration_since(t0),
            Some(Duration::from_millis(5))
        );
        assert_eq!(t0.checked_sub(Duration::from_millis(11)), None);
        assert_eq!(t0 - Duration::from_millis(11), Instant::ZERO);
        assert_eq!(Instant::MAX.checked_add(Duration::from_micros(1)), None);
        assert_eq!(Instant::MAX + Duration::from_micros(1), Instant::MAX);
        let mut t = t0;
        t += Duration::from_millis(1);
        t -= Duration::from_millis(2);
        assert_eq!(t, Instant::from_millis(9));
    }

    #[test]
    fn ordering() {
        assert!(Instant::from_micros(1) < Instant::from_micros(2));
        assert!(Duration::from_millis(1) > Duration::from_micros(999));
    }
}
