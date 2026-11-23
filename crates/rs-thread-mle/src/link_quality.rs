//! Link quality: RSS averaging, link margin to link quality mapping with
//! hysteresis, link cost, error-rate trackers (Thread 1.4.1 link quality and
//! link cost, §4.7 / §5.9; OpenThread `thread/link_quality.{hpp,cpp}`).
//!
//! Everything is integer arithmetic identical to OpenThread so that
//! neighbors derive the same link qualities from the same RSS samples.

use crate::consts::MAX_ROUTE_COST;

/// "No RSSI measurement" marker (OT `Radio::kInvalidRssi`).
pub const INVALID_RSSI: i8 = 127;

/// Link quality 0..=3 (3 = best), as carried in Route64 and Connectivity
/// TLVs (OT `LinkQuality`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(u8)]
pub enum LinkQuality {
    /// Unknown / unusable link (cost 16 = infinite).
    #[default]
    Q0 = 0,
    /// Poor link.
    Q1 = 1,
    /// Medium link.
    Q2 = 2,
    /// Good link.
    Q3 = 3,
}

impl LinkQuality {
    /// From the two low bits of `v` (wider values are masked).
    pub const fn from_bits(v: u8) -> Self {
        match v & 3 {
            0 => Self::Q0,
            1 => Self::Q1,
            2 => Self::Q2,
            _ => Self::Q3,
        }
    }

    /// Numeric value 0..=3.
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    /// Link quality for a link margin (dB above the noise floor), with
    /// hysteresis when `last` is known (OT `CalculateLinkQuality`): the
    /// thresholds for *entering* a better class are raised by 2 dB, so a
    /// link at a class boundary does not flap. Thresholds without
    /// hysteresis: margin > 20 => 3, > 10 => 2, > 2 => 1, else 0.
    pub const fn from_margin(link_margin: u8, last: Option<LinkQuality>) -> Self {
        const T1: u8 = 2;
        const T2: u8 = 10;
        const T3: u8 = 20;
        const HYSTERESIS: u8 = 2;
        let (mut t1, mut t2, mut t3) = (T1, T2, T3);
        if let Some(l) = last {
            // Falls through like OT's switch: Q0 raises all three, Q1 the
            // upper two, Q2 the top one.
            if (l as u8) == 0 {
                t1 += HYSTERESIS;
            }
            if (l as u8) <= 1 {
                t2 += HYSTERESIS;
            }
            if (l as u8) <= 2 {
                t3 += HYSTERESIS;
            }
        }
        if link_margin > t3 {
            Self::Q3
        } else if link_margin > t2 {
            Self::Q2
        } else if link_margin > t1 {
            Self::Q1
        } else {
            Self::Q0
        }
    }

    /// Link quality for a margin without history (OT
    /// `LinkQualityForLinkMargin`).
    pub const fn for_margin(link_margin: u8) -> Self {
        Self::from_margin(link_margin, None)
    }

    /// Link cost for this quality (OT `CostForLinkQuality`: 1, 2, 4,
    /// [`MAX_ROUTE_COST`] for quality 0).
    pub const fn cost(self) -> u8 {
        match self {
            Self::Q3 => 1,
            Self::Q2 => 2,
            Self::Q1 => 4,
            Self::Q0 => MAX_ROUTE_COST,
        }
    }

    /// A typical RSS for this quality at `noise_floor` (OT
    /// `GetTypicalRssForLinkQuality`): link margin 50 / 15 / 5 / 0 dB above
    /// the noise floor.
    pub const fn typical_rss(self, noise_floor: i8) -> i8 {
        let margin = match self {
            Self::Q3 => 50,
            Self::Q2 => 15,
            Self::Q1 => 5,
            Self::Q0 => 0,
        };
        margin + noise_floor
    }
}

/// Link margin: `rss - noise_floor` in dB, 0 if negative or `rss` invalid
/// (OT `ComputeLinkMargin`).
pub const fn compute_link_margin(noise_floor: i8, rss: i8) -> u8 {
    let m = rss as i16 - noise_floor as i16;
    if m < 0 || rss == INVALID_RSSI {
        0
    } else if m > 255 {
        255
    } else {
        m as u8
    }
}

/// Exponentially weighted moving average of RSS with 1/8 dB precision (OT
/// `RssAverager`): the first 8 samples form an arithmetic mean, afterwards
/// each sample has weight 1/8.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct RssAverager {
    /// `-RSS * 8`, 11 bits in OT.
    average: u16,
    /// Samples so far, capped at 8.
    count: u8,
}

impl RssAverager {
    const PRECISION_SHIFT: u8 = 3;
    const PRECISION: u16 = 1 << Self::PRECISION_SHIFT;
    const PRECISION_MASK: u16 = Self::PRECISION - 1;
    const COEFF: u8 = 1 << 3;

    /// Empty averager.
    pub const fn new() -> Self {
        Self {
            average: 0,
            count: 0,
        }
    }

    /// Forget all samples.
    pub fn clear(&mut self) {
        *self = Self::new();
    }

    /// `true` once a sample was added.
    pub const fn has_average(&self) -> bool {
        self.count != 0
    }

    /// Add a sample; `false` (ignored) for [`INVALID_RSSI`]. Values above 0
    /// are clamped to 0, below -128 are impossible for `i8`.
    pub fn add(&mut self, rss: i8) -> bool {
        if rss == INVALID_RSSI {
            return false;
        }
        let rss = rss.min(0);
        let new_value = (-(rss as i16)) as u16;
        let new_value = new_value << Self::PRECISION_SHIFT;
        if self.count < Self::COEFF {
            self.count += 1;
        }
        let c = u32::from(self.count);
        self.average = ((u32::from(self.average) * (c - 1) + u32::from(new_value)) / c) as u16;
        true
    }

    /// Average RSS in dBm (rounded to nearest), [`INVALID_RSSI`] if empty.
    pub fn average(&self) -> i8 {
        if self.count == 0 {
            return INVALID_RSSI;
        }
        let mut a = -((self.average >> Self::PRECISION_SHIFT) as i16);
        if self.average & Self::PRECISION_MASK >= Self::PRECISION >> 1 {
            a -= 1;
        }
        a.max(i8::MIN as i16) as i8
    }

    /// Raw `-RSS * 8` value (OT `GetRaw`).
    pub const fn raw(&self) -> u16 {
        self.average
    }
}

/// Averager of link quality indicator values (OT `LqiAverager`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct LqiAverager {
    average: u8,
    count: u8,
}

impl LqiAverager {
    const COEFF: u8 = 8;

    /// Empty averager.
    pub const fn new() -> Self {
        Self {
            average: 0,
            count: 0,
        }
    }

    /// Forget all samples.
    pub fn clear(&mut self) {
        *self = Self::new();
    }

    /// Add a sample.
    pub fn add(&mut self, lqi: u8) {
        self.count = self.count.saturating_add(1);
        let count = u16::from(Self::COEFF.min(self.count));
        self.average = ((u16::from(self.average) * (count - 1) + u16::from(lqi)) / count) as u8;
    }

    /// Average LQI.
    pub const fn average(&self) -> u8 {
        self.average
    }

    /// Number of samples (saturating at 255).
    pub const fn count(&self) -> u8 {
        self.count
    }
}

/// Weighted moving success/failure rate with 16-bit resolution (OT
/// `SuccessRateTracker`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct SuccessRateTracker {
    failure_rate: u16,
}

impl SuccessRateTracker {
    /// Value for 100 %.
    pub const MAX_RATE: u16 = 0xffff;
    /// Default sample weight (OT `kDefaultWeight`).
    pub const DEFAULT_WEIGHT: u16 = 64;

    /// 0 % failures.
    pub const fn new() -> Self {
        Self { failure_rate: 0 }
    }

    /// Reset to 0 % failures.
    pub fn clear(&mut self) {
        self.failure_rate = 0;
    }

    /// Add a sample; `weight` (>= 1) is the number of samples the average
    /// spans, ramped up by the caller for the first samples.
    pub fn add_sample(&mut self, success: bool, weight: u16) {
        let old = u32::from(self.failure_rate);
        let new_value = if success {
            0
        } else {
            u32::from(Self::MAX_RATE)
        };
        let n = u32::from(weight.max(1));
        self.failure_rate = ((old * (n - 1) + new_value + n / 2) / n) as u16;
    }

    /// Failure rate `0..=MAX_RATE`.
    pub const fn failure_rate(&self) -> u16 {
        self.failure_rate
    }

    /// Success rate `0..=MAX_RATE`.
    pub const fn success_rate(&self) -> u16 {
        Self::MAX_RATE - self.failure_rate
    }
}

/// Link quality state of a neighbor (OT `LinkQualityInfo`): RSS average,
/// incoming link quality (derived from it with hysteresis), outgoing link
/// quality (reported by the neighbor in Route64 / Link Margin TLVs), and
/// error rates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct LinkQualityInfo {
    rss: RssAverager,
    last_rss: i8,
    link_quality_in: LinkQuality,
    link_quality_out: LinkQuality,
    /// MAC frame error rate.
    pub frame_error_rate: SuccessRateTracker,
    /// IPv6 message error rate.
    pub message_error_rate: SuccessRateTracker,
}

impl Default for LinkQualityInfo {
    fn default() -> Self {
        Self::new()
    }
}

impl LinkQualityInfo {
    /// Cleared state: no RSS, link qualities 0.
    pub const fn new() -> Self {
        Self {
            rss: RssAverager::new(),
            last_rss: INVALID_RSSI,
            link_quality_in: LinkQuality::Q0,
            link_quality_out: LinkQuality::Q0,
            frame_error_rate: SuccessRateTracker::new(),
            message_error_rate: SuccessRateTracker::new(),
        }
    }

    /// Reset everything.
    pub fn clear(&mut self) {
        *self = Self::new();
    }

    /// Add an RSS sample (e.g. of a received frame) and update the incoming
    /// link quality using `noise_floor` (dBm). [`INVALID_RSSI`] is ignored.
    pub fn add_rss(&mut self, noise_floor: i8, rss: i8) {
        if rss == INVALID_RSSI {
            return;
        }
        self.last_rss = rss;
        let old = self.rss.has_average().then_some(self.link_quality_in);
        if self.rss.add(rss) {
            self.link_quality_in = LinkQuality::from_margin(self.link_margin(noise_floor), old);
        }
    }

    /// Forget the RSS average (OT `LinkQualityInfo::ClearAverageRss`); the
    /// incoming link quality stays until the next sample.
    pub fn clear_average_rss(&mut self) {
        self.rss.clear();
    }

    /// Average RSS, [`INVALID_RSSI`] if none.
    pub fn average_rss(&self) -> i8 {
        self.rss.average()
    }

    /// Raw averager value.
    pub const fn average_rss_raw(&self) -> u16 {
        self.rss.raw()
    }

    /// Last RSS sample, [`INVALID_RSSI`] if none.
    pub const fn last_rss(&self) -> i8 {
        self.last_rss
    }

    /// Link margin of the average RSS above `noise_floor`.
    pub fn link_margin(&self, noise_floor: i8) -> u8 {
        compute_link_margin(noise_floor, self.average_rss())
    }

    /// Incoming link quality (from our measurements of the neighbor).
    pub const fn link_quality_in(&self) -> LinkQuality {
        self.link_quality_in
    }

    /// Outgoing link quality (the neighbor's view of our transmissions).
    pub const fn link_quality_out(&self) -> LinkQuality {
        self.link_quality_out
    }

    /// Set the outgoing link quality.
    pub fn set_link_quality_out(&mut self, lq: LinkQuality) {
        self.link_quality_out = lq;
    }

    /// Set the incoming link quality directly (e.g. when restoring).
    pub fn set_link_quality_in(&mut self, lq: LinkQuality) {
        self.link_quality_in = lq;
    }

    /// Link quality of the two-way link: the minimum of in and out.
    pub fn two_way_quality(&self) -> LinkQuality {
        self.link_quality_in.min(self.link_quality_out)
    }
}

#[cfg(test)]
#[path = "link_quality_tests.rs"]
mod tests;
