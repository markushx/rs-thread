//! Enhanced-ACK based Link Metrics probing, MAC part (Thread 1.4.1 §4.11.3.3,
//! §4.11.3.4.4.6; OpenThread `LinkMetrics::Subject/Initiator` and the radio
//! platform's `otLinkMetricsEnhAckGenData`).
//!
//! A *subject* registers per probing initiator which single-sample metrics
//! of the acknowledged frame it reports ([`Mac::configure_enh_ack_probing`](super::Mac::configure_enh_ack_probing));
//! its enhanced ACKs to that initiator then carry a Thread vendor-specific
//! header IE (sub-type 0) with one or two bytes: LQI, link margin, RSSI, in
//! that order, the latter two scaled linearly to `0..=255`. An *initiator*
//! tells the MAC which metrics it configured at a neighbor
//! ([`Mac::track_enh_ack_probing`](super::Mac::track_enh_ack_probing)); the IE
//! of the neighbor's enhanced ACKs is then decoded and reported as
//! [`Event::EnhAckLinkMetrics`](super::Event::EnhAckLinkMetrics). The MLE Link
//! Metrics Management messages that drive both belong to MLE and are not
//! implemented yet.

use heapless::Vec;
use opentrust_core::types::{ExtAddress, ShortAddress};
use opentrust_core::{Error, Result};

use crate::frame::Address;

/// Maximum payload of the Enhanced-ACK probing IE (two metrics).
pub const ENH_ACK_PROBING_MAX_DATA: usize = 2;
/// Link margin is scaled from `0..=130` dB (OpenThread `kMaxLinkMargin`).
pub const MAX_LINK_MARGIN: u8 = 130;
/// RSSI is scaled from `-130..=0` dBm.
pub const MIN_RSSI: i16 = -130;

/// Which metrics of the acknowledged frame an enhanced ACK reports
/// (Thread Metric Type ID Flags with Type/Average 1: single sample).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct LinkMetricsFlags {
    /// Link Quality Indicator (Metric 1).
    pub lqi: bool,
    /// Link margin (Metric 2).
    pub link_margin: bool,
    /// RSSI (Metric 3).
    pub rssi: bool,
}

impl LinkMetricsFlags {
    /// No metric (clears a configuration).
    pub const NONE: Self = Self {
        lqi: false,
        link_margin: false,
        rssi: false,
    };

    /// Number of metrics.
    pub const fn count(&self) -> usize {
        self.lqi as usize + self.link_margin as usize + self.rssi as usize
    }

    /// No metric requested.
    pub const fn is_empty(&self) -> bool {
        self.count() == 0
    }
}

/// Values decoded from an Enhanced-ACK probing IE; `None` for metrics that
/// were not configured.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct EnhAckProbingValues {
    /// LQI of the acknowledged frame (0..=255).
    pub lqi: Option<u8>,
    /// Link margin in dB (0..=130).
    pub link_margin: Option<u8>,
    /// RSSI in dBm (-130..=0).
    pub rssi: Option<i8>,
}

/// Link margin of an RSSI over the noise floor (OpenThread
/// `ComputeLinkMargin`: never negative).
pub fn compute_link_margin(noise_floor: i8, rssi: i8) -> u8 {
    (i16::from(rssi) - i16::from(noise_floor)).clamp(0, 255) as u8
}

fn div_round(n: u32, d: u32) -> u32 {
    (n + d / 2) / d
}

/// Scale a link margin (dB) to the raw `0..=255` value of the IE.
pub fn scale_link_margin_to_raw(margin: u8) -> u8 {
    div_round(
        u32::from(margin.min(MAX_LINK_MARGIN)) * 255,
        u32::from(MAX_LINK_MARGIN),
    ) as u8
}

/// Inverse of [`scale_link_margin_to_raw`].
pub fn scale_raw_to_link_margin(raw: u8) -> u8 {
    div_round(u32::from(raw) * u32::from(MAX_LINK_MARGIN), 255) as u8
}

/// Scale an RSSI (dBm, clamped to `-130..=0`) to the raw `0..=255` value.
pub fn scale_rssi_to_raw(rssi: i8) -> u8 {
    let v = (i32::from(rssi).clamp(i32::from(MIN_RSSI), 0) - i32::from(MIN_RSSI)) as u32;
    div_round(v * 255, 130) as u8
}

/// Inverse of [`scale_rssi_to_raw`]. Values below -128 dBm saturate at
/// `i8::MIN` (OpenThread's `int8_t` result wraps there).
pub fn scale_raw_to_rssi(raw: u8) -> i8 {
    (div_round(u32::from(raw) * 130, 255) as i32 + i32::from(MIN_RSSI)).max(i32::from(i8::MIN))
        as i8
}

/// Encode the IE data for `flags`: LQI, link margin, RSSI in this order,
/// at most two bytes (a third metric is not reported, as OpenThread's
/// reference platform). Returns the bytes used, `None` if a requested
/// metric is not available (`lqi` / `rssi` missing from the radio).
pub fn encode_enh_ack_data(
    flags: LinkMetricsFlags,
    lqi: Option<u8>,
    rssi: Option<i8>,
    noise_floor: i8,
    out: &mut [u8; ENH_ACK_PROBING_MAX_DATA],
) -> Option<usize> {
    let mut n = 0;
    if flags.lqi {
        out[n] = lqi?;
        n += 1;
    }
    if flags.link_margin {
        out[n] = scale_link_margin_to_raw(compute_link_margin(noise_floor, rssi?));
        n += 1;
    }
    if flags.rssi && n < ENH_ACK_PROBING_MAX_DATA {
        out[n] = scale_rssi_to_raw(rssi?);
        n += 1;
    }
    Some(n)
}

/// Decode IE `data` for the metrics `flags` the initiator configured, in the
/// same order (OpenThread `Initiator::ProcessEnhAckIeData`); metrics beyond
/// the data present stay `None`.
pub fn decode_enh_ack_data(flags: LinkMetricsFlags, data: &[u8]) -> EnhAckProbingValues {
    let mut it = data.iter().copied();
    let mut v = EnhAckProbingValues::default();
    if flags.lqi {
        v.lqi = it.next();
    }
    if flags.link_margin {
        v.link_margin = it.next().map(scale_raw_to_link_margin);
    }
    if flags.rssi {
        v.rssi = it.next().map(scale_raw_to_rssi);
    }
    v
}

/// One configured probing relationship (subject side: the initiator;
/// initiator side: the subject).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ProbeEntry {
    pub short: ShortAddress,
    pub ext: ExtAddress,
    pub flags: LinkMetricsFlags,
}

impl ProbeEntry {
    pub fn matches(&self, a: Address) -> bool {
        match a {
            Address::Short(s) => s == self.short,
            Address::Extended(e) => e == self.ext,
            _ => false,
        }
    }
}

/// A small table of [`ProbeEntry`]s.
#[derive(Debug, Default)]
pub(crate) struct ProbeTable<const N: usize> {
    entries: Vec<ProbeEntry, N>,
}

impl<const N: usize> ProbeTable<N> {
    /// Add, update or (empty `flags`) remove the entry for the peer
    /// (`short`, `ext`). [`Error::NotFound`] when removing an unknown peer,
    /// [`Error::NoBufs`] when full, [`Error::InvalidArgs`] for more than two
    /// metrics.
    pub fn configure(
        &mut self,
        short: ShortAddress,
        ext: ExtAddress,
        flags: LinkMetricsFlags,
    ) -> Result<()> {
        if flags.count() > ENH_ACK_PROBING_MAX_DATA {
            return Err(Error::InvalidArgs);
        }
        let pos = self
            .entries
            .iter()
            .position(|e| e.short == short || e.ext == ext);
        match (pos, flags.is_empty()) {
            (Some(i), true) => {
                self.entries.swap_remove(i);
                Ok(())
            }
            (None, true) => Err(Error::NotFound),
            (Some(i), false) => {
                self.entries[i] = ProbeEntry { short, ext, flags };
                Ok(())
            }
            (None, false) => self
                .entries
                .push(ProbeEntry { short, ext, flags })
                .map_err(|_| Error::NoBufs),
        }
    }

    pub fn find(&self, a: Address) -> Option<&ProbeEntry> {
        self.entries.iter().find(|e| e.matches(a))
    }

    pub fn clear(&mut self) {
        self.entries.clear();
    }
}
