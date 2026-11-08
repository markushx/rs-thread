//! Link Metrics (Thread 1.4.1 section 4.11.3, 1.2 feature; OpenThread
//! `thread/link_metrics.cpp`, `link_metrics_types.cpp`,
//! `link_metrics_tlvs.hpp`).
//!
//! Content codecs for the sub-TLVs inside the Link Metrics Query /
//! Management / Report TLVs, the Forward Tracking Series state, and both
//! roles on [`crate::mle::Mle`]:
//!
//! - Initiator: [`crate::mle::Mle::link_metrics_query`] (single probe or series report
//!   through a Data Request), [`crate::mle::Mle::link_metrics_forward_series`] and
//!   [`crate::mle::Mle::link_metrics_enh_ack`] (Link Metrics Management Request),
//!   [`crate::mle::Mle::link_metrics_probe`] (Link Probe). Results arrive through
//!   [`crate::env::MleEnv::link_metrics_report`], [`crate::env::MleEnv::link_metrics_management_response`]
//!   and, for Enhanced-ACK probing, [`crate::mle::Mle::process_enh_ack_ie_data`] ->
//!   [`crate::env::MleEnv::enh_ack_probing_report`].
//! - Subject: Management Requests register / clear series and Enhanced-ACK
//!   probing ([`crate::env::MleEnv::configure_enh_ack_probing`]), Link Probes and the MAC
//!   frames reported with [`crate::mle::Mle::aggregate_link_metrics`] feed the series,
//!   and a Data Request carrying a Link Metrics Query is answered with a
//!   Link Metrics Report (feature `ftd`, as the Data Request handler).

use opentrust_core::bytes::Writer;
use opentrust_core::tlv::{self as core_tlv, TlvIter};
use opentrust_core::types::ExtAddress;
use opentrust_core::{Error, Result};
use opentrust_mac::mac::LinkMetricsFlags;

use crate::link_quality::{LqiAverager, RssAverager, compute_link_margin};
pub use crate::tlv::link_metrics::Status;
use crate::tlv::link_metrics::{
    METRIC_LINK_MARGIN, METRIC_LQI, METRIC_PDU, METRIC_RSSI, SUB_ENH_ACK_CONFIG,
    SUB_FWD_PROBING_REG, SUB_QUERY_ID, SUB_QUERY_OPTIONS, SUB_REPORT, SUB_STATUS,
};

/// Most Type IDs of a [`Metrics`] (OT `kMaxTypeIds`).
pub const MAX_TYPE_IDS: usize = 4;
/// Series a device holds for all neighbors together (OT
/// `OPENTHREAD_CONFIG_MLE_LINK_METRICS_MAX_SERIES_SUPPORTED`, default the
/// child count; fixed here).
pub const MAX_SERIES: usize = 8;
/// Longest Link Probe padding (OT `kLinkProbeMaxLen`).
pub const LINK_PROBE_MAX_LEN: u8 = 64;
/// Query ID of a single probe.
pub const QUERY_ID_SINGLE_PROBE: u8 = 0;
/// Series ID that stands for all series.
pub const SERIES_ID_ALL_SERIES: u8 = 255;

const MAX_LINK_MARGIN: u16 = 130;
const MIN_RSSI: i32 = -130;
const MAX_RSSI: i32 = 0;

/// Which metrics are selected (OT `Metrics`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Metrics {
    /// Number of PDUs received.
    pub pdu_count: bool,
    /// LQI.
    pub lqi: bool,
    /// Link margin.
    pub link_margin: bool,
    /// RSSI.
    pub rssi: bool,
    /// A reserved Type ID was present (the Subject refuses these).
    pub reserved: bool,
}

impl Metrics {
    /// Nothing selected.
    pub const NONE: Self = Self {
        pdu_count: false,
        lqi: false,
        link_margin: false,
        rssi: false,
        reserved: false,
    };

    /// `true` if no metric is selected.
    pub const fn is_empty(&self) -> bool {
        !(self.pdu_count || self.lqi || self.link_margin || self.rssi)
    }

    /// OT `ConvertToTypeIds`: the Type IDs in the order PDU, LQI, margin,
    /// RSSI; returns how many were written.
    pub fn to_type_ids(&self, out: &mut [u8; MAX_TYPE_IDS]) -> usize {
        let mut n = 0;
        for (on, id) in [
            (self.pdu_count, METRIC_PDU),
            (self.lqi, METRIC_LQI),
            (self.link_margin, METRIC_LINK_MARGIN),
            (self.rssi, METRIC_RSSI),
        ] {
            if on {
                out[n] = id;
                n += 1;
            }
        }
        n
    }

    /// OT `Subject::ReadTypeIdsFromMessage`: a duplicate Type ID is a
    /// parse error, a non-extended unknown one marks `reserved`, an extended
    /// one is skipped with its second byte.
    pub fn from_type_ids(ids: &[u8]) -> Result<Self> {
        let mut m = Self::NONE;
        let mut it = ids.iter();
        while let Some(&id) = it.next() {
            let slot = match id {
                METRIC_PDU => Some(&mut m.pdu_count),
                METRIC_LQI => Some(&mut m.lqi),
                METRIC_LINK_MARGIN => Some(&mut m.link_margin),
                METRIC_RSSI => Some(&mut m.rssi),
                _ => None,
            };
            match slot {
                Some(s) => {
                    if *s {
                        return Err(Error::Parse);
                    }
                    *s = true;
                }
                None if type_id_is_extended(id) => {
                    it.next();
                }
                None => m.reserved = true,
            }
        }
        Ok(m)
    }

    /// The Enhanced-ACK subset (LQI / margin / RSSI) as the MAC's flags.
    pub const fn enh_ack_flags(&self) -> LinkMetricsFlags {
        LinkMetricsFlags {
            lqi: self.lqi,
            link_margin: self.link_margin,
            rssi: self.rssi,
        }
    }
}

/// OT `TypeId::IsExtended`.
pub const fn type_id_is_extended(id: u8) -> bool {
    id & 0x80 != 0
}

/// OT `TypeId::GetValueLength`: 4 bytes for the length flag, else 1.
pub const fn type_id_value_len(id: u8) -> usize {
    if id & 0x40 != 0 { 4 } else { 1 }
}

/// Which frames a Forward Tracking Series counts (OT `SeriesFlags`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct SeriesFlags {
    /// MLE Link Probe messages.
    pub link_probe: bool,
    /// MAC data frames.
    pub mac_data: bool,
    /// MAC data request commands.
    pub mac_data_request: bool,
    /// MAC acknowledgments.
    pub mac_ack: bool,
}

impl SeriesFlags {
    /// OT `ConvertToMask`.
    pub const fn to_mask(&self) -> u8 {
        (self.link_probe as u8)
            | (self.mac_data as u8) << 1
            | (self.mac_data_request as u8) << 2
            | (self.mac_ack as u8) << 3
    }

    /// OT `SetFrom`.
    pub const fn from_mask(m: u8) -> Self {
        Self {
            link_probe: m & 1 != 0,
            mac_data: m & 2 != 0,
            mac_data_request: m & 4 != 0,
            mac_ack: m & 8 != 0,
        }
    }
}

/// Kind of a received frame for series accounting (OT `SeriesInfo`
/// frame types).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum FrameKind {
    /// MLE Link Probe.
    LinkProbe,
    /// MAC data frame.
    MacData,
    /// MAC command (data request).
    MacDataRequest,
    /// MAC acknowledgment.
    MacAck,
}

/// Metric values (OT `MetricsValues`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct MetricsValues {
    /// Which values are valid.
    pub metrics: Metrics,
    /// PDUs received.
    pub pdu_count: u32,
    /// Average LQI.
    pub lqi: u8,
    /// Average link margin in dB.
    pub link_margin: u8,
    /// Average RSSI in dBm.
    pub rssi: i8,
}

/// Enhanced-ACK configuration flag values (OT `EnhAckFlags`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(u8)]
pub enum EnhAckFlags {
    /// Clear the configuration.
    Clear = 0,
    /// Register the metrics.
    Register = 1,
}

// ---------------------------------------------------------------- scaling

fn div_round(n: i32, d: i32) -> i32 {
    (n + d / 2) / d
}

/// OT `ScaleLinkMarginToRawValue`: dB 0..=130 to 0..=255.
pub fn scale_link_margin_to_raw(margin: u8) -> u8 {
    let v = u16::from(margin).min(MAX_LINK_MARGIN) * 255;
    ((v + MAX_LINK_MARGIN / 2) / MAX_LINK_MARGIN) as u8
}

/// OT `ScaleRawValueToLinkMargin`.
pub fn scale_raw_to_link_margin(raw: u8) -> u8 {
    ((u16::from(raw) * MAX_LINK_MARGIN + 127) / 255) as u8
}

/// OT `ScaleRssiToRawValue`: dBm -130..=0 to 0..=255.
pub fn scale_rssi_to_raw(rssi: i8) -> u8 {
    let v = (i32::from(rssi).clamp(MIN_RSSI, MAX_RSSI) - MIN_RSSI) * 255;
    div_round(v, MAX_RSSI - MIN_RSSI) as u8
}

/// OT `ScaleRawValueToRssi`.
pub fn scale_raw_to_rssi(raw: u8) -> i8 {
    let v = div_round(i32::from(raw) * (MAX_RSSI - MIN_RSSI), 255) + MIN_RSSI;
    v.clamp(i32::from(i8::MIN), i32::from(i8::MAX)) as i8
}

// ---------------------------------------------------------------- encoders

/// Query sub-TLVs: Query ID and, for a single probe, the Query Options
/// listing `metrics` (OT `AppendLinkMetricsQueryTlv`, content only). Returns
/// the length.
pub fn write_query(out: &mut [u8], query_id: u8, metrics: &Metrics) -> Result<usize> {
    let mut w = Writer::new(out);
    core_tlv::write_u8(&mut w, SUB_QUERY_ID, query_id)?;
    let mut ids = [0u8; MAX_TYPE_IDS];
    let n = metrics.to_type_ids(&mut ids);
    if n != 0 {
        core_tlv::write(&mut w, SUB_QUERY_OPTIONS, &ids[..n])?;
    }
    Ok(w.len())
}

/// Forward Probing Registration sub-TLV for a Management Request. Returns
/// the length.
pub fn write_fwd_probing_reg(
    out: &mut [u8],
    series_id: u8,
    flags: &SeriesFlags,
    metrics: &Metrics,
) -> Result<usize> {
    let mut v = [0u8; 2 + MAX_TYPE_IDS];
    v[0] = series_id;
    v[1] = flags.to_mask();
    let mut ids = [0u8; MAX_TYPE_IDS];
    let n = metrics.to_type_ids(&mut ids);
    v[2..2 + n].copy_from_slice(&ids[..n]);
    let mut w = Writer::new(out);
    core_tlv::write(&mut w, SUB_FWD_PROBING_REG, &v[..2 + n])?;
    Ok(w.len())
}

/// Enhanced ACK Configuration sub-TLV for a Management Request. Returns the
/// length.
pub fn write_enh_ack_config(
    out: &mut [u8],
    flags: EnhAckFlags,
    metrics: &Metrics,
) -> Result<usize> {
    let mut v = [0u8; 1 + MAX_TYPE_IDS];
    v[0] = flags as u8;
    let mut ids = [0u8; MAX_TYPE_IDS];
    let n = metrics.to_type_ids(&mut ids);
    v[1..1 + n].copy_from_slice(&ids[..n]);
    let mut w = Writer::new(out);
    core_tlv::write(&mut w, SUB_ENH_ACK_CONFIG, &v[..1 + n])?;
    Ok(w.len())
}

/// Status sub-TLV. Returns the length.
pub fn write_status(out: &mut [u8], status: Status) -> Result<usize> {
    let mut w = Writer::new(out);
    core_tlv::write_u8(&mut w, SUB_STATUS, status as u8)?;
    Ok(w.len())
}

/// Report sub-TLVs for the selected values (OT
/// `AppendReportSubTlvToMessage`): one per metric, PDU count with a 4-byte
/// value. Returns the length.
pub fn write_report(out: &mut [u8], v: &MetricsValues) -> Result<usize> {
    let mut w = Writer::new(out);
    if v.metrics.pdu_count {
        let b = v.pdu_count.to_be_bytes();
        core_tlv::write(&mut w, SUB_REPORT, &[METRIC_PDU, b[0], b[1], b[2], b[3]])?;
    }
    if v.metrics.lqi {
        core_tlv::write(&mut w, SUB_REPORT, &[METRIC_LQI, v.lqi])?;
    }
    if v.metrics.link_margin {
        let raw = scale_link_margin_to_raw(v.link_margin);
        core_tlv::write(&mut w, SUB_REPORT, &[METRIC_LINK_MARGIN, raw])?;
    }
    if v.metrics.rssi {
        core_tlv::write(
            &mut w,
            SUB_REPORT,
            &[METRIC_RSSI, scale_rssi_to_raw(v.rssi)],
        )?;
    }
    Ok(w.len())
}

// ---------------------------------------------------------------- decoders

/// Decode the sub-TLVs of a Link Metrics Query TLV (OT
/// `Subject::AppendReport` input): the Query ID (required) and the Query
/// Options metrics.
pub fn parse_query(sub_tlvs: &[u8]) -> Result<(u8, Metrics)> {
    let mut id = None;
    let mut metrics = Metrics::NONE;
    for t in TlvIter::new(sub_tlvs) {
        let t = t?;
        if t.is_extended() {
            continue;
        }
        match t.ty() {
            SUB_QUERY_ID => id = Some(t.read_u8()?),
            SUB_QUERY_OPTIONS => metrics = Metrics::from_type_ids(t.value())?,
            _ => {}
        }
    }
    Ok((id.ok_or(Error::Parse)?, metrics))
}

/// A decoded Link Metrics Management Request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum ManagementRequest {
    /// Neither sub-TLV present.
    Empty,
    /// Forward Probing Registration.
    ForwardTracking {
        /// Series ID.
        series_id: u8,
        /// Series flags mask; 0 removes the series.
        flags_mask: u8,
        /// Requested metrics.
        metrics: Metrics,
    },
    /// Enhanced ACK Configuration.
    EnhAck {
        /// Configuration flags (0 clear, 1 register, else invalid).
        flags: u8,
        /// Requested metrics.
        metrics: Metrics,
    },
}

/// Decode a Link Metrics Management TLV (OT `Subject::HandleManagementRequest`
/// parsing): at most one of the two sub-TLVs, each with its minimum length.
pub fn parse_management_request(sub_tlvs: &[u8]) -> Result<ManagementRequest> {
    let mut req = ManagementRequest::Empty;
    for t in TlvIter::new(sub_tlvs) {
        let t = t?;
        if t.is_extended() {
            continue;
        }
        let v = t.value();
        let next = match t.ty() {
            SUB_FWD_PROBING_REG => {
                if v.len() < 2 {
                    return Err(Error::Parse);
                }
                ManagementRequest::ForwardTracking {
                    series_id: v[0],
                    flags_mask: v[1],
                    metrics: Metrics::from_type_ids(&v[2..])?,
                }
            }
            SUB_ENH_ACK_CONFIG => {
                if v.is_empty() {
                    return Err(Error::Parse);
                }
                ManagementRequest::EnhAck {
                    flags: v[0],
                    metrics: Metrics::from_type_ids(&v[1..])?,
                }
            }
            _ => continue,
        };
        if req != ManagementRequest::Empty {
            return Err(Error::Parse);
        }
        req = next;
    }
    Ok(req)
}

/// Decode the Status sub-TLV of a Link Metrics Management Response.
pub fn parse_management_response(sub_tlvs: &[u8]) -> Result<u8> {
    let mut status = None;
    for t in TlvIter::new(sub_tlvs) {
        let t = t?;
        if t.is_extended() || t.ty() != SUB_STATUS {
            continue;
        }
        if status.is_some() {
            return Err(Error::Parse);
        }
        status = Some(t.read_u8()?);
    }
    status.ok_or(Error::Parse)
}

/// The content of a Link Metrics Report TLV.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Report {
    /// The Subject answered with a Status (no values).
    Status(u8),
    /// Metric values.
    Values(MetricsValues),
}

/// Decode a Link Metrics Report TLV (OT `Initiator::HandleReport`): a Status
/// and Report sub-TLVs exclude each other; extended Type IDs are ignored.
pub fn parse_report(sub_tlvs: &[u8]) -> Result<Report> {
    let mut status = None;
    let mut values = MetricsValues::default();
    let mut has_report = false;
    for t in TlvIter::new(sub_tlvs) {
        let t = t?;
        if t.is_extended() {
            continue;
        }
        let v = t.value();
        match t.ty() {
            SUB_STATUS => {
                if status.is_some() || has_report {
                    return Err(Error::Drop);
                }
                status = Some(t.read_u8()?);
            }
            SUB_REPORT => {
                if status.is_some() {
                    return Err(Error::Drop);
                }
                if v.len() < 2 {
                    return Err(Error::Parse);
                }
                has_report = true;
                let id = v[0];
                if type_id_is_extended(id) {
                    continue;
                }
                if type_id_value_len(id) > 1 && v.len() < 5 {
                    return Err(Error::Parse);
                }
                match id {
                    METRIC_PDU => {
                        values.metrics.pdu_count = true;
                        values.pdu_count = u32::from_be_bytes([v[1], v[2], v[3], v[4]]);
                    }
                    METRIC_LQI => {
                        values.metrics.lqi = true;
                        values.lqi = v[1];
                    }
                    METRIC_LINK_MARGIN => {
                        values.metrics.link_margin = true;
                        values.link_margin = scale_raw_to_link_margin(v[1]);
                    }
                    METRIC_RSSI => {
                        values.metrics.rssi = true;
                        values.rssi = scale_raw_to_rssi(v[1]);
                    }
                    _ => {}
                }
            }
            _ => {}
        }
    }
    match status {
        Some(s) => Ok(Report::Status(s)),
        None if has_report => Ok(Report::Values(values)),
        None => Err(Error::Drop),
    }
}

/// Decode the data of an Enhanced-ACK Link Metrics IE for the metrics the
/// Initiator configured (OT `Initiator::ProcessEnhAckIeData`): the values
/// come in the order LQI, margin, RSSI.
pub fn parse_enh_ack_ie_data(configured: &LinkMetricsFlags, data: &[u8]) -> MetricsValues {
    let mut v = MetricsValues {
        metrics: Metrics {
            lqi: configured.lqi,
            link_margin: configured.link_margin,
            rssi: configured.rssi,
            ..Metrics::NONE
        },
        ..Default::default()
    };
    let mut it = data.iter().copied();
    if configured.lqi {
        v.lqi = it.next().unwrap_or(0);
    }
    if configured.link_margin {
        v.link_margin = it.next().map_or(0, scale_raw_to_link_margin);
    }
    if configured.rssi {
        v.rssi = it.next().map_or(0, scale_raw_to_rssi);
    }
    v
}

// ---------------------------------------------------------------- series

/// One Forward Tracking Series registered by a neighbor (OT `SeriesInfo`).
#[derive(Debug, Clone)]
pub struct SeriesInfo {
    /// Series ID.
    pub series_id: u8,
    /// Frames counted.
    pub flags: SeriesFlags,
    /// Metrics to report.
    pub metrics: Metrics,
    rss: RssAverager,
    lqi: LqiAverager,
    pdu_count: u32,
}

impl SeriesInfo {
    /// A new, empty series.
    pub fn new(series_id: u8, flags: SeriesFlags, metrics: Metrics) -> Self {
        Self {
            series_id,
            flags,
            metrics,
            rss: RssAverager::new(),
            lqi: LqiAverager::new(),
            pdu_count: 0,
        }
    }

    /// OT `IsFrameTypeMatch`: link probes are ignored while MAC data frames
    /// are counted.
    pub fn matches(&self, kind: FrameKind) -> bool {
        match kind {
            FrameKind::LinkProbe => !self.flags.mac_data && self.flags.link_probe,
            FrameKind::MacData => self.flags.mac_data,
            FrameKind::MacDataRequest => self.flags.mac_data_request,
            FrameKind::MacAck => self.flags.mac_ack,
        }
    }

    /// OT `AggregateLinkMetrics`.
    pub fn aggregate(&mut self, kind: FrameKind, lqi: u8, rss: i8) {
        if self.matches(kind) {
            self.pdu_count = self.pdu_count.saturating_add(1);
            self.lqi.add(lqi);
            self.rss.add(rss);
        }
    }

    /// Frames counted.
    pub const fn pdu_count(&self) -> u32 {
        self.pdu_count
    }

    /// Average LQI.
    pub fn average_lqi(&self) -> u8 {
        self.lqi.average()
    }

    /// Average RSS.
    pub fn average_rss(&self) -> i8 {
        self.rss.average()
    }
}

/// OT `Subject::AppendReport`: the Report (or Status) sub-TLVs answering a
/// Link Metrics Query (`query`: its sub-TLVs) from neighbor `ext`, whose
/// request message arrived with `lqi` / `rss`. A single probe reports
/// the request message itself, a series its accumulated values.
pub fn report_for_query<const N: usize>(
    series: &SeriesTable<N>,
    ext: &ExtAddress,
    query: &[u8],
    lqi: u8,
    rss: i8,
    noise_floor: i8,
    out: &mut [u8],
) -> Result<usize> {
    let (id, metrics) = parse_query(query)?;
    if id == QUERY_ID_SINGLE_PROBE {
        let v = MetricsValues {
            metrics,
            pdu_count: 1,
            lqi,
            link_margin: compute_link_margin(noise_floor, rss),
            rssi: rss,
        };
        return write_report(out, &v);
    }
    match series.find(ext, id) {
        None => write_status(out, Status::SeriesIdNotRecognized),
        Some(s) if s.pdu_count() == 0 => write_status(out, Status::NoMatchingFramesReceived),
        Some(s) => {
            let v = MetricsValues {
                metrics: s.metrics,
                pdu_count: s.pdu_count(),
                lqi: s.average_lqi(),
                link_margin: compute_link_margin(noise_floor, s.average_rss()),
                rssi: s.average_rss(),
            };
            write_report(out, &v)
        }
    }
}

/// The Forward Tracking Series of all neighbors, in a pool of `N` (OT
/// `mSeriesInfoPool`).
#[derive(Debug)]
pub struct SeriesTable<const N: usize> {
    entries: heapless::Vec<(ExtAddress, SeriesInfo), N>,
}

impl<const N: usize> Default for SeriesTable<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> SeriesTable<N> {
    /// An empty table.
    pub const fn new() -> Self {
        Self {
            entries: heapless::Vec::new(),
        }
    }

    /// The series `series_id` of neighbor `ext`.
    pub fn find(&self, ext: &ExtAddress, series_id: u8) -> Option<&SeriesInfo> {
        self.entries
            .iter()
            .find(|(e, s)| e == ext && s.series_id == series_id)
            .map(|(_, s)| s)
    }

    /// Number of series of all neighbors.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// `true` if there is no series.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Forget all series of neighbor `ext`.
    pub fn remove_neighbor(&mut self, ext: &ExtAddress) {
        self.entries.retain(|(e, _)| e != ext);
    }

    /// Forget everything.
    pub fn clear(&mut self) {
        self.entries.clear();
    }

    /// OT `Subject::ConfigureForwardTrackingSeries`: a zero `flags_mask`
    /// removes the series (255 removes all), otherwise a new one is
    /// registered.
    pub fn configure(
        &mut self,
        ext: &ExtAddress,
        series_id: u8,
        flags_mask: u8,
        metrics: Metrics,
    ) -> Status {
        if series_id == 0 {
            return Status::OtherError;
        }
        if flags_mask == 0 {
            if series_id == SERIES_ID_ALL_SERIES {
                self.remove_neighbor(ext);
                return Status::Success;
            }
            let before = self.entries.len();
            self.entries
                .retain(|(e, s)| !(e == ext && s.series_id == series_id));
            return if self.entries.len() == before {
                Status::SeriesIdNotRecognized
            } else {
                Status::Success
            };
        }
        if self.find(ext, series_id).is_some() {
            return Status::SeriesIdAlreadyRegistered;
        }
        let info = SeriesInfo::new(series_id, SeriesFlags::from_mask(flags_mask), metrics);
        match self.entries.push((*ext, info)) {
            Ok(()) => Status::Success,
            Err(_) => Status::CannotSupportNewSeries,
        }
    }

    /// OT `Neighbor::AggregateLinkMetrics`: a frame from `ext`; series ID 0
    /// matches all series of the neighbor.
    pub fn aggregate(
        &mut self,
        ext: &ExtAddress,
        series_id: u8,
        kind: FrameKind,
        lqi: u8,
        rss: i8,
    ) {
        for (e, s) in self.entries.iter_mut() {
            if e == ext && (series_id == 0 || series_id == s.series_id) {
                s.aggregate(kind, lqi, rss);
            }
        }
    }
}
