//! The Link Metrics Initiator and Subject roles on [`Mle`] (OT
//! `LinkMetrics::Initiator` / `Subject` and the `Mle::HandleLinkMetrics*` /
//! `HandleLinkProbe` message handlers). The codecs and the series state are
//! in [`crate::link_metrics`].

use core::net::Ipv6Addr;

use opentrust_core::types::{ExtAddress, Rloc16, ipv6};
use opentrust_core::{Error, Result};

use crate::consts::THREAD_VERSION_1_2;
use crate::endpoint::MleRx;
use crate::env::MleEnv;
use crate::link_metrics::{
    EnhAckFlags, FrameKind, LINK_PROBE_MAX_LEN, MAX_SERIES, ManagementRequest, Metrics,
    QUERY_ID_SINGLE_PROBE, Report, SERIES_ID_ALL_SERIES, SeriesFlags, SeriesTable, Status,
    parse_enh_ack_ie_data, parse_management_request, parse_management_response, parse_report,
    write_enh_ack_config, write_fwd_probing_reg, write_query, write_status,
};
use crate::message::Command;
use crate::mle::{Mle, NbRef, RxClass};
use crate::tlv::ty;

/// Longest sub-TLV content built here.
const SUB_BUF: usize = 32;

impl<const C: usize> Mle<C> {
    /// OT `Initiator::FindNeighbor`: the neighbor behind a link-local
    /// destination, which must speak Thread 1.2 or newer. Errors:
    /// [`Error::NotFound`] (unknown neighbor), [`Error::InvalidState`] (too
    /// old).
    fn link_metrics_neighbor(&mut self, dst: &Ipv6Addr) -> Result<NbRef> {
        if !ipv6::is_link_local(dst) {
            return Err(Error::NotFound);
        }
        let ext = ipv6::iid(dst).to_ext_address();
        let r = self.find_neighbor(&ext, false).ok_or(Error::NotFound)?;
        if !self.neighbor_is_valid(Some(r)) {
            return Err(Error::NotFound);
        }
        if self.neighbor_mut(r).version < THREAD_VERSION_1_2 {
            return Err(Error::InvalidState);
        }
        Ok(r)
    }

    // ---------------------------------------------------------- initiator

    /// OT `Initiator::Query`: ask neighbor `dst` (link-local address) for a
    /// Link Metrics Report in a Data Request. `series_id` 0 is a single
    /// probe of `metrics`, otherwise the report of that Forward Tracking
    /// Series (no `metrics` then). The answer arrives through
    /// [`MleEnv::link_metrics_report`].
    pub fn link_metrics_query<E: MleEnv>(
        &mut self,
        env: &mut E,
        dst: &Ipv6Addr,
        series_id: u8,
        metrics: Option<&Metrics>,
    ) -> Result<()> {
        self.link_metrics_neighbor(dst)?;
        let m = metrics.copied().unwrap_or(Metrics::NONE);
        if series_id != 0 && !m.is_empty() {
            return Err(Error::InvalidArgs);
        }
        let mut sub = [0u8; SUB_BUF];
        let n = write_query(&mut sub, series_id, &m)?;
        let active_ts = env.active_timestamp();
        let pending_ts = env.pending_timestamp();
        self.send(env, *dst, Command::DataRequest, |w| {
            w.tlv_request(&[ty::LINK_METRICS_REPORT])?;
            w.link_metrics_query(&sub[..n])?;
            if let Some(t) = &active_ts {
                w.active_timestamp(t)?;
            }
            if let Some(t) = &pending_ts {
                w.pending_timestamp(t)?;
            }
            Ok(())
        })
    }

    fn send_link_metrics_management_request<E: MleEnv>(
        &mut self,
        env: &mut E,
        dst: &Ipv6Addr,
        sub: &[u8],
    ) -> Result<()> {
        self.send(env, *dst, Command::LinkMetricsManagementRequest, |w| {
            w.link_metrics_management(sub)
        })
    }

    /// OT `Initiator::SendMgmtRequestForwardTrackingSeries`: register
    /// (`flags` not empty) or clear (empty flags) a series on `dst`. The
    /// Subject's Status arrives through
    /// [`MleEnv::link_metrics_management_response`].
    pub fn link_metrics_forward_series<E: MleEnv>(
        &mut self,
        env: &mut E,
        dst: &Ipv6Addr,
        series_id: u8,
        flags: &SeriesFlags,
        metrics: Option<&Metrics>,
    ) -> Result<()> {
        self.link_metrics_neighbor(dst)?;
        if series_id == QUERY_ID_SINGLE_PROBE {
            return Err(Error::InvalidArgs);
        }
        let mut sub = [0u8; SUB_BUF];
        let n = write_fwd_probing_reg(
            &mut sub,
            series_id,
            flags,
            &metrics.copied().unwrap_or(Metrics::NONE),
        )?;
        self.send_link_metrics_management_request(env, dst, &sub[..n])
    }

    /// OT `Initiator::SendMgmtRequestEnhAckProbing`: (de)configure
    /// Enhanced-ACK based probing on `dst`. The metrics the Initiator
    /// expects in the ACKs are remembered on the neighbor
    /// (`Neighbor::enh_ack_probing`) for [`Mle::process_enh_ack_ie_data`].
    pub fn link_metrics_enh_ack<E: MleEnv>(
        &mut self,
        env: &mut E,
        dst: &Ipv6Addr,
        flags: EnhAckFlags,
        metrics: Option<&Metrics>,
    ) -> Result<()> {
        let r = self.link_metrics_neighbor(dst)?;
        if flags == EnhAckFlags::Clear && metrics.is_some() {
            return Err(Error::InvalidArgs);
        }
        let m = metrics.copied().unwrap_or(Metrics::NONE);
        let mut sub = [0u8; SUB_BUF];
        let n = write_enh_ack_config(&mut sub, flags, &m)?;
        let res = self.send_link_metrics_management_request(env, dst, &sub[..n]);
        let nb = self.neighbor_mut(r);
        nb.enh_ack_probing = m.enh_ack_flags();
        let (flags, rloc16, ext) = (nb.enh_ack_probing, nb.rloc16, nb.ext_address);
        env.track_enh_ack_probing(flags, rloc16, &ext);
        res
    }

    /// OT `Initiator::SendLinkProbe`: a Link Probe of `len` padding bytes
    /// for series `series_id` (not 0 and not 255).
    pub fn link_metrics_probe<E: MleEnv>(
        &mut self,
        env: &mut E,
        dst: &Ipv6Addr,
        series_id: u8,
        len: u8,
    ) -> Result<()> {
        self.link_metrics_neighbor(dst)?;
        if len > LINK_PROBE_MAX_LEN
            || series_id == QUERY_ID_SINGLE_PROBE
            || series_id == SERIES_ID_ALL_SERIES
        {
            return Err(Error::InvalidArgs);
        }
        self.send(env, *dst, Command::LinkProbe, |w| {
            w.link_probe(series_id, usize::from(len))
        })
    }

    /// OT `Initiator::ProcessEnhAckIeData`: the Link Metrics IE data of an
    /// Enhanced ACK from neighbor `ext` (the MAC reports it as
    /// `Event::EnhAckLinkMetrics`); decoded with the metrics configured for
    /// it and passed to [`MleEnv::enh_ack_probing_report`].
    pub fn process_enh_ack_ie_data<E: MleEnv>(
        &mut self,
        env: &mut E,
        ext: &ExtAddress,
        data: &[u8],
    ) {
        let Some(r) = self.find_neighbor(ext, false) else {
            return;
        };
        let n = self.neighbor_mut(r);
        let (rloc16, ext, cfg) = (n.rloc16, n.ext_address, n.enh_ack_probing);
        let v = parse_enh_ack_ie_data(&cfg, data);
        env.enh_ack_probing_report(rloc16, &ext, &v);
    }

    /// A Link Metrics Report TLV arrived in a Data Response (OT
    /// `Initiator::HandleReport`).
    pub(crate) fn handle_link_metrics_report<E: MleEnv>(&mut self, env: &mut E, rx: &MleRx<'_>) {
        let Ok(sub) = rx.tlvs.link_metrics_report() else {
            return;
        };
        match parse_report(sub.as_bytes()) {
            Ok(Report::Status(s)) => {
                if let Some(s) = Status::from_u8(s) {
                    env.link_metrics_report(&rx.meta.src, None, s);
                }
            }
            Ok(Report::Values(v)) => {
                env.link_metrics_report(&rx.meta.src, Some(&v), Status::Success);
            }
            Err(_) => {}
        }
    }

    /// OT `HandleLinkMetricsManagementResponse`.
    pub(crate) fn handle_link_metrics_management_response<E: MleEnv>(
        &mut self,
        env: &mut E,
        rx: &MleRx<'_>,
        nb: Option<NbRef>,
    ) -> Result<RxClass> {
        if !self.neighbor_is_valid(nb) {
            return Err(Error::InvalidState);
        }
        let sub = rx.tlvs.link_metrics_management()?;
        let status = parse_management_response(sub.as_bytes())?;
        if let Some(s) = Status::from_u8(status) {
            env.link_metrics_management_response(&rx.meta.src, s);
        }
        Ok(RxClass::Peer)
    }

    // ------------------------------------------------------------ subject

    /// OT `Subject::ConfigureEnhAckProbing`.
    fn configure_enh_ack_probing<E: MleEnv>(
        env: &mut E,
        flags: u8,
        m: &Metrics,
        rloc16: Rloc16,
        ext: &ExtAddress,
    ) -> Status {
        if m.reserved {
            return Status::OtherError;
        }
        if flags == EnhAckFlags::Register as u8 {
            if m.pdu_count
                || !(m.lqi || m.link_margin || m.rssi)
                || (m.lqi && m.link_margin && m.rssi)
            {
                return Status::OtherError;
            }
        } else if flags == EnhAckFlags::Clear as u8 {
            if m.lqi || m.link_margin || m.rssi {
                return Status::OtherError;
            }
        } else {
            return Status::OtherError;
        }
        match env.configure_enh_ack_probing(m.enh_ack_flags(), rloc16, ext) {
            Ok(()) => Status::Success,
            Err(_) => Status::OtherError,
        }
    }

    /// OT `HandleLinkMetricsManagementRequest` +
    /// `Subject::HandleManagementRequest`.
    pub(crate) fn handle_link_metrics_management_request<E: MleEnv>(
        &mut self,
        env: &mut E,
        rx: &MleRx<'_>,
        nb: Option<NbRef>,
    ) -> Result<RxClass> {
        if !self.neighbor_is_valid(nb) {
            return Err(Error::InvalidState);
        }
        let r = nb.ok_or(Error::InvalidState)?;
        let sub = rx.tlvs.link_metrics_management()?;
        let req = parse_management_request(sub.as_bytes())?;
        let (ext, rloc16) = {
            let n = self.neighbor_mut(r);
            (n.ext_address, n.rloc16)
        };
        let status = match req {
            ManagementRequest::Empty => Status::OtherError,
            ManagementRequest::ForwardTracking {
                series_id,
                flags_mask,
                metrics,
            } => self
                .link_metrics
                .configure(&ext, series_id, flags_mask, metrics),
            ManagementRequest::EnhAck { flags, metrics } => {
                Self::configure_enh_ack_probing(env, flags, &metrics, rloc16, &ext)
            }
        };
        let mut sub = [0u8; 4];
        let n = write_status(&mut sub, status)?;
        self.send(
            env,
            rx.meta.src,
            Command::LinkMetricsManagementResponse,
            |w| w.link_metrics_management(&sub[..n]),
        )?;
        Ok(RxClass::Peer)
    }

    /// OT `HandleLinkProbe`: count the probe in the neighbor's series.
    pub(crate) fn handle_link_probe(
        &mut self,
        rx: &MleRx<'_>,
        nb: Option<NbRef>,
    ) -> Result<RxClass> {
        if !self.neighbor_is_valid(nb) {
            return Err(Error::InvalidState);
        }
        let r = nb.ok_or(Error::InvalidState)?;
        let (series_id, _) = rx.tlvs.link_probe()?;
        let ext = self.neighbor_mut(r).ext_address;
        self.link_metrics.aggregate(
            &ext,
            series_id,
            FrameKind::LinkProbe,
            rx.meta.link.lqi.unwrap_or(0),
            rx.meta
                .link
                .rss
                .unwrap_or(crate::link_quality::INVALID_RSSI),
        );
        Ok(RxClass::Peer)
    }

    /// OT `Neighbor::AggregateLinkMetrics` for MAC frames: a frame of `kind`
    /// from neighbor `ext` was received with `lqi` / `rss`. The MAC glue
    /// calls this for data, data request and ACK frames.
    pub fn aggregate_link_metrics(&mut self, ext: &ExtAddress, kind: FrameKind, lqi: u8, rss: i8) {
        self.link_metrics.aggregate(ext, 0, kind, lqi, rss);
    }

    /// The Forward Tracking Series registered by neighbors.
    pub fn link_metrics_series(&self) -> &SeriesTable<MAX_SERIES> {
        &self.link_metrics
    }
}
