//! MLE Discovery content and the active scanner (Thread 1.4.1 section
//! 4.13 / 8.4.3, OT `thread/discover_scanner.cpp`, `Mle::SendDiscoveryResponse`).
//!
//! - [`build_request_tlv`] / [`build_response_tlv`]: the value of the Thread
//!   Discovery TLV that [`Mle::send_discovery_request`] carries and that
//!   [`MleEnv::discovery_response`](opentrust_mle::env::MleEnv::discovery_response)
//!   returns.
//! - [`parse_response`]: a Discovery Response into a [`ScanResult`], with the
//!   Steering Data filter of OT `DiscoverScanner::HandleDiscoveryResponse`.
//! - [`DiscoverScanner`]: the per-channel state machine (one Discovery
//!   Request per channel, 300 ms of listening each). The caller sends the
//!   requests (`Mle::send_discovery_request` on the given channel) and
//!   feeds responses from
//!   [`MleEnv::discovery_response_received`](opentrust_mle::env::MleEnv::discovery_response_received).
//!
//! [`Mle::send_discovery_request`]: opentrust_mle::Mle::send_discovery_request

use heapless::Vec;
use opentrust_core::bytes::Writer;
use opentrust_core::time::{Duration, Instant};
use opentrust_core::types::{ExtAddress, ExtPanId, NetworkName};
use opentrust_core::{Error, Result};
use opentrust_mle::consts::THREAD_VERSION;
use opentrust_mle::env::DiscoveryResponseInfo;

use crate::steering::{HashBitIndexes, SteeringData};
use crate::tlv::{
    CHANNEL_MAX, CHANNEL_MIN, DiscoveryRequest, DiscoveryResponse, PAGE0_CHANNELS, Tlvs, WriterExt,
};

/// Time spent listening for Discovery Responses on each channel
/// (`Mac::kScanDurationDefault`).
pub const SCAN_DURATION: Duration = Duration::from_millis(300);

/// Discovery Request content (OT `DiscoverScanner::Discover`): the MeshCoP
/// Discovery Request sub-TLV with our Thread version and the Joiner flag.
/// Returns the length written to `out`.
pub fn build_request_tlv(joiner: bool, out: &mut [u8]) -> Result<usize> {
    let mut w = Writer::new(out);
    w.discovery_request(&DiscoveryRequest {
        version: THREAD_VERSION as u8,
        joiner,
    })?;
    Ok(w.written().len())
}

/// What a router puts into a Discovery Response (OT
/// `Mle::SendDiscoveryResponse`).
#[derive(Debug, Clone)]
pub struct ResponseContent<'a> {
    /// Extended PAN ID of the network.
    pub ext_pan_id: &'a ExtPanId,
    /// Network Name.
    pub network_name: &'a NetworkName,
    /// Steering Data from the Commissioning Data; `None` or empty: a
    /// single zero byte is sent.
    pub steering_data: Option<&'a SteeringData>,
    /// Joiner UDP Port of the Joiner Router (OT default 1000).
    pub joiner_udp_port: u16,
    /// The Security Policy allows native commissioning and a Border Agent
    /// listens on `commissioner_udp_port`.
    pub native_commissioner: Option<u16>,
    /// The Security Policy enables commercial commissioning.
    pub commercial_commissioning: bool,
    /// Thread Domain Name, if not the default.
    pub domain_name: Option<&'a str>,
}

/// Default Joiner UDP port (`OPENTHREAD_CONFIG_JOINER_UDP_PORT`).
pub const DEFAULT_JOINER_UDP_PORT: u16 = 1000;

/// Build the Thread Discovery TLV value of a Discovery Response. Returns
/// the length written to `out`.
pub fn build_response_tlv(c: &ResponseContent<'_>, out: &mut [u8]) -> Result<usize> {
    let mut w = Writer::new(out);
    if let Some(port) = c.native_commissioner {
        w.commissioner_udp_port(port)?;
    }
    w.discovery_response(&DiscoveryResponse {
        version: THREAD_VERSION as u8,
        native_commissioner: c.native_commissioner.is_some(),
        commercial_commissioning: c.commercial_commissioning,
    })?;
    w.ext_pan_id(c.ext_pan_id)?;
    w.network_name(c.network_name)?;
    match c.steering_data {
        Some(s) if !s.is_zero_length() => w.steering_data(s)?,
        _ => w.steering_data(&SteeringData::new(1))?,
    }
    w.joiner_udp_port(c.joiner_udp_port)?;
    if let Some(d) = c.domain_name {
        w.thread_domain_name(d)?;
    }
    Ok(w.written().len())
}

/// Does the Commissioning Data carry non-empty Steering Data (OT
/// `Leader::IsJoiningAllowed`)?
pub fn joining_allowed(commissioning_data: Option<&[u8]>) -> bool {
    commissioning_data
        .and_then(|c| Tlvs(c).steering_data().ok())
        .is_some_and(|s| !s.is_empty())
}

/// The Discovery Response content of a router with `dataset` as Active
/// Dataset and `commissioning_data` (the Commissioning Data TLV value of
/// the Network Data): Extended PAN ID and Network Name from the dataset,
/// Steering Data and Joiner UDP Port from the Commissioning Data, a
/// Border Agent is not assumed (no native commissioner). Returns the
/// length written to `out`.
pub fn build_response_from_dataset(
    dataset: &crate::dataset::Dataset,
    commissioning_data: Option<&[u8]>,
    out: &mut [u8],
) -> Result<usize> {
    build_response_with_border_agent(dataset, commissioning_data, None, out)
}

/// [`build_response_from_dataset`] for a device running a Border Agent on
/// `border_agent_port`: if the Security Policy enables native
/// commissioning, the response carries the Commissioner UDP Port and the
/// native commissioner flag (OT `Mle::SendDiscoveryResponse`).
pub fn build_response_with_border_agent(
    dataset: &crate::dataset::Dataset,
    commissioning_data: Option<&[u8]>,
    border_agent_port: Option<u16>,
    out: &mut [u8],
) -> Result<usize> {
    let t = dataset.tlvs();
    let ext_pan_id = t.ext_pan_id()?;
    let network_name = t.network_name()?;
    let policy = t.security_policy().unwrap_or_default();
    let cd = commissioning_data.map(Tlvs);
    let steering = cd.as_ref().and_then(|c| c.steering_data().ok());
    let port = cd
        .as_ref()
        .and_then(|c| c.joiner_udp_port().ok())
        .unwrap_or(DEFAULT_JOINER_UDP_PORT);
    build_response_tlv(
        &ResponseContent {
            ext_pan_id: &ext_pan_id,
            network_name: &network_name,
            steering_data: steering.as_ref(),
            joiner_udp_port: port,
            native_commissioner: border_agent_port.filter(|_| policy.native_commissioning),
            commercial_commissioning: policy.commercial_commissioning,
            domain_name: None,
        },
        out,
    )
}

/// A discovered Thread network (OT `otActiveScanResult` with
/// `mDiscover`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanResult {
    /// Extended address of the responding router.
    pub ext_address: ExtAddress,
    /// PAN ID of the network.
    pub pan_id: u16,
    /// Channel it was heard on.
    pub channel: u8,
    /// RSS in dBm.
    pub rssi: i8,
    /// LQI.
    pub lqi: u8,
    /// Thread version of the responder.
    pub version: u8,
    /// A native commissioner is available.
    pub is_native: bool,
    /// Extended PAN ID.
    pub ext_pan_id: Option<ExtPanId>,
    /// Network Name.
    pub network_name: Option<NetworkName>,
    /// Steering Data, if sent and non-empty.
    pub steering_data: Option<SteeringData>,
    /// Joiner UDP port.
    pub joiner_udp_port: Option<u16>,
}

/// Parse a Discovery Response (OT `HandleDiscoveryResponse`). With
/// `filter`, the response must carry Steering Data that contains the
/// indexes, otherwise it is dropped ([`Error::NotFound`]).
pub fn parse_response(
    info: &DiscoveryResponseInfo,
    tlvs: &[u8],
    filter: Option<&HashBitIndexes>,
) -> Result<ScanResult> {
    let mut r = ScanResult {
        ext_address: info.ext_address,
        pan_id: info.pan_id.unwrap_or(0xffff),
        channel: info.channel.unwrap_or(0),
        rssi: info.rss.unwrap_or(127),
        lqi: info.lqi.unwrap_or(0),
        version: 0,
        is_native: false,
        ext_pan_id: None,
        network_name: None,
        steering_data: None,
        joiner_udp_port: None,
    };
    let t = Tlvs(tlvs);
    let mut checked_steering = false;
    for tl in t.iter() {
        let tl = tl?;
        if tl.is_extended() {
            continue;
        }
        match tl.ty() {
            crate::tlv::ty::DISCOVERY_RESPONSE => {
                let d = DiscoveryResponse::from_bytes(tl.value())?;
                r.version = d.version;
                r.is_native = d.native_commissioner;
            }
            crate::tlv::ty::EXT_PAN_ID => r.ext_pan_id = Some(ExtPanId(tl.read_array()?)),
            crate::tlv::ty::NETWORK_NAME => {
                r.network_name =
                    Some(NetworkName::from_bytes(tl.value()).map_err(|_| Error::Parse)?)
            }
            crate::tlv::ty::STEERING_DATA if !tl.value().is_empty() => {
                let s = SteeringData::from_slice(tl.value());
                if let Some(f) = filter
                    && !s.contains_indexes(f)
                {
                    return Err(Error::NotFound);
                }
                checked_steering = true;
                r.steering_data = Some(s);
            }
            crate::tlv::ty::JOINER_UDP_PORT => r.joiner_udp_port = Some(tl.read_u16()?),
            _ => {}
        }
    }
    if filter.is_some() && !checked_steering {
        return Err(Error::NotFound);
    }
    Ok(r)
}

/// State of a scan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Idle,
    /// Send the request for `channel` at the next poll.
    Request,
    /// Listening for `channel` until the deadline.
    Listening,
    /// All channels done, report at the next poll.
    Done,
}

/// What the scanner needs done.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanStep {
    /// Send a Discovery Request on `channel` to PAN ID `pan_id`
    /// ([`Mle::send_discovery_request`](opentrust_mle::Mle::send_discovery_request)).
    Request {
        /// Channel.
        channel: u8,
        /// Destination PAN ID.
        pan_id: u16,
        /// The Joiner flag of the request.
        joiner: bool,
    },
    /// The scan is over (OT invokes the callback with a null result).
    Done,
}

/// Active Discovery scanner (OT `Mle::DiscoverScanner`).
#[derive(Debug, Clone)]
pub struct DiscoverScanner {
    state: State,
    channels: u32,
    channel: u8,
    pan_id: u16,
    joiner: bool,
    filter: Option<HashBitIndexes>,
    deadline: Option<Instant>,
}

impl Default for DiscoverScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl DiscoverScanner {
    /// Idle scanner.
    pub const fn new() -> Self {
        Self {
            state: State::Idle,
            channels: 0,
            channel: 0,
            pan_id: 0xffff,
            joiner: false,
            filter: None,
            deadline: None,
        }
    }

    /// A scan is running.
    pub fn is_scanning(&self) -> bool {
        self.state != State::Idle
    }

    /// Start a scan of the channels in `scan_channels` (bit `n` = channel
    /// `n`; `0` = all 2.4 GHz channels) intersected with `supported`.
    /// `pan_id` is the PAN ID to look for (`0xffff`: any). With `filter` only
    /// networks whose Steering Data contains it are reported (a Joiner
    /// passes `HashBitIndexes::of_joiner_id`). [`Error::Busy`] if a scan is
    /// running.
    pub fn start(
        &mut self,
        supported: u32,
        scan_channels: u32,
        pan_id: u16,
        joiner: bool,
        filter: Option<HashBitIndexes>,
    ) -> Result<()> {
        if self.state != State::Idle {
            return Err(Error::Busy);
        }
        let mut mask = supported & PAGE0_CHANNELS;
        if scan_channels != 0 {
            mask &= scan_channels;
        }
        self.channels = mask;
        self.pan_id = pan_id;
        self.joiner = joiner;
        self.filter = filter;
        self.deadline = None;
        match next_channel(mask, None) {
            Some(c) => {
                self.channel = c;
                self.state = State::Request;
            }
            None => self.state = State::Done,
        }
        Ok(())
    }

    /// Next step if one is due.
    pub fn poll(&mut self, now: Instant) -> Option<ScanStep> {
        match self.state {
            State::Idle => None,
            State::Request => {
                self.state = State::Listening;
                self.deadline = Some(now.saturating_add(SCAN_DURATION));
                Some(ScanStep::Request {
                    channel: self.channel,
                    pan_id: self.pan_id,
                    joiner: self.joiner,
                })
            }
            State::Listening => {
                if self.deadline.is_some_and(|d| d > now) {
                    return None;
                }
                self.deadline = None;
                match next_channel(self.channels, Some(self.channel)) {
                    Some(c) => {
                        self.channel = c;
                        self.state = State::Request;
                        self.poll(now)
                    }
                    None => {
                        self.state = State::Idle;
                        Some(ScanStep::Done)
                    }
                }
            }
            State::Done => {
                self.state = State::Idle;
                Some(ScanStep::Done)
            }
        }
    }

    /// When [`poll`](Self::poll) next has work.
    pub fn next_deadline(&self) -> Option<Instant> {
        self.deadline
    }

    /// A Discovery Response arrived. `None` if no scan is running, the
    /// response is malformed or fails the Steering Data filter.
    pub fn handle_response(&self, info: &DiscoveryResponseInfo, tlvs: &[u8]) -> Option<ScanResult> {
        if self.state != State::Listening {
            return None;
        }
        parse_response(info, tlvs, self.filter.as_ref()).ok()
    }
}

/// The next channel of `mask` after `after` (or the first).
fn next_channel(mask: u32, after: Option<u8>) -> Option<u8> {
    let start = after.map_or(CHANNEL_MIN, |c| c + 1);
    (start..=CHANNEL_MAX).find(|&c| mask & (1 << c) != 0)
}

/// Collect scan results of a whole scan.
pub type ScanResults<const N: usize> = Vec<ScanResult, N>;
