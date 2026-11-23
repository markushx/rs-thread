//! Types crossing the MAC core's boundaries: upper-layer requests and
//! events, radio actions and their completions.

use opentrust_core::Result;
use opentrust_core::time::{Duration, Instant};
use opentrust_core::types::{ExtAddress, PanId};
#[cfg(feature = "csl")]
use opentrust_platform::radio::CslConfig;
use opentrust_platform::radio::{
    Config, MacKeys, PsduRxInfo, PsduTxInfo, RadioErrorKind, SrcMatchConfig, sim::MAX_PSDU_LEN,
};

#[cfg(feature = "link-metrics")]
use super::link_metrics::EnhAckProbingValues;
#[cfg(feature = "csl")]
use crate::frame::CslIe;
use crate::frame::{Address, FCS_LEN, Frame, ThreadBeaconPayload};
use crate::frame_security::RxSecurityInfo;

/// Maximum MAC frame length without FCS (`aMaxPHYPacketSize` - 2).
pub const MAX_FRAME_LEN: usize = MAX_PSDU_LEN - FCS_LEN;

/// A radio PSDU: the MAC frame **plus** its 2-byte FCS, as exchanged with
/// [`Radio::transmit`](opentrust_platform::Radio::transmit) and
/// [`Radio::receive`](opentrust_platform::Radio::receive) (OpenThread
/// `mPsdu`/`mLength` convention: the radio fills in / checks the FCS).
pub type Psdu = heapless::Vec<u8, MAX_PSDU_LEN>;

/// A MAC frame without FCS (the [`crate::frame`] convention).
pub type FrameBuf = heapless::Vec<u8, MAX_FRAME_LEN>;

/// Opaque tag chosen by the upper layer to match a transmit request with
/// its [`Event::TxDone`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct TxHandle(pub u16);

/// Why a transmission failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum TxError {
    /// No ACK after all retries (OpenThread `kErrorNoAck`).
    NoAck,
    /// CCA failed on every CSMA-CA attempt (`kErrorChannelAccessFailure`).
    ChannelAccessFailure,
    /// The transmission was aborted (purged, radio refused the frame, or the
    /// driver was cancelled mid-transmit) (`kErrorAbort`).
    Abort,
    /// Securing the frame failed (no key, bad frame).
    Security,
}

/// A successful transmission.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct TxSuccess {
    /// Frame Pending bit of the ACK (`false` without ACK).
    pub frame_pending: bool,
    /// Number of retransmissions done by the MAC (0 if the radio retries).
    pub retries: u8,
}

/// Result of a transmission.
pub type TxResult = core::result::Result<TxSuccess, TxError>;

/// A received data frame, already filtered and unsecured.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct RxFrame {
    /// The frame without FCS; the payload is plaintext if the frame was
    /// secured (the MIC is still present).
    pub frame: FrameBuf,
    /// Channel the frame was received on.
    pub channel: u8,
    /// RSSI in dBm, if reported by the radio.
    pub rssi: Option<i8>,
    /// LQI, if reported by the radio.
    pub lqi: Option<u8>,
    /// Radio timestamp of the frame (see [`PsduRxInfo::timestamp_us`]).
    pub timestamp_us: Option<u64>,
    /// Security parameters if the frame was secured. Replay checking against
    /// the neighbor's frame counter is the upper layer's job.
    pub security: Option<RxSecurityInfo>,
    /// Whether the ACK sent for this frame had Frame Pending set.
    pub acked_with_frame_pending: bool,
    /// Delivered unfiltered and unprocessed because promiscuous mode is on.
    pub promiscuous: bool,
}

impl RxFrame {
    /// Parsed view of the frame.
    pub fn parse(&self) -> Result<Frame<'_>> {
        Frame::parse(&self.frame)
    }
}

/// A beacon heard during an active scan (OpenThread `ActiveScanResult`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct ScanResult {
    /// Scan channel.
    pub channel: u8,
    /// RSSI of the beacon, if reported.
    pub rssi: Option<i8>,
    /// LQI of the beacon, if reported.
    pub lqi: Option<u8>,
    /// Extended source address of the beacon sender.
    pub ext_addr: ExtAddress,
    /// PAN ID of the sender.
    pub pan_id: PanId,
    /// Thread beacon payload, if the beacon carried a valid one.
    pub thread: Option<ThreadBeaconPayload>,
}

/// Events from the MAC to the upper layer.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Event {
    /// A direct or indirect transmission requested with this handle finished.
    TxDone {
        /// The handle given with the request.
        handle: TxHandle,
        /// Outcome.
        result: TxResult,
    },
    /// A data frame was received.
    Received(RxFrame),
    /// A data poll (MAC Data Request) was sent (sleepy child).
    DataPollSent(TxResult),
    /// The poll's ACK announced pending data, but none arrived within
    /// [`DATA_POLL_TIMEOUT`](super::DATA_POLL_TIMEOUT).
    DataPollTimeout,
    /// A data poll from a child was received (parent). Indirect frames for
    /// it are served by the MAC; this is for child supervision in MLE.
    DataPollReceived {
        /// Source address of the poll.
        src: Address,
        /// Whether its ACK had Frame Pending set.
        frame_pending: bool,
        /// The CSL IE of the poll (a secured 2015 frame) and the radio
        /// timestamp of the frame, for a child that has not been tracked
        /// as a CSL child yet ([`Mac::csl_child_sample`](super::Mac::csl_child_sample)).
        #[cfg(feature = "csl")]
        csl: Option<(CslIe, Option<u64>)>,
        /// The poll was link-secured (and verified).
        secured: bool,
        /// LQI of the poll, if the radio reported it.
        lqi: Option<u8>,
        /// RSSI of the poll in dBm, if the radio reported it.
        rssi: Option<i8>,
    },
    /// A beacon was received during an active scan.
    ActiveScanResult(ScanResult),
    /// The active scan finished.
    ActiveScanDone,
    /// Energy scan result for one channel.
    EnergyScanResult {
        /// Channel.
        channel: u8,
        /// Maximum RSSI in dBm.
        max_rssi: i8,
    },
    /// The energy scan finished.
    EnergyScanDone,
    /// CSL transmissions to this child failed too often without an ACK: it
    /// is no longer CSL synchronized (queued frames wait for its data poll).
    #[cfg(feature = "csl")]
    CslChildOutOfSync(Address),
    /// An enhanced ACK from a neighbor tracked with
    /// [`Mac::track_enh_ack_probing`](super::Mac::track_enh_ack_probing)
    /// carried link metrics of the frame it acknowledged.
    #[cfg(feature = "link-metrics")]
    EnhAckLinkMetrics {
        /// The neighbor (the acked frame's destination).
        neighbor: Address,
        /// The reported values.
        values: EnhAckProbingValues,
    },
}

/// Upper-layer requests, for facades that pass requests through a queue
/// (see [`Mac::submit`](super::Mac::submit)). Each maps to a `Mac` method.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Request {
    /// [`Mac::transmit`](super::Mac::transmit).
    Transmit {
        /// Completion handle.
        handle: TxHandle,
        /// Frame without FCS.
        frame: FrameBuf,
    },
    /// [`Mac::transmit_indirect`](super::Mac::transmit_indirect).
    TransmitIndirect {
        /// Completion handle.
        handle: TxHandle,
        /// The sleepy child.
        dst: Address,
        /// Frame without FCS.
        frame: FrameBuf,
    },
    /// [`Mac::purge_indirect`](super::Mac::purge_indirect).
    PurgeIndirect(Address),
    /// [`Mac::send_data_poll`](super::Mac::send_data_poll).
    DataPoll,
    /// [`Mac::active_scan`](super::Mac::active_scan).
    ActiveScan {
        /// Channel mask (bit n = channel n); 0 means all supported channels.
        channels: u32,
        /// Time to listen on each channel.
        duration: Duration,
    },
    /// [`Mac::energy_scan`](super::Mac::energy_scan).
    EnergyScan {
        /// Channel mask; 0 means all supported channels.
        channels: u32,
        /// Duration per channel.
        duration: Duration,
    },
}

/// A frame for [`Radio::transmit`](opentrust_platform::Radio::transmit).
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct TxAction {
    /// PSDU including the (software computed) FCS.
    pub psdu: Psdu,
    /// What is already done to the frame and what the radio may do.
    pub info: PsduTxInfo,
    /// Channel.
    pub channel: u8,
    /// Transmit power in dBm.
    pub power: i8,
    /// CCA threshold, `None` for no CCA (ACKs, `max_csma_backoffs == 0`).
    pub cca_threshold: Option<i8>,
    /// Pass an ACK buffer: the frame requests an ACK and the radio matches
    /// ACKs itself (`MacCapabilities::TX_ACK`).
    pub wait_ack: bool,
    /// Abort the transmit (drop the future, contract C5) and report
    /// [`TxOutcome::AckTimeout`] if it has not completed by then. Set when
    /// the radio waits for the ACK but does not time out by itself.
    pub abort_at: Option<Instant>,
}

/// A command for the radio, produced by [`Mac::poll_action`](super::Mac::poll_action).
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum RadioAction {
    /// [`Radio::set_config`](opentrust_platform::Radio::set_config).
    Configure(Config),
    /// [`Radio::set_src_match_config`](opentrust_platform::Radio::set_src_match_config)
    /// (only for radios with `MacCapabilities::SRC_MATCH`).
    SetSrcMatch(SrcMatchConfig),
    /// [`Radio::set_mac_keys`](opentrust_platform::Radio::set_mac_keys)
    /// (radios that secure frames / enhanced ACKs themselves).
    SetMacKeys(Option<MacKeys>),
    /// [`Radio::set_mac_frame_counter`](opentrust_platform::Radio::set_mac_frame_counter).
    SetMacFrameCounter {
        /// The counter.
        frame_counter: u32,
        /// Only raise the radio's counter.
        if_larger: bool,
    },
    /// [`Radio::set_csl`](opentrust_platform::Radio::set_csl) (radios with
    /// `Capabilities::RECEIVE_TIMING`): the CSL schedule for their enhanced
    /// ACKs; sent again before every sample window.
    #[cfg(feature = "csl")]
    SetCsl(CslConfig),
    /// [`Radio::set_receive_at`](opentrust_platform::Radio::set_receive_at):
    /// one CSL sample window (radios with `Capabilities::RECEIVE_TIMING`).
    #[cfg(feature = "csl")]
    ReceiveAt {
        /// Channel.
        channel: u8,
        /// Window start, radio clock in microseconds.
        start_us: u64,
        /// Window duration in microseconds.
        duration_us: u32,
    },
    /// [`Radio::set_receive`](opentrust_platform::Radio::set_receive).
    Receive {
        /// Channel.
        channel: u8,
    },
    /// [`Radio::set_sleep`](opentrust_platform::Radio::set_sleep).
    Sleep,
    /// [`Radio::transmit`](opentrust_platform::Radio::transmit); complete
    /// with [`Mac::on_tx_done`](super::Mac::on_tx_done).
    Transmit(TxAction),
    /// [`Radio::energy_scan`](opentrust_platform::Radio::energy_scan);
    /// complete with [`Mac::on_energy_scan_done`](super::Mac::on_energy_scan_done).
    EnergyScan {
        /// Channel.
        channel: u8,
        /// Duration in milliseconds.
        duration_ms: u16,
    },
}

/// Completion of a [`RadioAction::Transmit`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TxOutcome<'a> {
    /// `transmit` returned `Ok(None)`: sent, no ACK reported by the radio.
    Sent,
    /// `transmit` returned the ACK: its PSDU (with FCS) and meta-data.
    Acked {
        /// The ACK PSDU including FCS.
        ack: &'a [u8],
        /// The ACK's receive info.
        info: PsduRxInfo,
    },
    /// `transmit` failed.
    Failed(RadioErrorKind),
    /// The driver aborted the transmit at [`TxAction::abort_at`].
    AckTimeout,
    /// The transmit was cancelled for another reason (e.g. the driver future
    /// was dropped).
    Aborted,
}

/// MAC counters (subset of OpenThread `otMacCounters`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct MacCounters {
    /// Frame transmission attempts (including retries and ACKs sent in software).
    pub tx_attempts: u32,
    /// Completed frame transmissions (excluding software ACKs).
    pub tx_total: u32,
    /// Transmissions that requested an ACK.
    pub tx_ack_requested: u32,
    /// Transmissions that were acknowledged.
    pub tx_acked: u32,
    /// Data frames sent (direct and indirect).
    pub tx_data: u32,
    /// Data polls sent.
    pub tx_data_poll: u32,
    /// Beacons sent.
    pub tx_beacon: u32,
    /// Beacon requests sent.
    pub tx_beacon_request: u32,
    /// Retransmissions.
    pub tx_retry: u32,
    /// ACKs generated in software.
    pub tx_soft_ack: u32,
    /// CCA failures.
    pub tx_err_cca: u32,
    /// Aborted transmissions.
    pub tx_err_abort: u32,
    /// Direct frames that failed after all retries.
    pub tx_direct_max_retry_expiry: u32,
    /// Indirect frames that failed after all poll attempts.
    pub tx_indirect_max_retry_expiry: u32,
    /// Frames handed to the MAC by the radio.
    pub rx_total: u32,
    /// Data frames delivered.
    pub rx_data: u32,
    /// Data polls received.
    pub rx_data_poll: u32,
    /// Beacons received.
    pub rx_beacon: u32,
    /// Beacon requests received.
    pub rx_beacon_request: u32,
    /// Frames dropped as uninteresting (wrong type, off-channel during scan, ...).
    pub rx_other: u32,
    /// Frames that failed to parse.
    pub rx_err_no_frame: u32,
    /// Frames dropped by destination PAN / address filtering.
    pub rx_dest_addr_filtered: u32,
    /// Frames from our own extended address.
    pub rx_err_invalid_src_addr: u32,
    /// Secured frames from a short address with no known extended address.
    pub rx_err_unknown_neighbor: u32,
    /// Frames that failed security processing.
    pub rx_err_sec: u32,
    /// Frames dropped because the event queue was full.
    pub rx_err_queue_full: u32,
    /// Unexpected or unmatched ACKs.
    pub rx_ack_unmatched: u32,
}
