//! MLE protocol constants (Thread 1.4.1 Table 4-3, §4.12) and OpenThread
//! defaults that the specification leaves open.
//!
//! Durations are [`Duration`]; jitter factors ("x random 0.9-1.1") are
//! applied by the caller.

use opentrust_core::time::Duration;

/// UDP port used by MLE (Thread 1.4.1 §4.3; OT `kUdpPort`).
pub const MLE_UDP_PORT: u16 = 19788;
/// IPv6 hop limit of every MLE message; received messages with another
/// value are dropped (§4.3).
pub const MLE_HOP_LIMIT: u8 = 255;

/// `FAILED_CHILD_TRANSMISSIONS`: consecutive no-ACK transmissions after
/// which a child is considered lost.
pub const FAILED_CHILD_TRANSMISSIONS: u8 = 4;
/// `MLE_MAX_EXTRA_LINK_PROBABILITY` (percent).
pub const MAX_EXTRA_LINK_PROBABILITY: u8 = 10;
/// `MLE_UNICAST_RETRANSMISSION_DELAY` (x random 0.9..1.1).
pub const UNICAST_RETRANSMISSION_DELAY: Duration = Duration::from_secs(1);
/// `MLE_MULTICAST_RETRANSMISSION_DELAY` (x random 0.9..1.1).
pub const MULTICAST_RETRANSMISSION_DELAY: Duration = Duration::from_secs(5);
/// `MLE_MAX_TRANSMISSION_COUNT`.
pub const MAX_TRANSMISSION_COUNT: u8 = 3;
/// `MLE_MAX_CRITICAL_TRANSMISSION_COUNT`.
pub const MAX_CRITICAL_TRANSMISSION_COUNT: u8 = 6;
/// `MLE_MAX_LINK_REQ_DELAY_CHILD`.
pub const MAX_LINK_REQ_DELAY_CHILD: Duration = Duration::from_secs(3);
/// `MLE_MAX_RESPONSE_DELAY`.
pub const MAX_RESPONSE_DELAY: Duration = Duration::from_secs(1);
/// `MLE_MAX_REACTION_TIME`.
pub const MAX_REACTION_TIME: Duration = Duration::from_secs(1);
/// `MLE_MIN_LINK_REQ_DELAY_CHILD` (1.5 s).
pub const MIN_LINK_REQ_DELAY_CHILD: Duration = Duration::from_millis(1500);
/// `MLE_END_DEVICE_TIMEOUT` (default child timeout), seconds.
pub const END_DEVICE_TIMEOUT_SECS: u32 = 240;
/// `MLE_NEW_PARENT_RSSI_MARGIN` (dB).
pub const NEW_PARENT_RSSI_MARGIN: u8 = 7;
/// `MLE_MIN_NEW_PARENT_WAIT_TIME` (480 s).
pub const MIN_NEW_PARENT_WAIT_TIME: Duration = Duration::from_secs(480);
/// `MLE_PARENT_REQ_SCANMASK_R_TIMEOUT` (0.75 s).
pub const PARENT_REQ_SCANMASK_R_TIMEOUT: Duration = Duration::from_millis(750);
/// `MLE_PARENT_REQ_SCANMASK_RE_TIMEOUT` (1.25 s).
pub const PARENT_REQ_SCANMASK_RE_TIMEOUT: Duration = Duration::from_millis(1250);
/// `MLE_PARENT_RSP_ROUTER_JITTER` (max, 0.5 s).
pub const PARENT_RSP_ROUTER_JITTER: Duration = Duration::from_millis(500);
/// `MLE_PARENT_RSP_REED_JITTER` (max, 1 s).
pub const PARENT_RSP_REED_JITTER: Duration = Duration::from_secs(1);
/// `ANNOUNCE_APPLY_DELAY_THRESHOLD` (60 s).
pub const ANNOUNCE_APPLY_DELAY_THRESHOLD: Duration = Duration::from_secs(60);
/// `ANNOUNCE_TRICKLE_I` (688 s).
pub const ANNOUNCE_TRICKLE_I: Duration = Duration::from_secs(688);
/// `ANNOUNCE_TRICKLE_K`.
pub const ANNOUNCE_TRICKLE_K: u8 = 8;
/// `ANNOUNCE_TRICKLE_JITTER` (max, 500 ms).
pub const ANNOUNCE_TRICKLE_JITTER: Duration = Duration::from_millis(500);

/// Thread protocol version advertised in the Version TLV (1.4 = 5).
pub const THREAD_VERSION: u16 = 5;
/// Thread 1.1 version value (2).
pub const THREAD_VERSION_1_1: u16 = 2;
/// Thread 1.2 version value (3).
pub const THREAD_VERSION_1_2: u16 = 3;
/// Thread 1.3 version value (4).
pub const THREAD_VERSION_1_3: u16 = 4;
/// Thread 1.4 version value (5).
pub const THREAD_VERSION_1_4: u16 = 5;

/// Shortest Challenge/Response value (OT `kMinChallengeSize`).
pub const MIN_CHALLENGE_LEN: usize = 4;
/// Longest Challenge/Response value (OT `kMaxChallengeSize`).
pub const MAX_CHALLENGE_LEN: usize = 8;

/// Maximum route cost; a link/route with this cost is unusable (§5.9,
/// OT `kMaxRouteCost` without long routes).
pub const MAX_ROUTE_COST: u8 = 16;

/// IPv6 addresses a child can register besides its ML-EID (OT
/// `OPENTHREAD_CONFIG_MLE_IP_ADDRS_PER_CHILD` (6) minus one).
pub const CHILD_MAX_ADDRESSES: usize = 5;
/// TLV types remembered from a child's request (OT `Child::kMaxRequestTlvs`).
pub const CHILD_MAX_REQUEST_TLVS: usize = 6;
