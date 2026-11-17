//! MLE protocol constants (Thread 1.4.1 Table 4-3, §4.12) and OpenThread
//! defaults that the specification leaves open.
//!
//! Durations are [`Duration`]; jitter factors ("x random 0.9-1.1") are
//! applied by the caller.

use opentrust_core::time::Duration;

/// UDP port used by MLE (Thread 1.4.1 §4.3; OT `kUdpPort`).
pub use opentrust_net::udp::MLE_UDP_PORT;
/// IPv6 hop limit of every MLE message; received messages with another
/// value are dropped (§4.3).
pub const MLE_HOP_LIMIT: u8 = 255;

/// `FAILED_CHILD_TRANSMISSIONS`: consecutive no-ACK transmissions after
/// which a child is considered lost.
pub const FAILED_CHILD_TRANSMISSIONS: u8 = 4;
/// OT `kFailedRouterTransmissions`: consecutive no-ACK transmissions to a
/// router (a child's parent) after which the link is dropped.
pub const FAILED_ROUTER_TRANSMISSIONS: u8 = 4;
/// OT `kFailedCslDataPollTransmissions`: the same for data polls carrying a
/// CSL IE (they are not retransmitted by the MAC).
pub const FAILED_CSL_DATA_POLL_TRANSMISSIONS: u8 = 15;
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
/// Multicast groups larger than realm-local a child can have registered
/// for Multicast Listener Registration (stored besides the unicast
/// addresses).
pub const CHILD_MAX_MULTICAST_ADDRESSES: usize = 4;
/// TLV types remembered from a child's request (OT `Child::kMaxRequestTlvs`).
pub const CHILD_MAX_REQUEST_TLVS: usize = 6;

// ---------------------------------------------------------------------------
// Router / leader (Thread 1.4.1 Table 5-10 and OpenThread defaults)

/// Router-role Border Routers at which a further `BorderRouterRequest` is
/// turned down (OT `kRouterUpgradeBorderRouterRequestThreshold`).
pub const ROUTER_UPGRADE_BORDER_ROUTER_REQUEST_THRESHOLD: usize = 2;
/// `MAX_ROUTERS`: routers that may be active in one partition.
pub const MAX_ROUTERS: usize = 32;
/// Highest router ID (`MAX_ROUTER_ID`).
pub const MAX_ROUTER_ID: u8 = 62;
/// "No router ID" marker (OT `kInvalidRouterId`).
pub const INVALID_ROUTER_ID: u8 = 63;
/// `ROUTER_UPGRADE_THRESHOLD`: a REED upgrades while fewer routers are active.
pub const ROUTER_UPGRADE_THRESHOLD: u8 = 16;
/// `ROUTER_DOWNGRADE_THRESHOLD`: a router may downgrade above this many routers.
pub const ROUTER_DOWNGRADE_THRESHOLD: u8 = 23;
/// `ROUTER_SELECTION_JITTER` (seconds).
pub const ROUTER_SELECTION_JITTER_SECS: u8 = 120;
/// `NETWORK_ID_TIMEOUT` (seconds without a new ID sequence number).
pub const NETWORK_ID_TIMEOUT_SECS: u8 = 120;
/// `ID_REUSE_DELAY` (seconds a released router ID stays reserved).
pub const ID_REUSE_DELAY_SECS: u8 = 100;
/// `ID_SEQUENCE_PERIOD`: the leader bumps the ID sequence at least this often.
pub const ID_SEQUENCE_PERIOD: Duration = Duration::from_secs(10);
/// `MIN_DOWNGRADE_NEIGHBORS`.
pub const MIN_DOWNGRADE_NEIGHBORS: u8 = 7;
/// Default leader weight (OT `kDefaultLeaderWeight`, `kBaseWeight`).
pub const DEFAULT_LEADER_WEIGHT: u8 = 64;
/// `ADVERTISEMENT_I_MIN`.
pub const ADVERTISEMENT_I_MIN: Duration = Duration::from_secs(1);
/// `ADVERTISEMENT_I_MAX`.
pub const ADVERTISEMENT_I_MAX: Duration = Duration::from_secs(32);
/// `ADVERTISEMENT_I_MAX_LOW`.
pub const ADVERTISEMENT_I_MAX_LOW: Duration = Duration::from_secs(12);
/// Imax per router neighbor (OT `kAdvIntervalNeighborMultiplier`, 4 s).
pub const ADVERTISEMENT_I_MAX_PER_NEIGHBOR: Duration = Duration::from_secs(4);
/// REED advertisement interval (OT `kReedAdvIntervalMin` / `Max`).
pub const REED_ADVERTISEMENT_MIN: Duration = Duration::from_secs(570);
/// See [`REED_ADVERTISEMENT_MIN`].
pub const REED_ADVERTISEMENT_MAX: Duration = Duration::from_secs(630);
/// `MAX_NEIGHBOR_AGE` of a router neighbor.
pub const MAX_NEIGHBOR_AGE: Duration = Duration::from_secs(100);
/// `MAX_EXT_NEIGHBOR_AGE`: neighbor age on an FTD child with many router links.
pub const MAX_NEIGHBOR_AGE_ON_CHILD: Duration = Duration::from_secs(150);
/// Routers that get no route and no Advertisement for this long lose their
/// ID at the leader (OT `kMaxLeaderToRouterTimeout`).
pub const MAX_LEADER_TO_ROUTER_TIMEOUT: Duration = Duration::from_secs(90);
/// Max delay of a Link Request sent after an Advertisement on a router.
pub const MAX_LINK_REQUEST_DELAY_ON_ROUTER: Duration = Duration::from_millis(1000);
/// Link Request delay window on an FTD child (OT `kMin/MaxLinkRequestDelayOnChild`).
pub const MIN_LINK_REQUEST_DELAY_ON_CHILD: Duration = Duration::from_millis(1500);
/// See [`MIN_LINK_REQUEST_DELAY_ON_CHILD`].
pub const MAX_LINK_REQUEST_DELAY_ON_CHILD: Duration = Duration::from_millis(3000);
/// Max delay of a Link Accept answering a multicast Link Request.
pub const MAX_LINK_ACCEPT_DELAY: Duration = Duration::from_millis(1000);
/// Max delay of a unicast Advertisement (OT `kMaxUnicastAdvertisementDelay`).
pub const MAX_UNICAST_ADVERTISEMENT_DELAY: Duration = Duration::from_millis(1000);
/// Max delay of a Data Request after an Advertisement (`MLE_MAX_RESPONSE_DELAY`).
pub const MAX_DATA_REQUEST_DELAY: Duration = MAX_RESPONSE_DELAY;
/// Seconds to wait for a Link Accept (OT `kLinkAcceptTimeout`).
pub const LINK_ACCEPT_TIMEOUT_SECS: u8 = 3;
/// Link Request attempts to a silent neighbor (OT `kMaxLinkRequestAttempts`).
pub const MAX_LINK_REQUEST_ATTEMPTS: u8 = 3;
/// Time to wait for the Link Accept of the final restore Link Request.
pub const LINK_REQUEST_TIMEOUT: Duration = Duration::from_millis(2000);
/// Router role restore: children that make the attempt critical (OT
/// `kMinCriticalChildrenCount`).
pub const MIN_CRITICAL_CHILDREN_COUNT: usize = 6;
/// Minimum link margin (dB) to send a Link Request on an Advertisement.
pub const LINK_REQUEST_MIN_MARGIN: u8 = 10;
/// Minimum link margin (dB) to react to an Advertisement of another partition.
pub const PARTITION_MERGE_MIN_MARGIN: u8 = 10;
/// Quick router links of an FTD child (OT `OPENTHREAD_CONFIG_MLE_CHILD_ROUTER_LINKS`).
pub const CHILD_ROUTER_LINKS: u8 = 3;
/// Additional, slowly established router links of an FTD child.
pub const EXTRA_CHILD_ROUTER_LINKS: u8 = 32;
/// An FTD child establishes the extra links only after being attached this long.
pub const GRADUAL_LINK_WAIT_AFTER_ATTACH: Duration = Duration::from_secs(300);
/// Gradual link establishment: delay window and probability (percent).
pub const GRADUAL_LINK_MIN_DELAY: Duration = Duration::from_millis(1500);
/// See [`GRADUAL_LINK_MIN_DELAY`].
pub const GRADUAL_LINK_MAX_DELAY: Duration = Duration::from_millis(10_000);
/// See [`GRADUAL_LINK_MIN_DELAY`].
pub const GRADUAL_LINK_PROBABILITY_PERCENT: u8 = 5;
/// Routers kept in the Route64 TLV of a Link Accept for a router neighbor
/// (OT `kMaxRoutersInRouteTlvForLinkAccept`).
pub const MAX_ROUTERS_IN_LINK_ACCEPT_ROUTE: usize = 20;
/// Sequence rollback applied to a truncated Route64 of a Link Accept.
pub const LINK_ACCEPT_SEQUENCE_ROLLBACK: u8 = 64;

/// Delay that aggregates several changes into one Child Update Request of
/// an MTD child (OT `kChildUpdateRequestDelay`).
pub const CHILD_UPDATE_REQUEST_DELAY: Duration = Duration::from_millis(100);
/// Maximum jitter of an unsolicited multicast Data Response of a router
/// (OT `kUnsolicitedDataResponseJitter`).
pub const UNSOLICITED_DATA_RESPONSE_JITTER_MS: u32 = 500;
