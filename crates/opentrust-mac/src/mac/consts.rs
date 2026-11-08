//! MAC timing constants and default parameters.
//!
//! Values follow the Thread 1.4.1 specification (§3.2 PIB modifications,
//! Table 3-8) and OpenThread's defaults (`src/core/mac/sub_mac.hpp`,
//! `src/core/mac/mac.hpp`, `src/core/config/mac.h`,
//! `src/core/mac/data_poll_sender.hpp`).

use opentrust_core::time::Duration;

/// 802.15.4 O-QPSK (2.4 GHz) symbol period.
pub const SYMBOL_PERIOD: Duration = Duration::from_micros(16);

/// `aUnitBackoffPeriod`: 20 symbols = 320 µs (Thread Table 3-8).
pub const UNIT_BACKOFF_PERIOD: Duration = Duration::from_micros(320);

/// `macMinBE` (IEEE 802.15.4-2006 default, OpenThread `kCsmaMinBe`).
pub const MIN_BE: u8 = 3;

/// `macMaxBE` (IEEE 802.15.4-2006 default, OpenThread `kCsmaMaxBe`).
pub const MAX_BE: u8 = 5;

/// `INIT_BACKOFF_EXPONENT` of the NO_ACK retransmission delay (Thread
/// Table 3-8; OpenThread `kRetxDelayMinBackoffExponent`).
pub const RETX_INIT_BACKOFF_EXPONENT: u8 = 0;

/// `MAX_BACKOFF_EXPONENT` of the NO_ACK retransmission delay (Table 3-8).
pub const RETX_MAX_BACKOFF_EXPONENT: u8 = 5;

/// Time to wait for an ACK when the MAC runs the ACK timeout in software
/// (OpenThread `SubMac::kAckTimeout`). Much longer than the spec's
/// `macAckWaitDuration` (≤ 864 µs) to absorb software latency.
pub const ACK_TIMEOUT: Duration = Duration::from_millis(16);

/// `macMaxFrameRetries` for direct transmissions: fixed to 15 by Thread
/// (§3.2: "read-only and set to value '15'"), which is also OpenThread's
/// `OPENTHREAD_CONFIG_MAC_DEFAULT_MAX_FRAME_RETRIES_DIRECT`.
pub const MAX_FRAME_RETRIES_DIRECT: u8 = 15;

/// Retries per data poll for indirect transmissions (OpenThread default 0:
/// the child's next poll is the retry).
pub const MAX_FRAME_RETRIES_INDIRECT: u8 = 0;

/// `macMaxCSMABackoffs` for direct transmissions (OpenThread default 4).
pub const MAX_CSMA_BACKOFFS_DIRECT: u8 = 4;

/// `macMaxCSMABackoffs` for indirect transmissions (OpenThread default 4).
pub const MAX_CSMA_BACKOFFS_INDIRECT: u8 = 4;

/// How many polls an indirect frame is offered to before it fails
/// (OpenThread `OPENTHREAD_CONFIG_MAC_MAX_TX_ATTEMPTS_INDIRECT_POLLS`).
pub const MAX_TX_ATTEMPTS_INDIRECT_POLLS: u8 = 4;

/// How long a sleepy device keeps its receiver on after a data poll ACK with
/// Frame Pending set (OpenThread `OPENTHREAD_CONFIG_MAC_DATA_POLL_TIMEOUT`).
pub const DATA_POLL_TIMEOUT: Duration = Duration::from_millis(100);

/// Default per-channel scan duration (OpenThread `kScanDurationDefault`).
pub const SCAN_DURATION_DEFAULT: Duration = Duration::from_millis(300);

/// Page-0 channels 11..=26.
pub const SUPPORTED_CHANNEL_MASK: u32 = 0x07ff_f800;

/// Poll period while retrying failed polls (OpenThread `kRetxPollPeriod`).
pub const RETX_POLL_PERIOD: Duration = Duration::from_millis(1000);

/// Poll period during fast polls (OpenThread `kFastPollPeriod`).
pub const FAST_POLL_PERIOD: Duration = Duration::from_millis(188);

/// Minimum poll period (OpenThread `OPENTHREAD_CONFIG_MAC_MINIMUM_POLL_PERIOD`).
pub const MIN_POLL_PERIOD: Duration = Duration::from_millis(10);

/// Default poll period: OpenThread derives it from the MLE child timeout
/// (default 240 s) minus `RETX_POLL_PERIOD * MAX_POLL_RETX_ATTEMPTS`. MLE
/// overrides it with [`Mac::set_poll_period`](super::Mac::set_poll_period).
pub const DEFAULT_POLL_PERIOD: Duration = Duration::from_millis(240_000 - 4 * 1000);

/// Quick re-polls after back-to-back data poll timeouts (OpenThread
/// `kQuickPollsAfterTimeout`).
pub const QUICK_POLLS_AFTER_TIMEOUT: u8 = 5;

/// Failed poll transmissions before falling back to the normal period
/// (OpenThread `OPENTHREAD_CONFIG_FAILED_CHILD_TRANSMISSIONS`).
pub const MAX_POLL_RETX_ATTEMPTS: u8 = 4;

/// Default number of fast polls (OpenThread `kDefaultFastPolls`).
pub const DEFAULT_FAST_POLLS: u8 = 8;

/// Maximum number of fast polls (OpenThread `kMaxFastPolls`).
pub const MAX_FAST_POLLS: u8 = 15;

/// Capacity of the direct transmit queue (frames handed down by the upper
/// layer and not yet transmitted).
pub const TX_QUEUE_LEN: usize = 4;

/// Capacity of the indirect (parent-side) frame queue, shared by all
/// sleepy children.
pub const INDIRECT_QUEUE_LEN: usize = 8;

/// Capacity of the upward event queue.
pub const EVENT_QUEUE_LEN: usize = 8;

/// Capacity of the short → extended address map used to find the CCM*
/// nonce source of secured frames sent from a short address.
pub const NEIGHBOR_MAP_LEN: usize = 32;

/// Data polls received (acked with Frame Pending) not yet served.
pub const POLL_REQUEST_QUEUE_LEN: usize = 4;

/// Capacity of the source-match table (per address type), as in the radio
/// trait.
pub const SRC_MATCH_CAPACITY: usize = opentrust_platform::radio::SRC_MATCH_CAPACITY;
