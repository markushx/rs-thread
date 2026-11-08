//! Coordinated Sampled Listening (Thread 1.4.1 §3.2.6.3, IEEE 802.15.4-2015
//! §6.12.2): the timing math and the per-peer state of both sides.
//!
//! - **Receiver (SSED)**: [`CslReceiver`] holds the schedule (period, channel,
//!   next sample time) and what OpenThread's `SubMac` keeps for it
//!   (`sub_mac_csl_receiver.cpp`); [`window_edges`] sizes the receive window
//!   from the clock drift since the last synchronization.
//! - **Transmitter (parent)**: [`CslChild`] is what `CslTxScheduler` keeps per
//!   child (period, phase, last receive timestamp);
//!   [`next_tx_window`] is `GetNextCslTransmissionDelay`.
//!
//! All times are microseconds of the *radio* clock
//! ([`RadioCaps::clock`](opentrust_platform::radio::RadioCaps::clock)); the
//! sample times are kept as `u32` like OpenThread (wrapping subtraction), the
//! transmit windows as `u64`.

use opentrust_core::time::Instant;
use opentrust_core::types::{ExtAddress, ShortAddress};

use crate::frame::Address;

/// One CSL period unit (10 symbols) in microseconds.
pub const US_PER_TEN_SYMBOLS: u32 = 160;
/// Shortest CSL period a receiver may configure, in units of 10 symbols
/// (OpenThread `kMinCslPeriod`: 10 ms).
pub const MIN_CSL_PERIOD: u16 = (10_000 / US_PER_TEN_SYMBOLS) as u16;
/// Shortest period a parent accepts in a CSL IE (OpenThread compares the raw
/// IE value with `OPENTHREAD_CONFIG_MAC_CSL_MIN_PERIOD`, i.e. 10).
pub const MIN_CSL_IE_PERIOD: u16 = 10;
/// Receiver radio-on time before the MHR (`OPENTHREAD_CONFIG_MIN_RECEIVE_ON_AHEAD`),
/// microseconds.
pub const MIN_RECEIVE_ON_AHEAD: u32 = 6 * 32;
/// Receiver radio-on time after the sample time
/// (`OPENTHREAD_CONFIG_MIN_RECEIVE_ON_AFTER`: longest frame + ACK), microseconds.
pub const MIN_RECEIVE_ON_AFTER: u32 = (127 + 6 + 39) * 32;
/// The receiver wakes up this much earlier than its window
/// (`OPENTHREAD_CONFIG_CSL_RECEIVE_TIME_AHEAD`), microseconds.
pub const CSL_RECEIVE_TIME_AHEAD: u32 = 320;
/// The transmitter starts this much earlier than the window
/// (`OPENTHREAD_CONFIG_CSL_TRANSMIT_TIME_AHEAD`), microseconds.
pub const CSL_TRANSMIT_TIME_AHEAD: u32 = 40;
/// CCA duration (8 symbols), microseconds.
pub const CCA_SAMPLE_INTERVAL: u32 = 128;
/// SHR (preamble + SFD) duration, microseconds.
pub const SHR_DURATION: u32 = 160;
/// PHR duration, microseconds.
pub const PHR_DURATION: u32 = 32;
/// How long before a CSL window the MAC takes the frame
/// (`OPENTHREAD_CONFIG_MAC_CSL_REQUEST_AHEAD_US`), microseconds.
pub const CSL_REQUEST_AHEAD: u32 = 2000;
/// Slack accepted when the frame request is late
/// (`CslTxScheduler::kFramePreparationGuardInterval`), microseconds.
pub const FRAME_PREPARATION_GUARD: u32 = 1500;
/// Frame size assumed for the radio bus transfer time of a CSL frame.
pub const CSL_BUS_FRAME_SIZE: u32 = 150;
/// Consecutive CSL transmissions without ACK after which a child counts as
/// out of sync (`kMaxCslTriggeredTxAttempts`).
pub const MAX_CSL_TX_ATTEMPTS: u8 = super::MAX_TX_ATTEMPTS_INDIRECT_POLLS;
/// Enhanced ACK turnaround (`aTurnaroundTime`, 12 symbols), microseconds.
pub const TURNAROUND_TIME: u32 = 192;

/// CSL accuracy and uncertainty of the parent, from the MLE CSL Accuracy TLV.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct CslAccuracy {
    /// Clock accuracy in +- ppm.
    pub clock_ppm: u8,
    /// Uncertainty in units of 10 us.
    pub uncertainty_10us: u8,
}

impl CslAccuracy {
    /// The worst case, assumed until the parent reports its own
    /// (OpenThread `CslAccuracy::Init`).
    pub const WORST: Self = Self {
        clock_ppm: 255,
        uncertainty_10us: 255,
    };

    /// The uncertainty in microseconds.
    pub const fn uncertainty_us(&self) -> u32 {
        self.uncertainty_10us as u32 * 10
    }
}

impl Default for CslAccuracy {
    fn default() -> Self {
        Self::WORST
    }
}

/// CSL phase (units of 10 symbols) of a frame whose SFD is at the antenna at
/// `tx_time_us`, for the next sample at `sample_time_us` (OpenThread
/// `ComputeCslPhase`). `period` in units of 10 symbols, non-zero.
pub fn csl_phase(sample_time_us: u32, tx_time_us: u32, period: u16) -> u16 {
    let period_us = u32::from(period) * US_PER_TEN_SYMBOLS;
    ((sample_time_us.wrapping_sub(tx_time_us) % period_us) / US_PER_TEN_SYMBOLS) as u16
}

/// Time the receiver must listen before and after the sample time
/// (`SubMac::GetCslWindowEdges`), microseconds `(ahead, after)`.
///
/// `elapsed_us` is the time since the last synchronization with the parent,
/// `own_ppm` / `own_uncertainty_10us` the radio's accuracy
/// ([`RadioCaps::csl_accuracy_ppm`](opentrust_platform::radio::RadioCaps::csl_accuracy_ppm)
/// and `csl_uncertainty`), `parent` the parent's.
pub fn window_edges(
    period: u16,
    elapsed_us: u32,
    own_ppm: u8,
    own_uncertainty_10us: u8,
    parent: CslAccuracy,
) -> (u32, u32) {
    let semi_period = u32::from(period) * US_PER_TEN_SYMBOLS / 2;
    let drift =
        u64::from(elapsed_us) * (u64::from(own_ppm) + u64::from(parent.clock_ppm)) / 1_000_000;
    let semi_window = drift as u32 + parent.uncertainty_us() + u32::from(own_uncertainty_10us) * 10;
    let ahead = semi_period.min(
        semi_window
            .saturating_add(MIN_RECEIVE_ON_AHEAD)
            .saturating_add(CSL_RECEIVE_TIME_AHEAD),
    );
    let after = semi_period.min(semi_window.saturating_add(MIN_RECEIVE_ON_AFTER));
    (ahead, after)
}

/// First CSL transmit window of a child that is at least `ahead_us` away from
/// `radio_now_us` (`CslTxScheduler::GetNextCslTransmissionDelay`).
///
/// The child's windows are `last_rx_timestamp + phase * 160 + n * period`.
/// Returns `(window, delay_from_last_rx, delay_from_now)`: the SFD time to
/// transmit at, its distance from the child's last frame (the `tx_delay` of
/// OpenThread's frame, relative to the base time `last_rx_timestamp`) and the
/// time left from `radio_now_us` until `ahead_us` before the window.
pub fn next_tx_window(
    radio_now_us: u64,
    period: u16,
    phase: u16,
    last_rx_timestamp_us: u64,
    ahead_us: u32,
) -> (u64, u32, u32) {
    let period_us = u64::from(period) * u64::from(US_PER_TEN_SYMBOLS);
    let first = last_rx_timestamp_us + u64::from(phase) * u64::from(US_PER_TEN_SYMBOLS);
    let mut next = radio_now_us - (radio_now_us % period_us) + (first % period_us);
    while next < radio_now_us + u64::from(ahead_us) {
        next += period_us;
    }
    (
        next,
        (next - last_rx_timestamp_us) as u32,
        (next - radio_now_us - u64::from(ahead_us)) as u32,
    )
}

/// Receiver-side CSL state (OpenThread `SubMac` CSL members).
#[derive(Debug, Clone, Copy)]
pub(crate) struct CslReceiver {
    /// CSL period in units of 10 symbols; 0 = off.
    pub period: u16,
    /// CSL channel; 0 = the PAN channel.
    pub channel: u8,
    pub peer_short: ShortAddress,
    pub peer_ext: ExtAddress,
    pub parent: CslAccuracy,
    /// Next sample time in radio time (low 32 bits, the MHR time).
    pub sample_radio: u32,
    /// The local-timer instant of the next sample.
    pub sample_local: Instant,
    /// Radio time of the last synchronization; `None` = never.
    pub last_sync: Option<u32>,
    /// Software sampling (no timed receive): the radio listens now.
    pub sampling: bool,
    /// A window to hand to the radio (`channel`, start, duration).
    pub window: Option<(u8, u64, u32)>,
    /// `Radio::set_csl` is due.
    pub radio_dirty: bool,
}

impl CslReceiver {
    pub const fn new() -> Self {
        Self {
            period: 0,
            channel: 0,
            peer_short: ShortAddress::INVALID,
            peer_ext: ExtAddress([0; 8]),
            parent: CslAccuracy::WORST,
            sample_radio: 0,
            sample_local: Instant::ZERO,
            last_sync: None,
            sampling: false,
            window: None,
            radio_dirty: false,
        }
    }

    pub const fn enabled(&self) -> bool {
        self.period != 0
    }

    pub fn period_us(&self) -> u32 {
        u32::from(self.period) * US_PER_TEN_SYMBOLS
    }

    /// Is `a` the CSL peer (the parent)?
    pub fn is_peer(&self, a: Address) -> bool {
        match a {
            Address::Short(s) => s == self.peer_short,
            Address::Extended(e) => e == self.peer_ext,
            _ => false,
        }
    }
}

/// Parent-side CSL state of one child (OpenThread `CslTxScheduler::NeighborInfo`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct CslChild {
    /// The child's address (as used for [`Mac::transmit_indirect`](super::Mac::transmit_indirect)).
    pub addr: Address,
    /// CSL period from its last CSL IE, units of 10 symbols.
    pub period: u16,
    /// CSL phase from its last CSL IE, units of 10 symbols.
    pub phase: u16,
    /// CSL channel; 0 = the PAN channel.
    pub channel: u8,
    /// A CSL IE was received and CSL transmissions have not failed since.
    pub synchronized: bool,
    /// Local time of the last frame with a CSL IE.
    pub last_heard: Option<Instant>,
    /// Radio timestamp of that frame (the base of the child's windows).
    pub last_rx_timestamp_us: u64,
    /// Consecutive failed CSL transmissions.
    pub tx_attempts: u8,
}

impl CslChild {
    pub(crate) const fn new(addr: Address) -> Self {
        Self {
            addr,
            period: 0,
            phase: 0,
            channel: 0,
            synchronized: false,
            last_heard: None,
            last_rx_timestamp_us: 0,
            tx_attempts: 0,
        }
    }
}
