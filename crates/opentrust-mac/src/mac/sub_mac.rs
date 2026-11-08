//! One frame transmission with CSMA-CA, ACK wait and retries (OpenThread
//! `SubMac` transmit path), as data. The state transitions are driven by
//! [`Mac`](super::Mac), which owns the timers and the RNG.
//!
//! ```text
//!            start / CCA busy (csma_backoffs < max)
//!   ┌──────────────► Backoff ──timer──► Ready ──poll_action──► InFlight
//!   │                   ▲                                         │
//!   │                   │                         on_tx_done ┌────┴─────────────┐
//!   │       other error │ (retries < max)       (sw ACK wait)│                  │ ACK / no AR /
//!   │                   │                                    ▼                  │ final error
//!   │    RetxDelay ◄────┴──── NO_ACK (retries < max) ◄──── WaitAck ──ACK──►  done
//!   │        │                                    (timer)
//!   └─timer──┘
//! ```

use opentrust_core::time::Duration;
use rand_core::Rng;

use super::consts::{MAX_BE, MIN_BE, UNIT_BACKOFF_PERIOD};
use super::types::{FrameBuf, TxHandle};
use crate::frame::Address;

/// What a transmission is for (decides what happens on completion).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TxKind {
    /// Direct data frame from the upper layer.
    Direct(TxHandle),
    /// Indirect frame for a polling child (`None`: an empty frame).
    Indirect(Option<TxHandle>),
    /// MAC Data Request (data poll).
    Poll,
    /// Beacon (answer to a Beacon Request).
    Beacon,
    /// Beacon Request (active scan).
    BeaconRequest,
}

/// Sub-MAC transmit state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TxState {
    /// Waiting for the CSMA-CA backoff timer.
    Backoff,
    /// Ready to be handed to the radio.
    Ready,
    /// Handed to the radio, waiting for `on_tx_done`.
    InFlight,
    /// Sent; waiting for the ACK in software (`SoftMacNeeds::MATCH_ACK`).
    WaitAck,
    /// Waiting the random delay before a retransmission after NO_ACK
    /// (Thread §3.2.x, `BENA`).
    RetxDelay,
}

/// A frame being transmitted.
#[derive(Debug, Clone)]
pub(crate) struct TxOp {
    pub kind: TxKind,
    /// The frame without FCS (secured if `secured`).
    pub frame: FrameBuf,
    pub channel: u8,
    pub dst: Address,
    pub ack_request: bool,
    pub seq: Option<u8>,
    /// Security is done by the MAC or not needed (else the radio does it).
    pub security_processed: bool,
    /// The frame was sent before (an indirect frame offered to an earlier
    /// poll).
    pub retransmission: bool,
    pub max_csma_backoffs: u8,
    pub max_frame_retries: u8,
    pub csma_backoffs: u8,
    pub retries: u8,
    /// NO_ACK retransmission backoff exponent (BENA).
    pub retx_be: u8,
    pub state: TxState,
}

/// CSMA-CA backoff exponent for the `nb`-th backoff (OpenThread
/// `StartCsmaBackoff`: `min(macMinBE + NB, macMaxBE)`).
pub(crate) fn csma_backoff_exponent(nb: u8) -> u8 {
    MIN_BE.saturating_add(nb).min(MAX_BE)
}

/// Random backoff of `r * aUnitBackoffPeriod` with `r` uniform in
/// `[0, 2^be - 1]` (OpenThread `StartTimerForBackoff`).
pub(crate) fn random_backoff(rng: &mut impl Rng, be: u8) -> Duration {
    let slots = 1u32 << be.min(31);
    let r = rng.next_u32() & (slots - 1);
    UNIT_BACKOFF_PERIOD.saturating_mul(u64::from(r))
}

/// Upper bound of the time a radio doing CSMA-CA itself may spend before
/// transmitting: every backoff at its maximum exponent plus a CCA (8
/// symbols) each.
pub(crate) fn max_csma_duration(max_backoffs: u8) -> Duration {
    let mut total = Duration::ZERO;
    for nb in 0..=max_backoffs {
        let slots = (1u64 << csma_backoff_exponent(nb)) - 1;
        total += UNIT_BACKOFF_PERIOD.saturating_mul(slots) + Duration::from_micros(128);
    }
    total
}

/// On-air time of a PSDU of `len` octets (SHR 5 + PHR 1 octets, 32 µs each).
pub(crate) fn air_time(len: usize) -> Duration {
    Duration::from_micros((len as u64 + 6) * 32)
}
