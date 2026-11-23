//! IEEE 802.15.4 MAC state machine (sans-IO) and its async driver.
//!
//! The Rust counterpart of OpenThread's `Mac` + `SubMac` + `DataPollSender`
//! (+ the MAC side of `DataPollHandler`/`IndirectSender`/
//! `SourceMatchController`): one radio operation at a time (scans, beacon,
//! indirect/direct data, data polls, the receive window after a poll),
//! unslotted CSMA-CA, retransmissions with the Thread NO_ACK delay, ACK
//! wait, software ACKs, receive filtering, frame security through
//! [`FrameSecurity`](crate::frame_security::FrameSecurity), active and
//! energy scans; CSL (receiver and transmitter, Thread 1.2) and Enhanced-ACK
//! based Link Metrics probing (MAC part).
//!
//! # Design
//!
//! [`Mac`] is a plain state machine without I/O, executor or clock: every
//! entry point takes `now: Instant`, and the MAC tells its caller what the
//! radio should do next ([`RadioAction`]) and when it wants to be called
//! again ([`Mac::next_deadline`]). Upper layers talk to it through methods
//! (or [`Request`]s) and receive [`Event`]s from a bounded queue.
//!
//! Why a *pull* interface (`poll_action` / `poll_event`) rather than
//! callbacks or a single `handle(Input) -> Output`:
//! - the radio can only do one thing at a time and its commands are async;
//!   pulling one command at a time maps 1:1 onto `radio.xxx().await` and
//!   never needs an output buffer of commands;
//! - completions come back as dedicated calls ([`Mac::on_tx_done`],
//!   [`Mac::on_energy_scan_done`]) with borrowed data (the ACK PSDU), no
//!   copies, no lifetimes in an `Input` enum;
//! - tests drive it directly, deterministically, with a fake RNG and
//!   hand-made `now` values, without an executor.
//!
//! [`MacDriver`] is the thin async shell (radio + [`Clock`] + [`Alarm`]).
//! It is executor-agnostic (only `embassy_futures::select`) and has no
//! channel of its own: [`MacDriver::run_until`] returns either an [`Event`]
//! or the output of a caller-supplied *wake* future (e.g. an
//! `embassy_sync::channel::Receiver::receive()` of upper-layer requests),
//! after which the caller submits the request through [`MacDriver::mac`] and
//! calls again. This keeps `embassy-sync` (and its mutex/critical-section
//! choice) out of the MAC; the async facade (`rs-thread-embassy`) owns the
//! channels. The wake future is only raced while the MAC idles, so a request
//! never aborts a transmission.
//!
//! [`Clock`]: rs_thread_platform::Clock
//! [`Alarm`]: rs_thread_platform::Alarm
//!
//! ## Sequence: direct transmission on a bare PHY (software CSMA, ACK)
//!
//! ```text
//!  upper layer          MacDriver                    Mac (core)                 Radio
//!      |  mac().transmit(h, frame)  |                       |                       |
//!      |--------------------------->|---------------------->| queue                 |
//!      |  run_until(req.receive())  |  poll_action(now)     |                       |
//!      |--------------------------->|---------------------->| start TransmitData,   |
//!      |                            |<-- None --------------| backoff timer         |
//!      |                            |  next_deadline()      |                       |
//!      |                            |  select(receive, alarm(deadline), wake)       |
//!      |                            |..... alarm fires .....|                       |
//!      |                            |  poll_action(now)     |                       |
//!      |                            |<-- Transmit(psdu) ----|                       |
//!      |                            |  transmit(psdu, cca) -------------------------->|
//!      |                            |<----------------------------------- Ok(None) --|
//!      |                            |  on_tx_done(Sent)     |                       |
//!      |                            |---------------------->| WaitAck, 16 ms timer  |
//!      |                            |  select(receive, alarm, wake)                 |
//!      |                            |<------------------------------- ACK frame -----|
//!      |                            |  on_rx(ack)           |                       |
//!      |                            |---------------------->| seq matches: done     |
//!      |                            |  poll_event()         |                       |
//!      |<-- Event(TxDone{h, Ok}) ---|<----------------------|                       |
//! ```
//!
//! With a full-offload radio (`CSMA_BACKOFF`, `TX_ACK`, `ACK_TIMEOUT`,
//! `TRANSMIT_RETRIES`) the same request is a single `transmit` returning the
//! ACK: the MAC skips the backoff timer, the ACK wait and the retries.
//!
//! # Software vs. radio
//!
//! [`RadioCaps::soft_mac_needs`](rs_thread_platform::radio::RadioCaps::soft_mac_needs)
//! decides what the MAC does itself:
//!
//! | Function | In software when | Notes |
//! |---|---|---|
//! | CSMA-CA backoff | no `CSMA_BACKOFF` | `min(macMinBE + NB, macMaxBE)`, `r * 320 µs`; then one CCA in the radio (`max_csma_backoffs = Some(0)`) |
//! | Retransmissions | no `TRANSMIT_RETRIES` | NO_ACK and CCA failures; Thread NO_ACK delay (BENA 0..5) |
//! | ACK matching | no `TX_ACK` | ACKs arrive through `receive`, matched by sequence number |
//! | ACK timeout | no `TX_ACK`, or `TX_ACK` without `ACK_TIMEOUT` | the driver drops the transmit future at [`TxAction::abort_at`] (contract C5) |
//! | Sending ACKs | no `RX_ACK` | imm-ACK / enh-ACK (2015 frames, secured if the frame was), Frame Pending from the source-match table; only meets the turnaround time on simulated media |
//! | Source match | no `SRC_MATCH` | table kept in the MAC either way; pushed to radios that have it |
//! | Address filtering | always | as OpenThread: radio filters only decide what the radio ACKs |
//! | TX security | no `TRANSMIT_SEC` | [`FrameSecurity::secure_tx`](crate::frame_security::FrameSecurity::secure_tx) before the first attempt |
//! | Keys / frame counter | radio with `TRANSMIT_SEC` or `RECEIVE_TIMING` | pushed to the radio ([`RadioAction::SetMacKeys`], [`RadioAction::SetMacFrameCounter`]) whenever [`FrameSecurity::radio_keys`](crate::frame_security::FrameSecurity::radio_keys) changes; counters the radio used are fed back ([`Mac::on_tx_frame_updated`], `PsduRxInfo::ack_security`) |
//! | CSL sampling | no `RECEIVE_TIMING` | the MAC turns the receiver on/off per period; with it one [`RadioAction::ReceiveAt`] per period and [`RadioAction::SetCsl`] (schedule for the radio's enh-ACKs) |
//! | CSL IE phase | no `TRANSMIT_SEC` | set per attempt from the radio clock, frame re-secured (new frame counter, same sequence number) |
//! | Timed transmit (CSL tx) | no `TRANSMIT_TIMING` | the MAC waits for `window - (CCA + 40 us + SHR)` by the radio clock; else [`PsduTxInfo::tx_at_us`](rs_thread_platform::radio::PsduTxInfo::tx_at_us) |
//! | Enh-ACK IEs (CSL, link metrics) | no `RX_ACK` (software ACKs) | built by the MAC; hardware ACKs know only the CSL schedule |
//! | Energy scan | never | without `ENERGY_SCAN`: [`Error::NotImplemented`](rs_thread_core::Error) (no RSSI read in the trait) |
//! //!
//! # CSL
//!
//! *Receiver* (SSED): [`Mac::set_csl`] configures period (units of 10
//! symbols), channel (0 = PAN channel) and the parent. The MAC schedules the
//! sample windows ([`window_edges`] widens them with the time since the last
//! synchronization, the radio's [`csl_accuracy_ppm`] / [`csl_uncertainty`]
//! and the parent's [`CslAccuracy`]), updates the CSL IE of frames that carry
//! one (phase of the next sample, [`csl_phase`]) on *every* attempt and
//! re-secures them (Thread §3.2.6.3.7), and adds the CSL IE to the enhanced
//! ACKs for the parent. Synchronization is tracked from ACKs of frames with a
//! CSL IE and from frames acknowledged with a secured enhanced ACK.
//!
//! *Transmitter* (parent): [`Mac::csl_add_child`] tracks a child. CSL IEs in
//! its secured 2015 frames and ACKs give period, phase and the radio
//! timestamp ([`CslChild`]); indirect frames queued for a synchronized child
//! go out at its next sample window ([`next_tx_window`]), requested
//! [`CSL_REQUEST_AHEAD`] (+ radio bus time) before it, dropped to the next
//! window if the MAC is late by more than [`FRAME_PREPARATION_GUARD`]. Four
//! consecutive NO_ACKs end the synchronization ([`Event::CslChildOutOfSync`]);
//! the frame then waits for the child's data poll. All CSL timing uses the
//! radio clock ([`RadioCaps::clock`](rs_thread_platform::radio::RadioCaps::clock)).
//!
//! [`csl_accuracy_ppm`]: rs_thread_platform::radio::RadioCaps::csl_accuracy_ppm
//! [`csl_uncertainty`]: rs_thread_platform::radio::RadioCaps::csl_uncertainty
//!
//! # Link Metrics probing
//!
//! [`Mac::configure_enh_ack_probing`] (subject) and
//! [`Mac::track_enh_ack_probing`] (initiator) are the calls MLE makes for the
//! Link Metrics Management messages; see the [`link_metrics`](self) helpers
//! ([`encode_enh_ack_data`], [`decode_enh_ack_data`]).
//!
//! # Capacities
//!
//! `Mac<S, G, TXQ, IND, EVQ, POLLQ, NBQ, CSLQ>` has const generics for the
//! direct queue, indirect queue, event queue, pending data polls, short ->
//! extended address map and CSL children, defaulting to the `*_LEN`
//! constants. [`Mac::new`] and [`MacDriver::init`] use the defaults;
//! [`Mac::with_capacities`] and [`MacDriver::new`] take others.
//!
//! # Not here (upper layers)
//!
//! - Duplicate detection and replay protection: per-neighbor frame counters
//!   / sequence numbers live in the neighbor table (MLE); received frames
//!   carry their [`RxSecurityInfo`](crate::frame_security::RxSecurityInfo).
//! - The neighbor table: the MAC keeps only a short → extended address map
//!   ([`Mac::set_neighbor`]) for CCM* nonces and poll matching. Unlike
//!   OpenThread it does not drop unsecured frames from unknown short
//!   addresses.
//! - Child table, child supervision, message-level indirect queues.
//!
//! # Deviations from OpenThread
//!
//! - The source-match table starts enabled and empty (OpenThread: disabled,
//!   i.e. Frame Pending for every poll, until its first entry).
//! - Promiscuous mode delivers every frame raw instead of feeding pcap.
//! - No broadcast retransmission (`kTxNumBcast`, default 1 in OpenThread
//!   anyway), no "stay awake between fragments" sleep delay, no MAC
//!   allow/deny filter, no multi-radio / TREL / wake-up frames.
//! - Frames with a short destination equal to an invalid (0xfffe) own short
//!   address are not accepted.
//! - The upper layer hands over complete frames; the MAC overwrites the
//!   sequence number (DSN) like OpenThread's `Mac::BeginTransmit`.

mod consts;
mod csl;
mod driver;
mod fcs;
mod filter;
mod indirect;
#[cfg(feature = "link-metrics")]
mod link_metrics;
mod machine;
mod poll;
mod sub_mac;
mod types;

#[cfg(test)]
mod tests;

pub use consts::*;
pub use csl::*;
pub use driver::{MacDriver, RunResult};
pub use fcs::{crc16, fcs};
pub use filter::{FilterError, FilterParams};
pub use indirect::ext_to_u64;
#[cfg(feature = "link-metrics")]
pub use link_metrics::*;
pub use machine::{Mac, MacConfig, Operation};
pub use types::*;
