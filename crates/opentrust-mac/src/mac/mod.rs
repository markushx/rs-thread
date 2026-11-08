//! IEEE 802.15.4 MAC state machine (sans-IO) and its async driver.
//!
//! The Rust counterpart of OpenThread's `Mac` + `SubMac` + `DataPollSender`
//! (+ the MAC side of `DataPollHandler`/`IndirectSender`/
//! `SourceMatchController`): one radio operation at a time (scans, beacon,
//! indirect/direct data, data polls, the receive window after a poll),
//! unslotted CSMA-CA, retransmissions with the Thread NO_ACK delay, ACK
//! wait, software ACKs, receive filtering, frame security through
//! [`FrameSecurity`](crate::frame_security::FrameSecurity), active and
//! energy scans.
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
//! choice) out of the MAC; the async facade (`opentrust-embassy`) owns the
//! channels. The wake future is only raced while the MAC idles, so a request
//! never aborts a transmission.
//!
//! [`Clock`]: opentrust_platform::Clock
//! [`Alarm`]: opentrust_platform::Alarm
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
//! [`RadioCaps::soft_mac_needs`](opentrust_platform::radio::RadioCaps::soft_mac_needs)
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
//! | Energy scan | never | without `ENERGY_SCAN`: [`Error::NotImplemented`](opentrust_core::Error) (no RSSI read in the trait) |
//! | CSL, timed TX, enh-ACK IEs | — | out of scope (later wave) |
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
//!   allow/deny filter, no multi-radio / TREL / CSL / wake-up frames.
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
pub use link_metrics::*;
pub use machine::{Mac, MacConfig, Operation};
pub use types::*;
