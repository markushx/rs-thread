#![no_std]
//! Spinel RCP (radio co-processor) and NCP support for the rs-thread Thread
//! stack.
//!
//! Part of rs-thread, a pure Rust implementation of the Thread 1.4.1 protocol.
//!
//! | module | contents |
//! |--------|----------|
//! | [`rcp`] | any [`rs_thread_platform::radio::Radio`] as an OpenThread-compatible RCP: [`rcp::Rcp`] serves the Spinel radio property set over a [`rcp::Transport`] |
//!
//! The frame codec and HDLC-lite framing are in `rs-thread-spinel`.
//! Deviations from OpenThread are listed in
//! `OPENTRUST-OPENTHREAD-DIFFERENCES.md` ("Spinel").

#[cfg(test)]
extern crate std;

pub mod rcp;

#[cfg(feature = "radio-spinel")]
extern crate std;

#[cfg(feature = "radio-spinel")]
pub mod radio_spinel;
#[cfg(feature = "radio-spinel")]
pub mod transport;

pub use rs_thread_spinel as spinel;
