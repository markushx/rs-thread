#![no_std]
//! CoAP, Thread Management Framework (TMF) and CoAPS for rs-thread.
//!
//! Part of rs-thread, a pure Rust implementation of the Thread 1.4.1 protocol.
//!
//! Sans-IO and allocation-free, like the rest of the stack:
//!
//! | module | contents |
//! |--------|----------|
//! | [`message`] | RFC 7252 codec: zero-copy parser, ordered builder, option helpers |
//! | [`endpoint`] | client/server state machine: retransmission, response cache, resources, [`endpoint::Transport`] / [`endpoint::SecureTransport`] seams |
//! | [`tmf`] | Thread Management Framework agent on UDP 61631: filtering, DSCP, handler dispatch |
//! | [`uri`] | the Thread TMF URI list |
//!
//! Generic TLV helpers shared with MLE/MeshCoP are in `rs_thread_core::tlv`.
//! CoAPS (DTLS 1.2 with EC-JPAKE) plugs in through
//! [`endpoint::SecureTransport`], implemented by `rs_thread_dtls::coaps::Coaps`. Deviations from OpenThread are listed in
//! `RSTHREAD-OPENTHREAD-DIFFERENCES.md` ("CoAP / TMF").

#[cfg(test)]
extern crate std;

pub mod endpoint;
pub mod message;
pub mod tmf;
pub mod uri;
