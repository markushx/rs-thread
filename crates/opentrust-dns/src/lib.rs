#![no_std]
//! DNS, DNS-SD and the Service Registration Protocol (SRP) for OpenTrust.
//!
//! Part of OpenTrust, a pure Rust implementation of the Thread 1.4.1 protocol.
//!
//! Sans-IO and allocation-free, like the rest of the stack: callers pass
//! `now` and an RNG in, outgoing datagrams leave through a context trait,
//! and the state machines expose their next deadline.
//!
//! | module | contents |
//! |--------|----------|
//! | [`wire`] | DNS header, names with compression (encode and decode, loop-safe), message [`wire::Writer`] and [`wire::Parser`] |
//! | [`rdata`] | TXT entries, KEY / SIG(0), EDNS(0) OPT with the Update Lease option (RFC 9664) |
//!
//! Deviations from OpenThread are listed in
//! `OPENTRUST-OPENTHREAD-DIFFERENCES.md` ("DNS and SRP").

#[cfg(test)]
extern crate std;

pub mod rdata;
pub mod wire;

#[cfg(test)]
mod tests;
