#![no_std]
//! DNS, DNS-SD and the Service Registration Protocol (SRP) for rs-thread.
//!
//! Part of rs-thread, a pure Rust implementation of the Thread 1.4.1 protocol.
//!
//! Sans-IO and allocation-free, like the rest of the stack: callers pass
//! `now` and an RNG in, outgoing datagrams leave through a context trait,
//! and the state machines expose their next deadline.
//!
//! | module | contents |
//! |--------|----------|
//! | [`wire`] | DNS header, names with compression (encode and decode, loop-safe), message [`wire::Writer`] and [`wire::Parser`] |
//! | [`client`] | DNS / DNS-SD client: AAAA, browse (PTR), service resolution (SRV + TXT) over UDP |
//! | [`srp`] | SRP client (RFC 9665): signed UPDATE, lease refresh, retry, server auto-start from Network Data |
//! | [`rdata`] | TXT entries, KEY / SIG(0), EDNS(0) OPT with the Update Lease option (RFC 9664) |
//!
//! Deviations from OpenThread are listed in
//! `RSTHREAD-OPENTHREAD-DIFFERENCES.md` ("DNS and SRP").

#[cfg(test)]
extern crate std;

#[cfg(feature = "dns-client")]
pub mod client;
pub mod rdata;
pub mod srp;
pub mod wire;

#[cfg(all(test, feature = "dns-client"))]
mod client_tests;
#[cfg(all(test, any(feature = "srp-client", feature = "dns-client")))]
mod test_util;
#[cfg(test)]
mod tests;
