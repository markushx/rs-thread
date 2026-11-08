#![no_std]
//! IPv6/UDP/ICMPv6 core, MPL, address resolution, SRP/DNS-SD client for OpenTrust.
//!
//! Part of OpenTrust, a pure Rust implementation of the Thread 1.4.1 protocol.
//!
//! - [`header`]: IPv6 header, extension headers, MPL option, fragment header.
//! - [`checksum`]: Internet checksum and IPv6 pseudo-header.
//! - [`icmp6`]: ICMPv6 message types and builders.
//!
//! Behaviour follows OpenThread's `src/core/net`; deviations are listed in
//! `OPENTRUST-OPENTHREAD-DIFFERENCES.md` ("Network layer (IPv6)").

#[cfg(test)]
extern crate std;

pub mod checksum;
pub mod header;
pub mod icmp6;
