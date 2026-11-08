#![no_std]
//! IPv6/UDP/ICMPv6 core, MPL, address resolution, SRP/DNS-SD client for OpenTrust.
//!
//! Part of OpenTrust, a pure Rust implementation of the Thread 1.4.1 protocol.
//!
//! - [`header`]: IPv6 header, extension headers, MPL option, fragment header.
//! - [`checksum`]: Internet checksum and IPv6 pseudo-header.
//! - [`addr`]: scopes, prefix matching, Thread multicast groups.
//! - [`netif`]: unicast/multicast address tables and source selection.
//! - [`slaac`]: RFC 7217 SLAAC address generation and management.
//! - [`ip6`]: the sans-IO IPv6 receive/send core ([`ip6::Ip6`]).
//! - [`mpl`]: MPL (RFC 7731) as in OpenThread.
//! - [`icmp6`]: ICMPv6 message types and builders.
//!
//! Behaviour follows OpenThread's `src/core/net`; deviations are listed in
//! `OPENTRUST-OPENTHREAD-DIFFERENCES.md` ("Network layer (IPv6)").

#[cfg(test)]
extern crate std;

pub mod addr;
pub mod checksum;
pub mod header;
pub mod icmp6;
pub mod ip6;
pub mod mpl;
pub mod netif;
pub mod slaac;
