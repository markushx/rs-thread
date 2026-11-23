#![no_std]
//! IPv6/UDP/ICMPv6 core, MPL, address resolution, SRP/DNS-SD client for rs-thread.
//!
//! Part of rs-thread, a pure Rust implementation of the Thread 1.4.1 protocol.
//!
//! - [`header`]: IPv6 header, extension headers, MPL option, fragment header.
//! - [`checksum`]: Internet checksum and IPv6 pseudo-header.
//! - [`addr`]: scopes, prefix matching, Thread multicast groups.
//! - [`netif`]: unicast/multicast address tables and source selection.
//! - [`resolver`]: EID-to-RLOC address resolution cache (no CoAP).
//! - [`slaac`]: RFC 7217 SLAAC address generation and management.
//! - [`ip6`]: the sans-IO IPv6 receive/send core ([`ip6::Ip6`]).
//! - [`mpl`]: MPL (RFC 7731) as in OpenThread.
//! - [`udp`]: UDP socket table and internal receiver hooks.
//! - [`icmp6`]: ICMPv6 message types and builders.
//!
//! # Data flow
//!
//! The crate is sans-IO and allocation-free. Everything is driven by the
//! caller with `now: Instant`, a random source and byte slices:
//!
//! ```text
//!  6LoWPAN reassembler --datagram--> Ip6::handle --> RxOutcome
//!                                       |               |- deliver  -> UdpSockets::handle_datagram / ICMPv6 handlers
//!                                       |               |- forward_thread -> mesh forwarder (hop limit already decremented)
//!                                       |               |- forward_host   -> host interface
//!                                       |               `- reply (echo)    -> mesh forwarder
//!  UdpSockets::build_send --> Ip6::send --> datagram for the mesh forwarder (+ local loopback delivery)
//!  Ip6::next_deadline / Ip6::poll          MPL retransmissions
//!  AddressResolver::{resolve, poll}        EID -> RLOC16 (events drive TMF in rs-thread-mesh)
//! ```
//!
//! Questions only other layers can answer (role, Network Data routes,
//! sleepy children, router table next hops) are traits: [`ip6::Ip6Env`],
//! [`resolver::ResolverEnv`], [`resolver::ChildLookup`].
//!
//! Behaviour follows OpenThread's `src/core/net`; deviations are listed in
//! `OPENTRUST-OPENTHREAD-DIFFERENCES.md` ("Network layer (IPv6)").

#[cfg(test)]
extern crate std;

pub mod addr;
pub mod checksum;
#[cfg(feature = "ip6-fragmentation")]
pub mod fragment;
pub mod header;
pub mod icmp6;
pub mod ip6;
pub mod mpl;
pub mod netif;
pub mod resolver;
pub mod slaac;
pub mod udp;
