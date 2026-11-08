#![no_std]
//! Thread mesh layer of OpenTrust: the Thread network-layer TMF messages
//! (router ID assignment, address resolution), mesh forwarding with 6LoWPAN
//! mesh headers, and indirect transmission to sleepy children.
//!
//! Part of OpenTrust, a pure Rust implementation of the Thread 1.4.1
//! protocol.
//!
//! The crate is sans-IO like the layers below it: functions take `now`
//! and an RNG, parse and build TMF payloads, and hand outgoing CoAP
//! messages to a [`UdpSink`](opentrust_coap::tmf::UdpSink).
//!
//! - [`tlv`]: the Thread network-layer TLVs (OT `ThreadTlv`).
//! - [`address`]: `/a/aq`, `/a/an`, `/a/ae`, the TMF side of address
//!   resolution (the cache is `opentrust_net::resolver`).
//! - `forwarder` (feature `ftd`): route lookup, mesh header insertion and
//!   forwarding, address resolution glue, ICMPv6 unreachable decisions.
//! - `indirect` (feature `ftd`): per-child queues for sleepy end devices,
//!   Frame Pending and source match bookkeeping, release on data polls.
//! - `router_id` (feature `ftd`): `/a/as` and `/a/ar`, the leader-side
//!   handlers and the client side around
//!   [`MleEnv::request_router_id`](opentrust_mle::MleEnv::request_router_id).

#[cfg(test)]
extern crate std;

pub mod address;
#[cfg(feature = "ftd")]
pub mod forwarder;
#[cfg(feature = "ftd")]
pub mod indirect;
#[cfg(feature = "ftd")]
pub mod router_id;
pub mod tlv;

#[cfg(all(test, feature = "ftd"))]
mod address_tests;
#[cfg(all(test, feature = "ftd"))]
mod forwarder_tests;
#[cfg(all(test, feature = "ftd"))]
mod indirect_tests;
#[cfg(all(test, feature = "ftd"))]
mod router_id_tests;
#[cfg(all(test, feature = "ftd"))]
mod sim;
