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
//! - [`netdata`]: Network Data: TLV codec and typed iterators, the stable
//!   copy for sleepy children, the leader store and `/a/sd` registration
//!   (feature `ftd`), local data and the notifier, route / anycast lookup,
//!   SLAAC and 6LoWPAN context adapters, ALOCs and the anycast locator.
//! - [`dua`]: Domain Unicast Address (Thread 1.2): DUA generation, `/n/dr`
//!   registration with the Primary Backbone Router, proxy registration for
//!   children (feature `ftd`); the Backbone Router view is
//!   [`netdata::backbone`].
//! - [`mlr`]: Multicast Listener Registration (Thread 1.2): `/n/mr`
//!   registration of subscribed and children's multicast groups with the
//!   Primary Backbone Router.
//! - `forwarder` (feature `ftd`): route lookup, mesh header insertion and
//!   forwarding, address resolution glue, ICMPv6 unreachable decisions.
//! - `indirect` (feature `ftd`): per-child queues for sleepy end devices,
//!   Frame Pending and source match bookkeeping, release on data polls.
//! - [`radio`]: the radio link a frame is sent on; with feature `trel`,
//!   `trel` is the Thread Radio Encapsulation Link (TREL packets, peer
//!   table, TREL key security, radio selection).
//! - `router_id` (feature `ftd`): `/a/as` and `/a/ar`, the leader-side
//!   handlers and the client side around
//!   [`MleEnv::request_router_id`](opentrust_mle::MleEnv::request_router_id).

#[cfg(test)]
extern crate std;

pub mod address;
#[cfg(all(feature = "ftd", feature = "bbr"))]
pub mod bbr_server;
#[cfg(feature = "bbr")]
pub mod dua;
pub mod forwarder;
pub mod indirect;
#[cfg(feature = "bbr")]
pub mod mlr;
pub mod netdata;
pub mod radio;
#[cfg(feature = "ftd")]
pub mod router_id;
pub mod tlv;
#[cfg(feature = "trel")]
pub mod trel;

#[cfg(all(test, feature = "ftd"))]
mod address_tests;
#[cfg(all(test, all(feature = "ftd", feature = "bbr")))]
mod bbr_server_tests;
#[cfg(all(test, all(feature = "bbr", feature = "ftd")))]
mod bbr_sim;
#[cfg(all(test, all(feature = "bbr", feature = "ftd")))]
mod dua_tests;
#[cfg(all(test, feature = "ftd"))]
mod e2e_tests;
#[cfg(all(test, feature = "ftd"))]
mod forwarder_tests;
#[cfg(all(test, feature = "ftd"))]
mod indirect_tests;
#[cfg(all(test, all(feature = "bbr", feature = "ftd")))]
mod mlr_tests;
#[cfg(all(test, feature = "ftd"))]
mod netdata_sim_tests;
#[cfg(all(test, feature = "ftd"))]
mod router_id_tests;
#[cfg(all(test, feature = "ftd"))]
mod sim;
