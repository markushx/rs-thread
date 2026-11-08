#![no_std]
//! Mesh Link Establishment (MLE): attach, roles, partitions for OpenTrust.
//!
//! Part of OpenTrust, a pure Rust implementation of the Thread 1.4.1 protocol.
//!
//! Protocol *building blocks*:
//!
//! - [`consts`]: Table 4-3 constants.
//! - [`tlv`]: typed parse/build of every MLE TLV.
//! - [`message`], [`security`]: commands, message building, MLE security.
//! - [`neighbor`], [`link_quality`]: neighbor/child/router data model, tables.
//! - [`endpoint`]: UDP glue (port 19788, rx validation/decryption, dispatch, tx).
//!
//! The sans-IO state machine [`Mle`] covers child-side
//! [`attach`], child role operation ([`child`]), parent-side child handling
//! (feature `ftd`, default on: `parent`) and [`persist`]ence with fast
//! re-attach. It reaches the key manager, MAC, netif, settings and network
//! through the [`MleEnv`] trait (see the [`env`](mod@env) module for the design) and is driven
//! by [`Mle::receive`] and [`Mle::poll`] / [`Mle::next_deadline`].
//!
//! Behind feature `ftd` it adds the router and leader role: leader
//! start and the Disabled -> Detached -> Child (REED) -> Router -> Leader
//! state machine (`router`), router links with Link Request / Accept
//! (`router_link`), Advertisements on a Trickle timer with route cost
//! propagation (`advert`) and partitions (comparison, merge, leader loss).
//! The Address Solicit exchange with the leader is a TMF message handled by
//! `opentrust-mesh` (`router_id`): see [`MleEnv::request_router_id`].

#[cfg(feature = "ftd")]
mod advert;
mod announce_sender;
pub mod attach;
pub mod child;
mod child_rx;
pub mod consts;
pub mod discovery;
pub mod endpoint;
pub mod env;
pub mod link_metrics;
mod link_metrics_roles;
pub mod link_quality;
pub mod message;
pub mod mle;
pub mod neighbor;
#[cfg(feature = "ftd")]
pub mod parent;
pub mod persist;
#[cfg(feature = "ftd")]
pub mod router;
pub mod router_config;
#[cfg(feature = "ftd")]
mod router_link;
pub mod security;
pub mod tlv;

pub use env::{MleEnv, MleEvent, Role, StoredDataset};
pub use mle::{Mle, MleConfig};
pub use router_config::{DeviceProperties, PowerSupply, RouterConfig, RoutingPolicy};

#[cfg(all(test, feature = "ftd"))]
mod advert_tests;
#[cfg(test)]
mod attach_tests;
#[cfg(test)]
mod child_tests;
#[cfg(all(test, feature = "ftd"))]
mod discovery_tests;
#[cfg(all(test, feature = "ftd"))]
mod e2e_tests;
#[cfg(all(test, feature = "ftd"))]
mod link_metrics_tests;
#[cfg(all(test, feature = "ftd"))]
mod mesh_tests;
#[cfg(all(test, feature = "ftd"))]
mod parent_tests;
#[cfg(all(test, feature = "ftd"))]
mod partition_tests;
#[cfg(test)]
mod persist_tests;
#[cfg(all(test, feature = "ftd"))]
mod router_link_tests;
#[cfg(all(test, feature = "ftd"))]
mod router_tests;
/// Multi-node simulator, also used by the `opentrust-mesh` tests.
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
#[cfg(feature = "ftd")]
pub mod sim;
/// Fake [`MleEnv`], also used by the `opentrust-mesh` tests.
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub mod test_support;
