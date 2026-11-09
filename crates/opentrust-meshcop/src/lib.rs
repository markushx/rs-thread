#![no_std]
//! Mesh Commissioning Protocol (MeshCoP): datasets, joiner, commissioner for OpenTrust.
//!
//! Part of OpenTrust, a pure Rust implementation of the Thread 1.4.1 protocol.
//!
//! # Scope
//!
//! The MeshCoP TLVs, Operational Datasets and their distribution, the
//! leader's commissioner session state, Discovery, Energy Scan, PAN ID
//! Query and Announce Begin, and the commissioning roles that run DTLS
//! (`opentrust-dtls`, EC-JPAKE): the [`joiner`] and the Joiner Router
//! relay (`joiner_router`, feature `ftd`) and the Commissioner
//! (`commissioner`, feature `commissioner`). The Border Agent is not
//! implemented yet.
//!
//! # Wiring
//!
//! The crate is sans-IO like the rest of the stack: time (`now`) and
//! random numbers are parameters, TMF requests are handled by functions
//! that take the CoAP [`Request`](opentrust_coap::endpoint::Request) and a
//! [`Responder`](opentrust_coap::tmf::Responder), and everything a module
//! needs from the rest of the stack is a trait ([`manager::DatasetEnv`]) or
//! an argument. See [`manager`] for the dataset side,
//! [`leader`] for the leader side and [`scan`] / [`discovery`] for
//! the scans. Leader and router code is behind feature `ftd` (default).
//!
//! - [`tlv`]: the MeshCoP TLV codec (Thread 1.4.1 section 8.10): type
//!   numbers, typed readers over a TLV buffer ([`tlv::Tlvs`]) and writers
//!   ([`tlv::WriterExt`]), Security Policy, Channel Mask, State, Discovery
//!   Request / Response.
//! - [`timestamp`]: Active / Pending Timestamp ordering (OT
//!   `MeshCoP::Timestamp::Compare`), Orphan Announce.
//! - [`dataset`]: the Operational Dataset TLV buffer.
//! - [`manager`]: Active / Pending dataset management, delay timer.
//! - [`mgmt`]: the `/c/ag` `/c/as` `/c/pg` `/c/ps` `/c/ar` TMF handlers and clients.
//! - [`leader`] (feature `ftd`): the leader's commissioner session
//!   (`/c/lp`, `/c/la`, `/c/cs`, `/c/cg`).
//! - [`updater`] (feature `ftd`): the Dataset Updater (change part of the
//!   Active Dataset through a Pending Dataset).
//! - [`discovery`]: Discovery Request / Response content and the active
//!   scanner.
//! - [`scan`]: Energy Scan, PAN ID Query and Announce Begin (servers and
//!   clients).
//! - [`steering`]: the Steering Data bloom filter, Joiner ID derivation and
//!   Joiner Discerner.
//! - [`pskd`]: the Joiner PSKd (validation, secret handling).
//! - [`secure`]: link-layer security classes of commissioning traffic and
//!   the DTLS / CoAP glue.
//! - [`joiner`]: the Joiner (discovery, DTLS with the PSKd, JOIN_FIN,
//!   Joiner Entrust under the KEK).
//! - `joiner_router` (feature `ftd`): the Joiner UDP port, Relay Receive /
//!   Transmit and the delayed Joiner Entrust.
//! - `commissioner` (feature `commissioner`, default): petition,
//!   keep-alive, Joiner list and Steering Data, Joiner DTLS sessions over
//!   the relay, JOIN_FIN, MGMT_COMMISSIONER_GET / SET; on-mesh transport
//!   `commissioner::MeshTransport`.

#[cfg(test)]
extern crate std;

#[cfg(feature = "commissioner")]
pub mod commissioner;
pub mod dataset;
pub mod discovery;
pub mod joiner;
#[cfg(feature = "ftd")]
pub mod joiner_router;
#[cfg(feature = "ftd")]
pub mod leader;
pub mod manager;
pub mod mgmt;
pub mod pskd;
pub mod scan;
pub mod secure;
pub mod steering;
pub mod timestamp;
pub mod tlv;
#[cfg(feature = "ftd")]
pub mod updater;

#[cfg(all(test, feature = "commissioner"))]
mod commissioner_tests;
#[cfg(test)]
mod dataset_tests;
#[cfg(test)]
mod dataset_vector_tests;
#[cfg(all(test, feature = "ftd"))]
mod joiner_router_tests;
#[cfg(test)]
mod joiner_tests;
#[cfg(all(test, feature = "ftd"))]
mod net_sim;
#[cfg(test)]
mod scan_tests;
#[cfg(all(test, feature = "ftd"))]
mod sim_scan_tests;
#[cfg(all(test, feature = "ftd"))]
mod sim_tests;
#[cfg(test)]
mod steering_tests;
#[cfg(test)]
mod test_rng;
#[cfg(test)]
mod tlv_tests;
