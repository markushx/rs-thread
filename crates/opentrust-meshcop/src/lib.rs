#![no_std]
//! Mesh Commissioning Protocol (MeshCoP): datasets, joiner, commissioner for OpenTrust.
//!
//! Part of OpenTrust, a pure Rust implementation of the Thread 1.4.1 protocol.
//!
//! # Scope
//!
//! Everything in the Thread network layer that needs no secure session: the
//! MeshCoP TLVs, Operational Datasets and their distribution, the leader's
//! commissioner session state, Discovery, Energy Scan, PAN ID Query and
//! Announce Begin. The DTLS / EC-JPAKE parts (Joiner, Joiner Router relay,
//! Commissioner, Border Agent) are not here; their hooks are the Steering
//! Data filter and the Discovery scanner, the Commissioning Data accessors
//! in [`commissioner`], the request builders in [`mgmt`] and [`scan`], and
//! `opentrust_core::crypto::pskc` / `opentrust-dtls`.
//!
//! # Wiring
//!
//! The crate is sans-IO like the rest of the stack: time (`now`) and
//! random numbers are parameters, TMF requests are handled by functions
//! that take the CoAP [`Request`](opentrust_coap::endpoint::Request) and a
//! [`Responder`](opentrust_coap::tmf::Responder), and everything a module
//! needs from the rest of the stack is a trait ([`manager::DatasetEnv`]) or
//! an argument. See [`manager`] for the dataset side,
//! [`commissioner`] for the leader side and [`scan`] / [`discovery`] for
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
//! - [`commissioner`] (feature `ftd`): the leader's commissioner session
//!   (`/c/lp`, `/c/la`, `/c/cs`, `/c/cg`).
//! - [`updater`] (feature `ftd`): the Dataset Updater (change part of the
//!   Active Dataset through a Pending Dataset).
//! - [`discovery`]: Discovery Request / Response content and the active
//!   scanner.
//! - [`scan`]: Energy Scan, PAN ID Query and Announce Begin (servers and
//!   clients).
//! - [`steering`]: the Steering Data bloom filter, Joiner ID derivation and
//!   Joiner Discerner.

#[cfg(test)]
extern crate std;

#[cfg(feature = "ftd")]
pub mod commissioner;
pub mod dataset;
pub mod discovery;
pub mod manager;
pub mod mgmt;
pub mod scan;
pub mod steering;
pub mod timestamp;
pub mod tlv;
#[cfg(feature = "ftd")]
pub mod updater;

#[cfg(test)]
mod dataset_tests;
#[cfg(test)]
mod dataset_vector_tests;
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
mod tlv_tests;
