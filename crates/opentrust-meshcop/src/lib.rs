#![no_std]
//! Mesh Commissioning Protocol (MeshCoP): datasets, joiner, commissioner for OpenTrust.
//!
//! Part of OpenTrust, a pure Rust implementation of the Thread 1.4.1 protocol.
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

#[cfg(test)]
mod dataset_tests;
#[cfg(test)]
mod dataset_vector_tests;
#[cfg(all(test, feature = "ftd"))]
mod net_sim;
#[cfg(all(test, feature = "ftd"))]
mod sim_scan_tests;
#[cfg(all(test, feature = "ftd"))]
mod sim_tests;
#[cfg(test)]
mod steering_tests;
#[cfg(test)]
mod tlv_tests;
