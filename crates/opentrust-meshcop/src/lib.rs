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
//! - [`steering`]: the Steering Data bloom filter, Joiner ID derivation and
//!   Joiner Discerner.

#[cfg(test)]
extern crate std;

pub mod dataset;
pub mod manager;
pub mod mgmt;
pub mod steering;
pub mod timestamp;
pub mod tlv;

#[cfg(test)]
mod dataset_tests;
#[cfg(test)]
mod dataset_vector_tests;
#[cfg(test)]
mod steering_tests;
#[cfg(test)]
mod tlv_tests;
