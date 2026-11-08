#![no_std]
//! Mesh Link Establishment (MLE): attach, roles, partitions for OpenTrust.
//!
//! Part of OpenTrust, a pure Rust implementation of the Thread 1.4.1 protocol.
//!
//! Phase 6a provides the protocol *building blocks*, no state machines:
//!
//! - [`consts`]: Table 4-3 constants.
//! - [`tlv`]: typed parse/build of every MLE TLV.

pub mod consts;
pub mod link_quality;
pub mod tlv;
