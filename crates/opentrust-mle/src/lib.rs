#![no_std]
//! Mesh Link Establishment (MLE): attach, roles, partitions for OpenTrust.
//!
//! Part of OpenTrust, a pure Rust implementation of the Thread 1.4.1 protocol.
//!
//! Phase 6a provides the protocol *building blocks*, no state machines:
//!
//! - [`consts`]: Table 4-3 constants.
//! - [`tlv`]: typed parse/build of every MLE TLV.
//! - [`message`], [`security`]: commands, message building, MLE security.
//! - [`neighbor`], [`link_quality`]: neighbor/child/router data model, tables.
//! - [`endpoint`]: UDP glue (port 19788, rx validation/decryption, dispatch, tx).

pub mod consts;
pub mod endpoint;
pub mod link_quality;
pub mod message;
pub mod neighbor;
pub mod security;
pub mod tlv;
