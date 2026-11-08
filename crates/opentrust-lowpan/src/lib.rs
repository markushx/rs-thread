#![no_std]
//! 6LoWPAN adaptation layer (IPHC/NHC, mesh and fragmentation headers) for OpenTrust.
//!
//! Part of OpenTrust, a pure Rust implementation of the Thread 1.4.1 protocol.
//!
//! - [`ip6`]: minimal IPv6/UDP header types (the seam to the Phase 4 IPv6 layer).
//! - [`iphc`]: LOWPAN_IPHC / LOWPAN_NHC compression and decompression
//!   (RFC 6282) with caller-provided 6LoWPAN contexts.
//! - [`mesh`]: Mesh Addressing header (RFC 4944).
//! - [`frag`]: FRAG1/FRAGN headers and the [`frag::Fragmenter`].
//! - [`reassembly`]: fixed-capacity reassembly table with timeouts.

#[cfg(test)]
extern crate std;

pub mod frag;
pub mod ip6;
pub mod iphc;
pub mod mesh;
pub mod reassembly;

#[cfg(test)]
mod tests;
