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
//! - [`forward`]: top-level frame dispatch and FTD mesh forwarding decisions.
//! - [`reassembly`]: fixed-capacity reassembly table with timeouts.
//!
//! # Data flow
//!
//! The crate is sans-IO and allocation-free; it exchanges byte slices with
//! the IPv6 layer (uncompressed datagrams) and the MAC (frame payloads).
//!
//! - Tx: [`frag::Fragmenter`] compresses the datagram (IPHC/NHC with
//!   contexts from a [`iphc::ContextProvider`]), prepends an optional
//!   [`mesh::MeshHeader`] and produces one MAC payload per call; the caller
//!   passes the maximum MAC payload per frame (frame size minus MAC header,
//!   security and FCS).
//! - Rx: [`forward::parse_frame`] classifies the payload. Mesh frames go
//!   through [`forward::handle_mesh`] (deliver / forward / drop; routing is
//!   provided by the caller). Fragments go to
//!   [`reassembly::Reassembler::handle_fragment`] together with `now`;
//!   unfragmented IPHC frames are expanded with
//!   [`iphc::decompress_datagram`]. Poll
//!   [`reassembly::Reassembler::next_deadline`] and call `expire`.
//!
//! Behaviour follows OpenThread (`lowpan.cpp`, `mesh_forwarder.cpp`); the
//! deviations are listed in `OPENTRUST-OPENTHREAD-DIFFERENCES.md`.

#[cfg(test)]
extern crate std;

pub mod forward;
pub mod frag;
pub mod ip6;
pub mod iphc;
pub mod mesh;
pub mod reassembly;

#[cfg(test)]
mod tests;
