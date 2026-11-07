#![no_std]
//! IEEE 802.15.4 MAC layer (frames, security, CSMA-CA, CSL, link metrics) for OpenTrust.
//!
//! Part of OpenTrust, a pure Rust implementation of the Thread 1.4.1 protocol.
//!
//! - [`frame`]: zero-copy frame parser and builder (2003/2006/2015 frames,
//!   header IEs, auxiliary security header, beacons, MAC commands).
//! - [`frame_security`]: contract between the MAC data path and frame security.

pub mod frame;
pub mod frame_security;
