#![no_std]
//! IEEE 802.15.4 MAC layer (frames, security, CSMA-CA, CSL, link metrics) for rs-thread.
//!
//! Part of rs-thread, a pure Rust implementation of the Thread 1.4.1 protocol.
//!
//! - [`frame`]: zero-copy frame parser and builder (2003/2006/2015 frames,
//!   header IEs, auxiliary security header, beacons, MAC commands).
//! - [`frame_security`]: contract between the MAC data path and frame security.
//! - [`security`]: frame security (key manager, key ID modes 1/2, replay
//!   protection, enhanced-ACK security).
//! - [`mac`]: the sans-IO MAC state machine (CSMA-CA, retries, ACKs, data
//!   polling, indirect transmission, scans) and its async driver.

pub mod frame;
pub mod frame_security;
pub mod mac;
pub mod security;
