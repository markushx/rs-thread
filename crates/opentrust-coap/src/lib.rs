#![no_std]
//! CoAP, Thread Management Framework (TMF) and CoAPS for OpenTrust.
//!
//! Part of OpenTrust, a pure Rust implementation of the Thread 1.4.1 protocol.

#[cfg(test)]
extern crate std;

pub mod endpoint;
pub mod message;
pub mod tmf;
pub mod uri;
