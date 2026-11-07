#![no_std]
//! Core types, errors, buffers, timers, crypto/settings traits and logging for OpenTrust.
//!
//! Part of OpenTrust, a pure Rust implementation of the Thread 1.4.1 protocol.

mod fmt;

pub mod bytes;
pub mod error;
pub mod message;
pub mod settings;
pub mod time;
pub mod timer;
pub mod trickle;
pub mod types;

pub use error::{Error, Result};

#[cfg(test)]
mod tests {
    #[test]
    fn log_macros_expand() {
        let x = 42u8;
        crate::trace!("trace {}", x);
        crate::debug!("debug {}", x);
        crate::info!("info {}", x);
        crate::warn!("warn {}", x);
        crate::error!("error {}", x);
    }
}
