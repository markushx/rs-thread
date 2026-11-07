#![no_std]
//! Core types, errors, buffers, timers, crypto/settings traits and logging for OpenTrust.
//!
//! Part of OpenTrust, a pure Rust implementation of the Thread 1.4.1 protocol.

mod fmt;

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
