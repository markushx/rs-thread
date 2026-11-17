#![no_std]
//! Spinel frame codec and HDLC-lite framing for OpenTrust.
//!
//! Part of OpenTrust, a pure Rust implementation of the Thread 1.4.1 protocol.
//!
//! Spinel is the host/co-processor protocol of OpenThread (RCP and NCP). The
//! crate is `no_std` and allocation-free and follows
//! `openthread/src/lib/spinel/spinel.h` and `src/lib/hdlc/hdlc.cpp`:
//!
//! | module | contents |
//! |--------|----------|
//! | [`hdlc`] | HDLC-lite: flag/escape stuffing, CRC-16/X.25 FCS, streaming [`hdlc::Decoder`] |
//! | [`codec`] | [`codec::Writer`] / [`codec::Reader`] for the Spinel data types (packed integers, `d`, `D`, `U`, `t(...)`) |
//! | [`frame`] | [`frame::Header`], [`frame::Frame`] parsing and property frame building |
//! | [`consts`] | commands, status codes, capabilities, property keys |

#[cfg(test)]
extern crate std;

pub mod codec;
pub mod consts;
pub mod frame;
pub mod hdlc;

/// Spinel codec errors.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Error {
    /// The input ended before the value was complete, or a length field
    /// points beyond the buffer.
    Parse,
    /// The output buffer is too small.
    NoBufs,
}

/// Result alias of the crate.
pub type Result<T> = core::result::Result<T, Error>;
