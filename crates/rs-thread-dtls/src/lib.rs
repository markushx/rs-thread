#![no_std]
//! Sans-IO DTLS 1.2 (RFC 6347) for Thread commissioning and CoAPS.
//!
//! Part of rs-thread, a pure Rust implementation of the Thread 1.4.1 protocol.
//!
//! Exactly one cipher suite, `TLS_ECJPAKE_WITH_AES_128_CCM_8` (0xC0FF,
//! draft-cragie-tls-ecjpake-01), as Thread 1.4.1 §7.4 / §8 require and
//! OpenThread configures mbedTLS (`MBEDTLS_SSL_CIPHERSUITES`). The password
//! is the PSKd (Joiner) or PSKc (Commissioner). See ADR
//! `docs/decisions/0001-ecjpake-dtls.md`.
//!
//! | module | contents |
//! |--------|----------|
//! | [`record`] | record header, epochs, 48-bit sequence numbers, anti-replay window, `AES_128_CCM_8` (RFC 6655) |
//! | [`handshake`] | handshake framing, fragment reassembly, Hello / HelloVerifyRequest codecs |
//! | [`session`] | the client/server state machine: flights, retransmission timers, cookies, key derivation, Finished, KEK, alerts |
//! | [`coaps`] | [`coaps::Coaps`]: a session behind the CoAP endpoint's `SecureTransport` seam |
//!
//! # Interoperability
//!
//! The handshake follows mbedTLS 3.6 (the DTLS stack of every OpenThread
//! device) message for message: ClientHello with `supported_groups`,
//! `ec_point_formats`, `ecjpake_key_kp_pair` and the renegotiation SCSV;
//! ServerHello with `renegotiation_info` / `ec_point_formats` echoed and
//! `ecjpake_key_kp_pair`; ServerKeyExchange / ClientKeyExchange carrying the
//! EC-JPAKE round-two messages; the TLS 1.2 PRF with SHA-256; the DTLS
//! transcript (HelloVerifyRequest and the first ClientHello excluded);
//! the record sequence number of the ClientHello copied into the server's
//! records; retransmission with doubling timeout (OpenThread: 8 s .. 60 s)
//! and a 508-byte MTU from the second retransmission on.
//! Deviations are listed in `RSTHREAD-OPENTHREAD-DIFFERENCES.md`
//! ("DTLS / EC-JPAKE").
//!
//! # Not supported
//!
//! Other cipher suites, certificates, session resumption, renegotiation,
//! extended master secret, connection IDs, compressed points.

#[cfg(test)]
extern crate std;

pub mod coaps;
pub mod handshake;
pub mod record;
pub mod session;

#[cfg(all(test, feature = "soft-crypto"))]
mod tests;

pub use session::{CloseReason, Config, Received, Session, State};

/// Maximum record plaintext we send and accept for handshake/alert records
/// (OpenThread `MBEDTLS_SSL_MAX_CONTENT_LEN` default of 768).
pub const MAX_CONTENT_LEN: usize = 768;

/// Alert level `warning`.
pub const ALERT_LEVEL_WARNING: u8 = 1;
/// Alert level `fatal`.
pub const ALERT_LEVEL_FATAL: u8 = 2;
/// `close_notify`.
pub const ALERT_CLOSE_NOTIFY: u8 = 0;
/// `bad_record_mac`.
pub const ALERT_BAD_RECORD_MAC: u8 = 20;
/// `handshake_failure`.
pub const ALERT_HANDSHAKE_FAILURE: u8 = 40;
