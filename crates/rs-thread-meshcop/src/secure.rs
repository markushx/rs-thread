//! Glue between the sans-IO DTLS session (`rs-thread-dtls`) and the CoAP
//! endpoint, shared by the Joiner, the Commissioner and the Border Agent,
//! and the link-layer security classes of commissioning traffic.
//!
//! The commissioning roles own their [`Session`] directly (rather than an
//! `rs_thread_dtls::coaps::Coaps`) because the ciphertext does not always
//! travel on a UDP socket: the Commissioner's records to a Joiner are
//! carried in Relay Transmit TMF messages.

use rand_core::CryptoRng;
use rs_thread_coap::endpoint::{Peer, SendOpts, Transport};
use rs_thread_core::Result;
use rs_thread_core::crypto::backend::CryptoBackend;
use rs_thread_core::crypto::ecjpake::P256;
use rs_thread_core::time::Instant;
use rs_thread_dtls::Session;
use rs_thread_dtls::coaps::MAX_DATAGRAM_LEN;

pub use rs_thread_dtls::MAX_CONTENT_LEN;

/// How a commissioning datagram is protected at the link layer (what the
/// MAC reported for a received frame, or must apply to an outgoing one).
///
/// - Joiner DTLS records between a Joiner and its Joiner Router travel
///   without link security ([`LinkSecurity::None`]) on the Joiner UDP port.
/// - The Joiner Entrust request and its response are secured with the KEK
///   in key ID mode 0 ([`LinkSecurity::Kek`], Thread 1.4.1 section
///   7.2.1.1, OT `kSubTypeJoinerEntrust`).
/// - Everything else uses the network key ([`LinkSecurity::Network`]).
pub use rs_thread_core::types::LinkSecurity;

/// A CoAP [`Transport`] that encrypts with `session` and hands the record
/// to `out`.
pub(crate) struct DtlsTx<'a, B: CryptoBackend, C: P256, F> {
    pub session: &'a mut Session<B, C>,
    pub out: F,
}

impl<B, C, F> Transport for DtlsTx<'_, B, C, F>
where
    B: CryptoBackend,
    B::Sha256: Clone,
    C: P256,
    F: FnMut(&[u8]) -> Result<()>,
{
    fn send(&mut self, _peer: &Peer, _opts: &SendOpts, data: &[u8]) -> Result<()> {
        let mut buf = [0u8; MAX_DATAGRAM_LEN];
        let n = self.session.send(data, &mut buf)?;
        (self.out)(&buf[..n])
    }
}

/// Send everything `session` queued (flights, alerts) to `out`; the first
/// error is reported, the queue is drained regardless.
pub(crate) fn flush<B, C, F>(session: &mut Session<B, C>, mut out: F) -> Result<()>
where
    B: CryptoBackend,
    B::Sha256: Clone,
    C: P256,
    F: FnMut(&[u8]) -> Result<()>,
{
    let mut buf = [0u8; MAX_DATAGRAM_LEN];
    let mut r = Ok(());
    while let Some(n) = session.poll_transmit(&mut buf) {
        let e = out(&buf[..n]);
        if r.is_ok() {
            r = e;
        }
    }
    r
}

/// Process the records of `rest` until one yields application data, which
/// is written to `app` (its length returned); `rest` is advanced past the
/// processed records. `None` once the datagram is exhausted.
pub(crate) fn next_app_data<B, C, R>(
    session: &mut Session<B, C>,
    now: Instant,
    rng: &mut R,
    rest: &mut &[u8],
    app: &mut [u8],
) -> Option<usize>
where
    B: CryptoBackend,
    B::Sha256: Clone,
    C: P256,
    R: CryptoRng + ?Sized,
{
    while !rest.is_empty() {
        let rx = session.handle_datagram(now, rng, rest, app).ok()?;
        let consumed = rx.consumed.min(rest.len());
        *rest = &rest[consumed..];
        if let Some(n) = rx.app_data {
            return Some(n);
        }
        if consumed == 0 {
            break;
        }
    }
    *rest = &[];
    None
}
