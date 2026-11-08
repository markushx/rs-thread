//! The sans-IO DTLS 1.2 session (client and server) for
//! `TLS_ECJPAKE_WITH_AES_128_CCM_8`.

use core::fmt;

use opentrust_core::crypto::backend::{CryptoBackend, HmacSha256, Sha256};
use opentrust_core::crypto::ecjpake::{
    EcJpake, P256, ROUND_ONE_MAX_LEN, ROUND_TWO_MAX_LEN, Role as JpakeRole,
};
use opentrust_core::crypto::kdf::{
    KEY_BLOCK_LEN, MASTER_SECRET_LEN, kek_from_key_block, tls12_prf_sha256,
};
use opentrust_core::time::{Duration, Instant};
use opentrust_core::types::Kek;
use opentrust_core::{Error, Result};
use rand_core::CryptoRng;
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use crate::handshake::{
    self as hs, HT_CLIENT_HELLO, HT_CLIENT_KEY_EXCHANGE, HT_FINISHED, HT_HELLO_VERIFY_REQUEST,
    HT_SERVER_HELLO, HT_SERVER_HELLO_DONE, HT_SERVER_KEY_EXCHANGE, MAX_COOKIE_LEN, MAX_MESSAGE_LEN,
    RANDOM_LEN, Reassembly, VERIFY_DATA_LEN,
};
use crate::record::{
    self, AEAD_OVERHEAD, CT_ALERT, CT_APPLICATION_DATA, CT_CHANGE_CIPHER_SPEC, CT_HANDSHAKE,
    DTLS_1_0, DTLS_1_2, Header, MAX_SEQ, RecordCipher, ReplayWindow,
};
use crate::{
    ALERT_BAD_RECORD_MAC, ALERT_CLOSE_NOTIFY, ALERT_HANDSHAKE_FAILURE, ALERT_LEVEL_FATAL,
    ALERT_LEVEL_WARNING, MAX_CONTENT_LEN,
};

/// MTU used from the second retransmission on (mbedTLS
/// `ssl_double_retransmit_timeout`, RFC 6347 §4.1.1.1).
pub const RETRANSMIT_MTU: usize = 508;
/// Smallest accepted [`Config::mtu`].
pub const MIN_MTU: usize = 128;
/// Cookie length (4-byte time stamp + 28-byte MAC, as mbedTLS
/// `ssl_cookie.c`).
pub const COOKIE_LEN: usize = 32;
/// Cookie lifetime in seconds (mbedTLS `MBEDTLS_SSL_COOKIE_TIMEOUT`).
pub const COOKIE_TIMEOUT_SECS: u32 = 60;
/// Maximum length of the transport-level client identity the server binds
/// cookies to.
pub const MAX_CLIENT_ID_LEN: usize = 32;

/// Flight buffer size (largest flight: the server's ServerHello,
/// ServerKeyExchange, ServerHelloDone, about 610 bytes; or a ClientHello
/// with a 255-byte cookie, about 650 bytes).
const FLIGHT_LEN: usize = 1024;
const ENTRY_HDR: usize = 6;
const KIND_HS0: u8 = 0;
const KIND_CCS: u8 = 1;
const KIND_HS1: u8 = 2;

/// Session configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Config {
    /// Initial retransmission timeout (mbedTLS `hs_timeout_min`).
    pub hs_timeout_min: Duration,
    /// Maximum retransmission timeout; when a timeout of this length
    /// expires the handshake fails (mbedTLS `hs_timeout_max`).
    pub hs_timeout_max: Duration,
    /// Maximum datagram size for handshake flights (larger messages are
    /// fragmented). Application data and alerts are single records.
    pub mtu: usize,
}

impl Config {
    /// OpenThread: `mbedtls_ssl_conf_handshake_timeout(8000, 60000)`
    /// (retransmissions after 8, 16, 32 and 60 s, then failure).
    pub const OPENTHREAD: Config = Config {
        hs_timeout_min: Duration::from_millis(8000),
        hs_timeout_max: Duration::from_millis(60000),
        mtu: MAX_CONTENT_LEN,
    };

    /// Thread 1.4.1 §7.4.5: initial timeout `THR_DTLS_INIT_RETRANSMIT_TIMEOUT`
    /// (8 s), at most `THR_DTLS_MAX_RETRANSMIT_COUNTER` (2)
    /// retransmissions.
    pub const THREAD_SPEC: Config = Config {
        hs_timeout_min: Duration::from_millis(8000),
        hs_timeout_max: Duration::from_millis(32000),
        mtu: MAX_CONTENT_LEN,
    };
}

impl Default for Config {
    /// [`Config::OPENTHREAD`].
    fn default() -> Self {
        Self::OPENTHREAD
    }
}

/// Why a session ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum CloseReason {
    /// [`Session::close`] was called (close_notify sent).
    Local,
    /// The peer sent close_notify.
    Peer,
    /// The peer sent a fatal alert with this description.
    PeerAlert(u8),
    /// We aborted with a fatal alert with this description (handshake
    /// failure, bad record MAC on Finished, ...).
    Failed(u8),
    /// The handshake timed out (an alert `handshake_failure` is sent, as
    /// OpenThread does).
    Timeout,
}

/// Session state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum State {
    /// Handshake in progress.
    Handshaking,
    /// Handshake complete; application data can flow.
    Connected,
    /// Ended.
    Closed(CloseReason),
}

/// Result of [`Session::handle_datagram`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Received {
    /// Bytes of the datagram processed. Less than the datagram length only
    /// when `app_data` is `Some` and more records follow: call again with
    /// the rest.
    pub consumed: usize,
    /// Length of application data written to the output buffer.
    pub app_data: Option<usize>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Hs {
    ClientWaitHello,
    ClientWaitSke,
    ClientWaitShd,
    ClientWaitCcs,
    ClientWaitFinished,
    ServerWaitHello,
    ServerWaitCke,
    ServerWaitCcs,
    ServerWaitFinished,
    Done,
}

/// The messages of our last flight, kept for retransmission (bodies only;
/// records are re-encoded with fresh sequence numbers on every
/// transmission, RFC 6347 §4.2.4).
struct Flight {
    buf: [u8; FLIGHT_LEN],
    len: usize,
    /// Transmission cursor: entry offset and fragment offset within it.
    tx_entry: usize,
    tx_frag: usize,
    tx_active: bool,
}

impl Flight {
    const fn new() -> Self {
        Self {
            buf: [0; FLIGHT_LEN],
            len: 0,
            tx_entry: 0,
            tx_frag: 0,
            tx_active: false,
        }
    }

    fn clear(&mut self) {
        self.buf[..self.len].zeroize();
        self.len = 0;
        self.tx_active = false;
    }

    /// Append a message whose body `f` writes; returns the body.
    fn push(
        &mut self,
        kind: u8,
        msg_type: u8,
        msg_seq: u16,
        f: impl FnOnce(&mut [u8]) -> Result<usize>,
    ) -> Result<&[u8]> {
        let start = self.len + ENTRY_HDR;
        if start > FLIGHT_LEN {
            return Err(Error::NoBufs);
        }
        let n = f(&mut self.buf[start..])?;
        let e = &mut self.buf[self.len..start];
        e[0] = kind;
        e[1] = msg_type;
        e[2..4].copy_from_slice(&msg_seq.to_be_bytes());
        e[4..6].copy_from_slice(&(n as u16).to_be_bytes());
        self.len = start + n;
        Ok(&self.buf[start..start + n])
    }

    fn start_tx(&mut self) {
        self.tx_entry = 0;
        self.tx_frag = 0;
        self.tx_active = self.len > 0;
    }
}

/// A DTLS 1.2 session with one peer, `TLS_ECJPAKE_WITH_AES_128_CCM_8`
/// only.
///
/// Sans-IO: feed received datagrams to [`handle_datagram`](Self::handle_datagram),
/// drain [`poll_transmit`](Self::poll_transmit) after every call, and call
/// [`handle_timeout`](Self::handle_timeout) at
/// [`next_timeout`](Self::next_timeout).
pub struct Session<B: CryptoBackend, C: P256> {
    crypto: B,
    cfg: Config,
    is_client: bool,
    state: State,
    hs: Hs,
    jpake: Option<EcJpake<C>>,
    transcript: B::Sha256,
    client_random: [u8; RANDOM_LEN],
    server_random: [u8; RANDOM_LEN],
    master: [u8; MASTER_SECRET_LEN],
    kek: Option<Kek>,
    /// The handshake completed at some point (the KEK stays available
    /// after a later close).
    established: bool,

    // Client: cookie and cached round one (re-sent after HelloVerifyRequest).
    cookie: [u8; MAX_COOKIE_LEN],
    cookie_len: usize,
    kkpp: [u8; ROUND_ONE_MAX_LEN],
    kkpp_len: usize,

    // Server: cookie secret and the transport identity of the client.
    cookie_key: [u8; 32],
    client_id: [u8; MAX_CLIENT_ID_LEN],
    client_id_len: usize,

    // Handshake sequencing.
    next_send_seq: u16,
    next_recv_seq: u16,
    /// Last message of the peer's previous flight: receiving it again
    /// means our flight was lost, so it is retransmitted.
    peer_last_seq: Option<u16>,
    reasm: Reassembly,
    flight: Flight,

    // Record layer.
    read_epoch: u16,
    replay: ReplayWindow,
    write_seq: [u64; 2],
    /// Epoch of alerts we send (1 once our ChangeCipherSpec is queued).
    alert_epoch: u16,
    read_cipher: Option<RecordCipher<B::Aes128>>,
    write_cipher: Option<RecordCipher<B::Aes128>>,

    // Timers.
    deadline: Option<Instant>,
    timeout: Duration,
    retransmissions: u8,

    // Pending one-shot output.
    pending_alert: Option<[u8; 2]>,
    pending_hvr: Option<(u64, u16, [u8; COOKIE_LEN])>,
}

impl<B: CryptoBackend, C: P256> fmt::Debug for Session<B, C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Session")
            .field("client", &self.is_client)
            .field("state", &self.state)
            .field("hs", &self.hs)
            .field("read_epoch", &self.read_epoch)
            .finish_non_exhaustive()
    }
}

impl<B: CryptoBackend, C: P256> Drop for Session<B, C> {
    fn drop(&mut self) {
        self.master.zeroize();
        self.cookie_key.zeroize();
        self.flight.clear();
    }
}

fn hf<T>(r: Result<T>) -> core::result::Result<T, u8> {
    // Thread 1.4.1 §7.4.4: any failure aborts with handshake_failure.
    r.map_err(|_| ALERT_HANDSHAKE_FAILURE)
}

type HsResult = core::result::Result<(), u8>;

impl<B, C> Session<B, C>
where
    B: CryptoBackend,
    B::Sha256: Clone,
    C: P256,
{
    fn new(crypto: B, curve: C, password: &[u8], cfg: Config, is_client: bool) -> Result<Self> {
        if cfg.mtu < MIN_MTU
            || cfg.hs_timeout_min.is_zero()
            || cfg.hs_timeout_max < cfg.hs_timeout_min
        {
            return Err(Error::InvalidArgs);
        }
        let role = if is_client {
            JpakeRole::Client
        } else {
            JpakeRole::Server
        };
        let jpake = EcJpake::new(curve, role, password)?;
        let transcript = crypto.sha256();
        Ok(Self {
            crypto,
            cfg,
            is_client,
            state: State::Handshaking,
            hs: if is_client {
                Hs::ClientWaitHello
            } else {
                Hs::ServerWaitHello
            },
            jpake: Some(jpake),
            transcript,
            client_random: [0; RANDOM_LEN],
            server_random: [0; RANDOM_LEN],
            master: [0; MASTER_SECRET_LEN],
            kek: None,
            established: false,
            cookie: [0; MAX_COOKIE_LEN],
            cookie_len: 0,
            kkpp: [0; ROUND_ONE_MAX_LEN],
            kkpp_len: 0,
            cookie_key: [0; 32],
            client_id: [0; MAX_CLIENT_ID_LEN],
            client_id_len: 0,
            next_send_seq: 0,
            next_recv_seq: 0,
            peer_last_seq: None,
            reasm: Reassembly::new(),
            flight: Flight::new(),
            read_epoch: 0,
            replay: ReplayWindow::new(),
            write_seq: [0; 2],
            alert_epoch: 0,
            read_cipher: None,
            write_cipher: None,
            deadline: None,
            timeout: cfg.hs_timeout_min,
            retransmissions: 0,
            pending_alert: None,
            pending_hvr: None,
        })
    }

    /// Start a client handshake (Joiner, or Commissioner towards a Border
    /// Agent): queues the ClientHello. `password` is the PSKd or PSKc.
    pub fn client<R: CryptoRng + ?Sized>(
        crypto: B,
        curve: C,
        password: &[u8],
        cfg: Config,
        now: Instant,
        rng: &mut R,
    ) -> Result<Self> {
        let mut s = Self::new(crypto, curve, password, cfg, true)?;
        rng.fill_bytes(&mut s.client_random);
        let jpake = s.jpake.as_mut().ok_or(Error::InvalidState)?;
        s.kkpp_len = jpake.write_round_one(&s.crypto, rng, &mut s.kkpp)?;
        s.send_client_hello(now)?;
        Ok(s)
    }

    /// Create a server session for the client identified by `client_id`
    /// (its transport address, e.g. IPv6 address and port; cookies are
    /// bound to it). The session waits for a ClientHello; ClientHellos
    /// without a valid cookie are answered with a HelloVerifyRequest
    /// without keeping state.
    pub fn server<R: CryptoRng + ?Sized>(
        crypto: B,
        curve: C,
        password: &[u8],
        cfg: Config,
        client_id: &[u8],
        rng: &mut R,
    ) -> Result<Self> {
        if client_id.len() > MAX_CLIENT_ID_LEN {
            return Err(Error::InvalidArgs);
        }
        let mut s = Self::new(crypto, curve, password, cfg, false)?;
        rng.fill_bytes(&mut s.cookie_key);
        s.client_id[..client_id.len()].copy_from_slice(client_id);
        s.client_id_len = client_id.len();
        Ok(s)
    }

    /// Current state.
    pub fn state(&self) -> State {
        self.state
    }

    /// `true` once the handshake completed and the session is open.
    pub fn is_connected(&self) -> bool {
        self.state == State::Connected
    }

    /// The Thread KEK of this session (`SHA-256(key_block)[0..16]`,
    /// OpenThread `HandleMbedtlsExportKeys`), available once connected.
    pub fn kek(&self) -> Option<&Kek> {
        if self.established {
            self.kek.as_ref()
        } else {
            None
        }
    }

    /// When [`handle_timeout`](Self::handle_timeout) must be called next.
    pub fn next_timeout(&self) -> Option<Instant> {
        self.deadline
    }

    /// Drive retransmission: on expiry the last flight is sent again with a
    /// doubled timeout, or the handshake fails once the maximum timeout
    /// expired (mbedTLS semantics).
    pub fn handle_timeout(&mut self, now: Instant) {
        let Some(d) = self.deadline else { return };
        if now < d || self.state != State::Handshaking {
            return;
        }
        if self.timeout >= self.cfg.hs_timeout_max {
            self.abort(ALERT_HANDSHAKE_FAILURE, CloseReason::Timeout);
            return;
        }
        self.timeout = self.timeout.saturating_mul(2).min(self.cfg.hs_timeout_max);
        self.retransmissions = self.retransmissions.saturating_add(1);
        self.deadline = Some(now + self.timeout);
        self.flight.start_tx();
    }

    /// Close the session: queues close_notify (encrypted once keys are in
    /// use) for [`poll_transmit`](Self::poll_transmit).
    pub fn close(&mut self) {
        if matches!(self.state, State::Closed(_)) {
            return;
        }
        self.pending_alert = Some([ALERT_LEVEL_WARNING, ALERT_CLOSE_NOTIFY]);
        self.finish_closed(CloseReason::Local);
    }

    /// Encrypt `data` as one application-data record into `out`; returns
    /// the datagram length. [`Error::InvalidState`] unless connected,
    /// [`Error::InvalidArgs`] if `data` exceeds [`MAX_CONTENT_LEN`].
    pub fn send(&mut self, data: &[u8], out: &mut [u8]) -> Result<usize> {
        if self.state != State::Connected {
            return Err(Error::InvalidState);
        }
        if data.len() > MAX_CONTENT_LEN {
            return Err(Error::InvalidArgs);
        }
        let seq = self.take_seq(1)?;
        let c = self.write_cipher.as_ref().ok_or(Error::InvalidState)?;
        c.seal(CT_APPLICATION_DATA, 1, seq, data, out)
    }

    fn take_seq(&mut self, epoch: u16) -> Result<u64> {
        let s = &mut self.write_seq[epoch as usize];
        if *s > MAX_SEQ {
            return Err(Error::NoBufs);
        }
        let v = *s;
        *s += 1;
        Ok(v)
    }

    /// Next datagram to send, if any. Call until it returns `None`.
    pub fn poll_transmit(&mut self, out: &mut [u8]) -> Option<usize> {
        if let Some(alert) = self.pending_alert.take() {
            return self.write_alert(alert, out).ok();
        }
        if let Some((rec_seq, msg_seq, cookie)) = self.pending_hvr.take() {
            return Self::write_hvr(rec_seq, msg_seq, &cookie, out).ok();
        }
        if !self.flight.tx_active {
            return None;
        }
        match self.write_flight(out) {
            Ok(0) | Err(_) => {
                self.flight.tx_active = false;
                None
            }
            Ok(n) => Some(n),
        }
    }

    fn write_alert(&mut self, alert: [u8; 2], out: &mut [u8]) -> Result<usize> {
        let epoch = self.alert_epoch;
        let seq = self.take_seq(epoch)?;
        if epoch == 0 {
            if out.len() < record::HEADER_LEN + 2 {
                return Err(Error::NoBufs);
            }
            record::write_header(out, CT_ALERT, 0, seq, 2);
            out[record::HEADER_LEN..record::HEADER_LEN + 2].copy_from_slice(&alert);
            Ok(record::HEADER_LEN + 2)
        } else {
            let c = self.write_cipher.as_ref().ok_or(Error::InvalidState)?;
            c.seal(CT_ALERT, epoch, seq, &alert, out)
        }
    }

    fn write_hvr(rec_seq: u64, msg_seq: u16, cookie: &[u8], out: &mut [u8]) -> Result<usize> {
        let body_len = 3 + cookie.len();
        let total = record::HEADER_LEN + hs::HEADER_LEN + body_len;
        if out.len() < total {
            return Err(Error::NoBufs);
        }
        // RFC 6347 §4.2.1: same record sequence number as the ClientHello.
        record::write_header(out, CT_HANDSHAKE, 0, rec_seq, hs::HEADER_LEN + body_len);
        let h = record::HEADER_LEN;
        hs::write_header(
            &mut out[h..],
            HT_HELLO_VERIFY_REQUEST,
            body_len,
            msg_seq,
            0,
            body_len,
        );
        hs::write_hello_verify_request(&mut out[h + hs::HEADER_LEN..], cookie)?;
        Ok(total)
    }

    /// Serialize as much of the flight as fits one datagram.
    fn write_flight(&mut self, out: &mut [u8]) -> Result<usize> {
        let mut mtu = out.len().min(self.cfg.mtu);
        if self.retransmissions >= 2 {
            mtu = mtu.min(RETRANSMIT_MTU);
        }
        let mut pos = 0;
        while self.flight.tx_entry < self.flight.len {
            let e = self.flight.tx_entry;
            let kind = self.flight.buf[e];
            let msg_type = self.flight.buf[e + 1];
            let msg_seq = u16::from_be_bytes([self.flight.buf[e + 2], self.flight.buf[e + 3]]);
            let blen =
                u16::from_be_bytes([self.flight.buf[e + 4], self.flight.buf[e + 5]]) as usize;
            let body_start = e + ENTRY_HDR;
            if kind == KIND_CCS {
                if pos + record::HEADER_LEN + 1 > mtu {
                    break;
                }
                let seq = self.take_seq(0)?;
                record::write_header(&mut out[pos..], CT_CHANGE_CIPHER_SPEC, 0, seq, 1);
                out[pos + record::HEADER_LEN] = 1;
                pos += record::HEADER_LEN + 1;
                self.flight.tx_entry = body_start + blen;
                continue;
            }
            let epoch: u16 = if kind == KIND_HS1 { 1 } else { 0 };
            let overhead =
                record::HEADER_LEN + hs::HEADER_LEN + if epoch == 1 { AEAD_OVERHEAD } else { 0 };
            if pos + overhead >= mtu {
                if pos == 0 {
                    return Err(Error::NoBufs);
                }
                break;
            }
            let off = self.flight.tx_frag;
            let remaining = blen - off;
            let fl = remaining.min(mtu - pos - overhead);
            if fl == 0 && remaining > 0 {
                break;
            }
            let seq = self.take_seq(epoch)?;
            let frag = &self.flight.buf[body_start + off..body_start + off + fl];
            if epoch == 0 {
                let rec = &mut out[pos..];
                record::write_header(rec, CT_HANDSHAKE, 0, seq, hs::HEADER_LEN + fl);
                let h = record::HEADER_LEN;
                hs::write_header(&mut rec[h..], msg_type, blen, msg_seq, off, fl);
                rec[h + hs::HEADER_LEN..h + hs::HEADER_LEN + fl].copy_from_slice(frag);
                pos += overhead + fl;
            } else {
                let mut plain = [0u8; hs::HEADER_LEN + MAX_MESSAGE_LEN];
                hs::write_header(&mut plain, msg_type, blen, msg_seq, off, fl);
                plain[hs::HEADER_LEN..hs::HEADER_LEN + fl].copy_from_slice(frag);
                let c = self.write_cipher.as_ref().ok_or(Error::InvalidState)?;
                pos += c.seal(
                    CT_HANDSHAKE,
                    1,
                    seq,
                    &plain[..hs::HEADER_LEN + fl],
                    &mut out[pos..],
                )?;
                plain.zeroize();
            }
            if off + fl == blen {
                self.flight.tx_entry = body_start + blen;
                self.flight.tx_frag = 0;
            } else {
                self.flight.tx_frag = off + fl;
                break;
            }
        }
        if self.flight.tx_entry >= self.flight.len {
            self.flight.tx_active = false;
        }
        Ok(pos)
    }

    /// Process one received datagram. Application data (connected only) is
    /// decrypted into `app_out`; see [`Received`]. Handshake progress and
    /// failures are reflected in [`state`](Self::state); queued responses
    /// must be drained with [`poll_transmit`](Self::poll_transmit).
    /// Invalid records are dropped silently (RFC 6347 §4.1.2.7), except a
    /// record that fails authentication while Finished is expected, which
    /// aborts with `bad_record_mac` (as mbedTLS / OpenThread).
    pub fn handle_datagram<R: CryptoRng + ?Sized>(
        &mut self,
        now: Instant,
        rng: &mut R,
        datagram: &[u8],
        app_out: &mut [u8],
    ) -> Result<Received> {
        let mut rest = datagram;
        while let Some((h, frag, tail)) = record::parse(rest) {
            rest = tail;
            if matches!(self.state, State::Closed(_)) {
                break;
            }
            if let Some(n) = self.handle_record(now, rng, &h, frag, app_out)? {
                return Ok(Received {
                    consumed: datagram.len() - rest.len(),
                    app_data: Some(n),
                });
            }
        }
        Ok(Received {
            consumed: datagram.len(),
            app_data: None,
        })
    }

    fn handle_record<R: CryptoRng + ?Sized>(
        &mut self,
        now: Instant,
        rng: &mut R,
        h: &Header,
        frag: &[u8],
        app_out: &mut [u8],
    ) -> Result<Option<usize>> {
        let version_ok = h.version == DTLS_1_2 || (h.epoch == 0 && h.version == DTLS_1_0);
        if !version_ok || h.epoch != self.read_epoch || !self.replay.check(h.seq) {
            return Ok(None);
        }
        let mut buf = [0u8; MAX_CONTENT_LEN];
        let plain: &[u8] = if self.read_epoch == 0 {
            if frag.len() > MAX_CONTENT_LEN {
                return Ok(None);
            }
            frag
        } else {
            let Some(c) = self.read_cipher.as_ref() else {
                return Ok(None);
            };
            let target: &mut [u8] = if h.content_type == CT_APPLICATION_DATA {
                &mut *app_out
            } else {
                &mut buf
            };
            match c.open(h, frag, target) {
                Ok(n) => {
                    if h.content_type == CT_APPLICATION_DATA {
                        self.replay.update(h.seq);
                        return Ok(if self.state == State::Connected {
                            Some(n)
                        } else {
                            None
                        });
                    }
                    &buf[..n]
                }
                Err(Error::Security) => {
                    if matches!(self.hs, Hs::ClientWaitFinished | Hs::ServerWaitFinished) {
                        self.abort(
                            ALERT_BAD_RECORD_MAC,
                            CloseReason::Failed(ALERT_BAD_RECORD_MAC),
                        );
                    }
                    return Ok(None);
                }
                Err(Error::NoBufs) if h.content_type == CT_APPLICATION_DATA => {
                    return Err(Error::NoBufs);
                }
                Err(_) => return Ok(None),
            }
        };
        self.replay.update(h.seq);
        let r = match h.content_type {
            CT_HANDSHAKE => self.handle_handshake(now, rng, h.seq, plain),
            CT_CHANGE_CIPHER_SPEC => self.handle_ccs(plain),
            CT_ALERT => {
                self.handle_alert(plain);
                Ok(())
            }
            _ => Ok(()), // plaintext application data or unknown type
        };
        buf.zeroize();
        if let Err(alert) = r {
            self.abort(alert, CloseReason::Failed(alert));
        }
        Ok(None)
    }

    fn handle_alert(&mut self, body: &[u8]) {
        if body.len() != 2 {
            return;
        }
        if body[1] == ALERT_CLOSE_NOTIFY {
            self.finish_closed(CloseReason::Peer);
        } else if body[0] == ALERT_LEVEL_FATAL {
            self.finish_closed(CloseReason::PeerAlert(body[1]));
        }
    }

    fn handle_ccs(&mut self, body: &[u8]) -> HsResult {
        if !matches!(self.hs, Hs::ClientWaitCcs | Hs::ServerWaitCcs) {
            return Ok(()); // early or retransmitted: ignore
        }
        if body != [1] {
            return Err(ALERT_HANDSHAKE_FAILURE);
        }
        self.read_epoch = 1;
        self.replay = ReplayWindow::new();
        self.hs = if self.is_client {
            Hs::ClientWaitFinished
        } else {
            Hs::ServerWaitFinished
        };
        Ok(())
    }

    fn handle_handshake<R: CryptoRng + ?Sized>(
        &mut self,
        now: Instant,
        rng: &mut R,
        rec_seq: u64,
        data: &[u8],
    ) -> HsResult {
        let mut rest = data;
        while !rest.is_empty() {
            let Ok((fh, frag, tail)) = hs::parse_fragment(rest) else {
                return Ok(()); // invalid header: drop the rest of the record
            };
            rest = tail;
            self.handle_fragment(now, rng, rec_seq, &fh, frag)?;
            if matches!(self.state, State::Closed(_)) {
                break;
            }
        }
        Ok(())
    }

    fn handle_fragment<R: CryptoRng + ?Sized>(
        &mut self,
        now: Instant,
        rng: &mut R,
        rec_seq: u64,
        fh: &hs::FragmentHeader,
        frag: &[u8],
    ) -> HsResult {
        let whole = fh.frag_off == 0 && fh.frag_len == fh.len;
        if self.hs == Hs::ServerWaitHello {
            // Any message_seq is adopted (RFC 6347 §4.2.2); like mbedTLS we
            // require an unfragmented ClientHello.
            if fh.msg_type == HT_CLIENT_HELLO && whole {
                return self.server_on_client_hello(now, rng, rec_seq, fh, frag);
            }
            return Ok(());
        }
        if fh.msg_seq < self.next_recv_seq {
            // Retransmission of the peer's previous flight: resend ours,
            // only on its last message (as mbedTLS) and once per message.
            if Some(fh.msg_seq) == self.peer_last_seq
                && fh.msg_type != HT_HELLO_VERIFY_REQUEST
                && fh.frag_off + fh.frag_len == fh.len
            {
                self.flight.start_tx();
            }
            return Ok(());
        }
        if fh.msg_seq > self.next_recv_seq || self.hs == Hs::Done {
            return Ok(()); // future message: dropped, recovered by retransmission
        }
        if whole {
            if fh.len > MAX_MESSAGE_LEN {
                return Err(ALERT_HANDSHAKE_FAILURE);
            }
            self.reasm.reset();
            return self.on_message(now, rng, fh.msg_type, fh.msg_seq, frag);
        }
        let mut body = [0u8; MAX_MESSAGE_LEN];
        let len = match self.reasm.add(fh, frag) {
            Ok(Some(b)) => {
                body[..b.len()].copy_from_slice(b);
                b.len()
            }
            Ok(None) => return Ok(()),
            Err(_) => return Err(ALERT_HANDSHAKE_FAILURE),
        };
        let r = self.on_message(now, rng, fh.msg_type, fh.msg_seq, &body[..len]);
        body.zeroize();
        r
    }

    fn hash_message(&mut self, msg_type: u8, msg_seq: u16, body: &[u8]) {
        self.transcript
            .update(&hs::full_header(msg_type, body.len(), msg_seq));
        self.transcript.update(body);
    }

    fn verify_data(&self, label: &[u8]) -> [u8; VERIFY_DATA_LEN] {
        let hash = self.transcript.clone().finalize();
        let mut out = [0u8; VERIFY_DATA_LEN];
        tls12_prf_sha256(&self.crypto, &self.master, label, &[&hash], &mut out);
        out
    }

    /// Derive master secret, record keys and KEK from the EC-JPAKE result.
    fn derive_keys(&mut self) -> Result<()> {
        let jpake = self.jpake.as_ref().ok_or(Error::InvalidState)?;
        let mut pms = jpake.derive_secret(&self.crypto)?;
        tls12_prf_sha256(
            &self.crypto,
            &pms,
            b"master secret",
            &[&self.client_random, &self.server_random],
            &mut self.master,
        );
        pms.zeroize();
        let mut kb = [0u8; KEY_BLOCK_LEN];
        tls12_prf_sha256(
            &self.crypto,
            &self.master,
            b"key expansion",
            &[&self.server_random, &self.client_random],
            &mut kb,
        );
        let key = |b: &[u8]| {
            let mut k = [0u8; 16];
            k.copy_from_slice(b);
            k
        };
        let iv = |b: &[u8]| [b[0], b[1], b[2], b[3]];
        let mut ck = key(&kb[0..16]);
        let mut sk = key(&kb[16..32]);
        let client = RecordCipher::new(self.crypto.aes128(&ck), iv(&kb[32..36]));
        let server = RecordCipher::new(self.crypto.aes128(&sk), iv(&kb[36..40]));
        ck.zeroize();
        sk.zeroize();
        self.kek = Some(kek_from_key_block(&self.crypto, &kb));
        kb.zeroize();
        if self.is_client {
            self.write_cipher = Some(client);
            self.read_cipher = Some(server);
        } else {
            self.write_cipher = Some(server);
            self.read_cipher = Some(client);
        }
        Ok(())
    }

    fn start_flight(&mut self, now: Instant, timer: bool) {
        self.flight.start_tx();
        self.retransmissions = 0;
        self.timeout = self.cfg.hs_timeout_min;
        self.deadline = if timer {
            Some(now + self.timeout)
        } else {
            None
        };
    }

    fn send_client_hello(&mut self, now: Instant) -> Result<()> {
        self.flight.clear();
        let seq = self.next_send_seq;
        let (random, cookie, kkpp) = (
            &self.client_random,
            &self.cookie[..self.cookie_len],
            &self.kkpp[..self.kkpp_len],
        );
        let body = self.flight.push(KIND_HS0, HT_CLIENT_HELLO, seq, |b| {
            hs::write_client_hello(b, random, cookie, kkpp)
        })?;
        self.transcript
            .update(&hs::full_header(HT_CLIENT_HELLO, body.len(), seq));
        self.transcript.update(body);
        self.next_send_seq = seq + 1;
        self.start_flight(now, true);
        Ok(())
    }

    fn on_message<R: CryptoRng + ?Sized>(
        &mut self,
        now: Instant,
        rng: &mut R,
        msg_type: u8,
        msg_seq: u16,
        body: &[u8],
    ) -> HsResult {
        match (self.hs, msg_type) {
            (Hs::ClientWaitHello, HT_HELLO_VERIFY_REQUEST) => {
                if self.cookie_len != 0 {
                    return Ok(()); // a second HelloVerifyRequest: ignore
                }
                let cookie = hf(hs::parse_hello_verify_request(body))?;
                self.cookie[..cookie.len()].copy_from_slice(cookie);
                self.cookie_len = cookie.len();
                self.next_recv_seq = msg_seq + 1;
                // RFC 6347 §4.2.6: neither the first ClientHello nor the
                // HelloVerifyRequest is part of the transcript.
                self.transcript = self.crypto.sha256();
                hf(self.send_client_hello(now))
            }
            (Hs::ClientWaitHello, HT_SERVER_HELLO) => {
                self.next_recv_seq = msg_seq + 1;
                self.hash_message(msg_type, msg_seq, body);
                let (random, kkpp) = hf(hs::parse_server_hello(body))?;
                self.server_random.copy_from_slice(random);
                let jpake = self.jpake.as_mut().ok_or(ALERT_HANDSHAKE_FAILURE)?;
                hf(jpake.read_round_one(&self.crypto, kkpp))?;
                self.hs = Hs::ClientWaitSke;
                Ok(())
            }
            (Hs::ClientWaitSke, HT_SERVER_KEY_EXCHANGE) => {
                self.next_recv_seq = msg_seq + 1;
                self.hash_message(msg_type, msg_seq, body);
                let jpake = self.jpake.as_mut().ok_or(ALERT_HANDSHAKE_FAILURE)?;
                hf(jpake.read_round_two(&self.crypto, body))?;
                self.hs = Hs::ClientWaitShd;
                Ok(())
            }
            (Hs::ClientWaitShd, HT_SERVER_HELLO_DONE) => {
                if !body.is_empty() {
                    return Err(ALERT_HANDSHAKE_FAILURE);
                }
                self.next_recv_seq = msg_seq + 1;
                self.peer_last_seq = Some(msg_seq);
                self.hash_message(msg_type, msg_seq, body);
                hf(self.send_client_final_flight(now, rng))
            }
            (Hs::ClientWaitFinished, HT_FINISHED) => {
                let expect = self.verify_data(b"server finished");
                if !bool::from(expect.ct_eq(body)) {
                    return Err(ALERT_HANDSHAKE_FAILURE);
                }
                self.next_recv_seq = msg_seq + 1;
                self.peer_last_seq = None;
                self.flight.clear();
                self.connected();
                Ok(())
            }
            (Hs::ServerWaitCke, HT_CLIENT_KEY_EXCHANGE) => {
                self.next_recv_seq = msg_seq + 1;
                self.hash_message(msg_type, msg_seq, body);
                let jpake = self.jpake.as_mut().ok_or(ALERT_HANDSHAKE_FAILURE)?;
                hf(jpake.read_round_two(&self.crypto, body))?;
                hf(self.derive_keys())?;
                self.hs = Hs::ServerWaitCcs;
                Ok(())
            }
            (Hs::ServerWaitFinished, HT_FINISHED) => {
                let expect = self.verify_data(b"client finished");
                if !bool::from(expect.ct_eq(body)) {
                    return Err(ALERT_HANDSHAKE_FAILURE);
                }
                self.next_recv_seq = msg_seq + 1;
                self.peer_last_seq = Some(msg_seq);
                self.hash_message(msg_type, msg_seq, body);
                hf(self.send_server_final_flight(now))
            }
            // Thread 1.4.1 §7.4.4: unexpected message -> handshake_failure.
            _ => Err(ALERT_HANDSHAKE_FAILURE),
        }
    }

    fn send_client_final_flight<R: CryptoRng + ?Sized>(
        &mut self,
        now: Instant,
        rng: &mut R,
    ) -> Result<()> {
        self.flight.clear();
        let seq = self.next_send_seq;
        let jpake = self.jpake.as_mut().ok_or(Error::InvalidState)?;
        let crypto = &self.crypto;
        let body = self
            .flight
            .push(KIND_HS0, HT_CLIENT_KEY_EXCHANGE, seq, |b| {
                let n = b.len().min(ROUND_TWO_MAX_LEN);
                jpake.write_round_two(crypto, rng, &mut b[..n])
            })?;
        self.transcript
            .update(&hs::full_header(HT_CLIENT_KEY_EXCHANGE, body.len(), seq));
        self.transcript.update(body);
        self.derive_keys()?;
        self.flight.push(KIND_CCS, 0, 0, |_| Ok(0))?;
        self.alert_epoch = 1;
        let vd = self.verify_data(b"client finished");
        self.flight.push(KIND_HS1, HT_FINISHED, seq + 1, |b| {
            b.get_mut(..VERIFY_DATA_LEN)
                .ok_or(Error::NoBufs)?
                .copy_from_slice(&vd);
            Ok(VERIFY_DATA_LEN)
        })?;
        self.hash_message(HT_FINISHED, seq + 1, &vd);
        self.next_send_seq = seq + 2;
        self.jpake = None;
        self.hs = Hs::ClientWaitCcs;
        self.start_flight(now, true);
        Ok(())
    }

    fn send_server_final_flight(&mut self, now: Instant) -> Result<()> {
        self.flight.clear();
        let seq = self.next_send_seq;
        self.flight.push(KIND_CCS, 0, 0, |_| Ok(0))?;
        self.alert_epoch = 1;
        let vd = self.verify_data(b"server finished");
        self.flight.push(KIND_HS1, HT_FINISHED, seq, |b| {
            b.get_mut(..VERIFY_DATA_LEN)
                .ok_or(Error::NoBufs)?
                .copy_from_slice(&vd);
            Ok(VERIFY_DATA_LEN)
        })?;
        self.next_send_seq = seq + 1;
        // Final flight: no timer; re-sent when the client's Finished is
        // retransmitted.
        self.start_flight(now, false);
        self.connected();
        Ok(())
    }

    fn connected(&mut self) {
        self.hs = Hs::Done;
        self.state = State::Connected;
        self.established = true;
        self.deadline = None;
        self.jpake = None;
        self.master.zeroize();
    }

    fn make_cookie(&self, t: u32) -> [u8; COOKIE_LEN] {
        let mut mac = self.crypto.hmac_sha256(&self.cookie_key);
        mac.update(&t.to_be_bytes());
        mac.update(&self.client_id[..self.client_id_len]);
        let m = mac.finalize();
        let mut c = [0u8; COOKIE_LEN];
        c[..4].copy_from_slice(&t.to_be_bytes());
        c[4..].copy_from_slice(&m[..COOKIE_LEN - 4]);
        c
    }

    fn cookie_valid(&self, now: Instant, cookie: &[u8]) -> bool {
        if cookie.len() != COOKIE_LEN {
            return false;
        }
        let t = u32::from_be_bytes([cookie[0], cookie[1], cookie[2], cookie[3]]);
        let now_s = now.as_secs() as u32;
        if now_s.wrapping_sub(t) > COOKIE_TIMEOUT_SECS {
            return false;
        }
        bool::from(self.make_cookie(t).ct_eq(cookie))
    }

    fn server_on_client_hello<R: CryptoRng + ?Sized>(
        &mut self,
        now: Instant,
        rng: &mut R,
        rec_seq: u64,
        fh: &hs::FragmentHeader,
        body: &[u8],
    ) -> HsResult {
        let Ok(ch) = hs::parse_client_hello(body) else {
            return Ok(()); // malformed: drop, no state
        };
        if !self.cookie_valid(now, ch.cookie) {
            let cookie = self.make_cookie(now.as_secs() as u32);
            self.pending_hvr = Some((rec_seq, fh.msg_seq, cookie));
            return Ok(());
        }
        // Cookie verified: from here on failures are fatal.
        let kkpp = match ch.kkpp {
            Some(k)
                if ch.offers_suite
                    && ch.null_compression
                    && ch.secp256r1
                    && (!ch.point_formats_present || ch.uncompressed_ok) =>
            {
                k
            }
            _ => return Err(ALERT_HANDSHAKE_FAILURE),
        };
        let jpake = self.jpake.as_mut().ok_or(ALERT_HANDSHAKE_FAILURE)?;
        hf(jpake.read_round_one(&self.crypto, kkpp))?;
        self.client_random.copy_from_slice(ch.random);
        let reneg = ch.secure_renegotiation;
        let point_formats = ch.point_formats_present;

        // mbedTLS copies the ClientHello's record sequence number and
        // message_seq (RFC 6347 §4.2.1, §4.2.2).
        self.write_seq[0] = rec_seq;
        self.next_send_seq = fh.msg_seq;
        self.next_recv_seq = fh.msg_seq.wrapping_add(1);
        self.peer_last_seq = Some(fh.msg_seq);
        self.hash_message(HT_CLIENT_HELLO, fh.msg_seq, body);
        hf(self.send_server_flight(now, rng, reneg, point_formats))
    }

    fn send_server_flight<R: CryptoRng + ?Sized>(
        &mut self,
        now: Instant,
        rng: &mut R,
        reneg: bool,
        point_formats: bool,
    ) -> Result<()> {
        self.flight.clear();
        rng.fill_bytes(&mut self.server_random);
        let seq = self.next_send_seq;
        let jpake = self.jpake.as_mut().ok_or(Error::InvalidState)?;
        let crypto = &self.crypto;
        let mut kkpp = [0u8; ROUND_ONE_MAX_LEN];
        let kn = jpake.write_round_one(crypto, rng, &mut kkpp)?;
        let random = &self.server_random;
        let body = self.flight.push(KIND_HS0, HT_SERVER_HELLO, seq, |b| {
            hs::write_server_hello(b, random, reneg, point_formats, &kkpp[..kn])
        })?;
        self.transcript
            .update(&hs::full_header(HT_SERVER_HELLO, body.len(), seq));
        self.transcript.update(body);
        let body = self
            .flight
            .push(KIND_HS0, HT_SERVER_KEY_EXCHANGE, seq + 1, |b| {
                let n = b.len().min(ROUND_TWO_MAX_LEN);
                jpake.write_round_two(crypto, rng, &mut b[..n])
            })?;
        self.transcript.update(&hs::full_header(
            HT_SERVER_KEY_EXCHANGE,
            body.len(),
            seq + 1,
        ));
        self.transcript.update(body);
        self.flight
            .push(KIND_HS0, HT_SERVER_HELLO_DONE, seq + 2, |_| Ok(0))?;
        self.hash_message(HT_SERVER_HELLO_DONE, seq + 2, &[]);
        self.next_send_seq = seq + 3;
        self.hs = Hs::ServerWaitCke;
        self.start_flight(now, true);
        Ok(())
    }

    fn abort(&mut self, alert: u8, reason: CloseReason) {
        self.pending_alert = Some([ALERT_LEVEL_FATAL, alert]);
        self.finish_closed(reason);
    }

    fn finish_closed(&mut self, reason: CloseReason) {
        self.state = State::Closed(reason);
        self.hs = Hs::Done;
        self.deadline = None;
        self.jpake = None;
        self.master.zeroize();
        self.flight.clear();
        self.pending_hvr = None;
        if !self.established {
            // Keys derived during an aborted handshake are never exported.
            self.kek = None;
        }
    }
}
