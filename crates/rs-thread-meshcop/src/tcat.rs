//! Thread Commissioning over Authenticated TLS (TCAT), the TCAT Device's
//! command engine (Thread 1.4.1 chapter 13, OT `MeshCoP::TcatAgent`).
//!
//! The engine is transport- and TLS-agnostic (ADR 0002): a TLS layer
//! (TLS 1.2 or 1.3 server with mutual X.509 authentication, over BLE GATT
//! or TCP) validates the TCAT Commissioner's certificate chain, then hands
//! the Thread certificate extensions of both certificates
//! ([`CertificateClaims`]) to [`TcatAgent::connected`] and feeds the
//! decrypted application data stream to [`TcatAgent::handle_received`].
//! Responses and link closure go through [`TcatSecureTransport`], which
//! the TLS layer implements; everything the commands need from the stack
//! is [`TcatEnv`].
//!
//! Every command is authorized anew with the procedure of section
//! 13.12.1 ([`TcatAgent::is_authorized`]): the Commissioner's command
//! class flags must all be satisfied, and the Device's flags must admit at
//! least one satisfied method (or grant access outright). Methods: proof
//! of possession of the PSKd (or an install code) or of the PSKc (Present
//! Hash commands, `HMAC-SHA256(secret, challenge || device
//! subjectPublicKeyInfo)`, compared in constant time), matching Network
//! Name / Extended PAN ID / Thread Domain Name; reserved methods always
//! fail.
//!
//! Feature `tcat` (default off).

use heapless::{Deque, Vec};
use rs_thread_core::bytes::Writer;
use rs_thread_core::crypto::backend::{CryptoBackend, HmacSha256 as _};
use rs_thread_core::tlv::{BASE_MAX_LENGTH, EXTENDED_LENGTH, Tlv};
use rs_thread_core::{Error, Result};
use rand_core::CryptoRng;
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use crate::dataset::{Dataset, DatasetType};
use crate::pskd::JoinerPskd;
use crate::tlv::{Tlvs, ty as meshcop_ty};

/// TCAT TLV types (section 13.9.2).
pub mod ty {
    /// Response With Status.
    pub const RESPONSE_WITH_STATUS: u8 = 0x01;
    /// Response With Payload.
    pub const RESPONSE_WITH_PAYLOAD: u8 = 0x02;
    /// Get Network Name.
    pub const GET_NETWORK_NAME: u8 = 0x08;
    /// Disconnect.
    pub const DISCONNECT: u8 = 0x09;
    /// Ping.
    pub const PING: u8 = 0x0a;
    /// Get Device ID.
    pub const GET_DEVICE_ID: u8 = 0x0b;
    /// Get Extended PAN ID.
    pub const GET_EXT_PAN_ID: u8 = 0x0c;
    /// Get Provisioning URL.
    pub const GET_PROVISIONING_URL: u8 = 0x0d;
    /// Present PSKd Hash.
    pub const PRESENT_PSKD_HASH: u8 = 0x10;
    /// Present PSKc Hash.
    pub const PRESENT_PSKC_HASH: u8 = 0x11;
    /// Present Install-code Hash.
    pub const PRESENT_INSTALL_CODE_HASH: u8 = 0x12;
    /// Request Random Number Challenge.
    pub const REQUEST_RANDOM_CHALLENGE: u8 = 0x13;
    /// Request PSKd Hash.
    pub const REQUEST_PSKD_HASH: u8 = 0x14;
    /// Set Active Operational Dataset.
    pub const SET_ACTIVE_DATASET: u8 = 0x20;
    /// Get Commissioner Certificate.
    pub const GET_COMMISSIONER_CERTIFICATE: u8 = 0x25;
    /// Get Diagnostic TLVs.
    pub const GET_DIAGNOSTIC_TLVS: u8 = 0x26;
    /// Start Thread Interface.
    pub const START_THREAD_INTERFACE: u8 = 0x27;
    /// Stop Thread Interface.
    pub const STOP_THREAD_INTERFACE: u8 = 0x28;
    /// Get Active Operational Dataset.
    pub const GET_ACTIVE_DATASET: u8 = 0x40;
    /// Decommission.
    pub const DECOMMISSION: u8 = 0x60;
    /// Get Application Layers.
    pub const GET_APPLICATION_LAYERS: u8 = 0x80;
    /// Send Application Data 1 (2..4 follow).
    pub const SEND_APPLICATION_DATA_1: u8 = 0x81;
    /// Send Application Data 4.
    pub const SEND_APPLICATION_DATA_4: u8 = 0x84;
    /// Service Name UDP (sub-TLV of Get Application Layers).
    pub const SERVICE_NAME_UDP: u8 = 0x89;
    /// Service Name TCP (sub-TLV of Get Application Layers).
    pub const SERVICE_NAME_TCP: u8 = 0x8a;
    /// Vendor Specific.
    pub const VENDOR_SPECIFIC: u8 = 0x9f;
}

/// Maximum Ping payload (section 13.9.4.3).
pub const MAX_PING_LEN: usize = 512;
/// Length of a proof-of-possession hash (HMAC-SHA256).
pub const HASH_LEN: usize = 32;
/// Length of a random number challenge (uint64).
pub const CHALLENGE_LEN: usize = 8;
/// Minimum length of the TCAT Commissioner Authorization extension
/// (header and four command class flag bytes, section 13.10.1).
pub const AUTH_FIELD_LEN: usize = 5;
/// Maximum Network Name / Domain Name length in a certificate.
pub const MAX_NAME_LEN: usize = 16;
/// The Thread Domain Name of a non-CCM device that has none configured
/// (section 13.10.4).
pub const DEFAULT_DOMAIN_NAME: &[u8] = b"DefaultDomain";
/// Timeout for the TLS handshake that the TLS layer enforces
/// (`TCAT_TLS_CONN_TIMEOUT`).
pub const TLS_CONN_TIMEOUT_SECS: u64 = 60;
/// Largest Commissioner certificate a Device must be able to store
/// (`TCAT_COMM_CERT_SIZE_MAX`).
pub const MAX_COMMISSIONER_CERT_LEN: usize = 1024;

/// Command class flag bits (sections 13.10.1.2, 13.10.1.3).
pub mod flag {
    /// Access to the class.
    pub const ACCESS: u8 = 1 << 0;
    /// Proof of possession of the PSKd (or an install code).
    pub const PSKD: u8 = 1 << 1;
    /// Matching Network Name.
    pub const NETWORK_NAME: u8 = 1 << 2;
    /// Matching Extended PAN ID.
    pub const EXT_PAN_ID: u8 = 1 << 3;
    /// Matching Thread Domain Name.
    pub const THREAD_DOMAIN: u8 = 1 << 4;
    /// Proof of possession of the PSKc.
    pub const PSKC: u8 = 1 << 5;
}

/// Header byte of the authorization extension: Commissioner flag (bit 0).
pub const HEADER_COMMISSIONER: u8 = 1 << 0;
/// Header byte: version field (bits 5-7).
pub const HEADER_VERSION_SHIFT: u8 = 5;

/// TCAT command class (section 13.9.1, Table 13-3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum CommandClass {
    /// 0x00-0x1F.
    General,
    /// 0x20-0x3F.
    Commissioning,
    /// 0x40-0x5F.
    Extraction,
    /// 0x60-0x7F.
    Decommissioning,
    /// 0x80-0x9F.
    Application,
    /// 0xA0-0xBF (CCM devices only; not supported).
    CommissioningCcm,
    /// 0xC0-0xFF.
    Reserved,
}

impl CommandClass {
    /// The class of command TLV type `t`.
    pub const fn of(t: u8) -> Self {
        match t >> 5 {
            0 => Self::General,
            1 => Self::Commissioning,
            2 => Self::Extraction,
            3 => Self::Decommissioning,
            4 => Self::Application,
            5 => Self::CommissioningCcm,
            _ => Self::Reserved,
        }
    }

    /// Index of the class's flags byte after the header in the
    /// authorization extension.
    const fn flags_index(self) -> Option<usize> {
        match self {
            Self::Commissioning => Some(0),
            Self::Extraction => Some(1),
            Self::Decommissioning => Some(2),
            Self::Application => Some(3),
            _ => None,
        }
    }
}

/// Status codes of the Response With Status TLV (section 13.9.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(u8)]
pub enum Status {
    /// Processed successfully.
    Success = 0x00,
    /// Unknown, reserved or unimplemented command.
    Unsupported = 0x01,
    /// Could not be parsed.
    ParseError = 0x02,
    /// Invalid value (too long, missing required TLVs, ...).
    ValueError = 0x03,
    /// Any other error.
    GeneralError = 0x04,
    /// Resource busy.
    Busy = 0x05,
    /// The requested value / data / service is not present.
    Undefined = 0x06,
    /// The presented hash is wrong.
    HashError = 0x07,
    /// The device is not in a state to accept the command.
    InvalidState = 0x08,
    /// Insufficient authorization.
    Unauthorized = 0x10,
}

/// The Thread-specific extensions of a validated certificate (section
/// 13.10), extracted by the TLS layer. Byte strings are the decoded
/// values (contents of the OCTET STRING / UTF8String / IA5String).
#[derive(Debug, Clone, Copy, Default)]
pub struct CertificateClaims<'a> {
    /// TCAT Commissioner Authorization (`1.3.6.1.4.1.44970.3`), at least
    /// [`AUTH_FIELD_LEN`] bytes; extra bytes are ignored.
    pub authorization: &'a [u8],
    /// Thread Network Name (`1.3.6.1.4.1.44970.4`), Commissioner only.
    pub network_name: Option<&'a [u8]>,
    /// Thread Extended PAN ID (`1.3.6.1.4.1.44970.5`), Commissioner only.
    pub ext_pan_id: Option<[u8; 8]>,
    /// Thread Domain Name (`1.3.6.1.4.1.44970.1`), Commissioner only.
    pub domain_name: Option<&'a [u8]>,
}

/// The secure link to the TCAT Commissioner, implemented by the TLS layer.
pub trait TcatSecureTransport {
    /// Send application data (response TLVs) over the TLS session.
    fn send(&mut self, data: &[u8]) -> Result<()>;
    /// Close the TLS session (alert) and the TCAT Link.
    fn disconnect(&mut self);
    /// DER of the Commissioner's validated end-entity certificate.
    fn peer_certificate_der(&self) -> &[u8];
    /// The DER subjectPublicKeyInfo of the Device's own TLS certificate
    /// (input of the proof-of-possession hashes).
    fn own_public_key_info(&self) -> &[u8];
}

/// Result of an environment operation: a status other than
/// [`Status::Success`] is sent back as the command's response.
pub type EnvResult<T> = core::result::Result<T, Status>;

/// What the TCAT commands need from the stack.
pub trait TcatEnv {
    /// The Active Operational Dataset TLVs (empty without one).
    fn active_dataset(&self) -> &[u8];
    /// Write (complete or partial) Active Operational Dataset TLVs; the
    /// Thread interface stays down until Start Thread Interface or the
    /// end of the link (section 13.12.2, [`TcatEvent::Disconnected`]).
    fn set_active_dataset(&mut self, tlvs: &[u8]) -> EnvResult<()>;
    /// Start the Thread interface (the dataset holds a Network Key).
    fn start_thread(&mut self) -> EnvResult<()>;
    /// Stop the Thread interface.
    fn stop_thread(&mut self) -> EnvResult<()>;
    /// Stop Thread, delete the Active / Pending datasets and the network
    /// information (factory-reset the Thread state, OT
    /// `ErasePersistentInfo`).
    fn decommission(&mut self) -> EnvResult<()>;
    /// Persist the Commissioner certificate (after Set Active Dataset or
    /// Decommission).
    fn store_commissioner_certificate(&mut self, der: &[u8]) -> EnvResult<()>;
    /// The stored Commissioner certificate.
    fn commissioner_certificate(&self) -> Option<&[u8]>;
    /// The device ID (e.g. the EUI-64) written to `out`; its length.
    fn device_id(&self, out: &mut [u8]) -> usize;
    /// The device's PSKd (Joining Device Credential), if it has one.
    fn pskd(&self) -> Option<&JoinerPskd>;
    /// A vendor install code, if any.
    fn install_code(&self) -> Option<&[u8]> {
        None
    }
    /// The Provisioning URL, if any.
    fn provisioning_url(&self) -> Option<&[u8]> {
        None
    }
    /// The Thread Domain Name stored on the device.
    fn domain_name(&self) -> &[u8] {
        DEFAULT_DOMAIN_NAME
    }
    /// Diagnostic TLVs of `types` (Network Diagnostic TLV types) written
    /// to `out`; their length.
    fn diagnostic_tlvs(&mut self, types: &[u8], out: &mut [u8]) -> EnvResult<usize> {
        let _ = (types, out);
        Err(Status::Unsupported)
    }
    /// The application layer list (Service Name UDP / TCP TLVs) written to
    /// `out`; its length.
    fn application_layers(&self, out: &mut [u8]) -> EnvResult<usize> {
        let _ = out;
        Ok(0)
    }
    /// Data for application protocol `protocol` (1..=4): `Ok(Some(n))`
    /// answers with the payload `out[..n]`, `Ok(None)` with Success.
    fn application_data(
        &mut self,
        protocol: u8,
        data: &[u8],
        out: &mut [u8],
    ) -> EnvResult<Option<usize>> {
        let _ = (protocol, data, out);
        Err(Status::Unsupported)
    }
    /// Vendor-specific command; answered like
    /// [`application_data`](Self::application_data).
    fn vendor_specific(&mut self, data: &[u8], out: &mut [u8]) -> EnvResult<Option<usize>> {
        let _ = (data, out);
        Err(Status::Unsupported)
    }
}

/// State of the TCAT agent (OT `TcatAgent::State`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum TcatState {
    /// Not accepting TCAT links.
    Disabled,
    /// Waiting for a TCAT Commissioner.
    Enabled,
    /// A TCAT Commissioner is connected.
    Connected,
}

/// Notification of the TCAT agent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum TcatEvent {
    /// A Commissioner was accepted.
    Connected,
    /// The link ended; `dataset_written`: an Active Dataset was set during
    /// the link and Thread was not started with Start Thread Interface (the
    /// device may now start Thread, section 13.12.2).
    Disconnected {
        /// See above.
        dataset_written: bool,
    },
    /// An Active Dataset was written.
    ActiveDatasetSet,
    /// The device was decommissioned.
    Decommissioned,
}

#[derive(Debug, Clone, Default)]
struct PeerInfo {
    auth: [u8; AUTH_FIELD_LEN],
    own: [u8; AUTH_FIELD_LEN],
    network_name: Option<Vec<u8, MAX_NAME_LEN>>,
    ext_pan_id: Option<[u8; 8]>,
    domain_name: Option<Vec<u8, MAX_NAME_LEN>>,
}

/// The TCAT Device's agent; `RX` bounds the largest command TLV (default
/// fits a 512-byte Ping and a full dataset).
pub struct TcatAgent<B: CryptoBackend, const RX: usize = 600> {
    crypto: B,
    state: TcatState,
    peer: PeerInfo,
    challenge: Option<[u8; CHALLENGE_LEN]>,
    pskd_verified: bool,
    pskc_verified: bool,
    commissioned_at_start: bool,
    dataset_written: bool,
    rx: Vec<u8, RX>,
    /// Bytes of an oversized command TLV still to be discarded.
    skip: usize,
    events: Deque<TcatEvent, 4>,
}

impl<B: CryptoBackend, const RX: usize> core::fmt::Debug for TcatAgent<B, RX> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TcatAgent")
            .field("state", &self.state)
            .finish_non_exhaustive()
    }
}

fn check_auth_field(field: &[u8], commissioner: bool) -> Result<[u8; AUTH_FIELD_LEN]> {
    let f: [u8; AUTH_FIELD_LEN] = field
        .get(..AUTH_FIELD_LEN)
        .and_then(|f| f.try_into().ok())
        .ok_or(Error::Parse)?;
    let c = f[0] & HEADER_COMMISSIONER != 0;
    if c != commissioner || f[0] >> HEADER_VERSION_SHIFT == 0 {
        return Err(Error::Parse);
    }
    Ok(f)
}

fn name(v: Option<&[u8]>) -> Result<Option<Vec<u8, MAX_NAME_LEN>>> {
    v.map(|n| Vec::from_slice(n).map_err(|_| Error::Parse))
        .transpose()
}

impl<B: CryptoBackend, const RX: usize> TcatAgent<B, RX> {
    /// A disabled agent.
    pub fn new(crypto: B) -> Self {
        Self {
            crypto,
            state: TcatState::Disabled,
            peer: PeerInfo::default(),
            challenge: None,
            pskd_verified: false,
            pskc_verified: false,
            commissioned_at_start: false,
            dataset_written: false,
            rx: Vec::new(),
            skip: 0,
            events: Deque::new(),
        }
    }

    /// The state.
    pub fn state(&self) -> TcatState {
        self.state
    }

    /// The next notification.
    pub fn pop_event(&mut self) -> Option<TcatEvent> {
        self.events.pop_front()
    }

    fn event(&mut self, e: TcatEvent) {
        if self.events.is_full() {
            self.events.pop_front();
        }
        let _ = self.events.push_back(e);
    }

    /// Accept TCAT links (OT `Start`).
    pub fn start(&mut self) {
        if self.state == TcatState::Disabled {
            self.state = TcatState::Enabled;
        }
    }

    /// Stop accepting TCAT links; a connected link is closed (OT `Stop`).
    pub fn stop<T: TcatSecureTransport + ?Sized>(&mut self, transport: &mut T) {
        if self.state == TcatState::Connected {
            transport.disconnect();
            self.disconnected();
        }
        self.state = TcatState::Disabled;
    }

    /// The TLS layer authenticated a Commissioner: `peer` and `own` are the
    /// Thread extensions of its and the Device's certificate. Checks the
    /// authorization headers (C flag 1 / 0, version >= 1, section 13.8.6);
    /// on an error the TLS layer must abort the link.
    pub fn connected<E: TcatEnv + ?Sized>(
        &mut self,
        env: &E,
        peer: &CertificateClaims<'_>,
        own: &CertificateClaims<'_>,
    ) -> Result<()> {
        if self.state != TcatState::Enabled {
            return Err(Error::InvalidState);
        }
        self.peer = PeerInfo {
            auth: check_auth_field(peer.authorization, true)?,
            own: check_auth_field(own.authorization, false)?,
            network_name: name(peer.network_name)?,
            ext_pan_id: peer.ext_pan_id,
            domain_name: name(peer.domain_name)?,
        };
        self.reset_link();
        // Set Active Dataset is refused if the device had a complete
        // dataset when the link started (section 13.9.4.11).
        self.commissioned_at_start = Dataset::from_tlvs_unchecked(env.active_dataset())
            .is_ok_and(|d| d.contains_all_required_for(DatasetType::Active));
        self.state = TcatState::Connected;
        self.event(TcatEvent::Connected);
        Ok(())
    }

    /// The link ended (closed by either side or failed).
    pub fn disconnected(&mut self) {
        if self.state != TcatState::Connected {
            return;
        }
        self.state = TcatState::Enabled;
        let dataset_written = self.dataset_written;
        self.reset_link();
        self.event(TcatEvent::Disconnected { dataset_written });
    }

    fn reset_link(&mut self) {
        self.challenge = None;
        self.pskd_verified = false;
        self.pskc_verified = false;
        self.dataset_written = false;
        self.rx.as_mut_slice().zeroize();
        self.rx.clear();
        self.skip = 0;
    }

    /// Application data received over the TLS session: complete command
    /// TLVs are executed and answered through `transport`; `out` is the
    /// scratch buffer for a response (its size bounds response payloads).
    pub fn handle_received<R, E, T>(
        &mut self,
        rng: &mut R,
        env: &mut E,
        transport: &mut T,
        mut data: &[u8],
        out: &mut [u8],
    ) where
        R: CryptoRng + ?Sized,
        E: TcatEnv + ?Sized,
        T: TcatSecureTransport + ?Sized,
    {
        while !data.is_empty() && self.state == TcatState::Connected {
            if self.skip > 0 {
                let n = self.skip.min(data.len());
                self.skip -= n;
                data = &data[n..];
                continue;
            }
            let room = RX - self.rx.len();
            let n = room.min(data.len());
            let _ = self.rx.extend_from_slice(&data[..n]);
            data = &data[n..];
            self.process_buffered(rng, env, transport, out);
            if self.rx.len() == RX {
                // A command TLV larger than the buffer: answer and discard.
                let total = tlv_total_len(&self.rx).unwrap_or(RX);
                self.skip = total.saturating_sub(RX);
                self.rx.as_mut_slice().zeroize();
                self.rx.clear();
                self.send_status(transport, out, Status::ValueError);
            }
        }
    }

    fn process_buffered<R, E, T>(
        &mut self,
        rng: &mut R,
        env: &mut E,
        transport: &mut T,
        out: &mut [u8],
    ) where
        R: CryptoRng + ?Sized,
        E: TcatEnv + ?Sized,
        T: TcatSecureTransport + ?Sized,
    {
        while self.state == TcatState::Connected {
            let Some(total) = tlv_total_len(&self.rx).filter(|&t| t <= self.rx.len()) else {
                return;
            };
            let mut cmd = [0u8; RX];
            cmd[..total].copy_from_slice(&self.rx[..total]);
            self.rx.rotate_left(total);
            let keep = self.rx.len() - total;
            // Wipe the consumed command (now at the end) before dropping it.
            self.rx[keep..].zeroize();
            self.rx.truncate(keep);
            if let Ok((tlv, _)) = Tlv::parse(&cmd[..total]) {
                self.execute(rng, env, transport, tlv.ty(), tlv.value(), out);
            }
            // Commands may carry the Network Key or secrets.
            cmd.zeroize();
        }
    }

    /// Section 13.12.1: may the connected Commissioner run command `t`?
    /// `value` is the command's payload (the dataset of Set Active
    /// Dataset is matched instead of the current one).
    pub fn is_authorized<E: TcatEnv + ?Sized>(&self, env: &E, t: u8, value: &[u8]) -> bool {
        if self.state != TcatState::Connected {
            return false;
        }
        let class = CommandClass::of(t);
        if class == CommandClass::General {
            return true;
        }
        let Some(i) = class.flags_index() else {
            return false;
        };
        let (c, d) = (self.peer.auth[1 + i], self.peer.own[1 + i]);
        if c & flag::ACCESS == 0 {
            return false;
        }
        let mut a = d & flag::ACCESS != 0;
        for j in 1..8 {
            let m = 1u8 << j;
            if c & m != 0 && !self.method_ok(env, m, t, value) {
                return false;
            }
        }
        for j in 1..8 {
            let m = 1u8 << j;
            if d & m != 0 && self.method_ok(env, m, t, value) {
                a = true;
            }
        }
        a
    }

    /// Table 13-9: is authorization method `m` satisfied?
    fn method_ok<E: TcatEnv + ?Sized>(&self, env: &E, m: u8, t: u8, value: &[u8]) -> bool {
        // Set Active Dataset matches against the dataset it writes
        // (sections 13.9.4.11, 13.10.1.2).
        let dataset = if t == ty::SET_ACTIVE_DATASET {
            value
        } else {
            env.active_dataset()
        };
        match m {
            flag::PSKD => self.pskd_verified,
            flag::NETWORK_NAME => self.peer.network_name.as_ref().is_some_and(|n| {
                Tlvs(dataset)
                    .value(meshcop_ty::NETWORK_NAME)
                    .is_ok_and(|v| v == n.as_slice())
            }),
            flag::EXT_PAN_ID => self.peer.ext_pan_id.is_some_and(|x| {
                Tlvs(dataset)
                    .value(meshcop_ty::EXT_PAN_ID)
                    .is_ok_and(|v| v == x)
            }),
            flag::THREAD_DOMAIN => self
                .peer
                .domain_name
                .as_ref()
                .is_some_and(|n| n.as_slice() == env.domain_name()),
            flag::PSKC => {
                self.pskc_verified
                    || (t == ty::SET_ACTIVE_DATASET
                        && !Tlvs(env.active_dataset()).contains(meshcop_ty::PSKC))
            }
            // Reserved methods always fail.
            _ => false,
        }
    }

    fn execute<R, E, T>(
        &mut self,
        rng: &mut R,
        env: &mut E,
        transport: &mut T,
        t: u8,
        value: &[u8],
        out: &mut [u8],
    ) where
        R: CryptoRng + ?Sized,
        E: TcatEnv + ?Sized,
        T: TcatSecureTransport + ?Sized,
    {
        if !is_supported(t) {
            self.send_status(transport, out, Status::Unsupported);
            return;
        }
        if !self.is_authorized(env, t, value) {
            self.send_status(transport, out, Status::Unauthorized);
            return;
        }
        if t == ty::DISCONNECT {
            // No response (section 13.9.4.2).
            transport.disconnect();
            self.disconnected();
            return;
        }
        let r = {
            let payload = out.get_mut(4..).unwrap_or(&mut []);
            self.run(rng, env, &*transport, t, value, payload)
        };
        match r {
            Ok(Some(n)) => self.send_payload(transport, out, n),
            Ok(None) => self.send_status(transport, out, Status::Success),
            Err(s) => self.send_status(transport, out, s),
        }
    }

    /// Execute an authorized command: `Ok(Some(n))` answers with the
    /// payload `out[..n]`, `Ok(None)` with Success.
    fn run<R, E, T>(
        &mut self,
        rng: &mut R,
        env: &mut E,
        transport: &T,
        t: u8,
        value: &[u8],
        out: &mut [u8],
    ) -> EnvResult<Option<usize>>
    where
        R: CryptoRng + ?Sized,
        E: TcatEnv + ?Sized,
        T: TcatSecureTransport + ?Sized,
    {
        match t {
            ty::GET_NETWORK_NAME => copy_out(
                out,
                Tlvs(env.active_dataset())
                    .value(meshcop_ty::NETWORK_NAME)
                    .ok(),
            ),
            ty::GET_EXT_PAN_ID => copy_out(
                out,
                Tlvs(env.active_dataset())
                    .value(meshcop_ty::EXT_PAN_ID)
                    .ok(),
            ),
            ty::PING => {
                if value.len() > MAX_PING_LEN {
                    return Err(Status::ValueError);
                }
                copy_out(out, Some(value))
            }
            ty::GET_DEVICE_ID => {
                let n = env.device_id(out);
                if n == 0 {
                    return Err(Status::Undefined);
                }
                Ok(Some(n))
            }
            ty::GET_PROVISIONING_URL => copy_out(out, env.provisioning_url()),
            ty::REQUEST_RANDOM_CHALLENGE => {
                let mut c = [0u8; CHALLENGE_LEN];
                rng.fill_bytes(&mut c);
                self.challenge = Some(c);
                copy_out(out, Some(&c))
            }
            ty::PRESENT_PSKD_HASH | ty::PRESENT_INSTALL_CODE_HASH | ty::PRESENT_PSKC_HASH => {
                let ok = match t {
                    ty::PRESENT_PSKD_HASH => env
                        .pskd()
                        .is_some_and(|k| self.verify_hash(transport, k.as_bytes(), value)),
                    ty::PRESENT_INSTALL_CODE_HASH => env
                        .install_code()
                        .is_some_and(|k| self.verify_hash(transport, k, value)),
                    _ => Tlvs(env.active_dataset())
                        .pskc()
                        .is_ok_and(|k| self.verify_hash(transport, &k.0, value)),
                };
                // The most recent presentation counts (Table 13-9); an
                // install code grants the PSKd rights.
                if t == ty::PRESENT_PSKC_HASH {
                    self.pskc_verified = ok;
                } else {
                    self.pskd_verified = ok;
                }
                if ok { Ok(None) } else { Err(Status::HashError) }
            }
            ty::REQUEST_PSKD_HASH => {
                let challenge: [u8; CHALLENGE_LEN] =
                    value.try_into().map_err(|_| Status::ParseError)?;
                let pskd = env.pskd().ok_or(Status::GeneralError)?;
                let h = self.hash(transport, pskd.as_bytes(), &challenge);
                copy_out(out, Some(&h))
            }
            ty::SET_ACTIVE_DATASET => {
                if self.commissioned_at_start {
                    return Err(Status::InvalidState);
                }
                let d = Dataset::from_tlvs(value).map_err(|_| Status::ParseError)?;
                if !d.contains(meshcop_ty::NETWORK_KEY) {
                    return Err(Status::ValueError);
                }
                env.set_active_dataset(d.as_bytes())?;
                env.store_commissioner_certificate(transport.peer_certificate_der())?;
                self.dataset_written = true;
                self.event(TcatEvent::ActiveDatasetSet);
                Ok(None)
            }
            ty::GET_COMMISSIONER_CERTIFICATE => copy_out(out, env.commissioner_certificate()),
            ty::GET_DIAGNOSTIC_TLVS => {
                let n = env.diagnostic_tlvs(value, out)?;
                Ok((n > 0).then_some(n))
            }
            ty::START_THREAD_INTERFACE => {
                if !Tlvs(env.active_dataset()).contains(meshcop_ty::NETWORK_KEY) {
                    return Err(Status::InvalidState);
                }
                env.start_thread()?;
                self.dataset_written = false;
                Ok(None)
            }
            ty::STOP_THREAD_INTERFACE => env.stop_thread().map(|()| None),
            ty::GET_ACTIVE_DATASET => {
                let a = env.active_dataset();
                if a.is_empty() {
                    return Err(Status::Undefined);
                }
                copy_out(out, Some(a))
            }
            ty::DECOMMISSION => {
                env.store_commissioner_certificate(transport.peer_certificate_der())?;
                env.decommission()?;
                self.pskc_verified = false;
                self.event(TcatEvent::Decommissioned);
                Ok(None)
            }
            ty::GET_APPLICATION_LAYERS => env.application_layers(out).map(Some),
            ty::SEND_APPLICATION_DATA_1..=ty::SEND_APPLICATION_DATA_4 => {
                env.application_data(t - ty::GET_APPLICATION_LAYERS, value, out)
            }
            ty::VENDOR_SPECIFIC => env.vendor_specific(value, out),
            _ => Err(Status::Unsupported),
        }
    }

    /// `HMAC-SHA256(key, challenge || device subjectPublicKeyInfo)`
    /// (section 13.9.4.6).
    fn hash<T: TcatSecureTransport + ?Sized>(
        &self,
        transport: &T,
        key: &[u8],
        challenge: &[u8; CHALLENGE_LEN],
    ) -> [u8; HASH_LEN] {
        let mut h = self.crypto.hmac_sha256(key);
        h.update(challenge);
        h.update(transport.own_public_key_info());
        h.finalize()
    }

    fn verify_hash<T: TcatSecureTransport + ?Sized>(
        &self,
        transport: &T,
        key: &[u8],
        presented: &[u8],
    ) -> bool {
        let Some(c) = self.challenge else {
            return false;
        };
        if presented.len() != HASH_LEN {
            return false;
        }
        let mut h = self.hash(transport, key, &c);
        let ok = bool::from(h.ct_eq(presented));
        h.zeroize();
        ok
    }

    fn send_status<T: TcatSecureTransport + ?Sized>(
        &mut self,
        transport: &mut T,
        out: &mut [u8],
        s: Status,
    ) {
        let r = {
            let mut w = Writer::new(out);
            rs_thread_core::tlv::write(&mut w, ty::RESPONSE_WITH_STATUS, &[s as u8])
                .map(|()| w.written().len())
        };
        if let Ok(n) = r {
            let _ = transport.send(&out[..n]);
        }
    }

    /// Frame `out[4..4 + n]` as a Response With Payload and send it; the
    /// buffer is wiped afterwards (it may hold the Network Key).
    fn send_payload<T: TcatSecureTransport + ?Sized>(
        &mut self,
        transport: &mut T,
        out: &mut [u8],
        n: usize,
    ) {
        if 4 + n > out.len() || n > usize::from(u16::MAX) {
            self.send_status(transport, out, Status::GeneralError);
            return;
        }
        let start = if n <= BASE_MAX_LENGTH {
            out[2] = ty::RESPONSE_WITH_PAYLOAD;
            out[3] = n as u8;
            2
        } else {
            out[0] = ty::RESPONSE_WITH_PAYLOAD;
            out[1] = EXTENDED_LENGTH;
            out[2..4].copy_from_slice(&(n as u16).to_be_bytes());
            0
        };
        let _ = transport.send(&out[start..4 + n]);
        out[..4 + n].zeroize();
    }
}

/// Is `t` a command the engine implements (others are answered with
/// Unsupported before authorization, section 13.9.2)?
const fn is_supported(t: u8) -> bool {
    matches!(
        t,
        ty::GET_NETWORK_NAME
            | ty::DISCONNECT
            | ty::PING
            | ty::GET_DEVICE_ID
            | ty::GET_EXT_PAN_ID
            | ty::GET_PROVISIONING_URL
            | ty::PRESENT_PSKD_HASH
            | ty::PRESENT_PSKC_HASH
            | ty::PRESENT_INSTALL_CODE_HASH
            | ty::REQUEST_RANDOM_CHALLENGE
            | ty::REQUEST_PSKD_HASH
            | ty::SET_ACTIVE_DATASET
            | ty::GET_COMMISSIONER_CERTIFICATE
            | ty::GET_DIAGNOSTIC_TLVS
            | ty::START_THREAD_INTERFACE
            | ty::STOP_THREAD_INTERFACE
            | ty::GET_ACTIVE_DATASET
            | ty::DECOMMISSION
            | ty::GET_APPLICATION_LAYERS
            | ty::SEND_APPLICATION_DATA_1
            ..=ty::SEND_APPLICATION_DATA_4 | ty::VENDOR_SPECIFIC
    )
}

/// Total size of the TLV at the start of `b` once its header is complete.
fn tlv_total_len(b: &[u8]) -> Option<usize> {
    match *b.get(1)? {
        EXTENDED_LENGTH => {
            let len = u16::from_be_bytes([*b.get(2)?, *b.get(3)?]);
            Some(4 + usize::from(len))
        }
        len => Some(2 + usize::from(len)),
    }
}

/// Copy `v` to `out` as the response payload (`Undefined` if absent).
fn copy_out(out: &mut [u8], v: Option<&[u8]>) -> EnvResult<Option<usize>> {
    let v = v.ok_or(Status::Undefined)?;
    out.get_mut(..v.len())
        .ok_or(Status::GeneralError)?
        .copy_from_slice(v);
    Ok(Some(v.len()))
}
