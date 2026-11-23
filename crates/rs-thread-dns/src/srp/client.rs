//! SRP client (RFC 9665 Service Registration Protocol; Thread 1.3/1.4
//! section on SRP; OT `Srp::Client`).
//!
//! The client registers one host (name, AAAA addresses, ECDSA P-256 public
//! key) and any number of DNS-SD services (instance, service type with
//! optional subtypes, port, priority, weight, TXT) with an SRP server using a
//! single signed DNS UPDATE message (SIG(0), RFC 2931; EDNS(0) Update Lease
//! option, RFC 9664). Names are given without the domain; the domain
//! defaults to `default.service.arpa`.
//!
//! # Driving the client
//!
//! Every method takes an [`Env`] (see [`SrpEnv`]): the current time, an RNG,
//! the crypto backend (SHA-256 + ECDSA P-256) and an [`SrpContext`] that
//! receives outgoing datagrams and [`SrpEvent`]s and provides the host
//! addresses and the persisted key / server.
//!
//! - configure: [`SrpClient::set_host_name`],
//!   [`SrpClient::enable_auto_host_address`] or
//!   [`SrpClient::set_host_addresses`], [`SrpClient::add_service`];
//! - start: [`SrpClient::start`] with an explicit server, or
//!   [`SrpClient::enable_auto_start`] and feed Network Data changes to
//!   [`SrpClient::handle_network_data`] (preference: unicast with the
//!   address in the service data, anycast with the highest sequence number,
//!   unicast with the address in the server data);
//! - feed datagrams from the server to [`SrpClient::handle_datagram`];
//! - call [`SrpClient::poll`] at [`SrpClient::next_deadline`];
//! - tell the client about attach / detach ([`SrpClient::set_attached`])
//!   and about address changes ([`SrpClient::on_addresses_changed`]).
//!
//! # Using it for Matter (rs-matter)
//!
//! Register `_matter._tcp` with the compressed fabric id and node id as
//! instance name (`<CFID>-<NodeId>`, 16 + 1 + 16 hex digits), the operational
//! subtypes as `sub_types`, port 5540 and the TXT entries rs-matter wants
//! (`SII`, `SAI`, `SAT`, `T`), plus `_matterc._udp` with a `_L<disc>` /
//! `_S<short disc>` subtypes while commissioning. Use the ML-EID / OMR
//! addresses ([`SrpContext::auto_addresses`]) and call
//! `DnsClient::set_default_server` with the server from
//! [`SrpEvent::ServerSelected`] to browse and resolve peers.

use core::net::{Ipv6Addr, SocketAddrV6};

use heapless::{String, Vec};
use rs_thread_core::crypto::ecdsa::{EcdsaP256, PUBLIC_KEY_LEN, SecretKey};
use rs_thread_core::crypto::{CryptoBackend, Sha256};
use rs_thread_core::time::{Duration, Instant};
use rs_thread_core::{Error, Result};
use rand_core::{CryptoRng, Rng};
use zeroize::Zeroize;

use super::discovery::{
    ANYCAST_SERVER_PORT, AnycastInfo, NetDataService, UnicastInfo, UnicastType, anycast_entries,
    preferred_anycast, unicast_entries,
};
use crate::rdata::{LeaseOption, TxtEntry, encode_txt};
use crate::rdata::{MAX_LABEL, MAX_TXT};
use crate::wire::{Header, Parser, Part, Writer, class, opcode, rcode, rtype};

/// Default domain.
pub const DEFAULT_DOMAIN: &str = "default.service.arpa";
/// Default lease in seconds (OT: 2 hours).
pub const DEFAULT_LEASE: u32 = 2 * 60 * 60;
/// Default key lease in seconds (OT: 14 days).
pub const DEFAULT_KEY_LEASE: u32 = 14 * 24 * 60 * 60;
/// Renew this many seconds before the lease expires.
pub const LEASE_RENEW_GUARD: u32 = 120;
/// Largest lease interval (OT `kMaxLease`).
pub const MAX_LEASE: u32 = 0x7fff_ffff / 1000 - 1;
/// Initial and minimum retry wait in ms.
pub const MIN_RETRY_WAIT_MS: u32 = 1800;
/// Maximum retry wait in ms (1 hour).
pub const MAX_RETRY_WAIT_MS: u32 = 3_600_000;
/// Retry wait jitter in ms (plus / minus).
pub const RETRY_JITTER_MS: u32 = 500;
/// Quick retries after a transmit failure.
pub const MAX_TX_FAILURE_RETRIES: u8 = 8;
/// Interval of the quick retries in ms.
pub const TX_FAILURE_RETRY_MS: u32 = 250;
/// Consecutive response timeouts before switching the server.
pub const MAX_TIMEOUT_FAILURES_TO_SWITCH_SERVER: u8 = 3;
/// UDP payload size announced in the OPT record (1280 - IPv6 - UDP).
pub const UDP_PAYLOAD_SIZE: u16 = 1232;
/// Longest host name (without the domain).
pub const MAX_HOST_NAME: usize = 64;
/// Longest service type (without the domain), e.g. `_matter._tcp`.
pub const MAX_SERVICE_NAME: usize = 64;
/// Subtypes per service.
pub const MAX_SUBTYPES: usize = 6;
/// Host addresses.
pub const MAX_HOST_ADDRS: usize = 4;
/// Server candidates remembered per kind for server switching.
pub const MAX_SERVERS: usize = 8;

const LEASE_RENEW_JITTER_MS: u32 = 15_000;
const MIN_TX_JITTER_MS: u32 = 10;
const MAX_TX_JITTER_DEFAULT_MS: u32 = 500;
const GUARD_AFTER_ATTACH_MS: u64 = 1000;

/// Handle of a registered service.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct ServiceId(pub u8);

/// A service to register.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceConfig {
    /// Service type without domain, e.g. `_matter._tcp`.
    pub service_name: String<MAX_SERVICE_NAME>,
    /// Instance label.
    pub instance_name: String<MAX_LABEL>,
    /// Subtype labels (without `._sub`).
    pub sub_types: Vec<String<MAX_LABEL>, MAX_SUBTYPES>,
    /// Port.
    pub port: u16,
    /// Priority.
    pub priority: u16,
    /// Weight.
    pub weight: u16,
    /// Encoded TXT rdata (empty: a single empty string is sent).
    pub txt: Vec<u8, MAX_TXT>,
    /// Lease in seconds (0: client default).
    pub lease: u32,
    /// Key lease in seconds (0: client default).
    pub key_lease: u32,
}

impl ServiceConfig {
    /// A service without subtypes or TXT entries.
    pub fn new(service_name: &str, instance_name: &str, port: u16) -> Result<Self> {
        if service_name.is_empty() || instance_name.is_empty() {
            return Err(Error::InvalidArgs);
        }
        Ok(Self {
            service_name: String::try_from(service_name).map_err(|_| Error::InvalidArgs)?,
            instance_name: String::try_from(instance_name).map_err(|_| Error::InvalidArgs)?,
            sub_types: Vec::new(),
            port,
            priority: 0,
            weight: 0,
            txt: Vec::new(),
            lease: 0,
            key_lease: 0,
        })
    }

    /// Add a subtype label.
    pub fn add_sub_type(&mut self, label: &str) -> Result<()> {
        let l = String::try_from(label).map_err(|_| Error::InvalidArgs)?;
        self.sub_types.push(l).map_err(|_| Error::NoBufs)
    }

    /// Set the TXT data from entries.
    pub fn set_txt_entries(&mut self, entries: &[TxtEntry<'_>]) -> Result<()> {
        let mut buf = [0u8; MAX_TXT];
        let n = encode_txt(entries, &mut buf)?;
        self.txt.clear();
        self.txt
            .extend_from_slice(&buf[..n])
            .map_err(|_| Error::NoBufs)
    }
}

/// State of the host or of a service (OT `ItemState`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum ItemState {
    /// To be added.
    ToAdd,
    /// Add sent, waiting for the response.
    Adding,
    /// To be refreshed.
    ToRefresh,
    /// Refresh sent.
    Refreshing,
    /// To be removed.
    ToRemove,
    /// Removal sent.
    Removing,
    /// Registered with the server.
    Registered,
    /// Removed.
    Removed,
}

use ItemState::*;

type StateTable = [ItemState; 8];

const ON_TX: StateTable = [
    Adding, Adding, Refreshing, Refreshing, Removing, Removing, Registered, Removed,
];
const ON_DONE: StateTable = [
    ToAdd, Registered, ToRefresh, Registered, ToRemove, Removed, Registered, Removed,
];
const ON_STOP: StateTable = [
    ToAdd, ToRefresh, ToRefresh, ToRefresh, ToRemove, ToRemove, ToRefresh, Removed,
];
const ON_PAUSE: StateTable = [
    ToAdd, ToRefresh, ToRefresh, ToRefresh, ToRemove, ToRemove, Registered, Removed,
];

/// Client state (OT `Client::State`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum ClientState {
    /// Not started.
    Stopped,
    /// Started but detached from the Thread network.
    Paused,
    /// An update is pending (waiting for the tx jitter).
    ToUpdate,
    /// Update sent, waiting for the response.
    Updating,
    /// Everything registered, waiting for the next lease refresh.
    Updated,
    /// Sending failed or was rejected; retry pending.
    ToRetry,
}

/// Why an update failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum SrpError {
    /// Server could not parse the message (FORMERR, BADNAME, ...).
    Parse,
    /// Server failure.
    Failed,
    /// NXDOMAIN / NXRRSET.
    NotFound,
    /// Server does not support UPDATE.
    NotImplemented,
    /// BADALG.
    NotCapable,
    /// YXDOMAIN / YXRRSET: the host or a service instance name is already
    /// used by another key; choose another name.
    NameConflict,
    /// REFUSED / NOTAUTH.
    Refused,
    /// No response in time.
    ResponseTimeout,
    /// The update message could not be built or sent.
    Tx(Error),
}

fn rcode_to_error(rc: u8) -> Option<SrpError> {
    Some(match rc {
        rcode::SUCCESS => return None,
        rcode::FORMAT_ERROR | rcode::BAD_NAME | rcode::BAD_TRUNCATION | rcode::NOT_ZONE => {
            SrpError::Parse
        }
        rcode::NAME_ERROR | rcode::RECORD_NOT_EXISTS => SrpError::NotFound,
        rcode::NOT_IMPLEMENTED => SrpError::NotImplemented,
        rcode::BAD_ALG => SrpError::NotCapable,
        rcode::NAME_EXISTS | rcode::RECORD_EXISTS => SrpError::NameConflict,
        rcode::REFUSED | rcode::NOT_AUTH => SrpError::Refused,
        _ => SrpError::Failed,
    })
}

/// Events reported to the application.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SrpEvent {
    /// Auto-start selected a server (`Some`, the client started) or lost it
    /// (`None`, the client stopped). Use it as the default DNS server.
    ServerSelected(Option<SocketAddrV6>),
    /// The server accepted the update; granted lease and key lease.
    Registered {
        /// Lease in seconds.
        lease: u32,
        /// Key lease in seconds.
        key_lease: u32,
    },
    /// The host (and all its services) was removed.
    HostRemoved,
    /// A removed service was dropped from the client.
    ServiceRemoved(ServiceId),
    /// An update failed (it is retried with backoff unless the cause is
    /// fixed by the application, e.g. [`SrpError::NameConflict`]).
    Failed(SrpError),
}

/// Outputs and platform services of the client.
pub trait SrpContext {
    /// Send a UDP datagram to the SRP server.
    fn send(&mut self, server: SocketAddrV6, payload: &[u8]) -> Result<()>;

    /// Report an event.
    fn event(&mut self, event: SrpEvent);

    /// Append the Thread interface addresses to register: valid, preferred,
    /// not link-local, not mesh-local (see [`filter_auto_addresses`]). If
    /// none is appended the client registers [`SrpContext::ml_eid`].
    fn auto_addresses(&mut self, out: &mut Vec<Ipv6Addr, MAX_HOST_ADDRS>);

    /// The mesh-local EID.
    fn ml_eid(&mut self) -> Ipv6Addr;

    /// Load the persisted ECDSA key (OT settings key `SrpEcdsaKey`).
    fn load_key(&mut self) -> Option<SecretKey> {
        None
    }

    /// Persist a newly generated key.
    fn store_key(&mut self, _key: &SecretKey) {}

    /// Load the server that was last registered with (OT `SrpClientInfo`).
    fn load_server(&mut self) -> Option<SocketAddrV6> {
        None
    }

    /// Persist (`Some`) or forget (`None`, anycast) the registered server.
    fn store_server(&mut self, _server: Option<SocketAddrV6>) {}
}

/// Everything a client call needs besides its own state.
pub trait Env {
    /// RNG (jitter and key generation).
    type Rng: CryptoRng + ?Sized;
    /// SHA-256 and ECDSA P-256.
    type Crypto: CryptoBackend + EcdsaP256;
    /// Outputs.
    type Ctx: SrpContext;

    /// Current time.
    fn now(&self) -> Instant;

    /// Split into the pieces.
    fn parts(&mut self) -> (&mut Self::Rng, &Self::Crypto, &mut Self::Ctx);
}

/// The plain [`Env`].
#[derive(Debug)]
pub struct SrpEnv<'a, R: ?Sized, C, X> {
    /// Current time.
    pub now: Instant,
    /// RNG.
    pub rng: &'a mut R,
    /// Crypto backend.
    pub crypto: &'a C,
    /// Context.
    pub ctx: &'a mut X,
}

impl<R, C, X> Env for SrpEnv<'_, R, C, X>
where
    R: CryptoRng + ?Sized,
    C: CryptoBackend + EcdsaP256,
    X: SrpContext,
{
    type Rng = R;
    type Crypto = C;
    type Ctx = X;

    fn now(&self) -> Instant {
        self.now
    }

    fn parts(&mut self) -> (&mut R, &C, &mut X) {
        (&mut *self.rng, self.crypto, &mut *self.ctx)
    }
}

/// Collect the addresses to register from `(address, preferred)` pairs of
/// valid interface addresses: preferred, not link-local, not mesh-local (OT
/// `ShouldHostAutoAddressRegister`).
pub fn filter_auto_addresses(
    addrs: impl Iterator<Item = (Ipv6Addr, bool)>,
    is_mesh_local: impl Fn(&Ipv6Addr) -> bool,
    out: &mut Vec<Ipv6Addr, MAX_HOST_ADDRS>,
) {
    for (a, preferred) in addrs {
        let link_local = a.segments()[0] & 0xffc0 == 0xfe80;
        if preferred && !link_local && !is_mesh_local(&a) {
            let _ = out.push(a);
        }
    }
}

// ------------------------------------------------------------------ internals

#[derive(Debug, Clone)]
struct ServiceSlot {
    cfg: ServiceConfig,
    state: ItemState,
    appended: bool,
    renew_time: Instant,
}

#[derive(Debug, Clone)]
struct HostInfo {
    name: String<MAX_HOST_NAME>,
    state: ItemState,
    auto: bool,
    addrs: Vec<Ipv6Addr, MAX_HOST_ADDRS>,
}

impl HostInfo {
    const fn new() -> Self {
        Self {
            name: String::new(),
            state: ToAdd,
            auto: false,
            addrs: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AutoState {
    Disabled,
    FirstTimeSelecting,
    Reselecting,
    SelectedUnicastPreferred,
    SelectedAnycast,
    SelectedUnicast,
}

impl AutoState {
    fn has_selected(self) -> bool {
        !matches!(
            self,
            Self::Disabled | Self::FirstTimeSelecting | Self::Reselecting
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Requester {
    User,
    Auto,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum JitterReason {
    DeviceReboot,
    ServerStart,
    ServerRestart,
    ServerSwitch,
    SlaacAddr,
}

impl JitterReason {
    fn max_ms(self) -> u32 {
        match self {
            Self::DeviceReboot => 700,
            _ => 10_000,
        }
    }
}

#[derive(Debug, Clone, Default)]
struct Snapshot {
    preferred: Vec<UnicastInfo, MAX_SERVERS>,
    in_server_data: Vec<UnicastInfo, MAX_SERVERS>,
    anycast: Option<AnycastInfo>,
}

fn serial_less16(a: u16, b: u16) -> bool {
    a != b && b.wrapping_sub(a) < 0x8000
}

fn range<R: Rng + ?Sized>(rng: &mut R, lo: u32, hi: u32) -> u32 {
    lo + rng.next_u32() % (hi - lo + 1)
}

fn add_jitter<R: Rng + ?Sized>(rng: &mut R, v: u32, j: u32) -> u32 {
    range(rng, v.saturating_sub(j), v.saturating_add(j))
}

fn ms(v: u32) -> Duration {
    Duration::from_millis(u64::from(v))
}

fn determine_lease(interval: u32, default: u32) -> u32 {
    MAX_LEASE.min(if interval != 0 { interval } else { default })
}

/// The SRP client with room for `S` services.
#[derive(Debug, Clone)]
pub struct SrpClient<const S: usize = 4> {
    state: ClientState,
    host: HostInfo,
    services: [Option<ServiceSlot>; S],
    domain: String<{ crate::rdata::MAX_NAME }>,
    server: Option<SocketAddrV6>,
    requester: Requester,
    auto: AutoState,
    anycast_seq: u8,
    timeout_failures: u8,
    guard_until: Option<Instant>,
    snapshot: Snapshot,
    key: Option<SecretKey>,
    timer: Option<Instant>,
    retry_wait_ms: u32,
    lease: u32,
    key_lease: u32,
    default_lease: u32,
    default_key_lease: u32,
    ttl: u32,
    next_msg_id: u16,
    response_msg_id: u16,
    tx_failure_retries: u8,
    single_service_mode: bool,
    should_remove_key_lease: bool,
    lease_renew_time: Instant,
    jitter_max: u32,
    jitter_time: Instant,
    registered_addrs: Vec<Ipv6Addr, MAX_HOST_ADDRS>,
}

impl<const S: usize> Default for SrpClient<S> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const S: usize> SrpClient<S> {
    /// A stopped client without host, services or key.
    pub fn new() -> Self {
        let mut domain = String::new();
        let _ = domain.push_str(DEFAULT_DOMAIN);
        Self {
            state: ClientState::Stopped,
            host: HostInfo::new(),
            services: [const { None }; S],
            domain,
            server: None,
            requester: Requester::User,
            auto: AutoState::Disabled,
            anycast_seq: 0,
            timeout_failures: 0,
            guard_until: None,
            snapshot: Snapshot::default(),
            key: None,
            timer: None,
            retry_wait_ms: MIN_RETRY_WAIT_MS,
            lease: 0,
            key_lease: 0,
            default_lease: DEFAULT_LEASE,
            default_key_lease: DEFAULT_KEY_LEASE,
            ttl: 0,
            next_msg_id: 0,
            response_msg_id: 0,
            tx_failure_retries: 0,
            single_service_mode: false,
            should_remove_key_lease: false,
            lease_renew_time: Instant::ZERO,
            jitter_max: 0,
            jitter_time: Instant::ZERO,
            registered_addrs: Vec::new(),
        }
    }

    // ---- accessors

    /// Client state.
    pub const fn state(&self) -> ClientState {
        self.state
    }

    /// The server in use.
    pub const fn server(&self) -> Option<SocketAddrV6> {
        self.server
    }

    /// The host name (empty until one is set, OT `otSrpClientGetHostInfo`).
    pub fn host_name(&self) -> &str {
        &self.host.name
    }

    /// Host state.
    pub const fn host_state(&self) -> ItemState {
        self.host.state
    }

    /// State of a service.
    pub fn service_state(&self, id: ServiceId) -> Option<ItemState> {
        self.services
            .get(usize::from(id.0))?
            .as_ref()
            .map(|s| s.state)
    }

    /// Default lease in seconds.
    pub const fn lease_interval(&self) -> u32 {
        self.default_lease
    }

    /// Default key lease in seconds.
    pub const fn key_lease_interval(&self) -> u32 {
        self.default_key_lease
    }

    /// Record TTL cap in seconds (0: the lease).
    pub const fn ttl(&self) -> u32 {
        self.ttl
    }

    /// Does the client register the interface addresses itself?
    pub const fn is_auto_host_address(&self) -> bool {
        self.host.auto
    }

    /// The configured host addresses (empty in auto address mode).
    pub fn host_addresses(&self) -> &[Ipv6Addr] {
        &self.host.addrs
    }

    /// Is server auto-start enabled?
    pub fn is_auto_start_enabled(&self) -> bool {
        self.auto != AutoState::Disabled
    }

    /// The services with their state, in the order they were added.
    pub fn services(&self) -> impl Iterator<Item = (ServiceId, &ServiceConfig, ItemState)> {
        self.services
            .iter()
            .enumerate()
            .filter_map(|(i, s)| s.as_ref().map(|s| (ServiceId(i as u8), &s.cfg, s.state)))
    }

    /// Did auto-start select the server (not an explicit `start`)?
    pub fn is_server_selected_by_auto_start(&self) -> bool {
        self.is_running() && self.requester == Requester::Auto
    }

    /// Is the client started (not stopped)?
    pub fn is_running(&self) -> bool {
        self.state != ClientState::Stopped
    }

    /// Next time [`SrpClient::poll`] has work to do.
    pub const fn next_deadline(&self) -> Option<Instant> {
        self.timer
    }

    /// Current retry wait interval in ms.
    pub const fn retry_wait_interval_ms(&self) -> u32 {
        self.retry_wait_ms
    }

    /// The public key (loads or generates the key pair).
    pub fn public_key<E: Env>(&mut self, env: &mut E) -> Result<[u8; PUBLIC_KEY_LEN]> {
        let k = self.ensure_key(env)?;
        env.parts().1.public_key(&k)
    }

    /// Use `key` as the key pair (e.g. restored by the application).
    pub fn set_key(&mut self, key: SecretKey) {
        self.key = Some(key);
    }

    /// Default lease (0: OT default 2 h).
    pub fn set_lease_interval(&mut self, secs: u32) {
        self.default_lease = determine_lease(secs, DEFAULT_LEASE);
    }

    /// Default key lease (0: OT default 14 d).
    pub fn set_key_lease_interval(&mut self, secs: u32) {
        self.default_key_lease = determine_lease(secs, DEFAULT_KEY_LEASE);
    }

    /// Record TTL cap in seconds (0: the lease).
    pub fn set_ttl(&mut self, secs: u32) {
        self.ttl = secs;
    }

    /// Set the domain (only before registration).
    pub fn set_domain(&mut self, domain: &str) -> Result<()> {
        if !matches!(self.host.state, ToAdd | Removed) {
            return Err(Error::InvalidState);
        }
        let d = domain.strip_suffix('.').unwrap_or(domain);
        self.domain = String::try_from(if d.is_empty() { DEFAULT_DOMAIN } else { d })
            .map_err(|_| Error::InvalidArgs)?;
        Ok(())
    }

    // ---- host and services

    /// Set the host name (only before registration or after removal).
    pub fn set_host_name<E: Env>(&mut self, env: &mut E, name: &str) -> Result<()> {
        if name.is_empty() {
            return Err(Error::InvalidArgs);
        }
        if !matches!(self.host.state, ToAdd | Removed) {
            return Err(Error::InvalidState);
        }
        self.host.name = String::try_from(name).map_err(|_| Error::InvalidArgs)?;
        self.host.state = ToAdd;
        self.update_state(env);
        Ok(())
    }

    /// Register the Thread interface addresses ([`SrpContext::auto_addresses`],
    /// falling back to the ML-EID) and follow their changes.
    pub fn enable_auto_host_address<E: Env>(&mut self, env: &mut E) -> Result<()> {
        if self.host.auto {
            return Ok(());
        }
        self.update_host_state_on_address_change()?;
        self.registered_addrs.clear();
        self.host.auto = true;
        self.update_state(env);
        Ok(())
    }

    /// Register explicit addresses.
    pub fn set_host_addresses<E: Env>(&mut self, env: &mut E, addrs: &[Ipv6Addr]) -> Result<()> {
        if addrs.is_empty() {
            return Err(Error::InvalidArgs);
        }
        let v = Vec::from_slice(addrs).map_err(|_| Error::InvalidArgs)?;
        self.update_host_state_on_address_change()?;
        self.host.addrs = v;
        self.host.auto = false;
        self.update_state(env);
        Ok(())
    }

    fn update_host_state_on_address_change(&mut self) -> Result<()> {
        match self.host.state {
            ToRemove | Removing => return Err(Error::InvalidState),
            Removed => self.host.state = ToAdd,
            ToAdd => {}
            _ => self.host.state = ToRefresh,
        }
        Ok(())
    }

    /// Add a service.
    pub fn add_service<E: Env>(&mut self, env: &mut E, cfg: ServiceConfig) -> Result<ServiceId> {
        if self.services.iter().flatten().any(|s| {
            s.cfg.instance_name.eq_ignore_ascii_case(&cfg.instance_name)
                && s.cfg.service_name.eq_ignore_ascii_case(&cfg.service_name)
        }) {
            return Err(Error::Already);
        }
        let i = self
            .services
            .iter()
            .position(Option::is_none)
            .ok_or(Error::NoBufs)?;
        self.services[i] = Some(ServiceSlot {
            cfg,
            state: ToAdd,
            appended: false,
            renew_time: Instant::ZERO,
        });
        self.update_state(env);
        Ok(ServiceId(i as u8))
    }

    /// Unregister a service (its slot is freed after the server confirms,
    /// see [`SrpEvent::ServiceRemoved`]).
    pub fn remove_service<E: Env>(&mut self, env: &mut E, id: ServiceId) -> Result<()> {
        let s = self
            .services
            .get_mut(usize::from(id.0))
            .and_then(Option::as_mut)
            .ok_or(Error::NotFound)?;
        if s.state != Removing {
            s.state = ToRemove;
        }
        self.update_state(env);
        Ok(())
    }

    /// Drop a service locally without telling the server.
    pub fn clear_service<E: Env>(&mut self, env: &mut E, id: ServiceId) -> Result<()> {
        let s = self
            .services
            .get_mut(usize::from(id.0))
            .ok_or(Error::NotFound)?;
        if s.take().is_none() {
            return Err(Error::NotFound);
        }
        self.update_state(env);
        Ok(())
    }

    /// Remove the host and all its services. With `remove_key_lease` the
    /// name is released entirely (key lease 0). A host that was never
    /// registered is only removed locally unless `send_unreg`.
    pub fn remove_host_and_services<E: Env>(
        &mut self,
        env: &mut E,
        remove_key_lease: bool,
        send_unreg: bool,
    ) -> Result<()> {
        if self.host.state == Removed {
            return Err(Error::Already);
        }
        if matches!(self.host.state, ToRemove | Removing)
            && self.should_remove_key_lease == remove_key_lease
        {
            return Ok(());
        }
        self.should_remove_key_lease = remove_key_lease;
        for s in self.services.iter_mut().flatten() {
            if s.state != Removing {
                s.state = ToRemove;
            }
        }
        if self.host.state == ToAdd && !send_unreg {
            self.host.state = Removed;
            for s in self.services.iter_mut().flatten() {
                s.state = Removed;
            }
            self.handle_update_done(env);
            return Ok(());
        }
        self.host.state = ToRemove;
        self.update_state(env);
        Ok(())
    }

    /// Forget the host and all services locally.
    pub fn clear_host_and_services(&mut self) {
        if matches!(
            self.state,
            ClientState::ToUpdate
                | ClientState::Updating
                | ClientState::Updated
                | ClientState::ToRetry
        ) {
            self.state = ClientState::Updated;
            self.timer = None;
        }
        self.tx_failure_retries = 0;
        self.retry_wait_ms = MIN_RETRY_WAIT_MS;
        self.services = [const { None }; S];
        self.host = HostInfo::new();
    }

    // ---- start / stop

    /// Start with an explicit server.
    pub fn start<E: Env>(&mut self, env: &mut E, server: SocketAddrV6) -> Result<()> {
        self.start_internal(env, server, Requester::User)
    }

    /// Stop; services return to their "to add" states so they are
    /// registered again after a restart. Disables auto-start.
    pub fn stop<E: Env>(&mut self, env: &mut E) {
        self.stop_internal(env, Requester::User, true);
    }

    /// Thread attach state: pause when detached, resume when attached.
    pub fn set_attached<E: Env>(&mut self, env: &mut E, attached: bool) {
        if attached {
            self.apply_guard_on_attach(env.now());
            if self.state == ClientState::Paused {
                self.resume(env);
            }
        } else if self.state != ClientState::Stopped {
            self.pause();
        }
    }

    /// The interface addresses changed: refresh the registration if the
    /// auto host addresses differ from the registered ones. `slaac`: a
    /// SLAAC address was added or removed, which asks for the longer
    /// transmit jitter (OT `HandleUnicastAddressEvent`).
    pub fn on_addresses_changed<E: Env>(&mut self, env: &mut E, slaac: bool) {
        if !self.host.auto {
            return;
        }
        let now = env.now();
        if slaac && self.is_running() && !self.guard_running(now) {
            self.request_jitter(JitterReason::SlaacAddr, now);
        }
        let cur = self.auto_address_list(env);
        if cur != self.registered_addrs {
            let _ = self.update_host_state_on_address_change();
            self.update_state(env);
        }
    }

    // ---- auto start

    /// Enable auto-start: select and follow a server from the Network Data.
    pub fn enable_auto_start<E: Env>(&mut self, env: &mut E) {
        if self.auto != AutoState::Disabled {
            return;
        }
        self.auto = AutoState::FirstTimeSelecting;
        self.apply_guard_on_attach(env.now());
        self.process_auto_start(env);
    }

    /// Disable auto-start (a running client keeps running).
    pub fn disable_auto_start(&mut self) {
        self.auto = AutoState::Disabled;
    }

    /// The Network Data (or the mesh-local prefix) changed: `entries` are
    /// all Server sub-TLVs of Service TLVs, `ml_prefix` the mesh-local
    /// prefix (for ALOC / RLOC derived server addresses).
    pub fn handle_network_data<'a, E, I>(&mut self, env: &mut E, entries: I, ml_prefix: [u8; 8])
    where
        E: Env,
        I: Iterator<Item = NetDataService<'a>> + Clone + 'a,
    {
        let mut snap = Snapshot::default();
        for u in unicast_entries(entries.clone(), ml_prefix, UnicastType::InServiceData) {
            let _ = snap.preferred.push(u);
        }
        for u in unicast_entries(entries.clone(), ml_prefix, UnicastType::InServerData) {
            let _ = snap.in_server_data.push(u);
        }
        let mut any: Vec<AnycastInfo, 16> = Vec::new();
        for a in anycast_entries(entries, ml_prefix) {
            let _ = any.push(a);
        }
        snap.anycast = preferred_anycast(&any);
        self.snapshot = snap;
        self.process_auto_start(env);
    }

    fn guard_running(&self, now: Instant) -> bool {
        self.guard_until.is_some_and(|g| now < g)
    }

    fn apply_guard_on_attach(&mut self, now: Instant) {
        if !self.is_running() && self.auto == AutoState::FirstTimeSelecting {
            self.guard_until =
                Some(now.saturating_add(Duration::from_millis(GUARD_AFTER_ATTACH_MS)));
        }
    }

    fn select_unicast<E: Env>(&mut self, env: &mut E, ty: UnicastType) -> Option<UnicastInfo> {
        let list = match ty {
            UnicastType::InServiceData => &self.snapshot.preferred,
            UnicastType::InServerData => &self.snapshot.in_server_data,
        };
        let saved = if self.is_running() {
            None
        } else {
            env.parts().2.load_server()
        };
        let mut best: Option<UnicastInfo> = None;
        for e in list {
            if self.auto.has_selected() && Some(e.addr) == self.server {
                return Some(*e);
            }
            if saved == Some(e.addr) {
                return Some(*e);
            }
            let better = match best {
                None => true,
                Some(b) => {
                    e.version > b.version || (e.version == b.version && e.addr.ip() < b.addr.ip())
                }
            };
            if better {
                best = Some(*e);
            }
        }
        best
    }

    fn process_auto_start<E: Env>(&mut self, env: &mut E) {
        if self.auto == AutoState::Disabled {
            return;
        }
        if self.is_running() && !self.auto.has_selected() {
            return;
        }
        let old = self.auto;
        let mut server: Option<SocketAddrV6> = None;
        let mut restart = false;
        if let Some(u) = self.select_unicast(env, UnicastType::InServiceData) {
            self.auto = AutoState::SelectedUnicastPreferred;
            server = Some(u.addr);
        } else if let Some(a) = self.snapshot.anycast {
            server = Some(SocketAddrV6::new(a.address, ANYCAST_SERVER_PORT, 0, 0));
            if self.auto != AutoState::SelectedAnycast || self.anycast_seq != a.sequence_number {
                restart = true;
                self.anycast_seq = a.sequence_number;
            }
            self.auto = AutoState::SelectedAnycast;
        } else if let Some(u) = self.select_unicast(env, UnicastType::InServerData) {
            self.auto = AutoState::SelectedUnicast;
            server = Some(u.addr);
        }
        if self.is_running() {
            if self.server == server && !restart {
                return;
            }
            self.stop_internal(env, Requester::Auto, true);
        }
        let Some(server) = server else {
            if self.auto.has_selected() {
                self.auto = AutoState::Reselecting;
            }
            return;
        };
        let now = env.now();
        match old {
            AutoState::Disabled => {}
            AutoState::FirstTimeSelecting => {
                let r = if self.guard_running(now) {
                    JitterReason::DeviceReboot
                } else {
                    JitterReason::ServerStart
                };
                self.request_jitter(r, now);
            }
            AutoState::Reselecting => self.request_jitter(JitterReason::ServerRestart, now),
            _ => self.request_jitter(JitterReason::ServerSwitch, now),
        }
        let _ = self.start_internal(env, server, Requester::Auto);
    }

    fn select_next_server<E: Env>(&mut self, env: &mut E, only_unregistered: bool) {
        if self.state == ClientState::Stopped {
            return;
        }
        let list = match self.auto {
            AutoState::SelectedUnicastPreferred => &self.snapshot.preferred,
            AutoState::SelectedUnicast => &self.snapshot.in_server_data,
            _ => return,
        };
        if only_unregistered && !matches!(self.host.state, Adding | ToAdd) {
            return;
        }
        let Some(cur) = list.iter().position(|e| Some(e.addr) == self.server) else {
            return;
        };
        let next = list[(cur + 1) % list.len()].addr;
        if Some(next) != self.server {
            self.host.state = ToAdd;
            self.stop_internal(env, Requester::Auto, false);
            let _ = self.start_internal(env, next, Requester::Auto);
        }
    }

    // ---- state machine

    fn request_jitter(&mut self, reason: JitterReason, now: Instant) {
        if self.jitter_max != 0 {
            let elapsed = now.saturating_duration_since(self.jitter_time).as_millis();
            self.jitter_max = u64::from(self.jitter_max).saturating_sub(elapsed) as u32;
        }
        self.jitter_max = self.jitter_max.max(reason.max_ms());
        self.jitter_time = now;
    }

    fn tx_delay<R: Rng + ?Sized>(&mut self, rng: &mut R, now: Instant) -> u32 {
        let mut max = MAX_TX_JITTER_DEFAULT_MS;
        if self.jitter_max != 0 {
            let elapsed = now.saturating_duration_since(self.jitter_time).as_millis();
            if elapsed < u64::from(self.jitter_max) {
                max = max.max(self.jitter_max - elapsed as u32);
            }
            self.jitter_max = 0;
        }
        range(rng, MIN_TX_JITTER_MS, max)
    }

    fn set_state<E: Env>(&mut self, env: &mut E, st: ClientState) {
        if st == self.state {
            return;
        }
        self.state = st;
        let now = env.now();
        match st {
            ClientState::Stopped | ClientState::Paused | ClientState::Updated => self.timer = None,
            ClientState::ToUpdate => {
                let d = self.tx_delay(env.parts().0, now);
                self.timer = Some(now.saturating_add(ms(d)));
            }
            ClientState::Updating => {
                self.timer = Some(now.saturating_add(ms(self.retry_wait_ms)));
            }
            ClientState::ToRetry => {}
        }
    }

    fn grow_retry(&mut self) {
        self.retry_wait_ms = (self.retry_wait_ms / 10 * 17).min(MAX_RETRY_WAIT_MS);
    }

    fn change_states<E: Env>(
        &mut self,
        env: &mut E,
        table: &StateTable,
        appended_only: bool,
    ) -> bool {
        let old_host = self.host.state;
        let mut changed = false;
        let new = table[self.host.state as usize];
        changed |= new != self.host.state;
        self.host.state = new;
        for s in self.services.iter_mut().flatten() {
            if appended_only && !s.appended {
                continue;
            }
            let new = table[s.state as usize];
            changed |= new != s.state;
            s.state = new;
        }
        if old_host != Registered && self.host.state == Registered {
            match self.auto {
                AutoState::SelectedUnicastPreferred | AutoState::SelectedUnicast => {
                    env.parts().2.store_server(self.server)
                }
                AutoState::SelectedAnycast => env.parts().2.store_server(None),
                _ => {}
            }
        }
        changed
    }

    fn start_internal<E: Env>(
        &mut self,
        env: &mut E,
        server: SocketAddrV6,
        requester: Requester,
    ) -> Result<()> {
        if self.state != ClientState::Stopped {
            return if self.server == Some(server) {
                Ok(())
            } else {
                Err(Error::Busy)
            };
        }
        self.server = Some(server);
        self.requester = requester;
        self.resume(env);
        if requester == Requester::Auto {
            env.parts().2.event(SrpEvent::ServerSelected(Some(server)));
        }
        Ok(())
    }

    fn stop_internal<E: Env>(&mut self, env: &mut E, requester: Requester, reset_retry: bool) {
        if self.state != ClientState::Stopped {
            self.single_service_mode = false;
            self.change_states(env, &ON_STOP, false);
            self.should_remove_key_lease = false;
            self.tx_failure_retries = 0;
            self.response_msg_id = self.next_msg_id;
            if reset_retry {
                self.retry_wait_ms = MIN_RETRY_WAIT_MS;
            }
            self.set_state(env, ClientState::Stopped);
            self.server = None;
            self.timeout_failures = 0;
            if requester == Requester::Auto {
                env.parts().2.event(SrpEvent::ServerSelected(None));
            }
        }
        if requester == Requester::User {
            self.auto = AutoState::Disabled;
        }
    }

    fn resume<E: Env>(&mut self, env: &mut E) {
        self.set_state(env, ClientState::Updated);
        self.update_state(env);
    }

    fn pause(&mut self) {
        self.single_service_mode = false;
        for s in self.services.iter_mut().flatten() {
            s.state = ON_PAUSE[s.state as usize];
        }
        self.host.state = ON_PAUSE[self.host.state as usize];
        self.state = ClientState::Paused;
        self.timer = None;
    }

    fn update_state<E: Env>(&mut self, env: &mut E) {
        if matches!(self.state, ClientState::Stopped | ClientState::Paused)
            || self.host.name.is_empty()
        {
            return;
        }
        let now = env.now();
        let mut should_update = false;
        let mut next: Option<Instant> = None;
        let mut hs = self.host.state;
        if hs == Registered && now >= self.lease_renew_time {
            self.host.state = ToRefresh;
            hs = ToRefresh;
        }
        match hs {
            ToAdd | ToRefresh => {
                let has_services = self.services.iter().any(Option::is_some);
                if !has_services || (!self.host.auto && self.host.addrs.is_empty()) {
                    return;
                }
                should_update = true;
            }
            ToRemove => should_update = true,
            Removed => return,
            _ => {}
        }
        if self.host.state != Removing {
            for s in self.services.iter_mut().flatten() {
                match s.state {
                    ToAdd | ToRefresh | ToRemove => should_update = true,
                    Registered => {
                        if s.renew_time <= now {
                            s.state = ToRefresh;
                            should_update = true;
                        } else {
                            next = Some(next.map_or(s.renew_time, |n| n.min(s.renew_time)));
                        }
                    }
                    _ => {}
                }
            }
        }
        if should_update {
            self.set_state(env, ClientState::ToUpdate);
        } else if self.state == ClientState::Updated {
            self.timer = next;
        }
    }

    /// Process timers: tx jitter / retry expiry, response timeout, lease
    /// refresh.
    pub fn poll<E: Env>(&mut self, env: &mut E) {
        let Some(t) = self.timer else { return };
        if env.now() < t {
            return;
        }
        self.timer = None;
        match self.state {
            ClientState::ToUpdate | ClientState::ToRetry => self.send_update(env),
            ClientState::Updating => {
                self.single_service_mode = false;
                self.grow_retry();
                self.set_state(env, ClientState::ToUpdate);
                env.parts()
                    .2
                    .event(SrpEvent::Failed(SrpError::ResponseTimeout));
                self.timeout_failures = self.timeout_failures.saturating_add(1);
                if self.timeout_failures >= MAX_TIMEOUT_FAILURES_TO_SWITCH_SERVER {
                    self.select_next_server(env, true);
                }
            }
            ClientState::Updated => self.update_state(env),
            ClientState::Stopped | ClientState::Paused => {}
        }
    }

    fn send_update<E: Env>(&mut self, env: &mut E) {
        let mut buf = [0u8; UDP_PAYLOAD_SIZE as usize];
        let mut r = self.prepare_update(env, &mut buf);
        if r == Err(Error::NoBufs) && !self.single_service_mode {
            self.single_service_mode = true;
            r = self.prepare_update(env, &mut buf);
        }
        let now = env.now();
        let r = r.and_then(|n| {
            let server = self.server.ok_or(Error::InvalidState)?;
            env.parts().2.send(server, &buf[..n])
        });
        match r {
            Ok(()) => {
                let changed = self.change_states(env, &ON_TX, true);
                if changed {
                    self.response_msg_id = self.next_msg_id;
                }
                self.next_msg_id = self.next_msg_id.wrapping_add(1);
                self.lease_renew_time = now;
                self.tx_failure_retries = 0;
                self.set_state(env, ClientState::Updating);
            }
            Err(e) => {
                self.single_service_mode = false;
                self.set_state(env, ClientState::ToRetry);
                if self.tx_failure_retries < MAX_TX_FAILURE_RETRIES {
                    self.tx_failure_retries += 1;
                    let d = add_jitter(env.parts().0, TX_FAILURE_RETRY_MS, 10);
                    self.timer = Some(now.saturating_add(ms(d)));
                } else {
                    let d = add_jitter(env.parts().0, self.retry_wait_ms, RETRY_JITTER_MS);
                    self.timer = Some(now.saturating_add(ms(d)));
                    self.grow_retry();
                    env.parts().2.event(SrpEvent::Failed(SrpError::Tx(e)));
                }
            }
        }
    }

    /// Process a datagram from the server.
    pub fn handle_datagram<E: Env>(&mut self, env: &mut E, from: SocketAddrV6, payload: &[u8]) {
        if matches!(
            self.state,
            ClientState::Stopped | ClientState::Paused | ClientState::Updated
        ) || Some(from) != self.server
        {
            return;
        }
        let Ok((mut p, h)) = Parser::new(payload) else {
            return;
        };
        if !h.response || h.opcode != opcode::UPDATE {
            return;
        }
        if serial_less16(h.id, self.response_msg_id) || !serial_less16(h.id, self.next_msg_id) {
            return;
        }
        self.response_msg_id = h.id.wrapping_add(1);
        self.timeout_failures = 0;
        if let Some(e) = rcode_to_error(h.rcode) {
            if self.host.state == Adding {
                self.host.state = ToAdd;
            }
            self.grow_retry();
            self.set_state(env, ClientState::ToRetry);
            env.parts().2.event(SrpEvent::Failed(e));
            if matches!(e, SrpError::NameConflict | SrpError::Refused) {
                self.select_next_server(env, true);
            }
            return;
        }
        if h.qd != 0 && (h.qd != 1 || p.question().is_err()) {
            return;
        }
        let total = u32::from(h.an) + u32::from(h.ns) + u32::from(h.ar);
        for _ in 0..total {
            let Ok(rec) = p.record() else { return };
            if rec.rtype == rtype::OPT {
                match rec.update_lease() {
                    Ok(Some(l)) => {
                        self.lease = l.lease.min(MAX_LEASE);
                        self.key_lease = l.key_lease.min(MAX_LEASE);
                    }
                    Ok(None) => {}
                    Err(_) => return,
                }
            }
        }
        let renew = if self.lease > 2 * LEASE_RENEW_GUARD {
            let iv = (self.lease - LEASE_RENEW_GUARD) * 1000;
            add_jitter(env.parts().0, iv, LEASE_RENEW_JITTER_MS)
        } else {
            self.lease * 1000 / 2
        };
        self.lease_renew_time = self.lease_renew_time.saturating_add(ms(renew));
        let t = self.lease_renew_time;
        for s in self.services.iter_mut().flatten() {
            if matches!(s.state, Adding | Refreshing) {
                s.renew_time = t;
            }
        }
        self.change_states(env, &ON_DONE, true);
        self.handle_update_done(env);
        self.update_state(env);
    }

    fn handle_update_done<E: Env>(&mut self, env: &mut E) {
        let host_removed = self.host.state == Removed;
        if host_removed {
            self.host = HostInfo::new();
            self.registered_addrs.clear();
        }
        self.retry_wait_ms = MIN_RETRY_WAIT_MS;
        self.set_state(env, ClientState::Updated);
        for i in 0..S {
            if self.services[i]
                .as_ref()
                .is_some_and(|s| s.state == Removed)
            {
                self.services[i] = None;
                env.parts()
                    .2
                    .event(SrpEvent::ServiceRemoved(ServiceId(i as u8)));
            }
        }
        let ev = if host_removed {
            SrpEvent::HostRemoved
        } else {
            SrpEvent::Registered {
                lease: self.lease,
                key_lease: self.key_lease,
            }
        };
        env.parts().2.event(ev);
    }

    // ---- update message

    fn ensure_key<E: Env>(&mut self, env: &mut E) -> Result<SecretKey> {
        let (rng, crypto, ctx) = env.parts();
        if self.key.is_none()
            && let Some(k) = ctx.load_key()
            && crypto.public_key(&k).is_ok()
        {
            self.key = Some(k);
        }
        if self.key.is_none() {
            for _ in 0..8 {
                let mut b = [0u8; 32];
                rng.fill_bytes(&mut b);
                let k = SecretKey(b);
                b.zeroize();
                if crypto.public_key(&k).is_ok() {
                    ctx.store_key(&k);
                    self.key = Some(k);
                    break;
                }
            }
        }
        self.key.clone().ok_or(Error::Security)
    }

    fn auto_address_list<E: Env>(&mut self, env: &mut E) -> Vec<Ipv6Addr, MAX_HOST_ADDRS> {
        let ctx = env.parts().2;
        let mut v = Vec::new();
        ctx.auto_addresses(&mut v);
        if v.is_empty() {
            let _ = v.push(ctx.ml_eid());
        }
        v
    }

    fn determine_ttl(&self) -> u32 {
        let lease = if self.lease == 0 {
            self.default_lease
        } else {
            self.lease
        };
        if self.ttl == 0 {
            lease
        } else {
            self.ttl.min(lease)
        }
    }

    fn can_append(&mut self, i: usize) -> bool {
        let s = self.services[i].as_ref().expect("slot in use");
        let lease = determine_lease(s.cfg.lease, self.default_lease);
        let key = determine_lease(s.cfg.key_lease, self.default_key_lease).max(lease);
        match s.state {
            ToAdd | Adding | ToRefresh | Refreshing | Registered => {
                if (self.lease != 0 && self.lease != lease)
                    || (self.key_lease != 0 && self.key_lease != key)
                {
                    return false;
                }
                self.lease = lease;
                self.key_lease = key;
                true
            }
            ToRemove | Removing => {
                if self.key_lease != 0 && self.key_lease != key {
                    return false;
                }
                self.key_lease = key;
                true
            }
            Removed => false,
        }
    }

    fn append_service_instructions(
        &mut self,
        w: &mut Writer<'_>,
        domain: &str,
        host: &str,
        now: Instant,
        count: &mut u16,
    ) -> Result<()> {
        if matches!(self.host.state, ToRemove | Removing) {
            for s in self.services.iter_mut().flatten() {
                s.appended = true;
            }
            self.lease = 0;
            self.key_lease = if self.should_remove_key_lease {
                0
            } else {
                self.default_key_lease
            };
            return Ok(());
        }
        self.lease = 0;
        self.key_lease = 0;
        let (dl, dk) = (self.default_lease, self.default_key_lease);
        let (mut lease, mut key_lease) = (0, 0);
        for s in self.services.iter_mut().flatten() {
            let l = determine_lease(s.cfg.lease, dl);
            let k = determine_lease(s.cfg.key_lease, dk).max(l);
            s.appended = false;
            match s.state {
                Adding | Refreshing => {
                    lease = l;
                    key_lease = k;
                }
                Removing => key_lease = k,
                _ => {}
            }
        }
        self.lease = lease;
        self.key_lease = key_lease;
        for i in 0..S {
            let Some(st) = self.services[i].as_ref().map(|s| s.state) else {
                continue;
            };
            if st != Registered && self.can_append(i) {
                self.append_service(w, i, domain, host, count)?;
                if self.single_service_mode {
                    break;
                }
            }
        }
        if !self.single_service_mode {
            for i in 0..S {
                let Some(s) = self.services[i].as_ref() else {
                    continue;
                };
                if s.state != Registered {
                    continue;
                }
                let early = u64::from(determine_lease(s.cfg.lease, dl)) * 1000 / 2;
                let renew = s.renew_time <= now.saturating_add(Duration::from_millis(early));
                if renew && self.can_append(i) {
                    self.services[i].as_mut().expect("in use").state = ToRefresh;
                    self.append_service(w, i, domain, host, count)?;
                }
            }
        }
        self.lease = determine_lease(self.lease, dl);
        self.key_lease = determine_lease(self.key_lease, dk);
        self.lease = self.lease.min(self.key_lease);
        Ok(())
    }

    fn append_service(
        &mut self,
        w: &mut Writer<'_>,
        i: usize,
        domain: &str,
        host: &str,
        count: &mut u16,
    ) -> Result<()> {
        let ttl = self.determine_ttl();
        let s = self.services[i].as_mut().expect("slot in use");
        s.appended = true;
        let removing = matches!(s.state, ToRemove | Removing);
        let cfg = &s.cfg;
        let svc = Part::Dotted(&cfg.service_name);
        let dom = Part::Dotted(domain);
        let inst = Part::Label(&cfg.instance_name);

        w.write_name_parts(&[svc, dom], true)?;
        let (cls, t) = if removing {
            (class::NONE, 0)
        } else {
            (class::IN, ttl)
        };
        let m = w.begin_record(rtype::PTR, cls, t)?;
        w.write_name_parts(&[inst, svc, dom], true)?;
        w.end_record(m)?;
        *count += 1;
        if !removing {
            for sub in &cfg.sub_types {
                w.write_name_parts(&[Part::Label(sub), Part::Label("_sub"), svc, dom], true)?;
                let m = w.begin_record(rtype::PTR, class::IN, ttl)?;
                w.write_name_parts(&[inst, svc, dom], true)?;
                w.end_record(m)?;
                *count += 1;
            }
        }
        // Delete all RRsets from the instance name.
        w.write_name_parts(&[inst, svc, dom], true)?;
        let m = w.begin_record(rtype::ANY, class::ANY, 0)?;
        w.end_record(m)?;
        *count += 1;
        if removing {
            return Ok(());
        }
        w.write_name_parts(&[inst, svc, dom], true)?;
        let m = w.begin_record(rtype::SRV, class::IN, ttl)?;
        w.put_u16(cfg.priority)?;
        w.put_u16(cfg.weight)?;
        w.put_u16(cfg.port)?;
        w.write_name_parts(&[Part::Dotted(host), dom], true)?;
        w.end_record(m)?;
        *count += 1;
        w.write_name_parts(&[inst, svc, dom], true)?;
        let m = w.begin_record(rtype::TXT, class::IN, ttl)?;
        if cfg.txt.is_empty() {
            w.put(&[0])?;
        } else {
            w.put(&cfg.txt)?;
        }
        w.end_record(m)?;
        *count += 1;
        Ok(())
    }

    fn prepare_update<E: Env>(&mut self, env: &mut E, buf: &mut [u8]) -> Result<usize> {
        let key = self.ensure_key(env)?;
        let now = env.now();
        let pk = env.parts().1.public_key(&key)?;
        let domain = self.domain.clone();
        let host = self.host.name.clone();
        let mut w = Writer::new(buf)?;
        w.write_name(&domain)?;
        w.put_u16(rtype::SOA)?;
        w.put_u16(class::IN)?;
        let mut count = 0u16;
        self.append_service_instructions(&mut w, &domain, &host, now, &mut count)?;

        // Host description instruction.
        let ttl = self.determine_ttl();
        let host_parts = [Part::Dotted(&host), Part::Dotted(&domain)];
        w.write_name_parts(&host_parts, true)?;
        let m = w.begin_record(rtype::ANY, class::ANY, 0)?;
        w.end_record(m)?;
        count += 1;
        let addrs: Vec<Ipv6Addr, MAX_HOST_ADDRS> = if self.host.auto {
            let v = self.auto_address_list(env);
            self.registered_addrs = v.clone();
            v
        } else {
            self.host.addrs.clone()
        };
        for a in &addrs {
            w.write_name_parts(&host_parts, true)?;
            w.write_aaaa(ttl, a)?;
            count += 1;
        }
        w.write_name_parts(&host_parts, true)?;
        w.write_key(ttl, &pk)?;
        count += 1;

        let mut hdr = Header {
            id: self.next_msg_id,
            opcode: opcode::UPDATE,
            qd: 1,
            ns: count,
            ar: 1,
            ..Header::default()
        };
        w.set_header(&hdr);
        w.write_opt(
            UDP_PAYLOAD_SIZE,
            true,
            Some(LeaseOption {
                lease: self.lease,
                key_lease: self.key_lease,
            }),
        )?;

        // SIG(0) over: SIG rdata (without signature, signer name
        // uncompressed) || message so far (RFC 2931).
        let sig_start = w.len();
        let mut fixed = [0u8; crate::rdata::SIG_FIXED_LEN];
        fixed[2] = crate::rdata::ALGORITHM_ECDSAP256SHA256;
        let mut scratch = [0u8; 12 + 256];
        let mut sw = Writer::new(&mut scratch)?;
        sw.write_name_parts(&host_parts, false)?;
        let mut hasher = env.parts().1.sha256();
        hasher.update(&fixed);
        hasher.update(&sw.as_bytes()[12..]);
        hasher.update(&w.as_bytes()[..sig_start]);
        let digest = hasher.finalize();
        let sig = env.parts().1.sign_digest(&key, &digest)?;
        w.write_root()?;
        let m = w.begin_record(rtype::SIG, class::ANY, 0)?;
        w.put(&fixed)?;
        w.write_name_parts(&host_parts, true)?;
        w.put(&sig)?;
        w.end_record(m)?;
        hdr.ar = 2;
        w.set_header(&hdr);
        Ok(w.len())
    }
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
