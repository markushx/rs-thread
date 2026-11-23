//! SRP server (RFC 9665; OT `Srp::Server`): processes signed DNS UPDATE
//! messages, keeps the registered hosts and services with their leases.
//!
//! Sans-IO and allocation-free. The caller feeds datagrams to
//! [`SrpServer::handle_message`] (the reply, if any, is written to the buffer
//! it passes) and calls [`SrpServer::poll`] at [`SrpServer::next_deadline`]
//! to expire leases. The server state (enabled, running, port, Network Data
//! publishing) lives in the instance.
//!
//! Storage is bounded by the const generics: `H` hosts, `S` services in
//! total and `U` services in one update message (OT uses the heap and has no
//! such limits). Names are kept in wire format, at most [`MAX_NAME_LEN`]
//! bytes. An update that does not fit is answered with SERVFAIL.
//!
//! Message processing follows OT `Srp::Server` step by step: zone check,
//! service discovery instructions, host description, service descriptions,
//! name conflicts, Update Lease option, SIG(0) verification (ECDSA P-256
//! over SHA-256), commit with granted lease / key lease / TTL.

use core::net::Ipv6Addr;

use heapless::Vec;
use rs_thread_core::crypto::ecdsa::{EcdsaP256, PUBLIC_KEY_LEN, SIGNATURE_LEN};
use rs_thread_core::crypto::{CryptoBackend, Sha256};
use rs_thread_core::time::{Duration, Instant};

use crate::rdata::OPT_UPDATE_LEASE;
use crate::wire::{HEADER_LEN, Name, Parser, Writer, class, opcode, rcode, rtype};

/// Longest name (wire format, with the root label) the server stores.
pub const MAX_NAME_LEN: usize = 128;
/// Subtypes per service.
pub const MAX_SUB_TYPES: usize = 6;
/// Addresses per host.
pub const MAX_ADDRESSES: usize = 8;
/// Longest TXT data of a service.
pub const MAX_TXT: usize = 256;
/// Default domain (OT `kDefaultDomain`).
pub const DEFAULT_DOMAIN: &str = "default.service.arpa";
/// First port of the range the server picks its port from.
pub const UDP_PORT_MIN: u16 = 53535;
/// Last port of the range.
pub const UDP_PORT_MAX: u16 = 53554;
/// Port of the anycast address mode.
pub const ANYCAST_PORT: u16 = 53;
/// UDP payload size announced in the response OPT record.
pub const UDP_PAYLOAD_SIZE: u16 = 1232;

const DEFAULT_MIN_LEASE: u32 = 30;
const DEFAULT_MAX_LEASE: u32 = 27 * 3600;
const DEFAULT_MIN_KEY_LEASE: u32 = 30;
const DEFAULT_MAX_KEY_LEASE: u32 = 189 * 3600;
/// OT `TimerMilli::kMaxDelay` in seconds.
const MAX_KEY_LEASE_LIMIT: u32 = 2_147_483;

type Rc = u8;
type R<T> = core::result::Result<T, Rc>;

const FORMERR: Rc = rcode::FORMAT_ERROR;
const SERVFAIL: Rc = rcode::SERVER_FAILURE;
const REFUSED: Rc = rcode::REFUSED;
const YXDOMAIN: Rc = rcode::NAME_EXISTS;

// ------------------------------------------------------------------- names

/// A name in uncompressed wire format (length-prefixed labels, root label).
/// Comparisons are ASCII case-insensitive.
#[derive(Debug, Clone, Default)]
pub struct WireName(Vec<u8, MAX_NAME_LEN>);

/// Labels of a [`WireName`].
#[derive(Debug, Clone)]
pub struct WireLabels<'a>(&'a [u8]);

impl<'a> Iterator for WireLabels<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<&'a [u8]> {
        let n = usize::from(*self.0.first()?);
        if n == 0 {
            return None;
        }
        let label = self.0.get(1..=n)?;
        self.0 = &self.0[1 + n..];
        Some(label)
    }
}

impl WireName {
    fn new_root() -> Self {
        let mut v = Vec::new();
        let _ = v.push(0);
        Self(v)
    }

    /// Copy a name of a message ([`SERVFAIL`] if it is too long for the
    /// store, FORMERR if malformed).
    fn from_msg(n: &Name<'_>) -> R<Self> {
        let mut v: Vec<u8, MAX_NAME_LEN> = Vec::new();
        for l in n.labels() {
            let l = l.map_err(|_| FORMERR)?;
            v.push(l.len() as u8).map_err(|_| SERVFAIL)?;
            v.extend_from_slice(l).map_err(|_| SERVFAIL)?;
        }
        v.push(0).map_err(|_| SERVFAIL)?;
        Ok(Self(v))
    }

    /// A name from a dotted string without escapes (trailing dot optional).
    pub fn from_dotted(s: &str) -> Option<Self> {
        let s = s.strip_suffix('.').unwrap_or(s);
        let mut v: Vec<u8, MAX_NAME_LEN> = Vec::new();
        if !s.is_empty() {
            for l in s.split('.') {
                if l.is_empty() || l.len() > crate::wire::MAX_LABEL_LEN {
                    return None;
                }
                v.push(l.len() as u8).ok()?;
                v.extend_from_slice(l.as_bytes()).ok()?;
            }
        }
        v.push(0).ok()?;
        Some(Self(v))
    }

    /// A name made of one `label` (any bytes) and the name `rest`.
    pub fn from_label_and(label: &[u8], rest: &WireName) -> Option<Self> {
        if label.is_empty() || label.len() > crate::wire::MAX_LABEL_LEN {
            return None;
        }
        let mut v: Vec<u8, MAX_NAME_LEN> = Vec::new();
        v.push(label.len() as u8).ok()?;
        v.extend_from_slice(label).ok()?;
        v.extend_from_slice(&rest.0).ok()?;
        Some(Self(v))
    }

    /// The wire format.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// No name set.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// The labels.
    pub fn labels(&self) -> WireLabels<'_> {
        WireLabels(&self.0)
    }

    /// The name inside a buffer (for the codec's [`Name`] helpers).
    pub fn as_name(&self) -> Name<'_> {
        Name::new(&self.0, 0)
    }

    /// Case-insensitive equality.
    pub fn eq_name(&self, o: &WireName) -> bool {
        self.0.eq_ignore_ascii_case(&o.0)
    }

    /// Is this name equal to or below `parent`?
    pub fn is_subdomain_of(&self, parent: &WireName) -> bool {
        let (a, b) = (self.labels().count(), parent.labels().count());
        let Some(skip) = a.checked_sub(b) else {
            return false;
        };
        self.labels()
            .skip(skip)
            .zip(parent.labels())
            .all(|(x, y)| x.eq_ignore_ascii_case(y))
    }

    /// The name without its first label.
    pub fn parent(&self) -> WireName {
        let n = self.labels().next().map_or(0, |l| l.len() + 1);
        let mut v = Vec::new();
        let _ = v.extend_from_slice(self.0.get(n..).unwrap_or(&[0]));
        if v.is_empty() {
            let _ = v.push(0);
        }
        Self(v)
    }

    /// Write the dotted form with escapes and a trailing dot (as OT prints
    /// names).
    pub fn fmt_dotted(&self, f: &mut dyn core::fmt::Write) -> core::fmt::Result {
        let mut any = false;
        for l in self.labels() {
            any = true;
            for &c in l {
                if c == b'.' || c == b'\\' {
                    f.write_char('\\')?;
                }
                if c.is_ascii_graphic() || c == b' ' {
                    f.write_char(c as char)?;
                } else {
                    write!(f, "\\{c:03}")?;
                }
            }
            f.write_char('.')?;
        }
        if !any {
            f.write_char('.')?;
        }
        Ok(())
    }
}

// ------------------------------------------------------------------- types

/// TTL limits (OT `TtlConfig`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TtlConfig {
    /// Smallest granted TTL.
    pub min: u32,
    /// Largest granted TTL.
    pub max: u32,
}

impl Default for TtlConfig {
    fn default() -> Self {
        Self {
            min: DEFAULT_MIN_LEASE,
            max: DEFAULT_MAX_LEASE,
        }
    }
}

impl TtlConfig {
    /// `min <= max`.
    pub const fn is_valid(&self) -> bool {
        self.min <= self.max
    }

    fn grant(&self, lease: u32, ttl: u32) -> u32 {
        ttl.min(lease).clamp(self.min, self.max)
    }
}

/// Lease limits (OT `LeaseConfig`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LeaseConfig {
    /// Smallest granted lease.
    pub min_lease: u32,
    /// Largest granted lease.
    pub max_lease: u32,
    /// Smallest granted key lease.
    pub min_key_lease: u32,
    /// Largest granted key lease.
    pub max_key_lease: u32,
}

impl Default for LeaseConfig {
    fn default() -> Self {
        Self {
            min_lease: DEFAULT_MIN_LEASE,
            max_lease: DEFAULT_MAX_LEASE,
            min_key_lease: DEFAULT_MIN_KEY_LEASE,
            max_key_lease: DEFAULT_MAX_KEY_LEASE,
        }
    }
}

impl LeaseConfig {
    /// The ranges are ordered (OT `LeaseConfig::IsValid`).
    pub const fn is_valid(&self) -> bool {
        self.max_key_lease <= MAX_KEY_LEASE_LIMIT
            && self.min_lease <= self.max_lease
            && self.min_key_lease <= self.max_key_lease
            && self.min_lease <= self.min_key_lease
            && self.max_lease <= self.max_key_lease
    }

    fn grant_lease(&self, lease: u32) -> u32 {
        if lease == 0 {
            0
        } else {
            lease.clamp(self.min_lease, self.max_lease)
        }
    }

    fn grant_key_lease(&self, lease: u32) -> u32 {
        if lease == 0 {
            0
        } else {
            lease.clamp(self.min_key_lease, self.max_key_lease)
        }
    }
}

/// A registered service instance.
#[derive(Debug, Clone)]
pub struct Service {
    /// Full instance name (`<instance>.<service>.<domain>.`).
    pub instance: WireName,
    /// Full service name (`<service>.<domain>.`); empty only while an
    /// update is parsed.
    pub service_name: WireName,
    /// Full subtype names (`<sub>._sub.<service>.<domain>.`).
    pub sub_types: Vec<WireName, MAX_SUB_TYPES>,
    /// TXT data (encoded entries).
    pub txt: Vec<u8, MAX_TXT>,
    /// Port.
    pub port: u16,
    /// Priority.
    pub priority: u16,
    /// Weight.
    pub weight: u16,
    /// Granted TTL.
    pub ttl: u32,
    /// Granted lease in seconds.
    pub lease: u32,
    /// Granted key lease in seconds.
    pub key_lease: u32,
    /// Removed, but the name is retained until the key lease expires.
    pub deleted: bool,
    /// Time of the update that registered it.
    pub update_time: Instant,
    /// The host it belongs to ([`Host::id`]).
    pub host_id: u16,
}

impl Service {
    fn new(instance: WireName, now: Instant) -> Self {
        Self {
            instance,
            service_name: WireName::default(),
            sub_types: Vec::new(),
            txt: Vec::new(),
            port: 0,
            priority: 0,
            weight: 0,
            ttl: 0,
            lease: 0,
            key_lease: 0,
            deleted: false,
            update_time: now,
            host_id: 0,
        }
    }

    /// The instance label (first label of the instance name).
    pub fn instance_label(&self) -> &[u8] {
        self.instance.labels().next().unwrap_or(&[])
    }

    /// The subtype label of `sub_types[i]` (the part before `._sub.`).
    pub fn sub_type_label(&self, i: usize) -> &[u8] {
        self.sub_types
            .get(i)
            .and_then(|n| n.labels().next())
            .unwrap_or(&[])
    }

    /// When the lease expires.
    pub fn expire_time(&self) -> Instant {
        self.update_time
            .saturating_add(Duration::from_secs(u64::from(self.lease)))
    }

    /// When the key lease expires.
    pub fn key_expire_time(&self) -> Instant {
        self.update_time
            .saturating_add(Duration::from_secs(u64::from(self.key_lease)))
    }

    /// Remaining lease in seconds (0 for a deleted service).
    pub fn remaining_lease(&self, now: Instant) -> u32 {
        if self.deleted {
            return 0;
        }
        remaining(self.expire_time(), now)
    }
}

fn remaining(t: Instant, now: Instant) -> u32 {
    u32::try_from(t.saturating_duration_since(now).as_millis().div_ceil(1000)).unwrap_or(u32::MAX)
}

/// A registered host.
#[derive(Debug, Clone)]
pub struct Host {
    /// Identifier, referenced by [`Service::host_id`].
    pub id: u16,
    /// Full host name (`<host>.<domain>.`).
    pub name: WireName,
    /// The ECDSA P-256 public key (`X || Y`) of the registrant.
    pub key: [u8; PUBLIC_KEY_LEN],
    /// Addresses (empty for a removed host).
    pub addresses: Vec<Ipv6Addr, MAX_ADDRESSES>,
    /// Granted TTL.
    pub ttl: u32,
    /// Granted lease in seconds (0: removed, name retained).
    pub lease: u32,
    /// Granted key lease in seconds.
    pub key_lease: u32,
    /// Time of the update that registered it.
    pub update_time: Instant,
}

impl Host {
    /// Removed, but the name is retained until the key lease expires.
    pub const fn is_deleted(&self) -> bool {
        self.lease == 0
    }

    /// The host label (first label of the name).
    pub fn label(&self) -> &[u8] {
        self.name.labels().next().unwrap_or(&[])
    }

    /// When the lease expires.
    pub fn expire_time(&self) -> Instant {
        self.update_time
            .saturating_add(Duration::from_secs(u64::from(self.lease)))
    }

    /// When the key lease expires.
    pub fn key_expire_time(&self) -> Instant {
        self.update_time
            .saturating_add(Duration::from_secs(u64::from(self.key_lease)))
    }

    /// Remaining lease in seconds (0 for a removed host).
    pub fn remaining_lease(&self, now: Instant) -> u32 {
        if self.is_deleted() {
            return 0;
        }
        remaining(self.expire_time(), now)
    }

    /// Remaining key lease in seconds.
    pub fn remaining_key_lease(&self, now: Instant) -> u32 {
        remaining(self.key_expire_time(), now)
    }
}

/// What [`SrpServer::handle_message`] did with a message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Reply {
    /// Length of the response in the output buffer.
    pub len: usize,
    /// The update was committed (a host stored). OT saves the port when the
    /// first update of a run is committed.
    pub committed: bool,
    /// The response code.
    pub rcode: u8,
}

// ------------------------------------------------------------ the server

struct PService {
    svc: Service,
    delete_all: bool,
    srv: bool,
    txt: bool,
}

struct Pending<const U: usize> {
    name: Option<WireName>,
    key: Option<[u8; PUBLIC_KEY_LEN]>,
    addrs: Vec<Ipv6Addr, MAX_ADDRESSES>,
    ttl: u32,
    lease: u32,
    key_lease: u32,
    short: bool,
    services: Vec<PService, U>,
}

impl<const U: usize> Pending<U> {
    fn process_ttl(&mut self, ttl: u32) -> R<()> {
        if ttl == 0 || (self.ttl != 0 && self.ttl != ttl) {
            return Err(REFUSED);
        }
        self.ttl = ttl;
        Ok(())
    }

    fn find(&self, instance: &WireName) -> Option<usize> {
        self.services
            .iter()
            .position(|s| s.svc.instance.eq_name(instance))
    }

    fn set_name(&mut self, name: WireName) -> R<()> {
        match &self.name {
            None => {
                self.name = Some(name);
                Ok(())
            }
            Some(n) if n.eq_name(&name) => Ok(()),
            Some(_) => Err(REFUSED),
        }
    }
}

/// The SRP server data: hosts, services, configuration.
#[derive(Debug)]
pub struct SrpServer<const H: usize, const S: usize, const U: usize> {
    hosts: Vec<Host, H>,
    services: Vec<Service, S>,
    ttl: TtlConfig,
    lease: LeaseConfig,
    domain: WireName,
    next_id: u16,
}

impl<const H: usize, const S: usize, const U: usize> Default for SrpServer<H, S, U> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const H: usize, const S: usize, const U: usize> SrpServer<H, S, U> {
    /// An empty server for [`DEFAULT_DOMAIN`] with the default limits.
    pub fn new() -> Self {
        Self {
            hosts: Vec::new(),
            services: Vec::new(),
            ttl: TtlConfig::default(),
            lease: LeaseConfig::default(),
            domain: WireName::from_dotted(DEFAULT_DOMAIN).unwrap_or_else(WireName::new_root),
            next_id: 0,
        }
    }

    /// The TTL limits.
    pub const fn ttl_config(&self) -> TtlConfig {
        self.ttl
    }

    /// Set the TTL limits; `false` if they are not ordered.
    pub fn set_ttl_config(&mut self, c: TtlConfig) -> bool {
        if !c.is_valid() {
            return false;
        }
        self.ttl = c;
        true
    }

    /// The lease limits.
    pub const fn lease_config(&self) -> LeaseConfig {
        self.lease
    }

    /// Set the lease limits; `false` if they are not valid.
    pub fn set_lease_config(&mut self, c: LeaseConfig) -> bool {
        if !c.is_valid() {
            return false;
        }
        self.lease = c;
        true
    }

    /// The domain.
    pub const fn domain(&self) -> &WireName {
        &self.domain
    }

    /// Set the domain (dotted, trailing dot optional); `false` if it is
    /// empty or invalid.
    pub fn set_domain(&mut self, domain: &str) -> bool {
        if domain.is_empty() {
            return false;
        }
        match WireName::from_dotted(domain) {
            Some(d) => {
                self.domain = d;
                true
            }
            None => false,
        }
    }

    /// The hosts, the most recently registered first (as OT lists them).
    pub fn hosts(&self) -> impl Iterator<Item = &Host> {
        self.hosts.iter().rev()
    }

    /// The services of `host`, the most recently added first.
    pub fn services_of(&self, host: &Host) -> impl Iterator<Item = &Service> {
        let id = host.id;
        self.services.iter().rev().filter(move |s| s.host_id == id)
    }

    /// All services with their hosts.
    pub fn all_services(&self) -> impl Iterator<Item = (&Host, &Service)> {
        self.hosts()
            .flat_map(|h| self.services_of(h).map(move |s| (h, s)))
    }

    /// The host with `name`.
    pub fn find_host(&self, name: &WireName) -> Option<&Host> {
        self.hosts.iter().find(|h| h.name.eq_name(name))
    }

    /// The host of a service.
    pub fn host_of(&self, s: &Service) -> Option<&Host> {
        self.hosts.iter().find(|h| h.id == s.host_id)
    }

    /// Remove all hosts and services (OT `Stop`).
    pub fn clear(&mut self) {
        self.hosts.clear();
        self.services.clear();
    }

    fn host_idx(&self, name: &WireName) -> Option<usize> {
        self.hosts.iter().position(|h| h.name.eq_name(name))
    }

    fn remove_host_at(&mut self, idx: usize) {
        let id = self.hosts[idx].id;
        self.hosts.remove(idx);
        self.services.retain(|s| s.host_id != id);
    }

    // ------------------------------------------------------- the update

    /// Process a datagram. `None`: nothing to answer (not an UPDATE). The
    /// response goes to `out`.
    pub fn handle_message<C: CryptoBackend + EcdsaP256>(
        &mut self,
        now: Instant,
        msg: &[u8],
        crypto: &C,
        out: &mut [u8],
    ) -> Option<Reply> {
        let (_, h) = Parser::new(msg).ok()?;
        if h.response || h.opcode != opcode::UPDATE {
            return None;
        }
        let r = self.process(now, msg, crypto);
        let mut w = Writer::new(out).ok()?;
        let mut hdr = crate::wire::Header {
            id: h.id,
            response: true,
            opcode: opcode::UPDATE,
            ..crate::wire::Header::default()
        };
        let (rc, committed) = match &r {
            Ok(done) => {
                if let Some((lease, key_lease, short)) = done.lease {
                    hdr.ar = 1;
                    w.set_header(&hdr);
                    let ok = (|| {
                        w.write_root().ok()?;
                        let m = w.begin_record(rtype::OPT, UDP_PAYLOAD_SIZE, 0x8000).ok()?;
                        w.put_u16(OPT_UPDATE_LEASE).ok()?;
                        if short {
                            w.put_u16(4).ok()?;
                            w.put_u32(lease).ok()?;
                        } else {
                            w.put_u16(8).ok()?;
                            w.put_u32(lease).ok()?;
                            w.put_u32(key_lease).ok()?;
                        }
                        w.end_record(m).ok()
                    })();
                    ok?;
                }
                (rcode::SUCCESS, done.committed)
            }
            Err(rc) => (*rc, false),
        };
        hdr.rcode = rc;
        w.set_header(&hdr);
        Some(Reply {
            len: w.len(),
            committed,
            rcode: rc,
        })
    }

    fn process<C: CryptoBackend + EcdsaP256>(
        &mut self,
        now: Instant,
        msg: &[u8],
        crypto: &C,
    ) -> R<Done> {
        let (mut p, h) = Parser::new(msg).map_err(|_| FORMERR)?;
        // Zone section.
        if h.qd != 1 {
            return Err(FORMERR);
        }
        let zone = p.question().map_err(|_| FORMERR)?;
        let zname = WireName::from_msg(&zone.name)?;
        if !zname.eq_name(&self.domain) {
            return Err(REFUSED);
        }
        if zone.qtype != rtype::SOA {
            return Err(FORMERR);
        }
        // No prerequisites (SRP: 2.3.2).
        if h.an != 0 {
            return Err(REFUSED);
        }
        let zone_class = zone.qclass;
        let first = p.clone();
        let mut after = p.clone();
        for _ in 0..h.ns {
            after.record().map_err(|_| FORMERR)?;
        }

        let mut pend: Pending<U> = Pending {
            name: None,
            key: None,
            addrs: Vec::new(),
            ttl: 0,
            lease: 0,
            key_lease: 0,
            short: false,
            services: Vec::new(),
        };
        self.service_discovery(&mut pend, first.clone(), h.ns, zone_class, now)?;
        Self::host_description(&mut pend, first.clone(), h.ns, zone_class)?;
        self.service_description(&mut pend, first, h.ns, zone_class)?;
        if self.has_name_conflicts(&pend) {
            return Err(YXDOMAIN);
        }
        self.additional_section(&mut pend, after, msg, h.ar, crypto)?;
        self.handle_update(now, &mut pend)?;
        self.commit(now, pend)
    }

    fn service_discovery<const V: usize>(
        &self,
        pend: &mut Pending<V>,
        mut p: Parser<'_>,
        count: u16,
        zone_class: u16,
        now: Instant,
    ) -> R<()> {
        for _ in 0..count {
            let rec = p.record().map_err(|_| FORMERR)?;
            let name = WireName::from_msg(&rec.name)?;
            if !name.is_subdomain_of(&self.domain) {
                return Err(REFUSED);
            }
            if rec.rtype != rtype::PTR {
                continue;
            }
            let target = rec.ptr().map_err(|_| FORMERR)?;
            let inst = WireName::from_msg(&target)?;
            // Class NONE: delete an RR from an RRset.
            let is_delete = rec.class == class::NONE;
            if !is_delete && rec.class != zone_class {
                return Err(FORMERR);
            }
            // `<sub>._sub.<service>`: the first `_sub` label that is not
            // the first label.
            let sub_idx = name
                .labels()
                .enumerate()
                .skip(1)
                .find(|(_, l)| l.eq_ignore_ascii_case(b"_sub"))
                .map(|(i, _)| i);
            let base = match sub_idx {
                Some(i) => {
                    let mut b = name.clone();
                    for _ in 0..=i {
                        b = b.parent();
                    }
                    b
                }
                None => name.clone(),
            };
            if !inst.is_subdomain_of(&base) {
                return Err(REFUSED);
            }
            let idx = match pend.find(&inst) {
                Some(i) => i,
                None => {
                    pend.services
                        .push(PService {
                            svc: Service::new(inst, now),
                            delete_all: false,
                            srv: false,
                            txt: false,
                        })
                        .map_err(|_| SERVFAIL)?;
                    pend.services.len() - 1
                }
            };
            let ps = &mut pend.services[idx];
            if sub_idx.is_some() {
                if ps.svc.sub_types.iter().any(|s| s.eq_name(&name)) {
                    return Err(REFUSED);
                }
                if !is_delete {
                    ps.svc.sub_types.push(name).map_err(|_| SERVFAIL)?;
                }
            } else {
                if !ps.svc.service_name.is_empty() {
                    return Err(REFUSED);
                }
                ps.svc.service_name = name;
                ps.svc.deleted = is_delete;
            }
            if !is_delete {
                pend.process_ttl(rec.ttl)?;
            }
        }
        for ps in &pend.services {
            if ps.svc.service_name.is_empty() {
                return Err(FORMERR);
            }
            if ps.svc.deleted && !ps.svc.sub_types.is_empty() {
                return Err(FORMERR);
            }
        }
        Ok(())
    }

    fn host_description<const V: usize>(
        pend: &mut Pending<V>,
        mut p: Parser<'_>,
        count: u16,
        zone_class: u16,
    ) -> R<()> {
        for _ in 0..count {
            let rec = p.record().map_err(|_| FORMERR)?;
            let name = WireName::from_msg(&rec.name)?;
            if rec.class == class::ANY {
                // Delete all RRsets from a name.
                if !is_delete_all(&rec) {
                    return Err(REFUSED);
                }
                // Only applies to a service or host description.
                if pend.find(&name).is_none() {
                    pend.set_name(name)?;
                    pend.addrs.clear();
                }
            } else if rec.rtype == rtype::AAAA {
                if rec.class != zone_class {
                    return Err(REFUSED);
                }
                pend.process_ttl(rec.ttl)?;
                pend.set_name(name)?;
                let a = rec.aaaa().map_err(|_| FORMERR)?;
                if a.is_multicast() || a.is_unspecified() || a.is_loopback() {
                    continue;
                }
                if pend.addrs.contains(&a) {
                    continue;
                }
                pend.addrs.push(a).map_err(|_| SERVFAIL)?;
            } else if rec.rtype == rtype::KEY {
                if rec.class != zone_class {
                    return Err(REFUSED);
                }
                pend.process_ttl(rec.ttl)?;
                let k = rec.key().map_err(|_| FORMERR)?;
                if k.algorithm != crate::rdata::ALGORITHM_ECDSAP256SHA256 {
                    return Err(FORMERR);
                }
                match &pend.key {
                    Some(old) => {
                        if old != k.public_key {
                            return Err(REFUSED);
                        }
                    }
                    None => pend.key = Some(*k.public_key),
                }
            }
        }
        if pend.name.is_none() || pend.key.is_none() {
            return Err(REFUSED);
        }
        Ok(())
    }

    fn service_description<const V: usize>(
        &self,
        pend: &mut Pending<V>,
        mut p: Parser<'_>,
        count: u16,
        zone_class: u16,
    ) -> R<()> {
        for _ in 0..count {
            let rec = p.record().map_err(|_| FORMERR)?;
            let name = WireName::from_msg(&rec.name)?;
            if rec.class == class::ANY {
                if !is_delete_all(&rec) {
                    return Err(REFUSED);
                }
                if let Some(i) = pend.find(&name) {
                    if pend.services[i].delete_all {
                        // OT silently ends the section here and then reads the
                        // rest from the wrong offset; reject instead.
                        return Err(FORMERR);
                    }
                    pend.services[i].delete_all = true;
                }
                continue;
            }
            if rec.rtype == rtype::SRV {
                if rec.class != zone_class {
                    return Err(REFUSED);
                }
                pend.process_ttl(rec.ttl)?;
                let srv = rec.srv().map_err(|_| FORMERR)?;
                let host = WireName::from_msg(&srv.target)?;
                if !name.is_subdomain_of(&self.domain) {
                    return Err(REFUSED);
                }
                if !pend.name.as_ref().is_some_and(|n| n.eq_name(&host)) {
                    return Err(REFUSED);
                }
                let i = pend.find(&name).ok_or(REFUSED)?;
                let ps = &mut pend.services[i];
                if ps.srv {
                    return Err(FORMERR);
                }
                ps.srv = true;
                ps.svc.ttl = rec.ttl;
                ps.svc.priority = srv.priority;
                ps.svc.weight = srv.weight;
                ps.svc.port = srv.port;
            } else if rec.rtype == rtype::TXT {
                if rec.class != zone_class {
                    return Err(REFUSED);
                }
                pend.process_ttl(rec.ttl)?;
                let i = pend.find(&name).ok_or(REFUSED)?;
                let ps = &mut pend.services[i];
                ps.txt = true;
                if !verify_txt(rec.rdata) {
                    return Err(FORMERR);
                }
                ps.svc.txt.clear();
                ps.svc
                    .txt
                    .extend_from_slice(rec.rdata)
                    .map_err(|_| SERVFAIL)?;
            }
        }
        for ps in &pend.services {
            if !ps.delete_all || ps.srv != ps.txt || (!ps.svc.deleted && !ps.srv) {
                return Err(REFUSED);
            }
        }
        Ok(())
    }

    fn has_name_conflicts<const V: usize>(&self, pend: &Pending<V>) -> bool {
        let (Some(name), Some(key)) = (&pend.name, &pend.key) else {
            return true;
        };
        if self.find_host(name).is_some_and(|h| &h.key != key) {
            return true;
        }
        for ps in &pend.services {
            for s in &self.services {
                if s.instance.eq_name(&ps.svc.instance)
                    && self.host_of(s).is_some_and(|h| &h.key != key)
                {
                    return true;
                }
            }
        }
        false
    }

    fn additional_section<const V: usize, C: CryptoBackend + EcdsaP256>(
        &self,
        pend: &mut Pending<V>,
        mut p: Parser<'_>,
        msg: &[u8],
        ar: u16,
        crypto: &C,
    ) -> R<()> {
        if ar != 2 {
            return Err(REFUSED);
        }
        // EDNS(0) Update Lease option.
        let opt = p.record().map_err(|_| FORMERR)?;
        if opt.name.labels().next().is_some() {
            return Err(SERVFAIL);
        }
        let mut lease_opt = None;
        for o in opt.opt_options() {
            let (code, d) = o.map_err(|_| FORMERR)?;
            if code == OPT_UPDATE_LEASE {
                let l = crate::rdata::LeaseOption::parse(d).map_err(|_| FORMERR)?;
                lease_opt = Some((l, d.len() == 4));
                break;
            }
        }
        let (l, short) = lease_opt.ok_or(REFUSED)?;
        pend.lease = l.lease;
        pend.key_lease = l.key_lease;
        pend.short = short;
        let host_lease = pend.lease;
        for ps in &mut pend.services {
            if host_lease == 0 {
                ps.svc.deleted = true;
            }
            ps.svc.lease = if ps.svc.deleted { 0 } else { l.lease };
            ps.svc.key_lease = l.key_lease;
        }
        if host_lease > 0 && pend.addrs.is_empty() {
            return Err(REFUSED);
        }

        // SIG(0).
        let sig_off = p.offset();
        let rec = p.record().map_err(|_| FORMERR)?;
        if rec.name.labels().next().is_some() {
            return Err(SERVFAIL);
        }
        if rec.rtype != rtype::SIG || rec.rdata.len() < crate::rdata::SIG_FIXED_LEN {
            return Err(FORMERR);
        }
        let signer_off = rec.rdata_off + crate::rdata::SIG_FIXED_LEN;
        let signer = Name::new(msg, signer_off);
        let sig_start = signer.end_offset().map_err(|_| FORMERR)?;
        let rdata_end = rec.rdata_off + rec.rdata.len();
        let sig_bytes = msg.get(sig_start..rdata_end).ok_or(FORMERR)?;
        let fixed = &rec.rdata[..crate::rdata::SIG_FIXED_LEN];
        if fixed[2] != crate::rdata::ALGORITHM_ECDSAP256SHA256 {
            return Err(REFUSED);
        }
        if fixed[0] != 0 || fixed[1] != 0 {
            return Err(REFUSED);
        }
        let sig: &[u8; SIGNATURE_LEN] = sig_bytes.try_into().map_err(|_| FORMERR)?;
        let key = pend.key.as_ref().ok_or(REFUSED)?;

        // SIG rdata less the signature, the signer name (uncompressed), the
        // header without the SIG in the additional count, and the message up
        // to the SIG record.
        let signer_wire = WireName::from_msg(&signer)?;
        let mut hdr = [0u8; HEADER_LEN];
        hdr.copy_from_slice(msg.get(..HEADER_LEN).ok_or(FORMERR)?);
        hdr[10..12].copy_from_slice(&(ar - 1).to_be_bytes());
        let mut sha = crypto.sha256();
        sha.update(fixed);
        sha.update(signer_wire.as_bytes());
        sha.update(&hdr);
        sha.update(msg.get(HEADER_LEN..sig_off).ok_or(FORMERR)?);
        let digest = sha.finalize();
        crypto
            .verify_digest(key, &digest, sig)
            .map_err(|_| REFUSED)?;
        Ok(())
    }

    fn handle_update<const V: usize>(&self, now: Instant, pend: &mut Pending<V>) -> R<()> {
        // A removal: the client may not list all services it has registered;
        // the server adds the known ones as removed.
        if pend.lease != 0 {
            return Ok(());
        }
        pend.addrs.clear();
        let Some(host) = pend.name.as_ref().and_then(|n| self.find_host(n)) else {
            return Ok(());
        };
        for s in self.services_of(host) {
            if s.deleted || pend.find(&s.instance).is_some() {
                continue;
            }
            let mut svc = Service::new(s.instance.clone(), now);
            svc.service_name = s.service_name.clone();
            svc.deleted = true;
            pend.services
                .push(PService {
                    svc,
                    delete_all: true,
                    srv: false,
                    txt: false,
                })
                .map_err(|_| SERVFAIL)?;
        }
        Ok(())
    }

    fn commit<const V: usize>(&mut self, now: Instant, pend: Pending<V>) -> R<Done> {
        let (Some(name), Some(key)) = (pend.name.clone(), pend.key) else {
            return Err(REFUSED);
        };
        let host_lease = pend.lease;
        let host_key_lease = pend.key_lease;
        let granted_lease = self.lease.grant_lease(host_lease);
        let granted_key = if pend.short {
            granted_lease
        } else {
            self.lease.grant_key_lease(host_key_lease)
        };
        let granted_ttl = self.ttl.grant(granted_lease, pend.ttl);
        let done_lease = if granted_lease == host_lease && granted_key == host_key_lease {
            None
        } else {
            Some((granted_lease, granted_key, pend.short))
        };
        let existing = self.host_idx(&name);

        if granted_key == 0 {
            if let Some(i) = existing {
                self.remove_host_at(i);
            }
            return Ok(Done {
                lease: done_lease,
                committed: false,
            });
        }

        // Capacity: hosts, and services after replacing the existing ones.
        let existing_id = existing.map(|i| self.hosts[i].id);
        let mut kept = 0usize;
        if let Some(id) = existing_id {
            for s in self.services.iter().filter(|s| s.host_id == id) {
                if pend.find(&s.instance).is_none() {
                    kept += 1;
                }
            }
        }
        let hosts_after = self.hosts.len() - usize::from(existing.is_some()) + 1;
        let others = self
            .services
            .iter()
            .filter(|s| Some(s.host_id) != existing_id)
            .count();
        if hosts_after > H || others + kept + pend.services.len() > S {
            return Err(SERVFAIL);
        }

        let id = match existing_id {
            Some(id) => id,
            None => {
                self.next_id = self.next_id.wrapping_add(1);
                while self.hosts.iter().any(|h| h.id == self.next_id) {
                    self.next_id = self.next_id.wrapping_add(1);
                }
                self.next_id
            }
        };
        let deleted_host = granted_lease == 0;
        if let Some(i) = existing {
            self.hosts.remove(i);
            // Existing services that the update lists are replaced; the
            // others are kept (and removed along with a removed host).
            self.services
                .retain(|s| s.host_id != id || pend.find(&s.instance).is_none());
            if deleted_host {
                for s in self.services.iter_mut().filter(|s| s.host_id == id) {
                    s.deleted = true;
                }
            }
        }
        let mut addrs = Vec::new();
        for a in &pend.addrs {
            let _ = addrs.push(*a);
        }
        let _ = self.hosts.push(Host {
            id,
            name,
            key,
            addresses: addrs,
            ttl: granted_ttl,
            lease: granted_lease,
            key_lease: granted_key,
            update_time: now,
        });
        for mut ps in pend.services {
            ps.svc.lease = granted_lease;
            ps.svc.key_lease = granted_key;
            ps.svc.ttl = granted_ttl;
            ps.svc.host_id = id;
            ps.svc.update_time = now;
            let _ = self.services.push(ps.svc);
        }
        Ok(Done {
            lease: done_lease,
            committed: true,
        })
    }

    // ------------------------------------------------------------ leases

    /// Expire leases (OT `HandleLeaseTimer`).
    pub fn poll(&mut self, now: Instant) {
        let mut i = 0;
        while i < self.hosts.len() {
            let host = &self.hosts[i];
            let id = host.id;
            if host.key_expire_time() <= now {
                self.remove_host_at(i);
                continue;
            }
            if host.is_deleted() {
                self.services
                    .retain(|s| s.host_id != id || s.key_expire_time() > now);
            } else if host.expire_time() <= now {
                for s in self.services.iter_mut().filter(|s| s.host_id == id) {
                    s.deleted = true;
                    s.lease = 0;
                }
                let h = &mut self.hosts[i];
                h.lease = 0;
                h.addresses.clear();
            } else {
                self.services
                    .retain(|s| s.host_id != id || s.key_expire_time() > now);
                for s in self.services.iter_mut().filter(|s| s.host_id == id) {
                    if !s.deleted && s.expire_time() <= now {
                        s.deleted = true;
                        s.lease = 0;
                    }
                }
            }
            i += 1;
        }
    }

    /// When [`SrpServer::poll`] needs to run next.
    pub fn next_deadline(&self) -> Option<Instant> {
        let mut next: Option<Instant> = None;
        let mut upd = |t: Instant| next = Some(next.map_or(t, |n| n.min(t)));
        for h in &self.hosts {
            upd(h.key_expire_time());
            if !h.is_deleted() {
                upd(h.expire_time());
            }
            for s in self.services.iter().filter(|s| s.host_id == h.id) {
                upd(s.key_expire_time());
                if !s.deleted && !h.is_deleted() {
                    upd(s.expire_time());
                }
            }
        }
        next
    }
}

struct Done {
    /// Granted `(lease, key lease, short variant)` if they differ from the
    /// request.
    lease: Option<(u32, u32, bool)>,
    committed: bool,
}

fn is_delete_all(rec: &crate::wire::Record<'_>) -> bool {
    rec.class == class::ANY && rec.rtype == rtype::ANY && rec.ttl == 0 && rec.rdata.is_empty()
}

/// TXT data that is a sequence of complete character strings and not empty.
fn verify_txt(d: &[u8]) -> bool {
    if d.is_empty() {
        return false;
    }
    let mut i = 0;
    while i < d.len() {
        i += 1 + usize::from(d[i]);
    }
    i == d.len()
}

mod dnssd;

#[cfg(all(test, feature = "srp-client", feature = "dns-client"))]
mod tests;
