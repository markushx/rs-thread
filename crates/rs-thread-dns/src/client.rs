//! DNS / DNS-SD client over UDP (OT `Dns::Client`, RFC 1035 / RFC 6763 /
//! RFC 8766 unicast queries as answered by an SRP server's DNS-SD front end
//! or a border router).
//!
//! Queries: host AAAA ([`DnsClient::resolve_address`]), service instance
//! browse by PTR ([`DnsClient::browse`]), and service instance resolution by
//! SRV + TXT with the host's AAAA taken from the additional section
//! ([`DnsClient::resolve_service`]).
//!
//! Defaults follow OT: server port 53, 6 s response timeout, 3 transmission
//! attempts, recursion desired, service mode "SRV+TXT optimize" (one query
//! with both questions; if it times out, two separate queries).
//!
//! # Driving the client
//!
//! - start a query (the first transmission happens immediately through
//!   [`DnsContext::send`]);
//! - feed every datagram received from the server port to
//!   [`DnsClient::handle_datagram`];
//! - call [`DnsClient::poll`] when [`DnsClient::next_deadline`] is reached;
//! - results arrive through [`DnsContext::result`].
//!
//! The default server is normally the SRP server selected by the SRP client's
//! auto-start (OT `UpdateDefaultConfigAddress`): pass the address from
//! the `ServerSelected` event of the SRP client to
//! [`DnsClient::set_default_server`].

use core::net::{Ipv6Addr, SocketAddrV6};

use heapless::{String, Vec};
use rand_core::Rng;
use rs_thread_core::time::{Duration, Instant};

use crate::wire::{Header, Name, Parser, Part, Writer, class, opcode, rcode, rtype};

/// Default DNS server port.
pub const DEFAULT_SERVER_PORT: u16 = 53;
/// Default response timeout (OT `DEFAULT_RESPONSE_TIMEOUT`, 6000 ms).
pub const DEFAULT_RESPONSE_TIMEOUT: Duration = Duration::from_millis(6000);
/// Default number of transmission attempts per query (OT: 3).
pub const DEFAULT_MAX_TX_ATTEMPTS: u8 = 3;
pub use crate::rdata::{MAX_LABEL, MAX_NAME, MAX_TXT};
/// Addresses kept per result.
pub const MAX_ADDRS: usize = 4;
/// Largest query message.
const MAX_QUERY: usize = 400;

/// How a service instance is resolved (OT `otDnsServiceMode`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum ServiceMode {
    /// SRV only.
    Srv,
    /// TXT only.
    Txt,
    /// One query with SRV and TXT questions.
    SrvTxt,
    /// Two queries, one per record type.
    SrvTxtSeparate,
    /// Try one combined query, fall back to two separate queries on timeout.
    #[default]
    SrvTxtOptimize,
}

/// Per-query configuration (OT `otDnsQueryConfig`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QueryConfig {
    /// Server address and port.
    pub server: SocketAddrV6,
    /// Time to wait for a response before retransmitting.
    pub response_timeout: Duration,
    /// Transmission attempts before the query fails.
    pub max_tx_attempts: u8,
    /// Set the "recursion desired" flag.
    pub recursion_desired: bool,
    /// Service resolution mode.
    pub service_mode: ServiceMode,
}

impl QueryConfig {
    /// Default configuration (see the module docs) for `server`.
    pub const fn new(server: SocketAddrV6) -> Self {
        Self {
            server,
            response_timeout: DEFAULT_RESPONSE_TIMEOUT,
            max_tx_attempts: DEFAULT_MAX_TX_ATTEMPTS,
            recursion_desired: true,
            service_mode: ServiceMode::SrvTxtOptimize,
        }
    }
}

/// Why a query failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum DnsError {
    /// Name error or no matching records.
    NotFound,
    /// No response after all attempts.
    ResponseTimeout,
    /// The server answered with this non-zero response code.
    Rcode(u8),
    /// Malformed response.
    Parse,
    /// The response was truncated (DNS over TCP is not supported).
    Truncated,
    /// A result did not fit the fixed-size buffers.
    NoBufs,
    /// The query was cancelled.
    Aborted,
}

/// Handle of a running query. Valid until its result is delivered or it is
/// cancelled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct QueryId(pub u8);

/// One AAAA record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AddressInfo {
    /// The address.
    pub addr: Ipv6Addr,
    /// Its TTL in seconds.
    pub ttl: u32,
}

/// Result of an address query.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ResolvedAddresses {
    /// AAAA records (at most [`MAX_ADDRS`]).
    pub addrs: Vec<AddressInfo, MAX_ADDRS>,
}

/// A resolved service instance (SRV + TXT + host addresses).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ResolvedService {
    /// SRV priority.
    pub priority: u16,
    /// SRV weight.
    pub weight: u16,
    /// SRV port.
    pub port: u16,
    /// SRV TTL.
    pub ttl: u32,
    /// Host name (dotted).
    pub host: String<MAX_NAME>,
    /// Raw TXT rdata (empty if the instance has no TXT record); decode with
    /// [`crate::rdata::TxtIter`].
    pub txt: Vec<u8, MAX_TXT>,
    /// TXT TTL.
    pub txt_ttl: u32,
    /// Host addresses found in the response (may be empty: resolve the host
    /// separately).
    pub addrs: Vec<AddressInfo, MAX_ADDRS>,
}

/// A browse response: the PTR instances and whatever the server included in
/// the additional section.
#[derive(Debug, Clone, Copy)]
pub struct BrowseResponse<'a> {
    msg: &'a [u8],
    service: &'a str,
}

impl<'a> BrowseResponse<'a> {
    /// Instance names (PTR targets of the browsed service type).
    pub fn instances(&self) -> impl Iterator<Item = Name<'a>> + 'a {
        let service = self.service;
        records(self.msg)
            .into_iter()
            .flatten()
            .filter_map(move |r| {
                (r.rtype == rtype::PTR && r.name.eq_dotted(service))
                    .then(|| r.ptr().ok())
                    .flatten()
            })
    }

    /// SRV / TXT / AAAA of `instance` from the response (OT
    /// `BrowseResponse::GetServiceInfo`).
    pub fn service_info(&self, instance: &Name<'_>) -> Result<ResolvedService, DnsError> {
        let mut acc = ResolvedService::default();
        let (srv, _) = extract_service(self.msg, |n| n.eq_name(instance), &mut acc)?;
        if srv {
            Ok(acc)
        } else {
            Err(DnsError::NotFound)
        }
    }

    /// The whole response message.
    pub const fn message(&self) -> &'a [u8] {
        self.msg
    }
}

/// Section of a record in a response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Section {
    /// Answer.
    Answer,
    /// Authority.
    Authority,
    /// Additional.
    Additional,
}

/// The response of an arbitrary record query.
#[derive(Debug, Clone, Copy)]
pub struct RecordsResponse<'a> {
    msg: &'a [u8],
}

impl<'a> RecordsResponse<'a> {
    /// Wrap a response message.
    pub const fn from_message(msg: &'a [u8]) -> Self {
        Self { msg }
    }

    /// The response message.
    pub const fn message(&self) -> &'a [u8] {
        self.msg
    }

    /// The records with their section (OPT records excluded).
    pub fn records(self) -> impl Iterator<Item = (Section, crate::wire::Record<'a>)> + 'a {
        let (an, ns) = Parser::new(self.msg)
            .map(|(_, h)| (usize::from(h.an), usize::from(h.ns)))
            .unwrap_or((0, 0));
        records(self.msg)
            .into_iter()
            .flatten()
            .enumerate()
            .filter(|(_, r)| r.rtype != rtype::OPT)
            .map(move |(i, r)| {
                let sec = if i < an {
                    Section::Answer
                } else if i < an + ns {
                    Section::Authority
                } else {
                    Section::Additional
                };
                (sec, r)
            })
    }
}

/// A delivered query result.
#[derive(Debug)]
pub enum DnsResult<'a> {
    /// AAAA records of the queried host.
    Address(&'a ResolvedAddresses),
    /// Browse response.
    Browse(BrowseResponse<'a>),
    /// Resolved service instance.
    Service(&'a ResolvedService),
    /// Records of an arbitrary record query.
    Records(RecordsResponse<'a>),
    /// The query failed.
    Failed(DnsError),
}

/// Outputs of the client.
pub trait DnsContext {
    /// Send a UDP datagram to `server` (the stack picks the source address
    /// and an ephemeral port).
    fn send(&mut self, server: SocketAddrV6, payload: &[u8]) -> rs_thread_core::Result<()>;

    /// A query completed.
    fn result(&mut self, id: QueryId, result: DnsResult<'_>);
}

// ---------------------------------------------------------------- internals

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Browse,
    Address,
    Service,
    Record,
}

#[derive(Debug, Clone, Copy)]
struct Wire {
    active: bool,
    done: bool,
    id: u16,
    qtypes: [u16; 2],
    tx: u8,
    retry_at: Instant,
}

impl Wire {
    const IDLE: Self = Self {
        active: false,
        done: false,
        id: 0,
        qtypes: [0; 2],
        tx: 0,
        retry_at: Instant::ZERO,
    };
}

#[derive(Debug, Clone)]
struct Slot {
    kind: Kind,
    config: QueryConfig,
    name: String<MAX_NAME>,
    label: String<MAX_LABEL>,
    rrtype: u16,
    wires: [Wire; 2],
    /// Combined SRV+TXT query that may fall back to separate queries.
    fallback_pending: bool,
    acc: ResolvedService,
    have_srv: bool,
}

impl Slot {
    fn parts(&self) -> ([Part<'_>; 2], usize) {
        match self.kind {
            Kind::Service | Kind::Record => {
                ([Part::Label(&self.label), Part::Dotted(&self.name)], 2)
            }
            _ => ([Part::Dotted(&self.name), Part::Dotted("")], 1),
        }
    }

    fn build(&self, w: usize, buf: &mut [u8]) -> rs_thread_core::Result<usize> {
        let wire = &self.wires[w];
        let mut wr = Writer::new(buf)?;
        let nq = wire.qtypes.iter().filter(|&&t| t != 0).count();
        let (parts, np) = self.parts();
        for &qt in wire.qtypes.iter().filter(|&&t| t != 0) {
            wr.write_name_parts(&parts[..np], true)?;
            wr.put_u16(qt)?;
            wr.put_u16(class::IN)?;
        }
        wr.set_header(&Header {
            id: wire.id,
            opcode: opcode::QUERY,
            rd: self.config.recursion_desired,
            qd: nq as u16,
            ..Header::default()
        });
        Ok(wr.len())
    }
}

/// The DNS client with room for `Q` concurrent queries.
#[derive(Debug, Clone)]
pub struct DnsClient<const Q: usize = 4> {
    slots: [Option<Slot>; Q],
    default_server: Option<SocketAddrV6>,
    /// The address was set by the user (not adopted from the SRP server).
    user_addr: bool,
    cfg: DefaultOptions,
    rrtype_next: u16,
}

/// The default query options besides the server.
#[derive(Debug, Clone, Copy)]
struct DefaultOptions {
    timeout: Duration,
    attempts: u8,
    recursion: bool,
    mode: ServiceMode,
}

impl DefaultOptions {
    const INIT: Self = Self {
        timeout: DEFAULT_RESPONSE_TIMEOUT,
        attempts: DEFAULT_MAX_TX_ATTEMPTS,
        recursion: true,
        mode: ServiceMode::SrvTxtOptimize,
    };
}

/// A default configuration with unspecified (`None`) fields (OT
/// `otDnsClientSetDefaultConfig`: they take the built-in defaults).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PartialConfig {
    /// Server; an unspecified address adopts the SRP server's.
    pub server: Option<SocketAddrV6>,
    /// Response timeout.
    pub timeout: Option<Duration>,
    /// Transmission attempts.
    pub attempts: Option<u8>,
    /// Recursion desired.
    pub recursion: Option<bool>,
    /// Service mode.
    pub mode: Option<ServiceMode>,
}

impl<const Q: usize> Default for DnsClient<Q> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const Q: usize> DnsClient<Q> {
    /// No queries, no default server.
    pub const fn new() -> Self {
        Self {
            slots: [const { None }; Q],
            default_server: None,
            user_addr: false,
            cfg: DefaultOptions::INIT,
            rrtype_next: 0,
        }
    }

    /// Set (or clear) the server used when a query gives no configuration.
    pub fn set_default_server(&mut self, server: Option<SocketAddrV6>) {
        self.default_server = server;
        self.user_addr = server.is_some();
    }

    /// The default configuration; an unset server reads `[::]:53`.
    pub fn default_config(&self) -> QueryConfig {
        let server = self
            .default_server
            .unwrap_or_else(|| SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, DEFAULT_SERVER_PORT, 0, 0));
        QueryConfig {
            server,
            response_timeout: self.cfg.timeout,
            max_tx_attempts: self.cfg.attempts,
            recursion_desired: self.cfg.recursion,
            service_mode: self.cfg.mode,
        }
    }

    /// Set the default configuration; unspecified fields take the built-in
    /// defaults. `srp_server`: the SRP server selected by auto-start, whose
    /// address is adopted unless the config names a server.
    pub fn set_default_config(&mut self, c: PartialConfig, srp_server: Option<Ipv6Addr>) {
        self.cfg = DefaultOptions {
            timeout: c.timeout.unwrap_or(DefaultOptions::INIT.timeout),
            attempts: c.attempts.unwrap_or(DefaultOptions::INIT.attempts),
            recursion: c.recursion.unwrap_or(DefaultOptions::INIT.recursion),
            mode: c.mode.unwrap_or(DefaultOptions::INIT.mode),
        };
        match c.server.filter(|s| !s.ip().is_unspecified()) {
            Some(s) => {
                self.default_server = Some(s);
                self.user_addr = true;
            }
            None => {
                self.user_addr = false;
                self.default_server = None;
                self.on_srp_server_selected(srp_server);
            }
        }
    }

    /// The SRP client selected a server by auto-start (OT
    /// `UpdateDefaultConfigAddress`): its address becomes the default DNS
    /// server (port 53) unless the user set one.
    pub fn on_srp_server_selected(&mut self, addr: Option<Ipv6Addr>) {
        if let Some(a) = addr.filter(|a| !a.is_unspecified())
            && !self.user_addr
        {
            self.default_server = Some(SocketAddrV6::new(a, DEFAULT_SERVER_PORT, 0, 0));
        }
    }

    /// The default server.
    pub const fn default_server(&self) -> Option<SocketAddrV6> {
        self.default_server
    }

    /// Number of running queries.
    pub fn active_queries(&self) -> usize {
        self.slots.iter().flatten().count()
    }

    /// Browse for instances of `service` (e.g. `_matter._tcp.default.service.arpa`).
    pub fn browse<R: Rng + ?Sized, X: DnsContext>(
        &mut self,
        now: Instant,
        rng: &mut R,
        ctx: &mut X,
        service: &str,
        config: Option<QueryConfig>,
    ) -> rs_thread_core::Result<QueryId> {
        self.start(now, rng, ctx, Kind::Browse, "", service, config)
    }

    /// Resolve the AAAA records of `host`.
    pub fn resolve_address<R: Rng + ?Sized, X: DnsContext>(
        &mut self,
        now: Instant,
        rng: &mut R,
        ctx: &mut X,
        host: &str,
        config: Option<QueryConfig>,
    ) -> rs_thread_core::Result<QueryId> {
        self.start(now, rng, ctx, Kind::Address, "", host, config)
    }

    /// Resolve service instance `instance` (a single label, may contain
    /// dots) of type `service`.
    pub fn resolve_service<R: Rng + ?Sized, X: DnsContext>(
        &mut self,
        now: Instant,
        rng: &mut R,
        ctx: &mut X,
        instance: &str,
        service: &str,
        config: Option<QueryConfig>,
    ) -> rs_thread_core::Result<QueryId> {
        self.start(now, rng, ctx, Kind::Service, instance, service, config)
    }

    /// Query records of type `rrtype` for `<first_label>.<next_labels>`
    /// (the first label may contain dots).
    #[allow(clippy::too_many_arguments)]
    pub fn query_record<R: Rng + ?Sized, X: DnsContext>(
        &mut self,
        now: Instant,
        rng: &mut R,
        ctx: &mut X,
        rrtype: u16,
        first_label: &str,
        next_labels: &str,
        config: Option<QueryConfig>,
    ) -> rs_thread_core::Result<QueryId> {
        self.rrtype_next = rrtype;
        self.start(
            now,
            rng,
            ctx,
            Kind::Record,
            first_label,
            next_labels,
            config,
        )
    }

    /// Cancel a query; no result is delivered.
    pub fn cancel(&mut self, id: QueryId) {
        if let Some(s) = self.slots.get_mut(usize::from(id.0)) {
            *s = None;
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn start<R: Rng + ?Sized, X: DnsContext>(
        &mut self,
        now: Instant,
        rng: &mut R,
        ctx: &mut X,
        kind: Kind,
        label: &str,
        name: &str,
        config: Option<QueryConfig>,
    ) -> rs_thread_core::Result<QueryId> {
        use rs_thread_core::Error;
        let config = config
            .or_else(|| self.default_server.map(|_| self.default_config()))
            .ok_or(Error::InvalidState)?;
        if config.max_tx_attempts == 0 {
            return Err(Error::InvalidArgs);
        }
        let idx = self
            .slots
            .iter()
            .position(Option::is_none)
            .ok_or(Error::NoBufs)?;
        let name = name.strip_suffix('.').unwrap_or(name);
        let mut slot = Slot {
            kind,
            config,
            name: String::try_from(name).map_err(|_| Error::InvalidArgs)?,
            label: String::try_from(label).map_err(|_| Error::InvalidArgs)?,
            rrtype: self.rrtype_next,
            wires: [Wire::IDLE; 2],
            fallback_pending: false,
            acc: ResolvedService::default(),
            have_srv: false,
        };
        if name.is_empty() && kind != Kind::Browse {
            return Err(Error::InvalidArgs);
        }
        slot.wires[0].active = true;
        match kind {
            Kind::Browse => slot.wires[0].qtypes[0] = rtype::PTR,
            Kind::Address => slot.wires[0].qtypes[0] = rtype::AAAA,
            Kind::Record => slot.wires[0].qtypes[0] = slot.rrtype,
            Kind::Service => match config.service_mode {
                ServiceMode::Srv => slot.wires[0].qtypes[0] = rtype::SRV,
                ServiceMode::Txt => slot.wires[0].qtypes[0] = rtype::TXT,
                ServiceMode::SrvTxt | ServiceMode::SrvTxtOptimize => {
                    slot.wires[0].qtypes = [rtype::SRV, rtype::TXT];
                    slot.fallback_pending = config.service_mode == ServiceMode::SrvTxtOptimize;
                }
                ServiceMode::SrvTxtSeparate => {
                    slot.wires[0].qtypes[0] = rtype::SRV;
                    slot.wires[1].active = true;
                    slot.wires[1].qtypes[0] = rtype::TXT;
                }
            },
        }
        let ids = [random_id(rng, &self.slots, &[]), 0];
        slot.wires[0].id = ids[0];
        if slot.wires[1].active {
            slot.wires[1].id = random_id(rng, &self.slots, &[ids[0]]);
        }
        // The first transmission must succeed (nothing is retried for the
        // caller otherwise).
        for w in 0..2 {
            if slot.wires[w].active {
                transmit(&mut slot, w, now, ctx)?;
            }
        }
        self.slots[idx] = Some(slot);
        Ok(QueryId(idx as u8))
    }

    /// Earliest retransmission / timeout deadline.
    pub fn next_deadline(&self) -> Option<Instant> {
        self.slots
            .iter()
            .flatten()
            .flat_map(|s| s.wires.iter())
            .filter(|w| w.active && !w.done)
            .map(|w| w.retry_at)
            .min()
    }

    /// Retransmit queries whose response timeout expired; fail those out of
    /// attempts.
    pub fn poll<R: Rng + ?Sized, X: DnsContext>(&mut self, now: Instant, rng: &mut R, ctx: &mut X) {
        for i in 0..Q {
            let Some(slot) = self.slots[i].as_mut() else {
                continue;
            };
            let mut fail = false;
            let mut fallback = false;
            for w in 0..2 {
                let wire = slot.wires[w];
                if !wire.active || wire.done || now < wire.retry_at {
                    continue;
                }
                if wire.tx >= slot.config.max_tx_attempts || slot.fallback_pending {
                    if slot.fallback_pending {
                        fallback = true;
                    } else {
                        fail = true;
                    }
                    break;
                }
                // A failed retransmission is retried at the next timeout.
                let _ = transmit(slot, w, now, ctx);
            }
            if fallback {
                // Replace the combined query by separate SRV and TXT queries.
                slot.fallback_pending = false;
                slot.wires[0].qtypes = [rtype::SRV, 0];
                slot.wires[0].tx = 0;
                slot.wires[1] = Wire {
                    active: true,
                    qtypes: [rtype::TXT, 0],
                    ..Wire::IDLE
                };
                let taken = [slot.wires[0].id];
                let id1 = random_id(rng, &[], &taken);
                slot.wires[1].id = id1;
                let _ = transmit(slot, 0, now, ctx);
                let _ = transmit(slot, 1, now, ctx);
            }
            if fail {
                self.finish(i, DnsResult::Failed(DnsError::ResponseTimeout), ctx);
            }
        }
    }

    fn finish<X: DnsContext>(&mut self, idx: usize, result: DnsResult<'_>, ctx: &mut X) {
        self.slots[idx] = None;
        ctx.result(QueryId(idx as u8), result);
    }

    /// Process a datagram received from `from` (the DNS server port).
    /// Datagrams that match no running query are ignored.
    pub fn handle_datagram<X: DnsContext>(
        &mut self,
        from: SocketAddrV6,
        payload: &[u8],
        ctx: &mut X,
    ) {
        let Ok((mut parser, hdr)) = Parser::new(payload) else {
            return;
        };
        if !hdr.response || hdr.opcode != opcode::QUERY {
            return;
        }
        let Some((i, w)) = self.slots.iter().enumerate().find_map(|(i, s)| {
            let s = s.as_ref()?;
            if s.config.server != from {
                return None;
            }
            (0..2)
                .find(|&w| s.wires[w].active && !s.wires[w].done && s.wires[w].id == hdr.id)
                .map(|w| (i, w))
        }) else {
            return;
        };
        let slot = self.slots[i].as_mut().expect("found above");
        // The first question must echo the query name (guards against ID
        // collisions).
        if hdr.qd > 0 {
            let Ok(q) = parser.question() else {
                return;
            };
            let (parts, np) = slot.parts();
            if !q.name.eq_parts(&parts[..np]) {
                return;
            }
        }
        if hdr.tc {
            return self.finish(i, DnsResult::Failed(DnsError::Truncated), ctx);
        }
        let kind = slot.kind;
        // A TXT lookup that finds nothing is not fatal for a service.
        let soft_txt = kind == Kind::Service && slot.wires[w].qtypes == [rtype::TXT, 0];
        if hdr.rcode != rcode::SUCCESS && !soft_txt {
            let e = if hdr.rcode == rcode::NAME_ERROR {
                DnsError::NotFound
            } else {
                DnsError::Rcode(hdr.rcode)
            };
            return self.finish(i, DnsResult::Failed(e), ctx);
        }
        match kind {
            Kind::Address => {
                let mut out = ResolvedAddresses::default();
                let qname = slot.name.clone();
                match collect_addresses(payload, |n| n.eq_dotted(&qname), &mut out.addrs) {
                    Ok(()) if !out.addrs.is_empty() => {
                        self.finish(i, DnsResult::Address(&out), ctx)
                    }
                    Ok(()) => self.finish(i, DnsResult::Failed(DnsError::NotFound), ctx),
                    Err(e) => self.finish(i, DnsResult::Failed(e), ctx),
                }
            }
            Kind::Browse => {
                let service = slot.name.clone();
                let resp = BrowseResponse {
                    msg: payload,
                    service: &service,
                };
                if resp.instances().next().is_none() {
                    self.finish(i, DnsResult::Failed(DnsError::NotFound), ctx);
                } else {
                    self.finish(i, DnsResult::Browse(resp), ctx);
                }
            }
            Kind::Record => {
                self.finish(i, DnsResult::Records(RecordsResponse { msg: payload }), ctx)
            }
            Kind::Service => {
                let label = slot.label.clone();
                let name = slot.name.clone();
                let is_instance =
                    |n: &Name<'_>| n.eq_parts(&[Part::Label(&label), Part::Dotted(&name)]);
                let mut acc = core::mem::take(&mut slot.acc);
                let r = if soft_txt && hdr.rcode != rcode::SUCCESS {
                    Ok((false, false))
                } else {
                    extract_service(payload, is_instance, &mut acc)
                };
                let slot = self.slots[i].as_mut().expect("still present");
                slot.acc = acc;
                let (srv, _txt) = match r {
                    Ok(v) => v,
                    Err(e) => return self.finish(i, DnsResult::Failed(e), ctx),
                };
                slot.have_srv |= srv;
                slot.wires[w].done = true;
                let separate = slot.wires[1].active;
                let all_done = slot.wires.iter().all(|x| !x.active || x.done);
                let wants_srv = slot.config.service_mode != ServiceMode::Txt;
                if separate && !all_done {
                    return;
                }
                if wants_srv && !slot.have_srv {
                    return self.finish(i, DnsResult::Failed(DnsError::NotFound), ctx);
                }
                if !wants_srv && slot.acc.txt.is_empty() && !soft_txt {
                    return self.finish(i, DnsResult::Failed(DnsError::NotFound), ctx);
                }
                let acc = core::mem::take(&mut slot.acc);
                self.finish(i, DnsResult::Service(&acc), ctx);
            }
        }
    }
}

fn random_id<R: Rng + ?Sized, const Q: usize>(
    rng: &mut R,
    slots: &[Option<Slot>; Q],
    also: &[u16],
) -> u16 {
    loop {
        let id = rng.next_u32() as u16;
        if id != 0
            && !also.contains(&id)
            && !slots
                .iter()
                .flatten()
                .any(|s| s.wires.iter().any(|w| w.active && w.id == id))
        {
            return id;
        }
    }
}

fn transmit<X: DnsContext>(
    slot: &mut Slot,
    w: usize,
    now: Instant,
    ctx: &mut X,
) -> rs_thread_core::Result<()> {
    let mut buf = [0u8; MAX_QUERY];
    let n = slot.build(w, &mut buf)?;
    slot.wires[w].tx += 1;
    slot.wires[w].retry_at = now.saturating_add(slot.config.response_timeout);
    ctx.send(slot.config.server, &buf[..n])
}

// ---------------------------------------------------------- response parsing

/// All records of a response (after the question section) as an iterator;
/// stops silently at the first malformed record.
fn records(msg: &[u8]) -> Option<impl Iterator<Item = crate::wire::Record<'_>>> {
    let (mut p, h) = Parser::new(msg).ok()?;
    for _ in 0..h.qd {
        p.question().ok()?;
    }
    let total = usize::from(h.an) + usize::from(h.ns) + usize::from(h.ar);
    let mut left = total;
    Some(core::iter::from_fn(move || {
        if left == 0 {
            return None;
        }
        left -= 1;
        match p.record() {
            Ok(r) => Some(r),
            Err(_) => {
                left = 0;
                None
            }
        }
    }))
}

fn collect_addresses<F: Fn(&Name<'_>) -> bool>(
    msg: &[u8],
    owner_matches: F,
    out: &mut Vec<AddressInfo, MAX_ADDRS>,
) -> Result<(), DnsError> {
    for r in records(msg).ok_or(DnsError::Parse)? {
        if r.rtype == rtype::AAAA && r.class == class::IN && owner_matches(&r.name) {
            let addr = r.aaaa().map_err(|_| DnsError::Parse)?;
            // Extra addresses beyond the capacity are dropped.
            let _ = out.push(AddressInfo { addr, ttl: r.ttl });
        }
    }
    Ok(())
}

/// Fill `acc` from the SRV / TXT of the instance (matched by
/// `is_instance`) and the AAAA records of the SRV target. Returns whether
/// an SRV and a TXT record were found.
fn extract_service<F: Fn(&Name<'_>) -> bool>(
    msg: &[u8],
    is_instance: F,
    acc: &mut ResolvedService,
) -> Result<(bool, bool), DnsError> {
    let (mut srv, mut txt) = (false, false);
    let mut target: Option<Name<'_>> = None;
    for r in records(msg).ok_or(DnsError::Parse)? {
        if r.class != class::IN || !is_instance(&r.name) {
            continue;
        }
        match r.rtype {
            rtype::SRV if !srv => {
                let s = r.srv().map_err(|_| DnsError::Parse)?;
                acc.priority = s.priority;
                acc.weight = s.weight;
                acc.port = s.port;
                acc.ttl = r.ttl;
                acc.host.clear();
                s.target
                    .fmt_dotted(&mut acc.host)
                    .map_err(|_| DnsError::NoBufs)?;
                target = Some(s.target);
                srv = true;
            }
            rtype::TXT if !txt => {
                acc.txt.clear();
                acc.txt
                    .extend_from_slice(r.rdata)
                    .map_err(|_| DnsError::NoBufs)?;
                acc.txt_ttl = r.ttl;
                txt = true;
            }
            _ => {}
        }
    }
    if let Some(t) = target {
        acc.addrs.clear();
        collect_addresses(msg, |n| n.eq_name(&t), &mut acc.addrs)?;
    }
    Ok((srv, txt))
}
