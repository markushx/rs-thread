//! SRP client and DNS client of the instance: UDP transport through the
//! instance's sockets, Network Data auto-start, host addresses from the
//! interface and persistence of the key and the server.
//!
//! OpenThread: `Srp::Client` (`otSrpClient*`), `Dns::Client` (`otDnsClient*`).

use core::net::{Ipv6Addr, SocketAddrV6};

use heapless::{Deque, String, Vec};
use opentrust_core::bufpool::{BufPool, Chain, POOL_BUF_SIZE};
use opentrust_core::crypto::ecdsa::SecretKey;
use opentrust_core::settings::SettingsKey;
use opentrust_core::time::Instant;
use opentrust_core::{Error, Result};
use opentrust_dns::client::{
    DnsClient, DnsContext, DnsError, DnsResult, MAX_LABEL, QueryConfig, QueryId, ResolvedAddresses,
    ResolvedService,
};
use opentrust_dns::srp::discovery::NetDataService;
use opentrust_dns::srp::{
    ItemState, MAX_HOST_ADDRS, ServiceConfig, ServiceId, SrpClient, SrpContext, SrpEnv, SrpError,
    SrpEvent, filter_auto_addresses,
};
use opentrust_mesh::netdata::ServiceEntry;
use opentrust_net::header::{MAX_DATAGRAM_LEN, PROTO_UDP};
use opentrust_net::udp::{SocketHandle, UdpSendOpts};
use opentrust_platform::SettingsStore;
use rand_core::{CryptoRng, Rng};

use crate::InstanceCrypto;

use crate::{Event, Instance, MAX_UDP_PAYLOAD};

/// Instances reported by one browse result.
pub const MAX_BROWSE_INSTANCES: usize = 4;

/// One instance of a browse result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrowseInstance {
    /// Instance label.
    pub label: String<MAX_LABEL>,
    /// SRV / TXT / AAAA of the instance if the server sent them in the
    /// additional section.
    pub info: Option<ResolvedService>,
}

/// The owned result of a DNS query ([`Event::DnsResult`],
/// [`Instance::dns_take_result`]).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[allow(clippy::large_enum_variant)] // no allocation: the result is a plain value
pub enum DnsOutcome {
    /// AAAA records of a host.
    Address(ResolvedAddresses),
    /// Instances of a browsed service type.
    Browse(Vec<BrowseInstance, MAX_BROWSE_INSTANCES>),
    /// A resolved service instance.
    Service(ResolvedService),
    /// The query failed.
    Failed(DnsError),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Which {
    Srp,
    Dns,
}

#[derive(Debug)]
struct Dgram {
    which: Which,
    dst: SocketAddrV6,
    len: usize,
    buf: [u8; MAX_UDP_PAYLOAD],
}

/// Queue of datagrams of the clients; the payloads are chains of buffers of
/// a pool (`NoBufs` when it is exhausted).
#[derive(Debug, Default)]
struct DgramQueue {
    q: Deque<(Which, SocketAddrV6, Chain), 2>,
    pool: BufPool<12, POOL_BUF_SIZE>,
}

impl DgramQueue {
    fn push(&mut self, which: Which, dst: SocketAddrV6, p: &[u8]) -> Result<()> {
        if self.q.is_full() {
            return Err(Error::NoBufs);
        }
        let chain = self.pool.alloc(p)?;
        let _ = self.q.push_back((which, dst, chain));
        Ok(())
    }

    fn is_empty(&self) -> bool {
        self.q.is_empty()
    }

    fn pop_front(&mut self) -> Option<Dgram> {
        let (which, dst, chain) = self.q.pop_front()?;
        let mut buf = [0u8; MAX_UDP_PAYLOAD];
        let len = self.pool.read(&chain, &mut buf);
        self.pool.free(chain);
        Some(Dgram {
            which,
            dst,
            len,
            buf,
        })
    }
}

/// Services the SRP client registers at once. Matter needs the commissionable
/// service plus one operational service per fabric (at least five fabrics), so
/// the default is six; the features `srp-services-8` and `srp-services-12`
/// raise it. Each slot costs about the size of a `ServiceConfig` plus its
/// update state (see `docs/memory-budget.md`).
#[cfg(feature = "srp-services-12")]
pub const SRP_SERVICES: usize = 12;
/// See above.
#[cfg(all(feature = "srp-services-8", not(feature = "srp-services-12")))]
pub const SRP_SERVICES: usize = 8;
/// See above.
#[cfg(not(any(feature = "srp-services-8", feature = "srp-services-12")))]
pub const SRP_SERVICES: usize = 6;

/// State of the SRP and DNS clients.
#[derive(Debug)]
pub(crate) struct DnsSrp {
    pub(crate) srp: SrpClient<SRP_SERVICES>,
    pub(crate) dns: DnsClient<4>,
    srp_sock: Option<SocketHandle>,
    dns_sock: Option<SocketHandle>,
    out: DgramQueue,
    srp_events: Deque<SrpEvent, 4>,
    /// The last failed update, until the application takes it.
    srp_failure: Option<SrpError>,
    results: Deque<(QueryId, DnsOutcome), 2>,
    /// Results already announced with an event.
    notified: usize,
    attached: bool,
    nd_hash: Option<u64>,
    addr_hash: Option<u64>,
}

impl DnsSrp {
    pub(crate) fn new() -> Self {
        Self {
            srp: SrpClient::new(),
            dns: DnsClient::new(),
            srp_sock: None,
            dns_sock: None,
            out: DgramQueue::default(),
            srp_events: Deque::new(),
            srp_failure: None,
            results: Deque::new(),
            notified: 0,
            attached: false,
            nd_hash: None,
            addr_hash: None,
        }
    }

    pub(crate) fn next_deadline(&self) -> Option<Instant> {
        [self.srp.next_deadline(), self.dns.next_deadline()]
            .into_iter()
            .flatten()
            .min()
    }

    pub(crate) fn has_pending_work(&self) -> bool {
        !self.out.is_empty() || !self.srp_events.is_empty() || self.results.len() > self.notified
    }
}

/// Settings value of `SrpClientInfo`: server address and port (OT
/// `SrpClientInfo`: `mServerAddress`, `mServerPort`).
const SERVER_INFO_LEN: usize = 18;

struct SrpCtx<'a, S> {
    out: &'a mut DgramQueue,
    events: &'a mut Deque<SrpEvent, 4>,
    settings: &'a mut S,
    addrs: Vec<Ipv6Addr, MAX_HOST_ADDRS>,
    ml_eid: Ipv6Addr,
}

fn queue(out: &mut DgramQueue, which: Which, dst: SocketAddrV6, p: &[u8]) -> Result<()> {
    out.push(which, dst, p)
}

impl<S: SettingsStore> SrpContext for SrpCtx<'_, S> {
    fn send(&mut self, server: SocketAddrV6, payload: &[u8]) -> Result<()> {
        queue(self.out, Which::Srp, server, payload)
    }
    fn event(&mut self, event: SrpEvent) {
        if self.events.is_full() {
            let _ = self.events.pop_front();
        }
        let _ = self.events.push_back(event);
    }
    fn auto_addresses(&mut self, out: &mut Vec<Ipv6Addr, MAX_HOST_ADDRS>) {
        out.clone_from(&self.addrs);
    }
    fn ml_eid(&mut self) -> Ipv6Addr {
        self.ml_eid
    }
    fn load_key(&mut self) -> Option<SecretKey> {
        let mut b = [0u8; 32];
        match self.settings.get(SettingsKey::SrpEcdsaKey, 0, &mut b) {
            Ok(32) => Some(SecretKey(b)),
            _ => None,
        }
    }
    fn store_key(&mut self, key: &SecretKey) {
        let _ = self.settings.set(SettingsKey::SrpEcdsaKey, &key.0);
    }
    fn load_server(&mut self) -> Option<SocketAddrV6> {
        let mut b = [0u8; SERVER_INFO_LEN];
        match self.settings.get(SettingsKey::SrpClientInfo, 0, &mut b) {
            Ok(SERVER_INFO_LEN) => {
                let mut a = [0u8; 16];
                a.copy_from_slice(&b[..16]);
                Some(SocketAddrV6::new(
                    Ipv6Addr::from(a),
                    u16::from_be_bytes([b[16], b[17]]),
                    0,
                    0,
                ))
            }
            _ => None,
        }
    }
    fn store_server(&mut self, server: Option<SocketAddrV6>) {
        match server {
            Some(s) => {
                let mut b = [0u8; SERVER_INFO_LEN];
                b[..16].copy_from_slice(&s.ip().octets());
                b[16..].copy_from_slice(&s.port().to_be_bytes());
                let _ = self.settings.set(SettingsKey::SrpClientInfo, &b);
            }
            None => {
                let _ = self.settings.delete(SettingsKey::SrpClientInfo, None);
            }
        }
    }
}

struct DnsCtx<'a> {
    out: &'a mut DgramQueue,
    results: &'a mut Deque<(QueryId, DnsOutcome), 2>,
}

impl DnsContext for DnsCtx<'_> {
    fn send(&mut self, server: SocketAddrV6, payload: &[u8]) -> Result<()> {
        queue(self.out, Which::Dns, server, payload)
    }
    fn result(&mut self, id: QueryId, result: DnsResult<'_>) {
        let o = match result {
            DnsResult::Address(a) => DnsOutcome::Address(a.clone()),
            DnsResult::Service(s) => DnsOutcome::Service(s.clone()),
            DnsResult::Failed(e) => DnsOutcome::Failed(e),
            DnsResult::Browse(b) => {
                let mut v: Vec<BrowseInstance, MAX_BROWSE_INSTANCES> = Vec::new();
                for name in b.instances() {
                    let Some(Ok(l)) = name.labels().next() else {
                        continue;
                    };
                    let Ok(l) = core::str::from_utf8(l) else {
                        continue;
                    };
                    let Ok(label) = String::try_from(l) else {
                        continue;
                    };
                    let info = b.service_info(&name).ok();
                    if v.push(BrowseInstance { label, info }).is_err() {
                        break;
                    }
                }
                DnsOutcome::Browse(v)
            }
        };
        if self.results.is_full() {
            let _ = self.results.pop_front();
        }
        let _ = self.results.push_back((id, o));
    }
}

fn adapt(e: ServiceEntry<'_>) -> NetDataService<'_> {
    NetDataService {
        service_id: e.service_id,
        enterprise_number: e.enterprise_number,
        service_data: e.service_data,
        rloc16: e.rloc16,
        server_data: e.server_data,
    }
}

fn fnv(h: &mut u64, b: &[u8]) {
    for x in b {
        *h = (*h ^ u64::from(*x)).wrapping_mul(0x0000_0100_0000_01b3);
    }
}

impl<S: SettingsStore, C: InstanceCrypto, R: Rng + CryptoRng> Instance<S, C, R> {
    fn auto_addrs(&self) -> Vec<Ipv6Addr, MAX_HOST_ADDRS> {
        let mut v = Vec::new();
        let mlp = self.core.cfg.cur.mesh_local_prefix;
        filter_auto_addresses(
            self.core
                .ip6
                .netif
                .unicast_addresses()
                .filter(|a| a.valid)
                .map(|a| (a.addr, a.preferred)),
            |a| opentrust_net::addr::is_mesh_local(a, &mlp),
            &mut v,
        );
        v
    }

    /// Run `f` on the SRP client with its environment.
    fn with_srp<T>(
        &mut self,
        now: Instant,
        f: impl FnOnce(&mut SrpClient<SRP_SERVICES>, &mut SrpEnv<'_, R, C, SrpCtx<'_, S>>) -> T,
    ) -> T {
        let addrs = self.auto_addrs();
        let ml_eid = self.core.ml_eid_addr();
        let st = &mut self.dnssrp;
        let mut ctx = SrpCtx {
            out: &mut st.out,
            events: &mut st.srp_events,
            settings: &mut self.core.settings,
            addrs,
            ml_eid,
        };
        let mut env = SrpEnv {
            now,
            rng: &mut self.core.rng,
            crypto: &self.core.crypto,
            ctx: &mut ctx,
        };
        f(&mut st.srp, &mut env)
    }

    fn after_call<T>(&mut self, now: Instant, r: T) -> T {
        self.core.now = now;
        self.poll(now);
        r
    }

    // ------------------------------------------------------------ SRP API

    /// Set the host name to register (OT `otSrpClientSetHostName`).
    pub fn srp_set_host_name(&mut self, name: &str, now: Instant) -> Result<()> {
        let r = self.with_srp(now, |c, e| c.set_host_name(e, name));
        self.after_call(now, r)
    }

    /// Register the interface addresses automatically (OT
    /// `otSrpClientEnableAutoHostAddress`).
    pub fn srp_enable_auto_host_address(&mut self, now: Instant) -> Result<()> {
        let r = self.with_srp(now, |c, e| c.enable_auto_host_address(e));
        self.after_call(now, r)
    }

    /// Register an explicit list of host addresses (OT
    /// `otSrpClientSetHostAddresses`).
    pub fn srp_set_host_addresses(&mut self, addrs: &[Ipv6Addr], now: Instant) -> Result<()> {
        let r = self.with_srp(now, |c, e| c.set_host_addresses(e, addrs));
        self.after_call(now, r)
    }

    /// Add a service (OT `otSrpClientAddService`).
    pub fn srp_add_service(&mut self, cfg: ServiceConfig, now: Instant) -> Result<ServiceId> {
        let r = self.with_srp(now, |c, e| c.add_service(e, cfg));
        self.after_call(now, r)
    }

    /// Remove a service from the server (OT `otSrpClientRemoveService`).
    pub fn srp_remove_service(&mut self, id: ServiceId, now: Instant) -> Result<()> {
        let r = self.with_srp(now, |c, e| c.remove_service(e, id));
        self.after_call(now, r)
    }

    /// Remove the host and all services (OT
    /// `otSrpClientRemoveHostAndServices`).
    pub fn srp_remove_host_and_services(
        &mut self,
        remove_key_lease: bool,
        send_unreg_to_server: bool,
        now: Instant,
    ) -> Result<()> {
        let r = self.with_srp(now, |c, e| {
            c.remove_host_and_services(e, remove_key_lease, send_unreg_to_server)
        });
        self.after_call(now, r)
    }

    /// Start with an explicit server (OT `otSrpClientStart`).
    pub fn srp_start(&mut self, server: SocketAddrV6, now: Instant) -> Result<()> {
        let r = self.with_srp(now, |c, e| c.start(e, server));
        self.after_call(now, r)
    }

    /// Stop the client (OT `otSrpClientStop`).
    pub fn srp_stop(&mut self, now: Instant) {
        self.with_srp(now, |c, e| c.stop(e));
        self.after_call(now, ());
    }

    /// Select the server from the Network Data automatically (OT
    /// `otSrpClientEnableAutoStartMode`).
    pub fn srp_enable_auto_start(&mut self, now: Instant) {
        self.dnssrp.nd_hash = None;
        self.with_srp(now, |c, e| c.enable_auto_start(e));
        self.after_call(now, ());
    }

    /// Disable auto-start.
    pub fn srp_disable_auto_start(&mut self) {
        self.dnssrp.srp.disable_auto_start();
    }

    /// The cause of the last failed SRP update, once (the application can
    /// react to [`SrpError::NameConflict`] by choosing another host name).
    pub fn srp_take_failure(&mut self) -> Option<SrpError> {
        self.dnssrp.srp_failure.take()
    }

    /// The host name of the SRP client (empty until set).
    pub fn srp_host_name(&self) -> &str {
        self.dnssrp.srp.host_name()
    }

    /// State of the host registration.
    pub fn srp_host_state(&self) -> ItemState {
        self.dnssrp.srp.host_state()
    }

    /// State of a service registration.
    pub fn srp_service_state(&self, id: ServiceId) -> Option<ItemState> {
        self.dnssrp.srp.service_state(id)
    }

    /// The SRP server in use.
    pub fn srp_server(&self) -> Option<SocketAddrV6> {
        self.dnssrp.srp.server()
    }

    /// Is the SRP client started?
    pub fn srp_is_running(&self) -> bool {
        self.dnssrp.srp.is_running()
    }

    // ------------------------------------------------------------ DNS API

    /// The server for queries without a configuration (OT
    /// `otDnsClientSetDefaultConfig`); auto-start sets it to the SRP server.
    pub fn dns_set_default_server(&mut self, server: Option<SocketAddrV6>) {
        self.dnssrp.dns.set_default_server(server);
    }

    /// Browse for instances of `service`, e.g. `_matter._tcp.default.service.arpa`
    /// (OT `otDnsClientBrowse`). The result is [`Event::DnsResult`].
    pub fn dns_browse(
        &mut self,
        service: &str,
        config: Option<QueryConfig>,
        now: Instant,
    ) -> Result<QueryId> {
        let (st, core) = (&mut self.dnssrp, &mut self.core);
        let mut ctx = DnsCtx {
            out: &mut st.out,
            results: &mut st.results,
        };
        let r = st.dns.browse(now, &mut core.rng, &mut ctx, service, config);
        self.after_call(now, r)
    }

    /// Resolve the AAAA records of `host` (OT `otDnsClientResolveAddress`).
    pub fn dns_resolve_address(
        &mut self,
        host: &str,
        config: Option<QueryConfig>,
        now: Instant,
    ) -> Result<QueryId> {
        let (st, core) = (&mut self.dnssrp, &mut self.core);
        let mut ctx = DnsCtx {
            out: &mut st.out,
            results: &mut st.results,
        };
        let r = st
            .dns
            .resolve_address(now, &mut core.rng, &mut ctx, host, config);
        self.after_call(now, r)
    }

    /// Resolve a service instance (OT `otDnsClientResolveService`).
    pub fn dns_resolve_service(
        &mut self,
        instance: &str,
        service: &str,
        config: Option<QueryConfig>,
        now: Instant,
    ) -> Result<QueryId> {
        let (st, core) = (&mut self.dnssrp, &mut self.core);
        let mut ctx = DnsCtx {
            out: &mut st.out,
            results: &mut st.results,
        };
        let r = st
            .dns
            .resolve_service(now, &mut core.rng, &mut ctx, instance, service, config);
        self.after_call(now, r)
    }

    /// Cancel a DNS query.
    pub fn dns_cancel(&mut self, id: QueryId) {
        self.dnssrp.dns.cancel(id);
    }

    /// The oldest completed DNS query.
    pub fn dns_take_result(&mut self) -> Option<(QueryId, DnsOutcome)> {
        let r = self.dnssrp.results.pop_front();
        if r.is_some() {
            self.dnssrp.notified = self.dnssrp.notified.saturating_sub(1);
        }
        r
    }

    /// The result of query `id` if it has completed, leaving the results of
    /// other queries queued.
    pub fn dns_take_result_for(&mut self, id: QueryId) -> Option<DnsOutcome> {
        let n = self.dnssrp.results.len();
        let mut found = None;
        for i in 0..n {
            let Some((q, o)) = self.dnssrp.results.pop_front() else {
                break;
            };
            if found.is_none() && q == id && i < self.dnssrp.notified {
                found = Some(o);
            } else {
                let _ = self.dnssrp.results.push_back((q, o));
            }
        }
        if found.is_some() {
            self.dnssrp.notified = self.dnssrp.notified.saturating_sub(1);
        }
        found
    }

    // ------------------------------------------------------------ driving

    /// Feed the clients: attach state, Network Data, addresses, timers,
    /// outgoing datagrams, events. Returns `true` if something happened.
    #[inline(never)]
    pub(crate) fn service_dns_srp(&mut self, now: Instant) -> bool {
        let mut busy = false;
        let attached = self.mle.role().is_attached();
        if attached != self.dnssrp.attached {
            self.dnssrp.attached = attached;
            self.with_srp(now, |c, e| c.set_attached(e, attached));
            busy = true;
        }
        // Network Data (and the mesh-local prefix) for auto-start.
        let mlp = self.core.cfg.cur.mesh_local_prefix;
        let mut h = 0xcbf2_9ce4_8422_2325u64;
        fnv(&mut h, self.core.netdata.view().0);
        fnv(&mut h, &mlp.0);
        if self.dnssrp.nd_hash != Some(h) {
            self.dnssrp.nd_hash = Some(h);
            let data = self.core.netdata.clone();
            let view = data.view();
            let entries = view
                .services()
                .map(adapt as fn(ServiceEntry<'_>) -> NetDataService<'_>);
            self.with_srp(now, |c, e| c.handle_network_data(e, entries, mlp.0));
            busy = true;
        }
        // Interface addresses.
        let mut ah = 0xcbf2_9ce4_8422_2325u64;
        for a in self.auto_addrs() {
            fnv(&mut ah, &a.octets());
        }
        if self.dnssrp.addr_hash != Some(ah) {
            let first = self.dnssrp.addr_hash.is_none();
            self.dnssrp.addr_hash = Some(ah);
            if !first {
                self.with_srp(now, |c, e| c.on_addresses_changed(e));
                busy = true;
            }
        }
        // Timers.
        if self.dnssrp.srp.next_deadline().is_some_and(|d| d <= now) {
            self.with_srp(now, |c, e| c.poll(e));
            busy = true;
        }
        if self.dnssrp.dns.next_deadline().is_some_and(|d| d <= now) {
            let (st, core) = (&mut self.dnssrp, &mut self.core);
            let mut ctx = DnsCtx {
                out: &mut st.out,
                results: &mut st.results,
            };
            st.dns.poll(now, &mut core.rng, &mut ctx);
            busy = true;
        }
        // Events.
        while let Some(ev) = self.dnssrp.srp_events.pop_front() {
            busy = true;
            if let SrpEvent::ServerSelected(s) = ev {
                self.dnssrp.dns.set_default_server(s);
            }
            if let SrpEvent::Failed(e) = ev {
                self.dnssrp.srp_failure = Some(e);
            }
            self.core.push_event(Event::SrpClient(ev));
        }
        while self.dnssrp.notified < self.dnssrp.results.len() {
            let id = self
                .dnssrp
                .results
                .iter()
                .nth(self.dnssrp.notified)
                .map(|(i, _)| *i);
            self.dnssrp.notified += 1;
            if let Some(id) = id {
                self.core.push_event(Event::DnsResult(id));
            }
            busy = true;
        }
        // Outgoing datagrams.
        while let Some(d) = self.dnssrp.out.pop_front() {
            busy = true;
            let _ = self.send_dns_srp(now, &d);
        }
        busy
    }

    fn send_dns_srp(&mut self, now: Instant, d: &Dgram) -> Result<()> {
        let slot = match d.which {
            Which::Srp => self.dnssrp.srp_sock,
            Which::Dns => self.dnssrp.dns_sock,
        };
        let sock = match slot {
            Some(s) => s,
            None => {
                let s = self.udp.open()?;
                let any = SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0, 0, 0);
                if let Err(e) = self.udp.bind(s, any, &self.core.ip6.netif) {
                    let _ = self.udp.close(s);
                    return Err(e);
                }
                match d.which {
                    Which::Srp => self.dnssrp.srp_sock = Some(s),
                    Which::Dns => self.dnssrp.dns_sock = Some(s),
                }
                s
            }
        };
        let mut buf = [0u8; MAX_DATAGRAM_LEN];
        let (info, n) = self.udp.build_send(
            sock,
            Some(d.dst),
            &UdpSendOpts::default(),
            &d.buf[..d.len],
            &mut buf,
            &self.core.ip6.netif,
        )?;
        self.ip6_send(now, &info, PROTO_UDP, &buf[..n])
    }

    /// A datagram queued on socket `h`: consumed here if it belongs to the
    /// SRP or DNS client.
    pub(crate) fn dns_srp_rx(&mut self, now: Instant, h: SocketHandle) -> bool {
        let which = if self.dnssrp.srp_sock == Some(h) {
            Which::Srp
        } else if self.dnssrp.dns_sock == Some(h) {
            Which::Dns
        } else {
            return false;
        };
        let mut buf = [0u8; MAX_UDP_PAYLOAD];
        while let Ok(Some(info)) = self.udp.recv(h, &mut buf) {
            if info.truncated {
                continue;
            }
            let from = info.meta.peer;
            let payload = &buf[..info.len];
            match which {
                Which::Srp => {
                    self.with_srp(now, |c, e| c.handle_datagram(e, from, payload));
                }
                Which::Dns => {
                    let (st, _) = (&mut self.dnssrp, &mut self.core);
                    let mut ctx = DnsCtx {
                        out: &mut st.out,
                        results: &mut st.results,
                    };
                    st.dns.handle_datagram(from, payload, &mut ctx);
                }
            }
        }
        true
    }
}

#[cfg(test)]
mod ot_vector_tests {
    extern crate std;

    use std::vec::Vec as StdVec;

    use opentrust_dns::srp::discovery::{anycast_entries, preferred_anycast};
    use opentrust_mesh::netdata::NetworkDataView;

    use super::adapt;

    const COMM: [u8; 6] = [0x08, 0x04, 0x0b, 0x02, 0x50, 0xb0];

    /// Anycast Service TLV (`0x5c` service data) with one Server sub-TLV
    /// of RLOC16 `0x5000 + idx`, optionally with a version byte.
    fn svc(id: u8, seq: u8, idx: u8, version: Option<u8>) -> StdVec<u8> {
        let mut v = std::vec![0x0b, 0x08, 0x80 | id, 0x02, 0x5c, seq, 0x0d, 0x02, 0x50, idx];
        if let Some(ver) = version {
            v[1] = 0x09;
            v[7] = 0x03;
            v.push(ver);
        }
        v
    }

    fn cat(parts: &[StdVec<u8>]) -> StdVec<u8> {
        let mut d = COMM.to_vec();
        for p in parts {
            d.extend_from_slice(p);
        }
        d
    }

    /// OpenThread `tests/unit/test_network_data.cpp`
    /// `TestNetworkDataDsnSrpAnycastSeqNumSelection`.
    #[test]
    fn test_network_data_dsn_srp_anycast_seq_num_selection() {
        let plain = |seqs: &[u8]| -> StdVec<u8> {
            cat(&seqs
                .iter()
                .enumerate()
                .map(|(i, &s)| svc(i as u8, s, i as u8, None))
                .collect::<StdVec<_>>())
        };
        // (network data, sequence numbers in order, preferred seq, preferred version)
        let mut tests: StdVec<(StdVec<u8>, StdVec<u8>, u8, u8)> = StdVec::new();
        for (seqs, pref) in [
            (&[1u8, 129][..], 129u8),
            (&[133, 5], 133),
            (&[1, 2, 255], 2),
            (&[10, 130, 250], 250),
            (&[130, 250, 10], 250),
            (&[250, 10, 130], 250),
            (&[250, 10, 138], 250),
            (&[1, 2, 255, 254], 2),
            (&[1, 2, 255, 254], 2),
            (&[254, 2, 120, 1], 120),
            (&[240, 2, 120, 1], 240),
        ] {
            tests.push((plain(seqs), seqs.to_vec(), pref, 0));
        }
        // 12: second service carries a version byte.
        tests.push((
            cat(&[svc(0, 1, 0, None), svc(1, 129, 1, Some(1))]),
            std::vec![1, 129],
            129,
            1,
        ));
        // 13: one service with two Server sub-TLVs (version 2).
        let mut t13 = cat(&[svc(0, 1, 0, None)]);
        t13.extend_from_slice(&[0x0b, 0x0e, 0x81, 0x02, 0x5c, 0x81]);
        t13.extend_from_slice(&[0x0d, 0x03, 0x50, 0x01, 0x02, 0x0d, 0x03, 0x50, 0x02, 0x02]);
        tests.push((t13, std::vec![1, 129, 129], 129, 2));
        // 14 and 15: one service with three or four Server sub-TLVs.
        let mut t14 = COMM.to_vec();
        t14.extend_from_slice(&[0x0b, 0x13, 0x81, 0x02, 0x5c, 0x07]);
        t14.extend_from_slice(&[0x0d, 0x03, 0x50, 0x00, 0x01]);
        t14.extend_from_slice(&[0x0d, 0x03, 0x50, 0x01, 0x02]);
        t14.extend_from_slice(&[0x0d, 0x03, 0x50, 0x02, 0x03]);
        tests.push((t14, std::vec![7, 7, 7], 7, 1));
        let mut t15 = COMM.to_vec();
        t15.extend_from_slice(&[0x0b, 0x17, 0x81, 0x02, 0x5c, 0x03]);
        t15.extend_from_slice(&[0x0d, 0x03, 0x50, 0x00, 0x01]);
        t15.extend_from_slice(&[0x0d, 0x03, 0x50, 0x01, 0x02]);
        t15.extend_from_slice(&[0x0d, 0x02, 0x50, 0x02]);
        t15.extend_from_slice(&[0x0d, 0x03, 0x50, 0x03, 0x01]);
        tests.push((t15, std::vec![3, 3, 3, 3], 3, 0));

        for (n, (data, seqs, pref_seq, pref_ver)) in tests.iter().enumerate() {
            let entries: StdVec<_> = NetworkDataView(data).services().map(adapt).collect();
            let any: StdVec<_> = anycast_entries(entries.iter().copied(), [0; 8]).collect();
            assert_eq!(any.len(), seqs.len(), "case {}", n + 1);
            for (i, a) in any.iter().enumerate() {
                assert_eq!(a.sequence_number, seqs[i], "case {}", n + 1);
                assert_eq!(a.rloc16, 0x5000 + i as u16, "case {}", n + 1);
            }
            let p = preferred_anycast(&any).unwrap();
            assert_eq!(p.sequence_number, *pref_seq, "case {}", n + 1);
            assert_eq!(p.version, *pref_ver, "case {}", n + 1);
        }
    }

    /// OpenThread `tests/unit/test_network_data.cpp`
    /// `TestNetworkDataDsnSrpServices` (anycast and unicast entries).
    #[test]
    fn test_network_data_dsn_srp_services() {
        use core::net::{Ipv6Addr, SocketAddrV6};
        use opentrust_dns::srp::discovery::{UnicastType, unicast_entries};

        #[rustfmt::skip]
        let net_data: &[u8] = &[
            0x0b, 0x01, 0x00,
            0x0b, 0x0b, 0x80, 0x02, 0x5c, 0x02, 0x0d, 0x01, 0x00, 0x0d, 0x02, 0x28, 0x00,
            0x0b, 0x09, 0x81, 0x02, 0x5c, 0xff, 0x0d, 0x03, 0x6c, 0x00, 0x05,
            0x0b, 0x09, 0x82, 0x03, 0x5c, 0x03, 0xaa, 0x0d, 0x02, 0x4c, 0x00,
            0x0b, 0x36, 0x83, 0x14, 0x5d, 0xfd, 0xde, 0xad, 0x00, 0xbe, 0xef, 0x00, 0x00, 0x2d,
            0x0e, 0xc6, 0x27, 0x55, 0x56, 0x18, 0xd9, 0x12, 0x34, 0x03, 0x0d, 0x02, 0x00, 0x00,
            0x0d, 0x14, 0x6c, 0x00, 0xfd, 0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11,
            0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0xab, 0xcd, 0x0d, 0x04, 0x28, 0x00, 0x56, 0x78,
            0x0b, 0x24, 0x84, 0x01, 0x5d, 0x0d, 0x02, 0x00, 0x00, 0x0d, 0x15, 0x4c, 0x00, 0xfd,
            0x00, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x01, 0x23, 0x45, 0x67, 0x89,
            0xab, 0x00, 0x0e, 0x01, 0x0d, 0x04, 0x6c, 0x00, 0xcd, 0x12,
            0x0b, 0x08, 0x84, 0x01, 0x5c, 0x0d, 0x02, 0x14, 0x01, 0x0d,
            0x0b, 0x07, 0x83, 0x01, 0x5c, 0x0d, 0x02, 0x28, 0x00,
            0x0b, 0x13, 0x83, 0x02, 0x5c, 0xfe, 0x0d, 0x03, 0x12, 0x00, 0x07, 0x0d, 0x03, 0x12,
            0x01, 0x06, 0x0d, 0x03, 0x16, 0x00, 0x07,
        ];
        let mlp = [0xfd, 0xde, 0xad, 0x00, 0xbe, 0xef, 0x00, 0x00];
        let entries: StdVec<_> = NetworkDataView(net_data).services().map(adapt).collect();

        // (ALOC low 16 bits, sequence number, version, RLOC16)
        let anycast_expected = [
            (0xfc10u16, 0x02u8, 0u8, 0x2800u16),
            (0xfc11, 0xff, 5, 0x6c00),
            (0xfc12, 0x03, 0, 0x4c00),
            (0xfc13, 0xfe, 7, 0x1200),
            (0xfc13, 0xfe, 6, 0x1201),
            (0xfc13, 0xfe, 7, 0x1600),
        ];
        let any: StdVec<_> = anycast_entries(entries.iter().copied(), mlp).collect();
        assert_eq!(any.len(), anycast_expected.len());
        for (a, (aloc, seq, ver, rloc)) in any.iter().zip(anycast_expected) {
            let o = a.address.octets();
            assert_eq!(o[..8], mlp);
            assert_eq!(o[8..14], [0, 0, 0, 0xff, 0xfe, 0]);
            assert_eq!(u16::from_be_bytes([o[14], o[15]]), aloc);
            assert_eq!((a.sequence_number, a.version, a.rloc16), (seq, ver, rloc));
        }
        assert_eq!(preferred_anycast(&any).unwrap().sequence_number, 0x03);
        assert_eq!(preferred_anycast(&any).unwrap().address, any[2].address);

        let uni = |ty, exp: &[(&str, u16, u8, u16)]| {
            let got: StdVec<_> = unicast_entries(entries.iter().copied(), mlp, ty).collect();
            assert_eq!(got.len(), exp.len());
            for (g, (addr, port, ver, rloc)) in got.iter().zip(exp) {
                let a: Ipv6Addr = addr.parse().unwrap();
                assert_eq!(g.addr, SocketAddrV6::new(a, *port, 0, 0));
                assert_eq!((g.version, g.rloc16), (*ver, *rloc));
            }
        };
        uni(
            UnicastType::InServerData,
            &[
                ("fd00:aabb:ccdd:eeff:11:2233:4455:6677", 0xabcd, 0, 0x6c00),
                ("fdde:ad00:beef:0:0:ff:fe00:2800", 0x5678, 0, 0x2800),
                ("fd00:1234:5678:9abc:def0:123:4567:89ab", 0x0e, 1, 0x4c00),
                ("fdde:ad00:beef:0:0:ff:fe00:6c00", 0xcd12, 0, 0x6c00),
            ],
        );
        uni(
            UnicastType::InServiceData,
            &[
                ("fdde:ad00:beef:0:2d0e:c627:5556:18d9", 0x1234, 3, 0x0000),
                ("fdde:ad00:beef:0:2d0e:c627:5556:18d9", 0x1234, 3, 0x6c00),
                ("fdde:ad00:beef:0:2d0e:c627:5556:18d9", 0x1234, 3, 0x2800),
            ],
        );
    }
}
