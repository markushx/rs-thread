//! `rs_matter::stack::mdns::Mdns` over the SRP client and the DNS-SD client
//! of the node (the Thread equivalent of `rs-matter-embassy`'s `OtMdns`).
//!
//! On Thread there is no link-local mDNS: a node registers its services with
//! the SRP server of a border router (RFC 9665), which advertises them on the
//! infrastructure link as mDNS, and discovers peers with unicast DNS-SD
//! queries to that server (`default.service.arpa`). [`SrpMdns::run`]
//!
//! - registers the host (name from the MAC / extended address, like the
//!   builtin responder, addresses chosen by the SRP client as OpenThread does: the
//!   preferred non-mesh-local, non-link-local addresses (SLAAC addresses of
//!   on-mesh prefixes), the ML-EID only when there are none) and keeps the SRP services in sync with
//!   [`Matter::mdns_services`] (`_matterc._udp` with its `_L`, `_S`, `_V`,
//!   `_T`, `_CM` subtypes while a commissioning window is open, one
//!   `_matter._tcp` with the `_I` subtype per fabric), re-synced whenever
//!   rs-matter signals a change (`Transport::wait_mdns`);
//! - answers rs-matter's operational / commissionable resolve requests with
//!   `dns_resolve_service` and its browse requests with `dns_browse` (plus a
//!   per-instance resolve when the server returns no additional records).
//!
//! The SRP server is taken from the Network Data (auto-start); the DNS
//! client's default server follows it. `net_stack`, `ipv4` and `interface`
//! are unused; `ipv6` only ranks resolved peer addresses.

use core::fmt::Write as _;
use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use embassy_sync::blocking_mutex::raw::RawMutex;
use heapless::{String, Vec};
use opentrust_dns::rdata::{TxtEntry, TxtIter};
use opentrust_embassy::{DnsClientError, OpenTrust, ResolvedService, ServiceId};
use opentrust_instance::{InstanceCrypto, SRP_SERVICES, ServiceConfig, SrpError};
use opentrust_platform::{Clock, SettingsStore};
use rand_core::{CryptoRng, Rng};
use rs_matter::Matter;
use rs_matter::crypto::Crypto;
use rs_matter::error::{Error, ErrorCode};
use rs_matter::stack::mdns::Mdns;
use rs_matter::stack::net::NetStack;
use rs_matter::transport::network::mdns::{DottedName, MdnsBrowseQuery, MdnsRemoteService};
use rs_matter::transport::network::{MatterLocalService, MatterRemoteService};
use rs_matter::utils::futures::{Coalesce, select, select3};
use rs_matter::utils::timers::{Duration, Timer};

use crate::error::map_err;
use crate::fmt::{log_debug, log_warn};

/// Services registered at once (the SRP client slots of the `Instance`, see
/// [`SRP_SERVICES`]): the commissionable service plus one operational service
/// per fabric. Matter requires at least five fabrics.
pub const MAX_SERVICES: usize = SRP_SERVICES;

/// The DNS-SD domain of SRP registrations (Thread 1.3 `default.service.arpa`).
pub const DOMAIN: &str = "default.service.arpa";

/// Longest service type with subtype, e.g. `_L1234._sub._matterc._udp`.
const MAX_SERVICE_TYPE: usize = 64;
/// Longest DNS-SD name used for a query (instance + service + domain).
const MAX_NAME: usize = 128;
/// Delay before a failed resolve / browse is retried while rs-matter still
/// waits for it.
const RETRY_MS: u64 = 1000;
/// Longest wait between attempts to register a service the SRP client still
/// holds (doubling from [`RETRY_MS`]): the client may hold it for long, for
/// instance while updates to the server go unanswered.
const PENDING_RETRY_MAX_MS: u64 = 32_000;
/// How often the SRP client is checked for a failed update once the host is
/// registered.
const FAILURE_POLL_MS: u64 = 5000;
/// The same while the host is not registered yet: a name conflict (the
/// server still holds the name for an earlier key, for example after a
/// factory reset) is answered within a round trip, so each name variant
/// costs about this long.
const REGISTERING_POLL_MS: u64 = 500;
/// TXT key / value pairs of one service.
const MAX_TXT: usize = 16;

/// The Thread mDNS of a node: SRP registration and DNS-SD resolution.
pub struct SrpMdns<'a, M, K, S, C, R>
where
    M: RawMutex,
    C: InstanceCrypto,
{
    ot: OpenTrust<'a, M, K, S, C, R>,
    registered: Vec<(MatterLocalService, ServiceId), MAX_SERVICES>,
    /// Host name suffix: 0 for the plain name, `-N` after N name conflicts.
    host_variant: u8,
}

impl<M: RawMutex, K, S, C: InstanceCrypto, R> core::fmt::Debug for SrpMdns<'_, M, K, S, C, R> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SrpMdns")
            .field("registered", &self.registered.len())
            .finish_non_exhaustive()
    }
}

impl<'a, M, K, S, C, R> SrpMdns<'a, M, K, S, C, R>
where
    M: RawMutex,
    K: Clock,
    S: SettingsStore,
    C: InstanceCrypto,
    R: Rng + CryptoRng,
{
    /// The mDNS of the node behind `ot`.
    pub const fn new(ot: OpenTrust<'a, M, K, S, C, R>) -> Self {
        Self {
            ot,
            registered: Vec::new(),
            host_variant: 0,
        }
    }

    /// The SRP service ids currently registered for Matter services.
    pub fn registered(&self) -> impl Iterator<Item = (&MatterLocalService, ServiceId)> {
        self.registered.iter().map(|(s, id)| (s, *id))
    }

    /// The host name: `mac` as hex (like the builtin responder), with a
    /// `-N` suffix after N name conflicts.
    fn host_name(&self, mac: &[u8]) -> Result<String<24>, Error> {
        let mut host: String<24> = String::new();
        for b in mac.iter().take(8) {
            write!(host, "{b:02X}").map_err(|_| Error::new(ErrorCode::BufferTooSmall))?;
        }
        if host.is_empty() {
            return Err(ErrorCode::InvalidArgument.into());
        }
        if self.host_variant != 0 {
            write!(host, "-{}", self.host_variant)
                .map_err(|_| Error::new(ErrorCode::BufferTooSmall))?;
        }
        Ok(host)
    }

    /// Register the host: addresses chosen by the SRP client, server from
    /// the Network Data.
    fn start_host(&self, mac: &[u8]) -> Result<(), Error> {
        let host = self.host_name(mac)?;
        self.ot
            .with(|i, now| {
                // A restarted future finds the host name set already (it can
                // only be changed before registration or after removal).
                if i.srp_host_name() != host.as_str() {
                    i.srp_set_host_name(&host, now)?;
                }
                i.srp_enable_auto_host_address(now)?;
                i.srp_enable_auto_start(now);
                Ok(())
            })
            .map_err(map_err)
    }

    /// React to a failed SRP update: a name conflict (the server holds the
    /// host name for another key, e.g. from before a factory reset, for the
    /// key lease of days) moves the host to the next name.
    fn handle_failure(&mut self, mac: &[u8]) {
        let failure = self.ot.with(|i, _| i.srp_take_failure());
        if failure != Some(SrpError::NameConflict) {
            return;
        }
        self.host_variant = self.host_variant.wrapping_add(1);
        let Ok(host) = self.host_name(mac) else {
            return;
        };
        log_warn!("SRP: host name conflict, trying {}", host.as_str());
        if let Err(e) = self.ot.with(|i, now| i.srp_set_host_name(&host, now)) {
            log_warn!("SRP: cannot change the host name: {:?}", e);
        }
    }

    /// Bring the SRP services in line with the services rs-matter advertises.
    ///
    /// Returns whether a wanted service could not be registered yet (the SRP
    /// client still holds the removal of an earlier registration of the same
    /// name, for instance after the network interface restarted this
    /// future); the caller retries shortly.
    fn sync_services(&mut self, matter: &Matter<'_>) -> Result<bool, Error> {
        let mut pending = false;
        let mut wanted: Vec<MatterLocalService, { MAX_SERVICES + 4 }> = Vec::new();
        matter.mdns_services(|s| {
            if wanted.push(s).is_err() {
                log_warn!("more Matter services than SRP slots");
            }
            Ok(())
        })?;
        // Remove what is gone (also when the service could not be added).
        let mut i = 0;
        while i < self.registered.len() {
            if wanted.contains(&self.registered[i].0) {
                i += 1;
            } else {
                let (_, id) = self.registered.swap_remove(i);
                let _ = self.ot.with(|inst, now| inst.srp_remove_service(id, now));
            }
        }
        for svc in &wanted {
            if self.registered.iter().any(|(s, _)| s == svc) {
                continue;
            }
            let id = match self.add_service(matter, svc) {
                Ok(id) => id,
                Err(e) => {
                    log_warn!("SRP: cannot register {:?}: {:?}", svc, e);
                    pending = true;
                    continue;
                }
            };
            if let Err((_, id)) = self.registered.push((svc.clone(), id)) {
                let _ = self.ot.with(|inst, now| inst.srp_remove_service(id, now));
                log_warn!("SRP: no slot for {:?}", svc);
            }
        }
        Ok(pending)
    }

    fn add_service(
        &self,
        matter: &Matter<'_>,
        svc: &MatterLocalService,
    ) -> Result<ServiceId, Error> {
        let mut buf = [0u8; 512];
        let (local, _) = svc.service(matter, &mut buf)?;
        let mut cfg =
            ServiceConfig::new(local.service_protocol, local.name, local.port).map_err(map_err)?;
        for sub in local.service_subtypes.clone() {
            cfg.add_sub_type(sub).map_err(map_err)?;
        }
        let entries: Vec<TxtEntry<'_>, MAX_TXT> = local
            .txt_kvs
            .clone()
            .map(|(k, v)| TxtEntry {
                key: k.as_bytes(),
                value: Some(v.as_bytes()),
            })
            .take(MAX_TXT)
            .collect();
        cfg.set_txt_entries(&entries).map_err(map_err)?;
        self.ot
            .with(|i, now| i.srp_add_service(cfg, now))
            .map_err(map_err)
    }

    /// Remove the Matter services from SRP (host and key stay).
    fn remove_all(&mut self) {
        for (_, id) in self.registered.drain(..) {
            let _ = self.ot.with(|inst, now| inst.srp_remove_service(id, now));
        }
    }
}

/// Removes the registered services when the `run` future ends or is
/// dropped (rs-matter races it with the rest of the stack).
struct RemoveOnDrop<'s, 'a, M, K, S, C, R>(&'s mut SrpMdns<'a, M, K, S, C, R>)
where
    M: RawMutex,
    K: Clock,
    S: SettingsStore,
    C: InstanceCrypto,
    R: Rng + CryptoRng;

impl<M, K, S, C, R> Drop for RemoveOnDrop<'_, '_, M, K, S, C, R>
where
    M: RawMutex,
    K: Clock,
    S: SettingsStore,
    C: InstanceCrypto,
    R: Rng + CryptoRng,
{
    fn drop(&mut self) {
        self.0.remove_all();
    }
}

/// The DNS-SD service type of a query: `<subtype>._sub.<type>` or `<type>`.
fn browse_service_type(query: &MdnsBrowseQuery, out: &mut String<MAX_SERVICE_TYPE>) {
    let mut t: String<64> = String::new();
    query.service_type(&mut t, false);
    out.clear();
    let _ = out.push_str(&t);
}

/// `<instance>.<service>.<domain>` (the full DNS-SD name of a resolved
/// service) and the `.local` instance name rs-matter matches against.
fn remote_names(
    svc: &MatterRemoteService,
    instance: &mut String<MAX_NAME>,
    local: &mut String<MAX_NAME>,
) {
    instance.clear();
    local.clear();
    match svc {
        MatterRemoteService::Operational {
            compressed_fabric_id,
            node_id,
        } => {
            let _ = write!(instance, "{compressed_fabric_id:016X}-{node_id:016X}");
        }
        MatterRemoteService::Commissionable { id } => {
            let _ = write!(instance, "{id:016X}");
        }
    }
    let _ = write!(local, "{}.{}.local", instance, svc.service_type());
}

/// Deposit a resolved service as an mDNS answer.
fn deposit<F>(resolved: &ResolvedService, local_name: &str, local_ipv6: &[Ipv6Addr], f: F)
where
    F: FnOnce(
        &MdnsRemoteService<
            DottedName<'_>,
            core::iter::Copied<core::slice::Iter<'_, IpAddr>>,
            core::iter::Copied<core::slice::Iter<'_, (&str, &str)>>,
        >,
    ),
{
    let txt: Vec<(&str, &str), MAX_TXT> = TxtIter::new(&resolved.txt)
        .filter_map(|e| e.ok())
        .filter_map(|e| {
            Some((
                core::str::from_utf8(e.key).ok()?,
                core::str::from_utf8(e.value.unwrap_or(&[])).ok()?,
            ))
        })
        .take(MAX_TXT)
        .collect();
    let addrs: Vec<IpAddr, 8> = resolved
        .addrs
        .iter()
        .map(|a| IpAddr::V6(a.addr))
        .take(8)
        .collect();
    let _ = local_ipv6;
    f(&MdnsRemoteService {
        instance_name: DottedName(local_name),
        port: Some(resolved.port),
        addrs: addrs.iter().copied(),
        txt: txt.iter().copied(),
        scope_id: 0,
    });
}

impl<M, K, S, C, R> Mdns for SrpMdns<'_, M, K, S, C, R>
where
    M: RawMutex,
    K: Clock,
    S: SettingsStore,
    C: InstanceCrypto,
    R: Rng + CryptoRng,
{
    async fn run<Y, N>(
        &mut self,
        matter: &Matter<'_>,
        _crypto: &Y,
        _net_stack: &N,
        mac: &[u8],
        _ipv4: Ipv4Addr,
        ipv6: &[Ipv6Addr],
        _interface: u32,
    ) -> Result<(), Error>
    where
        Y: Crypto,
        N: NetStack,
    {
        self.start_host(mac)?;
        let ot = self.ot;
        let responder = matter.transport().mdns_responder();
        let guard = RemoveOnDrop(self);

        let advertise = async {
            let mut pending_wait = RETRY_MS;
            loop {
                guard.0.handle_failure(mac);
                let pending = guard.0.sync_services(matter)?;
                // Poll for SRP failures as well, without a wake-up of their own.
                let registered =
                    ot.with(|i, _| i.srp_host_state() == opentrust_instance::ItemState::Registered);
                let wait = if pending {
                    let w = pending_wait;
                    pending_wait = (pending_wait * 2).min(PENDING_RETRY_MAX_MS);
                    w
                } else if registered {
                    FAILURE_POLL_MS
                } else {
                    REGISTERING_POLL_MS
                };
                if !pending {
                    pending_wait = RETRY_MS;
                }
                select(
                    matter.transport().wait_mdns(),
                    Timer::after(Duration::from_millis(wait)),
                )
                .await;
            }
        };

        let resolve = async {
            let mut instance: String<MAX_NAME> = String::new();
            let mut local: String<MAX_NAME> = String::new();
            let mut service: String<MAX_SERVICE_TYPE> = String::new();
            loop {
                let svc = responder.wait_resolve_request().await;
                remote_names(&svc, &mut instance, &mut local);
                service.clear();
                let _ = write!(service, "{}.{}", svc.service_type(), DOMAIN);
                while matter.transport().mdns_resolve_in_flight() {
                    match ot.dns_resolve_service(&instance, &service, None).await {
                        Ok(r) => {
                            deposit(&r, &local, ipv6, |answer| {
                                matter.transport().try_deposit_mdns_resolve(answer, ipv6);
                            });
                            break;
                        }
                        Err(e) => {
                            log_debug!("DNS-SD resolve of {} failed: {:?}", instance, e);
                            Timer::after(Duration::from_millis(RETRY_MS)).await;
                        }
                    }
                }
            }
        };

        let browse = async {
            let mut service: String<MAX_SERVICE_TYPE> = String::new();
            let mut name: String<MAX_NAME> = String::new();
            let mut local: String<MAX_NAME> = String::new();
            loop {
                let query = responder.wait_browse_request().await;
                browse_service_type(&query, &mut service);
                name.clear();
                let _ = write!(name, "{}.{}", service, DOMAIN);
                while matter.transport().mdns_browse_in_flight() {
                    let r = ot.dns_browse(&name, None).await;
                    let instances = match r {
                        Ok(i) => i,
                        Err(DnsClientError::Failed(e)) => {
                            log_debug!("DNS-SD browse of {} failed: {:?}", name, e);
                            Timer::after(Duration::from_millis(RETRY_MS)).await;
                            continue;
                        }
                        Err(e) => {
                            log_debug!("DNS-SD browse of {} failed: {:?}", name, e);
                            Timer::after(Duration::from_millis(RETRY_MS)).await;
                            continue;
                        }
                    };
                    for inst in &instances {
                        local.clear();
                        let _ = write!(local, "{}.{}.local", inst.label, query.base_service_type());
                        let resolved = match &inst.info {
                            Some(info) => Some(info.clone()),
                            None => {
                                let mut base: String<MAX_SERVICE_TYPE> = String::new();
                                let _ = write!(base, "{}.{}", query.base_service_type(), DOMAIN);
                                ot.dns_resolve_service(&inst.label, &base, None).await.ok()
                            }
                        };
                        if let Some(r) = resolved {
                            deposit(&r, &local, ipv6, |answer| {
                                matter.transport().try_deposit_mdns_browse(answer);
                            });
                        }
                    }
                    // One pass answers the window; rs-matter ends the browse
                    // when its window closes.
                    break;
                }
            }
        };

        select3(advertise, resolve, browse).coalesce().await
    }
}
