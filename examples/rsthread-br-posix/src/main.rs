//! rsthread-br-posix: Thread Border Router daemon.
//!
//! Opens a Spinel RCP connection (UART or TCP socket), runs the rs-thread
//! stack over it, and bridges Thread IPv6 traffic to the host network via a
//! TUN interface.  SRP registrations are advertised on the backbone via mDNS
//! and DNS queries are forwarded to the upstream resolver.

use std::cell::RefCell;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::rc::Rc;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;
use embassy_sync::blocking_mutex::raw::NoopRawMutex;
use rs_thread_br::{
    dns_proxy::DnsProxy, routing::{OmrPrefix, RoutingManager}, srp_proxy::{SrpProxy, SrpService},
    tun::TunInterface,
};
use rs_thread_core::{crypto::soft::SoftCrypto, time::Instant, types::NetworkKey};
use rs_thread_embassy::{Resources, RsThread};
use rs_thread_instance::{
    srp_server_types as sst, Config, Dataset, ExternalRouteConfig, Instance, NetPrefix,
    RANDOM_EXT_ADDRESS,
};
use rs_thread_ncp::{
    radio_spinel::RadioSpinel,
    rcp::Transport as RcpTransport,
    transport::{SocketTransport, UartTransport},
};
use rs_thread_platform::{Alarm, Clock, Radio, RamSettings};
use tokio::sync::mpsc;

// ── CLI ──────────────────────────────────────────────────────────────────────

/// Thread Border Router daemon — Rust port of ot-br-posix.
#[derive(Debug, Parser)]
struct Args {
    /// Radio URL: `spinel+uart:///dev/tty.usbmodem*` or
    /// `spinel+socket://127.0.0.1:9000`
    #[arg(long, short = 'r', value_name = "URL")]
    radio_url: String,

    /// Backbone interface name (e.g. `en0`, `eth0`)
    #[arg(long, short = 'b', value_name = "IFACE", default_value = "en0")]
    backbone: String,

    /// TUN interface name hint
    #[arg(long, default_value = "thread0")]
    tun: String,

    /// UDP address the DNS proxy listens on (use port 53 with CAP_NET_BIND_SERVICE / root)
    #[arg(long, default_value = "[::1]:5300")]
    dns_addr: String,

    /// Form a new Thread network immediately (leader mode).  Generates a
    /// random Network Key.  Use `--channel` to pick the channel.
    #[arg(long)]
    become_leader: bool,

    /// 802.15.4 channel to use with `--become-leader` (default: 15)
    #[arg(long, default_value_t = 15u8)]
    channel: u8,
}

// ── OS entropy RNG ───────────────────────────────────────────────────────────

struct OsRng;

impl rand_core::TryRng for OsRng {
    type Error = core::convert::Infallible;

    fn try_next_u32(&mut self) -> Result<u32, core::convert::Infallible> {
        let mut buf = [0u8; 4];
        getrandom::fill(&mut buf).expect("getrandom failed");
        Ok(u32::from_le_bytes(buf))
    }

    fn try_next_u64(&mut self) -> Result<u64, core::convert::Infallible> {
        let mut buf = [0u8; 8];
        getrandom::fill(&mut buf).expect("getrandom failed");
        Ok(u64::from_le_bytes(buf))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), core::convert::Infallible> {
        getrandom::fill(dst).expect("getrandom failed");
        Ok(())
    }
}

impl rand_core::TryCryptoRng for OsRng {}

// ── Tokio clock + alarm ──────────────────────────────────────────────────────

#[derive(Clone, Copy)]
struct TokioClock {
    start_sys: std::time::Instant,
}

impl TokioClock {
    fn new() -> Self {
        Self {
            start_sys: std::time::Instant::now(),
        }
    }
}

impl Clock for TokioClock {
    fn now(&self) -> Instant {
        Instant::from_micros(self.start_sys.elapsed().as_micros() as u64)
    }
}

struct TokioAlarm {
    start_sys: std::time::Instant,
    start_tokio: tokio::time::Instant,
}

impl TokioAlarm {
    fn new() -> Self {
        Self {
            start_sys: std::time::Instant::now(),
            start_tokio: tokio::time::Instant::now(),
        }
    }
}

impl Alarm for TokioAlarm {
    async fn wait_until(&mut self, at: Instant) {
        let elapsed_at = Duration::from_micros(at.as_micros());
        let wall = std::time::Instant::now()
            .checked_sub(self.start_sys.elapsed())
            .unwrap_or(std::time::Instant::now())
            + elapsed_at;
        let now_sys = std::time::Instant::now();
        if wall <= now_sys {
            return;
        }
        let tokio_deadline = self.start_tokio + Duration::from_micros(at.as_micros());
        tokio::time::sleep_until(tokio_deadline).await;
    }
}

// ── Transport enum ───────────────────────────────────────────────────────────

#[allow(clippy::large_enum_variant)]
enum RadioTransport {
    Uart(UartTransport),
    Socket(SocketTransport),
}

impl RcpTransport for RadioTransport {
    type Error = std::io::Error;

    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        match self {
            RadioTransport::Uart(t) => t.read(buf).await,
            RadioTransport::Socket(t) => t.read(buf).await,
        }
    }

    async fn write_all(&mut self, data: &[u8]) -> Result<(), Self::Error> {
        match self {
            RadioTransport::Uart(t) => t.write_all(data).await,
            RadioTransport::Socket(t) => t.write_all(data).await,
        }
    }
}

impl core::fmt::Debug for RadioTransport {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            RadioTransport::Uart(_) => write!(f, "RadioTransport::Uart(...)"),
            RadioTransport::Socket(_) => write!(f, "RadioTransport::Socket(...)"),
        }
    }
}

async fn open_transport(url: &str) -> Result<RadioTransport> {
    if let Some(path) = url.strip_prefix("spinel+uart://") {
        let file = tokio::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .await
            .with_context(|| format!("open {path}"))?;
        Ok(RadioTransport::Uart(UartTransport::new(file)))
    } else if let Some(addr) = url.strip_prefix("spinel+socket://") {
        let stream = SocketTransport::connect(addr)
            .await
            .with_context(|| format!("connect {addr}"))?;
        Ok(RadioTransport::Socket(stream))
    } else {
        anyhow::bail!(
            "unknown radio URL scheme: {url}\nExpected spinel+uart:// or spinel+socket://"
        )
    }
}

// ── SRP bridge helpers ────────────────────────────────────────────────────────

/// Strips the SRP server domain from `service_name` and appends `.local.`
/// to produce an mDNS-compatible service type string.
///
/// Example: `_matter._tcp.default.service.arpa.` + domain `default.service.arpa`
///   → `_matter._tcp.local.`
fn build_service_type(service_name: &sst::WireName, domain: &sst::WireName) -> String {
    let domain_len = domain.labels().count();
    let svc_labels: Vec<&[u8]> = service_name.labels().collect();
    let type_len = svc_labels.len().saturating_sub(domain_len);
    let mut s = String::new();
    for (i, label) in svc_labels[..type_len].iter().enumerate() {
        if i > 0 {
            s.push('.');
        }
        s.push_str(&String::from_utf8_lossy(label));
    }
    s.push_str(".local.");
    s
}

/// Parses DNS-wire-format TXT record data into `(key, value)` pairs.
fn parse_srp_txt(raw: &[u8]) -> Vec<(String, Vec<u8>)> {
    let mut result = Vec::new();
    let mut i = 0;
    while i < raw.len() {
        let len = raw[i] as usize;
        i += 1;
        if i + len > raw.len() {
            break;
        }
        let entry = &raw[i..i + len];
        i += len;
        let eq = entry.iter().position(|&b| b == b'=').unwrap_or(entry.len());
        let key = String::from_utf8_lossy(&entry[..eq]).into_owned();
        let val = if eq < entry.len() {
            entry[eq + 1..].to_vec()
        } else {
            Vec::new()
        };
        if !key.is_empty() {
            result.push((key, val));
        }
    }
    result
}

// ── Main ──────────────────────────────────────────────────────────────────────

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let args = Args::parse();
    log::info!("rsthread-br-posix starting");
    log::info!("  radio URL : {}", args.radio_url);
    log::info!("  backbone  : {}", args.backbone);
    log::info!("  tun       : {}", args.tun);
    log::info!("  dns addr  : {}", args.dns_addr);

    // 1. Open the Spinel transport and initialise the radio.
    let transport = open_transport(&args.radio_url).await?;
    let mut radio = RadioSpinel::new(transport);
    let caps = radio
        .init()
        .await
        .map_err(|e| anyhow::anyhow!("radio init: {e}"))?;
    log::info!("radio initialised: {caps:?}");

    // 2. Create the rs-thread Instance.
    let config = Config::router(RANDOM_EXT_ADDRESS, caps);
    let instance = Instance::new(config, RamSettings::<8192>::new(), SoftCrypto, OsRng);

    // 3. Wrap in embassy Resources and create the RsThread handle.
    let clock = TokioClock::new();
    let resources: &'static _ = Box::leak(Box::new(Resources::<NoopRawMutex, _, _, _, _>::new(
        instance, clock,
    )));
    let rsthread: RsThread<'static, NoopRawMutex, _, _, _, _> = RsThread::new(resources);

    // 4. Optionally form a new Thread network immediately.
    if args.become_leader {
        let mut key_bytes = [0u8; 16];
        getrandom::fill(&mut key_bytes).expect("getrandom failed");
        let network_key = NetworkKey(key_bytes);

        let mut ds = Dataset::default();
        ds.set_channel(args.channel)
            .context("invalid channel")?;
        ds.set_pan_id(0xface).context("set pan_id")?;
        ds.set_network_key(&network_key)
            .context("set network_key")?;
        rsthread
            .set_active_dataset(&ds)
            .map_err(|e| anyhow::anyhow!("set_active_dataset: {e:?}"))?;
        rsthread
            .become_leader()
            .map_err(|e| anyhow::anyhow!("become_leader: {e:?}"))?;
        log::info!(
            "Thread network formed (channel {}, PAN 0xface)",
            args.channel
        );
    } else {
        // Try to restore Thread from saved settings; non-fatal if no dataset.
        rsthread
            .thread_start()
            .map_err(|e| log::warn!("thread_start: {e:?} — configure a dataset via REST API"))
            .ok();
    }

    // 5. Enable the SRP server and publish the OMR prefix to Network Data.
    let omr = OmrPrefix::random();
    rsthread.with(|inst, now| {
        inst.srp_server_set_enabled(true, now);
        if let Ok(prefix) = NetPrefix::from_addr(&omr.prefix, omr.prefix_len) {
            let cfg = ExternalRouteConfig {
                prefix,
                preference: 0,
                nat64: false,
                adv_pio: false,
                stable: true,
            };
            if let Err(e) = inst.publish_external_route(cfg, now) {
                log::warn!("publish_external_route: {e:?}");
            }
        }
    });

    // 6. Open the TUN interface.
    let mut tun = TunInterface::open(&args.tun)
        .await
        .context("open TUN interface")?;
    log::info!("TUN interface opened: {}", tun.name());

    // Add OMR prefix route on the TUN so packets destined for Thread addresses
    // enter the tunnel.
    tun.add_route(omr.prefix, omr.prefix_len)
        .await
        .context("add OMR route to TUN")?;
    log::info!("OMR route {}/{} added to {}", omr.prefix, omr.prefix_len, tun.name());

    // 7. Create and start the SRP advertising proxy.
    let mut srp_proxy = SrpProxy::new();
    const BORDER_AGENT_PORT: u16 = 49191;
    srp_proxy
        .start(BORDER_AGENT_PORT)
        .context("SRP proxy start")?;
    log::info!("SRP proxy started (border agent port {BORDER_AGENT_PORT})");
    let srp = Rc::new(RefCell::new(srp_proxy));

    // 8. Create routing manager and DNS proxy.
    let mut routing = RoutingManager::new(&args.backbone);
    routing.set_omr_prefix(omr);

    let dns_addr: SocketAddr = args
        .dns_addr
        .parse()
        .context("parse --dns-addr")?;
    let dns_proxy = DnsProxy::new(dns_addr);

    // Channel: Thread→TUN datagrams.
    let (to_tun_tx, mut to_tun_rx) = mpsc::channel::<Vec<u8>>(8);

    // 9. Run everything concurrently until Ctrl-C / SIGTERM.
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async move {
            // Thread protocol driver — never returns.
            tokio::task::spawn_local(async move { rsthread.run(radio, TokioAlarm::new()).await });

            // Routing manager: sends periodic RA/RIO on the backbone.
            tokio::task::spawn_local(async move {
                if let Err(e) = routing.run().await {
                    log::error!("RoutingManager: {e}");
                }
            });

            // DNS proxy: forwards Thread unicast DNS queries upstream.
            tokio::task::spawn_local(async move {
                let mut proxy = dns_proxy;
                if let Err(e) = proxy.run().await {
                    log::error!("DnsProxy: {e}");
                }
            });

            // TUN ← Thread: drain Ip6Datagram events into the channel.
            let tx = to_tun_tx;
            tokio::task::spawn_local(async move {
                let mut buf = vec![0u8; rs_thread_br::tun::MAX_PACKET];
                loop {
                    rsthread.wait_changed().await;
                    loop {
                        let n = rsthread.with(|inst, _| inst.take_ip6_datagram(&mut buf));
                        let Some(n) = n else { break };
                        if tx.send(buf[..n].to_vec()).await.is_err() {
                            return;
                        }
                    }
                }
            });

            // SRP bridge: watches Instance SRP server for host/service changes
            // and mirrors them to the mDNS daemon on the backbone.
            let srp2 = Rc::clone(&srp);
            tokio::task::spawn_local(async move {
                // (host_id, instance_label) → update_time
                let mut known_svcs: HashMap<(u16, String), Instant> = HashMap::new();
                // host_id → host_name as "foo.local."
                let mut known_hosts: HashMap<u16, String> = HashMap::new();

                loop {
                    rsthread.wait_changed().await;

                    // Snapshot the SRP server store synchronously.
                    let (active_ids, services) = rsthread.with(|inst, _| {
                        let store = inst.srp_server_store();
                        let active: Vec<u16> = store
                            .hosts()
                            .filter(|h| !h.is_deleted())
                            .map(|h| h.id)
                            .collect();
                        let svcs: Vec<(sst::Host, sst::Service, sst::WireName)> = store
                            .all_services()
                            .filter(|(h, s)| !h.is_deleted() && !s.deleted)
                            .map(|(h, s)| (h.clone(), s.clone(), store.domain().clone()))
                            .collect();
                        (active, svcs)
                    });

                    // Hosts that have disappeared → unregister from mDNS.
                    let to_unregister: Vec<String> = known_hosts
                        .iter()
                        .filter(|(id, _)| !active_ids.contains(id))
                        .map(|(_, name)| name.clone())
                        .collect();
                    known_hosts.retain(|id, _| active_ids.contains(id));
                    known_svcs.retain(|(host_id, _), _| active_ids.contains(host_id));

                    // New or updated services → register on mDNS.
                    let mut to_register = Vec::new();
                    for (host, svc, domain) in &services {
                        let inst_label =
                            String::from_utf8_lossy(svc.instance_label()).into_owned();
                        let key = (host.id, inst_label.clone());

                        if known_svcs.get(&key) == Some(&svc.update_time) {
                            continue;
                        }

                        let host_name = format!(
                            "{}.local.",
                            String::from_utf8_lossy(host.label())
                        );
                        let service_type = build_service_type(&svc.service_name, domain);
                        let txt = parse_srp_txt(svc.txt.as_slice());
                        let host_addrs = host.addresses.iter().copied().collect::<Vec<_>>();

                        to_register.push(SrpService {
                            instance_name: inst_label.clone(),
                            service_type,
                            port: svc.port,
                            txt,
                            host_name: host_name.clone(),
                            host_addrs,
                        });

                        known_svcs.insert(key, svc.update_time);
                        known_hosts.insert(host.id, host_name);
                    }

                    // Apply changes to the SRP proxy (sync, no await needed).
                    let mut proxy = srp2.borrow_mut();
                    for host_name in &to_unregister {
                        if let Err(e) = proxy.unregister_host(host_name) {
                            log::warn!("SrpProxy: unregister {host_name}: {e}");
                        }
                    }
                    for svc in to_register {
                        if let Err(e) = proxy.register(svc) {
                            log::warn!("SrpProxy: register failed: {e}");
                        }
                    }
                }
            });

            // TUN I/O: host ↔ Thread datagram bridge.
            tokio::task::spawn_local(async move {
                let mut read_buf = vec![0u8; rs_thread_br::tun::MAX_PACKET];
                loop {
                    tokio::select! {
                        result = tun.read_packet(&mut read_buf) => {
                            match result {
                                Ok(0) => {}
                                Ok(n) => {
                                    rsthread.with(|inst, now| {
                                        inst.handle_ip6_from_host(now, &read_buf[..n]);
                                    });
                                }
                                Err(e) => {
                                    log::warn!("TUN read: {e}");
                                    tokio::time::sleep(Duration::from_millis(100)).await;
                                }
                            }
                        }
                        Some(pkt) = to_tun_rx.recv() => {
                            if let Err(e) = tun.write_packet(&pkt).await {
                                log::warn!("TUN write: {e}");
                            }
                        }
                    }
                }
            });

            tokio::signal::ctrl_c().await.expect("ctrl-c failed");
            log::info!("shutting down");
            rsthread.thread_stop();
        })
        .await;

    Ok(())
}
