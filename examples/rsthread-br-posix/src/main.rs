//! rsthread-br-posix: Thread Border Router daemon.
//!
//! Opens a Spinel RCP connection (UART or TCP socket), runs the rs-thread
//! stack over it, and bridges Thread IPv6 traffic to the host network via a
//! TUN interface.  SRP registrations are advertised on the backbone via mDNS
//! and DNS queries are forwarded to the upstream resolver.

use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;
use embassy_sync::blocking_mutex::raw::NoopRawMutex;
use rs_thread_br::{
    dns_proxy::DnsProxy,
    routing::RoutingManager,
    srp_proxy::SrpProxy,
    tun::TunInterface,
};
use rs_thread_core::{crypto::soft::SoftCrypto, time::Instant};
use rs_thread_embassy::{Resources, RsThread};
use rs_thread_instance::{Config, Instance, RANDOM_EXT_ADDRESS};
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

    fn try_fill_bytes(
        &mut self,
        dst: &mut [u8],
    ) -> Result<(), core::convert::Infallible> {
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
        Self { start_sys: std::time::Instant::now() }
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
        // `at` is µs since the same epoch used by TokioClock.
        let elapsed_at = Duration::from_micros(at.as_micros());
        // Convert to wall-clock instant.
        let wall = std::time::Instant::now()
            .checked_sub(self.start_sys.elapsed())
            .unwrap_or(std::time::Instant::now())
            + elapsed_at;
        // Determine if `at` is already in the past.
        let now_sys = std::time::Instant::now();
        if wall <= now_sys {
            return;
        }
        let tokio_deadline =
            self.start_tokio + Duration::from_micros(at.as_micros());
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

// ── Main ──────────────────────────────────────────────────────────────────────

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let args = Args::parse();
    log::info!("rsthread-br-posix starting");
    log::info!("  radio URL : {}", args.radio_url);
    log::info!("  backbone  : {}", args.backbone);
    log::info!("  tun       : {}", args.tun);

    // 1. Open the Spinel transport and initialise the radio.
    //    The radio must be initialised before the Instance is created so the
    //    reported capabilities can be passed to Config.
    let transport = open_transport(&args.radio_url).await?;
    let mut radio = RadioSpinel::new(transport);
    let caps = radio.init().await.map_err(|e| anyhow::anyhow!("radio init: {e}"))?;
    log::info!("radio initialised: {caps:?}");

    // 2. Create the rs-thread Instance with the radio's capabilities.
    let config = Config::router(RANDOM_EXT_ADDRESS, caps);
    let instance = Instance::new(config, RamSettings::<8192>::new(), SoftCrypto, OsRng);

    // 3. Wrap in embassy Resources and create the RsThread handle.
    //    Resources is heap-allocated and leaked so its lifetime is 'static,
    //    allowing the Copy handle to be freely passed to spawn_local tasks.
    let clock = TokioClock::new();
    let resources: &'static _ =
        Box::leak(Box::new(Resources::<NoopRawMutex, _, _, _, _>::new(instance, clock)));
    let rsthread: RsThread<'static, NoopRawMutex, _, _, _, _> = RsThread::new(resources);

    // 4. Open the TUN interface.
    let mut tun = TunInterface::open(&args.tun)
        .await
        .context("open TUN interface")?;
    log::info!("TUN interface opened: {}", tun.name());

    // 5. Create border router components (stubs, logging only until 16c-16e).
    let _routing = RoutingManager::new(&args.backbone);
    let _srp_proxy = SrpProxy::new();
    let _dns_proxy = DnsProxy::new("[::1]:53".parse().unwrap());

    // Channel: Thread→TUN datagrams (up to 8 pending).
    let (to_tun_tx, mut to_tun_rx) = mpsc::channel::<Vec<u8>>(8);

    // 6. Run everything concurrently until Ctrl-C.
    let local = tokio::task::LocalSet::new();
    local.run_until(async move {
        // Thread protocol driver — never returns.
        tokio::task::spawn_local(async move {
            rsthread.run(radio, TokioAlarm::new()).await
        });

        // TUN ← Thread: drain Ip6Datagram events and send through the channel.
        //
        // `wait_changed` wakes on every state change; we drain the host-ip6
        // queue on each wake and push packets into `to_tun_tx`.
        let tx = to_tun_tx;
        tokio::task::spawn_local(async move {
            let mut buf = vec![0u8; rs_thread_br::tun::MAX_PACKET];
            loop {
                rsthread.wait_changed().await;
                loop {
                    let n = rsthread.with(|inst, _| inst.take_ip6_datagram(&mut buf));
                    let Some(n) = n else { break };
                    if tx.send(buf[..n].to_vec()).await.is_err() {
                        return; // TUN task exited
                    }
                }
            }
        });

        // TUN I/O: host ↔ Thread datagram bridge.
        //
        // Reads from the TUN device are forwarded to the Thread stack via
        // `handle_ip6_from_host`.  Writes received from the event task above
        // are injected into the host routing stack.
        tokio::task::spawn_local(async move {
            let mut read_buf = vec![0u8; rs_thread_br::tun::MAX_PACKET];
            loop {
                tokio::select! {
                    // TUN → Thread
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
                    // Thread → TUN
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
    })
    .await;

    Ok(())
}
