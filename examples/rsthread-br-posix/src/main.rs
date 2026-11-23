//! Thread Border Router reference binary (ot-br-posix port).
//!
//! Connects to a Thread RCP over UART or TCP, opens a TUN interface for Thread
//! IPv6 traffic, and runs the Border Router services:
//!
//! - RadioSpinel host driver (Spinel over UART/TCP)
//! - TUN interface for IPv6 packet injection
//! - OMR prefix selection and RA/RIO advertisement (RoutingManager)
//! - SRP advertising proxy (SrpProxy → backbone mDNS)
//! - DNS proxy (Thread → upstream resolver)
//!
//! # Usage
//!
//! ```text
//! rsthread-br-posix --radio-url spinel+hdlc+uart:///dev/ttyUSB0 \
//!                   --backbone-interface eth0 \
//!                   --tun-interface thread0
//! ```

use clap::Parser;
use rs_thread_br::{dns_proxy::DnsProxy, routing::RoutingManager, srp_proxy::SrpProxy, tun::TunInterface};

/// Thread Border Router daemon.
#[derive(Parser, Debug)]
#[command(version, about)]
struct Args {
    /// Radio URL (e.g. `spinel+hdlc+uart:///dev/ttyUSB0` or
    /// `spinel+hdlc+tcp://localhost:9999`).
    #[arg(long, default_value = "spinel+hdlc+tcp://localhost:9999")]
    radio_url: String,

    /// Backbone network interface (e.g. `eth0`, `wlan0`).
    #[arg(long, default_value = "eth0")]
    backbone_interface: String,

    /// TUN interface name for Thread IPv6 packets.
    #[arg(long, default_value = "thread0")]
    tun_interface: String,

    /// UDP listen address for the DNS proxy.
    #[arg(long, default_value = "[::1]:5300")]
    dns_listen: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    let args = Args::parse();

    log::info!("rsthread-br-posix starting");
    log::info!("  radio-url:          {}", args.radio_url);
    log::info!("  backbone-interface: {}", args.backbone_interface);
    log::info!("  tun-interface:      {}", args.tun_interface);
    log::info!("  dns-listen:         {}", args.dns_listen);

    // Pending: parse radio_url and connect a RadioSpinel.
    // For now just show that the crate structure links correctly.

    let _tun = TunInterface::open(&args.tun_interface).await;
    let mut routing = RoutingManager::new(&args.backbone_interface);
    let mut srp = SrpProxy::new();
    let dns_addr: std::net::SocketAddr = args.dns_listen.parse()?;
    let mut dns = DnsProxy::new(dns_addr);

    srp.start().await?;

    tokio::select! {
        r = routing.run() => {
            log::error!("RoutingManager exited: {r:?}");
        }
        r = dns.run() => {
            log::error!("DnsProxy exited: {r:?}");
        }
    }

    Ok(())
}
