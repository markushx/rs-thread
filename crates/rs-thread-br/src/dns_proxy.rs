//! DNS proxy: forwards Thread unicast DNS queries upstream.
//!
//! Thread devices send DNS queries to the border router's Thread address.
//! This module forwards those queries to an upstream DNS resolver (typically
//! the host's system resolver or a DoT/DoH upstream) using
//! `hickory-resolver` and returns the results to the Thread querier.
//!
//! # Status
//!
//! Struct and query API defined; UDP listener and resolver wiring are stubs.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

/// The result of a proxied DNS lookup.
#[derive(Debug, Clone)]
pub enum DnsAnswer {
    /// One or more IPv4 addresses (A record).
    A(Vec<Ipv4Addr>),
    /// One or more IPv6 addresses (AAAA record).
    Aaaa(Vec<Ipv6Addr>),
    /// A service endpoint (SRV + A/AAAA).
    Srv {
        target: String,
        port: u16,
        addrs: Vec<Ipv6Addr>,
    },
    /// Text records (TXT).
    Txt(Vec<Vec<u8>>),
}

/// DNS proxy server.  Listens on a Thread-reachable UDP address and forwards
/// queries upstream via hickory-resolver.
#[derive(Debug)]
pub struct DnsProxy {
    /// Address the proxy listens on (Thread address of the border router).
    listen_addr: SocketAddr,
    // Pending: hickory_resolver::TokioAsyncResolver handle
}

impl DnsProxy {
    /// Creates a DNS proxy that will listen on `listen_addr`.
    pub fn new(listen_addr: SocketAddr) -> Self {
        Self { listen_addr }
    }

    /// Binds the UDP socket and starts the forwarding loop.
    ///
    /// This function does not return unless the loop is cancelled.
    ///
    /// # Status
    ///
    /// UDP bind and resolver loop are pending.
    pub async fn run(&mut self) -> std::io::Result<()> {
        log::info!("DnsProxy: listening on {} (stub)", self.listen_addr);
        // Pending:
        // 1. Bind a tokio::net::UdpSocket on self.listen_addr.
        // 2. Build a hickory_resolver::TokioAsyncResolver from system config.
        // 3. Loop: recv_from, spawn task: forward to resolver, send reply.
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(600)).await;
        }
    }

    /// Performs a one-shot DNS lookup for `name` of type `A`/`AAAA`, using the
    /// upstream resolver, without binding a listen socket.
    ///
    /// # Status
    ///
    /// Pending: replace stub with hickory_resolver call.
    pub async fn lookup_aaaa(&self, _name: &str) -> std::io::Result<Vec<Ipv6Addr>> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "DnsProxy::lookup_aaaa not yet implemented",
        ))
    }
}
