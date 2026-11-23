//! DNS proxy: forwards Thread unicast DNS queries to an upstream resolver.
//!
//! Thread devices send DNS queries to the border router's Thread address
//! (the DNS-SD anycast ALOC or the border router's ML-EID on port 53).
//! This module:
//!
//! 1. Binds a UDP socket on `listen_addr`.
//! 2. Receives raw DNS query packets.
//! 3. Parses the question with `hickory_proto`.
//! 4. Resolves A / AAAA / PTR questions via `hickory_resolver`
//!    (which reads `/etc/resolv.conf` by default; override with
//!    [`DnsProxy::with_upstream`]).
//! 5. Builds and returns a DNS response.
//!
//! # Limitations
//!
//! - Only A, AAAA and PTR record types are forwarded; other types receive
//!   NOTIMP.
//! - DNS-over-TCP is not supported.
//! - Thread's service discovery path (DNS-SD browse / resolve through the
//!   SRP server) is handled by the SRP server built into the rs-thread
//!   instance, not by this proxy.

use std::net::{IpAddr, Ipv6Addr, SocketAddr};

use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::rdata;
use hickory_proto::rr::{RData, Record, RecordType};
use hickory_resolver::config::{NameServerConfig, ResolverConfig};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::{Resolver, TokioResolver};
use tokio::net::UdpSocket;

/// Maximum DNS message size over UDP (RFC 1035 §4.2.1).
const MAX_DNS_UDP: usize = 512;

/// DNS proxy server.  Listens on a Thread-reachable UDP address and forwards
/// A / AAAA / PTR queries upstream via `hickory_resolver`.
#[derive(Debug)]
pub struct DnsProxy {
    listen_addr: SocketAddr,
    upstream: Option<IpAddr>,
}

impl DnsProxy {
    /// Creates a DNS proxy that will listen on `listen_addr`.
    pub fn new(listen_addr: SocketAddr) -> Self {
        Self {
            listen_addr,
            upstream: None,
        }
    }

    /// Overrides the upstream resolver address (default: system `/etc/resolv.conf`).
    pub fn with_upstream(mut self, ip: IpAddr) -> Self {
        self.upstream = Some(ip);
        self
    }

    /// Binds the UDP socket and starts the forwarding loop.
    ///
    /// This function does not return unless cancelled by dropping the future.
    pub async fn run(&mut self) -> std::io::Result<()> {
        let socket = UdpSocket::bind(self.listen_addr).await?;
        log::info!("DnsProxy: listening on {}", self.listen_addr);

        let resolver = build_resolver(self.upstream)
            .map_err(|e| std::io::Error::other(format!("DNS resolver init: {e}")))?;

        let mut buf = [0u8; MAX_DNS_UDP];
        loop {
            let (n, peer) = match socket.recv_from(&mut buf).await {
                Ok(r) => r,
                Err(e) => {
                    log::warn!("DnsProxy: recv_from: {e}");
                    continue;
                }
            };

            let query_bytes = &buf[..n];
            let response_bytes = match handle_query(&resolver, query_bytes).await {
                Ok(b) => b,
                Err(e) => {
                    log::debug!("DnsProxy: handle_query from {peer}: {e}");
                    continue;
                }
            };

            if let Err(e) = socket.send_to(&response_bytes, peer).await {
                log::warn!("DnsProxy: send_to {peer}: {e}");
            }
        }
    }

    /// One-shot AAAA lookup (without binding a listen socket).
    pub async fn lookup_aaaa(&self, name: &str) -> std::io::Result<Vec<Ipv6Addr>> {
        let resolver = build_resolver(self.upstream)
            .map_err(|e| std::io::Error::other(format!("DNS resolver init: {e}")))?;
        let result = resolver
            .lookup_ip(name)
            .await
            .map_err(|e| std::io::Error::other(format!("AAAA lookup for {name}: {e}")))?;
        Ok(result
            .iter()
            .filter_map(|ip| match ip {
                IpAddr::V6(v6) => Some(v6),
                _ => None,
            })
            .collect())
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

fn build_resolver(upstream: Option<IpAddr>) -> std::io::Result<TokioResolver> {
    let ip = upstream.unwrap_or_else(read_system_nameserver);
    let ns = NameServerConfig::udp(ip);
    let config = ResolverConfig::from_name_servers(vec![ns]);
    Resolver::builder_with_config(config, TokioRuntimeProvider::default())
        .build()
        .map_err(|e| std::io::Error::other(format!("resolver build: {e}")))
}

/// Reads the first nameserver IP from `/etc/resolv.conf`; falls back to 1.1.1.1.
fn read_system_nameserver() -> IpAddr {
    if let Ok(content) = std::fs::read_to_string("/etc/resolv.conf") {
        for line in content.lines() {
            let line = line.trim();
            if let Some(rest) = line.strip_prefix("nameserver") {
                if let Ok(ip) = rest.trim().parse::<IpAddr>() {
                    return ip;
                }
            }
        }
    }
    // Cloudflare public DNS as fallback.
    "1.1.1.1".parse().unwrap()
}

async fn handle_query(resolver: &TokioResolver, raw: &[u8]) -> std::io::Result<Vec<u8>> {
    let query = Message::from_vec(raw)
        .map_err(|e| std::io::Error::other(format!("DNS parse: {e}")))?;

    let id = query.metadata.id;
    let rd = query.metadata.recursion_desired;
    let mut response = Message::new(id, MessageType::Response, OpCode::Query);
    response.metadata.recursion_desired = rd;
    response.metadata.recursion_available = true;

    for q in &query.queries {
        response.queries.push(q.clone());

        let name = q.name().to_string();
        match q.query_type() {
            RecordType::A => {
                match resolver.lookup_ip(name.as_str()).await {
                    Ok(ips) => {
                        for ip in ips.iter() {
                            if let IpAddr::V4(v4) = ip {
                                response.add_answer(Record::from_rdata(
                                    q.name().clone(),
                                    300,
                                    RData::A(rdata::A(v4)),
                                ));
                            }
                        }
                    }
                    Err(e) => log::debug!("DnsProxy: A lookup {name}: {e}"),
                }
            }
            RecordType::AAAA => {
                match resolver.lookup_ip(name.as_str()).await {
                    Ok(ips) => {
                        for ip in ips.iter() {
                            if let IpAddr::V6(v6) = ip {
                                response.add_answer(Record::from_rdata(
                                    q.name().clone(),
                                    300,
                                    RData::AAAA(rdata::AAAA(v6)),
                                ));
                            }
                        }
                    }
                    Err(e) => log::debug!("DnsProxy: AAAA lookup {name}: {e}"),
                }
            }
            RecordType::PTR => {
                match resolver.reverse_lookup(name.as_str()).await {
                    Ok(result) => {
                        for rec in result.answers() {
                            if let RData::PTR(ptr) = &rec.data {
                                response.add_answer(Record::from_rdata(
                                    q.name().clone(),
                                    300,
                                    RData::PTR(ptr.clone()),
                                ));
                            }
                        }
                    }
                    Err(e) => log::debug!("DnsProxy: PTR lookup {name}: {e}"),
                }
            }
            other => {
                log::debug!("DnsProxy: unsupported query type {other:?} for {name}");
                response.metadata.response_code = ResponseCode::NotImp;
                return response
                    .to_vec()
                    .map_err(|e| std::io::Error::other(format!("DNS serialize: {e}")));
            }
        }
    }

    if response.answers.is_empty() && response.metadata.response_code == ResponseCode::NoError {
        response.metadata.response_code = ResponseCode::NXDomain;
    }

    response
        .to_vec()
        .map_err(|e| std::io::Error::other(format!("DNS serialize: {e}")))
}
