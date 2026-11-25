//! Border routing: OMR prefix selection and RA/RIO advertisement.
//!
//! # What this does
//!
//! 1. **OMR prefix selection** — picks a stable ULA /64 (or generates a fresh
//!    one) and publishes it into the Thread Network Data.
//!
//! 2. **RA/RIO transmission** — sends periodic ICMPv6 Router Advertisements on
//!    the backbone link that contain a Route Information Option (RIO) for the
//!    OMR prefix, so that backbone hosts route Thread-bound traffic through this
//!    border router.
//!
//! 3. **Backbone RA ingestion** (not yet implemented) — listening for RAs from
//!    other backbone routers and pushing their prefixes into Thread Network Data.
//!
//! # Sending RAs
//!
//! Router Advertisements use a raw `AF_INET6 SOCK_RAW IPPROTO_ICMPV6` socket.
//! RFC 4861 §6.1.2 requires hop limit 255 for all NDP packets; this is enforced
//! via `set_multicast_hops_v6(255)`.  The ICMPv6 checksum is computed in
//! software over the pseudo-header (RFC 2460 §8.1) so no unsafe `setsockopt`
//! is needed.
//!
//! The initial sequence is three RAs at 2-second intervals (RFC 4861 §6.2.4
//! recommends at least `MIN_DELAY_BETWEEN_RAS` = 3 s, but we use 2 s for fast
//! convergence on boot).  After that, one RA every `RA_INTERVAL_SECS`.

use std::net::{Ipv6Addr, SocketAddr, SocketAddrV6};

use socket2::{Domain, Protocol, Socket, Type};
use tokio::io::unix::AsyncFd;
use tokio::time::{Duration, sleep};

/// Destination for Router Advertisements: all-nodes multicast (ff02::1).
const ALL_NODES: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1);

/// Hop limit used for all NDP packets (RFC 4861 §6.1.2).
const ND_HOP_LIMIT: u32 = 255;

/// Periodic RA interval (seconds) after the initial burst.
const RA_INTERVAL_SECS: u64 = 200;

/// Route lifetime carried in the RIO option (seconds).
const ROUTE_LIFETIME_SECS: u32 = 1800;

// RA header (16 bytes) + RIO option for a /64 (16 bytes).
const RA_LEN: usize = 32;

/// An Off-Mesh-Routable (OMR) prefix: a /64 published into the Thread Network
/// Data and advertised via RA/RIO on the backbone link.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OmrPrefix {
    /// The /64 ULA prefix address (the low 64 bits are always 0).
    pub prefix: Ipv6Addr,
    /// Prefix length (always 64 for an OMR prefix).
    pub prefix_len: u8,
}

impl OmrPrefix {
    /// Generates a fresh random ULA /64 using time + PID as entropy.
    ///
    /// Not cryptographically strong; ULA prefixes are not secret and the
    /// result only needs to be unique across border routers in the same
    /// network.
    pub fn random() -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_nanos() as u64;
        let pid = std::process::id() as u64;
        // splitmix64 to mix time and PID into a 40-bit global ID.
        let mut h = now ^ pid.wrapping_mul(0x9e3779b97f4a7c15);
        h ^= h >> 30;
        h = h.wrapping_mul(0xbf58476d1ce4e5b9);
        h ^= h >> 27;
        h = h.wrapping_mul(0x94d049bb133111eb);
        h ^= h >> 31;
        let mut addr = [0u8; 16];
        addr[0] = 0xfd; // ULA prefix
        addr[1..6].copy_from_slice(&h.to_le_bytes()[..5]);
        Self {
            prefix: Ipv6Addr::from(addr),
            prefix_len: 64,
        }
    }
}

/// Routing manager: owns the OMR prefix and drives the RA/RIO loop.
#[derive(Debug)]
pub struct RoutingManager {
    backbone_ifname: String,
    omr_prefix: Option<OmrPrefix>,
}

impl RoutingManager {
    /// Creates a new routing manager bound to `backbone_ifname` (e.g. `"eth0"`).
    pub fn new(backbone_ifname: impl Into<String>) -> Self {
        Self {
            backbone_ifname: backbone_ifname.into(),
            omr_prefix: None,
        }
    }

    /// The currently active OMR prefix, if one has been selected.
    pub fn omr_prefix(&self) -> Option<OmrPrefix> {
        self.omr_prefix
    }

    /// Sets the OMR prefix to advertise.  Calling this before [`run`](Self::run)
    /// prevents the manager from generating a random one.
    pub fn set_omr_prefix(&mut self, prefix: OmrPrefix) {
        self.omr_prefix = Some(prefix);
    }

    /// Selects (or generates) an OMR prefix and starts the RA/RIO advertisement
    /// loop on the backbone link.
    ///
    /// This function does not return unless cancelled by dropping the future.
    ///
    /// Requires `CAP_NET_RAW` on Linux (or running as root).
    pub async fn run(&mut self) -> std::io::Result<()> {
        if self.omr_prefix.is_none() {
            self.omr_prefix = Some(OmrPrefix::random());
        }
        let omr = self.omr_prefix.unwrap();

        let if_index = get_if_index(&self.backbone_ifname)?;
        let src = get_link_local_addr(&self.backbone_ifname)?;

        log::info!(
            "RoutingManager: OMR {}/{} on {} (src {})",
            omr.prefix,
            omr.prefix_len,
            self.backbone_ifname,
            src
        );

        // Raw ICMPv6 socket.
        let socket = Socket::new(Domain::IPV6, Type::RAW, Some(Protocol::ICMPV6))?;
        socket.set_nonblocking(true)?;
        // NDP packets must have hop limit 255 (RFC 4861 §6.1.2).
        socket.set_multicast_hops_v6(ND_HOP_LIMIT)?;
        // Multicast traffic leaves on the backbone interface.
        socket.set_multicast_if_v6(if_index)?;

        // AsyncFd::new is deprecated in favor of AsyncFd::register (unsafe),
        // but socket2::Socket is I/O-safe (it owns its fd).
        #[allow(deprecated)]
        let async_socket = AsyncFd::new(socket)?;
        let dst = SocketAddr::V6(SocketAddrV6::new(ALL_NODES, 0, 0, if_index));
        let dst_addr = socket2::SockAddr::from(dst);

        // Three initial RAs at 2-second intervals (fast convergence on boot).
        for i in 0..3u32 {
            let pkt = build_ra_rio(src, omr);
            send_ra(&async_socket, &pkt, &dst_addr).await?;
            if i < 2 {
                sleep(Duration::from_secs(2)).await;
            }
        }

        // Periodic unsolicited RAs.
        loop {
            sleep(Duration::from_secs(RA_INTERVAL_SECS)).await;
            let pkt = build_ra_rio(src, omr);
            send_ra(&async_socket, &pkt, &dst_addr).await?;
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Returns the interface index for `name`.
fn get_if_index(name: &str) -> std::io::Result<u32> {
    nix::net::if_::if_nametoindex(name).map_err(std::io::Error::from)
}

/// Returns the link-local IPv6 address assigned to `ifname`.
fn get_link_local_addr(ifname: &str) -> std::io::Result<Ipv6Addr> {
    for entry in nix::ifaddrs::getifaddrs().map_err(std::io::Error::from)? {
        if entry.interface_name != ifname {
            continue;
        }
        let Some(sa) = entry.address else { continue };
        let Some(sin6) = sa.as_sockaddr_in6() else {
            continue;
        };
        let ip = sin6.ip();
        let octs = ip.octets();
        // Link-local range: fe80::/10.
        if octs[0] == 0xfe && (octs[1] & 0xc0) == 0x80 {
            return Ok(ip);
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::NotFound,
        format!("no link-local IPv6 address on {ifname}"),
    ))
}

/// Builds a 32-byte ICMPv6 Router Advertisement with one Route Information
/// Option for `omr`, sourced from `src`, destined for ff02::1.
fn build_ra_rio(src: Ipv6Addr, omr: OmrPrefix) -> [u8; RA_LEN] {
    let mut pkt = [0u8; RA_LEN];

    // ICMPv6 Router Advertisement header (type 134, code 0).
    pkt[0] = 134; // type: RA
    // pkt[1] = 0  code
    // pkt[2..4] = checksum (computed below)
    // pkt[4] = 0  cur hop limit (unspecified = host default)
    // pkt[5] = 0  M=0 O=0
    // pkt[6..8] = 0  router lifetime = 0 (not a default router; we only carry a RIO)
    // pkt[8..12] = 0  reachable time
    // pkt[12..16] = 0  retrans timer

    // Route Information Option (RFC 4191 type 24), /64 → 16 bytes → length field = 2.
    pkt[16] = 24; // type
    pkt[17] = 2; // length in 8-byte units (2 × 8 = 16 bytes)
    pkt[18] = omr.prefix_len; // prefix length (64)
    // pkt[19] = 0  prf = medium (bits 4:3 = 0), reserved = 0
    pkt[20..24].copy_from_slice(&ROUTE_LIFETIME_SECS.to_be_bytes());
    // For a /64, only the first 8 bytes of the prefix are significant.
    pkt[24..32].copy_from_slice(&omr.prefix.octets()[..8]);

    icmpv6_checksum_write(src, ALL_NODES, &mut pkt);
    pkt
}

/// Computes the ICMPv6 checksum over the pseudo-header and writes it at
/// bytes 2–3 of `msg` (the checksum field must be zeroed before calling).
fn icmpv6_checksum_write(src: Ipv6Addr, dst: Ipv6Addr, msg: &mut [u8]) {
    // Zero the checksum field first.
    msg[2] = 0;
    msg[3] = 0;

    let len = msg.len() as u32;
    let mut acc: u32 = 0;

    let mut add = |bytes: &[u8]| {
        let mut iter = bytes.chunks_exact(2);
        for chunk in iter.by_ref() {
            acc = acc.wrapping_add(u16::from_be_bytes([chunk[0], chunk[1]]) as u32);
        }
        if let [b] = iter.remainder() {
            acc = acc.wrapping_add((*b as u32) << 8);
        }
    };

    // IPv6 pseudo-header: src, dst, upper-layer length, zeros, next header 58.
    add(&src.octets());
    add(&dst.octets());
    add(&len.to_be_bytes());
    add(&[0u8, 0, 0, 58]); // 3 reserved zeros + ICMPv6 next-header = 58

    add(msg);

    // Fold carry bits.
    while acc >> 16 != 0 {
        acc = (acc & 0xffff) + (acc >> 16);
    }
    let cksum = !(acc as u16);
    msg[2..4].copy_from_slice(&cksum.to_be_bytes());
}

/// Sends `pkt` to `dst` on `socket`, waiting for writability via tokio.
async fn send_ra(
    socket: &AsyncFd<Socket>,
    pkt: &[u8],
    dst: &socket2::SockAddr,
) -> std::io::Result<()> {
    loop {
        let mut guard = socket.writable().await?;
        match guard.try_io(|inner| inner.get_ref().send_to(pkt, dst).map(|_| ())) {
            Ok(result) => return result,
            Err(_would_block) => continue,
        }
    }
}
