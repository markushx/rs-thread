//! Border routing: OMR prefix selection and RA/RIO advertisement.
//!
//! # What this does
//!
//! 1. **OMR prefix selection** — picks a stable ULA /64 from the Thread
//!    network's prefix set (or generates a new one and publishes it via the
//!    Thread Network Data).
//!
//! 2. **RA/RIO transmission** — sends periodic ICMPv6 Router Advertisements on
//!    the backbone link that contain a Route Information Option (RIO) for the
//!    OMR prefix, so that backbone hosts can reach Thread devices.
//!
//! 3. **Backbone RA ingestion** — listens for RAs from other backbone routers
//!    and applies their prefixes to the Thread Network Data, allowing backbone
//!    devices to be reached from Thread.
//!
//! # Status
//!
//! Struct and trait surface defined; RA send/receive loop bodies are stubs.

use std::net::Ipv6Addr;
use std::time::Duration;

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
    /// Generates a fresh random ULA /64.
    pub fn random() -> Self {
        let rand_bytes: [u8; 5] = std::array::from_fn(|_| {
            // Primitive entropy from the system clock; replaced with a proper
            // CSPRNG in the full implementation.
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or(Duration::ZERO)
                .subsec_nanos() as u8
        });
        // ULA prefix: fd00::/8 with global ID in bytes 1–5.
        let mut addr = [0u8; 16];
        addr[0] = 0xfd;
        addr[1..6].copy_from_slice(&rand_bytes);
        // The subnet ID and interface ID are zeroed (we store only the /48
        // global ID; the /64 subnet is allocated by the caller).
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

    /// Selects (or generates) an OMR prefix and starts the RA/RIO advertisement
    /// loop on the backbone link.
    ///
    /// This function does not return unless the loop is cancelled.
    ///
    /// # Status
    ///
    /// RA send/receive loop is a placeholder.
    pub async fn run(&mut self) -> std::io::Result<()> {
        if self.omr_prefix.is_none() {
            self.omr_prefix = Some(OmrPrefix::random());
        }
        let prefix = self.omr_prefix.unwrap();
        log::info!(
            "RoutingManager: OMR prefix {}/{} on {}",
            prefix.prefix,
            prefix.prefix_len,
            self.backbone_ifname
        );
        // Pending: open an ICMPv6 raw socket on `self.backbone_ifname`, send
        // periodic RAs with an RIO for `prefix`, and ingest backbone RAs.
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(600)).await;
        }
    }
}
