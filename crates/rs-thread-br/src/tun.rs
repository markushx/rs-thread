//! TUN (layer-3) interface for Thread IPv6 traffic.
//!
//! Opens a `IFF_TUN | IFF_NO_PI` device on Linux, or a `utun` device on
//! macOS, and provides async read/write for injecting IPv6 packets between
//! the Thread network and the host routing stack.
//!
//! # Status
//!
//! The API surface is complete; the platform-specific `open()` bodies need
//! the `libc` / `nix` helpers wired up.

use std::net::Ipv6Addr;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Maximum IPv6 packet size.
pub const MAX_PACKET: usize = 1500;

/// An opened TUN interface.  Created by [`TunInterface::open`].
#[derive(Debug)]
pub struct TunInterface {
    file: tokio::fs::File,
    name: String,
}

impl TunInterface {
    /// Opens (or creates) a TUN interface with `name` (e.g. `"thread0"`).
    ///
    /// On Linux this requires `CAP_NET_ADMIN`.
    ///
    /// # Platform support
    ///
    /// Linux `IFF_TUN | IFF_NO_PI` and macOS `utun` are planned; other
    /// platforms return an error.
    pub async fn open(_name: &str) -> std::io::Result<Self> {
        // Pending: platform-specific open via libc ioctl (Linux) or
        // AF_SYS_CONTROL/utun (macOS).
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "TunInterface::open not yet implemented on this platform",
        ))
    }

    /// The kernel-assigned interface name (e.g. `"thread0"`, `"utun3"`).
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Reads one IPv6 packet from the TUN device into `buf`.
    pub async fn read_packet(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.file.read(buf).await
    }

    /// Writes one IPv6 packet to the TUN device (injects it into the host
    /// routing stack).
    pub async fn write_packet(&mut self, packet: &[u8]) -> std::io::Result<()> {
        self.file.write_all(packet).await
    }

    /// Assigns the IPv6 address `addr/prefix_len` to the interface and brings
    /// it up via `ip(8)`.
    pub async fn set_addr(&self, addr: Ipv6Addr, prefix_len: u8) -> std::io::Result<()> {
        let status = tokio::process::Command::new("ip")
            .args([
                "addr",
                "add",
                &format!("{addr}/{prefix_len}"),
                "dev",
                &self.name,
            ])
            .status()
            .await?;
        if !status.success() {
            return Err(std::io::Error::other("ip addr add failed"));
        }
        let status = tokio::process::Command::new("ip")
            .args(["link", "set", &self.name, "up"])
            .status()
            .await?;
        if !status.success() {
            return Err(std::io::Error::other("ip link set up failed"));
        }
        Ok(())
    }

    /// Windows (wintun): open/create a TUN adapter via the wintun library.
    ///
    /// # Status
    ///
    /// Not yet implemented — requires the `wintun` crate and a wintun.dll.
    #[cfg(target_os = "windows")]
    pub async fn open_wintun(_name: &str, _description: &str) -> std::io::Result<Self> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "wintun backend not yet implemented",
        ))
    }
}
