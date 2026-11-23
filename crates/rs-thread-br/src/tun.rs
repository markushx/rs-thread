//! Async TUN interface for Thread IPv6 traffic.
//!
//! Wraps a [`tun2::AsyncDevice`] and provides packet-level read/write.
//! Uses `tun2` which handles platform differences (Linux `/dev/net/tun`,
//! macOS `utun`, Windows `wintun`) internally.
//!
//! # Privileges
//!
//! Creating a TUN device requires `CAP_NET_ADMIN` on Linux and administrator
//! rights on macOS and Windows.

use std::net::Ipv6Addr;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tun2::{AbstractDevice, AsyncDevice};

/// Maximum IPv6 packet size on a Thread TUN interface.
pub const MAX_PACKET: usize = 1500;

/// An opened TUN interface.
pub struct TunInterface {
    device: AsyncDevice,
    name: String,
}

impl core::fmt::Debug for TunInterface {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TunInterface").field("name", &self.name).finish()
    }
}

impl TunInterface {
    /// Opens (or creates) a TUN interface.
    ///
    /// `name` is a hint; the kernel may assign a different name (e.g.
    /// `utun3` on macOS).  Use [`name`](Self::name) to find the actual name.
    ///
    /// Requires `CAP_NET_ADMIN` on Linux, admin rights on macOS/Windows.
    pub async fn open(name: &str) -> std::io::Result<Self> {
        let mut config = tun2::Configuration::default();
        config.name(name);
        config.up();
        let device = tun2::create_as_async(&config)
            .map_err(|e| std::io::Error::other(e.to_string()))?;
        let actual_name = device
            .tun_name()
            .map_err(|e| std::io::Error::other(e.to_string()))?;
        Ok(Self { device, name: actual_name })
    }

    /// The kernel-assigned interface name (e.g. `"thread0"`, `"utun3"`).
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Reads one IPv6 packet from the TUN device into `buf`.
    ///
    /// Returns the number of bytes written into `buf`.
    pub async fn read_packet(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.device.read(buf).await
    }

    /// Writes one IPv6 packet to the TUN device (injects it into the host
    /// routing stack).
    pub async fn write_packet(&mut self, packet: &[u8]) -> std::io::Result<()> {
        self.device.write_all(packet).await
    }

    /// Assigns the IPv6 address `addr/prefix_len` to the interface and brings
    /// it up.
    ///
    /// Uses `ip(8)` on Linux and `ifconfig(8)` on macOS.
    pub async fn set_ipv6_addr(&self, addr: Ipv6Addr, prefix_len: u8) -> std::io::Result<()> {
        #[cfg(target_os = "linux")]
        {
            let status = tokio::process::Command::new("ip")
                .args([
                    "addr", "add",
                    &format!("{addr}/{prefix_len}"),
                    "dev", &self.name,
                ])
                .status()
                .await?;
            if !status.success() {
                return Err(std::io::Error::other(format!(
                    "ip addr add {addr}/{prefix_len} dev {} failed",
                    self.name
                )));
            }
            let status = tokio::process::Command::new("ip")
                .args(["link", "set", &self.name, "up"])
                .status()
                .await?;
            if !status.success() {
                return Err(std::io::Error::other(format!(
                    "ip link set {} up failed",
                    self.name
                )));
            }
        }
        #[cfg(target_os = "macos")]
        {
            let status = tokio::process::Command::new("ifconfig")
                .args([
                    &self.name, "inet6",
                    &format!("{addr}/{prefix_len}"),
                    "alias",
                ])
                .status()
                .await?;
            if !status.success() {
                return Err(std::io::Error::other(format!(
                    "ifconfig {} inet6 {addr}/{prefix_len} alias failed",
                    self.name
                )));
            }
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            let _ = (addr, prefix_len);
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "set_ipv6_addr not supported on this platform",
            ));
        }
        Ok(())
    }

    /// Adds an IPv6 route for `prefix/prefix_len` via this interface.
    pub async fn add_route(&self, prefix: Ipv6Addr, prefix_len: u8) -> std::io::Result<()> {
        #[cfg(target_os = "linux")]
        {
            let status = tokio::process::Command::new("ip")
                .args([
                    "-6", "route", "add",
                    &format!("{prefix}/{prefix_len}"),
                    "dev", &self.name,
                ])
                .status()
                .await?;
            if !status.success() {
                return Err(std::io::Error::other(format!(
                    "ip -6 route add {prefix}/{prefix_len} dev {} failed",
                    self.name
                )));
            }
        }
        #[cfg(target_os = "macos")]
        {
            let status = tokio::process::Command::new("route")
                .args([
                    "-n", "add", "-inet6",
                    &format!("{prefix}/{prefix_len}"),
                    "-interface", &self.name,
                ])
                .status()
                .await?;
            if !status.success() {
                return Err(std::io::Error::other(format!(
                    "route add -inet6 {prefix}/{prefix_len} -interface {} failed",
                    self.name
                )));
            }
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            let _ = (prefix, prefix_len);
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "add_route not supported on this platform",
            ));
        }
        Ok(())
    }
}
