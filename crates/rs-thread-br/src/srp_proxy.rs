//! SRP advertising proxy: bridges Thread SRP registrations to backbone mDNS.
//!
//! Thread devices register services via SRP (RFC 9448) with the border router's
//! SRP server.  This module re-advertises those registrations via DNS-SD / mDNS
//! on the backbone link using the `mdns-sd` crate so that backbone hosts can
//! discover Thread devices through standard mDNS discovery.
//!
//! Additionally, a `_meshcop._udp` service is advertised so that Thread
//! Commissioning apps can find this border router.
//!
//! # Usage
//!
//! ```ignore
//! let mut proxy = SrpProxy::new();
//! proxy.start(49191).await?;
//!
//! // Feed SRP server events:
//! proxy.register(SrpService { .. }).await?;
//! proxy.unregister_host("mydevice.local.").await?;
//! ```

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};

use mdns_sd::{ServiceDaemon, ServiceInfo};

/// A service registered via Thread SRP and to be re-advertised on the backbone.
#[derive(Debug, Clone)]
pub struct SrpService {
    /// Service instance name (e.g. `"My Thread Device"`).
    pub instance_name: String,
    /// Service type without the `.local.` suffix (e.g. `"_http._tcp"`).
    pub service_type: String,
    /// Port the service listens on.
    pub port: u16,
    /// TXT record key-value pairs.
    pub txt: Vec<(String, Vec<u8>)>,
    /// Hostname of the service host (should end with `.local.`).
    pub host_name: String,
    /// IPv6 addresses for the host.
    pub host_addrs: Vec<std::net::Ipv6Addr>,
}

/// SRP advertising proxy.
///
/// Keeps the mapping from SRP host names to active mDNS service registrations.
/// Call [`start`](Self::start) once before feeding SRP events.
pub struct SrpProxy {
    /// mDNS daemon, present after `start()`.
    daemon: Option<ServiceDaemon>,
    /// Tracks the mDNS full-name for every registered service so we can
    /// unregister it on host removal.
    registered: HashMap<String, Vec<String>>,
}

impl std::fmt::Debug for SrpProxy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SrpProxy")
            .field("active_hosts", &self.registered.len())
            .finish()
    }
}

impl SrpProxy {
    /// Creates a new proxy.  Call [`start`](Self::start) to begin advertising.
    pub fn new() -> Self {
        Self {
            daemon: None,
            registered: HashMap::new(),
        }
    }

    /// Starts the mDNS daemon and advertises `_meshcop._udp` for this border
    /// router on `border_agent_port`.
    pub fn start(&mut self, border_agent_port: u16) -> std::io::Result<()> {
        let daemon = ServiceDaemon::new()
            .map_err(|e| std::io::Error::other(format!("mdns-sd: {e}")))?;

        // Advertise the border agent service so Thread Commissioning apps can
        // find this border router on the backbone.
        let host = std::process::Command::new("hostname")
            .output()
            .ok()
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .map(|s| s.trim().to_owned())
            .unwrap_or_else(|| "rsthread-br".to_owned());
        let host_name = format!("{host}.local.");
        let meshcop_name = format!("{host} Border Router");

        let mut props = HashMap::new();
        props.insert("sb".to_string(), "0x0000".to_string());
        props.insert("vn".to_string(), "rs-thread".to_string());

        match ServiceInfo::new(
            "_meshcop._udp.local.",
            &meshcop_name,
            &host_name,
            IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            border_agent_port,
            props,
        ) {
            Ok(info) => {
                daemon
                    .register(info)
                    .map_err(|e| std::io::Error::other(format!("mdns-sd register meshcop: {e}")))?;
                log::info!("SrpProxy: advertised _meshcop._udp on port {border_agent_port}");
            }
            Err(e) => {
                log::warn!("SrpProxy: could not build _meshcop._udp ServiceInfo: {e}");
            }
        }

        self.daemon = Some(daemon);
        Ok(())
    }

    /// Registers or updates a service received via Thread SRP.
    ///
    /// If a service with the same instance name already exists it is first
    /// unregistered, then re-registered with the new details.
    pub fn register(&mut self, service: SrpService) -> std::io::Result<()> {
        let Some(daemon) = self.daemon.as_ref() else {
            return Err(std::io::Error::other("SrpProxy::start() not called"));
        };

        // Ensure the service type ends with `.local.`
        let svc_domain = if service.service_type.ends_with(".local.") {
            service.service_type.clone()
        } else {
            format!("{}.local.", service.service_type)
        };

        // Build TXT properties.
        let props: HashMap<String, String> = service
            .txt
            .iter()
            .map(|(k, v)| (k.clone(), String::from_utf8_lossy(v).into_owned()))
            .collect();

        let host_name = if service.host_name.ends_with(".local.") {
            service.host_name.clone()
        } else {
            format!("{}.local.", service.host_name)
        };

        // mdns-sd's ServiceInfo takes IPv4; we pass UNSPECIFIED and rely on
        // the host name being resolved via AAAA records the Thread device
        // registers separately.  IPv6 address support via mdns-sd is tracked
        // as a follow-up.
        let info = ServiceInfo::new(
            &svc_domain,
            &service.instance_name,
            &host_name,
            IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            service.port,
            props,
        )
        .map_err(|e| std::io::Error::other(format!("mdns-sd ServiceInfo: {e}")))?;

        let full_name = info.get_fullname().to_owned();

        // Remove any previous registration for the same instance.
        if let Some(old_names) = self.registered.get(&service.host_name) {
            for name in old_names.iter().filter(|n| n.as_str() == full_name) {
                let _ = daemon.unregister(name);
            }
        }

        daemon
            .register(info)
            .map_err(|e| std::io::Error::other(format!("mdns-sd register: {e}")))?;

        log::info!(
            "SrpProxy: registered {} ({}) on port {}",
            service.instance_name,
            svc_domain,
            service.port
        );

        self.registered
            .entry(service.host_name)
            .or_default()
            .push(full_name);

        Ok(())
    }

    /// Removes all services registered for `host_name` (SRP host removal or
    /// lease expiry).
    pub fn unregister_host(&mut self, host_name: &str) -> std::io::Result<()> {
        let Some(daemon) = self.daemon.as_ref() else {
            return Ok(());
        };
        if let Some(names) = self.registered.remove(host_name) {
            for name in names {
                if let Err(e) = daemon.unregister(&name) {
                    log::warn!("SrpProxy: failed to unregister {name}: {e}");
                }
            }
            log::info!("SrpProxy: unregistered host {host_name}");
        }
        Ok(())
    }
}

impl Default for SrpProxy {
    fn default() -> Self {
        Self::new()
    }
}
