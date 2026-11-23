//! SRP advertising proxy: bridges Thread SRP registrations to backbone mDNS.
//!
//! Thread devices register services via SRP (Service Registration Protocol,
//! RFC 9448) with the border router.  This module re-advertises those services
//! via DNS-SD / mDNS on the backbone link using the `mdns-sd` crate so that
//! backbone hosts can discover Thread devices through standard mDNS discovery.
//!
//! Additionally, a `_meshcop._udp` service is advertised so that
//! Thread Commissioning apps can find this border router.
//!
//! # Status
//!
//! Struct and registration API defined; mDNS advertisement stubs pending.

use std::collections::HashMap;

/// A service registered via Thread SRP and re-advertised on the backbone.
#[derive(Debug, Clone)]
pub struct SrpService {
    /// Service instance name (e.g. `"My Thread Device"`).
    pub instance_name: String,
    /// Service type (e.g. `"_http._tcp"`).
    pub service_type: String,
    /// Port the service listens on.
    pub port: u16,
    /// TXT record key-value pairs.
    pub txt: Vec<(String, Vec<u8>)>,
    /// Hostname of the service host.
    pub host_name: String,
    /// IPv6 addresses for the host.
    pub host_addrs: Vec<std::net::Ipv6Addr>,
}

/// SRP advertising proxy.  Maintains the mapping from SRP registrations to
/// active mDNS advertisements.
#[derive(Debug)]
pub struct SrpProxy {
    /// Active service registrations keyed by SRP host name.
    services: HashMap<String, Vec<SrpService>>,
    // Pending: mdns_sd::ServiceDaemon handle
}

impl SrpProxy {
    /// Creates a new proxy.  Call [`start`](Self::start) to begin advertising.
    pub fn new() -> Self {
        Self {
            services: HashMap::new(),
        }
    }

    /// Starts the mDNS service daemon and advertises `_meshcop._udp` for this
    /// border router.
    ///
    /// # Status
    ///
    /// Pending: start `mdns_sd::ServiceDaemon`, register `_meshcop._udp`.
    pub async fn start(&mut self) -> std::io::Result<()> {
        log::info!("SrpProxy: starting mDNS daemon (stub)");
        Ok(())
    }

    /// Registers or updates a service received via Thread SRP.
    ///
    /// If a service with the same host+type already exists it is updated;
    /// otherwise a new mDNS advertisement is created.
    ///
    /// # Status
    ///
    /// mDNS registration calls are pending.
    pub async fn register(&mut self, service: SrpService) -> std::io::Result<()> {
        log::info!(
            "SrpProxy: register {} {} (stub)",
            service.instance_name,
            service.service_type
        );
        self.services
            .entry(service.host_name.clone())
            .or_default()
            .push(service);
        Ok(())
    }

    /// Removes all services registered for `host_name` (SRP host removal).
    pub async fn unregister_host(&mut self, host_name: &str) -> std::io::Result<()> {
        log::info!("SrpProxy: unregister host {} (stub)", host_name);
        self.services.remove(host_name);
        Ok(())
    }
}

impl Default for SrpProxy {
    fn default() -> Self {
        Self::new()
    }
}
