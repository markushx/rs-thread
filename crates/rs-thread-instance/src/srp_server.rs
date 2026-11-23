//! SRP server of the instance: UDP transport, Network Data publishing,
//! port selection and persistence, lease timers.
//!
//! OpenThread: `Srp::Server` (`otSrpServer*`). The registration logic is
//! [`rs_thread_dns::srp::server::SrpServer`].

use core::net::{Ipv6Addr, SocketAddrV6};

use rs_thread_core::settings::SettingsKey;
use rs_thread_core::time::Instant;
use rs_thread_core::{Error, Result};
use rs_thread_dns::srp::server::{
    ANYCAST_PORT, LeaseConfig, SrpServer, TtlConfig, UDP_PORT_MAX, UDP_PORT_MIN,
};
use rs_thread_mesh::netdata::local::ServiceConfig;
use rs_thread_mesh::netdata::publisher::{DnsSrpService, PublisherEvent};
use rs_thread_mesh::netdata::tlv::THREAD_ENTERPRISE_NUMBER;
use rs_thread_net::header::{MAX_DATAGRAM_LEN, PROTO_UDP};
use rs_thread_net::udp::{SocketHandle, UdpSendOpts};
use rs_thread_platform::SettingsStore;
use rand_core::{CryptoRng, Rng};

const DNS_PORT: u16 = 53;

use crate::{Instance, InstanceCrypto, MAX_UDP_PAYLOAD};

/// Hosts the SRP server stores (OT: heap; see the differences document).
pub const SRP_SERVER_HOSTS: usize = 8;
/// Services the SRP server stores in total.
pub const SRP_SERVER_SERVICES: usize = 16;
/// Services in one update message.
pub const SRP_SERVER_UPDATE_SERVICES: usize = 8;

/// The SRP server with this instance's limits.
pub type SrpServerStore =
    SrpServer<SRP_SERVER_HOSTS, SRP_SERVER_SERVICES, SRP_SERVER_UPDATE_SERVICES>;

/// State of the SRP server (OT `otSrpServerState`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum SrpServerState {
    /// Not enabled.
    Disabled,
    /// Enabled and listening.
    Running,
    /// Enabled, waiting for its Network Data entry.
    Stopped,
}

/// How the server is reached (OT `otSrpServerAddressMode`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum SrpAddressMode {
    /// Unicast: the mesh-local EID and the port in the server data, via the
    /// Network Data publisher.
    Unicast,
    /// Anycast with the sequence number.
    Anycast,
    /// Unicast, added to the Network Data without the publisher's
    /// consideration of other servers.
    UnicastForceAdd,
}

#[derive(Debug)]
pub(crate) struct SrpServerCtx {
    pub(crate) store: SrpServerStore,
    state: SrpServerState,
    mode: SrpAddressMode,
    seq: u8,
    /// 0: not selected yet.
    port: u16,
    pub(crate) sock: Option<SocketHandle>,
    /// The DNS-SD socket (port 53) while the server runs, unless the SRP
    /// socket is on that port itself.
    pub(crate) dns_sock: Option<SocketHandle>,
    registered_any: bool,
}

impl SrpServerCtx {
    pub(crate) fn new() -> Self {
        Self {
            store: SrpServerStore::new(),
            state: SrpServerState::Disabled,
            mode: SrpAddressMode::Unicast,
            seq: 0,
            port: 0,
            sock: None,
            dns_sock: None,
            registered_any: false,
        }
    }

    pub(crate) fn next_deadline(&self) -> Option<Instant> {
        if self.state == SrpServerState::Running {
            self.store.next_deadline()
        } else {
            None
        }
    }
}

impl<S: SettingsStore, C: InstanceCrypto, R: Rng + CryptoRng> Instance<S, C, R> {
    /// The server's state.
    pub fn srp_server_state(&self) -> SrpServerState {
        self.dnssrp.srpd.state
    }

    /// The registered hosts and services.
    pub fn srp_server_store(&self) -> &SrpServerStore {
        &self.dnssrp.srpd.store
    }

    /// The port the server listens on (or will, once running); 0 before one
    /// was selected.
    pub fn srp_server_port(&self) -> u16 {
        self.dnssrp.srpd.port
    }

    /// The address mode.
    pub fn srp_server_address_mode(&self) -> SrpAddressMode {
        self.dnssrp.srpd.mode
    }

    /// Set the address mode ([`Error::InvalidState`] unless disabled).
    pub fn srp_server_set_address_mode(&mut self, mode: SrpAddressMode) -> Result<()> {
        if self.dnssrp.srpd.state != SrpServerState::Disabled {
            return Err(Error::InvalidState);
        }
        self.dnssrp.srpd.mode = mode;
        Ok(())
    }

    /// The anycast sequence number.
    pub fn srp_server_anycast_seq_num(&self) -> u8 {
        self.dnssrp.srpd.seq
    }

    /// Set the anycast sequence number ([`Error::InvalidState`] unless
    /// disabled).
    pub fn srp_server_set_anycast_seq_num(&mut self, seq: u8) -> Result<()> {
        if self.dnssrp.srpd.state != SrpServerState::Disabled {
            return Err(Error::InvalidState);
        }
        self.dnssrp.srpd.seq = seq;
        Ok(())
    }

    /// Set the domain ([`Error::InvalidState`] unless disabled,
    /// [`Error::InvalidArgs`] if invalid).
    pub fn srp_server_set_domain(&mut self, domain: &str) -> Result<()> {
        if self.dnssrp.srpd.state != SrpServerState::Disabled {
            return Err(Error::InvalidState);
        }
        if self.dnssrp.srpd.store.set_domain(domain) {
            Ok(())
        } else {
            Err(Error::InvalidArgs)
        }
    }

    /// Set the TTL limits.
    pub fn srp_server_set_ttl_config(&mut self, c: TtlConfig) -> Result<()> {
        if self.dnssrp.srpd.store.set_ttl_config(c) {
            Ok(())
        } else {
            Err(Error::InvalidArgs)
        }
    }

    /// Set the lease limits.
    pub fn srp_server_set_lease_config(&mut self, c: LeaseConfig) -> Result<()> {
        if self.dnssrp.srpd.store.set_lease_config(c) {
            Ok(())
        } else {
            Err(Error::InvalidArgs)
        }
    }

    /// Enable or disable the server (OT `otSrpServerSetEnabled`).
    pub fn srp_server_set_enabled(&mut self, enabled: bool, now: Instant) {
        if enabled {
            self.srp_server_enable(now);
        } else {
            self.srp_server_disable(now);
        }
        self.core.now = now;
        self.poll(now);
    }

    fn srp_server_enable(&mut self, now: Instant) {
        if self.dnssrp.srpd.state != SrpServerState::Disabled {
            return;
        }
        self.dnssrp.srpd.state = SrpServerState::Stopped;
        match self.dnssrp.srpd.mode {
            SrpAddressMode::Unicast => {
                self.srp_server_select_port();
                let port = self.dnssrp.srpd.port;
                self.publish_dns_srp_service(DnsSrpService::UnicastMlEid { port, version: 0 }, now);
            }
            SrpAddressMode::Anycast => {
                self.dnssrp.srpd.port = ANYCAST_PORT;
                let sequence_number = self.dnssrp.srpd.seq;
                self.publish_dns_srp_service(
                    DnsSrpService::Anycast {
                        sequence_number,
                        version: 0,
                    },
                    now,
                );
            }
            SrpAddressMode::UnicastForceAdd => {
                self.srp_server_select_port();
                if let Some(cfg) = self.srp_force_add_service() {
                    if self.add_service(cfg).is_err() {
                        return;
                    }
                    self.srp_server_start(now);
                }
            }
        }
    }

    fn srp_force_add_service(&self) -> Option<ServiceConfig> {
        let mut sv = [0u8; 18];
        sv[..16].copy_from_slice(&self.core.ml_eid_addr().octets());
        sv[16..].copy_from_slice(&self.dnssrp.srpd.port.to_be_bytes());
        ServiceConfig::new(THREAD_ENTERPRISE_NUMBER, &[0x5d], &sv, true).ok()
    }

    fn srp_server_disable(&mut self, now: Instant) {
        if self.dnssrp.srpd.state == SrpServerState::Disabled {
            return;
        }
        match self.dnssrp.srpd.mode {
            SrpAddressMode::Unicast | SrpAddressMode::Anycast => {
                self.unpublish_dns_srp_service(now);
            }
            SrpAddressMode::UnicastForceAdd => {
                let _ = self.remove_service(THREAD_ENTERPRISE_NUMBER, &[0x5d]);
            }
        }
        self.srp_server_stop();
        self.dnssrp.srpd.state = SrpServerState::Disabled;
    }

    /// OT `InitPort` and `SelectPort`: continue after the persisted port.
    fn srp_server_select_port(&mut self) {
        if self.dnssrp.srpd.port == 0 {
            self.dnssrp.srpd.port = UDP_PORT_MIN;
            let mut b = [0u8; 2];
            if matches!(
                self.core
                    .settings
                    .get(SettingsKey::SrpServerInfo, 0, &mut b),
                Ok(2)
            ) {
                self.dnssrp.srpd.port = u16::from_le_bytes(b);
            }
        }
        let d = &mut self.dnssrp.srpd;
        d.port = d.port.wrapping_add(1);
        if !(UDP_PORT_MIN..=UDP_PORT_MAX).contains(&d.port) {
            d.port = UDP_PORT_MIN;
        }
    }

    fn srp_server_start(&mut self, now: Instant) {
        if self.dnssrp.srpd.state != SrpServerState::Stopped {
            return;
        }
        self.dnssrp.srpd.state = SrpServerState::Running;
        if self.srp_server_prepare_socket().is_err() {
            // Re-enable to select a new port.
            self.srp_server_disable(now);
            self.srp_server_enable(now);
        }
    }

    fn srp_server_prepare_socket(&mut self) -> Result<()> {
        if self.dnssrp.srpd.sock.is_some() {
            return Ok(());
        }
        let s = self.udp.open()?;
        let any = SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, self.dnssrp.srpd.port, 0, 0);
        if let Err(e) = self.udp.bind(s, any, &self.core.ip6.netif) {
            let _ = self.udp.close(s);
            return Err(e);
        }
        self.dnssrp.srpd.sock = Some(s);
        if self.dnssrp.srpd.port != DNS_PORT && self.dnssrp.srpd.dns_sock.is_none() {
            let d = self.udp.open()?;
            let any = SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, DNS_PORT, 0, 0);
            if let Err(e) = self.udp.bind(d, any, &self.core.ip6.netif) {
                let _ = self.udp.close(d);
                return Err(e);
            }
            self.dnssrp.srpd.dns_sock = Some(d);
        }
        Ok(())
    }

    fn srp_server_stop(&mut self) {
        let d = &mut self.dnssrp.srpd;
        if d.state != SrpServerState::Running {
            return;
        }
        d.state = SrpServerState::Stopped;
        d.store.clear();
        d.registered_any = false;
        if let Some(s) = d.sock.take() {
            let _ = self.udp.close(s);
        }
        if let Some(s) = self.dnssrp.srpd.dns_sock.take() {
            let _ = self.udp.close(s);
        }
    }

    /// The publisher added or removed the DNS/SRP entry.
    pub(crate) fn srp_server_publisher_event(&mut self, e: &PublisherEvent, now: Instant) {
        match e {
            PublisherEvent::DnsSrpAdded => self.srp_server_start(now),
            PublisherEvent::DnsSrpRemoved => self.srp_server_stop(),
            _ => {}
        }
    }

    /// Expire leases that are due.
    pub(crate) fn service_srp_server(&mut self, now: Instant) -> bool {
        let d = &mut self.dnssrp.srpd;
        if d.state == SrpServerState::Running && d.store.next_deadline().is_some_and(|t| t <= now) {
            d.store.poll(now);
            return true;
        }
        false
    }

    /// A datagram on socket `h`: consumed here if it is the SRP server's.
    pub(crate) fn srp_server_rx(&mut self, now: Instant, h: SocketHandle) -> bool {
        let d = &self.dnssrp.srpd;
        if d.sock != Some(h) && d.dns_sock != Some(h) {
            return false;
        }
        let mut buf = [0u8; MAX_UDP_PAYLOAD];
        while let Ok(Some(info)) = self.udp.recv(h, &mut buf) {
            if info.truncated || self.dnssrp.srpd.state != SrpServerState::Running {
                continue;
            }
            let msg = &buf[..info.len];
            // A query (opcode 0) is DNS-SD, an UPDATE (opcode 5) is SRP.
            let is_query = msg.get(2).is_some_and(|b| (b >> 3) & 0xf == 0);
            if is_query {
                let mut out = [0u8; MAX_UDP_PAYLOAD];
                if let Some(n) = self.dnssrp.srpd.store.handle_query(now, msg, &mut out) {
                    self.srp_server_send(now, h, info.meta.peer, info.meta.local, &out[..n]);
                }
            } else if self.dnssrp.srpd.sock == Some(h) {
                self.srp_server_handle(now, h, info.meta.peer, info.meta.local, msg);
            }
        }
        true
    }

    /// Process one SRP message and send the response.
    pub(crate) fn srp_server_handle(
        &mut self,
        now: Instant,
        sock: SocketHandle,
        peer: SocketAddrV6,
        local: SocketAddrV6,
        msg: &[u8],
    ) {
        let mut out = [0u8; MAX_UDP_PAYLOAD];
        let d = &mut self.dnssrp.srpd;
        let Some(r) = d
            .store
            .handle_message(now, msg, &self.core.crypto, &mut out)
        else {
            return;
        };
        if r.committed && !d.registered_any {
            d.registered_any = true;
            if matches!(
                d.mode,
                SrpAddressMode::Unicast | SrpAddressMode::UnicastForceAdd
            ) {
                let port = d.port.to_le_bytes();
                let _ = self.core.settings.set(SettingsKey::SrpServerInfo, &port);
            }
        }
        self.srp_server_send(now, sock, peer, local, &out[..r.len]);
    }

    fn srp_server_send(
        &mut self,
        now: Instant,
        sock: SocketHandle,
        peer: SocketAddrV6,
        local: SocketAddrV6,
        payload: &[u8],
    ) {
        // Reply from the address the request was sent to (the anycast
        // address in anycast mode).
        let src = (!local.ip().is_multicast() && !local.ip().is_unspecified()).then(|| *local.ip());
        let opts = UdpSendOpts {
            src,
            ..UdpSendOpts::default()
        };
        let mut pkt = [0u8; MAX_DATAGRAM_LEN];
        if let Ok((info, n)) = self.udp.build_send(
            sock,
            Some(peer),
            &opts,
            payload,
            &mut pkt,
            &self.core.ip6.netif,
        ) {
            let _ = self.ip6_send(now, &info, PROTO_UDP, &pkt[..n]);
        }
    }
}
