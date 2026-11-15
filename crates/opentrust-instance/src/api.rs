//! The public API of the [`Instance`]: a loose mirror of the OpenThread
//! `otInstance` / `otThread*` / `otDataset*` / `otIp6*` / `otUdp*` /
//! `otIcmp6*` functions in idiomatic Rust.

use core::net::{Ipv6Addr, SocketAddrV6};

use heapless::Deque;
use opentrust_core::settings::SettingsKey;
use opentrust_core::time::Instant;
use opentrust_core::types::{
    ExtAddress, ExtPanId, NetworkKey, NetworkName, Prefix64, Pskc, Rloc16,
};
use opentrust_core::{Error, Result};
use opentrust_mesh::netdata::local::{ExternalRouteConfig, OnMeshPrefixConfig};
use opentrust_meshcop::dataset::Dataset;
use opentrust_meshcop::dataset::DatasetType;
use opentrust_meshcop::tlv::SecurityPolicy;
use opentrust_mle::Role;
use opentrust_mle::persist::Restored;
use opentrust_mle::tlv::{DeviceMode, LeaderData, Timestamp};
use opentrust_net::header::{PROTO_ICMP6, PROTO_UDP};
use opentrust_net::icmp6::{Icmp6Header, TYPE_ECHO_REPLY, TYPE_ECHO_REQUEST};
use opentrust_net::ip6::{Delivery, SendInfo};
use opentrust_net::netif::UnicastAddress;
use opentrust_net::udp::{RecvInfo, SocketHandle, UdpSendOpts};
use opentrust_platform::SettingsStore;
use rand_core::{CryptoRng, Rng};

use crate::InstanceCrypto;

use crate::{DnsSrpService, Event, Instance};

/// A UDP socket of the application (OT `otUdpSocket`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UdpSocket(pub(crate) SocketHandle);

/// A received ICMPv6 echo reply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PingReply {
    /// The replying address.
    pub src: Ipv6Addr,
    /// Identifier of the request.
    pub id: u16,
    /// Sequence number of the request.
    pub seq: u16,
    /// Payload length.
    pub payload_len: usize,
    /// Hop limit of the reply.
    pub hop_limit: u8,
    /// Arrival time.
    pub at: Instant,
}

#[derive(Debug, Default)]
pub(crate) struct PingState {
    replies: Deque<PingReply, 4>,
}

pub(crate) fn placeholder_key() -> NetworkKey {
    NetworkKey([0; 16])
}

impl<S: SettingsStore, C: InstanceCrypto, R: Rng + CryptoRng> Instance<S, C, R> {
    // ------------------------------------------------------------ link

    /// Enable or disable the IPv6 interface (OT `otIp6SetEnabled`).
    pub fn ip6_set_enabled(&mut self, enabled: bool) {
        self.ip6_enabled = enabled;
        if !enabled {
            self.thread_stop();
        }
    }

    /// Start Thread (OT `otThreadSetEnabled(true)`): restore the stored
    /// network or attach with the Active Dataset; if no router answers an
    /// FTD forms a new partition as its leader.
    ///
    /// [`Error::InvalidState`] without an enabled interface or a complete
    /// Active Dataset.
    pub fn thread_start(&mut self, now: Instant) -> Result<()> {
        self.start_inner(now, false)
    }

    /// Set the extended address (OT `otLinkSetExtendedAddress`) and with it
    /// the link-local address. [`Error::InvalidState`] while Thread is
    /// started.
    pub fn set_ext_address(&mut self, ext: ExtAddress) -> Result<()> {
        if self.started {
            return Err(Error::InvalidState);
        }
        use opentrust_mle::env::MleEnv as _;
        let iid = self.core.ml_iid;
        self.core.apply_restored_identity(&ext, &iid);
        Ok(())
    }

    /// Whether the IPv6 interface is enabled.
    pub fn ip6_enabled(&self) -> bool {
        self.ip6_enabled
    }

    /// The device mode (receiver on when idle, FTD, full Network Data).
    pub fn link_mode(&self) -> DeviceMode {
        self.mle.device_mode()
    }

    /// Change the device mode (OT `otThreadSetLinkMode`).
    pub fn set_link_mode(&mut self, mode: DeviceMode, now: Instant) -> Result<()> {
        self.core.now = now;
        self.mle.set_device_mode(&mut self.core, now, mode)?;
        self.poll(now);
        Ok(())
    }

    /// Start Thread and become the leader of a new partition at once (OT
    /// `otThreadBecomeLeader`).
    #[cfg(feature = "ftd")]
    pub fn become_leader(&mut self, now: Instant) -> Result<()> {
        self.start_inner(now, true)
    }

    fn start_inner(&mut self, now: Instant, lead: bool) -> Result<()> {
        self.core.now = now;
        if !self.ip6_enabled || self.mle.role() != Role::Disabled {
            return Err(Error::InvalidState);
        }
        // The Active Dataset: the one in RAM or the stored one.
        {
            let (ds, mut env) = self.core.ds();
            if !ds.is_saved(DatasetType::Active) {
                let _ = ds.restore(&mut env, now, DatasetType::Active);
            }
            if !ds.is_saved(DatasetType::Active) {
                return Err(Error::InvalidState);
            }
            let _ = ds.restore(&mut env, now, DatasetType::Pending);
        }
        self.load_iid_secret();
        self.load_dad_counter();
        self.started = true;
        self.sync_netif();
        let restored = if lead {
            Err(Error::NotFound)
        } else {
            self.mle.restore(&mut self.core, now)
        };
        match restored {
            Ok(Restored::Router { role, .. }) => {
                self.glue.restoring_leader = role == Role::Leader;
                #[cfg(feature = "ftd")]
                self.mle.restore_children(&mut self.core, now);
            }
            Ok(Restored::Child { .. }) => {}
            Err(_) => {
                self.mle.start(&mut self.core, now)?;
                #[cfg(feature = "ftd")]
                if lead {
                    self.mle.become_leader(&mut self.core, now, false)?;
                }
            }
        }
        self.poll(now);
        Ok(())
    }

    fn load_iid_secret(&mut self) {
        let mut b = [0u8; 32];
        match self
            .core
            .settings
            .get(SettingsKey::SlaacIidSecretKey, 0, &mut b)
        {
            Ok(32) => self.core.iid_secret = b,
            _ => {
                let _ = self
                    .core
                    .settings
                    .set(SettingsKey::SlaacIidSecretKey, &self.core.iid_secret);
            }
        }
    }

    /// Stop Thread (OT `otThreadSetEnabled(false)`).
    pub fn thread_stop(&mut self) {
        if self.mle.role() == Role::Disabled {
            return;
        }
        self.mle.stop(&mut self.core);
        self.started = false;
        self.fwd.clear();
        self.core.mac.stop_polling();
        self.poll(self.core.now);
    }

    /// Erase all persistent settings and stop (OT `otInstanceFactoryReset`).
    pub fn factory_reset(&mut self) {
        self.thread_stop();
        self.core.settings.wipe();
    }

    /// The settings store (read access, for example to serialise it for
    /// persistence; see [`SettingsStore::change_count`]).
    pub fn settings(&self) -> &S {
        &self.core.settings
    }

    /// The settings store with write access, for restoring persisted
    /// settings before [`thread_start`](Self::thread_start) (the instance
    /// reads datasets, network info and the SLAAC secret when it starts).
    /// Changing settings of a running node behind its back is not
    /// supported.
    pub fn settings_mut(&mut self) -> &mut S {
        &mut self.core.settings
    }

    /// Consume the instance and return its settings store (a power cycle in
    /// tests: build a new instance from the old settings).
    pub fn into_settings(self) -> S {
        self.core.settings
    }

    // ------------------------------------------------------------ getters

    /// Thread role.
    pub fn role(&self) -> Role {
        self.mle.role()
    }

    /// RLOC16 ([`Rloc16::INVALID`] while detached).
    pub fn rloc16(&self) -> Rloc16 {
        self.mle.rloc16()
    }

    /// Partition ID.
    pub fn partition_id(&self) -> u32 {
        self.mle.leader_data().partition_id
    }

    /// Leader Data (partition ID, weight, Network Data versions, leader
    /// router ID).
    pub fn leader_data(&self) -> LeaderData {
        *self.mle.leader_data()
    }

    /// The extended address.
    pub fn ext_address(&self) -> ExtAddress {
        self.core.ext
    }

    /// The mesh-local EID.
    pub fn ml_eid(&self) -> Ipv6Addr {
        self.core.ml_eid_addr()
    }

    /// The RLOC address, while attached.
    pub fn rloc(&self) -> Option<Ipv6Addr> {
        self.core.ip6.netif.rloc()
    }

    /// The link-local address.
    pub fn link_local(&self) -> Option<Ipv6Addr> {
        self.core.ip6.netif.link_local()
    }

    /// The unicast addresses of the interface.
    pub fn unicast_addresses(&self) -> impl Iterator<Item = &UnicastAddress> {
        self.core.ip6.netif.unicast_addresses()
    }

    /// The subscribed multicast addresses (fixed ones first).
    pub fn multicast_addresses(&self) -> impl Iterator<Item = Ipv6Addr> + '_ {
        self.core.ip6.netif.multicast_addresses()
    }

    /// Add a manually configured unicast address (OT `otIp6AddUnicastAddress`).
    pub fn add_unicast_address(&mut self, addr: Ipv6Addr, prefix_len: u8) -> Result<()> {
        self.core.ip6.netif.add_unicast(UnicastAddress {
            addr,
            prefix_len,
            origin: opentrust_net::netif::AddressOrigin::Manual,
            preferred: true,
            valid: true,
            scope_override: None,
            rloc: false,
            mesh_local: false,
        })
    }

    /// Remove a unicast address (OT `otIp6RemoveUnicastAddress`).
    pub fn remove_unicast_address(&mut self, addr: &Ipv6Addr) -> Result<()> {
        self.core.ip6.netif.remove_unicast(addr)
    }

    /// The factory-assigned EUI-64.
    pub fn eui64(&self) -> ExtAddress {
        self.cm.eui64
    }

    /// The Network Data as this device has it.
    pub fn network_data(&self) -> opentrust_mesh::netdata::NetworkDataView<'_> {
        self.core.netdata.view()
    }

    /// The MLE state (router table, children, parent).
    pub fn mle(&self) -> &opentrust_mle::Mle<{ crate::CHILDREN }> {
        &self.mle
    }

    /// The MAC (counters, addresses).
    pub fn mac(&self) -> &crate::stack::StackMac<C> {
        &self.core.mac
    }

    /// Entries of the address cache.
    pub fn address_cache(&self) -> impl Iterator<Item = opentrust_net::resolver::EntryInfo> + '_ {
        self.resolver.iter()
    }

    /// Set the data poll period of a sleepy end device (OT
    /// `otLinkSetPollPeriod`); `None` returns to the default derived from
    /// the child timeout. The shorter of the two is used.
    pub fn set_poll_period(&mut self, period: Option<opentrust_core::time::Duration>) {
        self.core.user_poll_period = period;
        self.core.apply_poll_period();
    }

    // ------------------------------------------------------------ datasets

    /// Set the Active Dataset (OT `otDatasetSetActive`): stored, and applied
    /// at once while Thread is disabled.
    pub fn set_active_dataset(&mut self, d: &Dataset, now: Instant) -> Result<()> {
        self.set_dataset(DatasetType::Active, d, now)
    }

    /// Set the Pending Dataset (OT `otDatasetSetPending`).
    pub fn set_pending_dataset(&mut self, d: &Dataset, now: Instant) -> Result<()> {
        self.set_dataset(DatasetType::Pending, d, now)
    }

    fn set_dataset(&mut self, t: DatasetType, d: &Dataset, now: Instant) -> Result<()> {
        self.core.now = now;
        let r = {
            let (ds, mut env) = self.core.ds();
            ds.save_local(&mut env, now, t, d)
        };
        self.poll(now);
        r
    }

    /// The Active Dataset, if there is one.
    pub fn active_dataset(&self, now: Instant) -> Option<Dataset> {
        self.core.datasets.read(DatasetType::Active, now)
    }

    /// The Pending Dataset, if there is one.
    pub fn pending_dataset(&self, now: Instant) -> Option<Dataset> {
        self.core.datasets.read(DatasetType::Pending, now)
    }

    /// A new complete Active Dataset with random credentials (OT
    /// `otDatasetCreateNewNetwork`).
    pub fn create_dataset(&mut self, channel: u8) -> Result<Dataset> {
        let mut d = Dataset::new();
        d.set_timestamp(
            DatasetType::Active,
            &Timestamp {
                seconds: 1,
                ticks: 0,
                authoritative: false,
            },
        )?;
        let mut key = [0u8; 16];
        self.core.rng.fill_bytes(&mut key);
        d.set_network_key(&NetworkKey(key))?;
        let mut xpan = [0u8; 8];
        self.core.rng.fill_bytes(&mut xpan);
        d.set_ext_pan_id(&ExtPanId(xpan))?;
        let mut mlp = [0u8; 8];
        self.core.rng.fill_bytes(&mut mlp);
        mlp[0] = 0xfd;
        mlp[6] = 0;
        mlp[7] = 0;
        d.set_mesh_local_prefix(&Prefix64(mlp))?;
        let mut pan = [0u8; 2];
        self.core.rng.fill_bytes(&mut pan);
        let pan = u16::from_le_bytes(pan);
        d.set_pan_id(if pan == 0xffff { 0xfffe } else { pan })?;
        let mut pskc = [0u8; 16];
        self.core.rng.fill_bytes(&mut pskc);
        d.set_pskc(&Pskc(pskc))?;
        d.set_network_name(&NetworkName::new("OpenTrust")?)?;
        d.set_channel(channel)?;
        d.set_channel_mask(0x07ff_f800)?;
        d.set_security_policy(&SecurityPolicy::default())?;
        Ok(d)
    }

    // ------------------------------------------------------------ Network Data

    /// Add an on-mesh prefix to the local Network Data (OT
    /// `otBorderRouterAddOnMeshPrefix`); the notifier registers it with the
    /// leader.
    pub fn add_on_mesh_prefix(&mut self, cfg: OnMeshPrefixConfig) -> Result<()> {
        self.local.add_on_mesh_prefix(cfg)?;
        self.notifier
            .event(opentrust_mesh::netdata::notifier::NotifierEvent::LocalChanged);
        Ok(())
    }

    /// Add an external route to the local Network Data (OT
    /// `otBorderRouterAddRoute`).
    pub fn add_external_route(&mut self, cfg: ExternalRouteConfig) -> Result<()> {
        self.local.add_external_route(cfg)?;
        self.notifier
            .event(opentrust_mesh::netdata::notifier::NotifierEvent::LocalChanged);
        Ok(())
    }

    /// Remove an on-mesh prefix from the local Network Data (OT
    /// `otBorderRouterRemoveOnMeshPrefix`).
    pub fn remove_on_mesh_prefix(
        &mut self,
        prefix: &opentrust_mesh::netdata::tlv::NetPrefix,
    ) -> Result<()> {
        self.local.remove_on_mesh_prefix(prefix)?;
        self.notifier
            .event(opentrust_mesh::netdata::notifier::NotifierEvent::LocalChanged);
        Ok(())
    }

    /// Remove an external route from the local Network Data (OT
    /// `otBorderRouterRemoveRoute`).
    pub fn remove_external_route(
        &mut self,
        prefix: &opentrust_mesh::netdata::tlv::NetPrefix,
    ) -> Result<()> {
        self.local.remove_external_route(prefix)?;
        self.notifier
            .event(opentrust_mesh::netdata::notifier::NotifierEvent::LocalChanged);
        Ok(())
    }

    /// The router configuration (eligibility, upgrade and downgrade
    /// thresholds, selection jitter, leader weight) for changes by the
    /// application, such as the CLI.
    pub fn router_config_mut(&mut self) -> &mut opentrust_mle::router_config::RouterConfig {
        self.mle.router_config_mut()
    }

    /// Publish this device as the DNS/SRP server in the Network Data (OT
    /// `otNetDataPublishDnsSrpService*`).
    pub fn publish_dns_srp_service(&mut self, service: DnsSrpService, now: Instant) {
        let attached = self.mle.role().is_attached();
        let ctx = opentrust_mesh::netdata::publisher::PublishContext {
            attached,
            router_or_leader: self.mle.role().is_router_or_leader(),
            rloc16: self.mle.rloc16(),
            leader: self.core.netdata.view(),
            ml_eid: self.core.ml_eid_addr(),
        };
        let mut pe: heapless::Vec<_, 4> = heapless::Vec::new();
        self.publisher
            .publish_dns_srp(service, &ctx, &mut self.local, now, &mut |e| {
                let _ = pe.push(e);
            });
        for e in pe {
            self.core.push_event(Event::Publisher(e));
        }
        self.poll(now);
    }

    /// Stop publishing the DNS/SRP service.
    pub fn unpublish_dns_srp_service(&mut self, now: Instant) {
        let mut pe: heapless::Vec<_, 4> = heapless::Vec::new();
        self.publisher.unpublish_dns_srp(&mut self.local, &mut |e| {
            let _ = pe.push(e);
        });
        for e in pe {
            self.core.push_event(Event::Publisher(e));
        }
        self.notifier
            .event(opentrust_mesh::netdata::notifier::NotifierEvent::LocalChanged);
        self.poll(now);
    }

    /// Add a service to the local Network Data (OT `otServerAddService`).
    pub fn add_service(
        &mut self,
        cfg: opentrust_mesh::netdata::local::ServiceConfig,
    ) -> Result<()> {
        self.local.add_service(cfg)?;
        self.notifier
            .event(opentrust_mesh::netdata::notifier::NotifierEvent::LocalChanged);
        Ok(())
    }

    /// Remove a service from the local Network Data.
    pub fn remove_service(&mut self, enterprise_number: u32, service_data: &[u8]) -> Result<()> {
        self.local.remove_service(enterprise_number, service_data)?;
        self.notifier
            .event(opentrust_mesh::netdata::notifier::NotifierEvent::LocalChanged);
        Ok(())
    }

    /// Serve extra TMF resources with `handler` (the request payload goes in,
    /// the response comes out). Replaces an earlier handler.
    pub fn set_tmf_extension(&mut self, uris: &[crate::TmfUri], handler: crate::TmfExtension) {
        for u in uris {
            let _ = self.agent.register(*u);
        }
        self.tmf_ext = Some(handler);
    }

    /// The local Network Data (what this device registers).
    pub fn local_data(&self) -> &opentrust_mesh::netdata::local::LocalData {
        &self.local
    }

    // ------------------------------------------------------------ UDP

    /// Open a UDP socket (OT `otUdpOpen`).
    pub fn udp_open(&mut self) -> Result<UdpSocket> {
        self.udp.open().map(UdpSocket)
    }

    /// Bind a socket (OT `otUdpBind`); port 0 picks an ephemeral port.
    pub fn udp_bind(&mut self, s: UdpSocket, local: SocketAddrV6) -> Result<()> {
        self.udp.bind(s.0, local, &self.core.ip6.netif)
    }

    /// Close a socket (OT `otUdpClose`).
    pub fn udp_close(&mut self, s: UdpSocket) -> Result<()> {
        self.udp.close(s.0)
    }

    /// The local address of a socket.
    pub fn udp_local_addr(&self, s: UdpSocket) -> Result<SocketAddrV6> {
        self.udp.local_addr(s.0)
    }

    /// Send a datagram (OT `otUdpSend`).
    pub fn udp_send_to(
        &mut self,
        s: UdpSocket,
        dst: SocketAddrV6,
        payload: &[u8],
        opts: &UdpSendOpts,
        now: Instant,
    ) -> Result<()> {
        self.core.now = now;
        let mut buf = [0u8; opentrust_net::header::MAX_DATAGRAM_LEN];
        let (info, n) = self.udp.build_send(
            s.0,
            Some(dst),
            opts,
            payload,
            &mut buf,
            &self.core.ip6.netif,
        )?;
        self.ip6_send(now, &info, PROTO_UDP, &buf[..n])?;
        self.poll(now);
        Ok(())
    }

    /// Receive a queued datagram into `buf` (`None` if there is none).
    pub fn udp_recv(&mut self, s: UdpSocket, buf: &mut [u8]) -> Result<Option<RecvInfo>> {
        self.udp.recv(s.0, buf)
    }

    /// Whether a datagram is queued on the socket ([`udp_recv`](Self::udp_recv)
    /// would return it).
    pub fn udp_has_data(&self, s: UdpSocket) -> Result<bool> {
        self.udp.has_data(s.0)
    }

    /// Accept UDP datagrams to `port` without link-layer security (OT
    /// `otIp6AddUnsecurePort`).
    pub fn add_unsecure_port(&mut self, port: u16) -> Result<()> {
        if self.glue.unsecure_ports.contains(&port) {
            return Ok(());
        }
        self.glue
            .unsecure_ports
            .push(port)
            .map_err(|_| Error::NoBufs)
    }

    /// Subscribe to a multicast address (OT `otIp6SubscribeMulticastAddress`).
    pub fn subscribe_multicast(&mut self, addr: Ipv6Addr) -> Result<()> {
        self.core.ip6.netif.subscribe_external(addr)
    }

    /// Leave a multicast address subscribed with
    /// [`subscribe_multicast`](Self::subscribe_multicast) (OT
    /// `otIp6UnsubscribeMulticastAddress`); [`Error::NotFound`] if it was
    /// not subscribed.
    pub fn unsubscribe_multicast(&mut self, addr: Ipv6Addr) -> Result<()> {
        self.core.ip6.netif.unsubscribe_external(&addr)
    }

    // ------------------------------------------------------------ ICMPv6

    /// Send an ICMPv6 echo request (OT `otIcmp6SendEchoRequest`); the reply
    /// is [`Event::PingReply`] / [`take_ping_reply`](Self::take_ping_reply).
    pub fn ping(
        &mut self,
        dst: Ipv6Addr,
        src: Option<Ipv6Addr>,
        id: u16,
        seq: u16,
        payload: &[u8],
        now: Instant,
    ) -> Result<()> {
        self.core.now = now;
        let mut buf = [0u8; 1280];
        let total = Icmp6Header::LEN + payload.len();
        let o = buf.get_mut(..total).ok_or(Error::NoBufs)?;
        let mut data = [0u8; 4];
        data[..2].copy_from_slice(&id.to_be_bytes());
        data[2..].copy_from_slice(&seq.to_be_bytes());
        Icmp6Header {
            ty: TYPE_ECHO_REQUEST,
            code: 0,
            checksum: 0,
            data,
        }
        .write(o)?;
        o[Icmp6Header::LEN..].copy_from_slice(payload);
        let mut info = SendInfo::new(dst);
        info.src = src;
        info.multicast_loop = true;
        self.ip6_send(now, &info, PROTO_ICMP6, &buf[..total])?;
        self.poll(now);
        Ok(())
    }

    /// The oldest unread echo reply.
    pub fn take_ping_reply(&mut self) -> Option<PingReply> {
        self.ping.replies.pop_front()
    }

    /// The oldest unread echo reply with identifier `id` and sequence number
    /// `seq`; other replies stay queued.
    pub fn take_ping_reply_matching(&mut self, id: u16, seq: u16) -> Option<PingReply> {
        let n = self.ping.replies.len();
        let mut found = None;
        for _ in 0..n {
            let Some(r) = self.ping.replies.pop_front() else {
                break;
            };
            if found.is_none() && r.id == id && r.seq == seq {
                found = Some(r);
            } else {
                let _ = self.ping.replies.push_back(r);
            }
        }
        found
    }

    pub(crate) fn ping_received(&mut self, now: Instant, d: &Delivery, bytes: &[u8]) {
        let Ok(h) = Icmp6Header::parse(bytes) else {
            return;
        };
        if h.ty != TYPE_ECHO_REPLY {
            return;
        }
        let r = PingReply {
            src: d.src,
            id: h.echo_id(),
            seq: h.echo_seq(),
            payload_len: bytes.len().saturating_sub(Icmp6Header::LEN),
            hop_limit: d.hop_limit,
            at: now,
        };
        if self.ping.replies.is_full() {
            let _ = self.ping.replies.pop_front();
        }
        let _ = self.ping.replies.push_back(r);
        self.core.push_event(Event::PingReply);
    }
}
