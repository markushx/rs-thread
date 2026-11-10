//! A surface that mirrors the esp-rs `openthread` crate (feature
//! `openthread-compat`), the type and method names `rs-matter-embassy` uses,
//! mapped onto the native API of this crate.
//!
//! What differs from esp-rs `openthread` (also listed in
//! `OPENTRUST-OPENTHREAD-DIFFERENCES.md`):
//!
//! - [`OpenThread`] has the generics of [`OpenTrust`] (raw mutex, clock and
//!   the instance types) because there is no single global instance; it is
//!   created from a [`Resources`], not from `new_with_udp_srp(eui64, caps,
//!   rng, settings, ...)` (the instance is built by the caller).
//! - [`OpenThread::run`] takes the [`Alarm`] as well (no `embassy-time`).
//! - Methods whose backing data the instance does not have return defaults
//!   (counters, neighbor age and frame counters, route LQI) or
//!   `OtError(Error::NotImplemented)` (CSL, child supervision, child
//!   timeout).

use core::net::{Ipv6Addr, SocketAddrV6};

use embassy_sync::blocking_mutex::raw::RawMutex;
use opentrust_core::Error;
use opentrust_core::time::Duration;
use opentrust_instance::{
    DeviceMode, Instance, InstanceCrypto, ItemState, Role, ServiceConfig, ServiceId, TxtEntry,
};
use opentrust_meshcop::dataset::Dataset;
use opentrust_platform::{Alarm, Clock, Radio, SettingsStore};
use rand_core::{CryptoRng, Rng};

use crate::state::{OpenTrust, Resources};

/// Error type of the compat surface (esp-rs: the OpenThread `otError`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OtError(pub Error);

impl OtError {
    /// The wrapped error.
    pub const fn into_inner(self) -> Error {
        self.0
    }
}

impl From<Error> for OtError {
    fn from(e: Error) -> Self {
        Self(e)
    }
}

/// Thread device role (esp-rs `DeviceRole`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum DeviceRole {
    /// Thread is disabled.
    Disabled,
    /// Not attached.
    Detached,
    /// Child.
    Child,
    /// Router.
    Router,
    /// Leader.
    Leader,
}

impl DeviceRole {
    /// Attached to a partition.
    pub const fn is_connected(&self) -> bool {
        matches!(self, Self::Child | Self::Router | Self::Leader)
    }
}

impl From<Role> for DeviceRole {
    fn from(r: Role) -> Self {
        match r {
            Role::Disabled => Self::Disabled,
            Role::Detached => Self::Detached,
            Role::Child => Self::Child,
            Role::Router => Self::Router,
            Role::Leader => Self::Leader,
        }
    }
}

/// Network status (esp-rs `NetStatus`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetStatus {
    /// The role.
    pub role: DeviceRole,
    /// Extended PAN ID of the Active Dataset.
    pub ext_pan_id: Option<u64>,
    /// The IPv6 interface is enabled.
    pub ip6_enabled: bool,
}

bitflags::bitflags! {
    /// Radio channels set (esp-rs `Channels`; bit `n` is channel `n`).
    #[repr(transparent)]
    #[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct Channels: u32 {
        /// Channel 11.
        const CH_11 = 1 << 11;
        /// Channel 12.
        const CH_12 = 1 << 12;
        /// Channel 13.
        const CH_13 = 1 << 13;
        /// Channel 14.
        const CH_14 = 1 << 14;
        /// Channel 15.
        const CH_15 = 1 << 15;
        /// Channel 16.
        const CH_16 = 1 << 16;
        /// Channel 17.
        const CH_17 = 1 << 17;
        /// Channel 18.
        const CH_18 = 1 << 18;
        /// Channel 19.
        const CH_19 = 1 << 19;
        /// Channel 20.
        const CH_20 = 1 << 20;
        /// Channel 21.
        const CH_21 = 1 << 21;
        /// Channel 22.
        const CH_22 = 1 << 22;
        /// Channel 23.
        const CH_23 = 1 << 23;
        /// Channel 24.
        const CH_24 = 1 << 24;
        /// Channel 25.
        const CH_25 = 1 << 25;
        /// Channel 26.
        const CH_26 = 1 << 26;
    }
}

/// A scan result (esp-rs `ScanResult`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanResult<'a> {
    /// Extended address of the responder.
    pub ext_address: u64,
    /// Network name.
    pub network_name: &'a str,
    /// Extended PAN ID.
    pub extended_pan_id: u64,
    /// Steering Data.
    pub steering_data: &'a [u8],
    /// PAN ID.
    pub pan_id: u16,
    /// Joiner UDP port.
    pub joiner_udp_port: u16,
    /// Channel.
    pub channel: u8,
    /// RSSI in dBm.
    pub rssi: i8,
    /// LQI.
    pub lqi: u8,
    /// Thread version.
    pub version: u8,
    /// A native commissioner is available.
    pub native_commissioner: bool,
    /// The result is from a discovery scan.
    pub discover: bool,
}

/// An energy scan result (esp-rs `EnergyScanResult`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct EnergyScanResult {
    /// Channel.
    pub channel: u8,
    /// Maximum RSSI in dBm.
    pub max_rssi: i8,
}

/// A neighbor (esp-rs `NeighborInfo`). `age`, the frame counters, `last_rssi`
/// and the error rates are not tracked by the instance and are `0` / `None`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[allow(missing_docs)]
pub struct NeighborInfo {
    pub ext_address: u64,
    pub age: u32,
    pub rloc16: u16,
    pub link_frame_counter: u32,
    pub mle_frame_counter: u32,
    pub link_quality_in: u8,
    pub average_rssi: Option<i8>,
    pub last_rssi: Option<i8>,
    pub frame_error_rate: u8,
    pub message_error_rate: u8,
    pub rx_on_when_idle: bool,
    pub full_thread_device: bool,
    pub full_network_data: bool,
    pub is_child: bool,
}

/// A router table entry (esp-rs `RouteInfo`). `ext_address`, the link
/// qualities and `age` are not tracked by the instance and are `0`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[allow(missing_docs)]
pub struct RouteInfo {
    pub ext_address: u64,
    pub rloc16: u16,
    pub router_id: u8,
    pub next_hop: u8,
    pub path_cost: u8,
    pub lqi_in: u8,
    pub lqi_out: u8,
    pub age: u8,
    pub allocated: bool,
    pub link_established: bool,
}

/// MAC counters (esp-rs `MacCounters`; OT names). Counters the MAC does not
/// keep (unicast / broadcast split, duplicates, FCS errors) are `0`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[allow(missing_docs)]
pub struct MacCounters {
    pub tx_total: u32,
    pub tx_unicast: u32,
    pub tx_broadcast: u32,
    pub tx_ack_requested: u32,
    pub tx_acked: u32,
    pub tx_no_ack_requested: u32,
    pub tx_data: u32,
    pub tx_data_poll: u32,
    pub tx_beacon: u32,
    pub tx_beacon_request: u32,
    pub tx_other: u32,
    pub tx_retry: u32,
    pub tx_direct_max_retry_expiry: u32,
    pub tx_indirect_max_retry_expiry: u32,
    pub tx_err_cca: u32,
    pub tx_err_abort: u32,
    pub tx_err_busy_channel: u32,
    pub rx_total: u32,
    pub rx_unicast: u32,
    pub rx_broadcast: u32,
    pub rx_data: u32,
    pub rx_data_poll: u32,
    pub rx_beacon: u32,
    pub rx_beacon_request: u32,
    pub rx_other: u32,
    pub rx_address_filtered: u32,
    pub rx_dest_addr_filtered: u32,
    pub rx_duplicated: u32,
    pub rx_err_no_frame: u32,
    pub rx_err_unknown_neighbor: u32,
    pub rx_err_invalid_src_addr: u32,
    pub rx_err_sec: u32,
    pub rx_err_fcs: u32,
    pub rx_err_other: u32,
}

/// MLE counters (esp-rs `MleCounters`); the instance keeps none, all zero.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[allow(missing_docs)]
pub struct MleCounters {
    pub disabled_role: u16,
    pub detached_role: u16,
    pub child_role: u16,
    pub router_role: u16,
    pub leader_role: u16,
    pub attach_attempts: u16,
    pub partition_id_changes: u16,
    pub better_partition_attach_attempts: u16,
    pub better_parent_attach_attempts: u16,
    pub parent_changes: u16,
    pub disabled_time_millis: u64,
    pub detached_time_millis: u64,
    pub child_time_millis: u64,
    pub router_time_millis: u64,
    pub leader_time_millis: u64,
    pub tracked_time_millis: u64,
}

/// IPv6 counters (esp-rs `IpCounters`); the instance keeps none, all zero.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[allow(missing_docs)]
pub struct IpCounters {
    pub tx_success: u32,
    pub rx_success: u32,
    pub tx_failure: u32,
    pub rx_failure: u32,
}

/// Placeholder for esp-rs `OtResources` (the instance holds the state).
#[derive(Debug, Default)]
pub struct OtResources;

impl OtResources {
    /// Create.
    pub const fn new() -> Self {
        Self
    }
}

/// Placeholder for esp-rs `OtUdpResources` (the instance has its own socket
/// table, `UDP_SOCKETS` entries).
#[derive(Debug, Default)]
pub struct OtUdpResources<const UDP_SOCKETS: usize = 1, const UDP_RX_SZ: usize = 1280>;

impl<const S: usize, const R: usize> OtUdpResources<S, R> {
    /// Create.
    pub const fn new() -> Self {
        Self
    }
}

/// Placeholder for esp-rs `OtSrpResources`.
#[derive(Debug, Default)]
pub struct OtSrpResources<const SRP_SVCS: usize = 3, const SRP_BUF_SZ: usize = 300>;

impl<const S: usize, const B: usize> OtSrpResources<S, B> {
    /// Create.
    pub const fn new() -> Self {
        Self
    }
}

/// SRP client configuration (esp-rs `SrpConf`). Only the host name and
/// addresses are applied; `ttl` and the lease times are not settable on the
/// instance.
#[derive(Debug, Clone)]
pub struct SrpConf<'a> {
    /// Host name.
    pub host_name: &'a str,
    /// Host addresses (empty: the client registers the interface addresses).
    pub host_addrs: &'a [Ipv6Addr],
    /// TTL (ignored).
    pub ttl: u32,
    /// Default lease (ignored).
    pub default_lease_secs: u32,
    /// Default key lease (ignored).
    pub default_key_lease_secs: u32,
}

/// An SRP service (esp-rs `SrpService`). Subtype labels are not applied.
#[derive(Debug, Clone)]
pub struct SrpService<'a, SI, TI> {
    /// Service type, e.g. `_matter._tcp`.
    pub name: &'a str,
    /// Instance label.
    pub instance_name: &'a str,
    /// Port.
    pub port: u16,
    /// Subtype labels (ignored).
    pub subtype_labels: SI,
    /// TXT entries.
    pub txt_entries: TI,
    /// Priority.
    pub priority: u16,
    /// Weight.
    pub weight: u16,
    /// Lease in seconds (0: client default).
    pub lease_secs: u32,
    /// Key lease in seconds (0: client default).
    pub key_lease_secs: u32,
}

/// Identifies a registered SRP service (esp-rs `SrpServiceSlot`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SrpServiceSlot(ServiceId);

/// The esp-rs `openthread`-shaped handle (cheap to copy).
pub struct OpenThread<'a, M: RawMutex, K, S, C: InstanceCrypto, R>(OpenTrust<'a, M, K, S, C, R>);

impl<M: RawMutex, K, S, C: InstanceCrypto, R> Clone for OpenThread<'_, M, K, S, C, R> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<M: RawMutex, K, S, C: InstanceCrypto, R> Copy for OpenThread<'_, M, K, S, C, R> {}

impl<M: RawMutex, K, S, C: InstanceCrypto, R> core::fmt::Debug for OpenThread<'_, M, K, S, C, R> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("OpenThread").finish_non_exhaustive()
    }
}

fn be64(b: &[u8; 8]) -> u64 {
    u64::from_be_bytes(*b)
}

impl<'a, M, K, S, C, R> OpenThread<'a, M, K, S, C, R>
where
    M: RawMutex,
    K: Clock,
    S: SettingsStore,
    C: InstanceCrypto,
    R: Rng + CryptoRng,
{
    /// The CSL period limit (esp-rs `CSL_MAX_PERIOD_US`).
    pub const CSL_MAX_PERIOD_US: u32 = u16::MAX as u32 * 160;

    /// A handle on `resources`.
    pub fn new(resources: &'a Resources<M, K, S, C, R>) -> Self {
        Self(OpenTrust::new(resources))
    }

    /// Like esp-rs `new_with_udp_srp`; the UDP and SRP resources are
    /// placeholders (the instance owns its sockets and SRP client).
    pub fn new_with_udp_srp<const US: usize, const UR: usize, const SS: usize, const SB: usize>(
        resources: &'a Resources<M, K, S, C, R>,
        _udp: &'a mut OtUdpResources<US, UR>,
        _srp: &'a mut OtSrpResources<SS, SB>,
    ) -> Result<Self, OtError> {
        Ok(Self::new(resources))
    }

    /// The native handle.
    pub fn opentrust(&self) -> OpenTrust<'a, M, K, S, C, R> {
        self.0
    }

    /// Run the node; see [`OpenTrust::run`] (esp-rs takes no alarm).
    pub async fn run<Rd: Radio, A: Alarm>(&self, radio: Rd, alarm: A) -> ! {
        self.0.run(radio, alarm).await
    }

    /// Wait for a state change; any number of tasks may wait.
    pub async fn wait_changed(&self) {
        self.0.wait_changed().await;
    }

    fn q<T>(&self, f: impl FnOnce(&mut Instance<S, C, R>) -> T) -> T {
        self.0.with(|i, _| f(i))
    }

    /// The EUI-64.
    pub fn ieee_eui64(&self) -> [u8; 8] {
        self.q(|i| i.ext_address().0)
    }

    /// The extended address.
    pub fn ext_address(&self) -> u64 {
        be64(&self.ieee_eui64())
    }

    /// Role, extended PAN ID and IPv6 state.
    pub fn net_status(&self) -> NetStatus {
        self.0.with(|i, now| NetStatus {
            role: i.role().into(),
            ext_pan_id: i
                .active_dataset(now)
                .and_then(|d| d.tlvs().ext_pan_id().ok())
                .map(|x| be64(&x.0)),
            ip6_enabled: i.ip6_enabled(),
        })
    }

    /// An Active Dataset is present.
    pub fn is_commissioned(&self) -> bool {
        self.0.with(|i, now| i.active_dataset(now).is_some())
    }

    /// The channel of the MAC.
    pub fn channel(&self) -> u8 {
        self.q(|i| i.mac().channel())
    }

    /// The role.
    pub fn device_role(&self) -> DeviceRole {
        self.0.role().into()
    }

    /// The receiver is on when idle.
    pub fn rx_on_when_idle(&self) -> bool {
        self.q(|i| i.link_mode().rx_on_when_idle())
    }

    /// Call `f` with the network name of the Active Dataset (empty if none).
    pub fn network_name<T>(&self, f: impl FnOnce(&str) -> T) -> T {
        let name = self.0.with(|i, now| {
            i.active_dataset(now)
                .and_then(|d| d.tlvs().network_name().ok())
        });
        f(name.as_ref().map_or("", |n| n.as_str()))
    }

    /// The PAN ID.
    pub fn pan_id(&self) -> u16 {
        self.q(|i| i.mac().pan_id().0)
    }

    /// The Mesh-Local Prefix (zero without an Active Dataset).
    pub fn mesh_local_prefix(&self) -> [u8; 8] {
        self.0.with(|i, now| {
            i.active_dataset(now)
                .and_then(|d| d.tlvs().mesh_local_prefix().ok())
                .map_or([0; 8], |p| p.0)
        })
    }

    /// The partition ID.
    pub fn partition_id(&self) -> u32 {
        self.q(|i| i.partition_id())
    }

    /// The leader weight.
    pub fn leader_weight(&self) -> u8 {
        self.q(|i| i.leader_data().weighting)
    }

    /// The Network Data version.
    pub fn net_data_version(&self) -> u8 {
        self.q(|i| i.leader_data().data_version)
    }

    /// The stable Network Data version.
    pub fn net_data_stable_version(&self) -> u8 {
        self.q(|i| i.leader_data().stable_data_version)
    }

    /// The router ID of the leader.
    pub fn leader_router_id(&self) -> u8 {
        self.q(|i| i.leader_data().leader_router_id)
    }

    /// The RLOC16.
    pub fn rloc16(&self) -> u16 {
        self.0.rloc16().0
    }

    /// The channels this device supports (2.4 GHz, 11 to 26).
    pub fn supported_channel_mask(&self) -> u32 {
        opentrust_meshcop::tlv::PAGE0_CHANNELS
    }

    /// Call `f` for every neighbor.
    pub fn neighbor_table<F: FnMut(&NeighborInfo)>(&self, mut f: F) {
        let t = self.q(|i| i.neighbor_table());
        for n in &t {
            f(&NeighborInfo {
                ext_address: be64(&n.ext.0),
                age: 0,
                rloc16: n.rloc16.0,
                link_frame_counter: 0,
                mle_frame_counter: 0,
                link_quality_in: n.link_quality_in,
                average_rssi: Some(n.average_rssi),
                last_rssi: None,
                frame_error_rate: 0,
                message_error_rate: 0,
                rx_on_when_idle: n.rx_on_when_idle,
                full_thread_device: n.full_thread_device,
                full_network_data: n.full_thread_device,
                is_child: n.is_child,
            });
        }
    }

    /// Call `f` for every router table entry (FTD).
    #[cfg(feature = "ftd")]
    pub fn route_table<F: FnMut(&RouteInfo)>(&self, mut f: F) {
        let t = self.q(|i| i.route_table());
        for r in &t {
            f(&RouteInfo {
                ext_address: 0,
                rloc16: r.rloc16.0,
                router_id: r.router_id,
                next_hop: r.next_hop.unwrap_or(63),
                path_cost: r.cost,
                lqi_in: 0,
                lqi_out: 0,
                age: 0,
                allocated: true,
                link_established: r.is_neighbor,
            });
        }
    }

    /// The device is router eligible (FTD).
    #[cfg(feature = "ftd")]
    pub fn router_eligible(&self) -> bool {
        self.q(|i| i.mle().is_router_eligible())
    }

    /// The MAC counters.
    pub fn mac_counters(&self) -> MacCounters {
        let c = self.q(|i| *i.mac_counters());
        MacCounters {
            tx_total: c.tx_total,
            tx_ack_requested: c.tx_ack_requested,
            tx_acked: c.tx_acked,
            tx_data: c.tx_data,
            tx_data_poll: c.tx_data_poll,
            tx_beacon: c.tx_beacon,
            tx_beacon_request: c.tx_beacon_request,
            tx_retry: c.tx_retry,
            tx_direct_max_retry_expiry: c.tx_direct_max_retry_expiry,
            tx_indirect_max_retry_expiry: c.tx_indirect_max_retry_expiry,
            tx_err_cca: c.tx_err_cca,
            tx_err_abort: c.tx_err_abort,
            rx_total: c.rx_total,
            rx_data: c.rx_data,
            rx_data_poll: c.rx_data_poll,
            rx_beacon: c.rx_beacon,
            rx_beacon_request: c.rx_beacon_request,
            rx_other: c.rx_other,
            rx_dest_addr_filtered: c.rx_dest_addr_filtered,
            rx_err_no_frame: c.rx_err_no_frame,
            rx_err_unknown_neighbor: c.rx_err_unknown_neighbor,
            rx_err_invalid_src_addr: c.rx_err_invalid_src_addr,
            rx_err_sec: c.rx_err_sec,
            ..MacCounters::default()
        }
    }

    /// The MLE counters (all zero).
    pub fn mle_counters(&self) -> MleCounters {
        MleCounters::default()
    }

    /// The IPv6 counters (all zero).
    pub fn ip_counters(&self) -> IpCounters {
        IpCounters::default()
    }

    /// Milliseconds on the node's clock.
    pub fn uptime_millis(&self) -> u64 {
        self.0.now().as_micros() / 1000
    }

    /// Call `f` for every unicast address with its prefix length; `f` is
    /// called with `None` at the end.
    pub fn ipv6_addrs<F>(&self, mut f: F) -> Result<(), OtError>
    where
        F: FnMut(Option<(Ipv6Addr, u8)>) -> Result<(), OtError>,
    {
        let addrs: heapless::Vec<(Ipv6Addr, u8), 16> = self.q(|i| {
            i.unicast_addresses()
                .map(|a| (a.addr, a.prefix_len))
                .take(16)
                .collect()
        });
        for a in addrs {
            f(Some(a))?;
        }
        f(None)
    }

    /// Enable or disable the IPv6 interface.
    pub fn enable_ipv6(&self, enable: bool) -> Result<(), OtError> {
        self.0.with(|i, _| i.ip6_set_enabled(enable));
        Ok(())
    }

    /// Subscribe to a multicast address.
    pub fn join_multicast(&self, addr: Ipv6Addr) -> Result<(), OtError> {
        Ok(self.0.join_multicast(addr)?)
    }

    /// Leave a multicast address.
    pub fn leave_multicast(&self, addr: Ipv6Addr) -> Result<(), OtError> {
        Ok(self.0.leave_multicast(addr)?)
    }

    /// Start or stop Thread.
    pub fn enable_thread(&self, enable: bool) -> Result<(), OtError> {
        if enable {
            Ok(self.0.with(|i, now| i.thread_start(now))?)
        } else {
            self.0.thread_stop();
            Ok(())
        }
    }

    /// Set the Active Dataset from its TLVs.
    pub fn set_active_dataset_tlv(&self, tlv: &[u8]) -> Result<(), OtError> {
        let ds = Dataset::from_tlvs(tlv)?;
        Ok(self.0.set_active_dataset(&ds)?)
    }

    /// Set the Pending Dataset from its TLVs.
    pub fn set_pending_dataset_tlv(&self, tlv: &[u8]) -> Result<(), OtError> {
        let ds = Dataset::from_tlvs(tlv)?;
        Ok(self.0.with(|i, now| i.set_pending_dataset(&ds, now))?)
    }

    /// Set the device mode.
    pub fn set_link_mode(
        &self,
        rx_on_when_idle: bool,
        full_thread_device: bool,
        receive_full_network_data: bool,
    ) -> Result<(), OtError> {
        let mode = DeviceMode::new(
            rx_on_when_idle,
            full_thread_device,
            receive_full_network_data,
        );
        Ok(self.0.with(|i, now| i.set_link_mode(mode, now))?)
    }

    /// Set the data poll period in milliseconds (0: default).
    pub fn set_poll_period(&self, period_millis: u32) -> Result<(), OtError> {
        self.0.with(|i, _| {
            i.set_poll_period(
                (period_millis != 0).then(|| Duration::from_millis(u64::from(period_millis))),
            );
        });
        Ok(())
    }

    /// Not supported by the instance ([`Error::NotImplemented`]).
    pub fn set_csl_period(&self, _period_micros: u32) -> Result<(), OtError> {
        Err(Error::NotImplemented.into())
    }

    /// Not supported by the instance (no effect).
    pub fn set_child_timeout(&self, _timeout_secs: u32) {}

    /// Not supported by the instance (no effect).
    pub fn set_child_supervision_interval(&self, _interval_secs: u16) {}

    /// Not supported by the instance (no effect).
    pub fn set_child_supervision_check_timeout(&self, _timeout_secs: u16) {}

    /// Scan for Thread networks (MLE discovery); `duration_millis` is
    /// ignored. `f` is called with each result and finally with `None`.
    pub async fn scan<F>(
        &self,
        channels: Channels,
        _duration_millis: u16,
        mut f: F,
    ) -> Result<(), OtError>
    where
        F: FnMut(Option<&ScanResult<'_>>),
    {
        self.0
            .scan(channels.bits(), |r| match r {
                Some(r) => {
                    let name = r.network_name;
                    f(Some(&ScanResult {
                        ext_address: be64(&r.ext_address.0),
                        network_name: name.as_ref().map_or("", |n| n.as_str()),
                        extended_pan_id: r.ext_pan_id.map_or(0, |x| be64(&x.0)),
                        steering_data: r.steering_data.as_ref().map_or(&[], |s| s.as_bytes()),
                        pan_id: r.pan_id,
                        joiner_udp_port: r.joiner_udp_port.unwrap_or(0),
                        channel: r.channel,
                        rssi: r.rssi,
                        lqi: r.lqi,
                        version: r.version,
                        native_commissioner: r.is_native,
                        discover: true,
                    }));
                }
                None => f(None),
            })
            .await?;
        Ok(())
    }

    /// Energy scan; `f` is called per channel and finally with `None`.
    pub async fn energy_scan<F>(
        &self,
        channels: Channels,
        duration_millis: u16,
        mut f: F,
    ) -> Result<(), OtError>
    where
        F: FnMut(Option<&EnergyScanResult>),
    {
        self.0
            .energy_scan(
                channels.bits(),
                Duration::from_millis(u64::from(duration_millis)),
                |channel, max_rssi| f(Some(&EnergyScanResult { channel, max_rssi })),
            )
            .await?;
        f(None);
        Ok(())
    }

    // -------------------------------------------------------------- SRP

    /// Set the SRP host name and addresses.
    pub fn srp_set_conf(&self, conf: &SrpConf<'_>) -> Result<(), OtError> {
        self.0.with(|i, now| {
            i.srp_set_host_name(conf.host_name, now)?;
            if conf.host_addrs.is_empty() {
                i.srp_enable_auto_host_address(now)
            } else {
                i.srp_set_host_addresses(conf.host_addrs, now)
            }
        })?;
        Ok(())
    }

    /// Start the SRP client with the server found in the Network Data.
    pub fn srp_autostart(&self) -> Result<(), OtError> {
        self.0.with(|i, now| i.srp_enable_auto_start(now));
        Ok(())
    }

    /// Start the SRP client with an explicit server.
    pub fn srp_start(&self, server_addr: SocketAddrV6) -> Result<(), OtError> {
        Ok(self.0.with(|i, now| i.srp_start(server_addr, now))?)
    }

    /// Stop the SRP client.
    pub fn srp_stop(&self) {
        self.0.with(|i, now| i.srp_stop(now));
    }

    /// The SRP client runs.
    pub fn srp_running(&self) -> Result<bool, OtError> {
        Ok(self.q(|i| i.srp_is_running()))
    }

    /// The SRP server in use.
    pub fn srp_server_addr(&self) -> Result<Option<SocketAddrV6>, OtError> {
        Ok(self.q(|i| i.srp_server()))
    }

    /// Register a service.
    pub fn srp_add_service<'s, SI, TI>(
        &self,
        service: &SrpService<'s, SI, TI>,
    ) -> Result<SrpServiceSlot, OtError>
    where
        TI: Iterator<Item = (&'s str, &'s [u8])> + Clone,
    {
        let mut cfg = ServiceConfig::new(service.name, service.instance_name, service.port)?;
        cfg.priority = service.priority;
        cfg.weight = service.weight;
        cfg.lease = service.lease_secs;
        cfg.key_lease = service.key_lease_secs;
        let entries: heapless::Vec<TxtEntry<'_>, 16> = service
            .txt_entries
            .clone()
            .map(|(k, v)| TxtEntry {
                key: k.as_bytes(),
                value: Some(v),
            })
            .take(16)
            .collect();
        cfg.set_txt_entries(&entries)?;
        let id = self.0.with(|i, now| i.srp_add_service(cfg, now))?;
        Ok(SrpServiceSlot(id))
    }

    /// Remove a service (`immediate` is ignored: the removal is sent).
    pub fn srp_remove_service(&self, slot: SrpServiceSlot, _immediate: bool) {
        let _ = self.0.with(|i, now| i.srp_remove_service(slot.0, now));
    }

    /// Remove the host and all services.
    pub fn srp_remove_all(&self, immediate: bool) {
        let _ = self
            .0
            .with(|i, now| i.srp_remove_host_and_services(immediate, true, now));
    }

    /// Wait until the SRP host registration changes to registered.
    pub async fn srp_wait_changed(&self) {
        self.0.wait_changed().await;
    }

    /// Whether the SRP host is registered.
    pub fn srp_host_registered(&self) -> bool {
        self.q(|i| i.srp_host_state() == ItemState::Registered)
    }
}
