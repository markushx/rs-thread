//! [`Core`]: every layer of the stack except the MLE state machine (and the
//! TMF agent and Network Data leader store), so that [`MleEnv`] and
//! [`DatasetEnv`] can be implemented on disjoint borrows of the instance
//! without `RefCell`.

use core::net::Ipv6Addr;

use heapless::{Deque, Vec};
use opentrust_coap::tmf::UdpSink;
use opentrust_core::bufpool::{BufPool, Chain};
use opentrust_core::crypto::CryptoBackend;
use opentrust_core::settings::{ChildInfo, NetworkInfo, ParentInfo, SettingsKey};
use opentrust_core::time::{Duration, Instant};
use opentrust_core::types::{
    ExtAddress, ExtPanId, Iid, NetworkName, PanId, Prefix64, Pskc, Rloc16,
};
use opentrust_core::{Error, Result};
use opentrust_mac::frame::Address;
use opentrust_mac::mac::Mac;
use opentrust_mac::security::KeyManager;
use opentrust_mesh::netdata::NetworkData as NetData;
use opentrust_meshcop::dataset::DatasetType;
use opentrust_meshcop::manager::{
    Configuration, CurrentConfig, DatasetEnv, DatasetEvent, Datasets,
};
use opentrust_meshcop::tlv::SecurityPolicy;
use opentrust_mle::Role;
use opentrust_mle::env::{
    DiscoveryRequestInfo, DiscoveryResponseInfo, MAX_REGISTERED_ADDRESSES, MleEnv, MleEvent,
    RouterIdRequest, StoredDataset, TxOptions,
};
use opentrust_mle::tlv::{LeaderData, Timestamp};
use opentrust_net::ip6::{Ip6, SendInfo};
use opentrust_net::netif::AddressOrigin;
use opentrust_platform::SettingsStore;
use rand_core::Rng;

/// Capacity of the child table (router role).
pub const CHILDREN: usize = 8;

/// UDP sockets of the application.
pub const UDP_SOCKETS: usize = 5;

/// Network Data capacity in bytes.
pub const NETDATA_LEN: usize = 512;

/// The MAC with the key manager as its frame security.
pub type StackMac<C> = Mac<KeyManager<C>, MacRng>;

/// Backoff randomness of the MAC (non-cryptographic xorshift64*, seeded
/// from the instance's RNG).
#[derive(Debug, Clone)]
pub struct MacRng(u64);

impl MacRng {
    pub(crate) fn new(seed: u64) -> Self {
        Self(seed | 1)
    }
}

/// Unit tests of this crate use it as the instance RNG.
#[cfg(test)]
impl rand_core::TryCryptoRng for MacRng {}

impl rand_core::TryRng for MacRng {
    type Error = core::convert::Infallible;
    fn try_next_u32(&mut self) -> core::result::Result<u32, Self::Error> {
        Ok((self.try_next_u64()? >> 32) as u32)
    }
    fn try_next_u64(&mut self) -> core::result::Result<u64, Self::Error> {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        Ok(self.0.wrapping_mul(0x2545_F491_4F6C_DD1D))
    }
    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> core::result::Result<(), Self::Error> {
        for chunk in dst.chunks_mut(8) {
            let v = self.try_next_u64()?.to_le_bytes();
            chunk.copy_from_slice(&v[..chunk.len()]);
        }
        Ok(())
    }
}

/// An outgoing UDP datagram queued for the IPv6 layer; the payload lives in
/// the pool of its [`Outbox`].
#[derive(Debug, Clone)]
pub struct Outgoing {
    /// Addressing and options.
    pub info: SendInfo,
    /// UDP source port.
    pub src_port: u16,
    /// UDP destination port.
    pub dst_port: u16,
    chain: Chain,
    /// Link-layer security of the frames instead of the one of `info`
    /// (key ID mode 0 for the Joiner Entrust, mode 2 for MLE Announce).
    pub security: Option<opentrust_core::types::LinkSecurity>,
    /// Channel and PAN ID to send the frames with.
    pub tx: (Option<u8>, Option<u16>),
}

/// Buffers of a queue payload pool (OpenThread message buffer size).
pub(crate) const OUTBOX_BUF: usize = 128;

/// Bounded queue of outgoing UDP datagrams (TMF, MLE, application). The
/// payloads are chains of [`OUTBOX_BUF`]-byte buffers from a pool of
/// `BLOCKS` buffers; a datagram that does not fit is refused with `NoBufs`.
#[derive(Debug, Default)]
pub struct Outbox<const BLOCKS: usize = 16> {
    q: Deque<Outgoing, 6>,
    pool: BufPool<BLOCKS, OUTBOX_BUF>,
}

impl<const BLOCKS: usize> Outbox<BLOCKS> {
    pub(crate) fn push(
        &mut self,
        info: SendInfo,
        src_port: u16,
        dst_port: u16,
        payload: &[u8],
    ) -> Result<()> {
        if self.q.is_full() {
            return Err(Error::NoBufs);
        }
        let chain = self.pool.alloc(payload)?;
        let _ = self.q.push_back(Outgoing {
            info,
            src_port,
            dst_port,
            chain,
            tx: (None, None),
            security: None,
        });
        Ok(())
    }

    pub(crate) fn len(&self) -> usize {
        self.q.len()
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.q.is_empty()
    }

    /// The most recently queued datagram.
    pub(crate) fn back_mut(&mut self) -> Option<&mut Outgoing> {
        self.q.back_mut()
    }

    /// Take the oldest datagram, copying its payload to the start of `buf`
    /// (the length is returned).
    pub(crate) fn pop_front(&mut self, buf: &mut [u8]) -> Option<(Outgoing, usize)> {
        let o = self.q.pop_front()?;
        let n = self.pool.read(&o.chain, buf);
        self.pool.free(o.chain);
        Some((o, n))
    }
}

impl<const BLOCKS: usize> UdpSink for Outbox<BLOCKS> {
    fn send(
        &mut self,
        info: &SendInfo,
        src_port: u16,
        dst_port: u16,
        payload: &[u8],
    ) -> Result<()> {
        self.push(*info, src_port, dst_port, payload)
    }
}

/// A router ID request or release MLE queued for the TMF client.
#[derive(Debug, Clone, Copy)]
#[cfg_attr(not(feature = "ftd"), allow(dead_code))]
pub(crate) enum SolicitCmd {
    Request(RouterIdRequest),
    Release(Rloc16),
}

/// Frames waiting for room in the MAC's transmit queue (the forwarder
/// hands over all fragments of a datagram at once, the MAC queues four).
#[derive(Debug, Default)]
pub struct MacTx {
    pub(crate) handle: u16,
    pub(crate) pending: Deque<(opentrust_mac::mac::FrameBuf, Option<u8>), 32>,
    /// Channel and PAN ID of the datagram being sent (MLE Discovery and
    /// Announce), `None`: the PAN's.
    pub(crate) channel: Option<u8>,
    pub(crate) pan_id: Option<u16>,
}

/// Changes of the child table the data path has to follow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ChildChange {
    Added(ExtAddress, Rloc16),
    Removed(ExtAddress, Rloc16),
    Supervise(Rloc16),
}

/// Network parameters applied from the Active Dataset.
#[derive(Debug)]
pub(crate) struct NetConfig {
    pub cur: CurrentConfig,
    pub ext_pan_id: Option<ExtPanId>,
    pub network_name: Option<NetworkName>,
    pub pskc: Option<Pskc>,
    pub policy: Option<SecurityPolicy>,
    pub ds_events: Deque<DatasetEvent, 4>,
    /// Leader: a dataset changed, Network Data versions must be bumped.
    pub nd_version_bump: bool,
    /// The configuration changed (channel, PAN ID, prefix, key).
    pub applied: bool,
}

/// Everything but the MLE state machine.
pub struct Core<S, C: CryptoBackend, R> {
    pub(crate) mac: StackMac<C>,
    pub(crate) rng: R,
    pub(crate) settings: S,
    pub(crate) crypto: C,
    pub(crate) now: Instant,
    pub(crate) ext: ExtAddress,
    pub(crate) ml_iid: Iid,
    pub(crate) role: Role,
    pub(crate) ip6: Ip6,
    /// MLE messages queued for the IPv6 layer.
    pub(crate) mle_out: Outbox<8>,
    /// Network Data this node serves and uses (the leader store's copy on
    /// the leader, the copy received through MLE elsewhere).
    pub(crate) netdata: NetData<NETDATA_LEN>,
    pub(crate) datasets: Datasets,
    pub(crate) cfg: NetConfig,
    pub(crate) mle_events: Deque<MleEvent, 32>,
    pub(crate) child_changes: Deque<ChildChange, 8>,
    /// Network Data received through MLE, not yet processed.
    pub(crate) nd_rx: Option<(LeaderData, Vec<u8, NETDATA_LEN>)>,
    pub(crate) solicit: Deque<SolicitCmd, 4>,
    /// Link info of the frame being processed (RSS, LQI, channel).
    pub(crate) rx_link: opentrust_mle::endpoint::LinkRxInfo,
    /// The parent as the MAC knows it (for polling).
    pub(crate) parent: Option<(ExtAddress, Rloc16)>,
    /// Poll period MLE asked for (the default of the child timeout).
    pub(crate) poll_period: Option<Duration>,
    /// Poll period set by the application (OT `otLinkSetPollPeriod`).
    pub(crate) user_poll_period: Option<Duration>,
    pub(crate) mactx: MacTx,
    /// Frames the MLE wants sent on another channel / PAN (Discovery).
    pub(crate) events: Deque<crate::Event, 16>,
    pub(crate) iid_secret: [u8; 32],
    /// Discovery Responses for the Joiner (sub-TLVs of the Discovery TLV).
    pub(crate) disc_rx: Deque<(DiscoveryResponseInfo, Vec<u8, DISCOVERY_TLVS>), 4>,
    /// The Joiner is discovering: keep Discovery Responses.
    pub(crate) joiner_discovering: bool,
    /// Discovery Responses for the discovery scan.
    pub(crate) scan_rx: Deque<(DiscoveryResponseInfo, Vec<u8, DISCOVERY_TLVS>), 4>,
    /// A discovery scan is running: keep Discovery Responses.
    pub(crate) scanning: bool,
    /// UDP port of the Border Agent (native commissioner flag of the
    /// Discovery Response).
    pub(crate) border_agent_port: Option<u16>,
}

/// Room for the Thread Discovery TLV value of a Discovery Response.
pub(crate) const DISCOVERY_TLVS: usize = 128;

impl<S, C: CryptoBackend, R> core::fmt::Debug for Core<S, C, R> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Core")
            .field("role", &self.role)
            .field("ext", &self.ext)
            .finish_non_exhaustive()
    }
}

impl<S, C: CryptoBackend, R> Core<S, C, R> {
    pub(crate) fn push_event(&mut self, e: crate::Event) {
        if self.events.is_full() {
            // Latest wins: drop the oldest.
            let _ = self.events.pop_front();
        }
        let _ = self.events.push_back(e);
    }
}

/// [`DatasetEnv`] over the parts of [`Core`] the dataset managers touch.
pub(crate) struct DsEnv<'a, S, C: CryptoBackend> {
    pub mac: &'a mut StackMac<C>,
    pub ip6: &'a mut Ip6,
    pub settings: &'a mut S,
    pub cfg: &'a mut NetConfig,
    pub ml_iid: Iid,
    pub role: Role,
    pub session_id: Option<u16>,
}

impl<S: SettingsStore, C: CryptoBackend> DatasetEnv for DsEnv<'_, S, C> {
    fn current(&self) -> CurrentConfig {
        self.cfg.cur.clone()
    }

    fn apply(&mut self, cfg: &Configuration) -> Result<()> {
        if let Some(c) = cfg.channel {
            self.mac.set_channel(c)?;
            self.cfg.cur.channel = c;
        }
        if let Some(p) = cfg.pan_id {
            self.mac.set_pan_id(PanId(p));
            self.cfg.cur.pan_id = p;
        }
        if let Some(e) = cfg.ext_pan_id {
            self.cfg.ext_pan_id = Some(e);
        }
        if let Some(n) = &cfg.network_name {
            self.cfg.network_name = Some(*n);
        }
        if let Some(k) = &cfg.network_key {
            self.mac.security_mut().set_network_key(k.clone());
            self.cfg.cur.network_key = k.clone();
        }
        if let Some(p) = &cfg.pskc {
            self.cfg.pskc = Some(p.clone());
        }
        if let Some(m) = &cfg.mesh_local_prefix {
            self.ip6.netif.set_mesh_local_prefix(*m)?;
            self.ip6.netif.set_mesh_local_eid(&self.ml_iid)?;
            self.cfg.cur.mesh_local_prefix = *m;
        }
        if let Some(p) = cfg.security_policy {
            self.mac
                .security_mut()
                .set_key_rotation_hours(p.rotation_time);
            self.cfg.policy = Some(p);
        }
        self.cfg.applied = true;
        Ok(())
    }

    fn role(&self) -> Role {
        self.role
    }

    fn store(&mut self, ty: DatasetType, tlvs: &[u8]) -> Result<()> {
        self.settings.set(settings_key(ty), tlvs)
    }

    fn load(&self, ty: DatasetType, out: &mut [u8]) -> Option<usize> {
        self.settings.get(settings_key(ty), 0, out).ok()
    }

    fn delete(&mut self, ty: DatasetType) {
        let _ = self.settings.delete(settings_key(ty), None);
    }

    fn event(&mut self, event: DatasetEvent) {
        if self.cfg.ds_events.is_full() {
            let _ = self.cfg.ds_events.pop_front();
        }
        let _ = self.cfg.ds_events.push_back(event);
    }

    fn commissioning_session_id(&self) -> Option<u16> {
        self.session_id
    }

    fn network_data_changed(&mut self) {
        self.cfg.nd_version_bump = true;
    }
}

fn settings_key(ty: DatasetType) -> SettingsKey {
    match ty {
        DatasetType::Active => SettingsKey::ActiveDataset,
        DatasetType::Pending => SettingsKey::PendingDataset,
    }
}

impl<S: SettingsStore, C: CryptoBackend, R: Rng> Core<S, C, R> {
    /// Split borrow of the dataset managers and their environment.
    pub(crate) fn ds(&mut self) -> (&mut Datasets, DsEnv<'_, S, C>) {
        (
            &mut self.datasets,
            DsEnv {
                mac: &mut self.mac,
                ip6: &mut self.ip6,
                settings: &mut self.settings,
                cfg: &mut self.cfg,
                ml_iid: self.ml_iid,
                role: self.role,
                session_id: None,
            },
        )
    }

    /// The effective poll period: the shorter of MLE's and the
    /// application's.
    pub(crate) fn apply_poll_period(&mut self) {
        let period = match (self.poll_period, self.user_poll_period) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, _) => a,
        };
        match (period, self.parent) {
            (Some(p), Some((_, r))) => {
                self.mac.set_poll_period(p, self.now);
                self.mac.start_polling(Address::Short(r.into()), self.now);
            }
            _ => self.mac.stop_polling(),
        }
    }

    /// The ML-EID address.
    pub(crate) fn ml_eid_addr(&self) -> Ipv6Addr {
        self.cfg.cur.mesh_local_prefix.with_iid(&self.ml_iid)
    }
}

impl<S: SettingsStore, C: CryptoBackend, R: Rng> MleEnv for Core<S, C, R> {
    type Crypto = C;

    fn keys(&self) -> &KeyManager<C> {
        self.mac.security()
    }

    fn keys_mut(&mut self) -> &mut KeyManager<C> {
        self.mac.security_mut()
    }

    fn ext_address(&self) -> ExtAddress {
        self.ext
    }

    fn fill_random(&mut self, buf: &mut [u8]) {
        self.rng.fill_bytes(buf);
    }

    fn send(&mut self, src: Ipv6Addr, dst: Ipv6Addr, payload: &[u8]) -> Result<()> {
        self.send_with(&TxOptions::default(), src, dst, payload)
    }

    fn send_with(
        &mut self,
        opts: &TxOptions,
        src: Ipv6Addr,
        dst: Ipv6Addr,
        payload: &[u8],
    ) -> Result<()> {
        let info = SendInfo {
            src: Some(src),
            dst,
            hop_limit: opentrust_mle::consts::MLE_HOP_LIMIT,
            dscp: 0,
            ecn: 0,
            multicast_loop: false,
            link_security: opts.link_security,
        };
        self.mle_out.push(
            info,
            opentrust_net::udp::MLE_UDP_PORT,
            opentrust_net::udp::MLE_UDP_PORT,
            payload,
        )?;
        if let Some(o) = self.mle_out.back_mut() {
            o.tx = (opts.channel, opts.pan_id);
            // The only link-secured MLE message with options is the Announce,
            // which OT sends with key ID mode 2 (receivers on another key).
            if opts.link_security {
                o.info.link_security = false;
                o.security = Some(opentrust_core::types::LinkSecurity::Mode2);
            }
        }
        Ok(())
    }

    fn pan_id(&self) -> u16 {
        self.mac.pan_id().0
    }

    fn pan_channel(&self) -> u8 {
        self.mac.channel()
    }

    fn set_pan_channel_and_id(&mut self, channel: u8, pan_id: u16) {
        let _ = self.mac.set_channel(channel);
        self.mac.set_pan_id(PanId(pan_id));
        self.cfg.cur.channel = channel;
        self.cfg.cur.pan_id = pan_id;
    }

    fn ext_pan_id(&self) -> Option<ExtPanId> {
        self.cfg.ext_pan_id
    }

    fn set_short_address(&mut self, rloc16: Rloc16) {
        self.mac.set_short_address(rloc16.into());
    }

    fn set_alternate_short_address(&mut self, rloc16: Option<Rloc16>) {
        self.mac.set_alternate_short_address(rloc16.map(Into::into));
    }

    fn set_rx_on_when_idle(&mut self, on: bool) {
        self.mac.set_rx_on_when_idle(on);
    }

    fn set_parent(&mut self, parent: Option<(ExtAddress, Rloc16)>) {
        if let Some((e, r)) = parent {
            let _ = self.mac.set_neighbor(r.into(), e);
        }
        self.parent = parent;
        if parent.is_none() {
            self.mac.stop_polling();
        }
    }

    fn set_csl(&mut self, period: u16, channel: u8, parent: Option<(ExtAddress, Rloc16)>) {
        let (short, ext) = parent.map_or((Rloc16::INVALID.into(), ExtAddress([0; 8])), |(e, r)| {
            (r.into(), e)
        });
        // A radio without a clock cannot sample CSL windows: the child then
        // keeps polling.
        let _ = self.mac.set_csl(period, channel, short, ext, self.now);
    }

    fn set_csl_parent_accuracy(&mut self, a: opentrust_mle::tlv::CslClockAccuracy) {
        self.mac
            .set_csl_parent_accuracy(opentrust_mac::mac::CslAccuracy {
                clock_ppm: a.accuracy_ppm,
                uncertainty_10us: a.uncertainty_10us,
            });
    }

    fn csl_clock_accuracy(&self) -> Option<opentrust_mle::tlv::CslClockAccuracy> {
        let caps = self.mac.caps();
        caps.clock
            .is_some()
            .then_some(opentrust_mle::tlv::CslClockAccuracy {
                accuracy_ppm: caps.csl_accuracy_ppm,
                uncertainty_10us: caps.csl_uncertainty,
            })
    }

    fn csl_child_update(&mut self, _ext: &ExtAddress, rloc16: Rloc16, channel: u8) {
        let a = Address::Short(rloc16.into());
        if self.mac.csl_add_child(a).is_ok() {
            let _ = self.mac.csl_set_child_channel(a, channel);
        }
    }

    fn csl_child_desync(&mut self, _ext: &ExtAddress, rloc16: Rloc16) {
        self.mac.csl_child_desync(Address::Short(rloc16.into()));
    }

    fn enh_ack_probing_report(
        &mut self,
        rloc16: Rloc16,
        ext: &ExtAddress,
        v: &opentrust_mle::link_metrics::MetricsValues,
    ) {
        self.push_event(crate::Event::EnhAckLinkMetrics {
            rloc16,
            ext: *ext,
            lqi: v.metrics.lqi.then_some(v.lqi),
            link_margin: v.metrics.link_margin.then_some(v.link_margin),
            rssi: v.metrics.rssi.then_some(v.rssi),
        });
    }

    fn configure_enh_ack_probing(
        &mut self,
        flags: opentrust_mac::mac::LinkMetricsFlags,
        rloc16: Rloc16,
        ext: &ExtAddress,
    ) -> Result<()> {
        self.mac
            .configure_enh_ack_probing(rloc16.into(), *ext, flags)
    }

    fn set_poll_attach_mode(&mut self, fast: bool) {
        self.mac.set_poll_attach_mode(fast, self.now);
    }

    fn send_fast_polls(&mut self) {
        self.mac.send_fast_polls(0, self.now);
    }

    fn set_poll_period(&mut self, period: Option<Duration>) {
        self.poll_period = period;
        self.apply_poll_period();
    }

    fn mesh_local_prefix(&self) -> Prefix64 {
        self.cfg.cur.mesh_local_prefix
    }

    fn ml_eid(&self) -> Ipv6Addr {
        self.ml_eid_addr()
    }

    fn registered_addresses(&self, f: &mut dyn FnMut(Ipv6Addr)) {
        let ml_eid = self.ml_eid_addr();
        let mut n = 0;
        for a in self.ip6.netif.unicast_addresses() {
            if n >= MAX_REGISTERED_ADDRESSES {
                break;
            }
            if a.rloc
                || !a.valid
                || a.addr == ml_eid
                || a.addr.is_unicast_link_local()
                || (a.origin == AddressOrigin::Thread
                    && (opentrust_net::addr::is_anycast_locator(
                        &a.addr,
                        &self.cfg.cur.mesh_local_prefix,
                    ) || opentrust_net::addr::is_routing_locator(
                        &a.addr,
                        &self.cfg.cur.mesh_local_prefix,
                    )))
            {
                continue;
            }
            n += 1;
            f(a.addr);
        }
    }

    fn registered_multicast_addresses(&self, f: &mut dyn FnMut(Ipv6Addr)) {
        use opentrust_net::netif::MulticastKind;
        let _ = MulticastKind::External;
        for a in self.ip6.netif.external_multicast_addresses() {
            f(a);
        }
    }

    fn lowpan_context(&self, context_id: u8) -> Option<Prefix64> {
        let view = self.netdata.view();
        opentrust_mesh::netdata::consumers::context_prefix64(&view, context_id)
    }

    fn lowpan_context_for(&self, addr: &Ipv6Addr) -> Option<u8> {
        let view = self.netdata.view();
        opentrust_mesh::netdata::consumers::context_id_for(&view, addr)
    }

    fn indirect_add_child(&mut self, ext: &ExtAddress, rloc16: Rloc16) {
        let _ = self
            .child_changes
            .push_back(ChildChange::Added(*ext, rloc16));
    }

    fn indirect_remove_child(&mut self, ext: &ExtAddress, rloc16: Rloc16) {
        let _ = self
            .child_changes
            .push_back(ChildChange::Removed(*ext, rloc16));
    }

    fn send_child_supervision(&mut self, _ext: &ExtAddress, rloc16: Rloc16) {
        let _ = self.child_changes.push_back(ChildChange::Supervise(rloc16));
    }

    fn network_data(&self, stable_only: bool, out: &mut [u8]) -> Result<usize> {
        if stable_only {
            self.netdata.copy_stable(out)
        } else {
            let d = self.netdata.as_bytes();
            out.get_mut(..d.len())
                .ok_or(Error::NoBufs)?
                .copy_from_slice(d);
            Ok(d.len())
        }
    }

    fn set_network_data(&mut self, leader: &LeaderData, data: &[u8]) {
        if let Ok(v) = Vec::from_slice(data) {
            self.nd_rx = Some((*leader, v));
        }
    }

    fn active_timestamp(&self) -> Option<Timestamp> {
        self.datasets.timestamp(DatasetType::Active)
    }

    fn pending_timestamp(&self) -> Option<Timestamp> {
        self.datasets.timestamp(DatasetType::Pending)
    }

    fn active_dataset(&self, now: Instant, out: &mut [u8]) -> Result<usize> {
        self.datasets.mle_dataset(DatasetType::Active, now, out)
    }

    fn pending_dataset(&self, now: Instant, out: &mut [u8]) -> Result<usize> {
        self.datasets.mle_dataset(DatasetType::Pending, now, out)
    }

    fn restore_dataset(&mut self, now: Instant, which: StoredDataset) -> bool {
        let t = match which {
            StoredDataset::Active => DatasetType::Active,
            StoredDataset::Pending => DatasetType::Pending,
        };
        let (ds, mut env) = self.ds();
        ds.restore(&mut env, now, t).is_ok()
    }

    fn apply_pending_configuration(&mut self, now: Instant) {
        let (ds, mut env) = self.ds();
        if let Some(d) = ds.read(DatasetType::Pending, now) {
            let _ = env.apply(&Configuration::from_dataset(&d));
        }
    }

    fn clear_pending_dataset(&mut self, _now: Instant) {
        let (ds, mut env) = self.ds();
        ds.clear(&mut env, DatasetType::Pending);
    }

    fn dataset_received(
        &mut self,
        now: Instant,
        active: Option<(Timestamp, Option<&[u8]>)>,
        pending: Option<(Timestamp, Option<&[u8]>)>,
    ) {
        let (ds, mut env) = self.ds();
        ds.dataset_received(&mut env, now, active, pending);
    }

    fn accept_discovery_request(&mut self, info: &DiscoveryRequestInfo) -> bool {
        // OT `IsJoiningAllowed`: a Joiner is answered only while the
        // Commissioning Data has non-empty Steering Data.
        !info.joiner
            || opentrust_meshcop::discovery::joining_allowed(
                self.netdata.view().commissioning_data(),
            )
    }

    fn discovery_response(&mut self, out: &mut [u8]) -> Result<usize> {
        let active = self
            .datasets
            .read(DatasetType::Active, self.now)
            .ok_or(Error::InvalidState)?;
        opentrust_meshcop::discovery::build_response_with_border_agent(
            &active,
            self.netdata.view().commissioning_data(),
            self.border_agent_port,
            out,
        )
    }

    fn discovery_response_received(&mut self, info: &DiscoveryResponseInfo, tlvs: &[u8]) {
        if self.scanning
            && let Ok(v) = Vec::from_slice(tlvs)
        {
            if self.scan_rx.is_full() {
                let _ = self.scan_rx.pop_front();
            }
            let _ = self.scan_rx.push_back((*info, v));
        }
        // For the Joiner (only while one is discovering).
        if self.joiner_discovering
            && let Ok(v) = Vec::from_slice(tlvs)
        {
            if self.disc_rx.is_full() {
                let _ = self.disc_rx.pop_front();
            }
            let _ = self.disc_rx.push_back((*info, v));
        }
    }

    fn apply_restored_identity(&mut self, ext: &ExtAddress, ml_iid: &Iid) {
        self.ext = *ext;
        self.mac.set_ext_address(*ext);
        self.ml_iid = *ml_iid;
        let _ = self.ip6.netif.set_link_local(ext);
        let _ = self.ip6.netif.set_mesh_local_eid(ml_iid);
    }

    fn store_network_info(&mut self, info: &NetworkInfo) -> Result<()> {
        let mut b = [0u8; NetworkInfo::ENCODED_LEN];
        let n = info.encode(&mut b)?;
        self.settings.set(SettingsKey::NetworkInfo, &b[..n])
    }

    fn load_network_info(&self) -> Option<NetworkInfo> {
        let mut b = [0u8; NetworkInfo::ENCODED_LEN];
        self.settings
            .get(SettingsKey::NetworkInfo, 0, &mut b)
            .ok()?;
        NetworkInfo::decode(&b).ok()
    }

    fn store_parent_info(&mut self, info: Option<&ParentInfo>) -> Result<()> {
        match info {
            Some(i) => {
                let mut b = [0u8; ParentInfo::ENCODED_LEN];
                let n = i.encode(&mut b)?;
                self.settings.set(SettingsKey::ParentInfo, &b[..n])
            }
            None => {
                let _ = self.settings.delete(SettingsKey::ParentInfo, None);
                Ok(())
            }
        }
    }

    fn load_parent_info(&self) -> Option<ParentInfo> {
        let mut b = [0u8; ParentInfo::ENCODED_LEN];
        self.settings.get(SettingsKey::ParentInfo, 0, &mut b).ok()?;
        ParentInfo::decode(&b).ok()
    }

    fn store_child_info(&mut self, info: &ChildInfo) -> Result<()> {
        let _ = self.delete_child_info(&info.ext_address);
        let mut b = [0u8; ChildInfo::ENCODED_LEN];
        let n = info.encode(&mut b)?;
        self.settings.add(SettingsKey::ChildInfo, &b[..n])
    }

    fn delete_child_info(&mut self, ext: &ExtAddress) -> Result<()> {
        for i in 0..self.settings.count(SettingsKey::ChildInfo) {
            if self
                .load_child_info(i)
                .is_some_and(|c| c.ext_address == *ext)
            {
                return self.settings.delete(SettingsKey::ChildInfo, Some(i));
            }
        }
        Err(Error::NotFound)
    }

    fn clear_child_infos(&mut self) -> Result<()> {
        let _ = self.settings.delete(SettingsKey::ChildInfo, None);
        Ok(())
    }

    fn load_child_info(&self, index: usize) -> Option<ChildInfo> {
        let mut b = [0u8; ChildInfo::ENCODED_LEN];
        self.settings
            .get(SettingsKey::ChildInfo, index, &mut b)
            .ok()?;
        ChildInfo::decode(&b).ok()
    }

    fn request_router_id(&mut self, request: &RouterIdRequest) -> Result<()> {
        self.solicit
            .push_back(SolicitCmd::Request(*request))
            .map_err(|_| Error::NoBufs)
    }

    fn release_router_id(&mut self, rloc16: Rloc16) {
        let _ = self.solicit.push_back(SolicitCmd::Release(rloc16));
    }

    fn event(&mut self, event: MleEvent) {
        if let MleEvent::RoleChanged { new, .. } = event {
            self.role = new;
        }
        if self.mle_events.is_full() {
            let _ = self.mle_events.pop_front();
        }
        let _ = self.mle_events.push_back(event);
    }
}
