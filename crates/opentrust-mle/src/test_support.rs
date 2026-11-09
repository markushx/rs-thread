//! Test environment shared by the MLE state machine tests: a fake
//! [`MleEnv`] with deterministic randomness and captured output.

#![allow(missing_docs, missing_debug_implementations, dead_code)]

extern crate std;

use core::net::{Ipv6Addr, SocketAddrV6};

use heapless::Vec;
use opentrust_core::crypto::SoftCrypto;
use opentrust_core::settings::{ChildInfo, NetworkInfo, ParentInfo, SettingsKey};
use opentrust_core::time::{Duration, Instant};
use opentrust_core::types::{ExtAddress, Iid, NetworkKey, Prefix64, Rloc16, ipv6};
use opentrust_core::{Error, Result};
use opentrust_mac::security::KeyManager;
use opentrust_net::udp::UdpMeta;
use opentrust_platform::settings::{RamSettings, SettingsStore};

use crate::consts::MLE_UDP_PORT;
use crate::endpoint::LinkRxInfo;
use crate::env::{MleEnv, MleEvent};
use crate::message::Command;
use crate::mle::Mle;
use crate::tlv::{LeaderData, Timestamp};

pub struct Out {
    pub src: Ipv6Addr,
    pub dst: Ipv6Addr,
    pub data: Vec<u8, 1100>,
    /// MAC PAN ID / channel the message was sent with (Discovery, Announce).
    pub pan_id: Option<u16>,
    pub channel: Option<u8>,
    pub link_security: bool,
}

/// Dataset behavior plugged into [`TestEnv`] by crates that own the dataset
/// logic (`opentrust-meshcop` tests).
pub trait DatasetBridge {
    fn active_timestamp(&self) -> Option<Timestamp>;
    fn pending_timestamp(&self) -> Option<Timestamp>;
    /// Dataset TLVs without the timestamp TLV.
    fn dataset(&self, active: bool, now: Instant, out: &mut [u8]) -> Result<usize>;
    fn received(
        &mut self,
        now: Instant,
        active: Option<(Timestamp, Option<&[u8]>)>,
        pending: Option<(Timestamp, Option<&[u8]>)>,
    );
    /// Restore the stored Active / Pending Dataset; `false` if none.
    fn restore(&mut self, _now: Instant, _active: bool) -> bool {
        false
    }
    /// Apply the restored Pending Dataset's configuration.
    fn apply_pending(&mut self, _now: Instant) {}
    /// Delete the Pending Dataset.
    fn clear_pending(&mut self, _now: Instant) {}
}

/// Stored datasets of a [`TestEnv`] without a [`DatasetBridge`], and the
/// reattach steps taken.
#[derive(Default)]
pub struct StoredDatasets {
    pub active: bool,
    pub pending: bool,
    pub restored: std::vec::Vec<crate::env::StoredDataset>,
    pub pending_applied: u32,
    pub pending_cleared: u32,
}

/// Link Metrics results seen by a [`TestEnv`].
#[derive(Default)]
pub struct LinkMetricsSeen {
    pub reports: std::vec::Vec<(
        Option<crate::link_metrics::MetricsValues>,
        crate::link_metrics::Status,
    )>,
    pub management: std::vec::Vec<crate::link_metrics::Status>,
    pub enh_ack: std::vec::Vec<crate::link_metrics::MetricsValues>,
    pub configured: std::vec::Vec<opentrust_mac::mac::LinkMetricsFlags>,
}

pub struct TestEnv {
    pub keys: KeyManager<SoftCrypto>,
    pub ext: ExtAddress,
    pub rng: u64,
    pub out: Vec<Out, 16>,
    pub short: Rloc16,
    pub rx_on: bool,
    pub poll: Option<Duration>,
    pub parent: Option<(ExtAddress, Rloc16)>,
    pub events: Vec<MleEvent, 256>,
    pub nd: Vec<u8, 512>,
    pub nd_leader: Option<LeaderData>,
    pub provided_nd: Vec<u8, 512>,
    /// Stable subset served when `stable_only` is requested (`None`: the
    /// full `provided_nd`).
    pub provided_nd_stable: Option<Vec<u8, 512>>,
    pub indirect: Vec<(ExtAddress, Rloc16), 8>,
    pub supervised: Vec<(ExtAddress, Rloc16), 8>,
    pub extra_addrs: Vec<Ipv6Addr, 4>,
    /// Multicast groups registered with the parent.
    pub extra_multicast: Vec<Ipv6Addr, 4>,
    pub settings: RamSettings<1024>,
    pub ml_iid: Option<Iid>,
    pub solicits: Vec<crate::env::RouterIdRequest, 4>,
    pub released: Vec<Rloc16, 4>,
    /// `request_router_id` fails (no TMF available).
    pub solicit_fails: bool,
    pub dataset_bridge: Option<std::boxed::Box<dyn DatasetBridge>>,
    pub stored: StoredDatasets,
    pub lm: LinkMetricsSeen,
    pub alternate_short: Option<Rloc16>,
    pub active_ts: Option<Timestamp>,
    pub mac_pan_id: u16,
    pub mac_channel: u8,
    pub mac_ext_pan_id: Option<opentrust_core::types::ExtPanId>,
    pub discovery_accept: bool,
    pub discovery_tlvs: std::vec::Vec<u8>,
    pub discovery_requests: std::vec::Vec<crate::env::DiscoveryRequestInfo>,
    pub discovery_responses: std::vec::Vec<(crate::env::DiscoveryResponseInfo, std::vec::Vec<u8>)>,
}

pub const MLP: Prefix64 = Prefix64([0xfd, 0, 0, 0, 0, 0, 0, 1]);

pub fn ext(n: u8) -> ExtAddress {
    ExtAddress([0x02, 0, 0, 0, 0, 0, 0, n])
}

pub fn ll(e: &ExtAddress) -> Ipv6Addr {
    ipv6::link_local(e)
}

impl TestEnv {
    pub fn new(n: u8) -> Self {
        Self {
            keys: KeyManager::new(SoftCrypto, NetworkKey([0x42; 16])),
            ext: ext(n),
            rng: 0x1234_5678_9abc_def0 ^ u64::from(n),
            out: Vec::new(),
            short: Rloc16::INVALID,
            rx_on: true,
            poll: None,
            parent: None,
            events: Vec::new(),
            nd: Vec::new(),
            nd_leader: None,
            provided_nd: Vec::new(),
            provided_nd_stable: None,
            indirect: Vec::new(),
            supervised: Vec::new(),
            extra_addrs: Vec::new(),
            extra_multicast: Vec::new(),
            settings: RamSettings::new(),
            ml_iid: None,
            solicits: Vec::new(),
            released: Vec::new(),
            solicit_fails: false,
            dataset_bridge: None,
            stored: StoredDatasets::default(),
            lm: LinkMetricsSeen::default(),
            alternate_short: None,
            active_ts: None,
            mac_pan_id: 0xface,
            mac_channel: 15,
            mac_ext_pan_id: None,
            discovery_accept: true,
            discovery_tlvs: std::vec::Vec::new(),
            discovery_requests: std::vec::Vec::new(),
            discovery_responses: std::vec::Vec::new(),
        }
    }

    pub fn take_out(&mut self) -> Vec<Out, 16> {
        core::mem::take(&mut self.out)
    }

    pub fn ml_eid(&self) -> Ipv6Addr {
        let iid = self
            .ml_iid
            .unwrap_or(Iid([0xaa, 0, 0, 0, 0, 0, 0, self.ext.0[7]]));
        MLP.with_iid(&iid)
    }

    /// Deliver `out` to `mle`/`env` (unicast filtered by destination).
    pub fn deliver<const C: usize>(
        out: &Out,
        mle: &mut Mle<C>,
        env: &mut TestEnv,
        now: Instant,
        rss: i8,
    ) -> Result<Command> {
        let me = ll(&env.ext);
        if !out.dst.is_multicast() && out.dst != me {
            return Err(Error::Drop);
        }
        let meta = UdpMeta {
            peer: SocketAddrV6::new(out.src, MLE_UDP_PORT, 0, 0),
            local: SocketAddrV6::new(out.dst, MLE_UDP_PORT, 0, 0),
            hop_limit: 255,
            ecn: 0,
            link_security: false,
        };
        let mut scratch = [0u8; 1100];
        let link = LinkRxInfo {
            rss: Some(rss),
            lqi: Some(200),
            pan_id: out.pan_id,
            channel: out.channel,
        };
        mle.receive(env, now, &meta, link, &out.data, &mut scratch)
    }

    #[cfg(feature = "ftd")]
    pub fn settings_child_count(&self) -> usize {
        self.settings.count(SettingsKey::ChildInfo)
    }

    #[cfg(feature = "ftd")]
    pub fn load_child(&self, i: usize) -> Option<ChildInfo> {
        MleEnv::load_child_info(self, i)
    }

    pub fn has_event(&self, e: MleEvent) -> bool {
        self.events.contains(&e)
    }
}

impl MleEnv for TestEnv {
    type Crypto = SoftCrypto;
    fn keys(&self) -> &KeyManager<SoftCrypto> {
        &self.keys
    }
    fn keys_mut(&mut self) -> &mut KeyManager<SoftCrypto> {
        &mut self.keys
    }
    fn ext_address(&self) -> ExtAddress {
        self.ext
    }
    fn fill_random(&mut self, buf: &mut [u8]) {
        for b in buf {
            // xorshift64*
            self.rng ^= self.rng >> 12;
            self.rng ^= self.rng << 25;
            self.rng ^= self.rng >> 27;
            *b = (self.rng.wrapping_mul(0x2545_f491_4f6c_dd1d) >> 56) as u8;
        }
    }
    fn send(&mut self, src: Ipv6Addr, dst: Ipv6Addr, payload: &[u8]) -> Result<()> {
        self.send_with(&crate::env::TxOptions::default(), src, dst, payload)
    }
    fn send_with(
        &mut self,
        opts: &crate::env::TxOptions,
        src: Ipv6Addr,
        dst: Ipv6Addr,
        payload: &[u8],
    ) -> Result<()> {
        self.out
            .push(Out {
                src,
                dst,
                data: Vec::from_slice(payload).map_err(|_| Error::NoBufs)?,
                pan_id: opts.pan_id,
                channel: opts.channel,
                link_security: opts.link_security,
            })
            .map_err(|_| Error::NoBufs)
    }
    fn set_pan_channel_and_id(&mut self, channel: u8, pan_id: u16) {
        self.mac_channel = channel;
        self.mac_pan_id = pan_id;
    }
    fn pan_id(&self) -> u16 {
        self.mac_pan_id
    }
    fn pan_channel(&self) -> u8 {
        self.mac_channel
    }
    fn ext_pan_id(&self) -> Option<opentrust_core::types::ExtPanId> {
        self.mac_ext_pan_id
    }
    fn accept_discovery_request(&mut self, info: &crate::env::DiscoveryRequestInfo) -> bool {
        self.discovery_requests.push(*info);
        // Joiners are only answered while joining is allowed.
        !info.joiner || self.discovery_accept
    }
    fn discovery_response(&mut self, out: &mut [u8]) -> Result<usize> {
        if self.discovery_tlvs.is_empty() {
            return Err(Error::NotImplemented);
        }
        let r = out
            .get_mut(..self.discovery_tlvs.len())
            .ok_or(Error::NoBufs)?;
        r.copy_from_slice(&self.discovery_tlvs);
        Ok(self.discovery_tlvs.len())
    }
    fn discovery_response_received(
        &mut self,
        info: &crate::env::DiscoveryResponseInfo,
        tlvs: &[u8],
    ) {
        self.discovery_responses.push((*info, tlvs.to_vec()));
    }
    fn link_metrics_report(
        &mut self,
        _from: &Ipv6Addr,
        values: Option<&crate::link_metrics::MetricsValues>,
        status: crate::link_metrics::Status,
    ) {
        self.lm.reports.push((values.copied(), status));
    }
    fn link_metrics_management_response(
        &mut self,
        _from: &Ipv6Addr,
        status: crate::link_metrics::Status,
    ) {
        self.lm.management.push(status);
    }
    fn enh_ack_probing_report(
        &mut self,
        _rloc16: Rloc16,
        _ext: &ExtAddress,
        values: &crate::link_metrics::MetricsValues,
    ) {
        self.lm.enh_ack.push(*values);
    }
    fn configure_enh_ack_probing(
        &mut self,
        flags: opentrust_mac::mac::LinkMetricsFlags,
        _rloc16: Rloc16,
        _ext: &ExtAddress,
    ) -> Result<()> {
        self.lm.configured.push(flags);
        Ok(())
    }
    fn set_alternate_short_address(&mut self, rloc16: Option<Rloc16>) {
        self.alternate_short = rloc16;
    }
    fn set_short_address(&mut self, rloc16: Rloc16) {
        self.short = rloc16;
    }
    fn set_rx_on_when_idle(&mut self, on: bool) {
        self.rx_on = on;
    }
    fn set_parent(&mut self, parent: Option<(ExtAddress, Rloc16)>) {
        self.parent = parent;
    }
    fn set_poll_period(&mut self, period: Option<Duration>) {
        self.poll = period;
    }
    fn mesh_local_prefix(&self) -> Prefix64 {
        MLP
    }
    fn ml_eid(&self) -> Ipv6Addr {
        TestEnv::ml_eid(self)
    }
    fn registered_addresses(&self, f: &mut dyn FnMut(Ipv6Addr)) {
        for a in &self.extra_addrs {
            f(*a);
        }
    }
    fn registered_multicast_addresses(&self, f: &mut dyn FnMut(Ipv6Addr)) {
        for a in &self.extra_multicast {
            f(*a);
        }
    }
    fn indirect_add_child(&mut self, ext: &ExtAddress, rloc16: Rloc16) {
        let _ = self.indirect.push((*ext, rloc16));
    }
    fn indirect_remove_child(&mut self, ext: &ExtAddress, _rloc16: Rloc16) {
        self.indirect.retain(|(e, _)| e != ext);
    }
    fn send_child_supervision(&mut self, ext: &ExtAddress, rloc16: Rloc16) {
        let _ = self.supervised.push((*ext, rloc16));
    }
    fn network_data(&self, stable_only: bool, out: &mut [u8]) -> Result<usize> {
        let nd = match (&self.provided_nd_stable, stable_only) {
            (Some(s), true) => s,
            _ => &self.provided_nd,
        };
        out.get_mut(..nd.len())
            .ok_or(Error::NoBufs)?
            .copy_from_slice(nd);
        Ok(nd.len())
    }
    fn set_network_data(&mut self, leader: &LeaderData, data: &[u8]) {
        self.nd_leader = Some(*leader);
        self.nd = Vec::from_slice(data).unwrap();
    }
    fn active_timestamp(&self) -> Option<Timestamp> {
        match &self.dataset_bridge {
            Some(b) => b.active_timestamp(),
            None => self.active_ts,
        }
    }
    fn pending_timestamp(&self) -> Option<Timestamp> {
        self.dataset_bridge.as_ref()?.pending_timestamp()
    }
    fn active_dataset(&self, now: Instant, out: &mut [u8]) -> Result<usize> {
        match &self.dataset_bridge {
            Some(b) => b.dataset(true, now, out),
            None => Ok(0),
        }
    }
    fn pending_dataset(&self, now: Instant, out: &mut [u8]) -> Result<usize> {
        match &self.dataset_bridge {
            Some(b) => b.dataset(false, now, out),
            None => Ok(0),
        }
    }
    fn restore_dataset(&mut self, now: Instant, which: crate::env::StoredDataset) -> bool {
        if let Some(b) = &mut self.dataset_bridge {
            return b.restore(now, which == crate::env::StoredDataset::Active);
        }
        self.stored.restored.push(which);
        match which {
            crate::env::StoredDataset::Active => self.stored.active,
            crate::env::StoredDataset::Pending => self.stored.pending,
        }
    }
    fn apply_pending_configuration(&mut self, now: Instant) {
        if let Some(b) = &mut self.dataset_bridge {
            b.apply_pending(now);
        }
        self.stored.pending_applied += 1;
    }
    fn clear_pending_dataset(&mut self, now: Instant) {
        if let Some(b) = &mut self.dataset_bridge {
            b.clear_pending(now);
        }
        self.stored.pending_cleared += 1;
    }
    fn dataset_received(
        &mut self,
        now: Instant,
        active: Option<(Timestamp, Option<&[u8]>)>,
        pending: Option<(Timestamp, Option<&[u8]>)>,
    ) {
        if let Some(b) = &mut self.dataset_bridge {
            b.received(now, active, pending);
        }
    }
    fn apply_restored_identity(&mut self, ext: &ExtAddress, ml_iid: &Iid) {
        self.ext = *ext;
        self.ml_iid = Some(*ml_iid);
    }
    fn store_network_info(&mut self, info: &NetworkInfo) -> Result<()> {
        let mut b = [0u8; NetworkInfo::ENCODED_LEN];
        let n = info.encode(&mut b)?;
        self.settings.set(SettingsKey::NetworkInfo, &b[..n])
    }
    fn load_network_info(&self) -> Option<NetworkInfo> {
        let mut b = [0u8; 64];
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
        let mut b = [0u8; 16];
        self.settings.get(SettingsKey::ParentInfo, 0, &mut b).ok()?;
        ParentInfo::decode(&b).ok()
    }
    fn store_child_info(&mut self, info: &ChildInfo) -> Result<()> {
        // Replace an existing record of the same child.
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
        let mut b = [0u8; 32];
        self.settings
            .get(SettingsKey::ChildInfo, index, &mut b)
            .ok()?;
        ChildInfo::decode(&b).ok()
    }
    fn event(&mut self, event: MleEvent) {
        let _ = self.events.push(event);
    }
    fn request_router_id(&mut self, request: &crate::env::RouterIdRequest) -> Result<()> {
        if self.solicit_fails {
            return Err(Error::NoBufs);
        }
        let _ = self.solicits.push(*request);
        Ok(())
    }
    fn release_router_id(&mut self, rloc16: Rloc16) {
        let _ = self.released.push(rloc16);
    }
}
