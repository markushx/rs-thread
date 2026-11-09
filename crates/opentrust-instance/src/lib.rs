#![no_std]
//! The OpenTrust `Instance`: one Thread node wiring every sans-IO layer of
//! the stack together (see `docs/decisions/0003-instance.md`).
//!
//! Part of OpenTrust, a pure Rust implementation of the Thread 1.4.1 protocol.
//!
//! # Shape
//!
//! [`Instance`] owns the MAC (with the key manager), 6LoWPAN / mesh
//! forwarding, IPv6 with the interface and UDP sockets, the TMF agent, MLE,
//! Network Data (leader store, local data, notifier, publisher, ALOCs,
//! SLAAC) and the dataset managers. It has no radio, clock or executor:
//!
//! ```text
//!  radio frame ----> handle_radio_rx(psdu, info, now) ----+
//!  radio result ---> handle_radio_tx_done(outcome, now) --+--> Instance
//!  timer expired --> poll(now) ---------------------------+      |
//!                                                                v
//!  radio <---------- poll_radio_action(now)    next_deadline() / poll_event()
//! ```
//!
//! The host (the async facade in `opentrust-embassy`, the simulator in
//! `opentrust-sim`) alternates: feed inputs, call [`Instance::poll`], execute
//! every [`RadioAction`] from [`Instance::poll_radio_action`], sleep until
//! [`Instance::next_deadline`], drain [`Instance::poll_event`].
//!
//! # Internals
//!
//! The layers are plain fields; the MLE state machine takes the rest of the
//! stack (`Core`) as its `MleEnv`, so no layer ever calls another
//! re-entrantly: hooks queue work (outgoing UDP datagrams, MLE events, child
//! table changes) and the instance loop in [`Instance::poll`] drains the
//! queues until nothing is left to do.
//!
//! # Features
//!
//! `ftd` (default; router, leader, forwarding), `commissioner`,
//! `border-agent`, `tcat`, `trel` are forwarded to the lower crates;
//! `defmt` / `log` select the logging backend.

mod api;
mod datapath;
mod netdata_glue;
mod stack;
mod tmf;

pub use api::{PingReply, UdpSocket};
pub use opentrust_core::types::{ExtAddress, Rloc16};
pub use opentrust_mesh::netdata::local::{ExternalRouteConfig, OnMeshPrefixConfig};
pub use opentrust_mesh::netdata::tlv::{BrFlags, NetPrefix};
pub use opentrust_meshcop::dataset::Dataset;
pub use opentrust_mle::tlv::DeviceMode;
pub use opentrust_mle::{MleConfig, Role};
pub use opentrust_net::udp::{RecvInfo, UdpMeta, UdpSendOpts};
pub use opentrust_platform::radio::{PsduRxInfo, RadioCaps};
pub use stack::{CHILDREN, NETDATA_LEN, UDP_SOCKETS};

pub use opentrust_mac::mac::{RadioAction, TxOutcome};

use heapless::Deque;
use opentrust_coap::tmf::Agent;
use opentrust_core::crypto::CryptoBackend;
use opentrust_core::time::Instant;
use opentrust_core::types::Iid;
use opentrust_mac::mac::Mac;
use opentrust_mac::security::KeyManager;
use opentrust_mesh::forwarder::MeshForwarder;
use opentrust_mesh::netdata::NetworkData as NetData;
use opentrust_mesh::netdata::aloc::AlocSet;
#[cfg(feature = "ftd")]
use opentrust_mesh::netdata::leader::Leader;
use opentrust_mesh::netdata::local::LocalData;
use opentrust_mesh::netdata::notifier::Notifier;
use opentrust_mesh::netdata::publisher::{Publisher, PublisherEvent};
#[cfg(feature = "ftd")]
use opentrust_mesh::router_id::RouterIdOutbox;
use opentrust_meshcop::manager::Datasets;
use opentrust_mle::Mle;
use opentrust_net::ip6::Ip6;
use opentrust_net::resolver::AddressResolver;
use opentrust_net::slaac::Slaac;
use opentrust_net::udp::{ReceiverId, UdpSockets};
use opentrust_platform::SettingsStore;
use rand_core::Rng;

use crate::stack::{Core, MacRng, NetConfig, Outbox};

/// Largest UDP payload of a queued datagram (IPv6 minimum MTU minus the IPv6
/// and UDP headers).
pub const MAX_UDP_PAYLOAD: usize = 1232;

/// The TMF agent with the capacities of the instance.
pub(crate) type TmfAgent = Agent<4, 16, 4, 320>;

/// Event for the application (OpenThread: `otStateChangedCallback` flags,
/// the receive callbacks of UDP and ICMPv6 and the result callbacks of the
/// joiner and the clients).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Event {
    /// The Thread role changed.
    RoleChanged {
        /// Previous role.
        old: Role,
        /// New role.
        new: Role,
    },
    /// The RLOC16 changed.
    Rloc16Changed(Rloc16),
    /// The device joined another partition or started a new one.
    PartitionChanged {
        /// New partition ID.
        partition_id: u32,
    },
    /// Interface addresses changed (SLAAC, RLOC, ALOCs, ML-EID).
    AddressesChanged,
    /// The Network Data changed.
    NetworkDataChanged,
    /// The Active Dataset changed.
    ActiveDatasetChanged,
    /// The Pending Dataset changed.
    PendingDatasetChanged,
    /// A child attached to this router.
    ChildAdded {
        /// Extended address.
        ext: ExtAddress,
        /// RLOC16.
        rloc16: Rloc16,
    },
    /// A child left this router.
    ChildRemoved {
        /// Extended address.
        ext: ExtAddress,
        /// RLOC16.
        rloc16: Rloc16,
    },
    /// A router joined the partition.
    RouterAdded {
        /// RLOC16.
        rloc16: Rloc16,
    },
    /// A router left the partition.
    RouterRemoved {
        /// RLOC16.
        rloc16: Rloc16,
    },
    /// A UDP socket has data ([`Instance::udp_recv`]).
    UdpReadable(UdpSocket),
    /// An ICMPv6 echo reply arrived ([`Instance::take_ping_reply`]).
    PingReply,
    /// A Network Data Publisher entry changed state.
    Publisher(PublisherEvent),
}

/// Configuration of an [`Instance`].
#[derive(Debug, Clone)]
pub struct Config {
    /// The device's extended address (IEEE EUI-64).
    pub ext_address: ExtAddress,
    /// MLE configuration (device mode, timeouts, router configuration).
    pub mle: MleConfig,
    /// Capabilities of the radio the host drives.
    pub radio: RadioCaps,
}

impl Config {
    /// An FTD (router eligible, rx-on-when-idle, full Network Data) with
    /// the OpenThread defaults.
    pub fn router(ext_address: ExtAddress, radio: RadioCaps) -> Self {
        Self {
            ext_address,
            mle: MleConfig::new(DeviceMode::new(true, true, true)),
            radio,
        }
    }

    /// A minimal end device (rx-on-when-idle, no routing).
    pub fn end_device(ext_address: ExtAddress, radio: RadioCaps) -> Self {
        Self {
            ext_address,
            mle: MleConfig::new(DeviceMode::new(true, false, false)),
            radio,
        }
    }

    /// A sleepy end device polling its parent.
    pub fn sleepy_end_device(ext_address: ExtAddress, radio: RadioCaps) -> Self {
        Self {
            ext_address,
            mle: MleConfig::new(DeviceMode::new(false, false, false)),
            radio,
        }
    }
}

/// A Thread node. See the [crate documentation](crate).
///
/// Type parameters: `S` the persistent [`SettingsStore`], `C` the crypto
/// backend, `R` the entropy source (a CSPRNG: MLE challenges, SLAAC secrets,
/// ML-EID).
pub struct Instance<S, C: CryptoBackend, R> {
    pub(crate) mle: Mle<{ CHILDREN }>,
    pub(crate) core: Core<S, C, R>,
    pub(crate) agent: TmfAgent,
    /// TMF and application datagrams queued for the IPv6 layer.
    pub(crate) sink: Outbox,
    #[cfg(feature = "ftd")]
    pub(crate) solicit: RouterIdOutbox,
    /// Non-cryptographic randomness (CoAP tokens, MPL and TMF jitter).
    pub(crate) prng: MacRng,
    pub(crate) udp: UdpSockets<{ UDP_SOCKETS }>,
    pub(crate) resolver: AddressResolver<8>,
    pub(crate) fwd: MeshForwarder<2, 2, 4>,
    #[cfg(feature = "ftd")]
    pub(crate) leader: Leader<{ NETDATA_LEN }>,
    pub(crate) local: LocalData,
    pub(crate) notifier: Notifier,
    pub(crate) publisher: Publisher<3>,
    pub(crate) alocs: AlocSet,
    pub(crate) slaac: Slaac<4>,
    pub(crate) glue: netdata_glue::GlueState,
    pub(crate) ping: api::PingState,
    pub(crate) ip6_enabled: bool,
    pub(crate) started: bool,
}

impl<S, C: CryptoBackend, R> core::fmt::Debug for Instance<S, C, R> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Instance")
            .field("role", &self.mle.role())
            .field("rloc16", &self.mle.rloc16())
            .finish_non_exhaustive()
    }
}

impl<S: SettingsStore, C: CryptoBackend + Clone, R: Rng> Instance<S, C, R> {
    /// Create an instance. Nothing is sent and the radio is not touched
    /// until [`thread_start`](Self::thread_start) /
    /// [`become_leader`](Self::become_leader).
    pub fn new(config: Config, settings: S, crypto: C, mut rng: R) -> Self {
        let mut iid = [0u8; 8];
        rng.fill_bytes(&mut iid);
        let mac_seed = rng.next_u64();
        let prng_seed = rng.next_u64();
        let msg_seed = rng.next_u32() as u16;
        let mut iid_secret = [0u8; 32];
        rng.fill_bytes(&mut iid_secret);

        let keys = KeyManager::new(crypto.clone(), api::placeholder_key());
        let mac = Mac::new(
            config.radio,
            config.ext_address,
            keys,
            MacRng::new(mac_seed),
        );
        let mut ip6 = Ip6::new();
        let _ = ip6.netif.set_link_local(&config.ext_address);
        let cur = opentrust_meshcop::manager::CurrentConfig {
            channel: mac.channel(),
            pan_id: mac.pan_id().0,
            mesh_local_prefix: opentrust_core::types::Prefix64([0xfd, 0, 0, 0, 0, 0, 0, 0]),
            network_key: api::placeholder_key(),
        };
        let core = Core {
            mac,
            rng,
            settings,
            crypto,
            now: Instant::ZERO,
            ext: config.ext_address,
            ml_iid: Iid(iid),
            role: Role::Disabled,
            ip6,
            netdata: NetData::new(),
            datasets: Datasets::new(),
            cfg: NetConfig {
                cur,
                ext_pan_id: None,
                network_name: None,
                pskc: None,
                policy: None,
                ds_events: Deque::new(),
                nd_version_bump: false,
                applied: false,
            },
            mle_events: Deque::new(),
            child_changes: Deque::new(),
            nd_rx: None,
            solicit: Deque::new(),
            mle_out: Outbox::default(),
            rx_link: opentrust_mle::endpoint::LinkRxInfo::default(),
            parent: None,
            poll_period: None,
            user_poll_period: None,
            mactx: stack::MacTx::default(),
            events: Deque::new(),
            iid_secret,
        };
        let mut udp = UdpSockets::new();
        let _ = udp.register_receiver(opentrust_net::udp::MLE_UDP_PORT, ReceiverId::MLE);
        let _ = udp.register_receiver(opentrust_net::ip6::TMF_UDP_PORT, ReceiverId::TMF);
        let mut agent = TmfAgent::new(msg_seed);
        tmf::register_uris(&mut agent);
        Self {
            mle: Mle::new(config.mle),
            core,
            agent,
            sink: Outbox::default(),
            #[cfg(feature = "ftd")]
            solicit: RouterIdOutbox::new(),
            prng: MacRng::new(prng_seed),
            udp,
            resolver: AddressResolver::new(),
            fwd: MeshForwarder::new(msg_seed ^ 0x5a5a),
            #[cfg(feature = "ftd")]
            leader: Leader::new(),
            local: LocalData::new(),
            notifier: Notifier::new(),
            publisher: Publisher::new(),
            alocs: AlocSet::new(),
            slaac: Slaac::new(),
            glue: netdata_glue::GlueState::default(),
            ping: api::PingState::default(),
            ip6_enabled: false,
            started: false,
        }
    }

    // ------------------------------------------------------------ driving

    /// Feed a received PSDU (with FCS) from the radio.
    pub fn handle_radio_rx(&mut self, psdu: &[u8], info: &PsduRxInfo, now: Instant) {
        self.core.now = now;
        self.core.mac.on_rx(psdu, info, now);
    }

    /// Report the outcome of a [`RadioAction::Transmit`].
    pub fn handle_radio_tx_done(&mut self, outcome: TxOutcome<'_>, now: Instant) {
        self.core.now = now;
        self.core.mac.on_tx_done(outcome, now);
    }

    /// Report the result of a [`RadioAction::Transmit`] together with the
    /// transmitted PSDU the radio finished in place (frame counter, CSL
    /// phase), see `PsduTxInfo`.
    pub fn handle_radio_tx_updated(
        &mut self,
        psdu: &[u8],
        info: &opentrust_platform::radio::PsduTxInfo,
    ) {
        self.core.mac.on_tx_frame_updated(psdu, info);
    }

    /// Report the result of a [`RadioAction::EnergyScan`].
    pub fn handle_radio_energy_scan_done(&mut self, max_rssi: i8, now: Instant) {
        self.core.now = now;
        self.core.mac.on_energy_scan_done(max_rssi, now);
    }

    /// The next thing the radio has to do, if any. Call after
    /// [`poll`](Self::poll) until `None`.
    pub fn poll_radio_action(&mut self, now: Instant) -> Option<RadioAction> {
        self.core.now = now;
        self.core.mac.poll_action(now)
    }

    /// Run everything that is due at `now` and drain all internal queues.
    pub fn poll(&mut self, now: Instant) {
        self.core.now = now;
        for _ in 0..32 {
            let mut busy = false;
            busy |= self.service_mac(now);
            busy |= self.service_timers(now);
            busy |= self.service_mle_events(now);
            busy |= self.service_netdata(now);
            busy |= self.service_tmf(now);
            busy |= self.service_outbox(now);
            if !busy {
                break;
            }
        }
    }

    /// The earliest instant at which [`poll`](Self::poll) (or the radio)
    /// has work to do.
    pub fn next_deadline(&self) -> Option<Instant> {
        let mut d = [
            self.core.mac.next_deadline(),
            self.mle.next_deadline(),
            self.core.mac.security().next_deadline(),
            self.core.ip6.next_deadline(),
            self.fwd.next_deadline(),
            self.resolver.next_deadline(),
            self.agent.next_deadline(),
            self.notifier.next_deadline(),
            self.publisher.next_deadline(),
            self.slaac.next_deadline(),
            self.core.datasets.next_deadline(),
            self.leader_deadline(),
            self.glue.next_deadline(),
        ]
        .into_iter()
        .flatten()
        .min();
        if self.has_pending_work() {
            d = Some(self.core.now);
        }
        d
    }

    #[cfg(feature = "ftd")]
    fn leader_deadline(&self) -> Option<Instant> {
        self.leader.next_deadline()
    }

    #[cfg(not(feature = "ftd"))]
    #[allow(clippy::unused_self)]
    fn leader_deadline(&self) -> Option<Instant> {
        None
    }

    #[cfg(feature = "ftd")]
    fn solicit_pending(&self) -> bool {
        self.solicit.is_pending()
    }

    #[cfg(not(feature = "ftd"))]
    #[allow(clippy::unused_self)]
    fn solicit_pending(&self) -> bool {
        false
    }

    fn has_pending_work(&self) -> bool {
        !self.core.mle_out.q.is_empty()
            || !self.sink.q.is_empty()
            || !self.core.mle_events.is_empty()
            || !self.core.child_changes.is_empty()
            || self.core.nd_rx.is_some()
            || !self.core.solicit.is_empty()
            || self.solicit_pending()
            || !self.core.cfg.ds_events.is_empty()
            || self.core.cfg.applied
    }

    /// The next application event.
    pub fn poll_event(&mut self) -> Option<Event> {
        self.core.events.pop_front()
    }
}

#[cfg(all(test, not(feature = "ftd")))]
mod mtd_tests {
    use opentrust_core::crypto::soft::SoftCrypto;
    use opentrust_core::time::{Duration, Instant};
    use opentrust_platform::RamSettings;

    use super::*;

    /// An end-device-only build attaches by sending a Parent Request on the
    /// dataset's channel and has no router, leader or indirect machinery.
    #[test]
    fn end_device_build_starts_and_asks_for_a_parent() {
        let cfg = Config::end_device(ExtAddress([2, 0, 0, 0, 0, 0, 0, 9]), RadioCaps::default());
        let mut i = Instance::new(cfg, RamSettings::<2048>::new(), SoftCrypto, MacRng::new(7));
        let mut now = Instant::from_secs(10);
        let ds = i.create_dataset(15).unwrap();
        i.set_active_dataset(&ds, now).unwrap();
        i.ip6_set_enabled(true);
        i.thread_start(now).unwrap();
        assert_eq!(i.role(), Role::Detached);
        let mut transmitted = false;
        for _ in 0..40 {
            i.poll(now);
            while let Some(a) = i.poll_radio_action(now) {
                if let RadioAction::Transmit(tx) = a {
                    assert_eq!(tx.channel, 15);
                    transmitted = true;
                }
            }
            match i.next_deadline() {
                Some(d) if d > now => now = d.min(now + Duration::from_secs(1)),
                _ => now += Duration::from_millis(10),
            }
            if transmitted {
                break;
            }
        }
        assert!(transmitted);
    }
}

#[cfg(all(test, feature = "ftd"))]
mod tests {
    extern crate std;

    use opentrust_core::crypto::soft::SoftCrypto;
    use opentrust_core::time::{Duration, Instant};
    use opentrust_platform::RamSettings;

    use super::*;

    fn instance() -> Instance<RamSettings<2048>, SoftCrypto, MacRng> {
        let cfg = Config::router(ExtAddress([2, 0, 0, 0, 0, 0, 0, 1]), RadioCaps::default());
        Instance::new(cfg, RamSettings::new(), SoftCrypto, MacRng::new(42))
    }

    #[test]
    fn start_needs_an_enabled_interface_and_a_dataset() {
        let mut i = instance();
        let now = Instant::from_secs(10);
        assert_eq!(
            i.thread_start(now),
            Err(opentrust_core::Error::InvalidState)
        );
        i.ip6_set_enabled(true);
        assert_eq!(
            i.thread_start(now),
            Err(opentrust_core::Error::InvalidState)
        );
        assert_eq!(i.role(), Role::Disabled);
    }

    #[test]
    fn become_leader_without_a_radio() {
        let mut i = instance();
        let now = Instant::from_secs(10);
        let ds = i.create_dataset(15).unwrap();
        i.set_active_dataset(&ds, now).unwrap();
        i.ip6_set_enabled(true);
        i.become_leader(now).unwrap();
        assert_eq!(i.role(), Role::Leader);
        assert_ne!(i.rloc16(), Rloc16::INVALID);
        assert!(i.rloc().is_some());
        // The radio is told to listen on the dataset's channel.
        let mut listening = false;
        while let Some(a) = i.poll_radio_action(now) {
            listening |= matches!(a, RadioAction::Receive { channel: 15 });
        }
        assert!(listening);
        let mut role_events = 0;
        while let Some(e) = i.poll_event() {
            role_events += usize::from(matches!(
                e,
                Event::RoleChanged {
                    new: Role::Leader,
                    ..
                }
            ));
        }
        assert_eq!(role_events, 1);
        // Timers (advertisements) are scheduled.
        assert!(i.next_deadline().is_some_and(|d| d >= now));
        i.poll(now + Duration::from_secs(1));
    }

    #[test]
    fn stop_and_factory_reset() {
        let mut i = instance();
        let now = Instant::from_secs(10);
        let ds = i.create_dataset(15).unwrap();
        i.set_active_dataset(&ds, now).unwrap();
        i.ip6_set_enabled(true);
        i.become_leader(now).unwrap();
        i.thread_stop();
        assert_eq!(i.role(), Role::Disabled);
        i.factory_reset();
        let s = i.into_settings();
        assert_eq!(
            s.count(opentrust_core::settings::SettingsKey::ActiveDataset),
            0
        );
    }
}
