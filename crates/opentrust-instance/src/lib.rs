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
//! # End-device builds
//!
//! `default-features = false` is a real end-device build: no router,
//! leader, Router ID, indirect queue or commissioner code. The forwarder
//! sends everything except link-local traffic to the parent and drops mesh
//! header frames (OT `mesh_forwarder_mtd.cpp`); `become_leader` does not
//! exist.
//!
//! # SRP and DNS clients
//!
//! The instance owns an SRP client and a DNS client (`srp_*`, `dns_*`,
//! [`Event::SrpClient`], [`Event::DnsResult`]). They use two internal UDP
//! sockets, take the server from the Network Data (`srp_enable_auto_start`),
//! persist the SRP key and server in the settings and register the
//! interface addresses. This needs `EcdsaP256` (`opentrust_core::crypto::ecdsa`)
//! on the crypto backend and a `CryptoRng` as the RNG.
//!
//! # Backbone Router client
//!
//! The Primary Backbone Router in the Network Data drives the Domain Unicast
//! Address (also registered for sleepy children) and the Multicast Listener
//! Registration ([`Instance::domain_unicast_address`]). Extra TMF resources
//! can be served by a layer on top with [`Instance::set_tmf_extension`].
//!
//! # Commissioning
//!
//! The instance owns the MeshCoP roles: the Joiner (always,
//! [`Instance::joiner_start`]), the Joiner Router and the leader's
//! commissioner session (`ftd`), the on-mesh Commissioner
//! (`commissioner`, `Instance::commissioner_start`) and the Border Agent
//! (`border-agent`, `Instance::border_agent_start`; the host carries its
//! DTLS datagrams on the external interface). The crypto parameter
//! implements [`InstanceCrypto`], which adds the EC-JPAKE curve.
//!
//! Frames carry a [`LinkSecurity`](opentrust_core::types::LinkSecurity)
//! class. Only key ID mode 1 counts as link-layer secured above the MAC.
//! Key ID mode 0 (the KEK) frames are accepted only from the peer of a
//! running Joiner Entrust exchange, addressed to us, with a frame counter
//! above the last accepted one under the current KEK, and only as UDP
//! between link-local addresses to the TMF port; they reach only the
//! Joiner / Joiner Router, never IPv6 or TMF ([`Instance::kek_drops`]).
//! Unsecured Joiner DTLS records are accepted on the Joiner UDP port only
//! between link-local addresses.
//!
//! # SLAAC IID secret
//!
//! Semantically opaque interface identifiers use a 32-byte secret that is
//! generated on first start and stored under the OT settings key
//! `SlaacIidSecretKey` (as `Slaac::SetIidSecretKey`), so addresses survive
//! resets.
//!
//! # Features
//!
//! `ftd` (default; router, leader, forwarding), `commissioner`,
//! `border-agent`, `tcat`, `trel` are forwarded to the lower crates;
//! `defmt` / `log` select the logging backend.

mod api;
mod bbr;
mod cm_api;
mod cm_comm;
mod cm_glue;
mod cm_io;
mod commissioning;
mod datapath;
mod dhcp6;
mod diag;
mod dns_srp;
#[cfg(feature = "link-metrics-manager")]
mod lmm;
mod netdata_glue;
mod scan;
#[cfg(feature = "srp-server")]
mod srp_server;
mod stack;
mod tmf;

pub use api::{PingReply, UdpSocket};
pub use bbr::MlrRegisterResult;
#[cfg(feature = "border-agent")]
pub use commissioning::BaDatagram;
pub use commissioning::InstanceCrypto;
#[cfg(feature = "ftd")]
pub use diag::RouteInfo;
pub use diag::{ChildInfo, NeighborInfo, tlv as diag_tlv};
pub use dns_srp::{BrowseInstance, DnsOutcome, MAX_BROWSE_INSTANCES, SRP_SERVICES};
#[cfg(feature = "srp-server")]
pub use dns_srp::{RECORDS_MSG, records_of};
pub use opentrust_coap::message::Code as CoapCode;
pub use opentrust_coap::uri::Uri as TmfUri;
pub use opentrust_core::types::{ExtAddress, Rloc16};
pub use opentrust_dns::client::{
    DnsError, PartialConfig, QueryConfig, QueryId, ResolvedAddresses, ResolvedService, Section,
    ServiceMode,
};
pub use opentrust_dns::rdata::TxtEntry;
#[cfg(feature = "srp-server")]
pub use opentrust_dns::srp::server as srp_server_types;
pub use opentrust_dns::srp::{ItemState, ServiceConfig, ServiceId, SrpError, SrpEvent};
pub use opentrust_mac::mac::MacCounters;
pub use opentrust_mac::mac::ScanResult as BeaconScanResult;
pub use opentrust_mesh::netdata::local::{ExternalRouteConfig, OnMeshPrefixConfig};
pub use opentrust_mesh::netdata::publisher::DnsSrpService;
pub use opentrust_mesh::netdata::tlv::{BrFlags, NetPrefix};
pub use opentrust_meshcop::dataset::Dataset;
pub use opentrust_meshcop::discovery::ScanResult as DiscoverResult;
pub use opentrust_meshcop::tlv::SecurityPolicy;
pub use opentrust_mle::tlv::{DeviceMode, LeaderData};
pub use opentrust_mle::{MleConfig, Role};
pub use opentrust_net::udp::{RecvInfo, UdpMeta, UdpSendOpts};
pub use opentrust_platform::radio::{PsduRxInfo, RadioCaps};
#[cfg(feature = "srp-server")]
pub use srp_server::{
    SRP_SERVER_HOSTS, SRP_SERVER_SERVICES, SRP_SERVER_UPDATE_SERVICES, SrpAddressMode,
    SrpServerState, SrpServerStore,
};
pub use stack::{CHILDREN, NETDATA_LEN, UDP_SOCKETS};

pub use opentrust_mac::mac::{RadioAction, TxOutcome};

use heapless::Deque;
use opentrust_coap::tmf::Agent;
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
use rand_core::{CryptoRng, Rng};

use crate::stack::{Core, MacRng, NetConfig, Outbox};

/// Largest UDP payload of a queued datagram (IPv6 minimum MTU minus the IPv6
/// and UDP headers).
pub const MAX_UDP_PAYLOAD: usize = 1232;

/// Application handler for TMF requests of registered extra URIs
/// ([`Instance::set_tmf_extension`]): returns the response code and payload
/// (`None`: no response). Used for roles built on top of the instance, e.g. a
/// Backbone Router.
pub type TmfExtension = fn(TmfUri, &[u8]) -> Option<(CoapCode, heapless::Vec<u8, 64>)>;

/// The TMF agent with the capacities of the instance.
pub(crate) type TmfAgent = Agent<4, 32, 4, TMF_MSG>;

/// Largest TMF message: a Relay Receive / Transmit carries a whole DTLS
/// record of the Joiner (FTD only; an end device relays nothing).
#[cfg(feature = "ftd")]
pub(crate) const TMF_MSG: usize = 1024;
#[cfg(not(feature = "ftd"))]
pub(crate) const TMF_MSG: usize = 320;

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
    /// Link metrics from an Enhanced ACK of a probed neighbor.
    EnhAckLinkMetrics {
        /// RLOC16 of the neighbor (invalid if unknown).
        rloc16: Rloc16,
        /// Extended address of the neighbor.
        ext: ExtAddress,
        /// LQI.
        lqi: Option<u8>,
        /// Link margin in dB.
        link_margin: Option<u8>,
        /// RSSI in dBm.
        rssi: Option<i8>,
    },
    /// A Link Metrics Report arrived (OT `otLinkMetricsReportCallback`):
    /// the values, or only the Subject's status.
    LinkMetricsReport {
        /// Sender (link-local address).
        from: core::net::Ipv6Addr,
        /// The metric values; `None` if the Subject answered with `status`.
        values: Option<opentrust_mle::link_metrics::MetricsValues>,
        /// Link Metrics Status value.
        status: u8,
    },
    /// A Link Metrics Management Response arrived (OT
    /// `otLinkMetricsMgmtResponseCallback`).
    LinkMetricsManagement {
        /// Sender (link-local address).
        from: core::net::Ipv6Addr,
        /// Link Metrics Status value.
        status: u8,
    },
    /// A graceful detach finished ([`Instance::detach_gracefully`]); Thread
    /// is stopped.
    DetachedGracefully,
    /// An anycast locate request finished ([`Instance::anycast_locate`]): the
    /// Mesh-Local EID and RLOC16 of the closest destination, or the error.
    AnycastLocated(core::result::Result<(core::net::Ipv6Addr, u16), opentrust_core::Error>),
    /// A Dataset Updater request finished ([`Instance::dataset_updater_request`]).
    /// `Ok` when the Active Dataset has the requested values, `Err(Error::Already)`
    /// when a conflicting update won.
    DatasetUpdateDone(core::result::Result<(), opentrust_core::Error>),
    /// The key sequence counter changed (rotation, adopted from a neighbor or
    /// the dataset).
    KeySequenceChanged(u32),
    /// A diagnostic answer arrived ([`Instance::diag_take_answer`]).
    DiagAnswer,
    /// A UDP socket has data ([`Instance::udp_recv`]).
    UdpReadable(UdpSocket),
    /// An ICMPv6 echo reply arrived ([`Instance::take_ping_reply`]).
    PingReply,
    /// A network answered the discovery scan ([`Instance::discover_start`]).
    DiscoverResult(DiscoverResult),
    /// The discovery scan finished.
    DiscoverDone,
    /// A beacon was heard during the active scan
    /// ([`Instance::active_scan_start`]).
    ActiveScanResult(BeaconScanResult),
    /// The active scan finished.
    ActiveScanDone,
    /// The maximum RSSI of one channel of the energy scan
    /// ([`Instance::energy_scan_start`]).
    EnergyScanResult {
        /// Channel.
        channel: u8,
        /// Maximum RSSI in dBm (the radio's "invalid" value 127 if it could
        /// not measure).
        max_rssi: i8,
    },
    /// The energy scan finished.
    EnergyScanDone,
    /// An Energy Report arrived for the Commissioner's Energy Scan query
    /// ([`Instance::take_energy_report`]).
    #[cfg(feature = "commissioner")]
    EnergyReport,
    /// A PAN ID Conflict report arrived for the Commissioner's PAN ID query.
    #[cfg(feature = "commissioner")]
    PanIdConflict {
        /// The PAN ID that was queried.
        pan_id: u16,
        /// The channels the PAN ID was heard on.
        channel_mask: u32,
    },
    /// A Network Data Publisher entry changed state.
    Publisher(PublisherEvent),
    /// The SRP client selected or lost a server, registered, or failed.
    SrpClient(SrpEvent),
    /// A DNS query completed ([`Instance::dns_take_result`]).
    DnsResult(QueryId),
    /// An MLR.req from [`Instance::mlr_register`] was answered or failed
    /// ([`Instance::mlr_take_register_result`]).
    MlrRegisterResult,
    /// The Joiner changed state.
    JoinerState(opentrust_meshcop::joiner::JoinerState),
    /// Joining ended (OT joiner callback): `Ok` after the Joiner Entrust
    /// (the credentials are the Active Dataset and Thread was started).
    JoinerResult(core::result::Result<(), opentrust_core::Error>),
    /// A notification of the on-mesh Commissioner.
    #[cfg(feature = "commissioner")]
    Commissioner(opentrust_meshcop::commissioner::CommissionerEvent),
    /// A notification of the Border Agent.
    #[cfg(feature = "border-agent")]
    BorderAgent(opentrust_meshcop::border_agent::BorderAgentEvent),
}

/// Extended address value that asks the instance for a random one (OT picks
/// a random extended address at every boot): drawn from the instance RNG when
/// the instance is created, locally administered and unicast, replaced by the
/// stored one when the network information of an attached device is restored.
pub const RANDOM_EXT_ADDRESS: ExtAddress = ExtAddress([0; 8]);

/// Configuration of an [`Instance`].
#[derive(Debug, Clone)]
pub struct Config {
    /// The device's extended address (IEEE EUI-64), or
    /// [`RANDOM_EXT_ADDRESS`].
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

/// Build a value in its own stack frame and write it to `dst`, so the
/// temporaries of the constructor do not add up in the caller's frame.
///
/// # Safety
///
/// `dst` must be valid for writes and suitably aligned.
#[allow(unsafe_code)]
#[inline(never)]
unsafe fn put<T>(dst: *mut T, f: impl FnOnce() -> T) {
    // SAFETY: the caller guarantees `dst`.
    unsafe { dst.write(f()) }
}

/// A Thread node. See the [crate documentation](crate).
///
/// Type parameters: `S` the persistent [`SettingsStore`], `C` the crypto
/// backend, `R` the entropy source (a CSPRNG: MLE challenges, SLAAC secrets,
/// ML-EID).
pub struct Instance<S, C: InstanceCrypto, R> {
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
    pub(crate) dnssrp: dns_srp::DnsSrp,
    pub(crate) dhcp6: dhcp6::Dhcp6,
    #[cfg(feature = "ftd")]
    pub(crate) updater: opentrust_meshcop::updater::DatasetUpdater,
    pub(crate) bbrg: bbr::BbrGlue,
    pub(crate) diag_in: Deque<diag::Answer, 2>,
    pub(crate) diag_query_id: u16,
    pub(crate) cm: commissioning::Commissioning<C>,
    pub(crate) tmf_ext: Option<TmfExtension>,
    pub(crate) ping: api::PingState,
    pub(crate) scan: scan::ScanState,
    pub(crate) ip6_enabled: bool,
    pub(crate) started: bool,
    /// Radio filter (OT `otLinkSetRadioFilterEnabled`): no frame is received
    /// or transmitted.
    pub(crate) radio_filter: bool,

    /// The stored network information has not been used since the instance
    /// was created (OT restores it at initialisation only; a later
    /// stop / start attaches from scratch).
    pub(crate) restore_pending: bool,
    /// A router sent an Address Release when it detached gracefully: its
    /// RLOC16 is gone, the next start attaches with a Parent Request.
    pub(crate) rloc_released: bool,
}

impl<S, C: InstanceCrypto, R> core::fmt::Debug for Instance<S, C, R> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Instance")
            .field("role", &self.mle.role())
            .field("rloc16", &self.mle.rloc16())
            .finish_non_exhaustive()
    }
}

impl<S: SettingsStore, C: InstanceCrypto, R: Rng + CryptoRng> Instance<S, C, R> {
    /// Create an instance. Nothing is sent and the radio is not touched
    /// until [`thread_start`](Self::thread_start) /
    /// [`become_leader`](Self::become_leader).
    ///
    /// The value is large (see `docs/memory-budget.md`); on a small target
    /// build it in place with [`init`](Self::init) instead of moving it
    /// through the stack.
    pub fn new(config: Config, settings: S, crypto: C, rng: R) -> Self {
        let mut slot = core::mem::MaybeUninit::<Self>::uninit();
        Self::init(&mut slot, config, settings, crypto, rng);
        // SAFETY: `init` initialised every field.
        #[allow(unsafe_code)]
        unsafe {
            slot.assume_init()
        }
    }

    /// Create an instance in place in `slot` (for example a
    /// `StaticCell<MaybeUninit<Instance>>` or a `static`), so that no value
    /// of the size of the instance (tens of kB) ever lives on the stack. The
    /// components are written one at a time; the largest stack temporary is
    /// the largest component (a few kB). Returns the initialised instance.
    #[allow(unsafe_code)]
    #[inline(never)]
    pub fn init(
        slot: &mut core::mem::MaybeUninit<Self>,
        config: Config,
        settings: S,
        crypto: C,
        mut rng: R,
    ) -> &mut Self {
        use core::ptr::addr_of_mut;

        let mut iid = [0u8; 8];
        rng.fill_bytes(&mut iid);
        let mac_seed = rng.next_u64();
        let prng_seed = rng.next_u64();
        let msg_seed = rng.next_u32() as u16;
        let mut iid_secret = [0u8; 32];
        rng.fill_bytes(&mut iid_secret);
        let leader_session_id = rng.next_u32() as u16;
        let mut ba_id = [0u8; 16];
        rng.fill_bytes(&mut ba_id);

        let ext = if config.ext_address == RANDOM_EXT_ADDRESS {
            let mut a = [0u8; 8];
            rng.fill_bytes(&mut a);
            a[0] = (a[0] | 0x02) & !0x01;
            ExtAddress(a)
        } else {
            config.ext_address
        };
        let p = slot.as_mut_ptr();
        // SAFETY: `p` is valid for writes of `Self`; every field of `Self`
        // and of `Core` is written exactly once below, then the value is
        // fully initialised. Each large component is built by `put` in its
        // own stack frame, straight into its field.
        unsafe {
            commissioning::Commissioning::init(
                addr_of_mut!((*p).cm),
                &crypto,
                ext,
                leader_session_id,
                ba_id,
            );
            let c = addr_of_mut!((*p).core);
            put(addr_of_mut!((*c).mac), || {
                let keys = KeyManager::new(crypto.clone(), api::placeholder_key());
                Mac::new(config.radio, ext, keys, MacRng::new(mac_seed))
            });
            let cur = opentrust_meshcop::manager::CurrentConfig {
                channel: (*c).mac.channel(),
                pan_id: (*c).mac.pan_id().0,
                mesh_local_prefix: opentrust_core::types::Prefix64([0xfd, 0, 0, 0, 0, 0, 0, 0]),
                network_key: api::placeholder_key(),
            };
            addr_of_mut!((*c).rng).write(rng);
            addr_of_mut!((*c).settings).write(settings);
            addr_of_mut!((*c).crypto).write(crypto);
            addr_of_mut!((*c).now).write(Instant::ZERO);
            addr_of_mut!((*c).ext).write(ext);
            addr_of_mut!((*c).ml_iid).write(Iid(iid));
            addr_of_mut!((*c).role).write(Role::Disabled);
            put(addr_of_mut!((*c).ip6), || {
                let mut ip6 = Ip6::new();
                let _ = ip6.netif.set_link_local(&ext);
                ip6
            });
            put(addr_of_mut!((*c).netdata), NetData::new);
            put(addr_of_mut!((*c).datasets), Datasets::new);
            addr_of_mut!((*c).cfg).write(NetConfig {
                cur,
                ext_pan_id: None,
                network_name: None,
                pskc: None,
                policy: None,
                ds_events: Deque::new(),
                nd_version_bump: false,
                applied: false,
                key_changed: false,
                policy_changed: false,
            });
            put(addr_of_mut!((*c).mle_events), Deque::new);
            addr_of_mut!((*c).child_changes).write(Deque::new());
            addr_of_mut!((*c).nd_rx).write(None);
            addr_of_mut!((*c).solicit).write(Deque::new());
            put(addr_of_mut!((*c).mle_out), Outbox::default);
            addr_of_mut!((*c).rx_link).write(opentrust_mle::endpoint::LinkRxInfo::default());
            addr_of_mut!((*c).parent).write(None);
            addr_of_mut!((*c).poll_period).write(None);
            addr_of_mut!((*c).user_poll_period).write(None);
            #[cfg(feature = "link-metrics-manager")]
            addr_of_mut!((*c).lmm).write(lmm::LinkMetricsManager::new());
            put(addr_of_mut!((*c).mactx), stack::MacTx::default);
            put(addr_of_mut!((*c).events), Deque::new);
            addr_of_mut!((*c).iid_secret).write(iid_secret);
            put(addr_of_mut!((*c).disc_rx), Deque::new);
            addr_of_mut!((*c).joiner_discovering).write(false);
            put(addr_of_mut!((*c).scan_rx), Deque::new);
            addr_of_mut!((*c).scanning).write(false);
            addr_of_mut!((*c).border_agent_port).write(None);

            put(addr_of_mut!((*p).mle), || Mle::new(config.mle));
            put(addr_of_mut!((*p).agent), || {
                let mut agent = TmfAgent::new(msg_seed);
                tmf::register_uris(&mut agent);
                agent
            });
            put(addr_of_mut!((*p).sink), Outbox::default);
            #[cfg(feature = "ftd")]
            put(addr_of_mut!((*p).solicit), RouterIdOutbox::new);
            addr_of_mut!((*p).prng).write(MacRng::new(prng_seed));
            put(addr_of_mut!((*p).udp), || {
                let mut udp = UdpSockets::new();
                let _ = udp.register_receiver(opentrust_net::udp::MLE_UDP_PORT, ReceiverId::MLE);
                let _ = udp.register_receiver(opentrust_net::ip6::TMF_UDP_PORT, ReceiverId::TMF);
                udp
            });
            put(addr_of_mut!((*p).resolver), AddressResolver::new);
            put(addr_of_mut!((*p).fwd), || {
                MeshForwarder::new(msg_seed ^ 0x5a5a)
            });
            #[cfg(feature = "ftd")]
            put(addr_of_mut!((*p).leader), Leader::new);
            put(addr_of_mut!((*p).local), LocalData::new);
            put(addr_of_mut!((*p).notifier), Notifier::new);
            put(addr_of_mut!((*p).publisher), Publisher::new);
            put(addr_of_mut!((*p).alocs), AlocSet::new);
            put(addr_of_mut!((*p).slaac), Slaac::new);
            put(addr_of_mut!((*p).glue), netdata_glue::GlueState::default);
            put(addr_of_mut!((*p).dnssrp), dns_srp::DnsSrp::new);
            put(addr_of_mut!((*p).dhcp6), dhcp6::Dhcp6::new);
            #[cfg(feature = "ftd")]
            put(
                addr_of_mut!((*p).updater),
                opentrust_meshcop::updater::DatasetUpdater::new,
            );
            put(addr_of_mut!((*p).bbrg), bbr::BbrGlue::new);
            put(addr_of_mut!((*p).diag_in), Deque::new);
            addr_of_mut!((*p).diag_query_id).write((prng_seed >> 16) as u16);
            addr_of_mut!((*p).tmf_ext).write(None);
            addr_of_mut!((*p).ping).write(api::PingState::default());
            put(addr_of_mut!((*p).scan), scan::ScanState::default);
            addr_of_mut!((*p).ip6_enabled).write(false);
            addr_of_mut!((*p).started).write(false);
            addr_of_mut!((*p).radio_filter).write(false);

            addr_of_mut!((*p).restore_pending).write(true);
            addr_of_mut!((*p).rloc_released).write(false);
            let inst = &mut *p;
            inst.restore_boot_identity();
            inst
        }
    }

    // ------------------------------------------------------------ driving

    /// Forget the RSS average of the neighbor with extended address `ext`
    /// (OT `Mac::Filter::ApplyToRxFrame`): a test radio whose MAC filter
    /// replaces the RSS of a frame calls this before delivering it.
    pub fn clear_neighbor_average_rss(&mut self, ext: &[u8; 8]) {
        self.mle
            .clear_neighbor_average_rss(&opentrust_core::types::ExtAddress(*ext));
    }

    /// Feed a received PSDU (with FCS) from the radio.
    pub fn handle_radio_rx(&mut self, psdu: &[u8], info: &PsduRxInfo, now: Instant) {
        self.core.now = now;
        if self.radio_filter {
            return;
        }
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

    /// The host lost the completion of the in-flight [`RadioAction::Transmit`]
    /// or [`RadioAction::EnergyScan`] (it dropped the future, which aborts the
    /// operation on the radio): treat it as aborted. No-op if none is in
    /// flight.
    pub fn abort_radio_in_flight(&mut self, now: Instant) {
        self.core.now = now;
        self.core.mac.abort_in_flight(now);
    }

    /// The next thing the radio has to do, if any. Call after
    /// [`poll`](Self::poll) until `None`.
    pub fn poll_radio_action(&mut self, now: Instant) -> Option<RadioAction> {
        self.core.now = now;
        loop {
            let a = self.core.mac.poll_action(now)?;
            if !self.radio_filter {
                return Some(a);
            }
            // Radio filter: a frame completes at once, as without an
            // acknowledgment when it asked for one (OT `SubMac::Send`).
            if let RadioAction::Transmit(tx) = &a {
                let ack = tx.psdu.first().is_some_and(|b| b & 0x20 != 0);
                let outcome = if ack {
                    TxOutcome::AckTimeout
                } else {
                    TxOutcome::Sent
                };
                self.core.mac.on_tx_done(outcome, now);
                continue;
            }
            if matches!(a, RadioAction::EnergyScan { .. }) {
                self.core
                    .mac
                    .on_energy_scan_done(opentrust_platform::radio::RSSI_INVALID, now);
                continue;
            }
            return Some(a);
        }
    }

    /// Enable or disable the radio filter (OT `otLinkSetRadioFilterEnabled`):
    /// while enabled, no frame is received and every transmission completes
    /// at once without an acknowledgment.
    pub fn set_radio_filter(&mut self, enabled: bool) {
        self.radio_filter = enabled;
    }

    /// The radio filter is enabled (OT `otLinkIsRadioFilterEnabled`).
    pub fn is_radio_filter_enabled(&self) -> bool {
        self.radio_filter
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
            busy |= self.service_dns_srp(now);
            busy |= self.service_bbr(now);
            busy |= self.service_commissioning(now);
            busy |= self.service_scan(now);
            #[cfg(feature = "link-metrics-manager")]
            {
                busy |= self.service_lmm(now);
            }
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
            self.scan.disc.next_deadline(),
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
            self.dnssrp.next_deadline(),
            self.dhcp6.next_deadline(),
            self.bbrg.next_deadline(),
            self.cm.next_deadline(),
            self.scan_servers_deadline(),
            self.lmm_deadline(),
        ]
        .into_iter()
        .flatten()
        .min();
        if self.has_pending_work() {
            d = Some(self.core.now);
        }
        d
    }

    #[cfg(feature = "link-metrics-manager")]
    fn lmm_deadline(&self) -> Option<Instant> {
        self.core.lmm.next_deadline()
    }

    #[cfg(not(feature = "link-metrics-manager"))]
    #[allow(clippy::unused_self)]
    const fn lmm_deadline(&self) -> Option<Instant> {
        None
    }

    #[cfg(feature = "scan-servers")]
    fn scan_servers_deadline(&self) -> Option<Instant> {
        self.scan.srv.next_deadline()
    }

    #[cfg(not(feature = "scan-servers"))]
    #[allow(clippy::unused_self)]
    fn scan_servers_deadline(&self) -> Option<Instant> {
        None
    }

    #[cfg(feature = "ftd")]
    fn leader_deadline(&self) -> Option<Instant> {
        [self.leader.next_deadline(), self.cm.leader.next_deadline()]
            .into_iter()
            .flatten()
            .min()
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
        !self.core.mle_out.is_empty()
            || !self.core.scan_rx.is_empty()
            || !self.sink.is_empty()
            || !self.core.mle_events.is_empty()
            || !self.core.child_changes.is_empty()
            || self.core.nd_rx.is_some()
            || !self.core.solicit.is_empty()
            || self.solicit_pending()
            || !self.core.cfg.ds_events.is_empty()
            || self.core.cfg.applied
            || self.dnssrp.has_pending_work()
            || self.bbrg.has_pending_work()
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

#[cfg(test)]
mod size_test;

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

    fn instance_with(cfg: Config, seed: u64) -> Instance<RamSettings<2048>, SoftCrypto, MacRng> {
        Instance::new(cfg, RamSettings::new(), SoftCrypto, MacRng::new(seed))
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

    /// The MLE's CSL requests reach the MAC and an SSED frame carries the
    /// CSL IE.
    #[test]
    fn csl_parameters_reach_the_mac() {
        use opentrust_core::types::ShortAddress;
        use opentrust_mle::MleEnv;
        use opentrust_platform::radio::RadioClock;

        let caps = RadioCaps {
            clock: Some(RadioClock(|| 1_000_000)),
            csl_accuracy_ppm: 20,
            csl_uncertainty: 10,
            ..RadioCaps::default()
        };
        let cfg = Config::sleepy_end_device(ExtAddress([2, 0, 0, 0, 0, 0, 0, 5]), caps);
        let mut i = Instance::new(cfg, RamSettings::<2048>::new(), SoftCrypto, MacRng::new(1));
        let parent = (ExtAddress([2, 0, 0, 0, 0, 0, 0, 1]), Rloc16(0x0400));
        MleEnv::set_csl(&mut i.core, 3125, 0, Some(parent));
        assert_eq!(i.core.mac.csl_period(), 3125);
        let acc = MleEnv::csl_clock_accuracy(&i.core).unwrap();
        assert_eq!((acc.accuracy_ppm, acc.uncertainty_10us), (20, 10));
        // A frame to the parent now has a CSL IE.
        let mut sink = crate::datapath::sink_for_tests(&mut i.core);
        let f = opentrust_mesh::forwarder::TxFrame {
            src: opentrust_mac::frame::Address::Short(ShortAddress(0x0401)),
            dst: opentrust_mesh::forwarder::MacDest::Short(parent.1),
            payload: &[0x7a, 1, 2, 3],
            security: opentrust_core::types::LinkSecurity::None,
            frame_pending: false,
            indirect: false,
            csl: false,
            radio: Default::default(),
        };
        opentrust_mesh::forwarder::FrameSink::transmit(&mut sink, &f).unwrap();
        MleEnv::set_csl(&mut i.core, 0, 0, None);
        assert_eq!(i.core.mac.csl_period(), 0);
    }

    /// Discovery and Announce frames use the channel and PAN ID of their
    /// transmit options.
    #[test]
    fn transmit_options_channel_and_pan_are_honoured() {
        use opentrust_mle::MleEnv;
        let mut i = instance();
        let now = Instant::from_secs(10);
        let ds = i.create_dataset(15).unwrap();
        i.set_active_dataset(&ds, now).unwrap();
        i.ip6_set_enabled(true);
        i.become_leader(now).unwrap();
        i.poll(now);
        while i.poll_radio_action(now).is_some() {}
        let opts = opentrust_mle::env::TxOptions {
            channel: Some(21),
            pan_id: Some(0xbeef),
            link_security: false,
        };
        let src = opentrust_core::types::ipv6::link_local(&ExtAddress([2, 0, 0, 0, 0, 0, 0, 1]));
        let dst = opentrust_core::types::ipv6::LINK_LOCAL_ALL_ROUTERS;
        MleEnv::send_with(&mut i.core, &opts, src, dst, &[0xaa; 20]).unwrap();
        i.poll(now);
        let mut seen = false;
        let mut t = now;
        for _ in 0..50 {
            while let Some(a) = i.poll_radio_action(t) {
                if let RadioAction::Transmit(tx) = a {
                    if tx.channel == 21 {
                        let f = opentrust_mac::frame::Frame::parse(&tx.psdu[..tx.psdu.len() - 2])
                            .unwrap();
                        if f.dst_pan_id().map(|p| p.0) == Some(0xbeef) {
                            seen = true;
                        }
                    }
                    // Other frames (Advertisements) finish, so that the
                    // queue moves on.
                    i.handle_radio_tx_done(opentrust_mac::mac::TxOutcome::Sent, t);
                }
            }
            if seen {
                break;
            }
            t += Duration::from_millis(20);
            i.poll(t);
        }
        assert!(seen);
    }

    #[test]
    fn identity_is_restored_at_creation() {
        let mut i = instance();
        let now = Instant::from_secs(10);
        let ds = i.create_dataset(15).unwrap();
        i.set_active_dataset(&ds, now).unwrap();
        i.ip6_set_enabled(true);
        i.become_leader(now).unwrap();
        i.poll(now);
        let (ext, ml_eid) = (i.ext_address(), i.ml_eid());
        let settings = i.into_settings();
        // After a reset the instance starts with a random address and takes
        // the stored one before Thread starts.
        let cfg = Config::router(RANDOM_EXT_ADDRESS, RadioCaps::default());
        let i2 = Instance::new(cfg.clone(), settings, SoftCrypto, MacRng::new(7));
        assert_eq!(i2.role(), Role::Disabled);
        assert_eq!(i2.ext_address(), ext);
        // The prefix comes with the dataset at start; the IID is restored.
        assert_eq!(i2.ml_eid().octets()[8..], ml_eid.octets()[8..]);
    }

    #[test]
    fn random_ext_address_without_stored_network() {
        let cfg = Config::router(RANDOM_EXT_ADDRESS, RadioCaps::default());
        let a = instance_with(cfg.clone(), 1).ext_address();
        let b = instance_with(cfg, 2).ext_address();
        assert_ne!(a, RANDOM_EXT_ADDRESS);
        assert_ne!(a, b);
        // Locally administered, unicast.
        assert_eq!(a.0[0] & 0x03, 0x02);
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
