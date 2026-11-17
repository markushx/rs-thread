//! The environment of the MLE core: everything it needs from, and does to,
//! the rest of the stack.
//!
//! # Design: context passing
//!
//! The MLE core ([`Mle`](crate::Mle)) is *sans-IO* and owns only MLE state:
//! role, attach state machine, parent / candidate / children, the outgoing
//! MLE frame counter, timers (as [`Instant`] deadlines). Everything that is
//! owned elsewhere is reached through the [`MleEnv`] trait, which the caller
//! implements on a small struct borrowing the pieces (`&mut KeyManager`,
//! `&mut Mac`, `&mut Netif`, the UDP sink, the settings store, an RNG). The
//! future `Instance` (public API) implements it once for its fields; unit tests
//! implement it on a plain struct.
//!
//! This keeps ownership flat (no `Rc`/`RefCell`, no back-references),
//! lets the borrow checker see which subsystems an operation touches, and
//! makes the MLE state machine testable with two [`Mle`](crate::Mle) values
//! and two fake environments.
//!
//! Time and randomness: `now` is a parameter of every entry point
//! ([`Mle::receive`](crate::Mle::receive), [`Mle::poll`](crate::Mle::poll),
//! ...); [`Mle::next_deadline`](crate::Mle::next_deadline) tells the caller
//! when to call `poll` again. Random numbers come from
//! [`MleEnv::fill_random`].
//!
//! Policy points that OpenThread handles with direct calls into other
//! modules (MAC short address, poll period, rx-on-when-idle, address list,
//! indirect queue for sleepy children, Network Data / dataset store,
//! settings) are methods here; the optional ones have no-op defaults.

use core::net::Ipv6Addr;

use opentrust_core::Result;
use opentrust_core::crypto::CryptoBackend;
use opentrust_core::settings::{ChildInfo, NetworkInfo, ParentInfo};
use opentrust_core::time::{Duration, Instant};
use opentrust_core::types::{ExtAddress, ExtPanId, Iid, Prefix64, Rloc16};
use opentrust_mac::security::KeyManager;

use crate::tlv::{LeaderData, Timestamp};

/// Thread device role (OT `DeviceRole`; the numeric values are what
/// `NetworkInfo::role` stores).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(u8)]
pub enum Role {
    /// Thread is not running.
    #[default]
    Disabled = 0,
    /// Not attached to a partition.
    Detached = 1,
    /// End device (or REED) attached to a parent.
    Child = 2,
    /// Router.
    Router = 3,
    /// Leader.
    Leader = 4,
}

impl Role {
    /// Decode a stored role byte.
    pub const fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            0 => Self::Disabled,
            1 => Self::Detached,
            2 => Self::Child,
            3 => Self::Router,
            4 => Self::Leader,
            _ => return None,
        })
    }

    /// `Router` or `Leader`.
    pub const fn is_router_or_leader(self) -> bool {
        matches!(self, Self::Router | Self::Leader)
    }

    /// `Child`, `Router` or `Leader`.
    pub const fn is_attached(self) -> bool {
        matches!(self, Self::Child | Self::Router | Self::Leader)
    }
}

/// Notifications from the MLE core (OT `Notifier` events, reduced to what
/// the other layers act on).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MleEvent {
    /// The role changed.
    RoleChanged {
        /// Previous role.
        old: Role,
        /// New role.
        new: Role,
    },
    /// The RLOC16 changed (`INVALID` = none).
    Rloc16Changed(Rloc16),
    /// A parent was selected and accepted us (Child ID Response processed).
    Attached {
        /// Parent's extended address.
        parent: ExtAddress,
        /// Parent's RLOC16.
        parent_rloc16: Rloc16,
    },
    /// The parent was lost (timeouts, rejection); a re-attach follows.
    ParentLost,
    /// The device attached to a new parent: the previous parent (given by
    /// its RLOC16) is to be told so it drops the child (OT
    /// `InformPreviousParent`).
    InformPreviousParent {
        /// RLOC16 of the previous parent.
        rloc16: Rloc16,
    },
    /// Network Data of the given Leader Data was stored through
    /// [`MleEnv::set_network_data`].
    NetworkDataChanged,
    /// A child became valid (parent side).
    ChildAdded {
        /// Child's extended address.
        ext: ExtAddress,
        /// Child's RLOC16.
        rloc16: Rloc16,
    },
    /// A child was removed (timeout, rejection, detach).
    ChildRemoved {
        /// Child's extended address.
        ext: ExtAddress,
        /// Child's RLOC16.
        rloc16: Rloc16,
    },
    /// This device started a new partition as its leader (`BecomeLeader`);
    /// the Network Data of the new partition is empty.
    LeaderStarted {
        /// The new partition ID.
        partition_id: u32,
    },
    /// The partition ID changed (attach to another partition, merge,
    /// leader start). Router table, address cache and pending Address
    /// Solicit state of the old partition are void.
    PartitionChanged {
        /// The new partition ID.
        partition_id: u32,
    },
    /// A router link became valid (Link Accept processed).
    RouterAdded {
        /// Router's extended address.
        ext: ExtAddress,
        /// Router's RLOC16.
        rloc16: Rloc16,
    },
    /// A router link was removed (age, Link Accept timeout, router ID
    /// released).
    RouterRemoved {
        /// Router's extended address.
        ext: ExtAddress,
        /// Router's RLOC16.
        rloc16: Rloc16,
    },
    /// An Announce from a network with a newer Active Dataset arrived. After
    /// `ANNOUNCE_PROCESS_TIMEOUT` the device switches to that channel and
    /// PAN ID and attaches there (informational; no action required).
    AnnounceFromNewerNetwork {
        /// Channel of the announcing network.
        channel: u8,
        /// PAN ID of the announcing network.
        pan_id: u16,
        /// Its Active Timestamp.
        timestamp: Timestamp,
    },
    /// The router table changed (route costs, next hops, ID set): the
    /// routing layer should refresh what it derives from it.
    RouterTableChanged,
    /// A graceful detach finished (OT `DetachGracefully` callback): the
    /// role is now `Disabled`.
    DetachedGracefully,
}

/// MAC-level options of an outgoing MLE message (Discovery Request /
/// Response and Announce are sent on a specific channel / PAN ID; Announce
/// is protected by link-layer security).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TxOptions {
    /// Send on this channel instead of the PAN channel (OT
    /// `Message::SetChannel`).
    pub channel: Option<u8>,
    /// Destination PAN ID of the frame (OT `Message::SetPanId`); `None`:
    /// the current PAN ID.
    pub pan_id: Option<u16>,
    /// Protect the datagram with link-layer security as well.
    pub link_security: bool,
}

/// A Discovery Request received by a router (Thread 1.4.1 section 4.13).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DiscoveryRequestInfo {
    /// Extended address of the sender.
    pub ext_address: ExtAddress,
    /// Thread version of the scanner (Discovery Request TLV); 0 if the TLV
    /// was missing.
    pub version: u8,
    /// The scanner is a Joiner.
    pub joiner: bool,
    /// Source PAN ID of the frame.
    pub pan_id: Option<u16>,
}

/// Where a Discovery Response came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DiscoveryResponseInfo {
    /// Extended address of the responding router.
    pub ext_address: ExtAddress,
    /// PAN ID of the frame (the network's PAN ID).
    pub pan_id: Option<u16>,
    /// Channel the response was received on.
    pub channel: Option<u8>,
    /// RSS in dBm.
    pub rss: Option<i8>,
    /// LQI.
    pub lqi: Option<u8>,
}

/// Which stored Operational Dataset a reattach step restores.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum StoredDataset {
    /// The Active Operational Dataset.
    Active,
    /// The Pending Operational Dataset.
    Pending,
}

/// Why a REED asks the leader for a router ID (Thread Status TLV values of
/// the Address Solicit request, §5.19; OT `ThreadStatusTlv`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(u8)]
pub enum RouterRequestReason {
    /// Fewer routers than `ROUTER_UPGRADE_THRESHOLD`.
    TooFewRouters = 2,
    /// A child sent a Child ID Request and needs a router parent.
    HaveChildIdRequest = 3,
    /// The partition changed while the device has children.
    ParentPartitionChange = 4,
    /// A Border Router asks for the router role.
    BorderRouterRequest = 5,
}

impl RouterRequestReason {
    /// Decode a Status TLV value.
    pub const fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            2 => Self::TooFewRouters,
            3 => Self::HaveChildIdRequest,
            4 => Self::ParentPartitionChange,
            5 => Self::BorderRouterRequest,
            _ => return None,
        })
    }
}

/// The Address Solicit request the core wants sent to the leader (TMF
/// `/a/as`, see `opentrust-mesh::router_id`). The environment sends it to the leader's RLOC and
/// later calls [`Mle::address_solicit_reply`](crate::Mle::address_solicit_reply)
/// with the outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RouterIdRequest {
    /// Previously held router ID (its RLOC16 goes into the request).
    pub previous_router_id: Option<u8>,
    /// Reason / Status TLV.
    pub reason: RouterRequestReason,
}

/// Maximum number of non-ML-EID addresses reported by
/// [`MleEnv::registered_addresses`].
pub const MAX_REGISTERED_ADDRESSES: usize = 4;
/// Maximum number of multicast groups reported by
/// [`MleEnv::registered_multicast_addresses`].
pub const MAX_REGISTERED_MULTICAST_ADDRESSES: usize = 4;

/// What the MLE core needs from its surroundings. See the [module
/// documentation](self).
pub trait MleEnv {
    /// Crypto backend of the key manager.
    type Crypto: CryptoBackend;

    // ------------------------------------------------------------ keys, identity, randomness

    /// Key material and the outgoing MAC frame counter.
    fn keys(&self) -> &KeyManager<Self::Crypto>;
    /// Mutable access: key sequence adoption (OT `ProcessKeySequence`).
    fn keys_mut(&mut self) -> &mut KeyManager<Self::Crypto>;
    /// This node's extended address.
    fn ext_address(&self) -> ExtAddress;
    /// Cryptographic or at least well-distributed random bytes (challenges,
    /// jitter).
    fn fill_random(&mut self, buf: &mut [u8]);
    /// Receiver noise floor in dBm used for link margin computation (OT
    /// `Mac::GetNoiseFloor`; default -100).
    fn noise_floor(&self) -> i8 {
        -100
    }

    // ------------------------------------------------------------ transmit

    /// Send a fully secured MLE datagram (UDP payload) from the link-local
    /// address `src` to `dst`, port 19788 -> 19788, hop limit 255. The core
    /// already applied [`endpoint`](crate::endpoint) addressing rules and
    /// MLE security; the caller wraps it into UDP/IPv6 (for example with
    /// [`UdpSink`](opentrust_coap::tmf::UdpSink)).
    fn send(&mut self, src: Ipv6Addr, dst: Ipv6Addr, payload: &[u8]) -> Result<()>;

    /// Like [`send`](Self::send) with MAC-level options (channel, PAN ID,
    /// link security). Default: the options are ignored.
    fn send_with(
        &mut self,
        _opts: &TxOptions,
        src: Ipv6Addr,
        dst: Ipv6Addr,
        payload: &[u8],
    ) -> Result<()> {
        self.send(src, dst, payload)
    }

    // ------------------------------------------------------------ MAC / netif

    /// Current PAN ID (for Announce).
    fn pan_id(&self) -> u16 {
        0xffff
    }
    /// Current PAN channel (for Announce).
    fn pan_channel(&self) -> u8 {
        11
    }
    /// Switch the MAC to `channel` and `pan_id` (Announce attach: moving to
    /// the announced network and, if attaching there fails, back; OT
    /// `Mac::SetPanChannel` / `SetPanId`). Default: no-op.
    fn set_pan_channel_and_id(&mut self, _channel: u8, _pan_id: u16) {}
    /// Channels (bit `n` = channel `n`) an Orphan Announce is sent on while
    /// attaching: the channel mask of the Active Dataset, else the supported
    /// channels. Default: channels 11 to 26.
    fn announce_channel_mask(&self) -> u32 {
        0x07ff_f800
    }
    /// Extended PAN ID of the Active Operational Dataset, if any.
    fn ext_pan_id(&self) -> Option<ExtPanId> {
        None
    }

    /// Set the MAC short address ([`Rloc16::INVALID`] clears it) and the
    /// RLOC / locator addresses derived from it.
    fn set_short_address(&mut self, rloc16: Rloc16);
    /// Receiver on when idle (`false` for sleepy end devices).
    fn set_rx_on_when_idle(&mut self, on: bool);
    /// Parent for data polls and indirect transmission (`None` clears).
    fn set_parent(&mut self, parent: Option<(ExtAddress, Rloc16)>);
    /// Data poll period for sleepy end devices (`None` = no polling).
    fn set_poll_period(&mut self, period: Option<Duration>);
    /// A sleepy device waits for the Child ID Response of `candidate`: poll
    /// it by its extended address at the attach poll period (OT
    /// `SendChildIdRequest`: `SetAttachMode(true)`); `None` ends it and
    /// stops polling. The receiver stays on (OT turns it off here), so that
    /// a parent that sends the response directly is heard too. Default:
    /// no-op.
    fn set_attach_polling(&mut self, _candidate: Option<ExtAddress>) {}
    /// A sleepy device that restored its state after a reset waits for the
    /// Child Update Response of its parent: poll it at the attach poll period
    /// with the addressing the parent knows the child by (short addresses:
    /// the parent's source match entry for the child is a short address one,
    /// and a poll by extended address would not be acknowledged with the
    /// frame pending bit). Default: [`set_attach_polling`](Self::set_attach_polling)
    /// by extended address.
    fn set_restore_polling(&mut self, parent_ext: ExtAddress, _parent_rloc16: Rloc16) {
        self.set_attach_polling(Some(parent_ext));
    }
    /// Poll quickly while attaching (OT `DataPollSender::SetAttachMode`).
    fn set_poll_attach_mode(&mut self, _fast: bool) {}
    /// Poll the parent a few times at the fast poll period, e.g. after a
    /// Data Request (OT `DataPollSender::SendFastPolls`). Default: no-op.
    fn send_fast_polls(&mut self) {}
    /// Configure CSL reception of a synchronized sleepy child: sample the
    /// channel every `period` (units of 10 symbols) on `channel` (0 = the
    /// PAN channel), the parent being `parent` (extended and short address);
    /// `period` 0 (and `None`) turns CSL off. OT `SubMac::SetCslParams`.
    /// Default: no-op.
    fn set_csl(&mut self, _period: u16, _channel: u8, _parent: Option<(ExtAddress, Rloc16)>) {}
    /// The parent's CSL clock accuracy and uncertainty, from its CSL Clock
    /// Accuracy TLV (sizes the receive window). Default: no-op.
    fn set_csl_parent_accuracy(&mut self, _accuracy: crate::tlv::CslClockAccuracy) {}
    /// Mesh-local prefix (to build the ML-EID address and expand registered
    /// addresses).
    fn mesh_local_prefix(&self) -> Prefix64;
    /// ML-EID address of this node.
    fn ml_eid(&self) -> Ipv6Addr;
    /// Unicast addresses besides link-local, RLOC and ML-EID that a sleepy
    /// child registers with its parent (OT `AppendAddressRegistrationTlv`
    /// "all addresses"), at most [`MAX_REGISTERED_ADDRESSES`]; call `f` for
    /// each.
    fn registered_addresses(&self, _f: &mut dyn FnMut(Ipv6Addr)) {}
    /// Multicast groups larger than realm-local this device listens to,
    /// registered with the parent for Multicast Listener Registration
    /// (at most [`MAX_REGISTERED_MULTICAST_ADDRESSES`]); call `f` for each.
    fn registered_multicast_addresses(&self, _f: &mut dyn FnMut(Ipv6Addr)) {}
    /// 6LoWPAN context prefix for `context_id` (to expand compressed
    /// Address Registration entries; id 0 is the mesh-local prefix, handled
    /// by the core). Default: none known.
    fn lowpan_context(&self, _context_id: u8) -> Option<Prefix64> {
        None
    }
    /// 6LoWPAN context id whose prefix covers `addr` (to compress outgoing
    /// Address Registration entries). Default: none, send uncompressed.
    fn lowpan_context_for(&self, _addr: &Ipv6Addr) -> Option<u8> {
        None
    }

    // ------------------------------------------------------------ children (parent side)

    /// A sleepy child became valid: start indirect transmission / source
    /// address matching for it.
    fn indirect_add_child(&mut self, _ext: &ExtAddress, _rloc16: Rloc16) {}
    /// A sleepy child was removed: drop its indirect messages and
    /// source-match entries.
    fn indirect_remove_child(&mut self, _ext: &ExtAddress, _rloc16: Rloc16) {}
    /// Clock accuracy and uncertainty of this device's radio, reported to
    /// CSL children in the CSL Clock Accuracy TLV (OT
    /// `Radio::GetCslAccuracy` / `GetCslUncertainty`). `None` (the default):
    /// this device cannot transmit CSL frames and omits the TLV.
    fn csl_clock_accuracy(&self) -> Option<crate::tlv::CslClockAccuracy> {
        None
    }
    /// A child announced its CSL channel (0 = the PAN channel): track it for
    /// CSL transmissions on that channel (its CSL IEs synchronize it).
    fn csl_child_update(&mut self, _ext: &ExtAddress, _rloc16: Rloc16, _channel: u8) {}
    /// A child is no longer CSL synchronized (CSL synchronized timeout,
    /// mode change, removal): its frames wait for data polls again.
    fn csl_child_desync(&mut self, _ext: &ExtAddress, _rloc16: Rloc16) {}

    /// Send a child supervision message (an empty frame / message that
    /// makes the sleepy child's data poll succeed) to a sleepy child.
    fn send_child_supervision(&mut self, _ext: &ExtAddress, _rloc16: Rloc16) {}

    // ------------------------------------------------------------ network data / dataset

    /// Full or stable (`stable_only`) Network Data for a Child ID /
    /// Data Response; returns the length, `Ok(0)` if none.
    fn network_data(&self, _stable_only: bool, _out: &mut [u8]) -> Result<usize> {
        Ok(0)
    }
    /// Store Network Data received from the parent, together with the
    /// Leader Data that versions it (the core does not parse it).
    fn set_network_data(&mut self, _leader: &LeaderData, _data: &[u8]) {}
    /// Timestamp of the Active Operational Dataset of the network (OT
    /// `ActiveDatasetManager::GetTimestamp`).
    fn active_timestamp(&self) -> Option<Timestamp> {
        None
    }
    /// Timestamp of the local Pending Operational Dataset.
    fn pending_timestamp(&self) -> Option<Timestamp> {
        None
    }
    /// The Active Operational Dataset TLVs for a Child ID Response (without
    /// the Active Timestamp TLV).
    fn active_dataset(&self, _now: Instant, _out: &mut [u8]) -> Result<usize> {
        Ok(0)
    }
    /// The Pending Operational Dataset TLVs for a Child ID Response.
    fn pending_dataset(&self, _now: Instant, _out: &mut [u8]) -> Result<usize> {
        Ok(0)
    }
    /// `true` if the Active Dataset holds at least the network key, channel
    /// and PAN ID (OT `IsPartiallyComplete`). Defaults to "an Active
    /// Timestamp is known".
    fn active_dataset_partially_complete(&self) -> bool {
        self.active_timestamp().is_some()
    }
    /// Reload a stored Operational Dataset from non-volatile memory (OT
    /// `DatasetManager::Restore`; for the Active Dataset this applies its
    /// configuration: channel, PAN ID, network key). Returns `false` if none
    /// is stored.
    fn restore_dataset(&mut self, _now: Instant, _which: StoredDataset) -> bool {
        false
    }
    /// Apply the configuration of the (restored) Pending Dataset: channel,
    /// PAN ID, network key (OT `PendingDatasetManager::ApplyConfiguration`).
    fn apply_pending_configuration(&mut self, _now: Instant) {}
    /// Delete the Pending Dataset (OT `PendingDatasetManager::Clear`).
    fn clear_pending_dataset(&mut self, _now: Instant) {}
    /// `true` once if applying a dataset changed the network key. MLE then
    /// forgets the neighbors' incoming key sequence and frame counters
    /// ([`Mle::reset_frame_counters`](crate::Mle::reset_frame_counters), OT
    /// `KeyManager::ResetFrameCounters`).
    fn take_network_key_changed(&mut self) -> bool {
        false
    }
    /// Datasets received in a Child ID Response / Data Response.
    fn dataset_received(
        &mut self,
        _now: Instant,
        _active: Option<(Timestamp, Option<&[u8]>)>,
        _pending: Option<(Timestamp, Option<&[u8]>)>,
    ) {
    }

    // ------------------------------------------------------------ link metrics

    /// A Link Metrics Report arrived from `from` (OT Initiator report
    /// callback): `values` unless the Subject answered with `status` only.
    fn link_metrics_report(
        &mut self,
        _from: &Ipv6Addr,
        _values: Option<&crate::link_metrics::MetricsValues>,
        _status: crate::link_metrics::Status,
    ) {
    }
    /// The Subject `from` answered a Link Metrics Management Request with
    /// `status`.
    fn link_metrics_management_response(
        &mut self,
        _from: &Ipv6Addr,
        _status: crate::link_metrics::Status,
    ) {
    }
    /// Link metrics decoded from the Enhanced ACKs of a neighbor (see
    /// `Mle::process_enh_ack_ie_data`).
    fn enh_ack_probing_report(
        &mut self,
        _rloc16: Rloc16,
        _ext: &ExtAddress,
        _values: &crate::link_metrics::MetricsValues,
    ) {
    }
    /// Subject side of Enhanced-ACK probing: configure (non-empty `flags`)
    /// or clear (empty) the metrics the radio puts into the ACKs to the
    /// neighbor (OT `Radio::ConfigureEnhAckProbing`). Default: not
    /// supported.
    fn configure_enh_ack_probing(
        &mut self,
        _flags: opentrust_mac::mac::LinkMetricsFlags,
        _rloc16: Rloc16,
        _ext: &ExtAddress,
    ) -> Result<()> {
        Err(opentrust_core::Error::NotImplemented)
    }

    /// Initiator side of Enhanced-ACK probing: the neighbor was asked to
    /// report `flags` (empty: nothing) in its Enhanced ACKs. The MAC decodes
    /// them and frames to this neighbor use Frame Version 2015 (OT
    /// `Neighbor::IsEnhAckProbingActive`). Default: ignore.
    fn track_enh_ack_probing(
        &mut self,
        _flags: opentrust_mac::mac::LinkMetricsFlags,
        _rloc16: Rloc16,
        _ext: &ExtAddress,
    ) {
    }

    // ------------------------------------------------------------ discovery

    /// A Discovery Request arrived at an eligible router: should it be
    /// answered? (OT: a Joiner is only answered while Network Data has
    /// non-empty Steering Data, `IsJoiningAllowed`.) Default: yes.
    fn accept_discovery_request(&mut self, _info: &DiscoveryRequestInfo) -> bool {
        true
    }
    /// The sub-TLVs of the Thread Discovery TLV of a Discovery Response
    /// (MeshCoP Discovery Response, Extended PAN ID, Network Name,
    /// Steering Data, Joiner UDP Port, ...). Default: none, no response is
    /// sent.
    fn discovery_response(&mut self, _out: &mut [u8]) -> Result<usize> {
        Err(opentrust_core::Error::NotImplemented)
    }
    /// A Discovery Response arrived (also while the device is disabled):
    /// `tlvs` are the sub-TLVs of the Thread Discovery TLV.
    fn discovery_response_received(&mut self, _info: &DiscoveryResponseInfo, _tlvs: &[u8]) {}
    /// With an Announce from a network whose Active Timestamp is newer:
    /// should it be ignored because a Pending Dataset with at least that
    /// Active Timestamp is about to be applied? (OT
    /// `kAnnounceBackoffForPendingDataset`.) Default: no.
    fn pending_dataset_applies_soon(&self, _announced: &Timestamp) -> bool {
        false
    }

    // ------------------------------------------------------------ persistence (SettingsStore)

    /// Apply the identity restored from settings before the first message
    /// is sent: set the extended address and the ML-EID interface
    /// identifier (OT `Mle::Restore`).
    fn apply_restored_identity(&mut self, _ext: &ExtAddress, _ml_iid: &Iid) {}
    /// Persist the network information (`SettingsKey::NetworkInfo`).
    fn store_network_info(&mut self, _info: &NetworkInfo) -> Result<()> {
        Ok(())
    }
    /// Read the persisted network information.
    fn load_network_info(&self) -> Option<NetworkInfo> {
        None
    }
    /// Persist (`Some`) or delete (`None`) the parent information.
    fn store_parent_info(&mut self, _info: Option<&ParentInfo>) -> Result<()> {
        Ok(())
    }
    /// Read the persisted parent information.
    fn load_parent_info(&self) -> Option<ParentInfo> {
        None
    }
    /// Add or update the persisted record of a child (keyed by extended
    /// address).
    fn store_child_info(&mut self, _info: &ChildInfo) -> Result<()> {
        Ok(())
    }
    /// Delete the persisted record of the child with this extended address.
    fn delete_child_info(&mut self, _ext: &ExtAddress) -> Result<()> {
        Ok(())
    }
    /// Delete all persisted child records.
    fn clear_child_infos(&mut self) -> Result<()> {
        Ok(())
    }
    /// The persisted child record at `index`.
    fn load_child_info(&self, _index: usize) -> Option<ChildInfo> {
        None
    }

    // ------------------------------------------------------------ router ID assignment (TMF)

    /// Send an Address Solicit (`/a/as`, confirmable POST to the leader's
    /// RLOC) with the ML-EUI64 (the extended address), the previous RLOC16
    /// if any and the Status TLV. The answer is delivered with
    /// `Mle::address_solicit_reply`. Return an error if the request cannot
    /// be sent (the core then clears its pending state). Default: not
    /// implemented, so a device never upgrades without the TMF client.
    fn request_router_id(&mut self, _request: &RouterIdRequest) -> Result<()> {
        Err(opentrust_core::Error::NotImplemented)
    }
    /// Also accept frames addressed to `rloc16` (the former child RLOC16 of a
    /// REED that became a router) or stop doing so (`None`); OT
    /// `Mac::SetAlternateShortAddress`. Default: no-op.
    fn set_alternate_short_address(&mut self, _rloc16: Option<Rloc16>) {}
    /// Send an Address Release (`/a/ar`) for `rloc16` to the leader (router
    /// downgrade). Default: nothing is sent.
    fn release_router_id(&mut self, _rloc16: Rloc16) {}

    // ------------------------------------------------------------ notifications

    /// Notification, see [`MleEvent`].
    fn event(&mut self, _event: MleEvent) {}
}
