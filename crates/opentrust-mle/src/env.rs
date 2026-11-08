//! The environment of the MLE core: everything it needs from, and does to,
//! the rest of the stack.
//!
//! # Design: context passing
//!
//! The MLE core ([`Mle`](crate::Mle)) is *sans-IO* and owns only MLE state:
//! role, attach state machine, parent / candidate / children, the outgoing
//! MLE frame counter, timers (as [`Instant`](opentrust_core::time::Instant) deadlines). Everything that is
//! owned elsewhere is reached through the [`MleEnv`] trait, which the caller
//! implements on a small struct borrowing the pieces (`&mut KeyManager`,
//! `&mut Mac`, `&mut Netif`, the UDP sink, the settings store, an RNG). The
//! future `Instance` (Phase 10) implements it once for its fields; unit tests
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
use opentrust_core::time::Duration;
use opentrust_core::types::{ExtAddress, Iid, Prefix64, Rloc16};
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
}

/// Maximum number of non-ML-EID addresses reported by
/// [`MleEnv::registered_addresses`].
pub const MAX_REGISTERED_ADDRESSES: usize = 4;

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

    // ------------------------------------------------------------ MAC / netif

    /// Set the MAC short address ([`Rloc16::INVALID`] clears it) and the
    /// RLOC / locator addresses derived from it.
    fn set_short_address(&mut self, rloc16: Rloc16);
    /// Receiver on when idle (`false` for sleepy end devices).
    fn set_rx_on_when_idle(&mut self, on: bool);
    /// Parent for data polls and indirect transmission (`None` clears).
    fn set_parent(&mut self, parent: Option<(ExtAddress, Rloc16)>);
    /// Data poll period for sleepy end devices (`None` = no polling).
    fn set_poll_period(&mut self, period: Option<Duration>);
    /// Poll quickly while attaching (OT `DataPollSender::SetAttachMode`).
    fn set_poll_attach_mode(&mut self, _fast: bool) {}
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

    /// Send a child supervision message (an empty frame / message that
    /// makes the sleepy child's data poll succeed) to a sleepy child.
    fn send_child_supervision(&mut self, _ext: &ExtAddress, _rloc16: Rloc16) {}

    // ------------------------------------------------------------ network data / dataset (Phase 7/8 consumers)

    /// Full or stable (`stable_only`) Network Data for a Child ID /
    /// Data Response; returns the length, `Ok(0)` if none.
    fn network_data(&self, _stable_only: bool, _out: &mut [u8]) -> Result<usize> {
        Ok(0)
    }
    /// Store Network Data received from the parent, together with the
    /// Leader Data that versions it (parsing is Phase 7).
    fn set_network_data(&mut self, _leader: &LeaderData, _data: &[u8]) {}
    /// Timestamp of the local Active Operational Dataset.
    fn active_timestamp(&self) -> Option<Timestamp> {
        None
    }
    /// Timestamp of the local Pending Operational Dataset.
    fn pending_timestamp(&self) -> Option<Timestamp> {
        None
    }
    /// The Active Operational Dataset TLVs for a Child ID Response.
    fn active_dataset(&self, _out: &mut [u8]) -> Result<usize> {
        Ok(0)
    }
    /// The Pending Operational Dataset TLVs for a Child ID Response.
    fn pending_dataset(&self, _out: &mut [u8]) -> Result<usize> {
        Ok(0)
    }
    /// Datasets received in a Child ID Response / Data Response.
    fn dataset_received(
        &mut self,
        _active: Option<(Timestamp, Option<&[u8]>)>,
        _pending: Option<(Timestamp, Option<&[u8]>)>,
    ) {
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

    // ------------------------------------------------------------ notifications

    /// Notification, see [`MleEvent`].
    fn event(&mut self, _event: MleEvent) {}
}
