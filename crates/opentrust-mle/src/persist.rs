//! Persistence and fast re-attach (Thread 1.4.1 §4.7.7; OpenThread
//! `Mle::Store`, `Mle::Restore`, `Mle::Start` after restore,
//! `ChildTable::Restore`).
//!
//! Records (layouts in [`opentrust_core::settings`]):
//!
//! | record | content | written |
//! |--------|---------|---------|
//! | `NetworkInfo` | role, mode, RLOC16, key sequence, MLE and MAC frame counters (stored ahead), previous partition ID, extended address, ML-EID IID, version | [`Mle::store`] on role/RLOC16 change and when a frame counter reaches its stored value |
//! | `ParentInfo` | parent's extended address and version | with `NetworkInfo`, while a child |
//! | `ChildInfo` | one per child | when a child becomes valid or changes, deleted on removal (parent side) |
//!
//! The core never touches the settings store directly: the environment
//! implements [`MleEnv::store_network_info`] and friends over a
//! `SettingsStore` and flash-write policy of its choosing; the core calls
//! [`Mle::store_if_needed`] at the end of [`Mle::receive`] and
//! [`Mle::poll`] so the counters are persisted ahead of use.
//!
//! # Restore
//!
//! [`Mle::restore`] re-establishes key sequence, frame counters, device
//! mode, short address, extended address and ML-EID, then, for a saved
//! *child*, makes the parent a `Restored` neighbor and sends it a Child
//! Update Request (with a Challenge) instead of attaching from scratch. A
//! parent that answers puts the child back in the `Child` role with the
//! old RLOC16 within one round trip; a parent that stays silent (4 retries,
//! 1 s apart) makes the device detach and attach normally.
//!
//! A saved *router/leader* (feature `ftd`) keeps its RLOC16 and starts the
//! router role restorer: multicast
//! Link Requests asking for Address16 and Route64; the first Link Accept
//! puts the device back in the router (or leader) role in its old
//! partition, [`Mle::restore_children`] having made the saved children
//! `Restored` (they get a Child Update Request once the role is entered).
//! Without an answer the device detaches and attaches (or starts a new
//! partition) as usual.

use opentrust_core::settings::{NetworkInfo, ParentInfo};
use opentrust_core::time::Instant;
use opentrust_core::types::{Rloc16, ipv6};
use opentrust_core::{Error, Result};

use crate::consts::THREAD_VERSION;
use crate::env::{MleEnv, Role};
use crate::mle::Mle;
use crate::neighbor::{NeighborState, Parent, Router};
use crate::tlv::DeviceMode;

/// Outcome of [`Mle::restore`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Restored {
    /// A child: the parent was restored and a Child Update Request sent.
    Child {
        /// Our RLOC16.
        rloc16: Rloc16,
    },
    /// A router or leader: identity and counters were restored and the
    /// router role restorer started (the role is entered once a neighbor
    /// answers).
    Router {
        /// Saved role.
        role: Role,
        /// Saved RLOC16.
        rloc16: Rloc16,
        /// Saved previous partition ID.
        previous_partition_id: u32,
    },
}

impl<const C: usize> Mle<C> {
    /// Previous partition ID (the partition we were in before the last
    /// partition change; persisted with `NetworkInfo`).
    pub fn previous_partition_id(&self) -> u32 {
        self.previous_partition_id
    }

    /// Set the previous partition ID persisted with `NetworkInfo`.
    pub fn set_previous_partition_id(&mut self, id: u32) {
        self.previous_partition_id = id;
    }

    /// Persist `NetworkInfo` (and `ParentInfo` for a child) now, with the
    /// frame counters stored ahead (OT `Mle::Store`). While not attached,
    /// only the key sequence and counters of an existing record are updated.
    pub fn store<E: MleEnv>(&mut self, env: &mut E) -> Result<()> {
        let mle_fc = self.mle_counter.to_store();
        let mac_fc = env.keys().frame_counter_to_store();
        let key_sequence = env.keys().key_sequence();
        let info = if self.role.is_attached() {
            NetworkInfo {
                role: self.role as u8,
                device_mode: self.cfg.mode.to_bits() & 0x0b,
                rloc16: self.rloc16,
                key_sequence,
                mle_frame_counter: mle_fc,
                mac_frame_counter: mac_fc,
                previous_partition_id: self.previous_partition_id,
                ext_address: env.ext_address(),
                ml_iid: ipv6::iid(&env.ml_eid()),
                version: THREAD_VERSION,
            }
        } else {
            let mut info = env.load_network_info().ok_or(Error::NotFound)?;
            info.key_sequence = key_sequence;
            info.device_mode = self.cfg.mode.to_bits() & 0x0b;
            info.mle_frame_counter = mle_fc;
            info.mac_frame_counter = mac_fc;
            info
        };
        env.store_network_info(&info)?;
        if self.role == Role::Child {
            if let Some(p) = &self.parent {
                env.store_parent_info(Some(&ParentInfo {
                    ext_address: p.router.neighbor.ext_address,
                    version: p.router.neighbor.version,
                }))?;
            }
        }
        self.mle_counter.stored(mle_fc);
        env.keys_mut().frame_counter_stored(mac_fc);
        self.store_pending = false;
        Ok(())
    }

    /// [`store`](Self::store) if something changed: role / RLOC16 / parent,
    /// key sequence, or a frame counter caught up with its stored value.
    pub fn store_if_needed<E: MleEnv>(&mut self, env: &mut E) {
        if !self.role.is_attached() {
            return;
        }
        if self.store_pending || self.mle_counter.needs_store() || env.keys().needs_store() {
            let _ = self.store(env);
        }
    }

    /// Restore from the persisted records (OT `Mle::Restore` followed by
    /// `Mle::Start`). Call on a stopped core before anything is sent.
    ///
    /// Errors: [`Error::NotFound`] without a usable record (the caller then
    /// starts fresh with [`start`](Self::start)); [`Error::InvalidState`] for
    /// a record of another Thread version or a role that is not attached.
    pub fn restore<E: MleEnv>(&mut self, env: &mut E, now: Instant) -> Result<Restored> {
        self.restore_inner(env, now, true)
    }

    /// [`restore`](Self::restore) for a device that already took the stored
    /// device mode with [`restore_device_mode`](Self::restore_device_mode)
    /// at boot and may have been given another mode since (OT restores at
    /// instance initialisation, a later `mode` command wins).
    pub fn restore_keeping_mode<E: MleEnv>(
        &mut self,
        env: &mut E,
        now: Instant,
    ) -> Result<Restored> {
        self.restore_inner(env, now, false)
    }

    /// Take the device mode from the stored network information bits (OT
    /// `Mle::Restore` at boot): the stored mode, including the FTD bit (a
    /// device configured with `mode -` stays a minimal device across a
    /// reset); an MTD build clears the FTD bit.
    pub fn restore_device_mode(&mut self, bits: u8) {
        let stored = DeviceMode::from_bits(bits);
        self.cfg.mode = DeviceMode::new(
            stored.rx_on_when_idle(),
            cfg!(feature = "ftd") && stored.full_thread_device(),
            stored.full_network_data(),
        );
    }

    fn restore_inner<E: MleEnv>(
        &mut self,
        env: &mut E,
        now: Instant,
        adopt_mode: bool,
    ) -> Result<Restored> {
        if self.role != Role::Disabled {
            return Err(Error::Already);
        }
        let info = env.load_network_info().ok_or(Error::NotFound)?;
        env.keys_mut()
            .restore(info.key_sequence, info.mac_frame_counter);
        // The restored key sequence is not a key switch: keep the stored
        // counter.
        self.mle_counter.sync(env.keys().key_epoch());
        self.mle_counter.restore(info.mle_frame_counter);
        if info.version != THREAD_VERSION {
            return Err(Error::InvalidState);
        }
        let role = Role::from_u8(info.role)
            .filter(|r| r.is_attached())
            .ok_or(Error::InvalidState)?;
        if adopt_mode {
            self.restore_device_mode(info.device_mode);
        }
        env.apply_restored_identity(&info.ext_address, &info.ml_iid);
        // OT `Mle::Start(kNormalAttach)`: a failed restore (no answer from
        // the parent or routers) continues with the stored Active Dataset
        // and then the stored Pending Dataset, whose channel / PAN ID the
        // network may have moved to while this device was off.
        self.attach.reattach = crate::attach::ReattachState::Start;
        if role.is_router_or_leader() {
            if !self.cfg.mode.full_thread_device() {
                return Err(Error::InvalidState);
            }
            #[cfg(feature = "ftd")]
            {
                self.previous_partition_id = info.previous_partition_id;
                self.set_role(env, Role::Detached);
                self.set_rloc16(env, info.rloc16);
                env.keys_mut().start(now);
                self.attach.counter = 0;
                self.restore_router(env, now, role, info.rloc16);
            }
            return Ok(Restored::Router {
                role,
                rloc16: info.rloc16,
                previous_partition_id: info.previous_partition_id,
            });
        }
        if info.rloc16 == Rloc16::INVALID || info.rloc16.is_router() {
            return Err(Error::InvalidState);
        }
        let pinfo = env.load_parent_info().ok_or(Error::NotFound)?;
        let mut router = Router::new(info.rloc16.router_id(), pinfo.ext_address, now);
        router.neighbor.rloc16 = info.rloc16.parent();
        router.neighbor.version = pinfo.version;
        router.neighbor.mode = DeviceMode::new(true, true, true);
        router.neighbor.state = NeighborState::Restored;
        self.parent = Some(Parent {
            router,
            leader_cost: 0,
            sed_buffer_size: 0,
            sed_datagram_count: 0,
            csl_accuracy: crate::tlv::CslClockAccuracy::WORST,
        });
        self.set_role(env, Role::Detached);
        self.set_rloc16(env, info.rloc16);
        env.keys_mut().start(now);
        self.attach.counter = 0;
        self.child.child_update_attempts = 0;
        self.send_child_update_request(env, now)?;
        Ok(Restored::Child {
            rloc16: info.rloc16,
        })
    }

    /// Restore the child table from the persisted `ChildInfo` records after
    /// entering the router role (OT `ChildTable::Restore`): the children are
    /// `Restored` and are sent a Child Update Request by the next
    /// [`poll`](Self::poll).
    #[cfg(feature = "ftd")]
    pub fn restore_children<E: MleEnv>(&mut self, env: &mut E, now: Instant) {
        self.restore_children_from(env, now);
    }
}
