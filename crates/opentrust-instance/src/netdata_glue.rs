//! The glue between MLE events, the interface, Network Data, the dataset
//! managers and the application: what OpenThread does through the
//! `Notifier` and the per-module `HandleNotifierEvents`.

use heapless::Vec;
use opentrust_core::time::Instant;
use opentrust_core::types::{Rloc16, ipv6};
use opentrust_mesh::address;
use opentrust_mesh::forwarder::DropReason;
use opentrust_mesh::netdata::aloc::desired_alocs;
use opentrust_mesh::netdata::anycast::Located;
use opentrust_mesh::netdata::consumers::slaac_prefixes;
use opentrust_mesh::netdata::notifier::{NotifierEvent, SyncInput, find_stale_child};
use opentrust_mesh::netdata::publisher::PublishContext;
use opentrust_mesh::netdata::server_data;
use opentrust_meshcop::manager::DatasetEvent;
use opentrust_mle::Role;
use opentrust_mle::env::MleEvent;
use opentrust_mle::neighbor::StateFilter;
use opentrust_net::resolver::ResolverEvent;
use opentrust_net::slaac::IidParams;
use opentrust_platform::SettingsStore;
use rand_core::{CryptoRng, Rng};

use crate::InstanceCrypto;

use crate::stack::ChildChange;
use crate::{Event, Instance};

/// State of the glue between layers.
#[derive(Debug, Default)]
pub(crate) struct GlueState {
    pub neighbors: Vec<(u16, [u8; 8]), 40>,
    pub src_match: Vec<Rloc16, 16>,
    pub unsecure_ports: Vec<u16, 2>,
    pub last_drop: Option<DropReason>,
    pub located: Option<Located>,
    pub addr_hash: u64,
    pub restoring_leader: bool,
    pub replay_drops: u32,
    pub commissioner_aloc: Option<u16>,
    pub key_sequence: Option<u32>,
}

impl GlueState {
    pub(crate) fn next_deadline(&self) -> Option<Instant> {
        None
    }
}

fn hash_bytes(h: &mut u64, b: &[u8]) {
    for x in b {
        *h = (*h ^ u64::from(*x)).wrapping_mul(0x0000_0100_0000_01b3);
    }
}

impl<S: SettingsStore, C: InstanceCrypto, R: Rng + CryptoRng> Instance<S, C, R> {
    // ------------------------------------------------------------ timers

    /// Run the timers of the layers.
    #[inline(never)]
    pub(crate) fn service_timers(&mut self, now: Instant) -> bool {
        // Key rotation advances the sequence on its own; adopting a newer one
        // from a neighbor or the dataset does too. MLE persists the network
        // info on its poll (`KeyManager::needs_store`).
        let _ = self.core.mac.security_mut().poll(now);
        self.mle.poll(&mut self.core, now);
        let ks = self.core.mac.security().key_sequence();
        if self.glue.key_sequence.is_some_and(|k| k != ks) {
            self.core.push_event(Event::KeySequenceChanged(ks));
        }
        self.glue.key_sequence = Some(ks);
        self.fwd.poll(now);
        {
            let (ds, mut env) = self.core.ds();
            ds.poll(&mut env, now);
        }
        self.slaac.poll(&mut self.core.ip6.netif, now);
        #[cfg(feature = "ftd")]
        if self.leader.sync_timed_out(now) {
            self.mle.become_detached(&mut self.core, now);
        }
        self.has_pending_work()
    }

    // ------------------------------------------------------------ events

    /// Dispatch the events of MLE and the dataset managers to their
    /// consumers.
    #[inline(never)]
    pub(crate) fn service_mle_events(&mut self, now: Instant) -> bool {
        let mut busy = false;
        while let Some(ev) = self.core.mle_events.pop_front() {
            busy = true;
            self.dispatch_mle_event(now, ev);
        }
        while let Some(c) = self.core.child_changes.pop_front() {
            busy = true;
            self.dispatch_child_change(now, c);
        }
        while let Some(e) = self.core.cfg.ds_events.pop_front() {
            busy = true;
            self.core.push_event(match e {
                DatasetEvent::ActiveChanged => Event::ActiveDatasetChanged,
                DatasetEvent::PendingChanged => Event::PendingDatasetChanged,
            });
        }
        if self.core.cfg.nd_version_bump {
            self.core.cfg.nd_version_bump = false;
            busy = true;
            #[cfg(feature = "ftd")]
            if self.mle.role() == Role::Leader {
                let c = self.leader.increment_version_and_stable();
                if c.any {
                    self.leader_changed(now);
                }
            }
        }
        if self.core.cfg.applied {
            self.core.cfg.applied = false;
            busy = true;
        }
        self.sync_netif();
        self.sync_mac_neighbors();
        busy
    }

    fn dispatch_mle_event(&mut self, now: Instant, ev: MleEvent) {
        let mut evs: Vec<ResolverEvent, 4> = Vec::new();
        address::handle_mle_event(&mut self.resolver, now, &ev, &mut |e| {
            let _ = evs.push(e);
        });
        for e in evs {
            self.handle_resolver_event(now, e);
        }
        match ev {
            MleEvent::RoleChanged { old, new } => {
                self.notifier.event(NotifierEvent::RoleChanged);
                #[cfg(feature = "ftd")]
                if new == Role::Leader {
                    let ld = *self.mle.leader_data();
                    if self.glue.restoring_leader {
                        self.glue.restoring_leader = false;
                        self.leader
                            .start_restoring(ld.data_version, ld.stable_data_version, now);
                    } else {
                        self.leader.start(ld.data_version, ld.stable_data_version);
                    }
                    self.core.netdata.clear();
                }
                if matches!(new, Role::Disabled | Role::Detached) {
                    self.fwd.clear();
                }
                self.core.push_event(Event::RoleChanged { old, new });
            }
            MleEvent::Rloc16Changed(r) => {
                self.core.push_event(Event::Rloc16Changed(r));
            }
            MleEvent::PartitionChanged { partition_id } => {
                self.notifier.event(NotifierEvent::PartitionChanged);
                self.core
                    .push_event(Event::PartitionChanged { partition_id });
            }
            MleEvent::LeaderStarted { partition_id } => {
                self.core
                    .push_event(Event::PartitionChanged { partition_id });
            }
            MleEvent::NetworkDataChanged => {}
            MleEvent::DetachedGracefully => {
                self.started = false;
                self.fwd.clear();
                self.core.push_event(Event::DetachedGracefully);
            }
            MleEvent::ChildAdded { ext, rloc16 } => {
                self.core.push_event(Event::ChildAdded { ext, rloc16 });
            }
            MleEvent::ChildRemoved { ext, rloc16 } => {
                self.notifier.event(NotifierEvent::ChildRemoved);
                self.core.push_event(Event::ChildRemoved { ext, rloc16 });
            }
            MleEvent::RouterAdded { rloc16, .. } => {
                self.core.push_event(Event::RouterAdded { rloc16 });
            }
            MleEvent::RouterRemoved { rloc16, .. } => {
                self.core.push_event(Event::RouterRemoved { rloc16 });
            }
            _ => {}
        }
    }

    fn dispatch_child_change(&mut self, now: Instant, c: ChildChange) {
        match c {
            ChildChange::Added(..) => {}
            ChildChange::Removed(_, rloc) => {
                // A child that is still valid and no longer sleeps gets its
                // queued messages sent directly.
                let rx_on = self
                    .mle
                    .children()
                    .find_by_rloc(rloc, StateFilter::Valid)
                    .is_some_and(|ch| ch.neighbor.is_rx_on_when_idle());
                if rx_on {
                    let mut notes = crate::datapath::FwdNotes::default();
                    crate::datapath::with_routing!(self, |r| {
                        let mut sink = crate::datapath::sink(
                            &mut self.core.mac,
                            &mut self.core.mactx,
                            &mut notes,
                        );
                        self.fwd.child_became_rx_on(rloc, &r, &mut sink);
                    });
                    self.after_forwarder(now, Vec::new(), notes);
                } else {
                    self.fwd.child_removed(rloc);
                }
                self.sync_src_match();
            }
            ChildChange::Supervise(rloc) => {
                self.fwd.send_child_supervision(rloc);
                self.sync_src_match();
            }
        }
    }

    // ------------------------------------------------------------ interface

    /// Bring the interface in line with MLE and the dataset.
    pub(crate) fn sync_netif(&mut self) {
        let enabled = self.started;
        let role = self.mle.role();
        let c = &mut self.core;
        let mlp = c.cfg.cur.mesh_local_prefix;
        if *c.ip6.netif.mesh_local_prefix() != mlp {
            let _ = c.ip6.netif.set_mesh_local_prefix(mlp);
        }
        let ml_eid = mlp.with_iid(&c.ml_iid);
        if c.ip6.netif.mesh_local_eid() != Some(ml_eid) {
            let _ = c.ip6.netif.set_mesh_local_eid(&c.ml_iid);
        }
        let rloc = (self.mle.rloc16() != Rloc16::INVALID).then(|| self.mle.rloc16());
        if c.ip6.netif.rloc() != rloc.map(|r| mlp.rloc(r)) {
            let _ = c.ip6.netif.set_rloc16(rloc);
        }
        // A REED (router-eligible FTD child) listens on the all-routers
        // groups too (OT `Mle::SetStateChild`): it answers Address Queries
        // for its own addresses itself, its parent does not register them.
        #[cfg(feature = "ftd")]
        let reed = role == crate::Role::Child && self.mle.is_router_eligible();
        #[cfg(not(feature = "ftd"))]
        let reed = false;
        if enabled {
            c.ip6.netif.subscribe_all_nodes();
            if role.is_router_or_leader() || reed {
                c.ip6.netif.subscribe_all_routers();
            } else {
                c.ip6.netif.unsubscribe_all_routers();
            }
        } else {
            c.ip6.netif.unsubscribe_all_nodes();
            c.ip6.netif.unsubscribe_all_routers();
        }
    }

    fn address_hash(&self) -> u64 {
        let mut h = 0xcbf2_9ce4_8422_2325u64;
        for a in self.core.ip6.netif.unicast_addresses() {
            hash_bytes(&mut h, &a.addr.octets());
        }
        for a in self.core.ip6.netif.multicast_addresses() {
            hash_bytes(&mut h, &a.octets());
        }
        h
    }

    // ------------------------------------------------------------ Network Data

    /// The leader store changed: serve it, advertise it.
    #[cfg(feature = "ftd")]
    pub(crate) fn leader_changed(&mut self, now: Instant) {
        self.core.netdata = self.leader.data().clone();
        self.leader.publish(&mut self.mle, &mut self.core, now);
        self.notifier.event(NotifierEvent::NetworkDataChanged);
        self.core.push_event(Event::NetworkDataChanged);
    }

    /// One round of the Network Data glue.
    #[inline(never)]
    pub(crate) fn service_netdata(&mut self, now: Instant) -> bool {
        let mut busy = false;
        let role = self.mle.role();
        #[cfg(feature = "ftd")]
        let leader_handled = role == Role::Leader;
        #[cfg(not(feature = "ftd"))]
        let leader_handled = false;
        #[cfg(feature = "ftd")]
        if leader_handled {
            let mask = self.mle.router_id_mask();
            let mut ch = self
                .leader
                .remove_stale_router_ids(|id| mask.contains(id), now);
            let c2 = self.leader.handle_timer(now);
            ch.any |= c2.any;
            // The commissioner session times out without keep-alives.
            ch.any |= self.cm.leader.poll(now, true, &mut self.leader);
            if ch.any {
                busy = true;
                self.leader_changed(now);
            }
            if let Some((ld, data)) = self.core.nd_rx.take() {
                // A restored leader gets its Network Data from a neighbor.
                if self.leader.is_waiting_for_sync()
                    && let Ok(c) = self.leader.restore(
                        &data,
                        ld.data_version,
                        ld.stable_data_version,
                        |id| mask.contains(id),
                        now,
                    )
                {
                    busy = true;
                    let _ = c;
                    // OT `HandleNetworkDataRestoredAfterReset`: the old
                    // commissioner session is gone.
                    let _ = self.cm.leader.adopt(&mut self.leader);
                    self.leader_changed(now);
                }
            }
            if self.core.netdata != *self.leader.data() {
                busy = true;
                self.leader_changed(now);
            }
        }
        #[cfg(feature = "ftd")]
        if !leader_handled && self.cm.leader.is_active() {
            self.cm.leader.reset();
        }
        if !leader_handled && let Some((_ld, data)) = self.core.nd_rx.take() {
            busy = true;
            if self.core.netdata.set(&data).is_ok() {
                #[cfg(feature = "ftd")]
                self.mle.network_data_updated(&mut self.core, now);
                self.notifier.event(NotifierEvent::NetworkDataChanged);
                self.core.push_event(Event::NetworkDataChanged);
            }
        }

        let attached = role.is_attached();
        let rloc = self.mle.rloc16();
        let view = self.core.netdata.view();
        // SLAAC and ALOCs follow Network Data and role.
        let prefixes = if attached {
            slaac_prefixes::<4>(&view)
        } else {
            Vec::new()
        };
        let params = IidParams {
            backend: &self.core.crypto,
            secret: &self.core.iid_secret,
            network_id: None,
        };
        self.slaac
            .update(&params, &mut self.core.ip6.netif, &prefixes, None, now);
        let want = desired_alocs(
            role == Role::Leader,
            &view,
            attached.then_some(rloc.0),
            self.glue.commissioner_aloc,
        );
        let _ = self.alocs.update(&mut self.core.ip6.netif, &want);

        // Published entries follow the Network Data.
        if attached {
            let ctx = PublishContext {
                attached,
                router_or_leader: role.is_router_or_leader(),
                rloc16: rloc,
                leader: view,
                ml_eid: self.core.ml_eid_addr(),
            };
            let mut pe: Vec<_, 8> = Vec::new();
            self.publisher
                .poll(now, &ctx, &mut self.local, &mut self.prng, &mut |e| {
                    let _ = pe.push(e);
                });
            for e in pe {
                self.core.push_event(Event::Publisher(e));
            }
            if self.publisher.take_local_changed() {
                self.notifier.event(NotifierEvent::LocalChanged);
                busy = true;
            }
        }

        // Server Data notifications.
        if attached {
            let mut local_buf = [0u8; 256];
            let ln = self.local.encode(rloc.0, &mut local_buf).unwrap_or(0);
            let view = self.core.netdata.view();
            let input = SyncInput {
                attached,
                router_or_leader: role.is_router_or_leader(),
                expected_to_become_router: false,
                rloc16: rloc,
                local: opentrust_mesh::netdata::NetworkDataView(&local_buf[..ln]),
                leader: view,
                stale_child: find_stale_child(&view, &self.mle),
            };
            if let Some(req) = self.notifier.poll(now, &input) {
                busy = true;
                let mut payload = [0u8; 300];
                let data = req.include_local.then_some(&local_buf[..ln]);
                let k =
                    server_data::build_server_data(req.old_rloc16, data, &mut payload).unwrap_or(0);
                if server_data::send_server_data(
                    &mut self.agent,
                    now,
                    &mut self.prng,
                    &mut self.sink,
                    &self.mle,
                    &self.core,
                    &payload[..k],
                )
                .is_err()
                {
                    self.notifier.response(now, true);
                }
            }
        }
        let h = self.address_hash();
        if h != self.glue.addr_hash {
            self.glue.addr_hash = h;
            self.core.push_event(Event::AddressesChanged);
            // A child that is not an FTD re-registers its addresses with
            // its parent (OT `Mle::HandleNotifierEvents`).
            if role == Role::Child && !self.mle.is_full_thread_device() {
                self.mle.schedule_child_update_request(&mut self.core, now);
            }
        }
        let _ = ipv6::LINK_LOCAL_ALL_NODES;
        busy
    }
}
