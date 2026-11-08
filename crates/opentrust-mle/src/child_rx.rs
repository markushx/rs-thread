//! Receive side of the child role: Child Update Request / Response, Data
//! Response and leader data handling (OpenThread
//! `Mle::HandleChildUpdateRequestOnChild`,
//! `HandleChildUpdateResponseOnChild`, `HandleDataResponse`,
//! `HandleLeaderData`). The send side and timers are in
//! [`child`](crate::child).
//!
//! Network Data and dataset *contents* are handed to the environment
//! unparsed ([`MleEnv::set_network_data`], [`MleEnv::dataset_received`]);
//! only the version numbers in Leader Data and the dataset timestamps are
//! interpreted here.

use opentrust_core::time::Instant;
use opentrust_core::{Error, Result};
use opentrust_mac::security::LinkFrameCounters;

use crate::child::{MAX_CHILD_TIMEOUT_SECS, MIN_CHILD_TIMEOUT_SECS};
use crate::endpoint::MleRx;
use crate::env::{MleEnv, MleEvent, Role};
use crate::link_quality::LinkQuality;
use crate::message::Command;
use crate::mle::{Mle, NbRef, RxClass};
use crate::neighbor::{MleReplay, NeighborState};
use crate::tlv::{STATUS_ERROR, ty};

/// `a` is newer than `b` in 8-bit serial number arithmetic (RFC 1982).
pub(crate) fn serial_greater(a: u8, b: u8) -> bool {
    a != b && a.wrapping_sub(b) < 0x80
}

fn add_unique(list: &mut heapless::Vec<u8, 16>, v: u8) {
    if !list.contains(&v) {
        let _ = list.push(v);
    }
}

impl<const C: usize> Mle<C> {
    /// OT `HandleLeaderData`: adopt a changed partition (child only), apply
    /// newer Network Data and datasets from Data Response / Child Update
    /// messages, or request them from the parent when the message only
    /// announces a newer version.
    fn handle_leader_data<E: MleEnv>(
        &mut self,
        env: &mut E,
        now: Instant,
        rx: &MleRx<'_>,
    ) -> Result<()> {
        let t = &rx.tlvs;
        let leader = t.leader_data()?;
        let cur = self.leader_data;
        if leader.partition_id != cur.partition_id
            || leader.weighting != cur.weighting
            || leader.leader_router_id != cur.leader_router_id
        {
            if self.role == Role::Child {
                self.leader_data = leader;
                self.child.retrieve_new_network_data = true;
            } else {
                return Err(Error::Drop);
            }
        } else if !self.child.retrieve_new_network_data {
            let (new, old) = if self.cfg.mode.full_network_data() {
                (leader.data_version, cur.data_version)
            } else {
                (leader.stable_data_version, cur.stable_data_version)
            };
            if !serial_greater(new, old) {
                return Ok(());
            }
        }
        let mut data_request = false;
        let mut active = None;
        let mut pending = None;
        match t.active_timestamp() {
            Ok(ts) => {
                if env.active_timestamp() != Some(ts) {
                    if t.contains(ty::ACTIVE_DATASET) {
                        active = Some((ts, t.active_dataset().ok()));
                    } else {
                        data_request = true;
                    }
                }
            }
            Err(Error::NotFound) => {}
            Err(e) => return Err(e),
        }
        if !data_request {
            match t.pending_timestamp() {
                Ok(ts) => {
                    if env.pending_timestamp() != Some(ts) {
                        if t.contains(ty::PENDING_DATASET) {
                            pending = Some((ts, t.pending_dataset().ok()));
                        } else {
                            data_request = true;
                        }
                    }
                }
                Err(Error::NotFound) => {}
                Err(e) => return Err(e),
            }
        }
        if !data_request {
            match t.network_data() {
                Ok(nd) => {
                    self.leader_data = leader;
                    self.child.retrieve_new_network_data = false;
                    env.set_network_data(&leader, nd);
                    env.event(MleEvent::NetworkDataChanged);
                    if active.is_some() || pending.is_some() {
                        env.dataset_received(active, pending);
                    }
                }
                Err(Error::NotFound) => data_request = true,
                Err(e) => return Err(e),
            }
        }
        if data_request {
            let _ = self.send_data_request(env, now);
        }
        Ok(())
    }

    /// OT `HandleChildUpdateRequestOnChild`: the parent asks for our state
    /// (and may announce new leader data).
    pub(crate) fn handle_child_update_request<E: MleEnv>(
        &mut self,
        env: &mut E,
        now: Instant,
        rx: &MleRx<'_>,
        nb: Option<NbRef>,
    ) -> Result<RxClass> {
        if self.role.is_router_or_leader() {
            return Err(Error::Drop);
        }
        let t = &rx.tlvs;
        let source = t.source_address()?;
        let mut list = heapless::Vec::<u8, 16>::new();
        let challenge = match t.challenge() {
            Ok(c) => {
                add_unique(&mut list, ty::RESPONSE);
                add_unique(&mut list, ty::MLE_FRAME_COUNTER);
                add_unique(&mut list, ty::LINK_FRAME_COUNTER);
                Some(c)
            }
            Err(Error::NotFound) => None,
            Err(e) => return Err(e),
        };
        if nb == Some(NbRef::Parent) {
            match t.status() {
                Ok(s) if s == STATUS_ERROR => {
                    self.become_detached(env, now);
                    return Ok(RxClass::Unknown);
                }
                Ok(_) | Err(Error::NotFound) => {}
                Err(e) => return Err(e),
            }
            let parent_rloc = self.parent.as_ref().map(|p| p.router.neighbor.rloc16);
            if parent_rloc != Some(source) {
                self.become_detached(env, now);
                return Ok(RxClass::Unknown);
            }
            self.handle_leader_data(env, now, rx)?;
            self.set_parent_link_margin(t.link_margin())?;
        } else {
            add_unique(&mut list, ty::STATUS);
        }
        match t.tlv_request() {
            Ok(req) => {
                for &r in req {
                    add_unique(&mut list, r);
                }
            }
            Err(Error::NotFound) => {}
            Err(e) => return Err(e),
        }
        if let Some(sec) = rx.meta.security {
            self.process_key_sequence(env, now, RxClass::Peer, sec, nb);
        }
        self.send_child_update_response(env, now, &list, challenge, rx.meta.src)?;
        if nb == Some(NbRef::Parent) {
            self.parent_frame_received(now);
        }
        Ok(RxClass::Unknown)
    }

    fn set_parent_link_margin(&mut self, margin: Result<u8>) -> Result<()> {
        match margin {
            Ok(m) => {
                if let Some(p) = self.parent.as_mut() {
                    p.router
                        .neighbor
                        .link_info
                        .set_link_quality_out(LinkQuality::for_margin(m));
                }
                Ok(())
            }
            Err(Error::NotFound) => Ok(()),
            Err(e) => Err(e),
        }
    }

    /// OT `SendChildUpdateResponse` (child side).
    fn send_child_update_response<E: MleEnv>(
        &mut self,
        env: &mut E,
        now: Instant,
        list: &[u8],
        challenge: Option<&[u8]>,
        dst: core::net::Ipv6Addr,
    ) -> Result<()> {
        let rloc = self.rloc16;
        let leader = self.leader_data;
        let timeout = self.cfg.timeout_secs;
        let dev = self.cfg.mode;
        let link_fc = env.keys().frame_counter();
        let mle_fc = self.mle_counter.current();
        let addrs = Self::address_entries(env, true);
        let sup = (dev.is_sleepy() && self.cfg.supervision_interval != 0)
            .then_some(self.cfg.supervision_interval);
        let mut ch = [0u8; 8];
        let clen = challenge.map_or(0, |c| {
            let n = c.len().min(8);
            ch[..n].copy_from_slice(&c[..n]);
            n
        });
        let mut check_address = false;
        self.send(env, dst, Command::ChildUpdateResponse, |w| {
            w.source_address(rloc)?;
            w.leader_data(&leader)?;
            for &tlv in list {
                match tlv {
                    ty::TIMEOUT => w.timeout(timeout)?,
                    ty::STATUS => w.status(STATUS_ERROR)?,
                    ty::ADDRESS_REGISTRATION if !dev.full_thread_device() => {
                        w.address_registration(&addrs)?;
                        check_address = true;
                    }
                    ty::RESPONSE => w.response(&ch[..clen])?,
                    ty::LINK_FRAME_COUNTER => w.link_frame_counter(link_fc)?,
                    ty::MLE_FRAME_COUNTER => w.mle_frame_counter(mle_fc)?,
                    ty::SUPERVISION_INTERVAL => {
                        if let Some(s) = sup {
                            w.supervision_interval(s)?;
                        }
                    }
                    _ => {}
                }
            }
            Ok(())
        })?;
        if check_address {
            // Only the ML-EID was registered; register the rest now.
            let mut any = false;
            env.registered_addresses(&mut |_| any = true);
            if any {
                let _ = self.send_child_update_request(env, now);
            }
        }
        Ok(())
    }

    /// OT `HandleChildUpdateResponseOnChild`.
    pub(crate) fn handle_child_update_response<E: MleEnv>(
        &mut self,
        env: &mut E,
        now: Instant,
        rx: &MleRx<'_>,
        nb: Option<NbRef>,
    ) -> Result<RxClass> {
        let t = &rx.tlvs;
        let response = match t.response() {
            Ok(r) => Some(r),
            Err(Error::NotFound) => None,
            Err(e) => return Err(e),
        };
        match self.role {
            Role::Detached => {
                if response != Some(&self.attach.challenge[..]) {
                    return Err(Error::Security);
                }
            }
            Role::Child => {
                if nb != Some(NbRef::Parent) || !self.neighbor_is_valid(nb) {
                    return Err(Error::Security);
                }
            }
            _ => return Err(Error::Drop),
        }
        if t.contains(ty::STATUS) {
            self.become_detached(env, now);
            return Ok(RxClass::Unknown);
        }
        let mode = t.mode()?;
        if mode != self.cfg.mode {
            return Err(Error::Drop);
        }
        let sec = rx.meta.security.ok_or(Error::Security)?;
        if self.role == Role::Detached {
            // Fast re-attach: the restored parent answered our challenge.
            let link_fc = t.link_frame_counter()?;
            let mle_fc = t.mle_frame_counter()?;
            let rloc = self.rloc16;
            let p = self.parent.as_mut().ok_or(Error::InvalidState)?;
            let n = &mut p.router.neighbor;
            n.link_counters = LinkFrameCounters::with(sec.key_sequence, link_fc);
            n.mle_replay = MleReplay::with(mle_fc);
            n.set_state(NeighborState::Valid, now);
            self.set_state_child(env, now, rloc);
            self.child.retrieve_new_network_data = true;
            self.child.request_route_tlv = self.cfg.mode.full_thread_device();
        }
        let source = t.source_address()?;
        let parent_rloc = self
            .parent
            .as_ref()
            .map(|p| p.router.neighbor.rloc16)
            .ok_or(Error::InvalidState)?;
        if parent_rloc.router_id() != source.router_id() {
            self.become_detached(env, now);
            return Ok(RxClass::Unknown);
        }
        self.handle_leader_data(env, now, rx)?;
        match t.timeout() {
            Ok(secs) => {
                let secs = secs.clamp(MIN_CHILD_TIMEOUT_SECS, MAX_CHILD_TIMEOUT_SECS);
                if secs != self.cfg.timeout_secs {
                    self.cfg.timeout_secs = secs;
                    self.recalculate_poll_period(env);
                }
            }
            Err(Error::NotFound) => {}
            Err(e) => return Err(e),
        }
        self.apply_rx_mode(env);
        self.set_parent_link_margin(t.link_margin())?;
        if self.child.waiting_child_update_response {
            self.child.child_update_attempts = 0;
            self.child.waiting_child_update_response = false;
            self.schedule_message_tx_timer(now);
        }
        self.parent_frame_received(now);
        Ok(if response.is_none() {
            RxClass::Peer
        } else {
            RxClass::Authoritative
        })
    }

    /// OT `HandleDataResponse` on a child.
    pub(crate) fn handle_data_response<E: MleEnv>(
        &mut self,
        env: &mut E,
        now: Instant,
        rx: &MleRx<'_>,
        nb: Option<NbRef>,
    ) -> Result<RxClass> {
        if nb != Some(NbRef::Parent) || !self.neighbor_is_valid(nb) || self.role != Role::Child {
            return Err(Error::Drop);
        }
        let r = self.handle_leader_data(env, now, rx);
        if self.child.waiting_data_response {
            self.child.waiting_data_response = false;
            self.child.data_request_attempts = 0;
            self.schedule_message_tx_timer(now);
        }
        if !self.is_rx_on_when_idle() {
            env.set_poll_attach_mode(false);
        }
        r?;
        self.parent_frame_received(now);
        Ok(RxClass::Peer)
    }
}
