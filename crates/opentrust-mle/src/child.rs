//! Child role operation (Thread 1.4.1 §4.5.2, §4.6; OpenThread
//! `Mle::SetStateChild`, `ScheduleMessageTransmissionTimer`,
//! `SendChildUpdateRequestToParent`, `SetTimeout`, `DataPollSender` period,
//! `SupervisionListener`).
//!
//! - A child with the receiver on when idle keeps its parent informed with a
//!   Child Update Request every `timeout - 4 s`; a sleepy child's data polls
//!   (period derived from the timeout) do that job.
//! - Unanswered Child Update / Data Requests are repeated every second, at
//!   most 4 times, then the child detaches and re-attaches.
//! - A sleepy child that hears nothing secure from its parent for the
//!   supervision check timeout (default 190 s) probes it with a Child
//!   Update Request.

use opentrust_core::time::{Duration, Instant};
use opentrust_core::types::{Rloc16, ipv6};
use opentrust_core::{Error, Result};

use crate::env::{MleEnv, Role};
use crate::message::Command;
use crate::mle::Mle;
use crate::tlv::ty;

/// Retransmission delay of Child Update / Data Requests (OT
/// `kUnicastRetxDelay`).
pub const UNICAST_RETX_DELAY: Duration = Duration::from_secs(1);
/// Maximum unanswered keep-alive attempts before re-attaching (OT
/// `kMaxChildKeepAliveAttempts`).
pub const MAX_CHILD_KEEP_ALIVE_ATTEMPTS: u8 = 4;
/// Smallest child timeout (OT `kMinTimeout`: 5 attempts * 1 s).
pub const MIN_CHILD_TIMEOUT_SECS: u32 = MAX_CHILD_KEEP_ALIVE_ATTEMPTS as u32 + 1;
/// Largest child timeout (8 hours; OT `kMaxTimeout`).
pub const MAX_CHILD_TIMEOUT_SECS: u32 = 8 * 3600;
/// Poll lead time subtracted from the timeout (OT `kRetxPollPeriod *
/// kMaxPollRetxAttempts`).
const POLL_AHEAD: Duration = Duration::from_secs(4);

/// Flavour of a Child Update Request (OT `ChildUpdateRequestMode`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChildUpdateMode {
    /// Plain keep-alive / state update.
    Normal,
    /// With a Challenge (parent must answer with Response and counters).
    Challenge,
    /// Timeout 0: tell the parent we are leaving (graceful detach).
    ZeroTimeout,
}

/// Child-role bookkeeping inside [`Mle`].
#[derive(Debug)]
pub(crate) struct ChildCtx {
    pub tx_deadline: Option<Instant>,
    pub supervision_deadline: Option<Instant>,
    /// Delayed Child Update Request that aggregates changes (OT
    /// `ScheduleChildUpdateRequestToParent`).
    pub update_deadline: Option<Instant>,
    pub waiting_child_update_response: bool,
    pub child_update_attempts: u8,
    pub waiting_data_response: bool,
    pub data_request_attempts: u8,
    pub retrieve_new_network_data: bool,
    pub request_route_tlv: bool,
}

impl ChildCtx {
    pub const fn new() -> Self {
        Self {
            tx_deadline: None,
            supervision_deadline: None,
            update_deadline: None,
            waiting_child_update_response: false,
            child_update_attempts: 0,
            waiting_data_response: false,
            data_request_attempts: 0,
            retrieve_new_network_data: false,
            request_route_tlv: false,
        }
    }

    pub fn reset(&mut self) {
        *self = Self::new();
    }
}

impl<const C: usize> Mle<C> {
    /// OT `SetStateChild`.
    pub(crate) fn set_state_child<E: MleEnv>(&mut self, env: &mut E, now: Instant, rloc16: Rloc16) {
        self.set_rloc16(env, rloc16);
        self.set_role(env, Role::Child);
        self.attach.state = crate::attach::AttachState::Idle;
        self.attach.reattach = crate::attach::ReattachState::Stop;
        self.attach.deadline = Some(now.saturating_add(crate::attach::ATTACH_BACKOFF_RESET));
        self.announce_attach_succeeded(env);
        self.child.child_update_attempts = 0;
        self.child.data_request_attempts = 0;
        if let Some(p) = &self.parent {
            env.set_parent(Some((
                p.router.neighbor.ext_address,
                p.router.neighbor.rloc16,
            )));
        }
        self.apply_rx_mode(env);
        self.sync_csl(env, now, true);
        self.recalculate_poll_period(env);
        self.schedule_message_tx_timer(now);
        self.restart_supervision(now);
        #[cfg(feature = "ftd")]
        self.handle_child_start(env, now);
    }

    /// Receiver on / off and attach-mode polling according to the device
    /// mode (the tail of OT `HandleChildIdResponse`).
    pub(crate) fn apply_rx_mode<E: MleEnv>(&mut self, env: &mut E) {
        if self.is_rx_on_when_idle() {
            env.set_rx_on_when_idle(true);
        } else {
            env.set_poll_attach_mode(false);
            env.set_rx_on_when_idle(false);
        }
    }

    /// Data poll period of a sleepy child: the timeout minus a lead time
    /// (OT `DataPollSender::GetDefaultPollPeriod`).
    ///
    /// With CSL the period is bounded by the CSL timeout (a poll with a CSL
    /// IE then resynchronizes the parent in time) and only one retransmission
    /// period of lead time is kept.
    pub fn default_poll_period(&self) -> Duration {
        let mut p = Duration::from_secs(u64::from(self.cfg.timeout_secs));
        let mut ahead = POLL_AHEAD;
        if self.is_csl_enabled() {
            p = p.min(Duration::from_secs(u64::from(self.effective_csl_timeout())));
            ahead = Duration::from_secs(1);
        }
        if p > ahead {
            p.saturating_sub(ahead)
        } else {
            p
        }
    }

    pub(crate) fn recalculate_poll_period<E: MleEnv>(&mut self, env: &mut E) {
        if self.role == Role::Child && !self.is_rx_on_when_idle() {
            env.set_poll_period(Some(self.default_poll_period()));
        } else {
            env.set_poll_period(None);
        }
    }

    /// Change the child timeout (clamped to 5 s ..= 8 h). A child tells its
    /// parent with a Child Update Request (OT `SetTimeout`).
    pub fn set_timeout<E: MleEnv>(&mut self, env: &mut E, now: Instant, secs: u32) {
        let secs = secs.clamp(MIN_CHILD_TIMEOUT_SECS, MAX_CHILD_TIMEOUT_SECS);
        if secs == self.cfg.timeout_secs {
            return;
        }
        self.cfg.timeout_secs = secs;
        self.recalculate_poll_period(env);
        if self.role == Role::Child {
            self.schedule_message_tx_timer(now);
            let _ = self.send_child_update_request(env, now);
        }
    }

    /// OT `ScheduleMessageTransmissionTimer`.
    pub(crate) fn schedule_message_tx_timer(&mut self, now: Instant) {
        let interval =
            if self.child.waiting_child_update_response || self.child.waiting_data_response {
                // In CSL operation the answer waits for a sample window.
                self.csl_response_wait()
                    .map_or(UNICAST_RETX_DELAY, |p| p + UNICAST_RETX_DELAY)
            } else if self.role == Role::Child && self.is_rx_on_when_idle() {
                Duration::from_secs(u64::from(self.cfg.timeout_secs)).saturating_sub(POLL_AHEAD)
            } else {
                Duration::ZERO
            };
        self.child.tx_deadline = (!interval.is_zero()).then(|| now.saturating_add(interval));
    }

    /// OT `HandleMessageTransmissionTimer`.
    pub(crate) fn handle_message_tx_timer<E: MleEnv>(&mut self, env: &mut E, now: Instant) {
        if !self.child.waiting_child_update_response {
            if self.child.waiting_data_response {
                if self.child.data_request_attempts >= MAX_CHILD_KEEP_ALIVE_ATTEMPTS {
                    self.become_detached(env, now);
                    return;
                }
                if self.send_data_request(env, now).is_ok() {
                    self.child.data_request_attempts += 1;
                }
                return;
            }
            if !(self.role == Role::Child && self.is_rx_on_when_idle()) {
                return;
            }
        }
        if self.child.child_update_attempts >= MAX_CHILD_KEEP_ALIVE_ATTEMPTS {
            self.become_detached(env, now);
            return;
        }
        if self.send_child_update_request(env, now).is_ok() {
            self.child.child_update_attempts += 1;
        }
    }

    /// OT `ScheduleChildUpdateRequestIfMtdChild`: the addresses of an MTD
    /// child changed (or another detail its parent keeps); send a Child
    /// Update Request after [`crate::consts::CHILD_UPDATE_REQUEST_DELAY`] so that several
    /// changes share one message. Does nothing for other roles / FTDs.
    pub fn schedule_child_update_request<E: MleEnv>(&mut self, _env: &mut E, now: Instant) {
        if self.role == Role::Child
            && !self.is_full_thread_device()
            && self.child.update_deadline.is_none()
        {
            self.child.update_deadline =
                Some(now.saturating_add(crate::consts::CHILD_UPDATE_REQUEST_DELAY));
        }
    }

    pub(crate) fn poll_child_update_request<E: MleEnv>(&mut self, env: &mut E, now: Instant) {
        if self.child.update_deadline.is_some_and(|d| now >= d) {
            self.child.update_deadline = None;
            let _ = self.send_child_update_request(env, now);
        }
    }

    /// Send a plain Child Update Request to the parent.
    pub fn send_child_update_request<E: MleEnv>(
        &mut self,
        env: &mut E,
        now: Instant,
    ) -> Result<()> {
        self.send_child_update_request_with(env, now, ChildUpdateMode::Normal)
    }

    /// OT `SendChildUpdateRequestToParent(aMode)`. Also used by a detached
    /// device that restored a parent from settings.
    pub fn send_child_update_request_with<E: MleEnv>(
        &mut self,
        env: &mut E,
        now: Instant,
        mode: ChildUpdateMode,
    ) -> Result<()> {
        let Some(parent) = &self.parent else {
            self.become_detached(env, now);
            return Err(Error::InvalidState);
        };
        if !parent.router.neighbor.state.is_valid_or_restoring() {
            self.become_detached(env, now);
            return Err(Error::InvalidState);
        }
        let dst = ipv6::link_local(&parent.router.neighbor.ext_address);
        if mode != ChildUpdateMode::ZeroTimeout {
            self.child.waiting_child_update_response = true;
            self.schedule_message_tx_timer(now);
        }
        let detached = self.role == Role::Detached;
        let challenge = if mode == ChildUpdateMode::Challenge || detached {
            let c = Self::new_challenge(env);
            self.attach.challenge = c;
            Some(c)
        } else {
            None
        };
        let dev = self.cfg.mode;
        let timeout = if mode == ChildUpdateMode::ZeroTimeout {
            0
        } else {
            self.cfg.timeout_secs
        };
        let sup = (dev.is_sleepy() && self.cfg.supervision_interval != 0)
            .then_some(self.cfg.supervision_interval);
        let csl = self
            .is_csl_enabled()
            .then(|| (self.csl_channel_tlv(), self.effective_csl_timeout()));
        let addrs = Self::address_entries(env, detached);
        let rloc = self.rloc16;
        let leader = self.leader_data;
        let is_child = self.role == Role::Child;
        self.send(env, dst, Command::ChildUpdateRequest, |w| {
            w.mode(dev)?;
            if let Some(c) = &challenge {
                w.challenge(c)?;
            }
            if is_child {
                w.source_address(rloc)?;
                w.leader_data(&leader)?;
                w.timeout(timeout)?;
                if let Some(s) = sup {
                    w.supervision_interval(s)?;
                }
                if let Some((ch, csl_timeout)) = csl {
                    w.csl_channel(ch)?;
                    w.csl_timeout(csl_timeout)?;
                }
            }
            if !dev.full_thread_device() {
                w.address_registration(&addrs)?;
            }
            Ok(())
        })?;
        if dev.rx_on_when_idle() {
            env.set_rx_on_when_idle(true);
        } else {
            env.set_rx_on_when_idle(false);
            // A CSL child is reached in its sample windows; no fast attach
            // polling.
            env.set_poll_attach_mode(!self.is_csl_enabled());
        }
        Ok(())
    }

    /// Restart the supervision check timer (OT
    /// `SupervisionListener::RestartTimer`): only a sleepy child runs it.
    pub(crate) fn restart_supervision(&mut self, now: Instant) {
        let t = self.cfg.supervision_check_timeout;
        self.child.supervision_deadline =
            (t != 0 && self.role == Role::Child && !self.is_rx_on_when_idle())
                .then(|| now.saturating_add(Duration::from_secs(u64::from(t))));
    }

    /// A secure frame from the parent was received (call from the MAC rx
    /// path; MLE messages from the parent do it themselves). OT
    /// `SupervisionListener::UpdateOnReceive`.
    pub fn parent_frame_received(&mut self, now: Instant) {
        if self.child.supervision_deadline.is_some() {
            self.restart_supervision(now);
        }
        if let Some(p) = self.parent.as_mut() {
            p.router.neighbor.last_heard = now;
        }
    }

    /// OT `SupervisionListener::HandleTimer`.
    pub(crate) fn handle_supervision_timer<E: MleEnv>(&mut self, env: &mut E, now: Instant) {
        self.child.supervision_deadline = None;
        if self.role == Role::Child && !self.is_rx_on_when_idle() {
            let _ = self.send_child_update_request(env, now);
        }
        self.restart_supervision(now);
    }

    /// Send a Data Request to the parent for Network Data (and the Route64
    /// TLV if `request_route_tlv`), OT `SendDataRequest`. A sleepy child
    /// then waits for the Data Response, retrying every second.
    pub fn send_data_request<E: MleEnv>(&mut self, env: &mut E, now: Instant) -> Result<()> {
        if !self.role.is_attached() {
            return Err(Error::InvalidState);
        }
        let parent = self.parent.as_ref().ok_or(Error::InvalidState)?;
        let dst = ipv6::link_local(&parent.router.neighbor.ext_address);
        let r = self.send_data_request_to(env, dst);
        if self.role == Role::Child && !self.is_rx_on_when_idle() {
            env.send_fast_polls();
            self.child.waiting_data_response = true;
            if !self.child.waiting_child_update_response {
                self.schedule_message_tx_timer(now);
            }
        }
        r
    }

    /// Send a Data Request for Network Data (and Route64 if wanted) to
    /// `dst`, a neighbor router or the parent.
    pub(crate) fn send_data_request_to<E: MleEnv>(
        &mut self,
        env: &mut E,
        dst: core::net::Ipv6Addr,
    ) -> Result<()> {
        let route = self.child.request_route_tlv;
        let active_ts = env.active_timestamp();
        let pending_ts = env.pending_timestamp();
        self.send(env, dst, Command::DataRequest, |w| {
            if route {
                w.tlv_request(&[ty::NETWORK_DATA, ty::ROUTE64])?;
            } else {
                w.tlv_request(&[ty::NETWORK_DATA])?;
            }
            if let Some(t) = &active_ts {
                w.active_timestamp(t)?;
            }
            if let Some(t) = &pending_ts {
                w.pending_timestamp(t)?;
            }
            Ok(())
        })
    }
}
