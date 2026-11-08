//! When to send Server Data to the leader (OT `NetworkData::Notifier`).
//!
//! The notifier is a small state machine fed with events and polled with
//! the current local / leader Network Data. It decides whether a `/a/sd`
//! notification is needed (the leader's entries for this RLOC16 differ from
//! the local data in either direction, or a child of this router that is
//! gone still has entries) and keeps the OT timing: a first check right
//! after a change, a re-check 300 s after a confirmed update, retry after a
//! timeout, no new request while one is outstanding.
//!
//! Not implemented: the Border Router router-role upgrade request
//! (`kBorderRouterRequest`) OT schedules from here.

use opentrust_core::time::{Duration, Instant};
use opentrust_core::types::Rloc16;

use super::local::contains_entries_from;
use super::view::NetworkDataView;

/// Delay of the re-check after a stale child entry was reported
/// (`kDelayRemoveStaleChildren`).
pub const DELAY_REMOVE_STALE_CHILDREN: Duration = Duration::from_secs(5);
/// Delay of the periodic consistency check after a confirmed update
/// (`kDelaySynchronizeServerData`).
pub const DELAY_SYNCHRONIZE_SERVER_DATA: Duration = Duration::from_secs(300);
/// Wait for a device that is about to become a router
/// (`RouterRoleTransitionTimeout + 1`).
pub const DELAY_ROUTER_TRANSITION: Duration = Duration::from_secs(11);

/// Events that make the notifier look again.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotifierEvent {
    /// The local data was changed by the application.
    LocalChanged,
    /// The leader's Network Data changed
    /// ([`MleEvent::NetworkDataChanged`](opentrust_mle::env::MleEvent::NetworkDataChanged),
    /// or the leader published a change itself).
    NetworkDataChanged,
    /// The Thread role changed.
    RoleChanged,
    /// A child was removed.
    ChildRemoved,
}

/// The current state the decision is based on.
#[derive(Debug, Clone, Copy)]
pub struct SyncInput<'a> {
    /// Attached to a partition (child, router or leader).
    pub attached: bool,
    /// The device is a router or leader (stale child detection applies).
    pub router_or_leader: bool,
    /// This device is a REED about to upgrade: wait.
    pub expected_to_become_router: bool,
    /// Our RLOC16.
    pub rloc16: Rloc16,
    /// The local data, encoded for [`rloc16`](Self::rloc16) with
    /// [`LocalData::encode`](super::local::LocalData::encode).
    pub local: NetworkDataView<'a>,
    /// The leader's Network Data as this device has it.
    pub leader: NetworkDataView<'a>,
    /// A child RLOC16 of this router that has entries in the leader's data
    /// but is no longer a valid child (see [`find_stale_child`]).
    pub stale_child: Option<Rloc16>,
}

/// A request the notifier wants sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServerDataRequest {
    /// RLOC16 TLV: a previous RLOC16 (or a stale child's) whose entries
    /// the leader removes.
    pub old_rloc16: Option<Rloc16>,
    /// Include the local data as Network Data TLV (`false` for a pure
    /// stale child removal).
    pub include_local: bool,
}

/// OT `Notifier` timing and decision state.
#[derive(Debug, Clone, Default)]
pub struct Notifier {
    waiting_for_response: bool,
    task_pending: bool,
    next_delay: Duration,
    timer: Option<Instant>,
    old_rloc: Option<Rloc16>,
}

impl Notifier {
    /// A notifier with nothing scheduled.
    pub const fn new() -> Self {
        Self {
            waiting_for_response: false,
            task_pending: false,
            next_delay: Duration::from_secs(0),
            timer: None,
            old_rloc: None,
        }
    }

    /// Report an event.
    pub fn event(&mut self, event: NotifierEvent) {
        match event {
            NotifierEvent::LocalChanged
            | NotifierEvent::RoleChanged
            | NotifierEvent::ChildRemoved => {
                self.next_delay = Duration::from_secs(0);
            }
            NotifierEvent::NetworkDataChanged => {}
        }
        self.task_pending = true;
    }

    /// Deadline of the next [`poll`](Self::poll) that may have work.
    pub fn next_deadline(&self) -> Option<Instant> {
        self.timer
    }

    /// `true` if [`poll`](Self::poll) should be called now (an event is
    /// pending).
    pub fn has_pending_work(&self) -> bool {
        self.task_pending
    }

    /// Run the pending check or an expired timer. `Some` asks the caller
    /// to send the Server Data notification and later report the outcome
    /// with [`response`](Self::response).
    pub fn poll(&mut self, now: Instant, input: &SyncInput<'_>) -> Option<ServerDataRequest> {
        if self.task_pending {
            self.task_pending = false;
            return self.synchronize(now, input);
        }
        if self.timer.is_some_and(|t| now >= t) {
            self.timer = None;
            return self.synchronize(now, input);
        }
        None
    }

    /// The outcome of a request returned by [`poll`](Self::poll):
    /// `acknowledged` for a response, `false` for a timeout or abort
    /// (tried again at once).
    pub fn response(&mut self, now: Instant, acknowledged: bool) {
        self.waiting_for_response = false;
        if acknowledged {
            self.timer = Some(now.saturating_add(self.next_delay + Duration::from_millis(1)));
        } else {
            self.task_pending = true;
        }
    }

    fn synchronize(&mut self, now: Instant, input: &SyncInput<'_>) -> Option<ServerDataRequest> {
        if !input.attached || self.waiting_for_response {
            return None;
        }
        if self.next_delay != Duration::from_secs(0) && self.timer.is_some() {
            return None;
        }
        self.next_delay = DELAY_REMOVE_STALE_CHILDREN;
        if input.router_or_leader
            && let Some(child) = input.stale_child
        {
            self.waiting_for_response = true;
            return Some(ServerDataRequest {
                old_rloc16: Some(child),
                include_local: false,
            });
        }
        self.next_delay = DELAY_SYNCHRONIZE_SERVER_DATA;
        if input.expected_to_become_router {
            self.timer = Some(now.saturating_add(DELAY_ROUTER_TRANSITION));
            return None;
        }
        let r = input.rloc16.0;
        if contains_entries_from(&input.leader, &input.local, r)
            && contains_entries_from(&input.local, &input.leader, r)
        {
            return None;
        }
        if self.old_rloc == Some(input.rloc16) {
            self.old_rloc = None;
        }
        let old_rloc16 = self.old_rloc;
        self.old_rloc = Some(input.rloc16);
        self.waiting_for_response = true;
        Some(ServerDataRequest {
            old_rloc16,
            include_local: true,
        })
    }
}

/// A child RLOC16 of this router that has Border Router, Has Route or
/// Server entries in `leader` but is not a valid child any more (OT
/// `RemoveStaleChildEntries`).
#[cfg(feature = "ftd")]
pub fn find_stale_child<const C: usize>(
    leader: &NetworkDataView<'_>,
    mle: &opentrust_mle::Mle<C>,
) -> Option<Rloc16> {
    use opentrust_mle::neighbor::StateFilter;
    let own = mle.rloc16();
    if !mle.role().is_router_or_leader() {
        return None;
    }
    leader
        .on_mesh_prefixes()
        .map(|e| e.rloc16)
        .chain(leader.external_routes().map(|e| e.rloc16))
        .chain(leader.services().map(|e| e.rloc16))
        .map(Rloc16)
        .find(|r| {
            !r.is_router()
                && r.0 & 0xfc00 != 0xfc00
                && r.router_id() == own.router_id()
                && mle
                    .children()
                    .find_by_rloc(*r, StateFilter::Valid)
                    .is_none()
        })
}
