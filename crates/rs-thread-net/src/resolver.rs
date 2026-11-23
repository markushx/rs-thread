//! EID-to-RLOC address resolution cache and query decision logic
//! (OT `thread/address_resolver.cpp`; Thread 1.4.1 section 5.x "Address
//! Query").
//!
//! This is only the *state machine*: no CoAP, no TMF. The `/a/aq`
//! (query), `/a/an` (notification) and `/a/ae` (error) messages are
//! built and parsed by `rs_thread_mesh::address` on top of the hooks here:
//!
//! - [`ResolverEvent::SendQuery`] -> send `/a/aq` (non-confirmable POST,
//!   Target TLV, to the realm-local all-routers address, from our RLOC);
//! - an incoming `/a/an` (Target, ML-EID IID, RLOC16 and optional Last
//!   Transaction Time TLVs) -> [`AddressResolver::handle_notify`]; send the
//!   empty ACK if it returns [`NotifyOutcome::Updated`];
//! - [`ResolverEvent::SendAddressError`] -> send `/a/ae` (non-confirmable
//!   to all routers when `dest` is `None`);
//! - an incoming `/a/ae` -> [`address_error_conflict`] (remove our address
//!   if it returns `true`) and, on routers, the child-table check;
//! - an incoming `/a/aq` on a router -> [`address_query_response`];
//! - [`ResolverEvent::Resolved`] / [`ResolverEvent::ResolutionFailed`] ->
//!   OT `MeshForwarder::HandleResolved`: resume or drop the datagrams that
//!   waited for the EID.
//!
//! # Entry states
//!
//! As in OT, an entry is in exactly one of four lists:
//!
//! | state        | meaning                                                    |
//! |--------------|------------------------------------------------------------|
//! | `Cached`     | in use; fresh for [`FRESHNESS_TIMEOUT`] s after a notify   |
//! | `Snooped`    | learned from a forwarded datagram; blocks eviction for [`SNOOP_BLOCK_EVICTION_S`] s (at most `max(1, N/16)` such entries) |
//! | `Query`      | query sent, waiting [`QUERY_TIMEOUT_S`] s for the notification |
//! | `QueryRetry` | the query timed out; wait the (exponentially growing, 15 s to 120 s) retry delay, then ramp down |
//!
//! Reclaim order when the table is full: free, `Snooped`, `QueryRetry`,
//! `Query`, `Cached`; oldest first within a state, and entries that cannot
//! be evicted yet (first-time queries, young snooped entries) are skipped.
//!
//! Time advances in 1-second ticks driven by [`AddressResolver::poll`] (OT
//! `TimeTicker`).

use core::net::Ipv6Addr;

use rs_thread_core::time::{Duration, Instant};
use rs_thread_core::types::{Iid, Rloc16};
use rs_thread_core::{Error, Result};

use crate::netif::Netif;

/// Default number of cache entries (OT `OPENTHREAD_CONFIG_TMF_ADDRESS_CACHE_ENTRIES`, MTD/FTD default 32).
pub const DEFAULT_CACHE_ENTRIES: usize = 32;
/// Seconds to wait for an Address Notification (OT `...ADDRESS_QUERY_TIMEOUT`).
pub const QUERY_TIMEOUT_S: u16 = 3;
/// First retry delay after a failed query in seconds.
pub const INITIAL_RETRY_DELAY_S: u16 = 15;
/// Maximum retry delay in seconds.
pub const MAX_RETRY_DELAY_S: u16 = 120;
/// Seconds a snooped entry cannot be evicted.
pub const SNOOP_BLOCK_EVICTION_S: u16 = 3;
/// Ticks a cached entry stays "fresh" after a notification.
pub const FRESHNESS_TIMEOUT: u8 = 3;

const TICK: Duration = Duration::from_secs(1);

/// Something the caller must do (or tell other layers).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolverEvent {
    /// Send an Address Query (`/a/aq`) for `eid`.
    SendQuery {
        /// The EID being resolved.
        eid: Ipv6Addr,
    },
    /// Send an Address Error (`/a/ae`) because two devices notified
    /// different ML-EID IIDs for `target`.
    SendAddressError {
        /// The duplicated address.
        target: Ipv6Addr,
        /// The IID received in the notification that conflicts.
        mesh_local_iid: Iid,
    },
    /// Resolution of `eid` succeeded (OT `HandleResolved(eid, kErrorNone)`).
    Resolved {
        /// The EID.
        eid: Ipv6Addr,
    },
    /// Resolution of `eid` failed or was aborted (OT `HandleResolved(eid, kErrorDrop)`).
    ResolutionFailed {
        /// The EID.
        eid: Ipv6Addr,
    },
}

/// Answers the resolver needs from the routing layer.
pub trait ResolverEnv {
    /// `true` if there is a next hop towards `rloc16` (OT
    /// `RouterTable::GetNextHop() != kInvalidRloc16`).
    fn has_route_to(&self, rloc16: Rloc16) -> bool;
    /// `true` if this device is an FTD (only FTDs snoop).
    fn is_ftd(&self) -> bool;
    /// `true` if `rloc16` is our own RLOC16.
    fn is_own_rloc16(&self, rloc16: Rloc16) -> bool;
    /// `true` if `rloc16` belongs to one of our minimal (MTD-like) children.
    fn is_minimal_child(&self, rloc16: Rloc16) -> bool;
}

/// Result of [`AddressResolver::resolve`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Resolution {
    /// The EID is at this RLOC16.
    Resolved(Rloc16),
    /// A query is in flight (just sent, or sent earlier); the datagram must
    /// wait for [`ResolverEvent::Resolved`] / [`ResolverEvent::ResolutionFailed`]
    /// (OT `kErrorAddressQuery`).
    QueryPending,
}

/// Result of [`AddressResolver::handle_notify`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotifyOutcome {
    /// Not interesting (no entry, or older information): no ACK is sent.
    Ignored,
    /// Conflicting ML-EID IID: an Address Error event was emitted, no ACK.
    DuplicateAddress,
    /// Entry updated: send the empty ACK.
    Updated,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
enum State {
    Free,
    Cached,
    Snooped,
    Query,
    QueryRetry,
}

#[derive(Debug, Clone, Copy)]
struct Entry {
    state: State,
    target: Ipv6Addr,
    rloc16: u16,
    mesh_local_iid: Iid,
    /// Last transaction time in seconds (`None` = invalid).
    last_transaction_time: Option<u32>,
    freshness: u8,
    /// Seconds: query/snoop eviction block/retry wait.
    timeout: u16,
    retry_delay: u16,
    can_evict: bool,
    ramp_down: bool,
    /// Order in which the entry joined its current state (larger = newer;
    /// the OT list head is the newest).
    order: u32,
}

impl Entry {
    const FREE: Self = Self {
        state: State::Free,
        target: Ipv6Addr::UNSPECIFIED,
        rloc16: Rloc16::INVALID.0,
        mesh_local_iid: Iid([0; 8]),
        last_transaction_time: None,
        freshness: 0,
        timeout: 0,
        retry_delay: INITIAL_RETRY_DELAY_S,
        can_evict: false,
        ramp_down: false,
        order: 0,
    };
}

/// Public read-only view of a cache entry (OT `otCacheEntryInfo`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EntryInfo {
    /// Target EID.
    pub target: Ipv6Addr,
    /// RLOC16 (invalid while querying).
    pub rloc16: Rloc16,
    /// State name.
    pub state: EntryState,
    /// Remaining timeout / retry wait in seconds (query/retry/snooped).
    pub timeout: u16,
    /// Current retry delay in seconds (query/retry).
    pub retry_delay: u16,
    /// `true` if the entry may be evicted.
    pub can_evict: bool,
}

/// State of an [`EntryInfo`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum EntryState {
    /// In use.
    Cached,
    /// Learned from a snooped datagram.
    Snooped,
    /// Query outstanding.
    Query,
    /// Waiting to retry a failed query.
    QueryRetry,
}

/// The address resolution cache with `N` entries.
#[derive(Debug, Clone)]
pub struct AddressResolver<const N: usize = DEFAULT_CACHE_ENTRIES> {
    entries: [Entry; N],
    seq: u32,
    next_tick: Option<Instant>,
}

impl<const N: usize> Default for AddressResolver<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> AddressResolver<N> {
    /// `max(1, N / 16)`: snooped entries that may block eviction at once.
    pub const MAX_NON_EVICTABLE_SNOOPED: usize = if N / 16 > 1 { N / 16 } else { 1 };

    /// An empty cache.
    pub const fn new() -> Self {
        Self {
            entries: [Entry::FREE; N],
            seq: 0,
            next_tick: None,
        }
    }

    fn bump(&mut self) -> u32 {
        self.seq = self.seq.wrapping_add(1);
        self.seq
    }

    fn find(&self, eid: &Ipv6Addr) -> Option<usize> {
        self.entries
            .iter()
            .position(|e| e.state != State::Free && e.target == *eid)
    }

    fn register_ticks(&mut self, now: Instant) {
        if self.next_tick.is_none() {
            self.next_tick = Some(now.saturating_add(TICK));
        }
    }

    /// Number of entries in use.
    pub fn len(&self) -> usize {
        self.entries
            .iter()
            .filter(|e| e.state != State::Free)
            .count()
    }

    /// `true` if the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Iterate over entries in use.
    pub fn iter(&self) -> impl Iterator<Item = EntryInfo> + '_ {
        self.entries.iter().filter_map(|e| {
            let state = match e.state {
                State::Free => return None,
                State::Cached => EntryState::Cached,
                State::Snooped => EntryState::Snooped,
                State::Query => EntryState::Query,
                State::QueryRetry => EntryState::QueryRetry,
            };
            Some(EntryInfo {
                target: e.target,
                rloc16: Rloc16(e.rloc16),
                state,
                timeout: e.timeout,
                retry_delay: e.retry_delay,
                can_evict: e.can_evict,
            })
        })
    }

    /// The entry for `eid`, if any.
    pub fn info(&self, eid: &Ipv6Addr) -> Option<EntryInfo> {
        self.iter().find(|i| i.target == *eid)
    }

    /// Remove everything (OT `Clear`); pending queries are reported as failed.
    pub fn clear(&mut self, sink: &mut impl FnMut(ResolverEvent)) {
        for i in 0..N {
            self.remove_at(i, sink);
        }
        self.next_tick = None;
    }

    fn remove_at(&mut self, i: usize, sink: &mut impl FnMut(ResolverEvent)) {
        let e = self.entries[i];
        if e.state == State::Query {
            sink(ResolverEvent::ResolutionFailed { eid: e.target });
        }
        self.entries[i] = Entry::FREE;
    }

    /// Remove the entry for `eid` (OT `RemoveEntryForAddress`), e.g. after an
    /// Address Error or when a child's address is removed.
    pub fn remove_entry_for_address(
        &mut self,
        eid: &Ipv6Addr,
        sink: &mut impl FnMut(ResolverEvent),
    ) {
        if let Some(i) = self.find(eid) {
            self.remove_at(i, sink);
        }
    }

    /// Remove cached and snooped entries whose RLOC16 has router ID `router_id`
    /// (OT `RemoveEntriesForRouterId`).
    pub fn remove_entries_for_router_id(&mut self, router_id: u8) {
        for e in &mut self.entries {
            if matches!(e.state, State::Cached | State::Snooped)
                && Rloc16(e.rloc16).router_id() == router_id
            {
                *e = Entry::FREE;
            }
        }
    }

    /// Remove cached and snooped entries with exactly `rloc16`.
    pub fn remove_entries_for_rloc16(&mut self, rloc16: Rloc16) {
        for e in &mut self.entries {
            if matches!(e.state, State::Cached | State::Snooped) && e.rloc16 == rloc16.0 {
                *e = Entry::FREE;
            }
        }
    }

    /// Change `old` to `new` in all cached and snooped entries.
    pub fn replace_entries_for_rloc16(&mut self, old: Rloc16, new: Rloc16) {
        for e in &mut self.entries {
            if matches!(e.state, State::Cached | State::Snooped) && e.rloc16 == old.0 {
                e.rloc16 = new.0;
            }
        }
    }

    /// OT `NewCacheEntry`: a free slot, else evict by the documented order.
    fn new_entry(&mut self, snooped: bool, sink: &mut impl FnMut(ResolverEvent)) -> Option<usize> {
        if let Some(i) = self.entries.iter().position(|e| e.state == State::Free) {
            return Some(i);
        }
        for list in [
            State::Snooped,
            State::QueryRetry,
            State::Query,
            State::Cached,
        ] {
            let mut victim: Option<usize> = None;
            let mut non_evictable = 0usize;
            for (i, e) in self.entries.iter().enumerate() {
                if e.state != list {
                    continue;
                }
                if list != State::Cached && !e.can_evict {
                    non_evictable += 1;
                    continue;
                }
                if victim.is_none_or(|v| e.order < self.entries[v].order) {
                    victim = Some(i);
                }
            }
            if let Some(v) = victim {
                self.remove_at(v, sink);
                return Some(v);
            }
            if snooped && list == State::Snooped && non_evictable >= Self::MAX_NON_EVICTABLE_SNOOPED
            {
                return None;
            }
        }
        None
    }

    /// Resolve `eid` (OT `AddressResolver::Resolve`).
    ///
    /// - cached/snooped entry that is fresh or has a route: `Resolved`
    ///   (and the entry becomes the newest cached entry);
    /// - otherwise, if `allow_query`, start (or continue waiting for) an
    ///   Address Query: [`ResolverEvent::SendQuery`] is emitted when a new
    ///   query must be sent, and the result is [`Resolution::QueryPending`];
    /// - [`Error::NotFound`] if no entry and queries are not allowed,
    ///   [`Error::NoBufs`] if no entry can be reclaimed,
    ///   [`Error::Drop`] if the EID is in the retry-delay wait.
    pub fn resolve(
        &mut self,
        now: Instant,
        eid: &Ipv6Addr,
        allow_query: bool,
        env: &impl ResolverEnv,
        sink: &mut impl FnMut(ResolverEvent),
    ) -> Result<Resolution> {
        let mut idx = self.find(eid);
        if let Some(i) = idx
            && matches!(self.entries[i].state, State::Cached | State::Snooped)
        {
            let e = self.entries[i];
            let fresh = e.state == State::Cached && e.freshness != 0;
            if !fresh && !env.has_route_to(Rloc16(e.rloc16)) {
                self.entries[i] = Entry::FREE;
                idx = None;
            } else {
                let order = self.bump();
                let e = &mut self.entries[i];
                if e.state == State::Snooped {
                    e.last_transaction_time = None;
                }
                e.state = State::Cached;
                e.order = order;
                return Ok(Resolution::Resolved(Rloc16(e.rloc16)));
            }
        }
        let is_new = idx.is_none();
        let i = match idx {
            Some(i) => i,
            None => {
                if !allow_query {
                    return Err(Error::NotFound);
                }
                let i = self.new_entry(false, sink).ok_or(Error::NoBufs)?;
                let mut e = Entry::FREE;
                e.target = *eid;
                self.entries[i] = e;
                i
            }
        };
        if !allow_query {
            return Err(Error::NotFound);
        }
        if !is_new {
            match self.entries[i].state {
                State::Query => return Ok(Resolution::QueryPending),
                State::QueryRetry if !self.entries[i].ramp_down => return Err(Error::Drop),
                _ => {}
            }
        }
        let order = self.bump();
        let e = &mut self.entries[i];
        e.state = State::Query;
        e.timeout = QUERY_TIMEOUT_S;
        e.order = order;
        if is_new {
            e.retry_delay = INITIAL_RETRY_DELAY_S;
            e.can_evict = false;
            e.ramp_down = false;
            e.rloc16 = Rloc16::INVALID.0;
        }
        sink(ResolverEvent::SendQuery { eid: *eid });
        self.register_ticks(now);
        Ok(Resolution::QueryPending)
    }

    /// Look up without starting a query (OT `LookUp`).
    pub fn lookup(
        &mut self,
        now: Instant,
        eid: &Ipv6Addr,
        env: &impl ResolverEnv,
        sink: &mut impl FnMut(ResolverEvent),
    ) -> Option<Rloc16> {
        match self.resolve(now, eid, false, env, sink) {
            Ok(Resolution::Resolved(r)) => Some(r),
            _ => None,
        }
    }

    /// The Address Query for `eid` could not be sent: drop the entry that
    /// was created for it.
    pub fn abort_query(&mut self, eid: &Ipv6Addr) {
        if let Some(i) = self.find(eid)
            && self.entries[i].state == State::Query
        {
            self.entries[i] = Entry::FREE;
        }
    }

    /// OT `UpdateCacheEntry`: update the entry for `eid` if there is one.
    /// A query entry becomes cached and [`ResolverEvent::Resolved`] is
    /// emitted. [`Error::NotFound`] if there is no entry.
    pub fn update_cache_entry(
        &mut self,
        eid: &Ipv6Addr,
        rloc16: Rloc16,
        sink: &mut impl FnMut(ResolverEvent),
    ) -> Result<()> {
        let i = self.find(eid).ok_or(Error::NotFound)?;
        match self.entries[i].state {
            State::Cached | State::Snooped => {
                self.entries[i].rloc16 = rloc16.0;
            }
            _ => {
                let order = self.bump();
                let e = &mut self.entries[i];
                e.state = State::Cached;
                e.rloc16 = rloc16.0;
                e.last_transaction_time = None;
                e.order = order;
                sink(ResolverEvent::Resolved { eid: *eid });
            }
        }
        Ok(())
    }

    /// OT `UpdateSnoopedCacheEntry`: learn `eid -> rloc16` from a datagram
    /// with source `eid` (sent from `rloc16`) that we are forwarding to
    /// `dest` (the RLOC16 it is addressed to).
    pub fn update_snooped(
        &mut self,
        now: Instant,
        eid: &Ipv6Addr,
        rloc16: Rloc16,
        dest: Rloc16,
        env: &impl ResolverEnv,
        sink: &mut impl FnMut(ResolverEvent),
    ) {
        if !env.is_ftd() {
            return;
        }
        if self.update_cache_entry(eid, rloc16, sink).is_ok() {
            return;
        }
        if env.is_own_rloc16(rloc16) || env.is_minimal_child(rloc16) {
            return;
        }
        if !(env.is_own_rloc16(dest) || env.is_minimal_child(dest)) {
            return;
        }
        let Some(i) = self.new_entry(true, sink) else {
            return;
        };
        let non_evictable = self
            .entries
            .iter()
            .filter(|e| e.state == State::Snooped && !e.can_evict)
            .count();
        let order = self.bump();
        let mut e = Entry::FREE;
        e.state = State::Snooped;
        e.target = *eid;
        e.rloc16 = rloc16.0;
        e.order = order;
        if non_evictable < Self::MAX_NON_EVICTABLE_SNOOPED {
            e.can_evict = false;
            e.timeout = SNOOP_BLOCK_EVICTION_S;
            self.register_ticks(now);
        } else {
            e.can_evict = true;
            e.timeout = 0;
        }
        self.entries[i] = e;
    }

    /// Handle an Address Notification (`/a/an`) for `target`
    /// (OT `HandleTmf<kUriAddressNotify>`). `last_transaction_time` is the
    /// Last Transaction Time TLV in seconds (`None` is treated as 0).
    pub fn handle_notify(
        &mut self,
        now: Instant,
        target: &Ipv6Addr,
        mesh_local_iid: Iid,
        rloc16: Rloc16,
        last_transaction_time: Option<u32>,
        sink: &mut impl FnMut(ResolverEvent),
    ) -> NotifyOutcome {
        let ltt = last_transaction_time.unwrap_or(0);
        let Some(i) = self.find(target) else {
            return NotifyOutcome::Ignored;
        };
        let e = self.entries[i];
        if e.state == State::Cached
            && let Some(prev) = e.last_transaction_time
        {
            // Notifications with different mesh-local IIDs: the EID is used by
            // more than one device.
            if e.mesh_local_iid != mesh_local_iid {
                sink(ResolverEvent::SendAddressError {
                    target: *target,
                    mesh_local_iid,
                });
                return NotifyOutcome::DuplicateAddress;
            }
            if ltt >= prev {
                return NotifyOutcome::Ignored;
            }
        }
        let order = self.bump();
        let e = &mut self.entries[i];
        e.rloc16 = rloc16.0;
        e.mesh_local_iid = mesh_local_iid;
        e.last_transaction_time = Some(ltt);
        e.freshness = FRESHNESS_TIMEOUT;
        e.state = State::Cached;
        e.order = order;
        self.register_ticks(now);
        sink(ResolverEvent::Resolved { eid: *target });
        NotifyOutcome::Updated
    }

    /// OT `RestartAddressQueries`: called when the router table changes in a
    /// way that may let pending queries succeed (e.g., attach to a new
    /// partition): retrying entries become active again and every active
    /// query is re-sent.
    pub fn restart_queries(&mut self, now: Instant, sink: &mut impl FnMut(ResolverEvent)) {
        for e in &mut self.entries {
            if e.state == State::QueryRetry {
                e.state = State::Query;
            }
        }
        let mut any = false;
        for e in &mut self.entries {
            if e.state == State::Query {
                sink(ResolverEvent::SendQuery { eid: e.target });
                e.timeout = QUERY_TIMEOUT_S;
                e.retry_delay = INITIAL_RETRY_DELAY_S;
                e.can_evict = false;
                any = true;
            }
        }
        if any {
            self.register_ticks(now);
        }
    }

    /// The instant at which [`Self::poll`] next has work.
    pub fn next_deadline(&self) -> Option<Instant> {
        self.next_tick
    }

    /// Run the 1-second ticks that are due at `now` (OT `HandleTimeTick`).
    pub fn poll(&mut self, now: Instant, sink: &mut impl FnMut(ResolverEvent)) {
        while let Some(t) = self.next_tick
            && t <= now
        {
            let more = self.tick(sink);
            self.next_tick = more.then(|| t.saturating_add(TICK));
        }
    }

    fn tick(&mut self, sink: &mut impl FnMut(ResolverEvent)) -> bool {
        let mut more = false;
        for i in 0..N {
            let e = &mut self.entries[i];
            match e.state {
                State::Free => {}
                State::Cached => {
                    if e.freshness != 0 {
                        e.freshness -= 1;
                        more = true;
                    }
                }
                State::Snooped => {
                    if e.timeout != 0 {
                        more = true;
                        e.timeout -= 1;
                        if e.timeout == 0 {
                            e.can_evict = true;
                        }
                    }
                }
                State::QueryRetry => {
                    if e.timeout != 0 {
                        more = true;
                        e.timeout -= 1;
                        if e.timeout == 0 {
                            if !e.ramp_down {
                                e.ramp_down = true;
                                e.timeout = MAX_RETRY_DELAY_S;
                            } else {
                                let d = (e.retry_delay >> 1).max(INITIAL_RETRY_DELAY_S);
                                if d != e.retry_delay {
                                    e.retry_delay = d;
                                    e.timeout = MAX_RETRY_DELAY_S;
                                }
                            }
                        }
                    }
                }
                State::Query => {
                    more = true;
                    e.timeout = e.timeout.saturating_sub(1);
                    if e.timeout == 0 {
                        e.timeout = e.retry_delay;
                        e.retry_delay = (e.retry_delay << 1).min(MAX_RETRY_DELAY_S);
                        e.can_evict = true;
                        e.ramp_down = false;
                        e.state = State::QueryRetry;
                        let eid = e.target;
                        let order = self.bump();
                        self.entries[i].order = order;
                        sink(ResolverEvent::ResolutionFailed { eid });
                    }
                }
            }
        }
        more
    }
}

/// Decision for an incoming Address Error (`/a/ae`) message (OT
/// `HandleTmf<kUriAddressError>`, first half): if `target` is one of our own
/// unicast addresses and the sender's ML-EID IID differs from ours, the
/// address is a duplicate and must be removed from the interface (or, for
/// a DUA, reported). Returns `true` in that case.
pub fn address_error_conflict<const U: usize, const M: usize>(
    netif: &Netif<U, M>,
    target: &Ipv6Addr,
    received_mesh_local_iid: &Iid,
    own_mesh_local_iid: &Iid,
) -> bool {
    netif.has_unicast(target) && received_mesh_local_iid != own_mesh_local_iid
}

/// Information a router puts into an Address Notification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QueryResponse {
    /// ML-EID IID of the device that owns the address.
    pub mesh_local_iid: Iid,
    /// Last Transaction Time TLV (seconds since the child was last heard);
    /// `None` for our own addresses.
    pub last_transaction_time: Option<u32>,
}

/// Child lookup for [`address_query_response`].
pub trait ChildLookup {
    /// A valid, reachable, non-FTD child with registered address `target`:
    /// its ML-EID IID and seconds since it was last heard.
    fn child_with_address(&self, target: &Ipv6Addr) -> Option<(Iid, u32)>;
}

/// Decide the response to an Address Query (`/a/aq`) on a router (OT
/// `HandleTmf<kUriAddressQuery>`): answer for our own addresses (ML-EID
/// IID, no transaction time) or for an MTD child's registered address.
pub fn address_query_response<const U: usize, const M: usize>(
    netif: &Netif<U, M>,
    own_mesh_local_iid: &Iid,
    children: &impl ChildLookup,
    target: &Ipv6Addr,
) -> Option<QueryResponse> {
    if netif.has_unicast(target) {
        return Some(QueryResponse {
            mesh_local_iid: *own_mesh_local_iid,
            last_transaction_time: None,
        });
    }
    children
        .child_with_address(target)
        .map(|(iid, secs)| QueryResponse {
            mesh_local_iid: iid,
            last_transaction_time: Some(secs),
        })
}

#[cfg(test)]
mod tests;
