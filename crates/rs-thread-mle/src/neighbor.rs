//! Neighbor, child and router data model and fixed-capacity tables
//! (Thread 1.4.1 §4.6, §4.7, §5.9; OpenThread `thread/neighbor.{hpp,cpp}`,
//! `child.{hpp,cpp}`, `router.{hpp,cpp}`, `child_table.cpp`,
//! `neighbor_table.cpp`).
//!
//! These are plain data holders with the small invariants OpenThread
//! encodes in their accessors; the *protocol* (attach, link establishment,
//! timeouts, routing) lives in the state machines built on top ([`Mle`](crate::Mle)).
//!
//! - [`Neighbor`]: what is common to parent, routers and children - address,
//!   [`NeighborState`], device mode, version, last-heard time, incoming key
//!   sequence / frame counters ([`LinkFrameCounters`] for MAC, [`MleReplay`]
//!   for MLE), [`LinkQualityInfo`], CSL and link-metrics bookkeeping.
//! - [`Child`]: a [`Neighbor`] plus timeout, registered IPv6 addresses,
//!   requested TLVs, Network Data version, supervision state.
//! - [`Router`] / [`Parent`]: a [`Neighbor`] plus routing state.
//! - [`ChildTable`] / [`RouterTable`]: fixed-capacity storage with stable
//!   slot indices and lookups by extended address, RLOC16, IPv6 address and
//!   [`StateFilter`].
//!
//! Deviations from OT: no intrusive linked lists or bit-packed fields; the
//! "validity" union of OT (`mValid` frame counters vs `mPending` challenge)
//! is two plain fields; children keep full IPv6 addresses (OT keeps
//! compressed ones); the router table has no per-id allocation bookkeeping
//! (router ID mask, sequence and reuse delay live in the router role,
//! `router`).

use core::net::Ipv6Addr;

use heapless::Vec;
use rs_thread_core::settings::ChildInfo;
use rs_thread_core::time::{Duration, Instant};
use rs_thread_core::types::{ExtAddress, Iid, Prefix64, Rloc16};
use rs_thread_core::{Error, Result};
#[cfg(feature = "link-metrics")]
use rs_thread_mac::mac::LinkMetricsFlags;
use rs_thread_mac::security::LinkFrameCounters;

use crate::consts::{
    CHILD_MAX_ADDRESSES, CHILD_MAX_MULTICAST_ADDRESSES, CHILD_MAX_REQUEST_TLVS, THREAD_VERSION_1_1,
};
use crate::link_quality::LinkQualityInfo;
use crate::security::RxSecurity;
use crate::tlv::{CslClockAccuracy, DeviceMode};

// ---------------------------------------------------------------------------
// State

/// State of a neighbor link (OT `Neighbor::State`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum NeighborState {
    /// Unused / link invalid.
    #[default]
    Invalid,
    /// Restored from non-volatile memory, not yet verified.
    Restored,
    /// Received a Parent Request (child candidate).
    ParentRequest,
    /// Received a Parent Response (parent candidate).
    ParentResponse,
    /// Received a Child ID Request.
    ChildIdRequest,
    /// Sent a Link Request.
    LinkRequest,
    /// Sent a Child Update Request (restoring the child).
    ChildUpdateRequest,
    /// Link is valid.
    Valid,
}

impl NeighborState {
    /// `Restored` or `ChildUpdateRequest` (OT `IsStateRestoring`).
    pub const fn is_restoring(self) -> bool {
        matches!(self, Self::Restored | Self::ChildUpdateRequest)
    }

    /// `Valid` or restoring (OT `IsStateValidOrRestoring`).
    pub const fn is_valid_or_restoring(self) -> bool {
        matches!(self, Self::Valid) || self.is_restoring()
    }

    /// `Valid`, `LinkRequest`, `ChildIdRequest` or restoring (OT
    /// `IsStateValidOrAttaching`).
    pub const fn is_valid_or_attaching(self) -> bool {
        matches!(self, Self::Valid | Self::LinkRequest | Self::ChildIdRequest)
            || self.is_restoring()
    }
}

/// Which states a lookup accepts (OT `Neighbor::StateFilter`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum StateFilter {
    /// Only `Valid`.
    Valid,
    /// `Valid` or restoring.
    ValidOrRestoring,
    /// Only `ChildIdRequest`.
    ChildIdRequest,
    /// `Valid`, `LinkRequest`, `ChildIdRequest` or restoring.
    ValidOrAttaching,
    /// Only `Invalid`.
    Invalid,
    /// Anything but `Invalid`.
    AnyExceptInvalid,
    /// Anything but `Valid` or restoring.
    AnyExceptValidOrRestoring,
    /// Any state.
    Any,
}

impl StateFilter {
    /// Whether `state` passes the filter.
    pub const fn matches(self, state: NeighborState) -> bool {
        match self {
            Self::Valid => matches!(state, NeighborState::Valid),
            Self::ValidOrRestoring => state.is_valid_or_restoring(),
            Self::ChildIdRequest => matches!(state, NeighborState::ChildIdRequest),
            Self::ValidOrAttaching => state.is_valid_or_attaching(),
            Self::Invalid => matches!(state, NeighborState::Invalid),
            Self::AnyExceptInvalid => !matches!(state, NeighborState::Invalid),
            Self::AnyExceptValidOrRestoring => !state.is_valid_or_restoring(),
            Self::Any => true,
        }
    }
}

// ---------------------------------------------------------------------------
// MLE replay protection

/// Incoming MLE frame counter of one neighbor (OT
/// `Neighbor::mValidPending.mValid.mMleFrameCounter`), checked together with
/// the neighbor's key sequence kept in its [`LinkFrameCounters`].
///
/// OT `Mle::HandleUdpReceive` for a message from a neighbor in `Valid`
/// state:
///
/// - same key sequence: the frame counter must be `>=` the next expected
///   one, else the message is a duplicate and is dropped;
/// - newer key sequence: adopt it, reset the link frame counters, and accept
///   any frame counter;
/// - older key sequence: dropped.
///
/// After acceptance the next expected counter is `frame_counter + 1`. It is
/// kept as `u64`, so a counter of `0xffffffff` does not wrap.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct MleReplay {
    next: u64,
}

impl MleReplay {
    /// Any counter acceptable.
    pub const fn new() -> Self {
        Self { next: 0 }
    }

    /// State after link establishment: the neighbor's MLE Frame Counter TLV
    /// value is the smallest acceptable counter (OT `SetMleFrameCounter`).
    pub const fn with(frame_counter: u32) -> Self {
        Self {
            next: frame_counter as u64,
        }
    }

    /// Smallest acceptable counter (`None` once `0xffffffff` was accepted).
    pub const fn frame_counter(&self) -> Option<u32> {
        if self.next > u32::MAX as u64 {
            None
        } else {
            Some(self.next as u32)
        }
    }

    /// Forget the counter.
    pub fn reset(&mut self) {
        self.next = 0;
    }

    /// Check a secured message from this neighbor without updating.
    /// [`Error::Drop`] for an older key sequence or a duplicate / replayed
    /// counter (OT `kErrorDuplicated`).
    pub fn check(&self, link: &LinkFrameCounters, rx: &RxSecurity) -> Result<()> {
        let ks = link.key_sequence();
        if rx.key_sequence < ks {
            return Err(Error::Drop);
        }
        if rx.key_sequence == ks && u64::from(rx.frame_counter) < self.next {
            return Err(Error::Drop);
        }
        Ok(())
    }

    /// [`check`](Self::check) and, if the message is acceptable, update:
    /// returns `true` if the key sequence advanced, in which case `link` was
    /// reset to `LinkFrameCounters::with(key_sequence, 0)`
    /// (OT: `SetKeySequence`, `GetLinkFrameCounters().Reset()`,
    /// `SetLinkAckFrameCounter(0)`). The caller then applies the MLE key
    /// sequence rules (`KeyManager::on_rx_key_sequence`).
    pub fn check_and_update(
        &mut self,
        link: &mut LinkFrameCounters,
        rx: &RxSecurity,
    ) -> Result<bool> {
        self.check(link, rx)?;
        let advanced = rx.key_sequence > link.key_sequence();
        if advanced {
            link.set(rx.key_sequence, 0);
        }
        self.next = u64::from(rx.frame_counter) + 1;
        Ok(advanced)
    }
}

// ---------------------------------------------------------------------------
// Neighbor

/// CSL state of a neighbor (OT `CslNeighbor` / `Child::mCslTimeout`,
/// `mCslChannel`, `mCslAccuracy`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct CslNeighborInfo {
    /// CSL synchronized timeout in seconds (0 = CSL not in use).
    pub timeout_secs: u32,
    /// CSL channel (0 = same as the PAN channel).
    pub channel: u8,
    /// CSL clock accuracy and uncertainty reported by the neighbor.
    pub accuracy: Option<CslClockAccuracy>,
}

impl CslNeighborInfo {
    /// `true` if the neighbor is CSL synchronized (timeout set).
    pub const fn is_synchronized(&self) -> bool {
        self.timeout_secs != 0
    }
}

/// Length of the attach challenge (OT `Mle::kChallengeSize`).
pub const CHALLENGE_LEN: usize = 8;

/// Data common to parent, router and child neighbors (OT `Neighbor`).
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Neighbor {
    /// Extended address.
    pub ext_address: ExtAddress,
    /// RLOC16 ([`Rloc16::INVALID`] while unassigned).
    pub rloc16: Rloc16,
    /// Link state.
    pub state: NeighborState,
    /// Device mode of the neighbor.
    pub mode: DeviceMode,
    /// Thread version (from the Version TLV; 1.1 if absent).
    pub version: u16,
    /// Last time any message was heard from the neighbor.
    pub last_heard: Instant,
    /// When the neighbor entered `Valid`, if it did.
    pub connection_start: Option<Instant>,
    /// Incoming key sequence and MAC frame counters.
    pub link_counters: LinkFrameCounters,
    /// Incoming MLE frame counter.
    pub mle_replay: MleReplay,
    /// Challenge we sent / need to answer while the link is being
    /// established (OT `mPending.mChallenge`).
    pub challenge: [u8; CHALLENGE_LEN],
    /// Link quality and RSS.
    pub link_info: LinkQualityInfo,
    /// Consecutive transmission failures to this neighbor.
    pub link_failures: u8,
    /// CSL state.
    pub csl: CslNeighborInfo,
    /// Metrics configured for Enhanced-ACK based probing at this neighbor
    /// (we are the initiator, it is the subject).
    #[cfg(feature = "link-metrics")]
    pub enh_ack_probing: LinkMetricsFlags,
}

impl Neighbor {
    /// A cleared neighbor in `Invalid` state.
    pub fn new(ext_address: ExtAddress, now: Instant) -> Self {
        Self {
            ext_address,
            rloc16: Rloc16::INVALID,
            state: NeighborState::Invalid,
            mode: DeviceMode::default(),
            version: THREAD_VERSION_1_1,
            last_heard: now,
            connection_start: None,
            link_counters: LinkFrameCounters::new(),
            mle_replay: MleReplay::new(),
            challenge: [0; CHALLENGE_LEN],
            link_info: LinkQualityInfo::new(),
            link_failures: 0,
            csl: CslNeighborInfo::default(),
            #[cfg(feature = "link-metrics")]
            enh_ack_probing: LinkMetricsFlags::NONE,
        }
    }

    /// Set the state; entering `Valid` records the connection start (OT
    /// `SetState`).
    pub fn set_state(&mut self, state: NeighborState, now: Instant) {
        if state == NeighborState::Valid && self.state != NeighborState::Valid {
            self.connection_start = Some(now);
        }
        if state != NeighborState::Valid {
            self.connection_start = None;
        }
        self.state = state;
    }

    /// `state == Valid`.
    pub const fn is_valid(&self) -> bool {
        matches!(self.state, NeighborState::Valid)
    }

    /// Whether the neighbor passes `filter`.
    pub const fn matches_filter(&self, filter: StateFilter) -> bool {
        filter.matches(self.state)
    }

    /// Seconds since the neighbor became `Valid` (0 if it is not).
    pub fn connection_time_secs(&self, now: Instant) -> u64 {
        match (self.state, self.connection_start) {
            (NeighborState::Valid, Some(t)) => now.saturating_duration_since(t).as_secs(),
            _ => 0,
        }
    }

    /// Record having heard from the neighbor.
    pub fn heard(&mut self, now: Instant) {
        self.last_heard = now;
    }

    /// `rx_on_when_idle` of the neighbor's mode.
    pub const fn is_rx_on_when_idle(&self) -> bool {
        self.mode.rx_on_when_idle()
    }

    /// Thread 1.1 neighbor (not `Invalid` and version 2), which e.g. lacks
    /// Enhanced ACKs and Link Metrics.
    pub const fn is_thread_version_1p1(&self) -> bool {
        !matches!(self.state, NeighborState::Invalid) && self.version == THREAD_VERSION_1_1
    }

    /// Thread 1.2 or newer (not `Invalid`).
    pub const fn is_thread_version_1p2_or_higher(&self) -> bool {
        !matches!(self.state, NeighborState::Invalid) && self.version >= 3
    }

    /// Reset to an unused neighbor, keeping the address.
    pub fn clear(&mut self, now: Instant) {
        *self = Self::new(self.ext_address, now);
    }

    /// Address match for lookups: the RLOC16 and/or extended address.
    fn matches_ext(&self, ext: &ExtAddress, filter: StateFilter) -> bool {
        self.matches_filter(filter) && self.ext_address == *ext
    }

    fn matches_rloc(&self, rloc: Rloc16, filter: StateFilter) -> bool {
        self.matches_filter(filter) && self.rloc16 == rloc
    }
}

// ---------------------------------------------------------------------------
// Child

/// Multicast Listener Registration state of a multicast address (OT
/// `MlrState`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MlrState {
    /// To be registered with the Primary Backbone Router.
    ToRegister,
    /// A registration is in flight.
    Registering,
    /// Registered.
    Registered,
}

/// A multicast group larger than realm-local a child listens to, with its
/// registration state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MulticastListener {
    /// The group.
    pub addr: Ipv6Addr,
    /// Registration state.
    pub mlr: MlrState,
}

/// A child of this router (OT `Child`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Child {
    /// Common neighbor data.
    pub neighbor: Neighbor,
    /// Child timeout in seconds (Timeout TLV).
    pub timeout_secs: u32,
    /// Network Data version the child last received (full or stable, per
    /// the child's mode).
    pub network_data_version: u8,
    /// Supervision interval requested by the child in seconds (0 = none).
    pub supervision_interval: u16,
    /// Seconds since the last supervision message to the child.
    pub seconds_since_supervision: u16,
    /// The child's CSL transmissions are synchronized: a frame with a CSL IE
    /// was received since the last (re)attach (OT `mCslSynchronized`).
    pub csl_synchronized: bool,
    /// CSL synchronized timeout the child asked for, seconds (OT
    /// `mCslTimeout`; 0 = none yet).
    pub csl_timeout_secs: u32,
    /// CSL channel of the child (0 = the PAN channel).
    pub csl_channel: u8,
    /// When a frame with a CSL IE was last received from the child.
    pub csl_last_heard: Instant,
    /// The child is known to use its assigned RLOC16: it sent a Child
    /// Update Request after the Child ID Response (set for restored
    /// children). Until then frames go to it directly (OT sends the Child
    /// ID Response to the extended address).
    pub confirmed: bool,
    ml_eid_iid: Option<Iid>,
    addresses: Vec<Ipv6Addr, CHILD_MAX_ADDRESSES>,
    multicast: Vec<MulticastListener, CHILD_MAX_MULTICAST_ADDRESSES>,
    request_tlvs: Vec<u8, CHILD_MAX_REQUEST_TLVS>,
}

impl Child {
    /// A new child in `Invalid` state.
    pub fn new(ext_address: ExtAddress, now: Instant) -> Self {
        Self {
            neighbor: Neighbor::new(ext_address, now),
            timeout_secs: 0,
            network_data_version: 0,
            supervision_interval: 0,
            seconds_since_supervision: 0,
            csl_synchronized: false,
            csl_timeout_secs: 0,
            csl_channel: 0,
            csl_last_heard: now,
            confirmed: false,
            ml_eid_iid: None,
            addresses: Vec::new(),
            multicast: Vec::new(),
            request_tlvs: Vec::new(),
        }
    }

    /// Restore a child from persistent settings: `Restored` state, and
    /// `last_heard = now` (OT `Mle::RefreshStoredChildren`).
    pub fn from_child_info(info: &ChildInfo, now: Instant) -> Self {
        let mut c = Self::new(info.ext_address, now);
        c.neighbor.rloc16 = info.rloc16;
        c.neighbor.mode = DeviceMode::from_bits(info.mode);
        c.neighbor.version = info.version;
        c.timeout_secs = info.timeout;
        c.neighbor.state = NeighborState::Restored;
        c.confirmed = true;
        c
    }

    /// The record to persist for this child.
    pub fn to_child_info(&self) -> ChildInfo {
        ChildInfo {
            ext_address: self.neighbor.ext_address,
            timeout: self.timeout_secs,
            rloc16: self.neighbor.rloc16,
            mode: self.neighbor.mode.to_bits(),
            version: self.neighbor.version,
        }
    }

    /// `true` if the child is a Thread 1.2+ device that can use CSL.
    pub const fn is_csl_capable(&self) -> bool {
        self.neighbor.version >= crate::consts::THREAD_VERSION_1_2
    }

    /// When the CSL synchronization of the child expires (`None` if it is
    /// not synchronized).
    pub fn csl_expiry(&self) -> Option<Instant> {
        self.csl_synchronized.then(|| {
            self.csl_last_heard
                .saturating_add(Duration::from_secs(u64::from(self.csl_timeout_secs)))
        })
    }

    /// The child's timeout as a [`Duration`].
    pub const fn timeout(&self) -> Duration {
        Duration::from_secs(self.timeout_secs as u64)
    }

    /// `true` if nothing was heard for the child timeout (OT
    /// `MleRouter::HandleTimeTick`: `now >= last_heard + timeout`).
    pub fn is_timed_out(&self, now: Instant) -> bool {
        now >= self.neighbor.last_heard.saturating_add(self.timeout())
    }

    /// The child's mesh-local EID IID, if registered.
    pub const fn ml_eid_iid(&self) -> Option<&Iid> {
        self.ml_eid_iid.as_ref()
    }

    /// Set / clear the mesh-local EID IID.
    pub fn set_ml_eid_iid(&mut self, iid: Option<Iid>) {
        self.ml_eid_iid = iid;
    }

    /// Registered addresses other than the mesh-local EID.
    pub fn addresses(&self) -> &[Ipv6Addr] {
        &self.addresses
    }

    /// Register an address. [`Error::Already`] if present,
    /// [`Error::NoBufs`] if the child's address list is full.
    pub fn add_address(&mut self, addr: Ipv6Addr) -> Result<()> {
        if self.addresses.contains(&addr) {
            return Err(Error::Already);
        }
        self.addresses.push(addr).map_err(|_| Error::NoBufs)
    }

    /// Remove an address; [`Error::NotFound`] if absent.
    pub fn remove_address(&mut self, addr: &Ipv6Addr) -> Result<()> {
        let i = self
            .addresses
            .iter()
            .position(|a| a == addr)
            .ok_or(Error::NotFound)?;
        self.addresses.swap_remove(i);
        Ok(())
    }

    /// Remove all registered addresses (the ML-EID is kept).
    pub fn clear_addresses(&mut self) {
        self.addresses.clear();
    }

    /// The multicast groups larger than realm-local the child registered
    /// with its parent, with their Multicast Listener Registration state.
    pub fn multicast_listeners(&self) -> &[MulticastListener] {
        &self.multicast
    }

    /// Mutable access to the listeners' registration state.
    pub fn multicast_listeners_mut(&mut self) -> &mut [MulticastListener] {
        &mut self.multicast
    }

    /// Register a multicast group (state `ToRegister`).
    /// [`Error::Already`] if present, [`Error::NoBufs`] if full.
    pub fn add_multicast_listener(&mut self, addr: Ipv6Addr) -> Result<()> {
        if self.multicast.iter().any(|m| m.addr == addr) {
            return Err(Error::Already);
        }
        self.multicast
            .push(MulticastListener {
                addr,
                mlr: MlrState::ToRegister,
            })
            .map_err(|_| Error::NoBufs)
    }

    /// Remove all multicast groups.
    pub fn clear_multicast_listeners(&mut self) {
        self.multicast.clear();
    }

    /// `true` if any group is in `state`.
    pub fn has_mlr_state(&self, state: MlrState) -> bool {
        self.multicast.iter().any(|m| m.mlr == state)
    }

    /// Whether `addr` is one of the child's addresses: the registered ones
    /// or the ML-EID formed with `ml_prefix`.
    pub fn has_address(&self, ml_prefix: &Prefix64, addr: &Ipv6Addr) -> bool {
        self.ip6_addresses(ml_prefix).any(|a| a == *addr)
    }

    /// All of the child's addresses: ML-EID (with `ml_prefix`) first, then
    /// the registered ones.
    pub fn ip6_addresses<'a>(
        &'a self,
        ml_prefix: &'a Prefix64,
    ) -> impl Iterator<Item = Ipv6Addr> + 'a {
        self.ml_eid_iid
            .iter()
            .map(|iid| ml_prefix.with_iid(iid))
            .chain(self.addresses.iter().copied())
    }

    /// TLV types the child asked for in its Child ID Request / Child Update
    /// Request (at most [`CHILD_MAX_REQUEST_TLVS`]).
    pub fn request_tlvs(&self) -> &[u8] {
        &self.request_tlvs
    }

    /// Store the requested TLV types; extra entries are ignored like OT
    /// (which truncates to `kMaxRequestTlvs`).
    pub fn set_request_tlvs(&mut self, tlvs: &[u8]) {
        self.request_tlvs.clear();
        let n = tlvs.len().min(CHILD_MAX_REQUEST_TLVS);
        // Cannot fail: n <= capacity.
        let _ = self.request_tlvs.extend_from_slice(&tlvs[..n]);
    }

    /// `true` if the child is a sleepy end device.
    pub const fn is_sleepy(&self) -> bool {
        self.neighbor.mode.is_sleepy()
    }
}

// ---------------------------------------------------------------------------
// Router, Parent

/// A neighboring or reachable router (OT `Router`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Router {
    /// Common neighbor data (state `Valid` only for routers we have a link
    /// with).
    pub neighbor: Neighbor,
    /// Router ID (0..=62).
    pub router_id: u8,
    /// Router ID of the next hop towards this router.
    pub next_hop: Option<u8>,
    /// Path cost to this router via `next_hop` (0..=16).
    pub cost: u8,
    /// Link Request attempts made (0..=3).
    pub link_request_attempts: u8,
    /// Seconds left waiting for a Link Accept.
    pub link_accept_timeout: u8,
}

impl Router {
    /// A new router entry with no route.
    pub fn new(router_id: u8, ext_address: ExtAddress, now: Instant) -> Self {
        let mut neighbor = Neighbor::new(ext_address, now);
        neighbor.rloc16 = Rloc16(u16::from(router_id) << 10);
        Self {
            neighbor,
            router_id,
            next_hop: None,
            cost: crate::consts::MAX_ROUTE_COST,
            link_request_attempts: 0,
            link_accept_timeout: 0,
        }
    }

    /// The router's RLOC16.
    pub const fn rloc16(&self) -> Rloc16 {
        self.neighbor.rloc16
    }
}

/// The parent of an end device or REED (OT `Parent`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Parent {
    /// Router part (the parent is a router).
    pub router: Router,
    /// Parent's cost to the leader (from Connectivity TLV).
    pub leader_cost: u8,
    /// SED buffer size the parent offers.
    pub sed_buffer_size: u16,
    /// SED datagram count the parent offers.
    pub sed_datagram_count: u8,
    /// CSL clock accuracy and uncertainty of the parent (CSL Clock Accuracy
    /// TLV; [`CslClockAccuracy::WORST`] until it reports).
    #[cfg(feature = "csl")]
    pub csl_accuracy: crate::tlv::CslClockAccuracy,
}

// ---------------------------------------------------------------------------
// Tables

/// Fixed-capacity child table with stable slot indices (OT `ChildTable`).
#[derive(Debug, Clone)]
pub struct ChildTable<const N: usize> {
    slots: [Option<Child>; N],
    /// Children the table accepts (OT `mMaxChildrenAllowed`, at most `N`).
    max_allowed: usize,
}

impl<const N: usize> Default for ChildTable<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> ChildTable<N> {
    /// Capacity.
    pub const CAPACITY: usize = N;

    /// Empty table.
    pub const fn new() -> Self {
        Self {
            slots: [const { None }; N],
            max_allowed: N,
        }
    }

    /// Number of children the table accepts (OT `GetMaxChildrenAllowed`).
    pub const fn max_allowed(&self) -> usize {
        self.max_allowed
    }

    /// Limit the number of children (OT `SetMaxChildrenAllowed`).
    /// [`Error::InvalidArgs`] unless `1..=N`; [`Error::InvalidState`] while
    /// there are children in any state but `Invalid`.
    pub fn set_max_allowed(&mut self, max: usize) -> Result<()> {
        if max == 0 || max > N {
            return Err(Error::InvalidArgs);
        }
        if self.has_children(StateFilter::AnyExceptInvalid) {
            return Err(Error::InvalidState);
        }
        self.max_allowed = max;
        Ok(())
    }

    fn has_room(&self) -> bool {
        self.slots.iter().flatten().count() < self.max_allowed
    }

    /// Remove every child.
    pub fn clear(&mut self) {
        self.slots.iter_mut().for_each(|s| *s = None);
    }

    /// Allocate a slot for a new child in `Invalid` state (OT
    /// `GetNewChild`). [`Error::NoBufs`] if full; [`Error::Already`] if a
    /// child with this extended address already exists.
    pub fn add(&mut self, ext_address: ExtAddress, now: Instant) -> Result<&mut Child> {
        if self.find_by_ext(&ext_address, StateFilter::Any).is_some() {
            return Err(Error::Already);
        }
        if !self.has_room() {
            return Err(Error::NoBufs);
        }
        let slot = self
            .slots
            .iter_mut()
            .find(|s| s.is_none())
            .ok_or(Error::NoBufs)?;
        Ok(slot.insert(Child::new(ext_address, now)))
    }

    /// Insert an already built child (e.g. restored from settings).
    pub fn insert(&mut self, child: Child) -> Result<&mut Child> {
        if self
            .find_by_ext(&child.neighbor.ext_address, StateFilter::Any)
            .is_some()
        {
            return Err(Error::Already);
        }
        if !self.has_room() {
            return Err(Error::NoBufs);
        }
        let slot = self
            .slots
            .iter_mut()
            .find(|s| s.is_none())
            .ok_or(Error::NoBufs)?;
        Ok(slot.insert(child))
    }

    /// Remove the child in slot `index`.
    pub fn remove(&mut self, index: usize) -> Option<Child> {
        self.slots.get_mut(index)?.take()
    }

    /// Child in slot `index`.
    pub fn get(&self, index: usize) -> Option<&Child> {
        self.slots.get(index)?.as_ref()
    }

    /// Mutable child in slot `index`.
    pub fn get_mut(&mut self, index: usize) -> Option<&mut Child> {
        self.slots.get_mut(index)?.as_mut()
    }

    /// Slot index of the child with `ext` passing `filter`.
    pub fn index_by_ext(&self, ext: &ExtAddress, filter: StateFilter) -> Option<usize> {
        self.iter_indexed(filter)
            .find(|(_, c)| c.neighbor.matches_ext(ext, filter))
            .map(|(i, _)| i)
    }

    /// Slot index of the child with RLOC16 `rloc` passing `filter`.
    pub fn index_by_rloc(&self, rloc: Rloc16, filter: StateFilter) -> Option<usize> {
        self.iter_indexed(filter)
            .find(|(_, c)| c.neighbor.matches_rloc(rloc, filter))
            .map(|(i, _)| i)
    }

    /// Find by extended address.
    pub fn find_by_ext(&self, ext: &ExtAddress, filter: StateFilter) -> Option<&Child> {
        self.get(self.index_by_ext(ext, filter)?)
    }

    /// Find by extended address, mutable.
    pub fn find_by_ext_mut(&mut self, ext: &ExtAddress, filter: StateFilter) -> Option<&mut Child> {
        let i = self.index_by_ext(ext, filter)?;
        self.get_mut(i)
    }

    /// Find by RLOC16.
    pub fn find_by_rloc(&self, rloc: Rloc16, filter: StateFilter) -> Option<&Child> {
        self.get(self.index_by_rloc(rloc, filter)?)
    }

    /// Find by RLOC16, mutable.
    pub fn find_by_rloc_mut(&mut self, rloc: Rloc16, filter: StateFilter) -> Option<&mut Child> {
        let i = self.index_by_rloc(rloc, filter)?;
        self.get_mut(i)
    }

    /// Find the child owning `addr` (its ML-EID with `ml_prefix`, or one of
    /// its registered addresses) among children passing `filter`.
    pub fn find_by_address(
        &self,
        ml_prefix: &Prefix64,
        addr: &Ipv6Addr,
        filter: StateFilter,
    ) -> Option<&Child> {
        self.iter(filter).find(|c| c.has_address(ml_prefix, addr))
    }

    /// Iterate `(slot, child)` for children passing `filter`.
    pub fn iter_indexed(&self, filter: StateFilter) -> impl Iterator<Item = (usize, &Child)> {
        self.slots
            .iter()
            .enumerate()
            .filter_map(|(i, s)| s.as_ref().map(|c| (i, c)))
            .filter(move |(_, c)| c.neighbor.matches_filter(filter))
    }

    /// Iterate children passing `filter`.
    pub fn iter(&self, filter: StateFilter) -> impl Iterator<Item = &Child> {
        self.iter_indexed(filter).map(|(_, c)| c)
    }

    /// Iterate children passing `filter`, mutable.
    pub fn iter_mut(&mut self, filter: StateFilter) -> impl Iterator<Item = &mut Child> {
        self.slots
            .iter_mut()
            .filter_map(|s| s.as_mut())
            .filter(move |c| c.neighbor.matches_filter(filter))
    }

    /// Number of children passing `filter`.
    pub fn count(&self, filter: StateFilter) -> usize {
        self.iter(filter).count()
    }

    /// `true` if at least one child passes `filter` (OT `HasChildren`).
    pub fn has_children(&self, filter: StateFilter) -> bool {
        self.iter(filter).next().is_some()
    }

    /// `true` if any valid (or restoring) child is not rx-on-when-idle.
    pub fn has_sleepy_children(&self) -> bool {
        self.iter(StateFilter::ValidOrRestoring)
            .any(|c| !c.neighbor.is_rx_on_when_idle())
    }

    /// Remove children that were not heard from for their timeout and are
    /// `Valid`; returns how many were removed. `on_remove(slot, child)` is
    /// called for each (to send/clear indirect messages, update Network
    /// Data, ...).
    pub fn expire<F: FnMut(usize, Child)>(&mut self, now: Instant, mut on_remove: F) -> usize {
        let mut n = 0;
        for (i, slot) in self.slots.iter_mut().enumerate() {
            let expired = slot
                .as_ref()
                .is_some_and(|c| c.neighbor.is_valid() && c.is_timed_out(now));
            if expired && let Some(c) = slot.take() {
                on_remove(i, c);
                n += 1;
            }
        }
        n
    }
}

/// Fixed-capacity router table (storage and lookups only; OT `RouterTable`
/// minus the router-ID allocation logic, which lives in the router role).
#[derive(Debug, Clone)]
pub struct RouterTable<const N: usize> {
    slots: [Option<Router>; N],
}

impl<const N: usize> Default for RouterTable<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> RouterTable<N> {
    /// Capacity (Thread allows at most 32 active routers).
    pub const CAPACITY: usize = N;

    /// Empty table.
    pub const fn new() -> Self {
        Self {
            slots: [const { None }; N],
        }
    }

    /// Remove all routers.
    pub fn clear(&mut self) {
        self.slots.iter_mut().for_each(|s| *s = None);
    }

    /// Add a router entry. [`Error::Already`] if the router ID is in use,
    /// [`Error::NoBufs`] if full, [`Error::InvalidArgs`] for an ID above 62.
    pub fn add(
        &mut self,
        router_id: u8,
        ext_address: ExtAddress,
        now: Instant,
    ) -> Result<&mut Router> {
        if router_id > Rloc16::MAX_ROUTER_ID {
            return Err(Error::InvalidArgs);
        }
        if self.find_by_id(router_id).is_some() {
            return Err(Error::Already);
        }
        let slot = self
            .slots
            .iter_mut()
            .find(|s| s.is_none())
            .ok_or(Error::NoBufs)?;
        Ok(slot.insert(Router::new(router_id, ext_address, now)))
    }

    /// Remove the router with `router_id`.
    pub fn remove(&mut self, router_id: u8) -> Option<Router> {
        self.slots
            .iter_mut()
            .find(|s| s.as_ref().is_some_and(|r| r.router_id == router_id))?
            .take()
    }

    /// Find by router ID.
    pub fn find_by_id(&self, router_id: u8) -> Option<&Router> {
        self.slots
            .iter()
            .flatten()
            .find(|r| r.router_id == router_id)
    }

    /// Find by router ID, mutable.
    pub fn find_by_id_mut(&mut self, router_id: u8) -> Option<&mut Router> {
        self.slots
            .iter_mut()
            .flatten()
            .find(|r| r.router_id == router_id)
    }

    /// Find by extended address among routers passing `filter`.
    pub fn find_by_ext(&self, ext: &ExtAddress, filter: StateFilter) -> Option<&Router> {
        self.iter(filter)
            .find(|r| r.neighbor.matches_ext(ext, filter))
    }

    /// Find by extended address, mutable.
    pub fn find_by_ext_mut(
        &mut self,
        ext: &ExtAddress,
        filter: StateFilter,
    ) -> Option<&mut Router> {
        self.iter_mut(filter)
            .find(|r| r.neighbor.matches_ext(ext, filter))
    }

    /// Find by RLOC16 (child bits ignored) among routers passing `filter`.
    pub fn find_by_rloc(&self, rloc: Rloc16, filter: StateFilter) -> Option<&Router> {
        let id = rloc.router_id();
        self.iter(filter)
            .find(|r| r.router_id == id && r.neighbor.matches_filter(filter))
    }

    /// Iterate routers passing `filter`.
    pub fn iter(&self, filter: StateFilter) -> impl Iterator<Item = &Router> {
        self.slots
            .iter()
            .flatten()
            .filter(move |r| r.neighbor.matches_filter(filter))
    }

    /// Iterate routers passing `filter`, mutable.
    pub fn iter_mut(&mut self, filter: StateFilter) -> impl Iterator<Item = &mut Router> {
        self.slots
            .iter_mut()
            .flatten()
            .filter(move |r| r.neighbor.matches_filter(filter))
    }

    /// Number of routers passing `filter`.
    pub fn count(&self, filter: StateFilter) -> usize {
        self.iter(filter).count()
    }
}

#[cfg(test)]
#[path = "neighbor_tests.rs"]
mod tests;
