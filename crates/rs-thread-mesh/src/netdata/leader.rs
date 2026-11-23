//! The Network Data of the Leader (OT `NetworkData::Leader`, FTD part):
//! registration of the Server Data of routers and their children, stale
//! entry removal, 6LoWPAN context ID allocation with reuse delay, service
//! ID allocation and the version / stable version counters.
//!
//! The store works on the TLV bytes like OT, but every change is built in
//! a scratch buffer of the same capacity and then swapped in, so a
//! registration that does not fit leaves the data (and the context ID
//! state) untouched, where OT keeps what was applied before the failure.
//!
//! # Use
//!
//! - On [`MleEvent::LeaderStarted`](rs_thread_mle::env::MleEvent::LeaderStarted)
//!   call [`Leader::start`] with the version numbers of the new Leader Data.
//! - Feed `/a/sd` to [`server_data::handle_server_data`](super::server_data::handle_server_data),
//!   call [`Leader::remove_stale_router_ids`] on
//!   [`MleEvent::RouterTableChanged`](rs_thread_mle::env::MleEvent::RouterTableChanged)
//!   and [`Leader::handle_timer`] at [`Leader::next_deadline`].
//! - After each of them, if the result [`Changed::any`], call
//!   [`Leader::publish`] to put the new versions into the MLE core.

use rs_thread_core::bytes::Writer;
use rs_thread_core::time::{Duration, Instant};
use rs_thread_core::{Error, Result};
use rs_thread_mle::Mle;
use rs_thread_mle::env::MleEnv;

use super::data::NetworkData;
use super::tlv::{
    ContextTlv, PrefixTlv, RawIter, ServerTlv, ServiceTlv, begin_tlv, end_tlv, ty, write_context,
    write_service,
};
use super::view::NetworkDataView;

/// Smallest allocatable 6LoWPAN context ID (0 is the mesh-local prefix).
pub const MIN_CONTEXT_ID: u8 = 1;
/// Largest context ID.
pub const MAX_CONTEXT_ID: u8 = 15;
/// How long a context ID stays reserved after its prefix lost its last
/// Border Router (OT `ContextIds::kReuseDelay`, 5 minutes).
pub const CONTEXT_ID_REUSE_DELAY: Duration = Duration::from_secs(5 * 60);
/// How long a leader that restores its role after a reset waits for the
/// Network Data from its neighbors (OT `kMaxNetDataSyncWait`).
pub const MAX_NET_DATA_SYNC_WAIT: Duration = Duration::from_secs(60);
/// Number of service IDs (4 bits).
const SERVICE_IDS: u8 = 16;

/// What a change touched (OT `ChangedFlags`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Changed {
    /// Network Data changed: the version was incremented.
    pub any: bool,
    /// A stable TLV changed: the stable version was incremented as well.
    pub stable: bool,
}

impl Changed {
    fn touch(&mut self, stable: bool) {
        self.any = true;
        self.stable |= stable;
    }
}

/// How an RLOC16 is matched when removing entries (OT `MatchMode`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatchMode {
    /// Exact RLOC16.
    Rloc16,
    /// Same router ID: the router and all its children.
    RouterId,
}

fn rloc_match(a: u16, b: u16, mode: MatchMode) -> bool {
    match mode {
        MatchMode::Rloc16 => a == b,
        MatchMode::RouterId => a >> 10 == b >> 10,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CtxState {
    Unallocated,
    InUse,
    /// Compression cleared; the ID is freed at this time.
    RemoveAt(Instant),
}

#[derive(Debug, Clone, Copy)]
struct ContextIds {
    state: [CtxState; 16],
    reuse_delay: Duration,
}

impl ContextIds {
    const fn new(reuse_delay: Duration) -> Self {
        Self {
            state: [CtxState::Unallocated; 16],
            reuse_delay,
        }
    }

    fn get_unallocated(&self) -> Result<u8> {
        (MIN_CONTEXT_ID..=MAX_CONTEXT_ID)
            .find(|&i| self.state[usize::from(i)] == CtxState::Unallocated)
            .ok_or(Error::NoBufs)
    }

    fn mark_in_use(&mut self, id: u8) {
        self.state[usize::from(id & 15)] = CtxState::InUse;
    }

    fn schedule_remove(&mut self, id: u8, now: Instant) {
        let s = &mut self.state[usize::from(id & 15)];
        if *s == CtxState::InUse {
            *s = CtxState::RemoveAt(now.saturating_add(self.reuse_delay));
        }
    }
}

/// One edit of the Network Data.
struct Edit<'p> {
    /// Entries of this RLOC16 are removed unless the payload has them.
    rloc: Option<(u16, MatchMode)>,
    /// Entries to add (registered Server Data, already validated).
    payload: NetworkDataView<'p>,
    /// Remove the 6LoWPAN context with this ID.
    drop_context: Option<u8>,
}

impl Edit<'_> {
    fn hit(&self, rloc16: u16) -> bool {
        self.rloc.is_some_and(|(r, m)| rloc_match(rloc16, r, m))
    }
}

const GROUPS: [(u8, bool); 4] = [
    (ty::HAS_ROUTE, false),
    (ty::HAS_ROUTE, true),
    (ty::BORDER_ROUTER, false),
    (ty::BORDER_ROUTER, true),
];

fn group_index(t: u8, stable: bool) -> usize {
    usize::from(t == ty::BORDER_ROUTER) * 2 + usize::from(stable)
}

fn entry_size(t: u8) -> usize {
    if t == ty::HAS_ROUTE { 3 } else { 4 }
}

/// The value of the payload prefix's `(ty, stable)` sub-TLV.
fn pay_group<'a>(pay: Option<&PrefixTlv<'a>>, t: u8, stable: bool) -> Option<&'a [u8]> {
    pay?.sub_tlvs()
        .find(|s| s.ty == t && s.stable == stable)
        .map(|s| s.value)
}

fn contains_entry(group: Option<&[u8]>, esz: usize, e: &[u8]) -> bool {
    group.is_some_and(|g| g.chunks_exact(esz).any(|x| x == e))
}

fn entry_rloc(e: &[u8]) -> u16 {
    u16::from_be_bytes([e[0], e[1]])
}

/// Write the merged Has Route / Border Router sub-TLV; `false` if it
/// ended up empty (and was not written).
fn emit_group(
    w: &mut Writer<'_>,
    t: u8,
    stable: bool,
    old: Option<&[u8]>,
    pay: Option<&[u8]>,
    edit: &Edit<'_>,
    ch: &mut Changed,
) -> Result<bool> {
    let esz = entry_size(t);
    let off = begin_tlv(w, t, stable)?;
    let start = w.len();
    if let Some(old) = old {
        for e in old.chunks_exact(esz) {
            if edit.hit(entry_rloc(e)) && !contains_entry(pay, esz, e) {
                ch.touch(stable);
            } else {
                w.write_slice(e)?;
            }
        }
    }
    if let Some(p) = pay {
        for e in p.chunks_exact(esz) {
            if !contains_entry(Some(&w.written()[start..]), esz, e) {
                w.write_slice(e)?;
                ch.touch(stable);
            }
        }
    }
    if w.len() == start {
        w.truncate(off);
        return Ok(false);
    }
    end_tlv(w, off)?;
    Ok(true)
}

fn merge_prefix(
    w: &mut Writer<'_>,
    ids: &mut ContextIds,
    old: Option<&PrefixTlv<'_>>,
    pay: Option<&PrefixTlv<'_>>,
    edit: &Edit<'_>,
    now: Instant,
    ch: &mut Changed,
) -> Result<()> {
    let base = old.or(pay).ok_or(Error::InvalidArgs)?;
    let prefix = base.prefix;

    let old_br_kept = old.is_some_and(|o| {
        o.sub_tlvs().filter(|s| s.ty == ty::BORDER_ROUTER).any(|s| {
            s.value.chunks_exact(4).any(|e| {
                !edit.hit(entry_rloc(e))
                    || contains_entry(pay_group(pay, ty::BORDER_ROUTER, s.stable), 4, e)
            })
        })
    });
    let pay_br = pay.is_some_and(|p| {
        p.sub_tlvs()
            .any(|s| s.ty == ty::BORDER_ROUTER && !s.value.is_empty())
    });
    let pay_stable_br = pay.is_some_and(|p| {
        p.sub_tlvs()
            .any(|s| s.ty == ty::BORDER_ROUTER && s.stable && !s.value.is_empty())
    });
    let br_after = old_br_kept || pay_br;

    let off = begin_tlv(w, ty::PREFIX, false)?;
    w.write_u8(base.domain_id)?;
    w.write_u8(prefix.len())?;
    w.write_slice(prefix.as_bytes())?;
    let mut any = false;
    let mut any_stable = false;
    let mut used = [false; 4];
    let mut ctx_done = false;

    if let Some(o) = old {
        for s in o.sub_tlvs() {
            match s.ty {
                ty::HAS_ROUTE | ty::BORDER_ROUTER => {
                    let idx = group_index(s.ty, s.stable);
                    let first = !used[idx];
                    used[idx] = true;
                    let pg = if first {
                        pay_group(pay, s.ty, s.stable)
                    } else {
                        None
                    };
                    if emit_group(w, s.ty, s.stable, Some(s.value), pg, edit, ch)? {
                        any = true;
                        any_stable |= s.stable;
                    }
                }
                ty::CONTEXT => {
                    let Ok(c) = ContextTlv::parse(&s) else {
                        continue;
                    };
                    if edit.drop_context == Some(c.id) {
                        continue;
                    }
                    let stable = s.stable || pay_stable_br;
                    if br_after {
                        ids.mark_in_use(c.id);
                    } else {
                        ids.schedule_remove(c.id, now);
                    }
                    write_context(w, stable, c.id, br_after, c.len)?;
                    any = true;
                    any_stable |= stable;
                    ctx_done = true;
                }
                _ => {
                    s.write(w)?;
                    any = true;
                    any_stable |= s.stable;
                }
            }
        }
    }
    for (idx, (t, stable)) in GROUPS.into_iter().enumerate() {
        if !used[idx]
            && let Some(pg) = pay_group(pay, t, stable)
            && emit_group(w, t, stable, None, Some(pg), edit, ch)?
        {
            any = true;
            any_stable |= stable;
        }
    }
    if !ctx_done && br_after && edit.drop_context.is_none() {
        let id = ids.get_unallocated()?;
        write_context(w, pay_stable_br, id, true, prefix.len())?;
        ids.mark_in_use(id);
        any = true;
        any_stable |= pay_stable_br;
    }

    if !any {
        w.truncate(off);
        return Ok(());
    }
    end_tlv(w, off)?;
    if any_stable {
        w.written_mut()[off] |= 1;
    }
    Ok(())
}

fn merge_service(
    w: &mut Writer<'_>,
    old: Option<&ServiceTlv<'_>>,
    pay: Option<&ServiceTlv<'_>>,
    service_id: u8,
    edit: &Edit<'_>,
    ch: &mut Changed,
) -> Result<()> {
    let base = old.or(pay).ok_or(Error::InvalidArgs)?;
    let pay_server = pay.and_then(|p| RawIter::new(p.subs).find(|t| t.ty == ty::SERVER));
    let off = w.len();
    let mut any = false;
    let mut any_stable = false;
    write_service(
        w,
        false,
        service_id,
        base.enterprise_number,
        base.service_data,
        |w| {
            let mut pay_present = false;
            if let Some(o) = old {
                for s in RawIter::new(o.subs) {
                    if s.ty == ty::SERVER {
                        let Ok(sv) = ServerTlv::parse(&s) else {
                            continue;
                        };
                        let same = pay_server == Some(s);
                        if edit.hit(sv.rloc16) && !same {
                            ch.touch(s.stable);
                            continue;
                        }
                        pay_present |= same;
                    }
                    s.write(w)?;
                    any = true;
                    any_stable |= s.stable;
                }
            }
            if let Some(p) = pay_server
                && !pay_present
            {
                p.write(w)?;
                ch.touch(p.stable);
                any = true;
                any_stable |= p.stable;
            }
            Ok(())
        },
    )?;
    if !any {
        w.truncate(off);
        return Ok(());
    }
    if any_stable {
        w.written_mut()[off] |= 1;
    }
    Ok(())
}

fn alloc_service_id(written: &[u8]) -> Result<u8> {
    (0..SERVICE_IDS)
        .find(|&id| {
            !NetworkDataView(written)
                .service_tlvs()
                .any(|s| s.service_id == id)
        })
        .ok_or(Error::NoBufs)
}

fn build(
    out: &mut [u8],
    data: &[u8],
    ids: &mut ContextIds,
    edit: &Edit<'_>,
    now: Instant,
    ch: &mut Changed,
) -> Result<usize> {
    let mut w = Writer::new(out);
    for t in NetworkDataView(data).tlvs() {
        match t.ty {
            ty::PREFIX => {
                let Ok(o) = PrefixTlv::parse(&t) else {
                    continue;
                };
                let pay = edit.payload.prefixes().find(|p| p.prefix == o.prefix);
                merge_prefix(&mut w, ids, Some(&o), pay.as_ref(), edit, now, ch)?;
            }
            ty::SERVICE => {
                let Ok(o) = ServiceTlv::parse(&t) else {
                    continue;
                };
                let pay = edit.payload.service_tlvs().find(|p| {
                    p.enterprise_number == o.enterprise_number && p.service_data == o.service_data
                });
                merge_service(&mut w, Some(&o), pay.as_ref(), o.service_id, edit, ch)?;
            }
            _ => t.write(&mut w)?,
        }
    }
    for p in edit.payload.prefixes() {
        if NetworkDataView(w.written())
            .prefixes()
            .any(|q| q.prefix == p.prefix)
        {
            continue;
        }
        merge_prefix(&mut w, ids, None, Some(&p), edit, now, ch)?;
    }
    for p in edit.payload.service_tlvs() {
        if NetworkDataView(w.written())
            .service_tlvs()
            .any(|q| q.enterprise_number == p.enterprise_number && q.service_data == p.service_data)
        {
            continue;
        }
        let id = alloc_service_id(w.written())?;
        merge_service(&mut w, None, Some(&p), id, edit, ch)?;
    }
    Ok(w.len())
}

/// Validate registered Server Data (OT `Leader::Validate`): well-formed,
/// no duplicate prefixes or services, every Border Router / Has Route /
/// Server entry carries `rloc16`, one entry per sub-TLV, at most one stable
/// and one temporary sub-TLV of each kind, a prefix with at least one
/// entry, a service with exactly one server.
pub fn validate(payload: &[u8], rloc16: u16) -> Result<()> {
    if !super::tlv::is_well_formed(payload) {
        return Err(Error::Parse);
    }
    let view = NetworkDataView(payload);
    for (i, t) in view.tlvs().enumerate() {
        match t.ty {
            ty::PREFIX => {
                let p = PrefixTlv::parse(&t)?;
                if view.tlvs().take(i).any(|q| {
                    q.ty == ty::PREFIX && PrefixTlv::parse(&q).is_ok_and(|x| x.prefix == p.prefix)
                }) {
                    return Err(Error::Parse);
                }
                validate_prefix(&p, rloc16)?;
            }
            ty::SERVICE => {
                let s = ServiceTlv::parse(&t)?;
                if view.tlvs().take(i).any(|q| {
                    q.ty == ty::SERVICE
                        && ServiceTlv::parse(&q).is_ok_and(|x| {
                            x.enterprise_number == s.enterprise_number
                                && x.service_data == s.service_data
                        })
                }) {
                    return Err(Error::Parse);
                }
                validate_service(&s, rloc16)?;
            }
            _ => {}
        }
    }
    Ok(())
}

fn validate_prefix(p: &PrefixTlv<'_>, rloc16: u16) -> Result<()> {
    let mut seen = [false; 4];
    let mut found = false;
    if !super::tlv::is_well_formed(p.subs) {
        return Err(Error::Parse);
    }
    for s in p.sub_tlvs() {
        if s.ty == ty::BORDER_ROUTER || s.ty == ty::HAS_ROUTE {
            let idx = group_index(s.ty, s.stable);
            if seen[idx] {
                return Err(Error::Parse);
            }
            seen[idx] = true;
            if s.value.len() != entry_size(s.ty) || entry_rloc(s.value) != rloc16 {
                return Err(Error::Parse);
            }
            found = true;
        }
    }
    if found { Ok(()) } else { Err(Error::Parse) }
}

fn validate_service(s: &ServiceTlv<'_>, rloc16: u16) -> Result<()> {
    if !super::tlv::is_well_formed(s.subs) {
        return Err(Error::Parse);
    }
    let mut servers = RawIter::new(s.subs).filter(|t| t.ty == ty::SERVER);
    let (Some(first), None) = (servers.next(), servers.next()) else {
        return Err(Error::Parse);
    };
    if ServerTlv::parse(&first)?.rloc16 == rloc16 {
        Ok(())
    } else {
        Err(Error::Parse)
    }
}

/// Leader Network Data with `N` bytes of capacity.
#[derive(Debug, Clone)]
pub struct Leader<const N: usize> {
    data: NetworkData<N>,
    version: u8,
    stable_version: u8,
    ids: ContextIds,
    /// Restoring after a reset: registrations are refused until the
    /// Network Data was recovered or this time passed.
    sync_deadline: Option<Instant>,
}

impl<const N: usize> Default for Leader<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> Leader<N> {
    /// An empty store, versions 0.
    pub const fn new() -> Self {
        Self {
            data: NetworkData::new(),
            version: 0,
            stable_version: 0,
            ids: ContextIds::new(CONTEXT_ID_REUSE_DELAY),
            sync_deadline: None,
        }
    }

    /// This device became the leader of a new partition (OT
    /// `Leader::Reset` on `BecomeLeader`): drop all data and context
    /// state and continue with the given versions (those of the Leader
    /// Data the MLE core chose).
    pub fn start(&mut self, version: u8, stable_version: u8) {
        self.data.clear();
        let delay = self.ids.reuse_delay;
        self.ids = ContextIds::new(delay);
        self.version = version;
        self.stable_version = stable_version;
        self.sync_deadline = None;
    }

    /// Seconds a freed 6LoWPAN Context ID stays unusable (OT
    /// `GetContextIdReuseDelay`).
    pub const fn context_id_reuse_delay(&self) -> Duration {
        self.ids.reuse_delay
    }

    /// This device restored the leader role after a reset (OT
    /// `Leader::Start(kRestoringLeaderRoleAfterReset)`): the store is empty
    /// and registrations / Commissioning Data changes are refused until
    /// [`restore`](Self::restore) delivers the Network Data a neighbor
    /// holds. After [`MAX_NET_DATA_SYNC_WAIT`] without it
    /// [`sync_timed_out`](Self::sync_timed_out) tells the caller to give up
    /// the leader role (`Mle::become_detached`).
    pub fn start_restoring(&mut self, version: u8, stable_version: u8, now: Instant) {
        self.start(version, stable_version);
        self.sync_deadline = Some(now.saturating_add(MAX_NET_DATA_SYNC_WAIT));
    }

    /// `true` between [`start_restoring`](Self::start_restoring) and the
    /// recovery (or the time-out).
    pub const fn is_waiting_for_sync(&self) -> bool {
        self.sync_deadline.is_some()
    }

    /// `true` once if the wait for the Network Data ran out (OT
    /// `Leader::HandleTimer` while `mWaitingForNetDataSync`).
    pub fn sync_timed_out(&mut self, now: Instant) -> bool {
        match self.sync_deadline {
            Some(t) if now >= t => {
                self.sync_deadline = None;
                true
            }
            _ => false,
        }
    }

    /// The Network Data of the partition arrived after
    /// [`start_restoring`](Self::start_restoring) (OT `SetNetworkData` +
    /// `HandleNetworkDataRestoredAfterReset`): adopt `data` and the
    /// versions of the Leader Data, drop the entries of router IDs that are
    /// not allocated any more (versions are incremented if so), and mark
    /// the 6LoWPAN context IDs in use (those without compression start
    /// their reuse delay). The caller then lets the commissioner state
    /// adopt the Commissioning Data. [`Error::InvalidState`] if the leader
    /// is not waiting; [`Error::NoBufs`] / [`Error::Parse`] if `data` does
    /// not fit / parse (still waiting then).
    pub fn restore(
        &mut self,
        data: &[u8],
        version: u8,
        stable_version: u8,
        is_router_id_allocated: impl Fn(u8) -> bool,
        now: Instant,
    ) -> Result<Changed> {
        if self.sync_deadline.is_none() {
            return Err(Error::InvalidState);
        }
        self.data.set(data)?;
        self.version = version;
        self.stable_version = stable_version;
        self.sync_deadline = None;
        let ch = self.remove_stale_router_ids(is_router_id_allocated, now);
        let mut ids = self.ids;
        for c in self.data.view().contexts() {
            ids.mark_in_use(c.id);
            if !c.compress {
                ids.schedule_remove(c.id, now);
            }
        }
        self.ids = ids;
        Ok(ch)
    }

    /// Change how long a context ID stays reserved after its last Border
    /// Router left (OT `SetContextIdReuseDelay`).
    pub fn set_context_id_reuse_delay(&mut self, delay: Duration) {
        self.ids.reuse_delay = delay;
    }

    /// The full Network Data.
    pub fn data(&self) -> &NetworkData<N> {
        &self.data
    }

    /// Network Data version.
    pub const fn version(&self) -> u8 {
        self.version
    }

    /// Stable Network Data version.
    pub const fn stable_version(&self) -> u8 {
        self.stable_version
    }

    /// Copy the full or the stable Network Data (the form
    /// [`MleEnv::network_data`] returns).
    pub fn copy_to(&self, stable_only: bool, out: &mut [u8]) -> Result<usize> {
        if stable_only {
            self.data.copy_stable(out)
        } else {
            out.get_mut(..self.data.len())
                .ok_or(Error::NoBufs)?
                .copy_from_slice(self.data.as_bytes());
            Ok(self.data.len())
        }
    }

    /// Put the current versions into the MLE core's Leader Data and let it
    /// react (advertise soon, refresh sleepy children). Call after every
    /// change.
    pub fn publish<E: MleEnv, const C: usize>(&self, mle: &mut Mle<C>, env: &mut E, now: Instant) {
        let mut ld = *mle.leader_data();
        ld.data_version = self.version;
        ld.stable_data_version = self.stable_version;
        mle.set_leader_data(ld);
        mle.network_data_updated(env, now);
    }

    fn bump(&mut self, ch: Changed) {
        if ch.any {
            self.version = self.version.wrapping_add(1);
            if ch.stable {
                self.stable_version = self.stable_version.wrapping_add(1);
            }
        }
    }

    fn apply(&mut self, edit: &Edit<'_>, now: Instant) -> Result<Changed> {
        let mut scratch = [0u8; N];
        let mut ids = self.ids;
        let mut ch = Changed::default();
        let n = build(
            &mut scratch,
            self.data.as_bytes(),
            &mut ids,
            edit,
            now,
            &mut ch,
        )?;
        self.data.set(&scratch[..n])?;
        self.ids = ids;
        self.bump(ch);
        Ok(ch)
    }

    /// Register the Server Data `payload` of `rloc16` (OT
    /// `RegisterNetworkData`): the entries of that RLOC16 not present in the
    /// payload are removed, the new ones added. `is_router_id_allocated`
    /// tells whether the router ID of `rloc16` is in use
    /// ([`Error::NotFound`] otherwise); [`Error::Parse`] if the payload
    /// does not validate, [`Error::NoBufs`] if it does not fit or no
    /// context / service ID is free (nothing is changed then).
    pub fn register(
        &mut self,
        rloc16: u16,
        payload: &[u8],
        is_router_id_allocated: impl Fn(u8) -> bool,
        now: Instant,
    ) -> Result<Changed> {
        if self.sync_deadline.is_some() {
            return Err(Error::InvalidState);
        }
        if !is_router_id_allocated((rloc16 >> 10) as u8) {
            return Err(Error::NotFound);
        }
        validate(payload, rloc16)?;
        self.apply(
            &Edit {
                rloc: Some((rloc16, MatchMode::Rloc16)),
                payload: NetworkDataView(payload),
                drop_context: None,
            },
            now,
        )
    }

    /// Remove all entries of `rloc16` (OT `RemoveBorderRouter`).
    pub fn remove_rloc(&mut self, rloc16: u16, mode: MatchMode, now: Instant) -> Changed {
        self.apply(
            &Edit {
                rloc: Some((rloc16, mode)),
                payload: NetworkDataView(&[]),
                drop_context: None,
            },
            now,
        )
        .unwrap_or_default()
    }

    /// Remove the entries of every router ID that is no longer allocated
    /// (a released or timed out router; OT `RouterTable::Release`).
    pub fn remove_stale_router_ids(
        &mut self,
        is_router_id_allocated: impl Fn(u8) -> bool,
        now: Instant,
    ) -> Changed {
        let mut total = Changed::default();
        loop {
            let v = self.data.view();
            let stale = v
                .on_mesh_prefixes()
                .map(|e| e.rloc16)
                .chain(v.external_routes().map(|e| e.rloc16))
                .chain(v.services().map(|e| e.rloc16))
                .find(|&r| r & 0xfc00 != 0xfc00 && !is_router_id_allocated((r >> 10) as u8));
            let Some(r) = stale else { break };
            let ch = self.remove_rloc(r, MatchMode::RouterId, now);
            if !ch.any {
                break;
            }
            total.any = true;
            total.stable |= ch.stable;
        }
        total
    }

    /// Free context IDs whose reuse delay has passed and remove their
    /// 6LoWPAN Context TLVs (OT `ContextIds::HandleTimer`); both versions
    /// are incremented for each.
    pub fn handle_timer(&mut self, now: Instant) -> Changed {
        let mut total = Changed::default();
        for id in MIN_CONTEXT_ID..=MAX_CONTEXT_ID {
            let CtxState::RemoveAt(t) = self.ids.state[usize::from(id)] else {
                continue;
            };
            if now < t {
                continue;
            }
            self.ids.state[usize::from(id)] = CtxState::Unallocated;
            let edit = Edit {
                rloc: None,
                payload: NetworkDataView(&[]),
                drop_context: Some(id),
            };
            let mut scratch = [0u8; N];
            let mut ids = self.ids;
            let mut ch = Changed::default();
            if let Ok(n) = build(
                &mut scratch,
                self.data.as_bytes(),
                &mut ids,
                &edit,
                now,
                &mut ch,
            ) && self.data.set(&scratch[..n]).is_ok()
            {
                self.ids = ids;
            }
            self.bump(Changed {
                any: true,
                stable: true,
            });
            total = Changed {
                any: true,
                stable: true,
            };
        }
        total
    }

    /// When [`handle_timer`](Self::handle_timer) next has work.
    pub fn next_deadline(&self) -> Option<Instant> {
        self.ids
            .state
            .iter()
            .filter_map(|s| match s {
                CtxState::RemoveAt(t) => Some(*t),
                _ => None,
            })
            .chain(self.sync_deadline)
            .min()
    }

    /// Increment the version (OT `IncrementVersion`).
    pub fn increment_version(&mut self) -> Changed {
        let ch = Changed {
            any: true,
            stable: false,
        };
        self.bump(ch);
        ch
    }

    /// Increment both versions (OT `IncrementVersionAndStableVersion`), as
    /// done when a dataset changes.
    pub fn increment_version_and_stable(&mut self) -> Changed {
        let ch = Changed {
            any: true,
            stable: true,
        };
        self.bump(ch);
        ch
    }

    /// Replace the Commissioning Data TLV with `value` (an empty `value`
    /// removes it) and increment the version (OT `SetCommissioningData`).
    /// The TLV is not stable and is appended last. [`Error::NoBufs`] if it
    /// does not fit (nothing is changed).
    pub fn set_commissioning_data(&mut self, value: &[u8]) -> Result<Changed> {
        if self.sync_deadline.is_some() {
            return Err(Error::InvalidState);
        }
        let mut scratch = [0u8; N];
        let mut w = Writer::new(&mut scratch);
        for t in RawIter::new(self.data.as_bytes()) {
            if t.ty != ty::COMMISSIONING {
                t.write(&mut w)?;
            }
        }
        if !value.is_empty() {
            super::tlv::RawTlv {
                ty: ty::COMMISSIONING,
                stable: false,
                value,
            }
            .write(&mut w)?;
        }
        let n = w.written().len();
        self.data.set(&scratch[..n])?;
        Ok(self.increment_version())
    }

    /// The Commissioning Data TLV value (OT `GetCommissioningData`).
    pub fn commissioning_data(&self) -> Option<&[u8]> {
        self.data.view().commissioning_data()
    }

    /// Context IDs currently reserved (in use or waiting for reuse), for
    /// diagnostics.
    pub fn allocated_context_ids(&self) -> impl Iterator<Item = u8> + '_ {
        (MIN_CONTEXT_ID..=MAX_CONTEXT_ID)
            .filter(|&i| self.ids.state[usize::from(i)] != CtxState::Unallocated)
    }
}
