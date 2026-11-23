//! Network Data Publisher (OT `NetworkData::Publisher`).
//!
//! Publishes on-mesh prefixes, external routes and the DNS/SRP service
//! (anycast, unicast with the address in the service data or in the server
//! data) into the local Network Data, but only as many entries as the
//! partition needs. For every published entry the publisher compares the
//! number of matching entries in the leader's Network Data with the desired
//! number: if there are too few it adds its entry after a random delay, if
//! there are too many it removes it after a random delay (longer if its own
//! entry is preferred over the others), so several devices that publish the
//! same thing converge without talking to each other.
//!
//! Sans-IO: [`Publisher::poll`] runs the state machines against the
//! current leader data ([`PublishContext`]) and edits the [`LocalData`];
//! when [`Publisher::take_local_changed`] returns `true` the caller reports
//! [`NotifierEvent::LocalChanged`](super::notifier::NotifierEvent::LocalChanged)
//! so the change reaches the leader. Call it on role and Network Data
//! changes and at [`Publisher::next_deadline`].
//!
//! OT's "requester" (user vs. Border Routing Manager entries) is not
//! modelled: all entries share one capacity.

use core::net::Ipv6Addr;

use rs_thread_core::time::{Duration, Instant};
use rs_thread_core::types::Rloc16;
use rs_thread_core::{Error, Result};
use rand_core::Rng;

use super::local::{ExternalRouteConfig, LocalData, OnMeshPrefixConfig, ServiceConfig};
use super::tlv::{NetPrefix, THREAD_ENTERPRISE_NUMBER};
use super::view::{NetworkDataView, ServiceEntry as ViewService};

/// Longest random delay before adding an entry
/// (`OPENTHREAD_CONFIG_NETDATA_PUBLISHER_MAX_DELAY_TO_ADD`).
pub const MAX_DELAY_TO_ADD: Duration = Duration::from_millis(3500);
/// Longest random delay before removing an entry (`..._MAX_DELAY_TO_REMOVE`).
pub const MAX_DELAY_TO_REMOVE: Duration = Duration::from_millis(15_000);
/// Extra delay before removing an entry that is preferred over the other
/// entries (`..._EXTRA_DELAY_TIME_TO_REMOVE_PREFERRED`).
pub const EXTRA_DELAY_TO_REMOVE_PREFERRED: Duration = Duration::from_millis(16_000);
/// Desired number of DNS/SRP anycast entries.
pub const DESIRED_NUM_ANYCAST: u8 = 8;
/// Desired number of DNS/SRP unicast entries.
pub const DESIRED_NUM_UNICAST: u8 = 2;
/// Desired number of entries of an on-mesh prefix.
pub const DESIRED_NUM_ON_MESH_PREFIX: u8 = 3;
/// Desired number of entries of an external route.
pub const DESIRED_NUM_EXTERNAL_ROUTE: u8 = 10;

const SERVICE_NUMBER_ANYCAST: u8 = 0x5c;
const SERVICE_NUMBER_UNICAST: u8 = 0x5d;

/// State of a published entry (OT `Publisher::Entry::State`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum EntryState {
    /// Not published.
    NoEntry,
    /// Published, waiting for the Network Data to need it.
    ToAdd,
    /// Will be added when the random delay is over.
    Adding,
    /// In the local Network Data.
    Added,
    /// Will be removed when the random delay is over.
    Removing,
}

/// An entry was added to / removed from the local Network Data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublisherEvent {
    /// A prefix or route entry was added.
    PrefixAdded(NetPrefix),
    /// A prefix or route entry was removed.
    PrefixRemoved(NetPrefix),
    /// The DNS/SRP service entry was added.
    DnsSrpAdded,
    /// The DNS/SRP service entry was removed.
    DnsSrpRemoved,
}

/// What the publisher reads from the rest of the stack.
#[derive(Debug, Clone, Copy)]
pub struct PublishContext<'a> {
    /// Attached to a partition; entries are only changed while attached.
    pub attached: bool,
    /// Router or leader (for the preference between entries).
    pub router_or_leader: bool,
    /// Own RLOC16.
    pub rloc16: Rloc16,
    /// The leader's Network Data as this device has it.
    pub leader: NetworkDataView<'a>,
    /// Mesh-local EID (for the unicast DNS/SRP entry with the address in
    /// the server data).
    pub ml_eid: Ipv6Addr,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Item {
    OnMesh(OnMeshPrefixConfig),
    Route(ExternalRouteConfig),
}

impl Item {
    fn prefix(&self) -> NetPrefix {
        match self {
            Self::OnMesh(c) => c.prefix,
            Self::Route(c) => c.prefix,
        }
    }

    fn same_kind(&self, other: &Item) -> bool {
        matches!(
            (self, other),
            (Self::OnMesh(_), Self::OnMesh(_)) | (Self::Route(_), Self::Route(_))
        )
    }
}

#[derive(Debug, Clone, Copy)]
struct PrefixEntry {
    item: Item,
    state: EntryState,
    update: Instant,
}

/// DNS/SRP service to publish.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsSrpService {
    /// Anycast service (address is the service ALOC).
    Anycast {
        /// Sequence number.
        sequence_number: u8,
        /// Version (0: not sent).
        version: u8,
    },
    /// Unicast service with the address and port in the service data.
    Unicast {
        /// Server address.
        address: Ipv6Addr,
        /// Port.
        port: u16,
        /// Version (0: not sent).
        version: u8,
    },
    /// Unicast service with the mesh-local EID and the port in the server
    /// data.
    UnicastMlEid {
        /// Port.
        port: u16,
        /// Version (0: not sent).
        version: u8,
    },
}

#[derive(Debug, Clone, Copy)]
struct ServiceEntry {
    info: DnsSrpService,
    /// The address of a [`DnsSrpService::UnicastMlEid`] entry as added.
    ml_eid: Ipv6Addr,
    state: EntryState,
    update: Instant,
}

/// The publisher with room for `E` prefix / route entries (OT: 3).
#[derive(Debug, Clone)]
pub struct Publisher<const E: usize = 3> {
    prefixes: [Option<PrefixEntry>; E],
    service: Option<ServiceEntry>,
    local_changed: bool,
}

impl<const E: usize> Default for Publisher<E> {
    fn default() -> Self {
        Self::new()
    }
}

fn random_delay<R: Rng + ?Sized>(rng: &mut R, max: Duration) -> Duration {
    let max_ms = max.as_millis().max(2) as u32;
    Duration::from_millis(u64::from(1 + rng.next_u32() % (max_ms - 1)))
}

/// OT `Entry::IsPreferred`: is an entry of `other` preferred over one of
/// ours? Routers beat end devices, then the smaller RLOC16 wins.
fn other_is_preferred(ctx: &PublishContext<'_>, other: u16) -> bool {
    let other_router = Rloc16(other).is_router();
    if ctx.router_or_leader == other_router {
        other < ctx.rloc16.0
    } else {
        other_router
    }
}

impl<const E: usize> Publisher<E> {
    /// Nothing published.
    pub const fn new() -> Self {
        Self {
            prefixes: [None; E],
            service: None,
            local_changed: false,
        }
    }

    /// `true` once after the local Network Data was changed.
    pub fn take_local_changed(&mut self) -> bool {
        core::mem::take(&mut self.local_changed)
    }

    // ---------------------------------------------------------- prefixes

    /// Publish an on-mesh prefix (OT `PublishOnMeshPrefix`);
    /// [`Error::InvalidArgs`] unless stable, [`Error::NoBufs`] if all
    /// entries are in use.
    pub fn publish_on_mesh_prefix<const P: usize, const R: usize, const S: usize>(
        &mut self,
        cfg: OnMeshPrefixConfig,
        local: &mut LocalData<P, R, S>,
        now: Instant,
        ev: &mut dyn FnMut(PublisherEvent),
    ) -> Result<()> {
        if !cfg.stable {
            return Err(Error::InvalidArgs);
        }
        self.publish_item(cfg.prefix, Item::OnMesh(cfg), local, now, ev)
    }

    /// Replace the published entry for `old` with the external route `cfg`
    /// (OT `ReplacePublishedExternalRoute`); a new entry if `old` is not
    /// published.
    pub fn replace_external_route<const P: usize, const R: usize, const S: usize>(
        &mut self,
        old: NetPrefix,
        cfg: ExternalRouteConfig,
        local: &mut LocalData<P, R, S>,
        now: Instant,
        ev: &mut dyn FnMut(PublisherEvent),
    ) -> Result<()> {
        if !cfg.stable {
            return Err(Error::InvalidArgs);
        }
        self.publish_item(old, Item::Route(cfg), local, now, ev)
    }

    /// Publish an external route (OT `PublishExternalRoute`).
    pub fn publish_external_route<const P: usize, const R: usize, const S: usize>(
        &mut self,
        cfg: ExternalRouteConfig,
        local: &mut LocalData<P, R, S>,
        now: Instant,
        ev: &mut dyn FnMut(PublisherEvent),
    ) -> Result<()> {
        if !cfg.stable {
            return Err(Error::InvalidArgs);
        }
        self.publish_item(cfg.prefix, Item::Route(cfg), local, now, ev)
    }

    /// Publish `item` in the entry that holds `prefix` (or a free one); the
    /// item's own prefix differs from `prefix` when an entry is replaced.
    fn publish_item<const P: usize, const R: usize, const S: usize>(
        &mut self,
        prefix: NetPrefix,
        item: Item,
        local: &mut LocalData<P, R, S>,
        now: Instant,
        ev: &mut dyn FnMut(PublisherEvent),
    ) -> Result<()> {
        let i = self
            .prefixes
            .iter()
            .position(|e| e.is_some_and(|e| e.item.prefix() == prefix))
            .or_else(|| self.prefixes.iter().position(Option::is_none))
            .ok_or(Error::NoBufs)?;
        match self.prefixes[i] {
            None => {
                self.prefixes[i] = Some(PrefixEntry {
                    item,
                    state: EntryState::ToAdd,
                    update: now,
                });
            }
            Some(old) if old.item == item => {}
            Some(old) => {
                // Changed type / flags: replace in the local data at once
                // if it was added.
                self.remove_prefix_item(&old, local, ev);
                let was_in = matches!(old.state, EntryState::Added | EntryState::Removing);
                let mut e = PrefixEntry {
                    item,
                    state: EntryState::ToAdd,
                    update: now,
                };
                if was_in
                    && old.item.same_kind(&item)
                    && Self::add_prefix_item(&item, local).is_ok()
                {
                    e.state = EntryState::Added;
                    self.local_changed = true;
                    ev(PublisherEvent::PrefixAdded(prefix));
                }
                self.prefixes[i] = Some(e);
            }
        }
        Ok(())
    }

    /// Stop publishing `prefix` and remove it from the local data (OT
    /// `UnpublishPrefix`); [`Error::NotFound`] if it was not published.
    pub fn unpublish_prefix<const P: usize, const R: usize, const S: usize>(
        &mut self,
        prefix: &NetPrefix,
        local: &mut LocalData<P, R, S>,
        ev: &mut dyn FnMut(PublisherEvent),
    ) -> Result<()> {
        let i = self
            .prefixes
            .iter()
            .position(|e| e.is_some_and(|e| e.item.prefix() == *prefix))
            .ok_or(Error::NotFound)?;
        if let Some(e) = self.prefixes[i].take() {
            self.remove_prefix_item(&e, local, ev);
        }
        Ok(())
    }

    /// The prefix is published and in the local data (OT `IsPrefixAdded`).
    pub fn is_prefix_added(&self, prefix: &NetPrefix) -> bool {
        self.prefix_state(prefix) == Some(EntryState::Added)
    }

    /// State of a published prefix.
    pub fn prefix_state(&self, prefix: &NetPrefix) -> Option<EntryState> {
        self.prefixes
            .iter()
            .flatten()
            .find(|e| e.item.prefix() == *prefix)
            .map(|e| e.state)
    }

    fn add_prefix_item<const P: usize, const R: usize, const S: usize>(
        item: &Item,
        local: &mut LocalData<P, R, S>,
    ) -> Result<()> {
        match item {
            Item::OnMesh(c) => local.add_on_mesh_prefix(*c),
            Item::Route(c) => local.add_external_route(*c),
        }
    }

    fn remove_from_local<const P: usize, const R: usize, const S: usize>(
        item: &Item,
        local: &mut LocalData<P, R, S>,
    ) {
        let p = item.prefix();
        let _ = match item {
            Item::OnMesh(_) => local.remove_on_mesh_prefix(&p),
            Item::Route(_) => local.remove_external_route(&p),
        };
    }

    /// Remove from the local data if it was in; reports the event.
    fn remove_prefix_item<const P: usize, const R: usize, const S: usize>(
        &mut self,
        e: &PrefixEntry,
        local: &mut LocalData<P, R, S>,
        ev: &mut dyn FnMut(PublisherEvent),
    ) {
        if matches!(e.state, EntryState::Added | EntryState::Removing) {
            Self::remove_from_local(&e.item, local);
            self.local_changed = true;
            ev(PublisherEvent::PrefixRemoved(e.item.prefix()));
        }
    }

    /// Matching entries in the leader's data: (total, preferred).
    fn count_prefix(item: &Item, ctx: &PublishContext<'_>) -> (u8, u8) {
        let (mut n, mut pref) = (0u8, 0u8);
        match item {
            Item::OnMesh(c) => {
                for e in ctx.leader.on_mesh_prefixes() {
                    // Matching flags and the same or a higher preference;
                    // lower preference entries are not counted.
                    if e.prefix == c.prefix
                        && e.stable
                        && e.flags.without_preference() == c.flags.without_preference()
                        && e.flags.preference() >= c.flags.preference()
                    {
                        n = n.saturating_add(1);
                        if e.flags.preference() > c.flags.preference()
                            || other_is_preferred(ctx, e.rloc16)
                        {
                            pref = pref.saturating_add(1);
                        }
                    }
                }
            }
            Item::Route(c) => {
                for e in ctx.leader.external_routes() {
                    if e.prefix == c.prefix
                        && e.stable
                        && e.nat64 == c.nat64
                        && e.adv_pio == c.adv_pio
                        && e.preference >= c.preference
                    {
                        n = n.saturating_add(1);
                        if e.preference > c.preference || other_is_preferred(ctx, e.rloc16) {
                            pref = pref.saturating_add(1);
                        }
                    }
                }
            }
        }
        (n, pref)
    }

    // ---------------------------------------------------------- DNS/SRP

    /// Publish the DNS/SRP service (OT `PublishDnsSrpService*`); an
    /// existing different service entry is removed first.
    pub fn publish_dns_srp<const P: usize, const R: usize, const S: usize>(
        &mut self,
        service: DnsSrpService,
        ctx: &PublishContext<'_>,
        local: &mut LocalData<P, R, S>,
        now: Instant,
        ev: &mut dyn FnMut(PublisherEvent),
    ) {
        if let Some(old) = self.service {
            if old.state != EntryState::NoEntry && old.info == service {
                return;
            }
            self.remove_service(local, ev);
        }
        self.service = Some(ServiceEntry {
            info: service,
            ml_eid: ctx.ml_eid,
            state: EntryState::ToAdd,
            update: now,
        });
    }

    /// Stop publishing the DNS/SRP service (OT `UnpublishDnsSrpService`).
    pub fn unpublish_dns_srp<const P: usize, const R: usize, const S: usize>(
        &mut self,
        local: &mut LocalData<P, R, S>,
        ev: &mut dyn FnMut(PublisherEvent),
    ) {
        self.remove_service(local, ev);
        self.service = None;
    }

    /// State of the DNS/SRP entry.
    pub fn dns_srp_state(&self) -> EntryState {
        self.service.map_or(EntryState::NoEntry, |s| s.state)
    }

    /// The mesh-local EID changed: re-add an added unicast-ML-EID entry
    /// with the new address at once.
    pub fn mesh_local_eid_changed<const P: usize, const R: usize, const S: usize>(
        &mut self,
        ml_eid: Ipv6Addr,
        local: &mut LocalData<P, R, S>,
        ev: &mut dyn FnMut(PublisherEvent),
    ) {
        let Some(s) = self.service else { return };
        if !matches!(s.info, DnsSrpService::UnicastMlEid { .. }) {
            return;
        }
        let added = s.state == EntryState::Added;
        if added {
            self.remove_service(local, ev);
        }
        if let Some(s) = self.service.as_mut() {
            s.ml_eid = ml_eid;
            if added {
                s.state = EntryState::Added;
            }
        }
        if added {
            self.add_service(local, ev);
        }
    }

    /// Service data and server data of an entry.
    fn service_bytes(s: &ServiceEntry) -> ([u8; 24], usize, [u8; 24], usize) {
        fn addr_data(buf: &mut [u8], a: &Ipv6Addr, port: u16, version: u8) -> usize {
            buf[..16].copy_from_slice(&a.octets());
            buf[16..18].copy_from_slice(&port.to_be_bytes());
            if version == 0 {
                18
            } else {
                buf[18] = version;
                19
            }
        }
        let mut sd = [0u8; 24];
        let mut sv = [0u8; 24];
        let (sdl, svl);
        match s.info {
            DnsSrpService::Anycast {
                sequence_number,
                version,
            } => {
                sd[0] = SERVICE_NUMBER_ANYCAST;
                sd[1] = sequence_number;
                sdl = 2;
                svl = usize::from(version != 0);
                sv[0] = version;
            }
            DnsSrpService::Unicast {
                address,
                port,
                version,
            } => {
                sd[0] = SERVICE_NUMBER_UNICAST;
                sdl = 1 + addr_data(&mut sd[1..], &address, port, version);
                svl = 0;
            }
            DnsSrpService::UnicastMlEid { port, version } => {
                sd[0] = SERVICE_NUMBER_UNICAST;
                sdl = 1;
                svl = addr_data(&mut sv, &s.ml_eid, port, version);
            }
        }
        (sd, sdl, sv, svl)
    }

    fn add_service<const P: usize, const R: usize, const S: usize>(
        &mut self,
        local: &mut LocalData<P, R, S>,
        ev: &mut dyn FnMut(PublisherEvent),
    ) {
        let Some(s) = self.service.as_mut() else {
            return;
        };
        let (sd, sdl, sv, svl) = Self::service_bytes(s);
        let Ok(cfg) = ServiceConfig::new(THREAD_ENTERPRISE_NUMBER, &sd[..sdl], &sv[..svl], true)
        else {
            return;
        };
        if local.add_service(cfg).is_ok() {
            s.state = EntryState::Added;
            self.local_changed = true;
            ev(PublisherEvent::DnsSrpAdded);
        }
    }

    /// Remove the entry from the local data (if added) and set `NoEntry`;
    /// the caller sets another state afterwards if needed.
    fn remove_service<const P: usize, const R: usize, const S: usize>(
        &mut self,
        local: &mut LocalData<P, R, S>,
        ev: &mut dyn FnMut(PublisherEvent),
    ) {
        let Some(s) = self.service.as_mut() else {
            return;
        };
        if matches!(s.state, EntryState::Added | EntryState::Removing) {
            let (sd, sdl, _, _) = Self::service_bytes(s);
            let _ = local.remove_service(THREAD_ENTERPRISE_NUMBER, &sd[..sdl]);
            self.local_changed = true;
            ev(PublisherEvent::DnsSrpRemoved);
        }
        s.state = EntryState::NoEntry;
    }

    /// (matching entries, preferred, desired) for the DNS/SRP entry.
    fn count_service(s: &ServiceEntry, ctx: &PublishContext<'_>) -> (u8, u8, u8) {
        let mut n = 0u8;
        let mut pref = 0u8;
        let any_anycast = ctx.leader.services().any(|e| dns_srp_anycast(&e).is_some());
        let any_sd_unicast = ctx
            .leader
            .services()
            .any(|e| dns_srp_unicast(&e, true).is_some());
        let version = match s.info {
            DnsSrpService::Anycast { version, .. }
            | DnsSrpService::Unicast { version, .. }
            | DnsSrpService::UnicastMlEid { version, .. } => version,
        };
        for e in ctx.leader.services() {
            let found = match s.info {
                DnsSrpService::Anycast {
                    sequence_number, ..
                } => dns_srp_anycast(&e)
                    .filter(|&(seq, _)| seq == sequence_number)
                    .map(|(_, v)| v),
                DnsSrpService::Unicast { .. } => dns_srp_unicast(&e, true),
                DnsSrpService::UnicastMlEid { .. } => dns_srp_unicast(&e, false),
            };
            if let Some(v) = found
                && v >= version
            {
                n = n.saturating_add(1);
                if v > version || other_is_preferred(ctx, e.rloc16) {
                    pref = pref.saturating_add(1);
                }
            }
        }
        let desired = match s.info {
            DnsSrpService::Anycast { .. } => DESIRED_NUM_ANYCAST,
            DnsSrpService::Unicast { .. } => DESIRED_NUM_UNICAST,
            // Any other kind of entry makes the ML-EID entry superfluous.
            DnsSrpService::UnicastMlEid { .. } if any_sd_unicast || any_anycast => 0,
            DnsSrpService::UnicastMlEid { .. } => DESIRED_NUM_UNICAST,
        };
        (n, pref, desired)
    }

    // ---------------------------------------------------------- time

    /// Deadline of the next random delay that expires.
    pub fn next_deadline(&self) -> Option<Instant> {
        let p = self
            .prefixes
            .iter()
            .flatten()
            .filter(|e| matches!(e.state, EntryState::Adding | EntryState::Removing))
            .map(|e| e.update);
        let s = self
            .service
            .filter(|s| matches!(s.state, EntryState::Adding | EntryState::Removing))
            .map(|s| s.update);
        p.chain(s).min()
    }

    /// Re-evaluate every entry against the current Network Data (OT
    /// `HandleNotifierEvents`) and add / remove the entries whose delay is
    /// over (OT `HandleTimer`). Does nothing while detached.
    pub fn poll<const P: usize, const R: usize, const S: usize, G: Rng + ?Sized>(
        &mut self,
        now: Instant,
        ctx: &PublishContext<'_>,
        local: &mut LocalData<P, R, S>,
        rng: &mut G,
        ev: &mut dyn FnMut(PublisherEvent),
    ) {
        if !ctx.attached {
            return;
        }
        for i in 0..E {
            let Some(mut e) = self.prefixes[i] else {
                continue;
            };
            let (n, pref) = Self::count_prefix(&e.item, ctx);
            let desired = match e.item {
                Item::OnMesh(_) => DESIRED_NUM_ON_MESH_PREFIX,
                Item::Route(_) => DESIRED_NUM_EXTERNAL_ROUTE,
            };
            (e.state, e.update) = Self::update_state(e.state, e.update, now, n, pref, desired, rng);
            if matches!(e.state, EntryState::Adding | EntryState::Removing) && e.update <= now {
                if e.state == EntryState::Adding {
                    if Self::add_prefix_item(&e.item, local).is_ok() {
                        e.state = EntryState::Added;
                        self.local_changed = true;
                        ev(PublisherEvent::PrefixAdded(e.item.prefix()));
                    }
                } else {
                    Self::remove_from_local(&e.item, local);
                    e.state = EntryState::ToAdd;
                    self.local_changed = true;
                    ev(PublisherEvent::PrefixRemoved(e.item.prefix()));
                }
            }
            self.prefixes[i] = Some(e);
        }
        if let Some(mut s) = self.service
            && s.state != EntryState::NoEntry
        {
            let (n, pref, desired) = Self::count_service(&s, ctx);
            (s.state, s.update) = Self::update_state(s.state, s.update, now, n, pref, desired, rng);
            self.service = Some(s);
            if matches!(s.state, EntryState::Adding | EntryState::Removing) && s.update <= now {
                if s.state == EntryState::Adding {
                    if let Some(x) = self.service.as_mut() {
                        x.ml_eid = ctx.ml_eid;
                    }
                    self.add_service(local, ev);
                } else {
                    self.remove_service(local, ev);
                    if let Some(x) = self.service.as_mut() {
                        x.state = EntryState::ToAdd;
                    }
                }
            }
        }
    }

    /// OT `Entry::UpdateState`.
    fn update_state<G: Rng + ?Sized>(
        state: EntryState,
        update: Instant,
        now: Instant,
        num: u8,
        preferred: u8,
        desired: u8,
        rng: &mut G,
    ) -> (EntryState, Instant) {
        match state {
            EntryState::ToAdd if num < desired => (
                EntryState::Adding,
                now.saturating_add(random_delay(rng, MAX_DELAY_TO_ADD)),
            ),
            EntryState::Adding if num >= desired => (EntryState::ToAdd, update),
            EntryState::Added if num > desired => {
                let mut d = random_delay(rng, MAX_DELAY_TO_REMOVE);
                if preferred < desired {
                    d += EXTRA_DELAY_TO_REMOVE_PREFERRED;
                }
                (EntryState::Removing, now.saturating_add(d))
            }
            EntryState::Removing if num <= desired => (EntryState::Added, update),
            s => (s, update),
        }
    }
}

/// `(sequence number, version)` of a DNS/SRP anycast service entry.
fn dns_srp_anycast(e: &ViewService<'_>) -> Option<(u8, u8)> {
    (e.enterprise_number == THREAD_ENTERPRISE_NUMBER
        && e.service_data.len() >= 2
        && e.service_data[0] == SERVICE_NUMBER_ANYCAST)
        .then(|| {
            (
                e.service_data[1],
                e.server_data.first().copied().unwrap_or(0),
            )
        })
}

/// Version of a DNS/SRP unicast entry with the address in the service data
/// (`in_service_data`) or in the server data.
fn dns_srp_unicast(e: &ViewService<'_>, in_service_data: bool) -> Option<u8> {
    if e.enterprise_number != THREAD_ENTERPRISE_NUMBER
        || e.service_data.first() != Some(&SERVICE_NUMBER_UNICAST)
    {
        return None;
    }
    let data = if in_service_data {
        &e.service_data[1..]
    } else {
        e.server_data
    };
    (data.len() >= 18).then(|| data.get(18).copied().unwrap_or(0))
}
