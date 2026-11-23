//! The Backbone Router view of Network Data, client side (OT
//! `BackboneRouter::Leader` and `NetworkData::Service::Manager::GetBackboneRouterPrimary`,
//! Thread 1.4.1 section 5.21).
//!
//! The Primary Backbone Router (PBBR) is announced as a Thread Network Data
//! service with service number 1 (service data `[0x01]`); the Server TLV of
//! each Backbone Router carries the BBR Dataset: sequence number,
//! reregistration delay and MLR timeout. A device uses the PBBR for Domain
//! Unicast Address and Multicast Listener registration. The Domain Prefix is
//! the on-mesh prefix with the DP flag.
//!
//! [`BackboneRouterLeader`] is fed the Network Data after every change with
//! [`BackboneRouterLeader::update`] and reports what changed as
//! [`BbrState`] and [`DomainPrefixEvent`], as OT does through
//! `HandleBackboneRouterPrimaryUpdate` / `HandleDomainPrefixUpdate`. Only the
//! client side is implemented; there is no Backbone Router server role.

use core::net::Ipv6Addr;

use super::tlv::{BrFlags, NetPrefix, THREAD_ENTERPRISE_NUMBER};
use super::view::NetworkDataView;

/// Service number of the Backbone Router service
/// (`kBackboneRouterServiceNumber`); the service data is this single byte.
pub const BACKBONE_ROUTER_SERVICE_NUMBER: u8 = 0x01;
/// Size of the BBR Dataset in the Server TLV: sequence number (1),
/// reregistration delay (2), MLR timeout (4).
pub const BBR_SERVER_DATA_LEN: usize = 7;
/// Default reregistration delay, seconds (`kDefaultRegistrationDelay`).
pub const DEFAULT_REGISTRATION_DELAY: u16 = 5;
/// Default MLR timeout, seconds (`kDefaultMlrTimeout`).
pub const DEFAULT_MLR_TIMEOUT: u32 = 3600;
/// Smallest MLR timeout a client uses, seconds (`kMinMlrTimeout`).
pub const MIN_MLR_TIMEOUT: u32 = 300;
/// Largest MLR timeout a client uses, seconds (`kMaxMlrTimeout`).
pub const MAX_MLR_TIMEOUT: u32 = 0x7fff_ffff / 1000;
/// Window of the random delay before a parent registers its children's
/// addresses, seconds (`kParentAggregateDelay`).
pub const PARENT_AGGREGATE_DELAY: u8 = 5;

/// The BBR Dataset of a Backbone Router (OT `BackboneRouter::Config`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct BbrConfig {
    /// RLOC16 of the Backbone Router.
    pub server16: u16,
    /// BBR sequence number.
    pub sequence_number: u8,
    /// Reregistration delay, seconds.
    pub reregistration_delay: u16,
    /// MLR timeout, seconds.
    pub mlr_timeout: u32,
}

impl BbrConfig {
    /// Encode the BBR Dataset as Server TLV data.
    pub fn server_data(&self) -> [u8; BBR_SERVER_DATA_LEN] {
        let mut d = [0u8; BBR_SERVER_DATA_LEN];
        d[0] = self.sequence_number;
        d[1..3].copy_from_slice(&self.reregistration_delay.to_be_bytes());
        d[3..7].copy_from_slice(&self.mlr_timeout.to_be_bytes());
        d
    }

    /// Decode Server TLV data (extra bytes are ignored, as in OT);
    /// `None` if it is shorter than [`BBR_SERVER_DATA_LEN`].
    pub fn from_server_data(server16: u16, d: &[u8]) -> Option<Self> {
        let d = d.get(..BBR_SERVER_DATA_LEN)?;
        Some(Self {
            server16,
            sequence_number: d[0],
            reregistration_delay: u16::from_be_bytes([d[1], d[2]]),
            mlr_timeout: u32::from_be_bytes([d[3], d[4], d[5], d[6]]),
        })
    }
}

/// What a Network Data update did to the Primary Backbone Router
/// (OT `BackboneRouter::Leader::State`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum BbrState {
    /// There was and is no Primary Backbone Router.
    None,
    /// A Primary Backbone Router appeared.
    Added,
    /// The Primary Backbone Router is gone.
    Removed,
    /// Its RLOC16 or sequence number changed: reregister everything.
    ToTriggerRereg,
    /// The reregistration delay or MLR timeout changed.
    Refreshed,
    /// Nothing changed.
    Unchanged,
}

/// What a Network Data update did to the Domain Prefix
/// (OT `BackboneRouter::DomainPrefixEvent`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum DomainPrefixEvent {
    /// There was and is no Domain Prefix.
    None,
    /// A Domain Prefix appeared.
    Added,
    /// The Domain Prefix is gone.
    Removed,
    /// The Domain Prefix changed.
    Refreshed,
    /// Nothing changed.
    Unchanged,
}

fn is_bbr_service(enterprise_number: u32, service_data: &[u8]) -> bool {
    enterprise_number == THREAD_ENTERPRISE_NUMBER
        && service_data.starts_with(&[BACKBONE_ROUTER_SERVICE_NUMBER])
}

/// The Primary Backbone Router in `view` (OT `GetBackboneRouterPrimary`):
/// the one on the leader wins, then the highest sequence number, then the
/// highest RLOC16. The MLR timeout is returned as announced (not clamped).
pub fn primary_backbone_router(
    view: &NetworkDataView<'_>,
    leader_rloc16: u16,
) -> Option<BbrConfig> {
    let mut best: Option<BbrConfig> = None;
    for s in view.services() {
        if !is_bbr_service(s.enterprise_number, s.service_data) {
            continue;
        }
        let Some(c) = BbrConfig::from_server_data(s.rloc16, s.server_data) else {
            continue;
        };
        let better = match &best {
            None => true,
            Some(b) => {
                if c.server16 == leader_rloc16 {
                    true
                } else if b.server16 == leader_rloc16 {
                    false
                } else {
                    c.sequence_number > b.sequence_number
                        || (c.sequence_number == b.sequence_number && c.server16 > b.server16)
                }
            }
        };
        if better {
            best = Some(c);
        }
    }
    best
}

/// The first on-mesh prefix with the DP flag (OT `UpdateDomainPrefixConfig`).
pub fn domain_prefix(view: &NetworkDataView<'_>) -> Option<NetPrefix> {
    view.on_mesh_prefixes()
        .find(|e| e.flags.has(BrFlags::DP))
        .map(|e| e.prefix)
}

/// The service ID of the Backbone Router service (the service ALOC is the
/// anycast address of the Primary Backbone Router), if announced.
pub fn backbone_router_service_id(view: &NetworkDataView<'_>) -> Option<u8> {
    view.services()
        .find(|s| is_bbr_service(s.enterprise_number, s.service_data))
        .map(|s| s.service_id)
}

/// The client's view of the Backbone Router state in Network Data (OT
/// `BackboneRouter::Leader`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BackboneRouterLeader {
    config: Option<BbrConfig>,
    domain_prefix: Option<NetPrefix>,
}

impl BackboneRouterLeader {
    /// No Primary Backbone Router, no Domain Prefix.
    pub const fn new() -> Self {
        Self {
            config: None,
            domain_prefix: None,
        }
    }

    /// Forget everything (OT `Leader::Reset`).
    pub fn reset(&mut self) {
        *self = Self::new();
    }

    /// The Primary Backbone Router's dataset, MLR timeout clamped to
    /// [`MIN_MLR_TIMEOUT`]..=[`MAX_MLR_TIMEOUT`] (OT `GetConfig`).
    pub const fn config(&self) -> Option<&BbrConfig> {
        self.config.as_ref()
    }

    /// `true` if there is a Primary Backbone Router.
    pub const fn has_primary(&self) -> bool {
        self.config.is_some()
    }

    /// The Domain Prefix.
    pub const fn domain_prefix(&self) -> Option<&NetPrefix> {
        self.domain_prefix.as_ref()
    }

    /// `true` if there is a Domain Prefix.
    pub const fn has_domain_prefix(&self) -> bool {
        self.domain_prefix.is_some()
    }

    /// `true` if `addr` is in the Domain Prefix (OT `IsDomainUnicast`).
    pub fn is_domain_unicast(&self, addr: &Ipv6Addr) -> bool {
        self.domain_prefix.is_some_and(|p| p.contains(addr))
    }

    /// Take over the Network Data after a change (OT
    /// `HandleNotifierEvents` on `kEventThreadNetdataChanged`). Returns what
    /// happened to the Primary Backbone Router and the Domain Prefix.
    pub fn update(
        &mut self,
        view: &NetworkDataView<'_>,
        leader_rloc16: u16,
    ) -> (BbrState, DomainPrefixEvent) {
        (
            self.update_primary(view, leader_rloc16),
            self.update_domain_prefix(view),
        )
    }

    /// The Primary Backbone Router part of [`update`](Self::update).
    pub fn update_primary(&mut self, view: &NetworkDataView<'_>, leader_rloc16: u16) -> BbrState {
        let new = primary_backbone_router(view, leader_rloc16);
        // As in OT the announced (unclamped) timeout is compared with the
        // stored, clamped one.
        let state = match (&self.config, &new) {
            (None, None) => BbrState::None,
            (None, Some(_)) => BbrState::Added,
            (Some(_), None) => BbrState::Removed,
            (Some(o), Some(n))
                if o.server16 != n.server16 || o.sequence_number != n.sequence_number =>
            {
                BbrState::ToTriggerRereg
            }
            (Some(o), Some(n))
                if o.reregistration_delay != n.reregistration_delay
                    || o.mlr_timeout != n.mlr_timeout =>
            {
                BbrState::Refreshed
            }
            _ => BbrState::Unchanged,
        };
        self.config = new.map(|mut c| {
            c.mlr_timeout = c.mlr_timeout.clamp(MIN_MLR_TIMEOUT, MAX_MLR_TIMEOUT);
            c
        });
        state
    }

    /// The Domain Prefix part of [`update`](Self::update).
    pub fn update_domain_prefix(&mut self, view: &NetworkDataView<'_>) -> DomainPrefixEvent {
        let new = domain_prefix(view);
        let ev = match (&self.domain_prefix, &new) {
            (None, None) => DomainPrefixEvent::None,
            (Some(_), None) => DomainPrefixEvent::Removed,
            (None, Some(_)) => DomainPrefixEvent::Added,
            (Some(o), Some(n)) if o == n => DomainPrefixEvent::Unchanged,
            (Some(_), Some(_)) => DomainPrefixEvent::Refreshed,
        };
        self.domain_prefix = new;
        ev
    }
}
