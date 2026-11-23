//! Questions routing asks of Network Data (OT `NetworkData::Leader`
//! `RouteLookup`, `ExternalRouteLookup`, `DefaultRouteLookup`,
//! `AnycastLookup`, `IsOnMesh`) and the adapters that turn them into the
//! traits of the layers below.

use core::cmp::Ordering;
use core::net::Ipv6Addr;

use rs_thread_core::{Error, Result};

use super::tlv::{BrFlags, ContextTlv, NetPrefix, PrefixTlv, ty};
use super::view::{NetworkDataView, SERVICE_ALOC_BASE};

/// ALOC16 of the leader.
pub const ALOC16_LEADER: u16 = 0xfc00;
/// First ALOC16 of the DHCPv6 agents (context ID 1).
pub const ALOC16_DHCP_AGENT_START: u16 = 0xfc01;
/// Last ALOC16 of the DHCPv6 agents.
pub const ALOC16_DHCP_AGENT_END: u16 = 0xfc0f;
/// Last service ALOC16.
pub const ALOC16_SERVICE_END: u16 = 0xfc1f;
/// First commissioner ALOC16.
pub const ALOC16_COMMISSIONER_START: u16 = 0xfc30;
/// Last commissioner ALOC16.
pub const ALOC16_COMMISSIONER_END: u16 = 0xfc37;
/// ALOC16 of the primary Backbone Router.
pub const ALOC16_BACKBONE_ROUTER_PRIMARY: u16 = 0xfc38;
/// First ALOC16 of the Neighbor Discovery agents (context ID 1).
pub const ALOC16_ND_AGENT_START: u16 = 0xfc40;
/// Last ALOC16 of the Neighbor Discovery agents.
pub const ALOC16_ND_AGENT_END: u16 = 0xfc4e;

/// MeshCoP Border Agent Locator TLV type in the Commissioning Data.
const MESHCOP_BORDER_AGENT_LOCATOR: u8 = 9;

/// What route selection needs to know about the mesh.
pub trait MeshInfo {
    /// Path cost to a router or child RLOC16 (16 if unreachable).
    fn path_cost(&self, rloc16: u16) -> u8;
    /// RLOC16 of the leader.
    fn leader_rloc16(&self) -> u16;
    /// `true` if `rloc16` is this device's RLOC16.
    fn has_rloc16(&self, rloc16: u16) -> bool;
    /// Full thread device: costs break ties (an MTD prefers itself as
    /// border router instead).
    fn is_ftd(&self) -> bool {
        true
    }
}

impl<const C: usize> MeshInfo for rs_thread_mle::Mle<C> {
    fn path_cost(&self, rloc16: u16) -> u8 {
        rs_thread_mle::Mle::path_cost(self, rs_thread_core::types::Rloc16(rloc16))
    }
    fn leader_rloc16(&self) -> u16 {
        rs_thread_mle::Mle::leader_rloc16(self).0
    }
    fn has_rloc16(&self, rloc16: u16) -> bool {
        self.rloc16().0 == rloc16
    }
    fn is_ftd(&self) -> bool {
        self.is_full_thread_device()
    }
}

const fn is_router_rloc16(r: u16) -> bool {
    r & 0x1ff == 0
}

/// OT `CompareRouteEntries`: `Greater` if the first entry is preferred.
fn compare<M: MeshInfo + ?Sized>(mesh: &M, p1: i8, r1: u16, p2: i8, r2: u16) -> Ordering {
    let o = p1.cmp(&p2);
    if o != Ordering::Equal {
        return o;
    }
    if !mesh.is_ftd() {
        return mesh.has_rloc16(r1).cmp(&mesh.has_rloc16(r2));
    }
    let o = mesh.path_cost(r2).cmp(&mesh.path_cost(r1));
    if o != Ordering::Equal {
        return o;
    }
    is_router_rloc16(r1).cmp(&is_router_rloc16(r2))
}

fn prefix_contains_addr(p: &PrefixTlv<'_>, a: &Ipv6Addr) -> bool {
    p.prefix.contains(a)
}

fn external_route_lookup<M: MeshInfo + ?Sized>(
    view: &NetworkDataView<'_>,
    mesh: &M,
    domain_id: u8,
    dst: &Ipv6Addr,
) -> Option<u16> {
    let mut best: Option<(u16, i8, u8)> = None;
    for p in view.prefixes() {
        if !prefix_contains_addr(&p, dst) || p.domain_id != domain_id {
            continue;
        }
        let len = p.prefix.len();
        if best.is_some_and(|(_, _, bl)| len <= bl) {
            continue;
        }
        for s in p.sub_tlvs().filter(|s| s.ty == ty::HAS_ROUTE) {
            for e in s
                .value
                .chunks_exact(3)
                .filter_map(super::tlv::HasRouteEntry::parse)
            {
                let better = match best {
                    None => true,
                    Some((br, bp, bl)) => {
                        len > bl
                            || compare(mesh, e.preference, e.rloc16, bp, br) == Ordering::Greater
                    }
                };
                if better {
                    best = Some((e.rloc16, e.preference, len));
                }
            }
        }
    }
    best.map(|(r, _, _)| r)
}

/// Best Border Router entry of `prefix` accepted by `accept` (OT
/// `LookupRouteIn`).
fn lookup_route_in<M: MeshInfo + ?Sized>(
    mesh: &M,
    prefix: &PrefixTlv<'_>,
    accept: impl Fn(&BrFlags) -> bool,
) -> Option<u16> {
    let mut best: Option<(u16, i8)> = None;
    for s in prefix.sub_tlvs().filter(|s| s.ty == ty::BORDER_ROUTER) {
        for e in s
            .value
            .chunks_exact(4)
            .filter_map(super::tlv::BorderRouterEntry::parse)
        {
            if !accept(&e.flags) {
                continue;
            }
            let p = e.flags.preference();
            if best.is_none_or(|(br, bp)| compare(mesh, p, e.rloc16, bp, br) == Ordering::Greater) {
                best = Some((e.rloc16, p));
            }
        }
    }
    best.map(|(r, _)| r)
}

/// The RLOC16 that serves `dst` for a datagram from `src` (OT
/// `RouteLookup`): for each prefix that contains `src` and has a Border
/// Router, the best external route of its domain covering `dst`, else the
/// best default-route Border Router.
pub fn route_lookup<M: MeshInfo + ?Sized>(
    view: &NetworkDataView<'_>,
    mesh: &M,
    src: &Ipv6Addr,
    dst: &Ipv6Addr,
) -> Option<u16> {
    for p in view.prefixes() {
        if !prefix_contains_addr(&p, src) || !p.sub_tlvs().any(|s| s.ty == ty::BORDER_ROUTER) {
            continue;
        }
        if let Some(r) = external_route_lookup(view, mesh, p.domain_id, dst) {
            return Some(r);
        }
        if let Some(r) = lookup_route_in(mesh, &p, |f| f.has(BrFlags::DEFAULT_ROUTE)) {
            return Some(r);
        }
    }
    None
}

/// The prefix and context of context ID `id`.
fn prefix_for_context<'a>(view: &NetworkDataView<'a>, id: u8) -> Option<PrefixTlv<'a>> {
    view.prefixes().find(|p| {
        p.sub_tlvs()
            .find(|s| s.ty == ty::CONTEXT)
            .and_then(|s| ContextTlv::parse(&s).ok())
            .is_some_and(|c| c.id == id)
    })
}

/// The Border Agent Locator in the Commissioning Data.
pub fn border_agent_locator(view: &NetworkDataView<'_>) -> Option<u16> {
    let mut rest = view.commissioning_data()?;
    while let [t, l, tail @ ..] = rest {
        let l = usize::from(*l);
        let v = tail.get(..l)?;
        if *t == MESHCOP_BORDER_AGENT_LOCATOR && l >= 2 {
            return Some(u16::from_be_bytes([v[0], v[1]]));
        }
        rest = &tail[l..];
    }
    None
}

/// The RLOC16 an anycast locator resolves to (OT `AnycastLookup`): the
/// leader, the best DHCPv6 / ND agent Border Router of a context, the best
/// server of a service, the Border Agent of the commissioner, the Primary
/// Backbone Router. A child is
/// replaced by its parent unless that is this device. [`Error::NotFound`]
/// if there is none, [`Error::Drop`] for an unsupported locator.
pub fn anycast_lookup<M: MeshInfo + ?Sized>(
    view: &NetworkDataView<'_>,
    mesh: &M,
    aloc16: u16,
) -> Result<u16> {
    let rloc16 = match aloc16 {
        ALOC16_LEADER => mesh.leader_rloc16(),
        ALOC16_DHCP_AGENT_START..=ALOC16_DHCP_AGENT_END => {
            let p =
                prefix_for_context(view, (aloc16 - ALOC16_LEADER) as u8).ok_or(Error::NotFound)?;
            lookup_route_in(mesh, &p, |f| {
                f.has(BrFlags::DHCP) || f.has(BrFlags::CONFIGURE)
            })
            .ok_or(Error::NotFound)?
        }
        SERVICE_ALOC_BASE..=ALOC16_SERVICE_END => {
            let id = (aloc16 - SERVICE_ALOC_BASE) as u8;
            view.services()
                .filter(|s| s.service_id == id)
                .map(|s| s.rloc16)
                .reduce(|best, r| {
                    if compare(mesh, 0, r, 0, best) == Ordering::Greater {
                        r
                    } else {
                        best
                    }
                })
                .ok_or(Error::NotFound)?
        }
        ALOC16_COMMISSIONER_START..=ALOC16_COMMISSIONER_END => {
            border_agent_locator(view).ok_or(Error::NotFound)?
        }
        ALOC16_BACKBONE_ROUTER_PRIMARY => {
            super::backbone::primary_backbone_router(view, mesh.leader_rloc16())
                .ok_or(Error::Drop)?
                .server16
        }
        ALOC16_ND_AGENT_START..=ALOC16_ND_AGENT_END => {
            let p = prefix_for_context(view, (aloc16 - ALOC16_ND_AGENT_START + 1) as u8)
                .ok_or(Error::NotFound)?;
            lookup_route_in(mesh, &p, |f| f.has(BrFlags::ND_DNS)).ok_or(Error::NotFound)?
        }
        _ => return Err(Error::Drop),
    };
    if !is_router_rloc16(rloc16) {
        let parent = rloc16 & 0xfc00;
        if !mesh.has_rloc16(parent) {
            return Ok(parent);
        }
    }
    Ok(rloc16)
}

/// A [`NetworkDataView`] with the mesh state it needs, as the
/// [`NetworkData`](crate::forwarder::NetworkData) of the forwarder and the
/// [`Ip6Env`](rs_thread_net::ip6::Ip6Env) route / on-mesh providers.
#[derive(Debug, Clone, Copy)]
pub struct Lookup<'a, M: ?Sized> {
    /// The Network Data.
    pub view: NetworkDataView<'a>,
    /// Routing state.
    pub mesh: &'a M,
}

impl<'a, M: MeshInfo + ?Sized> Lookup<'a, M> {
    /// Combine Network Data and mesh state.
    pub const fn new(view: NetworkDataView<'a>, mesh: &'a M) -> Self {
        Self { view, mesh }
    }

    /// [`route_lookup`] as an RLOC16.
    pub fn route(&self, src: &Ipv6Addr, dst: &Ipv6Addr) -> Option<rs_thread_core::types::Rloc16> {
        route_lookup(&self.view, self.mesh, src, dst).map(rs_thread_core::types::Rloc16)
    }
}

impl<M: MeshInfo + ?Sized> crate::forwarder::NetworkData for Lookup<'_, M> {
    fn route_lookup(
        &self,
        src: &Ipv6Addr,
        dst: &Ipv6Addr,
    ) -> Option<rs_thread_core::types::Rloc16> {
        self.route(src, dst)
    }
    fn is_on_mesh(&self, addr: &Ipv6Addr) -> bool {
        self.view.is_on_mesh(addr)
    }
    fn anycast_lookup(&self, aloc16: u16) -> Option<rs_thread_core::types::Rloc16> {
        anycast_lookup(&self.view, self.mesh, aloc16)
            .ok()
            .map(rs_thread_core::types::Rloc16)
    }
}

/// The longest prefix among on-mesh entries containing `addr`, for tests
/// and diagnostics.
pub fn on_mesh_prefix_of(view: &NetworkDataView<'_>, addr: &Ipv6Addr) -> Option<NetPrefix> {
    view.on_mesh_prefixes()
        .filter(|e| e.flags.has(BrFlags::ON_MESH) && e.prefix.contains(addr))
        .map(|e| e.prefix)
        .max_by_key(NetPrefix::len)
}

/// [`MeshInfo`] of an end device without routing tables (OT MTD): costs
/// are unknown, a Border Router that is the device itself wins ties.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EndDeviceMesh {
    /// This device's RLOC16.
    pub rloc16: u16,
    /// RLOC16 of the leader.
    pub leader_rloc16: u16,
}

impl MeshInfo for EndDeviceMesh {
    fn path_cost(&self, _rloc16: u16) -> u8 {
        16
    }
    fn leader_rloc16(&self) -> u16 {
        self.leader_rloc16
    }
    fn has_rloc16(&self, rloc16: u16) -> bool {
        self.rloc16 == rloc16
    }
    fn is_ftd(&self) -> bool {
        false
    }
}

/// [`Ip6Env`](rs_thread_net::ip6::Ip6Env) backed by Network Data and the
/// MLE core: role, external route lookup, on-mesh check.
#[derive(Debug, Clone, Copy)]
pub struct NetDataIp6Env<'a, const C: usize> {
    /// Network Data.
    pub view: NetworkDataView<'a>,
    /// MLE core.
    pub mle: &'a rs_thread_mle::Mle<C>,
}

impl<const C: usize> rs_thread_net::ip6::Ip6Env for NetDataIp6Env<'_, C> {
    fn role(&self) -> rs_thread_net::mpl::Role {
        use rs_thread_mle::Role as R;
        use rs_thread_net::mpl::Role;
        match self.mle.role() {
            R::Disabled => Role::Disabled,
            R::Detached => Role::Detached,
            R::Child => Role::Child,
            R::Router => Role::Router,
            R::Leader => Role::Leader,
        }
    }
    fn route_lookup(
        &self,
        src: &Ipv6Addr,
        dst: &Ipv6Addr,
    ) -> Option<rs_thread_core::types::Rloc16> {
        Lookup::new(self.view, self.mle).route(src, dst)
    }
    fn is_on_mesh(&self, addr: &Ipv6Addr) -> bool {
        self.view.is_on_mesh(addr)
    }
}
