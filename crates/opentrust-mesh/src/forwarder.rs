//! Mesh forwarding for routers (OT `MeshForwarder` with the FTD routing of
//! `mesh_forwarder_ftd.cpp`), sans-IO.
//!
//! The forwarder sits between the IPv6 layer and the MAC:
//!
//! ```text
//!  Ip6::handle -> forward_thread / local send
//!       -> MeshForwarder::send_datagram(IPv6 datagram)
//!            route lookup, address resolution, 6LoWPAN compression and
//!            fragmentation, mesh header for multi-hop
//!       -> FrameSink::transmit(MAC destination, frame payload)
//!
//!  MAC rx -> MeshForwarder::receive_frame(frame payload, MAC addresses)
//!       mesh header: deliver / forward to the next hop / drop
//!       fragments: reassembly; IPHC: decompression
//!       -> Rx::Datagram(IPv6 datagram) for Ip6::handle
//! ```
//!
//! # Routing (OT `UpdateIp6Route`, `UpdateIp6RouteFtd`)
//!
//! - detached: link-local multicast is broadcast, link-local unicast goes to
//!   the extended address in its IID, the rest is dropped;
//! - multicast: an end device with link security sends it to its parent,
//!   everybody else broadcasts it;
//! - link-local unicast: extended MAC address from the IID;
//! - a minimal end device sends everything else to its parent;
//! - otherwise the mesh destination is chosen: the RLOC16 of a routing
//!   locator; a Network Data lookup for an anycast locator; the RLOC16 of
//!   the child that owns the address; the address cache result for on-link
//!   (mesh-local) addresses ([`AddressResolver`], with the datagram held
//!   while a query is pending); the Network Data route lookup for the rest;
//! - the destination must be reachable (`IsReachable`), the next hop comes
//!   from [`Mle::next_hop_and_path_cost`]; a next hop other than the
//!   destination means a mesh header with `source = own RLOC16` and
//!   [`MESH_HEADER_HOPS_LEFT`] hops.
//!
//! # Forwarding mesh header frames (OT `HandleMesh`)
//!
//! Frames without link security are dropped. The EID-to-RLOC cache learns
//! the originator of on-mesh datagrams (snooping). Frames for this device
//! or for one of its minimal children are processed like unicast frames
//! (reassembled, decompressed, handed to IPv6). Other frames are forwarded
//! while hops are left: a frame that would go back to the router it came
//! from is a 2-hop routing loop ([`FrameSink::routing_loop`], drop), a
//! destination without a route triggers an ICMPv6 destination unreachable
//! ([`FrameSink::dest_unreachable`]); otherwise hops left is decremented and
//! the frame is sent to the next hop unchanged.
//!
//! # Network Data
//!
//! Anything that needs Network Data (external routes, on-mesh prefixes,
//! anycast locators) goes through the narrow [`NetworkData`] trait; the
//! default [`NoNetworkData`] knows no prefixes and no services.

use core::net::Ipv6Addr;

use opentrust_core::bufpool::{BufPool, Chain, POOL_BUF_SIZE};
use opentrust_core::time::Instant;
use opentrust_core::types::{ExtAddress, LinkSecurity, Prefix64, Rloc16};
use opentrust_core::{Error, Result};
use opentrust_lowpan::forward::{LowpanFrame, parse_frame};
use opentrust_lowpan::frag::{Fragmenter, TagCounter};
use opentrust_lowpan::ip6::Ipv6Header;
use opentrust_lowpan::iphc::{ContextProvider, decompress, decompress_datagram};
use opentrust_lowpan::mesh::{MESH_HEADER_HOPS_LEFT, MeshHeader};
use opentrust_lowpan::reassembly::{Reassembled, Reassembler, THREAD_MTU};
use opentrust_mac::frame::Address;
use opentrust_mle::neighbor::StateFilter;
use opentrust_mle::{Mle, Role};
use opentrust_net::netif::Netif;
use opentrust_net::resolver::{AddressResolver, Resolution, ResolverEnv, ResolverEvent};

use crate::indirect::{IndirectQueue, PollOutcome};
use crate::radio::RadioLink;

/// Largest MAC payload of a frame without mesh header (short addresses,
/// PAN ID compression, AES-CCM*-32 security).
pub const MAX_FRAME_PAYLOAD: usize = 106;
/// MAC overhead of the CSL IE a CSL receiver puts into its frames: the
/// Header IE (2 + 4 octets) and the Header Termination 2 IE before the payload.
pub const CSL_IE_OVERHEAD: usize = 8;
/// Largest MAC payload of a direct frame from `src` to `dst` with
/// `security` (IEEE 802.15.4-2006 frame, PAN ID compression, AES-CCM*-32).
pub(crate) fn frame_payload_limit(src: &Address, dst: MacDest, security: LinkSecurity) -> usize {
    let src_len = match src {
        Address::Extended(_) => 8,
        Address::Short(_) => 2,
        _ => 0,
    };
    let dst_len = match dst {
        MacDest::Extended(_) => 8,
        _ => 2,
    };
    // Auxiliary security header (control, frame counter, key identifier)
    // and the 4-byte MIC.
    let sec = match security {
        LinkSecurity::None => 0,
        LinkSecurity::Kek => 5 + 4,
        LinkSecurity::Network => 6 + 4,
        LinkSecurity::Mode2 => 10 + 4,
    };
    // PSDU 127 - FCS 2 - frame control 2 - sequence 1 - PAN ID 2.
    (127 - 2 - 2 - 1 - 2) - dst_len - src_len - sec
}

/// Largest MAC payload of a frame with mesh header: the minimum over all
/// possible next hops (extended addresses), as OpenThread's fixed
/// `kMeshHeaderFrameMtu` rule.
pub const MAX_MESH_FRAME_PAYLOAD: usize = 94;

/// IPv6 minimum MTU used for reassembly buffers.
pub const MTU: usize = THREAD_MTU;

/// MAC destination of a frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum MacDest {
    /// 16-bit short address.
    Short(Rloc16),
    /// Extended address (link-local unicast).
    Extended(ExtAddress),
    /// Broadcast (`0xffff`).
    Broadcast,
}

impl MacDest {
    pub(crate) fn address(self) -> Address {
        match self {
            Self::Short(r) => Address::Short(r.into()),
            Self::Extended(e) => Address::Extended(e),
            Self::Broadcast => Address::Short(opentrust_core::types::ShortAddress::BROADCAST),
        }
    }
}

/// A frame for the MAC.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TxFrame<'a> {
    /// MAC source address the payload was compressed against: the extended
    /// address for datagrams from an extended-address IID source, the own
    /// short address otherwise (and for mesh header frames).
    pub src: Address,
    /// MAC destination.
    pub dst: MacDest,
    /// MAC payload (6LoWPAN: mesh header, fragment header, IPHC, data).
    pub payload: &'a [u8],
    /// Link-layer security (key ID mode) to apply.
    pub security: LinkSecurity,
    /// Set the Frame Pending bit (more frames follow for a sleepy child).
    pub frame_pending: bool,
    /// Send as an indirect transmission (after a data poll).
    pub indirect: bool,
    /// The destination is a CSL synchronized child: the MAC sends the frame
    /// in the child's next sample window (its data poll still serves it if
    /// the windows are missed), see
    /// [`MeshForwarder::csl_flush`]. Implies `indirect`.
    pub csl: bool,
    /// The radio link to send the frame on (always the 802.15.4 radio
    /// without feature `trel`; see `RadioSelector`).
    pub radio: RadioLink,
}

/// Where the forwarder puts frames and notifications.
pub trait FrameSink {
    /// Transmit one frame. An error aborts the datagram.
    fn transmit(&mut self, frame: &TxFrame<'_>) -> Result<()>;
    /// Send an ICMPv6 destination unreachable (no route) about `invoking`
    /// (the start of the offending IPv6 datagram) to its source.
    fn dest_unreachable(&mut self, _invoking: &[u8]) {}
    /// All frames of a datagram were handed to [`transmit`](Self::transmit):
    /// `head` is the start of the datagram (at least the IPv6 header and
    /// eight bytes of the upper layer), `dst` the MAC destination of its
    /// frames (for the History Tracker).
    fn datagram_sent(&mut self, _head: &[u8], _dst: MacDest, _security: LinkSecurity) {}
    /// A frame for `dest` came from the router it would be sent to: tell
    /// the MLE layer to invalidate the route (OT `ResolveRoutingLoops`).
    fn routing_loop(&mut self, _from: Rloc16, _dest: Rloc16) {}
}

/// Network Data answers needed by routing. See the [module
/// documentation](self).
pub trait NetworkData {
    /// The RLOC16 that serves `dst` for `src` through an external route
    /// (OT `NetworkData::Leader::RouteLookup`).
    fn route_lookup(&self, _src: &Ipv6Addr, _dst: &Ipv6Addr) -> Option<Rloc16> {
        None
    }
    /// `true` if `addr` is covered by an on-mesh prefix.
    fn is_on_mesh(&self, _addr: &Ipv6Addr) -> bool {
        false
    }
    /// The RLOC16 selected for an anycast locator (OT `AnycastLookup`).
    fn anycast_lookup(&self, _aloc16: u16) -> Option<Rloc16> {
        None
    }
}

/// [`NetworkData`] without any content.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoNetworkData;
impl NetworkData for NoNetworkData {}

/// Everything the forwarder reads from the rest of the stack for one
/// call.
#[derive(Debug)]
pub struct Routing<'a, const C: usize, const U: usize, const M: usize, CP: ?Sized, ND: ?Sized> {
    /// MLE state: role, RLOC16, router table, children, parent.
    pub mle: &'a Mle<C>,
    /// Interface addresses.
    pub netif: &'a Netif<U, M>,
    /// 6LoWPAN contexts.
    pub contexts: &'a CP,
    /// Network Data.
    pub nd: &'a ND,
    /// Extended address of this device.
    pub ext: ExtAddress,
}

impl<const C: usize, const U: usize, const M: usize, CP: ?Sized, ND: ?Sized> Clone
    for Routing<'_, C, U, M, CP, ND>
{
    fn clone(&self) -> Self {
        *self
    }
}
impl<const C: usize, const U: usize, const M: usize, CP: ?Sized, ND: ?Sized> Copy
    for Routing<'_, C, U, M, CP, ND>
{
}

/// The routing answers of the MLE core as [`ResolverEnv`] for the address
/// cache.
#[derive(Debug)]
pub struct MleResolverEnv<'a, const C: usize>(pub &'a Mle<C>);

impl<const C: usize> ResolverEnv for MleResolverEnv<'_, C> {
    fn has_route_to(&self, rloc16: Rloc16) -> bool {
        self.0.next_hop_and_path_cost(rloc16).0.is_some()
    }
    fn is_ftd(&self) -> bool {
        self.0.is_full_thread_device()
    }
    fn is_own_rloc16(&self, rloc16: Rloc16) -> bool {
        self.0.rloc16() == rloc16
    }
    fn is_minimal_child(&self, rloc16: Rloc16) -> bool {
        self.0
            .children()
            .find_by_rloc(rloc16, StateFilter::Valid)
            .is_some_and(|c| !c.neighbor.mode.full_thread_device())
    }
}

/// How a datagram leaves this device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Route {
    /// Frames to `dst` without mesh header.
    Direct {
        /// MAC destination.
        dst: MacDest,
    },
    /// Frames with a mesh header to the next hop.
    Mesh {
        /// MAC destination (the next hop router).
        next_hop: Rloc16,
        /// Final destination for the mesh header.
        mesh_dest: Rloc16,
    },
    /// The destination is a sleepy child of this router: queue the
    /// datagram for its next data poll.
    Indirect {
        /// The child.
        child: Rloc16,
        /// The child's extended address if it has no RLOC16 yet (Child ID
        /// Response): the frames are exchanged between extended addresses.
        to_ext: Option<ExtAddress>,
    },
}

/// Why a datagram was not sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum DropReason {
    /// Malformed.
    Invalid,
    /// Policy (multicast source, detached, unroutable destination).
    Drop,
    /// No route to the destination.
    NoRoute,
    /// The address query failed or no resources to hold the datagram.
    AddressQuery,
    /// Out of buffers.
    NoBufs,
    /// The MAC refused a frame.
    Link,
    /// Mesh header frame without link security.
    Security,
    /// Hops left exhausted.
    HopsExhausted,
    /// 2-hop routing loop.
    RoutingLoop,
}

/// Result of [`MeshForwarder::send_datagram`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendResult {
    /// All frames were handed to the sink.
    Sent,
    /// Waiting for an Address Notification; sent by
    /// [`MeshForwarder::handle_resolved`].
    Held,
    /// For a sleepy child of this router (see [`Route::Indirect`]).
    Indirect(Rloc16),
    /// Not sent.
    Dropped(DropReason),
}

/// Result of [`MeshForwarder::receive_frame`].
#[derive(Debug, PartialEq, Eq)]
pub enum Rx<'a> {
    /// A complete IPv6 datagram for the IPv6 layer.
    Datagram(&'a [u8]),
    /// The frame was forwarded to the next hop.
    Forwarded,
    /// Consumed (a fragment was stored, an empty frame).
    Consumed,
    /// Dropped.
    Dropped(DropReason),
}

#[derive(Debug)]
struct Held {
    eid: Ipv6Addr,
    len: usize,
    security: LinkSecurity,
    buf: Chain,
}

/// The forwarder: holds datagrams for pending address queries (`HOLD` of
/// them), the reassembly table (`SLOTS` datagrams), the datagram tag
/// counter and the indirect queue for sleepy children (`QUEUE` messages).
#[derive(Debug)]
pub struct MeshForwarder<
    const HOLD: usize = 2,
    const SLOTS: usize = 2,
    const QUEUE: usize = 4,
    const HOLD_BUFS: usize = 12,
    const IPOOL: usize = 16,
> {
    /// Messages for sleepy children, released on data polls.
    pub indirect: IndirectQueue<QUEUE, IPOOL>,
    held: [Option<Held>; HOLD],
    held_pool: BufPool<HOLD_BUFS, POOL_BUF_SIZE>,
    reasm: Reassembler<SLOTS>,
    tags: TagCounter,
    rx_buf: [u8; MTU],
    sent_children: [Option<Rloc16>; SENT_CHILDREN],
    /// Multi-radio selection (feature `trel`).
    #[cfg(feature = "trel")]
    pub radios: crate::trel::RadioSelector,
}

/// Children whose "message sent" notification is buffered for
/// [`MeshForwarder::take_child_message_sent`].
const SENT_CHILDREN: usize = 4;

fn hdr_of(datagram: &[u8]) -> Option<Ipv6Header> {
    Ipv6Header::parse(datagram).ok()
}

impl<
    const HOLD: usize,
    const SLOTS: usize,
    const QUEUE: usize,
    const HOLD_BUFS: usize,
    const IPOOL: usize,
> MeshForwarder<HOLD, SLOTS, QUEUE, HOLD_BUFS, IPOOL>
{
    /// New forwarder; `tag_seed` seeds the datagram tags.
    pub fn new(tag_seed: u16) -> Self {
        Self {
            indirect: IndirectQueue::new(tag_seed.wrapping_add(0x4000)),
            held: [const { None }; HOLD],
            held_pool: BufPool::new(),
            reasm: Reassembler::new(),
            tags: TagCounter::new(tag_seed),
            rx_buf: [0; MTU],
            sent_children: [None; SENT_CHILDREN],
            #[cfg(feature = "trel")]
            radios: crate::trel::RadioSelector::new(),
        }
    }

    /// The radio link for a frame to `dst`: with feature `trel` the radio
    /// selector's choice for a unicast to a neighbor (OT
    /// `RadioSelector::Select`), otherwise (and for broadcasts, which go out
    /// on every radio the platform has) the 802.15.4 radio.
    #[cfg_attr(not(feature = "trel"), allow(clippy::unused_self))]
    fn select_radio(&self, dst: MacDest) -> RadioLink {
        #[cfg(feature = "trel")]
        if let MacDest::Short(n) = dst {
            return self.radios.select(n);
        }
        let _ = dst;
        RadioLink::Ieee802154
    }

    /// Deadline of the reassembly timeout.
    pub fn next_deadline(&self) -> Option<Instant> {
        self.reasm.next_deadline()
    }

    /// Expire reassemblies.
    pub fn poll(&mut self, now: Instant) {
        self.reasm.expire(now);
    }

    /// Drop everything in flight (role change, detach).
    pub fn clear(&mut self) {
        self.reasm.clear();
        self.indirect.clear();
        for h in &mut self.held {
            if let Some(h) = h.take() {
                self.held_pool.free(h.buf);
            }
        }
    }

    /// Number of datagrams waiting for address resolution.
    pub fn held_count(&self) -> usize {
        self.held.iter().flatten().count()
    }

    // ------------------------------------------------------------ routing

    /// `IsReachable` (OT).
    fn is_reachable<const C: usize, const U: usize, const M: usize, CP: ?Sized, ND: ?Sized>(
        r: &Routing<'_, C, U, M, CP, ND>,
        mesh_dest: Rloc16,
        dst: &Ipv6Addr,
    ) -> bool {
        let mle = r.mle;
        if mle.role() == Role::Child {
            return if mle.rloc16() == mesh_dest {
                r.netif.has_unicast(dst)
            } else {
                true
            };
        }
        if mle.rloc16() == mesh_dest {
            return r.netif.has_unicast(dst)
                || mle
                    .children()
                    .find_by_address(r.netif.mesh_local_prefix(), dst, StateFilter::Valid)
                    .is_some();
        }
        if mesh_dest.router_id() == mle.rloc16().router_id() {
            return mle
                .children()
                .find_by_rloc(mesh_dest, StateFilter::AnyExceptInvalid)
                .is_some();
        }
        mle.next_hop_and_path_cost(mesh_dest).0.is_some()
    }

    /// Choose the route of a datagram with these IPv6 addresses (OT
    /// `UpdateIp6Route`). Address resolution may start a query
    /// (`events`); then the answer is [`DropReason::AddressQuery`] with
    /// `held = true`.
    #[allow(clippy::too_many_arguments)]
    pub fn route<
        const C: usize,
        const U: usize,
        const M: usize,
        const N: usize,
        CP: ?Sized,
        ND: NetworkData + ?Sized,
    >(
        now: Instant,
        r: &Routing<'_, C, U, M, CP, ND>,
        resolver: &mut AddressResolver<N>,
        src: &Ipv6Addr,
        dst: &Ipv6Addr,
        security: impl Into<LinkSecurity>,
        events: &mut impl FnMut(ResolverEvent),
    ) -> core::result::Result<Route, RouteError> {
        let security = security.into();
        use opentrust_net::addr::{is_link_local_multicast, is_routing_locator};
        let mle = r.mle;
        let mlp: &Prefix64 = r.netif.mesh_local_prefix();
        if src.is_multicast() {
            return Err(RouteError::Drop);
        }
        let ll_unicast = dst.is_unicast_link_local();
        let ext_of_dst = || opentrust_core::types::ipv6::iid(dst).to_ext_address();
        if matches!(mle.role(), Role::Disabled | Role::Detached) {
            return if is_link_local_multicast(dst) {
                Ok(Route::Direct {
                    dst: MacDest::Broadcast,
                })
            } else if ll_unicast {
                Ok(Route::Direct {
                    dst: MacDest::Extended(ext_of_dst()),
                })
            } else {
                Err(RouteError::Drop)
            };
        }
        if dst.is_multicast() {
            let to_parent = mle.role() == Role::Child && security.is_network();
            return Ok(Route::Direct {
                dst: match (to_parent, mle.parent()) {
                    (true, Some(p)) => MacDest::Short(p.router.neighbor.rloc16),
                    _ => MacDest::Broadcast,
                },
            });
        }
        if ll_unicast {
            // A valid sleepy child is reached on its data polls (OT
            // `SendMessage`: `FindNeighbor` + `AddMessageForSleepyChild`).
            if let Some(c) = mle
                .children()
                .find_by_ext(&ext_of_dst(), StateFilter::Valid)
                && c.confirmed
                && !c.neighbor.mode.rx_on_when_idle()
            {
                // The MAC addresses follow the link-local IPv6 addresses
                // (extended), as in OT `GetMacSourceAndDestinationAddresses`.
                return Ok(Route::Indirect {
                    child: c.neighbor.rloc16,
                    to_ext: Some(c.neighbor.ext_address),
                });
            }
            // The Child ID Response for a sleepy child that is attaching
            // (the child is already valid when the queued MLE message is
            // routed, but has not confirmed its RLOC16 yet): queued for its
            // data poll, between extended addresses (OT
            // `AddMessageForSleepyChild`).
            if let Some(c) = mle
                .children()
                .find_by_ext(&ext_of_dst(), StateFilter::AnyExceptInvalid)
                && !c.neighbor.mode.rx_on_when_idle()
                && c.neighbor.rloc16 != Rloc16::INVALID
            {
                return Ok(Route::Indirect {
                    child: c.neighbor.rloc16,
                    to_ext: Some(c.neighbor.ext_address),
                });
            }
            return Ok(Route::Direct {
                dst: MacDest::Extended(ext_of_dst()),
            });
        }
        if mle.role() == Role::Child && !mle.is_full_thread_device() {
            let p = mle.parent().ok_or(RouteError::Drop)?;
            return Ok(Route::Direct {
                dst: MacDest::Short(p.router.neighbor.rloc16),
            });
        }
        // FTD: pick the mesh destination.
        let iid = opentrust_core::types::ipv6::iid(dst);
        let mesh_dest = if is_routing_locator(dst, mlp) {
            let rloc = Rloc16(iid.locator().ok_or(RouteError::Drop)?);
            if rloc.router_id() > Rloc16::MAX_ROUTER_ID {
                return Err(RouteError::Drop);
            }
            rloc
        } else if opentrust_net::addr::is_anycast_locator(dst, mlp) {
            let aloc = iid.locator().ok_or(RouteError::Drop)?;
            r.nd.anycast_lookup(aloc).ok_or(RouteError::NoRoute)?
        } else if let Some(c) = mle.children().find_by_address(mlp, dst, StateFilter::Valid) {
            c.neighbor.rloc16
        } else if r.netif.is_on_link(dst) {
            match resolver.resolve(now, dst, true, &MleResolverEnv(mle), events) {
                Ok(Resolution::Resolved(rloc)) => rloc,
                Ok(Resolution::QueryPending) => return Err(RouteError::AddressQuery),
                // The query failed a moment ago (e.g. its source is not
                // mesh-local at the parent, after a Dataset with another
                // mesh-local prefix but the same timestamp): the parent
                // resolves for its child, as it does for an MTD.
                Err(Error::Drop) if mle.role() == Role::Child => {
                    let p = mle.parent().ok_or(RouteError::Drop)?;
                    return Ok(Route::Direct {
                        dst: MacDest::Short(p.router.neighbor.rloc16),
                    });
                }
                Err(_) => return Err(RouteError::NoRoute),
            }
        } else {
            r.nd.route_lookup(src, dst).ok_or(RouteError::NoRoute)?
        };
        if mesh_dest == Rloc16::INVALID {
            return Err(RouteError::Drop);
        }
        if !Self::is_reachable(r, mesh_dest, dst) {
            return Err(RouteError::NoRoute);
        }
        let own = mle.rloc16();
        let (hop, _) = mle.next_hop_and_path_cost(mesh_dest);
        let hop = hop.ok_or(RouteError::NoRoute)?;
        if mesh_dest == own {
            // A datagram for this device does not go out.
            return Err(RouteError::NoRoute);
        }
        if hop == mesh_dest {
            if let Some(c) = mle.children().find_by_rloc(hop, StateFilter::Valid)
                && !c.neighbor.mode.rx_on_when_idle()
            {
                return Ok(Route::Indirect {
                    child: hop,
                    to_ext: None,
                });
            }
            return Ok(Route::Direct {
                dst: MacDest::Short(hop),
            });
        }
        Ok(Route::Mesh {
            next_hop: hop,
            mesh_dest,
        })
    }

    // ------------------------------------------------------------ send

    fn mac_source<const C: usize, const U: usize, const M: usize, CP: ?Sized, ND: ?Sized>(
        r: &Routing<'_, C, U, M, CP, ND>,
        src: &Ipv6Addr,
    ) -> Address {
        let iid = opentrust_core::types::ipv6::iid(src);
        if iid.to_ext_address() == r.ext {
            Address::Extended(r.ext)
        } else {
            Address::Short(r.mle.rloc16().into())
        }
    }

    /// Fragment `datagram` per `route` and hand the frames to `sink`.
    #[allow(clippy::too_many_arguments)]
    fn transmit<const C: usize, const U: usize, const M: usize, CP, ND, S>(
        &mut self,
        r: &Routing<'_, C, U, M, CP, ND>,
        datagram: &[u8],
        src: &Ipv6Addr,
        route: Route,
        security: LinkSecurity,
        sink: &mut S,
    ) -> Result<()>
    where
        CP: ContextProvider + ?Sized,
        ND: ?Sized,
        S: FrameSink + ?Sized,
    {
        let (dst, mesh, max) = match route {
            Route::Direct { dst } => (dst, None, MAX_FRAME_PAYLOAD),
            Route::Mesh {
                next_hop,
                mesh_dest,
            } => (
                MacDest::Short(next_hop),
                Some(MeshHeader::new(
                    r.mle.rloc16().0,
                    mesh_dest.0,
                    MESH_HEADER_HOPS_LEFT,
                )),
                MAX_MESH_FRAME_PAYLOAD,
            ),
            Route::Indirect { .. } => return Err(Error::InvalidArgs),
        };
        let mac_src = Self::mac_source(r, src);
        // A direct frame with extended addresses or another key ID mode has
        // more (or less) MAC overhead than the short-address default.
        let max = if mesh.is_none() {
            max.min(frame_payload_limit(&mac_src, dst, security))
        } else {
            max
        };
        // A CSL receiver puts a CSL IE (and the header termination IE that
        // follows it) into every frame it sends: that much less payload.
        let max = if r.mle.is_csl_enabled() {
            max.saturating_sub(CSL_IE_OVERHEAD)
        } else {
            max
        };
        let tag = self.tags.next_tag();
        let mut f = Fragmenter::new(r.contexts, mac_src, dst.address(), datagram, tag, mesh, max);
        let mut buf = [0u8; 128];
        while let Some(n) = f.next_frame(&mut buf)? {
            sink.transmit(&TxFrame {
                src: if mesh.is_some() {
                    Address::Short(r.mle.rloc16().into())
                } else {
                    mac_src
                },
                dst,
                payload: &buf[..n],
                security,
                frame_pending: false,
                indirect: false,
                csl: false,
                radio: self.select_radio(dst),
            })?;
        }
        sink.datagram_sent(&datagram[..datagram.len().min(48)], dst, security);
        Ok(())
    }

    /// Send an IPv6 datagram (OT `SendMessage` followed by the transmission
    /// preparation): route it, and either transmit it, hold it while its
    /// destination is being resolved, or report why it was dropped.
    #[allow(clippy::too_many_arguments)]
    pub fn send_datagram<
        const C: usize,
        const U: usize,
        const M: usize,
        const N: usize,
        CP,
        ND,
        S,
    >(
        &mut self,
        now: Instant,
        datagram: &[u8],
        security: impl Into<LinkSecurity>,
        r: &Routing<'_, C, U, M, CP, ND>,
        resolver: &mut AddressResolver<N>,
        events: &mut impl FnMut(ResolverEvent),
        sink: &mut S,
    ) -> SendResult
    where
        CP: ContextProvider + ?Sized,
        ND: NetworkData + ?Sized,
        S: FrameSink + ?Sized,
    {
        self.send_datagram_with(
            now,
            datagram,
            security.into(),
            false,
            r,
            resolver,
            events,
            sink,
        )
    }

    /// [`MeshForwarder::send_datagram`] with the MPL retransmission flag:
    /// retransmissions of a multicast datagram are not queued for sleepy
    /// children again (only the first transmission is, OT
    /// `SendMessage`).
    #[allow(clippy::too_many_arguments)]
    pub fn send_datagram_with<
        const C: usize,
        const U: usize,
        const M: usize,
        const N: usize,
        CP,
        ND,
        S,
    >(
        &mut self,
        now: Instant,
        datagram: &[u8],
        security: impl Into<LinkSecurity>,
        mpl_retransmission: bool,
        r: &Routing<'_, C, U, M, CP, ND>,
        resolver: &mut AddressResolver<N>,
        events: &mut impl FnMut(ResolverEvent),
        sink: &mut S,
    ) -> SendResult
    where
        CP: ContextProvider + ?Sized,
        ND: NetworkData + ?Sized,
        S: FrameSink + ?Sized,
    {
        let security = security.into();
        let Some(h) = hdr_of(datagram) else {
            return SendResult::Dropped(DropReason::Invalid);
        };
        if datagram.len() > MTU {
            return SendResult::Dropped(DropReason::Invalid);
        }
        let queued = if h.dst.is_multicast() && !mpl_retransmission {
            let n = self.queue_multicast_for_sleepy_children(r, &h.dst, datagram);
            if n > 0 {
                self.csl_flush(r, sink);
            }
            n
        } else {
            0
        };
        // Multicast larger than realm-local is only for sleepy children
        // (the IPv6 layer tunnels it to the MPL forwarders for everybody
        // else).
        if h.dst.is_multicast() && opentrust_net::addr::is_multicast_larger_than_realm_local(&h.dst)
        {
            return if queued > 0 {
                SendResult::Sent
            } else {
                SendResult::Dropped(DropReason::Drop)
            };
        }
        match Self::route(now, r, resolver, &h.src, &h.dst, security, events) {
            Ok(Route::Indirect { child, to_ext }) => match match to_ext {
                Some(e) => self
                    .indirect
                    .enqueue_ext(child, r.ext, e, datagram, security),
                None => self.indirect.enqueue_secured(child, datagram, security),
            } {
                Ok(()) => {
                    self.csl_flush(r, sink);
                    SendResult::Indirect(child)
                }
                Err(_) => SendResult::Dropped(DropReason::NoBufs),
            },
            Ok(route) => match self.transmit(r, datagram, &h.src, route, security, sink) {
                Ok(()) => SendResult::Sent,
                Err(Error::NoBufs) => SendResult::Dropped(DropReason::NoBufs),
                Err(_) => SendResult::Dropped(DropReason::Link),
            },
            Err(RouteError::AddressQuery) => match self.held.iter().position(Option::is_none) {
                Some(i) => match self.held_pool.alloc(datagram) {
                    Ok(buf) => {
                        self.held[i] = Some(Held {
                            eid: h.dst,
                            len: datagram.len(),
                            security,
                            buf,
                        });
                        SendResult::Held
                    }
                    Err(_) => SendResult::Dropped(DropReason::NoBufs),
                },
                None => SendResult::Dropped(DropReason::NoBufs),
            },
            Err(RouteError::NoRoute) => SendResult::Dropped(DropReason::NoRoute),
            Err(RouteError::Drop) => SendResult::Dropped(DropReason::Drop),
        }
    }

    /// Queue a copy of a multicast `datagram` for every sleepy child that
    /// subscribed to `dst` (or all of them for the all-Thread-nodes
    /// groups); returns how many children got it.
    fn queue_multicast_for_sleepy_children<
        const C: usize,
        const U: usize,
        const M: usize,
        CP: ?Sized,
        ND: ?Sized,
    >(
        &mut self,
        r: &Routing<'_, C, U, M, CP, ND>,
        dst: &Ipv6Addr,
        datagram: &[u8],
    ) -> usize {
        let mlp = r.netif.mesh_local_prefix();
        let for_all = *dst == opentrust_net::addr::link_local_all_thread_nodes(mlp)
            || *dst == opentrust_net::addr::realm_local_all_thread_nodes(mlp);
        let mut n = 0;
        for c in r.mle.children().iter(StateFilter::Valid) {
            if !c.neighbor.mode.rx_on_when_idle()
                && (for_all || c.has_address(mlp, dst))
                && self.indirect.enqueue(c.neighbor.rloc16, datagram).is_ok()
            {
                n += 1;
            }
        }
        n
    }

    // ------------------------------------------------------------ sleepy children

    /// Hand the queued messages of every CSL synchronized sleepy child to
    /// `sink` (frames with [`TxFrame::csl`]); the MAC transmits them in the
    /// child's sample windows and keeps them for its data poll if that fails
    /// (OT `CslTxScheduler` requests a frame ahead of each window; here the
    /// MAC holds the frames and does the timing). Returns the number of
    /// frames handed over. Called after queueing a message; call it again
    /// when a child became CSL synchronized (`Mle::child_csl_synchronized`)
    /// with messages already queued.
    pub fn csl_flush<
        const C: usize,
        const U: usize,
        const M: usize,
        CP: ContextProvider + ?Sized,
        ND: ?Sized,
        S: FrameSink + ?Sized,
    >(
        &mut self,
        r: &Routing<'_, C, U, M, CP, ND>,
        sink: &mut S,
    ) -> usize {
        let mut sent = 0;
        for c in r.mle.children().iter(StateFilter::Valid) {
            if c.neighbor.mode.rx_on_when_idle() || !c.csl_synchronized {
                continue;
            }
            let child = c.neighbor.rloc16;
            let n =
                self.indirect
                    .flush_csl(child, r.mle.rloc16(), r.contexts, MAX_FRAME_PAYLOAD, sink);
            if n > 0 {
                self.note_child_message_sent(child);
            }
            sent += n;
        }
        sent
    }

    /// The child (RLOC16) a data poll with MAC source `mac_src` came from.
    fn poll_child<const C: usize, const U: usize, const M: usize, CP: ?Sized, ND: ?Sized>(
        r: &Routing<'_, C, U, M, CP, ND>,
        mac_src: &Address,
    ) -> Option<Rloc16> {
        let children = r.mle.children();
        match mac_src {
            Address::Short(s) => children
                .find_by_rloc(Rloc16(s.0), StateFilter::Valid)
                .map(|c| c.neighbor.rloc16),
            // A child polls by extended address until its Child ID Response
            // is delivered (it is not valid before that).
            Address::Extended(e) => children
                .find_by_ext(e, StateFilter::AnyExceptInvalid)
                .map(|c| c.neighbor.rloc16)
                .filter(|r| *r != Rloc16::INVALID),
            Address::None => None,
        }
    }

    /// The Frame Pending bit for the ACK of a data poll from `mac_src`
    /// (OT source match table lookup).
    pub fn data_poll_frame_pending<
        const C: usize,
        const U: usize,
        const M: usize,
        CP: ?Sized,
        ND: ?Sized,
    >(
        &self,
        mac_src: &Address,
        r: &Routing<'_, C, U, M, CP, ND>,
    ) -> bool {
        Self::poll_child(r, mac_src).is_some_and(|c| self.indirect.frame_pending(c))
    }

    /// A data poll arrived from the sleepy child with MAC source `mac_src`:
    /// send its next frame (empty if nothing is queued). After
    /// [`PollOutcome::Sent`] the child is buffered for
    /// [`MeshForwarder::take_child_message_sent`] (the caller restarts the
    /// child's supervision interval with `Mle::child_message_sent`; the
    /// forwarder only sees the MLE core through a shared reference).
    /// [`Error::NotFound`] if the sender is not a valid child.
    pub fn handle_data_poll<
        const C: usize,
        const U: usize,
        const M: usize,
        CP: ContextProvider + ?Sized,
        ND: ?Sized,
        S: FrameSink + ?Sized,
    >(
        &mut self,
        mac_src: &Address,
        r: &Routing<'_, C, U, M, CP, ND>,
        sink: &mut S,
    ) -> Result<PollOutcome> {
        let child = Self::poll_child(r, mac_src).ok_or(Error::NotFound)?;
        // An empty answer to the poll is no message: it does not restart the
        // supervision interval of the child.
        let queued = self.indirect.count(child) > 0;
        let out = self.indirect.handle_data_poll(
            child,
            r.mle.rloc16(),
            r.contexts,
            MAX_FRAME_PAYLOAD,
            sink,
        );
        if queued && matches!(out, Ok(PollOutcome::Sent { .. })) {
            self.note_child_message_sent(child);
        }
        out
    }

    fn note_child_message_sent(&mut self, child: Rloc16) {
        if self.sent_children.contains(&Some(child)) {
            return;
        }
        if let Some(s) = self.sent_children.iter_mut().find(|s| s.is_none()) {
            *s = Some(child);
        }
    }

    /// Next child that was sent a message since the last call (OT
    /// `ChildSupervisor::UpdateOnSend`): call `Mle::child_message_sent`
    /// with it, in a loop until `None`.
    pub fn take_child_message_sent(&mut self) -> Option<Rloc16> {
        self.sent_children.iter_mut().find_map(Option::take)
    }

    /// A sleepy child switched to rx-on-when-idle
    /// (`MleEnv::indirect_remove_child` for a child that stays valid; OT
    /// `IndirectSender::HandleChildModeChange`): its queued datagrams are
    /// sent directly, oldest first; returns how many were handed to
    /// `sink`. Supervision messages are dropped.
    pub fn child_became_rx_on<
        const C: usize,
        const U: usize,
        const M: usize,
        CP: ContextProvider + ?Sized,
        ND: ?Sized,
        S: FrameSink + ?Sized,
    >(
        &mut self,
        rloc16: Rloc16,
        r: &Routing<'_, C, U, M, CP, ND>,
        sink: &mut S,
    ) -> usize {
        let mut sent = 0;
        let mut buf = [0u8; MTU];
        while let Some(n) = self.indirect.take_datagram(rloc16, &mut buf) {
            let Some(h) = hdr_of(&buf[..n]) else { continue };
            let route = Route::Direct {
                dst: MacDest::Short(rloc16),
            };
            if self
                .transmit(r, &buf[..n], &h.src, route, LinkSecurity::Network, sink)
                .is_ok()
            {
                sent += 1;
            }
        }
        sent
    }

    /// A child was removed or stopped sleeping (`MleEnv::indirect_remove_child`,
    /// `MleEvent::ChildRemoved`): drop its queued messages.
    pub fn child_removed(&mut self, rloc16: Rloc16) {
        self.indirect.remove_child(rloc16);
    }

    /// `MleEnv::send_child_supervision`: queue a supervision message.
    pub fn send_child_supervision(&mut self, rloc16: Rloc16) {
        self.indirect.enqueue_supervision(rloc16);
    }

    /// An address resolution finished (OT `MeshForwarder::HandleResolved`,
    /// fed with [`ResolverEvent::Resolved`] / [`ResolverEvent::ResolutionFailed`]).
    /// Datagrams held for `eid` are sent, or dropped if resolution failed;
    /// a dropped datagram that did not originate here is answered with a
    /// destination unreachable through `sink`.
    #[allow(clippy::too_many_arguments)]
    pub fn handle_resolved<
        const C: usize,
        const U: usize,
        const M: usize,
        const N: usize,
        CP,
        ND,
        S,
    >(
        &mut self,
        now: Instant,
        eid: &Ipv6Addr,
        resolved: bool,
        r: &Routing<'_, C, U, M, CP, ND>,
        resolver: &mut AddressResolver<N>,
        events: &mut impl FnMut(ResolverEvent),
        sink: &mut S,
    ) where
        CP: ContextProvider + ?Sized,
        ND: NetworkData + ?Sized,
        S: FrameSink + ?Sized,
    {
        for i in 0..HOLD {
            let Some(h) = self.held[i].take_if(|h| h.eid == *eid) else {
                continue;
            };
            let mut copy = [0u8; MTU];
            let n = self.held_pool.read(&h.buf, &mut copy[..h.len]);
            self.held_pool.free(h.buf);
            let data = &copy[..n];
            if !resolved {
                let local = hdr_of(data).is_some_and(|x| r.netif.has_unicast(&x.src));
                if !local {
                    sink.dest_unreachable(&data[..data.len().min(Ipv6Header::LEN)]);
                }
                continue;
            }
            let result = self.send_datagram(now, data, h.security, r, resolver, events, sink);
            // A datagram of this device is only dropped (OT answers with a
            // destination unreachable for forwarded datagrams only).
            let local = hdr_of(data).is_some_and(|x| r.netif.has_unicast(&x.src));
            if result == SendResult::Dropped(DropReason::NoRoute) && !local {
                sink.dest_unreachable(&data[..data.len().min(Ipv6Header::LEN)]);
            }
        }
    }

    // ------------------------------------------------------------ receive

    /// Peek at the IPv6 header carried in an IPHC frame or first fragment
    /// (`payload` starts with FRAG1 or IPHC), using `src`/`dst` as the
    /// addresses for IPHC.
    fn peek_header<CP: ContextProvider + ?Sized>(
        contexts: &CP,
        payload: &[u8],
        src: &Address,
        dst: &Address,
    ) -> Option<Ipv6Header> {
        let (data, size) = match parse_frame(payload).ok()? {
            LowpanFrame::Iphc(d) => (d, None),
            LowpanFrame::Fragment { header, payload } if header.datagram_offset == 0 => {
                (payload, Some(header.datagram_size))
            }
            _ => return None,
        };
        let mut hdr = [0u8; 128];
        // The IPv6 header is written first, even if the later headers do
        // not fit.
        let _ = decompress(contexts, src, dst, data, size, &mut hdr);
        Ipv6Header::parse(&hdr).ok()
    }

    /// Process a received frame payload. `mac_src` / `mac_dst` are the MAC
    /// addresses of the frame.
    #[allow(clippy::too_many_arguments)]
    pub fn receive_frame<
        'a,
        const C: usize,
        const U: usize,
        const M: usize,
        const N: usize,
        CP,
        ND,
        S,
    >(
        &'a mut self,
        now: Instant,
        payload: &[u8],
        mac_src: Address,
        mac_dst: Address,
        link_security: impl Into<LinkSecurity>,
        r: &Routing<'_, C, U, M, CP, ND>,
        resolver: &mut AddressResolver<N>,
        events: &mut impl FnMut(ResolverEvent),
        sink: &mut S,
    ) -> Rx<'a>
    where
        CP: ContextProvider + ?Sized,
        ND: NetworkData + ?Sized,
        S: FrameSink + ?Sized,
    {
        let link_security = link_security.into();
        let frame = match parse_frame(payload) {
            Ok(f) => f,
            Err(_) => return Rx::Dropped(DropReason::Invalid),
        };
        let (header, inner) = match frame {
            LowpanFrame::Mesh { header, payload } => (Some(header), payload),
            _ => (None, payload),
        };
        if header.is_none() {
            return self.receive_inner(now, inner, &mac_src, &mac_dst, link_security, r, sink);
        }
        let Some(mut header) = header else {
            return Rx::Consumed;
        };
        if cfg!(not(feature = "ftd")) {
            // OT `HandleReceivedFrame`: mesh header frames are an FTD feature.
            return Rx::Dropped(DropReason::Invalid);
        }
        if !link_security.is_network() {
            return Rx::Dropped(DropReason::Security);
        }
        let (msrc, mdst) = (Rloc16(header.source), Rloc16(header.destination));
        let a_src = Address::Short(msrc.into());
        let a_dst = Address::Short(mdst.into());
        // Snooping.
        if let Some(h) = Self::peek_header(r.contexts, inner, &a_src, &a_dst)
            && !opentrust_core::types::ipv6::iid(&h.src).is_locator()
            && r.nd.is_on_mesh(&h.src)
        {
            resolver.update_snooped(now, &h.src, msrc, mdst, &MleResolverEnv(r.mle), events);
        }
        let mle = r.mle;
        let is_minimal_child = mle
            .children()
            .find_by_rloc(mdst, StateFilter::Valid)
            .is_some_and(|c| !c.neighbor.mode.full_thread_device());
        if mle.rloc16() == mdst || is_minimal_child {
            return self.receive_inner(now, inner, &a_src, &a_dst, link_security, r, sink);
        }
        if header.hops_left == 0 {
            return Rx::Dropped(DropReason::HopsExhausted);
        }
        let prev = match mac_src {
            Address::Short(s) => Some(Rloc16(s.0)),
            _ => None,
        };
        let (hop, _) = mle.next_hop_and_path_cost(mdst);
        if let (Some(p), Some(h)) = (prev, hop)
            && p == h
        {
            sink.routing_loop(p, mdst);
            return Rx::Dropped(DropReason::RoutingLoop);
        }
        if let Some(h) = Self::peek_header(r.contexts, inner, &a_src, &a_dst)
            && !Self::is_reachable(r, mdst, &h.dst)
        {
            let mut inv = [0u8; Ipv6Header::LEN];
            if h.write(&mut inv).is_ok() {
                sink.dest_unreachable(&inv);
            }
            return Rx::Dropped(DropReason::NoRoute);
        }
        let Some(hop) = hop else {
            return Rx::Dropped(DropReason::NoRoute);
        };
        header.decrement_hops_left();
        let mut out = [0u8; 128];
        let n = match opentrust_lowpan::forward::rewrite(&header, inner, &mut out) {
            Ok(n) => n,
            Err(_) => return Rx::Dropped(DropReason::Invalid),
        };
        match sink.transmit(&TxFrame {
            src: Address::Short(mle.rloc16().into()),
            dst: MacDest::Short(hop),
            payload: &out[..n],
            security: LinkSecurity::Network,
            frame_pending: false,
            indirect: false,
            csl: false,
            radio: self.select_radio(MacDest::Short(hop)),
        }) {
            Ok(()) => Rx::Forwarded,
            Err(_) => Rx::Dropped(DropReason::Link),
        }
    }

    /// Fragment / IPHC frame for this device (after the mesh header, if
    /// any; `src` / `dst` are the originator and destination for IPHC).
    #[allow(clippy::too_many_arguments)]
    fn receive_inner<'a, const C: usize, const U: usize, const M: usize, CP, ND, S>(
        &'a mut self,
        now: Instant,
        payload: &[u8],
        src: &Address,
        dst: &Address,
        link_security: LinkSecurity,
        r: &Routing<'_, C, U, M, CP, ND>,
        sink: &mut S,
    ) -> Rx<'a>
    where
        CP: ContextProvider + ?Sized,
        ND: NetworkData + ?Sized,
        S: FrameSink + ?Sized,
    {
        let inner = match parse_frame(payload) {
            Ok(LowpanFrame::Mesh { .. }) | Err(_) => return Rx::Dropped(DropReason::Invalid),
            Ok(LowpanFrame::Empty) => return Rx::Consumed,
            Ok(f) => f,
        };
        let datagram: &[u8] = match inner {
            LowpanFrame::Fragment { .. } => {
                self.reasm
                    .set_sleepy(!r.mle.device_mode().rx_on_when_idle());
                match self
                    .reasm
                    .handle_fragment(now, r.contexts, src, dst, link_security, payload)
                {
                    Ok(Reassembled::Complete(d)) => {
                        let n = d.len();
                        self.rx_buf[..n].copy_from_slice(d);
                        &self.rx_buf[..n]
                    }
                    Ok(Reassembled::Incomplete) => return Rx::Consumed,
                    Err(_) => return Rx::Dropped(DropReason::Invalid),
                }
            }
            LowpanFrame::Iphc(d) => {
                match decompress_datagram(r.contexts, src, dst, d, None, &mut self.rx_buf) {
                    Ok(n) => &self.rx_buf[..n],
                    Err(_) => return Rx::Dropped(DropReason::Invalid),
                }
            }
            _ => return Rx::Consumed,
        };
        Self::check_stale_destination(r, src, dst, datagram, sink);
        Rx::Datagram(datagram)
    }

    /// OT `CheckReachabilityToSendIcmpError(message, macAddrs)`: a datagram
    /// sent to this device by a router (stale address cache) for an on-mesh
    /// address that is neither ours nor a neighbor's gets a destination
    /// unreachable.
    fn check_stale_destination<
        const C: usize,
        const U: usize,
        const M: usize,
        CP: ?Sized,
        ND: NetworkData + ?Sized,
        S: FrameSink + ?Sized,
    >(
        r: &Routing<'_, C, U, M, CP, ND>,
        src: &Address,
        dst: &Address,
        datagram: &[u8],
        sink: &mut S,
    ) {
        let (Address::Short(s), Address::Short(d)) = (src, dst) else {
            return;
        };
        if r.mle
            .children()
            .find_by_rloc(Rloc16(s.0), StateFilter::AnyExceptInvalid)
            .is_some_and(|c| !c.neighbor.mode.full_thread_device())
        {
            return;
        }
        let Some(h) = hdr_of(datagram) else { return };
        if h.dst.is_multicast() || !r.nd.is_on_mesh(&h.dst) {
            return;
        }
        if !Self::is_reachable(r, Rloc16(d.0), &h.dst) {
            sink.dest_unreachable(&datagram[..Ipv6Header::LEN.min(datagram.len())]);
        }
    }
}

/// Why [`MeshForwarder::route`] found no route.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteError {
    /// Policy: drop silently.
    Drop,
    /// No route to the destination.
    NoRoute,
    /// An address query is pending: hold the datagram.
    AddressQuery,
}

#[cfg(all(test, feature = "trel"))]
mod radio_tests {
    use super::*;
    use crate::trel::RadioSelector;

    #[test]
    fn frames_follow_the_radio_selection() {
        let mut f = MeshForwarder::<2, 2, 4>::new(1);
        let n = Rloc16(0x0800);
        // Unknown neighbors and broadcasts use the 802.15.4 radio.
        assert_eq!(f.select_radio(MacDest::Short(n)), RadioLink::Ieee802154);
        assert_eq!(f.select_radio(MacDest::Broadcast), RadioLink::Ieee802154);
        f.radios.on_receive(n, RadioLink::Ieee802154);
        f.radios.on_receive(n, RadioLink::Trel);
        assert_eq!(f.select_radio(MacDest::Short(n)), RadioLink::Trel);
        // Deferred ack timeouts move the traffic back.
        f.radios.on_deferred_ack(n, false);
        assert_eq!(f.select_radio(MacDest::Short(n)), RadioLink::Ieee802154);
        let _: &RadioSelector = &f.radios;
    }
}
