//! Network Diagnostics, server side (Thread 1.4.1 section 10, OT
//! `NetworkDiagnostic::Server`): `/d/dg` Diagnostic Get, `/d/dq` Diagnostic
//! Query (answered with a `/d/da` message), `/d/dr` Diagnostic Reset, and the
//! public getters for neighbors, children, routes and counters.

use heapless::Vec;
use opentrust_core::crypto::CryptoBackend;
use opentrust_core::types::{ExtAddress, Rloc16};
use opentrust_mac::mac::MacCounters;
use opentrust_mle::Mle;
use opentrust_mle::neighbor::StateFilter;
use opentrust_net::netif::Netif;

use crate::stack::{CHILDREN, Core};

/// Diagnostic TLV types (OT `OT_NETWORK_DIAGNOSTIC_TLV_*`).
pub mod tlv {
    /// MAC Extended Address.
    pub const EXT_ADDRESS: u8 = 0;
    /// Address16 (RLOC16).
    pub const SHORT_ADDRESS: u8 = 1;
    /// Device mode.
    pub const MODE: u8 = 2;
    /// Child timeout (sleepy devices).
    pub const TIMEOUT: u8 = 3;
    /// Connectivity.
    pub const CONNECTIVITY: u8 = 4;
    /// Route64.
    pub const ROUTE: u8 = 5;
    /// Leader Data.
    pub const LEADER_DATA: u8 = 6;
    /// Network Data.
    pub const NETWORK_DATA: u8 = 7;
    /// IPv6 Address List.
    pub const IP6_ADDR_LIST: u8 = 8;
    /// MAC Counters.
    pub const MAC_COUNTERS: u8 = 9;
    /// Child Table.
    pub const CHILD_TABLE: u8 = 16;
    /// Channel Pages.
    pub const CHANNEL_PAGES: u8 = 17;
    /// Type List.
    pub const TYPE_LIST: u8 = 18;
    /// Maximum Child Timeout.
    pub const MAX_CHILD_TIMEOUT: u8 = 19;
    /// EUI-64.
    pub const EUI64: u8 = 23;
    /// Thread version.
    pub const VERSION: u8 = 24;
    /// Answer.
    pub const ANSWER: u8 = 32;
    /// Query ID.
    pub const QUERY_ID: u8 = 33;
}

/// `user` value of the Diagnostic Get request in [`opentrust_coap::tmf::Agent::post`].
pub(crate) const USER_DIAG_GET: u32 = 0x0a53_0030;

/// Largest diagnostic response (the TMF message size).
pub const MAX_RESPONSE: usize = 256;

/// The TLVs of a response, built in place.
pub(crate) struct Out {
    pub buf: Vec<u8, MAX_RESPONSE>,
}

impl Out {
    pub(crate) fn new() -> Self {
        Self { buf: Vec::new() }
    }

    /// Append a TLV; `false` (nothing written) if it does not fit.
    fn put(&mut self, ty: u8, value: &[u8]) -> bool {
        let need = 2 + value.len();
        if value.len() > 254 || self.buf.len() + need > MAX_RESPONSE {
            return false;
        }
        let _ = self.buf.push(ty);
        let _ = self.buf.push(value.len() as u8);
        let _ = self.buf.extend_from_slice(value);
        true
    }
}

/// Link information of a neighbor (OT `otNeighborInfo`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NeighborInfo {
    /// Extended address.
    pub ext: ExtAddress,
    /// RLOC16.
    pub rloc16: Rloc16,
    /// Average RSSI in dBm.
    pub average_rssi: i8,
    /// Link quality of the incoming link (0..=3).
    pub link_quality_in: u8,
    /// Receiver on when idle.
    pub rx_on_when_idle: bool,
    /// Full Thread device.
    pub full_thread_device: bool,
    /// Is a child of this device (otherwise the parent or a router).
    pub is_child: bool,
}

/// An entry of the child table (OT `otChildInfo`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChildInfo {
    /// Extended address.
    pub ext: ExtAddress,
    /// RLOC16.
    pub rloc16: Rloc16,
    /// Child timeout in seconds.
    pub timeout_secs: u32,
    /// Average RSSI in dBm.
    pub average_rssi: i8,
    /// Receiver on when idle.
    pub rx_on_when_idle: bool,
    /// Full Thread device.
    pub full_thread_device: bool,
}

/// An entry of the router table (OT `otRouterInfo`).
#[cfg(feature = "ftd")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RouteInfo {
    /// Router ID.
    pub router_id: u8,
    /// RLOC16 of the router.
    pub rloc16: Rloc16,
    /// Router ID of the next hop, if any.
    pub next_hop: Option<u8>,
    /// Path cost.
    pub cost: u8,
    /// A direct neighbor of this device.
    pub is_neighbor: bool,
}

fn state_counters_sum(c: &MacCounters) -> [u32; 9] {
    [
        c.rx_other,
        c.rx_err_no_frame
            .wrapping_add(c.rx_err_unknown_neighbor)
            .wrapping_add(c.rx_err_invalid_src_addr)
            .wrapping_add(c.rx_err_sec),
        c.tx_err_cca,
        // The MAC counts received data frames, not unicast / broadcast.
        c.rx_data,
        c.rx_beacon_request,
        c.rx_dest_addr_filtered,
        c.tx_data,
        c.tx_beacon,
        c.tx_err_abort,
    ]
}

/// Append the diagnostic TLV `ty` (OT `Server::AppendDiagTlv`); TLVs that do
/// not apply to this device or do not fit are left out.
#[allow(clippy::collapsible_match)] // one arm per TLV reads better
pub(crate) fn append_tlv<S, C: CryptoBackend, R>(
    mle: &Mle<CHILDREN>,
    core: &Core<S, C, R>,
    ty: u8,
    out: &mut Out,
) {
    match ty {
        tlv::EXT_ADDRESS => {
            out.put(ty, &core.ext.0);
        }
        tlv::EUI64 => {
            out.put(ty, &core.ext.0);
        }
        tlv::SHORT_ADDRESS => {
            out.put(ty, &mle.rloc16().0.to_be_bytes());
        }
        tlv::MODE => {
            out.put(ty, &[mle.config().mode.to_bits()]);
        }
        tlv::TIMEOUT => {
            if !mle.config().mode.rx_on_when_idle() {
                out.put(ty, &mle.config().timeout_secs.to_be_bytes());
            }
        }
        tlv::LEADER_DATA => {
            let l = mle.leader_data();
            let mut v = [0u8; 8];
            v[..4].copy_from_slice(&l.partition_id.to_be_bytes());
            v[4] = l.weighting;
            v[5] = l.data_version;
            v[6] = l.stable_data_version;
            v[7] = l.leader_router_id;
            out.put(ty, &v);
        }
        tlv::NETWORK_DATA => {
            out.put(ty, core.netdata.view().0);
        }
        tlv::IP6_ADDR_LIST => ip6_list(&core.ip6.netif, out),
        tlv::MAC_COUNTERS => {
            let mut v = [0u8; 36];
            for (i, c) in state_counters_sum(core.mac.counters()).iter().enumerate() {
                v[i * 4..i * 4 + 4].copy_from_slice(&c.to_be_bytes());
            }
            out.put(ty, &v);
        }
        tlv::CHANNEL_PAGES => {
            out.put(ty, &[0]);
        }
        tlv::VERSION => {
            out.put(ty, &opentrust_mle::consts::THREAD_VERSION.to_be_bytes());
        }
        #[cfg(feature = "ftd")]
        tlv::CONNECTIVITY => {
            let c = mle.fill_connectivity();
            let mut b = [0u8; 10];
            let n = c.encode(&mut b);
            out.put(ty, &b[..n]);
        }
        #[cfg(feature = "ftd")]
        tlv::ROUTE => {
            if mle.role().is_router_or_leader() {
                out.put(ty, &mle.route64_value());
            }
        }
        #[cfg(feature = "ftd")]
        tlv::CHILD_TABLE => {
            if mle.role().is_router_or_leader() {
                let mut v: Vec<u8, 80> = Vec::new();
                for c in mle.children().iter(StateFilter::Valid) {
                    let mut t = 0u8;
                    while (1u64 << t) < u64::from(c.timeout_secs) {
                        t += 1;
                    }
                    let lqi = u16::from(c.neighbor.link_info.link_quality_in() as u8) & 3;
                    let w =
                        (u16::from(t + 4) & 0x1f) << 11 | lqi << 9 | (c.neighbor.rloc16.0 & 0x1ff);
                    let _ = v.extend_from_slice(&w.to_be_bytes());
                    let _ = v.push(c.neighbor.mode.to_bits());
                }
                out.put(ty, &v);
            }
        }
        #[cfg(feature = "ftd")]
        tlv::MAX_CHILD_TIMEOUT => {
            if mle.role().is_router_or_leader()
                && let Some(m) = mle
                    .children()
                    .iter(StateFilter::Valid)
                    .map(|c| c.timeout_secs)
                    .max()
            {
                out.put(ty, &m.to_be_bytes());
            }
        }
        _ => {}
    }
}

fn ip6_list<const U: usize, const M: usize>(netif: &Netif<U, M>, out: &mut Out) {
    let mut v: Vec<u8, 128> = Vec::new();
    for a in netif.unicast_addresses() {
        if v.extend_from_slice(&a.addr.octets()).is_err() {
            break;
        }
    }
    out.put(tlv::IP6_ADDR_LIST, &v);
}

/// The TLV types of the Type List TLV in `payload`.
pub(crate) fn requested_types(payload: &[u8]) -> Vec<u8, 40> {
    let mut v = Vec::new();
    let mut i = 0;
    while i + 2 <= payload.len() {
        let (ty, len) = (payload[i], usize::from(payload[i + 1]));
        let Some(val) = payload.get(i + 2..i + 2 + len) else {
            break;
        };
        if ty == tlv::TYPE_LIST {
            for t in val {
                let _ = v.push(*t);
            }
        }
        i += 2 + len;
    }
    v
}

/// The Query ID TLV of a request.
pub(crate) fn query_id(payload: &[u8]) -> Option<u16> {
    let mut i = 0;
    while i + 2 <= payload.len() {
        let (ty, len) = (payload[i], usize::from(payload[i + 1]));
        let val = payload.get(i + 2..i + 2 + len)?;
        if ty == tlv::QUERY_ID && len == 2 {
            return Some(u16::from_be_bytes([val[0], val[1]]));
        }
        i += 2 + len;
    }
    None
}

/// The response to a Diagnostic Get request.
pub(crate) fn build_response<S, C: CryptoBackend, R>(
    mle: &Mle<CHILDREN>,
    core: &Core<S, C, R>,
    request: &[u8],
) -> Out {
    let mut out = Out::new();
    for t in requested_types(request) {
        append_tlv(mle, core, t, &mut out);
    }
    out
}

/// The `/d/da` message for a Diagnostic Query: Query ID, the TLVs, Answer
/// TLV (index 0, last).
pub(crate) fn build_answer<S, C: CryptoBackend, R>(
    mle: &Mle<CHILDREN>,
    core: &Core<S, C, R>,
    request: &[u8],
) -> Out {
    let mut out = Out::new();
    if let Some(q) = query_id(request) {
        out.put(tlv::QUERY_ID, &q.to_be_bytes());
    }
    for t in requested_types(request) {
        append_tlv(mle, core, t, &mut out);
    }
    // Answer TLV: last flag and index 0.
    out.put(tlv::ANSWER, &[0x80, 0x00]);
    out
}

impl<S: opentrust_platform::SettingsStore, C: crate::InstanceCrypto, R> crate::Instance<S, C, R>
where
    C: opentrust_core::crypto::ecdsa::EcdsaP256 + Clone,
    R: rand_core::Rng + rand_core::CryptoRng,
{
    /// Ask `dst` for diagnostic TLVs with a Diagnostic Get request (OT
    /// `otThreadSendDiagnosticGet`); the response is
    /// [`Event::DiagAnswer`](crate::Event::DiagAnswer) /
    /// [`diag_take_answer`](Self::diag_take_answer).
    pub fn diag_get(
        &mut self,
        dst: core::net::Ipv6Addr,
        types: &[u8],
        now: opentrust_core::time::Instant,
    ) -> opentrust_core::Result<()> {
        self.diag_request(
            opentrust_coap::uri::Uri::DiagnosticGetRequest,
            dst,
            types,
            now,
        )
    }

    /// Send a Diagnostic Query (answered with one or more `/d/da` messages).
    pub fn diag_query(
        &mut self,
        dst: core::net::Ipv6Addr,
        types: &[u8],
        now: opentrust_core::time::Instant,
    ) -> opentrust_core::Result<()> {
        self.diag_request(
            opentrust_coap::uri::Uri::DiagnosticGetQuery,
            dst,
            types,
            now,
        )
    }

    fn diag_request(
        &mut self,
        uri: opentrust_coap::uri::Uri,
        dst: core::net::Ipv6Addr,
        types: &[u8],
        now: opentrust_core::time::Instant,
    ) -> opentrust_core::Result<()> {
        let mut p: Vec<u8, 48> = Vec::new();
        let n = u8::try_from(types.len()).map_err(|_| opentrust_core::Error::InvalidArgs)?;
        let _ = p.push(tlv::TYPE_LIST);
        let _ = p.push(n);
        p.extend_from_slice(types)
            .map_err(|_| opentrust_core::Error::InvalidArgs)?;
        let own = self.mle.rloc16();
        let mlp = self.core.cfg.cur.mesh_local_prefix;
        self.core.now = now;
        let r = self.agent.post(
            now,
            &mut self.prng,
            &mut self.sink,
            dst,
            (own != Rloc16::INVALID).then(|| mlp.rloc(own)),
            opentrust_core::message::Priority::Normal,
            uri,
            &p,
            (uri == opentrust_coap::uri::Uri::DiagnosticGetRequest).then_some(USER_DIAG_GET),
        );
        self.poll(now);
        r
    }

    /// The oldest received diagnostic answer: the TLVs of a Diagnostic Get
    /// response or a Diagnostic Answer message (decode with `diag_tlv`).
    pub fn diag_take_answer(&mut self) -> Option<Vec<u8, MAX_RESPONSE>> {
        self.diag_in.pop_front()
    }

    /// The MAC counters (OT `otLinkGetCounters`).
    pub fn mac_counters(&self) -> &MacCounters {
        self.core.mac.counters()
    }

    /// The neighbors: the parent, the routers and the children (OT
    /// `otThreadGetNextNeighborInfo`).
    pub fn neighbor_table(&self) -> Vec<NeighborInfo, 40> {
        let mut v = Vec::new();
        let info = |n: &opentrust_mle::neighbor::Neighbor, is_child: bool| NeighborInfo {
            ext: n.ext_address,
            rloc16: n.rloc16,
            average_rssi: n.link_info.average_rss(),
            link_quality_in: n.link_info.link_quality_in() as u8,
            rx_on_when_idle: n.mode.rx_on_when_idle(),
            full_thread_device: n.mode.full_thread_device(),
            is_child,
        };
        if let Some(p) = self.mle.parent() {
            let _ = v.push(info(&p.router.neighbor, false));
        }
        #[cfg(feature = "ftd")]
        for r in self.mle.router_table().iter(StateFilter::Valid) {
            if r.neighbor.rloc16 != self.mle.rloc16() {
                let _ = v.push(info(&r.neighbor, false));
            }
        }
        for c in self.mle.children().iter(StateFilter::Valid) {
            let _ = v.push(info(&c.neighbor, true));
        }
        v
    }

    /// The child table (OT `otThreadGetChildInfoByIndex`).
    pub fn child_table(&self) -> Vec<ChildInfo, { CHILDREN }> {
        let mut v = Vec::new();
        for c in self.mle.children().iter(StateFilter::Valid) {
            let _ = v.push(ChildInfo {
                ext: c.neighbor.ext_address,
                rloc16: c.neighbor.rloc16,
                timeout_secs: c.timeout_secs,
                average_rssi: c.neighbor.link_info.average_rss(),
                rx_on_when_idle: c.neighbor.mode.rx_on_when_idle(),
                full_thread_device: c.neighbor.mode.full_thread_device(),
            });
        }
        v
    }

    /// The router table (OT `otThreadGetRouterInfo`).
    #[cfg(feature = "ftd")]
    pub fn route_table(&self) -> Vec<RouteInfo, 62> {
        let mut v = Vec::new();
        for r in self.mle.router_table().iter(StateFilter::AnyExceptInvalid) {
            let _ = v.push(RouteInfo {
                router_id: r.router_id,
                rloc16: Rloc16::from_router_id(r.router_id).unwrap_or(Rloc16::INVALID),
                next_hop: r.next_hop,
                cost: r.cost,
                is_neighbor: r.neighbor.is_valid(),
            });
        }
        v
    }
}
