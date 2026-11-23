//! Network Diagnostics, server side (Thread 1.4.1 section 10, OT
//! `NetworkDiagnostic::Server`): `/d/dg` Diagnostic Get, `/d/dq` Diagnostic
//! Query (answered with a `/d/da` message), `/d/dr` Diagnostic Reset, and the
//! public getters for neighbors, children, routes and counters.

use heapless::Vec;
use rs_thread_core::crypto::CryptoBackend;
use rs_thread_core::types::{ExtAddress, Rloc16};
use rs_thread_mac::mac::MacCounters;
use rs_thread_mle::Mle;
use rs_thread_mle::neighbor::StateFilter;
use rs_thread_net::netif::Netif;

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
    /// Battery level.
    pub const BATTERY_LEVEL: u8 = 14;
    /// Supply voltage.
    pub const SUPPLY_VOLTAGE: u8 = 15;
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
    /// Vendor name.
    pub const VENDOR_NAME: u8 = 25;
    /// Vendor model.
    pub const VENDOR_MODEL: u8 = 26;
    /// Vendor software version.
    pub const VENDOR_SW_VERSION: u8 = 27;
    /// Thread stack version string.
    pub const THREAD_STACK_VERSION: u8 = 28;
    /// Answer.
    pub const ANSWER: u8 = 32;
    /// Query ID.
    pub const QUERY_ID: u8 = 33;
    /// Vendor application URL.
    pub const VENDOR_APP_URL: u8 = 35;
}

/// `user` value of the Diagnostic Get request in [`rs_thread_coap::tmf::Agent::post`].
pub(crate) const USER_DIAG_GET: u32 = 0x0a53_0030;

/// Largest diagnostic response (the TLVs of one message).
pub const MAX_RESPONSE: usize = 512;

/// A received diagnostic answer: the sender and the TLVs.
pub(crate) type Answer = (core::net::Ipv6Addr, Vec<u8, MAX_RESPONSE>);

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
        // Values of 255 bytes and more use the extended TLV form (length
        // 0xff followed by a 16-bit length), as OT does.
        let ext = value.len() > 254;
        let need = if ext { 4 } else { 2 } + value.len();
        if self.buf.len() + need > MAX_RESPONSE {
            return false;
        }
        let _ = self.buf.push(ty);
        if ext {
            let _ = self.buf.push(0xff);
            let _ = self
                .buf
                .extend_from_slice(&(value.len() as u16).to_be_bytes());
        } else {
            let _ = self.buf.push(value.len() as u8);
        }
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

/// Index of a role in the per-role time array.
pub(crate) const fn role_index(r: rs_thread_mle::Role) -> usize {
    use rs_thread_mle::Role;
    match r {
        Role::Disabled => 0,
        Role::Detached => 1,
        Role::Child => 2,
        Role::Router => 3,
        Role::Leader => 4,
    }
}

/// The MLE counters (OT `otMleCounters`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MleCountersInfo {
    /// The event counters.
    pub counts: rs_thread_mle::MleCounters,
    /// Milliseconds in the Disabled role.
    pub disabled_ms: u64,
    /// Milliseconds in the Detached role.
    pub detached_ms: u64,
    /// Milliseconds in the Child role.
    pub child_ms: u64,
    /// Milliseconds in the Router role.
    pub router_ms: u64,
    /// Milliseconds in the Leader role.
    pub leader_ms: u64,
    /// Milliseconds tracked by the role times.
    pub tracked_ms: u64,
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
    /// Network Data version the child last received.
    pub network_data_version: u8,
    /// Seconds since a message was last heard from the child.
    pub age_secs: u32,
    /// Incoming link quality (0..=3).
    pub link_quality_in: u8,
    /// Supervision interval the child asked for, seconds (0 = none).
    pub supervision_interval: u16,
    /// CSL transmissions of the child are synchronized.
    pub csl_synchronized: bool,
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
    /// Extended address (all zero if unknown).
    pub ext: ExtAddress,
    /// Link quality of the incoming link (0..=3).
    pub link_quality_in: u8,
    /// Link quality of the outgoing link (0..=3).
    pub link_quality_out: u8,
    /// Seconds since the router was last heard.
    pub age_secs: u32,
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
        tlv::THREAD_STACK_VERSION => {
            out.put(
                ty,
                concat!("rs-thread/", env!("CARGO_PKG_VERSION")).as_bytes(),
            );
        }
        tlv::VERSION => {
            out.put(ty, &rs_thread_mle::consts::THREAD_VERSION.to_be_bytes());
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
    let mut v: Vec<u8, 256> = Vec::new();
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

impl<S: rs_thread_platform::SettingsStore, C: crate::InstanceCrypto, R> crate::Instance<S, C, R>
where
    C: rs_thread_core::crypto::ecdsa::EcdsaP256 + Clone,
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
        now: rs_thread_core::time::Instant,
    ) -> rs_thread_core::Result<()> {
        self.diag_request(
            rs_thread_coap::uri::Uri::DiagnosticGetRequest,
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
        now: rs_thread_core::time::Instant,
    ) -> rs_thread_core::Result<()> {
        self.diag_request(
            rs_thread_coap::uri::Uri::DiagnosticGetQuery,
            dst,
            types,
            now,
        )
    }

    fn diag_request(
        &mut self,
        uri: rs_thread_coap::uri::Uri,
        dst: core::net::Ipv6Addr,
        types: &[u8],
        now: rs_thread_core::time::Instant,
    ) -> rs_thread_core::Result<()> {
        let mut p: Vec<u8, 48> = Vec::new();
        let n = u8::try_from(types.len()).map_err(|_| rs_thread_core::Error::InvalidArgs)?;
        if n > 0 {
            let _ = p.push(tlv::TYPE_LIST);
            let _ = p.push(n);
            p.extend_from_slice(types)
                .map_err(|_| rs_thread_core::Error::InvalidArgs)?;
        }
        if uri == rs_thread_coap::uri::Uri::DiagnosticGetQuery {
            self.diag_query_id = self.diag_query_id.wrapping_add(1);
            let _ = p.push(tlv::QUERY_ID);
            let _ = p.push(2);
            let _ = p.extend_from_slice(&self.diag_query_id.to_be_bytes());
        }
        let own = self.mle.rloc16();
        let mlp = self.core.cfg.cur.mesh_local_prefix;
        self.core.now = now;
        let r = self.agent.post(
            now,
            &mut self.prng,
            &mut self.sink,
            dst,
            (own != Rloc16::INVALID).then(|| mlp.rloc(own)),
            rs_thread_core::message::Priority::Normal,
            uri,
            &p,
            (uri == rs_thread_coap::uri::Uri::DiagnosticGetRequest).then_some(USER_DIAG_GET),
        );
        self.poll(now);
        r
    }

    /// The oldest received diagnostic answer: the TLVs of a Diagnostic Get
    /// response or a Diagnostic Answer message (decode with `diag_tlv`).
    pub fn diag_take_answer(&mut self) -> Option<Vec<u8, MAX_RESPONSE>> {
        self.diag_in.pop_front().map(|(_, v)| v)
    }

    /// Like [`diag_take_answer`](Self::diag_take_answer) with the address of
    /// the sender.
    pub fn diag_take_answer_from(
        &mut self,
    ) -> Option<(core::net::Ipv6Addr, Vec<u8, MAX_RESPONSE>)> {
        self.diag_in.pop_front()
    }

    /// Reset diagnostic counters of `dst` with a Diagnostic Reset request (OT
    /// `otThreadSendDiagnosticReset`; MAC counters are supported).
    pub fn diag_reset(
        &mut self,
        dst: core::net::Ipv6Addr,
        types: &[u8],
        now: rs_thread_core::time::Instant,
    ) -> rs_thread_core::Result<()> {
        self.diag_request(rs_thread_coap::uri::Uri::DiagnosticReset, dst, types, now)
    }

    /// The MLE counters (OT `otThreadGetMleCounters`).
    pub fn mle_counters(&self) -> MleCountersInfo {
        let mut ms = self.glue.role_ms;
        let t = self.core.now.as_millis();
        ms[role_index(self.mle.role())] += t.saturating_sub(self.glue.role_time_mark);
        MleCountersInfo {
            counts: *self.mle.counters(),
            disabled_ms: ms[0],
            detached_ms: ms[1],
            child_ms: ms[2],
            router_ms: ms[3],
            leader_ms: ms[4],
            tracked_ms: ms.iter().sum(),
        }
    }

    /// Reset the MLE counters (OT `otThreadResetMleCounters`), including the
    /// role times.
    pub fn reset_mle_counters(&mut self) {
        self.mle.reset_counters();
        self.glue.role_ms = [0; 5];
        self.glue.role_time_mark = self.core.now.as_millis();
    }

    /// The MAC counters (OT `otLinkGetCounters`).
    pub fn mac_counters(&self) -> &MacCounters {
        self.core.mac.counters()
    }

    /// The neighbors: the parent, the routers and the children (OT
    /// `otThreadGetNextNeighborInfo`).
    pub fn neighbor_table(&self) -> Vec<NeighborInfo, 40> {
        let mut v = Vec::new();
        let info = |n: &rs_thread_mle::neighbor::Neighbor, is_child: bool| NeighborInfo {
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
                network_data_version: c.network_data_version,
                age_secs: self
                    .core
                    .now
                    .saturating_duration_since(c.neighbor.last_heard)
                    .as_secs() as u32,
                link_quality_in: c.neighbor.link_info.link_quality_in() as u8,
                supervision_interval: c.supervision_interval,
                csl_synchronized: c.csl_synchronized,
            });
        }
        v
    }

    /// The router table (OT `otThreadGetRouterInfo`).
    #[cfg(feature = "ftd")]
    pub fn route_table(&self) -> Vec<RouteInfo, 62> {
        let mut v = Vec::new();
        for r in self.mle.router_table().iter(StateFilter::Any) {
            let _ = v.push(RouteInfo {
                router_id: r.router_id,
                rloc16: Rloc16::from_router_id(r.router_id).unwrap_or(Rloc16::INVALID),
                next_hop: r.next_hop,
                cost: r.cost,
                is_neighbor: r.neighbor.is_valid(),
                ext: r.neighbor.ext_address,
                link_quality_in: r.neighbor.link_info.link_quality_in() as u8,
                link_quality_out: r.neighbor.link_info.link_quality_out() as u8,
                age_secs: self
                    .core
                    .now
                    .saturating_duration_since(r.neighbor.last_heard)
                    .as_secs() as u32,
            });
        }
        v
    }
}
