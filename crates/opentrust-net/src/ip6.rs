//! Sans-IO IPv6 processing core (OT `net/ip6.cpp`, `net/icmp6.cpp`).
//!
//! [`Ip6`] owns the interface address state ([`Netif`]) and the MPL state
//! ([`Mpl`]); everything else comes in through arguments:
//!
//! - time and randomness through [`Ctx`] (`now`, an `Rng`, and an
//!   [`Ip6Env`] that answers questions only other layers can: the device
//!   role, Network Data route lookups, sleepy children);
//! - datagrams as byte slices, both directions. No message pool is used;
//!   the datagram buffer is modified in place (hop limit) and scratch
//!   space for tunnelled datagrams and replies is the caller-provided
//!   [`Scratch`].
//!
//! # Receive path
//!
//! [`Ip6::handle`] takes a complete IPv6 datagram (from the 6LoWPAN
//! reassembler: `Origin::ThreadNetif`; or from a host / the local send
//! path) and returns an [`RxOutcome`]:
//!
//! 1. validate the header; for untrusted origins drop loopback addresses;
//! 2. decide *receive* / *forward to Thread* / *forward to host* from the
//!    destination (OT `DetermineAction`);
//! 3. walk the extension headers ([`crate::header::parse_datagram`]),
//!    process the MPL option (duplicate suppression, buffering);
//! 4. IPv6-in-IPv6 tunnel (used for MPL to scopes larger than realm-local):
//!    the inner datagram is processed as above;
//! 5. verify the UDP/ICMPv6 checksum and report a [`Delivery`]; answer
//!    ICMPv6 echo requests into the scratch reply buffer;
//! 6. for forwarding: decrement the hop limit (routers only, for datagrams
//!    from Thread), filter ICMPv6 types and untrusted-host TMF.
//!
//! # Send path
//!
//! [`Ip6::send`] builds `[IPv6 header | upper-layer payload]` (source
//! address selection, default hop limit, checksum), inserts the MPL option
//! for realm-local multicast or tunnels larger-scope multicast to
//! `ff03::fc`, then runs the datagram through [`Ip6::handle`] with origin
//! `HostTrusted` as OT does (`EnqueueDatagram`), so local delivery
//! (multicast loop, own address) and MPL buffering happen uniformly.
//!
//! # Timers
//!
//! [`Ip6::next_deadline`] / [`Ip6::poll`] drive MPL: poll returns buffered
//! datagrams to retransmit on the mesh.

use core::net::Ipv6Addr;

use opentrust_core::message::Origin;
use opentrust_core::time::{Duration, Instant};
use opentrust_core::types::{Rloc16, ipv6};
use opentrust_core::{Error, Result};
use rand_core::Rng;

use crate::addr;
use crate::checksum;
use crate::header::{
    self, DEFAULT_HOP_LIMIT, EXT_UNIT, Ipv6Header, MAX_DATAGRAM_LEN, OFFSET_HOP_LIMIT,
    PROTO_HOP_OPTS, PROTO_ICMP6, PROTO_IPV6, PROTO_NONE, PROTO_UDP, UdpHeader,
};
use crate::icmp6::{self, Icmp6Header, Icmp6Message};
use crate::mpl::{Mpl, MplRx, MplTx, Role};
use crate::netif::Netif;

/// UDP port of TMF (Thread Management Framework).
pub const TMF_UDP_PORT: u16 = 61631;

/// Questions the IPv6 layer asks of the rest of the stack.
pub trait Ip6Env {
    /// Current Thread role.
    fn role(&self) -> Role;
    /// Network Data route lookup (OT `NetworkData::Leader::RouteLookup`):
    /// the RLOC16 that serves `dst` for `src`, or `None` if there is no
    /// route in the mesh.
    fn route_lookup(&self, src: &Ipv6Addr, dst: &Ipv6Addr) -> Option<Rloc16>;
    /// `true` if `addr` matches an on-mesh prefix in Network Data.
    fn is_on_mesh(&self, addr: &Ipv6Addr) -> bool;
    /// `true` if a sleepy child subscribed to multicast address `addr`
    /// (FTD only).
    fn has_sleepy_child_with_address(&self, _addr: &Ipv6Addr) -> bool {
        false
    }
}

/// Time, randomness and environment for one call.
#[derive(Debug)]
pub struct Ctx<'a, R: ?Sized, E: ?Sized> {
    /// Current time.
    pub now: Instant,
    /// Random source (MPL jitter).
    pub rng: &'a mut R,
    /// Environment hooks.
    pub env: &'a E,
}

/// Which ICMPv6 echo requests are answered (OT `otIcmp6EchoMode`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum EchoMode {
    /// Never answer.
    Disabled,
    /// Only unicast requests.
    UnicastOnly,
    /// Only multicast requests.
    MulticastOnly,
    /// All requests (default).
    All,
    /// Only requests to RLOC/ALOC addresses.
    RlocAlocOnly,
}

/// Where a datagram entered the IPv6 layer and how it was protected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RxMeta {
    /// Origin of the datagram.
    pub origin: Origin,
    /// Whether the link layer security was applied (reported to the
    /// receiver in [`Delivery::link_security`]).
    pub link_security: bool,
    /// Multicast loopback allowed (locally originated multicast only).
    pub multicast_loop: bool,
}

impl RxMeta {
    /// A datagram received from the Thread network.
    pub const fn thread(link_security: bool) -> Self {
        Self {
            origin: Origin::ThreadNetif,
            link_security,
            multicast_loop: false,
        }
    }
}

/// Scratch space: the inner datagram of a tunnel and the reply datagram.
#[derive(Debug, Clone)]
pub struct Scratch {
    inner: [u8; MAX_DATAGRAM_LEN],
    reply: [u8; MAX_DATAGRAM_LEN],
}

impl Default for Scratch {
    fn default() -> Self {
        Self::new()
    }
}

impl Scratch {
    /// Zeroed scratch space.
    pub const fn new() -> Self {
        Self {
            inner: [0; MAX_DATAGRAM_LEN],
            reply: [0; MAX_DATAGRAM_LEN],
        }
    }

    /// The inner (tunnelled) datagram of the last [`Ip6::handle`] call
    /// (valid when [`Delivery::from_inner`] or [`RxOutcome::inner_forward_thread`]).
    pub fn inner(&self) -> &[u8] {
        &self.inner
    }
}

/// An upper-layer payload to hand to UDP / ICMPv6 handlers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Delivery {
    /// [`PROTO_UDP`] or [`PROTO_ICMP6`].
    pub proto: u8,
    /// IPv6 source.
    pub src: Ipv6Addr,
    /// IPv6 destination.
    pub dst: Ipv6Addr,
    /// Hop limit of the datagram.
    pub hop_limit: u8,
    /// ECN bits.
    pub ecn: u8,
    /// Link security flag from [`RxMeta`].
    pub link_security: bool,
    /// `true` if the payload lives in [`Scratch::inner`] instead of the
    /// datagram passed to [`Ip6::handle`].
    pub from_inner: bool,
    /// Offset of the upper-layer header in that buffer.
    pub offset: usize,
    /// Length of the upper-layer data (header + payload).
    pub len: usize,
}

impl Delivery {
    /// The upper-layer bytes (header + payload) within `datagram` / `scratch`.
    pub fn bytes<'a>(&self, datagram: &'a [u8], scratch: &'a Scratch) -> &'a [u8] {
        let buf = if self.from_inner {
            &scratch.inner[..]
        } else {
            datagram
        };
        &buf[self.offset..self.offset + self.len]
    }
}

/// Result of [`Ip6::handle`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RxOutcome {
    /// Datagram for a local UDP/ICMPv6 handler.
    pub deliver: Option<Delivery>,
    /// Forward the datagram (hop limit already decremented) on the Thread
    /// network via the mesh forwarder.
    pub forward_thread: bool,
    /// Pass the datagram to the host network stack.
    pub forward_host: bool,
    /// An inner (tunnelled) datagram in [`Scratch::inner`] must be forwarded
    /// on the Thread network (sleepy children).
    pub inner_forward_thread: bool,
    /// Length of a reply datagram (ICMPv6 echo reply) in
    /// [`Scratch::reply`]; transmit it on the Thread network.
    pub reply_len: Option<usize>,
}

impl RxOutcome {
    /// The reply datagram, if any.
    pub fn reply<'a>(&self, scratch: &'a Scratch) -> Option<&'a [u8]> {
        self.reply_len.map(|n| &scratch.reply[..n])
    }
}

/// Parameters for [`Ip6::send`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SendInfo {
    /// Source address; `None`, unspecified or multicast selects one.
    pub src: Option<Ipv6Addr>,
    /// Destination address.
    pub dst: Ipv6Addr,
    /// Hop limit; 0 means [`DEFAULT_HOP_LIMIT`].
    pub hop_limit: u8,
    /// DSCP (6 bits).
    pub dscp: u8,
    /// ECN (2 bits).
    pub ecn: u8,
    /// Deliver multicast to local sockets too.
    pub multicast_loop: bool,
    /// Link security for the datagram.
    pub link_security: bool,
}

impl SendInfo {
    /// Defaults: auto source, default hop limit, DSCP/ECN 0, no loopback,
    /// link security on.
    pub const fn new(dst: Ipv6Addr) -> Self {
        Self {
            src: None,
            dst,
            hop_limit: 0,
            dscp: 0,
            ecn: 0,
            multicast_loop: false,
            link_security: true,
        }
    }
}

/// Result of [`Ip6::send`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SendOutcome {
    /// Length of the datagram written to the output buffer (what must be
    /// transmitted if `rx.forward_thread`).
    pub len: usize,
    /// Local processing result (loopback delivery, forwarding decision).
    pub rx: RxOutcome,
}

/// Token-bucket limiter for ICMPv6 errors (RFC 4443 section 2.4(f)).
#[derive(Debug, Clone, Copy)]
struct ErrorLimiter {
    tokens: u8,
    last: Instant,
}

/// ICMPv6 error burst size.
pub const ERROR_BURST: u8 = 10;
/// One error token is replenished per this interval.
pub const ERROR_REFILL: Duration = Duration::from_millis(100);

impl ErrorLimiter {
    const fn new() -> Self {
        Self {
            tokens: ERROR_BURST,
            last: Instant::ZERO,
        }
    }

    fn allow(&mut self, now: Instant) -> bool {
        let elapsed =
            now.saturating_duration_since(self.last).as_micros() / ERROR_REFILL.as_micros();
        if elapsed > 0 {
            let add = elapsed.min(u64::from(ERROR_BURST)) as u8;
            self.tokens = self.tokens.saturating_add(add).min(ERROR_BURST);
            self.last = self
                .last
                .saturating_add(Duration::from_micros(elapsed * ERROR_REFILL.as_micros()));
        }
        if self.tokens > 0 {
            self.tokens -= 1;
            true
        } else {
            false
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
struct Action {
    forward_thread: bool,
    forward_host: bool,
    receive: bool,
}

/// The IPv6 layer state. See the [module docs](self).
#[derive(Debug, Clone)]
pub struct Ip6<
    const U: usize = 8,
    const M: usize = 8,
    const SEEDS: usize = 35,
    const BUFS: usize = 4,
> {
    /// Interface addresses and subscriptions.
    pub netif: Netif<U, M>,
    /// MPL state.
    pub mpl: Mpl<SEEDS, BUFS>,
    /// Which echo requests are answered.
    pub echo_mode: EchoMode,
    limiter: ErrorLimiter,
}

impl<const U: usize, const M: usize, const SEEDS: usize, const BUFS: usize> Default
    for Ip6<U, M, SEEDS, BUFS>
{
    fn default() -> Self {
        Self::new()
    }
}

impl<const U: usize, const M: usize, const SEEDS: usize, const BUFS: usize> Ip6<U, M, SEEDS, BUFS> {
    /// New state with no addresses.
    pub const fn new() -> Self {
        Self {
            netif: Netif::new(),
            mpl: Mpl::new(),
            echo_mode: EchoMode::All,
            limiter: ErrorLimiter::new(),
        }
    }

    fn own_rloc16(&self) -> Option<Rloc16> {
        self.netif
            .rloc()
            .and_then(|a| ipv6::iid(&a).locator())
            .map(Rloc16)
    }

    fn has_rloc16(&self, r: Rloc16) -> bool {
        self.own_rloc16() == Some(r)
    }

    /// OT `Ip6::DetermineAction`.
    fn determine_action<E: Ip6Env + ?Sized>(
        &self,
        env: &E,
        meta: &RxMeta,
        h: &Ipv6Header,
    ) -> Action {
        let mut a = Action::default();
        let from_thread = meta.origin == Origin::ThreadNetif;
        if h.dst.is_multicast() {
            a.forward_thread = !from_thread;
            if from_thread
                && addr::is_multicast_larger_than_realm_local(&h.dst)
                && env.has_sleepy_child_with_address(&h.dst)
            {
                a.forward_thread = true;
            }
            a.forward_host = true;
            if (from_thread || meta.multicast_loop) && self.netif.is_multicast_subscribed(&h.dst) {
                a.receive = true;
            }
            return a;
        }
        if self.netif.has_unicast(&h.dst) {
            a.receive = true;
            return a;
        }
        if h.dst.is_unicast_link_local() {
            a.forward_thread = !from_thread;
            return a;
        }
        if env.is_on_mesh(&h.dst) || self.netif.is_on_link(&h.dst) {
            a.forward_thread = true;
            return a;
        }
        match env.route_lookup(&h.src, &h.dst) {
            None => a.forward_host = true,
            Some(r) if self.has_rloc16(r) => a.forward_host = true,
            Some(_) => a.forward_thread = true,
        }
        a
    }

    fn should_answer_echo(&self, dst: &Ipv6Addr) -> bool {
        match self.echo_mode {
            EchoMode::Disabled => false,
            EchoMode::UnicastOnly => !dst.is_multicast(),
            EchoMode::MulticastOnly => dst.is_multicast(),
            EchoMode::All => true,
            EchoMode::RlocAlocOnly => ipv6::iid(dst).is_locator(),
        }
    }

    /// Process a complete IPv6 datagram (see the [module docs](self)).
    ///
    /// `datagram` must be exactly the datagram (trailing bytes beyond the
    /// header's payload length are ignored). Errors: [`Error::Parse`]
    /// (malformed), [`Error::Drop`] (dropped by policy, duplicate, bad
    /// checksum, hop limit exhausted, ...).
    pub fn handle<R: Rng + ?Sized, E: Ip6Env + ?Sized>(
        &mut self,
        ctx: &mut Ctx<'_, R, E>,
        meta: RxMeta,
        datagram: &mut [u8],
        scratch: &mut Scratch,
    ) -> Result<RxOutcome> {
        self.handle_at(
            ctx,
            meta,
            datagram,
            &mut scratch.inner,
            &mut scratch.reply,
            0,
        )
    }

    fn handle_at<R: Rng + ?Sized, E: Ip6Env + ?Sized>(
        &mut self,
        ctx: &mut Ctx<'_, R, E>,
        meta: RxMeta,
        datagram: &mut [u8],
        inner: &mut [u8],
        reply: &mut [u8],
        depth: u8,
    ) -> Result<RxOutcome> {
        let p = header::parse_datagram(datagram)?;
        let h = p.header;
        let datagram = &mut datagram[..p.total_len];
        if meta.origin != Origin::HostTrusted && (h.src.is_loopback() || h.dst.is_loopback()) {
            return Err(Error::Drop);
        }
        let act = self.determine_action(ctx.env, &meta, &h);
        let mut out = RxOutcome {
            forward_thread: act.forward_thread,
            forward_host: act.forward_host,
            ..RxOutcome::default()
        };
        let mut receive = act.receive;

        if p.routing && receive {
            return Err(Error::Drop);
        }
        if p.fragment.is_some_and(|f| !f.is_atomic()) {
            // No IPv6 reassembly: fragments are dropped as in OT without
            // IP6_FRAGMENTATION_ENABLE.
            return Err(Error::Drop);
        }
        if let Some(opt) = p.mpl {
            let role = ctx.env.role();
            let rx = MplRx {
                origin: meta.origin,
                src: &h.src,
                opt: &opt,
                datagram,
            };
            if !self.mpl.process_option(ctx.now, ctx.rng, role, &rx)? {
                receive = false;
            }
        }
        if p.upper_proto == PROTO_NONE {
            return Err(Error::Drop);
        }

        if receive && p.upper_proto == PROTO_IPV6 {
            // Tunnelled datagram (MPL to larger-than-realm-local scope).
            if depth > 0 {
                return Err(Error::Drop);
            }
            let inner_src = &datagram[p.upper_offset..];
            let n = inner_src.len();
            inner[..n].copy_from_slice(inner_src);
            // Process the inner datagram with the same meta; a nested
            // tunnel is dropped (depth 1 has no inner buffer).
            if let Ok(i) = self.handle_at(ctx, meta, &mut inner[..n], &mut [], reply, depth + 1) {
                out.deliver = i.deliver.map(|d| Delivery {
                    from_inner: true,
                    ..d
                });
                out.inner_forward_thread = i.forward_thread;
                out.reply_len = i.reply_len;
            }
            receive = false;
            out.forward_host = false;
        }

        if receive {
            match p.upper_proto {
                PROTO_UDP | PROTO_ICMP6 => {
                    let upper = &datagram[p.upper_offset..];
                    // Errors here drop only the local delivery (OT logs and goes on).
                    if Self::validate_upper(p.upper_proto, &h, upper).is_ok() {
                        out.deliver = Some(Delivery {
                            proto: p.upper_proto,
                            src: h.src,
                            dst: h.dst,
                            hop_limit: h.hop_limit,
                            ecn: h.ecn(),
                            link_security: meta.link_security,
                            from_inner: false,
                            offset: p.upper_offset,
                            len: upper.len(),
                        });
                        if p.upper_proto == PROTO_ICMP6 {
                            out.reply_len = self.answer_echo(&h, upper, reply);
                        }
                    }
                }
                _ => {}
            }
        }

        if out.forward_thread {
            if meta.origin == Origin::ThreadNetif {
                if !ctx.env.role().is_router_or_leader() {
                    out.forward_thread = false;
                    return Ok(out);
                }
                datagram[OFFSET_HOP_LIMIT] = h.hop_limit.saturating_sub(1);
            }
            if datagram[OFFSET_HOP_LIMIT] == 0 {
                out.forward_thread = false;
                return if out.deliver.is_some() || out.forward_host {
                    Ok(out)
                } else {
                    Err(Error::Drop)
                };
            }
            if p.upper_proto == PROTO_ICMP6 {
                let ty = *datagram.get(p.upper_offset).ok_or(Error::Parse)?;
                if !icmp6::FORWARDED_TYPES.contains(&ty) {
                    out.forward_thread = false;
                    return if out.deliver.is_some() || out.forward_host {
                        Ok(out)
                    } else {
                        Err(Error::Drop)
                    };
                }
            }
            if meta.origin == Origin::HostUntrusted && p.upper_proto == PROTO_UDP {
                let u = UdpHeader::parse(&datagram[p.upper_offset..])?;
                if u.dst_port == TMF_UDP_PORT {
                    return Err(Error::Drop);
                }
            }
        }
        Ok(out)
    }

    fn validate_upper(proto: u8, h: &Ipv6Header, upper: &[u8]) -> Result<()> {
        match proto {
            PROTO_UDP => {
                let u = UdpHeader::parse(upper)?;
                if usize::from(u.length) != upper.len() || u.checksum == 0 {
                    return Err(Error::Drop);
                }
            }
            PROTO_ICMP6 => {
                Icmp6Header::parse(upper)?;
            }
            _ => return Ok(()),
        }
        if checksum::verify(&h.src, &h.dst, proto, upper) {
            Ok(())
        } else {
            Err(Error::Drop)
        }
    }

    /// OT `Icmp::HandleEchoRequest`: build the reply if configured to.
    fn answer_echo(&self, h: &Ipv6Header, upper: &[u8], reply: &mut [u8]) -> Option<usize> {
        let ih = Icmp6Header::parse(upper).ok()?;
        if ih.ty != icmp6::TYPE_ECHO_REQUEST
            || !self.should_answer_echo(&h.dst)
            || h.src.is_multicast()
            || h.src.is_unspecified()
        {
            return None;
        }
        let src = if h.dst.is_multicast() {
            self.netif.select_source(&h.src)?
        } else {
            h.dst
        };
        let msg = Icmp6Message {
            ty: icmp6::TYPE_ECHO_REPLY,
            code: 0,
            data: ih.data,
            body: &upper[Icmp6Header::LEN..],
        };
        icmp6::build_datagram(&src, &h.src, DEFAULT_HOP_LIMIT, &msg, reply).ok()
    }

    /// Build an ICMPv6 error datagram about `invoking` into `out`
    /// (OT `Icmp::SendError` semantics, plus RFC 4443 section 2.4 rules):
    ///
    /// - never in response to an ICMPv6 error, nor to a datagram with an
    ///   unspecified or multicast source;
    /// - not for multicast destinations except Packet Too Big and
    ///   Parameter Problem code 2;
    /// - rate limited ([`ERROR_BURST`] errors, one more per [`ERROR_REFILL`]);
    /// - like OpenThread, only the offending IPv6 header is quoted.
    ///
    /// Returns the error datagram length; [`Error::Drop`] if suppressed.
    pub fn build_error(
        &mut self,
        now: Instant,
        invoking: &[u8],
        kind: (u8, u8, u32),
        out: &mut [u8],
    ) -> Result<usize> {
        let (ty, code, data) = kind;
        let p = header::parse_datagram(invoking).or_else(|_| {
            Ipv6Header::parse(invoking).map(|h| header::ParsedDatagram {
                header: h,
                upper_proto: h.next_header,
                upper_offset: Ipv6Header::LEN,
                total_len: invoking.len().max(Ipv6Header::LEN),
                mpl: None,
                fragment: None,
                routing: false,
            })
        })?;
        let h = p.header;
        if h.src.is_unspecified() || h.src.is_multicast() {
            return Err(Error::Drop);
        }
        if p.upper_proto == PROTO_ICMP6
            && let Some(&t) = invoking.get(p.upper_offset)
            && icmp6::is_error(t)
        {
            return Err(Error::Drop);
        }
        let always = ty == icmp6::TYPE_PACKET_TOO_BIG
            || (ty == icmp6::TYPE_PARAMETER_PROBLEM && code == icmp6::CODE_PARAM_OPTION);
        if h.dst.is_multicast() && !always {
            return Err(Error::Drop);
        }
        let src = if h.dst.is_multicast() || !self.netif.has_unicast(&h.dst) {
            self.netif.select_source(&h.src).ok_or(Error::NotFound)?
        } else {
            h.dst
        };
        if !self.limiter.allow(now) {
            return Err(Error::Drop);
        }
        let quoted = &invoking[..Ipv6Header::LEN.min(invoking.len())];
        icmp6::build_error(
            &src,
            &h.src,
            DEFAULT_HOP_LIMIT,
            (ty, code, data),
            quoted,
            out,
        )
    }

    /// Build and process an outgoing datagram (see the [module docs](self)).
    /// `payload` is the upper-layer header and data with a zero (or any)
    /// checksum field for UDP/ICMPv6; the checksum is filled in. The
    /// complete datagram is written to `out`.
    pub fn send<R: Rng + ?Sized, E: Ip6Env + ?Sized>(
        &mut self,
        ctx: &mut Ctx<'_, R, E>,
        info: &SendInfo,
        proto: u8,
        payload: &[u8],
        out: &mut [u8],
        scratch: &mut Scratch,
    ) -> Result<SendOutcome> {
        let total = Ipv6Header::LEN + payload.len();
        if total > MAX_DATAGRAM_LEN || out.len() < MAX_DATAGRAM_LEN {
            return Err(Error::NoBufs);
        }
        let src = match info.src {
            Some(s) if !s.is_unspecified() && !s.is_multicast() => s,
            _ => self
                .netif
                .select_source(&info.dst)
                .ok_or(Error::InvalidState)?,
        };
        let mut h = Ipv6Header::new(
            proto,
            if info.hop_limit == 0 {
                DEFAULT_HOP_LIMIT
            } else {
                info.hop_limit
            },
            src,
            info.dst,
        );
        h.set_dscp(info.dscp);
        h.set_ecn(info.ecn);
        h.payload_len = payload.len() as u16;
        h.write(out)?;
        out[Ipv6Header::LEN..total].copy_from_slice(payload);
        if matches!(proto, PROTO_UDP | PROTO_ICMP6) {
            checksum::update(&src, &info.dst, proto, &mut out[Ipv6Header::LEN..total])?;
        }
        let len = self.insert_mpl_option(out, total)?;
        let meta = RxMeta {
            origin: Origin::HostTrusted,
            link_security: info.link_security,
            multicast_loop: info.multicast_loop,
        };
        let rx = self.handle(ctx, meta, &mut out[..len], scratch)?;
        Ok(SendOutcome { len, rx })
    }

    /// MPL option insertion for multicast datagrams originating on this
    /// device or coming from the host (OT `Ip6::InsertMplOption`):
    /// realm-local multicast gets a Hop-by-Hop MPL option (merged into an
    /// existing Hop-by-Hop header), scopes larger than realm-local are
    /// tunnelled to `ff03::fc` with the option on the outer header.
    /// Other destinations are left untouched. `buf` holds a datagram of
    /// `len` bytes (and must have `MAX_DATAGRAM_LEN` capacity); returns the
    /// new length.
    pub fn insert_mpl_option(&mut self, buf: &mut [u8], len: usize) -> Result<usize> {
        let h = Ipv6Header::parse(&buf[..len.min(buf.len())])?;
        if addr::is_multicast_larger_than_realm_local(&h.dst) {
            return self.tunnel_to_mpl_forwarders(buf, len);
        }
        if !addr::is_realm_local_multicast(&h.dst) {
            return Ok(len);
        }
        let own_rloc = self.netif.rloc().ok_or(Error::InvalidState)?;
        let rloc16 = self.own_rloc16().ok_or(Error::InvalidState)?;
        let mpl = self.mpl.init_option(&h.src, &own_rloc, rloc16);
        let mut hbh_opts = [0u8; 8];
        let n = mpl.write(&mut hbh_opts)?;
        let pad = header::write_padding(n, &mut hbh_opts[n..])?;
        let opt_len = n + pad;
        if h.next_header == PROTO_HOP_OPTS {
            // Append the option (padded to 8 bytes) to the existing header.
            let hbh_size =
                (usize::from(*buf.get(Ipv6Header::LEN + 1).ok_or(Error::Parse)?) + 1) * EXT_UNIT;
            if hbh_size > usize::from(h.payload_len) || len + EXT_UNIT > MAX_DATAGRAM_LEN {
                return Err(Error::Parse);
            }
            let at = Ipv6Header::LEN + hbh_size;
            buf.copy_within(at..len, at + EXT_UNIT);
            buf[at..at + opt_len].copy_from_slice(&hbh_opts[..opt_len]);
            if opt_len < EXT_UNIT {
                buf[at + opt_len..at + EXT_UNIT].fill(0);
            }
            buf[Ipv6Header::LEN + 1] += 1;
            let pl = h.payload_len + EXT_UNIT as u16;
            buf[header::OFFSET_PAYLOAD_LEN..header::OFFSET_PAYLOAD_LEN + 2]
                .copy_from_slice(&pl.to_be_bytes());
            Ok(len + EXT_UNIT)
        } else {
            let mut hbh = [0u8; 8];
            let n = header::write_hbh_mpl(h.next_header, &mpl, &mut hbh)?;
            if len + n > MAX_DATAGRAM_LEN {
                return Err(Error::NoBufs);
            }
            buf.copy_within(Ipv6Header::LEN..len, Ipv6Header::LEN + n);
            buf[Ipv6Header::LEN..Ipv6Header::LEN + n].copy_from_slice(&hbh[..n]);
            buf[header::OFFSET_NEXT_HEADER] = PROTO_HOP_OPTS;
            let pl = h.payload_len + n as u16;
            buf[header::OFFSET_PAYLOAD_LEN..header::OFFSET_PAYLOAD_LEN + 2]
                .copy_from_slice(&pl.to_be_bytes());
            Ok(len + n)
        }
    }

    /// OT `PrepareMulticastToLargerThanRealmLocal`: IP-in-IP (RFC 2473) to
    /// the realm-local all-MPL-forwarders address with an MPL option.
    fn tunnel_to_mpl_forwarders(&mut self, buf: &mut [u8], len: usize) -> Result<usize> {
        let dst = ipv6::REALM_LOCAL_ALL_MPL_FORWARDERS;
        let src = self.netif.select_source(&dst).ok_or(Error::InvalidState)?;
        let own_rloc = self.netif.rloc().ok_or(Error::InvalidState)?;
        let rloc16 = self.own_rloc16().ok_or(Error::InvalidState)?;
        let mpl = self.mpl.init_option(&src, &own_rloc, rloc16);
        let mut hbh = [0u8; 8];
        let n = header::write_hbh_mpl(PROTO_IPV6, &mpl, &mut hbh)?;
        let shift = Ipv6Header::LEN + n;
        if len + shift > MAX_DATAGRAM_LEN {
            return Err(Error::NoBufs);
        }
        buf.copy_within(..len, shift);
        let mut outer = Ipv6Header::new(PROTO_HOP_OPTS, DEFAULT_HOP_LIMIT, src, dst);
        outer.payload_len = (n + len) as u16;
        outer.write(buf)?;
        buf[Ipv6Header::LEN..shift].copy_from_slice(&hbh[..n]);
        Ok(len + shift)
    }

    /// Earliest deadline of the MPL timers.
    pub fn next_deadline(&self) -> Option<Instant> {
        self.mpl.next_deadline()
    }

    /// Run MPL timers; returns the next buffered datagram to transmit on
    /// the Thread network (call until `None`). The datagram is already
    /// processed (no local delivery): hand it to the mesh forwarder.
    pub fn poll<R: Rng + ?Sized, E: Ip6Env + ?Sized>(
        &mut self,
        ctx: &mut Ctx<'_, R, E>,
        out: &mut [u8],
    ) -> Option<MplTx> {
        self.mpl.poll(ctx.now, ctx.rng, ctx.env.role(), out)
    }
}

#[cfg(test)]
mod tests;
