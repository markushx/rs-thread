//! LOWPAN_IPHC / LOWPAN_NHC header compression (RFC 6282).
//!
//! Mirrors OpenThread's `Lowpan::Compress` / `Lowpan::Decompress`:
//!
//! - traffic class / flow label, hop limit (1, 64, 255 or inline),
//! - stateless link-local addresses with IIDs derived from the MAC address
//!   (extended: EUI-64 with the U/L bit flipped; short: `0000:00ff:fe00:XXXX`),
//! - stateful context-based addresses (context IDs 0-15, supplied by a
//!   [`ContextProvider`]; Network Data will implement it later, context 0 is
//!   the mesh-local prefix),
//! - multicast: 8/32/48-bit forms and the stateful form using context 0,
//! - NHC for UDP (port compression, checksum always inline as Thread
//!   requires), Hop-by-Hop Options (MPL option) incl. trailing Pad1/PadN
//!   elision, and IP-in-IP.
//!
//! The functions work on plain byte slices: an uncompressed IPv6 datagram on
//! the compression side, a MAC payload on the decompression side.

use core::net::Ipv6Addr;

use opentrust_core::bytes::Reader;
use opentrust_core::types::Iid;
use opentrust_core::{Error, Result};
use opentrust_mac::frame::Address;

use crate::ip6::{
    ECN_MARKED, Ipv6Header, PROTO_DST_OPTS, PROTO_FRAGMENT, PROTO_HOP_OPTS, PROTO_IPV6,
    PROTO_ROUTING, PROTO_UDP, UdpHeader,
};

// IPHC base encoding bits (first two bytes, big-endian).
const HC_DISPATCH: u16 = 0x6000;
const HC_DISPATCH_MASK: u16 = 0xe000;
const HC_TC: u16 = 1 << 11;
const HC_FL: u16 = 2 << 11;
const HC_TF_MASK: u16 = 3 << 11;
const HC_NH: u16 = 1 << 10;
const HC_HLIM_MASK: u16 = 3 << 8;
const HC_HLIM_1: u16 = 1 << 8;
const HC_HLIM_64: u16 = 2 << 8;
const HC_HLIM_255: u16 = 3 << 8;
const HC_CID: u16 = 1 << 7;
const HC_SAC: u16 = 1 << 6;
const HC_SAM_SHIFT: u32 = 4;
const HC_M: u16 = 1 << 3;
const HC_DAC: u16 = 1 << 2;
const HC_DAM_MASK: u16 = 3;

// NHC encodings.
const NHC_EXT_DISPATCH: u8 = 0xe0;
const NHC_EXT_MASK: u8 = 0xf0;
const NHC_EID_HBH: u8 = 0x00;
const NHC_EID_ROUTING: u8 = 0x02;
const NHC_EID_FRAGMENT: u8 = 0x04;
const NHC_EID_DST: u8 = 0x06;
const NHC_EID_IPV6: u8 = 0x0e;
const NHC_EID_MASK: u8 = 0x0e;
const NHC_EXT_NH: u8 = 0x01;
const NHC_EXT_MAX_LEN: usize = 255;
const NHC_UDP_DISPATCH: u8 = 0xf0;
const NHC_UDP_MASK: u8 = 0xf8;
const NHC_UDP_CHECKSUM: u8 = 1 << 2;
const NHC_UDP_PORT_MASK: u8 = 3;

/// A 6LoWPAN context (RFC 6282 §3.1.2), i.e. an address prefix of up to 128
/// bits identified by a 4-bit context ID.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Context {
    /// Context ID (0-15).
    pub id: u8,
    /// Prefix bytes (bits beyond `prefix_len` must be zero).
    pub prefix: [u8; 16],
    /// Prefix length in bits (0-128).
    pub prefix_len: u8,
    /// Whether this context may be used to *compress* addresses (the `C`
    /// flag of the Network Data 6LoWPAN Context ID TLV). Contexts without
    /// the flag are still honoured when *decompressing*.
    pub compress: bool,
}

impl Context {
    /// A 64-bit-prefix context.
    pub const fn new64(id: u8, prefix: [u8; 8], compress: bool) -> Self {
        let mut p = [0u8; 16];
        let mut i = 0;
        while i < 8 {
            p[i] = prefix[i];
            i += 1;
        }
        Self {
            id,
            prefix: p,
            prefix_len: 64,
            compress,
        }
    }

    fn matches(&self, addr: &[u8; 16]) -> bool {
        let n = usize::from(self.prefix_len).min(128);
        let full = n / 8;
        if self.prefix[..full] != addr[..full] {
            return false;
        }
        let rem = n % 8;
        if rem == 0 {
            return true;
        }
        let mask = 0xffu8 << (8 - rem);
        (self.prefix[full] ^ addr[full]) & mask == 0
    }
}

/// Source of 6LoWPAN contexts (provided by Network Data).
pub trait ContextProvider {
    /// The context with the given ID (0-15), if known. Used when
    /// decompressing; the `compress` flag is ignored there.
    fn by_id(&self, id: u8) -> Option<Context>;

    /// The best (longest) context matching `addr`, if any. The compressor
    /// only uses it if its `compress` flag is set.
    fn for_address(&self, addr: &Ipv6Addr) -> Option<Context>;
}

/// A provider without any contexts (stateless compression only).
#[derive(Debug, Clone, Copy, Default)]
pub struct NoContexts;

impl ContextProvider for NoContexts {
    fn by_id(&self, _id: u8) -> Option<Context> {
        None
    }
    fn for_address(&self, _addr: &Ipv6Addr) -> Option<Context> {
        None
    }
}

/// A fixed table of the 16 possible contexts; a simple [`ContextProvider`].
#[derive(Debug, Clone, Copy, Default)]
pub struct ContextTable {
    entries: [Option<Context>; 16],
}

impl ContextTable {
    /// An empty table.
    pub const fn new() -> Self {
        Self {
            entries: [None; 16],
        }
    }

    /// Set (or replace) a context; its `id` selects the slot.
    pub fn set(&mut self, ctx: Context) -> Result<()> {
        let slot = self
            .entries
            .get_mut(usize::from(ctx.id))
            .ok_or(Error::InvalidArgs)?;
        if ctx.prefix_len > 128 {
            return Err(Error::InvalidArgs);
        }
        *slot = Some(ctx);
        Ok(())
    }

    /// Remove the context with the given ID.
    pub fn remove(&mut self, id: u8) {
        if let Some(e) = self.entries.get_mut(usize::from(id)) {
            *e = None;
        }
    }

    /// Set context 0 to the mesh-local prefix (compressible).
    pub fn set_mesh_local(&mut self, prefix: &opentrust_core::types::Prefix64) {
        let _ = self.set(Context::new64(0, prefix.0, true));
    }
}

impl ContextProvider for ContextTable {
    fn by_id(&self, id: u8) -> Option<Context> {
        self.entries.get(usize::from(id)).copied().flatten()
    }

    fn for_address(&self, addr: &Ipv6Addr) -> Option<Context> {
        let a = addr.octets();
        self.entries
            .iter()
            .flatten()
            .filter(|c| c.matches(&a))
            .max_by_key(|c| c.prefix_len)
            .copied()
    }
}

/// Result of [`compress`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Compressed {
    /// Number of compressed header bytes written to the output buffer.
    pub header_len: usize,
    /// Number of bytes of the uncompressed datagram those headers replace;
    /// the remaining datagram bytes are carried as-is after the header.
    pub consumed: usize,
}

/// Result of [`decompress`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Decompressed {
    /// Number of frame bytes consumed (the compressed headers).
    pub consumed: usize,
    /// Number of uncompressed header bytes written to the output buffer.
    pub written: usize,
}

struct Out<'a> {
    buf: &'a mut [u8],
    len: usize,
}

impl<'a> Out<'a> {
    fn new(buf: &'a mut [u8]) -> Self {
        Self { buf, len: 0 }
    }
    fn put(&mut self, s: &[u8]) -> Result<()> {
        let end = self.len.checked_add(s.len()).ok_or(Error::NoBufs)?;
        self.buf
            .get_mut(self.len..end)
            .ok_or(Error::NoBufs)?
            .copy_from_slice(s);
        self.len = end;
        Ok(())
    }
    fn push(&mut self, b: u8) -> Result<()> {
        self.put(&[b])
    }
}

/// Copy the first `bits` bits of `src` into `dst`.
fn copy_bits(dst: &mut [u8], src: &[u8], bits: usize) {
    let full = bits / 8;
    dst[..full].copy_from_slice(&src[..full]);
    let rem = bits % 8;
    if rem != 0 {
        let mask = 0xffu8 << (8 - rem);
        dst[full] = (dst[full] & !mask) | (src[full] & mask);
    }
}

/// IID derived from a MAC address (with the context's bits beyond /64
/// applied), as used by SAM/DAM mode 3.
fn compute_iid(mac: &Address, ctx: Option<&Context>) -> Option<[u8; 8]> {
    let mut iid = match mac {
        Address::Short(s) => Iid::from_locator(s.0).0,
        Address::Extended(e) => e.to_iid().0,
        Address::None => return None,
    };
    if let Some(c) = ctx.filter(|c| c.prefix_len > 64) {
        copy_bits(&mut iid, &c.prefix[8..], usize::from(c.prefix_len) - 64);
    }
    Some(iid)
}

fn is_link_local_64(a: &Ipv6Addr) -> bool {
    let o = a.octets();
    o[0] == 0xfe && o[1] == 0x80 && o[2..8] == [0; 6]
}

// ---------------------------------------------------------------------------
// Compression
// ---------------------------------------------------------------------------

/// Compress the headers at the start of an uncompressed IPv6 `datagram`.
///
/// The compressed headers are written to `out`; its length is the space the
/// caller allows for them (for a first fragment, reserve room for the
/// fragment header beforehand). If the full compression does not fit, fewer
/// headers are compressed (like OpenThread's header-depth retry).
///
/// `mac_src` / `mac_dst` are the link addresses the frame is sent with (for a
/// mesh-header frame, the mesh originator and final destination as short
/// addresses); they allow eliding IIDs derived from them.
pub fn compress<C: ContextProvider + ?Sized>(
    ctxs: &C,
    mac_src: &Address,
    mac_dst: &Address,
    datagram: &[u8],
    out: &mut [u8],
) -> Result<Compressed> {
    let mut max_depth = u8::MAX;
    loop {
        let mut enc = Out::new(&mut *out);
        let mut depth = 0u8;
        match compress_at(
            ctxs, mac_src, mac_dst, datagram, 0, &mut enc, max_depth, &mut depth,
        ) {
            Ok(end) => {
                return Ok(Compressed {
                    header_len: enc.len,
                    consumed: end,
                });
            }
            Err(e) => {
                if depth == 0 || depth >= max_depth {
                    return Err(e);
                }
                max_depth = depth;
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn compress_at<C: ContextProvider + ?Sized>(
    ctxs: &C,
    mac_src: &Address,
    mac_dst: &Address,
    data: &[u8],
    start: usize,
    enc: &mut Out<'_>,
    max_depth: u8,
    depth: &mut u8,
) -> Result<usize> {
    let hdr = Ipv6Header::parse(data.get(start..).ok_or(Error::Parse)?)?;
    let src_ctx = ctxs.for_address(&hdr.src).filter(|c| c.compress);
    let dst_ctx = ctxs.for_address(&hdr.dst).filter(|c| c.compress);

    let hc_pos = enc.len;
    enc.put(&[0, 0])?;
    let mut hc = HC_DISPATCH;

    let sid = src_ctx.map_or(0, |c| c.id & 0x0f);
    let did = dst_ctx.map_or(0, |c| c.id & 0x0f);
    if sid != 0 || did != 0 {
        hc |= HC_CID;
        enc.push((sid << 4) | did)?;
    }

    // Traffic class and flow label.
    let dscp = hdr.dscp();
    let ecn = hdr.ecn() << 6;
    let fl = hdr.flow_label;
    if fl == 0 {
        if dscp == 0 && ecn == 0 {
            hc |= HC_TC | HC_FL;
        } else {
            hc |= HC_FL;
            enc.push(ecn | dscp)?;
        }
    } else if dscp == 0 {
        hc |= HC_TC;
        enc.push(ecn | ((fl >> 16) as u8 & 0x0f))?;
        enc.put(&[(fl >> 8) as u8, fl as u8])?;
    } else {
        enc.push(ecn | dscp)?;
        enc.push((fl >> 16) as u8 & 0x0f)?;
        enc.put(&[(fl >> 8) as u8, fl as u8])?;
    }

    // Next header.
    match hdr.next_header {
        PROTO_HOP_OPTS | PROTO_UDP | PROTO_IPV6 if *depth + 1 < max_depth => hc |= HC_NH,
        nh => enc.push(nh)?,
    }

    // Hop limit.
    match hdr.hop_limit {
        1 => hc |= HC_HLIM_1,
        64 => hc |= HC_HLIM_64,
        255 => hc |= HC_HLIM_255,
        h => enc.push(h)?,
    }

    // Source address.
    if hdr.src.is_unspecified() {
        hc |= HC_SAC;
    } else if is_link_local_64(&hdr.src) {
        hc |= compress_iid(mac_src, &hdr.src, None, enc)? << HC_SAM_SHIFT;
    } else if let Some(c) = &src_ctx {
        hc |= HC_SAC;
        hc |= compress_iid(mac_src, &hdr.src, Some(c), enc)? << HC_SAM_SHIFT;
    } else {
        enc.put(&hdr.src.octets())?;
    }

    // Destination address.
    if hdr.dst.is_multicast() {
        hc |= compress_multicast(ctxs, &hdr.dst, enc)?;
    } else if is_link_local_64(&hdr.dst) {
        hc |= compress_iid(mac_dst, &hdr.dst, None, enc)?;
    } else if let Some(c) = &dst_ctx {
        hc |= HC_DAC;
        hc |= compress_iid(mac_dst, &hdr.dst, Some(c), enc)?;
    } else {
        enc.put(&hdr.dst.octets())?;
    }

    *depth += 1;
    let mut off = start + Ipv6Header::LEN;
    let mut nh = hdr.next_header;

    while *depth < max_depth {
        match nh {
            PROTO_HOP_OPTS => {
                off = compress_ext_header(data, off, enc, &mut nh)?;
            }
            PROTO_UDP => {
                off = compress_udp(data, off, enc)?;
                break;
            }
            PROTO_IPV6 => {
                // For IP-in-IP the NH bit of the NHC must be zero.
                enc.push(NHC_EXT_DISPATCH | NHC_EID_IPV6)?;
                off = compress_at(ctxs, mac_src, mac_dst, data, off, enc, max_depth, depth)?;
                break;
            }
            _ => break,
        }
        *depth += 1;
    }

    enc.buf[hc_pos..hc_pos + 2].copy_from_slice(&hc.to_be_bytes());
    Ok(off)
}

/// Encode the IID of `addr` and return the SAM/DAM mode (1-3, unshifted).
fn compress_iid(
    mac: &Address,
    addr: &Ipv6Addr,
    ctx: Option<&Context>,
    enc: &mut Out<'_>,
) -> Result<u16> {
    let o = addr.octets();
    let iid = &o[8..16];
    if compute_iid(mac, ctx).is_some_and(|c| c == *iid) {
        Ok(3)
    } else if iid[..6] == Iid::LOCATOR_PREFIX {
        enc.put(&iid[6..8])?;
        Ok(2)
    } else {
        enc.put(iid)?;
        Ok(1)
    }
}

/// Encode a multicast destination; returns the M/DAC/DAM bits.
fn compress_multicast<C: ContextProvider + ?Sized>(
    ctxs: &C,
    addr: &Ipv6Addr,
    enc: &mut Out<'_>,
) -> Result<u16> {
    let a = addr.octets();
    let Some(i) = (2..16).find(|&i| a[i] != 0) else {
        // ffXX:: with an all-zero group: not compressible, send inline.
        enc.put(&a)?;
        return Ok(HC_M);
    };
    if a[1] == 0x02 && i >= 15 {
        enc.push(a[15])?;
        Ok(HC_M | 3)
    } else if i >= 13 {
        enc.push(a[1])?;
        enc.put(&a[13..16])?;
        Ok(HC_M | 2)
    } else if i >= 11 {
        enc.push(a[1])?;
        enc.put(&a[11..16])?;
        Ok(HC_M | 1)
    } else if ctxs
        .by_id(0)
        .is_some_and(|c| c.prefix_len == a[3] && c.prefix[..8] == a[4..12])
    {
        enc.put(&a[1..3])?;
        enc.put(&a[12..16])?;
        Ok(HC_M | HC_DAC)
    } else {
        enc.put(&a)?;
        Ok(HC_M)
    }
}

fn compress_ext_header(data: &[u8], off: usize, enc: &mut Out<'_>, nh: &mut u8) -> Result<usize> {
    let h = data.get(off..off + 2).ok_or(Error::Parse)?;
    let (next, units) = (h[0], usize::from(h[1]));
    let size = (units + 1) * 8;
    let mut len = size - 2;
    let body = data.get(off + 2..off + size).ok_or(Error::Parse)?;

    if matches!(next, PROTO_UDP | PROTO_IPV6) {
        enc.push(NHC_EXT_DISPATCH | NHC_EID_HBH | NHC_EXT_NH)?;
    } else {
        enc.push(NHC_EXT_DISPATCH | NHC_EID_HBH)?;
        enc.push(next)?;
    }

    // RFC 6282 does not support compressing large extension headers.
    if len > NHC_EXT_MAX_LEN {
        return Err(Error::InvalidArgs);
    }

    // A single trailing Pad1/PadN may be elided.
    let mut i = 0;
    let mut last = None;
    while i < len {
        let t = body[i];
        let sz = if t == 0 {
            1
        } else {
            let l = usize::from(*body.get(i + 1).ok_or(Error::Parse)?);
            2 + l
        };
        if i + sz > len {
            return Err(Error::Parse);
        }
        last = Some((t, sz));
        i += sz;
    }
    if let Some((_, sz)) = last.filter(|&(t, _)| t <= 1) {
        len -= sz;
    }

    *nh = next;
    enc.push(len as u8)?;
    enc.put(&body[..len])?;
    Ok(off + size)
}

fn compress_udp(data: &[u8], off: usize, enc: &mut Out<'_>) -> Result<usize> {
    let u = UdpHeader::parse(data.get(off..).ok_or(Error::Parse)?)?;
    let (s, d) = (u.src_port, u.dst_port);
    if s & 0xfff0 == 0xf0b0 && d & 0xfff0 == 0xf0b0 {
        enc.push(NHC_UDP_DISPATCH | 3)?;
        enc.push((((s & 0xf) << 4) | (d & 0xf)) as u8)?;
    } else if s & 0xff00 == 0xf000 {
        enc.push(NHC_UDP_DISPATCH | 2)?;
        enc.push(s as u8)?;
        enc.put(&d.to_be_bytes())?;
    } else if d & 0xff00 == 0xf000 {
        enc.push(NHC_UDP_DISPATCH | 1)?;
        enc.put(&s.to_be_bytes())?;
        enc.push(d as u8)?;
    } else {
        enc.push(NHC_UDP_DISPATCH)?;
        enc.put(&s.to_be_bytes())?;
        enc.put(&d.to_be_bytes())?;
    }
    enc.put(&u.checksum.to_be_bytes())?;
    Ok(off + UdpHeader::LEN)
}

// ---------------------------------------------------------------------------
// Decompression
// ---------------------------------------------------------------------------

/// Decompress the IPHC/NHC headers at the start of `frame` (a MAC payload
/// after any mesh/fragment headers) into `out`.
///
/// `datagram_len` is the total uncompressed datagram size if known from a
/// FRAG1 header; it determines the IPv6 payload length and the UDP length.
/// If `None`, the frame carries the whole datagram and both are derived from
/// the frame length.
///
/// `out` receives the uncompressed headers only (IPv6, extension headers,
/// UDP) starting at offset 0; the caller appends `frame[consumed..]`. See
/// [`decompress_datagram`] for a variant that does so.
pub fn decompress<C: ContextProvider + ?Sized>(
    ctxs: &C,
    mac_src: &Address,
    mac_dst: &Address,
    frame: &[u8],
    datagram_len: Option<u16>,
    out: &mut [u8],
) -> Result<Decompressed> {
    let mut r = Reader::new(frame);
    let mut o = Out::new(out);
    decompress_at(ctxs, mac_src, mac_dst, &mut r, datagram_len, &mut o)?;
    Ok(Decompressed {
        consumed: r.position(),
        written: o.len,
    })
}

/// Like [`decompress`] but also copies the remaining payload, producing the
/// complete datagram in `out`. Returns the datagram length.
pub fn decompress_datagram<C: ContextProvider + ?Sized>(
    ctxs: &C,
    mac_src: &Address,
    mac_dst: &Address,
    frame: &[u8],
    datagram_len: Option<u16>,
    out: &mut [u8],
) -> Result<usize> {
    let d = decompress(ctxs, mac_src, mac_dst, frame, datagram_len, out)?;
    let mut o = Out {
        buf: out,
        len: d.written,
    };
    o.put(&frame[d.consumed..])?;
    Ok(o.len)
}

fn nhc_to_next_header(b: u8) -> Result<u8> {
    if b & NHC_EXT_MASK == NHC_EXT_DISPATCH {
        match b & NHC_EID_MASK {
            NHC_EID_HBH => Ok(PROTO_HOP_OPTS),
            NHC_EID_ROUTING => Ok(PROTO_ROUTING),
            NHC_EID_FRAGMENT => Ok(PROTO_FRAGMENT),
            NHC_EID_DST => Ok(PROTO_DST_OPTS),
            NHC_EID_IPV6 => Ok(PROTO_IPV6),
            _ => Err(Error::Parse),
        }
    } else if b & NHC_UDP_MASK == NHC_UDP_DISPATCH {
        Ok(PROTO_UDP)
    } else {
        Err(Error::Parse)
    }
}

fn decompress_at<C: ContextProvider + ?Sized>(
    ctxs: &C,
    mac_src: &Address,
    mac_dst: &Address,
    r: &mut Reader<'_>,
    datagram_len: Option<u16>,
    o: &mut Out<'_>,
) -> Result<()> {
    let start = o.len;
    let (hdr, mut compressed) = decompress_base(ctxs, mac_src, mac_dst, r)?;
    let mut tmp = [0u8; Ipv6Header::LEN];
    hdr.write(&mut tmp)?;
    o.put(&tmp)?;

    while compressed {
        let b = r.peek_u8()?;
        if b & NHC_EXT_MASK == NHC_EXT_DISPATCH {
            if b & NHC_EID_MASK == NHC_EID_IPV6 {
                compressed = false;
                r.skip(1)?;
                decompress_at(ctxs, mac_src, mac_dst, r, datagram_len, o)?;
            } else {
                compressed = b & NHC_EXT_NH != 0;
                decompress_ext_header(r, o)?;
            }
        } else if b & NHC_UDP_MASK == NHC_UDP_DISPATCH {
            compressed = false;
            decompress_udp(r, o, datagram_len)?;
        } else {
            return Err(Error::Parse);
        }
    }

    let payload_len = match datagram_len {
        Some(n) => usize::from(n)
            .checked_sub(start + Ipv6Header::LEN)
            .ok_or(Error::Parse)?,
        None => o.len - start - Ipv6Header::LEN + r.remaining(),
    };
    let payload_len = u16::try_from(payload_len).map_err(|_| Error::Parse)?;
    o.buf[start + 4..start + 6].copy_from_slice(&payload_len.to_be_bytes());
    Ok(())
}

fn set_prefix(addr: &mut [u8; 16], ctx: &Context) {
    copy_bits(addr, &ctx.prefix, usize::from(ctx.prefix_len).min(128));
}

fn decompress_base<C: ContextProvider + ?Sized>(
    ctxs: &C,
    mac_src: &Address,
    mac_dst: &Address,
    r: &mut Reader<'_>,
) -> Result<(Ipv6Header, bool)> {
    let hc = r.read_u16()?;
    if hc & HC_DISPATCH_MASK != HC_DISPATCH {
        return Err(Error::Parse);
    }
    let (sid, did) = if hc & HC_CID != 0 {
        let b = r.read_u8()?;
        (b >> 4, b & 0x0f)
    } else {
        (0, 0)
    };
    let src_ctx = ctxs.by_id(sid);
    let dst_ctx = ctxs.by_id(did);

    // Traffic class and flow label.
    let (mut ecn, mut dscp, mut flow) = (0u8, 0u8, 0u32);
    if hc & HC_TF_MASK != HC_TF_MASK {
        let first = r.peek_u8()?;
        ecn = first >> 6;
        if hc & HC_TC == 0 {
            r.skip(1)?;
            dscp = first & 0x3f;
        }
        if hc & HC_FL == 0 {
            let b = r.read_slice(3)?;
            flow = (u32::from(b[0] & 0x0f) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        }
    }

    let next_header_inline = if hc & HC_NH == 0 {
        Some(r.read_u8()?)
    } else {
        None
    };

    let hop_limit = match hc & HC_HLIM_MASK {
        HC_HLIM_1 => 1,
        HC_HLIM_64 => 64,
        HC_HLIM_255 => 255,
        _ => r.read_u8()?,
    };

    // Source address.
    let sam = (hc >> HC_SAM_SHIFT) & 3;
    let sac = hc & HC_SAC != 0;
    let mut src = [0u8; 16];
    match sam {
        0 => {
            if !sac {
                src = r.read_array::<16>()?;
            }
        }
        1 => src[8..].copy_from_slice(&r.read_array::<8>()?),
        2 => {
            src[11] = 0xff;
            src[12] = 0xfe;
            src[14..].copy_from_slice(&r.read_array::<2>()?);
        }
        _ => {
            let ctx = if sac { src_ctx.as_ref() } else { None };
            src[8..].copy_from_slice(&compute_iid(mac_src, ctx).ok_or(Error::Parse)?);
        }
    }
    if sam != 0 {
        if !sac {
            src[0] = 0xfe;
            src[1] = 0x80;
        } else {
            set_prefix(&mut src, src_ctx.as_ref().ok_or(Error::Parse)?);
        }
    }

    // Destination address.
    let dam = hc & HC_DAM_MASK;
    let dac = hc & HC_DAC != 0;
    let mut dst = [0u8; 16];
    if hc & HC_M == 0 {
        match dam {
            0 => {
                if dac {
                    return Err(Error::Parse);
                }
                dst = r.read_array::<16>()?;
            }
            1 => dst[8..].copy_from_slice(&r.read_array::<8>()?),
            2 => {
                dst[11] = 0xff;
                dst[12] = 0xfe;
                dst[14..].copy_from_slice(&r.read_array::<2>()?);
            }
            _ => {
                let ctx = if dac { dst_ctx.as_ref() } else { None };
                dst[8..].copy_from_slice(&compute_iid(mac_dst, ctx).ok_or(Error::Parse)?);
            }
        }
        if !dac {
            if dam != 0 {
                dst[0] = 0xfe;
                dst[1] = 0x80;
            }
        } else {
            set_prefix(&mut dst, dst_ctx.as_ref().ok_or(Error::Parse)?);
        }
    } else {
        dst[0] = 0xff;
        if !dac {
            match dam {
                0 => dst = r.read_array::<16>()?,
                1 => {
                    dst[1] = r.read_u8()?;
                    dst[11..].copy_from_slice(&r.read_array::<5>()?);
                }
                2 => {
                    dst[1] = r.read_u8()?;
                    dst[13..].copy_from_slice(&r.read_array::<3>()?);
                }
                _ => {
                    dst[1] = 0x02;
                    dst[15] = r.read_u8()?;
                }
            }
        } else if dam == 0 {
            let ctx = dst_ctx.as_ref().ok_or(Error::Parse)?;
            dst[1..3].copy_from_slice(&r.read_array::<2>()?);
            dst[3] = ctx.prefix_len;
            dst[4..12].copy_from_slice(&ctx.prefix[..8]);
            dst[12..].copy_from_slice(&r.read_array::<4>()?);
        } else {
            return Err(Error::Parse);
        }
    }

    let (next_header, compressed) = match next_header_inline {
        Some(nh) => (nh, false),
        None => (nhc_to_next_header(r.peek_u8()?)?, true),
    };

    Ok((
        Ipv6Header {
            traffic_class: (dscp << 2) | ecn,
            flow_label: flow,
            payload_len: 0,
            next_header,
            hop_limit,
            src: Ipv6Addr::from(src),
            dst: Ipv6Addr::from(dst),
        },
        compressed,
    ))
}

fn decompress_ext_header(r: &mut Reader<'_>, o: &mut Out<'_>) -> Result<()> {
    let ctl = r.read_u8()?;
    let (next, len) = if ctl & NHC_EXT_NH != 0 {
        let len = usize::from(r.read_u8()?);
        let rest = r.rest();
        let n = nhc_to_next_header(*rest.get(len).ok_or(Error::Parse)?)?;
        (n, len)
    } else {
        let n = r.read_u8()?;
        (n, usize::from(r.read_u8()?))
    };
    let body = r.read_slice(len)?;

    let size = len + 2;
    o.put(&[next, (size.div_ceil(8) - 1) as u8])?;
    o.put(body)?;

    // The trailing Pad1/PadN may have been elided: pad to 8 octets again.
    match size % 8 {
        0 => {}
        rem => {
            let pad = 8 - rem;
            if pad == 1 {
                o.push(0)?;
            } else {
                o.put(&[1, (pad - 2) as u8])?;
                for _ in 0..pad - 2 {
                    o.push(0)?;
                }
            }
        }
    }
    Ok(())
}

fn decompress_udp(r: &mut Reader<'_>, o: &mut Out<'_>, datagram_len: Option<u16>) -> Result<()> {
    let ctl = r.read_u8()?;
    if ctl & NHC_UDP_MASK != NHC_UDP_DISPATCH {
        return Err(Error::Parse);
    }
    let (src_port, dst_port) = match ctl & NHC_UDP_PORT_MASK {
        0 => (r.read_u16()?, r.read_u16()?),
        1 => (r.read_u16()?, 0xf000 | u16::from(r.read_u8()?)),
        2 => (0xf000 | u16::from(r.read_u8()?), r.read_u16()?),
        _ => {
            let b = r.read_u8()?;
            (0xf0b0 | u16::from(b >> 4), 0xf0b0 | u16::from(b & 0x0f))
        }
    };
    // Thread requires the checksum to be carried inline.
    if ctl & NHC_UDP_CHECKSUM != 0 {
        return Err(Error::Parse);
    }
    let checksum = r.read_u16()?;
    let length = match datagram_len {
        None => UdpHeader::LEN + r.remaining(),
        Some(n) => usize::from(n).checked_sub(o.len).ok_or(Error::Parse)?,
    };
    let length = u16::try_from(length).map_err(|_| Error::Parse)?;
    let mut tmp = [0u8; UdpHeader::LEN];
    UdpHeader {
        src_port,
        dst_port,
        length,
        checksum,
    }
    .write(&mut tmp)?;
    o.put(&tmp)
}

// ---------------------------------------------------------------------------
// ECN helpers (for forwarding with congestion marking)
// ---------------------------------------------------------------------------

fn ecn_byte_offset(iphc: &[u8]) -> Option<(usize, bool)> {
    let hc = u16::from_be_bytes([*iphc.first()?, *iphc.get(1)?]);
    if hc & HC_DISPATCH_MASK != HC_DISPATCH {
        return None;
    }
    let elided = hc & HC_TF_MASK == HC_TF_MASK;
    Some((if hc & HC_CID != 0 { 3 } else { 2 }, elided))
}

/// ECN of a compressed IPv6 header (`None` if `iphc` is not LOWPAN_IPHC or
/// truncated). Zero if the traffic class is fully elided.
pub fn iphc_ecn(iphc: &[u8]) -> Option<u8> {
    let (off, elided) = ecn_byte_offset(iphc)?;
    if elided {
        return Some(0);
    }
    Some(iphc.get(off)? >> 6)
}

/// Set the ECN of a compressed IPv6 header to "congestion experienced".
/// Fails if the traffic class is elided (ECN not capable) or `iphc` is not a
/// valid compressed header.
pub fn iphc_mark_ecn(iphc: &mut [u8]) -> Result<()> {
    let (off, elided) = ecn_byte_offset(iphc).ok_or(Error::Parse)?;
    if elided {
        return Err(Error::InvalidState);
    }
    let b = iphc.get_mut(off).ok_or(Error::Parse)?;
    *b = (*b & 0x3f) | (ECN_MARKED << 6);
    Ok(())
}
