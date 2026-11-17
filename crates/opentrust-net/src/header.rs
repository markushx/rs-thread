//! IPv6 headers: the fixed header, extension headers and the options that
//! Thread uses (RFC 8200, RFC 7731).
//!
//! The fixed [`Ipv6Header`] and [`UdpHeader`] live in `opentrust-lowpan`
//! (the 6LoWPAN codecs need them) and are re-exported here, so this module
//! is the single place the IPv6 layer imports them from.
//!
//! [`parse_datagram`] walks the extension-header chain of a complete
//! datagram the way OpenThread's `Ip6::HandleExtensionHeaders` does:
//!
//! - Hop-by-Hop and Destination Options headers are parsed; Pad1/PadN are
//!   skipped, the MPL option is decoded, any other option whose two high
//!   bits are not `00` ("skip") makes the datagram [`Error::Drop`].
//! - A Routing header is skipped (and reported; the receive path drops it
//!   as OpenThread does).
//! - A Fragment header is recorded. An "atomic" fragment (offset 0, no more
//!   fragments) is walked through; any other fragment stops the walk at the
//!   Fragment header (`upper_proto == PROTO_FRAGMENT`).
//! - Everything else is the upper-layer protocol (including
//!   [`PROTO_IPV6`] for IP-in-IP tunnelling and [`PROTO_NONE`]).

use opentrust_core::{Error, Result};

pub use opentrust_lowpan::ip6::{
    ECN_MARKED, Ipv6Header, OFFSET_HOP_LIMIT, OFFSET_NEXT_HEADER, OFFSET_PAYLOAD_LEN,
    PROTO_DST_OPTS, PROTO_FRAGMENT, PROTO_HOP_OPTS, PROTO_ICMP6, PROTO_IPV6, PROTO_ROUTING,
    PROTO_UDP, UdpHeader,
};

/// IPv6 next-header value: no next header.
pub const PROTO_NONE: u8 = 59;

/// Maximum IPv6 datagram length handled (OT `OPENTHREAD_CONFIG_IP6_MAX_DATAGRAM_LENGTH`
/// = IPv6 minimum MTU; with the `ip6-fragmentation` feature the size of a
/// reassembled datagram, OT `IP6_MAX_ASSEMBLED_DATAGRAM`).
pub const MAX_DATAGRAM_LEN: usize = if cfg!(feature = "ip6-fragmentation") {
    2000
} else {
    1280
};
/// IPv6 minimum MTU: the largest datagram sent in one piece and the largest
/// ICMPv6 error message.
pub const MIN_MTU: usize = 1280;
/// Default hop limit for originated datagrams (OT `kDefaultHopLimit`).
pub const DEFAULT_HOP_LIMIT: u8 = 64;
/// Size unit of extension headers (RFC 8200).
pub const EXT_UNIT: usize = 8;

/// Option type: Pad1.
pub const OPT_PAD1: u8 = 0x00;
/// Option type: PadN.
pub const OPT_PADN: u8 = 0x01;
/// Option type: MPL (`01 1 01101`), RFC 7731.
pub const OPT_MPL: u8 = 0x6d;

/// What to do with an unrecognised option (top two bits of the type).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum OptionAction {
    /// `00`: skip the option.
    Skip,
    /// `01`: discard the packet.
    Discard,
    /// `10`: discard and send ICMP Parameter Problem.
    ForceIcmp,
    /// `11`: discard and send ICMP Parameter Problem unless multicast.
    Icmp,
}

impl OptionAction {
    /// Action encoded in an option type.
    pub const fn of(opt_type: u8) -> Self {
        match opt_type >> 6 {
            0 => Self::Skip,
            1 => Self::Discard,
            2 => Self::ForceIcmp,
            _ => Self::Icmp,
        }
    }
}

/// One TLV option inside a Hop-by-Hop / Destination Options header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv6Option<'a> {
    /// Option type.
    pub opt_type: u8,
    /// Option data (without the type and length bytes).
    pub data: &'a [u8],
}

impl Ipv6Option<'_> {
    /// `true` for Pad1 / PadN.
    pub const fn is_padding(&self) -> bool {
        self.opt_type == OPT_PAD1 || self.opt_type == OPT_PADN
    }
}

/// Iterator over the options of an options header body (the bytes after the
/// 2-byte header). Yields `Err(Error::Parse)` once on a truncated option.
#[derive(Debug, Clone)]
pub struct OptionIter<'a> {
    rest: &'a [u8],
}

impl<'a> OptionIter<'a> {
    /// Iterate over `body`.
    pub const fn new(body: &'a [u8]) -> Self {
        Self { rest: body }
    }
}

impl<'a> Iterator for OptionIter<'a> {
    type Item = Result<Ipv6Option<'a>>;

    fn next(&mut self) -> Option<Self::Item> {
        let (&t, rest) = self.rest.split_first()?;
        if t == OPT_PAD1 {
            self.rest = rest;
            return Some(Ok(Ipv6Option {
                opt_type: t,
                data: &[],
            }));
        }
        let Some((&len, rest)) = rest.split_first() else {
            self.rest = &[];
            return Some(Err(Error::Parse));
        };
        let len = usize::from(len);
        if rest.len() < len {
            self.rest = &[];
            return Some(Err(Error::Parse));
        }
        let (data, rest) = rest.split_at(len);
        self.rest = rest;
        Some(Ok(Ipv6Option { opt_type: t, data }))
    }
}

/// Length of the Seed ID in an MPL option (`S` field).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum MplSeedIdLen {
    /// `S=0`: the Seed ID is the IPv6 source address (an RLOC for Thread).
    Zero,
    /// `S=1`: 2-byte Seed ID.
    Two,
    /// `S=2`: 8-byte Seed ID (not supported, as in OT).
    Eight,
    /// `S=3`: 16-byte Seed ID (not supported, as in OT).
    Sixteen,
}

/// MPL option (RFC 7731 section 6.1) as used by Thread.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct MplOption {
    /// Seed ID length.
    pub seed_id_len: MplSeedIdLen,
    /// `M` flag.
    pub max: bool,
    /// Sequence number.
    pub sequence: u8,
    /// Seed ID; only meaningful for [`MplSeedIdLen::Two`].
    pub seed_id: u16,
}

impl MplOption {
    /// Option data length with an empty Seed ID.
    pub const DATA_LEN_S0: usize = 2;
    /// Option data length with a 2-byte Seed ID.
    pub const DATA_LEN_S2: usize = 4;

    /// Decode the option data (after type and length).
    ///
    /// `S=2/3` (8- and 16-byte Seed IDs) are rejected with
    /// [`Error::Parse`], as OpenThread does.
    pub fn parse(data: &[u8]) -> Result<Self> {
        let [ctl, seq, rest @ ..] = data else {
            return Err(Error::Parse);
        };
        let s = match ctl >> 6 {
            0 => MplSeedIdLen::Zero,
            1 => MplSeedIdLen::Two,
            2 => MplSeedIdLen::Eight,
            _ => MplSeedIdLen::Sixteen,
        };
        let seed_id = match s {
            MplSeedIdLen::Zero => 0,
            MplSeedIdLen::Two => match rest {
                [a, b, ..] => u16::from_be_bytes([*a, *b]),
                _ => return Err(Error::Parse),
            },
            _ => return Err(Error::Parse),
        };
        Ok(Self {
            seed_id_len: s,
            max: ctl & 0x20 != 0,
            sequence: *seq,
            seed_id,
        })
    }

    /// Encoded size including the type and length bytes.
    pub const fn encoded_len(&self) -> usize {
        match self.seed_id_len {
            MplSeedIdLen::Zero => 2 + Self::DATA_LEN_S0,
            _ => 2 + Self::DATA_LEN_S2,
        }
    }

    /// Encode type, length and data; only `S=0` and `S=1` can be written.
    pub fn write(&self, out: &mut [u8]) -> Result<usize> {
        let n = self.encoded_len();
        let o = out.get_mut(..n).ok_or(Error::NoBufs)?;
        let s: u8 = match self.seed_id_len {
            MplSeedIdLen::Zero => 0,
            MplSeedIdLen::Two => 1,
            _ => return Err(Error::InvalidArgs),
        };
        o[0] = OPT_MPL;
        o[1] = (n - 2) as u8;
        o[2] = (s << 6) | if self.max { 0x20 } else { 0 };
        o[3] = self.sequence;
        if n == 6 {
            o[4..6].copy_from_slice(&self.seed_id.to_be_bytes());
        }
        Ok(n)
    }
}

/// Write the padding (Pad1 or PadN) that brings `size` up to a multiple of
/// 8 bytes (OT `PadOption::InitToPadHeaderWithSize`). Returns the number of
/// bytes written (0 if `size` is already aligned).
pub fn write_padding(size: usize, out: &mut [u8]) -> Result<usize> {
    let pad = (EXT_UNIT - size % EXT_UNIT) % EXT_UNIT;
    let o = out.get_mut(..pad).ok_or(Error::NoBufs)?;
    match pad {
        0 => {}
        1 => o[0] = OPT_PAD1,
        _ => {
            o[0] = OPT_PADN;
            o[1] = (pad - 2) as u8;
            o[2..].fill(0);
        }
    }
    Ok(pad)
}

/// Build a Hop-by-Hop header holding only the MPL option (plus padding),
/// OT `Ip6::AddMplOption`. Returns the header length (6 or 8 bytes padded
/// to 8).
pub fn write_hbh_mpl(next_header: u8, mpl: &MplOption, out: &mut [u8]) -> Result<usize> {
    let total = (2 + mpl.encoded_len()).next_multiple_of(EXT_UNIT);
    if out.len() < total {
        return Err(Error::NoBufs);
    }
    out[0] = next_header;
    out[1] = (total / EXT_UNIT - 1) as u8;
    let n = mpl.write(&mut out[2..])?;
    write_padding(2 + n, &mut out[2 + n..])?;
    Ok(total)
}

/// IPv6 Fragment header (RFC 8200 section 4.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct FragmentHeader {
    /// Next header.
    pub next_header: u8,
    /// Fragment offset in bytes (multiple of 8).
    pub offset: u16,
    /// More-fragments flag.
    pub more: bool,
    /// Identification.
    pub id: u32,
}

impl FragmentHeader {
    /// Encoded length.
    pub const LEN: usize = 8;

    /// Parse from the start of `b`.
    pub fn parse(b: &[u8]) -> Result<Self> {
        let b = b.get(..Self::LEN).ok_or(Error::Parse)?;
        let of = u16::from_be_bytes([b[2], b[3]]);
        Ok(Self {
            next_header: b[0],
            offset: of & 0xfff8,
            more: of & 1 != 0,
            id: u32::from_be_bytes([b[4], b[5], b[6], b[7]]),
        })
    }

    /// Encode into `out`.
    pub fn write(&self, out: &mut [u8]) -> Result<()> {
        let o = out.get_mut(..Self::LEN).ok_or(Error::NoBufs)?;
        o[0] = self.next_header;
        o[1] = 0;
        o[2..4].copy_from_slice(&((self.offset & 0xfff8) | u16::from(self.more)).to_be_bytes());
        o[4..8].copy_from_slice(&self.id.to_be_bytes());
        Ok(())
    }

    /// `true` if this is the only fragment (offset 0, no more fragments).
    pub const fn is_atomic(&self) -> bool {
        self.offset == 0 && !self.more
    }
}

/// Result of walking a datagram's extension headers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParsedDatagram {
    /// The fixed header.
    pub header: Ipv6Header,
    /// Upper-layer protocol (or [`PROTO_FRAGMENT`] / [`PROTO_ROUTING`]-free
    /// terminal values as described in the module docs).
    pub upper_proto: u8,
    /// Offset of the upper-layer header within the datagram.
    pub upper_offset: usize,
    /// Total datagram length (`40 + payload_len`); trailing bytes beyond it
    /// are ignored.
    pub total_len: usize,
    /// MPL option, if present in a Hop-by-Hop or Destination Options header.
    pub mpl: Option<MplOption>,
    /// Fragment header, if present.
    pub fragment: Option<FragmentHeader>,
    /// `true` if a Routing header was present.
    pub routing: bool,
}

impl ParsedDatagram {
    /// Length of the upper-layer data (header plus payload).
    pub const fn upper_len(&self) -> usize {
        self.total_len - self.upper_offset
    }
}

/// Parse the fixed header and extension-header chain of `buf` (see the
/// module docs). `buf` may be longer than the datagram; shorter than the
/// declared payload length is [`Error::Parse`].
pub fn parse_datagram(buf: &[u8]) -> Result<ParsedDatagram> {
    let header = Ipv6Header::parse(buf)?;
    let total_len = Ipv6Header::LEN + usize::from(header.payload_len);
    if buf.len() < total_len {
        return Err(Error::Parse);
    }
    let buf = &buf[..total_len];
    let mut nh = header.next_header;
    let mut off = Ipv6Header::LEN;
    let mut out = ParsedDatagram {
        header,
        upper_proto: nh,
        upper_offset: off,
        total_len,
        mpl: None,
        fragment: None,
        routing: false,
    };
    loop {
        match nh {
            PROTO_HOP_OPTS | PROTO_DST_OPTS | PROTO_ROUTING => {
                let hdr = buf.get(off..off + 2).ok_or(Error::Parse)?;
                let size = (usize::from(hdr[1]) + 1) * EXT_UNIT;
                let body = buf.get(off + 2..off + size).ok_or(Error::Parse)?;
                if nh == PROTO_ROUTING {
                    out.routing = true;
                } else {
                    for opt in OptionIter::new(body) {
                        let opt = opt?;
                        if opt.is_padding() {
                            continue;
                        }
                        if opt.opt_type == OPT_MPL {
                            out.mpl = Some(MplOption::parse(opt.data)?);
                            continue;
                        }
                        if OptionAction::of(opt.opt_type) != OptionAction::Skip {
                            return Err(Error::Drop);
                        }
                    }
                }
                nh = hdr[0];
                off += size;
            }
            PROTO_FRAGMENT => {
                let f = FragmentHeader::parse(buf.get(off..).ok_or(Error::Parse)?)?;
                out.fragment = Some(f);
                if !f.is_atomic() {
                    out.upper_proto = PROTO_FRAGMENT;
                    out.upper_offset = off;
                    return Ok(out);
                }
                nh = f.next_header;
                off += FragmentHeader::LEN;
            }
            _ => break,
        }
    }
    out.upper_proto = nh;
    out.upper_offset = off;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    use core::net::Ipv6Addr;

    const SRC: Ipv6Addr = Ipv6Addr::new(
        0x0102, 0x0304, 0x0506, 0x0708, 0x090a, 0x0b0c, 0x0d0e, 0x0f12,
    );
    const DST: Ipv6Addr = Ipv6Addr::new(0x1122, 0x3344, 0x5566, 0, 0x7788, 0x99aa, 0xbbcc, 0xddee);

    /// Port of OT `test_ip6_header.cpp` `TestIp6Header`.
    #[test]
    fn ot_test_ip6_header() {
        let mut h = Ipv6Header::new(0, 0, Ipv6Addr::UNSPECIFIED, Ipv6Addr::UNSPECIFIED);
        let mut b = [0u8; 40];
        h.write(&mut b).unwrap();
        assert_eq!(u32::from_be_bytes([b[0], b[1], b[2], b[3]]), 0x6000_0000);
        h.payload_len = 650;
        h.next_header = PROTO_UDP;
        h.hop_limit = 0xd1;
        h.src = SRC;
        h.dst = DST;
        h.write(&mut b).unwrap();
        assert_eq!(
            u16::from_be_bytes([b[OFFSET_PAYLOAD_LEN], b[OFFSET_PAYLOAD_LEN + 1]]),
            650
        );
        assert_eq!(b[OFFSET_NEXT_HEADER], PROTO_UDP);
        assert_eq!(b[OFFSET_HOP_LIMIT], 0xd1);
        assert_eq!(b[8..24], SRC.octets());
        assert_eq!(b[24..40], DST.octets());
        for flow in [0x0u32, 0x1, 0xfff, 0xffff, 0xff000, 0xfffff] {
            for dscp in [0x0u8, 0x1, 0x3, 0xf, 0x30, 0x2f, 0x3f] {
                for ecn in 0u8..4 {
                    h.set_ecn(ecn);
                    h.set_dscp(dscp);
                    h.set_flow_label(flow);
                    let tc = (dscp << 2) | ecn;
                    let expect = 0x6000_0000 + (u32::from(tc) << 20) + flow;
                    h.write(&mut b).unwrap();
                    assert_eq!(u32::from_be_bytes([b[0], b[1], b[2], b[3]]), expect);
                    let p = Ipv6Header::parse(&b).unwrap();
                    assert_eq!((p.dscp(), p.ecn(), p.flow_label), (dscp, ecn, flow));
                }
            }
        }
        // Out-of-range values are masked.
        h.set_dscp(0);
        h.set_ecn(0);
        h.set_flow_label(0xff00_0001);
        assert_eq!(h.flow_label, 1);
        h.set_dscp(0xef);
        assert_eq!(h.dscp(), 0x2f);
    }

    fn datagram(next: u8, ext: &[u8], upper: &[u8]) -> ([u8; 200], usize) {
        let mut buf = [0u8; 200];
        let mut h = Ipv6Header::new(next, 64, SRC, DST);
        h.payload_len = (ext.len() + upper.len()) as u16;
        h.write(&mut buf).unwrap();
        buf[40..40 + ext.len()].copy_from_slice(ext);
        buf[40 + ext.len()..40 + ext.len() + upper.len()].copy_from_slice(upper);
        (buf, 40 + ext.len() + upper.len())
    }

    #[test]
    fn mpl_option_round_trip() {
        for (s, id, n) in [(MplSeedIdLen::Zero, 0, 4), (MplSeedIdLen::Two, 0x1c00, 6)] {
            for max in [false, true] {
                let o = MplOption {
                    seed_id_len: s,
                    max,
                    sequence: 0xa5,
                    seed_id: id,
                };
                let mut b = [0u8; 8];
                assert_eq!(o.write(&mut b).unwrap(), n);
                assert_eq!(b[0], OPT_MPL);
                assert_eq!(MplOption::parse(&b[2..n]).unwrap(), o);
            }
        }
        assert_eq!(
            MplOption::parse(&[0x80, 1, 0, 0, 0, 0, 0, 0, 0, 0]),
            Err(Error::Parse)
        );
        assert_eq!(MplOption::parse(&[0xc0, 1]), Err(Error::Parse));
        assert_eq!(MplOption::parse(&[0x40, 1, 0]), Err(Error::Parse));
    }

    #[test]
    fn hbh_mpl_build_and_parse() {
        for (s, id) in [(MplSeedIdLen::Zero, 0u16), (MplSeedIdLen::Two, 0x0800)] {
            let o = MplOption {
                seed_id_len: s,
                max: false,
                sequence: 7,
                seed_id: id,
            };
            let mut hbh = [0u8; 8];
            assert_eq!(write_hbh_mpl(PROTO_UDP, &o, &mut hbh).unwrap(), 8);
            assert_eq!(hbh[1], 0);
            let udp = [0u8; 8];
            let (buf, n) = datagram(PROTO_HOP_OPTS, &hbh, &udp);
            let p = parse_datagram(&buf[..n]).unwrap();
            assert_eq!(p.upper_proto, PROTO_UDP);
            assert_eq!(p.upper_offset, 48);
            assert_eq!(p.upper_len(), 8);
            assert_eq!(p.mpl, Some(o));
        }
    }

    #[test]
    fn padding_sizes() {
        let mut b = [0xffu8; 8];
        assert_eq!(write_padding(8, &mut b).unwrap(), 0);
        assert_eq!(write_padding(7, &mut b).unwrap(), 1);
        assert_eq!(b[0], OPT_PAD1);
        assert_eq!(write_padding(4, &mut b).unwrap(), 4);
        assert_eq!(&b[..4], &[OPT_PADN, 2, 0, 0]);
        assert_eq!(write_padding(6, &mut b[..1]), Err(Error::NoBufs));
    }

    #[test]
    fn unknown_options_and_routing() {
        // Unknown skip option (type 0x1e, action 00) is skipped.
        let ext = [PROTO_UDP, 0, 0x1e, 2, 0xaa, 0xbb, 1, 0];
        let (buf, n) = datagram(PROTO_DST_OPTS, &ext, &[0u8; 8]);
        let p = parse_datagram(&buf[..n]).unwrap();
        assert_eq!(p.upper_proto, PROTO_UDP);
        assert_eq!(p.mpl, None);
        // Discard action (01xxxxxx).
        let ext = [PROTO_UDP, 0, 0x5e, 4, 0, 0, 0, 0];
        let (buf, n) = datagram(PROTO_HOP_OPTS, &ext, &[0u8; 8]);
        assert_eq!(parse_datagram(&buf[..n]), Err(Error::Drop));
        // Routing header is skipped and reported.
        let ext = [PROTO_UDP, 0, 0, 0, 0, 0, 0, 0];
        let (buf, n) = datagram(PROTO_ROUTING, &ext, &[0u8; 8]);
        let p = parse_datagram(&buf[..n]).unwrap();
        assert!(p.routing);
        assert_eq!(p.upper_proto, PROTO_UDP);
        // Option running past the header.
        let ext = [PROTO_UDP, 0, 0x1e, 9, 0, 0, 0, 0];
        let (buf, n) = datagram(PROTO_HOP_OPTS, &ext, &[0u8; 8]);
        assert_eq!(parse_datagram(&buf[..n]), Err(Error::Parse));
    }

    #[test]
    fn fragment_header() {
        let f = FragmentHeader {
            next_header: PROTO_UDP,
            offset: 0,
            more: false,
            id: 0xdeadbeef,
        };
        let mut e = [0u8; 8];
        f.write(&mut e).unwrap();
        assert_eq!(FragmentHeader::parse(&e).unwrap(), f);
        let (buf, n) = datagram(PROTO_FRAGMENT, &e, &[0u8; 8]);
        let p = parse_datagram(&buf[..n]).unwrap();
        assert_eq!(p.upper_proto, PROTO_UDP);
        assert_eq!(p.upper_offset, 48);
        assert_eq!(p.fragment, Some(f));
        // Non-atomic fragment: walk stops at the fragment header.
        let f2 = FragmentHeader {
            offset: 1232,
            more: true,
            ..f
        };
        f2.write(&mut e).unwrap();
        let (buf, n) = datagram(PROTO_FRAGMENT, &e, &[0u8; 8]);
        let p = parse_datagram(&buf[..n]).unwrap();
        assert_eq!(p.upper_proto, PROTO_FRAGMENT);
        assert_eq!(p.upper_offset, 40);
        assert_eq!(p.fragment, Some(f2));
    }

    #[test]
    fn ip_in_ip_and_none() {
        let (buf, n) = datagram(PROTO_IPV6, &[], &[0u8; 40]);
        assert_eq!(parse_datagram(&buf[..n]).unwrap().upper_proto, PROTO_IPV6);
        let (buf, n) = datagram(PROTO_NONE, &[], &[]);
        assert_eq!(parse_datagram(&buf[..n]).unwrap().upper_proto, PROTO_NONE);
    }

    /// Every truncation of a valid datagram and arbitrary byte flips must
    /// not panic.
    #[test]
    fn truncation_and_corruption_never_panic() {
        let o = MplOption {
            seed_id_len: MplSeedIdLen::Two,
            max: false,
            sequence: 1,
            seed_id: 0x1234,
        };
        let mut hbh = [0u8; 8];
        write_hbh_mpl(PROTO_FRAGMENT, &o, &mut hbh).unwrap();
        let mut e = [0u8; 16];
        e[..8].copy_from_slice(&hbh);
        FragmentHeader {
            next_header: PROTO_UDP,
            offset: 0,
            more: false,
            id: 1,
        }
        .write(&mut e[8..])
        .unwrap();
        let (buf, n) = datagram(PROTO_HOP_OPTS, &e, &[1u8; 8]);
        assert!(parse_datagram(&buf[..n]).is_ok());
        for len in 0..n {
            assert!(parse_datagram(&buf[..len]).is_err(), "len {len}");
        }
        for i in 0..n {
            for bit in 0..8 {
                let mut b = buf;
                b[i] ^= 1 << bit;
                let _ = parse_datagram(&b[..n]);
            }
        }
    }
}
