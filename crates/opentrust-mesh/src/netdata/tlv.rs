//! Network Data TLV wire format (OT `network_data_tlvs.hpp`, Thread 1.4.1
//! section 5.18): `type<<1 | stable (1) | length (1) | value`.
//!
//! Unlike the generic TLVs of `opentrust-core` there is no extended length:
//! a Network Data TLV is at most 255 bytes long.

use core::net::Ipv6Addr;

use opentrust_core::bytes::Writer;
use opentrust_core::{Error, Result};

/// Network Data TLV type numbers.
pub mod ty {
    /// Has Route.
    pub const HAS_ROUTE: u8 = 0;
    /// Prefix.
    pub const PREFIX: u8 = 1;
    /// Border Router.
    pub const BORDER_ROUTER: u8 = 2;
    /// 6LoWPAN Context ID.
    pub const CONTEXT: u8 = 3;
    /// Commissioning Data.
    pub const COMMISSIONING: u8 = 4;
    /// Service.
    pub const SERVICE: u8 = 5;
    /// Server.
    pub const SERVER: u8 = 6;
}

/// The Thread enterprise number, implied by the `T` flag of a Service TLV.
pub const THREAD_ENTERPRISE_NUMBER: u32 = 44970;

/// RLOC16 placeholder in the stable copy of Network Data (OT
/// `RemoveTemporaryData`).
pub const STABLE_RLOC16: u16 = 0xfffe;

/// One Network Data TLV borrowing its value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct RawTlv<'a> {
    /// Type (7 bits, see [`ty`]).
    pub ty: u8,
    /// Stable flag.
    pub stable: bool,
    /// Value bytes.
    pub value: &'a [u8],
}

impl<'a> RawTlv<'a> {
    /// Parse the TLV at the start of `buf`; returns it and the rest.
    /// [`Error::Parse`] if truncated.
    pub fn parse(buf: &'a [u8]) -> Result<(Self, &'a [u8])> {
        let [t, len, rest @ ..] = buf else {
            return Err(Error::Parse);
        };
        let len = usize::from(*len);
        if rest.len() < len {
            return Err(Error::Parse);
        }
        let (value, rest) = rest.split_at(len);
        Ok((
            Self {
                ty: t >> 1,
                stable: t & 1 != 0,
                value,
            },
            rest,
        ))
    }

    /// Encoded size.
    pub const fn size(&self) -> usize {
        2 + self.value.len()
    }

    /// Re-encode.
    pub fn write(&self, w: &mut Writer<'_>) -> Result<()> {
        w.write_u8(self.ty << 1 | u8::from(self.stable))?;
        w.write_u8(u8::try_from(self.value.len()).map_err(|_| Error::NoBufs)?)?;
        w.write_slice(self.value)
    }
}

/// Iterator over the TLVs of a buffer; stops silently at the first
/// malformed TLV (as OT's iteration does).
#[derive(Debug, Clone)]
pub struct RawIter<'a> {
    rest: &'a [u8],
}

impl<'a> RawIter<'a> {
    /// Iterate over `buf`.
    pub const fn new(buf: &'a [u8]) -> Self {
        Self { rest: buf }
    }
}

impl<'a> Iterator for RawIter<'a> {
    type Item = RawTlv<'a>;
    fn next(&mut self) -> Option<RawTlv<'a>> {
        match RawTlv::parse(self.rest) {
            Ok((t, r)) => {
                self.rest = r;
                Some(t)
            }
            Err(_) => {
                self.rest = &[];
                None
            }
        }
    }
}

/// `true` if `buf` is a well-formed sequence of TLVs (no trailing bytes).
pub fn is_well_formed(buf: &[u8]) -> bool {
    let mut rest = buf;
    while !rest.is_empty() {
        match RawTlv::parse(rest) {
            Ok((_, r)) => rest = r,
            Err(_) => return false,
        }
    }
    true
}

// ------------------------------------------------------------------ prefix

/// An IPv6 prefix of 0-128 bits; bits past the length are zero.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct NetPrefix {
    bytes: [u8; 16],
    len: u8,
}

impl NetPrefix {
    /// From at least `ceil(len/8)` bytes of `bytes`; trailing bits are
    /// cleared. [`Error::InvalidArgs`] if `len > 128` or too few bytes.
    pub fn new(bytes: &[u8], len: u8) -> Result<Self> {
        if len > 128 {
            return Err(Error::InvalidArgs);
        }
        let n = usize::from(len).div_ceil(8);
        let src = bytes.get(..n).ok_or(Error::InvalidArgs)?;
        let mut b = [0u8; 16];
        b[..n].copy_from_slice(src);
        if len % 8 != 0 {
            b[n - 1] &= 0xffu8 << (8 - len % 8);
        }
        Ok(Self { bytes: b, len })
    }

    /// From an address.
    pub fn from_addr(addr: &Ipv6Addr, len: u8) -> Result<Self> {
        Self::new(&addr.octets(), len)
    }

    /// Length in bits.
    pub const fn len(&self) -> u8 {
        self.len
    }

    /// `true` for the zero-length (default route) prefix.
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The `ceil(len/8)` significant bytes (the wire form).
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..usize::from(self.len).div_ceil(8)]
    }

    /// The prefix padded with zeros to 16 bytes.
    pub const fn octets(&self) -> [u8; 16] {
        self.bytes
    }

    /// The prefix as an address (zero-padded).
    pub fn addr(&self) -> Ipv6Addr {
        Ipv6Addr::from(self.bytes)
    }

    /// `true` if the first `len` bits of `addr` equal this prefix.
    pub fn contains(&self, addr: &Ipv6Addr) -> bool {
        let o = addr.octets();
        let n = usize::from(self.len);
        let full = n / 8;
        if o[..full] != self.bytes[..full] {
            return false;
        }
        let rem = n % 8;
        rem == 0 || (o[full] ^ self.bytes[full]) & (0xffu8 << (8 - rem)) == 0
    }

    /// `true` if every address of `other` is in `self` (`self` is the
    /// shorter or equal prefix).
    pub fn contains_prefix(&self, other: &NetPrefix) -> bool {
        self.len <= other.len && self.contains(&other.addr())
    }
}

/// A parsed Prefix TLV.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrefixTlv<'a> {
    /// Stable flag of the TLV.
    pub stable: bool,
    /// Domain ID.
    pub domain_id: u8,
    /// The prefix.
    pub prefix: NetPrefix,
    /// Sub-TLVs.
    pub subs: &'a [u8],
}

impl<'a> PrefixTlv<'a> {
    /// Interpret `t` as a Prefix TLV. [`Error::Parse`] on a short value,
    /// length above 128 bits or a truncated prefix.
    pub fn parse(t: &RawTlv<'a>) -> Result<Self> {
        let [domain_id, len, rest @ ..] = t.value else {
            return Err(Error::Parse);
        };
        let n = usize::from(*len).div_ceil(8);
        if *len > 128 || rest.len() < n {
            return Err(Error::Parse);
        }
        Ok(Self {
            stable: t.stable,
            domain_id: *domain_id,
            prefix: NetPrefix::new(&rest[..n], *len)?,
            subs: &rest[n..],
        })
    }

    /// Sub-TLVs.
    pub fn sub_tlvs(&self) -> RawIter<'a> {
        RawIter::new(self.subs)
    }
}

// ------------------------------------------------------------------ route preference

/// Route preference from the 2-bit wire encoding: high 1, medium 0, low 3
/// (the reserved value 2 reads as medium).
pub const fn preference_from_bits(bits: u8) -> i8 {
    match bits & 3 {
        1 => 1,
        3 => -1,
        _ => 0,
    }
}

/// Inverse of [`preference_from_bits`] (positive = high, negative = low).
pub const fn preference_to_bits(p: i8) -> u8 {
    if p > 0 {
        1
    } else if p < 0 {
        3
    } else {
        0
    }
}

// ------------------------------------------------------------------ has route

/// One entry of a Has Route TLV (3 bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct HasRouteEntry {
    /// RLOC16 of the border router.
    pub rloc16: u16,
    /// Route preference (-1 low, 0 medium, 1 high).
    pub preference: i8,
    /// NAT64 prefix.
    pub nat64: bool,
    /// Advertising PIO (RA Prefix Information Option) flag.
    pub adv_pio: bool,
}

impl HasRouteEntry {
    /// Wire size.
    pub const SIZE: usize = 3;

    /// Flags byte.
    pub const fn flags(&self) -> u8 {
        preference_to_bits(self.preference) << 6
            | (self.nat64 as u8) << 5
            | (self.adv_pio as u8) << 4
    }

    /// Decode from 3 bytes.
    pub fn parse(b: &[u8]) -> Option<Self> {
        let [h, l, f] = *b else { return None };
        Some(Self {
            rloc16: u16::from_be_bytes([h, l]),
            preference: preference_from_bits(f >> 6),
            nat64: f & (1 << 5) != 0,
            adv_pio: f & (1 << 4) != 0,
        })
    }

    /// Encode.
    pub fn write(&self, w: &mut Writer<'_>) -> Result<()> {
        w.write_u16(self.rloc16)?;
        w.write_u8(self.flags())
    }
}

// ------------------------------------------------------------------ border router

/// Border Router entry flags (the 16 bits after the RLOC16; OT
/// `BorderRouterEntry`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct BrFlags(pub u16);

impl BrFlags {
    /// Preferred (SLAAC address is preferred).
    pub const PREFERRED: u16 = 1 << 13;
    /// SLAAC.
    pub const SLAAC: u16 = 1 << 12;
    /// DHCPv6 address server.
    pub const DHCP: u16 = 1 << 11;
    /// DHCPv6 other configuration data.
    pub const CONFIGURE: u16 = 1 << 10;
    /// Default route.
    pub const DEFAULT_ROUTE: u16 = 1 << 9;
    /// On-mesh.
    pub const ON_MESH: u16 = 1 << 8;
    /// ND DNS.
    pub const ND_DNS: u16 = 1 << 7;
    /// Domain prefix.
    pub const DP: u16 = 1 << 6;

    /// Test a flag constant.
    pub const fn has(&self, flag: u16) -> bool {
        self.0 & flag != 0
    }

    /// Set or clear a flag constant.
    pub const fn with(mut self, flag: u16, on: bool) -> Self {
        if on {
            self.0 |= flag;
        } else {
            self.0 &= !flag;
        }
        self
    }

    /// Route preference (-1, 0, 1).
    pub const fn preference(&self) -> i8 {
        preference_from_bits((self.0 >> 14) as u8)
    }

    /// Set the route preference.
    pub const fn with_preference(mut self, p: i8) -> Self {
        self.0 = (self.0 & !(3 << 14)) | (preference_to_bits(p) as u16) << 14;
        self
    }

    /// Flags without the preference (used to compare entries).
    pub const fn without_preference(&self) -> u16 {
        self.0 & !(3 << 14)
    }
}

/// One entry of a Border Router TLV (4 bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct BorderRouterEntry {
    /// RLOC16 of the border router (for a stable copy: `0xfffe` or
    /// `0xfc00 | context id`).
    pub rloc16: u16,
    /// Flags.
    pub flags: BrFlags,
}

impl BorderRouterEntry {
    /// Wire size.
    pub const SIZE: usize = 4;

    /// Decode from 4 bytes.
    pub fn parse(b: &[u8]) -> Option<Self> {
        let [a, b2, c, d] = *b else { return None };
        Some(Self {
            rloc16: u16::from_be_bytes([a, b2]),
            flags: BrFlags(u16::from_be_bytes([c, d])),
        })
    }

    /// Encode.
    pub fn write(&self, w: &mut Writer<'_>) -> Result<()> {
        w.write_u16(self.rloc16)?;
        w.write_u16(self.flags.0)
    }
}

// ------------------------------------------------------------------ context

/// 6LoWPAN Context ID flags byte: compress flag.
pub const CONTEXT_COMPRESS: u8 = 1 << 4;

/// A parsed 6LoWPAN Context ID sub-TLV.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct ContextTlv {
    /// Context ID (0-15).
    pub id: u8,
    /// Compression allowed.
    pub compress: bool,
    /// Prefix length in bits.
    pub len: u8,
    /// Stable flag.
    pub stable: bool,
}

impl ContextTlv {
    /// Interpret `t` (a sub-TLV of a Prefix TLV).
    pub fn parse(t: &RawTlv<'_>) -> Result<Self> {
        let [f, len, ..] = *t.value else {
            return Err(Error::Parse);
        };
        Ok(Self {
            id: f & 0x0f,
            compress: f & CONTEXT_COMPRESS != 0,
            len,
            stable: t.stable,
        })
    }
}

// ------------------------------------------------------------------ service

/// A parsed Service TLV (without its Server sub-TLVs).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServiceTlv<'a> {
    /// Stable flag.
    pub stable: bool,
    /// Service ID (4 bits).
    pub service_id: u8,
    /// Enterprise number ([`THREAD_ENTERPRISE_NUMBER`] if the T flag is set).
    pub enterprise_number: u32,
    /// Service data.
    pub service_data: &'a [u8],
    /// Server sub-TLVs.
    pub subs: &'a [u8],
}

impl<'a> ServiceTlv<'a> {
    /// Interpret `t` as a Service TLV.
    pub fn parse(t: &RawTlv<'a>) -> Result<Self> {
        let [f, rest @ ..] = t.value else {
            return Err(Error::Parse);
        };
        let (enterprise_number, rest) = if f & 0x80 != 0 {
            (THREAD_ENTERPRISE_NUMBER, rest)
        } else {
            let (e, r) = rest.split_first_chunk::<4>().ok_or(Error::Parse)?;
            (u32::from_be_bytes(*e), r)
        };
        let [dl, rest @ ..] = rest else {
            return Err(Error::Parse);
        };
        let dl = usize::from(*dl);
        if rest.len() < dl {
            return Err(Error::Parse);
        }
        Ok(Self {
            stable: t.stable,
            service_id: f & 0x0f,
            enterprise_number,
            service_data: &rest[..dl],
            subs: &rest[dl..],
        })
    }

    /// Server sub-TLVs.
    pub fn servers(&self) -> impl Iterator<Item = ServerTlv<'a>> + 'a {
        RawIter::new(self.subs)
            .filter(|t| t.ty == ty::SERVER)
            .filter_map(|t| ServerTlv::parse(&t).ok())
    }
}

/// A parsed Server sub-TLV.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServerTlv<'a> {
    /// Stable flag.
    pub stable: bool,
    /// RLOC16 of the server (in a stable copy: the service ALOC16).
    pub rloc16: u16,
    /// Server data.
    pub server_data: &'a [u8],
}

impl<'a> ServerTlv<'a> {
    /// Interpret `t` as a Server TLV.
    pub fn parse(t: &RawTlv<'a>) -> Result<Self> {
        let [a, b, rest @ ..] = t.value else {
            return Err(Error::Parse);
        };
        Ok(Self {
            stable: t.stable,
            rloc16: u16::from_be_bytes([*a, *b]),
            server_data: rest,
        })
    }
}

// ------------------------------------------------------------------ writers

/// Start a TLV in `w`: writes type and a zero length; pass the returned
/// offset to [`end_tlv`] once the value is written.
pub fn begin_tlv(w: &mut Writer<'_>, ty: u8, stable: bool) -> Result<usize> {
    let off = w.len();
    w.write_u8(ty << 1 | u8::from(stable))?;
    w.write_u8(0)?;
    Ok(off)
}

/// Patch the length of the TLV started at `off`. [`Error::NoBufs`] if the
/// value exceeds 255 bytes.
pub fn end_tlv(w: &mut Writer<'_>, off: usize) -> Result<()> {
    let len = w.len() - off - 2;
    w.written_mut()[off + 1] = u8::try_from(len).map_err(|_| Error::NoBufs)?;
    Ok(())
}

/// Write a complete TLV with a flat value.
pub fn write_tlv(w: &mut Writer<'_>, ty: u8, stable: bool, value: &[u8]) -> Result<()> {
    RawTlv { ty, stable, value }.write(w)
}

/// Write the header of a Prefix TLV and run `subs` for the sub-TLVs.
pub fn write_prefix(
    w: &mut Writer<'_>,
    stable: bool,
    domain_id: u8,
    prefix: &NetPrefix,
    subs: impl FnOnce(&mut Writer<'_>) -> Result<()>,
) -> Result<()> {
    let off = begin_tlv(w, ty::PREFIX, stable)?;
    w.write_u8(domain_id)?;
    w.write_u8(prefix.len())?;
    w.write_slice(prefix.as_bytes())?;
    subs(w)?;
    end_tlv(w, off)
}

/// Write a Has Route TLV.
pub fn write_has_route(w: &mut Writer<'_>, stable: bool, entries: &[HasRouteEntry]) -> Result<()> {
    let off = begin_tlv(w, ty::HAS_ROUTE, stable)?;
    for e in entries {
        e.write(w)?;
    }
    end_tlv(w, off)
}

/// Write a Border Router TLV.
pub fn write_border_router(
    w: &mut Writer<'_>,
    stable: bool,
    entries: &[BorderRouterEntry],
) -> Result<()> {
    let off = begin_tlv(w, ty::BORDER_ROUTER, stable)?;
    for e in entries {
        e.write(w)?;
    }
    end_tlv(w, off)
}

/// Write a 6LoWPAN Context ID sub-TLV.
pub fn write_context(
    w: &mut Writer<'_>,
    stable: bool,
    id: u8,
    compress: bool,
    prefix_len: u8,
) -> Result<()> {
    write_tlv(
        w,
        ty::CONTEXT,
        stable,
        &[
            (id & 0x0f) | if compress { CONTEXT_COMPRESS } else { 0 },
            prefix_len,
        ],
    )
}

/// Write the header of a Service TLV and run `servers` for the sub-TLVs.
pub fn write_service(
    w: &mut Writer<'_>,
    stable: bool,
    service_id: u8,
    enterprise_number: u32,
    service_data: &[u8],
    servers: impl FnOnce(&mut Writer<'_>) -> Result<()>,
) -> Result<()> {
    let off = begin_tlv(w, ty::SERVICE, stable)?;
    if enterprise_number == THREAD_ENTERPRISE_NUMBER {
        w.write_u8(0x80 | (service_id & 0x0f))?;
    } else {
        w.write_u8(service_id & 0x0f)?;
        w.write_u32(enterprise_number)?;
    }
    w.write_u8(u8::try_from(service_data.len()).map_err(|_| Error::NoBufs)?)?;
    w.write_slice(service_data)?;
    servers(w)?;
    end_tlv(w, off)
}

/// Write a Server sub-TLV.
pub fn write_server(
    w: &mut Writer<'_>,
    stable: bool,
    rloc16: u16,
    server_data: &[u8],
) -> Result<()> {
    let off = begin_tlv(w, ty::SERVER, stable)?;
    w.write_u16(rloc16)?;
    w.write_slice(server_data)?;
    end_tlv(w, off)
}
