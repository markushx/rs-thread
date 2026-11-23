//! Minimal IPv6 / UDP header representations used by the 6LoWPAN codecs.
//!
//! # Seam to the IPv6 layer
//!
//! `rs-thread-net` owns the full IPv6 stack. This module is
//! deliberately limited to what header compression needs: the fixed IPv6
//! header, the UDP header and the protocol numbers LOWPAN_NHC knows about.
//! The 6LoWPAN API otherwise exchanges plain byte slices (an uncompressed
//! IPv6 datagram, starting with the IPv6 header), so the IPv6 layer can swap
//! these types for its own without touching the codecs.

use core::net::Ipv6Addr;

use rs_thread_core::{Error, Result};

/// IPv6 next-header value: Hop-by-Hop Options.
pub const PROTO_HOP_OPTS: u8 = 0;
/// IPv6 next-header value: UDP.
pub const PROTO_UDP: u8 = 17;
/// IPv6 next-header value: IPv6 (IP-in-IP).
pub const PROTO_IPV6: u8 = 41;
/// IPv6 next-header value: Routing header.
pub const PROTO_ROUTING: u8 = 43;
/// IPv6 next-header value: Fragment header.
pub const PROTO_FRAGMENT: u8 = 44;
/// IPv6 next-header value: ICMPv6.
pub const PROTO_ICMP6: u8 = 58;
/// IPv6 next-header value: Destination Options.
pub const PROTO_DST_OPTS: u8 = 60;

/// Byte offset of the payload length field in the IPv6 header.
pub const OFFSET_PAYLOAD_LEN: usize = 4;
/// Byte offset of the next header field in the IPv6 header.
pub const OFFSET_NEXT_HEADER: usize = 6;
/// Byte offset of the hop limit field in the IPv6 header.
pub const OFFSET_HOP_LIMIT: usize = 7;

/// ECN codepoint "congestion experienced".
pub const ECN_MARKED: u8 = 3;

/// The fixed 40-byte IPv6 header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv6Header {
    /// Traffic class (DSCP in the upper 6 bits, ECN in the lower 2 bits).
    pub traffic_class: u8,
    /// 20-bit flow label.
    pub flow_label: u32,
    /// Payload length (everything after this header).
    pub payload_len: u16,
    /// Next header.
    pub next_header: u8,
    /// Hop limit.
    pub hop_limit: u8,
    /// Source address.
    pub src: Ipv6Addr,
    /// Destination address.
    pub dst: Ipv6Addr,
}

impl Ipv6Header {
    /// Encoded length.
    pub const LEN: usize = 40;

    /// DSCP (6 bits).
    pub const fn dscp(&self) -> u8 {
        self.traffic_class >> 2
    }

    /// ECN (2 bits).
    pub const fn ecn(&self) -> u8 {
        self.traffic_class & 0x03
    }

    /// A header with version 6, zero traffic class/flow and zero everything else.
    pub const fn new(next_header: u8, hop_limit: u8, src: Ipv6Addr, dst: Ipv6Addr) -> Self {
        Self {
            traffic_class: 0,
            flow_label: 0,
            payload_len: 0,
            next_header,
            hop_limit,
            src,
            dst,
        }
    }

    /// Set the DSCP (6 bits; higher bits are ignored), preserving ECN.
    pub fn set_dscp(&mut self, dscp: u8) {
        self.traffic_class = (self.traffic_class & 0x03) | ((dscp & 0x3f) << 2);
    }

    /// Set the ECN (2 bits; higher bits are ignored), preserving DSCP.
    pub fn set_ecn(&mut self, ecn: u8) {
        self.traffic_class = (self.traffic_class & 0xfc) | (ecn & 0x03);
    }

    /// Set the flow label (20 bits; higher bits are ignored).
    pub fn set_flow_label(&mut self, flow: u32) {
        self.flow_label = flow & 0x000f_ffff;
    }

    /// Parse the header from the start of `buf`; the version must be 6.
    pub fn parse(buf: &[u8]) -> Result<Self> {
        let b: &[u8; Self::LEN] = buf
            .get(..Self::LEN)
            .and_then(|s| s.try_into().ok())
            .ok_or(Error::Parse)?;
        if b[0] >> 4 != 6 {
            return Err(Error::Parse);
        }
        let mut src = [0u8; 16];
        let mut dst = [0u8; 16];
        src.copy_from_slice(&b[8..24]);
        dst.copy_from_slice(&b[24..40]);
        Ok(Self {
            traffic_class: (b[0] << 4) | (b[1] >> 4),
            flow_label: (u32::from(b[1] & 0x0f) << 16) | (u32::from(b[2]) << 8) | u32::from(b[3]),
            payload_len: u16::from_be_bytes([b[4], b[5]]),
            next_header: b[6],
            hop_limit: b[7],
            src: Ipv6Addr::from(src),
            dst: Ipv6Addr::from(dst),
        })
    }

    /// Encode into `out` (at least [`Self::LEN`] bytes).
    pub fn write(&self, out: &mut [u8]) -> Result<()> {
        let o: &mut [u8; Self::LEN] = out
            .get_mut(..Self::LEN)
            .and_then(|s| s.try_into().ok())
            .ok_or(Error::NoBufs)?;
        o[0] = 0x60 | (self.traffic_class >> 4);
        o[1] = (self.traffic_class << 4) | ((self.flow_label >> 16) as u8 & 0x0f);
        o[2] = (self.flow_label >> 8) as u8;
        o[3] = self.flow_label as u8;
        o[4..6].copy_from_slice(&self.payload_len.to_be_bytes());
        o[6] = self.next_header;
        o[7] = self.hop_limit;
        o[8..24].copy_from_slice(&self.src.octets());
        o[24..40].copy_from_slice(&self.dst.octets());
        Ok(())
    }
}

/// The 8-byte UDP header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct UdpHeader {
    /// Source port.
    pub src_port: u16,
    /// Destination port.
    pub dst_port: u16,
    /// Length of header plus payload.
    pub length: u16,
    /// Checksum.
    pub checksum: u16,
}

impl UdpHeader {
    /// Encoded length.
    pub const LEN: usize = 8;

    /// Parse from the start of `buf`.
    pub fn parse(buf: &[u8]) -> Result<Self> {
        let b = buf.get(..Self::LEN).ok_or(Error::Parse)?;
        Ok(Self {
            src_port: u16::from_be_bytes([b[0], b[1]]),
            dst_port: u16::from_be_bytes([b[2], b[3]]),
            length: u16::from_be_bytes([b[4], b[5]]),
            checksum: u16::from_be_bytes([b[6], b[7]]),
        })
    }

    /// Encode into `out` (at least [`Self::LEN`] bytes).
    pub fn write(&self, out: &mut [u8]) -> Result<()> {
        let o = out.get_mut(..Self::LEN).ok_or(Error::NoBufs)?;
        o[0..2].copy_from_slice(&self.src_port.to_be_bytes());
        o[2..4].copy_from_slice(&self.dst_port.to_be_bytes());
        o[4..6].copy_from_slice(&self.length.to_be_bytes());
        o[6..8].copy_from_slice(&self.checksum.to_be_bytes());
        Ok(())
    }
}
