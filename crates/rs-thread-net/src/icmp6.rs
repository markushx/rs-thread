//! ICMPv6 (RFC 4443) message types and builders for the messages Thread
//! uses: echo request/reply and the error messages (destination
//! unreachable, packet too big, time exceeded, parameter problem).
//!
//! Neighbour Discovery messages are not used on the Thread interface and are
//! only named here ([`TYPE_ROUTER_SOLICIT`] ...) so they can be filtered.

use core::net::Ipv6Addr;

use rs_thread_core::{Error, Result};

use crate::checksum;
use crate::header::{Ipv6Header, MIN_MTU, PROTO_ICMP6};

/// Destination Unreachable.
pub const TYPE_DST_UNREACH: u8 = 1;
/// Packet Too Big.
pub const TYPE_PACKET_TOO_BIG: u8 = 2;
/// Time Exceeded.
pub const TYPE_TIME_EXCEEDED: u8 = 3;
/// Parameter Problem.
pub const TYPE_PARAMETER_PROBLEM: u8 = 4;
/// Echo Request.
pub const TYPE_ECHO_REQUEST: u8 = 128;
/// Echo Reply.
pub const TYPE_ECHO_REPLY: u8 = 129;
/// Router Solicitation.
pub const TYPE_ROUTER_SOLICIT: u8 = 133;
/// Router Advertisement.
pub const TYPE_ROUTER_ADVERT: u8 = 134;
/// Neighbor Solicitation.
pub const TYPE_NEIGHBOR_SOLICIT: u8 = 135;
/// Neighbor Advertisement.
pub const TYPE_NEIGHBOR_ADVERT: u8 = 136;

/// Dest Unreachable code: no route to destination.
pub const CODE_DST_UNREACH_NO_ROUTE: u8 = 0;
/// Dest Unreachable code: administratively prohibited.
pub const CODE_DST_UNREACH_PROHIBITED: u8 = 1;
/// Dest Unreachable code: address unreachable.
pub const CODE_DST_UNREACH_ADDRESS: u8 = 3;
/// Dest Unreachable code: port unreachable.
pub const CODE_DST_UNREACH_PORT: u8 = 4;
/// Time Exceeded code: hop limit exceeded in transit.
pub const CODE_HOP_LIMIT_EXCEEDED: u8 = 0;
/// Time Exceeded code: fragment reassembly time exceeded.
pub const CODE_FRAGM_REAS_TIME_EX: u8 = 1;
/// Parameter Problem code: erroneous header field.
pub const CODE_PARAM_HEADER_FIELD: u8 = 0;
/// Parameter Problem code: unrecognized next header.
pub const CODE_PARAM_NEXT_HEADER: u8 = 1;
/// Parameter Problem code: unrecognized IPv6 option.
pub const CODE_PARAM_OPTION: u8 = 2;

/// ICMPv6 types that may be forwarded through the mesh (OT `kForwardIcmpTypes`).
pub const FORWARDED_TYPES: [u8; 6] = [
    TYPE_DST_UNREACH,
    TYPE_PACKET_TOO_BIG,
    TYPE_TIME_EXCEEDED,
    TYPE_PARAMETER_PROBLEM,
    TYPE_ECHO_REQUEST,
    TYPE_ECHO_REPLY,
];

/// `true` for ICMPv6 error messages (types below 128).
pub const fn is_error(ty: u8) -> bool {
    ty < TYPE_ECHO_REQUEST
}

/// The 8-byte ICMPv6 header (type, code, checksum, 4 bytes of message data).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Icmp6Header {
    /// Message type.
    pub ty: u8,
    /// Message code.
    pub code: u8,
    /// Checksum.
    pub checksum: u16,
    /// Message-specific data: echo identifier + sequence, MTU, pointer, or unused.
    pub data: [u8; 4],
}

impl Icmp6Header {
    /// Encoded length.
    pub const LEN: usize = 8;

    /// Parse from the start of `b`.
    pub fn parse(b: &[u8]) -> Result<Self> {
        let b = b.get(..Self::LEN).ok_or(Error::Parse)?;
        Ok(Self {
            ty: b[0],
            code: b[1],
            checksum: u16::from_be_bytes([b[2], b[3]]),
            data: [b[4], b[5], b[6], b[7]],
        })
    }

    /// Encode into `out`.
    pub fn write(&self, out: &mut [u8]) -> Result<()> {
        let o = out.get_mut(..Self::LEN).ok_or(Error::NoBufs)?;
        o[0] = self.ty;
        o[1] = self.code;
        o[2..4].copy_from_slice(&self.checksum.to_be_bytes());
        o[4..8].copy_from_slice(&self.data);
        Ok(())
    }

    /// Echo identifier (echo messages).
    pub const fn echo_id(&self) -> u16 {
        u16::from_be_bytes([self.data[0], self.data[1]])
    }

    /// Echo sequence number (echo messages).
    pub const fn echo_seq(&self) -> u16 {
        u16::from_be_bytes([self.data[2], self.data[3]])
    }

    /// `true` for error messages.
    pub const fn is_error(&self) -> bool {
        is_error(self.ty)
    }
}

/// An ICMPv6 message to be wrapped into an IPv6 datagram.
#[derive(Debug, Clone, Copy)]
pub struct Icmp6Message<'a> {
    /// Message type.
    pub ty: u8,
    /// Message code.
    pub code: u8,
    /// Message-specific 4 bytes after the checksum.
    pub data: [u8; 4],
    /// Message body.
    pub body: &'a [u8],
}

/// Build a complete IPv6 datagram `[IPv6 header | ICMPv6 header | body]`
/// with a valid checksum. Returns the datagram length.
pub fn build_datagram(
    src: &Ipv6Addr,
    dst: &Ipv6Addr,
    hop_limit: u8,
    msg: &Icmp6Message<'_>,
    out: &mut [u8],
) -> Result<usize> {
    let total = Ipv6Header::LEN + Icmp6Header::LEN + msg.body.len();
    if total > out.len() || total > Ipv6Header::LEN + usize::from(u16::MAX) {
        return Err(Error::NoBufs);
    }
    let mut h = Ipv6Header::new(PROTO_ICMP6, hop_limit, *src, *dst);
    h.payload_len = (total - Ipv6Header::LEN) as u16;
    h.write(out)?;
    let icmp = &mut out[Ipv6Header::LEN..total];
    Icmp6Header {
        ty: msg.ty,
        code: msg.code,
        checksum: 0,
        data: msg.data,
    }
    .write(icmp)?;
    icmp[Icmp6Header::LEN..].copy_from_slice(msg.body);
    checksum::update(src, dst, PROTO_ICMP6, icmp)?;
    Ok(total)
}

/// Build an Echo Request datagram (body = payload).
pub fn build_echo_request(
    src: &Ipv6Addr,
    dst: &Ipv6Addr,
    hop_limit: u8,
    id: u16,
    seq: u16,
    payload: &[u8],
    out: &mut [u8],
) -> Result<usize> {
    let mut d = [0u8; 4];
    d[..2].copy_from_slice(&id.to_be_bytes());
    d[2..].copy_from_slice(&seq.to_be_bytes());
    let msg = Icmp6Message {
        ty: TYPE_ECHO_REQUEST,
        code: 0,
        data: d,
        body: payload,
    };
    build_datagram(src, dst, hop_limit, &msg, out)
}

/// Build an ICMPv6 error datagram quoting as much of `invoking` (the
/// offending IPv6 datagram) as fits in the IPv6 minimum MTU (RFC 4443
/// section 2.4(c)). `(ty, code, data)`: `data` is the message-specific field
/// (MTU, pointer or zero).
pub fn build_error(
    src: &Ipv6Addr,
    dst: &Ipv6Addr,
    hop_limit: u8,
    (ty, code, data): (u8, u8, u32),
    invoking: &[u8],
    out: &mut [u8],
) -> Result<usize> {
    let room = MIN_MTU - Ipv6Header::LEN - Icmp6Header::LEN;
    let msg = Icmp6Message {
        ty,
        code,
        data: data.to_be_bytes(),
        body: &invoking[..invoking.len().min(room)],
    };
    build_datagram(src, dst, hop_limit, &msg, out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: Ipv6Addr = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1);
    const B: Ipv6Addr = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2);

    #[test]
    fn echo_request_builds_and_verifies() {
        let mut out = [0u8; 100];
        let n = build_echo_request(&A, &B, 64, 0x1234, 7, b"hello", &mut out).unwrap();
        assert_eq!(n, 40 + 8 + 5);
        let h = Ipv6Header::parse(&out).unwrap();
        assert_eq!(h.next_header, PROTO_ICMP6);
        assert_eq!(h.payload_len, 13);
        let i = Icmp6Header::parse(&out[40..n]).unwrap();
        assert_eq!(
            (i.ty, i.echo_id(), i.echo_seq()),
            (TYPE_ECHO_REQUEST, 0x1234, 7)
        );
        assert!(!i.is_error());
        assert!(checksum::verify(&A, &B, PROTO_ICMP6, &out[40..n]));
    }

    #[test]
    fn error_is_truncated_to_min_mtu() {
        let inv = [0x60u8; 2000];
        let mut out = [0u8; 1500];
        let n = build_error(
            &A,
            &B,
            64,
            (TYPE_DST_UNREACH, CODE_DST_UNREACH_NO_ROUTE, 0),
            &inv,
            &mut out,
        )
        .unwrap();
        assert_eq!(n, 1280);
        assert!(checksum::verify(&A, &B, PROTO_ICMP6, &out[40..n]));
        assert!(Icmp6Header::parse(&out[40..n]).unwrap().is_error());
        let n = build_error(
            &A,
            &B,
            64,
            (TYPE_PACKET_TOO_BIG, 0, 1280),
            &inv[..60],
            &mut out,
        )
        .unwrap();
        assert_eq!(n, 40 + 8 + 60);
        assert_eq!(&out[44..48], &1280u32.to_be_bytes());
    }

    #[test]
    fn small_buffers_and_truncated_headers() {
        let mut out = [0u8; 20];
        assert_eq!(
            build_echo_request(&A, &B, 1, 0, 0, &[], &mut out),
            Err(Error::NoBufs)
        );
        for l in 0..8 {
            assert_eq!(Icmp6Header::parse(&[0u8; 8][..l]), Err(Error::Parse));
        }
    }
}
