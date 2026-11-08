//! Internet checksum (RFC 1071) and the IPv6 pseudo-header (RFC 8200 §8.1).
//!
//! Mirrors `net/checksum.cpp` of OpenThread for the UDP and ICMPv6 cases
//! (the TCP/IPv4 variants are not needed in Thread).

use core::net::Ipv6Addr;

use opentrust_core::{Error, Result};

use crate::header::{PROTO_ICMP6, PROTO_UDP};

/// Incremental one's-complement checksum accumulator.
///
/// Handles data supplied in arbitrary chunks, including odd-length chunks.
#[derive(Debug, Clone, Copy, Default)]
pub struct Checksum {
    sum: u32,
    /// A pending high byte when an odd number of bytes was added so far.
    pending: Option<u8>,
}

impl Checksum {
    /// An empty accumulator.
    pub const fn new() -> Self {
        Self {
            sum: 0,
            pending: None,
        }
    }

    /// Accumulator pre-loaded with the IPv6 pseudo-header for an upper-layer
    /// payload of `len` bytes.
    pub fn with_pseudo_header(src: &Ipv6Addr, dst: &Ipv6Addr, proto: u8, len: u32) -> Self {
        let mut c = Self::new();
        c.add_bytes(&src.octets());
        c.add_bytes(&dst.octets());
        c.add_bytes(&len.to_be_bytes());
        c.add_bytes(&[0, 0, 0, proto]);
        c
    }

    fn add_word(&mut self, w: u16) {
        self.sum += u32::from(w);
        if self.sum > 0xffff_0000 {
            self.sum = (self.sum & 0xffff) + (self.sum >> 16);
        }
    }

    /// Add a chunk of bytes.
    pub fn add_bytes(&mut self, mut data: &[u8]) {
        if let Some(hi) = self.pending
            && let Some((&lo, rest)) = data.split_first()
        {
            self.add_word(u16::from_be_bytes([hi, lo]));
            self.pending = None;
            data = rest;
        }
        let mut chunks = data.chunks_exact(2);
        for c in &mut chunks {
            self.add_word(u16::from_be_bytes([c[0], c[1]]));
        }
        if let [b] = chunks.remainder() {
            self.pending = Some(*b);
        }
    }

    /// The folded sum (not complemented), as `CalculateChecksum()` in
    /// OpenThread's `test_checksum.cpp`. A valid message sums to `0xffff`.
    pub fn folded(&self) -> u16 {
        let mut sum = self.sum;
        if let Some(hi) = self.pending {
            sum += u32::from(hi) << 8;
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        sum as u16
    }

    /// The checksum value to put in a header (complemented sum).
    pub fn finish(&self) -> u16 {
        !self.folded()
    }
}

/// Checksum of `payload` (with its checksum field zeroed) for the pseudo
/// header; for UDP a zero result is transmitted as `0xffff` (RFC 8200 §8.1).
pub fn compute(src: &Ipv6Addr, dst: &Ipv6Addr, proto: u8, payload: &[u8]) -> u16 {
    let mut c = Checksum::with_pseudo_header(src, dst, proto, payload.len() as u32);
    c.add_bytes(payload);
    let v = c.finish();
    if proto == PROTO_UDP && v == 0 {
        0xffff
    } else {
        v
    }
}

/// `true` if the payload (including its checksum field) verifies.
pub fn verify(src: &Ipv6Addr, dst: &Ipv6Addr, proto: u8, payload: &[u8]) -> bool {
    let mut c = Checksum::with_pseudo_header(src, dst, proto, payload.len() as u32);
    c.add_bytes(payload);
    c.folded() == 0xffff
}

/// Byte offset of the checksum field in the upper-layer header.
const fn checksum_offset(proto: u8) -> Option<usize> {
    match proto {
        PROTO_UDP => Some(6),
        PROTO_ICMP6 => Some(2),
        _ => None,
    }
}

/// Compute and store the checksum of a UDP or ICMPv6 payload in place.
pub fn update(src: &Ipv6Addr, dst: &Ipv6Addr, proto: u8, payload: &mut [u8]) -> Result<()> {
    let off = checksum_offset(proto).ok_or(Error::InvalidArgs)?;
    let field = payload.get_mut(off..off + 2).ok_or(Error::Parse)?;
    field.copy_from_slice(&[0, 0]);
    let v = compute(src, dst, proto, payload);
    payload[off..off + 2].copy_from_slice(&v.to_be_bytes());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Reference implementation as in OT `tests/unit/test_checksum.cpp`
    /// (`CalculateChecksum(const void *, uint16_t)`).
    fn reference(data: &[u8]) -> u16 {
        let mut sum: u32 = 0;
        let mut chunks = data.chunks_exact(2);
        for c in &mut chunks {
            sum += u32::from(u16::from_be_bytes([c[0], c[1]]));
        }
        if let [b] = chunks.remainder() {
            sum += u32::from(*b) << 8;
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        sum as u16
    }

    /// Deterministic xorshift for payload generation.
    fn fill(buf: &mut [u8], mut seed: u32) {
        for b in buf {
            seed ^= seed << 13;
            seed ^= seed >> 17;
            seed ^= seed << 5;
            *b = seed as u8;
        }
    }

    const SRC: Ipv6Addr = Ipv6Addr::new(
        0xfd00, 0x1122, 0x3344, 0x5566, 0x7788, 0x99aa, 0xbbcc, 0xddee,
    );
    const DST: Ipv6Addr = Ipv6Addr::new(
        0xfd01, 0x2345, 0x6789, 0xabcd, 0xef01, 0x2345, 0x6789, 0xabcd,
    );

    /// Port of `TestUdpMessageChecksum` / `TestIcmp6MessageChecksum`: for each
    /// size, `update` must agree with the reference sum over pseudo header +
    /// payload, verify, and detect any single-bit corruption.
    #[test]
    fn matches_reference_for_all_sizes() {
        for proto in [PROTO_UDP, PROTO_ICMP6] {
            let min = if proto == PROTO_UDP { 8 } else { 4 };
            for size in min..=400usize {
                let mut buf = [0u8; 400];
                fill(&mut buf[..size], size as u32 * 7919 + 1);
                let p = &mut buf[..size];
                update(&SRC, &DST, proto, p).unwrap();
                let mut pseudo = [0u8; 40 + 400];
                pseudo[..16].copy_from_slice(&SRC.octets());
                pseudo[16..32].copy_from_slice(&DST.octets());
                pseudo[32..36].copy_from_slice(&(size as u32).to_be_bytes());
                pseudo[39] = proto;
                pseudo[40..40 + size].copy_from_slice(p);
                assert_eq!(reference(&pseudo[..40 + size]), 0xffff, "size {size}");
                assert!(verify(&SRC, &DST, proto, p));
                // Corrupt one bit (position derived from the size).
                p[(size * 5) % size] ^= 1 << (size % 8);
                assert!(!verify(&SRC, &DST, proto, p), "size {size}");
            }
        }
    }

    #[test]
    fn chunked_equals_whole() {
        let mut buf = [0u8; 101];
        fill(&mut buf, 42);
        let whole = {
            let mut c = Checksum::new();
            c.add_bytes(&buf);
            c.finish()
        };
        for split in 0..buf.len() {
            let mut c = Checksum::new();
            c.add_bytes(&buf[..split]);
            c.add_bytes(&buf[split..]);
            assert_eq!(c.finish(), whole);
        }
        assert_eq!(!whole, reference(&buf));
    }

    #[test]
    fn rfc1071_example() {
        // RFC 1071 section 3: 00 01 f2 03 f4 f5 f6 f7 -> sum ddf2.
        let mut c = Checksum::new();
        c.add_bytes(&[0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7]);
        assert_eq!(c.folded(), 0xddf2);
    }

    #[test]
    fn udp_zero_becomes_ffff() {
        // Search a payload whose checksum would be 0 by tweaking one word.
        let mut p = [0u8; 10];
        p[0..2].copy_from_slice(&1000u16.to_be_bytes());
        p[4..6].copy_from_slice(&10u16.to_be_bytes());
        let mut found = false;
        for w in 0..=u16::MAX {
            p[8..10].copy_from_slice(&w.to_be_bytes());
            let mut c = Checksum::with_pseudo_header(&SRC, &DST, PROTO_UDP, 10);
            c.add_bytes(&p);
            if c.finish() == 0 {
                assert_eq!(compute(&SRC, &DST, PROTO_UDP, &p), 0xffff);
                found = true;
                break;
            }
        }
        assert!(found);
    }

    #[test]
    fn update_errors() {
        let mut p = [0u8; 4];
        assert_eq!(update(&SRC, &DST, PROTO_UDP, &mut p), Err(Error::Parse));
        assert_eq!(update(&SRC, &DST, 6, &mut p), Err(Error::InvalidArgs));
    }
}
