//! 6LoWPAN Mesh Addressing header (RFC 4944 §5.2).
//!
//! Thread only uses the form with 16-bit originator and final destination
//! addresses (both `V` and `F` bits set), carrying the RLOC16s of the
//! originating and final-destination routers/children.

use opentrust_core::{Error, Result};

const DISPATCH: u8 = 0x80;
const DISPATCH_MASK: u8 = 0xc0;
const SOURCE_SHORT: u8 = 1 << 5;
const DEST_SHORT: u8 = 1 << 4;
const HOPS_LEFT_MASK: u8 = 0x0f;
/// Hops-left value in the dispatch byte announcing a separate hops-left byte.
const DEEP_HOPS_LEFT: u8 = 0x0f;

/// Hops left OpenThread puts into originated Mesh headers
/// (`kMaxRouteCost + 3` with the default max route cost of 16).
pub const MESH_HEADER_HOPS_LEFT: u8 = 19;

/// A parsed or to-be-written Mesh Addressing header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct MeshHeader {
    /// Remaining hops (0-255; 15 and above use the "deep hops" encoding).
    pub hops_left: u8,
    /// Originator RLOC16.
    pub source: u16,
    /// Final destination RLOC16.
    pub destination: u16,
}

impl MeshHeader {
    /// Length without the deep-hops byte.
    pub const MIN_LEN: usize = 5;
    /// Length with the deep-hops byte.
    pub const DEEP_LEN: usize = 6;

    /// Create a header.
    pub const fn new(source: u16, destination: u16, hops_left: u8) -> Self {
        Self {
            hops_left,
            source,
            destination,
        }
    }

    /// `true` if `frame` starts with a Mesh header dispatch and is long
    /// enough to hold the minimal header.
    pub fn is_mesh_header(frame: &[u8]) -> bool {
        frame.len() >= Self::MIN_LEN && frame[0] & DISPATCH_MASK == DISPATCH
    }

    /// Encoded length of this header.
    pub const fn len(&self) -> usize {
        if self.hops_left >= DEEP_HOPS_LEFT {
            Self::DEEP_LEN
        } else {
            Self::MIN_LEN
        }
    }

    /// Always `false` (a header has at least [`Self::MIN_LEN`] bytes).
    pub const fn is_empty(&self) -> bool {
        false
    }

    /// Decrement the hops-left counter (saturating at 0).
    pub fn decrement_hops_left(&mut self) {
        self.hops_left = self.hops_left.saturating_sub(1);
    }

    /// Parse a header from the start of `frame`; returns it with its
    /// encoded length. Headers with 64-bit addresses are rejected.
    pub fn parse(frame: &[u8]) -> Result<(Self, usize)> {
        if frame.len() < Self::MIN_LEN {
            return Err(Error::Parse);
        }
        let d = frame[0];
        if d & (DISPATCH_MASK | SOURCE_SHORT | DEST_SHORT) != DISPATCH | SOURCE_SHORT | DEST_SHORT {
            return Err(Error::Parse);
        }
        let mut hops_left = d & HOPS_LEFT_MASK;
        let mut rest = &frame[1..];
        let mut len = Self::MIN_LEN;
        if hops_left == DEEP_HOPS_LEFT {
            if frame.len() < Self::DEEP_LEN {
                return Err(Error::Parse);
            }
            hops_left = rest[0];
            rest = &rest[1..];
            len = Self::DEEP_LEN;
        }
        Ok((
            Self {
                hops_left,
                source: u16::from_be_bytes([rest[0], rest[1]]),
                destination: u16::from_be_bytes([rest[2], rest[3]]),
            },
            len,
        ))
    }

    /// Write the header to `out`; returns the number of bytes written.
    pub fn write(&self, out: &mut [u8]) -> Result<usize> {
        let len = self.len();
        let o = out.get_mut(..len).ok_or(Error::NoBufs)?;
        let d = DISPATCH | SOURCE_SHORT | DEST_SHORT;
        let a = if len == Self::MIN_LEN {
            o[0] = d | self.hops_left;
            1
        } else {
            o[0] = d | DEEP_HOPS_LEFT;
            o[1] = self.hops_left;
            2
        };
        o[a..a + 2].copy_from_slice(&self.source.to_be_bytes());
        o[a + 2..a + 4].copy_from_slice(&self.destination.to_be_bytes());
        Ok(len)
    }
}
