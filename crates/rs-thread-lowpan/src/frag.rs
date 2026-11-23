//! 6LoWPAN fragmentation (RFC 4944 §5.3): FRAG1/FRAGN headers and the
//! [`Fragmenter`] that splits a datagram into MAC-frame-sized payloads.
//!
//! Mirrors OpenThread's `Lowpan::FragmentHeader` and
//! `MeshForwarder::PrepareDataFrame`.

use rs_thread_core::{Error, Result};
use rs_thread_mac::frame::Address;

use crate::iphc::{ContextProvider, compress};
use crate::mesh::MeshHeader;

const DISPATCH: u8 = 0xc0;
/// Accepts FRAG1 (`0b11000xxx`) and FRAGN (`0b11100xxx`).
const DISPATCH_MASK: u8 = 0xd8;
const OFFSET_FLAG: u8 = 1 << 5;
const SIZE_MASK: u16 = 0x07ff;

/// A fragment header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct FragmentHeader {
    /// Size of the whole (uncompressed) datagram, 11 bits.
    pub datagram_size: u16,
    /// Datagram tag shared by all fragments of a datagram.
    pub datagram_tag: u16,
    /// Offset of this fragment in the uncompressed datagram, in bytes
    /// (a multiple of 8; 0 for FRAG1).
    pub datagram_offset: u16,
}

impl FragmentHeader {
    /// Length of a FRAG1 header.
    pub const FIRST_LEN: usize = 4;
    /// Length of a FRAGN header.
    pub const NEXT_LEN: usize = 5;

    /// A FRAG1 header.
    pub const fn first(size: u16, tag: u16) -> Self {
        Self {
            datagram_size: size,
            datagram_tag: tag,
            datagram_offset: 0,
        }
    }

    /// A FRAGN header; `offset` is truncated to a multiple of 8.
    pub const fn next(size: u16, tag: u16, offset: u16) -> Self {
        Self {
            datagram_size: size,
            datagram_tag: tag,
            datagram_offset: offset & !7,
        }
    }

    /// `true` if `frame` starts with a FRAG1/FRAGN dispatch and holds at
    /// least the FRAG1 header length.
    pub fn is_fragment_header(frame: &[u8]) -> bool {
        frame.len() >= Self::FIRST_LEN && frame[0] & DISPATCH_MASK == DISPATCH
    }

    /// Encoded length: FRAG1 for offset 0, FRAGN otherwise.
    pub const fn len(&self) -> usize {
        if self.datagram_offset == 0 {
            Self::FIRST_LEN
        } else {
            Self::NEXT_LEN
        }
    }

    /// Always `false`.
    pub const fn is_empty(&self) -> bool {
        false
    }

    /// Parse from the start of `frame`; returns the header and its length.
    /// A FRAGN with offset 0 is accepted (and treated as a first fragment
    /// by the reassembler, as OpenThread does).
    pub fn parse(frame: &[u8]) -> Result<(Self, usize)> {
        if !Self::is_fragment_header(frame) {
            return Err(Error::Parse);
        }
        let datagram_size = u16::from_be_bytes([frame[0], frame[1]]) & SIZE_MASK;
        let datagram_tag = u16::from_be_bytes([frame[2], frame[3]]);
        let (offset, len) = if frame[0] & OFFSET_FLAG != 0 {
            if frame.len() < Self::NEXT_LEN {
                return Err(Error::Parse);
            }
            (u16::from(frame[4]) * 8, Self::NEXT_LEN)
        } else {
            (0, Self::FIRST_LEN)
        };
        Ok((
            Self {
                datagram_size,
                datagram_tag,
                datagram_offset: offset,
            },
            len,
        ))
    }

    /// Write the header (FRAG1 if the offset is 0, else FRAGN); returns the
    /// number of bytes written.
    pub fn write(&self, out: &mut [u8]) -> Result<usize> {
        let len = self.len();
        let o = out.get_mut(..len).ok_or(Error::NoBufs)?;
        let size = self.datagram_size & SIZE_MASK;
        let dispatch = if len == Self::FIRST_LEN {
            0xc000
        } else {
            0xe000
        };
        o[0..2].copy_from_slice(&(dispatch | size).to_be_bytes());
        o[2..4].copy_from_slice(&self.datagram_tag.to_be_bytes());
        if len == Self::NEXT_LEN {
            o[4] = (self.datagram_offset >> 3) as u8;
        }
        Ok(len)
    }
}

/// Generator for datagram tags; never yields 0 (OpenThread uses 0 for
/// "tag not set").
#[derive(Debug, Clone, Copy)]
pub struct TagCounter(u16);

impl TagCounter {
    /// Create a counter starting at `seed` (use a random value).
    pub const fn new(seed: u16) -> Self {
        Self(seed)
    }

    /// The next tag.
    pub fn next_tag(&mut self) -> u16 {
        if self.0 == 0 {
            self.0 = 1;
        }
        let t = self.0;
        self.0 = self.0.wrapping_add(1);
        t
    }
}

/// Splits one uncompressed IPv6 datagram into 6LoWPAN frame payloads.
///
/// Call [`Fragmenter::next_frame`] repeatedly until it returns `None`. The
/// first frame carries the compressed headers (in a FRAG1 if the datagram
/// does not fit one frame); later frames carry FRAGN headers whose offsets
/// refer to the uncompressed datagram. If a Mesh header is given it is
/// prepended to every frame, and IPHC uses the mesh originator/destination
/// as its MAC addresses (as OpenThread does).
#[derive(Debug)]
pub struct Fragmenter<'a, C: ContextProvider + ?Sized> {
    ctxs: &'a C,
    mac_src: Address,
    mac_dst: Address,
    datagram: &'a [u8],
    tag: u16,
    mesh: Option<MeshHeader>,
    max_payload: usize,
    offset: usize,
    done: bool,
}

impl<'a, C: ContextProvider + ?Sized> Fragmenter<'a, C> {
    /// Create a fragmenter.
    ///
    /// - `mac_src` / `mac_dst`: link addresses of the frames (ignored in
    ///   favour of the mesh addresses if `mesh` is given),
    /// - `datagram`: the uncompressed IPv6 datagram,
    /// - `tag`: datagram tag (see [`TagCounter`]), used if fragmenting,
    /// - `max_payload`: the maximum MAC payload per frame, i.e. frame size
    ///   minus MAC header, security overhead and FCS. For frames with a Mesh
    ///   header use the fixed minimum of the 802.15.4 frame size, as the
    ///   forwarding path is unknown.
    pub fn new(
        ctxs: &'a C,
        mac_src: Address,
        mac_dst: Address,
        datagram: &'a [u8],
        tag: u16,
        mesh: Option<MeshHeader>,
        max_payload: usize,
    ) -> Self {
        Self {
            ctxs,
            mac_src,
            mac_dst,
            datagram,
            tag,
            mesh,
            max_payload,
            offset: 0,
            done: false,
        }
    }

    /// `true` once all frames were produced.
    pub fn is_done(&self) -> bool {
        self.done
    }

    /// Write the next frame payload into `out` and return its length, or
    /// `None` if all frames have been produced. On error the fragmenter
    /// should be dropped.
    pub fn next_frame(&mut self, out: &mut [u8]) -> Result<Option<usize>> {
        if self.done {
            return Ok(None);
        }
        let cap = out.len().min(self.max_payload);
        let out = &mut out[..cap];
        let mut pos = match &self.mesh {
            Some(m) => m.write(out)?,
            None => 0,
        };
        let len = self.datagram.len();

        if self.offset == 0 {
            let (src, dst) = match &self.mesh {
                Some(m) => (
                    Address::Short(rs_thread_core::types::ShortAddress(m.source)),
                    Address::Short(rs_thread_core::types::ShortAddress(m.destination)),
                ),
                None => (self.mac_src, self.mac_dst),
            };
            // Reserve room for a FRAG1 header so that compression leaves it.
            let frag_pos = pos;
            let room = out
                .get_mut(pos + FragmentHeader::FIRST_LEN..)
                .ok_or(Error::NoBufs)?;
            let c = compress(self.ctxs, &src, &dst, self.datagram, room)?;
            let payload = len - c.consumed;
            let hdr_end_plain = pos + c.header_len;

            if payload <= cap - hdr_end_plain {
                // Fits in one frame: drop the reserved FRAG1 room.
                let from = pos + FragmentHeader::FIRST_LEN;
                out.copy_within(from..from + c.header_len, pos);
                pos += c.header_len;
                out[pos..pos + payload].copy_from_slice(&self.datagram[c.consumed..]);
                self.done = true;
                return Ok(Some(pos + payload));
            }

            if len > usize::from(SIZE_MASK) {
                return Err(Error::InvalidArgs);
            }
            FragmentHeader::first(len as u16, self.tag).write(&mut out[frag_pos..])?;
            pos += FragmentHeader::FIRST_LEN + c.header_len;
            let n = (cap - pos) & !7;
            if n == 0 {
                return Err(Error::NoBufs);
            }
            out[pos..pos + n].copy_from_slice(&self.datagram[c.consumed..c.consumed + n]);
            self.offset = c.consumed + n;
            return Ok(Some(pos + n));
        }

        pos += FragmentHeader::next(len as u16, self.tag, self.offset as u16)
            .write(&mut out[pos..])?;
        let rest = len - self.offset;
        let avail = cap.checked_sub(pos).ok_or(Error::NoBufs)?;
        let n = if rest > avail { avail & !7 } else { rest };
        if n == 0 {
            return Err(Error::NoBufs);
        }
        out[pos..pos + n].copy_from_slice(&self.datagram[self.offset..self.offset + n]);
        self.offset += n;
        if self.offset >= len {
            self.done = true;
        }
        Ok(Some(pos + n))
    }
}
