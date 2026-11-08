//! Top-level 6LoWPAN frame dispatch and mesh forwarding decisions (FTD).
//!
//! [`parse_frame`] classifies a MAC payload like OpenThread's
//! `MeshForwarder::HandleReceivedFrame`. [`handle_mesh`] implements the
//! decision of `MeshForwarder::HandleMesh` for a frame carrying a Mesh
//! header: deliver locally, forward to the next hop, or drop. The routing
//! table itself is consulted through the [`NextHops`] trait and
//! the device's own addresses (own RLOC16, children) through
//! [`LocalRlocs`].

use opentrust_core::{Error, Result};

use crate::frag::FragmentHeader;
use crate::mesh::MeshHeader;

/// Kind of a 6LoWPAN MAC payload, without parsing it further.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Dispatch {
    /// Mesh Addressing header (`10xxxxxx`).
    Mesh,
    /// FRAG1 / FRAGN header.
    Fragment,
    /// LOWPAN_IPHC compressed IPv6 header (`011xxxxx`).
    Iphc,
    /// Empty payload (e.g. keep-alive data frame).
    Empty,
    /// Anything else (uncompressed IPv6, LOWPAN_BC0, ...), not supported by
    /// Thread.
    Unsupported,
}

/// Classify a MAC payload by its dispatch byte, using the same precedence
/// as OpenThread: mesh header, fragment header, IPHC.
pub fn classify(payload: &[u8]) -> Dispatch {
    if payload.is_empty() {
        Dispatch::Empty
    } else if MeshHeader::is_mesh_header(payload) {
        Dispatch::Mesh
    } else if FragmentHeader::is_fragment_header(payload) {
        Dispatch::Fragment
    } else if payload[0] & 0xe0 == 0x60 {
        Dispatch::Iphc
    } else {
        Dispatch::Unsupported
    }
}

/// A MAC payload split into its outermost 6LoWPAN header and the rest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LowpanFrame<'a> {
    /// Mesh header followed by `payload` (a fragment or IPHC frame, see
    /// [`parse_inner`]).
    Mesh {
        /// The mesh header.
        header: MeshHeader,
        /// Bytes after the mesh header.
        payload: &'a [u8],
    },
    /// Fragment header followed by `payload` (compressed header + data for
    /// FRAG1, raw datagram bytes for FRAGN).
    Fragment {
        /// The fragment header.
        header: FragmentHeader,
        /// Bytes after the fragment header.
        payload: &'a [u8],
    },
    /// A LOWPAN_IPHC frame (the whole slice, including the IPHC header).
    Iphc(&'a [u8]),
    /// Empty payload.
    Empty,
}

/// Parse the outermost 6LoWPAN header of a MAC payload.
///
/// Errors with [`Error::Parse`] for unsupported dispatch values and
/// truncated headers.
pub fn parse_frame(payload: &[u8]) -> Result<LowpanFrame<'_>> {
    match classify(payload) {
        Dispatch::Empty => Ok(LowpanFrame::Empty),
        Dispatch::Mesh => {
            let (header, n) = MeshHeader::parse(payload)?;
            Ok(LowpanFrame::Mesh {
                header,
                payload: &payload[n..],
            })
        }
        Dispatch::Fragment => {
            let (header, n) = FragmentHeader::parse(payload)?;
            Ok(LowpanFrame::Fragment {
                header,
                payload: &payload[n..],
            })
        }
        Dispatch::Iphc => Ok(LowpanFrame::Iphc(payload)),
        Dispatch::Unsupported => Err(Error::Parse),
    }
}

/// Parse the payload inside a Mesh header: only a fragment or IPHC frame is
/// valid there (no nested mesh header, no empty payload).
pub fn parse_inner(payload: &[u8]) -> Result<LowpanFrame<'_>> {
    match parse_frame(payload)? {
        LowpanFrame::Mesh { .. } | LowpanFrame::Empty => Err(Error::Parse),
        f => Ok(f),
    }
}

/// Which RLOC16s terminate at this device.
pub trait LocalRlocs {
    /// `true` if `rloc16` is this device's RLOC16 or that of an attached
    /// child (including sleepy children served by this parent).
    fn is_local(&self, rloc16: u16) -> bool;
}

impl LocalRlocs for u16 {
    fn is_local(&self, rloc16: u16) -> bool {
        *self == rloc16
    }
}

impl<F: Fn(u16) -> bool> LocalRlocs for F {
    fn is_local(&self, rloc16: u16) -> bool {
        self(rloc16)
    }
}

/// Next-hop lookup in the routing table (provided by the MLE router table).
pub trait NextHops {
    /// The RLOC16 of the next hop towards `destination`, if there is a route.
    fn next_hop(&self, destination: u16) -> Option<u16>;
}

impl<F: Fn(u16) -> Option<u16>> NextHops for F {
    fn next_hop(&self, destination: u16) -> Option<u16> {
        self(destination)
    }
}

/// Why a mesh frame was dropped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum DropReason {
    /// The frame was not secured at the link layer.
    Security,
    /// Malformed mesh header or inner payload.
    Parse,
    /// Not for this device and no hops left.
    HopsExhausted,
    /// No route to the final destination.
    NoRoute,
    /// The frame came from the neighbour that is our next hop towards the
    /// destination (2-hop routing loop). The caller should invalidate that
    /// route (as OpenThread's `ResolveRoutingLoops` does).
    RoutingLoop,
}

/// Decision for a received frame with a Mesh header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MeshOutcome<'a> {
    /// The datagram is for this device (or a child): process `payload`
    /// (a fragment or IPHC frame, see [`parse_inner`]) using the mesh
    /// originator/destination as the IPHC MAC addresses.
    Deliver {
        /// The received mesh header.
        header: MeshHeader,
        /// Bytes after the mesh header.
        payload: &'a [u8],
    },
    /// Forward the frame to `next_hop`: send `header` (hops left already
    /// decremented) followed by `payload`, e.g. via [`rewrite`].
    Forward {
        /// RLOC16 of the next hop.
        next_hop: u16,
        /// Mesh header to send (hops left decremented).
        header: MeshHeader,
        /// Bytes after the mesh header (unchanged).
        payload: &'a [u8],
    },
    /// Drop the frame.
    Drop(DropReason),
}

/// Decide what to do with a MAC payload that starts with a Mesh header.
///
/// - `link_security`: whether the frame was secured at the link layer (only
///   secured mesh frames are processed),
/// - `local`: this device's addresses,
/// - `routes`: next-hop lookup,
/// - `prev_hop`: RLOC16 of the neighbour the frame was received from, if
///   it has a short address (for routing loop detection).
pub fn handle_mesh<'a, L, R>(
    frame: &'a [u8],
    link_security: bool,
    local: &L,
    routes: &R,
    prev_hop: Option<u16>,
) -> MeshOutcome<'a>
where
    L: LocalRlocs + ?Sized,
    R: NextHops + ?Sized,
{
    if !link_security {
        return MeshOutcome::Drop(DropReason::Security);
    }
    let Ok((mut header, n)) = MeshHeader::parse(frame) else {
        return MeshOutcome::Drop(DropReason::Parse);
    };
    let payload = &frame[n..];

    if local.is_local(header.destination) {
        if parse_inner(payload).is_err() {
            return MeshOutcome::Drop(DropReason::Parse);
        }
        return MeshOutcome::Deliver { header, payload };
    }
    if header.hops_left == 0 {
        return MeshOutcome::Drop(DropReason::HopsExhausted);
    }
    let Some(next_hop) = routes.next_hop(header.destination) else {
        return MeshOutcome::Drop(DropReason::NoRoute);
    };
    if prev_hop == Some(next_hop) {
        return MeshOutcome::Drop(DropReason::RoutingLoop);
    }
    header.decrement_hops_left();
    MeshOutcome::Forward {
        next_hop,
        header,
        payload,
    }
}

/// Write `header` followed by `payload` into `out`; returns the length.
/// Used to build the frame to forward after [`handle_mesh`].
pub fn rewrite(header: &MeshHeader, payload: &[u8], out: &mut [u8]) -> Result<usize> {
    let n = header.write(out)?;
    let end = n.checked_add(payload.len()).ok_or(Error::NoBufs)?;
    out.get_mut(n..end)
        .ok_or(Error::NoBufs)?
        .copy_from_slice(payload);
    Ok(end)
}
