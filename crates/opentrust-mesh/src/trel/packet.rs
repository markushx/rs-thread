//! TREL packet encapsulation header (OT `Trel::Header`, Thread 1.3 TREL
//! specification): one byte of control (type in bits 0-1, ack mode in bit 2,
//! version in bits 5-7), channel, PAN ID, packet number, source extended
//! address and, for unicast and ack packets, the destination extended
//! address. All fields are big-endian; the payload is an IEEE 802.15.4 frame
//! without FCS.

use opentrust_core::types::ExtAddress;
use opentrust_core::{Error, Result};

/// Header version (OT `kVersion`).
pub const VERSION: u8 = 0;
/// Length of a broadcast packet header.
pub const BROADCAST_HEADER_LEN: usize = 16;
/// Length of a unicast or ack packet header.
pub const UNICAST_HEADER_LEN: usize = 24;

const TYPE_MASK: u8 = 0b11;
const ACK_MODE_FLAG: u8 = 1 << 2;
const VERSION_MASK: u8 = 0b111 << 5;

/// TREL packet type (OT `Header::Type`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum PacketType {
    /// A packet for all peers.
    Broadcast,
    /// A packet for one peer.
    Unicast,
    /// Acknowledgment of a unicast packet.
    Ack,
}

impl PacketType {
    const fn from_bits(b: u8) -> Option<Self> {
        match b {
            0 => Some(Self::Broadcast),
            1 => Some(Self::Unicast),
            2 => Some(Self::Ack),
            _ => None,
        }
    }

    /// Header length of this packet type (OT `Header::GetSize`).
    pub const fn header_len(self) -> usize {
        match self {
            Self::Broadcast => BROADCAST_HEADER_LEN,
            Self::Unicast | Self::Ack => UNICAST_HEADER_LEN,
        }
    }
}

/// A TREL packet header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Header {
    /// Packet type.
    pub ty: PacketType,
    /// The receiver must acknowledge the packet.
    pub ack_requested: bool,
    /// Channel of the encapsulated frame.
    pub channel: u8,
    /// Destination PAN ID of the encapsulated frame (`0xffff`: broadcast).
    pub pan_id: u16,
    /// Per-peer (unicast) or per-sender (broadcast) packet number; an ack
    /// echoes the number of the packet it acknowledges.
    pub packet_number: u32,
    /// Extended address of the sender.
    pub source: ExtAddress,
    /// Extended address of the receiver (unicast and ack only).
    pub destination: Option<ExtAddress>,
}

impl Header {
    /// Length of the encoded header.
    pub const fn len(&self) -> usize {
        self.ty.header_len()
    }

    /// Never empty; for clippy's `len_without_is_empty`.
    pub const fn is_empty(&self) -> bool {
        false
    }

    /// Encode into `out`; returns the header length. [`Error::InvalidArgs`]
    /// for a unicast / ack header without destination, [`Error::NoBufs`] if
    /// `out` is too short.
    pub fn write(&self, out: &mut [u8]) -> Result<usize> {
        let n = self.len();
        if out.len() < n {
            return Err(Error::NoBufs);
        }
        let mut control = VERSION << 5;
        control |= match self.ty {
            PacketType::Broadcast => 0,
            PacketType::Unicast => 1,
            PacketType::Ack => 2,
        };
        if self.ack_requested {
            control |= ACK_MODE_FLAG;
        }
        out[0] = control;
        out[1] = self.channel;
        out[2..4].copy_from_slice(&self.pan_id.to_be_bytes());
        out[4..8].copy_from_slice(&self.packet_number.to_be_bytes());
        out[8..16].copy_from_slice(&self.source.0);
        if self.ty != PacketType::Broadcast {
            let d = self.destination.ok_or(Error::InvalidArgs)?;
            out[16..24].copy_from_slice(&d.0);
        }
        Ok(n)
    }

    /// Parse a packet: the header and the payload behind it.
    /// [`Error::Parse`] for a bad version / type or a short packet.
    pub fn parse(packet: &[u8]) -> Result<(Self, &[u8])> {
        let control = *packet.first().ok_or(Error::Parse)?;
        if control & VERSION_MASK != VERSION << 5 {
            return Err(Error::Parse);
        }
        let ty = PacketType::from_bits(control & TYPE_MASK).ok_or(Error::Parse)?;
        let n = ty.header_len();
        if packet.len() < n {
            return Err(Error::Parse);
        }
        let ext = |at: usize| {
            let mut a = [0u8; 8];
            a.copy_from_slice(&packet[at..at + 8]);
            ExtAddress(a)
        };
        let h = Self {
            ty,
            ack_requested: control & ACK_MODE_FLAG != 0,
            channel: packet[1],
            pan_id: u16::from_be_bytes([packet[2], packet[3]]),
            packet_number: u32::from_be_bytes([packet[4], packet[5], packet[6], packet[7]]),
            source: ext(8),
            destination: (ty != PacketType::Broadcast).then(|| ext(16)),
        };
        Ok((h, &packet[n..]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SRC: ExtAddress = ExtAddress([1, 2, 3, 4, 5, 6, 7, 8]);
    const DST: ExtAddress = ExtAddress([8, 7, 6, 5, 4, 3, 2, 1]);

    #[test]
    fn broadcast_round_trip_and_wire_format() {
        let h = Header {
            ty: PacketType::Broadcast,
            ack_requested: false,
            channel: 15,
            pan_id: 0xface,
            packet_number: 0x0102_0304,
            source: SRC,
            destination: None,
        };
        let mut b = [0u8; 40];
        let n = h.write(&mut b).unwrap();
        assert_eq!(n, BROADCAST_HEADER_LEN);
        b[n..n + 3].copy_from_slice(&[9, 9, 9]);
        assert_eq!(&b[..8], &[0, 15, 0xfa, 0xce, 1, 2, 3, 4]);
        let (p, payload) = Header::parse(&b[..n + 3]).unwrap();
        assert_eq!(p, h);
        assert_eq!(payload, &[9, 9, 9]);
    }

    #[test]
    fn unicast_and_ack_carry_the_destination() {
        for (ty, bits, ack) in [
            (PacketType::Unicast, 1u8, true),
            (PacketType::Ack, 2u8, false),
        ] {
            let h = Header {
                ty,
                ack_requested: ack,
                channel: 26,
                pan_id: 1,
                packet_number: 7,
                source: SRC,
                destination: Some(DST),
            };
            let mut b = [0u8; 30];
            let n = h.write(&mut b).unwrap();
            assert_eq!(n, UNICAST_HEADER_LEN);
            assert_eq!(b[0], bits | if ack { 4 } else { 0 });
            assert_eq!(Header::parse(&b[..n]).unwrap(), (h, &[][..]));
        }
        let mut h = Header {
            ty: PacketType::Unicast,
            ack_requested: false,
            channel: 1,
            pan_id: 1,
            packet_number: 0,
            source: SRC,
            destination: None,
        };
        assert_eq!(h.write(&mut [0u8; 30]), Err(Error::InvalidArgs));
        h.destination = Some(DST);
        assert_eq!(h.write(&mut [0u8; 10]), Err(Error::NoBufs));
    }

    #[test]
    fn invalid_headers_are_rejected() {
        assert_eq!(Header::parse(&[]), Err(Error::Parse));
        // Version 1, type 3, truncated.
        assert_eq!(Header::parse(&[0x20; 24]), Err(Error::Parse));
        assert_eq!(Header::parse(&[0x03; 24]), Err(Error::Parse));
        assert_eq!(Header::parse(&[0x01; 23]), Err(Error::Parse));
        assert_eq!(Header::parse(&[0x00; 15]), Err(Error::Parse));
    }
}
