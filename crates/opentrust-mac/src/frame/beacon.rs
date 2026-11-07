//! Beacon frame payload (MAC beacon fields and Thread beacon payload).

use opentrust_core::bytes::{Reader, Writer};
use opentrust_core::{Error, Result};

/// Superframe Specification of a beacon (802.15.4 section 7.3.1.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct SuperframeSpec(pub u16);

impl SuperframeSpec {
    /// The value Thread beacons carry (BO = SO = 15, final CAP slot 15).
    pub const THREAD: Self = Self(0x0fff);

    /// Beacon order (bits 0..3).
    pub const fn beacon_order(self) -> u8 {
        (self.0 & 0xf) as u8
    }

    /// Superframe order (bits 4..7).
    pub const fn superframe_order(self) -> u8 {
        ((self.0 >> 4) & 0xf) as u8
    }

    /// Final CAP slot (bits 8..11).
    pub const fn final_cap_slot(self) -> u8 {
        ((self.0 >> 8) & 0xf) as u8
    }

    /// Battery life extension (bit 12).
    pub const fn battery_life_extension(self) -> bool {
        self.0 & (1 << 12) != 0
    }

    /// PAN coordinator (bit 14).
    pub const fn pan_coordinator(self) -> bool {
        self.0 & (1 << 14) != 0
    }

    /// Association permit (bit 15).
    pub const fn association_permit(self) -> bool {
        self.0 & (1 << 15) != 0
    }
}

/// The MAC payload of a Beacon frame, split into its fixed fields and the
/// beacon payload; GTS and pending-address lists are skipped correctly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Beacon<'a> {
    /// Superframe specification.
    pub superframe: SuperframeSpec,
    /// GTS permit flag.
    pub gts_permit: bool,
    /// Number of GTS descriptors that were skipped.
    pub gts_count: u8,
    /// Number of pending short addresses.
    pub pending_short: u8,
    /// Number of pending extended addresses.
    pub pending_extended: u8,
    /// Raw pending address list (`2 * short + 8 * extended` bytes).
    pub pending_addresses: &'a [u8],
    /// Beacon payload (for Thread: a [`ThreadBeaconPayload`]).
    pub payload: &'a [u8],
}

impl<'a> Beacon<'a> {
    /// Parse the payload of a Beacon frame (`Frame::payload()`).
    pub fn parse(payload: &'a [u8]) -> Result<Self> {
        let mut r = Reader::new(payload);
        let superframe = SuperframeSpec(r.read_u16_le()?);
        let gts_spec = r.read_u8()?;
        let gts_count = gts_spec & 0x7;
        if gts_count > 0 {
            r.skip(1 + 3 * usize::from(gts_count))?; // directions + descriptors
        }
        let pending = r.read_u8()?;
        let (pending_short, pending_extended) = (pending & 0x7, (pending >> 4) & 0x7);
        let pending_addresses =
            r.read_slice(2 * usize::from(pending_short) + 8 * usize::from(pending_extended))?;
        Ok(Self {
            superframe,
            gts_permit: gts_spec & 0x80 != 0,
            gts_count,
            pending_short,
            pending_extended,
            pending_addresses,
            payload: r.read_rest(),
        })
    }

    /// Write the fixed part of a Thread beacon (no GTS, no pending
    /// addresses); the beacon payload follows.
    pub fn write_thread_header(w: &mut Writer<'_>) -> Result<()> {
        w.write_u16_le(SuperframeSpec::THREAD.0)?;
        w.write_u8(0)?;
        w.write_u8(0)
    }
}

/// Thread beacon payload (26 bytes): protocol ID 3, flags, network name,
/// extended PAN ID.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct ThreadBeaconPayload {
    /// Thread protocol version (4 bits; 2 for Thread 1.1+).
    pub version: u8,
    /// Native Commissioner flag.
    pub native: bool,
    /// Joining permitted flag.
    pub joining_permitted: bool,
    /// Network name, zero padded to 16 bytes.
    pub network_name: [u8; 16],
    /// Extended PAN ID.
    pub ext_pan_id: [u8; 8],
}

impl ThreadBeaconPayload {
    /// Thread protocol ID in beacons.
    pub const PROTOCOL_ID: u8 = 3;
    /// Encoded length.
    pub const LEN: usize = 26;

    /// Parse; [`Error::Parse`] if too short or the protocol ID is not 3.
    pub fn parse(b: &[u8]) -> Result<Self> {
        let mut r = Reader::new(b);
        if r.read_u8()? != Self::PROTOCOL_ID {
            return Err(Error::Parse);
        }
        let flags = r.read_u8()?;
        Ok(Self {
            version: flags >> 4,
            native: flags & (1 << 3) != 0,
            joining_permitted: flags & 1 != 0,
            network_name: r.read_array()?,
            ext_pan_id: r.read_array()?,
        })
    }

    /// Network name bytes up to the first NUL.
    pub fn network_name_bytes(&self) -> &[u8] {
        let n = self
            .network_name
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(self.network_name.len());
        &self.network_name[..n]
    }

    /// Write the 26-byte payload.
    pub fn write(&self, w: &mut Writer<'_>) -> Result<()> {
        w.write_u8(Self::PROTOCOL_ID)?;
        w.write_u8(
            (self.version << 4) | (u8::from(self.native) << 3) | u8::from(self.joining_permitted),
        )?;
        w.write_slice(&self.network_name)?;
        w.write_slice(&self.ext_pan_id)
    }
}
