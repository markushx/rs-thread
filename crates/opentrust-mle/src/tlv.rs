//! Typed parse/build of all MLE TLVs (Thread 1.4.1 §4.4, Table 4-6;
//! OpenThread `thread/mle_tlvs.{hpp,cpp}`).
//!
//! - **Parse**: wrap the TLV region of a message in [`Tlvs`] and call the
//!   typed getters (`source_address()`, `leader_data()`, ...). A missing TLV
//!   yields [`Error::NotFound`], a malformed one [`Error::Parse`]; getters
//!   never panic on arbitrary input.
//! - **Build**: [`TlvWriter`] appends TLVs to a caller-provided buffer.
//! - TLV type numbers live in [`ty`].
//!
//! The generic wire format (type, length, `0xFF` extended length) is
//! implemented by [`opentrust_core::tlv`].

use core::net::Ipv6Addr;

use opentrust_core::bytes::Writer;
use opentrust_core::tlv::{self as core_tlv, Tlv, TlvIter};
use opentrust_core::types::{Channel, PanId, Rloc16};
use opentrust_core::{Error, Result};

use crate::consts::{MAX_CHALLENGE_LEN, MIN_CHALLENGE_LEN};
use crate::link_quality::LinkQuality;

/// MLE TLV type numbers (Table 4-6).
pub mod ty {
    /// Source Address (RLOC16 of the sender).
    pub const SOURCE_ADDRESS: u8 = 0;
    /// Mode (device mode bits).
    pub const MODE: u8 = 1;
    /// Timeout (child timeout, seconds).
    pub const TIMEOUT: u8 = 2;
    /// Challenge.
    pub const CHALLENGE: u8 = 3;
    /// Response.
    pub const RESPONSE: u8 = 4;
    /// Link-layer Frame Counter.
    pub const LINK_FRAME_COUNTER: u8 = 5;
    /// Link Quality (not used in Thread).
    pub const LINK_QUALITY: u8 = 6;
    /// Network Parameter (not used in Thread).
    pub const NETWORK_PARAMETER: u8 = 7;
    /// MLE Frame Counter.
    pub const MLE_FRAME_COUNTER: u8 = 8;
    /// Route64.
    pub const ROUTE64: u8 = 9;
    /// Address16 (assigned RLOC16).
    pub const ADDRESS16: u8 = 10;
    /// Leader Data.
    pub const LEADER_DATA: u8 = 11;
    /// Network Data.
    pub const NETWORK_DATA: u8 = 12;
    /// TLV Request.
    pub const TLV_REQUEST: u8 = 13;
    /// Scan Mask.
    pub const SCAN_MASK: u8 = 14;
    /// Connectivity.
    pub const CONNECTIVITY: u8 = 15;
    /// Link Margin.
    pub const LINK_MARGIN: u8 = 16;
    /// Status.
    pub const STATUS: u8 = 17;
    /// Version.
    pub const VERSION: u8 = 18;
    /// Address Registration.
    pub const ADDRESS_REGISTRATION: u8 = 19;
    /// IEEE 802.15.4 Channel.
    pub const CHANNEL: u8 = 20;
    /// PAN ID.
    pub const PAN_ID: u8 = 21;
    /// Active Timestamp.
    pub const ACTIVE_TIMESTAMP: u8 = 22;
    /// Pending Timestamp.
    pub const PENDING_TIMESTAMP: u8 = 23;
    /// Active Operational Dataset.
    pub const ACTIVE_DATASET: u8 = 24;
    /// Pending Operational Dataset.
    pub const PENDING_DATASET: u8 = 25;
    /// Thread Discovery (nested MeshCoP TLVs).
    pub const DISCOVERY: u8 = 26;
    /// Supervision Interval.
    pub const SUPERVISION_INTERVAL: u8 = 27;
    /// Wake-up Channel (Thread 1.4, OT `kWakeupChannel`).
    pub const WAKEUP_CHANNEL: u8 = 74;
    /// CSL Channel.
    pub const CSL_CHANNEL: u8 = 80;
    /// CSL Synchronized Timeout.
    pub const CSL_TIMEOUT: u8 = 85;
    /// CSL Clock Accuracy.
    pub const CSL_CLOCK_ACCURACY: u8 = 86;
    /// Link Metrics Query.
    pub const LINK_METRICS_QUERY: u8 = 87;
    /// Link Metrics Management.
    pub const LINK_METRICS_MANAGEMENT: u8 = 88;
    /// Link Metrics Report.
    pub const LINK_METRICS_REPORT: u8 = 89;
    /// Link Probe.
    pub const LINK_PROBE: u8 = 90;
    /// Time Request (OT time-sync extension, not in the specification).
    pub const TIME_REQUEST: u8 = 252;
    /// Time Parameter (OT time-sync extension).
    pub const TIME_PARAMETER: u8 = 253;
    /// XTAL Accuracy (OT time-sync extension).
    pub const XTAL_ACCURACY: u8 = 254;
}

/// Value of the Status TLV that signals an error (OT `StatusTlv::kError`).
pub const STATUS_ERROR: u8 = 1;
/// Scan Mask router flag (§4.4.13).
pub const SCAN_MASK_ROUTER: u8 = 1 << 7;
/// Scan Mask end-device flag (§4.4.13).
pub const SCAN_MASK_END_DEVICE: u8 = 1 << 6;
/// Largest router ID (62); the router ID mask has 64 bits.
pub const MAX_ROUTER_ID: u8 = 62;

// ---------------------------------------------------------------------------
// DeviceMode

/// Device mode of the Mode TLV (§4.4.2): bit 3 receiver on when idle, bit 1
/// full thread device, bit 0 full network data; bit 2 is reserved (set on
/// transmission, ignored on reception).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct DeviceMode {
    bits: u8,
}

impl DeviceMode {
    const RX_ON_WHEN_IDLE: u8 = 1 << 3;
    const RESERVED: u8 = 1 << 2;
    const FTD: u8 = 1 << 1;
    const FULL_NETWORK_DATA: u8 = 1;

    /// Build from the three flags.
    pub const fn new(
        rx_on_when_idle: bool,
        full_thread_device: bool,
        full_network_data: bool,
    ) -> Self {
        Self {
            bits: (rx_on_when_idle as u8) << 3
                | (full_thread_device as u8) << 1
                | full_network_data as u8,
        }
    }

    /// From the wire byte (the reserved bit and unknown bits are dropped).
    pub const fn from_bits(b: u8) -> Self {
        Self { bits: b & 0x0b }
    }

    /// Wire byte, with the reserved bit set as OT does on transmission.
    pub const fn to_bits(self) -> u8 {
        self.bits | Self::RESERVED
    }

    /// Receiver is on when idle (not a sleepy device).
    pub const fn rx_on_when_idle(self) -> bool {
        self.bits & Self::RX_ON_WHEN_IDLE != 0
    }

    /// Full Thread Device (FTD, as opposed to MTD).
    pub const fn full_thread_device(self) -> bool {
        self.bits & Self::FTD != 0
    }

    /// Device wants the full Network Data (not just the stable subset).
    pub const fn full_network_data(self) -> bool {
        self.bits & Self::FULL_NETWORK_DATA != 0
    }

    /// Minimal end device: anything that is not (FTD and rx-on-when-idle)
    /// (OT `IsMinimalEndDevice`).
    pub const fn is_minimal_end_device(self) -> bool {
        self.bits & (Self::FTD | Self::RX_ON_WHEN_IDLE) != (Self::FTD | Self::RX_ON_WHEN_IDLE)
    }

    /// Sleepy end device (not rx-on-when-idle).
    pub const fn is_sleepy(self) -> bool {
        !self.rx_on_when_idle()
    }
}

// ---------------------------------------------------------------------------
// Timestamp

/// MeshCoP/MLE Timestamp (Active/Pending Timestamp TLVs): 48-bit seconds,
/// 15-bit ticks (1/32768 s), authoritative bit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Timestamp {
    /// Seconds (only the low 48 bits are encoded).
    pub seconds: u64,
    /// Ticks, 15 bits.
    pub ticks: u16,
    /// Authoritative flag (set by a Commissioner/border agent).
    pub authoritative: bool,
}

impl Timestamp {
    /// Encoded length.
    pub const LEN: usize = 8;

    /// Decode from the first 8 bytes.
    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        let b: [u8; 8] = b
            .get(..8)
            .ok_or(Error::Parse)?
            .try_into()
            .map_err(|_| Error::Parse)?;
        let v = u64::from_be_bytes(b);
        Ok(Self {
            seconds: v >> 16,
            ticks: ((v >> 1) & 0x7fff) as u16,
            authoritative: v & 1 != 0,
        })
    }

    /// The timestamp of an MLE Orphan Announce (OT `SetToOrphanAnnounce`):
    /// zero seconds and ticks, authoritative flag set.
    pub const ORPHAN_ANNOUNCE: Self = Self {
        seconds: 0,
        ticks: 0,
        authoritative: true,
    };

    /// OT `IsOrphanAnnounce`.
    pub fn is_orphan_announce(&self) -> bool {
        *self == Self::ORPHAN_ANNOUNCE
    }

    /// OT `Timestamp::Compare`: a present (valid) timestamp is newer than
    /// an absent one; then seconds, ticks and the authoritative bit decide.
    pub fn compare(a: Option<&Self>, b: Option<&Self>) -> core::cmp::Ordering {
        use core::cmp::Ordering;
        match (a, b) {
            (None, None) => Ordering::Equal,
            (Some(_), None) => Ordering::Greater,
            (None, Some(_)) => Ordering::Less,
            (Some(a), Some(b)) => a
                .seconds
                .cmp(&b.seconds)
                .then(a.ticks.cmp(&b.ticks))
                .then(a.authoritative.cmp(&b.authoritative)),
        }
    }

    /// Encode to 8 bytes.
    pub fn to_bytes(&self) -> [u8; 8] {
        let v = (self.seconds & 0xffff_ffff_ffff) << 16
            | u64::from(self.ticks & 0x7fff) << 1
            | u64::from(self.authoritative);
        v.to_be_bytes()
    }
}

// ---------------------------------------------------------------------------
// LeaderData

/// Leader Data TLV value (§4.4.10).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct LeaderData {
    /// Partition ID.
    pub partition_id: u32,
    /// Leader weighting.
    pub weighting: u8,
    /// Network Data version.
    pub data_version: u8,
    /// Stable Network Data version.
    pub stable_data_version: u8,
    /// Router ID of the leader.
    pub leader_router_id: u8,
}

impl LeaderData {
    /// Encoded length.
    pub const LEN: usize = 8;

    /// Decode (extra bytes ignored, like OT `IsValid`: length >= 8).
    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        let b: [u8; 8] = b
            .get(..8)
            .ok_or(Error::Parse)?
            .try_into()
            .map_err(|_| Error::Parse)?;
        Ok(Self {
            partition_id: u32::from_be_bytes([b[0], b[1], b[2], b[3]]),
            weighting: b[4],
            data_version: b[5],
            stable_data_version: b[6],
            leader_router_id: b[7],
        })
    }

    /// Encode.
    pub fn to_bytes(&self) -> [u8; 8] {
        let p = self.partition_id.to_be_bytes();
        [
            p[0],
            p[1],
            p[2],
            p[3],
            self.weighting,
            self.data_version,
            self.stable_data_version,
            self.leader_router_id,
        ]
    }
}

// ---------------------------------------------------------------------------
// Route64

/// Router ID bit mask of the Route64 TLV (64 bits, MSB of byte 0 = router 0).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct RouterIdMask(pub [u8; 8]);

impl RouterIdMask {
    /// Empty mask.
    pub const fn new() -> Self {
        Self([0; 8])
    }

    /// Whether `id` is set (ids above 63 are never set).
    pub const fn contains(&self, id: u8) -> bool {
        id < 64 && self.0[(id / 8) as usize] & (0x80 >> (id % 8)) != 0
    }

    /// Set `id`; [`Error::InvalidArgs`] if above [`MAX_ROUTER_ID`].
    pub fn insert(&mut self, id: u8) -> Result<()> {
        if id > MAX_ROUTER_ID {
            return Err(Error::InvalidArgs);
        }
        self.0[(id / 8) as usize] |= 0x80 >> (id % 8);
        Ok(())
    }

    /// Clear `id`.
    pub fn remove(&mut self, id: u8) {
        if id < 64 {
            self.0[(id / 8) as usize] &= !(0x80 >> (id % 8));
        }
    }

    /// Number of set ids.
    pub fn count(&self) -> usize {
        self.0.iter().map(|b| b.count_ones() as usize).sum()
    }

    /// Iterate the set ids in ascending order.
    pub fn iter(&self) -> impl Iterator<Item = u8> + '_ {
        (0..64u8).filter(|&i| self.contains(i))
    }

    /// Index of router `id` in the route-data array (number of set ids below
    /// it), or `None` if `id` is not set.
    pub fn index_of(&self, id: u8) -> Option<usize> {
        self.contains(id)
            .then(|| (0..id).filter(|&i| self.contains(i)).count())
    }
}

/// One route data entry of a Route64 TLV: link quality out/in as seen by the
/// sender and the route cost to that router (§4.4.8; 1 byte per router:
/// `LQ_out(2) | LQ_in(2) | cost(4)`; cost 0 = no route, 15 = max).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct RouteEntry {
    /// Link quality of the link from the sender to the router (outgoing).
    pub link_quality_out: LinkQuality,
    /// Link quality of the link from the router to the sender (incoming).
    pub link_quality_in: LinkQuality,
    /// Route cost (4 bits).
    pub cost: u8,
}

impl RouteEntry {
    /// Decode a route data byte.
    pub const fn from_byte(b: u8) -> Self {
        Self {
            link_quality_out: LinkQuality::from_bits(b >> 6),
            link_quality_in: LinkQuality::from_bits(b >> 4),
            cost: b & 0x0f,
        }
    }

    /// Encode to the route data byte.
    pub const fn to_byte(self) -> u8 {
        self.link_quality_out.as_u8() << 6 | self.link_quality_in.as_u8() << 4 | (self.cost & 0x0f)
    }
}

/// Parsed Route64 TLV value (§4.4.8) borrowing the route data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Route64<'a> {
    /// Router ID sequence number.
    pub id_sequence: u8,
    /// Router ID mask.
    pub id_mask: RouterIdMask,
    route_data: &'a [u8],
}

impl<'a> Route64<'a> {
    /// Parse the TLV value. Requires one route data byte per set mask bit
    /// (OT `RouteTlv::IsValid` plus the router-count check done by users);
    /// trailing bytes are ignored.
    pub fn from_bytes(v: &'a [u8]) -> Result<Self> {
        let id_sequence = *v.first().ok_or(Error::Parse)?;
        let mask: [u8; 8] = v
            .get(1..9)
            .ok_or(Error::Parse)?
            .try_into()
            .map_err(|_| Error::Parse)?;
        let id_mask = RouterIdMask(mask);
        let n = id_mask.count();
        let route_data = v.get(9..9 + n).ok_or(Error::Parse)?;
        Ok(Self {
            id_sequence,
            id_mask,
            route_data,
        })
    }

    /// Number of routers (set mask bits).
    pub fn router_count(&self) -> usize {
        self.route_data.len()
    }

    /// Route data entry at array `index` (0 = lowest set router ID).
    pub fn entry(&self, index: usize) -> Option<RouteEntry> {
        self.route_data
            .get(index)
            .copied()
            .map(RouteEntry::from_byte)
    }

    /// Route data entry of router `router_id`.
    pub fn entry_for_router(&self, router_id: u8) -> Option<RouteEntry> {
        self.entry(self.id_mask.index_of(router_id)?)
    }

    /// Iterate `(router_id, entry)` pairs in ascending router ID order.
    pub fn entries(&self) -> impl Iterator<Item = (u8, RouteEntry)> + '_ {
        self.id_mask
            .iter()
            .zip(self.route_data.iter())
            .map(|(id, &b)| (id, RouteEntry::from_byte(b)))
    }

    /// `true` if at most one router is allocated (OT `IsSingleton`).
    pub fn is_singleton(&self) -> bool {
        self.router_count() <= 1
    }
}

// ---------------------------------------------------------------------------
// Connectivity

/// Parent priority of the Connectivity TLV (2-bit signed, §4.4.14).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum ParentPriority {
    /// Low (-1, wire 3).
    Low,
    /// Medium (0).
    #[default]
    Medium,
    /// High (+1).
    High,
}

impl ParentPriority {
    /// Decode the 2-bit field; the reserved value 2 maps to `None`
    /// (OT rejects it as unspecified).
    pub const fn from_bits(b: u8) -> Option<Self> {
        match b & 3 {
            0 => Some(Self::Medium),
            1 => Some(Self::High),
            3 => Some(Self::Low),
            _ => None,
        }
    }

    /// 2-bit wire value.
    pub const fn to_bits(self) -> u8 {
        match self {
            Self::Medium => 0,
            Self::High => 1,
            Self::Low => 3,
        }
    }
}

/// Connectivity TLV value (§4.4.14).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Connectivity {
    /// Parent priority.
    pub parent_priority: ParentPriority,
    /// Number of neighbors with link quality 3.
    pub link_quality_3: u8,
    /// Number of neighbors with link quality 2.
    pub link_quality_2: u8,
    /// Number of neighbors with link quality 1.
    pub link_quality_1: u8,
    /// Route cost to the leader.
    pub leader_cost: u8,
    /// Router ID sequence.
    pub id_sequence: u8,
    /// Number of active routers.
    pub active_routers: u8,
    /// SED buffer size (optional trailing field).
    pub sed_buffer_size: Option<u16>,
    /// SED datagram count (optional trailing field; present with the size).
    pub sed_datagram_count: Option<u8>,
}

impl Connectivity {
    /// Length without the SED fields.
    pub const BASE_LEN: usize = 7;
    /// Length with the SED fields.
    pub const FULL_LEN: usize = 10;

    /// Decode. The SED fields are taken only if all 10 bytes are present; a
    /// length between 7 and 9 is accepted as the base form (OT `IsValid`
    /// accepts only exactly 7 or at least 10 bytes; we are lenient and ignore
    /// the partial tail). A reserved parent priority is [`Error::Parse`].
    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        if b.len() < Self::BASE_LEN {
            return Err(Error::Parse);
        }
        let parent_priority = ParentPriority::from_bits(b[0] >> 6).ok_or(Error::Parse)?;
        let (sed_buffer_size, sed_datagram_count) = if b.len() >= Self::FULL_LEN {
            (Some(u16::from_be_bytes([b[7], b[8]])), Some(b[9]))
        } else {
            (None, None)
        };
        Ok(Self {
            parent_priority,
            link_quality_3: b[1],
            link_quality_2: b[2],
            link_quality_1: b[3],
            leader_cost: b[4],
            id_sequence: b[5],
            active_routers: b[6],
            sed_buffer_size,
            sed_datagram_count,
        })
    }

    /// Encode into `out` (7 or 10 bytes); returns the length.
    pub fn encode(&self, out: &mut [u8; 10]) -> usize {
        out[0] = self.parent_priority.to_bits() << 6;
        out[1] = self.link_quality_3;
        out[2] = self.link_quality_2;
        out[3] = self.link_quality_1;
        out[4] = self.leader_cost;
        out[5] = self.id_sequence;
        out[6] = self.active_routers;
        match (self.sed_buffer_size, self.sed_datagram_count) {
            (Some(size), Some(count)) => {
                out[7..9].copy_from_slice(&size.to_be_bytes());
                out[9] = count;
                Self::FULL_LEN
            }
            _ => Self::BASE_LEN,
        }
    }

    /// `true` if at most one router is active.
    pub fn is_singleton(&self) -> bool {
        self.active_routers <= 1
    }

    /// Count a neighbor of quality `lq` (OT `IncrementLinkQuality`; quality 0
    /// is not counted).
    pub fn increment_link_quality(&mut self, lq: LinkQuality) {
        match lq {
            LinkQuality::Q3 => self.link_quality_3 = self.link_quality_3.saturating_add(1),
            LinkQuality::Q2 => self.link_quality_2 = self.link_quality_2.saturating_add(1),
            LinkQuality::Q1 => self.link_quality_1 = self.link_quality_1.saturating_add(1),
            LinkQuality::Q0 => {}
        }
    }
}

// ---------------------------------------------------------------------------
// Address Registration

/// One entry of the Address Registration TLV (§4.4.18).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AddressEntry {
    /// Prefix elided via 6LoWPAN context `context_id`; only the IID is sent.
    Compressed {
        /// 6LoWPAN context ID (4 bits).
        context_id: u8,
        /// Interface identifier.
        iid: [u8; 8],
    },
    /// Full 128-bit address.
    Uncompressed(Ipv6Addr),
}

impl AddressEntry {
    const COMPRESSED: u8 = 1 << 7;
    const CONTEXT_MASK: u8 = 0x0f;

    /// Encoded size.
    pub const fn encoded_len(&self) -> usize {
        match self {
            Self::Compressed { .. } => 9,
            Self::Uncompressed(_) => 17,
        }
    }

    /// Append the entry.
    pub fn write(&self, w: &mut Writer<'_>) -> Result<()> {
        match self {
            Self::Compressed { context_id, iid } => {
                w.write_u8(Self::COMPRESSED | (context_id & Self::CONTEXT_MASK))?;
                w.write_slice(iid)
            }
            Self::Uncompressed(a) => {
                w.write_u8(0)?;
                w.write_slice(&a.octets())
            }
        }
    }
}

/// Iterator over the entries of an Address Registration TLV value. Yields
/// one `Err(Error::Parse)` on a truncated entry, then ends.
#[derive(Debug, Clone)]
pub struct AddressRegistration<'a> {
    rest: &'a [u8],
}

impl<'a> AddressRegistration<'a> {
    /// Iterate over the TLV value `v`.
    pub const fn new(v: &'a [u8]) -> Self {
        Self { rest: v }
    }
}

impl Iterator for AddressRegistration<'_> {
    type Item = Result<AddressEntry>;

    fn next(&mut self) -> Option<Self::Item> {
        let (&ctrl, rest) = self.rest.split_first()?;
        let compressed = ctrl & AddressEntry::COMPRESSED != 0;
        let n = if compressed { 8 } else { 16 };
        let Some(body) = rest.get(..n) else {
            self.rest = &[];
            return Some(Err(Error::Parse));
        };
        self.rest = &rest[n..];
        Some(Ok(if compressed {
            let mut iid = [0u8; 8];
            iid.copy_from_slice(body);
            AddressEntry::Compressed {
                context_id: ctrl & AddressEntry::CONTEXT_MASK,
                iid,
            }
        } else {
            let mut a = [0u8; 16];
            a.copy_from_slice(body);
            AddressEntry::Uncompressed(Ipv6Addr::from(a))
        }))
    }
}

// ---------------------------------------------------------------------------
// Small values

/// Channel / CSL Channel / Wake-up Channel TLV value: page (1) + channel (2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct ChannelValue {
    /// Channel page (0 for 2.4 GHz).
    pub page: u8,
    /// Channel number.
    pub channel: u16,
}

impl ChannelValue {
    /// Page 0 and a 2.4 GHz channel.
    pub const fn new(channel: Channel) -> Self {
        Self {
            page: 0,
            channel: channel.get() as u16,
        }
    }

    /// Decode (3 bytes minimum).
    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        let b: [u8; 3] = b
            .get(..3)
            .ok_or(Error::Parse)?
            .try_into()
            .map_err(|_| Error::Parse)?;
        Ok(Self {
            page: b[0],
            channel: u16::from_be_bytes([b[1], b[2]]),
        })
    }

    /// Encode.
    pub fn to_bytes(&self) -> [u8; 3] {
        let c = self.channel.to_be_bytes();
        [self.page, c[0], c[1]]
    }

    /// Validate: page 0 and channel 11..=26 (OT `ChannelTlvValue::IsValid`
    /// for a 2.4 GHz-only build) and return the channel.
    pub fn to_channel(&self) -> Result<Channel> {
        if self.page != 0 || self.channel > 0xff {
            return Err(Error::Parse);
        }
        Channel::new(self.channel as u8).map_err(|_| Error::Parse)
    }
}

/// CSL Clock Accuracy TLV value (§4.4.33).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct CslClockAccuracy {
    /// Clock accuracy in ppm.
    pub accuracy_ppm: u8,
    /// Uncertainty in units of 10 microseconds.
    pub uncertainty_10us: u8,
}

impl CslClockAccuracy {
    /// Worst case, assumed for a parent that reports nothing (OT
    /// `CslAccuracy::Init`).
    pub const WORST: Self = Self {
        accuracy_ppm: 255,
        uncertainty_10us: 255,
    };

    /// The uncertainty in microseconds.
    pub const fn uncertainty_us(&self) -> u32 {
        self.uncertainty_10us as u32 * 10
    }
}

/// Thread Time Parameter TLV value (OT time-sync extension).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct TimeParameter {
    /// Time sync period, seconds.
    pub period: u16,
    /// XTAL threshold, ppm.
    pub xtal_threshold: u16,
}

/// Link Metrics sub-TLV types, nested inside the Link Metrics Query /
/// Management / Report TLVs (Thread 1.4.1 §4.11.3, OT `LinkMetrics::SubTlv`).
pub mod link_metrics {
    /// Report sub-TLV (carries Metric Type ID + value pairs).
    pub const SUB_REPORT: u8 = 0;
    /// Query ID sub-TLV.
    pub const SUB_QUERY_ID: u8 = 1;
    /// Query Options sub-TLV (list of Metric Type IDs).
    pub const SUB_QUERY_OPTIONS: u8 = 2;
    /// Forward Probing Registration sub-TLV.
    pub const SUB_FWD_PROBING_REG: u8 = 3;
    /// Status sub-TLV.
    pub const SUB_STATUS: u8 = 5;
    /// Enhanced ACK Configuration sub-TLV.
    pub const SUB_ENH_ACK_CONFIG: u8 = 7;

    /// Metric Type ID: PDUs received (count, 4-byte value).
    pub const METRIC_PDU: u8 = 0x40;
    /// Metric Type ID: LQI (average, 1-byte value).
    pub const METRIC_LQI: u8 = 0x09;
    /// Metric Type ID: link margin (average, 1-byte value).
    pub const METRIC_LINK_MARGIN: u8 = 0x0a;
    /// Metric Type ID: RSSI (average, 1-byte value).
    pub const METRIC_RSSI: u8 = 0x0b;

    /// Link Metrics Status values (OT `LinkMetrics::Status`).
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    #[cfg_attr(feature = "defmt", derive(defmt::Format))]
    #[repr(u8)]
    pub enum Status {
        /// Success.
        Success = 0,
        /// Cannot support a new series.
        CannotSupportNewSeries = 1,
        /// Series ID already registered.
        SeriesIdAlreadyRegistered = 2,
        /// Series ID not recognized.
        SeriesIdNotRecognized = 3,
        /// No matching frames received.
        NoMatchingFramesReceived = 4,
        /// Other error.
        OtherError = 254,
    }

    impl Status {
        /// Decode a status byte.
        pub const fn from_u8(v: u8) -> Option<Self> {
            Some(match v {
                0 => Self::Success,
                1 => Self::CannotSupportNewSeries,
                2 => Self::SeriesIdAlreadyRegistered,
                3 => Self::SeriesIdNotRecognized,
                4 => Self::NoMatchingFramesReceived,
                254 => Self::OtherError,
                _ => return None,
            })
        }
    }
}

// ---------------------------------------------------------------------------
// Parsing

/// A TLV region of an MLE message with typed getters.
///
/// Getters return [`Error::NotFound`] if the TLV is absent and
/// [`Error::Parse`] if it (or an earlier TLV) is malformed. The first TLV of
/// a type wins, like OT `Tlv::FindTlv`.
#[derive(Debug, Clone, Copy)]
pub struct Tlvs<'a>(pub &'a [u8]);

macro_rules! uint_getter {
    ($(#[$m:meta])* $name:ident, $ty:expr, $t:ty, $read:ident) => {
        $(#[$m])*
        pub fn $name(&self) -> Result<$t> {
            self.find($ty)?.$read()
        }
    };
}

impl<'a> Tlvs<'a> {
    /// Wrap the TLV region.
    pub const fn new(buf: &'a [u8]) -> Self {
        Self(buf)
    }

    /// Raw bytes.
    pub const fn as_bytes(&self) -> &'a [u8] {
        self.0
    }

    /// Iterate the raw TLVs.
    pub fn iter(&self) -> TlvIter<'a> {
        TlvIter::new(self.0)
    }

    /// Check the whole region is well formed.
    pub fn validate(&self) -> Result<()> {
        core_tlv::validate(self.0)
    }

    /// Find a TLV by type number.
    pub fn find(&self, ty: u8) -> Result<Tlv<'a>> {
        core_tlv::find(self.0, ty)
    }

    /// Whether a TLV of type `ty` is present.
    pub fn contains(&self, ty: u8) -> bool {
        self.find(ty).is_ok()
    }

    fn value(&self, ty: u8) -> Result<&'a [u8]> {
        Ok(self.find(ty)?.value())
    }

    uint_getter!(
        /// Timeout TLV (seconds).
        timeout, ty::TIMEOUT, u32, read_u32
    );
    uint_getter!(
        /// Link-layer Frame Counter TLV.
        link_frame_counter, ty::LINK_FRAME_COUNTER, u32, read_u32
    );
    uint_getter!(
        /// MLE Frame Counter TLV.
        mle_frame_counter, ty::MLE_FRAME_COUNTER, u32, read_u32
    );
    uint_getter!(
        /// Link Margin TLV (dB).
        link_margin, ty::LINK_MARGIN, u8, read_u8
    );
    uint_getter!(
        /// Version TLV.
        version, ty::VERSION, u16, read_u16
    );
    uint_getter!(
        /// Status TLV.
        status, ty::STATUS, u8, read_u8
    );
    uint_getter!(
        /// Scan Mask TLV ([`SCAN_MASK_ROUTER`] / [`SCAN_MASK_END_DEVICE`]).
        scan_mask, ty::SCAN_MASK, u8, read_u8
    );
    uint_getter!(
        /// Supervision Interval TLV (seconds).
        supervision_interval, ty::SUPERVISION_INTERVAL, u16, read_u16
    );
    uint_getter!(
        /// CSL Synchronized Timeout TLV (seconds).
        csl_timeout, ty::CSL_TIMEOUT, u32, read_u32
    );
    uint_getter!(
        /// XTAL Accuracy TLV (ppm; OT time-sync extension).
        xtal_accuracy, ty::XTAL_ACCURACY, u16, read_u16
    );

    /// Source Address TLV (RLOC16 of the sender).
    pub fn source_address(&self) -> Result<Rloc16> {
        self.find(ty::SOURCE_ADDRESS)?.read_u16().map(Rloc16)
    }

    /// Address16 TLV (RLOC16 assigned to the receiver).
    pub fn address16(&self) -> Result<Rloc16> {
        self.find(ty::ADDRESS16)?.read_u16().map(Rloc16)
    }

    /// Mode TLV.
    pub fn mode(&self) -> Result<DeviceMode> {
        self.find(ty::MODE)?.read_u8().map(DeviceMode::from_bits)
    }

    /// Challenge TLV (4..=8 bytes).
    pub fn challenge(&self) -> Result<&'a [u8]> {
        check_challenge(self.value(ty::CHALLENGE)?)
    }

    /// Response TLV (4..=8 bytes).
    pub fn response(&self) -> Result<&'a [u8]> {
        check_challenge(self.value(ty::RESPONSE)?)
    }

    /// Route64 TLV.
    pub fn route64(&self) -> Result<Route64<'a>> {
        Route64::from_bytes(self.value(ty::ROUTE64)?)
    }

    /// Leader Data TLV.
    pub fn leader_data(&self) -> Result<LeaderData> {
        LeaderData::from_bytes(self.value(ty::LEADER_DATA)?)
    }

    /// Network Data TLV (opaque; decoded by `opentrust-mesh`).
    pub fn network_data(&self) -> Result<&'a [u8]> {
        self.value(ty::NETWORK_DATA)
    }

    /// TLV Request TLV: the list of requested TLV types.
    pub fn tlv_request(&self) -> Result<&'a [u8]> {
        self.value(ty::TLV_REQUEST)
    }

    /// Connectivity TLV.
    pub fn connectivity(&self) -> Result<Connectivity> {
        Connectivity::from_bytes(self.value(ty::CONNECTIVITY)?)
    }

    /// Address Registration TLV entries.
    pub fn address_registration(&self) -> Result<AddressRegistration<'a>> {
        Ok(AddressRegistration::new(
            self.value(ty::ADDRESS_REGISTRATION)?,
        ))
    }

    /// Channel TLV.
    pub fn channel(&self) -> Result<ChannelValue> {
        ChannelValue::from_bytes(self.value(ty::CHANNEL)?)
    }

    /// CSL Channel TLV.
    pub fn csl_channel(&self) -> Result<ChannelValue> {
        ChannelValue::from_bytes(self.value(ty::CSL_CHANNEL)?)
    }

    /// Wake-up Channel TLV.
    pub fn wakeup_channel(&self) -> Result<ChannelValue> {
        ChannelValue::from_bytes(self.value(ty::WAKEUP_CHANNEL)?)
    }

    /// PAN ID TLV.
    pub fn pan_id(&self) -> Result<PanId> {
        self.find(ty::PAN_ID)?.read_u16().map(PanId)
    }

    /// Active Timestamp TLV.
    pub fn active_timestamp(&self) -> Result<Timestamp> {
        Timestamp::from_bytes(self.value(ty::ACTIVE_TIMESTAMP)?)
    }

    /// Pending Timestamp TLV.
    pub fn pending_timestamp(&self) -> Result<Timestamp> {
        Timestamp::from_bytes(self.value(ty::PENDING_TIMESTAMP)?)
    }

    /// Active Operational Dataset TLV (nested MeshCoP TLVs, opaque).
    pub fn active_dataset(&self) -> Result<&'a [u8]> {
        self.value(ty::ACTIVE_DATASET)
    }

    /// Pending Operational Dataset TLV (nested MeshCoP TLVs, opaque).
    pub fn pending_dataset(&self) -> Result<&'a [u8]> {
        self.value(ty::PENDING_DATASET)
    }

    /// Thread Discovery TLV (nested MeshCoP TLVs, opaque).
    pub fn discovery(&self) -> Result<&'a [u8]> {
        self.value(ty::DISCOVERY)
    }

    /// CSL Clock Accuracy TLV.
    pub fn csl_clock_accuracy(&self) -> Result<CslClockAccuracy> {
        let b = self.find(ty::CSL_CLOCK_ACCURACY)?.read_array::<2>()?;
        Ok(CslClockAccuracy {
            accuracy_ppm: b[0],
            uncertainty_10us: b[1],
        })
    }

    /// Link Metrics Query TLV: nested sub-TLVs (see [`link_metrics`]).
    pub fn link_metrics_query(&self) -> Result<Tlvs<'a>> {
        self.value(ty::LINK_METRICS_QUERY).map(Tlvs)
    }

    /// Link Metrics Management TLV: nested sub-TLVs.
    pub fn link_metrics_management(&self) -> Result<Tlvs<'a>> {
        self.value(ty::LINK_METRICS_MANAGEMENT).map(Tlvs)
    }

    /// Link Metrics Report TLV: nested sub-TLVs.
    pub fn link_metrics_report(&self) -> Result<Tlvs<'a>> {
        self.value(ty::LINK_METRICS_REPORT).map(Tlvs)
    }

    /// Link Probe TLV: `(series_id, padding)`.
    pub fn link_probe(&self) -> Result<(u8, &'a [u8])> {
        let v = self.value(ty::LINK_PROBE)?;
        let (&id, pad) = v.split_first().ok_or(Error::Parse)?;
        Ok((id, pad))
    }

    /// Time Parameter TLV (OT time-sync extension).
    pub fn time_parameter(&self) -> Result<TimeParameter> {
        let b = self.find(ty::TIME_PARAMETER)?.read_array::<4>()?;
        Ok(TimeParameter {
            period: u16::from_be_bytes([b[0], b[1]]),
            xtal_threshold: u16::from_be_bytes([b[2], b[3]]),
        })
    }
}

fn check_challenge(v: &[u8]) -> Result<&[u8]> {
    if (MIN_CHALLENGE_LEN..=MAX_CHALLENGE_LEN).contains(&v.len()) {
        Ok(v)
    } else {
        Err(Error::Parse)
    }
}

// ---------------------------------------------------------------------------
// Building

/// Appends MLE TLVs to a buffer. Every method returns [`Error::NoBufs`] if
/// the TLV does not fit; on error the buffer may hold a partial TLV, so the
/// caller should discard the message.
#[derive(Debug)]
pub struct TlvWriter<'a> {
    w: Writer<'a>,
}

impl<'a> TlvWriter<'a> {
    /// Write into `buf` starting at offset 0.
    pub fn new(buf: &'a mut [u8]) -> Self {
        Self {
            w: Writer::new(buf),
        }
    }

    /// Wrap an existing [`Writer`] (e.g. after a command byte).
    pub const fn from_writer(w: Writer<'a>) -> Self {
        Self { w }
    }

    /// Bytes written so far.
    pub fn written(&self) -> &[u8] {
        self.w.written()
    }

    /// Number of bytes written.
    pub const fn len(&self) -> usize {
        self.w.len()
    }

    /// `true` if nothing was written.
    pub const fn is_empty(&self) -> bool {
        self.w.is_empty()
    }

    /// Remaining capacity.
    pub const fn remaining(&self) -> usize {
        self.w.remaining()
    }

    /// Underlying writer.
    pub fn writer(&mut self) -> &mut Writer<'a> {
        &mut self.w
    }

    /// Give back the underlying writer.
    pub fn into_writer(self) -> Writer<'a> {
        self.w
    }

    /// Append an arbitrary TLV (also for unknown/opaque types).
    pub fn raw(&mut self, ty: u8, value: &[u8]) -> Result<()> {
        core_tlv::write(&mut self.w, ty, value)
    }

    /// Source Address TLV.
    pub fn source_address(&mut self, rloc: Rloc16) -> Result<()> {
        core_tlv::write_u16(&mut self.w, ty::SOURCE_ADDRESS, rloc.0)
    }

    /// Mode TLV (the reserved bit is set).
    pub fn mode(&mut self, mode: DeviceMode) -> Result<()> {
        core_tlv::write_u8(&mut self.w, ty::MODE, mode.to_bits())
    }

    /// Timeout TLV (seconds).
    pub fn timeout(&mut self, secs: u32) -> Result<()> {
        core_tlv::write_u32(&mut self.w, ty::TIMEOUT, secs)
    }

    /// Challenge TLV; [`Error::InvalidArgs`] unless 4..=8 bytes.
    pub fn challenge(&mut self, c: &[u8]) -> Result<()> {
        check_challenge(c).map_err(|_| Error::InvalidArgs)?;
        self.raw(ty::CHALLENGE, c)
    }

    /// Response TLV; [`Error::InvalidArgs`] unless 4..=8 bytes.
    pub fn response(&mut self, c: &[u8]) -> Result<()> {
        check_challenge(c).map_err(|_| Error::InvalidArgs)?;
        self.raw(ty::RESPONSE, c)
    }

    /// Link-layer Frame Counter TLV.
    pub fn link_frame_counter(&mut self, c: u32) -> Result<()> {
        core_tlv::write_u32(&mut self.w, ty::LINK_FRAME_COUNTER, c)
    }

    /// MLE Frame Counter TLV.
    pub fn mle_frame_counter(&mut self, c: u32) -> Result<()> {
        core_tlv::write_u32(&mut self.w, ty::MLE_FRAME_COUNTER, c)
    }

    /// Route64 TLV from a mask and one entry per set mask bit, in ascending
    /// router ID order ([`Error::InvalidArgs`] on a count mismatch).
    pub fn route64(
        &mut self,
        id_sequence: u8,
        mask: &RouterIdMask,
        entries: &[RouteEntry],
    ) -> Result<()> {
        if entries.len() != mask.count() {
            return Err(Error::InvalidArgs);
        }
        core_tlv::write_with(&mut self.w, ty::ROUTE64, |w| {
            w.write_u8(id_sequence)?;
            w.write_slice(&mask.0)?;
            entries.iter().try_for_each(|e| w.write_u8(e.to_byte()))
        })
    }

    /// Address16 TLV.
    pub fn address16(&mut self, rloc: Rloc16) -> Result<()> {
        core_tlv::write_u16(&mut self.w, ty::ADDRESS16, rloc.0)
    }

    /// Leader Data TLV.
    pub fn leader_data(&mut self, ld: &LeaderData) -> Result<()> {
        self.raw(ty::LEADER_DATA, &ld.to_bytes())
    }

    /// Network Data TLV (opaque bytes).
    pub fn network_data(&mut self, data: &[u8]) -> Result<()> {
        self.raw(ty::NETWORK_DATA, data)
    }

    /// TLV Request TLV listing `types`.
    pub fn tlv_request(&mut self, types: &[u8]) -> Result<()> {
        self.raw(ty::TLV_REQUEST, types)
    }

    /// Scan Mask TLV.
    pub fn scan_mask(&mut self, mask: u8) -> Result<()> {
        core_tlv::write_u8(&mut self.w, ty::SCAN_MASK, mask)
    }

    /// Connectivity TLV.
    pub fn connectivity(&mut self, c: &Connectivity) -> Result<()> {
        let mut buf = [0u8; 10];
        let n = c.encode(&mut buf);
        self.raw(ty::CONNECTIVITY, &buf[..n])
    }

    /// Link Margin TLV.
    pub fn link_margin(&mut self, margin: u8) -> Result<()> {
        core_tlv::write_u8(&mut self.w, ty::LINK_MARGIN, margin)
    }

    /// Status TLV.
    pub fn status(&mut self, status: u8) -> Result<()> {
        core_tlv::write_u8(&mut self.w, ty::STATUS, status)
    }

    /// Version TLV.
    pub fn version(&mut self, version: u16) -> Result<()> {
        core_tlv::write_u16(&mut self.w, ty::VERSION, version)
    }

    /// Address Registration TLV.
    pub fn address_registration(&mut self, entries: &[AddressEntry]) -> Result<()> {
        core_tlv::write_with(&mut self.w, ty::ADDRESS_REGISTRATION, |w| {
            entries.iter().try_for_each(|e| e.write(w))
        })
    }

    /// Channel TLV.
    pub fn channel(&mut self, c: ChannelValue) -> Result<()> {
        self.raw(ty::CHANNEL, &c.to_bytes())
    }

    /// CSL Channel TLV.
    pub fn csl_channel(&mut self, c: ChannelValue) -> Result<()> {
        self.raw(ty::CSL_CHANNEL, &c.to_bytes())
    }

    /// Wake-up Channel TLV.
    pub fn wakeup_channel(&mut self, c: ChannelValue) -> Result<()> {
        self.raw(ty::WAKEUP_CHANNEL, &c.to_bytes())
    }

    /// PAN ID TLV.
    pub fn pan_id(&mut self, pan: PanId) -> Result<()> {
        core_tlv::write_u16(&mut self.w, ty::PAN_ID, pan.0)
    }

    /// Active Timestamp TLV.
    pub fn active_timestamp(&mut self, t: &Timestamp) -> Result<()> {
        self.raw(ty::ACTIVE_TIMESTAMP, &t.to_bytes())
    }

    /// Pending Timestamp TLV.
    pub fn pending_timestamp(&mut self, t: &Timestamp) -> Result<()> {
        self.raw(ty::PENDING_TIMESTAMP, &t.to_bytes())
    }

    /// Active Operational Dataset TLV (opaque nested TLVs).
    pub fn active_dataset(&mut self, data: &[u8]) -> Result<()> {
        self.raw(ty::ACTIVE_DATASET, data)
    }

    /// Pending Operational Dataset TLV (opaque nested TLVs).
    pub fn pending_dataset(&mut self, data: &[u8]) -> Result<()> {
        self.raw(ty::PENDING_DATASET, data)
    }

    /// Thread Discovery TLV (opaque nested MeshCoP TLVs).
    pub fn discovery(&mut self, data: &[u8]) -> Result<()> {
        self.raw(ty::DISCOVERY, data)
    }

    /// Supervision Interval TLV (seconds).
    pub fn supervision_interval(&mut self, secs: u16) -> Result<()> {
        core_tlv::write_u16(&mut self.w, ty::SUPERVISION_INTERVAL, secs)
    }

    /// CSL Synchronized Timeout TLV (seconds).
    pub fn csl_timeout(&mut self, secs: u32) -> Result<()> {
        core_tlv::write_u32(&mut self.w, ty::CSL_TIMEOUT, secs)
    }

    /// CSL Clock Accuracy TLV.
    pub fn csl_clock_accuracy(&mut self, a: CslClockAccuracy) -> Result<()> {
        self.raw(
            ty::CSL_CLOCK_ACCURACY,
            &[a.accuracy_ppm, a.uncertainty_10us],
        )
    }

    /// Link Metrics Query TLV with pre-encoded sub-TLVs.
    pub fn link_metrics_query(&mut self, sub_tlvs: &[u8]) -> Result<()> {
        self.raw(ty::LINK_METRICS_QUERY, sub_tlvs)
    }

    /// Link Metrics Management TLV with pre-encoded sub-TLVs.
    pub fn link_metrics_management(&mut self, sub_tlvs: &[u8]) -> Result<()> {
        self.raw(ty::LINK_METRICS_MANAGEMENT, sub_tlvs)
    }

    /// Link Metrics Report TLV with pre-encoded sub-TLVs.
    pub fn link_metrics_report(&mut self, sub_tlvs: &[u8]) -> Result<()> {
        self.raw(ty::LINK_METRICS_REPORT, sub_tlvs)
    }

    /// Link Probe TLV: series ID followed by `padding_len` zero bytes
    /// (at most 63).
    pub fn link_probe(&mut self, series_id: u8, padding_len: usize) -> Result<()> {
        if padding_len > 63 {
            return Err(Error::InvalidArgs);
        }
        core_tlv::write_with(&mut self.w, ty::LINK_PROBE, |w| {
            w.write_u8(series_id)?;
            (0..padding_len).try_for_each(|_| w.write_u8(0))
        })
    }

    /// Time Parameter TLV (OT time-sync extension).
    pub fn time_parameter(&mut self, p: TimeParameter) -> Result<()> {
        let mut b = [0u8; 4];
        b[..2].copy_from_slice(&p.period.to_be_bytes());
        b[2..].copy_from_slice(&p.xtal_threshold.to_be_bytes());
        self.raw(ty::TIME_PARAMETER, &b)
    }

    /// XTAL Accuracy TLV (OT time-sync extension).
    pub fn xtal_accuracy(&mut self, ppm: u16) -> Result<()> {
        core_tlv::write_u16(&mut self.w, ty::XTAL_ACCURACY, ppm)
    }
}

#[cfg(test)]
#[path = "tlv_tests.rs"]
mod tests;
