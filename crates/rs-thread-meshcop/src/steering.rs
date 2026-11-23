//! Steering Data (Bloom filter), Joiner ID and Joiner Discerner (OT
//! `meshcop/meshcop.cpp`, Thread 1.4.1 section 8.4.4.2).

use rs_thread_core::crypto::{CryptoBackend, Sha256};
use rs_thread_core::types::ExtAddress;
use rs_thread_core::{Error, Result};

/// CRC-16/CCITT polynomial (x^16 + x^12 + x^5 + 1).
pub(crate) const CRC16_CCITT: u16 = 0x1021;
/// CRC-16/ANSI polynomial (x^16 + x^15 + x^2 + 1).
pub(crate) const CRC16_ANSI: u16 = 0x8005;

/// OT `CrcCalculator<uint16_t>`: MSB first, initial value 0, no final xor.
pub(crate) fn crc16(poly: u16, data: &[u8]) -> u16 {
    let mut crc = 0u16;
    for &b in data {
        crc ^= u16::from(b) << 8;
        for _ in 0..8 {
            let msb = crc & 0x8000 != 0;
            crc <<= 1;
            if msb {
                crc ^= poly;
            }
        }
    }
    crc
}

/// Derive the Joiner ID from the Joiner's EUI-64: the first 8 bytes of
/// `SHA-256(eui64)` with the "local" bit set (OT `ComputeJoinerId`).
pub fn compute_joiner_id<B: CryptoBackend>(backend: &B, eui64: &ExtAddress) -> ExtAddress {
    let mut h = backend.sha256();
    h.update(eui64.as_bytes());
    let digest = h.finalize();
    let mut id = [0u8; 8];
    id.copy_from_slice(&digest[..8]);
    id[0] |= 0x02;
    ExtAddress(id)
}

/// A Joiner Discerner: the low `length` bits of `value` (1..=64) stand in
/// for the Joiner ID (OT `JoinerDiscerner`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct JoinerDiscerner {
    /// The value.
    pub value: u64,
    /// Length in bits.
    pub length: u8,
}

impl JoinerDiscerner {
    /// Maximum length in bits.
    pub const MAX_LENGTH: u8 = 64;

    /// `0 < length <= 64`.
    pub const fn is_valid(&self) -> bool {
        self.length > 0 && self.length <= Self::MAX_LENGTH
    }

    const fn mask(&self) -> u64 {
        if self.length >= 64 {
            u64::MAX
        } else {
            (1u64 << self.length) - 1
        }
    }

    /// Does a Joiner ID match the discerner (OT `Matches`)?
    pub fn matches(&self, joiner_id: &ExtAddress) -> bool {
        let m = self.mask();
        u64::from_be_bytes(joiner_id.0) & m == self.value & m
    }

    /// Copy the discerner bits into the low end of `addr`, leaving the
    /// other bits unchanged (OT `CopyTo`).
    pub fn copy_to(&self, addr: &mut ExtAddress) {
        let m = self.mask();
        let v = (u64::from_be_bytes(addr.0) & !m) | (self.value & m);
        addr.0 = v.to_be_bytes();
    }
}

/// The two Bloom filter bit indexes of a Joiner ID (OT `HashBitIndexes`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HashBitIndexes(pub [u16; 2]);

impl HashBitIndexes {
    /// OT `CalculateHashBitIndexes(joiner_id)`.
    pub fn of_joiner_id(id: &ExtAddress) -> Self {
        Self([crc16(CRC16_CCITT, &id.0), crc16(CRC16_ANSI, &id.0)])
    }

    /// OT `CalculateHashBitIndexes(discerner)`: the discerner is copied into
    /// an all-zero address first.
    pub fn of_discerner(d: &JoinerDiscerner) -> Self {
        let mut a = ExtAddress([0; 8]);
        d.copy_to(&mut a);
        Self::of_joiner_id(&a)
    }
}

/// Steering Data: a Bloom filter of up to 16 bytes (OT `SteeringData`).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct SteeringData {
    bytes: [u8; Self::MAX_LENGTH],
    len: u8,
}

impl core::fmt::Debug for SteeringData {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "SteeringData({:02x?})", self.as_bytes())
    }
}

#[cfg(feature = "defmt")]
impl defmt::Format for SteeringData {
    fn format(&self, f: defmt::Formatter<'_>) {
        defmt::write!(f, "SteeringData({=[u8]:x})", self.as_bytes());
    }
}

impl Default for SteeringData {
    fn default() -> Self {
        Self::new(0)
    }
}

impl SteeringData {
    /// Maximum length in bytes (`OT_STEERING_DATA_MAX_LENGTH`).
    pub const MAX_LENGTH: usize = 16;

    /// A cleared filter of `len` bytes (`Init`); `len` is capped at 16.
    pub fn new(len: usize) -> Self {
        Self {
            bytes: [0; Self::MAX_LENGTH],
            len: len.min(Self::MAX_LENGTH) as u8,
        }
    }

    /// Copy a filter from a TLV value (longer values are truncated like OT
    /// `SteeringDataTlv::CopyTo`).
    pub fn from_slice(b: &[u8]) -> Self {
        let mut s = Self::new(b.len());
        let n = usize::from(s.len);
        s.bytes[..n].copy_from_slice(&b[..n]);
        s
    }

    /// The filter bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..usize::from(self.len)]
    }

    /// Length in bytes.
    pub fn len(&self) -> usize {
        usize::from(self.len)
    }

    /// Zero length.
    pub fn is_zero_length(&self) -> bool {
        self.len == 0
    }

    /// `SetToPermitAllJoiners`: one byte, all ones.
    pub fn set_permit_all(&mut self) {
        *self = Self::new(1);
        self.bytes[0] = 0xff;
    }

    /// Clear all bits, keeping the length.
    pub fn clear(&mut self) {
        let n = self.len();
        self.bytes[..n].fill(0);
    }

    /// All bits zero (also true for length 0).
    pub fn is_empty(&self) -> bool {
        self.as_bytes().iter().all(|&b| b == 0)
    }

    /// All bits set and non-zero length.
    pub fn permits_all(&self) -> bool {
        self.len > 0 && self.as_bytes().iter().all(|&b| b == 0xff)
    }

    fn num_bits(&self) -> usize {
        usize::from(self.len) * 8
    }

    fn pos(&self, bit: usize) -> (usize, u8) {
        (usize::from(self.len) - 1 - bit / 8, 1 << (bit % 8))
    }

    /// Set the two bits of `idx` (`UpdateBloomFilter`); needs a non-zero
    /// length.
    pub fn update(&mut self, idx: &HashBitIndexes) -> Result<()> {
        if self.len == 0 {
            return Err(Error::InvalidState);
        }
        for i in idx.0 {
            let (p, m) = self.pos(usize::from(i) % self.num_bits());
            self.bytes[p] |= m;
        }
        Ok(())
    }

    /// Add a Joiner ID.
    pub fn add_joiner_id(&mut self, id: &ExtAddress) -> Result<()> {
        self.update(&HashBitIndexes::of_joiner_id(id))
    }

    /// Add a Joiner Discerner.
    pub fn add_discerner(&mut self, d: &JoinerDiscerner) -> Result<()> {
        self.update(&HashBitIndexes::of_discerner(d))
    }

    /// Does the filter contain both bits (`Contains`)?
    pub fn contains_indexes(&self, idx: &HashBitIndexes) -> bool {
        self.len > 0
            && idx.0.iter().all(|&i| {
                let (p, m) = self.pos(usize::from(i) % self.num_bits());
                self.bytes[p] & m != 0
            })
    }

    /// Does the filter contain this Joiner ID?
    pub fn contains_joiner_id(&self, id: &ExtAddress) -> bool {
        self.contains_indexes(&HashBitIndexes::of_joiner_id(id))
    }

    /// Does the filter contain this Joiner Discerner?
    pub fn contains_discerner(&self, d: &JoinerDiscerner) -> bool {
        self.contains_indexes(&HashBitIndexes::of_discerner(d))
    }
}
