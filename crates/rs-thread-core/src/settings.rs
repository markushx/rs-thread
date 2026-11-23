//! Persistent-settings model, byte-compatible with OpenThread.
//!
//! Keys and record layouts follow OpenThread's
//! `include/openthread/platform/settings.h` (`OT_SETTINGS_KEY_*`) and
//! `src/core/common/settings.hpp` (`Settings::NetworkInfo`,
//! `Settings::ParentInfo`). Records are `OT_TOOL_PACKED` structs: fields are
//! stored back to back with no padding, multi-byte integers little-endian
//! (the C++ code uses `LittleEndian::HostSwap*`), and byte-array fields
//! ([`ExtAddress`], [`Iid`]) as-is. This allows settings blobs to be compared
//! and shared with OpenThread in differential tests.
//!
//! The storage backend itself is the `SettingsStore` trait in
//! `rs-thread-platform`.

use crate::bytes::{Reader, Writer};
use crate::error::Result;
use crate::types::{ExtAddress, Iid, Rloc16};

/// Thread version value OpenThread stores in settings records for Thread 1.1
/// (`OT_THREAD_VERSION_1_1`). OpenThread's `Init()` writes this regardless of
/// the running version.
pub const THREAD_VERSION_1_1: u16 = 2;

/// First vendor-reserved settings key (`OT_SETTINGS_KEY_VENDOR_RESERVED_MIN`).
pub const VENDOR_KEY_MIN: u16 = 0x8000;

/// A settings key. Numeric values equal OpenThread's `OT_SETTINGS_KEY_*`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum SettingsKey {
    /// Active Operational Dataset (1).
    ActiveDataset,
    /// Pending Operational Dataset (2).
    PendingDataset,
    /// Thread network information, see [`NetworkInfo`] (3).
    NetworkInfo,
    /// Parent information, see [`ParentInfo`] (4).
    ParentInfo,
    /// Child information; multiple values (5).
    ChildInfo,
    /// SLAAC secret key for semantically opaque IIDs (7).
    SlaacIidSecretKey,
    /// Duplicate Address Detection information (8).
    DadInfo,
    /// SRP client ECDSA key pair (0x0b).
    SrpEcdsaKey,
    /// SRP client info: selected server address (0x0c).
    SrpClientInfo,
    /// SRP server info: UDP port (0x0d).
    SrpServerInfo,
    /// Border router ULA prefix (0x0f).
    BrUlaPrefix,
    /// Border router local on-link prefixes (0x10).
    BrOnLinkPrefixes,
    /// Unique Border Agent / Router ID (0x11).
    BorderAgentId,
    /// TCAT commissioner certificate (0x12).
    TcatCommrCert,
    /// Vendor-defined key (`0x8000..=0xffff`).
    Vendor(u16),
}

impl SettingsKey {
    /// The OpenThread numeric key.
    pub const fn as_u16(self) -> u16 {
        match self {
            Self::ActiveDataset => 0x0001,
            Self::PendingDataset => 0x0002,
            Self::NetworkInfo => 0x0003,
            Self::ParentInfo => 0x0004,
            Self::ChildInfo => 0x0005,
            Self::SlaacIidSecretKey => 0x0007,
            Self::DadInfo => 0x0008,
            Self::SrpEcdsaKey => 0x000b,
            Self::SrpClientInfo => 0x000c,
            Self::SrpServerInfo => 0x000d,
            Self::BrUlaPrefix => 0x000f,
            Self::BrOnLinkPrefixes => 0x0010,
            Self::BorderAgentId => 0x0011,
            Self::TcatCommrCert => 0x0012,
            Self::Vendor(k) => k,
        }
    }

    /// Parse an OpenThread numeric key. Returns `None` for unassigned keys.
    pub const fn from_u16(key: u16) -> Option<Self> {
        Some(match key {
            0x0001 => Self::ActiveDataset,
            0x0002 => Self::PendingDataset,
            0x0003 => Self::NetworkInfo,
            0x0004 => Self::ParentInfo,
            0x0005 => Self::ChildInfo,
            0x0007 => Self::SlaacIidSecretKey,
            0x0008 => Self::DadInfo,
            0x000b => Self::SrpEcdsaKey,
            0x000c => Self::SrpClientInfo,
            0x000d => Self::SrpServerInfo,
            0x000f => Self::BrUlaPrefix,
            0x0010 => Self::BrOnLinkPrefixes,
            0x0011 => Self::BorderAgentId,
            0x0012 => Self::TcatCommrCert,
            k if k >= VENDOR_KEY_MIN => Self::Vendor(k),
            _ => return None,
        })
    }
}

/// The device's own network information (`Settings::NetworkInfo`, key
/// [`SettingsKey::NetworkInfo`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct NetworkInfo {
    /// Thread role as OpenThread's `otDeviceRole` (0 disabled, 1 detached,
    /// 2 child, 3 router, 4 leader).
    pub role: u8,
    /// Device mode bits (`otLinkModeConfig` as a byte).
    pub device_mode: u8,
    /// RLOC16.
    pub rloc16: Rloc16,
    /// Key sequence.
    pub key_sequence: u32,
    /// MLE frame counter.
    pub mle_frame_counter: u32,
    /// MAC frame counter.
    pub mac_frame_counter: u32,
    /// Previous partition ID.
    pub previous_partition_id: u32,
    /// Extended address.
    pub ext_address: ExtAddress,
    /// Mesh-local IID (ML-EID).
    pub ml_iid: Iid,
    /// Thread version stored with the record.
    pub version: u16,
}

impl NetworkInfo {
    /// Encoded size: `1+1+2+4+4+4+4+8+8+2` bytes (packed C++ struct).
    pub const ENCODED_LEN: usize = 38;

    /// Encode in OpenThread's layout. Returns the number of bytes written
    /// ([`Self::ENCODED_LEN`]); [`crate::Error::NoBufs`] if `out` is too small.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize> {
        let mut w = Writer::new(out);
        w.write_u8(self.role)?;
        w.write_u8(self.device_mode)?;
        w.write_u16_le(self.rloc16.0)?;
        w.write_u32_le(self.key_sequence)?;
        w.write_u32_le(self.mle_frame_counter)?;
        w.write_u32_le(self.mac_frame_counter)?;
        w.write_u32_le(self.previous_partition_id)?;
        w.write_slice(self.ext_address.as_bytes())?;
        w.write_slice(self.ml_iid.as_bytes())?;
        w.write_u16_le(self.version)?;
        Ok(w.len())
    }

    /// Decode from OpenThread's layout. Like OpenThread, trailing bytes are
    /// ignored; a shorter blob is a parse error.
    pub fn decode(buf: &[u8]) -> Result<Self> {
        let mut r = Reader::new(buf);
        Ok(Self {
            role: r.read_u8()?,
            device_mode: r.read_u8()?,
            rloc16: Rloc16(r.read_u16_le()?),
            key_sequence: r.read_u32_le()?,
            mle_frame_counter: r.read_u32_le()?,
            mac_frame_counter: r.read_u32_le()?,
            previous_partition_id: r.read_u32_le()?,
            ext_address: ExtAddress(r.read_array()?),
            ml_iid: Iid(r.read_array()?),
            version: r.read_u16_le()?,
        })
    }
}

/// Information about the attached parent (`Settings::ParentInfo`, key
/// [`SettingsKey::ParentInfo`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct ParentInfo {
    /// Parent's extended address.
    pub ext_address: ExtAddress,
    /// Thread version stored with the record.
    pub version: u16,
}

impl ParentInfo {
    /// Encoded size: `8+2` bytes (packed C++ struct).
    pub const ENCODED_LEN: usize = 10;

    /// Encode in OpenThread's layout. Returns the number of bytes written.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize> {
        let mut w = Writer::new(out);
        w.write_slice(self.ext_address.as_bytes())?;
        w.write_u16_le(self.version)?;
        Ok(w.len())
    }

    /// Decode from OpenThread's layout (trailing bytes ignored).
    pub fn decode(buf: &[u8]) -> Result<Self> {
        let mut r = Reader::new(buf);
        Ok(Self {
            ext_address: ExtAddress(r.read_array()?),
            version: r.read_u16_le()?,
        })
    }
}

/// One child of the child table (`Settings::ChildInfo`, key
/// [`SettingsKey::ChildInfo`]; one record per child, stored with
/// `Settings::AddChildInfo`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct ChildInfo {
    /// Child's extended address.
    pub ext_address: ExtAddress,
    /// Child timeout in seconds.
    pub timeout: u32,
    /// Child's RLOC16.
    pub rloc16: Rloc16,
    /// MLE device mode bits.
    pub mode: u8,
    /// Thread version of the child.
    pub version: u16,
}

impl ChildInfo {
    /// Encoded size: `8+4+2+1+2` bytes (packed C++ struct).
    pub const ENCODED_LEN: usize = 17;

    /// Encode in OpenThread's layout. Returns the number of bytes written.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize> {
        let mut w = Writer::new(out);
        w.write_slice(self.ext_address.as_bytes())?;
        w.write_u32_le(self.timeout)?;
        w.write_u16_le(self.rloc16.0)?;
        w.write_u8(self.mode)?;
        w.write_u16_le(self.version)?;
        Ok(w.len())
    }

    /// Decode from OpenThread's layout (trailing bytes ignored).
    pub fn decode(buf: &[u8]) -> Result<Self> {
        let mut r = Reader::new(buf);
        Ok(Self {
            ext_address: ExtAddress(r.read_array()?),
            timeout: r.read_u32_le()?,
            rloc16: Rloc16(r.read_u16_le()?),
            mode: r.read_u8()?,
            version: r.read_u16_le()?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Error;

    #[test]
    fn key_numbers_match_openthread() {
        let all = [
            (SettingsKey::ActiveDataset, 1),
            (SettingsKey::PendingDataset, 2),
            (SettingsKey::NetworkInfo, 3),
            (SettingsKey::ParentInfo, 4),
            (SettingsKey::ChildInfo, 5),
            (SettingsKey::SlaacIidSecretKey, 7),
            (SettingsKey::DadInfo, 8),
            (SettingsKey::SrpEcdsaKey, 0x0b),
            (SettingsKey::SrpClientInfo, 0x0c),
            (SettingsKey::SrpServerInfo, 0x0d),
            (SettingsKey::BrUlaPrefix, 0x0f),
            (SettingsKey::BrOnLinkPrefixes, 0x10),
            (SettingsKey::BorderAgentId, 0x11),
            (SettingsKey::TcatCommrCert, 0x12),
            (SettingsKey::Vendor(0x8001), 0x8001),
        ];
        for (k, n) in all {
            assert_eq!(k.as_u16(), n);
            assert_eq!(SettingsKey::from_u16(n), Some(k));
        }
        assert_eq!(SettingsKey::from_u16(0), None);
        assert_eq!(SettingsKey::from_u16(6), None);
        assert_eq!(SettingsKey::from_u16(0x13), None);
        assert_eq!(SettingsKey::from_u16(0x7fff), None);
    }

    fn sample_network_info() -> NetworkInfo {
        NetworkInfo {
            role: 3,
            device_mode: 0x0f,
            rloc16: Rloc16(0x1c00),
            key_sequence: 0x0102_0304,
            mle_frame_counter: 0x1111_2222,
            mac_frame_counter: 0xaabb_ccdd,
            previous_partition_id: 0xdead_beef,
            ext_address: ExtAddress([1, 2, 3, 4, 5, 6, 7, 8]),
            ml_iid: Iid([0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7]),
            version: THREAD_VERSION_1_1,
        }
    }

    // Layout from OpenThread src/core/common/settings.hpp, `Settings::NetworkInfo`
    // (OT_TOOL_PACKED): u8 role, u8 device_mode, u16 rloc16, u32 key_sequence,
    // u32 mle_frame_counter, u32 mac_frame_counter, u32 previous_partition_id,
    // ExtAddress[8], InterfaceIdentifier[8], u16 version; integers little-endian.
    const NETWORK_INFO_BYTES: [u8; 38] = [
        0x03, // role
        0x0f, // device mode
        0x00, 0x1c, // rloc16 = 0x1c00 LE
        0x04, 0x03, 0x02, 0x01, // key sequence
        0x22, 0x22, 0x11, 0x11, // mle frame counter
        0xdd, 0xcc, 0xbb, 0xaa, // mac frame counter
        0xef, 0xbe, 0xad, 0xde, // previous partition id
        1, 2, 3, 4, 5, 6, 7, 8, // ext address
        0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, // ml iid
        0x02, 0x00, // version = 2 LE
    ];

    #[test]
    fn network_info_layout_and_roundtrip() {
        let ni = sample_network_info();
        let mut buf = [0u8; 64];
        let n = ni.encode(&mut buf).unwrap();
        assert_eq!(n, NetworkInfo::ENCODED_LEN);
        assert_eq!(&buf[..n], &NETWORK_INFO_BYTES);
        assert_eq!(NetworkInfo::decode(&buf[..n]).unwrap(), ni);
        // Trailing bytes are ignored.
        assert_eq!(NetworkInfo::decode(&buf).unwrap(), ni);
    }

    #[test]
    fn network_info_errors() {
        let ni = sample_network_info();
        let mut small = [0u8; 37];
        assert_eq!(ni.encode(&mut small).unwrap_err(), Error::NoBufs);
        assert_eq!(
            NetworkInfo::decode(&NETWORK_INFO_BYTES[..37]).unwrap_err(),
            Error::Parse
        );
        assert!(NetworkInfo::decode(&[]).is_err());
    }

    // Layout from OpenThread `Settings::ParentInfo` (OT_TOOL_PACKED):
    // ExtAddress[8], u16 version (little-endian).
    #[test]
    fn parent_info_layout_and_roundtrip() {
        let pi = ParentInfo {
            ext_address: ExtAddress([0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80]),
            version: 5,
        };
        let mut buf = [0u8; 10];
        assert_eq!(pi.encode(&mut buf).unwrap(), ParentInfo::ENCODED_LEN);
        assert_eq!(
            buf,
            [0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x05, 0x00]
        );
        assert_eq!(ParentInfo::decode(&buf).unwrap(), pi);
        assert_eq!(ParentInfo::decode(&buf[..9]).unwrap_err(), Error::Parse);
        assert_eq!(pi.encode(&mut buf[..9]).unwrap_err(), Error::NoBufs);
    }

    // Layout from OpenThread `Settings::ChildInfo` (OT_TOOL_PACKED):
    // ExtAddress[8], u32 timeout, u16 rloc16, u8 mode, u16 version, little-endian.
    #[test]
    fn child_info_layout_and_roundtrip() {
        let ci = ChildInfo {
            ext_address: ExtAddress([1, 2, 3, 4, 5, 6, 7, 8]),
            timeout: 0x0000_00f0,
            rloc16: Rloc16(0x0401),
            mode: 0x0a,
            version: 4,
        };
        let mut buf = [0u8; 17];
        assert_eq!(ci.encode(&mut buf).unwrap(), ChildInfo::ENCODED_LEN);
        assert_eq!(
            buf,
            [
                1, 2, 3, 4, 5, 6, 7, 8, 0xf0, 0, 0, 0, 0x01, 0x04, 0x0a, 0x04, 0x00
            ]
        );
        assert_eq!(ChildInfo::decode(&buf).unwrap(), ci);
        for n in 0..17 {
            assert_eq!(ChildInfo::decode(&buf[..n]).unwrap_err(), Error::Parse);
        }
        assert_eq!(ci.encode(&mut buf[..16]).unwrap_err(), Error::NoBufs);
    }
}
