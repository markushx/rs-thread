//! The Operational Dataset: a fixed-capacity buffer of MeshCoP TLVs (OT
//! `meshcop/dataset.{hpp,cpp}`).
//!
//! A [`Dataset`] holds the TLVs of an Active or Pending Operational Dataset
//! exactly as they travel in MeshCoP and MLE messages (no extended TLVs, no
//! duplicates, at most [`MAX_LEN`] bytes). Typed access goes through
//! [`Dataset::tlvs`] ([`Tlvs`]) and the `set_*` methods;
//! [`Dataset::validate`] is OT `ValidateTlvs`, [`Dataset::contains_all_required_for`]
//! the completeness check of a complete Active / Pending Dataset.

use rs_thread_core::tlv::TlvIter;
use rs_thread_core::types::{ExtPanId, NetworkKey, NetworkName, Prefix64, Pskc};
use rs_thread_core::{Error, Result};

use crate::timestamp::Timestamp;
use crate::tlv::{ChannelValue, SecurityPolicy, Tlvs, ty};

/// Maximum dataset length in bytes (`OT_OPERATIONAL_DATASET_MAX_LENGTH`).
pub const MAX_LEN: usize = 254;

/// Which dataset.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum DatasetType {
    /// Active Operational Dataset.
    Active,
    /// Pending Operational Dataset.
    Pending,
}

impl DatasetType {
    /// The Timestamp TLV type of this dataset.
    pub const fn timestamp_tlv(self) -> u8 {
        match self {
            Self::Active => ty::ACTIVE_TIMESTAMP,
            Self::Pending => ty::PENDING_TIMESTAMP,
        }
    }

    pub(crate) const fn index(self) -> usize {
        match self {
            Self::Active => 0,
            Self::Pending => 1,
        }
    }
}

/// An Operational Dataset (TLV buffer).
#[derive(Clone, PartialEq, Eq)]
pub struct Dataset {
    buf: [u8; MAX_LEN],
    len: u8,
}

/// The buffer holds the Network Key and PSKc: wipe it.
impl Drop for Dataset {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.buf);
    }
}

impl core::fmt::Debug for Dataset {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Keys are not printed.
        write!(f, "Dataset({} bytes)", self.len)
    }
}

#[cfg(feature = "defmt")]
impl defmt::Format for Dataset {
    fn format(&self, f: defmt::Formatter<'_>) {
        defmt::write!(f, "Dataset({=u8} bytes)", self.len);
    }
}

impl Default for Dataset {
    fn default() -> Self {
        Self::new()
    }
}

/// Is the value of a dataset TLV well-formed (OT `Dataset::IsTlvValid`)?
fn is_tlv_valid(ty: u8, v: &[u8]) -> bool {
    let min_len = match ty {
        ty::ACTIVE_TIMESTAMP | ty::PENDING_TIMESTAMP => 8,
        ty::DELAY_TIMER => 4,
        ty::PAN_ID => 2,
        ty::EXT_PAN_ID | ty::MESH_LOCAL_PREFIX => 8,
        ty::PSKC | ty::NETWORK_KEY => 16,
        ty::CHANNEL | ty::WAKEUP_CHANNEL => {
            return ChannelValue::from_bytes(v).is_ok_and(|c| c.is_valid());
        }
        ty::NETWORK_NAME => return NetworkName::is_valid_text(v),
        ty::SECURITY_POLICY => return SecurityPolicy::is_valid_len(v.len()),
        ty::CHANNEL_MASK => return crate::tlv::parse_channel_mask(v).is_ok(),
        _ => 0,
    };
    v.len() >= min_len
}

impl Dataset {
    /// An empty dataset.
    pub const fn new() -> Self {
        Self {
            buf: [0; MAX_LEN],
            len: 0,
        }
    }

    /// Copy `tlvs` without validating them (OT `SetFrom`); [`Error::InvalidArgs`]
    /// if longer than [`MAX_LEN`].
    pub fn from_tlvs_unchecked(tlvs: &[u8]) -> Result<Self> {
        if tlvs.len() > MAX_LEN {
            return Err(Error::InvalidArgs);
        }
        let mut d = Self::new();
        d.buf[..tlvs.len()].copy_from_slice(tlvs);
        d.len = tlvs.len() as u8;
        Ok(d)
    }

    /// Copy and validate (`SetFrom` + `ValidateTlvs`).
    pub fn from_tlvs(tlvs: &[u8]) -> Result<Self> {
        let d = Self::from_tlvs_unchecked(tlvs)?;
        d.validate()?;
        Ok(d)
    }

    /// The TLV bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.buf[..usize::from(self.len)]
    }

    /// Length in bytes.
    pub fn len(&self) -> usize {
        usize::from(self.len)
    }

    /// No TLVs.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Remove everything.
    pub fn clear(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.buf);
        self.len = 0;
    }

    /// Typed read view.
    pub fn tlvs(&self) -> Tlvs<'_> {
        Tlvs(self.as_bytes())
    }

    /// OT `ValidateTlvs`: well-formed framing without extended TLVs, every
    /// known TLV valid, no duplicates.
    pub fn validate(&self) -> Result<()> {
        let mut seen = [0u32; 8];
        for t in TlvIter::new(self.as_bytes()) {
            let t = t?;
            if t.is_extended() || !is_tlv_valid(t.ty(), t.value()) {
                return Err(Error::Parse);
            }
            let (w, b) = (usize::from(t.ty() / 32), t.ty() % 32);
            if seen[w] & (1 << b) != 0 {
                return Err(Error::Parse);
            }
            seen[w] |= 1 << b;
        }
        Ok(())
    }

    /// Is a TLV of `ty` present?
    pub fn contains(&self, ty: u8) -> bool {
        self.tlvs().contains(ty)
    }

    /// Remove the TLV of `ty` (OT `RemoveTlv`).
    pub fn remove(&mut self, ty: u8) {
        let Some((off, size)) = self.locate(ty) else {
            return;
        };
        let total = usize::from(self.len);
        self.buf.copy_within(off + size..total, off);
        self.len -= size as u8;
    }

    /// Offset and size of the TLV of `ty`.
    fn locate(&self, ty: u8) -> Option<(usize, usize)> {
        let bytes = self.as_bytes();
        let mut off = 0;
        while let Ok((t, rest)) = rs_thread_core::tlv::Tlv::parse(&bytes[off..]) {
            let size = bytes.len() - off - rest.len();
            if t.ty() == ty {
                return Some((off, size));
            }
            off += size;
        }
        None
    }

    /// Set the TLV of `ty` (OT `WriteTlv`): an existing TLV is removed and
    /// the new one appended. [`Error::NoBufs`] if it does not fit (the
    /// dataset is unchanged then); values over 254 bytes are
    /// [`Error::InvalidArgs`].
    pub fn write_tlv(&mut self, ty: u8, value: &[u8]) -> Result<()> {
        if value.len() > 254 {
            return Err(Error::InvalidArgs);
        }
        let old = self.locate(ty).map_or(0, |(_, size)| size);
        if usize::from(self.len) - old + 2 + value.len() > MAX_LEN {
            return Err(Error::NoBufs);
        }
        self.remove(ty);
        let n = usize::from(self.len);
        self.buf[n] = ty;
        self.buf[n + 1] = value.len() as u8;
        self.buf[n + 2..n + 2 + value.len()].copy_from_slice(value);
        self.len += 2 + value.len() as u8;
        Ok(())
    }

    /// Set every TLV of `other` (OT `WriteTlvsFrom(Dataset)`).
    pub fn write_tlvs_from(&mut self, other: &Dataset) -> Result<()> {
        other.validate()?;
        for t in TlvIter::new(other.as_bytes()) {
            let t = t?;
            self.write_tlv(t.ty(), t.value())?;
        }
        Ok(())
    }

    /// The Active or Pending Timestamp (`ReadTimestamp`).
    pub fn timestamp(&self, ty: DatasetType) -> Option<Timestamp> {
        Timestamp::from_bytes(self.tlvs().value(ty.timestamp_tlv()).ok()?).ok()
    }

    /// Set the Active or Pending Timestamp.
    pub fn set_timestamp(&mut self, ty: DatasetType, t: &Timestamp) -> Result<()> {
        self.write_tlv(ty.timestamp_tlv(), &t.to_bytes())
    }

    /// Remove the Active or Pending Timestamp.
    pub fn remove_timestamp(&mut self, ty: DatasetType) {
        self.remove(ty.timestamp_tlv());
    }

    /// Set the Delay Timer TLV (milliseconds).
    pub fn set_delay_timer(&mut self, ms: u32) -> Result<()> {
        self.write_tlv(ty::DELAY_TIMER, &ms.to_be_bytes())
    }

    /// Set the Channel TLV (page 0).
    pub fn set_channel(&mut self, channel: u8) -> Result<()> {
        self.write_tlv(
            ty::CHANNEL,
            &ChannelValue {
                page: 0,
                channel: u16::from(channel),
            }
            .to_bytes(),
        )
    }

    /// Set the Channel Mask TLV (page 0).
    pub fn set_channel_mask(&mut self, mask: u32) -> Result<()> {
        self.write_tlv(ty::CHANNEL_MASK, &crate::tlv::channel_mask_entry(mask))
    }

    /// Set the PAN ID TLV.
    pub fn set_pan_id(&mut self, v: u16) -> Result<()> {
        self.write_tlv(ty::PAN_ID, &v.to_be_bytes())
    }

    /// Set the Extended PAN ID TLV.
    pub fn set_ext_pan_id(&mut self, v: &ExtPanId) -> Result<()> {
        self.write_tlv(ty::EXT_PAN_ID, &v.0)
    }

    /// Set the Network Name TLV.
    pub fn set_network_name(&mut self, v: &NetworkName) -> Result<()> {
        self.write_tlv(ty::NETWORK_NAME, v.as_bytes())
    }

    /// Set the Network Key TLV.
    pub fn set_network_key(&mut self, v: &NetworkKey) -> Result<()> {
        self.write_tlv(ty::NETWORK_KEY, &v.0)
    }

    /// Set the PSKc TLV.
    pub fn set_pskc(&mut self, v: &Pskc) -> Result<()> {
        self.write_tlv(ty::PSKC, &v.0)
    }

    /// Set the Mesh-Local Prefix TLV.
    pub fn set_mesh_local_prefix(&mut self, v: &Prefix64) -> Result<()> {
        self.write_tlv(ty::MESH_LOCAL_PREFIX, &v.0)
    }

    /// Set the Security Policy TLV.
    pub fn set_security_policy(&mut self, v: &SecurityPolicy) -> Result<()> {
        self.write_tlv(ty::SECURITY_POLICY, &v.to_bytes())
    }

    /// The TLVs every complete dataset of this type must have (OT
    /// `ContainsAllRequiredTlvsFor`).
    pub fn contains_all_required_for(&self, kind: DatasetType) -> bool {
        const COMMON: [u8; 10] = [
            ty::ACTIVE_TIMESTAMP,
            ty::CHANNEL,
            ty::CHANNEL_MASK,
            ty::EXT_PAN_ID,
            ty::MESH_LOCAL_PREFIX,
            ty::NETWORK_KEY,
            ty::NETWORK_NAME,
            ty::PAN_ID,
            ty::PSKC,
            ty::SECURITY_POLICY,
        ];
        COMMON.iter().all(|&t| self.contains(t))
            && (kind == DatasetType::Active
                || (self.contains(ty::PENDING_TIMESTAMP) && self.contains(ty::DELAY_TIMER)))
    }

    /// Enough to join and operate: Network Key, Network Name, Extended PAN
    /// ID, PAN ID and Channel (OT `IsCommissioned`).
    pub fn is_commissioned(&self) -> bool {
        [
            ty::NETWORK_KEY,
            ty::NETWORK_NAME,
            ty::EXT_PAN_ID,
            ty::PAN_ID,
            ty::CHANNEL,
        ]
        .iter()
        .all(|&t| self.contains(t))
    }

    /// Are all TLVs of `self` (except timestamps and the delay timer) present
    /// with the same value in `other`? (OT `IsSubsetOf`)
    pub fn is_subset_of(&self, other: &Dataset) -> bool {
        TlvIter::new(self.as_bytes()).all(|t| match t {
            Ok(t) => {
                matches!(
                    t.ty(),
                    ty::ACTIVE_TIMESTAMP | ty::PENDING_TIMESTAMP | ty::DELAY_TIMER
                ) || other.tlvs().value(t.ty()).is_ok_and(|v| v == t.value())
            }
            Err(_) => false,
        })
    }

    /// Append the bytes of every TLV except `skip`, e.g. the dataset
    /// without its timestamp for the MLE Active / Pending Dataset TLV;
    /// returns the length written to `out`.
    pub fn copy_without(&self, skip: u8, out: &mut [u8]) -> Result<usize> {
        let mut n = 0;
        for t in TlvIter::new(self.as_bytes()) {
            let t = t?;
            if t.ty() == skip {
                continue;
            }
            let size = 2 + t.value().len();
            let dst = out.get_mut(n..n + size).ok_or(Error::NoBufs)?;
            dst[0] = t.ty();
            dst[1] = t.value().len() as u8;
            dst[2..].copy_from_slice(t.value());
            n += size;
        }
        Ok(n)
    }
}
