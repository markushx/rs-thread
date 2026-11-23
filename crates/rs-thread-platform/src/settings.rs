//! Persistent settings storage trait and an in-memory implementation.

use heapless::Vec;
use rs_thread_core::settings::SettingsKey;
use rs_thread_core::{Error, Result};

/// Blocking persistent key/value store with multiple values per key.
///
/// Semantics follow OpenThread's `otPlatSettings*`
/// (`include/openthread/platform/settings.h`): a key holds an ordered list of
/// values; most keys hold exactly one (written with [`set`](Self::set)), while
/// keys such as [`SettingsKey::ChildInfo`] hold several (written with
/// [`add`](Self::add)).
pub trait SettingsStore {
    /// Read the value at `index` (0-based) for `key` into `buf`.
    ///
    /// Returns the full length of the stored value; if `buf` is smaller the
    /// value is truncated but the full length is still returned (as OpenThread
    /// does). [`Error::NotFound`] if the key or index does not exist.
    fn get(&self, key: SettingsKey, index: usize, buf: &mut [u8]) -> Result<usize>;

    /// Replace all values of `key` with the single value `value`.
    /// [`Error::NoBufs`] if there is no space (existing values are kept).
    fn set(&mut self, key: SettingsKey, value: &[u8]) -> Result<()>;

    /// Append `value` after the existing values of `key`.
    /// [`Error::NoBufs`] if there is no space.
    fn add(&mut self, key: SettingsKey, value: &[u8]) -> Result<()>;

    /// Delete the value at `index` of `key`, or all values if `index` is
    /// `None`. Later values shift down. [`Error::NotFound`] if nothing matches.
    fn delete(&mut self, key: SettingsKey, index: Option<usize>) -> Result<()>;

    /// Remove all settings.
    fn wipe(&mut self);

    /// A counter that changes whenever the store is written (`set`, `add`,
    /// `delete`, `wipe`; the wrapping value itself is meaningless). The async
    /// facade compares it after every step of the node and wakes
    /// `wait_changed` when it moved, so a persistence task notices settings
    /// writes that come with no other state change (for example the frame
    /// counter store-ahead). The default `0` means "not tracked": such a
    /// store is only noticed together with the next state event.
    fn change_count(&self) -> u32 {
        0
    }

    /// Number of values stored for `key`.
    fn count(&self, key: SettingsKey) -> usize {
        let mut n = 0;
        while self.get(key, n, &mut []).is_ok() {
            n += 1;
        }
        n
    }
}

/// Size of the per-record header: key (u16 LE) + value length (u16 LE).
const HEADER: usize = 4;

/// In-memory [`SettingsStore`] using `CAP` bytes of fixed storage, for tests
/// and simulation. Records (header plus value) are stored back to back in
/// insertion order.
#[derive(Debug, Clone, Default)]
pub struct RamSettings<const CAP: usize> {
    data: Vec<u8, CAP>,
    changes: u32,
}

impl<const CAP: usize> RamSettings<CAP> {
    /// Create an empty store.
    pub const fn new() -> Self {
        Self {
            data: Vec::new(),
            changes: 0,
        }
    }

    /// Bytes currently used (including record headers).
    pub fn used(&self) -> usize {
        self.data.len()
    }

    /// Iterate records as `(start, key, value_len)`.
    fn records(&self) -> impl Iterator<Item = (usize, u16, usize)> + '_ {
        let mut pos = 0;
        core::iter::from_fn(move || {
            let h = self.data.get(pos..pos + HEADER)?;
            let key = u16::from_le_bytes([h[0], h[1]]);
            let len = u16::from_le_bytes([h[2], h[3]]) as usize;
            let start = pos;
            pos += HEADER + len;
            Some((start, key, len))
        })
    }

    fn find(&self, key: SettingsKey, index: usize) -> Option<(usize, usize)> {
        self.records()
            .filter(|&(_, k, _)| k == key.as_u16())
            .nth(index)
            .map(|(start, _, len)| (start, len))
    }

    fn remove_record(&mut self, start: usize, len: usize) {
        let end = start + HEADER + len;
        let total = self.data.len();
        self.data.copy_within(end..total, start);
        self.data.truncate(total - (end - start));
    }

    fn push(&mut self, key: SettingsKey, value: &[u8]) -> Result<()> {
        let len = u16::try_from(value.len()).map_err(|_| Error::InvalidArgs)?;
        if self.data.len() + HEADER + value.len() > CAP {
            return Err(Error::NoBufs);
        }
        // Capacity was checked above, so these cannot fail.
        self.data
            .extend_from_slice(&key.as_u16().to_le_bytes())
            .map_err(|_| Error::NoBufs)?;
        self.data
            .extend_from_slice(&len.to_le_bytes())
            .map_err(|_| Error::NoBufs)?;
        self.data
            .extend_from_slice(value)
            .map_err(|_| Error::NoBufs)
    }
}

impl<const CAP: usize> SettingsStore for RamSettings<CAP> {
    fn get(&self, key: SettingsKey, index: usize, buf: &mut [u8]) -> Result<usize> {
        let (start, len) = self.find(key, index).ok_or(Error::NotFound)?;
        let n = len.min(buf.len());
        let v = start + HEADER;
        buf[..n].copy_from_slice(&self.data[v..v + n]);
        Ok(len)
    }

    fn set(&mut self, key: SettingsKey, value: &[u8]) -> Result<()> {
        self.changes = self.changes.wrapping_add(1);
        // Work on a copy only when the new value would not fit after removal;
        // simplest all-or-nothing approach: compute the space freed first.
        let freed: usize = self
            .records()
            .filter(|&(_, k, _)| k == key.as_u16())
            .map(|(_, _, l)| HEADER + l)
            .sum();
        if u16::try_from(value.len()).is_err() {
            return Err(Error::InvalidArgs);
        }
        if self.data.len() - freed + HEADER + value.len() > CAP {
            return Err(Error::NoBufs);
        }
        match self.delete(key, None) {
            Ok(()) | Err(Error::NotFound) => {}
            Err(e) => return Err(e),
        }
        self.push(key, value)
    }

    fn add(&mut self, key: SettingsKey, value: &[u8]) -> Result<()> {
        self.changes = self.changes.wrapping_add(1);
        self.push(key, value)
    }

    fn delete(&mut self, key: SettingsKey, index: Option<usize>) -> Result<()> {
        self.changes = self.changes.wrapping_add(1);
        match index {
            Some(i) => {
                let (start, len) = self.find(key, i).ok_or(Error::NotFound)?;
                self.remove_record(start, len);
                Ok(())
            }
            None => {
                let mut found = false;
                while let Some((start, len)) = self.find(key, 0) {
                    self.remove_record(start, len);
                    found = true;
                }
                if found { Ok(()) } else { Err(Error::NotFound) }
            }
        }
    }

    fn wipe(&mut self) {
        self.changes = self.changes.wrapping_add(1);
        self.data.clear();
    }

    fn change_count(&self) -> u32 {
        self.changes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const K: SettingsKey = SettingsKey::NetworkInfo;
    const C: SettingsKey = SettingsKey::ChildInfo;

    #[test]
    fn set_get_replace() {
        let mut s = RamSettings::<64>::new();
        let mut buf = [0u8; 8];
        assert_eq!(s.get(K, 0, &mut buf), Err(Error::NotFound));
        s.set(K, &[1, 2, 3]).unwrap();
        assert_eq!(s.get(K, 0, &mut buf), Ok(3));
        assert_eq!(&buf[..3], &[1, 2, 3]);
        s.set(K, &[9]).unwrap();
        assert_eq!(s.get(K, 0, &mut buf), Ok(1));
        assert_eq!(buf[0], 9);
        assert_eq!(s.count(K), 1);
        assert_eq!(s.get(K, 1, &mut buf), Err(Error::NotFound));
    }

    #[test]
    fn change_count_moves_on_writes_only() {
        let mut s = RamSettings::<64>::new();
        let c0 = s.change_count();
        let mut b = [0u8; 4];
        let _ = s.get(K, 0, &mut b);
        assert_eq!(s.change_count(), c0);
        s.set(K, &[1]).unwrap();
        let c1 = s.change_count();
        assert_ne!(c1, c0);
        s.add(C, &[2]).unwrap();
        s.delete(C, None).unwrap();
        s.wipe();
        assert_eq!(s.change_count(), c1.wrapping_add(3));
    }

    #[test]
    fn set_replaces_all_values() {
        let mut s = RamSettings::<64>::new();
        s.add(C, &[1]).unwrap();
        s.add(C, &[2]).unwrap();
        s.set(C, &[3]).unwrap();
        assert_eq!(s.count(C), 1);
        let mut b = [0u8; 1];
        s.get(C, 0, &mut b).unwrap();
        assert_eq!(b[0], 3);
    }

    #[test]
    fn multiple_values_and_delete_by_index() {
        let mut s = RamSettings::<64>::new();
        s.add(C, &[10]).unwrap();
        s.set(K, &[0xaa]).unwrap();
        s.add(C, &[20, 21]).unwrap();
        s.add(C, &[30]).unwrap();
        assert_eq!(s.count(C), 3);
        let mut b = [0u8; 4];
        assert_eq!(s.get(C, 1, &mut b), Ok(2));
        assert_eq!(&b[..2], &[20, 21]);
        s.delete(C, Some(1)).unwrap();
        assert_eq!(s.count(C), 2);
        assert_eq!(s.get(C, 1, &mut b), Ok(1));
        assert_eq!(b[0], 30);
        assert_eq!(s.delete(C, Some(2)), Err(Error::NotFound));
        // Other keys are untouched.
        assert_eq!(s.get(K, 0, &mut b), Ok(1));
        assert_eq!(b[0], 0xaa);
        // Delete all values of a key.
        s.delete(C, None).unwrap();
        assert_eq!(s.count(C), 0);
        assert_eq!(s.delete(C, None), Err(Error::NotFound));
        assert_eq!(s.get(K, 0, &mut b), Ok(1));
    }

    #[test]
    fn truncated_get_returns_full_length() {
        let mut s = RamSettings::<64>::new();
        s.set(K, &[1, 2, 3, 4]).unwrap();
        let mut b = [0u8; 2];
        assert_eq!(s.get(K, 0, &mut b), Ok(4));
        assert_eq!(b, [1, 2]);
        assert_eq!(s.get(K, 0, &mut []), Ok(4));
    }

    #[test]
    fn empty_value_and_wipe() {
        let mut s = RamSettings::<64>::new();
        s.set(K, &[]).unwrap();
        assert_eq!(s.get(K, 0, &mut []), Ok(0));
        s.add(C, &[1]).unwrap();
        s.wipe();
        assert_eq!(s.used(), 0);
        assert_eq!(s.get(K, 0, &mut []), Err(Error::NotFound));
    }

    #[test]
    fn capacity_limits() {
        let mut s = RamSettings::<12>::new();
        s.add(C, &[1, 2, 3, 4]).unwrap(); // 8 bytes
        assert_eq!(s.add(C, &[5, 6, 7, 8, 9]), Err(Error::NoBufs));
        assert_eq!(s.count(C), 1);
        s.add(C, &[]).unwrap(); // header only: 4 bytes, now full
        assert_eq!(s.add(C, &[]), Err(Error::NoBufs));
        // A failing set keeps the old value.
        assert_eq!(s.set(C, &[0; 9]), Err(Error::NoBufs));
        assert_eq!(s.count(C), 2);
        // A set that fits only after freeing the old values works.
        s.set(C, &[0; 8]).unwrap();
        assert_eq!(s.count(C), 1);
        assert_eq!(s.used(), 12);
    }

    #[test]
    fn vendor_keys() {
        let mut s = RamSettings::<32>::new();
        let v = SettingsKey::Vendor(0x8123);
        s.set(v, &[7]).unwrap();
        let mut b = [0u8; 1];
        assert_eq!(s.get(v, 0, &mut b), Ok(1));
        assert_eq!(
            s.get(SettingsKey::Vendor(0x8124), 0, &mut b),
            Err(Error::NotFound)
        );
    }

    #[test]
    fn network_info_through_store() {
        use rs_thread_core::settings::{NetworkInfo, THREAD_VERSION_1_1};
        use rs_thread_core::types::{ExtAddress, Iid, Rloc16};
        let ni = NetworkInfo {
            role: 2,
            device_mode: 0x0d,
            rloc16: Rloc16(0x0401),
            key_sequence: 7,
            mle_frame_counter: 1,
            mac_frame_counter: 2,
            previous_partition_id: 3,
            ext_address: ExtAddress([8; 8]),
            ml_iid: Iid([9; 8]),
            version: THREAD_VERSION_1_1,
        };
        let mut s = RamSettings::<64>::new();
        let mut buf = [0u8; NetworkInfo::ENCODED_LEN];
        let n = ni.encode(&mut buf).unwrap();
        s.set(SettingsKey::NetworkInfo, &buf[..n]).unwrap();
        let mut out = [0u8; 64];
        let l = s.get(SettingsKey::NetworkInfo, 0, &mut out).unwrap();
        assert_eq!(NetworkInfo::decode(&out[..l]).unwrap(), ni);
    }
}
