//! The RAM image: records in insertion order, dirty-key tracking.

use core::cell::RefCell;

use critical_section::Mutex;
use opentrust_core::settings::SettingsKey;
use opentrust_core::{Error, Result};
use opentrust_platform::SettingsStore;

/// Per-record header in the image: key (u16 LE) + value length (u16 LE).
const HEADER: usize = 4;

/// The settings held in RAM: records `(key, value)` back to back in insertion
/// order (several records may share a key), the keys that differ from flash
/// and a change counter.
///
/// This is the part the node touches; it never waits for flash. It is
/// normally reached through a [`Shared`] cell.
#[derive(Debug)]
pub struct Image<const CAP: usize, const KEYS: usize> {
    data: [u8; CAP],
    len: usize,
    /// Keys changed since they were last written to flash.
    dirty: heapless::Vec<u16, KEYS>,
    /// Too many dirty keys (or a wipe): the next flush rewrites everything.
    dirty_all: bool,
    /// A wipe happened: the flush also erases the stale bank.
    wiped: bool,
    changes: u32,
}

impl<const CAP: usize, const KEYS: usize> Image<CAP, KEYS> {
    /// An empty image.
    pub const fn new() -> Self {
        Self {
            data: [0; CAP],
            len: 0,
            dirty: heapless::Vec::new(),
            dirty_all: false,
            wiped: false,
            changes: 0,
        }
    }

    /// Bytes of the image in use (record headers included).
    pub fn used(&self) -> usize {
        self.len
    }

    fn records(&self) -> impl Iterator<Item = (usize, u16, usize)> + '_ {
        let mut pos = 0;
        core::iter::from_fn(move || {
            if pos >= self.len {
                return None;
            }
            let h = &self.data[pos..pos + HEADER];
            let key = u16::from_le_bytes([h[0], h[1]]);
            let len = u16::from_le_bytes([h[2], h[3]]) as usize;
            let start = pos;
            pos += HEADER + len;
            Some((start, key, len))
        })
    }

    fn find(&self, key: u16, index: usize) -> Option<(usize, usize)> {
        self.records()
            .filter(|&(_, k, _)| k == key)
            .nth(index)
            .map(|(s, _, l)| (s, l))
    }

    fn remove_record(&mut self, start: usize, len: usize) {
        let end = start + HEADER + len;
        self.data.copy_within(end..self.len, start);
        self.len -= end - start;
    }

    fn push(&mut self, key: u16, value: &[u8]) -> Result<()> {
        let len = u16::try_from(value.len()).map_err(|_| Error::InvalidArgs)?;
        if self.len + HEADER + value.len() > CAP {
            return Err(Error::NoBufs);
        }
        let p = self.len;
        self.data[p..p + 2].copy_from_slice(&key.to_le_bytes());
        self.data[p + 2..p + HEADER].copy_from_slice(&len.to_le_bytes());
        self.data[p + HEADER..p + HEADER + value.len()].copy_from_slice(value);
        self.len += HEADER + value.len();
        Ok(())
    }

    fn mark(&mut self, key: u16) {
        self.changes = self.changes.wrapping_add(1);
        if self.dirty_all || self.dirty.contains(&key) {
            return;
        }
        if self.dirty.push(key).is_err() {
            self.dirty_all = true;
            self.dirty.clear();
        }
    }

    /// Read value `index` of `key`; returns its full length (see
    /// [`SettingsStore::get`]).
    pub fn get(&self, key: u16, index: usize, buf: &mut [u8]) -> Result<usize> {
        let (start, len) = self.find(key, index).ok_or(Error::NotFound)?;
        let n = len.min(buf.len());
        let v = start + HEADER;
        buf[..n].copy_from_slice(&self.data[v..v + n]);
        Ok(len)
    }

    /// Replace all values of `key` by `value`. On [`Error::NoBufs`] the
    /// existing values are kept.
    pub fn set(&mut self, key: u16, value: &[u8]) -> Result<()> {
        if value.len() > usize::from(u16::MAX) {
            return Err(Error::InvalidArgs);
        }
        let freed: usize = self
            .records()
            .filter(|&(_, k, _)| k == key)
            .map(|(_, _, l)| HEADER + l)
            .sum();
        if self.len - freed + HEADER + value.len() > CAP {
            return Err(Error::NoBufs);
        }
        self.remove_all(key);
        self.push(key, value)?;
        self.mark(key);
        Ok(())
    }

    /// Append `value` after the existing values of `key`.
    pub fn add(&mut self, key: u16, value: &[u8]) -> Result<()> {
        self.push(key, value)?;
        self.mark(key);
        Ok(())
    }

    /// Delete value `index` of `key`, or all of them for `None`.
    pub fn delete(&mut self, key: u16, index: Option<usize>) -> Result<()> {
        match index {
            Some(i) => {
                let (start, len) = self.find(key, i).ok_or(Error::NotFound)?;
                self.remove_record(start, len);
            }
            None => {
                if self.find(key, 0).is_none() {
                    return Err(Error::NotFound);
                }
                self.remove_all(key);
            }
        }
        self.mark(key);
        Ok(())
    }

    fn remove_all(&mut self, key: u16) {
        while let Some((start, len)) = self.find(key, 0) {
            self.remove_record(start, len);
        }
    }

    /// Remove everything. Flash is rewritten (and the old bank erased) by
    /// the next flush.
    pub fn wipe(&mut self) {
        self.len = 0;
        self.dirty.clear();
        self.dirty_all = true;
        self.wiped = true;
        self.changes = self.changes.wrapping_add(1);
    }

    /// The change counter (see [`SettingsStore::change_count`]).
    pub fn change_count(&self) -> u32 {
        self.changes
    }

    /// Whether flash is out of date.
    pub fn is_dirty(&self) -> bool {
        self.dirty_all || !self.dirty.is_empty()
    }

    /// The smallest key greater than `after` (or the smallest key for
    /// `None`) that has a value.
    pub fn next_key(&self, after: Option<u16>) -> Option<u16> {
        self.records()
            .map(|(_, k, _)| k)
            .filter(|&k| after.is_none_or(|a| k > a))
            .min()
    }

    /// Encode all values of `key` as `[len u16 LE, bytes]*` into `out`.
    /// Returns `(count, bytes)`.
    pub(crate) fn encode_key(&self, key: u16, out: &mut [u8]) -> Result<(u8, usize)> {
        let mut n = 0usize;
        let mut count = 0usize;
        for (start, _, len) in self.records().filter(|&(_, k, _)| k == key) {
            let end = n + 2 + len;
            if end > out.len() || count == usize::from(u8::MAX) {
                return Err(Error::NoBufs);
            }
            out[n..n + 2].copy_from_slice(&(len as u16).to_le_bytes());
            out[n + 2..end].copy_from_slice(&self.data[start + HEADER..start + HEADER + len]);
            n = end;
            count += 1;
        }
        Ok((count as u8, n))
    }

    /// Replace the values of `key` by those of an encoded payload (the
    /// replay of a flash entry). Does not mark the key dirty.
    pub(crate) fn apply_put(&mut self, key: u16, count: u8, payload: &[u8]) -> Result<()> {
        // Validate first so a bad payload leaves the key alone.
        let mut p = 0;
        for _ in 0..count {
            let h = payload.get(p..p + 2).ok_or(Error::Parse)?;
            let len = usize::from(u16::from_le_bytes([h[0], h[1]]));
            payload.get(p + 2..p + 2 + len).ok_or(Error::Parse)?;
            p += 2 + len;
        }
        if p != payload.len() {
            return Err(Error::Parse);
        }
        self.remove_all(key);
        let mut p = 0;
        for _ in 0..count {
            let len = usize::from(u16::from_le_bytes([payload[p], payload[p + 1]]));
            self.push(key, &payload[p + 2..p + 2 + len])?;
            p += 2 + len;
        }
        Ok(())
    }

    /// Take the next dirty key and encode it. `None` if no key is dirty.
    /// On an encoding error the key stays dirty.
    pub(crate) fn take_dirty(&mut self, out: &mut [u8]) -> Result<Option<(u16, u8, usize)>> {
        let Some(&key) = self.dirty.last() else {
            return Ok(None);
        };
        let (count, n) = self.encode_key(key, out)?;
        self.dirty.pop();
        Ok(Some((key, count, n)))
    }

    /// Put `key` back into the dirty list (a failed flash write).
    pub(crate) fn redirty(&mut self, key: u16) {
        if !self.dirty_all && !self.dirty.contains(&key) && self.dirty.push(key).is_err() {
            self.dirty_all = true;
            self.dirty.clear();
        }
    }

    pub(crate) fn clear_dirty(&mut self, key: u16) {
        self.dirty.retain(|&k| k != key);
    }

    pub(crate) fn take_dirty_all(&mut self) -> bool {
        core::mem::take(&mut self.dirty_all)
    }

    pub(crate) fn take_wiped(&mut self) -> bool {
        core::mem::take(&mut self.wiped)
    }

    pub(crate) fn set_dirty_all(&mut self) {
        self.dirty_all = true;
    }

    /// Forget dirtiness (after a mount, when the image equals flash).
    pub(crate) fn clear_all_dirty(&mut self) {
        self.dirty.clear();
        self.dirty_all = false;
        self.wiped = false;
    }
}

impl<const CAP: usize, const KEYS: usize> Default for Image<CAP, KEYS> {
    fn default() -> Self {
        Self::new()
    }
}

/// An [`Image`] shared between the node (through [`Settings`]), the
/// persistence task (through the flash writer) and, for a key-value store, the
/// application. Access is by critical section, kept short: nothing here waits
/// for flash.
#[derive(Debug)]
pub struct Shared<const CAP: usize, const KEYS: usize>(Mutex<RefCell<Image<CAP, KEYS>>>);

impl<const CAP: usize, const KEYS: usize> Shared<CAP, KEYS> {
    /// An empty shared image (usable in a `static`).
    pub const fn new() -> Self {
        Self(Mutex::new(RefCell::new(Image::new())))
    }

    /// Run `f` on the image inside a critical section.
    pub fn with<R>(&self, f: impl FnOnce(&mut Image<CAP, KEYS>) -> R) -> R {
        critical_section::with(|cs| f(&mut self.0.borrow_ref_mut(cs)))
    }

    /// A [`SettingsStore`] over this image, for the node.
    pub const fn settings(&self) -> Settings<'_, CAP, KEYS> {
        Settings(self)
    }

    /// Whether flash is out of date.
    pub fn is_dirty(&self) -> bool {
        self.with(|i| i.is_dirty())
    }
}

impl<const CAP: usize, const KEYS: usize> Default for Shared<CAP, KEYS> {
    fn default() -> Self {
        Self::new()
    }
}

/// [`SettingsStore`] over a [`Shared`] image: reads and writes go to RAM, a
/// [`FlashWriter`](crate::FlashWriter) persists them in the background.
#[derive(Debug)]
pub struct Settings<'a, const CAP: usize, const KEYS: usize>(&'a Shared<CAP, KEYS>);

impl<const CAP: usize, const KEYS: usize> Clone for Settings<'_, CAP, KEYS> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<const CAP: usize, const KEYS: usize> Copy for Settings<'_, CAP, KEYS> {}

impl<const CAP: usize, const KEYS: usize> SettingsStore for Settings<'_, CAP, KEYS> {
    fn get(&self, key: SettingsKey, index: usize, buf: &mut [u8]) -> Result<usize> {
        self.0.with(|i| i.get(key.as_u16(), index, buf))
    }

    fn set(&mut self, key: SettingsKey, value: &[u8]) -> Result<()> {
        self.0.with(|i| i.set(key.as_u16(), value))
    }

    fn add(&mut self, key: SettingsKey, value: &[u8]) -> Result<()> {
        self.0.with(|i| i.add(key.as_u16(), value))
    }

    fn delete(&mut self, key: SettingsKey, index: Option<usize>) -> Result<()> {
        self.0.with(|i| i.delete(key.as_u16(), index))
    }

    fn wipe(&mut self) {
        self.0.with(|i| i.wipe());
    }

    fn change_count(&self) -> u32 {
        self.0.with(|i| i.change_count())
    }
}
