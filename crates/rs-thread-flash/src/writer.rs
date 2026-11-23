//! The flash side: bank layout, mount (replay) and flush (append / compact).

use embedded_storage_async::nor_flash::NorFlash;

use crate::image::Shared;

/// Bank header magic.
const MAGIC: [u8; 4] = *b"OTFL";
/// Bytes of the bank header before alignment: magic, sequence, CRC-16.
const HEADER_RAW: usize = 10;
/// Bytes of an entry header: kind, count, key, payload length, CRC-16.
const ENTRY_HEADER: usize = 8;
/// Entry kind: the values of one key.
const KIND_PUT: u8 = 0xA5;

/// Errors of the flash writer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum FlashError<E> {
    /// The flash driver failed.
    Flash(E),
    /// The settings (or one key) do not fit a bank, or the entry buffer is
    /// too small for a key. The data stays in RAM.
    NoSpace,
    /// The flash region does not fit the device or is not erase-aligned.
    BadRegion,
    /// The log holds more data than the RAM image has room for.
    ImageTooSmall,
}

/// CRC-16/CCITT-FALSE.
fn crc16(parts: &[&[u8]]) -> u16 {
    let mut crc = 0xFFFFu16;
    for part in parts {
        for &b in *part {
            crc ^= u16::from(b) << 8;
            for _ in 0..8 {
                crc = if crc & 0x8000 != 0 {
                    (crc << 1) ^ 0x1021
                } else {
                    crc << 1
                };
            }
        }
    }
    crc
}

const fn align_up(v: usize, a: usize) -> usize {
    v.div_ceil(a) * a
}

/// Persists a [`Shared`] image in a flash region.
///
/// # Flash layout
///
/// The region is two banks of `pages` erase pages each. A bank is a header
/// followed by an append-only log:
///
/// ```text
/// header = "OTFL"  seq:u32le  crc16:u16le  (padded with 0xFF to the write size)
/// entry  = 0xA5  count:u8  key:u16le  plen:u16le  crc16:u16le  payload  (padded)
/// payload = (len:u16le  value)*count
/// ```
///
/// An entry holds all values of one key and replaces the earlier entries of
/// that key (`count` 0 deletes the key). The CRC covers the entry header and
/// payload, so an entry is applied completely or not at all. The header is
/// valid when its CRC matches; of two valid banks the one with the higher
/// sequence number (wrapping) is current.
///
/// # Power-fail safety
///
/// - Appending writes one entry with a single `write`. A cut leaves a torn
///   entry that fails the CRC; mount stops there, everything before is
///   intact, and the torn tail makes the next flush compact.
/// - A full bank is compacted into the other bank: erase it, write one entry
///   per key, then write the header last. Until the header is there the old
///   bank is current, afterwards the new one. A cut at any point leaves
///   either the complete old or the complete new state.
/// - Erased flash reads `0xFF`; entry kind `0xFF` marks the end of the log.
///   Mount also checks that the rest of the bank is blank, because a cut in
///   the first word of an entry can leave it reading `0xFF`-ish.
///
/// # Wear
///
/// A bank is erased once per compaction (and once at format time); the
/// banks alternate. With `pages` pages per bank and `n` bytes per update, an
/// erase happens about every `bank_size / n` updates.
#[derive(Debug)]
pub struct FlashWriter<F: NorFlash, const BUF: usize> {
    flash: F,
    start: u32,
    bank_size: u32,
    header_size: u32,
    active: u8,
    seq: u32,
    /// Offset in the active bank where the next entry goes.
    tail: u32,
    /// The active bank has a torn or dirty tail: compact before appending.
    must_compact: bool,
    buf: [u8; BUF],
}

impl<F: NorFlash, const BUF: usize> FlashWriter<F, BUF> {
    /// Largest payload of one entry; the rest of the buffer is padding room.
    const MAX_PAYLOAD: usize = BUF.saturating_sub(ENTRY_HEADER + 16);

    fn bank_addr(&self, bank: u8) -> u32 {
        self.start + u32::from(bank) * self.bank_size
    }

    /// Open the region at flash offset `start` (two banks of `pages` erase
    /// pages each), load its content into `shared` and format it if it holds
    /// no valid bank. `BUF` must hold the header plus the largest key (all
    /// its values, with 2 length bytes each).
    ///
    /// Call this before the node starts: it overwrites the image.
    pub async fn mount<const CAP: usize, const KEYS: usize>(
        flash: F,
        start: u32,
        pages: u32,
        shared: &Shared<CAP, KEYS>,
    ) -> Result<Self, FlashError<F::Error>> {
        let erase = F::ERASE_SIZE as u32;
        let bank_size = pages * erase;
        if pages == 0
            || start % erase != 0
            || (start as usize + 2 * bank_size as usize) > flash.capacity()
            || F::READ_SIZE != 1
            || F::WRITE_SIZE > 16
            || BUF < ENTRY_HEADER + 16 + 2
        {
            return Err(FlashError::BadRegion);
        }
        let mut w = Self {
            flash,
            start,
            bank_size,
            header_size: align_up(HEADER_RAW, F::WRITE_SIZE) as u32,
            active: 0,
            seq: 0,
            tail: 0,
            must_compact: false,
            buf: [0; BUF],
        };
        let s0 = w.read_header(0).await?;
        let s1 = w.read_header(1).await?;
        let active = match (s0, s1) {
            (Some(a), Some(b)) => {
                if (b.wrapping_sub(a) as i32) > 0 {
                    Some((1, b))
                } else {
                    Some((0, a))
                }
            }
            (Some(a), None) => Some((0, a)),
            (None, Some(b)) => Some((1, b)),
            (None, None) => None,
        };
        shared.with(|i| *i = crate::Image::new());
        match active {
            Some((bank, seq)) => {
                w.active = bank;
                w.seq = seq;
                w.replay(shared).await?;
            }
            None => w.format(0, 1).await?,
        }
        shared.with(|i| i.clear_all_dirty());
        Ok(w)
    }

    async fn read_header(&mut self, bank: u8) -> Result<Option<u32>, FlashError<F::Error>> {
        let mut h = [0u8; HEADER_RAW];
        self.flash
            .read(self.bank_addr(bank), &mut h)
            .await
            .map_err(FlashError::Flash)?;
        let crc = u16::from_le_bytes([h[8], h[9]]);
        if h[..4] == MAGIC && crc == crc16(&[&h[..8]]) {
            Ok(Some(u32::from_le_bytes([h[4], h[5], h[6], h[7]])))
        } else {
            Ok(None)
        }
    }

    async fn write_header(&mut self, bank: u8, seq: u32) -> Result<(), FlashError<F::Error>> {
        let mut h = [0xFFu8; 16];
        h[..4].copy_from_slice(&MAGIC);
        h[4..8].copy_from_slice(&seq.to_le_bytes());
        let crc = crc16(&[&h[..8]]);
        h[8..10].copy_from_slice(&crc.to_le_bytes());
        let n = self.header_size as usize;
        self.flash
            .write(self.bank_addr(bank), &h[..n])
            .await
            .map_err(FlashError::Flash)
    }

    async fn erase_bank(&mut self, bank: u8) -> Result<(), FlashError<F::Error>> {
        let a = self.bank_addr(bank);
        self.flash
            .erase(a, a + self.bank_size)
            .await
            .map_err(FlashError::Flash)
    }

    /// Erase `bank` and give it the header `seq`; it becomes the active bank.
    async fn format(&mut self, bank: u8, seq: u32) -> Result<(), FlashError<F::Error>> {
        self.erase_bank(bank).await?;
        self.write_header(bank, seq).await?;
        self.active = bank;
        self.seq = seq;
        self.tail = self.header_size;
        self.must_compact = false;
        Ok(())
    }

    /// Apply the log of the active bank to the image and find the tail.
    async fn replay<const CAP: usize, const KEYS: usize>(
        &mut self,
        shared: &Shared<CAP, KEYS>,
    ) -> Result<(), FlashError<F::Error>> {
        let base = self.bank_addr(self.active);
        let mut off = self.header_size;
        while off as usize + ENTRY_HEADER <= self.bank_size as usize {
            let mut h = [0u8; ENTRY_HEADER];
            self.flash
                .read(base + off, &mut h)
                .await
                .map_err(FlashError::Flash)?;
            if h[0] == 0xFF {
                break;
            }
            let count = h[1];
            let key = u16::from_le_bytes([h[2], h[3]]);
            let plen = usize::from(u16::from_le_bytes([h[4], h[5]]));
            let crc = u16::from_le_bytes([h[6], h[7]]);
            let total = align_up(ENTRY_HEADER + plen, F::WRITE_SIZE);
            if h[0] != KIND_PUT
                || plen > Self::MAX_PAYLOAD
                || off as usize + total > self.bank_size as usize
            {
                break;
            }
            let payload = &mut self.buf[..plen];
            self.flash
                .read(base + off + ENTRY_HEADER as u32, payload)
                .await
                .map_err(FlashError::Flash)?;
            if crc != crc16(&[&h[..6], payload]) {
                break;
            }
            let payload = &self.buf[..plen];
            match shared.with(|i| i.apply_put(key, count, payload)) {
                Ok(()) => {}
                Err(rs_thread_core::Error::NoBufs) => return Err(FlashError::ImageTooSmall),
                // CRC-valid but malformed: treat as the end of the log.
                Err(_) => break,
            }
            off += total as u32;
        }
        self.tail = off;
        // Everything after the last good entry must be blank to append there.
        let mut chunk = [0u8; 32];
        let mut pos = off;
        while pos < self.bank_size {
            let n = (self.bank_size - pos).min(chunk.len() as u32) as usize;
            self.flash
                .read(base + pos, &mut chunk[..n])
                .await
                .map_err(FlashError::Flash)?;
            if chunk[..n].iter().any(|&b| b != 0xFF) {
                self.must_compact = true;
                break;
            }
            pos += n as u32;
        }
        Ok(())
    }

    /// Write the entry in `self.buf[..ENTRY_HEADER + plen]` (header filled
    /// here) at `off` of `bank`. Returns the aligned entry size.
    async fn write_entry(
        &mut self,
        bank: u8,
        off: u32,
        key: u16,
        count: u8,
        plen: usize,
    ) -> Result<u32, FlashError<F::Error>> {
        let total = align_up(ENTRY_HEADER + plen, F::WRITE_SIZE);
        let b = &mut self.buf;
        b[0] = KIND_PUT;
        b[1] = count;
        b[2..4].copy_from_slice(&key.to_le_bytes());
        b[4..6].copy_from_slice(&(plen as u16).to_le_bytes());
        let crc = crc16(&[&b[..6], &b[ENTRY_HEADER..ENTRY_HEADER + plen]]);
        b[6..8].copy_from_slice(&crc.to_le_bytes());
        b[ENTRY_HEADER + plen..total].fill(0xFF);
        let addr = self.bank_addr(bank) + off;
        self.flash
            .write(addr, &self.buf[..total])
            .await
            .map_err(FlashError::Flash)?;
        Ok(total as u32)
    }

    /// Rewrite the image into the other bank and switch to it.
    async fn compact<const CAP: usize, const KEYS: usize>(
        &mut self,
        shared: &Shared<CAP, KEYS>,
    ) -> Result<(), FlashError<F::Error>> {
        let new = 1 - self.active;
        let wiped = shared.with(|i| {
            i.take_dirty_all();
            i.take_wiped()
        });
        self.erase_bank(new).await?;
        let mut off = self.header_size;
        let mut last = None;
        loop {
            // Encode one key and mark it clean in the same critical section;
            // later changes mark it dirty again and are appended afterwards.
            let enc = shared.with(|i| {
                let Some(key) = i.next_key(last) else {
                    return Ok(None);
                };
                let r = i.encode_key(
                    key,
                    &mut self.buf[ENTRY_HEADER..ENTRY_HEADER + Self::MAX_PAYLOAD],
                );
                if r.is_ok() {
                    i.clear_dirty(key);
                }
                r.map(|(count, n)| Some((key, count, n)))
            });
            let (key, count, plen) = match enc {
                Ok(Some(e)) => e,
                Ok(None) => break,
                Err(_) => {
                    shared.with(|i| i.set_dirty_all());
                    return Err(FlashError::NoSpace);
                }
            };
            last = Some(key);
            let total = align_up(ENTRY_HEADER + plen, F::WRITE_SIZE) as u32;
            if off + total > self.bank_size {
                shared.with(|i| i.set_dirty_all());
                return Err(FlashError::NoSpace);
            }
            off += self.write_entry(new, off, key, count, plen).await?;
        }
        let seq = self.seq.wrapping_add(1);
        self.write_header(new, seq).await?;
        let old = self.active;
        self.active = new;
        self.seq = seq;
        self.tail = off;
        self.must_compact = false;
        if wiped {
            // Factory reset: do not leave the old values in flash.
            self.erase_bank(old).await?;
        }
        Ok(())
    }

    /// Write all pending changes of the image to flash. Call it whenever
    /// [`Shared::is_dirty`] or the change counter says there is something;
    /// it returns when flash is up to date, or on the first error (the
    /// failed key stays dirty, so a later call retries).
    pub async fn flush<const CAP: usize, const KEYS: usize>(
        &mut self,
        shared: &Shared<CAP, KEYS>,
    ) -> Result<(), FlashError<F::Error>> {
        loop {
            if self.must_compact || shared.with(|i| i.take_dirty_all()) {
                // `take_dirty_all` was consumed above; compact rewrites all.
                if let Err(e) = self.compact(shared).await {
                    shared.with(|i| i.set_dirty_all());
                    return Err(e);
                }
                continue;
            }
            let taken = shared.with(|i| {
                i.take_dirty(&mut self.buf[ENTRY_HEADER..ENTRY_HEADER + Self::MAX_PAYLOAD])
            });
            let (key, count, plen) = match taken {
                Ok(Some(e)) => e,
                Ok(None) => return Ok(()),
                Err(_) => return Err(FlashError::NoSpace),
            };
            let total = align_up(ENTRY_HEADER + plen, F::WRITE_SIZE) as u32;
            if self.tail + total > self.bank_size {
                // Bank full: the compaction writes the current value of
                // every key, this one included.
                shared.with(|i| i.redirty(key));
                self.must_compact = true;
                continue;
            }
            match self
                .write_entry(self.active, self.tail, key, count, plen)
                .await
            {
                Ok(n) => self.tail += n,
                Err(e) => {
                    // A failed write may have left a torn entry.
                    self.must_compact = true;
                    shared.with(|i| i.redirty(key));
                    return Err(e);
                }
            }
        }
    }

    /// Give the flash back.
    pub fn into_inner(self) -> F {
        self.flash
    }
}
