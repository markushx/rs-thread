//! Persistence of the Thread settings in an rs-matter `KvBlobStore`.
//!
//! The node keeps its settings (datasets, network info, parent / child info,
//! SLAAC secret, SRP client key and server, DAD counter) in the
//! [`SettingsStore`] of its instance, which is RAM. [`ThreadPersist`] copies
//! the persisted subset to one blob of the rs-matter key-value store and
//! back, in the format of `rs-matter-embassy`'s `OtPersist`:
//!
//! ```text
//! blob   = record*
//! record = key:u16le  len:u16le  value:[u8; len]
//! ```
//!
//! with the OpenThread settings key of [`SettingsKey`], values of a
//! multi-value key (child info) as consecutive records in order. The blob
//! lives under [`THREAD_SETTINGS_KEY`] (the first vendor key of rs-matter).
//!
//! - [`ThreadPersist::load`] writes the blob into the settings store. Call
//!   it before `thread_start`: the instance reads the datasets, the network
//!   info and the SLAAC secret when it starts.
//!   [`ThreadRunner`](crate::driver::ThreadRunner) does it before it runs
//!   the node.
//! - [`ThreadPersist::run`] watches the node and writes the blob again,
//!   debounced, when the serialised settings differ from what was written
//!   last. Writes are triggered by the settings change counter of the
//!   instance ([`SettingsStore::change_count`]; with a store that does not
//!   count, by the next state event) and compared by a 64 bit hash of the
//!   serialisation, so an unchanged value costs no store write.
//!
//! # Write rate
//!
//! The instance decides what it writes and when; the persistence adds
//! only the debounce on top. In particular the MLE and MAC frame counters
//! are in the network info, which the instance writes when the counter
//! passes its store-ahead threshold (OpenThread's
//! `kStoreFrameCounterAhead`) and not on every frame; the persisted counter
//! is thus ahead of the live one and a restart never reuses a counter value.
//! At most one blob write happens per debounce interval
//! ([`DEFAULT_DEBOUNCE_SECS`]).
//!
//! Flash wear is the problem of the `KvBlobStore` behind it. The blob is
//! rewritten as a whole.

use embassy_sync::blocking_mutex::raw::RawMutex;
use opentrust_core::settings::SettingsKey;
use opentrust_embassy::OpenTrust;
use opentrust_instance::InstanceCrypto;
use opentrust_platform::{Clock, SettingsStore};
use rand_core::{CryptoRng, Rng};
use rs_matter::dm::persist::{KvBlobStoreAccess, VENDOR_KEYS_START};
use rs_matter::error::{Error, ErrorCode};
use rs_matter::utils::timers::{Duration, Timer};

use crate::error::map_err;
use crate::fmt::log_warn;

/// The rs-matter `KvBlobStore` key of the settings blob.
pub const THREAD_SETTINGS_KEY: u16 = VENDOR_KEYS_START;

/// The default time between a change of the settings and the write.
pub const DEFAULT_DEBOUNCE_SECS: u64 = 5;

/// The default size of the serialisation buffer.
pub const DEFAULT_BUF: usize = 1024;

/// The settings that are persisted, in blob order. Not persisted: Border
/// Router, SRP server and TCAT settings (a Matter node has none of them).
pub const PERSISTED: [SettingsKey; 9] = [
    SettingsKey::ActiveDataset,
    SettingsKey::PendingDataset,
    SettingsKey::NetworkInfo,
    SettingsKey::ParentInfo,
    SettingsKey::ChildInfo,
    SettingsKey::SlaacIidSecretKey,
    SettingsKey::DadInfo,
    SettingsKey::SrpEcdsaKey,
    SettingsKey::SrpClientInfo,
];

const HEADER: usize = 4;

/// Serialise the persisted subset of `s` into `out`. Returns the length, or
/// [`ErrorCode::ResourceExhausted`] if `out` is too small.
pub fn serialize<S: SettingsStore>(s: &S, out: &mut [u8]) -> Result<usize, Error> {
    let mut pos = 0;
    for key in PERSISTED {
        let mut index = 0;
        loop {
            let Some(room) = out.get_mut(pos + HEADER..) else {
                return Err(ErrorCode::ResourceExhausted.into());
            };
            match s.get(key, index, room) {
                Ok(len) => {
                    if len > room.len() {
                        return Err(ErrorCode::ResourceExhausted.into());
                    }
                    // `len` fits in a u16: the stores take u16-sized values.
                    out[pos..pos + 2].copy_from_slice(&key.as_u16().to_le_bytes());
                    out[pos + 2..pos + HEADER].copy_from_slice(&(len as u16).to_le_bytes());
                    pos += HEADER + len;
                    index += 1;
                }
                Err(opentrust_core::Error::NotFound) => break,
                Err(e) => return Err(map_err(e)),
            }
        }
    }
    Ok(pos)
}

/// Write the records of `blob` into `s`, replacing the persisted keys.
/// Records of other keys are skipped. A truncated record ends the blob (the
/// records before it are kept). Returns the number of records written.
pub fn deserialize<S: SettingsStore>(s: &mut S, blob: &[u8]) -> Result<usize, Error> {
    for key in PERSISTED {
        let _ = s.delete(key, None);
    }
    let mut pos = 0;
    let mut n = 0;
    while let Some(h) = blob.get(pos..pos + HEADER) {
        let key = u16::from_le_bytes([h[0], h[1]]);
        let len = usize::from(u16::from_le_bytes([h[2], h[3]]));
        let Some(value) = blob.get(pos + HEADER..pos + HEADER + len) else {
            log_warn!("thread settings blob truncated");
            break;
        };
        pos += HEADER + len;
        let Some(key) = SettingsKey::from_u16(key).filter(|k| PERSISTED.contains(k)) else {
            continue;
        };
        s.add(key, value).map_err(map_err)?;
        n += 1;
    }
    Ok(n)
}

fn fnv1a(data: &[u8]) -> u64 {
    let mut h = 0xcbf2_9ce4_8422_2325u64;
    for b in data {
        h ^= u64::from(*b);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

/// Loads and stores the Thread settings of a node in an rs-matter blob
/// store.
///
/// `N` is the size of the serialisation buffer: the persisted settings must
/// fit ([`DEFAULT_BUF`] is enough for a node with a few dozen children).
pub struct ThreadPersist<'a, M, K, S, C, R, A, const N: usize = DEFAULT_BUF>
where
    M: RawMutex,
    C: InstanceCrypto,
{
    ot: OpenTrust<'a, M, K, S, C, R>,
    kv: A,
    key: u16,
    debounce: Duration,
    buf: [u8; N],
    /// Hash of the blob that was last loaded or written.
    last: u64,
    loaded: bool,
    writes: u32,
}

impl<M: RawMutex, K, S, C: InstanceCrypto, R, A, const N: usize> core::fmt::Debug
    for ThreadPersist<'_, M, K, S, C, R, A, N>
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ThreadPersist")
            .field("writes", &self.writes)
            .finish_non_exhaustive()
    }
}

impl<'a, M, K, S, C, R, A, const N: usize> ThreadPersist<'a, M, K, S, C, R, A, N>
where
    M: RawMutex,
    K: Clock,
    S: SettingsStore,
    C: InstanceCrypto,
    R: Rng + CryptoRng,
    A: KvBlobStoreAccess,
{
    /// Persistence for the node behind `ot` in the store `kv`, with the
    /// default blob key and debounce and a buffer of `N` bytes.
    pub const fn new_sized(ot: OpenTrust<'a, M, K, S, C, R>, kv: A) -> Self {
        Self {
            ot,
            kv,
            key: THREAD_SETTINGS_KEY,
            debounce: Duration::from_secs(DEFAULT_DEBOUNCE_SECS),
            buf: [0; N],
            last: 0,
            loaded: false,
            writes: 0,
        }
    }

    /// Use another blob key (default [`THREAD_SETTINGS_KEY`]).
    pub const fn with_key(mut self, key: u16) -> Self {
        self.key = key;
        self
    }

    /// Change the debounce time (default [`DEFAULT_DEBOUNCE_SECS`]).
    pub const fn with_debounce(mut self, debounce: Duration) -> Self {
        self.debounce = debounce;
        self
    }

    /// The number of blob writes so far.
    pub const fn writes(&self) -> u32 {
        self.writes
    }

    /// Whether [`load`](Self::load) has run.
    pub const fn loaded(&self) -> bool {
        self.loaded
    }

    /// Load the blob into the settings of the node (nothing if the store
    /// has none). Returns the number of settings values restored. Call it
    /// before the node is started; it replaces the persisted settings of
    /// the instance, so it is done once ([`loaded`](Self::loaded)) and not
    /// when the runner restarts on live resources.
    pub fn load(&mut self) -> Result<usize, Error> {
        let key = self.key;
        let ot = self.ot;
        let n = self.kv.access(|kv, buf| match kv.load(key, buf)? {
            Some(blob) => ot.with(|i, _| deserialize(i.settings_mut(), blob)),
            None => Ok(0),
        })?;
        self.loaded = true;
        // The canonical serialisation of what is in the store now.
        self.last = self.hash_settings()?;
        Ok(n)
    }

    fn hash_settings(&mut self) -> Result<u64, Error> {
        let buf = &mut self.buf;
        let len = self.ot.with(|i, _| serialize(i.settings(), buf))?;
        Ok(fnv1a(&self.buf[..len]))
    }

    /// Write the blob now if the settings changed since the last write.
    /// Returns whether it wrote. An empty serialisation removes the blob
    /// (after a factory reset).
    pub fn flush(&mut self) -> Result<bool, Error> {
        let buf = &mut self.buf;
        let len = self.ot.with(|i, _| serialize(i.settings(), buf))?;
        let h = fnv1a(&self.buf[..len]);
        if h == self.last {
            return Ok(false);
        }
        let key = self.key;
        let data = &self.buf[..len];
        self.kv.access(|kv, scratch| {
            if data.is_empty() {
                kv.remove(key, scratch)
            } else {
                kv.store(key, data, scratch)
            }
        })?;
        self.last = h;
        self.writes = self.writes.wrapping_add(1);
        Ok(true)
    }

    /// Persist forever: after a change, wait the debounce time, then
    /// [`flush`](Self::flush). Drop-safe: a change that is waiting for its
    /// debounce when the future is dropped is written by the next `run` or
    /// `flush`.
    pub async fn run(&mut self) -> core::convert::Infallible {
        loop {
            let g = self.ot.generation();
            if let Err(e) = self.flush_if_due().await {
                log_warn!("thread settings store failed: {:?}", e);
                // Retry after one debounce period.
                Timer::after(self.debounce).await;
                continue;
            }
            self.ot.wait_changed_after(g).await;
        }
    }

    async fn flush_if_due(&mut self) -> Result<(), Error> {
        if self.hash_settings()? == self.last {
            return Ok(());
        }
        Timer::after(self.debounce).await;
        self.flush().map(|_| ())
    }
}

impl<'a, M, K, S, C, R, A> ThreadPersist<'a, M, K, S, C, R, A, DEFAULT_BUF>
where
    M: RawMutex,
    K: Clock,
    S: SettingsStore,
    C: InstanceCrypto,
    R: Rng + CryptoRng,
    A: KvBlobStoreAccess,
{
    /// Persistence for the node behind `ot` in the store `kv`, with the
    /// default blob key, debounce and a [`DEFAULT_BUF`] buffer.
    pub const fn new(ot: OpenTrust<'a, M, K, S, C, R>, kv: A) -> Self {
        Self::new_sized(ot, kv)
    }
}
