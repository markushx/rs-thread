//! Thread key management for MAC frame security (OpenThread `KeyManager`,
//! `Mac::ProcessTransmitSecurity` / `ProcessReceiveSecurity` /
//! `ProcessEnhAckSecurity`, `SubMac` frame counter handling).

use opentrust_core::crypto::kdf::{ThreadKeys, key_index, thread_keys};
use opentrust_core::crypto::nonce::{KEY_ID_MODE2_EXT_ADDRESS, KEY_ID_MODE2_KEY};
use opentrust_core::crypto::{CryptoBackend, SecurityLevel};
use opentrust_core::time::{Duration, Instant};
use opentrust_core::types::{ExtAddress, MacKey, MleKey, NetworkKey};
use opentrust_core::{Error, Result};
use opentrust_platform::radio::{AckSecurity, MacKeys};

use super::{open_psdu, seal_psdu, write_aux_header};
use crate::frame::{Frame, FrameType, FrameVersion, KeyIdMode, KeyIdentifier};
use crate::frame_security::{FrameSecurity, RxSecurityInfo};

/// Default `thrKeyRotation` in hours (Thread §7.1.2, Table 7-2).
pub const DEFAULT_KEY_ROTATION_HOURS: u16 = 672;
/// Minimum `thrKeyRotation` in hours (Thread §7.1.2: "SHALL be 1 hour").
pub const MIN_KEY_ROTATION_HOURS: u16 = 1;
/// `thrKeySwitchGuardTime = floor(0.93 * thrKeyRotation)` (Thread §7.1.7).
pub const KEY_SWITCH_GUARD_PERCENT: u32 = 93;
/// How far ahead of the used outgoing frame counter the persisted value is
/// kept (OpenThread `OPENTHREAD_CONFIG_STORE_FRAME_COUNTER_AHEAD`).
pub const DEFAULT_STORE_FRAME_COUNTER_AHEAD: u32 = 1000;
/// Key Source of MAC key ID mode 2 frames (Thread §7.2.3.3.2), on-air order.
pub const KEY_ID_MODE2_SOURCE: [u8; 4] = [0xff; 4];
/// Key Index of MAC key ID mode 2 frames (Thread §7.2.3.3.1).
pub const KEY_ID_MODE2_INDEX: u8 = 0xff;

const HOUR: Duration = Duration::from_secs(3600);

/// The key identifier of key ID mode 2 frames.
const MODE2_KEY_ID: KeyIdentifier = KeyIdentifier::Source4 {
    source: KEY_ID_MODE2_SOURCE,
    index: KEY_ID_MODE2_INDEX,
};

/// How a key sequence update is applied (OpenThread
/// `KeyManager::KeySeqUpdateFlags`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct KeySeqUpdate {
    /// Ignore the update while the key switch guard timer runs.
    pub apply_switch_guard: bool,
    /// Restart the key switch guard timer if the key sequence changes.
    pub reset_guard_timer: bool,
}

impl KeySeqUpdate {
    /// Unconditional update, guard timer unchanged (restoring from
    /// settings; MLE "authoritative" messages with a key sequence jump > 1).
    pub const FORCE: Self = Self {
        apply_switch_guard: false,
        reset_guard_timer: false,
    };
    /// Unconditional update that restarts the guard timer (key rotation;
    /// MLE "authoritative" messages with the next key sequence).
    pub const FORCE_RESET_GUARD: Self = Self {
        apply_switch_guard: false,
        reset_guard_timer: true,
    };
    /// Switch to a key sequence seen on reception from a neighbor, unless the
    /// guard timer runs (Thread §7.1.7 case 2; MAC frames and MLE "peer"
    /// messages).
    pub const GUARDED: Self = Self {
        apply_switch_guard: true,
        reset_guard_timer: true,
    };
}

/// Which security levels incoming frames (and enhanced ACKs) may use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum RxLevelPolicy {
    /// Only `ENC-MIC-32`, the Thread level (Thread §7.2.3.1; OpenThread).
    #[default]
    EncMic32Only,
    /// Any level with a MIC (1–3, 5–7). Level 4 (`ENC`, no integrity) is
    /// never accepted.
    Authenticated,
}

impl RxLevelPolicy {
    fn allows(self, level: SecurityLevel) -> bool {
        match self {
            Self::EncMic32Only => level == SecurityLevel::EncMic32,
            Self::Authenticated => level.mic_len() > 0,
        }
    }
}

/// Thread key manager and [`FrameSecurity`] implementation.
///
/// Holds the network key, `thrKeySequenceCounter` and the derived keys for
/// the previous, current and next key sequence (Thread §7.1.5; old keys are
/// zeroized when replaced), the outgoing MAC frame counter, a separate
/// counter for key ID mode 2 frames, key rotation and the key switch guard.
///
/// All time-dependent operations take `now`; the key rotation deadline is
/// [`next_deadline`](Self::next_deadline), to be serviced with
/// [`poll`](Self::poll).
///
/// Operations that change the keys or the key sequence return `true` when
/// they did; the caller then pushes [`mac_keys`](Self::mac_keys) and
/// [`frame_counter`](Self::frame_counter) to the radio, persists the key
/// sequence (see [`needs_store`](Self::needs_store)) and, after a network key
/// change, resets all neighbors' [`LinkFrameCounters`](super::LinkFrameCounters).
#[derive(Debug)]
pub struct KeyManager<B: CryptoBackend> {
    backend: B,
    network_key: NetworkKey,
    key_sequence: u32,
    /// Keys for `key_sequence - 1`, `key_sequence`, `key_sequence + 1`
    /// (wrapping, as OpenThread's sub-MAC keys).
    keys: [ThreadKeys; 3],
    /// Next outgoing frame counter; `u32::MAX` means exhausted (802.15.4
    /// forbids using `0xffffffff`).
    frame_counter: u32,
    /// Counter of key ID mode 2 frames (OpenThread `mKeyIdMode2FrameCounter`).
    mode2_frame_counter: u32,
    /// Frame counter value last persisted.
    stored_frame_counter: u32,
    /// The key sequence (or network key) changed since the last store.
    store_pending: bool,
    store_ahead: u32,
    rotation_hours: u16,
    guard_hours: u16,
    /// Start of the current key rotation period; `None` while stopped.
    rotation_start: Option<Instant>,
    /// End of the key switch guard period; `None` = timer is 0.
    guard_until: Option<Instant>,
    rx_level_policy: RxLevelPolicy,
}

impl<B: CryptoBackend> KeyManager<B> {
    /// Create a key manager for `network_key` with key sequence 0, frame
    /// counter 0, default rotation time, stopped key rotation.
    pub fn new(backend: B, network_key: NetworkKey) -> Self {
        let keys = derive_three(&backend, &network_key, 0);
        Self {
            backend,
            network_key,
            key_sequence: 0,
            keys,
            frame_counter: 0,
            mode2_frame_counter: 0,
            stored_frame_counter: 0,
            store_pending: true,
            store_ahead: DEFAULT_STORE_FRAME_COUNTER_AHEAD,
            rotation_hours: DEFAULT_KEY_ROTATION_HOURS,
            guard_hours: guard_hours(DEFAULT_KEY_ROTATION_HOURS),
            rotation_start: None,
            guard_until: None,
            rx_level_policy: RxLevelPolicy::EncMic32Only,
        }
    }

    /// The crypto backend.
    pub const fn backend(&self) -> &B {
        &self.backend
    }

    /// The network key.
    pub const fn network_key(&self) -> &NetworkKey {
        &self.network_key
    }

    /// Set the network key. If it differs from the current one, the key
    /// sequence and the outgoing frame counter are reset to 0 (Thread
    /// §7.1.3, §7.1.8) and `true` is returned: the caller must also reset all
    /// neighbors' incoming frame counters and key sequences (OpenThread
    /// `KeyManager::ResetFrameCounters`).
    pub fn set_network_key(&mut self, network_key: NetworkKey) -> bool {
        if network_key == self.network_key {
            return false;
        }
        self.network_key = network_key;
        self.key_sequence = 0;
        self.frame_counter = 0;
        self.keys = derive_three(&self.backend, &self.network_key, 0);
        self.store_pending = true;
        true
    }

    // ------------------------------------------------------------ key sequence

    /// `thrKeySequenceCounter`.
    pub const fn key_sequence(&self) -> u32 {
        self.key_sequence
    }

    /// Key index of outgoing key ID mode 1 frames (Thread §7.1.5).
    pub const fn key_index(&self) -> u8 {
        key_index(self.key_sequence)
    }

    /// Set the key sequence (OpenThread `KeyManager::SetCurrentKeySequence`).
    ///
    /// Returns `Ok(true)` if the key sequence changed: the keys are switched,
    /// the outgoing frame counter is reset to 0 (Thread §7.1.8), the key
    /// rotation period restarts and, with `reset_guard_timer`, the guard
    /// timer is set to `thrKeySwitchGuardTime`. `Ok(false)` if `key_sequence`
    /// is the current one or the update is blocked by the running guard
    /// timer (`apply_switch_guard`).
    ///
    /// [`Error::InvalidArgs`] if `key_sequence` is lower than the current
    /// one: `thrKeySequenceCounter` never decreases except through a network
    /// key change (Thread §7.1.3) or [`restore`](Self::restore).
    pub fn set_key_sequence(
        &mut self,
        key_sequence: u32,
        update: KeySeqUpdate,
        now: Instant,
    ) -> Result<bool> {
        if key_sequence == self.key_sequence {
            return Ok(false);
        }
        if key_sequence < self.key_sequence {
            return Err(Error::InvalidArgs);
        }
        if update.apply_switch_guard && self.guard_active(now) {
            return Ok(false);
        }
        self.switch_to(key_sequence);
        if self.rotation_start.is_some() {
            self.rotation_start = Some(now);
        }
        if update.reset_guard_timer {
            self.guard_until = (self.guard_hours > 0)
                .then(|| now.saturating_add(HOUR.saturating_mul(self.guard_hours.into())));
        }
        Ok(true)
    }

    /// A frame from a valid neighbor secured with `key_sequence` passed
    /// security and replay checks: switch to it if it is newer and the key
    /// switch guard allows (Thread §7.1.7 case 2, §7.2.1.2.1; OpenThread
    /// `Mac::ProcessReceiveSecurity`). Returns `true` if the keys changed.
    pub fn on_rx_key_sequence(&mut self, key_sequence: u32, now: Instant) -> bool {
        key_sequence > self.key_sequence
            && self
                .set_key_sequence(key_sequence, KeySeqUpdate::GUARDED, now)
                .unwrap_or(false)
    }

    fn switch_to(&mut self, key_sequence: u32) {
        // Frame counter first (see OpenThread `SetCurrentKeySequence`: a
        // radio securing enhanced ACKs must never pair the new key with the
        // old counter).
        self.frame_counter = 0;
        if key_sequence == self.key_sequence.wrapping_add(1) {
            // prev <- cur <- next; the old prev lands in slot 2 and is
            // overwritten (and zeroized on drop).
            self.keys.rotate_left(1);
            self.keys[2] = thread_keys(
                &self.backend,
                &self.network_key,
                key_sequence.wrapping_add(1),
            );
        } else {
            self.keys = derive_three(&self.backend, &self.network_key, key_sequence);
        }
        self.key_sequence = key_sequence;
        self.store_pending = true;
    }

    /// Restore key sequence and outgoing MAC frame counter from persistent
    /// settings (`NetworkInfo`), as OpenThread `Mle::Restore`: the key
    /// sequence is set unconditionally (guard timer unchanged) and the frame
    /// counter to the stored value, which was persisted ahead of use. Call
    /// once at start-up, before any frame is secured.
    pub fn restore(&mut self, key_sequence: u32, mac_frame_counter: u32) {
        if key_sequence != self.key_sequence {
            self.switch_to(key_sequence);
        }
        self.frame_counter = mac_frame_counter;
        self.stored_frame_counter = mac_frame_counter;
        self.store_pending = false;
    }

    // ------------------------------------------------------------ rotation / guard

    /// Start key rotation (OpenThread `KeyManager::Start`): the rotation
    /// period starts at `now` and the guard timer is cleared.
    pub fn start(&mut self, now: Instant) {
        self.guard_until = None;
        self.rotation_start = Some(now);
    }

    /// Stop key rotation.
    pub fn stop(&mut self) {
        self.rotation_start = None;
    }

    /// `thrKeyRotation` in hours.
    pub const fn key_rotation_hours(&self) -> u16 {
        self.rotation_hours
    }

    /// `thrKeySwitchGuardTime` in hours.
    pub const fn key_switch_guard_hours(&self) -> u16 {
        self.guard_hours
    }

    /// Set `thrKeyRotation` from the Security Policy (clamped to at least
    /// [`MIN_KEY_ROTATION_HOURS`]); `thrKeySwitchGuardTime` becomes
    /// `floor(0.93 * thrKeyRotation)` (Thread §7.1.7). A running guard timer
    /// is not changed. Call [`poll`](Self::poll) afterwards: a shorter
    /// rotation time may already have elapsed.
    pub fn set_key_rotation_hours(&mut self, hours: u16) {
        let hours = hours.max(MIN_KEY_ROTATION_HOURS);
        if hours != self.rotation_hours {
            self.rotation_hours = hours;
            self.guard_hours = guard_hours(hours);
        }
    }

    /// Set `thrKeySwitchGuardTime` directly (OpenThread
    /// `SetKeySwitchGuardTime`, testing).
    pub fn set_key_switch_guard_hours(&mut self, hours: u16) {
        self.guard_hours = hours;
    }

    /// `true` while the key switch guard timer is not 0.
    pub fn guard_active(&self, now: Instant) -> bool {
        self.guard_until.is_some_and(|t| now < t)
    }

    /// When [`poll`](Self::poll) has work to do (key rotation), if rotation
    /// is running.
    pub fn next_deadline(&self) -> Option<Instant> {
        self.rotation_start
            .map(|t| t.saturating_add(HOUR.saturating_mul(self.rotation_hours.into())))
    }

    /// Rotate the key if `thrKeyRotation` hours passed since the last key
    /// switch (Thread §7.1.7 case 1). Returns `true` if the keys changed.
    pub fn poll(&mut self, now: Instant) -> bool {
        match self.next_deadline() {
            Some(d) if now >= d => match self.key_sequence.checked_add(1) {
                Some(next) => self
                    .set_key_sequence(next, KeySeqUpdate::FORCE_RESET_GUARD, now)
                    .unwrap_or(false),
                None => false,
            },
            _ => false,
        }
    }

    // ------------------------------------------------------------ keys

    /// MAC and MLE keys of the current key sequence.
    pub const fn current_keys(&self) -> &ThreadKeys {
        &self.keys[1]
    }

    /// The current MAC key.
    pub const fn mac_key(&self) -> &MacKey {
        &self.keys[1].mac_key
    }

    /// The current MLE key.
    pub const fn mle_key(&self) -> &MleKey {
        &self.keys[1].mle_key
    }

    /// Cached keys for `key_sequence` if it is the previous, current or next
    /// one (not wrapping around 0 / `u32::MAX`).
    pub fn cached_keys(&self, key_sequence: u32) -> Option<&ThreadKeys> {
        let cur = self.key_sequence;
        if key_sequence == cur {
            Some(&self.keys[1])
        } else if cur.checked_sub(1) == Some(key_sequence) {
            Some(&self.keys[0])
        } else if cur.checked_add(1) == Some(key_sequence) {
            Some(&self.keys[2])
        } else {
            None
        }
    }

    /// Derive the keys of an arbitrary key sequence (OpenThread
    /// `GetTemporaryMleKey`, e.g. for MLE messages with a key sequence
    /// further away).
    pub fn derive_keys(&self, key_sequence: u32) -> ThreadKeys {
        thread_keys(&self.backend, &self.network_key, key_sequence)
    }

    /// Resolve a received key ID mode 1 key index (Thread §7.2.1.2): the key
    /// sequence and MAC key of the current, previous or next key sequence
    /// whose index matches (OpenThread `Mac::ProcessReceiveSecurity`), else
    /// `None` (key index mismatch).
    pub fn lookup_key_index(&self, idx: u8) -> Option<(u32, &MacKey)> {
        let cur = self.key_sequence;
        [Some(cur), cur.checked_sub(1), cur.checked_add(1)]
            .into_iter()
            .flatten()
            .find(|&s| key_index(s) == idx)
            .and_then(|s| Some((s, &self.cached_keys(s)?.mac_key)))
    }

    /// The keys for a radio that secures frames or enhanced ACKs itself
    /// (`Radio::set_mac_keys`): key ID mode 1, the current key index and the
    /// previous/current/next MAC keys (OpenThread `SubMac::SetMacKey`).
    pub fn mac_keys(&self) -> MacKeys {
        MacKeys {
            key_id_mode: KeyIdMode::Index.bits(),
            key_id: self.key_index(),
            prev: self.keys[0].mac_key.0,
            curr: self.keys[1].mac_key.0,
            next: self.keys[2].mac_key.0,
        }
    }

    // ------------------------------------------------------------ frame counter

    /// The next outgoing MAC frame counter (`macFrameCounter`).
    pub const fn frame_counter(&self) -> u32 {
        self.frame_counter
    }

    /// `true` if no outgoing frame counter is left for the current key
    /// sequence (the next one would be `0xffffffff`); key ID mode 1 frames
    /// then fail with [`Error::InvalidState`] until the key sequence changes.
    pub const fn frame_counter_exhausted(&self) -> bool {
        self.frame_counter == u32::MAX
    }

    /// Raise the outgoing frame counter to `frame_counter` if it is larger
    /// (OpenThread `SetAllMacFrameCounters(.., aSetIfLarger = true)`). The
    /// counter never decreases (Thread §7.1.8).
    pub fn advance_frame_counter(&mut self, frame_counter: u32) {
        self.frame_counter = self.frame_counter.max(frame_counter);
    }

    /// A radio used `frame_counter` with key index `key_index` (a frame it
    /// secured itself, or an enhanced ACK): the counter moves past it if the
    /// key index is the current one (OpenThread
    /// `SubMac::SignalFrameCounterUsed`, which tolerates out-of-order calls).
    pub fn frame_counter_used(&mut self, frame_counter: u32, key_index: u8) {
        if key_index == self.key_index() && frame_counter >= self.frame_counter {
            self.frame_counter = frame_counter.saturating_add(1);
        }
    }

    /// [`frame_counter_used`](Self::frame_counter_used) for the security
    /// material a radio reports for a secured enhanced ACK it sent.
    pub fn ack_frame_counter_used(&mut self, ack: &AckSecurity) {
        self.frame_counter_used(ack.frame_counter, ack.key_id);
    }

    fn next_frame_counter(&mut self) -> Result<u32> {
        if self.frame_counter_exhausted() {
            return Err(Error::InvalidState);
        }
        let fc = self.frame_counter;
        self.frame_counter += 1;
        Ok(fc)
    }

    // ------------------------------------------------------------ persistence

    /// Distance between the used and the persisted outgoing frame counter
    /// (default [`DEFAULT_STORE_FRAME_COUNTER_AHEAD`]).
    pub fn set_store_frame_counter_ahead(&mut self, ahead: u32) {
        self.store_ahead = ahead;
    }

    /// `true` if `NetworkInfo` must be persisted now: the key sequence (or
    /// network key) changed, or the outgoing frame counter reached the
    /// persisted value (OpenThread `KeyManager::MacFrameCounterUsed`). After
    /// a reset the device then continues at a counter that was never used.
    pub const fn needs_store(&self) -> bool {
        self.store_pending || self.frame_counter >= self.stored_frame_counter
    }

    /// The MAC frame counter to persist (`NetworkInfo::mac_frame_counter`):
    /// the next counter plus the store-ahead distance (OpenThread
    /// `Mle::Store`), saturating.
    pub const fn frame_counter_to_store(&self) -> u32 {
        self.frame_counter.saturating_add(self.store_ahead)
    }

    /// The caller persisted [`key_sequence`](Self::key_sequence) and
    /// `mac_frame_counter` (normally [`frame_counter_to_store`](Self::frame_counter_to_store)).
    pub fn frame_counter_stored(&mut self, mac_frame_counter: u32) {
        self.stored_frame_counter = mac_frame_counter;
        self.store_pending = false;
    }

    // ------------------------------------------------------------ policy

    /// Which security levels received frames may use (default:
    /// [`RxLevelPolicy::EncMic32Only`]).
    pub fn set_rx_level_policy(&mut self, policy: RxLevelPolicy) {
        self.rx_level_policy = policy;
    }

    /// The receive security level policy.
    pub const fn rx_level_policy(&self) -> RxLevelPolicy {
        self.rx_level_policy
    }

    // ------------------------------------------------------------ enhanced ACK

    /// Secure an enhanced ACK built with
    /// [`FrameBuilder::enh_ack`](crate::frame::FrameBuilder::enh_ack) for a
    /// secured frame, as a radio does (OpenThread `otMacFrameProcessTxSecurity`
    /// on an ACK): the key index (copied from the acked frame) selects the
    /// previous, current or next MAC key, the ACK gets the next outgoing
    /// frame counter and is sealed with `src_ext` (this device) in the nonce.
    ///
    /// Returns `Ok(None)` for an unsecured ACK, `Ok(Some(..))` with the
    /// consumed counter and key index otherwise. [`Error::InvalidArgs`] if
    /// the frame is not a 2015 ACK or not key ID mode 1, [`Error::Security`]
    /// if the key index matches no key, [`Error::InvalidState`] if the frame
    /// counter is exhausted.
    pub fn secure_enh_ack(
        &mut self,
        ack: &mut [u8],
        src_ext: &ExtAddress,
    ) -> Result<Option<AckSecurity>> {
        let f = Frame::parse(ack)?;
        let Some(s) = f.security_header() else {
            return Ok(None);
        };
        if f.frame_type() != FrameType::Ack || f.version() != FrameVersion::V2015 {
            return Err(Error::InvalidArgs);
        }
        let KeyIdentifier::Index(key_id) = s.key else {
            return Err(Error::InvalidArgs);
        };
        if self.lookup_key_index(key_id).is_none() {
            return Err(Error::Security);
        }
        let fc = self.next_frame_counter()?;
        write_aux_header(ack, fc, &KeyIdentifier::Index(key_id))?;
        let (_, key) = self.lookup_key_index(key_id).ok_or(Error::Security)?;
        let cipher = self.backend.aes128(&key.0);
        seal_psdu(&cipher, ack, src_ext)?;
        Ok(Some(AckSecurity {
            frame_counter: fc,
            key_id,
        }))
    }

    /// Verify and decrypt a received enhanced ACK (OpenThread
    /// `Mac::ProcessEnhAckSecurity`) for a transmitted frame secured with key
    /// ID mode 1 and key index `tx_key_index`. `src_ext` is the extended
    /// address of the ACK's sender (the acked frame's destination).
    ///
    /// Returns `Ok(None)` for an unsecured ACK (as OpenThread, the caller
    /// decides whether to accept it). [`Error::Security`] unless the ACK is a
    /// 2015 frame secured at an allowed level with key ID mode 1, the same key
    /// index as the transmitted frame, a known key and a valid MIC. The
    /// replay check of the ACK frame counter is
    /// [`LinkFrameCounters::check_and_update_ack`](super::LinkFrameCounters::check_and_update_ack).
    pub fn unsecure_enh_ack(
        &self,
        ack: &mut [u8],
        tx_key_index: u8,
        src_ext: &ExtAddress,
    ) -> Result<Option<RxSecurityInfo>> {
        let f = Frame::parse(ack)?;
        let Some(s) = f.security_header().copied() else {
            return Ok(None);
        };
        if f.version() != FrameVersion::V2015 || !self.rx_level_policy.allows(s.level) {
            return Err(Error::Security);
        }
        let (KeyIdentifier::Index(key_id), Some(fc)) = (s.key, s.frame_counter) else {
            return Err(Error::Security);
        };
        if key_id != tx_key_index {
            return Err(Error::Security);
        }
        let (seq, key) = self.lookup_key_index(key_id).ok_or(Error::Security)?;
        let cipher = self.backend.aes128(&key.0);
        open_psdu(&cipher, ack, src_ext)?;
        Ok(Some(RxSecurityInfo {
            level: s.level,
            key_id_mode: KeyIdMode::Index,
            key_sequence: Some(seq),
            frame_counter: fc,
        }))
    }
}

impl<B: CryptoBackend> FrameSecurity for KeyManager<B> {
    /// Key ID mode 1: next outgoing frame counter, current key index and MAC
    /// key, nonce from `src_ext`. Key ID mode 2: key source `0xffffffff`,
    /// key index `0xff`, the well-known key and nonce address, and a separate
    /// frame counter (OpenThread `mKeyIdMode2FrameCounter`; mode 2 offers no
    /// replay protection). The frame counter and key identifier in `psdu` are
    /// overwritten.
    ///
    /// [`Error::InvalidArgs`] for key ID modes 0/3 or a suppressed frame
    /// counter, [`Error::InvalidState`] if the frame counter is exhausted.
    fn secure_tx(&mut self, psdu: &mut [u8], src_ext: &ExtAddress) -> Result<()> {
        let f = Frame::parse(psdu)?;
        let Some(s) = f.security_header() else {
            return Ok(());
        };
        if s.frame_counter.is_none() || s.asn_in_nonce {
            return Err(Error::InvalidArgs);
        }
        match s.key_id_mode() {
            KeyIdMode::Index => {
                let fc = self.next_frame_counter()?;
                write_aux_header(psdu, fc, &KeyIdentifier::Index(self.key_index()))?;
                let cipher = self.backend.aes128(&self.keys[1].mac_key.0);
                seal_psdu(&cipher, psdu, src_ext)
            }
            KeyIdMode::Source4 => {
                self.mode2_frame_counter = self.mode2_frame_counter.wrapping_add(1);
                write_aux_header(psdu, self.mode2_frame_counter, &MODE2_KEY_ID)?;
                let cipher = self.backend.aes128(&KEY_ID_MODE2_KEY.0);
                seal_psdu(&cipher, psdu, &KEY_ID_MODE2_EXT_ADDRESS)
            }
            KeyIdMode::Implicit | KeyIdMode::Source8 => Err(Error::InvalidArgs),
        }
    }

    /// Key ID mode 1: the key index must match the current, previous or next
    /// key sequence (Thread §7.2.1.2); the reported `key_sequence` is that
    /// sequence. Key ID mode 2: only key source `0xffffffff` / key index
    /// `0xff` (Thread §7.2.1.3), `key_sequence` is `None`. Any other key
    /// identifier, a level outside the [`RxLevelPolicy`], a suppressed frame
    /// counter or a bad MIC yield [`Error::Security`].
    fn unsecure_rx(
        &mut self,
        psdu: &mut [u8],
        src_ext: &ExtAddress,
    ) -> Result<Option<RxSecurityInfo>> {
        let f = Frame::parse(psdu)?;
        let Some(s) = f.security_header().copied() else {
            return Ok(None);
        };
        if !self.rx_level_policy.allows(s.level) || s.asn_in_nonce {
            return Err(Error::Security);
        }
        let fc = s.frame_counter.ok_or(Error::Security)?;
        let key_sequence = match s.key {
            KeyIdentifier::Index(idx) => {
                let (seq, key) = self.lookup_key_index(idx).ok_or(Error::Security)?;
                let cipher = self.backend.aes128(&key.0);
                open_psdu(&cipher, psdu, src_ext)?;
                Some(seq)
            }
            k if k == MODE2_KEY_ID => {
                let cipher = self.backend.aes128(&KEY_ID_MODE2_KEY.0);
                open_psdu(&cipher, psdu, &KEY_ID_MODE2_EXT_ADDRESS)?;
                None
            }
            _ => return Err(Error::Security),
        };
        Ok(Some(RxSecurityInfo {
            level: s.level,
            key_id_mode: s.key_id_mode(),
            key_sequence,
            frame_counter: fc,
        }))
    }
}

fn derive_three<B: CryptoBackend>(b: &B, nk: &NetworkKey, seq: u32) -> [ThreadKeys; 3] {
    [
        thread_keys(b, nk, seq.wrapping_sub(1)),
        thread_keys(b, nk, seq),
        thread_keys(b, nk, seq.wrapping_add(1)),
    ]
}

const fn guard_hours(rotation_hours: u16) -> u16 {
    (rotation_hours as u32 * KEY_SWITCH_GUARD_PERCENT / 100) as u16
}
