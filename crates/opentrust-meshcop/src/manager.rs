//! Active and Pending dataset management (OT `meshcop/dataset_manager.cpp`,
//! `dataset_manager_ftd.cpp`).
//!
//! [`Datasets`] holds the local copy of both datasets together with the
//! network timestamps, the Pending Dataset delay timer and the retry timer
//! for synchronizing the local dataset with the leader. Everything the
//! datasets touch (MAC channel / PAN ID, key manager, mesh-local prefix,
//! settings, Network Data versions) is reached through [`DatasetEnv`].
//!
//! # Wiring
//!
//! - Implement [`DatasetEnv`] on the borrowed pieces of the stack and
//!   [`MleEnv::active_timestamp`](opentrust_mle::env::MleEnv::active_timestamp)
//!   / `pending_timestamp` / `active_dataset` / `pending_dataset` /
//!   `dataset_received` by forwarding to [`Datasets::timestamp`],
//!   [`Datasets::mle_dataset`] and [`Datasets::dataset_received`].
//! - Call [`Datasets::restore`] for both types before starting MLE, and
//!   [`Datasets::poll`] at [`Datasets::next_deadline`].
//! - The TMF side (`/c/ag`, `/c/as`, ...) is in [`mgmt`](crate::mgmt).

use opentrust_core::Result;
use opentrust_core::time::{Duration, Instant};
use opentrust_core::types::{ExtPanId, NetworkKey, NetworkName, Prefix64, Pskc};
use opentrust_mle::Role;

use crate::dataset::{Dataset, DatasetType};
use crate::timestamp::{Timestamp, compare};
use crate::tlv::{DEFAULT_DELAY_MS, MAX_DELAY_MS, MIN_DELAY_MS, SecurityPolicy, ty};

/// While the Pending delay timer runs the Pending Dataset is stored again
/// with the remaining delay at this interval, so a reset does not restart
/// the full delay (see [`Datasets::checkpoint_pending_delay`]).
pub const DELAY_CHECKPOINT_INTERVAL: Duration = Duration::from_secs(60);

/// Retry delay for sending MGMT_SET to the leader (`kSendSetDelay`).
pub const SEND_SET_DELAY: Duration = Duration::from_millis(5000);

/// Network parameters a dataset configures (the TLVs `ApplyConfiguration`
/// pushes into MAC, key manager, MLE); a field is `None` if the dataset
/// has no such TLV.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Configuration {
    /// PAN channel (page 0).
    pub channel: Option<u8>,
    /// PAN ID.
    pub pan_id: Option<u16>,
    /// Extended PAN ID.
    pub ext_pan_id: Option<ExtPanId>,
    /// Network name.
    pub network_name: Option<NetworkName>,
    /// Network key.
    pub network_key: Option<NetworkKey>,
    /// PSKc.
    pub pskc: Option<Pskc>,
    /// Mesh-local prefix.
    pub mesh_local_prefix: Option<Prefix64>,
    /// Security policy.
    pub security_policy: Option<SecurityPolicy>,
}

impl Configuration {
    /// Extract the configuration TLVs of `d` (invalid values are skipped).
    pub fn from_dataset(d: &Dataset) -> Self {
        let t = d.tlvs();
        Self {
            channel: t.channel().ok().map(|c| c.channel as u8),
            pan_id: t.pan_id().ok(),
            ext_pan_id: t.ext_pan_id().ok(),
            network_name: t.network_name().ok(),
            network_key: t.network_key().ok(),
            pskc: t.pskc().ok(),
            mesh_local_prefix: t.mesh_local_prefix().ok(),
            security_policy: t.security_policy().ok(),
        }
    }
}

/// The live values a new dataset is compared against (to decide whether it
/// affects connectivity or the network key).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CurrentConfig {
    /// PAN channel.
    pub channel: u8,
    /// PAN ID.
    pub pan_id: u16,
    /// Mesh-local prefix.
    pub mesh_local_prefix: Prefix64,
    /// Network key.
    pub network_key: NetworkKey,
}

/// A dataset changed (OT `kEventActiveDatasetChanged` /
/// `kEventPendingDatasetChanged`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum DatasetEvent {
    /// The Active Dataset changed.
    ActiveChanged,
    /// The Pending Dataset changed.
    PendingChanged,
}

/// What the dataset managers need from the rest of the stack.
pub trait DatasetEnv {
    /// Live channel, PAN ID, mesh-local prefix and network key.
    fn current(&self) -> CurrentConfig;
    /// Push the configuration of an Active Dataset into MAC, key manager
    /// and MLE (OT `ApplyConfiguration`). Errors are logged, not fatal.
    fn apply(&mut self, cfg: &Configuration) -> Result<()>;
    /// Device role.
    fn role(&self) -> Role;
    /// Persist a dataset (`SettingsKey::ActiveDataset` / `PendingDataset`).
    fn store(&mut self, _ty: DatasetType, _tlvs: &[u8]) -> Result<()> {
        Ok(())
    }
    /// Read the persisted dataset into `out`; its length.
    fn load(&self, _ty: DatasetType, _out: &mut [u8]) -> Option<usize> {
        None
    }
    /// Delete the persisted dataset.
    fn delete(&mut self, _ty: DatasetType) {}
    /// Notification, see [`DatasetEvent`].
    fn event(&mut self, _event: DatasetEvent) {}
    /// The Commissioner Session ID in the leader's Commissioning Data.
    fn commissioning_session_id(&self) -> Option<u16> {
        None
    }
    /// Leader: a dataset changed, increment the Network Data version and
    /// stable version (OT `IncrementVersionAndStableVersion`) and publish.
    fn network_data_changed(&mut self) {}
}

#[derive(Debug, Default, Clone)]
struct Manager {
    local: Dataset,
    local_saved: bool,
    network_ts: Option<Timestamp>,
    local_ts: Option<Timestamp>,
    local_update: Instant,
    send_set_at: Option<Instant>,
    mgmt_pending: bool,
    set_wanted: bool,
}

/// Local Active and Pending datasets with their timers.
#[derive(Debug, Clone)]
pub struct Datasets {
    m: [Manager; 2],
    delay_deadline: Option<Instant>,
    delay_checkpoint: Option<Instant>,
    delay_timer_minimal_ms: u32,
}

impl Default for Datasets {
    fn default() -> Self {
        Self::new()
    }
}

impl Datasets {
    /// Empty datasets, minimal delay timer of [`MIN_DELAY_MS`].
    pub fn new() -> Self {
        Self {
            m: Default::default(),
            delay_deadline: None,
            delay_checkpoint: None,
            delay_timer_minimal_ms: MIN_DELAY_MS,
        }
    }

    fn mgr(&self, t: DatasetType) -> &Manager {
        &self.m[t.index()]
    }

    fn mgr_mut(&mut self, t: DatasetType) -> &mut Manager {
        &mut self.m[t.index()]
    }

    /// The network timestamp (OT `GetTimestamp`): the timestamp of the
    /// dataset the network has, as learned from the leader.
    pub fn timestamp(&self, t: DatasetType) -> Option<Timestamp> {
        self.mgr(t).network_ts
    }

    /// The timestamp of the locally saved dataset.
    pub fn local_timestamp(&self, t: DatasetType) -> Option<Timestamp> {
        self.mgr(t).local_ts
    }

    /// A dataset is saved locally but not yet confirmed by the network
    /// (OT `IsPartiallyComplete`).
    pub fn is_partially_complete(&self) -> bool {
        let m = self.mgr(DatasetType::Active);
        m.local_saved && m.network_ts.is_none()
    }

    /// The Active Dataset is saved locally and known to the network (OT
    /// `IsComplete`).
    pub fn is_complete(&self) -> bool {
        let m = self.mgr(DatasetType::Active);
        m.local_saved && m.network_ts.is_some()
    }

    /// A dataset of this type is saved locally.
    pub fn is_saved(&self, t: DatasetType) -> bool {
        self.mgr(t).local_saved
    }

    /// The leader's minimal delay timer (OT `Leader::GetDelayTimerMinimal`).
    pub fn delay_timer_minimal_ms(&self) -> u32 {
        self.delay_timer_minimal_ms
    }

    /// OT `SetDelayTimerMinimal`: `0 < ms < MIN_DELAY_MS`.
    pub fn set_delay_timer_minimal_ms(&mut self, ms: u32) -> Result<()> {
        if ms == 0 || ms >= MIN_DELAY_MS {
            return Err(opentrust_core::Error::InvalidArgs);
        }
        self.delay_timer_minimal_ms = ms;
        Ok(())
    }

    /// The security policy of the Active Dataset (default if none).
    pub fn security_policy(&self) -> SecurityPolicy {
        let m = self.mgr(DatasetType::Active);
        if m.local_saved {
            m.local.tlvs().security_policy().unwrap_or_default()
        } else {
            SecurityPolicy::default()
        }
    }

    /// OT `Read`: the local dataset. The Active Dataset has no Pending
    /// Timestamp / Delay Timer; the Pending Dataset's Delay Timer is the
    /// remaining delay.
    pub fn read(&self, t: DatasetType, now: Instant) -> Option<Dataset> {
        let m = self.mgr(t);
        if !m.local_saved {
            return None;
        }
        let mut d = m.local.clone();
        match t {
            DatasetType::Active => {
                d.remove(ty::PENDING_TIMESTAMP);
                d.remove(ty::DELAY_TIMER);
            }
            DatasetType::Pending => {
                if let Ok(delay) = d.tlvs().delay_timer() {
                    let delay = delay.min(MAX_DELAY_MS);
                    let elapsed = now.saturating_duration_since(m.local_update).as_millis();
                    let remaining = u64::from(delay).saturating_sub(elapsed);
                    let _ = d.set_delay_timer(remaining as u32);
                }
            }
        }
        Some(d)
    }

    /// The dataset without its own timestamp TLV, for the MLE Active /
    /// Pending Dataset TLV (the timestamp is a separate MLE TLV). Returns
    /// the length, `0` if there is no dataset.
    pub fn mle_dataset(&self, t: DatasetType, now: Instant, out: &mut [u8]) -> Result<usize> {
        match self.read(t, now) {
            Some(d) => d.copy_without(t.timestamp_tlv(), out),
            None => Ok(0),
        }
    }

    /// Remaining Pending delay in milliseconds (`ReadRemainingDelay`).
    pub fn remaining_delay_ms(&self, now: Instant) -> Option<u32> {
        let d = self.delay_deadline?;
        Some(d.saturating_duration_since(now).as_millis() as u32)
    }

    /// Active Timestamp inside the Pending Dataset (`ReadActiveTimestamp`).
    pub fn pending_active_timestamp(&self) -> Option<Timestamp> {
        let m = self.mgr(DatasetType::Pending);
        if !m.local_saved {
            return None;
        }
        m.local.timestamp(DatasetType::Active)
    }

    // ------------------------------------------------------------ restore / save

    /// OT `Restore()`: load from settings and (Active) apply it.
    pub fn restore<E: DatasetEnv>(
        &mut self,
        env: &mut E,
        now: Instant,
        t: DatasetType,
    ) -> Result<()> {
        let mut buf = [0u8; crate::dataset::MAX_LEN];
        let loaded = env
            .load(t, &mut buf)
            .and_then(|n| Dataset::from_tlvs(&buf[..n]).ok());
        match loaded {
            Some(mut d) => {
                if t == DatasetType::Active {
                    d.remove(ty::PENDING_TIMESTAMP);
                    d.remove(ty::DELAY_TIMER);
                }
                self.m[t.index()].local = d.clone();
                self.restore_dataset(env, now, t, Some(&d));
                Ok(())
            }
            None => {
                self.restore_dataset(env, now, t, None);
                Err(opentrust_core::Error::NotFound)
            }
        }
    }

    /// OT `Restore(dataset)`: stop the timer, reset the timestamps from
    /// the dataset, apply the configuration if Active, signal.
    fn restore_dataset<E: DatasetEnv>(
        &mut self,
        env: &mut E,
        now: Instant,
        t: DatasetType,
        d: Option<&Dataset>,
    ) {
        let m = self.mgr_mut(t);
        m.send_set_at = None;
        m.network_ts = None;
        m.local_ts = None;
        if let Some(d) = d.filter(|d| !d.is_empty()) {
            m.local_saved = true;
            m.local_update = now;
            if let Some(ts) = d.timestamp(t) {
                m.local_ts = Some(ts);
                m.network_ts = Some(ts);
            }
            if t == DatasetType::Active {
                let _ = env.apply(&Configuration::from_dataset(d));
            } else {
                self.start_delay_timer(now);
            }
        } else {
            m.local_saved = false;
        }
        Self::signal(env, t);
    }

    fn signal<E: DatasetEnv>(env: &mut E, t: DatasetType) {
        env.event(match t {
            DatasetType::Active => DatasetEvent::ActiveChanged,
            DatasetType::Pending => DatasetEvent::PendingChanged,
        });
    }

    /// OT `Clear`: delete the dataset and its timers.
    pub fn clear<E: DatasetEnv>(&mut self, env: &mut E, t: DatasetType) {
        let m = self.mgr_mut(t);
        m.network_ts = None;
        m.local_ts = None;
        m.local_saved = false;
        m.local.clear();
        m.send_set_at = None;
        env.delete(t);
        if t == DatasetType::Pending {
            self.delay_deadline = None;
            self.delay_checkpoint = None;
        }
        Self::signal(env, t);
    }

    /// OT `LocalSave`.
    fn local_save<E: DatasetEnv>(
        &mut self,
        env: &mut E,
        now: Instant,
        t: DatasetType,
        d: &Dataset,
    ) {
        let m = self.mgr_mut(t);
        if d.is_empty() {
            env.delete(t);
            m.local_saved = false;
            m.local.clear();
        } else {
            let _ = env.store(t, d.as_bytes());
            m.local = d.clone();
            m.local_saved = true;
        }
        m.local_ts = d.timestamp(t);
        m.local_update = now;
        if t == DatasetType::Pending {
            self.start_delay_timer_for(now, d);
        }
    }

    /// OT `Save(dataset, allow_older)`: a dataset received from the
    /// network (MLE) or the leader's own accepted MGMT_SET.
    pub fn save<E: DatasetEnv>(
        &mut self,
        env: &mut E,
        now: Instant,
        t: DatasetType,
        d: &Dataset,
        allow_older: bool,
    ) -> Result<()> {
        if let Some(ts) = d.timestamp(t) {
            self.mgr_mut(t).network_ts = Some(ts);
            if t == DatasetType::Active {
                env.apply(&Configuration::from_dataset(d))?;
            }
        }
        let m = self.mgr(t);
        let cmp = compare(m.network_ts.as_ref(), m.local_ts.as_ref());
        if cmp.is_gt() || allow_older {
            self.local_save(env, now, t, d);
            if env.role() == Role::Leader {
                env.network_data_changed();
            }
        } else if cmp.is_lt() {
            self.mgr_mut(t).send_set_at = Some(now.saturating_add(SEND_SET_DELAY));
        }
        Self::signal(env, t);
        Ok(())
    }

    /// OT `SaveLocal(dataset)`: the application sets a dataset.
    pub fn save_local<E: DatasetEnv>(
        &mut self,
        env: &mut E,
        now: Instant,
        t: DatasetType,
        d: &Dataset,
    ) -> Result<()> {
        d.validate()?;
        self.local_save(env, now, t, d);
        match env.role() {
            Role::Disabled => self.restore_dataset(env, now, t, Some(d)),
            Role::Child | Role::Router => self.sync_local_with_leader(t),
            Role::Leader => {
                self.restore_dataset(env, now, t, Some(d));
                env.network_data_changed();
            }
            Role::Detached => {}
        }
        Self::signal(env, t);
        Ok(())
    }

    /// Generate the local Active Dataset from the live configuration
    /// where TLVs are missing (OT `GenerateLocal`, run when a device
    /// becomes leader without a dataset). `cfg` supplies the values for
    /// missing TLVs, `channel_mask` the Channel Mask.
    #[cfg(feature = "ftd")]
    pub fn generate_local<E: DatasetEnv>(
        &mut self,
        env: &mut E,
        now: Instant,
        cfg: &Configuration,
        channel_mask: u32,
    ) -> Result<()> {
        use opentrust_core::Error;
        let t = DatasetType::Active;
        if self.mgr(t).local_ts.is_some() {
            return Err(Error::Already);
        }
        let mut d = self.read(t, now).unwrap_or_default();
        if !d.contains(ty::ACTIVE_TIMESTAMP) {
            d.set_timestamp(t, &Timestamp::default())?;
        }
        if !d.contains(ty::CHANNEL) {
            d.set_channel(cfg.channel.ok_or(Error::InvalidArgs)?)?;
        }
        if !d.contains(ty::CHANNEL_MASK) {
            d.set_channel_mask(channel_mask)?;
        }
        if !d.contains(ty::EXT_PAN_ID) {
            d.set_ext_pan_id(cfg.ext_pan_id.as_ref().ok_or(Error::InvalidArgs)?)?;
        }
        if !d.contains(ty::MESH_LOCAL_PREFIX) {
            d.set_mesh_local_prefix(cfg.mesh_local_prefix.as_ref().ok_or(Error::InvalidArgs)?)?;
        }
        if !d.contains(ty::NETWORK_KEY) {
            d.set_network_key(cfg.network_key.as_ref().ok_or(Error::InvalidArgs)?)?;
        }
        if !d.contains(ty::NETWORK_NAME) {
            d.set_network_name(cfg.network_name.as_ref().ok_or(Error::InvalidArgs)?)?;
        }
        if !d.contains(ty::PAN_ID) {
            d.set_pan_id(cfg.pan_id.ok_or(Error::InvalidArgs)?)?;
        }
        if !d.contains(ty::PSKC) {
            d.set_pskc(cfg.pskc.as_ref().ok_or(Error::InvalidArgs)?)?;
        }
        if !d.contains(ty::SECURITY_POLICY) {
            d.set_security_policy(&cfg.security_policy.unwrap_or_default())?;
        }
        self.local_save(env, now, t, &d);
        self.restore_dataset(env, now, t, Some(&d));
        Ok(())
    }

    // ------------------------------------------------------------ MLE

    /// `MleEnv::dataset_received`: datasets from a Child ID Response / Data
    /// Response. The dataset bytes come without their timestamp TLV, which
    /// is passed separately (OT `ReadAndSaveDataset`). A dataset that does
    /// not validate is ignored.
    pub fn dataset_received<E: DatasetEnv>(
        &mut self,
        env: &mut E,
        now: Instant,
        active: Option<(Timestamp, Option<&[u8]>)>,
        pending: Option<(Timestamp, Option<&[u8]>)>,
    ) {
        for (t, rx) in [
            (DatasetType::Active, active),
            (DatasetType::Pending, pending),
        ] {
            let Some((ts, Some(bytes))) = rx else {
                continue;
            };
            let Ok(mut d) = Dataset::from_tlvs(bytes) else {
                continue;
            };
            if d.set_timestamp(t, &ts).is_err() {
                continue;
            }
            let _ = self.save(env, now, t, &d, false);
        }
    }

    // ------------------------------------------------------------ leader sync

    /// OT `SyncLocalWithLeader`: mark that the local dataset is newer than
    /// the network's and should be sent to the leader with MGMT_SET.
    fn sync_local_with_leader(&mut self, t: DatasetType) {
        let m = self.mgr_mut(t);
        if m.mgmt_pending {
            return;
        }
        if compare(m.network_ts.as_ref(), m.local_ts.as_ref()).is_lt() {
            m.set_wanted = true;
        }
    }

    /// The dataset to send in a MGMT_SET to the leader, if one is wanted and
    /// possible (child or router, no request pending, local timestamp newer
    /// than the network's, not during an Active -> Pending transition);
    /// marks the request as pending.
    pub fn take_set_request(
        &mut self,
        role: Role,
        now: Instant,
        t: DatasetType,
    ) -> Option<Dataset> {
        if !self.mgr(t).set_wanted || self.mgr(t).mgmt_pending {
            return None;
        }
        if !matches!(role, Role::Child | Role::Router) {
            return None;
        }
        let m = self.mgr(t);
        if !compare(m.network_ts.as_ref(), m.local_ts.as_ref()).is_lt() {
            self.mgr_mut(t).set_wanted = false;
            return None;
        }
        if t == DatasetType::Active
            && self.pending_active_timestamp().is_some()
            && self.pending_active_timestamp() == self.mgr(t).local_ts
        {
            return None;
        }
        let d = self.read(t, now)?;
        let m = self.mgr_mut(t);
        m.set_wanted = false;
        m.mgmt_pending = true;
        Some(d)
    }

    /// The MGMT_SET to the leader finished (response, timeout or send
    /// failure): retry in [`SEND_SET_DELAY`] (OT `HandleMgmtSetResponse`).
    pub fn mgmt_set_finished(&mut self, now: Instant, t: DatasetType) {
        let m = self.mgr_mut(t);
        m.mgmt_pending = false;
        m.send_set_at = Some(now.saturating_add(SEND_SET_DELAY));
    }

    // ------------------------------------------------------------ pending delay timer

    fn start_delay_timer(&mut self, now: Instant) {
        let d = self.read(DatasetType::Pending, now);
        self.delay_deadline = None;
        if let Some(d) = d {
            self.start_delay_timer_for_with_start(self.mgr(DatasetType::Pending).local_update, &d);
        }
    }

    fn start_delay_timer_for(&mut self, now: Instant, d: &Dataset) {
        self.start_delay_timer_for_with_start(now, d);
    }

    fn start_delay_timer_for_with_start(&mut self, start: Instant, d: &Dataset) {
        self.delay_deadline = None;
        self.delay_checkpoint = None;
        if let Ok(delay) = d.tlvs().delay_timer() {
            let delay = delay.min(MAX_DELAY_MS);
            self.delay_deadline =
                Some(start.saturating_add(Duration::from_millis(u64::from(delay))));
            self.delay_checkpoint = Some(start.saturating_add(DELAY_CHECKPOINT_INTERVAL));
        }
    }

    /// Store the Pending Dataset with the remaining delay (the Delay Timer
    /// TLV of [`read`](Self::read)) while the delay timer runs. A reset
    /// then restores the timer with what was left at the last checkpoint
    /// ([`restore`](Self::restore) starts the delay from the stored TLV)
    /// instead of the full delay. [`poll`](Self::poll) does this every
    /// [`DELAY_CHECKPOINT_INTERVAL`]; call it directly before a planned
    /// shutdown.
    pub fn checkpoint_pending_delay<E: DatasetEnv>(&mut self, env: &mut E, now: Instant) {
        if self.delay_deadline.is_none() {
            self.delay_checkpoint = None;
            return;
        }
        if let Some(d) = self.read(DatasetType::Pending, now) {
            let _ = env.store(DatasetType::Pending, d.as_bytes());
        }
        self.delay_checkpoint = Some(now.saturating_add(DELAY_CHECKPOINT_INTERVAL));
    }

    /// OT `PendingDatasetManager::StartDelayTimer()`: (re)start from the
    /// saved Pending Dataset (leader start).
    pub fn start_pending_delay_timer(&mut self, now: Instant) {
        self.start_delay_timer(now);
    }

    /// OT `PendingDatasetManager::ApplyActiveDataset`: the leader turns an
    /// Active Dataset update that affects connectivity into a Pending
    /// Dataset with the Active Timestamp as Pending Timestamp and the
    /// minimal delay.
    #[cfg(feature = "ftd")]
    pub fn apply_active_as_pending<E: DatasetEnv>(
        &mut self,
        env: &mut E,
        now: Instant,
        d: &mut Dataset,
    ) -> Result<()> {
        let ts = d
            .timestamp(DatasetType::Active)
            .ok_or(opentrust_core::Error::NotFound)?;
        d.set_timestamp(DatasetType::Pending, &ts)?;
        d.set_delay_timer(self.delay_timer_minimal_ms)?;
        self.save(env, now, DatasetType::Pending, d, false)?;
        self.start_delay_timer(now);
        Ok(())
    }

    /// OT `HandleDelayTimer`: the delay of the Pending Dataset elapsed;
    /// replace the Active Dataset if the Pending one has a newer Active
    /// Timestamp or a different network key, then drop it.
    fn handle_delay_timer<E: DatasetEnv>(&mut self, env: &mut E, now: Instant) {
        self.delay_deadline = None;
        self.delay_checkpoint = None;
        if let Some(mut d) = self.read(DatasetType::Pending, now) {
            let replace = match d.tlvs().active_timestamp() {
                Err(_) => false,
                Ok(ts) => {
                    if compare(Some(&ts), self.mgr(DatasetType::Active).network_ts.as_ref()).is_gt()
                    {
                        true
                    } else {
                        d.tlvs()
                            .network_key()
                            .is_ok_and(|k| k != env.current().network_key)
                    }
                }
            };
            if replace {
                d.remove(ty::PENDING_TIMESTAMP);
                d.remove(ty::DELAY_TIMER);
                let _ = self.save(env, now, DatasetType::Active, &d, true);
            }
        }
        self.clear(env, DatasetType::Pending);
    }

    // ------------------------------------------------------------ time

    /// Run due timers: the Pending delay timer and the MGMT_SET retry
    /// timers.
    pub fn poll<E: DatasetEnv>(&mut self, env: &mut E, now: Instant) {
        if self.delay_deadline.is_some_and(|d| d <= now) {
            self.handle_delay_timer(env, now);
        } else if self.delay_checkpoint.is_some_and(|c| c <= now) {
            self.checkpoint_pending_delay(env, now);
        }
        for t in [DatasetType::Active, DatasetType::Pending] {
            if self.mgr(t).send_set_at.is_some_and(|d| d <= now) {
                self.mgr_mut(t).send_set_at = None;
                self.sync_local_with_leader(t);
            }
        }
    }

    /// When [`poll`](Self::poll) next has work.
    pub fn next_deadline(&self) -> Option<Instant> {
        self.delay_deadline
            .into_iter()
            .chain(self.delay_checkpoint)
            .chain(self.m.iter().filter_map(|m| m.send_set_at))
            .min()
    }
}

/// Default Delay Timer for datasets created locally.
pub const DEFAULT_DELAY: Duration = Duration::from_millis(DEFAULT_DELAY_MS as u64);
