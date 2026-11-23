//! Dataset Updater (OT `meshcop/dataset_updater.cpp`, feature `ftd`).
//!
//! Changes parts of the Operational Dataset of a running network: the
//! requested TLVs are merged into the Active Dataset, both timestamps are
//! advanced by random ticks, a Delay Timer (default 30 seconds) is added
//! and the result is saved as Pending Dataset, which the dataset manager
//! sends to the leader (`MGMT_PENDING_SET`). The update is finished when
//! the Active Dataset contains the requested TLVs.
//!
//! Sans-IO: [`DatasetUpdater::request_update`] takes the dataset managers
//! and a random value; the caller feeds every [`DatasetEvent`] the
//! [`DatasetEnv`] receives to [`DatasetUpdater::handle_event`], which
//! returns the final [`UpdateOutcome`].

use rs_thread_core::time::Instant;
use rs_thread_core::{Error, Result};
use rs_thread_mle::Role;

use crate::dataset::{Dataset, DatasetType};
use crate::manager::{DatasetEnv, DatasetEvent, Datasets};
use crate::timestamp::{self, Timestamp, compare};
use crate::tlv::ty;

/// Delay Timer of an update without one (OT `OPENTHREAD_CONFIG_DATASET_UPDATER_DEFAULT_DELAY`).
pub const DEFAULT_DELAY_MS: u32 = 30_000;

/// How a requested update ended (the OT `UpdaterCallback` error).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpdateOutcome {
    /// The Active Dataset contains the requested TLVs.
    Done,
    /// A dataset with a timestamp at least as new as the requested one
    /// appeared without the requested TLVs: another device won
    /// (OT `kErrorAlready`).
    Conflict,
}

/// State of one update request.
#[derive(Debug, Clone, Default)]
pub struct DatasetUpdater {
    requested: Option<Dataset>,
}

impl DatasetUpdater {
    /// No update ongoing.
    pub const fn new() -> Self {
        Self { requested: None }
    }

    /// An update was requested and is not finished.
    pub const fn is_update_ongoing(&self) -> bool {
        self.requested.is_some()
    }

    /// Forget the request (OT `CancelUpdate`; no outcome is reported).
    pub fn cancel_update(&mut self) {
        self.requested = None;
    }

    /// OT `RequestUpdate`: `changes` holds the TLVs to change (no Active /
    /// Pending Timestamp; a Delay Timer is optional). `random_ticks` is a
    /// random value for the timestamp advance.
    ///
    /// Errors: [`Error::InvalidState`] if disabled or there is no Active
    /// Dataset; [`Error::InvalidArgs`] for an invalid dataset or one with
    /// timestamps; [`Error::Busy`] if an update is ongoing;
    /// [`Error::Already`] if the Active Dataset has the values already.
    pub fn request_update<E: DatasetEnv>(
        &mut self,
        ds: &mut Datasets,
        env: &mut E,
        now: Instant,
        changes: &Dataset,
        random_ticks: [u32; 2],
    ) -> Result<()> {
        if env.role() == Role::Disabled {
            return Err(Error::InvalidState);
        }
        let mut active = ds
            .read(DatasetType::Active, now)
            .ok_or(Error::InvalidState)?;
        let mut active_ts = active
            .timestamp(DatasetType::Active)
            .ok_or(Error::InvalidState)?;
        changes.validate().map_err(|_| Error::InvalidArgs)?;
        if changes.contains(ty::ACTIVE_TIMESTAMP) || changes.contains(ty::PENDING_TIMESTAMP) {
            return Err(Error::InvalidArgs);
        }
        if self.is_update_ongoing() {
            return Err(Error::Busy);
        }
        if changes.is_subset_of(&active) {
            return Err(Error::Already);
        }
        let mut req = changes.clone();
        timestamp::advance_ticks(&mut active_ts, random_ticks[0]);
        req.set_timestamp(DatasetType::Active, &active_ts)?;
        let mut pending_ts = ds.timestamp(DatasetType::Pending).unwrap_or_default();
        timestamp::advance_ticks(&mut pending_ts, random_ticks[1]);
        req.set_timestamp(DatasetType::Pending, &pending_ts)?;
        if !req.contains(ty::DELAY_TIMER) {
            req.set_delay_timer(DEFAULT_DELAY_MS)?;
        }
        active.write_tlvs_from(&req)?;
        ds.save_local(env, now, DatasetType::Pending, &active)?;
        self.requested = Some(req);
        Ok(())
    }

    /// OT `HandleDatasetChanged`: feed a dataset event. Returns the outcome
    /// once the update is finished.
    pub fn handle_event(
        &mut self,
        ds: &Datasets,
        now: Instant,
        event: DatasetEvent,
    ) -> Option<UpdateOutcome> {
        let t = match event {
            DatasetEvent::ActiveChanged => DatasetType::Active,
            DatasetEvent::PendingChanged => DatasetType::Pending,
        };
        let requested = self.requested.as_ref()?;
        let new = ds.read(t, now)?;
        // Found in the Active Dataset: done; found in the Pending Dataset:
        // wait for it to become Active.
        if requested.is_subset_of(&new) {
            if t == DatasetType::Active {
                self.requested = None;
                return Some(UpdateOutcome::Done);
            }
            return None;
        }
        // A timestamp ahead of the requested one: a conflicting update.
        let new_ts: Timestamp = new.timestamp(t)?;
        let req_ts = requested.timestamp(t)?;
        if compare(Some(&new_ts), Some(&req_ts)).is_ge() {
            self.requested = None;
            return Some(UpdateOutcome::Conflict);
        }
        None
    }
}
