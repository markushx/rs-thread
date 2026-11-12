//! ICD (Intermittently Connected Device) hooks: the network driver side of
//! rs-matter's `Icd` power mode state machine.
//!
//! rs-matter's ICD Management handler drives an `Icd`; the network driver is
//! expected to re-read [`IcdNetParams`] whenever `Icd::wait_net_changed`
//! resolves and apply them to its link. [`IcdFollower`] does that for the
//! Thread node:
//!
//! - the polling interval (fast while active, slow while idle) becomes the
//!   data poll period of the node ([`Instance::set_poll_period`]);
//! - the link mode (receiver on when idle or sleepy) is set with
//!   [`IcdFollower::set_sleepy`], which keeps the FTD / full Network Data
//!   bits of the current mode.
//!
//! Not supported by the [`Instance`](opentrust_instance::Instance), and thus
//! not applied: the child timeout derived from
//! `IcdNetParams::max_poll_interval_ms` (the child timeout is the fixed
//! stack default, so a slow poll interval longer than it makes the parent age
//! the child out), CSL (the MAC has no CSL), child supervision.
//!
//! [`Instance::set_poll_period`]: opentrust_instance::Instance::set_poll_period

use embassy_sync::blocking_mutex::raw::RawMutex;
use opentrust_core::time::Duration;
use opentrust_embassy::OpenTrust;
use opentrust_instance::{DeviceMode, InstanceCrypto};
use opentrust_platform::{Clock, SettingsStore};
use rand_core::{CryptoRng, Rng};
use rs_matter::dm::clusters::icd_mgmt::{Icd, IcdNetParams};
use rs_matter::error::Error;

use crate::error::map_err;

/// Applies the ICD network parameters to a Thread node.
pub struct IcdFollower<'a, M, K, S, C, R>
where
    M: RawMutex,
    C: InstanceCrypto,
{
    ot: OpenTrust<'a, M, K, S, C, R>,
}

impl<M: RawMutex, K, S, C: InstanceCrypto, R> core::fmt::Debug for IcdFollower<'_, M, K, S, C, R> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("IcdFollower").finish_non_exhaustive()
    }
}

impl<'a, M, K, S, C, R> IcdFollower<'a, M, K, S, C, R>
where
    M: RawMutex,
    K: Clock,
    S: SettingsStore,
    C: InstanceCrypto,
    R: Rng + CryptoRng,
{
    /// The follower of the node behind `ot`.
    pub const fn new(ot: OpenTrust<'a, M, K, S, C, R>) -> Self {
        Self { ot }
    }

    /// Make the node a sleepy end device (receiver off when idle, data
    /// polling) or a node with the receiver on when idle, keeping the other
    /// bits of the link mode.
    pub fn set_sleepy(&self, sleepy: bool) -> Result<(), Error> {
        self.ot
            .with(|i, now| {
                let cur = i.link_mode();
                i.set_link_mode(
                    DeviceMode::new(!sleepy, cur.full_thread_device(), cur.full_network_data()),
                    now,
                )
            })
            .map_err(map_err)
    }

    /// Apply the polling interval of `p`.
    pub fn apply(&self, p: &IcdNetParams) {
        let period =
            (p.poll_interval_ms != 0).then(|| Duration::from_millis(u64::from(p.poll_interval_ms)));
        self.ot.with(|i, _| i.set_poll_period(period));
    }

    /// Follow `icd` forever: apply its parameters now and after every change.
    /// Run it next to the ICD Management handler (one waiter per `Icd`).
    pub async fn run(&self, icd: &Icd) -> core::convert::Infallible {
        loop {
            self.apply(&icd.net_params());
            icd.wait_net_changed().await;
        }
    }
}
