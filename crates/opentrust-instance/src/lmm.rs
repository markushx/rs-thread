//! The Link Metrics Manager (OT `Utils::LinkMetricsManager`): while enabled
//! and attached, it configures Enhanced-ACK based probing (link margin and
//! RSSI) on every neighbor that speaks Thread 1.2 or newer, renews the
//! configuration periodically, and keeps the latest values per neighbor.

use heapless::Vec;
use opentrust_core::time::{Duration, Instant};
use opentrust_core::types::{ExtAddress, ipv6};
use opentrust_core::{Error, Result};
use opentrust_mle::link_metrics::{EnhAckFlags, Metrics, MetricsValues, Status};
use opentrust_platform::SettingsStore;
use rand_core::{CryptoRng, Rng};

use crate::{Instance, InstanceCrypto};

/// Delay between becoming attached and the first update (OT
/// `kTimeBeforeStartMilliSec`).
const TIME_BEFORE_START: Duration = Duration::from_millis(5_000);
/// Update and renewal interval (OT `kStateUpdateIntervalMilliSec`).
const STATE_UPDATE_INTERVAL: Duration = Duration::from_millis(150_000);
/// Configuration attempts before a neighbor counts as not supporting the
/// probing (OT `kConfigureLinkMetricsMaxAttempts`).
const MAX_ATTEMPTS: u8 = 3;
/// Neighbors tracked at the same time.
const MAX_SUBJECTS: usize = 16;

#[derive(Clone, Copy, PartialEq, Eq)]
enum State {
    NotConfigured,
    Configuring,
    Active,
    Renewing,
    NotSupported,
}

#[derive(Clone, Copy)]
struct Subject {
    ext: ExtAddress,
    state: State,
    attempts: u8,
    last_update: Instant,
    rssi: i8,
    link_margin: u8,
}

/// State of the Link Metrics Manager.
pub struct LinkMetricsManager {
    enabled: bool,
    running: bool,
    deadline: Option<Instant>,
    subjects: Vec<Subject, MAX_SUBJECTS>,
}

impl LinkMetricsManager {
    pub(crate) const fn new() -> Self {
        Self {
            enabled: false,
            running: false,
            deadline: None,
            subjects: Vec::new(),
        }
    }

    pub(crate) const fn next_deadline(&self) -> Option<Instant> {
        self.deadline
    }

    /// The answer to a Link Metrics Management Request (OT
    /// `HandleMgmtResponse`).
    pub(crate) fn on_management_response(&mut self, ext: &ExtAddress, status: Status) {
        if !self.running {
            return;
        }
        if let Some(s) = self.subjects.iter_mut().find(|s| s.ext == *ext) {
            s.state = if status == Status::Success {
                State::Active
            } else {
                State::NotConfigured
            };
        }
    }

    /// Metrics from an Enhanced ACK (OT `HandleEnhAckIe`).
    pub(crate) fn on_enh_ack(&mut self, ext: &ExtAddress, v: &MetricsValues, now: Instant) {
        if !self.running {
            return;
        }
        let Some(s) = self.subjects.iter_mut().find(|s| s.ext == *ext) else {
            return;
        };
        if !matches!(s.state, State::Active | State::Renewing) {
            return;
        }
        s.last_update = now;
        if v.metrics.rssi && v.metrics.link_margin {
            s.rssi = v.rssi;
            s.link_margin = v.link_margin;
        }
    }
}

impl<S: SettingsStore, C: InstanceCrypto, R: Rng + CryptoRng> Instance<S, C, R> {
    /// Enable or disable the Link Metrics Manager (OT
    /// `otLinkMetricsManagerSetEnabled`).
    pub fn link_metrics_manager_set_enabled(&mut self, enable: bool, now: Instant) {
        self.core.now = now;
        if self.core.lmm.enabled == enable {
            return;
        }
        self.core.lmm.enabled = enable;
        if !enable {
            self.lmm_stop(now);
        }
        self.poll(now);
    }

    /// Whether the Link Metrics Manager is enabled.
    pub fn is_link_metrics_manager_enabled(&self) -> bool {
        self.core.lmm.enabled
    }

    /// The link margin and RSSI the manager learned for a neighbor (OT
    /// `otLinkMetricsManagerGetMetricsValueByExtAddr`): `(link margin, rssi)`.
    /// Errors: [`Error::NotFound`], [`Error::InvalidState`] (not configured
    /// yet).
    pub fn link_metrics_manager_values(&self, ext: &ExtAddress) -> Result<(u8, i8)> {
        let s = self
            .core
            .lmm
            .subjects
            .iter()
            .find(|s| s.ext == *ext)
            .ok_or(Error::NotFound)?;
        if matches!(s.state, State::Active | State::Renewing) {
            Ok((s.link_margin, s.rssi))
        } else {
            Err(Error::InvalidState)
        }
    }

    fn lmm_stop(&mut self, now: Instant) {
        let m = &mut self.core.lmm;
        m.running = false;
        m.deadline = None;
        let mut subjects = core::mem::take(&mut m.subjects);
        for s in &subjects {
            let _ = self.lmm_send(&s.ext, EnhAckFlags::Clear, None, now);
        }
        subjects.clear();
    }

    fn lmm_send(
        &mut self,
        ext: &ExtAddress,
        flags: EnhAckFlags,
        metrics: Option<&Metrics>,
        now: Instant,
    ) -> Result<()> {
        let dst = ipv6::link_local(ext);
        self.core.now = now;
        self.mle
            .link_metrics_enh_ack(&mut self.core, &dst, flags, metrics)
    }

    /// Start, stop and run the manager's timer (OT `HandleNotifierEvents`
    /// and `HandleTimer`).
    pub(crate) fn service_lmm(&mut self, now: Instant) -> bool {
        let attached = self.core.role.is_attached();
        let m = &mut self.core.lmm;
        if !m.enabled {
            return false;
        }
        if attached && !m.running {
            m.running = true;
            m.deadline = Some(now.saturating_add(TIME_BEFORE_START));
            return false;
        }
        if !attached && m.running {
            self.lmm_stop(now);
            return false;
        }
        if !m.running || m.deadline.is_none_or(|d| d > now) {
            return false;
        }
        m.deadline = Some(now.saturating_add(STATE_UPDATE_INTERVAL));
        self.lmm_update(now);
        true
    }

    fn lmm_update(&mut self, now: Instant) {
        // New neighbors become subjects (OT `UpdateSubjects`).
        for n in self.neighbor_table() {
            let m = &mut self.core.lmm;
            if m.subjects.iter().any(|s| s.ext == n.ext) {
                continue;
            }
            let s = Subject {
                ext: n.ext,
                state: State::NotConfigured,
                attempts: 0,
                last_update: Instant::ZERO,
                rssi: 0,
                link_margin: 0,
            };
            if m.subjects.push(s).is_err() {
                break;
            }
        }
        // State per subject; the ones that are gone or cannot do it are
        // dropped (OT `UpdateLinkMetricsStates`).
        let mut i = 0;
        while i < self.core.lmm.subjects.len() {
            let mut s = self.core.lmm.subjects[i];
            let mut configure = false;
            match s.state {
                State::NotConfigured | State::Configuring | State::Renewing => {
                    if s.attempts >= MAX_ATTEMPTS {
                        s.state = State::NotSupported;
                    } else {
                        configure = true;
                    }
                }
                State::Active => {
                    configure =
                        now.saturating_duration_since(s.last_update) >= STATE_UPDATE_INTERVAL;
                }
                State::NotSupported => {}
            }
            let mut remove = s.state == State::NotSupported;
            if configure {
                let metrics = Metrics {
                    link_margin: true,
                    rssi: true,
                    ..Metrics::NONE
                };
                match self.lmm_send(&s.ext, EnhAckFlags::Register, Some(&metrics), now) {
                    Ok(()) => {
                        s.state = if s.state == State::Active {
                            State::Renewing
                        } else {
                            State::Configuring
                        };
                        s.attempts += 1;
                    }
                    Err(Error::NotFound | Error::InvalidState) => remove = true,
                    Err(_) => {}
                }
            }
            if remove {
                self.core.lmm.subjects.swap_remove(i);
            } else {
                self.core.lmm.subjects[i] = s;
                i += 1;
            }
        }
    }
}
