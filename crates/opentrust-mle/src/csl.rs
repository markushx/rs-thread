//! CSL receiver side of MLE (Thread 1.4.1 §3.2.6.3, §4.4.31-33; OpenThread
//! `Mle::SetCslTimeout`, `AppendCslChannelTlv`, `AppendCslTimeoutTlv`,
//! `CalcParentCslMetric`, `Mac::UpdateCslState`).
//!
//! A synchronized sleepy end device (SSED) is a child with the receiver off
//! whose parent is Thread 1.2 or newer and whose CSL period is non-zero:
//!
//! - after attaching, a Child Update Request carries the CSL Channel and CSL
//!   Synchronized Timeout TLVs; the parent starts transmitting into the
//!   child's sample windows from the CSL IE of the frames it receives and
//!   answers with its CSL Clock Accuracy TLV, which sizes the receive window;
//! - the data poll period shrinks to the CSL timeout so that a poll with a
//!   CSL IE resynchronizes the parent before it gives up on the child;
//! - parent selection prefers the parent with the smaller CSL metric (the
//!   energy the child spends listening on its clock errors).

use opentrust_core::time::{Duration, Instant};
use opentrust_core::types::Rloc16;

use crate::consts::THREAD_VERSION_1_2;
use crate::env::{MleEnv, Role};
use crate::mle::Mle;
use crate::tlv::{ChannelValue, CslClockAccuracy};

/// Default CSL synchronized timeout in seconds (OT
/// `OPENTHREAD_CONFIG_CSL_TIMEOUT`).
pub const DEFAULT_CSL_TIMEOUT_SECS: u32 = 100;

/// Shortest period in the CSL metric (OT `kMinCslPeriod` times
/// `kUsPerTenSymbols`), microseconds.
const METRIC_PERIOD_US: u64 = 10 * 160;

/// Energy proxy of a parent with CSL accuracy `acc` for a child with CSL
/// timeout `timeout_secs`: the summed "on quanta" over the timeout (OT
/// `Mle::CalcParentCslMetric`). Smaller is better.
pub fn csl_parent_metric(timeout_secs: u32, acc: &CslClockAccuracy) -> u64 {
    let k = u64::from(timeout_secs) * 1_000_000 / METRIC_PERIOD_US;
    k * (k + 1) * METRIC_PERIOD_US / 1_000_000 * u64::from(acc.accuracy_ppm)
        + u64::from(acc.uncertainty_us()) * k
}

/// CSL parameters applied to the MAC (change detection).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CslApplied {
    period: u16,
    channel: u8,
    parent: Rloc16,
    accuracy: CslClockAccuracy,
}

impl<const C: usize> Mle<C> {
    /// CSL period in units of 10 symbols (0 = CSL off).
    pub fn csl_period(&self) -> u16 {
        self.cfg.csl_period
    }

    /// CSL channel (0 = the PAN channel).
    pub fn csl_channel(&self) -> u8 {
        self.cfg.csl_channel
    }

    /// CSL synchronized timeout in seconds (0 = use the child timeout).
    pub fn csl_timeout(&self) -> u32 {
        self.cfg.csl_timeout_secs
    }

    /// The CSL timeout actually advertised (OT `AppendCslTimeoutTlv`).
    pub(crate) fn effective_csl_timeout(&self) -> u32 {
        if self.cfg.csl_timeout_secs == 0 {
            self.cfg.timeout_secs
        } else {
            self.cfg.csl_timeout_secs
        }
    }

    /// `true` while this device operates as a synchronized sleepy child:
    /// CSL period set, receiver off, a child of a Thread 1.2+ parent
    /// (OT `Mac::IsCslEnabled`).
    pub fn is_csl_enabled(&self) -> bool {
        self.cfg.csl_period != 0
            && self.role == Role::Child
            && !self.is_rx_on_when_idle()
            && self
                .parent
                .as_ref()
                .is_some_and(|p| p.router.neighbor.version >= THREAD_VERSION_1_2)
    }

    /// The CSL accuracy of the parent, if attached.
    pub fn parent_csl_accuracy(&self) -> Option<CslClockAccuracy> {
        self.parent.as_ref().map(|p| p.csl_accuracy)
    }

    /// Set the CSL period (units of 10 symbols, 0 turns CSL off). The
    /// parent is told with a Child Update Request.
    pub fn set_csl_period<E: MleEnv>(&mut self, env: &mut E, now: Instant, period: u16) {
        if period != self.cfg.csl_period {
            self.cfg.csl_period = period;
            self.sync_csl(env, now, true);
        }
    }

    /// Set the CSL channel (0 = the PAN channel).
    pub fn set_csl_channel<E: MleEnv>(&mut self, env: &mut E, now: Instant, channel: u8) {
        if channel != self.cfg.csl_channel {
            self.cfg.csl_channel = channel;
            self.sync_csl(env, now, true);
        }
    }

    /// Set the CSL synchronized timeout in seconds (OT `SetCslTimeout`).
    pub fn set_csl_timeout<E: MleEnv>(&mut self, env: &mut E, now: Instant, secs: u32) {
        if secs != self.cfg.csl_timeout_secs {
            self.cfg.csl_timeout_secs = secs;
            self.recalculate_poll_period(env);
            if self.is_csl_enabled() {
                self.schedule_csl_child_update(now);
            }
        }
    }

    /// The result of a data poll to the parent (OT
    /// `MeshForwarder::UpdateNeighborOnSentFrame`): an acknowledged poll
    /// clears the parent's link failure count, a poll without ACK counts one
    /// (other errors count none), and after
    /// [`FAILED_ROUTER_TRANSMISSIONS`](crate::consts::FAILED_ROUTER_TRANSMISSIONS)
    /// ([`FAILED_CSL_DATA_POLL_TRANSMISSIONS`](crate::consts::FAILED_CSL_DATA_POLL_TRANSMISSIONS)
    /// with CSL) in a row the child gives up its parent and attaches anew.
    pub fn parent_poll_result<E: MleEnv>(
        &mut self,
        env: &mut E,
        now: Instant,
        acked: Option<bool>,
    ) {
        if self.role != Role::Child {
            return;
        }
        let limit = if self.cfg.csl_period != 0 {
            crate::consts::FAILED_CSL_DATA_POLL_TRANSMISSIONS
        } else {
            crate::consts::FAILED_ROUTER_TRANSMISSIONS
        };
        let Some(p) = self.parent.as_mut() else {
            return;
        };
        let n = &mut p.router.neighbor;
        match acked {
            Some(true) => n.link_failures = 0,
            Some(false) => {
                n.link_failures = n.link_failures.saturating_add(1);
                if n.link_failures >= limit {
                    self.become_detached(env, now);
                }
            }
            None => {}
        }
    }

    pub(crate) fn schedule_csl_child_update(&mut self, now: Instant) {
        if self.child.update_deadline.is_none() {
            self.child.update_deadline =
                Some(now.saturating_add(crate::consts::CHILD_UPDATE_REQUEST_DELAY));
        }
    }

    /// Push the CSL parameters to the MAC when they changed, and tell the
    /// parent (`announce`) (OT `Mac::UpdateCslState` / `UpdateCslParameters`).
    /// Without CSL (or out of the child role) the MAC's CSL is turned off.
    pub(crate) fn sync_csl<E: MleEnv>(&mut self, env: &mut E, now: Instant, announce: bool) {
        let want = if self.is_csl_enabled() {
            self.parent.as_ref().map(|p| CslApplied {
                period: self.cfg.csl_period,
                channel: self.cfg.csl_channel,
                parent: p.router.neighbor.rloc16,
                accuracy: p.csl_accuracy,
            })
        } else {
            None
        };
        if want == self.csl_applied {
            return;
        }
        let was_on = self.csl_applied.is_some();
        self.csl_applied = want;
        match (want, self.parent.as_ref()) {
            (Some(w), Some(p)) => {
                env.set_csl_parent_accuracy(w.accuracy);
                env.set_csl(
                    w.period,
                    w.channel,
                    Some((p.router.neighbor.ext_address, w.parent)),
                );
                self.recalculate_poll_period(env);
                if announce {
                    self.schedule_csl_child_update(now);
                }
            }
            _ => {
                env.set_csl(0, 0, None);
                if was_on {
                    self.recalculate_poll_period(env);
                    // Back to plain polling: the parent learns it from the
                    // next Child Update Request (which then lacks the TLVs),
                    // or when it finds no CSL IE in the child's frames.
                    // OpenThread sends no Child Update Request for it (and
                    // so does not start polling at once).
                }
            }
        }
    }

    /// The parent reported its CSL accuracy (Child Update Response).
    pub(crate) fn set_parent_csl_accuracy<E: MleEnv>(
        &mut self,
        env: &mut E,
        now: Instant,
        acc: CslClockAccuracy,
    ) {
        if let Some(p) = self.parent.as_mut() {
            p.csl_accuracy = acc;
        }
        self.sync_csl(env, now, false);
    }

    /// CSL Channel TLV value (0 = unspecified).
    pub(crate) fn csl_channel_tlv(&self) -> ChannelValue {
        ChannelValue {
            page: 0,
            channel: u16::from(self.cfg.csl_channel),
        }
    }

    /// Wait for a Child Update Response in CSL operation: the response can
    /// only be sent in the next sample window (OT
    /// `ScheduleMessageTransmissionTimer`).
    pub(crate) fn csl_response_wait(&self) -> Option<Duration> {
        self.is_csl_enabled().then(|| {
            // CSL period in 160 microsecond units, rounded to milliseconds.
            let us = u64::from(self.cfg.csl_period) * 160;
            Duration::from_millis(us.div_ceil(1000))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metric_prefers_accurate_parent() {
        let good = CslClockAccuracy {
            accuracy_ppm: 20,
            uncertainty_10us: 5,
        };
        let bad = CslClockAccuracy {
            accuracy_ppm: 100,
            uncertainty_10us: 40,
        };
        assert!(csl_parent_metric(100, &good) < csl_parent_metric(100, &bad));
        assert!(csl_parent_metric(100, &good) > csl_parent_metric(10, &good));
        assert!(csl_parent_metric(8 * 3600, &CslClockAccuracy::WORST) > 0);
    }
}
