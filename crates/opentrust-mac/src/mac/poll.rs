//! Data poll sender state of a sleepy child (OpenThread `DataPollSender`):
//! poll period selection (default / retransmission / fast polls), its timer
//! and the reaction to poll results and timeouts. The actual poll frame is
//! built and sent by [`Mac`](super::Mac).

use opentrust_core::time::{Duration, Instant};

use super::consts::{
    ATTACH_POLL_PERIOD, DEFAULT_FAST_POLLS, DEFAULT_POLL_PERIOD, FAST_POLL_PERIOD, MAX_FAST_POLLS,
    MAX_FRAME_RETRIES_DIRECT, MAX_POLL_RETX_ATTEMPTS, MIN_POLL_PERIOD, QUICK_POLLS_AFTER_TIMEOUT,
    RETX_POLL_PERIOD,
};
use super::types::{TxError, TxResult};
use crate::frame::Address;

#[derive(Debug)]
pub(crate) struct PollSender {
    pub enabled: bool,
    /// Where polls go (the parent).
    pub parent: Address,
    /// Secure polls (EncMic32, key ID mode 1) as Thread requires.
    pub secure: bool,
    default_period: Duration,
    period: Duration,
    timer_start: Instant,
    deadline: Option<Instant>,
    retx_mode: bool,
    tx_failures: u8,
    timeouts: u8,
    fast_remaining: u8,
    /// Attach mode: poll at most every `ATTACH_POLL_PERIOD`.
    attach_mode: bool,
    /// CSL period (zero: CSL off), the retransmission period never exceeds it.
    csl_period: Duration,
    /// The parent supports the enhanced keep-alive (Thread 1.2 and later): a
    /// secured data frame acknowledged by it replaces the next poll.
    pub parent_enhanced_keep_alive: bool,
}

impl Default for PollSender {
    fn default() -> Self {
        Self {
            enabled: false,
            parent: Address::None,
            secure: true,
            default_period: DEFAULT_POLL_PERIOD,
            period: DEFAULT_POLL_PERIOD,
            timer_start: Instant::ZERO,
            deadline: None,
            retx_mode: false,
            tx_failures: 0,
            timeouts: 0,
            fast_remaining: 0,
            attach_mode: false,
            csl_period: Duration::ZERO,
            parent_enhanced_keep_alive: false,
        }
    }
}

impl PollSender {
    pub fn deadline(&self) -> Option<Instant> {
        self.deadline
    }

    pub fn period(&self) -> Duration {
        self.period
    }

    /// Consume the timer if it expired.
    pub fn take_expired(&mut self, now: Instant) -> bool {
        match self.deadline {
            Some(d) if d <= now => {
                self.deadline = None;
                true
            }
            _ => false,
        }
    }

    pub fn stop_timer(&mut self) {
        self.deadline = None;
    }

    pub fn start(&mut self, parent: Address, now: Instant) {
        self.parent = parent;
        if !self.enabled {
            self.enabled = true;
            self.schedule(true, now);
        }
    }

    pub fn stop(&mut self) {
        let (parent, secure, default_period) = (self.parent, self.secure, self.default_period);
        let csl_period = self.csl_period;
        *self = Self {
            parent,
            secure,
            default_period,
            csl_period,
            ..Self::default()
        };
    }

    pub fn set_default_period(&mut self, p: Duration, now: Instant) {
        self.default_period = p;
        if self.enabled {
            self.schedule(true, now);
        }
    }

    /// The CSL period in use (zero when CSL is off).
    pub fn set_csl_period(&mut self, p: Duration, now: Instant) {
        if self.csl_period != p {
            self.csl_period = p;
            if self.enabled {
                self.schedule(true, now);
            }
        }
    }

    /// Restart the poll timer: a frame with a CSL IE acknowledged by the
    /// parent did the keep-alive job (`DataPollSender::ResetKeepAliveTimer`).
    pub fn reset_keep_alive(&mut self, now: Instant) {
        if self.enabled && self.deadline.is_some() && !self.retx_mode && self.fast_remaining == 0 {
            self.timer_start = now;
            self.deadline = Some(now.saturating_add(self.period));
        }
    }

    /// OT `DataPollSender::ProcessTxDone` for a secured data frame that the
    /// parent acknowledged: the poll timeout count restarts and, unless the
    /// ACK announced pending data (the caller polls then), the keep-alive
    /// poll is postponed.
    pub fn handle_acked_data(&mut self, frame_pending: bool, now: Instant) {
        if !self.enabled || !self.parent_enhanced_keep_alive {
            return;
        }
        self.timeouts = 0;
        if !frame_pending {
            self.reset_keep_alive(now);
        }
    }

    /// OT `DataPollSender::SetAttachMode`.
    pub fn set_attach_mode(&mut self, on: bool, now: Instant) {
        if self.attach_mode != on {
            self.attach_mode = on;
            if self.enabled {
                self.schedule(true, now);
            }
        }
    }

    pub fn send_fast_polls(&mut self, n: u8, now: Instant) {
        let recalc = self.fast_remaining == 0;
        let n = if n == 0 { DEFAULT_FAST_POLLS } else { n }.min(MAX_FAST_POLLS);
        self.fast_remaining = self.fast_remaining.max(n);
        if self.enabled && recalc {
            self.schedule(true, now);
        }
    }

    fn calc_period(&self) -> Duration {
        let mut p = self.default_period;
        if self.attach_mode {
            p = p.min(ATTACH_POLL_PERIOD);
        }
        if self.retx_mode {
            p = p.min(RETX_POLL_PERIOD);
            if !self.csl_period.is_zero() {
                p = p.min(self.csl_period);
            }
        }
        if self.fast_remaining != 0 {
            p = p.min(FAST_POLL_PERIOD);
        }
        if p.is_zero() { MIN_POLL_PERIOD } else { p }
    }

    /// OpenThread `ScheduleNextPoll`.
    pub fn schedule(&mut self, recalc: bool, now: Instant) {
        let old = self.period;
        if recalc {
            self.period = self.calc_period();
        }
        if self.deadline.is_some() {
            if old != self.period {
                let at = self.timer_start.saturating_add(self.period);
                // Do not fire right away after switching to a shorter period.
                self.deadline = Some(if at < now.saturating_add(MIN_POLL_PERIOD) {
                    now.saturating_add(MIN_POLL_PERIOD)
                } else {
                    at
                });
            }
        } else {
            self.timer_start = now;
            self.deadline = Some(now.saturating_add(self.period));
        }
    }

    /// OpenThread `HandlePollSent`.
    pub fn handle_sent(&mut self, result: &TxResult, csl: bool, now: Instant) {
        // A poll with a CSL IE is sent once, so more failures are tolerated
        // (`kMaxCslPollRetxAttempts`).
        let max_attempts = if csl {
            MAX_FRAME_RETRIES_DIRECT
        } else {
            MAX_POLL_RETX_ATTEMPTS
        };
        if !self.enabled {
            return;
        }
        let mut recalc = false;
        match result {
            Ok(_) => {
                if self.fast_remaining != 0 {
                    self.fast_remaining -= 1;
                    recalc |= self.fast_remaining == 0;
                }
                if self.retx_mode {
                    self.retx_mode = false;
                    self.tx_failures = 0;
                    recalc = true;
                }
            }
            Err(TxError::ChannelAccessFailure | TxError::Abort) => {
                self.retx_mode = true;
                recalc = true;
            }
            Err(_) => {
                self.tx_failures += 1;
                if self.tx_failures < max_attempts {
                    if !self.retx_mode {
                        self.retx_mode = true;
                        recalc = true;
                    }
                } else {
                    self.retx_mode = false;
                    self.tx_failures = 0;
                    recalc = true;
                }
            }
        }
        if recalc {
            self.schedule(true, now);
        }
    }

    /// OpenThread `HandlePollTimeout`; `true` if another poll should be sent
    /// right away.
    pub fn handle_timeout(&mut self) -> bool {
        if !self.enabled {
            return false;
        }
        self.timeouts += 1;
        if self.timeouts < QUICK_POLLS_AFTER_TIMEOUT {
            true
        } else {
            self.timeouts = 0;
            false
        }
    }

    /// OpenThread `ProcessRxFrame`; `true` if the received frame announced
    /// more data and another poll should be sent right away.
    pub fn handle_rx(&mut self, frame_pending: bool) -> bool {
        if !self.enabled {
            return false;
        }
        self.timeouts = 0;
        frame_pending
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn acked_data_frame_postpones_the_keep_alive_poll() {
        let t = |s: u64| Instant::from_secs(s);
        let mut p = PollSender::default();
        p.start(Address::None, t(0));
        p.set_default_period(Duration::from_secs(26), t(0));
        let due = p.deadline().unwrap();
        // Parents before Thread 1.2 do not count data frames.
        p.handle_acked_data(false, t(10));
        assert_eq!(p.deadline(), Some(due));
        p.parent_enhanced_keep_alive = true;
        p.handle_acked_data(false, t(10));
        assert_eq!(p.deadline(), Some(t(10) + Duration::from_secs(26)));
        // Pending data: the caller polls, the timer stays.
        let d = p.deadline();
        p.handle_acked_data(true, t(12));
        assert_eq!(p.deadline(), d);
    }
}
