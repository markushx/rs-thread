//! Data poll sender state of a sleepy child (OpenThread `DataPollSender`):
//! poll period selection (default / retransmission / fast polls), its timer
//! and the reaction to poll results and timeouts. The actual poll frame is
//! built and sent by [`Mac`](super::Mac).

use opentrust_core::time::{Duration, Instant};

use super::consts::{
    DEFAULT_FAST_POLLS, DEFAULT_POLL_PERIOD, FAST_POLL_PERIOD, MAX_FAST_POLLS,
    MAX_POLL_RETX_ATTEMPTS, MIN_POLL_PERIOD, QUICK_POLLS_AFTER_TIMEOUT, RETX_POLL_PERIOD,
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
        *self = Self {
            parent,
            secure,
            default_period,
            ..Self::default()
        };
    }

    pub fn set_default_period(&mut self, p: Duration, now: Instant) {
        self.default_period = p;
        if self.enabled {
            self.schedule(true, now);
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
        if self.retx_mode {
            p = p.min(RETX_POLL_PERIOD);
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
    pub fn handle_sent(&mut self, result: &TxResult, now: Instant) {
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
                if self.tx_failures < MAX_POLL_RETX_ATTEMPTS {
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
