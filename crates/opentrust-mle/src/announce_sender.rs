//! Periodic Announce from attached routers (OpenThread
//! `AnnounceSender`, `thread/announce_sender.cpp`).
//!
//! A leader, a router, and a router-eligible rx-on child run a Trickle
//! timer (`Imin` = `Imax` = 688 s, `k` = 8). Each time it fires, one
//! "cycle" sends an Announce on every channel of
//! [`MleEnv::announce_channel_mask`], starting with the current PAN channel
//! and `344 s / channels` apart (jittered by 500 ms), so that devices that
//! lost their parent (or are on an older dataset) hear the network. An
//! Announce with an equal Active Timestamp counts as a consistent
//! transmission and suppresses our own.

use core::convert::Infallible;

use opentrust_core::time::{Duration, Instant};
use opentrust_core::trickle::{Trickle, TrickleConfig, TrickleEvent, TrickleMode};

use crate::env::{MleEnv, Role};
use crate::mle::Mle;

/// `OPENTHREAD_CONFIG_ANNOUNCE_SENDER_INTERVAL`.
pub const ANNOUNCE_SENDER_INTERVAL: Duration = Duration::from_millis(688_000);
/// Time one cycle over all channels is spread over (`kTxInterval`).
pub const ANNOUNCE_SENDER_TX_INTERVAL_MS: u32 = 688_000 / 2 + 1;
/// `OPENTHREAD_CONFIG_ANNOUNCE_SENDER_JITTER_INTERVAL` in ms.
pub const ANNOUNCE_SENDER_JITTER_MS: u32 = 500;
/// `OPENTHREAD_CONFIG_ANNOUNCE_SENDER_REDUNDANCY_CONSTANT`.
pub const ANNOUNCE_SENDER_REDUNDANCY: u16 = 8;

const CHANNELS: u32 = 0x07ff_f800;

/// Adapter that lets the [`Trickle`] timer draw from the environment's
/// random source.
pub(crate) struct EnvRng<'a, E: MleEnv>(pub &'a mut E);

impl<E: MleEnv> rand_core::TryRng for EnvRng<'_, E> {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> core::result::Result<u32, Infallible> {
        let mut b = [0u8; 4];
        self.0.fill_random(&mut b);
        Ok(u32::from_le_bytes(b))
    }

    fn try_next_u64(&mut self) -> core::result::Result<u64, Infallible> {
        let mut b = [0u8; 8];
        self.0.fill_random(&mut b);
        Ok(u64::from_le_bytes(b))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> core::result::Result<(), Infallible> {
        self.0.fill_random(dst);
        Ok(())
    }
}

/// State of the periodic Announce sender.
#[derive(Debug)]
pub(crate) struct AnnounceSender {
    trickle: Trickle,
    /// Announce cycles still to send (OT `mCount`).
    count: u8,
    /// Next Announce of the running cycle.
    deadline: Option<Instant>,
    channel: u8,
    starting_channel: u8,
    mask: u32,
    period_ms: u32,
}

impl AnnounceSender {
    pub const fn new() -> Self {
        let trickle = match TrickleConfig::new(
            ANNOUNCE_SENDER_INTERVAL,
            ANNOUNCE_SENDER_INTERVAL,
            ANNOUNCE_SENDER_REDUNDANCY,
            TrickleMode::Trickle,
        ) {
            Ok(c) => Trickle::new(c),
            Err(_) => panic!("invalid AnnounceSender trickle configuration"),
        };
        Self {
            trickle,
            count: 0,
            deadline: None,
            channel: 0,
            starting_channel: 0,
            mask: 0,
            period_ms: 0,
        }
    }

    pub fn deadline(&self) -> Option<Instant> {
        [self.deadline, self.trickle.next_deadline()]
            .into_iter()
            .flatten()
            .min()
    }

    /// An Announce with an equal Active Timestamp was received (OT
    /// `UpdateOnReceivedAnnounce`).
    pub fn consistent(&mut self) {
        self.trickle.consistent();
    }

    fn stop(&mut self) {
        self.trickle.stop();
        self.count = 0;
        self.deadline = None;
    }

    fn next_channel(&self, from: u8) -> u8 {
        let after = from.saturating_add(1);
        (after..=26)
            .chain(11..=26)
            .find(|c| self.mask >> c & 1 == 1)
            .unwrap_or(after)
    }
}

impl<const C: usize> Mle<C> {
    /// OT `AnnounceSender::HandleRoleChanged`: whether the device announces
    /// periodically in its current role.
    fn announce_sender_wanted(&self) -> bool {
        match self.role {
            Role::Leader | Role::Router => true,
            #[cfg(feature = "ftd")]
            Role::Child => self.is_router_eligible() && self.is_rx_on_when_idle(),
            _ => false,
        }
    }

    /// Start or stop the sender after a role change.
    pub(crate) fn update_announce_sender<E: MleEnv>(&mut self, env: &mut E, now: Instant) {
        let wanted = self.announce_sender_wanted();
        let running = self.announce_sender.trickle.is_running();
        if wanted && !running {
            self.announce_sender.trickle.start(now, &mut EnvRng(env));
        } else if !wanted && running {
            self.announce_sender.stop();
        }
    }

    /// OT `AnnounceSenderBase::SendAnnounce(1)`: queue one cycle.
    fn announce_sender_cycle<E: MleEnv>(&mut self, env: &mut E, now: Instant) {
        if self.announce_sender.deadline.is_some() {
            self.announce_sender.count = self.announce_sender.count.saturating_add(1);
            return;
        }
        let mask = env.announce_channel_mask() & CHANNELS;
        if mask == 0 {
            return;
        }
        let own = env.pan_channel();
        let s = &mut self.announce_sender;
        s.mask = mask;
        s.period_ms = ANNOUNCE_SENDER_TX_INTERVAL_MS / mask.count_ones();
        s.starting_channel = if own < 32 && mask >> own & 1 == 1 {
            own
        } else {
            s.next_channel(10)
        };
        s.channel = s.starting_channel;
        s.count = 1;
        let j = Self::rand_range(env, 0, ANNOUNCE_SENDER_JITTER_MS + 1);
        self.announce_sender.deadline = Some(now.saturating_add(Duration::from_millis(j.into())));
    }

    /// OT `AnnounceSenderBase::HandleTimer`.
    pub(crate) fn poll_announce_sender<E: MleEnv>(&mut self, env: &mut E, now: Instant) {
        self.update_announce_sender(env, now);
        let mut fire = false;
        while let Some(TrickleEvent::Transmit) =
            self.announce_sender.trickle.poll(now, &mut EnvRng(env))
        {
            fire = true;
        }
        if fire {
            self.announce_sender_cycle(env, now);
        }
        if self.announce_sender.deadline.is_none_or(|d| now < d) {
            return;
        }
        let ch = self.announce_sender.channel;
        let _ = self.send_announce(env, ch, false, None);
        let s = &mut self.announce_sender;
        s.channel = s.next_channel(ch);
        if s.channel == s.starting_channel && s.count != 0 {
            s.count -= 1;
            if s.count == 0 {
                s.deadline = None;
                return;
            }
        }
        let p = s.period_ms;
        let j = ANNOUNCE_SENDER_JITTER_MS.min(p);
        let d = p - j + Self::rand_range(env, 0, 2 * j + 1);
        self.announce_sender.deadline = Some(now.saturating_add(Duration::from_millis(d.into())));
    }
}
