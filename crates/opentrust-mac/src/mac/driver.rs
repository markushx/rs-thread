//! Async driver running the sans-IO [`Mac`] over a [`Radio`], a [`Clock`]
//! and an [`Alarm`]. Executor-agnostic: it only awaits the radio, the alarm
//! and a caller-supplied wake future, combined with `embassy_futures::select`.

use core::convert::Infallible;
use core::future::{Future, pending};
use core::pin::pin;

use embassy_futures::select::{Either, Either3, select, select3};
use opentrust_core::time::Instant;
use opentrust_platform::radio::{RSSI_INVALID, RadioError, sim::MAX_PSDU_LEN};
use opentrust_platform::{Alarm, Clock, Radio};
use rand_core::Rng;

use super::consts::*;
use super::machine::Mac;
use super::types::{Event, RadioAction, TxOutcome};
use crate::frame_security::FrameSecurity;

/// What ended a [`MacDriver::run_until`] call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RunResult<T> {
    /// The MAC produced an event for the upper layer.
    Event(Event),
    /// The wake future completed (e.g. an upper-layer request arrived).
    Woken(T),
}

/// Drives a [`Mac`] with a real (or simulated) radio.
///
/// See the [module docs](super#async-driver) for the loop and the
/// cancellation rules.
pub struct MacDriver<
    R,
    C,
    A,
    S,
    G,
    const TXQ: usize = TX_QUEUE_LEN,
    const IND: usize = INDIRECT_QUEUE_LEN,
    const EVQ: usize = EVENT_QUEUE_LEN,
    const POLLQ: usize = POLL_REQUEST_QUEUE_LEN,
    const NBQ: usize = NEIGHBOR_MAP_LEN,
> {
    radio: R,
    clock: C,
    alarm: A,
    mac: Mac<S, G, TXQ, IND, EVQ, POLLQ, NBQ>,
    rx_buf: [u8; MAX_PSDU_LEN],
    ack_buf: [u8; MAX_PSDU_LEN],
    /// A transmit / energy scan was started but its future dropped.
    interrupted: bool,
}

impl<
    R,
    C,
    A,
    S,
    G,
    const TXQ: usize,
    const IND: usize,
    const EVQ: usize,
    const POLLQ: usize,
    const NBQ: usize,
> core::fmt::Debug for MacDriver<R, C, A, S, G, TXQ, IND, EVQ, POLLQ, NBQ>
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MacDriver")
            .field("mac", &self.mac)
            .finish_non_exhaustive()
    }
}

async fn wait_deadline<A: Alarm>(alarm: &mut A, deadline: Option<Instant>) {
    match deadline {
        Some(t) => alarm.wait_until(t).await,
        None => pending().await,
    }
}

impl<
    R,
    C,
    A,
    S,
    G,
    const TXQ: usize,
    const IND: usize,
    const EVQ: usize,
    const POLLQ: usize,
    const NBQ: usize,
> MacDriver<R, C, A, S, G, TXQ, IND, EVQ, POLLQ, NBQ>
where
    R: Radio,
    C: Clock,
    A: Alarm,
    S: FrameSecurity,
    G: Rng,
{
    /// Wrap an initialized radio (its [`Radio::init`] caps must be the ones
    /// `mac` was created with; see [`MacDriver::init`]).
    pub fn new(radio: R, clock: C, alarm: A, mac: Mac<S, G, TXQ, IND, EVQ, POLLQ, NBQ>) -> Self {
        Self {
            radio,
            clock,
            alarm,
            mac,
            rx_buf: [0; MAX_PSDU_LEN],
            ack_buf: [0; MAX_PSDU_LEN],
            interrupted: false,
        }
    }

    /// The MAC core, for configuration and upper-layer requests.
    pub fn mac(&mut self) -> &mut Mac<S, G, TXQ, IND, EVQ, POLLQ, NBQ> {
        &mut self.mac
    }

    /// The radio (e.g. for test injection while the driver is not running).
    pub fn radio(&mut self) -> &mut R {
        &mut self.radio
    }

    /// The clock.
    pub fn clock(&self) -> &C {
        &self.clock
    }

    /// Wait for the next MAC event (radio work is done meanwhile).
    pub async fn next_event(&mut self) -> Event {
        match self.run_until(pending::<Infallible>()).await {
            RunResult::Event(e) => e,
            RunResult::Woken(never) => match never {},
        }
    }

    /// Run the MAC until it has an event for the upper layer or `wake`
    /// completes.
    ///
    /// `wake` is only polled while the MAC waits idle (for a frame or a
    /// timer), never during a transmission or an energy scan, so submitting
    /// a request never aborts radio work. It must be cancellation-safe (it is
    /// dropped when an event is returned), e.g. `channel.receive()`.
    pub async fn run_until<F: Future>(&mut self, wake: F) -> RunResult<F::Output> {
        let mut wake = pin!(wake);
        if self.interrupted {
            // The previous call was dropped mid-transmit / mid-scan: the
            // radio aborted it (contract C5); tell the MAC.
            self.interrupted = false;
            self.mac.abort_in_flight(self.clock.now());
        }
        loop {
            while let Some(action) = self.mac.poll_action(self.clock.now()) {
                self.execute(action).await;
            }
            if let Some(ev) = self.mac.poll_event() {
                return RunResult::Event(ev);
            }
            let deadline = self.mac.next_deadline();
            let r = select3(
                self.radio.receive(&mut self.rx_buf),
                wait_deadline(&mut self.alarm, deadline),
                wake.as_mut(),
            )
            .await;
            match r {
                Either3::First(Ok(info)) => {
                    let len = info.len.min(MAX_PSDU_LEN);
                    let now = self.clock.now();
                    self.mac.on_rx(&self.rx_buf[..len], &info, now);
                }
                Either3::First(Err(e)) => {
                    opentrust_core::debug!("mac: receive error {:?}", e.kind());
                }
                Either3::Second(()) => {} // timers run in the next poll_action
                Either3::Third(out) => return RunResult::Woken(out),
            }
        }
    }

    async fn execute(&mut self, action: RadioAction) {
        let res = match action {
            RadioAction::Configure(cfg) => self.radio.set_config(&cfg).await,
            RadioAction::SetSrcMatch(cfg) => self.radio.set_src_match_config(&cfg).await,
            #[cfg(feature = "csl")]
            RadioAction::SetCsl(csl) => self.radio.set_csl(&csl).await,
            #[cfg(feature = "csl")]
            RadioAction::ReceiveAt {
                channel,
                start_us,
                duration_us,
            } => {
                self.radio
                    .set_receive_at(channel, start_us, duration_us)
                    .await
            }
            RadioAction::SetMacKeys(keys) => self.radio.set_mac_keys(keys.as_ref()).await,
            RadioAction::SetMacFrameCounter {
                frame_counter,
                if_larger,
            } => {
                self.radio
                    .set_mac_frame_counter(frame_counter, if_larger)
                    .await
            }
            RadioAction::Receive { channel } => self.radio.set_receive(channel).await,
            RadioAction::Sleep => self.radio.set_sleep().await,
            RadioAction::EnergyScan {
                channel,
                duration_ms,
            } => {
                self.interrupted = true;
                let r = self.radio.energy_scan(channel, duration_ms).await;
                self.interrupted = false;
                let now = self.clock.now();
                self.mac.on_energy_scan_done(r.unwrap_or(RSSI_INVALID), now);
                Ok(())
            }
            RadioAction::Transmit(mut tx) => {
                self.interrupted = true;
                let ack_buf = if tx.wait_ack {
                    Some(&mut self.ack_buf[..])
                } else {
                    None
                };
                let fut = self.radio.transmit(
                    &mut tx.psdu,
                    &mut tx.info,
                    tx.channel,
                    tx.power,
                    tx.cca_threshold,
                    ack_buf,
                );
                let r = match tx.abort_at {
                    // Contract C5: dropping the transmit future aborts it.
                    Some(at) => match select(fut, self.alarm.wait_until(at)).await {
                        Either::First(r) => Some(r),
                        Either::Second(()) => None,
                    },
                    None => Some(fut.await),
                };
                self.interrupted = false;
                let now = self.clock.now();
                if r.is_some() {
                    self.mac.on_tx_frame_updated(&tx.psdu, &tx.info);
                }
                match r {
                    None => self.mac.on_tx_done(TxOutcome::AckTimeout, now),
                    Some(Ok(None)) => self.mac.on_tx_done(TxOutcome::Sent, now),
                    Some(Ok(Some(info))) => {
                        let len = info.len.min(MAX_PSDU_LEN);
                        self.mac.on_tx_done(
                            TxOutcome::Acked {
                                ack: &self.ack_buf[..len],
                                info,
                            },
                            now,
                        );
                    }
                    Some(Err(e)) => self.mac.on_tx_done(TxOutcome::Failed(e.kind()), now),
                }
                Ok(())
            }
        };
        if let Err(e) = res {
            opentrust_core::warn!("mac: radio command failed: {:?}", e.kind());
        }
    }
}

impl<R, C, A, S, G> MacDriver<R, C, A, S, G>
where
    R: Radio,
    C: Clock,
    A: Alarm,
    S: FrameSecurity,
    G: Rng,
{
    /// Initialize the radio and create the MAC (default queue capacities)
    /// from its capabilities. For other capacities call [`Radio::init`]
    /// yourself, build the MAC with [`Mac::with_capacities`] and use
    /// [`MacDriver::new`].
    pub async fn init(
        mut radio: R,
        clock: C,
        alarm: A,
        ext: opentrust_core::types::ExtAddress,
        security: S,
        rng: G,
    ) -> Result<Self, R::Error> {
        let caps = radio.init().await?;
        let mac = Mac::new(caps, ext, security, rng);
        Ok(Self::new(radio, clock, alarm, mac))
    }
}
