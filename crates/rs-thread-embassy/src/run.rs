//! The driver future.

use core::future::pending;

use embassy_futures::select::{Either, Either3, select, select3};
use embassy_sync::blocking_mutex::raw::RawMutex;
use rand_core::{CryptoRng, Rng};
use rs_thread_core::time::Instant;
use rs_thread_instance::{InstanceCrypto, RadioAction, TxOutcome};
use rs_thread_platform::radio::MAX_PSDU_LEN;
use rs_thread_platform::radio::{RSSI_INVALID, RadioError};
use rs_thread_platform::{Alarm, Clock, Radio, SettingsStore};

use crate::state::RsThread;

async fn wait_deadline<A: Alarm>(alarm: &mut A, deadline: Option<Instant>) {
    match deadline {
        Some(t) => alarm.wait_until(t).await,
        None => pending().await,
    }
}

impl<M, K, S, C, R> RsThread<'_, M, K, S, C, R>
where
    M: RawMutex,
    K: Clock,
    S: SettingsStore,
    C: InstanceCrypto,
    R: Rng + CryptoRng,
{
    /// Run the node over `radio` and `alarm`; never returns. Race it with
    /// the application.
    ///
    /// `radio` must have been initialized ([`Radio::init`]) and its
    /// capabilities given to the [`Config`](rs_thread_instance::Config) of
    /// the instance. `alarm` must run on the time base of the clock in the
    /// [`Resources`](crate::Resources).
    ///
    /// The instance is locked only for the short synchronous steps between
    /// radio operations. The future is drop-safe at every await point; if it
    /// is dropped during a transmission or an energy scan, the next `run`
    /// reports it to the MAC as aborted (the radio aborts on drop, see the
    /// radio contract). Radio configuration commands (channel, filters, keys)
    /// that were cut off by the drop are not repeated.
    ///
    /// Only one `run` may be active per node at a time.
    pub async fn run<Rd: Radio, A: Alarm>(&self, mut radio: Rd, mut alarm: A) -> ! {
        let mut rx_buf = [0u8; MAX_PSDU_LEN];
        let mut ack_buf = [0u8; MAX_PSDU_LEN];
        self.res.lock(|s| {
            if s.interrupted {
                s.interrupted = false;
                let now = self.res.clock().now();
                s.inst.abort_radio_in_flight(now);
            }
        });
        loop {
            let (action, deadline) = self.res.lock(|s| {
                let now = self.res.clock().now();
                s.inst.poll(now);
                let action = s.inst.poll_radio_action(now);
                s.drain();
                s.tx_waiters.wake();
                if s.req_deadline.is_some_and(|d| d <= now) {
                    // A request timed out: its waiters re-check and
                    // re-register their deadlines.
                    s.req_deadline = None;
                    s.req_waiters.wake();
                }
                let deadline = if action.is_none() {
                    [s.inst.next_deadline(), s.req_deadline]
                        .into_iter()
                        .flatten()
                        .min()
                } else {
                    None
                };
                (action, deadline)
            });
            if let Some(action) = action {
                self.execute(&mut radio, &mut alarm, &mut ack_buf, action)
                    .await;
                continue;
            }
            let r = select3(
                radio.receive(&mut rx_buf),
                wait_deadline(&mut alarm, deadline),
                self.res.kick().wait(),
            )
            .await;
            match r {
                Either3::First(Ok(info)) => {
                    let len = info.len.min(MAX_PSDU_LEN);
                    self.res.lock(|s| {
                        let now = self.res.clock().now();
                        s.inst.handle_radio_rx(&rx_buf[..len], &info, now);
                    });
                }
                Either3::First(Err(e)) => {
                    rs_thread_core::debug!("embassy: receive error {:?}", e.kind());
                }
                // Timers and new work are handled by the next poll.
                Either3::Second(()) | Either3::Third(()) => {}
            }
        }
    }

    async fn execute<Rd: Radio, A: Alarm>(
        &self,
        radio: &mut Rd,
        alarm: &mut A,
        ack_buf: &mut [u8; MAX_PSDU_LEN],
        action: RadioAction,
    ) {
        let res = match action {
            RadioAction::Configure(cfg) => radio.set_config(&cfg).await,
            RadioAction::SetSrcMatch(cfg) => radio.set_src_match_config(&cfg).await,
            #[cfg(feature = "csl")]
            RadioAction::SetCsl(csl) => radio.set_csl(&csl).await,
            #[cfg(feature = "csl")]
            RadioAction::ReceiveAt {
                channel,
                start_us,
                duration_us,
            } => radio.set_receive_at(channel, start_us, duration_us).await,
            RadioAction::SetMacKeys(keys) => radio.set_mac_keys(keys.as_ref()).await,
            RadioAction::SetMacFrameCounter {
                frame_counter,
                if_larger,
            } => radio.set_mac_frame_counter(frame_counter, if_larger).await,
            RadioAction::Receive { channel } => radio.set_receive(channel).await,
            RadioAction::Sleep => radio.set_sleep().await,
            RadioAction::EnergyScan {
                channel,
                duration_ms,
            } => {
                self.res.lock(|s| s.interrupted = true);
                let r = radio.energy_scan(channel, duration_ms).await;
                self.res.lock(|s| {
                    s.interrupted = false;
                    let now = self.res.clock().now();
                    s.inst
                        .handle_radio_energy_scan_done(r.unwrap_or(RSSI_INVALID), now);
                });
                Ok(())
            }
            RadioAction::Transmit(mut tx) => {
                self.res.lock(|s| s.interrupted = true);
                let ack = if tx.wait_ack {
                    Some(&mut ack_buf[..])
                } else {
                    None
                };
                let fut = radio.transmit(
                    &mut tx.psdu,
                    &mut tx.info,
                    tx.channel,
                    tx.power,
                    tx.cca_threshold,
                    ack,
                );
                let r = match tx.abort_at {
                    // Radio contract: dropping the transmit future aborts it.
                    Some(at) => match select(fut, alarm.wait_until(at)).await {
                        Either::First(r) => Some(r),
                        Either::Second(()) => None,
                    },
                    None => Some(fut.await),
                };
                self.res.lock(|s| {
                    s.interrupted = false;
                    let now = self.res.clock().now();
                    if r.is_some() {
                        s.inst.handle_radio_tx_updated(&tx.psdu, &tx.info);
                    }
                    match r {
                        None => s.inst.handle_radio_tx_done(TxOutcome::AckTimeout, now),
                        Some(Ok(None)) => s.inst.handle_radio_tx_done(TxOutcome::Sent, now),
                        Some(Ok(Some(info))) => {
                            let len = info.len.min(MAX_PSDU_LEN);
                            s.inst.handle_radio_tx_done(
                                TxOutcome::Acked {
                                    ack: &ack_buf[..len],
                                    info,
                                },
                                now,
                            );
                        }
                        Some(Err(e)) => s
                            .inst
                            .handle_radio_tx_done(TxOutcome::Failed(e.kind()), now),
                    }
                });
                Ok(())
            }
        };
        if let Err(e) = res {
            rs_thread_core::warn!("embassy: radio command failed: {:?}", e.kind());
        }
    }
}
