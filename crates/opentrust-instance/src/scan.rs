//! Scans: the MLE discovery scan, the MAC active (beacon) scan and the
//! energy scan (OT `otThreadDiscover`, `otLinkActiveScan`,
//! `otLinkEnergyScan`).
//!
//! Each scan reports its results as [`Event`]s and ends with a `Done` event.
//! Only one scan of a kind runs at a time ([`Error::Busy`]); the MAC runs
//! one active / energy scan at a time, and a discovery scan cannot start
//! while the Joiner is running.

use opentrust_core::time::{Duration, Instant};
use opentrust_core::{Error, Result};
use opentrust_meshcop::discovery::{DiscoverScanner, ScanStep, build_request_tlv};
use opentrust_meshcop::joiner::JoinerState;
use opentrust_platform::SettingsStore;
use rand_core::{CryptoRng, Rng};

use crate::{Event, Instance, InstanceCrypto};

#[derive(Debug, Default)]
pub(crate) struct ScanState {
    pub(crate) disc: DiscoverScanner,
    /// The MAC channel to restore when the discovery scan ends.
    prev_channel: Option<u8>,
    /// Responders already reported in this scan.
    seen: heapless::Vec<(opentrust_core::types::ExtAddress, u8), 16>,
    /// What the MAC beacon was last computed for: (beacons enabled,
    /// payload enabled, joining permitted, native commissioner).
    beacon_for: Option<(bool, bool, bool, bool)>,
    /// Put the Thread beacon payload into beacons (off by default).
    pub(crate) beacon_payload: bool,
}

impl<S: SettingsStore, C: InstanceCrypto, R: Rng + CryptoRng> Instance<S, C, R> {
    /// Start an MLE discovery scan (OT `otThreadDiscover`): a Discovery
    /// Request on each channel of `channels` (bit `n` = channel `n`, `0` = all
    /// 2.4 GHz channels), 300 ms of listening each. Every answering network
    /// is an [`Event::DiscoverResult`], the end [`Event::DiscoverDone`].
    /// `pan_id` is the PAN ID to look for (`0xffff`: any); `joiner` sets the
    /// Joiner flag of the request (only networks that allow joining
    /// answer).
    ///
    /// The MAC listens on the scanned channel meanwhile and returns to its
    /// channel afterwards. [`Error::InvalidState`] without an enabled IPv6
    /// interface or while the Joiner runs, [`Error::Busy`] while a scan runs.
    pub fn discover_start(
        &mut self,
        channels: u32,
        pan_id: u16,
        joiner: bool,
        now: Instant,
    ) -> Result<()> {
        if !self.ip6_enabled || self.cm.joiner.state() != JoinerState::Idle {
            return Err(Error::InvalidState);
        }
        self.scan
            .disc
            .start(u32::MAX, channels, pan_id, joiner, None)?;
        self.scan.prev_channel = Some(self.core.mac.channel());
        self.core.scanning = true;
        self.core.scan_rx.clear();
        self.scan.seen.clear();
        self.poll(now);
        Ok(())
    }

    /// Whether a discovery scan is running.
    pub fn discover_is_active(&self) -> bool {
        self.scan.disc.is_scanning()
    }

    /// Start an active scan with MAC Beacon Requests (OT
    /// `otLinkActiveScan`): `duration` of listening on each channel of
    /// `channels` (`0` = all supported). Beacons are
    /// [`Event::ActiveScanResult`], the end [`Event::ActiveScanDone`].
    /// [`Error::Busy`] while the MAC scans.
    pub fn active_scan_start(
        &mut self,
        channels: u32,
        duration: Duration,
        now: Instant,
    ) -> Result<()> {
        self.core.mac.active_scan(channels, duration)?;
        self.poll(now);
        Ok(())
    }

    /// Start an energy scan (OT `otLinkEnergyScan`): the maximum RSSI of each
    /// channel of `channels` (`0` = all supported) over `duration`, as
    /// [`Event::EnergyScanResult`] per channel and [`Event::EnergyScanDone`].
    /// [`Error::NotImplemented`] if the radio cannot energy-scan,
    /// [`Error::Busy`] while the MAC scans.
    pub fn energy_scan_start(
        &mut self,
        channels: u32,
        duration: Duration,
        now: Instant,
    ) -> Result<()> {
        self.core.mac.energy_scan(channels, duration)?;
        self.poll(now);
        Ok(())
    }

    /// Put the Thread beacon payload (protocol ID, joining permitted,
    /// network name, extended PAN ID) into the beacons this device sends.
    /// Off by default: Thread 1.2.1 removed beacon payloads, and OpenThread
    /// sends them only with
    /// `OPENTHREAD_CONFIG_MAC_OUTGOING_BEACON_PAYLOAD_ENABLE`. Useful for
    /// Thread 1.1 Commissioners and Joiners that scan with Beacon Requests.
    pub fn set_beacon_payload_enabled(&mut self, enabled: bool) {
        self.scan.beacon_payload = enabled;
    }

    /// Answer MAC Beacon Requests while this device is attached and router
    /// eligible (OT `Mle::SetStateChild` / `SetStateRouterOrLeader` call
    /// `Mac::SetBeaconEnabled`). With the payload enabled,
    /// `joining_permitted` follows the Steering Data and `native` the
    /// Border Agent.
    fn update_beacon(&mut self, now: Instant) {
        #[cfg(feature = "ftd")]
        let router = self.mle.role().is_attached() && self.mle.is_router_eligible();
        #[cfg(not(feature = "ftd"))]
        let router = false;
        let with_payload = router && self.scan.beacon_payload;
        let joining = opentrust_meshcop::discovery::joining_allowed(
            self.core.netdata.view().commissioning_data(),
        );
        let native = self.core.border_agent_port.is_some();
        let key = (router, with_payload, joining, native);
        if self.scan.beacon_for == Some(key) {
            return;
        }
        self.scan.beacon_for = Some(key);
        self.core.mac.set_beacon_enabled(router);
        let payload = if with_payload {
            self.core
                .datasets
                .read(opentrust_meshcop::dataset::DatasetType::Active, now)
                .and_then(|d| {
                    let t = d.tlvs();
                    let name = t.network_name().ok()?;
                    let xpan = t.ext_pan_id().ok()?;
                    let mut n = [0u8; 16];
                    n[..name.as_bytes().len()].copy_from_slice(name.as_bytes());
                    Some(opentrust_mac::frame::ThreadBeaconPayload {
                        version: 2,
                        native,
                        joining_permitted: joining,
                        network_name: n,
                        ext_pan_id: xpan.0,
                    })
                })
        } else {
            None
        };
        self.core.mac.set_beacon_payload(payload);
    }

    #[inline(never)]
    pub(crate) fn service_scan(&mut self, now: Instant) -> bool {
        self.update_beacon(now);
        let mut busy = false;
        while let Some((info, tlvs)) = self.core.scan_rx.pop_front() {
            busy = true;
            if let Some(r) = self.scan.disc.handle_response(&info, &tlvs) {
                // One result per responder and channel: a radio that retries
                // an unacknowledged response would repeat it.
                let key = (r.ext_address, r.channel);
                if !self.scan.seen.contains(&key) {
                    let _ = self.scan.seen.push(key);
                    self.core.push_event(Event::DiscoverResult(r));
                }
            }
        }
        while let Some(step) = self.scan.disc.poll(now) {
            busy = true;
            match step {
                ScanStep::Request {
                    channel,
                    pan_id,
                    joiner,
                } => {
                    let mut tlv = [0u8; 16];
                    if let Ok(n) = build_request_tlv(joiner, &mut tlv) {
                        let _ = self.core.mac.set_channel(channel);
                        let _ = self.mle.send_discovery_request(
                            &mut self.core,
                            pan_id,
                            Some(channel),
                            &tlv[..n],
                        );
                    }
                }
                ScanStep::Done => {
                    if let Some(c) = self.scan.prev_channel.take() {
                        let _ = self.core.mac.set_channel(c);
                    }
                    self.core.scanning = false;
                    self.core.scan_rx.clear();
                    self.core.push_event(Event::DiscoverDone);
                }
            }
        }
        busy
    }
}
