//! Scans: the MLE discovery scan, the MAC active (beacon) scan and the
//! energy scan (OT `otThreadDiscover`, `otLinkActiveScan`,
//! `otLinkEnergyScan`).
//!
//! Each scan reports its results as [`Event`]s and ends with a `Done` event.
//! Only one scan of a kind runs at a time ([`Error::Busy`]); the MAC runs
//! one active / energy scan at a time, and a discovery scan cannot start
//! while the Joiner is running.

use opentrust_core::time::{Duration, Instant};
#[cfg(feature = "scan-servers")]
use opentrust_core::types::Rloc16;
use opentrust_core::{Error, Result};
use opentrust_meshcop::discovery::{DiscoverScanner, ScanStep, build_request_tlv};
use opentrust_meshcop::joiner::JoinerState;
use opentrust_platform::SettingsStore;
use rand_core::{CryptoRng, Rng};

use crate::{Event, Instance, InstanceCrypto};

/// Listening time per channel of an active scan (OT default).
#[cfg(feature = "scan-servers")]
const ACTIVE_SCAN_DURATION: Duration = Duration::from_millis(300);

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
    /// The servers of the Commissioner's scan requests.
    #[cfg(feature = "scan-servers")]
    pub(crate) srv: ScanServers,
    /// The last Energy Report received as Commissioner.
    #[cfg(feature = "commissioner")]
    pub(crate) energy_report: Option<(
        u32,
        heapless::Vec<u8, { opentrust_meshcop::scan::MAX_ENERGY_RESULTS }>,
    )>,
}

/// Which request the MAC scan in progress belongs to.
#[cfg(feature = "scan-servers")]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ScanOwner {
    /// The application (events as [`Event`]s) or no scan.
    #[default]
    User,
    /// The Energy Scan server.
    Energy,
    /// The PAN ID Query server.
    PanId,
}

/// `/c/es`, `/c/pq` and `/c/ab` (OT `EnergyScanServer`, `PanIdQueryServer`,
/// `AnnounceBeginServer`).
#[cfg(feature = "scan-servers")]
#[derive(Debug, Default)]
pub(crate) struct ScanServers {
    pub(crate) energy: opentrust_meshcop::scan::EnergyScanServer,
    pub(crate) panid: opentrust_meshcop::scan::PanIdQueryServer,
    pub(crate) announce: opentrust_meshcop::scan::AnnounceBeginServer,
    pub(crate) owner: ScanOwner,
}

#[cfg(feature = "scan-servers")]
impl ScanServers {
    pub(crate) fn next_deadline(&self) -> Option<Instant> {
        [
            self.energy.next_deadline(),
            self.panid.next_deadline(),
            self.announce.next_deadline(),
        ]
        .into_iter()
        .flatten()
        .min()
    }
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

    /// A MAC energy scan result or its end. `true` if the Energy Scan
    /// server owns the scan (the result is not an [`Event`] then).
    #[cfg(feature = "scan-servers")]
    pub(crate) fn energy_result_to_server(&mut self, now: Instant, rssi: Option<i8>) -> bool {
        if self.scan.srv.owner != ScanOwner::Energy {
            return false;
        }
        if rssi.is_none() {
            self.scan.srv.owner = ScanOwner::User;
        }
        self.scan.srv.energy.scan_result(now, rssi);
        true
    }

    /// A MAC beacon of the active scan or its end (`None`). `true` if the
    /// PAN ID Query server owns the scan.
    #[cfg(feature = "scan-servers")]
    pub(crate) fn beacon_to_server(&mut self, now: Instant, beacon: Option<(u16, u8)>) -> bool {
        if self.scan.srv.owner != ScanOwner::PanId {
            return false;
        }
        if beacon.is_none() {
            self.scan.srv.owner = ScanOwner::User;
        }
        if self.scan.srv.panid.scan_result(beacon) {
            let mut buf = [0u8; 16];
            if let Ok((dst, n)) = self.scan.srv.panid.conflict(&mut buf) {
                let own = self.mle.rloc16();
                if own != Rloc16::INVALID {
                    let mlp = self.core.cfg.cur.mesh_local_prefix;
                    let _ = opentrust_meshcop::scan::send_pan_id_conflict(
                        &mut self.agent,
                        now,
                        &mut self.prng,
                        &mut self.sink,
                        &mlp,
                        own,
                        dst,
                        &buf[..n],
                    );
                }
            }
        }
        true
    }

    /// Run the three servers.
    #[cfg(feature = "scan-servers")]
    fn service_scan_servers(&mut self, now: Instant) -> bool {
        use opentrust_meshcop::scan::{EnergyAction, PanIdAction};
        let mut busy = false;
        match self.scan.srv.energy.poll(now) {
            Some(EnergyAction::Scan {
                channel,
                duration_ms,
            }) => {
                busy = true;
                let started = self.core.mac.energy_scan(
                    1u32 << channel,
                    Duration::from_millis(u64::from(duration_ms)),
                );
                if started.is_ok() {
                    self.scan.srv.owner = ScanOwner::Energy;
                } else {
                    self.scan.srv.energy.scan_failed(now);
                }
            }
            Some(EnergyAction::Report) => {
                busy = true;
                let mut buf = [0u8; 300];
                if let Ok((dst, n)) = self.scan.srv.energy.report(&mut buf) {
                    let own = self.mle.rloc16();
                    if own != Rloc16::INVALID {
                        let mlp = self.core.cfg.cur.mesh_local_prefix;
                        let _ = opentrust_meshcop::scan::send_energy_report(
                            &mut self.agent,
                            now,
                            &mut self.prng,
                            &mut self.sink,
                            &mlp,
                            own,
                            dst,
                            &buf[..n],
                        );
                    }
                }
            }
            None => {}
        }
        if let Some(PanIdAction::ActiveScan { channel_mask }) = self.scan.srv.panid.poll(now) {
            busy = true;
            if self
                .core
                .mac
                .active_scan(channel_mask, ACTIVE_SCAN_DURATION)
                .is_ok()
            {
                self.scan.srv.owner = ScanOwner::PanId;
            } else {
                self.scan.srv.panid.scan_failed(now);
            }
        }
        if let Some(channel) = self.scan.srv.announce.poll(now) {
            busy = true;
            let _ = self.mle.send_announce(&mut self.core, channel, false, None);
        }
        busy
    }

    #[inline(never)]
    pub(crate) fn service_scan(&mut self, now: Instant) -> bool {
        self.update_beacon(now);
        let mut busy = false;
        #[cfg(feature = "scan-servers")]
        {
            busy |= self.service_scan_servers(now);
        }
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
