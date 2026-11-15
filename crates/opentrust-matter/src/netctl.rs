//! The Thread backend of the Network Commissioning cluster (`NetCtl` and
//! `NetCtlStatus`).
//!
//! [`ThreadNetCtl`] is one object that implements `NetCtl`, `NetCtlStatus`,
//! `WirelessDiag` and (in [`crate::threaddiag`]) `ThreadDiag`; rs-matter
//! takes it by reference for each of them. The operational dataset store
//! (`Networks`: add / update / remove / reorder) stays with rs-matter; this
//! type only applies the dataset TLVs it is handed in `NetCtl::connect`.

use core::cell::Cell;

use embassy_futures::select::{Either, select};
use embassy_sync::blocking_mutex::raw::RawMutex;
use opentrust_embassy::OpenTrust;
use opentrust_instance::{Dataset, InstanceCrypto, Role};
use opentrust_platform::{Clock, SettingsStore};
use rand_core::{CryptoRng, Rng};
use rs_matter::dm::clusters::net_comm::{
    NetCtl, NetCtlError, NetCtlStatus, NetworkCommissioningStatusEnum, NetworkScanInfo,
    NetworkType, ThreadCapabilitiesBitmap, WirelessCreds,
};
use rs_matter::dm::clusters::wifi_diag::WirelessDiag;
use rs_matter::dm::networks::NetChangeNotif;
use rs_matter::error::{Error, ErrorCode};
use rs_matter::utils::timers::{Duration, Timer};

use crate::error::map_err;

/// How long `NetCtl::connect` waits for an attached role (rs-matter-embassy
/// uses the same 20 s).
pub const CONNECT_TIMEOUT_SECS: u8 = 20;
/// The advertised `ScanMaxTimeSeconds`: 16 channels of 300 ms plus margin.
pub const SCAN_MAX_TIME_SECS: u8 = 10;
/// The Thread version reported in `ThreadVersion` (Thread 1.4).
pub const THREAD_VERSION: u16 = 5;

pub(crate) const fn is_attached(role: Role) -> bool {
    matches!(role, Role::Child | Role::Router | Role::Leader)
}

/// The Thread network control of a node (`NetCtl`, `NetCtlStatus`,
/// `WirelessDiag`, `ThreadDiag`).
pub struct ThreadNetCtl<'a, M, K, S, C, R>
where
    M: RawMutex,
    C: InstanceCrypto,
{
    pub(crate) ot: OpenTrust<'a, M, K, S, C, R>,
    connect_timeout_secs: u8,
    status: Cell<Option<NetworkCommissioningStatusEnum>>,
    error_value: Cell<Option<i32>>,
    network_id: Cell<Option<[u8; 8]>>,
}

impl<M: RawMutex, K, S, C: InstanceCrypto, R> core::fmt::Debug for ThreadNetCtl<'_, M, K, S, C, R> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ThreadNetCtl").finish_non_exhaustive()
    }
}

impl<'a, M, K, S, C, R> ThreadNetCtl<'a, M, K, S, C, R>
where
    M: RawMutex,
    K: Clock,
    S: SettingsStore,
    C: InstanceCrypto,
    R: Rng + CryptoRng,
{
    /// The control of the node behind `ot`.
    pub const fn new(ot: OpenTrust<'a, M, K, S, C, R>) -> Self {
        Self {
            ot,
            connect_timeout_secs: CONNECT_TIMEOUT_SECS,
            status: Cell::new(None),
            error_value: Cell::new(None),
            network_id: Cell::new(None),
        }
    }

    /// Change the time `connect` waits for an attached role.
    pub const fn with_connect_timeout(mut self, secs: u8) -> Self {
        self.connect_timeout_secs = secs;
        self
    }

    fn done(&self, status: NetworkCommissioningStatusEnum) {
        self.status.set(Some(status));
        self.error_value.set(None);
    }

    /// Wait for the node to attach to an existing partition: as a child or
    /// router. A leader after a failed attach is the node forming a partition
    /// of its own, which is not the network the commissioner asked for.
    async fn wait_joined(&self) {
        loop {
            let g = self.ot.generation();
            if matches!(self.ot.role(), Role::Child | Role::Router) {
                return;
            }
            self.ot.wait_changed_after(g).await;
        }
    }
}

impl<M, K, S, C, R> NetCtl for ThreadNetCtl<'_, M, K, S, C, R>
where
    M: RawMutex,
    K: Clock,
    S: SettingsStore,
    C: InstanceCrypto,
    R: Rng + CryptoRng,
{
    fn net_type(&self) -> NetworkType {
        NetworkType::Thread
    }

    fn connect_max_time_seconds(&self) -> u8 {
        self.connect_timeout_secs.saturating_add(5)
    }

    fn scan_max_time_seconds(&self) -> u8 {
        SCAN_MAX_TIME_SECS
    }

    fn supported_thread_features(&self) -> ThreadCapabilitiesBitmap {
        let f = ThreadCapabilitiesBitmap::IS_SLEEPY_END_DEVICE_CAPABLE;
        #[cfg(feature = "ftd")]
        let f = f
            | ThreadCapabilitiesBitmap::IS_ROUTER_CAPABLE
            | ThreadCapabilitiesBitmap::IS_FULL_THREAD_DEVICE;
        f
    }

    fn thread_version(&self) -> u16 {
        THREAD_VERSION
    }

    fn set_enabled(&self, enabled: bool) -> Result<(), Error> {
        if !enabled {
            self.ot.thread_stop();
        }
        // Thread is started by `connect`; nothing to bring up earlier.
        Ok(())
    }

    async fn scan<F>(&self, network: Option<&[u8]>, mut f: F) -> Result<(), NetCtlError>
    where
        F: FnMut(&NetworkScanInfo<'_>) -> Result<(), Error>,
    {
        let mut first_err: Option<Error> = None;
        let mut found = false;
        // The discovery scan needs the IPv6 interface up.
        self.ot.with(|i, _| i.ip6_set_enabled(true));
        let r = self
            .ot
            .scan(0, |r| {
                let Some(r) = r else { return };
                if first_err.is_some() {
                    return;
                }
                let name = r.network_name.as_ref().map_or("", |n| n.as_str());
                let epid = r.ext_pan_id.map_or([0; 8], |x| x.0);
                if let Some(filter) = network {
                    // The filter is an Extended PAN ID (8 bytes) or a name.
                    let hit = if filter.len() == 8 {
                        filter == epid
                    } else {
                        filter == name.as_bytes()
                    };
                    if !hit {
                        return;
                    }
                }
                found = true;
                if let Err(e) = f(&NetworkScanInfo::Thread {
                    pan_id: r.pan_id,
                    ext_pan_id: u64::from_be_bytes(epid),
                    network_name: name,
                    channel: u16::from(r.channel),
                    version: r.version,
                    ext_addr: &r.ext_address.0,
                    rssi: r.rssi,
                    lqi: r.lqi,
                }) {
                    first_err = Some(e);
                }
            })
            .await;
        if let Some(e) = first_err {
            self.done(NetworkCommissioningStatusEnum::UnknownError);
            return Err(NetCtlError::Other(e));
        }
        match r {
            Err(e) => {
                self.done(NetworkCommissioningStatusEnum::UnknownError);
                Err(NetCtlError::Other(map_err(e)))
            }
            Ok(()) if network.is_some() && !found => {
                self.done(NetworkCommissioningStatusEnum::NetworkNotFound);
                Err(NetCtlError::NetworkNotFound)
            }
            Ok(()) => {
                self.done(NetworkCommissioningStatusEnum::Success);
                Ok(())
            }
        }
    }

    async fn connect(&self, creds: &WirelessCreds<'_>) -> Result<(), NetCtlError> {
        let WirelessCreds::Thread { dataset_tlv } = creds else {
            return Err(NetCtlError::Other(ErrorCode::InvalidAction.into()));
        };
        let ds = Dataset::from_tlvs(dataset_tlv).map_err(|e| {
            self.done(NetworkCommissioningStatusEnum::OutOfRange);
            NetCtlError::Other(map_err(e))
        })?;
        let epid = ds
            .tlvs()
            .ext_pan_id()
            .map_err(|e| NetCtlError::Other(map_err(e)))?
            .0;
        self.network_id.set(Some(epid));

        // The node already runs this network's dataset (restored at boot,
        // attached or still re-attaching): do not restart it, a restart
        // would throw away the restore of the stored role and parent and
        // fall back to a fresh attach.
        let same = self
            .ot
            .with(|i, now| i.active_dataset(now))
            .is_some_and(|d| d.is_subset_of(&ds) && ds.is_subset_of(&d));
        if same && is_attached(self.ot.role()) {
            self.done(NetworkCommissioningStatusEnum::Success);
            return Ok(());
        }
        let running = same && self.ot.role() != Role::Disabled;
        if !running {
            self.ot.thread_stop();
            if let Err(e) = self
                .ot
                .set_active_dataset(&ds)
                .and_then(|()| self.ot.thread_start())
            {
                self.done(NetworkCommissioningStatusEnum::UnknownError);
                return Err(NetCtlError::Other(map_err(e)));
            }
        }
        let timeout = Timer::after(Duration::from_secs(u64::from(self.connect_timeout_secs)));
        match select(self.wait_joined(), timeout).await {
            Either::First(()) => {
                self.done(NetworkCommissioningStatusEnum::Success);
                Ok(())
            }
            Either::Second(_) => {
                // A node that already ran this dataset keeps going: a
                // restored router needs up to half a minute of Link
                // Requests before it even starts a full attach (the stored
                // parent may be gone, or the border router renewed its
                // mesh-local prefix and PSKc), and a restart here would
                // begin that restore anew every time. A start made by this
                // call gives the radio back; a later `connect` starts again.
                if !running {
                    self.ot.thread_stop();
                }
                self.done(NetworkCommissioningStatusEnum::OtherConnectionFailure);
                Err(NetCtlError::OtherConnectionFailure)
            }
        }
    }
}

impl<M, K, S, C, R> NetCtlStatus for ThreadNetCtl<'_, M, K, S, C, R>
where
    M: RawMutex,
    C: InstanceCrypto,
{
    fn last_networking_status(&self) -> Result<Option<NetworkCommissioningStatusEnum>, Error> {
        Ok(self.status.get())
    }

    fn last_network_id<F, T>(&self, f: F) -> Result<T, Error>
    where
        F: FnOnce(Option<&[u8]>) -> Result<T, Error>,
    {
        let id = self.network_id.get();
        f(id.as_ref().map(|i| i.as_slice()))
    }

    fn last_connect_error_value(&self) -> Result<Option<i32>, Error> {
        Ok(self.error_value.get())
    }
}

impl<M, K, S, C, R> WirelessDiag for ThreadNetCtl<'_, M, K, S, C, R>
where
    M: RawMutex,
    K: Clock,
    S: SettingsStore,
    C: InstanceCrypto,
    R: Rng + CryptoRng,
{
    fn connected(&self) -> Result<bool, Error> {
        Ok(is_attached(self.ot.role()))
    }
}

impl<M, K, S, C, R> NetChangeNotif for ThreadNetCtl<'_, M, K, S, C, R>
where
    M: RawMutex,
    K: Clock,
    S: SettingsStore,
    C: InstanceCrypto,
    R: Rng + CryptoRng,
{
    async fn wait_changed(&self) {
        self.ot.wait_changed().await;
    }
}
