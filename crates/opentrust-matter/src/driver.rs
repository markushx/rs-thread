//! The Thread driver of rs-matter-stack: [`ThreadRunner`].
//!
//! `ThreadRunner` owns the radio, the alarm and the Matter side adapters of
//! one node and implements `rs_matter::stack::wireless::ThreadDriver` (and,
//! with a BLE peripheral next to it, `ThreadCoexDriver`, see below). Its
//! `run(task)`:
//!
//! 1. loads the persisted Thread settings into the instance, once
//!    ([`ThreadPersist::load`]), so that `NetCtl::connect` restores the
//!    attachment (RLOC16, parent, children, frame counters) instead of
//!    attaching afresh;
//! 2. races, in one `select`, the node ([`OpenTrust::run`]), the persistence
//!    loop ([`ThreadPersist::run`]), the ICD follower (if an
//!    [`Icd`] was given with [`with_icd`](ThreadRunner::with_icd)) and the
//!    task, which gets the network stack, the interface, the network control
//!    and the mDNS adapter of this crate;
//! 3. when the task ends, writes pending settings once more and returns the
//!    result of the task.
//!
//! The runner is drop-safe: dropping the `run` future at any await point
//! stops the node as `OpenTrust::run` does and loses at most the settings
//! that were still waiting for their debounce, which the next `run` writes.
//! Run it again on the same `ThreadRunner` (same
//! [`Resources`](opentrust_embassy::Resources)) after a drop or a task
//! failure: the radio and alarm are borrowed, not consumed, the settings are
//! not loaded again over the live ones, and the sockets of the previous run
//! belong to the task, which closes them by dropping them.
//!
//! # Coexistence driver
//!
//! `ThreadCoexDriver` (Thread next to BLE commissioning) is implemented for
//! [`ThreadCoexRunner`], which wraps a `ThreadRunner` and a
//! [`GattPeripheral`]. The BLE stack itself comes from elsewhere (for example
//! `rs-matter-embassy`); this crate has no BLE.

use core::convert::Infallible;

use embassy_futures::select::{Either4, select4};
use embassy_sync::blocking_mutex::raw::RawMutex;
use opentrust_embassy::OpenTrust;
use opentrust_instance::InstanceCrypto;
use opentrust_platform::{Alarm, Clock, Radio, SettingsStore};
use rand_core::{CryptoRng, Rng};
use rs_matter::dm::clusters::icd_mgmt::Icd;
use rs_matter::dm::persist::KvBlobStoreAccess;
use rs_matter::error::Error;
use rs_matter::stack::ble::GattPeripheral;
use rs_matter::stack::wireless::{ThreadCoexDriver, ThreadCoexTask, ThreadDriver, ThreadTask};

use crate::icd::IcdFollower;
use crate::mdns::SrpMdns;
use crate::net::MatterNetStack;
use crate::netctl::ThreadNetCtl;
use crate::netif::ThreadNetif;
use crate::persist::{DEFAULT_BUF, ThreadPersist};

/// The Thread driver of one node.
///
/// `Rd` is the [`Radio`] (initialized, see [`Radio::init`]), `A` the
/// [`Alarm`] on the time base of the clock of the resources, `Kv` the
/// rs-matter key-value store access for the settings blob (for example
/// `stack.matter().kv()`), `N` the settings serialisation buffer
/// ([`DEFAULT_BUF`]).
pub struct ThreadRunner<'a, M, K, S, C, R, Rd, A, Kv, const N: usize = DEFAULT_BUF>
where
    M: RawMutex,
    C: InstanceCrypto,
{
    ot: OpenTrust<'a, M, K, S, C, R>,
    radio: Rd,
    alarm: A,
    persist: ThreadPersist<'a, M, K, S, C, R, Kv, N>,
    net_stack: MatterNetStack<'a, M, K, S, C, R>,
    netif: ThreadNetif<'a, M, K, S, C, R>,
    net_ctl: ThreadNetCtl<'a, M, K, S, C, R>,
    mdns: SrpMdns<'a, M, K, S, C, R>,
    icd: Option<&'a Icd>,
}

impl<M, K, S, C, R, Rd, A, Kv, const N: usize> core::fmt::Debug
    for ThreadRunner<'_, M, K, S, C, R, Rd, A, Kv, N>
where
    M: RawMutex,
    C: InstanceCrypto,
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ThreadRunner").finish_non_exhaustive()
    }
}

impl<'a, M, K, S, C, R, Rd, A, Kv, const N: usize> ThreadRunner<'a, M, K, S, C, R, Rd, A, Kv, N>
where
    M: RawMutex,
    K: Clock,
    S: SettingsStore,
    C: InstanceCrypto,
    R: Rng + CryptoRng,
    Rd: Radio,
    A: Alarm,
    Kv: KvBlobStoreAccess,
{
    /// A runner for the node behind `ot` over `radio` and `alarm`, with the
    /// settings blob in `kv` and a settings buffer of `N` bytes.
    pub const fn new_sized(ot: OpenTrust<'a, M, K, S, C, R>, radio: Rd, alarm: A, kv: Kv) -> Self {
        Self {
            ot,
            radio,
            alarm,
            persist: ThreadPersist::new_sized(ot, kv),
            net_stack: MatterNetStack::new(ot),
            netif: ThreadNetif::new(ot),
            net_ctl: ThreadNetCtl::new(ot),
            mdns: SrpMdns::new(ot),
            icd: None,
        }
    }

    /// Apply the network parameters of `icd` to the node while the runner
    /// runs (see [`IcdFollower`]).
    pub const fn with_icd(mut self, icd: &'a Icd) -> Self {
        self.icd = Some(icd);
        self
    }

    /// Replace the settings persistence (other blob key, debounce, ...).
    pub fn with_persist(mut self, persist: ThreadPersist<'a, M, K, S, C, R, Kv, N>) -> Self {
        self.persist = persist;
        self
    }

    /// The network control (for use outside the task, e.g. tests).
    pub const fn net_ctl(&self) -> &ThreadNetCtl<'a, M, K, S, C, R> {
        &self.net_ctl
    }

    /// The settings persistence (blob write count, ...).
    pub const fn persist(&self) -> &ThreadPersist<'a, M, K, S, C, R, Kv, N> {
        &self.persist
    }

    /// The node handle.
    pub const fn ot(&self) -> OpenTrust<'a, M, K, S, C, R> {
        self.ot
    }

    fn prepare(&mut self) -> Result<(), Error> {
        if !self.persist.loaded() {
            self.persist.load()?;
        }
        Ok(())
    }

    async fn icd_loop(ot: OpenTrust<'a, M, K, S, C, R>, icd: Option<&Icd>) -> Infallible {
        match icd {
            Some(icd) => IcdFollower::new(ot).run(icd).await,
            None => core::future::pending().await,
        }
    }

    /// Run the node, the persistence and the ICD follower; never returns.
    pub async fn run_node(&mut self) -> Infallible {
        let ot = self.ot;
        let icd = self.icd;
        let node = ot.run(&mut self.radio, &mut self.alarm);
        match select4(
            node,
            self.persist.run(),
            Self::icd_loop(ot, icd),
            core::future::pending::<Infallible>(),
        )
        .await
        {
            Either4::First(n) => n,
            Either4::Second(i) | Either4::Third(i) | Either4::Fourth(i) => match i {},
        }
    }
}

impl<'a, M, K, S, C, R, Rd, A, Kv> ThreadRunner<'a, M, K, S, C, R, Rd, A, Kv, DEFAULT_BUF>
where
    M: RawMutex,
    K: Clock,
    S: SettingsStore,
    C: InstanceCrypto,
    R: Rng + CryptoRng,
    Rd: Radio,
    A: Alarm,
    Kv: KvBlobStoreAccess,
{
    /// A runner for the node behind `ot` over `radio` and `alarm`, with the
    /// settings blob in `kv` (and a [`DEFAULT_BUF`] settings buffer).
    pub const fn new(ot: OpenTrust<'a, M, K, S, C, R>, radio: Rd, alarm: A, kv: Kv) -> Self {
        Self::new_sized(ot, radio, alarm, kv)
    }
}

impl<'a, M, K, S, C, R, Rd, A, Kv, const N: usize> ThreadDriver
    for ThreadRunner<'a, M, K, S, C, R, Rd, A, Kv, N>
where
    M: RawMutex,
    K: Clock,
    S: SettingsStore,
    C: InstanceCrypto,
    R: Rng + CryptoRng,
    Rd: Radio,
    A: Alarm,
    Kv: KvBlobStoreAccess,
{
    type NetCtl<'t>
        = &'t ThreadNetCtl<'a, M, K, S, C, R>
    where
        Self: 't;

    async fn run<T>(&mut self, mut task: T) -> Result<(), Error>
    where
        T: ThreadTask,
    {
        self.prepare()?;
        let ot = self.ot;
        let icd = self.icd;
        let node = ot.run(&mut self.radio, &mut self.alarm);
        let user = task.run(&self.net_stack, &self.netif, &self.net_ctl, &mut self.mdns);
        let r = match select4(node, self.persist.run(), Self::icd_loop(ot, icd), user).await {
            Either4::Fourth(r) => r,
            Either4::First(n) => match n {},
            Either4::Second(i) | Either4::Third(i) => match i {},
        };
        let _ = self.persist.flush();
        r
    }
}

/// A [`ThreadRunner`] with a BLE GATT peripheral next to it:
/// `ThreadCoexDriver`.
pub struct ThreadCoexRunner<'a, M, K, S, C, R, Rd, A, Kv, G, const N: usize = DEFAULT_BUF>
where
    M: RawMutex,
    C: InstanceCrypto,
{
    /// The Thread side.
    pub thread: ThreadRunner<'a, M, K, S, C, R, Rd, A, Kv, N>,
    /// The BLE peripheral handed to the task.
    pub gatt: G,
}

impl<M, K, S, C, R, Rd, A, Kv, G, const N: usize> core::fmt::Debug
    for ThreadCoexRunner<'_, M, K, S, C, R, Rd, A, Kv, G, N>
where
    M: RawMutex,
    C: InstanceCrypto,
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ThreadCoexRunner").finish_non_exhaustive()
    }
}

impl<'a, M, K, S, C, R, Rd, A, Kv, G, const N: usize>
    ThreadCoexRunner<'a, M, K, S, C, R, Rd, A, Kv, G, N>
where
    M: RawMutex,
    C: InstanceCrypto,
{
    /// A coexistence runner of `thread` and the BLE peripheral `gatt`.
    pub const fn new(thread: ThreadRunner<'a, M, K, S, C, R, Rd, A, Kv, N>, gatt: G) -> Self {
        Self { thread, gatt }
    }
}

impl<'a, M, K, S, C, R, Rd, A, Kv, G, const N: usize> ThreadCoexDriver
    for ThreadCoexRunner<'a, M, K, S, C, R, Rd, A, Kv, G, N>
where
    M: RawMutex,
    K: Clock,
    S: SettingsStore,
    C: InstanceCrypto,
    R: Rng + CryptoRng,
    Rd: Radio,
    A: Alarm,
    Kv: KvBlobStoreAccess,
    G: GattPeripheral,
{
    async fn run<T>(&mut self, mut task: T) -> Result<(), Error>
    where
        T: ThreadCoexTask,
    {
        let t = &mut self.thread;
        t.prepare()?;
        let ot = t.ot;
        let icd = t.icd;
        let node = ot.run(&mut t.radio, &mut t.alarm);
        let user = task.run(
            &t.net_stack,
            &t.netif,
            &t.net_ctl,
            &mut t.mdns,
            &mut self.gatt,
        );
        let r = match select4(
            node,
            t.persist.run(),
            ThreadRunner::<'a, M, K, S, C, R, Rd, A, Kv, N>::icd_loop(ot, icd),
            user,
        )
        .await
        {
            Either4::Fourth(r) => r,
            Either4::First(n) => match n {},
            Either4::Second(i) | Either4::Third(i) => match i {},
        };
        let _ = t.persist.flush();
        r
    }
}
