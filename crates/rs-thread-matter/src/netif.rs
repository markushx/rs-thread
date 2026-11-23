//! The Thread network interface for rs-matter: `NetifDiag` (General
//! Diagnostics `NetworkInterfaces`) and `NetChangeNotif`.

use core::net::Ipv6Addr;

use embassy_sync::blocking_mutex::raw::RawMutex;
use heapless::Vec;
use rs_thread_embassy::RsThread;
use rs_thread_instance::{InstanceCrypto, Role};
use rs_thread_platform::{Clock, SettingsStore};
use rand_core::{CryptoRng, Rng};
use rs_matter::dm::clusters::gen_diag::{InterfaceTypeEnum, NetifDiag, NetifInfo};
use rs_matter::dm::networks::NetChangeNotif;
use rs_matter::error::Error;

/// The interface name reported to Matter.
pub const NETIF_NAME: &str = "thread0";
/// The interface index reported to Matter (one interface).
pub const NETIF_INDEX: u32 = 1;
/// Addresses reported at most (rs-matter advertises up to four).
pub const MAX_ADDRS: usize = 8;

/// The Thread interface of a node (`NetifDiag` + `NetChangeNotif`).
pub struct ThreadNetif<'a, M, K, S, C, R>
where
    M: RawMutex,
    C: InstanceCrypto,
{
    ot: RsThread<'a, M, K, S, C, R>,
}

impl<M: RawMutex, K, S, C: InstanceCrypto, R> core::fmt::Debug for ThreadNetif<'_, M, K, S, C, R> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ThreadNetif").finish_non_exhaustive()
    }
}

impl<'a, M, K, S, C, R> ThreadNetif<'a, M, K, S, C, R>
where
    M: RawMutex,
    K: Clock,
    S: SettingsStore,
    C: InstanceCrypto,
    R: Rng + CryptoRng,
{
    /// The interface of the node behind `ot`.
    pub const fn new(ot: RsThread<'a, M, K, S, C, R>) -> Self {
        Self { ot }
    }

    /// The addresses a peer can reach the node on: link-local first, then
    /// the ML-EID, then global / off-mesh-routable addresses. The RLOC and
    /// ALOCs (locator addresses) are not reported.
    pub fn addresses(&self) -> Vec<Ipv6Addr, MAX_ADDRS> {
        self.ot.with(|i, _| {
            let mut v: Vec<Ipv6Addr, MAX_ADDRS> = Vec::new();
            if let Some(ll) = i.link_local() {
                let _ = v.push(ll);
            }
            let ml_eid = i.ml_eid();
            if !ml_eid.is_unspecified() && !v.contains(&ml_eid) {
                let _ = v.push(ml_eid);
            }
            for a in i.unicast_addresses() {
                let seg = a.addr.segments();
                let locator =
                    a.rloc || (a.mesh_local && seg[4] == 0 && seg[5] == 0xff && seg[6] == 0xfe00);
                if locator || v.contains(&a.addr) || a.addr.is_unicast_link_local() {
                    continue;
                }
                let _ = v.push(a.addr);
            }
            v
        })
    }

    /// Whether the node is attached (child, router or leader).
    pub fn attached(&self) -> bool {
        matches!(self.ot.role(), Role::Child | Role::Router | Role::Leader)
    }
}

impl<M, K, S, C, R> NetifDiag for ThreadNetif<'_, M, K, S, C, R>
where
    M: RawMutex,
    K: Clock,
    S: SettingsStore,
    C: InstanceCrypto,
    R: Rng + CryptoRng,
{
    fn netifs(&self, f: &mut dyn FnMut(&NetifInfo<'_>) -> Result<(), Error>) -> Result<(), Error> {
        let hw_addr = self.ot.with(|i, _| i.ext_address().0);
        let addrs = self.addresses();
        f(&NetifInfo {
            name: NETIF_NAME,
            operational: self.attached(),
            offprem_svc_reachable_ipv4: None,
            offprem_svc_reachable_ipv6: None,
            hw_addr: &hw_addr,
            ipv4_addrs: &[],
            ipv6_addrs: &addrs,
            netif_type: InterfaceTypeEnum::Thread,
            netif_index: NETIF_INDEX,
        })
    }
}

impl<M, K, S, C, R> NetChangeNotif for ThreadNetif<'_, M, K, S, C, R>
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
