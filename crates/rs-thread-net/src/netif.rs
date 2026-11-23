//! The Thread network interface address state: unicast addresses,
//! multicast subscriptions and source address selection.
//!
//! This follows OpenThread's `Netif` (`net/netif.cpp`) and
//! `Ip6::SelectSourceAddress`. Storage is a pair of fixed-capacity tables;
//! both capacities are const generics of [`Netif`].
//!
//! # Unicast addresses
//!
//! - link-local `fe80::/64` from the extended address,
//! - mesh-local EID (ML-EID) and RLOC (`<mlp>:0:ff:fe00:<rloc16>`), which
//!   follow the mesh-local prefix,
//! - ALOCs (`<mlp>:0:ff:fe00:fcXX`),
//! - global addresses (SLAAC, see [`crate::slaac`], or manual).
//!
//! Mesh-local addresses carry a realm-local *scope override* (as in OT), so
//! they are chosen for realm-local and wider destinations.
//!
//! # Multicast subscriptions
//!
//! Three kinds, as in OT: *fixed* (all-nodes group = link-local `ff02::1`,
//! realm-local `ff03::1` and all-MPL-forwarders `ff03::fc`; all-routers
//! group = `ff02::2`, `ff03::2`), *internal* (stack-owned, e.g. the Thread
//! all-nodes groups derived from the mesh-local prefix) and *external*
//! (application-requested).

use core::net::Ipv6Addr;

use rs_thread_core::types::{ExtAddress, Iid, Prefix64, Rloc16, ipv6};
use rs_thread_core::{Error, Result};

use crate::addr::{self, SCOPE_REALM_LOCAL};

/// Origin of a unicast address (OT `otNetifAddressOrigin`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum AddressOrigin {
    /// Thread-internal (link-local, ML-EID, RLOC, ALOC).
    Thread,
    /// SLAAC.
    Slaac,
    /// DHCPv6.
    Dhcp6,
    /// Manually configured.
    Manual,
}

/// A unicast address on the interface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnicastAddress {
    /// The address.
    pub addr: Ipv6Addr,
    /// Prefix length in bits (on-link prefix).
    pub prefix_len: u8,
    /// Origin.
    pub origin: AddressOrigin,
    /// Preferred (not deprecated).
    pub preferred: bool,
    /// Valid.
    pub valid: bool,
    /// Scope override (e.g. realm-local for mesh-local addresses).
    pub scope_override: Option<u8>,
    /// `true` for the RLOC.
    pub rloc: bool,
    /// `true` for addresses in the mesh-local prefix (they follow it).
    pub mesh_local: bool,
}

impl UnicastAddress {
    /// A Thread-origin address with a /64 prefix, preferred and valid
    /// (OT `InitAsThreadOrigin`).
    pub const fn thread(addr: Ipv6Addr) -> Self {
        Self {
            addr,
            prefix_len: 64,
            origin: AddressOrigin::Thread,
            preferred: true,
            valid: true,
            scope_override: None,
            rloc: false,
            mesh_local: false,
        }
    }

    /// A Thread-origin mesh-local address (realm-local scope override).
    pub const fn mesh_local(addr: Ipv6Addr) -> Self {
        let mut a = Self::thread(addr);
        a.scope_override = Some(SCOPE_REALM_LOCAL);
        a.mesh_local = true;
        a
    }

    /// A SLAAC address (OT `InitAsSlaacOrigin`).
    pub const fn slaac(addr: Ipv6Addr, prefix_len: u8, preferred: bool) -> Self {
        Self {
            addr,
            prefix_len,
            origin: AddressOrigin::Slaac,
            preferred,
            valid: true,
            scope_override: None,
            rloc: false,
            mesh_local: false,
        }
    }

    /// A manually configured address (/64, preferred, valid).
    pub const fn manual(addr: Ipv6Addr) -> Self {
        let mut a = Self::thread(addr);
        a.origin = AddressOrigin::Manual;
        a
    }

    /// The effective scope (override or the address's own).
    pub fn scope(&self) -> u8 {
        self.scope_override
            .unwrap_or_else(|| addr::scope(&self.addr))
    }
}

/// Kind of a multicast subscription.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum MulticastKind {
    /// Subscribed by the stack.
    Internal,
    /// Subscribed by the application.
    External,
}

#[derive(Debug, Clone, Copy)]
struct McastEntry {
    addr: Ipv6Addr,
    kind: MulticastKind,
}

const FIXED_ALL_NODES: [Ipv6Addr; 3] = [
    ipv6::LINK_LOCAL_ALL_NODES,
    ipv6::REALM_LOCAL_ALL_NODES,
    ipv6::REALM_LOCAL_ALL_MPL_FORWARDERS,
];
const FIXED_ALL_ROUTERS: [Ipv6Addr; 2] =
    [ipv6::LINK_LOCAL_ALL_ROUTERS, ipv6::REALM_LOCAL_ALL_ROUTERS];

/// Interface address state with room for `U` unicast addresses and `M`
/// non-fixed multicast subscriptions.
#[derive(Debug, Clone)]
pub struct Netif<const U: usize, const M: usize> {
    unicast: [Option<UnicastAddress>; U],
    multicast: [Option<McastEntry>; M],
    all_nodes: bool,
    all_routers: bool,
    mlp: Prefix64,
    mlp_set: bool,
}

impl<const U: usize, const M: usize> Default for Netif<U, M> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const U: usize, const M: usize> Netif<U, M> {
    /// An interface with no addresses and no subscriptions.
    pub const fn new() -> Self {
        Self {
            unicast: [None; U],
            multicast: [None; M],
            all_nodes: false,
            all_routers: false,
            mlp: Prefix64([0; 8]),
            mlp_set: false,
        }
    }

    // ----------------------------------------------------------- unicast

    /// Iterator over the unicast addresses.
    pub fn unicast_addresses(&self) -> impl Iterator<Item = &UnicastAddress> {
        self.unicast.iter().flatten()
    }

    /// The entry for exactly `addr`.
    pub fn find_unicast(&self, addr: &Ipv6Addr) -> Option<&UnicastAddress> {
        self.unicast_addresses().find(|u| u.addr == *addr)
    }

    /// `true` if `addr` is one of our unicast addresses.
    pub fn has_unicast(&self, addr: &Ipv6Addr) -> bool {
        self.find_unicast(addr).is_some()
    }

    /// Add an address. Re-adding an existing address updates its entry in
    /// place. [`Error::NoBufs`] if the table is full.
    pub fn add_unicast(&mut self, a: UnicastAddress) -> Result<()> {
        if a.addr.is_multicast() || a.addr.is_unspecified() {
            return Err(Error::InvalidArgs);
        }
        if let Some(e) = self.unicast.iter_mut().flatten().find(|u| u.addr == a.addr) {
            *e = a;
            return Ok(());
        }
        let slot = self
            .unicast
            .iter_mut()
            .find(|s| s.is_none())
            .ok_or(Error::NoBufs)?;
        *slot = Some(a);
        Ok(())
    }

    /// Remove an address. [`Error::NotFound`] if absent.
    pub fn remove_unicast(&mut self, addr: &Ipv6Addr) -> Result<()> {
        let slot = self
            .unicast
            .iter_mut()
            .find(|s| matches!(s, Some(u) if u.addr == *addr))
            .ok_or(Error::NotFound)?;
        *slot = None;
        Ok(())
    }

    /// Set or clear the preferred flag of an address (SLAAC deprecation).
    pub fn set_preferred(&mut self, addr: &Ipv6Addr, preferred: bool) -> Result<()> {
        let e = self
            .unicast
            .iter_mut()
            .flatten()
            .find(|u| u.addr == *addr)
            .ok_or(Error::NotFound)?;
        e.preferred = preferred;
        Ok(())
    }

    /// Install the link-local address derived from `ext` (replacing any
    /// previous link-local address of Thread origin).
    pub fn set_link_local(&mut self, ext: &ExtAddress) -> Result<()> {
        for s in &mut self.unicast {
            if matches!(s, Some(u) if u.origin == AddressOrigin::Thread && u.addr.is_unicast_link_local())
            {
                *s = None;
            }
        }
        self.add_unicast(UnicastAddress::thread(ipv6::link_local(ext)))
    }

    /// The link-local address, if set.
    pub fn link_local(&self) -> Option<Ipv6Addr> {
        self.unicast_addresses()
            .find(|u| u.addr.is_unicast_link_local())
            .map(|u| u.addr)
    }

    // ------------------------------------------------------- mesh-local

    /// The mesh-local prefix (all zero until set).
    pub const fn mesh_local_prefix(&self) -> &Prefix64 {
        &self.mlp
    }

    /// Set the mesh-local prefix. Existing mesh-local unicast addresses (ML-EID,
    /// RLOC, ALOCs) are rewritten to the new prefix, and the link-local and
    /// realm-local all-Thread-nodes groups are re-subscribed.
    pub fn set_mesh_local_prefix(&mut self, mlp: Prefix64) -> Result<()> {
        if self.mlp_set && mlp == self.mlp {
            return Ok(());
        }
        if self.mlp_set {
            self.unsubscribe_multicast(&addr::link_local_all_thread_nodes(&self.mlp));
            self.unsubscribe_multicast(&addr::realm_local_all_thread_nodes(&self.mlp));
        }
        for u in self.unicast.iter_mut().flatten() {
            if u.mesh_local {
                let mut b = u.addr.octets();
                b[..8].copy_from_slice(&mlp.0);
                u.addr = Ipv6Addr::from(b);
            }
        }
        self.mlp = mlp;
        self.mlp_set = true;
        self.subscribe_multicast(addr::link_local_all_thread_nodes(&mlp))?;
        self.subscribe_multicast(addr::realm_local_all_thread_nodes(&mlp))
    }

    /// Set the mesh-local EID's IID (replacing a previous ML-EID).
    pub fn set_mesh_local_eid(&mut self, iid: &Iid) -> Result<()> {
        if let Some(old) = self.mesh_local_eid() {
            self.remove_unicast(&old)?;
        }
        self.add_unicast(UnicastAddress::mesh_local(self.mlp.with_iid(iid)))
    }

    /// The ML-EID: the mesh-local address that is neither RLOC nor ALOC.
    pub fn mesh_local_eid(&self) -> Option<Ipv6Addr> {
        self.unicast_addresses()
            .find(|u| u.mesh_local && !u.rloc && !ipv6::iid(&u.addr).is_locator())
            .map(|u| u.addr)
    }

    /// Set or clear the RLOC address.
    pub fn set_rloc16(&mut self, rloc16: Option<Rloc16>) -> Result<()> {
        if let Some(old) = self.rloc() {
            self.remove_unicast(&old)?;
        }
        if let Some(r) = rloc16 {
            let mut a = UnicastAddress::mesh_local(self.mlp.rloc(r));
            a.rloc = true;
            self.add_unicast(a)?;
        }
        Ok(())
    }

    /// The RLOC address, if set.
    pub fn rloc(&self) -> Option<Ipv6Addr> {
        self.unicast_addresses().find(|u| u.rloc).map(|u| u.addr)
    }

    /// Add an anycast locator address (`0xfc00..=0xfcff`).
    pub fn add_aloc(&mut self, aloc16: u16) -> Result<()> {
        let a = self.mlp.aloc(aloc16)?;
        self.add_unicast(UnicastAddress::mesh_local(a))
    }

    /// Remove an anycast locator address.
    pub fn remove_aloc(&mut self, aloc16: u16) -> Result<()> {
        let a = self.mlp.aloc(aloc16)?;
        self.remove_unicast(&a)
    }

    // --------------------------------------------------------- multicast

    /// Subscribe to the all-nodes group (`ff02::1`, `ff03::1`, `ff03::fc`).
    pub fn subscribe_all_nodes(&mut self) {
        self.all_nodes = true;
    }

    /// Unsubscribe from the all-nodes group.
    pub fn unsubscribe_all_nodes(&mut self) {
        self.all_nodes = false;
    }

    /// Subscribe to the all-routers group (`ff02::2`, `ff03::2`).
    pub fn subscribe_all_routers(&mut self) {
        self.all_routers = true;
    }

    /// Unsubscribe from the all-routers group.
    pub fn unsubscribe_all_routers(&mut self) {
        self.all_routers = false;
    }

    fn is_fixed(&self, a: &Ipv6Addr) -> bool {
        (self.all_nodes && FIXED_ALL_NODES.contains(a))
            || (self.all_routers && FIXED_ALL_ROUTERS.contains(a))
    }

    /// `true` if the interface is subscribed to multicast address `a`.
    pub fn is_multicast_subscribed(&self, a: &Ipv6Addr) -> bool {
        self.is_fixed(a) || self.multicast.iter().flatten().any(|e| e.addr == *a)
    }

    /// Iterate over all subscribed multicast addresses (fixed ones first).
    pub fn multicast_addresses(&self) -> impl Iterator<Item = Ipv6Addr> + '_ {
        let routers: &[Ipv6Addr] = if self.all_routers {
            &FIXED_ALL_ROUTERS
        } else {
            &[]
        };
        let nodes: &[Ipv6Addr] = if self.all_nodes {
            &FIXED_ALL_NODES
        } else {
            &[]
        };
        routers
            .iter()
            .copied()
            .chain(nodes.iter().copied())
            .chain(self.multicast.iter().flatten().map(|e| e.addr))
    }

    fn insert_multicast(&mut self, addr: Ipv6Addr, kind: MulticastKind) -> Result<()> {
        let slot = self
            .multicast
            .iter_mut()
            .find(|s| s.is_none())
            .ok_or(Error::NoBufs)?;
        *slot = Some(McastEntry { addr, kind });
        Ok(())
    }

    /// Subscribe (internal). Idempotent.
    pub fn subscribe_multicast(&mut self, a: Ipv6Addr) -> Result<()> {
        if !a.is_multicast() {
            return Err(Error::InvalidArgs);
        }
        if let Some(e) = self.multicast.iter_mut().flatten().find(|e| e.addr == a) {
            e.kind = MulticastKind::Internal;
            return Ok(());
        }
        if self.is_fixed(&a) {
            return Ok(());
        }
        self.insert_multicast(a, MulticastKind::Internal)
    }

    /// Unsubscribe an internal (or external) entry; no-op if absent.
    pub fn unsubscribe_multicast(&mut self, a: &Ipv6Addr) {
        for s in &mut self.multicast {
            if matches!(s, Some(e) if e.addr == *a) {
                *s = None;
            }
        }
    }

    /// Subscribe on behalf of the application (OT `SubscribeExternalMulticast`):
    /// [`Error::InvalidArgs`] if not multicast or if it is a fixed group
    /// (OT: `kErrorRejected`), [`Error::Already`] if already subscribed,
    /// [`Error::NoBufs`] if the table is full.
    pub fn subscribe_external(&mut self, a: Ipv6Addr) -> Result<()> {
        if !a.is_multicast() {
            return Err(Error::InvalidArgs);
        }
        if self.is_multicast_subscribed(&a) {
            return Err(Error::Already);
        }
        if FIXED_ALL_NODES.contains(&a) || FIXED_ALL_ROUTERS.contains(&a) {
            return Err(Error::InvalidArgs);
        }
        self.insert_multicast(a, MulticastKind::External)
    }

    /// Unsubscribe an external entry: [`Error::NotFound`] if not subscribed,
    /// [`Error::InvalidArgs`] if it is not external (OT: `kErrorRejected`).
    pub fn unsubscribe_external(&mut self, a: &Ipv6Addr) -> Result<()> {
        let kind = self
            .multicast
            .iter()
            .flatten()
            .find(|e| e.addr == *a)
            .map(|e| e.kind);
        match kind {
            Some(MulticastKind::External) => {
                self.unsubscribe_multicast(a);
                Ok(())
            }
            Some(MulticastKind::Internal) => Err(Error::InvalidArgs),
            None if self.is_fixed(a) => Err(Error::InvalidArgs),
            None => Err(Error::NotFound),
        }
    }

    /// The external (application) subscriptions with a scope larger than
    /// realm-local: the groups that are registered with the Primary
    /// Backbone Router (OT `kTypeMulticastLargerThanRealmLocal`).
    pub fn external_multicast_larger_than_realm_local(
        &self,
    ) -> impl Iterator<Item = Ipv6Addr> + '_ {
        self.multicast
            .iter()
            .flatten()
            .filter(|e| e.kind == MulticastKind::External)
            .map(|e| e.addr)
            .filter(addr::is_multicast_larger_than_realm_local)
    }

    /// The addresses subscribed by the application (what MLE registers with
    /// the parent on behalf of a sleepy child, Thread 1.2 MLR).
    pub fn external_multicast_addresses(&self) -> impl Iterator<Item = Ipv6Addr> + '_ {
        self.multicast
            .iter()
            .flatten()
            .filter(|e| e.kind == MulticastKind::External)
            .map(|e| e.addr)
    }

    /// Remove all external subscriptions.
    pub fn unsubscribe_all_external(&mut self) {
        for s in &mut self.multicast {
            if matches!(s, Some(e) if e.kind == MulticastKind::External) {
                *s = None;
            }
        }
    }

    // ------------------------------------------------------------ queries

    /// "Is this datagram destination for me": one of our unicast addresses
    /// or a subscribed multicast group.
    pub fn is_local_destination(&self, dst: &Ipv6Addr) -> bool {
        if dst.is_multicast() {
            self.is_multicast_subscribed(dst)
        } else {
            self.has_unicast(dst)
        }
    }

    /// `true` if `addr` shares the on-link prefix of one of our addresses
    /// (OT `Ip6::IsOnLink` without the Network Data part, which the caller
    /// adds).
    pub fn is_on_link(&self, addr: &Ipv6Addr) -> bool {
        self.unicast_addresses()
            .any(|u| addr::prefix_match_len(addr, &u.addr) >= u.prefix_len)
    }

    /// `true` if `addr` is a mesh-local RLOC under the current prefix.
    pub fn is_routing_locator(&self, a: &Ipv6Addr) -> bool {
        self.mlp_set && addr::is_routing_locator(a, &self.mlp)
    }

    /// `true` if `addr` is a mesh-local ALOC under the current prefix.
    pub fn is_anycast_locator(&self, a: &Ipv6Addr) -> bool {
        self.mlp_set && addr::is_anycast_locator(a, &self.mlp)
    }

    /// Source address selection (OT `Ip6::SelectSourceAddress`, an RFC 6724
    /// subset): same address, appropriate scope, avoid deprecated, longest
    /// prefix match, and RLOC sources for RLOC destinations (EID otherwise).
    /// Anycast locators are never used as source.
    pub fn select_source(&self, dst: &Ipv6Addr) -> Option<Ipv6Addr> {
        let mut dest_scope = addr::scope(dst);
        let dest_is_rloc = self.is_routing_locator(dst);
        let mut best: Option<&UnicastAddress> = None;
        let mut best_match = 0u8;
        for a in self.unicast_addresses() {
            if self.is_anycast_locator(&a.addr) {
                continue;
            }
            let mut match_len = addr::prefix_match_len(dst, &a.addr);
            let override_scope = if match_len >= a.prefix_len {
                match_len = a.prefix_len;
                a.scope()
            } else {
                dest_scope
            };
            if a.addr == *dst {
                return Some(a.addr);
            }
            let preferred = match best {
                None => true,
                Some(b) if a.scope() < b.scope() => a.scope() >= override_scope,
                Some(b) if a.scope() > b.scope() => b.scope() < override_scope,
                Some(b) if a.preferred != b.preferred => a.preferred,
                Some(_) if match_len > best_match => true,
                Some(_) => {
                    match_len == best_match && dest_is_rloc == self.is_routing_locator(&a.addr)
                }
            };
            if preferred {
                best = Some(a);
                best_match = match_len;
                if best_match >= a.prefix_len {
                    dest_scope = a.scope();
                }
            }
        }
        best.map(|a| a.addr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type N = Netif<8, 8>;

    const MLP: Prefix64 = Prefix64([0xfd, 0xde, 0xad, 0x00, 0xbe, 0xef, 0x00, 0x00]);

    fn a(s: &str) -> Ipv6Addr {
        s.parse().unwrap()
    }

    fn set(n: &N) -> std::vec::Vec<Ipv6Addr> {
        let mut v: std::vec::Vec<_> = n.multicast_addresses().collect();
        v.sort();
        v
    }

    fn expect(list: &[&str]) -> std::vec::Vec<Ipv6Addr> {
        let mut v: std::vec::Vec<_> = list.iter().map(|s| a(s)).collect();
        v.sort();
        v
    }

    /// Port of OT `test_netif.cpp` `TestNetifMulticastAddresses` (membership
    /// only; OT additionally checks list order, which is an implementation
    /// detail there).
    #[test]
    fn ot_test_netif_multicast_addresses() {
        let ll_all_routers = "ff02::2";
        let rl_all_routers = "ff03::2";
        let ll_all_nodes = "ff02::1";
        let rl_all_nodes = "ff03::1";
        let rl_all_mpl = "ff03::fc";
        let (t1, t2, t3) = ("ff02::114", "ff03::114", "ff04::114");
        let nodes = [ll_all_nodes, rl_all_nodes, rl_all_mpl];
        let mut n = N::new();
        assert!(set(&n).is_empty());

        n.subscribe_all_nodes();
        assert_eq!(set(&n), expect(&nodes));
        n.subscribe_all_nodes();
        assert_eq!(set(&n), expect(&nodes));

        n.subscribe_all_routers();
        assert_eq!(
            set(&n),
            expect(&[
                ll_all_routers,
                rl_all_routers,
                ll_all_nodes,
                rl_all_nodes,
                rl_all_mpl
            ])
        );
        n.subscribe_all_routers();
        n.unsubscribe_all_routers();
        assert_eq!(set(&n), expect(&nodes));
        n.unsubscribe_all_routers();
        assert_eq!(set(&n), expect(&nodes));

        n.subscribe_multicast(a(t1)).unwrap();
        assert_eq!(set(&n).len(), 4);
        n.subscribe_multicast(a(t1)).unwrap();
        assert_eq!(set(&n).len(), 4);

        n.unsubscribe_all_nodes();
        assert_eq!(set(&n), expect(&[t1]));
        n.unsubscribe_all_nodes();
        assert_eq!(set(&n), expect(&[t1]));

        n.subscribe_external(a(t2)).unwrap();
        assert_eq!(set(&n), expect(&[t1, t2]));
        n.subscribe_all_nodes();
        assert_eq!(set(&n).len(), 5);
        n.subscribe_all_routers();
        assert_eq!(set(&n).len(), 7);
        n.subscribe_external(a(t3)).unwrap();
        assert_eq!(set(&n).len(), 8);

        // t1 is internal, mpl is fixed: cannot be unsubscribed as external.
        assert_eq!(n.unsubscribe_external(&a(t1)), Err(Error::InvalidArgs));
        assert_eq!(
            n.unsubscribe_external(&a(rl_all_mpl)),
            Err(Error::InvalidArgs)
        );
        assert_eq!(n.unsubscribe_external(&a("ff05::1")), Err(Error::NotFound));

        n.unsubscribe_all_routers();
        assert_eq!(set(&n).len(), 6);
        n.unsubscribe_all_external();
        assert_eq!(
            set(&n),
            expect(&[ll_all_nodes, rl_all_nodes, rl_all_mpl, t1])
        );
        n.unsubscribe_multicast(&a(t1));
        n.unsubscribe_multicast(&a(t1));
        assert_eq!(set(&n), expect(&nodes));
        n.unsubscribe_all_nodes();
        assert!(set(&n).is_empty());

        // Fixed addresses cannot be added as external (even when unsubscribed).
        for f in [
            ll_all_routers,
            rl_all_routers,
            ll_all_nodes,
            rl_all_nodes,
            rl_all_mpl,
        ] {
            assert_eq!(n.subscribe_external(a(f)), Err(Error::InvalidArgs));
        }
        n.subscribe_all_nodes();
        assert_eq!(n.subscribe_external(a(rl_all_nodes)), Err(Error::Already));
        assert_eq!(n.subscribe_external(a("fd00::1")), Err(Error::InvalidArgs));
    }

    #[test]
    fn multicast_table_full() {
        let mut n = Netif::<2, 2>::new();
        n.subscribe_external(a("ff04::1")).unwrap();
        n.subscribe_external(a("ff04::2")).unwrap();
        assert_eq!(n.subscribe_external(a("ff04::3")), Err(Error::NoBufs));
        assert_eq!(n.subscribe_multicast(a("ff04::3")), Err(Error::NoBufs));
    }

    #[test]
    fn mesh_local_addresses_follow_prefix() {
        let mut n = N::new();
        let ext = ExtAddress([0x02, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77]);
        n.set_link_local(&ext).unwrap();
        assert_eq!(n.link_local(), Some(a("fe80::11:2233:4455:6677")));
        n.set_mesh_local_prefix(MLP).unwrap();
        n.set_mesh_local_eid(&Iid([1, 2, 3, 4, 5, 6, 7, 8]))
            .unwrap();
        n.set_rloc16(Some(Rloc16(0x0400))).unwrap();
        n.add_aloc(0xfc00).unwrap();
        assert_eq!(
            n.mesh_local_eid(),
            Some(a("fdde:ad00:beef:0:102:304:506:708"))
        );
        assert_eq!(n.rloc(), Some(MLP.rloc(Rloc16(0x0400))));
        assert!(n.has_unicast(&MLP.aloc(0xfc00).unwrap()));
        assert!(n.is_multicast_subscribed(&addr::link_local_all_thread_nodes(&MLP)));
        assert!(n.is_multicast_subscribed(&addr::realm_local_all_thread_nodes(&MLP)));

        let new = Prefix64([0xfd, 0x11, 0x22, 0x33, 0x44, 0x55, 0, 0]);
        n.set_mesh_local_prefix(new).unwrap();
        assert_eq!(n.rloc(), Some(new.rloc(Rloc16(0x0400))));
        assert!(n.has_unicast(&new.aloc(0xfc00).unwrap()));
        assert!(!n.has_unicast(&MLP.aloc(0xfc00).unwrap()));
        assert_eq!(
            n.mesh_local_eid(),
            Some(new.with_iid(&Iid([1, 2, 3, 4, 5, 6, 7, 8])))
        );
        assert!(!n.is_multicast_subscribed(&addr::realm_local_all_thread_nodes(&MLP)));
        assert!(n.is_multicast_subscribed(&addr::realm_local_all_thread_nodes(&new)));
        assert!(n.link_local().is_some());

        n.set_rloc16(None).unwrap();
        assert_eq!(n.rloc(), None);
        n.remove_aloc(0xfc00).unwrap();
        assert_eq!(n.remove_aloc(0xfc00), Err(Error::NotFound));
        assert_eq!(n.add_aloc(0x1234), Err(Error::InvalidArgs));
    }

    #[test]
    fn unicast_table_and_local_checks() {
        let mut n = Netif::<2, 4>::new();
        n.add_unicast(UnicastAddress::manual(a("2001:db8::1")))
            .unwrap();
        n.add_unicast(UnicastAddress::manual(a("2001:db8::1")))
            .unwrap();
        n.add_unicast(UnicastAddress::manual(a("2001:db8::2")))
            .unwrap();
        assert_eq!(
            n.add_unicast(UnicastAddress::manual(a("2001:db8::3"))),
            Err(Error::NoBufs)
        );
        assert_eq!(
            n.add_unicast(UnicastAddress::manual(a("ff02::1"))),
            Err(Error::InvalidArgs)
        );
        assert!(n.is_local_destination(&a("2001:db8::2")));
        assert!(!n.is_local_destination(&a("2001:db8::9")));
        assert!(n.is_on_link(&a("2001:db8::9")));
        assert!(!n.is_on_link(&a("2001:db9::9")));
        n.subscribe_all_nodes();
        assert!(n.is_local_destination(&a("ff03::1")));
        assert!(!n.is_local_destination(&a("ff03::2")));
        n.set_preferred(&a("2001:db8::2"), false).unwrap();
        assert!(!n.find_unicast(&a("2001:db8::2")).unwrap().preferred);
        n.remove_unicast(&a("2001:db8::2")).unwrap();
        assert_eq!(n.remove_unicast(&a("2001:db8::2")), Err(Error::NotFound));
    }

    fn thread_netif() -> N {
        let mut n = N::new();
        n.set_link_local(&ExtAddress([
            0x02, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        ]))
        .unwrap();
        n.set_mesh_local_prefix(MLP).unwrap();
        n.set_mesh_local_eid(&Iid([1, 2, 3, 4, 5, 6, 7, 8]))
            .unwrap();
        n.set_rloc16(Some(Rloc16(0x0400))).unwrap();
        n.add_aloc(0xfc00).unwrap();
        n
    }

    #[test]
    fn source_selection_thread() {
        let n = thread_netif();
        let ll = n.link_local().unwrap();
        let eid = n.mesh_local_eid().unwrap();
        let rloc = n.rloc().unwrap();
        // Link-local destination -> link-local source.
        assert_eq!(n.select_source(&a("fe80::1")), Some(ll));
        assert_eq!(n.select_source(&a("ff02::1")), Some(ll));
        // Realm-local multicast -> mesh-local EID (never ALOC, never RLOC for non-RLOC dst).
        assert_eq!(n.select_source(&a("ff03::1")), Some(eid));
        // Mesh-local EID destination -> EID.
        assert_eq!(
            n.select_source(&MLP.with_iid(&Iid([9, 9, 9, 9, 9, 9, 9, 9]))),
            Some(eid)
        );
        // RLOC destination -> RLOC source.
        assert_eq!(n.select_source(&MLP.rloc(Rloc16(0x0800))), Some(rloc));
        // Destination equal to an address -> that address.
        assert_eq!(n.select_source(&eid), Some(eid));
        // Never an ALOC even if it is the destination's twin... except exact (OT rule 1 skips ALOCs first).
        assert_eq!(n.select_source(&MLP.aloc(0xfc00).unwrap()), Some(eid));
        // Off-mesh destination with no global address: the widest-scope address is chosen.
        assert_eq!(n.select_source(&a("2001:db8::1")), Some(eid));
    }

    #[test]
    fn source_selection_prefers_global_and_non_deprecated() {
        let mut n = thread_netif();
        n.add_unicast(UnicastAddress::slaac(a("2001:db8:1::1"), 64, true))
            .unwrap();
        n.add_unicast(UnicastAddress::slaac(a("2001:db8:2::1"), 64, true))
            .unwrap();
        // Global destination: global scope beats mesh-local scope.
        assert_eq!(
            n.select_source(&a("2001:db8:2::99")),
            Some(a("2001:db8:2::1"))
        );
        assert_eq!(
            n.select_source(&a("2001:db8:1::99")),
            Some(a("2001:db8:1::1"))
        );
        // Mesh-local destination still uses the mesh-local EID (scope override).
        assert_eq!(n.select_source(&a("ff03::1")), n.mesh_local_eid());
        // Deprecated address avoided at equal scope.
        n.set_preferred(&a("2001:db8:2::1"), false).unwrap();
        assert_eq!(
            n.select_source(&a("2001:db8:3::99")),
            Some(a("2001:db8:1::1"))
        );
        // No addresses at all.
        assert_eq!(N::new().select_source(&a("2001:db8::1")), None);
    }
}
