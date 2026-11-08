//! SLAAC address generation and management for on-mesh prefixes with the
//! SLAAC flag (OT `utils/slaac_address.cpp`).
//!
//! IIDs are semantically opaque (RFC 7217):
//!
//! ```text
//! IID = SHA-256(prefix bytes || "wpan" || [network id] || DAD counter || secret key)[..8]
//! ```
//!
//! exactly as OpenThread, where the optional Network_ID is not used (pass
//! `None` for OT-compatible addresses) and the DAD counter is only
//! incremented when the IID is reserved (DAD itself is not performed in
//! Thread). The 32-byte secret key is caller-provided (OT generates it once
//! and stores it in settings).
//!
//! [`Slaac`] keeps the addresses it added, adds an address for every
//! SLAAC on-mesh prefix, and deprecates then removes it
//! [`DEPRECATION_INTERVAL`] after the prefix disappears. Network Data is
//! supplied by the caller as a slice of [`OnMeshPrefix`], so this module
//! does not depend on the Phase 7 Network Data store.

use core::net::Ipv6Addr;

use opentrust_core::crypto::backend::{CryptoBackend, Sha256};
use opentrust_core::time::{Duration, Instant};
use opentrust_core::types::{Iid, Prefix64};
use opentrust_core::{Error, Result};

use crate::addr::{iid_is_reserved, matches_prefix};
use crate::netif::{Netif, UnicastAddress};

/// Length of the IID secret key.
pub const IID_SECRET_LEN: usize = 32;
/// Maximum IID creation attempts (OT `kMaxIidCreationAttempts`).
pub const MAX_IID_ATTEMPTS: u16 = 256;
/// Time a SLAAC address stays deprecated after its prefix is gone
/// (OT `OPENTHREAD_CONFIG_IP6_SLAAC_DEPRECATION_INTERVAL` = 300 s).
pub const DEPRECATION_INTERVAL: Duration = Duration::from_secs(300);
/// The constant "net interface" string hashed into the IID.
const NET_IFACE: &[u8] = b"wpan";

/// Generate a semantically opaque IID (RFC 7217) for `prefix`
/// (`prefix_len` bits are hashed, rounded up to whole bytes).
///
/// `dad_counter` is the starting counter and is advanced past reserved IIDs;
/// the final value is stored back. [`Error::Abort`] if no non-reserved IID
/// is found in [`MAX_IID_ATTEMPTS`] tries.
pub fn generate_iid<B: CryptoBackend>(
    backend: &B,
    prefix: &Prefix64,
    prefix_len: u8,
    network_id: Option<&[u8]>,
    dad_counter: &mut u8,
    secret: &[u8; IID_SECRET_LEN],
) -> Result<Iid> {
    let n = usize::from(prefix_len).div_ceil(8).min(8);
    for _ in 0..MAX_IID_ATTEMPTS {
        let mut h = backend.sha256();
        h.update(&prefix.0[..n]);
        h.update(NET_IFACE);
        if let Some(id) = network_id {
            h.update(id);
        }
        h.update(&[*dad_counter]);
        h.update(secret);
        let hash = h.finalize();
        let mut iid = [0u8; 8];
        iid.copy_from_slice(&hash[..8]);
        let iid = Iid(iid);
        if !iid_is_reserved(&iid) {
            return Ok(iid);
        }
        *dad_counter = dad_counter.wrapping_add(1);
    }
    Err(Error::Abort)
}

/// Inputs for IID generation shared by all addresses of a [`Slaac::update`] call.
#[derive(Debug)]
pub struct IidParams<'a, B> {
    /// Crypto backend (SHA-256).
    pub backend: &'a B,
    /// The 32-byte secret key.
    pub secret: &'a [u8; IID_SECRET_LEN],
    /// Optional RFC 7217 Network_ID (`None` = OT-compatible).
    pub network_id: Option<&'a [u8]>,
}

/// An on-mesh prefix from Network Data, as far as SLAAC needs it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OnMeshPrefix {
    /// The /64 prefix (other lengths are never used for SLAAC).
    pub prefix: Prefix64,
    /// Prefix length in bits.
    pub prefix_len: u8,
    /// On-mesh flag (`false`: off-mesh route, address gets a /128 prefix).
    pub on_mesh: bool,
    /// Preferred flag.
    pub preferred: bool,
    /// SLAAC flag.
    pub slaac: bool,
    /// Domain-prefix flag (excluded from SLAAC).
    pub domain_prefix: bool,
}

impl OnMeshPrefix {
    /// OT `Slaac::IsSlaac`: SLAAC flag, not a domain prefix, /64.
    pub const fn is_slaac(&self) -> bool {
        self.slaac && !self.domain_prefix && self.prefix_len == 64
    }

    fn address_prefix_len(&self) -> u8 {
        if self.on_mesh { self.prefix_len } else { 128 }
    }
}

#[derive(Debug, Clone, Copy)]
struct Entry {
    addr: Ipv6Addr,
    prefix_len: u8,
    /// Set while deprecating: removal time.
    expires: Option<Instant>,
}

/// SLAAC manager holding up to `N` addresses (OT default 4).
#[derive(Debug, Clone)]
pub struct Slaac<const N: usize = 4> {
    entries: [Option<Entry>; N],
    enabled: bool,
}

impl<const N: usize> Default for Slaac<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> Slaac<N> {
    /// A new, enabled manager.
    pub const fn new() -> Self {
        Self {
            entries: [None; N],
            enabled: true,
        }
    }

    /// Enable or disable SLAAC; disabling removes all its addresses from
    /// `netif`.
    pub fn set_enabled<const U: usize, const M: usize>(
        &mut self,
        enabled: bool,
        netif: &mut Netif<U, M>,
    ) {
        if !enabled {
            for e in &mut self.entries {
                if let Some(x) = e.take() {
                    let _ = netif.remove_unicast(&x.addr);
                }
            }
        }
        self.enabled = enabled;
    }

    /// `true` if `addr` is managed by this SLAAC instance.
    pub fn owns(&self, addr: &Ipv6Addr) -> bool {
        self.entries.iter().flatten().any(|e| e.addr == *addr)
    }

    fn matches(entry: &Entry, p: &OnMeshPrefix) -> bool {
        entry.prefix_len == p.address_prefix_len()
            && matches_prefix(&entry.addr, &p.prefix.with_iid(&Iid([0; 8])), p.prefix_len)
    }

    /// Reconcile with the current Network Data prefixes (OT
    /// `RemoveOrDeprecateAddresses` + `AddAddresses`). Call whenever Network
    /// Data changes or one of our addresses is removed. `filter` may reject
    /// prefixes (OT `Slaac::SetFilter`).
    pub fn update<B: CryptoBackend, const U: usize, const M: usize>(
        &mut self,
        iid: &IidParams<'_, B>,
        netif: &mut Netif<U, M>,
        prefixes: &[OnMeshPrefix],
        filter: Option<fn(&OnMeshPrefix) -> bool>,
        now: Instant,
    ) {
        if !self.enabled {
            return;
        }
        let usable = |p: &OnMeshPrefix| p.is_slaac() && filter.is_none_or(|f| !f(p));

        // Remove or deprecate addresses without a matching prefix.
        for slot in &mut self.entries {
            let Some(e) = slot else { continue };
            let found = prefixes
                .iter()
                .find(|p| p.is_slaac() && Self::matches(e, p));
            match found {
                Some(p) if filter.is_some_and(|f| f(p)) => {
                    let _ = netif.remove_unicast(&e.addr);
                    *slot = None;
                }
                Some(_) => {}
                None if e.expires.is_none() => {
                    let preferred = netif.find_unicast(&e.addr).is_some_and(|u| u.preferred);
                    if preferred {
                        e.expires = Some(now.saturating_add(DEPRECATION_INTERVAL));
                        let _ = netif.set_preferred(&e.addr, false);
                    } else {
                        let _ = netif.remove_unicast(&e.addr);
                        *slot = None;
                    }
                }
                None => {}
            }
        }

        // Add addresses for new prefixes (and un-deprecate returning ones).
        for p in prefixes.iter().filter(|p| usable(p)) {
            if let Some(e) = self
                .entries
                .iter_mut()
                .flatten()
                .find(|e| Self::matches(e, p))
            {
                if e.expires.is_some() && p.preferred {
                    e.expires = None;
                    let _ = netif.set_preferred(&e.addr, true);
                }
                continue;
            }
            let plen = p.address_prefix_len();
            // An address with a matching prefix that we did not create
            // (e.g. manually added) suppresses SLAAC for the prefix.
            if netif.unicast_addresses().any(|u| {
                u.prefix_len == plen
                    && matches_prefix(&u.addr, &p.prefix.with_iid(&Iid([0; 8])), p.prefix_len)
            }) {
                continue;
            }
            self.add_for(iid, netif, p);
        }
    }

    fn add_for<B: CryptoBackend, const U: usize, const M: usize>(
        &mut self,
        iid: &IidParams<'_, B>,
        netif: &mut Netif<U, M>,
        p: &OnMeshPrefix,
    ) {
        // Free slot, else the deprecating entry that expires first.
        let idx = self.entries.iter().position(Option::is_none).or_else(|| {
            self.entries
                .iter()
                .enumerate()
                .filter_map(|(i, e)| e.and_then(|e| e.expires).map(|t| (i, t)))
                .min_by_key(|&(_, t)| t)
                .map(|(i, _)| i)
        });
        let Some(idx) = idx else { return };
        let mut dad = 0u8;
        let Ok(id) = generate_iid(
            iid.backend,
            &p.prefix,
            p.prefix_len,
            iid.network_id,
            &mut dad,
            iid.secret,
        ) else {
            return;
        };
        let addr = p.prefix.with_iid(&id);
        let plen = p.address_prefix_len();
        if netif
            .add_unicast(UnicastAddress::slaac(addr, plen, p.preferred))
            .is_err()
        {
            return;
        }
        if let Some(old) = self.entries[idx].take() {
            let _ = netif.remove_unicast(&old.addr);
        }
        self.entries[idx] = Some(Entry {
            addr,
            prefix_len: plen,
            expires: None,
        });
    }

    /// Remove deprecated addresses whose time has come.
    pub fn poll<const U: usize, const M: usize>(&mut self, netif: &mut Netif<U, M>, now: Instant) {
        for slot in &mut self.entries {
            if let Some(e) = slot
                && e.expires.is_some_and(|t| t <= now)
            {
                let _ = netif.remove_unicast(&e.addr);
                *slot = None;
            }
        }
    }

    /// Instant at which [`Self::poll`] next has work.
    pub fn next_deadline(&self) -> Option<Instant> {
        self.entries
            .iter()
            .flatten()
            .filter_map(|e| e.expires)
            .min()
    }

    /// The address added for `p`, if any.
    pub fn address_for(&self, p: &OnMeshPrefix) -> Option<Ipv6Addr> {
        self.entries
            .iter()
            .flatten()
            .find(|e| Self::matches(e, p))
            .map(|e| e.addr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::netif::AddressOrigin;
    use opentrust_core::crypto::soft::SoftCrypto;

    const SECRET: [u8; 32] = [0x5a; 32];
    const P1: Prefix64 = Prefix64([0x20, 0x01, 0x0d, 0xb8, 0, 1, 0, 0]);
    const P2: Prefix64 = Prefix64([0x20, 0x01, 0x0d, 0xb8, 0, 2, 0, 0]);

    const PARAMS: IidParams<'static, SoftCrypto> = IidParams {
        backend: &SoftCrypto,
        secret: &SECRET,
        network_id: None,
    };

    fn pfx(p: Prefix64) -> OnMeshPrefix {
        OnMeshPrefix {
            prefix: p,
            prefix_len: 64,
            on_mesh: true,
            preferred: true,
            slaac: true,
            domain_prefix: false,
        }
    }

    /// Reference computation of the OT hash input, independent of `generate_iid`.
    #[test]
    fn iid_matches_ot_construction() {
        let mut dad = 0;
        let iid = generate_iid(&SoftCrypto, &P1, 64, None, &mut dad, &SECRET).unwrap();
        let mut h = SoftCrypto.sha256();
        h.update(&P1.0);
        h.update(b"wpan");
        h.update(&[0u8]);
        h.update(&SECRET);
        assert_eq!(iid.0, h.finalize()[..8]);
        assert_eq!(dad, 0);
        // Stable, prefix- and key-dependent.
        let mut d2 = 0;
        assert_eq!(
            generate_iid(&SoftCrypto, &P1, 64, None, &mut d2, &SECRET).unwrap(),
            iid
        );
        assert_ne!(
            generate_iid(&SoftCrypto, &P2, 64, None, &mut d2, &SECRET).unwrap(),
            iid
        );
        assert_ne!(
            generate_iid(&SoftCrypto, &P1, 64, None, &mut d2, &[1; 32]).unwrap(),
            iid
        );
        assert_ne!(
            generate_iid(&SoftCrypto, &P1, 64, Some(b"net"), &mut d2, &SECRET).unwrap(),
            iid
        );
        assert!(!iid_is_reserved(&iid));
    }

    #[test]
    fn manager_adds_deprecates_and_removes() {
        let mut netif = Netif::<8, 4>::new();
        let mut s = Slaac::<2>::new();
        let t0 = Instant::from_secs(10);
        s.update(&PARAMS, &mut netif, &[pfx(P1)], None, t0);
        let a1 = s.address_for(&pfx(P1)).unwrap();
        assert!(P1.contains(&a1));
        let u = *netif.find_unicast(&a1).unwrap();
        assert_eq!(
            (u.origin, u.prefix_len, u.preferred),
            (AddressOrigin::Slaac, 64, true)
        );
        // Idempotent.
        s.update(&PARAMS, &mut netif, &[pfx(P1)], None, t0);
        assert_eq!(netif.unicast_addresses().count(), 1);

        // Prefix goes away -> deprecated, still present.
        s.update(&PARAMS, &mut netif, &[], None, t0);
        assert!(!netif.find_unicast(&a1).unwrap().preferred);
        assert_eq!(
            s.next_deadline(),
            Some(t0.saturating_add(DEPRECATION_INTERVAL))
        );
        // Prefix returns -> preferred again.
        s.update(&PARAMS, &mut netif, &[pfx(P1)], None, t0);
        assert!(netif.find_unicast(&a1).unwrap().preferred);
        assert_eq!(s.next_deadline(), None);

        // Gone again; removed after the interval.
        s.update(&PARAMS, &mut netif, &[], None, t0);
        s.poll(&mut netif, t0.saturating_add(Duration::from_secs(299)));
        assert!(netif.has_unicast(&a1));
        s.poll(&mut netif, t0.saturating_add(DEPRECATION_INTERVAL));
        assert!(!netif.has_unicast(&a1));
        assert!(!s.owns(&a1));
    }

    #[test]
    fn manager_filters_and_skips_non_slaac() {
        let mut netif = Netif::<8, 4>::new();
        let mut s = Slaac::<4>::new();
        let t = Instant::ZERO;
        let mut dp = pfx(P1);
        dp.domain_prefix = true;
        let mut no = pfx(P2);
        no.slaac = false;
        let mut p48 = pfx(P2);
        p48.prefix_len = 48;
        s.update(&PARAMS, &mut netif, &[dp, no, p48], None, t);
        assert_eq!(netif.unicast_addresses().count(), 0);
        // Filter rejects P1.
        s.update(&PARAMS, &mut netif, &[pfx(P1)], Some(|p| p.prefix == P1), t);
        assert_eq!(netif.unicast_addresses().count(), 0);
        // Off-mesh prefix -> /128 address.
        let mut off = pfx(P2);
        off.on_mesh = false;
        s.update(&PARAMS, &mut netif, &[off], None, t);
        assert_eq!(netif.unicast_addresses().next().unwrap().prefix_len, 128);
    }

    #[test]
    fn manager_capacity_evicts_deprecating() {
        let mut netif = Netif::<8, 4>::new();
        let mut s = Slaac::<1>::new();
        let t = Instant::ZERO;
        s.update(&PARAMS, &mut netif, &[pfx(P1)], None, t);
        let a1 = s.address_for(&pfx(P1)).unwrap();
        // Full and nothing deprecating: P2 is not added.
        s.update(&PARAMS, &mut netif, &[pfx(P1), pfx(P2)], None, t);
        assert_eq!(s.address_for(&pfx(P2)), None);
        // P1 withdrawn (deprecating) frees its slot for P2.
        s.update(&PARAMS, &mut netif, &[pfx(P2)], None, t);
        assert!(s.address_for(&pfx(P2)).is_some());
        assert!(!netif.has_unicast(&a1));
    }

    #[test]
    fn disable_removes_addresses() {
        let mut netif = Netif::<8, 4>::new();
        let mut s = Slaac::<4>::new();
        s.update(&PARAMS, &mut netif, &[pfx(P1)], None, Instant::ZERO);
        s.set_enabled(false, &mut netif);
        assert_eq!(netif.unicast_addresses().count(), 0);
        s.update(&PARAMS, &mut netif, &[pfx(P1)], None, Instant::ZERO);
        assert_eq!(netif.unicast_addresses().count(), 0);
    }
}
