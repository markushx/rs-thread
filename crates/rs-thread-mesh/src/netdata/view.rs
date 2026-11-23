//! Read access to a Network Data byte string: typed iterators and the
//! stable-only copy (OT `NetworkData` / `MutableNetworkData::RemoveTemporaryData`).

use rs_thread_core::bytes::Writer;
use rs_thread_core::{Error, Result};

use super::tlv::{
    BorderRouterEntry, BrFlags, ContextTlv, HasRouteEntry, NetPrefix, PrefixTlv, RawIter, RawTlv,
    STABLE_RLOC16, ServerTlv, ServiceTlv, ty, write_prefix, write_server, write_service, write_tlv,
};

/// Anycast locator of the first service ALOC (`0xfc10`); the service ID is
/// added (OT `Mle::ServiceAlocFromId`).
pub const SERVICE_ALOC_BASE: u16 = 0xfc10;
/// Anycast locator base of the 6LoWPAN context IDs in the stable copy of a
/// DHCPv6 / configure entry (`0xfc00 | context id`).
pub const CONTEXT_ALOC_BASE: u16 = 0xfc00;

/// One Border Router entry of a Prefix TLV (OT `OnMeshPrefixConfig`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct OnMeshEntry {
    /// The prefix.
    pub prefix: NetPrefix,
    /// Domain ID of the Prefix TLV.
    pub domain_id: u8,
    /// RLOC16 of the border router.
    pub rloc16: u16,
    /// Entry flags (preference, preferred, SLAAC, ...).
    pub flags: BrFlags,
    /// Stable flag of the Border Router TLV.
    pub stable: bool,
}

/// One Has Route entry of a Prefix TLV (OT `ExternalRouteConfig`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct RouteEntry {
    /// The route prefix.
    pub prefix: NetPrefix,
    /// RLOC16 of the border router.
    pub rloc16: u16,
    /// Preference (-1, 0, 1).
    pub preference: i8,
    /// NAT64 prefix.
    pub nat64: bool,
    /// Advertising PIO.
    pub adv_pio: bool,
    /// Stable flag of the Has Route TLV.
    pub stable: bool,
}

/// A 6LoWPAN context (OT `LowpanContextInfo`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct ContextEntry {
    /// Context ID.
    pub id: u8,
    /// Compression allowed.
    pub compress: bool,
    /// The context prefix.
    pub prefix: NetPrefix,
    /// Stable flag.
    pub stable: bool,
}

/// One server of a service (OT `ServiceConfig`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServiceEntry<'a> {
    /// Service ID.
    pub service_id: u8,
    /// Enterprise number.
    pub enterprise_number: u32,
    /// Service data.
    pub service_data: &'a [u8],
    /// RLOC16 of the server.
    pub rloc16: u16,
    /// Server data.
    pub server_data: &'a [u8],
    /// Stable flag of the Server TLV.
    pub stable: bool,
}

impl ServiceEntry<'_> {
    /// Service ALOC16 of this entry's service ID.
    pub const fn aloc16(&self) -> u16 {
        SERVICE_ALOC_BASE + self.service_id as u16
    }
}

/// A read view over Network Data bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetworkDataView<'a>(pub &'a [u8]);

impl<'a> NetworkDataView<'a> {
    /// The underlying bytes.
    pub const fn as_bytes(&self) -> &'a [u8] {
        self.0
    }

    /// Top-level TLVs.
    pub fn tlvs(&self) -> RawIter<'a> {
        RawIter::new(self.0)
    }

    /// Prefix TLVs.
    pub fn prefixes(&self) -> impl Iterator<Item = PrefixTlv<'a>> + 'a {
        self.tlvs()
            .filter(|t| t.ty == ty::PREFIX)
            .filter_map(|t| PrefixTlv::parse(&t).ok())
    }

    /// Service TLVs.
    pub fn service_tlvs(&self) -> impl Iterator<Item = ServiceTlv<'a>> + Clone + 'a {
        self.tlvs()
            .filter(|t| t.ty == ty::SERVICE)
            .filter_map(|t| ServiceTlv::parse(&t).ok())
    }

    /// All Border Router entries (on-mesh prefixes), in TLV order.
    pub fn on_mesh_prefixes(&self) -> impl Iterator<Item = OnMeshEntry> + 'a {
        self.prefixes().flat_map(|p| {
            p.sub_tlvs()
                .filter(|s| s.ty == ty::BORDER_ROUTER)
                .flat_map(move |s| {
                    s.value
                        .chunks_exact(BorderRouterEntry::SIZE)
                        .filter_map(BorderRouterEntry::parse)
                        .map(move |e| OnMeshEntry {
                            prefix: p.prefix,
                            domain_id: p.domain_id,
                            rloc16: e.rloc16,
                            flags: e.flags,
                            stable: s.stable,
                        })
                })
        })
    }

    /// All Has Route entries (external routes), in TLV order.
    pub fn external_routes(&self) -> impl Iterator<Item = RouteEntry> + 'a {
        self.prefixes().flat_map(|p| {
            p.sub_tlvs()
                .filter(|s| s.ty == ty::HAS_ROUTE)
                .flat_map(move |s| {
                    s.value
                        .chunks_exact(HasRouteEntry::SIZE)
                        .filter_map(HasRouteEntry::parse)
                        .map(move |e| RouteEntry {
                            prefix: p.prefix,
                            rloc16: e.rloc16,
                            preference: e.preference,
                            nat64: e.nat64,
                            adv_pio: e.adv_pio,
                            stable: s.stable,
                        })
                })
        })
    }

    /// All 6LoWPAN contexts.
    pub fn contexts(&self) -> impl Iterator<Item = ContextEntry> + 'a {
        self.prefixes().filter_map(|p| {
            let c = p
                .sub_tlvs()
                .find(|s| s.ty == ty::CONTEXT)
                .and_then(|s| ContextTlv::parse(&s).ok())?;
            Some(ContextEntry {
                id: c.id,
                compress: c.compress,
                prefix: NetPrefix::new(p.prefix.as_bytes(), c.len.min(p.prefix.len())).ok()?,
                stable: c.stable,
            })
        })
    }

    /// The context with this ID.
    pub fn context_by_id(&self, id: u8) -> Option<ContextEntry> {
        self.contexts().find(|c| c.id == id)
    }

    /// The compressing context with the longest prefix covering `addr`.
    pub fn context_for_address(&self, addr: &core::net::Ipv6Addr) -> Option<ContextEntry> {
        self.contexts()
            .filter(|c| c.compress && c.prefix.contains(addr))
            .max_by_key(|c| c.prefix.len())
    }

    /// All (service, server) pairs.
    pub fn services(&self) -> impl Iterator<Item = ServiceEntry<'a>> + Clone + 'a {
        self.service_tlvs().flat_map(|s| {
            RawIter::new(s.subs)
                .filter(|t| t.ty == ty::SERVER)
                .filter_map(move |t| {
                    let sv = ServerTlv::parse(&t).ok()?;
                    Some(ServiceEntry {
                        service_id: s.service_id,
                        enterprise_number: s.enterprise_number,
                        service_data: s.service_data,
                        rloc16: sv.rloc16,
                        server_data: sv.server_data,
                        stable: sv.stable,
                    })
                })
        })
    }

    /// Value of the Commissioning Data TLV, if present.
    pub fn commissioning_data(&self) -> Option<&'a [u8]> {
        self.tlvs()
            .find(|t| t.ty == ty::COMMISSIONING)
            .map(|t| t.value)
    }

    /// The Prefix TLV of exactly this prefix and domain.
    pub fn find_prefix(&self, prefix: &NetPrefix, domain_id: u8) -> Option<PrefixTlv<'a>> {
        self.prefixes()
            .find(|p| p.prefix == *prefix && p.domain_id == domain_id)
    }

    /// `true` if some on-mesh entry whose prefix covers `addr` has the
    /// on-mesh flag.
    pub fn is_on_mesh(&self, addr: &core::net::Ipv6Addr) -> bool {
        self.on_mesh_prefixes()
            .any(|e| e.flags.has(BrFlags::ON_MESH) && e.prefix.contains(addr))
    }

    /// `true` if any Border Router, Has Route or Server entry has this
    /// RLOC16.
    pub fn contains_rloc16(&self, rloc16: u16) -> bool {
        self.on_mesh_prefixes().any(|e| e.rloc16 == rloc16)
            || self.external_routes().any(|e| e.rloc16 == rloc16)
            || self.services().any(|e| e.rloc16 == rloc16)
    }

    /// Copy the stable subset (OT `RemoveTemporaryData`): temporary TLVs
    /// and sub-TLVs are dropped, prefixes / services left without
    /// sub-TLVs are dropped, and the RLOC16s of stable Border Router /
    /// Has Route entries become `0xfffe` (`0xfc00 | context id` for DHCP /
    /// configure entries with a context), those of Server entries the
    /// service ALOC16. Returns the length.
    pub fn copy_stable(&self, out: &mut [u8]) -> Result<usize> {
        let mut w = Writer::new(out);
        for t in self.tlvs() {
            match t.ty {
                ty::PREFIX => {
                    let Ok(p) = PrefixTlv::parse(&t) else {
                        continue;
                    };
                    if !p.sub_tlvs().any(|s| s.stable) {
                        continue;
                    }
                    write_prefix(&mut w, t.stable, p.domain_id, &p.prefix, |w| {
                        for (k, s) in p.sub_tlvs().enumerate().filter(|(_, s)| s.stable) {
                            // OpenThread removes the temporary sub-TLVs while
                            // walking the prefix: a Context sub-TLV that is
                            // not stable is only still there for the
                            // sub-TLVs before it.
                            let ctx = p
                                .sub_tlvs()
                                .enumerate()
                                .find(|(j, c)| c.ty == ty::CONTEXT && (c.stable || *j > k))
                                .and_then(|(_, c)| ContextTlv::parse(&c).ok());
                            copy_stable_prefix_sub(w, &s, ctx.map(|c| c.id))?;
                        }
                        Ok(())
                    })?;
                }
                ty::SERVICE => {
                    let Ok(s) = ServiceTlv::parse(&t) else {
                        continue;
                    };
                    if !RawIter::new(s.subs).any(|x| x.stable) {
                        continue;
                    }
                    write_service(
                        &mut w,
                        t.stable,
                        s.service_id,
                        s.enterprise_number,
                        s.service_data,
                        |w| {
                            for x in RawIter::new(s.subs).filter(|x| x.stable) {
                                if x.ty == ty::SERVER {
                                    let sv = ServerTlv::parse(&x)?;
                                    write_server(
                                        w,
                                        true,
                                        SERVICE_ALOC_BASE + u16::from(s.service_id),
                                        sv.server_data,
                                    )?;
                                } else {
                                    x.write(w)?;
                                }
                            }
                            Ok(())
                        },
                    )?;
                }
                _ if t.stable => t.write(&mut w)?,
                _ => {}
            }
        }
        Ok(w.len())
    }
}

fn copy_stable_prefix_sub(w: &mut Writer<'_>, s: &RawTlv<'_>, ctx: Option<u8>) -> Result<()> {
    match s.ty {
        ty::BORDER_ROUTER => {
            let mut buf = [0u8; 255];
            let mut n = 0;
            for e in s.value.chunks_exact(BorderRouterEntry::SIZE) {
                let mut e = BorderRouterEntry::parse(e).ok_or(Error::Parse)?;
                e.rloc16 = match ctx {
                    Some(id) if e.flags.has(BrFlags::DHCP) || e.flags.has(BrFlags::CONFIGURE) => {
                        CONTEXT_ALOC_BASE | u16::from(id)
                    }
                    _ => STABLE_RLOC16,
                };
                let mut ew = Writer::new(&mut buf[n..]);
                e.write(&mut ew)?;
                n += ew.len();
            }
            write_tlv(w, ty::BORDER_ROUTER, true, &buf[..n])
        }
        ty::HAS_ROUTE => {
            let mut buf = [0u8; 255];
            let mut n = 0;
            for e in s.value.chunks_exact(HasRouteEntry::SIZE) {
                // Only the RLOC16 changes; the flags byte is kept as received
                // (reserved bits included), like OpenThread.
                let mut ew = Writer::new(&mut buf[n..]);
                ew.write_u16(STABLE_RLOC16)?;
                ew.write_u8(e[2])?;
                n += ew.len();
            }
            write_tlv(w, ty::HAS_ROUTE, true, &buf[..n])
        }
        _ => s.write(w),
    }
}
