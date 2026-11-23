//! The Network Data this device serves itself (OT `NetworkData::Local`):
//! on-mesh prefixes (as Border Router), external routes (as Has Route
//! server) and services (as Server). The [`Notifier`](super::notifier::Notifier)
//! registers it with the leader.

use heapless::Vec;
use rs_thread_core::bytes::Writer;
use rs_thread_core::{Error, Result};

use super::tlv::{
    BorderRouterEntry, BrFlags, HasRouteEntry, NetPrefix, begin_tlv, end_tlv, ty,
    write_border_router, write_has_route, write_server, write_service,
};
use super::view::NetworkDataView;

/// Longest service data / server data of a local service.
pub const MAX_LOCAL_SERVICE_BYTES: usize = 32;

/// An on-mesh prefix this device serves (OT `OnMeshPrefixConfig`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct OnMeshPrefixConfig {
    /// The prefix.
    pub prefix: NetPrefix,
    /// Preference and flags (SLAAC, on-mesh, default route, ...).
    pub flags: BrFlags,
    /// Stable.
    pub stable: bool,
}

/// An external route this device serves (OT `ExternalRouteConfig`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct ExternalRouteConfig {
    /// The route prefix.
    pub prefix: NetPrefix,
    /// Preference (-1, 0, 1).
    pub preference: i8,
    /// NAT64 prefix.
    pub nat64: bool,
    /// Advertising PIO.
    pub adv_pio: bool,
    /// Stable.
    pub stable: bool,
}

/// A service this device serves (OT `ServiceConfig`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceConfig {
    /// Enterprise number.
    pub enterprise_number: u32,
    /// Service data.
    pub service_data: Vec<u8, MAX_LOCAL_SERVICE_BYTES>,
    /// Server data.
    pub server_data: Vec<u8, MAX_LOCAL_SERVICE_BYTES>,
    /// Stable.
    pub stable: bool,
}

impl ServiceConfig {
    /// Build a service; [`Error::NoBufs`] if the data is too long.
    pub fn new(
        enterprise_number: u32,
        service_data: &[u8],
        server_data: &[u8],
        stable: bool,
    ) -> Result<Self> {
        Ok(Self {
            enterprise_number,
            service_data: Vec::from_slice(service_data).map_err(|_| Error::NoBufs)?,
            server_data: Vec::from_slice(server_data).map_err(|_| Error::NoBufs)?,
            stable,
        })
    }
}

/// Local Network Data with room for `P` on-mesh prefixes, `R` external
/// routes and `S` services (OT: 4 / 4 / 1 by default).
#[derive(Debug, Clone, Default)]
pub struct LocalData<const P: usize = 4, const R: usize = 4, const S: usize = 2> {
    prefixes: Vec<OnMeshPrefixConfig, P>,
    routes: Vec<ExternalRouteConfig, R>,
    services: Vec<ServiceConfig, S>,
}

impl<const P: usize, const R: usize, const S: usize> LocalData<P, R, S> {
    /// Empty local data.
    pub const fn new() -> Self {
        Self {
            prefixes: Vec::new(),
            routes: Vec::new(),
            services: Vec::new(),
        }
    }

    /// `true` if there is nothing to register.
    pub fn is_empty(&self) -> bool {
        self.prefixes.is_empty() && self.routes.is_empty() && self.services.is_empty()
    }

    /// Add or replace (same prefix) an on-mesh prefix. [`Error::NoBufs`]
    /// if the table is full.
    pub fn add_on_mesh_prefix(&mut self, cfg: OnMeshPrefixConfig) -> Result<()> {
        if let Some(e) = self.prefixes.iter_mut().find(|e| e.prefix == cfg.prefix) {
            *e = cfg;
            return Ok(());
        }
        self.prefixes.push(cfg).map_err(|_| Error::NoBufs)
    }

    /// Remove an on-mesh prefix ([`Error::NotFound`] if absent).
    pub fn remove_on_mesh_prefix(&mut self, prefix: &NetPrefix) -> Result<()> {
        let i = self
            .prefixes
            .iter()
            .position(|e| e.prefix == *prefix)
            .ok_or(Error::NotFound)?;
        self.prefixes.remove(i);
        Ok(())
    }

    /// Add or replace (same prefix) an external route.
    pub fn add_external_route(&mut self, cfg: ExternalRouteConfig) -> Result<()> {
        if let Some(e) = self.routes.iter_mut().find(|e| e.prefix == cfg.prefix) {
            *e = cfg;
            return Ok(());
        }
        self.routes.push(cfg).map_err(|_| Error::NoBufs)
    }

    /// Remove an external route ([`Error::NotFound`] if absent).
    pub fn remove_external_route(&mut self, prefix: &NetPrefix) -> Result<()> {
        let i = self
            .routes
            .iter()
            .position(|e| e.prefix == *prefix)
            .ok_or(Error::NotFound)?;
        self.routes.remove(i);
        Ok(())
    }

    /// Add or replace (same enterprise number and service data) a service.
    pub fn add_service(&mut self, cfg: ServiceConfig) -> Result<()> {
        if let Some(e) = self.services.iter_mut().find(|e| {
            e.enterprise_number == cfg.enterprise_number && e.service_data == cfg.service_data
        }) {
            *e = cfg;
            return Ok(());
        }
        self.services.push(cfg).map_err(|_| Error::NoBufs)
    }

    /// Remove a service ([`Error::NotFound`] if absent).
    pub fn remove_service(&mut self, enterprise_number: u32, service_data: &[u8]) -> Result<()> {
        let i = self
            .services
            .iter()
            .position(|e| {
                e.enterprise_number == enterprise_number && e.service_data == service_data
            })
            .ok_or(Error::NotFound)?;
        self.services.remove(i);
        Ok(())
    }

    /// The on-mesh prefixes.
    pub fn on_mesh_prefixes(&self) -> &[OnMeshPrefixConfig] {
        &self.prefixes
    }

    /// The external routes.
    pub fn external_routes(&self) -> &[ExternalRouteConfig] {
        &self.routes
    }

    /// The services.
    pub fn services(&self) -> &[ServiceConfig] {
        &self.services
    }

    /// Encode as Network Data with every entry carrying `rloc16`: one
    /// Prefix TLV per prefix with a Border Router and / or Has Route
    /// sub-TLV of a single entry, one Service TLV per service with a
    /// single Server (the form [`Leader::register`](super::leader::Leader::register)
    /// accepts). Returns the length.
    pub fn encode(&self, rloc16: u16, out: &mut [u8]) -> Result<usize> {
        let mut w = Writer::new(out);
        let mut done: Vec<NetPrefix, 8> = Vec::new();
        let all = self
            .prefixes
            .iter()
            .map(|p| p.prefix)
            .chain(self.routes.iter().map(|r| r.prefix));
        for prefix in all {
            if done.contains(&prefix) {
                continue;
            }
            let _ = done.push(prefix);
            let br = self.prefixes.iter().find(|p| p.prefix == prefix);
            let hr = self.routes.iter().find(|r| r.prefix == prefix);
            let off = begin_tlv(
                &mut w,
                ty::PREFIX,
                br.is_some_and(|b| b.stable) || hr.is_some_and(|h| h.stable),
            )?;
            w.write_u8(0)?;
            w.write_u8(prefix.len())?;
            w.write_slice(prefix.as_bytes())?;
            if let Some(h) = hr {
                write_has_route(
                    &mut w,
                    h.stable,
                    &[HasRouteEntry {
                        rloc16,
                        preference: h.preference,
                        nat64: h.nat64,
                        adv_pio: h.adv_pio,
                    }],
                )?;
            }
            if let Some(b) = br {
                write_border_router(
                    &mut w,
                    b.stable,
                    &[BorderRouterEntry {
                        rloc16,
                        flags: b.flags,
                    }],
                )?;
            }
            end_tlv(&mut w, off)?;
        }
        for s in &self.services {
            write_service(
                &mut w,
                s.stable,
                0,
                s.enterprise_number,
                &s.service_data,
                |w| write_server(w, s.stable, rloc16, &s.server_data),
            )?;
        }
        Ok(w.len())
    }
}

/// `true` if `a` contains every entry of `b` that belongs to `rloc16`
/// (OT `ContainsEntriesFrom`): on-mesh prefixes, external routes and
/// services compared field by field including the stable flag.
pub fn contains_entries_from(
    a: &NetworkDataView<'_>,
    b: &NetworkDataView<'_>,
    rloc16: u16,
) -> bool {
    b.on_mesh_prefixes()
        .filter(|e| e.rloc16 == rloc16)
        .all(|e| {
            a.on_mesh_prefixes().any(|x| {
                x.rloc16 == rloc16
                    && x.prefix == e.prefix
                    && x.flags == e.flags
                    && x.stable == e.stable
            })
        })
        && b.external_routes()
            .filter(|e| e.rloc16 == rloc16)
            .all(|e| a.external_routes().any(|x| x == e))
        && b.services().filter(|e| e.rloc16 == rloc16).all(|e| {
            a.services().any(|x| {
                x.rloc16 == rloc16
                    && x.enterprise_number == e.enterprise_number
                    && x.service_data == e.service_data
                    && x.server_data == e.server_data
                    && x.stable == e.stable
            })
        })
}
