//! Network Data as the source of SLAAC prefixes and 6LoWPAN contexts.

use core::net::Ipv6Addr;

use heapless::Vec;
use rs_thread_core::types::Prefix64;
use rs_thread_lowpan::iphc::{Context, ContextProvider};
use rs_thread_net::slaac::OnMeshPrefix;

use super::tlv::BrFlags;
use super::view::NetworkDataView;

/// The Border Router entries as the prefix list [`Slaac::update`](rs_thread_net::slaac::Slaac::update)
/// takes (OT `Slaac::Update` iterating `GetNextOnMeshPrefix`), one entry per
/// distinct prefix and length; entries beyond `N` are ignored.
pub fn slaac_prefixes<const N: usize>(view: &NetworkDataView<'_>) -> Vec<OnMeshPrefix, N> {
    let mut out: Vec<OnMeshPrefix, N> = Vec::new();
    for e in view.on_mesh_prefixes() {
        let o = e.prefix.octets();
        let mut p64 = [0u8; 8];
        p64.copy_from_slice(&o[..8]);
        let p = OnMeshPrefix {
            prefix: Prefix64(p64),
            prefix_len: e.prefix.len(),
            on_mesh: e.flags.has(BrFlags::ON_MESH),
            preferred: e.flags.has(BrFlags::PREFERRED),
            slaac: e.flags.has(BrFlags::SLAAC),
            domain_prefix: e.flags.has(BrFlags::DP),
        };
        if out
            .iter()
            .any(|q| q.prefix == p.prefix && q.prefix_len == p.prefix_len)
        {
            continue;
        }
        if out.push(p).is_err() {
            break;
        }
    }
    out
}

/// 6LoWPAN contexts for IPHC: the mesh-local prefix as context 0 (always
/// compressible) and the Context TLVs of Network Data (OT
/// `Lowpan::FindContextForAddress` / `FindContextForId`).
#[derive(Debug, Clone, Copy)]
pub struct NetDataContexts<'a> {
    /// Network Data.
    pub view: NetworkDataView<'a>,
    /// Mesh-local prefix (context 0).
    pub mesh_local_prefix: Prefix64,
}

impl ContextProvider for NetDataContexts<'_> {
    fn by_id(&self, id: u8) -> Option<Context> {
        if id == 0 {
            return Some(Context::new64(0, self.mesh_local_prefix.0, true));
        }
        let c = self.view.context_by_id(id)?;
        Some(Context {
            id,
            prefix: c.prefix.octets(),
            prefix_len: c.prefix.len(),
            compress: c.compress,
        })
    }

    fn for_address(&self, addr: &Ipv6Addr) -> Option<Context> {
        if self.mesh_local_prefix.contains(addr) {
            return Some(Context::new64(0, self.mesh_local_prefix.0, true));
        }
        let c = self.view.context_for_address(addr)?;
        Some(Context {
            id: c.id,
            prefix: c.prefix.octets(),
            prefix_len: c.prefix.len(),
            compress: true,
        })
    }
}

/// The /64 prefix of context `id` for expanding compressed Address
/// Registration entries ([`MleEnv::lowpan_context`](rs_thread_mle::MleEnv::lowpan_context));
/// `None` for context 0 (the core handles it) and contexts shorter than 64
/// bits.
pub fn context_prefix64(view: &NetworkDataView<'_>, id: u8) -> Option<Prefix64> {
    if id == 0 {
        return None;
    }
    let c = view.context_by_id(id)?;
    if c.prefix.len() < 64 {
        return None;
    }
    let mut p = [0u8; 8];
    p.copy_from_slice(&c.prefix.octets()[..8]);
    Some(Prefix64(p))
}

/// The ID of the compressing context covering `addr` with at least 64
/// bits, for compressing outgoing Address Registration entries
/// ([`MleEnv::lowpan_context_for`](rs_thread_mle::MleEnv::lowpan_context_for)).
pub fn context_id_for(view: &NetworkDataView<'_>, addr: &Ipv6Addr) -> Option<u8> {
    let c = view.context_for_address(addr)?;
    (c.prefix.len() >= 64).then_some(c.id)
}
