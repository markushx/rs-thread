//! Thread Network Data (Thread 1.4.1 sections 5.13-5.15, OT
//! `thread/network_data*.{hpp,cpp}`).
//!
//! - [`tlv`]: the Network Data TLV wire format and writers.
//! - [`NetworkData`] / [`NetworkDataView`]: the byte buffer and typed
//!   iterators over on-mesh prefixes, external routes, 6LoWPAN contexts and
//!   services, plus the stable-only copy sent to sleepy children.

mod data;
pub mod tlv;
mod view;

pub use data::NetworkData;
pub use view::{
    CONTEXT_ALOC_BASE, ContextEntry, NetworkDataView, OnMeshEntry, RouteEntry, SERVICE_ALOC_BASE,
    ServiceEntry,
};

#[cfg(test)]
mod tests;
