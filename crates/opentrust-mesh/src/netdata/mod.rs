//! Thread Network Data (Thread 1.4.1 sections 5.13-5.15, OT
//! `thread/network_data*.{hpp,cpp}`).
//!
//! - [`tlv`]: the Network Data TLV wire format and writers.
//! - [`NetworkData`] / [`NetworkDataView`]: the byte buffer and typed
//!   iterators over on-mesh prefixes, external routes, 6LoWPAN contexts and
//!   services, plus the stable-only copy sent to sleepy children.
//! - `leader` (feature `ftd`): the leader's store, `/a/sd` registration,
//!   context and service ID allocation, versions.
//! - [`local`], [`notifier`], [`server_data`]: the Network Data a device
//!   serves itself, when to register it and the `/a/sd` messages.
//! - [`backbone`]: the Primary Backbone Router (BBR service in Network Data)
//!   and the Domain Prefix, client side.
//! - [`publisher`]: publishing prefixes, routes and the DNS/SRP service
//!   only as often as the partition needs them.

pub mod aloc;
pub mod anycast;
pub mod backbone;
pub mod consumers;
mod data;
#[cfg(feature = "ftd")]
pub mod leader;
pub mod local;
pub mod lookup;
pub mod notifier;
pub mod publisher;
pub mod server_data;
pub mod tlv;
mod view;

pub use data::NetworkData;
pub use view::{
    CONTEXT_ALOC_BASE, ContextEntry, NetworkDataView, OnMeshEntry, RouteEntry, SERVICE_ALOC_BASE,
    ServiceEntry,
};

#[cfg(test)]
mod backbone_tests;

#[cfg(test)]
mod tests;

#[cfg(all(test, feature = "ftd"))]
mod leader_tests;

#[cfg(test)]
mod notifier_tests;

#[cfg(all(test, feature = "ftd"))]
mod lookup_tests;

#[cfg(all(test, feature = "ftd"))]
mod publisher_tests;
