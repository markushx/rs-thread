//! The Service Registration Protocol (RFC 9665): the client (`srp-client`;
//! OT `OPENTHREAD_CONFIG_SRP_CLIENT_ENABLE`) and the server (`srp-server`;
//! OT `OPENTHREAD_CONFIG_SRP_SERVER_ENABLE`).

#[cfg(feature = "srp-client")]
mod client;
#[cfg(feature = "srp-client")]
pub mod discovery;
#[cfg(feature = "srp-server")]
pub mod server;

#[cfg(feature = "srp-client")]
pub use client::*;
