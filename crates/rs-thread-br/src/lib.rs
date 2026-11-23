//! Thread Border Router (ot-br-posix port) components.
//!
//! Part of rs-thread, a pure Rust implementation of the Thread 1.4.1 protocol.
//!
//! | module | contents |
//! |--------|----------|
//! | [`tun`] | Linux/macOS TUN interface for injecting Thread IPv6 traffic into the host network stack |
//! | [`routing`] | OMR prefix selection, RA/RIO advertisement to the backbone link |
//! | [`srp_proxy`] | SRP advertising proxy: bridges Thread SRP registrations to backbone mDNS |
//! | [`dns_proxy`] | DNS proxy: resolves Thread DNS queries via an upstream DNS-SD/unicast resolver |

pub mod dns_proxy;
pub mod routing;
pub mod srp_proxy;
pub mod tun;
