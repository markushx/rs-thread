//! Thread Radio Encapsulation Link (Thread 1.3 TREL; OT `src/core/radio/trel_*`):
//! Thread over an infrastructure network (Wi-Fi / Ethernet) next to or instead
//! of the IEEE 802.15.4 radio. Feature `trel` (off by default, so embedded
//! 802.15.4-only builds do not carry it).
//!
//! The link is sans-IO. The platform supplies the UDP socket and DNS-SD
//! through [`TrelPlatform`]:
//!
//! - it browses `_trel._udp` and reports peers with
//!   [`Trel::peer_discovered`] / [`Trel::peer_removed`]
//!   ([`parse_txt`] decodes the service's TXT data: extended address `xa`
//!   and extended PAN ID `xp`), and advertises our own service
//!   ([`TrelPlatform::register_service`]);
//! - it hands received UDP datagrams to [`Trel::handle_received`], which
//!   answers acks and returns the encapsulated 802.15.4 frame for the MAC;
//! - the MAC's frames go out with [`Trel::transmit`] (broadcast to all
//!   peers, unicast with an ack request; the ack is tracked as a "deferred
//!   ack" and a missing one is an [`Event::AckTimeout`] from [`Trel::poll`]).
//!
//! Layers:
//!
//! - [`packet`]: the TREL header codec;
//! - [`peer`]: the peer table and TXT data;
//! - [`security`]: [`TrelSecurity`], MAC frame security with the TREL key
//!   (`rs_thread_core::crypto::kdf::trel_key`) and a separate frame counter;
//! - [`selector`]: [`RadioSelector`], a narrow version of OT `RadioSelector`
//!   that the [`MeshForwarder`](crate::forwarder::MeshForwarder) consults to
//!   tag frames with the [`RadioLink`](crate::radio::RadioLink) to use.

pub mod link;
pub mod packet;
pub mod peer;
pub mod security;
pub mod selector;

pub use link::{ACK_WAIT_WINDOW, Dest, Event, MAX_FRAME_LEN, RX_RSSI, Rx, Trel, TrelPlatform};
pub use packet::{Header, PacketType};
pub use peer::{Peer, PeerTable, parse_txt, write_txt};
pub use security::TrelSecurity;
pub use selector::RadioSelector;

#[cfg(test)]
mod tests;
