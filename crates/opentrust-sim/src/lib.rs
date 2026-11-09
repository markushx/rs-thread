//! Simulated IEEE 802.15.4 medium and a multi-node network harness for
//! OpenTrust (std, for tests and tools).
//!
//! Part of OpenTrust, a pure Rust implementation of the Thread 1.4.1 protocol.
//!
//! [`Network`] owns N full-stack [`Instance`](opentrust_instance::Instance)s
//! and a [`Medium`]. The medium models what `docs/radio-contract.md` asks of
//! a radio with MAC offload (software CSMA is in the MAC, the radio does
//! CCA, retransmissions, ACK reception and ACK sending):
//!
//! - a link matrix with RSSI and a loss probability per direction (no entry:
//!   out of range), deterministic seeded randomness;
//! - frames are delivered to the nodes whose radio is in receive mode on the
//!   channel of the frame (a sleeping radio drops them);
//! - a unicast frame with the AR bit is acknowledged by the receiving radio
//!   if it matches the radio's PAN ID / address filter; the ACK carries the
//!   Frame Pending bit of the radio's source match table for MAC Data
//!   Requests; the transmitter retries up to 15 times when no ACK arrives
//!   (each try and each ACK is lost independently);
//! - CCA can be forced busy for a channel (jamming);
//! - virtual time: [`Network::run_for`] steps all instances to the earliest
//!   deadline. Frames take no air time.
//!
//! The harness runs every instance's `poll` / radio-action loop until the
//! network is quiescent at the current virtual time, then advances time to
//! the earliest deadline.

mod network;
mod radio;
mod rng;

pub use network::{Kind, Network, SimInstance, SimNode, SimSettings, TxRecord};
pub use radio::{Medium, SimRadio};
pub use rng::SimRng;

/// Extended address of node `n` (`02:00:00:00:00:00:00:n`).
pub fn ext_address(n: u8) -> opentrust_instance::ExtAddress {
    opentrust_instance::ExtAddress([0x02, 0, 0, 0, 0, 0, 0, n])
}
