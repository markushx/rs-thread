//! Which MAC functions the rs-thread MAC must provide in software, derived
//! from the radio's [`RadioCaps`]. rs-thread addition (esp-rs/openthread
//! instead panics or wraps the radio in its `MacRadio`).

use super::{Capabilities, MacCapabilities, RadioCaps};

bitflags::bitflags! {
    /// MAC functions the radio does *not* offload, which the rs-thread MAC
    /// therefore has to provide in software. See [`RadioCaps::soft_mac_needs`].
    #[derive(Debug, Default, Copy, Clone, Eq, PartialEq, Hash)]
    pub struct SoftMacNeeds: u16 {
        /// Send (immediate / enhanced) ACKs for received frames (no `MacCapabilities::RX_ACK`).
        const SEND_ACK = 1 << 0;
        /// Receive and match the ACK of a transmitted frame (no `MacCapabilities::TX_ACK`).
        const MATCH_ACK = 1 << 1;
        /// Run the ACK timeout timer (no `Capabilities::ACK_TIMEOUT`).
        const ACK_TIMEOUT = 1 << 2;
        /// Retransmit unacknowledged frames (no `Capabilities::TRANSMIT_RETRIES`).
        const RETRANSMIT = 1 << 3;
        /// CSMA-CA backoff (no `Capabilities::CSMA_BACKOFF`).
        const CSMA = 1 << 4;
        /// Frame counter, CSL IE and AES-CCM* at transmit time (no `Capabilities::TRANSMIT_SEC`).
        const TX_SECURITY = 1 << 5;
        /// CSL receive windows (no `Capabilities::RECEIVE_TIMING`).
        const CSL = 1 << 6;
        /// Transmit at a given radio-clock time (no `Capabilities::TRANSMIT_TIMING`).
        const TIMED_TX = 1 << 7;
        /// Energy scan by sampling RSSI (no `Capabilities::ENERGY_SCAN`).
        const ENERGY_SCAN = 1 << 8;
        /// PAN ID / short / extended address filtering (any `FILTER_*` missing).
        const ADDR_FILTER = 1 << 9;
        /// Source-address-match table for Frame Pending (no `MacCapabilities::SRC_MATCH`).
        const SRC_MATCH = 1 << 10;
    }
}

#[cfg(feature = "defmt")]
impl defmt::Format for SoftMacNeeds {
    fn format(&self, f: defmt::Formatter<'_>) {
        defmt::write!(f, "SoftMacNeeds({=u16:#x})", self.bits())
    }
}

#[cfg(feature = "defmt")]
impl defmt::Format for Capabilities {
    fn format(&self, f: defmt::Formatter<'_>) {
        defmt::write!(f, "Capabilities({=u16:#x})", self.bits())
    }
}

#[cfg(feature = "defmt")]
impl defmt::Format for MacCapabilities {
    fn format(&self, f: defmt::Formatter<'_>) {
        defmt::write!(f, "MacCapabilities({=u16:#x})", self.bits())
    }
}

impl RadioCaps {
    /// Does the radio acknowledge received frames by itself (HW auto-ACK)?
    pub const fn hw_auto_ack(&self) -> bool {
        self.mac.contains(MacCapabilities::RX_ACK)
    }

    /// Does the radio receive and match ACKs inside `transmit`?
    pub const fn hw_tx_ack(&self) -> bool {
        self.mac.contains(MacCapabilities::TX_ACK)
    }

    /// Does the radio run the ACK timeout itself?
    pub const fn hw_ack_timeout(&self) -> bool {
        self.phy.contains(Capabilities::ACK_TIMEOUT)
    }

    /// Does the radio retransmit unacknowledged frames itself?
    pub const fn hw_retransmit(&self) -> bool {
        self.phy.contains(Capabilities::TRANSMIT_RETRIES)
    }

    /// Does the radio do CSMA-CA backoff itself?
    pub const fn hw_csma(&self) -> bool {
        self.phy.contains(Capabilities::CSMA_BACKOFF)
    }

    /// Does the radio finish (counter, CSL IE, CCM*) transmitted frames itself?
    pub const fn hw_tx_security(&self) -> bool {
        self.phy.contains(Capabilities::TRANSMIT_SEC)
    }

    /// Does the radio support timed receive windows (needed for CSL)?
    pub const fn hw_csl(&self) -> bool {
        self.phy.contains(Capabilities::RECEIVE_TIMING)
    }

    /// Does the radio support energy scan?
    pub const fn hw_energy_scan(&self) -> bool {
        self.phy.contains(Capabilities::ENERGY_SCAN)
    }

    /// The MAC functions the software MAC must provide on top of this radio.
    pub const fn soft_mac_needs(&self) -> SoftMacNeeds {
        let mut n = SoftMacNeeds::empty();
        if !self.hw_auto_ack() {
            n = n.union(SoftMacNeeds::SEND_ACK);
        }
        if !self.hw_tx_ack() {
            n = n.union(SoftMacNeeds::MATCH_ACK);
        }
        if !self.hw_ack_timeout() {
            n = n.union(SoftMacNeeds::ACK_TIMEOUT);
        }
        if !self.hw_retransmit() {
            n = n.union(SoftMacNeeds::RETRANSMIT);
        }
        if !self.hw_csma() {
            n = n.union(SoftMacNeeds::CSMA);
        }
        if !self.hw_tx_security() {
            n = n.union(SoftMacNeeds::TX_SECURITY);
        }
        if !self.hw_csl() {
            n = n.union(SoftMacNeeds::CSL);
        }
        if !self.phy.contains(Capabilities::TRANSMIT_TIMING) {
            n = n.union(SoftMacNeeds::TIMED_TX);
        }
        if !self.hw_energy_scan() {
            n = n.union(SoftMacNeeds::ENERGY_SCAN);
        }
        let filters = MacCapabilities::FILTER_PAN_ID
            .union(MacCapabilities::FILTER_SHORT_ADDR)
            .union(MacCapabilities::FILTER_EXT_ADDR);
        if !self.mac.contains(filters) {
            n = n.union(SoftMacNeeds::ADDR_FILTER);
        }
        if !self.mac.contains(MacCapabilities::SRC_MATCH) {
            n = n.union(SoftMacNeeds::SRC_MATCH);
        }
        n
    }
}
