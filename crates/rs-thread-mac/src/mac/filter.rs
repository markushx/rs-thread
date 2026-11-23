//! Receive filtering (OpenThread `Mac::HandleReceivedFrame` destination and
//! source address checks).
//!
//! The MAC filters in software even when the radio filters too, as
//! OpenThread does: a radio's filter only decides what it ACKs.

use rs_thread_core::types::{ExtAddress, PanId, ShortAddress};

use crate::frame::{Address, Frame};

/// The addressing state the filter checks against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FilterParams {
    /// Our PAN ID.
    pub pan_id: PanId,
    /// Our short address ([`ShortAddress::INVALID`] if none).
    pub short: ShortAddress,
    /// Alternate short address (router transition), if any.
    pub alt_short: Option<ShortAddress>,
    /// Our extended address.
    pub ext: ExtAddress,
    /// Broadcasts are only accepted with the receiver on when idle
    /// (OpenThread `FilterDestShortAddress`).
    pub rx_on_when_idle: bool,
}

/// Why a frame was filtered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum FilterError {
    /// Destination address is not ours (`kErrorDestinationAddressFiltered`).
    DstAddress,
    /// Destination PAN ID is neither ours nor broadcast.
    DstPan,
    /// The source is our own extended address
    /// (`kErrorInvalidSourceAddress`, duplicate address protection).
    SrcIsSelf,
}

impl FilterParams {
    /// Is `dst` (a short address) one of ours, or an acceptable broadcast?
    fn short_dst_ok(&self, dst: ShortAddress) -> bool {
        (dst == self.short && dst != ShortAddress::INVALID)
            || self
                .alt_short
                .is_some_and(|a| a == dst && a != ShortAddress::INVALID)
            || (dst == ShortAddress::BROADCAST && self.rx_on_when_idle)
    }

    /// Is the frame addressed to us as a unicast (a frame we must ACK)?
    pub fn is_unicast_to_us(&self, f: &Frame<'_>) -> bool {
        match f.dst_address() {
            Address::Short(s) => s != ShortAddress::BROADCAST && self.short_dst_ok(s),
            Address::Extended(e) => e == self.ext,
            Address::None => false,
        }
    }

    /// Check a parsed (non-ACK) frame.
    pub fn check(&self, f: &Frame<'_>) -> Result<(), FilterError> {
        match f.dst_address() {
            Address::None => {}
            Address::Short(s) => {
                if !self.short_dst_ok(s) {
                    return Err(FilterError::DstAddress);
                }
            }
            Address::Extended(e) => {
                if e != self.ext {
                    return Err(FilterError::DstAddress);
                }
            }
        }
        if let Some(pan) = f.dst_pan_id()
            && pan != PanId::BROADCAST
            && pan != self.pan_id
        {
            return Err(FilterError::DstPan);
        }
        if f.src_address() == Address::Extended(self.ext) {
            return Err(FilterError::SrcIsSelf);
        }
        Ok(())
    }
}
