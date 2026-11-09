//! Radio selection for multi-radio devices (OT `RadioSelector`, simplified):
//! per neighbor, which radio links it was heard on and how reliable each is.
//! The forwarder asks [`RadioSelector::select`] for the link of a unicast
//! frame; results of transmissions (and TREL's deferred acks) and received
//! frames adjust the preferences.
//!
//! Differences from OpenThread: no probing of the TREL link while the 802.15.4
//! link is preferred, and neighbors are identified by RLOC16 in a small
//! fixed table.

use heapless::Vec;
use opentrust_core::types::Rloc16;

pub use crate::radio::RadioLink;

/// Preference change on a transmission error.
pub const CHANGE_ON_TX_ERROR: i16 = -35;
/// Preference change on a transmission success.
pub const CHANGE_ON_TX_SUCCESS: i16 = 25;
/// Preference change on a TREL deferred ack.
pub const CHANGE_ON_DEFERRED_ACK_SUCCESS: i16 = 25;
/// Preference change on a TREL deferred ack timeout.
pub const CHANGE_ON_DEFERRED_ACK_TIMEOUT: i16 = -100;
/// Preference change on a received frame.
pub const CHANGE_ON_RX: i16 = 15;
/// Preference of a radio link seen for the first time.
pub const INIT_PREFERENCE: u8 = 200;
/// Preference at which a link counts as good.
pub const HIGH_PREFERENCE: u8 = 220;

#[derive(Debug, Clone, Copy)]
struct Entry {
    neighbor: Rloc16,
    /// Preference per link; `None`: the neighbor was not seen on it.
    pref: [Option<u8>; 2],
}

/// Selection state for up to `N` neighbors.
#[derive(Debug, Clone)]
pub struct RadioSelector<const N: usize = 16> {
    entries: Vec<Entry, N>,
}

impl<const N: usize> Default for RadioSelector<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> RadioSelector<N> {
    /// No neighbors known.
    pub const fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    fn entry(&mut self, n: Rloc16) -> Option<&mut Entry> {
        if let Some(i) = self.entries.iter().position(|e| e.neighbor == n) {
            return Some(&mut self.entries[i]);
        }
        self.entries
            .push(Entry {
                neighbor: n,
                pref: [None; 2],
            })
            .ok()?;
        self.entries.last_mut()
    }

    /// Forget a neighbor.
    pub fn remove(&mut self, n: Rloc16) {
        if let Some(i) = self.entries.iter().position(|e| e.neighbor == n) {
            self.entries.swap_remove(i);
        }
    }

    /// The preference of `link` for `n` (`None`: not seen on it).
    pub fn preference(&self, n: Rloc16, link: RadioLink) -> Option<u8> {
        self.entries
            .iter()
            .find(|e| e.neighbor == n)
            .and_then(|e| e.pref[link.index()])
    }

    /// The radio link for a unicast frame to `n`: the one with the highest
    /// preference, TREL on a tie; the 802.15.4 radio for an unknown neighbor
    /// (it is the radio every Thread device has).
    pub fn select(&self, n: Rloc16) -> RadioLink {
        let p = |l| self.preference(n, l);
        match (p(RadioLink::Ieee802154), p(RadioLink::Trel)) {
            (_, None) => RadioLink::Ieee802154,
            (None, Some(_)) => RadioLink::Trel,
            (Some(a), Some(t)) if t >= a => RadioLink::Trel,
            _ => RadioLink::Ieee802154,
        }
    }

    fn update(&mut self, n: Rloc16, link: RadioLink, delta: i16, learn_on_gain: bool) {
        let Some(e) = self.entry(n) else { return };
        let slot = &mut e.pref[link.index()];
        match slot {
            Some(p) => *p = (i16::from(*p) + delta).clamp(0, 255) as u8,
            None if !learn_on_gain || delta > 0 => *slot = Some(INIT_PREFERENCE),
            None => {}
        }
    }

    /// A frame from `n` was received on `link` (OT `UpdateOnReceive`).
    pub fn on_receive(&mut self, n: Rloc16, link: RadioLink) {
        match self.preference(n, link) {
            Some(_) => self.update(n, link, CHANGE_ON_RX, false),
            None => self.update(n, link, 0, false),
        }
    }

    /// A unicast frame to `n` was sent on `link` (OT `UpdateOnSendDone`).
    /// TREL success is reported later with [`RadioSelector::on_deferred_ack`].
    pub fn on_send_done(&mut self, n: Rloc16, link: RadioLink, ok: bool) {
        if link == RadioLink::Trel && ok {
            return;
        }
        let delta = if ok {
            CHANGE_ON_TX_SUCCESS
        } else {
            CHANGE_ON_TX_ERROR
        };
        // A new link is only learned from a success.
        self.update(n, link, delta, true);
    }

    /// The deferred TREL ack of a packet to `n` arrived (`true`) or timed
    /// out (OT `UpdateOnDeferredAck`).
    pub fn on_deferred_ack(&mut self, n: Rloc16, ok: bool) {
        let delta = if ok {
            CHANGE_ON_DEFERRED_ACK_SUCCESS
        } else {
            CHANGE_ON_DEFERRED_ACK_TIMEOUT
        };
        if self.preference(n, RadioLink::Trel).is_some() {
            self.update(n, RadioLink::Trel, delta, false);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const N: Rloc16 = Rloc16(0x0800);

    #[test]
    fn unknown_neighbor_uses_the_802154_radio() {
        let s = RadioSelector::<4>::new();
        assert_eq!(s.select(N), RadioLink::Ieee802154);
    }

    #[test]
    fn trel_preferred_when_equal_and_dropped_after_ack_timeouts() {
        let mut s = RadioSelector::<4>::new();
        s.on_receive(N, RadioLink::Ieee802154);
        assert_eq!(s.select(N), RadioLink::Ieee802154);
        s.on_receive(N, RadioLink::Trel);
        assert_eq!(s.preference(N, RadioLink::Trel), Some(INIT_PREFERENCE));
        assert_eq!(s.select(N), RadioLink::Trel);
        // The 802.15.4 link proves reliable, TREL acks time out.
        for _ in 0..3 {
            s.on_send_done(N, RadioLink::Ieee802154, true);
        }
        assert_eq!(s.preference(N, RadioLink::Ieee802154), Some(255));
        s.on_deferred_ack(N, false);
        assert_eq!(s.preference(N, RadioLink::Trel), Some(100));
        assert_eq!(s.select(N), RadioLink::Ieee802154);
        // TREL recovers with acks and received frames.
        for _ in 0..8 {
            s.on_deferred_ack(N, true);
        }
        s.on_receive(N, RadioLink::Trel);
        assert_eq!(s.select(N), RadioLink::Trel);
    }

    #[test]
    fn failures_do_not_create_a_link_and_neighbors_can_be_forgotten() {
        let mut s = RadioSelector::<1>::new();
        s.on_send_done(N, RadioLink::Trel, false);
        assert_eq!(s.preference(N, RadioLink::Trel), None);
        s.on_send_done(N, RadioLink::Ieee802154, true);
        assert_eq!(s.preference(N, RadioLink::Ieee802154), Some(200));
        s.remove(N);
        assert_eq!(s.preference(N, RadioLink::Ieee802154), None);
    }
}
