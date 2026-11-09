//! TREL peer table (OT `Trel::PeerTable`, `Trel::Peer`) and the DNS-SD TXT
//! data of the `_trel._udp` service (OT `PeerDiscoverer::TxtData`).
//!
//! The platform discovers peers with DNS-SD (mDNS) and reports them with
//! [`Trel::peer_discovered`](super::Trel::peer_discovered); TXT data carries
//! the peer's extended address (`xa`) and extended PAN ID (`xp`).

use core::net::SocketAddrV6;

use heapless::Vec;
use opentrust_core::types::{ExtAddress, ExtPanId};
use opentrust_core::{Error, Result};

/// TXT key of the extended address.
pub const TXT_KEY_EXT_ADDRESS: &[u8] = b"xa";
/// TXT key of the extended PAN ID.
pub const TXT_KEY_EXT_PAN_ID: &[u8] = b"xp";

/// Encode the TXT data of our service into `out`; returns its length.
pub fn write_txt(ext: &ExtAddress, ext_pan_id: &ExtPanId, out: &mut [u8]) -> Result<usize> {
    let mut at = 0;
    for (key, val) in [
        (TXT_KEY_EXT_ADDRESS, &ext.0),
        (TXT_KEY_EXT_PAN_ID, &ext_pan_id.0),
    ] {
        let len = key.len() + 1 + val.len();
        let end = at + 1 + len;
        if out.len() < end {
            return Err(Error::NoBufs);
        }
        out[at] = len as u8;
        out[at + 1..at + 1 + key.len()].copy_from_slice(key);
        out[at + 1 + key.len()] = b'=';
        out[at + 2 + key.len()..end].copy_from_slice(val);
        at = end;
    }
    Ok(at)
}

/// Parse the TXT data of a peer's service: extended address and extended
/// PAN ID. [`Error::Parse`] if malformed or either key is missing / short;
/// unknown keys are skipped.
pub fn parse_txt(txt: &[u8]) -> Result<(ExtAddress, ExtPanId)> {
    let mut ext = None;
    let mut xpan = None;
    let mut rest = txt;
    while let Some((&len, tail)) = rest.split_first() {
        let len = usize::from(len);
        if len == 0 {
            rest = tail;
            continue;
        }
        if tail.len() < len {
            return Err(Error::Parse);
        }
        let (entry, next) = tail.split_at(len);
        rest = next;
        let Some(eq) = entry.iter().position(|&b| b == b'=') else {
            continue;
        };
        let (key, val) = (&entry[..eq], &entry[eq + 1..]);
        if key == TXT_KEY_EXT_ADDRESS {
            ext = Some(ExtAddress(val.try_into().map_err(|_| Error::Parse)?));
        } else if key == TXT_KEY_EXT_PAN_ID {
            xpan = Some(ExtPanId(val.try_into().map_err(|_| Error::Parse)?));
        }
    }
    Ok((ext.ok_or(Error::Parse)?, xpan.ok_or(Error::Parse)?))
}

/// A TREL peer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Peer {
    /// Extended address.
    pub ext_address: ExtAddress,
    /// Extended PAN ID of its network.
    pub ext_pan_id: ExtPanId,
    /// UDP address of its TREL service.
    pub addr: SocketAddrV6,
    pub(crate) tx_packet_number: u32,
    /// Unicast packets awaiting an ack, sent in the current / previous ack
    /// wait window (OT `mTrelCurrentPendingAcks` / `mTrelPreviousPendingAcks`).
    pub(crate) pending_current: u8,
    pub(crate) pending_previous: u8,
}

impl Peer {
    /// Unicast packets still waiting for their ack.
    pub fn pending_acks(&self) -> u8 {
        self.pending_current.saturating_add(self.pending_previous)
    }
}

/// Fixed-capacity peer table.
#[derive(Debug, Clone)]
pub struct PeerTable<const N: usize> {
    peers: Vec<Peer, N>,
}

impl<const N: usize> Default for PeerTable<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> PeerTable<N> {
    /// Empty table.
    pub const fn new() -> Self {
        Self { peers: Vec::new() }
    }

    /// Number of peers.
    pub fn len(&self) -> usize {
        self.peers.len()
    }

    /// `true` without peers.
    pub fn is_empty(&self) -> bool {
        self.peers.is_empty()
    }

    /// All peers.
    pub fn iter(&self) -> impl Iterator<Item = &Peer> {
        self.peers.iter()
    }

    /// The peer with extended address `ext`.
    pub fn find(&self, ext: &ExtAddress) -> Option<&Peer> {
        self.peers.iter().find(|p| p.ext_address == *ext)
    }

    pub(crate) fn find_mut(&mut self, ext: &ExtAddress) -> Option<&mut Peer> {
        self.peers.iter_mut().find(|p| p.ext_address == *ext)
    }

    /// Add a peer or update its address / extended PAN ID; returns `true`
    /// if the table changed. [`Error::NoBufs`] if full.
    pub fn add_or_update(
        &mut self,
        ext_address: ExtAddress,
        ext_pan_id: ExtPanId,
        addr: SocketAddrV6,
    ) -> Result<bool> {
        if let Some(p) = self.find_mut(&ext_address) {
            let changed = p.addr != addr || p.ext_pan_id != ext_pan_id;
            p.addr = addr;
            p.ext_pan_id = ext_pan_id;
            return Ok(changed);
        }
        self.peers
            .push(Peer {
                ext_address,
                ext_pan_id,
                addr,
                tx_packet_number: 0,
                pending_current: 0,
                pending_previous: 0,
            })
            .map_err(|_| Error::NoBufs)?;
        Ok(true)
    }

    /// Remove a peer.
    pub fn remove(&mut self, ext: &ExtAddress) -> bool {
        match self.peers.iter().position(|p| p.ext_address == *ext) {
            Some(i) => {
                self.peers.swap_remove(i);
                true
            }
            None => false,
        }
    }

    /// Remove all peers.
    pub fn clear(&mut self) {
        self.peers.clear();
    }

    pub(crate) fn iter_mut(&mut self) -> impl Iterator<Item = &mut Peer> {
        self.peers.iter_mut()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::net::Ipv6Addr;

    fn addr(n: u16) -> SocketAddrV6 {
        SocketAddrV6::new(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, n), 9000, 0, 0)
    }

    #[test]
    fn txt_round_trip_and_unknown_keys() {
        let ext = ExtAddress([1; 8]);
        let xp = ExtPanId([2; 8]);
        let mut b = [0u8; 64];
        let n = write_txt(&ext, &xp, &mut b).unwrap();
        assert_eq!(parse_txt(&b[..n]).unwrap(), (ext, xp));
        // An extra "vn=..." entry in front and an empty entry are skipped.
        let mut t = std::vec![6u8];
        t.extend_from_slice(b"vn=1.4");
        t.push(0);
        t.extend_from_slice(&b[..n]);
        assert_eq!(parse_txt(&t).unwrap(), (ext, xp));
        // Missing key, short value, truncated entry.
        assert_eq!(parse_txt(&b[..b[0] as usize + 1]), Err(Error::Parse));
        assert_eq!(parse_txt(&[5, b'x', b'a', b'=', 1, 2]), Err(Error::Parse));
        assert_eq!(parse_txt(&[40, b'x']), Err(Error::Parse));
        assert_eq!(write_txt(&ext, &xp, &mut [0u8; 10]), Err(Error::NoBufs));
    }

    #[test]
    fn peer_table() {
        let mut t = PeerTable::<2>::new();
        let (a, b, c) = (ExtAddress([1; 8]), ExtAddress([2; 8]), ExtAddress([3; 8]));
        let xp = ExtPanId([9; 8]);
        assert_eq!(t.add_or_update(a, xp, addr(1)), Ok(true));
        assert_eq!(t.add_or_update(a, xp, addr(1)), Ok(false));
        assert_eq!(t.add_or_update(a, xp, addr(2)), Ok(true));
        assert_eq!(t.find(&a).unwrap().addr, addr(2));
        t.add_or_update(b, xp, addr(3)).unwrap();
        assert_eq!(t.add_or_update(c, xp, addr(4)), Err(Error::NoBufs));
        assert_eq!(t.len(), 2);
        assert!(t.remove(&a));
        assert!(!t.remove(&a));
        assert!(t.find(&a).is_none() && t.find(&b).is_some());
    }
}
