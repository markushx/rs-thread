//! IPv6 fragmentation and reassembly above 6LoWPAN (OT `Ip6::FragmentDatagram`
//! and `Ip6::HandleFragment`, `OPENTHREAD_CONFIG_IP6_FRAGMENTATION_ENABLE`).
//!
//! A datagram larger than the IPv6 minimum MTU (1280 bytes) is cut into
//! fragments that each fit the minimum MTU; fragments for this device are
//! put together again in one of a few reassembly slots (datagrams of up to
//! [`MAX_DATAGRAM_LEN`] bytes, 2000 as OT's `IP6_MAX_ASSEMBLED_DATAGRAM`).
//!
//! # Deviations from OT
//!
//! - OT completes a datagram when the last fragment arrives, whether or not
//!   earlier ones are missing; here every 8-byte unit must have arrived.
//! - A slot that times out (60 s, `kReassemblyTimeout`) is dropped when the
//!   next fragment arrives; there is no timer and no ICMPv6 Time Exceeded
//!   message.
//! - The next header of the datagram is patched in the header that precedes
//!   the Fragment header (OT always writes the IPv6 header, which is wrong
//!   behind a Hop-by-Hop header).

use core::net::Ipv6Addr;

use rs_thread_core::time::{Duration, Instant};
use rs_thread_core::{Error, Result};

use crate::header::{
    EXT_UNIT, FragmentHeader, Ipv6Header, MAX_DATAGRAM_LEN, MIN_MTU, PROTO_DST_OPTS,
    PROTO_FRAGMENT, PROTO_HOP_OPTS, PROTO_ROUTING,
};

/// Reassembly slots.
pub const SLOTS: usize = 2;
/// Time a partially received datagram is kept (OT `kReassemblyTimeout`).
pub const REASSEMBLY_TIMEOUT: Duration = Duration::from_secs(60);

/// Length of the unfragmentable part of `dg`: the IPv6 header and the
/// extension headers before a Fragment header or the upper layer, and the
/// position of the next-header byte that points at what follows it.
fn unfragmentable(dg: &[u8]) -> Result<(usize, usize)> {
    let h = Ipv6Header::parse(dg)?;
    let mut nh = h.next_header;
    let mut off = Ipv6Header::LEN;
    let mut at = 6;
    while matches!(nh, PROTO_HOP_OPTS | PROTO_DST_OPTS | PROTO_ROUTING) {
        let hdr = dg.get(off..off + 2).ok_or(Error::Parse)?;
        at = off;
        nh = hdr[0];
        off += (usize::from(hdr[1]) + 1) * EXT_UNIT;
    }
    Ok((off, at))
}

/// Cut `dg` (a complete datagram, possibly longer than the minimum MTU) into
/// fragments of at most [`MIN_MTU`] bytes and pass each to `emit`. `id` is
/// the fragment identification. A datagram that fits is passed on as is.
pub fn fragment_datagram(
    dg: &[u8],
    id: u32,
    mut emit: impl FnMut(&[u8]) -> Result<()>,
) -> Result<()> {
    if dg.len() <= MIN_MTU {
        return emit(dg);
    }
    let (off, at) = unfragmentable(dg)?;
    let max = (MIN_MTU - off - FragmentHeader::LEN) & !7;
    if max == 0 {
        return Err(Error::InvalidArgs);
    }
    let orig_nh = *dg.get(at).ok_or(Error::Parse)?;
    let mut buf = [0u8; MIN_MTU];
    let mut pos = off;
    while pos < dg.len() {
        let n = (dg.len() - pos).min(max);
        let more = pos + n < dg.len();
        buf[..off].copy_from_slice(&dg[..off]);
        buf[at] = PROTO_FRAGMENT;
        FragmentHeader {
            next_header: orig_nh,
            offset: (pos - off) as u16,
            more,
            id,
        }
        .write(&mut buf[off..])?;
        buf[off + FragmentHeader::LEN..off + FragmentHeader::LEN + n]
            .copy_from_slice(&dg[pos..pos + n]);
        let total = off + FragmentHeader::LEN + n;
        let payload_len = (total - Ipv6Header::LEN) as u16;
        buf[4..6].copy_from_slice(&payload_len.to_be_bytes());
        emit(&buf[..total])?;
        pos += n;
    }
    Ok(())
}

#[derive(Debug, Clone)]
struct Slot {
    src: Ipv6Addr,
    dst: Ipv6Addr,
    id: u32,
    since: Instant,
    /// Length of the unfragmentable part.
    unfrag: usize,
    /// Fragmentable length once the last fragment arrived.
    total: Option<usize>,
    /// 8-byte units received.
    got: [u64; MAX_DATAGRAM_LEN.div_ceil(8 * 64)],
    buf: [u8; MAX_DATAGRAM_LEN],
}

/// Reassembly slots of the IPv6 layer.
#[derive(Debug, Clone)]
pub struct Reassembler {
    slots: [Option<Slot>; SLOTS],
}

impl Default for Reassembler {
    fn default() -> Self {
        Self::new()
    }
}

impl Reassembler {
    /// No partial datagrams.
    pub const fn new() -> Self {
        Self {
            slots: [const { None }; SLOTS],
        }
    }

    /// Drop all partial datagrams (OT `CleanupFragmentationBuffer`).
    pub fn clear(&mut self) {
        self.slots = [const { None }; SLOTS];
    }

    /// Add the fragment in `dg` (a datagram whose first extension header
    /// chain ends in a non-atomic Fragment header at offset `frag_at`).
    /// When it completes a datagram, the reassembled datagram (without the
    /// Fragment header) is written to `out` and its length returned. Errors:
    /// [`Error::NoBufs`] (too large or no free slot), [`Error::Drop`].
    pub fn add(
        &mut self,
        now: Instant,
        dg: &[u8],
        frag_at: usize,
        f: &FragmentHeader,
        out: &mut [u8],
    ) -> Result<Option<usize>> {
        for s in &mut self.slots {
            if s.as_ref()
                .is_some_and(|s| now.saturating_duration_since(s.since) >= REASSEMBLY_TIMEOUT)
            {
                *s = None;
            }
        }
        let h = Ipv6Header::parse(dg)?;
        let payload = dg
            .get(frag_at + FragmentHeader::LEN..Ipv6Header::LEN + usize::from(h.payload_len))
            .ok_or(Error::Parse)?;
        let offset = usize::from(f.offset);
        if frag_at + offset + payload.len() > MAX_DATAGRAM_LEN
            || (f.more && payload.len() % 8 != 0)
            || payload.is_empty()
        {
            return Err(Error::NoBufs);
        }
        let i = match self.slots.iter().position(|s| {
            s.as_ref()
                .is_some_and(|s| s.id == f.id && s.src == h.src && s.dst == h.dst)
        }) {
            Some(i) => i,
            None => {
                let i = self
                    .slots
                    .iter()
                    .position(Option::is_none)
                    .ok_or(Error::NoBufs)?;
                let mut s = Slot {
                    src: h.src,
                    dst: h.dst,
                    id: f.id,
                    since: now,
                    unfrag: frag_at,
                    total: None,
                    got: [0; MAX_DATAGRAM_LEN.div_ceil(8 * 64)],
                    buf: [0; MAX_DATAGRAM_LEN],
                };
                s.buf[..frag_at].copy_from_slice(&dg[..frag_at]);
                self.slots[i] = Some(s);
                i
            }
        };
        let Some(s) = self.slots[i].as_mut() else {
            return Err(Error::Drop);
        };
        s.buf[s.unfrag + offset..s.unfrag + offset + payload.len()].copy_from_slice(payload);
        let first = offset / 8;
        let units = payload.len().div_ceil(8);
        for u in first..first + units {
            s.got[u / 64] |= 1 << (u % 64);
        }
        if !f.more {
            s.total = Some(offset + payload.len());
        }
        let Some(total) = s.total else {
            return Ok(None);
        };
        let all = total.div_ceil(8);
        if (0..all).any(|u| s.got[u / 64] & (1 << (u % 64)) == 0) {
            return Ok(None);
        }
        // Complete: the Fragment header is gone, the next header of the
        // header before it now says what the fragments carried.
        let len = s.unfrag + total;
        let (_, at) = unfragmentable(&s.buf[..len]).unwrap_or((0, 6));
        s.buf[at] = f.next_header;
        s.buf[4..6].copy_from_slice(&((len - Ipv6Header::LEN) as u16).to_be_bytes());
        let o = out.get_mut(..len).ok_or(Error::NoBufs)?;
        o.copy_from_slice(&s.buf[..len]);
        self.slots[i] = None;
        Ok(Some(len))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::header::PROTO_UDP;

    fn datagram(len: usize) -> ([u8; MAX_DATAGRAM_LEN], usize) {
        let mut b = [0u8; MAX_DATAGRAM_LEN];
        let src = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1);
        let dst = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2);
        let mut h = Ipv6Header::new(PROTO_UDP, 64, src, dst);
        h.payload_len = (len - Ipv6Header::LEN) as u16;
        h.write(&mut b).unwrap();
        for (i, x) in b[Ipv6Header::LEN..len].iter_mut().enumerate() {
            *x = (i % 251) as u8;
        }
        (b, len)
    }

    struct Frags {
        bufs: [[u8; MIN_MTU]; 4],
        lens: [usize; 4],
        n: usize,
    }

    impl Default for Frags {
        fn default() -> Self {
            Self {
                bufs: [[0; MIN_MTU]; 4],
                lens: [0; 4],
                n: 0,
            }
        }
    }

    impl Frags {
        fn push(&mut self, f: &[u8]) -> Result<()> {
            let i = self.n;
            self.bufs.get_mut(i).ok_or(Error::NoBufs)?[..f.len()].copy_from_slice(f);
            self.lens[i] = f.len();
            self.n += 1;
            Ok(())
        }
        fn len(&self) -> usize {
            self.n
        }
        fn get(&self, i: usize) -> &[u8] {
            &self.bufs[i][..self.lens[i]]
        }
    }

    #[test]
    fn small_datagram_is_not_fragmented() {
        let (b, n) = datagram(1000);
        let mut count = 0;
        fragment_datagram(&b[..n], 1, |f| {
            assert_eq!(f, &b[..n]);
            count += 1;
            Ok(())
        })
        .unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn fragments_reassemble_in_any_order() {
        let (b, n) = datagram(2000);
        let mut frags = Frags::default();
        fragment_datagram(&b[..n], 7, |f| frags.push(f)).unwrap();
        assert_eq!(frags.len(), 2);
        assert!((0..frags.len()).all(|i| frags.get(i).len() <= MIN_MTU));
        for order in [[0, 1], [1, 0]] {
            let mut r = Reassembler::new();
            let mut out = [0u8; MAX_DATAGRAM_LEN];
            let mut done = None;
            for k in order {
                let f = frags.get(k);
                let p = crate::header::parse_datagram(f).unwrap();
                let fh = p.fragment.unwrap();
                assert!(!fh.is_atomic());
                done = r
                    .add(Instant::from_secs(1), f, p.upper_offset, &fh, &mut out)
                    .unwrap();
            }
            assert_eq!(done, Some(n));
            assert_eq!(&out[..n], &b[..n]);
        }
    }

    #[test]
    fn missing_fragment_and_timeout() {
        let (b, n) = datagram(2000);
        let mut frags = Frags::default();
        fragment_datagram(&b[..n], 7, |f| frags.push(f)).unwrap();
        let mut r = Reassembler::new();
        let mut out = [0u8; MAX_DATAGRAM_LEN];
        let f = frags.get(1);
        let p = crate::header::parse_datagram(f).unwrap();
        let fh = p.fragment.unwrap();
        assert_eq!(
            r.add(Instant::from_secs(1), f, p.upper_offset, &fh, &mut out),
            Ok(None)
        );
        // The first fragment arrives after the timeout: a new slot, still
        // incomplete.
        let f = frags.get(0);
        let p = crate::header::parse_datagram(f).unwrap();
        let fh = p.fragment.unwrap();
        assert_eq!(
            r.add(Instant::from_secs(100), f, p.upper_offset, &fh, &mut out),
            Ok(None)
        );
    }
}
