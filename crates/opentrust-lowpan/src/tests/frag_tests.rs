//! Mesh header, fragment header, fragmentation and reassembly tests.

use std::vec::Vec;

use opentrust_core::Error;
use opentrust_core::time::{Duration, Instant};
use opentrust_core::types::{ExtAddress, ShortAddress};
use opentrust_mac::frame::Address;

use super::{LONG_DST, LONG_SRC, ot_contexts};
use crate::frag::{FragmentHeader, Fragmenter, TagCounter};
use crate::ip6::{Ipv6Header, PROTO_UDP, UdpHeader};
use crate::iphc::NoContexts;
use crate::mesh::MeshHeader;
use crate::reassembly::{REASSEMBLY_TIMEOUT, Reassembled, Reassembler};

// ---- OpenThread test_lowpan.cpp: TestLowpanMeshHeader ----------------------

#[test]
fn ot_test_lowpan_mesh_header() {
    const SRC: u16 = 0x100;
    const DST: u16 = 0x200;
    const H1: [u8; 5] = [0xb1, 0x01, 0x00, 0x02, 0x00];
    const H2: [u8; 6] = [0xbf, 0x20, 0x01, 0x00, 0x02, 0x00];
    const H3: [u8; 6] = [0xbf, 0x01, 0x01, 0x00, 0x02, 0x00];
    let mut frame = [0u8; 127];

    let h = MeshHeader::new(SRC, DST, 1);
    assert_eq!(h.len(), H1.len());
    assert_eq!(h.write(&mut frame).unwrap(), H1.len());
    assert_eq!(&frame[..H1.len()], &H1);
    assert!(MeshHeader::is_mesh_header(&H1));
    let (p, l) = MeshHeader::parse(&H1).unwrap();
    assert_eq!((p, l), (h, 5));
    assert_eq!(MeshHeader::parse(&H1[..4]), Err(Error::Parse));

    let h = MeshHeader::new(SRC, DST, 0x20);
    assert_eq!(h.len(), H2.len());
    assert_eq!(h.write(&mut frame).unwrap(), H2.len());
    assert_eq!(&frame[..H2.len()], &H2);
    assert!(MeshHeader::is_mesh_header(&H2));
    let (p, l) = MeshHeader::parse(&H2).unwrap();
    assert_eq!((p, l), (h, 6));
    assert_eq!(MeshHeader::parse(&H2[..5]), Err(Error::Parse));

    // Deep-hops encoding of a small value parses; re-encoding is compact.
    let (p, l) = MeshHeader::parse(&H3).unwrap();
    assert_eq!((p.source, p.destination, p.hops_left, l), (SRC, DST, 1, 6));
    assert_eq!(p.write(&mut frame).unwrap(), H1.len());
    assert_eq!(MeshHeader::parse(&H3[..5]), Err(Error::Parse));
}

#[test]
fn mesh_header_extras() {
    // 64-bit address forms are rejected (Thread only uses short).
    assert_eq!(MeshHeader::parse(&[0x81, 0, 1, 0, 2]), Err(Error::Parse));
    assert_eq!(MeshHeader::parse(&[0x91, 0, 1, 0, 2]), Err(Error::Parse));
    assert!(!MeshHeader::is_mesh_header(&[0x7a, 0, 0, 0, 0]));
    assert!(!MeshHeader::is_mesh_header(&[0xb1, 0, 0, 0]));
    let mut h = MeshHeader::new(1, 2, 1);
    h.decrement_hops_left();
    assert_eq!(h.hops_left, 0);
    h.decrement_hops_left();
    assert_eq!(h.hops_left, 0);
    // Hops 14 -> short form, 15 -> deep form.
    assert_eq!(MeshHeader::new(1, 2, 14).len(), 5);
    assert_eq!(MeshHeader::new(1, 2, 15).len(), 6);
    let mut b = [0u8; 6];
    assert_eq!(MeshHeader::new(1, 2, 255).write(&mut b), Ok(6));
    assert_eq!(MeshHeader::parse(&b).unwrap().0.hops_left, 255);
    assert_eq!(
        MeshHeader::new(1, 2, 255).write(&mut b[..5]),
        Err(Error::NoBufs)
    );
}

// ---- OpenThread test_lowpan.cpp: TestLowpanFragmentHeader ------------------

#[test]
fn ot_test_lowpan_fragment_header() {
    const SIZE: u16 = 0x7ef;
    const TAG: u16 = 0x1234;
    const OFFSET: u16 = 100 * 8;
    const F1: [u8; 4] = [0xc7, 0xef, 0x12, 0x34];
    const F2: [u8; 5] = [0xe7, 0xef, 0x12, 0x34, 0x64];
    const F3: [u8; 5] = [0xe7, 0xef, 0x12, 0x34, 0x00];
    let mut frame = [0u8; 127];

    let h = FragmentHeader::first(SIZE, TAG);
    assert_eq!(h.write(&mut frame), Ok(4));
    assert_eq!(&frame[..4], &F1);
    assert!(FragmentHeader::is_fragment_header(&F1));
    let (p, l) = FragmentHeader::parse(&F1).unwrap();
    assert_eq!((p, l), (h, 4));
    assert_eq!(FragmentHeader::parse(&F1[..3]), Err(Error::Parse));

    for off in [OFFSET, OFFSET + 1, OFFSET + 7] {
        let h = FragmentHeader::next(SIZE, TAG, off);
        assert_eq!(h.write(&mut frame), Ok(5));
        assert_eq!(&frame[..5], &F2);
    }
    assert!(FragmentHeader::is_fragment_header(&F2));
    let (p, l) = FragmentHeader::parse(&F2).unwrap();
    assert_eq!(
        (p.datagram_size, p.datagram_tag, p.datagram_offset, l),
        (SIZE, TAG, OFFSET, 5)
    );
    assert_eq!(FragmentHeader::parse(&F2[..4]), Err(Error::Parse));

    // FRAGN with offset 0 parses.
    let (p, l) = FragmentHeader::parse(&F3).unwrap();
    assert_eq!(
        (p.datagram_size, p.datagram_tag, p.datagram_offset, l),
        (SIZE, TAG, 0, 5)
    );
    assert_eq!(FragmentHeader::parse(&F3[..4]), Err(Error::Parse));

    for bad in [
        [0xe8, 0xef, 0x12, 0x34, 0x64],
        [0xd0, 0xef, 0x12, 0x34, 0x64],
        [0x90, 0xef, 0x12, 0x34, 0x64],
    ] {
        assert!(!FragmentHeader::is_fragment_header(&bad));
        assert_eq!(FragmentHeader::parse(&bad), Err(Error::Parse));
    }
}

// ---- Fragmenter / Reassembler ----------------------------------------------

fn datagram(n: usize, sp: u16, dp: u16) -> Vec<u8> {
    let src = opentrust_core::types::ipv6::link_local(&ExtAddress([
        0, 0, 0x5e, 0xef, 0x10, 0x22, 0x11, 0,
    ]));
    let dst = opentrust_core::types::ipv6::link_local(&ExtAddress([
        0, 0, 0x5e, 0xef, 0x10, 0xaa, 0xbb, 0xcc,
    ]));
    let mut d = Vec::new();
    let mut h = [0u8; 40];
    Ipv6Header {
        traffic_class: 0,
        flow_label: 0,
        payload_len: (8 + n) as u16,
        next_header: PROTO_UDP,
        hop_limit: 64,
        src,
        dst,
    }
    .write(&mut h)
    .unwrap();
    d.extend_from_slice(&h);
    let mut u = [0u8; 8];
    UdpHeader {
        src_port: sp,
        dst_port: dp,
        length: (8 + n) as u16,
        checksum: 0xbeef,
    }
    .write(&mut u)
    .unwrap();
    d.extend_from_slice(&u);
    d.extend((0..n).map(|i| (i * 7 + 3) as u8));
    d
}

fn fragment(d: &[u8], tag: u16, mesh: Option<MeshHeader>, max: usize) -> Vec<Vec<u8>> {
    let ctxs = ot_contexts();
    let mut f = Fragmenter::new(&ctxs, LONG_SRC, LONG_DST, d, tag, mesh, max);
    let mut frames = Vec::new();
    loop {
        let mut buf = [0u8; 127];
        match f.next_frame(&mut buf).unwrap() {
            Some(n) => frames.push(buf[..n].to_vec()),
            None => break,
        }
    }
    assert!(f.is_done());
    frames
}

fn feed<'a, const N: usize>(
    r: &'a mut Reassembler<N, 1280>,
    now: Instant,
    frame: &[u8],
) -> Result<Reassembled<'a>, Error> {
    r.handle_fragment(now, &ot_contexts(), &LONG_SRC, &LONG_DST, true, frame)
}

fn complete(r: Result<Reassembled<'_>, Error>) -> Vec<u8> {
    match r.unwrap() {
        Reassembled::Complete(d) => d.to_vec(),
        Reassembled::Incomplete => panic!("incomplete"),
    }
}

#[test]
fn small_datagram_is_not_fragmented() {
    let d = datagram(20, 5683, 5684);
    let frames = fragment(&d, 1, None, 100);
    assert_eq!(frames.len(), 1);
    // Starts with IPHC, not a fragment header.
    assert_eq!(frames[0][0] & 0xe0, 0x60);
    assert!(frames[0].len() <= 100);
}

#[test]
fn fragment_and_reassemble_in_order() {
    for (n, max) in [
        (300, 100),
        (1000, 96),
        (1200, 104),
        (97, 100),
        (60, 64),
        (500, 127),
    ] {
        let d = datagram(n, 5683, 5684);
        let frames = fragment(&d, 0x1234, None, max);
        assert!(frames.len() > 1, "n={n}");
        let mut r = Reassembler::<2, 1280>::new();
        for (i, fr) in frames.iter().enumerate() {
            assert!(fr.len() <= max);
            // All but the last fragment payload sizes keep 8-byte alignment.
            let res = feed(&mut r, Instant::ZERO, fr);
            if i + 1 == frames.len() {
                assert_eq!(complete(res), d, "n={n}");
            } else {
                assert_eq!(res.unwrap(), Reassembled::Incomplete);
            }
        }
        assert_eq!(r.pending(), 0);
    }
}

#[test]
fn fragment_headers_are_consistent() {
    let d = datagram(500, 5683, 5684);
    let frames = fragment(&d, 0xabcd, None, 100);
    let (h0, l0) = FragmentHeader::parse(&frames[0]).unwrap();
    assert_eq!(h0.datagram_size as usize, d.len());
    assert_eq!(h0.datagram_tag, 0xabcd);
    assert_eq!(h0.datagram_offset, 0);
    // FRAG1 is followed by IPHC (compressed header), offsets of FRAGN refer
    // to the uncompressed datagram: 40 (IPv6) + 8 (UDP) + first chunk.
    assert_eq!(frames[0][l0] & 0xe0, 0x60);
    let first_payload = {
        let ctxs = ot_contexts();
        let mut out = [0u8; 127];
        let c = crate::iphc::compress(&ctxs, &LONG_SRC, &LONG_DST, &d, &mut out[..]).unwrap();
        frames[0].len() - l0 - c.header_len
    };
    let (h1, _) = FragmentHeader::parse(&frames[1]).unwrap();
    assert_eq!(h1.datagram_offset as usize, 48 + first_payload);
    assert_eq!(first_payload % 8, 0);
    let mut expect_off = h1.datagram_offset as usize;
    for fr in &frames[1..] {
        let (h, l) = FragmentHeader::parse(fr).unwrap();
        assert_eq!(h.datagram_offset as usize, expect_off);
        assert_eq!(h.datagram_tag, 0xabcd);
        expect_off += fr.len() - l;
    }
    assert_eq!(expect_off, d.len());
}

#[test]
fn fragments_with_mesh_header() {
    let d = datagram(300, 5683, 5684);
    let mesh = MeshHeader::new(0x0400, 0x0800, 19);
    let frames = fragment(&d, 7, Some(mesh), 100);
    assert!(frames.len() > 1);
    let mut r = Reassembler::<1, 1280>::new();
    let src = Address::Short(ShortAddress(0x0400));
    let dst = Address::Short(ShortAddress(0x0800));
    for (i, fr) in frames.iter().enumerate() {
        assert!(MeshHeader::is_mesh_header(fr));
        let (m, ml) = MeshHeader::parse(fr).unwrap();
        assert_eq!(m, mesh);
        assert!(fr.len() <= 100);
        let res = r.handle_fragment(Instant::ZERO, &ot_contexts(), &src, &dst, true, &fr[ml..]);
        if i + 1 == frames.len() {
            assert_eq!(complete(res), d);
        } else {
            assert_eq!(res.unwrap(), Reassembled::Incomplete);
        }
    }
}

#[test]
fn tiny_frames_fail_cleanly() {
    let d = datagram(300, 5683, 5684);
    let ctxs = NoContexts;
    let mut f = Fragmenter::new(&ctxs, LONG_SRC, LONG_DST, &d, 1, None, 8);
    let mut buf = [0u8; 127];
    assert!(f.next_frame(&mut buf).is_err());
    let mut f = Fragmenter::new(&ctxs, LONG_SRC, LONG_DST, &d, 1, None, 3);
    assert!(f.next_frame(&mut buf).is_err());
}

#[test]
fn out_of_order_next_fragments_are_dropped() {
    let d = datagram(500, 5683, 5684);
    let frames = fragment(&d, 5, None, 100);
    assert!(frames.len() >= 4);
    let mut r = Reassembler::<2, 1280>::new();
    assert_eq!(
        feed(&mut r, Instant::ZERO, &frames[0]).unwrap(),
        Reassembled::Incomplete
    );
    // Skip frame 1, deliver 2: dropped (gap), reassembly stays pending.
    assert_eq!(
        feed(&mut r, Instant::ZERO, &frames[2]).unwrap_err(),
        Error::Drop
    );
    assert_eq!(r.pending(), 1);
    // The in-order frame is still accepted afterwards.
    assert_eq!(
        feed(&mut r, Instant::ZERO, &frames[1]).unwrap(),
        Reassembled::Incomplete
    );
    for fr in &frames[2..frames.len() - 1] {
        assert_eq!(
            feed(&mut r, Instant::ZERO, fr).unwrap(),
            Reassembled::Incomplete
        );
    }
    assert_eq!(
        complete(feed(&mut r, Instant::ZERO, frames.last().unwrap())),
        d
    );
}

#[test]
fn duplicate_fragments_are_dropped() {
    let d = datagram(500, 5683, 5684);
    let frames = fragment(&d, 5, None, 100);
    let mut r = Reassembler::<2, 1280>::new();
    feed(&mut r, Instant::ZERO, &frames[0]).unwrap();
    // Duplicate FRAG1.
    assert_eq!(
        feed(&mut r, Instant::ZERO, &frames[0]).unwrap_err(),
        Error::Drop
    );
    assert_eq!(r.pending(), 1);
    feed(&mut r, Instant::ZERO, &frames[1]).unwrap();
    // Duplicate FRAGN (offset already received).
    assert_eq!(
        feed(&mut r, Instant::ZERO, &frames[1]).unwrap_err(),
        Error::Drop
    );
    for fr in &frames[2..frames.len() - 1] {
        feed(&mut r, Instant::ZERO, fr).unwrap();
    }
    assert_eq!(
        complete(feed(&mut r, Instant::ZERO, frames.last().unwrap())),
        d
    );
    // A late duplicate of the last fragment finds no reassembly.
    assert_eq!(
        feed(&mut r, Instant::ZERO, frames.last().unwrap()).unwrap_err(),
        Error::Drop
    );
}

#[test]
fn reassembly_times_out_and_refreshes() {
    let d = datagram(500, 5683, 5684);
    let frames = fragment(&d, 5, None, 100);
    let mut r = Reassembler::<2, 1280>::new();
    assert_eq!(r.next_deadline(), None);
    feed(&mut r, Instant::ZERO, &frames[0]).unwrap();
    assert_eq!(r.next_deadline(), Some(Instant::ZERO + REASSEMBLY_TIMEOUT));
    // Each accepted fragment restarts the timeout.
    let t1 = Instant::from_millis(1500);
    feed(&mut r, t1, &frames[1]).unwrap();
    assert_eq!(r.next_deadline(), Some(t1 + REASSEMBLY_TIMEOUT));
    assert_eq!(r.expire(Instant::from_millis(3000)), 0);
    assert_eq!(r.pending(), 1);
    assert_eq!(r.expire(Instant::from_millis(3500)), 1);
    assert_eq!(r.pending(), 0);
    // Fragments after expiry are dropped, also when they arrive via handle_fragment.
    assert_eq!(
        feed(&mut r, Instant::from_millis(3600), &frames[2]).unwrap_err(),
        Error::Drop
    );
    // handle_fragment expires implicitly.
    feed(&mut r, Instant::ZERO, &frames[0]).unwrap();
    assert_eq!(
        feed(&mut r, Instant::ZERO + REASSEMBLY_TIMEOUT, &frames[1]).unwrap_err(),
        Error::Drop
    );
    assert_eq!(r.pending(), 0);
}

#[test]
fn table_full_and_tag_reuse() {
    let d1 = datagram(300, 5683, 5684);
    let d2 = datagram(310, 5683, 5684);
    let d3 = datagram(320, 5683, 5684);
    let f1 = fragment(&d1, 1, None, 100);
    let f2 = fragment(&d2, 2, None, 100);
    let f3 = fragment(&d3, 3, None, 100);
    let mut r = Reassembler::<2, 1280>::new();
    feed(&mut r, Instant::ZERO, &f1[0]).unwrap();
    feed(&mut r, Instant::ZERO, &f2[0]).unwrap();
    // Table full: third datagram's FRAG1 is rejected.
    assert_eq!(
        feed(&mut r, Instant::ZERO, &f3[0]).unwrap_err(),
        Error::NoBufs
    );
    // Interleaved completion of the first two.
    for i in 1..f1.len().max(f2.len()) {
        if let Some(fr) = f1.get(i) {
            let res = feed(&mut r, Instant::ZERO, fr);
            if i + 1 == f1.len() {
                assert_eq!(complete(res), d1);
            } else {
                res.unwrap();
            }
        }
        if let Some(fr) = f2.get(i) {
            let res = feed(&mut r, Instant::ZERO, fr);
            if i + 1 == f2.len() {
                assert_eq!(complete(res), d2);
            } else {
                res.unwrap();
            }
        }
    }
    assert_eq!(r.pending(), 0);
    // Slots are free again and the tag of d1 may be reused for new content.
    let d4 = datagram(300, 5683, 5685);
    let f4 = fragment(&d4, 1, None, 100);
    feed(&mut r, Instant::ZERO, &f4[0]).unwrap();
    for fr in &f4[1..f4.len() - 1] {
        feed(&mut r, Instant::ZERO, fr).unwrap();
    }
    assert_eq!(
        complete(feed(&mut r, Instant::ZERO, f4.last().unwrap())),
        d4
    );
}

#[test]
fn key_includes_source_size_and_security() {
    let d = datagram(500, 5683, 5684);
    let frames = fragment(&d, 5, None, 100);
    let mut r = Reassembler::<2, 1280>::new();
    let ctxs = ot_contexts();
    r.handle_fragment(Instant::ZERO, &ctxs, &LONG_SRC, &LONG_DST, true, &frames[0])
        .unwrap();
    // Same tag/size from another originator: no match.
    let other = Address::Extended(ExtAddress([1, 2, 3, 4, 5, 6, 7, 8]));
    assert_eq!(
        r.handle_fragment(Instant::ZERO, &ctxs, &other, &LONG_DST, true, &frames[1])
            .unwrap_err(),
        Error::Drop
    );
    // Link security mismatch: no match.
    assert_eq!(
        r.handle_fragment(
            Instant::ZERO,
            &ctxs,
            &LONG_SRC,
            &LONG_DST,
            false,
            &frames[1]
        )
        .unwrap_err(),
        Error::Drop
    );
    // Different datagram size in the header: no match.
    let mut bad = frames[1].clone();
    bad[1] ^= 0x01;
    assert_eq!(feed(&mut r, Instant::ZERO, &bad).unwrap_err(), Error::Drop);
    // Original still completes.
    for fr in &frames[1..frames.len() - 1] {
        feed(&mut r, Instant::ZERO, fr).unwrap();
    }
    assert_eq!(
        complete(feed(&mut r, Instant::ZERO, frames.last().unwrap())),
        d
    );
}

#[test]
fn oversize_and_malformed_first_fragments() {
    let d = datagram(500, 5683, 5684);
    let frames = fragment(&d, 5, None, 100);
    let mut small = Reassembler::<1, 256>::new();
    assert_eq!(
        small
            .handle_fragment(
                Instant::ZERO,
                &ot_contexts(),
                &LONG_SRC,
                &LONG_DST,
                true,
                &frames[0]
            )
            .unwrap_err(),
        Error::NoBufs
    );
    let mut r = Reassembler::<1, 1280>::new();
    // Datagram size 0, truncated headers, garbage after FRAG1.
    assert_eq!(
        feed(&mut r, Instant::ZERO, &[0xc0, 0x00, 0, 1, 0x7a]).unwrap_err(),
        Error::Parse
    );
    assert_eq!(
        feed(&mut r, Instant::ZERO, &[0xc0, 0x50, 0, 1]).unwrap_err(),
        Error::Parse
    );
    assert_eq!(
        feed(&mut r, Instant::ZERO, &[0xc0, 0x50, 0, 1, 0x40, 1, 2]).unwrap_err(),
        Error::Parse
    );
    // Datagram size smaller than the decompressed headers.
    assert_eq!(
        feed(&mut r, Instant::ZERO, &[0xc0, 0x10, 0, 1, 0x7a, 0x33, 0x3a]).unwrap_err(),
        Error::Parse
    );
    assert_eq!(r.pending(), 0);
    // Not a fragment at all.
    assert_eq!(
        feed(&mut r, Instant::ZERO, &[0x7a, 0x33, 0x3a]).unwrap_err(),
        Error::Parse
    );
}

#[test]
fn tag_counter_skips_zero() {
    let mut t = TagCounter::new(0xfffe);
    assert_eq!(t.next_tag(), 0xfffe);
    assert_eq!(t.next_tag(), 0xffff);
    assert_eq!(t.next_tag(), 1);
    let mut t = TagCounter::new(0);
    assert_eq!(t.next_tag(), 1);
    let _ = Duration::from_secs(1);
}
