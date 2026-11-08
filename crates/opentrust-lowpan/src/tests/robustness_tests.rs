//! Round-trip, truncation and no-panic (pseudo-fuzz) tests.

use std::vec::Vec;

use core::net::Ipv6Addr;

use opentrust_core::time::Instant;
use opentrust_core::types::{ExtAddress, ShortAddress};
use opentrust_mac::frame::Address;

use super::{LONG_DST, LONG_SRC, SHORT_DST, SHORT_SRC, ot_contexts, ot_vectors};
use crate::forward::{handle_mesh, parse_frame, parse_inner};
use crate::frag::{FragmentHeader, Fragmenter};
use crate::ip6::{Ipv6Header, PROTO_HOP_OPTS, PROTO_ICMP6, PROTO_IPV6, PROTO_UDP, UdpHeader};
use crate::iphc::{NoContexts, compress, decompress, decompress_datagram, iphc_ecn, iphc_mark_ecn};
use crate::mesh::MeshHeader;
use crate::reassembly::{Reassembled, Reassembler};

struct Rng(u32);

impl Rng {
    fn next(&mut self) -> u32 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        self.0 = x;
        x
    }
    fn below(&mut self, n: u32) -> u32 {
        self.next() % n
    }
    fn byte(&mut self) -> u8 {
        self.next() as u8
    }
    fn pick<'a, T>(&mut self, s: &'a [T]) -> &'a T {
        &s[self.below(s.len() as u32) as usize]
    }
}

fn macs() -> [Address; 6] {
    [
        LONG_SRC,
        LONG_DST,
        SHORT_SRC,
        SHORT_DST,
        Address::Short(ShortAddress(0xffff)),
        Address::Extended(ExtAddress([0x02, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77])),
    ]
}

fn iid_of(mac: &Address) -> [u8; 8] {
    match mac {
        Address::Short(s) => opentrust_core::types::Iid::from_locator(s.0).0,
        Address::Extended(e) => e.to_iid().0,
        Address::None => [0; 8],
    }
}

fn addr(prefix: &[u8; 8], iid: [u8; 8]) -> Ipv6Addr {
    let mut o = [0u8; 16];
    o[..8].copy_from_slice(prefix);
    o[8..].copy_from_slice(&iid);
    Ipv6Addr::from(o)
}

fn random_unicast(rng: &mut Rng, mac: &Address) -> Ipv6Addr {
    const LL: [u8; 8] = [0xfe, 0x80, 0, 0, 0, 0, 0, 0];
    const ML: [u8; 8] = [0xfd, 0x00, 0xca, 0xfe, 0xfa, 0xce, 0x12, 0x34];
    const C1: [u8; 8] = [0x20, 0x01, 0, 2, 0, 0, 0, 1];
    const C2: [u8; 8] = [0x20, 0x01, 0, 2, 0, 0, 0, 2];
    const OTHER: [u8; 8] = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 9];
    let prefix = *rng.pick(&[LL, ML, C1, C2, OTHER]);
    let iid = match rng.below(4) {
        0 => iid_of(mac),
        1 => opentrust_core::types::Iid::from_locator((rng.next() & 0xffff) as u16).0,
        2 => (0..8)
            .map(|_| rng.byte())
            .collect::<Vec<_>>()
            .try_into()
            .unwrap(),
        _ => [0; 8],
    };
    addr(&prefix, iid)
}

fn random_dst(rng: &mut Rng, mac: &Address) -> Ipv6Addr {
    match rng.below(6) {
        0 => Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, rng.below(256) as u16),
        1 => Ipv6Addr::new(0xff03, 0, 0, 0, 0, 0, 0, 0xfc),
        2 => Ipv6Addr::new(
            0xff05,
            0,
            0,
            0,
            0,
            rng.below(256) as u16,
            rng.next() as u16,
            rng.next() as u16,
        ),
        3 => Ipv6Addr::new(0xff0e, 0, 0, 0, 0, 0, 0x100, rng.next() as u16),
        // Unicast-prefix based multicast with the mesh-local prefix.
        4 => Ipv6Addr::new(
            0xff33,
            0x0040,
            0xfd00,
            0xcafe,
            0xface,
            0x1234,
            rng.next() as u16,
            rng.next() as u16,
        ),
        _ => random_unicast(rng, mac),
    }
}

fn ext_header(rng: &mut Rng, next: u8) -> Vec<u8> {
    // Options area: MPL-like option (type 0x6d, 2..6 data bytes), optionally
    // padded to 8 octets with Pad1 or PadN.
    let dlen = 2 + rng.below(5) as usize;
    let mut opts = std::vec![0x6d, dlen as u8];
    opts.extend((0..dlen).map(|_| rng.byte()));
    let mut total = 2 + opts.len();
    if rng.below(2) == 0 {
        // Extra option so the trailing pad is not the only option.
        opts.extend_from_slice(&[0x01, 0x00]);
        total += 2;
    }
    let pad = (8 - total % 8) % 8;
    match pad {
        0 => {}
        1 => opts.push(0),
        n => {
            opts.push(1);
            opts.push((n - 2) as u8);
            opts.extend(core::iter::repeat_n(0, n - 2));
        }
    }
    let mut h = std::vec![next, ((2 + opts.len()) / 8 - 1) as u8];
    h.extend(opts);
    h
}

fn build_datagram(rng: &mut Rng, src_mac: &Address, dst_mac: &Address) -> Vec<u8> {
    let (tc, fl) = match rng.below(4) {
        0 => (0, 0),
        1 => (rng.byte(), 0),
        2 => (rng.byte() & 0xfc, rng.next() & 0xf_ffff),
        _ => (rng.byte() & 0x03, rng.next() & 0xf_ffff),
    };
    let hl = *rng.pick(&[1u8, 64, 255, 17, 128]);
    let src = if rng.below(10) == 0 {
        Ipv6Addr::UNSPECIFIED
    } else {
        random_unicast(rng, src_mac)
    };
    let dst = random_dst(rng, dst_mac);

    let payload_len = rng.below(40) as usize;
    let payload: Vec<u8> = (0..payload_len).map(|_| rng.byte()).collect();
    // 0: ICMPv6, 1: UDP, 2: HBH + UDP, 3: HBH + ICMPv6, 4: IP-in-IP UDP
    let kind = rng.below(5);
    let mut body = Vec::new();
    let nh;
    let inner_udp = |rng: &mut Rng, payload: &[u8]| {
        let ports = *rng.pick(&[
            (5683u16, 5684u16),
            (61616, 61631),
            (0xf0b3, 0xf0b9),
            (0xf012, 5683),
            (5683, 0xf0ff),
            (1, 2),
        ]);
        let mut u = [0u8; 8];
        UdpHeader {
            src_port: ports.0,
            dst_port: ports.1,
            length: (8 + payload.len()) as u16,
            checksum: rng.next() as u16,
        }
        .write(&mut u)
        .unwrap();
        let mut v = u.to_vec();
        v.extend_from_slice(payload);
        v
    };
    match kind {
        0 => {
            nh = PROTO_ICMP6;
            body.extend_from_slice(&payload);
        }
        1 => {
            nh = PROTO_UDP;
            body.extend(inner_udp(rng, &payload));
        }
        2 => {
            nh = PROTO_HOP_OPTS;
            body.extend(ext_header(rng, PROTO_UDP));
            body.extend(inner_udp(rng, &payload));
        }
        3 => {
            nh = PROTO_HOP_OPTS;
            body.extend(ext_header(rng, PROTO_ICMP6));
            body.extend_from_slice(&payload);
        }
        _ => {
            nh = PROTO_IPV6;
            let udp = inner_udp(rng, &payload);
            let mut h = [0u8; 40];
            Ipv6Header {
                traffic_class: 0,
                flow_label: 0,
                payload_len: udp.len() as u16,
                next_header: PROTO_UDP,
                hop_limit: 64,
                src: random_unicast(rng, src_mac),
                dst: random_dst(rng, dst_mac),
            }
            .write(&mut h)
            .unwrap();
            body.extend_from_slice(&h);
            body.extend(udp);
        }
    }
    let mut d = [0u8; 40].to_vec();
    Ipv6Header {
        traffic_class: tc,
        flow_label: fl,
        payload_len: body.len() as u16,
        next_header: nh,
        hop_limit: hl,
        src,
        dst,
    }
    .write(&mut d)
    .unwrap();
    d.extend(body);
    d
}

#[test]
fn compress_decompress_round_trip() {
    let ctxs = ot_contexts();
    let macs = macs();
    let mut rng = Rng(0x1234_5678);
    let mut compressed_smaller = 0;
    for i in 0..4000 {
        let sm = *rng.pick(&macs);
        let dm = *rng.pick(&macs);
        let d = build_datagram(&mut rng, &sm, &dm);
        // Also exercise the header-depth retry with small output buffers.
        let limit = *rng.pick(&[127usize, 127, 60, 24, 12, 8]);
        let mut out = [0u8; 127];
        let c = match compress(&ctxs, &sm, &dm, &d, &mut out[..limit]) {
            Ok(c) => c,
            Err(_) => {
                assert!(limit < 60, "iter {i}: compress failed with {limit} bytes");
                continue;
            }
        };
        assert!(c.header_len <= limit);
        let mut frame = out[..c.header_len].to_vec();
        frame.extend_from_slice(&d[c.consumed..]);
        if frame.len() < d.len() {
            compressed_smaller += 1;
        }
        let mut back = [0u8; 2048];
        let n = decompress_datagram(&ctxs, &sm, &dm, &frame, None, &mut back)
            .unwrap_or_else(|e| panic!("iter {i}: decompress failed: {e}; datagram {d:02x?}"));
        assert_eq!(&back[..n], &d[..], "iter {i}");

        // Fragmented view: size from "FRAG1", frame truncated.
        let cut = c.header_len.min(frame.len()) + (frame.len() - c.header_len) / 2;
        let mut hdrs = [0u8; 2048];
        let dd = decompress(
            &ctxs,
            &sm,
            &dm,
            &frame[..cut],
            Some(d.len() as u16),
            &mut hdrs,
        )
        .unwrap_or_else(|e| panic!("iter {i}: frag decompress failed: {e}"));
        assert_eq!(&hdrs[..dd.written], &d[..c.consumed], "iter {i}");
    }
    assert!(compressed_smaller > 2000);
}

#[test]
fn stateless_round_trip_without_contexts() {
    let macs = macs();
    let mut rng = Rng(0xdead_beef);
    for i in 0..1000 {
        let sm = *rng.pick(&macs);
        let dm = *rng.pick(&macs);
        let d = build_datagram(&mut rng, &sm, &dm);
        let mut out = [0u8; 127];
        let c = compress(&NoContexts, &sm, &dm, &d, &mut out).unwrap();
        let mut frame = out[..c.header_len].to_vec();
        frame.extend_from_slice(&d[c.consumed..]);
        let mut back = [0u8; 2048];
        let n = decompress_datagram(&NoContexts, &sm, &dm, &frame, None, &mut back).unwrap();
        assert_eq!(&back[..n], &d[..], "iter {i}");
    }
}

#[test]
fn fragmentation_round_trip() {
    let ctxs = ot_contexts();
    let mut rng = Rng(0xcafe_f00d);
    let mut r = Reassembler::<2, 1280>::new();
    for i in 0..300u16 {
        let (sm, dm) = (LONG_SRC, LONG_DST);
        let mut d = build_datagram(&mut rng, &sm, &dm);
        // Pad payload to get a range of sizes: rebuild with extra bytes.
        let extra = rng.below(1100) as usize;
        d.extend((0..extra).map(|_| rng.byte()));
        // Fix lengths: only for ICMPv6/UDP-without-ext-or-tunnel datagrams.
        let nh = d[6];
        if nh != PROTO_ICMP6 && nh != PROTO_UDP {
            continue;
        }
        let plen = (d.len() - 40) as u16;
        d[4..6].copy_from_slice(&plen.to_be_bytes());
        if nh == PROTO_UDP {
            d[44..46].copy_from_slice(&plen.to_be_bytes());
        }
        let max = 48 + rng.below(80) as usize;
        let mesh = (rng.below(2) == 0).then(|| MeshHeader::new(0x0400, 0x0800, 19));
        let (src, dst) = if mesh.is_some() {
            (
                Address::Short(ShortAddress(0x0400)),
                Address::Short(ShortAddress(0x0800)),
            )
        } else {
            (sm, dm)
        };
        let mut f = Fragmenter::new(&ctxs, sm, dm, &d, i + 1, mesh, max);
        let mut done = false;
        let mut n = 0;
        while let Some(len) = {
            let mut buf = [0u8; 127];
            let res = f.next_frame(&mut buf).unwrap();
            res.map(|l| (buf, l))
        } {
            let (buf, l) = len;
            assert!(l <= max);
            let mut frame = &buf[..l];
            if mesh.is_some() {
                let (_, ml) = MeshHeader::parse(frame).unwrap();
                frame = &frame[ml..];
            }
            n += 1;
            if FragmentHeader::is_fragment_header(frame) {
                match r
                    .handle_fragment(Instant::ZERO, &ctxs, &src, &dst, true, frame)
                    .unwrap()
                {
                    Reassembled::Complete(got) => {
                        assert_eq!(got, &d[..], "iter {i}");
                        done = true;
                    }
                    Reassembled::Incomplete => {}
                }
            } else {
                assert_eq!(n, 1);
                let mut back = [0u8; 2048];
                let k = decompress_datagram(&ctxs, &src, &dst, frame, None, &mut back).unwrap();
                assert_eq!(&back[..k], &d[..]);
                done = true;
            }
        }
        assert!(done, "iter {i}");
    }
}

#[test]
fn all_prefixes_of_ot_vectors_do_not_panic() {
    let ctxs = ot_contexts();
    for v in ot_vectors::VECTORS {
        let mut frame = v.iphc.to_vec();
        frame.extend_from_slice(&[0x80, 0, 1, 2, 3, 4, 5, 6]);
        for n in 0..=frame.len() {
            for dl in [None, Some(0u16), Some(40), Some(100), Some(1280)] {
                let mut out = [0u8; 256];
                let _ = decompress(&ctxs, &v.src, &v.dst, &frame[..n], dl, &mut out);
                let mut tiny = [0u8; 20];
                let _ = decompress(&ctxs, &v.src, &v.dst, &frame[..n], dl, &mut tiny);
            }
            let _ = iphc_ecn(&frame[..n]);
            let mut c = frame[..n].to_vec();
            let _ = iphc_mark_ecn(&mut c);
        }
    }
}

#[test]
fn truncated_datagrams_do_not_panic_the_compressor() {
    let ctxs = ot_contexts();
    let mut rng = Rng(77);
    for _ in 0..200 {
        let d = build_datagram(&mut rng, &LONG_SRC, &LONG_DST);
        for n in 0..d.len() {
            let mut out = [0u8; 127];
            let _ = compress(&ctxs, &LONG_SRC, &LONG_DST, &d[..n], &mut out);
            let mut out = [0u8; 5];
            let _ = compress(&ctxs, &LONG_SRC, &LONG_DST, &d[..n], &mut out);
        }
    }
}

#[test]
fn random_bytes_do_not_panic_any_parser() {
    let ctxs = ot_contexts();
    let macs = macs();
    let mut rng = Rng(0x0bad_cafe);
    let mut r = Reassembler::<3, 512>::new();
    for _ in 0..20000 {
        let len = rng.below(48) as usize;
        let mut b: Vec<u8> = (0..len).map(|_| rng.byte()).collect();
        // Bias the dispatch byte towards the interesting values.
        if !b.is_empty() {
            b[0] = match rng.below(5) {
                0 => 0x60 | (b[0] & 0x1f),
                1 => 0xb0 | (b[0] & 0x0f),
                2 => 0xc0 | (b[0] & 0x07),
                3 => 0xe0 | (b[0] & 0x07),
                _ => b[0],
            };
        }
        let sm = *rng.pick(&macs);
        let dm = *rng.pick(&macs);
        let mut out = [0u8; 300];
        let dl = if rng.below(2) == 0 {
            None
        } else {
            Some(rng.next() as u16)
        };
        let _ = decompress(&ctxs, &sm, &dm, &b, dl, &mut out);
        let _ = decompress_datagram(&NoContexts, &sm, &dm, &b, dl, &mut out);
        let _ = MeshHeader::parse(&b);
        let _ = FragmentHeader::parse(&b);
        let _ = parse_frame(&b);
        let _ = parse_inner(&b);
        let _ = handle_mesh(&b, true, &0x0800u16, &|d: u16| Some(d ^ 1), Some(1));
        let _ = r.handle_fragment(
            Instant::from_millis(u64::from(rng.below(10_000))),
            &ctxs,
            &sm,
            &dm,
            rng.below(2) == 0,
            &b,
        );
        let _ = iphc_ecn(&b);
        let mut m = b.clone();
        let _ = iphc_mark_ecn(&mut m);
        let _ = Ipv6Header::parse(&b);
        let _ = UdpHeader::parse(&b);
    }
}
