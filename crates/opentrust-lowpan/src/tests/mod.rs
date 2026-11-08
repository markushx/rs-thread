//! Tests for the 6LoWPAN crate.

mod forward_tests;
mod frag_tests;
mod ot_vectors;
mod robustness_tests;

use core::net::Ipv6Addr;
use core::str::FromStr;

use opentrust_core::types::{ExtAddress, ShortAddress};
use opentrust_core::{Error, Result};
use opentrust_mac::frame::Address;

use crate::ip6::{Ipv6Header, UdpHeader};
use crate::iphc::{
    self, Context, ContextProvider, ContextTable, NoContexts, compress, decompress,
    decompress_datagram,
};

const LONG_SRC: Address =
    Address::Extended(ExtAddress([0x00, 0x00, 0x5e, 0xef, 0x10, 0x22, 0x11, 0x00]));
const LONG_DST: Address =
    Address::Extended(ExtAddress([0x00, 0x00, 0x5e, 0xef, 0x10, 0xaa, 0xbb, 0xcc]));
const SHORT_SRC: Address = Address::Short(ShortAddress(0x0000));
const SHORT_DST: Address = Address::Short(ShortAddress(0xc003));
const BCAST: Address = Address::Short(ShortAddress(0xffff));
const PAYLOAD: [u8; 8] = [0x80, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06];

struct Ip {
    vcf: u32,
    plen: u16,
    nh: u8,
    hl: u8,
    src: &'static str,
    dst: &'static str,
}

struct Udp {
    sp: u16,
    dp: u16,
    ck: u16,
}

struct V {
    cpp: &'static str,
    name: &'static str,
    src: Address,
    dst: Address,
    ip: Option<Ip>,
    tun: Option<Ip>,
    ext: &'static [u8],
    udp: Option<Udp>,
    iphc: &'static [u8],
    payload_offset: usize,
    err: bool,
    compress: bool,
    decompress: bool,
}

/// The context set OpenThread's `test_lowpan.cpp` installs: mesh-local
/// prefix `fd00:cafe:face:1234` as context 0, `2001:2:0:1::/64` as context 1
/// (compressible), `2001:2:0:2::/64` as context 2 (not compressible).
fn ot_contexts() -> ContextTable {
    let mut t = ContextTable::new();
    t.set(Context::new64(
        0,
        [0xfd, 0x00, 0xca, 0xfe, 0xfa, 0xce, 0x12, 0x34],
        true,
    ))
    .unwrap();
    t.set(Context::new64(1, [0x20, 0x01, 0, 2, 0, 0, 0, 1], true))
        .unwrap();
    t.set(Context::new64(2, [0x20, 0x01, 0, 2, 0, 0, 0, 2], false))
        .unwrap();
    t
}

fn ip_header(ip: &Ip) -> Ipv6Header {
    Ipv6Header {
        traffic_class: (ip.vcf >> 20) as u8,
        flow_label: ip.vcf & 0xf_ffff,
        payload_len: ip.plen,
        next_header: ip.nh,
        hop_limit: ip.hl,
        src: Ipv6Addr::from_str(ip.src).unwrap(),
        dst: Ipv6Addr::from_str(ip.dst).unwrap(),
    }
}

fn uncompressed(v: &V) -> std::vec::Vec<u8> {
    let mut d = std::vec::Vec::new();
    let mut h = [0u8; 40];
    if let Some(ip) = &v.ip {
        ip_header(ip).write(&mut h).unwrap();
        d.extend_from_slice(&h);
    }
    d.extend_from_slice(v.ext);
    if let Some(ip) = &v.tun {
        ip_header(ip).write(&mut h).unwrap();
        d.extend_from_slice(&h);
    }
    if let Some(u) = &v.udp {
        let mut b = [0u8; 8];
        UdpHeader {
            src_port: u.sp,
            dst_port: u.dp,
            length: 16,
            checksum: u.ck,
        }
        .write(&mut b)
        .unwrap();
        d.extend_from_slice(&b);
    }
    if !v.err {
        d.extend_from_slice(&PAYLOAD);
    }
    d
}

fn run_vector(ctxs: &ContextTable, v: &V) {
    let ip6 = uncompressed(v);
    let mut frame = std::vec::Vec::from(v.iphc);
    if !v.err {
        frame.extend_from_slice(&PAYLOAD);
    }
    std::println!("=== {} ({}) ===", v.cpp, v.name);

    if v.compress {
        let mut out = [0u8; 127];
        let c = compress(ctxs, &v.src, &v.dst, &ip6, &mut out)
            .unwrap_or_else(|e| panic!("{}: compress failed: {e}", v.cpp));
        assert_eq!(&out[..c.header_len], v.iphc, "{}: compressed header", v.cpp);
        assert_eq!(c.consumed, v.payload_offset, "{}: consumed", v.cpp);
        // ECN accessors (OT `DecompressEcn` / `MarkCompressedEcn`).
        let hdr = Ipv6Header::parse(&ip6).unwrap();
        let mut hc = std::vec::Vec::from(&out[..c.header_len]);
        assert_eq!(iphc::iphc_ecn(&hc), Some(hdr.ecn()), "{}: ecn", v.cpp);
        if hdr.ecn() != 0 {
            iphc::iphc_mark_ecn(&mut hc).unwrap();
            assert_eq!(iphc::iphc_ecn(&hc), Some(3), "{}: marked ecn", v.cpp);
        }
    }

    if v.decompress {
        let mut out = [0u8; 512];
        let r = decompress(ctxs, &v.src, &v.dst, &frame, None, &mut out);
        if v.err {
            assert_eq!(
                r.unwrap_err(),
                Error::Parse,
                "{}: expected parse error",
                v.cpp
            );
            return;
        }
        let d = r.unwrap_or_else(|e| panic!("{}: decompress failed: {e}", v.cpp));
        assert_eq!(d.consumed, v.iphc.len(), "{}: consumed", v.cpp);
        assert_eq!(d.written, v.payload_offset, "{}: written", v.cpp);
        let mut full = [0u8; 512];
        let n = decompress_datagram(ctxs, &v.src, &v.dst, &frame, None, &mut full).unwrap();
        assert_eq!(&full[..n], &ip6[..], "{}: datagram", v.cpp);

        // Fragmented case: size comes from the FRAG1 header, the frame only
        // carries part of the payload.
        let cut = v.iphc.len() + 2;
        let mut out2 = [0u8; 512];
        let d2 = decompress(
            ctxs,
            &v.src,
            &v.dst,
            &frame[..cut],
            Some(ip6.len() as u16),
            &mut out2,
        )
        .unwrap();
        assert_eq!(
            &out2[..d2.written],
            &ip6[..v.payload_offset],
            "{}: frag hdrs",
            v.cpp
        );
    }
}

#[test]
fn ot_iphc_vectors() {
    let ctxs = ot_contexts();
    assert_eq!(ot_vectors::VECTORS.len(), 58);
    for v in ot_vectors::VECTORS {
        run_vector(&ctxs, v);
    }
}

#[test]
fn no_context_provider_is_stateless() {
    let r: Result<_> = decompress(
        &NoContexts,
        &LONG_SRC,
        &LONG_DST,
        &[0x7a, 0x33, 0x3a],
        None,
        &mut [0u8; 64],
    );
    assert!(r.is_ok());
    assert!(NoContexts.by_id(0).is_none());
}
