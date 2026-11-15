//! 6LoWPAN IPHC/NHC differential tests against OpenThread's `Lowpan`.

#[cfg(not(feature = "ot"))]
#[test]
fn skipped() {
    opentrust_difftest::skipped("lowpan");
}

#[cfg(feature = "ot")]
mod ot {
    use opentrust_core::types::{ExtAddress, Prefix64, ShortAddress};
    use opentrust_difftest::{Rng, cases, ffi};
    use opentrust_lowpan::iphc::{self, Context, ContextTable};
    use opentrust_mac::frame::Address;

    struct Env {
        ml: [u8; 8],
        ctxs: Vec<Context>,
        table: ContextTable,
    }

    impl Env {
        fn random(rng: &mut Rng) -> Self {
            let ml = rng.bytes::<8>();
            let mut ctxs: Vec<Context> = Vec::new();
            let n = rng.below(5);
            let mut ids: Vec<u8> = (1..16).collect();
            for _ in 0..n {
                let id = ids.swap_remove(rng.below(ids.len()));
                let prefix_len = match rng.below(4) {
                    0 => 64,
                    1 => 64 + rng.below(65) as u8,
                    2 => 16 + rng.below(113) as u8,
                    _ => 48,
                };
                let mut prefix = rng.bytes::<16>();
                // Zero the bits beyond the prefix length.
                for (i, b) in prefix.iter_mut().enumerate() {
                    let lo = i * 8;
                    if lo >= prefix_len as usize {
                        *b = 0;
                    } else if lo + 8 > prefix_len as usize {
                        *b &= 0xffu8 << (lo + 8 - prefix_len as usize);
                    }
                }
                // Keep prefixes distinct from each other and from the
                // mesh-local prefix.
                if ctxs
                    .iter()
                    .any(|c| c.prefix_len == prefix_len && c.prefix == prefix)
                    || (prefix_len == 64 && prefix[..8] == ml)
                {
                    continue;
                }
                ctxs.push(Context {
                    id,
                    prefix,
                    prefix_len,
                    compress: rng.chance(3, 4),
                });
            }
            let mut table = ContextTable::new();
            table.set_mesh_local(&Prefix64(ml));
            for c in &ctxs {
                table.set(*c).unwrap();
            }
            Self { ml, ctxs, table }
        }

        fn configure(&self, ot: &ffi::Ot) {
            let c: Vec<ffi::Context> = self
                .ctxs
                .iter()
                .map(|c| ffi::Context {
                    id: c.id,
                    compress: c.compress as u8,
                    prefix_len: c.prefix_len,
                    prefix: c.prefix,
                })
                .collect();
            ot.lowpan_configure(&self.ml, &c);
        }
    }

    #[derive(Clone, Copy)]
    enum Mac {
        None,
        Short(u16),
        Ext([u8; 8]),
    }

    impl Mac {
        fn random(rng: &mut Rng) -> Self {
            match rng.below(10) {
                0 => Mac::None,
                1..=4 => Mac::Short(rng.u16()),
                _ => Mac::Ext(rng.bytes()),
            }
        }

        fn ffi(self) -> ffi::MacAddr {
            match self {
                Mac::None => ffi::MacAddr::default(),
                Mac::Short(s) => ffi::MacAddr {
                    kind: 1,
                    short_addr: s.to_be_bytes(),
                    ext: [0; 8],
                },
                Mac::Ext(e) => ffi::MacAddr {
                    kind: 2,
                    short_addr: [0; 2],
                    ext: e,
                },
            }
        }

        fn addr(self) -> Address {
            match self {
                Mac::None => Address::None,
                Mac::Short(s) => Address::Short(ShortAddress(s)),
                Mac::Ext(e) => Address::Extended(ExtAddress(e)),
            }
        }

        /// The IID a link-layer address maps to (None for no address).
        fn iid(self, rng: &mut Rng) -> [u8; 8] {
            match self {
                Mac::Short(s) => {
                    let b = s.to_be_bytes();
                    [0, 0, 0, 0xff, 0xfe, 0, b[0], b[1]]
                }
                Mac::Ext(mut e) => {
                    e[0] ^= 0x02;
                    e
                }
                Mac::None => rng.bytes(),
            }
        }
    }

    fn prefix_with_len(p: &[u8; 16], len: u8) -> [u8; 16] {
        let mut o = [0u8; 16];
        let n = (len as usize).div_ceil(8);
        o[..n].copy_from_slice(&p[..n]);
        o
    }

    fn gen_addr(rng: &mut Rng, env: &Env, mac: Mac) -> [u8; 16] {
        let mut a = [0u8; 16];
        let iid = |rng: &mut Rng| -> [u8; 8] {
            match rng.below(3) {
                0 => mac.iid(rng),
                1 => {
                    let b = rng.u16().to_be_bytes();
                    [0, 0, 0, 0xff, 0xfe, 0, b[0], b[1]]
                }
                _ => rng.bytes(),
            }
        };
        match rng.below(12) {
            0 => {}
            1..=3 => {
                a[0] = 0xfe;
                a[1] = 0x80;
                a[8..].copy_from_slice(&iid(rng));
            }
            4..=5 => {
                a[..8].copy_from_slice(&env.ml);
                a[8..].copy_from_slice(&iid(rng));
            }
            6..=7 if !env.ctxs.is_empty() => {
                let c = rng.pick(&env.ctxs);
                a = c.prefix;
                // Fill the bits after the prefix with the IID.
                let tail = iid(rng);
                let plen = c.prefix_len as usize;
                if plen <= 64 {
                    let random = rng.bytes::<16>();
                    let from = plen.div_ceil(8);
                    a[from..8].copy_from_slice(&random[from..8]);
                    // Keep partial byte bits of the prefix.
                    if plen % 8 != 0 {
                        let keep = 0xffu8 << (8 - plen % 8);
                        a[plen / 8] = (c.prefix[plen / 8] & keep) | (random[plen / 8] & !keep);
                    }
                    a[8..].copy_from_slice(&tail);
                } else {
                    for i in 0..16 {
                        let bit = i * 8;
                        if bit >= plen {
                            a[i] = if i >= 8 { tail[i - 8] } else { rng.u8() };
                        } else if bit + 8 > plen {
                            let keep = 0xffu8 << (bit + 8 - plen);
                            a[i] = (c.prefix[i] & keep) | (tail[i - 8] & !keep);
                        }
                    }
                }
            }
            8 => {
                // Multicast.
                a[0] = 0xff;
                let scope = *rng.pick(&[1u8, 2, 3, 4, 5, 8, 0xe]);
                match rng.below(6) {
                    0 => {
                        a[1] = 0x02;
                        a[15] = rng.u8();
                    }
                    1 => {
                        a[1] = rng.u8() & 0xf0 | scope;
                        a[13..].copy_from_slice(&rng.bytes::<3>());
                        a[12] = 0;
                    }
                    2 => {
                        a[1] = scope;
                        a[11..].copy_from_slice(&rng.bytes::<5>());
                    }
                    3 => {
                        a[1..].copy_from_slice(&rng.bytes::<15>());
                    }
                    _ => {
                        // RFC 3306 unicast-prefix based, sometimes with a
                        // real context prefix.
                        a[1] = 0x30 | scope;
                        let (plen, prefix) = if !env.ctxs.is_empty() && rng.chance(2, 3) {
                            let c = rng.pick(&env.ctxs);
                            (c.prefix_len.min(64), c.prefix)
                        } else if rng.chance(1, 2) {
                            let mut p = [0u8; 16];
                            p[..8].copy_from_slice(&env.ml);
                            (64, p)
                        } else {
                            (rng.below(65) as u8, rng.bytes())
                        };
                        a[3] = plen;
                        a[4..12].copy_from_slice(&prefix_with_len(&prefix, plen)[..8]);
                        // Clear bits beyond plen in the copied part.
                        for (i, b) in a[4..12].iter_mut().enumerate() {
                            let lo = i * 8;
                            if lo >= plen as usize {
                                *b = 0;
                            } else if lo + 8 > plen as usize {
                                *b &= 0xffu8 << (lo + 8 - plen as usize);
                            }
                        }
                        a[12..].copy_from_slice(&rng.bytes::<4>());
                    }
                }
            }
            _ => a = rng.bytes(),
        }
        a
    }

    const NH_HBH: u8 = 0;
    const NH_UDP: u8 = 17;

    fn ext_header(rng: &mut Rng, next: u8) -> Vec<u8> {
        let units = rng.below(3); // total (units + 1) * 8 bytes
        let total = (units + 1) * 8;
        let mut h = vec![next, units as u8];
        // Options: PadN fill, or a mix of Pad1 and unknown options.
        while h.len() < total {
            let left = total - h.len();
            if left == 1 || rng.chance(1, 4) {
                h.push(0); // Pad1
            } else {
                let dlen = rng.below(left - 1);
                if rng.chance(1, 2) {
                    h.push(1); // PadN
                } else {
                    h.push(0x40 | (rng.u8() & 0x3f) | 0x1e); // some option type
                }
                h.push(dlen as u8);
                for _ in 0..dlen {
                    h.push(if rng.chance(1, 2) { 0 } else { rng.u8() });
                }
            }
        }
        h.truncate(total);
        h
    }

    fn gen_udp(rng: &mut Rng, payload_len: usize) -> Vec<u8> {
        let port = |rng: &mut Rng| -> u16 {
            match rng.below(5) {
                0 => 0xf0b0 + rng.below(16) as u16,
                1 => 0xf000 + rng.below(256) as u16,
                2 => 61616,
                3 => 1 + rng.below(1023) as u16,
                _ => rng.u16(),
            }
        };
        let (s, d) = (port(rng), port(rng));
        let mut u = Vec::new();
        u.extend_from_slice(&s.to_be_bytes());
        u.extend_from_slice(&d.to_be_bytes());
        let len = if rng.chance(1, 20) {
            rng.u16()
        } else {
            (8 + payload_len) as u16
        };
        u.extend_from_slice(&len.to_be_bytes());
        u.extend_from_slice(&rng.u16().to_be_bytes());
        u.extend(rng.vec(payload_len));
        u
    }

    fn gen_ip6(rng: &mut Rng, env: &Env, src: Mac, dst: Mac, depth: u32) -> Vec<u8> {
        // Upper layer + extension headers, built back to front.
        let payload_len = rng.below(60);
        let mut next = match rng.below(10) {
            0..=4 => NH_UDP,
            5 | 6 => 58,
            7 => 6,
            8 if depth == 0 => 41,
            _ => rng.u8(),
        };
        // Reserved values that would change the meaning of the chain.
        if matches!(next, 0 | 43 | 44 | 60 | 59 | 50 | 51) {
            next = 59;
        }
        let mut body = match next {
            NH_UDP => gen_udp(rng, payload_len),
            41 => gen_ip6(rng, env, src, dst, depth + 1),
            58 => {
                let mut b = vec![128, 0, rng.u8(), rng.u8()];
                b.extend(rng.vec(payload_len));
                b
            }
            _ => rng.vec(payload_len),
        };
        let mut first = next;
        if rng.chance(1, 4) {
            let n = 1 + rng.below(3);
            let mut kinds: Vec<u8> = Vec::new();
            for i in 0..n {
                kinds.push(match (i, rng.below(5)) {
                    (0, 0..=2) => NH_HBH,
                    (_, 0) | (_, 1) => 60,
                    (_, 2) => 43,
                    _ => 44,
                });
            }
            for k in kinds.iter().rev() {
                let mut h = if *k == 44 {
                    let mut f = vec![first, 0];
                    f.extend(rng.bytes::<6>());
                    f
                } else {
                    ext_header(rng, first)
                };
                h.extend(body);
                body = h;
                first = *k;
            }
        }
        let mut p = Vec::new();
        let tc = if rng.chance(1, 2) { 0 } else { rng.u8() };
        let flow = if rng.chance(1, 2) {
            0
        } else {
            rng.u32() & 0xf_ffff
        };
        p.extend_from_slice(&(0x6000_0000u32 | (tc as u32) << 20 | flow).to_be_bytes());
        let plen = if rng.chance(1, 30) {
            rng.u16()
        } else {
            body.len() as u16
        };
        p.extend_from_slice(&plen.to_be_bytes());
        p.push(first);
        p.push(
            *rng.pick(&[0u8, 1, 64, 255, 1, 64, 255]) | if rng.chance(1, 5) { rng.u8() } else { 0 },
        );
        p.extend_from_slice(&gen_addr(rng, env, src));
        p.extend_from_slice(&gen_addr(rng, env, dst));
        p.extend(body);
        p
    }

    fn rust_compress(
        env: &Env,
        src: Mac,
        dst: Mac,
        ip6: &[u8],
        cap: usize,
    ) -> Option<(Vec<u8>, usize)> {
        let mut out = vec![0u8; cap];
        iphc::compress(&env.table, &src.addr(), &dst.addr(), ip6, &mut out)
            .ok()
            .map(|c| {
                out.truncate(c.header_len);
                (out, c.consumed)
            })
    }

    /// The IPv6 headers (outer and tunneled) of a datagram.
    fn ip6_headers(mut ip6: &[u8]) -> Vec<&[u8]> {
        let mut v = Vec::new();
        while ip6.len() >= 40 {
            v.push(&ip6[..40]);
            let (mut off, mut nh) = (40usize, ip6[6]);
            let mut inner = None;
            while off + 8 <= ip6.len() {
                match nh {
                    0 | 43 | 60 => {
                        let n = ip6[off];
                        off += (ip6[off + 1] as usize + 1) * 8;
                        nh = n;
                    }
                    44 => {
                        nh = ip6[off];
                        off += 8;
                    }
                    41 => {
                        inner = ip6.get(off..);
                        break;
                    }
                    _ => break,
                }
            }
            match inner {
                Some(i) => ip6 = i,
                None => break,
            }
        }
        v
    }

    /// Inputs where OpenThread's output is known to be lossy or malformed:
    /// - with no link-layer address OpenThread ignores the error of the IID
    ///   derivation and compares the address with an uninitialized IID,
    /// - an address in `fe80::/10` but not `fe80::/64` is compressed as
    ///   link-local (the middle 54 bits are lost; RFC 6282 only covers
    ///   `fe80::/64`),
    /// - a multicast destination `ffxx::` whose bytes 2..15 are all zero gets
    ///   the multicast bit set but no address bytes at all (the datagram is
    ///   corrupted on decompression),
    /// - with a header depth cut-off (compression retried because the
    ///   result did not fit) after a Hop-by-Hop header, OpenThread sets the
    ///   NHC "next header compressed" bit although the UDP header that
    ///   follows is left uncompressed; with IP-in-IP the cut-off point
    ///   differs,
    /// - for a context prefix shorter than 64 bits OpenThread drops the
    ///   address bits between the prefix and the interface identifier;
    ///   OpenTrust only uses such a context if those bits are zero.
    fn known_compress_difference(
        env: &Env,
        src: Mac,
        dst: Mac,
        ip6: &[u8],
        cap: usize,
    ) -> Option<&'static str> {
        if matches!(src, Mac::None) || matches!(dst, Mac::None) {
            return Some(
                "absent link-layer address: OpenThread compares against an uninitialized IID",
            );
        }
        let headers = ip6_headers(ip6);
        let odd =
            |a: &[u8]| a[0] == 0xfe && a[1] & 0xc0 == 0x80 && a[1..8] != [0x80, 0, 0, 0, 0, 0, 0];
        if headers.iter().any(|h| odd(&h[8..24]) || odd(&h[24..40])) {
            return Some("fe80::/10 address compressed as fe80::/64 by OpenThread");
        }
        if headers
            .iter()
            .any(|h| h[24] == 0xff && h[26..40].iter().all(|b| *b == 0))
        {
            return Some(
                "multicast address with all-zero group compressed to nothing by OpenThread",
            );
        }
        let short_ctx = |a: &[u8]| {
            env.ctxs.iter().any(|c| {
                c.prefix_len < 64 && {
                    let n = c.prefix_len as usize;
                    a[..n / 8] == c.prefix[..n / 8]
                }
            })
        };
        if headers
            .iter()
            .any(|h| short_ctx(&h[8..24]) || short_ctx(&h[24..40]))
        {
            return Some("context shorter than 64 bits and non-zero bits between prefix and IID");
        }
        if cap < 127 && (ip6[6] == 0 || headers.len() > 1) {
            return Some("header depth cut-off after Hop-by-Hop or IP-in-IP");
        }
        None
    }

    #[test]
    fn compress_and_decompress_match() {
        let ot = ffi::lock();
        let mut rng = Rng::new(0x10a0);
        let n = cases(4000);
        let (mut both_ok, mut both_err, mut known, mut diffs) =
            (0usize, 0usize, 0usize, Vec::new());
        let mut env = Env::random(&mut rng);
        env.configure(&ot);
        for i in 0..n {
            if i % 20 == 0 {
                env = Env::random(&mut rng);
                env.configure(&ot);
            }
            let (src, dst) = (Mac::random(&mut rng), Mac::random(&mut rng));
            let ip6 = gen_ip6(&mut rng, &env, src, dst, 0);
            let cap = if rng.chance(1, 8) {
                20 + rng.below(40)
            } else {
                127
            };

            let ours = rust_compress(&env, src, dst, &ip6, cap);
            let theirs = ot.lowpan_compress(&src.ffi(), &dst.ffi(), &ip6, cap).ok();
            if ours != theirs {
                if let Some(kind) = known_compress_difference(&env, src, dst, &ip6, cap) {
                    // OpenThread's output is the odd one: ours must at least
                    // round-trip.
                    // (Without the context the headers may also not fit the
                    // frame at all.)
                    let ok = (ours.is_none() && cap < 127 && theirs.is_some())
                        || ours.as_ref().is_some_and(|(hdr, consumed)| {
                            let mut frame = hdr.clone();
                            frame.extend_from_slice(&ip6[*consumed..]);
                            let mut buf = vec![0u8; 2048];
                            iphc::decompress_datagram(
                                &env.table,
                                &src.addr(),
                                &dst.addr(),
                                &frame,
                                None,
                                &mut buf,
                            )
                            .is_ok_and(|l| {
                                // The decoder derives the payload length, and a
                                // trailing PadN is elided as a whole (also by
                                // OpenThread, even above the 7 octets of RFC
                                // 6282), so lengths may differ: compare the
                                // IPv6 header without the length.
                                l >= 40 && buf[..4] == ip6[..4] && buf[6..40] == ip6[6..40]
                            })
                        });
                    assert!(
                        ok,
                        "case {i}: {kind}: our output does not round-trip\n  ip6    {}\n  ours   {:02x?}\n  theirs {:02x?}\n  ml {} ctxs {:?} src {:?} dst {:?}",
                        hex(&ip6),
                        ours,
                        theirs,
                        hex(&env.ml),
                        env.ctxs,
                        src.ffi(),
                        dst.ffi()
                    );
                    known += 1;
                    continue;
                }
                diffs.push(format!(
                    "case {i} (cap {cap}): compress differs\n  ip6    {}\n  ours   {:02x?}\n  theirs {:02x?}\n  ml {} ctxs {:?} src {:?} dst {:?}",
                    hex(&ip6),
                    ours,
                    theirs,
                    hex(&env.ml),
                    env.ctxs,
                    src.ffi(),
                    dst.ffi()
                ));
                continue;
            }
            let Some((hdr, consumed)) = ours else {
                both_err += 1;
                continue;
            };
            both_ok += 1;

            // First fragment: only part of the payload, the datagram size
            // comes from the fragment header.
            {
                let keep = rng.below(ip6.len() - consumed + 1);
                let mut first = hdr.clone();
                first.extend_from_slice(&ip6[consumed..consumed + keep]);
                let mut buf = vec![0u8; 2048];
                let r = iphc::decompress_datagram(
                    &env.table,
                    &src.addr(),
                    &dst.addr(),
                    &first,
                    Some(ip6.len() as u16),
                    &mut buf,
                );
                let o = ot.lowpan_decompress(&src.ffi(), &dst.ffi(), &first, ip6.len() as u16);
                match (r, o) {
                    (Ok(l), Ok((d, _))) if buf[..l] == d[..] => {}
                    (Err(_), Err(_)) => {}
                    (r, o) => diffs.push(format!(
                        "case {i}: first-fragment decompress ours {:?} theirs {:?}\n  frame {}",
                        r.map_err(|e| format!("{e:?}")),
                        o.map(|(d, _)| hex(&d)),
                        hex(&first)
                    )),
                }
            }

            // Both decompress the (identical) compressed form to the original.
            let mut frame = hdr.clone();
            frame.extend_from_slice(&ip6[consumed..]);
            let mut buf = vec![0u8; 2048];
            let r = iphc::decompress_datagram(
                &env.table,
                &src.addr(),
                &dst.addr(),
                &frame,
                None,
                &mut buf,
            );
            let o = ot.lowpan_decompress(&src.ffi(), &dst.ffi(), &frame, 0);
            match (r, o) {
                (Ok(l), Ok((d, _))) => {
                    if buf[..l] != d[..] {
                        diffs.push(format!(
                            "case {i}: decompress differs\n  ours   {}\n  theirs {}",
                            hex(&buf[..l]),
                            hex(&d)
                        ));
                    }
                }
                (r, o) => diffs.push(format!(
                    "case {i}: decompress ours {:?} theirs {:?}\n  frame {}",
                    r.map_err(|e| format!("{e:?}")),
                    o.map(|(d, _)| d.len()),
                    hex(&frame)
                )),
            }
        }
        println!(
            "lowpan compress: {both_ok} identical, {both_err} rejected by both, {known} known OpenThread quirks, {} differences",
            diffs.len()
        );
        assert!(
            diffs.is_empty(),
            "{}\n",
            diffs.iter().take(5).cloned().collect::<Vec<_>>().join("\n")
        );
    }

    /// OpenThread quirks in IPHC decoding that make its result differ from
    /// the RFC (and from ours) for a few inputs:
    /// - a source IID elided to the link-layer address is derived even when
    ///   there is no such address (the error is ignored and the IID is
    ///   whatever the message buffer held; we reject the frame),
    /// - a multicast address with a context prefix shorter than 64 bits gets
    ///   stale bits behind the prefix,
    /// - the IID derived from the link-layer address gets the bits of the
    ///   context named in the CID byte applied even for link-local addresses
    ///   (SAC/DAC = 0), where no context is involved.
    fn known_decompress_difference(
        env: &Env,
        frame: &[u8],
        src: Mac,
        dst: Mac,
        ours_err: bool,
        theirs_ok: bool,
    ) -> bool {
        // The addresses of tunneled headers are not examined: any rejection
        // by us of a frame that OpenThread decodes with an absent link-layer
        // address is this quirk.
        if ours_err && theirs_ok && (matches!(src, Mac::None) || matches!(dst, Mac::None)) {
            return true;
        }
        if frame.len() < 2 {
            return false;
        }
        let b = frame[1];
        let cid = b & 0x80 != 0;
        let (sac, sam, m, dac, dam) = (
            (b >> 6) & 1,
            (b >> 4) & 3,
            (b >> 3) & 1,
            (b >> 2) & 1,
            b & 3,
        );
        let src_elided = sam == 3;
        let dst_elided = m == 0 && dam == 3;
        // Multicast with a context prefix shorter than 64 bits: OpenThread
        // copies 8 prefix bytes including stale bits beyond the prefix length.
        let dst_id = if cid && frame.len() > 2 {
            frame[2] & 0x0f
        } else {
            0
        };
        let short_ctx = env.ctxs.iter().any(|c| c.id == dst_id && c.prefix_len < 64);
        (src_elided && matches!(src, Mac::None))
            || (dst_elided && matches!(dst, Mac::None))
            || (cid && ((src_elided && sac == 0) || (dst_elided && dac == 0)))
            || (m == 1 && dac == 1 && dam == 0 && short_ctx)
    }

    /// Decompression of arbitrary and mutated frames: same accept/reject
    /// decision and, when accepted, the same datagram.
    #[test]
    fn decompress_arbitrary_frames_match() {
        let ot = ffi::lock();
        let mut rng = Rng::new(0x10a1);
        let n = cases(6000);
        let mut env = Env::random(&mut rng);
        env.configure(&ot);
        let (mut ok, mut err, mut known) = (0usize, 0usize, 0usize);
        let mut diffs = Vec::new();
        for i in 0..n {
            if i % 30 == 0 {
                env = Env::random(&mut rng);
                env.configure(&ot);
            }
            let (src, dst) = (Mac::random(&mut rng), Mac::random(&mut rng));
            let frame = if rng.chance(1, 3) {
                // Random bytes behind an IPHC dispatch.
                let mut f = rng.vec_range(2, 40);
                f[0] = 0x60 | (f[0] & 0x1f);
                f
            } else {
                // A valid frame with a few mutations.
                let ip6 = gen_ip6(&mut rng, &env, src, dst, 0);
                let Some((mut f, consumed)) = rust_compress(&env, src, dst, &ip6, 127) else {
                    continue;
                };
                f.extend_from_slice(&ip6[consumed..]);
                for _ in 0..rng.below(3) {
                    if f.is_empty() {
                        break;
                    }
                    match rng.below(4) {
                        0 => {
                            let k = rng.below(f.len().min(14));
                            f[k] ^= 1 << rng.below(8);
                        }
                        1 => {
                            let k = rng.below(f.len());
                            f[k] = rng.u8();
                        }
                        2 => f.truncate(rng.below(f.len())),
                        _ => {
                            let k = rng.below(f.len().min(12) + 1);
                            f.insert(k, rng.u8());
                        }
                    }
                }
                f
            };
            if frame.is_empty() {
                continue;
            }
            let mut buf = vec![0u8; 2048];
            let r = iphc::decompress_datagram(
                &env.table,
                &src.addr(),
                &dst.addr(),
                &frame,
                None,
                &mut buf,
            );
            let o = ot.lowpan_decompress(&src.ffi(), &dst.ffi(), &frame, 0);
            let same = match (&r, &o) {
                (Ok(l), Ok((d, _))) => buf[..*l] == d[..],
                (Err(_), Err(_)) => true,
                _ => false,
            };
            if !same && known_decompress_difference(&env, &frame, src, dst, r.is_err(), o.is_ok()) {
                known += 1;
                continue;
            }
            match (&r, &o) {
                (Ok(l), Ok((d, _))) => {
                    ok += 1;
                    if buf[..*l] != d[..] {
                        diffs.push(format!(
                            "case {i}: output differs (src {:?} dst {:?})\n  frame  {}\n  ours   {}\n  theirs {}",
                            src.ffi(),
                            dst.ffi(),
                            hex(&frame),
                            hex(&buf[..*l]),
                            hex(d)
                        ));
                    }
                }
                (Err(_), Err(_)) => err += 1,
                _ => diffs.push(format!(
                    "case {i}: ours {:?}, theirs {:?}\n  frame {} (src {:?} dst {:?})",
                    r.as_ref().map(|l| &buf[..*l]).map_err(|e| format!("{e:?}")),
                    o.as_ref().map(|(d, _)| hex(d)),
                    hex(&frame),
                    src.ffi(),
                    dst.ffi()
                )),
            }
        }
        println!(
            "lowpan decompress: {ok} accepted by both, {err} rejected by both, {known} known OpenThread quirks, {} differences",
            diffs.len()
        );
        assert!(
            diffs.is_empty(),
            "{}\n",
            diffs.iter().take(5).cloned().collect::<Vec<_>>().join("\n")
        );
    }

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }
}
