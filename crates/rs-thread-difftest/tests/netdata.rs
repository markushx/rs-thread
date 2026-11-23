//! Network Data differential tests: entries seen through OpenThread's public
//! iterators and the stable subset (`RemoveTemporaryData`).

#[cfg(not(feature = "ot"))]
#[test]
fn skipped() {
    rs_thread_difftest::skipped("netdata");
}

#[cfg(feature = "ot")]
mod ot {
    use std::fmt::Write as _;

    use rs_thread_difftest::{Rng, cases, ffi};
    use rs_thread_mesh::netdata::NetworkDataView;
    use rs_thread_mesh::netdata::tlv::NetPrefix;

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    fn prefix(p: &NetPrefix) -> String {
        let n = p.len() as usize;
        format!("{}/{}", hex(&p.as_bytes()[..n.div_ceil(8)]), n)
    }

    /// Our rendering of the entries, in the format of the shim.
    fn dump(d: &[u8]) -> String {
        let v = NetworkDataView(d);
        let mut s = String::new();
        for e in v.on_mesh_prefixes() {
            let f = e.flags;
            let flag = |b: u16| f.has(b) as u8;
            let _ = writeln!(
                s,
                "B {} pref={} P{} S{} D{} C{} R{} O{} N{} DP{} stable={} rloc={:04x}",
                prefix(&e.prefix),
                f.preference(),
                flag(rs_thread_mesh::netdata::tlv::BrFlags::PREFERRED),
                flag(rs_thread_mesh::netdata::tlv::BrFlags::SLAAC),
                flag(rs_thread_mesh::netdata::tlv::BrFlags::DHCP),
                flag(rs_thread_mesh::netdata::tlv::BrFlags::CONFIGURE),
                flag(rs_thread_mesh::netdata::tlv::BrFlags::DEFAULT_ROUTE),
                flag(rs_thread_mesh::netdata::tlv::BrFlags::ON_MESH),
                flag(rs_thread_mesh::netdata::tlv::BrFlags::ND_DNS),
                flag(rs_thread_mesh::netdata::tlv::BrFlags::DP),
                e.stable as u8,
                e.rloc16
            );
        }
        for e in v.external_routes() {
            let _ = writeln!(
                s,
                "R {} pref={} nat64={} adv={} stable={} rloc={:04x}",
                prefix(&e.prefix),
                e.preference,
                e.nat64 as u8,
                e.adv_pio as u8,
                e.stable as u8,
                e.rloc16
            );
        }
        for e in v.services() {
            let _ = writeln!(
                s,
                "S id={} ent={} sd={} srv={} stable={} rloc={:04x}",
                e.service_id,
                e.enterprise_number,
                hex(e.service_data),
                hex(e.server_data),
                e.stable as u8,
                e.rloc16
            );
        }
        for e in v.contexts() {
            let _ = writeln!(
                s,
                "C id={} comp={} {} stable={}",
                e.id,
                e.compress as u8,
                prefix(&e.prefix),
                e.stable as u8
            );
        }
        s
    }

    fn tlv(ty: u8, stable: bool, value: &[u8]) -> Vec<u8> {
        let mut v = vec![ty << 1 | stable as u8, value.len() as u8];
        v.extend_from_slice(value);
        v
    }

    fn gen_prefix(rng: &mut Rng) -> Vec<u8> {
        let plen = *rng.pick(&[64u8, 64, 64, 48, 0, 8, 127, 128, 65, 1]);
        let nbytes = (plen as usize).div_ceil(8);
        let mut body = vec![0u8, plen];
        let mut p = rng.vec(nbytes);
        if plen % 8 != 0 && nbytes > 0 {
            p[nbytes - 1] &= 0xffu8 << (8 - plen % 8);
        }
        body.extend(p);
        // At most one 6LoWPAN Context ID sub-TLV per prefix.
        let mut have_context = false;
        for _ in 0..1 + rng.below(3) {
            let stable = rng.chance(1, 2);
            match rng.below(3) {
                2 if have_context => {}
                0 => {
                    // Has Route entries: RLOC16 + flags byte.
                    let mut v = Vec::new();
                    for _ in 0..1 + rng.below(3) {
                        v.extend_from_slice(&rng.u16().to_be_bytes());
                        v.push(rng.u8());
                    }
                    if rng.chance(1, 20) {
                        v.push(rng.u8());
                    }
                    body.extend(tlv(0, stable, &v));
                }
                1 => {
                    // Border Router entries: RLOC16 + 2 flag bytes.
                    let mut v = Vec::new();
                    for _ in 0..1 + rng.below(3) {
                        v.extend_from_slice(&rng.u16().to_be_bytes());
                        v.extend_from_slice(&rng.u16().to_be_bytes());
                    }
                    if rng.chance(1, 20) {
                        v.push(rng.u8());
                    }
                    body.extend(tlv(2, stable, &v));
                }
                _ => {
                    have_context = true;
                    let cid = rng.u8() & 0x1f;
                    // A context longer than its prefix makes OpenThread read the
                    // bytes behind the prefix; keep it within the prefix.
                    let clen = if rng.chance(1, 6) {
                        rng.u8() % (plen + 1)
                    } else {
                        plen
                    };
                    body.extend(tlv(3, stable, &[cid, clen]));
                }
            }
        }
        tlv(1, rng.chance(1, 2), &body)
    }

    fn gen_service(rng: &mut Rng) -> Vec<u8> {
        let mut body = Vec::new();
        let sid = rng.u8() & 0x0f;
        if rng.chance(1, 2) {
            // Thread enterprise number, T bit set.
            body.push(0x80 | sid);
        } else {
            body.push(sid);
            body.extend_from_slice(&rng.u32().to_be_bytes());
        }
        let sd = rng.vec_below(10);
        body.push(sd.len() as u8);
        body.extend(sd);
        for _ in 0..1 + rng.below(3) {
            let mut v = rng.u16().to_be_bytes().to_vec();
            v.extend(rng.vec_below(8));
            body.extend(tlv(6, rng.chance(1, 2), &v));
        }
        tlv(5, rng.chance(1, 2), &body)
    }

    fn gen_netdata(rng: &mut Rng) -> (Vec<u8>, bool) {
        let mut d = Vec::new();
        for _ in 0..rng.below(4) {
            d.extend(match rng.below(5) {
                0 => gen_service(rng),
                1 => tlv(4, rng.chance(1, 2), &rng.vec_below(12)),
                _ => gen_prefix(rng),
            });
        }
        // Occasional corruption.
        let corrupted = rng.chance(1, 6) && !d.is_empty();
        if corrupted {
            match rng.below(3) {
                0 => {
                    let k = rng.below(d.len());
                    d[k] = rng.u8();
                }
                1 => {
                    let k = rng.below(d.len());
                    d.truncate(k);
                }
                _ => d.push(rng.u8()),
            }
        }
        (d, corrupted)
    }

    /// Splits `d` into `(type byte, value)` TLVs that fill it exactly.
    fn frame(d: &[u8]) -> Option<Vec<(u8, &[u8])>> {
        let (mut v, mut i) = (Vec::new(), 0);
        while i < d.len() {
            let n = *d.get(i + 1)? as usize;
            v.push((d[i], d.get(i + 2..i + 2 + n)?));
            i += 2 + n;
        }
        Some(v)
    }

    /// The structure OpenThread relies on without checking it again (it
    /// asserts on anything else, so only such data may be fed to it): TLVs
    /// that fill their parents exactly, Prefix TLVs that hold the prefix,
    /// Has Route / Border Router values in whole entries, a 2-byte Context
    /// sub-TLV and Server sub-TLVs with an RLOC16.
    fn well_formed(d: &[u8]) -> bool {
        let Some(tlvs) = frame(d) else {
            return false;
        };
        tlvs.iter().all(|(t, v)| match t >> 1 {
            1 => {
                if v.len() < 2 || v[1] > 128 {
                    return false;
                }
                let skip = 2 + (v[1] as usize).div_ceil(8);
                v.get(skip..).and_then(frame).is_some_and(|subs| {
                    subs.iter().all(|(st, sv)| match st >> 1 {
                        0 => !sv.is_empty() && sv.len() % 3 == 0,
                        2 => !sv.is_empty() && sv.len() % 4 == 0,
                        3 => sv.len() == 2 && sv[1] <= 128,
                        _ => true,
                    })
                })
            }
            5 => {
                let Some(&first) = v.first() else {
                    return false;
                };
                let skip = if first & 0x80 != 0 { 1 } else { 5 };
                let Some(&sd) = v.get(skip) else {
                    return false;
                };
                v.get(skip + 1 + sd as usize..)
                    .and_then(frame)
                    .is_some_and(|subs| subs.iter().all(|(st, sv)| st >> 1 != 6 || sv.len() >= 2))
            }
            _ => true,
        })
    }

    #[test]
    fn entries_and_stable_subset_match() {
        let ot = ffi::lock();
        let mut rng = Rng::new(0x9e7d);
        let (mut same, mut skipped, mut known, mut diffs) = (0usize, 0usize, 0usize, Vec::new());
        for i in 0..cases(5000) {
            let (d, corrupted) = gen_netdata(&mut rng);
            if d.len() > 250 {
                continue;
            }
            if !well_formed(&d) {
                // OpenThread does not tolerate this; we must not panic.
                let _ = dump(&d);
                let mut out = [0u8; 255];
                let _ = NetworkDataView(&d).copy_stable(&mut out);
                skipped += 1;
                continue;
            }
            let theirs = ot.netdata(&d, false).map(|v| String::from_utf8(v).unwrap());
            let ours = dump(&d);
            match theirs {
                Some(t) if t == ours => same += 1,
                // A corrupted Context length behind its prefix makes OpenThread
                // read the bytes that follow the prefix.
                Some(_) if corrupted => known += 1,
                t => diffs.push(format!(
                    "case {i}: entries differ\n  data   {}\n  ours   {:?}\n  theirs {:?}",
                    hex(&d),
                    ours,
                    t
                )),
            }

            // Stable subset. (OpenThread keeps the bits behind a prefix length
            // as received, we zero them; only corrupted data has such bits.)
            if corrupted {
                continue;
            }
            let mut out = [0u8; 255];
            let ours = NetworkDataView(&d)
                .copy_stable(&mut out)
                .map(|n| out[..n].to_vec());
            let theirs = ot.netdata(&d, true);
            match (ours, theirs) {
                (Ok(a), Some(b)) if a == b => same += 1,
                (a, b) => diffs.push(format!(
                    "case {i}: stable subset differs\n  data   {}\n  ours   {:?}\n  theirs {:?}",
                    hex(&d),
                    a.map(|v| hex(&v)),
                    b.map(|v| hex(&v))
                )),
            }
        }
        println!(
            "netdata: {same} comparisons identical, {skipped} malformed inputs only fed to us, {known} known differences, {} unexpected",
            diffs.len()
        );
        assert!(
            diffs.is_empty(),
            "{}",
            diffs.iter().take(5).cloned().collect::<Vec<_>>().join("\n")
        );
    }
}
