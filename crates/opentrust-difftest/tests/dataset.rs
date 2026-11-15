//! MeshCoP operational dataset differential tests: validation
//! (`otDatasetParseTlvs`) and the TLVs OpenThread keeps
//! (`otDatasetConvertToTlvs`).

#[cfg(not(feature = "ot"))]
#[test]
fn skipped() {
    opentrust_difftest::skipped("dataset");
}

#[cfg(feature = "ot")]
mod ot {
    use opentrust_difftest::{Rng, cases, ffi};
    use opentrust_meshcop::dataset::Dataset;

    const KNOWN: [u8; 13] = [0, 1, 2, 3, 4, 5, 7, 12, 14, 51, 52, 53, 74];

    fn gen_value(rng: &mut Rng, ty: u8) -> Vec<u8> {
        let mut v = match ty {
            0 | 74 => {
                let page = if rng.chance(9, 10) { 0 } else { rng.u8() };
                let ch = if rng.chance(9, 10) {
                    11 + rng.below(16) as u16
                } else {
                    rng.u16()
                };
                let mut v = vec![page];
                v.extend_from_slice(&ch.to_be_bytes());
                v
            }
            1 => rng.vec(2),
            2 | 7 | 14 | 51 => rng.vec(8),
            3 => {
                let len = if rng.chance(9, 10) {
                    1 + rng.below(16)
                } else {
                    rng.below(30)
                };
                if rng.chance(9, 10) {
                    (0..len).map(|_| b'a' + rng.u8() % 26).collect()
                } else {
                    rng.vec(len)
                }
            }
            4 | 5 => rng.vec(16),
            12 => {
                let n = *rng.pick(&[3usize, 3, 4, 4, 5, 2, 6]);
                rng.vec(n)
            }
            52 => rng.vec(4),
            53 => {
                // Entries: page, length, mask bytes.
                let mut v = Vec::new();
                for _ in 0..1 + rng.below(2) {
                    let n = *rng.pick(&[4u8, 4, 4, 2, 5]);
                    v.push(rng.u8() % 3);
                    v.push(n);
                    v.extend(rng.vec(n as usize));
                }
                v
            }
            _ => rng.vec_below(20),
        };
        // Wrong lengths (too short or long) now and then.
        if rng.chance(1, 8) && !v.is_empty() {
            match rng.below(3) {
                0 => v.truncate(rng.below(v.len())),
                1 => v.extend(rng.vec_range(1, 4)),
                _ => v.pop().map(|_| ()).unwrap_or(()),
            }
        }
        v
    }

    fn gen_dataset(rng: &mut Rng) -> Vec<u8> {
        let mut d = Vec::new();
        let mut types: Vec<u8> = KNOWN.iter().copied().filter(|_| rng.chance(3, 4)).collect();
        for _ in 0..rng.below(3) {
            types.push(*rng.pick(&[6u8, 9, 11, 33, 200, 255]));
        }
        if rng.chance(1, 20) && !types.is_empty() {
            let t = *rng.pick(&types);
            types.push(t); // duplicate
        }
        for t in types {
            let v = gen_value(rng, t);
            if v.len() > 250 {
                continue;
            }
            d.push(t);
            d.push(v.len() as u8);
            d.extend(v);
        }
        match rng.below(6) {
            0 if !d.is_empty() => {
                let k = rng.below(d.len());
                d[k] = rng.u8();
            }
            1 if !d.is_empty() => {
                let k = rng.below(d.len() + 1);
                d.truncate(k);
            }
            2 => d.push(rng.u8()),
            _ => {}
        }
        d
    }

    /// `(type, value)` list of well-framed TLVs.
    fn split(tlvs: &[u8]) -> Vec<(u8, &[u8])> {
        let (mut v, mut i) = (Vec::new(), 0);
        while i + 2 <= tlvs.len() {
            let n = tlvs[i + 1] as usize;
            v.push((tlvs[i], &tlvs[i + 2..i + 2 + n]));
            i += 2 + n;
        }
        v
    }

    #[test]
    fn validation_and_kept_tlvs_match() {
        let ot = ffi::lock();
        let mut rng = Rng::new(0xd5e7);
        let (mut ok, mut rej, mut known) = (0usize, 0usize, 0usize);
        let mut diffs = Vec::new();
        for i in 0..cases(8000) {
            let d = gen_dataset(&mut rng);
            let ours = Dataset::from_tlvs(&d);
            let theirs = ot.dataset_roundtrip(&d);
            match (&ours, &theirs) {
                (Ok(ds), Ok(kept)) => {
                    ok += 1;
                    // Every TLV OpenThread keeps has our value (OpenThread
                    // reads the fixed-size prefix and drops what it does not
                    // know).
                    for (ty, v) in split(kept) {
                        let ours = split(ds.as_bytes()).into_iter().find(|(t, _)| *t == ty);
                        let same = ours.is_some_and(|(_, ov)| match ty {
                            // Variable length or re-encoded by OpenThread:
                            // presence only (policy and mask are normalized).
                            12 | 53 => true,
                            // OpenThread keeps at most 16 bytes of the name.
                            3 => ov == v || (ov.len() > 16 && ov[..16] == *v),
                            _ => ov.len() >= v.len() && ov[..v.len()] == *v,
                        });
                        if !same {
                            diffs.push(format!(
                                "case {i}: TLV {ty} kept by OpenThread as {v:02x?}; ours {ours:02x?}\n  dataset {d:02x?}"
                            ));
                        }
                    }
                    // OpenThread does not drop a known TLV.
                    for (ty, _) in split(ds.as_bytes()) {
                        let known = KNOWN.contains(&ty) && ty != 6;
                        if known && !split(kept).iter().any(|(t, _)| *t == ty) {
                            diffs.push(format!(
                                "case {i}: OpenThread dropped TLV {ty}\n  dataset {d:02x?}"
                            ));
                        }
                    }
                }
                (Err(_), Err(_)) => rej += 1,
                // OpenThread's UTF-8 check only looks at the lead and
                // continuation byte pattern: overlong encodings and surrogates
                // pass there, we (std) reject them.
                (Err(_), Ok(_))
                    if split(&d)
                        .iter()
                        .any(|(t, v)| *t == 3 && std::str::from_utf8(v).is_err()) =>
                {
                    known += 1
                }
                _ => diffs.push(format!(
                    "case {i}: ours {} theirs {:?}\n  dataset {d:02x?}",
                    if ours.is_ok() { "accepts" } else { "rejects" },
                    theirs.as_ref().map(|_| "accepts").map_err(|e| *e)
                )),
            }
        }
        println!(
            "dataset: {ok} accepted by both, {rej} rejected by both, {known} known differences, {} unexpected",
            diffs.len()
        );
        assert!(
            diffs.is_empty(),
            "{}",
            diffs.iter().take(6).cloned().collect::<Vec<_>>().join("\n")
        );
    }
}
