//! MLE TLV differential tests: finding TLVs in a stream
//! (`Tlv::FindTlvValueOffsetRange`) and typed reads of fixed-size unsigned
//! TLVs (`Tlv::Find<UintTlvInfo>`).

#[cfg(not(feature = "ot"))]
#[test]
fn skipped() {
    opentrust_difftest::skipped("mle");
}

#[cfg(feature = "ot")]
mod ot {
    use opentrust_core::Error;
    use opentrust_difftest::{Rng, cases, ffi};
    use opentrust_mle::tlv::Tlvs;

    /// `(type, size)` of the fixed-size unsigned TLVs.
    const UINTS: [(u8, usize); 12] = [
        (0, 2),   // Source Address
        (1, 1),   // Mode
        (2, 4),   // Timeout
        (5, 4),   // Link Frame Counter
        (8, 4),   // MLE Frame Counter
        (10, 2),  // Address16
        (16, 1),  // Link Margin
        (18, 2),  // Version
        (21, 2),  // PAN ID
        (27, 2),  // Supervision Interval
        (85, 4),  // CSL Timeout
        (254, 2), // XTAL Accuracy
    ];

    const OT_NOT_FOUND: i32 = 23;
    const OT_PARSE: i32 = 6; // the typed read of a TLV of the wrong size

    fn gen_stream(rng: &mut Rng) -> Vec<u8> {
        let mut d = Vec::new();
        for _ in 0..rng.below(8) {
            let (ty, size) = if rng.chance(2, 3) {
                *rng.pick(&UINTS)
            } else {
                (rng.u8() % 100, rng.below(20))
            };
            let len = match rng.below(10) {
                0 => size.saturating_sub(1),
                1 => size + 1 + rng.below(3),
                _ => size,
            };
            let value = rng.vec(len);
            if rng.chance(1, 12) {
                // Extended length form.
                d.push(ty);
                d.push(0xff);
                d.extend_from_slice(&(len as u16).to_be_bytes());
            } else {
                d.push(ty);
                d.push(len as u8);
            }
            d.extend(value);
        }
        match rng.below(8) {
            0 if !d.is_empty() => {
                let k = rng.below(d.len());
                d[k] = rng.u8();
            }
            1 if !d.is_empty() => {
                let k = rng.below(d.len());
                d.truncate(k);
            }
            2 => d.push(rng.u8()),
            _ => {}
        }
        d
    }

    fn class(e: &Error) -> i32 {
        match e {
            Error::NotFound => OT_NOT_FOUND,
            _ => OT_PARSE,
        }
    }

    fn be(v: &[u8]) -> u32 {
        v.iter().fold(0u32, |a, b| a << 8 | *b as u32)
    }

    #[test]
    fn find_and_typed_reads_match() {
        let ot = ffi::lock();
        let mut rng = Rng::new(0x31e0);
        let (mut found, mut absent, mut errors) = (0usize, 0usize, 0usize);
        let mut diffs = Vec::new();
        for i in 0..cases(8000) {
            let s = gen_stream(&mut rng);
            let tlvs = Tlvs(&s);
            let mut types: Vec<u8> = UINTS.iter().map(|(t, _)| *t).collect();
            types.push(rng.u8() % 100);

            for ty in types {
                // Generic find.
                let ours = tlvs.find(ty);
                let theirs = ot.mle_find(&s, ty);
                match (&ours, &theirs) {
                    (Ok(t), Ok(v)) => {
                        found += 1;
                        if t.value() != &v[..] {
                            diffs.push(format!(
                                "case {i}: type {ty} value differs\n  stream {s:02x?}"
                            ));
                        }
                    }
                    (Err(e), Err(c)) if class(e) == *c => {
                        if *c == OT_NOT_FOUND {
                            absent += 1
                        } else {
                            errors += 1
                        }
                    }
                    _ => diffs.push(format!(
                        "case {i}: find type {ty}: ours {:?} theirs {:?}\n  stream {s:02x?}",
                        ours.as_ref().map(|t| t.value()),
                        theirs
                    )),
                }

                // Typed read of the unsigned TLVs.
                if let Some((_, size)) = UINTS.iter().find(|(t, _)| *t == ty) {
                    let ours = ours.and_then(|t| match size {
                        1 => t.read_u8().map(u32::from),
                        2 => t.read_u16().map(u32::from),
                        _ => t.read_u32(),
                    });
                    let theirs = ot.mle_uint(&s, ty);
                    match (&ours, &theirs) {
                        (Ok(a), Ok(b)) if a == b => {}
                        (Err(_), Err(_)) => {}
                        _ => diffs.push(format!(
                            "case {i}: typed read of type {ty}: ours {:?} theirs {:?}\n  stream {s:02x?}",
                            ours, theirs
                        )),
                    }
                }
            }
            let _ = be;
        }
        println!(
            "mle tlvs: {found} found, {absent} absent, {errors} malformed (agreeing), {} differences",
            diffs.len()
        );
        assert!(
            diffs.is_empty(),
            "{}",
            diffs.iter().take(6).cloned().collect::<Vec<_>>().join("\n")
        );
    }
}
