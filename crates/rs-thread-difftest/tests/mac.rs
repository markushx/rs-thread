//! IEEE 802.15.4 MAC frame differential tests: header building
//! (`TxFrame::Info::PrepareHeadersIn`) and parsing (`Mac::Frame`).

#[cfg(not(feature = "ot"))]
#[test]
fn skipped() {
    rs_thread_difftest::skipped("mac");
}

#[cfg(feature = "ot")]
mod ot {
    use rs_thread_core::crypto::SecurityLevel;
    use rs_thread_core::types::{ExtAddress, PanId, ShortAddress};
    use rs_thread_difftest::{Rng, cases, ffi};
    use rs_thread_mac::frame::{
        Address, CslIe, Frame, FrameBuilder, FrameType, FrameVersion, HeaderIeValue,
        IE_ID_HEADER_TERMINATION_1, KeyIdentifier, SecurityHeader,
    };

    fn mac_addr(a: &Address) -> ffi::MacAddr {
        match a {
            Address::None => ffi::MacAddr::default(),
            Address::Short(s) => ffi::MacAddr {
                kind: 1,
                short_addr: s.0.to_be_bytes(),
                ext: [0; 8],
            },
            Address::Extended(e) => ffi::MacAddr {
                kind: 2,
                short_addr: [0; 2],
                ext: e.0,
            },
        }
    }

    fn rand_addr(rng: &mut Rng) -> Address {
        match rng.below(6) {
            0 => Address::None,
            1 => Address::Short(ShortAddress::BROADCAST),
            2 | 3 => Address::Short(ShortAddress(rng.u16())),
            _ => Address::Extended(ExtAddress(rng.bytes())),
        }
    }

    /// The fields OpenThread reports for `psdu`, from our parser.
    fn our_info(psdu: &[u8]) -> Option<ffi::MacInfo> {
        let f = Frame::parse(psdu).ok()?;
        let mut i = ffi::MacInfo {
            valid: 1,
            frame_type: f.frame_type().bits(),
            version: f.version().bits(),
            security_enabled: f.security_enabled() as u8,
            frame_pending: f.frame_pending() as u8,
            ack_request: f.ack_request() as u8,
            pan_id_compressed: f.frame_control().pan_id_compression() as u8,
            ie_present: f.ie_present() as u8,
            header_len: f.header_len() as u16,
            payload_len: f.payload().len() as u16,
            footer_len: f.mic_len() as u16,
            ..Default::default()
        };
        if let Some(s) = f.sequence() {
            i.has_seq = 1;
            i.seq = s;
        }
        if let Some(p) = f.dst_pan_id() {
            i.has_dst_pan = 1;
            i.dst_pan = p.0;
        }
        i.dst = mac_addr(&f.dst_address());
        if let Some(p) = f.src_pan_id() {
            i.has_src_pan = 1;
            i.src_pan = p.0;
        }
        i.src = mac_addr(&f.src_address());
        if let Some(s) = f.security_header() {
            i.has_security = 1;
            i.sec_level = s.level.value();
            i.key_id_mode = s.key_id_mode().bits();
            if let Some(c) = s.frame_counter {
                i.has_counter = 1;
                i.counter = c;
            }
            if let Some(k) = s.key.index() {
                i.has_key_id = 1;
                i.key_id = k;
            }
        }
        Some(i)
    }

    struct Params {
        b: ffi::MacBuild,
        dst: Address,
        src: Address,
        dst_pan: Option<PanId>,
        src_pan: Option<PanId>,
    }

    fn gen_params(rng: &mut Rng) -> Params {
        let version = *rng.pick(&[0u8, 1, 1, 2, 2, 2]);
        let frame_type = *rng.pick(&[1u8, 1, 1, 3, 0]);
        let dst = rand_addr(rng);
        let src = rand_addr(rng);
        let both = !dst.is_none() && !src.is_none();
        let (dst_pan, src_pan);
        if version == 2 && !both {
            // Rows 1-6 of the 2015 PAN ID compression table: only the PAN ID
            // of the address that is present can be sent (both absent: the
            // destination PAN ID only).
            let pan = rng.chance(1, 2).then(|| PanId(rng.u16()));
            if src.is_none() {
                dst_pan = pan;
                src_pan = None;
            } else {
                dst_pan = None;
                src_pan = pan;
            }
        } else {
            // OpenThread compares the PAN IDs by value, so both are always set.
            let d = PanId(rng.u16());
            let s = if rng.chance(1, 2) {
                d
            } else {
                PanId(rng.u16())
            };
            dst_pan = Some(d);
            src_pan = Some(s);
        }
        let sec_level = if rng.chance(2, 3) { 5 } else { rng.u8() & 7 };
        let key_id_mode = *rng.pick(&[1u8, 1, 1, 2, 0, 3]);
        let mut b = ffi::MacBuild {
            frame_type,
            version,
            sec_level,
            key_id_mode,
            cmd_id: *rng.pick(&[1u8, 4, 4, 7, 8]),
            has_dst_pan: dst_pan.is_some() as u8,
            has_src_pan: src_pan.is_some() as u8,
            dst_pan: dst_pan.map_or(0, |p| p.0),
            src_pan: src_pan.map_or(0, |p| p.0),
            dst: mac_addr(&dst),
            src: mac_addr(&src),
            seq: rng.u8(),
            key_index: rng.u8(),
            counter: rng.u32(),
            empty_payload: rng.chance(1, 3) as u8,
            ..Default::default()
        };
        if version == 2 {
            b.suppress_seq = rng.chance(1, 4) as u8;
            b.csl_ie = rng.chance(1, 3) as u8;
        }
        Params {
            b,
            dst,
            src,
            dst_pan,
            src_pan,
        }
    }

    /// Our header for the parameters (no payload; MIC area zero).
    fn our_build(p: &Params, buf: &mut [u8]) -> Option<usize> {
        let b = &p.b;
        let ft = FrameType::from_bits(b.frame_type)?;
        let mut fb = FrameBuilder::new(buf)
            .frame_type(ft)
            .version(FrameVersion::from_bits(b.version)?)
            .sequence(b.seq)
            .dst(p.dst)
            .src(p.src);
        if b.suppress_seq != 0 {
            fb = fb.suppress_sequence();
        }
        if let Some(d) = p.dst_pan {
            fb = fb.dst_pan(d);
        }
        if let Some(s) = p.src_pan {
            fb = fb.src_pan(s);
        }
        if b.sec_level != 0 {
            let key = match b.key_id_mode {
                0 => KeyIdentifier::Implicit,
                1 => KeyIdentifier::Index(b.key_index),
                2 => KeyIdentifier::Source4 {
                    source: [0xff; 4],
                    index: b.key_index,
                },
                _ => KeyIdentifier::Source8 {
                    source: [0; 8],
                    index: b.key_index,
                },
            };
            fb = fb.security(SecurityHeader::new(
                SecurityLevel::from_bits(b.sec_level),
                b.counter,
                key,
            ));
        }
        if b.csl_ie != 0 {
            fb = fb.header_ie(HeaderIeValue::Csl(CslIe {
                phase: 0,
                period: 0,
                rendezvous_time: None,
            }));
        }
        if ft == FrameType::MacCmd {
            fb = fb.command_id(b.cmd_id);
        }
        // A payload (any byte) makes the builder append the Header
        // Termination IE like OpenThread's `mEmptyPayload == false`.
        let one = [0xaau8];
        let with_payload = b.empty_payload == 0 && ft != FrameType::MacCmd;
        if with_payload {
            fb = fb.payload(&one);
        }
        let n = fb.build().ok()?;
        // Cut the payload byte and keep the (zero) MIC.
        if with_payload {
            let mic = SecurityLevel::from_bits(b.sec_level).mic_len() * (b.sec_level != 0) as usize;
            let hdr = n - 1 - mic;
            buf.copy_within(hdr + 1..n, hdr);
            Some(n - 1)
        } else {
            Some(n)
        }
    }

    #[test]
    fn header_build_matches() {
        let ot = ffi::lock();
        let mut rng = Rng::new(0x3ac0);
        let n = cases(5000);
        let (mut same, mut rust_rejects) = (0usize, 0usize);
        let mut diffs = Vec::new();
        for i in 0..n {
            let p = gen_params(&mut rng);
            let mut buf = [0u8; 160];
            let ours = our_build(&p, &mut buf).map(|n| buf[..n].to_vec());
            let theirs = ot.mac_build(&p.b);
            match (&ours, &theirs) {
                (Some(a), Some(b)) if a == b => same += 1,
                (None, _) => rust_rejects += 1,
                _ => diffs.push(format!(
                    "case {i}: ours {:02x?}\n  theirs {:02x?}\n  params {:?}",
                    ours.as_ref().map(|v| hex(v)),
                    theirs.as_ref().map(|v| hex(v)),
                    p.b
                )),
            }
            // What OpenThread builds, we parse to the same fields.
            if let Some(t) = &theirs {
                let a = our_info(t);
                let o = ot.mac_parse(t);
                if a != Some(o) && o.valid == 1 {
                    diffs.push(format!(
                        "case {i}: parse of built header {}: ours {a:?} theirs {o:?}",
                        hex(t)
                    ));
                }
            }
        }
        println!(
            "mac build: {same} identical, {rust_rejects} not buildable by us, {} differences",
            diffs.len()
        );
        assert!(
            diffs.is_empty(),
            "{}",
            diffs.iter().take(5).cloned().collect::<Vec<_>>().join("\n")
        );
    }

    fn gen_frame(rng: &mut Rng) -> Vec<u8> {
        let p = gen_params(rng);
        let mut buf = [0u8; 160];
        let hdr = match our_build(&p, &mut buf) {
            Some(n) => n,
            None => return rng.vec_range(5, 30),
        };
        let mic = if p.b.sec_level != 0 {
            SecurityLevel::from_bits(p.b.sec_level).mic_len()
        } else {
            0
        };
        let mut f = buf[..hdr - mic].to_vec();
        f.extend(rng.vec_below(60));
        f.extend(rng.vec(mic));
        f
    }

    /// Where OpenThread (which only validates what it needs) and our stricter
    /// parser knowingly differ on corrupted frames:
    /// - frame types other than beacon, data, ACK and MAC command are
    ///   rejected by us only; multipurpose frames are not compared (the
    ///   OpenThread build has no multipurpose frame support),
    /// - the Sequence Number Suppression and IE Present bits (and the reserved
    ///   version 3) are honoured by OpenThread for every frame version, we
    ///   treat them as reserved before IEEE 802.15.4-2015,
    /// - the reserved address mode 01 is rejected by us only,
    /// - header IEs that are not terminated although payload bytes follow, or a
    ///   MAC command without command identifier, are rejected by us only,
    /// - Header Termination 1 IEs are terminators for us only,
    /// - the Frame Counter Suppression bit of the security control field is
    ///   honoured by us only (OpenThread always reads a counter).
    fn known_parse_difference(f: &[u8], ours: Option<&ffi::MacInfo>) -> bool {
        let fcf = u16::from_le_bytes([f[0], f[1]]);
        let ty = fcf & 7;
        let version = (fcf >> 12) & 3;
        // Multipurpose frames (Thread wake-up frames): the shim's OpenThread
        // is built without multipurpose frame support and reads the FCF in
        // the general format.
        if !matches!(ty, 0..=3) {
            return true;
        }
        if ty != 5 && version != 2 && (fcf & 0x0300 != 0 || version == 3) {
            return true;
        }
        // Reserved address mode 01 (also in the multipurpose layout).
        let (dst, src) = if ty == 5 {
            let raw = if fcf & (1 << 3) != 0 { fcf } else { fcf & 0xff };
            ((raw >> 4) & 3, (raw >> 6) & 3)
        } else {
            ((fcf >> 10) & 3, (fcf >> 14) & 3)
        };
        if dst == 1 || src == 1 {
            return true;
        }
        // We require a terminated IE list before a payload and a command
        // identifier after the IEs of a MAC command; OpenThread takes what is
        // left.
        if ours.is_none() && version == 2 && (fcf & 0x0200 != 0 || ty == 3) {
            return true;
        }
        // Header Termination 1 ends the header IEs for us (payload IEs follow);
        // OpenThread only knows Header Termination 2.
        if Frame::parse(f).is_ok_and(|fr| {
            fr.header_ies()
                .flatten()
                .any(|ie| ie.id == IE_ID_HEADER_TERMINATION_1)
        }) {
            return true;
        }
        ours.is_some_and(|o| o.has_security == 1 && o.has_counter == 0)
    }

    /// Securing a frame: the same ciphertext and MIC from OpenThread's
    /// `ProcessTransmitAesCcm` and `rs_thread_mac::security::seal_psdu`
    /// (nonce from source address, frame counter and security level; header as
    /// authenticated data). Levels 1 to 4 are not compared: OpenThread
    /// encrypts the payload at every level (1 to 3 are authentication only) and
    /// asserts on level 4 (encryption without MIC, a zero-length tag).
    #[test]
    fn frame_security_matches() {
        use rs_thread_core::crypto::{CryptoBackend, SoftCrypto};
        use rs_thread_mac::security::{open_psdu, seal_psdu};

        let ot = ffi::lock();
        let mut rng = Rng::new(0x3ac2);
        let mut compared = 0usize;
        for i in 0..cases(4000) {
            let mut p = gen_params(&mut rng);
            p.b.sec_level = *rng.pick(&[5u8, 5, 5, 6, 7]);
            p.b.key_id_mode = *rng.pick(&[1u8, 1, 2]);
            p.b.suppress_seq = 0;
            // The payload below needs a terminated IE list.
            p.b.empty_payload = 0;
            let mut buf = [0u8; 160];
            let Some(hdr_and_mic) = our_build(&p, &mut buf) else {
                continue;
            };
            let mic = SecurityLevel::from_bits(p.b.sec_level).mic_len();
            let mut frame = buf[..hdr_and_mic - mic].to_vec();
            frame.extend(rng.vec_below(80));
            frame.extend(vec![0u8; mic]);
            let key = rng.bytes::<16>();
            let src = rng.bytes::<8>();

            let mut theirs = frame.clone();
            if !ot.mac_secure(&key, &src, &mut theirs) {
                continue;
            }
            let mut ours = frame.clone();
            let cipher = SoftCrypto.aes128(&key);
            seal_psdu(&cipher, &mut ours, &ExtAddress(src)).unwrap();
            assert_eq!(hex(&ours), hex(&theirs), "case {i}: {:?}", p.b);
            // And we open what OpenThread sealed.
            open_psdu(&cipher, &mut theirs, &ExtAddress(src)).unwrap();
            let n = frame.len() - mic;
            assert_eq!(hex(&theirs[..n]), hex(&frame[..n]), "case {i}: open");
            compared += 1;
        }
        println!("mac security: {compared} frames identical");
    }

    #[test]
    fn parse_matches() {
        let ot = ffi::lock();
        let mut rng = Rng::new(0x3ac1);
        let n = cases(8000);
        let (mut ok, mut rej, mut known) = (0usize, 0usize, 0usize);
        let mut diffs = Vec::new();
        for i in 0..n {
            let mut f = gen_frame(&mut rng);
            match rng.below(4) {
                0 => {}
                1 => {
                    let k = rng.below(f.len().min(16));
                    f[k] ^= 1 << rng.below(8);
                }
                2 => f.truncate(rng.below(f.len() + 1)),
                _ => {
                    let k = rng.below(f.len());
                    f[k] = rng.u8();
                }
            }
            if f.len() < 2 {
                continue;
            }
            let theirs = ot.mac_parse(&f);
            let ours = our_info(&f);
            if ours != Some(theirs) && known_parse_difference(&f, ours.as_ref()) {
                known += 1;
                continue;
            }
            match ours {
                Some(a) if theirs.valid == 1 => {
                    ok += 1;
                    if a != theirs {
                        diffs.push(format!(
                            "case {i}: {}\n  ours   {a:?}\n  theirs {theirs:?}",
                            hex(&f)
                        ));
                    }
                }
                None if theirs.valid == 0 => rej += 1,
                a => diffs.push(format!(
                    "case {i}: {} ours {} theirs {}",
                    hex(&f),
                    if a.is_some() { "accepts" } else { "rejects" },
                    if theirs.valid == 1 {
                        "accepts"
                    } else {
                        "rejects"
                    }
                )),
            }
        }
        println!(
            "mac parse: {ok} accepted by both, {rej} rejected by both, {known} known differences, {} unexpected differences",
            diffs.len()
        );
        assert!(
            diffs.is_empty(),
            "{}",
            diffs.iter().take(8).cloned().collect::<Vec<_>>().join("\n")
        );
    }

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }
}
