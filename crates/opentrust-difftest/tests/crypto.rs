//! Crypto and key-derivation differential tests (AES-CCM*, nonces, Thread
//! keys, TREL key, KEK, HKDF/HMAC/SHA-256, PBKDF2, PSKc).

#[cfg(not(feature = "ot"))]
#[test]
fn skipped() {
    opentrust_difftest::skipped("crypto");
}

#[cfg(feature = "ot")]
mod ot {
    use opentrust_core::crypto::backend::CryptoBackend;
    use opentrust_core::crypto::{SecurityLevel, SoftCrypto, ccm, kdf, nonce, pskc};
    use opentrust_core::types::{ExtAddress, ExtPanId, NetworkKey, NetworkName};
    use opentrust_difftest::{Rng, cases, ffi};

    const SB: SoftCrypto = SoftCrypto;

    #[test]
    fn aes_ccm_matches() {
        let ot = ffi::lock();
        let mut rng = Rng::new(0xcc01);
        let n = cases(3000);
        for i in 0..n {
            let key = rng.bytes::<16>();
            let nonce_b = rng.bytes::<13>();
            let aad = rng.vec_below(48);
            // Mostly short payloads, sometimes long ones.
            let len = if rng.chance(1, 10) {
                rng.below(1200)
            } else {
                rng.below(130)
            };
            let plain = rng.vec(len);
            let tag_len = *rng.pick(&[4usize, 6, 8, 10, 12, 14, 16]);

            let (ot_ct, ot_tag) = ot.aes_ccm(&key, &nonce_b, &aad, &plain, tag_len, true);

            let cipher = SB.aes128(&key);
            let mut ct = plain.clone();
            let mut tag = vec![0u8; tag_len];
            ccm::encrypt(&cipher, &nonce_b, &aad, &mut ct, &mut tag).unwrap();
            assert_eq!(ct, ot_ct, "case {i}: ciphertext");
            assert_eq!(tag, ot_tag, "case {i}: tag");

            // OpenThread decrypts what we encrypted and vice versa.
            let (ot_pt, ot_tag2) = ot.aes_ccm(&key, &nonce_b, &aad, &ct, tag_len, false);
            assert_eq!(ot_pt, plain, "case {i}: OT decrypt");
            assert_eq!(ot_tag2, tag, "case {i}: OT decrypt tag");
            let mut pt = ot_ct.clone();
            ccm::decrypt(&cipher, &nonce_b, &aad, &mut pt, &ot_tag).unwrap();
            assert_eq!(pt, plain, "case {i}: our decrypt");
        }
    }

    #[test]
    fn frame_security_levels_match() {
        let ot = ffi::lock();
        let mut rng = Rng::new(0xcc02);
        for i in 0..cases(1500) {
            let key = rng.bytes::<16>();
            let src = rng.bytes::<8>();
            let counter = rng.u32();
            let level = SecurityLevel::from_bits(4 + rng.u8() % 4);
            let nonce_b = nonce::mac_nonce(&ExtAddress(src), counter, level);
            assert_eq!(
                nonce_b,
                ot.ccm_nonce(&src, counter, level.value()),
                "case {i}: nonce"
            );

            let header = rng.vec_range(5, 30);
            let plain = rng.vec_below(100);
            let mic_len = level.mic_len();
            if mic_len == 0 {
                continue;
            }
            let cipher = SB.aes128(&key);
            let mut payload = plain.clone();
            let mut mic = vec![0u8; mic_len];
            ccm::seal_frame(&cipher, &nonce_b, level, &header, &mut payload, &mut mic).unwrap();
            let (ot_ct, ot_tag) = ot.aes_ccm(&key, &nonce_b, &header, &plain, mic_len, true);
            assert_eq!((payload, mic), (ot_ct, ot_tag), "case {i}: level {level:?}");
        }
    }

    #[test]
    fn mle_nonce_matches() {
        let ot = ffi::lock();
        let mut rng = Rng::new(0xcc03);
        for _ in 0..cases(500) {
            let src = rng.bytes::<8>();
            let counter = rng.u32();
            assert_eq!(
                nonce::mle_nonce(&ExtAddress(src), counter),
                ot.ccm_nonce(&src, counter, 5)
            );
        }
    }

    #[test]
    fn thread_keys_match() {
        let ot = ffi::lock();
        let mut rng = Rng::new(0xcc04);
        let mut seqs = vec![0u32, 1, 0x7f, 0x80, 0xffff_ffff];
        for _ in 0..cases(1000) {
            seqs.push(rng.u32());
        }
        for (i, seq) in seqs.into_iter().enumerate() {
            let nk = NetworkKey(rng.bytes::<16>());
            let ours = kdf::thread_keys(&SB, &nk, seq);
            let (mle, mac) = ot.thread_keys(&nk.0, seq);
            assert_eq!(ours.mle_key.0, mle, "case {i}: MLE key (seq {seq})");
            assert_eq!(ours.mac_key.0, mac[1], "case {i}: MAC key (seq {seq})");
            let prev = kdf::thread_keys(&SB, &nk, seq.wrapping_sub(1));
            let next = kdf::thread_keys(&SB, &nk, seq.wrapping_add(1));
            assert_eq!(prev.mac_key.0, mac[0], "case {i}: previous MAC key");
            assert_eq!(next.mac_key.0, mac[2], "case {i}: next MAC key");
        }
    }

    #[test]
    fn trel_key_matches() {
        let ot = ffi::lock();
        let mut rng = Rng::new(0xcc05);
        for i in 0..cases(1000) {
            let nk = NetworkKey(rng.bytes::<16>());
            let seq = if i == 0 { 0 } else { rng.u32() };
            assert_eq!(
                kdf::trel_key(&SB, &nk, seq).0,
                ot.trel_key(&nk.0, seq),
                "case {i}"
            );
        }
    }

    #[test]
    fn hkdf_hmac_sha256_match() {
        let ot = ffi::lock();
        let mut rng = Rng::new(0xcc06);
        for i in 0..cases(1500) {
            let salt = rng.vec_below(80);
            let ikm = rng.vec_range(1, 80);
            let info = rng.vec_below(40);
            let out_len = 1 + rng.below(100);
            let mut a = vec![0u8; out_len];
            kdf::hkdf_sha256(&SB, &salt, &ikm, &info, &mut a).unwrap();
            let mut b = vec![0u8; out_len];
            ot.hkdf_sha256(&salt, &ikm, &info, &mut b);
            assert_eq!(a, b, "case {i}: HKDF");

            let msg = rng.vec_below(300);
            let key = rng.vec_range(1, 100);
            let mut h = SB.hmac_sha256(&key);
            opentrust_core::crypto::HmacSha256::update(&mut h, &msg);
            let ours = opentrust_core::crypto::HmacSha256::finalize(h);
            assert_eq!(ours, ot.hmac_sha256(&key, &msg), "case {i}: HMAC");

            let mut s = SB.sha256();
            opentrust_core::crypto::Sha256::update(&mut s, &msg);
            assert_eq!(
                opentrust_core::crypto::Sha256::finalize(s),
                ot.sha256(&msg),
                "case {i}: SHA-256"
            );
        }
    }

    /// KEK: SHA-256 of the DTLS key block (OpenThread `SecureTransport`), the
    /// key block from the TLS 1.2 PRF. The PRF reference is P_SHA256 composed
    /// of OpenThread's HMAC-SHA-256 (mbedTLS' own PRF is not exported).
    #[test]
    fn kek_derivation_matches() {
        let ot = ffi::lock();
        let mut rng = Rng::new(0xcc07);
        for i in 0..cases(500) {
            let master = rng.bytes::<{ kdf::MASTER_SECRET_LEN }>();
            let client = rng.bytes::<{ kdf::TLS_RANDOM_LEN }>();
            let server = rng.bytes::<{ kdf::TLS_RANDOM_LEN }>();

            // P_SHA256(secret, "key expansion" || server || client), 40 bytes.
            let mut seed = b"key expansion".to_vec();
            seed.extend_from_slice(&server);
            seed.extend_from_slice(&client);
            let mut block = Vec::new();
            let mut a = seed.clone();
            while block.len() < kdf::KEY_BLOCK_LEN {
                a = ot.hmac_sha256(&master, &a).to_vec();
                let mut input = a.clone();
                input.extend_from_slice(&seed);
                block.extend_from_slice(&ot.hmac_sha256(&master, &input));
            }
            block.truncate(kdf::KEY_BLOCK_LEN);
            let kek_ot = ot.sha256(&block);

            let kek = kdf::kek_from_master_secret(&SB, &master, &client, &server);
            assert_eq!(kek.0, kek_ot[..16], "case {i}");
            assert_eq!(
                kdf::kek_from_key_block(&SB, &block).0,
                kek_ot[..16],
                "case {i}"
            );
        }
    }

    #[test]
    fn pbkdf2_cmac_matches() {
        let ot = ffi::lock();
        let mut rng = Rng::new(0xcc08);
        for i in 0..cases(600) {
            let pw = rng.vec_range(1, 40);
            // OpenThread asserts on salts over 30 bytes and odd iteration counts.
            let salt = rng.vec_below(31);
            let iterations = 2 * (1 + rng.u32() % 20);
            let key_len = 1 + rng.below(48);
            let mut a = vec![0u8; key_len];
            pskc::pbkdf2_aes_cmac_prf_128(&SB, &pw, &salt, iterations, &mut a).unwrap();
            let mut b = vec![0u8; key_len];
            ot.pbkdf2_cmac(&pw, &salt, iterations, &mut b).unwrap();
            assert_eq!(a, b, "case {i}");
        }
    }

    #[test]
    fn pskc_matches() {
        let ot = ffi::lock();
        let mut rng = Rng::new(0xcc09);
        // 16384 iterations per case: far fewer cases.
        for i in 0..cases(40).min(150) {
            let pass_len = *rng.pick(&[6usize, 7, 16, 32, 255]);
            let pass: Vec<u8> = (0..pass_len).map(|_| b'A' + rng.u8() % 26).collect();
            let name_len = 1 + rng.below(16);
            let name: Vec<u8> = (0..name_len).map(|_| b'a' + rng.u8() % 26).collect();
            let ext = rng.bytes::<8>();
            let ours = pskc::pskc(
                &SB,
                &pass,
                &NetworkName::from_bytes(&name).unwrap(),
                &ExtPanId(ext),
            )
            .unwrap();
            assert_eq!(ot.pskc(&pass, &name, &ext), Ok(ours.0), "case {i}");
        }
        // Passphrase length limits: both sides reject the same lengths.
        for len in [0usize, 1, 5, 6, 255, 256, 300] {
            let pass = vec![b'x'; len];
            let ours = pskc::pskc(
                &SB,
                &pass,
                &NetworkName::new("net").unwrap(),
                &ExtPanId([1; 8]),
            )
            .is_ok();
            let theirs = ot.pskc(&pass, b"net", &[1; 8]).is_ok();
            assert_eq!(ours, theirs, "passphrase length {len}");
        }
    }
}
