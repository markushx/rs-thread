//! Known-answer tests. Sources are cited per test:
//!
//! - Thread 1.4.1 spec §7.1.4 (key derivation), §8.4.1.2.2 (PSKc)
//! - OpenThread `tests/unit/test_aes.cpp` (IEEE 802.15.4-2006 Annex C),
//!   `test_hmac_sha256.cpp` (FIPS 180-2 / RFC 4231), `test_hkdf_sha256.cpp`
//!   (RFC 5869), `test_pskc.cpp`
//! - RFC 3610, RFC 4493, RFC 4615, FIPS-197, the TLS 1.2 PRF test vector
//!   published on the IETF TLS WG list (also used by Go/NSS/mbedTLS tests)
//! - "Reference": values computed with an independent Python/OpenSSL
//!   implementation for constructions that have no published vector (TREL
//!   key, KEK, MLE message); these guard against regressions.

extern crate std;

use std::vec::Vec;

use super::backend::*;
use super::ccm::{self, Ccm, SecurityLevel};
use super::generic::{GenericCmac, GenericHmac};
use super::kdf;
use super::nonce;
use super::pskc;
use super::soft::{SoftAes128, SoftCrypto, SoftSha256};
use crate::error::Error;
use crate::types::{ExtAddress, ExtPanId, Iid, NetworkKey, NetworkName};

fn h(s: &str) -> Vec<u8> {
    let s: Vec<u8> = s.bytes().filter(|c| !c.is_ascii_whitespace()).collect();
    assert!(s.len().is_multiple_of(2));
    s.chunks(2)
        .map(|c| u8::from_str_radix(core::str::from_utf8(c).unwrap(), 16).unwrap())
        .collect()
}

fn h16(s: &str) -> [u8; 16] {
    h(s).try_into().unwrap()
}

fn h13(s: &str) -> [u8; 13] {
    h(s).try_into().unwrap()
}

/// Backend using only AES and SHA-256 from [`SoftCrypto`], with the generic
/// HMAC/CMAC combinators; all vectors run against both backends.
#[derive(Debug)]
struct GenericBackend;

impl CryptoBackend for GenericBackend {
    type Aes128 = SoftAes128;
    type Sha256 = SoftSha256;
    type HmacSha256 = GenericHmac<SoftSha256>;
    type AesCmac = GenericCmac<SoftAes128>;

    fn aes128(&self, key: &[u8; 16]) -> SoftAes128 {
        SoftCrypto.aes128(key)
    }
    fn sha256(&self) -> SoftSha256 {
        SoftCrypto.sha256()
    }
    fn hmac_sha256(&self, key: &[u8]) -> Self::HmacSha256 {
        GenericHmac::new(SoftCrypto.sha256(), key)
    }
    fn aes_cmac(&self, key: &[u8; 16]) -> Self::AesCmac {
        GenericCmac::new(SoftCrypto.aes128(key))
    }
}

macro_rules! both_backends {
    ($name:ident, $body:ident) => {
        #[test]
        fn $name() {
            $body(&SoftCrypto);
            $body(&GenericBackend);
        }
    };
}

// ---------------------------------------------------------------- primitives

#[test]
fn aes128_fips197() {
    // FIPS-197 Appendix C.1
    let c = SoftCrypto.aes128(&h16("000102030405060708090a0b0c0d0e0f"));
    let mut b = h16("00112233445566778899aabbccddeeff");
    c.encrypt_block(&mut b);
    assert_eq!(b.to_vec(), h("69c4e0d86a7b0430d8cdb78070b4c55a"));
}

#[test]
fn sha256_openthread() {
    // OpenThread tests/unit/test_hmac_sha256.cpp TestSha256 (FIPS 180-2)
    let cases: [(&[u8], &str); 4] = [
        (b"abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
        (b"", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
        (
            b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
        ),
        (
            b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
            "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1",
        ),
    ];
    for (data, exp) in cases {
        let mut s = SoftCrypto.sha256();
        // Split updates to exercise incremental hashing.
        let (a, b) = data.split_at(data.len() / 2);
        s.update(a);
        s.update(b);
        assert_eq!(s.finalize_reset().to_vec(), h(exp));
        // After reset the state is empty again.
        s.update(data);
        assert_eq!(s.finalize().to_vec(), h(exp));
    }
}

fn hmac_openthread<B: CryptoBackend>(b: &B) {
    // OpenThread tests/unit/test_hmac_sha256.cpp TestHmacSha256 (RFC 4231
    // test cases 1, 2, 3, 4, 6).
    let k5 = [0xaau8; 131];
    let cases: [(Vec<u8>, Vec<u8>, &str); 5] = [
        (
            [0x0b; 20].to_vec(),
            b"Hi There".to_vec(),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
        ),
        (
            b"Jefe".to_vec(),
            b"what do ya want for nothing?".to_vec(),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
        ),
        (
            [0xaa; 20].to_vec(),
            [0xdd; 50].to_vec(),
            "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe",
        ),
        (
            (1u8..=25).collect(),
            [0xcd; 50].to_vec(),
            "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b",
        ),
        (
            k5.to_vec(),
            b"This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.".to_vec(),
            "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2",
        ),
    ];
    for (key, data, exp) in cases {
        let mut m = b.hmac_sha256(&key);
        for chunk in data.chunks(7) {
            m.update(chunk);
        }
        assert_eq!(m.finalize_reset().to_vec(), h(exp));
        m.update(&data);
        assert_eq!(m.finalize().to_vec(), h(exp));
    }
}
both_backends!(hmac_sha256_openthread_rfc4231, hmac_openthread);

fn cmac_rfc4493<B: CryptoBackend>(b: &B) {
    // RFC 4493 §4
    let key = h16("2b7e151628aed2a6abf7158809cf4f3c");
    let m = h(
        "6bc1bee22e409f96e93d7e117393172a ae2d8a571e03ac9c9eb76fac45af8e51
               30c81c46a35ce411e5fbc1191a0a52ef f69f2445df4f9b17ad2b417be66c3710",
    );
    let cases = [
        (0, "bb1d6929e95937287fa37d129b756746"),
        (16, "070a16b46b4d4144f79bdd9dd04a287c"),
        (40, "dfa66747de9ae63030ca32611497c827"),
        (64, "51f0bebf7e3b9d92fc49741779363cfe"),
    ];
    for (len, exp) in cases {
        let mut c = b.aes_cmac(&key);
        for chunk in m[..len].chunks(5) {
            c.update(chunk);
        }
        assert_eq!(c.finalize_reset().to_vec(), h(exp), "len {len}");
        c.update(&m[..len]);
        assert_eq!(c.finalize().to_vec(), h(exp), "len {len}");
    }
}
both_backends!(aes_cmac_rfc4493, cmac_rfc4493);

fn cmac_prf_rfc4615<B: CryptoBackend>(b: &B) {
    // RFC 4615 §4
    let key = h("000102030405060708090a0b0c0d0e0fedcb");
    let msg = h("000102030405060708090a0b0c0d0e0f10111213");
    for (klen, exp) in [
        (18, "84a348a4a45d235babfffc0d2b4da09a"),
        (16, "980ae87b5f4c9c5214f5b6a8455e4c2d"),
        (10, "290d9e112edb09ee141fcf64c0b72f3d"),
    ] {
        assert_eq!(
            pskc::aes_cmac_prf_128(b, &key[..klen], &msg).to_vec(),
            h(exp)
        );
    }
}
both_backends!(aes_cmac_prf_128_rfc4615, cmac_prf_rfc4615);

// ---------------------------------------------------------------- CCM*

const KEY_C0: &str = "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf";

#[test]
fn ccm_ieee802154_beacon_mic64() {
    // OpenThread test_aes.cpp TestMacBeaconFrame, IEEE 802.15.4-2006
    // Annex C.2.1 (security level 2, MIC-64, authentication only).
    let c = SoftCrypto.aes128(&h16(KEY_C0));
    let nonce = h13("acde480000000001 00000005 02");
    let frame = h("08d0842143010000000048deac020500000055cf000051525354 223bc1ec841ab553");
    let (hdr, mic) = frame.split_at(frame.len() - 8);
    let mut tag = [0u8; 8];
    ccm::seal_frame(&c, &nonce, SecurityLevel::Mic64, hdr, &mut [], &mut tag).unwrap();
    assert_eq!(&tag[..], mic);
    ccm::open_frame(&c, &nonce, SecurityLevel::Mic64, hdr, &mut [], mic).unwrap();
    // Equivalent: whole header || payload as additional data.
    let (hdr2, payload) = hdr.split_at(20);
    let mut payload = payload.to_vec();
    ccm::seal_frame(
        &c,
        &nonce,
        SecurityLevel::Mic64,
        hdr2,
        &mut payload,
        &mut tag,
    )
    .unwrap();
    assert_eq!(&tag[..], mic);
    assert_eq!(payload, &hdr[20..], "MIC-only must not modify the payload");
}

#[test]
fn ccm_ieee802154_data_enc_only() {
    // IEEE 802.15.4-2006 Annex C.2.2 (security level 4, ENC, M = 0); the
    // expected ciphertext was additionally cross-checked with an independent
    // Python/OpenSSL CCM* implementation.
    let c = SoftCrypto.aes128(&h16(KEY_C0));
    let nonce = h13("acde480000000001 00000005 04");
    let hdr = h("69dc84214302000000004 8deac010000000048deac0405000000");
    let mut payload = b"abcd".to_vec();
    ccm::seal_frame(&c, &nonce, SecurityLevel::Enc, &hdr, &mut payload, &mut []).unwrap();
    assert_eq!(payload, h("d43e022b"));
    ccm::open_frame(&c, &nonce, SecurityLevel::Enc, &hdr, &mut payload, &[]).unwrap();
    assert_eq!(payload, b"abcd");
}

#[test]
fn ccm_ieee802154_command_encmic64() {
    // OpenThread test_aes.cpp TestMacCommandFrame, IEEE 802.15.4-2006
    // Annex C.2.3 (security level 6, ENC-MIC-64).
    let c = SoftCrypto.aes128(&h16(KEY_C0));
    let nonce = h13("acde480000000001 00000005 06");
    let hdr = h("2bdc842143020000000048deacffff010000000048deac0605000000 01");
    assert_eq!(hdr.len(), 29);
    let mut payload = h("ce");
    let mut tag = [0u8; 8];
    ccm::seal_frame(
        &c,
        &nonce,
        SecurityLevel::EncMic64,
        &hdr,
        &mut payload,
        &mut tag,
    )
    .unwrap();
    assert_eq!(payload, h("d8"));
    assert_eq!(tag.to_vec(), h("4fde529061f9c6f1"));
    ccm::open_frame(
        &c,
        &nonce,
        SecurityLevel::EncMic64,
        &hdr,
        &mut payload,
        &tag,
    )
    .unwrap();
    assert_eq!(payload, h("ce"));
}

#[test]
fn ccm_rfc3610_packet_vector_1() {
    // RFC 3610 §8, Packet Vector #1 (M = 8, L = 2, 8 bytes AAD, 23 bytes data)
    let c = SoftCrypto.aes128(&h16(KEY_C0));
    let nonce = h13("00000003020100a0a1a2a3a4a5");
    let pkt: Vec<u8> = (0u8..31).collect();
    let mut data = pkt[8..].to_vec();
    let mut tag = [0u8; 8];
    ccm::encrypt(&c, &nonce, &pkt[..8], &mut data, &mut tag).unwrap();
    assert_eq!(data, h("588c979a61c663d2f066d0c2c0f989806d5f6b61dac384"));
    assert_eq!(tag.to_vec(), h("17e8d12cfdf926e0"));
    ccm::decrypt(&c, &nonce, &pkt[..8], &mut data, &tag).unwrap();
    assert_eq!(data, &pkt[8..]);
}

#[test]
fn ccm_in_place_openthread() {
    // OpenThread test_aes.cpp TestInPlaceAesCcmProcessing: round trip of
    // 30/400/800-byte messages, 19-byte header, 4-byte tag; plus chunked
    // processing equals one-shot.
    let c = SoftCrypto.aes128(&h16("a0a1a2a3a4a5a6a7a8a9aaabacadaeaf"));
    let nonce = h13("acde480000000001 00000005 06");
    for len in [30usize, 400, 800] {
        let msg: Vec<u8> = (0..len).map(|i| ((len - i) & 0xff) as u8).collect();
        let (hdr, body) = msg.split_at(19);
        let mut ct = body.to_vec();
        let mut tag = [0u8; 4];
        ccm::encrypt(&c, &nonce, hdr, &mut ct, &mut tag).unwrap();
        assert_ne!(ct, body);

        // Chunked encryption gives the same result.
        let mut ct2 = body.to_vec();
        let mut tag2 = [0u8; 4];
        let mut s = Ccm::new(&c, &nonce, hdr.len(), ct2.len(), 4).unwrap();
        s.aad(&hdr[..5]).unwrap();
        s.aad(&hdr[5..]).unwrap();
        for chunk in ct2.chunks_mut(17) {
            s.encrypt(chunk).unwrap();
        }
        s.finish(&mut tag2).unwrap();
        assert_eq!((ct2, tag2), (ct.clone(), tag));

        ccm::decrypt(&c, &nonce, hdr, &mut ct, &tag).unwrap();
        assert_eq!(ct, body);
    }
}

#[test]
fn ccm_rejects_tampering_and_wipes() {
    let c = SoftCrypto.aes128(&h16(KEY_C0));
    let nonce = h13("acde480000000001 00000005 05");
    let hdr = b"header";
    let mut data = *b"some secret payload";
    let mut tag = [0u8; 4];
    ccm::encrypt(&c, &nonce, hdr, &mut data, &mut tag).unwrap();

    let mut bad = data;
    bad[3] ^= 1;
    assert_eq!(
        ccm::decrypt(&c, &nonce, hdr, &mut bad, &tag),
        Err(Error::Security)
    );
    assert_eq!(bad, [0u8; 19], "plaintext must be wiped on failure");

    let mut d = data;
    assert_eq!(
        ccm::decrypt(&c, &nonce, b"headex", &mut d, &tag),
        Err(Error::Security)
    );
    let mut d = data;
    let mut t = tag;
    t[0] ^= 0x80;
    assert_eq!(
        ccm::decrypt(&c, &nonce, hdr, &mut d, &t),
        Err(Error::Security)
    );
    let mut d = data;
    let mut n = nonce;
    n[11] ^= 1;
    assert_eq!(
        ccm::decrypt(&c, &n, hdr, &mut d, &tag),
        Err(Error::Security)
    );

    let mut d = data;
    ccm::decrypt(&c, &nonce, hdr, &mut d, &tag).unwrap();
    assert_eq!(&d, b"some secret payload");
}

#[test]
fn ccm_argument_checks() {
    let c = SoftCrypto.aes128(&[0; 16]);
    let n = [0u8; 13];
    for bad in [1, 2, 3, 5, 18] {
        assert!(Ccm::new(&c, &n, 0, 0, bad).is_err());
    }
    for ok in [0, 4, 6, 8, 10, 12, 14, 16] {
        assert!(Ccm::new(&c, &n, 0, 0, ok).is_ok());
    }
    assert!(Ccm::new(&c, &n, 0, 0x10000, 4).is_err());
    // Payload before AAD is complete.
    let mut s = Ccm::new(&c, &n, 4, 4, 4).unwrap();
    assert_eq!(s.encrypt(&mut [0; 4]), Err(Error::InvalidState));
    assert_eq!(s.aad(&[0; 5]), Err(Error::InvalidArgs));
    s.aad(&[0; 4]).unwrap();
    assert_eq!(s.encrypt(&mut [0; 5]), Err(Error::InvalidArgs));
    // Finishing early.
    assert_eq!(s.finish(&mut [0; 4]), Err(Error::InvalidState));
    // Wrong MIC length for the security level, and level 0.
    assert!(ccm::seal_frame(&c, &n, SecurityLevel::EncMic32, &[], &mut [], &mut [0; 8]).is_err());
    assert!(ccm::seal_frame(&c, &n, SecurityLevel::None, &[], &mut [], &mut []).is_err());
}

#[test]
fn ccm_differential_vs_rustcrypto_ccm() {
    // Cross-check M = 4/8/16 against the RustCrypto `ccm` crate for many
    // AAD/payload lengths, including the 0xff00 long-AAD boundary.
    use ::ccm::aead::{AeadInOut, KeyInit as _};
    use ::ccm::consts::{U4, U8, U13, U16};

    let key = h16("404142434445464748494a4b4c4d4e4f");
    let c = SoftCrypto.aes128(&key);
    let nonce = h13("101112131415161718191a1b1c");
    let big: Vec<u8> = (0..0xff10u32)
        .map(|i| (i.wrapping_mul(31) >> 3) as u8)
        .collect();

    macro_rules! check {
        ($m:ty, $mlen:expr, $alen:expr, $plen:expr) => {{
            let rc = ::ccm::Ccm::<aes::Aes128, $m, U13>::new(&key.into());
            let aad = &big[..$alen];
            let mut expect = big[100..100 + $plen].to_vec();
            let etag = rc
                .encrypt_inout_detached(&nonce.into(), aad, expect.as_mut_slice().into())
                .unwrap();
            let mut ours = big[100..100 + $plen].to_vec();
            let mut tag = [0u8; $mlen];
            ccm::encrypt(&c, &nonce, aad, &mut ours, &mut tag).unwrap();
            assert_eq!(ours, expect, "ct M={} a={} p={}", $mlen, $alen, $plen);
            assert_eq!(
                &tag[..],
                &etag[..],
                "tag M={} a={} p={}",
                $mlen,
                $alen,
                $plen
            );
        }};
    }
    for alen in [0usize, 1, 13, 14, 15, 16, 17, 31, 32, 33, 42, 127] {
        for plen in [0usize, 1, 15, 16, 17, 100, 127] {
            check!(U4, 4, alen, plen);
            check!(U8, 8, alen, plen);
            check!(U16, 16, alen, plen);
        }
    }
    for alen in [0xfeff, 0xff00, 0xff01] {
        check!(U8, 8, alen, 20);
    }
}

#[test]
fn ccm_12_byte_nonce_sp800_38c_example3() {
    // NIST SP 800-38C Appendix C, Example 3 (Nlen = 12, Tlen = 64: the
    // RFC 6655 AES_128_CCM_8 shape).
    let key = h16("404142434445464748494a4b4c4d4e4f");
    let c = SoftCrypto.aes128(&key);
    let nonce = h("101112131415161718191a1b");
    let aad = h("000102030405060708090a0b0c0d0e0f10111213");
    let mut data = h("202122232425262728292a2b2c2d2e2f3031323334353637");
    let mut ccm = Ccm::with_nonce(&c, &nonce, aad.len(), data.len(), 8).unwrap();
    ccm.aad(&aad).unwrap();
    ccm.encrypt(&mut data).unwrap();
    let mut tag = [0u8; 8];
    ccm.finish(&mut tag).unwrap();
    assert_eq!(data, h("e3b201a9f5b71a7a9b1ceaeccd97e70b6176aad9a4428aa5"));
    assert_eq!(tag[..], h("484392fbc1b09951")[..]);

    let mut ccm = Ccm::with_nonce(&c, &nonce, aad.len(), data.len(), 8).unwrap();
    ccm.aad(&aad).unwrap();
    ccm.decrypt(&mut data).unwrap();
    ccm.verify(&tag).unwrap();
    assert_eq!(data, h("202122232425262728292a2b2c2d2e2f3031323334353637"));

    // Nonce length limits.
    assert!(Ccm::with_nonce(&c, &[0; 6], 0, 0, 8).is_err());
    assert!(Ccm::with_nonce(&c, &[0; 14], 0, 0, 8).is_err());
}

#[test]
fn ccm_12_byte_nonce_differential_vs_rustcrypto_ccm() {
    use ::ccm::aead::{AeadInOut, KeyInit as _};
    use ::ccm::consts::{U8, U12};

    let key = h16("c0c1c2c3c4c5c6c7c8c9cacbcccdcecf");
    let c = SoftCrypto.aes128(&key);
    let nonce: [u8; 12] = core::array::from_fn(|i| 0xa0 + i as u8);
    let rc = ::ccm::Ccm::<aes::Aes128, U8, U12>::new(&key.into());
    let src: Vec<u8> = (0..2000u32).map(|i| (i * 7 + 3) as u8).collect();
    for alen in [0usize, 13, 14, 15, 16, 17] {
        for plen in [0usize, 1, 15, 16, 17, 768, 1500] {
            let aad = &src[..alen];
            let mut expect = src[200..200 + plen].to_vec();
            let etag = rc
                .encrypt_inout_detached(&nonce.into(), aad, expect.as_mut_slice().into())
                .unwrap();
            let mut ours = src[200..200 + plen].to_vec();
            let mut ccm = Ccm::with_nonce(&c, &nonce, alen, plen, 8).unwrap();
            ccm.aad(aad).unwrap();
            ccm.encrypt(&mut ours).unwrap();
            let mut tag = [0u8; 8];
            ccm.finish(&mut tag).unwrap();
            assert_eq!(ours, expect, "a={alen} p={plen}");
            assert_eq!(&tag[..], &etag[..], "a={alen} p={plen}");
        }
    }
}

// ---------------------------------------------------------------- nonces / MLE

#[test]
fn nonces() {
    let ext = ExtAddress(h("acde480000000001").try_into().unwrap());
    assert_eq!(
        nonce::mac_nonce(&ext, 5, SecurityLevel::Mic64).to_vec(),
        h("acde480000000001 00000005 02")
    );
    assert_eq!(
        nonce::mle_nonce(&ext, 0x01020304).to_vec(),
        h("acde480000000001 01020304 05")
    );
    assert_eq!(
        nonce::mac_mode2_nonce(7, SecurityLevel::EncMic32).to_vec(),
        h("3506feb823d48712 00000007 05")
    );
}

#[test]
fn mle_message_reference() {
    // MLE security (Thread §7.3, OpenThread Mle::ProcessMessageSecurity):
    // key = MLE key for sequence 0 (§7.1.4.1), nonce from the sender's
    // link-local IID, AAD = src IPv6 || dst IPv6 || aux security header
    // (10 bytes), 4-byte MIC. Reference value (Python/OpenSSL).
    let keys = kdf::thread_keys(
        &SoftCrypto,
        &NetworkKey(h16("00112233445566778899aabbccddeeff")),
        0,
    );
    let src = h("fe800000000000001322334455667788");
    let dst = h("ff020000000000000000000000000001");
    let aux = h("15 01000000 00000000 01");
    let sender = Iid(src[8..].try_into().unwrap()).to_ext_address();
    assert_eq!(sender.0.to_vec(), h("1122334455667788"));
    let n = nonce::mle_nonce(&sender, 1);
    let c = SoftCrypto.aes128(&keys.mle_key.0);
    let mut s = Ccm::new(&c, &n, 42, 4, 4).unwrap();
    s.aad(&src).unwrap();
    s.aad(&dst).unwrap();
    s.aad(&aux).unwrap();
    let mut payload = h("0b000102");
    s.encrypt(&mut payload).unwrap();
    let mut tag = [0u8; 4];
    s.finish(&mut tag).unwrap();
    assert_eq!(payload, h("b40046bd"));
    assert_eq!(tag.to_vec(), h("b337bac7"));
}

// ---------------------------------------------------------------- KDF

fn thread_key_vectors<B: CryptoBackend>(b: &B) {
    // Thread 1.4.1 §7.1.4.1 - §7.1.4.3. First 16 bytes = MLE key, last 16 =
    // MAC key (see `kdf::thread_keys` on the §7.1.4 prose inconsistency).
    let nk = NetworkKey(h16("00112233445566778899aabbccddeeff"));
    let cases = [
        (
            0u32,
            "5445f4158fd75912175809f8b57a66a4",
            "de89c53af382b421e0fde5a9bae3bef0",
            1u8,
        ),
        (
            1,
            "8f4cd1a27d95c07d12db8974bd615c13",
            "9be0d1af7bd87350deabcdd07febb9d5",
            2,
        ),
        (
            2,
            "016e2ab8ec88879687a72e0a357ecf2a",
            "564109e9d2aad7f723ec3b96110eefa3",
            3,
        ),
    ];
    for (seq, mle, mac, idx) in cases {
        let k = kdf::thread_keys(b, &nk, seq);
        assert_eq!(k.mle_key.0.to_vec(), h(mle), "MLE key seq {seq}");
        assert_eq!(k.mac_key.0.to_vec(), h(mac), "MAC key seq {seq}");
        assert_eq!(kdf::key_index(seq), idx);
    }
}
both_backends!(thread_key_derivation_spec_7_1_4, thread_key_vectors);

#[test]
fn key_index_wraps() {
    assert_eq!(kdf::key_index(127), 128);
    assert_eq!(kdf::key_index(128), 1);
    assert_eq!(kdf::key_index(u32::MAX), 128);
}

/// HKDF test case: (ikm, salt, info, expected okm hex).
type HkdfCase = (Vec<u8>, Vec<u8>, Vec<u8>, &'static str);

fn hkdf_openthread<B: CryptoBackend>(b: &B) {
    // OpenThread tests/unit/test_hkdf_sha256.cpp (RFC 5869 A.1-A.3 + #4)
    let cases: [HkdfCase; 4] = [
        (
            [0x0b; 22].to_vec(),
            (0u8..=0x0c).collect(),
            (0xf0u8..=0xf9).collect(),
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
        ),
        (
            (0u8..=0x4f).collect(),
            (0x60u8..=0xaf).collect(),
            (0xb0u8..=0xff).collect(),
            "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87",
        ),
        (
            [0x0b; 22].to_vec(),
            Vec::new(),
            Vec::new(),
            "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8",
        ),
        (
            b"hello".to_vec(),
            h("8e94ef805b93e683ff18"),
            Vec::new(),
            "13485067e21af17c0900f70d885f0259",
        ),
    ];
    for (ikm, salt, info, exp) in cases {
        let exp = h(exp);
        // Like the OT test: check that nothing beyond the output is written.
        let mut out = [0x77u8; 128];
        kdf::hkdf_sha256(b, &salt, &ikm, &info, &mut out[..exp.len()]).unwrap();
        assert_eq!(&out[..exp.len()], &exp[..]);
        assert!(out[exp.len()..].iter().all(|&x| x == 0x77));
    }
    let mut too_long = [0u8; 255 * 32 + 1];
    assert!(kdf::hkdf_sha256(b, &[], &[], &[], &mut too_long).is_err());
}
both_backends!(hkdf_sha256_openthread_rfc5869, hkdf_openthread);

#[test]
fn trel_key_reference() {
    // Reference values (Python hmac/hashlib HKDF) for OpenThread
    // KeyManager::ComputeTrelKey.
    let nk = NetworkKey(h16("00112233445566778899aabbccddeeff"));
    assert_eq!(
        kdf::trel_key(&SoftCrypto, &nk, 0).0.to_vec(),
        h("4a39fa2e5806104a9bd6075e5b3341e7")
    );
    assert_eq!(
        kdf::trel_key(&SoftCrypto, &nk, 1).0.to_vec(),
        h("2057fd999bfb0b93bb1b2adb4323dad6")
    );
}

fn tls_prf_vector<B: CryptoBackend>(b: &B) {
    // TLS 1.2 PRF (P_SHA256) test vector from the IETF TLS WG list.
    let mut out = [0u8; 100];
    let seed = h("a0ba9f936cda311827a6f796ffd5198c");
    kdf::tls12_prf_sha256(
        b,
        &h("9bbe436ba940f017b17652849a71db35"),
        b"test label",
        &[&seed[..4], &seed[4..]],
        &mut out,
    );
    assert_eq!(
        out.to_vec(),
        h(
            "e3f229ba727be17b8d122620557cd453c2aab21d07c3d495329b52d4e61edb5a
           6b301791e90d35c9c9a46b4e14baf9af0fa022f7077def17abfd3797c0564bab
           4fbc91666e9def9b97fce34f796789baa48082d122ee42c5a72e5a5110fff701
           87347b66"
        )
    );
}
both_backends!(tls12_prf_sha256_vector, tls_prf_vector);

#[test]
fn kek_reference() {
    // Thread §7.4.7.8: KEK = SHA-256(key expansion)[0..15]; key block per
    // RFC 5246 §6.3 (OpenThread SecureTransport::HandleMbedtlsExportKeys).
    // Reference value (Python hmac/hashlib).
    let ms: [u8; 48] = core::array::from_fn(|i| i as u8);
    let cr: [u8; 32] = core::array::from_fn(|i| 0x40 + i as u8);
    let sr: [u8; 32] = core::array::from_fn(|i| 0x80 + i as u8);
    let kek = kdf::kek_from_master_secret(&SoftCrypto, &ms, &cr, &sr);
    assert_eq!(kek.0.to_vec(), h("a8acbcc8bcc117e48f67ca127286f7a9"));
}

// ---------------------------------------------------------------- PSKc

fn ext_pan(s: &str) -> ExtPanId {
    ExtPanId(h(s).try_into().unwrap())
}

#[test]
fn pskc_spec_8_4_1_2_2() {
    // Thread 1.4.1 §8.4.1.2.2 (also OpenThread test_pskc.cpp TestExampleInSpec)
    let p = pskc::pskc(
        &SoftCrypto,
        b"12SECRETPASSWORD34",
        &NetworkName::new("Test Network").unwrap(),
        &ext_pan("0001020304050607"),
    )
    .unwrap();
    assert_eq!(p.0.to_vec(), h("c3f59368445a1b6106be420a706d4cc9"));
}

#[test]
fn pskc_openthread_min_max_passphrase() {
    // OpenThread tests/unit/test_pskc.cpp TestMinimumPassphrase /
    // TestMaximumPassphrase. Run on the generic CMAC as well.
    let name = NetworkName::new("OpenThread").unwrap();
    let xpan = ext_pan("0102030405060708");
    let max: Vec<u8> = b"12345678".iter().copied().cycle().take(255).collect();
    let cases: [(&[u8], &str); 2] = [
        (b"123456", "44988e22cf652eeeccd1e4c01d0154f8"),
        (&max, "9e81bd35a253762f80ee04ff2fa285e9"),
    ];
    for (pass, exp) in cases {
        assert_eq!(
            pskc::pskc(&SoftCrypto, pass, &name, &xpan)
                .unwrap()
                .0
                .to_vec(),
            h(exp)
        );
        assert_eq!(
            pskc::pskc(&GenericBackend, pass, &name, &xpan)
                .unwrap()
                .0
                .to_vec(),
            h(exp)
        );
    }
}

#[test]
fn pskc_rejects_bad_passphrase() {
    let name = NetworkName::new("OpenThread").unwrap();
    let xpan = ext_pan("0102030405060708");
    assert_eq!(
        pskc::pskc(&SoftCrypto, b"12345", &name, &xpan),
        Err(Error::InvalidArgs)
    );
    assert_eq!(
        pskc::pskc(&SoftCrypto, &[b'1'; 256], &name, &xpan),
        Err(Error::InvalidArgs)
    );
    assert_eq!(
        pskc::pskc(&SoftCrypto, &[0xff; 8], &name, &xpan),
        Err(Error::InvalidArgs)
    );
    let mut out = [0u8; 16];
    assert!(pskc::pbkdf2_aes_cmac_prf_128(&SoftCrypto, b"p", b"s", 0, &mut out).is_err());
}

#[test]
fn pbkdf2_multi_block() {
    // dkLen > 16 uses block index 2: block 1 equals the 16-byte result.
    let mut a = [0u8; 16];
    let mut b = [0u8; 40];
    pskc::pbkdf2_aes_cmac_prf_128(&SoftCrypto, b"password", b"salt", 3, &mut a).unwrap();
    pskc::pbkdf2_aes_cmac_prf_128(&SoftCrypto, b"password", b"salt", 3, &mut b).unwrap();
    assert_eq!(a, b[..16]);
    assert_ne!(b[16..32], b[..16]);
}
