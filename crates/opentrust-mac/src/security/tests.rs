//! MAC frame security tests.
//!
//! Vector sources:
//! - IEEE 802.15.4-2006 Annex C.2.1–C.2.3 (also OpenThread
//!   `tests/unit/test_aes.cpp`), run through the frame API ([`seal_psdu`] /
//!   [`open_psdu`]).
//! - Thread 1.4.1 §7.1.4.1–§7.1.4.3 key derivation vectors (network key
//!   `00112233445566778899aabbccddeeff`, key sequences 0–2) for the keys the
//!   key manager uses, §7.2.1.3 / Table 7-16 for key ID mode 2.
//! - "Reference" frames: complete key ID mode 1/2 frames whose CCM* output was
//!   computed with the independent RustCrypto `ccm` crate from the spec keys
//!   and a hand-built nonce (the differential tests below recompute them).
//! - Key manager / replay / enhanced-ACK rules from OpenThread `KeyManager`,
//!   `Mac::ProcessReceiveSecurity`, `Mac::ProcessEnhAckSecurity`, `SubMac`.

extern crate std;

use std::vec::Vec;

use opentrust_core::Error;
use opentrust_core::crypto::kdf::key_index;
use opentrust_core::crypto::{CryptoBackend, SecurityLevel, SoftCrypto};
use opentrust_core::time::{Duration, Instant};
use opentrust_core::types::{ExtAddress, NetworkKey, PanId, ShortAddress};
use opentrust_platform::radio::AckSecurity;

use super::*;
use crate::frame::{
    Address, Frame, FrameBuilder, FrameMut, FrameType, FrameVersion, KeyIdMode, KeyIdentifier,
    SecurityHeader,
};
use crate::frame_security::{FrameSecurity, RxSecurityInfo};

fn h(s: &str) -> Vec<u8> {
    let s: Vec<u8> = s.bytes().filter(|c| !c.is_ascii_whitespace()).collect();
    s.chunks(2)
        .map(|c| u8::from_str_radix(core::str::from_utf8(c).unwrap(), 16).unwrap())
        .collect()
}

fn h16(s: &str) -> [u8; 16] {
    h(s).try_into().unwrap()
}

const NK: &str = "00112233445566778899aabbccddeeff";
/// Thread §7.1.4.1–§7.1.4.3 MAC keys for key sequence 0, 1, 2.
const MAC_KEYS: [&str; 3] = [
    "de89c53af382b421e0fde5a9bae3bef0",
    "9be0d1af7bd87350deabcdd07febb9d5",
    "564109e9d2aad7f723ec3b96110eefa3",
];
/// Thread §7.2.1.3 key ID mode 2 key.
const MODE2_KEY: &str = "78581686fdb4580fb092546aecbd1566";

const EXT_A: ExtAddress = ExtAddress([0x16, 0x6e, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x01]);
const EXT_B: ExtAddress = ExtAddress([0x16, 0x6e, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x02]);
const PAN: PanId = PanId(0xface);
const PAYLOAD: &[u8] = b"Thread MAC frame payload";

fn nk() -> NetworkKey {
    NetworkKey(h16(NK))
}

fn km() -> KeyManager<SoftCrypto> {
    KeyManager::new(SoftCrypto, nk())
}

fn km_at(seq: u32) -> KeyManager<SoftCrypto> {
    let mut k = km();
    k.restore(seq, 0);
    k
}

fn t(h: u64) -> Instant {
    Instant::from_secs(h * 3600)
}

/// 2006 data frame, short destination, extended source.
fn frame(level: SecurityLevel, key: KeyIdentifier, payload: &[u8]) -> Vec<u8> {
    let mut buf = [0u8; 127];
    let len = FrameBuilder::new(&mut buf)
        .frame_type(FrameType::Data)
        .version(FrameVersion::V2006)
        .sequence(0x2a)
        .pan_id(PAN)
        .dst(Address::Short(ShortAddress(0x0400)))
        .src(Address::Extended(EXT_A))
        .security(SecurityHeader::new(level, 0, key))
        .payload(payload)
        .build()
        .unwrap();
    buf[..len].to_vec()
}

/// 2015 data frame, extended addresses, ack requested (for enhanced ACKs).
fn frame_2015(level: SecurityLevel, payload: &[u8]) -> Vec<u8> {
    let mut buf = [0u8; 127];
    let len = FrameBuilder::new(&mut buf)
        .frame_type(FrameType::Data)
        .version(FrameVersion::V2015)
        .sequence(0x55)
        .pan_id(PAN)
        .dst(Address::Extended(EXT_B))
        .src(Address::Extended(EXT_A))
        .ack_request(true)
        .security(SecurityHeader::new(level, 0, KeyIdentifier::Index(0)))
        .payload(payload)
        .build()
        .unwrap();
    buf[..len].to_vec()
}

fn mode1(level: SecurityLevel) -> Vec<u8> {
    frame(level, KeyIdentifier::Index(0), PAYLOAD)
}

fn mode2(level: SecurityLevel) -> Vec<u8> {
    frame(
        level,
        KeyIdentifier::Source4 {
            source: [0; 4],
            index: 0,
        },
        PAYLOAD,
    )
}

const LEVELS: [SecurityLevel; 7] = [
    SecurityLevel::Mic32,
    SecurityLevel::Mic64,
    SecurityLevel::Mic128,
    SecurityLevel::Enc,
    SecurityLevel::EncMic32,
    SecurityLevel::EncMic64,
    SecurityLevel::EncMic128,
];

/// CCM* with the RustCrypto `ccm` crate (M = 4/8/16), as an independent
/// reference: returns (ciphertext-or-plaintext payload, MIC).
fn reference_ccm(
    key: &[u8; 16],
    nonce: &[u8; 13],
    level: SecurityLevel,
    header: &[u8],
    payload: &[u8],
) -> (Vec<u8>, Vec<u8>) {
    use ::ccm::aead::{AeadInOut, KeyInit as _};
    use ::ccm::consts::{U4, U8, U13, U16};

    let (aad, mut data): (Vec<u8>, Vec<u8>) = if level.is_encrypted() {
        (header.to_vec(), payload.to_vec())
    } else {
        ([header, payload].concat(), Vec::new())
    };
    macro_rules! run {
        ($m:ty) => {{
            let c = ::ccm::Ccm::<aes::Aes128, $m, U13>::new(&(*key).into());
            c.encrypt_inout_detached(&(*nonce).into(), &aad, data.as_mut_slice().into())
                .unwrap()
                .to_vec()
        }};
    }
    let tag = match level.mic_len() {
        4 => run!(U4),
        8 => run!(U8),
        16 => run!(U16),
        _ => unreachable!("no MIC"),
    };
    if !level.is_encrypted() {
        data = payload.to_vec();
    }
    (data, tag)
}

fn nonce(src: &ExtAddress, fc: u32, level: SecurityLevel) -> [u8; 13] {
    let mut n = [0u8; 13];
    n[..8].copy_from_slice(&src.0);
    n[8..12].copy_from_slice(&fc.to_be_bytes());
    n[12] = level.value();
    n
}

fn parts(psdu: &[u8]) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let f = Frame::parse(psdu).unwrap();
    (f.header().to_vec(), f.payload().to_vec(), f.mic().to_vec())
}

// ---------------------------------------------------------------- Annex C

const KEY_C0: &str = "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf";
/// Annex C source address 0xacde480000000001.
const EXT_C: ExtAddress = ExtAddress([0xac, 0xde, 0x48, 0x00, 0x00, 0x00, 0x00, 0x01]);

/// IEEE 802.15.4-2006 Annex C.2.1: beacon frame, MIC-64, key ID mode 0.
#[test]
fn annex_c_2_1_beacon_mic64() {
    let cipher = SoftCrypto.aes128(&h16(KEY_C0));
    let secured = h("08d0842143010000000048deac020500000055cf000051525354 223bc1ec841ab553");
    let mut psdu = secured.clone();
    psdu[secured.len() - 8..].fill(0);
    let f = Frame::parse(&psdu).unwrap();
    assert_eq!(f.frame_type(), FrameType::Beacon);
    assert_eq!(
        f.security_header().unwrap().key_id_mode(),
        KeyIdMode::Implicit
    );
    seal_psdu(&cipher, &mut psdu, &EXT_C).unwrap();
    assert_eq!(psdu, secured);
    open_psdu(&cipher, &mut psdu, &EXT_C).unwrap();
    assert_eq!(psdu, secured);
}

/// IEEE 802.15.4-2006 Annex C.2.2: data frame, ENC (level 4, no MIC).
#[test]
fn annex_c_2_2_data_enc() {
    let cipher = SoftCrypto.aes128(&h16(KEY_C0));
    let hdr = h("69dc84214302000000004 8deac010000000048deac0405000000");
    let mut psdu = [hdr.as_slice(), b"abcd"].concat();
    seal_psdu(&cipher, &mut psdu, &EXT_C).unwrap();
    assert_eq!(psdu, [hdr.as_slice(), &h("d43e022b")].concat());
    open_psdu(&cipher, &mut psdu, &EXT_C).unwrap();
    assert_eq!(&psdu[hdr.len()..], b"abcd");
}

/// IEEE 802.15.4-2006 Annex C.2.3: MAC command frame, ENC-MIC-64.
#[test]
fn annex_c_2_3_command_encmic64() {
    let cipher = SoftCrypto.aes128(&h16(KEY_C0));
    let hdr = h("2bdc842143020000000048deacffff010000000048deac0605000000 01");
    let mut psdu = [hdr.as_slice(), &[0xce], &[0; 8]].concat();
    let f = Frame::parse(&psdu).unwrap();
    assert_eq!(f.header_len(), 29, "2006 command ID belongs to the header");
    seal_psdu(&cipher, &mut psdu, &EXT_C).unwrap();
    assert_eq!(
        psdu,
        [hdr.as_slice(), &h("d8"), &h("4fde529061f9c6f1")].concat()
    );
    open_psdu(&cipher, &mut psdu, &EXT_C).unwrap();
    assert_eq!(psdu[29], 0xce);

    // Wrong source address in the nonce -> MIC failure, payload wiped.
    seal_psdu(&cipher, &mut psdu, &EXT_C).unwrap();
    assert_eq!(open_psdu(&cipher, &mut psdu, &EXT_A), Err(Error::Security));
    assert_eq!(psdu[29], 0);
}

#[test]
fn seal_open_reject_unsecured_and_suppressed_counter() {
    let cipher = SoftCrypto.aes128(&h16(KEY_C0));
    let mut plain = h("41d8 01 cefa ffff 0100000000000000"); // no security
    assert_eq!(
        seal_psdu(&cipher, &mut plain, &EXT_A),
        Err(Error::InvalidArgs)
    );
    assert_eq!(open_psdu(&cipher, &mut plain, &EXT_A), Err(Error::Security));

    // 2015 frame with frame counter suppression.
    let mut buf = [0u8; 64];
    let mut sh = SecurityHeader::new(SecurityLevel::EncMic32, 0, KeyIdentifier::Index(1));
    sh.frame_counter = None;
    let len = FrameBuilder::new(&mut buf)
        .version(FrameVersion::V2015)
        .pan_id(PAN)
        .dst(Address::Short(ShortAddress(1)))
        .src(Address::Short(ShortAddress(2)))
        .security(sh)
        .payload(b"x")
        .build()
        .unwrap();
    let mut p = buf[..len].to_vec();
    assert_eq!(seal_psdu(&cipher, &mut p, &EXT_A), Err(Error::InvalidArgs));
    assert_eq!(open_psdu(&cipher, &mut p, &EXT_A), Err(Error::Security));
    let mut k = km();
    assert_eq!(k.secure_tx(&mut p, &EXT_A), Err(Error::InvalidArgs));
    assert_eq!(k.unsecure_rx(&mut p, &EXT_A), Err(Error::Security));
}

// ---------------------------------------------------------------- reference frames

/// Reference: key ID mode 1, key sequence 0 (spec MAC key), frame counter
/// 0, ENC-MIC-32, 2006 data frame. CCM* output from RustCrypto `ccm`.
#[test]
fn reference_key_id_mode1_frame() {
    let mut psdu = mode1(SecurityLevel::EncMic32);
    let mut k = km();
    k.secure_tx(&mut psdu, &EXT_A).unwrap();
    let f = Frame::parse(&psdu).unwrap();
    let s = *f.security_header().unwrap();
    assert_eq!(s.frame_counter, Some(0));
    assert_eq!(s.key, KeyIdentifier::Index(1), "key index of sequence 0");

    let (hdr, _, _) = parts(&psdu);
    let (ct, mic) = reference_ccm(
        &h16(MAC_KEYS[0]),
        &nonce(&EXT_A, 0, SecurityLevel::EncMic32),
        SecurityLevel::EncMic32,
        &hdr,
        PAYLOAD,
    );
    assert_eq!(psdu, [hdr.as_slice(), &ct, &mic].concat());
    assert_eq!(
        psdu,
        h("69d8 2a cefa 0004 0100000000 0a6e16 0d 00000000 01 \
           aa8365f435948f20a872c52ca87b6aa2950d17b128f06d7d 21e176eb"),
        "regression vector"
    );

    let mut rx = km();
    let info = rx.unsecure_rx(&mut psdu, &EXT_A).unwrap().unwrap();
    assert_eq!(
        info,
        RxSecurityInfo {
            level: SecurityLevel::EncMic32,
            key_id_mode: KeyIdMode::Index,
            key_sequence: Some(0),
            frame_counter: 0,
        }
    );
    assert_eq!(Frame::parse(&psdu).unwrap().payload(), PAYLOAD);
}

/// Reference: key ID mode 2 (Thread §7.2.1.3: key source 0xffffffff, key
/// index 0xff, well-known key, nonce address 0x3506feb823d48712).
#[test]
fn reference_key_id_mode2_frame() {
    let mut psdu = mode2(SecurityLevel::EncMic32);
    let mut k = km();
    k.secure_tx(&mut psdu, &EXT_A).unwrap();
    let s = *Frame::parse(&psdu).unwrap().security_header().unwrap();
    assert_eq!(
        s.key,
        KeyIdentifier::Source4 {
            source: [0xff; 4],
            index: 0xff
        }
    );
    // OpenThread pre-increments its mode 2 counter: first frame uses 1.
    assert_eq!(s.frame_counter, Some(1));
    assert_eq!(k.frame_counter(), 0, "mode 2 does not use the MAC counter");

    let (hdr, _, _) = parts(&psdu);
    let mode2_ext = ExtAddress(h("3506feb823d48712").try_into().unwrap());
    let (ct, mic) = reference_ccm(
        &h16(MODE2_KEY),
        &nonce(&mode2_ext, 1, SecurityLevel::EncMic32),
        SecurityLevel::EncMic32,
        &hdr,
        PAYLOAD,
    );
    assert_eq!(psdu, [hdr.as_slice(), &ct, &mic].concat());
    assert_eq!(
        psdu,
        h(
            "69d8 2a cefa 0004 0100000000 0a6e16 15 01000000 ffffffff ff \
           cceb443d7e38de4a3e20c9e41c5195d7490346c6edd31fb5 eb2f7a1f"
        ),
        "regression vector"
    );

    // Any network key can receive it (filtering only); src_ext is unused.
    let mut rx = KeyManager::new(SoftCrypto, NetworkKey([0x55; 16]));
    let info = rx.unsecure_rx(&mut psdu, &EXT_B).unwrap().unwrap();
    assert_eq!(info.key_id_mode, KeyIdMode::Source4);
    assert_eq!(info.key_sequence, None);
    assert_eq!(info.frame_counter, 1);
    assert_eq!(Frame::parse(&psdu).unwrap().payload(), PAYLOAD);
}

/// Key ID mode 2 frames with another key source / index are not the
/// Thread key (Thread §7.2.1.3: match on all of mode, source and index).
#[test]
fn key_id_mode2_wrong_source_or_index_rejected() {
    for (source, index) in [([0xff, 0xff, 0xff, 0xfe], 0xff), ([0xff; 4], 0x01)] {
        let mut psdu = mode2(SecurityLevel::EncMic32);
        km().secure_tx(&mut psdu, &EXT_A).unwrap();
        // Re-seal with the mode 2 key but a different key identifier.
        write_aux_header(&mut psdu, 7, &KeyIdentifier::Source4 { source, index }).unwrap();
        let mode2_ext = ExtAddress(h("3506feb823d48712").try_into().unwrap());
        let cipher = SoftCrypto.aes128(&h16(MODE2_KEY));
        {
            let mut fm = FrameMut::new(&mut psdu).unwrap();
            fm.payload_mut().unwrap().copy_from_slice(PAYLOAD);
        }
        seal_psdu(&cipher, &mut psdu, &mode2_ext).unwrap();
        assert_eq!(km().unsecure_rx(&mut psdu, &EXT_A), Err(Error::Security));
    }
}

// ---------------------------------------------------------------- round trips

#[test]
fn round_trip_all_levels_both_modes() {
    for level in LEVELS {
        for build in [mode1, mode2] {
            let mut tx = km();
            let mut rx = km();
            rx.set_rx_level_policy(RxLevelPolicy::Authenticated);
            let mut psdu = build(level);
            tx.secure_tx(&mut psdu, &EXT_A).unwrap();
            let f = Frame::parse(&psdu).unwrap();
            assert_eq!(f.mic_len(), level.mic_len());
            if level.is_encrypted() {
                assert_ne!(f.payload(), PAYLOAD, "{level:?} encrypts");
            } else {
                assert_eq!(f.payload(), PAYLOAD, "{level:?} keeps payload clear");
            }

            // Independent reference.
            let (hdr, payload, mic) = parts(&psdu);
            let s = *f.security_header().unwrap();
            let (key, src) = match s.key_id_mode() {
                KeyIdMode::Index => (h16(MAC_KEYS[0]), EXT_A),
                _ => (
                    h16(MODE2_KEY),
                    ExtAddress(h("3506feb823d48712").try_into().unwrap()),
                ),
            };
            let n = nonce(&src, s.frame_counter.unwrap(), level);
            if level.mic_len() > 0 {
                let (ct, rmic) = reference_ccm(&key, &n, level, &hdr, PAYLOAD);
                assert_eq!((payload, mic), (ct, rmic), "{level:?}");
            }

            if level == SecurityLevel::Enc {
                // No integrity: never accepted on receive.
                assert_eq!(rx.unsecure_rx(&mut psdu, &EXT_A), Err(Error::Security));
                let cipher = SoftCrypto.aes128(&key);
                open_psdu(&cipher, &mut psdu, &src).unwrap();
            } else {
                let info = rx.unsecure_rx(&mut psdu, &EXT_A).unwrap().unwrap();
                assert_eq!(info.level, level);
            }
            assert_eq!(Frame::parse(&psdu).unwrap().payload(), PAYLOAD);
        }
    }
}

#[test]
fn default_policy_accepts_only_enc_mic32() {
    for level in LEVELS {
        let mut psdu = mode1(level);
        km().secure_tx(&mut psdu, &EXT_A).unwrap();
        let r = km().unsecure_rx(&mut psdu, &EXT_A);
        if level == SecurityLevel::EncMic32 {
            assert!(r.unwrap().is_some());
        } else {
            assert_eq!(r, Err(Error::Security), "{level:?}");
        }
    }
}

#[test]
fn unsecured_frames_pass_through() {
    let mut buf = [0u8; 64];
    let len = FrameBuilder::new(&mut buf)
        .pan_id(PAN)
        .dst(Address::Short(ShortAddress(1)))
        .src(Address::Extended(EXT_A))
        .payload(b"plain")
        .build()
        .unwrap();
    let orig = buf[..len].to_vec();
    let mut p = orig.clone();
    let mut k = km();
    k.secure_tx(&mut p, &EXT_A).unwrap();
    assert_eq!(p, orig);
    assert_eq!(k.unsecure_rx(&mut p, &EXT_A), Ok(None));
    assert_eq!(p, orig);
    assert_eq!(k.frame_counter(), 0);
}

#[test]
fn unsupported_key_id_modes() {
    for key in [
        KeyIdentifier::Implicit,
        KeyIdentifier::Source8 {
            source: [0xff; 8],
            index: 1,
        },
    ] {
        let mut p = frame(SecurityLevel::EncMic32, key, PAYLOAD);
        let mut k = km();
        assert_eq!(k.secure_tx(&mut p, &EXT_A), Err(Error::InvalidArgs));
        assert_eq!(k.frame_counter(), 0, "no counter consumed");
        // A frame sealed with mode 0/3 is not accepted either.
        let cipher = SoftCrypto.aes128(&h16(MAC_KEYS[0]));
        seal_psdu(&cipher, &mut p, &EXT_A).unwrap();
        assert_eq!(k.unsecure_rx(&mut p, &EXT_A), Err(Error::Security));
    }
}

// ---------------------------------------------------------------- tampering

#[test]
fn tampering_any_byte_is_detected() {
    for build in [mode1, mode2] {
        let mut secured = build(SecurityLevel::EncMic32);
        km().secure_tx(&mut secured, &EXT_A).unwrap();
        for i in 0..secured.len() {
            for bit in [0x01u8, 0x80] {
                let mut p = secured.clone();
                p[i] ^= bit;
                let r = km().unsecure_rx(&mut p, &EXT_A);
                assert!(
                    matches!(r, Err(Error::Security | Error::Parse)),
                    "byte {i} bit {bit:#x}: {r:?}"
                );
                // Never leaves plaintext behind.
                if let Ok(f) = Frame::parse(&p) {
                    assert_ne!(f.payload(), PAYLOAD, "byte {i}: plaintext left behind");
                }
            }
        }
    }
}

#[test]
fn bad_mic_wipes_payload() {
    let mut p = mode1(SecurityLevel::EncMic32);
    km().secure_tx(&mut p, &EXT_A).unwrap();
    let n = p.len();
    p[n - 1] ^= 1;
    assert_eq!(km().unsecure_rx(&mut p, &EXT_A), Err(Error::Security));
    let f = Frame::parse(&p).unwrap();
    assert!(f.payload().iter().all(|&b| b == 0));
}

#[test]
fn wrong_frame_counter_key_index_source_or_network_key() {
    let mut secured = mode1(SecurityLevel::EncMic32);
    let mut tx = km();
    tx.advance_frame_counter(5);
    tx.secure_tx(&mut secured, &EXT_A).unwrap();

    // Frame counter rewritten (replayed under another counter).
    let mut p = secured.clone();
    write_aux_header(&mut p, 6, &KeyIdentifier::Index(1)).unwrap();
    assert_eq!(km().unsecure_rx(&mut p, &EXT_A), Err(Error::Security));

    // Key index rewritten to the next key (known, but wrong key).
    let mut p = secured.clone();
    write_aux_header(&mut p, 5, &KeyIdentifier::Index(2)).unwrap();
    assert_eq!(km().unsecure_rx(&mut p, &EXT_A), Err(Error::Security));

    // Unknown key index (0 is never used, 3 is two sequences ahead).
    for idx in [0, 3, 0x80, 0xff] {
        let mut p = secured.clone();
        write_aux_header(&mut p, 5, &KeyIdentifier::Index(idx)).unwrap();
        assert_eq!(km().unsecure_rx(&mut p, &EXT_A), Err(Error::Security));
    }

    // Wrong sender address in the nonce.
    let mut p = secured.clone();
    assert_eq!(km().unsecure_rx(&mut p, &EXT_B), Err(Error::Security));

    // Other network key.
    let mut p = secured.clone();
    let mut other = KeyManager::new(SoftCrypto, NetworkKey([0x11; 16]));
    assert_eq!(other.unsecure_rx(&mut p, &EXT_A), Err(Error::Security));

    let mut p = secured;
    assert!(km().unsecure_rx(&mut p, &EXT_A).unwrap().is_some());
}

// ---------------------------------------------------------------- key sequences

#[test]
fn spec_keys_are_used_and_cached() {
    let k = km_at(1);
    assert_eq!(k.mac_key().0, h16(MAC_KEYS[1]));
    assert_eq!(k.cached_keys(0).unwrap().mac_key.0, h16(MAC_KEYS[0]));
    assert_eq!(k.cached_keys(2).unwrap().mac_key.0, h16(MAC_KEYS[2]));
    assert!(k.cached_keys(3).is_none());
    assert_eq!(k.derive_keys(2).mac_key.0, h16(MAC_KEYS[2]));
    assert_eq!(
        k.mle_key().0,
        h16("8f4cd1a27d95c07d12db8974bd615c13"),
        "§7.1.4.2 MLE key"
    );

    let mk = k.mac_keys();
    assert_eq!(mk.key_id_mode, 1);
    assert_eq!(mk.key_id, 2);
    assert_eq!(mk.prev_key_id(), 1);
    assert_eq!(mk.next_key_id(), 3);
    assert_eq!(mk.prev, h16(MAC_KEYS[0]));
    assert_eq!(mk.curr, h16(MAC_KEYS[1]));
    assert_eq!(mk.next, h16(MAC_KEYS[2]));

    // Switching forward by one shifts the cache; by more re-derives.
    let mut k = km();
    assert!(k.set_key_sequence(1, KeySeqUpdate::FORCE, t(0)).unwrap());
    assert_eq!(k.mac_keys().prev, h16(MAC_KEYS[0]));
    assert_eq!(k.mac_keys().next, h16(MAC_KEYS[2]));
    let mut k = km();
    assert!(k.set_key_sequence(2, KeySeqUpdate::FORCE, t(0)).unwrap());
    assert_eq!(k.mac_keys().prev, h16(MAC_KEYS[1]));
    assert_eq!(k.mac_key().0, h16(MAC_KEYS[2]));
}

#[test]
fn previous_and_next_key_accepted_others_rejected() {
    let cur = 300u32;
    for (sender, ok) in [
        (cur - 2, false),
        (cur - 1, true),
        (cur, true),
        (cur + 1, true),
        (cur + 2, false),
        (cur + 128, false), // same key index as `cur`, different key
    ] {
        let mut tx = km_at(sender);
        let mut rx = km_at(cur);
        let mut p = mode1(SecurityLevel::EncMic32);
        tx.secure_tx(&mut p, &EXT_A).unwrap();
        let r = rx.unsecure_rx(&mut p, &EXT_A);
        if ok {
            assert_eq!(r.unwrap().unwrap().key_sequence, Some(sender));
        } else {
            assert_eq!(r, Err(Error::Security), "sender {sender}");
        }
        assert_eq!(rx.key_sequence(), cur, "rx never switches by itself");
    }
}

#[test]
fn key_index_wrap_around() {
    // Sequence 127 (index 128) -> 128 (index 1).
    for (sender, rx_seq) in [(127u32, 128u32), (128, 127)] {
        let mut tx = km_at(sender);
        let mut p = mode1(SecurityLevel::EncMic32);
        tx.secure_tx(&mut p, &EXT_A).unwrap();
        assert_eq!(
            Frame::parse(&p).unwrap().security_header().unwrap().key,
            KeyIdentifier::Index(key_index(sender))
        );
        let info = km_at(rx_seq).unsecure_rx(&mut p, &EXT_A).unwrap().unwrap();
        assert_eq!(info.key_sequence, Some(sender));
    }
    // At key sequence 0 there is no previous sequence: index 128 is unknown
    // (OpenThread would try sequence 0xffffffff).
    let k = km();
    assert!(k.lookup_key_index(128).is_none());
    assert_eq!(k.lookup_key_index(1).unwrap().0, 0);
    assert_eq!(k.lookup_key_index(2).unwrap().0, 1);
    let k = km_at(u32::MAX);
    assert!(k.lookup_key_index(1).is_none(), "no next after u32::MAX");
    assert_eq!(k.lookup_key_index(127).unwrap().0, u32::MAX - 1);
}

#[test]
fn key_sequence_never_decreases_and_resets_frame_counter() {
    let mut k = km_at(5);
    k.advance_frame_counter(100);
    assert_eq!(
        k.set_key_sequence(4, KeySeqUpdate::FORCE, t(0)),
        Err(Error::InvalidArgs)
    );
    assert_eq!(k.set_key_sequence(5, KeySeqUpdate::FORCE, t(0)), Ok(false));
    assert_eq!(k.frame_counter(), 100);
    assert_eq!(k.set_key_sequence(6, KeySeqUpdate::FORCE, t(0)), Ok(true));
    assert_eq!(k.frame_counter(), 0, "§7.1.8: counter reset on key switch");
    assert_eq!(k.key_index(), 7);
}

#[test]
fn network_key_change_resets_sequence_and_counter() {
    let mut k = km_at(9);
    k.advance_frame_counter(77);
    k.frame_counter_stored(5000);
    assert!(!k.set_network_key(nk()), "same key: no change");
    assert_eq!(k.key_sequence(), 9);
    assert!(k.set_network_key(NetworkKey([0x22; 16])));
    assert_eq!((k.key_sequence(), k.frame_counter()), (0, 0));
    assert!(k.needs_store());
    let expect = opentrust_core::crypto::kdf::thread_keys(&SoftCrypto, &NetworkKey([0x22; 16]), 0);
    assert_eq!(k.mac_key(), &expect.mac_key);
}

// ---------------------------------------------------------------- guard / rotation

#[test]
fn key_switch_guard_on_rx() {
    let mut k = km_at(10);
    assert_eq!(k.key_rotation_hours(), DEFAULT_KEY_ROTATION_HOURS);
    assert_eq!(k.key_switch_guard_hours(), 624, "floor(0.93 * 672)");
    k.start(t(0));
    assert!(!k.guard_active(t(0)), "guard timer starts at 0");

    // Older / same sequence: nothing.
    assert!(!k.on_rx_key_sequence(9, t(0)));
    assert!(!k.on_rx_key_sequence(10, t(0)));
    // Next sequence with guard 0: switch, guard timer starts.
    assert!(k.on_rx_key_sequence(11, t(1)));
    assert_eq!(k.key_sequence(), 11);
    assert!(k.guard_active(t(1)));
    assert!(k.guard_active(t(1 + 623)));
    // Within the guard time: frame accepted by caller but no switch.
    assert!(!k.on_rx_key_sequence(12, t(2)));
    assert!(!k.on_rx_key_sequence(12, t(1 + 623)));
    assert_eq!(k.key_sequence(), 11);
    // Guard expired exactly guard-time hours after the switch.
    assert!(!k.guard_active(t(1 + 624)));
    assert!(k.on_rx_key_sequence(12, t(1 + 624)));
    assert_eq!(k.key_sequence(), 12);

    // Forced updates ignore the guard.
    assert!(k.guard_active(t(626)));
    assert_eq!(
        k.set_key_sequence(20, KeySeqUpdate::FORCE, t(626)),
        Ok(true)
    );
    // `restore` and `FORCE` leave the guard timer unchanged.
    assert!(k.guard_active(t(626)));
    // `start` clears it.
    k.start(t(627));
    assert!(!k.guard_active(t(627)));
}

#[test]
fn key_rotation_timer() {
    let mut k = km();
    assert_eq!(k.next_deadline(), None, "stopped");
    assert!(!k.poll(t(10_000)));

    k.set_key_rotation_hours(10);
    assert_eq!(k.key_switch_guard_hours(), 9);
    k.start(t(100));
    assert_eq!(k.next_deadline(), Some(t(110)));
    assert!(!k.poll(t(110) - Duration::from_micros(1)));
    k.advance_frame_counter(50);
    assert!(k.poll(t(110)));
    assert_eq!(k.key_sequence(), 1);
    assert_eq!(k.frame_counter(), 0);
    assert!(k.guard_active(t(110)), "rotation resets the guard timer");
    assert!(!k.guard_active(t(119)));
    assert_eq!(k.next_deadline(), Some(t(120)));

    // A switch on rx restarts the rotation period.
    assert!(k.on_rx_key_sequence(2, t(119)));
    assert_eq!(k.next_deadline(), Some(t(129)));

    // Shorter policy: rotation is due immediately.
    k.set_key_rotation_hours(0);
    assert_eq!(k.key_rotation_hours(), MIN_KEY_ROTATION_HOURS);
    assert_eq!(k.key_switch_guard_hours(), 0);
    assert!(k.poll(t(120)));
    assert_eq!(k.key_sequence(), 3);
    assert!(!k.guard_active(t(120)), "guard time 0");

    k.stop();
    assert_eq!(k.next_deadline(), None);
    assert!(!k.poll(t(100_000)));
}

// ---------------------------------------------------------------- frame counter

#[test]
fn frame_counter_increments_and_exhausts() {
    let mut k = km();
    for expect in 0..3u32 {
        let mut p = mode1(SecurityLevel::EncMic32);
        k.secure_tx(&mut p, &EXT_A).unwrap();
        let s = *Frame::parse(&p).unwrap().security_header().unwrap();
        assert_eq!(s.frame_counter, Some(expect));
    }
    assert_eq!(k.frame_counter(), 3);

    // 0xfffffffe is the last usable counter.
    k.restore(0, u32::MAX - 1);
    let mut p = mode1(SecurityLevel::EncMic32);
    k.secure_tx(&mut p, &EXT_A).unwrap();
    assert_eq!(
        Frame::parse(&p)
            .unwrap()
            .security_header()
            .unwrap()
            .frame_counter,
        Some(u32::MAX - 1)
    );
    assert!(k.frame_counter_exhausted());
    let mut p = mode1(SecurityLevel::EncMic32);
    let before = p.clone();
    assert_eq!(k.secure_tx(&mut p, &EXT_A), Err(Error::InvalidState));
    assert_eq!(p, before, "frame untouched");
    // Key ID mode 2 still works (separate counter).
    let mut p2 = mode2(SecurityLevel::EncMic32);
    k.secure_tx(&mut p2, &EXT_A).unwrap();
    // Radio-reported counters cannot wrap it either.
    k.frame_counter_used(u32::MAX, k.key_index());
    assert!(k.frame_counter_exhausted());
    // A key switch recovers.
    assert!(k.set_key_sequence(1, KeySeqUpdate::FORCE, t(0)).unwrap());
    k.secure_tx(&mut p, &EXT_A).unwrap();
}

#[test]
fn frame_counter_used_by_radio() {
    let mut k = km_at(3);
    k.frame_counter_used(10, key_index(3));
    assert_eq!(k.frame_counter(), 11);
    // Out of order / older: ignored.
    k.frame_counter_used(5, key_index(3));
    assert_eq!(k.frame_counter(), 11);
    // Other key index (an ACK with the previous key): ignored.
    k.frame_counter_used(50, key_index(2));
    assert_eq!(k.frame_counter(), 11);
    k.ack_frame_counter_used(&AckSecurity {
        frame_counter: 20,
        key_id: key_index(3),
    });
    assert_eq!(k.frame_counter(), 21);
    k.advance_frame_counter(15);
    assert_eq!(k.frame_counter(), 21, "never decreases");
    k.advance_frame_counter(40);
    assert_eq!(k.frame_counter(), 40);
}

#[test]
fn frame_counter_persistence_ahead() {
    let mut k = km();
    assert!(k.needs_store(), "nothing persisted yet");
    assert_eq!(
        k.frame_counter_to_store(),
        DEFAULT_STORE_FRAME_COUNTER_AHEAD
    );
    k.frame_counter_stored(k.frame_counter_to_store());
    assert!(!k.needs_store());

    let mut p = mode1(SecurityLevel::EncMic32);
    for _ in 0..DEFAULT_STORE_FRAME_COUNTER_AHEAD - 1 {
        p = mode1(SecurityLevel::EncMic32);
        k.secure_tx(&mut p, &EXT_A).unwrap();
        assert!(!k.needs_store());
    }
    k.secure_tx(&mut p, &EXT_A).unwrap();
    assert_eq!(k.frame_counter(), 1000);
    assert!(k.needs_store(), "reached the stored value");
    assert_eq!(k.frame_counter_to_store(), 2000);
    k.frame_counter_stored(2000);
    assert!(!k.needs_store());

    // Restore after reset: continue at the stored (never used) value.
    let mut r = km();
    r.restore(0, 2000);
    assert_eq!(r.frame_counter(), 2000);
    assert!(
        r.needs_store(),
        "first counter after restore triggers a store"
    );
    let mut p = mode1(SecurityLevel::EncMic32);
    r.secure_tx(&mut p, &EXT_A).unwrap();
    assert_eq!(
        Frame::parse(&p)
            .unwrap()
            .security_header()
            .unwrap()
            .frame_counter,
        Some(2000)
    );

    // Key sequence change must be persisted.
    k.set_store_frame_counter_ahead(10);
    k.frame_counter_stored(k.frame_counter_to_store());
    assert!(!k.needs_store());
    assert!(k.on_rx_key_sequence(1, t(0)));
    assert!(k.needs_store());
    assert_eq!(k.frame_counter_to_store(), 10);
    k.frame_counter_stored(10);
    assert!(!k.needs_store());

    // Saturates.
    r.restore(0, u32::MAX - 5);
    assert_eq!(r.frame_counter_to_store(), u32::MAX);
}

// ---------------------------------------------------------------- replay

fn info(seq: Option<u32>, fc: u32) -> RxSecurityInfo {
    RxSecurityInfo {
        level: SecurityLevel::EncMic32,
        key_id_mode: if seq.is_some() {
            KeyIdMode::Index
        } else {
            KeyIdMode::Source4
        },
        key_sequence: seq,
        frame_counter: fc,
    }
}

#[test]
fn replay_rules() {
    let mut c = LinkFrameCounters::new();
    assert_eq!(c.check_and_update(&info(Some(0), 0)), Ok(false));
    assert_eq!(c.frame_counter(), Some(1));
    assert_eq!(
        c.check_and_update(&info(Some(0), 0)),
        Err(Error::Drop),
        "dup"
    );
    assert_eq!(c.check_and_update(&info(Some(0), 5)), Ok(false));
    assert_eq!(c.check_and_update(&info(Some(0), 5)), Err(Error::Drop));
    assert_eq!(c.check_and_update(&info(Some(0), 3)), Err(Error::Security));
    assert_eq!(c.check_and_update(&info(Some(0), 6)), Ok(false));
    // Gaps are fine.
    assert_eq!(c.check_and_update(&info(Some(0), 1000)), Ok(false));

    // Newer key sequence: accepted, counters restart.
    assert_eq!(c.check_and_update(&info(Some(1), 2)), Ok(true));
    assert_eq!(c.key_sequence(), 1);
    assert_eq!(c.frame_counter(), Some(3));
    assert_eq!(c.check_and_update(&info(Some(1), 1)), Err(Error::Security));
    // Older key sequence: rejected even with a high counter.
    assert_eq!(
        c.check_and_update(&info(Some(0), 5000)),
        Err(Error::Security)
    );
    assert!(!c.update(0, 5000), "update ignores older sequences");
    assert_eq!((c.key_sequence(), c.frame_counter()), (1, Some(3)));

    // Mode 2: no replay protection, no change.
    let before = c;
    assert_eq!(c.check_and_update(&info(None, 0)), Ok(false));
    assert_eq!(c, before);

    // No wrap at the top of the counter space.
    c.set(1, u32::MAX - 1);
    assert_eq!(c.check_and_update(&info(Some(1), u32::MAX)), Ok(false));
    assert_eq!(c.frame_counter(), None);
    assert_eq!(c.check_and_update(&info(Some(1), 0)), Err(Error::Security));
    assert_eq!(
        c.check_and_update(&info(Some(1), u32::MAX)),
        Err(Error::Drop)
    );

    // Link establishment value (MLE Link-layer Frame Counter TLV).
    let c = LinkFrameCounters::with(7, 100);
    assert_eq!(c.check(7, 99), Err(Error::Drop));
    assert_eq!(c.check(7, 98), Err(Error::Security));
    assert_eq!(c.check(7, 100), Ok(()));
    assert_eq!(c.check_ack(99), Err(Error::Security));
    assert_eq!(c.check_ack(100), Ok(()));
    let mut c = c;
    c.reset();
    assert_eq!(c, LinkFrameCounters::new());
}

#[test]
fn replay_ack_counters() {
    let mut c = LinkFrameCounters::with(0, 10);
    assert_eq!(
        c.check_and_update_ack(&info(Some(0), 9)),
        Err(Error::Security)
    );
    assert_eq!(c.check_and_update_ack(&info(Some(0), 10)), Ok(()));
    assert_eq!(c.ack_frame_counter(), Some(11));
    // ACK counters may repeat? No: equal to a used one is rejected.
    assert_eq!(
        c.check_and_update_ack(&info(Some(0), 10)),
        Err(Error::Security)
    );
    // Data frames move the ACK counter along (one counter per neighbor).
    assert_eq!(c.check_and_update(&info(Some(0), 20)), Ok(false));
    assert_eq!(c.ack_frame_counter(), Some(21));
    assert_eq!(c.check_ack(20), Err(Error::Security));
    // ...but an ACK does not move the data frame counter.
    assert_eq!(c.check_and_update_ack(&info(Some(0), 30)), Ok(()));
    assert_eq!(c.frame_counter(), Some(21));
}

/// End to end as `Mac::ProcessReceiveSecurity`: verify, replay check, then
/// adopt a newer key sequence.
#[test]
fn rx_pipeline_with_replay_and_key_switch() {
    let mut tx = km_at(4);
    let mut rx = km_at(4);
    rx.start(t(0));
    let mut neighbor = LinkFrameCounters::with(4, 0);

    let send = |tx: &mut KeyManager<SoftCrypto>| {
        let mut p = mode1(SecurityLevel::EncMic32);
        tx.secure_tx(&mut p, &EXT_A).unwrap();
        p
    };
    let p1 = send(&mut tx);
    let mut q = p1.clone();
    let i = rx.unsecure_rx(&mut q, &EXT_A).unwrap().unwrap();
    assert_eq!(neighbor.check_and_update(&i), Ok(false));
    // Replay of the same secured frame.
    let mut q = p1.clone();
    let i = rx.unsecure_rx(&mut q, &EXT_A).unwrap().unwrap();
    assert_eq!(neighbor.check_and_update(&i), Err(Error::Drop));

    // Sender rotates; receiver accepts the next key and switches.
    assert!(
        tx.set_key_sequence(5, KeySeqUpdate::FORCE_RESET_GUARD, t(1))
            .unwrap()
    );
    let mut q = send(&mut tx);
    let i = rx.unsecure_rx(&mut q, &EXT_A).unwrap().unwrap();
    assert_eq!(i.key_sequence, Some(5));
    assert_eq!(i.frame_counter, 0);
    assert_eq!(neighbor.check_and_update(&i), Ok(true));
    assert!(rx.on_rx_key_sequence(5, t(1)));
    assert_eq!(rx.key_sequence(), 5);
    // Old-key frame replayed afterwards: verifies (previous key) but the
    // replay check rejects it.
    let mut q = p1;
    let i = rx.unsecure_rx(&mut q, &EXT_A).unwrap().unwrap();
    assert_eq!(i.key_sequence, Some(4));
    assert_eq!(neighbor.check_and_update(&i), Err(Error::Security));
}

// ---------------------------------------------------------------- enhanced ACK

#[test]
fn enh_ack_secure_and_verify() {
    // A (sender of the data frame) at sequence 7, B (acker) at 8: B acks
    // with A's key index, i.e. its previous key.
    let mut a = km_at(7);
    let mut b = km_at(8);
    b.advance_frame_counter(40);

    let mut data = frame_2015(SecurityLevel::EncMic32, PAYLOAD);
    a.secure_tx(&mut data, &EXT_A).unwrap();
    let tx_key_index = Frame::parse(&data)
        .unwrap()
        .security_header()
        .unwrap()
        .key
        .index()
        .unwrap();
    assert_eq!(tx_key_index, key_index(7));

    let mut rxd = data.clone();
    b.unsecure_rx(&mut rxd, &EXT_A).unwrap().unwrap();
    let mut buf = [0u8; 64];
    let len = FrameBuilder::enh_ack(&mut buf, &Frame::parse(&rxd).unwrap(), false)
        .unwrap()
        .build()
        .unwrap();
    let mut ack = buf[..len].to_vec();
    let sec = b.secure_enh_ack(&mut ack, &EXT_B).unwrap().unwrap();
    assert_eq!(
        sec,
        AckSecurity {
            frame_counter: 40,
            key_id: key_index(7)
        }
    );
    assert_eq!(b.frame_counter(), 41, "ACK consumed a counter");

    // Independent reference for the ACK MIC (previous key of B = seq 7).
    let (hdr, payload, mic) = parts(&ack);
    let (_, rmic) = reference_ccm(
        &b.derive_keys(7).mac_key.0,
        &nonce(&EXT_B, 40, SecurityLevel::EncMic32),
        SecurityLevel::EncMic32,
        &hdr,
        &payload,
    );
    assert_eq!(mic, rmic);

    let mut neighbor_b = LinkFrameCounters::with(7, 0);
    let mut q = ack.clone();
    let i = a
        .unsecure_enh_ack(&mut q, tx_key_index, &EXT_B)
        .unwrap()
        .unwrap();
    assert_eq!((i.key_sequence, i.frame_counter), (Some(7), 40));
    assert_eq!(neighbor_b.check_and_update_ack(&i), Ok(()));
    // Replayed ACK.
    let mut q = ack.clone();
    let i = a
        .unsecure_enh_ack(&mut q, tx_key_index, &EXT_B)
        .unwrap()
        .unwrap();
    assert_eq!(neighbor_b.check_and_update_ack(&i), Err(Error::Security));

    // Key index must match the transmitted frame.
    let mut q = ack.clone();
    assert_eq!(
        a.unsecure_enh_ack(&mut q, key_index(8), &EXT_B),
        Err(Error::Security)
    );
    // Wrong sender address / tampered MIC.
    let mut q = ack.clone();
    assert_eq!(
        a.unsecure_enh_ack(&mut q, tx_key_index, &EXT_A),
        Err(Error::Security)
    );
    for i in 0..ack.len() {
        let mut q = ack.clone();
        q[i] ^= 0x04;
        assert!(
            a.unsecure_enh_ack(&mut q, tx_key_index, &EXT_B).is_err(),
            "byte {i}"
        );
    }
    // Unknown key index on the acker side.
    let c = km_at(20);
    let mut b2 = c;
    let mut q = buf[..len].to_vec();
    assert_eq!(b2.secure_enh_ack(&mut q, &EXT_B), Err(Error::Security));
    assert_eq!(b2.frame_counter(), 0, "no counter consumed");
}

#[test]
fn enh_ack_unsecured_and_invalid() {
    let mut k = km();
    // Unsecured enhanced ACK for an unsecured frame.
    let mut buf = [0u8; 127];
    let len = FrameBuilder::new(&mut buf)
        .version(FrameVersion::V2015)
        .pan_id(PAN)
        .dst(Address::Extended(EXT_B))
        .src(Address::Extended(EXT_A))
        .ack_request(true)
        .payload(b"x")
        .build()
        .unwrap();
    let data = buf[..len].to_vec();
    let mut abuf = [0u8; 64];
    let alen = FrameBuilder::enh_ack(&mut abuf, &Frame::parse(&data).unwrap(), true)
        .unwrap()
        .build()
        .unwrap();
    let mut ack = abuf[..alen].to_vec();
    assert_eq!(k.secure_enh_ack(&mut ack, &EXT_B), Ok(None));
    assert_eq!(k.unsecure_enh_ack(&mut ack, 1, &EXT_B), Ok(None));

    // A secured data frame (not an ACK) is refused by secure_enh_ack, and a
    // 2006 frame by unsecure_enh_ack.
    let mut d = mode1(SecurityLevel::EncMic32);
    assert_eq!(k.secure_enh_ack(&mut d, &EXT_A), Err(Error::InvalidArgs));
    k.secure_tx(&mut d, &EXT_A).unwrap();
    assert_eq!(
        k.unsecure_enh_ack(&mut d, k.key_index(), &EXT_A),
        Err(Error::Security)
    );
}
