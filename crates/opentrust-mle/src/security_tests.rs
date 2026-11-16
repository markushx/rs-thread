use opentrust_core::crypto::SoftCrypto;
use opentrust_core::time::Instant;
use opentrust_core::types::NetworkKey;
use opentrust_mac::security::KeySeqUpdate;

use super::*;
use crate::message::MleBuilder;

fn hex<const N: usize>(s: &str) -> [u8; N] {
    let mut out = [0u8; N];
    let s: heapless::Vec<u8, 128> = s.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    assert_eq!(s.len(), N * 2);
    for (i, o) in out.iter_mut().enumerate() {
        let v = |c: u8| (c as char).to_digit(16).unwrap() as u8;
        *o = v(s[2 * i]) << 4 | v(s[2 * i + 1]);
    }
    out
}

fn km() -> KeyManager<SoftCrypto> {
    KeyManager::new(
        SoftCrypto,
        NetworkKey(hex("00112233445566778899aabbccddeeff")),
    )
}

fn src() -> Ipv6Addr {
    Ipv6Addr::from(hex::<16>("fe800000000000001322334455667788"))
}

fn dst() -> Ipv6Addr {
    Ipv6Addr::from(hex::<16>("ff020000000000000000000000000001"))
}

/// The crypto reference vector (`crypto::tests::mle_message_reference`,
/// Thread §7.3 / OT `ProcessMessageSecurity`, Python/OpenSSL): network key
/// 00112233..eeff, key sequence 0, sender fe80::1322:3344:5566:7788,
/// destination ff02::1, frame counter 1, plaintext `0b 00 01 02`.
const VECTOR: &str = "00 15 01000000 00000000 01 b40046bd b337bac7";

#[test]
fn reference_vector_secure_and_unsecure() {
    let keys = km();
    let mut counter = MleFrameCounter::new();
    counter.restore(1);
    let mut buf = [0u8; 32];
    buf[0] = SECURITY_SUITE_154;
    buf[SECURED_PAYLOAD_OFFSET..SECURED_PAYLOAD_OFFSET + 4].copy_from_slice(&hex::<4>("0b000102"));
    let n = secure(&keys, &mut counter, &mut buf, 15, &src(), &dst()).unwrap();
    assert_eq!(n, 19);
    assert_eq!(buf[..n], hex::<19>(VECTOR));
    assert_eq!(counter.current(), 2);

    let mut rx = hex::<19>(VECTOR);
    let m = unsecure(&keys, &mut rx, &src(), &dst()).unwrap();
    assert_eq!(m.command, Command::ChildIdRequest);
    assert_eq!(
        m.security,
        Some(RxSecurity {
            key_sequence: 0,
            frame_counter: 1
        })
    );
    assert_eq!(m.tlvs.as_bytes(), &[0, 1, 2]);
}

#[test]
fn tamper_every_byte_fails() {
    let keys = km();
    for i in 0..19 {
        let mut rx = hex::<19>(VECTOR);
        rx[i] ^= 0x01;
        let r = unsecure(&keys, &mut rx, &src(), &dst());
        assert!(r.is_err(), "byte {i} tamper accepted");
    }
    // Wrong addresses are authenticated as well.
    let mut rx = hex::<19>(VECTOR);
    let other = Ipv6Addr::from(hex::<16>("fe800000000000001322334455667789"));
    assert_eq!(
        unsecure(&keys, &mut rx, &other, &dst()).unwrap_err(),
        Error::Security
    );
    let mut rx = hex::<19>(VECTOR);
    assert_eq!(
        unsecure(&keys, &mut rx, &src(), &src()).unwrap_err(),
        Error::Security
    );
    // Wrong network key.
    let other_keys = KeyManager::new(SoftCrypto, NetworkKey([7; 16]));
    let mut rx = hex::<19>(VECTOR);
    assert_eq!(
        unsecure(&other_keys, &mut rx, &src(), &dst()).unwrap_err(),
        Error::Security
    );
}

#[test]
fn failed_decrypt_wipes_payload() {
    let keys = km();
    let mut rx = hex::<19>(VECTOR);
    rx[18] ^= 1;
    assert!(unsecure(&keys, &mut rx, &src(), &dst()).is_err());
    assert_eq!(&rx[11..15], &[0, 0, 0, 0]);
}

#[test]
fn truncation_never_panics() {
    let keys = km();
    let full = hex::<19>(VECTOR);
    for len in 0..=19 {
        let mut b = full;
        let r = unsecure(&keys, &mut b[..len], &src(), &dst());
        assert_eq!(r.is_ok(), len == 19, "len {len}");
    }
    // Discovery truncations.
    for len in 0..2 {
        let mut b = [NO_SECURITY, 16];
        assert!(unsecure(&keys, &mut b[..len], &src(), &dst()).is_err());
    }
}

#[test]
fn aux_header_layout() {
    let h = AuxHeader {
        frame_counter: 0x01020304,
        key_sequence: 0x0a0b0c0d,
    };
    let b = h.to_bytes();
    // control, FC little endian, key source = key sequence big endian,
    // key index = (seq & 0x7f) + 1.
    assert_eq!(b, [0x15, 4, 3, 2, 1, 0x0a, 0x0b, 0x0c, 0x0d, 0x0d + 1]);
    assert_eq!(AuxHeader::from_bytes(&b).unwrap(), h);
    let mut bad = b;
    bad[0] = 0x05;
    assert_eq!(AuxHeader::from_bytes(&bad), Err(Error::Parse));
    assert_eq!(AuxHeader::from_bytes(&b[..9]), Err(Error::Parse));
}

#[test]
fn builder_secure_unsecure_roundtrip() {
    let keys = km();
    let mut counter = MleFrameCounter::new();
    let mut buf = [0u8; 128];
    let mut b = MleBuilder::new(&mut buf, Command::ParentRequest).unwrap();
    b.tlvs()
        .mode(crate::tlv::DeviceMode::new(true, true, true))
        .unwrap();
    b.tlvs().challenge(&[1, 2, 3, 4, 5, 6, 7, 8]).unwrap();
    b.tlvs().scan_mask(0xc0).unwrap();
    let len = b.finish();
    assert_eq!(buf[0], SECURITY_SUITE_154);
    let n = secure(&keys, &mut counter, &mut buf, len, &src(), &dst()).unwrap();
    assert_eq!(n, len + TAG_LEN);
    // Payload is encrypted.
    assert_ne!(buf[SECURED_PAYLOAD_OFFSET], Command::ParentRequest.as_u8());
    let m = unsecure(&keys, &mut buf[..n], &src(), &dst()).unwrap();
    assert_eq!(m.command, Command::ParentRequest);
    assert_eq!(m.security.unwrap().frame_counter, 0);
    assert_eq!(m.tlvs.scan_mask().unwrap(), 0xc0);
    assert_eq!(m.tlvs.challenge().unwrap(), &[1, 2, 3, 4, 5, 6, 7, 8]);
    assert!(m.tlvs.mode().unwrap().full_thread_device());
    // Second message uses the next counter.
    assert_eq!(counter.current(), 1);
}

#[test]
fn builder_buffer_too_small() {
    let mut tiny = [0u8; 14];
    assert!(MleBuilder::new(&mut tiny, Command::Advertisement).is_err());
    let mut buf = [0u8; 20];
    let mut b = MleBuilder::new(&mut buf, Command::Advertisement).unwrap();
    // 20 - 4 (MIC) - 12 (header) = 4 bytes left.
    assert_eq!(b.tlvs().timeout(1), Err(Error::NoBufs));
}

#[test]
fn secure_rejects_bad_arguments_without_consuming_counter() {
    let keys = km();
    let mut counter = MleFrameCounter::new();
    let mut buf = [0u8; 16];
    buf[0] = SECURITY_SUITE_154;
    // No room for the MIC.
    assert_eq!(
        secure(&keys, &mut counter, &mut buf, 14, &src(), &dst()),
        Err(Error::NoBufs)
    );
    // Header only, no command.
    assert_eq!(
        secure(&keys, &mut counter, &mut buf, 11, &src(), &dst()),
        Err(Error::NoBufs)
    );
    buf[0] = 7;
    assert_eq!(
        secure(&keys, &mut counter, &mut buf, 14, &src(), &dst()),
        Err(Error::InvalidArgs)
    );
    assert_eq!(counter.current(), 0);
}

#[test]
fn discovery_is_unsecured() {
    let keys = km();
    let mut counter = MleFrameCounter::new();
    let mut buf = [0u8; 64];
    let mut b = MleBuilder::new(&mut buf, Command::DiscoveryRequest).unwrap();
    b.tlvs().discovery(&[0x80, 0x01, 0x00]).unwrap();
    let len = b.finish();
    assert_eq!(&buf[..2], &[NO_SECURITY, 16]);
    let n = secure(&keys, &mut counter, &mut buf, len, &src(), &dst()).unwrap();
    assert_eq!(n, len);
    assert_eq!(counter.current(), 0, "no frame counter used");
    let m = unsecure(&keys, &mut buf[..n], &src(), &dst()).unwrap();
    assert_eq!(m.command, Command::DiscoveryRequest);
    assert!(m.security.is_none());
    assert_eq!(m.tlvs.discovery().unwrap(), &[0x80, 1, 0]);

    // Other commands with suite 255 are dropped; so is an unknown one.
    for cmd in [Command::Advertisement.as_u8(), 200] {
        let mut b = [NO_SECURITY, cmd, 0];
        assert_eq!(
            unsecure(&keys, &mut b, &src(), &dst()).unwrap_err(),
            Error::Drop
        );
    }
    // Unknown suite.
    let mut b = [1u8; 20];
    assert_eq!(
        unsecure(&keys, &mut b, &src(), &dst()).unwrap_err(),
        Error::Parse
    );
}

fn send_with(keys: &KeyManager<SoftCrypto>, counter: &mut MleFrameCounter) -> ([u8; 64], usize) {
    let mut buf = [0u8; 64];
    let mut b = MleBuilder::new(&mut buf, Command::Advertisement).unwrap();
    b.tlvs()
        .source_address(opentrust_core::types::Rloc16(0x0400))
        .unwrap();
    let len = b.finish();
    let n = secure(keys, counter, &mut buf, len, &src(), &dst()).unwrap();
    (buf, n)
}

#[test]
fn key_sequence_selection() {
    let now = Instant::from_secs(0);
    let mut tx = km();
    tx.set_key_sequence(1, KeySeqUpdate::FORCE, now).unwrap();
    let mut counter = MleFrameCounter::new();
    let (mut buf, n) = send_with(&tx, &mut counter);
    assert_eq!(AuxHeader::from_bytes(&buf[1..11]).unwrap().key_sequence, 1);

    // Receiver on sequence 0 uses its cached "next" key and reports 1.
    let rx = km();
    let m = unsecure(&rx, &mut buf[..n], &src(), &dst()).unwrap();
    assert_eq!(m.security.unwrap().key_sequence, 1);

    // Receiver far behind derives a temporary key.
    let mut tx = km();
    tx.set_key_sequence(500, KeySeqUpdate::FORCE, now).unwrap();
    let (mut buf, n) = send_with(&tx, &mut counter);
    let m = unsecure(&rx, &mut buf[..n], &src(), &dst()).unwrap();
    assert_eq!(m.security.unwrap().key_sequence, 500);
    // The receiver is not modified: adopting the sequence is the caller's job.
    assert_eq!(rx.key_sequence(), 0);

    // Receiver ahead of the sender (previous key cached).
    let mut rx2 = km();
    rx2.set_key_sequence(1, KeySeqUpdate::FORCE, now).unwrap();
    let (mut buf, n) = send_with(&km(), &mut counter);
    assert_eq!(
        unsecure(&rx2, &mut buf[..n], &src(), &dst())
            .unwrap()
            .security
            .unwrap()
            .key_sequence,
        0
    );
}

#[test]
fn frame_counter_store_ahead() {
    let mut c = MleFrameCounter::new();
    assert!(c.needs_store());
    assert_eq!(c.to_store(), DEFAULT_STORE_FRAME_COUNTER_AHEAD);
    c.stored(c.to_store());
    assert!(!c.needs_store());
    for _ in 0..999 {
        c.take().unwrap();
    }
    assert!(!c.needs_store());
    c.take().unwrap();
    assert!(c.needs_store(), "reached the persisted value");
    assert_eq!(c.to_store(), 2000);

    // Restore continues at the stored value; nothing used before is reused.
    let mut r = MleFrameCounter::new();
    r.restore(2000);
    assert_eq!(r.take().unwrap(), 2000);
    assert!(
        r.needs_store(),
        "restored value is already used up; persist again"
    );

    // Exhaustion: 0xffffffff is never used.
    let mut e = MleFrameCounter::new();
    e.restore(u32::MAX - 1);
    assert_eq!(e.take().unwrap(), u32::MAX - 1);
    assert!(e.exhausted());
    assert_eq!(e.take(), Err(Error::InvalidState));
    assert_eq!(e.to_store(), u32::MAX);
}

#[test]
fn command_codes() {
    assert_eq!(Command::from_u8(0), Some(Command::LinkRequest));
    assert_eq!(Command::from_u8(20), Some(Command::LinkProbe));
    assert_eq!(Command::from_u8(99), Some(Command::TimeSync));
    assert_eq!(Command::from_u8(21), None);
    for v in 0..=255u8 {
        if let Some(c) = Command::from_u8(v) {
            assert_eq!(c.as_u8(), v);
        }
    }
}

#[test]
fn key_switch_restarts_mle_frame_counter() {
    // OT `KeyManager::SetCurrentKeySequence` resets `mMleFrameCounter`
    // whatever caused the switch (rotation timer, neighbor, dataset); a
    // network key change (`SetNetworkKey`) does not.
    let now = Instant::from_secs(0);
    let mut keys = km();
    let mut counter = MleFrameCounter::new();
    let (_, _) = send_with(&keys, &mut counter);
    let (_, _) = send_with(&keys, &mut counter);
    assert_eq!(counter.current_for(keys.key_epoch()), 2);

    // Rotation through the poll.
    keys.start(now);
    let due = keys.next_deadline().unwrap();
    assert!(keys.poll(due));
    assert_eq!(keys.key_sequence(), 1);
    let (buf, _) = send_with(&keys, &mut counter);
    let aux = AuxHeader::from_bytes(&buf[1..11]).unwrap();
    assert_eq!((aux.key_sequence, aux.frame_counter), (1, 0));
    assert_eq!(counter.current(), 1);

    // An authoritative message with a newer key sequence.
    assert!(keys.set_key_sequence(2, KeySeqUpdate::FORCE, due).unwrap());
    assert_eq!(counter.current_for(keys.key_epoch()), 0);

    // A network key change keeps the counter.
    let _ = send_with(&keys, &mut counter);
    assert!(keys.set_network_key(NetworkKey([9; 16])));
    assert_eq!(counter.current_for(keys.key_epoch()), 1);
}
