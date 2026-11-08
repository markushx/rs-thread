use super::*;
use std::vec::Vec;

/// Hand-encoded CON POST `a/aq`, MID 0x1234, token 0xbeef, payload `01 02`
/// (layout per RFC 7252 section 3; TMF shape per OT `Message::Init(.., Uri)`).
const POST_AQ: [u8; 14] = [
    0x42, 0x02, 0x12, 0x34, 0xbe, 0xef, // header + token
    0xb1, b'a', // Uri-Path "a" (delta 11, len 1)
    0x02, b'a', b'q', // Uri-Path "aq" (delta 0, len 2)
    0xff, 0x01, 0x02,
];

#[test]
fn parse_post_aq() {
    let m = Message::parse(&POST_AQ).unwrap();
    assert_eq!(m.ty(), Type::Con);
    assert_eq!(m.code(), Code::POST);
    assert_eq!(m.message_id(), 0x1234);
    assert_eq!(m.token(), &[0xbe, 0xef]);
    assert_eq!(m.payload(), &[1, 2]);
    assert!(m.is_request() && m.is_confirmable() && !m.is_response());
    assert!(m.uri_path_is("a/aq"));
    assert!(!m.uri_path_is("a/ae"));
    assert!(!m.uri_path_is("a"));
    assert!(!m.uri_path_is("a/aq/x"));
    assert!(!m.uri_path_is(""));
    let mut buf = [0u8; 8];
    assert_eq!(m.uri_path(&mut buf), Ok("a/aq"));
    let mut tiny = [0u8; 3];
    assert_eq!(m.uri_path(&mut tiny), Err(Error::Parse));
}

#[test]
fn builder_matches_hand_encoding() {
    let mut buf = [0u8; 64];
    let mut b =
        MessageBuilder::new(&mut buf, Type::Con, Code::POST, 0x1234, &[0xbe, 0xef]).unwrap();
    b.uri_path("a/aq").unwrap();
    let n = b.finish_with_payload(&[1, 2]).unwrap();
    assert_eq!(&buf[..n], &POST_AQ);

    let mut buf = [0u8; 64];
    let mut b =
        MessageBuilder::new(&mut buf, Type::Con, Code::POST, 0x1234, &[0xbe, 0xef]).unwrap();
    b.uri_path("a/aq").unwrap();
    let n = b
        .finish_with(|w| {
            w.write_u8(1)?;
            w.write_u8(2)
        })
        .unwrap();
    assert_eq!(&buf[..n], &POST_AQ);

    // finish_with that writes nothing drops the marker.
    let mut buf = [0u8; 16];
    let b = MessageBuilder::new(&mut buf, Type::Non, Code::GET, 1, &[]).unwrap();
    let n = b.finish_with(|_| Ok(())).unwrap();
    assert_eq!(&buf[..n], &[0x50, 0x01, 0, 1]);
}

#[test]
fn empty_payload_has_no_marker() {
    let mut buf = [0u8; 16];
    let mut b = MessageBuilder::new(&mut buf, Type::Non, Code::GET, 1, &[]).unwrap();
    b.uri_path("x").unwrap();
    let n = b.finish_with_payload(&[]).unwrap();
    assert_eq!(&buf[..n], &[0x50, 0x01, 0, 1, 0xb1, b'x']);
    // Marker with zero-length payload is a format error.
    assert_eq!(
        Message::parse(&[0x50, 0x01, 0, 1, 0xb1, b'x', 0xff]),
        Err(Error::Parse)
    );
}

#[test]
fn extended_option_encodings() {
    let long = [7u8; 300];
    let mut buf = [0u8; 500];
    let mut b = MessageBuilder::new(&mut buf, Type::Con, Code::GET, 9, &[1]).unwrap();
    b.option(1, &[]).unwrap(); // delta 1, len 0
    b.option(13, &[0xaa; 13]).unwrap(); // delta 12, len 13 (1-byte ext)
    b.option(26, &[]).unwrap(); // delta 13 (1-byte ext)
    b.option(295, &long).unwrap(); // delta 269 and len 300 (2-byte ext)
    b.option(295, &[]).unwrap(); // repeated option, delta 0
    b.option(60000, &[]).unwrap(); // large delta (2-byte ext)
    let n = b.finish().unwrap();
    let m = Message::parse(&buf[..n]).unwrap();
    let o: Vec<_> = m.options().map(|o| (o.number, o.value.len())).collect();
    assert_eq!(
        o,
        [(1, 0), (13, 13), (26, 0), (295, 300), (295, 0), (60000, 0)]
    );
    // Re-encode is byte-identical.
    let mut out = [0u8; 500];
    let k = m.encode(&mut out).unwrap();
    assert_eq!(&out[..k], &buf[..n]);
    // Wire bytes: header(4) + token(1), then option 1 (0x10), option 13:
    // delta 12 | len 13 -> 0xcd, ext len byte 0.
    assert_eq!(&buf[5..8], &[0x10, 0xcd, 0x00]);
}

#[test]
fn option_order_enforced() {
    let mut buf = [0u8; 32];
    let mut b = MessageBuilder::new(&mut buf, Type::Con, Code::GET, 1, &[]).unwrap();
    b.option(opt::URI_QUERY, b"x").unwrap();
    assert_eq!(
        b.option(opt::URI_PATH, b"y").err(),
        Some(Error::InvalidArgs)
    );
    b.option(opt::URI_QUERY, b"z").unwrap();
    assert_eq!(
        MessageBuilder::new(&mut buf, Type::Con, Code::GET, 1, &[0; 9]).err(),
        Some(Error::InvalidArgs)
    );
}

#[test]
fn typed_options() {
    let mut buf = [0u8; 64];
    let mut b = MessageBuilder::new(&mut buf, Type::Ack, Code::CONTENT, 5, &[1, 2, 3]).unwrap();
    b.content_format(content_format::OCTET_STREAM).unwrap();
    b.uint_option(opt::MAX_AGE, 0).unwrap();
    b.uri_query("k=v").unwrap();
    b.block(
        opt::BLOCK2,
        BlockOption {
            num: 5,
            more: true,
            szx: 2,
        },
    )
    .unwrap();
    let n = b.finish().unwrap();
    let m = Message::parse(&buf[..n]).unwrap();
    assert_eq!(m.content_format(), Some(42));
    assert_eq!(m.option_uint(opt::MAX_AGE), Some(0));
    assert_eq!(m.option(opt::MAX_AGE).unwrap().value.len(), 0);
    assert_eq!(m.option(opt::URI_QUERY).unwrap().value, b"k=v");
    let blk = m.block(opt::BLOCK2).unwrap();
    assert_eq!((blk.num, blk.more, blk.szx, blk.size()), (5, true, 2, 64));
    assert_eq!(m.block(opt::BLOCK1), None);
    assert_eq!(BlockOption::decode(7), None);
    assert!(m.is_response());
    assert_eq!(Code::NOT_FOUND, Code::new(4, 4));
    assert_eq!(Code::CHANGED.class(), 2);
    assert_eq!(Code::CHANGED.detail(), 4);
}

#[test]
fn empty_messages() {
    let m = Message::parse(&[0x60, 0x00, 0xab, 0xcd]).unwrap();
    assert_eq!(
        (m.ty(), m.is_empty(), m.message_id()),
        (Type::Ack, true, 0xabcd)
    );
    assert!(Message::parse(&[0x70, 0x00, 0, 1]).is_ok());
    // Empty with token / payload / options is malformed.
    assert!(Message::parse(&[0x61, 0x00, 0, 1, 9]).is_err());
    assert!(Message::parse(&[0x60, 0x00, 0, 1, 0xff, 1]).is_err());
    assert!(Message::parse(&[0x60, 0x00, 0, 1, 0xb1, b'a']).is_err());
}

#[test]
fn malformed_rejected() {
    // Version 2.
    assert!(Message::parse(&[0x80, 1, 0, 1]).is_err());
    // TKL 9.
    assert!(Message::parse(&[0x49, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0]).is_err());
    // Reserved nibble 15 in delta / length.
    assert!(Message::parse(&[0x40, 1, 0, 1, 0xf1, 0]).is_err());
    assert!(Message::parse(&[0x40, 1, 0, 1, 0x1f, 0]).is_err());
    // Truncated token, option value, extension byte.
    assert!(Message::parse(&[0x42, 1, 0, 1, 0]).is_err());
    assert!(Message::parse(&[0x40, 1, 0, 1, 0xb5, b'a']).is_err());
    assert!(Message::parse(&[0x40, 1, 0, 1, 0xd0]).is_err());
    // Option number overflow: 0xfef2 + 269 = 65535 is the maximum.
    assert!(Message::parse(&[0x40, 1, 0, 1, 0xe0, 0xfe, 0xf2]).is_ok());
    assert!(Message::parse(&[0x40, 1, 0, 1, 0xe0, 0xfe, 0xf2, 0x10]).is_err());
    assert!(Message::parse(&[0x40, 1, 0, 1, 0xe0, 0xfe, 0xf3]).is_err());
    assert!(Message::parse(&[]).is_err());
}

#[test]
fn truncation_and_fuzz_never_panic() {
    let mut buf = [0u8; 400];
    let mut b = MessageBuilder::new(&mut buf, Type::Con, Code::POST, 7, &[1, 2, 3, 4]).unwrap();
    b.uri_path("c/ag").unwrap();
    b.option(300, &[5; 20]).unwrap();
    let n = b.finish_with_payload(&[9; 30]).unwrap();
    for cut in 0..n {
        if let Ok(m) = Message::parse(&buf[..cut]) {
            for _ in m.options() {}
            let mut p = [0u8; 40];
            let _ = m.uri_path(&mut p);
            let _ = m.uri_path_is("c/ag");
        }
    }
    // Deterministic pseudo-random garbage.
    let mut x = 0x1234_5678u32;
    for _ in 0..5000 {
        let mut c = [0u8; 64];
        let len = 4 + (x as usize % 60);
        for v in c.iter_mut().take(len) {
            x = x.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            *v = (x >> 24) as u8;
        }
        c[0] = 0x40 | (c[0] & 0x3f);
        if let Ok(m) = Message::parse(&c[..len]) {
            let mut o = [0u8; 80];
            let _ = m.encode(&mut o);
            for _ in m.options() {}
        }
    }
}

#[test]
fn builder_no_space() {
    let mut buf = [0u8; 6];
    assert_eq!(
        MessageBuilder::new(&mut buf, Type::Con, Code::GET, 1, &[1, 2, 3]).err(),
        Some(Error::NoBufs)
    );
    let mut buf = [0u8; 6];
    let mut b = MessageBuilder::new(&mut buf, Type::Con, Code::GET, 1, &[]).unwrap();
    assert_eq!(b.uri_path("abc").err(), Some(Error::NoBufs));
}
