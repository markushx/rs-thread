//! Codec tests, with vectors ported from OT `tests/unit/test_dns.cpp`.

use core::net::Ipv6Addr;
use std::string::String;

use crate::rdata::{LeaseOption, TxtEntry, TxtIter, encode_txt};
use crate::wire::{Header, Name, Parser, Part, Writer, class, opcode, rtype};

fn dotted(n: &Name<'_>) -> String {
    let mut s = String::new();
    n.fmt_dotted(&mut s).unwrap();
    s
}

#[test]
fn header_roundtrip() {
    let h = Header {
        id: 0xbeef,
        response: true,
        opcode: opcode::UPDATE,
        aa: true,
        tc: false,
        rd: true,
        ra: true,
        rcode: 6,
        qd: 1,
        an: 2,
        ns: 3,
        ar: 4,
    };
    let b = h.encode();
    assert_eq!(&b[..4], &[0xbe, 0xef, 0x80 | (5 << 3) | 0x04 | 0x01, 0x86]);
    assert_eq!(Header::decode(&b).unwrap(), h);
    assert!(Header::decode(&b[..11]).is_err());
}

#[test]
fn plain_names_encode_as_ot_vectors() {
    // OT TestDnsName: (dotted, encoding).
    let cases: &[(&str, &[u8])] = &[
        ("example.com", b"\x07example\x03com\x00"),
        ("example.com.", b"\x07example\x03com\x00"),
        ("foo.a.bb.edu", b"\x03foo\x01a\x02bb\x03edu\x00"),
        ("foundation.", b"\x0afoundation\x00"),
        ("", b"\x00"),
        (".", b"\x00"),
    ];
    for (name, enc) in cases {
        let mut buf = [0u8; 64];
        let mut w = Writer::new(&mut buf).unwrap();
        w.write_name_parts(&[Part::Dotted(name)], false).unwrap();
        assert_eq!(&w.as_bytes()[12..], *enc, "{name}");
        let n = Name::new(w.as_bytes(), 12);
        assert_eq!(n.end_offset().unwrap(), 12 + enc.len());
        assert!(n.eq_dotted(name));
    }
    // Invalid names.
    let mut buf = [0u8; 400];
    let mut w = Writer::new(&mut buf).unwrap();
    assert!(w.write_name("a..b").is_err());
    let long = "x".repeat(64);
    assert!(w.write_name(&long).is_err());
    let too_long = ["abcdefghi"; 26].join(".");
    assert!(w.write_name(&too_long).is_err());
    assert_eq!(w.len(), 12, "failed writes leave the message unchanged");
}

#[test]
fn compressed_names_as_ot_vectors() {
    // OT TestDnsCompressedName: "F.ISI.ARPA", then "FOO" + ptr, ptr only,
    // "Human.Readable" + ptr.
    let mut buf = [0u8; 128];
    let mut w = Writer::new(&mut buf).unwrap();
    let n1 = w.len();
    w.write_name("F.ISI.ARPA").unwrap();
    assert_eq!(&w.as_bytes()[n1..], b"\x01F\x03ISI\x04ARPA\x00");
    let n2 = w.len();
    w.write_name_parts(&[Part::Label("FOO"), Part::Dotted("F.ISI.ARPA")], true)
        .unwrap();
    assert_eq!(&w.as_bytes()[n2..], &[3, b'F', b'O', b'O', 0xc0, n1 as u8]);
    let n3 = w.len();
    w.write_name("isi.arpa").unwrap(); // case-insensitive suffix match
    assert_eq!(&w.as_bytes()[n3..], &[0xc0, (n1 + 2) as u8]);
    let n4 = w.len();
    w.write_name_parts(
        &[Part::Label("Human.Readable"), Part::Dotted("F.ISI.ARPA")],
        true,
    )
    .unwrap();
    assert_eq!(w.len() - n4, 15 + 2);

    let msg = w.as_bytes();
    let name = |o| Name::new(msg, o);
    assert_eq!(dotted(&name(n1)), "F.ISI.ARPA");
    assert_eq!(dotted(&name(n2)), "FOO.F.ISI.ARPA");
    assert_eq!(dotted(&name(n3)), "ISI.ARPA");
    assert_eq!(dotted(&name(n4)), "Human\\.Readable.F.ISI.ARPA");
    assert_eq!(name(n2).end_offset().unwrap(), n2 + 6);
    assert_eq!(name(n3).end_offset().unwrap(), n3 + 2);
    assert!(name(n4).eq_labels(&["Human.Readable", "F", "ISI", "ARPA"]));
    assert!(name(n2).eq_dotted("foo.f.isi.arpa."));
    assert!(!name(n2).eq_dotted("foo.f.isi"));
    assert_eq!(name(n2).strip_suffix_dotted("isi.arpa"), Some(2));
    assert_eq!(name(n2).strip_suffix_dotted("x.arpa"), None);
    assert_eq!(name(n2).labels().count(), 4);
}

#[test]
fn malformed_names_are_rejected() {
    // OT TestDnsCompressedName bad vectors (prefixed with 12 header bytes).
    let cases: &[&[u8]] = &[
        // pointer moving forward
        &[3, b'F', b'O', b'O', 0xc0, 6, 2, b'A', b'B', 0],
        // pointer to itself
        &[0xc0, 0],
        // looped one label
        &[3, b'F', b'O', b'O', 0xc0, 0],
        // looped two labels
        &[0, 0, 0, 3, b'F', b'O', b'O', 2, b'B', b'A', 0xc0, 3],
        // truncated label
        &[5, b'a', b'b'],
        // reserved label type 0x40
        &[0x41, b'a', 0],
        // missing terminator
        &[1, b'a'],
    ];
    for c in cases {
        // The two-label loop vector starts at offset 3.
        let off = if c.len() == 12 { 3 } else { 0 };
        let n = Name::new(c, off);
        assert!(n.end_offset().is_err(), "{c:?}");
        assert!(n.labels().any(|l| l.is_err()), "{c:?}");
    }
    // Valid (OT "valid-name").
    let msg = [0u8, 0, 0, 3, b'F', b'O', b'O', 2, b'B', b'A', 0xc0, 2];
    let n = Name::new(&msg, 3);
    assert_eq!(n.end_offset().unwrap(), msg.len());
    assert_eq!(dotted(&n), "FOO.BA");
}

#[test]
fn name_length_limit_on_decode() {
    // 5 labels of 63 bytes = 320 > 255.
    let mut msg = [0u8; 12].to_vec();
    for _ in 0..5 {
        msg.push(63);
        msg.extend_from_slice(&[b'a'; 63]);
    }
    msg.push(0);
    assert!(Name::new(&msg, 12).end_offset().is_err());
}

#[test]
fn records_roundtrip() {
    let mut buf = [0u8; 512];
    let mut w = Writer::new(&mut buf).unwrap();
    w.write_question("_matter._tcp.default.service.arpa", rtype::PTR, class::IN)
        .unwrap();
    // PTR answer: owner compressed against the question.
    w.write_name("_matter._tcp.default.service.arpa").unwrap();
    let m = w.begin_record(rtype::PTR, class::IN, 7200).unwrap();
    w.write_name_parts(
        &[
            Part::Label("ABCD-1234"),
            Part::Dotted("_matter._tcp.default.service.arpa"),
        ],
        true,
    )
    .unwrap();
    w.end_record(m).unwrap();
    // SRV.
    w.write_name_parts(
        &[
            Part::Label("ABCD-1234"),
            Part::Dotted("_matter._tcp.default.service.arpa"),
        ],
        true,
    )
    .unwrap();
    let m = w.begin_record(rtype::SRV, class::IN, 120).unwrap();
    w.put_u16(1).unwrap();
    w.put_u16(2).unwrap();
    w.put_u16(5540).unwrap();
    w.write_name("host.default.service.arpa").unwrap();
    w.end_record(m).unwrap();
    // AAAA.
    w.write_name("host.default.service.arpa").unwrap();
    let addr: Ipv6Addr = "fd00::1234".parse().unwrap();
    w.write_aaaa(120, &addr).unwrap();
    // TXT.
    w.write_name("abcd-1234._matter._tcp.default.service.arpa")
        .unwrap();
    let m = w.begin_record(rtype::TXT, class::IN, 120).unwrap();
    let mut t = [0u8; 40];
    let n = encode_txt(
        &[
            TxtEntry {
                key: b"CRI",
                value: Some(b"5000"),
            },
            TxtEntry {
                key: b"flag",
                value: None,
            },
        ],
        &mut t,
    )
    .unwrap();
    w.put(&t[..n]).unwrap();
    w.end_record(m).unwrap();
    w.set_header(&Header {
        id: 1,
        response: true,
        qd: 1,
        an: 4,
        ..Header::default()
    });

    let (mut p, h) = Parser::new(w.as_bytes()).unwrap();
    assert_eq!((h.id, h.qd, h.an), (1, 1, 4));
    let q = p.question().unwrap();
    assert_eq!((q.qtype, q.qclass), (rtype::PTR, class::IN));
    let r = p.record().unwrap();
    assert!(r.name.eq_dotted("_matter._tcp.default.service.arpa"));
    assert_eq!(r.ttl, 7200);
    let target = r.ptr().unwrap();
    assert!(target.eq_labels(&["ABCD-1234", "_matter", "_tcp", "default", "service", "arpa"]));
    let r = p.record().unwrap();
    let srv = r.srv().unwrap();
    assert_eq!((srv.priority, srv.weight, srv.port), (1, 2, 5540));
    assert!(srv.target.eq_dotted("host.default.service.arpa"));
    let r = p.record().unwrap();
    assert_eq!(r.aaaa().unwrap(), addr);
    let r = p.record().unwrap();
    let e: std::vec::Vec<_> = r.txt().map(|e| e.unwrap()).collect();
    assert_eq!(
        e[0],
        TxtEntry {
            key: b"CRI",
            value: Some(b"5000")
        }
    );
    assert_eq!(
        e[1],
        TxtEntry {
            key: b"flag",
            value: None
        }
    );
    assert!(p.record().is_err());
    // Truncation of the buffer is reported, not panicked.
    let mut small = [0u8; 50];
    let mut w = Writer::new(&mut small).unwrap();
    assert!(w.write_name("_matter._tcp.default.service.arpa").is_ok());
    assert!(w.write_name("another.default.service.arpa").is_err());
}

#[test]
fn txt_vectors() {
    // OT TestDnsTxtEntry encodings.
    let mut out = [0u8; 64];
    let cases: &[(TxtEntry<'_>, &[u8])] = &[
        (
            TxtEntry {
                key: b"key",
                value: Some(b"value"),
            },
            b"\x09key=value",
        ),
        (
            TxtEntry {
                key: b"E",
                value: Some(b"mc^2"),
            },
            b"\x06E=mc^2",
        ),
        (
            TxtEntry {
                key: b"space key",
                value: Some(b"=\0="),
            },
            b"\x0dspace key==\0=",
        ),
        (
            TxtEntry {
                key: b"boolKey",
                value: None,
            },
            b"\x07boolKey",
        ),
        (
            TxtEntry {
                key: b"emptyKey",
                value: Some(b""),
            },
            b"\x09emptyKey=",
        ),
        (
            TxtEntry {
                key: b"123456789",
                value: Some(b"\0"),
            },
            b"\x0b123456789=\0",
        ),
    ];
    for (e, enc) in cases {
        let n = encode_txt(core::slice::from_ref(e), &mut out).unwrap();
        assert_eq!(&out[..n], *enc);
        let back = TxtIter::new(enc).next().unwrap().unwrap();
        assert_eq!(back, *e);
    }
    assert_eq!(encode_txt(&[], &mut out).unwrap(), 1);
    assert_eq!(out[0], 0);
    // Key with '=' or empty key is rejected; value overflow too.
    assert!(
        encode_txt(
            &[TxtEntry {
                key: b"a=b",
                value: None
            }],
            &mut out
        )
        .is_err()
    );
    assert!(
        encode_txt(
            &[TxtEntry {
                key: b"",
                value: Some(b"x")
            }],
            &mut out
        )
        .is_err()
    );
    let big = [b'x'; 255];
    let mut bigout = [0u8; 400];
    assert!(
        encode_txt(
            &[TxtEntry {
                key: b"k",
                value: Some(&big)
            }],
            &mut bigout
        )
        .is_err()
    );
    // Special data: empty strings and "=..." entries are skipped.
    let special = b"\x00\x00\x03A=B\x02=C\x03D=E\x03=12";
    let v: std::vec::Vec<_> = TxtIter::new(special).map(|e| e.unwrap()).collect();
    assert_eq!(
        v,
        [
            TxtEntry {
                key: b"A",
                value: Some(b"B")
            },
            TxtEntry {
                key: b"D",
                value: Some(b"E")
            },
        ]
    );
    // Incorrect length.
    assert!(TxtIter::new(b"\x04a=b").next().unwrap().is_err());
}

#[test]
fn opt_and_lease_option() {
    let mut buf = [0u8; 64];
    let mut w = Writer::new(&mut buf).unwrap();
    w.write_opt(
        1232,
        true,
        Some(LeaseOption {
            lease: 7200,
            key_lease: 1_209_600,
        }),
    )
    .unwrap();
    assert_eq!(
        &w.as_bytes()[12..],
        &[
            0, 0, 41, 0x04, 0xd0, 0, 0, 0x80, 0, 0, 12, 0, 2, 0, 8, 0, 0, 0x1c, 0x20, 0, 0x12,
            0x75, 0
        ]
    );
    let (mut p, _) = Parser::new(w.as_bytes()).unwrap();
    let r = p.record().unwrap();
    assert_eq!(r.rtype, rtype::OPT);
    assert_eq!(r.opt_udp_payload(), 1232);
    assert!(r.opt_dnssec_ok());
    assert_eq!(
        r.update_lease().unwrap(),
        Some(LeaseOption {
            lease: 7200,
            key_lease: 1_209_600
        })
    );
    // Short variant.
    assert_eq!(
        LeaseOption::parse(&[0, 0, 0, 10]).unwrap(),
        LeaseOption {
            lease: 10,
            key_lease: 10
        }
    );
    assert!(LeaseOption::parse(&[0, 0, 0]).is_err());
}
