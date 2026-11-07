//! Frame tests. Vectors are ported from OpenThread
//! `tests/unit/test_mac_frame.cpp`; the originating test function is named
//! in each test's doc comment. OpenThread buffers include a 2-byte FCS, so
//! those are parsed with `Frame::parse_with_fcs`.

use opentrust_core::Error;
use opentrust_core::crypto::SecurityLevel;
use opentrust_core::types::{ExtAddress, PanId, ShortAddress};

use super::*;

const PAN1: PanId = PanId(0xbaba);
const PAN2: PanId = PanId(0xdede);
const SHORT1: ShortAddress = ShortAddress(0x1234);
const SHORT2: ShortAddress = ShortAddress(0x5678);
const EXT1: ExtAddress = ExtAddress([0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0]);
const EXT2: ExtAddress = ExtAddress([0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]);

// --- TestMacAddress ---------------------------------------------------

/// `TestMacAddress`: `Mac::Address` type/predicates and reversed byte order
/// on air (`ExtAddress::kReverseByteOrder`). Local/group bit helpers and
/// random generation of `Mac::ExtAddress` belong to `opentrust-core`.
#[test]
fn test_mac_address() {
    use opentrust_core::bytes::{Reader, Writer};

    let mut a = Address::None;
    assert!(a.is_none());
    assert_eq!(a.mode(), AddressMode::None);
    assert!(!a.is_broadcast() && !a.is_short_invalid());

    a = Address::Short(SHORT1);
    assert_eq!(a.mode(), AddressMode::Short);
    assert!(!a.is_none() && !a.is_broadcast() && !a.is_short_invalid());

    a = Address::Extended(EXT1);
    assert_eq!(a.mode(), AddressMode::Extended);
    assert!(!a.is_broadcast() && !a.is_short_invalid());

    assert!(Address::Short(ShortAddress::BROADCAST).is_broadcast());
    assert!(!Address::Short(ShortAddress::BROADCAST).is_short_invalid());
    assert!(Address::Short(ShortAddress::INVALID).is_short_invalid());
    assert!(!Address::Short(ShortAddress::INVALID).is_broadcast());

    // Extended address: canonical (big-endian) <-> on-air (reversed).
    let mut buf = [0u8; 8];
    let mut w = Writer::new(&mut buf);
    Address::Extended(EXT1).write(&mut w).unwrap();
    assert_eq!(buf, [0xf0, 0xde, 0xbc, 0x9a, 0x78, 0x56, 0x34, 0x12]);
    let mut r = Reader::new(&buf);
    assert_eq!(
        Address::read(&mut r, AddressMode::Extended).unwrap(),
        Address::Extended(EXT1)
    );
    let mut w = Writer::new(&mut buf);
    Address::Short(SHORT1).write(&mut w).unwrap();
    assert_eq!(&buf[..2], &[0x34, 0x12]);
}

// --- TestMacHeader ----------------------------------------------------

#[derive(Clone, Copy)]
enum A {
    N,
    S,
    E,
}
#[derive(Clone, Copy)]
enum P {
    No,
    P1,
    P2,
}

fn addr(t: A, short: ShortAddress, ext: ExtAddress) -> Address {
    match t {
        A::N => Address::None,
        A::S => Address::Short(short),
        A::E => Address::Extended(ext),
    }
}

fn pan(p: P) -> Option<PanId> {
    match p {
        P::No => None,
        P::P1 => Some(PAN1),
        P::P2 => Some(PAN2),
    }
}

/// `TestMacHeader`: header/footer lengths, addresses, PAN IDs, security
/// fields of all 50 table entries. OpenThread's footer length includes the
/// 2-byte FCS, ours only the MIC.
#[test]
fn test_mac_header() {
    use A::{E, N, S};
    use FrameVersion::{V2006 as V06, V2015 as V15};
    use P::{No, P1, P2};
    // (version, src, src pan, dst, dst pan, security, key mode, header, footer, suppress seq)
    type Case = (FrameVersion, A, P, A, P, bool, u8, usize, usize, bool);
    #[rustfmt::skip]
    let cases: &[Case] = &[
        (V06, N, No, N, No, false, 1, 3, 2, false),
        (V06, S, P1, N, No, false, 1, 7, 2, false),
        (V06, E, P1, N, No, false, 1, 13, 2, false),
        (V06, N, No, S, P1, false, 1, 7, 2, false),
        (V06, N, No, E, P1, false, 1, 13, 2, false),
        (V06, S, P1, S, P2, false, 1, 11, 2, false),
        (V06, S, P1, E, P2, false, 1, 17, 2, false),
        (V06, E, P1, S, P2, false, 1, 17, 2, false),
        (V06, E, P1, E, P2, false, 1, 23, 2, false),
        (V06, S, P1, S, P1, false, 1, 9, 2, false),
        (V06, S, P1, E, P1, false, 1, 15, 2, false),
        (V06, E, P1, S, P1, false, 1, 15, 2, false),
        (V06, E, P1, E, P1, false, 1, 21, 2, false),
        (V06, S, P1, S, P1, true, 1, 15, 6, false),
        (V06, S, P1, S, P1, true, 2, 19, 6, false),
        (V15, N, No, N, No, false, 1, 3, 2, false),
        (V15, S, P1, N, No, false, 1, 7, 2, false),
        (V15, E, P1, N, No, false, 1, 13, 2, false),
        (V15, N, No, S, P1, false, 1, 7, 2, false),
        (V15, N, No, E, P1, false, 1, 13, 2, false),
        (V15, S, P1, S, P2, false, 1, 11, 2, false),
        (V15, S, P1, E, P2, false, 1, 17, 2, false),
        (V15, E, P1, S, P2, false, 1, 17, 2, false),
        (V15, S, P1, S, P1, false, 1, 9, 2, false),
        (V15, S, P1, E, P1, false, 1, 15, 2, false),
        (V15, E, P1, S, P1, false, 1, 15, 2, false),
        (V15, E, P1, E, P1, false, 1, 21, 2, false),
        (V15, S, P1, S, P1, true, 1, 15, 6, false),
        (V15, S, P1, S, P1, true, 2, 19, 6, false),
        (V15, N, No, S, No, false, 1, 5, 2, false),
        (V15, N, No, S, No, true, 1, 11, 6, false),
        (V15, N, No, N, P1, false, 1, 5, 2, false),
        (V15, N, No, N, P1, true, 1, 11, 6, false),
        (V15, N, No, S, No, false, 1, 5, 2, false),
        (V15, N, No, E, No, false, 1, 11, 2, false),
        (V15, N, No, S, No, true, 1, 11, 6, false),
        (V15, N, No, E, No, true, 1, 17, 6, false),
        (V15, S, No, N, No, false, 1, 5, 2, false),
        (V15, S, No, N, No, true, 1, 11, 6, false),
        (V15, E, No, N, No, false, 1, 11, 2, false),
        (V15, E, No, N, No, true, 1, 17, 6, false),
        (V15, E, No, E, No, false, 1, 19, 2, false),
        (V15, E, No, E, No, true, 1, 25, 6, false),
        (V15, E, No, E, No, true, 1, 24, 6, true),
        // Not in OpenThread's table: remaining rows of Table 7-2.
        (V15, E, No, E, P1, false, 1, 21, 2, false),
        (V15, N, No, E, P1, false, 1, 13, 2, false),
        (V15, E, P1, N, No, false, 1, 13, 2, false),
        (V15, S, P1, E, P2, true, 1, 23, 6, false),
        (V15, E, P1, S, P1, true, 2, 25, 6, false),
        (V15, S, P1, S, P1, true, 2, 18, 6, true),
    ];

    for (i, c) in cases.iter().enumerate() {
        let (ver, st, sp, dt, dp, sec, kmode, hlen, flen, suppress) = *c;
        let src = addr(st, SHORT1, EXT1);
        let dst = addr(dt, SHORT2, EXT2);
        let security = sec.then(|| {
            let key = if kmode == 1 {
                KeyIdentifier::Index(1)
            } else {
                KeyIdentifier::Source4 {
                    source: [0xff; 4],
                    index: 0xff,
                }
            };
            SecurityHeader::new(SecurityLevel::Mic32, 0, key)
        });
        let mut buf = [0u8; 127];
        let mut b = FrameBuilder::new(&mut buf)
            .version(ver)
            .sequence(0x5a)
            .src(src)
            .dst(dst);
        if let Some(p) = pan(sp) {
            b = b.src_pan(p);
        }
        if let Some(p) = pan(dp) {
            b = b.dst_pan(p);
        }
        if suppress {
            b = b.suppress_sequence();
        }
        if let Some(s) = security {
            b = b.security(s);
        }
        let len = b.build().unwrap_or_else(|e| panic!("case {i}: {e}"));
        let f = Frame::parse(&buf[..len]).unwrap_or_else(|e| panic!("case {i}: {e}"));

        assert_eq!(f.header_len(), hlen, "case {i}");
        assert_eq!(f.mic_len() + FCS_LEN, flen, "case {i}");
        assert_eq!(len, hlen + f.mic_len(), "case {i}");
        assert_eq!(f.frame_type(), FrameType::Data);
        assert!(!f.is_ack());
        assert_eq!(f.version(), ver);
        assert_eq!(f.security_enabled(), sec);
        assert!(!f.frame_pending());
        assert!(!f.ie_present());
        assert_eq!(f.ack_request(), !matches!(dt, A::N), "case {i}");
        assert_eq!(f.src_address(), src);
        assert_eq!(f.dst_address(), dst);
        assert_eq!(f.dst_pan_id().is_some(), !matches!(dp, P::No), "case {i}");
        if let Some(p) = f.dst_pan_id() {
            assert_eq!(Some(p), pan(dp));
        }
        if let Some(p) = f.src_pan_id() {
            assert_eq!(Some(p), pan(sp));
        }
        if let Some(s) = f.security_header() {
            assert_eq!(s.level, SecurityLevel::Mic32);
            assert_eq!(s.key_id_mode().bits(), kmode);
        }
        assert_eq!(f.sequence(), if suppress { None } else { Some(0x5a) });
    }
}

// --- PAN ID compression: IEEE 802.15.4-2015 Table 7-2 ------------------

/// All 14 rows of Table 7-2 (and both short/extended variants of rows
/// 3-6), decoded from raw FCFs: `(dst, src, compression, dst PAN present,
/// src PAN present)`.
#[test]
fn pan_id_compression_table_7_2() {
    use AddressMode::{Extended as E, None as N, Short as S};
    #[rustfmt::skip]
    let rows: [(AddressMode, AddressMode, bool, bool, bool); 22] = [
        (N, N, false, false, false), // 1
        (N, N, true,  true,  false), // 2
        (S, N, false, true,  false), // 3 short
        (E, N, false, true,  false), // 3 ext
        (S, N, true,  false, false), // 4 short
        (E, N, true,  false, false), // 4 ext
        (N, S, false, false, true),  // 5 short
        (N, E, false, false, true),  // 5 ext
        (N, S, true,  false, false), // 6 short
        (N, E, true,  false, false), // 6 ext
        (E, E, false, true,  false), // 7
        (E, E, true,  false, false), // 8
        (S, S, false, true,  true),  // 9
        (S, E, false, true,  true),  // 10
        (E, S, false, true,  true),  // 11
        (S, E, true,  true,  false), // 12
        (E, S, true,  true,  false), // 13
        (S, S, true,  true,  false), // 14
        // Compression bit with a single short/ext address pair is covered
        // above; the rest are the symmetrical duplicates of 3-6 for 2015.
        (S, N, false, true,  false),
        (N, S, false, false, true),
        (E, E, false, true,  false),
        (S, S, true,  true,  false),
    ];
    for (i, (d, s, comp, dp, sp)) in rows.into_iter().enumerate() {
        let raw = 1u16
            | (comp as u16) << 6
            | u16::from(d.bits()) << 10
            | u16::from(FrameVersion::V2015.bits()) << 12
            | u16::from(s.bits()) << 14;
        let fc = FrameControl::from_bits(raw).unwrap();
        assert_eq!(fc.dst_pan_present(), dp, "row {i} dst pan");
        assert_eq!(fc.src_pan_present(), sp, "row {i} src pan");
        let expect = 3 + 2 * (dp as usize + sp as usize) + d.field_len() + s.field_len();
        assert_eq!(fc.addressing_len(), expect, "row {i} len");
    }
}

/// 2003/2006 rule: destination PAN iff destination address; source PAN iff
/// source address and no compression.
#[test]
fn pan_id_rules_2006() {
    use AddressMode::{Extended as E, None as N, Short as S};
    for v in [FrameVersion::V2003, FrameVersion::V2006] {
        for d in [N, S, E] {
            for s in [N, S, E] {
                for comp in [false, true] {
                    let raw = 1u16
                        | (comp as u16) << 6
                        | u16::from(d.bits()) << 10
                        | u16::from(v.bits()) << 12
                        | u16::from(s.bits()) << 14;
                    let fc = FrameControl::from_bits(raw).unwrap();
                    assert_eq!(fc.dst_pan_present(), d != N);
                    assert_eq!(fc.src_pan_present(), s != N && !comp);
                }
            }
        }
    }
}

/// Builder picks the compression bit exactly as the table prescribes.
#[test]
fn builder_compression_choice() {
    let build = |ver, dst: Address, src: Address, dp: Option<PanId>, sp: Option<PanId>| {
        let mut buf = [0u8; 64];
        let mut b = FrameBuilder::new(&mut buf).version(ver).dst(dst).src(src);
        if let Some(p) = dp {
            b = b.dst_pan(p);
        }
        if let Some(p) = sp {
            b = b.src_pan(p);
        }
        let n = b.build().unwrap();
        Frame::parse(&buf[..n]).unwrap().frame_control()
    };
    let (s, e) = (Address::Short(SHORT1), Address::Extended(EXT1));
    let n = Address::None;
    let v = FrameVersion::V2015;
    // Rows 9..14
    assert!(!build(v, s, s, Some(PAN1), Some(PAN2)).pan_id_compression());
    assert!(build(v, s, s, Some(PAN1), Some(PAN1)).pan_id_compression());
    assert!(build(v, s, e, Some(PAN1), Some(PAN1)).pan_id_compression());
    assert!(build(v, e, s, Some(PAN1), Some(PAN1)).pan_id_compression());
    // Rows 7, 8
    assert!(!build(v, e, e, Some(PAN1), None).pan_id_compression());
    assert!(build(v, e, e, None, None).pan_id_compression());
    // Rows 1..6
    assert!(!build(v, n, n, None, None).pan_id_compression());
    assert!(build(v, n, n, Some(PAN1), None).pan_id_compression());
    assert!(!build(v, s, n, Some(PAN1), None).pan_id_compression());
    assert!(build(v, s, n, None, None).pan_id_compression());
    assert!(!build(v, n, s, None, Some(PAN1)).pan_id_compression());
    assert!(build(v, n, s, None, None).pan_id_compression());
}

// --- TestMacFrameApi --------------------------------------------------

/// `TestMacFrameApi`: Imm-Ack, sequence 94 (`ack_psdu1`).
#[test]
fn test_mac_frame_api_imm_ack() {
    let ack_psdu1 = [0x02, 0x10, 0x5e, 0xd2, 0x9b];
    let f = Frame::parse_with_fcs(&ack_psdu1).unwrap();
    assert_eq!(f.frame_type(), FrameType::Ack);
    assert!(!f.security_enabled());
    assert!(!f.frame_pending());
    assert!(!f.ack_request());
    assert!(!f.ie_present());
    assert!(f.dst_pan_id().is_none());
    assert!(f.dst_address().is_none());
    assert_eq!(f.version(), FrameVersion::V2006);
    assert!(f.src_address().is_none());
    assert_eq!(f.sequence(), Some(94));
    assert_eq!(f.header_len(), 3);
    assert!(f.payload().is_empty());
}

/// `TestMacFrameApi`: IEEE 802.15.4-2015 Data (`data_psdu1`). The OpenThread
/// buffer sets "IE present" but carries no IE and no MIC, so it is not a
/// complete frame: it is inspected through `FrameControl` and
/// `SecurityHeader`, and `Frame::parse` rejects it.
#[test]
fn test_mac_frame_api_data_2015() {
    let data_psdu1 = [
        0x29, 0xee, 0x53, 0xce, 0xfa, 0x01, 0x00, 0x00, 0x00, 0x00, 0x0a, 0x6e, 0x16, 0x05, 0x00,
        0x00, 0x00, 0x00, 0x0a, 0x6e, 0x16, 0x0d, 0x01, 0x00, 0x00, 0x00, 0x01,
    ];
    let mut r = opentrust_core::bytes::Reader::new(&data_psdu1);
    let fc = FrameControl::parse(&mut r).unwrap();
    assert_eq!(fc.version(), FrameVersion::V2015);
    assert!(fc.dst_pan_present());
    assert!(fc.dst_mode() != AddressMode::None);
    assert!(fc.src_mode() != AddressMode::None);
    let sh = SecurityHeader::parse(&mut opentrust_core::bytes::Reader::new(
        &data_psdu1[fc.addressing_len()..],
    ))
    .unwrap();
    assert_eq!(sh.control(), 0x0d);
    assert_eq!(sh.level, SecurityLevel::EncMic32);
    assert_eq!(sh.frame_counter, Some(1));
    assert_eq!(sh.key, KeyIdentifier::Index(1));
    assert_eq!(Frame::parse(&data_psdu1).unwrap_err(), Error::Parse);
}

/// `TestMacFrameApi`: 802.15.4-2006 MAC command, sequence 133, Data Request
/// (`mac_cmd_psdu1`).
#[test]
fn test_mac_frame_api_mac_cmd_2006() {
    let mac_cmd_psdu1 = [
        0x6b, 0xdc, 0x85, 0xce, 0xfa, 0x47, 0x36, 0x07, 0xd9, 0x74, 0x45, 0x8d, 0xb2, 0x6e, 0x81,
        0x25, 0xc9, 0xdb, 0xac, 0x2b, 0x0a, 0x0d, 0x00, 0x00, 0x00, 0x00, 0x01, 0x04, 0xaf, 0x14,
        0xce, 0xaa, 0x5a, 0xe5,
    ];
    let f = Frame::parse_with_fcs(&mac_cmd_psdu1).unwrap();
    assert_eq!(f.sequence(), Some(133));
    assert_eq!(f.version(), FrameVersion::V2006);
    assert_eq!(f.frame_type(), FrameType::MacCmd);
    assert_eq!(f.command_id(), Some(0x04));
    assert_eq!(f.command(), Some(MacCommand::DataRequest));
    assert!(f.is_data_request());
    // Command ID is part of the header for pre-2015 frames.
    assert_eq!(f.header_len(), 28);
    assert!(f.payload().is_empty());
    assert_eq!(f.mic(), &[0xaf, 0x14, 0xce, 0xaa]);
    assert_eq!(f.security_header().unwrap().frame_counter, Some(0));
}

/// `TestMacFrameApi`: IEEE 802.15.4-2015 MAC command with CSL IE and
/// Header Termination 2 IE, sequence 141 (`mac_cmd_psdu2`).
#[test]
fn test_mac_frame_api_mac_cmd_2015() {
    let mac_cmd_psdu2 = [
        0x6b, 0xaa, 0x8d, 0xce, 0xfa, 0x00, 0x68, 0x01, 0x68, 0x0d, 0x08, 0x00, 0x00, 0x00, 0x01,
        0x04, 0x0d, 0xed, 0x0b, 0x35, 0x0c, 0x80, 0x3f, 0x04, 0x4b, 0x88, 0x89, 0xd6, 0x59, 0xe1,
    ];
    let f = Frame::parse_with_fcs(&mac_cmd_psdu2).unwrap();
    assert_eq!(f.sequence(), Some(141));
    assert_eq!(f.version(), FrameVersion::V2015);
    assert_eq!(f.frame_type(), FrameType::MacCmd);
    assert_eq!(f.command(), Some(MacCommand::DataRequest));
    let mut ies = f.header_ies();
    let csl = ies.next().unwrap().unwrap();
    assert_eq!(csl.id, IE_ID_CSL);
    assert_eq!(
        csl.csl(),
        Some(CslIe {
            phase: 0x0bed,
            period: 0x0c35,
            rendezvous_time: None
        })
    );
    let ht2 = ies.next().unwrap().unwrap();
    assert_eq!(ht2.id, IE_ID_HEADER_TERMINATION_2);
    assert!(ies.next().is_none());
    // In 2015 frames the command ID is the first payload byte.
    assert_eq!(f.payload(), &[0x04]);
    assert_eq!(f.header_len(), 23);
    assert_eq!(f.dst_address(), Address::Short(ShortAddress(0x6800)));
}

// --- TestMacFrameAckGeneration ---------------------------------------

/// `TestMacFrameAckGeneration`: Imm-Ack generated for received frame 1
/// (`data_psdu1`, 2006, extended addresses).
#[test]
fn test_mac_frame_ack_generation_imm() {
    let data_psdu1 = [
        0x61, 0xdc, 0xbd, 0xce, 0xfa, 0x01, 0x00, 0x00, 0x00, 0x00, 0x0a, 0x6e, 0x16, 0x02, 0x00,
        0x00, 0x00, 0x00, 0x0a, 0x6e, 0x16, 0x7f, 0x33, 0xf0, 0x4d, 0x4c, 0x4d, 0x4c, 0x8b, 0xf0,
        0x00, 0x15, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xc2, 0x57, 0x9c, 0x31,
        0xb3, 0x2a, 0xa1, 0x86, 0xba, 0x9a, 0xed, 0x5a, 0xb9, 0xa3, 0x59, 0x88, 0xeb, 0xbb, 0x0d,
        0xc3, 0xed, 0xeb, 0x8a, 0x53, 0xa6, 0xed, 0xf7, 0xdd, 0x45, 0x6e, 0xf7, 0x9a, 0x17, 0xb4,
        0xab, 0xc6, 0x75, 0x71, 0x46, 0x37, 0x93, 0x4a, 0x32, 0xb1, 0x21, 0x9f, 0x9d, 0xb3, 0x65,
        0x27, 0xd5, 0xfc, 0x50, 0x16, 0x90, 0xd2, 0xd4,
    ];
    let rx = Frame::parse_with_fcs(&data_psdu1).unwrap();
    assert_eq!(rx.version(), FrameVersion::V2006);
    assert!(rx.ack_request());

    let mut buf = [0u8; 100];
    let len = FrameBuilder::imm_ack_for(&mut buf, &rx, false).unwrap();
    // kImmAckLength (5) includes the FCS.
    assert_eq!(len + FCS_LEN, 5);
    let ack = Frame::parse(&buf[..len]).unwrap();
    assert_eq!(ack.frame_type(), FrameType::Ack);
    assert!(!ack.security_enabled());
    assert!(!ack.frame_pending());
    assert!(!ack.ack_request());
    assert!(!ack.ie_present());
    assert!(ack.dst_pan_id().is_none());
    assert!(ack.dst_address().is_none());
    assert!(ack.src_address().is_none());
    assert_eq!(ack.version(), FrameVersion::V2006);
    assert_eq!(ack.sequence(), Some(189));

    let len = FrameBuilder::imm_ack_for(&mut buf, &rx, true).unwrap();
    assert!(Frame::parse(&buf[..len]).unwrap().frame_pending());
}

/// `TestMacFrameAckGeneration`: Enhanced ACK generated for received frame 2
/// (`data_psdu2`, 2015, short addresses, secured) with a pre-encoded CSL
/// IE; then `SetCslIe(123, 456)`. The OpenThread vector carries no FCS
/// despite its comment, so it is parsed as is.
#[test]
fn test_mac_frame_ack_generation_enh() {
    let data_psdu2 = [
        0x69, 0xa8, 0x8e, 0xce, 0xfa, 0x02, 0x24, 0x00, 0x24, 0x0d, 0x02, 0x00, 0x00, 0x00, 0x01,
        0x6b, 0x64, 0x60, 0x08, 0x55, 0xb8, 0x10, 0x18, 0xc7, 0x40, 0x2e, 0xfb, 0xf3, 0xda, 0xf9,
        0x4e, 0x58, 0x70,
    ];
    let rx = Frame::parse(&data_psdu2).unwrap();
    assert_eq!(rx.mic(), &[0xf9, 0x4e, 0x58, 0x70]);
    assert_eq!(rx.payload().len(), 14);
    assert_eq!(rx.security_header().unwrap().frame_counter, Some(2));

    let ie_data = [0x04, 0x0d, 0x21, 0x0c, 0x35, 0x0c];
    let mut buf = [0u8; 100];
    let len = FrameBuilder::enh_ack(&mut buf, &rx, false)
        .unwrap()
        .raw_header_ies(&ie_data)
        .build()
        .unwrap();
    // OpenThread: mLength == 25 including the 2-byte FCS.
    assert_eq!(len + FCS_LEN, 25);
    {
        let ack = Frame::parse(&buf[..len]).unwrap();
        assert_eq!(ack.frame_type(), FrameType::Ack);
        assert!(ack.security_enabled());
        assert!(ack.ie_present());
        assert!(ack.dst_pan_id().is_some());
        assert_eq!(ack.dst_pan_id(), Some(PanId(0xface)));
        assert_eq!(ack.dst_address(), Address::Short(ShortAddress(0x2400)));
        assert!(ack.src_address().is_none());
        assert_eq!(ack.version(), FrameVersion::V2015);
        assert_eq!(ack.sequence(), Some(142));
        assert!(!ack.ack_request());
        let csl = ack.csl_ie().unwrap();
        assert_eq!((csl.period, csl.phase), (3125, 3105));
        let sh = ack.security_header().unwrap();
        assert_eq!(sh.level, SecurityLevel::EncMic32);
        assert_eq!(sh.key, KeyIdentifier::Index(1));
        assert_eq!(sh.frame_counter, Some(0));
        assert!(ack.payload().is_empty());
    }

    let mut m = FrameMut::new(&mut buf[..len]).unwrap();
    m.set_csl_ie(456, 123).unwrap();
    m.set_frame_counter(77).unwrap();
    let ack = m.frame().unwrap();
    let csl = ack.csl_ie().unwrap();
    assert_eq!((csl.period, csl.phase), (123, 456));
    assert_eq!(ack.security_header().unwrap().frame_counter, Some(77));
}

/// Enhanced ACK preconditions (`GenerateEnhAck` returns `kErrorParse`).
#[test]
fn enh_ack_rejects_unsuitable_frames() {
    let mut buf = [0u8; 64];
    let mut rxbuf = [0u8; 64];
    let mk = |rxbuf: &mut [u8], f: &dyn Fn(FrameBuilder<'_>) -> FrameBuilder<'_>| {
        let b = FrameBuilder::new(rxbuf)
            .version(FrameVersion::V2015)
            .pan_id(PAN1)
            .src(Address::Short(SHORT1))
            .dst(Address::Short(SHORT2));
        f(b).build().unwrap()
    };
    // No ack request.
    let n = mk(&mut rxbuf, &|b| b.ack_request(false));
    let rx = Frame::parse(&rxbuf[..n]).unwrap();
    assert!(FrameBuilder::enh_ack(&mut buf, &rx, false).is_err());
    // Broadcast destination.
    let n = mk(&mut rxbuf, &|b| {
        b.dst(Address::Short(ShortAddress::BROADCAST))
            .ack_request(true)
    });
    let rx = Frame::parse(&rxbuf[..n]).unwrap();
    assert!(FrameBuilder::enh_ack(&mut buf, &rx, false).is_err());
    // 2006 frame.
    let n = mk(&mut rxbuf, &|b| b.version(FrameVersion::V2006));
    let rx = Frame::parse(&rxbuf[..n]).unwrap();
    assert!(FrameBuilder::enh_ack(&mut buf, &rx, false).is_err());
    // Wrong security level.
    let n = mk(&mut rxbuf, &|b| {
        b.security(SecurityHeader::new(
            SecurityLevel::Mic32,
            1,
            KeyIdentifier::Index(1),
        ))
    });
    let rx = Frame::parse(&rxbuf[..n]).unwrap();
    assert!(FrameBuilder::enh_ack(&mut buf, &rx, false).is_err());
    // Fine: unsecured 2015.
    let n = mk(&mut rxbuf, &|b| b);
    let rx = Frame::parse(&rxbuf[..n]).unwrap();
    let len = FrameBuilder::enh_ack(&mut buf, &rx, true)
        .unwrap()
        .build()
        .unwrap();
    let ack = Frame::parse(&buf[..len]).unwrap();
    assert!(ack.frame_pending() && !ack.security_enabled());
    assert_eq!(ack.dst_address(), Address::Short(SHORT1));
}

// --- Wake-up frames ---------------------------------------------------

const WAKEUP_PSDU: [u8; 41] = [
    // Frame Control
    0xfd, 0x87, // PAN ID
    0xce, 0xfa, // Destination Address
    0x87, 0x96, 0xa5, 0xb4, 0xc3, 0xd2, 0xe1, 0xf0, // Source Address
    0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, // Security Header
    0x15, 0xfc, 0xfc, 0xfc, 0xfc, 0x00, 0x00, 0x00, 0x1c, 0x1d, // Rendezvous Time IE
    0x82, 0x0e, 0xcd, 0xab, // Connection IE
    0x05, 0x00, 0x9b, 0xb8, 0xea, 0x01, 0x1c,
];

/// `TestMacWakeupFrameGeneration`.
#[test]
fn test_mac_wakeup_frame_generation() {
    let src = Address::Extended(ExtAddress([1, 2, 3, 4, 5, 6, 7, 8]));
    let dst = Address::Extended(ExtAddress([0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87]));
    let mut buf = [0u8; 127];
    let len = FrameBuilder::wakeup(
        &mut buf,
        PanId(0xface),
        dst,
        src,
        0xabcd,
        ConnectionIe {
            retry_interval: 1,
            retry_count: 12,
        },
        SecurityHeader::new(
            SecurityLevel::EncMic32,
            0xfcfc_fcfc,
            KeyIdentifier::Source4 {
                source: [0, 0, 0, 0x1c],
                index: 0x1d,
            },
        ),
    )
    .build()
    .unwrap();
    // OpenThread's GetLength() == sizeof(kWakeupPsdu) + footer (MIC + FCS).
    assert_eq!(len, WAKEUP_PSDU.len() + 4);
    assert_eq!(&buf[..WAKEUP_PSDU.len()], &WAKEUP_PSDU);

    let f = Frame::parse(&buf[..len]).unwrap();
    assert_eq!(f.frame_type(), FrameType::Multipurpose);
    assert!(!f.ack_request());
    assert_eq!(f.sequence(), None);
    assert!(f.payload().is_empty());
    assert_eq!(f.src_address(), src);
    assert_eq!(f.dst_address(), dst);
    assert_eq!(f.dst_pan_id(), Some(PanId(0xface)));
    assert_eq!(f.rendezvous_time_ie().unwrap().rendezvous_time, 0xabcd);
    let c = f.connection_ie().unwrap();
    assert_eq!((c.retry_interval, c.retry_count), (1, 12));
    assert!(f.is_wakeup_frame());
}

/// `TestMacWakeupFrameDetectionNegative`.
#[test]
fn test_mac_wakeup_frame_detection_negative() {
    const FOOTER: [u8; 6] = [0; 6];
    let ack_requested: [&[u8]; 4] = [
        &[0xfd, 0xc7, 0xce, 0xfa],
        &[0xdd; 8],
        &[0x55; 8],
        &[0x15, 0xfc, 0xfc, 0xfc, 0xfc, 0x00, 0x00, 0x00, 0x1c, 0x1d],
    ];
    let ies: [u8; 11] = [
        0x82, 0x0e, 0xcd, 0xab, 0x05, 0x00, 0x9b, 0xb8, 0xea, 0x01, 0x1c,
    ];
    let conn_only = &ies[4..];

    let mut cases = [[0u8; 64]; 5];
    let mut lens = [0usize; 5];
    let mut put = |i: usize, parts: &[&[u8]]| {
        let mut n = 0;
        for p in parts {
            cases[i][n..n + p.len()].copy_from_slice(p);
            n += p.len();
        }
        lens[i] = n;
    };
    // ackRequestedPsdu
    put(
        0,
        &[
            ack_requested[0],
            ack_requested[1],
            ack_requested[2],
            ack_requested[3],
            &ies,
            &FOOTER,
        ],
    );
    // shortAddressPsdu
    put(
        1,
        &[
            &[0xbd, 0x87, 0xce, 0xfa],
            &[0xdd; 8],
            &[0x55; 2],
            ack_requested[3],
            &ies,
            &FOOTER,
        ],
    );
    // noRendezvousIePsdu
    put(
        2,
        &[
            &[0xfd, 0x87, 0xce, 0xfa],
            &[0xdd; 8],
            &[0x55; 8],
            ack_requested[3],
            conn_only,
            &FOOTER,
        ],
    );
    // noConnectionIePsdu (sub-type 2)
    let mut bad_ies = ies;
    bad_ies[9] = 0x02;
    put(
        3,
        &[
            &[0xfd, 0x87, 0xce, 0xfa],
            &[0xdd; 8],
            &[0x55; 8],
            ack_requested[3],
            &bad_ies,
            &FOOTER,
        ],
    );
    // keyIdMode1Psdu
    put(
        4,
        &[
            &[0xfd, 0x87, 0xce, 0xfa],
            &[0xdd; 8],
            &[0x55; 8],
            &[0x0d, 0xfc, 0xfc, 0xfc, 0xfc, 0x1d],
            &ies,
            &FOOTER,
        ],
    );
    for i in 0..5 {
        let f = Frame::parse_with_fcs(&cases[i][..lens[i]]).unwrap();
        assert!(!f.is_wakeup_frame(), "case {i}");
    }
    // The positive vector with a footer is recognized (control).
    let mut ok = [0u8; 64];
    ok[..WAKEUP_PSDU.len()].copy_from_slice(&WAKEUP_PSDU);
    let f = Frame::parse_with_fcs(&ok[..WAKEUP_PSDU.len() + 6]).unwrap();
    assert!(f.is_wakeup_frame());
}

// --- Frame control ------------------------------------------------------

#[test]
fn frame_control_rejects_reserved_values() {
    // Frame types 4, 6, 7; version 3; address mode 1.
    for t in [4u16, 6, 7] {
        assert_eq!(FrameControl::from_bits(t), Err(Error::Parse));
    }
    assert_eq!(FrameControl::from_bits(1 | 3 << 12), Err(Error::Parse));
    assert_eq!(FrameControl::from_bits(1 | 1 << 10), Err(Error::Parse));
    assert_eq!(FrameControl::from_bits(1 | 1 << 14), Err(Error::Parse));
    // Multipurpose address mode 1.
    assert_eq!(FrameControl::from_bits(5 | 8 | 1 << 4), Err(Error::Parse));
    // Short multipurpose FCF must not have high bits.
    assert_eq!(FrameControl::from_bits(5 | 1 << 9), Err(Error::Parse));
}

#[test]
fn short_multipurpose_fcf() {
    let f = Frame::parse(&[0x05, 0x09, 0xaa]).unwrap();
    assert_eq!(f.frame_type(), FrameType::Multipurpose);
    assert!(f.frame_control().is_short());
    assert_eq!(f.sequence(), Some(9));
    assert_eq!(f.payload(), &[0xaa]);
    let mut buf = [0x05, 0x09, 0xaa];
    let mut m = FrameMut::new(&mut buf).unwrap();
    // Ack request does not exist in the short FCF.
    assert_eq!(m.set_ack_request(true), Err(Error::InvalidState));
    m.set_sequence(1).unwrap();
}

#[test]
fn reserved_bits_ignored_before_2015() {
    // 2006 data frame, short dst, bit 8 (seq suppression in 2015) and bit 9
    // (IE present in 2015) set: reserved, so seq number is present and no IE.
    let psdu = [0x01, 0x1b, 0x07, 0xce, 0xfa, 0x34, 0x12, 0xaa];
    let f = Frame::parse(&psdu).unwrap();
    assert_eq!(f.version(), FrameVersion::V2006);
    assert_eq!(f.sequence(), Some(0x07));
    assert!(!f.ie_present());
    assert_eq!(f.payload(), &[0xaa]);
}

// --- Security header ------------------------------------------------------

#[test]
fn security_header_round_trip_all_modes() {
    use opentrust_core::bytes::{Reader, Writer};
    let levels = [
        SecurityLevel::Mic32,
        SecurityLevel::Mic64,
        SecurityLevel::Mic128,
        SecurityLevel::Enc,
        SecurityLevel::EncMic32,
        SecurityLevel::EncMic64,
        SecurityLevel::EncMic128,
    ];
    let keys = [
        (KeyIdentifier::Implicit, 1usize),
        (KeyIdentifier::Index(3), 2),
        (
            KeyIdentifier::Source4 {
                source: [1, 2, 3, 4],
                index: 9,
            },
            6,
        ),
        (
            KeyIdentifier::Source8 {
                source: [1, 2, 3, 4, 5, 6, 7, 8],
                index: 9,
            },
            10,
        ),
    ];
    for level in levels {
        for (key, key_len) in keys {
            for (fc, asn) in [(Some(0xdead_beefu32), false), (None, false), (None, true)] {
                let h = SecurityHeader {
                    level,
                    frame_counter: fc,
                    asn_in_nonce: asn,
                    key,
                };
                let expect = key_len + 4 * fc.is_some() as usize;
                assert_eq!(h.encoded_len(), expect);
                assert_eq!(h.mic_len(), level.mic_len());
                assert_eq!(h.is_encrypted(), level.is_encrypted());
                let mut buf = [0u8; 16];
                let mut w = Writer::new(&mut buf);
                h.write(&mut w).unwrap();
                assert_eq!(w.len(), expect);
                assert_eq!(buf[0] & 7, level.value());
                assert_eq!((buf[0] >> 3) & 3, key.mode().bits());
                let mut r = Reader::new(&buf[..expect]);
                assert_eq!(SecurityHeader::parse(&mut r).unwrap(), h);
                assert!(r.is_empty());
                for n in 0..expect {
                    let mut r = Reader::new(&buf[..n]);
                    assert_eq!(SecurityHeader::parse(&mut r), Err(Error::Parse));
                }
            }
        }
    }
    // Level 0 is rejected both ways.
    let mut r = opentrust_core::bytes::Reader::new(&[0x08, 0, 0, 0, 0, 1]);
    assert_eq!(SecurityHeader::parse(&mut r), Err(Error::Parse));
    let h = SecurityHeader::new(SecurityLevel::None, 0, KeyIdentifier::Implicit);
    let mut b = [0u8; 8];
    assert_eq!(
        h.write(&mut opentrust_core::bytes::Writer::new(&mut b)),
        Err(Error::InvalidArgs)
    );
}

#[test]
fn security_ranges_for_ccm() {
    let mut buf = [0u8; 64];
    let len = FrameBuilder::new(&mut buf)
        .version(FrameVersion::V2015)
        .pan_id(PAN1)
        .src(Address::Short(SHORT1))
        .dst(Address::Short(SHORT2))
        .security(SecurityHeader::new(
            SecurityLevel::EncMic64,
            5,
            KeyIdentifier::Index(2),
        ))
        .payload(&[1, 2, 3])
        .build()
        .unwrap();
    assert_eq!(len, 2 + 1 + 2 + 2 + 2 + 6 + 3 + 8);
    let mut m = FrameMut::new(&mut buf[..len]).unwrap();
    let p = m.parts_mut().unwrap();
    assert_eq!(p.header.len(), 15);
    assert_eq!(p.payload, &[1, 2, 3]);
    assert_eq!(p.mic.len(), 8);
    p.payload[0] = 9;
    p.mic.fill(0xee);
    let f = m.frame().unwrap();
    assert_eq!(f.payload_range(), 15..18);
    assert_eq!(f.mic_range(), 18..26);
    assert_eq!(f.payload(), &[9, 2, 3]);
    assert_eq!(f.mic(), &[0xee; 8]);
    assert_eq!(f.header().len(), f.header_len());
}

// --- Header IEs -------------------------------------------------------------

#[test]
fn header_ie_round_trips() {
    let probing = [0x11, 0x22];
    let ies: [HeaderIeValue<'_>; 6] = [
        CslIe {
            phase: 1,
            period: 2,
            rendezvous_time: None,
        }
        .into(),
        CslIe {
            phase: 3,
            period: 4,
            rendezvous_time: Some(5),
        }
        .into(),
        RendezvousTimeIe {
            rendezvous_time: 0x1234,
        }
        .into(),
        VendorIe::thread_enh_ack_probing(&probing).into(),
        TimeIe {
            sequence: 3,
            time: 0x0102_0304_0506_0708,
        }
        .into(),
        ConnectionIe {
            retry_interval: 2,
            retry_count: 7,
        }
        .into(),
    ];
    let mut buf = [0u8; 127];
    let mut b = FrameBuilder::new(&mut buf)
        .version(FrameVersion::V2015)
        .pan_id(PAN1)
        .dst(Address::Short(SHORT2));
    for ie in ies {
        b = b.header_ie(ie);
    }
    let len = b.payload(&[0xaa]).build().unwrap();
    let f = Frame::parse(&buf[..len]).unwrap();
    assert!(f.ie_present());
    let parsed: [HeaderIe<'_>; 7] = {
        let mut it = f.header_ies();
        core::array::from_fn(|_| it.next().unwrap().unwrap())
    };
    for (p, i) in parsed.iter().zip(ies.iter()) {
        assert_eq!(p.id, i.id());
        assert_eq!(p.encoded_len(), i.encoded_len());
    }
    // Automatic Header Termination 2 before the payload.
    assert_eq!(parsed[6].id, IE_ID_HEADER_TERMINATION_2);
    assert_eq!(f.payload(), &[0xaa]);
    assert_eq!(parsed[0].csl().unwrap().rendezvous_time, None);
    assert_eq!(parsed[1].csl().unwrap().rendezvous_time, Some(5));
    assert_eq!(parsed[2].rendezvous_time().unwrap().rendezvous_time, 0x1234);
    let v = parsed[3].vendor().unwrap();
    assert_eq!((v.oui, v.subtype, v.data), (THREAD_OUI, 0, &probing[..]));
    assert_eq!(
        f.find_thread_ie(THREAD_IE_ENH_ACK_PROBING).unwrap().data,
        &probing
    );
    assert!(f.find_thread_ie(THREAD_IE_CONNECTION).is_some());
    assert_eq!(f.time_ie().unwrap().time, 0x0102_0304_0506_0708);
    let c = f.connection_ie().unwrap();
    assert_eq!((c.retry_interval, c.retry_count), (2, 7));
    // Thread OUI is little-endian on air: 9b b8 ea.
    let pos = buf[..len]
        .windows(3)
        .position(|w| w == [0x9b, 0xb8, 0xea])
        .unwrap();
    assert!(pos > 0);
}

#[test]
fn header_termination_rules() {
    let build = |payload: &[u8], cmd: bool| {
        let mut buf = [0u8; 64];
        let mut b = FrameBuilder::new(&mut buf)
            .version(FrameVersion::V2015)
            .pan_id(PAN1)
            .dst(Address::Short(SHORT2))
            .header_ie(CslIe {
                phase: 1,
                period: 2,
                rendezvous_time: None,
            })
            .payload(payload);
        if cmd {
            b = b
                .frame_type(FrameType::MacCmd)
                .command(MacCommand::DataRequest);
        }
        let n = b.build().unwrap();
        let f = Frame::parse(&buf[..n]).unwrap();
        (n, f.header_ies().count(), f.payload().len(), f.header_len())
    };
    // No payload: no termination IE (IE ends the frame).
    assert_eq!(build(&[], false), (2 + 1 + 2 + 2 + 6, 1, 0, 13));
    // Payload: HT2 inserted.
    assert_eq!(build(&[7], false), (2 + 1 + 2 + 2 + 6 + 2 + 1, 2, 1, 15));
    // MAC command (2015): HT2 inserted, command ID is first payload byte.
    assert_eq!(build(&[], true), (2 + 1 + 2 + 2 + 6 + 2 + 1, 2, 1, 15));
}

#[test]
fn header_termination_1_ends_header() {
    // HT1 (0x7e): payload IEs follow.
    let mut buf = [0u8; 64];
    let pie = [0x02, 0x80 | 0x08, 0xaa, 0xbb]; // group 1, len 2
    let mut payload = [0u8; 8];
    payload[..4].copy_from_slice(&pie);
    payload[4..6].copy_from_slice(&[0x00, 0xf8]); // PT, group 0xf
    payload[6] = 0x55;
    let n = FrameBuilder::new(&mut buf)
        .version(FrameVersion::V2015)
        .pan_id(PAN1)
        .dst(Address::Short(SHORT2))
        .header_ie(HeaderIeValue::Termination1)
        .payload(&payload[..7])
        .build()
        .unwrap();
    let f = Frame::parse(&buf[..n]).unwrap();
    assert_eq!(f.header_ies().count(), 1);
    assert_eq!(f.payload().len(), 7);
    let mut it = PayloadIeIter::new(f.payload());
    let ie = it.next().unwrap().unwrap();
    assert_eq!((ie.group_id, ie.content), (1, &[0xaa, 0xbb][..]));
    let pt = it.next().unwrap().unwrap();
    assert_eq!(pt.group_id, PAYLOAD_IE_GROUP_TERMINATION);
    assert!(it.next().is_none());
    assert_eq!(it.rest(), &[0x55]);
    // Malformed payload IEs.
    assert_eq!(
        PayloadIeIter::new(&[0x01]).next().unwrap().unwrap_err(),
        Error::Parse
    );
    assert_eq!(
        PayloadIeIter::new(&[0x05, 0x88, 1])
            .next()
            .unwrap()
            .unwrap_err(),
        Error::Parse
    );
    // Header IE type bit set -> not a header IE.
    assert_eq!(
        HeaderIeIter::new(&[0x00, 0x80])
            .next()
            .unwrap()
            .unwrap_err(),
        Error::Parse
    );
}

#[test]
fn malformed_ies_are_parse_errors() {
    // 2015 data frame: FCF 0xa8 0x69? build from builder pieces, then break.
    let mut buf = [0u8; 64];
    let n = FrameBuilder::new(&mut buf)
        .version(FrameVersion::V2015)
        .pan_id(PAN1)
        .dst(Address::Short(SHORT2))
        .header_ie(CslIe {
            phase: 1,
            period: 2,
            rendezvous_time: None,
        })
        .build()
        .unwrap();
    let ie_off = n - 6;
    // IE length beyond frame.
    let mut bad = buf;
    bad[ie_off] = (bad[ie_off] & 0x80) | 0x7f;
    assert_eq!(Frame::parse(&bad[..n]).unwrap_err(), Error::Parse);
    // IE flag but no IE bytes.
    assert_eq!(Frame::parse(&buf[..ie_off]).unwrap_err(), Error::Parse);
    // One byte of IE only.
    assert_eq!(Frame::parse(&buf[..ie_off + 1]).unwrap_err(), Error::Parse);
    // Typed accessor on odd CSL content: structurally valid, typed view None.
    let mut odd = buf;
    odd[ie_off] = (odd[ie_off] & 0x80) | 5;
    let f = Frame::parse(&odd[..n + 1]).unwrap();
    assert!(f.csl_ie().is_none());
    assert!(f.find_header_ie(IE_ID_CSL).is_some());
}

// --- Beacon -------------------------------------------------------------------

#[test]
fn thread_beacon_round_trip() {
    use opentrust_core::bytes::Writer;
    let mut name = [0u8; 16];
    name[..6].copy_from_slice(b"OpenTh");
    let tb = ThreadBeaconPayload {
        version: 2,
        native: true,
        joining_permitted: true,
        network_name: name,
        ext_pan_id: [1, 2, 3, 4, 5, 6, 7, 8],
    };
    let mut payload = [0u8; 40];
    let mut w = Writer::new(&mut payload);
    Beacon::write_thread_header(&mut w).unwrap();
    tb.write(&mut w).unwrap();
    let plen = w.len();
    let mut buf = [0u8; 127];
    let n = FrameBuilder::new(&mut buf)
        .frame_type(FrameType::Beacon)
        .src_pan(PAN1)
        .src(Address::Extended(EXT1))
        .payload(&payload[..plen])
        .build()
        .unwrap();
    let f = Frame::parse(&buf[..n]).unwrap();
    assert_eq!(f.frame_type(), FrameType::Beacon);
    assert!(!f.ack_request());
    let b = Beacon::parse(f.payload()).unwrap();
    assert_eq!(b.superframe, SuperframeSpec::THREAD);
    assert_eq!(b.superframe.beacon_order(), 15);
    assert_eq!(b.superframe.superframe_order(), 15);
    assert_eq!(b.superframe.final_cap_slot(), 15);
    assert!(!b.superframe.pan_coordinator() && !b.superframe.association_permit());
    assert_eq!(
        (b.gts_count, b.pending_short, b.pending_extended),
        (0, 0, 0)
    );
    assert_eq!(ThreadBeaconPayload::parse(b.payload).unwrap(), tb);
    assert_eq!(tb.network_name_bytes(), b"OpenTh");
    assert_eq!(
        ThreadBeaconPayload::parse(&b.payload[..25]),
        Err(Error::Parse)
    );
    let mut wrong = [0u8; 26];
    wrong.copy_from_slice(b.payload);
    wrong[0] = 4;
    assert_eq!(ThreadBeaconPayload::parse(&wrong), Err(Error::Parse));
}

#[test]
fn beacon_gts_and_pending_are_skipped() {
    // Superframe 0xcf46: BO 6, SO 4, CAP 15, PAN coordinator + assoc permit.
    // GTS spec 0x82: 2 descriptors + permit; directions byte + 2 x 3 bytes.
    // Pending spec 0x21: 1 short (2 bytes) + 2 extended (16 bytes).
    let mut v = [0u8; 48];
    let head = [0x46, 0xcf, 0x82, 0b11, 1, 2, 3, 4, 5, 6, 0x21, 0xaa, 0xbb];
    v[..head.len()].copy_from_slice(&head);
    let mut n = head.len();
    for i in 0..16 {
        v[n] = 1 + (i / 8) as u8;
        n += 1;
    }
    v[n..n + 4].copy_from_slice(&[0x03, 0x01, 0xde, 0xad]);
    n += 4;
    let b = Beacon::parse(&v[..n]).unwrap();
    assert_eq!(b.superframe.beacon_order(), 6);
    assert_eq!(b.superframe.superframe_order(), 4);
    assert_eq!(b.superframe.final_cap_slot(), 15);
    assert!(b.superframe.pan_coordinator() && b.superframe.association_permit());
    assert!(b.gts_permit);
    assert_eq!(b.gts_count, 2);
    assert_eq!((b.pending_short, b.pending_extended), (1, 2));
    assert_eq!(b.pending_addresses.len(), 2 + 16);
    assert_eq!(b.payload, &[0x03, 0x01, 0xde, 0xad]);
    for k in 0..n - 4 {
        assert_eq!(
            Beacon::parse(&v[..k]).map(|_| ()),
            Err(Error::Parse),
            "k={k}"
        );
    }
}

// --- MAC commands ---------------------------------------------------------------

#[test]
fn mac_commands_round_trip() {
    use MacCommand::*;
    for (c, id) in [
        (AssociationRequest, 1),
        (AssociationResponse, 2),
        (DisassociationNotification, 3),
        (DataRequest, 4),
        (PanIdConflictNotification, 5),
        (OrphanNotification, 6),
        (BeaconRequest, 7),
        (CoordinatorRealignment, 8),
        (GtsRequest, 9),
    ] {
        assert_eq!(c.id(), id);
        assert_eq!(MacCommand::from_id(id), Some(c));
        for ver in [FrameVersion::V2006, FrameVersion::V2015] {
            let mut buf = [0u8; 64];
            // Beacon request: broadcast, no source, as Thread sends it.
            let n = FrameBuilder::new(&mut buf)
                .frame_type(FrameType::MacCmd)
                .version(ver)
                .sequence(id)
                .dst_pan(PanId::BROADCAST)
                .dst(Address::Short(ShortAddress::BROADCAST))
                .command(c)
                .build()
                .unwrap();
            let f = Frame::parse(&buf[..n]).unwrap();
            assert_eq!(f.command(), Some(c));
            assert_eq!(f.sequence(), Some(id));
            assert!(!f.ack_request());
            let hl = if ver == FrameVersion::V2006 { n } else { n - 1 };
            assert_eq!(f.header_len(), hl);
            // Truncating the command ID is an error.
            assert_eq!(Frame::parse(&buf[..n - 1]).unwrap_err(), Error::Parse);
        }
    }
    assert_eq!(MacCommand::from_id(0), None);
    assert_eq!(MacCommand::from_id(0x0a), None);
    // Data frames have no command.
    let mut buf = [0u8; 16];
    let n = FrameBuilder::new(&mut buf).build().unwrap();
    assert_eq!(Frame::parse(&buf[..n]).unwrap().command_id(), None);
}

/// Known on-air Beacon Request as sent by OpenThread (2006).
#[test]
fn beacon_request_vector() {
    // FCF 0x0803: MAC cmd, dst short, 2003; seq 0x2a, dst PAN ffff, dst ffff, cmd 7.
    let psdu = [0x03, 0x08, 0x2a, 0xff, 0xff, 0xff, 0xff, 0x07];
    let f = Frame::parse(&psdu).unwrap();
    assert_eq!(f.command(), Some(MacCommand::BeaconRequest));
    assert_eq!(f.dst_pan_id(), Some(PanId::BROADCAST));
    assert!(f.dst_address().is_broadcast());
    let mut buf = [0u8; 16];
    let n = FrameBuilder::new(&mut buf)
        .version(FrameVersion::V2003)
        .frame_type(FrameType::MacCmd)
        .sequence(0x2a)
        .dst_pan(PanId::BROADCAST)
        .dst(Address::Short(ShortAddress::BROADCAST))
        .command(MacCommand::BeaconRequest)
        .build()
        .unwrap();
    assert_eq!(&buf[..n], &psdu);
}

// --- Builder errors ----------------------------------------------------------------

#[test]
fn builder_errors() {
    let mut buf = [0u8; 127];
    // Missing PAN ID where required.
    assert_eq!(
        FrameBuilder::new(&mut buf)
            .dst(Address::Short(SHORT1))
            .build(),
        Err(Error::InvalidArgs)
    );
    // 2015, short/short without dst PAN (rows 9-14 always carry one).
    assert_eq!(
        FrameBuilder::new(&mut buf)
            .version(FrameVersion::V2015)
            .dst(Address::Short(SHORT1))
            .src(Address::Short(SHORT2))
            .build(),
        Err(Error::InvalidArgs)
    );
    // Sequence suppression / IEs before 2015.
    assert_eq!(
        FrameBuilder::new(&mut buf).suppress_sequence().build(),
        Err(Error::InvalidArgs)
    );
    assert_eq!(
        FrameBuilder::new(&mut buf)
            .header_ie(HeaderIeValue::Termination2)
            .build(),
        Err(Error::InvalidArgs)
    );
    // MAC command mismatch.
    assert_eq!(
        FrameBuilder::new(&mut buf)
            .frame_type(FrameType::MacCmd)
            .build(),
        Err(Error::InvalidArgs)
    );
    assert_eq!(
        FrameBuilder::new(&mut buf)
            .command(MacCommand::DataRequest)
            .build(),
        Err(Error::InvalidArgs)
    );
    // Level 0.
    assert_eq!(
        FrameBuilder::new(&mut buf)
            .security(SecurityHeader::new(
                SecurityLevel::None,
                0,
                KeyIdentifier::Implicit
            ))
            .build(),
        Err(Error::InvalidArgs)
    );
    // Too many IEs.
    let mut b = FrameBuilder::new(&mut buf).version(FrameVersion::V2015);
    for _ in 0..=MAX_HEADER_IES {
        b = b.header_ie(HeaderIeValue::Termination2);
    }
    assert_eq!(b.build(), Err(Error::NoBufs));
    // IE content too long for a header IE.
    let big = [0u8; 128];
    assert_eq!(
        FrameBuilder::new(&mut buf)
            .version(FrameVersion::V2015)
            .header_ie(HeaderIe {
                id: 0x30,
                content: &big
            })
            .build(),
        Err(Error::InvalidArgs)
    );
    // Wake-up requires both addresses.
    assert!(
        FrameBuilder::wakeup(
            &mut buf,
            PAN1,
            Address::None,
            Address::Extended(EXT1),
            0,
            ConnectionIe {
                retry_interval: 0,
                retry_count: 0
            },
            SecurityHeader::new(SecurityLevel::EncMic32, 0, KeyIdentifier::Implicit),
        )
        .build()
        .is_err()
    );
}

// --- Round trips, truncation and fuzzing ----------------------------------------------

/// Exercise every accessor of a parsed frame (must never panic).
fn exercise(f: &Frame<'_>) {
    let _ = f.header();
    let _ = f.payload();
    let _ = f.mic();
    let _ = f.pan_id();
    let _ = f.command();
    let _ = f.csl_ie();
    let _ = f.time_ie();
    let _ = f.connection_ie();
    let _ = f.rendezvous_time_ie();
    let _ = f.is_wakeup_frame();
    let _ = f.find_thread_ie(0);
    for ie in f.header_ies() {
        let _ = ie.map(|i| (i.csl(), i.vendor(), i.rendezvous_time(), i.connection()));
    }
    assert!(f.header_len() <= f.psdu().len());
    assert!(f.payload_range().end <= f.psdu().len());
    assert_eq!(
        f.header().len() + f.payload().len() + f.mic().len(),
        f.psdu().len()
    );
    let _ = Beacon::parse(f.payload());
    let _ = PayloadIeIter::new(f.payload()).count();
}

struct Corpus {
    data: [[u8; 127]; 64],
    lens: [usize; 64],
    n: usize,
}

impl Corpus {
    fn new() -> Self {
        Self {
            data: [[0; 127]; 64],
            lens: [0; 64],
            n: 0,
        }
    }
    fn push(&mut self, b: &[u8]) {
        if self.n < 64 {
            self.data[self.n][..b.len()].copy_from_slice(b);
            self.lens[self.n] = b.len();
            self.n += 1;
        }
    }
}

/// Build one frame for every version x dst mode x src mode x PAN option x
/// security combination, parse it back and compare all fields.
#[test]
fn round_trip_all_addressing_combinations() {
    let modes = [A::N, A::S, A::E];
    let versions = [
        FrameVersion::V2003,
        FrameVersion::V2006,
        FrameVersion::V2015,
    ];
    let pans = [P::No, P::P1, P::P2];
    let levels = [
        None,
        Some((SecurityLevel::EncMic32, KeyIdentifier::Index(1))),
        Some((
            SecurityLevel::Mic128,
            KeyIdentifier::Source4 {
                source: [0xff; 4],
                index: 0xff,
            },
        )),
    ];
    let (mut ok, mut rejected) = (0, 0);
    for ver in versions {
        for dt in modes {
            for st in modes {
                for dp in pans {
                    for sp in pans {
                        for lvl in levels {
                            for suppress in [false, true] {
                                let (src, dst) = (addr(st, SHORT1, EXT1), addr(dt, SHORT2, EXT2));
                                let mut buf = [0u8; 127];
                                let mut b = FrameBuilder::new(&mut buf)
                                    .version(ver)
                                    .sequence(0xa5)
                                    .src(src)
                                    .dst(dst)
                                    .payload(&[1, 2, 3, 4]);
                                if let Some(p) = pan(dp) {
                                    b = b.dst_pan(p);
                                }
                                if let Some(p) = pan(sp) {
                                    b = b.src_pan(p);
                                }
                                if suppress {
                                    b = b.suppress_sequence();
                                }
                                if let Some((l, k)) = lvl {
                                    b = b.security(SecurityHeader::new(l, 0x0102_0304, k));
                                }
                                let len = match b.build() {
                                    Ok(n) => n,
                                    Err(e) => {
                                        // Only legal reasons: missing required PAN ID, or
                                        // seq suppression before 2015.
                                        assert_eq!(e, Error::InvalidArgs);
                                        rejected += 1;
                                        continue;
                                    }
                                };
                                ok += 1;
                                let f = Frame::parse(&buf[..len]).unwrap();
                                exercise(&f);
                                assert_eq!(f.version(), ver);
                                assert_eq!(f.src_address(), src);
                                assert_eq!(f.dst_address(), dst);
                                assert_eq!(f.sequence(), (!suppress).then_some(0xa5));
                                assert_eq!(f.payload(), &[1, 2, 3, 4]);
                                assert_eq!(f.mic_len(), lvl.map_or(0, |(l, _)| l.mic_len()));
                                assert_eq!(
                                    f.security_header().map(|s| (s.level, s.frame_counter)),
                                    lvl.map(|(l, _)| (l, Some(0x0102_0304)))
                                );
                                assert_eq!(f.payload_range().start, f.header_len());
                                // Effective PAN IDs: each address's PAN, as inferred from
                                // the PAN ID fields on air, must equal what was given
                                // (except rows where the encoding drops one of two
                                // different PAN IDs).
                                let both_ext = matches!(dt, A::E) && matches!(st, A::E);
                                if !(ver == FrameVersion::V2015 && both_ext) {
                                    if !dst.is_none() {
                                        assert_eq!(f.dst_pan_id(), pan(dp));
                                    }
                                    if !src.is_none() {
                                        let eff = f.src_pan_id().or(f.dst_pan_id());
                                        let want = if dst.is_none() {
                                            pan(sp)
                                        } else {
                                            pan(sp).or(pan(dp))
                                        };
                                        assert_eq!(eff, want);
                                    }
                                }
                                // Truncated header region is always an error.
                                let min = f.frame_control().addressing_len()
                                    + f.security_header().map_or(0, |s| s.encoded_len());
                                for n in 0..min {
                                    assert_eq!(
                                        Frame::parse(&buf[..n]).unwrap_err(),
                                        Error::Parse,
                                        "prefix {n} of {len}"
                                    );
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    assert!(ok > 500, "ok={ok}");
    assert!(rejected > 0);
}

/// Build into buffers that are one byte too small: always `NoBufs`.
#[test]
fn builder_never_overruns() {
    let mut full = [0u8; 127];
    let make = |buf: &mut [u8]| {
        FrameBuilder::new(buf)
            .version(FrameVersion::V2015)
            .pan_id(PAN1)
            .src(Address::Extended(EXT1))
            .dst(Address::Short(SHORT2))
            .security(SecurityHeader::new(
                SecurityLevel::EncMic32,
                1,
                KeyIdentifier::Index(1),
            ))
            .header_ie(CslIe {
                phase: 1,
                period: 2,
                rendezvous_time: Some(3),
            })
            .payload(&[1, 2, 3])
            .build()
    };
    let n = make(&mut full).unwrap();
    for size in 0..n {
        let mut small = [0u8; 127];
        assert_eq!(make(&mut small[..size]), Err(Error::NoBufs), "size {size}");
    }
    let mut exact = [0u8; 127];
    assert_eq!(make(&mut exact[..n]), Ok(n));
}

struct XorShift(u64);
impl XorShift {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
}

/// Parse every truncation of every valid frame (built corpus plus all
/// OpenThread vectors), bit-flipped variants and random bytes without
/// panicking.
#[test]
fn truncation_and_random_inputs_never_panic() {
    let mut corpus = Corpus::new();
    corpus.push(&WAKEUP_PSDU);
    corpus.push(&[
        0x6b, 0xaa, 0x8d, 0xce, 0xfa, 0x00, 0x68, 0x01, 0x68, 0x0d, 0x08, 0x00, 0x00, 0x00, 0x01,
        0x04, 0x0d, 0xed, 0x0b, 0x35, 0x0c, 0x80, 0x3f, 0x04, 0x4b, 0x88, 0x89, 0xd6,
    ]);
    corpus.push(&[
        0x69, 0xa8, 0x8e, 0xce, 0xfa, 0x02, 0x24, 0x00, 0x24, 0x0d, 0x02, 0x00, 0x00, 0x00, 0x01,
        0x6b, 0x64, 0x60, 0x08, 0x55, 0xb8, 0x10, 0x18, 0xc7, 0x40, 0x2e, 0xfb, 0xf3, 0xda, 0xf9,
        0x4e, 0x58, 0x70,
    ]);
    corpus.push(&[0x02, 0x10, 0x5e]);
    // Frames with many IE kinds and a payload.
    let mut buf = [0u8; 127];
    let n = FrameBuilder::new(&mut buf)
        .version(FrameVersion::V2015)
        .pan_id(PAN1)
        .src(Address::Extended(EXT1))
        .dst(Address::Short(SHORT2))
        .security(SecurityHeader::new(
            SecurityLevel::EncMic64,
            1,
            KeyIdentifier::Source8 {
                source: [1; 8],
                index: 3,
            },
        ))
        .header_ie(CslIe {
            phase: 1,
            period: 2,
            rendezvous_time: Some(3),
        })
        .header_ie(VendorIe::thread_enh_ack_probing(&[1, 2]))
        .header_ie(TimeIe {
            sequence: 1,
            time: 2,
        })
        .payload(&[9; 20])
        .build()
        .unwrap();
    corpus.push(&buf[..n]);

    let mut rng = XorShift(0x1234_5678_9abc_def1);
    for i in 0..corpus.n {
        let len = corpus.lens[i];
        let mut local = [0u8; 127];
        local[..len].copy_from_slice(&corpus.data[i][..len]);
        let v = &local[..len];
        let mut parsed_ok = 0;
        for n in 0..=v.len() {
            if let Ok(f) = Frame::parse(&v[..n]) {
                exercise(&f);
                parsed_ok += 1;
            }
            let _ = Frame::parse_with_fcs(&v[..n]);
            let mut copy = [0u8; 127];
            copy[..n].copy_from_slice(&v[..n]);
            if let Ok(mut m) = FrameMut::new(&mut copy[..n]) {
                let _ = m.set_csl_ie(1, 2);
                let _ = m.set_frame_counter(1);
                let _ = m.set_ack_request(true);
                let _ = m.parts_mut();
            }
        }
        assert!(parsed_ok >= 1, "full frame must parse (corpus {i})");
        // Single-bit flips and byte mutations.
        for bit in 0..v.len() * 8 {
            let mut m = [0u8; 127];
            m[..v.len()].copy_from_slice(v);
            m[bit / 8] ^= 1 << (bit % 8);
            if let Ok(f) = Frame::parse(&m[..v.len()]) {
                exercise(&f);
            }
        }
    }
    for _ in 0..50_000 {
        let mut m = [0u8; 40];
        let len = (rng.next() % 41) as usize;
        for b in m.iter_mut() {
            *b = rng.next() as u8;
        }
        if let Ok(f) = Frame::parse(&m[..len]) {
            exercise(&f);
        }
    }
}

#[test]
fn frame_mut_setters() {
    let mut buf = [0u8; 64];
    let n = FrameBuilder::new(&mut buf)
        .version(FrameVersion::V2015)
        .pan_id(PAN1)
        .src(Address::Short(SHORT1))
        .dst(Address::Short(SHORT2))
        .security(SecurityHeader::new(
            SecurityLevel::EncMic32,
            0,
            KeyIdentifier::Index(1),
        ))
        .payload(&[1])
        .build()
        .unwrap();
    let mut m = FrameMut::new(&mut buf[..n]).unwrap();
    m.set_sequence(200).unwrap();
    m.set_ack_request(false).unwrap();
    m.set_frame_pending(true).unwrap();
    m.set_frame_counter(0x0a0b_0c0d).unwrap();
    assert_eq!(m.set_csl_ie(1, 2), Err(Error::NotFound));
    m.payload_mut().unwrap()[0] = 0x77;
    let f = m.frame().unwrap();
    assert_eq!(f.sequence(), Some(200));
    assert!(!f.ack_request() && f.frame_pending());
    assert_eq!(
        f.security_header().unwrap().frame_counter,
        Some(0x0a0b_0c0d)
    );
    assert_eq!(f.payload(), &[0x77]);
    m.set_ack_request(true).unwrap();
    assert!(m.frame().unwrap().ack_request());

    // Suppressed sequence number / no security: InvalidState.
    let mut b2 = [0u8; 32];
    let n = FrameBuilder::new(&mut b2)
        .version(FrameVersion::V2015)
        .suppress_sequence()
        .dst_pan(PAN1)
        .dst(Address::Short(SHORT1))
        .build()
        .unwrap();
    let mut m = FrameMut::new(&mut b2[..n]).unwrap();
    assert_eq!(m.set_sequence(1), Err(Error::InvalidState));
    assert_eq!(m.set_frame_counter(1), Err(Error::InvalidState));
}

/// Sanity of the `defmt`-gated derives: `Frame` must at least be `Debug`.
#[test]
fn debug_impls() {
    extern crate std;
    let f = Frame::parse(&[0x02, 0x10, 0x5e]).unwrap();
    let s = std::format!("{f:?}");
    assert!(s.contains("Ack"));
}

#[test]
fn max_psdu_frame() {
    // A 127-byte PSDU (incl. FCS) data frame: 125 bytes without FCS.
    let mut buf = [0u8; 127];
    let payload = [0x5a; 100];
    let n = FrameBuilder::new(&mut buf)
        .pan_id(PAN1)
        .src(Address::Short(SHORT1))
        .dst(Address::Short(SHORT2))
        .payload(&payload)
        .build()
        .unwrap();
    assert_eq!(n, 9 + 100);
    assert_eq!(Frame::parse(&buf[..n]).unwrap().payload(), &payload);
}
