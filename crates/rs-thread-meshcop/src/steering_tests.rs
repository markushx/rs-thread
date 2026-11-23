use rs_thread_core::crypto::{CryptoBackend, Sha256, SoftCrypto};
use rs_thread_core::types::ExtAddress;

use crate::steering::*;
use crate::timestamp::{self, Timestamp, compare};

const ADDR1: ExtAddress = ExtAddress([0x10, 0x20, 0x03, 0x15, 0x10, 0x00, 0x60, 0x16]);
const ADDR2: ExtAddress = ExtAddress([0xbe, 0xef, 0xca, 0xfe, 0xde, 0xad, 0xba, 0xbe]);

#[test]
fn crc_check_values() {
    assert_eq!(crc16(CRC16_CCITT, b"123456789"), 0x31c3);
    assert_eq!(crc16(CRC16_ANSI, b"123456789"), 0xfee8);
}

/// `TestSteeringData` of `test_meshcop.cpp`.
#[test]
fn steering_data_ot_test() {
    let idx2 = HashBitIndexes::of_joiner_id(&ADDR2);
    let mut s = SteeringData::new(16);
    s.set_permit_all();
    assert_eq!(s.len(), 1);
    assert!(s.permits_all());
    assert!(!s.is_empty());
    assert!(s.contains_joiner_id(&ADDR1));
    assert!(s.contains_joiner_id(&ADDR2));
    assert!(s.contains_indexes(&idx2));

    s.clear();
    assert_eq!(s.len(), 1);
    assert!(!s.permits_all());
    assert!(s.is_empty());
    assert!(!s.contains_joiner_id(&ADDR1));
    assert!(!s.contains_joiner_id(&ADDR2));
    assert!(!s.contains_indexes(&idx2));

    for len in 1..=SteeringData::MAX_LENGTH {
        let mut s = SteeringData::new(len);
        assert_eq!(s.len(), len);
        assert!(s.is_empty());
        assert!(!s.permits_all());
        assert!(!s.contains_joiner_id(&ADDR1));
        assert!(!s.contains_indexes(&idx2));

        s.add_joiner_id(&ADDR1).unwrap();
        assert!(!s.is_empty());
        assert!(s.contains_joiner_id(&ADDR1));

        s.add_joiner_id(&ADDR2).unwrap();
        assert!(s.contains_joiner_id(&ADDR1));
        assert!(s.contains_joiner_id(&ADDR2));
        assert!(s.contains_indexes(&idx2));
    }

    let mut s = SteeringData::new(0);
    assert!(s.is_zero_length());
    assert!(s.is_empty());
    assert!(!s.permits_all());
    assert!(!s.contains_joiner_id(&ADDR1));
    assert!(s.add_joiner_id(&ADDR1).is_err());
}

#[test]
fn bit_order_is_from_the_end() {
    // Bit 0 is the lowest bit of the last byte.
    let mut s = SteeringData::new(2);
    s.update(&HashBitIndexes([0, 9])).unwrap();
    assert_eq!(s.as_bytes(), &[0x02, 0x01]);
}

#[test]
fn discerner() {
    let d = JoinerDiscerner {
        value: 0xabc,
        length: 12,
    };
    assert!(d.is_valid());
    let mut a = ExtAddress([0xff; 8]);
    d.copy_to(&mut a);
    assert_eq!(a.0, [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfa, 0xbc]);
    assert!(d.matches(&a));
    assert!(!d.matches(&ExtAddress([0; 8])));
    let mut s = SteeringData::new(8);
    s.add_discerner(&d).unwrap();
    assert!(s.contains_discerner(&d));
    assert!(
        !JoinerDiscerner {
            value: 1,
            length: 0
        }
        .is_valid()
    );
    assert!(
        JoinerDiscerner {
            value: u64::MAX,
            length: 64
        }
        .matches(&ExtAddress([0xff; 8]))
    );
}

#[test]
fn joiner_id() {
    let id = compute_joiner_id(&SoftCrypto, &ADDR1);
    let mut h = SoftCrypto.sha256();
    h.update(&ADDR1.0);
    let d = h.finalize();
    assert_eq!(&id.0[1..], &d[1..8]);
    assert_eq!(id.0[0], d[0] | 0x02);
}

/// `TestTimestamp` of `test_meshcop.cpp` (comparison part).
#[test]
fn timestamp_compare() {
    use core::cmp::Ordering::*;
    let t1 = Timestamp::default();
    assert_eq!(compare(Some(&t1), Some(&t1)), Equal);
    assert_eq!(compare(None, None), Equal);
    assert_eq!(compare(Some(&t1), None), Greater);
    assert_eq!(compare(None, Some(&t1)), Less);

    let mut t2 = Timestamp {
        seconds: 0x1234_5678_abcd,
        ..Default::default()
    };
    assert_eq!(compare(Some(&t2), Some(&t1)), Greater);
    assert_eq!(compare(Some(&t1), Some(&t2)), Less);
    let t3 = t2;
    t2.authoritative = true;
    assert_eq!(compare(Some(&t2), Some(&t3)), Greater);
    t2.authoritative = false;
    t2.ticks = 0x7fff;
    assert_eq!(compare(Some(&t2), Some(&t3)), Greater);
    assert_eq!(compare(Some(&t3), Some(&t2)), Less);

    let o = Timestamp::default();
    assert!(!timestamp::is_orphan_announce(&o));
    let o = timestamp::ORPHAN_ANNOUNCE;
    assert!(timestamp::is_orphan_announce(&o));
    assert_eq!((o.seconds, o.ticks, o.authoritative), (0, 0, true));

    let mut t = Timestamp {
        seconds: 5,
        ticks: 0x7ffe,
        authoritative: false,
    };
    timestamp::advance_ticks(&mut t, 1);
    assert_eq!((t.seconds, t.ticks), (6, 0));
}
