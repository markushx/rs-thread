//! Ports of OpenThread `tests/unit/test_link_quality.cpp`.

use super::*;

const NOISE_FLOOR: i8 = -100;

/// OT `VerifyRawRssValue`.
fn verify_raw(a: &RssAverager) {
    if a.has_average() {
        assert_eq!(
            a.average() as i16,
            -(((a.raw() + 4) >> 3) as i16),
            "raw value does not match the average"
        );
    } else {
        assert_eq!(a.raw(), 0);
        assert_eq!(a.average(), INVALID_RSSI);
    }
}

// OT TestLinkQualityData / TestLinkQualityCalculations.
fn link_quality_data(list: &[i8], expected: u8) {
    let mut info = LinkQualityInfo::new();
    let (mut min, mut max) = (-128i8, 0i8);
    for &rss in list {
        min = min.min(rss);
        max = max.max(rss);
        info.add_rss(NOISE_FLOOR, rss);
        assert_eq!(info.last_rss(), rss);
        let ave = info.average_rss();
        assert!(ave >= min && ave <= max);
        assert_eq!(ave as i16, -(((info.average_rss_raw() + 4) >> 3) as i16));
    }
    assert_eq!(info.link_quality_in().as_u8(), expected);
}

#[test]
fn link_quality_calculations() {
    link_quality_data(
        &[-81, -80, -79, -78, -76, -80, -77, -75, -77, -76, -77, -74],
        3,
    );
    link_quality_data(&[-90, -80, -85], 2);
    link_quality_data(
        &[
            -95, -96, -98, -99, -100, -100, -98, -99, -100, -100, -100, -100, -100,
        ],
        0,
    );
    link_quality_data(
        &[
            -75, -100, -100, -100, -100, -100, -95, -92, -93, -94, -93, -93,
        ],
        1,
    );
}

const RSS_VALUES: [i8; 6] = [-128, -70, -40, -41, -10, 0];

fn lcg(state: &mut u32) -> u32 {
    *state = state.wrapping_mul(1664525).wrapping_add(1013904223);
    *state >> 8
}

#[test]
fn rss_averaging() {
    let mut a = RssAverager::new();
    // After clear.
    assert_eq!(a.average(), INVALID_RSSI);
    verify_raw(&a);
    // Single value.
    assert!(a.add(-70));
    assert_eq!(a.average(), -70);
    verify_raw(&a);
    a.clear();
    assert_eq!(a.average(), INVALID_RSSI);
    verify_raw(&a);

    // Same value many times.
    for &rss in &RSS_VALUES {
        a.clear();
        for _ in 0..300 {
            a.add(rss);
            assert_eq!(a.average(), rss);
            verify_raw(&a);
        }
    }

    // Two values: arithmetic mean (floor via >> 1).
    for &r1 in &RSS_VALUES {
        for &r2 in &RSS_VALUES {
            if r1 == r2 {
                continue;
            }
            a.clear();
            a.add(r1);
            a.add(r2);
            assert_eq!(
                a.average(),
                ((r1 as i16 + r2 as i16) >> 1) as i8,
                "{r1} {r2}"
            );
            verify_raw(&a);
        }
    }

    // One value many times and a different value once.
    for &r1 in &RSS_VALUES {
        for &r2 in &RSS_VALUES {
            if r1 == r2 {
                continue;
            }
            a.clear();
            for _ in 0..300 {
                a.add(r1);
            }
            a.add(r2);
            let ave = a.average();
            assert!(ave >= r1.min(r2) && ave <= r1.max(r2));
            verify_raw(&a);
        }
    }

    // Two alternating values.
    for &r1 in &RSS_VALUES {
        for &r2 in &RSS_VALUES {
            if r1 == r2 {
                continue;
            }
            a.clear();
            for _ in 0..300 {
                a.add(r1);
                a.add(r2);
                let ave = a.average() as i16;
                assert!(ave >= r1.min(r2) as i16 && ave <= r1.max(r2) as i16);
                let diff = ave - ((r1 as i16 + r2 as i16) >> 1);
                assert!(diff.abs() <= 16, "GetAverage() is incorrect");
                verify_raw(&a);
            }
        }
    }

    // For the first 8 values the average is the arithmetic mean.
    let mut st = 1u32;
    for _ in 0..1000 {
        a.clear();
        let mut sum = 0i32;
        for j in 1..=8 {
            let rss = -((lcg(&mut st) % 128) as i8);
            a.add(rss);
            sum += rss as i32;
            let mean = sum as f64 / j as f64;
            assert!((a.average() as f64 - mean).abs() < 1.0);
            verify_raw(&a);
        }
    }

    // Invalid RSSI is rejected.
    a.clear();
    assert!(!a.add(INVALID_RSSI));
    assert!(!a.has_average());
}

#[test]
fn success_rate_tracker() {
    const MAX_SAMPLES: u16 = 5000;
    let max_rate = SuccessRateTracker::MAX_RATE;
    let mut t = SuccessRateTracker::new();
    assert_eq!(t.success_rate(), max_rate);
    assert_eq!(t.failure_rate(), 0);

    for n in 1..MAX_SAMPLES {
        t.add_sample(true, n);
        assert_eq!(t.success_rate(), max_rate);
        assert_eq!(t.failure_rate(), 0);
    }
    t.clear();
    assert_eq!(t.success_rate(), max_rate);
    for n in 1..max_rate {
        t.add_sample(false, n);
        assert_eq!(t.success_rate(), 0);
        assert_eq!(t.failure_rate(), max_rate);
    }

    const WEIGHT_LIMIT: [u16; 7] = [64, 128, 256, 300, 512, 810, 900];
    for round in 0..WEIGHT_LIMIT.len() * 2 {
        let reverse = round % 2 == 0;
        let weight_limit = WEIGHT_LIMIT[round / 2];
        for period in 1..101u16 {
            let mut failures = 0u32;
            t.clear();
            for n in 1..MAX_SAMPLES {
                let mut success = n % period == 0;
                if reverse {
                    success = !success;
                }
                t.add_sample(success, n.min(weight_limit));
                if !success {
                    failures += 1;
                }
                let rate = f64::from(t.failure_rate()) * 100.0 / f64::from(max_rate);
                let expected = f64::from(failures) * 100.0 / f64::from(n);
                assert!(
                    (rate - expected).abs() <= 1.0,
                    "round {round} period {period} n {n}: {rate} vs {expected}"
                );
            }
        }
    }
}

#[test]
fn margin_to_quality_and_cost() {
    use LinkQuality::*;
    // Thresholds without history: > 2, > 10, > 20.
    for (margin, q) in [
        (0, Q0),
        (2, Q0),
        (3, Q1),
        (10, Q1),
        (11, Q2),
        (20, Q2),
        (21, Q3),
        (255, Q3),
    ] {
        assert_eq!(LinkQuality::for_margin(margin), q, "margin {margin}");
    }
    // Hysteresis: +2 dB to move up from the previous class.
    assert_eq!(LinkQuality::from_margin(21, Some(Q2)), Q2);
    assert_eq!(LinkQuality::from_margin(23, Some(Q2)), Q3);
    assert_eq!(LinkQuality::from_margin(21, Some(Q3)), Q3);
    assert_eq!(LinkQuality::from_margin(11, Some(Q1)), Q1);
    assert_eq!(LinkQuality::from_margin(13, Some(Q1)), Q2);
    assert_eq!(LinkQuality::from_margin(3, Some(Q0)), Q0);
    assert_eq!(LinkQuality::from_margin(5, Some(Q0)), Q1);
    // From Q0 the top thresholds are also raised by 2 (fall-through).
    assert_eq!(LinkQuality::from_margin(21, Some(Q0)), Q2);
    // Costs.
    assert_eq!([Q0, Q1, Q2, Q3].map(LinkQuality::cost), [16, 4, 2, 1]);
    // Typical RSS maps back into the same class.
    for q in [Q1, Q2, Q3] {
        let rss = q.typical_rss(-95);
        assert_eq!(LinkQuality::for_margin(compute_link_margin(-95, rss)), q);
    }
    assert_eq!(compute_link_margin(-100, -110), 0);
    assert_eq!(compute_link_margin(-100, INVALID_RSSI), 0);
    assert_eq!(compute_link_margin(-100, -70), 30);
    assert_eq!(compute_link_margin(-128, 126), 254);
}

#[test]
fn lqi_averager() {
    let mut a = LqiAverager::new();
    for _ in 0..300 {
        a.add(200);
        assert_eq!(a.average(), 200);
    }
    assert_eq!(a.count(), 255);
    a.clear();
    a.add(10);
    a.add(20);
    assert_eq!(a.average(), 15);
}

#[test]
fn info_two_way() {
    let mut i = LinkQualityInfo::new();
    assert_eq!(i.last_rss(), INVALID_RSSI);
    i.add_rss(NOISE_FLOOR, INVALID_RSSI);
    assert_eq!(i.last_rss(), INVALID_RSSI);
    i.add_rss(NOISE_FLOOR, -60);
    assert_eq!(i.link_quality_in(), LinkQuality::Q3);
    i.set_link_quality_out(LinkQuality::Q1);
    assert_eq!(i.two_way_quality(), LinkQuality::Q1);
    i.clear();
    assert_eq!(i.link_quality_in(), LinkQuality::Q0);
}
