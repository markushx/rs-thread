//! Operational Dataset timestamps (OT `meshcop/timestamp.cpp`).
//!
//! The wire type is [`rs_thread_mle::tlv::Timestamp`]; this module adds the
//! ordering OpenThread uses for dataset conflict resolution.

use core::cmp::Ordering;

pub use rs_thread_mle::tlv::Timestamp;

/// OT `Timestamp::Compare`: a present (valid) timestamp is newer than an
/// absent one; then seconds, ticks, and finally the authoritative bit
/// decide. `None` stands for OT's "invalid" timestamp (all ones /
/// not present).
pub fn compare(a: Option<&Timestamp>, b: Option<&Timestamp>) -> Ordering {
    Timestamp::compare(a, b)
}

/// The timestamp of an MLE Orphan Announce (`SetToOrphanAnnounce`):
/// seconds and ticks zero, authoritative flag set.
pub const ORPHAN_ANNOUNCE: Timestamp = Timestamp::ORPHAN_ANNOUNCE;

/// OT `IsOrphanAnnounce`.
pub fn is_orphan_announce(t: &Timestamp) -> bool {
    t.is_orphan_announce()
}

/// Largest tick value (15 bits).
pub const MAX_TICKS: u16 = 0x7fff;

/// OT `AdvanceRandomTicks`: add `1..=MAX_TICKS+1` ticks (`random_ticks` is
/// reduced into that range), carrying into the seconds.
pub fn advance_ticks(t: &mut Timestamp, random_ticks: u32) {
    let add = random_ticks % (u32::from(MAX_TICKS) + 1) + 1;
    let mut ticks = u32::from(t.ticks) + add;
    if ticks > u32::from(MAX_TICKS) {
        ticks -= u32::from(MAX_TICKS) + 1;
        t.seconds += 1;
    }
    t.ticks = ticks as u16;
}
