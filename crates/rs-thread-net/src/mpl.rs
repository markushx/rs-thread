//! Multicast Protocol for Low-Power and Lossy Networks (RFC 7731) as
//! implemented by OpenThread (`net/ip6_mpl.cpp`).
//!
//! # What OpenThread does (and this module mirrors)
//!
//! OpenThread does **not** run RFC 6206 Trickle for MPL data messages. It
//! uses the proactive-forwarding variant with fixed parameters:
//!
//! - a **seed set** of the most recent `(Seed ID, sequence)` pairs
//!   ([`SEED_ENTRIES`] entries, lifetime [`SEED_ENTRY_LIFETIME_TICKS`]
//!   seconds), kept grouped by seed and sorted by sequence, used for
//!   duplicate detection (`UpdateSeedSet`);
//! - a **buffered message set** (FTD only): every fresh MPL message seen by
//!   a router is cloned and retransmitted [`ROUTER_RETRANSMISSIONS`] times
//!   in total (children: 0); the transmission instants are random within
//!   `[0, 64 ms)` windows ([`DATA_MESSAGE_INTERVAL_MS`], see
//!   [`Mpl::poll`]);
//! - the Seed ID is the sender's RLOC16, carried in the MPL option
//!   (`S=1`, 2 bytes), or implicit (`S=0`) when the IPv6 source is the
//!   sender's RLOC.
//!
//! The retransmission scheduling is plain deadlines on [`Instant`]
//! (sans-IO): call [`Mpl::next_deadline`] and [`Mpl::poll`].

use core::net::Ipv6Addr;

use rand_core::Rng;
use rs_thread_core::message::Origin;
use rs_thread_core::time::{Duration, Instant};
use rs_thread_core::types::{Rloc16, ipv6};
use rs_thread_core::{Error, Result};

use crate::header::{MAX_DATAGRAM_LEN, MplOption, MplSeedIdLen, OFFSET_HOP_LIMIT};

/// Number of seed-set entries (OT `OPENTHREAD_CONFIG_MPL_SEED_SET_ENTRIES`).
pub const SEED_ENTRIES: usize = 35;
/// Seed entry lifetime in 1-second ticks (OT `..._SEED_SET_ENTRY_LIFETIME`).
pub const SEED_ENTRY_LIFETIME_TICKS: u8 = 5;
/// Window within which a retransmission is randomised (OT `kDataMessageInterval`).
pub const DATA_MESSAGE_INTERVAL_MS: u8 = 64;
/// Total transmissions of a message by a router (OT `kRouterRetransmissions`).
pub const ROUTER_RETRANSMISSIONS: u8 = 2;
/// Total transmissions of a message by a child (OT `kChildRetransmissions`).
pub const CHILD_RETRANSMISSIONS: u8 = 0;

/// Thread device role, as far as MPL needs it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Role {
    /// Thread disabled.
    Disabled,
    /// Detached.
    Detached,
    /// Child.
    Child,
    /// Router.
    Router,
    /// Leader.
    Leader,
}

impl Role {
    /// OT `Mpl::DetermineMaxRetransmissions`.
    pub const fn max_retransmissions(self) -> u8 {
        match self {
            Role::Disabled | Role::Detached => 0,
            Role::Child => CHILD_RETRANSMISSIONS,
            Role::Router | Role::Leader => ROUTER_RETRANSMISSIONS,
        }
    }

    /// `true` for Router and Leader.
    pub const fn is_router_or_leader(self) -> bool {
        matches!(self, Role::Router | Role::Leader)
    }
}

#[derive(Debug, Clone, Copy, Default)]
struct SeedEntry {
    seed_id: u16,
    sequence: u8,
    /// 0 = unused.
    lifetime: u8,
}

/// RFC 1982 serial-number comparison for 8-bit sequence numbers.
const fn serial_less(a: u8, b: u8) -> bool {
    let d = b.wrapping_sub(a);
    d != 0 && d < 128
}

#[derive(Debug, Clone)]
struct Buffered {
    len: usize,
    data: [u8; MAX_DATAGRAM_LEN],
    transmission_time: Instant,
    transmission_count: u8,
    interval_offset: u8,
}

/// A datagram the MPL layer wants (re)transmitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MplTx {
    /// Length of the datagram written to the output buffer.
    pub len: usize,
    /// `true` for the second and later transmissions (OT sub-type
    /// `MplRetransmission`).
    pub retransmission: bool,
}

/// A datagram carrying an MPL option, as seen by [`Mpl::process_option`].
#[derive(Debug, Clone, Copy)]
pub struct MplRx<'a> {
    /// Where the datagram came from.
    pub origin: Origin,
    /// The IPv6 source address.
    pub src: &'a Ipv6Addr,
    /// The decoded MPL option.
    pub opt: &'a MplOption,
    /// The full IPv6 datagram (copied if it gets buffered).
    pub datagram: &'a [u8],
}

/// MPL state: seed set plus up to `BUFS` buffered messages.
#[derive(Debug, Clone)]
pub struct Mpl<const SEEDS: usize = SEED_ENTRIES, const BUFS: usize = 4> {
    seeds: [SeedEntry; SEEDS],
    sequence: u8,
    bufs: [Option<Buffered>; BUFS],
    next_tick: Option<Instant>,
}

impl<const SEEDS: usize, const BUFS: usize> Default for Mpl<SEEDS, BUFS> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const SEEDS: usize, const BUFS: usize> Mpl<SEEDS, BUFS> {
    /// Empty state.
    pub const fn new() -> Self {
        Self {
            seeds: [SeedEntry {
                seed_id: 0,
                sequence: 0,
                lifetime: 0,
            }; SEEDS],
            sequence: 0,
            bufs: [const { None }; BUFS],
            next_tick: None,
        }
    }

    /// Create the MPL option for a datagram we originate (OT `InitOption`):
    /// `S=0` if `src` is our RLOC, else `S=1` with our RLOC16 as Seed ID.
    /// Consumes one sequence number.
    pub fn init_option(
        &mut self,
        src: &Ipv6Addr,
        own_rloc: &Ipv6Addr,
        rloc16: Rloc16,
    ) -> MplOption {
        let s0 = src == own_rloc;
        let o = MplOption {
            seed_id_len: if s0 {
                MplSeedIdLen::Zero
            } else {
                MplSeedIdLen::Two
            },
            max: false,
            sequence: self.sequence,
            seed_id: if s0 { 0 } else { rloc16.0 },
        };
        self.sequence = self.sequence.wrapping_add(1);
        o
    }

    /// Seed-set update (OT `Mpl::UpdateSeedSet`, ported entry for entry).
    /// [`Error::Drop`] for a duplicate or a too-old sequence.
    fn update_seed_set(&mut self, seed_id: u16, sequence: u8, now: Instant) -> Result<()> {
        let n = SEEDS;
        let mut insert: Option<usize> = None;
        let mut group = 0usize;
        let mut evict = 0usize;
        let mut cur = 0u8;
        let mut max = 0u8;
        let mut i = 0;
        while i < n {
            if self.seeds[i].lifetime == 0 {
                if insert.is_none() {
                    insert = Some(i);
                }
                evict = i;
                break;
            }
            if self.seeds[i].seed_id != self.seeds[group].seed_id {
                if seed_id == self.seeds[group].seed_id && insert.is_none() {
                    insert = Some(i);
                    cur += 1;
                }
                if max < cur {
                    evict = group;
                    max = cur;
                }
                group = i;
                cur = 0;
            }
            if seed_id == self.seeds[i].seed_id {
                if sequence == self.seeds[i].sequence {
                    self.seeds[i].lifetime = SEED_ENTRY_LIFETIME_TICKS;
                    return Err(Error::Drop);
                } else if insert.is_none() && serial_less(sequence, self.seeds[i].sequence) {
                    insert = Some(i);
                    cur += 1;
                }
            }
            i += 1;
            cur += 1;
        }
        if n == 0 {
            return Err(Error::Drop);
        }

        if self.seeds[evict].lifetime != 0 {
            if seed_id == self.seeds[group].seed_id && insert.is_none() {
                insert = Some(n);
                cur += 1;
            }
            if max < cur {
                evict = group;
                max = cur;
            }
            if max <= 1 {
                return Err(Error::Drop);
            }
            match insert {
                None => insert = Some(evict),
                Some(ins) => {
                    if !(ins > 0 && seed_id == self.seeds[ins - 1].seed_id) {
                        return Err(Error::Drop);
                    }
                }
            }
        }
        let mut insert = insert.ok_or(Error::Drop)?;
        if evict > insert {
            self.seeds.copy_within(insert..evict, insert + 1);
        } else if evict < insert {
            self.seeds.copy_within(evict + 1..insert, evict);
            insert -= 1;
        }
        self.seeds[insert] = SeedEntry {
            seed_id,
            sequence,
            lifetime: SEED_ENTRY_LIFETIME_TICKS,
        };
        if self.next_tick.is_none() {
            self.next_tick = Some(now.saturating_add(Duration::from_secs(1)));
        }
        Ok(())
    }

    fn tick_seeds(&mut self) -> bool {
        let mut j = 0;
        let mut live = false;
        for i in 0..SEEDS {
            if self.seeds[i].lifetime == 0 {
                break;
            }
            self.seeds[i].lifetime -= 1;
            if self.seeds[i].lifetime > 0 {
                self.seeds[j] = self.seeds[i];
                j += 1;
                live = true;
            }
        }
        for s in &mut self.seeds[j..] {
            s.lifetime = 0;
        }
        live
    }

    /// Number of seed-set entries in use.
    pub fn seed_count(&self) -> usize {
        self.seeds.iter().filter(|s| s.lifetime != 0).count()
    }

    /// Number of buffered messages awaiting retransmission.
    pub fn buffered_count(&self) -> usize {
        self.bufs.iter().flatten().count()
    }

    /// Process the MPL option of a received (or locally originated)
    /// datagram (OT `Mpl::ProcessOption`).
    ///
    /// Returns `Ok(true)` if the datagram is fresh, `Ok(false)` if it is a
    /// duplicate that did not come from the Thread network (it must not be
    /// received locally but may still be forwarded), and
    /// [`Error::Drop`] for a duplicate from the Thread network.
    /// [`Error::Parse`] for unsupported Seed ID lengths.
    ///
    /// Fresh datagrams are buffered for retransmission when the role allows
    /// it. `datagram` is the full IPv6 datagram.
    pub fn process_option<R: Rng + ?Sized>(
        &mut self,
        now: Instant,
        rng: &mut R,
        role: Role,
        rx: &MplRx<'_>,
    ) -> Result<bool> {
        let (seed_id, sequence) = match rx.opt.seed_id_len {
            MplSeedIdLen::Zero => {
                let iid = ipv6::iid(rx.src);
                (iid.locator().ok_or(Error::Drop)?, rx.opt.sequence)
            }
            MplSeedIdLen::Two => (rx.opt.seed_id, rx.opt.sequence),
            _ => return Err(Error::Parse),
        };
        match self.update_seed_set(seed_id, sequence, now) {
            Ok(()) => {
                self.add_buffered(now, rng, role, rx.origin, rx.datagram);
                Ok(true)
            }
            Err(_) if rx.origin != Origin::ThreadNetif => Ok(false),
            Err(e) => Err(e),
        }
    }

    fn add_buffered<R: Rng + ?Sized>(
        &mut self,
        now: Instant,
        rng: &mut R,
        role: Role,
        origin: Origin,
        datagram: &[u8],
    ) {
        if role.max_retransmissions() == 0 || datagram.len() > MAX_DATAGRAM_LEN {
            return;
        }
        let Some(slot) = self.bufs.iter_mut().find(|b| b.is_none()) else {
            return;
        };
        let mut data = [0u8; MAX_DATAGRAM_LEN];
        data[..datagram.len()].copy_from_slice(datagram);
        let from_thread = origin == Origin::ThreadNetif;
        if from_thread {
            let hl = data[OFFSET_HOP_LIMIT];
            if hl <= 1 {
                return;
            }
            data[OFFSET_HOP_LIMIT] = hl - 1;
        }
        let mut b = Buffered {
            len: datagram.len(),
            data,
            transmission_time: now,
            transmission_count: u8::from(!from_thread),
            interval_offset: 0,
        };
        generate_next_time(&mut b, now, DATA_MESSAGE_INTERVAL_MS, rng);
        *slot = Some(b);
    }

    /// The next instant at which [`Self::poll`] has work (seed tick or
    /// retransmission).
    pub fn next_deadline(&self) -> Option<Instant> {
        let retx = self
            .bufs
            .iter()
            .flatten()
            .map(|b| b.transmission_time)
            .min();
        match (self.next_tick, retx) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        }
    }

    /// Advance timers to `now` and return the next datagram to transmit, if
    /// any (call repeatedly until `None`). The datagram is written to `out`
    /// and must be handed to the forwarding path with origin "host
    /// trusted" (OT `Ip6::EnqueueDatagram`): the MPL option is already in
    /// place and the seed set already knows it, so it is forwarded without
    /// being received locally again.
    pub fn poll<R: Rng + ?Sized>(
        &mut self,
        now: Instant,
        rng: &mut R,
        role: Role,
        out: &mut [u8],
    ) -> Option<MplTx> {
        while let Some(t) = self.next_tick
            && t <= now
        {
            self.next_tick = if self.tick_seeds() {
                Some(t.saturating_add(Duration::from_secs(1)))
            } else {
                None
            };
        }
        let max_retx = role.max_retransmissions();
        for slot in &mut self.bufs {
            let Some(b) = slot else { continue };
            if now < b.transmission_time {
                continue;
            }
            b.transmission_count += 1;
            if b.transmission_count > max_retx {
                *slot = None;
                continue;
            }
            let retransmission = b.transmission_count > 1;
            if out.len() < b.len {
                // Output too small: keep the message for a later attempt.
                b.transmission_count -= 1;
                return None;
            }
            out[..b.len].copy_from_slice(&b.data[..b.len]);
            let len = b.len;
            if b.transmission_count < max_retx {
                generate_next_time(b, now, DATA_MESSAGE_INTERVAL_MS, rng);
            } else {
                *slot = None;
            }
            return Some(MplTx {
                len,
                retransmission,
            });
        }
        None
    }
}

/// OT `Metadata::GenerateNextTransmissionTime`: `t` uniform in
/// `[0, interval)`; next time `= now + offset + t`; `offset = interval - t`.
fn generate_next_time<R: Rng + ?Sized>(b: &mut Buffered, now: Instant, interval: u8, rng: &mut R) {
    let t = if interval == 0 {
        0
    } else {
        (rng.next_u32() % u32::from(interval)) as u8
    };
    b.transmission_time = now.saturating_add(Duration::from_millis(
        u64::from(b.interval_offset) + u64::from(t),
    ));
    b.interval_offset = interval - t;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec::Vec;

    /// Deterministic RNG returning a scripted sequence (cycling).
    struct Script(Vec<u32>, usize);
    impl rand_core::TryRng for Script {
        type Error = core::convert::Infallible;
        fn try_next_u32(&mut self) -> core::result::Result<u32, Self::Error> {
            let v = self.0[self.1 % self.0.len()];
            self.1 += 1;
            Ok(v)
        }
        fn try_next_u64(&mut self) -> core::result::Result<u64, Self::Error> {
            Ok(u64::from(self.try_next_u32()?))
        }
        fn try_fill_bytes(&mut self, d: &mut [u8]) -> core::result::Result<(), Self::Error> {
            d.fill(0);
            Ok(())
        }
    }

    fn src(n: u16) -> Ipv6Addr {
        ipv6::LINK_LOCAL_PREFIX.with_iid(&rs_thread_core::types::Iid::from_locator(n))
    }

    fn opt(seed: u16, seq: u8) -> MplOption {
        MplOption {
            seed_id_len: MplSeedIdLen::Two,
            max: false,
            sequence: seq,
            seed_id: seed,
        }
    }

    fn dgram() -> [u8; 60] {
        let mut d = [0u8; 60];
        d[0] = 0x60;
        d[OFFSET_HOP_LIMIT] = 32;
        d[5] = 20;
        d
    }

    #[allow(clippy::too_many_arguments)]
    fn rx<const S: usize, const B: usize, R: Rng + ?Sized>(
        m: &mut Mpl<S, B>,
        now: Instant,
        rng: &mut R,
        role: Role,
        origin: Origin,
        opt: &MplOption,
        src: &Ipv6Addr,
        datagram: &[u8],
    ) -> Result<bool> {
        m.process_option(
            now,
            rng,
            role,
            &MplRx {
                origin,
                src,
                opt,
                datagram,
            },
        )
    }

    fn feed<const S: usize>(m: &mut Mpl<S, 4>, seed: u16, seq: u8, origin: Origin) -> Result<bool> {
        let mut rng = Script(std::vec![0], 0);
        rx(
            m,
            Instant::ZERO,
            &mut rng,
            Role::Child,
            origin,
            &opt(seed, seq),
            &src(seed),
            &dgram(),
        )
    }

    #[test]
    fn duplicates_are_detected() {
        let mut m = Mpl::<35, 4>::new();
        assert_eq!(feed(&mut m, 0x400, 1, Origin::ThreadNetif), Ok(true));
        assert_eq!(
            feed(&mut m, 0x400, 1, Origin::ThreadNetif),
            Err(Error::Drop)
        );
        // Duplicate from the host: no error, but must not be received.
        assert_eq!(feed(&mut m, 0x400, 1, Origin::HostTrusted), Ok(false));
        assert_eq!(feed(&mut m, 0x400, 2, Origin::ThreadNetif), Ok(true));
        assert_eq!(feed(&mut m, 0x800, 1, Origin::ThreadNetif), Ok(true));
        assert_eq!(m.seed_count(), 3);
    }

    #[test]
    fn seed_entries_expire_after_lifetime() {
        let mut m = Mpl::<35, 4>::new();
        feed(&mut m, 0x400, 1, Origin::ThreadNetif).unwrap();
        let mut rng = Script(std::vec![0], 0);
        let mut out = [0u8; 1280];
        // 4 ticks: still there (lifetime 5), refreshing on duplicates resets.
        for s in 1..=4 {
            m.poll(Instant::from_secs(s), &mut rng, Role::Child, &mut out);
        }
        assert_eq!(m.seed_count(), 1);
        assert_eq!(
            feed(&mut m, 0x400, 1, Origin::ThreadNetif),
            Err(Error::Drop)
        );
        for s in 5..=8 {
            m.poll(Instant::from_secs(s), &mut rng, Role::Child, &mut out);
        }
        assert_eq!(m.seed_count(), 1);
        m.poll(Instant::from_secs(9), &mut rng, Role::Child, &mut out);
        assert_eq!(m.seed_count(), 0);
        assert_eq!(m.next_deadline(), None);
        assert_eq!(feed(&mut m, 0x400, 1, Origin::ThreadNetif), Ok(true));
    }

    #[test]
    fn full_seed_set_eviction() {
        // Capacity 3: groups are evicted from the largest group only when it
        // has at least two entries (OT UpdateSeedSet rules).
        let mut m = Mpl::<3, 4>::new();
        assert_eq!(feed(&mut m, 1, 10, Origin::ThreadNetif), Ok(true));
        assert_eq!(feed(&mut m, 2, 10, Origin::ThreadNetif), Ok(true));
        assert_eq!(feed(&mut m, 3, 10, Origin::ThreadNetif), Ok(true));
        // All groups have a single entry: a new seed cannot evict.
        assert_eq!(feed(&mut m, 4, 10, Origin::ThreadNetif), Err(Error::Drop));
        // A new sequence for an existing seed evicts that seed's oldest entry
        // (the group would have two entries after the insert) ...
        assert_eq!(feed(&mut m, 1, 11, Origin::ThreadNetif), Ok(true));
        // ... after which the evicted, older sequence is rejected as too old.
        assert_eq!(feed(&mut m, 1, 10, Origin::ThreadNetif), Err(Error::Drop));
        assert_eq!(feed(&mut m, 1, 11, Origin::ThreadNetif), Err(Error::Drop));
    }

    #[test]
    fn sequence_ordering_within_group() {
        let mut m = Mpl::<35, 4>::new();
        for seq in [5u8, 7, 6, 4] {
            assert_eq!(feed(&mut m, 9, seq, Origin::ThreadNetif), Ok(true));
        }
        for seq in [4u8, 5, 6, 7] {
            assert_eq!(feed(&mut m, 9, seq, Origin::ThreadNetif), Err(Error::Drop));
        }
        // Wrap-around: 255 then 0.
        assert_eq!(feed(&mut m, 10, 255, Origin::ThreadNetif), Ok(true));
        assert_eq!(feed(&mut m, 10, 0, Origin::ThreadNetif), Ok(true));
        assert_eq!(feed(&mut m, 10, 255, Origin::ThreadNetif), Err(Error::Drop));
    }

    #[test]
    fn serial_numbers() {
        assert!(serial_less(1, 2));
        assert!(!serial_less(2, 1));
        assert!(!serial_less(3, 3));
        assert!(serial_less(250, 3));
        assert!(!serial_less(3, 250));
        assert!(!serial_less(0, 128));
        assert!(serial_less(0, 127));
    }

    /// OpenThread `tests/unit/test_serial_number.cpp` `TestSerialNumber<uint8_t>`.
    #[test]
    fn test_serial_number_u8() {
        let max = u8::MAX;
        let mid = max / 2;
        let numbers = [0, 1, 20, mid - 1, mid, mid + 1, max - 20, max - 1, max];
        for n in numbers {
            let is_greater = |a: u8, b: u8| serial_less(b, a);
            assert!(!is_greater(n, n));
            assert!(!serial_less(n, n));
            assert!(is_greater(n.wrapping_add(1), n));
            assert!(is_greater(n.wrapping_add(mid - 1), n));
            assert!(is_greater(n.wrapping_add(mid), n));
            assert!(!is_greater(n.wrapping_add(mid + 2), n));
            assert!(!is_greater(n.wrapping_add(max - 1), n));
            assert!(serial_less(n.wrapping_sub(1), n));
            assert!(serial_less(n.wrapping_sub(mid - 1), n));
            assert!(serial_less(n.wrapping_sub(mid), n));
            assert!(!serial_less(n.wrapping_sub(mid + 2), n));
            assert!(!serial_less(n.wrapping_sub(max - 1), n));
        }
    }

    #[test]
    fn s0_option_requires_locator_source() {
        let mut m = Mpl::<35, 4>::new();
        let o = MplOption {
            seed_id_len: MplSeedIdLen::Zero,
            max: false,
            sequence: 3,
            seed_id: 0,
        };
        let mut rng = Script(std::vec![0], 0);
        let non_locator: Ipv6Addr = "fe80::1".parse().unwrap();
        assert_eq!(
            rx(
                &mut m,
                Instant::ZERO,
                &mut rng,
                Role::Child,
                Origin::ThreadNetif,
                &o,
                &non_locator,
                &dgram()
            ),
            Err(Error::Drop)
        );
        assert_eq!(
            rx(
                &mut m,
                Instant::ZERO,
                &mut rng,
                Role::Child,
                Origin::ThreadNetif,
                &o,
                &src(0x1c00),
                &dgram()
            ),
            Ok(true)
        );
        // Same seed via the S=1 form is a duplicate.
        assert_eq!(
            feed(&mut m, 0x1c00, 3, Origin::ThreadNetif),
            Err(Error::Drop)
        );
        let big = MplOption {
            seed_id_len: MplSeedIdLen::Eight,
            ..o
        };
        assert_eq!(
            rx(
                &mut m,
                Instant::ZERO,
                &mut rng,
                Role::Child,
                Origin::ThreadNetif,
                &big,
                &src(1),
                &dgram()
            ),
            Err(Error::Parse)
        );
    }

    #[test]
    fn init_option_sequence_and_seed() {
        let mut m = Mpl::<35, 4>::new();
        let rloc = src(0x0800);
        let a = m.init_option(&rloc, &rloc, Rloc16(0x0800));
        assert_eq!((a.seed_id_len, a.sequence), (MplSeedIdLen::Zero, 0));
        let eid: Ipv6Addr = "fd00::1".parse().unwrap();
        let b = m.init_option(&eid, &rloc, Rloc16(0x0800));
        assert_eq!(
            (b.seed_id_len, b.sequence, b.seed_id),
            (MplSeedIdLen::Two, 1, 0x0800)
        );
    }

    #[test]
    fn router_retransmission_schedule() {
        // Thread-origin message at a router: hop limit decremented in the
        // copy, 0 transmissions so far, so transmissions 1 (retx=false) and
        // 2 (retx=true) are sent, at deterministic times.
        let mut m = Mpl::<35, 4>::new();
        // Script: first draw (initial time) = 10 -> t=10 ms; second draw
        // after first tx = 20 -> offset(54)+20 = 74 ms later.
        let mut rng = Script(std::vec![10, 20], 0);
        let t0 = Instant::from_millis(1000);
        rx(
            &mut m,
            t0,
            &mut rng,
            Role::Router,
            Origin::ThreadNetif,
            &opt(0x400, 1),
            &src(0x400),
            &dgram(),
        )
        .unwrap();
        assert_eq!(m.buffered_count(), 1);
        assert_eq!(
            m.next_deadline(),
            Some(t0.saturating_add(Duration::from_millis(10)))
        );
        let mut out = [0u8; 1280];
        assert_eq!(
            m.poll(
                t0.saturating_add(Duration::from_millis(9)),
                &mut rng,
                Role::Router,
                &mut out
            ),
            None
        );
        let t1 = t0.saturating_add(Duration::from_millis(10));
        let tx = m.poll(t1, &mut rng, Role::Router, &mut out).unwrap();
        assert_eq!(
            tx,
            MplTx {
                len: 60,
                retransmission: false
            }
        );
        assert_eq!(out[OFFSET_HOP_LIMIT], 31);
        // Next: offset = 64-10 = 54, t = 20 -> 74 ms after t1.
        let t2 = t1.saturating_add(Duration::from_millis(74));
        assert_eq!(m.next_deadline(), Some(t2));
        assert_eq!(
            m.poll(
                t2.saturating_sub(Duration::from_millis(1)),
                &mut rng,
                Role::Router,
                &mut out
            ),
            None
        );
        let tx = m.poll(t2, &mut rng, Role::Router, &mut out).unwrap();
        assert!(tx.retransmission);
        assert_eq!(m.buffered_count(), 0);
        assert_eq!(m.poll(t2, &mut rng, Role::Router, &mut out), None);
    }

    #[test]
    fn host_origin_counts_first_transmission_and_children_do_not_buffer() {
        let mut m = Mpl::<35, 4>::new();
        let mut rng = Script(std::vec![0], 0);
        let t0 = Instant::ZERO;
        rx(
            &mut m,
            t0,
            &mut rng,
            Role::Child,
            Origin::HostTrusted,
            &opt(1, 1),
            &src(1),
            &dgram(),
        )
        .unwrap();
        assert_eq!(m.buffered_count(), 0);
        // Router, locally originated: already sent once -> one retransmission.
        rx(
            &mut m,
            t0,
            &mut rng,
            Role::Router,
            Origin::HostTrusted,
            &opt(1, 2),
            &src(1),
            &dgram(),
        )
        .unwrap();
        assert_eq!(m.buffered_count(), 1);
        let mut out = [0u8; 1280];
        let tx = m.poll(t0, &mut rng, Role::Router, &mut out).unwrap();
        assert!(tx.retransmission);
        // Hop limit untouched for host origin.
        assert_eq!(out[OFFSET_HOP_LIMIT], 32);
        assert_eq!(m.buffered_count(), 0);
    }

    #[test]
    fn hop_limit_one_is_not_buffered_and_role_loss_cancels() {
        let mut m = Mpl::<35, 4>::new();
        let mut rng = Script(std::vec![0], 0);
        let mut d = dgram();
        d[OFFSET_HOP_LIMIT] = 1;
        rx(
            &mut m,
            Instant::ZERO,
            &mut rng,
            Role::Router,
            Origin::ThreadNetif,
            &opt(1, 1),
            &src(1),
            &d,
        )
        .unwrap();
        assert_eq!(m.buffered_count(), 0);
        rx(
            &mut m,
            Instant::ZERO,
            &mut rng,
            Role::Router,
            Origin::ThreadNetif,
            &opt(1, 2),
            &src(1),
            &dgram(),
        )
        .unwrap();
        assert_eq!(m.buffered_count(), 1);
        // Demoted to child: buffered message is dropped at its deadline.
        let mut out = [0u8; 1280];
        assert_eq!(
            m.poll(Instant::from_millis(100), &mut rng, Role::Child, &mut out),
            None
        );
        assert_eq!(m.buffered_count(), 0);
    }

    #[test]
    fn buffer_pool_exhaustion_is_graceful() {
        let mut m = Mpl::<35, 2>::new();
        let mut rng = Script(std::vec![0], 0);
        for s in 0..5u8 {
            rx(
                &mut m,
                Instant::ZERO,
                &mut rng,
                Role::Router,
                Origin::ThreadNetif,
                &opt(1, s),
                &src(1),
                &dgram(),
            )
            .unwrap();
        }
        assert_eq!(m.buffered_count(), 2);
    }
}
