//! Differential tests: the same inputs go to OpenThread (through the C++ shim
//! in `tools/openthread-sys/shim/diff_shim.cpp`) and to OpenTrust, and the
//! outputs are compared.
//!
//! Run with `cargo test -p opentrust-difftest --features ot` (needs cmake,
//! ninja and the OpenThread sources, see `openthread-sys`). Without the `ot`
//! feature every test passes after printing "skipped". The number of random
//! cases per test is `OPENTRUST_DIFF_CASES` (default 2000).

// Keeps `openthread-sys` (and with it the link flags of OpenThread and the
// shim) in the final link.
#[cfg(feature = "ot")]
use openthread_sys as _;

#[cfg(feature = "ot")]
pub mod ffi;

/// A small deterministic generator (SplitMix64) so failures reproduce.
#[derive(Debug, Clone)]
pub struct Rng(u64);

impl Rng {
    pub const fn new(seed: u64) -> Self {
        Self(seed)
    }

    pub fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    pub fn u32(&mut self) -> u32 {
        (self.next_u64() >> 32) as u32
    }

    pub fn u8(&mut self) -> u8 {
        (self.next_u64() >> 56) as u8
    }

    pub fn u16(&mut self) -> u16 {
        (self.next_u64() >> 48) as u16
    }

    /// Uniform in `0..n` (`n > 0`).
    pub fn below(&mut self, n: usize) -> usize {
        (self.next_u64() % n as u64) as usize
    }

    pub fn chance(&mut self, num: u32, den: u32) -> bool {
        self.u32() % den < num
    }

    pub fn fill(&mut self, buf: &mut [u8]) {
        for b in buf {
            *b = self.u8();
        }
    }

    pub fn bytes<const N: usize>(&mut self) -> [u8; N] {
        let mut b = [0u8; N];
        self.fill(&mut b);
        b
    }

    pub fn vec(&mut self, len: usize) -> Vec<u8> {
        let mut v = vec![0u8; len];
        self.fill(&mut v);
        v
    }

    /// Random bytes, length uniform in `0..n`.
    pub fn vec_below(&mut self, n: usize) -> Vec<u8> {
        let len = self.below(n);
        self.vec(len)
    }

    /// Random bytes, length `base + (0..n)`.
    pub fn vec_range(&mut self, base: usize, n: usize) -> Vec<u8> {
        let len = base + self.below(n);
        self.vec(len)
    }

    pub fn pick<'a, T>(&mut self, items: &'a [T]) -> &'a T {
        &items[self.below(items.len())]
    }
}

/// Number of random cases per test: `OPENTRUST_DIFF_CASES` or `default`.
pub fn cases(default: usize) -> usize {
    std::env::var("OPENTRUST_DIFF_CASES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

/// Prints the skip notice of a test that needs the `ot` feature.
pub fn skipped(name: &str) {
    println!("skipped: {name} needs `--features ot` (OpenThread build)");
}
