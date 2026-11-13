//! Heap use of rs-matter's RustCrypto backend, to size the firmware heap.
//!
//! Everything in the backend works on fixed buffers except the PKCS#10
//! certificate signing request built during commissioning (`x509-cert`
//! allocates its DER structures). A counting allocator tracks the live bytes
//! of the thread while one request is generated.

#![allow(unsafe_code)]

use core::alloc::{GlobalAlloc, Layout};
use core::cell::Cell;
use std::alloc::System;

use rs_matter::crypto::{Crypto, SigningSecretKey as _, default_crypto};
use rs_matter::dm::devices::test::DAC_PRIVKEY;

struct Counting;

thread_local! {
    static LIVE: Cell<usize> = const { Cell::new(0) };
    static PEAK: Cell<usize> = const { Cell::new(0) };
}

// SAFETY: forwards to the system allocator, only adding thread-local counters.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        let _ = LIVE.try_with(|live| {
            live.set(live.get() + l.size());
            let _ = PEAK.try_with(|p| p.set(p.get().max(live.get())));
        });
        unsafe { System.alloc(l) }
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        let _ = LIVE.try_with(|live| live.set(live.get().saturating_sub(l.size())));
        unsafe { System.dealloc(p, l) }
    }
}

#[global_allocator]
static A: Counting = Counting;

#[test]
fn csr_generation_heap_peak() {
    let crypto = default_crypto(rand::rng(), DAC_PRIVKEY);
    let key = crypto.generate_secret_key().unwrap();
    let mut buf = [0u8; 256];
    let before = LIVE.with(Cell::get);
    PEAK.with(|p| p.set(before));
    let csr_len = key.csr(&mut buf).unwrap().len();
    let peak = PEAK.with(Cell::get) - before;
    println!("CSR of {csr_len} bytes: heap peak {peak} bytes");
    // The firmware heap is 4096 bytes.
    assert!(peak < 2048, "CSR heap peak {peak}");
}
