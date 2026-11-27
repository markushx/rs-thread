//! Embassy-time 0.5 (embassy-time-driver 0.2) driver for the ESP32-C6 SYSTIMER.
//!
//! # API
//! embassy-time-driver 0.2 uses a two-method `Driver` trait:
//! - `now()` → current tick count
//! - `schedule_wake(at, waker)` → schedule a wakeup at `at` ticks
//!
//! The driver manages a software timer queue (`embassy_time_queue_utils::Queue`)
//! and programs a single hardware alarm (SYSTIMER COMP0) for the next expiration.
//!
//! # Tick rate
//! SYSTIMER UNIT0 runs at 16 MHz (fXTAL / 2.5 on ESP32-C6, fXTAL = 40 MHz).
//! Cargo.toml selects `tick-hz-16_000_000` so embassy-time's notion of "ticks"
//! matches the raw SYSTIMER counter value directly (no conversion needed).

use core::{cell::RefCell, task::Waker};

use critical_section::Mutex;
use embassy_time_driver::Driver;
use embassy_time_queue_utils::Queue;
use esp_hal::{
    interrupt::{self, Priority},
    peripherals::{Interrupt, SYSTIMER},
};

embassy_time_driver::time_driver_impl!(static DRIVER: SystimerDriver = SystimerDriver {
    queue: Mutex::new(RefCell::new(Queue::new())),
});

struct SystimerDriver {
    queue: Mutex<RefCell<Queue>>,
}

unsafe impl Send for SystimerDriver {}
unsafe impl Sync for SystimerDriver {}

impl Driver for SystimerDriver {
    fn now(&self) -> u64 {
        read_unit0()
    }

    fn schedule_wake(&self, at: u64, waker: &Waker) {
        critical_section::with(|cs| {
            let mut q = self.queue.borrow(cs).borrow_mut();
            if q.schedule_wake(at, waker) {
                // The queue has a new earliest expiration; re-arm the alarm.
                let next = q.next_expiration(self.now());
                set_next_alarm(next);
            }
        });
    }
}

/// Program COMP0 and enable the interrupt for the given tick timestamp.
/// If `at` is in the past this is a no-op; the ISR will fire immediately via
/// `schedule_wake`'s contract.
fn set_next_alarm(at: u64) {
    if at == u64::MAX {
        // No pending timer; disable the alarm.
        unsafe {
            enable_comp0(false);
        }
        return;
    }
    unsafe {
        set_comp0(at);
        enable_comp0(true);
    }
    // Double-check for a race where `at` passed mid-write.
    if read_unit0() >= at {
        unsafe {
            enable_comp0(false);
        }
        // The queue will re-schedule when the caller awaits.
    }
}

/// ISR called when SYSTIMER COMP0 fires.
pub(crate) fn on_comp0_fired() {
    // Disable alarm first so the queue can re-arm safely.
    unsafe {
        enable_comp0(false);
    }

    critical_section::with(|cs| {
        let mut q = DRIVER.queue.borrow(cs).borrow_mut();
        // next_expiration() wakes all expired tasks and returns the next
        // expiration time still in the future.
        let next = q.next_expiration(DRIVER.now());
        set_next_alarm(next);
    });
}

/// Initialise the SYSTIMER driver and register the interrupt handler.
///
/// Must be called once before the embassy executor starts.
pub fn init(systimer: SYSTIMER) {
    // `SystemTimer::new` enables the SYSTIMER peripheral clock.
    // We drop the high-level struct because we drive COMP0 directly.
    let _ = esp_hal::timer::systimer::SystemTimer::new(systimer);

    unsafe {
        interrupt::bind_interrupt(
            Interrupt::SYSTIMER_TARGET0,
            systimer_target0_isr as unsafe extern "C" fn(),
        );
    }
    interrupt::enable(Interrupt::SYSTIMER_TARGET0, Priority::Priority1).unwrap();
}

unsafe extern "C" fn systimer_target0_isr() {
    on_comp0_fired();
}

// --- Low-level SYSTIMER register helpers ---

/// Read the current UNIT0 counter (52-bit at 16 MHz).
#[inline]
fn read_unit0() -> u64 {
    let st = unsafe { SYSTIMER::steal() };
    // Trigger the value-capture latch.
    st.unit_op(0).write(|w| w.update().set_bit());
    // Wait until the latched value is marked valid.
    while !st.unit_op(0).read().value_valid().bit_is_set() {}
    // Read HI then LO in a loop to guard against torn reads (same pattern as
    // the esp-hal SystemTimer::unit_value implementation).
    let v = st.unit_value(0);
    let mut lo_prev = v.lo().read().bits();
    loop {
        let lo = lo_prev;
        let hi = v.hi().read().bits() as u64;
        lo_prev = v.lo().read().bits();
        if lo == lo_prev {
            return (hi << 32) | lo as u64;
        }
    }
}

/// Program COMP0 target to `ticks` (raw 16 MHz SYSTIMER ticks).
unsafe fn set_comp0(ticks: u64) {
    let st = unsafe { SYSTIMER::steal() };
    // One-shot mode (not periodic).
    st.target_conf(0).modify(|_, w| w.period_mode().clear_bit());
    // Write target HI and LO.
    st.trgt(0).hi().write(|w| w.hi().set((ticks >> 32) as u32));
    st.trgt(0).lo().write(|w| w.lo().set(ticks as u32));
    // Load the new target into the comparator's shadow register.
    st.comp_load(0).write(|w| w.load().set_bit());
}

/// Enable or disable COMP0 and its interrupt.
unsafe fn enable_comp0(enable: bool) {
    let p = SYSTIMER::PTR;
    critical_section::with(|_| unsafe {
        (*p).conf().modify(|_, w| w.target0_work_en().bit(enable));
        (*p).int_ena().modify(|_, w| w.target0().bit(enable));
    });
}
