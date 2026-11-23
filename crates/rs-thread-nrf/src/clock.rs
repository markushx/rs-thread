//! `Clock` and `Alarm` over `embassy-time`.

use rs_thread_core::time::Instant;
use rs_thread_platform::{Alarm, Clock};

/// Time since boot from the embassy-time driver.
#[derive(Debug, Default, Clone, Copy)]
pub struct EmbassyClock;

impl Clock for EmbassyClock {
    fn now(&self) -> Instant {
        Instant::from_micros(embassy_time::Instant::now().as_micros())
    }
}

/// One-shot alarm on the embassy-time timer queue.
#[derive(Debug, Default, Clone, Copy)]
pub struct EmbassyAlarm;

impl Alarm for EmbassyAlarm {
    async fn wait_until(&mut self, at: Instant) {
        embassy_time::Timer::at(embassy_time::Instant::from_micros(at.as_micros())).await
    }
}
