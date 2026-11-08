//! MLE Advertisements (filled in by a later commit of Phase 6c).

use opentrust_core::time::Instant;

use crate::env::MleEnv;
use crate::mle::Mle;

impl<const C: usize> Mle<C> {
    pub(crate) fn router_role_entered<E: MleEnv>(&mut self, _env: &mut E, _now: Instant) {}
    pub(crate) fn reset_advertise_interval<E: MleEnv>(&mut self, _env: &mut E, _now: Instant) {}
    pub(crate) fn update_advertise_interval<E: MleEnv>(&mut self, _env: &mut E, _now: Instant) {}
    pub(crate) fn stop_advertising(&mut self) {}
    pub(crate) fn start_reed_advertising<E: MleEnv>(&mut self, _env: &mut E, _now: Instant) {}
}
