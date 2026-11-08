//! Router links (filled in by a later commit of Phase 6c).

use opentrust_core::time::Instant;

use crate::env::MleEnv;
use crate::mle::Mle;
use crate::neighbor::Parent;

impl<const C: usize> Mle<C> {
    pub(crate) fn router_neighbors_tick<E: MleEnv>(&mut self, _env: &mut E, _now: Instant) {}
    pub(crate) fn router_became_from_child<E: MleEnv>(
        &mut self,
        _env: &mut E,
        _now: Instant,
        _former_parent: &Parent,
    ) {
    }
}
