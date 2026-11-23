//! Anycast locator (ALOC) addresses this device answers to: the leader
//! ALOC, the service ALOCs of services it is a server of, the Neighbor
//! Discovery agent ALOC, and the
//! commissioner ALOC (OT `Mle::AddLeaderAloc`, `Service::Manager`, the
//! commissioner's `AddCommissionerAloc`).

use heapless::Vec;
use rs_thread_core::Result;
use rs_thread_net::netif::Netif;

use super::lookup::{ALOC16_COMMISSIONER_START, ALOC16_LEADER, ALOC16_ND_AGENT_START};
use super::tlv::BrFlags;
use super::view::{NetworkDataView, SERVICE_ALOC_BASE};

/// Largest number of ALOCs one device holds at a time (leader, 16
/// services, commissioner).
pub const MAX_ALOCS: usize = 20;

/// ALOC16 of the commissioner with this session ID (OT
/// `CommissionerAloc16FromId`).
pub const fn commissioner_aloc16(session_id: u16) -> u16 {
    (session_id & 0x0007) + ALOC16_COMMISSIONER_START
}

/// The ALOCs a device with `rloc16` should answer to.
pub fn desired_alocs(
    is_leader: bool,
    view: &NetworkDataView<'_>,
    rloc16: Option<u16>,
    commissioner_aloc16: Option<u16>,
) -> Vec<u16, MAX_ALOCS> {
    let mut out: Vec<u16, MAX_ALOCS> = Vec::new();
    let Some(rloc16) = rloc16 else {
        return out;
    };
    if is_leader {
        let _ = out.push(ALOC16_LEADER);
    }
    for s in view.services().filter(|s| s.rloc16 == rloc16) {
        let a = SERVICE_ALOC_BASE + u16::from(s.service_id);
        if !out.contains(&a) {
            let _ = out.push(a);
        }
    }
    // Neighbor Discovery agent (OT `NeighborDiscovery::Agent`): one ALOC for
    // the first on-mesh prefix with the ND DNS flag served by this device.
    if let Some(e) = view
        .on_mesh_prefixes()
        .find(|e| e.rloc16 == rloc16 && e.flags.has(BrFlags::ND_DNS))
        && let Some(c) = view
            .contexts()
            .filter(|c| c.prefix.contains(&e.prefix.addr()))
            .max_by_key(|c| c.prefix.len())
        && c.id >= 1
    {
        let _ = out.push(ALOC16_ND_AGENT_START + u16::from(c.id) - 1);
    }
    if let Some(a) = commissioner_aloc16
        && !out.contains(&a)
    {
        let _ = out.push(a);
    }
    out
}

/// The ALOCs added to the interface by this module.
#[derive(Debug, Clone, Default)]
pub struct AlocSet {
    active: Vec<u16, MAX_ALOCS>,
}

impl AlocSet {
    /// No ALOCs.
    pub const fn new() -> Self {
        Self { active: Vec::new() }
    }

    /// The ALOC16s currently on the interface.
    pub fn active(&self) -> &[u16] {
        &self.active
    }

    /// Make the interface's ALOCs exactly `desired`: add missing ones,
    /// remove ones no longer wanted. Returns the first error (the others
    /// are still attempted).
    pub fn update<const U: usize, const M: usize>(
        &mut self,
        netif: &mut Netif<U, M>,
        desired: &[u16],
    ) -> Result<()> {
        let mut result = Ok(());
        self.active.retain(|a| {
            if desired.contains(a) {
                true
            } else {
                let _ = netif.remove_aloc(*a);
                false
            }
        });
        for a in desired {
            if self.active.contains(a) {
                continue;
            }
            match netif.add_aloc(*a) {
                Ok(()) => {
                    let _ = self.active.push(*a);
                }
                Err(e) => result = result.and(Err(e)),
            }
        }
        result
    }
}
