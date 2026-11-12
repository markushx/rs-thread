//! `ThreadDiag`: the Thread Network Diagnostics cluster attributes of a
//! [`ThreadNetCtl`].
//!
//! What the [`Instance`](opentrust_instance::Instance) does not track is
//! reported with defaults, listed in `OPENTRUST-OPENTHREAD-DIFFERENCES.md`:
//! neighbor `age`, frame counters, `last_rssi` and the error rates are 0 /
//! `None`; router table `ext_address`, link qualities and `age` are 0; the
//! MAC counters the MAC does not keep (unicast / broadcast split, duplicates,
//! FCS errors) and all MLE counters are 0; `overrun_count` is 0 and
//! `reset_counts` has nothing to reset; `pending_timestamp` and `delay` are
//! `None` and `active_network_faults_list` is always empty.

use embassy_sync::blocking_mutex::raw::RawMutex;
use opentrust_instance::{InstanceCrypto, LeaderData, Role};
use opentrust_platform::{Clock, SettingsStore};
use rand_core::{CryptoRng, Rng};
#[cfg(feature = "ftd")]
use rs_matter::dm::clusters::thread_diag::RouteTable;
use rs_matter::dm::clusters::thread_diag::{
    MacCounters, MleCounters, NeighborTable, NetworkFaultEnum, OperationalDatasetComponents,
    RoutingRoleEnum, SecurityPolicy, ThreadDiag,
};
use rs_matter::error::Error;

use crate::netctl::{ThreadNetCtl, is_attached};

/// The Matter `RoutingRole` of a Thread role:
///
/// - disabled: `Unspecified`; detached: `Unassigned`;
/// - child with the receiver off when idle: `SleepyEndDevice`;
/// - child that could become a router: `REED`; other child: `EndDevice`;
/// - router: `Router`; leader: `Leader`.
pub const fn routing_role(
    role: Role,
    rx_on_when_idle: bool,
    router_eligible: bool,
) -> RoutingRoleEnum {
    match role {
        Role::Disabled => RoutingRoleEnum::Unspecified,
        Role::Detached => RoutingRoleEnum::Unassigned,
        Role::Child => {
            if !rx_on_when_idle {
                RoutingRoleEnum::SleepyEndDevice
            } else if router_eligible {
                RoutingRoleEnum::REED
            } else {
                RoutingRoleEnum::EndDevice
            }
        }
        Role::Router => RoutingRoleEnum::Router,
        Role::Leader => RoutingRoleEnum::Leader,
    }
}

fn be64(b: [u8; 8]) -> u64 {
    u64::from_be_bytes(b)
}

impl<M, K, S, C, R> ThreadNetCtl<'_, M, K, S, C, R>
where
    M: RawMutex,
    K: Clock,
    S: SettingsStore,
    C: InstanceCrypto,
    R: Rng + CryptoRng,
{
    /// Read from the Active Dataset while attached (`None` otherwise).
    fn attached_ds<T>(
        &self,
        f: impl FnOnce(&opentrust_meshcop::tlv::Tlvs<'_>) -> Option<T>,
    ) -> Option<T> {
        if !is_attached(self.ot.role()) {
            return None;
        }
        let ds = self.ot.with(|i, now| i.active_dataset(now))?;
        f(&ds.tlvs())
    }

    /// Read from the Leader Data while attached (`None` otherwise).
    fn leader<T>(&self, f: impl FnOnce(&LeaderData) -> T) -> Option<T> {
        self.ot
            .with(|i, _| is_attached(i.role()).then(|| f(&i.leader_data())))
    }
}

impl<M, K, S, C, R> ThreadDiag for ThreadNetCtl<'_, M, K, S, C, R>
where
    M: RawMutex,
    K: Clock,
    S: SettingsStore,
    C: InstanceCrypto,
    R: Rng + CryptoRng,
{
    fn channel(&self) -> Result<Option<u16>, Error> {
        if !is_attached(self.ot.role()) {
            return Ok(None);
        }
        Ok(Some(u16::from(self.ot.with(|i, _| i.mac().channel()))))
    }

    fn routing_role(&self) -> Result<Option<RoutingRoleEnum>, Error> {
        Ok(Some(self.ot.with(|i, _| {
            #[cfg(feature = "ftd")]
            let eligible = i.mle().is_router_eligible();
            #[cfg(not(feature = "ftd"))]
            let eligible = false;
            routing_role(i.role(), i.link_mode().rx_on_when_idle(), eligible)
        })))
    }

    fn network_name(
        &self,
        f: &mut dyn FnMut(Option<&str>) -> Result<(), Error>,
    ) -> Result<(), Error> {
        let name = self.attached_ds(|t| t.network_name().ok());
        f(name.as_ref().map(|n| n.as_str()))
    }

    fn pan_id(&self) -> Result<Option<u16>, Error> {
        if !is_attached(self.ot.role()) {
            return Ok(None);
        }
        Ok(Some(self.ot.with(|i, _| i.mac().pan_id().0)))
    }

    fn extended_pan_id(&self) -> Result<Option<u64>, Error> {
        Ok(self.attached_ds(|t| t.ext_pan_id().ok().map(|x| be64(x.0))))
    }

    fn mesh_local_prefix(
        &self,
        f: &mut dyn FnMut(Option<&[u8]>) -> Result<(), Error>,
    ) -> Result<(), Error> {
        let p = self.attached_ds(|t| t.mesh_local_prefix().ok());
        f(p.as_ref().map(|p| p.0.as_slice()))
    }

    fn neighbor_table(
        &self,
        f: &mut dyn FnMut(&NeighborTable) -> Result<(), Error>,
    ) -> Result<(), Error> {
        let t = self.ot.with(|i, _| i.neighbor_table());
        for n in &t {
            f(&NeighborTable {
                ext_address: be64(n.ext.0),
                age: 0,
                rloc16: n.rloc16.0,
                link_frame_counter: 0,
                mle_frame_counter: 0,
                lqi: n.link_quality_in,
                average_rssi: Some(n.average_rssi),
                last_rssi: None,
                frame_error_rate: 0,
                message_error_rate: 0,
                rx_on_when_idle: n.rx_on_when_idle,
                full_thread_device: n.full_thread_device,
                full_network_data: n.full_thread_device,
                is_child: n.is_child,
            })?;
        }
        Ok(())
    }

    #[cfg(feature = "ftd")]
    fn route_table(
        &self,
        f: &mut dyn FnMut(&RouteTable) -> Result<(), Error>,
    ) -> Result<(), Error> {
        let t = self.ot.with(|i, _| i.route_table());
        for r in &t {
            f(&RouteTable {
                ext_address: 0,
                rloc16: r.rloc16.0,
                router_id: r.router_id,
                next_hop: r.next_hop.unwrap_or(63),
                path_cost: r.cost,
                lqi_in: 0,
                lqi_out: 0,
                age: 0,
                allocated: true,
                link_established: r.is_neighbor,
            })?;
        }
        Ok(())
    }

    fn partition_id(&self) -> Result<Option<u32>, Error> {
        Ok(self.leader(|l| l.partition_id))
    }

    fn weighting(&self) -> Result<Option<u16>, Error> {
        Ok(self.leader(|l| u16::from(l.weighting)))
    }

    fn data_version(&self) -> Result<Option<u16>, Error> {
        Ok(self.leader(|l| u16::from(l.data_version)))
    }

    fn stable_data_version(&self) -> Result<Option<u16>, Error> {
        Ok(self.leader(|l| u16::from(l.stable_data_version)))
    }

    fn leader_router_id(&self) -> Result<Option<u8>, Error> {
        Ok(self.leader(|l| l.leader_router_id))
    }

    fn ext_address(&self) -> Result<Option<u64>, Error> {
        Ok(Some(be64(self.ot.with(|i, _| i.ext_address().0))))
    }

    fn rloc_16(&self) -> Result<Option<u16>, Error> {
        let r = self.ot.rloc16();
        Ok(
            (is_attached(self.ot.role()) && r != opentrust_core::types::Rloc16::INVALID)
                .then_some(r.0),
        )
    }

    fn security_policy(&self) -> Result<Option<SecurityPolicy>, Error> {
        Ok(self.attached_ds(|t| {
            let b = t.security_policy().ok()?.to_bytes();
            Some(SecurityPolicy {
                rotation_time: u16::from_be_bytes([b[0], b[1]]),
                flags: u16::from_be_bytes([b[2], b[3]]),
            })
        }))
    }

    fn channel_page0_mask(
        &self,
        f: &mut dyn FnMut(Option<&[u8]>) -> Result<(), Error>,
    ) -> Result<(), Error> {
        let m = self.attached_ds(|t| t.channel_mask().ok());
        f(m.map(u32::to_be_bytes).as_ref().map(|b| b.as_slice()))
    }

    fn operational_dataset_components(
        &self,
        f: &mut dyn FnMut(Option<&OperationalDatasetComponents>) -> Result<(), Error>,
    ) -> Result<(), Error> {
        let c = self.attached_ds(|t| {
            use opentrust_meshcop::tlv::ty;
            Some(OperationalDatasetComponents {
                active_timestamp_present: t.find(ty::ACTIVE_TIMESTAMP).is_ok(),
                pending_timestamp_present: t.find(ty::PENDING_TIMESTAMP).is_ok(),
                master_key_present: t.find(ty::NETWORK_KEY).is_ok(),
                network_name_present: t.find(ty::NETWORK_NAME).is_ok(),
                extended_pan_id_present: t.find(ty::EXT_PAN_ID).is_ok(),
                mesh_local_prefix_present: t.find(ty::MESH_LOCAL_PREFIX).is_ok(),
                delay_present: t.find(ty::DELAY_TIMER).is_ok(),
                pan_id_present: t.find(ty::PAN_ID).is_ok(),
                channel_present: t.find(ty::CHANNEL).is_ok(),
                pskc_present: t.find(ty::PSKC).is_ok(),
                security_policy_present: t.find(ty::SECURITY_POLICY).is_ok(),
                channel_mask_present: t.find(ty::CHANNEL_MASK).is_ok(),
            })
        });
        f(c.as_ref())
    }

    fn active_network_faults_list(
        &self,
        _f: &mut dyn FnMut(NetworkFaultEnum) -> Result<(), Error>,
    ) -> Result<(), Error> {
        Ok(())
    }

    fn mac_counters(
        &self,
        f: &mut dyn FnMut(Option<&MacCounters>) -> Result<(), Error>,
    ) -> Result<(), Error> {
        let c = self.ot.with(|i, _| *i.mac_counters());
        f(Some(&MacCounters {
            tx_total_count: c.tx_total,
            tx_ack_requested_count: c.tx_ack_requested,
            tx_acked_count: c.tx_acked,
            tx_data_count: c.tx_data,
            tx_data_poll_count: c.tx_data_poll,
            tx_beacon_count: c.tx_beacon,
            tx_beacon_request_count: c.tx_beacon_request,
            tx_retry_count: c.tx_retry,
            tx_direct_max_retry_expiry_count: Some(c.tx_direct_max_retry_expiry),
            tx_indirect_max_retry_expiry_count: Some(c.tx_indirect_max_retry_expiry),
            tx_err_cca_count: c.tx_err_cca,
            tx_err_abort_count: c.tx_err_abort,
            rx_total_count: c.rx_total,
            rx_data_count: c.rx_data,
            rx_data_poll_count: c.rx_data_poll,
            rx_beacon_count: c.rx_beacon,
            rx_beacon_request_count: c.rx_beacon_request,
            rx_other_count: c.rx_other,
            rx_dest_addr_filtered_count: c.rx_dest_addr_filtered,
            rx_err_no_frame_count: c.rx_err_no_frame,
            rx_err_unknown_neighbor_count: c.rx_err_unknown_neighbor,
            rx_err_invalid_src_addr_count: c.rx_err_invalid_src_addr,
            rx_err_sec_count: c.rx_err_sec,
            ..MacCounters::default()
        }))
    }

    fn mle_counters(
        &self,
        f: &mut dyn FnMut(Option<&MleCounters>) -> Result<(), Error>,
    ) -> Result<(), Error> {
        f(Some(&MleCounters::default()))
    }

    fn active_timestamp(&self) -> Result<Option<u64>, Error> {
        Ok(self.attached_ds(|t| {
            let ts = t.active_timestamp().ok()?;
            Some((ts.seconds << 16) | (u64::from(ts.ticks) << 1) | u64::from(ts.authoritative))
        }))
    }
}
