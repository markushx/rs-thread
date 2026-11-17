//! `ThreadDiag` / `WirelessDiag` of `ThreadNetCtl` on a two-node network.
mod common;

use core::cell::Cell;

use common::*;
use opentrust_instance::Role;
use opentrust_matter::icd::IcdFollower;
use opentrust_matter::netctl::ThreadNetCtl;
use opentrust_matter::threaddiag::routing_role;
use rs_matter::dm::clusters::thread_diag::{RoutingRoleEnum, ThreadDiag};
use rs_matter::dm::clusters::wifi_diag::WirelessDiag;

#[test]
fn role_mapping() {
    use RoutingRoleEnum as E;
    assert_eq!(routing_role(Role::Disabled, true, true), E::Unspecified);
    assert_eq!(routing_role(Role::Detached, true, true), E::Unassigned);
    assert_eq!(routing_role(Role::Child, false, true), E::SleepyEndDevice);
    assert_eq!(routing_role(Role::Child, true, true), E::REED);
    assert_eq!(routing_role(Role::Child, true, false), E::EndDevice);
    assert_eq!(routing_role(Role::Router, true, true), E::Router);
    assert_eq!(routing_role(Role::Leader, true, true), E::Leader);
}

#[test]
fn diagnostics_of_a_leader_and_a_child() {
    let clks = [clock(), clock()];
    let air = Air::new(2);
    let pend = [Cell::new(None), Cell::new(None)];
    let res0: Res<'_> = Res::new(instance(1), &clks[0]);
    let res1: Res<'_> = Res::new(instance(2), &clks[1]);
    let ots = [Ot::new(&res0), Ot::new(&res1)];
    let ds = make_dataset(ots[0]);
    let tasks = vec![
        run_task(ots[0], &air, 0, &clks[0], &pend[0]),
        run_task(ots[1], &air, 1, &clks[1], &pend[1]),
    ];
    let name = ds.tlvs().network_name().unwrap();
    let epid = u64::from_be_bytes(ds.tlvs().ext_pan_id().unwrap().0);
    let mlp = ds.tlvs().mesh_local_prefix().unwrap().0;
    drive(
        &[&clks[0], &clks[1]],
        &[&pend[0], &pend[1]],
        tasks,
        async {
            let d0 = ThreadNetCtl::new(ots[0]);
            let d1 = ThreadNetCtl::new(ots[1]);

            // Disabled: nothing is reported, the role is unspecified.
            assert!(!d0.connected().unwrap());
            assert_eq!(
                d0.routing_role().unwrap(),
                Some(RoutingRoleEnum::Unspecified)
            );
            assert_eq!(d0.channel().unwrap(), None);
            assert_eq!(d0.rloc_16().unwrap(), None);
            d0.network_name(&mut |n| {
                assert_eq!(n, None);
                Ok(())
            })
            .unwrap();

            form_network(&ots, &ds).await;

            assert!(d0.connected().unwrap() && d1.connected().unwrap());
            assert_eq!(d0.routing_role().unwrap(), Some(RoutingRoleEnum::Leader));
            assert_eq!(d1.routing_role().unwrap(), Some(RoutingRoleEnum::REED));
            for (d, ot) in [(&d0, ots[0]), (&d1, ots[1])] {
                assert_eq!(d.rloc_16().unwrap(), Some(ot.rloc16().0));
                assert_eq!(d.channel().unwrap(), Some(15));
                assert_eq!(d.extended_pan_id().unwrap(), Some(epid));
                assert_eq!(
                    d.pan_id().unwrap(),
                    Some(ot.with(|i, _| i.mac().pan_id().0))
                );
                d.network_name(&mut |n| {
                    assert_eq!(n, Some(name.as_str()));
                    Ok(())
                })
                .unwrap();
                d.mesh_local_prefix(&mut |p| {
                    assert_eq!(p, Some(mlp.as_slice()));
                    Ok(())
                })
                .unwrap();
                assert_eq!(
                    d.partition_id().unwrap(),
                    Some(ots[0].with(|i, _| i.partition_id()))
                );
                assert_eq!(
                    d.leader_router_id().unwrap(),
                    Some(ots[0].with(|i, _| i.leader_data().leader_router_id))
                );
                assert!(d.weighting().unwrap().is_some());
                assert!(d.data_version().unwrap().is_some());
                assert!(d.stable_data_version().unwrap().is_some());
                assert!(d.active_timestamp().unwrap().is_some());
                d.security_policy().unwrap().unwrap();
                d.channel_page0_mask(&mut |m| {
                    assert_eq!(m.map(<[u8]>::len), Some(4));
                    Ok(())
                })
                .unwrap();
                d.operational_dataset_components(&mut |c| {
                    let c = c.unwrap();
                    assert!(c.network_name_present && c.extended_pan_id_present);
                    assert!(c.channel_present && c.pan_id_present && c.master_key_present);
                    Ok(())
                })
                .unwrap();
                d.mac_counters(&mut |c| {
                    assert!(c.unwrap().tx_total_count > 0 || c.unwrap().rx_total_count > 0);
                    Ok(())
                })
                .unwrap();
            }
            assert_eq!(
                d0.ext_address().unwrap(),
                Some(u64::from_be_bytes(ots[0].with(|i, _| i.ext_address().0)))
            );

            // The leader sees the child, the child sees its parent.
            let mut seen = Vec::new();
            d0.neighbor_table(&mut |n| {
                seen.push((n.rloc16, n.is_child, n.rx_on_when_idle));
                Ok(())
            })
            .unwrap();
            assert_eq!(seen, [(ots[1].rloc16().0, true, true)]);
            let mut seen = Vec::new();
            d1.neighbor_table(&mut |n| {
                seen.push((n.rloc16, n.is_child));
                Ok(())
            })
            .unwrap();
            assert_eq!(seen, [(ots[0].rloc16().0, false)]);
            let mut routes = Vec::new();
            d0.route_table(&mut |r| {
                routes.push((r.rloc16, r.allocated));
                Ok(())
            })
            .unwrap();
            // The router table lists every allocated router ID, the node's own
            // entry included (OT `otThreadGetRouterInfo`): only the leader here.
            assert_eq!(routes, [(ots[0].rloc16().0, true)], "{routes:?}");

            // A sleepy child is reported as such.
            IcdFollower::new(ots[1]).set_sleepy(true).unwrap();
            assert_eq!(
                d1.routing_role().unwrap(),
                Some(RoutingRoleEnum::SleepyEndDevice)
            );
        },
        limit(),
    );
}
