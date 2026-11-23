//! `ThreadNetCtl` over the test medium in virtual time: scan, connect with a
//! dataset, connect timeout and the status attributes.
mod common;

use core::cell::{Cell, RefCell};

use common::*;
use rs_matter::dm::clusters::net_comm::{
    NetCtl, NetCtlError, NetCtlStatus, NetworkCommissioningStatusEnum, NetworkScanInfo,
    NetworkType, WirelessCreds,
};
use rs_thread_instance::Role;
use rs_thread_matter::netctl::ThreadNetCtl;

#[test]
fn scan_finds_the_leader_and_connect_joins_it() {
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
    let want_epid = ds.tlvs().ext_pan_id().unwrap().0;
    let want_name = ds.tlvs().network_name().unwrap();
    let found = RefCell::new(Vec::<(String, u64, u16, u8)>::new());
    drive(
        &[&clks[0], &clks[1]],
        &[&pend[0], &pend[1]],
        tasks,
        async {
            start_with(ots[0], &ds, true);
            wait_role(ots[0], Role::Leader).await;

            let ctl = ThreadNetCtl::new(ots[1]);
            assert_eq!(ctl.net_type(), NetworkType::Thread);
            assert_eq!(ctl.last_networking_status().unwrap(), None);

            // A filter that matches nothing.
            let r = ctl.scan(Some(&[9u8; 8]), |_| Ok(())).await;
            assert!(matches!(r, Err(NetCtlError::NetworkNotFound)), "{r:?}");
            assert_eq!(
                ctl.last_networking_status().unwrap(),
                Some(NetworkCommissioningStatusEnum::NetworkNotFound)
            );

            ctl.scan(None, |n| {
                let NetworkScanInfo::Thread {
                    network_name,
                    ext_pan_id,
                    channel,
                    pan_id,
                    ext_addr,
                    ..
                } = n
                else {
                    panic!("not a Thread result");
                };
                assert_eq!(ext_addr.len(), 8);
                found
                    .borrow_mut()
                    .push((network_name.to_string(), *ext_pan_id, *channel, 0));
                let _ = pan_id;
                Ok(())
            })
            .await
            .unwrap();
            assert_eq!(
                ctl.last_networking_status().unwrap(),
                Some(NetworkCommissioningStatusEnum::Success)
            );

            // An error of the callback aborts the scan.
            let r = ctl
                .scan(Some(&want_epid), |_| {
                    Err(rs_matter::error::ErrorCode::Busy.into())
                })
                .await;
            assert!(matches!(r, Err(NetCtlError::Other(_))));

            // Connect with the dataset TLVs.
            ctl.connect(&WirelessCreds::Thread {
                dataset_tlv: ds.as_bytes(),
            })
            .await
            .unwrap();
            assert!(matches!(
                ots[1].role(),
                Role::Child | Role::Router | Role::Leader
            ));
            assert_ne!(ots[1].with(|i, _| i.partition_id()), 0);
            assert_eq!(
                ctl.last_networking_status().unwrap(),
                Some(NetworkCommissioningStatusEnum::Success)
            );
            assert_eq!(ctl.last_connect_error_value().unwrap(), None);
            ctl.last_network_id(|id| {
                assert_eq!(id, Some(&want_epid[..]));
                Ok(())
            })
            .unwrap();
            // Connecting again to the network the node is on returns at once.
            ctl.connect(&WirelessCreds::Thread {
                dataset_tlv: ds.as_bytes(),
            })
            .await
            .unwrap();
        },
        limit(),
    );
    let found = found.into_inner();
    assert_eq!(found.len(), 1, "{found:?}");
    assert_eq!(found[0].0, want_name.as_str());
    assert_eq!(found[0].1.to_be_bytes(), want_epid);
    // Both nodes share the partition of the leader.
    assert_eq!(
        ots[0].with(|i, _| i.partition_id()),
        ots[1].with(|i, _| i.partition_id())
    );
}

#[test]
fn connect_to_a_missing_network_times_out() {
    let clks = [clock(), clock()];
    let air = Air::new(2);
    let pend = [Cell::new(None), Cell::new(None)];
    let res0: Res<'_> = Res::new(instance(1), &clks[0]);
    let res1: Res<'_> = Res::new(instance(2), &clks[1]);
    let ots = [Ot::new(&res0), Ot::new(&res1)];
    let ds = make_dataset(ots[0]);
    // Another network, which nobody runs.
    let other = ots[1].with(|i, _| i.create_dataset(20).unwrap());
    assert_ne!(
        other.tlvs().ext_pan_id().unwrap(),
        ds.tlvs().ext_pan_id().unwrap()
    );
    let tasks = vec![
        run_task(ots[0], &air, 0, &clks[0], &pend[0]),
        run_task(ots[1], &air, 1, &clks[1], &pend[1]),
    ];
    drive(
        &[&clks[0], &clks[1]],
        &[&pend[0], &pend[1]],
        tasks,
        async {
            start_with(ots[0], &ds, true);
            wait_role(ots[0], Role::Leader).await;

            let ctl = ThreadNetCtl::new(ots[1]).with_connect_timeout(10);
            let t0 = ots[1].now();
            let r = ctl
                .connect(&WirelessCreds::Thread {
                    dataset_tlv: other.as_bytes(),
                })
                .await;
            assert!(
                matches!(r, Err(NetCtlError::OtherConnectionFailure)),
                "{r:?}"
            );
            assert!(ots[1].now().as_micros() - t0.as_micros() >= 10_000_000);
            assert_eq!(
                ctl.last_networking_status().unwrap(),
                Some(NetworkCommissioningStatusEnum::OtherConnectionFailure)
            );
            // Thread is stopped again.
            assert_eq!(ots[1].role(), Role::Disabled);

            // A malformed dataset is rejected without touching the node.
            let r = ctl
                .connect(&WirelessCreds::Thread {
                    dataset_tlv: &[1, 2, 3],
                })
                .await;
            assert!(matches!(r, Err(NetCtlError::Other(_))));
        },
        limit(),
    );
}

/// `connect` with the dataset the node already runs (started at boot, still
/// attaching) waits for the attach instead of restarting Thread.
#[test]
fn connect_to_the_running_dataset_does_not_restart_thread() {
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
    drive(
        &[&clks[0], &clks[1]],
        &[&pend[0], &pend[1]],
        tasks,
        async {
            start_with(ots[0], &ds, true);
            wait_role(ots[0], Role::Leader).await;
            // The node starts first (as the light does at boot), then the
            // network manager connects with the same dataset.
            start_with(ots[1], &ds, false);
            assert_ne!(ots[1].role(), Role::Disabled);
            let ctl = ThreadNetCtl::new(ots[1]);
            ctl.connect(&WirelessCreds::Thread {
                dataset_tlv: ds.as_bytes(),
            })
            .await
            .unwrap();
            assert!(matches!(ots[1].role(), Role::Child | Role::Router));
        },
        limit(),
    );
}

/// A timed-out `connect` with the dataset the node runs leaves Thread
/// running: the attach (or the restore of the stored role) goes on and the
/// next `connect` finds the node attached.
#[test]
fn connect_timeout_with_the_running_dataset_keeps_attaching() {
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
    drive(
        &[&clks[0], &clks[1]],
        &[&pend[0], &pend[1]],
        tasks,
        async {
            // Nobody to attach to yet.
            start_with(ots[1], &ds, false);
            let ctl = ThreadNetCtl::new(ots[1]).with_connect_timeout(5);
            let r = ctl
                .connect(&WirelessCreds::Thread {
                    dataset_tlv: ds.as_bytes(),
                })
                .await;
            assert!(
                matches!(r, Err(NetCtlError::OtherConnectionFailure)),
                "{r:?}"
            );
            assert_ne!(ots[1].role(), Role::Disabled);

            start_with(ots[0], &ds, true);
            wait_role(ots[0], Role::Leader).await;
            let ctl = ThreadNetCtl::new(ots[1]).with_connect_timeout(60);
            ctl.connect(&WirelessCreds::Thread {
                dataset_tlv: ds.as_bytes(),
            })
            .await
            .unwrap();
            assert!(matches!(ots[1].role(), Role::Child | Role::Router));
        },
        limit(),
    );
}
