#![cfg(feature = "openthread-compat")]
//! The esp-rs `openthread`-shaped surface, called with the esp-rs
//! signatures.

mod common;

use core::cell::Cell;
use core::net::{Ipv6Addr, SocketAddrV6};

use common::*;
use opentrust_core::time::Duration;
use opentrust_embassy::compat::{
    Channels, DeviceRole, EnergyScanResult, IpCounters, MacCounters, MleCounters, NeighborInfo,
    NetStatus, OpenThread, OtError, OtResources, OtSrpResources, OtUdpResources, RouteInfo,
    ScanResult, SrpConf, SrpService,
};

type Ott<'a, 'c> = OpenThread<
    'a,
    embassy_sync::blocking_mutex::raw::NoopRawMutex,
    &'c opentrust_platform::time::MockClock,
    opentrust_sim::SimSettings,
    opentrust_core::crypto::soft::SoftCrypto,
    opentrust_sim::SimRng,
>;

async fn until_role(ot: Ott<'_, '_>, role: DeviceRole) {
    while ot.device_role() != role {
        ot.wait_changed().await;
    }
}

#[test]
fn esp_rs_shaped_api() {
    let clks = [clock(), clock()];
    let air = Air::new(2);
    let pend = [Cell::new(None), Cell::new(None)];
    let res0: Res<'_> = Res::new(instance(1), &clks[0]);
    let res1: Res<'_> = Res::new(instance(2), &clks[1]);
    let mut udp = OtUdpResources::<1, 1280>::new();
    let mut srp = OtSrpResources::<3, 300>::new();
    let _ = OtResources::new();
    let ot0: Ott<'_, '_> = OpenThread::new_with_udp_srp(&res0, &mut udp, &mut srp).unwrap();
    let ot1: Ott<'_, '_> = OpenThread::new(&res1);
    let tasks = vec![
        run_task(ot0.opentrust(), &air, 0, &clks[0], &pend[0]),
        run_task(ot1.opentrust(), &air, 1, &clks[1], &pend[1]),
    ];
    let tlv = ot0
        .opentrust()
        .with(|i, _| i.create_dataset(15).unwrap())
        .as_bytes()
        .to_vec();
    drive(
        &[&clks[0], &clks[1]],
        &[&pend[0], &pend[1]],
        tasks,
        async {
            assert!(!ot0.is_commissioned());
            let st: NetStatus = ot0.net_status();
            assert_eq!(st.role, DeviceRole::Disabled);
            assert!(!st.ip6_enabled);

            ot0.enable_ipv6(true).unwrap();
            ot0.set_active_dataset_tlv(&tlv).unwrap();
            assert!(ot0.is_commissioned());
            ot0.enable_thread(true).unwrap();
            until_role(ot0, DeviceRole::Leader).await;
            assert!(ot0.net_status().role.is_connected());
            assert!(ot0.net_status().ext_pan_id.is_some());

            // Getters with the esp-rs signatures.
            let _: [u8; 8] = ot0.ieee_eui64();
            let _: u64 = ot0.ext_address();
            assert_eq!(ot0.channel(), 15);
            assert!(ot0.rx_on_when_idle());
            ot0.network_name(|n| assert_eq!(n, "OpenTrust"));
            assert_ne!(ot0.pan_id(), 0xffff);
            assert_eq!(ot0.mesh_local_prefix()[0], 0xfd);
            assert_ne!(ot0.partition_id(), 0);
            let _: (u8, u8, u8, u8) = (
                ot0.leader_weight(),
                ot0.net_data_version(),
                ot0.net_data_stable_version(),
                ot0.leader_router_id(),
            );
            assert_ne!(ot0.rloc16(), 0xfffe);
            assert_eq!(ot0.supported_channel_mask(), 0x07ff_f800);
            assert!(ot0.router_eligible());
            let _: u32 = OpenThread::<
                '_,
                embassy_sync::blocking_mutex::raw::NoopRawMutex,
                &opentrust_platform::time::MockClock,
                opentrust_sim::SimSettings,
                opentrust_core::crypto::soft::SoftCrypto,
                opentrust_sim::SimRng,
            >::CSL_MAX_PERIOD_US;
            let mut n = 0;
            ot0.ipv6_addrs(|a| {
                if a.is_some() {
                    n += 1;
                }
                Ok::<(), OtError>(())
            })
            .unwrap();
            assert!(n >= 2);
            let _: MacCounters = ot0.mac_counters();
            let _: MleCounters = ot0.mle_counters();
            let _: IpCounters = ot0.ip_counters();
            ot0.join_multicast("ff03::1234".parse().unwrap()).unwrap();
            ot0.leave_multicast("ff03::1234".parse().unwrap()).unwrap();

            // Scan.
            ot1.enable_ipv6(true).unwrap();
            let mut seen = Vec::new();
            ot1.scan(Channels::all(), 500, |r: Option<&ScanResult<'_>>| {
                if let Some(r) = r {
                    seen.push((r.network_name.to_string(), r.channel, r.discover));
                }
            })
            .await
            .unwrap();
            assert_eq!(seen, vec![("OpenTrust".to_string(), 15, true)]);
            let mut ch = Vec::new();
            ot1.energy_scan(Channels::CH_11 | Channels::CH_15, 20, |r| {
                if let Some(EnergyScanResult { channel, .. }) = r {
                    ch.push(*channel);
                }
            })
            .await
            .unwrap();
            assert_eq!(ch, vec![11, 15]);

            // Attach node 1 with the same dataset, then the tables.
            ot1.set_active_dataset_tlv(&tlv).unwrap();
            ot1.set_link_mode(true, true, true).unwrap();
            ot1.set_poll_period(0).unwrap();
            ot1.enable_thread(true).unwrap();
            until_role(ot1, DeviceRole::Child).await;
            until_role(ot1, DeviceRole::Router).await;
            let mut neighbors = Vec::new();
            ot0.neighbor_table(|n: &NeighborInfo| neighbors.push(n.rloc16));
            assert!(!neighbors.is_empty(), "{neighbors:?} {:#x}", ot1.rloc16());
            loop {
                let g = ot0.opentrust().generation();
                let mut routes = 0;
                ot0.route_table(|_: &RouteInfo| routes += 1);
                if routes >= 1 {
                    break;
                }
                ot0.opentrust().wait_changed_after(g).await;
            }
            assert_eq!(
                ot1.set_csl_period(160),
                Err(opentrust_core::Error::NotImplemented.into())
            );

            // SRP configuration calls.
            let conf = SrpConf {
                host_name: "host",
                host_addrs: &[Ipv6Addr::LOCALHOST],
                ttl: 0,
                default_lease_secs: 0,
                default_key_lease_secs: 0,
            };
            ot1.srp_set_conf(&conf).unwrap();
            let svc = SrpService {
                name: "_matter._tcp",
                instance_name: "ABCD-1",
                port: 5540,
                subtype_labels: core::iter::empty::<&str>(),
                txt_entries: [("SII", &b"5000"[..])].into_iter(),
                priority: 0,
                weight: 0,
                lease_secs: 0,
                key_lease_secs: 0,
            };
            let slot = ot1.srp_add_service(&svc).unwrap();
            ot1.srp_start(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 53, 0, 0))
                .unwrap();
            assert!(ot1.srp_running().unwrap());
            assert!(ot1.srp_server_addr().unwrap().is_some());
            ot1.srp_remove_service(slot, true);
            ot1.srp_remove_all(true);
            ot1.srp_stop();
            ot1.enable_thread(false).unwrap();
            assert_eq!(ot1.device_role(), DeviceRole::Disabled);
            let _ = Duration::ZERO;
        },
        Duration::from_secs(3000),
    );
}
