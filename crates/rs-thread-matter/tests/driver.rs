//! `ThreadRunner` and the settings persistence over the test medium in
//! virtual time: restore after a restart, bounded write rate, drop and
//! restart of the runner.
mod common;

use core::cell::Cell;
use core::future::pending;

use common::kv::MemKv;
use common::*;
use embassy_futures::select::{Either, select};
use rs_matter::dm::clusters::gen_diag::NetifDiag;
use rs_matter::dm::clusters::net_comm::{NetCtl, WirelessCreds};
use rs_matter::dm::clusters::thread_diag::ThreadDiag;
use rs_matter::dm::networks::NetChangeNotif;
use rs_matter::error::{Error, ErrorCode};
use rs_matter::stack::ble::GattPeripheral;
use rs_matter::stack::mdns::Mdns;
use rs_matter::stack::net::NetStack;
use rs_matter::stack::wireless::{ThreadCoexDriver, ThreadCoexTask, ThreadDriver, ThreadTask};
use rs_matter::transport::network::btp::{AdvData, Btp};
use rs_matter::utils::timers::{Duration as TDuration, Timer};
use rs_thread_core::settings::SettingsKey;
use rs_thread_core::time::{Duration, Instant};
use rs_thread_instance::Role;
use rs_thread_matter::driver::{ThreadCoexRunner, ThreadRunner};
use rs_thread_matter::persist::{THREAD_SETTINGS_KEY, deserialize, serialize};
use rs_thread_platform::{Clock, RamSettings, SettingsStore};

/// Connects to the network of `ds`, records when it was joined, then idles.
struct ConnectTask<'x> {
    ds: &'x [u8],
    joined_at: &'x Cell<Option<Instant>>,
    now: &'x dyn Fn() -> Instant,
}

impl ThreadTask for ConnectTask<'_> {
    async fn run<S, N, C, M>(&mut self, _s: S, _n: N, ctl: C, _m: M) -> Result<(), Error>
    where
        S: NetStack,
        N: NetifDiag + NetChangeNotif,
        C: NetCtl + ThreadDiag + NetChangeNotif,
        M: Mdns,
    {
        ctl.connect(&WirelessCreds::Thread {
            dataset_tlv: self.ds,
        })
        .await
        .map_err(|_| Error::new(ErrorCode::Invalid))?;
        self.joined_at.set(Some((self.now)()));
        pending().await
    }
}

/// Like [`ConnectTask`], but ends after `secs`.
struct JoinThenReturn<'x>(ConnectTask<'x>, u64);

impl ThreadTask for JoinThenReturn<'_> {
    async fn run<S, N, C, M>(&mut self, s: S, n: N, ctl: C, m: M) -> Result<(), Error>
    where
        S: NetStack,
        N: NetifDiag + NetChangeNotif,
        C: NetCtl + ThreadDiag + NetChangeNotif,
        M: Mdns,
    {
        let secs = self.1;
        let t = select(self.0.run(s, n, ctl, m), async {
            Timer::after(TDuration::from_secs(secs)).await
        })
        .await;
        match t {
            Either::First(r) => r,
            Either::Second(()) => Ok(()),
        }
    }
}

/// A BLE peripheral that never connects; counts how often it is started.
struct IdleGatt<'x>(&'x Cell<u32>);

impl GattPeripheral for IdleGatt<'_> {
    async fn run(&mut self, _btp: &Btp, _name: &str, _adv: &AdvData) -> Result<(), Error> {
        self.0.set(self.0.get() + 1);
        pending().await
    }
}

/// The BLE commissioning flow as the Network Commissioning cluster drives it:
/// the node is unprovisioned (Thread disabled) while the task has the BLE
/// peripheral, then `connect` hands over the dataset and the node attaches.
struct BleThenConnect<'x> {
    inner: ConnectTask<'x>,
    disabled_before: &'x Cell<bool>,
    ot: Ot<'x, 'x>,
}

impl ThreadCoexTask for BleThenConnect<'_> {
    async fn run<S, N, C, M, G>(
        &mut self,
        _s: S,
        _n: N,
        ctl: C,
        _m: M,
        mut gatt: G,
    ) -> Result<(), Error>
    where
        S: NetStack,
        N: NetifDiag + NetChangeNotif,
        C: NetCtl + ThreadDiag + NetChangeNotif,
        M: Mdns,
        G: GattPeripheral,
    {
        // The stack's BLE task: runs the peripheral next to the commissioning.
        let btp = Btp::new();
        let adv = AdvData::new(&rs_matter::dm::devices::test::TEST_DEV_DET, 3840);
        let ble = gatt.run(&btp, "BT", &adv);
        let commission = async {
            Timer::after(TDuration::from_secs(5)).await;
            self.disabled_before.set(self.ot.role() == Role::Disabled);
            ctl.connect(&WirelessCreds::Thread {
                dataset_tlv: self.inner.ds,
            })
            .await
            .map_err(|_| Error::new(ErrorCode::Invalid))?;
            self.inner.joined_at.set(Some((self.inner.now)()));
            pending().await
        };
        match select(ble, commission).await {
            Either::First(r) => r,
            Either::Second(r) => r,
        }
    }
}

#[test]
fn coex_runner_attaches_on_connect_while_ble_runs() {
    let _serial = serial();
    let kv = MemKv::new();
    let clks = [clock(), clock()];
    let air = Air::new(2);
    let pend = [Cell::new(None), Cell::new(None)];
    let res0: Res<'_> = Res::new(instance(1), &clks[0]);
    let ots0 = Ot::new(&res0);
    let ds = make_dataset(ots0);
    let tlvs = ds.as_bytes().to_vec();
    start_with(ots0, &ds, true);
    let res1: Res<'_> = Res::new(instance(2), &clks[1]);
    let ot1 = Ot::new(&res1);
    let joined = Cell::new(None);
    let gatt_runs = Cell::new(0);
    let disabled_before = Cell::new(false);
    let now = || clks[1].now();
    let runner = ThreadRunner::new(
        ot1,
        AirRadio { air: &air, id: 1 },
        TestAlarm::new(&clks[1], &pend[1]),
        &kv,
    );
    let mut coex = ThreadCoexRunner::new(runner, IdleGatt(&gatt_runs));
    let task = BleThenConnect {
        inner: ConnectTask {
            ds: &tlvs,
            joined_at: &joined,
            now: &now,
        },
        disabled_before: &disabled_before,
        ot: ot1,
    };
    let tasks = vec![
        run_task(ots0, &air, 0, &clks[0], &pend[0]),
        Box::pin(async {
            let _ = coex.run(task).await;
        }),
    ];
    drive(
        &[&clks[0], &clks[1]],
        &[&pend[0], &pend[1]],
        tasks,
        async {
            wait_role(ots0, Role::Leader).await;
            while joined.get().is_none() {
                Timer::after(TDuration::from_millis(100)).await;
            }
            Timer::after(TDuration::from_secs(5)).await;
            assert!(matches!(ot1.role(), Role::Child | Role::Router));
        },
        limit(),
    );
    assert!(
        disabled_before.get(),
        "Thread stays off until ConnectNetwork"
    );
    assert_eq!(
        gatt_runs.get(),
        1,
        "the BLE peripheral ran once, next to Thread"
    );
}

#[test]
fn settings_survive_a_restart() {
    let _serial = serial();
    let kv = MemKv::new();
    let clks = [clock(), clock()];
    let air = Air::new(2);
    let pend = [Cell::new(None), Cell::new(None)];
    let res0: Res<'_> = Res::new(instance(1), &clks[0]);
    let ots0 = Ot::new(&res0);
    let ds = make_dataset(ots0);
    let tlvs = ds.as_bytes().to_vec();
    start_with(ots0, &ds, true);

    // First boot: attach, persist.
    let (rloc, part, attach_time) = {
        let res1: Res<'_> = Res::new(instance(2), &clks[1]);
        let ot1 = Ot::new(&res1);
        let joined = Cell::new(None);
        let started = Cell::new(Instant::from_secs(0));
        let now = || clks[1].now();
        let mut runner = ThreadRunner::new(
            ot1,
            AirRadio { air: &air, id: 1 },
            TestAlarm::new(&clks[1], &pend[1]),
            &kv,
        );
        let task = ConnectTask {
            ds: &tlvs,
            joined_at: &joined,
            now: &now,
        };
        let tasks = vec![
            run_task(ots0, &air, 0, &clks[0], &pend[0]),
            Box::pin(async {
                started.set(clks[1].now());
                let _ = runner.run(task).await;
            }),
        ];
        drive(
            &[&clks[0], &clks[1]],
            &[&pend[0], &pend[1]],
            tasks,
            async {
                wait_role(ots0, Role::Leader).await;
                while joined.get().is_none() {
                    Timer::after(TDuration::from_millis(100)).await;
                }
                // Joined; let the debounce time pass.
                Timer::after(TDuration::from_secs(30)).await;
                assert!(matches!(ot1.role(), Role::Child | Role::Router));
                (
                    ot1.rloc16(),
                    ot1.with(|i, _| i.partition_id()),
                    joined.get().unwrap() - started.get(),
                )
            },
            limit(),
        )
    };
    let blob = kv.blob(THREAD_SETTINGS_KEY).expect("blob written");
    assert!(!blob.is_empty());
    assert!(kv.writes() >= 1);
    assert_eq!(part, ots0.with(|i, _| i.partition_id()));

    // Power cycle: a new instance with empty settings and the same
    // identity; the runner loads the blob and `connect` restores the
    // attachment.
    let writes_before = kv.writes();
    let res1: Res<'_> = Res::new(instance(2), &clks[1]);
    let ot1 = Ot::new(&res1);
    assert_eq!(
        ot1.with(|i, _| i.settings().count(SettingsKey::NetworkInfo)),
        0
    );
    let joined = Cell::new(None);
    let started = Cell::new(Instant::from_secs(0));
    let now = || clks[1].now();
    let mut runner = ThreadRunner::new(
        ot1,
        AirRadio { air: &air, id: 1 },
        TestAlarm::new(&clks[1], &pend[1]),
        &kv,
    );
    let task = ConnectTask {
        ds: &tlvs,
        joined_at: &joined,
        now: &now,
    };
    let tasks = vec![
        run_task(ots0, &air, 0, &clks[0], &pend[0]),
        Box::pin(async {
            started.set(clks[1].now());
            let _ = runner.run(task).await;
        }),
    ];
    drive(
        &[&clks[0], &clks[1]],
        &[&pend[0], &pend[1]],
        tasks,
        async {
            while joined.get().is_none() {
                Timer::after(TDuration::from_millis(50)).await;
            }
            let restore_time = joined.get().unwrap() - started.get();
            assert_eq!(ot1.rloc16(), rloc);
            assert_eq!(ot1.with(|i, _| i.partition_id()), part);
            assert!(
                restore_time < attach_time,
                "restore {restore_time:?} vs attach {attach_time:?}"
            );
            Timer::after(TDuration::from_secs(30)).await;
        },
        limit(),
    );
    let more = kv.writes() - writes_before;
    assert!(more <= 3, "{more} writes after the restart");
}

#[test]
fn write_rate_is_bounded_under_traffic() {
    let _serial = serial();
    let kv = MemKv::new();
    let clks = [clock(), clock()];
    let air = Air::new(2);
    let pend = [Cell::new(None), Cell::new(None)];
    let res0: Res<'_> = Res::new(instance(1), &clks[0]);
    let res1: Res<'_> = Res::new(instance(2), &clks[1]);
    let ots = [Ot::new(&res0), Ot::new(&res1)];
    let ds = make_dataset(ots[0]);
    let tlvs = ds.as_bytes().to_vec();
    start_with(ots[0], &ds, true);
    let joined = Cell::new(None);
    let now = || clks[1].now();
    let mut runner = ThreadRunner::new(
        ots[1],
        AirRadio { air: &air, id: 1 },
        TestAlarm::new(&clks[1], &pend[1]),
        &kv,
    );
    let task = ConnectTask {
        ds: &tlvs,
        joined_at: &joined,
        now: &now,
    };
    let tasks = vec![
        run_task(ots[0], &air, 0, &clks[0], &pend[0]),
        Box::pin(async {
            let _ = runner.run(task).await;
        }),
    ];
    let pings = 2600u32;
    drive(
        &[&clks[0], &clks[1]],
        &[&pend[0], &pend[1]],
        tasks,
        async {
            wait_role(ots[0], Role::Leader).await;
            while joined.get().is_none() {
                Timer::after(TDuration::from_millis(100)).await;
            }
            Timer::after(TDuration::from_secs(30)).await;
            let base = kv.writes();
            let dst = ots[0].with(|i, _| i.ml_eid());
            let start = clks[1].now();
            for _ in 0..pings {
                ots[1]
                    .ping(dst, None, &[0; 8], Duration::from_secs(2))
                    .await
                    .unwrap();
                Timer::after(TDuration::from_millis(100)).await;
            }
            Timer::after(TDuration::from_secs(30)).await;
            let writes = kv.writes() - base;
            let secs = (clks[1].now() - start).as_secs();
            // The store-ahead distance is 1000 frames: a few network info
            // writes, far fewer than one per debounce window.
            assert!(writes >= 1, "no write under traffic");
            assert!(writes <= 8, "{writes} writes in {secs} s for {pings} pings");
            assert!(u64::from(writes) < secs / 5 / 2);
        },
        limit(),
    );
}

#[test]
fn runner_can_be_dropped_and_restarted() {
    let _serial = serial();
    let kv = MemKv::new();
    let clks = [clock(), clock()];
    let air = Air::new(2);
    let pend = [Cell::new(None), Cell::new(None)];
    let res0: Res<'_> = Res::new(instance(1), &clks[0]);
    let res1: Res<'_> = Res::new(instance(2), &clks[1]);
    let ots = [Ot::new(&res0), Ot::new(&res1)];
    let ds = make_dataset(ots[0]);
    let tlvs = ds.as_bytes().to_vec();
    start_with(ots[0], &ds, true);
    let joined = Cell::new(None);
    let now = || clks[1].now();
    let mut runner = ThreadRunner::new(
        ots[1],
        AirRadio { air: &air, id: 1 },
        TestAlarm::new(&clks[1], &pend[1]),
        &kv,
    );
    // Run 1: the task ends after a while; pending settings are flushed.
    {
        let task = JoinThenReturn(
            ConnectTask {
                ds: &tlvs,
                joined_at: &joined,
                now: &now,
            },
            20,
        );
        let tasks = vec![
            run_task(ots[0], &air, 0, &clks[0], &pend[0]),
            Box::pin(async {
                runner.run(task).await.unwrap();
                pending::<()>().await;
            }),
        ];
        drive(
            &[&clks[0], &clks[1]],
            &[&pend[0], &pend[1]],
            tasks,
            async {
                wait_role(ots[0], Role::Leader).await;
                while joined.get().is_none() {
                    Timer::after(TDuration::from_millis(100)).await;
                }
                Timer::after(TDuration::from_secs(25)).await;
            },
            limit(),
        );
    }
    assert!(kv.writes() >= 1, "written by the time the task ended");
    let part = ots[1].with(|i, _| i.partition_id());
    assert!(matches!(ots[1].role(), Role::Child | Role::Router));

    // Runs 2 and 3 on the same runner and resources; each is dropped
    // mid-run when `drive` returns. The settings are not loaded again over
    // the live ones and the node stays attached.
    for _ in 0..2 {
        joined.set(None);
        let task = ConnectTask {
            ds: &tlvs,
            joined_at: &joined,
            now: &now,
        };
        let tasks = vec![
            run_task(ots[0], &air, 0, &clks[0], &pend[0]),
            Box::pin(async {
                let _ = runner.run(task).await;
            }),
        ];
        drive(
            &[&clks[0], &clks[1]],
            &[&pend[0], &pend[1]],
            tasks,
            async {
                while joined.get().is_none() {
                    Timer::after(TDuration::from_millis(100)).await;
                }
                Timer::after(TDuration::from_secs(10)).await;
                assert!(matches!(ots[1].role(), Role::Child | Role::Router));
                assert_eq!(ots[1].with(|i, _| i.partition_id()), part);
            },
            limit(),
        );
    }
    assert!(runner.persist().loaded());
}

#[test]
fn blob_format_round_trips() {
    use SettingsKey as K;
    let mut a = RamSettings::<512>::new();
    a.set(K::ActiveDataset, &[1, 2, 3]).unwrap();
    a.add(K::ChildInfo, &[9]).unwrap();
    a.add(K::ChildInfo, &[8, 8]).unwrap();
    a.set(K::BrUlaPrefix, &[7; 8]).unwrap(); // not persisted
    let mut buf = [0u8; 64];
    let n = serialize(&a, &mut buf).unwrap();
    assert_eq!(
        &buf[..n],
        &[1, 0, 3, 0, 1, 2, 3, 5, 0, 1, 0, 9, 5, 0, 2, 0, 8, 8]
    );
    let mut b = RamSettings::<512>::new();
    b.set(K::PendingDataset, &[5]).unwrap(); // replaced by the load
    assert_eq!(deserialize(&mut b, &buf[..n]).unwrap(), 3);
    assert_eq!(b.count(K::ChildInfo), 2);
    assert_eq!(b.count(K::PendingDataset), 0);
    assert_eq!(b.count(K::BrUlaPrefix), 0);
    let mut buf2 = [0u8; 64];
    assert_eq!(serialize(&b, &mut buf2).unwrap(), n);
    assert_eq!(buf[..n], buf2[..n]);
    // Too small.
    assert!(serialize(&a, &mut [0u8; 8]).is_err());
    // A truncated blob keeps the complete records.
    let mut c = RamSettings::<512>::new();
    assert_eq!(deserialize(&mut c, &buf[..n - 1]).unwrap(), 2);
}
