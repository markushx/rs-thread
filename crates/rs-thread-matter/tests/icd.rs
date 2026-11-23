//! The ICD hooks: a poll period change of rs-matter's `Icd` reaches the node.
mod common;

use core::cell::Cell;

use common::*;
use embassy_futures::select::{Either, select};
use rs_thread_core::time::Duration;
use rs_thread_matter::icd::IcdFollower;
use rs_matter::dm::clusters::icd_mgmt::{Icd, IcdModeConfig, IcdNetParams, IcdPowerMode};
use rs_matter::utils::timers::{Duration as TDuration, Timer};

const CFG: IcdModeConfig = IcdModeConfig {
    idle_mode_duration_s: 60,
    active_mode_duration_ms: 1000,
    active_mode_threshold_ms: 500,
    user_active_mode_trigger_hint: 0,
    user_active_mode_trigger_instruction: "",
};

#[test]
fn poll_period_follows_the_icd_power_mode() {
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
    let icd = Icd::new(CFG);
    drive(
        &[&clks[0], &clks[1]],
        &[&pend[0], &pend[1]],
        tasks,
        async {
            let follower = IcdFollower::new(ots[1]);
            // Sleepy before attaching, so the parent keeps the child as a
            // sleepy one and the child polls.
            follower.set_sleepy(true).unwrap();
            form_network(&ots, &ds).await;
            let poll = || ots[1].with(|i, _| i.mac().poll_period());

            // A freshly booted ICD is active: `run` applies the fast
            // interval at once.
            let active = icd.net_params();
            assert_eq!(active.power_mode, IcdPowerMode::Active);
            let driver = async {
                Timer::after(TDuration::from_millis(100)).await;
            };
            match select(core::pin::pin!(follower.run(&icd)), driver).await {
                Either::First(never) => match never {},
                Either::Second(()) => {}
            }
            assert_eq!(
                poll(),
                Duration::from_millis(u64::from(active.poll_interval_ms))
            );

            // A change of the interval (idle mode, a configured SII) is
            // applied; the effective period is the shorter of it and the
            // stack's own one.
            let slower = IcdNetParams {
                poll_interval_ms: 3 * active.poll_interval_ms,
                ..active
            };
            follower.apply(&slower);
            assert!(poll() > Duration::from_millis(300));
            assert!(poll() <= Duration::from_millis(900));
            let faster = IcdNetParams {
                poll_interval_ms: 100,
                ..active
            };
            follower.apply(&faster);
            assert_eq!(poll(), Duration::from_millis(100));
            // The user period is cleared with 0: back to the stack's one.
            follower.apply(&IcdNetParams {
                poll_interval_ms: 0,
                ..active
            });
            assert!(poll() > Duration::from_millis(100));
        },
        limit(),
    );
}
