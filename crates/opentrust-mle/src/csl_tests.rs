//! SSED (child side of CSL): parameters in Child Update Requests, the MAC
//! configuration, poll period, response wait, and the CSL parent metric in
//! parent selection.

use opentrust_core::time::Duration;
use opentrust_core::types::Rloc16;
use opentrust_mac::security::KeySeqUpdate;

use crate::attach_tests::{FakeParent, T0, advance, challenge_of, decode, first_parent_request};
use crate::child_tests::{SLEEPY, attached, attached_with};
use crate::env::Role;
use crate::message::Command;
use crate::mle::{Mle, MleConfig};
use crate::test_support::{TestEnv, ext, ll};
use crate::tlv::{CslClockAccuracy, DeviceMode};

/// 500 ms in units of 10 symbols.
const PERIOD: u16 = 3125;

const GOOD: CslClockAccuracy = CslClockAccuracy {
    accuracy_ppm: 20,
    uncertainty_10us: 5,
};
const BAD: CslClockAccuracy = CslClockAccuracy {
    accuracy_ppm: 100,
    uncertainty_10us: 40,
};

fn csl_cfg() -> MleConfig {
    let mut cfg = MleConfig::new(SLEEPY);
    cfg.csl_period = PERIOD;
    cfg
}

#[test]
fn ssed_announces_csl_parameters_after_attach() {
    let (mut child, mut env, mut p, t) = attached_with(csl_cfg(), Some(GOOD));
    assert!(child.is_csl_enabled());
    // The MAC samples every period, on the PAN channel, for the parent; the
    // accuracy from the Parent Response is applied.
    assert_eq!(env.csl, Some((PERIOD, 0, p.env.ext, Rloc16(0x0400))));
    assert_eq!(env.csl_accuracy, Some(GOOD));
    assert_eq!(child.parent_csl_accuracy(), Some(GOOD));
    // CSL timeout (100 s) bounds the poll period: 100 s - 1 s lead.
    assert_eq!(env.poll, Some(Duration::from_secs(99)));
    // A Child Update Request with the CSL TLVs follows shortly.
    let t1 = advance(&mut child, &mut env, t);
    assert_eq!(t1 - t, Duration::from_millis(100));
    let out = env.take_out();
    assert_eq!(out.len(), 1);
    decode(&out[0], &p.env, |rx| {
        assert_eq!(rx.command, Command::ChildUpdateRequest);
        assert_eq!(rx.tlvs.csl_timeout().unwrap(), 100);
        let ch = rx.tlvs.csl_channel().unwrap();
        assert_eq!((ch.page, ch.channel), (0, 0));
        assert_eq!(rx.tlvs.timeout().unwrap(), 240);
    });
    // The response is only sent in a sample window: wait one CSL period
    // longer than the plain one second.
    assert_eq!(
        child.next_deadline(),
        Some(t1 + Duration::from_millis(500 + 1000))
    );
    // The parent answers with the (changed) accuracy: the MAC window shrinks.
    let rloc = p.rloc;
    let resp = p.msg(&env, Command::ChildUpdateResponse, |w| {
        w.source_address(rloc)?;
        w.leader_data(&FakeParent::leader())?;
        w.mode(SLEEPY)?;
        w.timeout(240)?;
        w.csl_clock_accuracy(BAD)
    });
    TestEnv::deliver(&resp, &mut child, &mut env, t1, -60).unwrap();
    assert_eq!(env.csl_accuracy, Some(BAD));
    assert_eq!(child.parent_csl_accuracy(), Some(BAD));
}

#[test]
fn csl_channel_and_timeout_are_configurable() {
    let mut cfg = csl_cfg();
    cfg.csl_channel = 20;
    cfg.csl_timeout_secs = 30;
    let (mut child, mut env, p, t) = attached_with(cfg, None);
    assert_eq!(env.csl.map(|c| c.1), Some(20));
    assert_eq!(env.poll, Some(Duration::from_secs(29)));
    // Parent without CSL accuracy: worst case.
    assert_eq!(child.parent_csl_accuracy(), Some(CslClockAccuracy::WORST));
    advance(&mut child, &mut env, t);
    let out = env.take_out();
    decode(&out[0], &p.env, |rx| {
        assert_eq!(rx.tlvs.csl_channel().unwrap().channel, 20);
        assert_eq!(rx.tlvs.csl_timeout().unwrap(), 30);
    });
    // A longer CSL timeout than the child timeout does not stretch the poll.
    let t = T0 + Duration::from_secs(5);
    child.set_csl_timeout(&mut env, t, 1000);
    assert_eq!(env.poll, Some(Duration::from_secs(239)));
    // 0: advertise the child timeout.
    child.set_csl_timeout(&mut env, t, 0);
    assert_eq!(child.csl_timeout(), 0);
    child.set_csl_period(&mut env, t, 0);
    assert_eq!(env.csl, None);
    assert_eq!(env.poll, Some(Duration::from_secs(236)));
}

#[test]
fn csl_off_for_rx_on_child_and_old_parent() {
    // An rx-on-when-idle child never uses CSL.
    let mut cfg = MleConfig::new(DeviceMode::new(true, false, true));
    cfg.csl_period = PERIOD;
    let (child, env, _p, _t) = attached_with(cfg, None);
    assert!(!child.is_csl_enabled());
    assert_eq!(env.csl, None);
    // Without CSL configured a sleepy child polls as before.
    let (child, env, _p, _t) = attached(SLEEPY);
    assert!(!child.is_csl_enabled());
    assert_eq!(env.csl, None);
    assert_eq!(env.poll, Some(Duration::from_secs(236)));
}

#[test]
fn csl_follows_mode_changes_and_detach() {
    let (mut child, mut env, _p, t) = attached_with(csl_cfg(), Some(GOOD));
    assert!(env.csl.is_some());
    // Becoming rx-on-when-idle ends CSL.
    child
        .set_device_mode(&mut env, t, DeviceMode::new(true, false, true))
        .unwrap();
    assert_eq!(env.csl, None);
    assert_eq!(env.poll, None);
    // And back to sleepy resumes it.
    child.set_device_mode(&mut env, t, SLEEPY).unwrap();
    assert!(env.csl.is_some());
    // Losing the parent turns CSL off.
    child.set_csl_period(&mut env, t, 0);
    assert_eq!(env.csl, None);
    child.set_csl_period(&mut env, t, PERIOD);
    assert!(env.csl.is_some());
    let mut t = t;
    for _ in 0..40 {
        if child.role() == Role::Detached {
            break;
        }
        t = advance(&mut child, &mut env, t);
        env.take_out();
    }
    assert_eq!(child.role(), Role::Detached);
    assert_eq!(env.csl, None);
}

/// Child attaches to the best of two parents; P2 answers first.
fn attach_with_accuracies(
    cfg: MleConfig,
    acc1: CslClockAccuracy,
    acc2: CslClockAccuracy,
) -> core::net::Ipv6Addr {
    let mut env = TestEnv::new(1);
    let mut child: Mle<0> = Mle::new(cfg);
    let (req, t) = first_parent_request(&mut child, &mut env);
    let ch = challenge_of(&req, &env);
    let mut p1 = FakeParent::new(10, 0x0400);
    let mut p2 = FakeParent::new(11, 0x0800);
    p1.csl_accuracy = Some(acc1);
    p2.csl_accuracy = Some(acc2);
    for p in [&mut p1, &mut p2] {
        p.env
            .keys
            .set_key_sequence(5, KeySeqUpdate::FORCE, t)
            .unwrap();
    }
    let r2 = p2.parent_response(&env, &ch);
    let r1 = p1.parent_response(&env, &ch);
    let t1 = t + Duration::from_millis(100);
    TestEnv::deliver(&r2, &mut child, &mut env, t1, -60).unwrap();
    TestEnv::deliver(&r1, &mut child, &mut env, t1, -60).unwrap();
    advance(&mut child, &mut env, t1);
    env.take_out().pop().unwrap().dst
}

#[test]
fn parent_selection_prefers_better_csl_accuracy_for_sleepy_child() {
    // Equal in every other respect: the more accurate parent wins although
    // the other answered first.
    let dst = attach_with_accuracies(csl_cfg(), GOOD, BAD);
    assert_eq!(dst, ll(&ext(10)));
    let dst = attach_with_accuracies(csl_cfg(), BAD, GOOD);
    assert_eq!(dst, ll(&ext(11)));
}

#[test]
fn parent_selection_ignores_csl_accuracy_for_rx_on_child() {
    // The first responder stays (nothing better in any other respect).
    let cfg = MleConfig::new(DeviceMode::new(true, false, true));
    let dst = attach_with_accuracies(cfg, GOOD, BAD);
    assert_eq!(dst, ll(&ext(11)));
}
