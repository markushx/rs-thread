use opentrust_core::time::{Duration, Instant};
use opentrust_core::types::Rloc16;

use crate::attach_tests::{FakeParent, T0, advance, challenge_of, decode};
use crate::env::{MleEvent, Role};
use crate::message::Command;
use crate::mle::{Mle, MleConfig};
use crate::test_support::{Out, TestEnv};
use crate::tlv::{DeviceMode, LeaderData, STATUS_ERROR, ty};

pub(crate) const RX_ON: DeviceMode = DeviceMode::new(true, false, true);
pub(crate) const SLEEPY: DeviceMode = DeviceMode::new(false, false, false);

/// Child attached to a fake parent (rloc 0x0400, child rloc 0x0401).
pub(crate) fn attached(mode: DeviceMode) -> (Mle<0>, TestEnv, FakeParent, Instant) {
    let mut env = TestEnv::new(1);
    let mut child: Mle<0> = Mle::new(MleConfig::new(mode));
    child.start(&mut env, T0).unwrap();
    let t = advance(&mut child, &mut env, T0);
    let req = env.take_out().pop().unwrap();
    let ch = challenge_of(&req, &env);
    let mut p = FakeParent::new(10, 0x0400);
    let r = p.parent_response(&env, &ch);
    TestEnv::deliver(&r, &mut child, &mut env, t, -60).unwrap();
    let t = advance(&mut child, &mut env, t);
    env.take_out();
    let resp = p.child_id_response(&env, 0x0401);
    TestEnv::deliver(&resp, &mut child, &mut env, t, -60).unwrap();
    assert_eq!(child.role(), Role::Child);
    (child, env, p, t)
}

fn newer_leader() -> LeaderData {
    LeaderData {
        data_version: 8,
        stable_data_version: 4,
        ..FakeParent::leader()
    }
}

fn cu_response(p: &mut FakeParent, env: &TestEnv, mode: DeviceMode, timeout: u32) -> Out {
    let rloc = p.rloc;
    p.msg(env, Command::ChildUpdateResponse, |w| {
        w.source_address(rloc)?;
        w.leader_data(&FakeParent::leader())?;
        w.mode(mode)?;
        w.timeout(timeout)
    })
}

#[test]
fn keep_alive_for_rx_on_child() {
    let (mut child, mut env, mut p, t) = attached(RX_ON);
    assert!(env.rx_on && env.poll.is_none());
    // Attach counter reset after 20 s, keep-alive after timeout - 4 s.
    let t1 = advance(&mut child, &mut env, t);
    assert_eq!(t1 - t, Duration::from_secs(20));
    assert!(env.out.is_empty());
    let t2 = advance(&mut child, &mut env, t1);
    assert_eq!(t2 - t, Duration::from_secs(236));
    let out = env.take_out();
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].dst, crate::test_support::ll(&p.env.ext));
    decode(&out[0], &p.env, |rx| {
        assert_eq!(rx.command, Command::ChildUpdateRequest);
        let t = &rx.tlvs;
        assert_eq!(t.mode().unwrap(), RX_ON);
        assert_eq!(t.source_address().unwrap(), Rloc16(0x0401));
        assert_eq!(t.leader_data().unwrap(), FakeParent::leader());
        assert_eq!(t.timeout().unwrap(), 240);
        assert!(!t.contains(ty::CHALLENGE));
    });
    let resp = cu_response(&mut p, &env, RX_ON, 240);
    let t3 = t2 + Duration::from_millis(10);
    assert_eq!(
        TestEnv::deliver(&resp, &mut child, &mut env, t3, -60),
        Ok(Command::ChildUpdateResponse)
    );
    assert_eq!(child.next_deadline(), Some(t3 + Duration::from_secs(236)));
    assert_eq!(child.role(), Role::Child);
}

#[test]
fn parent_loss_detaches_and_reattaches() {
    let (mut child, mut env, p, t) = attached(RX_ON);
    let mut t = advance(&mut child, &mut env, t); // attach counter reset
    let mut requests = 0;
    while child.role() == Role::Child {
        t = advance(&mut child, &mut env, t);
        for o in env.take_out() {
            decode(&o, &p.env, |rx| {
                assert_eq!(rx.command, Command::ChildUpdateRequest)
            });
            requests += 1;
        }
    }
    // 1 keep-alive + 3 retries, then the 4th timeout detaches.
    assert_eq!(requests, 4);
    assert_eq!(child.role(), Role::Detached);
    assert!(child.parent().is_none());
    assert!(env.parent.is_none());
    assert_eq!(env.short, Rloc16::INVALID);
    assert!(env.has_event(MleEvent::ParentLost));
    // Re-attach starts with a Parent Request.
    let _ = advance(&mut child, &mut env, t);
    let out = env.take_out();
    assert_eq!(out.len(), 1);
    decode(&out[0], &p.env, |rx| {
        assert_eq!(rx.command, Command::ParentRequest)
    });
}

#[test]
fn sleepy_child_supervision() {
    let (mut child, mut env, _p, t) = attached(SLEEPY);
    assert_eq!(env.poll, Some(Duration::from_secs(236)));
    assert!(!env.rx_on);
    // No keep-alive timer for a sleepy child; supervision check after 190 s.
    let t1 = advance(&mut child, &mut env, t);
    assert_eq!(t1 - t, Duration::from_secs(20));
    assert_eq!(child.next_deadline(), Some(t + Duration::from_secs(190)));
    // A frame from the parent postpones the check.
    child.parent_frame_received(t + Duration::from_secs(100));
    assert_eq!(child.next_deadline(), Some(t + Duration::from_secs(290)));
    let t2 = advance(&mut child, &mut env, t1);
    assert_eq!(t2, t + Duration::from_secs(290));
    let out = env.take_out();
    assert_eq!(out.len(), 1);
    // The probe is a Child Update Request, and the check restarts.
    assert_eq!(child.next_deadline(), Some(t2 + Duration::from_secs(1)));
}

#[test]
fn child_update_request_with_new_leader_data_triggers_data_request() {
    let (mut child, mut env, mut p, t) = attached(RX_ON);
    let rloc = p.rloc;
    let req = p.msg(&env, Command::ChildUpdateRequest, |w| {
        w.source_address(rloc)?;
        w.leader_data(&newer_leader())?;
        w.challenge(&[7; 8])?;
        w.tlv_request(&[ty::TIMEOUT])
    });
    let t = t + Duration::from_secs(1);
    assert_eq!(
        TestEnv::deliver(&req, &mut child, &mut env, t, -60),
        Ok(Command::ChildUpdateRequest)
    );
    let out = env.take_out();
    assert_eq!(out.len(), 2);
    decode(&out[0], &p.env, |rx| {
        assert_eq!(rx.command, Command::DataRequest);
        assert_eq!(rx.tlvs.tlv_request().unwrap(), &[ty::NETWORK_DATA]);
    });
    decode(&out[1], &p.env, |rx| {
        assert_eq!(rx.command, Command::ChildUpdateResponse);
        let t = &rx.tlvs;
        assert_eq!(t.response().unwrap(), &[7; 8]);
        assert!(t.contains(ty::LINK_FRAME_COUNTER) && t.contains(ty::MLE_FRAME_COUNTER));
        assert_eq!(t.timeout().unwrap(), 240);
        assert_eq!(t.source_address().unwrap(), Rloc16(0x0401));
    });
    // Data Response applies the new Network Data.
    let data = p.msg(&env, Command::DataResponse, |w| {
        w.source_address(rloc)?;
        w.leader_data(&newer_leader())?;
        w.network_data(&[9, 9])
    });
    assert_eq!(
        TestEnv::deliver(&data, &mut child, &mut env, t, -60),
        Ok(Command::DataResponse)
    );
    assert_eq!(&env.nd[..], &[9, 9]);
    assert_eq!(child.leader_data().data_version, 8);
    assert!(env.has_event(MleEvent::NetworkDataChanged));
    // Same version again: ignored (no data request).
    let again = p.msg(&env, Command::DataResponse, |w| {
        w.source_address(rloc)?;
        w.leader_data(&newer_leader())?;
        w.network_data(&[1])
    });
    TestEnv::deliver(&again, &mut child, &mut env, t, -60).unwrap();
    assert_eq!(&env.nd[..], &[9, 9]);
}

#[test]
fn sleepy_child_retries_data_request_then_detaches() {
    let (mut child, mut env, mut p, t) = attached(SLEEPY);
    let rloc = p.rloc;
    // Child Update Request announcing newer data (sleepy child asks for it).
    let req = p.msg(&env, Command::ChildUpdateRequest, |w| {
        w.source_address(rloc)?;
        w.leader_data(&newer_leader())
    });
    TestEnv::deliver(&req, &mut child, &mut env, t, -60).unwrap();
    let mut requests = env
        .take_out()
        .iter()
        .filter(|o| decode(o, &p.env, |rx| rx.command == Command::DataRequest))
        .count();
    assert_eq!(requests, 1);
    let mut t = t;
    while child.role() == Role::Child {
        t = advance(&mut child, &mut env, t);
        requests += env
            .take_out()
            .iter()
            .filter(|o| decode(o, &p.env, |rx| rx.command == Command::DataRequest))
            .count();
        if requests > 10 {
            break;
        }
    }
    // First request + 4 retries... capped by MAX_CHILD_KEEP_ALIVE_ATTEMPTS.
    assert_eq!(requests, 5);
    assert_eq!(child.role(), Role::Detached);
}

#[test]
fn status_error_and_wrong_parent_address_detach() {
    for bad in 0..2 {
        let (mut child, mut env, mut p, t) = attached(RX_ON);
        let rloc = if bad == 1 { Rloc16(0x0800) } else { p.rloc };
        let req = p.msg(&env, Command::ChildUpdateRequest, |w| {
            w.source_address(rloc)?;
            w.leader_data(&FakeParent::leader())?;
            if bad == 0 {
                w.status(STATUS_ERROR)?;
            }
            Ok(())
        });
        TestEnv::deliver(&req, &mut child, &mut env, t, -60).unwrap();
        assert_eq!(child.role(), Role::Detached, "case {bad}");
    }
}

#[test]
fn mode_change_to_sleepy() {
    let (mut child, mut env, mut p, t) = attached(RX_ON);
    child.set_device_mode(&mut env, t, SLEEPY).unwrap();
    assert!(!env.rx_on);
    assert_eq!(env.poll, Some(Duration::from_secs(236)));
    let out = env.take_out();
    assert_eq!(out.len(), 1);
    decode(&out[0], &p.env, |rx| {
        assert_eq!(rx.command, Command::ChildUpdateRequest);
        assert_eq!(rx.tlvs.mode().unwrap(), SLEEPY);
        assert_eq!(rx.tlvs.supervision_interval().unwrap(), 129);
        assert!(rx.tlvs.contains(ty::ADDRESS_REGISTRATION));
    });
    // A response carrying the old mode is dropped, the new one accepted.
    let old = cu_response(&mut p, &env, RX_ON, 240);
    assert!(TestEnv::deliver(&old, &mut child, &mut env, t, -60).is_err());
    let new = cu_response(&mut p, &env, SLEEPY, 300);
    TestEnv::deliver(&new, &mut child, &mut env, t, -60).unwrap();
    // The parent's timeout is adopted and drives the poll period.
    assert_eq!(child.config().timeout_secs, 300);
    assert_eq!(env.poll, Some(Duration::from_secs(296)));
    assert_eq!(child.role(), Role::Child);
}

#[test]
fn timeout_change_informs_parent() {
    let (mut child, mut env, p, t) = attached(SLEEPY);
    child.set_timeout(&mut env, t, 1);
    assert_eq!(child.config().timeout_secs, 5);
    let out = env.take_out();
    assert_eq!(out.len(), 1);
    decode(&out[0], &p.env, |rx| {
        assert_eq!(rx.tlvs.timeout().unwrap(), 5)
    });
    assert_eq!(env.poll, Some(Duration::from_secs(1)));
}

#[test]
fn graceful_detach_of_a_child_sends_zero_timeout_and_stops() {
    let (mut child, mut env, mut p, t) = attached(RX_ON);
    env.take_out();
    child.detach_gracefully(&mut env, t).unwrap();
    assert_eq!(
        child.detach_gracefully(&mut env, t),
        Err(opentrust_core::Error::Busy)
    );
    let out = env.take_out();
    assert_eq!(out.len(), 1);
    decode(&out[0], &env, |rx| {
        assert_eq!(rx.command, Command::ChildUpdateRequest);
        assert_eq!(rx.tlvs.timeout().unwrap(), 0);
        assert!(rx.tlvs.contains(ty::MODE));
    });
    // The parent echoes the zero timeout: stop at once.
    assert_eq!(child.role(), Role::Child);
    let r = cu_response(&mut p, &env, RX_ON, 0);
    TestEnv::deliver(&r, &mut child, &mut env, t, -60).unwrap();
    assert_eq!(child.role(), Role::Disabled);
    assert!(env.has_event(MleEvent::DetachedGracefully));
}

#[test]
fn graceful_detach_without_answer_stops_after_one_second() {
    let (mut child, mut env, _p, t) = attached(RX_ON);
    child.detach_gracefully(&mut env, t).unwrap();
    child.poll(&mut env, t + Duration::from_millis(999));
    assert_eq!(child.role(), Role::Child);
    child.poll(&mut env, t + Duration::from_millis(1000));
    assert_eq!(child.role(), Role::Disabled);
    assert!(env.has_event(MleEvent::DetachedGracefully));
    // Disabled and detached devices report without a message.
    env.events.clear();
    child.detach_gracefully(&mut env, t).unwrap();
    assert!(env.has_event(MleEvent::DetachedGracefully));
}
