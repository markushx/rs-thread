use opentrust_core::Error;
use opentrust_core::settings::NetworkInfo;
use opentrust_core::time::{Duration, Instant};
use opentrust_core::types::{Iid, Rloc16};
use opentrust_platform::settings::RamSettings;

use crate::attach_tests::{FakeParent, advance, decode};
use crate::child_tests::{RX_ON, SLEEPY, attached};
use crate::env::{MleEnv, Role};
use crate::message::Command;
use crate::mle::{Mle, MleConfig};
use crate::neighbor::NeighborState;
use crate::persist::Restored;
use crate::test_support::TestEnv;
use crate::tlv::{DeviceMode, ty};

/// A child attached to `p`, whose settings have been persisted.
fn persisted_child(mode: DeviceMode) -> (Mle<0>, TestEnv, FakeParent, Instant, RamSettings<1024>) {
    let (child, mut env, p, t) = attached(mode);
    let settings = core::mem::replace(&mut env.settings, RamSettings::new());
    (child, env, p, t, settings)
}

fn restart(settings: RamSettings<1024>, mode: DeviceMode) -> (Mle<0>, TestEnv) {
    // A different extended address: restore must bring the saved one back.
    let mut env = TestEnv::new(77);
    env.settings = settings;
    (Mle::new(MleConfig::new(mode)), env)
}

#[test]
fn network_info_and_parent_info_are_stored() {
    let (child, env, p, _t) = attached(RX_ON);
    let info = env.load_network_info().expect("stored on attach");
    assert_eq!(info.role, Role::Child as u8);
    assert_eq!(info.rloc16, Rloc16(0x0401));
    assert_eq!(info.device_mode, RX_ON.to_bits() & 0x0b);
    assert_eq!(info.key_sequence, env.keys.key_sequence());
    assert_eq!(info.ext_address, env.ext);
    assert_eq!(info.ml_iid, Iid([0xaa, 0, 0, 0, 0, 0, 0, 1]));
    assert_eq!(info.version, 5);
    // Counters are stored ahead of use.
    assert!(info.mle_frame_counter >= child.mle_frame_counter().current() + 1000);
    assert!(info.mac_frame_counter >= env.keys.frame_counter() + 1000);
    assert!(!child.mle_frame_counter().needs_store());
    let parent = env.load_parent_info().unwrap();
    assert_eq!(parent.ext_address, p.env.ext);
    assert_eq!(parent.version, 5);
}

#[test]
fn counter_is_stored_again_when_it_catches_up() {
    let (mut child, mut env, _p, t) = attached(RX_ON);
    let before = env.load_network_info().unwrap().mle_frame_counter;
    // Use up the stored-ahead distance.
    child.mle_frame_counter_mut().restore(before);
    child.mle_frame_counter_mut().stored(before);
    child.poll(&mut env, t + Duration::from_millis(1));
    let after = env.load_network_info().unwrap().mle_frame_counter;
    assert_eq!(after, before + 1000);
}

#[test]
fn restore_reattaches_with_child_update() {
    for mode in [RX_ON, SLEEPY] {
        let (child, env, mut p, t, settings) = persisted_child(mode);
        let stored_mle = child.mle_frame_counter().current() + 1000;
        let ext = env.ext;
        let (mut child2, mut env2) = restart(settings, mode);
        let t = t + Duration::from_secs(30);
        let r = child2.restore(&mut env2, t).unwrap();
        assert_eq!(
            r,
            Restored::Child {
                rloc16: Rloc16(0x0401)
            }
        );
        // Identity, short address and counters restored.
        assert_eq!(env2.ext, ext);
        assert_eq!(env2.short, Rloc16(0x0401));
        assert_eq!(child2.role(), Role::Detached);
        assert_eq!(child2.rloc16(), Rloc16(0x0401));
        assert!(env2.keys.frame_counter() >= env.keys.frame_counter() + 1000);
        let p2 = child2.parent().unwrap();
        assert_eq!(p2.router.neighbor.state, NeighborState::Restored);
        assert_eq!(p2.router.neighbor.rloc16, Rloc16(0x0400));
        // A Child Update Request with a challenge (and no source address) goes out.
        let out = env2.take_out();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].dst, crate::test_support::ll(&p.env.ext));
        let ch: [u8; 8] = decode(&out[0], &p.env, |rx| {
            assert_eq!(rx.command, Command::ChildUpdateRequest);
            let t = &rx.tlvs;
            assert_eq!(t.mode().unwrap(), mode);
            assert!(!t.contains(ty::SOURCE_ADDRESS) && !t.contains(ty::TIMEOUT));
            assert!(t.contains(ty::ADDRESS_REGISTRATION));
            t.challenge().unwrap().try_into().unwrap()
        });
        // The MLE counter continues at the stored value: nothing reused.
        assert_eq!(child2.mle_frame_counter().current(), stored_mle + 1);
        // The parent answers (it still has us as a child).
        let leader = FakeParent::leader();
        let resp = p.msg(&env2, Command::ChildUpdateResponse, |w| {
            w.source_address(Rloc16(0x0400))?;
            w.leader_data(&leader)?;
            w.response(&ch)?;
            w.link_frame_counter(1)?;
            w.mle_frame_counter(2)?;
            w.mode(mode)?;
            w.timeout(240)
        });
        assert_eq!(
            TestEnv::deliver(&resp, &mut child2, &mut env2, t, -60),
            Ok(Command::ChildUpdateResponse)
        );
        assert_eq!(child2.role(), Role::Child);
        assert_eq!(child2.rloc16(), Rloc16(0x0401));
        let p2 = child2.parent().unwrap();
        assert!(p2.router.neighbor.is_valid());
        assert_eq!(p2.router.neighbor.mle_replay.frame_counter(), Some(2));
        assert_eq!(env2.parent, Some((p.env.ext, Rloc16(0x0400))));
        // Leader data changed from the default: network data is requested.
        let out = env2.take_out();
        assert!(
            out.iter()
                .any(|o| decode(o, &p.env, |rx| rx.command == Command::DataRequest))
        );
        assert_eq!(*child2.leader_data(), leader);
        assert_eq!(env2.rx_on, mode.rx_on_when_idle());
    }
}

#[test]
fn restored_sleepy_child_polls_for_the_answer() {
    // The parent holds the Child Update Response of a sleepy child until it
    // polls: the restoring child polls the restored parent at once.
    let (_child, _env, p, t, settings) = persisted_child(SLEEPY);
    let (mut child2, mut env2) = restart(settings, SLEEPY);
    child2.restore(&mut env2, t).unwrap();
    assert_eq!(env2.attach_polling, Some(p.env.ext));
    let (_child, _env, _p, t, settings) = persisted_child(RX_ON);
    let (mut child3, mut env3) = restart(settings, RX_ON);
    child3.restore(&mut env3, t).unwrap();
    assert_eq!(env3.attach_polling, None);
}

#[test]
fn restore_with_wrong_challenge_response_is_rejected() {
    let (_child, _env, mut p, t, settings) = persisted_child(RX_ON);
    let (mut child2, mut env2) = restart(settings, RX_ON);
    child2.restore(&mut env2, t).unwrap();
    env2.take_out();
    let leader = FakeParent::leader();
    let resp = p.msg(&env2, Command::ChildUpdateResponse, |w| {
        w.source_address(Rloc16(0x0400))?;
        w.leader_data(&leader)?;
        w.response(&[1; 8])?;
        w.link_frame_counter(1)?;
        w.mle_frame_counter(2)?;
        w.mode(RX_ON)
    });
    assert_eq!(
        TestEnv::deliver(&resp, &mut child2, &mut env2, t, -60),
        Err(Error::Security)
    );
    assert_eq!(child2.role(), Role::Detached);
}

#[test]
fn silent_parent_falls_back_to_full_attach() {
    let (_child, _env, p, t, settings) = persisted_child(RX_ON);
    let (mut child2, mut env2) = restart(settings, RX_ON);
    child2.restore(&mut env2, t).unwrap();
    let mut t = t;
    let mut requests = env2.take_out().len();
    while child2.parent().is_some() {
        t = advance(&mut child2, &mut env2, t);
        for o in env2.take_out() {
            decode(&o, &p.env, |rx| {
                assert_eq!(rx.command, Command::ChildUpdateRequest)
            });
            requests += 1;
        }
    }
    // Initial request and 4 retries, 1 s apart.
    assert_eq!(requests, 5);
    assert_eq!(child2.role(), Role::Detached);
    assert_eq!(child2.rloc16(), Rloc16::INVALID);
    // A normal attach follows.
    advance(&mut child2, &mut env2, t);
    let out = env2.take_out();
    assert_eq!(out.len(), 1);
    decode(&out[0], &p.env, |rx| {
        assert_eq!(rx.command, Command::ParentRequest)
    });
}

#[test]
fn restore_error_cases() {
    // No record.
    let mut env = TestEnv::new(1);
    let mut mle: Mle<0> = Mle::new(MleConfig::new(RX_ON));
    assert_eq!(mle.restore(&mut env, Instant::ZERO), Err(Error::NotFound));
    // Child record without parent info.
    let mut info = NetworkInfo {
        role: Role::Child as u8,
        device_mode: RX_ON.to_bits() & 0x0b,
        rloc16: Rloc16(0x0401),
        key_sequence: 3,
        mle_frame_counter: 100,
        mac_frame_counter: 200,
        previous_partition_id: 0,
        ext_address: crate::test_support::ext(9),
        ml_iid: Iid([1; 8]),
        version: 5,
    };
    env.store_network_info(&info).unwrap();
    assert_eq!(mle.restore(&mut env, Instant::ZERO), Err(Error::NotFound));
    // Keys and counters are restored even then (OT restores them first).
    assert_eq!(env.keys.key_sequence(), 3);
    assert_eq!(env.keys.frame_counter(), 200);
    assert_eq!(mle.mle_frame_counter().current(), 100);
    // Wrong version / detached role.
    info.version = 4;
    env.store_network_info(&info).unwrap();
    assert_eq!(
        mle.restore(&mut env, Instant::ZERO),
        Err(Error::InvalidState)
    );
    info.version = 5;
    info.role = Role::Detached as u8;
    env.store_network_info(&info).unwrap();
    assert_eq!(
        mle.restore(&mut env, Instant::ZERO),
        Err(Error::InvalidState)
    );
    // A saved router only restores identity and counters.
    info.role = Role::Router as u8;
    info.device_mode = DeviceMode::new(true, true, true).to_bits() & 0x0b;
    info.rloc16 = Rloc16(0x0800);
    info.previous_partition_id = 0xabcd;
    env.store_network_info(&info).unwrap();
    // A router record of a device without the FTD bit in its mode.
    let mut mtd_info = info;
    mtd_info.device_mode = RX_ON.to_bits() & 0x0b & !0x02;
    env.store_network_info(&mtd_info).unwrap();
    assert_eq!(
        mle.restore(&mut env, Instant::ZERO),
        Err(Error::InvalidState)
    );
    env.store_network_info(&info).unwrap();
    let mut r: Mle<4> = Mle::new(MleConfig::new(DeviceMode::new(true, true, true)));
    assert_eq!(
        r.restore(&mut env, Instant::ZERO),
        Ok(Restored::Router {
            role: Role::Router,
            rloc16: Rloc16(0x0800),
            previous_partition_id: 0xabcd
        })
    );
    assert_eq!(env.ext, crate::test_support::ext(9));
}

#[test]
fn restore_starts_the_reattach_with_the_stored_datasets() {
    // OT `Mle::Start(kNormalAttach)`: a restore that fails continues with
    // the Active, then the Pending Dataset.
    let (_child, _env, _p, t, settings) = persisted_child(RX_ON);
    let (mut child2, mut env2) = restart(settings, RX_ON);
    child2.restore(&mut env2, t).unwrap();
    assert_eq!(child2.attach.reattach, crate::attach::ReattachState::Start);
}

#[test]
fn restore_keeps_the_stored_device_mode_bits() {
    // A device configured with `mode -` is not a full Thread device after
    // a reset, whatever the mode it is created with.
    let (_child, _env, _p, t, settings) = persisted_child(SLEEPY);
    assert!(!SLEEPY.full_thread_device());
    let (mut child2, mut env2) = restart(settings, RX_ON);
    child2.restore(&mut env2, t).unwrap();
    assert!(!child2.cfg.mode.full_thread_device());
}
