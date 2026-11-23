use core::net::Ipv6Addr;

use heapless::Vec;
use rs_thread_core::Error;
use rs_thread_core::time::{Duration, Instant};
use rs_thread_core::types::{Iid, Rloc16, ipv6};

use crate::attach_tests::{T0, decode};
use crate::env::{MleEvent, Role};
use crate::message::Command;
use crate::mle::{Mle, MleConfig, tx};
use crate::neighbor::{NeighborState, StateFilter};
use crate::parent::RouterInfo;
use crate::security::MleFrameCounter;
use crate::test_support::{MLP, Out, TestEnv, ll};
use crate::tlv::{Connectivity, DeviceMode, LeaderData, ParentPriority, ty};
use rs_thread_core::settings::ChildInfo;

pub(crate) const ROUTER_RLOC: Rloc16 = Rloc16(0x0400);
pub(crate) const FTD: DeviceMode = DeviceMode::new(true, true, true);
const RX_ON: DeviceMode = DeviceMode::new(true, false, true);
const SLEEPY: DeviceMode = DeviceMode::new(false, false, false);

pub(crate) fn leader() -> LeaderData {
    LeaderData {
        partition_id: 0x1122_3344,
        weighting: 64,
        data_version: 7,
        stable_data_version: 3,
        leader_router_id: 1,
    }
}

pub(crate) fn router() -> (Mle<4>, TestEnv) {
    let mut env = TestEnv::new(10);
    env.provided_nd = Vec::from_slice(&[0xaa, 0xbb, 0xcc]).unwrap();
    let mut mle: Mle<4> = Mle::new(MleConfig::new(FTD));
    let mut info = RouterInfo {
        connectivity: Connectivity {
            parent_priority: ParentPriority::Medium,
            link_quality_3: 1,
            leader_cost: 2,
            id_sequence: 9,
            active_routers: 3,
            ..Default::default()
        },
        accepting_children: true,
        ..Default::default()
    };
    info.route64
        .extend_from_slice(&[9, 0x80, 0, 0, 0, 0, 0, 0, 0, 0x11])
        .unwrap();
    mle.start(&mut env, T0).unwrap();
    mle.enter_router_role(&mut env, T0, Role::Router, ROUTER_RLOC, leader(), info)
        .unwrap();
    (mle, env)
}

struct FakeChild {
    env: TestEnv,
    counter: MleFrameCounter,
    mode: DeviceMode,
}

impl FakeChild {
    fn new(n: u8, mode: DeviceMode) -> Self {
        Self {
            env: TestEnv::new(n),
            counter: MleFrameCounter::new(),
            mode,
        }
    }

    fn msg(
        &mut self,
        dst: Ipv6Addr,
        cmd: Command,
        build: impl FnOnce(&mut crate::tlv::TlvWriter<'_>) -> rs_thread_core::Result<()>,
    ) -> Out {
        tx(&mut self.env, &mut self.counter, dst, cmd, build).unwrap();
        self.env.take_out().pop().unwrap()
    }

    fn parent_request(&mut self, scan: u8, challenge: [u8; 8]) -> Out {
        let mode = self.mode;
        self.msg(ipv6::LINK_LOCAL_ALL_ROUTERS, Command::ParentRequest, |w| {
            w.mode(mode)?;
            w.challenge(&challenge)?;
            w.scan_mask(scan)?;
            w.version(5)
        })
    }

    fn child_id_request(
        &mut self,
        parent: &TestEnv,
        response: &[u8],
        timeout: u32,
        sup: bool,
    ) -> Out {
        let mode = self.mode;
        let ml = self.env.ml_eid();
        let extra = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 5);
        let lfc = self.env.keys.frame_counter();
        let mfc = self.counter.current();
        self.msg(ll(&parent.ext), Command::ChildIdRequest, |w| {
            w.response(response)?;
            w.link_frame_counter(lfc)?;
            w.mle_frame_counter(mfc)?;
            w.mode(mode)?;
            w.timeout(timeout)?;
            w.version(5)?;
            if sup {
                w.supervision_interval(3)?;
            }
            if !mode.full_thread_device() {
                w.address_registration(&[
                    crate::tlv::AddressEntry::Compressed {
                        context_id: 0,
                        iid: ipv6::iid(&ml).0,
                    },
                    crate::tlv::AddressEntry::Uncompressed(extra),
                ])?;
            }
            w.tlv_request(&[ty::ADDRESS16, ty::NETWORK_DATA, ty::ROUTE64])
        })
    }
}

/// Run a child through Parent Request / Response; returns the parent's challenge.
fn parent_phase(
    p: &mut Mle<4>,
    penv: &mut TestEnv,
    c: &mut FakeChild,
    t: Instant,
) -> (Instant, [u8; 8]) {
    let req = c.parent_request(0x80, [3; 8]);
    assert_eq!(
        TestEnv::deliver(&req, p, penv, t, -60),
        Ok(Command::ParentRequest)
    );
    assert!(penv.out.is_empty(), "response is delayed");
    let due = t + Duration::from_millis(501);
    assert!(p.next_deadline().is_some());
    p.poll(penv, due);
    let out = penv.take_out();
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].dst, ll(&c.env.ext));
    let mut ch = [0u8; 8];
    decode(&out[0], &c.env, |rx| {
        assert_eq!(rx.command, Command::ParentResponse);
        let t = &rx.tlvs;
        assert_eq!(t.response().unwrap(), &[3; 8]);
        assert_eq!(t.source_address().unwrap(), ROUTER_RLOC);
        assert_eq!(t.leader_data().unwrap(), leader());
        assert_eq!(t.version().unwrap(), 5);
        assert_eq!(t.link_margin().unwrap(), 40);
        let conn = t.connectivity().unwrap();
        assert_eq!(
            (conn.leader_cost, conn.id_sequence, conn.active_routers),
            (2, 9, 3)
        );
        assert!(t.contains(ty::LINK_FRAME_COUNTER) && t.contains(ty::MLE_FRAME_COUNTER));
        ch.copy_from_slice(t.challenge().unwrap());
    });
    (due, ch)
}

#[test]
fn parent_response_and_child_id_exchange_for_rx_on_child() {
    let (mut p, mut penv) = router();
    let mut c = FakeChild::new(1, RX_ON);
    let (t, ch) = parent_phase(&mut p, &mut penv, &mut c, T0);
    // The child is tracked in ParentRequest state with a 5 s timeout.
    let ci = p
        .children()
        .find_by_ext(&c.env.ext, StateFilter::Any)
        .unwrap();
    assert_eq!(ci.neighbor.state, NeighborState::ParentRequest);
    assert_eq!(ci.timeout_secs, 5);

    // Wrong response is rejected.
    let bad = c.child_id_request(&penv, &[0; 8], 240, false);
    assert_eq!(
        TestEnv::deliver(&bad, &mut p, &mut penv, t, -60),
        Err(Error::Security)
    );
    let good = c.child_id_request(&penv, &ch, 240, false);
    assert_eq!(
        TestEnv::deliver(&good, &mut p, &mut penv, t, -60),
        Ok(Command::ChildIdRequest)
    );
    let out = penv.take_out();
    assert_eq!(out.len(), 1);
    decode(&out[0], &c.env, |rx| {
        assert_eq!(rx.command, Command::ChildIdResponse);
        let t = &rx.tlvs;
        assert_eq!(t.source_address().unwrap(), ROUTER_RLOC);
        assert_eq!(t.address16().unwrap(), Rloc16(0x0401));
        assert_eq!(t.leader_data().unwrap(), leader());
        assert_eq!(t.network_data().unwrap(), &[0xaa, 0xbb, 0xcc]);
        assert_eq!(t.route64().unwrap().router_count(), 1);
        assert!(t.contains(ty::ADDRESS_REGISTRATION));
    });
    let ci = p
        .children()
        .find_by_ext(&c.env.ext, StateFilter::Any)
        .unwrap();
    assert!(ci.neighbor.is_valid());
    assert_eq!(ci.neighbor.rloc16, Rloc16(0x0401));
    assert_eq!(ci.timeout_secs, 240);
    assert_eq!(ci.network_data_version, 7);
    assert!(penv.has_event(MleEvent::ChildAdded {
        ext: c.env.ext,
        rloc16: Rloc16(0x0401)
    }));
    // Persisted, and rx-on children get no indirect treatment.
    assert_eq!(penv.settings_child_count(), 1);
    assert!(penv.indirect.is_empty());

    // A second child gets the next child ID.
    let mut c2 = FakeChild::new(2, RX_ON);
    let (t2, ch2) = parent_phase(&mut p, &mut penv, &mut c2, t + Duration::from_secs(1));
    let req = c2.child_id_request(&penv, &ch2, 240, false);
    TestEnv::deliver(&req, &mut p, &mut penv, t2, -60).unwrap();
    let out = penv.take_out();
    decode(&out[0], &c2.env, |rx| {
        assert_eq!(rx.tlvs.address16().unwrap(), Rloc16(0x0402));
    });
}

#[test]
fn sleepy_child_gets_address_registration_and_indirect() {
    let (mut p, mut penv) = router();
    let mut c = FakeChild::new(1, SLEEPY);
    let (t, ch) = parent_phase(&mut p, &mut penv, &mut c, T0);
    let req = c.child_id_request(&penv, &ch, 240, true);
    TestEnv::deliver(&req, &mut p, &mut penv, t, -60).unwrap();
    let out = penv.take_out();
    decode(&out[0], &c.env, |rx| {
        let t = &rx.tlvs;
        assert_eq!(t.supervision_interval().unwrap(), 3);
        // MTD children get the same (stable) network data and a registration ack.
        assert!(t.contains(ty::ADDRESS_REGISTRATION));
    });
    let ci = p
        .children()
        .find_by_ext(&c.env.ext, StateFilter::Valid)
        .unwrap();
    assert_eq!(
        ci.addresses(),
        &[Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 5)]
    );
    assert_eq!(ci.ml_eid_iid(), Some(&Iid(ipv6::iid(&c.env.ml_eid()).0)));
    assert!(ci.has_address(&MLP, &c.env.ml_eid()));
    assert_eq!(&penv.indirect[..], &[(c.env.ext, Rloc16(0x0401))]);
    // Supervision: one message every 3 s.
    let mut now = t;
    for _ in 0..7 {
        now += Duration::from_secs(1);
        p.poll(&mut penv, now);
    }
    assert_eq!(penv.supervised.len(), 2);
    // Sending something else resets the counter.
    p.child_message_sent(Rloc16(0x0401));
}

#[test]
fn parent_request_filters() {
    let (mut p, mut penv) = router();
    let mut c = FakeChild::new(1, RX_ON);
    // REED-only scan mask: a router does not answer.
    let req = c.parent_request(0x40, [3; 8]);
    assert_eq!(
        TestEnv::deliver(&req, &mut p, &mut penv, T0, -60),
        Err(Error::Drop)
    );
    p.poll(&mut penv, T0 + Duration::from_millis(900));
    assert!(penv.out.is_empty());
    // Duplicate within 700 ms is dropped.
    let req = c.parent_request(0x80, [3; 8]);
    TestEnv::deliver(&req, &mut p, &mut penv, T0, -60).unwrap();
    let again = c.parent_request(0x80, [4; 8]);
    assert_eq!(
        TestEnv::deliver(
            &again,
            &mut p,
            &mut penv,
            T0 + Duration::from_millis(100),
            -60
        ),
        Err(Error::Drop)
    );
    // After the response is sent the child may ask again later.
    p.poll(&mut penv, T0 + Duration::from_millis(600));
    assert_eq!(penv.take_out().len(), 1);
    let later = c.parent_request(0x80, [5; 8]);
    TestEnv::deliver(
        &later,
        &mut p,
        &mut penv,
        T0 + Duration::from_millis(900),
        -60,
    )
    .unwrap();
    // Not accepting children / not a router: dropped.
    let info = RouterInfo {
        accepting_children: false,
        ..Default::default()
    };
    p.set_router_info(info);
    let mut c2 = FakeChild::new(2, RX_ON);
    let req = c2.parent_request(0x80, [3; 8]);
    assert!(TestEnv::deliver(&req, &mut p, &mut penv, T0, -60).is_err());
    let mut env2 = TestEnv::new(11);
    let mut detached: Mle<4> = Mle::new(MleConfig::new(FTD));
    detached.start(&mut env2, T0).unwrap();
    assert!(TestEnv::deliver(&req, &mut detached, &mut env2, T0, -60).is_err());
}

#[test]
fn child_update_request_from_child() {
    let (mut p, mut penv) = router();
    let mut c = FakeChild::new(1, RX_ON);
    let (t, ch) = parent_phase(&mut p, &mut penv, &mut c, T0);
    let req = c.child_id_request(&penv, &ch, 240, false);
    TestEnv::deliver(&req, &mut p, &mut penv, t, -60).unwrap();
    penv.take_out();
    c.mode = SLEEPY;
    let mode = SLEEPY;
    let upd = c.msg(ll(&penv.ext), Command::ChildUpdateRequest, |w| {
        w.mode(mode)?;
        w.challenge(&[8; 8])?;
        w.source_address(Rloc16(0x0401))?;
        w.leader_data(&LeaderData {
            data_version: 7,
            ..leader()
        })?;
        w.timeout(100)?;
        w.supervision_interval(60)
    });
    let t = t + Duration::from_secs(10);
    assert_eq!(
        TestEnv::deliver(&upd, &mut p, &mut penv, t, -60),
        Ok(Command::ChildUpdateRequest)
    );
    let out = penv.take_out();
    assert_eq!(out.len(), 1);
    decode(&out[0], &c.env, |rx| {
        assert_eq!(rx.command, Command::ChildUpdateResponse);
        let t = &rx.tlvs;
        assert_eq!(t.response().unwrap(), &[8; 8]);
        assert_eq!(t.mode().unwrap(), SLEEPY);
        assert_eq!(t.source_address().unwrap(), ROUTER_RLOC);
        assert_eq!(t.timeout().unwrap(), 100);
        assert_eq!(t.supervision_interval().unwrap(), 60);
        assert!(t.contains(ty::LINK_MARGIN) && t.contains(ty::MLE_FRAME_COUNTER));
        assert!(t.contains(ty::LINK_FRAME_COUNTER) && t.contains(ty::LEADER_DATA));
    });
    let ci = p
        .children()
        .find_by_ext(&c.env.ext, StateFilter::Valid)
        .unwrap();
    assert_eq!(ci.neighbor.mode, SLEEPY);
    assert_eq!(ci.timeout_secs, 100);
    // Mode change rx-on -> sleepy: indirect transmission begins and the
    // settings record follows.
    assert_eq!(&penv.indirect[..], &[(c.env.ext, Rloc16(0x0401))]);
    assert_eq!(penv.load_child(0).unwrap().timeout, 100);

    // Unknown rx-on child: Status error; unknown sleepy child: silence.
    let mut stranger = FakeChild::new(9, RX_ON);
    let st = stranger.msg(ll(&penv.ext), Command::ChildUpdateRequest, |w| {
        w.mode(RX_ON)
    });
    TestEnv::deliver(&st, &mut p, &mut penv, t, -60).unwrap();
    let out = penv.take_out();
    assert_eq!(out.len(), 1);
    decode(&out[0], &stranger.env, |rx| {
        assert!(rx.tlvs.contains(ty::STATUS));
    });
    let mut sleepy = FakeChild::new(8, SLEEPY);
    let st = sleepy.msg(ll(&penv.ext), Command::ChildUpdateRequest, |w| {
        w.mode(SLEEPY)
    });
    TestEnv::deliver(&st, &mut p, &mut penv, t, -60).unwrap();
    assert!(penv.out.is_empty());
}

#[test]
fn child_timeout_removes_child() {
    let (mut p, mut penv) = router();
    let mut c = FakeChild::new(1, SLEEPY);
    let (t, ch) = parent_phase(&mut p, &mut penv, &mut c, T0);
    // A child that never sends its Child ID Request times out after 5 s.
    let silent = p
        .children()
        .find_by_ext(&c.env.ext, StateFilter::Any)
        .unwrap();
    assert_eq!(silent.timeout_secs, 5);
    let mut c2 = FakeChild::new(2, SLEEPY);
    let (_t2, _) = parent_phase(&mut p, &mut penv, &mut c2, t + Duration::from_secs(1));
    p.poll(&mut penv, t + Duration::from_secs(5));
    assert!(
        p.children()
            .find_by_ext(&c.env.ext, StateFilter::Any)
            .is_none()
    );
    assert!(
        p.children()
            .find_by_ext(&c2.env.ext, StateFilter::Any)
            .is_some()
    );

    // A valid child expires after its timeout; settings and indirect state go.
    let mut c3 = FakeChild::new(3, SLEEPY);
    let t3 = t + Duration::from_secs(6);
    let (t3, ch3) = parent_phase(&mut p, &mut penv, &mut c3, t3);
    let _ = ch;
    let req = c3.child_id_request(&penv, &ch3, 20, false);
    TestEnv::deliver(&req, &mut p, &mut penv, t3, -60).unwrap();
    penv.take_out();
    assert_eq!(penv.settings_child_count(), 1);
    assert_eq!(penv.indirect.len(), 1);
    let expiry = t3 + Duration::from_secs(20);
    p.poll(&mut penv, expiry - Duration::from_millis(1));
    assert!(
        p.children()
            .find_by_ext(&c3.env.ext, StateFilter::Valid)
            .is_some()
    );
    p.poll(&mut penv, expiry);
    assert!(
        p.children()
            .find_by_ext(&c3.env.ext, StateFilter::Any)
            .is_none()
    );
    assert_eq!(penv.settings_child_count(), 0);
    assert!(penv.indirect.is_empty());
    assert!(
        penv.events
            .iter()
            .any(|e| matches!(e, MleEvent::ChildRemoved { .. }))
    );
}

#[test]
fn data_request_gets_data_response() {
    let (mut p, mut penv) = router();
    let mut c = FakeChild::new(1, RX_ON);
    let (t, ch) = parent_phase(&mut p, &mut penv, &mut c, T0);
    // Not a child yet: data request is refused.
    let early = c.msg(ll(&penv.ext), Command::DataRequest, |w| {
        w.tlv_request(&[ty::NETWORK_DATA])
    });
    assert!(TestEnv::deliver(&early, &mut p, &mut penv, t, -60).is_err());
    let req = c.child_id_request(&penv, &ch, 240, false);
    TestEnv::deliver(&req, &mut p, &mut penv, t, -60).unwrap();
    penv.take_out();
    p.set_leader_data(LeaderData {
        data_version: 8,
        ..leader()
    });
    penv.provided_nd = Vec::from_slice(&[1, 2]).unwrap();
    let dr = c.msg(ll(&penv.ext), Command::DataRequest, |w| {
        w.tlv_request(&[ty::NETWORK_DATA, ty::ROUTE64])
    });
    assert_eq!(
        TestEnv::deliver(&dr, &mut p, &mut penv, t, -60),
        Ok(Command::DataRequest)
    );
    let out = penv.take_out();
    decode(&out[0], &c.env, |rx| {
        assert_eq!(rx.command, Command::DataResponse);
        assert_eq!(rx.tlvs.network_data().unwrap(), &[1, 2]);
        assert_eq!(rx.tlvs.leader_data().unwrap().data_version, 8);
        assert!(rx.tlvs.contains(ty::ROUTE64));
    });
    assert_eq!(
        p.children()
            .find_by_ext(&c.env.ext, StateFilter::Valid)
            .unwrap()
            .network_data_version,
        8
    );
}

#[test]
fn restored_child_is_asked_and_becomes_valid() {
    let (mut p, mut penv) = router();
    let ext = crate::test_support::ext(1);
    let info = ChildInfo {
        ext_address: ext,
        timeout: 240,
        rloc16: Rloc16(0x0403),
        mode: RX_ON.to_bits(),
        version: 5,
    };
    {
        use crate::env::MleEnv;
        penv.store_child_info(&info).unwrap();
    }
    p.restore_children(&mut penv, T0);
    assert_eq!(
        p.children()
            .find_by_ext(&ext, StateFilter::Any)
            .unwrap()
            .neighbor
            .state,
        NeighborState::Restored
    );
    p.poll(&mut penv, T0);
    let out = penv.take_out();
    assert_eq!(out.len(), 1);
    let mut c = FakeChild::new(1, RX_ON);
    decode(&out[0], &c.env, |rx| {
        assert_eq!(rx.command, Command::ChildUpdateRequest);
        assert!(rx.tlvs.contains(ty::CHALLENGE) && rx.tlvs.contains(ty::NETWORK_DATA));
    });
    let ch: [u8; 8] = decode(&out[0], &c.env, |rx| {
        rx.tlvs.challenge().unwrap().try_into().unwrap()
    });
    assert_eq!(
        p.children()
            .find_by_ext(&ext, StateFilter::Any)
            .unwrap()
            .neighbor
            .state,
        NeighborState::ChildUpdateRequest
    );
    let resp = c.msg(ll(&penv.ext), Command::ChildUpdateResponse, |w| {
        w.source_address(Rloc16(0x0403))?;
        w.response(&ch)?;
        w.link_frame_counter(5)?;
        w.mle_frame_counter(6)?;
        w.mode(RX_ON)?;
        w.timeout(240)
    });
    assert_eq!(
        TestEnv::deliver(&resp, &mut p, &mut penv, T0 + Duration::from_secs(1), -60),
        Ok(Command::ChildUpdateResponse)
    );
    let ci = p.children().find_by_ext(&ext, StateFilter::Valid).unwrap();
    assert_eq!(ci.neighbor.mle_replay.frame_counter(), Some(6));
    assert!(penv.has_event(MleEvent::ChildAdded {
        ext,
        rloc16: Rloc16(0x0403)
    }));
}

// ---------------------------------------------------------------- CSL parent side

const RADIO_ACC: crate::tlv::CslClockAccuracy = crate::tlv::CslClockAccuracy {
    accuracy_ppm: 20,
    uncertainty_10us: 5,
};

/// A CSL capable (Thread 1.2+) sleepy child attached to a router whose radio
/// reports `RADIO_ACC`.
fn csl_child() -> (Mle<4>, TestEnv, FakeChild, Instant) {
    let (mut p, mut penv) = router();
    penv.csl_radio = Some(RADIO_ACC);
    let mut c = FakeChild::new(1, SLEEPY);
    let req = c.parent_request(0x80, [3; 8]);
    TestEnv::deliver(&req, &mut p, &mut penv, T0, -60).unwrap();
    let t = T0 + Duration::from_millis(501);
    p.poll(&mut penv, t);
    let out = penv.take_out();
    let mut ch = [0u8; 8];
    decode(&out[0], &c.env, |rx| {
        // Parent Response carries the CSL accuracy for a Thread 1.2+ child.
        assert_eq!(rx.tlvs.csl_clock_accuracy().unwrap(), RADIO_ACC);
        ch.copy_from_slice(rx.tlvs.challenge().unwrap());
    });
    let req = c.child_id_request(&penv, &ch, 240, false);
    TestEnv::deliver(&req, &mut p, &mut penv, t, -60).unwrap();
    penv.take_out();
    (p, penv, c, t)
}

fn csl_update(c: &mut FakeChild, penv: &TestEnv, timeout: u32, channel: u16) -> Out {
    c.msg(ll(&penv.ext), Command::ChildUpdateRequest, |w| {
        w.mode(SLEEPY)?;
        w.source_address(Rloc16(0x0401))?;
        w.leader_data(&leader())?;
        w.timeout(240)?;
        w.csl_channel(crate::tlv::ChannelValue { page: 0, channel })?;
        w.csl_timeout(timeout)
    })
}

#[test]
fn csl_child_update_stores_parameters_and_answers_with_accuracy() {
    let (mut p, mut penv, mut c, t) = csl_child();
    // Not synchronized yet: the CSL TLVs are ignored (OT) and no accuracy.
    let upd = csl_update(&mut c, &penv, 30, 20);
    TestEnv::deliver(&upd, &mut p, &mut penv, t, -60).unwrap();
    let out = penv.take_out();
    decode(&out[0], &c.env, |rx| {
        assert!(!rx.tlvs.contains(ty::CSL_CLOCK_ACCURACY));
    });
    assert!(penv.csl_tracked.is_empty());
    // A frame with a CSL IE synchronizes the child.
    assert!(p.child_csl_synchronized(Rloc16(0x0401), t));
    assert!(!p.child_csl_synchronized(Rloc16(0x0499), t));
    let upd = csl_update(&mut c, &penv, 30, 20);
    TestEnv::deliver(&upd, &mut p, &mut penv, t, -60).unwrap();
    let out = penv.take_out();
    decode(&out[0], &c.env, |rx| {
        assert_eq!(rx.tlvs.csl_clock_accuracy().unwrap(), RADIO_ACC);
    });
    let ci = p
        .children()
        .find_by_ext(&c.env.ext, StateFilter::Valid)
        .unwrap();
    assert!(ci.csl_synchronized);
    assert_eq!((ci.csl_timeout_secs, ci.csl_channel), (30, 20));
    assert_eq!(&penv.csl_tracked[..], &[(c.env.ext, Rloc16(0x0401), 20)]);
}

#[test]
fn csl_synchronization_expires_after_the_csl_timeout() {
    let (mut p, mut penv, mut c, t) = csl_child();
    p.child_csl_synchronized(Rloc16(0x0401), t);
    let upd = csl_update(&mut c, &penv, 30, 0);
    TestEnv::deliver(&upd, &mut p, &mut penv, t, -60).unwrap();
    penv.take_out();
    // The deadline is the CSL timeout, well before the child timeout.
    let expiry = t + Duration::from_secs(30);
    assert!(p.next_deadline().unwrap() <= expiry);
    p.poll(&mut penv, expiry - Duration::from_secs(1));
    assert!(penv.csl_desyncs.is_empty());
    // A new CSL IE postpones it.
    p.child_csl_synchronized(Rloc16(0x0401), t + Duration::from_secs(20));
    p.poll(&mut penv, expiry);
    assert!(penv.csl_desyncs.is_empty());
    let late = t + Duration::from_secs(50);
    p.poll(&mut penv, late);
    assert_eq!(&penv.csl_desyncs[..], &[(c.env.ext, Rloc16(0x0401))]);
    let ci = p
        .children()
        .find_by_ext(&c.env.ext, StateFilter::Valid)
        .unwrap();
    assert!(!ci.csl_synchronized);
}

#[test]
fn csl_child_going_rx_on_is_desynchronized() {
    let (mut p, mut penv, mut c, t) = csl_child();
    p.child_csl_synchronized(Rloc16(0x0401), t);
    c.mode = RX_ON;
    let upd = c.msg(ll(&penv.ext), Command::ChildUpdateRequest, |w| {
        w.mode(RX_ON)?;
        w.source_address(Rloc16(0x0401))?;
        w.leader_data(&leader())?;
        w.timeout(240)
    });
    TestEnv::deliver(&upd, &mut p, &mut penv, t, -60).unwrap();
    assert_eq!(&penv.csl_desyncs[..], &[(c.env.ext, Rloc16(0x0401))]);
}

#[test]
fn router_without_csl_radio_omits_the_accuracy() {
    let (mut p, mut penv) = router();
    let mut c = FakeChild::new(1, SLEEPY);
    let req = c.parent_request(0x80, [3; 8]);
    TestEnv::deliver(&req, &mut p, &mut penv, T0, -60).unwrap();
    p.poll(&mut penv, T0 + Duration::from_millis(501));
    let out = penv.take_out();
    decode(&out[0], &c.env, |rx| {
        assert!(!rx.tlvs.contains(ty::CSL_CLOCK_ACCURACY));
    });
}
