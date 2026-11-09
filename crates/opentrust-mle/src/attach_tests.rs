use core::net::SocketAddrV6;

use heapless::Vec;
use opentrust_core::Error;
use opentrust_core::time::{Duration, Instant};
use opentrust_core::types::{Rloc16, ipv6};
use opentrust_mac::security::KeySeqUpdate;
use opentrust_net::udp::UdpMeta;

use crate::consts::MLE_UDP_PORT;
use crate::endpoint::{LinkRxInfo, MleRx};
use crate::env::{MleEnv, MleEvent, Role};
use crate::message::Command;
use crate::mle::{Mle, MleConfig, tx};
use crate::security::MleFrameCounter;
use crate::test_support::{Out, TestEnv, ll};
use crate::tlv::{Connectivity, DeviceMode, LeaderData, ParentPriority, ty};

pub(crate) const T0: Instant = Instant::from_secs(1000);

pub(crate) fn mtd() -> Mle<0> {
    Mle::new(MleConfig::new(DeviceMode::new(true, false, true)))
}

/// Poll `mle` at its next deadline; returns the new time.
pub(crate) fn advance(mle: &mut Mle<0>, env: &mut TestEnv, now: Instant) -> Instant {
    let d = mle.next_deadline().expect("deadline");
    let t = if d > now { d } else { now };
    mle.poll(env, t);
    t
}

/// Decode an outgoing message with the (shared-key) keys of `env`.
pub(crate) fn decode<R>(out: &Out, env: &TestEnv, f: impl FnOnce(&MleRx<'_>) -> R) -> R {
    let meta = UdpMeta {
        peer: SocketAddrV6::new(out.src, MLE_UDP_PORT, 0, 0),
        local: SocketAddrV6::new(out.dst, MLE_UDP_PORT, 0, 0),
        hop_limit: 255,
        ecn: 0,
        link_security: false,
    };
    let mut scratch = [0u8; 1100];
    let rx = MleRx::parse(
        env.keys(),
        &meta,
        LinkRxInfo::default(),
        &out.data,
        &mut scratch,
    )
    .unwrap();
    f(&rx)
}

pub(crate) struct FakeParent {
    pub(crate) env: TestEnv,
    pub(crate) counter: MleFrameCounter,
    pub(crate) rloc: Rloc16,
    pub(crate) prio: ParentPriority,
    pub(crate) margin_out: u8,
    /// CSL Clock Accuracy TLV to include in Parent Responses.
    pub(crate) csl_accuracy: Option<crate::tlv::CslClockAccuracy>,
}

impl FakeParent {
    pub(crate) fn new(n: u8, rloc: u16) -> Self {
        Self {
            env: TestEnv::new(n),
            counter: MleFrameCounter::new(),
            rloc: Rloc16(rloc),
            prio: ParentPriority::Medium,
            margin_out: 40,
            csl_accuracy: None,
        }
    }

    pub(crate) fn leader() -> LeaderData {
        LeaderData {
            partition_id: 0x1122_3344,
            weighting: 64,
            data_version: 7,
            stable_data_version: 3,
            leader_router_id: 1,
        }
    }

    pub(crate) fn parent_response(&mut self, to: &TestEnv, challenge: &[u8]) -> Out {
        let (rloc, prio, margin) = (self.rloc, self.prio, self.margin_out);
        let csl = self.csl_accuracy;
        let link_fc = self.env.keys.frame_counter();
        let mle_fc = self.counter.current();
        let mut mine = [0u8; 8];
        self.env.fill_random(&mut mine);
        let conn = Connectivity {
            parent_priority: prio,
            link_quality_3: 2,
            link_quality_2: 1,
            link_quality_1: 0,
            leader_cost: 1,
            id_sequence: 5,
            active_routers: 3,
            sed_buffer_size: None,
            sed_datagram_count: None,
        };
        tx(
            &mut self.env,
            &mut self.counter,
            ll(&to.ext),
            Command::ParentResponse,
            |w| {
                w.source_address(rloc)?;
                w.leader_data(&Self::leader())?;
                w.link_frame_counter(link_fc)?;
                w.mle_frame_counter(mle_fc)?;
                w.response(challenge)?;
                w.challenge(&mine)?;
                w.link_margin(margin)?;
                w.connectivity(&conn)?;
                if let Some(a) = csl {
                    w.csl_clock_accuracy(a)?;
                }
                w.version(5)
            },
        )
        .unwrap();
        self.env.take_out().pop().unwrap()
    }

    /// Send an arbitrary secured message from this fake parent.
    pub(crate) fn msg(
        &mut self,
        to: &TestEnv,
        cmd: Command,
        build: impl FnOnce(&mut crate::tlv::TlvWriter<'_>) -> opentrust_core::Result<()>,
    ) -> Out {
        tx(&mut self.env, &mut self.counter, ll(&to.ext), cmd, build).unwrap();
        self.env.take_out().pop().unwrap()
    }

    pub(crate) fn child_id_response(&mut self, to: &TestEnv, child_rloc: u16) -> Out {
        let rloc = self.rloc;
        tx(
            &mut self.env,
            &mut self.counter,
            ll(&to.ext),
            Command::ChildIdResponse,
            |w| {
                w.source_address(rloc)?;
                w.leader_data(&Self::leader())?;
                w.address16(Rloc16(child_rloc))?;
                w.network_data(&[1, 2, 3, 4])
            },
        )
        .unwrap();
        self.env.take_out().pop().unwrap()
    }
}

/// Start the child and run until the first Parent Request; returns it.
pub(crate) fn first_parent_request(child: &mut Mle<0>, env: &mut TestEnv) -> (Out, Instant) {
    child.start(env, T0).unwrap();
    let t = advance(child, env, T0);
    let out = env.take_out();
    assert_eq!(out.len(), 1);
    let req = out.into_iter().next().unwrap();
    (req, t)
}

pub(crate) fn challenge_of(req: &Out, env: &TestEnv) -> Vec<u8, 8> {
    decode(req, env, |rx| {
        Vec::from_slice(rx.tlvs.challenge().unwrap()).unwrap()
    })
}

#[test]
fn parent_request_phases_and_backoff() {
    let mut env = TestEnv::new(1);
    let mut child = mtd();
    let (req, mut t) = first_parent_request(&mut child, &mut env);
    assert_eq!(req.dst, ipv6::LINK_LOCAL_ALL_ROUTERS);
    assert!(t - T0 <= Duration::from_millis(751));
    assert_eq!(child.role(), Role::Detached);
    let mut masks = Vec::<u8, 8>::new();
    masks
        .push(decode(&req, &env, |rx| {
            assert_eq!(rx.command, Command::ParentRequest);
            assert!(rx.tlvs.contains(ty::MODE) && rx.tlvs.contains(ty::VERSION));
            rx.tlvs.scan_mask().unwrap()
        }))
        .unwrap();
    // No answers: 6 requests in the first cycle (2 routers, 4 routers+REEDs).
    let mut gaps = Vec::<u64, 8>::new();
    let mut last = t;
    for _ in 0..5 {
        t = advance(&mut child, &mut env, t);
        gaps.push((t - last).as_millis()).unwrap();
        last = t;
        let out = env.take_out();
        assert_eq!(out.len(), 1);
        masks
            .push(decode(&out[0], &env, |rx| rx.tlvs.scan_mask().unwrap()))
            .unwrap();
    }
    assert_eq!(&masks[..], &[0x80, 0x80, 0xc0, 0xc0, 0xc0, 0xc0]);
    assert_eq!(&gaps[..], &[750, 750, 1250, 1250, 1250]);
    // An MTD then tries Orphan Announces: one more Parent Request, then an
    // Announce per channel 11..=26, 1400/17 = 82 ms apart.
    t = advance(&mut child, &mut env, t);
    let out = env.take_out();
    assert_eq!(out.len(), 1);
    assert_eq!(
        decode(&out[0], &env, |rx| rx.command),
        Command::ParentRequest
    );
    for ch in 11..=26u8 {
        let before = t;
        t = advance(&mut child, &mut env, t);
        assert_eq!((t - before).as_millis(), 82);
        let out = env.take_out();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].channel, Some(ch));
        assert!(
            decode(&out[0], &env, |rx| rx.tlvs.active_timestamp().unwrap()).is_orphan_announce()
        );
    }
    // Attempt over: detached, backoff of 251 ms (+<50 ms jitter) before the next.
    t = advance(&mut child, &mut env, t);
    assert!(env.out.is_empty());
    assert_eq!(child.role(), Role::Detached);
    let wait = child.next_deadline().unwrap() - t;
    assert!(
        wait >= Duration::from_millis(251) && wait < Duration::from_millis(302),
        "{wait:?}"
    );
    // Second attempt: 1 request to routers, 1 to routers and REEDs, then 502 ms backoff.
    t = advance(&mut child, &mut env, t);
    assert_eq!(env.take_out().len(), 1);
    t = advance(&mut child, &mut env, t);
    assert_eq!(env.take_out().len(), 1);
    // Announce phase again: a Parent Request and 16 Orphan Announces.
    for _ in 0..17 {
        t = advance(&mut child, &mut env, t);
        assert_eq!(env.take_out().len(), 1);
    }
    t = advance(&mut child, &mut env, t);
    let wait = child.next_deadline().unwrap() - t;
    assert!(
        wait >= Duration::from_millis(502) && wait < Duration::from_millis(553),
        "{wait:?}"
    );
}

fn attach_to_best(
    prio2: ParentPriority,
    rss2: i8,
) -> (Mle<0>, TestEnv, FakeParent, FakeParent, Out, Instant) {
    let mut env = TestEnv::new(1);
    let mut child = mtd();
    let (req, t) = first_parent_request(&mut child, &mut env);
    let ch = challenge_of(&req, &env);
    let mut p1 = FakeParent::new(10, 0x0400);
    let mut p2 = FakeParent::new(11, 0x0800);
    p2.prio = prio2;
    p1.env
        .keys
        .set_key_sequence(5, KeySeqUpdate::FORCE, t)
        .unwrap();
    p2.env
        .keys
        .set_key_sequence(5, KeySeqUpdate::FORCE, t)
        .unwrap();
    let r2 = p2.parent_response(&env, &ch);
    let r1 = p1.parent_response(&env, &ch);
    let t1 = t + Duration::from_millis(100);
    assert_eq!(
        TestEnv::deliver(&r2, &mut child, &mut env, t1, rss2),
        Ok(Command::ParentResponse)
    );
    assert_eq!(
        TestEnv::deliver(&r1, &mut child, &mut env, t1, -60),
        Ok(Command::ParentResponse)
    );
    // Authoritative message: key sequence adopted.
    assert_eq!(env.keys.key_sequence(), 5);
    // Timer expiry with an acceptable candidate sends the Child ID Request.
    let t2 = advance(&mut child, &mut env, t1);
    let out = env.take_out();
    assert_eq!(out.len(), 1);
    let cid = out.into_iter().next().unwrap();
    assert!(child.is_attaching());
    (child, env, p1, p2, cid, t2)
}

#[test]
fn selects_better_link_quality() {
    // P2 is weaker (rss -85 => margin 15 => Q2): P1 wins.
    let (mut child, mut env, mut p1, _p2, cid, t) = attach_to_best(ParentPriority::High, -85);
    assert_eq!(cid.dst, ll(&p1.env.ext));
    let ch1 = decode(&cid, &p1.env, |rx| {
        assert_eq!(rx.command, Command::ChildIdRequest);
        let t = &rx.tlvs;
        assert!(t.contains(ty::RESPONSE) && t.contains(ty::LINK_FRAME_COUNTER));
        assert!(t.contains(ty::MLE_FRAME_COUNTER) && t.contains(ty::MODE));
        assert_eq!(t.timeout().unwrap(), 240);
        assert_eq!(t.version().unwrap(), 5);
        assert_eq!(t.tlv_request().unwrap(), &[ty::ADDRESS16, ty::NETWORK_DATA]);
        assert!(t.contains(ty::ADDRESS_REGISTRATION));
        Vec::<u8, 8>::from_slice(t.response().unwrap()).unwrap()
    });
    assert_eq!(ch1.len(), 8);
    // Child ID Response completes the attach.
    let resp = p1.child_id_response(&env, 0x0405);
    let t = t + Duration::from_millis(10);
    assert_eq!(
        TestEnv::deliver(&resp, &mut child, &mut env, t, -60),
        Ok(Command::ChildIdResponse)
    );
    assert_eq!(child.role(), Role::Child);
    assert_eq!(child.rloc16(), Rloc16(0x0405));
    assert_eq!(env.short, Rloc16(0x0405));
    assert_eq!(env.parent, Some((p1.env.ext, Rloc16(0x0400))));
    assert_eq!(&env.nd[..], &[1, 2, 3, 4]);
    assert_eq!(env.nd_leader, Some(FakeParent::leader()));
    assert_eq!(*child.leader_data(), FakeParent::leader());
    let p = child.parent().unwrap();
    assert!(p.router.neighbor.is_valid());
    assert_eq!(p.router.neighbor.link_counters.key_sequence(), 5);
    // Link-layer replay protection for data frames from the parent.
    let parent = opentrust_mac::frame::Address::Short(Rloc16(0x0400).into());
    let fc = p.router.neighbor.link_counters.frame_counter().unwrap();
    assert_eq!(child.check_link_frame(parent, 5, fc + 10), Ok(()));
    assert_eq!(
        child.check_link_frame(parent, 5, fc + 10),
        Err(opentrust_core::Error::Drop),
        "duplicate"
    );
    assert_eq!(
        child.check_link_frame(parent, 5, fc + 5),
        Err(opentrust_core::Error::Security),
        "replay"
    );
    assert_eq!(
        child.check_link_frame(parent, 4, u32::MAX),
        Err(opentrust_core::Error::Security),
        "old key sequence"
    );
    // Unknown sources pass (MLE has its own protection for attaching devices).
    let other = opentrust_mac::frame::Address::Short(Rloc16(0x1234).into());
    assert_eq!(child.check_link_frame(other, 5, 0), Ok(()));
    let p = child.parent().unwrap();
    assert_eq!(p.leader_cost, 1);
    assert!(env.has_event(MleEvent::Attached {
        parent: p1.env.ext,
        parent_rloc16: Rloc16(0x0400)
    }));
    // Not sleepy: rx stays on, no polling.
    assert!(env.rx_on && env.poll.is_none());
}

#[test]
fn priority_breaks_ties() {
    // Same RSS: higher parent priority wins (P2).
    let (_child, _env, _p1, p2, cid, _t) = attach_to_best(ParentPriority::High, -60);
    assert_eq!(cid.dst, ll(&p2.env.ext));
}

#[test]
fn rejects_wrong_challenge_and_late_responses() {
    let mut env = TestEnv::new(1);
    let mut child = mtd();
    let (_req, t) = first_parent_request(&mut child, &mut env);
    let mut p = FakeParent::new(10, 0x0400);
    let bad = p.parent_response(&env, &[9; 8]);
    assert_eq!(
        TestEnv::deliver(&bad, &mut child, &mut env, t, -60),
        Err(Error::Security)
    );
    // A Child ID Response without a pending Child ID Request is dropped.
    let resp = p.child_id_response(&env, 0x0401);
    assert!(TestEnv::deliver(&resp, &mut child, &mut env, t, -60).is_err());
    assert_eq!(child.role(), Role::Detached);
}

#[test]
fn sleepy_child_polls_after_attach() {
    let mut env = TestEnv::new(1);
    let mut child: Mle<0> = Mle::new(MleConfig::new(DeviceMode::new(false, false, false)));
    child.start(&mut env, T0).unwrap();
    let t = advance(&mut child, &mut env, T0);
    let req = env.take_out().pop().unwrap();
    let ch = challenge_of(&req, &env);
    let mut p = FakeParent::new(10, 0x0400);
    let r = p.parent_response(&env, &ch);
    TestEnv::deliver(&r, &mut child, &mut env, t, -60).unwrap();
    let t = advance(&mut child, &mut env, t);
    let cid = env.take_out().pop().unwrap();
    decode(&cid, &p.env, |rx| {
        assert_eq!(rx.tlvs.supervision_interval().unwrap(), 129);
        assert_eq!(
            rx.tlvs.mode().unwrap(),
            DeviceMode::new(false, false, false)
        );
    });
    let resp = p.child_id_response(&env, 0x0402);
    TestEnv::deliver(&resp, &mut child, &mut env, t, -60).unwrap();
    assert_eq!(child.role(), Role::Child);
    assert!(!env.rx_on);
    assert_eq!(env.poll, Some(Duration::from_secs(236)));
}

#[test]
fn reattach_tries_stored_active_then_pending_dataset() {
    use crate::env::StoredDataset;
    let mut env = TestEnv::new(1);
    env.stored.active = true;
    env.stored.pending = true;
    let mut child = mtd();
    child.start(&mut env, T0).unwrap();
    let mut t = T0;
    // Start: the stored Active Dataset is restored.
    t = advance(&mut child, &mut env, t);
    assert_eq!(env.stored.restored, [StoredDataset::Active]);
    // Run the whole unsuccessful attach: no Orphan Announces while reattaching.
    let mut announces = 0;
    for _ in 0..6 {
        env.take_out().iter().for_each(|o| {
            announces += usize::from(decode(o, &env, |rx| rx.command) == Command::Announce);
        });
        t = advance(&mut child, &mut env, t);
    }
    env.take_out();
    // The Pending Dataset is applied, then a new attach cycle starts shortly.
    assert_eq!(
        env.stored.restored,
        [StoredDataset::Active, StoredDataset::Pending]
    );
    assert_eq!(env.stored.pending_applied, 1);
    assert_eq!(announces, 0);
    let wait = child.next_deadline().unwrap() - t;
    assert!(wait <= Duration::from_millis(51), "{wait:?}");
    // The second cycle also fails: the Active Dataset comes back and the
    // normal Orphan Announce phase follows.
    let mut guard = 0;
    while env.stored.restored.len() < 3 && guard < 40 {
        t = advance(&mut child, &mut env, t);
        guard += 1;
    }
    assert_eq!(env.stored.restored[2], StoredDataset::Active);
    assert_eq!(announces, 0);
}
