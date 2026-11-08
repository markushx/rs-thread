//! Indirect transmission to sleepy children: queue bookkeeping and the
//! full path through the mesh simulator (resolve, route, queue, data poll).

use opentrust_core::Error;
use opentrust_core::time::Duration;
use opentrust_core::types::Rloc16;
use opentrust_lowpan::ip6::{Ipv6Header, UdpHeader};
use opentrust_lowpan::iphc::NoContexts;
use opentrust_mle::Role;
use opentrust_mle::tlv::DeviceMode;

use crate::forwarder::{DropReason, FrameSink, SendResult, TxFrame};
use crate::indirect::{IndirectQueue, MAX_POLL_TX_ATTEMPTS, PollOutcome};
use crate::sim::MeshSim;

fn secs(s: u64) -> Duration {
    Duration::from_secs(s)
}

const OWN: Rloc16 = Rloc16(0x0400);
const CHILD: Rloc16 = Rloc16(0x0401);
const OTHER: Rloc16 = Rloc16(0x0402);

fn datagram(len: usize) -> std::vec::Vec<u8> {
    let src = "fd00::1".parse().unwrap();
    let dst = "fd00::2".parse().unwrap();
    let mut buf = std::vec![0u8; 48 + len];
    let mut h = Ipv6Header::new(17, 64, src, dst);
    h.payload_len = (UdpHeader::LEN + len) as u16;
    h.write(&mut buf).unwrap();
    UdpHeader {
        src_port: 1,
        dst_port: 2,
        length: h.payload_len,
        checksum: 1,
    }
    .write(&mut buf[40..])
    .unwrap();
    for (i, b) in buf[48..].iter_mut().enumerate() {
        *b = i as u8;
    }
    buf
}

#[derive(Default)]
struct Frames {
    sent: std::vec::Vec<(std::vec::Vec<u8>, bool)>,
    fail: bool,
}

impl FrameSink for Frames {
    fn transmit(&mut self, f: &TxFrame<'_>) -> opentrust_core::Result<()> {
        if self.fail {
            return Err(Error::Abort);
        }
        assert!(f.indirect);
        self.sent.push((f.payload.to_vec(), f.frame_pending));
        Ok(())
    }
}

fn poll(q: &mut IndirectQueue<4>, child: Rloc16, s: &mut Frames) -> PollOutcome {
    q.handle_data_poll(child, OWN, &NoContexts, 106, s).unwrap()
}

#[test]
fn queue_bookkeeping() {
    let mut q = IndirectQueue::<4>::new(1);
    assert!(q.is_empty());
    assert!(!q.frame_pending(CHILD));
    q.enqueue(CHILD, &datagram(4)).unwrap();
    q.enqueue(OTHER, &datagram(5)).unwrap();
    q.enqueue(CHILD, &datagram(6)).unwrap();
    assert_eq!(q.count(CHILD), 2);
    assert_eq!(q.len(), 3);
    // Source match table: every child with messages once.
    let mut table: std::vec::Vec<_> = q.src_match_children().collect();
    table.sort();
    assert_eq!(table, [CHILD, OTHER]);
    assert!(q.take_src_match_changed());
    assert!(!q.take_src_match_changed());
    // Messages are released in order, frame pending covers the next one.
    let mut s = Frames::default();
    assert_eq!(
        poll(&mut q, CHILD, &mut s),
        PollOutcome::Sent {
            frame_pending: true
        }
    );
    assert_eq!(
        poll(&mut q, CHILD, &mut s),
        PollOutcome::Sent {
            frame_pending: false
        }
    );
    assert_eq!(s.sent.len(), 2);
    assert!(s.sent[0].0.len() < s.sent[1].0.len());
    assert!(!q.frame_pending(CHILD));
    assert!(q.frame_pending(OTHER));
    // Nothing queued: an empty frame without frame pending.
    assert_eq!(
        poll(&mut q, CHILD, &mut s),
        PollOutcome::Sent {
            frame_pending: false
        }
    );
    assert!(s.sent[2].0.is_empty());
    // Purge.
    assert_eq!(q.remove_child(OTHER), 1);
    assert!(q.is_empty());
    assert!(q.take_src_match_changed());
    assert_eq!(q.remove_child(OTHER), 0);
}

#[test]
fn full_queue_and_oversized_datagram_are_refused() {
    let mut q = IndirectQueue::<4>::new(1);
    for _ in 0..4 {
        q.enqueue(CHILD, &datagram(1)).unwrap();
    }
    assert_eq!(q.enqueue(OTHER, &datagram(1)), Err(Error::NoBufs));
    let mut q = IndirectQueue::<4>::new(1);
    assert_eq!(
        q.enqueue(CHILD, &std::vec![0u8; 1281]),
        Err(Error::InvalidArgs)
    );
}

#[test]
fn supervision_message_rules() {
    let mut q = IndirectQueue::<4>::new(1);
    let mut s = Frames::default();
    // Not queued if the child has messages; replaced by a real message.
    assert!(q.enqueue_supervision(CHILD));
    assert!(!q.enqueue_supervision(CHILD));
    assert_eq!(q.count(CHILD), 1);
    q.enqueue(CHILD, &datagram(1)).unwrap();
    assert_eq!(q.count(CHILD), 1);
    assert!(!q.enqueue_supervision(CHILD));
    assert_eq!(
        poll(&mut q, CHILD, &mut s),
        PollOutcome::Sent {
            frame_pending: false
        }
    );
    assert!(!s.sent[0].0.is_empty());
    // A supervision message alone becomes an empty frame and is consumed.
    assert!(q.enqueue_supervision(CHILD));
    assert_eq!(
        poll(&mut q, CHILD, &mut s),
        PollOutcome::Sent {
            frame_pending: false
        }
    );
    assert!(s.sent[1].0.is_empty());
    assert_eq!(q.count(CHILD), 0);
}

#[test]
fn failed_transmissions_are_retried_and_finally_dropped() {
    let mut q = IndirectQueue::<4>::new(1);
    q.enqueue(CHILD, &datagram(3)).unwrap();
    let mut s = Frames {
        fail: true,
        ..Frames::default()
    };
    for _ in 0..MAX_POLL_TX_ATTEMPTS - 1 {
        assert_eq!(poll(&mut q, CHILD, &mut s), PollOutcome::Failed);
        assert_eq!(q.count(CHILD), 1);
    }
    // A success in between resets the attempts.
    s.fail = false;
    assert_eq!(
        poll(&mut q, CHILD, &mut s),
        PollOutcome::Sent {
            frame_pending: false
        }
    );
    assert_eq!(q.count(CHILD), 0);
    q.enqueue(CHILD, &datagram(3)).unwrap();
    s.fail = true;
    for _ in 0..MAX_POLL_TX_ATTEMPTS {
        assert_eq!(poll(&mut q, CHILD, &mut s), PollOutcome::Failed);
    }
    assert_eq!(q.count(CHILD), 0);
}

#[test]
fn fragments_go_out_one_per_poll_with_frame_pending() {
    let mut q = IndirectQueue::<4>::new(1);
    let d = datagram(300);
    q.enqueue(CHILD, &d).unwrap();
    let mut s = Frames::default();
    let mut n = 0;
    while q.frame_pending(CHILD) {
        let o = poll(&mut q, CHILD, &mut s);
        n += 1;
        let more = q.frame_pending(CHILD);
        assert_eq!(
            o,
            PollOutcome::Sent {
                frame_pending: more
            }
        );
        assert!(n < 10);
    }
    assert!(n >= 4);
    // Reassemble what was sent.
    let mut r = opentrust_lowpan::reassembly::Reassembler::<1>::new();
    let src = opentrust_mac::frame::Address::Short(OWN.into());
    let dst = opentrust_mac::frame::Address::Short(CHILD.into());
    let mut out = None;
    for (f, _) in &s.sent {
        if let opentrust_lowpan::reassembly::Reassembled::Complete(c) = r
            .handle_fragment(
                opentrust_core::time::Instant::from_secs(1),
                &NoContexts,
                &src,
                &dst,
                true,
                f,
            )
            .unwrap()
        {
            out = Some(c.to_vec());
        }
    }
    assert_eq!(out.unwrap(), d);
}

/// Leader - 1 - 2 - 3 routers, sleepy end device 4 attached to router 3.
fn line_with_sleepy() -> MeshSim {
    let ftd = DeviceMode::new(true, true, true);
    let sed = DeviceMode::new(false, false, false);
    let mut m = MeshSim::with_modes(&[ftd, ftd, ftd, ftd, sed]);
    for (a, b) in [(0, 1), (1, 2), (2, 3), (3, 4)] {
        m.connect(a, b, -60);
    }
    m.start(0);
    assert!(m.run_until(secs(60), |s| s.sim.role(0) == Role::Leader));
    for i in 1..4 {
        m.start(i);
        assert!(m.run_until(secs(60), |s| s.sim.role(i) == Role::Child));
        assert!(m.run_until(secs(300), |s| s.sim.role(i) == Role::Router));
    }
    let r3 = m.sim.nodes[3].mle.rloc16();
    let r0 = m.sim.nodes[0].mle.rloc16();
    assert!(m.run_until(secs(600), |s| {
        s.sim.nodes[0].mle.next_hop_and_path_cost(r3).0.is_some()
            && s.sim.nodes[3].mle.next_hop_and_path_cost(r0).0.is_some()
    }));
    m.start(4);
    assert!(m.run_until(secs(60), |s| s.sim.role(4) == Role::Child));
    assert!(!m.sim.nodes[4].env.rx_on);
    // The parent knows the child (indirect hook of the MLE core).
    assert!(m.run_until(secs(10), |s| !s.sim.nodes[3].env.indirect.is_empty()));
    m
}

fn queued(m: &MeshSim) -> usize {
    let child = m.sim.nodes[4].mle.rloc16();
    m.tmf[3].fwd.indirect.count(child)
}

#[test]
fn datagram_for_a_sleepy_child_waits_for_its_data_poll() {
    let mut m = line_with_sleepy();
    let child = m.sim.nodes[4].mle.rloc16();
    let eid = m.ml_eid(4);
    // Resolution through router 3 (it answers for its sleepy child), mesh
    // forwarding to router 3, then it queues the datagram.
    assert_eq!(m.send_udp(0, eid, b"wake up"), SendResult::Held);
    assert!(m.run_until(secs(10), |s| queued(s) == 1));
    assert!(m.tmf[4].delivered.is_empty());
    assert!(m.frame_log.iter().all(|(_, to, _)| *to != 4));
    let table: std::vec::Vec<_> = m.tmf[3].fwd.indirect.src_match_children().collect();
    assert_eq!(table, [child]);
    // The poll's ACK has Frame Pending, the answer is the datagram.
    let (fp, outcome) = m.data_poll(4);
    assert!(fp);
    assert_eq!(
        outcome,
        Ok(PollOutcome::Sent {
            frame_pending: false
        })
    );
    assert_eq!(m.tmf[4].delivered.len(), 1);
    assert_eq!(&m.tmf[4].delivered[0][48..], b"wake up");
    assert_eq!(queued(&m), 0);
    assert!(m.tmf[3].fwd.indirect.src_match_children().next().is_none());
    // The next poll finds nothing: no Frame Pending, an empty frame.
    let (fp, outcome) = m.data_poll(4);
    assert!(!fp);
    assert_eq!(
        outcome,
        Ok(PollOutcome::Sent {
            frame_pending: false
        })
    );
    assert!(m.frame_log.last().unwrap().2.is_empty());
    assert_eq!(m.tmf[4].delivered.len(), 1);
}

#[test]
fn large_datagram_and_following_message_are_delivered_poll_by_poll() {
    let mut m = line_with_sleepy();
    let eid = m.ml_eid(4);
    assert_eq!(m.send_udp(0, eid, &[0xa5; 200]), SendResult::Held);
    assert!(m.run_until(secs(10), |s| queued(s) == 1));
    // The EID is resolved now: a second datagram goes straight to the queue.
    m.send_udp(0, eid, b"second");
    assert!(m.run_until(secs(10), |s| queued(s) == 2));
    let mut polls = 0;
    while m.tmf[3]
        .fwd
        .indirect
        .frame_pending(m.sim.nodes[4].mle.rloc16())
    {
        let (fp, out) = m.data_poll(4);
        assert!(fp);
        out.unwrap();
        polls += 1;
        assert!(polls < 12);
    }
    assert!(polls >= 4);
    assert_eq!(m.tmf[4].delivered.len(), 2);
    assert_eq!(m.tmf[4].delivered[0].len(), 248);
    assert_eq!(&m.tmf[4].delivered[1][48..], b"second");
    // Every indirect frame but the last of the whole queue had Frame
    // Pending.
    let log = &m.tmf[3].fsink.pending_log;
    assert!(log[..log.len() - 1].iter().all(|p| *p));
    assert!(!log[log.len() - 1]);
}

#[test]
fn removed_child_loses_its_queue() {
    let mut m = line_with_sleepy();
    let child = m.sim.nodes[4].mle.rloc16();
    let eid = m.ml_eid(4);
    m.send_udp(0, eid, b"too late");
    assert!(m.run_until(secs(10), |s| queued(s) == 1));
    // The child disappears and times out at its parent.
    m.sim.isolate(4);
    assert!(m.run_until(secs(1200), |s| {
        s.sim.nodes[3]
            .mle
            .children()
            .find_by_rloc(
                child,
                opentrust_mle::neighbor::StateFilter::AnyExceptInvalid,
            )
            .is_none()
    }));
    m.run(secs(1));
    assert!(m.tmf[3].fwd.indirect.is_empty());
    assert!(m.tmf[3].fwd.indirect.src_match_children().next().is_none());
    assert!(!m.tmf[3].fwd.indirect.frame_pending(child));
}

#[test]
fn parent_supervision_message_makes_the_poll_worthwhile() {
    let mut m = line_with_sleepy();
    let child = m.sim.nodes[4].mle.rloc16();
    // Nothing was sent to the child for the supervision interval.
    assert!(m.run_until(secs(300), |s| s.tmf[3].fwd.indirect.count(child) == 1));
    assert!(m.tmf[4].delivered.is_empty());
    let (fp, outcome) = m.data_poll(4);
    assert!(fp);
    assert_eq!(
        outcome,
        Ok(PollOutcome::Sent {
            frame_pending: false
        })
    );
    // An empty frame: the child's poll succeeded without data.
    assert!(m.frame_log.last().unwrap().2.is_empty());
    assert_eq!(m.tmf[3].fwd.indirect.count(child), 0);
    // The counter restarted: no new supervision message right away.
    m.run(secs(5));
    assert_eq!(m.tmf[3].fwd.indirect.count(child), 0);
}

#[test]
fn multicast_is_queued_for_subscribed_sleepy_children_only() {
    let mut m = line_with_sleepy();
    let mlp = opentrust_mle::test_support::MLP;
    let all = opentrust_net::addr::realm_local_all_thread_nodes(&mlp);
    // Router 3 sends a realm-local multicast: broadcast, plus queued for
    // its sleepy child.
    assert_eq!(m.send_udp(3, all, b"mc"), SendResult::Sent);
    assert_eq!(queued(&m), 1);
    let (fp, _) = m.data_poll(4);
    assert!(fp);
    assert_eq!(&m.tmf[4].delivered[0][48..], b"mc");
    // A multicast group the child never joined: not queued.
    let other = "ff03::1234".parse().unwrap();
    assert_eq!(m.send_udp(3, other, b"mc"), SendResult::Sent);
    assert_eq!(queued(&m), 0);
    // Larger than realm-local without a subscriber: nothing to send.
    let site = "ff05::1234".parse().unwrap();
    assert_eq!(
        m.send_udp(3, site, b"mc"),
        SendResult::Dropped(DropReason::Drop)
    );
}

#[test]
fn queued_messages_become_direct_when_the_child_stops_sleeping() {
    let mut m = line_with_sleepy();
    let eid = m.ml_eid(4);
    m.send_udp(0, eid, b"first");
    assert!(m.run_until(secs(10), |s| queued(s) == 1));
    m.send_udp(0, eid, b"second");
    assert!(m.run_until(secs(10), |s| queued(s) == 2));
    assert!(m.tmf[4].delivered.is_empty());
    // The child becomes rx-on-when-idle (Child Update Request with the new
    // mode): the parent sends both messages directly, in order.
    let now = m.sim.now;
    let n = &mut m.sim.nodes[4];
    n.mle
        .set_device_mode(&mut n.env, now, DeviceMode::new(true, true, true))
        .unwrap();
    assert!(m.run_until(secs(10), |s| s.tmf[4].delivered.len() == 2));
    assert_eq!(&m.tmf[4].delivered[0][48..], b"first");
    assert_eq!(&m.tmf[4].delivered[1][48..], b"second");
    assert_eq!(queued(&m), 0);
    assert!(m.tmf[3].fwd.indirect.src_match_children().next().is_none());
}
