//! End-to-end scenario through the whole mesh layer, run twice to show
//! that the simulation is deterministic: routers get their IDs over
//! TMF, a datagram is resolved and routed over three hops to a sleepy
//! child behind another router, the child polls, and answers back.

use rs_thread_core::time::Duration;
use rs_thread_mle::Role;
use rs_thread_mle::tlv::DeviceMode;

use crate::forwarder::SendResult;
use crate::sim::MeshSim;

fn secs(s: u64) -> Duration {
    Duration::from_secs(s)
}

type Log = std::vec::Vec<(usize, usize, std::vec::Vec<u8>)>;

fn scenario() -> (Log, [usize; 5], std::vec::Vec<u8>) {
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
    assert!(m.run_until(secs(10), |s| !s.sim.nodes[3].env.indirect.is_empty()));
    m.frame_log.clear();

    // Leader to the sleepy child.
    let child_eid = m.ml_eid(4);
    assert_eq!(m.send_udp(0, child_eid, b"ping"), SendResult::Held);
    let child = m.sim.nodes[4].mle.rloc16();
    assert!(m.run_until(secs(10), |s| s.tmf[3].fwd.indirect.count(child) == 1));
    let (fp, out) = m.data_poll(4);
    assert!(fp);
    out.unwrap();
    assert_eq!(&m.tmf[4].delivered[0][48..], b"ping");

    // The child answers: plain frame to its parent, which resolves the
    // leader's EID and routes the datagram over three hops.
    assert_eq!(m.send_udp(4, m.ml_eid(0), b"pong"), SendResult::Sent);
    assert!(m.run_until(secs(10), |s| s.tmf[0].delivered.len() == 1));
    assert_eq!(&m.tmf[0].delivered[0][48..], b"pong");
    let reply = m.tmf[0].delivered[0].clone();

    let counts = [
        m.tmf[0].forwarded as usize,
        m.tmf[1].forwarded as usize,
        m.tmf[2].forwarded as usize,
        m.tmf[3].forwarded as usize,
        m.tmf[4].forwarded as usize,
    ];
    (m.frame_log, counts, reply)
}

#[test]
fn sleepy_child_round_trip_over_the_mesh_is_deterministic() {
    let (log1, fwd1, reply1) = scenario();
    let (log2, fwd2, reply2) = scenario();
    assert!(log1.len() > 6);
    assert_eq!(log1, log2);
    assert_eq!(fwd1, fwd2);
    assert_eq!(reply1, reply2);
    // The reply crossed routers 3 -> 2 -> 1 -> 0 as mesh frames; the
    // routers in the middle forwarded, the end points did not.
    assert!(fwd1[1] >= 2 && fwd1[2] >= 2);
    assert_eq!(fwd1[0], 0);
    assert_eq!(fwd1[4], 0);
}
