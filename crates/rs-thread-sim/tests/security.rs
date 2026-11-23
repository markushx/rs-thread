mod common;

use common::*;
use rs_thread_instance::PsduRxInfo;

#[test]
fn replayed_secured_frames_are_dropped() {
    let mut net = router_chain(51);
    // The ping puts secured data frames from node 0 to node 1 on the air.
    let dst = net.node(2).rloc().unwrap();
    assert!(ping(&mut net, 0, dst, 8, 5));
    let frame = net
        .tx_log
        .iter()
        .rev()
        .find(|t| t.from == 0 && t.received_by == [1] && t.acked)
        .expect("a frame from node 0 to node 1")
        .psdu
        .clone();
    let before = net.inst(1).replay_drops();
    let now = net.now;
    let info = PsduRxInfo {
        len: frame.len(),
        channel: 15,
        rssi: Some(-60),
        lqi: Some(200),
        timestamp_us: None,
        ack_security: None,
        acked_with_frame_pending: None,
    };
    net.node(1).handle_radio_rx(&frame, &info, now);
    net.settle();
    assert_eq!(net.inst(1).replay_drops(), before + 1);
}
