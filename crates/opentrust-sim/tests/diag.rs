//! Network Diagnostics server: Diagnostic Get and Query over the mesh, the
//! counters reset and the public tables.

mod common;

use common::*;
use opentrust_instance::{Event, Role, diag_tlv};
use opentrust_sim::{Kind, Network};

/// Find the value of TLV `ty` in `tlvs`.
fn find(tlvs: &[u8], ty: u8) -> Option<&[u8]> {
    let mut i = 0;
    while i + 2 <= tlvs.len() {
        let len = usize::from(tlvs[i + 1]);
        let v = tlvs.get(i + 2..i + 2 + len)?;
        if tlvs[i] == ty {
            return Some(v);
        }
        i += 2 + len;
    }
    None
}

#[test]
fn diagnostic_get_and_query() {
    let mut net = Network::new(&[Kind::Router, Kind::Router, Kind::EndDevice], 21);
    net.medium.connect(0, 1, -60);
    net.medium.connect(0, 2, -60);
    let ds = dataset(&mut net);
    start(&mut net, 0, &ds);
    assert!(net.run_until(secs(60), |n| role(n, 0) == Role::Leader));
    start(&mut net, 1, &ds);
    assert!(net.run_until(secs(300), |n| role(n, 1) == Role::Router));
    start(&mut net, 2, &ds);
    assert!(net.run_until(secs(300), |n| role(n, 2) == Role::Child));
    assert!(net.run_until(secs(300), |n| n.node(0).child_table().len() == 1));

    // Node 1 asks the leader (node 0) for its diagnostics.
    let dst = net.node(0).ml_eid();
    let types = [
        diag_tlv::EXT_ADDRESS,
        diag_tlv::SHORT_ADDRESS,
        diag_tlv::MODE,
        diag_tlv::LEADER_DATA,
        diag_tlv::CHILD_TABLE,
        diag_tlv::IP6_ADDR_LIST,
        diag_tlv::MAC_COUNTERS,
        diag_tlv::CONNECTIVITY,
        diag_tlv::ROUTE,
    ];
    net.with(1, |n, now| n.diag_get(dst, &types, now).unwrap());
    assert!(net.run_until(secs(30), |n| {
        n.nodes[1]
            .events
            .iter()
            .any(|e| matches!(e, Event::DiagAnswer))
    }));
    let a = net.node(1).diag_take_answer().unwrap();
    let leader = net.node(0).leader_data();
    assert_eq!(
        find(&a, diag_tlv::EXT_ADDRESS).unwrap(),
        &net.node(0).ext_address().0
    );
    assert_eq!(
        find(&a, diag_tlv::SHORT_ADDRESS).unwrap(),
        &net.node(0).rloc16().0.to_be_bytes()
    );
    assert_eq!(find(&a, diag_tlv::MODE).unwrap().len(), 1);
    let ld = find(&a, diag_tlv::LEADER_DATA).unwrap();
    assert_eq!(&ld[..4], &leader.partition_id.to_be_bytes());
    assert_eq!(
        find(&a, diag_tlv::CHILD_TABLE).unwrap().len(),
        3,
        "one child"
    );
    assert!(find(&a, diag_tlv::IP6_ADDR_LIST).unwrap().len() >= 32);
    assert_eq!(find(&a, diag_tlv::MAC_COUNTERS).unwrap().len(), 36);
    assert!(find(&a, diag_tlv::CONNECTIVITY).is_some());
    assert!(find(&a, diag_tlv::ROUTE).is_some());

    // A query is answered with a separate message carrying the Query ID.
    net.take_events(1);
    net.with(1, |n, now| {
        n.diag_query(dst, &[diag_tlv::VERSION], now).unwrap()
    });
    assert!(net.run_until(secs(30), |n| {
        n.nodes[1]
            .events
            .iter()
            .any(|e| matches!(e, Event::DiagAnswer))
    }));
    let a = net.node(1).diag_take_answer().unwrap();
    assert_eq!(find(&a, diag_tlv::VERSION).unwrap(), &[0, 5]);
    assert!(find(&a, diag_tlv::ANSWER).is_some());

    // Public tables.
    assert_eq!(net.node(0).neighbor_table().len(), 2);
    let r1 = net.node(1).rloc16();
    assert!(
        net.node(0)
            .route_table()
            .iter()
            .any(|r| r.rloc16 == r1 && r.is_neighbor)
    );
    assert!(net.node(0).mac_counters().tx_data > 0);
}
