//! Router ID assignment over TMF: wire formats, OT response handling and
//! multi-node scenarios through real CoAP messages.

use opentrust_coap::message::{Code, Message, MessageBuilder, Type};
use opentrust_core::time::Duration;
use opentrust_core::types::{ExtAddress, Rloc16};
use opentrust_mle::Role;
use opentrust_mle::env::{RouterIdRequest, RouterRequestReason};
use opentrust_mle::neighbor::StateFilter;
use opentrust_mle::router::{RouterIdGrant, RouterIdReply, SolicitRejection};
use opentrust_mle::tlv::RouterIdMask;

use crate::router_id::*;
use crate::sim::MeshSim;
use crate::tlv::{ThreadTlvs, status};

fn secs(s: u64) -> Duration {
    Duration::from_secs(s)
}

fn coap_response(code: Code, payload: &[u8]) -> std::vec::Vec<u8> {
    let mut b = [0u8; 64];
    let m = MessageBuilder::new(&mut b, Type::Ack, code, 1, &[1]).unwrap();
    let n = m.finish_with_payload(payload).unwrap();
    b[..n].to_vec()
}

fn grant() -> RouterIdGrant {
    let mut mask = RouterIdMask::new();
    mask.insert(0).unwrap();
    mask.insert(5).unwrap();
    RouterIdGrant {
        rloc16: Rloc16(5 << 10),
        id_sequence: 9,
        mask,
    }
}

#[test]
fn solicit_request_roundtrip() {
    let ext = ExtAddress([2, 0, 0, 0, 0, 0, 0, 7]);
    let req = RouterIdRequest {
        previous_router_id: Some(3),
        reason: RouterRequestReason::HaveChildIdRequest,
    };
    let mut buf = [0u8; 32];
    let n = build_address_solicit(ext, &req, &mut buf).unwrap();
    // Extended MAC Address, RLOC16, Status in this order like OT.
    assert_eq!(
        &buf[..n],
        &[1, 8, 2, 0, 0, 0, 0, 0, 0, 7, 2, 2, 0x0c, 0, 4, 1, 3]
    );
    let p = parse_address_solicit(&buf[..n]).unwrap();
    assert_eq!(p.ext, ext);
    assert_eq!(p.previous, Some(Rloc16(3 << 10)));
    assert_eq!(p.status, 3);

    let req = RouterIdRequest {
        previous_router_id: None,
        reason: RouterRequestReason::TooFewRouters,
    };
    let n = build_address_solicit(ext, &req, &mut buf).unwrap();
    let p = parse_address_solicit(&buf[..n]).unwrap();
    assert_eq!(p.previous, None);
    assert_eq!(p.status, 2);

    // Missing TLVs / malformed RLOC16.
    assert!(parse_address_solicit(&[4, 1, 2]).is_err());
    assert!(parse_address_solicit(&[1, 8, 2, 0, 0, 0, 0, 0, 0, 7]).is_err());
    assert!(parse_address_solicit(&[1, 8, 2, 0, 0, 0, 0, 0, 0, 7, 4, 1, 2, 2, 1, 0]).is_err());
}

#[test]
fn solicit_response_codec_and_status_codes() {
    let mut buf = [0u8; 32];
    let n = build_address_solicit_response(Ok(grant()), &mut buf).unwrap();
    let t = ThreadTlvs::new(&buf[..n]);
    assert_eq!(t.status().unwrap(), status::SUCCESS);
    assert_eq!(t.rloc16().unwrap(), Rloc16(5 << 10));
    assert_eq!(t.router_mask().unwrap().0, 9);

    let reply = |code, payload: &[u8]| {
        let raw = coap_response(code, payload);
        parse_address_solicit_response(&Message::parse(&raw).unwrap())
    };
    assert_eq!(
        reply(Code::CHANGED, &buf[..n]),
        RouterIdReply::Granted {
            rloc16: grant().rloc16,
            id_sequence: 9,
            mask: grant().mask,
        }
    );
    // Not 2.04, or no / unusable Status TLV: failure.
    assert_eq!(reply(Code::CONTENT, &buf[..n]), RouterIdReply::Failed);
    assert_eq!(reply(Code::CHANGED, &[]), RouterIdReply::Failed);
    // Success without RLOC16 or Router Mask: failure.
    assert_eq!(reply(Code::CHANGED, &[4, 1, 0]), RouterIdReply::Failed);
    assert_eq!(
        reply(Code::CHANGED, &[4, 1, 0, 2, 2, 0, 0]),
        RouterIdReply::Failed
    );
    // Refusals.
    let n = build_address_solicit_response(Err(SolicitRejection::NoAddressAvailable), &mut buf)
        .unwrap();
    assert_eq!(&buf[..n], &[4, 1, 1]);
    assert_eq!(reply(Code::CHANGED, &buf[..n]), RouterIdReply::Rejected);
    let n = build_address_solicit_response(Err(SolicitRejection::UnrecognizedStatus), &mut buf)
        .unwrap();
    assert_eq!(&buf[..n], &[4, 1, 6]);
    assert_eq!(reply(Code::CHANGED, &buf[..n]), RouterIdReply::Rejected);

    assert_eq!(
        client_failure(USER_ADDRESS_SOLICIT),
        Some(RouterIdReply::Failed)
    );
    assert_eq!(client_failure(USER_ADDRESS_RELEASE), None);
}

fn leader_mesh(n: u8) -> MeshSim {
    let mut m = MeshSim::new(n);
    for a in 0..usize::from(n) {
        for b in a + 1..usize::from(n) {
            m.connect(a, b, -60);
        }
    }
    m.start(0);
    assert!(m.run_until(secs(60), |s| s.sim.role(0) == Role::Leader));
    m
}

#[test]
fn leader_and_two_routers_get_ids_over_tmf() {
    let mut m = leader_mesh(3);
    m.start(1);
    assert!(m.run_until(secs(30), |s| s.sim.role(1) == Role::Child));
    m.start(2);
    assert!(m.run_until(secs(30), |s| s.sim.role(2) == Role::Child));
    // REEDs upgrade after their selection jitter; the Address Solicit and
    // its response are real CoAP messages.
    assert!(m.run_until(secs(300), |s| {
        s.sim.role(1) == Role::Router && s.sim.role(2) == Role::Router
    }));
    assert_eq!(m.sim.nodes[0].mle.active_router_count(), 3);
    assert_eq!(*m.tmf[0].rx.get(&uri_id_as()).unwrap(), 2);
    // Router IDs are distinct and everybody learned the mask.
    let ids: std::collections::BTreeSet<u8> = (0..3)
        .map(|i| m.sim.nodes[i].mle.router_id().unwrap())
        .collect();
    assert_eq!(ids.len(), 3);
    assert!(m.run_until(secs(120), |s| {
        s.sim
            .nodes
            .iter()
            .all(|n| n.mle.router_table().count(StateFilter::Valid) == 2)
    }));
    let mask = m.sim.nodes[0].mle.router_id_mask();
    for n in &m.sim.nodes {
        assert_eq!(n.mle.router_id_mask(), mask);
    }
    // The client side has no request pending any more.
    assert!(!m.sim.nodes[1].mle.is_address_solicit_pending());
}

fn uri_id_as() -> u16 {
    opentrust_coap::uri::Uri::AddressSolicit.id()
}

fn uri_id_ar() -> u16 {
    opentrust_coap::uri::Uri::AddressRelease.id()
}

#[test]
fn router_downgrade_releases_the_id_over_tmf() {
    let mut m = leader_mesh(2);
    m.start(1);
    assert!(m.run_until(secs(30), |s| s.sim.role(1) == Role::Child));
    assert!(m.run_until(secs(300), |s| s.sim.role(1) == Role::Router));
    assert_eq!(m.sim.nodes[0].mle.active_router_count(), 2);
    let id = m.sim.nodes[1].mle.router_id().unwrap();
    m.sim.force_downgrade(1);
    assert!(m.run_until(secs(60), |s| s.sim.role(1) == Role::Child));
    assert!(m.run_until(secs(60), |s| {
        s.tmf[0].rx.get(&uri_id_ar()).copied().unwrap_or(0) >= 1
    }));
    // The leader freed the ID (sequence bumped, router entry gone).
    assert!(m.run_until(secs(30), |s| {
        !s.sim.nodes[0].mle.router_id_mask().contains(id)
    }));
    assert_eq!(m.sim.nodes[0].mle.active_router_count(), 1);
}

#[test]
fn no_answer_leaves_the_reed_a_child() {
    let mut m = leader_mesh(2);
    m.start(1);
    assert!(m.run_until(secs(30), |s| s.sim.role(1) == Role::Child));
    // Requests reach nobody: the TMF messages are lost.
    m.blocked.push((1, 0));
    m.blocked.push((0, 1));
    assert!(m.run_until(secs(300), |s| {
        s.sim.nodes[1].mle.is_address_solicit_pending()
    }));
    assert!(m.run_until(secs(200), |s| {
        !s.sim.nodes[1].mle.is_address_solicit_pending()
    }));
    assert_eq!(m.sim.role(1), Role::Child);
    assert_eq!(m.tmf[0].rx.get(&uri_id_as()), None);
    assert_eq!(m.sim.nodes[0].mle.active_router_count(), 1);
}

#[test]
fn unrecognized_status_and_foreign_requests() {
    let mut m = leader_mesh(2);
    m.start(1);
    assert!(m.run_until(secs(30), |s| s.sim.role(1) == Role::Child));
    // Stop node 1's own solicit so the raw request below is the only one.
    let now = m.sim.now;
    let n1 = &mut m.sim.nodes[1];
    n1.mle.set_router_eligible(&mut n1.env, now, false);
    let ext = m.sim.nodes[1].env.ext;
    let mut payload = [0u8; 32];
    let req = RouterIdRequest {
        previous_router_id: None,
        reason: RouterRequestReason::TooFewRouters,
    };
    let n = build_address_solicit(ext, &req, &mut payload).unwrap();
    // Status 9 is not a known reason.
    payload[n - 1] = 9;
    let reply = m.raw_request(1, 0, "a/as", Type::Con, Code::POST, &payload[..n]);
    let (code, body) = reply.expect("leader answers");
    assert_eq!(code, Code::CHANGED);
    assert_eq!(body, [4, 1, 6]);

    // A NON request is not answered; neither is a non-leader.
    assert!(
        m.raw_request(1, 0, "a/as", Type::Non, Code::POST, &payload[..n])
            .is_none()
    );
    assert!(
        m.raw_request(0, 1, "a/as", Type::Con, Code::POST, &payload[..n])
            .is_none()
    );
    assert_eq!(m.sim.nodes[0].mle.active_router_count(), 1);
}
