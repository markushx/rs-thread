//! Leader start, REED / router transitions and router ID bookkeeping.

use opentrust_core::time::Duration;
use opentrust_core::types::Rloc16;

use crate::env::{MleEvent, Role, RouterRequestReason};
use crate::router::{RouterIdReply, SolicitRejection};
use crate::sim::Sim;
use crate::tlv::RouterIdMask;

fn secs(s: u64) -> Duration {
    Duration::from_secs(s)
}

/// Two nodes in range; node 0 started and became leader.
fn leader_sim(n: u8) -> Sim {
    let mut sim = Sim::new(n);
    for i in 1..usize::from(n) {
        sim.connect(0, i, -60);
    }
    sim.start(0);
    assert!(sim.run_until(secs(60), |s| s.role(0) == Role::Leader));
    sim
}

#[test]
fn lone_node_becomes_leader() {
    let mut sim = Sim::new(1);
    sim.start(0);
    assert!(sim.run_until(secs(60), |s| s.role(0) == Role::Leader));
    let n = &sim.nodes[0];
    let ld = *n.mle.leader_data();
    assert_eq!(ld.weighting, 64);
    assert!(ld.leader_router_id <= 62);
    assert_eq!(
        n.mle.rloc16(),
        Rloc16::from_router_id(ld.leader_router_id).unwrap()
    );
    assert_eq!(n.mle.router_id(), Some(ld.leader_router_id));
    assert_eq!(n.mle.active_router_count(), 1);
    assert!(n.mle.router_id_mask().contains(ld.leader_router_id));
    assert_eq!(n.env.short, n.mle.rloc16());
    assert!(n.env.has_event(MleEvent::LeaderStarted {
        partition_id: ld.partition_id
    }));
    assert!(n.env.has_event(MleEvent::PartitionChanged {
        partition_id: ld.partition_id
    }));
    // The leader is its own leader: age 0, cost 0.
    assert_eq!(n.mle.path_cost_to_leader(), 0);
    assert!(!n.mle.is_singleton() || n.mle.active_router_count() <= 1);
    // Network Data of the new partition starts empty and versioned.
    assert_eq!(n.env.nd_leader, Some(ld));
    assert!(n.env.nd.is_empty());
}

#[test]
fn leader_prefers_previous_router_id_and_weight() {
    let mut sim = Sim::new(1);
    sim.nodes[0].mle.set_preferred_router_id(17).unwrap();
    sim.nodes[0].mle.cfg.router.leader_weight = 80;
    sim.start(0);
    assert!(sim.run_until(secs(60), |s| s.role(0) == Role::Leader));
    let n = &sim.nodes[0];
    assert_eq!(n.mle.leader_data().leader_router_id, 17);
    assert_eq!(n.mle.leader_data().weighting, 80);
    assert_eq!(n.mle.rloc16(), Rloc16(17 << 10));
}

#[test]
fn leader_uses_router_id_range_and_preferred_partition() {
    let mut sim = Sim::new(1);
    let m = &mut sim.nodes[0].mle;
    assert_eq!(
        m.set_router_id_range(9, 8),
        Err(opentrust_core::Error::InvalidArgs)
    );
    assert_eq!(
        m.set_router_id_range(0, 63),
        Err(opentrust_core::Error::InvalidArgs)
    );
    m.set_router_id_range(20, 22).unwrap();
    m.cfg.router.preferred_partition_id = 0x1234;
    sim.start(0);
    assert!(sim.run_until(secs(60), |s| s.role(0) == Role::Leader));
    let n = &sim.nodes[0];
    assert!((20..=22).contains(&n.mle.leader_data().leader_router_id));
    assert_eq!(n.mle.leader_data().partition_id, 0x1234);
}

#[test]
fn parent_priority_is_assignable() {
    let mut sim = Sim::new(1);
    let m = &mut sim.nodes[0].mle;
    assert_eq!(
        m.set_parent_priority(2),
        Err(opentrust_core::Error::InvalidArgs)
    );
    assert_eq!(
        m.set_parent_priority(-3),
        Err(opentrust_core::Error::InvalidArgs)
    );
    assert_eq!(
        m.fill_connectivity().parent_priority,
        crate::tlv::ParentPriority::Medium
    );
    m.set_parent_priority(1).unwrap();
    assert_eq!(
        m.fill_connectivity().parent_priority,
        crate::tlv::ParentPriority::High
    );
    m.set_parent_priority(-1).unwrap();
    assert_eq!(
        m.fill_connectivity().parent_priority,
        crate::tlv::ParentPriority::Low
    );
}

#[test]
fn become_leader_checks_weight_when_attached() {
    let mut sim = leader_sim(1);
    // Already leader: no-op.
    let now = sim.now;
    let n = &mut sim.nodes[0];
    assert!(n.mle.become_leader(&mut n.env, now, true).is_ok());
    // Detached device that is not allowed to start a partition.
    let mut sim = Sim::new(1);
    let now = sim.now;
    let n = &mut sim.nodes[0];
    n.mle.start(&mut n.env, now).unwrap();
    n.mle.cfg.router.eligible = false;
    assert!(n.mle.become_leader(&mut n.env, now, false).is_err());
}

#[test]
fn second_node_attaches_as_child_of_the_leader() {
    let mut sim = leader_sim(2);
    sim.start(1);
    assert!(sim.run_until(secs(30), |s| s.role(1) == Role::Child));
    let a = &sim.nodes[0];
    let b = &sim.nodes[1];
    assert_eq!(a.mle.role(), Role::Leader);
    assert_eq!(b.mle.leader_data(), a.mle.leader_data());
    // The REED learned the router ID set from the Child ID Response.
    assert_eq!(b.mle.router_id_mask(), a.mle.router_id_mask());
    assert_eq!(b.mle.active_router_count(), 1);
    assert_eq!(b.mle.router_id_sequence(), a.mle.router_id_sequence());
    let lid = a.mle.leader_router_id();
    assert!(b.mle.router_table().find_by_id(lid).is_some());
    assert_eq!(b.mle.path_cost_to_leader(), 1);
    assert_eq!(b.mle.rloc16().router_id(), lid);
    assert_eq!(
        a.mle.children().count(crate::neighbor::StateFilter::Valid),
        1
    );
}

#[test]
fn reed_requests_a_router_id_and_becomes_router() {
    let mut sim = leader_sim(2);
    sim.start(1);
    assert!(sim.run_until(secs(30), |s| s.role(1) == Role::Child));
    // After the router selection jitter the REED asks for a router ID.
    assert!(sim.run_until(secs(130), |s| !s.nodes[1].env.solicits.is_empty()));
    let req = sim.nodes[1].env.solicits[0];
    assert_eq!(req.reason, RouterRequestReason::TooFewRouters);
    assert_eq!(req.previous_router_id, None);
    assert!(sim.nodes[1].mle.is_address_solicit_pending());

    // Stand-in for the TMF Address Solicit: deliver the request to the leader and the grant back.
    let now = sim.now;
    let ext = sim.nodes[1].env.ext;
    let grant = {
        let a = &mut sim.nodes[0];
        a.mle
            .handle_address_solicit(&mut a.env, now, ext, None, req.reason as u8)
            .unwrap()
    };
    assert_eq!(grant.mask.count(), 2);
    assert!(sim.nodes[0].mle.router_id_sequence() == grant.id_sequence);
    {
        let b = &mut sim.nodes[1];
        b.mle.address_solicit_reply(
            &mut b.env,
            now,
            RouterIdReply::Granted {
                rloc16: grant.rloc16,
                id_sequence: grant.id_sequence,
                mask: grant.mask,
            },
        );
    }
    let b = &sim.nodes[1];
    assert_eq!(b.mle.role(), Role::Router);
    assert_eq!(b.mle.rloc16(), grant.rloc16);
    assert_eq!(b.mle.router_id(), Some(grant.rloc16.router_id()));
    assert_eq!(b.mle.active_router_count(), 2);
    assert!(!b.mle.is_address_solicit_pending());
    assert_eq!(b.env.short, grant.rloc16);
    // The former parent (the leader) stays a neighbor and the route to the
    // leader survives.
    assert!(b.mle.path_cost_to_leader() < 16);
}

#[test]
fn rejected_or_failed_solicit_keeps_the_child_role() {
    let mut sim = leader_sim(2);
    sim.start(1);
    assert!(sim.run_until(secs(30), |s| s.role(1) == Role::Child));
    assert!(sim.run_until(secs(130), |s| !s.nodes[1].env.solicits.is_empty()));
    let now = sim.now;
    let b = &mut sim.nodes[1];
    b.mle
        .address_solicit_reply(&mut b.env, now, RouterIdReply::Rejected);
    assert_eq!(b.mle.role(), Role::Child);
    assert!(!b.mle.is_address_solicit_pending());
    // Without a request in flight a reply is ignored.
    b.mle
        .address_solicit_reply(&mut b.env, now, RouterIdReply::Failed);
    assert_eq!(b.mle.role(), Role::Child);
}

#[test]
fn child_id_request_makes_a_reed_ask_for_a_router_id() {
    // A REED (node 1, child of the leader) gets a Child ID Request from a
    // third node: it asks for a router ID and answers after the grant.
    let mut sim = leader_sim(3);
    sim.connect(1, 2, -60);
    sim.disconnect(0, 2);
    sim.start(1);
    assert!(sim.run_until(secs(30), |s| s.role(1) == Role::Child));
    sim.start(2);
    assert!(sim.run_until(secs(20), |s| !s.nodes[1].env.solicits.is_empty()));
    assert_eq!(
        sim.nodes[1].env.solicits[0].reason,
        RouterRequestReason::HaveChildIdRequest
    );
    assert_eq!(sim.role(2), Role::Detached);
    let now = sim.now;
    let ext = sim.nodes[1].env.ext;
    let grant = {
        let a = &mut sim.nodes[0];
        a.mle
            .handle_address_solicit(
                &mut a.env,
                now,
                ext,
                None,
                RouterRequestReason::HaveChildIdRequest as u8,
            )
            .unwrap()
    };
    {
        let b = &mut sim.nodes[1];
        b.mle.address_solicit_reply(
            &mut b.env,
            now,
            RouterIdReply::Granted {
                rloc16: grant.rloc16,
                id_sequence: grant.id_sequence,
                mask: grant.mask,
            },
        );
    }
    sim.pump();
    assert_eq!(sim.role(1), Role::Router);
    assert!(sim.run_until(secs(10), |s| s.role(2) == Role::Child));
    // The new child lives under the new router's ID.
    assert_eq!(
        sim.nodes[2].mle.rloc16().router_id(),
        grant.rloc16.router_id()
    );
}

#[test]
fn leader_allocates_and_releases_router_ids() {
    let mut sim = leader_sim(1);
    let now = sim.now;
    let a = &mut sim.nodes[0];
    let e1 = crate::test_support::ext(0x31);
    let e2 = crate::test_support::ext(0x32);
    let seq0 = a.mle.router_id_sequence();

    // Too few routers is justified, the preferred ID is honoured.
    let g1 = a
        .mle
        .handle_address_solicit(
            &mut a.env,
            now,
            e1,
            Some(Rloc16(40 << 10)),
            RouterRequestReason::TooFewRouters as u8,
        )
        .unwrap();
    assert_eq!(g1.rloc16, Rloc16(40 << 10));
    assert_eq!(g1.id_sequence, seq0.wrapping_add(1));
    assert_eq!(g1.mask.count(), 2);
    // Asking again with the same ML-EUI64 returns the same ID.
    let again = a
        .mle
        .handle_address_solicit(&mut a.env, now, e1, None, 2)
        .unwrap();
    assert_eq!(again.rloc16, g1.rloc16);
    // Unknown status.
    assert_eq!(
        a.mle.handle_address_solicit(&mut a.env, now, e2, None, 99),
        Err(SolicitRejection::UnrecognizedStatus)
    );
    // Release by the holder only.
    assert!(
        a.mle
            .handle_address_release(&mut a.env, now, g1.rloc16, e2)
            .is_err()
    );
    a.mle
        .handle_address_release(&mut a.env, now, g1.rloc16, e1)
        .unwrap();
    assert_eq!(a.mle.active_router_count(), 1);
    assert_eq!(a.mle.router_id_sequence(), seq0.wrapping_add(2));
    // The ID cannot be reassigned during ID_REUSE_DELAY.
    let g2 = a
        .mle
        .handle_address_solicit(
            &mut a.env,
            now,
            e2,
            Some(Rloc16(40 << 10)),
            RouterRequestReason::HaveChildIdRequest as u8,
        )
        .unwrap();
    assert_ne!(g2.rloc16.router_id(), 40);
    sim.run(secs(101));
    let now = sim.now;
    let a = &mut sim.nodes[0];
    let e3 = crate::test_support::ext(0x33);
    let g3 = a
        .mle
        .handle_address_solicit(
            &mut a.env,
            now,
            e3,
            Some(Rloc16(40 << 10)),
            RouterRequestReason::HaveChildIdRequest as u8,
        )
        .unwrap();
    assert_eq!(g3.rloc16.router_id(), 40);
}

#[test]
fn too_few_routers_is_refused_at_the_threshold() {
    let mut sim = leader_sim(1);
    let now = sim.now;
    let a = &mut sim.nodes[0];
    a.mle.cfg.router.upgrade_threshold = 1;
    assert_eq!(
        a.mle.handle_address_solicit(
            &mut a.env,
            now,
            crate::test_support::ext(0x40),
            None,
            RouterRequestReason::TooFewRouters as u8
        ),
        Err(SolicitRejection::NoAddressAvailable)
    );
    // A child that needs a parent is still served.
    assert!(
        a.mle
            .handle_address_solicit(
                &mut a.env,
                now,
                crate::test_support::ext(0x40),
                None,
                RouterRequestReason::HaveChildIdRequest as u8
            )
            .is_ok()
    );
    // Only the leader answers.
    let mut sim = Sim::new(1);
    let now = sim.now;
    let n = &mut sim.nodes[0];
    assert!(
        n.mle
            .handle_address_solicit(&mut n.env, now, crate::test_support::ext(1), None, 2)
            .is_err()
    );
}

#[test]
fn router_downgrades_when_too_many_routers_are_active() {
    let mut sim = leader_sim(2);
    sim.start(1);
    assert!(sim.run_until(secs(30), |s| s.role(1) == Role::Child));
    assert!(sim.run_until(secs(130), |s| !s.nodes[1].env.solicits.is_empty()));
    let now = sim.now;
    let ext = sim.nodes[1].env.ext;
    let grant = {
        let a = &mut sim.nodes[0];
        a.mle
            .handle_address_solicit(&mut a.env, now, ext, None, 2)
            .unwrap()
    };
    {
        let b = &mut sim.nodes[1];
        b.mle.address_solicit_reply(
            &mut b.env,
            now,
            RouterIdReply::Granted {
                rloc16: grant.rloc16,
                id_sequence: grant.id_sequence,
                mask: grant.mask,
            },
        );
    }
    assert_eq!(sim.role(1), Role::Router);
    // The router sees more routers than the downgrade threshold: after the
    // role transition delay it re-attaches as a REED and releases its ID.
    sim.nodes[1].mle.cfg.router.downgrade_threshold = 1;
    sim.nodes[1].mle.cfg.router.selection_jitter_secs = 3;
    {
        let b = &mut sim.nodes[1];
        b.mle.start_role_transition(&mut b.env);
    }
    let mut mask = RouterIdMask::new();
    for id in [
        grant.rloc16.router_id(),
        sim.nodes[0].mle.leader_router_id(),
        50,
        51,
    ] {
        mask.insert(id).unwrap();
    }
    let seq = sim.nodes[1].mle.router_id_sequence();
    let now = sim.now;
    {
        let b = &mut sim.nodes[1];
        b.mle.update_router_id_set(&mut b.env, now, seq, &mask);
    }
    assert!(sim.nodes[1].mle.active_router_count() > 1);
    let attach_started = sim.run_until(secs(10), |s| s.nodes[1].mle.is_attaching());
    assert!(attach_started);
    assert_eq!(
        sim.nodes[1].mle.attach.mode,
        crate::attach::AttachMode::DowngradeToReed
    );
}
