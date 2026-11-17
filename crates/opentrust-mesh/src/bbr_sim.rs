//! Test glue for the Backbone Router client in the mesh simulator: the
//! per-node [`BbrNode`] (Backbone Router view, DUA manager) driven from the
//! simulator's pump loop, and a [`FakeBbr`] that answers DUA.req on one node
//! like a Primary Backbone Router would.

#![allow(dead_code, missing_debug_implementations)]

extern crate std;

use core::net::Ipv6Addr;

use opentrust_coap::endpoint::Request;
use opentrust_coap::message::{Code, Type};
use opentrust_coap::tmf::Responder;
use opentrust_core::crypto::soft::SoftCrypto;
use opentrust_core::time::Instant;
use opentrust_core::types::Iid;
use opentrust_mle::env::MleEnv;
use opentrust_mle::neighbor::StateFilter;
use opentrust_mle::test_support::TestEnv;
use opentrust_mle::{Mle, Role};
use opentrust_net::slaac::IidParams;

use crate::dua::{
    ChildNotification, DuaContext, DuaManager, DuaResult, USER_DUA_NOTIFY, USER_DUA_REGISTRATION,
    build_dua_status, send_child_notification, send_dua_request,
};
use crate::mlr::{
    MlrContext, MlrManager, MlrResult, USER_MLR, build_mlr_response, parse_mlr_request,
    send_mlr_request,
};
use crate::netdata::backbone::{BackboneRouterLeader, BbrState, DomainPrefixEvent};
use crate::sim::TmfNode;
use crate::tlv::ThreadTlvs;

/// How a request this node sent ended.
#[derive(Debug, Clone)]
pub enum Outcome {
    Timeout,
    Failed,
    Response(Code, std::vec::Vec<u8>),
}

/// The Backbone Router client state of one simulated node.
pub struct BbrNode {
    pub bbr: BackboneRouterLeader,
    pub dua: DuaManager<8>,
    pub mlr: MlrManager<8>,
    /// MLR.req sent (the groups of each).
    pub mlr_sent: std::vec::Vec<std::vec::Vec<Ipv6Addr>>,
    nd_seen: std::vec::Vec<u8>,
    last_role: Role,
    /// DAD counter values handed to the settings hook.
    pub dad_stored: std::vec::Vec<u8>,
    /// DUA.req sent.
    pub dua_requests_sent: u32,
    /// DUA.ntf sent to children.
    pub child_notifications: std::vec::Vec<ChildNotification>,
    /// Primary Backbone Router / Domain Prefix events seen.
    pub events: std::vec::Vec<(BbrState, DomainPrefixEvent)>,
    /// DUA.ntf payloads received (`/n/dn`).
    pub ntf_inbox: std::vec::Vec<std::vec::Vec<u8>>,
    /// An Address Error reported our DUA as a duplicate.
    pub duplicate_flag: bool,
    /// Results of requests this node sent: (user, outcome).
    pub results: std::vec::Vec<(u32, Outcome)>,
    /// Results of MLR.req.
    pub mlr_results: std::vec::Vec<(u32, Outcome)>,
    /// DUAs that were removed after a duplicate report.
    pub dups_handled: u32,
    extra_dua: Option<Ipv6Addr>,
    extra_mcast: std::vec::Vec<Ipv6Addr>,
}

impl BbrNode {
    pub fn new() -> Self {
        Self {
            bbr: BackboneRouterLeader::new(),
            dua: DuaManager::new(),
            mlr: MlrManager::new(),
            mlr_sent: std::vec::Vec::new(),
            nd_seen: std::vec::Vec::new(),
            last_role: Role::Disabled,
            dad_stored: std::vec::Vec::new(),
            dua_requests_sent: 0,
            child_notifications: std::vec::Vec::new(),
            events: std::vec::Vec::new(),
            ntf_inbox: std::vec::Vec::new(),
            duplicate_flag: false,
            results: std::vec::Vec::new(),
            mlr_results: std::vec::Vec::new(),
            dups_handled: 0,
            extra_dua: None,
            extra_mcast: std::vec::Vec::new(),
        }
    }
}

/// A request the fake Primary Backbone Router received.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeenDua {
    /// Node index that received the request.
    pub at: usize,
    pub from: Ipv6Addr,
    pub target: Ipv6Addr,
    pub ml_eid_iid: Iid,
    pub last_transaction_time: Option<u32>,
}

/// Answers `/n/dr` on one node.
#[derive(Default)]
pub struct FakeBbr {
    /// Node that answers (`None`: nobody does).
    pub node: Option<usize>,
    /// Statuses for the next requests; then [`default_dua_status`](Self::default_dua_status).
    pub dua_script: std::collections::VecDeque<u8>,
    /// Status for the next request with this ML-EID IID (used once).
    pub dua_by_ml_eid: std::vec::Vec<(Iid, u8)>,
    pub default_dua_status: u8,
    /// Requests received.
    pub dua_seen: std::vec::Vec<SeenDua>,
    /// Do not answer (to test timeouts).
    pub silent: bool,
    /// Status and failed addresses for the next MLR.req.
    pub mlr_script: std::collections::VecDeque<(u8, std::vec::Vec<Ipv6Addr>)>,
    /// MLR.req received: (node, sender, groups).
    pub mlr_seen: std::vec::Vec<(usize, Ipv6Addr, std::vec::Vec<Ipv6Addr>)>,
}

impl FakeBbr {
    /// Handle a `/n/dr` request on node `idx`.
    pub fn handle_dua(&mut self, idx: usize, req: &Request<'_>, rsp: &mut dyn Responder) {
        if self.node != Some(idx) {
            return;
        }
        let t = ThreadTlvs::new(req.msg.payload());
        let (Ok(target), Ok(iid)) = (t.target(), t.ml_eid()) else {
            return;
        };
        self.dua_seen.push(SeenDua {
            at: idx,
            from: req.ctx.peer.addr,
            target,
            ml_eid_iid: iid,
            last_transaction_time: t.last_transaction_time().ok(),
        });
        if self.silent {
            return;
        }
        let by_iid = self.dua_by_ml_eid.iter().position(|(i, _)| *i == iid);
        let status = match by_iid {
            Some(k) => self.dua_by_ml_eid.remove(k).1,
            None => self
                .dua_script
                .pop_front()
                .unwrap_or(self.default_dua_status),
        };
        let mut buf = [0u8; 32];
        let n = build_dua_status(status, &target, &mut buf).unwrap();
        if req.msg.ty() == Type::Con {
            let _ = rsp.respond(Code::CHANGED, &buf[..n]);
        }
    }
}

impl FakeBbr {
    /// Handle a `/n/mr` request on node `idx`.
    pub fn handle_mlr(&mut self, idx: usize, req: &Request<'_>, rsp: &mut dyn Responder) {
        if self.node != Some(idx) {
            return;
        }
        let Ok(groups) = parse_mlr_request(req.msg.payload()) else {
            return;
        };
        self.mlr_seen
            .push((idx, req.ctx.peer.addr, groups.to_vec()));
        if self.silent {
            return;
        }
        let (status, failed) = self
            .mlr_script
            .pop_front()
            .unwrap_or((0, std::vec::Vec::new()));
        let mut buf = [0u8; 64];
        let n = build_mlr_response(status, &failed, &mut buf).unwrap();
        let _ = rsp.respond(Code::CHANGED, &buf[..n]);
    }
}

fn iid_secret(i: usize) -> [u8; 32] {
    [i as u8 + 1; 32]
}

/// One round of the Backbone Router client glue of node `i`. Returns `true`
/// if something happened that may need another pump round.
pub fn step(i: usize, now: Instant, mle: &mut Mle<4>, env: &mut TestEnv, t: &mut TmfNode) -> bool {
    let mut moved = false;
    let role = mle.role();
    let attached = role.is_attached();
    let secret = iid_secret(i);
    let params = IidParams {
        backend: &SoftCrypto,
        secret: &secret,
        network_id: None,
    };
    let b = &mut t.bbrn;
    let role_changed = role != b.last_role;
    b.last_role = role;

    // Network Data changes.
    let mut nd_event: Option<(BbrState, DomainPrefixEvent)> = None;
    if attached && b.nd_seen[..] != t.netdata.as_bytes()[..] {
        b.nd_seen = t.netdata.as_bytes().to_vec();
        let leader = mle.leader_rloc16();
        nd_event = Some(b.bbr.update(&t.netdata.view(), leader.0));
        b.events.extend(nd_event);
        moved = true;
    }
    let view = t.netdata.view();
    let ctx = DuaContext {
        now,
        attached,
        router_or_leader: role.is_router_or_leader(),
        full_thread_device: mle.is_full_thread_device(),
        parent_1p1: false,
        expected_to_become_router: false,
        bbr: &b.bbr,
        netdata: view,
        ml_eid_iid: opentrust_core::types::ipv6::iid(&env.ml_eid()),
    };
    let netif = &mut t.ip6.netif;
    if let Some((st, ev)) = nd_event {
        b.dua.handle_backbone_router_update(st, &ctx, &mut t.rng);
        b.dua.handle_domain_prefix_event(ev, &ctx, netif, &params);
        b.dua.handle_netdata_changed(&view, netif);
    }
    if role_changed {
        b.dua.handle_role_changed(&ctx, false, &mut t.rng);
    }

    // Duplicate reports and notifications.
    if core::mem::take(&mut b.duplicate_flag) {
        b.dups_handled += 1;
        b.dua.notify_duplicate(&ctx, netif, &params);
        moved = true;
    }
    for p in core::mem::take(&mut b.ntf_inbox) {
        moved = true;
        if let Some(n) = b.dua.handle_notify(&ctx, &p, &mut t.rng, netif, &params) {
            child_notification(&mut t.agent, now, &mut t.rng, &mut t.sink, mle, env, &n);
            b.child_notifications.push(n);
        }
    }
    // Results of our DUA.req.
    for (user, r) in core::mem::take(&mut b.results) {
        moved = true;
        if user != USER_DUA_REGISTRATION {
            continue;
        }
        let res = match &r {
            Outcome::Timeout => DuaResult::Timeout,
            Outcome::Failed => DuaResult::Failed,
            Outcome::Response(code, p) => DuaResult::Response {
                code: *code,
                payload: p,
            },
        };
        if let Some(n) = b.dua.handle_result(&ctx, res, &mut t.rng, netif, &params) {
            child_notification(&mut t.agent, now, &mut t.rng, &mut t.sink, mle, env, &n);
            b.child_notifications.push(n);
        }
    }

    // Multicast Listener Registration.
    let mctx = MlrContext {
        now,
        attached,
        full_thread_device: mle.is_full_thread_device(),
        is_child: role == Role::Child,
        bbr: &b.bbr,
    };
    if let Some((st, _)) = nd_event {
        b.mlr.handle_backbone_router_update(st, &mctx, &mut t.rng);
    }
    if role_changed {
        b.mlr.handle_role_changed(&mctx, &mut t.rng);
    }
    b.mlr.update(&mctx, &mut t.rng, netif, mle.children_mut());
    for (user, r) in core::mem::take(&mut b.mlr_results) {
        moved = true;
        let res = match &r {
            Outcome::Timeout => MlrResult::Timeout,
            Outcome::Failed => MlrResult::Failed,
            Outcome::Response(code, p) => MlrResult::Response {
                code: *code,
                payload: p,
            },
        };
        let _ = user;
        b.mlr
            .handle_result(&mctx, res, &mut t.rng, mle.children_mut());
    }
    if let Some(req) = b.mlr.poll(&mctx, &mut t.rng, mle.children_mut()) {
        moved = true;
        match send_mlr_request(
            &mut t.agent,
            now,
            &mut t.rng,
            &mut t.sink,
            &env.mesh_local_prefix(),
            mle.rloc16(),
            &req,
        ) {
            Ok(()) => b.mlr_sent.push(req.addresses.to_vec()),
            Err(_) => b.mlr.request_not_sent(now, mle.children_mut()),
        }
    }
    if !mle.is_full_thread_device() {
        let groups: std::vec::Vec<Ipv6Addr> =
            netif.external_multicast_larger_than_realm_local().collect();
        if groups != b.extra_mcast {
            env.extra_multicast.clear();
            for g in &groups {
                let _ = env.extra_multicast.push(*g);
            }
            b.extra_mcast = groups;
            mle.schedule_child_update_request(env, now);
            moved = true;
        }
    }

    // Children: their DUAs are registered by proxy.
    b.dua
        .sync_children(&ctx, mle.children().iter(StateFilter::Valid), &mut t.rng);

    if let Some(req) = b.dua.poll(&ctx, netif) {
        moved = true;
        match send_dua_request(
            &mut t.agent,
            now,
            &mut t.rng,
            &mut t.sink,
            &env.mesh_local_prefix(),
            mle.rloc16(),
            &req,
        ) {
            Ok(()) => b.dua_requests_sent += 1,
            Err(_) => b.dua.request_not_sent(now),
        }
    }
    if let Some(c) = b.dua.take_dad_counter_update() {
        b.dad_stored.push(c);
    }

    // An end device registers its DUA with its parent.
    if !mle.is_full_thread_device() {
        let dua = b
            .dua
            .domain_unicast_address()
            .filter(|a| netif.has_unicast(a));
        if dua != b.extra_dua {
            if let Some(old) = b.extra_dua {
                env.extra_addrs.retain(|a| *a != old);
            }
            if let Some(new) = dua {
                let _ = env.extra_addrs.push(new);
            }
            b.extra_dua = dua;
            mle.schedule_child_update_request(env, now);
            moved = true;
        }
    }
    moved
}

fn child_notification(
    agent: &mut crate::sim::TmfAgent,
    now: Instant,
    rng: &mut crate::sim::XRng,
    sink: &mut crate::sim::Sink,
    mle: &mut Mle<4>,
    env: &TestEnv,
    n: &ChildNotification,
) {
    if n.remove_address
        && let Some(c) = mle
            .children_mut()
            .find_by_ext_mut(&n.ext, StateFilter::Valid)
    {
        let _ = c.remove_address(&n.target);
    }
    let _ = send_child_notification(
        agent,
        now,
        rng,
        sink,
        &env.mesh_local_prefix(),
        mle.rloc16(),
        n,
    );
}

/// Earliest deadline of the Backbone Router client of node `t`.
pub fn next_deadline(t: &TmfNode) -> Option<Instant> {
    [t.bbrn.dua.next_deadline(), t.bbrn.mlr.next_deadline()]
        .into_iter()
        .flatten()
        .min()
}

/// Route a TMF outcome with `user` to the Backbone Router client; returns
/// `true` if it was one of ours.
pub fn queue_outcome(t: &mut TmfNode, user: u32, o: Outcome) -> bool {
    if user == USER_DUA_REGISTRATION || user == USER_DUA_NOTIFY {
        t.bbrn.results.push((user, o));
        true
    } else if user == USER_MLR {
        t.bbrn.mlr_results.push((user, o));
        true
    } else {
        false
    }
}
