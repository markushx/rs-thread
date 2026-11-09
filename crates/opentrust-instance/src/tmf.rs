//! TMF: the request handlers of this node, the outcomes of its own
//! requests and the timers of the agent.

use heapless::Vec;
use opentrust_coap::endpoint::{Event as CoapEvent, Request};
use opentrust_coap::message::Code;
use opentrust_coap::tmf::{Handler, Responder, TmfEnv, TmfRx};
use opentrust_coap::uri::Uri;
use opentrust_core::crypto::CryptoBackend;
use opentrust_core::time::Instant;
use opentrust_core::types::Prefix64;
use opentrust_mesh::address::{self, AddressAction, AddressErrorOutcome};
use opentrust_mesh::netdata::anycast;
use opentrust_mesh::netdata::backbone::BackboneRouterLeader;
use opentrust_mesh::netdata::leader::{Changed, Leader};
use opentrust_mesh::netdata::server_data::{self, USER_SERVER_DATA};
use opentrust_mesh::router_id;
use opentrust_meshcop::dataset::DatasetType;
use opentrust_meshcop::mgmt::{self, MgmtCommand};
use opentrust_mle::Mle;
use opentrust_net::resolver::{AddressResolver, ResolverEvent};
use opentrust_net::udp::UdpMeta;
use opentrust_platform::SettingsStore;
use rand_core::Rng;

use crate::stack::{CHILDREN, Core, NETDATA_LEN, SolicitCmd};
use crate::{Instance, TmfAgent};

/// The URIs this node serves.
pub(crate) fn register_uris(agent: &mut TmfAgent) {
    for u in [
        Uri::AddressSolicit,
        Uri::AddressRelease,
        Uri::AddressQuery,
        Uri::AddressNotify,
        Uri::AddressError,
        Uri::ServerData,
        Uri::AnycastLocate,
        Uri::ActiveGet,
        Uri::PendingGet,
        Uri::ActiveSet,
        Uri::PendingSet,
        Uri::ActiveReplace,
        Uri::DatasetChanged,
    ] {
        let _ = agent.register(u);
    }
}

struct MlTmfEnv(Prefix64);

impl TmfEnv for MlTmfEnv {
    fn is_mesh_local(&self, a: &core::net::Ipv6Addr) -> bool {
        opentrust_net::addr::is_mesh_local(a, &self.0)
    }
}

/// What a handler leaves for after the dispatch (it cannot reach the agent).
#[derive(Default)]
struct Deferred {
    actions: Vec<AddressAction, 4>,
    events: Vec<ResolverEvent, 4>,
    sd_changed: Changed,
    outcomes: Vec<mgmt::SetOutcome, 2>,
    duplicate_dua: bool,
}

struct NodeHandler<'a, S, C: CryptoBackend, R> {
    mle: &'a mut Mle<CHILDREN>,
    core: &'a mut Core<S, C, R>,
    leader: &'a mut Leader<NETDATA_LEN>,
    resolver: &'a mut AddressResolver<8>,
    now: Instant,
    out: Deferred,
}

impl<S: SettingsStore, C: CryptoBackend + Clone, R: Rng> Handler for NodeHandler<'_, S, C, R> {
    fn handle(&mut self, uri: Uri, req: &Request<'_>, rsp: &mut dyn Responder) {
        let now = self.now;
        let iid = self.core.ml_iid;
        match uri {
            Uri::AddressSolicit => {
                if let Some(h) =
                    router_id::handle_address_solicit(self.mle, self.core, now, req, rsp)
                    && let Some(old) = h.stale_rloc16
                {
                    self.resolver.remove_entries_for_rloc16(old);
                }
            }
            Uri::AddressRelease => {
                router_id::handle_address_release(self.mle, self.core, now, req, rsp);
            }
            Uri::AddressQuery => {
                if let Some(a) =
                    address::handle_address_query(&self.core.ip6.netif, self.mle, &iid, now, req)
                {
                    let _ = self.out.actions.push(a);
                }
            }
            Uri::AddressNotify => {
                let events = &mut self.out.events;
                address::handle_address_notify(self.resolver, now, req, rsp, &mut |e| {
                    let _ = events.push(e);
                });
            }
            Uri::AddressError => {
                let bbr = BackboneRouterLeader::default();
                match address::handle_address_error(
                    &mut self.core.ip6.netif,
                    self.mle,
                    &iid,
                    &bbr,
                    req,
                    rsp,
                ) {
                    AddressErrorOutcome::Ignored | AddressErrorOutcome::AddressRemoved => {}
                    AddressErrorOutcome::DuplicateDomainUnicast => self.out.duplicate_dua = true,
                    AddressErrorOutcome::ChildAddressRemoved(a) => {
                        let _ = self.out.actions.push(a);
                    }
                }
            }
            Uri::ServerData => {
                if let Some(c) =
                    server_data::handle_server_data(self.leader, self.mle, self.core, now, req, rsp)
                {
                    self.out.sd_changed.any |= c.any;
                    self.out.sd_changed.stable |= c.stable;
                }
            }
            Uri::AnycastLocate => {
                anycast::handle_anycast_locate(iid, self.mle.rloc16(), req, rsp);
            }
            Uri::ActiveGet => {
                mgmt::handle_get(&self.core.datasets, now, DatasetType::Active, req, rsp);
            }
            Uri::PendingGet => {
                mgmt::handle_get(&self.core.datasets, now, DatasetType::Pending, req, rsp);
            }
            Uri::ActiveSet | Uri::PendingSet | Uri::ActiveReplace => {
                let (t, cmd) = match uri {
                    Uri::ActiveSet => (DatasetType::Active, MgmtCommand::Set),
                    Uri::ActiveReplace => (DatasetType::Active, MgmtCommand::Replace),
                    _ => (DatasetType::Pending, MgmtCommand::Set),
                };
                let (ds, mut env) = self.core.ds();
                let o = mgmt::handle_set(ds, &mut env, now, t, cmd, req, rsp);
                let _ = self.out.outcomes.push(o);
            }
            Uri::DatasetChanged => {
                let _ = rsp.respond(Code::CHANGED, &[]);
            }
            _ => {}
        }
    }
}

impl<S: SettingsStore, C: CryptoBackend + Clone, R: Rng> Instance<S, C, R> {
    /// A datagram for the TMF port.
    pub(crate) fn handle_tmf(&mut self, now: Instant, meta: &UdpMeta, payload: &[u8]) {
        let env = MlTmfEnv(self.core.cfg.cur.mesh_local_prefix);
        let mut h = NodeHandler {
            mle: &mut self.mle,
            core: &mut self.core,
            leader: &mut self.leader,
            resolver: &mut self.resolver,
            now,
            out: Deferred::default(),
        };
        let r = self
            .agent
            .handle_dispatch(now, &mut self.sink, &env, meta, payload, &mut h);
        let out = core::mem::take(&mut h.out);
        match r {
            TmfRx::Response { user, msg, .. } => {
                if let Some(rep) = router_id::client_response(user, &msg) {
                    self.mle.address_solicit_reply(&mut self.core, now, rep);
                } else if user == USER_SERVER_DATA {
                    self.notifier.response(now, true);
                } else if let Some(t) = mgmt::set_user_type(user) {
                    let _ = mgmt::set_response(&msg);
                    self.core.datasets.mgmt_set_finished(now, t);
                } else if user == anycast::USER_ANYCAST_LOCATE
                    && let Ok(l) =
                        anycast::parse_response(&msg, self.core.cfg.cur.mesh_local_prefix)
                {
                    self.glue.located = Some(l);
                }
            }
            TmfRx::Failed { user, .. } => self.tmf_failed(now, user),
            _ => {}
        }
        if out.sd_changed.any {
            self.leader_changed(now);
        }
        for a in out.actions {
            let own = self.mle.rloc16();
            let _ = address::send_action(
                &mut self.agent,
                now,
                &mut self.prng,
                &mut self.sink,
                own,
                &self.core,
                &a,
            );
        }
        for e in out.events {
            self.handle_resolver_event(now, e);
        }
        for o in out.outcomes {
            if let Some(session) = o.notify_commissioner {
                let _ = session;
            }
        }
        if out.duplicate_dua {
            // The DUA manager reacts to duplicates; no DUA is configured.
        }
    }

    fn tmf_failed(&mut self, now: Instant, user: u32) {
        if let Some(r) = router_id::client_failure(user) {
            self.mle.address_solicit_reply(&mut self.core, now, r);
        } else if user == USER_SERVER_DATA {
            self.notifier.response(now, false);
        } else if let Some(t) = mgmt::set_user_type(user) {
            self.core.datasets.mgmt_set_finished(now, t);
        }
    }

    /// TMF timers and the requests MLE and the dataset managers queued.
    pub(crate) fn service_tmf(&mut self, now: Instant) -> bool {
        let mut busy = false;
        while let Some(cmd) = self.core.solicit.pop_front() {
            busy = true;
            match cmd {
                SolicitCmd::Request(r) => {
                    let _ = self.solicit.request_router_id(&r);
                }
                SolicitCmd::Release(r) => self.solicit.release_router_id(r),
            }
        }
        if self.solicit.is_pending() {
            busy = true;
            self.solicit.flush(
                &mut self.agent,
                now,
                &mut self.prng,
                &mut self.sink,
                &mut self.mle,
                &mut self.core,
            );
        }
        while let Some(ev) = self.agent.poll(now, &mut self.sink) {
            busy = true;
            let CoapEvent::Timeout { user } = ev;
            self.tmf_failed(now, user);
        }
        let mut evs: Vec<ResolverEvent, 4> = Vec::new();
        self.resolver.poll(now, &mut |e| {
            let _ = evs.push(e);
        });
        for e in evs {
            busy = true;
            self.handle_resolver_event(now, e);
        }
        // Local datasets newer than the network's go to the leader.
        let role = self.mle.role();
        if role.is_attached() && role != opentrust_mle::Role::Leader {
            let mlp = self.core.cfg.cur.mesh_local_prefix;
            let own = self.mle.rloc16();
            let n = mgmt::flush_set_requests(
                &mut self.core.datasets,
                &mut self.agent,
                now,
                &mut self.prng,
                &mut self.sink,
                role,
                &mlp,
                own,
            );
            busy |= n > 0;
        }
        busy
    }
}
