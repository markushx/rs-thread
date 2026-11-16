//! TMF: the request handlers of this node, the outcomes of its own
//! requests and the timers of the agent.

use heapless::Vec;
use opentrust_coap::endpoint::{Event as CoapEvent, Request};
use opentrust_coap::message::Code;
use opentrust_coap::tmf::{Handler, Responder, TmfEnv, TmfRx};
use opentrust_coap::uri::Uri;
use opentrust_core::crypto::CryptoBackend;
use opentrust_core::time::Instant;
use opentrust_core::types::{Prefix64, Rloc16};
use opentrust_mesh::address::{self, AddressAction, AddressErrorOutcome};
use opentrust_mesh::netdata::anycast;
#[cfg(feature = "ftd")]
use opentrust_mesh::netdata::leader::{Changed, Leader};
#[cfg(feature = "ftd")]
use opentrust_mesh::netdata::server_data;
use opentrust_mesh::netdata::server_data::USER_SERVER_DATA;
#[cfg(feature = "ftd")]
use opentrust_mesh::router_id;
use opentrust_meshcop::dataset::DatasetType;
use opentrust_meshcop::mgmt;
#[cfg(feature = "ftd")]
use opentrust_meshcop::mgmt::MgmtCommand;
use opentrust_mle::Mle;
use opentrust_net::resolver::{AddressResolver, ResolverEvent};
use opentrust_net::udp::UdpMeta;
use opentrust_platform::SettingsStore;
use rand_core::{CryptoRng, Rng};

use crate::InstanceCrypto;

use crate::stack::{CHILDREN, Core};
#[cfg(feature = "ftd")]
use crate::stack::{NETDATA_LEN, SolicitCmd};
use crate::{Instance, TmfAgent};

/// The URIs this node serves.
pub(crate) fn register_uris(agent: &mut TmfAgent) {
    for u in [
        Uri::AddressNotify,
        Uri::AddressError,
        Uri::AnycastLocate,
        Uri::DuaRegistrationNotify,
        Uri::DiagnosticGetRequest,
        Uri::DiagnosticGetQuery,
        Uri::DiagnosticReset,
        Uri::DiagnosticGetAnswer,
        Uri::ActiveGet,
        Uri::PendingGet,
        Uri::DatasetChanged,
    ] {
        let _ = agent.register(u);
    }
    #[cfg(feature = "scan-servers")]
    for u in [Uri::EnergyScan, Uri::PanIdQuery, Uri::AnnounceBegin] {
        let _ = agent.register(u);
    }
    #[cfg(feature = "commissioner")]
    for u in [Uri::EnergyReport, Uri::PanIdConflict] {
        let _ = agent.register(u);
    }
    // Relay of Joiner DTLS records: the Joiner Router takes `/c/tx`, the
    // Commissioner / Border Agent `/c/rx`.
    #[cfg(feature = "ftd")]
    let _ = agent.register(Uri::RelayTx);
    #[cfg(feature = "commissioner")]
    let _ = agent.register(Uri::RelayRx);
    // Leader / router side requests (OT: `OPENTHREAD_FTD` handlers).
    #[cfg(feature = "ftd")]
    for u in [
        Uri::AddressSolicit,
        Uri::AddressRelease,
        Uri::AddressQuery,
        Uri::ServerData,
        Uri::ActiveSet,
        Uri::PendingSet,
        Uri::ActiveReplace,
        // The leader's commissioner session.
        Uri::LeaderPetition,
        Uri::LeaderKeepAlive,
        Uri::CommissionerSet,
        Uri::CommissionerGet,
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
    #[cfg(feature = "ftd")]
    sd_changed: Changed,
    #[cfg(feature = "ftd")]
    outcomes: Vec<mgmt::SetOutcome, 2>,
    duplicate_dua: bool,
    reset_counters: bool,
    diag_event: bool,
    #[cfg(feature = "commissioner")]
    scan_event: Option<crate::Event>,
    diag_answer: Option<(core::net::Ipv6Addr, crate::diag::Out)>,
    relay: Option<crate::cm_comm::Relay>,
}

impl<S, C: CryptoBackend, R> NodeHandler<'_, S, C, R> {
    /// Keep a relay / dataset-changed request for after the dispatch (it
    /// needs the commissioning roles and the agent).
    fn defer_relay(&mut self, uri: Uri, req: &Request<'_>) {
        let con = req.msg.ty() == opentrust_coap::message::Type::Con;
        if let Ok(v) = Vec::from_slice(req.msg.payload()) {
            self.out.relay = Some((uri, con, v));
        }
    }
}

struct NodeHandler<'a, S, C: CryptoBackend, R> {
    mle: &'a mut Mle<CHILDREN>,
    core: &'a mut Core<S, C, R>,
    #[cfg(feature = "ftd")]
    leader: &'a mut Leader<NETDATA_LEN>,
    #[cfg(feature = "ftd")]
    ls: &'a mut opentrust_meshcop::leader::LeaderState,
    resolver: &'a mut AddressResolver<8>,
    bbrg: &'a mut crate::bbr::BbrGlue,
    diag_in: &'a mut heapless::Deque<crate::diag::Answer, 2>,
    #[cfg(any(feature = "scan-servers", feature = "commissioner"))]
    scan: &'a mut crate::scan::ScanState,
    ext: Option<crate::TmfExtension>,
    now: Instant,
    out: Deferred,
}

impl<S: SettingsStore, C: InstanceCrypto, R: Rng + CryptoRng> Handler for NodeHandler<'_, S, C, R> {
    fn handle(&mut self, uri: Uri, req: &Request<'_>, rsp: &mut dyn Responder) {
        let now = self.now;
        let iid = self.core.ml_iid;
        match uri {
            #[cfg(feature = "ftd")]
            Uri::AddressSolicit => {
                if let Some(h) =
                    router_id::handle_address_solicit(self.mle, self.core, now, req, rsp)
                    && let Some(old) = h.stale_rloc16
                {
                    self.resolver.remove_entries_for_rloc16(old);
                }
            }
            #[cfg(feature = "ftd")]
            Uri::AddressRelease => {
                router_id::handle_address_release(self.mle, self.core, now, req, rsp);
            }
            #[cfg(feature = "ftd")]
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
                match address::handle_address_error(
                    &mut self.core.ip6.netif,
                    self.mle,
                    &iid,
                    &self.bbrg.bbr,
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
            #[cfg(feature = "ftd")]
            Uri::ServerData => {
                if let Some(c) =
                    server_data::handle_server_data(self.leader, self.mle, self.core, now, req, rsp)
                {
                    self.out.sd_changed.any |= c.any;
                    self.out.sd_changed.stable |= c.stable;
                }
            }
            Uri::DiagnosticGetRequest => {
                // OT drops the request unless it is a confirmable POST.
                if req.msg.ty() != opentrust_coap::message::Type::Con {
                    return;
                }
                let o = crate::diag::build_response(self.mle, self.core, req.msg.payload());
                let _ = rsp.respond(Code::CHANGED, &o.buf);
            }
            Uri::DiagnosticGetQuery => {
                if req.msg.ty() == opentrust_coap::message::Type::Con {
                    let _ = rsp.respond(Code::CHANGED, &[]);
                }
                let o = crate::diag::build_answer(self.mle, self.core, req.msg.payload());
                self.out.diag_answer = Some((req.ctx.peer.addr, o));
            }
            Uri::DiagnosticGetAnswer => {
                if req.msg.ty() == opentrust_coap::message::Type::Con {
                    let _ = rsp.respond(Code::CHANGED, &[]);
                }
                if let Ok(v) = Vec::from_slice(req.msg.payload()) {
                    if self.diag_in.is_full() {
                        let _ = self.diag_in.pop_front();
                    }
                    let _ = self.diag_in.push_back((req.ctx.peer.addr, v));
                    self.out.diag_event = true;
                }
            }
            Uri::DiagnosticReset => {
                if req.msg.ty() != opentrust_coap::message::Type::Con {
                    return;
                }
                // OT: only a leading Type List TLV is honoured; MAC counters
                // are the one counter set kept here.
                let p = req.msg.payload();
                if p.first() == Some(&crate::diag::tlv::TYPE_LIST) {
                    let n = usize::from(p.get(1).copied().unwrap_or(0));
                    if let Some(t) = p.get(2..2 + n)
                        && t.contains(&crate::diag::tlv::MAC_COUNTERS)
                    {
                        self.out.reset_counters = true;
                    }
                }
                let _ = rsp.respond(Code::CHANGED, &[]);
            }
            Uri::DuaRegistrationNotify => {
                if req.msg.ty() == opentrust_coap::message::Type::Con {
                    let _ = rsp.respond(Code::CHANGED, &[]);
                }
                let mut v: Vec<u8, 64> = Vec::new();
                if v.extend_from_slice(req.msg.payload()).is_ok() {
                    let _ = self.bbrg.ntf_inbox.push_back(v);
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
            #[cfg(feature = "ftd")]
            Uri::ActiveSet | Uri::PendingSet | Uri::ActiveReplace => {
                let (t, cmd) = match uri {
                    Uri::ActiveSet => (DatasetType::Active, MgmtCommand::Set),
                    Uri::ActiveReplace => (DatasetType::Active, MgmtCommand::Replace),
                    _ => (DatasetType::Pending, MgmtCommand::Set),
                };
                // OT `FindCommissioningSessionId`: the Session ID of the
                // Commissioning Data in the Network Data.
                let session_id = opentrust_meshcop::leader::session_id(self.leader);
                let (ds, mut env) = self.core.ds();
                env.session_id = session_id;
                let o = mgmt::handle_set(ds, &mut env, now, t, cmd, req, rsp);
                let _ = self.out.outcomes.push(o);
            }
            #[cfg(feature = "ftd")]
            Uri::LeaderPetition | Uri::LeaderKeepAlive | Uri::CommissionerSet => {
                use opentrust_meshcop::leader;
                let is_leader = self.mle.role() == opentrust_mle::Role::Leader;
                let changed = match uri {
                    Uri::LeaderPetition => {
                        let mlp = self.core.cfg.cur.mesh_local_prefix;
                        leader::handle_petition(
                            self.ls,
                            self.leader,
                            is_leader,
                            &mlp,
                            now,
                            req,
                            rsp,
                        )
                    }
                    Uri::LeaderKeepAlive => {
                        leader::handle_keep_alive(self.ls, self.leader, is_leader, now, req, rsp)
                    }
                    _ => leader::handle_commissioner_set(self.leader, is_leader, req, rsp),
                };
                self.out.sd_changed.any |= changed;
            }
            #[cfg(feature = "ftd")]
            Uri::CommissionerGet => {
                let is_leader = self.mle.role() == opentrust_mle::Role::Leader;
                opentrust_meshcop::leader::handle_commissioner_get(
                    self.leader,
                    is_leader,
                    req,
                    rsp,
                );
            }
            #[cfg(feature = "scan-servers")]
            Uri::EnergyScan => self.scan.srv.energy.handle_request(now, req, rsp),
            #[cfg(feature = "scan-servers")]
            Uri::PanIdQuery => self.scan.srv.panid.handle_request(now, req, rsp),
            #[cfg(feature = "scan-servers")]
            Uri::AnnounceBegin => self.scan.srv.announce.handle_request(now, req, rsp),
            #[cfg(feature = "commissioner")]
            Uri::EnergyReport => {
                if let Some(r) = opentrust_meshcop::scan::parse_energy_report(req, rsp)
                    && let Ok(list) = Vec::from_slice(r.energy_list)
                {
                    self.scan.energy_report = Some((r.channel_mask, list));
                    self.out.scan_event = Some(crate::Event::EnergyReport);
                }
            }
            #[cfg(feature = "commissioner")]
            Uri::PanIdConflict => {
                if let Some(c) = opentrust_meshcop::scan::parse_pan_id_conflict(req, rsp) {
                    self.out.scan_event = Some(crate::Event::PanIdConflict {
                        pan_id: c.pan_id,
                        channel_mask: c.channel_mask,
                    });
                }
            }
            Uri::DatasetChanged => {
                let _ = rsp.respond(Code::CHANGED, &[]);
                self.defer_relay(uri, req);
            }
            Uri::RelayTx | Uri::RelayRx => self.defer_relay(uri, req),
            other => {
                if let Some(f) = self.ext
                    && let Some((code, body)) = f(other, req.msg.payload())
                {
                    let _ = rsp.respond(code, &body);
                }
            }
        }
    }
}

impl<S: SettingsStore, C: InstanceCrypto, R: Rng + CryptoRng> Instance<S, C, R> {
    /// A datagram for the TMF port.
    pub(crate) fn handle_tmf(&mut self, now: Instant, meta: &UdpMeta, payload: &[u8]) {
        let env = MlTmfEnv(self.core.cfg.cur.mesh_local_prefix);
        let mut h = NodeHandler {
            mle: &mut self.mle,
            core: &mut self.core,
            #[cfg(feature = "ftd")]
            leader: &mut self.leader,
            #[cfg(feature = "ftd")]
            ls: &mut self.cm.leader,
            resolver: &mut self.resolver,
            bbrg: &mut self.bbrg,
            diag_in: &mut self.diag_in,
            #[cfg(any(feature = "scan-servers", feature = "commissioner"))]
            scan: &mut self.scan,
            ext: self.tmf_ext,
            now,
            out: Deferred::default(),
        };
        let r = self
            .agent
            .handle_dispatch(now, &mut self.sink, &env, meta, payload, &mut h);
        let mut out = core::mem::take(&mut h.out);
        let relay = out.relay.take();
        match r {
            TmfRx::Response { user, msg, peer } => {
                if self.commissioning_response(now, user, Ok((msg.code(), msg.payload()))) {
                    // The Commissioner or the Border Agent took it.
                } else {
                    #[cfg(feature = "ftd")]
                    let solicit = router_id::client_response(user, &msg);
                    #[cfg(not(feature = "ftd"))]
                    let solicit: Option<()> = None;
                    if let Some(_rep) = solicit {
                        #[cfg(feature = "ftd")]
                        self.mle.address_solicit_reply(&mut self.core, now, _rep);
                    } else if user == USER_SERVER_DATA {
                        self.notifier.response(now, true);
                    } else if user == crate::diag::USER_DIAG_GET {
                        if let Ok(v) = Vec::from_slice(msg.payload()) {
                            if self.diag_in.is_full() {
                                let _ = self.diag_in.pop_front();
                            }
                            let _ = self.diag_in.push_back((peer.addr, v));
                            self.core.push_event(crate::Event::DiagAnswer);
                        }
                    } else if self.bbrg.queue_outcome(
                        user,
                        crate::bbr::Outcome::Response(msg.code(), {
                            let mut v = Vec::new();
                            let _ = v.extend_from_slice(msg.payload());
                            v
                        }),
                    ) {
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
            }
            TmfRx::Failed { user, .. } => self.tmf_failed(now, user, false),
            _ => {}
        }
        #[cfg(feature = "ftd")]
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
        #[cfg(feature = "ftd")]
        for o in out.outcomes {
            if let Some(session) = o.notify_commissioner {
                let _ = session;
            }
        }
        if out.duplicate_dua {
            self.bbrg.duplicate_dua = true;
        }
        if out.diag_event {
            self.core.push_event(crate::Event::DiagAnswer);
        }
        #[cfg(feature = "commissioner")]
        if let Some(e) = out.scan_event {
            self.core.push_event(e);
        }
        if out.reset_counters {
            self.core.mac.reset_counters();
        }
        if let Some(r) = relay {
            self.handle_relay(now, r);
        }
        if let Some((dst, o)) = out.diag_answer {
            let own = self.mle.rloc16();
            let mlp = self.core.cfg.cur.mesh_local_prefix;
            let _ = self.agent.post(
                now,
                &mut self.prng,
                &mut self.sink,
                dst,
                (own != Rloc16::INVALID).then(|| mlp.rloc(own)),
                opentrust_core::message::Priority::Normal,
                Uri::DiagnosticGetAnswer,
                &o.buf,
                None,
            );
        }
    }

    fn tmf_failed(&mut self, now: Instant, user: u32, timeout: bool) {
        let e = if timeout {
            opentrust_core::Error::ResponseTimeout
        } else {
            opentrust_core::Error::Abort
        };
        if self.commissioning_response(now, user, Err(e)) {
            return;
        }
        #[cfg(feature = "ftd")]
        if let Some(r) = router_id::client_failure(user) {
            self.mle.address_solicit_reply(&mut self.core, now, r);
            return;
        }
        if user == USER_SERVER_DATA {
            self.notifier.response(now, false);
        } else if self.bbrg.queue_outcome(
            user,
            if timeout {
                crate::bbr::Outcome::Timeout
            } else {
                crate::bbr::Outcome::Failed
            },
        ) {
        } else if let Some(t) = mgmt::set_user_type(user) {
            self.core.datasets.mgmt_set_finished(now, t);
        }
    }

    /// TMF timers and the requests MLE and the dataset managers queued.
    #[inline(never)]
    pub(crate) fn service_tmf(&mut self, now: Instant) -> bool {
        let mut busy = false;
        #[cfg(feature = "ftd")]
        {
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
        }
        while let Some(ev) = self.agent.poll(now, &mut self.sink) {
            busy = true;
            let CoapEvent::Timeout { user } = ev;
            self.tmf_failed(now, user, true);
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
