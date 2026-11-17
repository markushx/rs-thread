//! Backbone Router client glue: the Primary Backbone Router view of the
//! Network Data, the Domain Unicast Address manager and the Multicast
//! Listener Registration manager (OT `BackboneRouter::Leader`, `DuaManager`,
//! `MlrManager`).

use heapless::{Deque, Vec};
use opentrust_coap::message::Code;
use opentrust_core::settings::SettingsKey;
use opentrust_core::time::Instant;
#[cfg(feature = "bbr-server")]
use opentrust_mesh::bbr_server::{BbrContext, BbrServer, ServiceAction};
#[cfg(feature = "ftd")]
use opentrust_mesh::dua::{ChildNotification, send_child_notification};
use opentrust_mesh::dua::{
    DuaContext, DuaManager, DuaResult, USER_DUA_NOTIFY, USER_DUA_REGISTRATION, send_dua_request,
};
use opentrust_mesh::mlr::{
    MlrContext, MlrManager, MlrRegistration, MlrResult, USER_MLR, USER_MLR_REGISTER,
    parse_mlr_response, send_mlr_registration, send_mlr_request,
};
use opentrust_mesh::netdata::backbone::{BackboneRouterLeader, BbrState, DomainPrefixEvent};
use opentrust_mle::Role;
use opentrust_net::slaac::IidParams;
use opentrust_platform::SettingsStore;
use rand_core::{CryptoRng, Rng};

use crate::InstanceCrypto;

use crate::Instance;

/// A TMF outcome for the managers.
#[derive(Debug, Clone)]
#[allow(clippy::large_enum_variant)] // no allocation
pub(crate) enum Outcome {
    Timeout,
    Failed,
    Response(Code, Vec<u8, 256>),
}

/// State of the Backbone Router client.
#[derive(Debug)]
pub(crate) struct BbrGlue {
    pub bbr: BackboneRouterLeader,
    /// The Backbone Router service of this device.
    #[cfg(feature = "bbr-server")]
    pub server: BbrServer,
    /// The Domain Prefix of the Backbone Router role.
    #[cfg(feature = "bbr-server")]
    pub domain_prefix: Option<opentrust_mesh::netdata::local::OnMeshPrefixConfig>,
    pub dua: DuaManager<8>,
    pub mlr: MlrManager<8>,
    nd_hash: Option<u64>,
    last_role: Role,
    pub duplicate_dua: bool,
    pub ntf_inbox: Deque<Vec<u8, 64>, 2>,
    pub dua_results: Deque<(u32, Outcome), 2>,
    pub mlr_results: Deque<Outcome, 2>,
    /// An application MLR.req ([`Instance::mlr_register`]) is outstanding.
    pub mlr_register_pending: bool,
    /// The result arrived and its event is still to be queued.
    pub mlr_register_reported: bool,
    /// The reported result, until taken.
    pub mlr_register_result: Option<opentrust_core::Result<MlrRegisterResult>>,
}

/// The answer to an MLR.req requested by the application.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MlrRegisterResult {
    /// The MLR status ([`opentrust_mesh::tlv::mlr_status`]).
    pub status: u8,
    /// The addresses that failed.
    pub failed: Vec<core::net::Ipv6Addr, 15>,
}

impl BbrGlue {
    pub(crate) fn new() -> Self {
        Self {
            bbr: BackboneRouterLeader::new(),
            #[cfg(feature = "bbr-server")]
            server: BbrServer::new(),
            #[cfg(feature = "bbr-server")]
            domain_prefix: None,
            dua: DuaManager::new(),
            mlr: MlrManager::new(),
            nd_hash: None,
            last_role: Role::Disabled,
            duplicate_dua: false,
            ntf_inbox: Deque::new(),
            dua_results: Deque::new(),
            mlr_results: Deque::new(),
            mlr_register_pending: false,
            mlr_register_reported: false,
            mlr_register_result: None,
        }
    }

    pub(crate) fn next_deadline(&self) -> Option<Instant> {
        #[cfg(feature = "bbr-server")]
        let server = self.server.next_poll();
        #[cfg(not(feature = "bbr-server"))]
        let server = None;
        [self.dua.next_deadline(), self.mlr.next_deadline(), server]
            .into_iter()
            .flatten()
            .min()
    }

    pub(crate) fn has_pending_work(&self) -> bool {
        self.duplicate_dua
            || !self.ntf_inbox.is_empty()
            || !self.dua_results.is_empty()
            || !self.mlr_results.is_empty()
            || self.mlr_register_reported
    }

    /// Queue the outcome of a TMF request if `user` is one of ours.
    pub(crate) fn queue_outcome(&mut self, user: u32, o: Outcome) -> bool {
        if user == USER_DUA_REGISTRATION || user == USER_DUA_NOTIFY {
            if self.dua_results.is_full() {
                let _ = self.dua_results.pop_front();
            }
            let _ = self.dua_results.push_back((user, o));
            true
        } else if user == USER_MLR_REGISTER {
            self.mlr_register_pending = false;
            self.mlr_register_reported = true;
            self.mlr_register_result = Some(match o {
                Outcome::Response(code, p) if code == Code::CHANGED => {
                    parse_mlr_response(&p).map(|r| MlrRegisterResult {
                        status: r.status,
                        failed: r.failed,
                    })
                }
                Outcome::Response(..) => Err(opentrust_core::Error::Parse),
                Outcome::Timeout => Err(opentrust_core::Error::ResponseTimeout),
                Outcome::Failed => Err(opentrust_core::Error::Abort),
            });
            true
        } else if user == USER_MLR {
            if self.mlr_results.is_full() {
                let _ = self.mlr_results.pop_front();
            }
            let _ = self.mlr_results.push_back(o);
            true
        } else {
            false
        }
    }
}

fn fnv(bytes: &[u8]) -> u64 {
    let mut h = 0xcbf2_9ce4_8422_2325u64;
    for x in bytes {
        h = (h ^ u64::from(*x)).wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

impl<S: SettingsStore, C: InstanceCrypto, R: Rng + CryptoRng> Instance<S, C, R> {
    /// Load the persisted DAD counter (OT settings key `DadInfo`).
    pub(crate) fn load_dad_counter(&mut self) {
        let mut b = [0u8; 1];
        if let Ok(1) = self.core.settings.get(SettingsKey::DadInfo, 0, &mut b) {
            self.bbrg.dua.restore(b[0]);
        }
    }

    /// Register multicast listeners with the Primary Backbone Router
    /// (OT `otIp6RegisterMulticastListeners`, CLI `mlr reg`), with the
    /// Commissioner Session ID TLV while a Commissioner is active and the
    /// Timeout TLV if `timeout` is given (0 deregisters). The answer is
    /// [`Event::MlrRegisterResult`](crate::Event::MlrRegisterResult); fetch
    /// it with [`mlr_take_register_result`](Self::mlr_take_register_result).
    ///
    /// [`opentrust_core::Error::InvalidArgs`] for no or more than 15
    /// addresses, [`opentrust_core::Error::InvalidState`] without a Primary
    /// Backbone Router, [`opentrust_core::Error::Busy`] while another
    /// registration is outstanding. A Commissioner is not required (OT
    /// reference device builds also send without one).
    pub fn mlr_register(
        &mut self,
        addresses: &[core::net::Ipv6Addr],
        timeout: Option<u32>,
        now: Instant,
    ) -> opentrust_core::Result<()> {
        use opentrust_core::Error;
        if addresses.is_empty() || addresses.len() > opentrust_mesh::mlr::MAX_MLR_ADDRESSES {
            return Err(Error::InvalidArgs);
        }
        if self.bbrg.mlr_register_pending {
            return Err(Error::Busy);
        }
        let Some(server16) = self.bbrg.bbr.config().map(|c| c.server16) else {
            return Err(Error::InvalidState);
        };
        let mlp = self.core.cfg.cur.mesh_local_prefix;
        let own = self.mle.rloc16();
        let p1p1 = !self.mle.is_full_thread_device()
            && self
                .mle
                .parent()
                .is_some_and(|p| p.router.neighbor.is_thread_version_1p1());
        let dst = if p1p1 {
            let id = opentrust_mesh::netdata::backbone::backbone_router_service_id(
                &self.core.netdata.view(),
            )
            .ok_or(Error::InvalidState)?;
            mlp.aloc(0xfc10 + u16::from(id))?
        } else {
            mlp.rloc(opentrust_core::types::Rloc16(server16))
        };
        #[cfg(feature = "commissioner")]
        let session_id = (self.cm.comm.state()
            == opentrust_meshcop::commissioner::CommissionerState::Active)
            .then(|| self.cm.comm.session_id());
        #[cfg(not(feature = "commissioner"))]
        let session_id = None;
        let reg = MlrRegistration {
            dst,
            src: mlp.rloc(own),
            addresses,
            session_id,
            timeout,
        };
        send_mlr_registration(&mut self.agent, now, &mut self.prng, &mut self.sink, &reg)?;
        self.bbrg.mlr_register_pending = true;
        Ok(())
    }

    /// The answer to [`mlr_register`](Self::mlr_register): the status and
    /// the failed addresses, or the error of the exchange.
    pub fn mlr_take_register_result(
        &mut self,
    ) -> Option<opentrust_core::Result<MlrRegisterResult>> {
        self.bbrg.mlr_register_result.take()
    }

    /// The DUA of this device, if it has one.
    pub fn domain_unicast_address(&self) -> Option<core::net::Ipv6Addr> {
        self.bbrg.dua.domain_unicast_address()
    }

    /// Send a fake Address Notification for `target` with the mesh-local
    /// interface identifier `ml_iid` to `dest` (reference device, OT
    /// `otThreadSendAddressNotification`).
    pub fn send_fake_address_notification(
        &mut self,
        dest: core::net::Ipv6Addr,
        target: core::net::Ipv6Addr,
        ml_iid: [u8; 8],
        now: Instant,
    ) -> opentrust_core::Result<()> {
        let own = self.mle.rloc16();
        if own == opentrust_core::types::Rloc16::INVALID {
            return Err(opentrust_core::Error::InvalidState);
        }
        let a = opentrust_mesh::address::AddressAction::SendNotify {
            dest,
            notify: opentrust_mesh::address::AddressNotify {
                target,
                ml_eid_iid: opentrust_core::types::Iid(ml_iid),
                rloc16: own,
                last_transaction_time: None,
            },
        };
        opentrust_mesh::address::send_action(
            &mut self.agent,
            now,
            &mut self.prng,
            &mut self.sink,
            own,
            &self.core,
            &a,
        )
    }

    /// The fixed DUA interface identifier, if one is set (`dua iid`).
    pub fn dua_fixed_iid(&self) -> Option<[u8; 8]> {
        self.bbrg.dua.fixed_iid().map(|i| i.0)
    }

    /// Set (or with `None` clear) the fixed DUA interface identifier (OT
    /// `otThreadSetFixedDuaInterfaceIdentifier`).
    pub fn set_dua_fixed_iid(
        &mut self,
        iid: Option<[u8; 8]>,
        now: Instant,
    ) -> opentrust_core::Result<()> {
        let role = self.mle.role();
        let attached = role.is_attached();
        let ml_eid_iid = opentrust_core::types::ipv6::iid(&self.core.ml_eid_addr());
        let full = self.mle.is_full_thread_device();
        let p1p1 = !full
            && role == Role::Child
            && self
                .mle
                .parent()
                .is_some_and(|p| p.router.neighbor.is_thread_version_1p1());
        let expected = self.expected_to_become_router();
        let view = self.core.netdata.view();
        let secret = self.core.iid_secret;
        let params = IidParams {
            backend: &self.core.crypto,
            secret: &secret,
            network_id: None,
        };
        let b = &mut self.bbrg;
        let ctx = DuaContext {
            now,
            attached,
            router_or_leader: role.is_router_or_leader(),
            full_thread_device: full,
            expected_to_become_router: expected,
            parent_1p1: p1p1,
            bbr: &b.bbr,
            netdata: view,
            ml_eid_iid,
        };
        let netif = &mut self.core.ip6.netif;
        match iid {
            Some(i) => b
                .dua
                .set_fixed_iid(opentrust_core::types::Iid(i), &ctx, netif, &params),
            None => {
                b.dua.clear_fixed_iid(&ctx, netif, &params);
                Ok(())
            }
        }
    }

    /// The Primary Backbone Router as announced in the Network Data.
    pub fn primary_backbone_router(&self) -> Option<opentrust_mesh::netdata::backbone::BbrConfig> {
        self.bbrg.bbr.config().copied()
    }

    /// One round of the DUA / MLR glue. Returns `true` if something
    /// happened.
    #[inline(never)]
    pub(crate) fn service_bbr(&mut self, now: Instant) -> bool {
        let mut moved = false;
        let expected = self.expected_to_become_router();
        let b = &mut self.bbrg;
        let role = self.mle.role();
        let attached = role.is_attached();
        let role_changed = role != b.last_role;
        b.last_role = role;
        let ml_eid_iid = opentrust_core::types::ipv6::iid(&self.core.ml_eid_addr());
        let full = self.mle.is_full_thread_device();
        let p1p1 = !full
            && role == Role::Child
            && self
                .mle
                .parent()
                .is_some_and(|p| p.router.neighbor.is_thread_version_1p1());

        // Network Data changes.
        let mut nd_event: Option<(BbrState, DomainPrefixEvent)> = None;
        let h = fnv(self.core.netdata.view().0);
        if attached && b.nd_hash != Some(h) {
            b.nd_hash = Some(h);
            let leader = self.mle.leader_rloc16();
            nd_event = Some(b.bbr.update(&self.core.netdata.view(), leader.0));
            moved = true;
        }
        if !attached {
            b.nd_hash = None;
        }
        // The Backbone Router service of this device.
        #[cfg(feature = "bbr-server")]
        let mut actions: Vec<ServiceAction, 3> = Vec::new();
        #[cfg(feature = "bbr-server")]
        if b.server.is_enabled() {
            let ctx = BbrContext {
                attached,
                is_leader: role == Role::Leader,
                rloc16: self.mle.rloc16().0,
                leader: &b.bbr,
            };
            if !attached {
                let _ = actions.push(b.server.reset());
            } else {
                if nd_event.is_some() {
                    let _ = actions.push(b.server.handle_primary_update(&ctx, now, &mut self.prng));
                }
                let _ = actions.push(b.server.poll(now, &ctx));
            }
        }
        let view = self.core.netdata.view();
        let secret = self.core.iid_secret;
        let params = IidParams {
            backend: &self.core.crypto,
            secret: &secret,
            network_id: None,
        };
        let ctx = DuaContext {
            now,
            attached,
            router_or_leader: role.is_router_or_leader(),
            full_thread_device: full,
            expected_to_become_router: expected,
            parent_1p1: p1p1,
            bbr: &b.bbr,
            netdata: view,
            ml_eid_iid,
        };
        let netif = &mut self.core.ip6.netif;
        if let Some((st, ev)) = nd_event {
            b.dua
                .handle_backbone_router_update(st, &ctx, &mut self.prng);
            b.dua.handle_domain_prefix_event(ev, &ctx, netif, &params);
            b.dua.handle_netdata_changed(&view, netif);
        }
        if role_changed {
            b.dua.handle_role_changed(&ctx, false, &mut self.prng);
        }
        let mlp = self.core.cfg.cur.mesh_local_prefix;
        let own = self.mle.rloc16();

        // Duplicate reports and notifications.
        if core::mem::take(&mut b.duplicate_dua) {
            b.dua.notify_duplicate(&ctx, netif, &params);
            moved = true;
        }
        #[cfg(feature = "ftd")]
        let mut child_ntfs: Vec<ChildNotification, 4> = Vec::new();
        while let Some(p) = b.ntf_inbox.pop_front() {
            moved = true;
            #[cfg(feature = "ftd")]
            if let Some(n) = b
                .dua
                .handle_notify(&ctx, &p, &mut self.prng, netif, &params)
            {
                let _ = child_ntfs.push(n);
            }
            #[cfg(not(feature = "ftd"))]
            let _ = b
                .dua
                .handle_notify(&ctx, &p, &mut self.prng, netif, &params);
        }
        while let Some((user, r)) = b.dua_results.pop_front() {
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
            #[cfg(feature = "ftd")]
            if let Some(n) = b
                .dua
                .handle_result(&ctx, res, &mut self.prng, netif, &params)
            {
                let _ = child_ntfs.push(n);
            }
            #[cfg(not(feature = "ftd"))]
            let _ = b
                .dua
                .handle_result(&ctx, res, &mut self.prng, netif, &params);
        }

        // Multicast Listener Registration.
        let mctx = MlrContext {
            now,
            attached,
            full_thread_device: full,
            is_child: role == Role::Child,
            bbr: &b.bbr,
        };
        if let Some((st, _)) = nd_event {
            b.mlr
                .handle_backbone_router_update(st, &mctx, &mut self.prng);
        }
        if role_changed {
            b.mlr.handle_role_changed(&mctx, &mut self.prng);
        }
        #[cfg(feature = "ftd")]
        macro_rules! children {
            () => {
                self.mle.children_mut()
            };
        }
        #[cfg(not(feature = "ftd"))]
        macro_rules! children {
            () => {
                &mut ()
            };
        }
        b.mlr.update(&mctx, &mut self.prng, netif, children!());
        while let Some(r) = b.mlr_results.pop_front() {
            moved = true;
            let res = match &r {
                Outcome::Timeout => MlrResult::Timeout,
                Outcome::Failed => MlrResult::Failed,
                Outcome::Response(code, p) => MlrResult::Response {
                    code: *code,
                    payload: p,
                },
            };
            let _ = b.mlr.handle_result(&mctx, res, &mut self.prng, children!());
        }
        let mlr_reg_done = core::mem::take(&mut b.mlr_register_reported);
        moved |= mlr_reg_done;
        if let Some(req) = b.mlr.poll(&mctx, &mut self.prng, children!()) {
            moved = true;
            if send_mlr_request(
                &mut self.agent,
                now,
                &mut self.prng,
                &mut self.sink,
                &mlp,
                own,
                &req,
            )
            .is_err()
            {
                b.mlr.request_not_sent(now, children!());
            }
        }

        // Children: their DUAs are registered by proxy.
        #[cfg(feature = "ftd")]
        b.dua.sync_children(
            &ctx,
            self.mle
                .children()
                .iter(opentrust_mle::neighbor::StateFilter::Valid),
            &mut self.prng,
        );
        if let Some(req) = b.dua.poll(&ctx, netif) {
            moved = true;
            if send_dua_request(
                &mut self.agent,
                now,
                &mut self.prng,
                &mut self.sink,
                &mlp,
                own,
                &req,
            )
            .is_err()
            {
                b.dua.request_not_sent(now);
            }
        }
        if let Some(c) = b.dua.take_dad_counter_update() {
            let _ = self.core.settings.set(SettingsKey::DadInfo, &[c]);
        }
        #[cfg(feature = "bbr-server")]
        for a in actions {
            moved |= a != ServiceAction::None;
            self.apply_bbr_action(a);
        }
        #[cfg(feature = "ftd")]
        for n in child_ntfs {
            if n.remove_address
                && let Some(c) = self
                    .mle
                    .children_mut()
                    .find_by_ext_mut(&n.ext, opentrust_mle::neighbor::StateFilter::Valid)
            {
                let _ = c.remove_address(&n.target);
            }
            let _ = send_child_notification(
                &mut self.agent,
                now,
                &mut self.prng,
                &mut self.sink,
                &mlp,
                own,
                &n,
            );
        }
        if mlr_reg_done {
            self.core.push_event(crate::Event::MlrRegisterResult);
        }
        moved
    }
}

/// Backbone Router role (OT `otBackboneRouter*`).
#[cfg(feature = "bbr-server")]
impl<S: SettingsStore, C: InstanceCrypto, R: Rng + CryptoRng> Instance<S, C, R> {
    /// Put the outcome of a server step into the local Network Data.
    pub(crate) fn apply_bbr_action(&mut self, a: ServiceAction) {
        use opentrust_mesh::netdata::backbone::BACKBONE_ROUTER_SERVICE_NUMBER;
        use opentrust_mesh::netdata::local::ServiceConfig;
        use opentrust_mesh::netdata::tlv::THREAD_ENTERPRISE_NUMBER;
        match a {
            ServiceAction::None => {}
            ServiceAction::Add(c) => {
                if let Ok(cfg) = ServiceConfig::new(
                    THREAD_ENTERPRISE_NUMBER,
                    &[BACKBONE_ROUTER_SERVICE_NUMBER],
                    &c.server_data(),
                    true,
                ) {
                    let _ = self.add_service(cfg);
                    // The role registers its service itself (OT
                    // `Local::AddService` notifies the Network Data
                    // Notifier), also with manual registration.
                    self.register_netdata();
                }
            }
            ServiceAction::Remove => {
                let _ = self
                    .remove_service(THREAD_ENTERPRISE_NUMBER, &[BACKBONE_ROUTER_SERVICE_NUMBER]);
                self.register_netdata();
            }
        }
    }

    /// Set the Domain Prefix of the Backbone Router role (OT
    /// `BackboneRouter::Local::SetDomainPrefix`); it joins the local Network
    /// Data while the role is enabled.
    pub(crate) fn bbr_set_domain_prefix(
        &mut self,
        cfg: opentrust_mesh::netdata::local::OnMeshPrefixConfig,
    ) -> opentrust_core::Result<()> {
        if let Some(old) = self.bbrg.domain_prefix
            && self.bbrg.server.is_enabled()
        {
            let _ = self.local.remove_on_mesh_prefix(&old.prefix);
        }
        self.bbrg.domain_prefix = Some(cfg);
        if self.bbrg.server.is_enabled() {
            self.local.add_on_mesh_prefix(cfg)?;
        }
        self.notifier
            .event(opentrust_mesh::netdata::notifier::NotifierEvent::LocalChanged);
        Ok(())
    }

    /// Remove the Domain Prefix of the Backbone Router role;
    /// [`opentrust_core::Error::NotFound`] if `prefix` is not it.
    pub(crate) fn bbr_remove_domain_prefix(
        &mut self,
        prefix: &opentrust_mesh::netdata::tlv::NetPrefix,
    ) -> opentrust_core::Result<()> {
        match self.bbrg.domain_prefix {
            Some(d) if d.prefix == *prefix => {
                if self.bbrg.server.is_enabled() {
                    let _ = self.local.remove_on_mesh_prefix(prefix);
                }
                self.bbrg.domain_prefix = None;
                self.notifier
                    .event(opentrust_mesh::netdata::notifier::NotifierEvent::LocalChanged);
                Ok(())
            }
            _ => Err(opentrust_core::Error::NotFound),
        }
    }

    /// Enable or disable the Backbone Router role (`bbr enable`).
    pub fn bbr_set_enabled(&mut self, enable: bool) {
        self.bbrg.server.seed(&mut self.prng);
        if enable && !self.bbrg.server.is_enabled() {
            let _ = self.agent.register(crate::TmfUri::DuaRegistrationRequest);
            let _ = self.agent.register(crate::TmfUri::Mlr);
        }
        let a = {
            let ctx = BbrContext {
                attached: self.mle.role().is_attached(),
                is_leader: self.mle.role() == Role::Leader,
                rloc16: self.mle.rloc16().0,
                leader: &self.bbrg.bbr,
            };
            self.bbrg.server.set_enabled(enable, &ctx)
        };
        if let Some(d) = self.bbrg.domain_prefix {
            if enable {
                let _ = self.local.add_on_mesh_prefix(d);
            } else {
                let _ = self.local.remove_on_mesh_prefix(&d.prefix);
            }
            self.notifier
                .event(opentrust_mesh::netdata::notifier::NotifierEvent::LocalChanged);
        }
        self.apply_bbr_action(a);
    }

    /// State of the Backbone Router role (`bbr state`).
    pub fn bbr_state(&self) -> opentrust_mesh::bbr_server::LocalState {
        self.bbrg.server.state()
    }

    /// The configured BBR dataset (`bbr config`).
    pub fn bbr_config(&mut self) -> opentrust_mesh::netdata::backbone::BbrConfig {
        self.bbrg.server.seed(&mut self.prng);
        self.bbrg.server.config()
    }

    /// Set parts of the BBR dataset (`bbr config seqno|delay|timeout`).
    pub fn bbr_set_config(
        &mut self,
        seqno: Option<u8>,
        delay: Option<u16>,
        timeout: Option<u32>,
    ) -> opentrust_core::Result<()> {
        self.bbrg.server.seed(&mut self.prng);
        let a = {
            let ctx = BbrContext {
                attached: self.mle.role().is_attached(),
                is_leader: self.mle.role() == Role::Leader,
                rloc16: self.mle.rloc16().0,
                leader: &self.bbrg.bbr,
            };
            self.bbrg.server.set_config(seqno, delay, timeout, &ctx)?
        };
        self.apply_bbr_action(a);
        Ok(())
    }

    /// Register the BBR service now (`bbr register`).
    pub fn bbr_register(&mut self) -> opentrust_core::Result<()> {
        let a = {
            let ctx = BbrContext {
                attached: self.mle.role().is_attached(),
                is_leader: self.mle.role() == Role::Leader,
                rloc16: self.mle.rloc16().0,
                leader: &self.bbrg.bbr,
            };
            self.bbrg.server.register(&ctx)?
        };
        self.apply_bbr_action(a);
        Ok(())
    }

    /// Registration jitter (`bbr jitter`).
    pub fn bbr_jitter(&self) -> u8 {
        self.bbrg.server.jitter()
    }

    /// Set the registration jitter.
    pub fn bbr_set_jitter(&mut self, j: u8) {
        self.bbrg.server.set_jitter(j);
    }

    /// The Backbone Router service (listener and DUA tables, test hooks).
    pub fn bbr_server(&mut self) -> &mut BbrServer {
        &mut self.bbrg.server
    }

    /// Multicast listeners and the seconds left (`bbr mgmt mlr listener`).
    pub fn bbr_listeners(
        &self,
        now: Instant,
    ) -> impl Iterator<Item = (core::net::Ipv6Addr, u32)> + '_ {
        self.bbrg.server.listeners.iter().map(move |(a, t)| {
            let left = t.as_secs().saturating_sub(now.as_secs());
            (*a, u32::try_from(left).unwrap_or(u32::MAX))
        })
    }
}
