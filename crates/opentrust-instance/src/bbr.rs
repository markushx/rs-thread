//! Backbone Router client glue: the Primary Backbone Router view of the
//! Network Data, the Domain Unicast Address manager and the Multicast
//! Listener Registration manager (OT `BackboneRouter::Leader`, `DuaManager`,
//! `MlrManager`).

use heapless::{Deque, Vec};
use opentrust_coap::message::Code;
use opentrust_core::settings::SettingsKey;
use opentrust_core::time::Instant;
#[cfg(feature = "ftd")]
use opentrust_mesh::bbr_server::{BbrContext, BbrServer, ServiceAction};
#[cfg(feature = "ftd")]
use opentrust_mesh::dua::{ChildNotification, send_child_notification};
use opentrust_mesh::dua::{
    DuaContext, DuaManager, DuaResult, USER_DUA_NOTIFY, USER_DUA_REGISTRATION, send_dua_request,
};
use opentrust_mesh::mlr::{MlrContext, MlrManager, MlrResult, USER_MLR, send_mlr_request};
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
    #[cfg(feature = "ftd")]
    pub server: BbrServer,
    pub dua: DuaManager<8>,
    pub mlr: MlrManager<8>,
    nd_hash: Option<u64>,
    last_role: Role,
    pub duplicate_dua: bool,
    pub ntf_inbox: Deque<Vec<u8, 64>, 2>,
    pub dua_results: Deque<(u32, Outcome), 2>,
    pub mlr_results: Deque<Outcome, 2>,
}

impl BbrGlue {
    pub(crate) fn new() -> Self {
        Self {
            bbr: BackboneRouterLeader::new(),
            #[cfg(feature = "ftd")]
            server: BbrServer::new(),
            dua: DuaManager::new(),
            mlr: MlrManager::new(),
            nd_hash: None,
            last_role: Role::Disabled,
            duplicate_dua: false,
            ntf_inbox: Deque::new(),
            dua_results: Deque::new(),
            mlr_results: Deque::new(),
        }
    }

    pub(crate) fn next_deadline(&self) -> Option<Instant> {
        #[cfg(feature = "ftd")]
        let server = self.server.next_poll();
        #[cfg(not(feature = "ftd"))]
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
    }

    /// Queue the outcome of a TMF request if `user` is one of ours.
    pub(crate) fn queue_outcome(&mut self, user: u32, o: Outcome) -> bool {
        if user == USER_DUA_REGISTRATION || user == USER_DUA_NOTIFY {
            if self.dua_results.is_full() {
                let _ = self.dua_results.pop_front();
            }
            let _ = self.dua_results.push_back((user, o));
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

    /// The DUA of this device, if it has one.
    pub fn domain_unicast_address(&self) -> Option<core::net::Ipv6Addr> {
        self.bbrg.dua.domain_unicast_address()
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
            expected_to_become_router: false,
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
        let b = &mut self.bbrg;
        let role = self.mle.role();
        let attached = role.is_attached();
        let role_changed = role != b.last_role;
        b.last_role = role;
        let ml_eid_iid = opentrust_core::types::ipv6::iid(&self.core.ml_eid_addr());
        let full = self.mle.is_full_thread_device();

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
        #[cfg(feature = "ftd")]
        let mut actions: Vec<ServiceAction, 3> = Vec::new();
        #[cfg(feature = "ftd")]
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
            expected_to_become_router: false,
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
        #[cfg(feature = "ftd")]
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
        moved
    }
}

/// Backbone Router role (OT `otBackboneRouter*`).
#[cfg(feature = "ftd")]
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
                }
            }
            ServiceAction::Remove => {
                let _ = self
                    .remove_service(THREAD_ENTERPRISE_NUMBER, &[BACKBONE_ROUTER_SERVICE_NUMBER]);
            }
        }
    }

    /// Enable or disable the Backbone Router role (`bbr enable`).
    pub fn bbr_set_enabled(&mut self, enable: bool) {
        if enable && !self.bbrg.server.is_enabled() {
            self.bbrg.server.seed(&mut self.prng);
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
        self.apply_bbr_action(a);
    }

    /// State of the Backbone Router role (`bbr state`).
    pub fn bbr_state(&self) -> opentrust_mesh::bbr_server::LocalState {
        self.bbrg.server.state()
    }

    /// The configured BBR dataset (`bbr config`).
    pub fn bbr_config(&self) -> opentrust_mesh::netdata::backbone::BbrConfig {
        self.bbrg.server.config()
    }

    /// Set parts of the BBR dataset (`bbr config seqno|delay|timeout`).
    pub fn bbr_set_config(
        &mut self,
        seqno: Option<u8>,
        delay: Option<u16>,
        timeout: Option<u32>,
    ) -> opentrust_core::Result<()> {
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
