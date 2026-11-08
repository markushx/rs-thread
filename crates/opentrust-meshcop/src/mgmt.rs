//! Dataset management over TMF: MGMT_ACTIVE_GET / MGMT_PENDING_GET
//! (`/c/ag`, `/c/pg`), the leader's MGMT_ACTIVE_SET / MGMT_PENDING_SET /
//! MGMT_ACTIVE_REPLACE (`/c/as`, `/c/ps`, `/c/ar`), the device-side
//! MGMT_SET toward the leader and MGMT_GET (OT `DatasetManager::HandleGet`,
//! `ProcessGetRequest`, `HandleSetOrReplace`, `ProcessSetOrReplaceRequest`,
//! `SendSetRequest`, `SendGetRequest`).
//!
//! # Leader
//!
//! Feed `/c/as`, `/c/ps` and `/c/ar` to [`handle_set`]. A request that does
//! not pass OT's checks is answered with State Reject (also on a device that
//! is not the leader). If the outcome has `notify_commissioner` set, send a
//! `/c/dc` with [`send_dataset_changed`].
//!
//! # Device
//!
//! After every change call [`flush_set_requests`]; it sends the local
//! dataset to the leader's ALOC when it is newer than the network's. Hand
//! the response (or failure) of a request with user
//! [`USER_MGMT_SET_ACTIVE`] / [`USER_MGMT_SET_PENDING`] to
//! [`set_response`] / [`Datasets::mgmt_set_finished`].

use core::net::Ipv6Addr;

use opentrust_coap::endpoint::Request;
use opentrust_coap::message::{Code, Message};
use opentrust_coap::tmf::{Agent, Responder, UdpSink};
use opentrust_coap::uri::Uri;
use opentrust_core::bytes::Writer;
use opentrust_core::message::Priority;
use opentrust_core::time::Instant;
use opentrust_core::types::{Prefix64, Rloc16};
use opentrust_core::{Error, Result};
use opentrust_mle::Role;
use rand_core::Rng;

use crate::dataset::DatasetType;
use crate::manager::Datasets;
use crate::tlv::{State, Tlvs, WriterExt, ty};
#[cfg(feature = "ftd")]
use crate::{
    dataset::Dataset,
    manager::DatasetEnv,
    timestamp::compare,
    tlv::{DEFAULT_DELAY_MS, MAX_DELAY_MS},
};
#[cfg(feature = "ftd")]
use opentrust_coap::message::Type;

/// `user` of a MGMT_ACTIVE_SET request to the leader.
pub const USER_MGMT_SET_ACTIVE: u32 = 0x0c53_0001;
/// `user` of a MGMT_PENDING_SET request to the leader.
pub const USER_MGMT_SET_PENDING: u32 = 0x0c53_0002;
/// `user` of a MGMT_ACTIVE_GET / MGMT_PENDING_GET request.
pub const USER_MGMT_GET: u32 = 0x0c53_0003;
/// `user` of a `/c/dc` Dataset Changed notification.
pub const USER_DATASET_CHANGED: u32 = 0x0c53_0004;

/// Outcome of a MGMT_SET / MGMT_REPLACE response (OT
/// `HandleMgmtSetResponse`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum MgmtResult {
    /// State Accept.
    Accepted,
    /// State Reject.
    Rejected,
    /// The request failed or the response was malformed.
    Failed(Error),
}

#[cfg(feature = "ftd")]
fn is_confirmable_post(req: &Request<'_>) -> bool {
    req.msg.ty() == Type::Con && req.msg.code() == Code::POST
}

/// `/c/ag` and `/c/pg` (OT `DatasetManager::HandleGet`): answer with the
/// requested TLVs of the local dataset (all if the Get TLV is absent or
/// empty). The Network Key is left out if the Security Policy does not
/// allow obtaining it. A device without a dataset answers with an empty
/// payload.
pub fn handle_get(
    ds: &Datasets,
    now: Instant,
    t: DatasetType,
    req: &Request<'_>,
    rsp: &mut dyn Responder,
) {
    let tlvs = Tlvs(req.msg.payload());
    let mut list = [0u8; 40];
    let mut n = 0;
    if let Ok(g) = tlvs.get_list() {
        for &b in g.iter().take(list.len() - 1) {
            if !list[..n].contains(&b) {
                list[n] = b;
                n += 1;
            }
        }
        // MGMT_PENDING_GET.rsp must include the Delay Timer TLV.
        if n > 0 && t == DatasetType::Pending && !list[..n].contains(&ty::DELAY_TIMER) {
            list[n] = ty::DELAY_TIMER;
            n += 1;
        }
    }
    let list = &list[..n];
    let obtain_key = ds.security_policy().obtain_network_key;
    let mut buf = [0u8; 300];
    let mut w = Writer::new(&mut buf);
    if let Some(d) = ds.read(t, now) {
        for tl in d.tlvs().iter().flatten() {
            let wanted = list.is_empty() || list.contains(&tl.ty());
            if wanted
                && (obtain_key || tl.ty() != ty::NETWORK_KEY)
                && opentrust_core::tlv::write(&mut w, tl.ty(), tl.value()).is_err()
            {
                return;
            }
        }
    }
    let _ = rsp.respond(Code::CHANGED, w.written());
}

#[cfg(feature = "ftd")]
/// Which leader command a request is (OT `MgmtCommand`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MgmtCommand {
    /// MGMT_ACTIVE_SET / MGMT_PENDING_SET.
    Set,
    /// MGMT_ACTIVE_REPLACE.
    Replace,
}

#[cfg(feature = "ftd")]
/// Result of [`handle_set`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SetOutcome {
    /// The request was accepted and applied.
    pub accepted: bool,
    /// The change did not come from the commissioner: send `/c/dc` to the
    /// commissioner ALOC of this session ID ([`send_dataset_changed`]).
    pub notify_commissioner: Option<u16>,
}

#[cfg(feature = "ftd")]
struct RequestInfo {
    dataset: Dataset,
    affects_connectivity: bool,
    affects_network_key: bool,
    from_commissioner: bool,
}

#[cfg(feature = "ftd")]
/// OT `ProcessSetOrReplaceRequest`; `None` rejects.
fn process_set(
    ds: &Datasets,
    env: &impl DatasetEnv,
    now: Instant,
    t: DatasetType,
    cmd: MgmtCommand,
    payload: &[u8],
) -> Option<RequestInfo> {
    let mut dataset = Dataset::from_tlvs(payload).ok()?;
    let mut info = RequestInfo {
        dataset: Dataset::new(),
        affects_connectivity: false,
        affects_network_key: false,
        from_commissioner: false,
    };

    // Timestamps must be ahead of the locally stored ones.
    let active_ts = dataset.timestamp(DatasetType::Active)?;
    match t {
        DatasetType::Pending => {
            let pending_ts = dataset.timestamp(DatasetType::Pending)?;
            if !compare(Some(&pending_ts), ds.local_timestamp(t).as_ref()).is_gt() {
                return None;
            }
        }
        DatasetType::Active => {
            if !compare(Some(&active_ts), ds.local_timestamp(t).as_ref()).is_gt() {
                return None;
            }
        }
    }

    // Does the new dataset affect connectivity or the network key?
    let cur = env.current();
    let tl = dataset.tlvs();
    if tl
        .channel()
        .is_ok_and(|c| c.channel != u16::from(cur.channel))
    {
        info.affects_connectivity = true;
    }
    if tl.pan_id().is_ok_and(|p| p != cur.pan_id) {
        info.affects_connectivity = true;
    }
    if tl
        .mesh_local_prefix()
        .is_ok_and(|p| p != cur.mesh_local_prefix)
    {
        info.affects_connectivity = true;
    }
    if tl.network_key().is_ok_and(|k| k != cur.network_key) {
        info.affects_connectivity = true;
        info.affects_network_key = true;
    }

    // Active timestamp rollback check: unless the network key changes, the
    // Active Timestamp must be ahead of the network's.
    if t == DatasetType::Pending
        && !info.affects_network_key
        && !compare(Some(&active_ts), ds.timestamp(DatasetType::Active).as_ref()).is_gt()
    {
        return None;
    }

    // Request from the commissioner?
    if let Ok(session) = tl.commissioner_session_id() {
        info.from_commissioner = true;
        dataset.remove(ty::COMMISSIONER_SESSION_ID);
        if env.commissioning_session_id() != Some(session) {
            return None;
        }
        // An Active update from the commissioner must not affect
        // connectivity.
        if t == DatasetType::Active && info.affects_connectivity {
            return None;
        }
        // Partial updates are merged into the Active Dataset.
        if cmd == MgmtCommand::Set
            && let Some(active) = ds.read(DatasetType::Active, now)
        {
            info.dataset = active;
        }
    }

    if cmd == MgmtCommand::Replace
        && !(info.from_commissioner
            && t == DatasetType::Active
            && dataset.contains_all_required_for(DatasetType::Active))
    {
        return None;
    }

    info.dataset.write_tlvs_from(&dataset).ok()?;

    // Check and adjust the Delay Timer.
    if let Ok(delay) = info.dataset.tlvs().delay_timer() {
        let mut delay = delay.min(MAX_DELAY_MS);
        if info.affects_network_key && delay < DEFAULT_DELAY_MS {
            delay = DEFAULT_DELAY_MS;
        } else {
            delay = delay.max(ds.delay_timer_minimal_ms());
        }
        info.dataset.set_delay_timer(delay).ok()?;
    }
    Some(info)
}

#[cfg(feature = "ftd")]
fn respond_state(rsp: &mut dyn Responder, state: State) {
    let mut b = [0u8; 4];
    let mut w = Writer::new(&mut b);
    if w.state(state).is_ok() {
        let _ = rsp.respond(Code::CHANGED, w.written());
    }
}

#[cfg(feature = "ftd")]
/// Leader side of `/c/as`, `/c/ps` and `/c/ar` (OT `HandleSetOrReplace`,
/// followed by the type specific tail of `HandleTmf`). Always answers with
/// a State TLV.
pub fn handle_set<E: DatasetEnv>(
    ds: &mut Datasets,
    env: &mut E,
    now: Instant,
    t: DatasetType,
    cmd: MgmtCommand,
    req: &Request<'_>,
    rsp: &mut dyn Responder,
) -> SetOutcome {
    let reject = SetOutcome {
        accepted: false,
        notify_commissioner: None,
    };
    if env.role() != Role::Leader || !is_confirmable_post(req) {
        respond_state(rsp, State::Reject);
        return reject;
    }
    let Some(mut info) = process_set(ds, env, now, t, cmd, req.msg.payload()) else {
        respond_state(rsp, State::Reject);
        return reject;
    };

    if t == DatasetType::Active && info.affects_connectivity {
        // An Active update that affects connectivity must be delayed with
        // the Pending Dataset.
        if ds
            .apply_active_as_pending(env, now, &mut info.dataset)
            .is_err()
        {
            respond_state(rsp, State::Reject);
            return reject;
        }
    } else {
        if ds.save(env, now, t, &info.dataset, false).is_err() {
            respond_state(rsp, State::Reject);
            return reject;
        }
        env.network_data_changed();
    }

    // Reply, then notify the commissioner if the update is from a Thread
    // device.
    respond_state(rsp, State::Accept);
    let notify = if info.from_commissioner {
        None
    } else {
        env.commissioning_session_id()
    };

    match t {
        DatasetType::Active => {
            if let Some(d) = ds.read(DatasetType::Active, now) {
                let _ = env.apply(&crate::manager::Configuration::from_dataset(&d));
            }
        }
        DatasetType::Pending => ds.start_pending_delay_timer(now),
    }
    SetOutcome {
        accepted: true,
        notify_commissioner: notify,
    }
}

/// The ALOC16 of the leader.
const LEADER_ALOC16: u16 = 0xfc00;

/// Send MGMT_SET with `payload` (dataset TLVs) to the leader's ALOC (OT
/// `SendSetRequest`): confirmable, net priority, from our RLOC. The
/// response is tagged with the matching `USER_MGMT_SET_*`.
#[allow(clippy::too_many_arguments)]
pub fn send_set<
    R: Rng + ?Sized,
    S: UdpSink + ?Sized,
    const REQ: usize,
    const RES: usize,
    const CACHE: usize,
    const MSG: usize,
>(
    agent: &mut Agent<REQ, RES, CACHE, MSG>,
    now: Instant,
    rng: &mut R,
    sink: &mut S,
    mlp: &Prefix64,
    own_rloc16: Rloc16,
    t: DatasetType,
    payload: &[u8],
) -> Result<()> {
    let (uri, user) = match t {
        DatasetType::Active => (Uri::ActiveSet, USER_MGMT_SET_ACTIVE),
        DatasetType::Pending => (Uri::PendingSet, USER_MGMT_SET_PENDING),
    };
    agent.post(
        now,
        rng,
        sink,
        mlp.aloc(LEADER_ALOC16)?,
        Some(mlp.rloc(own_rloc16)),
        Priority::Net,
        uri,
        payload,
        Some(user),
    )
}

/// Send the local datasets that are newer than the network's to the leader
/// (OT `SyncLocalWithLeader`). Returns the number of requests sent.
#[allow(clippy::too_many_arguments)]
pub fn flush_set_requests<
    R: Rng + ?Sized,
    S: UdpSink + ?Sized,
    const REQ: usize,
    const RES: usize,
    const CACHE: usize,
    const MSG: usize,
>(
    ds: &mut Datasets,
    agent: &mut Agent<REQ, RES, CACHE, MSG>,
    now: Instant,
    rng: &mut R,
    sink: &mut S,
    role: Role,
    mlp: &Prefix64,
    own_rloc16: Rloc16,
) -> usize {
    let mut sent = 0;
    for t in [DatasetType::Active, DatasetType::Pending] {
        if let Some(d) = ds.take_set_request(role, now, t) {
            if send_set(agent, now, rng, sink, mlp, own_rloc16, t, d.as_bytes()).is_ok() {
                sent += 1;
            } else {
                ds.mgmt_set_finished(now, t);
            }
        }
    }
    sent
}

/// Interpret the response to a MGMT_SET / MGMT_REPLACE (OT
/// `HandleMgmtSetResponse`).
pub fn set_response(msg: &Message<'_>) -> MgmtResult {
    match Tlvs(msg.payload()).state() {
        Ok(State::Accept) => MgmtResult::Accepted,
        Ok(State::Reject) => MgmtResult::Rejected,
        _ => MgmtResult::Failed(Error::Parse),
    }
}

/// The dataset a `USER_MGMT_SET_*` belongs to.
pub fn set_user_type(user: u32) -> Option<DatasetType> {
    match user {
        USER_MGMT_SET_ACTIVE => Some(DatasetType::Active),
        USER_MGMT_SET_PENDING => Some(DatasetType::Pending),
        _ => None,
    }
}

/// Send MGMT_ACTIVE_GET / MGMT_PENDING_GET for the TLV `types` (empty:
/// everything) to `dst` (OT `SendGetRequest`); the answer is tagged
/// [`USER_MGMT_GET`].
#[allow(clippy::too_many_arguments)]
pub fn send_get<
    R: Rng + ?Sized,
    S: UdpSink + ?Sized,
    const REQ: usize,
    const RES: usize,
    const CACHE: usize,
    const MSG: usize,
>(
    agent: &mut Agent<REQ, RES, CACHE, MSG>,
    now: Instant,
    rng: &mut R,
    sink: &mut S,
    dst: Ipv6Addr,
    src: Option<Ipv6Addr>,
    t: DatasetType,
    types: &[u8],
) -> Result<()> {
    let mut buf = [0u8; 64];
    let mut w = Writer::new(&mut buf);
    if !types.is_empty() {
        w.get_list(types)?;
    }
    let uri = match t {
        DatasetType::Active => Uri::ActiveGet,
        DatasetType::Pending => Uri::PendingGet,
    };
    agent.post(
        now,
        rng,
        sink,
        dst,
        src,
        Priority::Net,
        uri,
        w.written(),
        Some(USER_MGMT_GET),
    )
}

#[cfg(feature = "ftd")]
/// Send `/c/dc` Dataset Changed to the commissioner's ALOC (OT
/// `Leader::SendDatasetChanged`).
#[allow(clippy::too_many_arguments)]
pub fn send_dataset_changed<
    R: Rng + ?Sized,
    S: UdpSink + ?Sized,
    const REQ: usize,
    const RES: usize,
    const CACHE: usize,
    const MSG: usize,
>(
    agent: &mut Agent<REQ, RES, CACHE, MSG>,
    now: Instant,
    rng: &mut R,
    sink: &mut S,
    mlp: &Prefix64,
    own_rloc16: Rloc16,
    session_id: u16,
) -> Result<()> {
    agent.post(
        now,
        rng,
        sink,
        mlp.aloc(opentrust_mesh::netdata::aloc::commissioner_aloc16(
            session_id,
        ))?,
        Some(mlp.rloc(own_rloc16)),
        Priority::Net,
        Uri::DatasetChanged,
        &[],
        Some(USER_DATASET_CHANGED),
    )
}
