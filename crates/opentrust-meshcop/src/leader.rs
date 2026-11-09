//! The leader's commissioner session state (OT `MeshCoP::Leader`: petition
//! and keep-alive, `NetworkData::Leader::HandleTmf<kUriCommissionerSet>` /
//! `<kUriCommissionerGet>`).
//!
//! Only the TMF / leader side is here: a commissioner (native over DTLS or
//! on-mesh) petitions the leader with `/c/lp`, keeps the session alive with
//! `/c/la` and changes the Commissioning Data (Steering Data, Joiner UDP
//! Port) with `/c/cs`. The leader stores the session in the Commissioning
//! Data TLV of the Network Data:
//! Border Agent Locator, Commissioner Session ID and Steering Data.
//!
//! # Use
//!
//! Hold a [`LeaderState`] next to the leader's Network Data
//! ([`Leader`]). Route `/c/lp` and `/c/la` to [`handle_petition`] /
//! [`handle_keep_alive`], `/c/cs` to [`handle_commissioner_set`] and `/c/cg`
//! to [`handle_commissioner_get`]; call [`LeaderState::poll`] at
//! [`LeaderState::next_deadline`]. When one of them returns `true` the
//! Network Data changed: publish it ([`Leader::publish`]).

use core::net::Ipv6Addr;

use heapless::String;
use opentrust_coap::endpoint::Request;
use opentrust_coap::message::Code;
use opentrust_coap::tmf::Responder;
use opentrust_core::bytes::Writer;
use opentrust_core::time::{Duration, Instant};
use opentrust_core::types::{Prefix64, ipv6};
use opentrust_core::{Error, Result, tlv};
use opentrust_mesh::netdata::leader::{Changed, Leader};

use crate::tlv::{MAX_COMMISSIONER_ID_LEN, State, Tlvs, WriterExt, ty};

/// Seconds without keep-alive after which the leader resigns the
/// commissioner (`TIMEOUT_LEAD_PET`).
pub const TIMEOUT_LEADER_PETITION: Duration = Duration::from_secs(50);

/// The commissioner session of the leader.
#[derive(Debug, Clone)]
pub struct LeaderState {
    session_id: u16,
    commissioner_id: String<MAX_COMMISSIONER_ID_LEN>,
    deadline: Option<Instant>,
}

/// Find a sub-TLV of the Commissioning Data.
fn sub_tlv<const N: usize>(nd: &Leader<N>, ty: u8) -> Option<&[u8]> {
    Tlvs(nd.commissioning_data()?).value(ty).ok()
}

fn read_u16(v: &[u8]) -> Option<u16> {
    Some(u16::from_be_bytes([*v.first()?, *v.get(1)?]))
}

/// The Commissioner Session ID of the Commissioning Data (OT
/// `FindCommissioningSessionId`).
pub fn session_id<const N: usize>(nd: &Leader<N>) -> Option<u16> {
    read_u16(sub_tlv(nd, ty::COMMISSIONER_SESSION_ID)?)
}

/// The Border Agent Locator of the Commissioning Data.
pub fn border_agent_locator<const N: usize>(nd: &Leader<N>) -> Option<u16> {
    read_u16(sub_tlv(nd, ty::BORDER_AGENT_LOCATOR)?)
}

/// The Joiner UDP Port of the Commissioning Data.
pub fn joiner_udp_port<const N: usize>(nd: &Leader<N>) -> Option<u16> {
    read_u16(sub_tlv(nd, ty::JOINER_UDP_PORT)?)
}

/// The Steering Data of the Commissioning Data.
pub fn steering_data<const N: usize>(nd: &Leader<N>) -> Option<crate::steering::SteeringData> {
    let v = sub_tlv(nd, ty::STEERING_DATA)?;
    (!v.is_empty()).then(|| crate::steering::SteeringData::from_slice(v))
}

/// The RLOC16 of the sender if it sent from a routing locator.
fn peer_locator(req: &Request<'_>, mlp: &Prefix64) -> Option<u16> {
    let a: Ipv6Addr = req.ctx.peer.addr;
    if !opentrust_net::addr::is_routing_locator(&a, mlp) {
        return None;
    }
    ipv6::iid(&a).locator()
}

fn respond(rsp: &mut dyn Responder, f: impl FnOnce(&mut Writer<'_>) -> opentrust_core::Result<()>) {
    let mut buf = [0u8; 96];
    let mut w = Writer::new(&mut buf);
    if f(&mut w).is_ok() {
        let _ = rsp.respond(Code::CHANGED, w.written());
    }
}

impl LeaderState {
    /// No commissioner; `initial_session_id` is the first session ID minus
    /// one (OT starts at a random value and increments before use).
    pub const fn new(initial_session_id: u16) -> Self {
        Self {
            session_id: initial_session_id,
            commissioner_id: String::new(),
            deadline: None,
        }
    }

    /// The last session ID handed out.
    pub const fn session_id(&self) -> u16 {
        self.session_id
    }

    /// Adopt a session ID, e.g. from restored Network Data.
    pub fn set_session_id(&mut self, id: u16) {
        self.session_id = id;
    }

    /// A commissioner is petitioned and alive (the OT timer is running).
    pub const fn is_active(&self) -> bool {
        self.deadline.is_some()
    }

    /// The Commissioner ID of the active commissioner.
    pub fn commissioner_id(&self) -> Option<&str> {
        self.is_active().then_some(self.commissioner_id.as_str())
    }

    /// Forget the commissioner without touching Network Data (the device
    /// lost the leader role).
    pub fn reset(&mut self) {
        self.deadline = None;
        self.commissioner_id.clear();
    }

    /// OT `ResignCommissioner`: stop the timer and replace the
    /// Commissioning Data by a bare, incremented session ID. Returns
    /// whether the Network Data changed.
    pub fn resign<const N: usize>(&mut self, nd: &mut Leader<N>) -> bool {
        self.deadline = None;
        self.commissioner_id.clear();
        self.session_id = self.session_id.wrapping_add(1);
        let mut b = [0u8; 4];
        let mut w = Writer::new(&mut b);
        let _ = w.commissioner_session_id(self.session_id);
        nd.set_commissioning_data(w.written()).is_ok()
    }

    /// Run the petition timeout. Returns whether the Network Data changed.
    pub fn poll<const N: usize>(
        &mut self,
        now: Instant,
        is_leader: bool,
        nd: &mut Leader<N>,
    ) -> bool {
        match self.deadline {
            Some(d) if d <= now => {
                if is_leader {
                    self.resign(nd)
                } else {
                    self.reset();
                    false
                }
            }
            _ => false,
        }
    }

    /// When [`poll`](Self::poll) next has work.
    pub fn next_deadline(&self) -> Option<Instant> {
        self.deadline
    }

    /// A leader that restored its role after a reset received the Network
    /// Data of the partition: [`Leader::restore`] it, then [`adopt`](Self::adopt)
    /// the Commissioning Data (OT `HandleNetworkDataRestoredAfterReset`).
    /// The commissioner session of the previous run is gone: its session ID
    /// is kept (and incremented by the resignation), the Commissioning Data
    /// is replaced by the bare session ID. Returns what changed in the
    /// Network Data; the caller publishes the versions
    /// ([`Leader::publish`]) if `any` is set.
    pub fn restore_leader<const N: usize>(
        &mut self,
        nd: &mut Leader<N>,
        data: &[u8],
        version: u8,
        stable_version: u8,
        is_router_id_allocated: impl Fn(u8) -> bool,
        now: Instant,
    ) -> Result<Changed> {
        let mut ch = nd.restore(data, version, stable_version, is_router_id_allocated, now)?;
        if self.adopt(nd) {
            ch.any = true;
        }
        Ok(ch)
    }

    /// After the Network Data was restored or taken over: adopt the session
    /// ID in it and resign an active commissioner (OT
    /// `Leader::RestoreNetworkData`).
    pub fn adopt<const N: usize>(&mut self, nd: &mut Leader<N>) -> bool {
        if let Some(id) = session_id(nd) {
            self.session_id = id;
        }
        border_agent_locator(nd).is_some() && self.resign(nd)
    }
}

/// `/c/lp` Leader Petition (OT `HandleTmf<kUriLeaderPetition>`). Returns
/// whether the Network Data changed. A non-leader answers State Reject.
pub fn handle_petition<const N: usize>(
    ls: &mut LeaderState,
    nd: &mut Leader<N>,
    is_leader: bool,
    mlp: &Prefix64,
    now: Instant,
    req: &Request<'_>,
    rsp: &mut dyn Responder,
) -> bool {
    let mut changed = false;
    let mut state = State::Reject;
    'exit: {
        if !is_leader {
            break 'exit;
        }
        let Some(locator) = peer_locator(req, mlp) else {
            break 'exit;
        };
        let Ok(id) = Tlvs(req.msg.payload()).commissioner_id() else {
            break 'exit;
        };
        if ls.is_active() {
            if ls.commissioner_id.as_str() != id {
                break 'exit;
            }
            changed |= ls.resign(nd);
        }
        ls.session_id = ls.session_id.wrapping_add(1);
        // Border Agent Locator, Session ID, empty Steering Data.
        let mut b = [0u8; 16];
        let mut w = Writer::new(&mut b);
        if w.border_agent_locator(locator).is_err()
            || w.commissioner_session_id(ls.session_id).is_err()
            || w.steering_data(&crate::steering::SteeringData::new(1))
                .is_err()
        {
            break 'exit;
        }
        if nd.set_commissioning_data(w.written()).is_err() {
            break 'exit;
        }
        changed = true;
        ls.commissioner_id.clear();
        let _ = ls.commissioner_id.push_str(id);
        state = State::Accept;
        ls.deadline = Some(now.saturating_add(TIMEOUT_LEADER_PETITION));
    }
    respond(rsp, |w| {
        w.state(state)?;
        if ls.is_active() {
            w.commissioner_id(ls.commissioner_id.as_str())?;
        }
        if state == State::Accept {
            w.commissioner_session_id(ls.session_id)?;
        }
        Ok(())
    });
    changed
}

/// `/c/la` Leader Keep Alive (OT `HandleTmf<kUriLeaderKeepAlive>`). Returns
/// whether the Network Data changed. Nothing is answered by a non-leader
/// or for a malformed request.
pub fn handle_keep_alive<const N: usize>(
    ls: &mut LeaderState,
    nd: &mut Leader<N>,
    is_leader: bool,
    now: Instant,
    req: &Request<'_>,
    rsp: &mut dyn Responder,
) -> bool {
    if !is_leader {
        return false;
    }
    let t = Tlvs(req.msg.payload());
    let (Ok(state), Ok(session)) = (t.state(), t.commissioner_session_id()) else {
        return false;
    };
    let mut changed = false;
    let response = match border_agent_locator(nd) {
        None => State::Reject,
        Some(_) if session != ls.session_id => State::Reject,
        Some(_) if state != State::Accept => {
            changed |= ls.resign(nd);
            State::Reject
        }
        Some(old) => {
            let rloc = ipv6::iid(&req.ctx.peer.addr).locator().unwrap_or(0);
            if old != rloc {
                changed |= replace_locator(nd, rloc);
            }
            ls.deadline = Some(now.saturating_add(TIMEOUT_LEADER_PETITION));
            State::Accept
        }
    };
    respond(rsp, |w| w.state(response));
    changed
}

/// Replace the Border Agent Locator in the Commissioning Data and increment
/// the version.
fn replace_locator<const N: usize>(nd: &mut Leader<N>, rloc: u16) -> bool {
    let Some(cur) = nd.commissioning_data() else {
        return false;
    };
    let mut buf = [0u8; 255];
    let mut w = Writer::new(&mut buf);
    for t in tlv::TlvIter::new(cur).flatten() {
        let r = if t.ty() == ty::BORDER_AGENT_LOCATOR {
            w.border_agent_locator(rloc)
        } else {
            tlv::write(&mut w, t.ty(), t.value())
        };
        if r.is_err() {
            return false;
        }
    }
    nd.set_commissioning_data(w.written()).is_ok()
}

/// `/c/cs` Commissioner Set (OT `HandleTmf<kUriCommissionerSet>`): replace
/// the Commissioning Data by the request's TLVs plus the Border Agent
/// Locator. Returns whether the Network Data changed. Answered with a
/// State TLV by the leader only.
pub fn handle_commissioner_set<const N: usize>(
    nd: &mut Leader<N>,
    is_leader: bool,
    req: &Request<'_>,
    rsp: &mut dyn Responder,
) -> bool {
    if !is_leader {
        return false;
    }
    let mut state = State::Reject;
    let mut changed = false;
    'exit: {
        let payload = req.msg.payload();
        // No Border Agent Locator in the request; this also validates the
        // framing of all TLVs.
        if !matches!(
            tlv::find(payload, ty::BORDER_AGENT_LOCATOR),
            Err(Error::NotFound)
        ) {
            break 'exit;
        }
        let Ok(session) = Tlvs(payload).commissioner_session_id() else {
            break 'exit;
        };
        if session_id(nd).is_some_and(|local| local != session) {
            break 'exit;
        }
        let mut buf = [0u8; 255];
        let mut w = Writer::new(&mut buf);
        if w.write_slice(payload).is_err() {
            break 'exit;
        }
        if let Some(ba) = border_agent_locator(nd)
            && w.border_agent_locator(ba).is_err()
        {
            break 'exit;
        }
        if nd.set_commissioning_data(w.written()).is_err() {
            break 'exit;
        }
        changed = true;
        state = State::Accept;
    }
    respond(rsp, |w| w.state(state));
    changed
}

/// `/c/cg` Commissioner Get (OT `HandleTmf<kUriCommissionerGet>`): the
/// sub-TLVs of the Commissioning Data named in the Get TLV, or all of
/// them. Only the leader answers.
pub fn handle_commissioner_get<const N: usize>(
    nd: &Leader<N>,
    is_leader: bool,
    req: &Request<'_>,
    rsp: &mut dyn Responder,
) {
    if !is_leader {
        return;
    }
    let mut buf = [0u8; 255];
    if let Some(n) = commissioner_get_payload(nd.commissioning_data(), req.msg.payload(), &mut buf)
    {
        let _ = rsp.respond(Code::CHANGED, &buf[..n]);
    }
}

/// The MGMT_COMMISSIONER_GET answer for the Commissioning Data `cd` and
/// the request TLVs (OT `ProcessCommissionerGetRequest`): the sub-TLVs
/// named in the Get TLV, or all of them. Used by the leader and the
/// Border Agent. `None` if `out` is too small.
pub fn commissioner_get_payload(
    cd: Option<&[u8]>,
    request: &[u8],
    out: &mut [u8],
) -> Option<usize> {
    let mut w = Writer::new(out);
    let ok = match Tlvs(request).get_list() {
        Ok(list) => list
            .iter()
            .all(|&ty| match cd.and_then(|c| Tlvs(c).value(ty).ok()) {
                Some(v) => tlv::write(&mut w, ty, v).is_ok(),
                None => true,
            }),
        Err(_) => cd.is_none_or(|c| w.write_slice(c).is_ok()),
    };
    ok.then(|| w.written().len())
}
