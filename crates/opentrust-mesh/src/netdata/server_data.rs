//! Server Data registration over TMF: `/a/sd` (OT `Leader::HandleTmf<kUriServerData>`
//! and `Notifier::SendServerDataNotification`).
//!
//! The leader side is [`handle_server_data`]; the device side builds and
//! sends the notification with [`send_server_data`] (see
//! [`Notifier`](super::notifier::Notifier) for when).

use super::lookup::ALOC16_LEADER;
#[cfg(feature = "ftd")]
use opentrust_coap::endpoint::Request;
#[cfg(feature = "ftd")]
use opentrust_coap::message::{Code, Type};
#[cfg(feature = "ftd")]
use opentrust_coap::tmf::Responder;
use opentrust_coap::tmf::{Agent, UdpSink};
use opentrust_coap::uri::Uri;
#[cfg(feature = "ftd")]
use opentrust_core::Error;
use opentrust_core::Result;
use opentrust_core::bytes::Writer;
use opentrust_core::message::Priority;
use opentrust_core::time::Instant;
use opentrust_core::types::Rloc16;
use opentrust_mle::Mle;
#[cfg(feature = "ftd")]
use opentrust_mle::Role;
use opentrust_mle::env::MleEnv;
use rand_core::Rng;

#[cfg(feature = "ftd")]
use super::leader::{Changed, Leader, MatchMode};
use crate::tlv::ThreadTlv;
#[cfg(feature = "ftd")]
use crate::tlv::ThreadTlvs;

/// `user` value of the Server Data request in [`Agent::post`].
pub const USER_SERVER_DATA: u32 = 0x0a53_0003;

/// Encode the payload of a Server Data notification: the Network Data TLV
/// (`None`: none, the leader only removes entries) and the RLOC16 TLV of
/// a previous RLOC16 whose entries are to be removed.
pub fn build_server_data(
    old_rloc16: Option<Rloc16>,
    data: Option<&[u8]>,
    out: &mut [u8],
) -> Result<usize> {
    let mut w = Writer::new(out);
    if let Some(d) = data {
        ThreadTlv::NetworkData(d).write(&mut w)?;
    }
    if let Some(r) = old_rloc16 {
        ThreadTlv::Rloc16(r).write(&mut w)?;
    }
    Ok(w.len())
}

/// Leader side of `/a/sd`. Nothing happens if this device is not the
/// leader, the request does not come from an RLOC or the Network Data TLV
/// is malformed; otherwise the optional RLOC16 TLV's entries are removed,
/// the Network Data is registered for the source RLOC16 and the request is
/// acknowledged (also if the registration was refused, as in OT).
///
/// Returns what changed, `None` if the request was ignored. If the result
/// is [`Changed::any`], call [`Leader::publish`].
#[cfg(feature = "ftd")]
pub fn handle_server_data<E: MleEnv, const C: usize, const N: usize>(
    leader: &mut Leader<N>,
    mle: &Mle<C>,
    env: &E,
    now: Instant,
    req: &Request<'_>,
    rsp: &mut dyn Responder,
) -> Option<Changed> {
    if mle.role() != Role::Leader || req.msg.code() != Code::POST {
        return None;
    }
    let peer = req.ctx.peer.addr;
    let mlp = env.mesh_local_prefix();
    if !opentrust_net::addr::is_routing_locator(&peer, &mlp) {
        return None;
    }
    let src = opentrust_core::types::ipv6::iid(&peer).locator()?;
    let t = ThreadTlvs::new(req.msg.payload());
    let mut total = Changed::default();
    let mut merge = |c: Changed| {
        total.any |= c.any;
        total.stable |= c.stable;
    };
    match t.rloc16() {
        Ok(old) => merge(leader.remove_rloc(old.0, MatchMode::Rloc16, now)),
        Err(Error::NotFound) => {}
        Err(_) => return None,
    }
    match t.network_data() {
        Ok(nd) => {
            let mask = mle.router_id_mask();
            if let Ok(c) = leader.register(src, nd, |id| mask.contains(id), now) {
                merge(c);
            }
        }
        Err(Error::NotFound) => {}
        Err(_) => return None,
    }
    if req.msg.ty() == Type::Con {
        // OT `SendEmptyAck`: an ACK with code 2.04 and no payload (the
        // requester completes its transaction with it).
        rsp.respond(Code::CHANGED, &[]).ok()?;
    }
    Some(total)
}

/// Send a Server Data notification (`payload` from [`build_server_data`])
/// to the leader ALOC from our RLOC (OT `SendServerDataNotification`:
/// confirmable, net priority).
pub fn send_server_data<
    R: Rng + ?Sized,
    S: UdpSink + ?Sized,
    E: MleEnv,
    const REQ: usize,
    const RES: usize,
    const CACHE: usize,
    const MSG: usize,
    const C: usize,
>(
    agent: &mut Agent<REQ, RES, CACHE, MSG>,
    now: Instant,
    rng: &mut R,
    sink: &mut S,
    mle: &Mle<C>,
    env: &E,
    payload: &[u8],
) -> Result<()> {
    let mlp = env.mesh_local_prefix();
    agent.post(
        now,
        rng,
        sink,
        mlp.aloc(ALOC16_LEADER)?,
        Some(mlp.rloc(mle.rloc16())),
        Priority::Net,
        Uri::ServerData,
        payload,
        Some(USER_SERVER_DATA),
    )
}
