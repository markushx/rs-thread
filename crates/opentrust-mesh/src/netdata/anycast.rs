//! Anycast locator (OT `AnycastLocator`): `/a/yl` asks the device behind an
//! anycast address for its mesh-local EID and RLOC16.

use core::net::Ipv6Addr;

use opentrust_coap::endpoint::Request;
use opentrust_coap::message::{Code, Message, Type};
use opentrust_coap::tmf::{Agent, Responder, UdpSink};
use opentrust_coap::uri::Uri;
use opentrust_core::bytes::Writer;
use opentrust_core::message::Priority;
use opentrust_core::time::Instant;
use opentrust_core::types::{Iid, Prefix64, Rloc16};
use opentrust_core::{Error, Result};
use rand_core::Rng;

use crate::tlv::{ThreadTlv, ThreadTlvs};

/// `user` value of the Anycast Locate request.
pub const USER_ANYCAST_LOCATE: u32 = 0x0a53_0004;

/// Answer of a located device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Located {
    /// Mesh-local EID of the device.
    pub ml_eid: Ipv6Addr,
    /// Its RLOC16.
    pub rloc16: Rloc16,
}

/// Responder side of `/a/yl` (OT `HandleTmf<kUriAnycastLocate>`): a
/// confirmable POST is answered with the Mesh-Local EID and RLOC16 TLVs.
/// Returns whether it was answered.
pub fn handle_anycast_locate(
    ml_eid_iid: Iid,
    rloc16: Rloc16,
    req: &Request<'_>,
    rsp: &mut dyn Responder,
) -> bool {
    if req.msg.ty() != Type::Con || req.msg.code() != Code::POST {
        return false;
    }
    let mut buf = [0u8; 24];
    let mut w = Writer::new(&mut buf);
    if ThreadTlv::MeshLocalEid(ml_eid_iid).write(&mut w).is_err()
        || ThreadTlv::Rloc16(rloc16).write(&mut w).is_err()
    {
        return false;
    }
    let n = w.len();
    rsp.respond(Code::CHANGED, &buf[..n]).is_ok()
}

/// Send the locate request to `anycast` (an ALOC) from our RLOC `src`
/// (OT `AnycastLocator::Locate`). The response arrives as a TMF response
/// with [`USER_ANYCAST_LOCATE`]; turn it into a result with
/// [`parse_response`].
pub fn send_anycast_locate<
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
    src: Ipv6Addr,
    anycast: Ipv6Addr,
) -> Result<()> {
    agent.post(
        now,
        rng,
        sink,
        anycast,
        Some(src),
        Priority::Net,
        Uri::AnycastLocate,
        &[],
        Some(USER_ANYCAST_LOCATE),
    )
}

/// Interpret a response to the locate request: [`Error::Parse`] if the
/// TLVs are missing.
pub fn parse_response(msg: &Message<'_>, mesh_local_prefix: Prefix64) -> Result<Located> {
    if msg.code() != Code::CHANGED {
        return Err(Error::Parse);
    }
    let t = ThreadTlvs::new(msg.payload());
    let iid = t.ml_eid().map_err(|_| Error::Parse)?;
    let rloc16 = t.rloc16().map_err(|_| Error::Parse)?;
    Ok(Located {
        ml_eid: mesh_local_prefix.with_iid(&iid),
        rloc16,
    })
}
