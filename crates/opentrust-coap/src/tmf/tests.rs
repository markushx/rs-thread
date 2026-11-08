use super::*;
use crate::message::Message;
use core::net::SocketAddrV6;
use std::vec::Vec;

/// Mesh-local prefix fd00:1::/64 for the tests.
struct Env;
impl TmfEnv for Env {
    fn is_mesh_local(&self, a: &Ipv6Addr) -> bool {
        a.octets()[..8] == [0xfd, 0, 0, 1, 0, 0, 0, 0]
    }
}

#[derive(Default)]
struct Sink {
    sent: Vec<(SendInfo, u16, u16, Vec<u8>)>,
}
impl UdpSink for Sink {
    fn send(&mut self, info: &SendInfo, sp: u16, dp: u16, payload: &[u8]) -> Result<()> {
        self.sent.push((*info, sp, dp, payload.to_vec()));
        Ok(())
    }
}

struct TestRng(u64);
impl rand_core::TryRng for TestRng {
    type Error = core::convert::Infallible;
    fn try_next_u32(&mut self) -> core::result::Result<u32, Self::Error> {
        Ok((self.try_next_u64()? >> 32) as u32)
    }
    fn try_next_u64(&mut self) -> core::result::Result<u64, Self::Error> {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        Ok(self.0.wrapping_mul(0x2545_F491_4F6C_DD1D))
    }
    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> core::result::Result<(), Self::Error> {
        for chunk in dst.chunks_mut(8) {
            let v = self.try_next_u64()?.to_le_bytes();
            chunk.copy_from_slice(&v[..chunk.len()]);
        }
        Ok(())
    }
}

type A = Agent<4, 8, 4, 256>;

const ML_A: Ipv6Addr = Ipv6Addr::new(0xfd00, 1, 0, 0, 0, 0, 0xff, 1);
const ML_B: Ipv6Addr = Ipv6Addr::new(0xfd00, 1, 0, 0, 0, 0, 0xff, 2);
const LL_A: Ipv6Addr = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
const LL_B: Ipv6Addr = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 2);
const REALM_ALL_ROUTERS: Ipv6Addr = Ipv6Addr::new(0xff03, 0, 0, 0, 0, 0, 0, 2);
const LL_ALL_NODES: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1);
const GLOBAL: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
const SITE_MC: Ipv6Addr = Ipv6Addr::new(0xff05, 0, 0, 0, 0, 0, 0, 2);

fn meta(src: Ipv6Addr, dst: Ipv6Addr, port: u16, sec: bool) -> UdpMeta {
    UdpMeta {
        peer: SocketAddrV6::new(src, 61631, 0, 0),
        local: SocketAddrV6::new(dst, port, 0, 0),
        hop_limit: 64,
        ecn: 0,
        link_security: sec,
    }
}

fn t(ms: u64) -> Instant {
    Instant::from_millis(ms)
}

fn request(ty: Type, mid: u16, token: &[u8], path: &str, payload: &[u8]) -> Vec<u8> {
    let mut b = [0u8; 128];
    let mut m = MessageBuilder::new(&mut b, ty, Code::POST, mid, token).unwrap();
    m.uri_path(path).unwrap();
    let n = m.finish_with_payload(payload).unwrap();
    b[..n].to_vec()
}

#[test]
fn dscp_mapping_matches_ot() {
    assert_eq!(priority_to_dscp(Priority::Net), 0x07);
    assert_eq!(priority_to_dscp(Priority::High), 0x0f);
    assert_eq!(priority_to_dscp(Priority::Normal), 0x0f);
    assert_eq!(priority_to_dscp(Priority::Low), 0x17);
    assert_eq!(dscp_to_priority(0x07), Priority::Net);
    assert_eq!(dscp_to_priority(0x0f), Priority::Normal);
    assert_eq!(dscp_to_priority(0x17), Priority::Low);
    // Unknown (legacy) DSCP -> net priority.
    assert_eq!(dscp_to_priority(0), Priority::Net);
    assert_eq!(dscp_to_priority(0x2a), Priority::Net);
}

#[test]
fn is_tmf_message_rules() {
    let p = UDP_PORT;
    // Link-local source.
    assert!(is_tmf_message(&Env, &LL_A, &LL_B, p));
    assert!(is_tmf_message(&Env, &LL_A, &LL_ALL_NODES, p));
    assert!(!is_tmf_message(&Env, &LL_A, &ML_B, p));
    assert!(!is_tmf_message(&Env, &LL_A, &REALM_ALL_ROUTERS, p));
    // Mesh-local source.
    assert!(is_tmf_message(&Env, &ML_A, &ML_B, p));
    assert!(is_tmf_message(&Env, &ML_A, &LL_ALL_NODES, p));
    assert!(is_tmf_message(&Env, &ML_A, &REALM_ALL_ROUTERS, p));
    assert!(!is_tmf_message(&Env, &ML_A, &SITE_MC, p));
    assert!(!is_tmf_message(&Env, &ML_A, &GLOBAL, p));
    assert!(!is_tmf_message(&Env, &ML_A, &LL_B, p));
    // Outside sources, wrong port.
    assert!(!is_tmf_message(&Env, &GLOBAL, &ML_B, p));
    assert!(!is_tmf_message(&Env, &ML_A, &ML_B, 5683));
}

/// Test handler: a fake `/a/aq` answering with a 2.04 carrying the request
/// payload reversed, and a counter for `c/ag`.
#[derive(Default)]
struct H {
    seen: Vec<(Uri, Vec<u8>)>,
}
impl Handler for H {
    fn handle(&mut self, uri: Uri, req: &Request<'_>, rsp: &mut dyn Responder) {
        self.seen.push((uri, req.msg.payload().to_vec()));
        if uri == Uri::AddressQuery {
            let mut p = req.msg.payload().to_vec();
            p.reverse();
            rsp.respond(Code::CHANGED, &p).unwrap();
        }
    }
}

fn agent() -> A {
    let mut a = A::new(1000);
    a.register(Uri::AddressQuery).unwrap();
    a.register(Uri::ActiveGet).unwrap();
    a
}

#[test]
fn fake_address_query_through_the_agent() {
    let mut a = agent();
    let mut sink = Sink::default();
    let mut h = H::default();
    // TMF target EID TLV (type 0, 16 bytes) as payload.
    let mut tlv = [0u8; 18];
    tlv[1] = 16;
    tlv[2..].copy_from_slice(&ML_B.octets());
    let req = request(Type::Con, 0x42, &[0xaa, 0xbb], "a/aq", &tlv);
    let m = meta(ML_A, ML_B, UDP_PORT, true);
    let r = a.handle_dispatch(t(0), &mut sink, &Env, &m, &req, &mut h);
    assert!(matches!(r, TmfRx::Handled));
    assert_eq!(h.seen.len(), 1);
    assert_eq!(h.seen[0].0, Uri::AddressQuery);
    assert_eq!(h.seen[0].1, tlv);

    // One response datagram, from port 61631 to the requester.
    assert_eq!(sink.sent.len(), 1);
    let (info, sp, dp, data) = &sink.sent[0];
    assert_eq!((*sp, *dp), (UDP_PORT, 61631));
    assert_eq!(info.dst, ML_A);
    assert_eq!(info.src, Some(ML_B), "answered from the address queried");
    assert_eq!(info.dscp, DSCP_NET);
    assert!(info.link_security);
    let rsp = Message::parse(data).unwrap();
    assert_eq!(
        (rsp.ty(), rsp.code(), rsp.message_id()),
        (Type::Ack, Code::CHANGED, 0x42)
    );
    assert_eq!(rsp.token(), &[0xaa, 0xbb]);
    let mut rev = tlv.to_vec();
    rev.reverse();
    assert_eq!(rsp.payload(), &rev[..]);

    // Duplicate request: cached answer, handler not called again.
    let r = a.handle_dispatch(t(100), &mut sink, &Env, &m, &req, &mut h);
    assert!(matches!(r, TmfRx::Handled));
    assert_eq!(h.seen.len(), 1);
    assert_eq!(sink.sent.len(), 2);
    assert_eq!(sink.sent[1].3, sink.sent[0].3);
}

#[test]
fn routing_and_unknown_uri() {
    let mut a = agent();
    let mut sink = Sink::default();
    let mut h = H::default();
    let m = meta(ML_A, ML_B, UDP_PORT, true);
    // Registered but handler does not answer: nothing sent.
    let req = request(Type::Non, 1, &[1], "c/ag", &[9]);
    a.handle_dispatch(t(0), &mut sink, &Env, &m, &req, &mut h);
    assert_eq!(h.seen, [(Uri::ActiveGet, std::vec![9u8])]);
    assert!(sink.sent.is_empty());
    // Unregistered URI (a/an): 4.04 for CON unicast, handler untouched.
    let req = request(Type::Con, 2, &[1], "a/an", &[]);
    a.handle_dispatch(t(0), &mut sink, &Env, &m, &req, &mut h);
    assert_eq!(h.seen.len(), 1);
    let rsp = Message::parse(&sink.sent[0].3).unwrap();
    assert_eq!(rsp.code(), Code::NOT_FOUND);
    // Non-TMF path text is also a 404.
    a.unregister(Uri::ActiveGet).unwrap();
    let req = request(Type::Con, 3, &[1], "c/ag", &[]);
    a.handle_dispatch(t(0), &mut sink, &Env, &m, &req, &mut h);
    assert_eq!(
        Message::parse(&sink.sent[1].3).unwrap().code(),
        Code::NOT_FOUND
    );
}

#[test]
fn filter_drops_non_tmf_and_insecure() {
    let mut a = agent();
    let mut sink = Sink::default();
    let mut h = H::default();
    let req = request(Type::Con, 7, &[1], "a/aq", &[1]);
    for m in [
        meta(GLOBAL, ML_B, UDP_PORT, true), // outside source
        meta(ML_A, GLOBAL, UDP_PORT, true), // outside destination
        meta(ML_A, ML_B, 5683, true),       // wrong port
        meta(ML_A, ML_B, UDP_PORT, false),  // no link security
        meta(LL_A, REALM_ALL_ROUTERS, UDP_PORT, true),
    ] {
        let r = a.handle_dispatch(t(0), &mut sink, &Env, &m, &req, &mut h);
        assert!(matches!(r, TmfRx::Dropped));
    }
    assert!(h.seen.is_empty() && sink.sent.is_empty());
    // Link-local to link-local is accepted; insecure accepted when allowed.
    let r = a.handle_dispatch(
        t(0),
        &mut sink,
        &Env,
        &meta(LL_A, LL_B, UDP_PORT, true),
        &req,
        &mut h,
    );
    assert!(matches!(r, TmfRx::Handled));
    a.require_link_security = false;
    let req2 = request(Type::Con, 8, &[1], "a/aq", &[1]);
    a.handle_dispatch(
        t(0),
        &mut sink,
        &Env,
        &meta(ML_A, ML_B, UDP_PORT, false),
        &req2,
        &mut h,
    );
    assert_eq!(h.seen.len(), 2);
}

#[test]
fn outgoing_request_dscp_retransmission_and_response() {
    let mut a = agent();
    let mut sink = Sink::default();
    let mut rng = TestRng(5);
    // Multicast address query: NON, realm-local all routers, normal priority.
    a.post(
        t(0),
        &mut rng,
        &mut sink,
        REALM_ALL_ROUTERS,
        Some(ML_A),
        Priority::Normal,
        Uri::AddressQuery,
        &[1, 2],
        Some(1),
    )
    .unwrap();
    let (info, sp, dp, data) = &sink.sent[0];
    assert_eq!((*sp, *dp), (UDP_PORT, UDP_PORT));
    assert_eq!(
        (info.dst, info.src, info.dscp),
        (REALM_ALL_ROUTERS, Some(ML_A), DSCP_NORMAL)
    );
    let m = Message::parse(data).unwrap();
    assert_eq!(m.ty(), Type::Non);
    assert!(m.uri_path_is("a/aq"));
    let token = m.token().to_vec();

    // Unicast CON to the leader, low priority; retransmitted, then ACKed.
    a.post(
        t(0),
        &mut rng,
        &mut sink,
        ML_B,
        Some(ML_A),
        Priority::Low,
        Uri::ServerData,
        &[],
        Some(2),
    )
    .unwrap();
    assert_eq!(sink.sent[1].0.dscp, DSCP_LOW);
    let d = a.next_deadline().unwrap();
    assert!(a.poll(d, &mut sink).is_none());
    assert_eq!(sink.sent.len(), 3);
    let cm = Message::parse(&sink.sent[1].3).unwrap();
    let mut b = [0u8; 32];
    let ack = MessageBuilder::new(
        &mut b,
        Type::Ack,
        Code::CHANGED,
        cm.message_id(),
        cm.token(),
    )
    .unwrap();
    let n = ack.finish().unwrap();
    let r = a.handle_receiver(
        d,
        &mut sink,
        &Env,
        &meta(ML_B, ML_A, UDP_PORT, true),
        &b[..n],
    );
    assert!(matches!(r, TmfRx::Response { user: 2, .. }));

    // A NON response from a multicast responder is delivered with its peer.
    let mut b2 = [0u8; 32];
    let rb = MessageBuilder::new(&mut b2, Type::Non, Code::CHANGED, 5, &token).unwrap();
    let n = rb.finish().unwrap();
    let r = a.handle_receiver(
        d,
        &mut sink,
        &Env,
        &meta(ML_B, ML_A, UDP_PORT, true),
        &b2[..n],
    );
    assert!(matches!(r, TmfRx::Response { user: 1, peer, .. } if peer.addr == ML_B));
}

#[test]
fn receiver_registration_and_truncation() {
    let mut udp: UdpSockets<2, 2, 64, 2> = UdpSockets::new();
    A::register_receiver(&mut udp).unwrap();
    assert_eq!(A::register_receiver(&mut udp), Err(Error::Already));
    A::unregister_receiver(&mut udp).unwrap();

    let mut a = agent();
    let mut sink = Sink::default();
    let mut h = H::default();
    let req = request(Type::Con, 7, &[1, 2], "a/aq", &[1, 2, 3]);
    for cut in 0..=req.len() {
        a.handle_dispatch(
            t(0),
            &mut sink,
            &Env,
            &meta(ML_A, ML_B, UDP_PORT, true),
            &req[..cut],
            &mut h,
        );
    }
}
