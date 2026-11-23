use super::*;
use crate::message::{Message, MessageBuilder};
use std::vec::Vec;

/// Deterministic xorshift64* test RNG (same shape as the one in core).
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

#[derive(Default)]
struct Rec {
    sent: Vec<(Peer, SendOpts, Vec<u8>)>,
}

impl Transport for Rec {
    fn send(&mut self, peer: &Peer, opts: &SendOpts, data: &[u8]) -> Result<()> {
        self.sent.push((*peer, *opts, data.to_vec()));
        Ok(())
    }
}

type Ep = Endpoint<4, 4, 3, 256>;

const PEER: Peer = Peer::new(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2), 61631);
const ME: Ipv6Addr = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1);
const MCAST: Ipv6Addr = Ipv6Addr::new(0xff03, 0, 0, 0, 0, 0, 0, 2);

fn t(ms: u64) -> Instant {
    Instant::from_millis(ms)
}

fn rx(peer: Peer, dst: Ipv6Addr) -> RxInfo {
    RxInfo { peer, dst }
}

fn parse(d: &[u8]) -> Message<'_> {
    Message::parse(d).unwrap()
}

fn build(ty: Type, code: Code, mid: u16, token: &[u8], path: &str, payload: &[u8]) -> Vec<u8> {
    let mut b = [0u8; 128];
    let mut m = MessageBuilder::new(&mut b, ty, code, mid, token).unwrap();
    if !path.is_empty() {
        m.uri_path(path).unwrap();
    }
    let n = m.finish_with_payload(payload).unwrap();
    b[..n].to_vec()
}

#[test]
fn tx_params_match_ot_defaults() {
    let p = TxParams::default();
    assert!(p.is_valid());
    // span(4) = 2000 * 15 / 2 * 3 = 45000; + 2 * 100000 + 2000.
    assert_eq!(p.exchange_lifetime(), Duration::from_millis(247_000));
    // span(5) = 2000 * 31 / 2 * 3 = 93000.
    assert_eq!(p.max_transmit_wait(), Duration::from_millis(93_000));
    let mut rng = TestRng(7);
    for _ in 0..200 {
        let d = p.initial_timeout(&mut rng).as_millis();
        assert!((2000..=3000).contains(&d), "{d}");
    }
    assert!(
        !TxParams {
            ack_timeout_ms: 500,
            ..p
        }
        .is_valid()
    );
}

#[test]
fn con_request_retransmission_schedule() {
    let mut ep = Ep::new(100, TxParams::default());
    let mut rng = TestRng(1);
    let mut tr = Rec::default();
    ep.post(
        t(1000),
        &mut rng,
        &mut tr,
        &PEER,
        &SendOpts::default(),
        "a/aq",
        &[1, 2, 3],
        Some(7),
    )
    .unwrap();
    assert_eq!(tr.sent.len(), 1);
    let first = tr.sent[0].2.clone();
    let m = parse(&first);
    assert_eq!(
        (m.ty(), m.code(), m.message_id()),
        (Type::Con, Code::POST, 100)
    );
    assert!(m.uri_path_is("a/aq"));
    assert_eq!(m.token().len(), 2);
    assert_eq!(m.payload(), &[1, 2, 3]);

    // Deterministic: the schedule is t0, 2*t0, 4*t0, 8*t0 apart, then a
    // final 16*t0 wait before the timeout is reported.
    let d0 = ep.next_deadline().unwrap();
    let t0 = d0.as_millis() - 1000;
    assert!((2000..=3000).contains(&t0));
    // Nothing before the deadline.
    assert_eq!(ep.poll(t(d0.as_millis() - 1), &mut tr), None);
    assert_eq!(tr.sent.len(), 1);
    let mut now = d0.as_millis();
    for k in 1..=4u64 {
        assert_eq!(ep.next_deadline(), Some(t(now)));
        assert_eq!(ep.poll(t(now), &mut tr), None);
        assert_eq!(tr.sent.len() as u64, 1 + k);
        assert_eq!(tr.sent.last().unwrap().2, first, "retransmission identical");
        now += t0 << k;
        assert_eq!(ep.next_deadline(), Some(t(now)));
    }
    assert_eq!(ep.poll(t(now), &mut tr), Some(Event::Timeout { user: 7 }));
    assert_eq!(tr.sent.len(), 5);
    assert_eq!(ep.pending_len(), 0);
    assert_eq!(ep.next_deadline(), None);
    assert_eq!(ep.poll(t(now + 100_000), &mut tr), None);
}

#[test]
fn piggybacked_response_completes_request() {
    let mut ep = Ep::new(1, TxParams::default());
    let mut rng = TestRng(2);
    let mut tr = Rec::default();
    ep.post(
        t(0),
        &mut rng,
        &mut tr,
        &PEER,
        &SendOpts::default(),
        "a/aq",
        &[],
        Some(5),
    )
    .unwrap();
    let req = tr.sent[0].2.clone();
    let rq = parse(&req);
    let token = rq.token().to_vec();

    // Wrong token in an ACK with a response code: ignored, still pending.
    let bad = build(Type::Ack, Code::CHANGED, rq.message_id(), &[9, 9], "", &[]);
    assert!(matches!(
        ep.handle_datagram(t(10), &mut tr, &rx(PEER, ME), &bad),
        Rx::Handled
    ));
    assert_eq!(ep.pending_len(), 1);
    // Wrong peer: ignored.
    let other = Peer::new(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 9), 61631);
    let ok = build(
        Type::Ack,
        Code::CHANGED,
        rq.message_id(),
        &token,
        "",
        &[0xaa],
    );
    assert!(matches!(
        ep.handle_datagram(t(10), &mut tr, &rx(other, ME), &ok),
        Rx::Handled
    ));
    assert_eq!(ep.pending_len(), 1);
    match ep.handle_datagram(t(20), &mut tr, &rx(PEER, ME), &ok) {
        Rx::Response { user, msg, peer } => {
            assert_eq!(user, 5);
            assert_eq!(peer, PEER);
            assert_eq!(msg.code(), Code::CHANGED);
            assert_eq!(msg.payload(), &[0xaa]);
        }
        _ => panic!(),
    }
    assert_eq!(ep.pending_len(), 0);
    assert_eq!(tr.sent.len(), 1);
    // No more retransmissions / timeouts.
    assert_eq!(ep.poll(t(100_000), &mut tr), None);
    assert_eq!(tr.sent.len(), 1);
}

#[test]
fn empty_ack_then_separate_response() {
    let mut ep = Ep::new(1, TxParams::default());
    let mut rng = TestRng(3);
    let mut tr = Rec::default();
    ep.post(
        t(0),
        &mut rng,
        &mut tr,
        &PEER,
        &SendOpts::default(),
        "x/y",
        &[],
        Some(1),
    )
    .unwrap();
    let req = tr.sent[0].2.clone();
    let rq = parse(&req);
    let token = rq.token().to_vec();
    let mid = rq.message_id();

    let ack = build(Type::Ack, Code::EMPTY, mid, &[], "", &[]);
    assert!(matches!(
        ep.handle_datagram(t(100), &mut tr, &rx(PEER, ME), &ack),
        Rx::Handled
    ));
    assert_eq!(ep.pending_len(), 1);
    // Retransmission is suppressed once acknowledged, but the request is
    // still tracked and times out (OT behaviour).
    let mut now = 0;
    let mut ev = None;
    for _ in 0..10 {
        now = ep.next_deadline().unwrap().as_millis();
        ev = ep.poll(t(now), &mut tr);
        if ev.is_some() {
            break;
        }
    }
    assert_eq!(ev, Some(Event::Timeout { user: 1 }));
    assert_eq!(tr.sent.len(), 1, "no retransmission after empty ACK");

    // New exchange: separate CON response is ACKed and delivered.
    ep.post(
        t(now),
        &mut rng,
        &mut tr,
        &PEER,
        &SendOpts::default(),
        "x/y",
        &[],
        Some(2),
    )
    .unwrap();
    let rq2 = parse(&tr.sent.last().unwrap().2.clone()).token().to_vec();
    let sep = build(Type::Con, Code::CONTENT, 0x4444, &rq2, "", &[7]);
    let before = tr.sent.len();
    match ep.handle_datagram(t(now + 5), &mut tr, &rx(PEER, ME), &sep) {
        Rx::Response { user, msg, .. } => {
            assert_eq!(user, 2);
            assert_eq!(msg.payload(), &[7]);
        }
        _ => panic!(),
    }
    assert_eq!(tr.sent.len(), before + 1);
    let a = parse(&tr.sent[before].2);
    assert_eq!(
        (a.ty(), a.code(), a.message_id()),
        (Type::Ack, Code::EMPTY, 0x4444)
    );
    let _ = token;
}

#[test]
fn reset_aborts_request_and_unmatched_con_gets_rst() {
    let mut ep = Ep::new(50, TxParams::default());
    let mut rng = TestRng(4);
    let mut tr = Rec::default();
    ep.post(
        t(0),
        &mut rng,
        &mut tr,
        &PEER,
        &SendOpts::default(),
        "a",
        &[],
        Some(9),
    )
    .unwrap();
    let rst = build(Type::Rst, Code::EMPTY, 50, &[], "", &[]);
    match ep.handle_datagram(t(1), &mut tr, &rx(PEER, ME), &rst) {
        Rx::Failed { user, error } => assert_eq!((user, error), (9, Error::Abort)),
        _ => panic!(),
    }
    assert_eq!(ep.pending_len(), 0);

    // Unmatched CON response -> RST; unmatched NON -> silent.
    let con = build(Type::Con, Code::CONTENT, 0x1111, &[1, 1], "", &[]);
    tr.sent.clear();
    assert!(matches!(
        ep.handle_datagram(t(2), &mut tr, &rx(PEER, ME), &con),
        Rx::Handled
    ));
    let r = parse(&tr.sent[0].2);
    assert_eq!((r.ty(), r.message_id()), (Type::Rst, 0x1111));
    let non = build(Type::Non, Code::CONTENT, 0x2222, &[1, 1], "", &[]);
    tr.sent.clear();
    ep.handle_datagram(t(2), &mut tr, &rx(PEER, ME), &non);
    assert!(tr.sent.is_empty());
}

#[test]
fn multicast_request_collects_responses_until_wait_expires() {
    let mut ep = Ep::new(1, TxParams::default());
    let mut rng = TestRng(5);
    let mut tr = Rec::default();
    let dst = Peer::new(MCAST, 61631);
    ep.post(
        t(0),
        &mut rng,
        &mut tr,
        &dst,
        &SendOpts::default(),
        "d/dg",
        &[],
        Some(3),
    )
    .unwrap();
    let req = parse(&tr.sent[0].2.clone()).token().to_vec();
    assert_eq!(parse(&tr.sent[0].2).ty(), Type::Non);
    assert_eq!(ep.next_deadline(), Some(t(93_000)));
    for (i, src) in [2u16, 3, 4].into_iter().enumerate() {
        let from = Peer::new(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, src), 61631);
        let resp = build(
            Type::Non,
            Code::CHANGED,
            0x100 + i as u16,
            &req,
            "",
            &[src as u8],
        );
        match ep.handle_datagram(t(1000), &mut tr, &rx(from, ME), &resp) {
            Rx::Response { user, peer, msg } => {
                assert_eq!((user, peer), (3, from));
                assert_eq!(msg.payload(), &[src as u8]);
            }
            _ => panic!(),
        }
    }
    assert_eq!(ep.pending_len(), 1);
    assert_eq!(ep.poll(t(92_999), &mut tr), None);
    assert_eq!(
        ep.poll(t(93_000), &mut tr),
        Some(Event::Timeout { user: 3 })
    );
    assert_eq!(tr.sent.len(), 1, "NON is never retransmitted");
}

fn server() -> (Ep, Rec) {
    let mut ep = Ep::new(1, TxParams::default());
    ep.add_resource("a/aq", ResourceId(1)).unwrap();
    ep.add_resource("c/ag", ResourceId(2)).unwrap();
    (ep, Rec::default())
}

#[test]
fn resource_table() {
    let (mut ep, _) = server();
    assert_eq!(ep.add_resource("a/aq", ResourceId(3)), Err(Error::Already));
    ep.add_resource("x", ResourceId(3)).unwrap();
    ep.add_resource("y", ResourceId(4)).unwrap();
    assert_eq!(ep.add_resource("z", ResourceId(5)), Err(Error::NoBufs));
    ep.remove_resource("x").unwrap();
    assert_eq!(ep.remove_resource("x"), Err(Error::NotFound));
    ep.add_resource("z", ResourceId(5)).unwrap();
    assert_eq!(
        ep.add_resource("0123456789012345678901234567890123", ResourceId(6)),
        Err(Error::InvalidArgs)
    );
}

#[test]
fn con_request_piggybacked_response_and_duplicate_cache() {
    let (mut ep, mut tr) = server();
    let req = build(Type::Con, Code::POST, 0xabcd, &[1, 2, 3], "a/aq", &[0x10]);
    let r = match ep.handle_datagram(t(0), &mut tr, &rx(PEER, ME), &req) {
        Rx::Request(r) => r,
        _ => panic!(),
    };
    assert_eq!(r.resource, ResourceId(1));
    assert_eq!(r.msg.payload(), &[0x10]);
    assert_eq!(r.ctx.token(), &[1, 2, 3]);
    assert!(tr.sent.is_empty());
    ep.respond_payload(
        t(0),
        &mut tr,
        &r.ctx,
        &SendOpts::default(),
        Code::CHANGED,
        &[0x20],
    )
    .unwrap();
    assert_eq!(tr.sent.len(), 1);
    let resp = tr.sent[0].2.clone();
    let m = parse(&resp);
    assert_eq!(
        (m.ty(), m.code(), m.message_id()),
        (Type::Ack, Code::CHANGED, 0xabcd)
    );
    assert_eq!(m.token(), &[1, 2, 3]);
    assert_eq!(
        tr.sent[0].1.src,
        Some(ME),
        "reply from the address it was sent to"
    );
    assert_eq!(ep.cached_len(), 1);

    // Duplicate (same mid + peer): answered from the cache, app not involved.
    assert!(matches!(
        ep.handle_datagram(t(1000), &mut tr, &rx(PEER, ME), &req),
        Rx::Handled
    ));
    assert_eq!(tr.sent.len(), 2);
    assert_eq!(tr.sent[1].2, resp);
    // Same mid from another peer is a different exchange.
    let other = Peer::new(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 7), 1234);
    assert!(matches!(
        ep.handle_datagram(t(1000), &mut tr, &rx(other, ME), &req),
        Rx::Request(_)
    ));
    // Entry expires after EXCHANGE_LIFETIME.
    assert_eq!(ep.next_deadline(), Some(t(247_000)));
    ep.poll(t(246_999), &mut tr);
    assert_eq!(ep.cached_len(), 1);
    ep.poll(t(247_000), &mut tr);
    assert_eq!(ep.cached_len(), 0);
    assert!(matches!(
        ep.handle_datagram(t(247_001), &mut tr, &rx(PEER, ME), &req),
        Rx::Request(_)
    ));
}

#[test]
fn response_cache_evicts_earliest() {
    let (mut ep, mut tr) = server();
    for i in 0..4u16 {
        let req = build(Type::Con, Code::POST, 100 + i, &[i as u8], "a/aq", &[]);
        let now = t(1000 * (i as u64 + 1));
        let Rx::Request(r) = ep.handle_datagram(now, &mut tr, &rx(PEER, ME), &req) else {
            panic!()
        };
        ep.respond(
            now,
            &mut tr,
            &r.ctx,
            &SendOpts::default(),
            Code::CHANGED,
            |b| b.finish(),
        )
        .unwrap();
        assert_eq!(ep.cached_len(), (i as usize + 1).min(3));
    }
    // mid 100 (earliest) was evicted: a repeat is a fresh request again;
    // mid 103 is still cached.
    let again = build(Type::Con, Code::POST, 100, &[0], "a/aq", &[]);
    assert!(matches!(
        ep.handle_datagram(t(5000), &mut tr, &rx(PEER, ME), &again),
        Rx::Request(_)
    ));
    let n = tr.sent.len();
    let dup = build(Type::Con, Code::POST, 103, &[3], "a/aq", &[]);
    assert!(matches!(
        ep.handle_datagram(t(5000), &mut tr, &rx(PEER, ME), &dup),
        Rx::Handled
    ));
    assert_eq!(tr.sent.len(), n + 1);
}

#[test]
fn non_request_gets_non_response_and_no_cache() {
    let (mut ep, mut tr) = server();
    let req = build(Type::Non, Code::POST, 9, &[4, 4], "c/ag", &[]);
    let Rx::Request(r) = ep.handle_datagram(t(0), &mut tr, &rx(PEER, ME), &req) else {
        panic!()
    };
    ep.respond_payload(
        t(0),
        &mut tr,
        &r.ctx,
        &SendOpts::default(),
        Code::CHANGED,
        &[1],
    )
    .unwrap();
    let m = parse(&tr.sent[0].2);
    assert_eq!((m.ty(), m.token()), (Type::Non, &[4u8, 4][..]));
    assert_ne!(m.message_id(), 9);
    assert_eq!(ep.cached_len(), 0);
}

#[test]
fn multicast_request_no_src_override_and_unknown_path_rules() {
    let (mut ep, mut tr) = server();
    // Multicast NON request for a known resource: respond() must not force
    // the multicast address as source.
    let req = build(Type::Non, Code::POST, 1, &[1], "a/aq", &[]);
    let Rx::Request(r) = ep.handle_datagram(t(0), &mut tr, &rx(PEER, MCAST), &req) else {
        panic!()
    };
    assert!(r.ctx.is_multicast());
    ep.respond_payload(
        t(0),
        &mut tr,
        &r.ctx,
        &SendOpts::default(),
        Code::CHANGED,
        &[],
    )
    .unwrap();
    assert_eq!(tr.sent[0].1.src, None);

    // Unknown path: CON unicast -> piggybacked 4.04; multicast -> silence.
    tr.sent.clear();
    let unk = build(Type::Con, Code::POST, 0x77, &[5], "z/z", &[]);
    ep.handle_datagram(t(0), &mut tr, &rx(PEER, ME), &unk);
    let m = parse(&tr.sent[0].2);
    assert_eq!(
        (m.ty(), m.code(), m.message_id()),
        (Type::Ack, Code::NOT_FOUND, 0x77)
    );
    tr.sent.clear();
    let unk_mc = build(Type::Con, Code::POST, 0x79, &[5], "z/z", &[]);
    ep.handle_datagram(t(0), &mut tr, &rx(PEER, MCAST), &unk_mc);
    assert!(tr.sent.is_empty());
    // NON unknown: NON 4.04.
    let unk = build(Type::Non, Code::POST, 0x78, &[5], "z/z", &[]);
    ep.handle_datagram(t(0), &mut tr, &rx(PEER, ME), &unk);
    let m = parse(&tr.sent[0].2);
    assert_eq!((m.ty(), m.code()), (Type::Non, Code::NOT_FOUND));
}

#[test]
fn malformed_datagrams() {
    let (mut ep, mut tr) = server();
    // CON with bad option (nibble 15): RST for unicast, nothing for multicast.
    let bad = [0x40, 0x02, 0x12, 0x34, 0xf1, 0x00];
    assert!(matches!(
        ep.handle_datagram(t(0), &mut tr, &rx(PEER, ME), &bad),
        Rx::Handled
    ));
    let m = parse(&tr.sent[0].2);
    assert_eq!((m.ty(), m.message_id()), (Type::Rst, 0x1234));
    tr.sent.clear();
    ep.handle_datagram(t(0), &mut tr, &rx(PEER, MCAST), &bad);
    assert!(tr.sent.is_empty());
    // NON malformed and wrong version: ignored.
    let bad = [0x50, 0x02, 0x12, 0x34, 0xf1, 0x00];
    ep.handle_datagram(t(0), &mut tr, &rx(PEER, ME), &bad);
    let bad = [0x80, 0x02, 0x12, 0x34];
    ep.handle_datagram(t(0), &mut tr, &rx(PEER, ME), &bad);
    ep.handle_datagram(t(0), &mut tr, &rx(PEER, ME), &[]);
    assert!(tr.sent.is_empty());
}

#[test]
fn separate_response_flow_on_server() {
    let (mut ep, mut tr) = server();
    let mut rng = TestRng(11);
    let req = build(Type::Con, Code::POST, 0x500, &[8, 8], "a/aq", &[]);
    let Rx::Request(r) = ep.handle_datagram(t(0), &mut tr, &rx(PEER, ME), &req) else {
        panic!()
    };
    ep.ack_empty(&mut tr, &r.ctx).unwrap();
    let a = parse(&tr.sent[0].2);
    assert_eq!(
        (a.ty(), a.code(), a.message_id()),
        (Type::Ack, Code::EMPTY, 0x500)
    );
    ep.respond_separate(
        t(10),
        &mut rng,
        &mut tr,
        &r.ctx,
        &SendOpts::default(),
        Code::CHANGED,
        |b| b.finish_with_payload(&[5]),
    )
    .unwrap();
    let sbytes = tr.sent[1].2.clone();
    let s = parse(&sbytes);
    assert_eq!(
        (s.ty(), s.code(), s.token()),
        (Type::Con, Code::CHANGED, &[8u8, 8][..])
    );
    let smid = s.message_id();
    assert_eq!(ep.pending_len(), 1);
    // Retransmitted until ACKed.
    let d = ep.next_deadline().unwrap();
    ep.poll(d, &mut tr);
    assert_eq!(tr.sent.len(), 3);
    let ack = build(Type::Ack, Code::EMPTY, smid, &[], "", &[]);
    ep.handle_datagram(d, &mut tr, &rx(PEER, ME), &ack);
    assert_eq!(ep.pending_len(), 0);
    assert_eq!(ep.next_deadline(), None);
}

#[test]
fn capacity_limits_and_cancel() {
    let mut ep = Ep::new(1, TxParams::default());
    let mut rng = TestRng(12);
    let mut tr = Rec::default();
    for u in 0..4 {
        ep.post(
            t(0),
            &mut rng,
            &mut tr,
            &PEER,
            &SendOpts::default(),
            "a",
            &[],
            Some(u),
        )
        .unwrap();
    }
    assert_eq!(
        ep.post(
            t(0),
            &mut rng,
            &mut tr,
            &PEER,
            &SendOpts::default(),
            "a",
            &[],
            Some(9)
        ),
        Err(Error::NoBufs)
    );
    assert!(ep.cancel(2));
    assert!(!ep.cancel(2));
    assert_eq!(ep.pending_len(), 3);
    ep.clear_requests(&PEER.addr);
    assert_eq!(ep.pending_len(), 0);
    // Oversized payload does not fit MSG=256 and leaves no state behind.
    let big = [0u8; 300];
    assert!(
        ep.post(
            t(0),
            &mut rng,
            &mut tr,
            &PEER,
            &SendOpts::default(),
            "a",
            &big,
            Some(1)
        )
        .is_err()
    );
    assert_eq!(ep.pending_len(), 0);
    // NON fire-and-forget is not stored.
    ep.send_request(
        t(0),
        &mut rng,
        &mut tr,
        &PEER,
        &SendOpts::default(),
        Type::Non,
        Code::POST,
        None,
        |b| b.finish(),
    )
    .unwrap();
    assert_eq!(ep.pending_len(), 0);
    assert_eq!(
        ep.send_request(
            t(0),
            &mut rng,
            &mut tr,
            &PEER,
            &SendOpts::default(),
            Type::Ack,
            Code::POST,
            None,
            |b| b.finish()
        ),
        Err(Error::InvalidArgs)
    );
}

#[test]
fn truncated_and_random_input_never_panics() {
    let (mut ep, mut tr) = server();
    let full = build(Type::Con, Code::POST, 0x500, &[8, 8], "a/aq", &[1, 2, 3, 4]);
    for cut in 0..=full.len() {
        let _ = ep.handle_datagram(t(0), &mut tr, &rx(PEER, ME), &full[..cut]);
    }
    let mut rng = TestRng(99);
    let mut buf = [0u8; 40];
    for _ in 0..3000 {
        rand_core::Rng::fill_bytes(&mut rng, &mut buf);
        buf[0] = 0x40 | (buf[0] & 0x3f);
        let n = 4 + (buf[1] as usize % 36);
        let dst = if buf[2] & 1 == 0 { ME } else { MCAST };
        if let Rx::Request(r) = ep.handle_datagram(t(1), &mut tr, &rx(PEER, dst), &buf[..n]) {
            let _ = ep.respond(
                t(1),
                &mut tr,
                &r.ctx,
                &SendOpts::default(),
                Code::CHANGED,
                |b| b.finish(),
            );
        }
        tr.sent.clear();
        ep.poll(t(2), &mut tr);
    }
}
