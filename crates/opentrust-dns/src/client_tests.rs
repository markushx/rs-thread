//! DNS client tests against a scripted (sans-IO) fake server.

use core::net::{Ipv6Addr, SocketAddrV6};
use std::vec::Vec;

use opentrust_core::time::{Duration, Instant};

use crate::client::*;
use crate::rdata::{TxtEntry, encode_txt};
use crate::test_util::TestRng;
use crate::wire::{Header, Parser, Part, Writer, class, opcode, rcode, rtype};

const SERVICE: &str = "_matter._tcp.default.service.arpa";
const HOST: &str = "host1.default.service.arpa";
const INSTANCE: &str = "ABCD-1234";

fn server() -> SocketAddrV6 {
    SocketAddrV6::new("fd00::53".parse().unwrap(), 53, 0, 0)
}

#[derive(Debug)]
enum Res {
    Address(ResolvedAddresses),
    Service(ResolvedService),
    Browse(Vec<std::string::String>, Option<ResolvedService>),
    Failed(DnsError),
}

#[derive(Default)]
struct Ctx {
    sent: Vec<(SocketAddrV6, Vec<u8>)>,
    results: Vec<(QueryId, Res)>,
}

impl DnsContext for Ctx {
    fn send(&mut self, server: SocketAddrV6, payload: &[u8]) -> opentrust_core::Result<()> {
        self.sent.push((server, payload.to_vec()));
        Ok(())
    }

    fn result(&mut self, id: QueryId, result: DnsResult<'_>) {
        let r = match result {
            DnsResult::Address(a) => Res::Address(a.clone()),
            DnsResult::Service(s) => Res::Service(s.clone()),
            DnsResult::Failed(e) => Res::Failed(e),
            DnsResult::Browse(b) => {
                let names: Vec<_> = b
                    .instances()
                    .map(|n| n.to_dotted::<128>().unwrap().as_str().into())
                    .collect();
                let first = b.instances().next().and_then(|n| b.service_info(&n).ok());
                Res::Browse(names, first)
            }
        };
        self.results.push((id, r));
    }
}

fn t(secs: u64) -> Instant {
    Instant::from_secs(secs)
}

/// Build a response to `query` from a record-writing closure.
fn respond(query: &[u8], rcode: u8, fill: impl FnOnce(&mut Writer<'_>) -> u16) -> Vec<u8> {
    let (mut p, h) = Parser::new(query).unwrap();
    let mut buf = [0u8; 600];
    let mut w = Writer::new(&mut buf).unwrap();
    let mut first = None;
    for _ in 0..h.qd {
        let q = p.question().unwrap();
        let mut name = std::string::String::new();
        q.name.fmt_dotted(&mut name).unwrap();
        w.write_question(&name, q.qtype, q.qclass).unwrap();
        first.get_or_insert(q.qtype);
    }
    let an = fill(&mut w);
    w.set_header(&Header {
        id: h.id,
        response: true,
        rd: true,
        ra: true,
        rcode,
        qd: h.qd,
        an,
        ..Header::default()
    });
    w.as_bytes().to_vec()
}

fn questions(q: &[u8]) -> Vec<(std::string::String, u16)> {
    let (mut p, h) = Parser::new(q).unwrap();
    (0..h.qd)
        .map(|_| {
            let q = p.question().unwrap();
            let mut s = std::string::String::new();
            q.name.fmt_dotted(&mut s).unwrap();
            (s, q.qtype)
        })
        .collect()
}

fn new_client() -> (DnsClient, Ctx, TestRng) {
    let mut c = DnsClient::new();
    c.set_default_server(Some(server()));
    (c, Ctx::default(), TestRng(0x1234_5678_9abc))
}

#[test]
fn address_query_and_answer() {
    let (mut c, mut ctx, mut rng) = new_client();
    let id = c
        .resolve_address(t(0), &mut rng, &mut ctx, HOST, None)
        .unwrap();
    assert_eq!(ctx.sent.len(), 1);
    let (dst, q) = ctx.sent[0].clone();
    assert_eq!(dst, server());
    let h = Header::decode(&q).unwrap();
    assert!(!h.response && h.rd && h.qd == 1 && h.id != 0);
    assert_eq!(h.opcode, opcode::QUERY);
    assert_eq!(questions(&q), [(HOST.into(), rtype::AAAA)]);
    assert_eq!(c.next_deadline(), Some(t(6)));

    let a1: Ipv6Addr = "fd00::1".parse().unwrap();
    let a2: Ipv6Addr = "2001:db8::2".parse().unwrap();
    let resp = respond(&q, rcode::SUCCESS, |w| {
        w.write_name(HOST).unwrap();
        w.write_aaaa(100, &a1).unwrap();
        w.write_name(HOST).unwrap();
        w.write_aaaa(200, &a2).unwrap();
        // Unrelated record is ignored.
        w.write_name("other.default.service.arpa").unwrap();
        w.write_aaaa(1, &a1).unwrap();
        3
    });
    c.handle_datagram(server(), &resp, &mut ctx);
    let [(rid, Res::Address(a))] = &ctx.results[..] else {
        panic!("{:?}", ctx.results)
    };
    assert_eq!(*rid, id);
    assert_eq!(a.addrs.len(), 2);
    assert_eq!(a.addrs[0], AddressInfo { addr: a1, ttl: 100 });
    assert_eq!(a.addrs[1].addr, a2);
    assert_eq!(c.active_queries(), 0);
    assert_eq!(c.next_deadline(), None);
}

#[test]
fn rejects_foreign_responses() {
    let (mut c, mut ctx, mut rng) = new_client();
    c.resolve_address(t(0), &mut rng, &mut ctx, HOST, None)
        .unwrap();
    let q = ctx.sent[0].1.clone();
    let ok = respond(&q, rcode::SUCCESS, |w| {
        w.write_name(HOST).unwrap();
        w.write_aaaa(1, &Ipv6Addr::LOCALHOST).unwrap();
        1
    });
    // Wrong source.
    let other = SocketAddrV6::new("fd00::54".parse().unwrap(), 53, 0, 0);
    c.handle_datagram(other, &ok, &mut ctx);
    // Wrong id.
    let mut bad = ok.clone();
    bad[1] ^= 1;
    c.handle_datagram(server(), &bad, &mut ctx);
    // Not a response.
    let mut notresp = ok.clone();
    notresp[2] &= 0x7f;
    c.handle_datagram(server(), &notresp, &mut ctx);
    // Question mismatch.
    let mismatch = respond(&q, rcode::SUCCESS, |_| 0);
    let mut mm = mismatch.clone();
    mm[13] ^= 0x20; // flips the case of the first label char: still equal
    c.handle_datagram(server(), &[0u8; 5], &mut ctx);
    assert!(ctx.results.is_empty());
    // Case-only differences in the question are accepted (then NotFound
    // since there are no answers).
    c.handle_datagram(server(), &mm, &mut ctx);
    assert!(matches!(
        ctx.results[..],
        [(_, Res::Failed(DnsError::NotFound))]
    ));
}

#[test]
fn nxdomain_and_other_rcodes() {
    for (rc, want) in [
        (rcode::NAME_ERROR, DnsError::NotFound),
        (rcode::SERVER_FAILURE, DnsError::Rcode(2)),
        (rcode::REFUSED, DnsError::Rcode(5)),
    ] {
        let (mut c, mut ctx, mut rng) = new_client();
        c.resolve_address(t(0), &mut rng, &mut ctx, HOST, None)
            .unwrap();
        let q = ctx.sent[0].1.clone();
        let r = respond(&q, rc, |_| 0);
        c.handle_datagram(server(), &r, &mut ctx);
        assert!(matches!(&ctx.results[..], [(_, Res::Failed(e))] if *e == want));
    }
    // Truncated.
    let (mut c, mut ctx, mut rng) = new_client();
    c.resolve_address(t(0), &mut rng, &mut ctx, HOST, None)
        .unwrap();
    let mut r = respond(&ctx.sent[0].1.clone(), rcode::SUCCESS, |_| 0);
    r[2] |= 0x02;
    c.handle_datagram(server(), &r, &mut ctx);
    assert!(matches!(
        ctx.results[..],
        [(_, Res::Failed(DnsError::Truncated))]
    ));
}

#[test]
fn retransmission_and_timeout() {
    let (mut c, mut ctx, mut rng) = new_client();
    c.resolve_address(t(0), &mut rng, &mut ctx, HOST, None)
        .unwrap();
    c.poll(t(5), &mut rng, &mut ctx);
    assert_eq!(ctx.sent.len(), 1);
    c.poll(t(6), &mut rng, &mut ctx);
    assert_eq!(ctx.sent.len(), 2);
    assert_eq!(ctx.sent[0].1, ctx.sent[1].1, "same id and content");
    assert_eq!(c.next_deadline(), Some(t(12)));
    c.poll(t(12), &mut rng, &mut ctx);
    assert_eq!(ctx.sent.len(), 3);
    assert!(ctx.results.is_empty());
    c.poll(t(18), &mut rng, &mut ctx);
    assert_eq!(ctx.sent.len(), 3);
    assert!(matches!(
        ctx.results[..],
        [(_, Res::Failed(DnsError::ResponseTimeout))]
    ));
    assert_eq!(c.active_queries(), 0);
}

#[test]
fn custom_config_and_no_server() {
    let mut c: DnsClient = DnsClient::new();
    let mut ctx = Ctx::default();
    let mut rng = TestRng(7);
    assert_eq!(
        c.browse(t(0), &mut rng, &mut ctx, SERVICE, None),
        Err(opentrust_core::Error::InvalidState)
    );
    let mut cfg = QueryConfig::new(server());
    cfg.recursion_desired = false;
    cfg.max_tx_attempts = 1;
    cfg.response_timeout = Duration::from_secs(2);
    let id = c
        .browse(t(0), &mut rng, &mut ctx, SERVICE, Some(cfg))
        .unwrap();
    assert!(!Header::decode(&ctx.sent[0].1).unwrap().rd);
    c.poll(t(2), &mut rng, &mut ctx);
    assert!(matches!(ctx.results[..], [(i, Res::Failed(DnsError::ResponseTimeout))] if i == id));
    // Cancel delivers nothing.
    let id = c
        .browse(t(3), &mut rng, &mut ctx, SERVICE, Some(cfg))
        .unwrap();
    c.cancel(id);
    c.poll(t(10), &mut rng, &mut ctx);
    assert_eq!(ctx.results.len(), 1);
}

fn instance_parts() -> [Part<'static>; 2] {
    [Part::Label(INSTANCE), Part::Dotted(SERVICE)]
}

fn write_service_records(w: &mut Writer<'_>, with_aaaa: bool) -> u16 {
    w.write_name_parts(&instance_parts(), true).unwrap();
    let m = w.begin_record(rtype::SRV, class::IN, 120).unwrap();
    w.put_u16(0).unwrap();
    w.put_u16(0).unwrap();
    w.put_u16(5540).unwrap();
    w.write_name(HOST).unwrap();
    w.end_record(m).unwrap();
    w.write_name_parts(&instance_parts(), true).unwrap();
    let m = w.begin_record(rtype::TXT, class::IN, 60).unwrap();
    let mut t = [0u8; 32];
    let n = encode_txt(
        &[TxtEntry {
            key: b"CRI",
            value: Some(b"5000"),
        }],
        &mut t,
    )
    .unwrap();
    w.put(&t[..n]).unwrap();
    w.end_record(m).unwrap();
    if with_aaaa {
        w.write_name(HOST).unwrap();
        w.write_aaaa(120, &"fd00::abcd".parse().unwrap()).unwrap();
        3
    } else {
        2
    }
}

#[test]
fn resolve_service_combined() {
    let (mut c, mut ctx, mut rng) = new_client();
    c.resolve_service(t(0), &mut rng, &mut ctx, INSTANCE, SERVICE, None)
        .unwrap();
    let q = ctx.sent[0].1.clone();
    let full = std::format!("{INSTANCE}.{SERVICE}");
    assert_eq!(
        questions(&q),
        [(full.clone(), rtype::SRV), (full, rtype::TXT)]
    );
    let r = respond(&q, rcode::SUCCESS, |w| write_service_records(w, true));
    c.handle_datagram(server(), &r, &mut ctx);
    let [(_, Res::Service(s))] = &ctx.results[..] else {
        panic!("{:?}", ctx.results)
    };
    assert_eq!((s.port, s.ttl, s.host.as_str()), (5540, 120, HOST));
    assert_eq!(&s.txt[..], b"\x08CRI=5000");
    assert_eq!(s.addrs.len(), 1);
    assert_eq!(s.addrs[0].addr, "fd00::abcd".parse::<Ipv6Addr>().unwrap());
}

#[test]
fn resolve_service_optimize_falls_back_to_separate_queries() {
    let (mut c, mut ctx, mut rng) = new_client();
    c.resolve_service(t(0), &mut rng, &mut ctx, INSTANCE, SERVICE, None)
        .unwrap();
    assert_eq!(ctx.sent.len(), 1);
    // The combined query is not retransmitted: it is replaced.
    c.poll(t(6), &mut rng, &mut ctx);
    assert_eq!(ctx.sent.len(), 3);
    let (q_srv, q_txt) = (ctx.sent[1].1.clone(), ctx.sent[2].1.clone());
    assert_eq!(questions(&q_srv).len(), 1);
    assert_eq!(questions(&q_srv)[0].1, rtype::SRV);
    assert_eq!(questions(&q_txt)[0].1, rtype::TXT);
    assert_ne!(q_srv[..2], q_txt[..2]);
    // TXT answer first: still waiting for SRV.
    let r_txt = respond(&q_txt, rcode::SUCCESS, |w| {
        w.write_name_parts(&instance_parts(), true).unwrap();
        let m = w.begin_record(rtype::TXT, class::IN, 60).unwrap();
        w.put(&[3, b'a', b'=', b'b']).unwrap();
        w.end_record(m).unwrap();
        1
    });
    c.handle_datagram(server(), &r_txt, &mut ctx);
    assert!(ctx.results.is_empty());
    let r_srv = respond(&q_srv, rcode::SUCCESS, |w| {
        w.write_name_parts(&instance_parts(), true).unwrap();
        let m = w.begin_record(rtype::SRV, class::IN, 120).unwrap();
        w.put_u16(1).unwrap();
        w.put_u16(2).unwrap();
        w.put_u16(5541).unwrap();
        w.write_name(HOST).unwrap();
        w.end_record(m).unwrap();
        w.write_name(HOST).unwrap();
        w.write_aaaa(9, &"fd00::5".parse().unwrap()).unwrap();
        2
    });
    c.handle_datagram(server(), &r_srv, &mut ctx);
    let [(_, Res::Service(s))] = &ctx.results[..] else {
        panic!("{:?}", ctx.results)
    };
    assert_eq!((s.priority, s.weight, s.port), (1, 2, 5541));
    assert_eq!(&s.txt[..], b"\x03a=b");
    assert_eq!(s.addrs.len(), 1);
}

#[test]
fn resolve_service_separate_mode_and_missing_srv() {
    let (mut c, mut ctx, mut rng) = new_client();
    let mut cfg = QueryConfig::new(server());
    cfg.service_mode = ServiceMode::SrvTxtSeparate;
    c.resolve_service(t(0), &mut rng, &mut ctx, INSTANCE, SERVICE, Some(cfg))
        .unwrap();
    assert_eq!(ctx.sent.len(), 2);
    // SRV wire answers with nothing, TXT wire with NXDOMAIN: not found.
    let r_txt = respond(&ctx.sent[1].1.clone(), rcode::NAME_ERROR, |_| 0);
    c.handle_datagram(server(), &r_txt, &mut ctx);
    assert!(ctx.results.is_empty(), "a missing TXT is not fatal");
    let r_srv = respond(&ctx.sent[0].1.clone(), rcode::SUCCESS, |_| 0);
    c.handle_datagram(server(), &r_srv, &mut ctx);
    assert!(matches!(
        ctx.results[..],
        [(_, Res::Failed(DnsError::NotFound))]
    ));
}

#[test]
fn browse_with_additional_records() {
    let (mut c, mut ctx, mut rng) = new_client();
    c.browse(t(0), &mut rng, &mut ctx, SERVICE, None).unwrap();
    let q = ctx.sent[0].1.clone();
    assert_eq!(questions(&q), [(SERVICE.into(), rtype::PTR)]);
    let r = respond(&q, rcode::SUCCESS, |w| {
        for inst in ["ABCD-1234", "FFFF-0000"] {
            w.write_name(SERVICE).unwrap();
            let m = w.begin_record(rtype::PTR, class::IN, 100).unwrap();
            w.write_name_parts(&[Part::Label(inst), Part::Dotted(SERVICE)], true)
                .unwrap();
            w.end_record(m).unwrap();
        }
        // Additional: details of the first instance only.
        write_service_records(w, true);
        2
    });
    // `respond` counts only the two PTRs as answers; the rest are
    // additional records, patch the header counts.
    let mut r = r;
    r[10..12].copy_from_slice(&3u16.to_be_bytes());
    c.handle_datagram(server(), &r, &mut ctx);
    let [(_, Res::Browse(names, info))] = &ctx.results[..] else {
        panic!("{:?}", ctx.results)
    };
    assert_eq!(names.len(), 2);
    assert!(names[0].starts_with("ABCD-1234."));
    let info = info.as_ref().unwrap();
    assert_eq!(info.port, 5540);
    assert_eq!(info.addrs.len(), 1);
}

#[test]
fn browse_without_instances_is_not_found() {
    let (mut c, mut ctx, mut rng) = new_client();
    c.browse(t(0), &mut rng, &mut ctx, SERVICE, None).unwrap();
    let r = respond(&ctx.sent[0].1.clone(), rcode::SUCCESS, |_| 0);
    c.handle_datagram(server(), &r, &mut ctx);
    assert!(matches!(
        ctx.results[..],
        [(_, Res::Failed(DnsError::NotFound))]
    ));
}

#[test]
fn concurrent_queries_use_distinct_ids() {
    let (mut c, mut ctx, mut rng) = new_client();
    for _ in 0..4 {
        c.resolve_address(t(0), &mut rng, &mut ctx, HOST, None)
            .unwrap();
    }
    assert_eq!(
        c.resolve_address(t(0), &mut rng, &mut ctx, HOST, None),
        Err(opentrust_core::Error::NoBufs)
    );
    let mut ids: Vec<_> = ctx.sent.iter().map(|(_, q)| [q[0], q[1]]).collect();
    ids.sort();
    ids.dedup();
    assert_eq!(ids.len(), 4);
}
