//! SRP server tests: updates made by the SRP client of this crate.

use core::net::{Ipv6Addr, SocketAddrV6};
use std::vec::Vec;

use rs_thread_core::crypto::SoftCrypto;
use rs_thread_core::crypto::ecdsa::SecretKey;
use rs_thread_core::time::Instant;

use super::*;
use crate::rdata::TxtEntry;
use crate::srp::{
    ClientState, MAX_HOST_ADDRS, ServiceConfig, SrpClient, SrpContext, SrpEnv, SrpEvent,
};
use crate::test_util::TestRng;

type Srv = SrpServer<4, 8, 4>;

fn t(secs: u64) -> Instant {
    Instant::from_secs(secs)
}

fn server_addr() -> SocketAddrV6 {
    SocketAddrV6::new("fd00::a".parse().unwrap(), 53535, 0, 0)
}

#[derive(Default)]
struct Ctx {
    sent: Vec<Vec<u8>>,
    key: Option<[u8; 32]>,
}

impl SrpContext for Ctx {
    fn send(&mut self, _s: SocketAddrV6, payload: &[u8]) -> rs_thread_core::Result<()> {
        self.sent.push(payload.to_vec());
        Ok(())
    }
    fn event(&mut self, _e: SrpEvent) {}
    fn auto_addresses(&mut self, out: &mut heapless::Vec<Ipv6Addr, MAX_HOST_ADDRS>) {
        let _ = out.push("2001:db8::1".parse().unwrap());
    }
    fn ml_eid(&mut self) -> Ipv6Addr {
        "fd11:22::1234".parse().unwrap()
    }
    fn load_key(&mut self) -> Option<SecretKey> {
        self.key.map(SecretKey)
    }
    fn store_key(&mut self, key: &SecretKey) {
        self.key = Some(key.0);
    }
}

struct Client {
    c: SrpClient,
    ctx: Ctx,
    rng: TestRng,
}

macro_rules! env {
    ($cl:expr, $now:expr) => {
        SrpEnv {
            now: $now,
            rng: &mut $cl.rng,
            crypto: &SoftCrypto,
            ctx: &mut $cl.ctx,
        }
    };
}

impl Client {
    fn new(seed: u8, host: &str, services: &[(&str, &str)]) -> Self {
        let mut cl = Self {
            c: SrpClient::new(),
            ctx: Ctx {
                key: Some([seed; 32]),
                ..Ctx::default()
            },
            rng: TestRng(0x1234_5678 + u64::from(seed)),
        };
        let mut env = env!(cl, t(0));
        cl.c.set_host_name(&mut env, host).unwrap();
        cl.c.enable_auto_host_address(&mut env).unwrap();
        for (inst, svc) in services {
            let mut s = ServiceConfig::new(svc, inst, 5540).unwrap();
            s.add_sub_type("_sub1").unwrap();
            s.set_txt_entries(&[TxtEntry {
                key: b"k",
                value: Some(b"v"),
            }])
            .unwrap();
            cl.c.add_service(&mut env, s).unwrap();
        }
        cl
    }

    /// Drive the client until it has sent a message; returns it.
    fn message(&mut self) -> Vec<u8> {
        let before = self.ctx.sent.len();
        let mut now = t(0);
        if self.c.state() == ClientState::Stopped {
            let mut env = env!(self, now);
            self.c.start(&mut env, server_addr()).unwrap();
        }
        while self.ctx.sent.len() == before {
            now = now.max(self.c.next_deadline().unwrap());
            let mut env = env!(self, now);
            self.c.poll(&mut env);
        }
        self.ctx.sent.last().unwrap().clone()
    }

    fn deliver(&mut self, resp: &[u8]) {
        let mut env = env!(self, t(1));
        self.c.handle_datagram(&mut env, server_addr(), resp);
    }
}

fn send(s: &mut Srv, now: Instant, msg: &[u8]) -> (Reply, Vec<u8>) {
    let mut out = [0u8; 512];
    let r = s.handle_message(now, msg, &SoftCrypto, &mut out).unwrap();
    (r, out[..r.len].to_vec())
}

fn name(s: &str) -> WireName {
    WireName::from_dotted(s).unwrap()
}

#[test]
fn register_and_response() {
    let mut s = Srv::new();
    let mut c = Client::new(1, "my-host", &[("inst", "_ipps._tcp")]);
    let m = c.message();
    let (r, resp) = send(&mut s, t(1), &m);
    assert_eq!(r.rcode, rcode::SUCCESS);
    assert!(r.committed);
    // The default maximum key lease (189 h) is below the 14 days asked for:
    // the response carries the granted values.
    assert!(r.len > 12);
    c.deliver(&resp);
    assert_eq!(c.c.state(), ClientState::Updated);

    let h = s.hosts().next().unwrap();
    assert!(h.name.eq_name(&name("MY-host.default.service.arpa")));
    assert_eq!(
        h.addresses.as_slice(),
        ["2001:db8::1".parse::<Ipv6Addr>().unwrap()]
    );
    assert_eq!((h.lease, h.key_lease, h.ttl), (7200, 680_400, 7200));
    let sv: Vec<_> = s.services_of(h).collect();
    assert_eq!(sv.len(), 1);
    assert!(
        sv[0]
            .instance
            .eq_name(&name("inst._ipps._tcp.default.service.arpa"))
    );
    assert!(
        sv[0]
            .service_name
            .eq_name(&name("_ipps._tcp.default.service.arpa"))
    );
    assert_eq!(sv[0].sub_types.len(), 1);
    assert_eq!(sv[0].sub_type_label(0), b"_sub1");
    assert_eq!(sv[0].port, 5540);
    assert_eq!(sv[0].txt.as_slice(), b"\x03k=v");
    assert!(!sv[0].deleted);
    assert_eq!(sv[0].ttl, 7200);
}

#[test]
fn lease_is_clamped_and_reported() {
    let mut s = Srv::new();
    assert!(s.set_lease_config(LeaseConfig {
        min_lease: 30,
        max_lease: 1000,
        min_key_lease: 30,
        max_key_lease: 5000,
    }));
    assert!(!s.set_lease_config(LeaseConfig {
        min_lease: 30,
        max_lease: 1000,
        min_key_lease: 30,
        max_key_lease: 500,
    }));
    let mut c = Client::new(1, "h", &[("i", "_a._tcp")]);
    let m = c.message();
    let (r, resp) = send(&mut s, t(1), &m);
    assert_eq!(r.rcode, 0);
    assert!(r.len > 12);
    let (_, hd) = Parser::new(&resp).unwrap();
    assert_eq!(hd.ar, 1);
    let h = s.hosts().next().unwrap();
    assert_eq!((h.lease, h.key_lease, h.ttl), (1000, 5000, 1000));
    c.deliver(&resp);
    assert_eq!(c.c.state(), ClientState::Updated);
}

#[test]
fn bad_signature_is_refused() {
    let mut s = Srv::new();
    let mut c = Client::new(1, "h", &[("i", "_a._tcp")]);
    let m = c.message();
    // The port of the SRV record is covered by the signature.
    let mut bad = m.clone();
    let pos = bad.windows(2).position(|w| w == [0x15, 0xa4]).unwrap();
    bad[pos] ^= 1;
    let (r, _) = send(&mut s, t(1), &bad);
    assert_eq!(r.rcode, rcode::REFUSED);
    assert!(s.hosts().next().is_none());
    // A flipped bit in the signature itself.
    let mut bad = m.clone();
    let l = bad.len();
    bad[l - 5] ^= 0x40;
    let (r, _) = send(&mut s, t(1), &bad);
    assert_eq!(r.rcode, rcode::REFUSED);
    let (r, _) = send(&mut s, t(1), &m);
    assert_eq!(r.rcode, 0);
}

#[test]
fn name_conflicts_need_the_same_key() {
    let mut s = Srv::new();
    let mut a = Client::new(1, "host-a", &[("inst", "_a._tcp")]);
    let m = a.message();
    assert_eq!(send(&mut s, t(1), &m).0.rcode, 0);

    // Another key, same host name.
    let mut b = Client::new(2, "host-a", &[("other", "_a._tcp")]);
    let m = b.message();
    assert_eq!(send(&mut s, t(2), &m).0.rcode, rcode::NAME_EXISTS);
    // Another key, new host name, same service instance name.
    let mut c = Client::new(3, "host-c", &[("inst", "_a._tcp")]);
    let m = c.message();
    assert_eq!(send(&mut s, t(2), &m).0.rcode, rcode::NAME_EXISTS);
    // The same key may move the instance to another host.
    let mut d = Client::new(1, "host-d", &[("inst", "_a._tcp")]);
    let m = d.message();
    assert_eq!(send(&mut s, t(2), &m).0.rcode, 0);
    assert_eq!(s.hosts().count(), 2);
}

#[test]
fn update_replaces_listed_services_and_keeps_others() {
    let mut s = Srv::new();
    let mut a = Client::new(1, "h", &[("one", "_a._tcp")]);
    send(&mut s, t(1), &a.message());
    let mut a2 = Client::new(1, "h", &[("two", "_a._tcp")]);
    assert_eq!(send(&mut s, t(5), &a2.message()).0.rcode, 0);
    let h = s.hosts().next().unwrap();
    assert_eq!(s.services_of(h).count(), 2, "the service not listed stays");
    assert_eq!(s.hosts().count(), 1);
}

#[test]
fn lease_expiry_keeps_names_until_the_key_lease_ends() {
    let mut s = Srv::new();
    let mut a = Client::new(1, "h", &[("one", "_a._tcp"), ("two", "_a._tcp")]);
    let m = a.message();
    send(&mut s, t(10), &m);
    assert_eq!(s.next_deadline().unwrap(), t(10 + 7200));

    s.poll(t(10 + 7200));
    let h = s.hosts().next().unwrap();
    assert!(h.is_deleted());
    assert!(h.addresses.is_empty());
    assert!(s.services_of(h).all(|x| x.deleted));
    assert_eq!(s.next_deadline().unwrap(), t(10 + 680_400));

    s.poll(t(10 + 680_400));
    assert!(s.hosts().next().is_none());
    assert_eq!(s.all_services().count(), 0);
    assert!(s.next_deadline().is_none());
}

#[test]
fn removal_keeps_or_releases_names() {
    let mut s = Srv::new();
    let mut a = Client::new(1, "h", &[("one", "_a._tcp"), ("two", "_a._tcp")]);
    let m = a.message();
    send(&mut s, t(10), &m);
    a.deliver(&[]);
    {
        let mut env = env!(a, t(20));
        a.c.remove_host_and_services(&mut env, false, true).unwrap();
    }
    let m = a.message();
    let (r, _) = send(&mut s, t(20), &m);
    assert_eq!(r.rcode, 0);
    let h = s.hosts().next().unwrap();
    assert!(h.is_deleted());
    assert_eq!(s.services_of(h).count(), 2);
    assert!(s.services_of(h).all(|x| x.deleted));

    let mut a = Client::new(1, "h", &[]);
    {
        let mut env = env!(a, t(30));
        a.c.remove_host_and_services(&mut env, true, true).unwrap();
    }
    let m = a.message();
    let (r, _) = send(&mut s, t(30), &m);
    assert_eq!(r.rcode, 0);
    assert!(s.hosts().next().is_none());
}

#[test]
fn not_an_update_is_dropped_and_garbage_is_refused() {
    let mut s = Srv::new();
    let mut out = [0u8; 64];
    let q = [0u8; 12];
    assert!(s.handle_message(t(0), &q, &SoftCrypto, &mut out).is_none());
    // An UPDATE without zone.
    let mut u = [0u8; 12];
    u[2] = 5 << 3;
    let r = s.handle_message(t(0), &u, &SoftCrypto, &mut out).unwrap();
    assert_eq!(r.rcode, rcode::FORMAT_ERROR);
    assert!(
        s.handle_message(t(0), &[1, 2], &SoftCrypto, &mut out)
            .is_none()
    );
}

#[test]
fn capacity_limits_are_servfail() {
    let mut s: SrpServer<1, 2, 4> = SrpServer::new();
    let mut a = Client::new(1, "a", &[("i", "_a._tcp")]);
    let mut out = [0u8; 512];
    let m = a.message();
    assert_eq!(
        s.handle_message(t(1), &m, &SoftCrypto, &mut out)
            .unwrap()
            .rcode,
        0
    );
    let mut b = Client::new(2, "b", &[("j", "_a._tcp")]);
    let m = b.message();
    assert_eq!(
        s.handle_message(t(1), &m, &SoftCrypto, &mut out)
            .unwrap()
            .rcode,
        rcode::SERVER_FAILURE
    );
}

#[derive(Default)]
struct DnsCtx {
    sent: Vec<Vec<u8>>,
    out: Vec<(usize, usize, u16, Vec<u8>)>,
    failed: Vec<crate::client::DnsError>,
}

impl crate::client::DnsContext for DnsCtx {
    fn send(&mut self, _s: SocketAddrV6, p: &[u8]) -> rs_thread_core::Result<()> {
        self.sent.push(p.to_vec());
        Ok(())
    }
    fn result(&mut self, _id: crate::client::QueryId, r: crate::client::DnsResult<'_>) {
        use crate::client::DnsResult;
        match r {
            DnsResult::Browse(b) => {
                let n = b.instances().count();
                let info = b
                    .instances()
                    .next()
                    .and_then(|i| b.service_info(&i).ok())
                    .map(|i| (i.port, i.txt.to_vec()))
                    .unwrap_or_default();
                self.out.push((n, 0, info.0, info.1));
            }
            DnsResult::Service(s) => self.out.push((1, s.addrs.len(), s.port, s.txt.to_vec())),
            DnsResult::Failed(e) => self.failed.push(e),
            DnsResult::Address(a) => self.out.push((0, a.addrs.len(), 0, Vec::new())),
            DnsResult::Records(_) => {}
        }
    }
}

#[test]
fn dnssd_answers_browse_resolve_and_nxdomain() {
    use crate::client::{DnsClient, QueryConfig};
    let mut s = Srv::new();
    let mut a = Client::new(1, "h1", &[("ins1", "_a._tcp")]);
    send(&mut s, t(1), &a.message());
    let mut b = Client::new(2, "h2", &[("ins2", "_a._tcp")]);
    send(&mut s, t(1), &b.message());

    let mut dns: DnsClient = DnsClient::new();
    let mut ctx = DnsCtx::default();
    let mut rng = TestRng(7);
    let cfg = QueryConfig::new(server_addr());
    let run = |s: &Srv, dns: &mut DnsClient, ctx: &mut DnsCtx| {
        let q = ctx.sent.last().unwrap().clone();
        let mut o = [0u8; 1232];
        let n = s.handle_query(t(10), &q, &mut o).unwrap();
        dns.handle_datagram(server_addr(), &o[..n], ctx);
    };
    // Two instances: the PTR answers only.
    dns.browse(
        t(10),
        &mut rng,
        &mut ctx,
        "_A._tcp.default.service.arpa",
        Some(cfg),
    )
    .unwrap();
    run(&s, &mut dns, &mut ctx);
    assert_eq!(ctx.out.pop().unwrap().0, 2);
    // One instance via subtype: service info comes in the additional section.
    dns.browse(
        t(10),
        &mut rng,
        &mut ctx,
        "_a._tcp.default.service.arpa",
        Some(cfg),
    )
    .unwrap();
    run(&s, &mut dns, &mut ctx);
    // Resolve an instance (SRV + TXT + AAAA).
    dns.resolve_service(
        t(10),
        &mut rng,
        &mut ctx,
        "INS1",
        "_a._tcp.default.service.arpa",
        Some(cfg),
    )
    .unwrap();
    run(&s, &mut dns, &mut ctx);
    let r = ctx.out.pop().unwrap();
    assert_eq!((r.0, r.1, r.2), (1, 1, 5540));
    // Host addresses.
    dns.resolve_address(
        t(10),
        &mut rng,
        &mut ctx,
        "H2.default.service.arpa",
        Some(cfg),
    )
    .unwrap();
    run(&s, &mut dns, &mut ctx);
    assert_eq!(ctx.out.pop().unwrap().1, 1);
    // Unknown name.
    dns.resolve_address(
        t(10),
        &mut rng,
        &mut ctx,
        "nope.default.service.arpa",
        Some(cfg),
    )
    .unwrap();
    run(&s, &mut dns, &mut ctx);
    assert_eq!(ctx.failed.pop(), Some(crate::client::DnsError::NotFound));
}
