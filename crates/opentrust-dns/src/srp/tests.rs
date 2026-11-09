//! SRP client tests against a scripted (sans-IO) fake server. Signatures are
//! verified with the RustCrypto `p256` `VerifyingKey`.

use core::net::{Ipv6Addr, SocketAddrV6};
use std::string::String;
use std::vec::Vec;

use opentrust_core::crypto::SoftCrypto;
use opentrust_core::crypto::ecdsa::{PUBLIC_KEY_LEN, SecretKey};
use opentrust_core::time::Instant;
use p256::ecdsa::signature::hazmat::PrehashVerifier;
use sha2::{Digest, Sha256};

use super::discovery::*;
use super::*;
use crate::rdata::{LeaseOption, TxtEntry};
use crate::test_util::TestRng;
use crate::wire::{Header, Parser, Writer, class, opcode, rcode, rtype};

fn server() -> SocketAddrV6 {
    SocketAddrV6::new("fd00::a".parse().unwrap(), 53535, 0, 0)
}

fn t(ms: u64) -> Instant {
    Instant::from_millis(ms)
}

#[derive(Default)]
struct Ctx {
    sent: Vec<(SocketAddrV6, Vec<u8>)>,
    events: Vec<SrpEvent>,
    key: Option<[u8; 32]>,
    saved_server: Option<SocketAddrV6>,
    auto: Vec<Ipv6Addr>,
    fail_send: bool,
}

impl SrpContext for Ctx {
    fn send(&mut self, server: SocketAddrV6, payload: &[u8]) -> opentrust_core::Result<()> {
        if self.fail_send {
            return Err(opentrust_core::Error::Platform);
        }
        self.sent.push((server, payload.to_vec()));
        Ok(())
    }
    fn event(&mut self, event: SrpEvent) {
        self.events.push(event);
    }
    fn auto_addresses(&mut self, out: &mut heapless::Vec<Ipv6Addr, MAX_HOST_ADDRS>) {
        for a in &self.auto {
            let _ = out.push(*a);
        }
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
    fn load_server(&mut self) -> Option<SocketAddrV6> {
        self.saved_server
    }
    fn store_server(&mut self, s: Option<SocketAddrV6>) {
        self.saved_server = s;
    }
}

struct Rig {
    c: SrpClient,
    ctx: Ctx,
    rng: TestRng,
}

impl Rig {
    fn new() -> Self {
        Self {
            c: SrpClient::new(),
            ctx: Ctx::default(),
            rng: TestRng(0xdead_beef_1234),
        }
    }
}

macro_rules! with_env {
    ($rig:expr, $now:expr, |$c:ident, $env:ident| $body:expr) => {{
        let r = &mut *$rig;
        let mut $env = SrpEnv {
            now: $now,
            rng: &mut r.rng,
            crypto: &SoftCrypto,
            ctx: &mut r.ctx,
        };
        let $c = &mut r.c;
        $body
    }};
}

fn configured() -> Rig {
    let mut r = Rig::new();
    r.ctx.auto = std::vec!["2001:db8::1".parse().unwrap()];
    with_env!(&mut r, t(0), |c, env| {
        c.set_host_name(&mut env, "my-host").unwrap();
        c.enable_auto_host_address(&mut env).unwrap();
        let mut s = ServiceConfig::new("_matter._tcp", "ABCD-1234", 5540).unwrap();
        s.add_sub_type("_I0123").unwrap();
        s.set_txt_entries(&[TxtEntry {
            key: b"SII",
            value: Some(b"5000"),
        }])
        .unwrap();
        c.add_service(&mut env, s).unwrap();
    });
    r
}

// ---------------------------------------------------------- fake server

#[derive(Debug)]
struct Rec {
    name: String,
    rtype: u16,
    class: u16,
    ttl: u32,
    rdata: Vec<u8>,
}

#[derive(Debug)]
struct Update {
    id: u16,
    zone: String,
    updates: Vec<Rec>,
    lease: Option<LeaseOption>,
    host_key: Option<[u8; PUBLIC_KEY_LEN]>,
    sig_valid: bool,
}

fn dotted(n: &crate::wire::Name<'_>) -> String {
    let mut s = String::new();
    n.fmt_dotted(&mut s).unwrap();
    s
}

/// Parse an update and verify its SIG(0) with the KEY it carries.
fn parse_update(msg: &[u8]) -> Update {
    let (mut p, h) = Parser::new(msg).unwrap();
    assert!(!h.response);
    assert_eq!(h.opcode, opcode::UPDATE);
    assert_eq!((h.qd, h.an, h.ar), (1, 0, 2));
    let q = p.question().unwrap();
    assert_eq!((q.qtype, q.qclass), (rtype::SOA, class::IN));
    let zone = dotted(&q.name);
    let mut updates = Vec::new();
    let mut host_key = None;
    for _ in 0..h.ns {
        let r = p.record().unwrap();
        if r.rtype == rtype::KEY {
            host_key = Some(*r.key().unwrap().public_key);
        }
        updates.push(Rec {
            name: dotted(&r.name),
            rtype: r.rtype,
            class: r.class,
            ttl: r.ttl,
            rdata: r.rdata.to_vec(),
        });
    }
    let opt = p.record().unwrap();
    assert_eq!(opt.rtype, rtype::OPT);
    assert!(opt.opt_dnssec_ok());
    assert_eq!(opt.opt_udp_payload(), 1232);
    let lease = opt.update_lease().unwrap();
    let sig_start = p.offset();
    let sig = p.record().unwrap();
    assert_eq!((sig.rtype, sig.class, sig.ttl), (rtype::SIG, class::ANY, 0));
    assert!(sig.name.eq_dotted("."));
    let s = sig.sig().unwrap();
    assert_eq!((s.type_covered, s.algorithm, s.labels), (0, 13, 0));
    // Reconstruct what was signed.
    let mut signed = Vec::new();
    signed.extend_from_slice(&sig.rdata[..18]);
    for l in s.signer.labels() {
        let l = l.unwrap();
        signed.push(l.len() as u8);
        signed.extend_from_slice(l);
    }
    signed.push(0);
    let mut m = msg[..sig_start].to_vec();
    m[10..12].copy_from_slice(&1u16.to_be_bytes());
    signed.extend_from_slice(&m);
    let digest = Sha256::digest(&signed);
    let mut sec1 = [0u8; 65];
    sec1[0] = 4;
    sec1[1..].copy_from_slice(&host_key.expect("host KEY record"));
    let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(&sec1).unwrap();
    let sg = p256::ecdsa::Signature::from_slice(s.signature).unwrap();
    let sig_valid = vk.verify_prehash(&digest, &sg).is_ok();
    Update {
        id: h.id,
        zone,
        updates,
        lease,
        host_key,
        sig_valid,
    }
}

fn response(id: u16, rc: u8, lease: Option<LeaseOption>) -> Vec<u8> {
    let mut buf = [0u8; 128];
    let mut w = Writer::new(&mut buf).unwrap();
    if lease.is_some() {
        w.write_opt(1232, false, lease).unwrap();
    }
    w.set_header(&Header {
        id,
        response: true,
        opcode: opcode::UPDATE,
        rcode: rc,
        ar: u16::from(lease.is_some()),
        ..Header::default()
    });
    w.as_bytes().to_vec()
}

fn count(u: &Update, ty: u16, cl: u16) -> usize {
    u.updates
        .iter()
        .filter(|r| r.rtype == ty && r.class == cl)
        .count()
}

/// Run the client from `from_ms` until it has sent one update; returns it.
fn drive_until_sent(r: &mut Rig, from_ms: u64) -> (Update, Instant) {
    let before = r.ctx.sent.len();
    let mut now = from_ms;
    while r.ctx.sent.len() == before {
        let dl =
            r.c.next_deadline()
                .expect("a deadline while waiting to send");
        now = now.max(dl.as_millis());
        with_env!(r, t(now), |c, env| c.poll(&mut env));
        assert!(now < from_ms + 20_000_000);
    }
    (parse_update(&r.ctx.sent.last().unwrap().1), t(now))
}

// ---------------------------------------------------------------- tests

#[test]
fn registration_message_and_signature() {
    let mut r = configured();
    with_env!(&mut r, t(0), |c, env| c.start(&mut env, server()).unwrap());
    assert_eq!(r.c.state(), ClientState::ToUpdate);
    // Jitter window [10, 500] ms.
    let dl = r.c.next_deadline().unwrap().as_millis();
    assert!((10..=500).contains(&dl), "{dl}");
    with_env!(&mut r, t(dl - 1), |c, env| c.poll(&mut env));
    assert!(r.ctx.sent.is_empty());
    with_env!(&mut r, t(dl), |c, env| c.poll(&mut env));
    assert_eq!(r.ctx.sent.len(), 1);
    assert_eq!(r.ctx.sent[0].0, server());
    assert_eq!(r.c.state(), ClientState::Updating);
    assert_eq!(r.c.host_state(), ItemState::Adding);
    assert_eq!(r.c.next_deadline(), Some(t(dl + 1800)));

    let u = parse_update(&r.ctx.sent[0].1);
    assert!(u.sig_valid, "SIG(0) verifies with the KEY in the message");
    assert_eq!(u.zone, "default.service.arpa");
    assert_eq!(
        u.lease,
        Some(LeaseOption {
            lease: 7200,
            key_lease: 1_209_600
        })
    );
    // Service: PTR + subtype PTR + delete-all + SRV + TXT; host: delete-all
    // + AAAA + KEY.
    assert_eq!(count(&u, rtype::PTR, class::IN), 2);
    assert_eq!(count(&u, rtype::ANY, class::ANY), 2);
    assert_eq!(count(&u, rtype::SRV, class::IN), 1);
    assert_eq!(count(&u, rtype::TXT, class::IN), 1);
    assert_eq!(count(&u, rtype::AAAA, class::IN), 1);
    assert_eq!(count(&u, rtype::KEY, class::IN), 1);
    let ptr = &u.updates[0];
    assert_eq!(ptr.name, "_matter._tcp.default.service.arpa");
    assert_eq!(ptr.ttl, 7200);
    let sub = &u.updates[1];
    assert_eq!(sub.name, "_I0123._sub._matter._tcp.default.service.arpa");
    let srv = u.updates.iter().find(|r| r.rtype == rtype::SRV).unwrap();
    assert_eq!(srv.name, "ABCD-1234._matter._tcp.default.service.arpa");
    assert_eq!(&srv.rdata[..6], &[0, 0, 0, 0, 0x15, 0xa4]);
    let aaaa = u.updates.iter().find(|r| r.rtype == rtype::AAAA).unwrap();
    assert_eq!(aaaa.name, "my-host.default.service.arpa");
    assert_eq!(
        aaaa.rdata,
        "2001:db8::1".parse::<Ipv6Addr>().unwrap().octets()
    );
    // Key persisted through the settings hook.
    assert!(r.ctx.key.is_some());
    let pk = with_env!(&mut r, t(0), |c, env| c.public_key(&mut env).unwrap());
    assert_eq!(Some(pk), u.host_key);
}

#[test]
fn key_is_reused_from_settings() {
    let mut r = configured();
    with_env!(&mut r, t(0), |c, env| c.start(&mut env, server()).unwrap());
    let (u1, _) = drive_until_sent(&mut r, 0);
    // A new client (reboot) with the persisted key registers with the same key.
    let mut r2 = configured();
    r2.ctx.key = r.ctx.key;
    with_env!(&mut r2, t(0), |c, env| c.start(&mut env, server()).unwrap());
    let (u2, _) = drive_until_sent(&mut r2, 0);
    assert_eq!(u1.host_key, u2.host_key);
    assert!(u2.sig_valid);
}

#[test]
fn response_registers_and_lease_is_renewed() {
    let mut r = configured();
    with_env!(&mut r, t(0), |c, env| c.start(&mut env, server()).unwrap());
    let (u, tx) = drive_until_sent(&mut r, 0);
    // Server grants a shorter lease than requested.
    let resp = response(
        u.id,
        rcode::SUCCESS,
        Some(LeaseOption {
            lease: 1000,
            key_lease: 5000,
        }),
    );
    with_env!(&mut r, tx, |c, env| c.handle_datagram(
        &mut env,
        server(),
        &resp
    ));
    assert_eq!(r.c.state(), ClientState::Updated);
    assert_eq!(r.c.host_state(), ItemState::Registered);
    assert_eq!(r.c.service_state(ServiceId(0)), Some(ItemState::Registered));
    assert_eq!(
        r.ctx.events.last(),
        Some(&SrpEvent::Registered {
            lease: 1000,
            key_lease: 5000
        })
    );
    assert_eq!(r.c.retry_wait_interval_ms(), MIN_RETRY_WAIT_MS);
    // Renewal at tx + (lease - guard) s +- 15 s.
    let dl = r.c.next_deadline().unwrap().as_millis() - tx.as_millis();
    let base = (1000 - 120) * 1000;
    assert!((base - 15_000..=base + 15_000).contains(&dl), "{dl}");
    assert_eq!(r.ctx.saved_server, None, "explicit start is not saved");

    // Refresh: the service is re-sent as part of the update, the lease is
    // the default again (the client asks for 7200 each time).
    let renew_at = r.c.next_deadline().unwrap();
    with_env!(&mut r, renew_at, |c, env| c.poll(&mut env));
    assert_eq!(r.c.state(), ClientState::ToUpdate);
    assert_eq!(r.c.host_state(), ItemState::ToRefresh);
    let (u2, tx2) = drive_until_sent(&mut r, renew_at.as_millis());
    assert!(u2.sig_valid);
    assert_eq!(count(&u2, rtype::SRV, class::IN), 1);
    assert_eq!(u2.id, u.id.wrapping_add(1));
    assert_eq!(r.c.service_state(ServiceId(0)), Some(ItemState::Refreshing));
    // A response to the old message id is ignored.
    let old = response(u.id, rcode::SUCCESS, None);
    with_env!(&mut r, tx2, |c, env| c.handle_datagram(
        &mut env,
        server(),
        &old
    ));
    assert_eq!(r.c.state(), ClientState::Updating);
    let resp2 = response(u2.id, rcode::SUCCESS, None);
    with_env!(&mut r, tx2, |c, env| c.handle_datagram(
        &mut env,
        server(),
        &resp2
    ));
    assert_eq!(r.c.state(), ClientState::Updated);
    // No lease option in the response: the requested 7200 applies.
    assert_eq!(
        r.ctx.events.last(),
        Some(&SrpEvent::Registered {
            lease: 7200,
            key_lease: 1_209_600
        })
    );
}

#[test]
fn foreign_responses_are_ignored() {
    let mut r = configured();
    with_env!(&mut r, t(0), |c, env| c.start(&mut env, server()).unwrap());
    let (u, tx) = drive_until_sent(&mut r, 0);
    let resp = response(u.id, rcode::SUCCESS, None);
    let other = SocketAddrV6::new("fd00::b".parse().unwrap(), 53535, 0, 0);
    with_env!(&mut r, tx, |c, env| c
        .handle_datagram(&mut env, other, &resp));
    let bad_id = response(u.id.wrapping_add(5), rcode::SUCCESS, None);
    with_env!(&mut r, tx, |c, env| c.handle_datagram(
        &mut env,
        server(),
        &bad_id
    ));
    with_env!(&mut r, tx, |c, env| c.handle_datagram(
        &mut env,
        server(),
        &[1, 2, 3]
    ));
    assert_eq!(r.c.state(), ClientState::Updating);
}

#[test]
fn name_conflict_and_rejection_retry() {
    let mut r = configured();
    with_env!(&mut r, t(0), |c, env| c.start(&mut env, server()).unwrap());
    let (u, tx) = drive_until_sent(&mut r, 0);
    let resp = response(u.id, rcode::NAME_EXISTS, None);
    with_env!(&mut r, tx, |c, env| c.handle_datagram(
        &mut env,
        server(),
        &resp
    ));
    assert_eq!(
        r.ctx.events.last(),
        Some(&SrpEvent::Failed(SrpError::NameConflict))
    );
    assert_eq!(r.c.state(), ClientState::ToRetry);
    assert_eq!(r.c.host_state(), ItemState::ToAdd, "allows a new host name");
    assert_eq!(r.c.retry_wait_interval_ms(), 3060, "1800 / 10 * 17");
    // The application picks another name; the retry timer is still the one
    // armed when the update was sent.
    with_env!(&mut r, tx, |c, env| c
        .set_host_name(&mut env, "other-host")
        .unwrap());
    let (u2, tx2) = drive_until_sent(&mut r, tx.as_millis());
    assert!(u2.sig_valid);
    assert!(u2.updates.iter().any(|x| x.name.starts_with("other-host.")));
    assert!(tx2.as_millis() >= tx.as_millis());
    // Other rcodes map to errors; REFUSED is a security error.
    let resp = response(u2.id, rcode::REFUSED, None);
    with_env!(&mut r, tx2, |c, env| c.handle_datagram(
        &mut env,
        server(),
        &resp
    ));
    assert_eq!(
        r.ctx.events.last(),
        Some(&SrpEvent::Failed(SrpError::Refused))
    );
}

#[test]
fn timeouts_back_off_exponentially_and_keep_trying() {
    let mut r = configured();
    with_env!(&mut r, t(0), |c, env| c.start(&mut env, server()).unwrap());
    let mut expected = 1800u32;
    let mut now = 0u64;
    for round in 0..4 {
        let (_, tx) = drive_until_sent(&mut r, now);
        assert_eq!(
            r.c.next_deadline(),
            Some(tx.saturating_add(ms(expected))),
            "round {round}"
        );
        now = r.c.next_deadline().unwrap().as_millis();
        with_env!(&mut r, t(now), |c, env| c.poll(&mut env));
        assert_eq!(
            r.ctx.events.last(),
            Some(&SrpEvent::Failed(SrpError::ResponseTimeout))
        );
        expected = expected / 10 * 17;
        assert_eq!(r.c.retry_wait_interval_ms(), expected);
        assert_eq!(r.c.state(), ClientState::ToUpdate);
    }
    // The cap.
    let mut x = 1800u32;
    for _ in 0..40 {
        x = (x / 10 * 17).min(MAX_RETRY_WAIT_MS);
    }
    assert_eq!(x, MAX_RETRY_WAIT_MS);
}

#[test]
fn tx_failure_quick_retries_then_backoff() {
    let mut r = configured();
    r.ctx.fail_send = true;
    with_env!(&mut r, t(0), |c, env| c.start(&mut env, server()).unwrap());
    let mut now = r.c.next_deadline().unwrap().as_millis();
    for i in 0..8 {
        with_env!(&mut r, t(now), |c, env| c.poll(&mut env));
        assert_eq!(r.c.state(), ClientState::ToRetry, "{i}");
        let next = r.c.next_deadline().unwrap().as_millis();
        assert!((240..=260).contains(&(next - now)), "quick retry {i}");
        assert!(r.ctx.events.is_empty(), "not reported yet");
        now = next;
    }
    with_env!(&mut r, t(now), |c, env| c.poll(&mut env));
    assert!(matches!(
        r.ctx.events.last(),
        Some(SrpEvent::Failed(SrpError::Tx(_)))
    ));
    let wait = r.c.next_deadline().unwrap().as_millis() - now;
    assert!((1300..=2300).contains(&wait), "{wait}");
    // Recovery.
    r.ctx.fail_send = false;
    now += wait;
    with_env!(&mut r, t(now), |c, env| c.poll(&mut env));
    assert_eq!(r.c.state(), ClientState::Updating);
}

#[test]
fn full_removal_uses_zero_key_lease() {
    let mut r = configured();
    with_env!(&mut r, t(0), |c, env| c.start(&mut env, server()).unwrap());
    let (u, tx) = drive_until_sent(&mut r, 0);
    let resp = response(u.id, rcode::SUCCESS, None);
    with_env!(&mut r, tx, |c, env| c.handle_datagram(
        &mut env,
        server(),
        &resp
    ));
    with_env!(&mut r, tx, |c, env| c
        .remove_host_and_services(&mut env, true, false)
        .unwrap());
    assert_eq!(r.c.host_state(), ItemState::ToRemove);
    let (u, tx) = drive_until_sent(&mut r, tx.as_millis());
    assert!(u.sig_valid);
    assert_eq!(
        u.lease,
        Some(LeaseOption {
            lease: 0,
            key_lease: 0
        })
    );
    // No service records in a host removal.
    assert_eq!(
        count(&u, rtype::PTR, class::IN) + count(&u, rtype::SRV, class::IN),
        0
    );
    assert_eq!(count(&u, rtype::KEY, class::IN), 1);
    let resp = response(u.id, rcode::SUCCESS, None);
    with_env!(&mut r, tx, |c, env| c.handle_datagram(
        &mut env,
        server(),
        &resp
    ));
    assert!(
        r.ctx
            .events
            .contains(&SrpEvent::ServiceRemoved(ServiceId(0)))
    );
    assert_eq!(r.ctx.events.last(), Some(&SrpEvent::HostRemoved));
    assert_eq!(r.c.service_state(ServiceId(0)), None);
    // Removal that keeps the name reserved sends the default key lease.
    let mut r = configured();
    with_env!(&mut r, t(0), |c, env| c.start(&mut env, server()).unwrap());
    let (u, tx) = drive_until_sent(&mut r, 0);
    let resp = response(u.id, rcode::SUCCESS, None);
    with_env!(&mut r, tx, |c, env| c.handle_datagram(
        &mut env,
        server(),
        &resp
    ));
    with_env!(&mut r, tx, |c, env| c
        .remove_host_and_services(&mut env, false, false)
        .unwrap());
    let (u, _) = drive_until_sent(&mut r, tx.as_millis());
    assert_eq!(
        u.lease,
        Some(LeaseOption {
            lease: 0,
            key_lease: 1_209_600
        })
    );
}

#[test]
fn service_removal_sends_none_class_ptr() {
    let mut r = configured();
    with_env!(&mut r, t(0), |c, env| c.start(&mut env, server()).unwrap());
    let (u, tx) = drive_until_sent(&mut r, 0);
    let resp = response(u.id, rcode::SUCCESS, None);
    with_env!(&mut r, tx, |c, env| c.handle_datagram(
        &mut env,
        server(),
        &resp
    ));
    with_env!(&mut r, tx, |c, env| {
        c.remove_service(&mut env, ServiceId(0)).unwrap()
    });
    let (u, tx) = drive_until_sent(&mut r, tx.as_millis());
    assert!(u.sig_valid);
    assert_eq!(count(&u, rtype::PTR, class::NONE), 1);
    assert_eq!(count(&u, rtype::SRV, class::IN), 0);
    assert_eq!(count(&u, rtype::KEY, class::IN), 1);
    let resp = response(u.id, rcode::SUCCESS, None);
    with_env!(&mut r, tx, |c, env| c.handle_datagram(
        &mut env,
        server(),
        &resp
    ));
    assert_eq!(
        r.ctx.events[r.ctx.events.len() - 2],
        SrpEvent::ServiceRemoved(ServiceId(0))
    );
    assert_eq!(r.c.host_state(), ItemState::Registered);
}

#[test]
fn address_change_triggers_refresh() {
    let mut r = configured();
    with_env!(&mut r, t(0), |c, env| c.start(&mut env, server()).unwrap());
    let (u, tx) = drive_until_sent(&mut r, 0);
    let resp = response(u.id, rcode::SUCCESS, None);
    with_env!(&mut r, tx, |c, env| c.handle_datagram(
        &mut env,
        server(),
        &resp
    ));
    // No change: nothing happens.
    with_env!(&mut r, tx, |c, env| c.on_addresses_changed(&mut env));
    assert_eq!(r.c.state(), ClientState::Updated);
    r.ctx.auto.push("2001:db8:1::2".parse().unwrap());
    with_env!(&mut r, tx, |c, env| c.on_addresses_changed(&mut env));
    assert_eq!(r.c.state(), ClientState::ToUpdate);
    let (u2, _) = drive_until_sent(&mut r, tx.as_millis());
    assert_eq!(count(&u2, rtype::AAAA, class::IN), 2);
    // Without usable addresses the ML-EID is registered.
    let mut r = configured();
    r.ctx.auto.clear();
    with_env!(&mut r, t(0), |c, env| c.start(&mut env, server()).unwrap());
    let (u, _) = drive_until_sent(&mut r, 0);
    let a = u.updates.iter().find(|x| x.rtype == rtype::AAAA).unwrap();
    assert_eq!(
        a.rdata,
        "fd11:22::1234".parse::<Ipv6Addr>().unwrap().octets()
    );
}

#[test]
fn detach_pauses_and_attach_resumes() {
    let mut r = configured();
    with_env!(&mut r, t(0), |c, env| c.start(&mut env, server()).unwrap());
    let (u, tx) = drive_until_sent(&mut r, 0);
    let _ = u;
    with_env!(&mut r, tx, |c, env| c.set_attached(&mut env, false));
    assert_eq!(r.c.state(), ClientState::Paused);
    assert_eq!(r.c.host_state(), ItemState::ToRefresh);
    with_env!(&mut r, tx, |c, env| c.set_attached(&mut env, true));
    assert_eq!(r.c.state(), ClientState::ToUpdate);
    let (u2, _) = drive_until_sent(&mut r, tx.as_millis());
    assert!(u2.sig_valid);
}

// ----------------------------------------------- discovery and auto-start

const MLP: [u8; 8] = [0xfd, 0x11, 0x22, 0, 0, 0, 0, 0];

fn unicast_sd(addr: &str, port: u16, version: Option<u8>) -> Vec<u8> {
    let mut v = std::vec![SERVICE_NUMBER_UNICAST];
    v.extend_from_slice(&addr.parse::<Ipv6Addr>().unwrap().octets());
    v.extend_from_slice(&port.to_be_bytes());
    v.extend(version);
    v
}

fn entry<'a>(id: u8, sd: &'a [u8], rloc: u16, srv: &'a [u8]) -> NetDataService<'a> {
    NetDataService {
        service_id: id,
        enterprise_number: THREAD_ENTERPRISE_NUMBER,
        service_data: sd,
        rloc16: rloc,
        server_data: srv,
    }
}

#[test]
fn discovery_parsing_and_preference() {
    let u1 = unicast_sd("fd00::2", 100, Some(1));
    let u2 = unicast_sd("fd00::1", 200, Some(1));
    let u3 = unicast_sd("fd00::9", 300, Some(2));
    let entries = [
        entry(1, &u1, 0x0400, &[]),
        entry(1, &u2, 0x0800, &[]),
        entry(1, &u3, 0x0c00, &[]),
        // Wrong enterprise number is ignored.
        NetDataService {
            enterprise_number: 1,
            ..entry(1, &u1, 0, &[])
        },
    ];
    let v: Vec<_> =
        unicast_entries(entries.iter().copied(), MLP, UnicastType::InServiceData).collect();
    assert_eq!(v.len(), 3);
    assert_eq!(v[2].version, 2);
    assert_eq!(v[0].addr.port(), 100);
    // Server-data form: address + port, or port only (RLOC address).
    let sd = [SERVICE_NUMBER_UNICAST];
    let full = &u1[1..];
    let port_only = [0x12, 0x34];
    let entries = [
        entry(2, &sd, 0x0400, full),
        entry(2, &sd, 0x0c00, &port_only),
    ];
    let v: Vec<_> =
        unicast_entries(entries.iter().copied(), MLP, UnicastType::InServerData).collect();
    assert_eq!(v[0].addr.ip(), &"fd00::2".parse::<Ipv6Addr>().unwrap());
    assert_eq!(v[1].addr.port(), 0x1234);
    assert_eq!(
        v[1].addr.ip(),
        &"fd11:2200::ff:fe00:c00".parse::<Ipv6Addr>().unwrap()
    );
    // Anycast: ALOC from the service id, sequence number from service data.
    let any_sd = [SERVICE_NUMBER_ANYCAST, 7];
    let entries = [entry(3, &any_sd, 0x0400, &[2])];
    let a: Vec<_> = anycast_entries(entries.iter().copied(), MLP).collect();
    assert_eq!(
        a[0].address,
        "fd11:2200::ff:fe00:fc13".parse::<Ipv6Addr>().unwrap()
    );
    assert_eq!((a[0].sequence_number, a[0].version), (7, 2));
}

#[test]
fn preferred_anycast_serial_arithmetic() {
    let mk = |s: u8| AnycastInfo {
        address: Ipv6Addr::UNSPECIFIED,
        sequence_number: s,
        version: 0,
        rloc16: 0,
    };
    assert!(serial_is_greater(1, 255));
    assert!(!serial_is_greater(255, 1));
    assert!(!serial_is_greater(0, 128) && !serial_is_greater(128, 0));
    // Wrap-around: 1 is newer than 254.
    assert_eq!(
        preferred_anycast(&[mk(254), mk(1)])
            .unwrap()
            .sequence_number,
        1
    );
    assert_eq!(
        preferred_anycast(&[mk(5), mk(9), mk(7)])
            .unwrap()
            .sequence_number,
        9
    );
    // Undefined ordering (diff 128): fall back to the numerically largest.
    assert_eq!(
        preferred_anycast(&[mk(0), mk(128)])
            .unwrap()
            .sequence_number,
        128
    );
    assert!(preferred_anycast(&[]).is_none());
}

fn run_auto(r: &mut Rig, entries: &[NetDataService<'_>], now: u64) {
    with_env!(r, t(now), |c, env| c.handle_network_data(
        &mut env,
        entries.iter().copied(),
        MLP
    ));
}

#[test]
fn auto_start_prefers_unicast_then_anycast_and_switches() {
    let mut r = configured();
    with_env!(&mut r, t(0), |c, env| c.enable_auto_start(&mut env));
    assert!(!r.c.is_running());
    // Anycast only.
    let any7 = [SERVICE_NUMBER_ANYCAST, 7];
    let anycast_addr = SocketAddrV6::new("fd11:2200::ff:fe00:fc10".parse().unwrap(), 53, 0, 0);
    run_auto(&mut r, &[entry(0, &any7, 0x0400, &[])], 1000);
    assert_eq!(r.c.server(), Some(anycast_addr));
    assert_eq!(r.ctx.events, [SrpEvent::ServerSelected(Some(anycast_addr))]);
    // Registration to the anycast server succeeds.
    let (u, tx) = drive_until_sent(&mut r, 1000);
    assert_eq!(r.ctx.sent.last().unwrap().0, anycast_addr);
    let resp = response(u.id, rcode::SUCCESS, None);
    with_env!(&mut r, tx, |c, env| c.handle_datagram(
        &mut env,
        anycast_addr,
        &resp
    ));
    assert_eq!(r.c.host_state(), ItemState::Registered);
    assert_eq!(r.ctx.saved_server, None, "anycast is never saved");

    // Same entry again: nothing changes. New sequence number: restart and
    // re-register.
    let n = r.ctx.events.len();
    run_auto(&mut r, &[entry(0, &any7, 0x0400, &[])], tx.as_millis());
    assert_eq!(r.ctx.events.len(), n);
    let any8 = [SERVICE_NUMBER_ANYCAST, 8];
    run_auto(&mut r, &[entry(0, &any8, 0x0400, &[])], tx.as_millis() + 10);
    assert_eq!(
        &r.ctx.events[n..],
        [
            SrpEvent::ServerSelected(None),
            SrpEvent::ServerSelected(Some(anycast_addr))
        ]
    );
    assert_eq!(
        r.c.host_state(),
        ItemState::ToRefresh,
        "registered items refresh"
    );
    // The server switch gets a long (up to 10 s) tx jitter.
    let dl = r.c.next_deadline().unwrap().as_millis() - (tx.as_millis() + 10);
    assert!((10..=10_000).contains(&dl));

    // A unicast entry with the address in the service data is preferred.
    let u1 = unicast_sd("fd00::77", 5353, Some(0));
    let uni = SocketAddrV6::new("fd00::77".parse().unwrap(), 5353, 0, 0);
    run_auto(
        &mut r,
        &[entry(0, &any8, 0x0400, &[]), entry(1, &u1, 0x0800, &[])],
        tx.as_millis() + 20,
    );
    assert_eq!(r.c.server(), Some(uni));
    let (u, tx2) = drive_until_sent(&mut r, tx.as_millis() + 20);
    let resp = response(u.id, rcode::SUCCESS, None);
    with_env!(&mut r, tx2, |c, env| c
        .handle_datagram(&mut env, uni, &resp));
    assert_eq!(
        r.ctx.saved_server,
        Some(uni),
        "unicast server is remembered"
    );
    // All entries gone: client stops and waits (re-selecting).
    run_auto(&mut r, &[], tx2.as_millis() + 1);
    assert!(!r.c.is_running());
    assert_eq!(r.ctx.events.last(), Some(&SrpEvent::ServerSelected(None)));
    // The server comes back: the services are registered again.
    run_auto(&mut r, &[entry(1, &u1, 0x0800, &[])], tx2.as_millis() + 5);
    assert_eq!(r.c.server(), Some(uni));
}

#[test]
fn auto_start_switches_to_next_unicast_server_on_timeouts() {
    let mut r = configured();
    with_env!(&mut r, t(0), |c, env| c.enable_auto_start(&mut env));
    let a = unicast_sd("fd00::1", 5353, Some(0));
    let b = unicast_sd("fd00::2", 5353, Some(0));
    let entries = [entry(1, &a, 0x0400, &[]), entry(1, &b, 0x0800, &[])];
    run_auto(&mut r, &entries, 0);
    // Numerically smaller address wins at equal version.
    let sa = SocketAddrV6::new("fd00::1".parse().unwrap(), 5353, 0, 0);
    let sb = SocketAddrV6::new("fd00::2".parse().unwrap(), 5353, 0, 0);
    assert_eq!(r.c.server(), Some(sa));
    // Three timeouts in a row move on to the next entry (host unregistered).
    let mut now = 0;
    for _ in 0..3 {
        let (_, tx) = drive_until_sent(&mut r, now);
        now = r.c.next_deadline().unwrap().as_millis().max(tx.as_millis());
        with_env!(&mut r, t(now), |c, env| c.poll(&mut env));
    }
    assert_eq!(r.c.server(), Some(sb));
    // The retry interval was kept across the switch.
    assert!(r.c.retry_wait_interval_ms() > MIN_RETRY_WAIT_MS);
    let (_, _) = drive_until_sent(&mut r, now);
    assert_eq!(r.ctx.sent.last().unwrap().0, sb);
}

#[test]
fn rejected_update_switches_server_only_when_unregistered() {
    let mut r = configured();
    with_env!(&mut r, t(0), |c, env| c.enable_auto_start(&mut env));
    let a = unicast_sd("fd00::1", 5353, Some(0));
    let b = unicast_sd("fd00::2", 5353, Some(0));
    run_auto(
        &mut r,
        &[entry(1, &a, 0x0400, &[]), entry(1, &b, 0x0800, &[])],
        0,
    );
    let sa = SocketAddrV6::new("fd00::1".parse().unwrap(), 5353, 0, 0);
    let (u, tx) = drive_until_sent(&mut r, 0);
    let resp = response(u.id, rcode::NAME_EXISTS, None);
    with_env!(&mut r, tx, |c, env| c.handle_datagram(&mut env, sa, &resp));
    assert_eq!(
        r.c.server().map(|s| *s.ip()),
        Some("fd00::2".parse().unwrap())
    );
}

#[test]
fn user_stop_disables_auto_start_and_keeps_services() {
    let mut r = configured();
    with_env!(&mut r, t(0), |c, env| c.enable_auto_start(&mut env));
    let a = unicast_sd("fd00::1", 5353, Some(0));
    run_auto(&mut r, &[entry(1, &a, 0x0400, &[])], 0);
    assert!(r.c.is_running());
    with_env!(&mut r, t(5), |c, env| c.stop(&mut env));
    assert!(!r.c.is_running());
    run_auto(&mut r, &[entry(1, &a, 0x0400, &[])], 10);
    assert!(
        !r.c.is_running(),
        "auto-start was disabled by the user stop"
    );
    // Restart by hand: the host is registered again.
    with_env!(&mut r, t(20), |c, env| c.start(&mut env, server()).unwrap());
    let (u, _) = drive_until_sent(&mut r, 20);
    assert!(u.sig_valid);
}

#[test]
fn host_name_changes_and_duplicates() {
    let mut r = configured();
    // Duplicate service is rejected.
    let dup = ServiceConfig::new("_matter._tcp", "abcd-1234", 1).unwrap();
    assert_eq!(
        with_env!(&mut r, t(0), |c, env| c.add_service(&mut env, dup)),
        Err(opentrust_core::Error::Already)
    );
    with_env!(&mut r, t(0), |c, env| c.start(&mut env, server()).unwrap());
    let (u, tx) = drive_until_sent(&mut r, 0);
    // While adding, the host name cannot change.
    assert_eq!(
        with_env!(&mut r, tx, |c, env| c.set_host_name(&mut env, "x")),
        Err(opentrust_core::Error::InvalidState)
    );
    let _ = u;
}

#[test]
fn large_update_falls_back_to_single_service_mode() {
    let mut r = Rig::new();
    r.ctx.auto = std::vec!["2001:db8::1".parse().unwrap()];
    with_env!(&mut r, t(0), |c, env| {
        c.set_host_name(&mut env, "big").unwrap();
        c.enable_auto_host_address(&mut env).unwrap();
        for i in 0..4 {
            let mut s = ServiceConfig::new(
                "_x._tcp",
                &std::format!("inst-{i}-{}", "y".repeat(40)),
                1000,
            )
            .unwrap();
            // ~250 bytes of TXT per service: 4 services do not fit in 1232 bytes.
            let big = [b'v'; 120];
            s.set_txt_entries(&[
                TxtEntry {
                    key: b"a",
                    value: Some(&big),
                },
                TxtEntry {
                    key: b"b",
                    value: Some(&big),
                },
            ])
            .unwrap();
            c.add_service(&mut env, s).unwrap();
        }
        c.start(&mut env, server()).unwrap();
    });
    let (u, tx) = drive_until_sent(&mut r, 0);
    assert!(u.sig_valid);
    assert_eq!(count(&u, rtype::SRV, class::IN), 1, "single service mode");
    let _ = tx;
}
