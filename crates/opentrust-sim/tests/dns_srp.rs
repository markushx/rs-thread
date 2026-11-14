//! SRP client and DNS client over the mesh: a router runs a minimal fake
//! SRP / DNS server on a UDP socket, a sleepy end device registers a
//! `_matter._tcp` instance, a third node resolves it.

mod common;

use core::net::{Ipv6Addr, SocketAddrV6};

use common::*;
use opentrust_core::time::Instant;
use opentrust_dns::wire::{Header, Parser, Writer, class, opcode, rcode, rtype};
use opentrust_instance::{
    DnsOutcome, DnsSrpService, Event, ItemState, QueryConfig, Role, ServiceConfig, SrpEvent,
    TxtEntry, UdpSendOpts, UdpSocket,
};
use opentrust_sim::{Kind, Network};
use p256::ecdsa::signature::hazmat::PrehashVerifier;
use sha2::{Digest, Sha256};

const SERVICE: &str = "_matter._tcp.default.service.arpa";
const INSTANCE: &str = "0123456789ABCDEF-0000000000000001";

#[derive(Default)]
struct Registered {
    host: String,
    addr: Option<Ipv6Addr>,
    port: u16,
    txt: Vec<u8>,
    updates: usize,
    bad_signatures: usize,
}

fn dotted(n: &opentrust_dns::wire::Name<'_>) -> String {
    let mut s = String::new();
    n.fmt_dotted(&mut s).unwrap();
    s
}

/// Handle an SRP update: verify SIG(0) with the host KEY and store the data.
fn handle_update(msg: &[u8], reg: &mut Registered) -> Vec<u8> {
    let (mut p, h) = Parser::new(msg).unwrap();
    let _ = p.question().unwrap();
    let mut key = None;
    let mut recs = Vec::new();
    for _ in 0..h.ns {
        let r = p.record().unwrap();
        if r.rtype == rtype::KEY {
            key = Some(*r.key().unwrap().public_key);
        }
        recs.push(r);
    }
    let _opt = p.record().unwrap();
    let sig_start = p.offset();
    let sig = p.record().unwrap();
    let s = sig.sig().unwrap();
    let mut signed = sig.rdata[..18].to_vec();
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
    sec1[1..].copy_from_slice(&key.expect("host KEY"));
    let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(&sec1).unwrap();
    let sg = p256::ecdsa::Signature::from_slice(s.signature).unwrap();
    let ok = vk.verify_prehash(&digest, &sg).is_ok();
    let mut rc = rcode::SUCCESS;
    if ok {
        reg.updates += 1;
        for r in &recs {
            match r.rtype {
                rtype::AAAA => {
                    reg.host = dotted(&r.name);
                    reg.addr = Some(r.aaaa().unwrap());
                }
                rtype::SRV => reg.port = r.srv().unwrap().port,
                rtype::TXT => reg.txt = r.rdata.to_vec(),
                _ => {}
            }
        }
    } else {
        reg.bad_signatures += 1;
        rc = rcode::REFUSED;
    }
    let mut buf = [0u8; 128];
    let mut w = Writer::new(&mut buf).unwrap();
    w.write_opt(
        1232,
        false,
        Some(opentrust_dns::rdata::LeaseOption {
            lease: 7200,
            key_lease: 1_209_600,
        }),
    )
    .unwrap();
    w.set_header(&Header {
        id: h.id,
        response: true,
        opcode: opcode::UPDATE,
        rcode: rc,
        ar: 1,
        ..Header::default()
    });
    w.as_bytes().to_vec()
}

/// Answer a service resolution query from the registered data.
fn handle_query(msg: &[u8], reg: &Registered) -> Vec<u8> {
    let (mut p, h) = Parser::new(msg).unwrap();
    let q = p.question().unwrap();
    let qname = dotted(&q.name);
    let instance_name = format!("{INSTANCE}.{SERVICE}");
    let mut buf = [0u8; 1024];
    let mut w = Writer::new(&mut buf).unwrap();
    for _ in 0..h.qd {
        // Echo the questions.
        w.write_question(&qname, q.qtype, q.qclass).unwrap();
    }
    let mut an = 0;
    let found = reg.addr.is_some() && qname.eq_ignore_ascii_case(&instance_name);
    if found {
        w.write_name(&instance_name).unwrap();
        let m = w.begin_record(rtype::SRV, class::IN, 120).unwrap();
        w.put_u16(0).unwrap();
        w.put_u16(0).unwrap();
        w.put_u16(reg.port).unwrap();
        w.write_name(&reg.host).unwrap();
        w.end_record(m).unwrap();
        an += 1;
        w.write_name(&instance_name).unwrap();
        let m = w.begin_record(rtype::TXT, class::IN, 120).unwrap();
        w.put(&reg.txt).unwrap();
        w.end_record(m).unwrap();
        an += 1;
        w.write_name(&reg.host).unwrap();
        w.write_aaaa(120, &reg.addr.unwrap()).unwrap();
    }
    w.set_header(&Header {
        id: h.id,
        response: true,
        opcode: opcode::QUERY,
        rd: h.rd,
        ra: true,
        rcode: if found {
            rcode::SUCCESS
        } else {
            rcode::NAME_ERROR
        },
        qd: h.qd,
        an,
        ar: u16::from(found),
        ..Header::default()
    });
    w.as_bytes().to_vec()
}

fn serve(net: &mut Network, sock: UdpSocket, reg: &mut Registered, queries: &mut usize) {
    let mut buf = [0u8; 1280];
    while let Ok(Some(rx)) = net.node(0).udp_recv(sock, &mut buf) {
        let msg = buf[..rx.len].to_vec();
        let Ok((_, h)) = Parser::new(&msg) else {
            continue;
        };
        let rsp = if h.opcode == opcode::UPDATE {
            handle_update(&msg, reg)
        } else {
            *queries += 1;
            handle_query(&msg, reg)
        };
        let peer = rx.meta.peer;
        net.with(0, |n, now| {
            n.udp_send_to(sock, peer, &rsp, &UdpSendOpts::default(), now)
                .unwrap();
        });
    }
}

#[test]
fn srp_registration_and_dns_resolution_over_the_mesh() {
    let mut net = Network::new(&[Kind::Router, Kind::Sleepy, Kind::Router], 77);
    net.medium.connect(0, 1, -60);
    net.medium.connect(0, 2, -60);
    let ds = dataset(&mut net);
    start(&mut net, 0, &ds);
    assert!(net.run_until(secs(60), |n| role(n, 0) == Role::Leader));
    start(&mut net, 2, &ds);
    assert!(net.run_until(secs(300), |n| role(n, 2) == Role::Router));
    start(&mut net, 1, &ds);
    assert!(net.run_until(secs(300), |n| role(n, 1) == Role::Child));
    net.with(1, |n, _| {
        n.set_poll_period(Some(opentrust_core::time::Duration::from_secs(1)));
    });

    // Node 0: server socket and Network Data entry.
    let sock = net.node(0).udp_open().unwrap();
    net.node(0)
        .udp_bind(sock, SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 53, 0, 0))
        .unwrap();
    net.with(0, |n, now| {
        n.publish_dns_srp_service(
            DnsSrpService::UnicastMlEid {
                port: 53,
                version: 0,
            },
            now,
        );
    });
    let server = SocketAddrV6::new(net.node(0).ml_eid(), 53, 0, 0);

    // Node 1: register the Matter service, server found through Network Data.
    let mut txt = [0u8; 64];
    let n = opentrust_dns::rdata::encode_txt(
        &[TxtEntry {
            key: b"SII",
            value: Some(b"5000"),
        }],
        &mut txt,
    )
    .unwrap();
    let txt = txt[..n].to_vec();
    net.with(1, |n, now| {
        n.srp_set_host_name("sed-one", now).unwrap();
        n.srp_enable_auto_host_address(now).unwrap();
        let mut cfg = ServiceConfig::new("_matter._tcp", INSTANCE, 5540).unwrap();
        cfg.set_txt_entries(&[TxtEntry {
            key: b"SII",
            value: Some(b"5000"),
        }])
        .unwrap();
        n.srp_add_service(cfg, now).unwrap();
        n.srp_enable_auto_start(now);
    });

    let mut reg = Registered::default();
    let mut queries = 0;
    let ok = net.run_until(secs(600), |n| {
        serve(n, sock, &mut reg, &mut queries);
        n.nodes[1]
            .events
            .iter()
            .any(|e| matches!(e, Event::SrpClient(SrpEvent::Registered { .. })))
    });
    assert!(
        ok,
        "no registration (updates {}) events {:?}",
        reg.updates, net.nodes[1].events
    );
    assert_eq!(net.node(1).srp_server(), Some(server));
    assert_eq!(net.node(1).srp_host_state(), ItemState::Registered);
    assert_eq!(reg.bad_signatures, 0);
    assert_eq!(reg.updates, 1);
    assert_eq!(reg.host, "sed-one.default.service.arpa");
    assert_eq!(reg.addr, Some(net.node(1).ml_eid()));
    assert_eq!(reg.port, 5540);
    assert_eq!(reg.txt, txt);

    // Node 2 resolves the instance through the server.
    net.with(2, |n, now| {
        n.dns_resolve_service(INSTANCE, SERVICE, Some(QueryConfig::new(server)), now)
            .unwrap();
    });
    let ok = net.run_until(secs(120), |n| {
        serve(n, sock, &mut reg, &mut queries);
        n.nodes[2]
            .events
            .iter()
            .any(|e| matches!(e, Event::DnsResult(_)))
    });
    assert!(ok, "no DNS result (queries {queries})");
    let (_, out) = net.node(2).dns_take_result().unwrap();
    let DnsOutcome::Service(s) = out else {
        panic!("unexpected result {out:?}");
    };
    assert_eq!(s.port, 5540);
    assert_eq!(s.txt.as_slice(), txt.as_slice());
    assert_eq!(s.addrs[0].addr, net.node(1).ml_eid());
    let _: Instant = net.now;
}

/// A Matter node needs one operational service per fabric (at least five)
/// plus the commissionable service.
#[test]
fn srp_client_has_slots_for_five_fabrics_and_the_commissionable_service() {
    const _: () = assert!(opentrust_instance::SRP_SERVICES >= 6);
    let mut net = Network::new(&[Kind::Router], 5);
    net.with(0, |n, now| {
        for i in 0..opentrust_instance::SRP_SERVICES {
            let name = format!("{:016X}-{:016X}", 0x1111_u64 + i as u64, 2u64);
            let cfg = ServiceConfig::new("_matter._tcp", &name, 5540).unwrap();
            n.srp_add_service(cfg, now).unwrap();
        }
        let cfg =
            ServiceConfig::new("_matter._tcp", "FFFFFFFFFFFFFFFF-0000000000000002", 5540).unwrap();
        assert!(n.srp_add_service(cfg, now).is_err());
    });
}
