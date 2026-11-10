//! A minimal fake SRP / DNS-SD server on a node's UDP socket (port 53),
//! published in the Network Data so the SRP client auto-starts. It accepts
//! every update (the SIG(0) check is covered by the opentrust-sim tests) and
//! answers service-instance resolution queries from what was registered.

use core::cell::RefCell;
use core::net::{Ipv6Addr, SocketAddrV6};

use opentrust_dns::wire::{Header, Parser, Writer, class, opcode, rcode, rtype};
use opentrust_embassy::UdpSocket;
use opentrust_instance::DnsSrpService;
use opentrust_sim::testing::Ot;

/// One registered service instance.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Instance {
    /// Full name, e.g. `ABCD._matterc._udp.default.service.arpa`.
    pub name: String,
    pub port: u16,
    pub txt: Vec<u8>,
    /// Subtype PTR owner names pointing at this instance.
    pub subtypes: Vec<String>,
}

#[derive(Debug, Default)]
pub struct Registered {
    pub host: String,
    pub addrs: Vec<Ipv6Addr>,
    pub instances: Vec<Instance>,
    pub updates: usize,
    pub queries: usize,
}

impl Registered {
    pub fn instance(&self, prefix: &str) -> Option<&Instance> {
        self.instances.iter().find(|i| {
            i.name
                .to_ascii_uppercase()
                .starts_with(&prefix.to_ascii_uppercase())
        })
    }
}

fn dotted(n: &opentrust_dns::wire::Name<'_>) -> String {
    let mut s = String::new();
    n.fmt_dotted(&mut s).unwrap();
    s
}

fn handle_update(msg: &[u8], reg: &mut Registered) -> Vec<u8> {
    let (mut p, h) = Parser::new(msg).unwrap();
    let _ = p.question().unwrap();
    reg.updates += 1;
    let mut removed: Vec<String> = Vec::new();
    for _ in 0..h.ns {
        let r = p.record().unwrap();
        let name = dotted(&r.name);
        match r.rtype {
            rtype::AAAA => {
                reg.host = name;
                let a = r.aaaa().unwrap();
                if !reg.addrs.contains(&a) {
                    reg.addrs.push(a);
                }
            }
            rtype::SRV => {
                let srv = r.srv().unwrap();
                let inst = match reg.instances.iter_mut().find(|i| i.name == name) {
                    Some(i) => i,
                    None => {
                        reg.instances.push(Instance {
                            name: name.clone(),
                            ..Default::default()
                        });
                        reg.instances.last_mut().unwrap()
                    }
                };
                inst.port = srv.port;
            }
            rtype::TXT => {
                if let Some(i) = reg.instances.iter_mut().find(|i| i.name == name) {
                    i.txt = r.rdata.to_vec();
                }
            }
            rtype::PTR => {
                let target = dotted(&r.ptr().unwrap());
                if r.ttl == 0 {
                    // Delete of the instance (class ANY / NONE, TTL 0).
                    removed.push(target);
                } else if name.contains("._sub.") {
                    let inst = match reg.instances.iter_mut().find(|i| i.name == target) {
                        Some(i) => i,
                        None => {
                            reg.instances.push(Instance {
                                name: target.clone(),
                                ..Default::default()
                            });
                            reg.instances.last_mut().unwrap()
                        }
                    };
                    if !inst.subtypes.contains(&name) {
                        inst.subtypes.push(name);
                    }
                }
            }
            _ => {}
        }
    }
    for name in removed {
        reg.instances.retain(|i| i.name != name);
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
        rcode: rcode::SUCCESS,
        ar: 1,
        ..Header::default()
    });
    w.as_bytes().to_vec()
}

fn handle_query(msg: &[u8], reg: &mut Registered) -> Vec<u8> {
    reg.queries += 1;
    let (mut p, h) = Parser::new(msg).unwrap();
    let q = p.question().unwrap();
    let qname = dotted(&q.name);
    let mut buf = [0u8; 1024];
    let mut w = Writer::new(&mut buf).unwrap();
    for _ in 0..h.qd {
        w.write_question(&qname, q.qtype, q.qclass).unwrap();
    }
    let mut an = 0;
    let mut ar = 0;
    let found = reg
        .instances
        .iter()
        .find(|i| i.name.eq_ignore_ascii_case(&qname))
        .cloned();
    if let Some(inst) = &found {
        w.write_name(&inst.name).unwrap();
        let m = w.begin_record(rtype::SRV, class::IN, 120).unwrap();
        w.put_u16(0).unwrap();
        w.put_u16(0).unwrap();
        w.put_u16(inst.port).unwrap();
        w.write_name(&reg.host).unwrap();
        w.end_record(m).unwrap();
        an += 1;
        w.write_name(&inst.name).unwrap();
        let m = w.begin_record(rtype::TXT, class::IN, 120).unwrap();
        w.put(&inst.txt).unwrap();
        w.end_record(m).unwrap();
        an += 1;
        for a in &reg.addrs {
            w.write_name(&reg.host).unwrap();
            w.write_aaaa(120, a).unwrap();
            ar += 1;
        }
    }
    w.set_header(&Header {
        id: h.id,
        response: true,
        opcode: opcode::QUERY,
        rd: h.rd,
        ra: true,
        rcode: if found.is_some() {
            rcode::SUCCESS
        } else {
            rcode::NAME_ERROR
        },
        qd: h.qd,
        an,
        ar,
        ..Header::default()
    });
    w.as_bytes().to_vec()
}

/// Serve SRP updates and DNS queries on `ot` (port 53) forever; publishes
/// the server in the Network Data first (unicast, ML-EID).
pub async fn serve(ot: Ot<'_, '_>, reg: &RefCell<Registered>) {
    let sock = UdpSocket::bind(ot, SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 53, 0, 0)).unwrap();
    ot.with(|i, now| {
        i.publish_dns_srp_service(
            DnsSrpService::UnicastMlEid {
                port: 53,
                version: 0,
            },
            now,
        );
    });
    let mut buf = [0u8; 1280];
    loop {
        let (n, local, peer) = sock.recv(&mut buf).await.unwrap();
        let msg = buf[..n].to_vec();
        let Ok((_, h)) = Parser::new(&msg) else {
            continue;
        };
        let rsp = {
            let mut r = reg.borrow_mut();
            if h.opcode == opcode::UPDATE {
                handle_update(&msg, &mut r)
            } else {
                handle_query(&msg, &mut r)
            }
        };
        sock.send(&rsp, Some(*local.ip()), peer).await.unwrap();
    }
}
