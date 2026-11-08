use super::*;
use crate::header::{OPT_PADN, PROTO_HOP_OPTS};
use crate::icmp6::*;
use opentrust_core::types::{ExtAddress, Iid, Prefix64};
use std::vec::Vec;

const MLP: Prefix64 = Prefix64([0xfd, 0xde, 0xad, 0x00, 0xbe, 0xef, 0x00, 0x00]);

struct Script(Vec<u32>, usize);
impl rand_core::TryRng for Script {
    type Error = core::convert::Infallible;
    fn try_next_u32(&mut self) -> core::result::Result<u32, Self::Error> {
        let v = self.0[self.1 % self.0.len()];
        self.1 += 1;
        Ok(v)
    }
    fn try_next_u64(&mut self) -> core::result::Result<u64, Self::Error> {
        Ok(u64::from(self.try_next_u32()?))
    }
    fn try_fill_bytes(&mut self, d: &mut [u8]) -> core::result::Result<(), Self::Error> {
        d.fill(0);
        Ok(())
    }
}

struct Env {
    role: Role,
    route: Option<Rloc16>,
    on_mesh: bool,
    sleepy: bool,
}

impl Env {
    const ROUTER: Env = Env {
        role: Role::Router,
        route: None,
        on_mesh: false,
        sleepy: false,
    };
}

impl Ip6Env for Env {
    fn role(&self) -> Role {
        self.role
    }
    fn route_lookup(&self, _: &Ipv6Addr, _: &Ipv6Addr) -> Option<Rloc16> {
        self.route
    }
    fn is_on_mesh(&self, _: &Ipv6Addr) -> bool {
        self.on_mesh
    }
    fn has_sleepy_child_with_address(&self, _: &Ipv6Addr) -> bool {
        self.sleepy
    }
}

fn node(rloc16: u16) -> Ip6 {
    let mut ip = Ip6::new();
    let n = &mut ip.netif;
    n.set_link_local(&ExtAddress([
        2,
        0,
        0,
        0,
        0,
        0,
        (rloc16 >> 8) as u8,
        rloc16 as u8,
    ]))
    .unwrap();
    n.set_mesh_local_prefix(MLP).unwrap();
    n.set_mesh_local_eid(&Iid([
        0xaa,
        0,
        0,
        0,
        0,
        0,
        (rloc16 >> 8) as u8,
        rloc16 as u8,
    ]))
    .unwrap();
    n.set_rloc16(Some(Rloc16(rloc16))).unwrap();
    n.subscribe_all_nodes();
    ip
}

fn eid(ip: &Ip6) -> Ipv6Addr {
    ip.netif.mesh_local_eid().unwrap()
}

fn udp(src_port: u16, dst_port: u16, data: &[u8]) -> Vec<u8> {
    let mut v = std::vec![0u8; 8 + data.len()];
    UdpHeader {
        src_port,
        dst_port,
        length: (8 + data.len()) as u16,
        checksum: 0,
    }
    .write(&mut v)
    .unwrap();
    v[8..].copy_from_slice(data);
    v
}

fn rng() -> Script {
    Script(std::vec![0], 0)
}

/// Run `f` with a context at time `t` ms.
fn ctx_run<T>(
    t: u64,
    env: &Env,
    rng: &mut Script,
    f: impl FnOnce(&mut Ctx<'_, Script, Env>) -> T,
) -> T {
    let mut c = Ctx {
        now: Instant::from_millis(t),
        rng,
        env,
    };
    f(&mut c)
}

fn handle(
    ip: &mut Ip6,
    env: &Env,
    meta: RxMeta,
    d: &mut [u8],
    s: &mut Scratch,
) -> Result<RxOutcome> {
    ctx_run(0, env, &mut rng(), |c| ip.handle(c, meta, d, s))
}

fn echo_request(src: &Ipv6Addr, dst: &Ipv6Addr, id: u16, seq: u16, data: &[u8]) -> Vec<u8> {
    let mut b = std::vec![0u8; 200];
    let n = build_echo_request(src, dst, 64, id, seq, data, &mut b).unwrap();
    b.truncate(n);
    b
}

const HOST_UNTRUSTED: RxMeta = RxMeta {
    origin: Origin::HostUntrusted,
    link_security: true,
    multicast_loop: false,
};

#[test]
fn echo_responder_unicast() {
    let mut ip = node(0x0400);
    let peer = MLP.with_iid(&Iid([9; 8]));
    let mut req = echo_request(&peer, &eid(&ip), 0x1234, 7, b"ping!");
    let mut s = Scratch::new();
    let o = handle(
        &mut ip,
        &Env::ROUTER,
        RxMeta::thread(true),
        &mut req,
        &mut s,
    )
    .unwrap();
    let d = o.deliver.unwrap();
    assert_eq!(
        (d.proto, d.src, d.dst, d.link_security),
        (PROTO_ICMP6, peer, eid(&ip), true)
    );
    assert!(!o.forward_thread && !o.forward_host);
    let r = o.reply(&s).unwrap();
    let h = Ipv6Header::parse(r).unwrap();
    assert_eq!(
        (h.src, h.dst, h.hop_limit),
        (eid(&ip), peer, DEFAULT_HOP_LIMIT)
    );
    let i = Icmp6Header::parse(&r[40..]).unwrap();
    assert_eq!(
        (i.ty, i.echo_id(), i.echo_seq()),
        (TYPE_ECHO_REPLY, 0x1234, 7)
    );
    assert_eq!(&r[48..], b"ping!");
    assert!(checksum::verify(&h.src, &h.dst, PROTO_ICMP6, &r[40..]));
    assert_eq!(d.bytes(&req, &s).len(), 8 + 5);
}

#[test]
fn echo_modes() {
    let peer = MLP.with_iid(&Iid([9; 8]));
    let mut s = Scratch::new();
    for (mode, uni, multi, rloc) in [
        (EchoMode::Disabled, false, false, false),
        (EchoMode::UnicastOnly, true, false, true),
        (EchoMode::MulticastOnly, false, true, false),
        (EchoMode::All, true, true, true),
        (EchoMode::RlocAlocOnly, false, false, true),
    ] {
        let mut ip = node(0x0400);
        ip.echo_mode = mode;
        let rloc_addr = ip.netif.rloc().unwrap();
        for (dst, expect) in [
            (eid(&ip), uni),
            (ipv6::REALM_LOCAL_ALL_NODES, multi),
            (rloc_addr, rloc),
        ] {
            let mut req = echo_request(&peer, &dst, 1, 1, b"x");
            let o = handle(
                &mut ip,
                &Env::ROUTER,
                RxMeta::thread(true),
                &mut req,
                &mut s,
            )
            .unwrap();
            assert_eq!(o.reply_len.is_some(), expect, "{mode:?} {dst}");
        }
    }
}

#[test]
fn echo_to_multicast_replies_from_selected_source() {
    let mut ip = node(0x0400);
    let peer = MLP.with_iid(&Iid([9; 8]));
    let mut req = echo_request(&peer, &ipv6::REALM_LOCAL_ALL_NODES, 1, 2, b"");
    let mut s = Scratch::new();
    let o = handle(
        &mut ip,
        &Env::ROUTER,
        RxMeta::thread(true),
        &mut req,
        &mut s,
    )
    .unwrap();
    let h = Ipv6Header::parse(o.reply(&s).unwrap()).unwrap();
    assert_eq!((h.src, h.dst), (eid(&ip), peer));
    // Multicast from the Thread netif is not forwarded by IPv6 (MPL does that).
    assert!(!o.forward_thread);
    assert!(o.forward_host);
}

#[test]
fn bad_checksum_and_bad_udp_not_delivered() {
    let mut ip = node(0x0400);
    let peer = MLP.with_iid(&Iid([9; 8]));
    let mut s = Scratch::new();
    let mut req = echo_request(&peer, &eid(&ip), 1, 1, b"abc");
    req[45] ^= 0x10;
    let o = handle(
        &mut ip,
        &Env::ROUTER,
        RxMeta::thread(true),
        &mut req,
        &mut s,
    )
    .unwrap();
    assert!(o.deliver.is_none() && o.reply_len.is_none());

    let mut out = [0u8; 1280];
    let mut r = rng();
    let info = SendInfo {
        src: Some(peer),
        ..SendInfo::new(eid(&ip))
    };
    let mut sender = node(0x0800);
    sender
        .netif
        .add_unicast(crate::netif::UnicastAddress::manual(peer))
        .unwrap();
    let so = ctx_run(0, &Env::ROUTER, &mut r, |c| {
        sender.send(
            c,
            &info,
            PROTO_UDP,
            &udp(1000, 2000, b"hello"),
            &mut out,
            &mut s,
        )
    })
    .unwrap();
    let mut good = out[..so.len].to_vec();
    let o = handle(
        &mut ip,
        &Env::ROUTER,
        RxMeta::thread(true),
        &mut good,
        &mut s,
    )
    .unwrap();
    let d = o.deliver.unwrap();
    let bytes = d.bytes(&good, &s);
    assert_eq!(UdpHeader::parse(bytes).unwrap().dst_port, 2000);
    assert_eq!(&bytes[8..], b"hello");
    // Zero UDP checksum is invalid on IPv6.
    let mut z = out[..so.len].to_vec();
    z[40 + 6] = 0;
    z[40 + 7] = 0;
    let o = handle(&mut ip, &Env::ROUTER, RxMeta::thread(true), &mut z, &mut s).unwrap();
    assert!(o.deliver.is_none());
    // Corrupt UDP length.
    let mut z = out[..so.len].to_vec();
    z[40 + 5] += 1;
    let o = handle(&mut ip, &Env::ROUTER, RxMeta::thread(true), &mut z, &mut s).unwrap();
    assert!(o.deliver.is_none());
}

#[test]
fn forwarding_decisions() {
    let mut ip = node(0x0400);
    let src = MLP.with_iid(&Iid([9; 8]));
    let other = MLP.rloc(Rloc16(0x0800));
    let mut s = Scratch::new();
    let mk = |dst: &Ipv6Addr| {
        let mut v = std::vec![0u8; 200];
        let n = build_echo_request(&src, dst, 10, 1, 1, b"", &mut v).unwrap();
        v.truncate(n);
        v
    };
    // Mesh-local unicast not ours: on-link via ML prefix -> forward, hop limit - 1.
    let mut d = mk(&other);
    let o = handle(&mut ip, &Env::ROUTER, RxMeta::thread(true), &mut d, &mut s).unwrap();
    assert!(o.forward_thread && !o.forward_host && o.deliver.is_none());
    assert_eq!(d[OFFSET_HOP_LIMIT], 9);
    // A child does not forward from Thread.
    let child = Env {
        role: Role::Child,
        ..Env::ROUTER
    };
    let mut d = mk(&other);
    let o = handle(&mut ip, &child, RxMeta::thread(true), &mut d, &mut s).unwrap();
    assert!(!o.forward_thread);
    assert_eq!(d[OFFSET_HOP_LIMIT], 10);
    // Hop limit 1 -> exhausted.
    let mut d = mk(&other);
    d[OFFSET_HOP_LIMIT] = 1;
    assert_eq!(
        handle(&mut ip, &Env::ROUTER, RxMeta::thread(true), &mut d, &mut s),
        Err(Error::Drop)
    );
    // Link-local destination from Thread: not forwarded; from host: forwarded.
    let ll: Ipv6Addr = "fe80::1234".parse().unwrap();
    let mut d = mk(&ll);
    let o = handle(&mut ip, &Env::ROUTER, RxMeta::thread(true), &mut d, &mut s).unwrap();
    assert!(!o.forward_thread);
    let o = handle(&mut ip, &Env::ROUTER, HOST_UNTRUSTED, &mut d, &mut s).unwrap();
    assert!(o.forward_thread);
    // Off-mesh destination: route lookup decides.
    let off: Ipv6Addr = "2001:db8::1".parse().unwrap();
    for (route, thread, hostfwd) in [
        (None, false, true),
        (Some(Rloc16(0x0400)), false, true),
        (Some(Rloc16(0x0c00)), true, false),
    ] {
        let env = Env {
            route,
            ..Env::ROUTER
        };
        let mut d = mk(&off);
        let o = handle(&mut ip, &env, RxMeta::thread(true), &mut d, &mut s).unwrap();
        assert_eq!(
            (o.forward_thread, o.forward_host),
            (thread, hostfwd),
            "{route:?}"
        );
    }
    // On-mesh prefix destination goes to Thread.
    let env = Env {
        on_mesh: true,
        ..Env::ROUTER
    };
    let mut d = mk(&off);
    let o = handle(&mut ip, &env, RxMeta::thread(true), &mut d, &mut s).unwrap();
    assert!(o.forward_thread);
}

#[test]
fn icmp_forward_filter_and_tmf_origin_filter() {
    let mut ip = node(0x0400);
    let src = MLP.with_iid(&Iid([9; 8]));
    let dst = MLP.rloc(Rloc16(0x0800));
    let mut s = Scratch::new();
    let mut v = std::vec![0u8; 200];
    let n = build_datagram(
        &src,
        &dst,
        10,
        &Icmp6Message {
            ty: TYPE_NEIGHBOR_SOLICIT,
            code: 0,
            data: [0; 4],
            body: &[0; 16],
        },
        &mut v,
    )
    .unwrap();
    assert_eq!(
        handle(
            &mut ip,
            &Env::ROUTER,
            RxMeta::thread(true),
            &mut v[..n],
            &mut s
        ),
        Err(Error::Drop)
    );
    // TMF from untrusted host is dropped, from trusted host forwarded.
    let mut out = [0u8; 1280];
    let mut ip2 = node(0x0800);
    let mut r = rng();
    let info = SendInfo::new(dst);
    let so = ctx_run(0, &Env::ROUTER, &mut r, |c| {
        ip2.send(
            c,
            &info,
            PROTO_UDP,
            &udp(1, TMF_UDP_PORT, b"x"),
            &mut out,
            &mut s,
        )
    })
    .unwrap();
    let mut d = out[..so.len].to_vec();
    assert_eq!(
        handle(&mut ip, &Env::ROUTER, HOST_UNTRUSTED, &mut d, &mut s),
        Err(Error::Drop)
    );
    let trusted = RxMeta {
        origin: Origin::HostTrusted,
        ..HOST_UNTRUSTED
    };
    let mut d = out[..so.len].to_vec();
    let o = handle(&mut ip, &Env::ROUTER, trusted, &mut d, &mut s).unwrap();
    assert!(o.forward_thread);
}

#[test]
fn loopback_routing_and_fragments_dropped() {
    let mut ip = node(0x0400);
    let mut s = Scratch::new();
    let mut d = echo_request(&Ipv6Addr::LOCALHOST, &eid(&ip), 1, 1, b"");
    assert_eq!(
        handle(&mut ip, &Env::ROUTER, RxMeta::thread(true), &mut d, &mut s),
        Err(Error::Drop)
    );
    let peer = MLP.with_iid(&Iid([9; 8]));
    // Routing header addressed to us.
    let mut v = std::vec![0u8; 100];
    let mut h = Ipv6Header::new(header::PROTO_ROUTING, 64, peer, eid(&ip));
    h.payload_len = 8;
    h.write(&mut v).unwrap();
    v[40] = PROTO_UDP;
    assert_eq!(
        handle(
            &mut ip,
            &Env::ROUTER,
            RxMeta::thread(true),
            &mut v[..48],
            &mut s
        ),
        Err(Error::Drop)
    );
    // Non-atomic fragment.
    let mut h = Ipv6Header::new(header::PROTO_FRAGMENT, 64, peer, eid(&ip));
    h.payload_len = 16;
    h.write(&mut v).unwrap();
    header::FragmentHeader {
        next_header: PROTO_UDP,
        offset: 0,
        more: true,
        id: 1,
    }
    .write(&mut v[40..])
    .unwrap();
    assert_eq!(
        handle(
            &mut ip,
            &Env::ROUTER,
            RxMeta::thread(true),
            &mut v[..56],
            &mut s
        ),
        Err(Error::Drop)
    );
    // Next header "none".
    let h = Ipv6Header::new(PROTO_NONE, 64, peer, eid(&ip));
    h.write(&mut v).unwrap();
    assert_eq!(
        handle(
            &mut ip,
            &Env::ROUTER,
            RxMeta::thread(true),
            &mut v[..40],
            &mut s
        ),
        Err(Error::Drop)
    );
}

/// Full MPL scenario with a deterministic RNG: node A originates a
/// realm-local multicast, node B (router) receives, delivers once,
/// suppresses the duplicate, and retransmits twice.
#[test]
fn mpl_end_to_end() {
    let mut a = node(0x0400);
    let mut b = node(0x0800);
    let mut s = Scratch::new();
    let mut out = [0u8; 1280];
    let dst: Ipv6Addr = "ff03::114".parse().unwrap();
    a.netif.subscribe_external(dst).unwrap();
    b.netif.subscribe_external(dst).unwrap();

    // A sends at t=1000 (script: first draw 10 -> first retx at +10ms).
    let mut ra = Script(std::vec![10, 0], 0);
    let info = SendInfo {
        multicast_loop: true,
        ..SendInfo::new(dst)
    };
    let so = ctx_run(1000, &Env::ROUTER, &mut ra, |c| {
        a.send(
            c,
            &info,
            PROTO_UDP,
            &udp(5000, 5001, b"mcast"),
            &mut out,
            &mut s,
        )
    })
    .unwrap();
    // Looped back locally and forwarded on the mesh.
    assert!(so.rx.deliver.is_some());
    assert!(so.rx.forward_thread);
    let p = header::parse_datagram(&out[..so.len]).unwrap();
    let mpl = p.mpl.unwrap();
    assert_eq!((mpl.seed_id, mpl.sequence), (0x0400, 0));
    assert_eq!(p.upper_proto, PROTO_UDP);
    let sent = out[..so.len].to_vec();

    // A will retransmit once (count starts at 1, router max 2).
    assert_eq!(a.next_deadline(), Some(Instant::from_millis(1010)));
    let mut buf = [0u8; 1280];
    let tx = ctx_run(1010, &Env::ROUTER, &mut ra, |c| a.poll(c, &mut buf)).unwrap();
    assert!(tx.retransmission);
    assert_eq!(&buf[..tx.len], &sent[..]);
    assert_eq!(
        ctx_run(1500, &Env::ROUTER, &mut ra, |c| a.poll(c, &mut buf)),
        None
    );

    // B receives the original from Thread: delivered, not forwarded by IPv6.
    let mut rb = Script(std::vec![30, 5], 0);
    let mut d = sent.clone();
    let o = ctx_run(1002, &Env::ROUTER, &mut rb, |c| {
        b.handle(c, RxMeta::thread(true), &mut d, &mut s)
    })
    .unwrap();
    let del = o.deliver.unwrap();
    assert_eq!(&del.bytes(&d, &s)[8..], b"mcast");
    assert!(!o.forward_thread);
    // Duplicate from Thread: dropped.
    let mut d = sent.clone();
    assert_eq!(
        ctx_run(1003, &Env::ROUTER, &mut rb, |c| b.handle(
            c,
            RxMeta::thread(true),
            &mut d,
            &mut s
        )),
        Err(Error::Drop)
    );
    // B's buffered copy: first tx at 1002+30, second at +(64-30)+5 later.
    assert_eq!(b.next_deadline(), Some(Instant::from_millis(1032)));
    let tx1 = ctx_run(1032, &Env::ROUTER, &mut rb, |c| b.poll(c, &mut buf)).unwrap();
    assert!(!tx1.retransmission);
    assert_eq!(buf[OFFSET_HOP_LIMIT], 63);
    assert_eq!(b.next_deadline(), Some(Instant::from_millis(1032 + 34 + 5)));
    assert_eq!(
        ctx_run(1070, &Env::ROUTER, &mut rb, |c| b.poll(c, &mut buf)),
        None
    );
    let tx2 = ctx_run(1071, &Env::ROUTER, &mut rb, |c| b.poll(c, &mut buf)).unwrap();
    assert!(tx2.retransmission);
    assert_eq!(
        ctx_run(2000, &Env::ROUTER, &mut rb, |c| b.poll(c, &mut buf)),
        None
    );
    // The retransmitted datagram fed back with host-trusted origin is
    // forwarded on the mesh and not delivered again.
    let mut again = buf[..tx2.len].to_vec();
    let host = RxMeta {
        origin: Origin::HostTrusted,
        link_security: true,
        multicast_loop: true,
    };
    let o = ctx_run(2001, &Env::ROUTER, &mut rb, |c| {
        b.handle(c, host, &mut again, &mut s)
    })
    .unwrap();
    assert!(o.forward_thread && o.deliver.is_none());
}

#[test]
fn tunnelled_larger_scope_multicast() {
    let mut a = node(0x0400);
    let mut b = node(0x0800);
    let mut s = Scratch::new();
    let mut out = [0u8; 1280];
    let dst: Ipv6Addr = "ff05::abcd".parse().unwrap();
    b.netif.subscribe_external(dst).unwrap();
    let mut r = rng();
    let info = SendInfo::new(dst);
    let so = ctx_run(0, &Env::ROUTER, &mut r, |c| {
        a.send(c, &info, PROTO_UDP, &udp(1, 2, b"tunnel"), &mut out, &mut s)
    })
    .unwrap();
    let p = header::parse_datagram(&out[..so.len]).unwrap();
    assert_eq!(p.header.dst, ipv6::REALM_LOCAL_ALL_MPL_FORWARDERS);
    assert_eq!(p.upper_proto, PROTO_IPV6);
    assert!(p.mpl.is_some());
    assert!(so.rx.forward_thread);
    // B receives the tunnel: inner datagram is delivered.
    let mut d = out[..so.len].to_vec();
    let o = handle(&mut b, &Env::ROUTER, RxMeta::thread(true), &mut d, &mut s).unwrap();
    let del = o.deliver.unwrap();
    assert!(del.from_inner);
    assert_eq!(del.dst, dst);
    assert_eq!(&del.bytes(&d, &s)[8..], b"tunnel");
    // A node that is not subscribed to the inner group delivers nothing.
    let mut c = node(0x0c00);
    let mut d = out[..so.len].to_vec();
    let o = handle(&mut c, &Env::ROUTER, RxMeta::thread(true), &mut d, &mut s).unwrap();
    assert!(o.deliver.is_none());
}

#[test]
fn insert_mpl_option_into_existing_hbh() {
    let mut a = node(0x0400);
    let src = eid(&a);
    let dst: Ipv6Addr = "ff03::114".parse().unwrap();
    let payload = udp(1, 2, b"hi");
    let mut buf = [0u8; 1280];
    // Datagram with an existing HBH (PadN only).
    let mut h = Ipv6Header::new(PROTO_HOP_OPTS, 64, src, dst);
    h.payload_len = (8 + payload.len()) as u16;
    h.write(&mut buf).unwrap();
    buf[40..48].copy_from_slice(&[PROTO_UDP, 0, OPT_PADN, 4, 0, 0, 0, 0]);
    buf[48..48 + payload.len()].copy_from_slice(&payload);
    checksum::update(&src, &dst, PROTO_UDP, &mut buf[48..48 + payload.len()]).unwrap();
    let len = 48 + payload.len();
    let n = a.insert_mpl_option(&mut buf, len).unwrap();
    assert_eq!(n, len + 8);
    let p = header::parse_datagram(&buf[..n]).unwrap();
    assert_eq!(p.upper_proto, PROTO_UDP);
    assert_eq!(p.upper_offset, 56);
    assert_eq!(p.mpl.unwrap().seed_id, 0x0400);
    assert_eq!(buf[41], 1);
    assert!(checksum::verify(&src, &dst, PROTO_UDP, &buf[56..n]));
    // Unicast and link-local multicast are untouched.
    let h2 = Ipv6Header::new(PROTO_UDP, 64, src, "ff02::1".parse().unwrap());
    h2.write(&mut buf).unwrap();
    assert_eq!(a.insert_mpl_option(&mut buf, 40).unwrap(), 40);
    // Realm-local multicast from the RLOC itself uses S=0.
    let rloc = a.netif.rloc().unwrap();
    let h3 = Ipv6Header::new(PROTO_UDP, 64, rloc, dst);
    h3.write(&mut buf).unwrap();
    let n = a.insert_mpl_option(&mut buf, 40).unwrap();
    assert_eq!(n, 48);
    let p = header::parse_datagram(&buf[..n]).unwrap();
    assert_eq!(p.mpl.unwrap().seed_id_len, header::MplSeedIdLen::Zero);
}

#[test]
fn send_to_self_and_errors() {
    let mut a = node(0x0400);
    let mut s = Scratch::new();
    let mut out = [0u8; 1280];
    let mut r = rng();
    let me = eid(&a);
    let so = ctx_run(0, &Env::ROUTER, &mut r, |c| {
        a.send(
            c,
            &SendInfo::new(me),
            PROTO_UDP,
            &udp(1, 2, b"self"),
            &mut out,
            &mut s,
        )
    })
    .unwrap();
    assert!(so.rx.deliver.is_some() && !so.rx.forward_thread && !so.rx.forward_host);
    // Oversized.
    let big = std::vec![0u8; 1300];
    assert_eq!(
        ctx_run(0, &Env::ROUTER, &mut r, |c| a.send(
            c,
            &SendInfo::new(me),
            PROTO_UDP,
            &big,
            &mut out,
            &mut s
        )),
        Err(Error::NoBufs)
    );
    // No source address available.
    let mut empty = Ip6::<2, 2, 4, 1>::new();
    let mut s2 = Scratch::new();
    let dst: Ipv6Addr = "fd00::1".parse().unwrap();
    assert_eq!(
        ctx_run(0, &Env::ROUTER, &mut r, |c| empty.send(
            c,
            &SendInfo::new(dst),
            PROTO_UDP,
            &udp(1, 2, b""),
            &mut out,
            &mut s2
        )),
        Err(Error::InvalidState)
    );
    // Explicit source honoured.
    let ll = a.netif.link_local().unwrap();
    let so = ctx_run(0, &Env::ROUTER, &mut r, |c| {
        a.send(
            c,
            &SendInfo {
                src: Some(ll),
                hop_limit: 1,
                dscp: 0x2a,
                ecn: 1,
                ..SendInfo::new("fe80::9".parse().unwrap())
            },
            PROTO_UDP,
            &udp(1, 2, b""),
            &mut out,
            &mut s,
        )
    })
    .unwrap();
    let h = Ipv6Header::parse(&out).unwrap();
    assert_eq!((h.hop_limit, h.dscp(), h.ecn(), h.src), (1, 0x2a, 1, ll));
    assert!(so.rx.forward_thread);
}

#[test]
fn icmp_error_rules_and_rate_limit() {
    let mut ip = node(0x0400);
    let me = eid(&ip);
    let peer = MLP.with_iid(&Iid([9; 8]));
    let mut out = [0u8; 1280];
    let t0 = Instant::from_millis(1000);
    let inv = echo_request(&peer, &me, 1, 1, b"data");
    let n = ip
        .build_error(
            t0,
            &inv,
            (TYPE_DST_UNREACH, CODE_DST_UNREACH_NO_ROUTE, 0),
            &mut out,
        )
        .unwrap();
    let h = Ipv6Header::parse(&out).unwrap();
    // Only the IPv6 header of the offender is quoted; reply from the original destination.
    assert_eq!(n, 40 + 8 + 40);
    assert_eq!((h.src, h.dst), (me, peer));
    assert!(checksum::verify(&h.src, &h.dst, PROTO_ICMP6, &out[40..n]));
    assert_eq!(&out[48..88], &inv[..40]);
    // Not in response to an ICMPv6 error.
    let err_pkt = out[..n].to_vec();
    assert_eq!(
        ip.build_error(t0, &err_pkt, (TYPE_DST_UNREACH, 0, 0), &mut out),
        Err(Error::Drop)
    );
    // Not for multicast destinations (but Packet Too Big is).
    let mc = echo_request(&peer, &ipv6::REALM_LOCAL_ALL_NODES, 1, 1, b"");
    assert_eq!(
        ip.build_error(t0, &mc, (TYPE_DST_UNREACH, 0, 0), &mut out),
        Err(Error::Drop)
    );
    assert!(
        ip.build_error(t0, &mc, (TYPE_PACKET_TOO_BIG, 0, 1280), &mut out)
            .is_ok()
    );
    // Not for multicast / unspecified sources.
    let bad = echo_request(&Ipv6Addr::UNSPECIFIED, &me, 1, 1, b"");
    assert_eq!(
        ip.build_error(t0, &bad, (TYPE_DST_UNREACH, 0, 0), &mut out),
        Err(Error::Drop)
    );
    let bad = echo_request(&"ff03::1".parse().unwrap(), &me, 1, 1, b"");
    assert_eq!(
        ip.build_error(t0, &bad, (TYPE_DST_UNREACH, 0, 0), &mut out),
        Err(Error::Drop)
    );
    // Rate limit: one token used for the first error and one for PTB.
    let mut ok = 0;
    for _ in 0..20 {
        if ip
            .build_error(t0, &inv, (TYPE_DST_UNREACH, 0, 0), &mut out)
            .is_ok()
        {
            ok += 1;
        }
    }
    assert_eq!(ok, usize::from(ERROR_BURST) - 2);
    // One token returns after the refill interval.
    let t1 = t0.saturating_add(ERROR_REFILL);
    assert!(
        ip.build_error(t1, &inv, (TYPE_DST_UNREACH, 0, 0), &mut out)
            .is_ok()
    );
    assert_eq!(
        ip.build_error(t1, &inv, (TYPE_DST_UNREACH, 0, 0), &mut out),
        Err(Error::Drop)
    );
}

#[test]
fn sleepy_child_forwarding_of_larger_scope_multicast() {
    let mut ip = node(0x0400);
    let mut s = Scratch::new();
    let src = MLP.with_iid(&Iid([9; 8]));
    let dst: Ipv6Addr = "ff05::1".parse().unwrap();
    let mut v = std::vec![0u8; 200];
    let n = build_echo_request(&src, &dst, 10, 1, 1, b"", &mut v).unwrap();
    let env = Env {
        sleepy: true,
        ..Env::ROUTER
    };
    let o = handle(&mut ip, &env, RxMeta::thread(true), &mut v[..n], &mut s).unwrap();
    assert!(o.forward_thread);
    assert_eq!(v[OFFSET_HOP_LIMIT], 9);
    let o = handle(
        &mut ip,
        &Env::ROUTER,
        RxMeta::thread(true),
        &mut v[..n],
        &mut s,
    )
    .unwrap();
    assert!(!o.forward_thread);
}

#[test]
fn truncation_and_corruption_never_panic() {
    let mut a = node(0x0400);
    let mut b = node(0x0800);
    let mut s = Scratch::new();
    let mut out = [0u8; 1280];
    let mut r = rng();
    let dst: Ipv6Addr = "ff05::7".parse().unwrap();
    b.netif.subscribe_external(dst).unwrap();
    let so = ctx_run(0, &Env::ROUTER, &mut r, |c| {
        a.send(
            c,
            &SendInfo::new(dst),
            PROTO_UDP,
            &udp(1, 2, b"abcdefgh"),
            &mut out,
            &mut s,
        )
    })
    .unwrap();
    let good = out[..so.len].to_vec();
    for len in 0..good.len() {
        let mut d = good[..len].to_vec();
        let mut bb = b.clone();
        let _ = handle(&mut bb, &Env::ROUTER, RxMeta::thread(true), &mut d, &mut s);
    }
    for i in 0..good.len() {
        for bit in 0..8 {
            let mut d = good.clone();
            d[i] ^= 1 << bit;
            let mut bb = b.clone();
            let _ = handle(&mut bb, &Env::ROUTER, RxMeta::thread(true), &mut d, &mut s);
        }
    }
    // build_error on garbage.
    for len in 0..60 {
        let _ = a.build_error(
            Instant::ZERO,
            &good[..len.min(good.len())],
            (TYPE_DST_UNREACH, 0, 0),
            &mut out,
        );
    }
}
