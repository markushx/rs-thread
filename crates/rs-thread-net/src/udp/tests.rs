use super::*;
use crate::ip6::{Ctx, Ip6, Ip6Env, RxMeta, Scratch};
use crate::mpl::Role;
use rs_thread_core::time::Instant;
use rs_thread_core::types::{ExtAddress, Iid, Prefix64, Rloc16};
use std::vec::Vec;

type Socks = UdpSockets<3, 2, 64, 3>;

const MLP: Prefix64 = Prefix64([0xfd, 0xde, 0xad, 0x00, 0xbe, 0xef, 0x00, 0x00]);

fn netif(id: u8) -> Netif<8, 8> {
    let mut n = Netif::new();
    n.set_link_local(&ExtAddress([2, 0, 0, 0, 0, 0, 0, id]))
        .unwrap();
    n.set_mesh_local_prefix(MLP).unwrap();
    n.set_mesh_local_eid(&Iid([0xaa, 0, 0, 0, 0, 0, 0, id]))
        .unwrap();
    n.set_rloc16(Some(Rloc16(u16::from(id) << 10))).unwrap();
    n.subscribe_all_nodes();
    n
}

fn a(s: &str) -> Ipv6Addr {
    s.parse().unwrap()
}

fn sa(ip: Ipv6Addr, port: u16) -> SocketAddrV6 {
    SocketAddrV6::new(ip, port, 0, 0)
}

fn dgram(
    src: Ipv6Addr,
    src_port: u16,
    dst: Ipv6Addr,
    dst_port: u16,
    data: &[u8],
) -> (UdpRxInfo, Vec<u8>) {
    let mut v = std::vec![0u8; 8 + data.len()];
    UdpHeader {
        src_port,
        dst_port,
        length: (8 + data.len()) as u16,
        checksum: 0x1234,
    }
    .write(&mut v)
    .unwrap();
    v[8..].copy_from_slice(data);
    (
        UdpRxInfo {
            src,
            dst,
            hop_limit: 63,
            ecn: 0,
            link_security: true,
        },
        v,
    )
}

#[test]
fn ephemeral_ports_follow_ot() {
    let n = netif(1);
    let mut s = Socks::new();
    let h = s.open().unwrap();
    s.bind(h, sa(Ipv6Addr::UNSPECIFIED, 0), &n).unwrap();
    // OT increments before use: first port is Min + 1.
    assert_eq!(s.local_addr(h).unwrap().port(), EPHEMERAL_PORT_MIN + 1);
    let h2 = s.open().unwrap();
    s.bind(h2, sa(Ipv6Addr::UNSPECIFIED, 0), &n).unwrap();
    assert_eq!(s.local_addr(h2).unwrap().port(), EPHEMERAL_PORT_MIN + 2);
    // Wrap-around.
    s.next_ephemeral = EPHEMERAL_PORT_MAX;
    let h3 = s.open().unwrap();
    s.bind(h3, sa(Ipv6Addr::UNSPECIFIED, 0), &n).unwrap();
    assert_eq!(s.local_addr(h3).unwrap().port(), EPHEMERAL_PORT_MIN);
}

#[test]
fn ephemeral_skips_reserved_and_used_ports() {
    let n = netif(1);
    let mut s = Socks::new();
    s.next_ephemeral = SRP_SERVER_PORT_MIN - 1;
    let h = s.open().unwrap();
    s.bind(h, sa(Ipv6Addr::UNSPECIFIED, 0), &n).unwrap();
    assert_eq!(s.local_addr(h).unwrap().port(), SRP_SERVER_PORT_MAX + 1);
    // In-use port is skipped.
    s.next_ephemeral = SRP_SERVER_PORT_MAX;
    let h2 = s.open().unwrap();
    s.bind(h2, sa(Ipv6Addr::UNSPECIFIED, 0), &n).unwrap();
    assert_eq!(s.local_addr(h2).unwrap().port(), SRP_SERVER_PORT_MAX + 2);
}

#[test]
fn bind_rules() {
    let n = netif(1);
    let eid = n.mesh_local_eid().unwrap();
    let mut s = Socks::new();
    let h = s.open().unwrap();
    // Not one of our addresses.
    assert_eq!(
        s.bind(h, sa(a("2001:db8::1"), 5540), &n),
        Err(Error::InvalidArgs)
    );
    s.bind(h, sa(Ipv6Addr::UNSPECIFIED, 5540), &n).unwrap();
    // Wildcard clash and specific-vs-wildcard clash.
    let h2 = s.open().unwrap();
    assert_eq!(
        s.bind(h2, sa(Ipv6Addr::UNSPECIFIED, 5540), &n),
        Err(Error::Already)
    );
    assert_eq!(s.bind(h2, sa(eid, 5540), &n), Err(Error::Already));
    // Different port or disjoint specific addresses are fine.
    s.bind(h2, sa(eid, 5541), &n).unwrap();
    let h3 = s.open().unwrap();
    s.bind(h3, sa(n.link_local().unwrap(), 5541), &n).unwrap();
    // Receiver ports are taken.
    s.register_receiver(MLE_UDP_PORT, ReceiverId::MLE).unwrap();
    let mut t = Socks::new();
    t.register_receiver(MLE_UDP_PORT, ReceiverId::MLE).unwrap();
    let th = t.open().unwrap();
    assert_eq!(
        t.bind(th, sa(Ipv6Addr::UNSPECIFIED, MLE_UDP_PORT), &n),
        Err(Error::Already)
    );
    // Rebinding keeps the port but changes the address.
    s.bind(h2, sa(Ipv6Addr::UNSPECIFIED, 0), &n).unwrap();
    assert_eq!(s.local_addr(h2).unwrap().port(), 5541);
    // Table full / invalid handle.
    assert_eq!(s.open(), Err(Error::NoBufs));
    s.close(h3).unwrap();
    assert_eq!(s.close(h3), Err(Error::InvalidArgs));
    assert!(s.open().is_ok());
}

#[test]
fn matching_rules() {
    let n = netif(1);
    let eid = n.mesh_local_eid().unwrap();
    let peer = a("fd00::9");
    let mut s = Socks::new();
    let wild = s.open().unwrap();
    s.bind(wild, sa(Ipv6Addr::UNSPECIFIED, 1000), &n).unwrap();
    let specific = s.open().unwrap();
    s.bind(specific, sa(eid, 2000), &n).unwrap();
    let conn = s.open().unwrap();
    s.bind(conn, sa(Ipv6Addr::UNSPECIFIED, 3000), &n).unwrap();
    s.connect(conn, sa(peer, 4000), &n).unwrap();

    let (i, d) = dgram(peer, 7, eid, 1000, b"w");
    assert_eq!(s.handle_datagram(&i, &d), UdpRx::Queued(wild));
    // Specific local address only matches its own destination ...
    let (i, d) = dgram(peer, 7, eid, 2000, b"s");
    assert_eq!(s.handle_datagram(&i, &d), UdpRx::Queued(specific));
    let (i, d) = dgram(peer, 7, a("fd00::1"), 2000, b"x");
    assert_eq!(
        s.handle_datagram(&i, &d),
        UdpRx::Dropped(DropReason::NoSocket)
    );
    // ... but multicast matches any bound socket on the port.
    let (i, d) = dgram(peer, 7, a("ff03::1"), 2000, b"m");
    assert_eq!(s.handle_datagram(&i, &d), UdpRx::Queued(specific));
    // Connected: peer port and address must match.
    let (i, d) = dgram(peer, 4000, eid, 3000, b"c");
    assert_eq!(s.handle_datagram(&i, &d), UdpRx::Queued(conn));
    let (i, d) = dgram(peer, 4001, eid, 3000, b"c");
    assert_eq!(
        s.handle_datagram(&i, &d),
        UdpRx::Dropped(DropReason::NoSocket)
    );
    let (i, d) = dgram(a("fd00::a"), 4000, eid, 3000, b"c");
    assert_eq!(
        s.handle_datagram(&i, &d),
        UdpRx::Dropped(DropReason::NoSocket)
    );
    // Unbound sockets never match port 0.
    let (i, d) = dgram(peer, 7, eid, 0, b"z");
    assert_eq!(
        s.handle_datagram(&i, &d),
        UdpRx::Dropped(DropReason::NoSocket)
    );
}

#[test]
fn newest_socket_wins_on_overlap() {
    let n = netif(1);
    let eid = n.mesh_local_eid().unwrap();
    let peer = a("fd00::9");
    let mut s = Socks::new();
    let old = s.open().unwrap();
    s.bind(old, sa(eid, 1000), &n).unwrap();
    let new = s.open().unwrap();
    // Overlapping bindings cannot be created through the API; force one.
    s.sock_mut(new).unwrap().local = sa(Ipv6Addr::UNSPECIFIED, 1000);
    let (i, d) = dgram(peer, 7, eid, 1000, b"x");
    assert_eq!(s.handle_datagram(&i, &d), UdpRx::Queued(new));
}

#[test]
fn receive_queue_is_bounded_fifo_with_truncation() {
    let n = netif(1);
    let eid = n.mesh_local_eid().unwrap();
    let peer = a("fd00::9");
    let mut s = Socks::new();
    let h = s.open().unwrap();
    s.bind(h, sa(Ipv6Addr::UNSPECIFIED, 1000), &n).unwrap();
    assert_eq!(s.has_data(h), Ok(false));
    assert_eq!(s.recv(h, &mut [0; 8]), Ok(None));
    let e0 = s.rx_epoch();
    for (k, data) in [b"one".as_slice(), b"two", b"three"]
        .into_iter()
        .enumerate()
    {
        let (i, d) = dgram(peer, 7 + k as u16, eid, 1000, data);
        let r = s.handle_datagram(&i, &d);
        if k < 2 {
            assert_eq!(r, UdpRx::Queued(h));
        } else {
            assert_eq!(r, UdpRx::Dropped(DropReason::QueueFull));
        }
    }
    assert_ne!(s.rx_epoch(), e0);
    assert_eq!(s.dropped(h), Ok(1));
    assert_eq!(s.peek_len(h), Ok(Some(3)));
    let mut buf = [0u8; 2];
    let r = s.recv(h, &mut buf).unwrap().unwrap();
    assert_eq!((r.len, r.truncated, &buf[..]), (2, true, &b"on"[..]));
    assert_eq!(r.meta.peer, sa(peer, 7));
    assert_eq!(r.meta.local, sa(eid, 1000));
    assert_eq!((r.meta.hop_limit, r.meta.link_security), (63, true));
    let mut buf = [0u8; 8];
    let r = s.recv(h, &mut buf).unwrap().unwrap();
    assert_eq!(
        (&buf[..r.len], r.truncated, r.meta.peer.port()),
        (&b"two"[..], false, 8)
    );
    assert_eq!(s.recv(h, &mut buf), Ok(None));
    // Space again; wrap-around of the ring.
    for _ in 0..5 {
        let (i, d) = dgram(peer, 7, eid, 1000, b"z");
        assert_eq!(s.handle_datagram(&i, &d), UdpRx::Queued(h));
        assert!(s.recv(h, &mut buf).unwrap().is_some());
    }
    // Oversized payload is truncated at BUF (64) with the full length reported.
    let big = [7u8; 100];
    let (i, d) = dgram(peer, 7, eid, 1000, &big);
    s.handle_datagram(&i, &d);
    assert_eq!(s.peek_len(h), Ok(Some(100)));
    let mut b2 = [0u8; 200];
    let r = s.recv(h, &mut b2).unwrap().unwrap();
    assert_eq!((r.len, r.truncated), (64, true));
}

#[test]
fn receivers_take_precedence() {
    let n = netif(1);
    let eid = n.mesh_local_eid().unwrap();
    let mut s = Socks::new();
    s.register_receiver(TMF_UDP_PORT, ReceiverId::TMF).unwrap();
    s.register_receiver(MLE_UDP_PORT, ReceiverId::MLE).unwrap();
    assert_eq!(
        s.register_receiver(MLE_UDP_PORT, ReceiverId(9)),
        Err(Error::Already)
    );
    let (i, d) = dgram(a("fe80::2"), 19788, a("fe80::1"), MLE_UDP_PORT, b"mle!");
    match s.handle_datagram(&i, &d) {
        UdpRx::Receiver { id, meta, payload } => {
            assert_eq!(id, ReceiverId::MLE);
            assert_eq!(payload, b"mle!");
            assert_eq!(meta.peer.port(), 19788);
        }
        r => panic!("{r:?}"),
    }
    let _ = eid;
    s.unregister_receiver(ReceiverId::MLE).unwrap();
    assert_eq!(s.unregister_receiver(ReceiverId::MLE), Err(Error::NotFound));
    assert_eq!(
        s.handle_datagram(&i, &d),
        UdpRx::Dropped(DropReason::NoSocket)
    );
    for k in 0..3 {
        s.register_receiver(1000 + k, ReceiverId(10 + k as u8))
            .unwrap_or(());
    }
    assert_eq!(
        s.register_receiver(2000, ReceiverId(20)),
        Err(Error::NoBufs)
    );
}

#[test]
fn malformed_datagrams_never_panic() {
    let n = netif(1);
    let eid = n.mesh_local_eid().unwrap();
    let mut s = Socks::new();
    let h = s.open().unwrap();
    s.bind(h, sa(Ipv6Addr::UNSPECIFIED, 1000), &n).unwrap();
    let (i, d) = dgram(a("fd00::9"), 7, eid, 1000, b"hello");
    for len in 0..d.len() {
        assert_eq!(
            s.handle_datagram(&i, &d[..len]),
            UdpRx::Dropped(DropReason::Malformed)
        );
    }
    let mut bad = d.clone();
    bad[5] += 1;
    assert_eq!(
        s.handle_datagram(&i, &bad),
        UdpRx::Dropped(DropReason::Malformed)
    );
    for k in 0..d.len() {
        for bit in 0..8 {
            let mut x = d.clone();
            x[k] ^= 1 << bit;
            let _ = s.handle_datagram(&i, &x);
        }
    }
}

#[test]
fn build_send_rules() {
    let n = netif(1);
    let eid = n.mesh_local_eid().unwrap();
    let mut s = Socks::new();
    let h = s.open().unwrap();
    let mut out = [0u8; 100];
    let opts = UdpSendOpts::default();
    // No peer.
    assert_eq!(
        s.build_send(h, None, &opts, b"x", &mut out, &n)
            .unwrap_err(),
        Error::InvalidArgs
    );
    assert_eq!(
        s.build_send(h, Some(sa(a("fd00::9"), 0)), &opts, b"x", &mut out, &n)
            .unwrap_err(),
        Error::InvalidArgs
    );
    // Implicit bind to an ephemeral port; unspecified local -> auto source.
    let (info, len) = s
        .build_send(h, Some(sa(a("fd00::9"), 5540)), &opts, b"abc", &mut out, &n)
        .unwrap();
    assert_eq!(len, 11);
    let hdr = UdpHeader::parse(&out).unwrap();
    assert_eq!((hdr.dst_port, hdr.length, hdr.checksum), (5540, 11, 0));
    assert_eq!(hdr.src_port, s.local_addr(h).unwrap().port());
    assert_eq!((info.src, info.dst), (None, a("fd00::9")));
    assert_eq!(&out[8..11], b"abc");
    // Connected: defaults from the peer; specific local used as source.
    let h2 = s.open().unwrap();
    s.bind(h2, sa(eid, 1234), &n).unwrap();
    s.connect(h2, sa(a("fd00::7"), 4321), &n).unwrap();
    assert_eq!(s.peer_addr(h2).unwrap(), Some(sa(a("fd00::7"), 4321)));
    let (info, _) = s.build_send(h2, None, &opts, b"", &mut out, &n).unwrap();
    assert_eq!((info.src, info.dst), (Some(eid), a("fd00::7")));
    assert_eq!(UdpHeader::parse(&out).unwrap().dst_port, 4321);
    // Override source and options.
    let o = UdpSendOpts {
        hop_limit: 255,
        multicast_loop: true,
        link_security: false,
        dscp: 10,
        src: Some(a("fe80::1")),
    };
    let (info, _) = s
        .build_send(h2, Some(sa(a("ff03::1"), 9)), &o, b"", &mut out, &n)
        .unwrap();
    assert_eq!(
        (
            info.src,
            info.hop_limit,
            info.multicast_loop,
            info.link_security,
            info.dscp
        ),
        (Some(a("fe80::1")), 255, true, false, 10)
    );
    // Output too small.
    assert_eq!(
        s.build_send(h2, None, &opts, &[0; 200], &mut out, &n)
            .unwrap_err(),
        Error::NoBufs
    );
}

struct Env;
impl Ip6Env for Env {
    fn role(&self) -> Role {
        Role::Router
    }
    fn route_lookup(&self, _: &Ipv6Addr, _: &Ipv6Addr) -> Option<Rloc16> {
        None
    }
    fn is_on_mesh(&self, _: &Ipv6Addr) -> bool {
        false
    }
}

struct Zero;
impl rand_core::TryRng for Zero {
    type Error = core::convert::Infallible;
    fn try_next_u32(&mut self) -> core::result::Result<u32, Self::Error> {
        Ok(0)
    }
    fn try_next_u64(&mut self) -> core::result::Result<u64, Self::Error> {
        Ok(0)
    }
    fn try_fill_bytes(&mut self, d: &mut [u8]) -> core::result::Result<(), Self::Error> {
        d.fill(0);
        Ok(())
    }
}

fn ip6_node(id: u8) -> Ip6 {
    let mut ip = Ip6::new();
    ip.netif = netif(id);
    ip
}

/// Socket -> IPv6 send path -> IPv6 receive path -> socket, between two
/// nodes (unicast and realm-local multicast).
#[test]
fn end_to_end_between_two_nodes() {
    let (mut ipa, mut ipb) = (ip6_node(1), ip6_node(2));
    let (mut sa_, mut sb) = (Socks::new(), Socks::new());
    let mut scratch = Scratch::new();
    let mut out = [0u8; 1280];
    let mut rng = Zero;

    let hb = sb.open().unwrap();
    sb.bind(hb, sa(Ipv6Addr::UNSPECIFIED, 5540), &ipb.netif)
        .unwrap();
    let ha = sa_.open().unwrap();

    for dst_ip in [ipb.netif.mesh_local_eid().unwrap(), a("ff03::1")] {
        let mut payload = [0u8; 1280];
        let (info, n) = sa_
            .build_send(
                ha,
                Some(sa(dst_ip, 5540)),
                &UdpSendOpts::default(),
                b"matter",
                &mut payload,
                &ipa.netif,
            )
            .unwrap();
        let mut c = Ctx {
            now: Instant::from_millis(1),
            rng: &mut rng,
            env: &Env,
        };
        let so = ipa
            .send(
                &mut c,
                &info,
                UdpSockets::<1>::PROTO,
                &payload[..n],
                &mut out,
                &mut scratch,
            )
            .unwrap();
        assert!(so.rx.forward_thread, "{dst_ip}");
        let mut d = out[..so.len].to_vec();
        let mut c = Ctx {
            now: Instant::from_millis(2),
            rng: &mut rng,
            env: &Env,
        };
        let o = ipb
            .handle(&mut c, RxMeta::thread(true), &mut d, &mut scratch)
            .unwrap();
        let del = o.deliver.unwrap();
        let bytes = del.bytes(&d, &scratch).to_vec();
        assert_eq!(
            sb.handle_datagram(&UdpRxInfo::from(&del), &bytes),
            UdpRx::Queued(hb)
        );
        let mut buf = [0u8; 32];
        let r = sb.recv(hb, &mut buf).unwrap().unwrap();
        assert_eq!(&buf[..r.len], b"matter");
        assert_eq!(r.meta.peer.port(), sa_.local_addr(ha).unwrap().port());
        assert_eq!(*r.meta.peer.ip(), ipa.netif.mesh_local_eid().unwrap());
        assert_eq!(*r.meta.local.ip(), dst_ip);
    }
}
