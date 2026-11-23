use core::net::SocketAddrV6;

use rs_thread_core::crypto::SoftCrypto;
use rs_thread_core::types::{NetworkKey, Rloc16};
use rs_thread_net::header::UdpHeader;
use rs_thread_net::udp::{UdpRx, UdpSockets};

use super::*;
use crate::message::MleBuilder;

fn keys() -> KeyManager<SoftCrypto> {
    KeyManager::new(SoftCrypto, NetworkKey([0x42; 16]))
}

fn ll(n: u8) -> Ipv6Addr {
    Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, u16::from(n))
}

const ALL_NODES: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1);

#[derive(Default)]
struct Sink {
    sent: heapless::Vec<(SendInfo, u16, u16, heapless::Vec<u8, 128>), 4>,
}

impl UdpSink for Sink {
    fn send(
        &mut self,
        info: &SendInfo,
        src_port: u16,
        dst_port: u16,
        payload: &[u8],
    ) -> Result<()> {
        let v = heapless::Vec::from_slice(payload).map_err(|_| Error::NoBufs)?;
        self.sent
            .push((*info, src_port, dst_port, v))
            .map_err(|_| Error::NoBufs)
    }
}

#[derive(Default)]
struct Recorder {
    seen: heapless::Vec<(Command, Option<RxSecurity>, Ipv6Addr, bool), 8>,
    adverts: u32,
    sources: heapless::Vec<Rloc16, 8>,
}

impl MleHandler for Recorder {
    fn on_advertisement(&mut self, rx: &MleRx<'_>) {
        self.adverts += 1;
        self.sources
            .push(rx.tlvs.source_address().unwrap())
            .unwrap();
    }
    fn handle(&mut self, rx: &MleRx<'_>) {
        self.seen
            .push((
                rx.command,
                rx.meta.security,
                rx.meta.src,
                rx.meta.link_security,
            ))
            .unwrap();
        // Default dispatch afterwards.
        if rx.command == Command::Advertisement {
            self.on_advertisement(rx);
        }
    }
}

fn meta(src: Ipv6Addr, dst: Ipv6Addr, hop_limit: u8) -> UdpMeta {
    UdpMeta {
        peer: SocketAddrV6::new(src, MLE_UDP_PORT, 0, 0),
        local: SocketAddrV6::new(dst, MLE_UDP_PORT, 0, 0),
        hop_limit,
        ecn: 0,
        link_security: false,
    }
}

fn advertisement(
    keys: &KeyManager<SoftCrypto>,
    counter: &mut MleFrameCounter,
    sink: &mut Sink,
    src: Ipv6Addr,
    dst: Ipv6Addr,
) {
    let mut buf = [0u8; 128];
    let mut b = MleBuilder::new(&mut buf, Command::Advertisement).unwrap();
    b.tlvs().source_address(Rloc16(0x0800)).unwrap();
    let len = b.finish();
    send(
        keys,
        counter,
        sink,
        &TxInfo {
            src,
            dst,
            link_security: false,
        },
        &mut buf,
        len,
    )
    .unwrap();
}

#[test]
fn register_and_full_loopback_through_udp() {
    let k = keys();
    let mut udp = UdpSockets::<2>::new();
    register_receiver(&mut udp).unwrap();
    assert_eq!(register_receiver(&mut udp), Err(Error::Already));

    let mut counter = MleFrameCounter::new();
    let mut sink = Sink::default();
    advertisement(&k, &mut counter, &mut sink, ll(1), ALL_NODES);
    let (info, sp, dp, payload) = &sink.sent[0];
    assert_eq!((*sp, *dp), (19788, 19788));
    assert_eq!(info.hop_limit, 255);
    assert_eq!(info.src, Some(ll(1)));
    assert_eq!(info.dst, ALL_NODES);
    assert!(!info.link_security);

    // Wrap into UDP and run through the socket table as the stack would.
    let mut dgram = [0u8; 160];
    let total = UdpHeader::LEN + payload.len();
    UdpHeader {
        src_port: 19788,
        dst_port: 19788,
        length: total as u16,
        checksum: 0,
    }
    .write(&mut dgram)
    .unwrap();
    dgram[UdpHeader::LEN..total].copy_from_slice(payload);
    let rxinfo = rs_thread_net::udp::UdpRxInfo {
        src: ll(1),
        dst: ALL_NODES,
        hop_limit: 255,
        ecn: 0,
        link_security: false,
    };
    let UdpRx::Receiver { id, meta, payload } = udp.handle_datagram(&rxinfo, &dgram[..total])
    else {
        panic!("not claimed by the MLE receiver");
    };
    assert_eq!(id, RECEIVER_ID);

    let mut rec = Recorder::default();
    let mut scratch = [0u8; 128];
    let cmd = receive(
        &k,
        &meta,
        LinkRxInfo {
            rss: Some(-60),
            lqi: Some(200),
            ..Default::default()
        },
        payload,
        &mut scratch,
        &mut rec,
    )
    .unwrap();
    assert_eq!(cmd, Command::Advertisement);
    assert_eq!(rec.adverts, 1);
    assert_eq!(rec.sources.as_slice(), &[Rloc16(0x0800)]);
    let (_, sec, src, ls) = rec.seen[0];
    assert_eq!(
        sec,
        Some(RxSecurity {
            key_sequence: 0,
            frame_counter: 0
        })
    );
    assert_eq!(src, ll(1));
    assert!(!ls);

    unregister_receiver(&mut udp).unwrap();
    assert!(matches!(
        udp.handle_datagram(&rxinfo, &dgram[..total]),
        UdpRx::Dropped(_)
    ));
}

#[test]
fn parse_exposes_metadata_and_sender() {
    let k = keys();
    let mut counter = MleFrameCounter::new();
    counter.restore(77);
    let mut sink = Sink::default();
    advertisement(&k, &mut counter, &mut sink, ll(9), ll(2));
    let payload = &sink.sent[0].3;
    let mut scratch = [0u8; 128];
    let rx = MleRx::parse(
        &k,
        &meta(ll(9), ll(2), 255),
        LinkRxInfo {
            rss: Some(-70),
            lqi: Some(3),
            ..Default::default()
        },
        payload,
        &mut scratch,
    )
    .unwrap();
    assert_eq!(rx.meta.security.unwrap().frame_counter, 77);
    assert_eq!(rx.meta.link.rss, Some(-70));
    assert_eq!(rx.meta.link.lqi, Some(3));
    assert_eq!(rx.meta.src_port, 19788);
    // Sender ext address comes from the IID (U/L bit flipped).
    assert_eq!(
        rx.meta.sender_ext_address(),
        ipv6::iid(&ll(9)).to_ext_address()
    );
    assert_eq!(rx.command, Command::Advertisement);
}

#[test]
fn rx_validation() {
    let k = keys();
    let mut counter = MleFrameCounter::new();
    let mut sink = Sink::default();
    advertisement(&k, &mut counter, &mut sink, ll(1), ALL_NODES);
    let payload = sink.sent[0].3.clone();
    let mut scratch = [0u8; 128];
    let link = LinkRxInfo::default();
    let mut parse =
        |m: &UdpMeta, p: &[u8]| MleRx::parse(&k, m, link, p, &mut scratch).map(|r| r.command);

    assert!(parse(&meta(ll(1), ALL_NODES, 255), &payload).is_ok());
    // Hop limit.
    for hl in [0, 64, 254] {
        assert_eq!(
            parse(&meta(ll(1), ALL_NODES, hl), &payload),
            Err(Error::Parse)
        );
    }
    // Source must be link-local unicast.
    let ml = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1);
    assert_eq!(parse(&meta(ml, ALL_NODES, 255), &payload), Err(Error::Drop));
    assert_eq!(
        parse(&meta(ALL_NODES, ALL_NODES, 255), &payload),
        Err(Error::Drop)
    );
    // Destination: global unicast and larger-scope multicast are refused.
    assert_eq!(parse(&meta(ll(1), ml, 255), &payload), Err(Error::Drop));
    let site = Ipv6Addr::new(0xff05, 0, 0, 0, 0, 0, 0, 1);
    assert_eq!(parse(&meta(ll(1), site, 255), &payload), Err(Error::Drop));
    // Realm-local multicast is tolerated for rx (the AAD then differs, so
    // the MIC fails: addressing is authenticated).
    let rl = Ipv6Addr::new(0xff03, 0, 0, 0, 0, 0, 0, 1);
    assert_eq!(parse(&meta(ll(1), rl, 255), &payload), Err(Error::Security));
    // Wrong port.
    let mut m = meta(ll(1), ALL_NODES, 255);
    m.local = SocketAddrV6::new(ALL_NODES, 1234, 0, 0);
    assert_eq!(parse(&m, &payload), Err(Error::Drop));
    // Wrong source address (authenticated by the nonce / AAD).
    assert_eq!(
        parse(&meta(ll(2), ALL_NODES, 255), &payload),
        Err(Error::Security)
    );
    // Tampered payload and truncations never panic.
    for i in 0..payload.len() {
        let mut p = payload.clone();
        p[i] ^= 0x80;
        assert!(parse(&meta(ll(1), ALL_NODES, 255), &p).is_err(), "byte {i}");
    }
    for len in 0..payload.len() {
        assert!(parse(&meta(ll(1), ALL_NODES, 255), &payload[..len]).is_err());
    }
}

#[test]
fn scratch_too_small() {
    let k = keys();
    let mut counter = MleFrameCounter::new();
    let mut sink = Sink::default();
    advertisement(&k, &mut counter, &mut sink, ll(1), ALL_NODES);
    let mut tiny = [0u8; 4];
    assert_eq!(
        MleRx::parse(
            &k,
            &meta(ll(1), ALL_NODES, 255),
            LinkRxInfo::default(),
            &sink.sent[0].3,
            &mut tiny
        )
        .unwrap_err(),
        Error::NoBufs
    );
}

#[test]
fn tx_destination_rules() {
    let k = keys();
    let mut counter = MleFrameCounter::new();
    let mut sink = Sink::default();
    let mut build = |src: Ipv6Addr, dst: Ipv6Addr| {
        let mut buf = [0u8; 64];
        let mut b = MleBuilder::new(&mut buf, Command::Advertisement).unwrap();
        b.tlvs().source_address(Rloc16(1)).unwrap();
        let len = b.finish();
        send(
            &k,
            &mut counter,
            &mut sink,
            &TxInfo {
                src,
                dst,
                link_security: false,
            },
            &mut buf,
            len,
        )
    };
    assert!(build(ll(1), ll(2)).is_ok());
    assert!(build(ll(1), Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 2)).is_ok());
    // Realm-local multicast, mesh-local unicast, global: refused.
    assert_eq!(
        build(ll(1), Ipv6Addr::new(0xff03, 0, 0, 0, 0, 0, 0, 2)),
        Err(Error::InvalidArgs)
    );
    assert_eq!(
        build(ll(1), Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2)),
        Err(Error::InvalidArgs)
    );
    // Source must be link-local.
    assert_eq!(
        build(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1), ll(2)),
        Err(Error::InvalidArgs)
    );
    // Refused sends do not consume a counter value.
    assert_eq!(counter.current(), 2);
}

#[test]
fn discovery_goes_unsecured_and_dispatches() {
    let k = keys();
    let mut counter = MleFrameCounter::new();
    let mut sink = Sink::default();
    let mut buf = [0u8; 64];
    let mut b = MleBuilder::new(&mut buf, Command::DiscoveryRequest).unwrap();
    b.tlvs().discovery(&[0x80, 0x02, 0x00, 0x00]).unwrap();
    let len = b.finish();
    send(
        &k,
        &mut counter,
        &mut sink,
        &TxInfo {
            src: ll(1),
            dst: ALL_NODES,
            link_security: false,
        },
        &mut buf,
        len,
    )
    .unwrap();
    assert_eq!(counter.current(), 0);
    let mut rec = Recorder::default();
    let mut scratch = [0u8; 64];
    let cmd = receive(
        &k,
        &meta(ll(1), ALL_NODES, 255),
        LinkRxInfo::default(),
        &sink.sent[0].3,
        &mut scratch,
        &mut rec,
    )
    .unwrap();
    assert_eq!(cmd, Command::DiscoveryRequest);
    assert_eq!(rec.seen[0].1, None, "no security metadata for suite 255");
}

#[test]
fn every_command_reaches_its_handler_method() {
    use core::sync::atomic::{AtomicU32, Ordering};
    static HITS: AtomicU32 = AtomicU32::new(0);

    struct One;
    impl MleHandler for One {
        fn on_link_request(&mut self, _: &MleRx<'_>) {
            HITS.fetch_or(1 << 0, Ordering::Relaxed);
        }
        fn on_parent_response(&mut self, _: &MleRx<'_>) {
            HITS.fetch_or(1 << 10, Ordering::Relaxed);
        }
        fn on_link_probe(&mut self, _: &MleRx<'_>) {
            HITS.fetch_or(1 << 20, Ordering::Relaxed);
        }
    }
    let mut h = One;
    for v in 0..=255u8 {
        if let Some(command) = Command::from_u8(v) {
            let rx = MleRx {
                meta: RxMeta {
                    src: ll(1),
                    dst: ll(2),
                    src_port: 19788,
                    link_security: false,
                    security: None,
                    link: LinkRxInfo::default(),
                },
                command,
                tlvs: Tlvs::new(&[]),
            };
            h.handle(&rx);
        }
    }
    assert_eq!(HITS.load(Ordering::Relaxed), 1 | 1 << 10 | 1 << 20);
}
