//! Joiner Router relay and Joiner Entrust.

use core::net::Ipv6Addr;
use std::vec::Vec;

use opentrust_coap::endpoint::Peer;
use opentrust_coap::message::{Code, Message, MessageBuilder, Type};
use opentrust_coap::tmf::{Agent, UdpSink};
use opentrust_core::bytes::Writer;
use opentrust_core::time::{Duration, Instant};
use opentrust_core::types::{
    ExtAddress, ExtPanId, Iid, Kek, NetworkKey, NetworkName, Prefix64, Pskc, Rloc16, ipv6,
};
use opentrust_core::{Error, Result};
use opentrust_mle::test_support::MLP;
use opentrust_net::ip6::SendInfo;

use crate::dataset::Dataset;
use crate::joiner_router::{
    ENTRUST_TLVS, JOINER_ENTRUST_TX_DELAY, JoinerRouter, JoinerRouterEvent, JoinerRouterIo,
};
use crate::secure::LinkSecurity;
use crate::steering::SteeringData;
use crate::test_rng::TestRng;
use crate::timestamp::Timestamp;
use crate::tlv::{SecurityPolicy, Tlvs, WriterExt, ty};

#[derive(Default)]
struct Io {
    port: Option<u16>,
    port_changes: u32,
    unsecured: Vec<(u16, Peer, Vec<u8>)>,
    kek: Option<Kek>,
    kek_sent: Vec<(Peer, Kek, Vec<u8>)>,
}

impl JoinerRouterIo for Io {
    fn set_joiner_port(&mut self, port: Option<u16>) {
        self.port = port;
        self.port_changes += 1;
    }
    fn send_unsecured(&mut self, src_port: u16, dst: &Peer, payload: &[u8]) -> Result<()> {
        self.unsecured.push((src_port, *dst, payload.to_vec()));
        Ok(())
    }
    fn set_kek(&mut self, kek: Option<&Kek>) {
        self.kek = kek.cloned();
    }
    fn send_kek(&mut self, src_port: u16, dst: &Peer, payload: &[u8]) -> Result<()> {
        assert_eq!(src_port, 61631);
        let kek = self
            .kek
            .clone()
            .expect("KEK installed before a mode 0 frame");
        self.kek_sent.push((*dst, kek, payload.to_vec()));
        Ok(())
    }
}

#[derive(Default)]
struct Sink {
    out: Vec<(SendInfo, u16, Vec<u8>)>,
}

impl UdpSink for Sink {
    fn send(&mut self, info: &SendInfo, _sp: u16, dp: u16, payload: &[u8]) -> Result<()> {
        self.out.push((*info, dp, payload.to_vec()));
        Ok(())
    }
}

fn cd(steering: bool, port: Option<u16>) -> Vec<u8> {
    let mut b = [0u8; 64];
    let mut w = Writer::new(&mut b);
    w.border_agent_locator(0x0400).unwrap();
    w.commissioner_session_id(7).unwrap();
    let mut s = SteeringData::new(1);
    if steering {
        s.set_permit_all();
    }
    w.steering_data(&s).unwrap();
    if let Some(p) = port {
        w.joiner_udp_port(p).unwrap();
    }
    w.written().to_vec()
}

fn active() -> Dataset {
    let mut d = Dataset::new();
    d.set_network_key(&NetworkKey([0x42; 16])).unwrap();
    d.set_mesh_local_prefix(&MLP).unwrap();
    d.set_ext_pan_id(&ExtPanId([0xde; 8])).unwrap();
    d.set_network_name(&NetworkName::new("OpenTrust").unwrap())
        .unwrap();
    d.set_timestamp(
        crate::dataset::DatasetType::Active,
        &Timestamp {
            seconds: 1,
            ticks: 0,
            authoritative: false,
        },
    )
    .unwrap();
    d.set_channel_mask(0x07ff_f800).unwrap();
    d.set_pskc(&Pskc([0x11; 16])).unwrap();
    d.set_security_policy(&SecurityPolicy::default()).unwrap();
    d.set_channel(15).unwrap();
    d.set_pan_id(0x1234).unwrap();
    d
}

const JOINER: ExtAddress = ExtAddress([0x02, 0xaa, 0, 0, 0, 0, 0, 1]);

fn joiner_ll() -> Ipv6Addr {
    ipv6::link_local(&JOINER)
}

fn relay_tx(kek: Option<&[u8]>) -> Vec<u8> {
    let mut b = [0u8; 128];
    let mut w = Writer::new(&mut b);
    w.joiner_udp_port(1000).unwrap();
    w.joiner_iid(&JOINER.to_iid()).unwrap();
    w.joiner_router_locator(0x0800).unwrap();
    if let Some(k) = kek {
        opentrust_core::tlv::write(&mut w, ty::JOINER_ROUTER_KEK, k).unwrap();
    }
    w.joiner_dtls_encapsulation(b"\x16\xfe\xfdrecords").unwrap();
    w.written().to_vec()
}

struct Fx {
    jr: JoinerRouter,
    io: Io,
    now: Instant,
    rng: TestRng,
}

impl Fx {
    fn open() -> Self {
        let mut fx = Self {
            jr: JoinerRouter::new(),
            io: Io::default(),
            now: Instant::from_secs(5),
            rng: TestRng(3),
        };
        fx.jr.update(true, Some(&cd(true, None)), &mut fx.io);
        assert_eq!(fx.io.port, Some(1000));
        fx
    }

    fn poll(&mut self, ds: Option<&Dataset>) -> Option<JoinerRouterEvent> {
        self.jr.poll(self.now, &mut self.rng, &mut self.io, ds, 3)
    }
}

#[test]
fn joiner_port_follows_commissioning_data() {
    let mut jr = JoinerRouter::new();
    let mut io = Io::default();
    jr.update(true, None, &mut io);
    assert_eq!((io.port, io.port_changes), (None, 0));
    // Empty Steering Data: joining not allowed.
    jr.update(true, Some(&cd(false, Some(1234))), &mut io);
    assert_eq!(io.port, None);
    jr.update(true, Some(&cd(true, Some(1234))), &mut io);
    assert_eq!((io.port, jr.open_port()), (Some(1234), Some(1234)));
    jr.update(true, Some(&cd(true, Some(1234))), &mut io);
    assert_eq!(io.port_changes, 1, "no churn");
    // Default port without a Joiner UDP Port TLV, a configured port wins.
    jr.update(true, Some(&cd(true, None)), &mut io);
    assert_eq!(io.port, Some(1000));
    jr.set_joiner_udp_port(4321);
    jr.update(true, Some(&cd(true, Some(1234))), &mut io);
    assert_eq!(io.port, Some(4321));
    // Not an FTD, or joining no longer allowed: closed.
    jr.update(false, Some(&cd(true, None)), &mut io);
    assert_eq!(io.port, None);
    jr.update(true, Some(&cd(true, None)), &mut io);
    jr.update(true, Some(&cd(false, None)), &mut io);
    assert_eq!((io.port, jr.open_port()), (None, None));
}

#[test]
fn relay_rx_to_border_agent() {
    let mut fx = Fx::open();
    let mut agent: Agent<2, 2, 2, 1280> = Agent::new(1);
    let mut sink = Sink::default();
    let src = Peer::new(joiner_ll(), 1000);
    let records = [0x16u8; 300];
    let own = Rloc16(0x0800);
    let mut relay = |jr: &mut JoinerRouter, src: &Peer, port: u16, ba: Option<u16>| {
        jr.handle_joiner_datagram(
            &mut agent,
            fx.now,
            &mut fx.rng,
            &mut sink,
            &MLP,
            own,
            ba,
            src,
            port,
            &records,
        )
    };
    assert_eq!(
        relay(&mut fx.jr, &src, 1001, Some(0x0400)),
        Err(Error::Drop)
    );
    let off_link = Peer::new(MLP.rloc(Rloc16(0x0c00)), 1000);
    assert_eq!(
        relay(&mut fx.jr, &off_link, 1000, Some(0x0400)),
        Err(Error::Drop),
        "only link-local Joiners are relayed"
    );
    assert_eq!(relay(&mut fx.jr, &src, 1000, None), Err(Error::NotFound));
    relay(&mut fx.jr, &src, 1000, Some(0x0400)).unwrap();
    assert_eq!(sink.out.len(), 1);
    let (info, dp, msg) = &sink.out[0];
    assert_eq!(*dp, 61631);
    assert_eq!(info.dst, MLP.rloc(Rloc16(0x0400)));
    assert_eq!(info.src, Some(MLP.rloc(own)));
    assert!(info.link_security);
    let m = Message::parse(msg).unwrap();
    assert_eq!((m.ty(), m.code()), (Type::Non, Code::POST));
    assert!(m.uri_path_is("c/rx"));
    let t = Tlvs(m.payload());
    assert_eq!(t.joiner_udp_port(), Ok(1000));
    assert_eq!(t.joiner_iid(), Ok(JOINER.to_iid()));
    assert_eq!(t.joiner_router_locator(), Ok(0x0800));
    assert_eq!(t.joiner_dtls_encapsulation(), Ok(&records[..]));
    // OT writes the encapsulation as an extended TLV.
    let pos = m
        .payload()
        .windows(2)
        .position(|w| w == [ty::JOINER_DTLS_ENCAPSULATION, 0xff])
        .unwrap();
    assert_eq!(&m.payload()[pos + 2..pos + 4], &300u16.to_be_bytes());
}

#[test]
fn relay_tx_and_joiner_entrust() {
    let mut fx = Fx::open();
    let ds = active();
    // Relay Transmit without KEK: only the records go out, unsecured.
    fx.jr
        .handle_relay_tx(fx.now, &mut fx.io, false, &relay_tx(None))
        .unwrap();
    let (sp, dst, rec) = fx.io.unsecured.pop().unwrap();
    assert_eq!((sp, dst), (1000, Peer::new(joiner_ll(), 1000)));
    assert_eq!(rec, b"\x16\xfe\xfdrecords");
    fx.now += Duration::from_secs(1);
    assert_eq!(fx.poll(Some(&ds)), None);
    assert!(fx.io.kek_sent.is_empty());

    // A confirmable Relay Transmit is dropped (OT).
    assert_eq!(
        fx.jr
            .handle_relay_tx(fx.now, &mut fx.io, true, &relay_tx(None)),
        Err(Error::Drop)
    );
    // A malformed KEK TLV is an error; no Joiner Entrust.
    assert_eq!(
        fx.jr
            .handle_relay_tx(fx.now, &mut fx.io, false, &relay_tx(Some(&[7; 15]))),
        Err(Error::Parse)
    );
    assert_eq!(fx.jr.next_deadline(), None);

    // With the KEK: Joiner Entrust 50 ms later, under the KEK.
    let kek = [0x5a; 16];
    fx.jr
        .handle_relay_tx(fx.now, &mut fx.io, false, &relay_tx(Some(&kek)))
        .unwrap();
    assert_eq!(
        fx.jr.next_deadline(),
        Some(fx.now + JOINER_ENTRUST_TX_DELAY)
    );
    fx.now += Duration::from_millis(49);
    assert_eq!(fx.poll(Some(&ds)), None);
    fx.now += Duration::from_millis(1);
    assert_eq!(
        fx.poll(Some(&ds)),
        Some(JoinerRouterEvent::EntrustSent(joiner_ll()))
    );
    let (dst, used, msg) = fx.io.kek_sent.pop().unwrap();
    assert_eq!(dst, Peer::new(joiner_ll(), 61631));
    assert_eq!(used, Kek(kek));
    let m = Message::parse(&msg).unwrap();
    assert_eq!((m.ty(), m.code()), (Type::Con, Code::POST));
    assert!(m.uri_path_is("c/je"));
    let t = Tlvs(m.payload());
    for want in ENTRUST_TLVS {
        assert_eq!(t.value(want), ds.tlvs().value(want), "TLV {want}");
    }
    assert_eq!(t.network_key_sequence(), Ok(3));
    assert!(!t.contains(ty::CHANNEL) && !t.contains(ty::PAN_ID));

    // A response under the network key does not count; under the KEK it
    // does, and the KEK is discarded.
    let mut b = [0u8; 32];
    let n = MessageBuilder::new(&mut b, Type::Ack, Code::CHANGED, m.message_id(), m.token())
        .unwrap()
        .finish()
        .unwrap();
    let from = Peer::new(joiner_ll(), 61631);
    let me = ipv6::link_local(&ExtAddress([2, 0, 0, 0, 0, 0, 0, 9]));
    assert_eq!(
        fx.jr.handle_kek_datagram(
            fx.now,
            &mut fx.io,
            LinkSecurity::Network,
            &from,
            &me,
            &b[..n]
        ),
        None
    );
    assert!(fx.io.kek.is_some());
    assert_eq!(
        fx.jr
            .handle_kek_datagram(fx.now, &mut fx.io, LinkSecurity::Kek, &from, &me, &b[..n]),
        Some(JoinerRouterEvent::EntrustAcknowledged(joiner_ll()))
    );
    assert!(fx.io.kek.is_none());
    assert_eq!(fx.jr.next_deadline(), None);
}

/// Unanswered Joiner Entrust: retransmitted under the KEK (CoAP), then
/// timed out and the KEK discarded; a second queued Joiner Entrust waits
/// for its turn.
#[test]
fn joiner_entrust_timeout_and_queue() {
    let mut fx = Fx::open();
    let ds = active();
    fx.jr
        .handle_relay_tx(fx.now, &mut fx.io, false, &relay_tx(Some(&[1; 16])))
        .unwrap();
    let mut second = relay_tx(Some(&[2; 16]));
    // Another Joiner.
    let other = ExtAddress([0x02, 0xbb, 0, 0, 0, 0, 0, 2]);
    let pos = second
        .windows(10)
        .position(|w| w[..2] == [ty::JOINER_IID, 8])
        .unwrap();
    second[pos + 2..pos + 10].copy_from_slice(&other.to_iid().0);
    fx.jr
        .handle_relay_tx(fx.now, &mut fx.io, false, &second)
        .unwrap();
    // Full queue.
    assert_eq!(
        fx.jr
            .handle_relay_tx(fx.now, &mut fx.io, false, &relay_tx(Some(&[3; 16]))),
        Err(Error::NoBufs)
    );
    let mut events = Vec::new();
    for _ in 0..5000 {
        fx.now += Duration::from_millis(50);
        if let Some(e) = fx.poll(Some(&ds)) {
            events.push(e);
        }
    }
    assert_eq!(
        events,
        [
            JoinerRouterEvent::EntrustSent(joiner_ll()),
            JoinerRouterEvent::EntrustTimeout(joiner_ll()),
            JoinerRouterEvent::EntrustSent(ipv6::link_local(&other)),
            JoinerRouterEvent::EntrustTimeout(ipv6::link_local(&other)),
        ]
    );
    // 1 + 4 retransmissions each, every one under its own KEK.
    assert_eq!(fx.io.kek_sent.len(), 10);
    assert!(
        fx.io.kek_sent[..5]
            .iter()
            .all(|(_, k, _)| *k == Kek([1; 16]))
    );
    assert!(
        fx.io.kek_sent[5..]
            .iter()
            .all(|(_, k, _)| *k == Kek([2; 16]))
    );
    assert!(fx.io.kek.is_none());
}

/// A Joiner Entrust needs a complete Active Dataset; a response without a
/// Joiner Entrust in flight is ignored.
#[test]
fn joiner_entrust_needs_dataset_and_kek() {
    let mut fx = Fx::open();
    let from = Peer::new(joiner_ll(), 61631);
    let me = ipv6::link_local(&ExtAddress([2, 0, 0, 0, 0, 0, 0, 9]));
    assert_eq!(
        fx.jr.handle_kek_datagram(
            fx.now,
            &mut fx.io,
            LinkSecurity::Kek,
            &from,
            &me,
            &[0x60, 0x44, 0, 1]
        ),
        None
    );
    fx.jr
        .handle_relay_tx(fx.now, &mut fx.io, false, &relay_tx(Some(&[1; 16])))
        .unwrap();
    let mut partial = active();
    partial.remove(ty::PSKC);
    fx.now += Duration::from_millis(60);
    assert_eq!(fx.poll(Some(&partial)), None);
    assert!(fx.io.kek_sent.is_empty());
    assert!(fx.io.kek.is_none());
    let _ = Iid([0; 8]);
    let _: Prefix64 = MLP;
}
