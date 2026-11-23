//! TREL link: unicast / broadcast exchange between two nodes, acks and
//! their timeouts, filtering, and the secure round trip of an 802.15.4 frame
//! with the TREL key.

extern crate std;

use core::net::{Ipv6Addr, SocketAddrV6};
use std::vec::Vec;

use rs_thread_core::crypto::{SecurityLevel, SoftCrypto};
use rs_thread_core::time::{Duration, Instant};
use rs_thread_core::types::{ExtAddress, ExtPanId, NetworkKey, PanId};
use rs_thread_core::{Error, Result};
use rs_thread_mac::frame::{
    Address, Frame, FrameBuilder, FrameType, FrameVersion, KeyIdentifier, SecurityHeader,
};
use rs_thread_mac::frame_security::FrameSecurity;
use rs_thread_mac::security::KeyManager;

use super::*;

const PAN: u16 = 0xface;
const XPAN: ExtPanId = ExtPanId([0xab; 8]);
const A: ExtAddress = ExtAddress([0xa0; 8]);
const B: ExtAddress = ExtAddress([0xb0; 8]);
const CH: u8 = 15;

fn sock(n: u16) -> SocketAddrV6 {
    SocketAddrV6::new(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, n), 9000, 0, 0)
}

#[derive(Default)]
struct Plat {
    sent: Vec<(SocketAddrV6, Vec<u8>)>,
    enabled: Option<bool>,
    service: Option<(u16, Vec<u8>)>,
    fail: bool,
}

impl TrelPlatform for Plat {
    fn local_port(&self) -> u16 {
        9000
    }
    fn send(&mut self, dst: SocketAddrV6, packet: &[u8]) -> Result<()> {
        if self.fail {
            return Err(Error::Abort);
        }
        self.sent.push((dst, packet.to_vec()));
        Ok(())
    }
    fn set_enabled(&mut self, enabled: bool) {
        self.enabled = Some(enabled);
    }
    fn register_service(&mut self, port: u16, txt: &[u8]) {
        self.service = Some((port, txt.to_vec()));
    }
}

fn t(ms: u64) -> Instant {
    Instant::from_millis(ms)
}

/// Two enabled nodes that know each other; A at fd00::a, B at fd00::b.
fn pair() -> (Trel<4>, Plat, Trel<4>, Plat) {
    let mut a = Trel::<4>::new(A);
    let mut b = Trel::<4>::new(B);
    let (mut pa, mut pb) = (Plat::default(), Plat::default());
    for (n, p) in [(&mut a, &mut pa), (&mut b, &mut pb)] {
        n.set_network(p, PAN, XPAN);
        n.set_rx_channel(CH);
        n.enable(p, t(0));
    }
    assert!(a.peer_discovered(B, XPAN, sock(0xb)).unwrap());
    assert!(b.peer_discovered(A, XPAN, sock(0xa)).unwrap());
    (a, pa, b, pb)
}

#[test]
fn enable_registers_the_service_and_filters_peers() {
    let mut a = Trel::<2>::new(A);
    let mut p = Plat::default();
    // Disabled: nothing is accepted.
    assert_eq!(a.peer_discovered(B, XPAN, sock(1)), Ok(false));
    a.set_network(&mut p, PAN, XPAN);
    a.enable(&mut p, t(0));
    assert_eq!(p.enabled, Some(true));
    let (port, txt) = p.service.clone().unwrap();
    assert_eq!(port, 9000);
    assert_eq!(parse_txt(&txt).unwrap(), (A, XPAN));
    // Ourselves, other networks: ignored.
    assert_eq!(a.peer_discovered(A, XPAN, sock(1)), Ok(false));
    assert_eq!(a.peer_discovered(B, ExtPanId([1; 8]), sock(1)), Ok(false));
    assert_eq!(a.peer_discovered(B, XPAN, sock(1)), Ok(true));
    // A new extended PAN ID re-registers and drops the peers.
    a.set_network(&mut p, PAN, ExtPanId([2; 8]));
    assert!(a.peers().is_empty());
    assert_eq!(
        parse_txt(&p.service.clone().unwrap().1).unwrap().1.0,
        [2; 8]
    );
    a.disable(&mut p);
    assert_eq!(p.enabled, Some(false));
    assert_eq!(
        a.transmit(&mut p, Dest::Broadcast, CH, PAN, &[1]),
        Err(Error::InvalidState)
    );
}

#[test]
fn unicast_is_delivered_and_acknowledged() {
    let (mut a, mut pa, mut b, mut pb) = pair();
    a.transmit(&mut pa, Dest::Unicast(B), CH, PAN, b"frame")
        .unwrap();
    assert_eq!(a.peers().find(&B).unwrap().pending_acks(), 1);
    let (to, pkt) = pa.sent.pop().unwrap();
    assert_eq!(to, sock(0xb));
    let rx = b.handle_received(&mut pb, &pkt, sock(0xa)).unwrap();
    assert_eq!(
        rx,
        Rx::Frame {
            source: A,
            sender: sock(0xa),
            channel: CH,
            broadcast: false,
            frame: b"frame",
        }
    );
    // B acknowledged to A's address.
    let (to, ack) = pb.sent.pop().unwrap();
    assert_eq!(to, sock(0xa));
    assert_eq!(
        a.handle_received(&mut pa, &ack, sock(0xb)),
        Ok(Rx::Ack { source: B })
    );
    assert_eq!(a.peers().find(&B).unwrap().pending_acks(), 0);
    // A second ack is not expected.
    assert_eq!(
        a.handle_received(&mut pa, &ack, sock(0xb)),
        Err(Error::Drop)
    );
    // Packet numbers count per peer.
    a.transmit(&mut pa, Dest::Unicast(B), CH, PAN, b"x")
        .unwrap();
    let (h, _) = Header::parse(&pa.sent[0].1).unwrap();
    assert_eq!(h.packet_number, 1);
    assert_eq!(
        a.transmit(&mut pa, Dest::Unicast(ExtAddress([9; 8])), CH, PAN, b"x"),
        Err(Error::NotFound)
    );
}

#[test]
fn broadcast_goes_to_all_peers_without_ack() {
    let (mut a, mut pa, mut b, mut pb) = pair();
    a.peer_discovered(ExtAddress([0xc0; 8]), XPAN, sock(0xc))
        .unwrap();
    a.transmit(&mut pa, Dest::Broadcast, CH, 0xffff, b"hello")
        .unwrap();
    assert_eq!(pa.sent.len(), 2);
    let to_b = pa.sent.iter().find(|(d, _)| *d == sock(0xb)).unwrap();
    let rx = b.handle_received(&mut pb, &to_b.1, sock(0xa)).unwrap();
    assert!(matches!(
        rx,
        Rx::Frame {
            broadcast: true,
            frame: b"hello",
            ..
        }
    ));
    assert!(pb.sent.is_empty(), "no ack for broadcast");
    // All sends failing is an error.
    pa.fail = true;
    assert_eq!(
        a.transmit(&mut pa, Dest::Broadcast, CH, PAN, b"x"),
        Err(Error::Abort)
    );
}

#[test]
fn packets_that_are_not_for_us_are_dropped() {
    let (mut a, mut pa, mut b, mut pb) = pair();
    a.transmit(&mut pa, Dest::Unicast(B), CH, PAN, b"f")
        .unwrap();
    let pkt = pa.sent.pop().unwrap().1;
    // Wrong channel (not an ack).
    b.set_rx_channel(CH + 1);
    assert_eq!(
        b.handle_received(&mut pb, &pkt, sock(0xa)),
        Err(Error::Drop)
    );
    b.set_rx_channel(CH);
    // Other PAN.
    b.set_network(&mut pb, 0x1234, XPAN);
    assert_eq!(
        b.handle_received(&mut pb, &pkt, sock(0xa)),
        Err(Error::Drop)
    );
    b.set_network(&mut pb, PAN, XPAN);
    // Addressed to someone else, own packet, garbage.
    let mut c = Trel::<4>::new(ExtAddress([0xc0; 8]));
    let mut pc = Plat::default();
    c.set_network(&mut pc, PAN, XPAN);
    c.set_rx_channel(CH);
    c.enable(&mut pc, t(0));
    assert_eq!(
        c.handle_received(&mut pc, &pkt, sock(0xa)),
        Err(Error::Drop)
    );
    assert_eq!(
        a.handle_received(&mut pa, &pkt, sock(0xa)),
        Err(Error::Drop)
    );
    assert_eq!(
        b.handle_received(&mut pb, &[0xff; 3], sock(0xa)),
        Err(Error::Parse)
    );
    // The right one still works.
    assert!(b.handle_received(&mut pb, &pkt, sock(0xa)).is_ok());
    // Verified frames update the peer's address.
    b.peer_address_verified(&A, sock(0x99));
    assert_eq!(b.peers().find(&A).unwrap().addr, sock(0x99));
}

#[test]
fn missing_acks_time_out_after_two_windows() {
    let (mut a, mut pa, mut b, mut pb) = pair();
    let mut events = Vec::new();
    // One acked, one lost.
    a.transmit(&mut pa, Dest::Unicast(B), CH, PAN, b"1")
        .unwrap();
    a.transmit(&mut pa, Dest::Unicast(B), CH, PAN, b"2")
        .unwrap();
    let first = pa.sent[0].1.clone();
    b.handle_received(&mut pb, &first, sock(0xa)).unwrap();
    let ack = pb.sent.pop().unwrap().1;
    a.handle_received(&mut pa, &ack, sock(0xb)).unwrap();
    assert_eq!(a.next_deadline(), Some(t(0) + ACK_WAIT_WINDOW));
    let w = ACK_WAIT_WINDOW;
    a.poll(t(0) + w, &mut |e| events.push(e));
    assert!(events.is_empty());
    a.poll(t(0) + w + w, &mut |e| events.push(e));
    assert_eq!(events, [Event::AckTimeout { peer: B }]);
    assert_eq!(a.peers().find(&B).unwrap().pending_acks(), 0);
    let _ = Duration::ZERO;
}

// ---------------------------------------------------------------- security

const NK: NetworkKey = NetworkKey([0x11; 16]);

fn data_frame(payload: &[u8]) -> Vec<u8> {
    let mut buf = [0u8; 127];
    let n = FrameBuilder::new(&mut buf)
        .frame_type(FrameType::Data)
        .version(FrameVersion::V2006)
        .sequence(7)
        .pan_id(PanId(PAN))
        .dst(Address::Extended(B))
        .src(Address::Extended(A))
        .ack_request(true)
        .security(SecurityHeader::new(
            SecurityLevel::EncMic32,
            0,
            KeyIdentifier::Index(1),
        ))
        .payload(payload)
        .build()
        .unwrap();
    buf[..n].to_vec()
}

#[test]
fn secure_round_trip_over_the_link() {
    let (mut a, mut pa, mut b, mut pb) = pair();
    let mut sa = TrelSecurity::new(SoftCrypto, NK, 5, 100);
    let mut sb = TrelSecurity::new(SoftCrypto, NK, 5, 0);
    let mut frame = data_frame(b"secret payload");
    sa.secure_tx(&mut frame, &A).unwrap();
    // Encrypted on the wire, counter and key index set.
    assert!(!frame.windows(14).any(|w| w == b"secret payload"));
    let f = Frame::parse(&frame).unwrap();
    let s = f.security_header().unwrap();
    assert_eq!(s.frame_counter, Some(100));
    assert_eq!(s.key, KeyIdentifier::Index(6));
    assert_eq!(sa.frame_counter(), 101);

    a.transmit(&mut pa, Dest::Unicast(B), CH, PAN, &frame)
        .unwrap();
    let pkt = pa.sent.pop().unwrap().1;
    let Rx::Frame {
        source, frame: rxf, ..
    } = b.handle_received(&mut pb, &pkt, sock(0xa)).unwrap()
    else {
        panic!("frame expected");
    };
    let mut rxf = rxf.to_vec();
    let info = sb.unsecure_rx(&mut rxf, &source).unwrap().unwrap();
    assert_eq!(info.frame_counter, 100);
    assert_eq!(info.key_sequence, Some(5));
    assert_eq!(info.level, SecurityLevel::EncMic32);
    assert_eq!(Frame::parse(&rxf).unwrap().payload(), b"secret payload");

    // Tampering is detected and the plaintext not exposed.
    let mut bad = frame.clone();
    let last = bad.len() - 1;
    bad[last] ^= 1;
    assert_eq!(sb.unsecure_rx(&mut bad, &A), Err(Error::Security));
    // The normal MAC key does not open a TREL frame.
    let mut km = KeyManager::new(SoftCrypto, NK);
    let mut other = frame.clone();
    assert_eq!(km.unsecure_rx(&mut other, &A), Err(Error::Security));
    // Another network key does not either.
    let mut sc = TrelSecurity::new(SoftCrypto, NetworkKey([0x22; 16]), 5, 0);
    assert_eq!(sc.unsecure_rx(&mut frame.clone(), &A), Err(Error::Security));
}

#[test]
fn key_sequence_changes_are_followed_one_step() {
    let mut sa = TrelSecurity::new(SoftCrypto, NK, 6, 0);
    let mut old = TrelSecurity::new(SoftCrypto, NK, 5, 0);
    let mut f = data_frame(b"x");
    sa.secure_tx(&mut f, &A).unwrap();
    // A receiver one sequence behind still accepts the next key ...
    let info = old.unsecure_rx(&mut f.clone(), &A).unwrap().unwrap();
    assert_eq!(info.key_sequence, Some(6));
    // ... and one ahead the previous one.
    let mut cur = TrelSecurity::new(SoftCrypto, NK, 7, 0);
    assert_eq!(
        cur.unsecure_rx(&mut f.clone(), &A)
            .unwrap()
            .unwrap()
            .key_sequence,
        Some(6)
    );
    // Two sequences away is unknown.
    let mut far = TrelSecurity::new(SoftCrypto, NK, 8, 0);
    assert_eq!(far.unsecure_rx(&mut f.clone(), &A), Err(Error::Security));
    far.set_key_sequence(6);
    assert!(far.unsecure_rx(&mut f, &A).is_ok());
    // Unsecured frames pass through untouched.
    let mut plain = [0u8; 127];
    let n = FrameBuilder::new(&mut plain)
        .frame_type(FrameType::Data)
        .version(FrameVersion::V2006)
        .sequence(1)
        .pan_id(PanId(PAN))
        .dst(Address::Extended(B))
        .src(Address::Extended(A))
        .build()
        .unwrap();
    assert_eq!(far.unsecure_rx(&mut plain[..n], &A), Ok(None));
    assert_eq!(far.secure_tx(&mut plain[..n], &A), Ok(()));
}
