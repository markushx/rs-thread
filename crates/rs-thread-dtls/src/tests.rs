//! In-memory client/server tests of the DTLS session.

use std::vec::Vec;

use rs_thread_core::crypto::SoftCrypto;
use rs_thread_core::crypto::ecjpake::SoftP256;
use rs_thread_core::time::{Duration, Instant};

use crate::record::{self, CT_APPLICATION_DATA, CT_HANDSHAKE};
use crate::*;

/// Deterministic xorshift RNG (tests only).
pub(crate) struct TestRng(pub u64);

impl rand_core::TryRng for TestRng {
    type Error = core::convert::Infallible;
    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        Ok(self.try_next_u64()? as u32)
    }
    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        Ok(x)
    }
    fn try_fill_bytes(&mut self, out: &mut [u8]) -> Result<(), Self::Error> {
        for c in out.chunks_mut(8) {
            let v = self.try_next_u64()?.to_le_bytes();
            c.copy_from_slice(&v[..c.len()]);
        }
        Ok(())
    }
}

impl rand_core::TryCryptoRng for TestRng {}

pub(crate) type Dtls = Session<SoftCrypto, SoftP256>;

const PSKD: &[u8] = b"J01NME";
const CLIENT_ID: &[u8] = &[
    0xfe, 0x80, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 0x4d, 0x4c,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Dir {
    ToServer,
    ToClient,
}

struct Pair {
    c: Dtls,
    s: Dtls,
    now: Instant,
    rng: TestRng,
    /// All datagrams sent so far, in order.
    log: Vec<(Dir, Vec<u8>)>,
    /// Application data received by (client, server).
    app: (Vec<Vec<u8>>, Vec<Vec<u8>>),
}

impl Pair {
    fn new(client_pw: &[u8], server_pw: &[u8], cfg: Config) -> Self {
        let mut rng = TestRng(0x1234_5678_9abc_def1);
        let now = Instant::from_secs(1000);
        let c = Dtls::client(SoftCrypto, SoftP256, client_pw, cfg, now, &mut rng).unwrap();
        let s = Dtls::server(SoftCrypto, SoftP256, server_pw, cfg, CLIENT_ID, &mut rng).unwrap();
        Self {
            c,
            s,
            now,
            rng,
            log: Vec::new(),
            app: (Vec::new(), Vec::new()),
        }
    }

    fn drain(&mut self, dir: Dir) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        let mut buf = [0u8; 1500];
        let sess = match dir {
            Dir::ToServer => &mut self.c,
            Dir::ToClient => &mut self.s,
        };
        while let Some(n) = sess.poll_transmit(&mut buf) {
            out.push(buf[..n].to_vec());
            self.log.push((dir, buf[..n].to_vec()));
        }
        out
    }

    fn deliver(&mut self, dir: Dir, d: &[u8]) {
        let mut app = [0u8; 1024];
        let (sess, sink) = match dir {
            Dir::ToServer => (&mut self.s, &mut self.app.1),
            Dir::ToClient => (&mut self.c, &mut self.app.0),
        };
        let mut rest = d;
        loop {
            let r = sess
                .handle_datagram(self.now, &mut self.rng, rest, &mut app)
                .unwrap();
            if let Some(n) = r.app_data {
                sink.push(app[..n].to_vec());
            }
            rest = &rest[r.consumed..];
            if rest.is_empty() || r.app_data.is_none() {
                break;
            }
        }
    }

    /// Exchange datagrams until both sides are quiet; `keep(dir, index,
    /// datagram)` decides whether a datagram is delivered.
    fn pump(&mut self, mut keep: impl FnMut(Dir, usize, &[u8]) -> bool) {
        let mut idx = 0;
        for _ in 0..50 {
            let mut any = false;
            for dir in [Dir::ToServer, Dir::ToClient] {
                for d in self.drain(dir) {
                    any = true;
                    if keep(dir, idx, &d) {
                        self.deliver(dir, &d);
                    }
                    idx += 1;
                }
            }
            if !any {
                return;
            }
        }
        panic!("no quiescence");
    }

    /// Advance time to the next timer of either side and fire it.
    fn tick(&mut self) -> bool {
        let next = [self.c.next_timeout(), self.s.next_timeout()]
            .into_iter()
            .flatten()
            .min();
        let Some(t) = next else { return false };
        self.now = t;
        self.c.handle_timeout(t);
        self.s.handle_timeout(t);
        true
    }

    fn connected(&self) -> bool {
        self.c.is_connected() && self.s.is_connected()
    }
}

fn all(_: Dir, _: usize, _: &[u8]) -> bool {
    true
}

#[test]
fn handshake_app_data_kek_close() {
    let mut p = Pair::new(PSKD, PSKD, Config::default());
    p.pump(all);
    assert!(p.connected(), "{:?} {:?}", p.c.state(), p.s.state());
    let kc = p.c.kek().unwrap();
    let ks = p.s.kek().unwrap();
    assert_eq!(kc.0, ks.0);
    assert_ne!(kc.0, [0; 16]);

    // Flights: CH, HVR, CH+cookie, server flight, client flight, server
    // final flight (each one datagram with the default MTU).
    let dirs: Vec<Dir> = p.log.iter().map(|(d, _)| *d).collect();
    assert_eq!(
        dirs,
        [
            Dir::ToServer,
            Dir::ToClient,
            Dir::ToServer,
            Dir::ToClient,
            Dir::ToServer,
            Dir::ToClient
        ]
    );
    // The HelloVerifyRequest re-uses the ClientHello record sequence number.
    let (ch, _, _) = record::parse(&p.log[0].1).unwrap();
    let (hvr, _, _) = record::parse(&p.log[1].1).unwrap();
    assert_eq!(ch.seq, hvr.seq);
    // Records of all flights fit the OpenThread content length.
    assert!(p.log.iter().all(|(_, d)| d.len() <= MAX_CONTENT_LEN));

    let mut buf = [0u8; 1024];
    let n = p.c.send(b"coap request", &mut buf).unwrap();
    p.deliver(Dir::ToServer, &buf[..n]);
    let n = p.s.send(b"coap response", &mut buf).unwrap();
    p.deliver(Dir::ToClient, &buf[..n]);
    assert_eq!(p.app.1, [b"coap request".to_vec()]);
    assert_eq!(p.app.0, [b"coap response".to_vec()]);

    p.c.close();
    assert_eq!(p.c.state(), State::Closed(CloseReason::Local));
    p.pump(all);
    assert_eq!(p.s.state(), State::Closed(CloseReason::Peer));
    // The KEK of an established session survives the close.
    assert!(p.c.kek().is_some());
    assert!(p.c.send(b"x", &mut buf).is_err());
}

#[test]
fn several_records_per_datagram() {
    let mut p = Pair::new(PSKD, PSKD, Config::default());
    p.pump(all);
    let mut buf = [0u8; 1024];
    let n1 = p.c.send(b"one", &mut buf).unwrap();
    let n2 = p.c.send(b"two", &mut buf[n1..]).unwrap();
    let d = buf[..n1 + n2].to_vec();
    p.deliver(Dir::ToServer, &d);
    assert_eq!(p.app.1, [b"one".to_vec(), b"two".to_vec()]);
}

#[test]
fn replayed_and_tampered_records_are_dropped() {
    let mut p = Pair::new(PSKD, PSKD, Config::default());
    p.pump(all);
    let mut buf = [0u8; 1024];
    let n = p.c.send(b"once", &mut buf).unwrap();
    let rec = buf[..n].to_vec();
    p.deliver(Dir::ToServer, &rec);
    p.deliver(Dir::ToServer, &rec);
    assert_eq!(p.app.1.len(), 1);
    // Tampered ciphertext: dropped silently, session stays up.
    let n = p.c.send(b"twice", &mut buf).unwrap();
    let mut bad = buf[..n].to_vec();
    bad[n - 1] ^= 1;
    p.deliver(Dir::ToServer, &bad);
    assert_eq!(p.app.1.len(), 1);
    assert!(p.s.is_connected());
    // The genuine record still arrives (the failed one did not consume
    // its sequence number).
    let good = buf[..n].to_vec();
    p.deliver(Dir::ToServer, &good);
    assert_eq!(p.app.1.len(), 2);
    // Old epoch / plaintext application data is ignored.
    let mut plain = [0u8; 20];
    record::write_header(&mut plain, CT_APPLICATION_DATA, 0, 99, 7);
    p.deliver(Dir::ToServer, &plain);
    assert_eq!(p.app.1.len(), 2);
}

#[test]
fn wrong_password_fails_with_bad_record_mac() {
    let mut p = Pair::new(b"J01NME", b"J01NMF", Config::default());
    p.pump(all);
    // The server cannot authenticate the client's Finished record.
    assert_eq!(
        p.s.state(),
        State::Closed(CloseReason::Failed(ALERT_BAD_RECORD_MAC))
    );
    assert_eq!(
        p.c.state(),
        State::Closed(CloseReason::PeerAlert(ALERT_BAD_RECORD_MAC))
    );
    assert!(p.c.kek().is_none() && p.s.kek().is_none());
    // The alert went out in plaintext (the server never sent its CCS).
    let (dir, last) = p.log.last().unwrap();
    assert_eq!(*dir, Dir::ToClient);
    assert_eq!(&last[13..], &[ALERT_LEVEL_FATAL, ALERT_BAD_RECORD_MAC]);
}

#[test]
fn lost_server_flight_is_retransmitted() {
    let mut p = Pair::new(PSKD, PSKD, Config::default());
    // Drop the first ServerHello flight (datagram 3).
    p.pump(|d, i, _| !(d == Dir::ToClient && i == 3));
    assert_eq!(p.c.state(), State::Handshaking);
    // Client timer (8 s) fires, ClientHello is re-sent, server resends its
    // flight on the retransmitted ClientHello.
    let t0 = p.now;
    assert!(p.tick());
    assert_eq!(p.now - t0, Duration::from_secs(8));
    p.pump(all);
    assert!(p.connected());
    assert_eq!(p.c.kek().unwrap().0, p.s.kek().unwrap().0);
}

#[test]
fn lost_client_final_flight_is_retransmitted() {
    let mut p = Pair::new(PSKD, PSKD, Config::default());
    p.pump(|d, i, _| !(d == Dir::ToServer && i == 4));
    assert_eq!(p.c.state(), State::Handshaking);
    assert!(p.tick());
    p.pump(all);
    assert!(p.connected());
}

#[test]
fn lost_server_final_flight_is_retransmitted() {
    let mut p = Pair::new(PSKD, PSKD, Config::default());
    p.pump(|d, i, _| !(d == Dir::ToClient && i == 5));
    assert!(p.s.is_connected());
    assert!(!p.c.is_connected());
    // Client retransmits its final flight; the connected server resends
    // CCS + Finished on the retransmitted Finished.
    assert!(p.tick());
    p.pump(all);
    assert!(p.connected());
    assert_eq!(p.c.kek().unwrap().0, p.s.kek().unwrap().0);
}

#[test]
fn fragmented_and_reordered_flights() {
    let cfg = Config {
        mtu: 500,
        ..Config::default()
    };
    let mut p = Pair::new(PSKD, PSKD, cfg);
    // Deliver every flight's datagrams in reverse order.
    let mut held: Vec<(Dir, Vec<u8>)> = Vec::new();
    for _ in 0..20 {
        for dir in [Dir::ToServer, Dir::ToClient] {
            let mut ds = p.drain(dir);
            assert!(ds.iter().all(|d| d.len() <= 500));
            ds.reverse();
            for d in ds {
                held.push((dir, d));
            }
        }
        if held.is_empty() {
            if !p.tick() {
                break;
            }
            continue;
        }
        for (dir, d) in core::mem::take(&mut held) {
            p.deliver(dir, &d);
        }
        if p.connected() {
            break;
        }
    }
    assert!(p.connected(), "{:?} {:?}", p.c.state(), p.s.state());
    assert_eq!(p.c.kek().unwrap().0, p.s.kek().unwrap().0);
}

#[test]
fn client_times_out() {
    let mut p = Pair::new(PSKD, PSKD, Config::default());
    // Server never answers.
    let _ = p.drain(Dir::ToServer);
    let start = p.now;
    let mut times = Vec::new();
    while p.tick() {
        times.push((p.now - start).as_secs());
        let _ = p.drain(Dir::ToServer);
    }
    // OpenThread: retransmit after 8, 24, 56 s; give up at 116 s.
    assert_eq!(times, [8, 24, 56, 116]);
    assert_eq!(p.c.state(), State::Closed(CloseReason::Timeout));
    // The last datagram is the handshake_failure alert.
    let (_, last) = p.log.last().unwrap();
    assert_eq!(&last[13..], &[ALERT_LEVEL_FATAL, ALERT_HANDSHAKE_FAILURE]);
}

/// Up to the server's first flight; returns it (not delivered).
fn to_server_flight(p: &mut Pair) -> Vec<Vec<u8>> {
    let (_, hvr) = first_exchange(p);
    p.deliver(Dir::ToClient, &hvr);
    let ch2 = p.drain(Dir::ToServer).remove(0);
    p.deliver(Dir::ToServer, &ch2);
    p.drain(Dir::ToClient)
}

fn server_retransmit(p: &mut Pair) -> Vec<Vec<u8>> {
    p.now = p.s.next_timeout().unwrap();
    p.s.handle_timeout(p.now);
    p.drain(Dir::ToClient)
}

#[test]
fn retransmissions_fall_back_to_small_mtu() {
    let mut p = Pair::new(PSKD, PSKD, Config::default());
    // The server's flight (ServerHello .. ServerHelloDone, about 650
    // bytes) is never acknowledged.
    let mut sizes: Vec<Vec<usize>> = Vec::new();
    sizes.push(to_server_flight(&mut p).iter().map(|d| d.len()).collect());
    for _ in 0..3 {
        sizes.push(server_retransmit(&mut p).iter().map(|d| d.len()).collect());
    }
    // Initial transmission and first retransmission: one datagram; from
    // the second retransmission on at most 508 bytes (fragmented).
    assert_eq!(sizes[0].len(), 1);
    assert!(sizes[0][0] > 508);
    assert_eq!(sizes[1], sizes[0]);
    for s in &sizes[2..] {
        assert!(s.len() > 1 && s.iter().all(|&n| n <= 508), "{s:?}");
    }

    // A client that only sees the fragmented retransmission connects.
    let mut p = Pair::new(PSKD, PSKD, Config::default());
    let _lost = to_server_flight(&mut p);
    let _lost = server_retransmit(&mut p);
    let frags = server_retransmit(&mut p);
    for d in frags {
        p.deliver(Dir::ToClient, &d);
    }
    p.pump(all);
    assert!(p.connected());
}

#[test]
fn thread_spec_timeouts() {
    let mut p = Pair::new(PSKD, PSKD, Config::THREAD_SPEC);
    let _ = p.drain(Dir::ToServer);
    let start = p.now;
    let mut times = Vec::new();
    while p.tick() {
        times.push((p.now - start).as_secs());
        let _ = p.drain(Dir::ToServer);
    }
    // Two retransmissions (8 s, then 16 s), then failure.
    assert_eq!(times, [8, 24, 56]);
}

/// Take the first ClientHello (no cookie) and the server's HVR.
fn first_exchange(p: &mut Pair) -> (Vec<u8>, Vec<u8>) {
    let ch = p.drain(Dir::ToServer).remove(0);
    p.deliver(Dir::ToServer, &ch);
    let hvr = p.drain(Dir::ToClient).remove(0);
    (ch, hvr)
}

/// Offset of the cookie in a ClientHello datagram.
const CH_COOKIE_LEN_OFF: usize = 13 + 12 + 2 + 32 + 1;

#[test]
fn cookie_exchange_and_mismatch() {
    let mut p = Pair::new(PSKD, PSKD, Config::default());
    let (_, hvr) = first_exchange(&mut p);
    assert_eq!(hvr[13], handshake::HT_HELLO_VERIFY_REQUEST);
    p.deliver(Dir::ToClient, &hvr);
    let ch2 = p.drain(Dir::ToServer).remove(0);
    assert_eq!(ch2[CH_COOKIE_LEN_OFF] as usize, session::COOKIE_LEN);

    // Forged cookie: answered with a new HelloVerifyRequest, no state.
    let mut forged = ch2.clone();
    forged[CH_COOKIE_LEN_OFF + 10] ^= 1;
    p.deliver(Dir::ToServer, &forged);
    let r = p.drain(Dir::ToClient);
    assert_eq!(r.len(), 1);
    assert_eq!(r[0][13], handshake::HT_HELLO_VERIFY_REQUEST);
    assert_eq!(p.s.state(), State::Handshaking);

    // The same cookie presented for another client identity is invalid.
    let mut rng = TestRng(7);
    let mut other = Dtls::server(
        SoftCrypto,
        SoftP256,
        PSKD,
        Config::default(),
        b"other",
        &mut rng,
    )
    .unwrap();
    let mut buf = [0u8; 1024];
    other
        .handle_datagram(p.now, &mut rng, &ch2, &mut buf)
        .unwrap();
    let mut out = [0u8; 1500];
    let n = other.poll_transmit(&mut out).unwrap();
    assert_eq!(out[13], handshake::HT_HELLO_VERIFY_REQUEST);
    assert_eq!(n, 13 + 12 + 3 + 32);

    // An expired cookie (older than 60 s) is refused as well (new record
    // sequence number, else it is a replay of the forged record).
    p.now += Duration::from_secs(61);
    let mut late = ch2.clone();
    late[10] = 9;
    p.deliver(Dir::ToServer, &late);
    let r = p.drain(Dir::ToClient);
    assert_eq!(r[0][13], handshake::HT_HELLO_VERIFY_REQUEST);
}

#[test]
fn client_hello_missing_kkpp_fails_after_cookie() {
    let mut p = Pair::new(PSKD, PSKD, Config::default());
    let (_, hvr) = first_exchange(&mut p);
    p.deliver(Dir::ToClient, &hvr);
    let mut ch2 = p.drain(Dir::ToServer).remove(0);
    // Turn the ecjpake_kkpp extension (the last one) into an unknown
    // type (0x0101).
    let i = (CH_COOKIE_LEN_OFF..ch2.len() - 4)
        .find(|&i| {
            ch2[i] == 0x01
                && ch2[i + 1] == 0x00
                && u16::from_be_bytes([ch2[i + 2], ch2[i + 3]]) as usize == ch2.len() - i - 4
        })
        .unwrap();
    ch2[i + 1] = 0x01;
    p.deliver(Dir::ToServer, &ch2);
    assert_eq!(
        p.s.state(),
        State::Closed(CloseReason::Failed(ALERT_HANDSHAKE_FAILURE))
    );
    let r = p.drain(Dir::ToClient);
    assert_eq!(&r[0][13..], &[ALERT_LEVEL_FATAL, ALERT_HANDSHAKE_FAILURE]);
}

#[test]
fn corrupted_zkp_fails_with_handshake_failure() {
    let mut p = Pair::new(PSKD, PSKD, Config::default());
    let (_, hvr) = first_exchange(&mut p);
    p.deliver(Dir::ToClient, &hvr);
    let ch2 = p.drain(Dir::ToServer).remove(0);
    p.deliver(Dir::ToServer, &ch2);
    let mut flight = p.drain(Dir::ToClient).remove(0);
    // Corrupt a byte inside the ServerHello's ecjpake_kkpp (a ZKP).
    flight[13 + 12 + 300] ^= 1;
    p.deliver(Dir::ToClient, &flight);
    assert_eq!(
        p.c.state(),
        State::Closed(CloseReason::Failed(ALERT_HANDSHAKE_FAILURE))
    );
    p.pump(all);
    assert_eq!(
        p.s.state(),
        State::Closed(CloseReason::PeerAlert(ALERT_HANDSHAKE_FAILURE))
    );
}

#[test]
fn unexpected_message_fails() {
    let mut p = Pair::new(PSKD, PSKD, Config::default());
    let (_, hvr) = first_exchange(&mut p);
    p.deliver(Dir::ToClient, &hvr);
    let _ = p.drain(Dir::ToServer);
    // A ServerHelloDone (msg_seq 1) instead of the ServerHello.
    let mut d = [0u8; 25];
    record::write_header(&mut d, CT_HANDSHAKE, 0, 5, 12);
    handshake::write_header(&mut d[13..], handshake::HT_SERVER_HELLO_DONE, 0, 1, 0, 0);
    p.deliver(Dir::ToClient, &d);
    assert_eq!(
        p.c.state(),
        State::Closed(CloseReason::Failed(ALERT_HANDSHAKE_FAILURE))
    );
}

#[test]
fn config_validation() {
    let mut rng = TestRng(1);
    let bad = Config {
        mtu: 50,
        ..Config::default()
    };
    assert!(
        Dtls::client(
            SoftCrypto,
            SoftP256,
            PSKD,
            bad,
            Instant::from_secs(0),
            &mut rng
        )
        .is_err()
    );
    assert!(
        Dtls::server(
            SoftCrypto,
            SoftP256,
            PSKD,
            Config::default(),
            &[0; 33],
            &mut rng
        )
        .is_err()
    );
    assert!(
        Dtls::client(
            SoftCrypto,
            SoftP256,
            b"",
            Config::default(),
            Instant::from_secs(0),
            &mut rng
        )
        .is_err()
    );
}
