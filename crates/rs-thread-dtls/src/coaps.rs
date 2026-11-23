//! CoAPS: a DTLS [`Session`] behind the CoAP endpoint's
//! [`SecureTransport`] seam (OpenThread `CoapSecure` / `SecureTransport`).
//!
//! [`Coaps`] owns one session with one peer and the plain UDP
//! [`Transport`] the records travel on. The CoAP
//! [`Endpoint`](rs_thread_coap::endpoint::Endpoint) sends through it
//! (encrypting) and is fed the plaintext that [`SecureTransport::decrypt`]
//! returns; handshake flights, retransmissions and alerts go out on the
//! UDP transport automatically.
//!
//! One application-data record per datagram is delivered (mbedTLS and
//! OpenThread send exactly one per datagram); further application-data
//! records in the same datagram are dropped.

use rs_thread_coap::endpoint::{Peer, SecureTransport, SendOpts, Transport};
use rs_thread_core::crypto::backend::CryptoBackend;
use rs_thread_core::crypto::ecjpake::P256;
use rs_thread_core::time::Instant;
use rs_thread_core::types::Kek;
use rs_thread_core::{Error, Result};
use rand_core::CryptoRng;

use crate::record::{AEAD_OVERHEAD, HEADER_LEN};
use crate::{Config, MAX_CONTENT_LEN, Session, State};

/// Largest datagram [`Coaps`] produces (one full application record).
pub const MAX_DATAGRAM_LEN: usize = HEADER_LEN + AEAD_OVERHEAD + MAX_CONTENT_LEN;

/// A CoAPS session with one peer.
#[derive(Debug)]
pub struct Coaps<B: CryptoBackend, C: P256, R, T> {
    session: Session<B, C>,
    peer: Peer,
    rng: R,
    udp: T,
    opts: SendOpts,
}

impl<B, C, R, T> Coaps<B, C, R, T>
where
    B: CryptoBackend,
    B::Sha256: Clone,
    C: P256,
    R: CryptoRng,
    T: Transport,
{
    /// Start a client session to `peer` (Joiner: PSKd; Commissioner: PSKc)
    /// and send the ClientHello on `udp`.
    #[allow(clippy::too_many_arguments)]
    pub fn client(
        crypto: B,
        curve: C,
        password: &[u8],
        cfg: Config,
        now: Instant,
        mut rng: R,
        peer: Peer,
        udp: T,
    ) -> Result<Self> {
        let session = Session::client(crypto, curve, password, cfg, now, &mut rng)?;
        let mut s = Self {
            session,
            peer,
            rng,
            udp,
            opts: SendOpts::default(),
        };
        s.flush()?;
        Ok(s)
    }

    /// Accept a session from `peer` (Border Agent / Joiner Router /
    /// Commissioner side). Cookies are bound to the peer's address and
    /// port.
    #[cfg(feature = "dtls-server")]
    pub fn server(
        crypto: B,
        curve: C,
        password: &[u8],
        cfg: Config,
        mut rng: R,
        peer: Peer,
        udp: T,
    ) -> Result<Self> {
        let mut id = [0u8; 18];
        id[..16].copy_from_slice(&peer.addr.octets());
        id[16..].copy_from_slice(&peer.port.to_be_bytes());
        let session = Session::server(crypto, curve, password, cfg, &id, &mut rng)?;
        Ok(Self {
            session,
            peer,
            rng,
            udp,
            opts: SendOpts::default(),
        })
    }

    /// The DTLS session.
    pub fn session(&self) -> &Session<B, C> {
        &self.session
    }

    /// Session state.
    pub fn state(&self) -> State {
        self.session.state()
    }

    /// The peer.
    pub fn peer(&self) -> &Peer {
        &self.peer
    }

    /// The KEK once connected.
    pub fn kek(&self) -> Option<&Kek> {
        self.session.kek()
    }

    /// The UDP transport.
    pub fn udp_mut(&mut self) -> &mut T {
        &mut self.udp
    }

    /// Options used for the ciphertext datagrams (source address,
    /// priority).
    pub fn set_send_opts(&mut self, opts: SendOpts) {
        self.opts = opts;
    }

    /// When [`poll`](Self::poll) must be called next.
    pub fn next_timeout(&self) -> Option<Instant> {
        self.session.next_timeout()
    }

    /// Drive handshake retransmission.
    pub fn poll(&mut self, now: Instant) -> Result<()> {
        self.session.handle_timeout(now);
        self.flush()
    }

    /// Send everything the session queued (flights, alerts).
    fn flush(&mut self) -> Result<()> {
        let mut buf = [0u8; MAX_DATAGRAM_LEN];
        let mut r = Ok(());
        while let Some(n) = self.session.poll_transmit(&mut buf) {
            // Keep draining on error; report the first one.
            let e = self.udp.send(&self.peer, &self.opts, &buf[..n]);
            if r.is_ok() {
                r = e;
            }
        }
        r
    }
}

impl<B, C, R, T> Transport for Coaps<B, C, R, T>
where
    B: CryptoBackend,
    B::Sha256: Clone,
    C: P256,
    R: CryptoRng,
    T: Transport,
{
    /// Encrypt one CoAP message for the peer. [`Error::InvalidArgs`] for
    /// another peer, [`Error::InvalidState`] before the handshake
    /// completed.
    fn send(&mut self, peer: &Peer, opts: &SendOpts, data: &[u8]) -> Result<()> {
        if *peer != self.peer {
            return Err(Error::InvalidArgs);
        }
        let mut buf = [0u8; MAX_DATAGRAM_LEN];
        let n = self.session.send(data, &mut buf)?;
        let opts = SendOpts {
            src: opts.src.or(self.opts.src),
            ..*opts
        };
        self.udp.send(&self.peer, &opts, &buf[..n])
    }
}

impl<B, C, R, T> SecureTransport for Coaps<B, C, R, T>
where
    B: CryptoBackend,
    B::Sha256: Clone,
    C: P256,
    R: CryptoRng,
    T: Transport,
{
    fn is_connected(&self, peer: &Peer) -> bool {
        *peer == self.peer && self.session.is_connected()
    }

    fn decrypt(
        &mut self,
        now: Instant,
        peer: &Peer,
        record: &[u8],
        plaintext: &mut [u8],
    ) -> Result<Option<usize>> {
        if *peer != self.peer {
            return Err(Error::InvalidArgs);
        }
        let r = self
            .session
            .handle_datagram(now, &mut self.rng, record, plaintext);
        if let Ok(rx) = r {
            // Process the remaining records (handshake, alerts); further
            // application records are dropped (one plaintext per call).
            let mut rest = &record[rx.consumed..];
            let mut scratch = [0u8; MAX_CONTENT_LEN];
            while !rest.is_empty() {
                match self
                    .session
                    .handle_datagram(now, &mut self.rng, rest, &mut scratch)
                {
                    Ok(more) => rest = &rest[more.consumed..],
                    Err(_) => break,
                }
            }
        }
        let f = self.flush();
        let app = r?.app_data;
        f?;
        Ok(app)
    }

    fn close(&mut self, peer: &Peer) {
        if *peer == self.peer {
            self.session.close();
            let _ = self.flush();
        }
    }
}

#[cfg(all(test, feature = "soft-crypto"))]
mod tests {
    use core::net::Ipv6Addr;
    use std::vec::Vec;

    use rs_thread_coap::endpoint::{Endpoint, ResourceId, Rx, RxInfo, TxParams};
    use rs_thread_coap::message::Code;
    use rs_thread_core::crypto::SoftCrypto;
    use rs_thread_core::crypto::ecjpake::SoftP256;
    use rs_thread_core::time::Duration;

    use super::*;
    use crate::tests::TestRng;
    use crate::{ALERT_BAD_RECORD_MAC, CloseReason};

    #[derive(Debug, Default)]
    struct Udp {
        sent: Vec<Vec<u8>>,
    }

    impl Transport for Udp {
        fn send(&mut self, _peer: &Peer, _opts: &SendOpts, data: &[u8]) -> Result<()> {
            self.sent.push(data.to_vec());
            Ok(())
        }
    }

    type Link = Coaps<SoftCrypto, SoftP256, TestRng, Udp>;
    type Ep = Endpoint<2, 2, 2, 256, 4>;

    const JOINER: Ipv6Addr = Ipv6Addr::new(0xfe80, 0, 0, 0, 0x1234, 0, 0, 1);
    const AGENT: Ipv6Addr = Ipv6Addr::new(0xfe80, 0, 0, 0, 0x1234, 0, 0, 2);
    const JOINER_PEER: Peer = Peer::new(JOINER, 49153);
    const AGENT_PEER: Peer = Peer::new(AGENT, 1000);

    struct Net {
        now: Instant,
        joiner: Link,
        agent: Link,
        jep: Ep,
        aep: Ep,
        rng: TestRng,
        /// Plaintext CoAP datagrams delivered to (joiner, agent).
        delivered: (Vec<Vec<u8>>, Vec<Vec<u8>>),
    }

    impl Net {
        fn new(pskd_joiner: &[u8], pskd_agent: &[u8]) -> Self {
            let now = Instant::from_secs(50);
            let joiner = Link::client(
                SoftCrypto,
                SoftP256,
                pskd_joiner,
                Config::default(),
                now,
                TestRng(11),
                AGENT_PEER,
                Udp::default(),
            )
            .unwrap();
            let agent = Link::server(
                SoftCrypto,
                SoftP256,
                pskd_agent,
                Config::default(),
                TestRng(22),
                JOINER_PEER,
                Udp::default(),
            )
            .unwrap();
            let mut aep = Ep::new(7, TxParams::default());
            aep.add_resource("c/jf", ResourceId(1)).unwrap();
            Self {
                now,
                joiner,
                agent,
                jep: Ep::new(9, TxParams::default()),
                aep,
                rng: TestRng(33),
                delivered: (Vec::new(), Vec::new()),
            }
        }

        /// Move ciphertext both ways until quiet; `keep(to_agent, d)`
        /// filters. Plaintext is collected in `delivered`.
        fn pump(&mut self, mut keep: impl FnMut(bool, &[u8]) -> bool) {
            for _ in 0..20 {
                let to_agent = core::mem::take(&mut self.joiner.udp_mut().sent);
                let to_joiner = core::mem::take(&mut self.agent.udp_mut().sent);
                if to_agent.is_empty() && to_joiner.is_empty() {
                    return;
                }
                let mut pt = [0u8; 512];
                for d in to_agent.iter().filter(|d| keep(true, d)) {
                    if let Some(n) = self
                        .agent
                        .decrypt(self.now, &JOINER_PEER, d, &mut pt)
                        .unwrap()
                    {
                        self.delivered.1.push(pt[..n].to_vec());
                    }
                }
                for d in to_joiner.iter().filter(|d| keep(false, d)) {
                    if let Some(n) = self
                        .joiner
                        .decrypt(self.now, &AGENT_PEER, d, &mut pt)
                        .unwrap()
                    {
                        self.delivered.0.push(pt[..n].to_vec());
                    }
                }
            }
            panic!("no quiescence");
        }
    }

    #[test]
    fn coaps_request_response_and_kek() {
        let mut n = Net::new(b"J01NME", b"J01NME");
        // Requests before the handshake completed are refused.
        let opts = SendOpts::default();
        assert_eq!(
            n.jep.post(
                n.now,
                &mut n.rng,
                &mut n.joiner,
                &AGENT_PEER,
                &opts,
                "c/jf",
                b"x",
                Some(1)
            ),
            Err(Error::InvalidState)
        );
        assert!(!n.joiner.is_connected(&AGENT_PEER));
        n.pump(|_, _| true);
        assert!(n.joiner.is_connected(&AGENT_PEER));
        assert!(n.agent.is_connected(&JOINER_PEER));
        assert!(!n.agent.is_connected(&AGENT_PEER));
        assert_eq!(n.joiner.kek().unwrap().0, n.agent.kek().unwrap().0);

        // Joiner Finalize-like request over CoAPS.
        n.jep
            .post(
                n.now,
                &mut n.rng,
                &mut n.joiner,
                &AGENT_PEER,
                &opts,
                "c/jf",
                &[0x10, 0x01, 0x01],
                Some(42),
            )
            .unwrap();
        n.pump(|_, _| true);
        assert_eq!(n.delivered.1.len(), 1);
        let req = n.delivered.1.remove(0);
        let info = RxInfo {
            peer: JOINER_PEER,
            dst: AGENT,
        };
        let ctx = match n.aep.handle_datagram(n.now, &mut n.agent, &info, &req) {
            Rx::Request(r) => {
                assert_eq!(r.resource, ResourceId(1));
                assert_eq!(r.msg.payload(), &[0x10, 0x01, 0x01]);
                r.ctx
            }
            other => panic!("{other:?}"),
        };
        n.aep
            .respond_payload(
                n.now,
                &mut n.agent,
                &ctx,
                &opts,
                Code::CHANGED,
                &[0x10, 0x01, 0x01],
            )
            .unwrap();
        n.pump(|_, _| true);
        let resp = n.delivered.0.remove(0);
        let info = RxInfo {
            peer: AGENT_PEER,
            dst: JOINER,
        };
        match n.jep.handle_datagram(n.now, &mut n.joiner, &info, &resp) {
            Rx::Response { user, msg, .. } => {
                assert_eq!(user, 42);
                assert_eq!(msg.code(), Code::CHANGED);
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(n.jep.pending_len(), 0);

        // Wrong peer.
        assert_eq!(
            n.agent.send(&AGENT_PEER, &opts, b"x"),
            Err(Error::InvalidArgs)
        );

        // Close: the agent sees close_notify.
        n.joiner.close(&AGENT_PEER);
        n.pump(|_, _| true);
        assert_eq!(n.agent.state(), State::Closed(CloseReason::Peer));
        assert!(!n.agent.is_connected(&JOINER_PEER));
    }

    #[test]
    fn coaps_replay_is_rejected() {
        let mut n = Net::new(b"J01NME", b"J01NME");
        n.pump(|_, _| true);
        n.joiner
            .send(&AGENT_PEER, &SendOpts::default(), b"\x50\x01\x00\x01")
            .unwrap();
        let d = n.joiner.udp_mut().sent.remove(0);
        let mut pt = [0u8; 64];
        assert_eq!(
            n.agent.decrypt(n.now, &JOINER_PEER, &d, &mut pt).unwrap(),
            Some(4)
        );
        assert_eq!(
            n.agent.decrypt(n.now, &JOINER_PEER, &d, &mut pt).unwrap(),
            None
        );
        // Records from another peer are refused.
        assert_eq!(
            n.agent.decrypt(n.now, &AGENT_PEER, &d, &mut pt),
            Err(Error::InvalidArgs)
        );
    }

    #[test]
    fn coaps_close_notify_after_app_data_in_one_datagram() {
        let mut n = Net::new(b"J01NME", b"J01NME");
        n.pump(|_, _| true);
        let opts = SendOpts::default();
        n.joiner.send(&AGENT_PEER, &opts, b"first").unwrap();
        n.joiner.send(&AGENT_PEER, &opts, b"second").unwrap();
        n.joiner.close(&AGENT_PEER);
        let d: Vec<u8> = n.joiner.udp_mut().sent.concat();
        let mut pt = [0u8; 64];
        assert_eq!(
            n.agent.decrypt(n.now, &JOINER_PEER, &d, &mut pt).unwrap(),
            Some(5)
        );
        assert_eq!(&pt[..5], b"first");
        // "second" is dropped, but the trailing close_notify is processed.
        assert_eq!(n.agent.state(), State::Closed(CloseReason::Peer));
    }

    #[test]
    fn coaps_lost_flight_recovers_via_poll() {
        let mut n = Net::new(b"J01NME", b"J01NME");
        let mut dropped = false;
        // Drop the agent's first ServerHello flight (the datagram > 300
        // bytes).
        n.pump(|to_agent, d| {
            if !to_agent && d.len() > 300 && !dropped {
                dropped = true;
                return false;
            }
            true
        });
        assert!(!n.joiner.is_connected(&AGENT_PEER));
        n.now = n.joiner.next_timeout().unwrap();
        assert_eq!(n.now, Instant::from_secs(50) + Duration::from_secs(8));
        n.joiner.poll(n.now).unwrap();
        n.agent.poll(n.now).unwrap();
        n.pump(|_, _| true);
        assert!(n.joiner.is_connected(&AGENT_PEER));
        assert_eq!(n.joiner.kek().unwrap().0, n.agent.kek().unwrap().0);
    }

    #[test]
    fn coaps_wrong_pskd_fails() {
        let mut n = Net::new(b"J01NME", b"WRONG1");
        n.pump(|_, _| true);
        assert_eq!(
            n.agent.state(),
            State::Closed(CloseReason::Failed(ALERT_BAD_RECORD_MAC))
        );
        assert_eq!(
            n.joiner.state(),
            State::Closed(CloseReason::PeerAlert(ALERT_BAD_RECORD_MAC))
        );
        assert!(n.joiner.kek().is_none());
        assert!(!n.joiner.is_connected(&AGENT_PEER));
    }

    #[test]
    fn coaps_cookie_mismatch_gets_new_hello_verify_request() {
        let mut n = Net::new(b"J01NME", b"J01NME");
        // ClientHello -> HVR -> ClientHello with cookie; corrupt the cookie.
        let ch1 = n.joiner.udp_mut().sent.remove(0);
        let mut pt = [0u8; 64];
        n.agent.decrypt(n.now, &JOINER_PEER, &ch1, &mut pt).unwrap();
        let hvr = n.agent.udp_mut().sent.remove(0);
        n.joiner.decrypt(n.now, &AGENT_PEER, &hvr, &mut pt).unwrap();
        let mut ch2 = n.joiner.udp_mut().sent.remove(0);
        ch2[13 + 12 + 2 + 32 + 1 + 1 + 5] ^= 0xff;
        n.agent.decrypt(n.now, &JOINER_PEER, &ch2, &mut pt).unwrap();
        let r = n.agent.udp_mut().sent.remove(0);
        assert_eq!(r[13], crate::handshake::HT_HELLO_VERIFY_REQUEST);
        assert_eq!(n.agent.state(), State::Handshaking);
    }
}
