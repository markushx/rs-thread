//! TCAT engine against a fake TLS transport and a fake stack.

use std::vec::Vec;

use rs_thread_core::bytes::Writer;
use rs_thread_core::crypto::SoftCrypto;
use rs_thread_core::crypto::backend::{CryptoBackend, HmacSha256};
use rs_thread_core::types::{NetworkKey, NetworkName, Pskc};

use crate::dataset::{Dataset, DatasetType};
use crate::pskd::JoinerPskd;
use crate::tcat::{
    CertificateClaims, CommandClass, EnvResult, Status, TcatAgent, TcatEnv, TcatEvent,
    TcatSecureTransport, TcatState, flag, ty,
};
use crate::test_rng::TestRng;
use crate::timestamp::Timestamp;

const SPKI: &[u8] = b"device-subjectPublicKeyInfo";
const PEER_DER: &[u8] = b"commissioner-certificate-der";
const PSKC: Pskc = Pskc([0x5c; 16]);

#[derive(Default)]
struct FakeTls {
    sent: Vec<Vec<u8>>,
    closed: bool,
}

impl TcatSecureTransport for FakeTls {
    fn send(&mut self, data: &[u8]) -> rs_thread_core::Result<()> {
        self.sent.push(data.to_vec());
        Ok(())
    }
    fn disconnect(&mut self) {
        self.closed = true;
    }
    fn peer_certificate_der(&self) -> &[u8] {
        PEER_DER
    }
    fn own_public_key_info(&self) -> &[u8] {
        SPKI
    }
}

#[derive(Default)]
struct FakeEnv {
    active: Vec<u8>,
    cert: Option<Vec<u8>>,
    thread: bool,
    decommissioned: bool,
    pskd: Option<JoinerPskd>,
    domain: Option<&'static [u8]>,
}

impl TcatEnv for FakeEnv {
    fn active_dataset(&self) -> &[u8] {
        &self.active
    }
    fn set_active_dataset(&mut self, tlvs: &[u8]) -> EnvResult<()> {
        self.active = tlvs.to_vec();
        Ok(())
    }
    fn start_thread(&mut self) -> EnvResult<()> {
        self.thread = true;
        Ok(())
    }
    fn stop_thread(&mut self) -> EnvResult<()> {
        self.thread = false;
        Ok(())
    }
    fn decommission(&mut self) -> EnvResult<()> {
        self.thread = false;
        self.active.clear();
        self.decommissioned = true;
        Ok(())
    }
    fn store_commissioner_certificate(&mut self, der: &[u8]) -> EnvResult<()> {
        self.cert = Some(der.to_vec());
        Ok(())
    }
    fn commissioner_certificate(&self) -> Option<&[u8]> {
        self.cert.as_deref()
    }
    fn device_id(&self, out: &mut [u8]) -> usize {
        out[..8].copy_from_slice(&[0x18, 0xb4, 0x30, 0, 0, 0, 0, 1]);
        8
    }
    fn pskd(&self) -> Option<&JoinerPskd> {
        self.pskd.as_ref()
    }
    fn domain_name(&self) -> &[u8] {
        self.domain.unwrap_or(crate::tcat::DEFAULT_DOMAIN_NAME)
    }
    fn application_data(
        &mut self,
        protocol: u8,
        data: &[u8],
        out: &mut [u8],
    ) -> EnvResult<Option<usize>> {
        out[0] = protocol;
        out[1..1 + data.len()].copy_from_slice(data);
        Ok(Some(1 + data.len()))
    }
}

/// Authorization extension: header (C flag, version 1) and the class
/// flags (Commissioning, Extraction, Decommissioning, Application).
fn auth(commissioner: bool, classes: [u8; 4]) -> [u8; 5] {
    [
        u8::from(commissioner) | (1 << 5),
        classes[0],
        classes[1],
        classes[2],
        classes[3],
    ]
}

fn dataset(name: &str, complete: bool) -> Vec<u8> {
    let mut d = Dataset::new();
    d.set_network_key(&NetworkKey([0x11; 16])).unwrap();
    d.set_network_name(&NetworkName::new(name).unwrap())
        .unwrap();
    d.set_ext_pan_id(&rs_thread_core::types::ExtPanId([0xde; 8]))
        .unwrap();
    d.set_channel(15).unwrap();
    d.set_pan_id(0x1234).unwrap();
    if complete {
        d.set_pskc(&PSKC).unwrap();
        d.set_channel_mask(0x07ff_f800).unwrap();
        d.set_mesh_local_prefix(&rs_thread_core::types::Prefix64([
            0xfd, 0, 0, 0, 0, 0, 0, 0,
        ]))
        .unwrap();
        d.set_security_policy(&crate::tlv::SecurityPolicy::default())
            .unwrap();
        d.set_timestamp(
            DatasetType::Active,
            &Timestamp {
                seconds: 1,
                ticks: 0,
                authoritative: false,
            },
        )
        .unwrap();
        assert!(d.contains_all_required_for(DatasetType::Active));
    }
    d.as_bytes().to_vec()
}

fn tlv(t: u8, v: &[u8]) -> Vec<u8> {
    let mut b = std::vec![0u8; v.len() + 4];
    let mut w = Writer::new(&mut b);
    rs_thread_core::tlv::write(&mut w, t, v).unwrap();
    let n = w.written().len();
    b.truncate(n);
    b
}

fn hash(key: &[u8], challenge: &[u8]) -> [u8; 32] {
    let mut h = SoftCrypto.hmac_sha256(key);
    h.update(challenge);
    h.update(SPKI);
    h.finalize()
}

struct Fx {
    agent: TcatAgent<SoftCrypto>,
    env: FakeEnv,
    tls: FakeTls,
    rng: TestRng,
}

#[derive(Debug, PartialEq)]
enum Rsp {
    Status(Status),
    Payload(Vec<u8>),
}

impl Fx {
    fn new(peer: [u8; 5], own: [u8; 5], active: Vec<u8>) -> Self {
        Self::with_claims(
            &CertificateClaims {
                authorization: &peer,
                network_name: Some(b"Home"),
                ext_pan_id: Some([0xde; 8]),
                domain_name: None,
            },
            own,
            active,
        )
    }

    fn with_claims(peer: &CertificateClaims<'_>, own: [u8; 5], active: Vec<u8>) -> Self {
        let mut fx = Self {
            agent: TcatAgent::new(SoftCrypto),
            env: FakeEnv {
                active,
                pskd: Some(JoinerPskd::new("J01NME").unwrap()),
                ..Default::default()
            },
            tls: FakeTls::default(),
            rng: TestRng(3),
        };
        fx.agent.start();
        let own = CertificateClaims {
            authorization: &own,
            ..Default::default()
        };
        fx.agent.connected(&fx.env, peer, &own).unwrap();
        assert_eq!(fx.agent.pop_event(), Some(TcatEvent::Connected));
        fx
    }

    fn feed(&mut self, data: &[u8]) {
        let mut out = [0u8; 700];
        self.agent
            .handle_received(&mut self.rng, &mut self.env, &mut self.tls, data, &mut out);
    }

    fn responses(&mut self) -> Vec<Rsp> {
        self.tls
            .sent
            .drain(..)
            .map(|r| {
                let (t, rest) = rs_thread_core::tlv::Tlv::parse(&r).unwrap();
                assert!(rest.is_empty());
                match t.ty() {
                    ty::RESPONSE_WITH_STATUS => {
                        let s = t.value()[0];
                        Rsp::Status(
                            [
                                Status::Success,
                                Status::Unsupported,
                                Status::ParseError,
                                Status::ValueError,
                                Status::GeneralError,
                                Status::Busy,
                                Status::Undefined,
                                Status::HashError,
                                Status::InvalidState,
                                Status::Unauthorized,
                            ]
                            .into_iter()
                            .find(|x| *x as u8 == s)
                            .unwrap(),
                        )
                    }
                    ty::RESPONSE_WITH_PAYLOAD => Rsp::Payload(t.value().to_vec()),
                    other => panic!("response type {other}"),
                }
            })
            .collect()
    }

    fn cmd(&mut self, t: u8, v: &[u8]) -> Rsp {
        self.feed(&tlv(t, v));
        let mut r = self.responses();
        assert_eq!(r.len(), 1, "one response per command");
        r.remove(0)
    }

    fn challenge(&mut self) -> Vec<u8> {
        match self.cmd(ty::REQUEST_RANDOM_CHALLENGE, &[]) {
            Rsp::Payload(c) => {
                assert_eq!(c.len(), 8);
                c
            }
            r => panic!("{r:?}"),
        }
    }
}

const OPEN: [u8; 4] = [flag::ACCESS; 4];

#[test]
fn command_classes() {
    assert_eq!(CommandClass::of(0x00), CommandClass::General);
    assert_eq!(CommandClass::of(0x1f), CommandClass::General);
    assert_eq!(CommandClass::of(0x20), CommandClass::Commissioning);
    assert_eq!(CommandClass::of(0x40), CommandClass::Extraction);
    assert_eq!(CommandClass::of(0x7f), CommandClass::Decommissioning);
    assert_eq!(CommandClass::of(0x9f), CommandClass::Application);
    assert_eq!(CommandClass::of(0xa0), CommandClass::CommissioningCcm);
    assert_eq!(CommandClass::of(0xc0), CommandClass::Reserved);
}

/// Section 13.8.6: C flag 1 for the Commissioner, 0 for the Device,
/// version >= 1, at least 5 bytes (more are ignored).
#[test]
fn certificate_header_checks() {
    let env = FakeEnv::default();
    let own = auth(false, OPEN);
    let mut a = TcatAgent::<SoftCrypto>::new(SoftCrypto);
    let claims = |x: &'static [u8]| CertificateClaims {
        authorization: x,
        ..Default::default()
    };
    let own_c = CertificateClaims {
        authorization: &own,
        ..Default::default()
    };
    // Not enabled.
    let ok: &'static [u8] = &[0x21, 1, 1, 1, 1, 0xff];
    assert!(a.connected(&env, &claims(ok), &own_c).is_err());
    a.start();
    for bad in [
        &[0x20u8, 1, 1, 1, 1][..], // C = 0
        &[0x01, 1, 1, 1, 1],       // version 0
        &[0x21, 1, 1, 1],          // too short
    ] {
        let bad: &'static [u8] = std::boxed::Box::leak(bad.to_vec().into_boxed_slice());
        assert!(a.connected(&env, &claims(bad), &own_c).is_err());
    }
    // The Device's own certificate must have C = 0.
    assert!(a.connected(&env, &claims(ok), &claims(ok)).is_err());
    let long_name: &'static [u8] = b"a-network-name-of-17";
    let mut c = claims(ok);
    c.network_name = Some(long_name);
    assert!(a.connected(&env, &c, &own_c).is_err());
    assert_eq!(a.state(), TcatState::Enabled);
    a.connected(&env, &claims(ok), &own_c).unwrap();
    assert_eq!(a.state(), TcatState::Connected);
}

/// The section 13.12.1 algorithm, method by method.
#[test]
fn authorization_procedure() {
    let ds = dataset("Home", true);
    // Commissioner without access: refused even if the Device is open.
    let fx = Fx::new(auth(true, [0, 0, 0, 0]), auth(false, OPEN), ds.clone());
    assert!(fx.agent.is_authorized(&fx.env, ty::GET_NETWORK_NAME, &[]));
    assert!(!fx.agent.is_authorized(&fx.env, ty::GET_ACTIVE_DATASET, &[]));
    // Both open.
    let fx = Fx::new(auth(true, OPEN), auth(false, OPEN), ds.clone());
    assert!(fx.agent.is_authorized(&fx.env, ty::GET_ACTIVE_DATASET, &[]));
    assert!(!fx.agent.is_authorized(&fx.env, 0xa0, &[]), "CCM class");
    // The Device requires a method: Network Name matches (certificate has
    // "Home").
    let dev = [flag::NETWORK_NAME; 4];
    let fx = Fx::new(auth(true, OPEN), auth(false, dev), ds.clone());
    assert!(fx.agent.is_authorized(&fx.env, ty::GET_ACTIVE_DATASET, &[]));
    let fx = Fx::new(auth(true, OPEN), auth(false, dev), dataset("Other", true));
    assert!(!fx.agent.is_authorized(&fx.env, ty::GET_ACTIVE_DATASET, &[]));
    // XPAN ID.
    let fx = Fx::new(
        auth(true, OPEN),
        auth(false, [flag::EXT_PAN_ID; 4]),
        ds.clone(),
    );
    assert!(fx.agent.is_authorized(&fx.env, ty::DECOMMISSION, &[]));
    // The Commissioner requires a matching name: not met.
    let c = [flag::ACCESS | flag::NETWORK_NAME; 4];
    let fx = Fx::new(auth(true, c), auth(false, OPEN), dataset("Other", true));
    assert!(!fx.agent.is_authorized(&fx.env, ty::GET_ACTIVE_DATASET, &[]));
    // Reserved bits always fail, on either side.
    let fx = Fx::new(
        auth(true, [flag::ACCESS | 0x40; 4]),
        auth(false, OPEN),
        ds.clone(),
    );
    assert!(!fx.agent.is_authorized(&fx.env, ty::GET_ACTIVE_DATASET, &[]));
    let fx = Fx::new(auth(true, OPEN), auth(false, [0x80; 4]), ds.clone());
    assert!(!fx.agent.is_authorized(&fx.env, ty::GET_ACTIVE_DATASET, &[]));
    // Domain: the Commissioner's domain must equal the stored one
    // ("DefaultDomain" when none is configured).
    let peer = auth(true, [flag::ACCESS | flag::THREAD_DOMAIN; 4]);
    let mut fx = Fx::with_claims(
        &CertificateClaims {
            authorization: &peer,
            domain_name: Some(b"DefaultDomain"),
            ..Default::default()
        },
        auth(false, OPEN),
        ds.clone(),
    );
    assert!(fx.agent.is_authorized(&fx.env, ty::GET_ACTIVE_DATASET, &[]));
    fx.env.domain = Some(b"Other");
    assert!(!fx.agent.is_authorized(&fx.env, ty::GET_ACTIVE_DATASET, &[]));
    // PSKc exception: Set Active Dataset on a device without PSKc.
    let fx = Fx::new(auth(true, OPEN), auth(false, [flag::PSKC; 4]), Vec::new());
    assert!(fx.agent.is_authorized(&fx.env, ty::SET_ACTIVE_DATASET, &[]));
    assert!(!fx.agent.is_authorized(&fx.env, ty::DECOMMISSION, &[]));
}

/// Section 13.12.2: open Commissioning class; dataset, certificate,
/// Thread start, disconnect.
#[test]
fn basic_commissioning() {
    let mut fx = Fx::new(auth(true, OPEN), auth(false, OPEN), Vec::new());
    assert_eq!(
        fx.cmd(ty::GET_NETWORK_NAME, &[]),
        Rsp::Status(Status::Undefined)
    );
    assert_eq!(
        fx.cmd(ty::START_THREAD_INTERFACE, &[]),
        Rsp::Status(Status::InvalidState)
    );
    // Missing Network Key: Value Error; malformed: Parse Error.
    let mut no_key = Dataset::new();
    no_key.set_channel(15).unwrap();
    assert_eq!(
        fx.cmd(ty::SET_ACTIVE_DATASET, no_key.as_bytes()),
        Rsp::Status(Status::ValueError)
    );
    assert_eq!(
        fx.cmd(ty::SET_ACTIVE_DATASET, &[0, 5, 1]),
        Rsp::Status(Status::ParseError)
    );
    let partial = dataset("Home", false);
    assert_eq!(
        fx.cmd(ty::SET_ACTIVE_DATASET, &partial),
        Rsp::Status(Status::Success)
    );
    assert_eq!(fx.env.active, partial);
    assert_eq!(fx.env.cert.as_deref(), Some(PEER_DER));
    assert!(!fx.env.thread, "Thread stays down");
    // Writing again in the same link is allowed.
    assert_eq!(
        fx.cmd(ty::SET_ACTIVE_DATASET, &partial),
        Rsp::Status(Status::Success)
    );
    assert_eq!(
        fx.cmd(ty::GET_COMMISSIONER_CERTIFICATE, &[]),
        Rsp::Payload(PEER_DER.to_vec())
    );
    assert_eq!(
        fx.cmd(ty::GET_NETWORK_NAME, &[]),
        Rsp::Payload(b"Home".to_vec())
    );
    assert_eq!(
        fx.cmd(ty::GET_EXT_PAN_ID, &[]),
        Rsp::Payload(std::vec![0xde; 8])
    );
    assert_eq!(
        fx.cmd(ty::START_THREAD_INTERFACE, &[]),
        Rsp::Status(Status::Success)
    );
    assert!(fx.env.thread);
    assert_eq!(
        fx.cmd(ty::STOP_THREAD_INTERFACE, &[]),
        Rsp::Status(Status::Success)
    );
    // Disconnect: no response, link closed.
    fx.feed(&tlv(ty::DISCONNECT, &[]));
    assert!(fx.responses().is_empty());
    assert!(fx.tls.closed);
    assert_eq!(fx.agent.state(), TcatState::Enabled);
    let ev: Vec<_> = core::iter::from_fn(|| fx.agent.pop_event()).collect();
    assert!(ev.contains(&TcatEvent::Disconnected {
        dataset_written: false
    }));
    // Nothing is processed after the link closed.
    fx.feed(&tlv(ty::PING, &[1]));
    assert!(fx.responses().is_empty());
}

/// A device with a complete dataset at link start refuses Set Active
/// Dataset (section 13.9.4.11).
#[test]
fn commissioned_device_refuses_dataset() {
    let mut fx = Fx::new(auth(true, OPEN), auth(false, OPEN), dataset("Home", true));
    assert_eq!(
        fx.cmd(ty::SET_ACTIVE_DATASET, &dataset("Home", false)),
        Rsp::Status(Status::InvalidState)
    );
}

/// Section 13.12.4: the Device requires the PSKd; proof of possession
/// through the challenge, wrong and right hashes, and the reverse proof.
#[test]
fn commissioning_with_pskd() {
    let dev = [flag::PSKD, 0, 0, 0];
    let mut fx = Fx::new(auth(true, OPEN), auth(false, dev), Vec::new());
    let ds = dataset("Home", false);
    assert_eq!(
        fx.cmd(ty::SET_ACTIVE_DATASET, &ds),
        Rsp::Status(Status::Unauthorized)
    );
    // No challenge yet.
    assert_eq!(
        fx.cmd(ty::PRESENT_PSKD_HASH, &hash(b"J01NME", &[0; 8])),
        Rsp::Status(Status::HashError)
    );
    let c = fx.challenge();
    assert_eq!(
        fx.cmd(ty::PRESENT_PSKD_HASH, &hash(b"J01NMF", &c)),
        Rsp::Status(Status::HashError)
    );
    assert_eq!(
        fx.cmd(ty::PRESENT_PSKD_HASH, &hash(b"J01NME", &c)[..31]),
        Rsp::Status(Status::HashError)
    );
    assert_eq!(
        fx.cmd(ty::PRESENT_PSKD_HASH, &hash(b"J01NME", &c)),
        Rsp::Status(Status::Success)
    );
    assert_eq!(
        fx.cmd(ty::SET_ACTIVE_DATASET, &ds),
        Rsp::Status(Status::Success)
    );
    // A later failed presentation revokes the authorization.
    assert_eq!(
        fx.cmd(ty::PRESENT_PSKD_HASH, &[0; 32]),
        Rsp::Status(Status::HashError)
    );
    assert_eq!(
        fx.cmd(ty::SET_ACTIVE_DATASET, &ds),
        Rsp::Status(Status::Unauthorized)
    );
    // The Commissioner checks the Device's PSKd.
    let mine = [9u8, 8, 7, 6, 5, 4, 3, 2];
    assert_eq!(
        fx.cmd(ty::REQUEST_PSKD_HASH, &mine),
        Rsp::Payload(hash(b"J01NME", &mine).to_vec())
    );
    assert_eq!(
        fx.cmd(ty::REQUEST_PSKD_HASH, &mine[..7]),
        Rsp::Status(Status::ParseError)
    );
    // The link ends: the proof does not carry over.
    fx.agent.disconnected();
    let ev: Vec<_> = core::iter::from_fn(|| fx.agent.pop_event()).collect();
    assert!(ev.contains(&TcatEvent::Disconnected {
        dataset_written: true
    }));
}

/// Extraction and decommissioning gated on the PSKc (section 13.12.5).
#[test]
fn extraction_and_decommission_with_pskc() {
    let dev = [0, flag::PSKC, flag::PSKC, 0];
    let ds = dataset("Home", true);
    let mut fx = Fx::new(auth(true, OPEN), auth(false, dev), ds.clone());
    assert_eq!(
        fx.cmd(ty::GET_ACTIVE_DATASET, &[]),
        Rsp::Status(Status::Unauthorized)
    );
    let c = fx.challenge();
    assert_eq!(
        fx.cmd(ty::PRESENT_PSKC_HASH, &hash(&PSKC.0, &c)),
        Rsp::Status(Status::Success)
    );
    match fx.cmd(ty::GET_ACTIVE_DATASET, &[]) {
        Rsp::Payload(p) => {
            assert_eq!(p, ds);
            assert!(crate::tlv::Tlvs(&p).network_key().is_ok());
        }
        r => panic!("{r:?}"),
    }
    assert_eq!(fx.cmd(ty::DECOMMISSION, &[]), Rsp::Status(Status::Success));
    assert!(fx.env.decommissioned && fx.env.active.is_empty());
    assert_eq!(fx.env.cert.as_deref(), Some(PEER_DER));
    // The PSKc proof is gone with the dataset.
    assert_eq!(
        fx.cmd(ty::DECOMMISSION, &[]),
        Rsp::Status(Status::Unauthorized)
    );
}

/// TLV framing over the stream: split, batched, extended, oversized,
/// unsupported.
#[test]
fn framing_and_general_commands() {
    let mut fx = Fx::new(auth(true, OPEN), auth(false, OPEN), dataset("Home", true));
    // Split across three reads.
    let p = tlv(ty::PING, b"hello");
    fx.feed(&p[..1]);
    fx.feed(&p[1..3]);
    assert!(fx.tls.sent.is_empty());
    fx.feed(&p[3..]);
    assert_eq!(fx.responses(), [Rsp::Payload(b"hello".to_vec())]);
    // Two commands in one read.
    let mut two = tlv(ty::GET_DEVICE_ID, &[]);
    two.extend(tlv(0x05, &[]));
    fx.feed(&two);
    assert_eq!(
        fx.responses(),
        [
            Rsp::Payload(std::vec![0x18, 0xb4, 0x30, 0, 0, 0, 0, 1]),
            Rsp::Status(Status::Unsupported)
        ]
    );
    // Extended TLV ping of 300 bytes, echoed as an extended response.
    let big = std::vec![0xab; 300];
    let req = tlv(ty::PING, &big);
    assert_eq!(req[1], 0xff);
    fx.feed(&req);
    let raw = fx.tls.sent.pop().unwrap();
    assert_eq!(&raw[..4], &[ty::RESPONSE_WITH_PAYLOAD, 0xff, 0x01, 0x2c]);
    assert_eq!(&raw[4..], &big[..]);
    // A command larger than the receive buffer: Value Error, skipped, the
    // next command works.
    let huge = tlv(ty::VENDOR_SPECIFIC, &std::vec![1; 900]);
    fx.feed(&huge[..500]);
    fx.feed(&huge[500..]);
    fx.feed(&tlv(ty::PING, &[7]));
    assert_eq!(
        fx.responses(),
        [Rsp::Status(Status::ValueError), Rsp::Payload(std::vec![7])]
    );
    // Ping limit, CCM / reserved types, unimplemented optional commands.
    assert_eq!(fx.cmd(ty::PING, &[0; 513]), Rsp::Status(Status::ValueError));
    assert_eq!(fx.cmd(0xa0, &[]), Rsp::Status(Status::Unsupported));
    assert_eq!(fx.cmd(0xf0, &[]), Rsp::Status(Status::Unsupported));
    assert_eq!(
        fx.cmd(ty::GET_PROVISIONING_URL, &[]),
        Rsp::Status(Status::Undefined)
    );
    assert_eq!(
        fx.cmd(ty::GET_DIAGNOSTIC_TLVS, &[0, 1]),
        Rsp::Status(Status::Unsupported)
    );
    assert_eq!(
        fx.cmd(ty::VENDOR_SPECIFIC, &[1]),
        Rsp::Status(Status::Unsupported)
    );
    // Application data to protocol 2.
    assert_eq!(
        fx.cmd(ty::SEND_APPLICATION_DATA_1 + 1, b"x"),
        Rsp::Payload(std::vec![2, b'x'])
    );
    assert_eq!(
        fx.cmd(ty::GET_APPLICATION_LAYERS, &[]),
        Rsp::Payload(Vec::new())
    );
}

/// Stopping the agent closes the link.
#[test]
fn stop_closes_link() {
    let mut fx = Fx::new(auth(true, OPEN), auth(false, OPEN), Vec::new());
    fx.agent.stop(&mut fx.tls);
    assert!(fx.tls.closed);
    assert_eq!(fx.agent.state(), TcatState::Disabled);
    fx.feed(&tlv(ty::PING, &[1]));
    assert!(fx.responses().is_empty());
}
