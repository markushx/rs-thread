//! Test support: a Joiner that discovered one Joiner Router and talks to
//! it through relay TLVs built by the test (the Joiner Router's role).

use std::vec::Vec;

use rs_thread_coap::endpoint::Peer;
use rs_thread_core::Result;
use rs_thread_core::bytes::Writer;
use rs_thread_core::crypto::SoftCrypto;
use rs_thread_core::crypto::ecjpake::SoftP256;
use rs_thread_core::time::{Duration, Instant};
use rs_thread_core::types::{ExtAddress, Kek, ipv6};
use rs_thread_mle::env::DiscoveryResponseInfo;

use crate::dataset::Dataset;
use crate::discovery::{ResponseContent, build_response_tlv};
use crate::joiner::{Joiner, JoinerConfig, JoinerEvent, JoinerIo, JoinerState};
use crate::steering::{SteeringData, compute_joiner_id};
use crate::test_rng::TestRng;
use crate::tlv::{Tlvs, WriterExt};

pub const EUI64: ExtAddress = ExtAddress([0x18, 0xb4, 0x30, 0, 0, 0, 0, 1]);
pub const ROUTER: ExtAddress = ExtAddress([0x12, 0x34, 0, 0, 0, 0, 0, 2]);
pub const ROUTER_RLOC: u16 = 0x0800;

#[derive(Default)]
pub struct JIo {
    pub unsecured: Vec<Vec<u8>>,
    pub kek: Option<Kek>,
    pub events: Vec<JoinerEvent>,
}

impl JoinerIo for JIo {
    fn send_discovery_request(&mut self, _c: u8, _p: u16, _t: &[u8]) -> Result<()> {
        Ok(())
    }
    fn set_ext_address(&mut self, _ext: &ExtAddress) {}
    fn set_pan(&mut self, _c: u8, _p: u16) -> Result<()> {
        Ok(())
    }
    fn set_unsecure_port(&mut self, _port: u16, _allow: bool) {}
    fn send_unsecured(&mut self, _sp: u16, _dst: &Peer, payload: &[u8]) -> Result<()> {
        self.unsecured.push(payload.to_vec());
        Ok(())
    }
    fn set_kek(&mut self, kek: Option<&Kek>) {
        self.kek = kek.cloned();
    }
    fn send_kek(&mut self, _sp: u16, _dst: &Peer, _p: &[u8]) -> Result<()> {
        Ok(())
    }
    fn save_dataset(&mut self, _d: &Dataset) {}
    fn event(&mut self, e: JoinerEvent) {
        self.events.push(e);
    }
}

pub struct JoinerFx {
    pub j: Joiner<SoftCrypto, SoftP256>,
    pub io: JIo,
    pub rng: TestRng,
    pub now: Instant,
    pub id: ExtAddress,
}

impl JoinerFx {
    /// Started, discovered `ROUTER` (with `steering`), ClientHello queued.
    pub fn new(pskd: &str, steering: &SteeringData) -> Self {
        let mut j = Joiner::new(SoftCrypto, SoftP256);
        let mut io = JIo::default();
        let mut rng = TestRng(1234);
        let now = Instant::from_secs(100);
        j.start(
            now,
            &mut rng,
            &mut io,
            &EUI64,
            pskd,
            &JoinerConfig {
                vendor_name: "V",
                vendor_model: "M",
                vendor_sw_version: "1",
                ..Default::default()
            },
            1 << 15,
        )
        .unwrap();
        j.poll(now, &mut rng, &mut io);
        let ext_pan = rs_thread_core::types::ExtPanId([1; 8]);
        let name = rs_thread_core::types::NetworkName::new("RsThread").unwrap();
        let mut b = [0u8; 128];
        let n = build_response_tlv(
            &ResponseContent {
                ext_pan_id: &ext_pan,
                network_name: &name,
                steering_data: Some(steering),
                joiner_udp_port: 1000,
                native_commissioner: None,
                commercial_commissioning: false,
                domain_name: None,
            },
            &mut b,
        )
        .unwrap();
        j.handle_discovery_response(
            &DiscoveryResponseInfo {
                ext_address: ROUTER,
                pan_id: Some(0x1234),
                channel: Some(15),
                rss: Some(-50),
                lqi: None,
            },
            &b[..n],
        );
        let now = now + Duration::from_millis(400);
        j.poll(now, &mut rng, &mut io);
        assert_eq!(j.state(), JoinerState::Connect);
        Self {
            j,
            io,
            rng,
            now,
            id: compute_joiner_id(&SoftCrypto, &EUI64),
        }
    }

    /// The `/c/rx` TLVs a Joiner Router builds for datagram `d`.
    pub fn relay_rx(&self, d: &[u8]) -> Vec<u8> {
        let mut b = [0u8; 1100];
        let mut w = Writer::new(&mut b);
        w.joiner_udp_port(1000).unwrap();
        w.joiner_iid(&self.id.to_iid()).unwrap();
        w.joiner_router_locator(ROUTER_RLOC).unwrap();
        w.joiner_dtls_encapsulation(d).unwrap();
        w.written().to_vec()
    }

    /// Deliver the records of a `/c/tx` to the Joiner.
    pub fn deliver(&mut self, tx: &[u8]) {
        let t = Tlvs(tx);
        assert_eq!(t.joiner_iid(), Ok(self.id.to_iid()));
        let router = Peer::new(ipv6::link_local(&ROUTER), 1000);
        self.j.handle_udp(
            self.now,
            &mut self.rng,
            &mut self.io,
            &router,
            t.joiner_dtls_encapsulation().unwrap(),
        );
    }
}
