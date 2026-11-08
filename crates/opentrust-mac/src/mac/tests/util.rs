//! Shared test helpers: fake RNG, recording frame security, frame builders.

extern crate std;

use core::convert::Infallible;
use std::vec::Vec;

use opentrust_core::crypto::SecurityLevel;
use opentrust_core::time::{Duration, Instant};
use opentrust_core::types::{ExtAddress, PanId, ShortAddress};
use opentrust_core::{Error, Result};
use opentrust_platform::radio::{
    Capabilities, MacCapabilities, PsduRxInfo, RadioCaps, sim::rx_info,
};
use rand_core::TryRng;

use crate::frame::{
    Address, Frame, FrameBuilder, FrameMut, FrameType, FrameVersion, KeyIdentifier, MacCommand,
    SecurityHeader,
};
use crate::frame_security::{FrameSecurity, NoSecurity, RxSecurityInfo};
use crate::mac::{Mac, Psdu, RadioAction, TxAction, fcs};

pub const PAN: PanId = PanId(0xface);
pub const OWN_SHORT: ShortAddress = ShortAddress(0x1000);
pub const OWN_EXT: ExtAddress = ExtAddress([0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17]);
pub const PEER_SHORT: ShortAddress = ShortAddress(0x2000);
pub const PEER_EXT: ExtAddress = ExtAddress([0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27]);
pub const CH: u8 = 15;

/// A "random" source returning a fixed value (and counting the calls).
#[derive(Debug, Clone, Copy)]
pub struct FakeRng {
    pub value: u32,
    pub calls: u32,
}

impl FakeRng {
    pub const fn new(value: u32) -> Self {
        Self { value, calls: 0 }
    }
}

impl TryRng for FakeRng {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> core::result::Result<u32, Infallible> {
        self.calls += 1;
        Ok(self.value)
    }

    fn try_next_u64(&mut self) -> core::result::Result<u64, Infallible> {
        self.calls += 1;
        Ok(u64::from(self.value))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> core::result::Result<(), Infallible> {
        dst.fill(self.value as u8);
        Ok(())
    }
}

/// Mock security that records its calls. "Encryption" XORs the payload
/// with 0x5a and writes a MIC of 0xaa bytes; the frame counter counts up.
#[derive(Debug, Default)]
pub struct RecordingSecurity {
    pub tx_calls: Vec<ExtAddress>,
    pub rx_calls: Vec<ExtAddress>,
    pub counter: u32,
}

impl FrameSecurity for RecordingSecurity {
    fn secure_tx(&mut self, psdu: &mut [u8], src_ext: &ExtAddress) -> Result<()> {
        self.tx_calls.push(*src_ext);
        if !Frame::parse(psdu)?.security_enabled() {
            return Ok(());
        }
        let mut m = FrameMut::new(psdu)?;
        m.set_frame_counter(self.counter)?;
        self.counter += 1;
        let parts = m.parts_mut()?;
        for b in parts.payload.iter_mut() {
            *b ^= 0x5a;
        }
        parts.mic.fill(0xaa);
        Ok(())
    }

    fn unsecure_rx(
        &mut self,
        psdu: &mut [u8],
        src_ext: &ExtAddress,
    ) -> Result<Option<RxSecurityInfo>> {
        self.rx_calls.push(*src_ext);
        let f = Frame::parse(psdu)?;
        let Some(sh) = f.security_header().copied() else {
            return Ok(None);
        };
        let mut m = FrameMut::new(psdu)?;
        let parts = m.parts_mut()?;
        if parts.mic.iter().any(|b| *b != 0xaa) {
            return Err(Error::Security);
        }
        for b in parts.payload.iter_mut() {
            *b ^= 0x5a;
        }
        Ok(Some(RxSecurityInfo {
            level: sh.level,
            key_id_mode: sh.key_id_mode(),
            key_sequence: None,
            frame_counter: sh.frame_counter.unwrap_or(0),
        }))
    }
}

/// A bare PHY: everything in software.
pub fn bare_caps() -> RadioCaps {
    RadioCaps::default()
}

/// A full MAC offload radio (CSMA, retries, ACK timeout, ACKs, filters,
/// source match, energy scan).
pub fn full_caps() -> RadioCaps {
    RadioCaps {
        phy: Capabilities::CSMA_BACKOFF
            | Capabilities::ACK_TIMEOUT
            | Capabilities::TRANSMIT_RETRIES
            | Capabilities::ENERGY_SCAN,
        mac: MacCapabilities::all(),
        ..RadioCaps::default()
    }
}

pub type TestMac<S = NoSecurity> = Mac<S, FakeRng>;

pub fn mac_with<S: FrameSecurity>(caps: RadioCaps, sec: S, rng: u32) -> TestMac<S> {
    let mut m = Mac::new(caps, OWN_EXT, sec, FakeRng::new(rng));
    m.set_pan_id(PAN);
    m.set_short_address(OWN_SHORT);
    m.set_channel(CH).unwrap();
    m
}

pub fn mac(caps: RadioCaps, rng: u32) -> TestMac {
    mac_with(caps, NoSecurity, rng)
}

pub fn t(us: u64) -> Instant {
    Instant::from_micros(us)
}

pub fn ms(v: u64) -> Duration {
    Duration::from_millis(v)
}

/// Collect actions until the MAC has nothing to do or waits for a
/// completion.
pub fn actions<S: FrameSecurity>(m: &mut TestMac<S>, now: Instant) -> Vec<RadioAction> {
    let mut v = Vec::new();
    while let Some(a) = m.poll_action(now) {
        let stop = matches!(a, RadioAction::Transmit(_) | RadioAction::EnergyScan { .. });
        v.push(a);
        if stop {
            break;
        }
    }
    v
}

/// The transmit action among `acts`, if any.
pub fn tx_of(acts: &[RadioAction]) -> Option<TxAction> {
    acts.iter().find_map(|a| match a {
        RadioAction::Transmit(t) => Some(t.clone()),
        _ => None,
    })
}

/// Drain all events.
pub fn events<S: FrameSecurity>(m: &mut TestMac<S>) -> Vec<crate::mac::Event> {
    let mut v = Vec::new();
    while let Some(e) = m.poll_event() {
        v.push(e);
    }
    v
}

/// Frame (without FCS) of a PSDU from a transmit action.
pub fn frame_of(tx: &TxAction) -> &[u8] {
    &tx.psdu[..tx.psdu.len() - 2]
}

/// Append the FCS.
pub fn psdu(frame: &[u8]) -> Psdu {
    let mut p = Psdu::from_slice(frame).unwrap();
    p.extend_from_slice(&fcs(frame)).unwrap();
    p
}

pub fn info(channel: u8) -> PsduRxInfo {
    rx_info(channel)
}

/// Unsecured 2006 data frame.
pub fn data_frame(seq: u8, dst: Address, src: Address, ack: bool, payload: &[u8]) -> Vec<u8> {
    let mut buf = [0u8; 127];
    let n = FrameBuilder::new(&mut buf)
        .frame_type(FrameType::Data)
        .version(FrameVersion::V2006)
        .sequence(seq)
        .pan_id(PAN)
        .dst(dst)
        .src(src)
        .ack_request(ack)
        .payload(payload)
        .build()
        .unwrap();
    buf[..n].to_vec()
}

/// Secured (EncMic32, key ID mode 1) 2006 data frame, plaintext payload.
pub fn secured_data_frame(seq: u8, dst: Address, src: Address, payload: &[u8]) -> Vec<u8> {
    let mut buf = [0u8; 127];
    let n = FrameBuilder::new(&mut buf)
        .frame_type(FrameType::Data)
        .version(FrameVersion::V2006)
        .sequence(seq)
        .pan_id(PAN)
        .dst(dst)
        .src(src)
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

/// MAC Data Request (unsecured) from `src` to `dst`.
pub fn data_request(seq: u8, dst: Address, src: Address) -> Vec<u8> {
    let mut buf = [0u8; 127];
    let n = FrameBuilder::new(&mut buf)
        .frame_type(FrameType::MacCmd)
        .version(FrameVersion::V2006)
        .sequence(seq)
        .pan_id(PAN)
        .dst(dst)
        .src(src)
        .ack_request(true)
        .command(MacCommand::DataRequest)
        .build()
        .unwrap();
    buf[..n].to_vec()
}

/// Immediate ACK frame (without FCS).
pub fn imm_ack(seq: u8, fp: bool) -> Vec<u8> {
    let mut buf = [0u8; 8];
    let n = FrameBuilder::imm_ack(&mut buf, FrameVersion::V2006, seq, fp).unwrap();
    buf[..n].to_vec()
}

pub fn short(a: ShortAddress) -> Address {
    Address::Short(a)
}

pub fn ext(a: ExtAddress) -> Address {
    Address::Extended(a)
}

/// Sequence number of a transmitted frame.
pub fn seq_of(tx: &TxAction) -> u8 {
    Frame::parse(frame_of(tx)).unwrap().sequence().unwrap()
}
