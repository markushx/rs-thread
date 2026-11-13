//! KeyManager wired into the MAC: end-to-end secured frame + enhanced ACK
//! between two MACs, key sequence switches and radios with hardware security.

extern crate std;

use std::vec::Vec;

use opentrust_core::crypto::{SecurityLevel, SoftCrypto};
use opentrust_core::time::Instant;
use opentrust_core::types::{ExtAddress, NetworkKey};
use opentrust_platform::radio::{AckSecurity, Capabilities, PsduTxInfo, RadioCaps};

use super::util::*;
use crate::frame::{
    Address, Frame, FrameBuilder, FrameMut, FrameType, FrameVersion, KeyIdentifier, SecurityHeader,
};
use crate::mac::*;
use crate::security::{KeyManager, KeySeqUpdate};

type SecMac = Mac<KeyManager<SoftCrypto>, FakeRng>;

const NK: [u8; 16] = [
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
];

fn sec_mac(caps: RadioCaps, ext: ExtAddress) -> SecMac {
    let km = KeyManager::new(SoftCrypto, NetworkKey(NK));
    let mut m = Mac::new(caps, ext, km, FakeRng::new(0));
    m.set_pan_id(PAN);
    m.set_channel(CH).unwrap();
    m
}

/// 2015 data frame from `src` to `dst` (extended addresses), key ID mode 1.
fn secured_2015(seq: u8, dst: ExtAddress, src: ExtAddress, ack: bool, payload: &[u8]) -> Vec<u8> {
    let mut buf = [0u8; 127];
    let n = FrameBuilder::new(&mut buf)
        .frame_type(FrameType::Data)
        .version(FrameVersion::V2015)
        .sequence(seq)
        .pan_id(PAN)
        .dst(Address::Extended(dst))
        .src(Address::Extended(src))
        .ack_request(ack)
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

/// A sends a secured frame to B, B acks. Returns (A's TxDone result, B's
/// received frame, the ACK frame as sent).
fn exchange(a: &mut SecMac, b: &mut SecMac, now: u64) -> (TxResult, RxFrame, Vec<u8>) {
    actions(a, t(now));
    actions(b, t(now));
    let f = secured_2015(0, PEER_EXT, OWN_EXT, true, b"secured hello");
    a.transmit(TxHandle(7), &f).unwrap();
    let data = tx_of(&actions(a, t(now))).expect("data frame");
    a.on_tx_done(TxOutcome::Sent, t(now + 1));
    b.on_rx(&data.psdu, &info(CH), t(now + 1));
    let ack = tx_of(&actions(b, t(now + 2))).expect("enh-ACK");
    b.on_tx_done(TxOutcome::Sent, t(now + 3));
    a.on_rx(&ack.psdu, &info(CH), t(now + 4));
    let Some(Event::TxDone { handle, result }) = events(a).into_iter().next() else {
        panic!("no TxDone")
    };
    assert_eq!(handle, TxHandle(7));
    let Some(Event::Received(rx)) = events(b).into_iter().next() else {
        panic!("no Received")
    };
    (result, rx, frame_of(&ack).to_vec())
}

#[test]
fn secured_data_frame_and_enh_ack_end_to_end() {
    let mut a = sec_mac(bare_caps(), OWN_EXT);
    let mut b = sec_mac(bare_caps(), PEER_EXT);
    let (res, rx, ack) = exchange(&mut a, &mut b, 0);
    assert_eq!(
        res,
        Ok(TxSuccess {
            frame_pending: false,
            retries: 0
        })
    );
    let sec = rx.security.unwrap();
    assert_eq!(sec.key_sequence, Some(0));
    assert_eq!(sec.frame_counter, 0);
    assert_eq!(rx.parse().unwrap().payload(), b"secured hello");
    // The ACK is a secured enhanced ACK with B's first frame counter and the
    // key index of the acked frame.
    let f = Frame::parse(&ack).unwrap();
    assert_eq!(f.frame_type(), FrameType::Ack);
    assert_eq!(f.version(), FrameVersion::V2015);
    let s = f.security_header().unwrap();
    assert_eq!(s.frame_counter, Some(0));
    assert_eq!(s.key, KeyIdentifier::Index(1));
    assert_eq!(a.security().frame_counter(), 1);
    assert_eq!(b.security().frame_counter(), 1);
    assert_eq!(a.counters().rx_err_sec, 0);
}

#[test]
fn key_sequence_switch_is_followed_by_peer() {
    let mut a = sec_mac(bare_caps(), OWN_EXT);
    let mut b = sec_mac(bare_caps(), PEER_EXT);
    // A moves to key sequence 1; B (still at 0) holds it as its "next" key.
    assert!(
        a.security_mut()
            .set_key_sequence(1, KeySeqUpdate::GUARDED, Instant::ZERO)
            .unwrap()
    );
    let (res, rx, ack) = exchange(&mut a, &mut b, 0);
    assert!(res.is_ok());
    assert_eq!(rx.security.unwrap().key_sequence, Some(1));
    // The ACK carries the key index of the acked frame (2 = key sequence 1).
    let f = Frame::parse(&ack).unwrap();
    assert_eq!(f.security_header().unwrap().key, KeyIdentifier::Index(2));
    // The neighbor layer then switches B, as OT's ProcessReceiveSecurity does.
    assert!(b.security_mut().on_rx_key_sequence(1, Instant::ZERO));
    let (res, rx, _) = exchange(&mut a, &mut b, 100);
    assert!(res.is_ok());
    assert_eq!(rx.security.unwrap().key_sequence, Some(1));

    // A frame secured two sequences ahead is rejected.
    assert!(
        a.security_mut()
            .set_key_sequence(3, KeySeqUpdate::FORCE, Instant::ZERO)
            .unwrap()
    );
    actions(&mut a, t(200));
    let f = secured_2015(0, PEER_EXT, OWN_EXT, true, b"x");
    a.transmit(TxHandle(8), &f).unwrap();
    let data = tx_of(&actions(&mut a, t(200))).unwrap();
    b.on_rx(&data.psdu, &info(CH), t(201));
    assert_eq!(b.counters().rx_err_sec, 1);
}

fn hw_caps() -> RadioCaps {
    let mut c = bare_caps();
    c.phy |= Capabilities::TRANSMIT_SEC;
    c
}

fn key_actions(m: &mut SecMac, now: u64) -> Vec<RadioAction> {
    actions(m, t(now))
        .into_iter()
        .filter(|a| {
            matches!(
                a,
                RadioAction::SetMacKeys(_) | RadioAction::SetMacFrameCounter { .. }
            )
        })
        .collect()
}

#[test]
fn hw_security_radio_gets_keys_and_counters() {
    let mut m = sec_mac(hw_caps(), OWN_EXT);
    // Init: keys, then the counter (not "if larger").
    let acts = key_actions(&mut m, 0);
    let expected = m.security().mac_keys();
    assert_eq!(
        acts,
        [
            RadioAction::SetMacKeys(Some(expected)),
            RadioAction::SetMacFrameCounter {
                frame_counter: 0,
                if_larger: false
            }
        ]
    );
    assert!(key_actions(&mut m, 1).is_empty());

    // The radio secures a frame itself and reports counter 5.
    let f = secured_2015(0, PEER_EXT, OWN_EXT, false, b"abc");
    m.transmit(TxHandle(1), &f).unwrap();
    let tx = tx_of(&actions(&mut m, t(2))).unwrap();
    assert!(!tx.info.security_processed);
    assert!(!tx.info.header_updated);
    let mut done = tx.psdu.clone();
    let n = done.len() - 2;
    FrameMut::new(&mut done[..n])
        .unwrap()
        .set_frame_counter(5)
        .unwrap();
    m.on_tx_frame_updated(
        &done,
        &PsduTxInfo {
            header_updated: true,
            security_processed: true,
            ..tx.info
        },
    );
    m.on_tx_done(TxOutcome::Sent, t(3));
    assert_eq!(m.security().frame_counter(), 6);
    // Nothing to push: the radio is already ahead.
    assert!(key_actions(&mut m, 4).is_empty());

    // Radio-secured enhanced ACK reported with a received frame.
    let mut i = info(CH);
    i.ack_security = Some(AckSecurity {
        frame_counter: 9,
        key_id: m.security().key_index(),
    });
    let rx = data_frame(1, short(OWN_SHORT), ext(PEER_EXT), false, b"x");
    m.on_rx(&psdu(&rx), &i, t(5));
    assert_eq!(m.security().frame_counter(), 10);
    assert!(key_actions(&mut m, 6).is_empty());

    // Key sequence switch: new keys and a counter reset to 0.
    m.security_mut()
        .set_key_sequence(1, KeySeqUpdate::FORCE, Instant::ZERO)
        .unwrap();
    let acts = key_actions(&mut m, 7);
    let expected = m.security().mac_keys();
    assert_eq!(
        acts,
        [
            RadioAction::SetMacKeys(Some(expected)),
            RadioAction::SetMacFrameCounter {
                frame_counter: 0,
                if_larger: false
            }
        ]
    );
    // Network key change likewise.
    assert!(m.security_mut().set_network_key(NetworkKey([7; 16])));
    assert_eq!(key_actions(&mut m, 8).len(), 2);
}

#[test]
fn software_secured_frames_raise_radio_counter_for_hw_acks() {
    // RECEIVE_TIMING radios secure enhanced ACKs themselves: data frames
    // secured in software must push their counter to the radio.
    let mut c = bare_caps();
    c.phy |= Capabilities::RECEIVE_TIMING;
    let mut m = sec_mac(c, OWN_EXT);
    assert_eq!(key_actions(&mut m, 0).len(), 2);
    let f = secured_2015(0, PEER_EXT, OWN_EXT, false, b"abc");
    m.transmit(TxHandle(1), &f).unwrap();
    // The counter reaches the radio before the frame goes out.
    let acts = actions(&mut m, t(1));
    assert_eq!(
        acts[0],
        RadioAction::SetMacFrameCounter {
            frame_counter: 1,
            if_larger: true
        }
    );
    let tx = tx_of(&acts).unwrap();
    assert!(tx.info.security_processed);
    m.on_tx_done(TxOutcome::Sent, t(2));
    assert!(key_actions(&mut m, 3).is_empty());
}

#[test]
fn hw_security_frame_key_index_follows_a_key_sequence_switch() {
    // A frame queued before a key sequence switch carries the old key index;
    // the radio finds its key by the index in the frame, so the MAC brings it
    // up to date for the attempt (otherwise the radio rejects the frame).
    let mut m = sec_mac(hw_caps(), OWN_EXT);
    key_actions(&mut m, 0);
    let f = secured_2015(0, PEER_EXT, OWN_EXT, false, b"abc");
    assert_eq!(
        Frame::parse(&f).unwrap().security_header().unwrap().key,
        KeyIdentifier::Index(1)
    );
    m.transmit(TxHandle(1), &f).unwrap();
    m.security_mut()
        .set_key_sequence(4, KeySeqUpdate::FORCE, Instant::ZERO)
        .unwrap();
    let acts = actions(&mut m, t(1));
    let expected = m.security().mac_keys();
    assert!(acts.contains(&RadioAction::SetMacKeys(Some(expected))));
    let tx = tx_of(&acts).unwrap();
    let n = tx.psdu.len() - 2;
    let sent = Frame::parse(&tx.psdu[..n]).unwrap();
    assert_eq!(
        sent.security_header().unwrap().key,
        KeyIdentifier::Index(expected.key_id)
    );
    assert_eq!(expected.key_id, 5);
}

#[test]
fn hw_security_radio_gets_mode2_frames_secured_in_software() {
    // The radio knows the key ID mode 1 keys only (it rejects other key
    // identifiers): a key ID mode 2 frame (MLE Announce) is secured by the MAC.
    let mut m = sec_mac(hw_caps(), OWN_EXT);
    key_actions(&mut m, 0);
    let mut buf = [0u8; 127];
    let n = FrameBuilder::new(&mut buf)
        .frame_type(FrameType::Data)
        .version(FrameVersion::V2015)
        .sequence(0)
        .pan_id(PAN)
        .dst(Address::Extended(PEER_EXT))
        .src(Address::Extended(OWN_EXT))
        .security(SecurityHeader::new(
            SecurityLevel::EncMic32,
            0,
            KeyIdentifier::Source4 {
                source: [0xff; 4],
                index: 0xff,
            },
        ))
        .payload(b"announce")
        .build()
        .unwrap();
    m.transmit(TxHandle(1), &buf[..n]).unwrap();
    let tx = tx_of(&actions(&mut m, t(1))).unwrap();
    assert!(tx.info.security_processed);
    // Encrypted in place: the payload is no longer in clear.
    assert!(!tx.psdu.windows(8).any(|w| w == b"announce"));
}
