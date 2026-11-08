//! Differential tests of the codec against the `coap-lite` crate (dev-only
//! oracle; the production codec is allocation-free).

use super::*;
use coap_lite::{CoapOption, MessageType, Packet};
use std::collections::BTreeMap;
use std::collections::LinkedList;
use std::vec::Vec;

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D) >> 11
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
    fn pick<T: Copy>(&mut self, v: &[T]) -> T {
        v[self.below(v.len())]
    }
    fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.next() as u8).collect()
    }
}

struct Spec {
    ty: u8,
    code: u8,
    mid: u16,
    token: Vec<u8>,
    options: Vec<(u16, Vec<u8>)>,
    payload: Vec<u8>,
}

fn random_spec(r: &mut Rng) -> Spec {
    let empty = r.below(8) == 0;
    let ty = r.below(4) as u8;
    let (code, token, options, payload) = if empty {
        (0, Vec::new(), Vec::new(), Vec::new())
    } else {
        // Request methods, success, client and server error classes.
        let code = r.pick(&[
            1u8, 2, 3, 4, 0x41, 0x44, 0x45, 0x5f, 0x80, 0x84, 0x8f, 0xa0, 0xa5,
        ]);
        let tl = r.below(9);
        let mut options = Vec::new();
        let mut number = 0u16;
        let mut size = 12usize; // stays below the builder's 512-byte header limit
        for _ in 0..r.below(8) {
            let delta = r.pick(&[0u16, 0, 1, 5, 11, 12, 13, 14, 268, 269, 270, 1000]);
            number = match number.checked_add(delta) {
                Some(n) => n,
                None => break,
            };
            let len = r.pick(&[0usize, 1, 5, 12, 13, 14, 100, 268, 269, 300]);
            size += len + 5;
            if size > 500 {
                break;
            }
            options.push((number, r.bytes(len)));
        }
        let plen = r.pick(&[0usize, 0, 1, 10, 200]);
        (code, r.bytes(tl), options, r.bytes(plen))
    };
    Spec {
        ty,
        code,
        mid: r.next() as u16,
        token,
        options,
        payload,
    }
}

fn ours_encode(s: &Spec) -> Vec<u8> {
    let mut buf = std::vec![0u8; 4096];
    let ty = Type::from_bits(s.ty);
    let mut b = MessageBuilder::new(&mut buf, ty, Code(s.code), s.mid, &s.token).unwrap();
    for (n, v) in &s.options {
        // The builder's own header limit applies; skip oversized specs.
        b.option(*n, v).unwrap();
    }
    let n = b.finish_with_payload(&s.payload).unwrap();
    buf.truncate(n);
    buf
}

fn lite_encode(s: &Spec) -> Vec<u8> {
    let mut p = Packet::new();
    p.header.set_version(1);
    p.header.set_type(match s.ty {
        0 => MessageType::Confirmable,
        1 => MessageType::NonConfirmable,
        2 => MessageType::Acknowledgement,
        _ => MessageType::Reset,
    });
    p.header.code = s.code.into();
    p.header.message_id = s.mid;
    p.set_token(s.token.clone());
    for (n, v) in &s.options {
        p.add_option(CoapOption::from(*n), v.clone());
    }
    p.payload = s.payload.clone();
    p.to_bytes_unlimited().unwrap()
}

fn lite_options(p: &Packet) -> BTreeMap<u16, Vec<Vec<u8>>> {
    p.options()
        .map(|(n, l): (&u16, &LinkedList<Vec<u8>>)| (*n, l.iter().cloned().collect()))
        .collect()
}

fn our_options(m: &Message<'_>) -> BTreeMap<u16, Vec<Vec<u8>>> {
    let mut out: BTreeMap<u16, Vec<Vec<u8>>> = BTreeMap::new();
    for o in m.options() {
        out.entry(o.number).or_default().push(o.value.to_vec());
    }
    out
}

fn assert_same(m: &Message<'_>, p: &Packet, what: &str) {
    assert_eq!(m.ty() as u8, p.header.get_type() as u8, "{what}: type");
    assert_eq!(m.code().0, u8::from(p.header.code), "{what}: code");
    assert_eq!(m.message_id(), p.header.message_id, "{what}: mid");
    assert_eq!(m.token(), p.get_token(), "{what}: token");
    assert_eq!(our_options(m), lite_options(p), "{what}: options");
    assert_eq!(m.payload(), &p.payload[..], "{what}: payload");
}

#[test]
fn our_encoding_parses_identically_in_coap_lite() {
    let mut r = Rng(0xdead_beef_1234_5678);
    for _ in 0..3000 {
        let s = random_spec(&mut r);
        let bytes = ours_encode(&s);
        let m = Message::parse(&bytes).unwrap();
        let p = Packet::from_bytes(&bytes).unwrap();
        assert_same(&m, &p, "ours->lite");
        // And the oracle's view equals the spec we generated.
        assert_eq!(p.get_token(), &s.token[..]);
        assert_eq!(p.payload, s.payload);
    }
}

#[test]
fn coap_lite_encoding_parses_identically_here() {
    let mut r = Rng(0x0123_4567_89ab_cdef);
    for _ in 0..3000 {
        let s = random_spec(&mut r);
        let bytes = lite_encode(&s);
        let m = Message::parse(&bytes).unwrap();
        let p = Packet::from_bytes(&bytes).unwrap();
        assert_same(&m, &p, "lite->ours");
    }
}

#[test]
fn encodings_are_byte_identical() {
    let mut r = Rng(42);
    for _ in 0..3000 {
        let s = random_spec(&mut r);
        assert_eq!(ours_encode(&s), lite_encode(&s));
    }
}
