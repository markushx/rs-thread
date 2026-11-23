//! HDLC-lite framing as used on the Spinel UART link (OpenThread
//! `Hdlc::Encoder` / `Hdlc::Decoder`).
//!
//! A frame is `0x7e`, the escaped payload, the escaped CRC-16/X.25 FCS
//! (little endian) and `0x7e`. The bytes `0x7e`, `0x7d`, `0x11`, `0x13` and
//! `0xf8` are sent as `0x7d` followed by the byte XOR `0x20`.

use crate::{Error, Result};

/// Frame delimiter.
pub const FLAG: u8 = 0x7e;
/// Escape marker.
pub const ESCAPE: u8 = 0x7d;
/// Initial FCS value.
pub const INIT_FCS: u16 = 0xffff;
/// FCS value of a frame including its (valid) FCS.
pub const GOOD_FCS: u16 = 0xf0b8;
/// Size of the FCS in bytes.
pub const FCS_SIZE: usize = 2;

const XON: u8 = 0x11;
const XOFF: u8 = 0x13;
const SPECIAL: u8 = 0xf8;

const fn make_table() -> [u16; 256] {
    let mut table = [0u16; 256];
    let mut i = 0;
    while i < 256 {
        let mut crc = i as u16;
        let mut bit = 0;
        while bit < 8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0x8408
            } else {
                crc >> 1
            };
            bit += 1;
        }
        table[i] = crc;
        i += 1;
    }
    table
}

static FCS_TABLE: [u16; 256] = make_table();

/// Updates a running FCS with one byte.
pub fn update_fcs(fcs: u16, byte: u8) -> u16 {
    (fcs >> 8) ^ FCS_TABLE[((fcs ^ u16::from(byte)) & 0xff) as usize]
}

/// CRC-16/X.25 (initial value `0xffff`, final XOR `0xffff`) of `data`.
pub fn crc16(data: &[u8]) -> u16 {
    data.iter().fold(INIT_FCS, |f, &b| update_fcs(f, b)) ^ 0xffff
}

fn needs_escape(byte: u8) -> bool {
    matches!(byte, XON | XOFF | ESCAPE | FLAG | SPECIAL)
}

/// The size of `payload` as an HDLC frame in the worst case (every byte
/// escaped).
pub const fn max_encoded_len(payload: usize) -> usize {
    2 + 2 * (payload + FCS_SIZE)
}

/// Encodes `payload` as one HDLC-lite frame into `out`; returns the length.
pub fn encode(payload: &[u8], out: &mut [u8]) -> Result<usize> {
    let mut s = Sink { out, n: 0 };
    s.put(FLAG)?;
    let mut fcs = INIT_FCS;
    for &b in payload {
        s.put_escaped(b)?;
        fcs = update_fcs(fcs, b);
    }
    fcs ^= 0xffff;
    s.put_escaped((fcs & 0xff) as u8)?;
    s.put_escaped((fcs >> 8) as u8)?;
    s.put(FLAG)?;
    Ok(s.n)
}

struct Sink<'a> {
    out: &'a mut [u8],
    n: usize,
}

impl Sink<'_> {
    fn put(&mut self, b: u8) -> Result<()> {
        *self.out.get_mut(self.n).ok_or(Error::NoBufs)? = b;
        self.n += 1;
        Ok(())
    }

    fn put_escaped(&mut self, b: u8) -> Result<()> {
        if needs_escape(b) {
            self.put(ESCAPE)?;
            self.put(b ^ 0x20)
        } else {
            self.put(b)
        }
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
enum State {
    NoSync,
    Sync,
    Escaped,
}

/// Streaming HDLC-lite decoder with a fixed `N`-byte frame buffer.
#[derive(Debug)]
pub struct Decoder<const N: usize> {
    state: State,
    buf: [u8; N],
    len: usize,
    fcs: u16,
}

impl<const N: usize> Default for Decoder<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> Decoder<N> {
    /// A decoder waiting for the first flag.
    pub const fn new() -> Self {
        Self {
            state: State::NoSync,
            buf: [0; N],
            len: 0,
            fcs: INIT_FCS,
        }
    }

    /// Drops the partial frame and waits for the next flag.
    pub fn reset(&mut self) {
        self.state = State::NoSync;
        self.len = 0;
        self.fcs = INIT_FCS;
    }

    fn push(&mut self, byte: u8) -> Result<()> {
        if self.len == N {
            self.reset();
            return Err(Error::NoBufs);
        }
        self.fcs = update_fcs(self.fcs, byte);
        self.buf[self.len] = byte;
        self.len += 1;
        Ok(())
    }

    /// Feeds one byte. Returns `Some(Ok(payload))` when a frame with a good
    /// FCS ended (the payload excludes the FCS and borrows the decoder until
    /// the next call), `Some(Err(_))` for a bad frame (`Parse`: short or bad
    /// FCS, `NoBufs`: longer than `N`), `None` otherwise.
    pub fn feed(&mut self, byte: u8) -> Option<Result<&[u8]>> {
        match self.state {
            State::NoSync => {
                if byte == FLAG {
                    self.state = State::Sync;
                    self.len = 0;
                    self.fcs = INIT_FCS;
                }
                None
            }
            State::Sync => match byte {
                ESCAPE => {
                    self.state = State::Escaped;
                    None
                }
                FLAG => {
                    let len = self.len;
                    let fcs = self.fcs;
                    self.len = 0;
                    self.fcs = INIT_FCS;
                    if len == 0 {
                        None
                    } else if len >= FCS_SIZE && fcs == GOOD_FCS {
                        Some(Ok(&self.buf[..len - FCS_SIZE]))
                    } else {
                        Some(Err(Error::Parse))
                    }
                }
                b => self.push(b).err().map(Err),
            },
            State::Escaped => {
                self.state = State::Sync;
                self.push(byte ^ 0x20).err().map(Err)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec::Vec;

    const OPENTHREAD_TEXT: &[u8] = b"OpenThread Rocks";
    const MOTTO_TEXT: &[u8] = b"Think good thoughts, say good words, do good deeds!";
    const SPECIALS: &[u8] = &[FLAG, 0x11, 0x13, ESCAPE, 0xf8, 0x20, 0x5e];

    fn enc(payload: &[u8]) -> Vec<u8> {
        let mut out = std::vec![0u8; max_encoded_len(payload.len())];
        let n = encode(payload, &mut out).unwrap();
        out.truncate(n);
        out
    }

    #[test]
    fn crc_check_value() {
        // CRC-16/X.25 catalogue check value.
        assert_eq!(crc16(b"123456789"), 0x906e);
        assert_eq!(crc16(&[]), 0);
    }

    #[test]
    fn known_frame() {
        // Spinel "PROP_VALUE_GET PROTOCOL_VERSION" (header 0x81) framed by
        // OpenThread: 7e 81 02 01 <fcs> 7e.
        let fcs = crc16(&[0x81, 0x02, 0x01]);
        let f = enc(&[0x81, 0x02, 0x01]);
        let mut expected = std::vec![FLAG, 0x81, 0x02, 0x01];
        for b in [(fcs & 0xff) as u8, (fcs >> 8) as u8] {
            if needs_escape(b) {
                expected.extend([ESCAPE, b ^ 0x20]);
            } else {
                expected.push(b);
            }
        }
        expected.push(FLAG);
        assert_eq!(f, expected);
    }

    #[test]
    fn escapes() {
        let f = enc(&[FLAG, ESCAPE, 0x11, 0x13, 0xf8, 0x00]);
        assert_eq!(
            &f[..12],
            &[
                FLAG, 0x7d, 0x5e, 0x7d, 0x5d, 0x7d, 0x31, 0x7d, 0x33, 0x7d, 0xd8, 0x00
            ]
        );
    }

    #[test]
    fn encoder_decoder_roundtrip() {
        // Ported from OpenThread tests/unit/test_hdlc.cpp (TestEncoderDecoder).
        let bad_short = [FLAG, 0xaa, FLAG];
        let mut stream = Vec::new();
        stream.extend(enc(OPENTHREAD_TEXT));
        stream.extend(enc(MOTTO_TEXT));
        stream.extend(enc(SPECIALS));
        stream.extend(bad_short);
        stream.extend(enc(b"Hello there!"));
        let mut dec = Decoder::<128>::new();
        let mut got: Vec<Result<Vec<u8>>> = Vec::new();
        for b in stream {
            if let Some(r) = dec.feed(b) {
                got.push(r.map(|p| p.to_vec()));
            }
        }
        assert_eq!(
            got,
            std::vec![
                Ok(OPENTHREAD_TEXT.to_vec()),
                Ok(MOTTO_TEXT.to_vec()),
                Ok(SPECIALS.to_vec()),
                Err(Error::Parse),
                Ok(b"Hello there!".to_vec()),
            ]
        );
    }

    #[test]
    fn bad_fcs_and_overflow() {
        let mut f = enc(b"abc");
        f[2] ^= 1;
        let mut dec = Decoder::<16>::new();
        let r: Vec<_> = f
            .iter()
            .filter_map(|&b| dec.feed(b).map(|r| r.is_ok()))
            .collect();
        assert_eq!(r, std::vec![false]);
        let mut dec = Decoder::<4>::new();
        let big = enc(&[1u8; 32]);
        let mut errs = 0;
        for &b in &big {
            if let Some(Err(Error::NoBufs)) = dec.feed(b) {
                errs += 1;
            }
        }
        assert_eq!(errs, 1);
    }

    #[test]
    fn small_output() {
        let mut out = [0u8; 5];
        assert_eq!(encode(b"abc", &mut out), Err(Error::NoBufs));
    }
}
