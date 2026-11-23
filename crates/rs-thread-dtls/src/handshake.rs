//! DTLS 1.2 handshake framing (RFC 6347 §4.2.2), fragment reassembly and
//! the ClientHello / ServerHello / HelloVerifyRequest codecs for
//! `TLS_ECJPAKE_WITH_AES_128_CCM_8` as mbedTLS encodes them.

use rs_thread_core::crypto::ecjpake::ROUND_ONE_MAX_LEN;
use rs_thread_core::{Error, Result};

use crate::record::{DTLS_1_0, DTLS_1_2};

/// Handshake message header length.
pub const HEADER_LEN: usize = 12;

/// `client_hello`.
pub const HT_CLIENT_HELLO: u8 = 1;
/// `server_hello`.
pub const HT_SERVER_HELLO: u8 = 2;
/// `hello_verify_request`.
pub const HT_HELLO_VERIFY_REQUEST: u8 = 3;
/// `server_key_exchange`.
pub const HT_SERVER_KEY_EXCHANGE: u8 = 12;
/// `server_hello_done`.
pub const HT_SERVER_HELLO_DONE: u8 = 14;
/// `client_key_exchange`.
pub const HT_CLIENT_KEY_EXCHANGE: u8 = 16;
/// `finished`.
pub const HT_FINISHED: u8 = 20;

/// `TLS_ECJPAKE_WITH_AES_128_CCM_8` (draft-cragie-tls-ecjpake-01).
pub const TLS_ECJPAKE_WITH_AES_128_CCM_8: u16 = 0xc0ff;
/// `TLS_EMPTY_RENEGOTIATION_INFO_SCSV` (RFC 5746).
pub const TLS_EMPTY_RENEGOTIATION_INFO_SCSV: u16 = 0x00ff;

/// `supported_groups` (formerly `elliptic_curves`).
pub const EXT_SUPPORTED_GROUPS: u16 = 0x000a;
/// `ec_point_formats`.
pub const EXT_EC_POINT_FORMATS: u16 = 0x000b;
/// `ecjpake_key_kp_pair` (mbedTLS `MBEDTLS_TLS_EXT_ECJPAKE_KKPP`).
pub const EXT_ECJPAKE_KKPP: u16 = 0x0100;
/// `renegotiation_info` (RFC 5746).
pub const EXT_RENEGOTIATION_INFO: u16 = 0xff01;
/// Named group secp256r1.
pub const GROUP_SECP256R1: u16 = 23;
/// Point format `uncompressed`.
pub const POINT_FORMAT_UNCOMPRESSED: u8 = 0;

/// `verify_data` length.
pub const VERIFY_DATA_LEN: usize = 12;
/// Random length.
pub const RANDOM_LEN: usize = 32;
/// Maximum cookie length (DTLS 1.2: `opaque cookie<0..2^8-1>`).
pub const MAX_COOKIE_LEN: usize = 255;

/// Largest handshake message we accept (all messages of this cipher
/// suite are well below; mbedTLS in OpenThread's configuration limits
/// records to 768 bytes as well).
pub const MAX_MESSAGE_LEN: usize = 768;

/// A handshake fragment header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FragmentHeader {
    /// Message type.
    pub msg_type: u8,
    /// Total message length.
    pub len: usize,
    /// Message sequence number.
    pub msg_seq: u16,
    /// Fragment offset.
    pub frag_off: usize,
    /// Fragment length.
    pub frag_len: usize,
}

fn u24(b: &[u8]) -> usize {
    (b[0] as usize) << 16 | (b[1] as usize) << 8 | b[2] as usize
}

fn put_u24(out: &mut [u8], v: usize) {
    out[0] = (v >> 16) as u8;
    out[1] = (v >> 8) as u8;
    out[2] = v as u8;
}

/// Split the first handshake fragment off a handshake record's plaintext.
/// Rejects fragments that do not fit the message (mbedTLS
/// `ssl_check_hs_header`).
pub fn parse_fragment(data: &[u8]) -> Result<(FragmentHeader, &[u8], &[u8])> {
    if data.len() < HEADER_LEN {
        return Err(Error::Parse);
    }
    let h = FragmentHeader {
        msg_type: data[0],
        len: u24(&data[1..4]),
        msg_seq: u16::from_be_bytes([data[4], data[5]]),
        frag_off: u24(&data[6..9]),
        frag_len: u24(&data[9..12]),
    };
    if h.frag_off > h.len || h.frag_len > h.len - h.frag_off || data.len() - HEADER_LEN < h.frag_len
    {
        return Err(Error::Parse);
    }
    let end = HEADER_LEN + h.frag_len;
    Ok((h, &data[HEADER_LEN..end], &data[end..]))
}

/// Write a handshake fragment header.
pub fn write_header(
    out: &mut [u8],
    msg_type: u8,
    len: usize,
    msg_seq: u16,
    frag_off: usize,
    frag_len: usize,
) {
    out[0] = msg_type;
    put_u24(&mut out[1..4], len);
    out[4..6].copy_from_slice(&msg_seq.to_be_bytes());
    put_u24(&mut out[6..9], frag_off);
    put_u24(&mut out[9..12], frag_len);
}

/// The header of a complete (unfragmented) message, as hashed into the
/// transcript (RFC 6347 §4.2.6).
pub fn full_header(msg_type: u8, len: usize, msg_seq: u16) -> [u8; HEADER_LEN] {
    let mut h = [0u8; HEADER_LEN];
    write_header(&mut h, msg_type, len, msg_seq, 0, len);
    h
}

/// Reassembly buffer for one handshake message (fragments in any order,
/// overlaps and duplicates allowed, as mbedTLS).
pub struct Reassembly {
    active: bool,
    msg_type: u8,
    msg_seq: u16,
    len: usize,
    received: usize,
    buf: [u8; MAX_MESSAGE_LEN],
    mask: [u8; MAX_MESSAGE_LEN.div_ceil(8)],
}

impl core::fmt::Debug for Reassembly {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Reassembly")
            .field("active", &self.active)
            .field("msg_type", &self.msg_type)
            .field("msg_seq", &self.msg_seq)
            .field("len", &self.len)
            .field("received", &self.received)
            .finish_non_exhaustive()
    }
}

impl Default for Reassembly {
    fn default() -> Self {
        Self::new()
    }
}

impl Reassembly {
    /// Empty buffer.
    pub const fn new() -> Self {
        Self {
            active: false,
            msg_type: 0,
            msg_seq: 0,
            len: 0,
            received: 0,
            buf: [0; MAX_MESSAGE_LEN],
            mask: [0; MAX_MESSAGE_LEN.div_ceil(8)],
        }
    }

    /// Drop any partial message.
    pub fn reset(&mut self) {
        self.active = false;
        self.received = 0;
    }

    /// Add a fragment of the expected message. Returns the complete body
    /// once all bytes arrived. [`Error::NoBufs`] for an oversized message,
    /// [`Error::Parse`] if the fragment contradicts earlier fragments.
    pub fn add(&mut self, h: &FragmentHeader, frag: &[u8]) -> Result<Option<&[u8]>> {
        if h.len > MAX_MESSAGE_LEN {
            return Err(Error::NoBufs);
        }
        if !self.active {
            self.active = true;
            self.msg_type = h.msg_type;
            self.msg_seq = h.msg_seq;
            self.len = h.len;
            self.received = 0;
            self.mask = [0; MAX_MESSAGE_LEN.div_ceil(8)];
        } else if self.msg_type != h.msg_type || self.msg_seq != h.msg_seq || self.len != h.len {
            return Err(Error::Parse);
        }
        for (i, &b) in frag.iter().enumerate() {
            let pos = h.frag_off + i;
            let (byte, bit) = (pos / 8, 1u8 << (pos % 8));
            if self.mask[byte] & bit == 0 {
                self.mask[byte] |= bit;
                self.received += 1;
            }
            self.buf[pos] = b;
        }
        if self.received == self.len {
            self.active = false;
            Ok(Some(&self.buf[..self.len]))
        } else {
            Ok(None)
        }
    }
}

/// Bounds-checked reader.
#[derive(Debug)]
pub struct Reader<'a>(pub &'a [u8]);

impl<'a> Reader<'a> {
    /// Take `n` bytes.
    pub fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.0.len() < n {
            return Err(Error::Parse);
        }
        let (a, b) = self.0.split_at(n);
        self.0 = b;
        Ok(a)
    }
    /// One byte.
    pub fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }
    /// Big-endian u16.
    pub fn u16(&mut self) -> Result<u16> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }
    /// `opaque <0..2^8-1>`.
    pub fn vec8(&mut self) -> Result<&'a [u8]> {
        let n = self.u8()? as usize;
        self.take(n)
    }
    /// `opaque <0..2^16-1>`.
    pub fn vec16(&mut self) -> Result<&'a [u8]> {
        let n = self.u16()? as usize;
        self.take(n)
    }
    /// Remaining bytes.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// Bounds-checked writer.
#[derive(Debug)]
pub struct Writer<'a> {
    buf: &'a mut [u8],
    pos: usize,
}

impl<'a> Writer<'a> {
    /// Writer over `buf`.
    pub fn new(buf: &'a mut [u8]) -> Self {
        Self { buf, pos: 0 }
    }
    /// Bytes written.
    pub fn len(&self) -> usize {
        self.pos
    }
    /// Nothing written yet.
    pub fn is_empty(&self) -> bool {
        self.pos == 0
    }
    /// Append bytes.
    pub fn put(&mut self, d: &[u8]) -> Result<()> {
        let end = self.pos + d.len();
        self.buf
            .get_mut(self.pos..end)
            .ok_or(Error::NoBufs)?
            .copy_from_slice(d);
        self.pos = end;
        Ok(())
    }
    /// Append a u16.
    pub fn u16(&mut self, v: u16) -> Result<()> {
        self.put(&v.to_be_bytes())
    }
    /// Append one byte.
    pub fn u8(&mut self, v: u8) -> Result<()> {
        self.put(&[v])
    }
    /// Append an extension.
    pub fn ext(&mut self, ext_type: u16, body: &[u8]) -> Result<()> {
        self.u16(ext_type)?;
        self.u16(body.len() as u16)?;
        self.put(body)
    }
    /// Mutable access to written bytes.
    pub fn written_mut(&mut self) -> &mut [u8] {
        &mut self.buf[..self.pos]
    }
}

/// Our ClientHello body (mbedTLS order: `supported_groups`,
/// `ec_point_formats`, `ecjpake_key_kp_pair`; cipher suites `0xC0FF` and the
/// renegotiation SCSV, empty session id, null compression).
pub fn write_client_hello(
    out: &mut [u8],
    random: &[u8; RANDOM_LEN],
    cookie: &[u8],
    kkpp: &[u8],
) -> Result<usize> {
    let mut w = Writer::new(out);
    w.put(&DTLS_1_2)?;
    w.put(random)?;
    w.u8(0)?; // session_id
    w.u8(cookie.len() as u8)?;
    w.put(cookie)?;
    w.u16(4)?;
    w.u16(TLS_ECJPAKE_WITH_AES_128_CCM_8)?;
    w.u16(TLS_EMPTY_RENEGOTIATION_INFO_SCSV)?;
    w.put(&[1, 0])?; // compression: null
    let ext_len = 8 + 6 + 4 + kkpp.len();
    w.u16(ext_len as u16)?;
    w.ext(
        EXT_SUPPORTED_GROUPS,
        &[0x00, 0x02, 0x00, GROUP_SECP256R1 as u8],
    )?;
    w.ext(EXT_EC_POINT_FORMATS, &[0x01, POINT_FORMAT_UNCOMPRESSED])?;
    w.ext(EXT_ECJPAKE_KKPP, kkpp)?;
    Ok(w.len())
}

/// A parsed ClientHello (fields borrowed from the message).
#[derive(Debug)]
pub struct ClientHello<'a> {
    /// Client random.
    pub random: &'a [u8],
    /// Cookie (may be empty).
    pub cookie: &'a [u8],
    /// Offers `TLS_ECJPAKE_WITH_AES_128_CCM_8`.
    pub offers_suite: bool,
    /// Offers the null compression method.
    pub null_compression: bool,
    /// Sent the renegotiation SCSV or an empty `renegotiation_info`.
    pub secure_renegotiation: bool,
    /// `supported_groups` contains secp256r1.
    pub secp256r1: bool,
    /// `ec_point_formats` was present.
    pub point_formats_present: bool,
    /// `ec_point_formats` (if present) contains `uncompressed`.
    pub uncompressed_ok: bool,
    /// `ecjpake_key_kp_pair` body.
    pub kkpp: Option<&'a [u8]>,
}

/// Iterate the extensions block, rejecting duplicates of the extensions we
/// interpret.
fn for_each_ext<'a>(
    r: &mut Reader<'a>,
    mut f: impl FnMut(u16, &'a [u8]) -> Result<()>,
) -> Result<()> {
    if r.is_empty() {
        return Ok(());
    }
    let mut exts = Reader(r.vec16()?);
    if !r.is_empty() {
        return Err(Error::Parse);
    }
    let mut seen = 0u8;
    while !exts.is_empty() {
        let t = exts.u16()?;
        let body = exts.vec16()?;
        let bit = match t {
            EXT_SUPPORTED_GROUPS => 1,
            EXT_EC_POINT_FORMATS => 2,
            EXT_ECJPAKE_KKPP => 4,
            EXT_RENEGOTIATION_INFO => 8,
            _ => 0,
        };
        if seen & bit != 0 {
            return Err(Error::Parse);
        }
        seen |= bit;
        f(t, body)?;
    }
    Ok(())
}

/// Parse a ClientHello body (server side).
pub fn parse_client_hello(body: &[u8]) -> Result<ClientHello<'_>> {
    let mut r = Reader(body);
    let v = r.take(2)?;
    // Any DTLS version >= 1.2 (lower minor = newer); DTLS 1.0-only clients
    // are refused.
    if v[0] != 0xfe || v[1] > DTLS_1_2[1] {
        return Err(Error::NotImplemented);
    }
    let random = r.take(RANDOM_LEN)?;
    let sid = r.vec8()?;
    if sid.len() > 32 {
        return Err(Error::Parse);
    }
    let cookie = r.vec8()?;
    let suites = r.vec16()?;
    if suites.is_empty() || suites.len() % 2 != 0 {
        return Err(Error::Parse);
    }
    let mut ch = ClientHello {
        random,
        cookie,
        offers_suite: false,
        null_compression: false,
        secure_renegotiation: false,
        secp256r1: false,
        point_formats_present: false,
        uncompressed_ok: false,
        kkpp: None,
    };
    for s in suites.chunks(2) {
        match u16::from_be_bytes([s[0], s[1]]) {
            TLS_ECJPAKE_WITH_AES_128_CCM_8 => ch.offers_suite = true,
            TLS_EMPTY_RENEGOTIATION_INFO_SCSV => ch.secure_renegotiation = true,
            _ => {}
        }
    }
    let comp = r.vec8()?;
    if comp.is_empty() {
        return Err(Error::Parse);
    }
    ch.null_compression = comp.contains(&0);
    for_each_ext(&mut r, |t, b| {
        match t {
            EXT_SUPPORTED_GROUPS => {
                let mut g = Reader(b);
                let list = g.vec16()?;
                if !g.is_empty() || list.len() % 2 != 0 {
                    return Err(Error::Parse);
                }
                ch.secp256r1 = list
                    .chunks(2)
                    .any(|c| u16::from_be_bytes([c[0], c[1]]) == GROUP_SECP256R1);
            }
            EXT_EC_POINT_FORMATS => {
                let mut p = Reader(b);
                let list = p.vec8()?;
                if !p.is_empty() {
                    return Err(Error::Parse);
                }
                ch.point_formats_present = true;
                ch.uncompressed_ok = list.contains(&POINT_FORMAT_UNCOMPRESSED);
            }
            EXT_ECJPAKE_KKPP => ch.kkpp = Some(b),
            EXT_RENEGOTIATION_INFO => {
                // Initial handshake: renegotiated_connection must be empty.
                if b != [0] {
                    return Err(Error::Security);
                }
                ch.secure_renegotiation = true;
            }
            _ => {}
        }
        Ok(())
    })?;
    Ok(ch)
}

/// Our ServerHello body (mbedTLS extension order: `renegotiation_info`,
/// `ec_point_formats`, `ecjpake_key_kp_pair`; empty session id).
pub fn write_server_hello(
    out: &mut [u8],
    random: &[u8; RANDOM_LEN],
    renegotiation_info: bool,
    point_formats: bool,
    kkpp: &[u8],
) -> Result<usize> {
    let mut w = Writer::new(out);
    w.put(&DTLS_1_2)?;
    w.put(random)?;
    w.u8(0)?; // session_id
    w.u16(TLS_ECJPAKE_WITH_AES_128_CCM_8)?;
    w.u8(0)?; // compression
    let ext_len =
        if renegotiation_info { 5 } else { 0 } + if point_formats { 6 } else { 0 } + 4 + kkpp.len();
    w.u16(ext_len as u16)?;
    if renegotiation_info {
        w.ext(EXT_RENEGOTIATION_INFO, &[0])?;
    }
    if point_formats {
        w.ext(EXT_EC_POINT_FORMATS, &[0x01, POINT_FORMAT_UNCOMPRESSED])?;
    }
    w.ext(EXT_ECJPAKE_KKPP, kkpp)?;
    Ok(w.len())
}

/// Parse a ServerHello body (client side); returns `(server_random,
/// kkpp)`. Strict: the version must be DTLS 1.2, the suite and compression
/// ours, and only the extensions we can have caused are allowed.
pub fn parse_server_hello(body: &[u8]) -> Result<(&[u8], &[u8])> {
    let mut r = Reader(body);
    if r.take(2)? != DTLS_1_2 {
        return Err(Error::NotImplemented);
    }
    let random = r.take(RANDOM_LEN)?;
    if r.vec8()?.len() > 32 {
        return Err(Error::Parse);
    }
    if r.u16()? != TLS_ECJPAKE_WITH_AES_128_CCM_8 || r.u8()? != 0 {
        return Err(Error::Security);
    }
    let mut kkpp = None;
    for_each_ext(&mut r, |t, b| {
        match t {
            EXT_ECJPAKE_KKPP => kkpp = Some(b),
            EXT_EC_POINT_FORMATS => {
                let mut p = Reader(b);
                let list = p.vec8()?;
                if !p.is_empty() || !list.contains(&POINT_FORMAT_UNCOMPRESSED) {
                    return Err(Error::Security);
                }
            }
            EXT_RENEGOTIATION_INFO => {
                if b != [0] {
                    return Err(Error::Security);
                }
            }
            // RFC 5246 §7.4.1.4: unsolicited extension.
            _ => return Err(Error::Security),
        }
        Ok(())
    })?;
    let kkpp = kkpp.ok_or(Error::Security)?;
    if kkpp.len() > ROUND_ONE_MAX_LEN {
        return Err(Error::Parse);
    }
    Ok((random, kkpp))
}

/// HelloVerifyRequest body.
pub fn write_hello_verify_request(out: &mut [u8], cookie: &[u8]) -> Result<usize> {
    let mut w = Writer::new(out);
    w.put(&DTLS_1_2)?;
    w.u8(cookie.len() as u8)?;
    w.put(cookie)?;
    Ok(w.len())
}

/// Parse a HelloVerifyRequest body; returns the cookie.
pub fn parse_hello_verify_request(body: &[u8]) -> Result<&[u8]> {
    let mut r = Reader(body);
    let v = r.take(2)?;
    if v != DTLS_1_2 && v != DTLS_1_0 {
        return Err(Error::Parse);
    }
    let cookie = r.vec8()?;
    if cookie.is_empty() || !r.is_empty() {
        return Err(Error::Parse);
    }
    Ok(cookie)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fragment_header() {
        let mut b = [0u8; 20];
        write_header(&mut b, HT_FINISHED, 12, 3, 4, 8);
        let (h, f, rest) = parse_fragment(&b).unwrap();
        assert_eq!(
            h,
            FragmentHeader {
                msg_type: HT_FINISHED,
                len: 12,
                msg_seq: 3,
                frag_off: 4,
                frag_len: 8
            }
        );
        assert_eq!(f.len(), 8);
        assert!(rest.is_empty());
        // Fragment beyond the message / the record.
        write_header(&mut b, HT_FINISHED, 12, 3, 8, 8);
        assert!(parse_fragment(&b).is_err());
        write_header(&mut b, HT_FINISHED, 12, 3, 0, 9);
        assert!(parse_fragment(&b).is_err());
    }

    #[test]
    fn reassembly_any_order() {
        let msg: [u8; 100] = core::array::from_fn(|i| i as u8);
        let mut r = Reassembly::new();
        let hdr = |off: usize, len: usize| FragmentHeader {
            msg_type: HT_SERVER_HELLO,
            len: 100,
            msg_seq: 1,
            frag_off: off,
            frag_len: len,
        };
        assert!(r.add(&hdr(60, 40), &msg[60..]).unwrap().is_none());
        assert!(r.add(&hdr(0, 30), &msg[..30]).unwrap().is_none());
        // Overlap and duplicate.
        assert!(r.add(&hdr(20, 20), &msg[20..40]).unwrap().is_none());
        assert!(r.add(&hdr(0, 30), &msg[..30]).unwrap().is_none());
        // Inconsistent header.
        let mut bad = hdr(40, 20);
        bad.len = 101;
        assert_eq!(r.add(&bad, &msg[40..60]), Err(Error::Parse));
        assert_eq!(r.add(&hdr(40, 20), &msg[40..60]).unwrap(), Some(&msg[..]));
        // Oversized.
        let mut big = hdr(0, 1);
        big.len = MAX_MESSAGE_LEN + 1;
        assert_eq!(r.add(&big, &[0]), Err(Error::NoBufs));
    }

    #[test]
    fn hello_roundtrip() {
        let mut buf = [0u8; 512];
        let kkpp = [0x41u8; 300];
        let n = write_client_hello(&mut buf, &[7; 32], &[1, 2, 3], &kkpp).unwrap();
        let ch = parse_client_hello(&buf[..n]).unwrap();
        assert_eq!(ch.random, &[7; 32]);
        assert_eq!(ch.cookie, &[1, 2, 3]);
        assert!(ch.offers_suite && ch.null_compression && ch.secure_renegotiation);
        assert!(ch.secp256r1 && ch.point_formats_present && ch.uncompressed_ok);
        assert_eq!(ch.kkpp, Some(&kkpp[..]));
        // Trailing byte.
        assert!(parse_client_hello(&buf[..n + 1]).is_err());

        let n = write_server_hello(&mut buf, &[9; 32], true, true, &kkpp).unwrap();
        let (r, k) = parse_server_hello(&buf[..n]).unwrap();
        assert_eq!(r, &[9; 32]);
        assert_eq!(k, &kkpp[..]);
        let n2 = write_server_hello(&mut buf, &[9; 32], false, false, &kkpp).unwrap();
        assert_eq!(n2, n - 11);
        parse_server_hello(&buf[..n2]).unwrap();

        let n = write_hello_verify_request(&mut buf, &[5; 32]).unwrap();
        assert_eq!(parse_hello_verify_request(&buf[..n]).unwrap(), &[5; 32]);
    }

    #[test]
    fn server_hello_rejects_unsolicited_extension() {
        let mut buf = [0u8; 512];
        let n = write_server_hello(&mut buf, &[9; 32], false, false, &[1; 10]).unwrap();
        // Append an unknown extension (fix up the extensions length).
        let mut v = buf[..n].to_vec();
        v.extend_from_slice(&[0x00, 0x17, 0x00, 0x00]);
        let el = u16::from_be_bytes([v[38], v[39]]) + 4;
        v[38..40].copy_from_slice(&el.to_be_bytes());
        assert_eq!(parse_server_hello(&v), Err(Error::Security));
    }
}
