//! CoAP message codec (RFC 7252 section 3; OT `coap/coap_message.{hpp,cpp}`).
//!
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |Ver| T |  TKL  |      Code     |          Message ID           |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! | Token (0-8 bytes) ... | Options ... | 0xFF | Payload ...
//! ```
//!
//! [`Message::parse`] validates the whole header and option list once and
//! then borrows from the datagram (zero-copy); [`MessageBuilder`] writes
//! into a caller buffer with options in non-decreasing number order.
//! Nothing here panics on malformed input.

use rs_thread_core::bytes::{Reader, Writer};
use rs_thread_core::{Error, Result};

/// CoAP version (always 1).
pub const VERSION: u8 = 1;
/// Maximum token length (RFC 7252; OT `OT_COAP_MAX_TOKEN_LENGTH`).
pub const MAX_TOKEN_LEN: usize = 8;
/// Length of the fixed header.
pub const HEADER_LEN: usize = 4;
/// Payload marker byte.
pub const PAYLOAD_MARKER: u8 = 0xff;
/// Longest URI path accepted on received messages (OT `kMaxReceivedUriPath`).
pub const MAX_URI_PATH_LEN: usize = 32;
/// OT `kMaxHeaderLength`: header + options must stay below this.
pub const MAX_HEADER_LEN: usize = 512;

/// Message type (RFC 7252 section 3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Type {
    /// Confirmable.
    Con = 0,
    /// Non-confirmable.
    Non = 1,
    /// Acknowledgement.
    Ack = 2,
    /// Reset.
    Rst = 3,
}

impl Type {
    const fn from_bits(b: u8) -> Self {
        match b & 3 {
            0 => Type::Con,
            1 => Type::Non,
            2 => Type::Ack,
            _ => Type::Rst,
        }
    }
}

/// Message code, `class.detail` packed as `class << 5 | detail`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Code(pub u8);

impl Code {
    /// 0.00 Empty.
    pub const EMPTY: Code = Code(0);
    /// 0.01 GET.
    pub const GET: Code = Code(1);
    /// 0.02 POST.
    pub const POST: Code = Code(2);
    /// 0.03 PUT.
    pub const PUT: Code = Code(3);
    /// 0.04 DELETE.
    pub const DELETE: Code = Code(4);
    /// 2.01 Created.
    pub const CREATED: Code = Code::new(2, 1);
    /// 2.02 Deleted.
    pub const DELETED: Code = Code::new(2, 2);
    /// 2.03 Valid.
    pub const VALID: Code = Code::new(2, 3);
    /// 2.04 Changed.
    pub const CHANGED: Code = Code::new(2, 4);
    /// 2.05 Content.
    pub const CONTENT: Code = Code::new(2, 5);
    /// 2.31 Continue (RFC 7959).
    pub const CONTINUE: Code = Code::new(2, 31);
    /// 4.00 Bad Request.
    pub const BAD_REQUEST: Code = Code::new(4, 0);
    /// 4.01 Unauthorized.
    pub const UNAUTHORIZED: Code = Code::new(4, 1);
    /// 4.02 Bad Option.
    pub const BAD_OPTION: Code = Code::new(4, 2);
    /// 4.03 Forbidden.
    pub const FORBIDDEN: Code = Code::new(4, 3);
    /// 4.04 Not Found.
    pub const NOT_FOUND: Code = Code::new(4, 4);
    /// 4.05 Method Not Allowed.
    pub const METHOD_NOT_ALLOWED: Code = Code::new(4, 5);
    /// 4.06 Not Acceptable.
    pub const NOT_ACCEPTABLE: Code = Code::new(4, 6);
    /// 4.08 Request Entity Incomplete (RFC 7959).
    pub const REQUEST_INCOMPLETE: Code = Code::new(4, 8);
    /// 4.12 Precondition Failed.
    pub const PRECONDITION_FAILED: Code = Code::new(4, 12);
    /// 4.13 Request Entity Too Large.
    pub const REQUEST_TOO_LARGE: Code = Code::new(4, 13);
    /// 4.15 Unsupported Content-Format.
    pub const UNSUPPORTED_FORMAT: Code = Code::new(4, 15);
    /// 5.00 Internal Server Error.
    pub const INTERNAL_ERROR: Code = Code::new(5, 0);
    /// 5.01 Not Implemented.
    pub const NOT_IMPLEMENTED: Code = Code::new(5, 1);
    /// 5.02 Bad Gateway.
    pub const BAD_GATEWAY: Code = Code::new(5, 2);
    /// 5.03 Service Unavailable.
    pub const SERVICE_UNAVAILABLE: Code = Code::new(5, 3);
    /// 5.04 Gateway Timeout.
    pub const GATEWAY_TIMEOUT: Code = Code::new(5, 4);
    /// 5.05 Proxying Not Supported.
    pub const PROXY_NOT_SUPPORTED: Code = Code::new(5, 5);

    /// Build from class (0..=7) and detail (0..=31).
    pub const fn new(class: u8, detail: u8) -> Code {
        Code(((class & 7) << 5) | (detail & 31))
    }
    /// Class (the `c` of `c.dd`).
    pub const fn class(self) -> u8 {
        self.0 >> 5
    }
    /// Detail (the `dd` of `c.dd`).
    pub const fn detail(self) -> u8 {
        self.0 & 31
    }
    /// Request method (0.01..=0.04, as OT `IsRequest`).
    pub const fn is_request(self) -> bool {
        self.0 >= Code::GET.0 && self.0 <= Code::DELETE.0
    }
    /// Response (classes 2, 4, 5; OT `IsResponse`: code >= 2.00).
    pub const fn is_response(self) -> bool {
        self.0 >= 0x40
    }
}

/// Option numbers (RFC 7252 section 12.2, RFC 7959).
pub mod opt {
    /// If-Match.
    pub const IF_MATCH: u16 = 1;
    /// Uri-Host.
    pub const URI_HOST: u16 = 3;
    /// ETag.
    pub const ETAG: u16 = 4;
    /// If-None-Match.
    pub const IF_NONE_MATCH: u16 = 5;
    /// Observe (RFC 7641).
    pub const OBSERVE: u16 = 6;
    /// Uri-Port.
    pub const URI_PORT: u16 = 7;
    /// Location-Path.
    pub const LOCATION_PATH: u16 = 8;
    /// Uri-Path.
    pub const URI_PATH: u16 = 11;
    /// Content-Format.
    pub const CONTENT_FORMAT: u16 = 12;
    /// Max-Age.
    pub const MAX_AGE: u16 = 14;
    /// Uri-Query.
    pub const URI_QUERY: u16 = 15;
    /// Accept.
    pub const ACCEPT: u16 = 17;
    /// Location-Query.
    pub const LOCATION_QUERY: u16 = 20;
    /// Block2 (RFC 7959).
    pub const BLOCK2: u16 = 23;
    /// Block1 (RFC 7959).
    pub const BLOCK1: u16 = 27;
    /// Size2 (RFC 7959).
    pub const SIZE2: u16 = 28;
    /// Proxy-Uri.
    pub const PROXY_URI: u16 = 35;
    /// Proxy-Scheme.
    pub const PROXY_SCHEME: u16 = 39;
    /// Size1.
    pub const SIZE1: u16 = 60;
}

/// Content-Format registry values used by Thread.
pub mod content_format {
    /// `text/plain; charset=utf-8`.
    pub const TEXT_PLAIN: u16 = 0;
    /// `application/octet-stream`.
    pub const OCTET_STREAM: u16 = 42;
    /// `application/json`.
    pub const JSON: u16 = 50;
    /// `application/cbor`.
    pub const CBOR: u16 = 60;
}

/// One CoAP option.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct CoapOption<'a> {
    /// Option number.
    pub number: u16,
    /// Raw value.
    pub value: &'a [u8],
}

impl CoapOption<'_> {
    /// Value as an RFC 7252 `uint` (0..=4 bytes, big-endian, leading zeros
    /// stripped). `None` if longer than 4 bytes.
    pub fn as_uint(&self) -> Option<u32> {
        if self.value.len() > 4 {
            return None;
        }
        Some(self.value.iter().fold(0u32, |a, &b| (a << 8) | b as u32))
    }
}

/// Iterator over the options of a parsed message (already validated).
#[derive(Debug, Clone)]
pub struct OptionIter<'a> {
    rest: &'a [u8],
    number: u32,
}

impl<'a> OptionIter<'a> {
    fn new(rest: &'a [u8]) -> Self {
        Self { rest, number: 0 }
    }
}

fn read_ext(r: &mut Reader<'_>, nibble: u8) -> Result<u32> {
    match nibble {
        0..=12 => Ok(nibble as u32),
        13 => Ok(r.read_u8()? as u32 + 13),
        14 => Ok(r.read_u16()? as u32 + 269),
        _ => Err(Error::Parse),
    }
}

/// Decode one option from `r`; `Ok(None)` on end of options (payload marker
/// or end of buffer). `r` is left positioned after the option, or *at* the
/// marker.
fn next_option<'a>(r: &mut Reader<'a>, number: &mut u32) -> Result<Option<CoapOption<'a>>> {
    let Ok(b) = r.peek_u8() else {
        return Ok(None);
    };
    if b == PAYLOAD_MARKER {
        return Ok(None);
    }
    r.skip(1)?;
    let delta = read_ext(r, b >> 4)?;
    let len = read_ext(r, b & 0x0f)?;
    let n = number.checked_add(delta).ok_or(Error::Parse)?;
    if n > u16::MAX as u32 {
        return Err(Error::Parse);
    }
    let value = r.read_slice(len as usize)?;
    *number = n;
    Ok(Some(CoapOption {
        number: n as u16,
        value,
    }))
}

impl<'a> Iterator for OptionIter<'a> {
    type Item = CoapOption<'a>;

    fn next(&mut self) -> Option<CoapOption<'a>> {
        let mut r = Reader::new(self.rest);
        match next_option(&mut r, &mut self.number) {
            Ok(Some(o)) => {
                self.rest = r.rest();
                Some(o)
            }
            _ => {
                self.rest = &[];
                None
            }
        }
    }
}

/// A parsed CoAP message borrowing from the datagram.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Message<'a> {
    ty: Type,
    code: Code,
    message_id: u16,
    token_len: u8,
    token: [u8; MAX_TOKEN_LEN],
    options: &'a [u8],
    payload: &'a [u8],
}

impl<'a> Message<'a> {
    /// Parse and validate a datagram.
    ///
    /// Errors ([`Error::Parse`]): short header, version != 1, TKL > 8,
    /// truncated token/option, reserved option nibble 15, option number
    /// overflow, payload marker followed by no payload (RFC 7252 section
    /// 3), empty message (code 0.00) with token, options or payload.
    pub fn parse(buf: &'a [u8]) -> Result<Message<'a>> {
        let mut r = Reader::new(buf);
        let b0 = r.read_u8()?;
        let code = Code(r.read_u8()?);
        let message_id = r.read_u16()?;
        if b0 >> 6 != VERSION {
            return Err(Error::Parse);
        }
        let tkl = (b0 & 0x0f) as usize;
        if tkl > MAX_TOKEN_LEN {
            return Err(Error::Parse);
        }
        let mut token = [0u8; MAX_TOKEN_LEN];
        token[..tkl].copy_from_slice(r.read_slice(tkl)?);
        let opt_start = buf.len() - r.remaining();
        let mut number = 0u32;
        while next_option(&mut r, &mut number)?.is_some() {}
        let opt_end = buf.len() - r.remaining();
        let options = &buf[opt_start..opt_end];
        let payload = if r.remaining() > 0 {
            // At the payload marker.
            r.skip(1)?;
            if r.remaining() == 0 {
                return Err(Error::Parse);
            }
            r.rest()
        } else {
            &[]
        };
        if code == Code::EMPTY && (tkl != 0 || !options.is_empty() || !payload.is_empty()) {
            return Err(Error::Parse);
        }
        Ok(Message {
            ty: Type::from_bits(b0 >> 4),
            code,
            message_id,
            token_len: tkl as u8,
            token,
            options,
            payload,
        })
    }

    /// Message type.
    pub const fn ty(&self) -> Type {
        self.ty
    }
    /// Message code.
    pub const fn code(&self) -> Code {
        self.code
    }
    /// Message ID.
    pub const fn message_id(&self) -> u16 {
        self.message_id
    }
    /// Token (0..=8 bytes).
    pub fn token(&self) -> &[u8] {
        &self.token[..self.token_len as usize]
    }
    /// Payload (empty if none).
    pub const fn payload(&self) -> &'a [u8] {
        self.payload
    }
    /// Iterate all options in order.
    pub fn options(&self) -> OptionIter<'a> {
        OptionIter::new(self.options)
    }
    /// `true` for the empty message (code 0.00).
    pub const fn is_empty(&self) -> bool {
        self.code.0 == 0
    }
    /// `true` if confirmable.
    pub const fn is_confirmable(&self) -> bool {
        matches!(self.ty, Type::Con)
    }
    /// `true` if the code is a request method.
    pub const fn is_request(&self) -> bool {
        self.code.is_request()
    }
    /// `true` if the code is a response.
    pub const fn is_response(&self) -> bool {
        self.code.is_response()
    }
    /// First option with `number`.
    pub fn option(&self, number: u16) -> Option<CoapOption<'a>> {
        self.options().find(|o| o.number == number)
    }
    /// First option with `number` decoded as `uint` (`None` if absent or
    /// longer than 4 bytes).
    pub fn option_uint(&self, number: u16) -> Option<u32> {
        self.option(number).and_then(|o| o.as_uint())
    }
    /// Content-Format option, if present.
    pub fn content_format(&self) -> Option<u16> {
        self.option_uint(opt::CONTENT_FORMAT)
            .and_then(|v| u16::try_from(v).ok())
    }
    /// Parsed Block1 or Block2 option (`number` = [`opt::BLOCK1`] / [`opt::BLOCK2`]).
    pub fn block(&self, number: u16) -> Option<BlockOption> {
        self.option_uint(number).and_then(BlockOption::decode)
    }

    /// Uri-Path joined with `/` into `out` (OT `ReadUriPathOptions`; the
    /// path must be shorter than `out`, [`Error::Parse`] otherwise or if it
    /// is not UTF-8). A message without Uri-Path yields `""`.
    pub fn uri_path<'b>(&self, out: &'b mut [u8]) -> Result<&'b str> {
        let mut n = 0usize;
        let mut first = true;
        for o in self.options().filter(|o| o.number == opt::URI_PATH) {
            if !first {
                *out.get_mut(n).ok_or(Error::Parse)? = b'/';
                n += 1;
            }
            first = false;
            let end = n + o.value.len();
            out.get_mut(n..end)
                .ok_or(Error::Parse)?
                .copy_from_slice(o.value);
            n = end;
        }
        core::str::from_utf8(&out[..n]).map_err(|_| Error::Parse)
    }

    /// `true` if the Uri-Path options spell exactly `path` (segments joined
    /// by `/`, e.g. `"a/aq"`). No copying.
    pub fn uri_path_is(&self, path: &str) -> bool {
        let mut opts = self.options().filter(|o| o.number == opt::URI_PATH);
        if path.is_empty() {
            return opts.next().is_none();
        }
        let mut segs = path.split('/');
        loop {
            match (opts.next(), segs.next()) {
                (None, None) => return true,
                (Some(o), Some(s)) if o.value == s.as_bytes() => {}
                _ => return false,
            }
        }
    }

    /// Re-encode the fixed header, token and options of this message with a
    /// different type, code and message ID (used for copies, e.g. cached
    /// responses). Payload is appended unchanged.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize> {
        let mut w = Writer::new(out);
        w.write_u8(VERSION << 6 | (self.ty as u8) << 4 | self.token_len)?;
        w.write_u8(self.code.0)?;
        w.write_u16(self.message_id)?;
        w.write_slice(self.token())?;
        w.write_slice(self.options)?;
        if !self.payload.is_empty() {
            w.write_u8(PAYLOAD_MARKER)?;
            w.write_slice(self.payload)?;
        }
        Ok(w.len())
    }
}

/// Decoded Block1/Block2 option value (RFC 7959 section 2.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct BlockOption {
    /// Block number (0..2^20).
    pub num: u32,
    /// More blocks follow.
    pub more: bool,
    /// Size exponent `szx` (block size `16 << szx`, 0..=6).
    pub szx: u8,
}

impl BlockOption {
    /// Block size in bytes.
    pub const fn size(&self) -> usize {
        16usize << self.szx
    }
    /// Decode from an option `uint`. `None` for the reserved `szx` 7 or a
    /// number above 2^20 - 1.
    pub const fn decode(v: u32) -> Option<Self> {
        let szx = (v & 7) as u8;
        if szx == 7 || v >> 4 > 0xf_ffff {
            return None;
        }
        Some(Self {
            num: v >> 4,
            more: v & 8 != 0,
            szx,
        })
    }
    /// Encode to an option `uint`.
    pub const fn encode(&self) -> u32 {
        (self.num << 4) | ((self.more as u32) << 3) | (self.szx as u32)
    }
}

/// Builds a message into a caller-provided buffer.
///
/// Options must be added in non-decreasing option number order
/// ([`Error::InvalidArgs`] otherwise, like OT `AppendOptionHeader`).
#[derive(Debug)]
pub struct MessageBuilder<'a> {
    w: Writer<'a>,
    last_option: u16,
}

impl<'a> MessageBuilder<'a> {
    /// Start a message. `token` must be at most 8 bytes.
    pub fn new(
        buf: &'a mut [u8],
        ty: Type,
        code: Code,
        message_id: u16,
        token: &[u8],
    ) -> Result<Self> {
        if token.len() > MAX_TOKEN_LEN {
            return Err(Error::InvalidArgs);
        }
        let mut w = Writer::new(buf);
        w.write_u8(VERSION << 6 | (ty as u8) << 4 | token.len() as u8)?;
        w.write_u8(code.0)?;
        w.write_u16(message_id)?;
        w.write_slice(token)?;
        Ok(Self { w, last_option: 0 })
    }

    fn ext(v: u32) -> (u8, [u8; 2], usize) {
        if v < 13 {
            (v as u8, [0, 0], 0)
        } else if v < 269 {
            (13, [(v - 13) as u8, 0], 1)
        } else {
            let e = ((v - 269) as u16).to_be_bytes();
            (14, e, 2)
        }
    }

    /// Append an option.
    pub fn option(&mut self, number: u16, value: &[u8]) -> Result<&mut Self> {
        if number < self.last_option || value.len() > u16::MAX as usize - 269 {
            return Err(Error::InvalidArgs);
        }
        let (dn, de, dl) = Self::ext((number - self.last_option) as u32);
        let (ln, le, ll) = Self::ext(value.len() as u32);
        if self.w.len() + 1 + dl + ll + value.len() >= MAX_HEADER_LEN {
            return Err(Error::NoBufs);
        }
        if self.w.remaining() < 1 + dl + ll + value.len() {
            return Err(Error::NoBufs);
        }
        self.w.write_u8(dn << 4 | ln)?;
        self.w.write_slice(&de[..dl])?;
        self.w.write_slice(&le[..ll])?;
        self.w.write_slice(value)?;
        self.last_option = number;
        Ok(self)
    }

    /// Append a `uint` option (minimal length encoding; 0 is empty).
    pub fn uint_option(&mut self, number: u16, v: u32) -> Result<&mut Self> {
        let b = v.to_be_bytes();
        let skip = b.iter().take_while(|&&x| x == 0).count();
        self.option(number, &b[skip..])
    }

    /// Append one Uri-Path option per `/`-separated segment (OT
    /// `AppendUriPathOptions`: `"a/aq"` gives `a`, `aq`).
    pub fn uri_path(&mut self, path: &str) -> Result<&mut Self> {
        for seg in path.split('/') {
            self.option(opt::URI_PATH, seg.as_bytes())?;
        }
        Ok(self)
    }

    /// Append a Uri-Query option.
    pub fn uri_query(&mut self, q: &str) -> Result<&mut Self> {
        self.option(opt::URI_QUERY, q.as_bytes())
    }

    /// Append a Content-Format option.
    pub fn content_format(&mut self, cf: u16) -> Result<&mut Self> {
        self.uint_option(opt::CONTENT_FORMAT, cf as u32)
    }

    /// Append a Block1 or Block2 option.
    pub fn block(&mut self, number: u16, b: BlockOption) -> Result<&mut Self> {
        if number != opt::BLOCK1 && number != opt::BLOCK2 {
            return Err(Error::InvalidArgs);
        }
        self.uint_option(number, b.encode())
    }

    /// Finish with `payload` (marker omitted if the payload is empty, as OT
    /// `Message::Finish`); returns the encoded length.
    pub fn finish_with_payload(mut self, payload: &[u8]) -> Result<usize> {
        if !payload.is_empty() {
            self.w.write_u8(PAYLOAD_MARKER)?;
            self.w.write_slice(payload)?;
        }
        Ok(self.w.len())
    }

    /// Finish without payload; returns the encoded length.
    pub fn finish(self) -> Result<usize> {
        Ok(self.w.len())
    }

    /// Free space left in the buffer (for payload writers that fill the
    /// buffer directly via [`MessageBuilder::finish_with`]).
    pub fn remaining(&self) -> usize {
        self.w.remaining()
    }

    /// Finish with a payload produced by `f`, which writes into the
    /// builder's writer (e.g. TLVs). The marker is written first and
    /// removed again if `f` wrote nothing.
    pub fn finish_with<F>(mut self, f: F) -> Result<usize>
    where
        F: FnOnce(&mut Writer<'a>) -> Result<()>,
    {
        let before = self.w.len();
        self.w.write_u8(PAYLOAD_MARKER)?;
        f(&mut self.w)?;
        if self.w.len() == before + 1 {
            // `f` wrote nothing: the marker lies beyond the returned length.
            return Ok(before);
        }
        Ok(self.w.len())
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod diff_tests;
