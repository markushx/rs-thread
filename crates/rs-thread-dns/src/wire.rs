//! DNS wire format (RFC 1035, RFC 2136, RFC 6891): header, names with
//! compression, message writer and reader.
//!
//! Names are ASCII. A name is a sequence of labels of 1..=63 bytes with a
//! total encoded length of at most 255 bytes. Label comparison is ASCII
//! case-insensitive.
//!
//! # Compression
//!
//! [`Writer::write_name_parts`] compresses against the names already in
//! the message (longest matching suffix, up to [`MAX_COMPRESS_TARGETS`]
//! remembered label starts). [`Name`] follows compression pointers on read.
//! A pointer must point strictly before the start of the label run it
//! terminates, which makes pointer loops impossible (OT
//! `Name::LabelIterator` rejects the same cases).

use core::fmt;
use core::net::Ipv6Addr;

use rs_thread_core::{Error, Result};

/// Fixed DNS header length.
pub const HEADER_LEN: usize = 12;
/// Maximum label length.
pub const MAX_LABEL_LEN: usize = 63;
/// Maximum encoded name length (including the root label).
pub const MAX_NAME_LEN: usize = 255;
/// Compression targets remembered by a [`Writer`].
pub const MAX_COMPRESS_TARGETS: usize = 32;
/// Largest offset a compression pointer can express.
pub const MAX_POINTER_OFFSET: usize = 0x3fff;

/// Record types.
pub mod rtype {
    /// NS.
    pub const NS: u16 = 2;
    /// CNAME.
    pub const CNAME: u16 = 5;
    /// SOA (zone section type of an UPDATE).
    pub const SOA: u16 = 6;
    /// PTR.
    pub const PTR: u16 = 12;
    /// TXT.
    pub const TXT: u16 = 16;
    /// SIG (RFC 2535, used for SIG(0)).
    pub const SIG: u16 = 24;
    /// KEY (RFC 2535).
    pub const KEY: u16 = 25;
    /// AAAA.
    pub const AAAA: u16 = 28;
    /// SRV.
    pub const SRV: u16 = 33;
    /// OPT (EDNS(0)).
    pub const OPT: u16 = 41;
    /// ANY.
    pub const ANY: u16 = 255;
}

/// Record classes.
pub mod class {
    /// IN.
    pub const IN: u16 = 1;
    /// NONE (RFC 2136 delete one RR).
    pub const NONE: u16 = 254;
    /// ANY.
    pub const ANY: u16 = 255;
}

/// Opcodes.
pub mod opcode {
    /// Standard query.
    pub const QUERY: u8 = 0;
    /// Dynamic update (RFC 2136).
    pub const UPDATE: u8 = 5;
}

/// Response codes (the low 4 bits live in the header, RFC 6895 extended
/// codes are in the OPT record).
pub mod rcode {
    /// NOERROR.
    pub const SUCCESS: u8 = 0;
    /// FORMERR.
    pub const FORMAT_ERROR: u8 = 1;
    /// SERVFAIL.
    pub const SERVER_FAILURE: u8 = 2;
    /// NXDOMAIN.
    pub const NAME_ERROR: u8 = 3;
    /// NOTIMP.
    pub const NOT_IMPLEMENTED: u8 = 4;
    /// REFUSED.
    pub const REFUSED: u8 = 5;
    /// YXDOMAIN: a name that must not exist, exists (SRP name conflict).
    pub const NAME_EXISTS: u8 = 6;
    /// YXRRSET.
    pub const RECORD_EXISTS: u8 = 7;
    /// NXRRSET.
    pub const RECORD_NOT_EXISTS: u8 = 8;
    /// NOTAUTH.
    pub const NOT_AUTH: u8 = 9;
    /// NOTZONE.
    pub const NOT_ZONE: u8 = 10;
    /// BADNAME.
    pub const BAD_NAME: u8 = 20;
    /// BADALG.
    pub const BAD_ALG: u8 = 21;
    /// BADTRUNC.
    pub const BAD_TRUNCATION: u8 = 22;
}

/// The DNS header. The four counts are, depending on the opcode, the
/// question / answer / authority / additional counts of a query, or the
/// zone / prerequisite / update / additional counts of an UPDATE.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Header {
    /// Message ID.
    pub id: u16,
    /// QR flag: this is a response.
    pub response: bool,
    /// Opcode (4 bits).
    pub opcode: u8,
    /// Authoritative answer.
    pub aa: bool,
    /// Truncated.
    pub tc: bool,
    /// Recursion desired.
    pub rd: bool,
    /// Recursion available.
    pub ra: bool,
    /// Response code (4 bits).
    pub rcode: u8,
    /// Question (zone) count.
    pub qd: u16,
    /// Answer (prerequisite) count.
    pub an: u16,
    /// Authority (update) count.
    pub ns: u16,
    /// Additional count.
    pub ar: u16,
}

impl Header {
    /// Encode to wire format.
    pub fn encode(&self) -> [u8; HEADER_LEN] {
        let mut b = [0u8; HEADER_LEN];
        b[0..2].copy_from_slice(&self.id.to_be_bytes());
        b[2] = (u8::from(self.response) << 7)
            | ((self.opcode & 0x0f) << 3)
            | (u8::from(self.aa) << 2)
            | (u8::from(self.tc) << 1)
            | u8::from(self.rd);
        b[3] = (u8::from(self.ra) << 7) | (self.rcode & 0x0f);
        b[4..6].copy_from_slice(&self.qd.to_be_bytes());
        b[6..8].copy_from_slice(&self.an.to_be_bytes());
        b[8..10].copy_from_slice(&self.ns.to_be_bytes());
        b[10..12].copy_from_slice(&self.ar.to_be_bytes());
        b
    }

    /// Decode the first [`HEADER_LEN`] bytes of `msg`.
    pub fn decode(msg: &[u8]) -> Result<Self> {
        let b = msg.get(..HEADER_LEN).ok_or(Error::Parse)?;
        let u = |i: usize| u16::from_be_bytes([b[i], b[i + 1]]);
        Ok(Self {
            id: u(0),
            response: b[2] & 0x80 != 0,
            opcode: (b[2] >> 3) & 0x0f,
            aa: b[2] & 0x04 != 0,
            tc: b[2] & 0x02 != 0,
            rd: b[2] & 0x01 != 0,
            ra: b[3] & 0x80 != 0,
            rcode: b[3] & 0x0f,
            qd: u(4),
            an: u(6),
            ns: u(8),
            ar: u(10),
        })
    }
}

// ------------------------------------------------------------------- names

/// A (possibly compressed) name inside a message.
#[derive(Clone, Copy)]
pub struct Name<'a> {
    msg: &'a [u8],
    off: usize,
}

impl fmt::Debug for Name<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Name(")?;
        self.fmt_dotted(f)?;
        write!(f, ")")
    }
}

impl<'a> Name<'a> {
    /// The name starting at `off` in `msg` (not validated until read).
    pub const fn new(msg: &'a [u8], off: usize) -> Self {
        Self { msg, off }
    }

    /// Iterate over the labels (without the root label).
    pub fn labels(&self) -> Labels<'a> {
        Labels {
            msg: self.msg,
            pos: self.off,
            run_start: self.off,
            consumed: 0,
            done: false,
        }
    }

    /// Validate the name and return the offset right after its in-place
    /// encoding (after the terminating root label or the first pointer).
    pub fn end_offset(&self) -> Result<usize> {
        let mut pos = self.off;
        loop {
            match *self.msg.get(pos).ok_or(Error::Parse)? {
                0 => {
                    pos += 1;
                    break;
                }
                l if l & 0xc0 == 0xc0 => {
                    pos += 2;
                    break;
                }
                l if l & 0xc0 == 0 => pos += 1 + usize::from(l),
                _ => return Err(Error::Parse),
            }
        }
        if pos > self.msg.len() {
            return Err(Error::Parse);
        }
        // Full validation (pointer targets, total length).
        for l in self.labels() {
            l?;
        }
        Ok(pos)
    }

    /// Does this name equal `labels` (ASCII case-insensitive)?
    pub fn eq_labels<L: AsRef<[u8]>>(&self, labels: &[L]) -> bool {
        let mut it = self.labels();
        for want in labels {
            match it.next() {
                Some(Ok(l)) if l.eq_ignore_ascii_case(want.as_ref()) => {}
                _ => return false,
            }
        }
        it.next().is_none()
    }

    /// Does this name equal `other` (ASCII case-insensitive; the two may
    /// live in different messages)?
    pub fn eq_name(&self, other: &Name<'_>) -> bool {
        let mut a = self.labels();
        let mut b = other.labels();
        loop {
            match (a.next(), b.next()) {
                (None, None) => return true,
                (Some(Ok(x)), Some(Ok(y))) if x.eq_ignore_ascii_case(y) => {}
                _ => return false,
            }
        }
    }

    /// Does this name equal the name made of `parts` (as written by
    /// [`Writer::write_name_parts`])?
    pub fn eq_parts(&self, parts: &[Part<'_>]) -> bool {
        let mut it = self.labels();
        for p in parts {
            let (single, dotted) = match *p {
                Part::Label(l) => (Some(l), ""),
                Part::Dotted(d) => (None, d.strip_suffix('.').unwrap_or(d)),
            };
            let mut it_single = single.into_iter();
            let mut it_dotted = dotted.split('.').filter(|_| !dotted.is_empty());
            while let Some(want) = it_single.next().or_else(|| it_dotted.next()) {
                match it.next() {
                    Some(Ok(l)) if l.eq_ignore_ascii_case(want.as_bytes()) => {}
                    _ => return false,
                }
            }
        }
        it.next().is_none()
    }

    /// Does this name equal the dotted name `s` (trailing dot optional,
    /// no escapes)?
    pub fn eq_dotted(&self, s: &str) -> bool {
        let s = s.strip_suffix('.').unwrap_or(s);
        let mut it = self.labels();
        if s.is_empty() {
            return it.next().is_none();
        }
        for want in s.split('.') {
            match it.next() {
                Some(Ok(l)) if l.eq_ignore_ascii_case(want.as_bytes()) => {}
                _ => return false,
            }
        }
        it.next().is_none()
    }

    /// Is this name a subdomain of (or equal to) the dotted `suffix`?
    /// Returns the number of leading labels in front of the suffix.
    pub fn strip_suffix_dotted(&self, suffix: &str) -> Option<usize> {
        let suffix = suffix.strip_suffix('.').unwrap_or(suffix);
        let total = self.labels().count();
        let n = if suffix.is_empty() {
            0
        } else {
            suffix.split('.').count()
        };
        let lead = total.checked_sub(n)?;
        let mut it = self.labels().skip(lead);
        if !suffix.is_empty() {
            for want in suffix.split('.') {
                match it.next() {
                    Some(Ok(l)) if l.eq_ignore_ascii_case(want.as_bytes()) => {}
                    _ => return None,
                }
            }
        }
        Some(lead)
    }

    /// Write the dotted form (`.` and `\` inside labels are escaped with a
    /// backslash; the root name is `.`; no trailing dot otherwise).
    pub fn fmt_dotted(&self, f: &mut dyn fmt::Write) -> fmt::Result {
        let mut any = false;
        for l in self.labels() {
            let Ok(l) = l else {
                return f.write_str("<invalid>");
            };
            if any {
                f.write_char('.')?;
            }
            any = true;
            for &c in l {
                if c == b'.' || c == b'\\' {
                    f.write_char('\\')?;
                }
                f.write_char(if c.is_ascii_graphic() || c == b' ' {
                    c as char
                } else {
                    '?'
                })?;
            }
        }
        if !any {
            f.write_char('.')?;
        }
        Ok(())
    }

    /// The dotted form into a bounded string ([`Error::NoBufs`] if it does
    /// not fit).
    pub fn to_dotted<const N: usize>(&self) -> Result<heapless::String<N>> {
        let mut s = heapless::String::new();
        self.fmt_dotted(&mut s).map_err(|_| Error::NoBufs)?;
        Ok(s)
    }
}

/// Iterator over the labels of a [`Name`]; yields `Err` once on a
/// malformed name.
#[derive(Debug, Clone)]
pub struct Labels<'a> {
    msg: &'a [u8],
    pos: usize,
    run_start: usize,
    consumed: usize,
    done: bool,
}

impl<'a> Iterator for Labels<'a> {
    type Item = Result<&'a [u8]>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        loop {
            let Some(&l) = self.msg.get(self.pos) else {
                self.done = true;
                return Some(Err(Error::Parse));
            };
            match l {
                0 => {
                    self.done = true;
                    return None;
                }
                l if l & 0xc0 == 0xc0 => {
                    let Some(&b) = self.msg.get(self.pos + 1) else {
                        self.done = true;
                        return Some(Err(Error::Parse));
                    };
                    let target = (usize::from(l & 0x3f) << 8) | usize::from(b);
                    if target >= self.run_start {
                        self.done = true;
                        return Some(Err(Error::Parse));
                    }
                    self.pos = target;
                    self.run_start = target;
                }
                l if l & 0xc0 == 0 => {
                    let n = usize::from(l);
                    let start = self.pos + 1;
                    let Some(label) = self.msg.get(start..start + n) else {
                        self.done = true;
                        return Some(Err(Error::Parse));
                    };
                    self.consumed += 1 + n;
                    if self.consumed + 1 > MAX_NAME_LEN {
                        self.done = true;
                        return Some(Err(Error::Parse));
                    }
                    self.pos = start + n;
                    return Some(Ok(label));
                }
                _ => {
                    self.done = true;
                    return Some(Err(Error::Parse));
                }
            }
        }
    }
}

/// One piece of a name given to [`Writer::write_name_parts`].
#[derive(Debug, Clone, Copy)]
pub enum Part<'a> {
    /// A single label (may contain dots, e.g. a DNS-SD instance name).
    Label(&'a str),
    /// A dotted sequence of labels (trailing dot optional; empty or `.` is
    /// nothing).
    Dotted(&'a str),
}

// ------------------------------------------------------------------ reader

/// A parsed question.
#[derive(Debug, Clone, Copy)]
pub struct Question<'a> {
    /// Question name.
    pub name: Name<'a>,
    /// QTYPE.
    pub qtype: u16,
    /// QCLASS.
    pub qclass: u16,
}

/// A parsed resource record (rdata not interpreted).
#[derive(Debug, Clone, Copy)]
pub struct Record<'a> {
    /// The whole message (names inside the rdata are relative to it).
    pub msg: &'a [u8],
    /// Owner name.
    pub name: Name<'a>,
    /// Type.
    pub rtype: u16,
    /// Class (for OPT: the UDP payload size).
    pub class: u16,
    /// TTL (for OPT: extended rcode, version and flags).
    pub ttl: u32,
    /// Offset of the rdata in `msg`.
    pub rdata_off: usize,
    /// The rdata.
    pub rdata: &'a [u8],
}

/// Sequential reader over the sections of a message.
#[derive(Debug, Clone)]
pub struct Parser<'a> {
    msg: &'a [u8],
    pos: usize,
}

impl<'a> Parser<'a> {
    /// Start reading `msg` after the header, which is returned.
    pub fn new(msg: &'a [u8]) -> Result<(Self, Header)> {
        let h = Header::decode(msg)?;
        Ok((
            Self {
                msg,
                pos: HEADER_LEN,
            },
            h,
        ))
    }

    /// Current offset.
    pub const fn offset(&self) -> usize {
        self.pos
    }

    /// Read a question (also the zone section of an UPDATE).
    pub fn question(&mut self) -> Result<Question<'a>> {
        let name = Name::new(self.msg, self.pos);
        let p = name.end_offset()?;
        let f = self.msg.get(p..p + 4).ok_or(Error::Parse)?;
        self.pos = p + 4;
        Ok(Question {
            name,
            qtype: u16::from_be_bytes([f[0], f[1]]),
            qclass: u16::from_be_bytes([f[2], f[3]]),
        })
    }

    /// Read a resource record.
    pub fn record(&mut self) -> Result<Record<'a>> {
        let name = Name::new(self.msg, self.pos);
        let p = name.end_offset()?;
        let f = self.msg.get(p..p + 10).ok_or(Error::Parse)?;
        let rdlen = usize::from(u16::from_be_bytes([f[8], f[9]]));
        let rdata_off = p + 10;
        let rdata = self
            .msg
            .get(rdata_off..rdata_off + rdlen)
            .ok_or(Error::Parse)?;
        self.pos = rdata_off + rdlen;
        Ok(Record {
            msg: self.msg,
            name,
            rtype: u16::from_be_bytes([f[0], f[1]]),
            class: u16::from_be_bytes([f[2], f[3]]),
            ttl: u32::from_be_bytes([f[4], f[5], f[6], f[7]]),
            rdata_off,
            rdata,
        })
    }
}

/// SRV rdata.
#[derive(Debug, Clone, Copy)]
pub struct Srv<'a> {
    /// Priority.
    pub priority: u16,
    /// Weight.
    pub weight: u16,
    /// Port.
    pub port: u16,
    /// Target host name.
    pub target: Name<'a>,
}

impl<'a> Record<'a> {
    /// AAAA rdata.
    pub fn aaaa(&self) -> Result<Ipv6Addr> {
        let b: [u8; 16] = self.rdata.try_into().map_err(|_| Error::Parse)?;
        Ok(Ipv6Addr::from(b))
    }

    /// PTR (or CNAME / NS) rdata: the target name.
    pub fn ptr(&self) -> Result<Name<'a>> {
        let n = Name::new(self.msg, self.rdata_off);
        if n.end_offset()? != self.rdata_off + self.rdata.len() {
            return Err(Error::Parse);
        }
        Ok(n)
    }

    /// SRV rdata.
    pub fn srv(&self) -> Result<Srv<'a>> {
        let b = self.rdata.get(..6).ok_or(Error::Parse)?;
        let target = Name::new(self.msg, self.rdata_off + 6);
        if target.end_offset()? != self.rdata_off + self.rdata.len() {
            return Err(Error::Parse);
        }
        Ok(Srv {
            priority: u16::from_be_bytes([b[0], b[1]]),
            weight: u16::from_be_bytes([b[2], b[3]]),
            port: u16::from_be_bytes([b[4], b[5]]),
            target,
        })
    }
}

// ------------------------------------------------------------------ writer

/// Message builder over a caller-provided buffer.
///
/// Every write returns [`Error::NoBufs`] when the buffer is too small; a
/// failed message must be discarded (or [`Writer::truncate`]d back to a
/// known length by the caller).
#[derive(Debug)]
pub struct Writer<'a> {
    buf: &'a mut [u8],
    len: usize,
    targets: [u16; MAX_COMPRESS_TARGETS],
    ntargets: usize,
}

impl<'a> Writer<'a> {
    /// A writer with room for the header, which is zeroed.
    pub fn new(buf: &'a mut [u8]) -> Result<Self> {
        let hdr = buf.get_mut(..HEADER_LEN).ok_or(Error::NoBufs)?;
        hdr.fill(0);
        Ok(Self {
            buf,
            len: HEADER_LEN,
            targets: [0; MAX_COMPRESS_TARGETS],
            ntargets: 0,
        })
    }

    /// Bytes written so far.
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Always false (the header is always present).
    pub const fn is_empty(&self) -> bool {
        false
    }

    /// The message so far.
    pub fn as_bytes(&self) -> &[u8] {
        &self.buf[..self.len]
    }

    /// Cut the message back to `len` bytes (forgets compression targets at
    /// or beyond it).
    pub fn truncate(&mut self, len: usize) {
        if len < self.len {
            self.len = len.max(HEADER_LEN);
            while self.ntargets > 0 && usize::from(self.targets[self.ntargets - 1]) >= self.len {
                self.ntargets -= 1;
            }
        }
    }

    /// Overwrite the header.
    pub fn set_header(&mut self, h: &Header) {
        self.buf[..HEADER_LEN].copy_from_slice(&h.encode());
    }

    /// Append raw bytes.
    pub fn put(&mut self, data: &[u8]) -> Result<()> {
        let end = self.len + data.len();
        self.buf
            .get_mut(self.len..end)
            .ok_or(Error::NoBufs)?
            .copy_from_slice(data);
        self.len = end;
        Ok(())
    }

    /// Append a `u16`.
    pub fn put_u16(&mut self, v: u16) -> Result<()> {
        self.put(&v.to_be_bytes())
    }

    /// Append a `u32`.
    pub fn put_u32(&mut self, v: u32) -> Result<()> {
        self.put(&v.to_be_bytes())
    }

    /// Append the root label.
    pub fn write_root(&mut self) -> Result<()> {
        self.put(&[0])
    }

    /// Append a compression pointer to `offset`.
    pub fn write_pointer(&mut self, offset: usize) -> Result<()> {
        if offset > MAX_POINTER_OFFSET {
            return Err(Error::InvalidArgs);
        }
        self.put_u16(0xc000 | offset as u16)
    }

    /// Write a dotted name, compressed.
    pub fn write_name(&mut self, dotted: &str) -> Result<()> {
        self.write_name_parts(&[Part::Dotted(dotted)], true)
    }

    /// Write a name made of `parts`; `compress` allows pointers to earlier
    /// names (and records this name as a target).
    pub fn write_name_parts(&mut self, parts: &[Part<'_>], compress: bool) -> Result<()> {
        let mut labels: [&str; 127] = [""; 127];
        let mut k = 0usize;
        let mut total = 1usize;
        for p in parts {
            let (single, dotted) = match *p {
                Part::Label(l) => (Some(l), ""),
                Part::Dotted(d) => (None, d.strip_suffix('.').unwrap_or(d)),
            };
            let mut it_single = single.into_iter();
            let mut it_dotted = dotted.split('.').filter(|_| !dotted.is_empty());
            while let Some(l) = it_single.next().or_else(|| it_dotted.next()) {
                if l.is_empty() || l.len() > MAX_LABEL_LEN || k >= labels.len() {
                    return Err(Error::InvalidArgs);
                }
                total += 1 + l.len();
                if total > MAX_NAME_LEN {
                    return Err(Error::InvalidArgs);
                }
                labels[k] = l;
                k += 1;
            }
        }
        self.write_labels(&labels[..k], compress)
    }

    /// Write the name in `wire` (uncompressed wire format with the root
    /// label) as a name.
    pub fn write_wire_name(&mut self, wire: &[u8], compress: bool) -> Result<()> {
        let mut labels: [&[u8]; 127] = [&[]; 127];
        let mut k = 0usize;
        let mut i = 0usize;
        loop {
            let n = usize::from(*wire.get(i).ok_or(Error::Parse)?);
            if n == 0 {
                break;
            }
            if n > MAX_LABEL_LEN || k >= labels.len() {
                return Err(Error::Parse);
            }
            labels[k] = wire.get(i + 1..i + 1 + n).ok_or(Error::Parse)?;
            k += 1;
            i += 1 + n;
        }
        self.write_labels(&labels[..k], compress)
    }

    /// Write `labels` as a name.
    pub fn write_labels<L: AsRef<[u8]>>(&mut self, labels: &[L], compress: bool) -> Result<()> {
        let start_len = self.len;
        let start_targets = self.ntargets;
        let r = self.write_labels_inner(labels, compress);
        if r.is_err() {
            self.len = start_len;
            self.ntargets = start_targets;
        }
        r
    }

    fn write_labels_inner<L: AsRef<[u8]>>(&mut self, labels: &[L], compress: bool) -> Result<()> {
        // Longest suffix already present in the message.
        let mut ptr_to = None;
        let mut emit = labels.len();
        if compress {
            for i in 0..labels.len() {
                let suffix = &labels[i..];
                let found = self.targets[..self.ntargets]
                    .iter()
                    .find(|&&t| Name::new(&self.buf[..self.len], usize::from(t)).eq_labels(suffix));
                if let Some(&t) = found {
                    ptr_to = Some(usize::from(t));
                    emit = i;
                    break;
                }
            }
        }
        for l in &labels[..emit] {
            let l = l.as_ref();
            let off = self.len;
            self.put(&[l.len() as u8])?;
            self.put(l)?;
            if compress && off <= MAX_POINTER_OFFSET && self.ntargets < MAX_COMPRESS_TARGETS {
                self.targets[self.ntargets] = off as u16;
                self.ntargets += 1;
            }
        }
        match ptr_to {
            Some(t) => self.write_pointer(t),
            None => self.write_root(),
        }
    }

    /// Write a question / zone entry.
    pub fn write_question(&mut self, name: &str, qtype: u16, qclass: u16) -> Result<()> {
        self.write_name(name)?;
        self.put_u16(qtype)?;
        self.put_u16(qclass)
    }

    /// Start a record whose owner name is already written: appends type,
    /// class, TTL and a zero RDLENGTH. Pass the result to
    /// [`Writer::end_record`] after writing the rdata.
    pub fn begin_record(&mut self, rtype: u16, class: u16, ttl: u32) -> Result<usize> {
        self.put_u16(rtype)?;
        self.put_u16(class)?;
        self.put_u32(ttl)?;
        let mark = self.len;
        self.put_u16(0)?;
        Ok(mark)
    }

    /// Patch the RDLENGTH of the record started with `mark`.
    pub fn end_record(&mut self, mark: usize) -> Result<()> {
        let rdlen = self.len - mark - 2;
        let rdlen = u16::try_from(rdlen).map_err(|_| Error::NoBufs)?;
        self.buf[mark..mark + 2].copy_from_slice(&rdlen.to_be_bytes());
        Ok(())
    }

    /// Write a complete AAAA record for the already written owner name.
    pub fn write_aaaa(&mut self, ttl: u32, addr: &Ipv6Addr) -> Result<()> {
        let m = self.begin_record(rtype::AAAA, class::IN, ttl)?;
        self.put(&addr.octets())?;
        self.end_record(m)
    }
}
