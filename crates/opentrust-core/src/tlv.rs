//! Generic Type-Length-Value utilities shared by MLE, TMF and MeshCoP
//! (OT `common/tlvs.{hpp,cpp}`).
//!
//! Wire format: `type (1) | length (1) | value (length)`. A length byte of
//! `0xFF` escapes to an *extended* TLV: `type | 0xFF | length (2, BE) | value`.
//! The writer uses the extended form iff the value is longer than 254 bytes
//! (OT `kBaseTlvMaxLength`); the parser accepts an extended form for any
//! length, like OT.
//!
//! The module lives in `opentrust-core` (not `opentrust-coap`) because MLE
//! and MeshCoP need it without depending on CoAP, while every protocol
//! crate already depends on core. It works on plain byte slices; a
//! [`crate::message::Message`] exposes its payload as a slice.
//!
//! - Parse: [`Tlv::parse`], [`TlvIter`], [`find`], [`Tlv::read_u8`] ...
//! - Build: [`write`], [`write_uint`], [`write_str`], [`write_with`].

use crate::bytes::Writer;
use crate::error::{Error, Result};

/// Length byte value that announces a 2-byte extended length.
pub const EXTENDED_LENGTH: u8 = 0xff;
/// Longest value of a base (non-extended) TLV.
pub const BASE_MAX_LENGTH: usize = 254;

/// A parsed TLV borrowing its value from the input buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Tlv<'a> {
    ty: u8,
    extended: bool,
    value: &'a [u8],
}

impl<'a> Tlv<'a> {
    /// Parse one TLV from the start of `buf`; returns it and the remaining
    /// bytes. [`Error::Parse`] if the header or value is truncated.
    pub fn parse(buf: &'a [u8]) -> Result<(Tlv<'a>, &'a [u8])> {
        let (&ty, rest) = buf.split_first().ok_or(Error::Parse)?;
        let (&len, rest) = rest.split_first().ok_or(Error::Parse)?;
        let (extended, len, rest) = if len == EXTENDED_LENGTH {
            let hi = *rest.first().ok_or(Error::Parse)?;
            let lo = *rest.get(1).ok_or(Error::Parse)?;
            (
                true,
                u16::from_be_bytes([hi, lo]) as usize,
                rest.get(2..).ok_or(Error::Parse)?,
            )
        } else {
            (false, len as usize, rest)
        };
        if rest.len() < len {
            return Err(Error::Parse);
        }
        let (value, rest) = rest.split_at(len);
        Ok((
            Tlv {
                ty,
                extended,
                value,
            },
            rest,
        ))
    }

    /// TLV type.
    pub const fn ty(&self) -> u8 {
        self.ty
    }

    /// `true` if the TLV used the extended (2-byte) length encoding.
    pub const fn is_extended(&self) -> bool {
        self.extended
    }

    /// Value bytes.
    pub const fn value(&self) -> &'a [u8] {
        self.value
    }

    /// Encoded size (header + value).
    pub const fn size(&self) -> usize {
        header_len(self.value.len()) + self.value.len()
    }

    /// First `N` value bytes (OT `ReadTlvValue` with a minimum length; extra
    /// bytes are ignored). [`Error::Parse`] if the value is shorter.
    pub fn read_array<const N: usize>(&self) -> Result<[u8; N]> {
        let mut out = [0u8; N];
        out.copy_from_slice(self.value.get(..N).ok_or(Error::Parse)?);
        Ok(out)
    }

    /// Value as `u8` (value must be at least 1 byte).
    pub fn read_u8(&self) -> Result<u8> {
        Ok(self.read_array::<1>()?[0])
    }

    /// Value as big-endian `u16` (at least 2 bytes).
    pub fn read_u16(&self) -> Result<u16> {
        Ok(u16::from_be_bytes(self.read_array()?))
    }

    /// Value as big-endian `u32` (at least 4 bytes).
    pub fn read_u32(&self) -> Result<u32> {
        Ok(u32::from_be_bytes(self.read_array()?))
    }

    /// Value as big-endian `u64` (at least 8 bytes).
    pub fn read_u64(&self) -> Result<u64> {
        Ok(u64::from_be_bytes(self.read_array()?))
    }

    /// Value as a string of at most `max_len` bytes (OT `ReadStringTlv`
    /// truncates silently); [`Error::Parse`] if the bytes are not UTF-8.
    pub fn read_str(&self, max_len: usize) -> Result<&'a str> {
        let v = &self.value[..self.value.len().min(max_len)];
        core::str::from_utf8(v).map_err(|_| Error::Parse)
    }
}

/// Iterator over the TLVs of a buffer. After a malformed TLV it yields one
/// `Err(Error::Parse)` and then ends.
#[derive(Debug, Clone)]
pub struct TlvIter<'a> {
    rest: &'a [u8],
}

impl<'a> TlvIter<'a> {
    /// Iterate over the TLVs in `buf`.
    pub const fn new(buf: &'a [u8]) -> Self {
        Self { rest: buf }
    }
}

impl<'a> Iterator for TlvIter<'a> {
    type Item = Result<Tlv<'a>>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.rest.is_empty() {
            return None;
        }
        match Tlv::parse(self.rest) {
            Ok((t, rest)) => {
                self.rest = rest;
                Some(Ok(t))
            }
            Err(e) => {
                self.rest = &[];
                Some(Err(e))
            }
        }
    }
}

/// Find the first TLV of type `ty` (OT `Tlv::FindTlv`). [`Error::NotFound`]
/// if absent, [`Error::Parse`] if a malformed TLV is hit before it.
pub fn find(buf: &[u8], ty: u8) -> Result<Tlv<'_>> {
    for t in TlvIter::new(buf) {
        let t = t?;
        if t.ty == ty {
            return Ok(t);
        }
    }
    Err(Error::NotFound)
}

/// Check that `buf` is a well-formed sequence of TLVs.
pub fn validate(buf: &[u8]) -> Result<()> {
    TlvIter::new(buf).try_for_each(|t| t.map(|_| ()))
}

const fn header_len(value_len: usize) -> usize {
    if value_len > BASE_MAX_LENGTH { 4 } else { 2 }
}

/// Append a TLV (OT `Tlv::AppendTlv`), choosing the extended form for values
/// longer than 254 bytes. [`Error::NoBufs`] if it does not fit,
/// [`Error::InvalidArgs`] if the value exceeds 65535 bytes.
pub fn write(w: &mut Writer<'_>, ty: u8, value: &[u8]) -> Result<()> {
    if value.len() > u16::MAX as usize {
        return Err(Error::InvalidArgs);
    }
    if w.remaining() < header_len(value.len()) + value.len() {
        return Err(Error::NoBufs);
    }
    write_header(w, ty, value.len())?;
    w.write_slice(value)
}

fn write_header(w: &mut Writer<'_>, ty: u8, len: usize) -> Result<()> {
    w.write_u8(ty)?;
    if len > BASE_MAX_LENGTH {
        w.write_u8(EXTENDED_LENGTH)?;
        w.write_u16(len as u16)
    } else {
        w.write_u8(len as u8)
    }
}

/// Append a TLV whose value is produced by `f` (for nested TLVs or values of
/// unknown size). On error the writer may contain a partial TLV.
pub fn write_with<F>(w: &mut Writer<'_>, ty: u8, f: F) -> Result<()>
where
    F: FnOnce(&mut Writer<'_>) -> Result<()>,
{
    let start = w.reserve(0)?;
    w.write_u8(ty)?;
    w.write_u8(0)?;
    let value_start = start + 2;
    f(w)?;
    let len = w.len() - value_start;
    if len > u16::MAX as usize {
        return Err(Error::InvalidArgs);
    }
    if len > BASE_MAX_LENGTH {
        // Make room for the 2 extra length bytes and shift the value.
        w.reserve(2)?;
        let buf = w.written_mut();
        buf.copy_within(value_start..value_start + len, value_start + 2);
        buf[start + 1] = EXTENDED_LENGTH;
        buf[start + 2..start + 4].copy_from_slice(&(len as u16).to_be_bytes());
    } else {
        w.written_mut()[start + 1] = len as u8;
    }
    Ok(())
}

/// Append a 1-byte TLV.
pub fn write_u8(w: &mut Writer<'_>, ty: u8, v: u8) -> Result<()> {
    write(w, ty, &[v])
}

/// Append a big-endian 2-byte TLV.
pub fn write_u16(w: &mut Writer<'_>, ty: u8, v: u16) -> Result<()> {
    write(w, ty, &v.to_be_bytes())
}

/// Append a big-endian 4-byte TLV.
pub fn write_u32(w: &mut Writer<'_>, ty: u8, v: u32) -> Result<()> {
    write(w, ty, &v.to_be_bytes())
}

/// Append a big-endian 8-byte TLV.
pub fn write_u64(w: &mut Writer<'_>, ty: u8, v: u64) -> Result<()> {
    write(w, ty, &v.to_be_bytes())
}

/// Append a string TLV (no terminator). [`Error::InvalidArgs`] if the string
/// is longer than `max_len`.
pub fn write_str(w: &mut Writer<'_>, ty: u8, max_len: usize, s: &str) -> Result<()> {
    if s.len() > max_len {
        return Err(Error::InvalidArgs);
    }
    write(w, ty, s.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Port of OT `tests/unit/test_tlv.cpp` `TestTlv`: the same TLV sequence
    /// is built (normal/extended, empty, with value, truncated, overflow)
    /// and probed with find/read at each step.
    #[test]
    fn ot_test_tlv() {
        let mut msg: [u8; 64] = [0; 64];
        let mut n = 0usize;
        fn push(msg: &mut [u8; 64], n: &mut usize, b: &[u8]) {
            msg[*n..*n + b.len()].copy_from_slice(b);
            *n += b.len();
        }
        // Reads value of TLV at `off` requiring `min` bytes (ReadTlvValue).
        fn read_value(buf: &[u8], off: usize, min: usize) -> Result<[u8; 4]> {
            let (t, _) = Tlv::parse(buf.get(off..).ok_or(Error::Parse)?)?;
            let v = t.value();
            if v.len() < min {
                return Err(Error::Parse);
            }
            let mut out = [0; 4];
            out[..min].copy_from_slice(&v[..min]);
            Ok(out)
        }

        assert_eq!(find(&msg[..0], 1), Err(Error::NotFound));
        assert_eq!(read_value(&msg[..0], 0, 1), Err(Error::Parse));

        // type 1, empty
        let off1 = n;
        push(&mut msg, &mut n, &[1, 0]);
        let t = find(&msg[..n], 1).unwrap();
        assert_eq!((t.value().len(), t.is_extended()), (0, false));
        assert!(read_value(&msg[..n], off1, 0).is_ok());
        assert_eq!(read_value(&msg[..n], off1, 1), Err(Error::Parse));

        // type 2, extended, empty
        let off2 = n;
        push(&mut msg, &mut n, &[2, 0xff, 0, 0]);
        let t = find(&msg[..n], 2).unwrap();
        assert!(t.is_extended() && t.value().is_empty());
        assert!(read_value(&msg[..n], off2, 0).is_ok());
        assert_eq!(read_value(&msg[..n], off2, 1), Err(Error::Parse));

        // type 3, one byte 0xff
        let off3 = n;
        push(&mut msg, &mut n, &[3, 1, 0xff]);
        assert_eq!(find(&msg[..n], 3).unwrap().value(), &[0xff]);
        assert_eq!(read_value(&msg[..n], off3, 1).unwrap()[0], 0xff);
        assert_eq!(read_value(&msg[..n], off3, 2), Err(Error::Parse));

        // type 4, extended, 0x12 0x34
        let off4 = n;
        push(&mut msg, &mut n, &[4, 0xff, 0, 2, 0x12, 0x34]);
        let t = find(&msg[..n], 4).unwrap();
        assert_eq!(t.value(), &[0x12, 0x34]);
        assert_eq!(t.read_u16(), Ok(0x1234));
        assert_eq!(read_value(&msg[..n], off4, 3), Err(Error::Parse));

        // type 5, missing value, then completed
        let off5 = n;
        push(&mut msg, &mut n, &[5, 1]);
        assert!(find(&msg[..n], 5).is_err());
        assert_eq!(read_value(&msg[..n], off5, 0), Err(Error::Parse));
        push(&mut msg, &mut n, &[0xaa]);
        assert_eq!(find(&msg[..n], 5).unwrap().value(), &[0xaa]);
        assert_eq!(read_value(&msg[..n], off5, 2), Err(Error::Parse));

        // type 6, extended, missing last byte, then completed
        let off6 = n;
        push(&mut msg, &mut n, &[6, 0xff, 0, 2, 0xbb]);
        assert!(find(&msg[..n], 6).is_err());
        assert_eq!(read_value(&msg[..n], off6, 1), Err(Error::Parse));
        push(&mut msg, &mut n, &[0xcc]);
        let t = find(&msg[..n], 6).unwrap();
        assert_eq!(t.value(), &[0xbb, 0xcc]);
        assert_eq!(read_value(&msg[..n], off6, 3), Err(Error::Parse));

        // type 7, extended with overflow length
        let off7 = n;
        push(&mut msg, &mut n, &[7, 0xff, 0xff, 0xff, 0x11]);
        assert!(find(&msg[..n], 7).is_err());
        assert_eq!(read_value(&msg[..n], off7, 1), Err(Error::Parse));
    }

    #[test]
    fn iterate_and_errors() {
        let buf = [1, 1, 9, 2, 0, 3, 2, 1, 2];
        let mut it = TlvIter::new(&buf);
        assert_eq!(it.next().unwrap().unwrap().ty(), 1);
        assert_eq!(it.next().unwrap().unwrap().size(), 2);
        assert_eq!(it.next().unwrap().unwrap().value(), &[1, 2]);
        assert!(it.next().is_none());
        assert_eq!(validate(&buf), Ok(()));
        let bad = [1, 1, 9, 2, 5];
        let mut it = TlvIter::new(&bad);
        assert!(it.next().unwrap().is_ok());
        assert_eq!(it.next().unwrap().unwrap_err(), Error::Parse);
        assert!(it.next().is_none());
        assert_eq!(find(&bad, 1).unwrap().read_u8(), Ok(9));
        assert_eq!(find(&bad, 3), Err(Error::Parse));
        assert_eq!(find(&buf, 9), Err(Error::NotFound));
    }

    #[test]
    fn typed_helpers_round_trip() {
        let mut b = [0u8; 64];
        let mut w = Writer::new(&mut b);
        write_u8(&mut w, 1, 0xab).unwrap();
        write_u16(&mut w, 2, 0x1234).unwrap();
        write_u32(&mut w, 3, 0xdead_beef).unwrap();
        write_u64(&mut w, 4, 0x0102_0304_0506_0708).unwrap();
        write_str(&mut w, 5, 8, "thread").unwrap();
        assert_eq!(write_str(&mut w, 5, 3, "thread"), Err(Error::InvalidArgs));
        let n = w.len();
        let buf = &b[..n];
        assert_eq!(find(buf, 1).unwrap().read_u8(), Ok(0xab));
        assert_eq!(find(buf, 2).unwrap().read_u16(), Ok(0x1234));
        assert_eq!(find(buf, 3).unwrap().read_u32(), Ok(0xdead_beef));
        assert_eq!(find(buf, 4).unwrap().read_u64(), Ok(0x0102_0304_0506_0708));
        assert_eq!(find(buf, 5).unwrap().read_str(4), Ok("thre"));
        assert_eq!(find(buf, 2).unwrap().read_u32(), Err(Error::Parse));
        assert_eq!(find(buf, 2).unwrap().read_array::<2>(), Ok([0x12, 0x34]));
    }

    #[test]
    fn extended_boundary_and_nested() {
        let data = [0x5a; 300];
        for len in [0usize, 1, 253, 254, 255, 256, 300] {
            let mut b = [0u8; 320];
            let mut w = Writer::new(&mut b);
            write(&mut w, 7, &data[..len]).unwrap();
            let n = w.len();
            let (t, rest) = Tlv::parse(&b[..n]).unwrap();
            assert_eq!(t.is_extended(), len > 254, "len {len}");
            assert_eq!(t.value(), &data[..len]);
            assert_eq!(t.size(), n);
            assert!(rest.is_empty());

            // write_with produces identical bytes.
            let mut b2 = [0u8; 320];
            let mut w2 = Writer::new(&mut b2);
            write_with(&mut w2, 7, |w| w.write_slice(&data[..len])).unwrap();
            assert_eq!(w2.written(), &b[..n]);
        }
        // Nested TLVs.
        let mut b = [0u8; 16];
        let mut w = Writer::new(&mut b);
        write_with(&mut w, 1, |w| {
            write_u8(w, 2, 5)?;
            write_u8(w, 3, 6)
        })
        .unwrap();
        let outer = find(w.written(), 1).unwrap();
        assert_eq!(find(outer.value(), 3).unwrap().read_u8(), Ok(6));
        // Buffer too small.
        let mut small = [0u8; 3];
        let mut w = Writer::new(&mut small);
        assert_eq!(write(&mut w, 1, &[1, 2]), Err(Error::NoBufs));
        assert_eq!(w.len(), 0);
        let mut big = [0u8; 4];
        let mut w = Writer::new(&mut big);
        assert_eq!(write(&mut w, 1, &[0; 70_000]), Err(Error::InvalidArgs));
    }

    #[test]
    fn truncation_never_panics() {
        let mut b = [0u8; 400];
        let mut w = Writer::new(&mut b);
        write(&mut w, 1, &[7; 3]).unwrap();
        write(&mut w, 2, &[8; 300]).unwrap();
        write_u16(&mut w, 3, 9).unwrap();
        let n = w.len();
        for cut in 0..n {
            let _ = validate(&b[..cut]);
            let _ = find(&b[..cut], 3);
            for t in TlvIter::new(&b[..cut]).flatten() {
                let _ = t.read_u32();
                let _ = t.read_str(3);
            }
        }
        assert_eq!(validate(&b[..n]), Ok(()));
    }
}
