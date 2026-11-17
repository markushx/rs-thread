//! Spinel data types (`spinel_datatype_pack`/`unpack` of OpenThread).
//!
//! | char | type | encoding |
//! |------|------|----------|
//! | `b` | bool | 1 byte |
//! | `C` `c` | u8, i8 | 1 byte |
//! | `S` `s` | u16, i16 | little endian |
//! | `L` `l` | u32, i32 | little endian |
//! | `X` `x` | u64, i64 | little endian |
//! | `i` | packed unsigned | 7 bits per byte, LSB first, MSB = more |
//! | `6` `E` `e` | IPv6 / EUI-64 / EUI-48 | 16 / 8 / 6 bytes |
//! | `U` | UTF-8 string | NUL terminated |
//! | `d` | data | `u16` length prefix |
//! | `D` | data | rest of the enclosing struct or frame |
//! | `t(...)` | struct | `u16` length prefix |
//! | `A(...)` | array | the elements back to back |

use crate::{Error, Result};

/// Largest value of a packed unsigned integer (`SPINEL_MAX_UINT_PACKED`).
pub const MAX_UINT_PACKED: u32 = 2_097_151;

/// Writes Spinel values into a caller-provided buffer.
#[derive(Debug)]
pub struct Writer<'a> {
    buf: &'a mut [u8],
    len: usize,
}

impl<'a> Writer<'a> {
    /// A writer over `buf`.
    pub fn new(buf: &'a mut [u8]) -> Self {
        Self { buf, len: 0 }
    }

    /// Bytes written so far.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Whether nothing was written.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The bytes written so far.
    pub fn as_slice(&self) -> &[u8] {
        &self.buf[..self.len]
    }

    /// Bytes still available.
    pub fn remaining(&self) -> usize {
        self.buf.len() - self.len
    }

    /// Drops everything after the first `len` bytes.
    pub fn truncate(&mut self, len: usize) {
        self.len = self.len.min(len);
    }

    /// Appends raw bytes (`D` without a length, also the building block of
    /// the other writers).
    pub fn bytes(&mut self, data: &[u8]) -> Result<()> {
        let end = self.len.checked_add(data.len()).ok_or(Error::NoBufs)?;
        self.buf
            .get_mut(self.len..end)
            .ok_or(Error::NoBufs)?
            .copy_from_slice(data);
        self.len = end;
        Ok(())
    }

    /// `b`
    pub fn bool(&mut self, v: bool) -> Result<()> {
        self.u8(v as u8)
    }

    /// `C`
    pub fn u8(&mut self, v: u8) -> Result<()> {
        self.bytes(&[v])
    }

    /// `c`
    pub fn i8(&mut self, v: i8) -> Result<()> {
        self.bytes(&[v as u8])
    }

    /// `S`
    pub fn u16(&mut self, v: u16) -> Result<()> {
        self.bytes(&v.to_le_bytes())
    }

    /// `s`
    pub fn i16(&mut self, v: i16) -> Result<()> {
        self.bytes(&v.to_le_bytes())
    }

    /// `L`
    pub fn u32(&mut self, v: u32) -> Result<()> {
        self.bytes(&v.to_le_bytes())
    }

    /// `l`
    pub fn i32(&mut self, v: i32) -> Result<()> {
        self.bytes(&v.to_le_bytes())
    }

    /// `X`
    pub fn u64(&mut self, v: u64) -> Result<()> {
        self.bytes(&v.to_le_bytes())
    }

    /// `x`
    pub fn i64(&mut self, v: i64) -> Result<()> {
        self.bytes(&v.to_le_bytes())
    }

    /// `i`: packed unsigned integer.
    pub fn packed(&mut self, mut v: u32) -> Result<()> {
        loop {
            let low = (v & 0x7f) as u8;
            v >>= 7;
            if v == 0 {
                return self.u8(low);
            }
            self.u8(low | 0x80)?;
        }
    }

    /// `E` and `6`: a fixed-size array.
    pub fn array<const N: usize>(&mut self, v: &[u8; N]) -> Result<()> {
        self.bytes(v)
    }

    /// `U`: NUL terminated string.
    pub fn utf8(&mut self, s: &str) -> Result<()> {
        self.bytes(s.as_bytes())?;
        self.u8(0)
    }

    /// `d`: data with a `u16` length prefix.
    pub fn data(&mut self, data: &[u8]) -> Result<()> {
        let len = u16::try_from(data.len()).map_err(|_| Error::NoBufs)?;
        self.u16(len)?;
        self.bytes(data)
    }

    /// `t(...)`: runs `f` and prefixes what it wrote with its `u16` length.
    pub fn structure(&mut self, f: impl FnOnce(&mut Self) -> Result<()>) -> Result<()> {
        let mark = self.len;
        self.u16(0)?;
        let r = f(self);
        if r.is_err() {
            self.len = mark;
            return r;
        }
        let n = u16::try_from(self.len - mark - 2).map_err(|_| {
            self.len = mark;
            Error::NoBufs
        })?;
        self.buf[mark..mark + 2].copy_from_slice(&n.to_le_bytes());
        Ok(())
    }
}

/// Reads Spinel values from a byte slice.
#[derive(Debug, Copy, Clone)]
pub struct Reader<'a> {
    data: &'a [u8],
}

impl<'a> Reader<'a> {
    /// A reader over `data`.
    pub const fn new(data: &'a [u8]) -> Self {
        Self { data }
    }

    /// Bytes left.
    pub const fn remaining(&self) -> usize {
        self.data.len()
    }

    /// Whether everything was read.
    pub const fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// `D`: all bytes left.
    pub fn rest(&mut self) -> &'a [u8] {
        core::mem::take(&mut self.data)
    }

    /// The next `n` bytes.
    pub fn bytes(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.data.len() < n {
            return Err(Error::Parse);
        }
        let (head, tail) = self.data.split_at(n);
        self.data = tail;
        Ok(head)
    }

    /// A fixed-size array (`E`, `6`, ...).
    pub fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        let mut out = [0u8; N];
        out.copy_from_slice(self.bytes(N)?);
        Ok(out)
    }

    /// `C`
    pub fn u8(&mut self) -> Result<u8> {
        Ok(self.bytes(1)?[0])
    }

    /// `c`
    pub fn i8(&mut self) -> Result<i8> {
        Ok(self.u8()? as i8)
    }

    /// `b`
    pub fn bool(&mut self) -> Result<bool> {
        Ok(self.u8()? != 0)
    }

    /// `S`
    pub fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_le_bytes(self.array()?))
    }

    /// `s`
    pub fn i16(&mut self) -> Result<i16> {
        Ok(i16::from_le_bytes(self.array()?))
    }

    /// `L`
    pub fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.array()?))
    }

    /// `l`
    pub fn i32(&mut self) -> Result<i32> {
        Ok(i32::from_le_bytes(self.array()?))
    }

    /// `X`
    pub fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(self.array()?))
    }

    /// `x`
    pub fn i64(&mut self) -> Result<i64> {
        Ok(i64::from_le_bytes(self.array()?))
    }

    /// `i`: packed unsigned integer.
    pub fn packed(&mut self) -> Result<u32> {
        let mut v: u32 = 0;
        for shift in (0..35).step_by(7) {
            let b = self.u8()?;
            let part = u32::from(b & 0x7f);
            if shift == 28 && part > 0xf {
                return Err(Error::Parse);
            }
            v |= part << shift;
            if b & 0x80 == 0 {
                return Ok(v);
            }
        }
        Err(Error::Parse)
    }

    /// `U`: NUL terminated string.
    pub fn utf8(&mut self) -> Result<&'a str> {
        let nul = self.data.iter().position(|&b| b == 0).ok_or(Error::Parse)?;
        let s = core::str::from_utf8(&self.data[..nul]).map_err(|_| Error::Parse)?;
        self.data = &self.data[nul + 1..];
        Ok(s)
    }

    /// `d`: data with a `u16` length prefix.
    pub fn data(&mut self) -> Result<&'a [u8]> {
        let n = usize::from(self.u16()?);
        self.bytes(n)
    }

    /// `t(...)`: a reader over the body of the next struct.
    pub fn structure(&mut self) -> Result<Reader<'a>> {
        Ok(Reader::new(self.data()?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packed_uint_vectors() {
        // Values from the Spinel specification and OpenThread's
        // `spinel_packed_uint_*` usage (property IDs above 127 take two bytes).
        for (v, enc) in [
            (0u32, &[0x00u8][..]),
            (1, &[0x01]),
            (127, &[0x7f]),
            (128, &[0x80, 0x01]),
            (0x1200, &[0x80, 0x24]),
            (0x1301, &[0x81, 0x26]),
            (0x800, &[0x80, 0x10]),
            (2_097_151, &[0xff, 0xff, 0x7f]),
            (u32::MAX, &[0xff, 0xff, 0xff, 0xff, 0x0f]),
        ] {
            let mut buf = [0u8; 8];
            let mut w = Writer::new(&mut buf);
            w.packed(v).unwrap();
            assert_eq!(w.as_slice(), enc, "{v}");
            assert_eq!(Reader::new(enc).packed().unwrap(), v);
        }
        assert!(Reader::new(&[0x80]).packed().is_err());
        assert!(
            Reader::new(&[0xff, 0xff, 0xff, 0xff, 0x1f])
                .packed()
                .is_err()
        );
        assert!(
            Reader::new(&[0x80, 0x80, 0x80, 0x80, 0x80, 0x01])
                .packed()
                .is_err()
        );
    }

    #[test]
    fn mixed_roundtrip() {
        // Same shape as OpenThread's test_spinel_encoder "TestSpinelEncoder":
        // bool, u8, u16, u32, u64, packed, eui64, ipv6, utf8, data, struct.
        let mut buf = [0u8; 128];
        let mut w = Writer::new(&mut buf);
        w.bool(true).unwrap();
        w.u8(0x12).unwrap();
        w.i8(-2).unwrap();
        w.u16(0x1234).unwrap();
        w.u32(0xdead_beef).unwrap();
        w.u64(0x0102_0304_0506_0708).unwrap();
        w.packed(300).unwrap();
        w.array(&[1, 2, 3, 4, 5, 6, 7, 8]).unwrap();
        w.utf8("OpenThread").unwrap();
        w.data(&[9, 8, 7]).unwrap();
        w.structure(|w| {
            w.u8(0xaa)?;
            w.u16(0xbbcc)
        })
        .unwrap();
        w.bytes(&[0xee, 0xff]).unwrap();
        let out = w.as_slice();
        assert_eq!(&out[..8], &[1, 0x12, 0xfe, 0x34, 0x12, 0xef, 0xbe, 0xad]);
        let mut r = Reader::new(out);
        assert!(r.bool().unwrap());
        assert_eq!(r.u8().unwrap(), 0x12);
        assert_eq!(r.i8().unwrap(), -2);
        assert_eq!(r.u16().unwrap(), 0x1234);
        assert_eq!(r.u32().unwrap(), 0xdead_beef);
        assert_eq!(r.u64().unwrap(), 0x0102_0304_0506_0708);
        assert_eq!(r.packed().unwrap(), 300);
        assert_eq!(r.array::<8>().unwrap(), [1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(r.utf8().unwrap(), "OpenThread");
        assert_eq!(r.data().unwrap(), &[9, 8, 7]);
        let mut s = r.structure().unwrap();
        assert_eq!(s.remaining(), 3);
        assert_eq!(s.u8().unwrap(), 0xaa);
        assert_eq!(s.u16().unwrap(), 0xbbcc);
        assert!(s.is_empty());
        assert_eq!(r.rest(), &[0xee, 0xff]);
        assert!(r.is_empty());
        assert_eq!(r.u8(), Err(Error::Parse));
    }

    #[test]
    fn overflow_and_truncated() {
        let mut buf = [0u8; 3];
        let mut w = Writer::new(&mut buf);
        assert_eq!(w.u32(1), Err(Error::NoBufs));
        assert!(w.is_empty());
        let mut buf = [0u8; 4];
        let mut w = Writer::new(&mut buf);
        assert_eq!(w.structure(|w| w.u32(1)), Err(Error::NoBufs));
        assert!(w.is_empty());
        // Length prefix beyond the buffer.
        assert_eq!(Reader::new(&[5, 0, 1]).data(), Err(Error::Parse));
        // Unterminated string.
        assert_eq!(Reader::new(b"abc").utf8(), Err(Error::Parse));
    }
}
