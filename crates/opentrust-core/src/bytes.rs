//! Zero-copy, allocation-free byte reader and writer for protocol codecs.
//!
//! Multi-byte integers are big-endian (network order) unless the method name
//! ends in `_le` (IEEE 802.15.4 fields are little-endian).

use crate::error::{Error, Result};

/// Cursor over an immutable byte slice. Reads past the end return
/// [`Error::Parse`] and leave the cursor unchanged.
#[derive(Debug, Clone)]
pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

macro_rules! read_int {
    ($name:ident, $name_le:ident, $t:ty) => {
        #[doc = concat!("Read a big-endian `", stringify!($t), "`.")]
        pub fn $name(&mut self) -> Result<$t> {
            Ok(<$t>::from_be_bytes(self.read_array()?))
        }
        #[doc = concat!("Read a little-endian `", stringify!($t), "`.")]
        pub fn $name_le(&mut self) -> Result<$t> {
            Ok(<$t>::from_le_bytes(self.read_array()?))
        }
    };
}

impl<'a> Reader<'a> {
    /// Create a reader positioned at the start of `buf`.
    pub const fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    /// Current offset from the start of the buffer.
    pub const fn position(&self) -> usize {
        self.pos
    }

    /// Number of unread bytes.
    pub const fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    /// `true` if all bytes have been read.
    pub const fn is_empty(&self) -> bool {
        self.remaining() == 0
    }

    /// The unread bytes, without consuming them.
    pub fn rest(&self) -> &'a [u8] {
        &self.buf[self.pos..]
    }

    /// Peek at the next byte without consuming it.
    pub fn peek_u8(&self) -> Result<u8> {
        self.buf.get(self.pos).copied().ok_or(Error::Parse)
    }

    /// Consume and return the next `len` bytes.
    pub fn read_slice(&mut self, len: usize) -> Result<&'a [u8]> {
        let end = self.pos.checked_add(len).ok_or(Error::Parse)?;
        let s = self.buf.get(self.pos..end).ok_or(Error::Parse)?;
        self.pos = end;
        Ok(s)
    }

    /// Consume all remaining bytes.
    pub fn read_rest(&mut self) -> &'a [u8] {
        let s = &self.buf[self.pos..];
        self.pos = self.buf.len();
        s
    }

    /// Consume `N` bytes into an array.
    pub fn read_array<const N: usize>(&mut self) -> Result<[u8; N]> {
        let s = self.read_slice(N)?;
        let mut a = [0u8; N];
        a.copy_from_slice(s);
        Ok(a)
    }

    /// Skip `len` bytes.
    pub fn skip(&mut self, len: usize) -> Result<()> {
        self.read_slice(len).map(|_| ())
    }

    /// Split off a sub-reader over the next `len` bytes (e.g. a TLV value)
    /// and advance past them.
    pub fn sub_reader(&mut self, len: usize) -> Result<Reader<'a>> {
        self.read_slice(len).map(Reader::new)
    }

    /// Read one byte.
    pub fn read_u8(&mut self) -> Result<u8> {
        let b = self.peek_u8()?;
        self.pos += 1;
        Ok(b)
    }

    read_int!(read_u16, read_u16_le, u16);
    read_int!(read_u32, read_u32_le, u32);
    read_int!(read_u64, read_u64_le, u64);
}

/// Cursor over a mutable byte slice. Writes that do not fit return
/// [`Error::NoBufs`] and leave the cursor unchanged.
#[derive(Debug)]
pub struct Writer<'a> {
    buf: &'a mut [u8],
    pos: usize,
}

macro_rules! write_int {
    ($name:ident, $name_le:ident, $t:ty) => {
        #[doc = concat!("Write a big-endian `", stringify!($t), "`.")]
        pub fn $name(&mut self, v: $t) -> Result<()> {
            self.write_slice(&v.to_be_bytes())
        }
        #[doc = concat!("Write a little-endian `", stringify!($t), "`.")]
        pub fn $name_le(&mut self, v: $t) -> Result<()> {
            self.write_slice(&v.to_le_bytes())
        }
    };
}

impl<'a> Writer<'a> {
    /// Create a writer positioned at the start of `buf`.
    pub fn new(buf: &'a mut [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    /// Number of bytes written so far.
    pub const fn len(&self) -> usize {
        self.pos
    }

    /// `true` if nothing has been written.
    pub const fn is_empty(&self) -> bool {
        self.pos == 0
    }

    /// Free space left.
    pub const fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    /// The bytes written so far.
    pub fn written(&self) -> &[u8] {
        &self.buf[..self.pos]
    }

    /// Consume the writer, returning the written part of the buffer.
    pub fn into_written(self) -> &'a mut [u8] {
        &mut self.buf[..self.pos]
    }

    /// Write a byte slice.
    pub fn write_slice(&mut self, data: &[u8]) -> Result<()> {
        let end = self.pos.checked_add(data.len()).ok_or(Error::NoBufs)?;
        self.buf
            .get_mut(self.pos..end)
            .ok_or(Error::NoBufs)?
            .copy_from_slice(data);
        self.pos = end;
        Ok(())
    }

    /// Reserve `len` bytes (zero-filled) to be patched later, e.g. a length
    /// field. Returns the offset of the reserved area.
    pub fn reserve(&mut self, len: usize) -> Result<usize> {
        let off = self.pos;
        let end = off.checked_add(len).ok_or(Error::NoBufs)?;
        self.buf.get_mut(off..end).ok_or(Error::NoBufs)?.fill(0);
        self.pos = end;
        Ok(off)
    }

    /// Mutable access to already-written bytes (for patching reserved fields).
    pub fn written_mut(&mut self) -> &mut [u8] {
        &mut self.buf[..self.pos]
    }

    /// Write one byte.
    pub fn write_u8(&mut self, v: u8) -> Result<()> {
        self.write_slice(&[v])
    }

    write_int!(write_u16, write_u16_le, u16);
    write_int!(write_u32, write_u32_le, u32);
    write_int!(write_u64, write_u64_le, u64);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let mut buf = [0u8; 16];
        let mut w = Writer::new(&mut buf);
        w.write_u8(0xab).unwrap();
        w.write_u16(0x1234).unwrap();
        w.write_u16_le(0x1234).unwrap();
        w.write_u32(0xdead_beef).unwrap();
        let off = w.reserve(1).unwrap();
        w.written_mut()[off] = 7;
        assert_eq!(w.len(), 10);
        let n = w.len();

        let mut r = Reader::new(&buf[..n]);
        assert_eq!(r.read_u8(), Ok(0xab));
        assert_eq!(r.read_u16(), Ok(0x1234));
        assert_eq!(r.read_slice(2), Ok(&[0x34, 0x12][..]));
        assert_eq!(r.read_u32(), Ok(0xdead_beef));
        assert_eq!(r.read_u8(), Ok(7));
        assert!(r.is_empty());
        assert_eq!(r.read_u8(), Err(Error::Parse));
    }

    #[test]
    fn errors_leave_cursor_unchanged() {
        let mut r = Reader::new(&[1, 2, 3]);
        assert_eq!(r.read_u32(), Err(Error::Parse));
        assert_eq!(r.position(), 0);
        assert_eq!(r.read_slice(usize::MAX), Err(Error::Parse));
        let mut sub = r.sub_reader(2).unwrap();
        assert_eq!(sub.read_u16(), Ok(0x0102));
        assert_eq!(r.read_rest(), &[3]);

        let mut buf = [0u8; 3];
        let mut w = Writer::new(&mut buf);
        assert_eq!(w.write_u32(1), Err(Error::NoBufs));
        assert_eq!(w.len(), 0);
        w.write_u16_le(0x0102).unwrap();
        assert_eq!(w.written(), &[2, 1]);
    }
}
