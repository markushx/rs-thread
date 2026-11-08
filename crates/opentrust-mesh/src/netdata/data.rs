//! Fixed-capacity Network Data buffer.

use heapless::Vec;
use opentrust_core::{Error, Result};

use super::tlv::is_well_formed;
use super::view::NetworkDataView;

/// Network Data of at most `N` bytes (a MLE Data Response carries at most
/// 254 bytes in practice; the leader's own copy can be larger).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct NetworkData<const N: usize> {
    buf: Vec<u8, N>,
}

impl<const N: usize> NetworkData<N> {
    /// Empty Network Data.
    pub const fn new() -> Self {
        Self { buf: Vec::new() }
    }

    /// Copy well-formed Network Data. [`Error::Parse`] if the TLVs are
    /// malformed, [`Error::NoBufs`] if it does not fit.
    pub fn from_slice(data: &[u8]) -> Result<Self> {
        if !is_well_formed(data) {
            return Err(Error::Parse);
        }
        Ok(Self {
            buf: Vec::from_slice(data).map_err(|_| Error::NoBufs)?,
        })
    }

    /// Replace the content (same checks as [`from_slice`](Self::from_slice);
    /// unchanged on error).
    pub fn set(&mut self, data: &[u8]) -> Result<()> {
        *self = Self::from_slice(data)?;
        Ok(())
    }

    /// The TLV bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.buf
    }

    /// Read view with the typed iterators.
    pub fn view(&self) -> NetworkDataView<'_> {
        NetworkDataView(&self.buf)
    }

    /// Length in bytes.
    pub fn len(&self) -> usize {
        self.buf.len()
    }

    /// `true` if there is no data.
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    /// Remove everything.
    pub fn clear(&mut self) {
        self.buf.clear();
    }

    /// Stable subset, see [`NetworkDataView::copy_stable`].
    pub fn copy_stable(&self, out: &mut [u8]) -> Result<usize> {
        self.view().copy_stable(out)
    }

    /// Insert `bytes` at `at`. [`Error::NoBufs`] if it does not fit.
    #[allow(dead_code)]
    pub(crate) fn insert(&mut self, at: usize, bytes: &[u8]) -> Result<()> {
        if self.buf.len() + bytes.len() > N {
            return Err(Error::NoBufs);
        }
        for (i, b) in bytes.iter().enumerate() {
            // Cannot fail: capacity checked above.
            let _ = self.buf.insert(at + i, *b);
        }
        Ok(())
    }

    /// Remove `len` bytes at `at`.
    #[allow(dead_code)]
    pub(crate) fn remove(&mut self, at: usize, len: usize) {
        let n = self.buf.len();
        self.buf.copy_within(at + len..n, at);
        self.buf.truncate(n - len);
    }
}
