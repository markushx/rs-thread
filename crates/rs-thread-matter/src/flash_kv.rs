//! An rs-matter [`KvBlobStore`] over the flash settings image.
//!
//! [`FlashKv`] reads and writes the RAM [`Shared`] image of `rs-thread-flash`;
//! a [`FlashWriter`](rs_thread_flash::FlashWriter) task persists it. The
//! calls of the trait are synchronous and never wait for flash, so this works
//! with flash drivers that are async only (the MPSL flash driver of the nRF52
//! radio backend). The blobs of one `KvBlobStore` key are one value of the
//! image; the image must be big enough for all blobs together (Matter keeps
//! fabrics, ACLs, networks and counters here, plus the Thread settings blob
//! of [`ThreadPersist`](crate::persist::ThreadPersist)).
//!
//! A power cut loses what was stored after the last completed flush; the
//! flash itself stays consistent (see `rs-thread-flash`).

use rs_thread_core::Error as CoreError;
use rs_thread_flash::Shared;
use rs_matter::dm::persist::KvBlobStore;
use rs_matter::error::{Error, ErrorCode};

use crate::error::map_err;

/// [`KvBlobStore`] over a [`Shared`] flash image of `CAP` bytes tracking up to
/// `KEYS` dirty keys. Copyable handle.
#[derive(Debug)]
pub struct FlashKv<'a, const CAP: usize, const KEYS: usize>(&'a Shared<CAP, KEYS>);

impl<'a, const CAP: usize, const KEYS: usize> FlashKv<'a, CAP, KEYS> {
    /// Wrap the shared image.
    pub const fn new(shared: &'a Shared<CAP, KEYS>) -> Self {
        Self(shared)
    }
}

impl<const CAP: usize, const KEYS: usize> Clone for FlashKv<'_, CAP, KEYS> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<const CAP: usize, const KEYS: usize> Copy for FlashKv<'_, CAP, KEYS> {}

impl<const CAP: usize, const KEYS: usize> KvBlobStore for FlashKv<'_, CAP, KEYS> {
    fn load<'b>(&mut self, key: u16, buf: &'b mut [u8]) -> Result<Option<&'b [u8]>, Error> {
        match self.0.with(|i| i.get(key, 0, buf)) {
            Ok(len) if len <= buf.len() => Ok(Some(&buf[..len])),
            Ok(_) => Err(ErrorCode::ResourceExhausted.into()),
            Err(CoreError::NotFound) => Ok(None),
            Err(e) => Err(map_err(e)),
        }
    }

    fn store(&mut self, key: u16, data: &[u8], _buf: &mut [u8]) -> Result<(), Error> {
        self.0.with(|i| i.set(key, data)).map_err(map_err)
    }

    fn remove(&mut self, key: u16, _buf: &mut [u8]) -> Result<(), Error> {
        match self.0.with(|i| i.delete(key, None)) {
            Ok(()) | Err(CoreError::NotFound) => Ok(()),
            Err(e) => Err(map_err(e)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_store_remove() {
        let shared = Shared::<256, 4>::new();
        let mut kv = FlashKv::new(&shared);
        let mut buf = [0u8; 64];
        assert_eq!(kv.load(7, &mut buf).unwrap(), None);
        kv.store(7, b"hello", &mut []).unwrap();
        assert_eq!(kv.load(7, &mut buf).unwrap(), Some(&b"hello"[..]));
        kv.store(7, b"hi", &mut []).unwrap();
        assert_eq!(kv.load(7, &mut buf).unwrap(), Some(&b"hi"[..]));
        assert!(shared.is_dirty());
        kv.remove(7, &mut []).unwrap();
        kv.remove(7, &mut []).unwrap();
        assert_eq!(kv.load(7, &mut buf).unwrap(), None);
    }

    /// A handler key in the vendor range (the OnOff cluster of the light
    /// keeps its state there) survives alongside the stack's own keys.
    #[test]
    fn vendor_key_round_trip() {
        use rs_matter::persist::VENDOR_KEYS_START;

        let shared = Shared::<256, 4>::new();
        let key = VENDOR_KEYS_START + 0x10;
        let mut kv = FlashKv::new(&shared);
        kv.store(3, b"fabrics", &mut []).unwrap();
        kv.store(key, &[1, 2, 3], &mut []).unwrap();
        kv.store(key, &[4, 5, 6, 7], &mut []).unwrap();
        // A second handle over the same image sees the latest value.
        let mut other = FlashKv::new(&shared);
        let mut buf = [0u8; 16];
        assert_eq!(
            other.load(key, &mut buf).unwrap(),
            Some(&[4u8, 5, 6, 7][..])
        );
        assert_eq!(other.load(3, &mut buf).unwrap(), Some(&b"fabrics"[..]));
    }

    #[test]
    fn small_buffer_and_full_image_are_errors() {
        let shared = Shared::<32, 4>::new();
        let mut kv = FlashKv::new(&shared);
        kv.store(1, &[5; 20], &mut []).unwrap();
        let mut small = [0u8; 4];
        assert!(kv.load(1, &mut small).is_err());
        assert!(kv.store(2, &[0; 20], &mut []).is_err());
        // The first blob is intact.
        let mut buf = [0u8; 32];
        assert_eq!(kv.load(1, &mut buf).unwrap(), Some(&[5u8; 20][..]));
    }
}
