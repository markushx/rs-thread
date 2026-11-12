//! An in-memory rs-matter `KvBlobStore` that counts its writes.
use core::cell::{Cell, RefCell};
use std::collections::BTreeMap;

use rs_matter::dm::persist::{KvBlobStore, KvBlobStoreAccess};
use rs_matter::error::Error;

#[derive(Debug, Default)]
struct Inner {
    map: BTreeMap<u16, Vec<u8>>,
}

impl KvBlobStore for Inner {
    fn load<'a>(&mut self, key: u16, buf: &'a mut [u8]) -> Result<Option<&'a [u8]>, Error> {
        Ok(self.map.get(&key).map(|v| {
            buf[..v.len()].copy_from_slice(v);
            &buf[..v.len()]
        }))
    }

    fn store(&mut self, key: u16, data: &[u8], _buf: &mut [u8]) -> Result<(), Error> {
        self.map.insert(key, data.to_vec());
        Ok(())
    }

    fn remove(&mut self, key: u16, _buf: &mut [u8]) -> Result<(), Error> {
        self.map.remove(&key);
        Ok(())
    }
}

/// The store: lives outside the node so it survives a "power cycle".
#[derive(Debug)]
pub struct MemKv {
    inner: RefCell<Inner>,
    scratch: RefCell<Vec<u8>>,
    writes: Cell<u32>,
}

impl MemKv {
    pub fn new() -> Self {
        Self {
            inner: RefCell::default(),
            scratch: RefCell::new(vec![0; 2048]),
            writes: Cell::new(0),
        }
    }

    /// The number of `store` / `remove` calls.
    pub fn writes(&self) -> u32 {
        self.writes.get()
    }

    pub fn blob(&self, key: u16) -> Option<Vec<u8>> {
        self.inner.borrow().map.get(&key).cloned()
    }
}

struct Counting<'a>(&'a mut Inner, &'a Cell<u32>);

impl KvBlobStore for Counting<'_> {
    fn load<'a>(&mut self, key: u16, buf: &'a mut [u8]) -> Result<Option<&'a [u8]>, Error> {
        self.0.load(key, buf)
    }

    fn store(&mut self, key: u16, data: &[u8], buf: &mut [u8]) -> Result<(), Error> {
        self.1.set(self.1.get() + 1);
        self.0.store(key, data, buf)
    }

    fn remove(&mut self, key: u16, buf: &mut [u8]) -> Result<(), Error> {
        self.1.set(self.1.get() + 1);
        self.0.remove(key, buf)
    }
}

impl KvBlobStoreAccess for &MemKv {
    fn access<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&mut dyn KvBlobStore, &mut [u8]) -> R,
    {
        let mut inner = self.inner.borrow_mut();
        let mut scratch = self.scratch.borrow_mut();
        f(&mut Counting(&mut inner, &self.writes), &mut scratch)
    }
}
