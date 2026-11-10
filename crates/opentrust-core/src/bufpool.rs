//! Handle-based pool of small fixed-size buffers, chained per message.
//!
//! This is the storage model of OpenThread's `MessagePool`
//! (`OPENTHREAD_CONFIG_NUM_MESSAGE_BUFFERS` buffers of
//! `OPENTHREAD_CONFIG_MESSAGE_BUFFER_SIZE` bytes, a message is a chain of
//! buffers, allocation fails with `NoBufs`). Unlike
//! [`crate::message::MessagePool`], whose messages borrow the pool, a
//! [`Chain`] is a plain `Copy` handle, so queues of chains can live in the
//! same struct as the pool they draw from. The owner must give every chain
//! back with [`BufPool::free`] (a dropped chain leaks its buffers).

use crate::error::{Error, Result};

const NIL: u8 = u8::MAX;

/// A message stored in a [`BufPool`]: the first buffer and the byte length.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Chain {
    head: u8,
    len: u16,
}

impl Chain {
    /// Length of the stored data in bytes.
    pub const fn len(&self) -> usize {
        self.len as usize
    }

    /// Whether the chain holds no data.
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }
}

/// `N` buffers of `SIZE` bytes (`N` below 255).
#[derive(Debug)]
pub struct BufPool<const N: usize, const SIZE: usize> {
    data: [[u8; SIZE]; N],
    next: [u8; N],
    free_head: u8,
    free_count: u8,
}

impl<const N: usize, const SIZE: usize> Default for BufPool<N, SIZE> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize, const SIZE: usize> BufPool<N, SIZE> {
    /// An empty pool with every buffer free.
    pub fn new() -> Self {
        const { assert!(N < NIL as usize && SIZE > 0) };
        let mut next = [NIL; N];
        let mut i = 0;
        while i + 1 < N {
            next[i] = (i + 1) as u8;
            i += 1;
        }
        Self {
            data: [[0; SIZE]; N],
            next,
            free_head: if N == 0 { NIL } else { 0 },
            free_count: N as u8,
        }
    }

    /// Number of free buffers.
    pub fn free_count(&self) -> usize {
        usize::from(self.free_count)
    }

    /// Copy `data` into a new chain; `NoBufs` (nothing allocated) when there
    /// are not enough free buffers or `data` exceeds 65535 bytes.
    pub fn alloc(&mut self, data: &[u8]) -> Result<Chain> {
        let need = data.len().div_ceil(SIZE);
        if need > self.free_count() || data.len() > usize::from(u16::MAX) {
            return Err(Error::NoBufs);
        }
        let mut head = NIL;
        let mut tail = NIL;
        for part in data.chunks(SIZE) {
            let b = self.free_head;
            self.free_head = self.next[usize::from(b)];
            self.free_count -= 1;
            self.data[usize::from(b)][..part.len()].copy_from_slice(part);
            self.next[usize::from(b)] = NIL;
            if tail == NIL {
                head = b;
            } else {
                self.next[usize::from(tail)] = b;
            }
            tail = b;
        }
        Ok(Chain {
            head,
            len: data.len() as u16,
        })
    }

    /// Copy the chain into `out`; returns the bytes copied (`out.len()`
    /// limits it).
    pub fn read(&self, chain: &Chain, out: &mut [u8]) -> usize {
        let total = chain.len().min(out.len());
        let mut done = 0;
        let mut b = chain.head;
        while done < total && b != NIL {
            let n = (total - done).min(SIZE);
            out[done..done + n].copy_from_slice(&self.data[usize::from(b)][..n]);
            done += n;
            b = self.next[usize::from(b)];
        }
        done
    }

    /// Return the buffers of `chain` to the pool.
    pub fn free(&mut self, chain: Chain) {
        let mut b = chain.head;
        while b != NIL {
            let nxt = self.next[usize::from(b)];
            self.next[usize::from(b)] = self.free_head;
            self.free_head = b;
            self.free_count += 1;
            b = nxt;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alloc_read_free_roundtrip() {
        let mut p = BufPool::<4, 8>::new();
        let data: [u8; 20] = core::array::from_fn(|i| i as u8);
        let c = p.alloc(&data).unwrap();
        assert_eq!(p.free_count(), 1);
        let mut out = [0u8; 32];
        assert_eq!(p.read(&c, &mut out), 20);
        assert_eq!(&out[..20], &data);
        p.free(c);
        assert_eq!(p.free_count(), 4);
    }

    #[test]
    fn exhaustion_is_no_bufs_and_leaves_pool_intact() {
        let mut p = BufPool::<2, 8>::new();
        assert_eq!(p.alloc(&[0; 17]), Err(Error::NoBufs));
        assert_eq!(p.free_count(), 2);
        let a = p.alloc(&[1; 16]).unwrap();
        assert_eq!(p.alloc(&[1]), Err(Error::NoBufs));
        p.free(a);
        let e = p.alloc(&[]).unwrap();
        assert!(e.is_empty());
        assert_eq!(p.free_count(), 2);
    }
}
