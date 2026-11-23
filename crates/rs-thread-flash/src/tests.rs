use core::cell::RefCell;
use std::rc::Rc;
use std::vec::Vec;

use embassy_futures::block_on;
use embedded_storage_async::nor_flash::{
    ErrorType, NorFlash, NorFlashError, NorFlashErrorKind, ReadNorFlash,
};
use rs_thread_core::Error;
use rs_thread_core::settings::SettingsKey;
use rs_thread_platform::SettingsStore;

use crate::{FlashError, FlashWriter, Shared};

const PAGE: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct MockError;

impl NorFlashError for MockError {
    fn kind(&self) -> NorFlashErrorKind {
        NorFlashErrorKind::Other
    }
}

#[derive(Debug)]
struct Inner {
    mem: Vec<u8>,
    budget: Option<usize>,
    used: usize,
    dead: bool,
    erases: usize,
}

/// NOR flash that can lose power: after `budget` units (one per erased page
/// or written word) the current operation is left half done and everything
/// after fails. Clones share the memory, so a test keeps a handle after the
/// writer is gone.
#[derive(Debug, Clone)]
struct Mock(Rc<RefCell<Inner>>);

impl Mock {
    fn new(pages: usize) -> Self {
        Self(Rc::new(RefCell::new(Inner {
            mem: std::vec![0xFF; pages * PAGE],
            budget: None,
            used: 0,
            dead: false,
            erases: 0,
        })))
    }

    fn with_budget(pages: usize, budget: usize) -> Self {
        let m = Self::new(pages);
        m.0.borrow_mut().budget = Some(budget);
        m
    }

    fn revive(&self) {
        let mut i = self.0.borrow_mut();
        i.dead = false;
        i.budget = None;
    }

    fn mem(&self) -> Vec<u8> {
        self.0.borrow().mem.clone()
    }

    fn used(&self) -> usize {
        self.0.borrow().used
    }

    fn erases(&self) -> usize {
        self.0.borrow().erases
    }
}

impl Inner {
    /// Spend one unit; false if the power failed at this unit.
    fn spend(&mut self) -> bool {
        if self.dead {
            return false;
        }
        if self.budget.is_some_and(|b| self.used >= b) {
            self.dead = true;
            return false;
        }
        self.used += 1;
        true
    }
}

impl ErrorType for Mock {
    type Error = MockError;
}

impl ReadNorFlash for Mock {
    const READ_SIZE: usize = 1;
    async fn read(&mut self, offset: u32, bytes: &mut [u8]) -> Result<(), MockError> {
        let i = self.0.borrow();
        if i.dead {
            return Err(MockError);
        }
        let o = offset as usize;
        bytes.copy_from_slice(&i.mem[o..o + bytes.len()]);
        Ok(())
    }
    fn capacity(&self) -> usize {
        self.0.borrow().mem.len()
    }
}

impl NorFlash for Mock {
    const WRITE_SIZE: usize = 4;
    const ERASE_SIZE: usize = PAGE;
    async fn erase(&mut self, from: u32, to: u32) -> Result<(), MockError> {
        assert!((from as usize).is_multiple_of(PAGE) && (to as usize).is_multiple_of(PAGE));
        let mut m = self.0.borrow_mut();
        for p in (from as usize / PAGE)..(to as usize / PAGE) {
            let a = p * PAGE;
            if !m.spend() {
                // Half erased page: first half blank, second half garbage.
                m.mem[a..a + PAGE / 2].fill(0xFF);
                for (n, x) in m.mem[a + PAGE / 2..a + PAGE].iter_mut().enumerate() {
                    *x = (n as u8).wrapping_mul(37) ^ 0x5A;
                }
                return Err(MockError);
            }
            m.mem[a..a + PAGE].fill(0xFF);
            m.erases += 1;
        }
        Ok(())
    }
    async fn write(&mut self, offset: u32, bytes: &[u8]) -> Result<(), MockError> {
        let o = offset as usize;
        assert!(
            o.is_multiple_of(4) && bytes.len().is_multiple_of(4),
            "unaligned write"
        );
        let mut m = self.0.borrow_mut();
        for (w, chunk) in bytes.chunks(4).enumerate() {
            let a = o + w * 4;
            if !m.spend() {
                // The word in flight: only some of the bits got programmed.
                for (j, &c) in chunk.iter().enumerate() {
                    m.mem[a + j] &= c | 0x33;
                }
                return Err(MockError);
            }
            for (j, &c) in chunk.iter().enumerate() {
                // Flash can only clear bits.
                m.mem[a + j] &= c;
            }
        }
        Ok(())
    }
}

type Sh = Shared<512, 8>;
const BUF: usize = 96;
type Wr = FlashWriter<Mock, BUF>;

fn mount(flash: &Mock, shared: &Sh) -> Result<Wr, FlashError<MockError>> {
    block_on(Wr::mount(flash.clone(), 0, 1, shared))
}

type Dump = Vec<(u16, Vec<Vec<u8>>)>;

fn dump(s: &Sh) -> Dump {
    s.with(|i| {
        let mut out = Vec::new();
        let mut last = None;
        while let Some(k) = i.next_key(last) {
            let mut vals = Vec::new();
            let mut n = 0;
            let mut buf = [0u8; 300];
            while let Ok(len) = i.get(k, n, &mut buf) {
                vals.push(buf[..len].to_vec());
                n += 1;
            }
            out.push((k, vals));
            last = Some(k);
        }
        out
    })
}

fn flush(w: &mut Wr, s: &Sh) -> Result<(), FlashError<MockError>> {
    block_on(w.flush(s))
}

/// Mount the same flash again into a fresh image (a reboot).
fn reboot(f: &Mock) -> (Wr, Sh) {
    f.revive();
    let s = Sh::new();
    (mount(f, &s).unwrap(), s)
}

#[derive(Debug, Clone)]
enum Op {
    Set(u16, Vec<u8>),
    Add(u16, Vec<u8>),
    Del(u16, Option<usize>),
    Wipe,
}

fn apply(s: &Sh, op: &Op) {
    s.with(|i| match op {
        Op::Set(k, v) => i.set(*k, v).unwrap(),
        Op::Add(k, v) => i.add(*k, v).unwrap(),
        Op::Del(k, idx) => i.delete(*k, *idx).unwrap(),
        Op::Wipe => i.wipe(),
    });
}

fn v(b: u8, n: usize) -> Vec<u8> {
    std::vec![b; n]
}

#[test]
fn fresh_flash_is_empty_and_round_trips() {
    let f = Mock::new(2);
    let s = Sh::new();
    let mut w = mount(&f, &s).unwrap();
    assert!(dump(&s).is_empty());
    assert!(!s.is_dirty());
    s.with(|i| i.set(3, b"hello").unwrap());
    s.with(|i| i.set(1, &[9; 20]).unwrap());
    assert!(s.is_dirty());
    flush(&mut w, &s).unwrap();
    assert!(!s.is_dirty());
    let (_, s2) = reboot(&f);
    assert_eq!(dump(&s2), dump(&s));
    assert_eq!(dump(&s2).len(), 2);
}

#[test]
fn multi_value_delete_shift_and_wipe() {
    let f = Mock::new(2);
    let s = Sh::new();
    let mut w = mount(&f, &s).unwrap();
    s.with(|i| {
        i.add(5, b"a").unwrap();
        i.add(5, b"bb").unwrap();
        i.add(5, b"ccc").unwrap();
        i.set(1, b"x").unwrap();
    });
    flush(&mut w, &s).unwrap();
    s.with(|i| i.delete(5, Some(1)).unwrap());
    flush(&mut w, &s).unwrap();
    let (mut w, s2) = reboot(&f);
    assert_eq!(
        dump(&s2),
        std::vec![
            (1, std::vec![v(b'x', 1)]),
            (5, std::vec![b"a".to_vec(), b"ccc".to_vec()])
        ]
    );
    s2.with(|i| i.delete(5, None).unwrap());
    flush(&mut w, &s2).unwrap();
    let (mut w, s3) = reboot(&f);
    assert_eq!(dump(&s3), std::vec![(1, std::vec![v(b'x', 1)])]);
    s3.with(|i| i.wipe());
    flush(&mut w, &s3).unwrap();
    // The wipe left no trace of the old values in flash.
    let mem = f.mem();
    assert!(!mem.windows(3).any(|x| x == b"ccc"));
    assert!(!mem.windows(2).any(|x| x == b"bb"));
    let (_, s4) = reboot(&f);
    assert!(dump(&s4).is_empty());
}

#[test]
fn compaction_keeps_state_and_spreads_wear() {
    let f = Mock::new(2);
    let s = Sh::new();
    let mut w = mount(&f, &s).unwrap();
    for n in 0..200u32 {
        let k = (n % 3) as u16 + 1;
        s.with(|i| i.set(k, &[n as u8; 24]).unwrap());
        flush(&mut w, &s).unwrap();
        if n % 17 == 0 {
            let (_, s2) = reboot(&f);
            assert_eq!(dump(&s2), dump(&s), "after {n}");
        }
    }
    // Each 256-byte bank takes about 7 entries between compactions.
    assert!(f.erases() > 10, "erases {}", f.erases());
    assert!(f.erases() <= 2 + 200 / 3);
}

#[test]
fn dirty_overflow_rewrites_everything() {
    let f = Mock::new(2);
    let s = Sh::new();
    let mut w = mount(&f, &s).unwrap();
    for k in 1..=12u16 {
        s.with(|i| i.set(k, &[k as u8; 4]).unwrap());
    }
    flush(&mut w, &s).unwrap();
    s.with(|i| i.delete(7, None).unwrap());
    for k in 1..=12u16 {
        if k != 7 {
            s.with(|i| i.set(k, &[k as u8 + 1; 4]).unwrap());
        }
    }
    flush(&mut w, &s).unwrap();
    let (_, s2) = reboot(&f);
    assert_eq!(dump(&s2), dump(&s));
    assert_eq!(dump(&s2).len(), 11);
}

#[test]
fn too_big_for_a_bank_or_buffer_is_an_error_and_data_stays() {
    let f = Mock::new(2);
    let s = Sh::new();
    let mut w = mount(&f, &s).unwrap();
    s.with(|i| i.set(1, b"keep").unwrap());
    flush(&mut w, &s).unwrap();
    // Larger than the entry buffer.
    s.with(|i| i.set(2, &[1; 200]).unwrap());
    assert_eq!(flush(&mut w, &s), Err(FlashError::NoSpace));
    assert_eq!(s.with(|i| i.get(2, 0, &mut [0u8; 1])), Ok(200));
    s.with(|i| i.delete(2, None).unwrap());
    flush(&mut w, &s).unwrap();
    // Many keys together larger than a bank (256 B).
    for k in 10..20u16 {
        s.with(|i| i.set(k, &[0; 40]).unwrap());
    }
    assert_eq!(flush(&mut w, &s), Err(FlashError::NoSpace));
    // Dropping them recovers; the old key survived all along.
    for k in 10..20u16 {
        s.with(|i| i.delete(k, None).unwrap());
    }
    flush(&mut w, &s).unwrap();
    let (_, s2) = reboot(&f);
    assert_eq!(dump(&s2), std::vec![(1, std::vec![b"keep".to_vec()])]);
}

#[test]
fn settings_store_semantics() {
    let sh = Sh::new();
    let mut st = sh.settings();
    assert_eq!(st.change_count(), 0);
    st.set(SettingsKey::NetworkInfo, &[1, 2, 3, 4]).unwrap();
    assert_eq!(st.change_count(), 1);
    let mut small = [0u8; 2];
    assert_eq!(st.get(SettingsKey::NetworkInfo, 0, &mut small), Ok(4));
    assert_eq!(small, [1, 2]);
    assert_eq!(
        st.get(SettingsKey::NetworkInfo, 1, &mut small),
        Err(Error::NotFound)
    );
    st.add(SettingsKey::ChildInfo, &[7]).unwrap();
    st.add(SettingsKey::ChildInfo, &[8]).unwrap();
    assert_eq!(st.count(SettingsKey::ChildInfo), 2);
    st.delete(SettingsKey::ChildInfo, Some(0)).unwrap();
    let mut b = [0u8; 1];
    st.get(SettingsKey::ChildInfo, 0, &mut b).unwrap();
    assert_eq!(b, [8]);
    let c = st.change_count();
    assert_eq!(
        st.delete(SettingsKey::ParentInfo, None),
        Err(Error::NotFound)
    );
    assert_eq!(st.change_count(), c);
    // NoBufs keeps the old value.
    assert_eq!(
        st.set(SettingsKey::NetworkInfo, &[0; 600]),
        Err(Error::NoBufs)
    );
    st.get(SettingsKey::NetworkInfo, 0, &mut b).unwrap();
    assert_eq!(b, [1]);
    st.wipe();
    assert_eq!(st.count(SettingsKey::NetworkInfo), 0);
    assert!(st.change_count() > c);
}

#[test]
fn corrupt_entry_is_ignored_and_later_writes_work() {
    let f = Mock::new(2);
    let s = Sh::new();
    let mut w = mount(&f, &s).unwrap();
    s.with(|i| i.set(1, b"one").unwrap());
    flush(&mut w, &s).unwrap();
    s.with(|i| i.set(2, b"two").unwrap());
    flush(&mut w, &s).unwrap();
    // Flip a payload bit of the second entry (header 12 bytes, entry 1 is
    // 8 + 2 + 3 = 13 -> 16 bytes).
    f.0.borrow_mut().mem[12 + 16 + 11] &= !0x01;
    let (mut w, s2) = reboot(&f);
    assert_eq!(dump(&s2), std::vec![(1, std::vec![b"one".to_vec()])]);
    s2.with(|i| i.set(3, b"three").unwrap());
    flush(&mut w, &s2).unwrap();
    let (_, s3) = reboot(&f);
    assert_eq!(dump(&s3), dump(&s2));
    assert_eq!(dump(&s3).len(), 2);
}

#[test]
fn bad_region_is_rejected() {
    let s = Sh::new();
    assert!(matches!(
        block_on(Wr::mount(Mock::new(2), 0, 2, &s)),
        Err(FlashError::BadRegion)
    ));
    assert!(matches!(
        block_on(Wr::mount(Mock::new(2), 100, 1, &s)),
        Err(FlashError::BadRegion)
    ));
}

fn script() -> Vec<Op> {
    let mut ops = std::vec![Op::Add(9, v(1, 3))];
    for n in 0..40u8 {
        let k = u16::from(n % 4) + 1;
        ops.push(match n % 7 {
            0 => Op::Add(9, v(n, 10)),
            1 => Op::Del(9, Some(0)),
            5 if n > 30 => Op::Wipe,
            _ => Op::Set(k, v(n, 5 + usize::from(n) % 20)),
        });
    }
    // Drop deletes that do not match a value at that point.
    let t = Sh::new();
    let mut valid = Vec::new();
    for op in ops {
        let ok = match &op {
            Op::Del(k, Some(i)) => t.with(|im| im.get(*k, *i, &mut []).is_ok()),
            _ => true,
        };
        if ok {
            apply(&t, &op);
            valid.push(op);
        }
    }
    valid
}

#[test]
fn power_cut_at_every_step_keeps_a_consistent_state() {
    let ops = script();
    // Cost of the whole script without a cut.
    let total = {
        let f = Mock::new(2);
        let s = Sh::new();
        let mut w = mount(&f, &s).unwrap();
        for op in &ops {
            apply(&s, op);
            flush(&mut w, &s).unwrap();
        }
        f.used()
    };
    assert!(total > 200);

    for budget in 0..=total {
        let f = Mock::with_budget(2, budget);
        let s = Sh::new();
        // `states[n]`: the image after n completed ops.
        let mut states: Vec<Dump> = std::vec![Vec::new()];
        let mut done = 0;
        if let Ok(mut w) = mount(&f, &s) {
            for op in &ops {
                apply(&s, op);
                if flush(&mut w, &s).is_err() {
                    break;
                }
                states.push(dump(&s));
                done += 1;
            }
        }
        let (mut w, s2) = reboot(&f);
        let got = dump(&s2);
        // The state of the last completed op, or of the interrupted one.
        let interrupted = (done < ops.len()).then(|| {
            let t = Sh::new();
            for op in &ops[..=done] {
                apply(&t, op);
            }
            dump(&t)
        });
        assert!(
            got == states[done] || interrupted.as_ref() == Some(&got),
            "budget {budget}: after {done} ops got {got:?}, want {:?} or {interrupted:?}",
            states[done]
        );
        // The store keeps working after the cut.
        s2.with(|i| i.set(77, b"after").unwrap());
        flush(&mut w, &s2).unwrap();
        let (_, s3) = reboot(&f);
        assert_eq!(dump(&s3), dump(&s2), "budget {budget}: write after cut");
    }
}
