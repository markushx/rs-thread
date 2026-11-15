//! `opentrust-cli-vt`: a drop-in for OpenThread's `ot-cli-ftd` of the
//! simulation platform (virtual time).
//!
//! ```text
//! opentrust-cli-vt <node id>
//! ```
//!
//! The OpenTrust node speaks the simulation protocol of OpenThread's
//! `thread-cert` simulator (see `opentrust_sim::vt`), so it can share one
//! virtual network with `ot-cli-ftd` processes. Commands come in on stdin,
//! the CLI answers on stdout with the OpenThread prompt `> ` and CR LF line
//! ends (the terminal is not in raw mode, so this program echoes the input
//! like the OpenThread UART CLI). `PORT_BASE` and `PORT_OFFSET` select the
//! simulator. The settings of the node are kept in
//! `tmp/<PORT_OFFSET>_<node id>.flash` (`OT_SETTINGS_PATH` selects another
//! directory) and survive a restart of the process; `reset` re-creates the
//! node in the same process with its settings.

use std::fmt::Write as _;
use std::io::{Read, Write};
use std::sync::mpsc;

use opentrust_cli::Cli;
use opentrust_sim::vt::{
    EV_ALARM, EV_RADIO, FileSettings, VtEvent, VtInstance, VtLink, VtRadio, instant, new_instance,
};

const LINE_MAX: usize = 384;

enum In {
    Sim(VtEvent),
    Input(Vec<u8>),
    Eof,
}

struct Line {
    buf: Vec<u8>,
    esc: u8,
    after_cr: bool,
}

struct Node {
    id: u16,
    seed: u64,
    radio: VtRadio,
    inst: Box<VtInstance>,
    cli: Cli,
    now_us: u64,
    out: String,
    line: Line,
}

fn settings_dir() -> String {
    std::env::var("OT_SETTINGS_PATH").unwrap_or_else(|_| "tmp".into())
}

impl Node {
    fn flush(&mut self) {
        if self.out.is_empty() {
            return;
        }
        let mut so = std::io::stdout().lock();
        let _ = so.write_all(self.out.as_bytes());
        let _ = so.flush();
        self.out.clear();
    }

    /// Run the node at the current time until it has nothing left to do.
    fn settle(&mut self) {
        for _ in 0..10_000 {
            let t = instant(self.now_us);
            self.radio.on_timer(&mut self.inst, self.now_us);
            self.inst.poll(t);
            let mut did = false;
            while let Some(a) = self.inst.poll_radio_action(t) {
                did = true;
                self.radio.exec(&mut self.inst, self.now_us, a);
            }
            while let Some(e) = self.inst.poll_event() {
                did = true;
                self.cli.handle_event(&mut self.inst, t, &e, &mut self.out);
            }
            self.cli.poll(&mut self.inst, t, &mut self.out);
            if !did {
                break;
            }
        }
        self.flush();
        if self.cli.take_reset_request() {
            self.reset();
        }
    }

    /// `reset`: a new node with the settings of the old one.
    fn reset(&mut self) {
        let placeholder = new_instance(self.id, FileSettings::memory(), 1);
        let old = std::mem::replace(&mut self.inst, placeholder);
        let settings = old.into_settings();
        self.seed = self.seed.wrapping_add(self.now_us | 1);
        self.inst = new_instance(self.id, settings, self.seed);
        self.cli = Cli::new();
        // A fresh radio on the same socket.
        let link = self.radio.link().try_clone().expect("socket");
        self.radio = VtRadio::new(link);
        self.settle();
    }

    /// Report the next alarm to the simulator.
    fn sleep(&mut self) {
        let t = instant(self.now_us);
        let next = [
            self.inst.next_deadline(),
            self.cli.next_deadline(),
            self.radio.next_deadline().map(instant),
        ]
        .into_iter()
        .flatten()
        .min();
        let delay = match next {
            // A deadline in the past that the node did not clear: do not spin.
            Some(d) => d.as_micros().saturating_sub(t.as_micros()).max(100),
            None => i64::MAX as u64,
        };
        let _ = self.radio.link().send(delay, EV_ALARM, &[]);
    }

    fn sim_event(&mut self, ev: VtEvent) {
        self.now_us += ev.delay;
        if ev.kind == EV_RADIO {
            self.radio
                .on_radio(&mut self.inst, self.now_us, &ev.data, &mut |_| true);
        }
        self.settle();
    }

    /// Process a byte of console input (OpenThread's UART CLI: echo, CR or LF
    /// ends the line, the prompt follows every line).
    fn input(&mut self, bytes: &[u8]) {
        for &c in bytes {
            let was_cr = std::mem::take(&mut self.line.after_cr);
            match self.line.esc {
                1 => {
                    self.line.esc = if c == b'[' || c == b'O' { 2 } else { 0 };
                    continue;
                }
                2 => {
                    if (0x40..=0x7e).contains(&c) {
                        self.line.esc = 0;
                    }
                    continue;
                }
                _ => {}
            }
            match c {
                0x1b => self.line.esc = 1,
                b'\r' | b'\n' => {
                    if c == b'\n' && was_cr {
                        continue;
                    }
                    self.line.after_cr = c == b'\r';
                    self.out.push_str("\r\n");
                    let line =
                        String::from_utf8_lossy(&std::mem::take(&mut self.line.buf)).into_owned();
                    let t = instant(self.now_us);
                    self.cli
                        .process_line(&mut self.inst, t, &line, &mut self.out);
                    self.out.push_str("> ");
                    self.settle();
                }
                0x08 | 0x7f if !self.line.buf.is_empty() => {
                    self.line.buf.pop();
                    self.out.push_str("\x08 \x08");
                }
                0x20..=0x7e if self.line.buf.len() < LINE_MAX - 1 => {
                    self.line.buf.push(c);
                    let _ = self.out.write_char(c as char);
                }
                _ => {}
            }
        }
        self.flush();
    }
}

fn main() {
    let id: u16 = match std::env::args().nth(1).and_then(|a| a.parse().ok()) {
        Some(n) if (1..=33).contains(&n) => n,
        _ => {
            eprintln!("usage: opentrust-cli-vt <node id 1..33>");
            std::process::exit(1);
        }
    };
    let seed = std::env::var("OPENTRUST_SEED")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(1u64);
    let link = VtLink::connect(id).unwrap_or_else(|e| {
        eprintln!("cannot open the simulation socket: {e}");
        std::process::exit(1);
    });
    let (tx, rx) = mpsc::channel::<In>();
    {
        let reader = link.try_clone().expect("socket");
        let tx = tx.clone();
        std::thread::spawn(move || {
            while let Ok(ev) = reader.recv() {
                if tx.send(In::Sim(ev)).is_err() {
                    break;
                }
            }
        });
    }
    std::thread::spawn(move || {
        let mut si = std::io::stdin().lock();
        let mut b = [0u8; 256];
        loop {
            match si.read(&mut b) {
                Ok(0) | Err(_) => {
                    let _ = tx.send(In::Eof);
                    break;
                }
                Ok(n) => {
                    if tx.send(In::Input(b[..n].to_vec())).is_err() {
                        break;
                    }
                }
            }
        }
    });

    let settings = FileSettings::open(FileSettings::node_path(settings_dir(), id));
    let mut node = Node {
        id,
        seed,
        radio: VtRadio::new(link),
        inst: new_instance(id, settings, seed),
        cli: Cli::new(),
        now_us: 0,
        out: String::new(),
        line: Line {
            buf: Vec::new(),
            esc: 0,
            after_cr: false,
        },
    };
    node.settle();
    loop {
        node.sleep();
        match rx.recv() {
            Ok(In::Sim(ev)) => node.sim_event(ev),
            Ok(In::Input(b)) => node.input(&b),
            Ok(In::Eof) | Err(_) => break,
        }
    }
}
