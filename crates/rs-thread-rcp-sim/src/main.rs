//! `rs-thread-rcp-sim`: an OpenThread-compatible simulation RCP.
//!
//! Speaks HDLC-lite framed Spinel on stdin/stdout, like OpenThread's
//! `ot-rcp` simulation build, and uses OpenThread's real-time simulation
//! radio protocol (UDP multicast, see [`sim_radio`]). An OpenThread posix
//! host starts it with
//!
//! ```text
//! spinel+hdlc+forkpty:///path/to/rs-thread-rcp-sim?forkpty-arg=<node id>
//! ```
//!
//! Environment: `PORT_BASE` (default 9000) and `PORT_OFFSET` (default 0) of
//! the simulation, `RSTHREAD_RCP_LOG` (a file to log to; nothing is ever
//! written to stdout/stderr besides the Spinel link).

#![allow(clippy::std_instead_of_core)]

mod sim_radio;

use std::future::Future;
use std::io::{Read, Write};
use std::pin::pin;
use std::sync::mpsc::{Receiver, TryRecvError, channel};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use rs_thread_core::crypto::soft::SoftCrypto;
use rs_thread_ncp::rcp::{Rcp, RcpInfo, Transport};
use sim_radio::SimRadio;

/// Stdin through a reader thread (so the single-threaded executor can poll
/// it), stdout directly.
struct Stdio {
    rx: Receiver<Vec<u8>>,
    pending: Vec<u8>,
}

#[derive(Debug)]
struct Closed;

impl Stdio {
    fn new() -> Self {
        let (tx, rx) = channel();
        std::thread::spawn(move || {
            let mut stdin = std::io::stdin().lock();
            let mut buf = [0u8; 256];
            while let Ok(n) = stdin.read(&mut buf) {
                if n == 0 || tx.send(buf[..n].to_vec()).is_err() {
                    break;
                }
            }
        });
        Self {
            rx,
            pending: Vec::new(),
        }
    }
}

impl Transport for Stdio {
    type Error = Closed;

    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, Closed> {
        std::future::poll_fn(|_| {
            if self.pending.is_empty() {
                match self.rx.try_recv() {
                    Ok(v) => self.pending = v,
                    Err(TryRecvError::Empty) => return Poll::Pending,
                    Err(TryRecvError::Disconnected) => return Poll::Ready(Err(Closed)),
                }
            }
            let n = buf.len().min(self.pending.len());
            buf[..n].copy_from_slice(&self.pending[..n]);
            self.pending.drain(..n);
            Poll::Ready(Ok(n))
        })
        .await
    }

    async fn write_all(&mut self, data: &[u8]) -> Result<(), Closed> {
        let mut out = std::io::stdout().lock();
        out.write_all(data)
            .and_then(|()| out.flush())
            .map_err(|_| Closed)
    }
}

/// Polls `f` to completion, sleeping briefly whenever it is idle (all I/O is
/// non-blocking and polled).
fn block_on<F: Future>(f: F) -> F::Output {
    let mut f = pin!(f);
    let mut cx = Context::from_waker(Waker::noop());
    loop {
        if let Poll::Ready(v) = f.as_mut().poll(&mut cx) {
            return v;
        }
        std::thread::sleep(Duration::from_micros(100));
    }
}

fn env_u16(name: &str, default: u16) -> u16 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn now_us() -> u64 {
    use std::sync::OnceLock;
    use std::time::Instant;
    static START: OnceLock<Instant> = OnceLock::new();
    START.get_or_init(Instant::now).elapsed().as_micros() as u64
}

fn main() {
    // The node ID is the last numeric argument (`ot-rcp` takes options such as
    // `--sleep-to-tx`, `-E` and `-L<address>` before it; they are accepted and
    // ignored: the radio always supports energy scans and sleep to TX).
    let node_id: u16 = std::env::args()
        .skip(1)
        .filter_map(|a| a.parse().ok())
        .next_back()
        .unwrap_or(1);
    let radio = match SimRadio::new(
        node_id,
        env_u16("PORT_BASE", 9000),
        env_u16("PORT_OFFSET", 0),
    ) {
        Ok(r) => r,
        Err(e) => {
            if let Some(path) = std::env::var_os("RSTHREAD_RCP_LOG") {
                let _ = std::fs::write(path, format!("radio: {e}\n"));
            }
            std::process::exit(1);
        }
    };
    // The OpenThread simulation's EUI-64: 18b430 + node ID.
    let id = u32::from(node_id).to_be_bytes();
    let info = RcpInfo {
        version: concat!("OPENTRUST/", env!("CARGO_PKG_VERSION"), "; RCP; simulation"),
        eui64: [0x18, 0xb4, 0x30, 0x00, id[0], id[1], id[2], id[3]],
        now_us,
    };
    let mut io = Stdio::new();
    let r = block_on(async {
        let mut rcp = Rcp::new(radio, SoftCrypto, info)
            .await
            .map_err(|_| Closed)?;
        rcp.run(&mut io).await
    });
    std::process::exit(if r.is_ok() { 0 } else { 1 });
}
