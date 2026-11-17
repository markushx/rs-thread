//! OpenThread-compatible CLI of OpenTrust on the nRF52840 DK.
//!
//! The interpreter of `opentrust-cli` runs over UARTE0 on the pins of the
//! J-Link VCOM port (TX P0.06, RX P0.08, 115200 8N1), like `ot-cli-ftd` on
//! `ot-nrf528xx`: prompt `> `, the typed line is echoed, CR or LF ends it,
//! backspace edits it, and asynchronous output (ping replies, scan results,
//! joiner and commissioner events, received UDP datagrams) is printed as it
//! happens.
//!
//! The settings (datasets, network info with the frame counters stored ahead,
//! child and parent info, ...) are persisted in
//! the Thread region of flash (`opentrust-flash`, see `memory.x`) and survive
//! a reset. `reset` restarts the chip; `factoryreset` erases the settings
//! first (the next boot picks a new random extended address unless the network information restores one), as does Button 1 held
//! at boot.
//!
//! Build: `cargo build --release --bin cli --features cli-all`; single
//! command groups are the features `cli-dataset`, `cli-ping`, ... (see
//! `Cargo.toml`).

#![no_std]
#![no_main]

use core::fmt::Write;

use defmt::info;
use defmt_rtt as _;
use embassy_executor::Spawner;
use embassy_futures::select::{Either3, select3};
use embassy_nrf::buffered_uarte::{self, BufferedUarte, BufferedUarteTx};
use embassy_nrf::interrupt::{self, InterruptExt, Priority};
use embassy_nrf::{bind_interrupts, peripherals, uarte};
use embassy_sync::blocking_mutex::raw::NoopRawMutex;
use embassy_time::Timer;
use nrf52840_leader::Board;
use opentrust_cli::Cli;
use opentrust_core::crypto::soft::SoftCrypto;
use opentrust_embassy::{OpenTrust, Resources};
use opentrust_flash::{FlashWriter, Settings, Shared};
use opentrust_instance::Instance;
use opentrust_nrf::{EmbassyAlarm, EmbassyClock, NrfRng};
use opentrust_platform::Radio;
use panic_probe as _;
use static_cell::StaticCell;

defmt::timestamp!("{=u64:us}", embassy_time::Instant::now().as_micros());

bind_interrupts!(struct Irqs {
    UARTE0 => buffered_uarte::InterruptHandler<peripherals::UARTE0>;
});

/// RAM image of the settings (bytes) and the number of distinct keys tracked.
static STORE: Shared<2048, 16> = Shared::new();
type Store = Settings<'static, 2048, 16>;
type Res = Resources<NoopRawMutex, EmbassyClock, Store, SoftCrypto, NrfRng<'static>>;
static RES: StaticCell<Res> = StaticCell::new();
static RX_BUF: StaticCell<[u8; 256]> = StaticCell::new();
static TX_BUF: StaticCell<[u8; 512]> = StaticCell::new();

/// Longest command line (OpenThread: 640).
const LINE_MAX: usize = 640;

/// Output of one call into the interpreter, written to the UART afterwards.
/// Text beyond the capacity is dropped.
struct Sink {
    buf: [u8; 3072],
    len: usize,
}

impl Write for Sink {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        let n = s.len().min(self.buf.len() - self.len);
        self.buf[self.len..self.len + n].copy_from_slice(&s.as_bytes()[..n]);
        self.len += n;
        Ok(())
    }
}

impl Sink {
    async fn flush(&mut self, tx: &mut BufferedUarteTx<'static>) {
        let mut sent = 0;
        while sent < self.len {
            match tx.write(&self.buf[sent..self.len]).await {
                Ok(n) => sent += n,
                Err(_) => break,
            }
        }
        self.len = 0;
    }
}

/// The line editor of OpenThread's UART CLI.
struct Line {
    buf: [u8; LINE_MAX],
    len: usize,
    /// Inside an escape sequence (arrow keys etc. are ignored): 1 after ESC,
    /// 2 after `ESC [`.
    esc: u8,
    /// The last byte was CR (a following LF is part of the same line end).
    after_cr: bool,
}

#[embassy_executor::main]
async fn main(spawner: Spawner) {
    let Board {
        rng,
        mut radio,
        mut flash,
        button1,
        uart,
        ..
    } = nrf52840_leader::init(&spawner);
    nrf52840_leader::flash::check();
    if nrf52840_leader::flash::factory_reset_requested(&button1).await {
        info!("factory reset: erasing the settings");
        nrf52840_leader::flash::erase_all(&mut flash).await.unwrap();
    }
    let mut writer = FlashWriter::<_, 512>::mount(
        flash,
        nrf52840_leader::flash::THREAD_START,
        nrf52840_leader::flash::THREAD_PAGES,
        &STORE,
    )
    .await
    .unwrap();
    info!("settings: {} bytes loaded", STORE.with(|i| i.used()));
    let caps = radio.init().await.unwrap();
    info!("OpenTrust CLI");
    let config = opentrust_instance::Config::router(opentrust_instance::RANDOM_EXT_ADDRESS, caps);
    let res: &'static Res = Resources::init(RES.uninit(), EmbassyClock, |slot| {
        Instance::init(slot, config, STORE.settings(), SoftCrypto, rng);
    });
    let ot = OpenTrust::new(res);

    // Application interrupts must stay below MPSL's priorities.
    interrupt::UARTE0.set_priority(Priority::P3);
    let mut cfg = uarte::Config::default();
    cfg.baudrate = uarte::Baudrate::Baud115200;
    let u = BufferedUarte::new(
        uart.uarte,
        uart.timer,
        uart.ppi_ch0,
        uart.ppi_ch1,
        uart.ppi_group,
        uart.rxd,
        uart.txd,
        Irqs,
        cfg,
        RX_BUF.init([0; 256]),
        TX_BUF.init([0; 512]),
    );
    let (mut rx, mut tx) = u.split();

    let app = async {
        let mut cli = Cli::new();
        let mut line = Line {
            buf: [0; LINE_MAX],
            len: 0,
            esc: 0,
            after_cr: false,
        };
        let mut sink = Sink {
            buf: [0; 3072],
            len: 0,
        };
        let mut rxb = [0u8; 32];
        let _ = sink.write_str("> ");
        sink.flush(&mut tx).await;
        loop {
            let wait_us = ot
                .with(|_, now| {
                    cli.next_deadline()
                        .map(|d| d.as_micros().saturating_sub(now.as_micros()))
                })
                .unwrap_or(100_000)
                .min(100_000);
            match select3(
                rx.read(&mut rxb),
                ot.next_event(),
                Timer::after_micros(wait_us),
            )
            .await
            {
                Either3::First(Ok(n)) => {
                    for &c in &rxb[..n] {
                        feed(&mut line, c, &mut cli, &ot, &mut sink);
                        // Large outputs go out between bytes.
                        if sink.len > 2048 {
                            sink.flush(&mut tx).await;
                        }
                    }
                }
                Either3::First(Err(_)) => {}
                Either3::Second(ev) => {
                    ot.with(|i, now| cli.handle_event(i, now, &ev, &mut sink));
                }
                Either3::Third(()) => {}
            }
            ot.with(|i, now| cli.poll(i, now, &mut sink));
            sink.flush(&mut tx).await;
            // Settings changed (also the frame counter store-ahead): write
            // them to flash. `factoryreset` wiped the image, which the flush
            // turns into an erase of the old bank.
            if STORE.is_dirty()
                && let Err(e) = writer.flush(&STORE).await
            {
                defmt::warn!("flash write failed: {}", e);
            }
            if cli.take_reset_request() {
                let _ = tx.flush().await;
                Timer::after_millis(50).await;
                cortex_m::peripheral::SCB::sys_reset();
            }
        }
    };
    embassy_futures::select::select(ot.run(radio, EmbassyAlarm), app).await;
}

/// Process one received byte.
fn feed(
    l: &mut Line,
    c: u8,
    cli: &mut Cli,
    ot: &OpenTrust<'_, NoopRawMutex, EmbassyClock, Store, SoftCrypto, NrfRng<'static>>,
    o: &mut Sink,
) {
    let was_cr = core::mem::take(&mut l.after_cr);
    match l.esc {
        1 => {
            l.esc = if c == b'[' || c == b'O' { 2 } else { 0 };
            return;
        }
        2 => {
            // Parameters and intermediates continue, a final byte ends it.
            if (0x40..=0x7e).contains(&c) {
                l.esc = 0;
            }
            return;
        }
        _ => {}
    }
    match c {
        0x1b => l.esc = 1,
        b'\r' | b'\n' => {
            if c == b'\n' && was_cr {
                return;
            }
            l.after_cr = c == b'\r';
            let _ = o.write_str("\r\n");
            let n = core::mem::take(&mut l.len);
            if let Ok(text) = core::str::from_utf8(&l.buf[..n]) {
                ot.with(|i, now| cli.process_line(i, now, text, o));
            }
            let _ = o.write_str("> ");
        }
        0x08 | 0x7f if l.len > 0 => {
            l.len -= 1;
            let _ = o.write_str("\x08 \x08");
        }
        0x20..=0x7e if l.len < LINE_MAX - 1 => {
            l.buf[l.len] = c;
            l.len += 1;
            let _ = o.write_char(c as char);
        }
        _ => {}
    }
}
