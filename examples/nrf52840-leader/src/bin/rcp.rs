//! OpenThread-compatible radio co-processor (RCP) on the nRF52840 DK.
//!
//! The nRF52840's 802.15.4 radio (`radio-nrf802154`) behind HDLC-lite framed
//! Spinel on UARTE0, the pins of the J-Link VCOM port (TX P0.06, RX P0.08,
//! 460800 8N1, no flow control), served by `rs_thread_ncp::rcp::Rcp`. An
//! OpenThread posix host (`ot-br-posix`, `ot-cli`) uses it as
//!
//! ```text
//! spinel+hdlc+uart:///dev/cu.usbmodem...?uart-baudrate=460800
//! ```
//!
//! Build: `cargo build --release --bin rcp --features rcp`.

#![no_std]
#![no_main]

use defmt::{info, warn};
use defmt_rtt as _;
use embassy_executor::Spawner;
use embassy_nrf::buffered_uarte::{self, BufferedUarte, BufferedUarteRx, BufferedUarteTx};
use embassy_nrf::interrupt::{self, InterruptExt, Priority};
use embassy_nrf::{bind_interrupts, peripherals, uarte};
use nrf52840_leader::Board;
use rs_thread_core::crypto::soft::SoftCrypto;
use rs_thread_ncp::rcp::{Rcp, RcpInfo, Transport};
use panic_probe as _;
use static_cell::StaticCell;

defmt::timestamp!("{=u64:us}", embassy_time::Instant::now().as_micros());

bind_interrupts!(struct Irqs {
    UARTE0 => buffered_uarte::InterruptHandler<peripherals::UARTE0>;
});

static RX_BUF: StaticCell<[u8; 1024]> = StaticCell::new();
static TX_BUF: StaticCell<[u8; 1024]> = StaticCell::new();

/// The Spinel link: the buffered UARTE of the VCOM port.
struct Uart {
    rx: BufferedUarteRx<'static>,
    tx: BufferedUarteTx<'static>,
}

impl Transport for Uart {
    type Error = buffered_uarte::Error;

    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        self.rx.read(buf).await
    }

    async fn write_all(&mut self, data: &[u8]) -> Result<(), Self::Error> {
        let mut sent = 0;
        while sent < data.len() {
            sent += self.tx.write(&data[sent..]).await?;
        }
        Ok(())
    }
}

fn now_us() -> u64 {
    embassy_time::Instant::now().as_micros()
}

/// The EUI-64 of the radio: the 64-bit device ID of the chip.
fn eui64() -> [u8; 8] {
    let ficr = embassy_nrf::pac::FICR;
    let hi = ficr.deviceid(1).read();
    let lo = ficr.deviceid(0).read();
    let mut e = [0u8; 8];
    e[..4].copy_from_slice(&hi.to_be_bytes());
    e[4..].copy_from_slice(&lo.to_be_bytes());
    e
}

#[embassy_executor::main]
async fn main(spawner: Spawner) {
    let Board { radio, uart, .. } = nrf52840_leader::init(&spawner);
    info!("RsThread RCP");

    // Application interrupts must stay below MPSL's priorities.
    interrupt::UARTE0.set_priority(Priority::P3);
    let mut cfg = uarte::Config::default();
    cfg.baudrate = uarte::Baudrate::Baud460800;
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
        RX_BUF.init([0; 1024]),
        TX_BUF.init([0; 1024]),
    );
    let (rx, tx) = u.split();
    let mut io = Uart { rx, tx };

    let info = RcpInfo {
        version: concat!("RSTHREAD/", env!("CARGO_PKG_VERSION"), "; RCP; nrf52840"),
        eui64: eui64(),
        now_us,
    };
    let Ok(mut rcp) = Rcp::new(radio, SoftCrypto, info).await else {
        warn!("radio init failed");
        return;
    };
    // Returns only if the transport fails; the host resets the RCP then.
    let _ = rcp.run(&mut io).await;
    warn!("Spinel transport failed");
}
