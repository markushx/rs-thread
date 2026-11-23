//! Concrete [`Transport`] implementations for the host-side Spinel link.
//!
//! [`UartTransport`] wraps a Tokio serial port opened as an async file (Linux
//! `/dev/ttyUSBx`, macOS `/dev/cu.*`).  [`SocketTransport`] wraps a
//! `TcpStream` for simulation and testing against an RCP exposed over TCP
//! (e.g. `ot-rcp` with `--radio-url spinel+hdlc+uart:///dev/pts/N` and
//! `socat`).

extern crate std;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::rcp::Transport;

// ── UartTransport ─────────────────────────────────────────────────────────────

/// A [`Transport`] backed by a UART / USB-serial port opened as a Tokio file.
///
/// Open the port with `tokio::fs::OpenOptions`:
/// ```ignore
/// let file = tokio::fs::OpenOptions::new()
///     .read(true).write(true).open("/dev/ttyUSB0").await?;
/// let mut driver = RadioSpinel::new(UartTransport::new(file));
/// ```
#[derive(Debug)]
pub struct UartTransport {
    file: tokio::fs::File,
}

impl UartTransport {
    /// Wraps an already-opened serial port file.
    pub fn new(file: tokio::fs::File) -> Self {
        Self { file }
    }
}

impl Transport for UartTransport {
    type Error = std::io::Error;

    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        self.file.read(buf).await
    }

    async fn write_all(&mut self, data: &[u8]) -> Result<(), Self::Error> {
        self.file.write_all(data).await
    }
}

// ── SocketTransport ──────────────────────────────────────────────────────────

/// A [`Transport`] backed by a TCP socket.
///
/// Useful for simulation against `ot-rcp --radio-url spinel+hdlc+tcp://…`.
#[derive(Debug)]
pub struct SocketTransport {
    stream: TcpStream,
}

impl SocketTransport {
    /// Wraps a connected `TcpStream`.
    pub fn new(stream: TcpStream) -> Self {
        Self { stream }
    }

    /// Connects to `addr` and returns a ready transport.
    pub async fn connect(addr: impl tokio::net::ToSocketAddrs) -> std::io::Result<Self> {
        Ok(Self::new(TcpStream::connect(addr).await?))
    }
}

impl Transport for SocketTransport {
    type Error = std::io::Error;

    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        self.stream.read(buf).await
    }

    async fn write_all(&mut self, data: &[u8]) -> Result<(), Self::Error> {
        self.stream.write_all(data).await
    }
}
