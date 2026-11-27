//! rsthread-br-posix: Thread Border Router daemon.
//!
//! Drop-in replacement for `otbr-agent` with the same argument surface.
//! Accepts both OT RCP firmware URLs (`spinel+hdlc+uart://`) and rs-thread
//! RCP URLs (`spinel+uart://`); HDLC-lite framing is handled inside the
//! RadioSpinel layer, so both map to the same transport.
//!
//! Usage (matches otbr-agent):
//!   rsthread-br-posix [-I thread-ifname] [-B backbone-ifname]
//!                     [-d debug-level] [-v] [--auto-attach[=0/1]]
//!                     RADIO_URL \[RADIO_URL_2\]

use std::cell::RefCell;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::rc::Rc;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;
use embassy_sync::blocking_mutex::raw::NoopRawMutex;
use rs_thread_br::{
    dns_proxy::DnsProxy,
    routing::{OmrPrefix, RoutingManager},
    srp_proxy::{SrpProxy, SrpService},
    tun::TunInterface,
};
use rs_thread_core::{crypto::soft::SoftCrypto, time::Instant, types::NetworkKey};
use rs_thread_embassy::{Resources, RsThread};
use rs_thread_instance::{
    Config, Dataset, ExternalRouteConfig, Instance, NetPrefix, RANDOM_EXT_ADDRESS,
    srp_server_types as sst,
};
use rs_thread_ncp::{
    radio_spinel::RadioSpinel, rcp::Transport as RcpTransport, transport::SocketTransport,
};
use rs_thread_platform::{Alarm, Clock, Radio, RamSettings};
use std::os::unix::io::AsFd;
use tokio::sync::mpsc;

#[cfg(feature = "rest")]
mod rest;

// ── CLI (matches otbr-agent) ──────────────────────────────────────────────────

/// Thread Border Router daemon — rs-thread implementation of ot-br-posix.
///
/// Accepts both OT RCP firmware (`spinel+hdlc+uart://`) and rs-thread RCP
/// (`spinel+uart://`) URLs.  HDLC-lite framing is handled inside the
/// RadioSpinel layer.
#[derive(Debug, Parser)]
#[command(version, name = "rsthread-br-posix")]
struct Args {
    /// Spinel radio URL(s).  Accepts the same schemes as otbr-agent:
    /// `spinel+hdlc+uart:///dev/ttyUSB0?uart-baudrate=115200`,
    /// `spinel+hdlc+uart:///dev/ttyUSB0`, or
    /// `spinel+socket://127.0.0.1:9000`.
    /// The `+hdlc+` variant is equivalent — HDLC framing is built in.
    #[arg(value_name = "RADIO_URL", required = true)]
    radio_urls: Vec<String>,

    /// Thread network interface (TUN device) name.
    /// On macOS the kernel assigns `utunN` names; pass `-I utun9` or similar.
    /// On Linux the default `wpan0` matches otbr-agent.
    #[cfg_attr(
        target_os = "macos",
        arg(
            short = 'I',
            long = "thread-ifname",
            value_name = "IFNAME",
            default_value = "utun9"
        )
    )]
    #[cfg_attr(
        not(target_os = "macos"),
        arg(
            short = 'I',
            long = "thread-ifname",
            value_name = "IFNAME",
            default_value = "wpan0"
        )
    )]
    thread_ifname: String,

    /// Backbone network interface name.  May be specified multiple times;
    /// the first value is used.
    #[arg(short = 'B', long = "backbone-ifname", value_name = "IFNAME")]
    backbone_ifnames: Vec<String>,

    /// Log level, 0 (emergency) – 7 (debug).  Default 5 (notice / info).
    /// Overridden by the `RUST_LOG` environment variable if set.
    #[arg(short = 'd', long = "debug-level", value_name = "LEVEL",
          value_parser = clap::value_parser!(u8).range(0..=7))]
    debug_level: Option<u8>,

    /// Enable verbose (debug) logging; equivalent to `-d 7`.
    #[arg(short = 'v', long = "verbose")]
    verbose: bool,

    /// Enable or disable auto-attach to an existing Thread network on startup.
    /// Pass `--auto-attach` or `--auto-attach=1` to enable (default),
    /// `--auto-attach=0` to disable.
    #[arg(long = "auto-attach", value_name = "0|1",
          num_args = 0..=1, default_missing_value = "1",
          require_equals = false)]
    auto_attach: Option<u8>,

    /// REST API listen address (not yet implemented; accepted for compatibility).
    #[arg(
        long = "rest-listen-address",
        value_name = "ADDR",
        default_value = "::"
    )]
    rest_listen_address: String,

    /// REST API listen port (not yet implemented; accepted for compatibility).
    #[arg(
        long = "rest-listen-port",
        value_name = "PORT",
        default_value_t = 8081u16
    )]
    rest_listen_port: u16,

    // ── rs-thread extensions (not in otbr-agent) ───────────────────────────
    /// UDP address the DNS proxy listens on.
    /// Use port 53 with CAP_NET_BIND_SERVICE or root.
    #[arg(long = "dns-addr", value_name = "ADDR", default_value = "[::1]:5300")]
    dns_addr: String,

    /// Form a new Thread network immediately as leader.  Generates a random
    /// Network Key; use `--channel` to pick the 802.15.4 channel.
    #[arg(long = "become-leader")]
    become_leader: bool,

    /// 802.15.4 channel to use with `--become-leader`.
    #[arg(long = "channel", default_value_t = 15u8)]
    channel: u8,

    /// Active dataset to inject at startup, as a hex-encoded TLV string
    /// (e.g. the output of `dataset convert` in `ot-cli`).  When supplied,
    /// the dataset is set before `--auto-attach` or `--become-leader` runs.
    #[arg(long = "dataset", value_name = "HEX")]
    dataset_hex: Option<String>,
}

impl Args {
    /// Returns the first (primary) radio URL.
    fn radio_url(&self) -> &str {
        &self.radio_urls[0]
    }

    /// Returns the backbone interface name, defaulting to `en0` / `eth0`.
    fn backbone(&self) -> &str {
        self.backbone_ifnames
            .first()
            .map(String::as_str)
            .unwrap_or("en0")
    }

    /// Returns true if auto-attach is enabled (the default).
    fn auto_attach_enabled(&self) -> bool {
        self.auto_attach.map(|v| v != 0).unwrap_or(true)
    }

    /// Applies `-d` / `-v` to the env_logger builder.
    fn apply_log_level(&self, builder: &mut env_logger::Builder) {
        // RUST_LOG takes priority; only apply -d/-v when it isn't set.
        if std::env::var("RUST_LOG").is_ok() {
            return;
        }
        let level = if self.verbose {
            log::LevelFilter::Trace
        } else {
            match self.debug_level.unwrap_or(5) {
                0..=3 => log::LevelFilter::Error,
                4 => log::LevelFilter::Warn,
                5 => log::LevelFilter::Info,
                6 => log::LevelFilter::Debug,
                _ => log::LevelFilter::Trace,
            }
        };
        builder.filter_level(level);
    }
}

// ── OS entropy RNG ───────────────────────────────────────────────────────────

struct OsRng;

impl rand_core::TryRng for OsRng {
    type Error = core::convert::Infallible;

    fn try_next_u32(&mut self) -> Result<u32, core::convert::Infallible> {
        let mut buf = [0u8; 4];
        getrandom::fill(&mut buf).expect("getrandom failed");
        Ok(u32::from_le_bytes(buf))
    }

    fn try_next_u64(&mut self) -> Result<u64, core::convert::Infallible> {
        let mut buf = [0u8; 8];
        getrandom::fill(&mut buf).expect("getrandom failed");
        Ok(u64::from_le_bytes(buf))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), core::convert::Infallible> {
        getrandom::fill(dst).expect("getrandom failed");
        Ok(())
    }
}

impl rand_core::TryCryptoRng for OsRng {}

// ── Tokio clock + alarm ──────────────────────────────────────────────────────

#[derive(Clone, Copy)]
struct TokioClock {
    start_sys: std::time::Instant,
}

impl TokioClock {
    fn new() -> Self {
        Self {
            start_sys: std::time::Instant::now(),
        }
    }
}

impl Clock for TokioClock {
    fn now(&self) -> Instant {
        Instant::from_micros(self.start_sys.elapsed().as_micros() as u64)
    }
}

struct TokioAlarm {
    start_sys: std::time::Instant,
    start_tokio: tokio::time::Instant,
}

impl TokioAlarm {
    fn new() -> Self {
        Self {
            start_sys: std::time::Instant::now(),
            start_tokio: tokio::time::Instant::now(),
        }
    }
}

impl Alarm for TokioAlarm {
    async fn wait_until(&mut self, at: Instant) {
        let elapsed_at = Duration::from_micros(at.as_micros());
        let wall = std::time::Instant::now()
            .checked_sub(self.start_sys.elapsed())
            .unwrap_or(std::time::Instant::now())
            + elapsed_at;
        let now_sys = std::time::Instant::now();
        if wall <= now_sys {
            return;
        }
        let tokio_deadline = self.start_tokio + Duration::from_micros(at.as_micros());
        tokio::time::sleep_until(tokio_deadline).await;
    }
}

// ── Serial transport (AsyncFd) ────────────────────────────────────────────────

/// UART transport backed by `AsyncFd<std::fs::File>` with `O_NONBLOCK`.
///
/// `tokio::fs::File` serialises reads and writes through an internal `Busy`
/// state machine: while a `spawn_blocking(read)` is running, any `write_all`
/// call returns `Pending` and blocks until the read completes.  When the
/// embassy loop's `select3` exits early (timer or kick), the abandoned read
/// task can hold the file busy for several seconds, delaying the next radio
/// transmit command beyond the MLE Parent Request scan window.
///
/// `AsyncFd` with `O_NONBLOCK` avoids this: `readable()` / `writable()` are
/// independent kqueue interests and never block each other.
struct SerialTransport {
    fd: tokio::io::unix::AsyncFd<std::fs::File>,
}

impl SerialTransport {
    #[allow(unsafe_code)]
    fn new(file: std::fs::File) -> std::io::Result<Self> {
        // Safety: `file` owns its fd uniquely; we are on a Tokio runtime.
        let fd = unsafe { tokio::io::unix::AsyncFd::register(file) }
            .map_err(|e| std::io::Error::other(format!("AsyncFd::register: {e}")))?;
        Ok(Self { fd })
    }
}

impl core::fmt::Debug for SerialTransport {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SerialTransport").finish_non_exhaustive()
    }
}

/// Non-blocking `read(2)` on the serial fd; returns `WouldBlock` on `EAGAIN`.
#[allow(unsafe_code)]
fn serial_read_raw(
    afd: &tokio::io::unix::AsyncFd<std::fs::File>,
    buf: &mut [u8],
) -> std::io::Result<usize> {
    use std::os::unix::io::AsRawFd;
    loop {
        let n = unsafe {
            libc::read(
                afd.as_raw_fd(),
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len(),
            )
        };
        if n >= 0 {
            return Ok(n as usize);
        }
        let e = std::io::Error::last_os_error();
        if e.kind() != std::io::ErrorKind::Interrupted {
            return Err(e);
        }
    }
}

/// Non-blocking `write(2)` on the serial fd; returns `WouldBlock` on `EAGAIN`.
#[allow(unsafe_code)]
fn serial_write_raw(
    afd: &tokio::io::unix::AsyncFd<std::fs::File>,
    buf: &[u8],
) -> std::io::Result<usize> {
    use std::os::unix::io::AsRawFd;
    loop {
        let n = unsafe {
            libc::write(
                afd.as_raw_fd(),
                buf.as_ptr() as *const libc::c_void,
                buf.len(),
            )
        };
        if n >= 0 {
            return Ok(n as usize);
        }
        let e = std::io::Error::last_os_error();
        if e.kind() != std::io::ErrorKind::Interrupted {
            return Err(e);
        }
    }
}

impl RcpTransport for SerialTransport {
    type Error = std::io::Error;

    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        loop {
            let mut guard = self.fd.readable().await?;
            match guard.try_io(|afd| serial_read_raw(afd, buf)) {
                Ok(r) => return r,
                Err(_would_block) => continue,
            }
        }
    }

    async fn write_all(&mut self, data: &[u8]) -> Result<(), Self::Error> {
        let mut sent = 0;
        while sent < data.len() {
            let mut guard = self.fd.writable().await?;
            match guard.try_io(|afd| serial_write_raw(afd, &data[sent..])) {
                Ok(Ok(n)) => sent += n,
                Ok(Err(e)) => return Err(e),
                Err(_would_block) => continue,
            }
        }
        Ok(())
    }
}

// ── Transport enum ───────────────────────────────────────────────────────────

#[allow(clippy::large_enum_variant)]
enum RadioTransport {
    Serial(SerialTransport),
    Socket(SocketTransport),
}

impl RcpTransport for RadioTransport {
    type Error = std::io::Error;

    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        match self {
            RadioTransport::Serial(t) => t.read(buf).await,
            RadioTransport::Socket(t) => t.read(buf).await,
        }
    }

    async fn write_all(&mut self, data: &[u8]) -> Result<(), Self::Error> {
        match self {
            RadioTransport::Serial(t) => t.write_all(data).await,
            RadioTransport::Socket(t) => t.write_all(data).await,
        }
    }
}

impl core::fmt::Debug for RadioTransport {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            RadioTransport::Serial(_) => write!(f, "RadioTransport::Serial(...)"),
            RadioTransport::Socket(_) => write!(f, "RadioTransport::Socket(...)"),
        }
    }
}

/// Configures a UART fd for raw binary Spinel: raw mode, 8N1, `baud_rate`.
fn configure_serial(file: &std::fs::File, baud_rate: u32) -> std::io::Result<()> {
    use nix::sys::termios::{
        BaudRate, ControlFlags, FlushArg, SetArg, cfmakeraw, cfsetspeed, tcflush, tcgetattr,
        tcsetattr,
    };
    use std::os::unix::io::AsRawFd;

    let mut tios =
        tcgetattr(file.as_fd()).map_err(|e| std::io::Error::other(format!("tcgetattr: {e}")))?;

    cfmakeraw(&mut tios);
    tios.control_flags &= !(ControlFlags::CSTOPB | ControlFlags::PARENB | ControlFlags::CRTSCTS);
    tios.control_flags |= ControlFlags::CS8 | ControlFlags::CREAD | ControlFlags::CLOCAL;
    tios.control_chars[nix::sys::termios::SpecialCharacterIndices::VMIN as usize] = 1;
    tios.control_chars[nix::sys::termios::SpecialCharacterIndices::VTIME as usize] = 0;

    // nix::BaudRate only covers speeds available on all POSIX targets; for speeds
    // that are platform-specific (e.g. 460800 on macOS) we fall through to cfsetspeed
    // via the libc termios directly after tcsetattr.
    let std_baud = match baud_rate {
        9600 => Some(BaudRate::B9600),
        19200 => Some(BaudRate::B19200),
        38400 => Some(BaudRate::B38400),
        57600 => Some(BaudRate::B57600),
        115200 => Some(BaudRate::B115200),
        230400 => Some(BaudRate::B230400),
        _ => None,
    };

    if let Some(baud) = std_baud {
        cfsetspeed(&mut tios, baud)
            .map_err(|e| std::io::Error::other(format!("cfsetspeed: {e}")))?;
        tcsetattr(file.as_fd(), SetArg::TCSANOW, &tios)
            .map_err(|e| std::io::Error::other(format!("tcsetattr: {e}")))?;
    } else {
        // For non-standard speeds (e.g. 460800 on macOS) use the Apple-specific
        // IOSSIOSPEED ioctl (_IOW('T', 2, speed_t) = 0x8008_5402 on 64-bit macOS).
        // Apply cfmakeraw/flags first, then patch the speed.
        tcsetattr(file.as_fd(), SetArg::TCSANOW, &tios)
            .map_err(|e| std::io::Error::other(format!("tcsetattr(raw): {e}")))?;
        // macOS: use the IOSSIOSPEED ioctl to set arbitrary baud rates.
        // Other platforms can be added as needed.
        #[cfg(target_os = "macos")]
        macos_set_arbitrary_baud(file.as_raw_fd(), baud_rate)?;
        #[cfg(not(target_os = "macos"))]
        return Err(std::io::Error::other(format!(
            "unsupported baud rate {baud_rate} on this platform"
        )));
    }

    tcflush(file.as_fd(), FlushArg::TCIOFLUSH)
        .map_err(|e| std::io::Error::other(format!("tcflush: {e}")))?;

    Ok(())
}

/// Sets an arbitrary baud rate on macOS via the IOSSIOSPEED ioctl.
///
/// macOS's standard POSIX termios only supports the speeds defined in `BaudRate`.
/// For higher speeds (e.g. 460800) the IOKit `IOSSIOSPEED` ioctl must be used;
/// it takes a pointer to a `speed_t` (u64 on 64-bit macOS).
#[cfg(target_os = "macos")]
#[allow(unsafe_code)]
fn macos_set_arbitrary_baud(fd: std::os::unix::io::RawFd, baud: u32) -> std::io::Result<()> {
    // IOSSIOSPEED = _IOW('T', 2, speed_t) = 0x8008_5402 on 64-bit macOS.
    const IOSSIOSPEED: libc::c_ulong = 0x8008_5402;
    let speed: libc::speed_t = baud.into();
    // Safety: `fd` is a valid open file descriptor; `speed` lives for the call.
    let rc = unsafe { libc::ioctl(fd, IOSSIOSPEED, &speed) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Normalises a Spinel radio URL and opens the transport.
///
/// Accepted schemes:
///   - `spinel+hdlc+uart:///dev/ttyUSB0?uart-baudrate=115200`  (OT RCP)
///   - `spinel+hdlc+uart:///dev/ttyUSB0`
///   - `spinel+uart:///dev/ttyUSB0`                            (rs-thread RCP)
///   - `spinel+hdlc+socket://127.0.0.1:9000`
///   - `spinel+socket://127.0.0.1:9000`
///
/// HDLC-lite framing is handled inside RadioSpinel — `+hdlc+` and the plain
/// variants are equivalent at this level.  On macOS `tty.*` paths are
/// automatically opened as `cu.*` to avoid blocking on DCD.
async fn open_transport(url: &str) -> Result<RadioTransport> {
    let normalised = url
        .replace("spinel+hdlc+uart://", "spinel+uart://")
        .replace("spinel+hdlc+socket://", "spinel+socket://");

    // Split off query string; extract uart-baudrate if present.
    let (path_part, query) = match normalised.split_once('?') {
        Some((p, q)) => (p, Some(q)),
        None => (normalised.as_str(), None),
    };
    let baud_rate: u32 = query
        .and_then(|q| {
            q.split('&').find_map(|kv| {
                let (k, v) = kv.split_once('=')?;
                if k == "uart-baudrate" {
                    v.parse().ok()
                } else {
                    None
                }
            })
        })
        .unwrap_or(115200);

    if let Some(raw_path) = path_part.strip_prefix("spinel+uart://") {
        // On macOS, open the callout (cu.*) device to avoid blocking on DCD.
        #[cfg(target_os = "macos")]
        let device_path = if let Some(stem) = raw_path.strip_prefix("/dev/tty.") {
            format!("/dev/cu.{stem}")
        } else {
            raw_path.to_owned()
        };
        #[cfg(not(target_os = "macos"))]
        let device_path = raw_path.to_owned();

        log::info!("opening UART: {device_path} @ {baud_rate} baud");
        // Open with O_NONBLOCK so that AsyncFd can use kqueue for read/write
        // readiness independently.  tokio::fs::File serialises reads and writes
        // through an internal Busy state, causing multi-second stalls when a
        // read future is cancelled mid-flight (e.g. inside embassy's select3).
        use std::os::unix::fs::OpenOptionsExt;
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(&device_path)
            .with_context(|| format!("open {device_path}"))?;
        configure_serial(&file, baud_rate).with_context(|| format!("configure {device_path}"))?;
        log::debug!("serial port configured (raw, 8N1, {} baud)", baud_rate);

        Ok(RadioTransport::Serial(
            SerialTransport::new(file).with_context(|| format!("AsyncFd {device_path}"))?,
        ))
    } else if let Some(addr) = path_part.strip_prefix("spinel+socket://") {
        log::info!("connecting TCP socket: {addr}");
        let stream = SocketTransport::connect(addr)
            .await
            .with_context(|| format!("connect {addr}"))?;
        Ok(RadioTransport::Socket(stream))
    } else {
        anyhow::bail!(
            "unknown radio URL: {url}\n\
             Expected spinel+hdlc+uart://, spinel+uart://, \
             spinel+hdlc+socket://, or spinel+socket://"
        )
    }
}

// ── SRP bridge helpers ────────────────────────────────────────────────────────

/// Strips the SRP server domain from `service_name` and appends `.local.`
/// to produce an mDNS-compatible service type string.
///
/// Example: `_matter._tcp.default.service.arpa.` + domain `default.service.arpa`
///   → `_matter._tcp.local.`
fn build_service_type(service_name: &sst::WireName, domain: &sst::WireName) -> String {
    let domain_len = domain.labels().count();
    let svc_labels: Vec<&[u8]> = service_name.labels().collect();
    let type_len = svc_labels.len().saturating_sub(domain_len);
    let mut s = String::new();
    for (i, label) in svc_labels[..type_len].iter().enumerate() {
        if i > 0 {
            s.push('.');
        }
        s.push_str(&String::from_utf8_lossy(label));
    }
    s.push_str(".local.");
    s
}

/// Parses DNS-wire-format TXT record data into `(key, value)` pairs.
fn parse_srp_txt(raw: &[u8]) -> Vec<(String, Vec<u8>)> {
    let mut result = Vec::new();
    let mut i = 0;
    while i < raw.len() {
        let len = raw[i] as usize;
        i += 1;
        if i + len > raw.len() {
            break;
        }
        let entry = &raw[i..i + len];
        i += len;
        let eq = entry.iter().position(|&b| b == b'=').unwrap_or(entry.len());
        let key = String::from_utf8_lossy(&entry[..eq]).into_owned();
        let val = if eq < entry.len() {
            entry[eq + 1..].to_vec()
        } else {
            Vec::new()
        };
        if !key.is_empty() {
            result.push((key, val));
        }
    }
    result
}

// ── Main ──────────────────────────────────────────────────────────────────────

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let args = Args::parse();

    let mut log_builder =
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"));
    args.apply_log_level(&mut log_builder);
    log_builder.init();

    log::info!("rsthread-br-posix starting");
    log::info!("  radio URL : {}", args.radio_url());
    log::info!("  backbone  : {}", args.backbone());
    log::info!("  ifname    : {}", args.thread_ifname);
    log::info!("  dns addr  : {}", args.dns_addr);
    log::info!("  auto-attach: {}", args.auto_attach_enabled());

    // 1. Open the Spinel transport and initialise the radio.
    let transport = open_transport(args.radio_url()).await?;
    let mut radio = RadioSpinel::new(transport);
    let caps = radio
        .init()
        .await
        .map_err(|e| anyhow::anyhow!("radio init: {e}"))?;
    log::info!("radio initialised: {caps:?}");

    // 2. Create the rs-thread Instance.
    let config = Config::router(RANDOM_EXT_ADDRESS, caps);
    let instance = Instance::new(config, RamSettings::<8192>::new(), SoftCrypto, OsRng);

    // 3. Wrap in embassy Resources and create the RsThread handle.
    let clock = TokioClock::new();
    let resources: &'static _ = Box::leak(Box::new(Resources::<NoopRawMutex, _, _, _, _>::new(
        instance, clock,
    )));
    let rsthread: RsThread<'static, NoopRawMutex, _, _, _, _> = RsThread::new(resources);

    // Derive the border router service name from the last 2 bytes of the EUI-64,
    // matching the "rs-thread BorderRouter #XXXX" scheme (otbr uses "OpenThread BorderRouter #XXXX").
    let ext_addr_bytes = rsthread.with(|inst, _| *inst.ext_address().as_bytes());
    let br_name = format!(
        "rs-thread BorderRouter #{:02X}{:02X}",
        ext_addr_bytes[6], ext_addr_bytes[7]
    );
    log::info!("  name      : {br_name}");

    #[cfg(feature = "rest")]
    if !args.rest_listen_address.is_empty() {
        log::info!(
            "  REST API  : {}:{}",
            args.rest_listen_address,
            args.rest_listen_port
        );
    }

    // 4a. Inject a dataset from the CLI if provided (must happen before thread_start).
    if let Some(ref hex) = args.dataset_hex {
        let tlvs: Vec<u8> = (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16))
            .collect::<Result<_, _>>()
            .context("--dataset: invalid hex")?;
        let ds = Dataset::from_tlvs(&tlvs).context("--dataset: invalid TLVs")?;
        rsthread
            .set_active_dataset(&ds)
            .map_err(|e| anyhow::anyhow!("--dataset set_active_dataset: {e:?}"))?;
        log::info!("dataset injected from --dataset flag");
    }

    // 4b. Optionally form a new Thread network immediately, or auto-attach.
    if args.become_leader {
        // Only generate a fresh dataset when --dataset was not supplied.
        // When --dataset is present the dataset was already injected in 4a;
        // --become-leader then just forms the network on top of it.
        if args.dataset_hex.is_none() {
            let mut key_bytes = [0u8; 16];
            getrandom::fill(&mut key_bytes).expect("getrandom failed");
            let network_key = NetworkKey(key_bytes);

            let mut ds = Dataset::default();
            ds.set_channel(args.channel).context("invalid channel")?;
            ds.set_pan_id(0xface).context("set pan_id")?;
            ds.set_network_key(&network_key)
                .context("set network_key")?;
            rsthread
                .set_active_dataset(&ds)
                .map_err(|e| anyhow::anyhow!("set_active_dataset: {e:?}"))?;
            log::info!(
                "Thread network formed (channel {}, PAN 0xface, random key)",
                args.channel
            );
        }
        rsthread
            .become_leader()
            .map_err(|e| anyhow::anyhow!("become_leader: {e:?}"))?;
        log::info!("Thread Leader started");
    } else if args.auto_attach_enabled() {
        // Try to resume Thread from saved settings; non-fatal if no dataset.
        rsthread
            .thread_start()
            .map_err(|e| log::warn!("thread_start: {e:?} — configure a dataset via REST API"))
            .ok();
    } else {
        log::info!("auto-attach disabled; waiting for dataset to be configured");
    }

    // 5. Enable the SRP server and publish the OMR prefix to Network Data.
    let omr = OmrPrefix::random();
    rsthread.with(|inst, now| {
        inst.srp_server_set_enabled(true, now);
        if let Ok(prefix) = NetPrefix::from_addr(&omr.prefix, omr.prefix_len) {
            let cfg = ExternalRouteConfig {
                prefix,
                preference: 0,
                nat64: false,
                adv_pio: false,
                stable: true,
            };
            if let Err(e) = inst.publish_external_route(cfg, now) {
                log::warn!("publish_external_route: {e:?}");
            }
        }
    });

    // 6. Open the TUN interface.
    let mut tun = TunInterface::open(&args.thread_ifname)
        .await
        .context("open TUN interface")?;
    log::info!("TUN interface opened: {}", tun.name());

    // Assign the border router's OMR address (prefix::1) to the TUN interface.
    // macOS requires the interface to have an IPv6 address before a route can
    // be added to it; this also makes the border router reachable from Thread
    // devices at this address.
    let omr_br_addr = {
        let mut b = omr.prefix.octets();
        b[15] = 1;
        std::net::Ipv6Addr::from(b)
    };
    tun.set_ipv6_addr(omr_br_addr, omr.prefix_len)
        .await
        .context("assign OMR address to TUN")?;
    log::info!("TUN address: {}/{}", omr_br_addr, omr.prefix_len);

    // Now add the OMR prefix route so packets destined for Thread addresses
    // enter the tunnel.
    tun.add_route(omr.prefix, omr.prefix_len)
        .await
        .context("add OMR route to TUN")?;
    log::info!(
        "OMR route {}/{} added to {}",
        omr.prefix,
        omr.prefix_len,
        tun.name()
    );

    // 7. Create and start the SRP advertising proxy.
    let mut srp_proxy = SrpProxy::new();
    const BORDER_AGENT_PORT: u16 = 49191;
    srp_proxy
        .start(&br_name, BORDER_AGENT_PORT)
        .context("SRP proxy start")?;
    log::info!("SRP proxy started (border agent port {BORDER_AGENT_PORT})");
    let srp = Rc::new(RefCell::new(srp_proxy));

    // 8. Create routing manager and DNS proxy.
    let omr_prefix_str = format!("{}/{}", omr.prefix, omr.prefix_len);
    let mut routing = RoutingManager::new(args.backbone());
    routing.set_omr_prefix(omr);

    let dns_addr: SocketAddr = args.dns_addr.parse().context("parse --dns-addr")?;
    let dns_proxy = DnsProxy::new(dns_addr);

    // Channel: Thread→TUN datagrams.
    let (to_tun_tx, mut to_tun_rx) = mpsc::channel::<Vec<u8>>(8);

    // 9. Run everything concurrently until Ctrl-C / SIGTERM.

    // Channels for the REST API: LocalSet tasks write state; axum reads it.
    #[cfg(feature = "rest")]
    let (node_tx, node_rx) = tokio::sync::watch::channel(rest::NodeSnapshot::default());
    #[cfg(feature = "rest")]
    let (cmd_tx, mut cmd_rx) = tokio::sync::mpsc::channel::<rest::BrCommand>(4);

    // Spawn the axum server outside the LocalSet so it can run on the runtime.
    #[cfg(feature = "rest")]
    if !args.rest_listen_address.is_empty() {
        // Bracket IPv6 addresses (e.g. "::" → "[::]:8081").
        let listen: SocketAddr = args
            .rest_listen_address
            .parse::<std::net::IpAddr>()
            .map(|ip| SocketAddr::from((ip, args.rest_listen_port)))
            .or_else(|_| format!("{}:{}", args.rest_listen_address, args.rest_listen_port).parse())
            .context("parse REST listen address")?;
        let app_state = rest::AppState {
            node_rx,
            cmd_tx: cmd_tx.clone(),
        };
        let app = rest::build_router(app_state);
        tokio::spawn(async move {
            match tokio::net::TcpListener::bind(listen).await {
                Ok(listener) => {
                    log::info!("REST API listening on http://{listen}");
                    if let Err(e) = axum::serve(listener, app).await {
                        log::error!("REST API: {e}");
                    }
                }
                Err(e) => log::error!("REST API: bind {listen}: {e}"),
            }
        });
    }

    let local = tokio::task::LocalSet::new();
    local
        .run_until(async move {
            // Thread protocol driver — never returns.
            tokio::task::spawn_local(async move { rsthread.run(radio, TokioAlarm::new()).await });

            // Routing manager: sends periodic RA/RIO on the backbone.
            tokio::task::spawn_local(async move {
                if let Err(e) = routing.run().await {
                    log::error!("RoutingManager: {e}");
                }
            });

            // DNS proxy: forwards Thread unicast DNS queries upstream.
            tokio::task::spawn_local(async move {
                let mut proxy = dns_proxy;
                if let Err(e) = proxy.run().await {
                    log::error!("DnsProxy: {e}");
                }
            });

            // TUN ← Thread: drain Ip6Datagram events into the channel.
            let tx = to_tun_tx;
            tokio::task::spawn_local(async move {
                let mut buf = vec![0u8; rs_thread_br::tun::MAX_PACKET];
                loop {
                    rsthread.wait_changed().await;
                    loop {
                        let n = rsthread.with(|inst, _| inst.take_ip6_datagram(&mut buf));
                        let Some(n) = n else { break };
                        if tx.send(buf[..n].to_vec()).await.is_err() {
                            return;
                        }
                    }
                }
            });

            // SRP bridge: watches Instance SRP server for host/service changes
            // and mirrors them to the mDNS daemon on the backbone.
            let srp2 = Rc::clone(&srp);
            tokio::task::spawn_local(async move {
                // (host_id, instance_label) → update_time
                let mut known_svcs: HashMap<(u16, String), Instant> = HashMap::new();
                // host_id → host_name as "foo.local."
                let mut known_hosts: HashMap<u16, String> = HashMap::new();

                loop {
                    rsthread.wait_changed().await;

                    // Snapshot the SRP server store synchronously.
                    let (active_ids, services) = rsthread.with(|inst, _| {
                        let store = inst.srp_server_store();
                        let active: Vec<u16> = store
                            .hosts()
                            .filter(|h| !h.is_deleted())
                            .map(|h| h.id)
                            .collect();
                        let svcs: Vec<(sst::Host, sst::Service, sst::WireName)> = store
                            .all_services()
                            .filter(|(h, s)| !h.is_deleted() && !s.deleted)
                            .map(|(h, s)| (h.clone(), s.clone(), store.domain().clone()))
                            .collect();
                        (active, svcs)
                    });

                    // Hosts that have disappeared → unregister from mDNS.
                    let to_unregister: Vec<String> = known_hosts
                        .iter()
                        .filter(|(id, _)| !active_ids.contains(id))
                        .map(|(_, name)| name.clone())
                        .collect();
                    known_hosts.retain(|id, _| active_ids.contains(id));
                    known_svcs.retain(|(host_id, _), _| active_ids.contains(host_id));

                    // New or updated services → register on mDNS.
                    let mut to_register = Vec::new();
                    for (host, svc, domain) in &services {
                        let inst_label = String::from_utf8_lossy(svc.instance_label()).into_owned();
                        let key = (host.id, inst_label.clone());

                        if known_svcs.get(&key) == Some(&svc.update_time) {
                            continue;
                        }

                        let host_name = format!("{}.local.", String::from_utf8_lossy(host.label()));
                        let service_type = build_service_type(&svc.service_name, domain);
                        let txt = parse_srp_txt(svc.txt.as_slice());
                        let host_addrs = host.addresses.iter().copied().collect::<Vec<_>>();

                        to_register.push(SrpService {
                            instance_name: inst_label.clone(),
                            service_type,
                            port: svc.port,
                            txt,
                            host_name: host_name.clone(),
                            host_addrs,
                        });

                        known_svcs.insert(key, svc.update_time);
                        known_hosts.insert(host.id, host_name);
                    }

                    // Apply changes to the SRP proxy (sync, no await needed).
                    let mut proxy = srp2.borrow_mut();
                    for host_name in &to_unregister {
                        if let Err(e) = proxy.unregister_host(host_name) {
                            log::warn!("SrpProxy: unregister {host_name}: {e}");
                        }
                    }
                    for svc in to_register {
                        if let Err(e) = proxy.register(svc) {
                            log::warn!("SrpProxy: register failed: {e}");
                        }
                    }
                }
            });

            // TUN I/O: host ↔ Thread datagram bridge.
            tokio::task::spawn_local(async move {
                let mut read_buf = vec![0u8; rs_thread_br::tun::MAX_PACKET];
                loop {
                    tokio::select! {
                        result = tun.read_packet(&mut read_buf) => {
                            match result {
                                Ok(0) => {}
                                Ok(n) => {
                                    rsthread.with(|inst, now| {
                                        inst.handle_ip6_from_host(now, &read_buf[..n]);
                                    });
                                }
                                Err(e) => {
                                    log::warn!("TUN read: {e}");
                                    tokio::time::sleep(Duration::from_millis(100)).await;
                                }
                            }
                        }
                        Some(pkt) = to_tun_rx.recv() => {
                            if let Err(e) = tun.write_packet(&pkt).await {
                                log::warn!("TUN write: {e}");
                            }
                        }
                    }
                }
            });

            // REST API state monitor: publishes a NodeSnapshot on every OT change.
            #[cfg(feature = "rest")]
            {
                let rsthread_st = rsthread;
                let omr_pstr = omr_prefix_str.clone();
                tokio::task::spawn_local(async move {
                    loop {
                        rsthread_st.wait_changed().await;
                        let role = format!("{:?}", rsthread_st.role());
                        let rloc16_val = rsthread_st.rloc16().0;
                        let snap = rsthread_st.with(|inst, now| {
                            let ds = inst.active_dataset(now);
                            rest::NodeSnapshot {
                                role: role.clone(),
                                ext_address: {
                                    let b = *inst.ext_address().as_bytes();
                                    b.iter().map(|x| format!("{x:02x}")).collect()
                                },
                                rloc16: format!("0x{rloc16_val:04x}"),
                                network_name: ds
                                    .as_ref()
                                    .and_then(|d| d.tlvs().network_name().ok())
                                    .map(|n| n.as_str().to_owned())
                                    .unwrap_or_default(),
                                channel: ds
                                    .as_ref()
                                    .and_then(|d| d.tlvs().channel().ok())
                                    .map(|c| c.channel as u8)
                                    .unwrap_or(0),
                                pan_id: ds
                                    .as_ref()
                                    .and_then(|d| d.tlvs().pan_id().ok())
                                    .map(|p| format!("0x{p:04x}"))
                                    .unwrap_or_default(),
                                omr_prefix: omr_pstr.clone(),
                                dataset_tlvs_hex: ds
                                    .map(|d| {
                                        d.as_bytes().iter().map(|b| format!("{b:02x}")).collect()
                                    })
                                    .unwrap_or_default(),
                            }
                        });
                        let _ = node_tx.send(snap);
                    }
                });

                // Command processor: applies dataset updates from the REST API.
                tokio::task::spawn_local(async move {
                    while let Some(cmd) = cmd_rx.recv().await {
                        match cmd {
                            rest::BrCommand::SetDatasetTlv(tlvs) => {
                                match Dataset::from_tlvs(&tlvs) {
                                    Ok(ds) => {
                                        if let Err(e) = rsthread.set_active_dataset(&ds) {
                                            log::warn!("REST SetDataset: {e:?}");
                                        }
                                    }
                                    Err(e) => log::warn!("REST SetDataset: invalid TLVs: {e:?}"),
                                }
                            }
                        }
                    }
                });
            }

            tokio::signal::ctrl_c().await.expect("ctrl-c failed");
            log::info!("shutting down");
            rsthread.thread_stop();
            srp.borrow().shutdown();
        })
        .await;

    std::process::exit(0);
}
