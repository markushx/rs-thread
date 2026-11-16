//! The `[THCI]` certification lines of OpenThread's reference device build
//! (feature `cert-log`): the commissioning trace of `opentrust-meshcop`
//! printed like OpenThread's `LogCert` through the CLI output, which the
//! `thread-cert` scripts read (`read_cert_messages_in_commissioning_log`).

use core::fmt::Write as _;
use std::format;
use std::io::Write as _;
use std::string::{String, ToString};
use std::vec::Vec;

struct CertLogger;

/// Hex dump of OpenThread's `GenerateNextHexDumpLine`: a title line, rows of
/// 16 bytes in two groups of 8 with their ASCII rendering, a closing line.
fn dump(title: &str, data: &[u8]) -> String {
    const WIDTH: usize = 72;
    let suffix = "[ len=000]".len();
    let txt = title.len().min(WIDTH - suffix) + suffix;
    let left = (WIDTH - txt) / 2;
    let mut s = String::new();
    s.push_str(&"=".repeat(left));
    let _ = write!(s, "[{title} len={:03}]", data.len());
    s.push_str(&"=".repeat(WIDTH - txt - left));
    s.push_str("\r\n");
    for chunk in data.chunks(16) {
        s.push('|');
        for i in 0..16 {
            match chunk.get(i) {
                Some(b) => {
                    let _ = write!(s, " {b:02X}");
                }
                None => s.push_str("   "),
            }
            if i % 8 == 7 {
                s.push_str(" |");
            }
        }
        s.push(' ');
        for i in 0..16 {
            s.push(match chunk.get(i) {
                Some(b) if (0x20..0x7f).contains(b) => char::from(*b),
                Some(_) => '.',
                None => ' ',
            });
        }
        s.push_str(" |\r\n");
    }
    s.push_str(&"-".repeat(WIDTH));
    s.push_str("\r\n");
    s
}

impl log::Log for CertLogger {
    fn enabled(&self, m: &log::Metadata<'_>) -> bool {
        m.target() == opentrust_meshcop::cert_log::TARGET
    }

    fn log(&self, r: &log::Record<'_>) {
        if !self.enabled(r.metadata()) {
            return;
        }
        // "<send|recv> <TYPE> <hex payload>"
        let text = r.args().to_string();
        let mut it = text.split(' ');
        let (Some(dir), Some(ty)) = (it.next(), it.next()) else {
            return;
        };
        let hex = it.next().unwrap_or("");
        let data: Vec<u8> = (0..hex.len() / 2)
            .filter_map(|i| u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).ok())
            .collect();
        let title = format!("[THCI] direction={dir} | type={ty} |");
        let out = if ty.starts_with("JOIN_FIN") {
            dump(&title, &data)
        } else {
            format!("[THCI] direction={dir} | type={ty}\r\n")
        };
        let mut so = std::io::stdout().lock();
        let _ = so.write_all(out.as_bytes());
        let _ = so.flush();
    }

    fn flush(&self) {}
}

/// Route the commissioning trace of the stack to the CLI output.
pub fn init() {
    static LOGGER: CertLogger = CertLogger;
    if log::set_logger(&LOGGER).is_ok() {
        log::set_max_level(log::LevelFilter::Info);
    }
}
