//! Argument parsing, error numbering and output helpers shared by the
//! commands. Error numbers and names are those of OpenThread (`otError`).

// Helpers are used by feature-gated command groups.
#![allow(dead_code)]

use core::fmt::{self, Display, Write};
use core::net::Ipv6Addr;

use rs_thread_core::Error;

/// Maximum number of arguments of a command line (OT: 32).
pub const MAX_ARGS: usize = 32;

/// An OpenThread error code (`otError`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct E(pub u8);

#[allow(dead_code)]
impl E {
    pub const FAILED: E = E(1);
    pub const NO_BUFS: E = E(3);
    pub const BUSY: E = E(5);
    pub const PARSE: E = E(6);
    pub const INVALID_ARGS: E = E(7);
    pub const NOT_IMPLEMENTED: E = E(12);
    pub const INVALID_STATE: E = E(13);
    pub const NOT_FOUND: E = E(23);
    pub const ALREADY: E = E(24);
    pub const INVALID_COMMAND: E = E(35);
    /// The command completes later: no `Done`, the async output prints it.
    pub const PENDING: E = E(36);
}

impl From<Error> for E {
    fn from(e: Error) -> Self {
        match e {
            Error::Parse => E(6),
            Error::NoBufs => E(3),
            Error::InvalidArgs => E(7),
            Error::InvalidState => E(13),
            Error::NotFound => E(23),
            Error::Already => E(24),
            Error::Busy => E(5),
            Error::Security => E(8),
            Error::Drop => E(2),
            Error::ResponseTimeout => E(28),
            Error::NotImplemented => E(12),
            Error::Abort => E(11),
            _ => E(1),
        }
    }
}

/// Result of a command.
pub type R = Result<(), E>;

/// The OT name of an error number (`otThreadErrorToString`).
pub fn error_name(code: u8) -> &'static str {
    const NAMES: [&str; 38] = [
        "None",
        "Failed",
        "Drop",
        "NoBufs",
        "NoRoute",
        "Busy",
        "Parse",
        "InvalidArgs",
        "Security",
        "AddressQuery",
        "NoAddress",
        "Abort",
        "NotImplemented",
        "InvalidState",
        "NoAck",
        "ChannelAccessFailure",
        "Detached",
        "FcsErr",
        "NoFrameReceived",
        "UnknownNeighbor",
        "InvalidSourceAddress",
        "AddressFiltered",
        "DestinationAddressFiltered",
        "NotFound",
        "Already",
        "ReservedError25",
        "Ipv6AddressCreationFailure",
        "NotCapable",
        "ResponseTimeout",
        "Duplicated",
        "ReassemblyTimeout",
        "NotTmf",
        "NonLowpanDataFrame",
        "Reserved33",
        "LinkMarginLow",
        "InvalidCommand",
        "Pending",
        "Rejected",
    ];
    NAMES.get(usize::from(code)).copied().unwrap_or("Generic")
}

/// The split arguments of one command line; missing arguments read as `""`.
pub struct Args<'a> {
    v: [&'a str; MAX_ARGS],
    n: usize,
}

impl<'a> Args<'a> {
    /// Split `line` at ASCII whitespace; `None` if there are too many
    /// arguments.
    pub fn parse(line: &'a str) -> Option<Self> {
        let mut a = Args {
            v: [""; MAX_ARGS],
            n: 0,
        };
        // Arguments are separated by whitespace; a backslash escapes the next
        // character (OT CLI). The escapes stay in the argument, see
        // `unescape`.
        let b = line.as_bytes();
        let (mut i, mut start) = (0usize, None);
        while i <= b.len() {
            let sep = i == b.len() || b[i].is_ascii_whitespace();
            match (start, sep) {
                (None, false) => start = Some(i),
                (Some(st), true) => {
                    *a.v.get_mut(a.n)? = &line[st..i];
                    a.n += 1;
                    start = None;
                }
                _ => {}
            }
            if i < b.len() && b[i] == b'\\' {
                i += 1;
            }
            i += 1;
        }
        Some(a)
    }

    /// Argument `i` (`""` if absent).
    pub fn get(&self, i: usize) -> &'a str {
        self.v.get(i).copied().unwrap_or("")
    }

    /// The arguments from index `i`.
    pub fn rest(&self, i: usize) -> &[&'a str] {
        self.v.get(i..self.n).unwrap_or(&[])
    }
}

/// Remove the backslash escapes of a CLI argument (a backslash makes the
/// next character literal).
pub fn unescape<const N: usize>(s: &str) -> Result<heapless::String<N>, E> {
    let mut out = heapless::String::new();
    let mut esc = false;
    for c in s.chars() {
        if c == '\\' && !esc {
            esc = true;
            continue;
        }
        esc = false;
        out.push(c).map_err(|_| E::INVALID_ARGS)?;
    }
    Ok(out)
}

/// Parse a decimal or `0x` hexadecimal unsigned number (OT `ParseAsUint32`).
pub fn parse_u32(s: &str) -> Result<u32, E> {
    parse_u64(s)?.try_into().map_err(|_| E::INVALID_ARGS)
}

/// Parse a decimal or `0x` hexadecimal unsigned number.
pub fn parse_u64(s: &str) -> Result<u64, E> {
    let r = if let Some(h) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(h, 16)
    } else {
        s.parse::<u64>()
    };
    r.map_err(|_| E::INVALID_ARGS)
}

/// Parse an unsigned 16-bit number.
pub fn parse_u16(s: &str) -> Result<u16, E> {
    parse_u32(s)?.try_into().map_err(|_| E::INVALID_ARGS)
}

/// Parse an unsigned 8-bit number.
pub fn parse_u8(s: &str) -> Result<u8, E> {
    parse_u32(s)?.try_into().map_err(|_| E::INVALID_ARGS)
}

fn nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// Parse a hex string (no `0x`) of any even length into `out`; returns the
/// number of bytes (OT `ParseAsHexString`).
pub fn parse_hex(s: &str, out: &mut [u8]) -> Result<usize, E> {
    let b = s.as_bytes();
    if b.len() % 2 != 0 || b.len() / 2 > out.len() {
        return Err(E::INVALID_ARGS);
    }
    for (i, p) in b.chunks(2).enumerate() {
        let (Some(h), Some(l)) = (nibble(p[0]), nibble(p[1])) else {
            return Err(E::INVALID_ARGS);
        };
        out[i] = h << 4 | l;
    }
    Ok(b.len() / 2)
}

/// Like [`parse_hex`], but an odd number of digits is accepted: the first
/// digit is then the low nibble of the first byte (OT `ParseAsHexString`).
pub fn parse_hex_padded(s: &str, out: &mut [u8]) -> Result<usize, E> {
    let mut tmp = [0u8; 2 * 64];
    let b = s.as_bytes();
    if b.len() >= tmp.len() {
        return Err(E::INVALID_ARGS);
    }
    let pad = b.len() % 2;
    tmp[0] = b'0';
    tmp[pad..pad + b.len()].copy_from_slice(b);
    let t = core::str::from_utf8(&tmp[..pad + b.len()]).map_err(|_| E::INVALID_ARGS)?;
    parse_hex(t, out)
}

/// Parse a hex string of exactly `N` bytes.
pub fn parse_hex_exact<const N: usize>(s: &str) -> Result<[u8; N], E> {
    let mut b = [0u8; N];
    if parse_hex(s, &mut b)? != N {
        return Err(E::INVALID_ARGS);
    }
    Ok(b)
}

/// Parse an IPv6 address.
pub fn parse_ip6(s: &str) -> Result<core::net::Ipv6Addr, E> {
    s.parse().map_err(|_| E::INVALID_ARGS)
}

/// Parse an IPv6 prefix `addr/len`.
pub fn parse_prefix(s: &str) -> Result<(core::net::Ipv6Addr, u8), E> {
    let (a, l) = s.split_once('/').ok_or(E::INVALID_ARGS)?;
    let len = parse_u8(l)?;
    if len > 128 {
        return Err(E::INVALID_ARGS);
    }
    Ok((parse_ip6(a)?, len))
}

/// Write `bytes` as lowercase hex without separators.
pub fn hex<W: Write>(out: &mut W, bytes: &[u8]) {
    for b in bytes {
        let _ = write!(out, "{b:02x}");
    }
}

/// Write one output line terminated as OT does (`\r\n`).
macro_rules! ln {
    ($out:expr) => {{ let _ = $out.write_str("\r\n"); }};
    ($out:expr, $($t:tt)*) => {{
        let _ = core::write!($out, $($t)*);
        let _ = $out.write_str("\r\n");
    }};
}
pub(crate) use ln;

/// Write without a line terminator.
#[allow(unused_macros)]
macro_rules! out {
    ($out:expr, $($t:tt)*) => {{ let _ = core::write!($out, $($t)*); }};
}
#[allow(unused_imports)]
pub(crate) use out;

/// A table header with the titles as OT prints them (`OutputTableHeader`),
/// followed by the separator line.
pub fn table_header<W: Write>(out: &mut W, titles: &[&str], widths: &[usize]) {
    for (t, &w) in titles.iter().zip(widths) {
        if t.len() + 2 <= w {
            let _ = write!(out, "| {:<1$}", t, w - 1);
        } else {
            let _ = write!(out, "|{:<1$.1$}", t, w);
        }
    }
    let _ = out.write_str("|\r\n");
    table_separator(out, widths);
}

/// The `+---+---+` line of a table.
pub fn table_separator<W: Write>(out: &mut W, widths: &[usize]) {
    for &w in widths {
        let _ = out.write_char('+');
        for _ in 0..w {
            let _ = out.write_char('-');
        }
    }
    let _ = out.write_str("+\r\n");
}

/// An IPv6 address as OpenThread prints it: eight hex groups without leading
/// zeros and without `::` compression (`fe80:0:0:0:1:2:3:4`).
pub(crate) struct Ip6(pub Ipv6Addr);

impl Display for Ip6 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = self.0.segments();
        write!(
            f,
            "{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}",
            s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]
        )
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use std::string::String;

    use super::*;

    #[test]
    fn error_names_follow_openthread() {
        assert_eq!(error_name(7), "InvalidArgs");
        assert_eq!(error_name(13), "InvalidState");
        assert_eq!(error_name(35), "InvalidCommand");
        assert_eq!(error_name(37), "Rejected");
        assert_eq!(E::from(Error::InvalidState), E(13));
        assert_eq!(E::from(Error::NotFound), E(23));
    }

    #[test]
    fn table_header_matches_ot() {
        let mut s = String::new();
        table_header(&mut s, &["Ch", "RSSI"], &[4, 6]);
        assert_eq!(s, "| Ch | RSSI |\r\n+----+------+\r\n");
        let mut s = String::new();
        table_header(&mut s, &["ID", "R"], &[5, 1]);
        assert_eq!(s, "| ID  |R|\r\n+-----+-+\r\n");
    }

    #[test]
    fn numbers_and_hex() {
        assert_eq!(parse_u32("0x10"), Ok(16));
        assert_eq!(parse_u32("16"), Ok(16));
        assert_eq!(parse_u8("256"), Err(E::INVALID_ARGS));
        assert_eq!(parse_hex_exact::<2>("0aFF"), Ok([0x0a, 0xff]));
        assert_eq!(parse_hex_exact::<2>("0xff"), Err(E::INVALID_ARGS));
        assert_eq!(parse_hex_exact::<2>("0a"), Err(E::INVALID_ARGS));
        assert_eq!(parse_prefix("fd00::/64").map(|p| p.1), Ok(64));
        assert!(Args::parse("a b c").is_some());
    }
}
