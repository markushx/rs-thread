//! `history netinfo|rx|tx|rxtx [list] [<num>]` (OT `cli_history.cpp`).

use core::fmt::Write;

use rs_thread_core::time::Instant;
use rs_thread_instance::InstanceCrypto;
use rs_thread_instance::history::{MessageEntry, age_ms};
use rs_thread_mle::Role;
use rs_thread_platform::SettingsStore;
use rand_core::{CryptoRng, Rng};

use crate::Ctx;
use crate::util::{Args, E, Ip6, R, ln, out, table_header, table_separator};

const ONE_DAY_MS: u64 = 24 * 60 * 60 * 1000;

/// OT `EntryAgeToString`.
fn age_string(now: Instant, at: Instant, s: &mut impl Write) {
    match age_ms(now, at) {
        None => {
            let _ = write!(
                s,
                "more than {} days",
                rs_thread_instance::history::MAX_AGE_MS / ONE_DAY_MS
            );
        }
        Some(mut a) => {
            let days = a / ONE_DAY_MS;
            if days > 0 {
                let _ = write!(s, "{days} day{} ", if days == 1 { "" } else { "s" });
                a -= days * ONE_DAY_MS;
            }
            let _ = write!(
                s,
                "{:02}:{:02}:{:02}.{:03}",
                a / 3_600_000,
                (a % 3_600_000) / 60_000,
                (a % 60_000) / 1000,
                a % 1000
            );
        }
    }
}

fn age(now: Instant, at: Instant) -> heapless::String<32> {
    let mut s = heapless::String::new();
    age_string(now, at, &mut s);
    s
}

const fn role_str(r: Role) -> &'static str {
    match r {
        Role::Disabled => "disabled",
        Role::Detached => "detached",
        Role::Child => "child",
        Role::Router => "router",
        Role::Leader => "leader",
    }
}

fn proto_str(e: &MessageEntry) -> &'static str {
    match e.proto {
        0 => "HopOpts",
        6 => "TCP",
        17 => "UDP",
        41 => "IP6",
        43 => "Routing",
        44 => "Frag",
        58 => match e.icmp_type {
            1 => "ICMP6(Unreach)",
            2 => "ICMP6(TooBig)",
            128 => "ICMP6(EchoReqst)",
            129 => "ICMP6(EchoReply)",
            133 => "ICMP6(RouterSol)",
            134 => "ICMP6(RouterAdv)",
            _ => "ICMP6(Other)",
        },
        59 => "None",
        60 => "DstOpts",
        _ => "Unknown",
    }
}

const fn priority_str(p: u8) -> &'static str {
    match p {
        0 => "low",
        1 => "norm",
        2 => "high",
        3 => "net",
        _ => "unkn",
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Dir {
    Rx,
    Tx,
    RxTx,
}

impl<S, C, Rn, W> Ctx<'_, S, C, Rn, W>
where
    S: SettingsStore,
    C: InstanceCrypto,
    Rn: Rng + CryptoRng,
    W: Write,
{
    /// `[list] [<num>]` after the sub-command: `(is_list, count)`.
    fn history_args(a: &Args<'_>) -> core::result::Result<(bool, usize), E> {
        let mut k = 2;
        let list = a.get(k) == "list";
        if list {
            k += 1;
        }
        let mut n = 0;
        if let Ok(v) = a.get(k).parse::<u16>() {
            n = usize::from(v);
            k += 1;
        }
        if a.get(k).is_empty() {
            Ok((list, n))
        } else {
            Err(E::INVALID_ARGS)
        }
    }

    pub(crate) fn history(&mut self, a: &Args<'_>) -> R {
        match a.get(1) {
            "netinfo" => self.history_netinfo(a),
            "rx" => self.history_rxtx(a, Dir::Rx),
            "tx" => self.history_rxtx(a, Dir::Tx),
            "rxtx" => self.history_rxtx(a, Dir::RxTx),
            "help" => {
                for c in ["netinfo", "rx", "rxtx", "tx"] {
                    ln!(self.o, "{c}");
                }
                Ok(())
            }
            _ => Err(E::INVALID_COMMAND),
        }
    }

    fn history_netinfo(&mut self, a: &Args<'_>) -> R {
        let (list, n) = Self::history_args(a)?;
        if !list {
            table_header(
                self.o,
                &["Age", "Role", "Mode", "RLOC16", "Partition ID"],
                &[22, 10, 6, 8, 14],
            );
        }
        let now = self.now;
        for (i, e) in self.i.history().net_info().enumerate() {
            if n != 0 && i >= n {
                break;
            }
            let age = age(now, e.at);
            let mut mode = heapless::String::<4>::new();
            for (on, c) in [
                (e.rx_on_when_idle, 'r'),
                (e.full_thread_device, 'd'),
                (e.full_network_data, 'n'),
            ] {
                if on {
                    let _ = mode.push(c);
                }
            }
            if mode.is_empty() {
                let _ = mode.push('-');
            }
            if list {
                ln!(
                    self.o,
                    "{age} -> role:{} mode:{mode} rloc16:0x{:04x} partition-id:{}",
                    role_str(e.role),
                    e.rloc16.0,
                    e.partition_id
                );
            } else {
                ln!(
                    self.o,
                    "| {age:>20} | {:<8} | {mode:<4} | 0x{:04x} | {:>12} |",
                    role_str(e.role),
                    e.rloc16.0,
                    e.partition_id
                );
            }
        }
        Ok(())
    }

    fn history_rxtx(&mut self, a: &Args<'_>, dir: Dir) -> R {
        const WIDTHS: [usize; 10] = [22, 18, 7, 8, 5, 6, 6, 4, 8, 7];
        let (list, n) = Self::history_args(a)?;
        if !list {
            table_header(
                self.o,
                &[
                    "Age", "Type", "Len", "Chksum", "Sec", "Prio", "RSS", "Dir", "Neighb", "Radio",
                ],
                &WIDTHS,
            );
        }
        let now = self.now;
        let mut rx = self.i.history().rx().peekable();
        let mut tx = self.i.history().tx().peekable();
        let mut index = 0;
        while n == 0 || index < n {
            let (e, is_rx) = match dir {
                Dir::Rx => match rx.next() {
                    Some(e) => (e, true),
                    None => break,
                },
                Dir::Tx => match tx.next() {
                    Some(e) => (e, false),
                    None => break,
                },
                Dir::RxTx => {
                    // The newer entry first (the smaller age).
                    let take_rx = match (rx.peek().map(|e| e.at), tx.peek().map(|e| e.at)) {
                        (Some(r), Some(t)) => r >= t,
                        (Some(_), None) => true,
                        (None, Some(_)) => false,
                        (None, None) => break,
                    };
                    let e = if take_rx { rx.next() } else { tx.next() };
                    match e {
                        Some(e) => (e, take_rx),
                        None => break,
                    }
                }
            };
            let age = age(now, e.at);
            if list {
                ln!(self.o, "{age}");
                out!(
                    self.o,
                    "    type:{} len:{} checksum:0x{:04x} sec:{} prio:{} ",
                    proto_str(e),
                    e.payload_len,
                    e.checksum,
                    if e.link_security { "yes" } else { "no" },
                    priority_str(e.priority)
                );
                if is_rx {
                    out!(self.o, "rss:{}", e.rss);
                } else {
                    out!(
                        self.o,
                        "tx-success:{}",
                        if e.tx_success { "yes" } else { "no" }
                    );
                }
                ln!(
                    self.o,
                    " {}:0x{:04x} radio:15.4",
                    if is_rx { "from" } else { "to" },
                    e.neighbor
                );
                ln!(self.o, "    src:[{}]:{}", Ip6(e.src), e.src_port);
                ln!(self.o, "    dst:[{}]:{}", Ip6(e.dst), e.dst_port);
            } else {
                if index != 0 {
                    table_separator(self.o, &WIDTHS);
                }
                out!(
                    self.o,
                    "| {:20} | {:<16.16} | {:5} | 0x{:04x} | {:>3} | {:>4} | ",
                    "",
                    proto_str(e),
                    e.payload_len,
                    e.checksum,
                    if e.link_security { "yes" } else { "no" },
                    priority_str(e.priority)
                );
                if is_rx {
                    out!(self.o, "{:4} | RX ", e.rss);
                } else {
                    out!(self.o, " NA  |");
                    out!(self.o, "{}", if e.tx_success { " TX " } else { "TX-F" });
                }
                match e.neighbor {
                    0xffff => out!(self.o, "| bcast  "),
                    0xfffe => out!(self.o, "| unknwn "),
                    r => out!(self.o, "| 0x{r:04x} "),
                }
                ln!(self.o, "| {:5.5} |", "15.4");
                let mut s = heapless::String::<80>::new();
                let _ = write!(s, "[{}]:{}", Ip6(e.src), e.src_port);
                ln!(self.o, "| {age:>20} | src: {s:<70} |");
                s.clear();
                let _ = write!(s, "[{}]:{}", Ip6(e.dst), e.dst_port);
                ln!(self.o, "| {:20} | dst: {s:<70} |", "");
            }
            index += 1;
        }
        Ok(())
    }
}
