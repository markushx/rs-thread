//! `ping` (OT `cli_ping.cpp`): ICMPv6 echo requests with statistics.

use core::fmt::Write;
use core::net::Ipv6Addr;

use opentrust_core::time::{Duration, Instant};
use opentrust_instance::InstanceCrypto;
use opentrust_platform::SettingsStore;
use rand_core::{CryptoRng, Rng};

use crate::Ctx;
use crate::util::{Args, E, R, ln, out, parse_ip6, parse_u8, parse_u16};

/// Largest echo payload (the instance sends from a stack buffer).
const MAX_PAYLOAD: usize = 512;
/// Echo requests whose send time is remembered for the round-trip time.
const SLOTS: usize = 16;
/// OT defaults.
const DEFAULT_SIZE: u16 = 8;
const DEFAULT_COUNT: u16 = 1;
const DEFAULT_INTERVAL_MS: u32 = 1000;
const DEFAULT_TIMEOUT_MS: u32 = 2000;
/// ICMPv6 header length (the printed size includes it).
const ICMP_HEADER: usize = 8;

#[derive(Debug)]
pub(crate) struct Ping {
    dst: Ipv6Addr,
    src: Option<Ipv6Addr>,
    size: u16,
    count: u16,
    interval: Duration,
    timeout: Duration,
    id: u16,
    sent: u16,
    received: u16,
    is_async: bool,
    multicast: bool,
    last_send: Instant,
    sent_at: [Instant; SLOTS],
    min_rtt: u32,
    max_rtt: u32,
    total_rtt: u32,
}

impl Ping {
    pub(crate) fn deadline(&self) -> Instant {
        if self.sent < self.count {
            self.last_send.saturating_add(self.interval)
        } else {
            self.last_send.saturating_add(self.timeout)
        }
    }
}

/// OT `ParsePingInterval`: seconds with up to three decimals, in ms.
fn parse_interval(s: &str) -> Result<u32, E> {
    let mut ms = 0u32;
    let mut factor = 1000u32;
    let mut dot = false;
    for c in s.chars() {
        match c {
            '0'..='9' => {
                let d = c as u32 - '0' as u32;
                if dot {
                    ms = ms.checked_add(d * factor).ok_or(E::INVALID_ARGS)?;
                    factor /= 10;
                } else {
                    ms = ms
                        .checked_mul(10)
                        .and_then(|v| v.checked_add(d * 1000))
                        .ok_or(E::INVALID_ARGS)?;
                }
            }
            '.' if !dot => {
                dot = true;
                factor = 100;
            }
            _ => return Err(E::INVALID_ARGS),
        }
    }
    Ok(ms)
}

impl<S, C, Rn, W> Ctx<'_, S, C, Rn, W>
where
    S: SettingsStore,
    C: InstanceCrypto,
    Rn: Rng + CryptoRng,
    W: Write,
{
    pub(crate) fn ping_cmd(&mut self, a: &Args<'_>) -> R {
        if a.get(1) == "stop" {
            self.st.ping = None;
            return Ok(());
        }
        let mut k = 1;
        let mut is_async = false;
        let mut src = None;
        if a.get(k) == "async" {
            is_async = true;
            k += 1;
        }
        if a.get(k) == "-I" {
            src = Some(parse_ip6(a.get(k + 1))?);
            k += 2;
        }
        let mut multicast_loop = false;
        if a.get(k) == "-m" {
            multicast_loop = true;
            k += 1;
        }
        let _ = multicast_loop;
        let dst = parse_ip6(a.get(k))?;
        let size = if a.get(k + 1).is_empty() {
            DEFAULT_SIZE
        } else {
            parse_u16(a.get(k + 1))?
        };
        let count = if a.get(k + 2).is_empty() {
            DEFAULT_COUNT
        } else {
            parse_u16(a.get(k + 2))?
        };
        let interval = if a.get(k + 3).is_empty() {
            DEFAULT_INTERVAL_MS
        } else {
            parse_interval(a.get(k + 3))?
        };
        // The hop limit (argument 4) is accepted but the instance sends
        // echo requests with its default hop limit.
        if !a.get(k + 4).is_empty() {
            parse_u8(a.get(k + 4))?;
        }
        let timeout = if a.get(k + 5).is_empty() {
            DEFAULT_TIMEOUT_MS
        } else {
            parse_interval(a.get(k + 5))?
        };
        if !a.get(k + 6).is_empty() || usize::from(size) > MAX_PAYLOAD {
            return Err(E::INVALID_ARGS);
        }
        let mut p = Ping {
            dst,
            src,
            size,
            count,
            interval: Duration::from_millis(u64::from(interval)),
            timeout: Duration::from_millis(u64::from(timeout)),
            id: 0x4f54,
            sent: 0,
            received: 0,
            is_async,
            multicast: dst.is_multicast(),
            last_send: self.now,
            sent_at: [self.now; SLOTS],
            min_rtt: u32::MAX,
            max_rtt: 0,
            total_rtt: 0,
        };
        self.send_one(&mut p)?;
        let sync = !p.is_async;
        self.st.ping = Some(p);
        if sync { Err(E::PENDING) } else { Ok(()) }
    }

    fn send_one(&mut self, p: &mut Ping) -> R {
        let mut buf = [0u8; MAX_PAYLOAD];
        let payload = &mut buf[..usize::from(p.size)];
        for (i, b) in payload.iter_mut().enumerate() {
            *b = i as u8;
        }
        let seq = p.sent.wrapping_add(1);
        self.i
            .ping(p.dst, p.src, p.id, seq, payload, self.now)
            .map_err(E::from)?;
        p.sent = seq;
        p.last_send = self.now;
        p.sent_at[usize::from(seq) % SLOTS] = self.now;
        Ok(())
    }

    pub(crate) fn ping_replies(&mut self) {
        while let Some(r) = self.i.take_ping_reply() {
            let Some(p) = self.st.ping.as_mut() else {
                continue;
            };
            if r.id != p.id {
                continue;
            }
            let rtt =
                r.at.saturating_duration_since(p.sent_at[usize::from(r.seq) % SLOTS])
                    .as_millis() as u32;
            p.received += 1;
            p.min_rtt = p.min_rtt.min(rtt);
            p.max_rtt = p.max_rtt.max(rtt);
            p.total_rtt = p.total_rtt.saturating_add(rtt);
            ln!(
                self.o,
                "{} bytes from {}: icmp_seq={} hlim={} time={}ms",
                r.payload_len + ICMP_HEADER,
                r.src,
                r.seq,
                r.hop_limit,
                rtt
            );
            if !p.multicast && p.sent >= p.count && p.received >= p.count {
                self.ping_finish();
                return;
            }
        }
    }

    pub(crate) fn ping_poll(&mut self) {
        let Some(mut p) = self.st.ping.take() else {
            return;
        };
        if p.sent < p.count {
            if self.now >= p.last_send.saturating_add(p.interval) {
                let _ = self.send_one(&mut p);
            }
            self.st.ping = Some(p);
        } else if self.now >= p.last_send.saturating_add(p.timeout) {
            self.st.ping = Some(p);
            self.ping_finish();
        } else {
            self.st.ping = Some(p);
        }
    }

    fn ping_finish(&mut self) {
        let Some(p) = self.st.ping.take() else {
            return;
        };
        out!(
            self.o,
            "{} packets transmitted, {} packets received.",
            p.sent,
            p.received
        );
        if p.sent != 0 && !p.multicast && p.received <= p.sent {
            let loss = 1000 * u32::from(p.sent - p.received) / u32::from(p.sent);
            out!(self.o, " Packet loss = {}.{}%.", loss / 10, loss % 10);
        }
        if p.received != 0 {
            let avg = 1000 * u64::from(p.total_rtt) / u64::from(p.received);
            out!(
                self.o,
                " Round-trip min/avg/max = {}/{}.{}/{} ms.",
                p.min_rtt,
                avg / 1000,
                avg % 1000,
                p.max_rtt
            );
        }
        ln!(self.o);
        if !p.is_async {
            ln!(self.o, "Done");
        }
    }
}
