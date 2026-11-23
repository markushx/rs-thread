//! `networkdiagnostic get|reset` (OT `cli.cpp`, `networkdiagnostic`): send a
//! Diagnostic Get / Query / Reset and print the answers as YAML-like lines.

use core::fmt::Write;
use core::net::Ipv6Addr;

use rand_core::{CryptoRng, Rng};
use rs_thread_core::time::{Duration, Instant};
use rs_thread_instance::{InstanceCrypto, diag_tlv as t};
use rs_thread_platform::SettingsStore;

use crate::Ctx;
use crate::util::{Args, E, Ip6, R, hex, ln, out, parse_ip6, parse_u8};

/// How long a `networkdiagnostic get` collects answers before it prints
/// `Done` (OT `kNetworkDiagnosticTimeoutMsecs`).
const TIMEOUT: Duration = Duration::from_millis(5000);

/// Largest number of TLV types of a request (OT `OT_NETWORK_DIAGNOSTIC_TYPELIST_MAX_ENTRIES`).
const MAX_TYPES: usize = 35;

/// Indentation step of nested YAML lines.
const INDENT: usize = 4;

/// A `networkdiagnostic get` waiting for its answers.
#[derive(Debug)]
pub(crate) struct Pending {
    deadline: Instant,
}

impl Pending {
    pub(crate) fn deadline(&self) -> Instant {
        self.deadline
    }
}

fn pad<W: Write>(o: &mut W, n: usize) {
    for _ in 0..n {
        let _ = o.write_char(' ');
    }
}

impl<S, C, Rn, W> Ctx<'_, S, C, Rn, W>
where
    S: SettingsStore,
    C: InstanceCrypto,
    Rn: Rng + CryptoRng,
    W: Write,
{
    pub(crate) fn networkdiagnostic(&mut self, a: &Args<'_>) -> R {
        if !matches!(a.get(1), "get" | "reset") {
            return Err(E::INVALID_COMMAND);
        }
        let addr = parse_ip6(a.get(2))?;
        let mut types = [0u8; MAX_TYPES];
        let mut n = 0;
        for s in a.rest(3) {
            *types.get_mut(n).ok_or(E::INVALID_ARGS)? = parse_u8(s)?;
            n += 1;
        }
        let types = &types[..n];
        if a.get(1) == "get" {
            // OT: the result is `Done` after the timeout, the answers print
            // as they arrive.
            if addr.is_multicast() {
                self.i.diag_query(addr, types, self.now)?;
            } else {
                self.i.diag_get(addr, types, self.now)?;
            }
            self.st.diag = Some(Pending {
                deadline: self.now.saturating_add(TIMEOUT),
            });
            Err(E::PENDING)
        } else {
            // OT ignores the send error of the reset.
            let _ = self.i.diag_reset(addr, types, self.now);
            Ok(())
        }
    }

    pub(crate) fn diag_poll(&mut self) {
        if let Some(p) = &self.st.diag
            && self.now >= p.deadline
        {
            self.st.diag = None;
            ln!(self.o, "Done");
        }
    }

    pub(crate) fn diag_answers(&mut self) {
        while let Some((from, tlvs)) = self.i.diag_take_answer_from() {
            print_answer(self.o, from, &tlvs);
        }
    }
}

/// The first TLV of `b`: type, value and the rest (`None` if cut).
fn next_tlv(b: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let ty = *b.first()?;
    let l = *b.get(1)?;
    let (len, hdr) = if l == 0xff {
        (usize::from(u16::from_be_bytes([*b.get(2)?, *b.get(3)?])), 4)
    } else {
        (usize::from(l), 2)
    };
    let v = b.get(hdr..hdr + len)?;
    Some((ty, v, &b[hdr + len..]))
}

fn print_mode<W: Write>(o: &mut W, ind: usize, m: u8) {
    pad(o, ind);
    ln!(o, "RxOnWhenIdle: {}", u8::from(m & 0x08 != 0));
    pad(o, ind);
    ln!(o, "DeviceType: {}", u8::from(m & 0x02 != 0));
    pad(o, ind);
    ln!(o, "NetworkData: {}", u8::from(m & 0x01 != 0));
}

fn u32_at(v: &[u8], i: usize) -> Option<u32> {
    Some(u32::from_be_bytes(v.get(i..i + 4)?.try_into().ok()?))
}

fn print_answer<W: Write>(o: &mut W, from: Ipv6Addr, tlvs: &[u8]) {
    out!(o, "DIAG_GET.rsp/ans from {}: ", Ip6(from));
    hex(o, tlvs);
    ln!(o);
    let mut rest = tlvs;
    while let Some((ty, v, r)) = next_tlv(rest) {
        rest = r;
        print_tlv(o, ty, v);
    }
}

fn print_tlv<W: Write>(o: &mut W, ty: u8, v: &[u8]) {
    match ty {
        t::EXT_ADDRESS if v.len() == 8 => {
            out!(o, "Ext Address: ");
            hex(o, v);
            ln!(o);
        }
        t::SHORT_ADDRESS if v.len() == 2 => {
            ln!(o, "Rloc16: 0x{:04x}", u16::from_be_bytes([v[0], v[1]]));
        }
        t::MODE if v.len() == 1 => {
            ln!(o, "Mode:");
            print_mode(o, INDENT, v[0]);
        }
        t::TIMEOUT => {
            if let Some(x) = u32_at(v, 0) {
                ln!(o, "Timeout: {}", x);
            }
        }
        t::CONNECTIVITY if v.len() >= 7 => {
            ln!(o, "Connectivity:");
            pad(o, INDENT);
            ln!(o, "ParentPriority: {}", (v[0] as i8) >> 6);
            for (n, i) in [(3, 1), (2, 2), (1, 3)] {
                pad(o, INDENT);
                ln!(o, "LinkQuality{}: {}", n, v[i]);
            }
            pad(o, INDENT);
            ln!(o, "LeaderCost: {}", v[4]);
            pad(o, INDENT);
            ln!(o, "IdSequence: {}", v[5]);
            pad(o, INDENT);
            ln!(o, "ActiveRouters: {}", v[6]);
            let sed = v.get(7..9).map_or(0, |b| u16::from_be_bytes([b[0], b[1]]));
            pad(o, INDENT);
            ln!(o, "SedBufferSize: {}", sed);
            pad(o, INDENT);
            ln!(o, "SedDatagramCount: {}", v.get(9).copied().unwrap_or(0));
        }
        t::ROUTE if v.len() >= 9 => {
            ln!(o, "Route:");
            pad(o, INDENT);
            ln!(o, "IdSequence: {}", v[0]);
            pad(o, INDENT);
            ln!(o, "RouteData:");
            let mut k = 9;
            for id in 0..64u8 {
                if v[1 + usize::from(id / 8)] & (0x80 >> (id % 8)) == 0 {
                    continue;
                }
                let Some(&d) = v.get(k) else { break };
                k += 1;
                pad(o, 2 * INDENT);
                ln!(o, "- RouteId: 0x{:02x}", id);
                pad(o, 2 * INDENT + 2);
                ln!(o, "LinkQualityOut: {}", d >> 6 & 3);
                pad(o, 2 * INDENT + 2);
                ln!(o, "LinkQualityIn: {}", d >> 4 & 3);
                pad(o, 2 * INDENT + 2);
                ln!(o, "RouteCost: {}", d & 0xf);
            }
        }
        t::LEADER_DATA if v.len() == 8 => {
            ln!(o, "Leader Data:");
            pad(o, INDENT);
            ln!(
                o,
                "PartitionId: 0x{:08x}",
                u32::from_be_bytes([v[0], v[1], v[2], v[3]])
            );
            pad(o, INDENT);
            ln!(o, "Weighting: {}", v[4]);
            pad(o, INDENT);
            ln!(o, "DataVersion: {}", v[5]);
            pad(o, INDENT);
            ln!(o, "StableDataVersion: {}", v[6]);
            pad(o, INDENT);
            ln!(o, "LeaderRouterId: 0x{:02x}", v[7]);
        }
        t::NETWORK_DATA => {
            out!(o, "Network Data: ");
            hex(o, v);
            ln!(o);
        }
        t::IP6_ADDR_LIST if v.len().is_multiple_of(16) => {
            ln!(o, "IP6 Address List:");
            for a in v.chunks_exact(16) {
                let mut b = [0u8; 16];
                b.copy_from_slice(a);
                pad(o, INDENT);
                ln!(o, "- {}", Ip6(Ipv6Addr::from(b)));
            }
        }
        t::MAC_COUNTERS if v.len() == 36 => {
            ln!(o, "MAC Counters:");
            const NAMES: [&str; 9] = [
                "IfInUnknownProtos",
                "IfInErrors",
                "IfOutErrors",
                "IfInUcastPkts",
                "IfInBroadcastPkts",
                "IfInDiscards",
                "IfOutUcastPkts",
                "IfOutBroadcastPkts",
                "IfOutDiscards",
            ];
            for (i, n) in NAMES.iter().enumerate() {
                pad(o, INDENT);
                ln!(o, "{}: {}", n, u32_at(v, i * 4).unwrap_or(0));
            }
        }
        t::BATTERY_LEVEL if v.len() == 1 => ln!(o, "Battery Level: {}%", v[0]),
        t::SUPPLY_VOLTAGE if v.len() == 2 => {
            ln!(o, "Supply Voltage: {}mV", u16::from_be_bytes([v[0], v[1]]));
        }
        t::CHILD_TABLE if v.len().is_multiple_of(3) => {
            ln!(o, "Child Table:");
            for e in v.chunks_exact(3) {
                let w = u16::from_be_bytes([e[0], e[1]]);
                pad(o, INDENT);
                ln!(o, "- ChildId: 0x{:04x}", w & 0x1ff);
                pad(o, INDENT + 2);
                ln!(o, "Timeout: {}", w >> 11);
                pad(o, INDENT + 2);
                ln!(o, "Link Quality: {}", w >> 9 & 3);
                pad(o, INDENT + 2);
                ln!(o, "Mode:");
                print_mode(o, INDENT + 2 + INDENT, e[2]);
            }
        }
        t::CHANNEL_PAGES => {
            out!(o, "Channel Pages: '");
            hex(o, v);
            ln!(o, "'");
        }
        t::MAX_CHILD_TIMEOUT => {
            if let Some(x) = u32_at(v, 0) {
                ln!(o, "Max Child Timeout: {}", x);
            }
        }
        t::EUI64 if v.len() == 8 => {
            out!(o, "EUI64: ");
            hex(o, v);
            ln!(o);
        }
        t::VENDOR_NAME => print_str(o, "Vendor Name", v),
        t::VENDOR_MODEL => print_str(o, "Vendor Model", v),
        t::VENDOR_SW_VERSION => print_str(o, "Vendor SW Version", v),
        t::VENDOR_APP_URL => print_str(o, "Vendor App URL", v),
        t::THREAD_STACK_VERSION => print_str(o, "Thread Stack Version", v),
        _ => {}
    }
}

fn print_str<W: Write>(o: &mut W, name: &str, v: &[u8]) {
    out!(o, "{}: ", name);
    for &b in v {
        let _ = o.write_char(if b.is_ascii() { b as char } else { '?' });
    }
    ln!(o);
}
