//! SRP server discovery from the Thread Network Data (OT
//! `NetworkData::Service::Manager`: `GetNextDnsSrpUnicastInfo`,
//! `FindPreferredDnsSrpAnycastInfo`; Thread 1.4.1 section on DNS/SRP
//! services).
//!
//! Three kinds of Service TLV entries (enterprise number 44970, service
//! numbers 0x5c anycast and 0x5d unicast) announce an SRP server:
//!
//! | kind | service data | server data |
//! |------|--------------|-------------|
//! | unicast, address in service data | `5d addr[16] port[2] [version]` | - |
//! | anycast | `5c seq` | `[version]` |
//! | unicast, address in server data | `5d` | `addr[16] port[2] [version]` or just `port[2]` (address is the server's RLOC) |
//!
//! Callers map their Network Data view to [`NetDataService`] (one item per
//! Server sub-TLV; `opentrust_mesh::netdata::view::ServiceEntry` has exactly
//! these fields).

use core::net::{Ipv6Addr, SocketAddrV6};

/// Thread enterprise number in Service TLVs.
pub const THREAD_ENTERPRISE_NUMBER: u32 = 44970;
/// Service number of the DNS/SRP anycast service.
pub const SERVICE_NUMBER_ANYCAST: u8 = 0x5c;
/// Service number of the DNS/SRP unicast service.
pub const SERVICE_NUMBER_UNICAST: u8 = 0x5d;
/// Port of an anycast SRP server.
pub const ANYCAST_SERVER_PORT: u16 = 53;
/// First service ALOC16 (`0xfc10 + service id`).
pub const SERVICE_ALOC_BASE: u16 = 0xfc10;

/// One Server sub-TLV of a Service TLV in the Network Data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetDataService<'a> {
    /// Service ID (4 bits).
    pub service_id: u8,
    /// Enterprise number.
    pub enterprise_number: u32,
    /// Service data.
    pub service_data: &'a [u8],
    /// RLOC16 of the server.
    pub rloc16: u16,
    /// Server data.
    pub server_data: &'a [u8],
}

/// Where a unicast entry carries the server address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnicastType {
    /// In the service data (preferred by OT).
    InServiceData,
    /// In the server data.
    InServerData,
}

/// A unicast SRP server.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnicastInfo {
    /// Address and port.
    pub addr: SocketAddrV6,
    /// Server version (higher is preferred).
    pub version: u8,
    /// RLOC16 of the server's device.
    pub rloc16: u16,
}

/// An anycast SRP server.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AnycastInfo {
    /// The service ALOC.
    pub address: Ipv6Addr,
    /// Sequence number.
    pub sequence_number: u8,
    /// Server version.
    pub version: u8,
    /// RLOC16 of the server's device.
    pub rloc16: u16,
}

/// `ml_prefix` + `0000:00ff:fe00:<last16>`.
fn locator(ml_prefix: &[u8; 8], last16: u16) -> Ipv6Addr {
    let mut o = [0u8; 16];
    o[..8].copy_from_slice(ml_prefix);
    o[11] = 0xff;
    o[12] = 0xfe;
    o[14..].copy_from_slice(&last16.to_be_bytes());
    Ipv6Addr::from(o)
}

fn parse_addr_port_version(d: &[u8]) -> Option<(Ipv6Addr, u16, u8)> {
    let a: [u8; 16] = d.get(..16)?.try_into().ok()?;
    let port = u16::from_be_bytes([*d.get(16)?, *d.get(17)?]);
    Some((Ipv6Addr::from(a), port, d.get(18).copied().unwrap_or(0)))
}

fn is_thread(e: &NetDataService<'_>, number: u8) -> bool {
    e.enterprise_number == THREAD_ENTERPRISE_NUMBER && e.service_data.first() == Some(&number)
}

/// Unicast entries of `ty`, in Network Data order.
pub fn unicast_entries<'a, I>(
    entries: I,
    ml_prefix: [u8; 8],
    ty: UnicastType,
) -> impl Iterator<Item = UnicastInfo> + 'a
where
    I: Iterator<Item = NetDataService<'a>> + 'a,
{
    entries.filter_map(move |e| {
        if !is_thread(&e, SERVICE_NUMBER_UNICAST) {
            return None;
        }
        let (addr, port, version) = match ty {
            UnicastType::InServiceData => parse_addr_port_version(&e.service_data[1..])?,
            UnicastType::InServerData => match parse_addr_port_version(e.server_data) {
                Some(v) => v,
                None if e.server_data.len() == 2 => (
                    locator(&ml_prefix, e.rloc16),
                    u16::from_be_bytes([e.server_data[0], e.server_data[1]]),
                    0,
                ),
                None => return None,
            },
        };
        Some(UnicastInfo {
            addr: SocketAddrV6::new(addr, port, 0, 0),
            version,
            rloc16: e.rloc16,
        })
    })
}

/// Anycast entries in Network Data order.
pub fn anycast_entries<'a, I>(
    entries: I,
    ml_prefix: [u8; 8],
) -> impl Iterator<Item = AnycastInfo> + 'a
where
    I: Iterator<Item = NetDataService<'a>> + 'a,
{
    entries.filter_map(move |e| {
        if !is_thread(&e, SERVICE_NUMBER_ANYCAST) || e.service_data.len() < 2 {
            return None;
        }
        Some(AnycastInfo {
            address: locator(&ml_prefix, SERVICE_ALOC_BASE + u16::from(e.service_id)),
            sequence_number: e.service_data[1],
            version: e.server_data.first().copied().unwrap_or(0),
            rloc16: e.rloc16,
        })
    })
}

/// Serial number arithmetic (RFC 1982) for 8-bit sequence numbers: is `a`
/// greater than `b`?
pub const fn serial_is_greater(a: u8, b: u8) -> bool {
    a != b && a.wrapping_sub(b) < 0x80
}

/// The preferred anycast entry (OT `FindPreferredDnsSrpAnycastInfo`): the
/// largest sequence number in serial arithmetic if that is well defined
/// (greater than every other one), else the numerically largest.
pub fn preferred_anycast(entries: &[AnycastInfo]) -> Option<AnycastInfo> {
    let mut best: Option<AnycastInfo> = None;
    let mut max_num: Option<AnycastInfo> = None;
    for &e in entries {
        match best {
            None => {
                best = Some(e);
                max_num = Some(e);
            }
            Some(b) => {
                if serial_is_greater(e.sequence_number, b.sequence_number) {
                    best = Some(e);
                }
                if e.sequence_number > max_num.map_or(0, |m| m.sequence_number) {
                    max_num = Some(e);
                }
            }
        }
    }
    let mut best = best?;
    for e in entries {
        let seq = e.sequence_number;
        if seq == best.sequence_number {
            continue;
        }
        let diff = seq.wrapping_sub(best.sequence_number);
        if diff == 0x80 || !serial_is_greater(best.sequence_number, seq) {
            best = max_num?;
            break;
        }
    }
    // The version is the minimum supported by all entries with the
    // selected sequence number.
    for e in entries {
        if e.sequence_number == best.sequence_number {
            best.version = best.version.min(e.version);
        }
    }
    Some(best)
}
