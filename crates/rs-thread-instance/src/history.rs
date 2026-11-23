//! History Tracker (OT `Utils::HistoryTracker`, feature `history-tracker`):
//! ring buffers of the recent network information (role, mode, RLOC16,
//! partition ID) and of the IPv6 messages received from and sent to the
//! Thread network, each entry with the time it was recorded.
//!
//! # Deviations from OT
//!
//! - Only the network information and the RX / TX message lists exist; the
//!   address, neighbor, router, prefix, route and ephemeral key lists of OT
//!   are not kept.
//! - An entry is recorded as a TX message when the datagram is handed to the
//!   MAC, not when the last frame is done: `tx-success` is always `yes`.
//! - Entries are never deleted for age; the age reads "more than 49 days"
//!   beyond that (OT also marks them).
//! - Thread control messages (MLE, TMF) are excluded as in OT's default
//!   configuration.

use core::net::Ipv6Addr;

use heapless::Deque;
use rs_thread_core::time::Instant;
use rs_thread_core::types::Rloc16;
use rs_thread_mle::Role;
use rs_thread_net::header::{Ipv6Header, PROTO_ICMP6, PROTO_UDP};

/// Entries of the network information list (OT default).
pub const NET_INFO_ENTRIES: usize = 32;
/// Entries of each of the RX and TX lists (OT default).
pub const MESSAGE_ENTRIES: usize = 32;
/// Age after which an entry reads "more than 49 days" (OT
/// `OT_HISTORY_TRACKER_MAX_AGE`), milliseconds.
pub const MAX_AGE_MS: u64 = 49 * 24 * 60 * 60 * 1000;

/// UDP port of MLE.
const MLE_PORT: u16 = 19788;
/// UDP port of TMF.
const TMF_PORT: u16 = 61631;

/// One network information entry (OT `otHistoryTrackerNetworkInfo`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetInfoEntry {
    /// When the entry was recorded.
    pub at: Instant,
    /// Device role.
    pub role: Role,
    /// Receiver on when idle.
    pub rx_on_when_idle: bool,
    /// Full Thread device.
    pub full_thread_device: bool,
    /// Full Network Data.
    pub full_network_data: bool,
    /// RLOC16.
    pub rloc16: Rloc16,
    /// Partition ID.
    pub partition_id: u32,
}

/// One message entry (OT `otHistoryTrackerMessageInfo`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MessageEntry {
    /// When the entry was recorded.
    pub at: Instant,
    /// IPv6 payload length.
    pub payload_len: u16,
    /// RLOC16 of the neighbor the message came from / was sent to
    /// (`0xfffe` unknown, `0xffff` broadcast).
    pub neighbor: u16,
    /// IPv6 source address.
    pub src: Ipv6Addr,
    /// Source port (0 unless UDP).
    pub src_port: u16,
    /// IPv6 destination address.
    pub dst: Ipv6Addr,
    /// Destination port (0 unless UDP).
    pub dst_port: u16,
    /// Checksum of the UDP / ICMPv6 header (0 otherwise).
    pub checksum: u16,
    /// IPv6 Next Header value.
    pub proto: u8,
    /// ICMPv6 type (0 unless ICMPv6).
    pub icmp_type: u8,
    /// Average RSS in dBm (RX only; 127 when unknown).
    pub rss: i8,
    /// Link layer security was used.
    pub link_security: bool,
    /// Transmission succeeded (TX only).
    pub tx_success: bool,
    /// Priority: 0 low, 1 normal, 2 high, 3 network control.
    pub priority: u8,
}

/// The lists.
#[derive(Debug, Default)]
pub struct HistoryTracker {
    net_info: Deque<NetInfoEntry, NET_INFO_ENTRIES>,
    rx: Deque<MessageEntry, MESSAGE_ENTRIES>,
    tx: Deque<MessageEntry, MESSAGE_ENTRIES>,
}

fn push<T, const N: usize>(q: &mut Deque<T, N>, e: T) {
    if q.is_full() {
        let _ = q.pop_front();
    }
    let _ = q.push_back(e);
}

impl HistoryTracker {
    /// Empty lists.
    pub const fn new() -> Self {
        Self {
            net_info: Deque::new(),
            rx: Deque::new(),
            tx: Deque::new(),
        }
    }

    /// Record the network information (OT `RecordNetworkInfo`).
    pub fn record_net_info(&mut self, e: NetInfoEntry) {
        push(&mut self.net_info, e);
    }

    /// Record the IPv6 datagram `dg` received from (`tx == false`) or sent
    /// to (`tx == true`) the neighbor `neighbor` (OT `RecordMessage`).
    /// Thread control messages are not recorded.
    pub fn record_message(
        &mut self,
        at: Instant,
        tx: bool,
        dg: &[u8],
        neighbor: u16,
        rss: Option<i8>,
        link_security: bool,
    ) {
        let Ok(h) = Ipv6Header::parse(dg) else {
            return;
        };
        let upper = dg.get(Ipv6Header::LEN..).unwrap_or(&[]);
        let (mut src_port, mut dst_port, mut checksum, mut icmp_type) = (0, 0, 0, 0);
        match h.next_header {
            PROTO_UDP if upper.len() >= 8 => {
                src_port = u16::from_be_bytes([upper[0], upper[1]]);
                dst_port = u16::from_be_bytes([upper[2], upper[3]]);
                checksum = u16::from_be_bytes([upper[6], upper[7]]);
                let port = if tx { src_port } else { dst_port };
                if port == MLE_PORT || port == TMF_PORT {
                    return;
                }
            }
            PROTO_ICMP6 if upper.len() >= 4 => {
                icmp_type = upper[0];
                checksum = u16::from_be_bytes([upper[2], upper[3]]);
            }
            _ => {}
        }
        let e = MessageEntry {
            at,
            payload_len: h.payload_len,
            neighbor,
            src: h.src,
            src_port,
            dst: h.dst,
            dst_port,
            checksum,
            proto: h.next_header,
            icmp_type,
            rss: rss.unwrap_or(127),
            link_security,
            tx_success: true,
            priority: 1,
        };
        push(if tx { &mut self.tx } else { &mut self.rx }, e);
    }

    /// Network information entries, newest first.
    pub fn net_info(&self) -> impl Iterator<Item = &NetInfoEntry> {
        self.net_info.iter().rev()
    }

    /// Received messages, newest first.
    pub fn rx(&self) -> impl Iterator<Item = &MessageEntry> {
        self.rx.iter().rev()
    }

    /// Sent messages, newest first.
    pub fn tx(&self) -> impl Iterator<Item = &MessageEntry> {
        self.tx.iter().rev()
    }
}

/// Age of an entry recorded at `at`, milliseconds, `None` when it reads
/// "more than 49 days".
pub fn age_ms(now: Instant, at: Instant) -> Option<u64> {
    let a = now.saturating_duration_since(at).as_millis();
    (a < MAX_AGE_MS).then_some(a)
}
