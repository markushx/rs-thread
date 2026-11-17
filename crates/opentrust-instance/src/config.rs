//! Capacities of the instance: every fixed-size table and buffer pool of the
//! stack in one place (OpenThread: `config/*.h` capacity macros). The values
//! differ between the full device (`ftd`) and the end-device build
//! (`default-features = false`).

/// Capacity of the child table (router role).
pub const CHILDREN: usize = 10;

/// UDP sockets of the application.
pub const UDP_SOCKETS: usize = 5;
/// Receive queue depth of each UDP socket.
pub const UDP_QUEUE: usize = 2;
/// Registered UDP receivers (internal protocols).
pub const UDP_RECEIVERS: usize = 4;
/// Buffers (of 128 bytes) in the pool of the UDP receive queues.
pub const UDP_POOL_BLOCKS: usize = 16;

/// Datagrams held while an address query runs.
pub const HOLD_SLOTS: usize = 2;
/// Buffers that hold datagrams while an address query runs (the default of
/// the forwarder; two full-size datagrams with IPv6 fragmentation).
pub const HOLD_BUFS: usize = if cfg!(feature = "ip6-fragmentation") {
    24
} else {
    12
};
/// Datagrams being reassembled from 6LoWPAN fragments.
pub const REASM_SLOTS: usize = 2;
/// Messages in the indirect queue for sleepy children.
pub const INDIRECT_MSGS: usize = 4;
/// Buffers (of 128 bytes) in the pool of the indirect queue.
pub const INDIRECT_POOL_BLOCKS: usize = 16;

/// Entries of the MPL seed set (duplicate detection; every node).
pub const MPL_SEEDS: usize = 35;
/// Buffered messages of MPL forwarding (retransmissions; routers only).
pub const MPL_BUFS: usize = 4;

/// Network Data capacity in bytes.
pub const NETDATA_LEN: usize = 512;

/// Buffers (of 128 bytes) of the TMF and application outbox.
pub const TMF_OUTBOX_BLOCKS: usize = 16;
/// Buffers (of 128 bytes) of the MLE outbox.
pub const MLE_OUTBOX_BLOCKS: usize = 8;

/// Pending requests of the TMF agent.
pub const TMF_REQUESTS: usize = 4;
/// Resource slots of the TMF agent.
pub const TMF_RESOURCES: usize = 32;
/// Cached responses of the TMF agent.
pub const TMF_CACHE: usize = 4;
/// Largest TMF message: a Relay Receive / Transmit carries a whole DTLS
/// record of the Joiner (FTD only; an end device relays nothing).
pub const TMF_MSG: usize = if cfg!(feature = "ftd") { 1024 } else { 320 };

/// Entries of the address resolver cache.
pub const RESOLVER_ENTRIES: usize = 8;
/// Entries of the Network Data publisher.
pub const PUBLISHER_ENTRIES: usize = 3;
/// SLAAC addresses.
pub const SLAAC_ADDRS: usize = 4;

/// Frames in the MAC direct transmit queue.
pub const MAC_TX: usize = opentrust_mac::mac::TX_QUEUE_LEN;
/// Frames in the MAC indirect queue (for sleepy children).
pub const MAC_INDIRECT: usize = opentrust_mac::mac::INDIRECT_QUEUE_LEN;
/// Events in the MAC upward queue.
pub const MAC_EVENTS: usize = opentrust_mac::mac::EVENT_QUEUE_LEN;
/// Data poll requests in the MAC queue (parent side).
pub const MAC_POLL_REQUESTS: usize = opentrust_mac::mac::POLL_REQUEST_QUEUE_LEN;
/// Entries of the MAC short to extended address map.
pub const MAC_NEIGHBORS: usize = opentrust_mac::mac::NEIGHBOR_MAP_LEN;
/// CSL children of the MAC (parent side).
pub const MAC_CSL_CHILDREN: usize = opentrust_mac::mac::CSL_CHILD_LEN;
