# Memory budget

RAM used by `opentrust_instance::Instance` (x86_64 `size_of_val`, includes a
caller-provided `RamSettings<4096>`; 32-bit targets are somewhat smaller).
Regenerate with
`cargo test -p opentrust-instance instance_size_breakdown -- --nocapture`;
the test asserts an upper bound per feature set (`src/size_test.rs`).

## Total per feature set

| Feature set | Before pooling | Now |
|---|---|---|
| default (ftd + commissioner + border-agent) | 150000 | 107136 |
| `ftd` only | 116240 | 82528 |
| MTD (`--no-default-features`) | 102800 | 74576 |

## Per component (default feature set)

| Component | Before | Now |
|---|---|---|
| commissioning (`cm`: joiner 7616, commissioner 7536, border agent 15408, border agent outbox 1672) | 43664 | 34416 |
| core (MAC 5848, IPv6 5768, MAC tx 4640, settings 4104, MLE outbox 1384, events 1840) | 33464 | 27048 |
| DNS/SRP clients | 14792 | 13872 |
| mesh forwarder | 11784 | 7720 |
| MLE | 8328 | 8328 |
| TMF agent | 10584 | 4488 |
| UDP sockets | 14040 | 3304 |
| TMF/app outbox (`sink`) | 7800 | 2416 |
| backbone router glue | 2072 | 2072 |

## Storage model

Queued messages live in chains of 128-byte buffers (`opentrust_core::bufpool`,
OpenThread's message buffer size) taken from a pool owned by the queue's
owner: outbox, Border Agent outbox, UDP sockets (one pool for all receive
queues), indirect queue, forwarder held datagrams, CoAP endpoint (pending
requests and cached responses), DNS/SRP datagrams. An allocation that does not
fit fails with `NoBufs`. The pool sizes are const generics with defaults.

## Target devices

| Device | RAM | Instance (default) | Instance (MTD) |
|---|---|---|---|
| nRF52840 | 256 kB | leaves about 60% for the application | about 70% |
| nRF54L15 | 256 kB | as above | as above |
| ESP32-C6 | 512 kB | fits comfortably | fits comfortably |
| ESP32-H2 | 320 kB | fits | fits |

## What remains

- Core (MAC 5848, IPv6 5768, MAC tx queue 4640, `RamSettings` 4096) and the
  forwarder (reassembly slots and receive buffer, 1280 bytes each) still hold
  worst-case buffers.
- The DTLS roles (Joiner, Commissioner, Border Agent) are all resident; the
  Joiner and Commissioner are never active together and could share storage.
- The DNS client result queue and the SRP client carry fixed-size records.
- One pool shared by all queues (OpenThread default: 44 buffers) is not done:
  each queue owns its pool because the queues are borrowed as disjoint
  fields by the view structs (ADR 0003) and a handle-based pool cannot be
  lent to several of them at once without passing it through every view.
