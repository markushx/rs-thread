# Memory budget

RAM used by `opentrust_instance::Instance` (x86_64 `size_of_val`, includes a
caller-provided `RamSettings<4096>`; 32-bit targets are somewhat smaller).
Regenerate with
`cargo test -p opentrust-instance instance_size_breakdown -- --nocapture`;
the test asserts an upper bound per feature set (`src/size_test.rs`).

## Total per feature set

| Feature set | Before pooling | Now |
|---|---|---|
| default (ftd + commissioner + border-agent) | 150000 | 107424 |
| `ftd` only | 116240 | 82816 |
| MTD (`--no-default-features`) | 102800 | 74864 |

## Per component (default feature set)

| Component | Before | Now |
|---|---|---|
| commissioning (`cm`: joiner 7616, commissioner 7536, border agent 15408, border agent outbox 1672) | 43664 | 34416 |
| core (MAC 5848, IPv6 5768, MAC tx 4640, settings 4104, MLE outbox 1384, events 1840) | 33464 | 27048 |
| DNS/SRP clients (five SRP subtypes per service, for Matter's commissionable service) | 14792 | 14160 |
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

## Matter light node (`opentrust-matter`)

RAM of the on-off light of `crates/opentrust-matter/tests/light.rs` (x86_64
`size_of_val`, debug build; the release build prints the same numbers).
Regenerate with
`cargo test -p opentrust-matter --test light -- --nocapture`.

| Object | Bytes |
|---|---|
| `Resources` (default `Instance` with a 4096-byte `RamSettings`, state, wakers) | 110400 |
| `ThreadRunner` (net stack, netif, net ctl, mDNS, persist with its settings buffer) | 1304 |
| `MatterStack<64 kB bump, ThreadNetworks>`: `Matter` 26632 + bump 65536 + buffers, IM state, networks store, ... | 110376 |
| future of `run_thread_oper` | 3448 |
| `OnOffHandler` | 168 |
| Total | about 225700 |

Notes, no optimisation done:

- 32-bit targets are smaller (pointers and `usize`), roughly 10 to 15%, so
  about 190 to 200 kB on a Cortex-M4. That leaves 50 to 60 kB of the nRF52840's
  256 kB for the stacks of the tasks, the executor, the radio driver, BLE
  (`trouble-host`) while commissioning and the application. Tight but
  plausible; it does not fit with the default settings on a 64 kB budget
  elsewhere in the system.
- The bump allocator (65536 bytes here, the size rs-matter's examples use for
  an unoptimised build) holds the pinned futures of the stack. An optimised
  embedded build needs much less of it; the actual peak was not measured.
- Levers that exist already: an MTD / `ftd`-less `Instance` (74864 against
  107424 bytes), fewer subscriptions / fabrics / responders (rs-matter
  features `stack-max-*`, `max-fabrics-*`), a smaller bump.
- The ESP32-C6 (512 kB) and ESP32-H2 (320 kB) have room.

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

## nRF52840 firmware (`examples/nrf52840-leader`)

Measured on the nRF52840 DK: `cargo build --release` of the leader firmware
(`opt-level = "s"`, fat LTO, `panic = "abort"`, rustc 1.95), `Instance` with the
`ftd` feature only (no commissioner / border agent), soft crypto (including
the ECDSA / EC-JPAKE code `opentrust-instance` always pulls in), a 4096-byte
`RamSettings`, defmt over RTT.

| Section | Bytes |
|---|---|
| Flash: vector table 256 + `.text` 351660 + `.rodata` 22280 + `.data` image 80 | 374276 (about 365 KiB of 1024 KiB) |
| RAM, static: `.data` 80 + `.bss` 85084 + `.uninit` 1024 | 86188 (about 84 KiB of 256 KiB) |
| of which `Resources` (the `Instance`, 4096-byte settings, state) | about 82000 |
| Stack high-water: construction of the `Instance` / `Resources` (moved by value) | 111856 |
| Stack high-water: running as Leader, advertising | 127688 |

Notes:

- Stack is measured by painting the RAM between `.bss` and the stack pointer
  (`stack_high_water` in the firmware). The 125 kB of stack is not yet
  explained; it is far more than the 80 kB static `Instance` and points at
  large by-value temporaries (construction and moves of the `Instance`, large
  locals in the poll path). With the static RAM this leaves about 40 kB of the
  256 kB free, not enough for rs-matter (see the Matter light section above).
  Constructing the `Instance` in place (`StaticCell::init_with`-style) and
  finding the large stack frames is the first RAM optimisation to do.
- `.text` is dominated by the cryptography (P-256 ECDSA / EC-JPAKE, AES, SHA);
  no per-crate breakdown was made.
