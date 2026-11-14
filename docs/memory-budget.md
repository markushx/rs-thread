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
  embedded build needs much less: 26760 bytes were measured on the nRF52840 (see below).
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

Measured on the nRF52840 DK with both radio backends: `cargo build --release` of the leader firmware
(`opt-level = "s"`, fat LTO, `panic = "abort"`, rustc 1.95), `Instance` with the
`ftd` feature only (no commissioner / border agent), soft crypto (including
the ECDSA / EC-JPAKE code `opentrust-instance` always pulls in), a 4096-byte
`RamSettings`, defmt over RTT.

| Section | `radio-embassy` | `radio-nrf802154` (default) |
|---|---|---|
| Flash: vector table 256 + `.text` + `.rodata` + `.data` image | 365560 (before 374496): about 357 KiB of 1024 KiB | 431172 (before 440172): about 421 KiB of 1024 KiB |
| RAM, static: `.data` + `.bss` + `.uninit` 1024 | 86196 (`.bss` 85092): about 84 KiB of 256 KiB | 95072 (`.data` 3180, `.bss` 90868): about 93 KiB of 256 KiB |
| of which `Resources` (the `Instance`, 4096-byte settings, state) | about 82000 | about 82000 |
| Stack high-water: construction of the `Instance` / `Resources` | 15820 (before 111856) | 15820 (before 111864) |
| Stack high-water: running as Leader, advertising | 16920 (before 127688) | 16912 (before 127688) |

The Nordic backend costs about 66 kB of flash (driver, MPSL and service layer
libraries, the Rust glue) and about 9 kB of static RAM (driver state, MPSL,
the receive queue of 16 frames), and nothing in stack: the stack peaks are
the stack's own. The MAC code the Nordic backend makes unnecessary is still
in the image (the MAC chooses at run time; `SoftMacNeeds` is `RETRANSMIT` only
with `radio-nrf802154` against `0x6ff` with `radio-embassy`), so the software
ACK / CSMA / security paths are dead weight in the Nordic build that a
feature split of the MAC could remove.

Notes:

- Stack is measured by painting the RAM between `.bss` and the stack pointer
  (`stack_high_water` in the firmware).
- Flash dropped by about 9 kB with the RAM work (the by-value moves of the
  instance were large `memcpy`s and temporaries).

- `.text` is dominated by the cryptography (P-256 ECDSA / EC-JPAKE, AES, SHA);
  no per-crate breakdown was made.

## Stack: where the 128 kB went, and the fix

Finding (disassembly of the release ELF, sum of `sub sp` and `push` per
function): the stack peak was not the running stack but one frame. The async
`main` task's `poll` had a frame of 110752 bytes: `Instance::new` built the
~82 kB instance (and the ~28 kB of the larger components, one temporary per
component, nothing is overlapped) in that frame, then `Resources::new(instance,
..)` moved it by value into the `StaticCell`. As a frame lives as long as the
poll runs, the 111864 bytes of the construction were still counted while the
node ran (`127688` = 110752 frame + about 17 kB of real depth). Below it, the
poll path summed the `Instance::poll` steps inlined into one 7.4 kB frame
(MTU-sized `[u8; 1280]` buffers of the outbox, MPL and datagram paths in
`service_outbox`, `send_udp_datagram`, `ip6_send_sec`, `deliver`).

Fix:

- `Instance::init(&mut MaybeUninit<Instance>, ..)` and
  `Resources::init(&mut MaybeUninit<Resources>, clock, |slot| Instance::init(..))`
  build the value in place. Each component is built by a non-inlined `put`
  helper straight into its field, so the temporaries do not add up; the largest
  is about 11 kB. `Resources` keeps its state in its own raw mutex + borrow
  flag cell (embassy's `Mutex<RefCell<_>>` cannot be initialised in place).
  `new` stays for hosts and tests and calls `init`.
- The `Instance::poll` service steps are `#[inline(never)]`, so the frames of
  the steps are not summed into `poll`; the main task frame is 4.5 kB.

Result on the DK, both backends: construction peak 15820 bytes, running
16912 / 16920 bytes (was 111864 / 127688). The remaining deepest frames are
`service_mac` (6.2 kB), `ip6_send_sec` (5.5 kB), `handle_tmf` (5.0 kB),
`DnsClient::finish` (7.7 kB) and the `put` helpers during construction (up to
11 kB); further reduction would need shared datagram scratch buffers instead
of per-function `[u8; 1280]` arrays.

## Matter light on the nRF52840 DK (`examples/nrf52840-light`)

Firmware: the `opentrust-matter` on-off light (`ThreadRunner` +
`MatterStack::run_thread_oper`, Thread only, no BLE) with a preset dataset
(the node is Leader), `radio-nrf802154`, rs-matter test device attestation,
RustCrypto backend of rs-matter (`rustcrypto`: pure Rust p256 / aes / sha2, no
hardware crypto; it needs `alloc`, so there is a 4096-byte `embedded-alloc`
heap, 0 bytes used while idle), `case-responder-only`, a flash-backed key-value store
(`opentrust-flash`, see below), defmt over RTT, LED1 follows the OnOff attribute.
It builds, boots, becomes Leader and runs rs-matter (PASE window open,
mDNS, responders); it logs the pairing code `3497-011-2332`, discriminator 3840
and the QR code. Not commissioned (no controller and no BLE here); the LED
path is untested.

| Section | Bytes |
|---|---|
| Flash (`.text` 766896 + `.rodata` 56940 + vector table 256 + `.data` 3180) | 827332 (about 808 KiB of 1024 KiB) |
| Static RAM (`.data` 3180 + `.bss` 175188, includes `.uninit` 1024) | 178368 (about 174 KiB of 256 KiB) |
| of which `Resources` (`Instance`, 4096-byte `RamSettings`, state) | 82272 |
| of which `MatterStack` (`Matter` 25696, rs-matter bump 28672, buffers, IM state, networks) | 72400 |
| of which the rest (main task future with the 3048-byte run future, MPSL and driver about 9000, heap 4096, KV scratch 2048, RTT, executor) | about 23700 |
| Stack high-water while running, idle, Thread Leader | 31352 (13200 right after start, 15660 during construction) |
| Left for BLE, application and a deeper stack (256 kB - static - stack) | about 52000 |

rs-matter's bump allocator needs 26760 bytes for the operational run (logged
by rs-matter-stack at start-up; `BUMP` = 28 kB here, the sim test uses 64 kB).
The 31 kB stack peak is rs-matter's: a 20 kB frame of an `embassy_futures`
`select3` poll that inlines the stack's futures, plus the Thread path below it.
A `MatterStack` with `BUMP` of 16 kB panics with "Out of bump memory" at start.

The bump area is filled once at start (futures of the transport, responders and
the operational task), not per transaction: PASE and CASE run on the stack and in
fixed buffers inside those futures, so 28 kB stays enough. The only heap user of the
RustCrypto backend is the PKCS#10 request of commissioning (`x509-cert`): 531 bytes
at peak (`crates/opentrust-matter/tests/heap.rs`, counting allocator, host build),
so the 4096-byte heap has about 3.5 kB of headroom and was not raised.
Measured on the DK against a real border router and chip-tool (PASE, attestation, CSR,
AddNOC, CASE, CommissioningComplete, On/Off toggle): stack high-water 35192 bytes
(31352 idle), heap 0 bytes used when sampled every 2 s, no bump or allocation failure.

### Persistent settings in flash (`opentrust-flash`)

Both firmwares keep their settings in the last 24 KiB of flash (outside the
linker's `FLASH` region, so the image cannot overlap it, and untouched when
probe-rs reflashes the image):

| Region | Address | Size | Used by |
|---|---|---|---|
| Thread settings | 0xFA000 | 2 banks of 1 page (8 KiB) | `node` binary: datasets, network info with the frame counters, parent / child info |
| Key-value store | 0xFC000 | 2 banks of 2 pages (16 KiB) | Matter light: all rs-matter blobs plus the Thread settings blob (`ThreadPersist`) |

Cost, measured on the DK (`radio-nrf802154`):

| | Flash image | Static RAM |
|---|---|---|
| `node` binary (RAM image 1536 + 16 dirty keys, entry buffer 512, replaces the 4096-byte `RamSettings`) | 447556 (about 437 KiB; the leader `main` without the store is 431172) | 93628 (`main` with `RamSettings<4096>`: 95072) |
| Light (RAM image 4096 + 32 dirty keys, entry buffer 2080, next to the unchanged `RamSettings<4096>` of the instance) | 851300 (about 831 KiB, +23968 over 827332 before) | 186140 (+7772 over 178368 before) |

The flash code itself (log, CRC, compaction, the MPSL flash driver and its
timeslot session memory) is about 16 KiB of the flash growth; the rest in the
light is the `KvBlobStore` glue and rs-matter paths that now do real work.
Wear: one 4 KiB-page bank erase per compaction; a bank fills after about
100 to 250 key updates (12 to 80 bytes each), and the two banks alternate, so
10000 erase cycles per page last for millions of updates.

### BLE commissioning (measured)

The light with BLE (`ble` feature, the default of `examples/nrf52840-light`)
adds the Nordic SoftDevice Controller (`nrf-sdc` 0.4, peripheral library,
one connection, advertising only, no central, no scanning) and `trouble-host`
0.8 (peripheral and GATT server) on the MPSL instance that already serves the
802.15.4 driver, and rs-matter's BTP engine with the coexistence runner
(`run_thread`). Same build settings as above (release, `opt-level = "s"`,
fat LTO, one codegen unit), `radio-nrf802154`:

| | Thread only (`--no-default-features`) | With BLE | Difference |
|---|---|---|---|
| Flash (`.text` + `.rodata` + `.data` + vectors) | 852392 (832.4 KiB) | 972712 (950.0 KiB) | +120320 (+117.5 KiB) |
| of which `.text` | 790780 | 895664 | +104884 |
| of which `.rodata` | 58108 | 69392 | +11284 |
| of which `.data` | 3248 | 7400 | +4152 (SoftDevice Controller state) |
| Static RAM (`.data` + `.bss` + `.uninit` 1024) | 186140 | 205912 (201.1 KiB) | +19772 |
| of which rs-matter bump (`BUMP` 28 kB without BLE; 34012 bytes used with BLE, set to 36 kB) | 28672 | 36864 | +8192 |
| of which the rest (SoftDevice Controller 3084-byte pool, `trouble-host` resources, BTP and GATT buffers) | | | +11580 |
| Stack high-water, idle, waiting for BLE commissioning | 31352 (idle, Thread leader) | 17676 | the unprovisioned light runs no Thread yet |
| Flash headroom (the image must end below 0xFA000 = 1024000) | 171608 | 51288 | |
| RAM left for stack and application (256 kB - static) | 76004 | 56232 | -19772 |

The 1000 KiB FLASH region of `memory.x` (settings above 0xFA000) holds the
image with 50 kB to spare; static RAM leaves 56 kB for the stack,
whose commissioning peak is 35 kB. The SoftDevice Controller is created only
while BLE advertises (`SdcGatt` in the light), so its pool is a static
buffer rather than a stack or heap use. Size levers, none needed yet: the
unused `RamSettings<4096>` is not removable (the `Instance` keeps its own
settings store; the flash store holds the persistent copy), `opt-level = "z"`
for the BLE crates, `DEFMT_LOG=warn` (all `info!` strings out of the image),
fewer rs-matter clusters, `max-fabrics-*` and `stack-max-*` features.

## SRP service slots

The SRP client keeps `SRP_SERVICES` service slots (`opentrust_instance::SRP_SERVICES`,
default 6, features `srp-services-8` and `srp-services-12`): Matter registers one
operational service per fabric plus the commissionable service, and requires at
least five fabrics. With four slots only three fabrics fitted next to the
commissionable service. Measured on the nRF52840 light (BLE build, nrf802154):
`.bss` 197496 -> 199288 bytes (+1792) and `Resources` 82264 -> 83800 bytes
(+1536) for two more slots, so about 770 bytes per slot; flash is unchanged
(-84 bytes). Eight slots cost about 1.5 kB more than six, twelve about 4.6 kB.
The size of one SRP update message is not bounded by the slot count: with all
slots filled and five subtypes on the commissionable service it can approach the
1232 byte UDP payload of the client.
