# OpenTrust – Implementation Plan

Pure Rust (`no_std`, no alloc by default) implementation of the Thread 1.4.1 protocol.

**Approach:** clean re-implementation from the specification in idiomatic Rust — *not* a C++-to-Rust translation of OpenThread.
OpenThread serves as design reference (module boundaries, constants, timing), source of test vectors, and interop/differential-test peer.

**Integration target:** must work as the Thread transport for [rs-matter](https://github.com/project-chip/rs-matter) (Matter over Thread).

License: Apache-2.0.
Spec: `spec/Threadv1.4.1SpecificationFinal_5345_1.pdf` (chapter refs below as "§n").

Legend: `[ ]` todo · `[~]` in progress · `[x]` done

## Guiding principles

- `#![no_std]`, `heapless`/fixed-capacity buffers; optional `alloc`/`std` features for host & sim.
- Sans-IO core: protocol state machines take frames/timers in, emit frames/timers out. No executor dependency in core (mirrors OpenThread's single-threaded tasklet/timer/callback model, which is also not async).
- First-class async facade on top (`opentrust-embassy`): executor-agnostic `async` API using `embassy-sync` primitives, matching what rs-matter expects; this is the primary user-facing API.
- Platform abstraction via traits (radio, timer/clock, entropy, crypto, settings/flash).
- OpenThread is the reference: every feature gets a differential/interop test against an OpenThread node.
- Feature-gated device roles: `mtd` (MED/SED), `ftd` (REED/Router/Leader), `ssed`, `border-router`.

## Phase 0 – Repository groundwork

- [x] Relicense to Apache-2.0: replace `LICENSE`, update `license` fields in all `Cargo.toml`s
- [x] Decide fate of old code: `openthread-sys` moved to `tools/openthread-sys` (test/interop oracle, not a default workspace member), `openthread-rust` sample removed
  - [ ] Fix `tools/openthread-sys/build.rs`: stop running `script/bootstrap` (installs system packages) and building inside the source tree; build into `OUT_DIR`; regenerate bindings against the new OpenThread headers (Phase 11)
- [x] Refresh OpenThread submodule to `thread-reference-20250612` (Thread 1.4 reference release, `8a19434`)
- [x] Evaluate esp-rs/openthread crate → `docs/research/rs-matter-integration.md` (mirror its async `Radio` trait from HEAD, offer a source-compatible `OpenThread`-style facade)
- [x] Decide scope of BLE commissioning for Matter (BTP): in OpenTrust vs. left to rs-matter/platform BLE stack
  - Decision: leave Matter BLE/BTP to rs-matter (+ `trouble-host`/NimBLE via rs-matter-embassy); OpenTrust only tolerates radio arbitration (Thread/BLE coexistence in the radio driver). TCAT: transport-agnostic engine in `-meshcop`, optional thin BLE adapter crate later.
- [x] Evaluate rs-matter (and rs-matter-embassy) integration points: networking traits (`edge-nal` UDP), Thread network commissioning, SRP/DNS-SD, ICD/sleepy-device needs → `docs/research/rs-matter-integration.md` (`NetCtl`, `ThreadDiag`/`NetifDiag`, `Mdns` via SRP, `IcdNetParams`)
- [x] New workspace layout (`crates/`): `opentrust-core`, `-mac`, `-lowpan`, `-mle`, `-mesh`, `-meshcop`, `-coap`, `-net`, `-platform`, `-embassy` (async facade), `-matter` (rs-matter glue), `-sim`, `-cli`, `-ncp`
- [x] Toolchain: edition 2024, MSRV 1.85 (rs-matter needs 1.92 → raise for `opentrust-matter` when the dependency is added), `rust-toolchain.toml` pinned to 1.95, targets `thumbv7em-none-eabihf` (nRF52), `thumbv8m.main-none-eabihf` (nRF54), `riscv32imac-unknown-none-elf` (ESP32-C6/H2). No Xtensa: the original ESP32/S3 have no 802.15.4 radio
- [x] CI (`.gitlab-ci.yml`, remote is GitLab): fmt, clippy, `cargo test`, `no_std` check per embedded target (cargo aliases `check-nrf52`/`check-nrf54`/`check-esp32c6`), `cargo audit`
- [x] `defmt`/`log` feature-gated logging (`opentrust_core::{trace,debug,info,warn,error}!`)
- [x] Extract spec section index & constants table into `docs/spec-map.md` (spec section → module; 554 sections, 196 constants, TLV registries)
  - [ ] Resolve the spec inconsistencies listed in `docs/spec-map.md` §4 (e.g. §7.1.4 key halves → follow test vectors/OpenThread; done in `crypto::kdf::thread_keys`)
  - [ ] Per-module second pass for constants that live only in prose (ch. 4/5)

## Phase 1 – Foundations

- [x] Core types (`opentrust_core::types`): `ExtAddress`, `ShortAddress (RLOC16)`, `PanId`, `ExtPanId`, `NetworkKey`, `Pskc`, `MeshLocalPrefix`, `Channel`, `Ipv6Addr` helpers
- [x] Error type, result conventions, zero-copy byte reader/writer (`bytes`-like, no alloc)
- [x] Timer service (sans-IO, caller passes `now`): µs `Instant`/`Duration`, fixed-capacity `TimerQueue`, Trickle timer (RFC 6206 + OT plain mode)
  - [ ] Platform clock/alarm trait → with the async facade (Phase 2/10)
  - [ ] `Trickle::set_interval_max` (OT `SetIntervalMax`) when MPL/advertisements need it
- [x] Message buffer pool (fixed slots, headroom for prepends, intrusive priority queue, no `unsafe`) like OT `MessagePool`
- [x] Settings: OT-compatible `SettingsKey`s, `NetworkInfo`/`ParentInfo` codecs (OT byte layout); `opentrust_platform::SettingsStore` + `RamSettings`
  - [ ] `ChildInfo` and dataset codecs (with MLE / MeshCoP)
- [x] Crypto trait: AES-128-CCM*, AES-CMAC/HMAC-SHA256, KDF (Thread key derivation §7), PBKDF2-CMAC for PSKc, EC-JPAKE + DTLS 1.2 deps; software impls (RustCrypto) + HW-accelerated backends (nrf CryptoCell/ESP AES)
  - [x] `opentrust_core::crypto`: `CryptoBackend` trait, CCM* (M=0/4/8/16), MAC/MLE nonces, MAC/MLE/TREL keys, HKDF, TLS 1.2 PRF, KEK, PBKDF2-AES-CMAC-PRF-128/PSKc, `soft-crypto` backend; spec + OT unit-test vectors
  - [ ] HW backends (Phase 12), EC-JPAKE + DTLS 1.2 (Phase 5, see ADR 0001)
  - [ ] Cross-check TREL key, KEK and MLE-message vectors (self-generated) against `openthread-sys` (Phase 11)
  - [x] Secret key types are not `Copy`, zeroize on drop, constant-time `==`
- [x] Entropy: `opentrust_platform::Entropy` = `rand_core::CryptoRng` (0.10, same as rs-matter/esp-rs openthread)
- [x] Decide EC-JPAKE / DTLS 1.2 source (→ [ADR 0001](docs/decisions/0001-ecjpake-dtls.md), accepted: Rust EC-JPAKE on `p256` + minimal sans-IO DTLS 1.2, mbedTLS only as test oracle): no mainstream Rust crate implements the EC-JPAKE TLS cipher suite (draft-cragie-tls-ecjpake-01) → port from mbedTLS vs. own implementation on RustCrypto `p256`; check whether rs-matter's `Crypto` trait can be shared

## Phase 2 – IEEE 802.15.4 MAC (§3, 802.15.4-2015/2006)

- [ ] Frame parse/build: header IEs, payload IEs, security header, versions 2006/2015
- [ ] MAC security: frame counters, key ID mode 1/2, key sequence rotation (§7)
- [x] Radio trait (`opentrust_platform::radio`, mirrors esp-rs/openthread `Radio`; `TestRadio`; `SoftMacNeeds`) + `time::{Clock, Alarm, MockClock}`
- [ ] CSMA-CA, retries, ack handling (soft-ack fallback for radios without HW ack)
- [ ] Active scan / energy scan / discovery scan (MLE Discovery)
- [ ] Data polling (SED), indirect transmission queue (parent side), source match table
- [ ] CSL transmitter/receiver & enhanced ACK (Thread 1.2+), Link Metrics probing (§4.x 1.2)
- [ ] Unit tests against OT frame vectors (`tests/unit/test_mac_frame.cpp` vectors)

## Phase 3 – 6LoWPAN adaptation (§3.3–3.5, RFC 4944/6282)

- [ ] IPHC / NHC (UDP) compression & decompression with context IDs
- [ ] Mesh header, fragmentation header, reassembly with timeouts
- [ ] Mesh forwarding (mesh header) for FTD
- [ ] Port OT `test_lowpan.cpp` vectors as Rust tests

## Phase 4 – IPv6 / UDP / ICMPv6 core (§5)

- [ ] Own minimal IPv6 stack, modeled on OpenThread's `src/core/net` (which has its own IPv6/UDP/ICMPv6/MPL stack); `smoltcp` lacks Thread specifics (RLOC/ALOC, MPL, mesh-local scoping) and only re-evaluate if it saves real effort: addresses (link-local, ML-EID, RLOC, ALOC, GUA/SLAAC), multicast subscriptions, MPL (RFC 7731) for realm-local multicast
- [ ] UDP sockets API, ICMPv6 echo, errors
- [ ] Address resolution: Address Query/Notification/Error (`/a/aq`, `/a/an`, `/a/ae`), EID-to-RLOC cache (§5.x)
- [ ] DHCPv6 / SLAAC (as needed for BR prefixes), DUA (§5.x, 1.2)

## Phase 5 – CoAP / CoAPS

- [ ] CoAP (RFC 7252) no_std: messages, options, confirmable/retransmit, block-wise optional
- [ ] TMF resource dispatcher (port 61631)
- [ ] DTLS 1.2 + EC-JPAKE (CoAPS for commissioning)

## Phase 6 – MLE (§4)

- [ ] MLE message codec + all TLVs, MLE security (AES-CCM with key derivation)
- [ ] Attach: Parent Request/Response, Child ID Request/Response, parent selection (link quality, connectivity)
- [ ] Child Update Request/Response, keep-alive, SED/MED/SSED modes, supervision
- [ ] Link Request/Accept (router link establishment), Advertisement, link margin/quality
- [ ] Partition handling: leader data, partition ID/weight, merging (§5.16)
- [ ] Role state machine: Disabled → Detached → Child → Router → Leader
- [ ] Persist & restore network state (fast re-attach)

## Phase 7 – Mesh / routing (FTD) (§5)

- [ ] Router ID assignment (Leader `/a/as`, `/a/ar`), router ID sequence, router upgrade/downgrade thresholds
- [ ] Distance-vector routing table, route cost, Route TLV handling
- [ ] Child table & forwarding to sleepy children
- [ ] Network Data (§5.13–5.15): leader store, prefix/route/service/server TLVs, `/a/sd` registration, distribution & versioning
- [ ] Anycast locators, Service ALOCs
- [ ] Commissioning datasets (Active/Pending Operational Dataset, delay timer)

## Phase 8 – MeshCoP / Commissioning (§8)

- [ ] Dataset TLVs, Active/Pending dataset management (`/c/ag`, `/c/as`, `/c/pg`, `/c/ps`)
- [ ] Joiner (DTLS EC-JPAKE with PSKd, Joiner Router relay `/c/rx` `/c/tx`, Joiner Entrust)
- [ ] Joiner Router, Commissioner (native & on-mesh), Border Agent hooks
- [ ] Energy scan / PAN ID query / Announce begin (`/c/es`, `/c/pq`, `/c/ab`)
- [ ] Steering data bloom filter, Discovery Request/Response TLVs

## Phase 9 – Thread 1.2 / 1.3 / 1.4 features

- [ ] Domain Unicast Address & Backbone Router client support (1.2)
- [ ] Multicast Listener Registration (MLR) (1.2)
- [ ] Enhanced CSL, Link Metrics (initiator & subject)
- [ ] SRP client (RFC 9665) & DNS-SD client (1.3) — **pulled forward**: required by Matter for operational discovery (`_matter._tcp`); target M4
- [ ] TREL hooks (optional, 1.3)
- [ ] Thread 1.4 additions: ephemeral key / ePSKc Border Agent, TCAT (BLE commissioning) — scope review, mark optional
- [ ] Border Router role (feature `border-router`, `std`/Linux only initially): RA/RIO, OMR prefix, NAT64 hooks — likely defer

## Phase 10 – Public API & host interfaces

- [ ] Ergonomic Rust API (`Instance`, `Dataset`, `Role`, events), async facade (embassy-sync, executor-agnostic)
- [ ] rs-matter integration (`opentrust-matter`):
  - [ ] `edge-nal` UDP socket traits (bind/send/receive over IPv6) for Matter traffic
  - [ ] Thread Network Commissioning cluster backend: scan, add/update dataset, connect, status
  - [ ] SRP service registration + DNS-SD browse for Matter discovery
  - [ ] Thread Network Diagnostics cluster data (role, RLOC16, neighbors, counters)
  - [ ] ICD support: SED/SSED polling intervals controllable by Matter ICD manager
  - [ ] Example: rs-matter on-off light over Thread in sim, then on nRF52840/ESP32-C6
- [ ] OT-compatible CLI (`ot-cli` command subset) — required to drive OT test scripts
- [ ] Spinel/NCP (RCP host side & NCP device side) — optional, enables `ot-br-posix` interop

## Phase 11 – Simulation & testing (reuse OpenThread test framework)

- [ ] `opentrust-sim`: POSIX simulation platform compatible with OT's simulation protocol (UDP-based radio sim, `OT_SIMULATION`/`otns` event format) so Rust nodes and OT nodes share one virtual network
- [ ] Build `ot-cli-ftd`/`ot-cli-mtd`-compatible binaries from Rust (same CLI prompt/output) so OT `tests/scripts/thread-cert` Python tests can run against them
- [ ] `cargo test` harness (`tests/thread_cert.rs`, custom harness `harness = false`) that:
  - [ ] builds OT reference nodes from `openthread-sys/vendor/openthread` (simulation platform)
  - [ ] runs selected `thread-cert` cases (Cert_5_1_*, 5_2_*, 5_3_*, …, v1_2_*) with Rust nodes as DUT and OT nodes as peers
  - [ ] manages Python venv (`.venv` already present) via `uv`/pip for pktverify/pyshark deps
- [ ] Port OT C++ unit-test vectors (`tests/unit/*.cpp`: mac frame, lowpan, mle, crypto, dataset, network data, coap) into Rust `#[test]`s
- [ ] Differential tests: same input to `openthread-sys` (FFI) and Rust impl, compare outputs (codecs, crypto, KDF)
- [ ] OTNS (OpenThread Network Simulator) integration for large-topology/visual testing
- [ ] Fuzzing (`cargo fuzz`) for all parsers (MAC, 6LoWPAN, MLE TLVs, CoAP, MeshCoP TLVs)
- [ ] Track cert test pass-rate in `docs/test-status.md`

## Phase 12 – Embedded targets

- [ ] nRF52840: radio driver (embassy-nrf / nrf-radio), RTC timer, CryptoCell/ECB, flash settings
- [ ] nRF54L15/H20: radio driver, timers, CRACEN crypto
- [ ] ESP32-C6/H2 (802.15.4 capable; RISC-V): radio via `esp-ieee802154` (esp-hal), reuse esp-rs/openthread platform glue
- [ ] Example apps per board: MTD (SED) sensor, FTD router, CLI over UART/USB-CDC
- [ ] Footprint budgets (flash/RAM per role) and power measurements for SED/SSED
- [ ] Hardware-in-loop interop test with OT RCP/`ot-br-posix` border router

## Phase 13 – Certification readiness & docs

- [ ] Map every Thread 1.4.1 test-plan case to status (pass/fail/NA)
- [ ] Security review (key handling, frame counters, replay protection)
- [ ] API docs, architecture doc, porting guide for new platforms
- [ ] Release crates to crates.io

## Milestones

1. **M1 – Codecs**: MAC + 6LoWPAN + MLE TLVs + crypto, verified by OT vectors and differential tests
2. **M2 – MTD in sim**: Rust MED/SED attaches to OT leader in simulation; ping works
3. **M3 – FTD in sim**: Rust router/leader; mixed Rust/OT network passes core `thread-cert` 5.x cases
4. **M4 – Commissioning & Matter**: Joiner + Commissioner interop with OT; SRP client; rs-matter device reachable over a Rust Thread node in sim
5. **M5 – Hardware**: nRF52840 + ESP32-C6 nodes join an OT/OTBR network
6. **M6 – Thread 1.2–1.4 features** and certification test-plan coverage

## Open questions

- ~~Own IPv6 stack vs. `smoltcp`?~~ → own stack (see Phase 4)
- ~~Async vs. sans-IO?~~ → both: sans-IO core + first-class async facade for rs-matter
- ~~License~~ → Apache-2.0
- ~~BLE commissioning for Matter (BTP)~~ → left to rs-matter; TCAT engine in `-meshcop` (see Phase 0)
