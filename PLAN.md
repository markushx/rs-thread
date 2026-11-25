# rs-thread – Implementation Plan

Pure Rust (`no_std`, no alloc by default) implementation of the Thread 1.4.1 protocol.

**Approach:** clean re-implementation from the specification in idiomatic Rust — *not* a C++-to-Rust translation of OpenThread.
OpenThread serves as design reference (module boundaries, constants, timing), source of test vectors, and interop/differential-test peer.

**Integration target:** must work as the Thread transport for [rs-matter](https://github.com/project-chip/rs-matter) (Matter over Thread).

License: Apache-2.0.
Spec: `spec/Threadv1.4.1SpecificationFinal_5345_1.pdf` (chapter refs below as "§n").

Legend: `[ ]` todo · `[~]` in progress · `[x]` done · `[-]` not planned

## Guiding principles

- `#![no_std]`, `heapless`/fixed-capacity buffers; optional `alloc`/`std` features for host & sim.
- Sans-IO core: protocol state machines take frames/timers in, emit frames/timers out. No executor dependency in core (mirrors OpenThread's single-threaded tasklet/timer/callback model, which is also not async).
- First-class async facade on top (`rs-thread-embassy`): executor-agnostic `async` API using `embassy-sync` primitives, matching what rs-matter expects; this is the primary user-facing API.
- Platform abstraction via traits (radio, timer/clock, entropy, crypto, settings/flash).
- OpenThread is the reference: every feature gets a differential/interop test against an OpenThread node.
- Feature-gated device roles: `mtd` (MED/SED), `ftd` (REED/Router/Leader), `ssed`, `border-router`.

## Phase 0 – Repository groundwork

- [x] Relicense to Apache-2.0: replace `LICENSE`, update `license` fields in all `Cargo.toml`s
- [x] Decide fate of old code: `openthread-sys` moved to `tools/openthread-sys` (test/interop oracle, not a default workspace member), `openthread-rust` sample removed
  - [x] Fix `tools/openthread-sys/build.rs`: no `script/bootstrap`, cmake + ninja build into `OUT_DIR` (simulation platform, virtual time, `MinSizeRel`, one build tree), bindings regenerated; the reference nodes `ot-cli-ftd` (feature `mtd`: also `ot-cli-mtd`) are copied to `<target dir>/ot-sim/`; the source tree is `vendor/openthread` or `$OPENTHREAD_SRC`
- [x] Refresh OpenThread submodule to `thread-reference-20250612` (Thread 1.4 reference release, `8a19434`)
- [x] Evaluate esp-rs/openthread crate → `docs/research/rs-matter-integration.md` (mirror its async `Radio` trait from HEAD, offer a source-compatible `OpenThread`-style facade)
- [x] Decide scope of BLE commissioning for Matter (BTP): in rs-thread vs. left to rs-matter/platform BLE stack
  - Decision: leave Matter BLE/BTP to rs-matter (+ `trouble-host`/NimBLE via rs-matter-embassy); rs-thread only tolerates radio arbitration (Thread/BLE coexistence in the radio driver). TCAT: transport-agnostic engine in `-meshcop`, optional thin BLE adapter crate later.
- [x] Evaluate rs-matter (and rs-matter-embassy) integration points: networking traits (`edge-nal` UDP), Thread network commissioning, SRP/DNS-SD, ICD/sleepy-device needs → `docs/research/rs-matter-integration.md` (`NetCtl`, `ThreadDiag`/`NetifDiag`, `Mdns` via SRP, `IcdNetParams`)
- [x] New workspace layout (`crates/`): `rs-thread-core`, `-mac`, `-lowpan`, `-mle`, `-mesh`, `-meshcop`, `-coap`, `-net`, `-platform`, `-embassy` (async facade), `-matter` (rs-matter glue), `-sim`, `-cli`, `-ncp`
- [x] Toolchain: edition 2024, MSRV 1.85 (rs-matter needs 1.92 → raise for `rs-thread-matter` when the dependency is added), `rust-toolchain.toml` pinned to 1.95, targets `thumbv7em-none-eabihf` (nRF52), `thumbv8m.main-none-eabihf` (nRF54), `riscv32imac-unknown-none-elf` (ESP32-C6/H2). No Xtensa: the original ESP32/S3 have no 802.15.4 radio
- [x] CI (`.github/workflows/`, remote is GitHub): fmt, clippy, `cargo test`, `no_std` check per embedded target (cargo aliases `check-nrf52`/`check-nrf54`/`check-esp32c6`), `cargo audit`
- [x] `defmt`/`log` feature-gated logging (`rs_thread_core::{trace,debug,info,warn,error}!`)
- [x] Extract spec section index & constants table into `docs/spec-map.md` (spec section → module; 554 sections, 196 constants, TLV registries)
  - [ ] Resolve the spec inconsistencies listed in `docs/spec-map.md` §4 (e.g. §7.1.4 key halves → follow test vectors/OpenThread; done in `crypto::kdf::thread_keys`)
  - [ ] Per-module second pass for constants that live only in prose (ch. 4/5)

## Phase 1 – Foundations

- [x] Core types (`rs_thread_core::types`): `ExtAddress`, `ShortAddress (RLOC16)`, `PanId`, `ExtPanId`, `NetworkKey`, `Pskc`, `MeshLocalPrefix`, `Channel`, `Ipv6Addr` helpers
- [x] Error type, result conventions, zero-copy byte reader/writer (`bytes`-like, no alloc)
- [x] Timer service (sans-IO, caller passes `now`): µs `Instant`/`Duration`, fixed-capacity `TimerQueue`, Trickle timer (RFC 6206 + OT plain mode)
  - [x] Platform clock/alarm trait: `rs_thread_platform::time::{Clock, Alarm}`, embassy-time implementations in `rs-thread-embassy` / `rs-thread-nrf`
  - [ ] `Trickle::set_interval_max` (OT `SetIntervalMax`) when MPL/advertisements need it
- [x] Message buffer pool (fixed slots, headroom for prepends, intrusive priority queue, no `unsafe`) like OT `MessagePool`
- [x] Settings: OT-compatible `SettingsKey`s, `NetworkInfo`/`ParentInfo` codecs (OT byte layout); `rs_thread_platform::SettingsStore` + `RamSettings`
  - [ ] `ChildInfo` and dataset codecs (with MLE / MeshCoP)
- [x] Crypto trait: AES-128-CCM*, AES-CMAC/HMAC-SHA256, KDF (Thread key derivation §7), PBKDF2-CMAC for PSKc, EC-JPAKE + DTLS 1.2 deps; software impls (RustCrypto) + HW-accelerated backends (nrf CryptoCell/ESP AES)
  - [x] `rs_thread_core::crypto`: `CryptoBackend` trait, CCM* (M=0/4/8/16), MAC/MLE nonces, MAC/MLE/TREL keys, HKDF, TLS 1.2 PRF, KEK, PBKDF2-AES-CMAC-PRF-128/PSKc, `soft-crypto` backend; spec + OT unit-test vectors
  - [ ] HW backends (Phase 12)
  - [x] EC-JPAKE + DTLS 1.2 (Phase 5b, see ADR 0001)
  - [x] Cross-check TREL key, KEK and MLE-message vectors (self-generated) against `openthread-sys`: `crates/rs-thread-difftest/tests/crypto.rs` compares the TREL key (OT's HKDF), the KEK (SHA-256 of the DTLS key block; TLS 1.2 PRF against P_SHA256 composed of OT's HMAC), the Thread MLE / MAC keys (OT `KeyManager`), the MLE nonce and CCM* (OT `AesCcm`); the assembly of the MLE aux header and AAD is not compared with OT's `Mle` class (`docs/differential-tests.md`)
  - [x] Secret key types are not `Copy`, zeroize on drop, constant-time `==`
- [x] Entropy: `rs_thread_platform::Entropy` = `rand_core::CryptoRng` (0.10, same as rs-matter/esp-rs openthread)
- [x] Decide EC-JPAKE / DTLS 1.2 source (→ [ADR 0001](docs/decisions/0001-ecjpake-dtls.md), accepted: Rust EC-JPAKE on `p256` + minimal sans-IO DTLS 1.2, mbedTLS only as test oracle): no mainstream Rust crate implements the EC-JPAKE TLS cipher suite (draft-cragie-tls-ecjpake-01) → port from mbedTLS vs. own implementation on RustCrypto `p256`; check whether rs-matter's `Crypto` trait can be shared

## Phase 2 – IEEE 802.15.4 MAC (§3, 802.15.4-2015/2006)

- [x] Frame parse/build (`rs_thread_mac::frame`): header IEs, payload IEs, security header, versions 2003/2006/2015, imm/enh ACK, wake-up frames
- [x] MAC security (`rs_thread_mac::security`): `KeyManager` (prev/cur/next keys, key switch guard, rotation), key ID mode 1/2, frame counter + store-ahead, `LinkFrameCounters` replay check, enh-ACK security
- [x] Radio trait (`rs_thread_platform::radio`, mirrors esp-rs/openthread `Radio`; `TestRadio`; `SoftMacNeeds`) + `time::{Clock, Alarm, MockClock}`
- [x] Sans-IO MAC (`rs_thread_mac::mac`) + async `MacDriver`: CSMA-CA, retries, ack handling incl. software ACK / ACK timeout per `SoftMacNeeds`, rx filtering
- [x] Active scan / energy scan (radio-only); MLE Discovery scan → Phase 6
- [x] Data polling (SED), indirect transmission queue (parent side), source match table
- [x] CSL receiver (SSED) and transmitter (parent) + enhanced ACK with CSL IE (Thread 1.2+): sample windows (`ReceiveAt` / software sampling), phase math, CSL IE update + re-secure per attempt, per-child sync from CSL IEs, timed indirect tx with guard times
  - [x] CSL IE in MAC-built data polls (2015 poll frame with the CSL IE, no retransmission, 15 failures tolerated, retx period bounded by the CSL period, keep-alive timer reset by acknowledged CSL frames; the MLE bounds the poll period by the CSL timeout)
  - [x] CSL synchronized timeout, CSL Channel / Accuracy TLVs, child CSL parameters from MLE (`rs_thread_mle::csl`, `Child::csl_*`, Phase 9c)
  - [ ] CSL broadcast / wake-up frame (TL2 wake-up coordinator and end device, Thread 1.4): the wake-up frame builder / parser, Rendezvous Time / Connection IEs and the Wake-up Channel TLV exist; the wake-up transmit sequence (OT `WakeupTxScheduler`), the wake-up listen window and the rendezvous with the Parent Request still need to be built (Phase 9)
  - [x] Hardware-ACK radios: CSL IE in hardware enh-ACKs needs the schedule only (`set_csl` done; verified on the nRF52840 against OpenThread)
  - [ ] Hardware-ACK radios: link-metrics IE needs a trait method (`configure_enh_ack_probing`)
- [x] Enh-ACK based Link Metrics probing, MAC part: per-initiator metric config, Thread vendor IE in enh-ACKs, initiator-side decode (`Event::EnhAckLinkMetrics`)
  - [x] MLE Link Metrics Management / Report TLVs, forward tracking series, single probe (`rs_thread_mle::link_metrics`; the MAC-to-MLE calls are listed in Phase 6)
- [x] Unit tests against OT frame vectors (`tests/unit/test_mac_frame.cpp` vectors)
- [x] Wire `KeyManager` into the MAC/driver (push `mac_keys()`/frame counter to radios with HW tx security, feed back used counters), end-to-end secured data frame + enh-ACK + key sequence switch tests
- [x] Const-generic capacities for MAC queues (`Mac<S, G, TXQ, IND, EVQ, POLLQ, NBQ, CSLQ>`, defaults 4/8/8/4/32/8)
  - [ ] Capacities of the enh-ACK probing tables (fixed 8)
- [x] Verify CSL timing against OpenThread on a simulated radio medium: `rs_thread_sim::vt` has a virtual radio clock; the MAC samples the CSL windows and builds the enhanced ACKs with the CSL IE as OpenThread's simulation radio does; mixed tests `crates/rs-thread-sim/tests/csl.rs` (rs-thread SSED under an OpenThread parent, OpenThread SSED under an rs-thread parent, both ends rs-thread: attach, CSL synchronized, pings both ways inside one CSL period without data polls, fragmented pings, CSL channel change, CSL off) and the cert cases `v1_2_LowPower_5_3_01_SSEDAttachment` (all runs pass) and `v1_2_test_csl_transmission` (see `docs/test-status.md`)
  - [ ] The simulated radio has no timed receive / transmit (`RECEIVE_TIMING`, `TRANSMIT_TIMING`): that path of the MAC (`ReceiveAt`, `SetCsl`, radio-timed tx) is covered by unit tests only

## Phase 3 – 6LoWPAN adaptation (§3.3–3.5, RFC 4944/6282)

- [x] IPHC / NHC (UDP) compression & decompression with context IDs (`rs_thread_lowpan::iphc`: stateless/stateful unicast and multicast, TF/NH/HLIM, NHC UDP/Hop-by-Hop/IP-in-IP, `ContextProvider` trait + `ContextTable`, ECN helpers)
  - [x] Network Data implementing `ContextProvider` (Phase 7b, `rs_thread_mesh::netdata::consumers::NetDataContexts`; context 0 = mesh-local prefix is built in, `ContextTable::set_mesh_local` stays for other users)
  - [ ] Compression of Destination Options / Routing / Fragment extension headers (OT only compresses Hop-by-Hop; others are sent inline)
- [x] Mesh header, fragmentation header, reassembly with timeouts (`mesh`, `frag`, `reassembly`: `MeshHeader`, `FragmentHeader`, sans-IO `Fragmenter`, fixed-capacity `Reassembler`, 2 s timeout like OT)
  - [ ] Out-of-order reassembly (OT drops out-of-order fragments; so do we)
  - [x] Sleepy-device reassembly rules (clear list on new secure first fragment / mismatch): `Reassembler::set_sleepy`, set by the forwarder from the device mode on every fragment; a sleepy device keeps one datagram, a secure first fragment or an unmatched secure next fragment drops the rest like OT `HandleFragment`
  - [x] Reassembling and queueing the Tx side (`Fragmenter` frames -> MAC) is done by the mesh forwarder and the `Instance` (frames wait in a bounded queue for room in the MAC transmit queue)
  - [ ] MLE messages that need fragmentation must be link-secured (`MeshForwarder` retry with security) and delay-aware queue management (Phase 6)
- [x] Mesh forwarding (mesh header) for FTD (`forward`: `classify`/`parse_frame`, `handle_mesh` deliver/forward/drop with `LocalRlocs` + `NextHops` traits, hops-left handling, 2-hop loop detection)
  - [x] Routing table / next-hop provider, ICMPv6 destination-unreachable decisions, EID-RLOC cache update from forwarded frames (Phase 7a: `rs_thread_mesh::forwarder`, which drives `forward`'s rules on `Mle::next_hop_and_path_cost`)
  - [ ] Forwarding queue with message priorities, aging, delay-aware queue management and fragment priority tracking (the forwarder routes and transmits a datagram at once)
- [x] Port OT `test_lowpan.cpp` vectors as Rust tests (all 58 IPHC vectors + `TestLowpanMeshHeader` + `TestLowpanFragmentHeader`), plus randomized round-trips and no-panic tests
  - [x] Differential tests against OpenThread's `Lowpan` via `openthread-sys`: `crates/rs-thread-difftest/tests/lowpan.rs` (random datagrams, contexts and link-layer addresses: identical compressed bytes, same decompression; OT quirks classified, one rs-thread bug fixed; `docs/differential-tests.md`)

## Phase 4 – IPv6 / UDP / ICMPv6 core (§5)

- [x] Own minimal IPv6 stack in `rs-thread-net`, modeled on OpenThread's `src/core/net` (`smoltcp` lacks Thread specifics: RLOC/ALOC, MPL, mesh-local scoping): fixed + extension headers (Hop-by-Hop/MPL/padding, Fragment, Routing/Destination skip), pseudo-header checksum, ICMPv6 builders (`header`, `checksum`, `icmp6`)
- [x] Addresses (`addr`, `netif`, `slaac`): link-local, ML-EID, RLOC, ALOCs, GUA/OMR via SLAAC (RFC 7217 IIDs as OT, deprecation timer), unicast/multicast tables with fixed/internal/external subscriptions, Thread all-nodes/routers/MPL-forwarders and the mesh-local-derived all-Thread-nodes groups, RFC 6724-subset source selection
- [x] Sans-IO IPv6 core (`ip6::Ip6`): receive path (validate, receive/forward-to-Thread/forward-to-host decision with `Ip6Env` hooks, extension headers, IPv6-in-IPv6 tunnel, checksum verification, hop limit, ICMPv6/TMF forward filters), send path (source selection, MPL option insertion, tunnelling of larger-scope multicast, loopback), ICMPv6 echo responder and rate-limited error builder
- [x] MPL (RFC 7731) as OpenThread implements it (`mpl`): seed set, buffered retransmissions with jittered deadlines, duplicate suppression, seed ID from RLOC16
- [x] UDP sockets (`udp`): fixed-capacity socket table, bind/connect/ephemeral ports 49152-65535 (OT rules), bounded receive queues with per-packet metadata, internal receiver hooks for MLE (19788) and TMF (61631); mapping to the Phase 10 `edge-nal` facade documented in the module
- [x] Address resolution data structures (`resolver`): EID-to-RLOC cache with OT's cached/snooped/query/query-retry states, timeouts, exponential retry delay and ramp-down, eviction order, snooping, notification and duplicate-address decisions, address-query/-error decision helpers
  - [x] TMF messages `/a/aq`, `/a/an`, `/a/ae` (CoAP encoding, TLVs, sending, ACKs) wired to `resolver::ResolverEvent`, router-side child lookup on the MLE child table, duplicate address handling (Phase 7a: `rs_thread_mesh::address`)
    - [x] DUA duplicate notification in `/a/ae` (`address::AddressErrorOutcome::DuplicateDomainUnicast`, Phase 9)
    - [ ] Backbone Query extension of `/a/aq` / `/b/bq` (belongs to the Backbone Router server role, Phase 9)
  - [x] Mesh forwarder glue: hold datagrams while an EID resolves, `HandleResolved`, ICMPv6 destination-unreachable on no route/resolution failure, snooping from forwarded frames (Phase 7a: `rs_thread_mesh::forwarder`)
  - [x] Network Data providers for `Ip6Env` (`route_lookup`, `is_on_mesh`) and for SLAAC (`OnMeshPrefix` list) (Phase 7b, `rs_thread_mesh::netdata::lookup::NetDataIp6Env`, `consumers::slaac_prefixes`)
  - [x] Persisted SLAAC IID secret key in settings (`Instance::thread_start` loads / stores `SettingsKey::SlaacIidSecretKey`)
- [x] DHCPv6 address allocation (OT `Dhcp6Client`/`Dhcp6Server`: Solicit / Rapid Commit / Reply, DHCP agent ALOCs; `rs-thread-instance` `dhcp6`; needed by thread-cert 5.3.8 / 5.3.9)
- [x] Domain Unicast Address client (Thread 1.2, `/n/dr`, `/n/dn`, duplicate DUA handling in `/a/ae`: `rs_thread_mesh::dua`); `/b/bq` / `/b/bb` belong to the Backbone Router server role (Phase 9)
- [x] Multicast Listener Registration (MLR, `/n/mr`) for subscribed multicast groups (`rs_thread_mesh::mlr`, Phase 9)
- [x] IPv6 fragmentation/reassembly above the 6LoWPAN layer (OT `OPENTHREAD_CONFIG_IP6_FRAGMENTATION_ENABLE`; feature `ip6-fragmentation` of `rs-thread-net` / `rs-thread-instance` / `rs-thread-cli`, on in the simulator nodes, off in the firmware; `test_ipv6_fragmentation` passes)
- [ ] Host (border router) interface: `RemoveMplOption` before passing to host, host-origin multicast policy (Phase 9, border routing)

## Phase 5 – CoAP / CoAPS

- [x] Generic TLV utilities (`rs_thread_core::tlv`: normal/extended TLVs, iterator, find, typed read/write; OT `test_tlv.cpp` ported)
- [x] CoAP (RFC 7252) no_std: message codec (`rs_thread_coap::message`), sans-IO endpoint (`endpoint`): confirmable retransmission, separate responses, RST/empty ACK, multicast NON, resource table, duplicate detection + response cache; differential tests against `coap-lite`
  - [ ] Block-wise transfer (RFC 7959) and Observe: off in OT's default config; only the `BlockOption` codec exists
- [x] TMF agent on UDP 61631 (`rs_thread_coap::tmf`): URI list, DSCP/priority mapping, `IsTmfMessage` filtering, handler dispatcher, `UdpSockets` receiver registration
  - [ ] Registering more TMF resources than the agent's capacity must return an error (today `register_uris` / `set_tmf_extension` in `rs-thread-instance` ignore the failure, and the extra URIs are silently not served; found when the Network Diagnostics URIs pushed the agent past 16 resources)
  - [x] `/a/aq`, `/a/an`, `/a/ae` wired to `resolver::ResolverEvent` and `/a/as`, `/a/ar` handlers (Phase 7a, `rs-thread-mesh`)
  - [x] MeshCoP and Network Data handlers (`/a/sd`, `/c/*`, `/n/*`) wired in `rs-thread-instance/src/tmf.rs`
- [x] Phase 5b: DTLS 1.2 + EC-JPAKE (CoAPS for commissioning, ADR 0001): `rs_thread_core::crypto::ecjpake` (feature `ecjpake`, RustCrypto `p256`, all mbedTLS self-test vectors), crate `rs-thread-dtls` (sans-IO DTLS 1.2, `TLS_ECJPAKE_WITH_AES_128_CCM_8` only, client + server, cookies, retransmission, fragmentation, KEK) and `rs_thread_dtls::coaps::Coaps` behind `rs_thread_coap::endpoint::SecureTransport`; manually interop-tested against mbedTLS 3.6.0 `ssl_server2`/`ssl_client2`
  - [ ] Automated differential/interop handshakes against `openthread-sys` / mbedTLS (Joiner and Commissioner, both roles, lossy links) (Phase 11)
  - [ ] Hardware P-256 backends for the `ecjpake::P256` trait (CryptoCell, CRACEN) and an rs-matter `EcPoint`/`EcScalar` adapter (Phase 12; ESP ECC in Phase 17)
  - [ ] Fuzz the record/handshake parsers and the EC-JPAKE readers (Phase 11)
  - [ ] Security review of the EC-JPAKE/DTLS code before M4 (ADR 0001); include the commissioning decisions listed under Phase 8b
  - [x] Wire into MeshCoP Joiner / Commissioner / Border Agent (relay, connection-attempt limits, guard times) (Phase 8b; the roles own `rs_thread_dtls::Session` directly via `rs_thread_meshcop::secure`)
    - [x] ePSKc (Thread 1.4 ephemeral PSKc on the Border Agent) (Phase 9: `epskc`, second Border Agent listener)

## Phase 6 – MLE (§4)

- [x] MLE message codec + all TLVs, MLE security (AES-CCM with key derivation) (Phase 6a, `rs-thread-mle`: `tlv` typed parse/build of every Thread 1.4.1 MLE TLV, `message` commands + builder, `security` secure/unsecure + MLE frame counter store-ahead, vectors from the Phase 1 crypto reference, tamper/truncation tests)
- [x] Neighbor / child / router data model (`neighbor`: states, filters, `Child`/`Router`/`Parent`, `ChildTable<N>`, `RouterTable<N>`, `MleReplay`, `ChildInfo` settings), link quality (`link_quality`: RSS averager, margin to quality with hysteresis, costs; `test_link_quality.cpp` ported)
- [x] MLE UDP glue (`endpoint`: port 19788 receiver, hop limit 255 + addressing rules, `MleRx::parse`, `MleHandler` dispatch by command, `send` through the TMF `UdpSink`)
  - [x] Phase 6b: sans-IO `Mle<C>` core with the `MleEnv` context trait (keys, MAC/netif, tx, settings, Network Data hooks; `env`), child-side attach (`attach`: Parent Request phases and OT backoff, Parent Response collection, `IsBetterParent`, Child ID Request/Response, key sequence adoption), child role (`child`, `child_rx`: Child Update, keep-alive, data poll period from the timeout, supervision check, 4-attempt parent loss and re-attach, Data Request/Response, leader-data versioning), parent side behind feature `ftd` (default on; `parent`: Parent Request/Response with jitter, Child ID exchange with child RLOC16 allocation, address registration, Child Update, Data Request, child timeouts, supervision ticks, indirect hooks for SEDs, entered through `enter_router_role` for Phase 6c), persistence and fast re-attach (`persist`: `NetworkInfo`/`ParentInfo`/`ChildInfo`, store-ahead counters, restore via Child Update Request, restored children); two-core end-to-end test over byte buffers (`e2e_tests`)
    - [x] Network Data / dataset content (passed as bytes through `MleEnv`; Network Data in Phase 7b, Active / Pending Dataset in Phase 8a: `rs_thread_meshcop::manager::Datasets` behind `MleEnv::{active,pending}_timestamp`, `{active,pending}_dataset`, `dataset_received`, which now take `now`)
    - [x] Announce send / receive (Phase 8a, `rs_thread_mle::discovery`: `Mle::send_announce`, OT `HandleAnnounce` decisions, `MleEvent::AnnounceFromNewerNetwork`)
    - [x] Announce attach (`rs_thread_mle::discovery`: newer-network Announce -> switch channel / PAN ID after `ANNOUNCE_PROCESS_TIMEOUT` via `MleEnv::set_pan_channel_and_id`, attach there, inform the old channel on success, restore the old channel / PAN ID on failure) and Orphan Announces on all channels after unanswered Parent Requests (`AttachState::Announce`)
    - [x] Reattach with the stored Active / Pending Dataset (`ReattachState`, `MleEnv::{restore_dataset, apply_pending_configuration, clear_pending_dataset}`), periodic `AnnounceSender` (`announce_sender`: Trickle 688 s, channel cycle, equal-timestamp suppression, unicast Announce response)
    - [x] Graceful detach (`Mle::detach_gracefully`: zero-timeout Child Update / Address Release, 1 s wait, `MleEvent::DetachedGracefully`)
    - [x] CSL parent metric in parent selection (`rs_thread_mle::csl::csl_parent_metric`, CSL Clock Accuracy TLV from Parent Response, Phase 9c)
  - [x] Phase 6c (feature `ftd`): role state machine (`router`: `become_leader`, REED upgrade decision with `ROUTER_SELECTION_JITTER`, router downgrade, `ID_SEQUENCE_PERIOD`, router ID bookkeeping with `ID_REUSE_DELAY`, leader-side `handle_address_solicit` / `handle_address_release`, Connectivity / Route64 content from the live router table, path cost and next hop, `RouterConfig`, `DeviceProperties` leader weight with the `test_mle.cpp` vectors), router links (`router_link`: Link Request / Accept / Accept And Request, challenge / response, frame counters, delayed Link Accept, Link Accept timeout, `MAX_NEIGHBOR_AGE` re-request and removal, `UpdateRoutes` cost bookkeeping, router role restorer after a reset), Advertisements (`advert`: `rs_thread_core::trickle` with OT parameters, Route64 content, router discovery, former-child takeover, FTD child router links, downgrade conditions, parent Advertisement handling), partitions (ComparePartitions, better-partition attach, FTD Parent Response rules per attach mode, leader loss after `NETWORK_ID_TIMEOUT`, new partition as leader, previous-partition avoidance, REED answering Parent Requests / Child ID Requests); tests with a multi-node simulator (`sim`, `router_tests`, `router_link_tests`, `advert_tests`, `partition_tests`, `mesh_tests`)
    - [x] Phase 7a hooks: TMF `/a/as` / `/a/ar` client and server around `MleEnv::request_router_id` / `release_router_id`, `Mle::address_solicit_reply`, `Mle::handle_address_solicit`, `Mle::handle_address_release` (`rs_thread_mesh::router_id`); mesh forwarding from `Mle::next_hop_and_path_cost`; `Mle::resolve_routing_loop`; indirect hooks for sleepy children
    - [x] Network Data hooks (Phase 7b): leader reset on `MleEvent::LeaderStarted` (`netdata::leader::Leader::start`), version bumps through `Mle::set_leader_data` (`Leader::publish`, `Mle::network_data_updated`), Network Data bytes served through `MleEnv::network_data` / stored from `set_network_data`, stale Network Data entries on `MleEvent::RouterTableChanged` (`Leader::remove_stale_router_ids`)
    - [x] Hooks: alternate RLOC16 after REED -> router (`MleEnv::set_alternate_short_address`), `Mle::remove_child_that_moved`, `Mle::set_device_mode` FTD <-> MTD re-attach, address cache reactions to MLE events (`rs_thread_mesh::address::handle_mle_event`)
    - [x] `Mle::remove_child_that_moved` (called by the `Instance` for mesh header frames that end at this router; frames it only forwards are not examined, see the differences file) and `handle_mle_event` (the `Instance` consumes the MLE events)
    - [x] Border Router router role upgrade (`BorderRouterRequest` from the notifier, leader side threshold of 2 router-role Border Routers; `test_br_upgrade_router_role` passes) and the Security Policy part of `is_router_eligible` (`Mle::set_routing_policy`)
    - [ ] Time Sync TLVs in Link Request / Accept / Advertisement
  - [x] Link Metrics Management / Report sub-TLV codecs, Forward Tracking Series, Enhanced-ACK configuration, Link Probe, Initiator and Subject (`rs_thread_mle::link_metrics`, `link_metrics_roles`)
    - [x] MAC glue: `Mle::aggregate_link_metrics` for received secured data frames and data requests (`Event::DataPollReceived` carries LQI / RSSI), `MleEnv::configure_enh_ack_probing` (subject) and `MleEnv::track_enh_ack_probing` (initiator) onto the MAC's per-neighbor tables, frames to a probed neighbor use Frame Version 2015
    - [ ] Aggregate the ACKs of our own frames (`MacAck` series flag; the MAC does not report an ACK's LQI)
  - [x] MLE delay queue and retransmission as OT: Link Request / Accept / Advertisement / Data Request delays, multicast Data Response jitter, aggregated Child Update Request of MTD children (`Mle::schedule_child_update_request`), Child Update / Data Request retries
    - [x] Delayed Child Update Request triggers from the device glue (address changes of an MTD child call `schedule_child_update_request`; full-stack test)
  - [x] Address Registration context resolution (Phase 7b: `netdata::consumers::context_prefix64` / `context_id_for` back `MleEnv::lowpan_context` / `lowpan_context_for`)
  - [x] MLR state in `Child` (`Child::multicast_listeners`, `MlrState`; Phase 9)
- [x] Attach: Parent Request/Response, Child ID Request/Response, parent selection (link quality, connectivity) (6b)
- [x] Child Update Request/Response, keep-alive, SED/MED modes, supervision (6b); SSED / CSL parameters (CSL Channel, CSL Synchronized Timeout, CSL Clock Accuracy; `MleConfig::{csl_period, csl_channel, csl_timeout_secs}`, `MleEnv::{set_csl, set_csl_parent_accuracy}`) in Phase 9c
- [x] Link Request/Accept (router link establishment), Advertisement, link margin/quality (6c)
- [x] Partition handling: leader data, partition ID/weight, merging (§5.16) (6c)
- [x] Role state machine: Disabled → Detached → Child → Router → Leader (6c; router IDs come from the Phase 7 TMF hook)
- [x] Persist & restore network state (fast re-attach) (6b: child and children; 6c: router / leader restore through the router role restorer)

## Phase 7 – Mesh / routing (FTD) (§5)

- [x] Router ID assignment over TMF (Phase 7a, `rs_thread_mesh::router_id`: Leader `/a/as`, `/a/ar` CoAP handlers, `RouterIdOutbox` client, status codes and failure handling as OT; the allocation itself is in `rs-thread-mle`, Phase 6c); Thread network-layer TLV codec `rs_thread_mesh::tlv`
- [x] Mesh forwarding on the routing table (Phase 7a, `rs_thread_mesh::forwarder`: `MeshForwarder` route lookup incl. child / on-link / Network Data hooks, mesh header insertion, forwarding with hops left and 2-hop loop detection, held datagrams and `handle_resolved`, destination unreachable decisions, snooping; address resolution TMF in `rs_thread_mesh::address`)
  - [x] Routing through Network Data (Phase 7b): `netdata::lookup::Lookup` implements the `NetworkData` trait (external routes by longest prefix / preference / path cost, default route, on-mesh, anycast lookup)
  - [x] Sleepy child -> rx-on mode change converts queued indirect messages to direct (`MeshForwarder::child_became_rx_on`)
  - [x] `Mle::child_message_sent` is called by the `Instance` after every forwarder call
  - [x] CSL transmitter for sleepy children (`IndirectQueue::flush_csl`, `MeshForwarder::csl_flush`, `TxFrame::csl`; the MAC does the window timing and keeps the data poll as fallback), multi-radio selection hook (`RadioLink`, `trel::RadioSelector`, feature `trel`) (Phase 9c)
  - [ ] CSMA collision-avoidance delay of forwarded frames
- [x] Child table & forwarding to sleepy children (Phase 7a, `rs_thread_mesh::indirect`: per-child queue, Frame Pending / source match bookkeeping, fragments per data poll, supervision messages, purge on child removal; the child table itself is `rs-thread-mle`)
- [x] Network Data (§5.13–5.15, Phase 7b, `rs_thread_mesh::netdata`): TLV codec with typed iterators and the stable copy (`tlv`, `NetworkData<N>`; vectors of `test_network_data.cpp`), leader store (`leader`: `/a/sd` registration with validation and in-place merge, context ID allocation with 5 min reuse delay, service IDs, stale router / child entry removal, version and stable version), `/a/sd` server and client (`server_data`), local data and the OT notifier timing (`local`, `notifier`), consumers (`lookup`, `consumers`), distribution through MLE (`Leader::publish` + `Mle::network_data_updated`; full and stable data from `MleEnv::network_data`); multi-node tests in `netdata_sim_tests`
  - [x] Publisher is part of the mesh simulator (`MeshSim` polls `TmfNode::publisher`); tests: five publishers settle at three entries and a replacement takes over (`netdata_sim_tests`)
  - [x] Network Data Publisher (`netdata::publisher`: on-mesh prefix, external route, DNS/SRP anycast / unicast entries) and the `kBorderRouterRequest` decision in the notifier (`schedule_router_upgrade` / `router_upgrade_tick`)
  - [x] Backbone Router service and Domain Prefix entries are read by `netdata::backbone` (Primary BBR selection, BBR Dataset, Domain Prefix events; client side, Phase 9)
  - [ ] Consume the router upgrade flag in the MLE (`is_router_eligible` Border Router rule), DNS/SRP query helpers (client side done in `rs-thread-dns`), DHCPv6 / ND agent ALOC subscription, Publisher driven by the Border Routing Manager (requester quotas)
- [x] Anycast locators, Service ALOCs (Phase 7b: `netdata::aloc` (leader, service and commissioner ALOC set maintenance), `netdata::anycast` (`/a/yl`), `lookup::anycast_lookup` for leader / service / commissioner / DHCP / ND ALOCs)
- [x] Commissioning datasets (Phase 8a: Active / Pending Operational Dataset, delay timer in `rs_thread_meshcop::{dataset, manager, mgmt}`; the Commissioning Data TLV of Network Data is written by `Leader::set_commissioning_data` and `rs_thread_meshcop::leader`)

## Phase 8 – MeshCoP / Commissioning (§8)

Phase 8a (crate `rs-thread-meshcop`, leader / router code behind feature `ftd`):

- [x] MeshCoP TLV codec (`tlv`: all section 8.10 TLVs, Security Policy 1.2+ layout, Channel Mask page 0, State, Discovery Request / Response), Timestamp ordering (`timestamp`; `rs_thread_mle::tlv::Timestamp::compare`), Steering Data bloom filter, Joiner ID, Joiner Discerner (`steering`; vectors of `test_meshcop.cpp`)
- [x] Operational Dataset type (`dataset`: fixed 254 byte TLV buffer, validation, typed setters; vectors of `test_dataset.cpp`)
- [x] Active / Pending dataset management (`manager::Datasets`: network and local timestamps, persistence hooks `DatasetEnv::{store, load, delete}`, Pending delay timer -> Active, timestamp rules on receipt through MLE, MGMT_SET retry toward the leader) and `/c/ag` `/c/pg` `/c/as` `/c/ps` `/c/ar` (`mgmt`: leader accept / reject rules, partial updates from the commissioner, Active updates that change connectivity become Pending, `/c/dc` notification, clients)
- [x] Security Policy feeds router eligibility (`rs_thread_mle::RoutingPolicy`, `Mle::set_routing_policy`)
- [x] Leader commissioner session (`leader`, formerly `commissioner`: `/c/lp` petition, `/c/la` keep-alive, 50 s timeout, resign, `/c/cs` Commissioner Set, `/c/cg` Commissioner Get, Commissioning Data in Network Data)
- [x] Discovery (`rs_thread_mle::discovery` transport, `rs_thread_meshcop::discovery` content, Steering Data filter, active scanner state machine), MLE Announce send / receive
- [x] Energy Scan, PAN ID Query, Announce Begin servers and commissioner-side requests (`scan`: `/c/es` `/c/er` `/c/pq` `/c/pc` `/c/ab`)
- [x] Multi-node tests (`net_sim`, `sim_tests`, `sim_scan_tests` over the MLE simulator with a TMF agent, dataset managers and commissioner state per node)
- [x] Dataset Updater (`rs_thread_meshcop::updater`) and persistence of the Pending delay across resets (checkpoint every 60 s)
- [x] `MGMT_COMMISSIONER_GET` by a commissioner client for the Commissioner Dataset (Phase 8b: `Commissioner::send_commissioner_get`, `MgmtResponse::CommissionerGet`)
- [x] Announce attach state and Orphan Announces (see Phase 6b)
- [x] Reattach with the stored Active / Pending Dataset, periodic Announce sender (see Phase 6b; on the nRF52840 light the stored dataset and network info restore the role after reset, also against a border router whose dataset changed without a newer timestamp)

Phase 8b (security part; features `ftd`, `commissioner`, `border-agent`, all default; a joiner-only device uses `default-features = false`):

- [x] Joiner (`joiner`, `pskd`): PSKd validation and secret handling, filtered discovery with OT candidate ranking, DTLS EC-JPAKE with the PSKd over the Joiner UDP port (unsecured link), JOIN_FIN with vendor TLVs / Provisioning URL, Joiner Entrust accepted only under key ID mode 0 (KEK), dataset saved, retries over the candidates, timeouts, events
- [x] Joiner Router (`joiner_router`, feature `ftd`): Joiner UDP port from the Commissioning Data, relay `/c/rx` `/c/tx`, delayed Joiner Entrust under the KEK (dedicated CoAP endpoint, one in flight), answer handling; KEK derivation is in `rs-thread-dtls` (`Session::kek`)
- [x] MAC key ID mode 0 (`rs_thread_mac::security::KeyManager::set_kek`)
- [x] Commissioner (`commissioner`): petition / keep-alive / resign, session ID, Commissioner ALOC, Joiner list (any / EUI-64 / discerner, PSKd, expiry), Steering Data and `/c/cs`, `/c/rx` -> DTLS server per Joiner with that Joiner's PSKd, JOIN_FIN, `/c/tx` with the KEK, session timeout, Joiner removal, MGMT_COMMISSIONER_GET / SET, generic management requests; on-mesh `MeshTransport`
- [x] Border Agent (`border_agent`): DTLS server keyed with the PSKc, COMM_PET / COMM_KA forwarding, local `/c/cg` `/c/ag` `/c/pg` (`kIgnoreSecurityPolicyFlags`), `/c/tx`, `/c/rx`, UDP proxy `/c/ut` `/c/ur`, Border Agent ID, native commissioner flag in Discovery Responses (`discovery::build_response_with_border_agent`), keep-alive timeout, guard time, connection-attempt limit; external Commissioner client (`BorderAgentClient`, `ExternalTransport`)
- [x] Tests: unit tests per role (real Joiner against Commissioner / Border Agent through relay TLVs), end-to-end in the meshcop simulator (`net_sim_commissioning`, `commissioning_sim_tests`)
- [x] ePSKc on the Border Agent (Phase 9): separate listener, single use, timeout, attempt limit, `_meshcop-e._udp` hook
- [ ] DNS-SD `_meshcop._udp` advertisement and state bitmap, several concurrent Border Agent sessions, Border Agent counters
- [x] Wire the roles into a full stack (`rs-thread-instance`): the `Instance` owns the Joiner, Joiner Router, leader commissioner session, Commissioner and Border Agent (`InstanceCrypto` with the EC-JPAKE curve type), per-frame link security classes (`LinkSecurity`: none, mode 1, KEK / mode 0, mode 2) in the forwarder and 6LoWPAN reassembly, the Joiner Entrust in key ID mode 0, KEK frames routed only to `handle_kek_datagram`, the Joiner UDP port relay, public API (`joiner_*`, `commissioner_*`, `border_agent_*`, ePSKc) and full-stack tests over the real MAC (`rs-thread-sim/tests/commissioning.rs`)
- [x] ML-EID of a joined node: not a dataset hand-over bug (the Joiner, like OT, saves only network key, channel and PAN ID from the Joiner Entrust; prefix, ext PAN ID, name and timestamp come from the parent in the Child ID Response, and the joined node's Active Dataset matches the leader's). A router-capable child is not resolvable by ML-EID (OT address query skips full-function children) and its RLOC changes on the router upgrade; once a router with converged routes, address queries resolve in both directions (`commissioning.rs` asserts this)
- [ ] Border Agent UDP proxy receive (`handle_proxy_rx`) for datagrams to the Commissioner ALOC, Joiner Router events and `/c/dc` to an external Commissioner in the `Instance`; DNS-SD service publication hook
- [x] Interop of Joiner / Commissioner against OpenThread in simulation (`rs-thread-sim/tests/commissioning_mixed.rs`, Cert 8.x / 9.2 pass); hardware open (OTBR commissioner on macOS, see Phase 12)

Security-relevant decisions for the review before M4:

- PSKd (`JoinerPskd`) and PSKc / KEK / network key (`rs_thread_core::types` secret types) are wiped on drop or replacement, compared in constant time, redacted in `Debug` / `defmt`, and never logged (the commissioning modules log nothing; OT logs the PSKd).
- `Dataset` wipes its TLV buffer on drop and `clear`; temporary buffers that held the Network Key, PSKc or KEK (Joiner Entrust payload, Relay Transmit with KEK, Border Agent get answers) are zeroized after use.
- The Joiner accepts a Joiner Entrust only when the caller reports key ID mode 0 under the KEK of its own DTLS session (`LinkSecurity::Kek`) and only in the Entrust state; network-key or unsecured frames never reach it. The KEK is discarded when the Joiner finishes and by the Joiner Router after the answer / timeout (single use, Thread 7.2.1.1).
- The Commissioner attaches the KEK only to the Relay Transmit of an accepting JOIN_FIN.rsp (OT also for a rejection), so a rejected Joiner never receives the Network Key.
- The Joiner Entrust content is the OT set (Network Key, Mesh-Local Prefix, Extended PAN ID, Network Name, Active Timestamp, Channel Mask, PSKc, Security Policy, Key Sequence); the KEK in `/c/tx` and the Joiner Entrust travel under the network key / KEK respectively, never in the clear.
- The Joiner Router relays only link-local sources; one Joiner Entrust is in flight so the MAC never swaps the KEK while an answer is pending.
- Commissioner: one Joiner DTLS session at a time, bound to the Joiner IID (others get `Busy`), PSKd chosen by OT's best-match rule, 30 s session timeout; confirmable Relay Receive is dropped.
- Border Agent: one session; sessions keyed with the PSKc; 2 s guard time after every session end; optional connection-attempt limit; keep-alive timeout 50 s; Relay Receive / UDP proxy only for a petitioned (active) Commissioner, proxied UDP always from its ALOC; local Active / Pending gets include the Network Key for the PSKc-authenticated Commissioner (OT behaviour, worth a review).
- External Commissioner CoAP tokens come from a non-cryptographic generator seeded from the caller's RNG (tokens match responses only; the DTLS layer authenticates).
- ePSKc: the key octets are the EC-JPAKE password (OT); `EphemeralKey` is wiped on drop and when discarded, redacted, constant-time compared, never logged; single use (discarded when its connected session ends for any reason, including `disconnect()`), discarded at its timeout (2 min default, clamped to 10 min; the session is closed with close_notify) and after 10 connection attempts; at most one ePSKc session; 2 s guard time after each ePSKc session end. Every new peer that gets a DTLS session consumes an attempt before the cookie exchange (as OT), so an off-path attacker spoofing ClientHellos can exhaust the attempts (denial of service, not key recovery) — worth a review. The passcode generator uses rejection sampling for uniform digits.
- ePSKc sessions are served like PSKc sessions: Active / Pending gets include the Network Key without petitioning (spec 8.4.9.4.1.4 exceptions 1-2), keep-alive timeout 50 s; the PSKc listener stays usable in parallel (OT).
- TCAT engine (feature `tcat`): authorization re-evaluated for every command (13.12.1), reserved methods fail, proof-of-possession hashes compared in constant time; the challenge is kept for the link (spec) and hash presentations are not rate-limited beyond the TLS session (OT likewise) — online PSKd guessing needs a valid Commissioner certificate; Set Active Dataset refused when a complete dataset existed at link start; buffers holding datasets are wiped. Chain validation, validity dates and the 60 s handshake timeout are the TLS layer's job.
- The meshcop simulator emulates key ID mode 0 by comparing KEKs; the full stack (`rs-thread-sim/tests/commissioning.rs`) runs the real MAC path: the Joiner Entrust and its answer are key ID mode 0 frames under the KEK, the network key never appears in the clear on the air (asserted on every frame), a wrong PSKd yields no KEK frame, replayed mode 0 frames are dropped by the MAC once the KEK is discarded.
- Instance: key ID mode 0 frames are accepted only from the one peer of a running KEK exchange (the Joiner Router of our Joiner in the Entrust / Joined state, or the Joiner whose Joiner Entrust is in flight), only to our extended address, only with a frame counter above the last accepted one under the current KEK (OT checks none), and the reassembled datagram only as UDP from that peer's link-local address (IID = authenticated MAC source) to ours and the TMF port with a valid checksum; it reaches only `handle_kek_datagram`, never IPv6 / TMF / forwarding (OT treats mode 0 frames as link-secured for every layer). Drops are counted (`Instance::kek_drops`).
- Instance: key ID mode 0 is only framed between extended addresses (the nonce binds them); a KEK datagram is refused without an installed KEK; queued KEK frames fail at the MAC if the KEK was discarded meanwhile (no fallback to another key).
- Instance: 6LoWPAN reassembly is keyed by the security class, so an unsecured or mode 2 fragment cannot complete a mode 0 or mode 1 datagram; only mode 1 counts as link-layer secured above the MAC (mode 2 uses a public key).
- Instance: unsecured datagrams to the Joiner UDP port only between link-local unicast addresses; the Joiner takes them only from its Joiner Router, the Joiner Router relays only link-local sources; the port is open only while a Joiner runs or joining is allowed.
- Instance: the Joiner Entrust dataset (network key) is kept in a wiped `Dataset` until saved; a successful join starts Thread with it (OT leaves that to the application). The Border Agent gets the PSKc only on `border_agent_start` and loses it on stop; ePSKc keys go straight into `EphemeralKey`.

- [x] Reload of the leader's commissioner state after a reset (`LeaderState::restore_leader`; leader Network Data wait-for-sync: `Leader::start_restoring` / `restore` / `sync_timed_out`)

## Phase 9 – Thread 1.2 / 1.3 / 1.4 features

- [x] Domain Unicast Address & Backbone Router client support (1.2): `netdata::backbone`, `dua` (generation with persisted DAD counter, `/n/dr` registration, retry / reregistration, duplicate handling, proxy registration for children), mesh-simulator tests with a fake Primary BBR
  - [x] Backbone Router role without a backbone link (`rs_thread_mesh::bbr_server`, instance feature `bbr-server`: BBR service, Primary selection, `/n/dr` and `/n/mr` answers, PBBR ALOC, `bbr`/`bbr mgmt`/`dua iid`/`fake /a/an` CLI)
  - [ ] Backbone link: DAD, ND proxying, `/b/bq`, `/b/ba`, `/b/bmr`, multicast routing
  - [x] Thread 1.1 parents (registration through the BBR service ALOC)
  - [x] Device glue in the `Instance` (`rs-thread-instance::bbr`): `BackboneRouterLeader` from Network Data, `DuaManager` (DAD counter persisted under `DadInfo`, DUA registered with the address registration, proxy registration for children), `MlrManager` (external multicast and children); sim test `crates/rs-thread-sim/tests/bbr.rs` with a fake Backbone Router as `Instance::set_tmf_extension`
- [x] Multicast Listener Registration (MLR) (1.2): `mlr` (device and child groups, `/n/mr`, timeouts, reregistration, failed addresses, `MlrState` in `Child`)
  - [x] Commissioner MLR (`mlr reg`: Commissioner Session ID / Timeout TLVs; end devices with a Thread 1.1 parent register through the service ALOC)
- [x] Enhanced CSL (Phase 9c): SSED child side (`rs_thread_mle::csl`: parameters, parent metric, poll period, response wait), parent side (`Child` CSL state, CSL timeout, `MleEnv::{csl_clock_accuracy, csl_child_update, csl_child_desync}`, `Mle::child_csl_synchronized`), CSL frame hand-over to the MAC (`rs_thread_mesh::indirect`), CSL IE in data polls (`rs_thread_mac`)
  - [ ] CSL wake-up (Thread 1.4): wake-up coordinator and wake-up end device (see the Phase 2 item)
  - [x] Glue in the `Instance` and end-to-end test: CSL IE receptions (frames and data polls) reach `Mle::child_csl_synchronized` and start the MAC's CSL child tracking (`Mac::csl_child_sample`), `csl_flush` / `parent_frame_received` / `Mac::set_csl` are called, the MAC puts the CSL IE into every frame an SSED sends to its parent, MLE messages of a CSL receiver are link-secured (OT `MeshForwarder` rule), the forwarder leaves room for the CSL IE (`CSL_IE_OVERHEAD`), frames for a CSL child wait in the MAC as 2015 frames until its window, a retransmitted frame with a CSL IE triggers a data poll; end-to-end over the virtual-time medium (`rs-thread-sim/tests/csl.rs`)
  - [x] `v1_2_test_csl_transmission` with the leader OpenThread and the SSED rs-thread ends at the last step: after the leader was away for longer than the timeout and came back, no Child Update Request of the SSED is seen within 5 s (the child counted no link failures of its parent: data polls without ACK now count, 4 in a row, 15 with CSL, and the child detaches and attaches anew like OT `UpdateNeighborOnSentFrame`; the data frames to the parent do not count yet)
  - [x] Live CSL period change on the nRF52840: the timed receive windows started 0.4 to 0.9 ms late (the backend moved a window handed over less than 3 ms ahead; the executor latency from the MAC timer to the driver call ate the margin), so the parent's frames were missed after the attach and after every change; the MAC timer lead of the Nordic backend is 5000 us now; 500 -> 100 -> 200 -> 1000 -> 500 ms, 50 of 50 pings at each period, no unacked parent frame (docs/csl-hardware.md)
  - [x] Slow sleepy attach on the nRF52840 (15 to 45 s): not a sleepy or radio problem. The OpenThread parent drops the Parent Requests of a reset RAM-settings CLI node while it still holds the child entry of the previous attach (MLE frame counter restarted at 0, replay check); with a fresh extended address the attach takes 1.0 to 1.8 s for SED, SSED and non-sleepy (10 attaches each). Parent loss: SED left after 6.2 s, SSED after 9.7 s (3 s poll period), both attached again 15 to 18 s after the parent restarted (docs/csl-hardware.md)
  - [x] CLI firmware keeps the frame counters (and the other Thread settings) over a reset in the `rs-thread-flash` log
- [x] Link Metrics (initiator & subject, Thread 1.2): Management / Query / Report / Link Probe, Forward Tracking Series per neighbor, Enhanced-ACK probing with the Thread IE in the MAC's enh-ACKs, `linkmetrics request|config|probe` and `linkmetricsmgr` CLI, `mac send emptydata|datarequest`, Link Metrics Manager (`Instance::link_metrics_manager_set_enabled`, feature `link-metrics-manager`); LowPower 7.1.1, 7.1.2, 7.2.1 and the link metrics functional tests pass (docs/test-plan-status.md)
- [x] SRP client (RFC 9665) & DNS-SD client (1.3) — **pulled forward**: required by Matter for operational discovery (`_matter._tcp`); target M4 (`rs-thread-dns`: `wire` / `rdata` DNS codec with name compression, TXT, KEY / SIG(0), OPT Update Lease; `client` DNS / DNS-SD client: AAAA, browse, SRV+TXT resolve; `srp` SRP client with SIG(0) ECDSA P-256 signing (`rs_thread_core::crypto::ecdsa`), lease refresh, OT retry backoff, Network Data auto-start with unicast / anycast selection and server switching; tests against a scripted fake server, no simulator end-to-end test yet)
  - [x] CLI gaps for the OT functional scripts: `dataset updater`, `service`, `locate`, `radiofilter`, child supervision (secured empty frames, interval and failure counter), ND agent ALOC, loopback of echo replies to own addresses; `test_dataset_updater`, `test_key_rotation_and_key_guard_time`, `test_anycast`, `test_anycast_locator`, `test_service`, `test_reed_address_solicit_rejected`, `test_radio_filter`, `test_child_supervision` pass with all nodes rs-thread
  - [x] Functional scripts `test_br_upgrade_router_role`, `test_inform_previous_parent_on_reattach`, `test_netdata_publisher`, `test_ipv6_fragmentation`, `test_history_tracker`, `test_diag` pass (`test_detach` and `test_route_table` too)
  - [ ] Open functional script: `test_coaps` (needs the `coaps` CLI, DTLS with the PSK suite `TLS_PSK_WITH_AES_128_CCM_8` and X.509 certificates / ECDHE-ECDSA; rs-thread's DTLS has EC-JPAKE only)
  - [ ] History Tracker lists besides `netinfo` / `rx` / `tx` (`ipaddr`, `ipmaddr`, `neighbor`, `router`, `prefix`, `route`), `counters ip`, real frames for `diag send`
  - [x] SRP server (`rs_thread_dns::srp::server`, instance feature `srp-server`: signed update processing with ECDSA P-256 verification, key-bound names, lease / key lease / TTL limits and timers, unicast / anycast / unicast-force-add publishing, persisted port), DNS-SD answers from the registrations (PTR / SRV / TXT / AAAA / KEY), CLI `srp server ...`, full `srp client ...` and `dns config|resolve|browse|service|servicehost|query`; the 15 `test_srp_*` (except `register_500_services`, baseline fail) and 3 DNS-SD scripts pass with all rs-thread nodes
  - [ ] SRP server, open: advertising proxy / service update handler, auto-enable and fast start, response counters, DNS-SD SOA / NS, upstream forwarding and discovery proxy, mDNS, DNS over TCP, NAT64 (A record) queries; storage is bounded (8 hosts, 16 services)
- [x] TREL hooks (optional, 1.3; feature `trel` of `rs-thread-mesh`, default off): `trel::Trel` sans-IO link (packet header codec, peer table fed by the platform's DNS-SD results, TXT data `xa` / `xp`, unicast with deferred acks and ack timeouts, broadcast), `TrelPlatform` (UDP send, service registration), `TrelSecurity` (MAC frame security with the TREL key and its own frame counter, `FrameSecurity` impl), `RadioSelector` + `TxFrame::radio` in the forwarder
  - [ ] TREL glue in `rs-thread-mac` / `rs-thread-embassy`: a `Radio` implementation over `Trel`, key ID mode 2 / mode 0 frames over TREL (secure them with the `KeyManager`), key sequence and frame counter persistence for the TREL counter, multi-radio neighbor table (supported radios per neighbor), radio selection feedback from MAC results (`RadioSelector::on_send_done`, `on_receive`, `on_deferred_ack`) and probing of the TREL link, DNS-SD itself (platform)
- [x] Thread 1.4 additions: ephemeral key / ePSKc Border Agent (`rs_thread_meshcop::epskc`, `BorderAgent::start_ephemeral_key` / `stop_ephemeral_key` / `handle_ephemeral_udp`, `BorderAgentClient::connect_ephemeral`; OT `EphemeralKeyManager` semantics: 6..32-octet key used directly as the EC-JPAKE password, 2 min default / 10 min max timeout, 10 connection attempts, single use, independent of the PSKc listener; passcode generation with Verhoeff check digit; DNS-SD `_meshcop-e._udp` through `BorderAgentIo::ephemeral_service`)
  - [ ] Border Agent counters and history events for ePSKc; ePSKc end-to-end in the meshcop simulator
- [ ] TCAT (Thread Commissioning over Authenticated TLS, BLE commissioning) — **optional**; scope review done (ADR 0002, option (b)):
  - [x] Transport- and TLS-agnostic TCAT engine in `rs-thread-meshcop` (feature `tcat`, default off): command TLVs, command classes, section 13.12.1 authorization over certificate claims, `TcatSecureTransport` seam (`rs_thread_meshcop::tcat`, tests with a fake transport)
  - [ ] TLS 1.3 server with mutual certificate authentication (`TLS_AES_128_GCM_SHA256`, secp256r1, ECDSA) and a no-alloc X.509 chain validator on RustCrypto `p256` / `aes-gcm` / `der` (own crate, separate security review; ~2.5-3.5 kLOC)
  - [ ] Thin BLE GATT adapter (TCAT service 0xFFFB, C1/C2, advertisement TLVs) on a BLE host such as `trouble-host`; TMF `/c/te` (TCAT_ENABLE)
- [ ] Border Router role (feature `border-router`, `std`/Linux only initially): RA/RIO, OMR prefix, NAT64 hooks — likely defer

## Phase 10 – Public API & host interfaces

- [x] `Instance` (`rs-thread-instance`, [ADR 0003](docs/decisions/0003-instance.md)): one struct owning MAC + key manager, 6LoWPAN / mesh forwarder, IPv6 / netif / UDP / ICMPv6, TMF agent, MLE, Network Data (leader store, local data, notifier, publisher, ALOCs, SLAAC), address cache and the dataset managers; sans-IO radio edge (`handle_radio_rx`, `handle_radio_tx_done`, `poll_radio_action`, `poll`, `next_deadline`, `poll_event`); persistence through `SettingsStore`; public API (`thread_start` / `become_leader` / `thread_stop` / `factory_reset`, role / RLOC16 / partition / leader data, Active / Pending dataset, `create_dataset`, addresses, UDP sockets, ping, local Network Data, poll period) and typed `Event`s
  - [x] RAM footprint of `Instance`: size test with per-feature-set bound and `docs/memory-budget.md`; chained 128-byte buffer pools (`rs_thread_core::bufpool`) for the outbox, Border Agent outbox, UDP receive queues, indirect queue, held datagrams, CoAP pending / cached messages and DNS/SRP datagrams (default 150000 to 107136 bytes, MTD 102800 to 74576)
  - [ ] RAM footprint: one pool shared by all queues (OpenThread `NUM_MESSAGE_BUFFERS`), reassembly slots and forwarder receive buffer, MAC transmit queue, DTLS roles sharing storage (Joiner / Commissioner), DNS/SRP record sizes
  - [x] `rs-thread-sim`: simulated 802.15.4 medium (link matrix, RSSI, loss, jamming, air time, ACK / Frame Pending / retry semantics of a MAC-offload radio) and a `Network` harness; full-stack tests: leader formation, child attach and router upgrade, 3-router chain ping with mesh header and fragmentation, ML-EID address query, border router prefix and route with SLAAC, non-FTD child address registration, UDP across the mesh, sleepy end device polling, leader restart restore, link-layer replay protection
  - [x] MTD-only data path (`default-features = false` is a real end-device build: no router / leader / Router ID code, parent-only routing, mesh header frames dropped) and SRP client + DNS client wiring (`rs_thread_instance::dns_srp`: Network Data auto-start, persisted key and server, `Instance::srp_*` / `dns_*`, `publish_dns_srp_service`; full-stack sim test `crates/rs-thread-sim/tests/dns_srp.rs` with a fake SRP/DNS server)
  - [ ] Instance wiring still missing: TCAT, TREL radio, Pending dataset delay timer persistence checks (the energy scan / PAN ID query / announce begin servers and the Commissioner requests are wired, feature `scan-servers`; Joiner, Joiner Router, Commissioner, Border Agent and the leader commissioner session are wired)
  - [x] Sleepy end device with the default poll period stays attached: the parent queued link-local unicast (MLE) for a sleepy child as a direct frame (OT queues it indirectly: `Route::Indirect` once the child is `confirmed`), the child had no attach-mode / fast polls after a Data Request (`Mac::set_poll_attach_mode`, `MleEnv::send_fast_polls`); sim test `sleepy_end_device_with_default_poll_period_stays_attached`
  - [ ] The SRP/DNS wiring needs `EcdsaP256` on the crypto backend and `CryptoRng` on the RNG of `Instance`; hardware backends must provide ECDSA. `cargo check-nrf52 -p rs-thread-instance` builds with `p256` in the tree (compile check only; flash size of the ECDSA code not measured yet)
  - [x] CSL and link metrics glue in the `Instance` (`Mac::set_csl`, CSL IE in SSED frames and on receive, Enhanced ACK probing events); end-to-end CSL tests in `rs-thread-sim/tests/csl.rs` over the virtual-time radio (clock, software sampling; no timed receive)
  - [x] Key rotation event, Discovery / Announce `TxOptions` channel and PAN honoured by the MAC path, Network Diagnostics TMF server (`/d/dg`, `/d/dq`, `/d/dr`, `diag_get` / `diag_query` client, `neighbor_table` / `child_table` / `route_table` / `mac_counters` getters; sim tests `diag.rs`, `keyrot.rs`)
  - [ ] Network Diagnostics: multi-message answers, Child / Router Neighbor / Enhanced Route / MLE counters / vendor TLVs, `/d/dr` client
  - [x] Initiator side of Enhanced ACK probing (`Mac::track_enh_ack_probing`) and aggregation of data requests; ACK frames are open (see Link Metrics)
  - [x] Async facade (`rs-thread-embassy`): `Resources` / `rs-thread` handle, drop-safe `run(radio, alarm)`, multi-waiter `wait_changed`, `next_event`, `with` passthrough, async `UdpSocket`; tested over an async test medium in virtual time
  - [x] `edge-nal` UDP traits (feature `edge-nal`), async wrappers for ping / joiner / SRP wait / DNS (resolve address, browse, resolve service)
  - [x] Scans in the `Instance` (MLE discovery, MAC active scan with beacons from attached router-eligible devices, energy scan) and async `scan` / `energy_scan` wrappers
  - [x] esp-rs `openthread`-compatible surface (feature `openthread-compat`, module `compat`): `OpenThread` with the lifecycle, status, getters, scan / energy scan, tables, multicast, link mode, poll period and SRP client calls
  - [ ] Compat surface, open (the `Instance` lacks the data, the methods return defaults or `NotImplemented`): MLE and IP counters, MAC unicast / broadcast / duplicate / FCS counters, neighbor age / frame counters / last RSSI / error rates, route table ext address / link qualities / age, CSL period and timeout, child timeout setter, child supervision, `detach_gracefully`, `buffer_info`, subtype labels and lease / TTL settings of the SRP client, pending dataset components (`active_dataset_diag`), the DNS client calls (`dns_browse`, `dns_resolve_service[_and_host_address]`, `dns_resolve_address` with esp-rs `DnsResponse`; the native async DNS wrappers exist), ping sender, joiner and `with_instance` / raw rx / tx
  - [ ] Async facade, open: an async wrapper for the MAC active scan; a cancel API for discovery / energy scans (dropping the scan future does not stop the scan)
  - [x] Beacons as OpenThread: sent while attached and router eligible, without payload by default (Thread 1.2.1+, OT `OPENTHREAD_CONFIG_MAC_OUTGOING_BEACON_PAYLOAD_ENABLE` off); Thread beacon payload opt-in with `Instance::set_beacon_payload_enabled`
  - [ ] Beacons from a detached, non-router-capable device while joinable (OT `OPENTHREAD_CONFIG_MAC_BEACON_RSP_WHEN_JOINABLE_ENABLE`, off by default)
  - [ ] Buffer pools: a single MLE/TMF message over 1024 bytes cannot be queued in the MLE outbox and pending / cached CoAP messages over 2 kB are refused with `NoBufs`; check large Network Diagnostics answers and size the pools against OT's largest messages
  - [ ] Differential tests of the `Instance` against an OpenThread node (Phase 11)
- [ ] rs-matter integration (`rs-thread-matter`, rs-matter pinned to revision `95e4110`, Rust 1.92):
  - [x] rs-matter `NetStack` / `NetSocket` (transport `NetworkSend` / `NetworkReceive` / `NetworkMulticast`) over the native `UdpSocket` for Matter traffic (rs-matter-stack 0.4 does not consume `edge-nal`); two-node virtual-time test; shared async test harness in `rs_thread_sim::testing` with a virtual `embassy-time` driver
  - [x] `Mdns` over the SRP client + DNS-SD client (`SrpMdns`): host from the extended address, `_matterc._udp` / `_matter._tcp` with subtypes and TXT kept in sync with `Matter::mdns_services`, removed when the future is dropped; operational / commissionable resolve and browse through `dns_resolve_service` / `dns_browse`; `NetifDiag` + `NetChangeNotif` (`ThreadNetif`); test with a fake SRP / DNS-SD server on the leader
  - [x] SRP service slots: 6 by default (`rs_thread_instance::SRP_SERVICES`, features `srp-services-8` / `srp-services-12`), enough for the commissionable service and 5 fabrics (about 770 B RAM per slot)
  - [ ] `SrpMdns`, open: lease / TTL are the client defaults, a browse answers one pass per request (no re-query while the window is open), no `MdnsBrowseMatch` for subtype-only answers, resolution of a peer registered with several hosts
  - [x] Thread Network Commissioning cluster backend (`ThreadNetCtl`: `NetCtl` + `NetCtlStatus`): MLE-discovery scan with Extended PAN ID / name filter, connect from the dataset TLVs (stop, set Active Dataset, start, wait for child / router with a 20 s timeout, `OtherConnectionFailure` and Thread stopped on timeout), last status / network ID; the `Networks` store (add / update / remove / reorder) stays with rs-matter; virtual-time tests (scan finds the leader, connect joins, missing network times out)
  - [x] Thread Network Diagnostics cluster data (`ThreadDiag` + `WirelessDiag` on `ThreadNetCtl`): routing role (Disabled / Detached / SED / REED / EndDevice / Router / Leader), RLOC16, channel, PAN ID, ext PAN ID, name, mesh-local prefix, partition / leader data, neighbor and route tables, MAC counters, security policy, channel mask, dataset components, active timestamp
  - [ ] Diagnostics, open (defaults where the `Instance` has no data): neighbor age / frame counters / last RSSI / error rates, route table ext address / link qualities / age and the node's own entry, MLE counters, MAC unicast / broadcast / duplicate / FCS counters, `overrun_count`, pending timestamp / delay, network faults
  - [x] ICD hooks (`IcdFollower`): follows rs-matter's `Icd::net_params` and applies the poll interval to the node (`set_poll_period`), `set_sleepy` for the link mode; test with a sleepy child
  - [ ] ICD, open: child timeout from `max_poll_interval_ms`, CSL period, child supervision (the `Instance` has none of them)
  - [x] `ThreadDriver` / `ThreadCoexDriver` runner (`ThreadRunner`, `ThreadCoexRunner`): `rs-thread::run` + settings persistence + ICD follower raced with the task, drop-safe, restartable on the same `Resources`; `Instance::settings()` / `settings_mut()`, `SettingsStore::change_count` (wakes `wait_changed` on settings writes); `ThreadPersist` stores the Thread settings in one rs-matter `KvBlobStore` blob (`OtPersist` format, debounced, hash-compared); virtual-time tests (restore after a restart without a fresh attach, bounded write rate under traffic, drop / restart of the runner)
  - [ ] Persistence, open: the rs-matter `Networks` store itself is rs-matter's; no wear levelling or write coalescing beyond the 5 s debounce in the persistence itself (the nRF52840 flash log of `rs-thread-flash` levels wear and merges writes per key); the settings are loaded once per `ThreadRunner`, not re-read on a restart with live resources
  - [x] rs-matter on-off light over Thread in sim (`crates/rs-thread-matter/tests/light.rs`, virtual time): a leader hosts the fake SRP / DNS-SD server and runs rs-matter's `Commissioner` over the mesh; the light is a child with a full `MatterStack` through `ThreadRunner` (`run_thread_oper`, dataset preset); asserts attach, `_matterc._udp` and `_matter._tcp` registration, PASE, commissioning, CASE, OnOff read / Toggle / read. RAM numbers in `docs/memory-budget.md`
  - [x] Light on real hardware, nRF52840 DK (`examples/nrf52840-light`): `radio-nrf802154`, embassy-time `Alarm` / `Clock`, flash-backed Thread settings and rs-matter KV (`rs-thread-flash`, wear levelling), RNG entropy, RustCrypto `Crypto`, BLE commissioning (`rs_thread_matter::ble`, `ThreadCoexRunner`), commissioned with chip-tool over BLE (`pairing ble-thread`) and on-network through `ot-br-posix`; 62 min soak with 123/123 toggles, random resets, factory reset back to BLE advertising (`docs/thread-border-router.md`, `docs/memory-budget.md`)
  - Light on ESP32-C6: see Phase 17
- [x] OT-compatible CLI (`ot-cli` command subset) — required to drive OT test scripts: `crates/rs-thread-cli` (`no_std`, no alloc, feature-gated command groups, sim tests driving 1 to 3 nodes by CLI strings only; see RSTHREAD-OPENTHREAD-DIFFERENCES.md for what is missing)
- [~] Spinel (`docs/spinel.md`): RCP mode (enables `ot-br-posix` interop); NCP not planned
  - [x] `rs-thread-spinel` (`no_std`, no alloc): HDLC-lite, Spinel data types, frame header and parsing, constants; unit tests with the OpenThread `test_hdlc` vectors
  - [x] RCP: any `Radio` behind the Spinel radio property set of `RadioSpinel` (`rs_thread_ncp::rcp::Rcp`; software frame retries and transmit security for radios without them); `rs-thread-rcp-sim` (stdio + OpenThread's real-time simulation radio); interop with the OpenThread posix host: network formed with the rs-thread RCP, an `ot-cli-ftd` joins, pings both ways, and the reverse (`crates/rs-thread-rcp-sim/tests/posix_host.rs`, `openthread-sys` feature `posix-host`); subset of OpenThread's `posix-*.exp` scripts
  - [x] RCP firmware for the nRF52840 DK (`examples/nrf52840-leader --bin rcp`, builds: about 105 KB flash, 16 KB RAM)
  - [ ] RCP, open: run on hardware (DK VCOM link, `ot-br-posix`), USB CDC transport for the Dongle, enhanced ACK probing (`RCP_ENH_ACK_PROBING`), CSL IE phase of CSL child frames and enhanced ACKs in the simulation RCP, coexistence, power tables, counters, multi-PAN
  - [-] NCP mode: not planned (user decision 2026-11-17: NCP is no longer used; OTBR uses RCP + posix host)

## Phase 11 – Simulation & testing (reuse OpenThread test framework)

- [x] `rs-thread-sim`: OT's virtual-time simulation protocol (`rs_thread_sim::vt`: UDP event socket, radio with ACK, energy scan, settings file) so Rust nodes and OT nodes share one virtual network; `rs_thread_sim::vtsim`: Rust port of thread-cert's `VirtualTime` simulator driving `ot-cli-ftd` / Rust node processes (mixed-network test `crates/rs-thread-sim/tests/mixed.rs`: OT leader + rs-thread router and the reverse, router tables, pings both ways; skipped without `ot-cli-ftd`)
- [x] `rs-thread-cli-vt` (`rs-thread-cli --features sim`): `ot-cli-ftd`-compatible node (argv: node id; stdin/stdout CLI with echo and prompt; `PORT_OFFSET`/`PORT_BASE`; settings in `tmp/<offset>_<id>.flash`); the MTD variant (`ot-cli-mtd`) is not built
- [x] `cargo test` harness (`tests/thread_cert.rs`, custom harness `harness = false`) that:
  - [x] builds OT reference nodes from `openthread-sys/vendor/openthread` (simulation platform): `cargo build -p openthread-sys` (build script, about 25 s, 11 MB build tree)
  - [x] runs `thread-cert` cases Cert_5_1_*, 5_2_*, 5_3_* with rs-thread nodes in place of OT nodes (`crates/rs-thread-sim/tests/thread_cert.rs`, `RSTHREAD_CERT=1`): 273 of 273 runs pass (all-OT, each node, all rs-thread), details in `docs/test-status.md`; pktverify runs with a macOS workaround, 9 of the 12 cases that pass with OpenThread also pass with rs-thread
  - [x] OT SED attach to an rs-thread parent (Child ID Response queued for the poll)
  - [x] cert baseline failures fixed (`ot-cli-ftd` built with `OT_BORDER_ROUTER`, `OT_LOG_OUTPUT=APP`, `OT_BACKBONE_ROUTER`, plus a Thread 1.1 node); 5.x-9.x and v1.2: 819 of 819 runs pass (all-OT, each node, all rs-thread; harness default now `ot,half,all`)
  - [x] manages Python venv (`.venv`, created / completed with pip: pexpect, pycryptodome, pyshark 0.4.6, lxml)
- [x] Port OT C++ unit-test vectors (`tests/unit/*.cpp`: mac frame, lowpan, mle, crypto, dataset, network data, coap) into Rust `#[test]`s (inventory and status per test in `docs/ot-unit-test-port.md`; the rest is OT-internal framework, IPv4/NAT64, Spinel/HDLC and platform tests with no rs-thread counterpart)
- [x] Differential tests: same input to `openthread-sys` (FFI) and Rust impl, compare outputs (codecs, crypto, KDF): `crates/rs-thread-difftest` (feature `ot`; C++ shim `tools/openthread-sys/shim/diff_shim.cpp`, feature `diff-shim`) compares crypto / KDF, 6LoWPAN, MAC frames, MeshCoP datasets, Network Data and MLE TLV lookup with seeded random inputs; skipped without the feature; coverage and findings in `docs/differential-tests.md`, deviations in `RSTHREAD-OPENTHREAD-DIFFERENCES.md`; five rs-thread defects found and fixed
- [ ] OTNS (OpenThread Network Simulator) integration for large-topology/visual testing
- [ ] Fuzzing (`cargo fuzz`) for all parsers (MAC, 6LoWPAN, MLE TLVs, CoAP, MeshCoP TLVs)
- [x] Track cert test pass-rate in `docs/test-status.md`

## Phase 12 – Embedded targets

- [ ] nRF52840 (DK, running): `crates/rs-thread-nrf` and `examples/nrf52840-leader` (standalone firmware, own target dir; `cargo run --release`, `--bin scan`)
  - [x] Radio driver over `embassy-nrf` 0.11 `radio::ieee802154` (feature `radio-embassy`, the default). No MAC offload: the MAC does ACK, retries, CSMA and filtering in software; CCA is carrier sense only; energy scan by RSSI sampling; RSSI of received frames estimated from the LQI byte. Differences in `RSTHREAD-OPENTHREAD-DIFFERENCES.md`
  - [x] `Clock` / `Alarm` over `embassy-time` (RTC1, 32.768 kHz tick), entropy from the RNG peripheral, `RamSettings`
  - [x] Firmware: Leader with a fixed dataset (channel 15, PAN 0x1234, "rs-thread"), MLE Advertisements transmitted, no radio errors; energy scan of all channels and active scan with real RF
  - [x] Flash / RAM measured (`docs/memory-budget.md`): 365 KiB flash, 84 KiB static RAM, stack high-water 17 kB after the in-place construction (was about 125 kB)
  - [x] RAM: `Instance::init` / `Resources::init` build the node in place (no 100 kB value on the stack), the `Instance::poll` steps are not inlined into one frame; stack high-water 15.8 kB during construction and 16.9 kB running on both backends (`docs/memory-budget.md`)
  - [x] Matter on-off light firmware (`examples/nrf52840-light`, Thread Leader with a preset dataset, rs-matter RustCrypto backend, test attestation, no BLE; since the flash work a flash-backed key-value store: 831 KiB flash, 182 KiB static RAM): 808 KiB flash before it, 174 KiB static RAM, 31 kB stack, boots and runs rs-matter on the DK; commissioning on the board and LED control are not yet exercised; on-network rehearsal: build-time dataset (`RSTHREAD_DATASET`), SLAAC address from an on-mesh prefix, SRP host and `_matterc._udp` registered with an OpenThread SRP server, ping from the peer; see docs/thread-border-router.md
  - [x] Second radio backend over sysgrok `nrf-802154` (Nordic C driver + MPSL), feature `radio-nrf802154` of `rs-thread-nrf` (exclusive with `radio-embassy`, which stays the crate default; the firmware defaults to the Nordic backend). Reports all MAC offloads plus ACK timeout, CSMA, timed TX/RX, TX security, auto sleep and energy scan, so `SoftMacNeeds` is `RETRANSMIT` only. On the DK: Leader, MLE Advertisements out, no radio errors; `scan` found 5 and 3 beacons in two rounds where the embassy backend found 1 and 1 (same place, one board). Flash 430 KiB, static RAM 93 KiB (`docs/memory-budget.md`). Uses a pinned git commit of `nrf-802154` (the released 0.1.0 lacks timed RX / CSL / secured enhanced ACKs); needs `clang`, `cmake`, Rust 1.93 and, on macOS, `llvm-ar` in place of Apple's `ar` (crate docs)
    - **The exception to pure Rust.** The driver is C (BSD-3-Clause source); the 802.15.4 service layer (`libnrf-802154-sl.a`, 54 kB) and MPSL (`libmpsl.a`, 88 kB) are prebuilt Nordic binaries under `LicenseRef-Nordic-5-Clause` (Nordic silicon only, no reverse engineering). MPSL has no source; details in the `rs-thread-nrf` crate docs
    - [x] CSL timing against an OpenThread parent on the DK (`docs/csl-hardware.md`): SSED with 500 / 200 / 100 ms periods, 0 loss over 60 / 30 / 60 pings, no data polls, RTT uniform over one period, window about 6.4 ms (1.3 % at 500 ms); a live period change does not resynchronize the parent (open)
    - [ ] BLE coexistence measurements (throughput / timing; functionally verified: Thread attaches within about 1 s while a BLE connection is open, full `chip-tool pairing ble-thread` works); `TRANSMIT_RETRIES` is not offered by the driver, the MAC keeps the retry loop
  - [x] Flash-backed settings: `rs-thread-flash` (RAM image + async two-bank log writer over any async `NorFlash`; CRC-protected per-key entries, compaction with the header written last, power-cut tests at every flash operation on the host), `rs_thread_nrf::Flash` (`nrf_mpsl::Flash` through MPSL timeslots with `radio-nrf802154`, NVMC with `radio-embassy`), `rs_thread_matter::flash_kv::FlashKv` (`KvBlobStore`), regions in `memory.x` (last 24 KiB, survive a reflash), factory reset with Button 1 at boot. On the DK: the `node` restores ML-EID, RLOC16 and role after a reset and is child again after 20 ms (fresh attach 820 ms), frame counters grow across resets (3000, 4000, 5010), peer RxErrSec 0; the light reloads its key-value store and Thread settings. Not verified: Button 1 on the board (a feature forces the reset instead), power cut on the board, rs-matter fabrics (no commissioning yet)
  - [x] BLE for Matter commissioning on the light: Nordic SoftDevice Controller (`nrf-sdc` 0.4, peripheral library) and `trouble-host` 0.8 on the MPSL instance of the 802.15.4 driver, BTP GATT peripheral ported from `rs-matter-embassy` (`rs_thread_matter::ble`, feature `ble-trouble`), `run_thread` with `ThreadCoexRunner` (BLE next to Thread); the unprovisioned light advertises (discriminator 3840, seen from a Mac while Thread runs as router), a commissioned one does not, BLE stops when commissioning completes (on-network rehearsal with the BLE firmware: PASE window, CommissioningComplete, toggle, reboot stays commissioned). Flash 950 KiB, static RAM 201 KiB (`docs/memory-budget.md`). Not verified on the board: `chip-tool pairing ble-thread` end to end (macOS needs Apple's Matter BLE developer profile, section 5a of `docs/thread-border-router.md`)
  - [ ] CryptoCell / hardware crypto (the RAM reduction is done, see above)
  - [x] Interop against OpenThread (`ot-cli-ftd`, ot-nrf528xx `d2c0b13` / OpenThread `e5629fa`, second DK, `examples/nrf52840-leader --bin node`, channel 25), `radio-nrf802154` backend: rs-thread attaches as child in 1 to 7 s, upgrades to router (peer router table: link quality 3/3), pings both ways with 0 loss over hundreds of echoes (RTT 10 to 30 ms), rs-thread Leader with the OpenThread node joining as child and router, leader reset (partition merge, takeover by the peer after 120 s), 12 min run without retries, security or channel access errors. Bugs found and fixed: MLE Announce (key ID mode 2) reached the driver unsecured (`KEY_ID_INVALID`), key index of queued frames after a key sequence switch
  - [ ] Interop with the `radio-embassy` backend: rs-thread does not attach to the OpenThread Leader (no Parent Response seen, peer counts 8 security errors and no unicast TX) and an rs-thread Leader is not joined by the peer; the Nordic-driver backend works, so the cause is in the software MAC path or the embassy-nrf radio layer (a packet capture is needed; not diagnosed yet)
  - [x] Interop CSL (rs-thread SSED under the OpenThread parent, see `docs/csl-hardware.md`); the reverse direction needs an OpenThread build with the CSL receiver
  - [ ] Interop still open: SED polling, runs over several hours (62 min with the light done), packet capture (no sniffer)
- [ ] nRF54L15/H20: radio driver, timers, CRACEN crypto
- [ ] ESP32-C6/H2: see Phase 17
- [ ] Example apps per board: MTD (SED) sensor open; FTD router / leader (`examples/nrf52840-leader`, `--bin node`) and CLI over UART done on the nRF52840 DK
  - [x] CLI over UART on the nRF52840 DK (`examples/nrf52840-leader --bin cli --features cli-all`, UARTE0 on the J-Link VCOM, prompt `> `, echo and CR/LF as OT's UART CLI, settings in RAM): interop against `ot-cli-ftd` on a second DK on channel 25 with CLI commands only (OT forms / rs-thread joins by `dataset set active`, rs-thread forms / OT joins; `state`, `ping` and `udp` both ways to ML-EID and RLOC, `router table`, `child table`, `neighbor table`, `netdata show`, `ipaddr`, `dataset active` identical in format). Flash 447 KB with no command group, 501 KB with all, RAM 98 / 106 KB (per group: dataset +8 KB, scan +3, ping +4, tables +10, netdata +5, srp +5, dns +2, udp +3, commissioning +16 KB flash and +7 KB RAM)
  - [x] CLI firmware persistent settings: the `cli` and `node` binaries keep the Thread settings (datasets, network info with the frame counters stored ahead, parent / child info, random extended address) in the Thread region of the `rs-thread-flash` log; `factoryreset` and Button 1 at boot erase it (hardware: ten resets in a row against an OpenThread parent, no growth of the attach time)
  - [x] CSL receive window after-time configurable per radio (`RadioCaps::csl_receive_on_after_us`, default the OpenThread 5.5 ms `MIN_RECEIVE_ON_AFTER`), unit test in `rs-thread-mac`
  - [ ] CLI firmware, open: commissioner / joiner against OpenThread on hardware (OTBR commissioner on macOS blocked), (`child <id>`, `counters mle` done; `counters ip` open; `dataset mgmtsetcommand` / `mgmtgetcommand` done)
- [ ] Footprint budgets (flash/RAM per role) and power measurements for SED/SSED
- [x] Hardware-in-loop interop with an OT RCP / `ot-br-posix` border router (manual, on a Mac with an nRF52840 Dongle RCP; `docs/thread-border-router.md`): the light registers over SRP, is commissioned on-network and over BLE, and is controlled by chip-tool through the BR
  - [ ] Automate it (scripted BR + chip-tool run)
  - [ ] Commissioning through the OTBR: `otbr-agent` on macOS exits without a log line or crash report right after `ot-ctl commissioner start` ("petitioning"); joiner test of the rs-thread CLI DK against the OTBR commissioner blocked (needs `otbr-agent` in the foreground with a higher log level)

## Phase 13 – Certification readiness & docs

- [x] Map every Thread 1.4.1 test-plan case to status (pass/fail/NA): `docs/test-plan-status.md` lists every case with an OpenThread `thread-cert` script (5.x to 9.x, LowPower) per configuration (all OT, each node rs-thread, all rs-thread, MTD build), plus the functional tests and the NA scripts (OTBR / backbone); cases without an OpenThread script are not covered
- [ ] Cross-check rs-thread against OpenThread
- [ ] Cross-check rs-thread against Thread specification
- [ ] Security review (key handling, frame counters, replay protection). Items the `Instance` adds for the review:
  - link-layer replay protection for received data frames is `Mle::check_link_frame`, called by the `Instance` before the forwarder for every secured frame (key ID mode 1) from a known neighbor; frames from unknown sources pass, key ID mode 2 frames are not checked; key ID mode 0 frames are checked per KEK (counter above the last accepted one) and accepted only from the peer of the running Joiner Entrust exchange
  - the unsecure-port filter in `Instance::unsecure_allowed` (datagrams without link security only for UDP to the MLE port and the ports of `add_unsecure_port`)
  - the TX path secures every frame with its `LinkSecurity` class at the MAC (level 5; key ID mode 1, mode 0 for the Joiner Entrust, mode 2 for MLE Announce) through the key manager; the key sequence rotation poll (`KeyManager::poll`) result reaches MLE through `KeyManager::key_epoch` (the MLE frame counter restarts on every key switch, as OT `SetCurrentKeySequence`)
  - a network key change (Pending Dataset delay timer, MGMT_SET, API, Child ID Response) resets the parent's, routers' and children's incoming key sequence and link / MLE frame counters (`Mle::reset_frame_counters`, `MleEnv::take_network_key_changed`; OT `KeyManager::ResetFrameCounters`); before, neighbors that kept their old counters dropped the frames of the new key sequence 0
  - the SLAAC IID secret key and the ML-EID IID come from the instance RNG; the secret key is stored in the settings in clear
  - a non-FTD child accepts MAC frames from its parent without per-frame counter state beyond what `check_link_frame` keeps
- [ ] API docs, architecture doc, porting guide for new platforms

## Phase 14 – Cleanup

- [ ] Full code review
- [x] Remove mention of PLAN phases from code and comments (keep it that way for new code)
- [x] Check what can/needs to be disabled on embedded devices (feature gates done: bbr, border-router, link-metrics, csl, dtls-server, ping, srp-client, dns-client)
- [x] Check for remaining TODOs (none — no todo!()/unimplemented!(); 3 benign comment-TODOs in ble.rs and platform/radio)
- [x] Review no_std compliance (all core crates pass `cargo check --target thumbv7em-none-eabihf --no-default-features`; fixed child_polled gate in datapath.rs)
- [x] Check whether to change things for `cargo --release` (`cargo check --release` clean on instance FTD + MTD + embassy; nrf-802154 firmware requires Nordic shim toolchain, not buildable on macOS without it)
- [x] Check that all rs-thread tooling is Rust based (no Perl/node; two Python dev helpers in examples/nrf52840-leader/tools/ are hardware debug scripts, exempted; cert harness is OpenThread tooling)

## Phase 15 – Publish rs-thread

- [x] Add Github actions to build and release with trusted publishing
- [x] Push to Github (PR #10 merged)
- [ ] Release crates to crates.io (blocked: rs-matter git dep, not yet on crates.io)
- [x] Announce / Market rs-thread (email drafts: announcement for rs-matter / embedded Rust community, OpenThread bug findings, Thread Group spec issues)

## Phase 16 – Port ot-br-posix

**Goal**: a Rust `std`/Linux border router binary (`examples/rsthread-br-posix`) that uses the rs-thread stack with a Spinel-RCP radio and bridges a Thread mesh to the IP backbone — a Rust replacement for `ot-br-posix`.
Reference source: `/Users/markusbecker/src/ot-br-posix` (tag `v2026.11.0`); components in scope: `src/agent`, `src/border_router`, `src/mdns`, `src/rest`.

### 16a – Spinel host transport (`rs-thread-ncp`, `std` feature)

- [x] `rs-thread-ncp`: add a host-side `RadioSpinel` module (feature `radio-spinel`, `std`-only) that is the mirror of the existing device-side `Rcp`: it drives an RCP by sending Spinel property-get/set/insert/remove commands and dispatching unsolicited `STREAM_RAW` frames; implements `rs_thread_platform::radio::Radio` so the rs-thread MAC can use it transparently
  - Transport: reuse the existing `Transport` trait (`rcp.rs:48`); add a tokio-backed `UartTransport` (`tokio-serial` crate or `/dev/tty*` via `tokio::fs`) and a `SocketTransport` (Unix-domain or TCP socket, for use with `rs-thread-rcp-sim`)
  - Property mapping: `PROP_PHY_CHAN`, `PROP_MAC_15_4_PANID`, `PROP_MAC_15_4_LADDR/SADDR`, `PROP_STREAM_RAW` (TX with frame metadata, RX callback dispatch), `PROP_PHY_RSSI`, `PROP_MAC_ENERGY_SCAN_RESULT`, `PROP_MAC_SCAN_STATE`, `PROP_RADIO_CAPS`
  - `SoftMacNeeds`: derive from `PROP_RADIO_CAPS` exactly as the device side does (capabilities the RCP advertises → subtract from what the host does in software)
  - Response tracking: in-flight TID map, `WAIT_RESPONSE_TIMEOUT` retry, unsolicited frame dispatch loop
- [ ] Extend `rs-thread-rcp-sim/tests/posix_host.rs` to exercise the new host-side `RadioSpinel` ↔ `rs-thread-rcp-sim` path (rs-thread node → `SocketTransport` → `rs-thread-rcp-sim` → virtual radio → OT nodes; bidirectional frames, attach, ping); replaces the `openthread-sys` posix-host shim in that test

### 16b – rs-thread host stack

- [x] `rs-thread-instance`: verify the `std` + `alloc` feature build on Linux (`x86_64-unknown-linux-gnu`); ensure `Instance` and `rs_thread_embassy::ThreadRunner` accept a `RadioSpinel<impl Transport>` as the radio (the trait bound is already `Radio`; confirm it compiles cleanly with the new host driver)
- [x] `rs-thread-instance`: expose an `Instance::handle_ip6_from_host` entry point that feeds an IPv6 datagram arriving from the backbone into the Thread IP layer (symmetric to the existing `poll_event` `Ip6Datagram` variant that sends Thread datagrams toward the host)

### 16c – Tun/tap interface and backbone routing (`crates/rs-thread-br`, new crate)

- [x] `rs-thread-br` (`std`, Linux + macOS): `TunInterface` backed by `tun2 2.x` async API; reads/writes raw IPv6 packets via `AsyncRead`/`AsyncWrite`, adds/removes system routes via `ip`/`ifconfig` CLI commands
  - Linux: `tun2` wraps `/dev/net/tun`; route management via `ip addr add` / `ip -6 route add`
  - macOS: `tun2` wraps `utun`; route management via `ifconfig inet6 alias` / `route -n add -inet6`
  - Inject path: `Event::Ip6Datagram` → `take_ip6_datagram` → mpsc channel → `tun.write_packet`
  - Receive path: `tun.read_packet` → `handle_ip6_from_host`
- [ ] Windows support (optional, feature `tun-windows`): `TunInterface` backend via the `wintun` crate (WireGuard's WinTUN driver, redistributable `wintun.dll`/`.sys`, must be installed separately); route management via IP Helper API (`iphlpapi.dll`, `windows` crate bindings); raw ICMPv6 socket for RA/RIO requires elevated privileges — same requirement as Linux/macOS; mark as not tested against `ot-br-posix` behavior (which is Linux-only)
- [x] Border routing manager (`rs_thread_br::routing`): OMR prefix selection (`OmrPrefix::random()` picks a stable ULA /64 using time+PID entropy; `set_omr_prefix` for external control), periodic unsolicited RA/RIO transmission on the backbone using a raw `IPPROTO_ICMPV6` socket (socket2), nix for `if_nametoindex` and link-local address lookup, manual ICMPv6 checksum over pseudo-header — 3 fast initial RAs then every 200 s; backbone RA ingestion and Network Data push not yet wired (no `Instance` dep in this crate)

### 16d – SRP advertising proxy (`rs_thread_br::srp_proxy`)

- [x] `SrpProxy::start(name, port)` starts an `mdns-sd::ServiceDaemon` and advertises `_meshcop._udp`; instance name is `"rs-thread BorderRouter #XXXX"` (last 2 EUI-64 bytes), matching the otbr-agent naming scheme; `enable_addr_auto()` lets mdns-sd pick the host's real IP addresses; `SrpProxy::shutdown()` sends a stop signal to the daemon background thread for clean exit
- [x] Wire `SrpProxy` to `Instance::srp_server_store()` in the border router binary: the SRP bridge task snapshots `all_services()` on each `wait_changed()`, diffs against a `(host_id, instance_label) → update_time` map, calls `register`/`unregister_host` for new/removed entries; `_meshcop-e._udp` and full state bitmap deferred

### 16e – DNS proxy (`rs_thread_br::dns_proxy`)

- [x] `DnsProxy::run()` binds a UDP socket, parses DNS queries with `hickory-proto`, resolves A / AAAA / PTR via `hickory-resolver` (reads `/etc/resolv.conf` on start via a simple `nameserver` line parser; override with `with_upstream(ip)`); serialises and returns the response; unrecognised record types return NOTIMP

### 16f – Binary and integration

- [x] `examples/rsthread-br-posix` (workspace crate, `std`, Linux/macOS): daemon binary that:
  1. opens the Spinel transport (`--radio-url` for UART path or `spinel+socket://…`)
  2. creates the rs-thread `Instance` with `RadioSpinel` as the radio and runs the embassy thread runner
  3. creates the `TunInterface`, assigns the OMR address (`prefix::1`) to the TUN, adds the OMR prefix route, starts border routing RA/RIO (spawn_local task)
  4. starts the SRP advertising proxy (`--become-leader` to form a new network) and DNS proxy (spawn_local tasks)
  5. SRP bridge task: diffs `srp_server_store()` on each `wait_changed()` and calls `SrpProxy::register/unregister_host`; OMR prefix published to Network Data via `publish_external_route`; `srp_server_set_enabled(true)` on startup
  6. handles `SIGTERM`/`SIGINT` with `rsthread.thread_stop()` + `SrpProxy::shutdown()` then `process::exit(0)`
  7. REST API (`feature = "rest"`, enabled by default): `GET /api/v1/node`, `/api/v1/node/state`, `/api/v1/node/dataset/active`, `POST /api/v1/node/dataset/active`, `DELETE /api/v1/node` (501); state shared via `tokio::sync::watch`, commands via `mpsc`; embedded HTML status page at `GET /` (polls `/api/v1/node` every 3 s, dark-mode aware, no external deps)
- [x] otbr-agent CLI compatibility: same positional `RADIO_URL`, `-I`/`-B`/`-d`/`-v`/`--auto-attach`/`--rest-listen-address`/`--rest-listen-port` arguments; `spinel+hdlc+uart://` → `spinel+uart://` URL normalization; `tty.*` → `cu.*` on macOS; `uart-baudrate` query param parsed
- [x] Serial port raw mode: `cfmakeraw()` + 8N1 + explicit baud via `nix::sys::termios`; required for binary Spinel over UART (without it line discipline mangles Spinel frames)
- [x] Workspace `Cargo.toml`: add `examples/rsthread-br-posix`; shared `target/` dir
- [x] Integration test skeleton (`examples/rsthread-br-posix/tests/integration.rs`): three `#[ignore]` tests (network formation, SRP bridge, DNS proxy); execution requires `rs-thread-rcp-sim` backend (run with `-- --ignored`)
- [x] Hardware smoke test (nRF52840 Dongle RCP, macOS): radio init, Thread network formed as Leader (channel 15, PAN 0xface), TUN `utun9` with OMR address `fd…::1/64`, OMR route in routing table, `_meshcop._udp` discoverable via `dns-sd`, DNS proxy up; verified with `netstat -rn -f inet6` and `dns-sd -B _meshcop._udp local`
- [ ] Hardware smoke test — full flow: join nRF52840 light DK to the network, verify SRP registration on Thread and mDNS on macOS, on-network commissioning with `chip-tool`, one on/off toggle (`docs/thread-border-router.md` section: rsthread-br-posix)

## Phase 17 – ESP32-C6/H2 targets

Target boards: **ESP32-C6-DevKitC-1** and **M5Stack NanoC6** (both ESP32-C6 RISC-V; same firmware binary, board feature flags for LED / button pins).
Target is `riscv32imac-unknown-none-elf` (already in toolchain and `check-esp32c6` alias).
Reference: Phase 12 (nRF52840 bring-up). Radio notes: `docs/radio-contract.md` §EspRadio row.

The `rs-thread-platform::Radio` trait is already identical to `esp-rs/openthread`'s `Radio` (by design — ADR research); the `EspRadio` wrapper in that crate drops in directly. BLE coexistence is handled by the ESP COEX framework inside `esp-radio`, not by the Thread stack.

### 17a – `rs-thread-esp` crate

- [x] New crate `crates/rs-thread-esp` mirroring `rs-thread-nrf` structure (`lib.rs`, `radio.rs`, `clock.rs`, `flash.rs`):
  - Soft-MAC radio backend wrapping `esp-ieee802154 0.5` / `esp-hal 0.23`: no hardware ACK offload (`MacCapabilities::empty()`), no BLE coexistence (future work in 17d)
  - `Clock` / `Alarm` over `embassy-time` (esp-hal's `SystemTimer`-backed time driver)
  - Entropy from `esp-hal::rng::Rng` implementing `rand_core::CryptoRng`
  - Flash-backed settings: `EspFlash` over `embedded-storage-async` backed by `esp-storage` with `nor-flash` feature
  - Target arch guard `cfg(target_arch = "riscv32")` for all hardware deps (same pattern as nRF's `target_arch = "arm"`)
  - Chip selection via crate features `esp32c6` (default) / `esp32h2`; `defmt` optional feature
  - [x] Verify `cargo check-esp32c6 -p rs-thread-esp` builds clean

### 17b – `examples/esp32c6-leader` (FTD firmware)

- [ ] Board bring-up: clock init, radio init, RNG, LED (GPIO / WS2812; feature flags `devkitc1` / `nanoc6`), panic handler (RTT + halt)
- [ ] Standalone FTD leader firmware (channel 15, PAN 0x1234, `rs-thread`), beacons out, `scan` variant with energy and active scan
  - Only one radio backend (`esp-radio`), no `radio-embassy` pitfall from Phase 12
  - [ ] Flash / RAM budget measured and recorded in `docs/memory-budget.md` (ESP32-C6: 4 MB flash, 512 KB SRAM; target ≤ 450 KB flash / ≤ 100 KB static RAM for a bare FTD leader)
- [ ] CLI firmware (`--bin cli`, USB-CDC serial or UART0): same `rs-thread-cli` command set as `examples/nrf52840-leader --bin cli`; persistent settings via `rs-thread-flash`, factory reset via GPIO9 at boot
- [ ] Interop against `ot-cli-ftd`: rs-thread attaches as child, upgrades to router, pings both ways with 0 loss; rs-thread Leader with an OT node joining as child / router; leader reset / partition merge (same test protocol as `docs/csl-hardware.md` for nRF)
  - [ ] Document results in `docs/memory-budget.md` (flash / RAM) and a new `docs/esp32c6-hardware.md` (interop results, radio quirks)

### 17c – Hardware crypto

- [x] `EspCrypto` backend in `crates/rs-thread-esp/src/crypto.rs` (feature `ecdsa`):
  - `EspAes128`: hardware AES-128 block cipher via `esp-hal::aes::Aes` + critical-section mutex
  - `EspCrypto: CryptoBackend` (hardware AES, software SHA-256/HMAC-SHA256)
  - `EspP256: P256` delegates to `SoftP256`; note left that RSA/MPI acceleration is a future optimization
  - `EcdsaP256 for EspCrypto` delegates to `SoftCrypto`
  - ESP32-C6 RSA/MPI confirmed to expose `RsaModularMultiplication` for Montgomery multiply — full MPI-backed P-256 deferred (no ECC accelerator, 2–3× speedup estimate, needs §§ of field-arithmetic wrapper)
- [ ] Benchmark `EspAes128` vs. `SoftAes128` and document in `docs/memory-budget.md`
- [ ] `EspCrypto` referenced in Phase 12 as "Phase 17" deliverables; close those items once benchmarks done

### 17d – `examples/esp32c6-light` (rs-matter on-off light)

- [ ] Thread + BLE commissioning:
  - BLE: `esp-radio` BLE controller + `trouble-host` 0.8 (mirrors `nrf-sdc` + `trouble-host` on nRF)
  - BTP GATT peripheral reused from `rs_thread_matter::ble` (`ble-trouble` feature); `ThreadCoexRunner` for BLE-next-to-Thread
  - ESP COEX framework handles radio arbitration (no changes to the Thread stack)
- [ ] Flash KV store: rs-matter settings and Thread settings in separate NVS partitions backed by `rs-thread-flash`
- [ ] Hardware crypto: `EspP256` for EC-JPAKE and ECDSA P-256 (Phase 17c); `EspAesCcm` for AES
- [ ] On-network rehearsal before BLE: `RSTHREAD_DATASET` build-time dataset, SLAAC address from an on-mesh prefix, SRP host and `_matterc._udp` registered with an OpenThread SRP server, ping from the peer
- [ ] BLE commissioning rehearsal: `chip-tool pairing ble-thread` via OTBR; on/off toggle; soak test (≥ 1 hour, random resets, factory reset back to advertising)
  - [ ] Document commissioning results in `docs/thread-border-router.md` (ESP32-C6 section) and `docs/memory-budget.md`

### 17e – Interop and test coverage

- [ ] Hardware interop against `ot-cli-ftd` on a second board (ESP32-C6-DevKitC-1 as OT node, or nRF52840 DK):
  - Child attach, router upgrade, pings both ways, leader reset / partition merge; same 12-min protocol as nRF interop
  - [ ] CSL interop (rs-thread SSED under an OT parent; OT SSED under rs-thread parent) if `EspRadio` advertises `TIMED_RECEIVE` / `CSL_RECEIVER` caps
- [ ] Thread-cert pass-rate with ESP32-C6 in virtual time (`rs-thread-cli-vt` built for `riscv32imac`):
  - 5.x / 9.x all-OT, each-node, all-rs-thread; LowPower (SED/SSED); same harness as `crates/rs-thread-sim/tests/thread_cert.rs`
  - [ ] Update `docs/test-status.md` with ESP32-C6 results
- [ ] Commissioning interop: rs-thread Joiner against OTBR commissioner on macOS (blocked on Phase 12 open item: `otbr-agent` exits on petition; resolve that first)
- [ ] Update `docs/test-plan-status.md` and `docs/memory-budget.md` with ESP32-C6 numbers
- [ ] Close M5 milestone when: ESP32-C6 leader attaches to an OT/OTBR network and the light is commissioned on hardware

## Phase 18 – Maintenance

- [ ] Align with current OpenThread main branch
- [ ] Align with later Thread versions

## Milestones

- [x] **M1 – Codecs**: MAC + 6LoWPAN + MLE TLVs + crypto, verified by OT vectors and differential tests
  - [x] Codecs for MAC, 6LoWPAN, MLE TLVs, crypto, MeshCoP TLVs, network data, CoAP
  - [x] OT unit-test vectors ported (`tests/unit/*.cpp`, `docs/ot-unit-test-port.md`)
  - [x] Differential tests against `openthread-sys` (`crates/rs-thread-difftest`, `docs/differential-tests.md`; CoAP, the large MLE TLVs and the MeshCoP TLVs outside the dataset are not covered differentially)
- [x] **M2 – MTD in sim**: Rust MED/SED attaches to OT leader in simulation; ping works
  - [x] True MTD build (`rs-thread-cli-vt-mtd`, `--no-default-features --features sim-mtd`: no ftd, commissioner, Border Agent): MED, SED and SSED attach to an OT leader and to an OT router and ping both ways incl. fragmented datagrams (`rs-thread-sim/tests/mtd.rs`); thread-cert runs with `mtd:<nodes>` (Cert_5_1_02, Cert_5_3_04, v1_2_LowPower_5_3_01) pass
  - [x] Mixed-test flake: two tests of csl.rs used the name `csl-off` and so one directory (one removed the other's working directory: `spawn node: NotFound`, settings of nodes mixed up); every test has its own directory now, and the port range (`VtSim::new_free`) is claimed by binding it free of nodes of other simulators, serialized with node starts (40 parallel runs of mixed, csl and mtd, no failure)
  - [x] MED: rs-thread MEDs attach to an OT leader and answer pings in the OT virtual-time simulation (Cert_5_3_04 nodes 4-7)
  - [x] SED: rs-thread SED in the mixed simulation (Cert_5_3_04 node 3, Cert_5_3_02 node 4, Cert_5_1_02 node 3 pass)
- [x] **M3 – FTD in sim**: Rust router/leader; mixed Rust/OT network passes core `thread-cert` 5.x cases
  - [x] Mixed OT/rs-thread network in OT's virtual-time simulation (`rs-thread-sim/tests/mixed.rs`), rs-thread as leader and as router
  - [x] `thread-cert` harness (`rs-thread-sim/tests/thread_cert.rs`)
  - [x] Core 5.1 / 5.2 / 5.3 cases pass with rs-thread in every role (273 of 273 runs: all OpenThread, each node rs-thread, all rs-thread; MTD build for the MED / SED nodes; `docs/test-status.md`). The five baseline failures were an `ot-cli-ftd` built without Border Router support, then DHCPv6 (5.3.8, 5.3.9)
- [x] **M4 – Commissioning & Matter**: Joiner + Commissioner interop with OT; SRP client; rs-matter device reachable over a Rust Thread node in sim
  - [x] SRP client (against the OTBR SRP server on hardware)
  - [x] rs-matter device reachable over a Rust Thread node in sim (`rs-thread-matter/tests/light.rs`) and on the nRF52840 through an OTBR
  - [x] Joiner + Commissioner interop with OT nodes in sim (`rs-thread-sim/tests/commissioning_mixed.rs`: OT Commissioner with an rs-thread FTD / MTD Joiner, rs-thread Commissioner with an OT Joiner, Joiner two hops away behind a Joiner Router of the other implementation, wrong PSKd on both sides, petition / keep-alive / resign and a refused second Commissioner, MGMT_ACTIVE_SET; thread-cert `Cert_8_*` pass in all configurations, `Cert_9_2_*` with the gaps listed in `docs/test-status.md`; not run on hardware)
- [ ] **M5 – Hardware**: nRF52840 + ESP32-C6 nodes join an OT/OTBR network
  - [x] nRF52840: joins OT nodes and an OTBR network (router, child, leader; Matter light commissioned through the OTBR)
  - [ ] ESP32-C6 (Phase 17)
- [ ] **M6 – Thread 1.2–1.4 features** and certification test-plan coverage
  - [ ] Test-plan gaps found by `docs/test-plan-status.md` (OpenThread `thread-cert` scripts, simulation only):
    - [x] 9.2.8, 9.2.9, 9.2.11 to 9.2.14, 9.2.18 pass (pending dataset delay, key switch frame counters, restore, scan servers)
    - [x] 5.7.1 to 5.7.3 pass (`networkdiagnostic` CLI, diagnostic server fixes)
    - [x] 6.2.2 passes
    - [x] 6.5.2 (the DUT reported a random extended address after a reset, so the script allow-listed the wrong one at the leader; the stored identity is now restored when the instance is created, also for the MTD build)
    - [x] LowPower 7.1.1, 7.1.2, 7.2.1 and the link-metrics functional tests (7.1.2: a 2 s ping with a 2 s poll period needs the keep-alive reset only at the default poll period; 7.2.1: data requests and LQI-less frames count in the series); the MTD build does not apply (the cases are not `is_mtd`)
    - [x] `v1_2_test_enhanced_keep_alive` node 2 (parent restore after `thread stop` / `start`: OT attaches from scratch, rs-thread restores and sends a Child Update Request; failed already before the link metrics work; fixed: the stored network information is restored only at the first start after instance creation, as OT)
    - [x] BBR / DUA / MLR (Thread 1.2): all 7 scripts pass (ot, each, all) with the sim `ot-cli-ftd` built with `OT_BACKBONE_ROUTER`; the Backbone link (DAD, ND proxy, multicast routing), MATN, BBR 5.11.1 and the `border_router` scripts need an OTBR / backbone harness (listed under Phase 9)
    - [~] OpenThread functional tests: SRP (14 of 15; 500 services needs more storage, fails all-OT too), DNS-SD, radio filter, anycast locator, child supervision, detach, route table, dataset updater, key rotation, service pass; netdata publisher, BR router-role upgrade, inform previous parent on reattach, IPv6 fragmentation, history tracker, factory diag; open: `coaps`
    - [ ] pktverify with `tshark` 4.6 is unreliable (dissection differs); pin the Wireshark version the scripts were written for
    - [x] pktverify: the 15 cases that passed with OpenThread only now pass with rs-thread too; 47 cases pass with both

## Open questions

- ~~Own IPv6 stack vs. `smoltcp`?~~ → own stack (see Phase 4)
- ~~Async vs. sans-IO?~~ → both: sans-IO core + first-class async facade for rs-matter
- ~~License~~ → Apache-2.0
- ~~BLE commissioning for Matter (BTP)~~ → left to rs-matter; TCAT engine in `-meshcop` (see Phase 0)
