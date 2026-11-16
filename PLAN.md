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
  - [x] Fix `tools/openthread-sys/build.rs`: no `script/bootstrap`, cmake + ninja build into `OUT_DIR` (simulation platform, virtual time, `MinSizeRel`, one build tree), bindings regenerated; the reference nodes `ot-cli-ftd` (feature `mtd`: also `ot-cli-mtd`) are copied to `<target dir>/ot-sim/`; the source tree is `vendor/openthread` or `$OPENTHREAD_SRC`
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
  - [x] Platform clock/alarm trait: `opentrust_platform::time::{Clock, Alarm}`, embassy-time implementations in `opentrust-embassy` / `opentrust-nrf`
  - [ ] `Trickle::set_interval_max` (OT `SetIntervalMax`) when MPL/advertisements need it
- [x] Message buffer pool (fixed slots, headroom for prepends, intrusive priority queue, no `unsafe`) like OT `MessagePool`
- [x] Settings: OT-compatible `SettingsKey`s, `NetworkInfo`/`ParentInfo` codecs (OT byte layout); `opentrust_platform::SettingsStore` + `RamSettings`
  - [ ] `ChildInfo` and dataset codecs (with MLE / MeshCoP)
- [x] Crypto trait: AES-128-CCM*, AES-CMAC/HMAC-SHA256, KDF (Thread key derivation §7), PBKDF2-CMAC for PSKc, EC-JPAKE + DTLS 1.2 deps; software impls (RustCrypto) + HW-accelerated backends (nrf CryptoCell/ESP AES)
  - [x] `opentrust_core::crypto`: `CryptoBackend` trait, CCM* (M=0/4/8/16), MAC/MLE nonces, MAC/MLE/TREL keys, HKDF, TLS 1.2 PRF, KEK, PBKDF2-AES-CMAC-PRF-128/PSKc, `soft-crypto` backend; spec + OT unit-test vectors
  - [ ] HW backends (Phase 12)
  - [x] EC-JPAKE + DTLS 1.2 (Phase 5b, see ADR 0001)
  - [x] Cross-check TREL key, KEK and MLE-message vectors (self-generated) against `openthread-sys`: `crates/opentrust-difftest/tests/crypto.rs` compares the TREL key (OT's HKDF), the KEK (SHA-256 of the DTLS key block; TLS 1.2 PRF against P_SHA256 composed of OT's HMAC), the Thread MLE / MAC keys (OT `KeyManager`), the MLE nonce and CCM* (OT `AesCcm`); the assembly of the MLE aux header and AAD is not compared with OT's `Mle` class (`docs/differential-tests.md`)
  - [x] Secret key types are not `Copy`, zeroize on drop, constant-time `==`
- [x] Entropy: `opentrust_platform::Entropy` = `rand_core::CryptoRng` (0.10, same as rs-matter/esp-rs openthread)
- [x] Decide EC-JPAKE / DTLS 1.2 source (→ [ADR 0001](docs/decisions/0001-ecjpake-dtls.md), accepted: Rust EC-JPAKE on `p256` + minimal sans-IO DTLS 1.2, mbedTLS only as test oracle): no mainstream Rust crate implements the EC-JPAKE TLS cipher suite (draft-cragie-tls-ecjpake-01) → port from mbedTLS vs. own implementation on RustCrypto `p256`; check whether rs-matter's `Crypto` trait can be shared

## Phase 2 – IEEE 802.15.4 MAC (§3, 802.15.4-2015/2006)

- [x] Frame parse/build (`opentrust_mac::frame`): header IEs, payload IEs, security header, versions 2003/2006/2015, imm/enh ACK, wake-up frames
- [x] MAC security (`opentrust_mac::security`): `KeyManager` (prev/cur/next keys, key switch guard, rotation), key ID mode 1/2, frame counter + store-ahead, `LinkFrameCounters` replay check, enh-ACK security
- [x] Radio trait (`opentrust_platform::radio`, mirrors esp-rs/openthread `Radio`; `TestRadio`; `SoftMacNeeds`) + `time::{Clock, Alarm, MockClock}`
- [x] Sans-IO MAC (`opentrust_mac::mac`) + async `MacDriver`: CSMA-CA, retries, ack handling incl. software ACK / ACK timeout per `SoftMacNeeds`, rx filtering
- [x] Active scan / energy scan (radio-only); MLE Discovery scan → Phase 6
- [x] Data polling (SED), indirect transmission queue (parent side), source match table
- [x] CSL receiver (SSED) and transmitter (parent) + enhanced ACK with CSL IE (Thread 1.2+): sample windows (`ReceiveAt` / software sampling), phase math, CSL IE update + re-secure per attempt, per-child sync from CSL IEs, timed indirect tx with guard times
  - [x] CSL IE in MAC-built data polls (2015 poll frame with the CSL IE, no retransmission, 15 failures tolerated, retx period bounded by the CSL period, keep-alive timer reset by acknowledged CSL frames; the MLE bounds the poll period by the CSL timeout)
  - [x] CSL synchronized timeout, CSL Channel / Accuracy TLVs, child CSL parameters from MLE (`opentrust_mle::csl`, `Child::csl_*`, Phase 9c)
  - [ ] CSL broadcast / wake-up frame (TL2 wake-up coordinator and end device, Thread 1.4): the wake-up frame builder / parser, Rendezvous Time / Connection IEs and the Wake-up Channel TLV exist; the wake-up transmit sequence (OT `WakeupTxScheduler`), the wake-up listen window and the rendezvous with the Parent Request still need to be built (Phase 9)
  - [x] Hardware-ACK radios: CSL IE in hardware enh-ACKs needs the schedule only (`set_csl` done; verified on the nRF52840 against OpenThread)
  - [ ] Hardware-ACK radios: link-metrics IE needs a trait method (`configure_enh_ack_probing`)
- [x] Enh-ACK based Link Metrics probing, MAC part: per-initiator metric config, Thread vendor IE in enh-ACKs, initiator-side decode (`Event::EnhAckLinkMetrics`)
  - [x] MLE Link Metrics Management / Report TLVs, forward tracking series, single probe (`opentrust_mle::link_metrics`; the MAC-to-MLE calls are listed in Phase 6)
- [x] Unit tests against OT frame vectors (`tests/unit/test_mac_frame.cpp` vectors)
- [x] Wire `KeyManager` into the MAC/driver (push `mac_keys()`/frame counter to radios with HW tx security, feed back used counters), end-to-end secured data frame + enh-ACK + key sequence switch tests
- [x] Const-generic capacities for MAC queues (`Mac<S, G, TXQ, IND, EVQ, POLLQ, NBQ, CSLQ>`, defaults 4/8/8/4/32/8)
  - [ ] Capacities of the enh-ACK probing tables (fixed 8)
- [x] Verify CSL timing against OpenThread on a simulated radio medium: `opentrust_sim::vt` has a virtual radio clock; the MAC samples the CSL windows and builds the enhanced ACKs with the CSL IE as OpenThread's simulation radio does; mixed tests `crates/opentrust-sim/tests/csl.rs` (OpenTrust SSED under an OpenThread parent, OpenThread SSED under an OpenTrust parent, both ends OpenTrust: attach, CSL synchronized, pings both ways inside one CSL period without data polls, fragmented pings, CSL channel change, CSL off) and the cert cases `v1_2_LowPower_5_3_01_SSEDAttachment` (all runs pass) and `v1_2_test_csl_transmission` (see `docs/test-status.md`)
  - [ ] The simulated radio has no timed receive / transmit (`RECEIVE_TIMING`, `TRANSMIT_TIMING`): that path of the MAC (`ReceiveAt`, `SetCsl`, radio-timed tx) is covered by unit tests only

## Phase 3 – 6LoWPAN adaptation (§3.3–3.5, RFC 4944/6282)

- [x] IPHC / NHC (UDP) compression & decompression with context IDs (`opentrust_lowpan::iphc`: stateless/stateful unicast and multicast, TF/NH/HLIM, NHC UDP/Hop-by-Hop/IP-in-IP, `ContextProvider` trait + `ContextTable`, ECN helpers)
  - [x] Network Data implementing `ContextProvider` (Phase 7b, `opentrust_mesh::netdata::consumers::NetDataContexts`; context 0 = mesh-local prefix is built in, `ContextTable::set_mesh_local` stays for other users)
  - [ ] Compression of Destination Options / Routing / Fragment extension headers (OT only compresses Hop-by-Hop; others are sent inline)
- [x] Mesh header, fragmentation header, reassembly with timeouts (`mesh`, `frag`, `reassembly`: `MeshHeader`, `FragmentHeader`, sans-IO `Fragmenter`, fixed-capacity `Reassembler`, 2 s timeout like OT)
  - [ ] Out-of-order reassembly (OT drops out-of-order fragments; so do we)
  - [x] Sleepy-device reassembly rules (clear list on new secure first fragment / mismatch): `Reassembler::set_sleepy`, set by the forwarder from the device mode on every fragment; a sleepy device keeps one datagram, a secure first fragment or an unmatched secure next fragment drops the rest like OT `HandleFragment`
  - [x] Reassembling and queueing the Tx side (`Fragmenter` frames -> MAC) is done by the mesh forwarder and the `Instance` (frames wait in a bounded queue for room in the MAC transmit queue)
  - [ ] MLE messages that need fragmentation must be link-secured (`MeshForwarder` retry with security) and delay-aware queue management (Phase 6)
- [x] Mesh forwarding (mesh header) for FTD (`forward`: `classify`/`parse_frame`, `handle_mesh` deliver/forward/drop with `LocalRlocs` + `NextHops` traits, hops-left handling, 2-hop loop detection)
  - [x] Routing table / next-hop provider, ICMPv6 destination-unreachable decisions, EID-RLOC cache update from forwarded frames (Phase 7a: `opentrust_mesh::forwarder`, which drives `forward`'s rules on `Mle::next_hop_and_path_cost`)
  - [ ] Forwarding queue with message priorities, aging, delay-aware queue management and fragment priority tracking (the forwarder routes and transmits a datagram at once)
- [x] Port OT `test_lowpan.cpp` vectors as Rust tests (all 58 IPHC vectors + `TestLowpanMeshHeader` + `TestLowpanFragmentHeader`), plus randomized round-trips and no-panic tests
  - [x] Differential tests against OpenThread's `Lowpan` via `openthread-sys`: `crates/opentrust-difftest/tests/lowpan.rs` (random datagrams, contexts and link-layer addresses: identical compressed bytes, same decompression; OT quirks classified, one OpenTrust bug fixed; `docs/differential-tests.md`)

## Phase 4 – IPv6 / UDP / ICMPv6 core (§5)

- [x] Own minimal IPv6 stack in `opentrust-net`, modeled on OpenThread's `src/core/net` (`smoltcp` lacks Thread specifics: RLOC/ALOC, MPL, mesh-local scoping): fixed + extension headers (Hop-by-Hop/MPL/padding, Fragment, Routing/Destination skip), pseudo-header checksum, ICMPv6 builders (`header`, `checksum`, `icmp6`)
- [x] Addresses (`addr`, `netif`, `slaac`): link-local, ML-EID, RLOC, ALOCs, GUA/OMR via SLAAC (RFC 7217 IIDs as OT, deprecation timer), unicast/multicast tables with fixed/internal/external subscriptions, Thread all-nodes/routers/MPL-forwarders and the mesh-local-derived all-Thread-nodes groups, RFC 6724-subset source selection
- [x] Sans-IO IPv6 core (`ip6::Ip6`): receive path (validate, receive/forward-to-Thread/forward-to-host decision with `Ip6Env` hooks, extension headers, IPv6-in-IPv6 tunnel, checksum verification, hop limit, ICMPv6/TMF forward filters), send path (source selection, MPL option insertion, tunnelling of larger-scope multicast, loopback), ICMPv6 echo responder and rate-limited error builder
- [x] MPL (RFC 7731) as OpenThread implements it (`mpl`): seed set, buffered retransmissions with jittered deadlines, duplicate suppression, seed ID from RLOC16
- [x] UDP sockets (`udp`): fixed-capacity socket table, bind/connect/ephemeral ports 49152-65535 (OT rules), bounded receive queues with per-packet metadata, internal receiver hooks for MLE (19788) and TMF (61631); mapping to the Phase 10 `edge-nal` facade documented in the module
- [x] Address resolution data structures (`resolver`): EID-to-RLOC cache with OT's cached/snooped/query/query-retry states, timeouts, exponential retry delay and ramp-down, eviction order, snooping, notification and duplicate-address decisions, address-query/-error decision helpers
  - [x] TMF messages `/a/aq`, `/a/an`, `/a/ae` (CoAP encoding, TLVs, sending, ACKs) wired to `resolver::ResolverEvent`, router-side child lookup on the MLE child table, duplicate address handling (Phase 7a: `opentrust_mesh::address`)
    - [x] DUA duplicate notification in `/a/ae` (`address::AddressErrorOutcome::DuplicateDomainUnicast`, Phase 9)
    - [ ] Backbone Query extension of `/a/aq` / `/b/bq` (belongs to the Backbone Router server role, Phase 9)
  - [x] Mesh forwarder glue: hold datagrams while an EID resolves, `HandleResolved`, ICMPv6 destination-unreachable on no route/resolution failure, snooping from forwarded frames (Phase 7a: `opentrust_mesh::forwarder`)
  - [x] Network Data providers for `Ip6Env` (`route_lookup`, `is_on_mesh`) and for SLAAC (`OnMeshPrefix` list) (Phase 7b, `opentrust_mesh::netdata::lookup::NetDataIp6Env`, `consumers::slaac_prefixes`)
  - [x] Persisted SLAAC IID secret key in settings (`Instance::thread_start` loads / stores `SettingsKey::SlaacIidSecretKey`)
- [x] DHCPv6 address allocation (OT `Dhcp6Client`/`Dhcp6Server`: Solicit / Rapid Commit / Reply, DHCP agent ALOCs; `opentrust-instance` `dhcp6`; needed by thread-cert 5.3.8 / 5.3.9)
- [x] Domain Unicast Address client (Thread 1.2, `/n/dr`, `/n/dn`, duplicate DUA handling in `/a/ae`: `opentrust_mesh::dua`); `/b/bq` / `/b/bb` belong to the Backbone Router server role (Phase 9)
- [x] Multicast Listener Registration (MLR, `/n/mr`) for subscribed multicast groups (`opentrust_mesh::mlr`, Phase 9)
- [ ] IPv6 fragmentation/reassembly above the 6LoWPAN layer (OT `OPENTHREAD_CONFIG_IP6_FRAGMENTATION_ENABLE`, off by default; not needed for 1280-byte Thread datagrams)
- [ ] Host (border router) interface: `RemoveMplOption` before passing to host, host-origin multicast policy (Phase 9, border routing)

## Phase 5 – CoAP / CoAPS

- [x] Generic TLV utilities (`opentrust_core::tlv`: normal/extended TLVs, iterator, find, typed read/write; OT `test_tlv.cpp` ported)
- [x] CoAP (RFC 7252) no_std: message codec (`opentrust_coap::message`), sans-IO endpoint (`endpoint`): confirmable retransmission, separate responses, RST/empty ACK, multicast NON, resource table, duplicate detection + response cache; differential tests against `coap-lite`
  - [ ] Block-wise transfer (RFC 7959) and Observe: off in OT's default config; only the `BlockOption` codec exists
- [x] TMF agent on UDP 61631 (`opentrust_coap::tmf`): URI list, DSCP/priority mapping, `IsTmfMessage` filtering, handler dispatcher, `UdpSockets` receiver registration
  - [ ] Registering more TMF resources than the agent's capacity must return an error (today `register_uris` / `set_tmf_extension` in `opentrust-instance` ignore the failure, and the extra URIs are silently not served; found when the Network Diagnostics URIs pushed the agent past 16 resources)
  - [x] `/a/aq`, `/a/an`, `/a/ae` wired to `resolver::ResolverEvent` and `/a/as`, `/a/ar` handlers (Phase 7a, `opentrust-mesh`)
  - [ ] MeshCoP and Network Data handlers (`/a/sd`, `/c/*`, `/n/*`; Phases 7-8)
- [x] Phase 5b: DTLS 1.2 + EC-JPAKE (CoAPS for commissioning, ADR 0001): `opentrust_core::crypto::ecjpake` (feature `ecjpake`, RustCrypto `p256`, all mbedTLS self-test vectors), crate `opentrust-dtls` (sans-IO DTLS 1.2, `TLS_ECJPAKE_WITH_AES_128_CCM_8` only, client + server, cookies, retransmission, fragmentation, KEK) and `opentrust_dtls::coaps::Coaps` behind `opentrust_coap::endpoint::SecureTransport`; manually interop-tested against mbedTLS 3.6.0 `ssl_server2`/`ssl_client2`
  - [ ] Automated differential/interop handshakes against `openthread-sys` / mbedTLS (Joiner and Commissioner, both roles, lossy links) (Phase 11)
  - [ ] Hardware P-256 backends for the `ecjpake::P256` trait (CryptoCell, CRACEN) and an rs-matter `EcPoint`/`EcScalar` adapter (Phase 12; ESP ECC in Phase 14)
  - [ ] Fuzz the record/handshake parsers and the EC-JPAKE readers (Phase 11)
  - [ ] Security review of the EC-JPAKE/DTLS code before M4 (ADR 0001); include the commissioning decisions listed under Phase 8b
  - [x] Wire into MeshCoP Joiner / Commissioner / Border Agent (relay, connection-attempt limits, guard times) (Phase 8b; the roles own `opentrust_dtls::Session` directly via `opentrust_meshcop::secure`)
    - [x] ePSKc (Thread 1.4 ephemeral PSKc on the Border Agent) (Phase 9: `epskc`, second Border Agent listener)

## Phase 6 – MLE (§4)

- [x] MLE message codec + all TLVs, MLE security (AES-CCM with key derivation) (Phase 6a, `opentrust-mle`: `tlv` typed parse/build of every Thread 1.4.1 MLE TLV, `message` commands + builder, `security` secure/unsecure + MLE frame counter store-ahead, vectors from the Phase 1 crypto reference, tamper/truncation tests)
- [x] Neighbor / child / router data model (`neighbor`: states, filters, `Child`/`Router`/`Parent`, `ChildTable<N>`, `RouterTable<N>`, `MleReplay`, `ChildInfo` settings), link quality (`link_quality`: RSS averager, margin to quality with hysteresis, costs; `test_link_quality.cpp` ported)
- [x] MLE UDP glue (`endpoint`: port 19788 receiver, hop limit 255 + addressing rules, `MleRx::parse`, `MleHandler` dispatch by command, `send` through the TMF `UdpSink`)
  - [x] Phase 6b: sans-IO `Mle<C>` core with the `MleEnv` context trait (keys, MAC/netif, tx, settings, Network Data hooks; `env`), child-side attach (`attach`: Parent Request phases and OT backoff, Parent Response collection, `IsBetterParent`, Child ID Request/Response, key sequence adoption), child role (`child`, `child_rx`: Child Update, keep-alive, data poll period from the timeout, supervision check, 4-attempt parent loss and re-attach, Data Request/Response, leader-data versioning), parent side behind feature `ftd` (default on; `parent`: Parent Request/Response with jitter, Child ID exchange with child RLOC16 allocation, address registration, Child Update, Data Request, child timeouts, supervision ticks, indirect hooks for SEDs, entered through `enter_router_role` for Phase 6c), persistence and fast re-attach (`persist`: `NetworkInfo`/`ParentInfo`/`ChildInfo`, store-ahead counters, restore via Child Update Request, restored children); two-core end-to-end test over byte buffers (`e2e_tests`)
    - [x] Network Data / dataset content (passed as bytes through `MleEnv`; Network Data in Phase 7b, Active / Pending Dataset in Phase 8a: `opentrust_meshcop::manager::Datasets` behind `MleEnv::{active,pending}_timestamp`, `{active,pending}_dataset`, `dataset_received`, which now take `now`)
    - [x] Announce send / receive (Phase 8a, `opentrust_mle::discovery`: `Mle::send_announce`, OT `HandleAnnounce` decisions, `MleEvent::AnnounceFromNewerNetwork`)
    - [x] Announce attach (`opentrust_mle::discovery`: newer-network Announce -> switch channel / PAN ID after `ANNOUNCE_PROCESS_TIMEOUT` via `MleEnv::set_pan_channel_and_id`, attach there, inform the old channel on success, restore the old channel / PAN ID on failure) and Orphan Announces on all channels after unanswered Parent Requests (`AttachState::Announce`)
    - [x] Reattach with the stored Active / Pending Dataset (`ReattachState`, `MleEnv::{restore_dataset, apply_pending_configuration, clear_pending_dataset}`), periodic `AnnounceSender` (`announce_sender`: Trickle 688 s, channel cycle, equal-timestamp suppression, unicast Announce response)
    - [x] Graceful detach (`Mle::detach_gracefully`: zero-timeout Child Update / Address Release, 1 s wait, `MleEvent::DetachedGracefully`)
    - [x] CSL parent metric in parent selection (`opentrust_mle::csl::csl_parent_metric`, CSL Clock Accuracy TLV from Parent Response, Phase 9c)
  - [x] Phase 6c (feature `ftd`): role state machine (`router`: `become_leader`, REED upgrade decision with `ROUTER_SELECTION_JITTER`, router downgrade, `ID_SEQUENCE_PERIOD`, router ID bookkeeping with `ID_REUSE_DELAY`, leader-side `handle_address_solicit` / `handle_address_release`, Connectivity / Route64 content from the live router table, path cost and next hop, `RouterConfig`, `DeviceProperties` leader weight with the `test_mle.cpp` vectors), router links (`router_link`: Link Request / Accept / Accept And Request, challenge / response, frame counters, delayed Link Accept, Link Accept timeout, `MAX_NEIGHBOR_AGE` re-request and removal, `UpdateRoutes` cost bookkeeping, router role restorer after a reset), Advertisements (`advert`: `opentrust_core::trickle` with OT parameters, Route64 content, router discovery, former-child takeover, FTD child router links, downgrade conditions, parent Advertisement handling), partitions (ComparePartitions, better-partition attach, FTD Parent Response rules per attach mode, leader loss after `NETWORK_ID_TIMEOUT`, new partition as leader, previous-partition avoidance, REED answering Parent Requests / Child ID Requests); tests with a multi-node simulator (`sim`, `router_tests`, `router_link_tests`, `advert_tests`, `partition_tests`, `mesh_tests`)
    - [x] Phase 7a hooks: TMF `/a/as` / `/a/ar` client and server around `MleEnv::request_router_id` / `release_router_id`, `Mle::address_solicit_reply`, `Mle::handle_address_solicit`, `Mle::handle_address_release` (`opentrust_mesh::router_id`); mesh forwarding from `Mle::next_hop_and_path_cost`; `Mle::resolve_routing_loop`; indirect hooks for sleepy children
    - [x] Network Data hooks (Phase 7b): leader reset on `MleEvent::LeaderStarted` (`netdata::leader::Leader::start`), version bumps through `Mle::set_leader_data` (`Leader::publish`, `Mle::network_data_updated`), Network Data bytes served through `MleEnv::network_data` / stored from `set_network_data`, stale Network Data entries on `MleEvent::RouterTableChanged` (`Leader::remove_stale_router_ids`)
    - [x] Hooks: alternate RLOC16 after REED -> router (`MleEnv::set_alternate_short_address`), `Mle::remove_child_that_moved`, `Mle::set_device_mode` FTD <-> MTD re-attach, address cache reactions to MLE events (`opentrust_mesh::address::handle_mle_event`)
    - [x] `Mle::remove_child_that_moved` (called by the `Instance` for mesh header frames that end at this router; frames it only forwards are not examined, see the differences file) and `handle_mle_event` (the `Instance` consumes the MLE events)
    - [ ] Border Router specific upgrade in `is_router_eligible` (the Security Policy part is done: `Mle::set_routing_policy`); Time Sync TLVs in Link Request / Accept / Advertisement
  - [x] Link Metrics Management / Report sub-TLV codecs, Forward Tracking Series, Enhanced-ACK configuration, Link Probe, Initiator and Subject (`opentrust_mle::link_metrics`, `link_metrics_roles`)
    - [ ] MAC glue: call `Mle::aggregate_link_metrics` for received data / data request / ACK frames and `Mle::process_enh_ack_ie_data` for `Event::EnhAckLinkMetrics`; `MleEnv::configure_enh_ack_probing` onto the MAC's per-initiator configuration
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

- [x] Router ID assignment over TMF (Phase 7a, `opentrust_mesh::router_id`: Leader `/a/as`, `/a/ar` CoAP handlers, `RouterIdOutbox` client, status codes and failure handling as OT; the allocation itself is in `opentrust-mle`, Phase 6c); Thread network-layer TLV codec `opentrust_mesh::tlv`
- [x] Mesh forwarding on the routing table (Phase 7a, `opentrust_mesh::forwarder`: `MeshForwarder` route lookup incl. child / on-link / Network Data hooks, mesh header insertion, forwarding with hops left and 2-hop loop detection, held datagrams and `handle_resolved`, destination unreachable decisions, snooping; address resolution TMF in `opentrust_mesh::address`)
  - [x] Routing through Network Data (Phase 7b): `netdata::lookup::Lookup` implements the `NetworkData` trait (external routes by longest prefix / preference / path cost, default route, on-mesh, anycast lookup)
  - [x] Sleepy child -> rx-on mode change converts queued indirect messages to direct (`MeshForwarder::child_became_rx_on`)
  - [x] `Mle::child_message_sent` is called by the `Instance` after every forwarder call
  - [x] CSL transmitter for sleepy children (`IndirectQueue::flush_csl`, `MeshForwarder::csl_flush`, `TxFrame::csl`; the MAC does the window timing and keeps the data poll as fallback), multi-radio selection hook (`RadioLink`, `trel::RadioSelector`, feature `trel`) (Phase 9c)
  - [ ] CSMA collision-avoidance delay of forwarded frames
- [x] Child table & forwarding to sleepy children (Phase 7a, `opentrust_mesh::indirect`: per-child queue, Frame Pending / source match bookkeeping, fragments per data poll, supervision messages, purge on child removal; the child table itself is `opentrust-mle`)
- [x] Network Data (§5.13–5.15, Phase 7b, `opentrust_mesh::netdata`): TLV codec with typed iterators and the stable copy (`tlv`, `NetworkData<N>`; vectors of `test_network_data.cpp`), leader store (`leader`: `/a/sd` registration with validation and in-place merge, context ID allocation with 5 min reuse delay, service IDs, stale router / child entry removal, version and stable version), `/a/sd` server and client (`server_data`), local data and the OT notifier timing (`local`, `notifier`), consumers (`lookup`, `consumers`), distribution through MLE (`Leader::publish` + `Mle::network_data_updated`; full and stable data from `MleEnv::network_data`); multi-node tests in `netdata_sim_tests`
  - [x] Publisher is part of the mesh simulator (`MeshSim` polls `TmfNode::publisher`); tests: five publishers settle at three entries and a replacement takes over (`netdata_sim_tests`)
  - [x] Network Data Publisher (`netdata::publisher`: on-mesh prefix, external route, DNS/SRP anycast / unicast entries) and the `kBorderRouterRequest` decision in the notifier (`schedule_router_upgrade` / `router_upgrade_tick`)
  - [x] Backbone Router service and Domain Prefix entries are read by `netdata::backbone` (Primary BBR selection, BBR Dataset, Domain Prefix events; client side, Phase 9)
  - [ ] Consume the router upgrade flag in the MLE (`is_router_eligible` Border Router rule), DNS/SRP query helpers (client side done in `opentrust-dns`), DHCPv6 / ND agent ALOC subscription, Publisher driven by the Border Routing Manager (requester quotas)
- [x] Anycast locators, Service ALOCs (Phase 7b: `netdata::aloc` (leader, service and commissioner ALOC set maintenance), `netdata::anycast` (`/a/yl`), `lookup::anycast_lookup` for leader / service / commissioner / DHCP / ND ALOCs)
- [x] Commissioning datasets (Phase 8a: Active / Pending Operational Dataset, delay timer in `opentrust_meshcop::{dataset, manager, mgmt}`; the Commissioning Data TLV of Network Data is written by `Leader::set_commissioning_data` and `opentrust_meshcop::leader`)

## Phase 8 – MeshCoP / Commissioning (§8)

Phase 8a (crate `opentrust-meshcop`, leader / router code behind feature `ftd`):

- [x] MeshCoP TLV codec (`tlv`: all section 8.10 TLVs, Security Policy 1.2+ layout, Channel Mask page 0, State, Discovery Request / Response), Timestamp ordering (`timestamp`; `opentrust_mle::tlv::Timestamp::compare`), Steering Data bloom filter, Joiner ID, Joiner Discerner (`steering`; vectors of `test_meshcop.cpp`)
- [x] Operational Dataset type (`dataset`: fixed 254 byte TLV buffer, validation, typed setters; vectors of `test_dataset.cpp`)
- [x] Active / Pending dataset management (`manager::Datasets`: network and local timestamps, persistence hooks `DatasetEnv::{store, load, delete}`, Pending delay timer -> Active, timestamp rules on receipt through MLE, MGMT_SET retry toward the leader) and `/c/ag` `/c/pg` `/c/as` `/c/ps` `/c/ar` (`mgmt`: leader accept / reject rules, partial updates from the commissioner, Active updates that change connectivity become Pending, `/c/dc` notification, clients)
- [x] Security Policy feeds router eligibility (`opentrust_mle::RoutingPolicy`, `Mle::set_routing_policy`)
- [x] Leader commissioner session (`leader`, formerly `commissioner`: `/c/lp` petition, `/c/la` keep-alive, 50 s timeout, resign, `/c/cs` Commissioner Set, `/c/cg` Commissioner Get, Commissioning Data in Network Data)
- [x] Discovery (`opentrust_mle::discovery` transport, `opentrust_meshcop::discovery` content, Steering Data filter, active scanner state machine), MLE Announce send / receive
- [x] Energy Scan, PAN ID Query, Announce Begin servers and commissioner-side requests (`scan`: `/c/es` `/c/er` `/c/pq` `/c/pc` `/c/ab`)
- [x] Multi-node tests (`net_sim`, `sim_tests`, `sim_scan_tests` over the MLE simulator with a TMF agent, dataset managers and commissioner state per node)
- [x] Dataset Updater (`opentrust_meshcop::updater`) and persistence of the Pending delay across resets (checkpoint every 60 s)
- [x] `MGMT_COMMISSIONER_GET` by a commissioner client for the Commissioner Dataset (Phase 8b: `Commissioner::send_commissioner_get`, `MgmtResponse::CommissionerGet`)
- [x] Announce attach state and Orphan Announces (see Phase 6b)
- [x] Reattach with the stored Active / Pending Dataset, periodic Announce sender (see Phase 6b; on the nRF52840 light the stored dataset and network info restore the role after reset, also against a border router whose dataset changed without a newer timestamp)

Phase 8b (security part; features `ftd`, `commissioner`, `border-agent`, all default; a joiner-only device uses `default-features = false`):

- [x] Joiner (`joiner`, `pskd`): PSKd validation and secret handling, filtered discovery with OT candidate ranking, DTLS EC-JPAKE with the PSKd over the Joiner UDP port (unsecured link), JOIN_FIN with vendor TLVs / Provisioning URL, Joiner Entrust accepted only under key ID mode 0 (KEK), dataset saved, retries over the candidates, timeouts, events
- [x] Joiner Router (`joiner_router`, feature `ftd`): Joiner UDP port from the Commissioning Data, relay `/c/rx` `/c/tx`, delayed Joiner Entrust under the KEK (dedicated CoAP endpoint, one in flight), answer handling; KEK derivation is in `opentrust-dtls` (`Session::kek`)
- [x] MAC key ID mode 0 (`opentrust_mac::security::KeyManager::set_kek`)
- [x] Commissioner (`commissioner`): petition / keep-alive / resign, session ID, Commissioner ALOC, Joiner list (any / EUI-64 / discerner, PSKd, expiry), Steering Data and `/c/cs`, `/c/rx` -> DTLS server per Joiner with that Joiner's PSKd, JOIN_FIN, `/c/tx` with the KEK, session timeout, Joiner removal, MGMT_COMMISSIONER_GET / SET, generic management requests; on-mesh `MeshTransport`
- [x] Border Agent (`border_agent`): DTLS server keyed with the PSKc, COMM_PET / COMM_KA forwarding, local `/c/cg` `/c/ag` `/c/pg` (`kIgnoreSecurityPolicyFlags`), `/c/tx`, `/c/rx`, UDP proxy `/c/ut` `/c/ur`, Border Agent ID, native commissioner flag in Discovery Responses (`discovery::build_response_with_border_agent`), keep-alive timeout, guard time, connection-attempt limit; external Commissioner client (`BorderAgentClient`, `ExternalTransport`)
- [x] Tests: unit tests per role (real Joiner against Commissioner / Border Agent through relay TLVs), end-to-end in the meshcop simulator (`net_sim_commissioning`, `commissioning_sim_tests`)
- [x] ePSKc on the Border Agent (Phase 9): separate listener, single use, timeout, attempt limit, `_meshcop-e._udp` hook
- [ ] DNS-SD `_meshcop._udp` advertisement and state bitmap, several concurrent Border Agent sessions, Border Agent counters
- [x] Wire the roles into a full stack (`opentrust-instance`): the `Instance` owns the Joiner, Joiner Router, leader commissioner session, Commissioner and Border Agent (`InstanceCrypto` with the EC-JPAKE curve type), per-frame link security classes (`LinkSecurity`: none, mode 1, KEK / mode 0, mode 2) in the forwarder and 6LoWPAN reassembly, the Joiner Entrust in key ID mode 0, KEK frames routed only to `handle_kek_datagram`, the Joiner UDP port relay, public API (`joiner_*`, `commissioner_*`, `border_agent_*`, ePSKc) and full-stack tests over the real MAC (`opentrust-sim/tests/commissioning.rs`)
- [x] ML-EID of a joined node: not a dataset hand-over bug (the Joiner, like OT, saves only network key, channel and PAN ID from the Joiner Entrust; prefix, ext PAN ID, name and timestamp come from the parent in the Child ID Response, and the joined node's Active Dataset matches the leader's). A router-capable child is not resolvable by ML-EID (OT address query skips full-function children) and its RLOC changes on the router upgrade; once a router with converged routes, address queries resolve in both directions (`commissioning.rs` asserts this)
- [ ] Border Agent UDP proxy receive (`handle_proxy_rx`) for datagrams to the Commissioner ALOC, Joiner Router events and `/c/dc` to an external Commissioner in the `Instance`; DNS-SD service publication hook
- [ ] Interop of Joiner / Commissioner / Border Agent against OpenThread (`openthread-sys`) nodes (Phase 11)

Security-relevant decisions for the review before M4:

- PSKd (`JoinerPskd`) and PSKc / KEK / network key (`opentrust_core::types` secret types) are wiped on drop or replacement, compared in constant time, redacted in `Debug` / `defmt`, and never logged (the commissioning modules log nothing; OT logs the PSKd).
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
- The meshcop simulator emulates key ID mode 0 by comparing KEKs; the full stack (`opentrust-sim/tests/commissioning.rs`) runs the real MAC path: the Joiner Entrust and its answer are key ID mode 0 frames under the KEK, the network key never appears in the clear on the air (asserted on every frame), a wrong PSKd yields no KEK frame, replayed mode 0 frames are dropped by the MAC once the KEK is discarded.
- Instance: key ID mode 0 frames are accepted only from the one peer of a running KEK exchange (the Joiner Router of our Joiner in the Entrust / Joined state, or the Joiner whose Joiner Entrust is in flight), only to our extended address, only with a frame counter above the last accepted one under the current KEK (OT checks none), and the reassembled datagram only as UDP from that peer's link-local address (IID = authenticated MAC source) to ours and the TMF port with a valid checksum; it reaches only `handle_kek_datagram`, never IPv6 / TMF / forwarding (OT treats mode 0 frames as link-secured for every layer). Drops are counted (`Instance::kek_drops`).
- Instance: key ID mode 0 is only framed between extended addresses (the nonce binds them); a KEK datagram is refused without an installed KEK; queued KEK frames fail at the MAC if the KEK was discarded meanwhile (no fallback to another key).
- Instance: 6LoWPAN reassembly is keyed by the security class, so an unsecured or mode 2 fragment cannot complete a mode 0 or mode 1 datagram; only mode 1 counts as link-layer secured above the MAC (mode 2 uses a public key).
- Instance: unsecured datagrams to the Joiner UDP port only between link-local unicast addresses; the Joiner takes them only from its Joiner Router, the Joiner Router relays only link-local sources; the port is open only while a Joiner runs or joining is allowed.
- Instance: the Joiner Entrust dataset (network key) is kept in a wiped `Dataset` until saved; a successful join starts Thread with it (OT leaves that to the application). The Border Agent gets the PSKc only on `border_agent_start` and loses it on stop; ePSKc keys go straight into `EphemeralKey`.

- [x] Reload of the leader's commissioner state after a reset (`LeaderState::restore_leader`; leader Network Data wait-for-sync: `Leader::start_restoring` / `restore` / `sync_timed_out`)

## Phase 9 – Thread 1.2 / 1.3 / 1.4 features

- [x] Domain Unicast Address & Backbone Router client support (1.2): `netdata::backbone`, `dua` (generation with persisted DAD counter, `/n/dr` registration, retry / reregistration, duplicate handling, proxy registration for children), mesh-simulator tests with a fake Primary BBR
  - [ ] Backbone Router server role (`BackboneRouter::Local` / `Manager`: BBR service publication, DUA ND proxying, `/b/bq`, `/b/ba`, `/b/bmr`, MLR on the backbone link)
  - [ ] Thread 1.1 parents (registration through the BBR service ALOC)
  - [x] Device glue in the `Instance` (`opentrust-instance::bbr`): `BackboneRouterLeader` from Network Data, `DuaManager` (DAD counter persisted under `DadInfo`, DUA registered with the address registration, proxy registration for children), `MlrManager` (external multicast and children); sim test `crates/opentrust-sim/tests/bbr.rs` with a fake Backbone Router as `Instance::set_tmf_extension`
- [x] Multicast Listener Registration (MLR) (1.2): `mlr` (device and child groups, `/n/mr`, timeouts, reregistration, failed addresses, `MlrState` in `Child`)
  - [ ] Commissioner MLR (Commissioner Session ID / Timeout TLVs)
- [x] Enhanced CSL (Phase 9c): SSED child side (`opentrust_mle::csl`: parameters, parent metric, poll period, response wait), parent side (`Child` CSL state, CSL timeout, `MleEnv::{csl_clock_accuracy, csl_child_update, csl_child_desync}`, `Mle::child_csl_synchronized`), CSL frame hand-over to the MAC (`opentrust_mesh::indirect`), CSL IE in data polls (`opentrust_mac`)
  - [ ] CSL wake-up (Thread 1.4): wake-up coordinator and wake-up end device (see the Phase 2 item)
  - [x] Glue in the `Instance` and end-to-end test: CSL IE receptions (frames and data polls) reach `Mle::child_csl_synchronized` and start the MAC's CSL child tracking (`Mac::csl_child_sample`), `csl_flush` / `parent_frame_received` / `Mac::set_csl` are called, the MAC puts the CSL IE into every frame an SSED sends to its parent, MLE messages of a CSL receiver are link-secured (OT `MeshForwarder` rule), the forwarder leaves room for the CSL IE (`CSL_IE_OVERHEAD`), frames for a CSL child wait in the MAC as 2015 frames until its window, a retransmitted frame with a CSL IE triggers a data poll; end-to-end over the virtual-time medium (`opentrust-sim/tests/csl.rs`)
  - [x] `v1_2_test_csl_transmission` with the leader OpenThread and the SSED OpenTrust ends at the last step: after the leader was away for longer than the timeout and came back, no Child Update Request of the SSED is seen within 5 s (the child counted no link failures of its parent: data polls without ACK now count, 4 in a row, 15 with CSL, and the child detaches and attaches anew like OT `UpdateNeighborOnSentFrame`; the data frames to the parent do not count yet)
  - [x] Live CSL period change on the nRF52840: the timed receive windows started 0.4 to 0.9 ms late (the backend moved a window handed over less than 3 ms ahead; the executor latency from the MAC timer to the driver call ate the margin), so the parent's frames were missed after the attach and after every change; the MAC timer lead of the Nordic backend is 5000 us now; 500 -> 100 -> 200 -> 1000 -> 500 ms, 50 of 50 pings at each period, no unacked parent frame (docs/csl-hardware.md)
  - [x] Slow sleepy attach on the nRF52840 (15 to 45 s): not a sleepy or radio problem. The OpenThread parent drops the Parent Requests of a reset RAM-settings CLI node while it still holds the child entry of the previous attach (MLE frame counter restarted at 0, replay check); with a fresh extended address the attach takes 1.0 to 1.8 s for SED, SSED and non-sleepy (10 attaches each). Parent loss: SED left after 6.2 s, SSED after 9.7 s (3 s poll period), both attached again 15 to 18 s after the parent restarted (docs/csl-hardware.md)
  - [ ] The CLI firmware does not keep the frame counters over a reset (noinit RAM or flash store), so repeated resets against one OpenThread parent need a new extended address or the child timeout
- [ ] Link Metrics (initiator & subject)
- [x] SRP client (RFC 9665) & DNS-SD client (1.3) — **pulled forward**: required by Matter for operational discovery (`_matter._tcp`); target M4 (`opentrust-dns`: `wire` / `rdata` DNS codec with name compression, TXT, KEY / SIG(0), OPT Update Lease; `client` DNS / DNS-SD client: AAAA, browse, SRV+TXT resolve; `srp` SRP client with SIG(0) ECDSA P-256 signing (`opentrust_core::crypto::ecdsa`), lease refresh, OT retry backoff, Network Data auto-start with unicast / anycast selection and server switching; tests against a scripted fake server, no simulator end-to-end test yet)
  - [ ] SRP server (advertising proxy), DNS-SD discovery proxy, mDNS, DNS over TCP, NAT64 (A record) queries
- [x] TREL hooks (optional, 1.3; feature `trel` of `opentrust-mesh`, default off): `trel::Trel` sans-IO link (packet header codec, peer table fed by the platform's DNS-SD results, TXT data `xa` / `xp`, unicast with deferred acks and ack timeouts, broadcast), `TrelPlatform` (UDP send, service registration), `TrelSecurity` (MAC frame security with the TREL key and its own frame counter, `FrameSecurity` impl), `RadioSelector` + `TxFrame::radio` in the forwarder
  - [ ] TREL glue in `opentrust-mac` / `opentrust-embassy`: a `Radio` implementation over `Trel`, key ID mode 2 / mode 0 frames over TREL (secure them with the `KeyManager`), key sequence and frame counter persistence for the TREL counter, multi-radio neighbor table (supported radios per neighbor), radio selection feedback from MAC results (`RadioSelector::on_send_done`, `on_receive`, `on_deferred_ack`) and probing of the TREL link, DNS-SD itself (platform)
- [x] Thread 1.4 additions: ephemeral key / ePSKc Border Agent (`opentrust_meshcop::epskc`, `BorderAgent::start_ephemeral_key` / `stop_ephemeral_key` / `handle_ephemeral_udp`, `BorderAgentClient::connect_ephemeral`; OT `EphemeralKeyManager` semantics: 6..32-octet key used directly as the EC-JPAKE password, 2 min default / 10 min max timeout, 10 connection attempts, single use, independent of the PSKc listener; passcode generation with Verhoeff check digit; DNS-SD `_meshcop-e._udp` through `BorderAgentIo::ephemeral_service`)
  - [ ] Border Agent counters and history events for ePSKc; ePSKc end-to-end in the meshcop simulator
- [ ] TCAT (Thread Commissioning over Authenticated TLS, BLE commissioning) — **optional**; scope review done (ADR 0002, option (b)):
  - [x] Transport- and TLS-agnostic TCAT engine in `opentrust-meshcop` (feature `tcat`, default off): command TLVs, command classes, section 13.12.1 authorization over certificate claims, `TcatSecureTransport` seam (`opentrust_meshcop::tcat`, tests with a fake transport)
  - [ ] TLS 1.3 server with mutual certificate authentication (`TLS_AES_128_GCM_SHA256`, secp256r1, ECDSA) and a no-alloc X.509 chain validator on RustCrypto `p256` / `aes-gcm` / `der` (own crate, separate security review; ~2.5-3.5 kLOC)
  - [ ] Thin BLE GATT adapter (TCAT service 0xFFFB, C1/C2, advertisement TLVs) on a BLE host such as `trouble-host`; TMF `/c/te` (TCAT_ENABLE)
- [ ] Border Router role (feature `border-router`, `std`/Linux only initially): RA/RIO, OMR prefix, NAT64 hooks — likely defer

## Phase 10 – Public API & host interfaces

- [x] `Instance` (`opentrust-instance`, [ADR 0003](docs/decisions/0003-instance.md)): one struct owning MAC + key manager, 6LoWPAN / mesh forwarder, IPv6 / netif / UDP / ICMPv6, TMF agent, MLE, Network Data (leader store, local data, notifier, publisher, ALOCs, SLAAC), address cache and the dataset managers; sans-IO radio edge (`handle_radio_rx`, `handle_radio_tx_done`, `poll_radio_action`, `poll`, `next_deadline`, `poll_event`); persistence through `SettingsStore`; public API (`thread_start` / `become_leader` / `thread_stop` / `factory_reset`, role / RLOC16 / partition / leader data, Active / Pending dataset, `create_dataset`, addresses, UDP sockets, ping, local Network Data, poll period) and typed `Event`s
  - [x] RAM footprint of `Instance`: size test with per-feature-set bound and `docs/memory-budget.md`; chained 128-byte buffer pools (`opentrust_core::bufpool`) for the outbox, Border Agent outbox, UDP receive queues, indirect queue, held datagrams, CoAP pending / cached messages and DNS/SRP datagrams (default 150000 to 107136 bytes, MTD 102800 to 74576)
  - [ ] RAM footprint: one pool shared by all queues (OpenThread `NUM_MESSAGE_BUFFERS`), reassembly slots and forwarder receive buffer, MAC transmit queue, DTLS roles sharing storage (Joiner / Commissioner), DNS/SRP record sizes
  - [x] `opentrust-sim`: simulated 802.15.4 medium (link matrix, RSSI, loss, jamming, air time, ACK / Frame Pending / retry semantics of a MAC-offload radio) and a `Network` harness; full-stack tests: leader formation, child attach and router upgrade, 3-router chain ping with mesh header and fragmentation, ML-EID address query, border router prefix and route with SLAAC, non-FTD child address registration, UDP across the mesh, sleepy end device polling, leader restart restore, link-layer replay protection
  - [x] MTD-only data path (`default-features = false` is a real end-device build: no router / leader / Router ID code, parent-only routing, mesh header frames dropped) and SRP client + DNS client wiring (`opentrust_instance::dns_srp`: Network Data auto-start, persisted key and server, `Instance::srp_*` / `dns_*`, `publish_dns_srp_service`; full-stack sim test `crates/opentrust-sim/tests/dns_srp.rs` with a fake SRP/DNS server)
  - [ ] Instance wiring still missing: TCAT, TREL radio, Pending dataset delay timer persistence checks, energy scan / PAN ID query servers (Joiner, Joiner Router, Commissioner, Border Agent and the leader commissioner session are wired)
  - [x] Sleepy end device with the default poll period stays attached: the parent queued link-local unicast (MLE) for a sleepy child as a direct frame (OT queues it indirectly: `Route::Indirect` once the child is `confirmed`), the child had no attach-mode / fast polls after a Data Request (`Mac::set_poll_attach_mode`, `MleEnv::send_fast_polls`); sim test `sleepy_end_device_with_default_poll_period_stays_attached`
  - [ ] The SRP/DNS wiring needs `EcdsaP256` on the crypto backend and `CryptoRng` on the RNG of `Instance`; hardware backends must provide ECDSA. `cargo check-nrf52 -p opentrust-instance` builds with `p256` in the tree (compile check only; flash size of the ECDSA code not measured yet)
  - [x] CSL and link metrics glue in the `Instance` (`Mac::set_csl`, CSL IE in SSED frames and on receive, Enhanced ACK probing events); end-to-end CSL tests in `opentrust-sim/tests/csl.rs` over the virtual-time radio (clock, software sampling; no timed receive)
  - [x] Key rotation event, Discovery / Announce `TxOptions` channel and PAN honoured by the MAC path, Network Diagnostics TMF server (`/d/dg`, `/d/dq`, `/d/dr`, `diag_get` / `diag_query` client, `neighbor_table` / `child_table` / `route_table` / `mac_counters` getters; sim tests `diag.rs`, `keyrot.rs`)
  - [ ] Network Diagnostics: multi-message answers, Child / Router Neighbor / Enhanced Route / MLE counters / vendor TLVs, `/d/dr` client
  - [ ] Initiator side of Enhanced ACK probing (`Mac::track_enh_ack_probing`) and aggregation of data request / ACK frames
  - [x] Async facade (`opentrust-embassy`): `Resources` / `OpenTrust` handle, drop-safe `run(radio, alarm)`, multi-waiter `wait_changed`, `next_event`, `with` passthrough, async `UdpSocket`; tested over an async test medium in virtual time
  - [x] `edge-nal` UDP traits (feature `edge-nal`), async wrappers for ping / joiner / SRP wait / DNS (resolve address, browse, resolve service)
  - [x] Scans in the `Instance` (MLE discovery, MAC active scan with beacons from attached router-eligible devices, energy scan) and async `scan` / `energy_scan` wrappers
  - [x] esp-rs `openthread`-compatible surface (feature `openthread-compat`, module `compat`): `OpenThread` with the lifecycle, status, getters, scan / energy scan, tables, multicast, link mode, poll period and SRP client calls
  - [ ] Compat surface, open (the `Instance` lacks the data, the methods return defaults or `NotImplemented`): MLE and IP counters, MAC unicast / broadcast / duplicate / FCS counters, neighbor age / frame counters / last RSSI / error rates, route table ext address / link qualities / age, CSL period and timeout, child timeout setter, child supervision, `detach_gracefully`, `buffer_info`, subtype labels and lease / TTL settings of the SRP client, pending dataset components (`active_dataset_diag`), the DNS client calls (`dns_browse`, `dns_resolve_service[_and_host_address]`, `dns_resolve_address` with esp-rs `DnsResponse`; the native async DNS wrappers exist), ping sender, joiner and `with_instance` / raw rx / tx
  - [ ] Async facade, open: an async wrapper for the MAC active scan; a cancel API for discovery / energy scans (dropping the scan future does not stop the scan)
  - [x] Beacons as OpenThread: sent while attached and router eligible, without payload by default (Thread 1.2.1+, OT `OPENTHREAD_CONFIG_MAC_OUTGOING_BEACON_PAYLOAD_ENABLE` off); Thread beacon payload opt-in with `Instance::set_beacon_payload_enabled`
  - [ ] Beacons from a detached, non-router-capable device while joinable (OT `OPENTHREAD_CONFIG_MAC_BEACON_RSP_WHEN_JOINABLE_ENABLE`, off by default)
  - [ ] Buffer pools: a single MLE/TMF message over 1024 bytes cannot be queued in the MLE outbox and pending / cached CoAP messages over 2 kB are refused with `NoBufs`; check large Network Diagnostics answers and size the pools against OT's largest messages
  - [ ] Differential tests of the `Instance` against an OpenThread node (Phase 11)
- [ ] rs-matter integration (`opentrust-matter`, rs-matter pinned to revision `95e4110`, Rust 1.92):
  - [x] rs-matter `NetStack` / `NetSocket` (transport `NetworkSend` / `NetworkReceive` / `NetworkMulticast`) over the native `UdpSocket` for Matter traffic (rs-matter-stack 0.4 does not consume `edge-nal`); two-node virtual-time test; shared async test harness in `opentrust_sim::testing` with a virtual `embassy-time` driver
  - [x] `Mdns` over the SRP client + DNS-SD client (`SrpMdns`): host from the extended address, `_matterc._udp` / `_matter._tcp` with subtypes and TXT kept in sync with `Matter::mdns_services`, removed when the future is dropped; operational / commissionable resolve and browse through `dns_resolve_service` / `dns_browse`; `NetifDiag` + `NetChangeNotif` (`ThreadNetif`); test with a fake SRP / DNS-SD server on the leader
  - [x] SRP service slots: 6 by default (`opentrust_instance::SRP_SERVICES`, features `srp-services-8` / `srp-services-12`), enough for the commissionable service and 5 fabrics (about 770 B RAM per slot)
  - [ ] `SrpMdns`, open: lease / TTL are the client defaults, a browse answers one pass per request (no re-query while the window is open), no `MdnsBrowseMatch` for subtype-only answers, resolution of a peer registered with several hosts
  - [x] Thread Network Commissioning cluster backend (`ThreadNetCtl`: `NetCtl` + `NetCtlStatus`): MLE-discovery scan with Extended PAN ID / name filter, connect from the dataset TLVs (stop, set Active Dataset, start, wait for child / router with a 20 s timeout, `OtherConnectionFailure` and Thread stopped on timeout), last status / network ID; the `Networks` store (add / update / remove / reorder) stays with rs-matter; virtual-time tests (scan finds the leader, connect joins, missing network times out)
  - [x] Thread Network Diagnostics cluster data (`ThreadDiag` + `WirelessDiag` on `ThreadNetCtl`): routing role (Disabled / Detached / SED / REED / EndDevice / Router / Leader), RLOC16, channel, PAN ID, ext PAN ID, name, mesh-local prefix, partition / leader data, neighbor and route tables, MAC counters, security policy, channel mask, dataset components, active timestamp
  - [ ] Diagnostics, open (defaults where the `Instance` has no data): neighbor age / frame counters / last RSSI / error rates, route table ext address / link qualities / age and the node's own entry, MLE counters, MAC unicast / broadcast / duplicate / FCS counters, `overrun_count`, pending timestamp / delay, network faults
  - [x] ICD hooks (`IcdFollower`): follows rs-matter's `Icd::net_params` and applies the poll interval to the node (`set_poll_period`), `set_sleepy` for the link mode; test with a sleepy child
  - [ ] ICD, open: child timeout from `max_poll_interval_ms`, CSL period, child supervision (the `Instance` has none of them)
  - [x] `ThreadDriver` / `ThreadCoexDriver` runner (`ThreadRunner`, `ThreadCoexRunner`): `OpenTrust::run` + settings persistence + ICD follower raced with the task, drop-safe, restartable on the same `Resources`; `Instance::settings()` / `settings_mut()`, `SettingsStore::change_count` (wakes `wait_changed` on settings writes); `ThreadPersist` stores the Thread settings in one rs-matter `KvBlobStore` blob (`OtPersist` format, debounced, hash-compared); virtual-time tests (restore after a restart without a fresh attach, bounded write rate under traffic, drop / restart of the runner)
  - [ ] Persistence, open: the rs-matter `Networks` store itself is rs-matter's; no wear levelling or write coalescing beyond the 5 s debounce in the persistence itself (the nRF52840 flash log of `opentrust-flash` levels wear and merges writes per key); the settings are loaded once per `ThreadRunner`, not re-read on a restart with live resources
  - [x] rs-matter on-off light over Thread in sim (`crates/opentrust-matter/tests/light.rs`, virtual time): a leader hosts the fake SRP / DNS-SD server and runs rs-matter's `Commissioner` over the mesh; the light is a child with a full `MatterStack` through `ThreadRunner` (`run_thread_oper`, dataset preset); asserts attach, `_matterc._udp` and `_matter._tcp` registration, PASE, commissioning, CASE, OnOff read / Toggle / read. RAM numbers in `docs/memory-budget.md`
  - [x] Light on real hardware, nRF52840 DK (`examples/nrf52840-light`): `radio-nrf802154`, embassy-time `Alarm` / `Clock`, flash-backed Thread settings and rs-matter KV (`opentrust-flash`, wear levelling), RNG entropy, RustCrypto `Crypto`, BLE commissioning (`opentrust_matter::ble`, `ThreadCoexRunner`), commissioned with chip-tool over BLE (`pairing ble-thread`) and on-network through `ot-br-posix`; 62 min soak with 123/123 toggles, random resets, factory reset back to BLE advertising (`docs/thread-border-router.md`, `docs/memory-budget.md`)
  - Light on ESP32-C6: see Phase 14
- [x] OT-compatible CLI (`ot-cli` command subset) — required to drive OT test scripts: `crates/opentrust-cli` (`no_std`, no alloc, feature-gated command groups, sim tests driving 1 to 3 nodes by CLI strings only; see OPENTRUST-OPENTHREAD-DIFFERENCES.md for what is missing)
- [ ] Spinel/NCP (RCP host side & NCP device side) — optional, enables `ot-br-posix` interop

## Phase 11 – Simulation & testing (reuse OpenThread test framework)

- [x] `opentrust-sim`: OT's virtual-time simulation protocol (`opentrust_sim::vt`: UDP event socket, radio with ACK, energy scan, settings file) so Rust nodes and OT nodes share one virtual network; `opentrust_sim::vtsim`: Rust port of thread-cert's `VirtualTime` simulator driving `ot-cli-ftd` / Rust node processes (mixed-network test `crates/opentrust-sim/tests/mixed.rs`: OT leader + OpenTrust router and the reverse, router tables, pings both ways; skipped without `ot-cli-ftd`)
- [x] `opentrust-cli-vt` (`opentrust-cli --features sim`): `ot-cli-ftd`-compatible node (argv: node id; stdin/stdout CLI with echo and prompt; `PORT_OFFSET`/`PORT_BASE`; settings in `tmp/<offset>_<id>.flash`); the MTD variant (`ot-cli-mtd`) is not built
- [ ] `cargo test` harness (`tests/thread_cert.rs`, custom harness `harness = false`) that:
  - [x] builds OT reference nodes from `openthread-sys/vendor/openthread` (simulation platform): `cargo build -p openthread-sys` (build script, about 25 s, 11 MB build tree)
  - [x] runs `thread-cert` cases Cert_5_1_*, 5_2_*, 5_3_* with OpenTrust nodes in place of OT nodes (`crates/opentrust-sim/tests/thread_cert.rs`, `OPENTRUST_CERT=1`): 273 of 273 runs pass (all-OT, each node, all OpenTrust), details in `docs/test-status.md`; pktverify runs with a macOS workaround, 9 of the 12 cases that pass with OpenThread also pass with OpenTrust
  - [x] OT SED attach to an OpenTrust parent (Child ID Response queued for the poll)
  - [ ] cert failures open: five cases fail with OpenThread only
  - [x] manages Python venv (`.venv`, created / completed with pip: pexpect, pycryptodome, pyshark 0.4.6, lxml)
- [x] Port OT C++ unit-test vectors (`tests/unit/*.cpp`: mac frame, lowpan, mle, crypto, dataset, network data, coap) into Rust `#[test]`s (inventory and status per test in `docs/ot-unit-test-port.md`; the rest is OT-internal framework, IPv4/NAT64, Spinel/HDLC and platform tests with no OpenTrust counterpart)
- [x] Differential tests: same input to `openthread-sys` (FFI) and Rust impl, compare outputs (codecs, crypto, KDF): `crates/opentrust-difftest` (feature `ot`; C++ shim `tools/openthread-sys/shim/diff_shim.cpp`, feature `diff-shim`) compares crypto / KDF, 6LoWPAN, MAC frames, MeshCoP datasets, Network Data and MLE TLV lookup with seeded random inputs; skipped without the feature; coverage and findings in `docs/differential-tests.md`, deviations in `OPENTRUST-OPENTHREAD-DIFFERENCES.md`; five OpenTrust defects found and fixed
- [ ] OTNS (OpenThread Network Simulator) integration for large-topology/visual testing
- [ ] Fuzzing (`cargo fuzz`) for all parsers (MAC, 6LoWPAN, MLE TLVs, CoAP, MeshCoP TLVs)
- [x] Track cert test pass-rate in `docs/test-status.md`

## Phase 12 – Embedded targets

- [ ] nRF52840 (DK, running): `crates/opentrust-nrf` and `examples/nrf52840-leader` (standalone firmware, own target dir; `cargo run --release`, `--bin scan`)
  - [x] Radio driver over `embassy-nrf` 0.11 `radio::ieee802154` (feature `radio-embassy`, the default). No MAC offload: the MAC does ACK, retries, CSMA and filtering in software; CCA is carrier sense only; energy scan by RSSI sampling; RSSI of received frames estimated from the LQI byte. Differences in `OPENTRUST-OPENTHREAD-DIFFERENCES.md`
  - [x] `Clock` / `Alarm` over `embassy-time` (RTC1, 32.768 kHz tick), entropy from the RNG peripheral, `RamSettings`
  - [x] Firmware: Leader with a fixed dataset (channel 15, PAN 0x1234, "OpenTrust"), MLE Advertisements transmitted, no radio errors; energy scan of all channels and active scan with real RF
  - [x] Flash / RAM measured (`docs/memory-budget.md`): 365 KiB flash, 84 KiB static RAM, stack high-water 17 kB after the in-place construction (was about 125 kB)
  - [x] RAM: `Instance::init` / `Resources::init` build the node in place (no 100 kB value on the stack), the `Instance::poll` steps are not inlined into one frame; stack high-water 15.8 kB during construction and 16.9 kB running on both backends (`docs/memory-budget.md`)
  - [x] Matter on-off light firmware (`examples/nrf52840-light`, Thread Leader with a preset dataset, rs-matter RustCrypto backend, test attestation, no BLE; since the flash work a flash-backed key-value store: 831 KiB flash, 182 KiB static RAM): 808 KiB flash before it, 174 KiB static RAM, 31 kB stack, boots and runs rs-matter on the DK; commissioning on the board and LED control are not yet exercised; on-network rehearsal: build-time dataset (`OPENTRUST_DATASET`), SLAAC address from an on-mesh prefix, SRP host and `_matterc._udp` registered with an OpenThread SRP server, ping from the peer; see docs/thread-border-router.md
  - [x] Second radio backend over sysgrok `nrf-802154` (Nordic C driver + MPSL), feature `radio-nrf802154` of `opentrust-nrf` (exclusive with `radio-embassy`, which stays the crate default; the firmware defaults to the Nordic backend). Reports all MAC offloads plus ACK timeout, CSMA, timed TX/RX, TX security, auto sleep and energy scan, so `SoftMacNeeds` is `RETRANSMIT` only. On the DK: Leader, MLE Advertisements out, no radio errors; `scan` found 5 and 3 beacons in two rounds where the embassy backend found 1 and 1 (same place, one board). Flash 430 KiB, static RAM 93 KiB (`docs/memory-budget.md`). Uses a pinned git commit of `nrf-802154` (the released 0.1.0 lacks timed RX / CSL / secured enhanced ACKs); needs `clang`, `cmake`, Rust 1.93 and, on macOS, `llvm-ar` in place of Apple's `ar` (crate docs)
    - **The exception to pure Rust.** The driver is C (BSD-3-Clause source); the 802.15.4 service layer (`libnrf-802154-sl.a`, 54 kB) and MPSL (`libmpsl.a`, 88 kB) are prebuilt Nordic binaries under `LicenseRef-Nordic-5-Clause` (Nordic silicon only, no reverse engineering). MPSL has no source; details in the `opentrust-nrf` crate docs
    - [x] CSL timing against an OpenThread parent on the DK (`docs/csl-hardware.md`): SSED with 500 / 200 / 100 ms periods, 0 loss over 60 / 30 / 60 pings, no data polls, RTT uniform over one period, window about 6.4 ms (1.3 % at 500 ms); a live period change does not resynchronize the parent (open)
    - [ ] BLE coexistence measurements (throughput / timing; functionally verified: Thread attaches within about 1 s while a BLE connection is open, full `chip-tool pairing ble-thread` works); `TRANSMIT_RETRIES` is not offered by the driver, the MAC keeps the retry loop
  - [x] Flash-backed settings: `opentrust-flash` (RAM image + async two-bank log writer over any async `NorFlash`; CRC-protected per-key entries, compaction with the header written last, power-cut tests at every flash operation on the host), `opentrust_nrf::Flash` (`nrf_mpsl::Flash` through MPSL timeslots with `radio-nrf802154`, NVMC with `radio-embassy`), `opentrust_matter::flash_kv::FlashKv` (`KvBlobStore`), regions in `memory.x` (last 24 KiB, survive a reflash), factory reset with Button 1 at boot. On the DK: the `node` restores ML-EID, RLOC16 and role after a reset and is child again after 20 ms (fresh attach 820 ms), frame counters grow across resets (3000, 4000, 5010), peer RxErrSec 0; the light reloads its key-value store and Thread settings. Not verified: Button 1 on the board (a feature forces the reset instead), power cut on the board, rs-matter fabrics (no commissioning yet)
  - [x] BLE for Matter commissioning on the light: Nordic SoftDevice Controller (`nrf-sdc` 0.4, peripheral library) and `trouble-host` 0.8 on the MPSL instance of the 802.15.4 driver, BTP GATT peripheral ported from `rs-matter-embassy` (`opentrust_matter::ble`, feature `ble-trouble`), `run_thread` with `ThreadCoexRunner` (BLE next to Thread); the unprovisioned light advertises (discriminator 3840, seen from a Mac while Thread runs as router), a commissioned one does not, BLE stops when commissioning completes (on-network rehearsal with the BLE firmware: PASE window, CommissioningComplete, toggle, reboot stays commissioned). Flash 950 KiB, static RAM 201 KiB (`docs/memory-budget.md`). Not verified on the board: `chip-tool pairing ble-thread` end to end (macOS needs Apple's Matter BLE developer profile, section 5a of `docs/thread-border-router.md`)
  - [ ] CryptoCell / hardware crypto (the RAM reduction is done, see above)
  - [x] Interop against OpenThread (`ot-cli-ftd`, ot-nrf528xx `d2c0b13` / OpenThread `e5629fa`, second DK, `examples/nrf52840-leader --bin node`, channel 25), `radio-nrf802154` backend: OpenTrust attaches as child in 1 to 7 s, upgrades to router (peer router table: link quality 3/3), pings both ways with 0 loss over hundreds of echoes (RTT 10 to 30 ms), OpenTrust Leader with the OpenThread node joining as child and router, leader reset (partition merge, takeover by the peer after 120 s), 12 min run without retries, security or channel access errors. Bugs found and fixed: MLE Announce (key ID mode 2) reached the driver unsecured (`KEY_ID_INVALID`), key index of queued frames after a key sequence switch
  - [ ] Interop with the `radio-embassy` backend: OpenTrust does not attach to the OpenThread Leader (no Parent Response seen, peer counts 8 security errors and no unicast TX) and an OpenTrust Leader is not joined by the peer; the Nordic-driver backend works, so the cause is in the software MAC path or the embassy-nrf radio layer (a packet capture is needed; not diagnosed yet)
  - [x] Interop CSL (OpenTrust SSED under the OpenThread parent, see `docs/csl-hardware.md`); the reverse direction needs an OpenThread build with the CSL receiver
  - [ ] Interop still open: SED polling, runs over several hours (62 min with the light done), packet capture (no sniffer)
- [ ] nRF54L15/H20: radio driver, timers, CRACEN crypto
- ESP32-C6/H2: see Phase 14
- [ ] Example apps per board: MTD (SED) sensor open; FTD router / leader (`examples/nrf52840-leader`, `--bin node`) and CLI over UART done on the nRF52840 DK
  - [x] CLI over UART on the nRF52840 DK (`examples/nrf52840-leader --bin cli --features cli-all`, UARTE0 on the J-Link VCOM, prompt `> `, echo and CR/LF as OT's UART CLI, settings in RAM): interop against `ot-cli-ftd` on a second DK on channel 25 with CLI commands only (OT forms / OpenTrust joins by `dataset set active`, OpenTrust forms / OT joins; `state`, `ping` and `udp` both ways to ML-EID and RLOC, `router table`, `child table`, `neighbor table`, `netdata show`, `ipaddr`, `dataset active` identical in format). Flash 447 KB with no command group, 501 KB with all, RAM 98 / 106 KB (per group: dataset +8 KB, scan +3, ping +4, tables +10, netdata +5, srp +5, dns +2, udp +3, commissioning +16 KB flash and +7 KB RAM)
  - [x] CLI firmware persistent settings: the `cli` and `node` binaries keep the Thread settings (datasets, network info with the frame counters stored ahead, parent / child info, random extended address) in the Thread region of the `opentrust-flash` log; `factoryreset` and Button 1 at boot erase it (hardware: ten resets in a row against an OpenThread parent, no growth of the attach time)
  - [x] CSL receive window after-time configurable per radio (`RadioCaps::csl_receive_on_after_us`, default the OpenThread 5.5 ms `MIN_RECEIVE_ON_AFTER`), unit test in `opentrust-mac`
  - [ ] CLI firmware, open: commissioner / joiner against OpenThread on hardware (needs an `ot-cli-ftd` built with `OT_COMMISSIONER` and `OT_JOINER`), `child <id>`, `counters mle`, `dataset mgmtsetcommand` / `mgmtgetcommand`
- [ ] Footprint budgets (flash/RAM per role) and power measurements for SED/SSED
- [x] Hardware-in-loop interop with an OT RCP / `ot-br-posix` border router (manual, on a Mac with an nRF52840 Dongle RCP; `docs/thread-border-router.md`): the light registers over SRP, is commissioned on-network and over BLE, and is controlled by chip-tool through the BR
  - [ ] Automate it (scripted BR + chip-tool run)

## Phase 13 – Certification readiness & docs

- [x] Map every Thread 1.4.1 test-plan case to status (pass/fail/NA): `docs/test-plan-status.md` lists every case with an OpenThread `thread-cert` script (5.x to 9.x, LowPower) per configuration (all OT, each node OpenTrust, all OpenTrust, MTD build), plus the functional tests and the NA scripts (OTBR / backbone); cases without an OpenThread script are not covered
- [ ] Cross-check OpenTrust against OpenThread
- [ ] Cross-check OpenTrust against Thread specification
- [ ] Security review (key handling, frame counters, replay protection). Items the `Instance` adds for the review:
  - link-layer replay protection for received data frames is `Mle::check_link_frame`, called by the `Instance` before the forwarder for every secured frame (key ID mode 1) from a known neighbor; frames from unknown sources pass, key ID mode 2 frames are not checked; key ID mode 0 frames are checked per KEK (counter above the last accepted one) and accepted only from the peer of the running Joiner Entrust exchange
  - the unsecure-port filter in `Instance::unsecure_allowed` (datagrams without link security only for UDP to the MLE port and the ports of `add_unsecure_port`)
  - the TX path secures every frame with its `LinkSecurity` class at the MAC (level 5; key ID mode 1, mode 0 for the Joiner Entrust, mode 2 for MLE Announce) through the key manager; the key sequence rotation poll (`KeyManager::poll`) result is not yet fed back to MLE
  - the SLAAC IID secret key and the ML-EID IID come from the instance RNG; the secret key is stored in the settings in clear
  - a non-FTD child accepts MAC frames from its parent without per-frame counter state beyond what `check_link_frame` keeps
- [ ] API docs, architecture doc, porting guide for new platforms

## Phase 14 – ESP32 targets

- [ ] ESP32-C6/H2 (802.15.4 capable; RISC-V): radio via `esp-ieee802154` (esp-hal), reuse esp-rs/openthread platform glue; `Clock` / `Alarm` on the target timer, entropy, flash-backed settings
- [ ] Light on ESP32-C6: radio over `esp-ieee802154`, timer, flash KV, BLE (Matter commissioning through the ESP BLE controller next to 802.15.4)
- [ ] Hardware crypto: ESP AES and ESP ECC backends for `CryptoBackend` / the `ecjpake::P256` trait and rs-matter
- [ ] Example apps (FTD router / leader, CLI over UART / USB-CDC) and interop against OpenThread / an OTBR as on the nRF52840
- [ ] ESP32-C6 part of milestone M5

## Phase 15 – Cleanup

- [ ] Full code review
- [x] Remove mention of PLAN phases from code and comments (keep it that way for new code)
- [ ] Check what can/needs to be disabled on embedded devices
- [ ] Check for remaining TODOs
- [ ] Review no_std compliance

## Phase 16 – Port ot-br-posix

- [ ] Port ot-br-posix to Rust

## Phase 17 – Publish OpenTrust

- [ ] Push to Github/Gitlab
- [ ] Release crates to crates.io
- [ ] Announce / Market OpenTrust

## Phase 18 – Maintenance

- [ ] Align with current OpenThread main branch
- [ ] Align with later Thread versions

## Milestones

- [x] **M1 – Codecs**: MAC + 6LoWPAN + MLE TLVs + crypto, verified by OT vectors and differential tests
  - [x] Codecs for MAC, 6LoWPAN, MLE TLVs, crypto, MeshCoP TLVs, network data, CoAP
  - [x] OT unit-test vectors ported (`tests/unit/*.cpp`, `docs/ot-unit-test-port.md`)
  - [x] Differential tests against `openthread-sys` (`crates/opentrust-difftest`, `docs/differential-tests.md`; CoAP, the large MLE TLVs and the MeshCoP TLVs outside the dataset are not covered differentially)
- [x] **M2 – MTD in sim**: Rust MED/SED attaches to OT leader in simulation; ping works
  - [x] True MTD build (`opentrust-cli-vt-mtd`, `--no-default-features --features sim-mtd`: no ftd, commissioner, Border Agent): MED, SED and SSED attach to an OT leader and to an OT router and ping both ways incl. fragmented datagrams (`opentrust-sim/tests/mtd.rs`); thread-cert runs with `mtd:<nodes>` (Cert_5_1_02, Cert_5_3_04, v1_2_LowPower_5_3_01) pass
  - [x] Mixed-test flake: two tests of csl.rs used the name `csl-off` and so one directory (one removed the other's working directory: `spawn node: NotFound`, settings of nodes mixed up); every test has its own directory now, and the port range (`VtSim::new_free`) is claimed by binding it free of nodes of other simulators, serialized with node starts (40 parallel runs of mixed, csl and mtd, no failure)
  - [x] MED: OpenTrust MEDs attach to an OT leader and answer pings in the OT virtual-time simulation (Cert_5_3_04 nodes 4-7)
  - [x] SED: OpenTrust SED in the mixed simulation (Cert_5_3_04 node 3, Cert_5_3_02 node 4, Cert_5_1_02 node 3 pass)
- [x] **M3 – FTD in sim**: Rust router/leader; mixed Rust/OT network passes core `thread-cert` 5.x cases
  - [x] Mixed OT/OpenTrust network in OT's virtual-time simulation (`opentrust-sim/tests/mixed.rs`), OpenTrust as leader and as router
  - [x] `thread-cert` harness (`opentrust-sim/tests/thread_cert.rs`)
  - [x] Core 5.1 / 5.2 / 5.3 cases pass with OpenTrust in every role (273 of 273 runs: all OpenThread, each node OpenTrust, all OpenTrust; MTD build for the MED / SED nodes; `docs/test-status.md`). The five baseline failures were an `ot-cli-ftd` built without Border Router support, then DHCPv6 (5.3.8, 5.3.9)
- [x] **M4 – Commissioning & Matter**: Joiner + Commissioner interop with OT; SRP client; rs-matter device reachable over a Rust Thread node in sim
  - [x] SRP client (against the OTBR SRP server on hardware)
  - [x] rs-matter device reachable over a Rust Thread node in sim (`opentrust-matter/tests/light.rs`) and on the nRF52840 through an OTBR
  - [x] Joiner + Commissioner interop with OT nodes in sim (`opentrust-sim/tests/commissioning_mixed.rs`: OT Commissioner with an OpenTrust FTD / MTD Joiner, OpenTrust Commissioner with an OT Joiner, Joiner two hops away behind a Joiner Router of the other implementation, wrong PSKd on both sides, petition / keep-alive / resign and a refused second Commissioner, MGMT_ACTIVE_SET; thread-cert `Cert_8_*` pass in all configurations, `Cert_9_2_*` with the gaps listed in `docs/test-status.md`; not run on hardware)
- [ ] **M5 – Hardware**: nRF52840 + ESP32-C6 nodes join an OT/OTBR network
  - [x] nRF52840: joins OT nodes and an OTBR network (router, child, leader; Matter light commissioned through the OTBR)
  - [ ] ESP32-C6 (Phase 14)
- [ ] **M6 – Thread 1.2–1.4 features** and certification test-plan coverage
  - [ ] Test-plan gaps found by `docs/test-plan-status.md` (OpenThread `thread-cert` scripts, simulation only):
    - [ ] 9.2.8, 9.2.9, 9.2.11 to 9.2.14, 9.2.18 fail with OpenTrust nodes (being fixed)
    - [ ] 5.7.1 to 5.7.3: the OpenTrust DUT does not answer Network Diagnostic Get (no diagnostic server / `networkdiagnostic` CLI)
    - [ ] 6.2.2 (OpenTrust as Router 1 after the merge) and 6.5.2 (SED child stays detached after reset, also MTD build)
    - [ ] LowPower 7.1.1, 7.1.2, 7.2.1 and the link-metrics functional tests: `linkmetrics` CLI / enhanced-ack probing / forward tracking
    - [ ] BBR / DUA / MLR (Thread 1.2): needs a sim `ot-cli-ftd` with `OT_BACKBONE_ROUTER` to get a baseline; MATN, BBR 5.11.1 and the `border_router` scripts need an OTBR / backbone harness
    - [ ] OpenThread functional tests that fail with all-OpenTrust nodes: SRP (CLI), DNS-SD, diag, history, radio filter, anycast locator, child supervision, detach, route table (list in the status file)
    - [ ] pktverify with `tshark` 4.6 is unreliable (dissection differs); pin the Wireshark version the scripts were written for

## Open questions

- ~~Own IPv6 stack vs. `smoltcp`?~~ → own stack (see Phase 4)
- ~~Async vs. sans-IO?~~ → both: sans-IO core + first-class async facade for rs-matter
- ~~License~~ → Apache-2.0
- ~~BLE commissioning for Matter (BTP)~~ → left to rs-matter; TCAT engine in `-meshcop` (see Phase 0)
