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
  - [ ] HW backends (Phase 12)
  - [x] EC-JPAKE + DTLS 1.2 (Phase 5b, see ADR 0001)
  - [ ] Cross-check TREL key, KEK and MLE-message vectors (self-generated) against `openthread-sys` (Phase 11)
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
  - [ ] CSL IE in MAC-built data polls (poll keep-alive resync, OT `DataPollSender` CSL rules) with the poll sender / MLE
  - [ ] CSL synchronized timeout, CSL Channel / Accuracy TLVs, child CSL parameters from MLE (Phase 6/7)
  - [ ] CSL broadcast / wake-up frame (TL2 wake-up coordinator, Thread 1.4) (Phase 9)
  - [ ] Hardware-ACK radios: CSL IE in hardware enh-ACKs needs the schedule only (`set_csl` done); link-metrics IE needs a trait method (`configure_enh_ack_probing`)
- [x] Enh-ACK based Link Metrics probing, MAC part: per-initiator metric config, Thread vendor IE in enh-ACKs, initiator-side decode (`Event::EnhAckLinkMetrics`)
  - [ ] MLE Link Metrics Management / Report TLVs, forward tracking series, single probe (Phase 6)
- [x] Unit tests against OT frame vectors (`tests/unit/test_mac_frame.cpp` vectors)
- [x] Wire `KeyManager` into the MAC/driver (push `mac_keys()`/frame counter to radios with HW tx security, feed back used counters), end-to-end secured data frame + enh-ACK + key sequence switch tests
- [x] Const-generic capacities for MAC queues (`Mac<S, G, TXQ, IND, EVQ, POLLQ, NBQ, CSLQ>`, defaults 4/8/8/4/32/8)
  - [ ] Capacities of the enh-ACK probing tables (fixed 8)
- [ ] Verify CSL timing against OpenThread on a simulated radio medium (Phase 11 interop; unit tests only cover the math and the sans-IO schedule)

## Phase 3 – 6LoWPAN adaptation (§3.3–3.5, RFC 4944/6282)

- [x] IPHC / NHC (UDP) compression & decompression with context IDs (`opentrust_lowpan::iphc`: stateless/stateful unicast and multicast, TF/NH/HLIM, NHC UDP/Hop-by-Hop/IP-in-IP, `ContextProvider` trait + `ContextTable`, ECN helpers)
  - [x] Network Data implementing `ContextProvider` (Phase 7b, `opentrust_mesh::netdata::consumers::NetDataContexts`; context 0 = mesh-local prefix is built in, `ContextTable::set_mesh_local` stays for other users)
  - [ ] Compression of Destination Options / Routing / Fragment extension headers (OT only compresses Hop-by-Hop; others are sent inline)
- [x] Mesh header, fragmentation header, reassembly with timeouts (`mesh`, `frag`, `reassembly`: `MeshHeader`, `FragmentHeader`, sans-IO `Fragmenter`, fixed-capacity `Reassembler`, 2 s timeout like OT)
  - [ ] Out-of-order reassembly (OT drops out-of-order fragments; so do we)
  - [ ] Sleepy-device reassembly rules (clear list on new secure first fragment / mismatch): call `Reassembler::clear` from the MLE/role layer
  - [ ] Reassembling into `Message`s from the pool and queueing the Tx side (`Fragmenter` frames -> MAC) belongs to the Phase 4/6 mesh forwarder glue
  - [ ] MLE messages that need fragmentation must be link-secured (`MeshForwarder` retry with security) and delay-aware queue management (Phase 6)
- [x] Mesh forwarding (mesh header) for FTD (`forward`: `classify`/`parse_frame`, `handle_mesh` deliver/forward/drop with `LocalRlocs` + `NextHops` traits, hops-left handling, 2-hop loop detection)
  - [x] Routing table / next-hop provider, ICMPv6 destination-unreachable decisions, EID-RLOC cache update from forwarded frames (Phase 7a: `opentrust_mesh::forwarder`, which drives `forward`'s rules on `Mle::next_hop_and_path_cost`)
  - [ ] Forwarding queue with message priorities, aging, delay-aware queue management and fragment priority tracking (the forwarder routes and transmits a datagram at once)
- [x] Port OT `test_lowpan.cpp` vectors as Rust tests (all 58 IPHC vectors + `TestLowpanMeshHeader` + `TestLowpanFragmentHeader`), plus randomized round-trips and no-panic tests
  - [ ] Differential tests against OpenThread's `Lowpan` via `openthread-sys` (Phase 11)

## Phase 4 – IPv6 / UDP / ICMPv6 core (§5)

- [x] Own minimal IPv6 stack in `opentrust-net`, modeled on OpenThread's `src/core/net` (`smoltcp` lacks Thread specifics: RLOC/ALOC, MPL, mesh-local scoping): fixed + extension headers (Hop-by-Hop/MPL/padding, Fragment, Routing/Destination skip), pseudo-header checksum, ICMPv6 builders (`header`, `checksum`, `icmp6`)
- [x] Addresses (`addr`, `netif`, `slaac`): link-local, ML-EID, RLOC, ALOCs, GUA/OMR via SLAAC (RFC 7217 IIDs as OT, deprecation timer), unicast/multicast tables with fixed/internal/external subscriptions, Thread all-nodes/routers/MPL-forwarders and the mesh-local-derived all-Thread-nodes groups, RFC 6724-subset source selection
- [x] Sans-IO IPv6 core (`ip6::Ip6`): receive path (validate, receive/forward-to-Thread/forward-to-host decision with `Ip6Env` hooks, extension headers, IPv6-in-IPv6 tunnel, checksum verification, hop limit, ICMPv6/TMF forward filters), send path (source selection, MPL option insertion, tunnelling of larger-scope multicast, loopback), ICMPv6 echo responder and rate-limited error builder
- [x] MPL (RFC 7731) as OpenThread implements it (`mpl`): seed set, buffered retransmissions with jittered deadlines, duplicate suppression, seed ID from RLOC16
- [x] UDP sockets (`udp`): fixed-capacity socket table, bind/connect/ephemeral ports 49152-65535 (OT rules), bounded receive queues with per-packet metadata, internal receiver hooks for MLE (19788) and TMF (61631); mapping to the Phase 10 `edge-nal` facade documented in the module
- [x] Address resolution data structures (`resolver`): EID-to-RLOC cache with OT's cached/snooped/query/query-retry states, timeouts, exponential retry delay and ramp-down, eviction order, snooping, notification and duplicate-address decisions, address-query/-error decision helpers
  - [x] TMF messages `/a/aq`, `/a/an`, `/a/ae` (CoAP encoding, TLVs, sending, ACKs) wired to `resolver::ResolverEvent`, router-side child lookup on the MLE child table, duplicate address handling (Phase 7a: `opentrust_mesh::address`)
    - [ ] Backbone Query extension of `/a/aq` and DUA duplicate notification in `/a/ae` (Phase 9)
  - [x] Mesh forwarder glue: hold datagrams while an EID resolves, `HandleResolved`, ICMPv6 destination-unreachable on no route/resolution failure, snooping from forwarded frames (Phase 7a: `opentrust_mesh::forwarder`)
  - [x] Network Data providers for `Ip6Env` (`route_lookup`, `is_on_mesh`) and for SLAAC (`OnMeshPrefix` list) (Phase 7b, `opentrust_mesh::netdata::lookup::NetDataIp6Env`, `consumers::slaac_prefixes`)
  - [ ] Persisted SLAAC IID secret key in settings (Phase 6 settings wiring; the key is a caller argument)
- [ ] DHCPv6 address allocation (OT `Dhcp6Client`/`Dhcp6Server`, legacy; only if a use case needs it)
- [ ] Domain Unicast Address (DUA, Thread 1.2, `/n/dr`, `/b/bq`, `/b/bb`, duplicate DUA handling in `/a/ae`) -> Phase 9
- [ ] Multicast Listener Registration (MLR, `/n/mr`) for subscribed multicast groups -> Phase 9
- [ ] IPv6 fragmentation/reassembly above the 6LoWPAN layer (OT `OPENTHREAD_CONFIG_IP6_FRAGMENTATION_ENABLE`, off by default; not needed for 1280-byte Thread datagrams)
- [ ] Host (border router) interface: `RemoveMplOption` before passing to host, host-origin multicast policy (Phase 9, border routing)

## Phase 5 – CoAP / CoAPS

- [x] Generic TLV utilities (`opentrust_core::tlv`: normal/extended TLVs, iterator, find, typed read/write; OT `test_tlv.cpp` ported)
- [x] CoAP (RFC 7252) no_std: message codec (`opentrust_coap::message`), sans-IO endpoint (`endpoint`): confirmable retransmission, separate responses, RST/empty ACK, multicast NON, resource table, duplicate detection + response cache; differential tests against `coap-lite`
  - [ ] Block-wise transfer (RFC 7959) and Observe: off in OT's default config; only the `BlockOption` codec exists
- [x] TMF agent on UDP 61631 (`opentrust_coap::tmf`): URI list, DSCP/priority mapping, `IsTmfMessage` filtering, handler dispatcher, `UdpSockets` receiver registration
  - [x] `/a/aq`, `/a/an`, `/a/ae` wired to `resolver::ResolverEvent` and `/a/as`, `/a/ar` handlers (Phase 7a, `opentrust-mesh`)
  - [ ] MeshCoP and Network Data handlers (`/a/sd`, `/c/*`, `/n/*`; Phases 7-8)
- [x] Phase 5b: DTLS 1.2 + EC-JPAKE (CoAPS for commissioning, ADR 0001): `opentrust_core::crypto::ecjpake` (feature `ecjpake`, RustCrypto `p256`, all mbedTLS self-test vectors), crate `opentrust-dtls` (sans-IO DTLS 1.2, `TLS_ECJPAKE_WITH_AES_128_CCM_8` only, client + server, cookies, retransmission, fragmentation, KEK) and `opentrust_dtls::coaps::Coaps` behind `opentrust_coap::endpoint::SecureTransport`; manually interop-tested against mbedTLS 3.6.0 `ssl_server2`/`ssl_client2`
  - [ ] Automated differential/interop handshakes against `openthread-sys` / mbedTLS (Joiner and Commissioner, both roles, lossy links) (Phase 11)
  - [ ] Hardware P-256 backends for the `ecjpake::P256` trait (CryptoCell, CRACEN, ESP ECC) and an rs-matter `EcPoint`/`EcScalar` adapter (Phase 12)
  - [ ] Fuzz the record/handshake parsers and the EC-JPAKE readers (Phase 11)
  - [ ] Security review of the EC-JPAKE/DTLS code before M4 (ADR 0001)
  - [ ] Wire into MeshCoP Joiner / Commissioner / Border Agent (relay, ePSKc, connection-attempt limits, guard times) (Phase 8)

## Phase 6 – MLE (§4)

- [x] MLE message codec + all TLVs, MLE security (AES-CCM with key derivation) (Phase 6a, `opentrust-mle`: `tlv` typed parse/build of every Thread 1.4.1 MLE TLV, `message` commands + builder, `security` secure/unsecure + MLE frame counter store-ahead, vectors from the Phase 1 crypto reference, tamper/truncation tests)
- [x] Neighbor / child / router data model (`neighbor`: states, filters, `Child`/`Router`/`Parent`, `ChildTable<N>`, `RouterTable<N>`, `MleReplay`, `ChildInfo` settings), link quality (`link_quality`: RSS averager, margin to quality with hysteresis, costs; `test_link_quality.cpp` ported)
- [x] MLE UDP glue (`endpoint`: port 19788 receiver, hop limit 255 + addressing rules, `MleRx::parse`, `MleHandler` dispatch by command, `send` through the TMF `UdpSink`)
  - [x] Phase 6b: sans-IO `Mle<C>` core with the `MleEnv` context trait (keys, MAC/netif, tx, settings, Network Data hooks; `env`), child-side attach (`attach`: Parent Request phases and OT backoff, Parent Response collection, `IsBetterParent`, Child ID Request/Response, key sequence adoption), child role (`child`, `child_rx`: Child Update, keep-alive, data poll period from the timeout, supervision check, 4-attempt parent loss and re-attach, Data Request/Response, leader-data versioning), parent side behind feature `ftd` (default on; `parent`: Parent Request/Response with jitter, Child ID exchange with child RLOC16 allocation, address registration, Child Update, Data Request, child timeouts, supervision ticks, indirect hooks for SEDs, entered through `enter_router_role` for Phase 6c), persistence and fast re-attach (`persist`: `NetworkInfo`/`ParentInfo`/`ChildInfo`, store-ahead counters, restore via Child Update Request, restored children); two-core end-to-end test over byte buffers (`e2e_tests`)
    - [x] Network Data / dataset content (passed as bytes through `MleEnv`; Network Data in Phase 7b, Active / Pending Dataset in Phase 8a: `opentrust_meshcop::manager::Datasets` behind `MleEnv::{active,pending}_timestamp`, `{active,pending}_dataset`, `dataset_received`, which now take `now`)
    - [x] Announce send / receive (Phase 8a, `opentrust_mle::discovery`: `Mle::send_announce`, OT `HandleAnnounce` decisions, `MleEvent::AnnounceFromNewerNetwork`)
    - [ ] Announce attach state (re-attach on the channel / PAN ID of a newer network after `ANNOUNCE_PROCESS_TIMEOUT`, orphan Announce while detached), reattach with the stored Active / Pending Dataset (the `Reattach` steps), periodic `AnnounceSender`, CSL parent metric in parent selection, graceful detach (zero-timeout Child Update + 1 s wait)
  - [x] Phase 6c (feature `ftd`): role state machine (`router`: `become_leader`, REED upgrade decision with `ROUTER_SELECTION_JITTER`, router downgrade, `ID_SEQUENCE_PERIOD`, router ID bookkeeping with `ID_REUSE_DELAY`, leader-side `handle_address_solicit` / `handle_address_release`, Connectivity / Route64 content from the live router table, path cost and next hop, `RouterConfig`, `DeviceProperties` leader weight with the `test_mle.cpp` vectors), router links (`router_link`: Link Request / Accept / Accept And Request, challenge / response, frame counters, delayed Link Accept, Link Accept timeout, `MAX_NEIGHBOR_AGE` re-request and removal, `UpdateRoutes` cost bookkeeping, router role restorer after a reset), Advertisements (`advert`: `opentrust_core::trickle` with OT parameters, Route64 content, router discovery, former-child takeover, FTD child router links, downgrade conditions, parent Advertisement handling), partitions (ComparePartitions, better-partition attach, FTD Parent Response rules per attach mode, leader loss after `NETWORK_ID_TIMEOUT`, new partition as leader, previous-partition avoidance, REED answering Parent Requests / Child ID Requests); tests with a multi-node simulator (`sim`, `router_tests`, `router_link_tests`, `advert_tests`, `partition_tests`, `mesh_tests`)
    - [x] Phase 7a hooks: TMF `/a/as` / `/a/ar` client and server around `MleEnv::request_router_id` / `release_router_id`, `Mle::address_solicit_reply`, `Mle::handle_address_solicit`, `Mle::handle_address_release` (`opentrust_mesh::router_id`); mesh forwarding from `Mle::next_hop_and_path_cost`; `Mle::resolve_routing_loop`; indirect hooks for sleepy children
    - [x] Network Data hooks (Phase 7b): leader reset on `MleEvent::LeaderStarted` (`netdata::leader::Leader::start`), version bumps through `Mle::set_leader_data` (`Leader::publish`, `Mle::network_data_updated`), Network Data bytes served through `MleEnv::network_data` / stored from `set_network_data`, stale Network Data entries on `MleEvent::RouterTableChanged` (`Leader::remove_stale_router_ids`)
    - [ ] Remaining hooks: reaction to `MleEvent::RouterTableChanged` in the caller (`AddressResolver::restart_queries`, `clear` on partition change); alternate RLOC16 after REED -> router; removal of a former child that moved to another parent (second half of OT `UpdateEidRlocCacheAndStaleChild`); Border Router specific upgrade in `is_router_eligible` (the Security Policy part is done: `Mle::set_routing_policy`, Phase 8a); `Mle::set_device_mode` FTD -> MTD while holding children; Time Sync TLVs in Link Request / Accept / Advertisement
  - [ ] Link Metrics Management / Report sub-TLV content codecs and series state (the TLV containers and constants exist)
  - [ ] MLE message retransmission / delay queue (Table 4-3 constants exist in `consts`)
  - [x] Address Registration context resolution (Phase 7b: `netdata::consumers::context_prefix64` / `context_id_for` back `MleEnv::lowpan_context` / `lowpan_context_for`)
  - [ ] MLR state in `Child` (Phase 9)
- [x] Attach: Parent Request/Response, Child ID Request/Response, parent selection (link quality, connectivity) (6b)
- [x] Child Update Request/Response, keep-alive, SED/MED modes, supervision (6b; SSED/CSL parameters remain open)
- [x] Link Request/Accept (router link establishment), Advertisement, link margin/quality (6c)
- [x] Partition handling: leader data, partition ID/weight, merging (§5.16) (6c)
- [x] Role state machine: Disabled → Detached → Child → Router → Leader (6c; router IDs come from the Phase 7 TMF hook)
- [x] Persist & restore network state (fast re-attach) (6b: child and children; 6c: router / leader restore through the router role restorer)

## Phase 7 – Mesh / routing (FTD) (§5)

- [x] Router ID assignment over TMF (Phase 7a, `opentrust_mesh::router_id`: Leader `/a/as`, `/a/ar` CoAP handlers, `RouterIdOutbox` client, status codes and failure handling as OT; the allocation itself is in `opentrust-mle`, Phase 6c); Thread network-layer TLV codec `opentrust_mesh::tlv`
- [x] Mesh forwarding on the routing table (Phase 7a, `opentrust_mesh::forwarder`: `MeshForwarder` route lookup incl. child / on-link / Network Data hooks, mesh header insertion, forwarding with hops left and 2-hop loop detection, held datagrams and `handle_resolved`, destination unreachable decisions, snooping; address resolution TMF in `opentrust_mesh::address`)
  - [x] Routing through Network Data (Phase 7b): `netdata::lookup::Lookup` implements the `NetworkData` trait (external routes by longest prefix / preference / path cost, default route, on-mesh, anycast lookup)
  - [ ] Sleepy child -> rx-on mode change converts queued indirect messages to direct; `Mle::child_message_sent` is called by the caller, not by the forwarder
  - [ ] Multi-radio, CSL transmitter, CSMA collision-avoidance delay of forwarded frames
- [x] Child table & forwarding to sleepy children (Phase 7a, `opentrust_mesh::indirect`: per-child queue, Frame Pending / source match bookkeeping, fragments per data poll, supervision messages, purge on child removal; the child table itself is `opentrust-mle`)
- [x] Network Data (§5.13–5.15, Phase 7b, `opentrust_mesh::netdata`): TLV codec with typed iterators and the stable copy (`tlv`, `NetworkData<N>`; vectors of `test_network_data.cpp`), leader store (`leader`: `/a/sd` registration with validation and in-place merge, context ID allocation with 5 min reuse delay, service IDs, stale router / child entry removal, version and stable version), `/a/sd` server and client (`server_data`), local data and the OT notifier timing (`local`, `notifier`), consumers (`lookup`, `consumers`), distribution through MLE (`Leader::publish` + `Mle::network_data_updated`; full and stable data from `MleEnv::network_data`); multi-node tests in `netdata_sim_tests`
  - [ ] Network Data Publisher, DNS/SRP service helpers, Backbone Router / DUA entries, `kBorderRouterRequest` router upgrade from the notifier, restoring the leader's Network Data after a reset (wait-for-sync), DHCPv6 / ND agent ALOC subscription
- [x] Anycast locators, Service ALOCs (Phase 7b: `netdata::aloc` (leader, service and commissioner ALOC set maintenance), `netdata::anycast` (`/a/yl`), `lookup::anycast_lookup` for leader / service / commissioner / DHCP / ND ALOCs)
- [x] Commissioning datasets (Phase 8a: Active / Pending Operational Dataset, delay timer in `opentrust_meshcop::{dataset, manager, mgmt}`; the Commissioning Data TLV of Network Data is written by `Leader::set_commissioning_data` and `opentrust_meshcop::commissioner`)

## Phase 8 – MeshCoP / Commissioning (§8)

Phase 8a (this batch, crate `opentrust-meshcop`, leader / router code behind feature `ftd`):

- [x] MeshCoP TLV codec (`tlv`: all section 8.10 TLVs, Security Policy 1.2+ layout, Channel Mask page 0, State, Discovery Request / Response), Timestamp ordering (`timestamp`; `opentrust_mle::tlv::Timestamp::compare`), Steering Data bloom filter, Joiner ID, Joiner Discerner (`steering`; vectors of `test_meshcop.cpp`)
- [x] Operational Dataset type (`dataset`: fixed 254 byte TLV buffer, validation, typed setters; vectors of `test_dataset.cpp`)
- [x] Active / Pending dataset management (`manager::Datasets`: network and local timestamps, persistence hooks `DatasetEnv::{store, load, delete}`, Pending delay timer -> Active, timestamp rules on receipt through MLE, MGMT_SET retry toward the leader) and `/c/ag` `/c/pg` `/c/as` `/c/ps` `/c/ar` (`mgmt`: leader accept / reject rules, partial updates from the commissioner, Active updates that change connectivity become Pending, `/c/dc` notification, clients)
- [x] Security Policy feeds router eligibility (`opentrust_mle::RoutingPolicy`, `Mle::set_routing_policy`)
- [x] Leader commissioner session (`commissioner`: `/c/lp` petition, `/c/la` keep-alive, 50 s timeout, resign, `/c/cs` Commissioner Set, `/c/cg` Commissioner Get, Commissioning Data in Network Data)
- [x] Discovery (`opentrust_mle::discovery` transport, `opentrust_meshcop::discovery` content, Steering Data filter, active scanner state machine), MLE Announce send / receive
- [x] Energy Scan, PAN ID Query, Announce Begin servers and commissioner-side requests (`scan`: `/c/es` `/c/er` `/c/pq` `/c/pc` `/c/ab`)
- [x] Multi-node tests (`net_sim`, `sim_tests`, `sim_scan_tests` over the MLE simulator with a TMF agent, dataset managers and commissioner state per node)
- [ ] Dataset Updater (`dataset_updater.cpp`), Dataset persistence for the delay timer across resets (the full delay restarts), `MGMT_*_GET` for the Commissioner Dataset by a commissioner client (the leader side exists)
- [ ] Reattach with the stored Active / Pending Dataset, Announce attach state, periodic Announce sender (see Phase 6b)

Open for the security batch (hooks exist, nothing implemented):

- [ ] Joiner: DTLS EC-JPAKE with the PSKd, Joiner Finalize, Joiner Entrust / KEK (`DiscoverScanner` and the Steering Data filter feed it; `opentrust_core::crypto::{pskc, ecjpake}` and `opentrust-dtls` exist)
- [ ] Joiner Router: relay `/c/rx` `/c/tx`, Joiner Entrust, KEK derivation, Joiner UDP port from the Commissioning Data (`commissioner::joiner_udp_port`)
- [ ] Commissioner: native (DTLS to the Border Agent) and on-mesh, Joiner list and Steering Data computation, commissioner dataset client (`mgmt::send_set` / `send_get` and `scan::send_*` are the request side)
- [ ] Border Agent: DTLS server for external commissioners, `/c/ur` `/c/ut` proxy, Border Agent ID, Native Commissioner flag in Discovery Responses (`ResponseContent::native_commissioner`), `ProcessCommissionerGetRequest` with `kIgnoreSecurityPolicyFlags`
- [ ] Reload of the leader's commissioner state after a reset (`LeaderState::adopt`)

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

## Phase 14 – Cleanup

- [ ] Full code review
- [ ] Remove mention of PLAN phases from code and comments

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
