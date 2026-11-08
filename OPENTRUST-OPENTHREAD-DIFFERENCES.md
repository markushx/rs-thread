# OpenTrust vs. OpenThread: Differences

OpenTrust is a clean re-implementation of Thread 1.4.1 in Rust, not a port.
OpenThread (`thread-reference-20250612`, vendored in
`tools/openthread-sys/vendor/openthread`) is the reference for behaviour,
constants and test vectors. This file records every place where OpenTrust
deliberately behaves differently, why, and whether it affects interop.

**Interop** column: **none** = invisible on the air / to peers;
**stricter** = OpenTrust rejects some input OpenThread accepts (still
interoperable with spec-conformant peers, including OpenThread);
**API** = only affects the programming interface.

Keep this file up to date with every change that deviates from OpenThread.

## Architecture

| Area | OpenThread | OpenTrust | Reason | Interop |
|------|------------|-----------|--------|---------|
| Language / memory | C++, global instance, intrusive lists, heap optional | Rust, `no_std`, no alloc, no `unsafe` in protocol crates | Memory safety, embedded targets | none |
| Execution model | Single-threaded tasklets, timers, callbacks; platform calls in (`otPlat*`) | I/O-free core state machines (caller passes `now`) + executor-agnostic async facade | Deterministic tests, rs-matter integration | API |
| Time base | `TimerMilli` (ms) and `TimerMicro` (µs) | One `Instant`/`Duration` type, `u64` µs | Single type, CSL needs µs | none |
| Platform radio API | `otPlatRadio*` functions + callbacks | Async `Radio` trait mirrored from esp-rs/openthread; `RadioCaps::soft_mac_needs()` tells the MAC what to do in software; `MacCapabilities::missing_required()` instead of a panicking assert | Drop-in for esp-rs/openthread radio drivers | API |
| Clock / alarm | `otPlatAlarmMilli*` / `otPlatAlarmMicro*` | Own `Clock` / async `Alarm` traits; `embassy-time` adapter belongs in `opentrust-embassy` | Keep platform crate free of embassy-time driver choices | API |
| Entropy | `otPlatEntropyGet` | `rand_core::CryptoRng` (0.10) | Same type as rs-matter / esp-rs openthread | API |
| Logging | `otLog*` | `opentrust_core::{trace,debug,info,warn,error}!` → `defmt` or `log` | Embedded Rust conventions | none |
| DTLS / EC-JPAKE | mbedTLS | Rust EC-JPAKE on RustCrypto `p256` (`opentrust_core::crypto::ecjpake`) + minimal sans-IO DTLS 1.2 (`opentrust-dtls`, ADR 0001); mbedTLS only as test oracle. Details in "DTLS / EC-JPAKE" below | No heap, no C toolchain, no `unsafe` | none (byte-compatible with mbedTLS 3.6; see below) |

## Core (`opentrust-core`)

| Area | OpenThread | OpenTrust | Reason | Interop |
|------|------------|-----------|--------|---------|
| Message buffers | Chained 128-byte buffers, ref-counted, `Message::Type`, datagram tag, timestamps | Fixed contiguous slots with headroom for prepends; no type/tag/timestamp/ref-count yet | Simplicity; add fields when upper layers need them | none |
| Settings keys | `uint16_t` keys | Typed `SettingsKey` enum (+ `Vendor(u16)` escape hatch); same numeric values and byte layouts for `NetworkInfo` / `ParentInfo` | Type safety; blobs stay comparable with OT | API |
| Secret key types | Plain byte arrays, copyable | `NetworkKey`, `Pskc`, `MacKey`, `MleKey`, `Kek` are not `Copy`, zeroize on drop, compare in constant time, redacted in `Debug`/`defmt` | Key hygiene | none |
| MLE/MAC key split (spec §7.1.4) | First 16 bytes = MLE key, last 16 = MAC key | Same as OpenThread; the spec *text* ("MAC key = upper 16 bytes") contradicts its own test vectors, OpenTrust follows the vectors and OT | Interop | none |

## MAC frames (`opentrust-mac::frame`)

| Area | OpenThread | OpenTrust | Reason | Interop |
|------|------------|-----------|--------|---------|
| PSDU / FCS | Frame length includes FCS | All frame APIs work on the PSDU **without** FCS; `Frame::parse_with_fcs` strips it | Radios handle FCS | none |
| Sequence-number suppression / IE-present bits | Honoured regardless of frame version | Honoured only for 2015 (and multipurpose) frames; reserved bits in 2003/2006 | IEEE 802.15.4-2015 | stricter |
| Frame-counter suppression | Not supported | Parsed/built (no counter field when suppressed) | Completeness | none |
| Command ID in 2015 frames | Treated as first payload byte | Same (encrypted when the frame is secured); in 2003/2006 frames it counts as header | Matches OT | none |
| Enh-ACK key identifier | Copies key index from the acked frame | Copies the full key identifier (mode, source, index) | Correct for key ID mode 2 acks | none |
| Typed header IEs in builder | Unlimited | Up to `MAX_HEADER_IES` (6) typed IEs; more via `raw_header_ies` | Fixed-size, no alloc | API |

## MAC security (`opentrust-mac::security`)

| Area | OpenThread | OpenTrust | Reason | Interop |
|------|------------|-----------|--------|---------|
| Key ID mode 2 rx | Key source / index not checked | Requires key source `ffffffff` and key index `ff` | Thread §7.2.1.3 (lookup MUST match mode, source, index); OT sends exactly these | stricter |
| Previous/next key at sequence edges | `seq - 1` / `seq + 1` with wraparound | No "previous" key at sequence 0, no "next" at `u32::MAX` (radio `MacKeys` still carries the wrapped keys, like OT) | Avoid accepting keys of a wrapped sequence | stricter |
| Key sequence decrease | Possible via API | `set_key_sequence` rejects a lower value; only `set_network_key` / `restore` may lower it | Thread §7.1.3 | none |
| Frame counter exhaustion | Wraps | Never uses `0xffffffff`; returns `InvalidState` when exhausted | Never reuse a nonce | none |
| Replay counters | `u32` | Stored as `u64`, so receiving `0xffffffff` does not let a counter of `0` pass afterwards | Replay safety | stricter |
| Minimum key rotation time | 2 h | 1 h | Thread spec minimum | none |
| Key switch guard | Hourly countdown | Deadline-based (`Instant`), same effective behaviour | Sans-IO timers | none |
| Rx security-level policy | Only ENC-MIC-32 | Default only ENC-MIC-32; optional `Authenticated` policy accepts any level with a MIC, never level 4 (ENC without MIC) | Configurable, still safe | none |
| Order of replay check | Before decryption | After decryption (contract returns `RxSecurityInfo`; replay state lives in the neighbor table) | Layering; same outcome, only costs a CCM on replayed frames | none |
| Retransmissions | Re-secure allowed per case | A plain retransmission must resend the already-secured PSDU; calling `secure_tx` again uses a new counter (needed for CSL-IE updates) | Documented contract | none |

## MAC state machine (`opentrust-mac::mac`)

| Area | OpenThread | OpenTrust | Reason | Interop |
|------|------------|-----------|--------|---------|
| Structure | `Mac` + `SubMac` + callbacks | One sans-IO `Mac` core (pull-style `poll_action` / `on_tx_done` / `on_rx` / `poll_event`) + async `MacDriver`; no internal channel, the facade passes a wake future | Executor-agnostic, deterministic tests | API |
| Radio PSDU / FCS | Radio frame buffers include FCS | Radio-side PSDUs include FCS; the MAC computes it on tx and strips it on rx; upper layers never see it | Matches the `Radio` contract | none |
| Source-match table at start | Disabled → frame pending set for every poll | Enabled and empty → frame pending only for children with queued frames | Avoid needless wake-ups of sleepy children | none |
| Promiscuous mode | Filtered delivery with flags | Delivers raw, unfiltered frames | Sniffer use | API |
| Frames to short address `0xfffe` | Accepted in some paths | Never accepted | `0xfffe` means "no short address" | stricter |
| Unsecured frames from unknown short source | Dropped in MAC (neighbor lookup) | Delivered; the neighbor table (MLE) decides | Neighbor table lives in MLE | none (policy moves up) |
| Software ACK timing | n/a (radio does ACKs) | Software ACKs only meet the 802.15.4 turnaround on simulated media | Bare PHYs need HW ACK in production | none in sim |
| Energy scan without radio support | Software RSSI sampling via `otPlatRadioGetRssi` | `Error::NotImplemented` (the `Radio` trait has no RSSI read) | Trait mirrors esp-rs/openthread | API |
| Not yet implemented | — | Broadcast retransmission, stay-awake between fragments, MAC allow/deny filter, multi-radio/TREL, wake-up frame tx/rx flow, CSL IE in data polls, hardware-ACK radios reporting enh-ACK link metrics | Later waves / phases | — |
| Queue capacities | Compile-time config macros | Const generics of `Mac` / `MacDriver` with defaults: direct queue 4, indirect 8, events 8, poll requests 4, neighbor map 32, CSL children 8. `Mac::new` / `MacDriver::init` use the defaults; `Mac::with_capacities` + `MacDriver::new` take others (a `Mac::new` call cannot infer non-default const params) | no global config, several MACs per binary | none |
| Radio key / frame-counter push | `SubMac::SetMacKey` / `SetFrameCounter` called by `KeyManager` on every change | The MAC compares `FrameSecurity::radio_keys()` with what it pushed last at every `poll_action`, so *any* change through `Mac::security_mut()` (key switch, network key change) reaches the radio as `RadioAction::SetMacKeys` + `SetMacFrameCounter(.., if_larger = false)`; later counter growth (software-secured frames) is pushed with `if_larger = true`; radios with `TRANSMIT_SEC` or `RECEIVE_TIMING` only | No change notification plumbing between `KeyManager` and `Mac`; sans-IO | none |
| Frame counter feedback | `SubMac::SignalFrameCounterUsed` from the radio callbacks | `Mac::on_tx_frame_updated(psdu, info)` (driver calls it after a `TRANSMIT_SEC` transmit, also stores the radio-updated frame for retransmission) and `PsduRxInfo::ack_security` in `on_rx` feed `FrameSecurity::frame_counter_used` / `ack_frame_counter_used` | Explicit data flow instead of callbacks | none |
| Software enh-ACK security | Done by the radio (`otMacFrameProcessTransmitSecurity`) | `FrameSecurity::secure_enh_ack` (KeyManager: key index copied from the acked frame, prev/cur/next key, next frame counter); falls back to `secure_tx` for other key modes | Same result for bare PHYs / simulation | none |
| CSL needs a radio clock | `otPlatRadioGetNow` always available | `Mac::set_csl` / `csl_add_child` return `Error::NotImplemented` when `RadioCaps::clock` is `None` | The trait has no mandatory clock | API |
| CSL phase reference | `ComputeCslPhase(SFD time)`, parent: `last_rx_timestamp + phase * 160` | Same convention as OpenThread (SFD/timestamp based), not the spec text's "first symbol of the MAC header" (a 32 us PHR offset that OT absorbs in `CSL_TRANSMIT_TIME_AHEAD`) | Interop with OT | none |
| CSL IE in outgoing frames | Upper layer (`MeshForwarder`) appends the IE, radio fills phase | Same: the MAC never inserts a CSL IE, it only updates the phase/period of a frame that already carries one (placeholder from `FrameBuilder::header_ie(CslIe)`); data polls built by the MAC do not carry one yet | Frames are built by the upper layer | none |
| CSL IE phase without `TRANSMIT_SEC` | Radio platform must support it (capability required for CSL) | Software fallback: phase from the radio clock at the start of the attempt plus CCA + SHR (288 us); the frame is re-secured with a new frame counter on every attempt (`TxOp::csl_plain`) | Bare PHYs / simulation | accuracy (parent's window absorbs it) |
| CSL receiver without `RECEIVE_TIMING` | `HandleCslReceiveOrSleep` (timer twice per period) | Same algorithm in the MAC (`desired_mode` is Receive on the CSL channel while sampling) | — | none |
| CSL receive window handover | `otPlatRadioReceiveAt` is called even while in other sub-MAC states | `RadioAction::ReceiveAt` only once the radio is asleep and the MAC wants to sleep; dropped for rx-on-when-idle devices and when stale | A window must not cancel (or be cancelled by) a pending `Sleep` / transmit | none |
| CSL transmitter child table | `ChildTable` entries (`IsCslSynchronized`, ...) | `Mac::csl_add_child` registers a child explicitly; its CSL IEs (rx frames and ACKs, 2015 + secured, period >= 10) synchronize it; the CSL synchronized timeout, CSL channel TLV and accuracy TLV are set by MLE (`csl_child_desync`, `csl_set_child_channel`, `set_csl_parent_accuracy`) | Child table lives in MLE | none |
| CSL tx scheduling | `RescheduleCslTx` picks the earliest child, `Mac::RequestCslFrameTransmission(ms)` | Same selection with a microsecond timer (`TimerId::CslTx`) and a dedicated operation `TransmitDataCsl`; request-ahead 2000 us + radio bus time, guard 1500 us, as OT; failed CSL tx keeps the frame with its counter/sequence, 4 NO_ACKs -> `Event::CslChildOutOfSync` | — | none |
| Timed transmit without `TRANSMIT_TIMING` | `SubMac` timer before `BeginTransmit` | Same (`tx_at - (CCA 128 + 40 + SHR 160)`), the MAC waits using the radio clock; with `TRANSMIT_TIMING` the SFD time goes to the radio in `PsduTxInfo::tx_at_us` | — | none |
| Enh-ACK probing (subject) | Radio platform keeps the table (`otPlatRadioConfigureEnhAckProbing`) | The MAC keeps it (`configure_enh_ack_probing`, 8 entries) and adds the IE to *its own software* enh-ACKs; a radio that acknowledges in hardware cannot (no trait method) | The `Radio` trait mirrors esp-rs/openthread, which has none | feature gap |
| Enh-ACK probing data | LQI, margin (truncated `*255/130`), RSSI; three metrics accepted but only two bytes sent | Same order, fixed regardless of the request order; at most two metrics are accepted (`InvalidArgs`); scaling rounds to nearest like OT's initiator-side `ScaleLinkMarginToRawValue`; raw 0 RSSI saturates at -128 dBm (OT's `int8_t` wraps); no IE if a requested metric is unknown | Spec limits to two metrics; avoid OT's inconsistencies | none |
| Enh-ACK probing (initiator) | `Mac::ProcessEnhAckProbing` -> `Initiator::ProcessEnhAckIeData` with the neighbor's configured metrics | `track_enh_ack_probing` keeps the metrics per neighbor; the IE of ACKs to our frames is reported as `Event::EnhAckLinkMetrics` | MLE (Phase 6) calls it | none |

Matches OpenThread (listed because a draft said otherwise): `macMaxFrameRetries` = 15 for direct frames (Thread §3.2); indirect frames use 0 retries per poll and up to 4 polls.

## 6LoWPAN (`opentrust-lowpan`)

| Area | OpenThread | OpenTrust | Reason | Interop |
|------|------------|-----------|--------|---------|
| API shape | `Lowpan::Compress/Decompress` work on `Message` + `FrameBuilder`/`FrameData` and read Network Data directly | Functions on byte slices (`compress`, `decompress`, `decompress_datagram`); contexts come from a `ContextProvider` trait (`ContextTable` is a ready implementation) | Sans-IO, no global Network Data; Phase 7 implements the trait | API |
| IPv6 types | Full `Ip6::Header`/`Udp::Header` | Minimal `Ipv6Header`/`UdpHeader` in `opentrust_lowpan::ip6`, re-exported by `opentrust_net::header` (which adds setters and the extension headers); the codecs take/produce raw datagram bytes | Avoid a dependency cycle between lowpan and net | API |
| Context prefix length | Up to 128 bits | Same (bits beyond /64 are applied to the IID); stateful multicast uses the first 64 prefix bits like OT | — | none |
| Link-local detection when compressing | `IsLinkLocalUnicast` (`fe80::/10`); the decompressor restores `fe80::/64`, so `fe80:0:0:1::x` would be corrupted | Only `fe80::/64` is treated as link-local, other `fe80::/10` addresses fall through to context/inline | Round-trip correctness | none |
| Stateful multicast without context 0 | Compares against a cleared context (prefix length 0, all-zero prefix), which can wrongly match | Requires a real context 0 | Round-trip correctness | none |
| Multicast with an all-zero group (`ffXX::`) | Emits no address bytes | Sent inline (128 bit) | Round-trip correctness | none |
| SAM/DAM = 11 without MAC address | Source: IID left zero; destination: parse error | Parse error for both | Do not invent addresses | stricter |
| Context applied to link-local mode 3 | `ComputeIid` applies context 0's bits beyond /64 even when SAC = 0 | Context only used when SAC/DAC = 1 | RFC 6282 | none |
| Traffic class/IPv6 version | Compress reads the header without checking the version | `Ipv6Header::parse` requires version 6 (`Error::Parse`) | Defensive parsing | stricter |
| NHC chaining at the header-depth limit | When the compressed-header budget forces fewer compressed headers, the Hop-by-Hop NHC may still announce a compressed next header | NH bit only set if the next header will really be compressed | Round-trip correctness | none |
| ECN accessors | `DecompressEcn`/`MarkCompressedEcn` read the byte at offset 2 even when a context-ID byte is present | `iphc_ecn`/`iphc_mark_ecn` skip the context-ID byte | Correctness | none |
| Extension headers | Compresses Hop-by-Hop only; decompresses Hop-by-Hop/Routing/Fragment/Destination/IP-in-IP NHC | Same | — | none |
| UDP checksum | NHC with elided checksum rejected | Same (Thread requires inline checksum) | — | none |
| Mesh header | Short originator/destination only; hops left 0-255 (deep hops) | Same; `MESH_HEADER_HOPS_LEFT` = 19 (`kMaxRouteCost` 16 + 3) | — | none |
| Fragment header | Offset in 8-byte units; `FRAGN` with offset 0 accepted and treated as first fragment | Same | — | none |
| Reassembly storage | `Message`s from the pool in a reassembly list | Fixed const-generic slots (`Reassembler<SLOTS, MAX_DATAGRAM>`, default 1280 B each) holding the uncompressed datagram; completion returns `&[u8]` | No alloc; Phase 4 copies into a `Message` if needed | API |
| Reassembly key | Datagram size + tag (+ offset, link security); source address not compared | (originator address, size, tag) plus offset and link security | Avoid mixing datagrams of different senders with equal tags | stricter |
| Duplicate FRAG1 | A second reassembly is started | Dropped while a reassembly with the same key is pending | Retransmitted FRAG1 must not reset progress | none |
| Out-of-order / duplicate FRAGN | Dropped, pending reassembly kept | Same (`Error::Drop`) | — | none |
| Reassembly timeout | 2 s granularity via the 1 s time ticker, refreshed by each fragment | Exact deadline (`next_deadline`/`expire`, 2 s), refreshed by each accepted fragment | Sans-IO timers | none |
| Sleepy-device reassembly | Clears the list on a new secure first/mismatching next fragment | Not built in; `Reassembler::clear()` for the role layer | Role is MLE's concern | none |
| Fragmenter | Per-message state in `Message` (offset, tag), 0 = unset tag | `Fragmenter` iterator with caller-supplied tag; `TagCounter` never yields 0 | Sans-IO | API |
| Fragment size limit | `uint16_t` size masked to 11 bits | Datagrams above 2047 bytes are rejected when fragmenting (`InvalidArgs`) | Avoid silently wrong size | stricter |
| Mesh forwarding | `HandleMesh` mixes parsing, routing, queueing | `handle_mesh` only decides (deliver/forward/drop) via `LocalRlocs`/`NextHops`; a 2-hop loop is reported as `DropReason::RoutingLoop` and the caller invalidates the route; no route is detected immediately (OT drops at send time) | Routing table is Phase 7 | API |

## Network layer (IPv6) (`opentrust-net`)

| Area | OpenThread | OpenTrust | Reason | Interop |
|------|------------|-----------|--------|---------|
| API shape | `Ip6`, `Udp`, `Icmp`, `Mpl`, `Netif` operate on `Message`s from the global pool and read the instance (MLE, Network Data, child table) directly | Byte-slice datagrams, caller-provided `Scratch` space, time/RNG in `Ctx`, and an `Ip6Env` trait for role, Network Data route lookup, on-mesh test and sleepy children; `Netif`/`Mpl`/`UdpSockets`/`AddressResolver` are plain const-generic structs | Sans-IO, no alloc, no globals | API |
| Message pool | Datagrams and MPL buffered copies live in the shared message pool | MPL buffered messages are stored inline (`BUFS` x 1280 B, default 4); no pool involvement in `Ip6`/`UdpSockets` | Simple ownership without lifetimes in the public types; sizes are explicit | API |
| Extension-header validation | Only the Hop-by-Hop header is parsed for datagrams that are merely forwarded; other headers only when receiving | The whole chain is always validated (`parse_datagram`); malformed or unsupported chains are dropped even if they would only be forwarded | One parser, defensive | stricter |
| Routing header | Dropped (when processed) | Parsed and skipped by the parser; dropped by the receive path when the datagram is for us, ignored when only forwarding | Parser reusable for other callers | none |
| Fragment header | Atomic fragments walked; others dropped unless `IP6_FRAGMENTATION_ENABLE` | Same as the default build (no IPv6 reassembly; non-atomic fragments dropped) | Not needed for Thread | none |
| `RemoveMplOption` | Strips the MPL option before passing datagrams to the host | Not implemented (no host interface yet) | Phase 9 border routing | API |
| Host handling | `PassToHost` has extra policy (multicast loop, border-router counters, backbone) | `RxOutcome::forward_host` only reflects `DetermineAction` | No host interface yet | API |
| MPL timing and Trickle | Proactive forwarding with a custom random schedule (`GenerateNextTransmissionTime`, 64 ms window, router: 2 total transmissions, child: 0); **no RFC 6206 Trickle** | Same algorithm and constants, as deadlines on `Instant`; `opentrust_core::trickle` is deliberately not used because OpenThread does not use Trickle for MPL | Interop with OpenThread's observable retransmissions | none |
| MPL randomness | `Random::NonCrypto::GetUint8InRange` | `Rng::next_u32() % interval` with the caller's RNG (bias < 2^-24) | Deterministic tests | none |
| MPL seed lifetime tick | `TimeTicker` (shared 1 s tick) | Own 1 s deadline chain started at the first seed insertion | Sans-IO | none |
| MPL sleepy-child copy | `PrepareMulticastToLargerThanRealmLocal` clones the datagram for sleepy children that subscribed | Not done in `Ip6::send`; `DetermineAction` honours `has_sleepy_child_with_address` for received datagrams only | Child table is Phase 7 | API |
| Datagram size | `kMaxDatagramLength` 1280 and optional IP fragmentation | 1280 hard limit (`Error::NoBufs`) | Same default | none |
| UDP checksum | `VerifyMessageChecksum` | Verified in `Ip6::handle` (UDP: zero checksum and length mismatches dropped as OT does); `UdpSockets` re-checks the length | Defensive | none |
| UDP delivery rules | Socket list with head insertion; first match wins; multicast matches any socket on the port | Same matching rules; among overlapping matches the most recently opened socket wins (same effect as head insertion) | — | none |
| UDP bind conflicts | Platform bind decides; the internal list accepts duplicates | Explicit `Error::Already` for overlapping address/port bindings; internal receivers' ports cannot be bound | Predictable socket API for `edge-nal` | stricter |
| Ephemeral port | `GetEphemeralPort` skips TMF and SRP-server ports | Same, and also skips ports already bound | Avoid collisions without a platform bind | none |
| UDP receive queue | Callback per datagram | Bounded per-socket queue (`Q` packets of `BUF` bytes); overflow counted and dropped; longer payloads truncated with a flag | Async facade pulls data | API |
| ICMPv6 error generation | `Icmp::SendError` quotes the IPv6 header only, no limiter; errors only from the mesh forwarder/reassembly | `Ip6::build_error` quotes the IPv6 header only (like OT) and adds RFC 4443 section 2.4 suppression rules (no errors for errors, unspecified/multicast sources, multicast destinations except Packet Too Big/Param Problem code 2) and a token-bucket rate limiter (burst 10, one per 100 ms) | RFC 4443 compliance; OT has no limiter | none |
| Hop-limit exhaustion | Silent drop (no Time Exceeded) | Same | Matches OT | none |
| Echo responder | Replies via `SendDatagram` | Reply datagram built into `Scratch`; echo to our own address is not looped back through the reply path | Edge case | none |
| Source selection | `Ip6::SelectSourceAddress` | Same rules, including the RLOC rule; ALOCs are skipped before the "same address" rule as in OT | — | none |
| Address scope | `Address::GetScope`; mesh-local addresses get a realm-local scope override | Same | — | none |
| Multicast API errors | `kErrorRejected` for fixed/non-external groups | `Error::InvalidArgs` (no `Rejected` in the shared error type) | Error set | API |
| All-Thread-nodes groups | Subscribed by MLE when the mesh-local prefix changes | `Netif::set_mesh_local_prefix` (re)subscribes `ff32:40:<mlp>::1` and `ff33:40:<mlp>::1` itself | Keeps prefix-derived state consistent in one place | none |
| SLAAC IID | SHA-256(prefix, "wpan", DAD counter, 32-byte secret); Network_ID not used; secret persisted in settings | Same, with an optional RFC 7217 Network_ID (`None` = OT-compatible); secret is a caller argument | Persistence is the caller's | none |
| SLAAC manager | Reads Network Data, filter callback, notifier events | Takes the on-mesh prefix list as input (`OnMeshPrefix`), filter as `fn` pointer, 1 s deadlines instead of the time ticker | Network Data is Phase 7 | API |
| SLAAC context ID tracking | Updates the 6LoWPAN context ID per address and notifies MLE | Not tracked | Phase 7 | API |
| Address resolver API | Calls `MeshForwarder::HandleResolved`, sends TMF directly | Emits `ResolverEvent`s (send query/error, resolved/failed) to a caller sink; replies to `/a/aq` are decided by `address_query_response` | CoAP/TMF are Phase 5/7 | API |
| Address resolver lists | Four intrusive linked lists | One entry array with a state and an insertion counter (same eviction order and capacities) | No alloc, no pointers | none |
| Address resolver extras | `ResolveUsingNetDataServices`, Backbone Router queries, DUA, `/a/ae` child handling | Not implemented | Phases 7/9 | API |
| DHCPv6 | Optional client/server | Not implemented | Legacy; no use case yet | none |

## CoAP / TMF (`opentrust-coap`, TLVs in `opentrust-core::tlv`)

| Area | OpenThread | OpenTrust | Reason | Interop |
|------|------------|-----------|--------|---------|
| Generic TLVs | `Tlv` / `ExtendedTlv` structs over `Message` | `opentrust_core::tlv`: slice-based `Tlv::parse`, `TlvIter`, `find`, typed readers, `write*`/`write_with` (extended form iff value > 254 bytes); lives in core so MLE/MeshCoP reuse it | No message-chain abstraction; no dependency on CoAP | none |
| Message API | `Message` mutated in place, `Finish()` writes the header | Zero-copy `Message::parse` + `MessageBuilder` over a caller buffer; options must be added in order (`InvalidArgs` otherwise, as OT) | no alloc / no unsafe | API |
| Parse strictness | `ParseHeader` does not check the version or the empty-message rules | Version != 1 is ignored silently (RFC 7252 3); empty message (0.00) with token/options/payload is a format error | RFC 7252 3 / 4.1 | stricter |
| Format-error reply | RST for CON, unicast only | Same (needs a readable header with version 1) | | none |
| Sans-IO endpoint | `CoapBase` with callbacks, timers, message queues | `Endpoint<REQ, RES, CACHE, MSG>`: caller feeds datagrams and time, output via `Transport`; outcomes are `Rx::{Request,Response,Failed}` / `Event::Timeout` carrying a caller `u32` instead of handler pointers | Executor-free, fixed capacity | API |
| Retransmission | `TxParameters` (2000 ms, 3/2, 4), ACK stops retransmission but the request still times out after the remaining back-off | Same numbers and behaviour, deterministic with a caller RNG; `exchange_lifetime` 247 s, `max_transmit_wait` 93 s | | none |
| Duplicate detection | Response cache keyed by (message id, peer), 10 entries, earliest-expiry eviction | Same (capacity `CACHE`); like OT only requests that already have a cached piggybacked response are recognised as duplicates | | none |
| Multicast response jitter | none in the CoAP layer (individual handlers delay) | none in the endpoint; handlers delay | same as OT | none |
| Interceptor / default handler / resource handler callback | `SetInterceptor`, `SetDefaultHandler`, `SetResourceHandler` | Filtering is done by the TMF agent (`is_tmf_message`); resources are a fixed table; unknown path gets 4.04 (not for multicast); no default handler | Simplicity | API |
| Block-wise, Observe | Compile-time options, off by default | Not implemented (`BlockOption` codec only) | Off in OT's default config; Thread does not need them | none |
| CoAP Ping / reserved classes | Reserved-class and empty CON handled by the general paths | Empty CON gets RST through the unmatched-response path | | none |
| TMF link security | Not in the TMF filter (mesh forwarder drops unsecured frames) | `Agent::require_link_security` (default on) drops datagrams without link-layer security | Defence in depth | stricter |
| TMF default priority | `NewPriorityResponseMessage` per handler | `Agent::response_priority` (default net), per-request priority for `post` | | none |
| URI list | `uri_paths.cpp`, 40 entries | `Uri` enum, same paths in the same sorted order (test) | | none |
| CoAPS | `SecureAgent` on mbedTLS | `SecureTransport` trait seam, implemented by `opentrust_dtls::coaps::Coaps` (see "DTLS / EC-JPAKE") | | none |
| Test oracle | OT has no CoAP unit tests | Dev-only differential tests against `coap-lite` (random messages encode byte-identically and parse identically both ways); the production codec stays no-alloc | | none |

## DTLS / EC-JPAKE (`opentrust_core::crypto::ecjpake`, `opentrust-dtls`)

Reference: mbedTLS 3.6.0 as configured by OpenThread
(`third_party/mbedtls/mbedtls-config.h`, `src/core/meshcop/secure_transport.cpp`).
Interop was checked manually against mbedTLS 3.6.0 `ssl_server2` /
`ssl_client2` (default config + `MBEDTLS_KEY_EXCHANGE_ECJPAKE_ENABLED`):
both roles, cookies, fragmented flights, identical KEK, wrong password.

| Area | OpenThread (mbedTLS) | OpenTrust | Reason | Interop |
|------|------------|-----------|--------|---------|
| Implementation | mbedTLS `ecjpake.c` + `ssl_*.c`, heap-allocated contexts | `EcJpake<C: P256>` (port of `ecjpake.c`, `SoftP256` on RustCrypto `p256`) + `Session<B, C>` with fixed buffers (about 5 KB per session incl. the AES key schedules) | ADR 0001 | none |
| Cipher suites | `TLS_ECJPAKE_WITH_AES_128_CCM_8`; with the TLS API also PSK / ECDHE-ECDSA suites | Only `TLS_ECJPAKE_WITH_AES_128_CCM_8`; no certificates (TCAT is Phase 9) | Thread commissioning needs nothing else | none |
| EC point format | Reads uncompressed and compressed points, writes the negotiated format | Uncompressed only (sent, and required in `ec_point_formats` if the peer sends that extension) | OpenThread never negotiates compressed points | stricter |
| Password | Any length up to the MPI limit (32 bytes in OT's config); `s = 0` not rejected | 1..=32 bytes; a password that is `0 mod n` is rejected | Degenerate secrets | stricter |
| ZKP `r` encoding | Minimal length; `r = 0` would be written as an empty (invalid) vector | Same minimal length; a nonce giving `r = 0` is redrawn | Never emit an invalid message | none |
| Received points | `X` checked for zero and (via the multiplication) on-curve; `V` only compared | Every point (`X`, `V`, round-two `X`) fully validated (uncompressed, coordinates `< p`, on curve, not identity); `r < n` as mbedTLS; peer generator and shared point `K` must not be the identity; trailing bytes rejected | Defence in depth (cofactor 1, so equivalent for valid peers) | stricter |
| Blinding | Scalar blinding with random multiples of `n` and randomized coordinates | Constant-time `p256` arithmetic without extra blinding | `p256` is constant time; blinding protects mbedTLS's non-CT bignum code | none |
| Client/Server random | 32 random bytes (no `MBEDTLS_HAVE_TIME` in OT's config) | 32 random bytes | | none |
| ServerHello session id | 32 random bytes | Empty (no session cache, no resumption) | Nothing to resume | none |
| ServerHello extensions | `renegotiation_info` (if SCSV/extension seen), `ec_point_formats` (if sent by client), `ecjpake_key_kp_pair`; echoes `max_fragment_length` | Same order and conditions; `max_fragment_length` is ignored (OT clients never send it) | | none |
| Unsolicited ServerHello extensions | Ignored | Abort with `handshake_failure` (RFC 5246 §7.4.1.4) | | stricter |
| Duplicate extensions | Not checked for most extensions | Duplicates of interpreted extensions are rejected | RFC 5246 §7.4.1.4 | stricter |
| Extended master secret, encrypt-then-MAC, CID, renegotiation, tickets | Disabled in OT's config | Not implemented; requests from other mbedTLS configs are ignored (not echoed), as RFC 7627/7366 allow | | none |
| Cookies | `mbedtls_ssl_cookie`: 4-byte time + HMAC-SHA224, 60 s, bound to the peer IPv6 address | 4-byte time + truncated HMAC-SHA256 (32 bytes), 60 s, bound to the caller's client id (`Coaps`: address **and** port); ZKPs of the first ClientHello are only verified once the cookie is valid; a malformed ClientHello before cookie verification is dropped silently | Cookies are opaque to the client; less work for unverified peers | none |
| ClientHello fragmentation | Not supported (server) | Not supported (server); our client never fragments it with the default MTU | Same as mbedTLS | none |
| Future handshake messages / epoch-1 records before CCS | Buffered (`MBEDTLS_SSL_DTLS_MAX_BUFFERING`) | Dropped; recovered by the retransmission of the peer's flight. Out-of-order fragments of the current message are reassembled | Fixed RAM | none (slower recovery under reordering) |
| Retransmission | `mbedtls_ssl_conf_handshake_timeout(8000, 60000)`: retransmit after 8, 16, 32, 60 s timeouts then fail; MTU 508 from the 2nd retransmission; resend on the last message of the peer's previous flight | Same (`Config::OPENTHREAD`, default); `Config::THREAD_SPEC` (8 s / 32 s: two retransmissions as Thread 1.4.1 §7.4.5 requires, which OpenThread exceeds) | Spec vs. OT | none |
| Final flight | Server keeps its last flight while the handshake context lives | Server re-sends CCS + Finished whenever the client's Finished is retransmitted while connected | Simplicity | none |
| Record size | `MBEDTLS_SSL_MAX_CONTENT_LEN` 768 (900 with the CoAP secure API) | Sends at most 768-byte records (`MAX_CONTENT_LEN`), handshake flights packed into datagrams of at most `Config::mtu` (768); accepts handshake messages up to 768 bytes and application records as large as the caller's buffer | Do not exceed the input buffer of OT peers | none |
| Alerts | Bad MAC while expecting Finished: `bad_record_mac`; Finished mismatch: `decode_error` (+ OT `handshake_failure`); other errors: `handshake_failure` from OT's `SecureSession::Process` | Bad MAC while expecting Finished: `bad_record_mac`; every other handshake failure (ZKP, missing extension, unexpected message, Finished mismatch, timeout): `handshake_failure` | Thread 1.4.1 §7.4.4 | none |
| Invalid records | Silently discarded (DTLS) | Same, incl. replayed, wrong-epoch and unauthenticated records (64-record window) | RFC 6347 §4.1.2.7 | none |
| KEK export | `HandleMbedtlsExportKeys`: `SHA-256(key_block)[0..16]` | Same value, computed from the key block at key derivation and exposed once connected (`Session::kek`); never exposed for an aborted handshake | | none |
| Sessions / connection attempts | One `SecureSession` per transport, `mMaxConnectionAttempts`, guard times | One `Session` (or `Coaps`) per peer, created by the caller; attempt limits and guard times belong to MeshCoP (Phase 8) | Sans-IO | API |
| Application records per datagram (CoAPS) | `mbedtls_ssl_read` loop delivers all | `Session::handle_datagram` delivers all (via `Received::consumed`); `Coaps::decrypt` (one plaintext per `SecureTransport::decrypt`) delivers the first, processes the remaining handshake/alert records and drops further application records of the same datagram | Seam signature; OT/mbedTLS send one per datagram | none |
