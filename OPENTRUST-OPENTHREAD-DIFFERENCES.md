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
| DTLS / EC-JPAKE | mbedTLS | Rust EC-JPAKE on RustCrypto `p256` + minimal sans-IO DTLS 1.2 (ADR 0001); mbedTLS only as test oracle | No heap, no C toolchain, no `unsafe` | none (planned, Phase 5) |

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
