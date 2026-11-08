# ADR 0001: EC-JPAKE and DTLS 1.2 for Thread commissioning

- Status: accepted (2026-11-07): option (a)
- Date: 2026-11-07
- Scope: Phase 1 (crypto foundations), Phase 5 (CoAPS), Phase 8 (Joiner/Commissioner)

## Context

Thread commissioning (Joiner ↔ Commissioner/Border Agent, Thread 1.4.1 §7.4 and
§8) runs CoAP over DTLS 1.2 with a single cipher suite,
`TLS_ECJPAKE_WITH_AES_128_CCM_8` (0xC0FF, draft-cragie-tls-ecjpake-01), on
curve P-256 (secp256r1). The password is the PSKd (Joiner) or the PSKc
(Commissioner). §7.4.7 specifies the EC-JPAKE rounds (Schnorr ZKPs with
`h = SHA-256(G, V, X, ID)`), the premaster secret
(`PMS = SHA-256(x(PMSK))`), the RFC 5246 PRF/key block and
`KEK = SHA-256(key_block)[0..16]`, and the AEAD (RFC 6655 `AES_128_CCM_8`).

What OpenTrust already has (Phase 1, `opentrust_core::crypto`): AES-CCM*
(incl. M=8, so `AES_128_CCM_8` record protection), SHA-256, HMAC-SHA256,
the TLS 1.2 PRF (`kdf::tls12_prf_sha256`) and the KEK derivation
(`kdf::kek_from_master_secret`). Missing: the EC-JPAKE key exchange on P-256
and the DTLS 1.2 record/handshake layer.

Constraints: `no_std`, no heap, MSRV 1.85, no `unsafe` in OpenTrust crates,
Apache-2.0, must coexist with rs-matter (which already pulls in RustCrypto
`p256` 0.14 for SPAKE2+ in its `rustcrypto` backend).

## Findings

### EC-JPAKE

- **crates.io** (searched `ecjpake`, `ec-jpake`, `jpake`, Nov 2026): no Rust
  implementation of EC-JPAKE. The only hit for `ecjpake` is `mbedtls-rs-sys`
  (raw C bindings). PAKE crates that exist (`spake2`, `pakery-spake2`,
  `pakery-spake2plus`, `pakery-cpace`, `pakery-opaque`) implement other PAKEs.
- **mbedTLS** (`third_party/mbedtls/repo/library/ecjpake.c`, ~1.2 kLOC,
  enabled in OpenThread's `mbedtls-config.h` via `MBEDTLS_ECJPAKE_C`,
  `MBEDTLS_KEY_EXCHANGE_ECJPAKE_ENABLED`): the reference implementation used
  by every certified Thread device; it has self-test vectors
  (`mbedtls_ecjpake_self_test`, fixed private keys and expected round
  messages / premaster secret) that can be ported as known-answer tests.
- **RustCrypto `p256` 0.14** (`arithmetic` feature, MSRV 1.85, `no_std`,
  no alloc) provides constant-time `ProjectivePoint`/`Scalar` arithmetic,
  SEC1 encoding and point validation: everything EC-JPAKE needs (it is
  "only" scalar multiplications, point additions, ZKP hashing and
  modular arithmetic on scalars).
- **rs-matter** implements SPAKE2+ (`rs-matter-sc/src/pase/spake2p.rs`) on
  its `Crypto` trait's `EcScalar`/`EcPoint` (backed by `p256` or mbedTLS).
  The same abstraction would carry EC-JPAKE, which lets a Matter-over-Thread
  build share one P-256 implementation (and possibly a HW-accelerated one).

### DTLS 1.2

- `dtls` 0.17 (webrtc-rs): `std` + tokio, certificate/PSK suites, no ECJPAKE.
- `dimpl` 0.9 (DTLS 1.2/1.3, sans-IO): `std`, certificate-oriented
  (WebRTC), MSRV 1.89, defaults to aws-lc-rs; no ECJPAKE, no `no_std`.
- `embedded-tls` 0.19: `no_std`, but TLS 1.3 client only (no DTLS 1.2).
- No `no_std` DTLS 1.2 crate exists, and none supports a custom PAKE key
  exchange. OpenThread itself uses mbedTLS's DTLS (`SecureTransport`).

## Options

### (a) Port EC-JPAKE to Rust on `p256`; write a minimal DTLS 1.2

EC-JPAKE (~600–800 lines of Rust) as a sans-IO state machine generic over a
small P-256 trait (default impl: RustCrypto `p256`; optional adapter onto
rs-matter's `EcPoint`/`EcScalar`). A minimal DTLS 1.2 implementing exactly
one suite and one key exchange: record layer (epochs, 48-bit sequence
numbers, replay window, `AES_128_CCM_8` via our CCM*), handshake framing
with fragmentation/reassembly into a fixed buffer, retransmission timers
(sans-IO, driven by `opentrust-core::timer`), cookie exchange
(HelloVerifyRequest), `Finished` verification via the TLS PRF, and the
EC-JPAKE extension (`ecjpake_key_kp_pair_list`, RFC 8235 Schnorr NIZK proofs) and
ServerKeyExchange/ClientKeyExchange. No certificates, no renegotiation, no
resumption (ePSKc forbids it anyway; Thread does not need it).

- \+ Pure Rust, `no_std`, no alloc, no `unsafe`, fits the sans-IO design and
  the async facade; one crypto backend story (HW AES via `CryptoBackend`).
- \+ Small, auditable scope: one cipher suite, one curve.
- − New security-critical code: needs careful constant-time review, KATs from
  mbedTLS self-test, and differential/interop tests against OpenThread.
- − DTLS handshake state machine is fiddly (fragmentation, retransmission,
  epoch switching), estimated 1.5–2.5 kLOC incl. tests.

### (b) Bind mbedTLS via FFI for EC-JPAKE (and/or DTLS)

Build mbedTLS (as in `tools/openthread-sys` or `mbedtls-rs-sys`, which
esp-rs/openthread and rs-matter's `mbedtls` backend already use) and call
`mbedtls_ecjpake_*` / `mbedtls_ssl_*`.

- \+ Battle-tested, the exact code certified devices run; fastest path.
- − Requires `unsafe` FFI and a C toolchain for every target (cross-compiling
  for thumbv7em/thumbv8m/riscv32), libc shims (`tinyrlibc`), and either a
  heap (mbedTLS SSL contexts use `calloc`) or a static allocator; conflicts
  with "pure Rust" and with the `unsafe_code = "deny"` workspace lint (would
  need an isolated `-sys` crate).
- − Using only `ecjpake.c` still needs `bignum.c`/`ecp.c` (large), and its
  RNG/allocation conventions; using the full DTLS stack drags in most of
  mbedTLS (tens of kB flash).

### (c) Existing Rust crates

- No Rust EC-JPAKE crate exists; no `no_std` DTLS 1.2 crate exists; the
  existing DTLS crates are `std`/WebRTC-oriented and would need forking to
  add a PAKE suite and remove `std`. Not viable.

## Decision

**Option (a)**: implement EC-JPAKE in Rust on RustCrypto `p256` (behind a
narrow P-256 trait so a hardware or rs-matter-backed implementation can be
substituted), and write a minimal sans-IO DTLS 1.2 that supports only
`TLS_ECJPAKE_WITH_AES_128_CCM_8`, reusing `opentrust_core::crypto` (CCM*,
TLS PRF, KEK). mbedTLS is used **only as a test oracle**: its EC-JPAKE
self-test vectors become Rust KATs, and `tools/openthread-sys` (OpenThread +
mbedTLS) serves as the interop/differential peer for full Joiner and
Commissioner handshakes in simulation.

Placement: EC-JPAKE in `opentrust-core::crypto::ecjpake` (feature
`ecjpake`, pulls in `p256`), DTLS in `opentrust-coap` (or a dedicated
`opentrust-dtls` crate if it grows), driven by `opentrust-meshcop`.

## Consequences

- `p256 = { version = "0.14", default-features = false, features =
  ["arithmetic"] }` (same line as rs-matter, so a combined build has a
  single copy). Implemented: `opentrust_core::crypto::ecjpake` (feature
  `ecjpake`) and the `opentrust-dtls` crate (with `coaps::Coaps` behind
  `SecureTransport`).
- Security review of the EC-JPAKE/DTLS code is mandatory before M4
  (constant-time scalar handling, ZKP verification incl. point validation
  and rejection of the identity, `Finished` MAC comparison in constant time,
  replay window, nonce uniqueness).
- Test plan: mbedTLS `ecjpake` self-test KATs; ZKP negative tests; DTLS
  handshake transcripts captured from OpenThread (`ot-cli` joiner/commissioner
  in simulation) replayed against the Rust implementation; live interop with
  OpenThread nodes in `opentrust-sim`; fuzzing of the record/handshake
  parsers.
- If the minimal DTLS turns out too costly, fall back to (b) for DTLS only,
  isolated in a `-sys` crate behind a feature, keeping EC-JPAKE in Rust.
- TCAT (Thread 1.4, TLS 1.2 with certificates over BLE) is out of scope of
  this ADR; it would need ECDHE-ECDSA and X.509 and is re-evaluated in
  Phase 9.
