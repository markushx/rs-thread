# OpenTrust

A pure Rust implementation of the [Thread](https://www.threadgroup.org/) 1.4.1
protocol for embedded devices (nRF52, nRF54, ESP32-C6/H2) and simulation.
Designed to serve as the Thread transport for
[rs-matter](https://github.com/project-chip/rs-matter).

- `no_std`, no heap allocation by default
- I/O-free protocol core plus an executor-agnostic async API (`embassy-sync`)
- Tested against [OpenThread](https://github.com/openthread/openthread), the
  reference implementation, using OpenThread's test vectors and certification scripts

**Status:** early development. See [PLAN.md](PLAN.md) for the roadmap.

## Layout

| Path | Purpose |
|------|---------|
| `crates/opentrust-core` | Core types, buffers, timers, crypto/settings traits, logging |
| `crates/opentrust-platform` | Platform traits: radio, clock/alarm, entropy, settings |
| `crates/opentrust-mac` | IEEE 802.15.4 MAC |
| `crates/opentrust-lowpan` | 6LoWPAN adaptation |
| `crates/opentrust-net` | IPv6/UDP/ICMPv6, MPL, address resolution, SRP/DNS-SD |
| `crates/opentrust-coap` | CoAP, TMF, CoAPS |
| `crates/opentrust-dtls` | Sans-IO DTLS 1.2 with EC-JPAKE (`TLS_ECJPAKE_WITH_AES_128_CCM_8`) for commissioning / CoAPS |
| `crates/opentrust-mle` | Mesh Link Establishment |
| `crates/opentrust-mesh` | Routing, router IDs, Network Data |
| `crates/opentrust-meshcop` | Commissioning, datasets |
| `crates/opentrust-instance` | `Instance`: one Thread node wiring all layers (sans-IO), public API ([ADR 0003](docs/decisions/0003-instance.md)) |
| `crates/opentrust-embassy` | Async API |
| `crates/opentrust-matter` | rs-matter integration |
| `crates/opentrust-cli` | OpenThread-compatible CLI |
| `crates/opentrust-ncp` | Spinel NCP/RCP |
| `crates/opentrust-sim` | Simulated 802.15.4 medium and multi-node `Network` harness (std, for tests) |
| `tools/openthread-sys` | FFI bindings to OpenThread (`thread-reference-20250612`), used as test oracle; not built by default |
| `docs/` | Spec map, research notes |

## Building

```sh
cargo test                  # host tests
cargo check-nrf52           # thumbv7em-none-eabihf
cargo check-nrf54           # thumbv8m.main-none-eabihf
cargo check-esp32c6         # riscv32imac-unknown-none-elf
```

## Quick start

An `Instance` is a Thread node without a radio, clock or executor: the host
feeds it frames and time and executes the radio actions it asks for. The
simulator in `opentrust-sim` does exactly that for N nodes
(`crates/opentrust-sim/tests/` has more):

```rust
use opentrust_instance::Role;
use opentrust_sim::Network;

let mut net = Network::routers(2, /* seed */ 1);
net.medium.connect(0, 1, -60);
let dataset = net.node(0).create_dataset(15)?;
for i in 0..2 {
    net.with(i, |n, now| {
        n.set_active_dataset(&dataset, now)?;
        n.ip6_set_enabled(true);
        n.thread_start(now)
    })?;
}
net.run_until(Duration::from_secs(300), |n| n.node(1).role() == Role::Router);
```

On a device the same calls drive a real radio: loop over
`instance.handle_radio_rx(..)`, `instance.poll(now)`,
`instance.poll_radio_action(now)` / `handle_radio_tx_done(..)` and sleep until
`instance.next_deadline()`.

Logging: enable either the `defmt` or the `log` feature (not both).

Crypto: `opentrust-core` ships a RustCrypto software backend behind the
default feature `soft-crypto`; disable default features to use only a
hardware backend (`opentrust_core::crypto::CryptoBackend`).

The OpenThread submodule is only needed for `tools/openthread-sys`:
`git submodule update --init`.

## License

Apache-2.0, see [LICENSE](LICENSE). The vendored OpenThread sources are BSD-3-Clause.
