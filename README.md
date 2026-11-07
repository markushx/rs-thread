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
| `crates/opentrust-mle` | Mesh Link Establishment |
| `crates/opentrust-mesh` | Routing, router IDs, Network Data |
| `crates/opentrust-meshcop` | Commissioning, datasets |
| `crates/opentrust-embassy` | Async API |
| `crates/opentrust-matter` | rs-matter integration |
| `crates/opentrust-cli` | OpenThread-compatible CLI |
| `crates/opentrust-ncp` | Spinel NCP/RCP |
| `crates/opentrust-sim` | Simulation platform (std) |
| `tools/openthread-sys` | FFI bindings to OpenThread (`thread-reference-20250612`), used as test oracle; not built by default |
| `docs/` | Spec map, research notes |

## Building

```sh
cargo test                  # host tests
cargo check-nrf52           # thumbv7em-none-eabihf
cargo check-nrf54           # thumbv8m.main-none-eabihf
cargo check-esp32c6         # riscv32imac-unknown-none-elf
```

Logging: enable either the `defmt` or the `log` feature (not both).

The OpenThread submodule is only needed for `tools/openthread-sys`:
`git submodule update --init`.

## License

Apache-2.0, see [LICENSE](LICENSE). The vendored OpenThread sources are BSD-3-Clause.
