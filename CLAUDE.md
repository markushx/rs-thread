# rs-thread

## Objective

Create a pure Rust implementation of the Thread 1.4.1 protocol for embedded devices.

The existing code in this directory is old possibly outdated code.

Target embedded devices (esp32, nrf52, nrf54, ...) and simulation/emulation

Re-use existing test framework from OpenThread within Rust tool landscape (cargo test).
Re-use existing OpenThread Rust bindings.

## Documents

Thread 1.4.1 specification: spec/Threadv1.4.1SpecificationFinal_5345_1.pdf

## Before creating a PR

Run all three CI checks locally and fix any failures before pushing:

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace --exclude openthread-sys
```

Or auto-fix format and then check the other two:

```sh
cargo fmt
cargo clippy --all-targets -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace --exclude openthread-sys
```

## Links

OpenThread: <https://github.com/openthread/openthread>
Thread Rust bindings: <https://github.com/esp-rs/openthread>
rs-matter: <https://github.com/project-chip/rs-matter>
