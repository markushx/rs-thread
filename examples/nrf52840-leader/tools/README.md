# nrf52840-leader tools

- `mkshims.sh`: ar/ranlib/clang shims for the `radio-nrf802154` backend on macOS.
- `runpty.py`: run `probe-rs run` on a pty and log the defmt output
  (`python3 -I tools/runpty.py <log> <secs> probe-rs run --probe <sel> --chip nRF52840_xxAA <elf>`).
- `otcli.py`: drive an OpenThread CLI device over its VCOM port (interop tests); `drain:<s>` prints asynchronous output (UDP receive, scan results) for that long.

The `cli` binary (`cargo build --release --bin cli --features cli-all`) is the OpenTrust
CLI on UARTE0 (TX P0.06, RX P0.08, 115200 8N1: the J-Link VCOM port of the DK), so
`otcli.py` drives it like an `ot-cli-ftd` DK. Its settings are kept in RAM only.

Interop test: build `ot-cli-ftd` from ot-nrf528xx (UART transport), flash it to
the second DK, start it with the dataset `DATASET_HEX` of `src/lib.rs`, and run
the `node` binary (`--features child-only` for a child that never upgrades) on
the first DK.
