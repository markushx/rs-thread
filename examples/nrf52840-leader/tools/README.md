# nrf52840-leader tools

- `mkshims.sh`: ar/ranlib/clang shims for the `radio-nrf802154` backend on macOS.
- `runpty.py`: run `probe-rs run` on a pty and log the defmt output
  (`python3 -I tools/runpty.py <log> <secs> probe-rs run --probe <sel> --chip nRF52840_xxAA <elf>`).
- `otcli.py`: drive an OpenThread CLI device over its VCOM port (interop tests).

Interop test: build `ot-cli-ftd` from ot-nrf528xx (UART transport), flash it to
the second DK, start it with the dataset `DATASET_HEX` of `src/lib.rs`, and run
the `node` binary (`--features child-only` for a child that never upgrades) on
the first DK.
