# nrf-802154-sys macOS cross-compile fix (llvm-ar)

## Problem

On macOS, `nrf-802154-sys` builds its C driver via CMake using the system `ar`
(`/usr/bin/ar`).  macOS `ar` only understands Mach-O objects; it silently
creates an empty archive (96 bytes, only the `__.SYMDEF SORTED` header) when
given ARM ELF `.obj` files.  `ranlib` then prints a warning and exits, leaving
the library empty.  The result is a successful-looking CMake build followed by
a cascade of `undefined symbol: nrf_802154_*` linker errors when cargo links
the final firmware binary.

The same CMake build directory is reused across cargo invocations (Cargo caches
it), so running `cargo build` a second time just reuses the empty archives and
fails again.

## Symptoms

```
error: linking with `rust-lld` failed: exit status: 1
rust-lld: error: undefined symbol: nrf_802154_tx_power_get
rust-lld: error: undefined symbol: nrf_802154_init
...
```

The CMake build itself reports `[100%] Built target nrf-802154-driver` with no
errors — the problem is invisible until link time.

## Fix (manual, one-time per clean target dir)

Find the build dir (the hash changes if `nrf-802154-sys` is rebuilt from
scratch):

```bash
BUILD=/Users/markusbecker/src/opentrust/target/fw/thumbv7em-none-eabihf/release/build/nrf-802154-sys-*/out/build
LLVM_AR=$HOME/.rustup/toolchains/$(rustup toolchain list | grep -v override | grep stable | head -1 | awk '{print $1}')/lib/rustlib/aarch64-apple-darwin/bin/llvm-ar
```

Rebuild the ELF object files and archive them with `llvm-ar`:

```bash
# Rebuild objects (cmake --clean-first to regenerate .obj files)
cmake --build $BUILD --target nrf-802154-driver --clean-first

# Re-archive with llvm-ar instead of macOS ar
$LLVM_AR qc $BUILD/nrf_802154/driver/libnrf-802154-driver.a \
  $(find $BUILD/nrf_802154/driver/CMakeFiles/nrf-802154-driver.dir -name "*.obj" | tr '\n' ' ')
$LLVM_AR s $BUILD/nrf_802154/driver/libnrf-802154-driver.a

$LLVM_AR qc $BUILD/nrf_802154/common/libnrf-802154-common.a \
  $(find $BUILD/nrf_802154/common/CMakeFiles/nrf-802154-common.dir -name "*.obj" 2>/dev/null | tr '\n' ' ')
$LLVM_AR s $BUILD/nrf_802154/common/libnrf-802154-common.a
```

Delete the stale `nrf-802154-sys` rlibs so cargo re-links:

```bash
rm -f /Users/markusbecker/src/opentrust/target/fw/thumbv7em-none-eabihf/release/deps/libnrf_802154_sys-*.rlib \
      /Users/markusbecker/src/opentrust/target/fw/thumbv7em-none-eabihf/release/deps/libnrf_802154_sys-*.rmeta \
      /Users/markusbecker/src/opentrust/target/fw/thumbv7em-none-eabihf/release/deps/nrf_802154_sys-*.d
```

Then `cargo build --release` in `examples/nrf52840-light` succeeds.

## Root cause

The `nrf-802154-sys` build script (`build.rs`) calls `cmake::Config::new(…)` but
does not set `CMAKE_AR` to an ELF-capable archiver.  CMake picks up the host
`/usr/bin/ar`, which produces empty archives for cross-compiled objects.

The upstream fix is to add

```rust
.define("CMAKE_AR", llvm_ar_path)
.define("CMAKE_RANLIB", llvm_ranlib_path)
```

to the `cmake::Config` call in `nrf-802154-sys/build.rs` and open a PR to
[sysgrok/nrf-802154](https://github.com/sysgrok/nrf-802154).

## Notes

- This only affects the **nrf52840-light** firmware (uses `radio-nrf802154`
  feature).  The workspace embedded check (`cargo check-nrf52`) uses
  `radio-embassy` and is not affected.
- The build dir hash in the path changes whenever the `nrf-802154-sys` crate
  is rebuilt from scratch (e.g. after `cargo clean`).  Use the glob pattern
  `target/fw/.../release/build/nrf-802154-sys-*/out/build` to find the
  current one.
