#!/bin/sh
# Create ar/ranlib/clang shims for building the nRF 802.15.4 driver C code
# with the default `radio-nrf802154` backend on macOS (no arm-none-eabi
# toolchain needed). Usage, from anywhere:
#   export PATH="$(examples/nrf52840-leader/tools/mkshims.sh):$PATH"
# The shims go to <target-dir of .cargo/config.toml>/shims (target/fw/shims)
# and the script prints that directory.
set -e
here=$(cd "$(dirname "$0")/.." && pwd)
tdir=$(sed -n 's/^target-dir *= *"\(.*\)"/\1/p' "$here/.cargo/config.toml")
dir="${tdir:-$here/target}/shims"
mkdir -p "$dir"
sysroot=$(rustc --print sysroot)
host=$(rustc -vV | sed -n 's/^host: //p')
ln -sf "$sysroot/lib/rustlib/$host/bin/llvm-ar" "$dir/ar"
ln -sf /usr/bin/true "$dir/ranlib"
ln -sf /usr/bin/clang "$dir/clang"
echo "$dir"
