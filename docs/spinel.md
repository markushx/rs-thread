# Spinel: rs-thread as OpenThread's radio co-processor

Spinel is the host/co-processor protocol of OpenThread. rs-thread implements
the **RCP** side (an rs-thread radio serves OpenThread host software such as
`ot-br-posix` or the posix `ot-cli`); the **NCP** side (the rs-thread stack
behind Spinel) is not implemented yet.

| crate | contents |
|-------|----------|
| `rs-thread-spinel` | `no_std`, no alloc: HDLC-lite framing (`Hdlc::Encoder` / `Decoder` of OpenThread, CRC-16/X.25), Spinel data types (`codec::Writer` / `Reader`: packed integers, `d`, `D`, `U`, `t(...)`), frame header and `Frame` parsing, command / status / capability / property constants |
| `rs-thread-ncp` | `no_std`, no alloc: `rcp::Rcp`, any `rs_thread_platform::radio::Radio` behind the Spinel radio property set, over a `rcp::Transport` (UART, USB CDC, pipe) |
| `rs-thread-rcp-sim` | host binary: `Rcp` on stdin / stdout plus OpenThread's real-time simulation radio (UDP multicast), like `ot-rcp` of the simulation platform |
| `examples/nrf52840-leader` `--bin rcp` | firmware: the nRF52840 radio (`radio-nrf802154`) as RCP on the DK's VCOM UART |

## Status

- Frame codec and HDLC: unit tests with the vectors of OpenThread's
  `tests/unit/test_hdlc.cpp` (encoder / decoder round trip, bad short frame),
  the CRC-16/X.25 check value and the packed integer examples of the
  specification.
- RCP engine: tests against `TestRadio` (what a host sees: boot notification,
  identity properties, configuration, receive, transmit with ACK / retries /
  failure, source match, MAC keys, energy scan, reset), `cargo test -p rs-thread-ncp`.
- Interoperability: OpenThread's posix host `ot-cli` with `rs-thread-rcp-sim`
  as RCP (`crates/rs-thread-rcp-sim/tests/posix_host.rs`): the host forms a
  network, an `ot-cli-ftd` simulation node joins and both ping each other;
  and the reverse (the OpenThread node leads, the host attaches). A subset of
  OpenThread's own `tests/scripts/expect/posix-*.exp` runs against the RCP
  (see below).
- Real-time simulation only: OpenThread's posix host cannot run in virtual
  time against an RCP over a pipe (the posix virtual-time mode needs the
  UART carried as simulator events), so the interop tests use the real-time
  simulation radio (UDP multicast on `224.0.0.116`, `PORT_BASE` /
  `PORT_OFFSET`). A test takes about 5 s.
- Not done: NCP mode, hardware runs (the firmware only builds).

## Supported properties (RCP)

`GET` unless noted; `S` = `SET`, `I`/`R` = `INSERT` / `REMOVE`.

| property | notes |
|----------|-------|
| `PROTOCOL_VERSION`, `NCP_VERSION`, `INTERFACE_TYPE`, `VENDOR_ID`, `INTERFACE_COUNT`, `CAPS`, `HWADDR`, `RCP_VERSION` | `CAPS`: radio co-processor, raw MAC stream, writable raw stream, 802.15.4 2003/2006/2011 and 2.4 GHz O-QPSK, RCP API version and minimum host API version |
| `RCP_API_VERSION` (11), `RCP_MIN_HOST_API_VERSION` (4) | as OpenThread |
| `LAST_STATUS` | unsolicited boot / reset notification, status of failed commands, transmit done |
| `PHY_ENABLED` S, `PHY_CHAN` S, `PHY_CHAN_SUPPORTED`, `PHY_CHAN_PREFERRED`, `PHY_FREQ` | channels 11 to 26 |
| `PHY_TX_POWER` S, `PHY_CCA_THRESHOLD` S, `PHY_RX_SENSITIVITY`, `PHY_FEM_LNA_GAIN` S | the LNA gain is stored only (no radio has an FEM) |
| `PHY_RSSI` | a 1 ms energy scan of the receive channel (the `Radio` trait has no instantaneous RSSI) |
| `RADIO_CAPS` | the radio's PHY capabilities plus the retries and the transmit security the RCP provides itself |
| `MAC_15_4_PANID` S, `MAC_15_4_SADDR` S, `MAC_15_4_ALT_SADDR` S, `MAC_15_4_LADDR` S, `MAC_PROMISCUOUS_MODE` S, `MAC_RX_ON_WHEN_IDLE_MODE` S | become the radio's `Config` |
| `MAC_RAW_STREAM_ENABLED` S | receive on `PHY_CHAN` / sleep |
| `MAC_SRC_MATCH_ENABLED` S, `MAC_SRC_MATCH_SHORT_ADDRESSES` S/I/R, `MAC_SRC_MATCH_EXTENDED_ADDRESSES` S/I/R | up to 16 entries each; become the radio's `SrcMatchConfig` |
| `STREAM_RAW` | `SET` transmits (channel, CSMA flag, max backoffs, max retries, header updated, retransmission, security processed, TX delay, delay base time, RX channel after TX, power); the answer is the transmit-done `LAST_STATUS` with ACK frame and the key ID / frame counter assigned; received frames are reported unsolicited with RSSI, LQI, timestamp, ACK frame-pending / secured-ACK flags |
| `MAC_SCAN_MASK` S, `MAC_SCAN_PERIOD` S, `MAC_SCAN_STATE` S, `MAC_ENERGY_SCAN_RESULT` | energy scan (the scan runs inline and blocks the RCP for its duration) |
| `MAC_RX_AT` S | timed receive, only if the radio has `RECEIVE_TIMING` (nRF52840: yes) |
| `RCP_MAC_KEY` S, `RCP_MAC_FRAME_COUNTER` S | kept for the software transmit security and handed to the radio (secured enhanced ACKs) |
| `RCP_TIMESTAMP` | the radio clock (the radio's `clock`, else the monotonic clock of the firmware) |
| `RCP_CSL_ACCURACY`, `RCP_CSL_UNCERTAINTY` | from the radio's capabilities |
| `RCP_LOG_CRASH_DUMP` S | accepted, nothing to dump |
| commands `NOOP`, `RESET`, `PROP_VALUE_GET/SET/INSERT/REMOVE` and the replies `IS`, `INSERTED`, `REMOVED` | `RESET` clears the RCP state, puts the radio to sleep and sends `RESET_SOFTWARE` |

### Unsupported (answered with `PROP_NOT_FOUND`, `NOT_CAPABLE` or ignored)

- `RCP_ENH_ACK_PROBING`: the `Radio` trait has no enhanced ACK probing
  (link metrics probing of a CSL / sleepy child by ACK IEs).
- `RADIO_COEX_ENABLE` / `RADIO_COEX_METRICS`, `PHY_CHAN_MAX_POWER`,
  `PHY_REGION_CODE`, `PHY_CALIBRATED_POWER`, `PHY_CHAN_TARGET_POWER`,
  `PHY_PCAP_ENABLED`: no radio coexistence, power tables or region handling.
- `MAC_ALLOWLIST` / `DENYLIST` / `FIXED_RSS` (simulation helpers), counters
  (`CNTR_*`), `STREAM_LOG` / `STREAM_DEBUG`, multi-PAN (`MULTIPAN_*`),
  `SPINEL_RESET_BOOTLOADER`, diagnostics (`diag`).
- CSL: the RCP does not fill the CSL IE phase of frames a CSL child sends
  (`PsduTxInfo::csl_present` is never set), and `rs-thread-rcp-sim` answers
  every frame with an immediate ACK (no enhanced ACK, so no CSL). A radio
  with `TRANSMIT_SEC` (nRF52840) does its own CSL processing.

## Capabilities a host needs

An OpenThread 1.2+ posix host refuses an RCP without `tx-security` and
`tx-timing` radio capabilities. `Rcp` always reports `TRANSMIT_RETRIES` and
`TRANSMIT_SEC` (it does both in software when the radio does not) but
`TRANSMIT_TIMING` only if the radio has it: the simulation radio and the
nRF52840 do.

## How to run

Real-time OpenThread binaries (needs `cmake` and `ninja`, builds the
OpenThread posix host and the real-time simulation nodes, about 3 min):

```sh
cargo build -p openthread-sys --features posix-host   # -> <target>/ot-sim/ot-cli-posix, ot-cli-ftd-rt, ot-rcp-rt
cargo build -p rs-thread-rcp-sim
cargo test -p rs-thread-rcp-sim                        # skips without the OpenThread binaries
```

By hand:

```sh
PORT_OFFSET=1 ot-cli-posix 'spinel+hdlc+forkpty://target/debug/rs-thread-rcp-sim?forkpty-arg=1'
PORT_OFFSET=1 ot-cli-ftd-rt 2     # a simulation peer on the same radio
```

The node ID is the `forkpty-arg`; `rs-thread-rcp-sim` takes `PORT_BASE`
(default 9000) and `PORT_OFFSET` (default 0) like OpenThread's simulation
and logs to the file named by `RSTHREAD_RCP_LOG` (`RSTHREAD_RCP_HEX=1`
adds the received PSDUs); it never writes to stderr (which is the Spinel
link).

OpenThread's expect scripts (`tests/scripts/expect/posix-*.exp`) run against
the RCP with `OT_NODE_TYPE=rcp`, `OT_POSIX_APPS` pointing at a directory with
`ot-cli-posix` as `ot-cli`, and `OT_SIMULATION_APPS` at one with
`rs-thread-rcp-sim` as `ncp/ot-rcp` (and the real-time `ot-cli-ftd` as
`cli/ot-cli-ftd`). Keep the working directory fresh per run: the posix host
and the simulation nodes persist their settings (frame counters!) in `tmp/`,
and stale ones make the secured frames of a new run fail the replay check.

### Expect scripts against `rs-thread-rcp-sim`

A script counts as passed when it reaches its final `dispose_all` (the
`dispose_all` itself hangs on macOS because the posix CLI ignores `^D`, so
the run is cut after 60 s):

| script | result |
|--------|--------|
| `posix-rcp`, `posix-rcp-energy-scan`, `posix-channel-mask`, `posix-ccathreshold`, `posix-fem-lnagain`, `posix-scan-tx-to-sleep` (two RCPs, active scan) | pass |
| `posix-max-power-table`, `posix-power-calibration`, `posix-diag-rcp` | reach the end (the power table / calibration properties are answered `PROP_NOT_FOUND`; the script does not check them against the RCP) |
| `posix-url-enable-coex` | the host stops: `RADIO_COEX_ENABLE` is not supported |
| `posix-rcp-restoration`, `posix-rcp-stack-reset` | skipped by the scripts on macOS (need `socat`); not run |

## Firmware (`examples/nrf52840-leader`, `--bin rcp`)

`cargo build --release --bin rcp --features rcp` (target dir
`$CARGO_TARGET_DIR/fw`, see the example's `.cargo/config.toml`). The
nRF52840 radio behind Spinel on UARTE0 (the DK's VCOM port, TX P0.06 / RX
P0.08, 460800 8N1, no flow control). Not flashed or run yet.

| | size |
|---|---|
| flash | about 105 KB (`.text` 96 KB, `.rodata` 5.7 KB, `.data` 3.2 KB) |
| static RAM | about 16 KB (`.bss` 12 KB, `.data` 3.2 KB, `.uninit` 1 KB), of it 2 KB UART buffers and about 2 KB RCP buffers |

Host side: `spinel+hdlc+uart:///dev/cu.usbmodemXXXX?uart-baudrate=460800`.

## Next steps on hardware

1. Flash the `rcp` firmware on a DK (the J-Link VCOM port is the link) and
   run `ot-cli-posix 'spinel+hdlc+uart:///dev/cu.usbmodemXXXX?uart-baudrate=460800'`:
   `rcp version`, `eui64`, form a network, scan.
2. Interop with a second device (the nRF52840 DK light or an OpenThread
   node): attach both ways, ping, an energy scan; look at ACK timing at
   460800 baud and RX ring overflow at 1024 bytes under load.
3. `ot-br-posix` on the Mac with the RCP in place of the OpenThread RCP of the
   border router (`docs/thread-border-router.md`), SRP registration and a
   Matter commissioning through it.
4. CSL and link metrics probing (`RCP_ENH_ACK_PROBING`): enhanced ACK
   handling in the RCP engine and the CSL IE phase of CSL child frames.
5. USB CDC ACM transport for the nRF52840 Dongle (`Transport` over
   `embassy-usb`), the usual RCP hardware.
6. The NCP side (below).

## NCP (not implemented)

OpenThread itself moved from NCP to RCP + posix host for the border router;
the remaining NCP hosts are `wpantund` (unmaintained), the Zephyr / ESP hosts
and `pyspinel`'s `spinel-cli.py`. An NCP would serve `NET_*`, `THREAD_*`,
`IPV6_*` and `STREAM_NET` from `rs-thread-instance` over the same
`Transport`; the codec and constants of `rs-thread-spinel` are written for
it.
