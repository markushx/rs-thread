# Thread Border Router for the OpenTrust Matter light

The nRF52840 light (`examples/nrf52840-light`) can be commissioned two ways:
over BLE (the default build, section 5a: chip-tool hands it the Thread dataset)
or on-network with a build-time dataset (chip-tool reaches it over IP). Both
need a Thread Border Router (BR) that

- is on the same Thread network as the light (same Active Dataset),
- runs an SRP server and an advertising proxy, so the light's `_matterc._udp`
  service shows up as mDNS on your LAN,
- routes between the LAN and the Thread mesh (an on-mesh prefix with SLAAC and
  a route to it on the host that runs chip-tool).

The light gets an address from the BR's on-mesh prefix by SLAAC, registers it
(and not its mesh-local address) with the BR's SRP server and keeps the
registration up to date. A BR needs no input from the light besides the dataset.

## What you need

- A Linux machine (Raspberry Pi 4/5 or a PC; macOS also works, see the end)
  with Ethernet or Wi-Fi to the same LAN as the machine that runs chip-tool.
- A third nRF52840 DK (or an nRF52840 Dongle) as the radio co-processor (RCP).
- The other two DKs: the one with the light, optionally the OpenThread peer.

## 1. The RCP image

The RCP runs OpenThread's radio-only firmware (`ot-rcp`) and talks Spinel to
`otbr-agent` over USB CDC. Built from ot-nrf528xx (`d2c0b13`, OpenThread
`e5629fa`) with the Nordic GCC toolchain:

```sh
git clone --recurse-submodules https://github.com/openthread/ot-nrf528xx
cd ot-nrf528xx
# DK, nRF USB connector (J3), no bootloader:
OT_CMAKE_NINJA_TARGET=ot-rcp ./script/build nrf52840 USB_trans
# nRF52840 Dongle (Nordic USB bootloader): add -DOT_BOOTLOADER=USB
arm-none-eabi-objcopy -O ihex build/bin/ot-rcp ot-rcp.hex
```

Why USB CDC and not the J-Link VCOM UART: the ot-br-posix documentation and the
OpenThread codelabs use `USB_trans` for the nRF52840 and the host sees
`/dev/ttyACM0` at full speed with no flow-control wiring. The UART variant
(`UART_trans`, 460800 baud, hardware flow control on the J-Link VCOM) also works
but only with `rtscts` enabled on both sides, and drops frames when the cable
or the setting is off.

Prebuilt images from this repository's work are kept next to the build:
`ot-rcp-nrf52840-dk-usb.hex` (DK) and `ot-rcp-nrf52840-usb.hex` (Dongle, with
`OT_BOOTLOADER=USB`). Flash the DK with the J-Link on its debug USB port
(`probe-rs download --chip nRF52840_xxAA --binary-format hex ot-rcp.hex` or
`nrfjprog --program ot-rcp.hex --chiperase --verify -r`), then move the cable to
the **nRF USB** port (J3 on the DK; switch "nRF power source" to VDD, "nRF only"
as the DK manual describes). The Dongle is flashed with
`nrfutil device program` / the nRF Connect "Programmer" app from the DFU package.
Do not use the board with the light or the peer for this.

## 2. ot-br-posix on Linux

Docker (simplest, Raspberry Pi OS / Ubuntu, 64 bit):

```sh
docker run -d --name otbr --sysctl "net.ipv6.conf.all.disable_ipv6=0 net.ipv4.conf.all.forwarding=1 net.ipv6.conf.all.forwarding=1" \
  -p 8080:80 --dns=127.0.0.1 -it --volume /dev/ttyACM0:/dev/ttyACM0 --privileged \
  openthread/border-router --radio-url "spinel+hdlc+uart:///dev/ttyACM0?uart-baudrate=460800" \
  --backbone-interface eth0
```

(`--backbone-interface` is the LAN interface; on Wi-Fi `wlan0`.) From source:

```sh
git clone https://github.com/openthread/ot-br-posix && cd ot-br-posix
./script/bootstrap
INFRA_IF_NAME=eth0 ./script/setup        # builds and installs otbr-agent, sets up the services
```

Both enable the SRP server with the advertising proxy (`OTBR_SRP_ADVERTISING_PROXY=ON`),
the Border Routing manager (it announces the OMR prefix) and the web UI on
port 80/8080. The SRP server is published in the Network Data as service
`5d` (unicast) or `5c` (anycast); OpenTrust's SRP client finds either.

## 3. Form the network and get the dataset

```sh
sudo ot-ctl dataset init new
sudo ot-ctl dataset channel 15          # any of 11..26, a quiet one
sudo ot-ctl dataset commit active
sudo ot-ctl ifconfig up
sudo ot-ctl thread start
sudo ot-ctl state                       # leader after a few seconds
sudo ot-ctl netdata show                # an on-mesh prefix (OMR) and the SRP service 5d/5c
sudo ot-ctl srp server state            # running
sudo ot-ctl dataset active -x           # THE DATASET HEX
```

`dataset active -x` prints one hex string (about 200 characters). Keep it.
In `netdata show` the prefix line must read like `fd0d:... paos med` (P =
preferred, A = SLAAC address configuration, O = on mesh, S = stable). If there is
no on-mesh prefix the BR has no working infrastructure link yet (see
Troubleshooting).

## 4. Build and flash the light with the dataset

```sh
export OPENTRUST_DATASET=<hex from "dataset active -x">
cd examples/nrf52840-light
unset CARGO_TARGET_DIR
export PATH="$(../nrf52840-leader/tools/mkshims.sh):$PATH"
CARGO_INCREMENTAL=0 cargo build --release          # router eligible (FTD)
CARGO_INCREMENTAL=0 cargo build --release --features med   # end device, never a router
probe-rs download --chip nRF52840_xxAA --probe <selector> \
  ../../target/fw/thumbv7em-none-eabihf/release/nrf52840-light
probe-rs reset --chip nRF52840_xxAA --probe <selector>
```

The build embeds the dataset (`build.rs` reads `OPENTRUST_DATASET` and rebuilds
when it changes). Without the variable the light forms its own standalone
network, as before. The light attaches to the BR's network (it forms a partition
of its own only if no router answers, as OpenThread does). A partial dataset
(channel, PAN ID, extended PAN ID, network name, network key) is enough: the
rest is learned from the parent.

A network stored in the light's flash wins over the embedded dataset, so a light
that already joined something else keeps that network. Hold **Button 1** while
resetting (or building with `--features test-factory-reset`) to erase the
store (fabrics and Thread network) before it starts. Note that the erase
runs flash operations through the radio's timeslot layer: do not let a debugger
halt the core while it runs (`probe-rs run` is fine, `probe-rs attach` right
after a reset is not).

## 5. chip-tool

Any of:

- Build from the connectedhomeip repository:
  `source scripts/activate.sh && scripts/examples/gn_build_example.sh examples/chip-tool out/chip-tool`
  (Linux and macOS; a few GB and an hour).
- The Snap: `sudo snap install chip-tool` (Linux), and `chip-tool` is on the
  PATH.
- A prebuilt `chip-tool` from a connectedhomeip CI artifact or a Docker image
  (`docker run --rm -it --network host ghcr.io/project-chip/chip-tool`); use
  host networking so that mDNS works.

The machine that runs chip-tool must be on the same LAN as the BR (mDNS and the
OMR route). Run, with the light's test credentials (passcode 20202021,
discriminator 3840):

```sh
chip-tool pairing onnetwork-long 1 20202021 3840
chip-tool onoff toggle 1 1
chip-tool onoff read on-off 1 1
```

`onnetwork-long` looks the device up by its long discriminator
(`_L3840._sub._matterc._udp`) and passcode, runs PASE, adds the fabric
(AddNOC) and finishes with CASE and CommissioningComplete. The test device
attestation of rs-matter is not in the production PAA store, so chip-tool needs
`--paa-trust-store-path <connectedhomeip>/credentials/development/paa-root-certs`
or `--bypass-attestation-verifier true`.

Expected light log (RTT, `probe-rs attach`):

```
network: build-time dataset 100 bytes, stored dataset false
manual pairing code 3497-011-2332
SetupQRCode: [MT:-24J0AFN00KA064IJ3P0WISA0DK5N1K8SQ1RYCU1O0]
role: "Detached"
Netif up: NetifState { ipv6: [fe80::..., fd..., <prefix>::...], ... }
role: "Child"          (Router after about a minute)
```

then rs-matter lines for PASE, "Commissioning complete", CASE and the On/Off
command; LED1 follows the attribute.

### Verified setup

Run on a Mac with ot-br-posix (`otbr-agent`, OpenThread thread-reference-20230710,
RCP = nRF52840 Dongle, mDNSResponder advertising proxy), channel 24, on-mesh
prefix `fd11:69::/64`, the light (this repository, `OPENTRUST_DATASET` = the
BR's dataset): the light attached (Child after about 3 to 12 s, Router after
about a minute), got `fd11:69::<iid>` by SLAAC, registered `_matterc._udp` with
subtypes `_L3840`, `_S15`, `_V65521`, `_CM` and TXT `D=3840 CM=1 VP=65521+32769
DN=MyTest PH=0`; `dns-sd -B _matterc._udp`, `dns-sd -L` and `dns-sd -G v6` showed
it, `ping6` worked, and `chip-tool pairing already-discovered 1 20202021
<light address> 5540 --bypass-attestation-verifier true` finished with
"Device commissioning completed with success" (PASE, attestation, CSR, AddNOC,
CASE, CommissioningComplete); `chip-tool onoff toggle 1 1` and `onoff read on-off 1 1`
then worked over the mesh with the `_matter._tcp` instance resolved from the
light's SRP registration.

Caveat when you reflash or factory reset the light repeatedly: the BR's SRP server
keeps the old host and `_matterc._udp` instance until their lease ends (2 hours),
so `dns-sd` and chip-tool `onnetwork-long` can still list the old instance and
try its dead address first. The light registers its host under another name
(`<EUI-64>-1`) when the server refuses the name because its key changed. Remedy:
`sudo ot-ctl srp server disable; sudo ot-ctl srp server enable` on the BR (this
drops all registrations), or pair by address with
`chip-tool pairing already-discovered 1 20202021 <address from the light log> 5540`.

## 5a. BLE commissioning

The default build of the light (feature `ble`, no `OPENTRUST_DATASET`) is
unprovisioned: it keeps Thread off, advertises the Matter service over BLE
(UUID 0xFFF6, discriminator 3840, name `BT`) and waits for a commissioner. The
Nordic SoftDevice Controller and the 802.15.4 driver share MPSL, so BLE runs
next to Thread; the controller exists only while rs-matter has a commissioning
window open on BLE and is dropped, with the advertising, when commissioning
completes (and the window closes). A light that is already commissioned, or has
a stored or build-time dataset, does not advertise.

```sh
cd examples/nrf52840-light
CARGO_INCREMENTAL=0 cargo build --release        # BLE, unprovisioned
# --no-default-features: Thread only, as before (OPENTRUST_DATASET still works)
# Button 1 held at boot: factory reset, back to BLE commissioning
chip-tool pairing ble-thread 2 hex:<active dataset TLVs> 20202021 3840 \
    --storage-directory <dir>
chip-tool onoff toggle 2 1 --storage-directory <dir>
```

Over BLE chip-tool runs PASE (BTP), reads the attestation, sends the operational
credentials, then `AddOrUpdateThreadNetwork` and `ConnectNetwork`; the light
attaches to the BR's network, BLE stops, and chip-tool finishes with CASE over
Thread through the BR and `CommissioningComplete`.

**macOS.** Apple blocks the Matter BLE characteristic UUIDs for third-party
apps: a scan sees the light's service data, but connecting and using C1 / C2
fails with `CBErrorDomain Code=8 "The specified UUID is not allowed for this
operation."` (chip-tool: `Failed to write characteristic`, then a PASE timeout).
Install Apple's developer profile first (it needs an Apple developer login):
`EnableBluetoothCentralMatterClientDeveloperMode.mobileconfig` from
<https://developer.apple.com/services-account/download?path=/iOS/iOS_Logs/EnableBluetoothCentralMatterClientDeveloperMode.mobileconfig>,
see the chip-tool Darwin guide (`docs/guides/darwin.md`, "Using chip-tool on macOS").
The terminal also needs Bluetooth permission (System Settings, Privacy and
Security, Bluetooth). Linux chip-tool (BlueZ) needs neither.

## 6. Troubleshooting

- **Verified on the DK (BLE build, 2026-11-14)**: `test-factory-reset` erased
  the store and the light advertised the Matter BLE service unprovisioned
  (discriminator 3840), then `chip-tool pairing ble-thread` commissioned it again
  in 23 s (Button 1 itself was not pressed; it runs the same erase). Ten resets at
  random moments while toggles were in flight (1 to 8 s after the command): every
  boot restored its fabric and Router role (0.4 to 1.3 s) and `onoff read` worked
  (`p5a-summary.txt`). A 62 minute run with one toggle every 30 s: 123 of 123
  toggles succeeded (3 to 4 s each), one role change (Child, then Router at
  55 s), no flash write failure, stack high-water 39328 bytes, heap used 0 of
  4096 bytes, radio tx 2608 / rx 5280 with 73 no-ack and 13 busy-channel
  (`soak-dev.log`, `soak-summary.txt`).
- **After a reset the light needs about 13 s before it is a Child again**:
  a restored router asks its former neighbours with Link Requests (three
  attempts, the last one waits 2 s) and attaches normally when nobody answers,
  as OpenThread does. The border router answers only while it still holds the
  light's router entry; it drops the entry about 100 s after the last
  Advertisement, so an outage that long (or a flash download of the light,
  which takes 97 s) ends in a fresh attach: `Detached` at 0.5 s, `Child` at
  12.9 to 13.7 s (hardware logs `t2a-dev.log`, `t2b-dev.log`, `t1-f2r1.log`).
  A reset within the window restores the Router role in 0.7 to 1.3 s and a
  stored Child role in 0.4 s; a Child whose parent has forgotten it re-attaches
  in 1.7 s (the parent answers the Child Update Request with an error status).
- **The first commands after a reset fail**: wait for `role: Child` or `Router`
  and for the SRP registration. The light registers its host under `<EUI-64>`
  and, when the server answers with a name conflict (the key lease of an older
  key, e.g. from before a factory reset, is 14 days), under `<EUI-64>-1`, `-2`,
  ... in turn; the variant is not stored, so every start walks the conflicting
  names again (one SRP round trip each, polled every 500 ms). While that
  happens chip-tool resolves the stale entry of the border router, which
  usually still works; a toggle sent during the 13 s re-attach fails with
  `CHIP Error 0x32` (CASE timeout). Clearing the BR's SRP server
  (`ot-ctl srp server disable; ot-ctl srp server enable`) removes the stale
  names.
- **BLE commissioning right after wiping flash with a debugger fails**: a
  running light writes its key-value store a moment after a change, so a wipe
  by `probe-rs download` of 0xFA000.. while it runs can be followed by a write
  of old state. Use the `test-factory-reset` feature or hold Button 1 at boot,
  or reset the light before and after the wipe.
- **BLE commissioning: ConnectNetwork times out (networkingStatus 9)**: the
  light's `radio:` log line (frames received / sent, send failures by cause)
  shows whether the 802.15.4 driver is alive while the BLE connection is up. On
  the nRF52840 DK the light attached as a Child within about 1.3 s of
  `AddOrUpdateThreadNetwork` with an open BLE connection (both a held bleak
  connection and a full `chip-tool pairing ble-thread`), with no timeslot
  ended / denied or busy-channel failures, so BLE and 802.15.4 do coexist. If
  the light sends Parent Requests (tx rises) but receives nothing and ends up
  Leader of its own partition, first check that the BR is running and
  reachable (`otbr-agent` process, RCP dongle on USB, REST API on port 8081)
  and that its active dataset matches the one handed over. An aborted attempt leaves the fail-safe armed
  until it expires (133 s): the next PASE session then gets
  `InvalidAuthentication` on `ArmFailSafe`; this is rs-matter's handling of a
  closed commissioning session, not this layer's.
- **The border router start script runs `dataset init new` on every start**:
  the network key, channel, PAN ID, Extended PAN ID and name stay, but the
  mesh-local prefix and the PSKc are new, and the Active Timestamp is 1 again.
  A device holding the earlier dataset cannot tell the datasets apart (equal
  timestamps count as equal), so it keeps its old mesh-local prefix; the border
  router does not push the new one. What the light (and an OpenThread device,
  tested with `ot-cli-ftd` on a second DK) does then:
  - it attaches to the border router with its stored dataset, as a Child, and
    receives the new Network Data (OMR prefix, SRP server, default route);
  - its ML-EID and RLOC live under the old prefix and are not reachable from
    the border router's side; the OMR address and the SRP registration work;
  - Address Queries and Notifications between it and the border router are
    dropped (their source is not mesh-local for the other side), so a Child
    sends datagrams for on-mesh addresses (for example the border router host's
    OMR address, where chip-tool lives) through its parent after the first query
    failed: the first reply after a long pause takes a few seconds (a toggle
    took about 7 s on the DK), later ones are quicker;
  - Thread diagnostics, `ping` of the ML-EID and anything else that needs the
    old prefix keep failing until the light is given the current dataset: re-run
    `AddOrUpdateThreadNetwork` with the new dataset (the PSKc and prefix change),
    or keep the BR dataset stable (`dataset init new` only on the first start; see
    the otbr `dataset` persistence under `/var/lib/thread`).
  A light that restored the Router role has to give up its Link Requests first
  (see the 13 s above; with the Leader role or many children OpenThread makes up
  to six attempts), so the first attach can take 20 to 30 s. Earlier builds
  stopped Thread when the network manager's 20 s connect attempt ended and
  restarted the whole restore on the next attempt, so such a light stayed
  `Detached` for ever (`Connecting to network ...` every few seconds, followed by
  `role: "Disabled"`, `Detached`); the stop only happens now for a network the node
  was not holding.
- **The light does not attach**: dataset wrong or a different channel (check
  `ot-ctl dataset active`), or the stored network wins (factory reset).
  `role: "Detached"` forever means no parent answered; a leader of its own network
  appears after the attach attempts (`role: "Leader"` with a different partition).
- **No prefix address on the light**: `ot-ctl netdata show` must list a prefix
  with `a` (SLAAC) and `o`. Without an infrastructure link with IPv6 router
  advertisements the BR publishes none. On the Pi: `ip -6 addr show eth0`, and
  `ot-ctl br omrprefix`, `ot-ctl br onlinkprefix`.
- **SRP registration fails / service not listed**: `ot-ctl srp server host` and
  `ot-ctl srp server service` must show the light's host (16 hex digits, its
  EUI-64) and the `_matterc._udp` instance with subtypes `_L3840`, `_S15`, `_V65521`,
  `_CM` while the commissioning window is open (it is open from boot until a
  fabric exists). After commissioning the service is `_matter._tcp`. An SRP server
  that is not enabled (`srp server state` disabled) or no `5d/5c` service in the
  Network Data leaves the light unregistered.
- **mDNS does not show the service on the LAN**: the advertising proxy
  publishes through the BR's mDNS daemon (avahi on Linux, mDNSResponder on
  macOS). On the commissioner: `avahi-browse -rt _matterc._udp` or
  `dns-sd -B _matterc._udp`. If `ot-ctl srp server service` lists the service but
  the LAN does not, check `ot-ctl srp server` output for the proxy and
  `systemctl status avahi-daemon otbr-agent`.
- **PASE times out although the service is found**: the commissioner has no route
  to the OMR prefix. The BR sends a Router Advertisement with a Route Information
  Option for it on the LAN; the host needs `net.ipv6.conf.<if>.accept_ra=2` (when
  it forwards) and `accept_ra_rt_info_max_plen>=64`; on macOS the route appears
  through the BR's `utun` interface only with RA route info. Fallback:
  `sudo ip -6 route add <omr-prefix>::/64 via <BR link-local> dev eth0`. Test with
  `ping6 <light prefix address>`.
- **Router Advertisements are blocked** by a switch or access point (multicast
  filtering on Wi-Fi) breaks both RA and mDNS; use Ethernet for the BR and the
  commissioner machine for the first try.
- **Power cycle after reflashing the BR RCP**: `otbr-agent` needs the RCP
  to be reset after changing the image.

## 7. Commercial border routers (Apple, Google, Amazon)

Apple TV / HomePod, Google Nest Hub / Wifi and Amazon Echo are Thread border
routers, but they do not hand out their Thread dataset and offer no commissioner
interface to other tools: a light that is not commissioned through their own
Matter controller app (which needs BLE for the first step, or a QR code the
ecosystem app drives itself) cannot join them. The Apple and Google credentials
are shared with Matter devices only during their own commissioning, over BLE.
OpenTrust's light can be commissioned over BLE (section 5a), but only by a
commissioner that has the dataset to give it: use your own BR (this document)
with `chip-tool pairing ble-thread`, or the standalone network of the
Thread-only build. Commissioning it through an ecosystem app needs that app's
own BLE commissioning, which the light offers (it is a Matter BLE peripheral),
but the ecosystem then hands over its own network.

## 8. macOS host

ot-br-posix builds and runs on macOS (the `otbr-agent` links `mDNSResponder`
through `OTBR_MDNS=mDNSResponder` and creates a `utun` interface for the Thread
network). The RCP is the USB CDC device `/dev/tty.usbmodem*`. `ot-ctl` talks to
the agent over its control socket and needs `sudo`. The LAN interface is `en0`
for Wi-Fi/Ethernet. The host routes the Thread OMR prefix through the `utun`
interface; chip-tool and `dns-sd` run on the same Mac and need no extra route
when the BR runs on the machine itself.
