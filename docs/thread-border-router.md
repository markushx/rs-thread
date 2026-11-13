# Thread Border Router for the OpenTrust Matter light

The nRF52840 light (`examples/nrf52840-light`) has no BLE, so it is commissioned
on-network: chip-tool reaches it over IP. That needs a Thread Border Router (BR)
that

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

## 6. Troubleshooting

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
OpenTrust's light has no BLE yet, so it can only join with a dataset you know:
use your own BR (this document), or the standalone network of the light.

## 8. macOS host

ot-br-posix builds and runs on macOS (the `otbr-agent` links `mDNSResponder`
through `OTBR_MDNS=mDNSResponder` and creates a `utun` interface for the Thread
network). The RCP is the USB CDC device `/dev/tty.usbmodem*`. `ot-ctl` talks to
the agent over its control socket and needs `sudo`. The LAN interface is `en0`
for Wi-Fi/Ethernet. The host routes the Thread OMR prefix through the `utun`
interface; chip-tool and `dns-sd` run on the same Mac and need no extra route
when the BR runs on the machine itself.
