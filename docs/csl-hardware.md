# CSL on the nRF52840 (SSED under an OpenThread parent)

OpenTrust as a Thread 1.2 synchronized sleepy end device on the nRF52840 DK
(`examples/nrf52840-leader`, `--bin cli --features cli-all`, backend
`radio-nrf802154`) under an OpenThread parent (`ot-cli-ftd`, ot-nrf528xx,
OpenThread `e5629fa`, second DK; channel 25, PAN 0x1234, no other nodes).

## Set-up

Peer: `dataset set active <hex>`, `ifconfig up`, `thread start` (it becomes Leader).
OpenTrust: `dataset set active <hex>`, `mode -`, `pollperiod 240000`, `ifconfig up`,
`thread start`, wait for `child`, then `csl period <us>` and `csl channel 25`.
The CSL period is given in microseconds (a multiple of 160). Setting CSL before
the device has attached is accepted but the sleepy attach is slow, so set it afterwards.
`csl period` set once after the attach works at 100, 200 and 500 ms; changing the
period of a running CSL link does not (see "Open").

The peer's CSL support: `csl accuracy` / `csl uncertainty` only (20 and 20), no `csl
period|channel|timeout`: that `ot-cli-ftd` is CSL transmitter only, so the reverse
direction (OpenTrust parent, OpenThread SSED) cannot be run on this hardware.

## What the hardware path does

- **Timed receive**: one `RadioAction::ReceiveAt` per period to the driver's
  `nrf_802154_receive_at`. The driver refuses a window that starts within about a
  millisecond (it reserves an MPSL timeslot) and accepts one at 4 ms; the MAC therefore
  arms its window timer `RadioCaps::receive_at_lead_us` (3000 us on the Nordic backend)
  before the window. Before that fix every window was refused and no parent frame was
  ever received.
- **Enhanced ACKs**: the Nordic driver writes the CSL IE (phase, period) itself into the
  secured enhanced ACKs from its CSL anchor time (`set_csl_anchor_time`,
  `set_csl_period`, `set_csl_ie_peer`); `PsduRxInfo::ack_security` marks the frames the
  radio acknowledged that way, and the MAC resynchronizes (`last_sync`) on them. The
  parent's `child table` shows CSL = 1 right after the first Child Update Request.
- **Replies and data polls** carry the CSL IE filled by the driver at transmit time
  (`TRANSMIT_SEC`); data polls only happen when the parent sets Frame Pending (pings
  faster than the period queue up at the parent), never otherwise.

## Measurements

OpenThread `ping <addr> 32 <count> <interval>` from the parent, interval chosen as no
multiple of the period (phases spread uniformly) and longer than the period (no queueing
at the parent). Parent `counters mac` `RxDataPoll` is unchanged over every run
(no data polls).

| CSL period | pings | lost | RTT min / median / mean / p95 / max (ms) |
|---|---|---|---|
| 500 ms | 60 | 0 | 16 / 257.5 / 260.6 / 478 / 508 |
| 200 ms | 30 | 0 | 20 / 105 / 111.2 / 197 / 214 |
| 100 ms | 60 | 0 | 16 / 63 / 63.8 / 109 / 115 |

The RTT is the wait for the child's next window plus about 15 ms (frame, ACK, echo
reply, ACK): uniform between about 15 ms and the period plus 15 ms.

Receiver duty cycle (no power meter; radio-on time estimated from the `receive_at`
windows the driver was given, logged with the driver's trace output): the window is
`ahead + after` of `window_edges` (OpenThread's `GetCslWindowEdges`): with the parent
reporting 20 ppm / 200 us, the radio's 20 ppm / 120 us and OpenThread's
`MIN_RECEIVE_ON_AFTER` (a maximum-length frame plus ACK, 5.5 ms) it is about 6.4 ms
right after a synchronization and grows by 40 us per 500 ms until the next frame from
the parent (measured: 6374 us rising to 7.4 ms). Over 40 s at 500 ms (80 windows) the mean
was 6.5 ms, 1.30 % radio-on in the windows; the same window at 200 ms and 100 ms is
about 3.2 % and 6.4 %, plus the time of frames received and sent. Windows are not
shortened when nothing arrives (the driver ends them at the programmed time), as in
OpenThread. At 100 ms the RTT logging dropped messages, so only the 500 ms figure is
a count.

## Open

- Changing the CSL period of a running link (500 -> 100 ms, 100 -> 200 ms) leaves the
  parent unable to hit the windows (about half of its CSL frames get no ACK, then it
  falls back to waiting for polls); a fresh `csl period` after the attach works. Not
  diagnosed (the parent's own log is compiled out).
- A sleepy attach (`mode -` set before `thread start`) takes 15 to 45 s (Parent
  Requests, the radio sends bursts of 16 identical 74-byte broadcasts 82 ms apart between
  rounds); the non-sleepy attach takes a few seconds.
  In the simulation (`opentrust-sim/tests/sleepy_attach.rs`) an OpenTrust SED attaches as
  fast as an OpenThread one (1.2 s), also with the CSL period set first, and its Parent
  Request rounds have OpenThread's timing. The bursts are not retransmissions: after the
  Parent Request rounds OpenThread and OpenTrust both send an MLE Announce per channel
  (16 frames, 82 ms apart, a new sequence number each). A radio that transmits from sleep
  has to listen on the transmit channel afterwards (contract C4); the embassy backend
  of `opentrust-nrf` did not (fixed, and the simulated radio now transmits from sleep
  and does the same). The `radio-nrf802154` backend does not transmit from sleep, so this
  does not explain the measurement: needs hardware (log the radio actions and the rx
  state of the first Parent Request round).
- The window could be shortened (the 5.5 ms after-time is OpenThread's conservative
  choice) to lower the duty cycle.
