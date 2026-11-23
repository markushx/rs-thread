# CSL on the nRF52840 (SSED under an OpenThread parent)

rs-thread as a Thread 1.2 synchronized sleepy end device on the nRF52840 DK
(`examples/nrf52840-leader`, `--bin cli --features cli-all`, backend
`radio-nrf802154`) under an OpenThread parent (`ot-cli-ftd`, ot-nrf528xx,
OpenThread `e5629fa`, second DK; channel 25, PAN 0x1234, no other nodes).

## Set-up

Peer: `dataset set active <hex>`, `ifconfig up`, `thread start` (it becomes Leader).
rs-thread: `dataset set active <hex>`, `mode -`, `pollperiod 240000`, `ifconfig up`,
`thread start`, wait for `child`, then `csl period <us>` and `csl channel 25`.
The CSL period is given in microseconds (a multiple of 160). `csl period` works at
100, 200, 500 and 1000 ms, set after the attach and also changed on a running link.

The peer's CSL support: `csl accuracy` / `csl uncertainty` only (20 and 20), no `csl
period|channel|timeout`: that `ot-cli-ftd` is CSL transmitter only, so the reverse
direction (rs-thread parent, OpenThread SSED) cannot be run on this hardware.

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

## Window start: the cause of the "live period change" failure

Symptom: after `csl period 500000` -> `100000` (and 100 -> 200 ms) about half of the
parent's CSL frames got no ACK, the parent marked the child desynchronized and queued
its messages (73 on one run). It was not specific to a change: with the logging
level of the firmware lowered (no radio traces) even a first `csl period 500000` after
the attach lost 28 of 30 pings, whereas a build with MAC and radio traces (slower)
behaved differently from run to run, which hid the cause in the previous session.

Cause (from `nrf: receive_at` traces: requested and issued window start):

- The MAC arms its window timer `RadioCaps::receive_at_lead_us` (3000 us) plus
  `ahead` before the window; the window starts `ahead - CSL_RECEIVE_TIME_AHEAD` (320 us)
  before the sample time, about 0.5 ms with a synchronized parent at 500 ms
  (`window_edges`: 340 us semi window + 192 us). From the timer to the driver call the
  executor needs time (wake-up, `SetCsl` action first, logging): 0.4 to 0.7 ms
  measured with traces.
- The backend must hand the window to the driver at least 3000 us ahead of its start and
  moved a window that was handed over later forward to `now + 3000 us`. So every
  window started 0.4 to 0.9 ms late, i.e. after the SHR of the parent's frame (the
  MHR is expected at the sample time, the SHR starts 192 us earlier, the receiver
  needs about 130 us to ramp up). The frames of the parent were missed (no ACK),
  except in the wide windows right after CSL is switched on (the unsynchronized
  window is a full period).
- The first Child Update Request with the CSL IE (sent right after `csl period`) is
  acknowledged, but the parent's Child Update Response in the child's windows was not
  received: the child sent the request again every 1.5 s and detached after the
  retries (a re-attach with CSL off and on again), then the same again. A live period
  change is the same state: the first window of the new schedule is wide, the next
  ones narrow.

Fix: `NrfRadio::RECEIVE_AT_LEAD_US` (the lead the MAC arms its timer with) is 5000 us,
the minimum lead the driver needs (`MIN_RECEIVE_AT_LEAD_US`, the trim threshold) stays at
3000 us; the 2 ms margin covers the time from the timer to the driver call, so a
window is issued at its nominal start.

Verification: SSED under the OpenThread parent, live changes 500 -> 100 -> 200 -> 1000 ->
500 ms, 50 pings from the parent at each period (interval 1.21 periods + 30 ms),
firmware without radio traces. Before the fix (same procedure, 30 pings): 3, 1, 0, 9 and 2
received. After:

| CSL period | pings | lost | RTT min / median / max (ms) | parent frames unacked |
|---|---|---|---|---|
| 500 ms | 50 | 0 | 29 / 260 / 498 | 0 |
| 100 ms | 50 | 0 | 24 / 74 / 116 | 0 |
| 200 ms | 50 | 0 | 20 / 140 / 486 | 0 |
| 1000 ms | 50 | 0 | 42 / 575 / 1888 | 0 |
| 500 ms | 50 | 0 | 28 / 315 / 944 | 0 |

(Unacked: parent `counters mac` `TxAckRequested` minus `TxAcked` over the run; the
RTTs above 1 period + 15 ms are pings that waited behind the previous one at the parent.)

## Slow sleepy attach: the cause is the parent's replay check, not the radio

Symptom: a CLI node with `mode -` needed 15 to 45 s to attach to the OpenThread leader
(Parent Requests without Parent Response), non-sleepy attach "a few seconds".

Radio actions, rx state and frames of the first Parent Request rounds were logged
(`act:` traces of every `RadioAction`, `rx:` of every frame handed to the MAC): the
radio is in receive on the PAN channel from the first `Receive` until the Child ID
Request (rx-on-when-idle is true during the attach, the MLE layer sets it), the
transmissions go out, and the node hears the parent (Advertisements arrive). What
does not come is the Parent Response: the parent receives the Parent Requests
(`RxBroadcast` grows) and sends nothing (`TxUnicast` constant).

Cause: Parent Requests are MLE secured. The OpenThread parent keeps the child entry
(Valid, child timeout 240 s) of the previous attach of the same extended address and
drops every secured MLE message whose frame counter is below the one it stored for
that neighbor (`Mle::HandleUdpReceive`: `frameCounter >= neighbor->GetMleFrameCounter()`
else `kErrorDuplicated`). The CLI firmware kept its settings in RAM only at the time (it persists them in flash now, see below), so the MLE
frame counter restarts at 0 after every reset, and each Parent Request counts one up
until the counter has caught up with the parent's: the attach time grows with the
number of earlier attaches (4.9, 7.7, 12.1, 16.3, 21.7 s over five resets; 6.8, 11, 14,
19, 25, 32, 43, 63 s and two 90 s failures with a graceful `thread stop` between).
It happens to the non-sleepy attach the same way (it was not compared with the same
history). A fresh parent entry removes it: with a new extended address (`extaddr`) and
`childtimeout 10` per attach the attach takes 1.0 to 1.8 s:

| mode | attaches | time `thread start` -> `child` (s) |
|---|---|---|
| SED (`mode -`) | 10 | 1.0 to 1.6, median 1.56 |
| SSED (`mode -`, `csl period 500000` set before the attach) | 10 | 1.3 to 1.8, median 1.56 |
| non-sleepy (`mode rdn`) | 10 | 1.0 to 1.6, median 1.30 |

(polled every 0.25 s over the CLI, so +- 0.3 s) the same as in the simulation (1.2 s).
The attach with CSL set first is no slower. Firmware with settings in flash
(`nrf52840-light`) stores the frame counters ahead and does not have the problem. When
testing with a RAM-settings firmware against an OpenThread parent, give every attach a new
extended address or wait for the child timeout of the old entry.

With the settings in flash (frame counters stored ahead, as OpenThread) the CLI firmware
resets cleanly: ten resets in a row against the OpenThread parent show no growth of the
attach time; `factoryreset` erases the settings and the next boot picks a new random
extended address. Time from `thread start` to `child` over ten hardware resets (the
stored dataset, role and counters restored, `mode` set before the start):

| mode | first start | after each of 9 resets (s) |
|---|---|---|
| SED (`mode -`) | 1.6 s | 6.1 to 6.6, median 6.3, no growth |
| non-sleepy (`mode rdn`) | 1.0 s | 0.1 (restored role, one Child Update exchange) |

The restored SED did not get the answer of its Child Update Request (four attempts
about 5 s, then a normal attach of about 1.3 s); the non-sleepy restore is answered at
once. Cause: the parent holds the Child Update Response of a sleepy child until the child
polls, and the restore request started no poll (the poll target was only set with the child
state; OpenThread polls the restored parent in attach mode). The restoring sleepy child now
polls its restored parent (also a CSL child, since the restoring request carries no CSL
TLVs). Not measured on the board after the fix: the second DK was not reachable (its J-Link
VCOM and debug interface were gone) and no border router was running.

A second restore difference showed in `Cert_6_5_02`: OpenThread restores the extended
address at instance creation, rs-thread only at `thread start`, so a reset device reported a
random address before the start (see RSTHREAD-OPENTHREAD-DIFFERENCES.md).

## Parent loss and re-attach

SED (`mode -`) and SSED (CSL 500 ms) attached, `pollperiod 3000` (3 s), the OpenThread
parent (the only other node, Leader) stopped with `thread stop` and `ifconfig down`
(after `thread stop` alone the radio of the parent still acknowledges data polls in
hardware, so the child neither notices nor leaves: 187 s and 192 s until its child
timeout side ended the link in that case, polls acknowledged until then).

| | parent lost -> child `detached` | parent `ifconfig up` + `thread start` -> child `child` again |
|---|---|---|
| SED | 6.2 s | 15.3 s |
| SSED (CSL 500 ms) | 9.7 s | 17.9 s |

The child leaves after 4 (15 with CSL) data polls without ACK, as OpenThread. The parent
needs about 15 s after `thread start` to become Leader again, the child attaches to
it as soon as the Parent Request round finds it (the parent restart cleared its child
table, so no stale-counter delay).

## Open

- The CLI firmware does not keep the frame counters over a reset (see above); a
  noinit-RAM or flash backed counter store would remove the stale-entry attach delay.
- The window could be shortened (the 5.5 ms after-time is OpenThread's conservative
  choice) to lower the duty cycle.
