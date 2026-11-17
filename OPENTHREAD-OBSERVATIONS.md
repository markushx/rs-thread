# OpenThread observations

Behaviour of OpenThread that OpenTrust follows for interoperability or
certification, but that is questionable against the Thread specification or
from a security point of view. Each entry is a candidate for a later review
(and possibly a report upstream). Differences in OpenTrust itself are listed in
`OPENTRUST-OPENTHREAD-DIFFERENCES.md`.

## Joiner receives the Network Key after a rejected JOIN_FIN

- **Status:** OpenTrust follows OpenThread (decision 2026-11-16: keep for now).
- **Spec (Thread 1.4.1, 8.9.2.2 JOIN_FIN.rsp):** "When JOIN_FIN.rsp is
  encapsulated as DTLS Application Data in a RLY_TX.ntf message, the
  Commissioner MUST include the KEK TLV in this RLY_TX.ntf message." There is no
  exception for a `Reject`. For the Joiner the same section says: "Wrong
  Commissioner ('Reject' received in State field): Joiner Session closes." The
  State TLV is `Reject` when the Provisioning URL of the JOIN_FIN.req does not
  match a URL the Commissioner application can handle.
- **OpenThread:** the Commissioner always relays the KEK with JOIN_FIN.rsp, so
  the Joiner Router sends the Joiner Entrust (JOIN_ENT.ntf, with the Network
  Key) after `DELAY_JOIN_ENT`. The Joiner (`Joiner::HandleJoinerFinalizeResponse`,
  `src/core/meshcop/joiner.cpp`) moves to `kStateEntrust` for any State value
  and accepts the Joiner Entrust, so a rejected Joiner still gets the Network
  Key and attaches.
- **Assessment:** the Commissioner side matches the spec text. The Joiner side
  is not required by the spec: after a `Reject` the spec says the Joiner Session
  closes; it does not say the Joiner should accept the credentials. The Joiner
  has proven the PSKd, so the Commissioner admitted it cryptographically; the
  `Reject` only concerns the vendor provisioning application. Still, a device
  told "wrong Commissioner" ends up with the Network Key.
- **OpenTrust before the change:** relayed the KEK only for `Accept`, and the
  Joiner failed with a security error on `Reject`. OpenThread certification
  cases Cert_8_1_06 and Cert_8_2_05 fail with that behaviour.
- **Code:** `crates/opentrust-meshcop/src/commissioner.rs` (KEK with every
  JOIN_FIN.rsp), `crates/opentrust-meshcop/src/joiner.rs` (Entrust state after
  any State value).
- **Options for later:** a build/runtime option for the strict behaviour (no KEK
  on `Reject`, Joiner stops on `Reject`); ask the Thread Group whether the
  Joiner should discard JOIN_ENT after `Reject`.

## Energy Scan and PAN ID Query servers stall when the MAC is busy

- **OpenThread:** `EnergyScanServer::HandleTimer` and `PanIdQueryServer::HandleTimer`
  call `Mac::EnergyScan` / `Mac::ActiveScan` and ignore the error. If another
  scan runs (for example `scan` on the CLI), no result callback ever arrives, the
  timer is not restarted and the request is never answered; the Commissioner
  waits for a report that does not come.
- **OpenTrust:** the server tries again after 500 ms
  (`EnergyScanServer::scan_failed`, `PanIdQueryServer::scan_failed`).
- **Options for later:** answer the request with an empty list after a number of
  retries.

## Enhanced keep-alive and an application poll period

- **OpenThread:** `DataPollSender::ResetKeepAliveTimer` (called after an acknowledged secured data frame to a Thread 1.2 parent) only restarts the poll timer when `mPollPeriod == GetDefaultPollPeriod()`, the period derived from the child timeout. A device with `pollperiod 2000` therefore keeps polling on its own schedule, but a device whose application period is longer than the default (the default wins as the minimum) has its poll postponed by every data frame.
- **Why it matters:** LowPower 7.1.2 pings with a timeout equal to the poll period; a postponing implementation misses it.
- **OpenTrust:** copies the condition (`PollSender::mle_period`).

## Link metrics of a radio without LQI

- **OpenThread:** the simulation radio reports `OT_RADIO_LQI_NONE` (0) for every received frame; `Neighbor::AggregateLinkMetrics` still counts the frame, with LQI 0.
- **OpenTrust:** counts such frames with LQI 0 as well.

## Simulated radio acknowledges frames for short address 0x0000 on every node

In the OpenThread simulation platform (examples/platforms/simulation/radio.c) a
node whose RLOC16 is not 0x0000 still sends an enhanced ACK for a frame
addressed to the short address 0x0000 (observed: the leader acks the frames a
child sends to its router with Router ID 0). The sender gets two ACKs for one
frame; the first one comes from a node that cannot have the right key and
the radio reports it as the ACK of the transmission, so every transmission to
the router fails its 15 retries. The alternate short address of the simulated
radio is probably never initialised to invalid. About 1 run in 62 gives the
router Router ID 0; the thread-cert and mtd tests flaked at that rate.
The OpenTrust virtual-time simulator drops an ACK from a node whose
known short address differs from a 0x0000 destination.
