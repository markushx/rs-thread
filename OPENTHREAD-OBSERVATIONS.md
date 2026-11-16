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
