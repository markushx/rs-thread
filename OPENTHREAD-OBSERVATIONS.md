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

## DHCPv6 server lists the prefixes in reverse Network Data order

- **OpenThread:** `Dhcp6::Server::AddPrefixAgent` walks the agent slots without
  stopping at the first free one, so a new prefix agent lands in the last free
  slot. `AppendIaAddressOptions` then walks the slots in ascending order. For
  prefixes 2001::/64, 2002::/64, 2003::/64 (added in this order) the Reply carries
  the addresses 2003, 2002, 2001, and the client's `ipaddr` lists them as
  2001, 2002, 2003 (newest first).
- **Assessment:** harmless but accidental; the order is not specified. The
  certification case Cert_5_3_08 verifies its pings in the order of the `ipaddr`
  listing, so the order is observable.
- **OpenTrust:** copies the order (`crates/opentrust-instance/src/dhcp6.rs`,
  Reply): the prefixes this node serves in reverse Network Data order. A server
  that removed and re-added prefixes may order differently from OpenThread (the
  slot positions are not modelled).

## SRP server: a duplicate "delete all RRsets" record ends the service description pass silently

- **OpenThread:** in `Server::ProcessServiceDescriptionInstructions` a second
  "Delete All RRsets from a name" record for the same service instance executes
  `VerifyOrExit(!service->mParsedDeleteAllRrset)` without assigning an error, so
  the function returns success without the final checks and without advancing
  `aMetadata.mOffset`. `ProcessAdditionalSection` then reads the OPT and SIG
  records from the start of the update section.
- **Assessment:** accidental; the result is a parse failure further on. It
  cannot make a signature verify that does not.
- **OpenTrust:** rejects the message with FORMERR
  (`crates/opentrust-dns/src/srp/server.rs`, `service_description`).

## SRP server: the signer name of the SIG(0) record is not checked

- **OpenThread:** `VerifySignature` hashes the signer name of the SIG record but
  never compares it with the host name; only the key of the host description
  matters (the key binds the names).
- **Assessment:** consistent with RFC 9665 (the signature proves possession of
  the key registered for the names).
- **OpenTrust:** copies it (`additional_section`).

## SRP server: a KEY record of any name sets the host key

- **OpenThread:** the host description pass takes the first KEY record of the
  update section for the host regardless of its owner name.
- **OpenTrust:** copies it (`host_description`).
