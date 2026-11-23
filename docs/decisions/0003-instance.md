# ADR 0003: the `Instance` integration layer

Status: accepted

## Context

The protocol crates are sans-IO building blocks. Each has its own test
simulator that feeds the hooks of that layer by hand (`rs-thread-mle::sim`,
`rs-thread-mesh::sim`, `rs-thread-meshcop::net_sim`). A device needs one
object that owns every layer, connects the hooks and exposes a public API
(OpenThread: `otInstance` plus `otThread*`, `otDataset*`, `otIp6*`, `otUdp*`,
`otSrpClient*`).

## Decision

### Where it lives

A new crate `rs-thread-instance`. It depends on `-core`, `-platform`, `-mac`,
`-lowpan`, `-net`, `-coap`, `-mle`, `-mesh`, `-meshcop`, `-dns`. Nothing below
depends on it; `rs-thread-embassy` (async facade), `rs-thread-sim` (test radio
medium) and the future `-matter` / `-cli` / `-ncp` depend on it. Features
mirror the lower crates and are forwarded: `ftd` (default), `commissioner`,
`border-agent`, `tcat`, `trel`, `defmt`, `log`. An MTD-only build
(`default-features = false`) has no router, leader or commissioner code.

### Sans-IO with the radio at the edge

`Instance<C, const ..>` does not own a `Radio`. It owns the MAC state machine
and exposes the same pull model as the MAC:

```text
instance.handle_radio_rx(psdu, &PsduRxInfo, now)   // frame in
instance.handle_radio_tx_done(TxOutcome, now)      // result of a RadioAction::Transmit
instance.poll_radio_action(now) -> Option<RadioAction>   // what the radio does next
instance.poll(now)                                  // run everything that is due
instance.next_deadline() -> Option<Instant>
instance.poll_event() -> Option<Event>
```

The async facade (`rs-thread-embassy`) runs the `Radio` trait against these
calls (as `MacDriver` does for the bare MAC); the simulator calls them
directly with virtual time. Time, entropy and settings are arguments or
generic parameters: `C: CryptoBackend`, `R: rand_core::Rng`
(the `Entropy` trait), `S: SettingsStore`. Capacities are const generics
with defaults; the public struct has a small number of them (children,
UDP sockets, ...); everything else uses the layer defaults.

### Ownership and split borrows

One struct owns all layers as plain fields (MAC with the `KeyManager` as its
`FrameSecurity`, `Mle`, `Ip6` with `Netif`, `UdpSockets`, TMF `Agent`,
forwarder, address cache, Network Data, dataset managers, ...). Layer methods
take `&mut self` plus an environment trait object (`MleEnv`, `DatasetEnv`,
`Ip6Env`, `Routing`, ...). The Instance builds a short-lived *view* struct that
borrows every field except the one being called (`Mle` is driven with an
`MleView { mac, ip6, netdata, datasets, settings, outbox, events, .. }`)
and implements the env traits on it. No `RefCell`, no `unsafe`.

Layers never call each other re-entrantly. Hooks that would need another
layer push into bounded queues on the Instance:

- an *outbox* of UDP datagrams (TMF, MLE, user sockets): `(SendInfo, ports,
  payload)`; drained after every entry point through `Ip6::send` -> forwarder
  -> 6LoWPAN -> MAC;
- an *MLE event queue* (`MleEvent`), an *address event* queue (netif),
  dataset events and the Network Data notifier input.

`step()` loops (bounded) until all queues are empty and then recomputes
`next_deadline` as the minimum over MAC, MLE, forwarder, resolver, TMF agent,
Ip6/MPL, key manager, datasets, notifier, publisher, ... .

### Events and the Notifier

OpenThread's `Notifier` is a flag set (`OT_CHANGED_*`) plus callbacks. The
internal consumers (SLAAC, ALOCs, the Network Data notifier, DUA / MLR,
persistence) are not callbacks here: the Instance's `dispatch_events` is the
single place that maps an `MleEvent` / dataset event / netif change onto the
consumers, in a fixed order, so the order is testable. For the application
there is an `Event` queue (`poll_event`) with typed variants (`RoleChanged`,
`Rloc16Changed`, `PartitionChanged`, `AddressesChanged`,
`NetworkDataChanged`, `ActiveDatasetChanged`, `PendingDatasetChanged`,
`JoinerResult`, `SrpClient`, `UdpReceived` readiness, ...). A bounded queue
with "latest wins" coalescing for flag-like events: no allocation, no
callback lifetimes, usable from an async facade (one `Signal`/`Channel` per
Instance). Documented deviation: no flag bitmask API.

### Persistence

Everything persistent goes through `SettingsStore` with the OpenThread keys
(`SettingsKey`): Active/Pending Dataset, NetworkInfo (role, RLOC16, key
sequence, MLE and MAC frame counters, partition ID, ML-EID IID), ParentInfo,
ChildInfo, DAD counter, SLAAC IID secret key, SRP client key (a Rust-only
key in the vendor range), BR / Network Data publisher state where OT has it.
Frame counters are stored `frame_counter_ahead` and restored plus the
margin. The Instance restores on `thread_start` and writes through the
existing hooks (`store_network_info`, `DatasetEnv::store`, ...).

### Public API

Loose mirror of OT naming, idiomatic Rust (methods on `Instance`, `Result`,
no globals):

- link: `ip6_set_enabled` (`up`/`down`), `thread_start`/`thread_stop`,
  `role`, `rloc16`, `partition_id`, `leader_data`, `extended_address`,
  `factory_reset`;
- datasets: `set_active_dataset(&Dataset)`, `active_dataset()`,
  `set_pending_dataset`, raw TLV variants, `become_leader` helper through
  `create_new_dataset`;
- addresses: `unicast_addresses()`, `ml_eid()`, `rloc()`, `subscribe_multicast`;
- UDP: `udp_open`, `udp_bind`, `udp_send_to`, `udp_recv`, `udp_close`;
- ICMP: `ping(dst, payload)` and `Event::PingReply`;
- SRP client / DNS client: `srp_set_host`, `srp_add_service`, `srp_start`;
- joiner (`commissioner`-independent, always present): `joiner_start`;
  commissioner (feature): `commissioner_start`, `commissioner_add_joiner`.

Types: `Role` (from `rs-thread-mle`), `Dataset` (from `rs-thread-meshcop`),
`Event`, `Config`.

## Consequences

- One place implements all env traits; the per-layer simulators remain as
  unit-test fixtures of their crates.
- The sim crate drives full stacks over a simulated radio without async.
- A sans-IO radio edge means the same code runs on embassy, in tests and in
  a future NCP, at the price of one extra copy of each PSDU at the edge.
