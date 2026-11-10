# Memory budget

RAM used by `opentrust_instance::Instance` (x86_64 `size_of_val`, includes a
caller-provided `RamSettings<4096>`; 32-bit targets are somewhat smaller).
Regenerate with
`cargo test -p opentrust-instance instance_size_breakdown -- --nocapture`;
the test asserts an upper bound per feature set (`src/size_test.rs`).

## Total per feature set

| Feature set | Bytes |
|---|---|
| default (ftd + commissioner + border-agent) | 150000 |
| `ftd` only | 116240 |
| MTD (`--no-default-features`) | 102800 |

## Per component (default / MTD)

| Component | default | MTD |
|---|---|---|
| commissioning (`cm`) | 43664 | 8928 |
| core (MAC 5848, IPv6 5768, MLE outbox 7800, MAC tx 4640, settings 4104, events 1840) | 33464 | 33464 |
| DNS/SRP clients | 14792 | 14792 |
| UDP sockets | 14040 | 14040 |
| mesh forwarder | 11784 | 11784 |
| TMF agent | 10584 | 4248 |
| MLE | 8328 | 3424 |
| TMF/app outbox (`sink`) | 7800 | 7800 |
| backbone router glue | 2072 | 1672 |
| other (resolver, leader, netdata, ...) | ~3500 | ~2300 |

Inside `cm` (default): joiner 7856, commissioner 9040, border agent 19440,
border-agent outbox 5272.

## Target devices

| Device | RAM | Instance (default) | Instance (MTD) |
|---|---|---|---|
| nRF52840 | 256 kB | does not leave room for the application | fits |
| nRF54L15 | 256 kB | as above | fits |
| ESP32-C6 | 512 kB | fits | fits |
| ESP32-H2 | 320 kB | tight | fits |

## Cause and direction

Almost every queue reserves worst-case 1280-byte buffers per slot. OpenThread
instead uses one shared pool of 128-byte buffers
(`OPENTHREAD_CONFIG_NUM_MESSAGE_BUFFERS`, default 44, about 5.6 kB).
