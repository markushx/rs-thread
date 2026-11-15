# Test status

## thread-cert (OpenThread `tests/scripts/thread-cert`, Cert_5_1 to 5_3)

Run: `OPENTRUST_CERT=1 cargo test -p opentrust-sim --test thread_cert` (see the header of `crates/opentrust-sim/tests/thread_cert.rs`; needs `ot-cli-ftd` from `cargo build -p openthread-sys`, cmake, ninja, a Python venv with `pexpect pycryptodome pyshark==0.4.6 lxml`). Virtual time, OpenThread `simulator.py`, `THREAD_VERSION=1.4`. Each case runs once with all nodes `ot-cli-ftd` (baseline, validates the setup) and once per node of its topology with only that node replaced by `opentrust-cli-vt`, so a pass means that role works against OpenThread peers. 30 cases, 243 runs: **202 pass, 41 fail** (all 41 failures are the five cases that fail with OpenThread nodes only; before the sleepy-child attach fix: 197 / 46). The whole run takes about 25 minutes.

Packet verification (pktverify, tshark) is not run: `thread_cert.py` refuses it on macOS ("Linux only"), so only the CLI based assertions of the cases are checked (`OPENTRUST_CERT_PKTVERIFY=1` enables it on Linux).

| case | all OT (baseline) | OpenTrust as node n: pass | OpenTrust as node n: fail/timeout |
|---|---|---|---|
| Cert_5_1_01_RouterAttach | pass | 1,2 |  |
| Cert_5_1_02_ChildAddressTimeout | pass | 1,2,3,4 |  |
| Cert_5_1_03_RouterAddressReallocation | pass | 1,2,3 |  |
| Cert_5_1_04_RouterAddressReallocation | pass | 1,2,3 |  |
| Cert_5_1_05_RouterAddressTimeout | pass | 1,2 |  |
| Cert_5_1_06_RemoveRouterId | pass | 1,2 |  |
| Cert_5_1_07_MaxChildCount | pass | 1,2,3,4,5,6,7,8,9,10,11,12 |  |
| Cert_5_1_08_RouterAttachConnectivity | pass | 1,2,3,4,5 |  |
| Cert_5_1_09_REEDAttachConnectivity | pass | 1,2,3,4,5 |  |
| Cert_5_1_10_RouterAttachLinkQuality | pass | 1,2,3,4 |  |
| Cert_5_1_11_REEDAttachLinkQuality | pass | 1,2,3,4 |  |
| Cert_5_1_12_NewRouterNeighborSync | pass | 1,2,3 |  |
| Cert_5_1_13_RouterReset | pass | 1,2 |  |
| Cert_5_2_01_REEDAttach | pass | 1,2,3,4 |  |
| Cert_5_2_03_LeaderReject2Hops | pass | 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33 |  |
| Cert_5_2_04_REEDUpgrade | pass | 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18 |  |
| Cert_5_2_05_AddressQuery | FAIL |  | 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18 |
| Cert_5_2_06_RouterDowngrade | pass | 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24 |  |
| Cert_5_2_07_REEDSynchronization | pass | 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17 |  |
| Cert_5_3_01_LinkLocal | pass | 1,2 |  |
| Cert_5_3_02_RealmLocal | pass | 1,2,3,4 |  |
| Cert_5_3_03_AddressQuery | pass | 1,2,3,4,5 |  |
| Cert_5_3_04_AddressMapCache | pass | 1,2,3,4,5,6,7 |  |
| Cert_5_3_05_RoutingLinkQuality | pass | 1,2,3,4 |  |
| Cert_5_3_06_RouterIdMask | pass | 1,2,3 |  |
| Cert_5_3_07_DuplicateAddress | FAIL |  | 1,2,3,4,5,6 |
| Cert_5_3_08_ChildAddressSet | FAIL |  | 1,2,3,4 |
| Cert_5_3_09_AddressQuery | FAIL |  | 1,2,3,4,5 |
| Cert_5_3_10_AddressQuery | FAIL | 2 | 1,3,4,5 |
| Cert_5_3_11_AddressQueryTimeoutIntervals | pass | 1,2,3 |  |

## Thread 1.2 (CSL, SSED), `v1_2_*` cases

Run with `OPENTRUST_CERT_CASES=v1_2_LowPower_5_3_01_SSEDAttachment,v1_2_test_csl_transmission` and `OPENTRUST_CERT_CONFIGS=ot,each,all`.

| case | all OT (baseline) | OpenTrust as node n: pass | OpenTrust as node n: fail |
|---|---|---|---|
| v1_2_LowPower_5_3_01_SSEDAttachment (1 leader, 2 router, 3 SSED) | pass | 1,2,3, all | |
| v1_2_test_csl_transmission (1 leader, 2 SSED) | pass | 1, all | 2 |

Node 2 of `v1_2_test_csl_transmission` (OpenTrust SSED, OpenThread leader) passes every step up to the last one: after the leader was away for more than the child timeout and returns, the SSED sends no Child Update Request within 5 s.

End-to-end CSL tests in `crates/opentrust-sim/tests/csl.rs` (virtual time, mixed OpenThread / OpenTrust): OpenTrust SSED under an OpenThread parent, OpenThread SSED under an OpenTrust parent, both OpenTrust. Each: attach with `csl period 500000`, the parent reports `CSL Synchronized: 1` (OpenThread parent), 4 x 2 pings with round trips between 42 and 444 ms (all inside one 500 ms period, they follow the phase between pings), no data polls of the child for them, fragmented 128 byte pings both ways, CSL channel 12 and back, `csl period 0` (child unreachable afterwards). Sample: OpenTrust child under OpenThread parent `[193, 192, 393, 392, 92, 92, 294, 292]` ms, polls 1 to 1.

## Failures and reasons

- **Baseline failures (all OpenThread nodes fail too): 5.2.05, 5.3.07, 5.3.08, 5.3.09, 5.3.10.** Not OpenTrust problems; the cause in the reference setup is not investigated. Their OpenTrust columns are meaningless.
- **Fixed: OpenThread sleepy child (SED) attaching to an OpenTrust router (5.1.02, 5.1.07, 5.3.02, 5.3.04).** The Child ID Response is queued for the SED's data poll (extended addresses); polls keep the child alive; the first MPL copy of a received multicast is queued for sleepy children.
- **Fixed in this round:** the CLI commands `childmax`, `childtimeout`, `releaserouterid`, `routeridrange`, `networkidtimeout`, `parentpriority`, `preferrouterid`, `keysequence`, `contextreusedelay`, `eidcache`, `mliid`, `detach`, `pollperiod`, `childsupervision`, `partitionid preferred` (5.1.03 / 5.1.04 node 3, 5.1.06 node 1, 5.1.07, 5.3.03 node 5); `ping` payload up to 1232 bytes (5.1.07 node 1); a sleepy OpenTrust child polls its parent candidate for the Child ID Response, which an OpenThread parent queues indirectly (5.1.07 nodes 7 to 12 and the OpenTrust SED nodes of 5.1.02, 5.3.02, 5.3.04); child table of 10 (OT default).

## Host tests

`cargo test --workspace --exclude openthread-sys`: 980 pass (the CSL work added the virtual radio tests in `opentrust_sim::vt`, the MAC `csl_child_sample` test and the five tests of `opentrust-sim/tests/csl.rs`). The mixed OpenThread / OpenTrust network tests (`crates/opentrust-sim/tests/mixed.rs`: OT leader with OpenTrust router and the reverse, router tables, pings both ways) run when `ot-cli-ftd` is built and are skipped otherwise.
