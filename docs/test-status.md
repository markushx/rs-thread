# Test status

Per-case status of every OpenThread `thread-cert` test-plan script (5.x to 9.x, LowPower, functional tests): [test-plan-status.md](test-plan-status.md).

## thread-cert (OpenThread `tests/scripts/thread-cert`, Cert_5_1 to 5_3)

Run: `OPENTRUST_CERT=1 OPENTRUST_CERT_CONFIGS=ot,each,all cargo test -p rs-thread-sim --test thread_cert` (see the header of `crates/rs-thread-sim/tests/thread_cert.rs`; needs `ot-cli-ftd` from `cargo build -p openthread-sys` (rebuild it after changing the build options: the harness uses the existing binary), cmake, ninja, a Python venv with `pexpect pycryptodome pyshark==0.4.6 lxml`). Virtual time, OpenThread `simulator.py`, `THREAD_VERSION=1.4`. Each case runs once with all nodes `ot-cli-ftd` (baseline, validates the setup), once per node of its topology with only that node replaced by `rs-thread-cli-vt` (`each`, so a pass means that role works against OpenThread peers) and once with all nodes `rs-thread-cli-vt` (`all`). 30 cases, 273 runs: **273 pass, 0 fail** (30 `ot`, 213 `each`, 30 `all`). The whole run takes about 35 minutes.

The five cases that failed with OpenThread nodes only (5.2.5, 5.3.7 to 5.3.10; earlier 202 / 243) failed because `ot-cli-ftd` was built without `OT_BORDER_ROUTER`: `prefix add` is not a command then, and `add_prefix` in `node.py` waited for `Done`. The build has the option now (`tools/openthread-sys/build.rs`). 5.3.8 and 5.3.9 then showed that rs-thread had no DHCPv6 (prefixes with the `d` flag): the client and server (`rs-thread-instance` `dhcp6`) were missing, so as border router / leader or as client it got no GUA.

MTD build (`mtd:<nodes>`, one run per case with all its MED / SED nodes on `rs-thread-cli-vt-mtd`, OpenThread for the rest): 12 of 12 pass (5.1.2 nodes 3+4, 5.1.7 nodes 3 to 12, 5.2.1 node 4, 5.2.5 node 17, 5.3.2 node 4, 5.3.3 node 5, 5.3.4 nodes 3 to 7, 5.3.7 nodes 4 to 6, 5.3.8 nodes 3+4, 5.3.9 node 5, 5.3.10 node 5, 5.3.11 node 3).

Packet verification (pktverify with `tshark`, `OPENTRUST_CERT_PKTVERIFY=1`): `thread_cert.py` refuses it on macOS ("Linux only") and `pktverify` assumes an older Python and Wireshark; the harness works around that (`tests/cert_pyshim/sitecustomize.py` reports Linux from `os.uname()`, supplies the removed asyncio child watcher for `pyshark` and parses `tshark` 4.6 booleans; `tshark` is linked to `/tmp/thread-wireshark`). Result with Homebrew `tshark` 4.6.9: all-OpenThread 12 of 30 cases pass (the rest fail in `pktverify`, i.e. the Wireshark dissection of 4.6 differs from the version the cases were written for), of those 12 all-rs-thread passes 9 (5.1.7 to 5.1.13, 5.2.7, 5.3.6); 5.2.4 (`pv.vars['LEADER_MLEID']` missing), 5.3.5 and 5.3.8 (an expected packet not found, not analysed) fail only with rs-thread. CLI based assertions are the default and what the table below shows.

| case | all OT (baseline) | rs-thread as node n: pass (all also pass with every node rs-thread) | rs-thread as node n: fail/timeout |
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
| Cert_5_2_05_AddressQuery | pass | 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18 |  |
| Cert_5_2_06_RouterDowngrade | pass | 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24 |  |
| Cert_5_2_07_REEDSynchronization | pass | 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17 |  |
| Cert_5_3_01_LinkLocal | pass | 1,2 |  |
| Cert_5_3_02_RealmLocal | pass | 1,2,3,4 |  |
| Cert_5_3_03_AddressQuery | pass | 1,2,3,4,5 |  |
| Cert_5_3_04_AddressMapCache | pass | 1,2,3,4,5,6,7 |  |
| Cert_5_3_05_RoutingLinkQuality | pass | 1,2,3,4 |  |
| Cert_5_3_06_RouterIdMask | pass | 1,2,3 |  |
| Cert_5_3_07_DuplicateAddress | pass | 1,2,3,4,5,6 |  |
| Cert_5_3_08_ChildAddressSet | pass | 1,2,3,4 |  |
| Cert_5_3_09_AddressQuery | pass | 1,2,3,4,5 |  |
| Cert_5_3_10_AddressQuery | pass | 1,2,3,4,5 |  |
| Cert_5_3_11_AddressQueryTimeoutIntervals | pass | 1,2,3 |  |

## Commissioning and datasets (`Cert_8_*`, `Cert_9_2_*`)

Run: `OPENTRUST_CERT=1 OPENTRUST_CERT_CASES=Cert_8_,Cert_9_2_ OPENTRUST_CERT_CONFIGS=ot,each,all cargo test -p rs-thread-sim --test thread_cert` (CLI based assertions, no packet verification). 26 cases, 134 runs: **134 pass, 0 fail**. `ot-cli-ftd` has commissioner, joiner and Border Router enabled; it logs through the CLI (`OT_LOG_OUTPUT=APP`, built by `openthread-sys` when its `cli` feature is on) because the cases read the `[THCI]` commissioning lines from the CLI output (before that, `Cert_8_1_01`, `8_1_06` and `8_2_05` failed with OpenThread nodes only). Rebuild `ot-cli-ftd` with `cargo build -p openthread-sys` after pulling this change.

Everything passes in every configuration (rs-thread as each node, as all nodes). The last open cases were fixed by: a reattach that keeps the Pending Dataset delay (`Cert_9_2_09`), a router attaching to a better partition (`9_2_09`), the frame counter reset of the neighbors on a network key change (`9_2_11`, `9_2_18`), the restored reattach state and device mode (`9_2_08`), and the instance wiring of Announce Begin, Energy Scan and PAN ID Query with the broadcast PAN ID of the MLE Announce (`9_2_12` to `9_2_14`). The cert harness also takes `OPENTRUST_CERT_CONFIGS=set:2+4` (exactly those nodes rs-thread).

| case | all OT (baseline) | rs-thread as node n: pass | rs-thread as node n: fail | all rs-thread |
|---|---|---|---|---|
| Cert_8_1_01_Commissioning | pass | 1,2 |  | pass |
| Cert_8_1_02_Commissioning | pass | 1,2 |  | pass |
| Cert_8_1_06_Commissioning | pass | 1,2 |  | pass |
| Cert_8_2_01_JoinerRouter | pass | 1,2,3 |  | pass |
| Cert_8_2_02_JoinerRouter | pass | 1,2,3 |  | pass |
| Cert_8_2_05_JoinerRouter | pass | 1,2,3 |  | pass |
| Cert_8_3_01_CommissionerPetition | pass | 1,2 |  | pass |
| Cert_9_2_01_MGMTCommissionerGet | pass | 1,2 |  | pass |
| Cert_9_2_02_MGMTCommissionerSet | pass | 1,2 |  | pass |
| Cert_9_2_03_ActiveDatasetGet | pass | 1,2 |  | pass |
| Cert_9_2_04_ActiveDataset | pass | 1,2 |  | pass |
| Cert_9_2_05_ActiveDataset | pass | 1,2 |  | pass |
| Cert_9_2_06_DatasetDissemination | pass | 1,2,3,4,5 |  | pass |
| Cert_9_2_07_DelayTimer | pass | 1,2,3 |  | pass |
| Cert_9_2_08_PersistentDatasets | pass | 1,2,3 |  | pass |
| Cert_9_2_09_PendingPartition | pass | 1,2,3,4 |  | pass |
| Cert_9_2_10_PendingPartition | pass | 1,2,3,4,5 |  | pass |
| Cert_9_2_11_NetworkKey | pass | 1,2,3,4,5 |  | pass |
| Cert_9_2_12_Announce | pass | 1,2,3,4 |  | pass |
| Cert_9_2_13_EnergyScan | pass | 1,2,3,4 |  | pass |
| Cert_9_2_14_PanIdQuery | pass | 1,2,3,4 |  | pass |
| Cert_9_2_15_PendingPartition | pass | 1,2,3,4 |  | pass |
| Cert_9_2_16_ActivePendingPartition | pass | 1,2,3,4 |  | pass |
| Cert_9_2_17_Orphan | pass | 1,2,3 |  | pass |
| Cert_9_2_18_RollBackActiveTimestamp | pass | 1,2,3,4,5 |  | pass |
| Cert_9_2_19_PendingDatasetGet | pass | 1,2 |  | pass |

In-process mixed tests (`crates/rs-thread-sim/tests/commissioning_mixed.rs`, virtual time, `ot-cli-ftd` with `rs-thread-cli-vt` / `rs-thread-cli-vt-mtd`): 15 tests pass. OpenThread Commissioner with an rs-thread FTD and with an MTD Joiner; rs-thread Commissioner with an OpenThread Joiner (EUI-64 and `*`); the Joiner two hops away behind a Joiner Router of the other implementation (OpenThread JR with rs-thread Commissioner and Joiner, rs-thread JR with OpenThread Commissioner and Joiner, MTD Joiner behind an OpenThread JR, rs-thread JR with rs-thread Commissioner and OpenThread Joiner); wrong PSKd on both sides (Joiner fails, the Network Key does not reach it, the right PSKd works afterwards); Commissioner petition with either implementation as Leader (stays active through several keep-alive periods, a second Commissioner with another ID is refused, accepted after the first resigned); MGMT_ACTIVE_SET from a Commissioner of one implementation to a Leader of the other. Bugs found: the rs-thread Leader never matched the Commissioner Session ID of an MGMT_ACTIVE_SET / PENDING_SET (every set from a Commissioner was rejected); the Joiner stopped on a Reject and the Commissioner withheld the KEK (see `OPENTRUST-OPENTHREAD-DIFFERENCES.md`); `joiner` was missing on the MTD build; `state leader` was refused while Thread was running. The 5.x suite after these changes: 273 of 273 pass.

Nothing of this ran on hardware.

## Thread 1.2 (CSL, SSED), `v1_2_*` cases

Run with `OPENTRUST_CERT_CASES=v1_2_LowPower_5_3_01_SSEDAttachment,v1_2_test_csl_transmission` and `OPENTRUST_CERT_CONFIGS=ot,each,all`.

| case | all OT (baseline) | rs-thread as node n: pass | rs-thread as node n: fail |
|---|---|---|---|
| v1_2_LowPower_5_3_01_SSEDAttachment (1 leader, 2 router, 3 SSED) | pass | 1,2,3, all | |
| v1_2_test_csl_transmission (1 leader, 2 SSED) | pass | 1, 2, all | |

Node 2 of `v1_2_test_csl_transmission` (rs-thread SSED, OpenThread leader) passes: the SSED counts the failed data polls to its parent and detaches after 15 (4 without CSL) like OpenThread, so it attaches again when the leader returns.

### MTD build (`rs-thread-cli-vt-mtd`, no ftd / commissioner / Border Agent)

`OPENTRUST_CERT_CONFIGS=mtd:3` etc. runs the named nodes with the MTD binary. All pass: Cert_5_1_02 (node 3, node 4, nodes 3+4), Cert_5_3_04 (node 3, node 4, 3+4, 3+4+5+6+7), v1_2_LowPower_5_3_01 (node 3). `crates/rs-thread-sim/tests/mtd.rs`: MED, SED and SSED attach to an OpenThread leader and to an OpenThread router (macfilter), ping both ways with 8 to 1232 byte datagrams.

End-to-end CSL tests in `crates/rs-thread-sim/tests/csl.rs` (virtual time, mixed OpenThread / rs-thread): rs-thread SSED under an OpenThread parent, OpenThread SSED under an rs-thread parent, both rs-thread. Each: attach with `csl period 500000`, the parent reports `CSL Synchronized: 1` (OpenThread parent), 4 x 2 pings with round trips between 42 and 444 ms (all inside one 500 ms period, they follow the phase between pings), no data polls of the child for them, fragmented 128 byte pings both ways, CSL channel 12 and back, `csl period 0` (child unreachable afterwards). Sample: rs-thread child under OpenThread parent `[193, 192, 393, 392, 92, 92, 294, 292]` ms, polls 1 to 1.

## Failures and reasons

- **Baseline failures (all OpenThread nodes fail too): 5.2.05, 5.3.07, 5.3.08, 5.3.09, 5.3.10.** Not rs-thread problems; the cause in the reference setup is not investigated. Their rs-thread columns are meaningless.
- **Fixed: OpenThread sleepy child (SED) attaching to an rs-thread router (5.1.02, 5.1.07, 5.3.02, 5.3.04).** The Child ID Response is queued for the SED's data poll (extended addresses); polls keep the child alive; the first MPL copy of a received multicast is queued for sleepy children.
- **Fixed in this round:** the CLI commands `childmax`, `childtimeout`, `releaserouterid`, `routeridrange`, `networkidtimeout`, `parentpriority`, `preferrouterid`, `keysequence`, `contextreusedelay`, `eidcache`, `mliid`, `detach`, `pollperiod`, `childsupervision`, `partitionid preferred` (5.1.03 / 5.1.04 node 3, 5.1.06 node 1, 5.1.07, 5.3.03 node 5); `ping` payload up to 1232 bytes (5.1.07 node 1); a sleepy rs-thread child polls its parent candidate for the Child ID Response, which an OpenThread parent queues indirectly (5.1.07 nodes 7 to 12 and the rs-thread SED nodes of 5.1.02, 5.3.02, 5.3.04); child table of 10 (OT default).

## Host tests

`cargo test --workspace --exclude openthread-sys`: 980 pass (the CSL work added the virtual radio tests in `opentrust_sim::vt`, the MAC `csl_child_sample` test and the five tests of `rs-thread-sim/tests/csl.rs`). The mixed OpenThread / rs-thread network tests (`crates/rs-thread-sim/tests/mixed.rs`: OT leader with rs-thread router and the reverse, router tables, pings both ways) run when `ot-cli-ftd` is built and are skipped otherwise.

## Gaps closed (key handling, diagnostics, Thread 1.2)

Regression `Cert_5_` to `Cert_9_`, `ot,each,all`: 706 runs, 704 pass; the two failures are the known `Cert_6_5_02` (node 3, all). Newly passing: 5.7.1 to 5.7.3 (`networkdiagnostic` CLI), 6.2.2 (did not reproduce), `test_mle_msg_key_seq_jump`, `test_router_downgrade_on_sec_policy_change`, `v1_2_test_enhanced_frame_pending`, `v1_2_test_enhanced_keep_alive`, `v1_2_test_single_probe`. Open: `test_key_rotation_and_key_guard_time` and `test_dataset_updater` need `dataset updater`; the LowPower link metrics cases still fail (`mac send emptydata`, subject side).

## Link Metrics (Thread 1.2)

LowPower 7.1.1, 7.1.2, 7.2.1, `v1_2_LowPower_test_forward_tracking_series`, `v1_2_LowPower_test_link_metrics_manager` and `v1_2_test_single_probe` pass with `ot,each,all` (7.1.1, 7.1.2 and the manager also with pktverify; 7.2.1 pktverify fails with all OpenThread nodes as well). The `mtd:N` configurations do not apply: the cases do not set `is_mtd`, so the harness sends `routerselectionjitter`, which the MTD build rejects as OT's MTD does. Fixes: `mac send emptydata|datarequest`, data requests and LQI-less frames in series accounting, keep-alive reset only at the default poll period (7.1.2 node 2 ping: with `pollperiod 2000` every acked ping postponed the poll by 2 s and the reply missed the 2 s timeout), Frame Version 2015 to a probed neighbor, `linkmetrics config ... enhanced-ack register <metrics> r`, `linkmetricsmgr`.

Regression `Cert_5_` to `Cert_9_`, `ot,each,all`: 706 runs, 705 pass on the first run and the one failure (`Cert_5_3_08` node 3) passes alone (simulator port collision); `v1_2_LowPower_*` all pass. `v1_2_test_enhanced_keep_alive` node 2 and all fail, already before this work (OT attaches from scratch after `thread stop` / `start`, rs-thread restores the parent and sends a Child Update Request; no Child ID Response). The `v1_2_test_backbone_router_service`, DUA and multicast registration scripts fail with all OpenThread nodes too.

`examples/nrf52840-light` (BLE build): about 980 kB of flash (text 910 kB + rodata 70 kB), 2.8 kB less than at the base commit (983.5 kB), static RAM unchanged; the Subject was already in the build and the Link Metrics Manager (feature `link-metrics-manager`, +450 B RAM, a few kB code) is off in the light.
