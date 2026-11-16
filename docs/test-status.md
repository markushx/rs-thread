# Test status

## thread-cert (OpenThread `tests/scripts/thread-cert`, Cert_5_1 to 5_3)

Run: `OPENTRUST_CERT=1 OPENTRUST_CERT_CONFIGS=ot,each,all cargo test -p opentrust-sim --test thread_cert` (see the header of `crates/opentrust-sim/tests/thread_cert.rs`; needs `ot-cli-ftd` from `cargo build -p openthread-sys` (rebuild it after changing the build options: the harness uses the existing binary), cmake, ninja, a Python venv with `pexpect pycryptodome pyshark==0.4.6 lxml`). Virtual time, OpenThread `simulator.py`, `THREAD_VERSION=1.4`. Each case runs once with all nodes `ot-cli-ftd` (baseline, validates the setup), once per node of its topology with only that node replaced by `opentrust-cli-vt` (`each`, so a pass means that role works against OpenThread peers) and once with all nodes `opentrust-cli-vt` (`all`). 30 cases, 273 runs: **273 pass, 0 fail** (30 `ot`, 213 `each`, 30 `all`). The whole run takes about 35 minutes.

The five cases that failed with OpenThread nodes only (5.2.5, 5.3.7 to 5.3.10; earlier 202 / 243) failed because `ot-cli-ftd` was built without `OT_BORDER_ROUTER`: `prefix add` is not a command then, and `add_prefix` in `node.py` waited for `Done`. The build has the option now (`tools/openthread-sys/build.rs`). 5.3.8 and 5.3.9 then showed that OpenTrust had no DHCPv6 (prefixes with the `d` flag): the client and server (`opentrust-instance` `dhcp6`) were missing, so as border router / leader or as client it got no GUA.

MTD build (`mtd:<nodes>`, one run per case with all its MED / SED nodes on `opentrust-cli-vt-mtd`, OpenThread for the rest): 12 of 12 pass (5.1.2 nodes 3+4, 5.1.7 nodes 3 to 12, 5.2.1 node 4, 5.2.5 node 17, 5.3.2 node 4, 5.3.3 node 5, 5.3.4 nodes 3 to 7, 5.3.7 nodes 4 to 6, 5.3.8 nodes 3+4, 5.3.9 node 5, 5.3.10 node 5, 5.3.11 node 3).

Packet verification (pktverify with `tshark`, `OPENTRUST_CERT_PKTVERIFY=1`): `thread_cert.py` refuses it on macOS ("Linux only") and `pktverify` assumes an older Python and Wireshark; the harness works around that (`tests/cert_pyshim/sitecustomize.py` reports Linux from `os.uname()`, supplies the removed asyncio child watcher for `pyshark` and parses `tshark` 4.6 booleans; `tshark` is linked to `/tmp/thread-wireshark`). Result with Homebrew `tshark` 4.6.9: all-OpenThread 12 of 30 cases pass (the rest fail in `pktverify`, i.e. the Wireshark dissection of 4.6 differs from the version the cases were written for), of those 12 all-OpenTrust passes 9 (5.1.7 to 5.1.13, 5.2.7, 5.3.6); 5.2.4 (`pv.vars['LEADER_MLEID']` missing), 5.3.5 and 5.3.8 (an expected packet not found, not analysed) fail only with OpenTrust. CLI based assertions are the default and what the table below shows.

| case | all OT (baseline) | OpenTrust as node n: pass (all also pass with every node OpenTrust) | OpenTrust as node n: fail/timeout |
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

## Thread 1.2 (CSL, SSED), `v1_2_*` cases

Run with `OPENTRUST_CERT_CASES=v1_2_LowPower_5_3_01_SSEDAttachment,v1_2_test_csl_transmission` and `OPENTRUST_CERT_CONFIGS=ot,each,all`.

| case | all OT (baseline) | OpenTrust as node n: pass | OpenTrust as node n: fail |
|---|---|---|---|
| v1_2_LowPower_5_3_01_SSEDAttachment (1 leader, 2 router, 3 SSED) | pass | 1,2,3, all | |
| v1_2_test_csl_transmission (1 leader, 2 SSED) | pass | 1, 2, all | |

Node 2 of `v1_2_test_csl_transmission` (OpenTrust SSED, OpenThread leader) passes: the SSED counts the failed data polls to its parent and detaches after 15 (4 without CSL) like OpenThread, so it attaches again when the leader returns.

### MTD build (`opentrust-cli-vt-mtd`, no ftd / commissioner / Border Agent)

`OPENTRUST_CERT_CONFIGS=mtd:3` etc. runs the named nodes with the MTD binary. All pass: Cert_5_1_02 (node 3, node 4, nodes 3+4), Cert_5_3_04 (node 3, node 4, 3+4, 3+4+5+6+7), v1_2_LowPower_5_3_01 (node 3). `crates/opentrust-sim/tests/mtd.rs`: MED, SED and SSED attach to an OpenThread leader and to an OpenThread router (macfilter), ping both ways with 8 to 1232 byte datagrams.

End-to-end CSL tests in `crates/opentrust-sim/tests/csl.rs` (virtual time, mixed OpenThread / OpenTrust): OpenTrust SSED under an OpenThread parent, OpenThread SSED under an OpenTrust parent, both OpenTrust. Each: attach with `csl period 500000`, the parent reports `CSL Synchronized: 1` (OpenThread parent), 4 x 2 pings with round trips between 42 and 444 ms (all inside one 500 ms period, they follow the phase between pings), no data polls of the child for them, fragmented 128 byte pings both ways, CSL channel 12 and back, `csl period 0` (child unreachable afterwards). Sample: OpenTrust child under OpenThread parent `[193, 192, 393, 392, 92, 92, 294, 292]` ms, polls 1 to 1.

## Failures and reasons

- **Baseline failures (all OpenThread nodes fail too): 5.2.05, 5.3.07, 5.3.08, 5.3.09, 5.3.10.** Not OpenTrust problems; the cause in the reference setup is not investigated. Their OpenTrust columns are meaningless.
- **Fixed: OpenThread sleepy child (SED) attaching to an OpenTrust router (5.1.02, 5.1.07, 5.3.02, 5.3.04).** The Child ID Response is queued for the SED's data poll (extended addresses); polls keep the child alive; the first MPL copy of a received multicast is queued for sleepy children.
- **Fixed in this round:** the CLI commands `childmax`, `childtimeout`, `releaserouterid`, `routeridrange`, `networkidtimeout`, `parentpriority`, `preferrouterid`, `keysequence`, `contextreusedelay`, `eidcache`, `mliid`, `detach`, `pollperiod`, `childsupervision`, `partitionid preferred` (5.1.03 / 5.1.04 node 3, 5.1.06 node 1, 5.1.07, 5.3.03 node 5); `ping` payload up to 1232 bytes (5.1.07 node 1); a sleepy OpenTrust child polls its parent candidate for the Child ID Response, which an OpenThread parent queues indirectly (5.1.07 nodes 7 to 12 and the OpenTrust SED nodes of 5.1.02, 5.3.02, 5.3.04); child table of 10 (OT default).

## Host tests

`cargo test --workspace --exclude openthread-sys`: 980 pass (the CSL work added the virtual radio tests in `opentrust_sim::vt`, the MAC `csl_child_sample` test and the five tests of `opentrust-sim/tests/csl.rs`). The mixed OpenThread / OpenTrust network tests (`crates/opentrust-sim/tests/mixed.rs`: OT leader with OpenTrust router and the reverse, router tables, pings both ways) run when `ot-cli-ftd` is built and are skipped otherwise.
