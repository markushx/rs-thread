# Test status

## thread-cert (OpenThread `tests/scripts/thread-cert`, Cert_5_1 to 5_3)

Run: `OPENTRUST_CERT=1 cargo test -p opentrust-sim --test thread_cert` (see the header of `crates/opentrust-sim/tests/thread_cert.rs`; needs `ot-cli-ftd` from `cargo build -p openthread-sys`, cmake, ninja, a Python venv with `pexpect pycryptodome pyshark==0.4.6 lxml`). Virtual time, OpenThread `simulator.py`, `THREAD_VERSION=1.4`. Each case runs once with all nodes `ot-cli-ftd` (baseline, validates the setup) and once per node of its topology with only that node replaced by `opentrust-cli-vt`, so a pass means that role works against OpenThread peers. 30 cases, 243 runs: **178 pass, 65 fail**. The whole run takes about 25 minutes.

Packet verification (pktverify, tshark) is not run: `thread_cert.py` refuses it on macOS ("Linux only"), so only the CLI based assertions of the cases are checked (`OPENTRUST_CERT_PKTVERIFY=1` enables it on Linux).

| case | all OT (baseline) | OpenTrust as node n: pass | OpenTrust as node n: fail/timeout |
|---|---|---|---|
| Cert_5_1_01_RouterAttach | pass | 1,2 |  |
| Cert_5_1_02_ChildAddressTimeout | pass | 1 | 2,3,4 |
| Cert_5_1_03_RouterAddressReallocation | pass | 1,2 | 3 |
| Cert_5_1_04_RouterAddressReallocation | pass | 1,2 | 3 |
| Cert_5_1_05_RouterAddressTimeout | pass | 1,2 |  |
| Cert_5_1_06_RemoveRouterId | pass | 2 | 1 |
| Cert_5_1_07_MaxChildCount | pass |  | 1,2,3,4,5,6,7,8,9,10,11,12 |
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
| Cert_5_3_02_RealmLocal | pass | 1,2 | 3,4 |
| Cert_5_3_03_AddressQuery | pass | 1,2,3,4 | 5 |
| Cert_5_3_04_AddressMapCache | pass | 1,4,5,6,7 | 2,3 |
| Cert_5_3_05_RoutingLinkQuality | pass | 1,2,3,4 |  |
| Cert_5_3_06_RouterIdMask | pass | 1,2,3 |  |
| Cert_5_3_07_DuplicateAddress | FAIL |  | 1,2,3,4,5,6 |
| Cert_5_3_08_ChildAddressSet | FAIL |  | 1,2,3,4 |
| Cert_5_3_09_AddressQuery | FAIL |  | 1,2,3,4,5 |
| Cert_5_3_10_AddressQuery | FAIL | 2 | 1,3,4,5 |
| Cert_5_3_11_AddressQueryTimeoutIntervals | pass | 1,2,3 |  |

## Failures and reasons

- **Baseline failures (all OpenThread nodes fail too): 5.2.05, 5.3.07, 5.3.08, 5.3.09, 5.3.10.** Not OpenTrust problems; the cause in the reference setup is not investigated. Their OpenTrust columns are meaningless.
- **Sleepy child (SED) attaching to an OpenTrust router: 5.1.02 (nodes 2 to 4), 5.3.02 (3, 4), 5.3.04 (2, 3).** An `ot-cli-ftd` SED switches its radio off after the Child ID Request and polls; the OpenTrust parent sends the Child ID Response directly to the extended address of the child (queued indirectly only for confirmed children), so the SED never receives it. A fix needs indirect transmission to the extended address (frames addressed with the child's extended address, source match table with both addresses; a patch was tried and reverted) and a fast attach-time poll in the OpenTrust SED, which breaks `opentrust-matter/tests/icd.rs` as it stands.
- **5.1.03 / 5.1.04 node 3, 5.1.06 node 1, 5.1.07 (all nodes), 5.3.03 node 5, 5.3.10:** probably CLI commands the OpenTrust CLI does not have yet (`childmax`, `childtimeout`, `releaserouterid`, `routeridrange`, `networkidtimeout`, `parentpriority`, `preferrouterid`, `keysequence`, `contextreusedelay`, `eidcache`, `mliid`, `detach`, `pollperiod`, `childsupervision`); the run directories' `out.log` / `err.log` show `Error 35: InvalidCommand`. Not triaged one by one.

## Host tests

`cargo test --workspace --exclude openthread-sys`: 937 pass. The mixed OpenThread / OpenTrust network tests (`crates/opentrust-sim/tests/mixed.rs`: OT leader with OpenTrust router and the reverse, router tables, pings both ways) run when `ot-cli-ftd` is built and are skipped otherwise.
