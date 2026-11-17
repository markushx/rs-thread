# Thread test-plan status (OpenThread thread-cert numbering)

Maps every test-plan case that OpenThread ships as a `thread-cert` script
(`tests/scripts/thread-cert/`, vendored at `tools/openthread-sys/vendor/openthread`)
to its status with OpenTrust. **The source is OpenThread's script set, numbered as in the
Thread test plan (`Cert_5_1_01_RouterAttach.py` = 5.1.1, `v1_2_LowPower_5_3_01_SSEDAttachment.py` =
LowPower 5.3.1), not the Thread Group test-plan document: a case that OpenThread has no script for
is not covered here.** Titles are derived from the script names. Details of the 5.x runs and of the
harness are in [test-status.md](test-status.md).

## Method

- Harness: `crates/opentrust-sim/tests/thread_cert.rs` (`OPENTRUST_CERT=1`), virtual time, OpenThread
  `simulator.py`, `THREAD_VERSION=1.4`, `ot-cli-ftd` from `cargo build -p openthread-sys`
  (`OT_BORDER_ROUTER`, `OT_DUA`, `OT_MLR`, `OT_BACKBONE_ROUTER`, `OT_CSL_RECEIVER`, link metrics, SRP client and
  server; plus `ot-cli-ftd-1.1`, a Thread 1.1 build for the nodes with `'version': '1.1'`).
- Configurations per case: `ot` (all nodes OpenThread, the baseline), `each` (one run per node of the
  topology with only that node `opentrust-cli-vt`), `all` (all nodes OpenTrust). The "runs passed" column
  counts these runs (without the MTD runs). The MTD column lists runs with the MED / SED nodes of the
  case on `opentrust-cli-vt-mtd` (OpenThread for the rest): one run per case, every case that has MTD nodes.
- Packet verification is **off** for the status columns (CLI based assertions only): the Homebrew
  `tshark` 4.6 dissects some fields differently from the Wireshark the `pktverify` checks were written for,
  so `pktverify` results are unreliable (see the pktverify section).
- Status: **pass** = every `ot`, `each` and `all` run passes; **partial** = the baseline passes but some
  OpenTrust runs fail (the detail names the nodes); **fail** = every OpenTrust run fails;
  **baseline-fail** = the all-OpenThread run fails (OpenTrust not judged); **NA** = cannot run in the
  simulation harness (reason given); **not run**.
- Cases were first run in several batches in parallel (about 8 processes on 8 cores); every failure of
  a case with a passing baseline was rerun alone, which removed all flakes (parallel runs collide on
  simulator ports and time out: 5.1.6 baseline, 5.1.12, 5.5.1, 5.5.4, 5.5.7, 5.6.1, 6.1.1, 6.1.2, 6.1.5,
  7.1.8, 8.1.2, 9.2.1 passed on the rerun). Failures listed below are reproducible.

## Summary per section

| section | cases | pass | partial | fail | baseline-fail | not run | runs passed / run |
|---|---|---|---|---|---|---|---|
| 5.x | 50 | 47 | 3 | 0 | 0 | 0 | 425/431 |
| 6.x | 18 | 17 | 1 | 0 | 0 | 0 | 90/92 |
| 7.x | 8 | 8 | 0 | 0 | 0 | 0 | 49/49 |
| 8.x | 7 | 7 | 0 | 0 | 0 | 0 | 31/31 |
| 9.x | 19 | 12 | 6 | 1 | 0 | 0 | 78/103 |
| LowPower | 6 | 3 | 2 | 1 | 0 | 0 | 20/30 |

NA (cannot run in this harness): 11 backbone + 8 MATN + 3 border-router LowPower + 5 internet +
23 border-router scripts, see "Not runnable".

## Test-plan cases

### 5.x Network formation, routing, address resolution, network data, diagnostics, security

| # | title | script | status | runs passed | MTD build | pktverify (ot / all) | detail |
|---|---|---|---|---|---|---|---|
| 5.1.1 | Router Attach | `Cert_5_1_01_RouterAttach` | pass | 4/4 |  | fail / fail |  |
| 5.1.2 | Child Address Timeout | `Cert_5_1_02_ChildAddressTimeout` | pass | 6/6 |  | fail / fail |  |
| 5.1.3 | Router Address Reallocation | `Cert_5_1_03_RouterAddressReallocation` | pass | 5/5 |  | fail / fail |  |
| 5.1.4 | Router Address Reallocation | `Cert_5_1_04_RouterAddressReallocation` | pass | 5/5 |  | fail / fail |  |
| 5.1.5 | Router Address Timeout | `Cert_5_1_05_RouterAddressTimeout` | pass | 4/4 |  | fail / fail |  |
| 5.1.6 | Remove Router Id | `Cert_5_1_06_RemoveRouterId` | pass | 4/4 |  | fail / fail |  |
| 5.1.7 | Max Child Count | `Cert_5_1_07_MaxChildCount` | pass | 14/14 |  | pass / pass |  |
| 5.1.8 | Router Attach Connectivity | `Cert_5_1_08_RouterAttachConnectivity` | pass | 7/7 |  | pass / pass |  |
| 5.1.9 | REED Attach Connectivity | `Cert_5_1_09_REEDAttachConnectivity` | pass | 7/7 |  | pass / pass |  |
| 5.1.10 | Router Attach Link Quality | `Cert_5_1_10_RouterAttachLinkQuality` | pass | 6/6 |  | pass / pass |  |
| 5.1.11 | REED Attach Link Quality | `Cert_5_1_11_REEDAttachLinkQuality` | pass | 6/6 |  | pass / pass |  |
| 5.1.12 | New Router Neighbor Sync | `Cert_5_1_12_NewRouterNeighborSync` | pass | 5/5 |  | fail / pass |  |
| 5.1.13 | Router Reset | `Cert_5_1_13_RouterReset` | pass | 4/4 |  | pass / pass |  |
| 5.2.1 | REED Attach | `Cert_5_2_01_REEDAttach` | pass | 6/6 |  | fail / fail |  |
| 5.2.3 | Leader Reject2 Hops | `Cert_5_2_03_LeaderReject2Hops` | pass | 35/35 |  | fail / fail |  |
| 5.2.4 | REED Upgrade | `Cert_5_2_04_REEDUpgrade` | pass | 20/20 |  | pass / fail |  |
| 5.2.5 | Address Query | `Cert_5_2_05_AddressQuery` | pass | 20/20 |  | fail / fail |  |
| 5.2.6 | Router Downgrade | `Cert_5_2_06_RouterDowngrade` | pass | 26/26 |  | fail / fail |  |
| 5.2.7 | REED Synchronization | `Cert_5_2_07_REEDSynchronization` | pass | 19/19 |  | pass / pass |  |
| 5.3.1 | Link Local | `Cert_5_3_01_LinkLocal` | pass | 4/4 |  | fail / pass |  |
| 5.3.2 | Realm Local | `Cert_5_3_02_RealmLocal` | pass | 6/6 |  | fail / fail |  |
| 5.3.3 | Address Query | `Cert_5_3_03_AddressQuery` | pass | 7/7 |  | fail / fail |  |
| 5.3.4 | Address Map Cache | `Cert_5_3_04_AddressMapCache` | pass | 9/9 |  | fail / fail |  |
| 5.3.5 | Routing Link Quality | `Cert_5_3_05_RoutingLinkQuality` | pass | 6/6 |  | pass / fail |  |
| 5.3.6 | Router Id Mask | `Cert_5_3_06_RouterIdMask` | pass | 5/5 |  | pass / pass |  |
| 5.3.7 | Duplicate Address | `Cert_5_3_07_DuplicateAddress` | pass | 8/8 |  | fail / fail |  |
| 5.3.8 | Child Address Set | `Cert_5_3_08_ChildAddressSet` | pass | 6/6 |  | pass / fail |  |
| 5.3.9 | Address Query | `Cert_5_3_09_AddressQuery` | pass | 7/7 |  | fail / fail |  |
| 5.3.10 | Address Query | `Cert_5_3_10_AddressQuery` | pass | 7/7 |  | fail / fail |  |
| 5.3.11 | Address Query Timeout Intervals | `Cert_5_3_11_AddressQueryTimeoutIntervals` | pass | 5/5 |  | fail / fail |  |
| 5.5.1 | Leader Reboot | `Cert_5_5_01_LeaderReboot` | pass | 4/4 |  | pass / pass |  |
| 5.5.2 | Leader Reboot | `Cert_5_5_02_LeaderReboot` | pass | 5/5 |  | fail / fail |  |
| 5.5.3 | Split Merge Children | `Cert_5_5_03_SplitMergeChildren` | pass | 7/7 |  | fail / fail |  |
| 5.5.4 | Split Merge Routers | `Cert_5_5_04_SplitMergeRouters` | pass | 7/7 |  | pass / pass |  |
| 5.5.5 | Split Merge REED | `Cert_5_5_05_SplitMergeREED` | pass | 19/19 |  | pass / pass |  |
| 5.5.7 | Split Merge Three Way | `Cert_5_5_07_SplitMergeThreeWay` | pass | 6/6 |  | pass / pass |  |
| 5.6.1 | Network Data Register Before Attach Leader | `Cert_5_6_01_NetworkDataRegisterBeforeAttachLeader` | pass | 6/6 |  | fail / fail |  |
| 5.6.2 | Network Data Register Before Attach Router | `Cert_5_6_02_NetworkDataRegisterBeforeAttachRouter` | pass | 6/6 |  | fail / fail |  |
| 5.6.3 | Network Data Register After Attach Leader | `Cert_5_6_03_NetworkDataRegisterAfterAttachLeader` | pass | 6/6 |  | fail / fail |  |
| 5.6.4 | Network Data Register After Attach Router | `Cert_5_6_04_NetworkDataRegisterAfterAttachRouter` | pass | 6/6 |  | fail / fail |  |
| 5.6.5 | Network Data Register After Attach Router | `Cert_5_6_05_NetworkDataRegisterAfterAttachRouter` | pass | 6/6 |  | fail / fail |  |
| 5.6.6 | Network Data Expiration | `Cert_5_6_06_NetworkDataExpiration` | pass | 6/6 |  | fail / fail |  |
| 5.6.7 | Network Data Request REED | `Cert_5_6_07_NetworkDataRequestREED` | pass | 19/19 |  | pass / pass |  |
| 5.6.9 | Network Data Forwarding | `Cert_5_6_09_NetworkDataForwarding` | pass | 7/7 |  | fail / fail |  |
| 5.7.1 | Coap Diag Commands | `Cert_5_7_01_CoapDiagCommands` | pass | 8/8 |  | pass / pass | the DUT answered all along; the Leader needed the `networkdiagnostic get|reset` CLI |
| 5.7.2 | Coap Diag Commands | `Cert_5_7_02_CoapDiagCommands` | pass | 19/19 |  | pass / pass | as 5.7.1 |
| 5.7.3 | Coap Diag Commands | `Cert_5_7_03_CoapDiagCommands` | pass | 7/7 |  | pass / pass | as 5.7.1 |
| 5.8.2 | Key Increment | `Cert_5_8_02_KeyIncrement` | pass | 4/4 |  | pass / fail |  |
| 5.8.3 | Key Increment Roll Over | `Cert_5_8_03_KeyIncrementRollOver` | pass | 4/4 |  | pass / fail |  |
| 5.8.4 | Security Policy TLV | `Cert_5_8_04_SecurityPolicyTLV` | pass | 6/6 |  | fail / fail |  |

### 6.x Attaching, partitions, reset, link-local / realm-local, key increment

| # | title | script | status | runs passed | MTD build | pktverify (ot / all) | detail |
|---|---|---|---|---|---|---|---|
| 6.1.1 | Router Attach | `Cert_6_1_01_RouterAttach` | pass | 4/4 | n2 pass | pass / pass |  |
| 6.1.2 | REED Attach | `Cert_6_1_02_REEDAttach` | pass | 5/5 | n3 pass | fail / fail |  |
| 6.1.3 | Router Attach Connectivity | `Cert_6_1_03_RouterAttachConnectivity` | pass | 7/7 | n5 pass | pass / fail |  |
| 6.1.4 | REED Attach Connectivity | `Cert_6_1_04_REEDAttachConnectivity` | pass | 7/7 | n5 pass | fail / fail |  |
| 6.1.5 | REED Attach Connectivity | `Cert_6_1_05_REEDAttachConnectivity` | pass | 7/7 | n5 pass | pass / pass |  |
| 6.1.6 | REED Attach Link Quality | `Cert_6_1_06_REEDAttachLinkQuality` | pass | 6/6 | n4 pass | pass / pass |  |
| 6.1.7 | Router Attach Link Quality | `Cert_6_1_07_RouterAttachLinkQuality` | pass | 6/6 | n4 pass | pass / fail |  |
| 6.2.1 | New Partition | `Cert_6_2_01_NewPartition` | pass | 5/5 | n3 pass | pass / pass |  |
| 6.2.2 | New Partition | `Cert_6_2_02_NewPartition` | pass | 6/6 |  | pass / fail | passes in every configuration on the current tree (the earlier node 2 / all failure did not reproduce; not traced to a change); pktverify differs |
| 6.3.1 | Orphan Reattach | `Cert_6_3_01_OrphanReattach` | pass | 5/5 | n3 pass | pass / pass |  |
| 6.3.2 | Network Data Update | `Cert_6_3_02_NetworkDataUpdate` | pass | 4/4 | n2 pass | pass / pass |  |
| 6.4.1 | Link Local | `Cert_6_4_01_LinkLocal` | pass | 4/4 | n2 pass | fail / pass |  |
| 6.4.2 | Realm Local | `Cert_6_4_02_RealmLocal` | pass | 5/5 | n3 pass | fail / fail |  |
| 6.5.1 | Child Reset Reattach | `Cert_6_5_01_ChildResetReattach` | pass | 4/4 | n2 pass | pass / fail |  |
| 6.5.2 | Child Reset Reattach | `Cert_6_5_02_ChildResetReattach` | pass | 5/5 | n3 pass | pass / fail | fixed: the stored extended address is restored when the instance is created (before `thread start`), as OpenThread does; the script reads it after the reset to allow-list the DUT at the leader |
| 6.5.3 | Child Reset Synchronize | `Cert_6_5_03_ChildResetSynchronize` | pass | 4/4 | n2 pass | fail / pass |  |
| 6.6.1 | Key Increment | `Cert_6_6_01_KeyIncrement` | pass | 4/4 | n2 pass | pass / fail |  |
| 6.6.2 | Key Increment Roll Over | `Cert_6_6_02_KeyIncrementRollOver` | pass | 4/4 | n2 pass | pass / fail |  |

### 7.x Border router (network data / on-mesh prefixes)

| # | title | script | status | runs passed | MTD build | pktverify (ot / all) | detail |
|---|---|---|---|---|---|---|---|
| 7.1.1 | Border Router As Leader | `Cert_7_1_01_BorderRouterAsLeader` | pass | 6/6 | n3+4 pass | fail / fail |  |
| 7.1.2 | Border Router As Router | `Cert_7_1_02_BorderRouterAsRouter` | pass | 6/6 | n3+4 pass | fail / fail |  |
| 7.1.3 | Border Router As Leader | `Cert_7_1_03_BorderRouterAsLeader` | pass | 6/6 | n3+4 pass | fail / fail |  |
| 7.1.4 | Border Router As Router | `Cert_7_1_04_BorderRouterAsRouter` | pass | 6/6 | n3+4 pass | fail / fail |  |
| 7.1.5 | Border Router As Router | `Cert_7_1_05_BorderRouterAsRouter` | pass | 6/6 | n3+4 pass | fail / fail |  |
| 7.1.6 | Border Router As Leader | `Cert_7_1_06_BorderRouterAsLeader` | pass | 7/7 | n4+5 pass | fail / fail |  |
| 7.1.7 | Border Router As Leader | `Cert_7_1_07_BorderRouterAsLeader` | pass | 7/7 | n4+5 pass | fail / fail |  |
| 7.1.8 | Border Router As FED | `Cert_7_1_08_BorderRouterAsFED` | pass | 5/5 |  | fail / fail |  |

### 8.x Commissioning, joiner router, commissioner petition

| # | title | script | status | runs passed | MTD build | pktverify (ot / all) | detail |
|---|---|---|---|---|---|---|---|
| 8.1.1 | Commissioning | `Cert_8_1_01_Commissioning` | pass | 4/4 |  | pass / pass |  |
| 8.1.2 | Commissioning | `Cert_8_1_02_Commissioning` | pass | 4/4 |  | fail / fail |  |
| 8.1.6 | Commissioning | `Cert_8_1_06_Commissioning` | pass | 4/4 |  | fail / fail |  |
| 8.2.1 | Joiner Router | `Cert_8_2_01_JoinerRouter` | pass | 5/5 |  | fail / fail |  |
| 8.2.2 | Joiner Router | `Cert_8_2_02_JoinerRouter` | pass | 5/5 |  | fail / fail |  |
| 8.2.5 | Joiner Router | `Cert_8_2_05_JoinerRouter` | pass | 5/5 |  | fail / fail |  |
| 8.3.1 | Commissioner Petition | `Cert_8_3_01_CommissionerPetition` | pass | 4/4 |  | fail / fail |  |

### 9.x Management: dataset get / set, pending dataset, announce, energy scan, PAN ID query

| # | title | script | status | runs passed | MTD build | pktverify (ot / all) | detail |
|---|---|---|---|---|---|---|---|
| 9.2.1 | MGMT Commissioner Get | `Cert_9_2_01_MGMTCommissionerGet` | pass | 4/4 |  | fail / fail |  |
| 9.2.2 | MGMT Commissioner Set | `Cert_9_2_02_MGMTCommissionerSet` | pass | 4/4 |  | fail / fail |  |
| 9.2.3 | Active Dataset Get | `Cert_9_2_03_ActiveDatasetGet` | pass | 4/4 |  | fail / fail |  |
| 9.2.4 | Active Dataset | `Cert_9_2_04_ActiveDataset` | pass | 4/4 |  | fail / fail |  |
| 9.2.5 | Active Dataset | `Cert_9_2_05_ActiveDataset` | pass | 4/4 |  | fail / fail |  |
| 9.2.6 | Dataset Dissemination | `Cert_9_2_06_DatasetDissemination` | pass | 7/7 | n4+5 pass | fail / fail |  |
| 9.2.7 | Delay Timer | `Cert_9_2_07_DelayTimer` | pass | 5/5 |  | fail / fail |  |
| 9.2.8 | Persistent Datasets | `Cert_9_2_08_PersistentDatasets` | partial | 3/5 |  | fail / fail | fails: n3, all; known, being fixed |
| 9.2.9 | Pending Partition | `Cert_9_2_09_PendingPartition` | partial | 4/6 |  | fail / fail | fails: n3, all; known, being fixed |
| 9.2.10 | Pending Partition | `Cert_9_2_10_PendingPartition` | pass | 7/7 | n4+5 pass | fail / fail |  |
| 9.2.11 | Network Key | `Cert_9_2_11_NetworkKey` | partial | 3/7 | n4+5 pass | fail / fail | fails: n1, n2, n3, all; known, being fixed |
| 9.2.12 | Announce | `Cert_9_2_12_Announce` | partial | 2/6 | n4 pass | pass / fail | fails: n1, n2, n3, all; known, being fixed |
| 9.2.13 | Energy Scan | `Cert_9_2_13_EnergyScan` | partial | 2/6 |  | fail / fail | fails: n1, n3, n4, all; known, being fixed |
| 9.2.14 | Pan Id Query | `Cert_9_2_14_PanIdQuery` | partial | 3/6 |  | fail / fail | fails: n1, n3, all; known, being fixed |
| 9.2.15 | Pending Partition | `Cert_9_2_15_PendingPartition` | pass | 6/6 |  | pass / pass |  |
| 9.2.16 | Active Pending Partition | `Cert_9_2_16_ActivePendingPartition` | pass | 6/6 |  | pass / pass |  |
| 9.2.17 | Orphan | `Cert_9_2_17_Orphan` | pass | 5/5 | n3 pass | pass / fail |  |
| 9.2.18 | Roll Back Active Timestamp | `Cert_9_2_18_RollBackActiveTimestamp` | fail | 1/7 | n4+5 FAIL | fail / fail | fails: n1, n2, n3, n4, n5, all; known, being fixed (fails in every role and with the MTD build) |
| 9.2.19 | Pending Dataset Get | `Cert_9_2_19_PendingDatasetGet` | pass | 4/4 |  | fail / fail |  |

### LowPower (Thread 1.2): SSED attach, link metrics, forward tracking, 1.2 router

| # | title | script | status | runs passed | MTD build | pktverify (ot / all) | detail |
|---|---|---|---|---|---|---|---|
| 5.1.1 (v1.2 router) | Router attach (Thread 1.2 variant) | `v1_2_router_5_1_1` | pass | 4/4 |  | pass / pass |  |
| LowPower 5.3.1 | SSED Attachment | `v1_2_LowPower_5_3_01_SSEDAttachment` | pass | 5/5 | n3 pass | pass / fail |  |
| LowPower 6.1.7 | Preferring A Router Over A Reed | `v1_2_LowPower_6_1_07_PreferringARouterOverAReed` | pass | 6/6 | n4 pass | fail / fail |  |
| LowPower 7.1.1 | Single Probe Link Metrics With Enhanced Acks | `v1_2_LowPower_7_1_01_SingleProbeLinkMetricsWithEnhancedAcks` | partial | 2/5 |  |  | fails: n2, n3, all; `linkmetrics` CLI commands missing in opentrust-cli (`Error 35: InvalidCommand`); the Leader (node 1) side works |
| LowPower 7.1.2 | Single Probe Link Metrics Without Enhanced Ack | `v1_2_LowPower_7_1_02_SingleProbeLinkMetricsWithoutEnhancedAck` | partial | 2/5 |  |  | fails: n2, n3, all; same cause as LowPower 7.1.1 |
| LowPower 7.2.1 | Forward Tracking Series | `v1_2_LowPower_7_2_01_ForwardTrackingSeries` | fail | 1/5 |  |  | fails: n1, n2, n3, all; forward tracking series not registered (`No matching series ID`) / `linkmetrics` CLI missing |


## Not runnable in the simulation harness (NA)

These scripts need the OTBR / Docker / backbone (`PORT_OFFSET`, `ot-br-posix` containers, a
simulated infrastructure link, `radvd`, `dnsmasq`, TREL, `dbus`) which are hardware or host networking
dependent; the harness does not start them. They are test-plan cases (Backbone / MATN / BBR, Thread 1.2 and
later) or OpenThread functional tests of the border router.

| script(s) | test-plan # | reason |
|---|---|---|
| `backbone/bbr_5_11_01.py` | BBR 5.11.1 | needs the backbone link, `OT_BACKBONE_ROUTER` and a real BBR container |
| `border_router/MATN/MATN_02, 03, 04, 05, 09, 12, 15, 16` | MATN 02, 03, 04, 05, 09, 12, 15, 16 | multicast across the backbone: BBR, backbone link, `radvd` |
| `border_router/LowPower/v1_2_LowPower_5_3_01_SSEDAttachment_BR, 7_1_01_..._BR, 7_2_01_..._BR` | LowPower 5.3.1 / 7.1.1 / 7.2.1 with a BR as parent | OTBR docker topology (the non-BR versions are in the LowPower table) |
| `backbone/test_*` (bmlr, dua_dad, dua_routing, dua_routing_med, mle_must_not_send_icmpv6_destination_unreachable, mlr_multicast_routing x4, ndproxy) | functional | backbone link + BBR |
| `border_router/internet/test_*` (dhcp6pd, multi_border_routers, single_border_router, upstream_dns, with_infrastructure_prefix) | functional | infrastructure interface, DHCPv6-PD / upstream DNS |
| `border_router/test_*` (advertising_proxy, border_router_as_fed, dnssd_*, end_device_udp_reachability, external_route, firewall, manual_*, mdns_restart, multi_ail, multi_border_routers, multi_thread_networks, on_link_prefix, plat_udp_accessiblity, publish_meshcop_service, radvd_coexist, rcp_radio_version, single_border_router, srp_register_500_services_br, trel_connectivity) | functional | OTBR (`ot-br-posix`) container, infrastructure link, mDNS / radvd, TREL, RCP |

Not scripts of the test plan: `addon_test_channel_manager_autocsl.py` (functional, below),
`Test_Cli.py` and the `common`/`node`/`simulator` libraries.

## OpenThread functional tests (`test_*.py`, `v1_2_test_*.py`)

These are not test-plan cases; they exercise OpenThread features. Run with `ot,all` only
(timeout 120 s each). **fail** here means the all-OpenTrust run fails, **baseline-fail** the all-OpenThread run.

| area | scripts | pass | partial | fail | baseline-fail | NA |
|---|---|---|---|---|---|---|
| SRP | 15 | 0 | 0 | 14 | 1 | 0 |
| DNS / DNS-SD | 3 | 0 | 0 | 3 | 0 | 0 |
| CoAP / CoAPS | 4 | 2 | 0 | 1 | 0 | 1 |
| Backbone router / DUA / MLR (Thread 1.2) | 7 | 3 | 4 | 0 | 0 | 0 |
| CSL | 2 | 1 | 0 | 0 | 1 | 0 |
| Link metrics / enhanced ack (Thread 1.2) | 5 | 0 | 3 | 2 | 0 | 0 |
| Python unit tests of the cert libraries (no nodes) | 8 | 0 | 0 | 0 | 0 | 8 |
| Other (routing, MLE, ping, network data, diagnostics, ...) | 32 | 21 | 0 | 10 | 1 | 0 |

#### SRP

| script | status | runs passed | detail |
|---|---|---|---|
| `test_srp_auto_host_address` | fail | 1/2 | fails: all |
| `test_srp_auto_start_mode` | fail | 1/2 | fails: all |
| `test_srp_client_change_lease` | fail | 1/2 | fails: all |
| `test_srp_client_remove_host` | fail | 1/2 | fails: all |
| `test_srp_client_save_server_info` | fail | 1/2 | fails: all |
| `test_srp_lease` | fail | 1/2 | fails: all |
| `test_srp_many_services_mtu_check` | fail | 1/2 | fails: all |
| `test_srp_name_conflicts` | fail | 1/2 | fails: all |
| `test_srp_register_500_services` | baseline-fail | 0/2 | all-OT: FAIL FAILED (failures=1); baseline: failed / timed out at the 120 s limit |
| `test_srp_register_services_diff_lease` | fail | 1/2 | fails: all |
| `test_srp_register_single_service` | fail | 1/2 | fails: all |
| `test_srp_server_anycast_mode` | fail | 1/2 | fails: all |
| `test_srp_server_reboot_port` | fail | 1/2 | fails: all |
| `test_srp_sub_type` | fail | 1/2 | fails: all |
| `test_srp_ttl` | fail | 1/2 | fails: all |

#### DNS / DNS-SD

| script | status | runs passed | detail |
|---|---|---|---|
| `test_dns_client_config_auto_start` | fail | 1/2 | fails: all; `Error 7: InvalidArgs` from the `dns` CLI |
| `test_dnssd` | fail | 1/2 | fails: all |
| `test_dnssd_name_with_special_chars` | fail | 1/2 | fails: all |

#### CoAP / CoAPS

| script | status | runs passed | detail |
|---|---|---|---|
| `test_coap` | NA | 2/2 | Python unit test, no simulated nodes |
| `test_coap_block` | pass | 2/2 |  |
| `test_coap_observe` | pass | 2/2 |  |
| `test_coaps` | fail | 1/2 | fails: all |

#### Backbone router / DUA / MLR (Thread 1.2)

| script | status | runs passed | detail |
|---|---|---|---|
| `test_pbbr_aloc` | pass | 5/5 | all-OT, each, all pass |
| `v1_2_test_backbone_router_service` | pass | 6/6 | all-OT, each, all pass |
| `v1_2_test_domain_unicast_address` | partial | 5/7 | each node 5 (SED with a Thread 1.1 parent) and all: the BBR cannot ping its DUA (registration through the BBR service ALOC works, `v1_2_test_domain_unicast_address_registration` passes) |
| `v1_2_test_domain_unicast_address_registration` | pass | 11/11 | all-OT, each, all pass |
| `v1_2_test_dua_handle_address_error` | partial | 5/6 | each passes; `all` not rerun after the FTD-child all-routers fix (a run before it failed pinging the FED DUA) |
| `v1_2_test_multicast_listener_registration` | partial | 5/10 | all-OT passes; the commissioner role (`mlr reg`, Commissioner Session ID / Timeout TLVs) is not implemented, so each node 1, 3, 5, 6 and all fail |
| `v1_2_test_multicast_registration` | pass | 10/10 | all-OT, each, all pass |

#### CSL

| script | status | runs passed | detail |
|---|---|---|---|
| `addon_test_channel_manager_autocsl` | baseline-fail | 0/2 | all-OT: TIMEOUT ValueError: MAC check failed; baseline timeout at the 120 s limit; OpenTrust: `Error 7: InvalidArgs` (no channel manager) |
| `v1_2_test_csl_transmission` | pass | 4/4 | CSL transmission passes with every node OpenTrust |

#### Link metrics / enhanced ack (Thread 1.2)

| script | status | runs passed | detail |
|---|---|---|---|
| `v1_2_LowPower_test_forward_tracking_series` | partial | 2/4 | fails: n2, all; link metrics (CLI missing) |
| `v1_2_LowPower_test_link_metrics_manager` | partial | 3/5 | fails: n1, all; link metrics manager / `linkmetrics` CLI missing |
| `v1_2_test_enhanced_frame_pending` | pass | 4/4 | child timeout is refreshed by data frames (enhanced keep-alive) |
| `v1_2_test_enhanced_keep_alive` | pass | 4/4 | parent and child side of the enhanced keep-alive |
| `v1_2_test_single_probe` | pass | 4/4 | `linkmetrics` initiator CLI; extended MAC addresses for indirect link-local frames |

#### Python unit tests of the cert libraries (no nodes)

| script | status | runs passed | detail |
|---|---|---|---|
| `test_common` | NA | 2/2 | Python unit test, no simulated nodes |
| `test_crypto` | NA | 2/2 | Python unit test, no simulated nodes |
| `test_ipv6` | NA | 2/2 | Python unit test, no simulated nodes |
| `test_lowpan` | NA | 2/2 | Python unit test, no simulated nodes |
| `test_mac802154` | NA | 2/2 | Python unit test, no simulated nodes |
| `test_mle` | NA | 2/2 | Python unit test, no simulated nodes |
| `test_network_data` | NA | 2/2 | Python unit test, no simulated nodes |
| `test_network_layer` | NA | 2/2 | Python unit test, no simulated nodes |

#### Other (routing, MLE, ping, network data, diagnostics, ...)

| script | status | runs passed | detail |
|---|---|---|---|
| `test_anycast` | pass | 2/2 | Neighbor Discovery agent ALOC |
| `test_anycast_locator` | pass | 2/2 | `locate` CLI and anycast locate API |
| `test_br_upgrade_router_role` | fail | 1/2 | fails: all; child does not upgrade to router (`child` != `router`) |
| `test_child_supervision` | pass | 2/2 | secured empty frames, polls do not reset the supervision interval, failure counter kept across a detach, child table columns |
| `test_dataset_updater` | pass | 2/2 | `dataset updater start|cancel`, 30 s default delay as OT |
| `test_detach` | fail | 1/2 | fails: all; router stays `detached` (`detached` != `router`) |
| `test_diag` | fail | 1/2 | fails: all; `diag` CLI missing |
| `test_history_tracker` | fail | 1/2 | fails: all; `Error 35: InvalidCommand` (history CLI missing) |
| `test_inform_previous_parent_on_reattach` | fail | 1/2 | fails: all; old parent still lists the child |
| `test_ipv6_fragmentation` | fail | 1/2 | fails: all; timeout (large ping / fragmentation path) |
| `test_ipv6_source_selection` | pass | 2/2 |  |
| `test_key_rotation_and_key_guard_time` | pass | 2/2 | Dataset Updater; minimum key rotation time 2 as OT |
| `test_leader_reboot_multiple_link_request` | pass | 2/2 |  |
| `test_mac_scan` | pass | 2/2 |  |
| `test_mle_msg_key_seq_jump` | pass | 2/2 | reestablish link with a child, key sequence stored while disabled |
| `test_netdata_publisher` | fail | 1/2 | fails: all |
| `test_on_mesh_prefix` | pass | 2/2 |  |
| `test_ping` | pass | 2/2 |  |
| `test_ping_lla_src` | pass | 2/2 |  |
| `test_radio_filter` | pass | 2/2 | `radiofilter` CLI, filter in the instance |
| `test_reed_address_solicit_rejected` | pass | 2/2 | `service add|remove` CLI |
| `test_reset` | pass | 2/2 |  |
| `test_route_table` | fail | 1/2 | fails: all; route table differs from the expected set |
| `test_router_downgrade_on_sec_policy_change` | pass | 2/2 |  |
| `test_router_multicast_link_request` | pass | 2/2 |  |
| `test_router_reattach` | pass | 2/2 |  |
| `test_router_reboot_multiple_link_request` | pass | 2/2 |  |
| `test_router_upgrade` | pass | 2/2 |  |
| `test_service` | pass | 2/2 | `service add|remove` CLI, Neighbor Discovery agent ALOC, echo reply to an own address |
| `test_set_mliid` | pass | 2/2 |  |
| `test_zero_len_external_route` | pass | 2/2 |  |
| `v1_2_test_parent_selection` | baseline-fail | 0/9 | all-OT: FAIL FAILED (failures=1); baseline failure of the case itself (assertion in the script with `ot-cli-ftd`) |


## pktverify (packet verification with tshark 4.6)

`OPENTRUST_CERT_PKTVERIFY=1`, configurations `ot` and `all` only, 105 cases (the cases of the tables above
without the functional tests). The "pktverify (ot / all)" column is the result of the all-OpenThread run /
the all-OpenTrust run. The CLI based status is the authoritative column: with `tshark` 4.6.x the dissection
differs from the Wireshark version the `pktverify` checks were written for, so a failure in both
columns is the tooling (63 cases fail with OpenThread nodes too).

- Pass with both implementations (23): 5.1.7 to 5.1.11, 5.1.13, 5.2.7, 5.3.6, 5.5.1, 5.5.4, 5.5.5, 5.5.7,
  5.6.7, 6.1.1, 6.1.5, 6.1.6, 6.2.1, 6.3.1, 6.3.2, 8.1.1, 9.2.15, 9.2.16, 5.1.1 (v1.2 router).
- Pass with OpenThread, fail with OpenTrust (15, packet-level differences not analysed): 5.2.4, 5.3.5,
  5.3.8, 5.8.2, 5.8.3, 6.1.3, 6.1.7, 6.2.2, 6.5.1, 6.5.2, 6.6.1, 6.6.2, 9.2.12, 9.2.17, LowPower 5.3.1.
- Fail with OpenThread, pass with OpenTrust (4): 5.1.12, 5.3.1, 6.4.1, 6.5.3 (tool artefacts).
