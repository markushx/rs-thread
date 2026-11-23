# OpenThread unit-test port

Inventory of `tests/unit/*.cpp` (OpenThread `tools/openthread-sys/vendor/openthread`) against the Rust tests. Status: **ported** (new test here), **covered** (an earlier test already uses the OT vectors), **N/A** (OT-internal API with no rs-thread counterpart, or out of scope).

11 OT test functions were ported in this pass (marked ported); the rows marked covered were already ported earlier (including all 58 IPHC vectors); N/A rows are explained per row. Two rs-thread bugs were found and fixed (Verhoeff permutation table, minimum version of the preferred anycast SRP entry).

## Crypto (`rs-thread-core::crypto`)

| OT file | OT test | rs-thread test | Status |
|---|---|---|---|
| test_aes.cpp | TestMacBeaconFrame, TestMacCommandFrame, TestInPlaceAesCcmProcessing | `crypto::tests::ccm_ieee802154_*`, `ccm_in_place_openthread`; `rs-thread-mac security::tests::annex_c_*` | covered |
| test_hmac_sha256.cpp | TestSha256, TestHmacSha256 | `sha256_openthread`, `hmac_sha256_openthread*` | covered (the message-chain variants test OT `Message` reads: N/A) |
| test_hkdf_sha256.cpp | TestHkdfSha256 | `hkdf_sha256_openthread_rfc5869` | covered |
| test_pskc.cpp | TestMinimumPassphrase, TestMaximumPassphrase, TestExampleInSpec | `pskc_openthread_min_max_passphrase`, `pskc_spec_8_4_1_2_2` | covered |
| test_ecdsa.cpp | TestEcdsaVector | `ecdsa::tests::test_ecdsa_vector` (RFC 6979 A.2.5: public key, deterministic signature, verify) | ported |
| test_ecdsa.cpp | TestEcdsaKeyGenerationSignAndVerify | `ecdsa::tests::test_ecdsa_key_generation_sign_and_verify` (key generation is the caller's RNG; sign, verify, reject on other digest) | ported |
| test_checksum.cpp | TestVerhoeffChecksum | `rs-thread-meshcop epskc::tests::test_verhoeff_checksum` | ported; exposed a wrong permutation row (fixed) |

## MAC (`rs-thread-mac`)

| OT file | OT test | rs-thread test | Status |
|---|---|---|---|
| test_mac_frame.cpp | TestMacAddress, TestMacHeader | `frame::tests::test_mac_address`, `test_mac_header` | covered |
| test_mac_frame.cpp | TestMacFrameApi | `test_mac_frame_api_*` (imm ACK, data 2015, cmd 2006, cmd 2015) | covered |
| test_mac_frame.cpp | TestMacFrameAckGeneration | `test_mac_frame_ack_generation_imm`, `_enh` | covered |
| test_mac_frame.cpp | TestMacWakeupFrameGeneration, TestMacWakeupFrameDetectionNegative | `test_mac_wakeup_frame_generation`, `_detection_negative` | covered |
| test_mac_frame.cpp | TestMacChannelMask | no `ChannelMask` type: channel masks are `u32` bit sets | N/A |
| test_crc.cpp | TestCrc16, TestCrc32 | `rs-thread-meshcop steering_tests::crc_check_values` (the CRC-16 used by steering data) | covered |
| test_link_quality.cpp | all four | `rs-thread-mle link_quality_tests` | covered |

## 6LoWPAN (`rs-thread-lowpan`)

| OT file | OT test | rs-thread test | Status |
|---|---|---|---|
| test_lowpan.cpp | TestLowpanIphc: all 58 `TestIphcVector` cases (addresses, contexts, multicast, TC/FL, hop limit, UDP NHC, extension headers, IP-in-IP, errors) | `tests::ot_vectors::VECTORS` (compress and decompress, each tagged with its OT test name) | covered |
| test_lowpan.cpp | TestLowpanMeshHeader, TestLowpanFragmentHeader | `tests::frag_tests` | covered |

## MLE, MeshCoP, network data

| OT file | OT test | rs-thread test | Status |
|---|---|---|---|
| test_mle.cpp | TestDefaultDeviceProperties, TestLeaderWeightCalculation | `rs-thread-mle router_config` tests | covered |
| test_dataset.cpp | TestDataset | `rs-thread-meshcop dataset_vector_tests::ot_test_dataset_vector` | covered |
| test_meshcop.cpp | TestSteeringData, TestTimestamp | `steering_tests::steering_data_ot_test`, `timestamp_compare` | covered |
| test_network_name.cpp | TestNetworkName | `rs-thread-core types::tests::test_network_name` | ported (empty name differs, see the differences file) |
| test_network_data.cpp | TestNetworkDataIterator | `rs-thread-mesh netdata::tests::iterator_vector_1..3` | covered |
| test_network_data.cpp | TestNetworkDataFindNextService | no prefix/exact service-data search API on `Local`; services are matched by the callers | N/A |
| test_network_data.cpp | TestNetworkDataDsnSrpServices | `rs-thread-instance dns_srp::ot_vector_tests::test_network_data_dsn_srp_services` | ported (ALOC, sequence number, version, RLOC16; unicast from service data and server data; preferred entry) |
| test_network_data.cpp | TestNetworkDataDsnSrpAnycastSeqNumSelection | `ot_vector_tests::test_network_data_dsn_srp_anycast_seq_num_selection` (15 vectors) | ported; exposed the missing minimum-version step (fixed) |
| test_serial_number.cpp | TestSerialNumber<u8> | `rs-thread-net mpl::tests::test_serial_number_u8` (the serial compare helper used by MPL) | ported |
| test_serial_number.cpp | TestPreference | `netdata::tests::test_preference` (2-bit route preference) | ported |
| test_serial_number.cpp | TestNumUtils, TestSerialNumber<u16/u32> | Rust `min`, `max`, `clamp`, `div_ceil`, `count_ones`; u16/u32 compare only in the SRP lease code | N/A |
| test_tlv.cpp | TestTlv | `rs-thread-core tlv::tests::ot_test_tlv` | covered |
| test_child_table.cpp, test_child.cpp | child table API | OT `ChildTable` iterator filters; rs-thread has its own `ChildTable` with tests in `rs-thread-mle child_tests` | N/A |
| test_multicast_listeners_table.cpp | MLR table | `rs-thread-mesh mlr_tests` own vectors | N/A |

## IPv6, DNS, SRP

| OT file | OT test | rs-thread test | Status |
|---|---|---|---|
| test_ip6_header.cpp | TestIp6Header | `rs-thread-net header::tests::ot_test_ip6_header` | covered |
| test_checksum.cpp | TestUdpMessageChecksum | `rs-thread-net checksum::tests::test_udp_message_checksum` | ported |
| test_checksum.cpp | TestIcmp6MessageChecksum | `checksum::tests::test_icmp6_message_checksum` | ported |
| test_checksum.cpp | TestExampleVector (RFC 1071 example), random compare | `rfc1071_example`, `matches_reference_for_all_sizes` | covered |
| test_checksum.cpp | TestTcp4/Udp4/Icmp4 | no IPv4 stack | N/A |
| test_ip_address.cpp | TestIp6Prefix | `rs-thread-mesh netdata::tests::test_ip6_prefix` (matching and containment) | ported (ordering and `IsLinkLocal()` style prefix helpers: N/A) |
| test_ip_address.cpp | FromString, Tidy, SetPrefix, Ip4*, NAT64 | `core::net` parses and formats addresses | N/A |
| test_ip4_header.cpp, test_nat64.cpp, test_netif.cpp | IPv4 / NAT64 | no NAT64 | N/A (`rs-thread-net netif` tests cover the netif vectors) |
| test_dns.cpp | TestDnsName, TestDnsCompressedName, TestHeaderAndResourceRecords, TestDnsTxtEntry | `rs-thread-dns tests::plain_names_encode_as_ot_vectors`, `compressed_names_as_ot_vectors`, `records_roundtrip`, `txt_vectors` | covered |
| test_dns_client.cpp, test_dso.cpp, test_dnssd_discovery_proxy.cpp, test_mdns.cpp, test_srp_server.cpp, test_srp_adv_proxy.cpp | OT service plumbing (platform DNS-SD, mDNS, heap-based server) | `rs-thread-dns client_tests`, `srp::tests` | N/A |

## Timers, platform, OT-internal utilities

| OT file | Status |
|---|---|
| test_trickle_timer.cpp | covered by `rs-thread-core trickle::tests` (plain and trickle mode, redundancy, min/max interval change) |
| test_timer.cpp | covered by `rs-thread-core timer::tests` for ordering and expiry; the OT alarm-driver cases are N/A |
| test_message.cpp, test_message_queue.cpp, test_priority_queue.cpp, test_pool.cpp, test_heap*.cpp, test_array.cpp, test_linked_list.cpp, test_smart_ptrs.cpp, test_string.cpp, test_data.cpp, test_offset_range.cpp, test_binary_search.cpp, test_frame_builder.cpp, test_macros.cpp, test_toolchain*.c, test_address_sanitizer.cpp, test_util.* | N/A: OT buffer/containers framework; rs-thread uses Rust types (`heapless`, slices, `Writer`) |
| test_cmd_line_parser.cpp, test_url.cpp, test_ncp_*.cpp | N/A: OT CLI/NCP argument parsing (the CLI crate has its own parser tests) |
| test_spinel_*.cpp, test_hdlc.cpp | N/A: Spinel/HDLC are not implemented |
| test_flash.cpp, test_platform.*, test_power_calibration.cpp, test_multipan_rcp_instances.cpp | N/A: platform / radio-driver APIs |
| test_routing_manager.cpp, test_ndproxy_table.cpp, test_link_metrics_manager.cpp, test_tcat.cpp | N/A: border-routing infrastructure and TCAT plumbing without the OT test harness; TCAT is covered by `rs-thread-meshcop tcat_tests` |
