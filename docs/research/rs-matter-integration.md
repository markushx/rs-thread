# rs-matter / esp-rs/openthread integration research

Purpose: define the API surface rs-thread (`rs-thread-embassy`, `rs-thread-matter`) must offer to be a drop-in
replacement for `esp-rs/openthread` underneath rs-matter.

## Sources and revisions (shallow clones, read-only; build scripts not executed)

| Repo | Commit | Notes |
|---|---|---|
| https://github.com/esp-rs/openthread | `705c5576ccfd7b417cfa4b23912a13b1b99e01f2` | `openthread` crate 0.4.0 + "Unreleased" section in `openthread/CHANGELOG.md` |
| https://github.com/project-chip/rs-matter | `bf3fe6b94f6428d12611c67fcf698883c269507d` | workspace 0.4.1; `rs-matter-stack` is now in-tree |
| https://github.com/sysgrok/rs-matter-embassy | `165534170a48e86a96a659ba9e5162be1ce0e927` | crate `rs-matter-embassy` 0.1.0 (README badges still point at the old `ivmarkov/` location; the Cargo `repository` is `sysgrok/`) |
| https://github.com/sysgrok/edge-net | `2b12b3b1900287a7b0f1f95f5fd66be6672621f9` | only for `edge-nal-openthread` (found via the `rs-matter-embassy` Cargo deps) |

Clones live in the session scratchpad (`.../scratchpad/research/`), not in the repo. Paths below are relative to each repo root.

Key architectural finding: the glue is **three layers**, and rs-thread must replace the middle one:

```
rs-matter  (+ rs-matter-stack, in-tree)      <- defines NetStack/NetSocket/Mdns/NetCtl/ThreadDiag/Icd/GattPeripheral
   ^
rs-matter-embassy  src/ot.rs, src/nal.rs, src/wireless/thread.rs   <- adapts `openthread` crate to those traits
   ^
edge-nal-openthread (edge-net repo)           <- thin edge-nal UdpBind/UdpSocket shim over openthread::UdpSocket
   ^
openthread (esp-rs)  -> openthread-sys (C OpenThread)
```

---

## 1. esp-rs/openthread

### 1.1 Crate layout
Workspace (`Cargo.toml`): members `openthread`, `openthread-sys`, `examples/std`; excluded `examples/esp`, `examples/nrf`, `xtask`, `tests`.

- `openthread/` (v0.4.0, edition 2021, rust-version 1.85): safe async wrapper. Modules in `openthread/src/`:
  `lib.rs` (4385 lines; `OpenThread`, `OtResources`, `OtContext`), `radio.rs` + `radio/{esp,nrf,mac,proxy,spinel}.rs`, `settings.rs`, `udp.rs`,
  `srp.rs`, `dns.rs`, `dataset.rs`, `scan.rs`, `netdata.rs`, `ping.rs`, `joiner.rs`, `nat64.rs`, `cli.rs`, `enet.rs` (embassy-net driver), `platform.rs`, `signal.rs`.
- `openthread-sys/`: bindgen bindings + vendored C OpenThread, pre-compiled libs for `riscv32imac-unknown-none-elf`, `thumbv7em-none-eabi`, `thumbv6m-none-eabi`.
- Deps: `embassy-sync 0.8`, `embassy-time 0.5`, `embassy-futures`, `heapless 0.9`, `rand_core 0.10`, optional `embassy-net-driver-channel`, `embedded-hal(-async)`, `embedded-io-async`.

### 1.2 Public API / how it is driven
- Single handle type `OpenThread<'a>` (`lib.rs:153`), cheaply `Clone`, backed by `&'a RefCell<OtState>`. Only **one instance per firmware** (`OT_REFCNT`; second `new` returns `OT_ERROR_NO_BUFS`).
- Static memory model: caller supplies `OtResources` (+ `OtUdpResources<N_SOCKETS, RX_SZ>` + `OtSrpResources<N_SVCS, BUF_SZ>`). No alloc needed by the Rust side (OpenThread C keeps its own internal heap; see `heap-*` features).
- Constructors (`lib.rs:252-411`):
```rust
pub fn new(ieee_eui64: [u8; 8], radio_caps: &RadioCaps, rng: &'a mut dyn OtRng,
           settings: &'a mut dyn Settings, resources: &'a mut OtResources) -> Result<Self, OtError>;
pub fn new_with_udp<const UDP_SOCKETS: usize, const UDP_RX_SZ: usize>(/* + udp: &'a mut OtUdpResources<..> */);
pub fn new_with_srp<const SRP_SVCS: usize, const SRP_BUF_SZ: usize>(/* + srp: &'a mut OtSrpResources<..> */);
pub fn new_with_udp_srp<..>(/* both */);
```
  `radio_caps` must come from a prior `Radio::init().await` (OpenThread reads the caps only once at construction).
- **Driving**: a single async runner future, `pub async fn run<R: Radio>(&self, radio: R) -> !` (`lib.rs:1350`). It internally `select`s
  `run_radio`, `run_alarm` (embassy-time) and `run_tasklets` (otTaskletsProcess). Not spawned by the crate; the caller polls it in its own task/select.
  `pub async fn wait_changed(&self)` is a state-change notification (single waker; do not call from multiple tasks).
- Control surface (all sync `&self` methods unless stated): `enable_ipv6`, `enable_thread`, `set_active_dataset_tlv(&[u8])`, `set_pending_dataset*`,
  `create_new_network_dataset`, `scan(Channels, ms, FnMut(Option<ScanResult>)).await`, `energy_scan(..).await`, `net_status()`, `device_role()`,
  `set_link_mode(rx_on_when_idle, device_type_ftd, full_network_data)`, `set_poll_period`, `set_child_timeout`, `set_csl_period`, `set_csl_timeout`,
  `set_child_supervision_*`, `join_multicast/leave_multicast`, `ipv6_addrs(FnMut)`, `neighbor_table(FnMut)`, `route_table(FnMut)`, `mac_counters()`, `mle_counters()`,
  `ip_counters()`, `detach_gracefully().await`, `with_instance(|*mut otInstance| ..)` (raw escape hatch), raw `rx/tx` for IP packets (`rx(&mut [u8])`, `tx(&[u8])`).
- `OtError(otError)` is the error type; wraps the C code.
- Optional: `enet::new(ot, &mut EnetDriverState) -> (StateRunner, EnetRunner, EnetDriver)` for `embassy-net` (`openthread/src/enet.rs`).
- Also: Joiner, Commissioner (feature), DNS client (`dns_browse`, `dns_resolve_service`, `dns_resolve_address`, ...), ping sender, NAT64, CLI.

### 1.3 `Radio` trait (exact; `openthread/src/radio.rs:672`)
All methods are `async fn` in trait (native AFIT; not `Send`-bounded in the trait itself).
```rust
pub trait Radio {
    type Error: RadioError;                       // RadioError: Debug { fn kind(&self) -> RadioErrorKind }

    async fn init(&mut self) -> Result<RadioCaps, Self::Error>;
    async fn set_config(&mut self, config: &Config) -> Result<(), Self::Error>;
    async fn set_src_match_config(&mut self, config: &SrcMatchConfig) -> Result<(), Self::Error>;
    async fn set_receive(&mut self, channel: u8) -> Result<(), Self::Error>;
    async fn set_receive_at(&mut self, channel: u8, start_us: u64, duration_us: u32) -> Result<(), Self::Error> { /* default: warn, Ok */ }
    async fn set_sleep(&mut self) -> Result<(), Self::Error>;
    async fn set_csl(&mut self, csl: &CslConfig) -> Result<(), Self::Error> { Ok(()) }
    async fn set_mac_keys(&mut self, keys: Option<&MacKeys>) -> Result<(), Self::Error> { Ok(()) }
    async fn set_mac_frame_counter(&mut self, frame_counter: u32, if_larger: bool) -> Result<(), Self::Error> { Ok(()) }
    async fn energy_scan(&mut self, channel: u8, duration_millis: u16) -> Result<i8, Self::Error> { /* default: OT_RADIO_RSSI_INVALID */ }
    async fn transmit(&mut self, psdu: &mut [u8], psdu_tx: &mut PsduTxInfo, channel: u8, power: i8,
                      cca_threshold: Option<i8>, ack_psdu_buf: Option<&mut [u8]>) -> Result<Option<PsduRxInfo>, Self::Error>;
    async fn receive(&mut self, psdu_buf: &mut [u8]) -> Result<PsduRxInfo, Self::Error>;
}
impl<T: Radio> Radio for &mut T { .. }
```
Supporting types (same file):
- `RadioErrorKind { TxInvalid, RxInvalid, RxFailed, TxFailed, TxAckFailed, RxAckFailed, TxAckTimeout, RxAckTimeout, RxAckInvalid, Other }`.
- `RadioCaps { phy: Capabilities, mac: MacCapabilities, receive_sensitivity: i8, default_tx_power: i8, default_cca_threshold: i8 }` plus (per CHANGELOG "Unreleased") `bus_speed`, `bus_latency_us`, and a `clock` (`RadioClock(pub fn() -> u64)`).
- `Capabilities` (bitflags mirroring `otRadioCaps`): `ACK_TIMEOUT, ENERGY_SCAN, TRANSMIT_RETRIES, CSMA_BACKOFF, SLEEP_TO_TX, TRANSMIT_SEC, TRANSMIT_TIMING, RECEIVE_TIMING, AUTO_SLEEP, TRANSMIT_FRAME_POWER, ALT_SHORT_ADDR`.
- `MacCapabilities` (bitflags): `TX_ACK, RX_ACK, PROMISCUOUS, FILTER_PAN_ID, FILTER_SHORT_ADDR, FILTER_EXT_ADDR, SRC_MATCH`; `MacCapabilities::REQUIRED = all()`.
- `Config { auto_sleep, promiscuous, pan_id: Option<u16>, short_addr: Option<u16>, alt_short_addr: Option<u16>, ext_addr: Option<u64> }`.
- `SrcMatchConfig { enabled, short_addrs: heapless::Vec<u16,_>, ext_addrs: heapless::Vec<u64,_> }`.
- `PsduRxInfo { len, channel, rssi: Option<i8>, lqi: Option<u8>, timestamp_us: Option<u64>, ack_security: Option<AckSecurity>, acked_with_frame_pending: Option<bool> }`.
- `PsduTxInfo { security_processed, header_updated, csl_present, retransmission, tx_at_us: Option<u64>, max_csma_backoffs: Option<u8> }`.
- `CslConfig { period, short_addr, ext_addr, sample_time_us }`, `MacKeys { key_id_mode, key_id, prev, curr, next }`, `AckSecurity { frame_counter, key_id }`.

Contract is documented in `openthread/docs/radio-contract.md` and the trait doc: `transmit` is the complete CSMA+TX+ACK-wait sequence and cancellation-safe
(future may be dropped); `receive` must be cancellation-safe and not lose frames received during `transmit`; a sleeping radio drops frames except in `set_receive_at` windows;
MAC (ack, filtering, src-match, retries not required) is emulated in software by `radio::mac::MacRadio` for bare-PHY radios; `radio::proxy::{ProxyRadio, PhyRadioRunner}` runs the PHY in a higher-priority executor.
Provided impls: `EspRadio` (feature `esp-radio`), `NrfRadio` (feature `embassy-nrf`, "with caveats"; README recommends `sysgrok/nrf-802154` instead), `SpinelRadio` (feature `rcp`; UART/SPI/serial transports), `MacRadio`, `ProxyRadio`.

### 1.4 Settings / RNG / timers
- **Settings** (`openthread/src/settings.rs:114`): sync, byte-blob, multi-value-per-key trait (mirrors `otPlatSettings*`):
```rust
pub trait Settings {
    fn init(&mut self, sensitive_keys: &[u16]);
    fn get(&mut self, key: u16, index: usize, buf: &mut [u8]) -> Result<Option<usize>, SettingsError>;
    fn add(&mut self, key: u16, value: &[u8]) -> Result<(), SettingsError>;
    fn remove(&mut self, key: u16, index: Option<usize>) -> Result<bool, SettingsError>;
    fn set(&mut self, key: u16, value: &[u8]) -> Result<(), SettingsError>;
    fn clear(&mut self) -> Result<(), SettingsError>;
    fn deinit(&mut self);
}
```
  Impls: `()`, `&mut T`, `RamSettings<'a, T>` (RAM store over a caller buffer with a change callback/`Signal`), `SharedRamSettings<M, T>` (embassy-sync `Mutex<M, RefCell<..>>`), `SimpleRamSettings`.
  `enum SettingsKey` lists the OT keys. Persistence is *not* in the crate: rs-matter-embassy's `OtPersist` (`rs-matter-embassy/src/ot.rs`) keeps RAM settings, waits for `poll_changed`, and serialises the persisted subset
  (`PERSISTED_SETTINGS` = ActiveDataset, PendingDataset, NetworkInfo, SrpEcdsaKey, SrpClientInfo, ... ) as `[key:u16le][len:u16le][value]*` into one rs-matter `KvBlobStore` blob (key `OT_SETTINGS_KEY`).
- **RNG**: `pub use rand_core::CryptoRng as OtRng;` passed as `&'a mut dyn OtRng` (rand_core **0.10**). Used for OT's `otPlatEntropyGet` and (indirectly) crypto seeding.
- **Timers**: via `embassy-time` (`run_alarm` -> `otPlatAlarmMilli*`; radio clock for micro alarm when the radio advertises one). No timer trait to implement; the application must provide an embassy-time driver.
- **Crypto**: bundled MbedTLS (or `mbedtls-rs-sys` feature to share with rs-matter's `mbedtls` feature). Platform crypto offload not exposed in Rust.
- C libc: user must poly-fill `str*` (`tinyrlibc`).

### 1.5 UDP sockets
`openthread::UdpSocket<'a>` (`udp.rs:17`) is **not** edge-nal itself:
```rust
impl<'a> UdpSocket<'a> {
    pub fn bind(ot: OpenThread<'a>, local: &SocketAddrV6) -> Result<Self, OtError>;
    pub fn connect(ot: OpenThread<'a>, remote: &SocketAddrV6) -> Result<Self, OtError>;
    pub async fn wait_recv_available(&self) -> Result<(), OtError>;
    pub async fn recv(&self, buf: &mut [u8]) -> Result<(usize, SocketAddrV6 /*local*/, SocketAddrV6 /*remote*/), OtError>;
    pub async fn send(&self, data: &[u8], src: Option<&SocketAddrV6>, dst: &SocketAddrV6) -> Result<(), OtError>;
}
```
(multicast join/leave is `OpenThread::join_multicast/leave_multicast`). The edge-nal binding is the separate crate `edge-nal-openthread` 0.3.0 (edge-net repo, `edge-nal-openthread/src/lib.rs`):
`OtUdpStack<'a>(OpenThread<'a>)` implements `edge_nal::{UdpBind, UdpConnect}`; `OtUdpSocket` implements `UdpSend, UdpReceive, Readable, MulticastV4, MulticastV6, UdpSocket, UdpSplit, UdpSplitMulticast` (+ the same for `&OtUdpSocket`). This crate is tiny; rs-thread can supply an equivalent (or have rs-matter-embassy depend on an `rs-thread-*` variant).
Alternative path: `enet` feature gives an `embassy-net` `Device` (IP medium) so smoltcp sockets/`edge-nal-embassy` work; rs-matter-embassy's `OtNetStack` does **not** use it (uses native OT UDP, max 1 socket: `OT_MAX_UDP_SOCKETS = 1`, RX buf = `MAX_RX_PACKET_SIZE`).

### 1.6 SRP client API (feature `srp-client`; `openthread/src/srp.rs`)
```rust
pub struct OtSrpResources<const SRP_SVCS: usize = 3, const SRP_BUF_SZ: usize = 300>;
pub struct SrpConf<'a> { host_name: &'a str, host_addrs: &'a [Ipv6Addr] /* empty = auto */, ttl: u32, default_lease_secs: u32, default_key_lease_secs: u32 }
pub struct SrpService<'a, SI, TI> { /* name, instance_name, port, subtype_labels: SI, txt_entries: TI, priority, weight, lease, key_lease */ }
// OpenThread<'_> methods:
fn srp_conf<F,R>(&self, f: F) -> Result<R, OtError>;  fn srp_set_conf(&self, &SrpConf) -> Result<(), OtError>;
fn srp_autostart(&self) -> Result<(), OtError>;  fn srp_autostart_enabled(&self) -> Result<bool,_>;
fn srp_start(&self, server_addr: SocketAddrV6);  fn srp_stop(&self);  fn srp_running(&self) -> Result<bool,_>;
fn srp_server_addr(&self) -> Result<Option<SocketAddrV6>, OtError>;
fn srp_add_service<'a, SI, TI>(&self, &'a SrpService<'a, SI, TI>) -> Result<SrpServiceSlot, OtError>;   // SI: Iterator<Item=&str>+Clone, TI: Iterator<Item=(&str,&[u8])>+Clone
fn srp_remove_service(&self, SrpServiceSlot, immediate: bool);  fn srp_remove_all(&self, immediate: bool);  fn srp_is_empty(&self);
fn srp_services<F>(&self, f: F);  async fn srp_wait_changed(&self);
```
Also a DNS-SD client over unicast DNS (`dns.rs`: `dns_browse`, `dns_resolve_service[_and_host_address]`, `dns_resolve_address`; feature `dns-client`) used for operational discovery.

### 1.7 How it plugs into rs-matter
Via `rs-matter-embassy` (`rs-matter-embassy/src/ot.rs`, `wireless/thread.rs`, feature `openthread`):
- `OtNetStack<'d>(edge_nal_openthread::OtUdpStack<'d>)` implements rs-matter's `NetStack` (section 2.1) by wrapping the edge-nal socket in `nal::NalSocket`.
- `OtNetif<'d>` implements `NetifDiag` + `NetChangeNotif` (one netif named `"ot"`, `InterfaceTypeEnum::Thread`, hw addr = EUI-64, IPv6 addrs from `ipv6_addrs`).
- `OtNetCtl<'a>` implements `NetCtl` + `NetChangeNotif` + `WirelessDiag` + `ThreadDiag`. `scan` -> `OpenThread::scan(Channels::all(), 500ms, ..)`; `connect(WirelessCreds::Thread{dataset_tlv})` -> `enable_thread(false)`, `set_active_dataset_tlv`, `enable_thread(true)`, poll `net_status().role.is_connected()` with 20 s timeout.
- `OtMdns<'a,'d>` implements `rs_matter_stack::mdns::Mdns` using **SRP client** (register own services) + **OT DNS client** (resolve/browse). Run-loop waits for an SRP server in Network Data (`srp_server_addr().is_some()`), then `srp_remove_all(true)`, `srp_set_conf`, `srp_add_service` per Matter service.
- `OtThreadRunner::run` (wireless/thread.rs): locks `OtNetContext{ IfMutex<OtMatterResources> }`, loads `OtPersist`, `radio.init()`, `OpenThread::new_with_udp_srp(eui64, &caps, &mut rand, &mut settings, ...)`,
  builds the four adapters, then `select4(matter_task, ot.run(radio), persister.run(), run_icd(..))`; `enable_ipv6(true)`, `srp_autostart()`; on exit disables thread/SRP/ipv6.
  Wrapped as `EmbassyThread<'a, PreexistingThreadRadio<R: Radio, B: bt_hci Controller>, K: KvBlobStoreAccess, C: CryptoRng+Copy>` implementing rs-matter-stack `ThreadDriver` / `ThreadCoexDriver` / `GattDriver`; stack type `EmbassyThreadMatterStack<'a, B, E, S>`.
- ICD: `EmbassyThread::with_icd(&Icd)`; `configure_sed` -> `set_link_mode(false,false,false)`, `set_poll_period`, `set_child_timeout`, `set_child_supervision_*`; CSL branch uses `set_csl_period` (period rounded to 160 us units, max `OpenThread::CSL_MAX_PERIOD_US`) and `CSL_SYNC_POLL_PERIOD_MS = 10_000`.

### 1.8 Features
Cargo features (`openthread/Cargo.toml`): default `["matter"]` (= `srp-client`, `dns-client`, `ping-sender`); `ftd` (off = MTD, default), `rcp` (remote radio via Spinel), `std`, `udp`, `cli`,
`joiner`, `commissioner`, `border-router`, `border-routing`, `csl-receiver`, `link-metrics-*`, `child-supervision`, `mac-filter`, `jam-detection`, `netdiag-client`, `mesh-diag`, `ecdsa`, `trel`, `heap-ext-ot`, `heap-ext-mbedtls`, `heap-int-<N>`, `mbedtls-rs-sys`, `esp-radio`, `embassy-nrf`, `defmt`/`log`.
README claims: Thread 1.4 compatibility; MTD and FTD; SED "(but no CSL yet)" - **but** `CHANGELOG.md` "Unreleased" lists breaking CSL (SSED receiver) support and the `Radio` trait already carries `set_csl`/`set_receive_at`; `ftd` always compiles the CSL transmitter. (README is stale; treat CSL as landed-unreleased at this commit.) Border Router is a stated non-goal (although `border-router` features exist in `-sys`). No TCAT in the Rust API (only a `-sys` Cargo comment about cert-based DTLS "TCAT / ECDHE-ECDSA" opt-in).
Hardware: ESP32-C6/H2 (esp-radio), nRF52840 and nRF54L10/15 (via `nrf-802154`). Tests: upstream OT E2E + expect tests with virtual time under `tests/`.
License: `MIT OR Apache-2.0` (LICENSE-MIT + LICENSE-APACHE). OpenThread C itself is BSD-3-Clause (in `-sys`).

---

## 2. rs-matter

Workspace v0.4.1, `edition = "2021"`, `rust-version = "1.92"`, license **Apache-2.0** (note: `rs-matter-embassy`, `edge-nal-openthread`, `openthread` are `MIT OR Apache-2.0`).
Crates are now split: `rs-matter-transport`, `rs-matter-dm`, `rs-matter-dm-core`, `rs-matter-dm-clusters`, `rs-matter-stack`, `rs-matter-utils`, `rs-matter-crypto`, etc.; facade `rs-matter`.

### 2.1 Networking traits
rs-matter itself does **not** use edge-nal traits. The core transport takes `NetworkSend`/`NetworkReceive` (`rs-matter-transport/src/network.rs:277-343`); `rs-matter-stack` adds a socket-factory layer (`rs-matter-stack/src/net.rs`).
`rs-matter-embassy/src/nal.rs` adapts edge-nal sockets (`NalSocket<S: UdpSplitMulticast>`) to these.
```rust
// rs_matter_transport::network  (MaybeSend = Send only under feature `send-sync`, otherwise empty)
pub trait NetworkSend: MaybeSend {
    fn send_to(&mut self, data: &[u8], addr: Address) -> impl Future<Output = Result<(), Error>> + MaybeSend;
}
pub trait NetworkReceive: MaybeSend {
    fn wait_available(&mut self) -> impl Future<Output = Result<(), Error>> + MaybeSend;
    fn recv_from(&mut self, buffer: &mut [u8]) -> impl Future<Output = Result<(usize, Address), Error>> + MaybeSend;
}
pub trait NetworkMulticast: MaybeSend {
    fn join(&mut self, addr: IpAddr) -> impl Future<Output = Result<(), Error>> + MaybeSend;
    fn leave(&mut self, addr: IpAddr) -> impl Future<Output = Result<(), Error>> + MaybeSend;
}
pub enum Address { Udp(SocketAddr), Tcp(SocketAddr), Btp(BtAddr) }

// rs_matter_stack::net
pub trait NetStack: MaybeSendSync {
    type Socket<'a>: NetSocket where Self: 'a;
    fn bind(&self, addr: SocketAddr, ipv4_interface: Ipv4Addr, ipv6_interface: u32)
        -> impl Future<Output = Result<Self::Socket<'_>, Error>> + MaybeSend;
}
pub trait NetSocket: MaybeSend {
    type Send<'a>: NetworkSend where Self: 'a;
    type Receive<'a>: NetworkReceive where Self: 'a;
    type Multicast<'a>: NetworkMulticast where Self: 'a;
    fn split(&mut self) -> (Self::Send<'_>, Self::Receive<'_>, Self::Multicast<'_>);
}
```
Matter binds UDP/5540 on `[::]`; mDNS (builtin) binds UDP/5353 and joins `ff02::fb`. On Thread only 1 socket is allocated in the OT adapter, so the Thread path must not use the builtin mDNS responder (see 2.2).

### 2.2 mDNS / DNS-SD vs SRP
Abstracted by one trait in `rs-matter-stack/src/mdns.rs`; the *whole* advertise/resolve implementation is replaceable:
```rust
pub trait Mdns: MaybeSend {
    fn run<C, S>(&mut self, matter: &Matter<'_>, crypto: &C, net_stack: &S,
                 mac: &[u8], ipv4: Ipv4Addr, ipv6: &[Ipv6Addr], interface: u32)
        -> impl Future<Output = Result<(), Error>> + MaybeSend
    where C: Crypto, S: NetStack;
}
```
`BuiltinMdns` (rs-matter's own responder over `NetStack`) is the default for Wi-Fi/Ethernet. For Thread, `OtMdns` ignores `net_stack` and drives SRP + DNS client directly, using rs-matter types
`MatterLocalService`, `MatterRemoteService`, `MdnsRemoteService`, `MdnsTxt`, `DottedName` and `MdnsResponder`/`Matter` hooks (`rs-matter-embassy/src/ot.rs`). Only the **SRP client** + a unicast **DNS client** (for operational discovery of peers / CASE initiation; can be dropped with feature `case-responder-only`) are needed from the Thread stack. An SRP *server* is not needed (border router provides it).

### 2.3 Thread Network Commissioning backend
In `rs-matter-dm/src/clusters/net_comm.rs:358`:
```rust
pub trait NetCtl: MaybeSendSync {
    fn net_type(&self) -> NetworkType;                         // NetworkType::Thread
    fn connect_max_time_seconds(&self) -> u8 { 30 }
    fn scan_max_time_seconds(&self) -> u8 { 30 }
    fn supported_wifi_bands<F>(&self, f: F) -> Result<(), Error> where F: FnMut(WiFiBandEnum) -> Result<(), Error> { .. }
    fn supported_thread_features(&self) -> ThreadCapabilitiesBitmap { ThreadCapabilitiesBitmap::empty() }
    fn thread_version(&self) -> u16 { 4 }
    fn set_enabled(&self, enabled: bool) -> Result<(), Error> { /* default: only enabled=true OK */ }
    fn scan<F>(&self, network: Option<&[u8]> /* ext PAN ID */, f: F)
        -> impl Future<Output = Result<(), NetCtlError>> + MaybeSend where F: FnMut(&NetworkScanInfo) -> Result<(), Error> + MaybeSend;
    fn connect(&self, creds: &WirelessCreds) -> impl Future<Output = Result<(), NetCtlError>> + MaybeSend;
}
pub enum NetworkScanInfo<'a> { Wifi{..}, Thread { pan_id: u16, ext_pan_id: u64, network_name: &'a str, channel: u16, version: u8, ext_addr: &'a [u8], rssi: i8, lqi: u8 } }
pub enum WirelessCreds<'a> { Wifi{ ssid, pass }, Thread { dataset_tlv: &'a [u8] } }   // rs-matter-node-core/src/networks.rs
pub enum NetCtlError { NetworkNotFound, UnsupportedSecurity, AuthFailure, OtherConnectionFailure, IpBindFailed, IpV6Failed, Other(Error) }
pub trait NetChangeNotif: MaybeSendSync { fn wait_changed(&self) -> impl Future<Output = ()> + MaybeSend; }   // rs-matter-dm/src/networks.rs:49
```
Matter's add/update network = Operational Dataset as raw **Thread TLV bytes** (AddOrUpdateThreadNetwork); rs-matter stores it (`ThreadNetworks`, persisted in KV store) and calls `connect` at ConnectNetwork. The backend only needs: scan, apply dataset TLV + enable, report connected. Note `supported_thread_features` (e.g. `IS_FULL_THREAD_DEVICE`, `IS_SLEEPY_END_DEVICE_CAPABLE`, ...) is currently left at the default by `OtNetCtl` - a spot rs-thread can do better.

### 2.4 Thread Network Diagnostics data
`rs-matter-dm/src/clusters/thread_diag.rs:236`: `pub trait ThreadDiag: WirelessDiag` (plus `WirelessDiag::connected() -> Result<bool, Error>`), all methods with defaults returning "null"/empty; exact set:
```rust
fn channel(&self) -> Result<Option<u16>, Error>;
fn routing_role(&self) -> Result<Option<RoutingRoleEnum>, Error>;   // Unspecified/Unassigned/SleepyEndDevice/EndDevice/REED/Router/Leader
fn network_name(&self, f: &mut dyn FnMut(Option<&str>) -> Result<(), Error>) -> Result<(), Error>;
fn pan_id(&self) -> Result<Option<u16>, Error>;
fn extended_pan_id(&self) -> Result<Option<u64>, Error>;
fn mesh_local_prefix(&self, f: &mut dyn FnMut(Option<&[u8]>) -> Result<(), Error>) -> Result<(), Error>;  // 1 byte bit-len (64) + 8 prefix bytes
fn neighbor_table(&self, f: &mut dyn FnMut(&NeighborTable) -> Result<(), Error>) -> Result<(), Error>;   // called once per entry
fn route_table(&self, f: &mut dyn FnMut(&RouteTable) -> Result<(), Error>) -> Result<(), Error>;
fn partition_id(&self) -> Result<Option<u32>, Error>;      fn weighting(&self) -> Result<Option<u16>, Error>;
fn data_version(&self) -> Result<Option<u16>, Error>;      fn stable_data_version(&self) -> Result<Option<u16>, Error>;
fn leader_router_id(&self) -> Result<Option<u8>, Error>;   fn ext_address(&self) -> Result<Option<u64>, Error>;
fn rloc_16(&self) -> Result<Option<u16>, Error>;           fn security_policy(&self) -> Result<Option<SecurityPolicy>, Error>; // {rotation_time:u16, flags:u16}
fn channel_page0_mask(&self, f: &mut dyn FnMut(Option<&[u8]>) -> ..) -> Result<(), Error>;
fn operational_dataset_components(&self, f: &mut dyn FnMut(Option<&OperationalDatasetComponents>) -> ..) -> Result<(), Error>;
fn active_network_faults_list(&self, f: &mut dyn FnMut(NetworkFaultEnum) -> ..) -> Result<(), Error>;
fn mac_counters(&self, f: &mut dyn FnMut(Option<&MacCounters>) -> ..) -> Result<(), Error>;
fn mle_counters(&self, f: &mut dyn FnMut(Option<&MleCounters>) -> ..) -> Result<(), Error>;
fn overrun_count(&self) -> Result<u64, Error>;  fn reset_counts(&self) -> Result<(), Error>;
fn active_timestamp(&self) -> Result<Option<u64>, Error>;  fn pending_timestamp(&self) -> Result<Option<u64>, Error>;  fn delay(&self) -> Result<Option<u32>, Error>;
```
Data structs: `NeighborTable { ext_address, age, rloc16, ... }`, `RouteTable { ext_address, rloc16, router_id, ... }`, `MacCounters { tx_total_count, tx_unicast_count, ... }`, `MleCounters { detached_role_count, child_role_count, router_role_count, ... }`
(full field lists: `rs-matter-dm/src/clusters/thread_diag.rs:43-200`; fields mirror Matter ThreadNetworkDiagnostics structs, i.e. the MAC/MLE counters rs-thread must keep anyway for Thread spec §counters).
Also `NetifDiag` (`gen_diag.rs:156`): `fn netifs(&self, f: &mut dyn FnMut(&NetifInfo) -> Result<(), Error>) -> Result<(), Error>` with `NetifInfo { name, operational, offprem_svc_reachable_ipv4/ipv6, hw_addr, ipv4_addrs, ipv6_addrs, netif_type, netif_index }`.

### 2.5 ICD hooks
rs-matter owns the ICD logic (`rs-matter-dm/src/clusters/icd_mgmt.rs`); it exposes network parameters the transport must apply:
```rust
pub struct Icd { .. }   // Icd::new(IcdModeConfig) const; with rs-matter-stack: EmbassyThread::with_icd(&'a Icd)
pub fn Icd::net_params(&self) -> IcdNetParams;
pub struct IcdNetParams { pub power_mode: IcdPowerMode /*Active|Idle*/, pub operating_mode: OperatingModeEnum /*SIT|LIT*/, pub poll_interval_ms: u32, pub max_poll_interval_ms: u32 }
pub struct IcdModeConfig { idle_mode_duration_s, active_mode_duration_ms, active_mode_threshold_ms, user_active_mode_trigger_hint, user_active_mode_trigger_instruction }
consts: STAY_ACTIVE_MAX_MS = 30_000, SIT_SLOW_POLL_MAX_MS = 15_000, DEFAULT_FAST_POLL_MS = 300, DEFAULT_SLOW_POLL_MS = 15_000
```
Reaction side lives in `rs-matter-embassy/src/wireless/thread.rs`: `configure_sed`, `apply_icd_params(ot, &IcdNetParams, csl: bool)`, `run_icd(&ot, Option<&Icd>)` (re-applies on power-mode change, i.e. fast poll while Active, slow poll / CSL while Idle; child timeout = f(max_poll_interval), constants `CHILD_TIMEOUT_DEFAULT_S=240`, `CHILD_TIMEOUT_MARGIN_S=30`, `CHILD_SUPERVISION_INTERVAL_S=129`, `CHILD_SUPERVISION_CHECK_TIMEOUT_DEFAULT_S=190`). So rs-thread needs dynamic, runtime-changeable: rx-on-when-idle, poll period, CSL period/timeout, child timeout, supervision intervals. (LIT also benefits from MLE "Link Metrics" / check-in; no hook exists today beyond these.) Uncertain: exact semantics of `run_icd` - read only the top-level shape.

### 2.6 Async-runtime assumptions / MSRV
- Executor-agnostic. `rs-matter-utils` depends on `embassy-sync`, `embassy-time`, `embassy-futures`, `critical-section`; feature `os` swaps in std. Own `select*`, `Notification`, `IfMutex`, `Timer` wrappers over those.
- Traits use `impl Future + MaybeSend`; `MaybeSend`/`MaybeSendSync` are empty unless feature `send-sync` (work-stealing executors). A no-std rs-thread facade should *not* require `Send` but should be **`Send` when its parts are** so the feature can be flipped (avoid `Rc`/`RefCell` in public futures, or document).
- Fixed-size, in-place initialised (`Init`/`init!`) statics, no heap except ~4 KB for x509 (per README of examples). Futures are bump-allocated in `rs-matter-stack` (`BUMP_SIZE`).
- Time: `rs_matter::utils::timers::{Duration, Instant, Timer}` = embassy-time. Tied to `embassy-time` driver, same as `openthread`.
- Crypto: rs-matter has its own `Crypto` trait (`rs-matter-crypto/src/lib.rs:60`, impls `rustcrypto` / `mbedtls`), `Crypto::Rand<'a>: CryptoRng + Copy`. rs-matter-embassy passes its `CryptoRng + Copy` into the OT runner (rand_core 0.10).
- MSRV: rs-matter **1.92**, rs-matter-embassy **1.92**, edge-nal-openthread 1.88, openthread 1.85. Edition 2021 across all. rs-thread MSRV must be <= 1.92 if it is to be consumed together (and >= what native AFIT needs, 1.75).

---

## 3. BLE commissioning (BTP)

- rs-matter core implements **BTP framing, session and handshake** transport-agnostically (`rs-matter-transport/src/network/btp.rs`, `btp/session`, `btp/gatt`), exposing `Btp` plus constants `MATTER_BLE_SERVICE_UUID16`, `C1_CHARACTERISTIC_UUID`, `C2_CHARACTERISTIC_UUID` and `AdvData`.
  The platform only has to move bytes through GATT: `Btp::process_incoming` on C2 indications, `process_outgoing`/`wait_outgoing` -> GATT write on C1.
- The GATT trait (`rs-matter-stack/src/ble.rs:36`):
```rust
pub trait GattPeripheral: MaybeSend {
    fn run(&mut self, btp: &Btp, service_name: &str, service_adv: &AdvData)
        -> impl Future<Output = Result<(), Error>> + MaybeSend;
}
```
  Built-in impls on hosts: `bluer` (Linux/BlueZ), `zbus` (BlueZ D-Bus), Windows (win32).
- `rs-matter-embassy` provides `GattPeripheral` for MCUs over a `bt_hci::Controller` (`bt-hci 0.10`), with two selectable BLE hosts: **`trouble-host` 0.8** (default, pure Rust, peripheral+gatt only; `src/ble/trouble.rs`, a `#[gatt_server]` with one service and C1 write / C2 indicate characteristics)
  or **`nimble-rs`** (C NimBLE; `src/ble/nimble.rs`; ~10 KB flash / ~3 KB RAM more on ESP32-C6). Controllers: ESP (`esp-radio` `ble`), nRF (`nrf-sdc` SoftDevice Controller + `nrf-mpsl`), RP (cyw43).
- Concurrent BLE + Thread ("coex") is first-class: `ThreadCoexDriver`/`ThreadCoexTask` and `run_coex`, with 15.4 and BLE arbitration done by the *radio driver layer* (`nrf-mpsl` + `nrf-802154` on Nordic, ESP coex in `esp-radio`), not by the Thread stack. README of esp-rs/openthread: `nrf-802154` "supports BLE coex".

**Recommendation: rs-thread owns no BLE/BTP code for Matter commissioning.** Leave GATT/BTP to rs-matter (+ rs-matter-embassy / trouble-host); rs-thread only has to
(a) not assume exclusive ownership of the 802.15.4 radio (the `Radio` trait must tolerate an MPSL-style time-sliced radio: `transmit` may be delayed/fail, `receive` may be interrupted; document in the contract),
(b) work under `run_coex` (Thread run-future must be cancellable and restartable, and `set_sleep` must let BLE use the antenna), and
(c) let the Matter glue apply the dataset received via BLE-based Network Commissioning (`NetCtl::connect`).

**Does Thread 1.4 TCAT change this?** Partly, but not the Matter recommendation. TCAT (Thread Commissioning over BLE/TLS, Thread 1.4) runs a DTLS/TLS-secured command channel, either over BLE (GATT carrying a TLS stream) or over IP (secure CoAP/TCP on the mesh); the *TLS/TCAT command logic* is Thread-spec scope and belongs in rs-thread's `-meshcop`/`-tcat` sans-IO crate
(byte-stream in/out, cert-based ECDHE-ECDSA, TCAT TLVs; use MeshCoP, dataset set/get, diag). Neither rs-matter nor esp-rs/openthread implements TCAT (only a `-sys` Cargo comment mentions cert-based TCAT DTLS as manual opt-in; I found no Rust API), so rs-thread would be the first Rust implementation.
Recommendation: rs-thread owns the **TCAT session engine** (transport-agnostic, `AsyncRead/Write`-like or sans-IO), and ships at most a thin, optional `rs-thread-tcat-ble` adapter implementing the Thread TCAT GATT service on top of `trouble-host` (reusing the same controller as Matter's BTP; must co-exist with it - only one peripheral connection at a time is enabled in rs-matter-embassy: `MAX_CONNECTIONS = 1`). GATT UUIDs and the TCAT BLE framing must be taken from the Thread 1.4 spec (not verified here; marked **uncertain**). Defer the BLE adapter until after the core TCAT engine exists. A Matter-only product never needs TCAT.

---

## 4. Recommendation: API surface for drop-in replacement

### 4.1 Target
`rs-matter-embassy`'s `openthread` feature compiles against exactly this surface of the `openthread` crate (extracted from `src/ot.rs`, `src/wireless/thread.rs`, `src/wireless/thread/{esp_thread,nrf}.rs`, and `edge-nal-openthread`).
rs-thread offers it in `rs-thread-embassy` as a **source-compatible facade** (type/method names and signatures identical), and glues in `rs-thread-matter`.

Two integration options (recommended order):
1. **Compat facade (fastest, zero upstream change)**: `rs-thread-embassy` exposes `OpenThread`, `OtResources`, `OtUdpResources`, `OtSrpResources`, `Radio`, ... with the same names; users swap the dependency (`openthread = { package = "rs-thread-embassy", ... }`), and `rs-matter-embassy`/`edge-nal-openthread` keep working untouched.
2. **Own glue crate `rs-thread-matter`** (long-term, avoids dependence on a facade-shaped API): implements rs-matter-stack `ThreadDriver` / `ThreadCoexDriver` / `NetStack` / `Mdns` / `NetCtl` / `ThreadDiag` / `NetifDiag` / `NetChangeNotif` directly (code analogous to `rs-matter-embassy/src/ot.rs`), so it can skip the edge-nal hop and the `RefCell`-based single instance, and add TCAT/LIT/CSL polish. Ship both; (2) can be a fork-free PR into `rs-matter-embassy` behind a new `opentrust` feature.

### 4.2 Minimum compat surface (names/signatures to mirror from `esp-rs/openthread`)
Types: `OpenThread<'a>` (Clone), `OtResources`, `OtUdpResources<const N, const RX>`, `OtSrpResources<const N, const BUF>`, `OtError`, `NetStatus`, `DeviceRole { Disabled, Detached, Child, Router, Leader, Other(_) }` with `is_connected()`, `Channels` (bitflags), `ScanResult { pan_id, extended_pan_id: u64, network_name: &str, channel, version, ext_address: u64, rssi, lqi }`, `UdpSocket`, `SrpConf`, `SrpService`, `SrpServiceSlot`, `DnsResponse`, `Settings` + `SettingsKey` + `RamSettings` + `SharedRamSettings` + `RamSettingsChange`, `SecurityPolicy`, `OperationalDatasetComponents`, `NeighborInfo`, `RouteInfo`, `MacCounters`, `MleCounters`, `IpCounters`, `Capabilities`, `Radio`.
Methods used by rs-matter-embassy (must exist, same semantics): `new_with_udp_srp`, `run(radio).await -> !`, `wait_changed`, `enable_ipv6`, `enable_thread`, `set_active_dataset_tlv`, `scan`, `net_status`, `is_commissioned`, `device_role`, `rx_on_when_idle`, `channel`, `network_name`, `pan_id`, `mesh_local_prefix`, `partition_id`, `leader_weight`, `net_data_version`, `net_data_stable_version`, `leader_router_id`, `ext_address`, `rloc16`, `supported_channel_mask`, `neighbor_table`, `route_table`, `router_eligible` (ftd), `mac_counters`, `mle_counters`, `ipv6_addrs`, `ieee_eui64`, `set_link_mode`, `set_poll_period`, `set_child_timeout`, `set_csl_period`, `set_child_supervision_*`, `CSL_MAX_PERIOD_US`, all `srp_*`, `dns_browse`, `dns_resolve_service[_and_host_address]`, `dns_resolve_address`, `join_multicast`, `leave_multicast`, `UdpSocket::{bind, connect, wait_recv_available, recv, send}`.
Plus `rs-thread-embassy` additionally exposes a *native* (non-compat) idiomatic API on top of the sans-IO core.

Traits: `Radio` (4.3 below), `Settings` (as above), `OtRng = rand_core::CryptoRng` (rand_core 0.10).

### 4.3 Radio trait: mirror it verbatim, extend additively
- Keep `rs-thread-platform::Radio` **identical** to `openthread::Radio` (same names, same `async fn`s, same `RadioCaps`/`Capabilities`/`MacCapabilities`/`Config`/`SrcMatchConfig`/`PsduTxInfo`/`PsduRxInfo`/`CslConfig`/`MacKeys`/`AckSecurity`, same error trait `RadioError::kind()`), so existing drivers - `nrf-802154` (`features=["openthread"]`), `esp-radio` wrapper `EspRadio`, `SpinelRadio`, `MacRadio`, `ProxyRadio` - work unchanged against rs-thread. Do not split into sync/async variants; sans-IO core sees a narrower internal trait and the embassy layer adapts.
- Since the trait lives in the `openthread` crate, a real "same trait" requires either (a) a shared tiny crate (e.g. `ieee802154-radio`/`thread-radio`) that both depend on - propose upstream - or (b) a blanket adapter `impl<R: openthread::Radio> opentrust::Radio for R` behind an optional `openthread-radio-compat` feature (cost: pulls `openthread` -> `openthread-sys` dependency in the dependency graph; avoid by default). Preferred: (a), fallback: copy the trait and keep a conformance test that the signatures match (CI check against a pinned `openthread` version).
- Adopt the contract in `docs/radio-contract.md` as rs-thread's own radio spec and port `MacRadio`'s software emulation (ack, src-match, filtering, retries) - it is exactly the MAC offload rs-thread Phase 2 needs. Be careful about the `-> !` `run` and cancellation-safety requirements.
- Pay attention to the pending API churn: the CHANGELOG "Unreleased" breaking change (`transmit(&mut psdu, &mut PsduTxInfo, ...)`, `PsduMeta -> PsduRxInfo`, `OpenThread::new*` taking `&RadioCaps`) means mirror the **unreleased HEAD**, not the 0.4.0 release; track upstream.

### 4.4 Storage, RNG, time
- Keep the `Settings` trait shape (sync, key/index/blob, `sensitive_keys` hint) so `OtPersist`'s `RamSettings`+KV persistence is reusable; define rs-thread's own `SettingsKey` numbering to be **compatible with OT key IDs** (it makes dataset migration from an OpenThread-based firmware possible; **uncertain** whether worth the constraint).
- RNG: accept `&mut dyn rand_core::CryptoRng` (0.10).
- Time: embassy-time, nothing else. Core takes `now` as input (sans-IO); the embassy layer owns timers.

### 4.5 `rs-thread-matter` glue (what rs-matter needs, by trait)
| rs-matter trait | rs-thread provider | Backed by |
|---|---|---|
| `rs_matter_stack::net::{NetStack, NetSocket}` + `NetworkSend/Receive/Multicast` | `OtNetStack` | rs-thread UDP sockets (1 socket for Matter port 5540; ideally a few more to avoid re-binding for SRP/DNS later) |
| `rs_matter_stack::mdns::Mdns` | `OtMdns` | SRP client + DNS-SD client (Phase 7/8 in PLAN) |
| `NetCtl` + `NetChangeNotif` | `OtNetCtl` | discovery scan, dataset TLV apply, attach with timeout, role watcher |
| `ThreadDiag` + `WirelessDiag` | `OtNetCtl` | MLE/MAC counters, neighbor/route tables, leader data, dataset components |
| `NetifDiag` + `NetChangeNotif` | `OtNetif` | address list (ML-EID, RLOC, link-local, GUA/ALOC) |
| `ThreadDriver` / `ThreadCoexDriver` | `OtThreadRunner` | `rs-thread::run(radio)` + persist loop + ICD loop |
| `Icd` hooks | `apply_icd_params` | poll period, CSL, child timeout, supervision, link mode |
| `GattPeripheral` | **not ours** | rs-matter-embassy (trouble-host/nimble) |
| `KvBlobStoreAccess` | not ours | rs-matter; rs-thread persists its settings through `Settings` |
Required data/knobs from the Thread core for this table: MAC and MLE counters (all fields of Matter's `MacCounters`/`MleCounters`), neighbor table (ext addr, age, rloc16, link frame counter, mle frame counter, LQI, avg/last RSSI, frame error rate, message error rate, rx-on-when-idle, full-thread-device, full-network-data, is-child), route table (ext addr, rloc16, router id, next hop, path cost, LQI in/out, age, allocated, link established), leader data (partition id, weighting, data versions, leader router id), security policy, dataset component presence flags, active/pending timestamp + delay timer, channel mask, `RoutingRole` mapping (Disabled->Unspecified, Detached->Unassigned, Child: `!rx_on_when_idle`->SleepyEndDevice, router-eligible+ftd->REED, else EndDevice).

### 4.6 Implementation notes / gotchas learned
1. **One-instance rule**: esp-rs/openthread enforces a single `OpenThread`. rs-matter-embassy relies on `OtNetContext` lock to re-create `OpenThread` per `run` (thread driver may be restarted on Wi-Fi/Thread switch). rs-thread should support restart with the same resources (no leaking global state), and ideally multiple instances (simulation).
2. **`run` returns `!`** and is raced against the Matter task via `select4`; dropping it must be safe at any await point.
3. **Network change notification** is one waker (`wait_changed`); rs-matter calls it from `NetChangeNotif` in several tasks (netif + netctl) - rs-thread should use `embassy_sync::signal`/`Watch`/`MultiWakerRegistration` so multiple waiters work.
4. **`NetCtl::scan` is async + callback with borrowed data**; `connect` must time out and return `NetCtlError::OtherConnectionFailure` (rs-matter-embassy uses 20 s, spec failsafe is typically 60 s+).
5. **Memory**: Matter on Thread gets only one UDP socket in the adapter; SRP buffers `OT_SRP_BUF_SZ = 512`, 4 records; OT settings buf 1024 B. Use these as sizing baselines. OpenThread keeps its own C heap and shares MbedTLS with rs-matter (a pain point addressed via `heap-*` features) - rs-thread being pure Rust with a shared `rs_matter::crypto::Crypto`-compatible primitive layer (or RustCrypto, as rs-matter's default) removes this class of problem; consider letting `rs-thread-matter` accept rs-matter's `Crypto` object for AES/CMAC/SHA/ECJPAKE where possible (**uncertain**: rs-matter's `Crypto` trait does not obviously expose AES-CCM*/EC-JPAKE; would need checking `rs-matter-crypto`).
6. **Features to match**: `ftd` vs MTD (`router_eligible`, REED role), `csl-receiver`, `srp-client`, `dns-client`, `ping-sender` (rs-matter-embassy enables only `matter` = srp + dns + ping). `border-router` is out of scope for rs-thread initially (also a non-goal upstream).
7. **Chips** that the downstream ecosystem already targets with this stack: ESP32-C6/H2, nRF52840, nRF54L05/10/15/LM20 (rs-matter-embassy features `nrf52840`, `nrf54l*`). `rs-matter-embassy/src/wireless/thread/nrf.rs` and `esp_thread.rs` contain the board-glue (MPSL, timers) - reuse as-is when rs-thread matches the `Radio` trait.

### 4.7 Test harness hint
`openthread/tests` (excluded workspace member) runs upstream OpenThread E2E + expect tests with a virtual-time lock-step `embassy_executor::raw` executor plus `tests/esp`, `tests/nrf` for HIL. This is the closest existing "OpenThread test framework in cargo" and is directly relevant to the project goal "re-use OpenThread tests via cargo test"; it can be pointed at rs-thread once the compat facade exists. (Not examined in depth; **uncertain** how pluggable it is.)

---

## Summary of uncertainties
- Exact CSL status of esp-rs/openthread (README stale vs CHANGELOG "Unreleased"): treated as landed in HEAD but unreleased.
- Whether TCAT BLE UUIDs/framing and whether any other project has TCAT-over-BLE in Rust: not found; take from Thread 1.4 spec.
- Full field lists of `NeighborTable`/`RouteTable`/`MacCounters`/`MleCounters` only partially quoted; see `rs-matter-dm/src/clusters/thread_diag.rs:43-200`.
- rs-matter `Crypto` trait coverage for Thread primitives (AES-CCM*, EC-JPAKE) unchecked.
- `run_icd` internals read only at a high level.
- rs-matter-embassy repo location is `sysgrok/rs-matter-embassy` (Cargo `repository`), README badges still link to `ivmarkov/`; the org may move again.
