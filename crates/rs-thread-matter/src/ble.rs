//! BLE: the BTP GATT peripheral of Matter commissioning on `trouble-host`.
//!
//! [`TroubleBtpGattPeripheral`] implements rs-matter's
//! `rs_matter::stack::ble::GattPeripheral` (advertise the Matter service
//! 0xFFF6 with its service data, serve the C1 write / C2 indicate
//! characteristics, drive the `Btp` instance) over any `bt-hci` controller,
//! for example the Nordic SoftDevice Controller (`nrf-sdc`).
//!
//! Ported from `rs-matter-embassy` (`rs-matter-embassy/src/ble.rs` and
//! `src/ble/trouble.rs`, <https://github.com/sysgrok/rs-matter-embassy>,
//! MIT OR Apache-2.0, authored by Ivan Markov and contributors, revision
//! 252cc60), adapted to this crate's logging shim and without its
//! `nimble` backend selection. The behaviour is the same.

#![allow(clippy::useless_conversion)] // https://github.com/embassy-rs/trouble/issues/248
#![allow(clippy::needless_borrows_for_generic_args)]
#![allow(
    clippy::large_futures,
    clippy::large_stack_frames,
    missing_debug_implementations
)]

use core::fmt::Debug;
use core::future::Future;
use core::mem::MaybeUninit;
use core::ops::Deref;
use core::pin::pin;

use bt_hci::ControllerToHostPacket;
use bt_hci::cmd::{AsyncCmd, SyncCmd};
use bt_hci::controller::{ControllerCmdAsync, ControllerCmdSync};
use bt_hci::data::{AclPacket, IsoPacket, SyncPacket};
use embedded_io::ErrorType;
use rs_matter::crypto::Rng;
use rs_matter::error::{Error, ErrorCode};
use rs_matter::stack::ble::GattPeripheral;
use rs_matter::transport::network::BtAddr;
use rs_matter::transport::network::btp::{
    AdvData, Btp, C1_CHARACTERISTIC_UUID, C2_CHARACTERISTIC_UUID, MATTER_BLE_SERVICE_UUID16,
};
use rs_matter::utils::futures::{Coalesce, select};
use rs_matter::utils::init::{Init, init};
use rs_matter::utils::storage::Vec;
use rs_matter::utils::sync::{IfMutex, Notification};
use trouble_host::att::{AttClient, AttReq, AttRsp};
use trouble_host::prelude::*;
use trouble_host::{self, BleHostError, HostResources};

use crate::fmt::{log_debug, log_info, log_warn};

/// A newtype allowing to use a bt_hci `&Controller` as a `Controller`
/// A workaround for:
/// https://github.com/embassy-rs/bt-hci/issues/32
pub struct ControllerRef<'a, C>(&'a C);

impl<'a, C> ControllerRef<'a, C> {
    /// Create a new instance.
    pub const fn new(controller: &'a C) -> Self {
        Self(controller)
    }
}

impl<C> ErrorType for ControllerRef<'_, C>
where
    C: ErrorType,
{
    type Error = C::Error;
}

impl<C> bt_hci::controller::Controller for ControllerRef<'_, C>
where
    C: bt_hci::controller::Controller,
{
    type Buffer<'b> = C::Buffer<'b>;

    fn alloc_buf(&self) -> Result<Self::Buffer<'_>, Self::Error> {
        self.0.alloc_buf()
    }

    fn write_acl_data(
        &self,
        packet: &AclPacket<'_>,
    ) -> impl Future<Output = Result<(), Self::Error>> {
        self.0.write_acl_data(packet)
    }

    fn write_sync_data(
        &self,
        packet: &SyncPacket<'_>,
    ) -> impl Future<Output = Result<(), Self::Error>> {
        self.0.write_sync_data(packet)
    }

    fn write_iso_data(
        &self,
        packet: &IsoPacket<'_>,
    ) -> impl Future<Output = Result<(), Self::Error>> {
        self.0.write_iso_data(packet)
    }

    fn read<'a>(
        &self,
        buf: &'a mut Self::Buffer<'_>,
    ) -> impl Future<Output = Result<ControllerToHostPacket<'a>, Self::Error>> {
        self.0.read(buf)
    }
}

impl<C> bt_hci::controller::blocking::Controller for ControllerRef<'_, C>
where
    C: bt_hci::controller::blocking::Controller,
{
    type Buffer<'b> = C::Buffer<'b>;

    fn alloc_buf(&self) -> Result<Self::Buffer<'_>, Self::Error> {
        self.0.alloc_buf()
    }

    fn write_acl_data(&self, packet: &AclPacket<'_>) -> Result<(), Self::Error> {
        self.0.write_acl_data(packet)
    }

    fn write_sync_data(&self, packet: &SyncPacket<'_>) -> Result<(), Self::Error> {
        self.0.write_sync_data(packet)
    }

    fn write_iso_data(&self, packet: &IsoPacket<'_>) -> Result<(), Self::Error> {
        self.0.write_iso_data(packet)
    }

    fn try_write_acl_data(
        &self,
        packet: &AclPacket<'_>,
    ) -> Result<(), bt_hci::controller::blocking::TryError<Self::Error>> {
        self.0.try_write_acl_data(packet)
    }

    fn try_write_sync_data(
        &self,
        packet: &SyncPacket<'_>,
    ) -> Result<(), bt_hci::controller::blocking::TryError<Self::Error>> {
        self.0.try_write_sync_data(packet)
    }

    fn try_write_iso_data(
        &self,
        packet: &IsoPacket<'_>,
    ) -> Result<(), bt_hci::controller::blocking::TryError<Self::Error>> {
        self.0.try_write_iso_data(packet)
    }

    fn read<'a>(
        &self,
        buf: &'a mut Self::Buffer<'_>,
    ) -> Result<ControllerToHostPacket<'a>, Self::Error> {
        self.0.read(buf)
    }

    fn try_read<'a>(
        &self,
        buf: &'a mut Self::Buffer<'_>,
    ) -> Result<ControllerToHostPacket<'a>, bt_hci::controller::blocking::TryError<Self::Error>>
    {
        self.0.try_read(buf)
    }
}

impl<C, Q> ControllerCmdSync<Q> for ControllerRef<'_, C>
where
    C: ControllerCmdSync<Q>,
    Q: SyncCmd + ?Sized,
{
    fn exec(
        &self,
        cmd: &Q,
    ) -> impl Future<Output = Result<Q::Return, bt_hci::cmd::Error<Self::Error>>> {
        self.0.exec(cmd)
    }
}

impl<C, Q> ControllerCmdAsync<Q> for ControllerRef<'_, C>
where
    C: ControllerCmdAsync<Q>,
    Q: AsyncCmd + ?Sized,
{
    fn exec(&self, cmd: &Q) -> impl Future<Output = Result<(), bt_hci::cmd::Error<Self::Error>>> {
        self.0.exec(cmd)
    }
}
/// The `bt-hci` controller contract the peripheral drives.
pub use trouble_host::Controller;

const MAX_CONNECTIONS: usize = 1;
const MAX_MTU_SIZE: usize = DefaultPacketPool::MTU;
const MAX_CHANNELS: usize = 2;
const ADV_SETS: usize = 1;

pub type GPHostResources =
    HostResources<DefaultPacketPool, MAX_CONNECTIONS, MAX_CHANNELS, ADV_SETS>;

type External = [u8; 0];

// GATT Server definition
#[gatt_server]
struct Server {
    matter_service: MatterService,
}

/// Matter service
#[gatt_service(uuid = MATTER_BLE_SERVICE_UUID16)]
struct MatterService {
    #[characteristic(uuid = C1_CHARACTERISTIC_UUID, write)]
    c1: External,
    #[characteristic(uuid = C2_CHARACTERISTIC_UUID, write, indicate)]
    c2: External,
}

struct TroubleBtpResources {
    resources: GPHostResources,
    ind_buf: Vec<u8, MAX_MTU_SIZE>,
}

impl TroubleBtpResources {
    const fn new() -> Self {
        Self {
            resources: GPHostResources::new(),
            ind_buf: Vec::new(),
        }
    }

    #[allow(unsafe_code, clippy::uninit_assumed_init)]
    fn init() -> impl Init<Self> {
        init!(Self {
            // SAFETY: `HostResources` is a bunch of `MaybeUninit`s (trouble-host
            // 0.8), so an uninitialised value is a valid one; this keeps the
            // multi-kilobyte struct off the stack. Breaks if that changes.
            resources: unsafe { MaybeUninit::<GPHostResources>::uninit().assume_init() },
            ind_buf <- Vec::init(),
        })
    }
}

/// The state of the `TroubleBtpGattPeripheral` struct.
/// Isolated as a separate struct to allow for `const fn` construction
/// and static allocation.
pub struct TroubleBtpGattContext {
    resources: IfMutex<TroubleBtpResources>,
}

impl TroubleBtpGattContext {
    /// Create a new instance.
    #[allow(clippy::large_stack_frames)]
    #[inline(always)]
    pub const fn new() -> Self {
        Self {
            resources: IfMutex::new(TroubleBtpResources::new()),
        }
    }

    /// Return an in-place initializer for the type.
    pub fn init() -> impl Init<Self> {
        init!(Self {
            resources <- IfMutex::init(TroubleBtpResources::init()),
        })
    }
}

impl Default for TroubleBtpGattContext {
    // TODO
    #[allow(clippy::large_stack_frames)]
    #[inline(always)]
    fn default() -> Self {
        Self::new()
    }
}

/// A GATT peripheral implementation for the BTP protocol in `rs-matter` via `trouble-host`.
/// Implements the `GattPeripheral` trait.
pub struct TroubleBtpGattPeripheral<'a, R, C>
where
    R: Rng + Copy,
    C: Controller,
{
    // TODO: Ideally this should be the controller itself, but this is not possible
    // until `bt-hci` is updated with `impl<C: Controller>` Controller for &C {}`
    ble_ctl: C,
    rand: Option<R>,
    context: &'a TroubleBtpGattContext,
}

impl<'a, R, C> TroubleBtpGattPeripheral<'a, R, C>
where
    R: Rng + Copy,
    C: Controller,
{
    /// Create a new instance.
    ///
    /// Creation might fail if the GATT context cannot be reset, so user should ensure
    /// that there are no other GATT peripherals running before calling this function.
    pub const fn new(ble_ctl: C, rand: Option<R>, context: &'a TroubleBtpGattContext) -> Self {
        Self {
            ble_ctl,
            rand,
            context,
        }
    }

    /// Run the GATT peripheral.
    pub async fn run(
        &mut self,
        btp: &Btp,
        service_name: &str,
        service_adv_data: &AdvData,
    ) -> Result<(), Error> {
        log_info!("Starting advertising and GATT service");

        let mut resources = self.context.resources.lock().await;
        let resources = &mut *resources;

        resources
            .ind_buf
            .resize_default(MAX_MTU_SIZE)
            .map_err(|_| Error::from(ErrorCode::BtpError))?;

        let ind_buf = &mut resources.ind_buf;
        let resources = &mut resources.resources;

        let controller = ControllerRef::new(&self.ble_ctl);

        let stack = trouble_host::new(controller, resources);

        let stack = if let Some(mut rand) = self.rand {
            // Generate a valid BLE Static Random Address
            // - Two most significant bits must be 11 (static random address)
            // - Lower 46 bits must contain at least one 0 and one 1
            let address: [u8; 6] = loop {
                let addr = rand.next_u64() & 0x3f_ff_ff_ff_ff_ff;
                if addr != 0 && addr != 0x3f_ff_ff_ff_ff_ff {
                    // A BLE BD_ADDR is little-endian, so its most-significant byte -- the
                    // one that must carry the 0b11 static-random type bits -- is the last of
                    // the six. Emit little-endian so the 0xc0 lands on address[5].
                    break (addr | 0xc0_00_00_00_00_00).to_le_bytes()[..6]
                        .try_into()
                        .unwrap();
                }
            };

            log_info!("Random GATT address = {:?}", address);

            stack.set_random_address(Address::random(address))
        } else {
            stack
        };

        let stack = stack.build();

        let runner = stack.runner();
        let mut peripheral = stack.peripheral();

        let server = Server::new_with_config(GapConfig::Peripheral(PeripheralConfig {
            name: "RsThread",
            appearance: &appearance::power_device::GENERIC_POWER_DEVICE,
        }))
        .map_err(to_matter_err)?;

        // TODO: The `rs-matter` stack stops BLE by dropping this future when a commissioning window
        // closes. The advertiser and the connection then only queue their stop and disconnect
        // requests for the runner, which is dropped along with them, so nothing reaches the
        // controller. A controller that outlives `run` (see `ControllerGattPeripheral`) keeps
        // advertising until the next `run` resets it. A fix needs `GattPeripheral::run` to be told
        // to stop and then awaited, instead of dropped.
        let mut ble_task = pin!(Self::run_ble(runner));
        let mut peripheral_task = pin!(Self::run_peripheral(
            btp,
            service_name,
            service_adv_data,
            &server,
            &mut peripheral,
            ind_buf
        ));

        select(&mut ble_task, &mut peripheral_task)
            .coalesce()
            .await?;

        Ok(())
    }

    async fn run_ble(
        mut runner: Runner<'_, impl Controller, impl PacketPool>,
    ) -> Result<(), Error> {
        loop {
            runner.run().await.map_err(to_matter_err)?;
        }
    }

    async fn run_peripheral(
        btp: &Btp,
        service_name: &str,
        service_adv_data: &AdvData,
        server: &Server<'_>,
        peripheral: &mut Peripheral<'_, impl Controller, DefaultPacketPool>,
        ind_buf: &mut [u8],
    ) -> Result<(), Error> {
        loop {
            let conn = Self::advertise(service_name, service_adv_data, peripheral)
                .await
                .map_err(to_matter_err)?;

            let conn = conn
                .with_attribute_server(server.deref())
                .map_err(to_matter_err)?;

            btp.reset();

            let ind_ack = Notification::new();

            let events = Self::handle_events(server, &conn, &ind_ack, btp);
            let indications = Self::handle_indications(server, &conn, ind_buf, &ind_ack, btp);

            select(events, indications).coalesce().await?;
        }
    }

    /// Create an advertiser to use to connect to a BLE Central, and wait for it to connect.
    async fn advertise<'p, CC: Controller>(
        service_name: &str,
        service_adv_data: &AdvData,
        peripheral: &mut Peripheral<'p, CC, DefaultPacketPool>,
    ) -> Result<Connection<'p, DefaultPacketPool>, BleHostError<CC::Error>> {
        let service_adv_enc_data = service_adv_data
            .service_payload_iter()
            .collect::<Vec<_, 8>>();

        let adv_data = [
            AdStructure::Flags(LE_GENERAL_DISCOVERABLE | BR_EDR_NOT_SUPPORTED),
            AdStructure::ServiceData16 {
                uuid: MATTER_BLE_SERVICE_UUID16.to_le_bytes(),
                data: &service_adv_enc_data,
            },
            AdStructure::CompleteLocalName(service_name.as_bytes()),
        ];

        let mut adv_enc_data = [0; 31];
        let len = AdStructure::encode_slice(&adv_data, &mut adv_enc_data)?;

        let advertiser = peripheral
            .advertise(
                &Default::default(),
                Advertisement::ConnectableScannableUndirected {
                    adv_data: &adv_enc_data[..len],
                    scan_data: &[],
                },
            )
            .await?;

        log_info!("GATT: Advertising");

        let conn = advertiser.accept().await?;

        log_info!("GATT: Connection established");

        Ok(conn)
    }

    /// Stream events until the connection closes or the other peer unsibscribes from char C2.
    async fn handle_events(
        server: &Server<'_>,
        conn: &GattConnection<'_, '_, DefaultPacketPool>,
        ind_ack: &Notification,
        btp: &Btp,
    ) -> Result<(), Error> {
        fn to_bt_addr(addr: &BdAddr) -> BtAddr {
            let raw = addr.raw();
            BtAddr([raw[0], raw[1], raw[2], raw[3], raw[4], raw[5]])
        }

        let mut subscribed = false;

        loop {
            match conn.next().await {
                GattConnectionEvent::Disconnected { reason } => {
                    log_info!("GATT: Disconnect: {:?}", reason);
                    break;
                }
                GattConnectionEvent::Gatt { event } => {
                    log_debug!("GATT: {:?}", event.payload());
                    match event.payload().incoming() {
                        AttClient::Request(AttReq::Write {
                            handle,
                            data: bytes,
                        }) => {
                            log_debug!("GATT: write handle {} len {}", handle, bytes.len());
                            if handle == server.matter_service.c1.handle {
                                btp.process_incoming(
                                    Some(conn.raw().att_mtu()),
                                    to_bt_addr(&conn.raw().peer_address().addr),
                                    bytes,
                                )
                                .map_err(to_matter_err)?;

                                Self::write_reply(event).await?;
                            } else if Some(handle) == server.matter_service.c2.cccd_handle {
                                let subscription_req = bytes[0] != 0;

                                // NOTE: We MUST let the attribute server process the CCCD write
                                // (via `accept`) rather than replying to it ourselves, so that
                                // `trouble-host` records the subscription in its own CCCD table.
                                // `Characteristic::indicate` in `handle_indications` consults that
                                // table (`should_indicate`) and silently drops the indication if the
                                // peer is not registered as subscribed there.
                                Self::accept(event).await?;

                                if subscription_req {
                                    if !subscribed {
                                        log_info!("GATT: Peer subscribed");
                                        subscribed = true;
                                        ind_ack.notify();
                                    }
                                } else if subscribed {
                                    log_info!("GATT: Peer unsubscribed");
                                    break;
                                }
                            } else {
                                Self::accept(event).await?;
                            }
                        }
                        _ => Self::accept(event).await?,
                    }
                }
                _ => (),
            }
        }

        log_info!("GATT: Events task finished");

        Ok(())
    }

    /// Handle outgoing data from Btp as indications
    async fn handle_indications(
        server: &Server<'_>,
        conn: &GattConnection<'_, '_, DefaultPacketPool>,
        ind_buf: &mut [u8],
        ind_ack: &Notification,
        btp: &Btp,
    ) -> Result<(), Error> {
        // Wait until `handle_events` indicates to us
        // that the peer did subscribe to char C2
        ind_ack.wait().await;

        loop {
            let len = btp.process_outgoing(Some(conn.raw().att_mtu()), ind_buf)?;
            if len > 0 {
                let data = &ind_buf[..len];

                // Sends the indication and then blocks until the peer's
                // `HandleValueConfirmation` is received (or the 30s ATT transaction
                // timeout elapses, in which case the connection is torn down).
                //
                // NOTE: As of `trouble-host` commit 50d0f9f, the indication confirmation
                // is consumed internally by `trouble-host` and is NO LONGER surfaced as a
                // `GattConnectionEvent` in `handle_events` - hence waiting for it here,
                // rather than via a separate notification signalled from the events task.
                server
                    .matter_service
                    .c2
                    .indicate_raw(conn, data, false)
                    .await
                    .map_err(to_matter_err)?;
            } else {
                btp.wait_outgoing().await;
            }
        }
    }

    async fn write_reply(event: GattEvent<'_, '_, DefaultPacketPool>) -> Result<(), Error> {
        event
            .into_payload()
            .reply(AttRsp::Write)
            .await
            .map_err(to_matter_err)
    }

    async fn accept(event: GattEvent<'_, '_, DefaultPacketPool>) -> Result<(), Error> {
        match event.accept() {
            Ok(reply) => {
                reply.send().await;
            }
            Err(e) => {
                log_warn!("GATT: Error accepting event: {:?}", e);
            }
        }

        Ok(())
    }
}

impl<R, C> GattPeripheral for TroubleBtpGattPeripheral<'_, R, C>
where
    R: Rng + Copy,
    C: Controller,
{
    async fn run(
        &mut self,
        btp: &Btp,
        service_name: &str,
        adv_data: &AdvData,
    ) -> Result<(), Error> {
        TroubleBtpGattPeripheral::run(self, btp, service_name, adv_data)
            .await
            .map_err(|_| {
                log_warn!("running the BTP GATT peripheral failed");
                ErrorCode::BtpError
            })?;

        Ok(())
    }
}

fn to_matter_err<E: Debug>(err: E) -> Error {
    #[cfg(feature = "defmt")]
    defmt::warn!("BLE error: {:?}", defmt::Debug2Format(&err));
    #[cfg(feature = "log")]
    ::log::warn!("BLE error: {:?}", err);
    #[cfg(not(any(feature = "defmt", feature = "log")))]
    let _ = &err;
    ErrorCode::BtpError.into()
}
