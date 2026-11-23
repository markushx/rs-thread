//! BLE commissioning: the Nordic SoftDevice Controller (`nrf-sdc`, the
//! peripheral-only library) on MPSL, next to the 802.15.4 driver, as a
//! `GattPeripheral` of rs-matter.
//!
//! The controller exists only while the peripheral runs, that is while
//! rs-matter has a commissioning window open on BLE: dropping it (`sdc_disable`)
//! stops advertising and any connection, and releases MPSL's timeslots to
//! Thread alone. The BLE host (`trouble-host`) and the BTP engine are
//! `rs_thread_matter::ble`.
//!
//! The structure follows `SdcGattPeripheral` of `rs-matter-embassy`
//! (`src/wireless/thread/nrf.rs`, MIT OR Apache-2.0).

use defmt::{info, warn};
use nrf_sdc::{Builder, Mem, Peripherals};
use rs_thread_matter::ble::{TroubleBtpGattContext, TroubleBtpGattPeripheral};
use rs_matter::error::{Error, ErrorCode};
use rs_matter::stack::ble::GattPeripheral;
use rs_matter::transport::network::btp::{AdvData, Btp};

/// ATT MTU / L2CAP buffer size and the TX / RX queue depth of the controller
/// (one connection; BTP fragments to the MTU, 247 bytes of payload at most).
const L2CAP_MTU: u16 = 251;
const L2CAP_TXQ: u8 = 3;
const L2CAP_RXQ: u8 = 3;

/// Memory the controller needs for this configuration (checked at run time
/// against `Builder::required_memory`, which is logged).
pub const SDC_MEM: usize = 3084;

/// A `rand_core` 0.9 RNG (what `nrf-sdc` asks for) over a `rand_core` 0.10
/// one (what rs-matter and embassy-nrf have).
struct Rng09<R>(R);

impl<R: rand_core::Rng> rand_core09::RngCore for Rng09<R> {
    fn next_u32(&mut self) -> u32 {
        self.0.next_u32()
    }
    fn next_u64(&mut self) -> u64 {
        self.0.next_u64()
    }
    fn fill_bytes(&mut self, dst: &mut [u8]) {
        self.0.fill_bytes(dst)
    }
}

impl<R: rand_core::CryptoRng> rand_core09::CryptoRng for Rng09<R> {}

/// The BLE side of the radio: everything the SoftDevice Controller needs.
pub struct SdcGatt<R> {
    mpsl: &'static rs_thread_nrf::Mpsl,
    sdc: Peripherals<'static>,
    mem: &'static mut Mem<SDC_MEM>,
    context: &'static TroubleBtpGattContext,
    rand: R,
}

impl<R> SdcGatt<R> {
    pub fn new(
        mpsl: &'static rs_thread_nrf::Mpsl,
        sdc: Peripherals<'static>,
        mem: &'static mut Mem<SDC_MEM>,
        context: &'static TroubleBtpGattContext,
        rand: R,
    ) -> Self {
        Self {
            mpsl,
            sdc,
            mem,
            context,
            rand,
        }
    }
}

fn sdc_err(e: nrf_sdc::Error) -> Error {
    warn!("SoftDevice Controller: {}", defmt::Debug2Format(&e));
    ErrorCode::BtpError.into()
}

impl<R> GattPeripheral for SdcGatt<R>
where
    R: rand_core::Rng + rand_core::CryptoRng + Copy,
{
    async fn run(
        &mut self,
        btp: &Btp,
        service_name: &str,
        service_adv: &AdvData,
    ) -> Result<(), Error> {
        let builder = Builder::new()
            .map_err(sdc_err)?
            .support_adv()
            .support_peripheral()
            .peripheral_count(1)
            .map_err(sdc_err)?
            .buffer_cfg(L2CAP_MTU, L2CAP_MTU, L2CAP_TXQ, L2CAP_RXQ)
            .map_err(sdc_err)?;
        info!(
            "BLE: SoftDevice Controller needs {} bytes of {}",
            builder.required_memory().unwrap_or(0),
            SDC_MEM
        );
        let mut rng = Rng09(self.rand);
        let p = Peripherals {
            ppi_ch17: self.sdc.ppi_ch17.reborrow(),
            ppi_ch18: self.sdc.ppi_ch18.reborrow(),
            ppi_ch20: self.sdc.ppi_ch20.reborrow(),
            ppi_ch21: self.sdc.ppi_ch21.reborrow(),
            ppi_ch22: self.sdc.ppi_ch22.reborrow(),
            ppi_ch23: self.sdc.ppi_ch23.reborrow(),
            ppi_ch24: self.sdc.ppi_ch24.reborrow(),
            ppi_ch25: self.sdc.ppi_ch25.reborrow(),
            ppi_ch26: self.sdc.ppi_ch26.reborrow(),
            ppi_ch27: self.sdc.ppi_ch27.reborrow(),
            ppi_ch28: self.sdc.ppi_ch28.reborrow(),
            ppi_ch29: self.sdc.ppi_ch29.reborrow(),
        };
        let controller = builder
            .build(p, &mut rng, self.mpsl, &mut *self.mem)
            .map_err(sdc_err)?;
        info!("BLE: controller up");
        let mut peripheral =
            TroubleBtpGattPeripheral::new(controller, Some(self.rand), self.context);
        let r = peripheral.run(btp, service_name, service_adv).await;
        info!("BLE: controller down");
        r
    }
}
