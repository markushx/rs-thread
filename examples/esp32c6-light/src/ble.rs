//! BLE commissioning stub for the ESP32-C6.
//!
//! # Current state
//!
//! This is a placeholder.  The full implementation wires `esp-wifi`'s BLE
//! controller (the HCI transport the ESP32-C6 BLE hardware exposes) to
//! `trouble-host` and from there to [`TroubleBtpGattPeripheral`].  The ESP
//! COEX framework handles radio arbitration between the BLE controller and
//! the `esp-ieee802154` Thread driver — no changes to the Thread stack are
//! needed.
//!
//! # Wiring plan (Phase 17e)
//!
//! 1. Add `esp-wifi = { version = "≥0.13", features = ["ble", "esp32c6"] }`.
//! 2. Init: `let (wifi_controller, _) = esp_wifi::init(systimer, rng, radio_clk)?;`
//! 3. BLE connector: `let ble = wifi_controller.into_ble_connector();`
//! 4. Pass to `TroubleBtpGattPeripheral::new(ble, rand, context)`.
//!
//! [`TroubleBtpGattPeripheral`]: rs_thread_matter::ble::TroubleBtpGattPeripheral

use defmt::warn;
use rs_matter::error::{Error, ErrorCode};
use rs_matter::stack::ble::GattPeripheral;
use rs_matter::transport::network::btp::{AdvData, Btp};
use rs_thread_matter::ble::TroubleBtpGattContext;

/// BLE commissioning peripheral (stub).
///
/// Replace with an `esp-wifi`-backed implementation in Phase 17e.
pub struct EspWifiBleGatt {
    #[allow(dead_code)]
    context: &'static TroubleBtpGattContext,
}

impl EspWifiBleGatt {
    pub fn new(context: &'static TroubleBtpGattContext) -> Self {
        Self { context }
    }
}

impl GattPeripheral for EspWifiBleGatt {
    async fn run(
        &mut self,
        _btp: &Btp,
        _service_name: &str,
        _service_adv: &AdvData,
    ) -> Result<(), Error> {
        // Phase 17e: replace with esp-wifi BLE controller + TroubleBtpGattPeripheral.
        warn!("BLE commissioning not yet implemented on ESP32-C6; skipping");
        Err(ErrorCode::Invalid.into())
    }
}
