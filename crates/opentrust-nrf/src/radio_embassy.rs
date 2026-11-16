//! [`Radio`] over `embassy-nrf`'s IEEE 802.15.4 driver.

use embassy_nrf::pac;
use embassy_nrf::radio::ieee802154::{Cca, Packet, Radio as HwRadio};
use opentrust_platform::radio::{
    Capabilities, Config, MacCapabilities, PsduRxInfo, PsduTxInfo, Radio, RadioCaps, RadioClock,
    RadioErrorKind, SrcMatchConfig,
};

/// Transmit powers (dBm) the nRF52840 RADIO supports, ascending.
const TX_POWERS: [i8; 15] = [-40, -30, -20, -16, -12, -8, -4, 0, 2, 3, 4, 5, 6, 7, 8];

/// Largest supported power not above `power` (the lowest one if none is).
fn clamp_power(power: i8) -> i8 {
    let mut best = TX_POWERS[0];
    for p in TX_POWERS {
        if p <= power {
            best = p;
        }
    }
    best
}

/// RSSI estimate in dBm from the hardware LQI byte. The LQI is the energy
/// detect level (1 LSB = 0.25 dB above the -94 dBm floor).
fn rssi_from_lqi(lqi: u8) -> i8 {
    -94 + (lqi / 4) as i8
}

fn now_us() -> u64 {
    embassy_time::Instant::now().as_micros()
}

/// nRF52840 802.15.4 radio.
///
/// Reports no MAC offload (see the crate docs). Not reported / not done:
/// hardware address filtering, auto-ACK, ACK matching inside `transmit`,
/// timed transmit/receive (CSL), the CCA threshold (the hardware does carrier
/// sense; without a threshold in `transmit` the CCA is disabled by an
/// unreachable ED threshold).
pub struct NrfRadio<'d> {
    hw: HwRadio<'d>,
    tx: Packet,
    rx: Packet,
    /// Channel last programmed into the driver (`None` = unknown).
    channel: Option<u8>,
    /// CCA mode last programmed: `true` = carrier sense.
    cca_on: Option<bool>,
    power: Option<i8>,
    /// `set_receive` was called and the radio was not put to sleep.
    receiving: bool,
    rx_channel: u8,
}

impl core::fmt::Debug for NrfRadio<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("NrfRadio")
            .field("channel", &self.channel)
            .field("receiving", &self.receiving)
            .finish_non_exhaustive()
    }
}

impl<'d> NrfRadio<'d> {
    /// Wrap an initialised embassy-nrf 802.15.4 driver.
    pub fn new(hw: HwRadio<'d>) -> Self {
        Self {
            hw,
            tx: Packet::new(),
            rx: Packet::new(),
            channel: None,
            cca_on: None,
            power: None,
            receiving: false,
            rx_channel: 11,
        }
    }

    fn tune(&mut self, channel: u8) -> Result<(), RadioErrorKind> {
        if !(11..=26).contains(&channel) {
            return Err(RadioErrorKind::Other);
        }
        if self.channel != Some(channel) {
            self.hw.set_channel(channel);
            self.channel = Some(channel);
        }
        Ok(())
    }

    fn set_cca_mode(&mut self, on: bool) {
        if self.cca_on != Some(on) {
            self.hw.set_cca(if on {
                Cca::CarrierSense
            } else {
                // An ED level of 255 is never exceeded: CCA always idle.
                Cca::EnergyDetection { ed_threshold: 255 }
            });
            self.cca_on = Some(on);
            // The driver re-enables the radio after a CCA change.
        }
    }
}

impl Radio for NrfRadio<'_> {
    type Error = RadioErrorKind;

    async fn init(&mut self) -> Result<RadioCaps, Self::Error> {
        Ok(RadioCaps {
            phy: Capabilities::ENERGY_SCAN | Capabilities::SLEEP_TO_TX,
            mac: MacCapabilities::empty(),
            receive_sensitivity: -100,
            default_tx_power: 0,
            default_cca_threshold: RadioCaps::DEFAULT_CCA_THRESHOLD,
            clock: Some(RadioClock(now_us)),
            ..RadioCaps::default()
        })
    }

    async fn set_config(&mut self, _config: &Config) -> Result<(), Self::Error> {
        // No hardware filtering: the MAC filters in software.
        Ok(())
    }

    async fn set_src_match_config(&mut self, _config: &SrcMatchConfig) -> Result<(), Self::Error> {
        Ok(())
    }

    async fn set_receive(&mut self, channel: u8) -> Result<(), Self::Error> {
        self.tune(channel)?;
        self.rx_channel = channel;
        self.receiving = true;
        Ok(())
    }

    async fn set_sleep(&mut self) -> Result<(), Self::Error> {
        // No receive future is running here (the MAC is the only caller and
        // drops `receive` first); the driver parks the radio after every
        // operation that ends in the disabled state.
        self.receiving = false;
        Ok(())
    }

    async fn energy_scan(&mut self, channel: u8, duration_millis: u16) -> Result<i8, Self::Error> {
        if !(11..=26).contains(&channel) {
            return Err(RadioErrorKind::Other);
        }
        let r = pac::RADIO;
        // The driver's bookkeeping of channel and mode is stale from here on.
        self.channel = None;
        // Stop whatever the driver was doing and re-tune by hand.
        r.shorts().write(|_| {});
        r.tasks_ccastop().write_value(1);
        r.tasks_stop().write_value(1);
        r.tasks_disable().write_value(1);
        while r.state().read().state() != pac::radio::vals::State::Disabled {}
        r.frequency().write(|w| {
            w.set_frequency((channel - 10) * 5);
            w.set_map(pac::radio::vals::Map::Default);
        });
        r.events_rxready().write_value(0);
        r.tasks_rxen().write_value(1);
        while r.events_rxready().read() == 0 {}
        r.events_rxready().write_value(0);

        let end = embassy_time::Instant::now()
            + embassy_time::Duration::from_millis(u64::from(duration_millis.max(1)));
        let mut max_dbm = i8::MIN;
        loop {
            r.events_rssiend().write_value(0);
            r.tasks_rssistart().write_value(1);
            while r.events_rssiend().read() == 0 {}
            let dbm = -(r.rssisample().read().rssisample() as i8);
            max_dbm = max_dbm.max(dbm);
            if embassy_time::Instant::now() >= end {
                break;
            }
            embassy_time::Timer::after_micros(100).await;
        }
        // Park the radio; the next operation re-tunes it.
        r.tasks_disable().write_value(1);
        while r.state().read().state() != pac::radio::vals::State::Disabled {}
        Ok(max_dbm)
    }

    async fn transmit(
        &mut self,
        psdu: &mut [u8],
        _psdu_tx: &mut PsduTxInfo,
        channel: u8,
        power: i8,
        cca_threshold: Option<i8>,
        _ack_psdu_buf: Option<&mut [u8]>,
    ) -> Result<Option<PsduRxInfo>, Self::Error> {
        if psdu.is_empty() || psdu.len() > usize::from(Packet::CAPACITY) {
            return Err(RadioErrorKind::TxInvalid);
        }
        self.tune(channel)?;
        let power = clamp_power(power);
        if self.power != Some(power) {
            self.hw.set_transmission_power(power);
            self.power = Some(power);
        }
        self.set_cca_mode(cca_threshold.is_some());
        self.tx.copy_from_slice(psdu);
        // Dropping this future mid-frame is fine: the driver's next
        // operation disables the radio first.
        let sent = self.hw.try_send(&mut self.tx).await;
        // The radio listens on the transmit channel afterwards (contract C4),
        // also when it transmitted from sleep (`SLEEP_TO_TX`): a sleepy device
        // sends its Parent Requests that way and has to hear the answer.
        self.rx_channel = channel;
        self.receiving = true;
        match sent {
            Ok(()) => Ok(None),
            Err(_) => Err(RadioErrorKind::TxFailed),
        }
    }

    async fn receive(&mut self, psdu_buf: &mut [u8]) -> Result<PsduRxInfo, Self::Error> {
        if !self.receiving {
            core::future::pending::<()>().await;
        }
        loop {
            self.tune(self.rx_channel)?;
            // Cancellation drops the in-flight reception only (the driver
            // stops the radio from its drop guard).
            match self.hw.receive(&mut self.rx).await {
                Ok(()) => {
                    let len = self.rx.len() as usize;
                    if len > psdu_buf.len() {
                        return Err(RadioErrorKind::RxInvalid);
                    }
                    psdu_buf[..len].copy_from_slice(&self.rx);
                    let lqi = self.rx.lqi();
                    return Ok(PsduRxInfo {
                        len,
                        channel: self.rx_channel,
                        rssi: Some(rssi_from_lqi(lqi)),
                        lqi: Some(lqi),
                        timestamp_us: Some(now_us()),
                        ack_security: None,
                        acked_with_frame_pending: None,
                    });
                }
                // CRC failure: skip the frame and listen again.
                Err(_) => continue,
            }
        }
    }
}
