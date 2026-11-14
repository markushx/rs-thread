//! `scan`, `scan energy` and `discover`.

use core::fmt::Write;

use opentrust_core::time::Duration;
use opentrust_instance::{Event, InstanceCrypto};
use opentrust_platform::SettingsStore;
use rand_core::{CryptoRng, Rng};

use crate::Ctx;
use crate::util::{Args, E, R, hex, ln, out, parse_u8, parse_u16, table_header};

/// Listening time per channel of an active scan (OT default).
const ACTIVE_SCAN_DURATION: Duration = Duration::from_millis(300);
/// Default energy scan time per channel.
const ENERGY_SCAN_DURATION_MS: u64 = 100;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Kind {
    Active,
    Energy,
    Discover,
}

fn channel_mask(s: &str) -> Result<u32, E> {
    if s.is_empty() {
        return Ok(0);
    }
    let c = parse_u8(s)?;
    if c >= 32 {
        return Err(E::INVALID_ARGS);
    }
    Ok(1 << c)
}

impl<S, C, Rn, W> Ctx<'_, S, C, Rn, W>
where
    S: SettingsStore,
    C: InstanceCrypto,
    Rn: Rng + CryptoRng,
    W: Write,
{
    pub(crate) fn scan_cmd(&mut self, a: &Args<'_>) -> R {
        if self.st.scan.is_some() {
            return Err(E::BUSY);
        }
        if a.get(1) == "energy" {
            let mut k = 2;
            let mut duration = ENERGY_SCAN_DURATION_MS;
            if !a.get(k).is_empty() {
                duration = u64::from(parse_u16(a.get(k))?);
                k += 1;
            }
            let mask = channel_mask(a.get(k))?;
            table_header(self.o, &["Ch", "RSSI"], &[4, 6]);
            self.i
                .energy_scan_start(mask, Duration::from_millis(duration), self.now)?;
            self.st.scan = Some(Kind::Energy);
        } else {
            let mask = channel_mask(a.get(1))?;
            table_header(
                self.o,
                &["PAN", "MAC Address", "Ch", "dBm", "LQI"],
                &[6, 18, 4, 5, 5],
            );
            self.i
                .active_scan_start(mask, ACTIVE_SCAN_DURATION, self.now)?;
            self.st.scan = Some(Kind::Active);
        }
        Err(E::PENDING)
    }

    pub(crate) fn discover(&mut self, a: &Args<'_>) -> R {
        if self.st.scan.is_some() {
            return Err(E::BUSY);
        }
        let mask = channel_mask(a.get(1))?;
        self.i.discover_start(mask, 0xffff, false, self.now)?;
        table_header(
            self.o,
            &[
                "Network Name",
                "Extended PAN",
                "PAN",
                "MAC Address",
                "Ch",
                "dBm",
                "LQI",
            ],
            &[18, 18, 6, 18, 4, 5, 5],
        );
        self.st.scan = Some(Kind::Discover);
        Err(E::PENDING)
    }

    pub(crate) fn scan_event(&mut self, ev: &Event) {
        match ev {
            Event::ActiveScanResult(r) if self.st.scan == Some(Kind::Active) => {
                out!(self.o, "| {:04x} | ", r.pan_id.0);
                hex(self.o, &r.ext_addr.0);
                out!(self.o, " | {:2} ", r.channel);
                out!(self.o, "| {:3} ", r.rssi.unwrap_or(127));
                ln!(self.o, "| {:3} |", r.lqi.unwrap_or(0));
            }
            Event::EnergyScanResult { channel, max_rssi } if self.st.scan == Some(Kind::Energy) => {
                ln!(self.o, "| {:2} | {:4} |", channel, max_rssi);
            }
            Event::DiscoverResult(r) if self.st.scan == Some(Kind::Discover) => {
                let name = r.network_name.as_ref().map_or("", |n| n.as_str());
                out!(self.o, "| {:<16} | ", name);
                match &r.ext_pan_id {
                    Some(x) => hex(self.o, &x.0),
                    None => out!(self.o, "0000000000000000"),
                }
                out!(self.o, " | {:04x} | ", r.pan_id);
                hex(self.o, &r.ext_address.0);
                out!(self.o, " | {:2} ", r.channel);
                out!(self.o, "| {:3} ", r.rssi);
                ln!(self.o, "| {:3} |", r.lqi);
            }
            Event::ActiveScanDone | Event::EnergyScanDone | Event::DiscoverDone
                if self.st.scan.take().is_some() =>
            {
                ln!(self.o, "Done");
            }
            _ => {}
        }
    }
}
