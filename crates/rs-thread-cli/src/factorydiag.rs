//! `diag` (OT factory diagnostics, `diag.cpp`): the diagnostics mode with
//! channel, power, packet statistics and the `send` / `repeat` commands.
//!
//! The mode is a bookkeeping state of the CLI: no raw frame is transmitted
//! (the instance has no raw radio access in diagnostics mode), `send` and
//! `repeat` only count the packets as sent successfully.

use core::fmt::Write;

use rs_thread_instance::InstanceCrypto;
use rs_thread_platform::SettingsStore;
use rand_core::{CryptoRng, Rng};

use crate::Ctx;
use crate::util::{Args, E, R, ln, parse_u8, parse_u32};

/// Channels of the 2.4 GHz band.
const CHANNELS: core::ops::RangeInclusive<u8> = 11..=26;

/// State of the diagnostics mode.
#[derive(Debug, Default)]
pub(crate) struct State {
    enabled: bool,
    channel: u8,
    power: i8,
    repeating: bool,
    sent: u32,
}

impl<S, C, Rn, W> Ctx<'_, S, C, Rn, W>
where
    S: SettingsStore,
    C: InstanceCrypto,
    Rn: Rng + CryptoRng,
    W: Write,
{
    pub(crate) fn factory_diag(&mut self, a: &Args<'_>) -> R {
        let enabled = self.st.factory_diag.enabled;
        match a.get(1) {
            "" => {
                ln!(
                    self.o,
                    "diagnostics mode is {}",
                    if enabled { "enabled" } else { "disabled" }
                );
                Ok(())
            }
            "start" => {
                self.st.factory_diag = State {
                    enabled: true,
                    channel: 11,
                    ..State::default()
                };
                Ok(())
            }
            "stop" => {
                if !enabled {
                    return Err(E::INVALID_STATE);
                }
                self.st.factory_diag.enabled = false;
                self.st.factory_diag.repeating = false;
                Ok(())
            }
            "channel" => {
                if !enabled {
                    return Err(E::INVALID_STATE);
                }
                if a.get(2).is_empty() {
                    ln!(self.o, "{}", self.st.factory_diag.channel);
                    return Ok(());
                }
                let ch = parse_u8(a.get(2))?;
                if !CHANNELS.contains(&ch) {
                    return Err(E::INVALID_ARGS);
                }
                self.st.factory_diag.channel = ch;
                Ok(())
            }
            "power" => {
                if !enabled {
                    return Err(E::INVALID_STATE);
                }
                if a.get(2).is_empty() {
                    ln!(self.o, "{}", self.st.factory_diag.power);
                    return Ok(());
                }
                self.st.factory_diag.power = a.get(2).parse().map_err(|_| E::INVALID_ARGS)?;
                Ok(())
            }
            "send" => {
                if !enabled {
                    return Err(E::INVALID_STATE);
                }
                let packets = parse_u32(a.get(2))?;
                let len = parse_u32(a.get(3))?;
                if packets == 0 || !(3..=127).contains(&len) {
                    return Err(E::INVALID_ARGS);
                }
                self.st.factory_diag.sent += packets;
                Ok(())
            }
            "repeat" => {
                if !enabled {
                    return Err(E::INVALID_STATE);
                }
                if a.get(2) == "stop" {
                    self.st.factory_diag.repeating = false;
                    return Ok(());
                }
                let _delay = parse_u32(a.get(2))?;
                let len = parse_u32(a.get(3))?;
                if !(3..=127).contains(&len) {
                    return Err(E::INVALID_ARGS);
                }
                self.st.factory_diag.repeating = true;
                Ok(())
            }
            "stats" => {
                if !enabled {
                    return Err(E::INVALID_STATE);
                }
                let d = &self.st.factory_diag;
                ln!(self.o, "received packets: 0");
                ln!(self.o, "sent success packets: {}", d.sent);
                ln!(self.o, "sent error cca packets: 0");
                ln!(self.o, "sent error abort packets: 0");
                ln!(self.o, "sent error invalid state packets: 0");
                ln!(self.o, "sent error others packets: 0");
                ln!(self.o, "first received packet: rssi=0, lqi=0");
                ln!(self.o, "last received packet: rssi=0, lqi=0");
                Ok(())
            }
            "version" => {
                ln!(self.o, "RsThread");
                Ok(())
            }
            other => {
                ln!(self.o, "diag feature '{other}' is not supported");
                Err(E::INVALID_COMMAND)
            }
        }
    }
}
