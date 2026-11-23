//! `joiner` (OT `cli_joiner.cpp`).

use core::fmt::Write;

use rand_core::{CryptoRng, Rng};
use rs_thread_instance::InstanceCrypto;
use rs_thread_meshcop::joiner::{JoinerConfig, JoinerState};
use rs_thread_platform::SettingsStore;

use crate::Ctx;
use crate::util::{Args, E, R, error_name, hex, ln};

impl<S, C, Rn, W> Ctx<'_, S, C, Rn, W>
where
    S: SettingsStore,
    C: InstanceCrypto,
    Rn: Rng + CryptoRng,
    W: Write,
{
    pub(crate) fn joiner(&mut self, a: &Args<'_>) -> R {
        match a.get(1) {
            "start" => {
                let pskd = a.get(2);
                if pskd.is_empty() {
                    return Err(E::INVALID_ARGS);
                }
                let url = a.get(3);
                let cfg = JoinerConfig {
                    provisioning_url: if url.is_empty() { None } else { Some(url) },
                    vendor_name: "RsThread",
                    vendor_model: "CLI",
                    vendor_sw_version: env!("CARGO_PKG_VERSION"),
                    vendor_data: None,
                    vendor_stack_version: [0; 6],
                };
                self.i
                    .joiner_start(pskd, &cfg, 0, self.now)
                    .map_err(E::from)
            }
            "stop" => {
                self.i.joiner_stop(self.now);
                Ok(())
            }
            "id" => {
                hex(self.o, &self.i.joiner_id().0);
                ln!(self.o);
                Ok(())
            }
            "state" => {
                let s = match self.i.joiner_state() {
                    JoinerState::Idle => "Idle",
                    JoinerState::Discover => "Discover",
                    JoinerState::Connect => "Connecting",
                    JoinerState::Connected => "Connected",
                    JoinerState::Entrust => "Entrust",
                    JoinerState::Joined => "Joined",
                };
                ln!(self.o, "{s}");
                Ok(())
            }
            _ => Err(E::INVALID_COMMAND),
        }
    }

    pub(crate) fn joiner_result(&mut self, r: Result<(), rs_thread_core::Error>) {
        match r {
            Ok(()) => ln!(self.o, "Join success"),
            Err(e) => {
                let E(n) = E::from(e);
                ln!(self.o, "Join failed [{}]", error_name(n));
            }
        }
    }
}
