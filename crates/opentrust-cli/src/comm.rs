//! `joiner` and `commissioner` (OT `cli_joiner.cpp`, `cli_commissioner.cpp`).

use core::fmt::Write;

use opentrust_core::time::Duration;
use opentrust_instance::InstanceCrypto;
use opentrust_meshcop::commissioner::{CommissionerEvent, CommissionerState, JoinerKind};
use opentrust_meshcop::joiner::{JoinerConfig, JoinerState};
use opentrust_platform::SettingsStore;
use rand_core::{CryptoRng, Rng};

use crate::Ctx;
use crate::util::{Args, E, R, error_name, hex, ln, parse_hex_exact, parse_u32};

/// Commissioner ID sent in the petition (OT default).
const COMMISSIONER_ID: &str = "OpenThread Commissioner";
/// Joiner timeout of `commissioner joiner add` without a timeout (OT).
const DEFAULT_JOINER_TIMEOUT_SECS: u32 = 120;

fn joiner_kind(s: &str) -> Result<JoinerKind, E> {
    if s == "*" {
        Ok(JoinerKind::Any)
    } else {
        Ok(JoinerKind::Eui64(parse_hex_exact::<8>(s)?.into()))
    }
}

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
                    vendor_name: "OpenTrust",
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

    pub(crate) fn joiner_result(&mut self, r: Result<(), opentrust_core::Error>) {
        match r {
            Ok(()) => ln!(self.o, "Join success"),
            Err(e) => {
                let E(n) = E::from(e);
                ln!(self.o, "Join failed [{}]", error_name(n));
            }
        }
    }

    pub(crate) fn commissioner(&mut self, a: &Args<'_>) -> R {
        match a.get(1) {
            "start" => self
                .i
                .commissioner_start(COMMISSIONER_ID, None, self.now)
                .map_err(E::from),
            "stop" => {
                self.i.commissioner_stop(self.now);
                Ok(())
            }
            "state" => {
                let s = match self.i.commissioner_state() {
                    CommissionerState::Disabled => "disabled",
                    CommissionerState::Petition => "petition",
                    CommissionerState::Active => "active",
                };
                ln!(self.o, "{s}");
                Ok(())
            }
            "sessionid" => {
                ln!(self.o, "{}", self.i.commissioner_session_id());
                Ok(())
            }
            "joiner" => match a.get(2) {
                "add" => {
                    let kind = joiner_kind(a.get(3))?;
                    let pskd = a.get(4);
                    if pskd.is_empty() {
                        return Err(E::INVALID_ARGS);
                    }
                    let timeout = if a.get(5).is_empty() {
                        DEFAULT_JOINER_TIMEOUT_SECS
                    } else {
                        parse_u32(a.get(5))?
                    };
                    self.i
                        .commissioner_add_joiner(
                            kind,
                            pskd,
                            Duration::from_secs(u64::from(timeout)),
                            self.now,
                        )
                        .map_err(E::from)
                }
                "remove" => {
                    let kind = joiner_kind(a.get(3))?;
                    self.i
                        .commissioner_remove_joiner(&kind, self.now)
                        .map_err(E::from)
                }
                _ => Err(E::INVALID_COMMAND),
            },
            _ => Err(E::INVALID_COMMAND),
        }
    }

    pub(crate) fn commissioner_event(&mut self, e: &CommissionerEvent) {
        match e {
            CommissionerEvent::State(s) => {
                let s = match s {
                    CommissionerState::Disabled => "disabled",
                    CommissionerState::Petition => "petition",
                    CommissionerState::Active => "active",
                };
                ln!(self.o, "Commissioner: {s}");
            }
            CommissionerEvent::JoinerStart(_, id) => {
                crate::util::out!(self.o, "Commissioner: Joiner start ");
                hex(self.o, &id.0);
                ln!(self.o);
            }
            CommissionerEvent::JoinerConnected(id) => {
                crate::util::out!(self.o, "Commissioner: Joiner connect ");
                hex(self.o, &id.0);
                ln!(self.o);
            }
            CommissionerEvent::JoinerFinalize(id, _) => {
                crate::util::out!(self.o, "Commissioner: Joiner finalize ");
                hex(self.o, &id.0);
                ln!(self.o);
            }
            CommissionerEvent::JoinerEnd(id) => {
                crate::util::out!(self.o, "Commissioner: Joiner end ");
                hex(self.o, &id.0);
                ln!(self.o);
            }
            _ => {}
        }
    }
}
