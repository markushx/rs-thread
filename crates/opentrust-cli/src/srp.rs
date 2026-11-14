//! `srp client` (OT `cli_srp_client.cpp`).

use core::fmt::Write;
use core::net::{Ipv6Addr, SocketAddrV6};

use heapless::{String, Vec};
use opentrust_instance::{InstanceCrypto, ItemState, ServiceConfig, ServiceId};
use opentrust_platform::SettingsStore;
use rand_core::{CryptoRng, Rng};

use crate::Ctx;
use crate::util::{Args, E, R, ln, parse_ip6, parse_u16};

/// Services the CLI can track by name.
const MAX_SERVICES: usize = 6;

/// The services added with `srp client service add`, to find them again by
/// name for `service remove`.
#[derive(Debug)]
pub(crate) struct Services(Vec<(ServiceId, String<32>, String<48>), MAX_SERVICES>);

impl Services {
    pub(crate) const fn new() -> Self {
        Self(Vec::new())
    }
}

fn state_name(s: ItemState) -> &'static str {
    match s {
        ItemState::ToAdd => "ToAdd",
        ItemState::Adding => "Adding",
        ItemState::ToRefresh => "ToRefresh",
        ItemState::Refreshing => "Refreshing",
        ItemState::ToRemove => "ToRemove",
        ItemState::Removing => "Removing",
        ItemState::Registered => "Registered",
        ItemState::Removed => "Removed",
    }
}

impl<S, C, Rn, W> Ctx<'_, S, C, Rn, W>
where
    S: SettingsStore,
    C: InstanceCrypto,
    Rn: Rng + CryptoRng,
    W: Write,
{
    pub(crate) fn srp(&mut self, a: &Args<'_>) -> R {
        if a.get(1) != "client" {
            return Err(E::INVALID_COMMAND);
        }
        match a.get(2) {
            "state" => {
                let s = if self.i.srp_is_running() {
                    "Enabled"
                } else {
                    "Disabled"
                };
                ln!(self.o, "{s}");
                Ok(())
            }
            "server" => {
                let s = self.i.srp_server().ok_or(E::NOT_FOUND)?;
                ln!(self.o, "[{}]:{}", s.ip(), s.port());
                Ok(())
            }
            "start" => {
                let addr = parse_ip6(a.get(3))?;
                let port = parse_u16(a.get(4))?;
                self.i
                    .srp_start(SocketAddrV6::new(addr, port, 0, 0), self.now)
                    .map_err(E::from)
            }
            "stop" => {
                self.i.srp_stop(self.now);
                Ok(())
            }
            "autostart" => match a.get(3) {
                "enable" => {
                    self.i.srp_enable_auto_start(self.now);
                    Ok(())
                }
                "disable" => {
                    self.i.srp_disable_auto_start();
                    Ok(())
                }
                _ => Err(E::INVALID_ARGS),
            },
            "host" => self.srp_host(a),
            "service" => self.srp_service(a),
            _ => Err(E::INVALID_COMMAND),
        }
    }

    fn srp_host(&mut self, a: &Args<'_>) -> R {
        match a.get(3) {
            "name" => {
                if a.get(4).is_empty() {
                    ln!(self.o, "{}", self.i.srp_host_name());
                    Ok(())
                } else {
                    self.i
                        .srp_set_host_name(a.get(4), self.now)
                        .map_err(E::from)
                }
            }
            "state" => {
                ln!(self.o, "{}", state_name(self.i.srp_host_state()));
                Ok(())
            }
            "address" => {
                if a.get(4).is_empty() || a.get(4) == "auto" {
                    return self
                        .i
                        .srp_enable_auto_host_address(self.now)
                        .map_err(E::from);
                }
                let mut v: Vec<Ipv6Addr, 4> = Vec::new();
                for s in a.rest(4) {
                    v.push(parse_ip6(s)?).map_err(|_| E::NO_BUFS)?;
                }
                self.i.srp_set_host_addresses(&v, self.now).map_err(E::from)
            }
            "remove" => {
                let key_lease = a.get(4) == "1" || a.get(4) == "true";
                let unreg = a.get(5) == "1" || a.get(5) == "true";
                self.i
                    .srp_remove_host_and_services(key_lease, unreg, self.now)
                    .map_err(E::from)
            }
            _ => Err(E::INVALID_COMMAND),
        }
    }

    fn srp_service(&mut self, a: &Args<'_>) -> R {
        match a.get(3) {
            "add" => {
                let (inst, svc) = (a.get(4), a.get(5));
                let port = parse_u16(a.get(6))?;
                let mut names = svc.split(',');
                let base = names.next().unwrap_or("");
                let mut cfg = ServiceConfig::new(base, inst, port)?;
                for sub in names {
                    cfg.add_sub_type(sub)?;
                }
                if !a.get(7).is_empty() {
                    cfg.priority = parse_u16(a.get(7))?;
                }
                if !a.get(8).is_empty() {
                    cfg.weight = parse_u16(a.get(8))?;
                }
                let inst_s: String<32> = String::try_from(inst).map_err(|_| E::INVALID_ARGS)?;
                let svc_s: String<48> = String::try_from(svc).map_err(|_| E::INVALID_ARGS)?;
                if self.st.srp.0.is_full() {
                    return Err(E::NO_BUFS);
                }
                let id = self.i.srp_add_service(cfg, self.now)?;
                let _ = self.st.srp.0.push((id, inst_s, svc_s));
                Ok(())
            }
            "remove" => {
                let pos = self
                    .st
                    .srp
                    .0
                    .iter()
                    .position(|(_, i, s)| i.as_str() == a.get(4) && s.as_str() == a.get(5))
                    .ok_or(E::NOT_FOUND)?;
                let id = self.st.srp.0[pos].0;
                self.i.srp_remove_service(id, self.now)?;
                self.st.srp.0.swap_remove(pos);
                Ok(())
            }
            _ => Err(E::INVALID_COMMAND),
        }
    }
}
