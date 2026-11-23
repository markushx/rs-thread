//! `bbr` and `dua` (OT `cli_bbr.cpp`, `dua iid` of `cli.cpp`).

use rs_thread_instance::InstanceCrypto;
use rs_thread_platform::SettingsStore;
use rand_core::{CryptoRng, Rng};

use crate::Ctx;
use crate::util::{Args, E, R, ln, parse_hex_exact};
#[cfg(feature = "bbr-server")]
use crate::util::{Ip6, parse_ip6, parse_u8, parse_u16, parse_u32};

fn output_config<W: core::fmt::Write>(o: &mut W, c: &rs_thread_mesh::netdata::backbone::BbrConfig) {
    ln!(o, "seqno:    {}", c.sequence_number);
    ln!(o, "delay:    {} secs", c.reregistration_delay);
    ln!(o, "timeout:  {} secs", c.mlr_timeout);
}

impl<S, C, Rn, W> Ctx<'_, S, C, Rn, W>
where
    S: SettingsStore,
    C: InstanceCrypto,
    Rn: Rng + CryptoRng,
    W: core::fmt::Write,
{
    pub(crate) fn dua(&mut self, a: &Args<'_>) -> R {
        if a.get(1) != "iid" {
            return Err(E::INVALID_COMMAND);
        }
        match a.get(2) {
            "" => {
                if let Some(iid) = self.i.dua_fixed_iid() {
                    crate::util::hex(&mut self.o, &iid);
                    ln!(self.o, "");
                }
                Ok(())
            }
            "clear" => self.i.set_dua_fixed_iid(None, self.now).map_err(E::from),
            s => {
                let iid = parse_hex_exact::<8>(s)?;
                self.i
                    .set_dua_fixed_iid(Some(iid), self.now)
                    .map_err(E::from)
            }
        }
    }

    #[cfg(feature = "bbr-server")]
    /// `fake /a/an <dst> <target> <mliid>` (reference device).
    pub(crate) fn fake(&mut self, a: &Args<'_>) -> R {
        if a.get(1) != "/a/an" {
            return Err(E::INVALID_COMMAND);
        }
        let dst = crate::util::parse_ip6(a.get(2))?;
        let target = crate::util::parse_ip6(a.get(3))?;
        let iid = parse_hex_exact::<8>(a.get(4))?;
        self.i
            .send_fake_address_notification(dst, target, iid, self.now)
            .map_err(E::from)
    }

    pub(crate) fn bbr(&mut self, a: &Args<'_>) -> R {
        if a.get(1).is_empty() {
            match self.i.primary_backbone_router() {
                Some(c) => {
                    ln!(self.o, "BBR Primary:");
                    ln!(self.o, "server16: 0x{:04X}", c.server16);
                    output_config(&mut self.o, &c);
                }
                None => ln!(self.o, "BBR Primary: None"),
            }
            return Ok(());
        }
        #[cfg(feature = "bbr-server")]
        {
            self.bbr_ftd(a)
        }
        #[cfg(not(feature = "bbr-server"))]
        Err(E::INVALID_COMMAND)
    }

    #[cfg(feature = "bbr-server")]
    fn bbr_ftd(&mut self, a: &Args<'_>) -> R {
        use rs_thread_mesh::bbr_server::LocalState;
        match a.get(1) {
            "enable" => {
                self.i.bbr_set_enabled(true);
                Ok(())
            }
            "disable" => {
                self.i.bbr_set_enabled(false);
                Ok(())
            }
            "register" => self.i.bbr_register().map_err(E::from),
            "jitter" => {
                if a.get(2).is_empty() {
                    ln!(self.o, "{}", self.i.bbr_jitter());
                } else {
                    self.i.bbr_set_jitter(parse_u8(a.get(2))?);
                }
                Ok(())
            }
            "state" => {
                let s = match self.i.bbr_state() {
                    LocalState::Disabled => "Disabled",
                    LocalState::Secondary => "Secondary",
                    LocalState::Primary => "Primary",
                };
                ln!(self.o, "{}", s);
                Ok(())
            }
            "config" => {
                if a.get(2).is_empty() {
                    let c = self.i.bbr_config();
                    output_config(&mut self.o, &c);
                    return Ok(());
                }
                let (mut seqno, mut delay, mut timeout) = (None, None, None);
                let args = a.rest(2);
                let mut k = 0;
                while k < args.len() {
                    let v = args.get(k + 1).copied().unwrap_or("");
                    match args[k] {
                        "seqno" => seqno = Some(parse_u8(v)?),
                        "delay" => delay = Some(parse_u16(v)?),
                        "timeout" => timeout = Some(parse_u32(v)?),
                        _ => return Err(E::INVALID_ARGS),
                    }
                    k += 2;
                }
                self.i
                    .bbr_set_config(seqno, delay, timeout)
                    .map_err(E::from)
            }
            "mgmt" => self.bbr_mgmt(a),
            _ => Err(E::INVALID_COMMAND),
        }
    }

    #[cfg(feature = "bbr-server")]
    fn bbr_mgmt(&mut self, a: &Args<'_>) -> R {
        match a.get(2) {
            "dua" => {
                let status = parse_u8(a.get(3))?;
                let iid = if a.get(4).is_empty() {
                    None
                } else {
                    if !a.get(5).is_empty() {
                        return Err(E::INVALID_ARGS);
                    }
                    Some(rs_thread_core::types::Iid(parse_hex_exact::<8>(a.get(4))?))
                };
                self.i.bbr_server().set_next_dua_response(status, iid);
                Ok(())
            }
            "mlr" => match a.get(3) {
                "listener" => match a.get(4) {
                    "" => {
                        let now = self.now;
                        let list: heapless::Vec<_, 75> = self.i.bbr_listeners(now).collect();
                        for (addr, left) in list {
                            ln!(self.o, "{} {}", Ip6(addr), left);
                        }
                        Ok(())
                    }
                    "clear" => {
                        self.i.bbr_server().listeners.clear();
                        Ok(())
                    }
                    "add" => {
                        let addr = parse_ip6(a.get(5))?;
                        let mut timeout = if a.get(6).is_empty() {
                            0
                        } else {
                            parse_u32(a.get(6))?
                        };
                        // As OT `otBackboneRouterMulticastListenerAdd`: 0 is
                        // the MLR timeout of the local dataset; capped.
                        if timeout == 0 {
                            timeout = self.i.bbr_config().mlr_timeout;
                        }
                        let timeout =
                            timeout.min(rs_thread_mesh::netdata::backbone::MAX_MLR_TIMEOUT);
                        let expire = self.now
                            + rs_thread_core::time::Duration::from_secs(u64::from(timeout));
                        self.i
                            .bbr_server()
                            .listeners
                            .add(addr, expire)
                            .map_err(E::from)
                    }
                    _ => Err(E::INVALID_COMMAND),
                },
                "response" => {
                    let status = parse_u8(a.get(4))?;
                    self.i.bbr_server().set_next_mlr_response(status);
                    Ok(())
                }
                _ => Err(E::INVALID_COMMAND),
            },
            _ => Err(E::INVALID_COMMAND),
        }
    }
}

#[cfg(feature = "bbr-server")]
impl<S, C, Rn, W> Ctx<'_, S, C, Rn, W>
where
    S: SettingsStore,
    C: InstanceCrypto,
    Rn: Rng + CryptoRng,
    W: core::fmt::Write,
{
    /// `mlr reg <addr>... [<timeout>]` (OT `otIp6RegisterMulticastListeners`).
    pub(crate) fn mlr(&mut self, a: &Args<'_>) -> R {
        if a.get(1) != "reg" {
            return Err(E::INVALID_COMMAND);
        }
        let mut addrs: heapless::Vec<core::net::Ipv6Addr, 15> = heapless::Vec::new();
        let mut k = 2;
        while let Ok(ip) = parse_ip6(a.get(k)) {
            k += 1;
            if addrs.push(ip).is_err() {
                break;
            }
        }
        let timeout = match parse_u32(a.get(k)) {
            Ok(t) => {
                k += 1;
                Some(t)
            }
            Err(_) => None,
        };
        if !a.get(k).is_empty() || addrs.is_empty() {
            return Err(E::INVALID_ARGS);
        }
        self.i.mlr_register(&addrs, timeout, self.now)?;
        Err(E::PENDING)
    }

    pub(crate) fn mlr_reg_result(&mut self) {
        let Some(r) = self.i.mlr_take_register_result() else {
            return;
        };
        match r {
            Ok(r) => {
                ln!(self.o, "status {}, {} failed", r.status, r.failed.len());
                for f in &r.failed {
                    ln!(self.o, "{}", Ip6(*f));
                }
                ln!(self.o, "Done");
            }
            Err(e) => {
                let E(n) = E::from(e);
                ln!(self.o, "Error {}: {}", n, crate::util::error_name(n));
            }
        }
    }
}
