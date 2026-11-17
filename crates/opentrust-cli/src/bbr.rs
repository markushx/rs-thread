//! `bbr` and `dua` (OT `cli_bbr.cpp`, `dua iid` of `cli.cpp`).

use opentrust_instance::InstanceCrypto;
use opentrust_platform::SettingsStore;
use rand_core::{CryptoRng, Rng};

use crate::Ctx;
use crate::util::{Args, E, R, ln, parse_hex_exact};
#[cfg(feature = "ftd")]
use crate::util::{Ip6, parse_ip6, parse_u8, parse_u16, parse_u32};

fn output_config<W: core::fmt::Write>(o: &mut W, c: &opentrust_mesh::netdata::backbone::BbrConfig) {
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
        #[cfg(feature = "ftd")]
        {
            self.bbr_ftd(a)
        }
        #[cfg(not(feature = "ftd"))]
        Err(E::INVALID_COMMAND)
    }

    #[cfg(feature = "ftd")]
    fn bbr_ftd(&mut self, a: &Args<'_>) -> R {
        use opentrust_mesh::bbr_server::LocalState;
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

    #[cfg(feature = "ftd")]
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
                    Some(opentrust_core::types::Iid(parse_hex_exact::<8>(a.get(4))?))
                };
                self.i.bbr_server().set_next_dua_response(status, iid);
                Ok(())
            }
            "mlr" => match a.get(3) {
                "listener" => match a.get(4) {
                    "" => {
                        let now = self.now;
                        let list: heapless::Vec<_, 16> = self.i.bbr_listeners(now).collect();
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
                        let timeout = if a.get(6).is_empty() {
                            0
                        } else {
                            parse_u32(a.get(6))?
                        };
                        let expire = self.now
                            + opentrust_core::time::Duration::from_secs(u64::from(timeout));
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
