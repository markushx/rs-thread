//! `ipaddr` and `ipmaddr`.

use core::fmt::Write;

use opentrust_instance::InstanceCrypto;
use opentrust_platform::SettingsStore;
use rand_core::{CryptoRng, Rng};

use crate::Ctx;
use crate::util::{Args, E, R, ln, parse_ip6};

impl<S, C, Rn, W> Ctx<'_, S, C, Rn, W>
where
    S: SettingsStore,
    C: InstanceCrypto,
    Rn: Rng + CryptoRng,
    W: Write,
{
    pub(crate) fn ipaddr(&mut self, a: &Args<'_>) -> R {
        match a.get(1) {
            "" | "-v" => {
                for u in self.i.unicast_addresses() {
                    ln!(self.o, "{}", u.addr);
                }
                Ok(())
            }
            "add" => {
                let addr = parse_ip6(a.get(2))?;
                self.i.add_unicast_address(addr, 64).map_err(E::from)
            }
            "del" => {
                let addr = parse_ip6(a.get(2))?;
                self.i.remove_unicast_address(&addr).map_err(E::from)
            }
            "mleid" => {
                let m = self.i.ml_eid();
                self.one_addr(Some(m))
            }
            "rloc" => {
                let r = self.i.rloc();
                self.one_addr(r)
            }
            "linklocal" => {
                let l = self.i.link_local();
                self.one_addr(l)
            }
            _ => Err(E::INVALID_COMMAND),
        }
    }

    fn one_addr(&mut self, a: Option<core::net::Ipv6Addr>) -> R {
        let a = a.ok_or(E::NOT_FOUND)?;
        ln!(self.o, "{a}");
        Ok(())
    }

    pub(crate) fn ipmaddr(&mut self, a: &Args<'_>) -> R {
        match a.get(1) {
            "" => {
                for m in self.i.multicast_addresses() {
                    ln!(self.o, "{m}");
                }
                Ok(())
            }
            "add" => {
                let addr = parse_ip6(a.get(2))?;
                self.i.subscribe_multicast(addr).map_err(E::from)
            }
            "del" => {
                let addr = parse_ip6(a.get(2))?;
                self.i.unsubscribe_multicast(addr).map_err(E::from)
            }
            _ => Err(E::INVALID_COMMAND),
        }
    }
}
