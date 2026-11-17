//! `ipaddr` and `ipmaddr`.

use core::fmt::Write;

use opentrust_instance::InstanceCrypto;
use opentrust_platform::SettingsStore;
use rand_core::{CryptoRng, Rng};

use crate::Ctx;
use crate::util::{Args, E, Ip6, R, ln, parse_ip6};

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
                // OpenThread lists the newest address first.
                let n = self.i.unicast_addresses().count();
                for k in (0..n).rev() {
                    if let Some(u) = self.i.unicast_addresses().nth(k) {
                        ln!(self.o, "{}", Ip6(u.addr));
                    }
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
                let r = self.i.rloc_or_invalid();
                self.one_addr(Some(r))
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
        ln!(self.o, "{}", Ip6(a));
        Ok(())
    }

    pub(crate) fn ipmaddr(&mut self, a: &Args<'_>) -> R {
        match a.get(1) {
            "" => {
                // OpenThread lists the subscribed addresses newest first,
                // then the fixed ones of the interface.
                let fixed = |m: &core::net::Ipv6Addr| {
                    let s = m.segments();
                    s[1..7] == [0; 6]
                        && matches!((s[0], s[7]), (0xff02 | 0xff03, 1 | 2) | (0xff03, 0xfc))
                };
                let n = self.i.multicast_addresses().count();
                for k in (0..n).rev() {
                    if let Some(m) = self.i.multicast_addresses().nth(k)
                        && !fixed(&m)
                    {
                        ln!(self.o, "{}", Ip6(m));
                    }
                }
                for m in self.i.multicast_addresses().filter(fixed) {
                    ln!(self.o, "{}", Ip6(m));
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
