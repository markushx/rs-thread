//! `srp client` and `srp server` (OT `cli_srp_client.cpp`,
//! `cli_srp_server.cpp`).

use core::fmt::Write;
use core::net::{Ipv6Addr, SocketAddrV6};

use heapless::Vec;
use rs_thread_instance::{InstanceCrypto, ItemState, ServiceConfig};
use rs_thread_platform::SettingsStore;
use rand_core::{CryptoRng, Rng};

use crate::Ctx;
use crate::util::{Args, E, Ip6, R, ln, out, parse_hex, parse_ip6, parse_u16, parse_u32};

/// The interpreter state of the SRP commands: whether the SRP client prints
/// its results (`srp client callback`).
#[derive(Debug)]
pub(crate) struct Services {
    pub(crate) callback: bool,
}

impl Services {
    pub(crate) const fn new() -> Self {
        Self { callback: false }
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

fn enabled(b: bool) -> &'static str {
    if b { "Enabled" } else { "Disabled" }
}

/// `[key=hex, key, ...]` as OT prints TXT data.
#[allow(dead_code)]
pub(crate) fn output_txt<W: Write>(o: &mut W, txt: &[u8]) {
    use crate::util::hex;
    use rs_thread_dns::rdata::TxtIter;
    out!(o, "[");
    let mut first = true;
    for e in TxtIter::new(txt) {
        let Ok(e) = e else { break };
        if !first {
            out!(o, ", ");
        }
        first = false;
        // A key longer than the recommended maximum (9) is not parsed as a
        // key: the whole entry is printed in hex.
        if e.key.len() > 9 {
            out!(o, "[");
            hex(o, e.key);
            if let Some(v) = e.value {
                out!(o, "3d");
                hex(o, v);
            }
            out!(o, "]");
            continue;
        }
        for &c in e.key {
            out!(o, "{}", c as char);
        }
        if let Some(v) = e.value {
            out!(o, "=");
            hex(o, v);
        }
    }
    out!(o, "]");
}

impl<S, C, Rn, W> Ctx<'_, S, C, Rn, W>
where
    S: SettingsStore,
    C: InstanceCrypto,
    Rn: Rng + CryptoRng,
    W: Write,
{
    pub(crate) fn srp(&mut self, a: &Args<'_>) -> R {
        match a.get(1) {
            "client" => self.srp_client(a),
            #[cfg(feature = "srp-server")]
            "server" => self.srp_server_cmd(a),
            _ => Err(E::INVALID_COMMAND),
        }
    }

    fn get_set_u32(&mut self, a: &Args<'_>, get: u32, set: fn(&mut Self, u32)) -> R {
        if a.get(3).is_empty() {
            ln!(self.o, "{get}");
            return Ok(());
        }
        let v = parse_u32(a.get(3))?;
        set(self, v);
        Ok(())
    }

    fn srp_client(&mut self, a: &Args<'_>) -> R {
        match a.get(2) {
            "state" => {
                if !a.get(3).is_empty() {
                    return Err(E::INVALID_ARGS);
                }
                let s = enabled(self.i.srp_is_running());
                ln!(self.o, "{s}");
                Ok(())
            }
            "server" => {
                let s = self
                    .i
                    .srp_server()
                    .unwrap_or_else(|| SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0, 0, 0));
                match a.get(3) {
                    "" => ln!(self.o, "[{}]:{}", Ip6(*s.ip()), s.port()),
                    "address" if a.get(4).is_empty() => ln!(self.o, "{}", Ip6(*s.ip())),
                    "port" if a.get(4).is_empty() => ln!(self.o, "{}", s.port()),
                    "address" | "port" => return Err(E::INVALID_ARGS),
                    _ => return Err(E::INVALID_COMMAND),
                }
                Ok(())
            }
            "start" => {
                let addr = parse_ip6(a.get(3))?;
                let port = parse_u16(a.get(4))?;
                if !a.get(5).is_empty() {
                    return Err(E::INVALID_ARGS);
                }
                self.i
                    .srp_start(SocketAddrV6::new(addr, port, 0, 0), self.now)
                    .map_err(E::from)
            }
            "stop" => {
                if !a.get(3).is_empty() {
                    return Err(E::INVALID_ARGS);
                }
                self.i.srp_stop(self.now);
                Ok(())
            }
            "autostart" => match a.get(3) {
                "" => {
                    let s = enabled(self.i.srp_client().is_auto_start_enabled());
                    ln!(self.o, "{s}");
                    Ok(())
                }
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
            "callback" => match a.get(3) {
                "" => {
                    let s = enabled(self.st.srp.callback);
                    ln!(self.o, "{s}");
                    Ok(())
                }
                "enable" => {
                    self.st.srp.callback = true;
                    Ok(())
                }
                "disable" => {
                    self.st.srp.callback = false;
                    Ok(())
                }
                _ => Err(E::INVALID_ARGS),
            },
            "leaseinterval" => {
                let v = self.i.srp_client().lease_interval();
                self.get_set_u32(a, v, |s, v| s.i.srp_set_lease_interval(v))
            }
            "keyleaseinterval" => {
                let v = self.i.srp_client().key_lease_interval();
                self.get_set_u32(a, v, |s, v| s.i.srp_set_key_lease_interval(v))
            }
            "ttl" => {
                let v = self.i.srp_client().ttl();
                self.get_set_u32(a, v, |s, v| s.i.srp_set_ttl(v))
            }
            "host" => self.srp_host(a),
            "service" => self.srp_service(a),
            _ => Err(E::INVALID_COMMAND),
        }
    }

    fn output_host_info(&mut self) {
        let c = self.i.srp_client();
        let name = c.host_name();
        out!(self.o, "name:");
        if name.is_empty() {
            out!(self.o, "(null)");
        } else {
            out!(self.o, "\"{name}\"");
        }
        out!(self.o, ", state:{}, addrs:", state_name(c.host_state()));
        if c.is_auto_host_address() {
            ln!(self.o, "auto");
        } else {
            out!(self.o, "[");
            for (i, a) in c.host_addresses().iter().enumerate() {
                if i > 0 {
                    out!(self.o, ", ");
                }
                out!(self.o, "{}", Ip6(*a));
            }
            ln!(self.o, "]");
        }
    }

    fn srp_host(&mut self, a: &Args<'_>) -> R {
        match a.get(3) {
            "" => {
                self.output_host_info();
                Ok(())
            }
            "name" => {
                if a.get(4).is_empty() {
                    let n = self.i.srp_host_name();
                    ln!(self.o, "{}", if n.is_empty() { "(null)" } else { n });
                    Ok(())
                } else {
                    if !a.get(5).is_empty() {
                        return Err(E::INVALID_ARGS);
                    }
                    self.i
                        .srp_set_host_name(a.get(4), self.now)
                        .map_err(E::from)
                }
            }
            "state" => {
                if !a.get(4).is_empty() {
                    return Err(E::INVALID_ARGS);
                }
                ln!(self.o, "{}", state_name(self.i.srp_host_state()));
                Ok(())
            }
            "address" => {
                if a.get(4).is_empty() {
                    let c = self.i.srp_client();
                    if c.is_auto_host_address() {
                        ln!(self.o, "auto");
                    } else {
                        let addrs: Vec<Ipv6Addr, 4> = c.host_addresses().iter().copied().collect();
                        for x in &addrs {
                            ln!(self.o, "{}", Ip6(*x));
                        }
                    }
                    return Ok(());
                }
                if a.get(4) == "auto" {
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
                let parse_bool = |s: &str| match s {
                    "1" | "true" => Ok(true),
                    "0" | "false" => Ok(false),
                    _ => Err(E::INVALID_ARGS),
                };
                let mut key_lease = false;
                let mut unreg = false;
                if !a.get(4).is_empty() {
                    key_lease = parse_bool(a.get(4))?;
                    if !a.get(5).is_empty() {
                        unreg = parse_bool(a.get(5))?;
                        if !a.get(6).is_empty() {
                            return Err(E::INVALID_ARGS);
                        }
                    }
                }
                self.i
                    .srp_remove_host_and_services(key_lease, unreg, self.now)
                    .map_err(E::from)
            }
            "clear" => {
                if !a.get(4).is_empty() {
                    return Err(E::INVALID_ARGS);
                }
                self.i.srp_clear_host_and_services();
                Ok(())
            }
            _ => Err(E::INVALID_COMMAND),
        }
    }

    fn output_service(&mut self, cfg: &ServiceConfig, state: ItemState) {
        out!(
            self.o,
            "instance:\"{}\", name:\"{}",
            cfg.instance_name,
            cfg.service_name
        );
        for s in &cfg.sub_types {
            out!(self.o, ",{s}");
        }
        ln!(
            self.o,
            "\", state:{}, port:{}, priority:{}, weight:{}",
            state_name(state),
            cfg.port,
            cfg.priority,
            cfg.weight
        );
    }

    fn srp_service(&mut self, a: &Args<'_>) -> R {
        match a.get(3) {
            "" => {
                let list: Vec<(ServiceConfig, ItemState), { rs_thread_instance::SRP_SERVICES }> =
                    self.i
                        .srp_client()
                        .services()
                        .map(|(_, c, s)| (c.clone(), s))
                        .collect();
                for (c, s) in &list {
                    self.output_service(c, *s);
                }
                Ok(())
            }
            "add" => {
                let inst_s: heapless::String<64> = crate::util::unescape(a.get(4))?;
                let (inst, svc) = (inst_s.as_str(), a.get(5));
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
                if !a.get(9).is_empty() && a.get(9) != "-" {
                    let mut b = [0u8; 256];
                    let n = parse_hex(a.get(9), &mut b)?;
                    cfg.txt.extend_from_slice(&b[..n]).map_err(|_| E::NO_BUFS)?;
                }
                if !a.get(10).is_empty() {
                    cfg.lease = parse_u32(a.get(10))?;
                }
                if !a.get(11).is_empty() {
                    cfg.key_lease = parse_u32(a.get(11))?;
                    if !a.get(12).is_empty() {
                        return Err(E::INVALID_ARGS);
                    }
                }
                self.i.srp_add_service(cfg, self.now)?;
                Ok(())
            }
            cmd @ ("remove" | "clear") => {
                if a.get(5).is_empty() || !a.get(6).is_empty() {
                    return Err(E::INVALID_ARGS);
                }
                let inst: heapless::String<64> = crate::util::unescape(a.get(4))?;
                let id = self
                    .i
                    .srp_client()
                    .services()
                    .find(|(_, c, _)| {
                        c.instance_name.as_str() == inst.as_str()
                            && c.service_name.as_str() == a.get(5)
                    })
                    .map(|(id, _, _)| id)
                    .ok_or(E::NOT_FOUND)?;
                if cmd == "remove" {
                    self.i.srp_remove_service(id, self.now)?;
                } else {
                    self.i.srp_clear_service(id, self.now)?;
                }
                Ok(())
            }
            _ => Err(E::INVALID_COMMAND),
        }
    }
}

#[cfg(feature = "srp-server")]
impl<S, C, Rn, W> Ctx<'_, S, C, Rn, W>
where
    S: SettingsStore,
    C: InstanceCrypto,
    Rn: Rng + CryptoRng,
    W: Write,
{
    fn srp_server_cmd(&mut self, a: &Args<'_>) -> R {
        use rs_thread_instance::srp_server_types::{LeaseConfig, TtlConfig};
        use rs_thread_instance::{SrpAddressMode, SrpServerState};
        match a.get(2) {
            "state" => {
                let s = match self.i.srp_server_state() {
                    SrpServerState::Disabled => "disabled",
                    SrpServerState::Running => "running",
                    SrpServerState::Stopped => "stopped",
                };
                ln!(self.o, "{s}");
                Ok(())
            }
            "enable" => {
                self.i.srp_server_set_enabled(true, self.now);
                Ok(())
            }
            "disable" => {
                self.i.srp_server_set_enabled(false, self.now);
                Ok(())
            }
            "addrmode" => {
                let mode = match a.get(3) {
                    "" => {
                        let s = match self.i.srp_server_address_mode() {
                            SrpAddressMode::Unicast => "unicast",
                            SrpAddressMode::Anycast => "anycast",
                            SrpAddressMode::UnicastForceAdd => "unicast-force-add",
                        };
                        ln!(self.o, "{s}");
                        return Ok(());
                    }
                    "unicast" => SrpAddressMode::Unicast,
                    "anycast" => SrpAddressMode::Anycast,
                    "unicast-force-add" => SrpAddressMode::UnicastForceAdd,
                    _ => return Err(E::INVALID_ARGS),
                };
                self.i.srp_server_set_address_mode(mode).map_err(E::from)
            }
            "seqnum" => {
                if a.get(3).is_empty() {
                    ln!(self.o, "{}", self.i.srp_server_anycast_seq_num());
                    return Ok(());
                }
                let v = crate::util::parse_u8(a.get(3))?;
                self.i.srp_server_set_anycast_seq_num(v).map_err(E::from)
            }
            "port" => {
                ln!(self.o, "{}", self.i.srp_server_port());
                Ok(())
            }
            "domain" => {
                if a.get(3).is_empty() {
                    let d = self.i.srp_server_store().domain().clone();
                    let mut s: heapless::String<130> = heapless::String::new();
                    let _ = d.fmt_dotted(&mut s);
                    ln!(self.o, "{s}");
                    return Ok(());
                }
                self.i.srp_server_set_domain(a.get(3)).map_err(E::from)
            }
            "ttl" => {
                if a.get(3).is_empty() {
                    let c = self.i.srp_server_store().ttl_config();
                    ln!(self.o, "min ttl: {}", c.min);
                    ln!(self.o, "max ttl: {}", c.max);
                    return Ok(());
                }
                let c = TtlConfig {
                    min: parse_u32(a.get(3))?,
                    max: parse_u32(a.get(4))?,
                };
                if !a.get(5).is_empty() {
                    return Err(E::INVALID_ARGS);
                }
                self.i.srp_server_set_ttl_config(c).map_err(E::from)
            }
            "lease" => {
                if a.get(3).is_empty() {
                    let c = self.i.srp_server_store().lease_config();
                    ln!(self.o, "min lease: {}", c.min_lease);
                    ln!(self.o, "max lease: {}", c.max_lease);
                    ln!(self.o, "min key-lease: {}", c.min_key_lease);
                    ln!(self.o, "max key-lease: {}", c.max_key_lease);
                    return Ok(());
                }
                let c = LeaseConfig {
                    min_lease: parse_u32(a.get(3))?,
                    max_lease: parse_u32(a.get(4))?,
                    min_key_lease: parse_u32(a.get(5))?,
                    max_key_lease: parse_u32(a.get(6))?,
                };
                if !a.get(7).is_empty() {
                    return Err(E::INVALID_ARGS);
                }
                self.i.srp_server_set_lease_config(c).map_err(E::from)
            }
            "host" => {
                if !a.get(3).is_empty() {
                    return Err(E::INVALID_ARGS);
                }
                self.srp_server_hosts();
                Ok(())
            }
            "service" => {
                if !a.get(3).is_empty() {
                    return Err(E::INVALID_ARGS);
                }
                self.srp_server_services();
                Ok(())
            }
            _ => Err(E::INVALID_COMMAND),
        }
    }

    fn srp_server_hosts(&mut self) {
        let store = self.i.srp_server_store();
        for h in store.hosts() {
            let mut name: heapless::String<130> = heapless::String::new();
            let _ = h.name.fmt_dotted(&mut name);
            ln!(self.o, "{name}");
            ln!(self.o, "    deleted: {}", h.is_deleted());
            if h.is_deleted() {
                continue;
            }
            out!(self.o, "    addresses: [");
            for (i, a) in h.addresses.iter().enumerate() {
                if i > 0 {
                    out!(self.o, ", ");
                }
                out!(self.o, "{}", Ip6(*a));
            }
            ln!(self.o, "]");
        }
    }

    fn srp_server_services(&mut self) {
        let now = self.now;
        let store = self.i.srp_server_store();
        for (h, s) in store.all_services() {
            let mut name: heapless::String<130> = heapless::String::new();
            let _ = s.instance.fmt_dotted(&mut name);
            ln!(self.o, "{name}");
            ln!(self.o, "    deleted: {}", s.deleted);
            if s.deleted {
                continue;
            }
            out!(self.o, "    subtypes: ");
            if s.sub_types.is_empty() {
                ln!(self.o, "(null)");
            } else {
                for i in 0..s.sub_types.len() {
                    if i > 0 {
                        out!(self.o, ",");
                    }
                    for &c in s.sub_type_label(i) {
                        out!(self.o, "{}", c as char);
                    }
                }
                ln!(self.o);
            }
            ln!(self.o, "    port: {}", s.port);
            ln!(self.o, "    priority: {}", s.priority);
            ln!(self.o, "    weight: {}", s.weight);
            ln!(self.o, "    ttl: {}", s.ttl);
            ln!(self.o, "    lease: {}", s.lease);
            ln!(self.o, "    key-lease: {}", s.key_lease);
            let _ = now;
            out!(self.o, "    TXT: ");
            output_txt(self.o, &s.txt);
            ln!(self.o);
            let mut hn: heapless::String<130> = heapless::String::new();
            let _ = h.name.fmt_dotted(&mut hn);
            ln!(self.o, "    host: {hn}");
            out!(self.o, "    addresses: [");
            for (i, a) in h.addresses.iter().enumerate() {
                if i > 0 {
                    out!(self.o, ", ");
                }
                out!(self.o, "{}", Ip6(*a));
            }
            ln!(self.o, "]");
        }
    }
}
