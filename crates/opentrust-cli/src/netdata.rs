//! `netdata`, `prefix` and `route`.

use core::fmt::Write;

use opentrust_instance::InstanceCrypto;
use opentrust_mesh::netdata::local::{ExternalRouteConfig, OnMeshPrefixConfig, ServiceConfig};
use opentrust_mesh::netdata::tlv::{BrFlags, NetPrefix};
use opentrust_platform::SettingsStore;
use rand_core::{CryptoRng, Rng};

use crate::Ctx;
use crate::util::{
    Args, E, Ip6, R, hex, ln, out, parse_hex_padded, parse_ip6, parse_prefix, parse_u8, parse_u16,
    parse_u32,
};

/// A prefix as OT prints it: the words covered by the prefix length, then
/// `::` (`fd00:dead:beef:cafe::/64`).
fn print_prefix<W: Write>(o: &mut W, p: &NetPrefix) {
    let b = p.octets();
    let words = usize::from(p.len()).div_ceil(16);
    for w in 0..words {
        if w > 0 {
            let _ = o.write_char(':');
        }
        let _ = write!(o, "{:x}", u16::from_be_bytes([b[2 * w], b[2 * w + 1]]));
    }
    if words < 8 {
        let _ = o.write_str("::");
    }
    let _ = write!(o, "/{}", p.len());
}

fn preference_name(bits: u8) -> &'static str {
    match bits {
        1 => "high",
        3 => "low",
        _ => "med",
    }
}

fn parse_preference(s: &str) -> Option<i8> {
    match s {
        "high" => Some(1),
        "med" => Some(0),
        "low" => Some(-1),
        _ => None,
    }
}

impl<S, C, Rn, W> Ctx<'_, S, C, Rn, W>
where
    S: SettingsStore,
    C: InstanceCrypto,
    Rn: Rng + CryptoRng,
    W: Write,
{
    /// `service [add|remove <enterprise> <service data> [<server data>]]`
    /// (OT `Interpreter::Process<Cmd("service")>`); without arguments the
    /// local services are listed.
    pub(crate) fn service(&mut self, a: &Args<'_>) -> R {
        if a.get(1).is_empty() {
            return Ok(());
        }
        let ent = parse_u32(a.get(2))?;
        let mut sd = [0u8; 64];
        let n = parse_hex_padded(a.get(3), &mut sd)?;
        if n == 0 {
            return Err(E::INVALID_ARGS);
        }
        match a.get(1) {
            "add" => {
                let mut srv = [0u8; 64];
                let m = parse_hex_padded(a.get(4), &mut srv)?;
                if !a.get(4).is_empty() && m == 0 {
                    return Err(E::INVALID_ARGS);
                }
                let cfg = ServiceConfig::new(ent, &sd[..n], &srv[..m], true)?;
                self.i.add_service(cfg).map_err(E::from)
            }
            "remove" => self.i.remove_service(ent, &sd[..n]).map_err(E::from),
            _ => Err(E::INVALID_COMMAND),
        }
    }

    /// `locate <anycast address>` (OT `Interpreter::Process<Cmd("locate")>`).
    pub(crate) fn locate(&mut self, a: &Args<'_>) -> R {
        if a.get(1).is_empty() {
            return if self.st.locating {
                ln!(self.o, "In Progress");
                Ok(())
            } else {
                ln!(self.o, "Idle");
                Ok(())
            };
        }
        let addr = parse_ip6(a.get(1))?;
        self.i.anycast_locate(addr, self.now)?;
        self.st.locating = true;
        Err(E::PENDING)
    }

    pub(crate) fn locate_done(
        &mut self,
        r: Result<(core::net::Ipv6Addr, u16), opentrust_core::Error>,
    ) {
        if !self.st.locating {
            return;
        }
        self.st.locating = false;
        let r = match r {
            Ok((addr, rloc)) => {
                ln!(self.o, "{} 0x{:04x}", Ip6(addr), rloc);
                Ok(())
            }
            Err(e) => Err(E::from(e)),
        };
        crate::output_result(self.o, r);
    }

    pub(crate) fn netdata(&mut self, a: &Args<'_>) -> R {
        match a.get(1) {
            "show" => {
                let nd = self.i.network_data();
                match a.get(2) {
                    "-x" => {
                        hex(self.o, nd.as_bytes());
                        ln!(self.o);
                        return Ok(());
                    }
                    "" => {}
                    _ => return Err(E::INVALID_ARGS),
                }
                ln!(self.o, "Prefixes:");
                for e in nd.on_mesh_prefixes() {
                    print_prefix(self.o, &e.prefix);
                    let _ = self.o.write_char(' ');
                    let mut any = false;
                    for (f, c) in [
                        (BrFlags::PREFERRED, 'p'),
                        (BrFlags::SLAAC, 'a'),
                        (BrFlags::DHCP, 'd'),
                        (BrFlags::CONFIGURE, 'c'),
                        (BrFlags::DEFAULT_ROUTE, 'r'),
                        (BrFlags::ON_MESH, 'o'),
                    ] {
                        if e.flags.has(f) {
                            let _ = self.o.write_char(c);
                            any = true;
                        }
                    }
                    if e.stable {
                        let _ = self.o.write_char('s');
                        any = true;
                    }
                    for (f, c) in [(BrFlags::ND_DNS, 'n'), (BrFlags::DP, 'D')] {
                        if e.flags.has(f) {
                            let _ = self.o.write_char(c);
                            any = true;
                        }
                    }
                    if !any {
                        let _ = self.o.write_char('-');
                    }
                    ln!(
                        self.o,
                        " {} {:04x}",
                        preference_name((e.flags.0 >> 14) as u8 & 3),
                        e.rloc16
                    );
                }
                ln!(self.o, "Routes:");
                for e in nd.external_routes() {
                    print_prefix(self.o, &e.prefix);
                    let _ = self.o.write_char(' ');
                    let mut any = false;
                    for (on, c) in [(e.adv_pio, 'p'), (e.nat64, 'n'), (e.stable, 's')] {
                        if on {
                            let _ = self.o.write_char(c);
                            any = true;
                        }
                    }
                    if !any {
                        let _ = self.o.write_char('-');
                    }
                    let pref = match e.preference {
                        1 => "high",
                        -1 => "low",
                        _ => "med",
                    };
                    ln!(self.o, " {} {:04x}", pref, e.rloc16);
                }
                ln!(self.o, "Services:");
                for s in nd.services() {
                    out!(self.o, "{} ", s.enterprise_number);
                    hex(self.o, s.service_data);
                    let _ = self.o.write_char(' ');
                    hex(self.o, s.server_data);
                    ln!(
                        self.o,
                        " {} {:04x}",
                        if s.stable { 's' } else { '-' },
                        s.rloc16
                    );
                }
                ln!(self.o, "Contexts:");
                for c in nd.contexts() {
                    print_prefix(self.o, &c.prefix);
                    ln!(self.o, " {} {}", c.id, if c.compress { 'c' } else { '-' });
                }
                // The Commissioning Dataset: session ID, border agent locator,
                // joiner UDP port, steering data; ` e` if other TLVs follow.
                ln!(self.o, "Commissioning:");
                let (mut sid, mut loc, mut port, mut steer, mut extra) =
                    (None, None, None, None, false);
                let mut rest = nd.commissioning_data().unwrap_or(&[]);
                while let [t, len, tail @ ..] = rest {
                    let len = usize::from(*len);
                    let Some((v, next)) = tail.split_at_checked(len) else {
                        break;
                    };
                    let u16v = || (v.len() == 2).then(|| u16::from_be_bytes([v[0], v[1]]));
                    match *t {
                        11 => sid = u16v(),
                        9 => loc = u16v(),
                        18 => port = u16v(),
                        8 => steer = Some(v),
                        _ => extra = true,
                    }
                    rest = next;
                }
                match sid {
                    Some(v) => out!(self.o, "{} ", v),
                    None => out!(self.o, "- "),
                }
                match loc {
                    Some(v) => out!(self.o, "{:04x} ", v),
                    None => out!(self.o, "- "),
                }
                match port {
                    Some(v) => out!(self.o, "{} ", v),
                    None => out!(self.o, "- "),
                }
                match steer {
                    Some(v) => hex(self.o, v),
                    None => out!(self.o, "-"),
                }
                if extra {
                    out!(self.o, " e");
                }
                ln!(self.o);
                Ok(())
            }
            "register" => {
                self.i.register_netdata();
                Ok(())
            }
            "publish" if a.get(2) == "dnssrp" => self.publish_dnssrp(a),
            "publish" if a.get(2) == "prefix" => {
                let cfg = parse_on_mesh(a, 3)?;
                self.i
                    .publish_on_mesh_prefix(cfg, self.now)
                    .map_err(E::from)
            }
            "publish" if a.get(2) == "route" => {
                let cfg = parse_route(a, 3)?;
                self.i
                    .publish_external_route(cfg, self.now)
                    .map_err(E::from)
            }
            "publish" if a.get(2) == "replace" => {
                let (addr, len) = parse_prefix(a.get(3))?;
                let old = NetPrefix::from_addr(&addr, len)?;
                let cfg = parse_route(a, 4)?;
                self.i
                    .replace_published_external_route(old, cfg, self.now)
                    .map_err(E::from)
            }
            "unpublish" if a.get(2) != "dnssrp" && !a.get(2).is_empty() => {
                let (addr, len) = parse_prefix(a.get(2))?;
                let prefix = NetPrefix::from_addr(&addr, len)?;
                self.i.unpublish_prefix(&prefix, self.now).map_err(E::from)
            }
            "unpublish" if a.get(2) == "dnssrp" => {
                self.i.unpublish_dns_srp_service(self.now);
                Ok(())
            }
            _ => Err(E::INVALID_COMMAND),
        }
    }

    /// `netdata publish dnssrp anycast <seq> [version]` and
    /// `netdata publish dnssrp unicast [addr] <port> [version]`.
    fn publish_dnssrp(&mut self, a: &Args<'_>) -> R {
        use opentrust_mesh::netdata::publisher::DnsSrpService;
        let svc = match a.get(3) {
            "anycast" => {
                let sequence_number = parse_u8(a.get(4))?;
                let mut version = 0;
                if !a.get(5).is_empty() {
                    version = parse_u8(a.get(5))?;
                    if !a.get(6).is_empty() {
                        return Err(E::INVALID_ARGS);
                    }
                }
                DnsSrpService::Anycast {
                    sequence_number,
                    version,
                }
            }
            "unicast" => {
                let mut k = 4;
                let address = parse_ip6(a.get(k)).ok();
                if address.is_some() {
                    k += 1;
                }
                let port = parse_u16(a.get(k))?;
                k += 1;
                let mut version = 0;
                if !a.get(k).is_empty() {
                    version = parse_u8(a.get(k))?;
                    k += 1;
                }
                if !a.get(k).is_empty() {
                    return Err(E::INVALID_ARGS);
                }
                match address {
                    Some(address) => DnsSrpService::Unicast {
                        address,
                        port,
                        version,
                    },
                    None => DnsSrpService::UnicastMlEid { port, version },
                }
            }
            _ => return Err(E::INVALID_ARGS),
        };
        self.i.publish_dns_srp_service(svc, self.now);
        Ok(())
    }

    pub(crate) fn prefix(&mut self, a: &Args<'_>) -> R {
        match a.get(1) {
            "add" => {
                let cfg = parse_on_mesh(a, 2)?;
                self.i.add_on_mesh_prefix(cfg).map_err(E::from)
            }
            "remove" => {
                let (addr, len) = parse_prefix(a.get(2))?;
                let prefix = NetPrefix::from_addr(&addr, len)?;
                self.i.remove_on_mesh_prefix(&prefix).map_err(E::from)
            }
            _ => Err(E::INVALID_COMMAND),
        }
    }

    pub(crate) fn route(&mut self, a: &Args<'_>) -> R {
        match a.get(1) {
            "add" => {
                let cfg = parse_route(a, 2)?;
                self.i.add_external_route(cfg).map_err(E::from)
            }
            "remove" => {
                let (addr, len) = parse_prefix(a.get(2))?;
                let prefix = NetPrefix::from_addr(&addr, len)?;
                self.i.remove_external_route(&prefix).map_err(E::from)
            }
            _ => Err(E::INVALID_COMMAND),
        }
    }
}

/// `<prefix> [padcrosnD] [high|med|low]` from argument `at` on (OT
/// `ParsePrefix`).
fn parse_on_mesh(a: &Args<'_>, at: usize) -> core::result::Result<OnMeshPrefixConfig, E> {
    let (addr, len) = parse_prefix(a.get(at))?;
    let prefix = NetPrefix::from_addr(&addr, len)?;
    let mut flags = BrFlags::default();
    let mut stable = false;
    let mut pref = 0i8;
    for arg in a.rest(at + 1) {
        if let Some(p) = parse_preference(arg) {
            pref = p;
            continue;
        }
        for c in arg.chars() {
            match c {
                'p' => flags = flags.with(BrFlags::PREFERRED, true),
                'a' => flags = flags.with(BrFlags::SLAAC, true),
                'd' => flags = flags.with(BrFlags::DHCP, true),
                'c' => flags = flags.with(BrFlags::CONFIGURE, true),
                'r' => flags = flags.with(BrFlags::DEFAULT_ROUTE, true),
                'o' => flags = flags.with(BrFlags::ON_MESH, true),
                's' => stable = true,
                'n' => flags = flags.with(BrFlags::ND_DNS, true),
                'D' => flags = flags.with(BrFlags::DP, true),
                '-' => {}
                _ => return Err(E::INVALID_ARGS),
            }
        }
    }
    flags.0 |= ((pref as u16) & 3) << 14;
    Ok(OnMeshPrefixConfig {
        prefix,
        flags,
        stable,
    })
}

/// `<prefix> [sn] [high|med|low]` from argument `at` on (OT `ParseRoute`).
fn parse_route(a: &Args<'_>, at: usize) -> core::result::Result<ExternalRouteConfig, E> {
    let (addr, len) = parse_prefix(a.get(at))?;
    let prefix = NetPrefix::from_addr(&addr, len)?;
    let mut cfg = ExternalRouteConfig {
        prefix,
        preference: 0,
        nat64: false,
        adv_pio: false,
        stable: false,
    };
    for arg in a.rest(at + 1) {
        if let Some(p) = parse_preference(arg) {
            cfg.preference = p;
            continue;
        }
        for c in arg.chars() {
            match c {
                's' => cfg.stable = true,
                'n' => cfg.nat64 = true,
                'p' => cfg.adv_pio = true,
                '-' => {}
                _ => return Err(E::INVALID_ARGS),
            }
        }
    }
    Ok(cfg)
}
