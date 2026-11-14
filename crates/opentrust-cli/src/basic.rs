//! `help`, `version`, `state`, `ifconfig`, `thread`, the network parameter
//! getters and setters, `mode`, `reset` and the router parameters.

use core::fmt::Write;

use opentrust_core::types::{ExtPanId, NetworkKey, NetworkName};
use opentrust_instance::InstanceCrypto;
use opentrust_meshcop::dataset::Dataset;
use opentrust_mle::Role;
use opentrust_mle::tlv::DeviceMode;
use opentrust_platform::SettingsStore;
use rand_core::{CryptoRng, Rng};

use crate::util::{Args, E, R, hex, ln, parse_hex_exact, parse_u8, parse_u16};
use crate::{Ctx, VERSION};

/// Network parameters set with the individual commands (`channel`, `panid`,
/// `extpanid`, `networkname`, `networkkey`) while Thread is disabled. OT
/// applies them to the MAC and key manager directly; here they are folded
/// into the Active Dataset by `thread start`.
#[derive(Debug, Default)]
pub(crate) struct Legacy {
    pub channel: Option<u8>,
    pub pan_id: Option<u16>,
    pub ext_pan_id: Option<[u8; 8]>,
    pub name: Option<NetworkName>,
    pub key: Option<[u8; 16]>,
}

impl Legacy {
    fn is_empty(&self) -> bool {
        self.channel.is_none()
            && self.pan_id.is_none()
            && self.ext_pan_id.is_none()
            && self.name.is_none()
            && self.key.is_none()
    }
}

pub(crate) const COMMANDS: &[&str] = &[
    "channel",
    "child",
    "commissioner",
    "counters",
    "dataset",
    "discover",
    "dns",
    "eui64",
    "extaddr",
    "extpanid",
    "factoryreset",
    "help",
    "ifconfig",
    "ipaddr",
    "ipmaddr",
    "joiner",
    "leaderdata",
    "leaderweight",
    "mode",
    "neighbor",
    "netdata",
    "networkkey",
    "networkname",
    "panid",
    "partitionid",
    "ping",
    "prefix",
    "reset",
    "rloc16",
    "route",
    "router",
    "routerdowngradethreshold",
    "routereligible",
    "routerselectionjitter",
    "routerupgradethreshold",
    "scan",
    "srp",
    "state",
    "thread",
    "udp",
    "version",
];

pub(crate) fn role_name(r: Role) -> &'static str {
    match r {
        Role::Disabled => "disabled",
        Role::Detached => "detached",
        Role::Child => "child",
        Role::Router => "router",
        Role::Leader => "leader",
    }
}

impl<S, C, Rn, W> Ctx<'_, S, C, Rn, W>
where
    S: SettingsStore,
    C: InstanceCrypto,
    Rn: Rng + CryptoRng,
    W: Write,
{
    #[allow(clippy::match_like_matches_macro)]
    pub(crate) fn help(&mut self) -> R {
        for c in COMMANDS {
            let enabled = match *c {
                "child" | "counters" | "neighbor" => cfg!(feature = "tables"),
                "router" => cfg!(all(feature = "tables", feature = "ftd")),
                "routerselectionjitter"
                | "routerupgradethreshold"
                | "routerdowngradethreshold"
                | "routereligible"
                | "leaderweight" => cfg!(feature = "ftd"),
                "commissioner" | "joiner" => cfg!(feature = "commissioning"),
                "dataset" => cfg!(feature = "dataset"),
                "discover" | "scan" => cfg!(feature = "scan"),
                "dns" => cfg!(feature = "dns"),
                "netdata" | "prefix" | "route" => cfg!(feature = "netdata"),
                "ping" => cfg!(feature = "ping"),
                "srp" => cfg!(feature = "srp"),
                "udp" => cfg!(feature = "udp"),
                _ => true,
            };
            if enabled {
                ln!(self.o, "{c}");
            }
        }
        Ok(())
    }

    pub(crate) fn version(&mut self, a: &Args<'_>) -> R {
        match a.get(1) {
            "" => ln!(self.o, "{}", VERSION),
            "api" => ln!(self.o, "1"),
            _ => return Err(E::INVALID_ARGS),
        }
        Ok(())
    }

    pub(crate) fn state(&mut self, a: &Args<'_>) -> R {
        match a.get(1) {
            "" => {
                ln!(self.o, "{}", role_name(self.i.role()));
                Ok(())
            }
            #[cfg(feature = "ftd")]
            "leader" => {
                self.start_pending()?;
                self.i.become_leader(self.now).map_err(E::from)
            }
            #[cfg(not(feature = "ftd"))]
            "leader" => Err(E::NOT_IMPLEMENTED),
            "detached" | "child" | "router" => Err(E::NOT_IMPLEMENTED),
            _ => Err(E::INVALID_ARGS),
        }
    }

    pub(crate) fn ifconfig(&mut self, a: &Args<'_>) -> R {
        match a.get(1) {
            "" => {
                ln!(
                    self.o,
                    "{}",
                    if self.i.ip6_enabled() { "up" } else { "down" }
                );
            }
            "up" => self.i.ip6_set_enabled(true),
            "down" => self.i.ip6_set_enabled(false),
            _ => return Err(E::INVALID_COMMAND),
        }
        Ok(())
    }

    pub(crate) fn thread(&mut self, a: &Args<'_>) -> R {
        match a.get(1) {
            "start" => {
                self.start_pending()?;
                self.i.thread_start(self.now).map_err(E::from)
            }
            "stop" => {
                self.i.thread_stop();
                Ok(())
            }
            "version" => {
                ln!(self.o, "5");
                Ok(())
            }
            _ => Err(E::INVALID_COMMAND),
        }
    }

    /// Fold the parameters of the legacy setters into the Active Dataset
    /// before Thread starts; a missing dataset is created.
    fn start_pending(&mut self) -> R {
        if self.st.legacy.is_empty() {
            return Ok(());
        }
        let l = core::mem::take(&mut self.st.legacy);
        let mut d = match self.i.active_dataset(self.now) {
            Some(d) => d,
            None => self.i.create_dataset(l.channel.unwrap_or(11))?,
        };
        if let Some(c) = l.channel {
            d.set_channel(c)?;
        }
        if let Some(p) = l.pan_id {
            d.set_pan_id(p)?;
        }
        if let Some(x) = l.ext_pan_id {
            d.set_ext_pan_id(&ExtPanId(x))?;
        }
        if let Some(n) = &l.name {
            d.set_network_name(n)?;
        }
        if let Some(k) = l.key {
            d.set_network_key(&NetworkKey(k))?;
        }
        self.i.set_active_dataset(&d, self.now)?;
        Ok(())
    }

    fn active(&self) -> Option<Dataset> {
        self.i.active_dataset(self.now)
    }

    fn require_disabled(&self) -> R {
        if self.i.role() == Role::Disabled {
            Ok(())
        } else {
            Err(E::INVALID_STATE)
        }
    }

    pub(crate) fn channel(&mut self, a: &Args<'_>) -> R {
        if a.get(1).is_empty() {
            let c = self
                .st
                .legacy
                .channel
                .or_else(|| {
                    self.active()
                        .and_then(|d| d.tlvs().channel().ok())
                        .map(|c| c.channel as u8)
                })
                .unwrap_or(0);
            ln!(self.o, "{c}");
            return Ok(());
        }
        let c = parse_u8(a.get(1))?;
        if !(11..=26).contains(&c) {
            return Err(E::INVALID_ARGS);
        }
        self.require_disabled()?;
        self.st.legacy.channel = Some(c);
        Ok(())
    }

    pub(crate) fn panid(&mut self, a: &Args<'_>) -> R {
        if a.get(1).is_empty() {
            let p = self
                .st
                .legacy
                .pan_id
                .or_else(|| self.active().and_then(|d| d.tlvs().pan_id().ok()))
                .unwrap_or(0xffff);
            ln!(self.o, "0x{p:04x}");
            return Ok(());
        }
        let p = parse_u16(a.get(1))?;
        self.require_disabled()?;
        self.st.legacy.pan_id = Some(p);
        Ok(())
    }

    pub(crate) fn extpanid(&mut self, a: &Args<'_>) -> R {
        if a.get(1).is_empty() {
            let x = self
                .st
                .legacy
                .ext_pan_id
                .or_else(|| {
                    self.active()
                        .and_then(|d| d.tlvs().ext_pan_id().ok())
                        .map(|x| x.0)
                })
                .unwrap_or([0; 8]);
            hex(self.o, &x);
            ln!(self.o);
            return Ok(());
        }
        let x = parse_hex_exact::<8>(a.get(1))?;
        self.require_disabled()?;
        self.st.legacy.ext_pan_id = Some(x);
        Ok(())
    }

    pub(crate) fn networkname(&mut self, a: &Args<'_>) -> R {
        if a.get(1).is_empty() {
            let n = self
                .st
                .legacy
                .name
                .or_else(|| self.active().and_then(|d| d.tlvs().network_name().ok()));
            ln!(self.o, "{}", n.as_ref().map_or("", |n| n.as_str()));
            return Ok(());
        }
        let n = NetworkName::new(a.get(1)).map_err(E::from)?;
        self.require_disabled()?;
        self.st.legacy.name = Some(n);
        Ok(())
    }

    pub(crate) fn networkkey(&mut self, a: &Args<'_>) -> R {
        if a.get(1).is_empty() {
            let k = self
                .st
                .legacy
                .key
                .or_else(|| {
                    self.active()
                        .and_then(|d| d.tlvs().network_key().ok())
                        .map(|k| k.0)
                })
                .unwrap_or([0; 16]);
            hex(self.o, &k);
            ln!(self.o);
            return Ok(());
        }
        let k = parse_hex_exact::<16>(a.get(1))?;
        self.require_disabled()?;
        self.st.legacy.key = Some(k);
        Ok(())
    }

    pub(crate) fn extaddr(&mut self, a: &Args<'_>) -> R {
        if !a.get(1).is_empty() {
            return Err(E::INVALID_ARGS);
        }
        hex(self.o, &self.i.ext_address().0);
        ln!(self.o);
        Ok(())
    }

    pub(crate) fn eui64(&mut self) -> R {
        hex(self.o, &self.i.eui64().0);
        ln!(self.o);
        Ok(())
    }

    pub(crate) fn rloc16(&mut self) -> R {
        ln!(self.o, "{:04x}", self.i.rloc16().0);
        Ok(())
    }

    pub(crate) fn partitionid(&mut self) -> R {
        ln!(self.o, "{}", self.i.partition_id());
        Ok(())
    }

    pub(crate) fn leaderdata(&mut self) -> R {
        if !self.i.role().is_attached() {
            return Err(E(16)); // Detached
        }
        let d = self.i.leader_data();
        ln!(self.o, "Partition ID: {}", d.partition_id);
        ln!(self.o, "Weighting: {}", d.weighting);
        ln!(self.o, "Data Version: {}", d.data_version);
        ln!(self.o, "Stable Data Version: {}", d.stable_data_version);
        ln!(self.o, "Leader Router ID: {}", d.leader_router_id);
        Ok(())
    }

    pub(crate) fn mode(&mut self, a: &Args<'_>) -> R {
        if a.get(1).is_empty() {
            let m = self.i.link_mode();
            let mut any = false;
            for (on, c) in [
                (m.rx_on_when_idle(), 'r'),
                (m.full_thread_device(), 'd'),
                (m.full_network_data(), 'n'),
            ] {
                if on {
                    let _ = self.o.write_char(c);
                    any = true;
                }
            }
            if !any {
                let _ = self.o.write_char('-');
            }
            ln!(self.o);
            return Ok(());
        }
        let (mut r, mut d, mut n) = (false, false, false);
        if a.get(1) != "-" {
            for c in a.get(1).chars() {
                match c {
                    'r' => r = true,
                    'd' => d = true,
                    'n' => n = true,
                    _ => return Err(E::INVALID_ARGS),
                }
            }
        }
        self.i
            .set_link_mode(DeviceMode::new(r, d, n), self.now)
            .map_err(E::from)
    }

    pub(crate) fn reset(&mut self) -> R {
        self.i.thread_stop();
        self.st.reset = true;
        Err(E::PENDING)
    }

    #[cfg(feature = "ftd")]
    pub(crate) fn router_u8(
        &mut self,
        a: &Args<'_>,
        f: fn(&mut opentrust_mle::RouterConfig) -> &mut u8,
    ) -> R {
        let slot = f(self.i.router_config_mut());
        if a.get(1).is_empty() {
            let v = *slot;
            ln!(self.o, "{v}");
            return Ok(());
        }
        *slot = parse_u8(a.get(1))?;
        Ok(())
    }

    #[cfg(feature = "ftd")]
    pub(crate) fn routereligible(&mut self, a: &Args<'_>) -> R {
        let c = self.i.router_config_mut();
        match a.get(1) {
            "" => {
                let e = if c.eligible { "Enabled" } else { "Disabled" };
                ln!(self.o, "{e}");
            }
            "enable" => c.eligible = true,
            "disable" => c.eligible = false,
            _ => return Err(E::INVALID_COMMAND),
        }
        Ok(())
    }
}
