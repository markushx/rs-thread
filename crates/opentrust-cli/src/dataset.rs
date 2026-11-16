//! The `dataset` command group (OT `cli_dataset.cpp`): a local dataset
//! buffer that is edited component by component and committed as the Active
//! or Pending Dataset.

use core::fmt::Write;

use opentrust_core::types::{ExtPanId, NetworkKey, NetworkName, Prefix64, Pskc};
use opentrust_instance::InstanceCrypto;
use opentrust_meshcop::dataset::{Dataset, DatasetType};
use opentrust_meshcop::tlv::SecurityPolicy;
use opentrust_mle::tlv::Timestamp;
use opentrust_platform::SettingsStore;
use rand_core::{CryptoRng, Rng};

use crate::Ctx;
use crate::util::{
    Args, E, R, hex, ln, out, parse_hex, parse_hex_exact, parse_ip6, parse_u8, parse_u16,
    parse_u32, parse_u64,
};

/// Channel of a dataset created by `dataset init new`.
const NEW_NETWORK_CHANNEL: u8 = 11;

fn print_prefix<W: Write>(o: &mut W, p: &Prefix64) {
    let g = |i: usize| u16::from_be_bytes([p.0[i], p.0[i + 1]]);
    ln!(o, "{:x}:{:x}:{:x}:{:x}::/64", g(0), g(2), g(4), g(6));
}

fn print_policy<W: Write>(o: &mut W, p: &SecurityPolicy) {
    out!(o, "{} ", p.rotation_time);
    for (on, c) in [
        (p.obtain_network_key, 'o'),
        (p.native_commissioning, 'n'),
        (p.routers, 'r'),
        (p.external_commissioning, 'c'),
        (p.commercial_commissioning, 'C'),
        (p.autonomous_enrollment, 'e'),
        (p.network_key_provisioning, 'p'),
    ] {
        if on {
            let _ = o.write_char(c);
        }
    }
    ln!(o, " {}", p.version_threshold_for_routing);
}

/// Print a dataset in OT's `dataset active` format.
fn print_dataset<W: Write>(o: &mut W, d: &Dataset, non_sensitive_only: bool) -> R {
    d.validate().map_err(E::from)?;
    let t = d.tlvs();
    if let Some(ts) = d.timestamp(DatasetType::Pending) {
        ln!(o, "Pending Timestamp: {}", ts.seconds);
    }
    if let Some(ts) = d.timestamp(DatasetType::Active) {
        ln!(o, "Active Timestamp: {}", ts.seconds);
    }
    if let Ok(c) = t.channel() {
        ln!(o, "Channel: {}", c.channel);
    }
    if let Ok(m) = t.channel_mask() {
        ln!(o, "Channel Mask: 0x{m:08x}");
    }
    if let Ok(v) = t.delay_timer() {
        ln!(o, "Delay: {v}");
    }
    if let Ok(x) = t.ext_pan_id() {
        out!(o, "Ext PAN ID: ");
        hex(o, &x.0);
        ln!(o);
    }
    if let Ok(p) = t.mesh_local_prefix() {
        out!(o, "Mesh Local Prefix: ");
        print_prefix(o, &p);
    }
    if let Ok(k) = t.network_key() {
        if non_sensitive_only {
            ln!(o, "Network Key: [Redacted]");
        } else {
            out!(o, "Network Key: ");
            hex(o, &k.0);
            ln!(o);
        }
    }
    if let Ok(n) = t.network_name() {
        ln!(o, "Network Name: {}", n.as_str());
    }
    if let Ok(p) = t.pan_id() {
        ln!(o, "PAN ID: 0x{p:04x}");
    }
    if let Ok(k) = t.pskc() {
        if non_sensitive_only {
            ln!(o, "PSKc: [Redacted]");
        } else {
            out!(o, "PSKc: ");
            hex(o, &k.0);
            ln!(o);
        }
    }
    if let Ok(p) = t.security_policy() {
        out!(o, "Security Policy: ");
        print_policy(o, &p);
    }
    Ok(())
}

fn parse_policy(a: &Args<'_>, i: usize) -> Result<SecurityPolicy, E> {
    let mut p = SecurityPolicy {
        rotation_time: parse_u16(a.get(i))?,
        obtain_network_key: false,
        native_commissioning: false,
        routers: false,
        external_commissioning: false,
        commercial_commissioning: false,
        autonomous_enrollment: false,
        network_key_provisioning: false,
        toble_link: false,
        non_ccm_routers: false,
        version_threshold_for_routing: 0,
    };
    for c in a.get(i + 1).chars() {
        match c {
            'o' => p.obtain_network_key = true,
            'n' => p.native_commissioning = true,
            'r' => p.routers = true,
            'c' => p.external_commissioning = true,
            'C' => p.commercial_commissioning = true,
            'e' => p.autonomous_enrollment = true,
            'p' => p.network_key_provisioning = true,
            'R' => p.toble_link = true,
            'N' => p.non_ccm_routers = true,
            _ => return Err(E::INVALID_ARGS),
        }
    }
    if !a.get(i + 2).is_empty() {
        p.version_threshold_for_routing = parse_u8(a.get(i + 2))?;
    }
    Ok(p)
}

/// Set the dataset component `name` from the argument at `i` (the value);
/// returns the number of value arguments consumed.
fn set_component(d: &mut Dataset, name: &str, a: &Args<'_>, i: usize) -> Result<usize, E> {
    let v = a.get(i);
    match name {
        "activetimestamp" | "pendingtimestamp" => {
            let ty = if name == "activetimestamp" {
                DatasetType::Active
            } else {
                DatasetType::Pending
            };
            let ts = Timestamp {
                seconds: parse_u64(v)?,
                ticks: 0,
                authoritative: false,
            };
            d.set_timestamp(ty, &ts)?;
        }
        "channel" => d.set_channel(parse_u8(v)?)?,
        "channelmask" => d.set_channel_mask(parse_u32(v)?)?,
        "delay" | "delaytimer" => d.set_delay_timer(parse_u32(v)?)?,
        "extpanid" => d.set_ext_pan_id(&ExtPanId(parse_hex_exact::<8>(v)?))?,
        "meshlocalprefix" | "localprefix" => {
            let p = if let Some((addr, _)) = v.split_once('/') {
                parse_ip6(addr)?
            } else {
                parse_ip6(v)?
            };
            let mut b = [0u8; 8];
            b.copy_from_slice(&p.octets()[..8]);
            d.set_mesh_local_prefix(&Prefix64(b))?;
        }
        "networkkey" => d.set_network_key(&NetworkKey(parse_hex_exact::<16>(v)?))?,
        "networkname" => d.set_network_name(&NetworkName::new(v)?)?,
        "panid" => d.set_pan_id(parse_u16(v)?)?,
        "pskc" => d.set_pskc(&Pskc(parse_hex_exact::<16>(v)?))?,
        "securitypolicy" => {
            d.set_security_policy(&parse_policy(a, i)?)?;
            return Ok(if parse_u8(a.get(i + 2)).is_ok() { 3 } else { 2 });
        }
        _ => return Err(E::INVALID_ARGS),
    }
    Ok(1)
}

/// TLV type of a dataset component name (`dataset mgmtgetcommand`).
#[cfg(feature = "commissioning")]
fn component_tlv(name: &str) -> Option<u8> {
    Some(match name {
        "activetimestamp" => 14,
        "pendingtimestamp" => 51,
        "networkkey" => 5,
        "networkname" => 3,
        "extpanid" => 2,
        "meshlocalprefix" | "localprefix" => 7,
        "delay" | "delaytimer" => 52,
        "panid" => 1,
        "channel" => 0,
        "pskc" => 4,
        "securitypolicy" => 12,
        "channelmask" => 53,
        _ => return None,
    })
}

impl<S, C, Rn, W> Ctx<'_, S, C, Rn, W>
where
    S: SettingsStore,
    C: InstanceCrypto,
    Rn: Rng + CryptoRng,
    W: Write,
{
    pub(crate) fn dataset(&mut self, a: &Args<'_>) -> R {
        match a.get(1) {
            "" => print_dataset(self.o, &self.st.dataset, false),
            "init" => match a.get(2) {
                "active" => {
                    self.st.dataset = self.i.active_dataset(self.now).ok_or(E::NOT_FOUND)?;
                    Ok(())
                }
                "pending" => {
                    self.st.dataset = self.i.pending_dataset(self.now).ok_or(E::NOT_FOUND)?;
                    Ok(())
                }
                "new" => {
                    self.st.dataset = self.i.create_dataset(NEW_NETWORK_CHANNEL)?;
                    Ok(())
                }
                "tlvs" => {
                    let mut b = [0u8; 254];
                    let n = parse_hex(a.get(3), &mut b)?;
                    self.st.dataset = Dataset::from_tlvs_unchecked(&b[..n])?;
                    Ok(())
                }
                _ => Err(E::INVALID_ARGS),
            },
            "active" => {
                let d = self.i.active_dataset(self.now).ok_or(E::NOT_FOUND)?;
                self.show(a.get(2), &d)
            }
            "pending" => {
                let d = self.i.pending_dataset(self.now).ok_or(E::NOT_FOUND)?;
                self.show(a.get(2), &d)
            }
            "set" => {
                let mut b = [0u8; 254];
                let n = parse_hex(a.get(3), &mut b)?;
                let d = Dataset::from_tlvs(&b[..n])?;
                match a.get(2) {
                    "active" => self.i.set_active_dataset(&d, self.now).map_err(E::from),
                    "pending" => self.i.set_pending_dataset(&d, self.now).map_err(E::from),
                    _ => Err(E::INVALID_ARGS),
                }
            }
            #[cfg(feature = "commissioning")]
            "mgmtsetcommand" => self.mgmt_set(a),
            #[cfg(feature = "commissioning")]
            "mgmtgetcommand" => self.mgmt_get(a),
            "clear" => {
                self.st.dataset.clear();
                Ok(())
            }
            "tlvs" => {
                hex(self.o, self.st.dataset.as_bytes());
                ln!(self.o);
                Ok(())
            }
            "commit" => match a.get(2) {
                "active" => self
                    .i
                    .set_active_dataset(&self.st.dataset, self.now)
                    .map_err(E::from),
                "pending" => self
                    .i
                    .set_pending_dataset(&self.st.dataset, self.now)
                    .map_err(E::from),
                _ => Err(E::INVALID_ARGS),
            },
            "activetimestamp" | "pendingtimestamp" | "channel" | "channelmask" | "delay"
            | "delaytimer" | "extpanid" | "meshlocalprefix" | "localprefix" | "networkkey"
            | "networkname" | "panid" | "pskc" | "securitypolicy" => self.component(a),
            _ => Err(E::INVALID_COMMAND),
        }
    }

    fn show(&mut self, opt: &str, d: &Dataset) -> R {
        match opt {
            "" => print_dataset(self.o, d, false),
            "-x" => {
                hex(self.o, d.as_bytes());
                ln!(self.o);
                Ok(())
            }
            "-ns" => print_dataset(self.o, d, true),
            _ => Err(E::INVALID_ARGS),
        }
    }

    /// `dataset <component> [value...]`: print or set one component of the
    /// buffer.
    fn component(&mut self, a: &Args<'_>) -> R {
        let name = a.get(1);
        let v = a.get(2);
        let d = &mut self.st.dataset;
        if v.is_empty() {
            let t = d.tlvs();
            match name {
                "activetimestamp" => {
                    let ts = d.timestamp(DatasetType::Active).ok_or(E::NOT_FOUND)?;
                    ln!(self.o, "{}", ts.seconds);
                }
                "pendingtimestamp" => {
                    let ts = d.timestamp(DatasetType::Pending).ok_or(E::NOT_FOUND)?;
                    ln!(self.o, "{}", ts.seconds);
                }
                "channel" => ln!(self.o, "{}", t.channel().map_err(E::from)?.channel),
                "channelmask" => ln!(self.o, "0x{:08x}", t.channel_mask().map_err(E::from)?),
                "delay" | "delaytimer" => ln!(self.o, "{}", t.delay_timer().map_err(E::from)?),
                "extpanid" => {
                    hex(self.o, &t.ext_pan_id().map_err(E::from)?.0);
                    ln!(self.o);
                }
                "meshlocalprefix" | "localprefix" => {
                    print_prefix(self.o, &t.mesh_local_prefix().map_err(E::from)?)
                }
                "networkkey" => {
                    hex(self.o, &t.network_key().map_err(E::from)?.0);
                    ln!(self.o);
                }
                "networkname" => ln!(self.o, "{}", t.network_name().map_err(E::from)?.as_str()),
                "panid" => ln!(self.o, "0x{:04x}", t.pan_id().map_err(E::from)?),
                "pskc" => {
                    hex(self.o, &t.pskc().map_err(E::from)?.0);
                    ln!(self.o);
                }
                _ => print_policy(self.o, &t.security_policy().map_err(E::from)?),
            }
            return Ok(());
        }
        set_component(d, name, a, 2)?;
        Ok(())
    }

    /// `dataset mgmtsetcommand active|pending [<component> <value>]... [-x tlvs]`
    /// (OT `otDatasetSendMgmtActiveSet` / `PendingSet`).
    #[cfg(feature = "commissioning")]
    fn mgmt_set(&mut self, a: &Args<'_>) -> R {
        let active = match a.get(2) {
            "active" => true,
            "pending" => false,
            _ => return Err(E::INVALID_ARGS),
        };
        let mut d = Dataset::new();
        let n = a.rest(0).len();
        let mut i = 3;
        while i < n {
            let name = a.get(i);
            i += 1;
            if name == "-x" {
                let mut b = [0u8; 254];
                let len = parse_hex(a.get(i), &mut b)?;
                let other = Dataset::from_tlvs_unchecked(&b[..len])?;
                d.write_tlvs_from(&other)?;
                i += 1;
            } else {
                i += set_component(&mut d, name, a, i)?;
            }
        }
        self.i
            .dataset_mgmt_set(active, &d, self.now)
            .map_err(E::from)
    }

    /// `dataset mgmtgetcommand active|pending [address <ip6>] [<component>]...
    /// [-x tlvs]` (OT `otDatasetSendMgmtActiveGet` / `PendingGet`).
    #[cfg(feature = "commissioning")]
    fn mgmt_get(&mut self, a: &Args<'_>) -> R {
        let active = match a.get(2) {
            "active" => true,
            "pending" => false,
            _ => return Err(E::INVALID_ARGS),
        };
        let mut types = [0u8; 40];
        let mut len = 0;
        let mut dest = None;
        let n = a.rest(0).len();
        let mut i = 3;
        while i < n {
            let name = a.get(i);
            i += 1;
            if let Some(t) = component_tlv(name) {
                if len < types.len() {
                    types[len] = t;
                    len += 1;
                }
            } else if name == "-x" {
                len += parse_hex(a.get(i), &mut types[len..])?;
                i += 1;
            } else if name == "address" {
                dest = Some(parse_ip6(a.get(i))?);
                i += 1;
            } else {
                return Err(E::INVALID_ARGS);
            }
        }
        self.i
            .dataset_mgmt_get(active, &types[..len], dest, self.now)
            .map_err(E::from)
    }
}
