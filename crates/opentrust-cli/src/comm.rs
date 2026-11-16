//! `commissioner` (OT `cli_commissioner.cpp`).

use core::fmt::Write;

use opentrust_core::bytes::Writer;
use opentrust_core::time::Duration;
use opentrust_instance::InstanceCrypto;
use opentrust_meshcop::commissioner::{CommissionerEvent, CommissionerState, JoinerKind};
use opentrust_meshcop::tlv::{WriterExt, ty as tlv};
use opentrust_platform::SettingsStore;
use rand_core::{CryptoRng, Rng};

use crate::Ctx;
use crate::util::{Args, E, R, hex, ln, parse_hex, parse_hex_exact, parse_u16, parse_u32};

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
    pub(crate) fn commissioner(&mut self, a: &Args<'_>) -> R {
        match a.get(1) {
            "start" => {
                // The ID and the Provisioning URL set before (OT keeps them
                // in the Commissioner).
                let mut id = heapless::String::<64>::new();
                let _ = id.push_str(self.i.commissioner_id());
                if id.is_empty() {
                    let _ = id.push_str(COMMISSIONER_ID);
                }
                let mut url = heapless::String::<64>::new();
                let _ = url.push_str(self.i.commissioner_provisioning_url());
                self.i
                    .commissioner_start(&id, Some(&url), self.now)
                    .map_err(E::from)
            }
            "id" => {
                if a.get(2).is_empty() {
                    let id = self.i.commissioner_id();
                    ln!(
                        self.o,
                        "{}",
                        if id.is_empty() { COMMISSIONER_ID } else { id }
                    );
                    Ok(())
                } else {
                    self.i.commissioner_set_id(a.get(2)).map_err(E::from)
                }
            }
            "provisioningurl" => {
                if a.get(2).is_empty() && a.rest(0).len() < 3 {
                    ln!(self.o, "{}", self.i.commissioner_provisioning_url());
                    Ok(())
                } else {
                    self.i
                        .commissioner_set_provisioning_url(a.get(2))
                        .map_err(E::from)
                }
            }
            "mgmtget" => {
                let mut tlvs = [0u8; 32];
                let mut n = 0;
                let mut i = 2;
                while i < a.rest(0).len() {
                    let ty = match a.get(i) {
                        "locator" => Some(tlv::BORDER_AGENT_LOCATOR),
                        "sessionid" => Some(tlv::COMMISSIONER_SESSION_ID),
                        "steeringdata" => Some(tlv::STEERING_DATA),
                        "joinerudpport" => Some(tlv::JOINER_UDP_PORT),
                        "-x" => None,
                        _ => return Err(E::INVALID_ARGS),
                    };
                    if n >= tlvs.len() {
                        return Err(E::NO_BUFS);
                    }
                    if let Some(t) = ty {
                        tlvs[n] = t;
                        n += 1;
                    } else {
                        i += 1;
                        n += parse_hex(a.get(i), &mut tlvs[n..])?;
                    }
                    i += 1;
                }
                self.i
                    .commissioner_mgmt_get(&tlvs[..n], self.now)
                    .map_err(E::from)
            }
            "mgmtset" => {
                if a.rest(0).len() < 3 {
                    return Err(E::INVALID_ARGS);
                }
                let mut out = [0u8; 255];
                let mut w = Writer::new(&mut out);
                let mut raw = [0u8; 32];
                let mut raw_len = 0;
                let mut i = 2;
                while i < a.rest(0).len() {
                    let key = a.get(i);
                    i += 1;
                    match key {
                        "locator" => {
                            w.border_agent_locator(parse_u16(a.get(i))?)
                                .map_err(|_| E::NO_BUFS)?;
                        }
                        "sessionid" => {
                            w.commissioner_session_id(parse_u16(a.get(i))?)
                                .map_err(|_| E::NO_BUFS)?;
                        }
                        "steeringdata" => {
                            let mut sd = [0u8; 16];
                            let n = parse_hex(a.get(i), &mut sd)?;
                            opentrust_core::tlv::write(&mut w, tlv::STEERING_DATA, &sd[..n])
                                .map_err(|_| E::NO_BUFS)?;
                        }
                        "joinerudpport" => {
                            w.joiner_udp_port(parse_u16(a.get(i))?)
                                .map_err(|_| E::NO_BUFS)?;
                        }
                        "-x" => raw_len = parse_hex(a.get(i), &mut raw)?,
                        _ => return Err(E::INVALID_ARGS),
                    }
                    i += 1;
                }
                w.write_slice(&raw[..raw_len]).map_err(|_| E::NO_BUFS)?;
                self.i
                    .commissioner_mgmt_set(w.written(), self.now)
                    .map_err(E::from)
            }
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
