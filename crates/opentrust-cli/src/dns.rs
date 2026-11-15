//! `dns resolve` and `dns config` (OT `cli_dns.cpp`).

use core::fmt::Write;
use core::net::SocketAddrV6;

use heapless::String;
use opentrust_instance::{DnsError, DnsOutcome, InstanceCrypto, QueryConfig, QueryId};
use opentrust_platform::SettingsStore;
use rand_core::{CryptoRng, Rng};

use crate::Ctx;
use crate::util::{Args, E, Ip6, R, error_name, ln, out, parse_ip6, parse_u16};

const DNS_PORT: u16 = 53;

#[derive(Debug)]
pub(crate) struct Pending {
    id: QueryId,
    host: String<64>,
}

fn dns_error(e: DnsError) -> E {
    match e {
        DnsError::NotFound => E::NOT_FOUND,
        DnsError::ResponseTimeout => E(28),
        DnsError::Parse => E::PARSE,
        DnsError::NoBufs => E::NO_BUFS,
        DnsError::Aborted => E(11),
        _ => E::FAILED,
    }
}

impl<S, C, Rn, W> Ctx<'_, S, C, Rn, W>
where
    S: SettingsStore,
    C: InstanceCrypto,
    Rn: Rng + CryptoRng,
    W: Write,
{
    pub(crate) fn dns(&mut self, a: &Args<'_>) -> R {
        match a.get(1) {
            "config" => {
                let addr = parse_ip6(a.get(2))?;
                let port = if a.get(3).is_empty() {
                    DNS_PORT
                } else {
                    parse_u16(a.get(3))?
                };
                self.i
                    .dns_set_default_server(Some(SocketAddrV6::new(addr, port, 0, 0)));
                Ok(())
            }
            "resolve" => {
                if self.st.dns.is_some() {
                    return Err(E::BUSY);
                }
                let host = a.get(2);
                let cfg = if a.get(3).is_empty() {
                    None
                } else {
                    let addr = parse_ip6(a.get(3))?;
                    let port = if a.get(4).is_empty() {
                        DNS_PORT
                    } else {
                        parse_u16(a.get(4))?
                    };
                    Some(QueryConfig::new(SocketAddrV6::new(addr, port, 0, 0)))
                };
                let host_s: String<64> = String::try_from(host).map_err(|_| E::INVALID_ARGS)?;
                let id = self.i.dns_resolve_address(host, cfg, self.now)?;
                self.st.dns = Some(Pending { id, host: host_s });
                Err(E::PENDING)
            }
            _ => Err(E::INVALID_COMMAND),
        }
    }

    pub(crate) fn dns_result(&mut self, id: QueryId) {
        let Some(p) = &self.st.dns else {
            return;
        };
        if p.id != id {
            return;
        }
        let Some(res) = self.i.dns_take_result_for(id) else {
            return;
        };
        let Some(p) = self.st.dns.take() else {
            return;
        };
        out!(self.o, "DNS response for {}", p.host);
        match res {
            DnsOutcome::Address(r) => {
                out!(self.o, " - ");
                for ai in &r.addrs {
                    out!(self.o, "{} TTL:{} ", Ip6(ai.addr), ai.ttl);
                }
                ln!(self.o);
                ln!(self.o, "Done");
            }
            DnsOutcome::Failed(e) => {
                ln!(self.o);
                let E(n) = dns_error(e);
                ln!(self.o, "Error {}: {}", n, error_name(n));
            }
            _ => {
                ln!(self.o);
                ln!(self.o, "Done");
            }
        }
    }
}
