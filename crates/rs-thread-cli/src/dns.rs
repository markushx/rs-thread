//! `dns` (OT `cli_dns.cpp`): `config`, `resolve`, `browse`, `service`,
//! `servicehost`, `query`.

use core::fmt::Write;
use core::net::{Ipv6Addr, SocketAddrV6};

use heapless::String;
use rs_thread_core::time::Duration;
use rs_thread_instance::{
    DnsError, DnsOutcome, InstanceCrypto, PartialConfig, QueryConfig, QueryId, ResolvedService,
    ServiceMode,
};
use rs_thread_platform::SettingsStore;
use rand_core::{CryptoRng, Rng};

use crate::Ctx;
use crate::util::{
    Args, E, Ip6, R, error_name, ln, out, parse_ip6, parse_u8, parse_u16, parse_u32, unescape,
};

const DNS_PORT: u16 = 53;

#[derive(Debug)]
pub(crate) enum Query {
    Address(String<96>),
    Browse(String<96>),
    Service(String<96>, String<96>),
    #[cfg(feature = "srp-server")]
    Record(String<200>),
}

#[derive(Debug)]
pub(crate) struct Pending {
    id: QueryId,
    q: Query,
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

fn mode_name(m: ServiceMode) -> &'static str {
    match m {
        ServiceMode::Srv => "srv",
        ServiceMode::Txt => "txt",
        ServiceMode::SrvTxt => "srv_txt",
        ServiceMode::SrvTxtSeparate => "srv_txt_sep",
        ServiceMode::SrvTxtOptimize => "srv_txt_opt",
    }
}

fn parse_mode(s: &str) -> Result<ServiceMode, E> {
    Ok(match s {
        "def" => ServiceMode::SrvTxtOptimize,
        "srv" => ServiceMode::Srv,
        "txt" => ServiceMode::Txt,
        "srv_txt" => ServiceMode::SrvTxt,
        "srv_txt_sep" => ServiceMode::SrvTxtSeparate,
        "srv_txt_opt" => ServiceMode::SrvTxtOptimize,
        _ => return Err(E::INVALID_ARGS),
    })
}

fn parse_bool(s: &str) -> Result<bool, E> {
    match s {
        "1" | "true" => Ok(true),
        "0" | "false" => Ok(false),
        _ => Err(E::INVALID_ARGS),
    }
}

/// The optional config arguments `[server] [port] [timeout] [attempts]
/// [recursion] [mode] [transport]` starting at `a[k]`.
fn partial_config(a: &Args<'_>, k: usize) -> Result<Option<PartialConfig>, E> {
    if a.get(k).is_empty() {
        return Ok(None);
    }
    let addr = parse_ip6(a.get(k))?;
    let mut c = PartialConfig::default();
    let mut port = DNS_PORT;
    if !a.get(k + 1).is_empty() {
        port = parse_u16(a.get(k + 1))?;
        if !a.get(k + 2).is_empty() {
            let t = parse_u32(a.get(k + 2))?;
            c.timeout = (t != 0).then(|| Duration::from_millis(u64::from(t)));
            if !a.get(k + 3).is_empty() {
                let n = parse_u8(a.get(k + 3))?;
                c.attempts = (n != 0).then_some(n);
                if !a.get(k + 4).is_empty() {
                    c.recursion = Some(parse_bool(a.get(k + 4))?);
                    if !a.get(k + 5).is_empty() {
                        c.mode = Some(parse_mode(a.get(k + 5))?);
                        match a.get(k + 6) {
                            "" | "udp" => {}
                            _ => return Err(E::INVALID_ARGS),
                        }
                    }
                }
            }
        }
    }
    c.server = Some(SocketAddrV6::new(
        addr,
        if port == 0 { DNS_PORT } else { port },
        0,
        0,
    ));
    Ok(Some(c))
}

impl<S, C, Rn, W> Ctx<'_, S, C, Rn, W>
where
    S: SettingsStore,
    C: InstanceCrypto,
    Rn: Rng + CryptoRng,
    W: Write,
{
    /// The per-query config (`None`: the default config).
    fn query_config(&self, a: &Args<'_>, k: usize) -> Result<Option<QueryConfig>, E> {
        let Some(p) = partial_config(a, k)? else {
            return Ok(None);
        };
        let d = self.i.dns_default_config();
        Ok(Some(QueryConfig {
            server: p.server.unwrap_or(d.server),
            response_timeout: p.timeout.unwrap_or(d.response_timeout),
            max_tx_attempts: p.attempts.unwrap_or(d.max_tx_attempts),
            recursion_desired: p.recursion.unwrap_or(d.recursion_desired),
            service_mode: p.mode.unwrap_or(d.service_mode),
        }))
    }

    pub(crate) fn dns(&mut self, a: &Args<'_>) -> R {
        match a.get(1) {
            "config" => {
                if a.get(2).is_empty() {
                    let d = self.i.dns_default_config();
                    ln!(
                        self.o,
                        "Server: [{}]:{}",
                        Ip6(*d.server.ip()),
                        d.server.port()
                    );
                    ln!(
                        self.o,
                        "ResponseTimeout: {} ms",
                        d.response_timeout.as_millis()
                    );
                    ln!(self.o, "MaxTxAttempts: {}", d.max_tx_attempts);
                    ln!(
                        self.o,
                        "RecursionDesired: {}",
                        if d.recursion_desired { "yes" } else { "no" }
                    );
                    ln!(self.o, "ServiceMode: {}", mode_name(d.service_mode));
                    return Ok(());
                }
                let p = partial_config(a, 2)?.unwrap_or_default();
                self.i.dns_set_default_config(p);
                Ok(())
            }
            "resolve" => {
                if a.get(2).is_empty() {
                    return Err(E::INVALID_ARGS);
                }
                let cfg = self.query_config(a, 3)?;
                let host: String<96> = String::try_from(a.get(2)).map_err(|_| E::INVALID_ARGS)?;
                let id = self.i.dns_resolve_address(a.get(2), cfg, self.now)?;
                self.start(id, Query::Address(host))
            }
            "browse" => {
                if a.get(2).is_empty() {
                    return Err(E::INVALID_ARGS);
                }
                let cfg = self.query_config(a, 3)?;
                let name: String<96> = String::try_from(a.get(2)).map_err(|_| E::INVALID_ARGS)?;
                let id = self.i.dns_browse(a.get(2), cfg, self.now)?;
                self.start(id, Query::Browse(name))
            }
            "service" | "servicehost" => {
                if a.get(3).is_empty() {
                    return Err(E::INVALID_ARGS);
                }
                let cfg = self.query_config(a, 4)?;
                let label: String<96> = unescape(a.get(2))?;
                let svc: String<96> = String::try_from(a.get(3)).map_err(|_| E::INVALID_ARGS)?;
                let id = self
                    .i
                    .dns_resolve_service(&label, a.get(3), cfg, self.now)?;
                self.start(id, Query::Service(label, svc))
            }
            #[cfg(feature = "srp-server")]
            "query" => {
                let rrtype = parse_u16(a.get(2))?;
                if a.get(4).is_empty() {
                    return Err(E::INVALID_ARGS);
                }
                let cfg = self.query_config(a, 5)?;
                let first: String<96> = unescape(a.get(3))?;
                let mut name: String<200> = String::new();
                let _ = write!(name, "{}.{}", first, a.get(4));
                let id = self
                    .i
                    .dns_query_record(rrtype, &first, a.get(4), cfg, self.now)?;
                self.start(id, Query::Record(name))
            }
            _ => Err(E::INVALID_COMMAND),
        }
    }

    fn start(&mut self, id: QueryId, q: Query) -> R {
        if self.st.dns.is_some() {
            self.i.dns_cancel(id);
            return Err(E::BUSY);
        }
        self.st.dns = Some(Pending { id, q });
        Err(E::PENDING)
    }

    fn output_service_info(&mut self, indent: usize, s: &ResolvedService) {
        let pad = "    ";
        let p = &pad[..indent.min(4)];
        ln!(
            self.o,
            "{p}Port:{}, Priority:{}, Weight:{}, TTL:{}",
            s.port,
            s.priority,
            s.weight,
            s.ttl
        );
        ln!(self.o, "{p}Host:{}.", s.host.trim_end_matches('.'));
        let (addr, ttl) = s
            .addrs
            .first()
            .map_or((Ipv6Addr::UNSPECIFIED, 0), |a| (a.addr, a.ttl));
        ln!(self.o, "{p}HostAddress:{} TTL:{}", Ip6(addr), ttl);
        out!(self.o, "{p}TXT:");
        crate::srp::output_txt(self.o, &s.txt);
        ln!(self.o, " TTL:{}", s.txt_ttl);
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
        let failed = if let DnsOutcome::Failed(e) = &res {
            Some(dns_error(*e))
        } else {
            None
        };
        match (&p.q, &res) {
            (Query::Address(h), _) => {
                out!(self.o, "DNS response for {h} - ");
                if let DnsOutcome::Address(r) = &res {
                    for ai in &r.addrs {
                        out!(self.o, "{} TTL:{} ", Ip6(ai.addr), ai.ttl);
                    }
                    ln!(self.o);
                }
            }
            (Query::Browse(n), _) => {
                ln!(self.o, "DNS browse response for {n}");
                if let DnsOutcome::Browse(v) = &res {
                    for i in v {
                        ln!(self.o, "{}", i.label);
                        if let Some(info) = &i.info {
                            self.output_service_info(4, info);
                        }
                        ln!(self.o);
                    }
                }
            }
            (Query::Service(l, n), _) => {
                ln!(
                    self.o,
                    "DNS service resolution response for {l} for service {n}"
                );
                if let DnsOutcome::Service(s) = &res {
                    self.output_service_info(0, s);
                    ln!(self.o);
                }
            }
            #[cfg(feature = "srp-server")]
            (Query::Record(n), _) => {
                ln!(self.o, "DNS query response for {n}. ");
                if let DnsOutcome::Records(m) = &res {
                    self.output_records(m);
                }
            }
        }
        match failed {
            None => ln!(self.o, "Done"),
            Some(E(n)) => ln!(self.o, "Error {}: {}", n, error_name(n)),
        }
    }

    #[cfg(feature = "srp-server")]
    fn output_records(&mut self, msg: &[u8]) {
        use rs_thread_instance::Section;
        for (i, (sec, r)) in rs_thread_instance::records_of(msg).enumerate() {
            ln!(self.o, "{i})");
            let sec = match sec {
                Section::Answer => "answer",
                Section::Authority => "authority",
                Section::Additional => "additional",
            };
            ln!(
                self.o,
                "    RecordType:{}, RecordLength:{}, TTL:{}, Section:{}",
                r.rtype,
                10 + r.rdata.len(),
                r.ttl,
                sec
            );
            let mut name: String<130> = String::new();
            let _ = r.name.fmt_dotted(&mut name);
            ln!(self.o, "    Name:{}.", name.trim_end_matches('.'));
            out!(self.o, "    RecordData:[");
            crate::util::hex(self.o, &r.rdata[..r.rdata.len().min(255)]);
            if r.rdata.len() > 255 {
                out!(self.o, "...");
            }
            ln!(self.o, "]");
        }
    }
}
