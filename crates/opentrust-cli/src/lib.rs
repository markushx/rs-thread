#![no_std]
//! OpenThread-compatible CLI for the OpenTrust Thread stack.
//!
//! Part of OpenTrust, a pure Rust implementation of the Thread 1.4.1 protocol.
//!
//! The interpreter reads one command line at a time and writes OpenThread's
//! output (`Done`, `Error <n>: <Name>`, tables and values, `\r\n` line ends)
//! to a [`core::fmt::Write`]. It owns no instance, no line editor and no
//! allocator: the caller passes the [`Instance`] and the current time with
//! every call, which suits the `with` closure of `opentrust-embassy` as well
//! as a host loop.
//!
//! ```text
//! cli.process_line(inst, now, "ifconfig up", &mut out);
//! cli.handle_event(inst, now, &event, &mut out);   // for each Instance event
//! cli.poll(inst, now, &mut out);                   // timers (ping), regularly
//! ```
//!
//! Command groups are cargo features (`dataset`, `scan`, `ping`, `tables`,
//! `netdata`, `srp`, `dns`, `udp`, `diag`, `commissioning`; `ftd` for the router
//! commands) so that firmware only pays for what it ships. A command of a
//! disabled group, or one that OpenTrust does not implement, answers
//! `Error 35: InvalidCommand` like OpenThread does for an unknown command.

mod basic;
#[cfg(feature = "cert-log")]
extern crate std;
#[cfg(feature = "cert-log")]
pub mod cert_log;
#[cfg(feature = "commissioning")]
mod comm;
#[cfg(feature = "dataset")]
mod dataset;
#[cfg(feature = "diag")]
mod diag;
#[cfg(feature = "dns")]
mod dns;
#[cfg(feature = "joiner")]
mod joiner;
mod net;
#[cfg(feature = "netdata")]
mod netdata;
#[cfg(feature = "ping")]
mod ping;
#[cfg(feature = "scan")]
mod scan;
mod settings;
#[cfg(feature = "srp")]
mod srp;
#[cfg(feature = "tables")]
mod tables;
#[cfg(feature = "udp")]
mod udp;
mod util;

use core::fmt::Write;

use opentrust_core::time::Instant;
use opentrust_instance::{Event, Instance, InstanceCrypto};
use opentrust_platform::SettingsStore;
use rand_core::{CryptoRng, Rng};

use util::{Args, E, R, error_name, ln};

/// Version string of the `version` command.
pub const VERSION: &str = concat!("OpenTrust/", env!("CARGO_PKG_VERSION"), "; Thread 1.4.1");

/// State of the interpreter between commands.
#[derive(Debug)]
pub(crate) struct State {
    pub legacy: basic::Legacy,
    pub reset: bool,
    /// A blocking `detach` waits for the end of the graceful detach.
    pub detaching: bool,
    #[cfg(feature = "dataset")]
    pub dataset: opentrust_meshcop::dataset::Dataset,
    #[cfg(feature = "ping")]
    pub ping: Option<ping::Ping>,
    #[cfg(feature = "scan")]
    pub scan: Option<scan::Kind>,
    #[cfg(feature = "diag")]
    pub diag: Option<diag::Pending>,
    #[cfg(feature = "dns")]
    pub dns: Option<dns::Pending>,
    #[cfg(feature = "udp")]
    pub udp: Option<opentrust_instance::UdpSocket>,
    #[cfg(feature = "srp")]
    pub srp: srp::Services,
}

/// The interpreter.
#[derive(Debug)]
pub struct Cli {
    st: State,
}

impl Default for Cli {
    fn default() -> Self {
        Self::new()
    }
}

/// One command invocation: the interpreter state, the instance, the clock and
/// the output.
pub(crate) struct Ctx<'a, S, C: InstanceCrypto, Rn, W> {
    pub st: &'a mut State,
    pub i: &'a mut Instance<S, C, Rn>,
    pub now: Instant,
    pub o: &'a mut W,
}

impl Cli {
    /// A new interpreter.
    pub fn new() -> Self {
        Self {
            st: State {
                legacy: basic::Legacy::default(),
                reset: false,
                detaching: false,
                #[cfg(feature = "dataset")]
                dataset: opentrust_meshcop::dataset::Dataset::new(),
                #[cfg(feature = "ping")]
                ping: None,
                #[cfg(feature = "scan")]
                scan: None,
                #[cfg(feature = "diag")]
                diag: None,
                #[cfg(feature = "dns")]
                dns: None,
                #[cfg(feature = "udp")]
                udp: None,
                #[cfg(feature = "srp")]
                srp: srp::Services::new(),
            },
        }
    }

    /// Run one command line and write its output, ending with `Done` or
    /// `Error <n>: <Name>` (nothing for a command that completes later, such
    /// as `ping` or `scan`: its async output ends with `Done`). Empty lines
    /// do nothing.
    pub fn process_line<S, C, Rn, W>(
        &mut self,
        inst: &mut Instance<S, C, Rn>,
        now: Instant,
        line: &str,
        out: &mut W,
    ) where
        S: SettingsStore,
        C: InstanceCrypto,
        Rn: Rng + CryptoRng,
        W: Write,
    {
        let line = line.trim();
        if line.is_empty() {
            return;
        }
        let r = match Args::parse(line) {
            Some(args) => {
                let mut ctx = Ctx {
                    st: &mut self.st,
                    i: inst,
                    now,
                    o: out,
                };
                ctx.dispatch(&args)
            }
            None => Err(E::INVALID_ARGS),
        };
        output_result(out, r);
    }

    /// Turn an instance event into OpenThread's asynchronous output (ping
    /// replies, scan results, joiner and commissioner state, UDP receive,
    /// DNS responses). Call it for every event the instance reports.
    pub fn handle_event<S, C, Rn, W>(
        &mut self,
        inst: &mut Instance<S, C, Rn>,
        now: Instant,
        event: &Event,
        out: &mut W,
    ) where
        S: SettingsStore,
        C: InstanceCrypto,
        Rn: Rng + CryptoRng,
        W: Write,
    {
        let mut ctx = Ctx {
            st: &mut self.st,
            i: inst,
            now,
            o: out,
        };
        ctx.event(event);
    }

    /// Run the timers of the interpreter (ping interval and timeout) and
    /// print datagrams waiting on the `udp` socket. Call it whenever
    /// [`next_deadline`](Self::next_deadline) is reached, and regularly
    /// (every 100 ms is fine) when UDP readiness events are not forwarded to
    /// [`handle_event`](Self::handle_event).
    pub fn poll<S, C, Rn, W>(&mut self, inst: &mut Instance<S, C, Rn>, now: Instant, out: &mut W)
    where
        S: SettingsStore,
        C: InstanceCrypto,
        Rn: Rng + CryptoRng,
        W: Write,
    {
        let mut ctx = Ctx {
            st: &mut self.st,
            i: inst,
            now,
            o: out,
        };
        ctx.poll_timers();
    }

    /// Whether `reset` or `factoryreset` asked for a restart of the device
    /// (OT reboots the node); the flag is cleared by this call.
    pub fn take_reset_request(&mut self) -> bool {
        core::mem::take(&mut self.st.reset)
    }

    /// The next time [`poll`](Self::poll) has work.
    pub fn next_deadline(&self) -> Option<Instant> {
        let mut next: Option<Instant> = None;
        #[cfg(feature = "ping")]
        if let Some(p) = &self.st.ping {
            next = Some(p.deadline());
        }
        #[cfg(feature = "diag")]
        if let Some(p) = &self.st.diag {
            next = Some(next.map_or(p.deadline(), |n| n.min(p.deadline())));
        }
        next
    }
}

/// Write `Done` or the error line.
pub(crate) fn output_result<W: Write>(out: &mut W, r: R) {
    match r {
        Ok(()) => ln!(out, "Done"),
        Err(e) if e == E::PENDING => {}
        Err(E(n)) => ln!(out, "Error {}: {}", n, error_name(n)),
    }
}

impl<S, C, Rn, W> Ctx<'_, S, C, Rn, W>
where
    S: SettingsStore,
    C: InstanceCrypto,
    Rn: Rng + CryptoRng,
    W: Write,
{
    fn dispatch(&mut self, a: &Args<'_>) -> R {
        match a.get(0) {
            "help" => self.help(),
            "version" => self.version(a),
            "state" => self.state(a),
            "ifconfig" => self.ifconfig(a),
            "thread" => self.thread(a),
            "channel" => self.channel(a),
            "panid" => self.panid(a),
            "extpanid" => self.extpanid(a),
            "networkname" => self.networkname(a),
            "networkkey" => self.networkkey(a),
            "extaddr" => self.extaddr(a),
            "eui64" => self.eui64(),
            "rloc16" => self.rloc16(),
            "leaderdata" => self.leaderdata(),
            "partitionid" => self.partitionid(a),
            "childtimeout" => self.childtimeout(a),
            "pollperiod" => self.pollperiod(a),
            "csl" => self.csl(a),
            "childsupervision" => self.childsupervision(a),
            "keysequence" => self.keysequence(a),
            "mliid" => self.mliid(a),
            "detach" => self.detach(a),
            #[cfg(feature = "ftd")]
            "childmax" => self.childmax(a),
            #[cfg(feature = "ftd")]
            "releaserouterid" => self.releaserouterid(a),
            #[cfg(feature = "ftd")]
            "preferrouterid" => self.preferrouterid(a),
            #[cfg(feature = "ftd")]
            "routeridrange" => self.routeridrange(a),
            #[cfg(feature = "ftd")]
            "networkidtimeout" => self.router_u8(a, |c| &mut c.network_id_timeout_secs),
            #[cfg(feature = "ftd")]
            "parentpriority" => self.parentpriority(a),
            #[cfg(feature = "ftd")]
            "contextreusedelay" => self.contextreusedelay(a),
            #[cfg(feature = "ftd")]
            "eidcache" => self.eidcache(),
            "mode" => self.mode(a),
            "ipaddr" => self.ipaddr(a),
            "ipmaddr" => self.ipmaddr(a),
            "factoryreset" => {
                self.i.factory_reset();
                self.st.reset = true;
                Err(E::PENDING)
            }
            "reset" => self.reset(),
            #[cfg(feature = "ftd")]
            "routerselectionjitter" => self.router_u8(a, |c| &mut c.selection_jitter_secs),
            #[cfg(feature = "ftd")]
            "routerupgradethreshold" => self.router_u8(a, |c| &mut c.upgrade_threshold),
            #[cfg(feature = "ftd")]
            "routerdowngradethreshold" => self.router_u8(a, |c| &mut c.downgrade_threshold),
            #[cfg(feature = "ftd")]
            "leaderweight" => self.router_u8(a, |c| &mut c.leader_weight),
            #[cfg(feature = "ftd")]
            "routereligible" => self.routereligible(a),
            #[cfg(feature = "dataset")]
            "dataset" => self.dataset(a),
            #[cfg(feature = "ping")]
            "ping" => self.ping_cmd(a),
            #[cfg(feature = "tables")]
            "child" => self.child(a),
            #[cfg(all(feature = "tables", feature = "ftd"))]
            "router" => self.router(a),
            #[cfg(feature = "tables")]
            "neighbor" => self.neighbor(a),
            #[cfg(feature = "tables")]
            "counters" => self.counters(a),
            #[cfg(feature = "netdata")]
            "netdata" => self.netdata(a),
            #[cfg(feature = "netdata")]
            "prefix" => self.prefix(a),
            #[cfg(feature = "netdata")]
            "route" => self.route(a),
            #[cfg(feature = "scan")]
            "scan" => self.scan_cmd(a),
            #[cfg(feature = "scan")]
            "discover" => self.discover(a),
            #[cfg(feature = "srp")]
            "srp" => self.srp(a),
            #[cfg(feature = "dns")]
            "dns" => self.dns(a),
            #[cfg(feature = "udp")]
            "udp" => self.udp(a),
            #[cfg(feature = "diag")]
            "networkdiagnostic" => self.networkdiagnostic(a),
            #[cfg(feature = "commissioning")]
            "commissioner" => self.commissioner(a),
            #[cfg(feature = "joiner")]
            "joiner" => self.joiner(a),
            _ => Err(E::INVALID_COMMAND),
        }
    }

    fn event(&mut self, ev: &Event) {
        match ev {
            #[cfg(feature = "ping")]
            Event::PingReply => self.ping_replies(),
            #[cfg(feature = "scan")]
            Event::ActiveScanResult(_)
            | Event::ActiveScanDone
            | Event::EnergyScanResult { .. }
            | Event::EnergyScanDone
            | Event::DiscoverResult(_)
            | Event::DiscoverDone => self.scan_event(ev),
            #[cfg(feature = "diag")]
            Event::DiagAnswer => self.diag_answers(),
            #[cfg(feature = "udp")]
            Event::UdpReadable(s) => self.udp_readable(*s),
            #[cfg(feature = "dns")]
            Event::DnsResult(id) => self.dns_result(*id),
            #[cfg(feature = "joiner")]
            Event::JoinerResult(r) => self.joiner_result(*r),
            #[cfg(feature = "commissioning")]
            Event::Commissioner(e) => self.commissioner_event(e),
            #[cfg(feature = "commissioning")]
            Event::EnergyReport => self.energy_report(),
            #[cfg(feature = "commissioning")]
            Event::PanIdConflict {
                pan_id,
                channel_mask,
            } => self.pan_id_conflict(*pan_id, *channel_mask),
            Event::DetachedGracefully => self.detach_done(),
            _ => {}
        }
    }

    fn poll_timers(&mut self) {
        #[cfg(feature = "ping")]
        self.ping_poll();
        #[cfg(feature = "diag")]
        self.diag_poll();
        // Drivers that do not forward `Event::UdpReadable` (the embassy
        // wrapper keeps UDP readiness out of its event queue) rely on this.
        #[cfg(feature = "udp")]
        if let Some(s) = self.st.udp {
            self.udp_readable(s);
        }
    }
}
