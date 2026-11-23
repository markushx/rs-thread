//! Thread parameters of the MLE and key management: `childmax`,
//! `childtimeout`, `childsupervision`, `pollperiod`, `keysequence`,
//! `parentpriority`, `preferrouterid`, `releaserouterid`, `routeridrange`,
//! `contextreusedelay`, `eidcache`, `mliid`, `detach` and
//! `partitionid preferred`.

use core::fmt::Write;

use rand_core::{CryptoRng, Rng};
use rs_thread_core::time::Duration;
use rs_thread_instance::InstanceCrypto;
use rs_thread_platform::SettingsStore;

use crate::Ctx;
use crate::util::{Args, E, R, ln, parse_hex_exact, parse_u16, parse_u32};
#[cfg(feature = "ftd")]
use crate::util::{out, parse_u8};

/// Smallest external poll period (OT `OPENTHREAD_CONFIG_MAC_MINIMUM_POLL_PERIOD`).
const MIN_POLL_PERIOD_MS: u32 = 10;
/// Largest external poll period (OT `kMaxExternalPeriod`).
const MAX_POLL_PERIOD_MS: u32 = (1 << 26) - 1;

impl<S, C, Rn, W> Ctx<'_, S, C, Rn, W>
where
    S: SettingsStore,
    C: InstanceCrypto,
    Rn: Rng + CryptoRng,
    W: Write,
{
    pub(crate) fn childtimeout(&mut self, a: &Args<'_>) -> R {
        if a.get(1).is_empty() {
            ln!(self.o, "{}", self.i.child_timeout());
            return Ok(());
        }
        let secs = parse_u32(a.get(1))?;
        self.i.set_child_timeout(secs, self.now);
        Ok(())
    }

    pub(crate) fn pollperiod(&mut self, a: &Args<'_>) -> R {
        if a.get(1).is_empty() {
            ln!(self.o, "{}", self.i.poll_period().as_millis());
            return Ok(());
        }
        let ms = parse_u32(a.get(1))?;
        if ms == 0 {
            self.i.set_poll_period(None);
            return Ok(());
        }
        if ms < MIN_POLL_PERIOD_MS {
            return Err(E::INVALID_ARGS);
        }
        let ms = ms.min(MAX_POLL_PERIOD_MS);
        self.i
            .set_poll_period(Some(Duration::from_millis(u64::from(ms))));
        Ok(())
    }

    /// `csl`, `csl channel|period|timeout [value]`, `csl accuracy|uncertainty`
    /// (the period is in microseconds, a multiple of 160 like OpenThread).
    pub(crate) fn csl(&mut self, a: &Args<'_>) -> R {
        match (a.get(1), a.get(2)) {
            ("", _) => {
                ln!(self.o, "channel: {}", self.i.csl_channel());
                ln!(self.o, "period: {}us", u32::from(self.i.csl_period()) * 160);
                ln!(self.o, "timeout: {}s", self.i.csl_timeout());
                Ok(())
            }
            ("accuracy", "") => {
                ln!(self.o, "{}", self.i.csl_clock_accuracy().0);
                Ok(())
            }
            ("uncertainty", "") => {
                ln!(self.o, "{}", self.i.csl_clock_accuracy().1);
                Ok(())
            }
            ("channel", v) => {
                let ch = crate::util::parse_u8(v)?;
                if !(11..=26).contains(&ch) && ch != 0 {
                    return Err(E::INVALID_ARGS);
                }
                self.i.set_csl_channel(ch, self.now);
                Ok(())
            }
            ("period", v) => {
                let us = parse_u32(v)?;
                if us % 160 != 0 || us / 160 > u32::from(u16::MAX) {
                    return Err(E::INVALID_ARGS);
                }
                self.i.set_csl_period((us / 160) as u16, self.now);
                Ok(())
            }
            ("timeout", v) => {
                self.i.set_csl_timeout(parse_u32(v)?, self.now);
                Ok(())
            }
            _ => Err(E::INVALID_COMMAND),
        }
    }

    pub(crate) fn childsupervision(&mut self, a: &Args<'_>) -> R {
        match (a.get(1), a.get(2)) {
            ("interval", "") => {
                ln!(self.o, "{}", self.i.supervision_interval());
                Ok(())
            }
            ("interval", v) => {
                let secs = parse_u16(v)?;
                self.i.set_supervision_interval(secs, self.now);
                Ok(())
            }
            ("checktimeout", "") => {
                ln!(self.o, "{}", self.i.supervision_check_timeout());
                Ok(())
            }
            ("checktimeout", v) => {
                let secs = parse_u16(v)?;
                self.i.set_supervision_check_timeout(secs, self.now);
                Ok(())
            }
            ("failcounter", "") => {
                ln!(self.o, "{}", self.i.supervision_check_failures());
                Ok(())
            }
            ("failcounter", "reset") => {
                self.i.reset_supervision_check_failures();
                Ok(())
            }
            _ => Err(E::INVALID_ARGS),
        }
    }

    pub(crate) fn keysequence(&mut self, a: &Args<'_>) -> R {
        match (a.get(1), a.get(2)) {
            ("counter", "") => {
                ln!(self.o, "{}", self.i.key_sequence_counter());
                Ok(())
            }
            ("counter", v) => {
                let n = parse_u32(v)?;
                self.i
                    .set_key_sequence_counter(n, self.now)
                    .map_err(E::from)
            }
            ("guardtime", "") => {
                ln!(self.o, "{}", self.i.key_switch_guard_time());
                Ok(())
            }
            ("guardtime", v) => {
                let h = parse_u32(v)?;
                self.i
                    .set_key_switch_guard_time(h.min(u32::from(u16::MAX)) as u16);
                Ok(())
            }
            _ => Err(E::INVALID_ARGS),
        }
    }

    pub(crate) fn mliid(&mut self, a: &Args<'_>) -> R {
        if !a.get(2).is_empty() {
            return Err(E::INVALID_ARGS);
        }
        let iid = parse_hex_exact::<8>(a.get(1))?;
        self.i
            .set_ml_eid_iid(rs_thread_core::types::Iid(iid))
            .map_err(E::from)
    }

    /// `radiofilter [enable|disable]` (OT `Interpreter::Process<Cmd("radiofilter")>`).
    pub(crate) fn radiofilter(&mut self, a: &Args<'_>) -> R {
        match a.get(1) {
            "" => {
                let s = if self.i.is_radio_filter_enabled() {
                    "Enabled"
                } else {
                    "Disabled"
                };
                ln!(self.o, "{s}");
                Ok(())
            }
            "enable" => {
                self.i.set_radio_filter(true);
                Ok(())
            }
            "disable" => {
                self.i.set_radio_filter(false);
                Ok(())
            }
            _ => Err(E::INVALID_ARGS),
        }
    }

    pub(crate) fn detach(&mut self, a: &Args<'_>) -> R {
        let asynchronous = a.get(1) == "async";
        self.i.detach_gracefully(self.now).map_err(E::from)?;
        if asynchronous {
            Ok(())
        } else {
            self.st.detaching = true;
            Err(E::PENDING)
        }
    }

    /// `Event::DetachedGracefully`: finish a blocking `detach`.
    pub(crate) fn detach_done(&mut self) {
        if core::mem::take(&mut self.st.detaching) {
            ln!(self.o, "Finished detaching");
            ln!(self.o, "Done");
        }
    }

    #[cfg(feature = "ftd")]
    pub(crate) fn childmax(&mut self, a: &Args<'_>) -> R {
        if a.get(1).is_empty() {
            ln!(self.o, "{}", self.i.max_children());
            return Ok(());
        }
        let n = parse_u16(a.get(1))?;
        self.i.set_max_children(usize::from(n)).map_err(E::from)
    }

    #[cfg(feature = "ftd")]
    pub(crate) fn releaserouterid(&mut self, a: &Args<'_>) -> R {
        let id = parse_u8(a.get(1))?;
        self.i.release_router_id(id, self.now).map_err(E::from)
    }

    #[cfg(feature = "ftd")]
    pub(crate) fn preferrouterid(&mut self, a: &Args<'_>) -> R {
        let id = parse_u8(a.get(1))?;
        self.i.set_preferred_router_id(id).map_err(E::from)
    }

    #[cfg(feature = "ftd")]
    pub(crate) fn routeridrange(&mut self, a: &Args<'_>) -> R {
        if a.get(1).is_empty() {
            let (min, max) = self.i.router_id_range();
            ln!(self.o, "{min} {max}");
            return Ok(());
        }
        let min = parse_u8(a.get(1))?;
        let max = parse_u8(a.get(2))?;
        if !a.get(3).is_empty() {
            return Err(E::INVALID_ARGS);
        }
        self.i.set_router_id_range(min, max).map_err(E::from)
    }

    #[cfg(feature = "ftd")]
    pub(crate) fn parentpriority(&mut self, a: &Args<'_>) -> R {
        if a.get(1).is_empty() {
            ln!(self.o, "{}", self.i.parent_priority());
            return Ok(());
        }
        let p: i8 = a.get(1).parse().map_err(|_| E::INVALID_ARGS)?;
        self.i.set_parent_priority(p).map_err(E::from)
    }

    #[cfg(feature = "ftd")]
    pub(crate) fn contextreusedelay(&mut self, a: &Args<'_>) -> R {
        if a.get(1).is_empty() {
            ln!(self.o, "{}", self.i.context_id_reuse_delay());
            return Ok(());
        }
        let secs = parse_u32(a.get(1))?;
        self.i.set_context_id_reuse_delay(secs);
        Ok(())
    }

    /// `partitionid preferred [<id>]` (the plain `partitionid` is in
    /// `basic`).
    #[cfg(feature = "ftd")]
    pub(crate) fn preferred_partition(&mut self, a: &Args<'_>) -> R {
        if a.get(2).is_empty() {
            ln!(self.o, "{}", self.i.preferred_partition_id());
            return Ok(());
        }
        let id = parse_u32(a.get(2))?;
        self.i.set_preferred_partition_id(id);
        Ok(())
    }

    #[cfg(feature = "ftd")]
    pub(crate) fn eidcache(&mut self) -> R {
        use rs_thread_net::resolver::EntryState;
        for e in self.i.address_cache() {
            let state = match e.state {
                EntryState::Cached => "cache",
                EntryState::Snooped => "snoop",
                EntryState::Query => "query",
                EntryState::QueryRetry => "retry",
            };
            out!(
                self.o,
                "{} {:04x} {} canEvict={}",
                e.target,
                e.rloc16.0,
                state,
                u8::from(e.can_evict)
            );
            if e.state != EntryState::Cached {
                out!(self.o, " timeout={}", e.timeout);
            }
            if e.state == EntryState::QueryRetry {
                out!(self.o, " retryDelay={} rampDown=0", e.retry_delay);
            }
            ln!(self.o);
        }
        Ok(())
    }
}
