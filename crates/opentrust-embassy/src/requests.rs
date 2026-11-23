//! Async wrappers for requests the instance answers with an event or a
//! result queue: ping, joiner, SRP and DNS.
//!
//! Each wrapper issues the request through [`OpenTrust::with`] and waits on a
//! per-request waiter. The waiter checks the instance's own result for *its*
//! request (the ping reply with its identifier, the DNS result with its
//! query id, the service state, the joiner result), so concurrent requests do
//! not steal each other's results, and the events still reach
//! [`OpenTrust::next_event`] and [`OpenTrust::wait_changed`] unchanged. The
//! results are removed from the instance's queues, though: do not take the
//! same result with [`OpenTrust::with`] (`take_ping_reply`,
//! `dns_take_result`) while a wrapper for it is pending.
//!
//! Timeouts are driven by the [`run`](OpenTrust::run) future (it wakes at the
//! earliest request deadline), so they need no timer of their own.

#[cfg(feature = "ping")]
use core::net::Ipv6Addr;

use embassy_sync::blocking_mutex::raw::RawMutex;
#[cfg(feature = "dns-client")]
use heapless::Vec;
use opentrust_core::Error;
use opentrust_core::time::{Duration, Instant};
#[cfg(feature = "dns-client")]
use opentrust_instance::Instance;
#[cfg(feature = "ping")]
use opentrust_instance::PingReply;
#[cfg(feature = "dns-client")]
use opentrust_instance::{
    BrowseInstance, DnsError, DnsOutcome, MAX_BROWSE_INSTANCES, QueryConfig, QueryId,
    ResolvedAddresses, ResolvedService,
};
use opentrust_instance::{DiscoverResult, InstanceCrypto};
#[cfg(feature = "srp-client")]
use opentrust_instance::{ItemState, ServiceId};
use opentrust_meshcop::joiner::JoinerConfig;
use opentrust_platform::{Clock, SettingsStore};
use rand_core::{CryptoRng, Rng};

use crate::state::{OpenTrust, State};

/// Identifier of the echo requests of [`OpenTrust::ping`].
#[cfg(feature = "ping")]
const PING_ID: u16 = 0x4f54;

/// Error of the async DNS wrappers.
#[cfg(feature = "dns-client")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum DnsClientError {
    /// The request was rejected (no server, queue full, invalid name, ...).
    Request(Error),
    /// The query ran and failed (including its timeout).
    Failed(DnsError),
}

struct OnDrop<F: FnMut()>(Option<F>);

impl<F: FnMut()> Drop for OnDrop<F> {
    fn drop(&mut self) {
        if let Some(f) = &mut self.0 {
            f();
        }
    }
}

impl<M, K, S, C, R> OpenTrust<'_, M, K, S, C, R>
where
    M: RawMutex,
    K: Clock,
    S: SettingsStore,
    C: InstanceCrypto,
    R: Rng + CryptoRng,
{
    /// Wait until `f` returns a value; [`Error::ResponseTimeout`] once
    /// `deadline` has passed. `f` runs on every state event and at the
    /// deadline, with the node locked.
    pub(crate) async fn wait_for<T>(
        &self,
        deadline: Option<Instant>,
        mut f: impl FnMut(&mut State<S, C, R>) -> Option<T>,
    ) -> Result<T, Error> {
        core::future::poll_fn(|cx| {
            let now = self.now();
            self.res.lock(|s| {
                let r = f(s);
                s.drain();
                if let Some(v) = r {
                    return core::task::Poll::Ready(Ok(v));
                }
                if let Some(d) = deadline {
                    if now >= d {
                        return core::task::Poll::Ready(Err(Error::ResponseTimeout));
                    }
                    if s.req_deadline.is_none_or(|e| d < e) {
                        s.req_deadline = Some(d);
                        // The driver sleeps until its own next deadline:
                        // let it pick up the new one.
                        self.res.kick().signal(());
                    }
                }
                s.req_waiters.register(cx.waker());
                core::task::Poll::Pending
            })
        })
        .await
    }

    /// Send an ICMPv6 echo request with `payload` and wait for its reply
    /// ([`Error::ResponseTimeout`] after `timeout`).
    #[cfg(feature = "ping")]
    pub async fn ping(
        &self,
        dst: Ipv6Addr,
        src: Option<Ipv6Addr>,
        payload: &[u8],
        timeout: Duration,
    ) -> Result<PingReply, Error> {
        let deadline = self.now().saturating_add(timeout);
        let seq = self.res.lock(|s| {
            s.ping_seq = s.ping_seq.wrapping_add(1);
            s.ping_seq
        });
        self.with(|i, now| i.ping(dst, src, PING_ID, seq, payload, now))?;
        self.wait_for(Some(deadline), |s| {
            s.inst.take_ping_reply_matching(PING_ID, seq)
        })
        .await
    }

    /// Join a Thread network as a Joiner (see [`Instance::joiner_start`]) and
    /// wait for the result. `Ok` means the credentials are the Active Dataset
    /// and Thread was started. Dropping the future stops joining.
    pub async fn joiner_start(
        &self,
        pskd: &str,
        cfg: &JoinerConfig<'_>,
        scan_channels: u32,
    ) -> Result<(), Error> {
        self.res.lock(|s| s.joiner_result = None);
        self.with(|i, now| i.joiner_start(pskd, cfg, scan_channels, now))?;
        let mut guard = OnDrop(Some(|| self.with(|i, now| i.joiner_stop(now))));
        let r = self.wait_for(None, |s| s.joiner_result.take()).await;
        guard.0 = None;
        r?
    }

    /// Wait until the SRP client has registered the host
    /// ([`Error::ResponseTimeout`] after `timeout`, if given).
    #[cfg(feature = "srp-client")]
    pub async fn srp_wait_host_registered(&self, timeout: Option<Duration>) -> Result<(), Error> {
        let deadline = timeout.map(|t| self.now().saturating_add(t));
        self.wait_for(deadline, |s| {
            (s.inst.srp_host_state() == ItemState::Registered).then_some(())
        })
        .await
    }

    /// Wait until the SRP client has registered service `id`
    /// ([`Error::NotFound`] if it is not a known service).
    #[cfg(feature = "srp-client")]
    pub async fn srp_wait_service_registered(
        &self,
        id: ServiceId,
        timeout: Option<Duration>,
    ) -> Result<(), Error> {
        let deadline = timeout.map(|t| self.now().saturating_add(t));
        let mut missing = false;
        let r = self
            .wait_for(deadline, |s| match s.inst.srp_service_state(id) {
                Some(ItemState::Registered) => Some(()),
                Some(_) => None,
                None => {
                    missing = true;
                    Some(())
                }
            })
            .await;
        if missing { Err(Error::NotFound) } else { r }
    }

    #[cfg(feature = "dns-client")]
    async fn dns_query(
        &self,
        start: impl FnOnce(&mut Instance<S, C, R>, Instant) -> Result<QueryId, Error>,
    ) -> Result<DnsOutcome, DnsClientError> {
        let id = self.with(start).map_err(DnsClientError::Request)?;
        let mut guard = OnDrop(Some(|| self.with(|i, _| i.dns_cancel(id))));
        let r = self
            .wait_for(None, |s| s.inst.dns_take_result_for(id))
            .await;
        guard.0 = None;
        match r {
            Ok(DnsOutcome::Failed(e)) => Err(DnsClientError::Failed(e)),
            Ok(o) => Ok(o),
            Err(e) => Err(DnsClientError::Request(e)),
        }
    }

    /// Scan for Thread networks with the MLE discovery scan (see
    /// [`Instance::discover_start`]; OT `otThreadDiscover`, esp-rs
    /// `OpenThread::scan`): `f` is called with every answering network and
    /// finally with `None`. `channels` is a bit mask (`0`: all 2.4 GHz
    /// channels); each channel takes 300 ms.
    ///
    /// [`Error::Busy`] while a scan runs. Dropping the future does not stop
    /// the scan (the instance has no cancel); a new scan fails with `Busy`
    /// until it ends.
    pub async fn scan(
        &self,
        channels: u32,
        mut f: impl FnMut(Option<&DiscoverResult>),
    ) -> Result<(), Error> {
        self.res.lock(|s| s.disc_q.clear());
        self.with(|i, now| i.discover_start(channels, 0xffff, false, now))?;
        loop {
            match self.wait_for(None, |s| s.disc_q.pop_front()).await? {
                Some(r) => f(Some(&r)),
                None => {
                    f(None);
                    return Ok(());
                }
            }
        }
    }

    /// Energy scan (see [`Instance::energy_scan_start`]): `f(channel, max_rssi)`
    /// per channel of `channels` (`0`: all supported) after `duration` each;
    /// the RSSI is 127 if the radio cannot measure. [`Error::NotImplemented`]
    /// if the radio has no energy scan, [`Error::Busy`] while a scan runs.
    pub async fn energy_scan(
        &self,
        channels: u32,
        duration: Duration,
        mut f: impl FnMut(u8, i8),
    ) -> Result<(), Error> {
        self.res.lock(|s| s.energy_q.clear());
        self.with(|i, now| i.energy_scan_start(channels, duration, now))?;
        loop {
            match self.wait_for(None, |s| s.energy_q.pop_front()).await? {
                Some((channel, rssi)) => f(channel, rssi),
                None => return Ok(()),
            }
        }
    }

    /// Resolve the AAAA records of `host` (see
    /// [`Instance::dns_resolve_address`]).
    #[cfg(feature = "dns-client")]
    pub async fn dns_resolve_address(
        &self,
        host: &str,
        config: Option<QueryConfig>,
    ) -> Result<ResolvedAddresses, DnsClientError> {
        match self
            .dns_query(|i, now| i.dns_resolve_address(host, config, now))
            .await?
        {
            DnsOutcome::Address(a) => Ok(a),
            _ => Err(DnsClientError::Request(Error::InvalidState)),
        }
    }

    /// Browse for the instances of `service` (see [`Instance::dns_browse`]).
    #[cfg(feature = "dns-client")]
    pub async fn dns_browse(
        &self,
        service: &str,
        config: Option<QueryConfig>,
    ) -> Result<Vec<BrowseInstance, MAX_BROWSE_INSTANCES>, DnsClientError> {
        match self
            .dns_query(|i, now| i.dns_browse(service, config, now))
            .await?
        {
            DnsOutcome::Browse(b) => Ok(b),
            _ => Err(DnsClientError::Request(Error::InvalidState)),
        }
    }

    /// Resolve a service instance (see [`Instance::dns_resolve_service`]).
    #[cfg(feature = "dns-client")]
    pub async fn dns_resolve_service(
        &self,
        instance: &str,
        service: &str,
        config: Option<QueryConfig>,
    ) -> Result<ResolvedService, DnsClientError> {
        match self
            .dns_query(|i, now| i.dns_resolve_service(instance, service, config, now))
            .await?
        {
            DnsOutcome::Service(s) => Ok(s),
            _ => Err(DnsClientError::Request(Error::InvalidState)),
        }
    }
}
