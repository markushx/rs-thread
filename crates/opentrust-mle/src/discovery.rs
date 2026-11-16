//! MLE Discovery (Thread 1.4.1 section 4.13) and Announce (section 4.14)
//! transport.
//!
//! The MeshCoP content of a Discovery Request / Response (the sub-TLVs of
//! the Thread Discovery TLV) is built and parsed by `opentrust-meshcop`;
//! this module is the MLE side:
//!
//! - [`Mle::send_discovery_request`]: an unsecured Discovery Request to
//!   `ff02::2` on a given channel and PAN ID (the scanner steps through
//!   the channels).
//! - Discovery Request reception at an eligible router (feature `ftd`,
//!   OT `Mle::HandleDiscoveryRequest`): the request is checked with
//!   [`MleEnv::accept_discovery_request`] and answered after a random
//!   delay of 1 to 250 ms with an unsecured Discovery Response whose
//!   content comes from [`MleEnv::discovery_response`].
//! - Discovery Response reception ([`MleEnv::discovery_response_received`]),
//!   also on a disabled device.
//! - [`Mle::send_announce`] and the Announce handling of OT
//!   `Mle::HandleAnnounce`: an Announce from an older network (or an
//!   orphan) is answered with our own Announce on the sender's channel; one
//!   from a network with a newer Active Timestamp starts the Announce
//!   attach: [`MleEvent::AnnounceFromNewerNetwork`] is raised, and after
//!   `ANNOUNCE_PROCESS_TIMEOUT` (250 ms) the device leaves its attachment,
//!   switches to the announced channel and PAN ID
//!   ([`MleEnv::set_pan_channel_and_id`]) and attaches to any partition
//!   there. Success informs the previous channel with an Announce; failure
//!   restores the previous channel and PAN ID and detaches. A newer
//!   Announce received meanwhile replaces a pending one only if its Active
//!   Timestamp (seconds) is larger.
//! - Orphan Announces sent by a detached device after its Parent Requests
//!   went unanswered are part of the attach procedure ([`crate::attach`]).

use core::net::Ipv6Addr;

use opentrust_core::time::Duration;
use opentrust_core::time::Instant;
use opentrust_core::types::{Channel, PanId};
use opentrust_core::{Error, Result};

use crate::endpoint::MleRx;
#[cfg(feature = "ftd")]
use crate::env::DiscoveryRequestInfo;
use crate::env::{DiscoveryResponseInfo, MleEnv, MleEvent, Role, TxOptions};
use crate::message::Command;
use crate::mle::{Mle, RxClass};
use crate::tlv::{ChannelValue, Timestamp};

/// Maximum random delay of a Discovery Response in milliseconds
/// (`kDiscoveryMaxJitter`).
pub const DISCOVERY_MAX_JITTER_MS: u16 = 250;
/// Longest Thread Discovery TLV value this core sends or accepts.
pub const MAX_DISCOVERY_TLV_LEN: usize = 200;

/// MeshCoP Discovery Request sub-TLV type.
#[cfg(feature = "ftd")]
const MC_DISCOVERY_REQUEST: u8 = 128;
/// MeshCoP Extended PAN ID sub-TLV type.
#[cfg(feature = "ftd")]
const MC_EXT_PAN_ID: u8 = 2;

/// `ff02::2`.
const ALL_ROUTERS: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 2);
/// `ff02::1`.
const ALL_NODES: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1);

/// Delay between receiving a newer Announce and acting on it (OT
/// `kAnnounceProcessTimeout`).
pub const ANNOUNCE_PROCESS_TIMEOUT: Duration = Duration::from_millis(250);

/// Announce attach progress (OT `AnnounceHandler::State`; the "inform
/// previous channel" step is immediate).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AnnounceState {
    Idle,
    /// A newer network was announced; waiting for the process timeout.
    ToAttach,
    /// Attaching on the announced channel / PAN ID.
    Attaching,
}

/// Announce attach bookkeeping (OT `mAlternateChannel`, `mAlternatePanId`,
/// `mAlternateTimestamp`): the announced network while `ToAttach`, the
/// network to fall back to while `Attaching`.
#[derive(Debug)]
pub(crate) struct AnnounceCtx {
    pub state: AnnounceState,
    pub channel: u8,
    pub pan_id: u16,
    pub timestamp_secs: u64,
    pub deadline: Option<Instant>,
}

impl AnnounceCtx {
    pub const fn new() -> Self {
        Self {
            state: AnnounceState::Idle,
            channel: 0,
            pan_id: 0,
            timestamp_secs: 0,
            deadline: None,
        }
    }
}

/// A Discovery Response waiting for its jitter.
#[cfg(feature = "ftd")]
#[derive(Debug, Clone, Copy)]
pub(crate) struct DiscoveryOut {
    due: Instant,
    dst: Ipv6Addr,
    pan_id: Option<u16>,
}

impl<const C: usize> Mle<C> {
    /// Send an unsecured Discovery Request (OT `DiscoverScanner::Discover`,
    /// one channel) to the link-local all-routers address. `tlv` is the
    /// value of the Thread Discovery TLV (the MeshCoP Discovery Request
    /// sub-TLV and optionally a Joiner Advertisement). `pan_id` is the
    /// destination PAN ID (0xffff when the PAN is unknown) and `channel`
    /// the channel to send on. Works on a disabled device.
    pub fn send_discovery_request<E: MleEnv>(
        &mut self,
        env: &mut E,
        pan_id: u16,
        channel: Option<u8>,
        tlv: &[u8],
    ) -> Result<()> {
        let opts = TxOptions {
            channel,
            pan_id: Some(pan_id),
            link_security: false,
        };
        self.send_with(env, ALL_ROUTERS, Command::DiscoveryRequest, &opts, |w| {
            w.discovery(tlv)
        })
    }

    /// Send an Announce on `channel` to `dst` (default: link-local
    /// all-nodes) carrying our channel, Active Timestamp and PAN ID (OT
    /// `Mle::SendAnnounce`). With `orphan` the timestamp is the Orphan
    /// Announce marker. The message uses link-layer security.
    pub fn send_announce<E: MleEnv>(
        &mut self,
        env: &mut E,
        channel: u8,
        orphan: bool,
        dst: Option<Ipv6Addr>,
    ) -> Result<()> {
        Channel::new(channel)?;
        let own = Channel::new(env.pan_channel())?;
        let ts = if orphan {
            Some(Timestamp::ORPHAN_ANNOUNCE)
        } else {
            env.active_timestamp()
        };
        let pan = env.pan_id();
        // The frame goes to the broadcast PAN ID: the receivers on `channel`
        // are on other PANs (OT `MeshForwarder::UpdateIp6Route`).
        let opts = TxOptions {
            channel: Some(channel),
            pan_id: Some(opentrust_core::types::PanId::BROADCAST.0),
            link_security: true,
        };
        self.send_with(
            env,
            dst.unwrap_or(ALL_NODES),
            Command::Announce,
            &opts,
            |w| {
                w.channel(ChannelValue::new(own))?;
                if let Some(t) = &ts {
                    w.active_timestamp(t)?;
                }
                w.pan_id(PanId(pan))
            },
        )
    }

    /// Unsecured messages (Discovery Request / Response).
    pub(crate) fn handle_unsecured<E: MleEnv>(
        &mut self,
        env: &mut E,
        now: Instant,
        rx: &MleRx<'_>,
    ) -> Result<Command> {
        match rx.command {
            Command::DiscoveryResponse => self.handle_discovery_response(env, rx)?,
            #[cfg(feature = "ftd")]
            Command::DiscoveryRequest => self.handle_discovery_request(env, now, rx)?,
            _ => {}
        }
        let _ = now;
        Ok(rx.command)
    }

    fn handle_discovery_response<E: MleEnv>(&mut self, env: &mut E, rx: &MleRx<'_>) -> Result<()> {
        let tlvs = rx.tlvs.discovery()?;
        let info = DiscoveryResponseInfo {
            ext_address: rx.meta.sender_ext_address(),
            pan_id: rx.meta.link.pan_id,
            channel: rx.meta.link.channel,
            rss: rx.meta.link.rss,
            lqi: rx.meta.link.lqi,
        };
        env.discovery_response_received(&info, tlvs);
        Ok(())
    }

    /// OT `HandleDiscoveryRequest`.
    #[cfg(feature = "ftd")]
    fn handle_discovery_request<E: MleEnv>(
        &mut self,
        env: &mut E,
        now: Instant,
        rx: &MleRx<'_>,
    ) -> Result<()> {
        if self.role == Role::Disabled || !self.is_router_eligible() {
            return Err(Error::InvalidState);
        }
        let d = rx.tlvs.discovery()?;
        let mut request: Option<(u8, bool)> = None;
        for t in opentrust_core::tlv::TlvIter::new(d) {
            let t = t?;
            if t.is_extended() {
                continue;
            }
            match t.ty() {
                MC_DISCOVERY_REQUEST => {
                    let [f, _, ..] = t.value() else {
                        return Err(Error::Parse);
                    };
                    request = Some((f >> 4, f & 0x08 != 0));
                }
                MC_EXT_PAN_ID => {
                    let v = t.read_array::<8>()?;
                    if env.ext_pan_id().is_some_and(|own| own.0 == v) {
                        return Err(Error::Drop);
                    }
                }
                _ => {}
            }
        }
        if let Some((version, joiner)) = request {
            let info = DiscoveryRequestInfo {
                ext_address: rx.meta.sender_ext_address(),
                version,
                joiner,
                pan_id: rx.meta.link.pan_id,
            };
            if !env.accept_discovery_request(&info) {
                return Err(Error::Security);
            }
        }
        let mut jitter = [0u8; 2];
        env.fill_random(&mut jitter);
        let delay = 1 + u64::from(u16::from_le_bytes(jitter) % (DISCOVERY_MAX_JITTER_MS + 1));
        let _ = self.discovery_out.push(DiscoveryOut {
            due: now.saturating_add(Duration::from_millis(delay)),
            dst: rx.meta.src,
            pan_id: rx.meta.link.pan_id,
        });
        Ok(())
    }

    /// When a delayed Discovery Response is due.
    #[cfg(feature = "ftd")]
    pub(crate) fn discovery_deadline(&self) -> Option<Instant> {
        self.discovery_out.iter().map(|d| d.due).min()
    }

    /// Send the Discovery Responses that are due.
    #[cfg(feature = "ftd")]
    pub(crate) fn poll_discovery<E: MleEnv>(&mut self, env: &mut E, now: Instant) {
        let mut i = 0;
        while i < self.discovery_out.len() {
            if self.discovery_out[i].due > now {
                i += 1;
                continue;
            }
            let o = self.discovery_out.swap_remove(i);
            let mut tlv = [0u8; MAX_DISCOVERY_TLV_LEN];
            let Ok(n) = env.discovery_response(&mut tlv) else {
                continue;
            };
            let opts = TxOptions {
                channel: None,
                pan_id: o.pan_id,
                link_security: false,
            };
            let _ = self.send_with(env, o.dst, Command::DiscoveryResponse, &opts, |w| {
                w.discovery(&tlv[..n])
            });
        }
    }

    /// OT `AnnounceHandler::HandleAnnounce`.
    pub(crate) fn handle_announce<E: MleEnv>(
        &mut self,
        env: &mut E,
        now: Instant,
        rx: &MleRx<'_>,
    ) -> Result<RxClass> {
        let channel = rx.tlvs.channel()?;
        let ts = rx.tlvs.active_timestamp()?;
        let pan = rx.tlvs.pan_id()?;
        let channel = u8::try_from(channel.channel).map_err(|_| Error::Parse)?;

        let orphan = ts.is_orphan_announce();
        let own_ts = env.active_timestamp();
        let cmp = Timestamp::compare(Some(&ts), own_ts.as_ref());
        let same_network = channel == env.pan_channel() && pan.0 == env.pan_id();

        if orphan || cmp.is_lt() {
            if orphan && same_network {
                return Ok(RxClass::Peer);
            }
            // Tell the sender about our newer network on its channel.
            let _ = self.send_announce(env, channel, false, None);
            // Also answer the sender directly (OT
            // `SEND_UNICAST_ANNOUNCE_RESPONSE`).
            let _ = self.send_announce(env, channel, false, Some(rx.meta.src));
        } else if cmp.is_gt() {
            // Nothing to do for a detached device already on that
            // channel and PAN.
            if self.role == Role::Detached && same_network {
                return Ok(RxClass::Peer);
            }
            if env.pending_dataset_applies_soon(&ts) || self.role == Role::Disabled {
                return Ok(RxClass::Peer);
            }
            // A pending Announce attach is only replaced by a newer one.
            if self.announce.state == AnnounceState::ToAttach
                && self.announce.timestamp_secs >= ts.seconds
            {
                return Ok(RxClass::Peer);
            }
            self.announce.timestamp_secs = ts.seconds;
            self.announce.channel = channel;
            self.announce.pan_id = pan.0;
            self.announce.state = AnnounceState::ToAttach;
            self.announce.deadline = Some(now.saturating_add(ANNOUNCE_PROCESS_TIMEOUT));
            env.event(MleEvent::AnnounceFromNewerNetwork {
                channel,
                pan_id: pan.0,
                timestamp: ts,
            });
        } else {
            // Equal timestamps: a consistent transmission for the
            // AnnounceSender's Trickle timer.
            self.announce_sender.consistent();
        }
        Ok(RxClass::Peer)
    }

    /// The Announce process timer (OT `AnnounceHandler::HandleTimer` /
    /// `StartAnnounceAttach`): leave the current attachment, move to the
    /// announced channel and PAN ID, remembering the old ones, and attach
    /// to any partition there.
    pub(crate) fn poll_announce<E: MleEnv>(&mut self, env: &mut E, now: Instant) {
        if self.announce.deadline.is_none_or(|d| now < d) {
            return;
        }
        self.announce.deadline = None;
        if self.announce.state != AnnounceState::ToAttach {
            return;
        }
        let (channel, pan_id) = (self.announce.channel, self.announce.pan_id);
        self.announce.channel = env.pan_channel();
        self.announce.pan_id = env.pan_id();
        self.announce.timestamp_secs = 0;
        self.announce.state = AnnounceState::Attaching;
        env.set_pan_channel_and_id(channel, pan_id);
        let had_parent = self.parent.is_some();
        self.reset_to_detached(env);
        if had_parent {
            env.event(MleEvent::ParentLost);
        }
        self.attach.counter = 0;
        self.attach_begin(env, now, crate::attach::AttachMode::AnyPartition);
    }

    /// Attached on the announced network (OT
    /// `HandleAnnounceAttachSuccess`): tell the old channel about it.
    pub(crate) fn announce_attach_succeeded<E: MleEnv>(&mut self, env: &mut E) {
        if self.announce.state != AnnounceState::Attaching {
            return;
        }
        self.announce.state = AnnounceState::Idle;
        let _ = self.send_announce(env, self.announce.channel, false, None);
    }

    /// Attaching on the announced network failed (OT
    /// `HandleAnnounceAttachFailure`): back to the previous channel and PAN
    /// ID. Returns whether an Announce attach was running.
    pub(crate) fn announce_attach_failed<E: MleEnv>(&mut self, env: &mut E) -> bool {
        if self.announce.state != AnnounceState::Attaching {
            return false;
        }
        self.announce.state = AnnounceState::Idle;
        env.set_pan_channel_and_id(self.announce.channel, self.announce.pan_id);
        true
    }
}
