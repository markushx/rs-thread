//! MLE UDP endpoint glue (sans-IO): claim port 19788, validate and decrypt
//! incoming MLE datagrams, dispatch them by command, secure and send
//! outgoing ones (Thread 1.4.1 §4.3; OpenThread `Mle::HandleUdpReceive`
//! up to the command dispatch, `Mle::TxMessage::SendTo`).
//!
//! No protocol logic lives here; attach, link establishment, routing etc.
//! are implemented by [`MleHandler`]s (the [`Mle`](crate::Mle) state machine).
//!
//! # Receive path
//!
//! ```text
//! Ip6::handle -> UdpSockets::handle_datagram -> UdpRx::Receiver{ReceiverId::MLE, meta, payload}
//!   -> endpoint::MleRx::parse(keys, &meta, link, payload, scratch)   // hop limit, addresses, decrypt
//!   -> [caller: neighbor lookup, MleReplay::check_and_update, KeyManager::on_rx_key_sequence]
//!   -> handler.handle(&rx)                                            // dispatch by command
//! ```
//!
//! [`MleRx::parse`] and [`MleHandler::handle`] are separate so that the
//! caller can apply the receiver-side policy between them (OT does it
//! between decryption and the `Handle*()` calls) without the borrow checker
//! tying the [`KeyManager`] to the handler. [`receive`] chains both for
//! callers that need nothing in between.
//!
//! # Send path
//!
//! Build with [`MleBuilder`](crate::message::MleBuilder), then
//! [`send`]: applies the destination rules, secures the message with the
//! next MLE frame counter and hands it to a [`UdpSink`] (shared with the TMF
//! agent) with hop limit 255.

use core::net::Ipv6Addr;

use opentrust_coap::tmf::UdpSink;
use opentrust_core::crypto::CryptoBackend;
use opentrust_core::types::{ExtAddress, ipv6};
use opentrust_core::{Error, Result};
use opentrust_mac::security::KeyManager;
use opentrust_net::addr::is_link_local_multicast;
use opentrust_net::ip6::SendInfo;
use opentrust_net::udp::{ReceiverId, UdpMeta, UdpSockets};

use crate::consts::{MLE_HOP_LIMIT, MLE_UDP_PORT};
use crate::message::Command;
use crate::security::{self, MleFrameCounter, RxSecurity};
use crate::tlv::Tlvs;

/// The [`ReceiverId`] used for MLE.
pub const RECEIVER_ID: ReceiverId = ReceiverId::MLE;

/// Claim UDP port 19788 for MLE (OT `Mle::Enable` / `mSocket.Open`).
pub fn register_receiver<const N: usize, const Q: usize, const BUF: usize, const R: usize>(
    udp: &mut UdpSockets<N, Q, BUF, R>,
) -> Result<()> {
    udp.register_receiver(MLE_UDP_PORT, RECEIVER_ID)
}

/// Release the MLE port.
pub fn unregister_receiver<const N: usize, const Q: usize, const BUF: usize, const R: usize>(
    udp: &mut UdpSockets<N, Q, BUF, R>,
) -> Result<()> {
    udp.unregister_receiver(RECEIVER_ID)
}

/// Destination rule for outgoing MLE messages: a link-local unicast address
/// or a link-local multicast address (all-nodes `ff02::1`, all-routers
/// `ff02::2`, ...). OT only ever sends to these.
pub fn is_valid_tx_destination(dst: &Ipv6Addr) -> bool {
    dst.is_unicast_link_local() || is_link_local_multicast(dst)
}

/// Source/destination rule for incoming MLE messages: the source is a
/// link-local unicast address (its IID identifies the sender, see
/// [`security`]); the destination is link-local unicast or multicast with
/// link-local or realm-local scope (lenient on the latter, which OT does not
/// check at all).
pub fn is_valid_rx_addressing(src: &Ipv6Addr, dst: &Ipv6Addr) -> bool {
    use opentrust_net::addr::is_realm_local_multicast;
    src.is_unicast_link_local()
        && (dst.is_unicast_link_local()
            || is_link_local_multicast(dst)
            || is_realm_local_multicast(dst))
}

/// Link-layer reception info of the frame that carried the datagram
/// (from the MAC / fragment reassembly).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct LinkRxInfo {
    /// RSS of the frame in dBm.
    pub rss: Option<i8>,
    /// LQI of the frame.
    pub lqi: Option<u8>,
    /// Source PAN ID of the frame (Discovery messages are answered with
    /// the PAN ID of the request).
    pub pan_id: Option<u16>,
    /// Channel the frame was received on (Discovery Responses report the
    /// channel of the network).
    pub channel: Option<u8>,
}

/// Metadata of a received MLE message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RxMeta {
    /// IPv6 source (link-local; its IID is the sender's extended address,
    /// see [`RxMeta::sender_ext_address`]).
    pub src: Ipv6Addr,
    /// IPv6 destination.
    pub dst: Ipv6Addr,
    /// UDP source port.
    pub src_port: u16,
    /// Whether the datagram was protected by link-layer security.
    pub link_security: bool,
    /// Key sequence and frame counter of a secured message (`None` for
    /// Discovery Request/Response).
    pub security: Option<RxSecurity>,
    /// RSS / LQI of the receiving frame.
    pub link: LinkRxInfo,
}

impl RxMeta {
    /// The sender's extended address derived from the source IID.
    pub fn sender_ext_address(&self) -> ExtAddress {
        ipv6::iid(&self.src).to_ext_address()
    }
}

/// A received, verified and decrypted MLE message.
#[derive(Debug, Clone, Copy)]
pub struct MleRx<'a> {
    /// Message metadata.
    pub meta: RxMeta,
    /// Command.
    pub command: Command,
    /// TLVs following the command.
    pub tlvs: Tlvs<'a>,
}

impl<'a> MleRx<'a> {
    /// Validate and decrypt a datagram delivered to the MLE receiver.
    ///
    /// `payload` is the UDP payload from
    /// [`UdpRx::Receiver`](opentrust_net::udp::UdpRx::Receiver); it is copied
    /// into `scratch` (decryption is in place), so `scratch` must be at
    /// least as long (an MLE message is at most 1280 - 48 bytes).
    ///
    /// Errors: [`Error::Drop`] for a wrong port or illegal addressing,
    /// [`Error::Parse`] for hop limit other than 255 (OT `kErrorParse`) or a
    /// malformed message, [`Error::NoBufs`] if `scratch` is too small, and
    /// everything [`security::unsecure`] returns ([`Error::Security`] on MIC
    /// failure).
    pub fn parse<B: CryptoBackend>(
        keys: &KeyManager<B>,
        meta: &UdpMeta,
        link: LinkRxInfo,
        payload: &[u8],
        scratch: &'a mut [u8],
    ) -> Result<Self> {
        if meta.local.port() != MLE_UDP_PORT {
            return Err(Error::Drop);
        }
        if meta.hop_limit != MLE_HOP_LIMIT {
            return Err(Error::Parse);
        }
        let (src, dst) = (*meta.peer.ip(), *meta.local.ip());
        if !is_valid_rx_addressing(&src, &dst) {
            return Err(Error::Drop);
        }
        let buf = scratch.get_mut(..payload.len()).ok_or(Error::NoBufs)?;
        buf.copy_from_slice(payload);
        let m = security::unsecure(keys, buf, &src, &dst)?;
        Ok(Self {
            meta: RxMeta {
                src,
                dst,
                src_port: meta.peer.port(),
                link_security: meta.link_security,
                security: m.security,
                link,
            },
            command: m.command,
            tlvs: m.tlvs,
        })
    }
}

macro_rules! dispatch {
    ($($(#[$m:meta])* $fn:ident => $cmd:ident),* $(,)?) => {
        /// Receives decrypted MLE messages, one method per command.
        ///
        /// Override the methods for the commands you implement, or override
        /// [`handle`](Self::handle) to do your own `match`; unhandled
        /// commands are ignored. All methods default to doing nothing.
        pub trait MleHandler {
            /// Entry point; the default dispatches on `rx.command`.
            fn handle(&mut self, rx: &MleRx<'_>) {
                match rx.command {
                    $(Command::$cmd => self.$fn(rx),)*
                }
            }

            $(
                $(#[$m])*
                fn $fn(&mut self, _rx: &MleRx<'_>) {}
            )*
        }
    };
}

dispatch! {
    /// Link Request.
    on_link_request => LinkRequest,
    /// Link Accept.
    on_link_accept => LinkAccept,
    /// Link Accept and Request.
    on_link_accept_and_request => LinkAcceptAndRequest,
    /// Link Reject.
    on_link_reject => LinkReject,
    /// Advertisement.
    on_advertisement => Advertisement,
    /// Update (not used in Thread).
    on_update => Update,
    /// Update Request (not used in Thread).
    on_update_request => UpdateRequest,
    /// Data Request.
    on_data_request => DataRequest,
    /// Data Response.
    on_data_response => DataResponse,
    /// Parent Request.
    on_parent_request => ParentRequest,
    /// Parent Response.
    on_parent_response => ParentResponse,
    /// Child ID Request.
    on_child_id_request => ChildIdRequest,
    /// Child ID Response.
    on_child_id_response => ChildIdResponse,
    /// Child Update Request.
    on_child_update_request => ChildUpdateRequest,
    /// Child Update Response.
    on_child_update_response => ChildUpdateResponse,
    /// Announce.
    on_announce => Announce,
    /// Discovery Request (unsecured).
    on_discovery_request => DiscoveryRequest,
    /// Discovery Response (unsecured).
    on_discovery_response => DiscoveryResponse,
    /// Link Metrics Management Request.
    on_link_metrics_management_request => LinkMetricsManagementRequest,
    /// Link Metrics Management Response.
    on_link_metrics_management_response => LinkMetricsManagementResponse,
    /// Link Probe.
    on_link_probe => LinkProbe,
    /// Time Sync (OT extension).
    on_time_sync => TimeSync,
}

/// [`MleRx::parse`] followed by [`MleHandler::handle`]; returns the command
/// that was dispatched.
pub fn receive<B: CryptoBackend, H: MleHandler + ?Sized>(
    keys: &KeyManager<B>,
    meta: &UdpMeta,
    link: LinkRxInfo,
    payload: &[u8],
    scratch: &mut [u8],
    handler: &mut H,
) -> Result<Command> {
    let rx = MleRx::parse(keys, meta, link, payload, scratch)?;
    handler.handle(&rx);
    Ok(rx.command)
}

/// Addressing of an outgoing MLE message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TxInfo {
    /// Our link-local address (determines the security nonce).
    pub src: Ipv6Addr,
    /// Destination, see [`is_valid_tx_destination`].
    pub dst: Ipv6Addr,
    /// Protect the datagram with link-layer security as well (only
    /// Announce does).
    pub link_security: bool,
}

/// Secure the message `buf[..len]` built with
/// [`MleBuilder`](crate::message::MleBuilder) and send it from the
/// link-local address `tx.src` to `tx.dst` through `sink`.
///
/// Rules (OT `Mle::TxMessage::SendTo`, Thread §4.3): `dst` must satisfy
/// [`is_valid_tx_destination`] ([`Error::InvalidArgs`] otherwise), `src` must
/// be link-local unicast, hop limit is 255, source and destination port are
/// 19788. MLE messages are *not* protected by link-layer security (they have
/// their own), except Announce, which sets `link_security` (OT
/// `SendAnnounce`); set [`TxInfo::link_security`] accordingly. The MLE frame counter
/// is consumed only for secured messages; the caller persists it when
/// [`MleFrameCounter::needs_store`] says so.
pub fn send<B: CryptoBackend, S: UdpSink + ?Sized>(
    keys: &KeyManager<B>,
    counter: &mut MleFrameCounter,
    sink: &mut S,
    tx: &TxInfo,
    buf: &mut [u8],
    len: usize,
) -> Result<()> {
    if !is_valid_tx_destination(&tx.dst) || !tx.src.is_unicast_link_local() {
        return Err(Error::InvalidArgs);
    }
    let n = security::secure(keys, counter, buf, len, &tx.src, &tx.dst)?;
    let info = SendInfo {
        src: Some(tx.src),
        dst: tx.dst,
        hop_limit: MLE_HOP_LIMIT,
        dscp: 0,
        ecn: 0,
        multicast_loop: false,
        link_security: tx.link_security,
    };
    sink.send(&info, MLE_UDP_PORT, MLE_UDP_PORT, &buf[..n])
}

#[cfg(test)]
#[path = "endpoint_tests.rs"]
mod tests;
