//! The link-level I/O of the Joiner and the Joiner Router: unsecured and
//! key ID mode 0 (KEK) datagrams, the KEK in the MAC, the Joiner UDP port.

use core::net::Ipv6Addr;

use heapless::{Deque, Vec};
use opentrust_coap::endpoint::Peer;
use opentrust_core::crypto::CryptoBackend;
use opentrust_core::types::{ExtAddress, Kek, LinkSecurity, PanId, ipv6};
use opentrust_core::{Error, Result};
use opentrust_meshcop::dataset::Dataset;
use opentrust_meshcop::joiner::{JoinerEvent, JoinerIo};
#[cfg(feature = "ftd")]
use opentrust_meshcop::joiner_router::JoinerRouterIo;
use opentrust_net::ip6::{Ip6, SendInfo};
use opentrust_net::udp::{ReceiverId, UdpSockets};

use crate::UDP_SOCKETS;
use crate::stack::{Outbox, StackMac};

/// Receiver of the Joiner UDP port (Joiner and Joiner Router).
pub(crate) const JOINER_RECEIVER: ReceiverId = ReceiverId(2);

/// What the Joiner asks for that needs the whole stack (done after the
/// Joiner call).
// No allocator: the dataset (wiped on drop) is kept inline.
#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
pub(crate) enum JoinerAction {
    Discovery(u8, u16, Vec<u8, 16>),
    Save(Dataset),
    Event(JoinerEvent),
}

/// [`JoinerIo`] / [`JoinerRouterIo`] over disjoint parts of the instance.
pub(crate) struct LinkIo<'a, C: CryptoBackend> {
    pub mac: &'a mut StackMac<C>,
    pub ip6: &'a mut Ip6,
    pub ext: &'a mut ExtAddress,
    pub out: &'a mut Outbox,
    pub udp: &'a mut UdpSockets<{ UDP_SOCKETS }>,
    /// The unsecure Joiner UDP port (link-local only).
    pub joiner_port: &'a mut Option<u16>,
    /// Highest key ID mode 0 frame counter accepted under the current KEK.
    pub kek_rx_fc: &'a mut Option<u32>,
    pub actions: &'a mut Deque<JoinerAction, 4>,
}

impl<C: CryptoBackend> LinkIo<'_, C> {
    fn link_local(&self) -> Ipv6Addr {
        ipv6::link_local(self.ext)
    }

    fn send(
        &mut self,
        security: LinkSecurity,
        src_port: u16,
        dst: &Peer,
        payload: &[u8],
    ) -> Result<()> {
        // Unsecured and KEK datagrams only go to a link-local neighbor.
        if !dst.addr.is_unicast_link_local() {
            return Err(Error::InvalidArgs);
        }
        if security == LinkSecurity::Kek && self.mac.security().kek().is_none() {
            return Err(Error::InvalidState);
        }
        let mut info = SendInfo::new(dst.addr);
        info.src = Some(self.link_local());
        info.hop_limit = 255;
        info.link_security = false;
        self.out.push(info, src_port, dst.port, payload)?;
        if let Some(o) = self.out.back_mut() {
            o.security = Some(security);
        }
        Ok(())
    }

    fn set_port(&mut self, port: Option<u16>) {
        let _ = self.udp.unregister_receiver(JOINER_RECEIVER);
        *self.joiner_port = port;
        if let Some(p) = port {
            let _ = self.udp.register_receiver(p, JOINER_RECEIVER);
        }
    }

    fn install_kek(&mut self, kek: Option<&Kek>) {
        self.mac.security_mut().set_kek(kek.cloned());
        *self.kek_rx_fc = None;
    }

    fn act(&mut self, a: JoinerAction) {
        if self.actions.is_full() {
            let _ = self.actions.pop_front();
        }
        let _ = self.actions.push_back(a);
    }
}

impl<C: CryptoBackend> JoinerIo for LinkIo<'_, C> {
    fn send_discovery_request(&mut self, channel: u8, pan_id: u16, tlv: &[u8]) -> Result<()> {
        let v = Vec::from_slice(tlv).map_err(|_| Error::NoBufs)?;
        self.act(JoinerAction::Discovery(channel, pan_id, v));
        Ok(())
    }

    fn set_ext_address(&mut self, ext: &ExtAddress) {
        *self.ext = *ext;
        self.mac.set_ext_address(*ext);
        let _ = self.ip6.netif.set_link_local(ext);
    }

    fn set_pan(&mut self, channel: u8, pan_id: u16) -> Result<()> {
        self.mac.set_channel(channel)?;
        self.mac.set_pan_id(PanId(pan_id));
        Ok(())
    }

    fn set_unsecure_port(&mut self, port: u16, allow: bool) {
        self.set_port(allow.then_some(port));
    }

    fn send_unsecured(&mut self, src_port: u16, dst: &Peer, payload: &[u8]) -> Result<()> {
        self.send(LinkSecurity::None, src_port, dst, payload)
    }

    fn set_kek(&mut self, kek: Option<&Kek>) {
        self.install_kek(kek);
    }

    fn send_kek(&mut self, src_port: u16, dst: &Peer, payload: &[u8]) -> Result<()> {
        self.send(LinkSecurity::Kek, src_port, dst, payload)
    }

    fn save_dataset(&mut self, dataset: &Dataset) {
        self.act(JoinerAction::Save(dataset.clone()));
    }

    fn event(&mut self, event: JoinerEvent) {
        self.act(JoinerAction::Event(event));
    }
}

#[cfg(feature = "ftd")]
impl<C: CryptoBackend> JoinerRouterIo for LinkIo<'_, C> {
    fn set_joiner_port(&mut self, port: Option<u16>) {
        self.set_port(port);
    }

    fn send_unsecured(&mut self, src_port: u16, dst: &Peer, payload: &[u8]) -> Result<()> {
        self.send(LinkSecurity::None, src_port, dst, payload)
    }

    fn set_kek(&mut self, kek: Option<&Kek>) {
        self.install_kek(kek);
    }

    fn send_kek(&mut self, src_port: u16, dst: &Peer, payload: &[u8]) -> Result<()> {
        self.send(LinkSecurity::Kek, src_port, dst, payload)
    }
}
