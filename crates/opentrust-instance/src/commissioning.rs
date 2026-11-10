//! The MeshCoP commissioning roles owned by the [`Instance`](crate::Instance):
//! the Joiner (always), the Joiner Router and the leader's commissioner
//! session (`ftd`), the on-mesh Commissioner (`commissioner`) and the
//! Border Agent (`border-agent`).

use heapless::Deque;
use opentrust_core::crypto::CryptoBackend;
use opentrust_core::crypto::ecdsa::EcdsaP256;
use opentrust_core::crypto::ecjpake::{P256, SoftP256};
use opentrust_core::crypto::soft::SoftCrypto;
#[cfg(feature = "border-agent")]
use opentrust_meshcop::border_agent::BorderAgent;
#[cfg(feature = "commissioner")]
use opentrust_meshcop::commissioner::Commissioner;
use opentrust_meshcop::joiner::Joiner;
#[cfg(feature = "ftd")]
use opentrust_meshcop::joiner_router::JoinerRouter;
#[cfg(feature = "ftd")]
use opentrust_meshcop::leader::LeaderState;

use crate::cm_io::JoinerAction;

/// The cryptography an [`Instance`](crate::Instance) needs: the
/// [`CryptoBackend`] (AES-CCM*, SHA-256, HMAC, CMAC), ECDSA P-256 (SRP
/// client) and the P-256 group of EC-JPAKE (DTLS of the Joiner, the
/// Commissioner and the Border Agent).
///
/// Implemented for the software backend [`SoftCrypto`] (with
/// [`SoftP256`]); a hardware backend implements it once with its own curve
/// type, so the instance keeps three type parameters.
pub trait InstanceCrypto: CryptoBackend<Sha256: Clone> + EcdsaP256 + Clone {
    /// The P-256 group used by EC-JPAKE.
    type Curve: P256 + Clone;

    /// A handle to the P-256 group.
    fn curve(&self) -> Self::Curve;
}

impl InstanceCrypto for SoftCrypto {
    type Curve = SoftP256;

    fn curve(&self) -> SoftP256 {
        SoftP256
    }
}

/// The commissioning roles and their glue state.
pub(crate) struct Commissioning<C: InstanceCrypto> {
    /// The Joiner (idle unless [`Instance::joiner_start`](crate::Instance)).
    pub joiner: Joiner<C, C::Curve>,
    /// The Joiner Router (opens the Joiner UDP port while joining is
    /// allowed and this is an attached FTD).
    #[cfg(feature = "ftd")]
    pub jr: JoinerRouter,
    /// The leader's commissioner session (`/c/lp`, `/c/la`, `/c/cs`,
    /// `/c/cg`).
    #[cfg(feature = "ftd")]
    pub leader: LeaderState,
    /// The on-mesh Commissioner.
    #[cfg(feature = "commissioner")]
    pub comm: Commissioner<C, C::Curve>,
    /// The Border Agent.
    #[cfg(feature = "border-agent")]
    pub ba: BorderAgent<C, C::Curve>,
    /// Datagrams of the Border Agent for the external Commissioner.
    #[cfg(feature = "border-agent")]
    pub ba_out: BaOut,
    /// The unsecure Joiner UDP port (Joiner, or Joiner Router).
    pub joiner_port: Option<u16>,
    /// Highest key ID mode 0 frame counter accepted under the current KEK.
    pub kek_rx_fc: Option<u32>,
    /// Key ID mode 0 frames dropped (no KEK exchange with the sender).
    pub kek_drops: u32,
    pub actions: Deque<JoinerAction, 4>,
    /// The factory EUI-64 (Joiner ID derivation).
    pub eui64: opentrust_core::types::ExtAddress,
}

/// A DTLS datagram of the Border Agent to the external Commissioner.
#[cfg(feature = "border-agent")]
#[derive(Debug, Clone)]
pub struct BaDatagram {
    /// The listener (Border Agent or ePSKc port) it is sent from.
    pub listener: opentrust_meshcop::border_agent::Listener,
    /// The Commissioner.
    pub peer: opentrust_coap::endpoint::Peer,
    /// The DTLS records.
    pub data: heapless::Vec<u8, 1280>,
}

/// Queue of [`BaDatagram`]s; the records are stored in a pool of
/// [`crate::stack::OUTBOX_BUF`]-byte buffers (`NoBufs` when it is full).
#[cfg(feature = "border-agent")]
#[derive(Debug, Default)]
pub(crate) struct BaOut {
    q: Deque<
        (
            opentrust_meshcop::border_agent::Listener,
            opentrust_coap::endpoint::Peer,
            opentrust_core::bufpool::Chain,
        ),
        4,
    >,
    pool: opentrust_core::bufpool::BufPool<12, { crate::stack::OUTBOX_BUF }>,
}

#[cfg(feature = "border-agent")]
impl BaOut {
    pub(crate) fn push(
        &mut self,
        listener: opentrust_meshcop::border_agent::Listener,
        peer: opentrust_coap::endpoint::Peer,
        data: &[u8],
    ) -> opentrust_core::Result<()> {
        if self.q.is_full() {
            return Err(opentrust_core::Error::NoBufs);
        }
        let chain = self.pool.alloc(data)?;
        let _ = self.q.push_back((listener, peer, chain));
        Ok(())
    }

    pub(crate) fn pop_front(&mut self) -> Option<BaDatagram> {
        let (listener, peer, chain) = self.q.pop_front()?;
        let mut data = heapless::Vec::new();
        let _ = data.resize_default(chain.len());
        self.pool.read(&chain, &mut data);
        self.pool.free(chain);
        Some(BaDatagram {
            listener,
            peer,
            data,
        })
    }
}

impl<C: InstanceCrypto> Commissioning<C> {
    pub(crate) fn new(
        crypto: &C,
        eui64: opentrust_core::types::ExtAddress,
        leader_session_id: u16,
        ba_id: [u8; 16],
    ) -> Self {
        #[cfg(not(feature = "ftd"))]
        let _ = leader_session_id;
        #[cfg(not(feature = "border-agent"))]
        let _ = ba_id;
        Self {
            joiner: Joiner::new(crypto.clone(), crypto.curve()),
            #[cfg(feature = "ftd")]
            jr: JoinerRouter::new(),
            #[cfg(feature = "ftd")]
            leader: LeaderState::new(leader_session_id),
            #[cfg(feature = "commissioner")]
            comm: Commissioner::new(crypto.clone(), crypto.curve()),
            #[cfg(feature = "border-agent")]
            ba: BorderAgent::new(crypto.clone(), crypto.curve(), ba_id),
            #[cfg(feature = "border-agent")]
            ba_out: BaOut::default(),
            joiner_port: None,
            kek_rx_fc: None,
            kek_drops: 0,
            actions: Deque::new(),
            eui64,
        }
    }

    /// The earliest timer of the roles.
    pub(crate) fn next_deadline(&self) -> Option<opentrust_core::time::Instant> {
        [
            self.joiner.next_deadline(),
            #[cfg(feature = "ftd")]
            self.jr.next_deadline(),
            #[cfg(feature = "commissioner")]
            self.comm.next_deadline(),
            #[cfg(feature = "border-agent")]
            self.ba.next_deadline(),
        ]
        .into_iter()
        .flatten()
        .min()
    }
}
