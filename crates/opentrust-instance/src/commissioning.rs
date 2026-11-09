//! The MeshCoP commissioning roles owned by the [`Instance`](crate::Instance):
//! the Joiner (always), the Joiner Router and the leader's commissioner
//! session (`ftd`), the on-mesh Commissioner (`commissioner`) and the
//! Border Agent (`border-agent`).

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
}

impl<C: InstanceCrypto> Commissioning<C> {
    pub(crate) fn new(crypto: &C, leader_session_id: u16, ba_id: [u8; 16]) -> Self {
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
