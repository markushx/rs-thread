//! TREL link security (OT `KeyManager::ComputeTrelKey`, `Mac` TREL frame
//! counter): frames sent over TREL are secured like normal MAC frames
//! (AES-CCM*, key ID mode 1) but with the TREL key derived from the network
//! key and the key sequence, and with their own outgoing frame counter.
//!
//! [`TrelSecurity`] implements
//! [`FrameSecurity`](opentrust_mac::frame_security::FrameSecurity) so the MAC
//! of a TREL-only device can use it in place of the
//! [`KeyManager`](opentrust_mac::security::KeyManager). Key ID mode 2 (Thread
//! discovery frames) and mode 0 (Joiner Entrust) are not handled here; a
//! multi-radio device secures them with the `KeyManager` before handing the
//! frame to the TREL link.

use opentrust_core::crypto::CryptoBackend;
use opentrust_core::crypto::kdf::{key_index, trel_key};
use opentrust_core::types::{ExtAddress, MacKey, NetworkKey};
use opentrust_core::{Error, Result};
use opentrust_mac::frame::{Frame, KeyIdMode, KeyIdentifier};
use opentrust_mac::frame_security::{FrameSecurity, RxSecurityInfo};
use opentrust_mac::security::{open_psdu, seal_psdu, write_aux_header};

/// Frame security with the TREL key.
#[derive(Debug)]
pub struct TrelSecurity<B: CryptoBackend> {
    backend: B,
    network_key: NetworkKey,
    key_sequence: u32,
    /// Keys of the previous, current and next key sequence.
    keys: [MacKey; 3],
    frame_counter: u32,
}

impl<B: CryptoBackend> TrelSecurity<B> {
    /// Security for `network_key` at `key_sequence`; the frame counter
    /// starts at `frame_counter`.
    pub fn new(backend: B, network_key: NetworkKey, key_sequence: u32, frame_counter: u32) -> Self {
        let keys = Self::derive(&backend, &network_key, key_sequence);
        Self {
            backend,
            network_key,
            key_sequence,
            keys,
            frame_counter,
        }
    }

    fn derive(b: &B, nk: &NetworkKey, seq: u32) -> [MacKey; 3] {
        [
            trel_key(b, nk, seq.wrapping_sub(1)),
            trel_key(b, nk, seq),
            trel_key(b, nk, seq.wrapping_add(1)),
        ]
    }

    /// The key sequence changed (new network key sequence from MLE).
    pub fn set_key_sequence(&mut self, key_sequence: u32) {
        if key_sequence != self.key_sequence {
            self.key_sequence = key_sequence;
            self.keys = Self::derive(&self.backend, &self.network_key, key_sequence);
        }
    }

    /// The network key changed.
    pub fn set_network_key(&mut self, network_key: NetworkKey) {
        self.network_key = network_key;
        self.keys = Self::derive(&self.backend, &self.network_key, self.key_sequence);
    }

    /// The next outgoing frame counter (to persist, as for the MAC).
    pub const fn frame_counter(&self) -> u32 {
        self.frame_counter
    }

    /// The current key sequence.
    pub const fn key_sequence(&self) -> u32 {
        self.key_sequence
    }
}

impl<B: CryptoBackend> FrameSecurity for TrelSecurity<B> {
    fn secure_tx(&mut self, psdu: &mut [u8], src_ext: &ExtAddress) -> Result<()> {
        let f = Frame::parse(psdu)?;
        let Some(s) = f.security_header() else {
            return Ok(());
        };
        if s.frame_counter.is_none() || s.asn_in_nonce || s.key_id_mode() != KeyIdMode::Index {
            return Err(Error::InvalidArgs);
        }
        let fc = self.frame_counter;
        self.frame_counter = fc.checked_add(1).ok_or(Error::InvalidState)?;
        write_aux_header(
            psdu,
            fc,
            &KeyIdentifier::Index(key_index(self.key_sequence)),
        )?;
        let cipher = self.backend.aes128(&self.keys[1].0);
        seal_psdu(&cipher, psdu, src_ext)
    }

    fn unsecure_rx(
        &mut self,
        psdu: &mut [u8],
        src_ext: &ExtAddress,
    ) -> Result<Option<RxSecurityInfo>> {
        let f = Frame::parse(psdu)?;
        let Some(s) = f.security_header().copied() else {
            return Ok(None);
        };
        let (KeyIdentifier::Index(idx), Some(fc)) = (s.key, s.frame_counter) else {
            return Err(Error::Security);
        };
        if s.asn_in_nonce {
            return Err(Error::Security);
        }
        // Previous, current or next key sequence, whichever has this index.
        let seq = [-1i8, 0, 1]
            .iter()
            .enumerate()
            .find_map(|(i, &d)| {
                let seq = self.key_sequence.wrapping_add_signed(i32::from(d));
                (key_index(seq) == idx).then_some((i, seq))
            })
            .ok_or(Error::Security)?;
        let cipher = self.backend.aes128(&self.keys[seq.0].0);
        open_psdu(&cipher, psdu, src_ext)?;
        Ok(Some(RxSecurityInfo {
            level: s.level,
            key_id_mode: KeyIdMode::Index,
            key_sequence: Some(seq.1),
            frame_counter: fc,
        }))
    }
}
