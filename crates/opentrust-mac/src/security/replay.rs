//! Per-neighbor replay protection for MAC frames (Thread §7.1.8, §7.2.2;
//! OpenThread `Mac::ProcessReceiveSecurity` / `ProcessEnhAckSecurity` with
//! `Neighbor::{GetKeySequence, GetLinkFrameCounters, GetLinkAckFrameCounter}`).

use opentrust_core::{Error, Result};

use crate::frame_security::RxSecurityInfo;

/// Incoming key sequence and frame counters of one neighbor, kept in the
/// neighbor table.
///
/// A frame secured with key sequence `s` and frame counter `c` is accepted
/// if `s` is newer than the neighbor's key sequence (the counters restart),
/// or if `s` is the same and `c` is larger than every counter accepted so far
/// (or at least the value learnt from an MLE Link-layer Frame Counter TLV).
/// Frames with an older key sequence are rejected.
///
/// Unlike OpenThread, the "next acceptable" counters are kept as `u64`, so a
/// frame with counter `0xffffffff` does not wrap the state back to 0.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct LinkFrameCounters {
    key_sequence: u32,
    /// Smallest acceptable link frame counter.
    next: u64,
    /// Smallest acceptable enhanced-ACK frame counter.
    ack_next: u64,
}

impl LinkFrameCounters {
    /// Key sequence 0, all counters acceptable.
    pub const fn new() -> Self {
        Self {
            key_sequence: 0,
            next: 0,
            ack_next: 0,
        }
    }

    /// State after link establishment: the neighbor's key sequence and the
    /// value of its Link-layer Frame Counter TLV, which is the smallest
    /// acceptable frame counter for data frames and enhanced ACKs
    /// (OpenThread `GetLinkFrameCounters().SetAll(c); SetLinkAckFrameCounter(c)`).
    pub const fn with(key_sequence: u32, frame_counter: u32) -> Self {
        Self {
            key_sequence,
            next: frame_counter as u64,
            ack_next: frame_counter as u64,
        }
    }

    /// The neighbor's key sequence.
    pub const fn key_sequence(&self) -> u32 {
        self.key_sequence
    }

    /// Smallest acceptable link frame counter (`None`: counter `0xffffffff`
    /// was already accepted, nothing more is).
    pub const fn frame_counter(&self) -> Option<u32> {
        as_u32(self.next)
    }

    /// Smallest acceptable enhanced-ACK frame counter.
    pub const fn ack_frame_counter(&self) -> Option<u32> {
        as_u32(self.ack_next)
    }

    /// Set key sequence and counters (see [`with`](Self::with)).
    pub fn set(&mut self, key_sequence: u32, frame_counter: u32) {
        *self = Self::with(key_sequence, frame_counter);
    }

    /// Back to [`new`](Self::new) (network key change, OpenThread
    /// `KeyManager::ResetFrameCounters`).
    pub fn reset(&mut self) {
        *self = Self::new();
    }

    /// Check a frame's key sequence and frame counter without updating.
    ///
    /// [`Error::Security`] for an older key sequence or a replayed (older)
    /// counter, [`Error::Drop`] for an exact duplicate of the last accepted
    /// frame (OpenThread `kErrorDuplicated`).
    pub fn check(&self, key_sequence: u32, frame_counter: u32) -> Result<()> {
        if key_sequence < self.key_sequence {
            return Err(Error::Security);
        }
        if key_sequence == self.key_sequence {
            let c = u64::from(frame_counter);
            if c + 1 == self.next {
                return Err(Error::Drop);
            }
            if c < self.next {
                return Err(Error::Security);
            }
        }
        Ok(())
    }

    /// Record an accepted frame (after [`check`](Self::check) and successful
    /// MIC verification). Returns `true` if the neighbor's key sequence
    /// advanced: its counters restarted and the caller must also reset the
    /// neighbor's MLE frame counter (OpenThread `SetMleFrameCounter(0)`).
    /// Ignores frames with an older key sequence.
    pub fn update(&mut self, key_sequence: u32, frame_counter: u32) -> bool {
        if key_sequence < self.key_sequence {
            return false;
        }
        let advanced = key_sequence > self.key_sequence;
        if advanced {
            *self = Self {
                key_sequence,
                next: 0,
                ack_next: 0,
            };
        }
        let next = u64::from(frame_counter) + 1;
        self.next = self.next.max(next);
        // The neighbor uses one counter for frames and enhanced ACKs.
        self.ack_next = self.ack_next.max(next);
        advanced
    }

    /// [`check`](Self::check) and [`update`](Self::update) for a frame that
    /// passed [`FrameSecurity::unsecure_rx`](crate::frame_security::FrameSecurity::unsecure_rx).
    /// Key ID mode 2 frames (`key_sequence: None`) carry no replay
    /// protection (Thread §7.2.1.3) and are accepted without change
    /// (`Ok(false)`).
    pub fn check_and_update(&mut self, info: &RxSecurityInfo) -> Result<bool> {
        let Some(seq) = info.key_sequence else {
            return Ok(false);
        };
        self.check(seq, info.frame_counter)?;
        Ok(self.update(seq, info.frame_counter))
    }

    /// Check an enhanced ACK frame counter (OpenThread
    /// `ProcessEnhAckSecurity`: `frameCounter >= GetLinkAckFrameCounter()`).
    /// [`Error::Security`] if it is older.
    pub fn check_ack(&self, frame_counter: u32) -> Result<()> {
        if u64::from(frame_counter) < self.ack_next {
            return Err(Error::Security);
        }
        Ok(())
    }

    /// Check and record an enhanced ACK that passed
    /// [`KeyManager::unsecure_enh_ack`](super::KeyManager::unsecure_enh_ack).
    /// The ACK's key sequence is not adopted (as OpenThread).
    pub fn check_and_update_ack(&mut self, info: &RxSecurityInfo) -> Result<()> {
        self.check_ack(info.frame_counter)?;
        self.ack_next = u64::from(info.frame_counter) + 1;
        Ok(())
    }
}

const fn as_u32(v: u64) -> Option<u32> {
    if v > u32::MAX as u64 {
        None
    } else {
        Some(v as u32)
    }
}
