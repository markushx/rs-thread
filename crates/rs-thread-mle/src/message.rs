//! MLE command types and message building (Thread 1.4.1 §4.3, §4.13.2;
//! OpenThread `Mle::TxMessage`).
//!
//! An MLE message is the payload of a UDP datagram on port
//! [`MLE_UDP_PORT`](crate::consts::MLE_UDP_PORT):
//!
//! ```text
//! secured:   suite (0) | aux security header (10) | command | TLVs ... | MIC (4)
//!            (command + TLVs are encrypted, see `security`)
//! unsecured: suite (255) | command | TLVs ...    (Discovery Request/Response only)
//! ```
//!
//! [`MleBuilder`] lays out the header for you and exposes a
//! [`TlvWriter`] for the TLVs; [`security::secure`](crate::security::secure)
//! then fills the header and encrypts. [`security::unsecure`](crate::security::unsecure)
//! is the inverse and returns the command and a [`Tlvs`](crate::tlv::Tlvs) view.

use rs_thread_core::{Error, Result};

use crate::security::{AUX_HEADER_LEN, NO_SECURITY, SECURITY_SUITE_154, TAG_LEN};
use crate::tlv::TlvWriter;

/// MLE command types (Table 4-5; OT `Mle::Command`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(u8)]
pub enum Command {
    /// Link Request.
    LinkRequest = 0,
    /// Link Accept.
    LinkAccept = 1,
    /// Link Accept and Request.
    LinkAcceptAndRequest = 2,
    /// Link Reject.
    LinkReject = 3,
    /// Advertisement.
    Advertisement = 4,
    /// Update (not used in Thread).
    Update = 5,
    /// Update Request (not used in Thread).
    UpdateRequest = 6,
    /// Data Request.
    DataRequest = 7,
    /// Data Response.
    DataResponse = 8,
    /// Parent Request.
    ParentRequest = 9,
    /// Parent Response.
    ParentResponse = 10,
    /// Child ID Request.
    ChildIdRequest = 11,
    /// Child ID Response.
    ChildIdResponse = 12,
    /// Child Update Request.
    ChildUpdateRequest = 13,
    /// Child Update Response.
    ChildUpdateResponse = 14,
    /// Announce.
    Announce = 15,
    /// Discovery Request.
    DiscoveryRequest = 16,
    /// Discovery Response.
    DiscoveryResponse = 17,
    /// Link Metrics Management Request.
    LinkMetricsManagementRequest = 18,
    /// Link Metrics Management Response.
    LinkMetricsManagementResponse = 19,
    /// Link Probe.
    LinkProbe = 20,
    /// Time Sync (OT time-sync extension, not in the specification).
    TimeSync = 99,
}

impl Command {
    /// Decode a command byte; `None` for unassigned values.
    pub const fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            0 => Self::LinkRequest,
            1 => Self::LinkAccept,
            2 => Self::LinkAcceptAndRequest,
            3 => Self::LinkReject,
            4 => Self::Advertisement,
            5 => Self::Update,
            6 => Self::UpdateRequest,
            7 => Self::DataRequest,
            8 => Self::DataResponse,
            9 => Self::ParentRequest,
            10 => Self::ParentResponse,
            11 => Self::ChildIdRequest,
            12 => Self::ChildIdResponse,
            13 => Self::ChildUpdateRequest,
            14 => Self::ChildUpdateResponse,
            15 => Self::Announce,
            16 => Self::DiscoveryRequest,
            17 => Self::DiscoveryResponse,
            18 => Self::LinkMetricsManagementRequest,
            19 => Self::LinkMetricsManagementResponse,
            20 => Self::LinkProbe,
            99 => Self::TimeSync,
            _ => return None,
        })
    }

    /// Wire value.
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    /// Commands sent with security suite 255 (no MLE security): the
    /// Discovery Request and Response (§4.13.1, OT `HandleUdpReceive`).
    pub const fn is_unsecured(self) -> bool {
        matches!(self, Self::DiscoveryRequest | Self::DiscoveryResponse)
    }
}

/// Lays out an outgoing MLE message in a caller-provided buffer.
///
/// The builder writes the security suite (0 or 255, chosen from the command),
/// leaves room for the auxiliary security header of secured messages, writes
/// the command byte and hands out a [`TlvWriter`] for the TLVs. Room for the
/// 4-byte MIC is reserved at the end of the buffer. After the TLVs are
/// written, [`finish`](Self::finish) yields the message length and
/// [`security::secure`](crate::security::secure) completes it.
#[derive(Debug)]
pub struct MleBuilder<'a> {
    tlvs: TlvWriter<'a>,
}

impl<'a> MleBuilder<'a> {
    /// Start a message with `command`; the security suite follows
    /// [`Command::is_unsecured`]. [`Error::NoBufs`] if `buf` cannot hold the
    /// header (and MIC).
    pub fn new(buf: &'a mut [u8], command: Command) -> Result<Self> {
        if command.is_unsecured() {
            Self::start(buf, NO_SECURITY, 0, command)
        } else {
            Self::start(buf, SECURITY_SUITE_154, AUX_HEADER_LEN, command)
        }
    }

    fn start(buf: &'a mut [u8], suite: u8, aux: usize, command: Command) -> Result<Self> {
        let tag = if suite == SECURITY_SUITE_154 {
            TAG_LEN
        } else {
            0
        };
        let end = buf.len().checked_sub(tag).ok_or(Error::NoBufs)?;
        let mut tlvs = TlvWriter::new(&mut buf[..end]);
        let w = tlvs.writer();
        w.write_u8(suite)?;
        for _ in 0..aux {
            w.write_u8(0)?;
        }
        w.write_u8(command.as_u8())?;
        Ok(Self { tlvs })
    }

    /// The TLV writer.
    pub fn tlvs(&mut self) -> &mut TlvWriter<'a> {
        &mut self.tlvs
    }

    /// Length of the message so far (the value to pass to
    /// [`security::secure`](crate::security::secure); for an unsecured
    /// message this is the final length).
    pub fn finish(self) -> usize {
        self.tlvs.len()
    }
}
