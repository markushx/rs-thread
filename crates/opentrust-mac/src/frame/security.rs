//! Auxiliary Security Header (IEEE 802.15.4-2015 section 9.4).

use opentrust_core::bytes::{Reader, Writer};
use opentrust_core::crypto::SecurityLevel;
use opentrust_core::{Error, Result};

/// Key Identifier Mode (Security Control bits 3..4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum KeyIdMode {
    /// Mode 0: key determined implicitly from the addresses.
    Implicit,
    /// Mode 1: 1-byte key index, default key source (Thread MAC frames).
    Index,
    /// Mode 2: 4-byte key source + key index (Thread key-ID-mode-2 frames).
    Source4,
    /// Mode 3: 8-byte key source + key index.
    Source8,
}

impl KeyIdMode {
    /// The 2-bit wire value.
    pub const fn bits(self) -> u8 {
        match self {
            Self::Implicit => 0,
            Self::Index => 1,
            Self::Source4 => 2,
            Self::Source8 => 3,
        }
    }

    /// Decode the 2-bit wire value.
    pub const fn from_bits(bits: u8) -> Self {
        match bits & 3 {
            0 => Self::Implicit,
            1 => Self::Index,
            2 => Self::Source4,
            _ => Self::Source8,
        }
    }

    /// Size of the key source field in bytes.
    pub const fn key_source_len(self) -> usize {
        match self {
            Self::Implicit | Self::Index => 0,
            Self::Source4 => 4,
            Self::Source8 => 8,
        }
    }

    /// Size of the whole Key Identifier field (key source + key index).
    pub const fn key_identifier_len(self) -> usize {
        match self {
            Self::Implicit => 0,
            m => m.key_source_len() + 1,
        }
    }
}

/// The Key Identifier field. Key sources are kept in on-air byte order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum KeyIdentifier {
    /// Mode 0: no key identifier.
    Implicit,
    /// Mode 1: key index.
    Index(u8),
    /// Mode 2: 4-byte key source and key index.
    Source4 {
        /// Key source bytes.
        source: [u8; 4],
        /// Key index.
        index: u8,
    },
    /// Mode 3: 8-byte key source and key index.
    Source8 {
        /// Key source bytes.
        source: [u8; 8],
        /// Key index.
        index: u8,
    },
}

impl KeyIdentifier {
    /// The Key Identifier Mode of this identifier.
    pub const fn mode(&self) -> KeyIdMode {
        match self {
            Self::Implicit => KeyIdMode::Implicit,
            Self::Index(_) => KeyIdMode::Index,
            Self::Source4 { .. } => KeyIdMode::Source4,
            Self::Source8 { .. } => KeyIdMode::Source8,
        }
    }

    /// The key index, if the mode has one.
    pub const fn index(&self) -> Option<u8> {
        match self {
            Self::Implicit => None,
            Self::Index(i) | Self::Source4 { index: i, .. } | Self::Source8 { index: i, .. } => {
                Some(*i)
            }
        }
    }

    /// The key source bytes (empty for modes 0 and 1).
    pub fn source(&self) -> &[u8] {
        match self {
            Self::Source4 { source, .. } => source,
            Self::Source8 { source, .. } => source,
            _ => &[],
        }
    }
}

/// Parsed / to-be-built Auxiliary Security Header.
///
/// Thread uses security level 5 (`EncMic32`) with key ID mode 1 for
/// regular frames and mode 2 for some link-establishment frames
/// (Thread 1.x section 7.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct SecurityHeader {
    /// Security level (never [`SecurityLevel::None`]).
    pub level: SecurityLevel,
    /// Frame counter; `None` if suppressed (2015 only, ASN used instead).
    pub frame_counter: Option<u32>,
    /// ASN-in-nonce bit (802.15.4-2015, TSCH).
    pub asn_in_nonce: bool,
    /// Key identifier.
    pub key: KeyIdentifier,
}

impl SecurityHeader {
    /// Create a header with a frame counter and no ASN in the nonce.
    pub const fn new(level: SecurityLevel, frame_counter: u32, key: KeyIdentifier) -> Self {
        Self {
            level,
            frame_counter: Some(frame_counter),
            asn_in_nonce: false,
            key,
        }
    }

    /// Key Identifier Mode.
    pub const fn key_id_mode(&self) -> KeyIdMode {
        self.key.mode()
    }

    /// The Security Control octet.
    pub const fn control(&self) -> u8 {
        self.level.value()
            | self.key.mode().bits() << 3
            | (self.frame_counter.is_none() as u8) << 5
            | (self.asn_in_nonce as u8) << 6
    }

    /// Length of the encoded header in bytes (control + counter + key id).
    pub const fn encoded_len(&self) -> usize {
        1 + 4 * self.frame_counter.is_some() as usize + self.key.mode().key_identifier_len()
    }

    /// Length of the MIC this level appends to the frame.
    pub const fn mic_len(&self) -> usize {
        self.level.mic_len()
    }

    /// `true` if the payload is encrypted at this level.
    pub const fn is_encrypted(&self) -> bool {
        self.level.is_encrypted()
    }

    /// Parse from `r`. Level 0 (an aux header without protection) is
    /// rejected, as OpenThread does.
    pub fn parse(r: &mut Reader<'_>) -> Result<Self> {
        let ctl = r.read_u8()?;
        let level = SecurityLevel::from_bits(ctl);
        if level == SecurityLevel::None {
            return Err(Error::Parse);
        }
        let mode = KeyIdMode::from_bits(ctl >> 3);
        let frame_counter = if ctl & (1 << 5) != 0 {
            None
        } else {
            Some(r.read_u32_le()?)
        };
        let key = match mode {
            KeyIdMode::Implicit => KeyIdentifier::Implicit,
            KeyIdMode::Index => KeyIdentifier::Index(r.read_u8()?),
            KeyIdMode::Source4 => KeyIdentifier::Source4 {
                source: r.read_array()?,
                index: r.read_u8()?,
            },
            KeyIdMode::Source8 => KeyIdentifier::Source8 {
                source: r.read_array()?,
                index: r.read_u8()?,
            },
        };
        Ok(Self {
            level,
            frame_counter,
            asn_in_nonce: ctl & (1 << 6) != 0,
            key,
        })
    }

    /// Write the header. [`Error::InvalidArgs`] for level 0.
    pub fn write(&self, w: &mut Writer<'_>) -> Result<()> {
        if self.level == SecurityLevel::None {
            return Err(Error::InvalidArgs);
        }
        w.write_u8(self.control())?;
        if let Some(c) = self.frame_counter {
            w.write_u32_le(c)?;
        }
        match self.key {
            KeyIdentifier::Implicit => Ok(()),
            KeyIdentifier::Index(i) => w.write_u8(i),
            KeyIdentifier::Source4 { source, index } => {
                w.write_slice(&source)?;
                w.write_u8(index)
            }
            KeyIdentifier::Source8 { source, index } => {
                w.write_slice(&source)?;
                w.write_u8(index)
            }
        }
    }
}
