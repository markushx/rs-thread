//! Spinel frame header and frame (de)serialisation.
//!
//! A frame is the header byte (`0b10` flag, 2 bit interface ID, 4 bit TID),
//! the command as packed integer and the command payload. Property commands
//! carry the property key (packed) followed by the value.

use crate::codec::{Reader, Writer};
use crate::consts::cmd;
use crate::{Error, Result};

/// The fixed flag bits of a header byte.
pub const HEADER_FLAG: u8 = 0x80;

/// A frame header: interface ID and transaction ID.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Header {
    /// Interface ID (0..=3).
    pub iid: u8,
    /// Transaction ID (0..=15); 0 marks unsolicited frames.
    pub tid: u8,
}

impl Header {
    /// A header for interface `iid` and transaction `tid`.
    pub const fn new(iid: u8, tid: u8) -> Self {
        Self {
            iid: iid & 3,
            tid: tid & 0xf,
        }
    }

    /// Unsolicited frames use TID 0 on interface 0.
    pub const UNSOLICITED: Self = Self::new(0, 0);

    /// The header byte.
    pub const fn to_byte(self) -> u8 {
        HEADER_FLAG | (self.iid << 4) | self.tid
    }

    /// Parses a header byte; the flag bits must be `0b10`.
    pub fn from_byte(b: u8) -> Result<Self> {
        if b & 0xc0 != HEADER_FLAG {
            return Err(Error::Parse);
        }
        Ok(Self {
            iid: (b >> 4) & 3,
            tid: b & 0xf,
        })
    }
}

/// A parsed frame: header, command and command payload.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct Frame<'a> {
    /// The frame header.
    pub header: Header,
    /// The command (`cmd::*`).
    pub command: u32,
    /// Everything after the command.
    pub payload: &'a [u8],
}

impl<'a> Frame<'a> {
    /// Parses a frame.
    pub fn parse(data: &'a [u8]) -> Result<Self> {
        let mut r = Reader::new(data);
        let header = Header::from_byte(r.u8()?)?;
        let command = r.packed()?;
        Ok(Self {
            header,
            command,
            payload: r.rest(),
        })
    }

    /// Whether the command carries a property key.
    pub const fn is_property_command(&self) -> bool {
        matches!(
            self.command,
            cmd::PROP_VALUE_GET
                | cmd::PROP_VALUE_SET
                | cmd::PROP_VALUE_INSERT
                | cmd::PROP_VALUE_REMOVE
                | cmd::PROP_VALUE_IS
                | cmd::PROP_VALUE_INSERTED
                | cmd::PROP_VALUE_REMOVED
        )
    }

    /// For property commands: the key and the value bytes.
    pub fn property(&self) -> Result<(u32, &'a [u8])> {
        if !self.is_property_command() {
            return Err(Error::Parse);
        }
        let mut r = Reader::new(self.payload);
        let key = r.packed()?;
        Ok((key, r.rest()))
    }
}

/// Starts a frame in `w`: header and command.
pub fn begin(w: &mut Writer<'_>, header: Header, command: u32) -> Result<()> {
    w.u8(header.to_byte())?;
    w.packed(command)
}

/// Starts a property frame in `w`: header, command and key; the value
/// follows.
pub fn begin_property(w: &mut Writer<'_>, header: Header, command: u32, key: u32) -> Result<()> {
    begin(w, header, command)?;
    w.packed(key)
}

/// A complete `PROP_VALUE_IS LAST_STATUS` frame.
pub fn write_last_status(w: &mut Writer<'_>, header: Header, status: u32) -> Result<()> {
    begin_property(
        w,
        header,
        cmd::PROP_VALUE_IS,
        crate::consts::prop::LAST_STATUS,
    )?;
    w.packed(status)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consts::prop;

    #[test]
    fn header() {
        assert_eq!(Header::new(0, 1).to_byte(), 0x81);
        assert_eq!(Header::new(2, 15).to_byte(), 0xaf);
        assert_eq!(Header::from_byte(0xaf).unwrap(), Header::new(2, 15));
        assert!(Header::from_byte(0x01).is_err());
        assert!(Header::from_byte(0xc1).is_err());
    }

    #[test]
    fn get_protocol_version() {
        // The first frame an OpenThread host sends: 81 02 01.
        let f = Frame::parse(&[0x81, 0x02, 0x01]).unwrap();
        assert_eq!(f.header, Header::new(0, 1));
        assert_eq!(f.command, cmd::PROP_VALUE_GET);
        assert_eq!(f.property().unwrap(), (prop::PROTOCOL_VERSION, &[][..]));
    }

    #[test]
    fn two_byte_key_frame() {
        // SET RADIO_CAPS-sized key (0x120b) = 0x8b 0x24.
        let mut buf = [0u8; 16];
        let mut w = Writer::new(&mut buf);
        begin_property(
            &mut w,
            Header::new(0, 3),
            cmd::PROP_VALUE_IS,
            prop::RADIO_CAPS,
        )
        .unwrap();
        w.packed(0x27).unwrap();
        assert_eq!(w.as_slice(), &[0x83, 0x06, 0x8b, 0x24, 0x27]);
        let f = Frame::parse(w.as_slice()).unwrap();
        assert_eq!(f.property().unwrap(), (prop::RADIO_CAPS, &[0x27][..]));
    }

    #[test]
    fn last_status_and_noop() {
        let mut buf = [0u8; 8];
        let mut w = Writer::new(&mut buf);
        write_last_status(&mut w, Header::UNSOLICITED, 114).unwrap();
        assert_eq!(w.as_slice(), &[0x80, 0x06, 0x00, 114]);
        let f = Frame::parse(&[0x82, 0x00]).unwrap();
        assert_eq!(f.command, cmd::NOOP);
        assert!(f.property().is_err());
        assert!(Frame::parse(&[]).is_err());
    }
}
