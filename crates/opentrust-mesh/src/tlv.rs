//! Thread network-layer TLVs (OT `thread_tlvs.hpp`, Thread 1.4.1 section
//! 5.19): the payload of the address solicit / release / query / notify /
//! error TMF messages.
//!
//! [`ThreadTlv`] is the typed form of one TLV with parse and write;
//! [`ThreadTlvs`] is a read view over a payload with one accessor per TLV
//! type. All values are big-endian like the wire format.

use core::net::Ipv6Addr;

use opentrust_core::bytes::Writer;
use opentrust_core::tlv::{self, Tlv, TlvIter};
use opentrust_core::types::{ExtAddress, Iid, Rloc16};
use opentrust_core::{Error, Result};
use opentrust_mle::tlv::RouterIdMask;

/// TLV type numbers (OT `ThreadTlv::Type`).
pub mod ty {
    /// Target EID.
    pub const TARGET: u8 = 0;
    /// Extended MAC Address.
    pub const EXT_MAC_ADDRESS: u8 = 1;
    /// RLOC16.
    pub const RLOC16: u8 = 2;
    /// Mesh-Local EID.
    pub const MESH_LOCAL_EID: u8 = 3;
    /// Status.
    pub const STATUS: u8 = 4;
    /// Time Since Last Transaction.
    pub const LAST_TRANSACTION_TIME: u8 = 6;
    /// Router Mask.
    pub const ROUTER_MASK: u8 = 7;
    /// ND Option.
    pub const ND_OPTION: u8 = 8;
    /// ND Data.
    pub const ND_DATA: u8 = 9;
    /// Thread Network Data.
    pub const NETWORK_DATA: u8 = 10;
    /// Timeout.
    pub const TIMEOUT: u8 = 11;
    /// Network Name.
    pub const NETWORK_NAME: u8 = 12;
    /// IPv6 Addresses.
    pub const IP6_ADDRESSES: u8 = 14;
    /// Commissioner Session ID.
    pub const COMMISSIONER_SESSION_ID: u8 = 15;
}

/// Status TLV values (OT `ThreadStatusTlv::Status`).
pub mod status {
    /// Success.
    pub const SUCCESS: u8 = 0;
    /// No address available.
    pub const NO_ADDRESS_AVAILABLE: u8 = 1;
    /// Address Solicit because there are too few routers.
    pub const TOO_FEW_ROUTERS: u8 = 2;
    /// Address Solicit because of a Child ID Request.
    pub const HAVE_CHILD_ID_REQUEST: u8 = 3;
    /// Address Solicit because of a parent partition change.
    pub const PARENT_PARTITION_CHANGE: u8 = 4;
    /// Address Solicit from a Border Router request.
    pub const BORDER_ROUTER_REQUEST: u8 = 5;
    /// The requested status is unrecognized.
    pub const UNRECOGNIZED_STATUS: u8 = 6;
}

/// Length of the Router Mask TLV value (ID sequence + 64-bit mask).
pub const ROUTER_MASK_LEN: usize = 9;

/// One Thread network-layer TLV.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreadTlv<'a> {
    /// Target EID (an IPv6 address).
    Target(Ipv6Addr),
    /// Extended MAC address (ML-EUI64 for address solicit).
    ExtMacAddress(ExtAddress),
    /// RLOC16.
    Rloc16(Rloc16),
    /// Mesh-Local EID interface identifier.
    MeshLocalEid(Iid),
    /// Status.
    Status(u8),
    /// Seconds since the last transaction of the target EID.
    LastTransactionTime(u32),
    /// Router ID sequence and assigned router ID mask.
    RouterMask {
        /// Router ID sequence number.
        id_sequence: u8,
        /// Assigned router IDs.
        mask: RouterIdMask,
    },
    /// Thread Network Data (not interpreted here).
    NetworkData(&'a [u8]),
    /// Timeout in seconds.
    Timeout(u32),
    /// Network name.
    NetworkName(&'a str),
    /// IPv6 Addresses (not interpreted here).
    Ip6Addresses(&'a [u8]),
    /// Commissioner Session ID.
    CommissionerSessionId(u16),
    /// Any other type.
    Unknown {
        /// Type number.
        ty: u8,
        /// Raw value.
        value: &'a [u8],
    },
}

impl<'a> ThreadTlv<'a> {
    /// Interpret a raw TLV. [`Error::Parse`] if the value of a known type
    /// has the wrong length.
    pub fn from_tlv(t: &Tlv<'a>) -> Result<Self> {
        Ok(match t.ty() {
            ty::TARGET => Self::Target(Ipv6Addr::from(t.read_array::<16>()?)),
            ty::EXT_MAC_ADDRESS => Self::ExtMacAddress(ExtAddress(t.read_array::<8>()?)),
            ty::RLOC16 => Self::Rloc16(Rloc16(t.read_u16()?)),
            ty::MESH_LOCAL_EID => Self::MeshLocalEid(Iid(t.read_array::<8>()?)),
            ty::STATUS => Self::Status(t.read_u8()?),
            ty::LAST_TRANSACTION_TIME => Self::LastTransactionTime(t.read_u32()?),
            ty::ROUTER_MASK => {
                // OT `ThreadRouterMaskTlv::IsValid`: at least the fixed part.
                let v = t.value();
                if v.len() < ROUTER_MASK_LEN {
                    return Err(Error::Parse);
                }
                let mut m = [0u8; 8];
                m.copy_from_slice(&v[1..9]);
                Self::RouterMask {
                    id_sequence: v[0],
                    mask: RouterIdMask(m),
                }
            }
            ty::NETWORK_DATA => Self::NetworkData(t.value()),
            ty::TIMEOUT => Self::Timeout(t.read_u32()?),
            ty::NETWORK_NAME => {
                Self::NetworkName(core::str::from_utf8(t.value()).map_err(|_| Error::Parse)?)
            }
            ty::IP6_ADDRESSES => Self::Ip6Addresses(t.value()),
            ty::COMMISSIONER_SESSION_ID => Self::CommissionerSessionId(t.read_u16()?),
            other => Self::Unknown {
                ty: other,
                value: t.value(),
            },
        })
    }

    /// Iterate over the typed TLVs of `payload`.
    pub fn iter(payload: &'a [u8]) -> impl Iterator<Item = Result<ThreadTlv<'a>>> {
        TlvIter::new(payload).map(|t| t.and_then(|t| Self::from_tlv(&t)))
    }

    /// Append this TLV.
    pub fn write(&self, w: &mut Writer<'_>) -> Result<()> {
        match *self {
            Self::Target(a) => tlv::write(w, ty::TARGET, &a.octets()),
            Self::ExtMacAddress(e) => tlv::write(w, ty::EXT_MAC_ADDRESS, &e.0),
            Self::Rloc16(r) => tlv::write_u16(w, ty::RLOC16, r.0),
            Self::MeshLocalEid(i) => tlv::write(w, ty::MESH_LOCAL_EID, &i.0),
            Self::Status(s) => tlv::write_u8(w, ty::STATUS, s),
            Self::LastTransactionTime(t) => tlv::write_u32(w, ty::LAST_TRANSACTION_TIME, t),
            Self::RouterMask { id_sequence, mask } => {
                let mut v = [0u8; ROUTER_MASK_LEN];
                v[0] = id_sequence;
                v[1..].copy_from_slice(&mask.0);
                tlv::write(w, ty::ROUTER_MASK, &v)
            }
            Self::NetworkData(d) => tlv::write(w, ty::NETWORK_DATA, d),
            Self::Timeout(t) => tlv::write_u32(w, ty::TIMEOUT, t),
            Self::NetworkName(n) => tlv::write(w, ty::NETWORK_NAME, n.as_bytes()),
            Self::Ip6Addresses(d) => tlv::write(w, ty::IP6_ADDRESSES, d),
            Self::CommissionerSessionId(s) => tlv::write_u16(w, ty::COMMISSIONER_SESSION_ID, s),
            Self::Unknown { ty, value } => tlv::write(w, ty, value),
        }
    }
}

/// Read view over a payload of Thread network-layer TLVs. Each accessor
/// returns [`Error::NotFound`] if the TLV is absent and [`Error::Parse`] if
/// it (or an earlier TLV) is malformed, like OT `Tlv::Find`.
#[derive(Debug, Clone, Copy)]
pub struct ThreadTlvs<'a>(&'a [u8]);

impl<'a> ThreadTlvs<'a> {
    /// View over `payload`.
    pub const fn new(payload: &'a [u8]) -> Self {
        Self(payload)
    }

    fn find(&self, ty: u8) -> Result<ThreadTlv<'a>> {
        ThreadTlv::from_tlv(&tlv::find(self.0, ty)?)
    }

    /// Target EID TLV.
    pub fn target(&self) -> Result<Ipv6Addr> {
        match self.find(ty::TARGET)? {
            ThreadTlv::Target(a) => Ok(a),
            _ => Err(Error::Parse),
        }
    }

    /// Extended MAC Address TLV.
    pub fn ext_mac_address(&self) -> Result<ExtAddress> {
        match self.find(ty::EXT_MAC_ADDRESS)? {
            ThreadTlv::ExtMacAddress(a) => Ok(a),
            _ => Err(Error::Parse),
        }
    }

    /// RLOC16 TLV.
    pub fn rloc16(&self) -> Result<Rloc16> {
        match self.find(ty::RLOC16)? {
            ThreadTlv::Rloc16(a) => Ok(a),
            _ => Err(Error::Parse),
        }
    }

    /// Mesh-Local EID TLV.
    pub fn ml_eid(&self) -> Result<Iid> {
        match self.find(ty::MESH_LOCAL_EID)? {
            ThreadTlv::MeshLocalEid(a) => Ok(a),
            _ => Err(Error::Parse),
        }
    }

    /// Status TLV.
    pub fn status(&self) -> Result<u8> {
        match self.find(ty::STATUS)? {
            ThreadTlv::Status(a) => Ok(a),
            _ => Err(Error::Parse),
        }
    }

    /// Time Since Last Transaction TLV.
    pub fn last_transaction_time(&self) -> Result<u32> {
        match self.find(ty::LAST_TRANSACTION_TIME)? {
            ThreadTlv::LastTransactionTime(a) => Ok(a),
            _ => Err(Error::Parse),
        }
    }

    /// Thread Network Data TLV: the Network Data TLV bytes.
    pub fn network_data(&self) -> Result<&'a [u8]> {
        match self.find(ty::NETWORK_DATA)? {
            ThreadTlv::NetworkData(a) => Ok(a),
            _ => Err(Error::Parse),
        }
    }

    /// Router Mask TLV: ID sequence and mask.
    pub fn router_mask(&self) -> Result<(u8, RouterIdMask)> {
        match self.find(ty::ROUTER_MASK)? {
            ThreadTlv::RouterMask { id_sequence, mask } => Ok((id_sequence, mask)),
            _ => Err(Error::Parse),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(t: ThreadTlv<'_>) {
        let mut buf = [0u8; 64];
        let mut w = Writer::new(&mut buf);
        t.write(&mut w).unwrap();
        let n = w.len();
        let mut it = ThreadTlv::iter(&buf[..n]);
        assert_eq!(it.next().unwrap().unwrap(), t);
        assert!(it.next().is_none());
    }

    #[test]
    fn typed_roundtrip() {
        let mut mask = RouterIdMask::new();
        mask.insert(0).unwrap();
        mask.insert(17).unwrap();
        roundtrip(ThreadTlv::Target("fd00::1234".parse().unwrap()));
        roundtrip(ThreadTlv::ExtMacAddress(ExtAddress([
            1, 2, 3, 4, 5, 6, 7, 8,
        ])));
        roundtrip(ThreadTlv::Rloc16(Rloc16(0x4400)));
        roundtrip(ThreadTlv::MeshLocalEid(Iid([9; 8])));
        roundtrip(ThreadTlv::Status(status::HAVE_CHILD_ID_REQUEST));
        roundtrip(ThreadTlv::LastTransactionTime(0x0102_0304));
        roundtrip(ThreadTlv::RouterMask {
            id_sequence: 7,
            mask,
        });
        roundtrip(ThreadTlv::Timeout(240));
        roundtrip(ThreadTlv::NetworkName("OpenTrust"));
        roundtrip(ThreadTlv::CommissionerSessionId(0xabcd));
        roundtrip(ThreadTlv::NetworkData(&[1, 2, 3]));
        roundtrip(ThreadTlv::Unknown {
            ty: 99,
            value: &[1],
        });
    }

    #[test]
    fn wire_format() {
        // Status TLV and the router mask from the OT response layout.
        let mut buf = [0u8; 32];
        let mut w = Writer::new(&mut buf);
        ThreadTlv::Status(0).write(&mut w).unwrap();
        ThreadTlv::Rloc16(Rloc16(0x0800)).write(&mut w).unwrap();
        let mut m = RouterIdMask::new();
        m.insert(0).unwrap();
        m.insert(2).unwrap();
        ThreadTlv::RouterMask {
            id_sequence: 3,
            mask: m,
        }
        .write(&mut w)
        .unwrap();
        let n = w.len();
        assert_eq!(
            &buf[..n],
            &[4, 1, 0, 2, 2, 0x08, 0, 7, 9, 3, 0xa0, 0, 0, 0, 0, 0, 0, 0]
        );
    }

    #[test]
    fn accessors() {
        let mut buf = [0u8; 64];
        let mut w = Writer::new(&mut buf);
        ThreadTlv::Target("fd00::1".parse().unwrap())
            .write(&mut w)
            .unwrap();
        ThreadTlv::MeshLocalEid(Iid([5; 8])).write(&mut w).unwrap();
        ThreadTlv::Rloc16(Rloc16(0x1c00)).write(&mut w).unwrap();
        ThreadTlv::LastTransactionTime(9).write(&mut w).unwrap();
        let n = w.len();
        let v = ThreadTlvs::new(&buf[..n]);
        assert_eq!(v.target().unwrap(), "fd00::1".parse::<Ipv6Addr>().unwrap());
        assert_eq!(v.ml_eid().unwrap(), Iid([5; 8]));
        assert_eq!(v.rloc16().unwrap(), Rloc16(0x1c00));
        assert_eq!(v.last_transaction_time().unwrap(), 9);
        assert_eq!(v.status(), Err(Error::NotFound));
        assert_eq!(v.router_mask(), Err(Error::NotFound));
    }

    #[test]
    fn malformed() {
        // Wrong lengths of known types.
        assert_eq!(ThreadTlvs::new(&[2, 1, 0]).rloc16(), Err(Error::Parse));
        assert_eq!(ThreadTlvs::new(&[4, 0]).status(), Err(Error::Parse));
        assert_eq!(
            ThreadTlvs::new(&[7, 3, 0, 0, 0]).router_mask(),
            Err(Error::Parse)
        );
        // Truncated TLV.
        assert_eq!(ThreadTlvs::new(&[2, 2, 0]).rloc16(), Err(Error::Parse));
        // Longer router mask is accepted (OT only checks the minimum).
        let mut v = [0u8; 12];
        v[0] = 7;
        v[1] = 10;
        assert!(ThreadTlvs::new(&v).router_mask().is_ok());
    }
}
