//! MeshCoP TLV codec (Thread 1.4.1 section 8.10, OT `meshcop_tlvs.{hpp,cpp}`).
//!
//! MeshCoP TLVs use the generic Type / Length / Value framing of
//! [`opentrust_core::tlv`] (1-byte length, `0xff` marks a 2-byte extended
//! length). [`Tlvs`] is a typed read view over a buffer of TLVs (a CoAP
//! payload, an Operational Dataset, a Discovery TLV value); [`WriterExt`]
//! appends typed TLVs to a [`Writer`].

use core::net::Ipv6Addr;
use opentrust_core::bytes::Writer;
use opentrust_core::tlv::{self, Tlv, TlvIter};

use opentrust_core::types::{ExtPanId, Iid, Kek, NetworkKey, NetworkName, Prefix64, Pskc};
use opentrust_core::{Error, Result};

use crate::steering::SteeringData;
use crate::timestamp::Timestamp;

/// MeshCoP TLV type numbers (OT `Tlv::Type`).
pub mod ty {
    /// Channel.
    pub const CHANNEL: u8 = 0;
    /// PAN ID.
    pub const PAN_ID: u8 = 1;
    /// Extended PAN ID.
    pub const EXT_PAN_ID: u8 = 2;
    /// Network Name.
    pub const NETWORK_NAME: u8 = 3;
    /// PSKc.
    pub const PSKC: u8 = 4;
    /// Network Key (master key).
    pub const NETWORK_KEY: u8 = 5;
    /// Network Key Sequence.
    pub const NETWORK_KEY_SEQUENCE: u8 = 6;
    /// Mesh-Local Prefix.
    pub const MESH_LOCAL_PREFIX: u8 = 7;
    /// Steering Data.
    pub const STEERING_DATA: u8 = 8;
    /// Border Agent Locator.
    pub const BORDER_AGENT_LOCATOR: u8 = 9;
    /// Commissioner ID.
    pub const COMMISSIONER_ID: u8 = 10;
    /// Commissioner Session ID.
    pub const COMMISSIONER_SESSION_ID: u8 = 11;
    /// Security Policy.
    pub const SECURITY_POLICY: u8 = 12;
    /// Get (list of requested TLV types).
    pub const GET: u8 = 13;
    /// Active Timestamp.
    pub const ACTIVE_TIMESTAMP: u8 = 14;
    /// Commissioner UDP Port.
    pub const COMMISSIONER_UDP_PORT: u8 = 15;
    /// State.
    pub const STATE: u8 = 16;
    /// Joiner DTLS Encapsulation.
    pub const JOINER_DTLS_ENCAPSULATION: u8 = 17;
    /// Joiner UDP Port.
    pub const JOINER_UDP_PORT: u8 = 18;
    /// Joiner IID.
    pub const JOINER_IID: u8 = 19;
    /// Joiner Router Locator.
    pub const JOINER_ROUTER_LOCATOR: u8 = 20;
    /// Joiner Router KEK.
    pub const JOINER_ROUTER_KEK: u8 = 21;
    /// Provisioning URL.
    pub const PROVISIONING_URL: u8 = 32;
    /// Vendor Name.
    pub const VENDOR_NAME: u8 = 33;
    /// Vendor Model.
    pub const VENDOR_MODEL: u8 = 34;
    /// Vendor SW Version.
    pub const VENDOR_SW_VERSION: u8 = 35;
    /// Vendor Data.
    pub const VENDOR_DATA: u8 = 36;
    /// Vendor Stack Version.
    pub const VENDOR_STACK_VERSION: u8 = 37;
    /// UDP Encapsulation.
    pub const UDP_ENCAPSULATION: u8 = 48;
    /// IPv6 Address.
    pub const IPV6_ADDRESS: u8 = 49;
    /// Pending Timestamp.
    pub const PENDING_TIMESTAMP: u8 = 51;
    /// Delay Timer.
    pub const DELAY_TIMER: u8 = 52;
    /// Channel Mask.
    pub const CHANNEL_MASK: u8 = 53;
    /// Count.
    pub const COUNT: u8 = 54;
    /// Period.
    pub const PERIOD: u8 = 55;
    /// Scan Duration.
    pub const SCAN_DURATION: u8 = 56;
    /// Energy List.
    pub const ENERGY_LIST: u8 = 57;
    /// Thread Domain Name.
    pub const THREAD_DOMAIN_NAME: u8 = 59;
    /// Wake-up Channel.
    pub const WAKEUP_CHANNEL: u8 = 74;
    /// Discovery Request.
    pub const DISCOVERY_REQUEST: u8 = 128;
    /// Discovery Response.
    pub const DISCOVERY_RESPONSE: u8 = 129;
    /// Joiner Advertisement.
    pub const JOINER_ADVERTISEMENT: u8 = 241;
}

/// Maximum Commissioner ID length (OT `kMaxCommissionerIdLength`).
pub const MAX_COMMISSIONER_ID_LEN: usize = 64;
/// Maximum Provisioning URL length (`ProvisioningUrlTlv::kMaxUrlLength`).
pub const MAX_PROVISIONING_URL_LEN: usize = 64;
/// Maximum Vendor Name length.
pub const MAX_VENDOR_NAME_LEN: usize = 32;
/// Maximum Vendor Model length.
pub const MAX_VENDOR_MODEL_LEN: usize = 32;
/// Maximum Vendor SW Version length.
pub const MAX_VENDOR_SW_VERSION_LEN: usize = 16;
/// Maximum Vendor Data length.
pub const MAX_VENDOR_DATA_LEN: usize = 64;
/// Vendor Stack Version TLV length (OUI, build, revision, version).
pub const VENDOR_STACK_VERSION_LEN: usize = 6;

/// Maximum Thread Domain Name length.
pub const MAX_DOMAIN_NAME_LEN: usize = 16;
/// Smallest Key Rotation Time in hours (`SecurityPolicy::kMinKeyRotationTime`).
pub const MIN_KEY_ROTATION_TIME: u16 = 2;
/// Default Key Rotation Time in hours.
pub const DEFAULT_KEY_ROTATION_TIME: u16 = 672;
/// Delay Timer limits and defaults in milliseconds (OT `DelayTimerTlv`).
pub const MIN_DELAY_MS: u32 = 30_000;
/// Largest Delay Timer value: 72 hours.
pub const MAX_DELAY_MS: u32 = 72 * 3_600_000;
/// Default Delay Timer used when a Pending Dataset is created locally.
pub const DEFAULT_DELAY_MS: u32 = 300_000;

/// First and last IEEE 802.15.4 2.4 GHz channel.
pub const CHANNEL_MIN: u8 = 11;
/// See [`CHANNEL_MIN`].
pub const CHANNEL_MAX: u8 = 26;

/// State TLV value (OT `StateTlv::State`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(u8)]
pub enum State {
    /// Reject (-1).
    Reject = 0xff,
    /// Pending.
    Pending = 0,
    /// Accept.
    Accept = 1,
}

impl State {
    /// Decode a State TLV byte.
    pub const fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            0xff => Self::Reject,
            0 => Self::Pending,
            1 => Self::Accept,
            _ => return None,
        })
    }
}

/// The Channel TLV value: page and channel number (OT `ChannelTlvValue`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct ChannelValue {
    /// Channel page (0 for 2.4 GHz).
    pub page: u8,
    /// Channel number.
    pub channel: u16,
}

impl ChannelValue {
    /// Page 0 and a channel in 11..=26 (the radio capability check of OT
    /// `ChannelTlvValue::IsValid` for a 2.4 GHz radio).
    pub const fn is_valid(&self) -> bool {
        self.page == 0 && self.channel >= CHANNEL_MIN as u16 && self.channel <= CHANNEL_MAX as u16
    }

    /// Decode from a TLV value.
    pub fn from_bytes(v: &[u8]) -> Result<Self> {
        match v {
            [page, c0, c1, ..] => Ok(Self {
                page: *page,
                channel: u16::from_be_bytes([*c0, *c1]),
            }),
            _ => Err(Error::Parse),
        }
    }

    /// Encode.
    pub fn to_bytes(&self) -> [u8; 3] {
        let c = self.channel.to_be_bytes();
        [self.page, c[0], c[1]]
    }
}

/// Reverse the bit order of a `u32` (OT `Reverse32`).
const fn reverse32(v: u32) -> u32 {
    v.reverse_bits()
}

/// Channel Mask TLV: entries of (channel page, mask length, mask), decoded
/// to a `u32` with bit `n` set for channel `n` of page 0. Entries of other
/// pages are skipped; a page-0 entry whose mask is not 4 bytes is an error
/// (OT `ChannelMaskTlv::EntriesData::Parse`).
pub fn parse_channel_mask(v: &[u8]) -> Result<u32> {
    if v.is_empty() {
        return Err(Error::Parse);
    }
    let mut mask = 0u32;
    let mut rest = v;
    while !rest.is_empty() {
        let [page, len, tail @ ..] = rest else {
            return Err(Error::Parse);
        };
        let len = usize::from(*len);
        if tail.len() < len {
            return Err(Error::Parse);
        }
        if *page == 0 {
            if len != 4 {
                return Err(Error::Parse);
            }
            let m = reverse32(u32::from_be_bytes([tail[0], tail[1], tail[2], tail[3]]));
            mask |= m & PAGE0_CHANNELS;
        }
        rest = &tail[len..];
    }
    Ok(mask)
}

/// Channels 11..=26 as a mask.
pub const PAGE0_CHANNELS: u32 = 0x07ff_f800;

/// Encode the page-0 Channel Mask entry for `mask` (bit `n` = channel `n`).
pub fn channel_mask_entry(mask: u32) -> [u8; 6] {
    let m = reverse32(mask & PAGE0_CHANNELS).to_be_bytes();
    [0, 4, m[0], m[1], m[2], m[3]]
}

/// Security Policy TLV (Thread 1.2+ format with two flag bytes; the 1.1
/// format with one flag byte is accepted when reading).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct SecurityPolicy {
    /// Key rotation time in hours.
    pub rotation_time: u16,
    /// `O` bit: Network Key may be obtained out of band.
    pub obtain_network_key: bool,
    /// `N` bit: native commissioning.
    pub native_commissioning: bool,
    /// `R` bit: routers enabled.
    pub routers: bool,
    /// `C` bit: external commissioner authentication.
    pub external_commissioning: bool,
    /// `CCM` (inverted on the wire): commercial commissioning.
    pub commercial_commissioning: bool,
    /// `AE` (inverted on the wire): autonomous enrollment.
    pub autonomous_enrollment: bool,
    /// `NKP` (inverted on the wire): network key provisioning.
    pub network_key_provisioning: bool,
    /// `T` bit: ToBLE link.
    pub toble_link: bool,
    /// `NCR` (inverted on the wire): non-CCM routers.
    pub non_ccm_routers: bool,
    /// `RV`: version threshold for routing (0..=7).
    pub version_threshold_for_routing: u8,
}

impl Default for SecurityPolicy {
    /// OT `SetToDefault`.
    fn default() -> Self {
        Self {
            rotation_time: DEFAULT_KEY_ROTATION_TIME,
            obtain_network_key: true,
            native_commissioning: true,
            routers: true,
            external_commissioning: true,
            commercial_commissioning: false,
            autonomous_enrollment: false,
            network_key_provisioning: false,
            toble_link: true,
            non_ccm_routers: false,
            version_threshold_for_routing: 0,
        }
    }
}

impl SecurityPolicy {
    /// Encoded length (rotation time + two flag bytes).
    pub const ENCODED_LEN: usize = 4;

    /// Valid TLV value: rotation time plus at least one flag byte (OT
    /// `SecurityPolicyTlv::IsValid`).
    pub fn is_valid_len(len: usize) -> bool {
        len >= 3
    }

    /// Decode a TLV value (`SecurityPolicyTlv::GetSecurityPolicy`): flags
    /// not present keep their defaults.
    pub fn from_bytes(v: &[u8]) -> Result<Self> {
        if !Self::is_valid_len(v.len()) {
            return Err(Error::Parse);
        }
        let mut p = Self {
            rotation_time: u16::from_be_bytes([v[0], v[1]]),
            ..Self::default()
        };
        let f0 = v[2];
        p.obtain_network_key = f0 & 0x80 != 0;
        p.native_commissioning = f0 & 0x40 != 0;
        p.routers = f0 & 0x20 != 0;
        p.external_commissioning = f0 & 0x10 != 0;
        p.commercial_commissioning = f0 & 0x04 == 0;
        p.autonomous_enrollment = f0 & 0x02 == 0;
        p.network_key_provisioning = f0 & 0x01 == 0;
        if let Some(&f1) = v.get(3) {
            p.toble_link = f1 & 0x80 != 0;
            p.non_ccm_routers = f1 & 0x40 == 0;
            p.version_threshold_for_routing = f1 & 0x07;
        }
        Ok(p)
    }

    /// The fields that decide router eligibility.
    pub fn routing_policy(&self) -> opentrust_mle::RoutingPolicy {
        opentrust_mle::RoutingPolicy {
            routers_enabled: self.routers,
            commercial_commissioning: self.commercial_commissioning,
            non_ccm_routers: self.non_ccm_routers,
            version_threshold_for_routing: self.version_threshold_for_routing,
        }
    }

    /// Encode as TLV value.
    pub fn to_bytes(&self) -> [u8; Self::ENCODED_LEN] {
        let r = self.rotation_time.to_be_bytes();
        let mut f0 = 0u8;
        let mut f1 = 0u8;
        let bit = |b: bool, m: u8| if b { m } else { 0 };
        f0 |= bit(self.obtain_network_key, 0x80);
        f0 |= bit(self.native_commissioning, 0x40);
        f0 |= bit(self.routers, 0x20);
        f0 |= bit(self.external_commissioning, 0x10);
        f0 |= bit(!self.commercial_commissioning, 0x04);
        f0 |= bit(!self.autonomous_enrollment, 0x02);
        f0 |= bit(!self.network_key_provisioning, 0x01);
        f1 |= bit(self.toble_link, 0x80);
        f1 |= bit(!self.non_ccm_routers, 0x40);
        // OT also sets the reserved bits (kReservedMask).
        f1 |= 0x38 | (self.version_threshold_for_routing & 0x07);
        [r[0], r[1], f0, f1]
    }
}

/// Discovery Request TLV value (OT `DiscoveryRequestTlv`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct DiscoveryRequest {
    /// Protocol version (4 bits).
    pub version: u8,
    /// The sender is a Joiner.
    pub joiner: bool,
}

impl DiscoveryRequest {
    /// Decode (two bytes needed).
    pub fn from_bytes(v: &[u8]) -> Result<Self> {
        match v {
            [f, _, ..] => Ok(Self {
                version: f >> 4,
                joiner: f & 0x08 != 0,
            }),
            _ => Err(Error::Parse),
        }
    }

    /// Encode.
    pub fn to_bytes(&self) -> [u8; 2] {
        [(self.version << 4) | (u8::from(self.joiner) << 3), 0]
    }
}

/// Discovery Response TLV value (OT `DiscoveryResponseTlv`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct DiscoveryResponse {
    /// Protocol version (4 bits).
    pub version: u8,
    /// A native commissioner is available.
    pub native_commissioner: bool,
    /// Commercial commissioning mode.
    pub commercial_commissioning: bool,
}

impl DiscoveryResponse {
    /// Decode (two bytes needed).
    pub fn from_bytes(v: &[u8]) -> Result<Self> {
        match v {
            [f, _, ..] => Ok(Self {
                version: f >> 4,
                native_commissioner: f & 0x08 != 0,
                commercial_commissioning: f & 0x04 != 0,
            }),
            _ => Err(Error::Parse),
        }
    }

    /// Encode.
    pub fn to_bytes(&self) -> [u8; 2] {
        [
            (self.version << 4)
                | (u8::from(self.native_commissioner) << 3)
                | (u8::from(self.commercial_commissioning) << 2),
            0,
        ]
    }
}

/// A typed read view over a buffer of MeshCoP TLVs.
#[derive(Debug, Clone, Copy)]
pub struct Tlvs<'a>(pub &'a [u8]);

fn exact<const N: usize>(v: &[u8]) -> Result<[u8; N]> {
    v.get(..N)
        .and_then(|s| s.try_into().ok())
        .ok_or(Error::Parse)
}

impl<'a> Tlvs<'a> {
    /// The raw buffer.
    pub const fn as_bytes(&self) -> &'a [u8] {
        self.0
    }

    /// Iterate over the TLVs.
    pub fn iter(&self) -> TlvIter<'a> {
        TlvIter::new(self.0)
    }

    /// Check the framing of the whole buffer.
    pub fn validate(&self) -> Result<()> {
        tlv::validate(self.0)
    }

    /// The first TLV of `ty` ([`Error::NotFound`] if absent).
    pub fn find(&self, ty: u8) -> Result<Tlv<'a>> {
        tlv::find(self.0, ty)
    }

    /// Is a TLV of `ty` present?
    pub fn contains(&self, ty: u8) -> bool {
        self.find(ty).is_ok()
    }

    /// The value of the first TLV of `ty`.
    pub fn value(&self, ty: u8) -> Result<&'a [u8]> {
        Ok(self.find(ty)?.value())
    }

    /// Channel TLV.
    pub fn channel(&self) -> Result<ChannelValue> {
        ChannelValue::from_bytes(self.value(ty::CHANNEL)?)
    }
    /// Wake-up Channel TLV.
    pub fn wakeup_channel(&self) -> Result<ChannelValue> {
        ChannelValue::from_bytes(self.value(ty::WAKEUP_CHANNEL)?)
    }
    /// PAN ID TLV.
    pub fn pan_id(&self) -> Result<u16> {
        self.find(ty::PAN_ID)?.read_u16()
    }
    /// Extended PAN ID TLV.
    pub fn ext_pan_id(&self) -> Result<ExtPanId> {
        Ok(ExtPanId(exact(self.value(ty::EXT_PAN_ID)?)?))
    }
    /// Network Name TLV (1..=16 bytes of UTF-8).
    pub fn network_name(&self) -> Result<NetworkName> {
        NetworkName::from_bytes(self.value(ty::NETWORK_NAME)?).map_err(|_| Error::Parse)
    }
    /// PSKc TLV.
    pub fn pskc(&self) -> Result<Pskc> {
        Ok(Pskc(exact(self.value(ty::PSKC)?)?))
    }
    /// Network Key TLV.
    pub fn network_key(&self) -> Result<NetworkKey> {
        Ok(NetworkKey(exact(self.value(ty::NETWORK_KEY)?)?))
    }
    /// Network Key Sequence TLV.
    pub fn network_key_sequence(&self) -> Result<u32> {
        self.find(ty::NETWORK_KEY_SEQUENCE)?.read_u32()
    }
    /// Mesh-Local Prefix TLV.
    pub fn mesh_local_prefix(&self) -> Result<Prefix64> {
        Ok(Prefix64(exact(self.value(ty::MESH_LOCAL_PREFIX)?)?))
    }
    /// Steering Data TLV (at least one byte).
    pub fn steering_data(&self) -> Result<SteeringData> {
        let v = self.value(ty::STEERING_DATA)?;
        if v.is_empty() {
            return Err(Error::Parse);
        }
        Ok(SteeringData::from_slice(v))
    }
    /// Border Agent Locator TLV.
    pub fn border_agent_locator(&self) -> Result<u16> {
        self.find(ty::BORDER_AGENT_LOCATOR)?.read_u16()
    }
    /// Commissioner ID TLV (up to 64 bytes).
    pub fn commissioner_id(&self) -> Result<&'a str> {
        self.find(ty::COMMISSIONER_ID)?
            .read_str(MAX_COMMISSIONER_ID_LEN)
    }
    /// Commissioner Session ID TLV.
    pub fn commissioner_session_id(&self) -> Result<u16> {
        self.find(ty::COMMISSIONER_SESSION_ID)?.read_u16()
    }
    /// Security Policy TLV.
    pub fn security_policy(&self) -> Result<SecurityPolicy> {
        SecurityPolicy::from_bytes(self.value(ty::SECURITY_POLICY)?)
    }
    /// Get TLV: the requested TLV types.
    pub fn get_list(&self) -> Result<&'a [u8]> {
        self.value(ty::GET)
    }
    /// Active Timestamp TLV.
    pub fn active_timestamp(&self) -> Result<Timestamp> {
        Timestamp::from_bytes(self.value(ty::ACTIVE_TIMESTAMP)?)
    }
    /// Pending Timestamp TLV.
    pub fn pending_timestamp(&self) -> Result<Timestamp> {
        Timestamp::from_bytes(self.value(ty::PENDING_TIMESTAMP)?)
    }
    /// Delay Timer TLV in milliseconds.
    pub fn delay_timer(&self) -> Result<u32> {
        self.find(ty::DELAY_TIMER)?.read_u32()
    }
    /// Channel Mask TLV (page 0 as a `u32`).
    pub fn channel_mask(&self) -> Result<u32> {
        parse_channel_mask(self.value(ty::CHANNEL_MASK)?)
    }
    /// State TLV.
    pub fn state(&self) -> Result<State> {
        State::from_u8(self.find(ty::STATE)?.read_u8()?).ok_or(Error::Parse)
    }
    /// Commissioner UDP Port TLV.
    pub fn commissioner_udp_port(&self) -> Result<u16> {
        self.find(ty::COMMISSIONER_UDP_PORT)?.read_u16()
    }
    /// Joiner UDP Port TLV.
    pub fn joiner_udp_port(&self) -> Result<u16> {
        self.find(ty::JOINER_UDP_PORT)?.read_u16()
    }
    /// Count TLV.
    pub fn count(&self) -> Result<u8> {
        self.find(ty::COUNT)?.read_u8()
    }
    /// Period TLV (milliseconds).
    pub fn period(&self) -> Result<u16> {
        self.find(ty::PERIOD)?.read_u16()
    }
    /// Scan Duration TLV (milliseconds).
    pub fn scan_duration(&self) -> Result<u16> {
        self.find(ty::SCAN_DURATION)?.read_u16()
    }
    /// Energy List TLV (one RSSI byte per scanned channel).
    pub fn energy_list(&self) -> Result<&'a [u8]> {
        self.value(ty::ENERGY_LIST)
    }
    /// Thread Domain Name TLV.
    pub fn thread_domain_name(&self) -> Result<&'a str> {
        self.find(ty::THREAD_DOMAIN_NAME)?
            .read_str(MAX_DOMAIN_NAME_LEN)
    }
    /// Provisioning URL TLV.
    pub fn provisioning_url(&self) -> Result<&'a str> {
        self.find(ty::PROVISIONING_URL)?
            .read_str(MAX_PROVISIONING_URL_LEN)
    }
    /// Vendor Name TLV.
    pub fn vendor_name(&self) -> Result<&'a str> {
        self.find(ty::VENDOR_NAME)?.read_str(MAX_VENDOR_NAME_LEN)
    }
    /// Vendor Model TLV.
    pub fn vendor_model(&self) -> Result<&'a str> {
        self.find(ty::VENDOR_MODEL)?.read_str(MAX_VENDOR_MODEL_LEN)
    }
    /// Vendor SW Version TLV.
    pub fn vendor_sw_version(&self) -> Result<&'a str> {
        self.find(ty::VENDOR_SW_VERSION)?
            .read_str(MAX_VENDOR_SW_VERSION_LEN)
    }
    /// Vendor Data TLV.
    pub fn vendor_data(&self) -> Result<&'a str> {
        self.find(ty::VENDOR_DATA)?.read_str(MAX_VENDOR_DATA_LEN)
    }
    /// Joiner IID TLV.
    pub fn joiner_iid(&self) -> Result<Iid> {
        Ok(Iid(self.find(ty::JOINER_IID)?.read_array()?))
    }
    /// Joiner Router Locator TLV.
    pub fn joiner_router_locator(&self) -> Result<u16> {
        self.find(ty::JOINER_ROUTER_LOCATOR)?.read_u16()
    }
    /// Joiner Router KEK TLV.
    pub fn joiner_router_kek(&self) -> Result<Kek> {
        let v = self.value(ty::JOINER_ROUTER_KEK)?;
        if v.len() != 16 {
            return Err(Error::Parse);
        }
        let mut k = Kek([0; 16]);
        k.0.copy_from_slice(v);
        Ok(k)
    }
    /// Joiner DTLS Encapsulation TLV (the DTLS records).
    pub fn joiner_dtls_encapsulation(&self) -> Result<&'a [u8]> {
        self.value(ty::JOINER_DTLS_ENCAPSULATION)
    }
    /// UDP Encapsulation TLV: source port, destination port, payload.
    pub fn udp_encapsulation(&self) -> Result<(u16, u16, &'a [u8])> {
        let v = self.value(ty::UDP_ENCAPSULATION)?;
        if v.len() < 4 {
            return Err(Error::Parse);
        }
        Ok((
            u16::from_be_bytes([v[0], v[1]]),
            u16::from_be_bytes([v[2], v[3]]),
            &v[4..],
        ))
    }
    /// IPv6 Address TLV.
    pub fn ipv6_address(&self) -> Result<Ipv6Addr> {
        Ok(Ipv6Addr::from(
            self.find(ty::IPV6_ADDRESS)?.read_array::<16>()?,
        ))
    }
    /// Discovery Request TLV.
    pub fn discovery_request(&self) -> Result<DiscoveryRequest> {
        DiscoveryRequest::from_bytes(self.value(ty::DISCOVERY_REQUEST)?)
    }
    /// Discovery Response TLV.
    pub fn discovery_response(&self) -> Result<DiscoveryResponse> {
        DiscoveryResponse::from_bytes(self.value(ty::DISCOVERY_RESPONSE)?)
    }
}

/// Typed MeshCoP TLV writers for [`Writer`].
pub trait WriterExt {
    /// Channel TLV.
    fn channel(&mut self, c: &ChannelValue) -> Result<()>;
    /// Channel TLV for page 0 and channel number `c`.
    fn channel_page0(&mut self, c: u8) -> Result<()> {
        self.channel(&ChannelValue {
            page: 0,
            channel: u16::from(c),
        })
    }
    /// PAN ID TLV.
    fn pan_id(&mut self, v: u16) -> Result<()>;
    /// Extended PAN ID TLV.
    fn ext_pan_id(&mut self, v: &ExtPanId) -> Result<()>;
    /// Network Name TLV.
    fn network_name(&mut self, v: &NetworkName) -> Result<()>;
    /// PSKc TLV.
    fn pskc(&mut self, v: &Pskc) -> Result<()>;
    /// Network Key TLV.
    fn network_key(&mut self, v: &NetworkKey) -> Result<()>;
    /// Network Key Sequence TLV.
    fn network_key_sequence(&mut self, v: u32) -> Result<()>;
    /// Mesh-Local Prefix TLV.
    fn mesh_local_prefix(&mut self, v: &Prefix64) -> Result<()>;
    /// Steering Data TLV.
    fn steering_data(&mut self, v: &SteeringData) -> Result<()>;
    /// Border Agent Locator TLV.
    fn border_agent_locator(&mut self, rloc16: u16) -> Result<()>;
    /// Commissioner ID TLV.
    fn commissioner_id(&mut self, id: &str) -> Result<()>;
    /// Commissioner Session ID TLV.
    fn commissioner_session_id(&mut self, id: u16) -> Result<()>;
    /// Security Policy TLV.
    fn security_policy(&mut self, p: &SecurityPolicy) -> Result<()>;
    /// Get TLV.
    fn get_list(&mut self, types: &[u8]) -> Result<()>;
    /// Active Timestamp TLV.
    fn active_timestamp(&mut self, t: &Timestamp) -> Result<()>;
    /// Pending Timestamp TLV.
    fn pending_timestamp(&mut self, t: &Timestamp) -> Result<()>;
    /// Delay Timer TLV.
    fn delay_timer(&mut self, ms: u32) -> Result<()>;
    /// Channel Mask TLV (page 0).
    fn channel_mask(&mut self, mask: u32) -> Result<()>;
    /// State TLV.
    fn state(&mut self, s: State) -> Result<()>;
    /// Commissioner UDP Port TLV.
    fn commissioner_udp_port(&mut self, port: u16) -> Result<()>;
    /// Joiner UDP Port TLV.
    fn joiner_udp_port(&mut self, port: u16) -> Result<()>;
    /// Count TLV.
    fn count(&mut self, v: u8) -> Result<()>;
    /// Period TLV.
    fn period(&mut self, v: u16) -> Result<()>;
    /// Scan Duration TLV.
    fn scan_duration(&mut self, v: u16) -> Result<()>;
    /// Energy List TLV.
    fn energy_list(&mut self, v: &[u8]) -> Result<()>;
    /// Thread Domain Name TLV.
    fn thread_domain_name(&mut self, v: &str) -> Result<()>;
    /// Discovery Request TLV.
    fn discovery_request(&mut self, v: &DiscoveryRequest) -> Result<()>;
    /// Discovery Response TLV.
    fn discovery_response(&mut self, v: &DiscoveryResponse) -> Result<()>;
    /// Provisioning URL TLV.
    fn provisioning_url(&mut self, v: &str) -> Result<()>;
    /// Vendor Name TLV.
    fn vendor_name(&mut self, v: &str) -> Result<()>;
    /// Vendor Model TLV.
    fn vendor_model(&mut self, v: &str) -> Result<()>;
    /// Vendor SW Version TLV.
    fn vendor_sw_version(&mut self, v: &str) -> Result<()>;
    /// Vendor Data TLV.
    fn vendor_data(&mut self, v: &str) -> Result<()>;
    /// Vendor Stack Version TLV.
    fn vendor_stack_version(&mut self, v: &[u8; VENDOR_STACK_VERSION_LEN]) -> Result<()>;
    /// Joiner IID TLV.
    fn joiner_iid(&mut self, iid: &Iid) -> Result<()>;
    /// Joiner Router Locator TLV.
    fn joiner_router_locator(&mut self, rloc16: u16) -> Result<()>;
    /// Joiner Router KEK TLV.
    fn joiner_router_kek(&mut self, kek: &Kek) -> Result<()>;
    /// Joiner DTLS Encapsulation TLV, always in the extended form (as OT
    /// writes it).
    fn joiner_dtls_encapsulation(&mut self, records: &[u8]) -> Result<()>;
    /// UDP Encapsulation TLV (extended form): ports and payload.
    fn udp_encapsulation(&mut self, src_port: u16, dst_port: u16, payload: &[u8]) -> Result<()>;
    /// IPv6 Address TLV.
    fn ipv6_address(&mut self, a: &Ipv6Addr) -> Result<()>;
}

/// Write an extended TLV header (`ty`, `0xff`, 16-bit length).
fn extended_header(w: &mut Writer<'_>, ty: u8, len: usize) -> Result<()> {
    let len = u16::try_from(len).map_err(|_| Error::InvalidArgs)?;
    if w.remaining() < 4 + usize::from(len) {
        return Err(Error::NoBufs);
    }
    w.write_u8(ty)?;
    w.write_u8(tlv::EXTENDED_LENGTH)?;
    w.write_u16(len)
}

impl WriterExt for Writer<'_> {
    fn channel(&mut self, c: &ChannelValue) -> Result<()> {
        tlv::write(self, ty::CHANNEL, &c.to_bytes())
    }
    fn pan_id(&mut self, v: u16) -> Result<()> {
        tlv::write_u16(self, ty::PAN_ID, v)
    }
    fn ext_pan_id(&mut self, v: &ExtPanId) -> Result<()> {
        tlv::write(self, ty::EXT_PAN_ID, &v.0)
    }
    fn network_name(&mut self, v: &NetworkName) -> Result<()> {
        tlv::write(self, ty::NETWORK_NAME, v.as_bytes())
    }
    fn pskc(&mut self, v: &Pskc) -> Result<()> {
        tlv::write(self, ty::PSKC, &v.0)
    }
    fn network_key(&mut self, v: &NetworkKey) -> Result<()> {
        tlv::write(self, ty::NETWORK_KEY, &v.0)
    }
    fn network_key_sequence(&mut self, v: u32) -> Result<()> {
        tlv::write_u32(self, ty::NETWORK_KEY_SEQUENCE, v)
    }
    fn mesh_local_prefix(&mut self, v: &Prefix64) -> Result<()> {
        tlv::write(self, ty::MESH_LOCAL_PREFIX, &v.0)
    }
    fn steering_data(&mut self, v: &SteeringData) -> Result<()> {
        tlv::write(self, ty::STEERING_DATA, v.as_bytes())
    }
    fn border_agent_locator(&mut self, rloc16: u16) -> Result<()> {
        tlv::write_u16(self, ty::BORDER_AGENT_LOCATOR, rloc16)
    }
    fn commissioner_id(&mut self, id: &str) -> Result<()> {
        tlv::write_str(self, ty::COMMISSIONER_ID, MAX_COMMISSIONER_ID_LEN, id)
    }
    fn commissioner_session_id(&mut self, id: u16) -> Result<()> {
        tlv::write_u16(self, ty::COMMISSIONER_SESSION_ID, id)
    }
    fn security_policy(&mut self, p: &SecurityPolicy) -> Result<()> {
        tlv::write(self, ty::SECURITY_POLICY, &p.to_bytes())
    }
    fn get_list(&mut self, types: &[u8]) -> Result<()> {
        tlv::write(self, ty::GET, types)
    }
    fn active_timestamp(&mut self, t: &Timestamp) -> Result<()> {
        tlv::write(self, ty::ACTIVE_TIMESTAMP, &t.to_bytes())
    }
    fn pending_timestamp(&mut self, t: &Timestamp) -> Result<()> {
        tlv::write(self, ty::PENDING_TIMESTAMP, &t.to_bytes())
    }
    fn delay_timer(&mut self, ms: u32) -> Result<()> {
        tlv::write_u32(self, ty::DELAY_TIMER, ms)
    }
    fn channel_mask(&mut self, mask: u32) -> Result<()> {
        tlv::write(self, ty::CHANNEL_MASK, &channel_mask_entry(mask))
    }
    fn state(&mut self, s: State) -> Result<()> {
        tlv::write_u8(self, ty::STATE, s as u8)
    }
    fn commissioner_udp_port(&mut self, port: u16) -> Result<()> {
        tlv::write_u16(self, ty::COMMISSIONER_UDP_PORT, port)
    }
    fn joiner_udp_port(&mut self, port: u16) -> Result<()> {
        tlv::write_u16(self, ty::JOINER_UDP_PORT, port)
    }
    fn count(&mut self, v: u8) -> Result<()> {
        tlv::write_u8(self, ty::COUNT, v)
    }
    fn period(&mut self, v: u16) -> Result<()> {
        tlv::write_u16(self, ty::PERIOD, v)
    }
    fn scan_duration(&mut self, v: u16) -> Result<()> {
        tlv::write_u16(self, ty::SCAN_DURATION, v)
    }
    fn energy_list(&mut self, v: &[u8]) -> Result<()> {
        tlv::write(self, ty::ENERGY_LIST, v)
    }
    fn thread_domain_name(&mut self, v: &str) -> Result<()> {
        tlv::write_str(self, ty::THREAD_DOMAIN_NAME, MAX_DOMAIN_NAME_LEN, v)
    }
    fn discovery_request(&mut self, v: &DiscoveryRequest) -> Result<()> {
        tlv::write(self, ty::DISCOVERY_REQUEST, &v.to_bytes())
    }
    fn discovery_response(&mut self, v: &DiscoveryResponse) -> Result<()> {
        tlv::write(self, ty::DISCOVERY_RESPONSE, &v.to_bytes())
    }
    fn provisioning_url(&mut self, v: &str) -> Result<()> {
        tlv::write_str(self, ty::PROVISIONING_URL, MAX_PROVISIONING_URL_LEN, v)
    }
    fn vendor_name(&mut self, v: &str) -> Result<()> {
        tlv::write_str(self, ty::VENDOR_NAME, MAX_VENDOR_NAME_LEN, v)
    }
    fn vendor_model(&mut self, v: &str) -> Result<()> {
        tlv::write_str(self, ty::VENDOR_MODEL, MAX_VENDOR_MODEL_LEN, v)
    }
    fn vendor_sw_version(&mut self, v: &str) -> Result<()> {
        tlv::write_str(self, ty::VENDOR_SW_VERSION, MAX_VENDOR_SW_VERSION_LEN, v)
    }
    fn vendor_data(&mut self, v: &str) -> Result<()> {
        tlv::write_str(self, ty::VENDOR_DATA, MAX_VENDOR_DATA_LEN, v)
    }
    fn vendor_stack_version(&mut self, v: &[u8; VENDOR_STACK_VERSION_LEN]) -> Result<()> {
        tlv::write(self, ty::VENDOR_STACK_VERSION, v)
    }
    fn joiner_iid(&mut self, iid: &Iid) -> Result<()> {
        tlv::write(self, ty::JOINER_IID, &iid.0)
    }
    fn joiner_router_locator(&mut self, rloc16: u16) -> Result<()> {
        tlv::write_u16(self, ty::JOINER_ROUTER_LOCATOR, rloc16)
    }
    fn joiner_router_kek(&mut self, kek: &Kek) -> Result<()> {
        tlv::write(self, ty::JOINER_ROUTER_KEK, &kek.0)
    }
    fn joiner_dtls_encapsulation(&mut self, records: &[u8]) -> Result<()> {
        extended_header(self, ty::JOINER_DTLS_ENCAPSULATION, records.len())?;
        self.write_slice(records)
    }
    fn udp_encapsulation(&mut self, src_port: u16, dst_port: u16, payload: &[u8]) -> Result<()> {
        extended_header(self, ty::UDP_ENCAPSULATION, 4 + payload.len())?;
        self.write_u16(src_port)?;
        self.write_u16(dst_port)?;
        self.write_slice(payload)
    }
    fn ipv6_address(&mut self, a: &Ipv6Addr) -> Result<()> {
        tlv::write(self, ty::IPV6_ADDRESS, &a.octets())
    }
}
