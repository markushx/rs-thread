//! Spinel constants (`openthread/src/lib/spinel/spinel.h`): commands, status
//! codes, capabilities and the property keys rs-thread implements.
//!
//! Keys are plain `u32` because the property space is open (vendor and
//! experimental ranges) and a host may send any value.

/// Spinel protocol version (major) implemented, `SPINEL_PROTOCOL_VERSION_THREAD_MAJOR`.
pub const PROTOCOL_VERSION_MAJOR: u32 = 4;
/// Spinel protocol version (minor), `SPINEL_PROTOCOL_VERSION_THREAD_MINOR`.
pub const PROTOCOL_VERSION_MINOR: u32 = 3;
/// RCP API version implemented, `SPINEL_RCP_API_VERSION`.
pub const RCP_API_VERSION: u32 = 11;
/// Oldest host RCP API version served, `SPINEL_MIN_HOST_SUPPORTED_RCP_API_VERSION`.
pub const MIN_HOST_SUPPORTED_RCP_API_VERSION: u32 = 4;

/// `SPINEL_INTERFACE_TYPE_THREAD`
pub const INTERFACE_TYPE_THREAD: u32 = 3;

/// Commands.
pub mod cmd {
    /// `CMD_NOOP`
    pub const NOOP: u32 = 0;
    /// `CMD_RESET`
    pub const RESET: u32 = 1;
    /// `CMD_PROP_VALUE_GET`
    pub const PROP_VALUE_GET: u32 = 2;
    /// `CMD_PROP_VALUE_SET`
    pub const PROP_VALUE_SET: u32 = 3;
    /// `CMD_PROP_VALUE_INSERT`
    pub const PROP_VALUE_INSERT: u32 = 4;
    /// `CMD_PROP_VALUE_REMOVE`
    pub const PROP_VALUE_REMOVE: u32 = 5;
    /// `CMD_PROP_VALUE_IS`
    pub const PROP_VALUE_IS: u32 = 6;
    /// `CMD_PROP_VALUE_INSERTED`
    pub const PROP_VALUE_INSERTED: u32 = 7;
    /// `CMD_PROP_VALUE_REMOVED`
    pub const PROP_VALUE_REMOVED: u32 = 8;
    /// `CMD_NET_CLEAR`
    pub const NET_CLEAR: u32 = 10;
}

/// Reset types (payload of `CMD_RESET`).
pub mod reset {
    /// `SPINEL_RESET_PLATFORM`
    pub const PLATFORM: u32 = 1;
    /// `SPINEL_RESET_STACK`
    pub const STACK: u32 = 2;
    /// `SPINEL_RESET_BOOTLOADER`
    pub const BOOTLOADER: u32 = 3;
}

/// Status codes (`LAST_STATUS`).
pub mod status {
    /// `SPINEL_STATUS_OK`
    pub const OK: u32 = 0;
    /// `SPINEL_STATUS_FAILURE`
    pub const FAILURE: u32 = 1;
    /// `SPINEL_STATUS_UNIMPLEMENTED`
    pub const UNIMPLEMENTED: u32 = 2;
    /// `SPINEL_STATUS_INVALID_ARGUMENT`
    pub const INVALID_ARGUMENT: u32 = 3;
    /// `SPINEL_STATUS_INVALID_STATE`
    pub const INVALID_STATE: u32 = 4;
    /// `SPINEL_STATUS_INVALID_COMMAND`
    pub const INVALID_COMMAND: u32 = 5;
    /// `SPINEL_STATUS_INTERNAL_ERROR`
    pub const INTERNAL_ERROR: u32 = 7;
    /// `SPINEL_STATUS_PARSE_ERROR`
    pub const PARSE_ERROR: u32 = 9;
    /// `SPINEL_STATUS_IN_PROGRESS`
    pub const IN_PROGRESS: u32 = 10;
    /// `SPINEL_STATUS_NOMEM`
    pub const NOMEM: u32 = 11;
    /// `SPINEL_STATUS_BUSY`
    pub const BUSY: u32 = 12;
    /// `SPINEL_STATUS_PROP_NOT_FOUND`
    pub const PROP_NOT_FOUND: u32 = 13;
    /// `SPINEL_STATUS_DROPPED`
    pub const DROPPED: u32 = 14;
    /// `SPINEL_STATUS_NO_ACK`
    pub const NO_ACK: u32 = 17;
    /// `SPINEL_STATUS_CCA_FAILURE`
    pub const CCA_FAILURE: u32 = 18;
    /// `SPINEL_STATUS_ALREADY`
    pub const ALREADY: u32 = 19;
    /// `SPINEL_STATUS_ITEM_NOT_FOUND`
    pub const ITEM_NOT_FOUND: u32 = 20;
    /// `SPINEL_STATUS_INVALID_COMMAND_FOR_PROP`
    pub const INVALID_COMMAND_FOR_PROP: u32 = 21;
    /// `SPINEL_STATUS_NOT_CAPABLE`
    pub const NOT_CAPABLE: u32 = 23;
    /// `SPINEL_STATUS_RESET_POWER_ON`
    pub const RESET_POWER_ON: u32 = 112;
    /// `SPINEL_STATUS_RESET_EXTERNAL`
    pub const RESET_EXTERNAL: u32 = 113;
    /// `SPINEL_STATUS_RESET_SOFTWARE`
    pub const RESET_SOFTWARE: u32 = 114;
}

/// Capabilities (`PROP_CAPS`).
pub mod cap {
    /// `SPINEL_CAP_COUNTERS`
    pub const COUNTERS: u32 = 5;
    /// `SPINEL_CAP_WRITABLE_RAW_STREAM`
    pub const WRITABLE_RAW_STREAM: u32 = 8;
    /// `SPINEL_CAP_UNSOL_UPDATE_FILTER`
    pub const UNSOL_UPDATE_FILTER: u32 = 12;
    /// `SPINEL_CAP_802_15_4_2003`
    pub const IEEE_802_15_4_2003: u32 = 16;
    /// `SPINEL_CAP_802_15_4_2006`
    pub const IEEE_802_15_4_2006: u32 = 17;
    /// `SPINEL_CAP_802_15_4_2011`
    pub const IEEE_802_15_4_2011: u32 = 18;
    /// `SPINEL_CAP_802_15_4_PIB`
    pub const IEEE_802_15_4_PIB: u32 = 21;
    /// `SPINEL_CAP_802_15_4_2450MHZ_OQPSK`
    pub const IEEE_802_15_4_2450MHZ_OQPSK: u32 = 24;
    /// `SPINEL_CAP_CONFIG_FTD`
    pub const CONFIG_FTD: u32 = 32;
    /// `SPINEL_CAP_CONFIG_MTD`
    pub const CONFIG_MTD: u32 = 33;
    /// `SPINEL_CAP_CONFIG_RADIO`
    pub const CONFIG_RADIO: u32 = 34;
    /// `SPINEL_CAP_ROLE_ROUTER`
    pub const ROLE_ROUTER: u32 = 48;
    /// `SPINEL_CAP_ROLE_SLEEPY`
    pub const ROLE_SLEEPY: u32 = 49;
    /// `SPINEL_CAP_NET_THREAD_1_0`
    pub const NET_THREAD_1_0: u32 = 52;
    /// `SPINEL_CAP_NET_THREAD_1_1`
    pub const NET_THREAD_1_1: u32 = 53;
    /// `SPINEL_CAP_NET_THREAD_1_2`
    pub const NET_THREAD_1_2: u32 = 54;
    /// `SPINEL_CAP_RCP_API_VERSION`
    pub const RCP_API_VERSION: u32 = 64;
    /// `SPINEL_CAP_RCP_MIN_HOST_API_VERSION`
    pub const RCP_MIN_HOST_API_VERSION: u32 = 65;
    /// `SPINEL_CAP_MAC_RAW`
    pub const MAC_RAW: u32 = 513;
    /// `SPINEL_CAP_POSIX`
    pub const POSIX: u32 = 521;
    /// `SPINEL_CAP_RADIO_COEX`
    pub const RADIO_COEX: u32 = 523;
}

/// Property keys.
pub mod prop {
    /// `PROP_LAST_STATUS` `i`
    pub const LAST_STATUS: u32 = 0;
    /// `PROP_PROTOCOL_VERSION` `ii`
    pub const PROTOCOL_VERSION: u32 = 1;
    /// `PROP_NCP_VERSION` `U`
    pub const NCP_VERSION: u32 = 2;
    /// `PROP_INTERFACE_TYPE` `i`
    pub const INTERFACE_TYPE: u32 = 3;
    /// `PROP_VENDOR_ID` `i`
    pub const VENDOR_ID: u32 = 4;
    /// `PROP_CAPS` `A(i)`
    pub const CAPS: u32 = 5;
    /// `PROP_INTERFACE_COUNT` `C`
    pub const INTERFACE_COUNT: u32 = 6;
    /// `PROP_HWADDR` `E`
    pub const HWADDR: u32 = 8;

    /// `PROP_PHY_ENABLED` `b`
    pub const PHY_ENABLED: u32 = 0x20;
    /// `PROP_PHY_CHAN` `C`
    pub const PHY_CHAN: u32 = 0x21;
    /// `PROP_PHY_CHAN_SUPPORTED` `A(C)`
    pub const PHY_CHAN_SUPPORTED: u32 = 0x22;
    /// `PROP_PHY_FREQ` `L` (kHz)
    pub const PHY_FREQ: u32 = 0x23;
    /// `PROP_PHY_CCA_THRESHOLD` `c`
    pub const PHY_CCA_THRESHOLD: u32 = 0x24;
    /// `PROP_PHY_TX_POWER` `c`
    pub const PHY_TX_POWER: u32 = 0x25;
    /// `PROP_PHY_RSSI` `c`
    pub const PHY_RSSI: u32 = 0x26;
    /// `PROP_PHY_RX_SENSITIVITY` `c`
    pub const PHY_RX_SENSITIVITY: u32 = 0x27;
    /// `PROP_PHY_CHAN_PREFERRED` `A(C)`
    pub const PHY_CHAN_PREFERRED: u32 = 0x29;
    /// `PROP_PHY_FEM_LNA_GAIN` `c`
    pub const PHY_FEM_LNA_GAIN: u32 = 0x2a;
    /// `PROP_PHY_CHAN_MAX_POWER` `Cc`
    pub const PHY_CHAN_MAX_POWER: u32 = 0x2b;
    /// `PROP_PHY_REGION_CODE` `S`
    pub const PHY_REGION_CODE: u32 = 0x2c;
    /// `PROP_PHY_CALIBRATED_POWER` `A(Cd)`
    pub const PHY_CALIBRATED_POWER: u32 = 0x2d;
    /// `PROP_PHY_CHAN_TARGET_POWER` `Cc`
    pub const PHY_CHAN_TARGET_POWER: u32 = 0x2e;

    /// `PROP_RADIO_CAPS` `i`
    pub const RADIO_CAPS: u32 = 0x120b;
    /// `PROP_RADIO_COEX_METRICS`
    pub const RADIO_COEX_METRICS: u32 = 0x120c;
    /// `PROP_RADIO_COEX_ENABLE` `b`
    pub const RADIO_COEX_ENABLE: u32 = 0x120d;

    /// `PROP_MAC_SCAN_STATE` `C`
    pub const MAC_SCAN_STATE: u32 = 0x30;
    /// `PROP_MAC_SCAN_MASK` `A(C)`
    pub const MAC_SCAN_MASK: u32 = 0x31;
    /// `PROP_MAC_SCAN_PERIOD` `S` (ms)
    pub const MAC_SCAN_PERIOD: u32 = 0x32;
    /// `PROP_MAC_15_4_LADDR` `E`
    pub const MAC_15_4_LADDR: u32 = 0x34;
    /// `PROP_MAC_15_4_SADDR` `S`
    pub const MAC_15_4_SADDR: u32 = 0x35;
    /// `PROP_MAC_15_4_PANID` `S`
    pub const MAC_15_4_PANID: u32 = 0x36;
    /// `PROP_MAC_RAW_STREAM_ENABLED` `b`
    pub const MAC_RAW_STREAM_ENABLED: u32 = 0x37;
    /// `PROP_MAC_PROMISCUOUS_MODE` `C`
    pub const MAC_PROMISCUOUS_MODE: u32 = 0x38;
    /// `PROP_MAC_ENERGY_SCAN_RESULT` `Cc`
    pub const MAC_ENERGY_SCAN_RESULT: u32 = 0x39;
    /// `PROP_MAC_RX_ON_WHEN_IDLE_MODE` `b`
    pub const MAC_RX_ON_WHEN_IDLE_MODE: u32 = 0x3b;
    /// `PROP_MAC_15_4_ALT_SADDR` `S`
    pub const MAC_15_4_ALT_SADDR: u32 = 0x3c;
    /// `PROP_MAC_RX_AT` `XLC`
    pub const MAC_RX_AT: u32 = 0x3d;
    /// `PROP_MAC_SRC_MATCH_ENABLED` `b`
    pub const MAC_SRC_MATCH_ENABLED: u32 = 0x1303;
    /// `PROP_MAC_SRC_MATCH_SHORT_ADDRESSES` `A(S)`
    pub const MAC_SRC_MATCH_SHORT_ADDRESSES: u32 = 0x1304;
    /// `PROP_MAC_SRC_MATCH_EXTENDED_ADDRESSES` `A(E)`
    pub const MAC_SRC_MATCH_EXTENDED_ADDRESSES: u32 = 0x1305;

    /// `PROP_STREAM_DEBUG` `UD`
    pub const STREAM_DEBUG: u32 = 0x70;
    /// `PROP_STREAM_RAW` `dD`
    pub const STREAM_RAW: u32 = 0x71;
    /// `PROP_STREAM_LOG` `UD`
    pub const STREAM_LOG: u32 = 0x74;

    /// `PROP_RCP_MAC_KEY` `CCddd`
    pub const RCP_MAC_KEY: u32 = 0x800;
    /// `PROP_RCP_MAC_FRAME_COUNTER` `Lb`
    pub const RCP_MAC_FRAME_COUNTER: u32 = 0x801;
    /// `PROP_RCP_TIMESTAMP` `X`
    pub const RCP_TIMESTAMP: u32 = 0x802;
    /// `PROP_RCP_ENH_ACK_PROBING`
    pub const RCP_ENH_ACK_PROBING: u32 = 0x803;
    /// `PROP_RCP_CSL_ACCURACY` `C`
    pub const RCP_CSL_ACCURACY: u32 = 0x804;
    /// `PROP_RCP_CSL_UNCERTAINTY` `C`
    pub const RCP_CSL_UNCERTAINTY: u32 = 0x805;

    /// `PROP_RCP_API_VERSION` `i`
    pub const RCP_API_VERSION: u32 = 0xb0;
    /// `PROP_RCP_MIN_HOST_API_VERSION` `i`
    pub const RCP_MIN_HOST_API_VERSION: u32 = 0xb1;
    /// `PROP_RCP_LOG_CRASH_DUMP`
    pub const RCP_LOG_CRASH_DUMP: u32 = 0xb2;
    /// `PROP_RCP_VERSION` `U`
    pub const RCP_VERSION: u32 = 0x190c;
}

/// Scan states (`PROP_MAC_SCAN_STATE`).
pub mod scan_state {
    /// `SPINEL_SCAN_STATE_IDLE`
    pub const IDLE: u8 = 0;
    /// `SPINEL_SCAN_STATE_ENERGY`
    pub const ENERGY: u8 = 2;
}

/// Frame metadata flags of `STREAM_RAW`.
pub mod md_flag {
    /// `SPINEL_MD_FLAG_TX`
    pub const TX: u16 = 0x0001;
    /// `SPINEL_MD_FLAG_BAD_FCS`
    pub const BAD_FCS: u16 = 0x0004;
    /// `SPINEL_MD_FLAG_ACKED_FP`: the frame was acknowledged with frame pending set.
    pub const ACKED_FP: u16 = 0x0010;
    /// `SPINEL_MD_FLAG_ACKED_SEC`: the frame was acknowledged with a secured enhanced ACK.
    pub const ACKED_SEC: u16 = 0x0020;
}
