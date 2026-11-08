//! Router configuration and the leader weight calculation (OpenThread
//! `DeviceProperties::CalculateLeaderWeight`, `Mle::SetRouterEligible`,
//! `SetRouterUpgradeThreshold`, ...).

use crate::consts::{
    DEFAULT_LEADER_WEIGHT, NETWORK_ID_TIMEOUT_SECS, ROUTER_DOWNGRADE_THRESHOLD,
    ROUTER_SELECTION_JITTER_SECS, ROUTER_UPGRADE_THRESHOLD,
};

/// Power supply of the device (OT `otPowerSupply`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum PowerSupply {
    /// Battery powered.
    Battery,
    /// Externally powered.
    #[default]
    External,
    /// Externally powered and stable (no unplanned power loss).
    ExternalStable,
    /// Externally powered, may lose power unexpectedly.
    ExternalUnstable,
}

/// Device properties that determine the leader weight.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct DeviceProperties {
    /// Power supply.
    pub power_supply: PowerSupply,
    /// The device is a Border Router.
    pub is_border_router: bool,
    /// The device supports CCM (only counted for Border Routers).
    pub supports_ccm: bool,
    /// The device is unstable (reboots / disconnects frequently).
    pub is_unstable: bool,
    /// Manual weight adjustment, clamped to -16..=16.
    pub leader_weight_adjustment: i8,
}

impl DeviceProperties {
    /// Leader weight for these properties (OT `CalculateLeaderWeight`).
    pub const fn leader_weight(&self) -> u8 {
        let mut w = DEFAULT_LEADER_WEIGHT as i16;
        if self.is_border_router {
            w += if self.supports_ccm { 8 } else { 1 };
        }
        w += match self.power_supply {
            PowerSupply::Battery => -8,
            PowerSupply::External => 0,
            PowerSupply::ExternalStable => 4,
            PowerSupply::ExternalUnstable => -4,
        };
        if self.is_unstable
            && !matches!(
                self.power_supply,
                PowerSupply::Battery | PowerSupply::ExternalUnstable
            )
        {
            w -= 4;
        }
        let adj = self.leader_weight_adjustment;
        let adj = if adj < -16 {
            -16
        } else if adj > 16 {
            16
        } else {
            adj
        };
        w += adj as i16;
        if w < 0 {
            0
        } else if w > 255 {
            255
        } else {
            w as u8
        }
    }
}

/// Router role configuration (part of [`MleConfig`](crate::MleConfig)).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RouterConfig {
    /// The device may become a router / leader (OT `mRouterEligible`).
    pub eligible: bool,
    /// Weight announced when this device becomes leader.
    pub leader_weight: u8,
    /// A REED upgrades while fewer than this many routers are active.
    pub upgrade_threshold: u8,
    /// A router may downgrade while more than this many routers are active.
    pub downgrade_threshold: u8,
    /// Upper bound (seconds) of the random delay before a role transition.
    pub selection_jitter_secs: u8,
    /// Seconds without a new router ID sequence before the leader is
    /// considered lost.
    pub network_id_timeout_secs: u8,
}

impl RouterConfig {
    /// OpenThread defaults.
    pub const fn new() -> Self {
        Self {
            eligible: true,
            leader_weight: DEFAULT_LEADER_WEIGHT,
            upgrade_threshold: ROUTER_UPGRADE_THRESHOLD,
            downgrade_threshold: ROUTER_DOWNGRADE_THRESHOLD,
            selection_jitter_secs: ROUTER_SELECTION_JITTER_SECS,
            network_id_timeout_secs: NETWORK_ID_TIMEOUT_SECS,
        }
    }
}

impl Default for RouterConfig {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use PowerSupply::{Battery, External, ExternalStable, ExternalUnstable};

    fn w(ps: PowerSupply, br: bool, ccm: bool, unstable: bool, adj: i8) -> u8 {
        DeviceProperties {
            power_supply: ps,
            is_border_router: br,
            supports_ccm: ccm,
            is_unstable: unstable,
            leader_weight_adjustment: adj,
        }
        .leader_weight()
    }

    /// Vectors of OpenThread `tests/unit/test_mle.cpp`
    /// `TestLeaderWeightCalculation`: (power, br, ccm, unstable, adj) -> weight.
    #[test]
    fn leader_weight_vectors() {
        let cases: &[(PowerSupply, bool, bool, bool, i8, u8)] = &[
            (Battery, false, false, false, 0, 56),
            (External, false, false, false, 0, 64),
            (ExternalStable, false, false, false, 0, 68),
            (ExternalUnstable, false, false, false, 0, 60),
            (Battery, true, false, false, 0, 57),
            (External, true, false, false, 0, 65),
            (ExternalStable, true, false, false, 0, 69),
            (ExternalUnstable, true, false, false, 0, 61),
            (Battery, true, true, false, 0, 64),
            (External, true, true, false, 0, 72),
            (ExternalStable, true, true, false, 0, 76),
            (ExternalUnstable, true, true, false, 0, 68),
            (Battery, false, false, true, 0, 56),
            (External, false, false, true, 0, 60),
            (ExternalStable, false, false, true, 0, 64),
            (ExternalUnstable, false, false, true, 0, 60),
            (Battery, true, false, true, 0, 57),
            (External, true, false, true, 0, 61),
            (ExternalStable, true, false, true, 0, 65),
            (ExternalUnstable, true, false, true, 0, 61),
            (Battery, true, false, false, 10, 67),
            (External, true, false, false, 10, 75),
            (ExternalStable, true, false, false, 10, 79),
            (ExternalUnstable, true, false, false, 10, 71),
            (Battery, false, false, false, -10, 46),
            (External, false, false, false, -10, 54),
            (ExternalStable, false, false, false, -10, 58),
            (ExternalUnstable, false, false, false, -10, 50),
            // Adjustments beyond +-16 clamp.
            (Battery, false, false, false, 20, 72),
            (External, false, false, false, 20, 80),
            (ExternalStable, false, false, false, 20, 84),
            (ExternalUnstable, false, false, false, 20, 76),
            (Battery, true, false, false, -20, 41),
            (External, true, false, false, -20, 49),
            (ExternalStable, true, false, false, -20, 53),
            (ExternalUnstable, true, false, false, -20, 45),
        ];
        for &(ps, br, ccm, un, adj, want) in cases {
            assert_eq!(
                w(ps, br, ccm, un, adj),
                want,
                "{ps:?} {br} {ccm} {un} {adj}"
            );
        }
    }

    #[test]
    fn default_properties_give_default_weight() {
        assert_eq!(DeviceProperties::default().leader_weight(), 64);
        assert_eq!(RouterConfig::new().leader_weight, 64);
    }
}
