//! Radio link identification for multi-radio devices (OT `Mac::RadioType`).

/// The radio link a frame is sent on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum RadioLink {
    /// The IEEE 802.15.4 radio (the default; every Thread device has it).
    #[default]
    Ieee802154,
    /// Thread Radio Encapsulation Link over the infrastructure network
    /// (feature `trel`).
    Trel,
}

impl RadioLink {
    /// Index for per-link tables.
    pub const fn index(self) -> usize {
        match self {
            Self::Ieee802154 => 0,
            Self::Trel => 1,
        }
    }
}
