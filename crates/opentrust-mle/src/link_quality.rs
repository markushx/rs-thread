//! Link quality (Thread 1.4.1 §4.? / OT `link_quality.{hpp,cpp}`).

/// Link quality 0..=3 (3 = best), as carried in Route64 and Connectivity
/// TLVs (OT `LinkQuality`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(u8)]
pub enum LinkQuality {
    /// Unknown / unusable link (cost 16 = infinite).
    #[default]
    Q0 = 0,
    /// Poor link.
    Q1 = 1,
    /// Medium link.
    Q2 = 2,
    /// Good link.
    Q3 = 3,
}

impl LinkQuality {
    /// Number of the two low bits of `v` (wider values are masked).
    pub const fn from_bits(v: u8) -> Self {
        match v & 3 {
            0 => Self::Q0,
            1 => Self::Q1,
            2 => Self::Q2,
            _ => Self::Q3,
        }
    }

    /// Numeric value 0..=3.
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}
