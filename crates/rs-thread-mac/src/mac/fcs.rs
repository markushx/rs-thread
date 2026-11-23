//! IEEE 802.15.4 frame check sequence (CRC-16/KERMIT: ITU-T polynomial,
//! reflected, transmitted least significant octet first).

use crate::frame::FCS_LEN;

/// CRC-16 over `data` as used for the 802.15.4 FCS.
pub fn crc16(data: &[u8]) -> u16 {
    let mut crc = 0u16;
    for &b in data {
        crc ^= u16::from(b);
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0x8408
            } else {
                crc >> 1
            };
        }
    }
    crc
}

/// The 2-byte FCS field for `data`.
pub fn fcs(data: &[u8]) -> [u8; FCS_LEN] {
    crc16(data).to_le_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kermit_check_value() {
        assert_eq!(crc16(b"123456789"), 0x2189);
    }

    #[test]
    fn residue_is_zero() {
        let f = [0x02, 0x00, 0x2e];
        let mut all = [0u8; 5];
        all[..3].copy_from_slice(&f);
        all[3..].copy_from_slice(&fcs(&f));
        assert_eq!(crc16(&all), 0);
    }
}
