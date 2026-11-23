/// Deterministic xorshift64* random source (not cryptographic; tests only).
#[derive(Debug, Clone)]
pub struct SimRng(u64);

impl SimRng {
    /// A generator for `seed`.
    pub fn new(seed: u64) -> Self {
        Self(seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1)
    }

    /// A uniform value in `0.0..1.0`.
    pub fn unit(&mut self) -> f64 {
        use rand_core::Rng;
        (self.next_u64() >> 11) as f64 / (1u64 << 53) as f64
    }
}

impl rand_core::TryRng for SimRng {
    type Error = core::convert::Infallible;
    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        Ok((self.try_next_u64()? >> 32) as u32)
    }
    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        Ok(self.0.wrapping_mul(0x2545_F491_4F6C_DD1D))
    }
    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        for chunk in dst.chunks_mut(8) {
            let v = self.try_next_u64()?.to_le_bytes();
            chunk.copy_from_slice(&v[..chunk.len()]);
        }
        Ok(())
    }
}

impl rand_core::TryCryptoRng for SimRng {}
