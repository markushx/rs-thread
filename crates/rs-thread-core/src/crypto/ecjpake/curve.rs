//! The narrow P-256 interface EC-JPAKE needs, and its RustCrypto
//! implementation [`SoftP256`].
//!
//! The trait exists so a hardware engine (nRF CryptoCell/CRACEN, ESP ECC)
//! or rs-matter's `EcPoint`/`EcScalar` can be substituted later (ADR 0001).
//! Implementations must be constant time in scalars for [`P256::mul`],
//! [`P256::mul_base`] and the scalar arithmetic: these see the secret keys
//! and the password.

use core::fmt;

use zeroize::Zeroize;

/// Length of an uncompressed SEC1 point (`0x04 || X || Y`).
pub const POINT_LEN: usize = 65;
/// Length of a big-endian scalar / field element.
pub const SCALAR_LEN: usize = 32;

/// P-256 (secp256r1) group and scalar-field operations.
///
/// Points handed out by the implementation are always valid group elements
/// (possibly the identity); [`P256::decode`] only yields validated,
/// non-identity points.
pub trait P256 {
    /// Scalar modulo the group order `n`.
    type Scalar: Copy + Zeroize;
    /// Group element (any internal representation).
    type Point: Copy;

    /// Decode a big-endian scalar; `None` unless `0 <= value < n`.
    fn scalar_from_be(&self, bytes: &[u8; SCALAR_LEN]) -> Option<Self::Scalar>;
    /// Interpret 32 big-endian bytes as an integer and reduce it modulo `n`
    /// (used for hash-to-scalar and the password).
    fn scalar_reduce(&self, bytes: &[u8; SCALAR_LEN]) -> Self::Scalar;
    /// Encode a scalar as 32 big-endian bytes.
    fn scalar_to_be(&self, s: &Self::Scalar) -> [u8; SCALAR_LEN];
    /// `s == 0`.
    fn scalar_is_zero(&self, s: &Self::Scalar) -> bool;
    /// `a * b mod n`.
    fn scalar_mul(&self, a: &Self::Scalar, b: &Self::Scalar) -> Self::Scalar;
    /// `a - b mod n`.
    fn scalar_sub(&self, a: &Self::Scalar, b: &Self::Scalar) -> Self::Scalar;

    /// The base point `G`.
    fn generator(&self) -> Self::Point;
    /// `k * G` (constant time in `k`).
    fn mul_base(&self, k: &Self::Scalar) -> Self::Point;
    /// `k * P` (constant time in `k`).
    fn mul(&self, p: &Self::Point, k: &Self::Scalar) -> Self::Point;
    /// `a * P + b * Q`. The default uses two [`P256::mul`]s.
    fn mul_add(
        &self,
        a: &Self::Scalar,
        p: &Self::Point,
        b: &Self::Scalar,
        q: &Self::Point,
    ) -> Self::Point {
        let ap = self.mul(p, a);
        let bq = self.mul(q, b);
        self.add(&ap, &bq)
    }
    /// `P + Q`.
    fn add(&self, p: &Self::Point, q: &Self::Point) -> Self::Point;
    /// `P - Q`.
    fn sub(&self, p: &Self::Point, q: &Self::Point) -> Self::Point;
    /// `-P`.
    fn neg(&self, p: &Self::Point) -> Self::Point;
    /// `P == O` (the point at infinity).
    fn is_identity(&self, p: &Self::Point) -> bool;
    /// `P == Q`.
    fn point_eq(&self, p: &Self::Point, q: &Self::Point) -> bool;

    /// Uncompressed SEC1 encoding; `None` for the identity (which has no
    /// uncompressed encoding).
    fn encode(&self, p: &Self::Point) -> Option<[u8; POINT_LEN]>;
    /// Decode an uncompressed SEC1 point. Returns `None` unless `bytes` is
    /// exactly `0x04 || X || Y` with `X, Y < p` on the curve (P-256 has
    /// cofactor 1, so this is the full public-key validation of SEC1
    /// §3.2.2.1; the identity cannot be encoded this way).
    fn decode(&self, bytes: &[u8]) -> Option<Self::Point>;
}

impl<T: P256 + ?Sized> P256 for &T {
    type Scalar = T::Scalar;
    type Point = T::Point;

    fn scalar_from_be(&self, bytes: &[u8; SCALAR_LEN]) -> Option<Self::Scalar> {
        (**self).scalar_from_be(bytes)
    }
    fn scalar_reduce(&self, bytes: &[u8; SCALAR_LEN]) -> Self::Scalar {
        (**self).scalar_reduce(bytes)
    }
    fn scalar_to_be(&self, s: &Self::Scalar) -> [u8; SCALAR_LEN] {
        (**self).scalar_to_be(s)
    }
    fn scalar_is_zero(&self, s: &Self::Scalar) -> bool {
        (**self).scalar_is_zero(s)
    }
    fn scalar_mul(&self, a: &Self::Scalar, b: &Self::Scalar) -> Self::Scalar {
        (**self).scalar_mul(a, b)
    }
    fn scalar_sub(&self, a: &Self::Scalar, b: &Self::Scalar) -> Self::Scalar {
        (**self).scalar_sub(a, b)
    }
    fn generator(&self) -> Self::Point {
        (**self).generator()
    }
    fn mul_base(&self, k: &Self::Scalar) -> Self::Point {
        (**self).mul_base(k)
    }
    fn mul(&self, p: &Self::Point, k: &Self::Scalar) -> Self::Point {
        (**self).mul(p, k)
    }
    fn mul_add(
        &self,
        a: &Self::Scalar,
        p: &Self::Point,
        b: &Self::Scalar,
        q: &Self::Point,
    ) -> Self::Point {
        (**self).mul_add(a, p, b, q)
    }
    fn add(&self, p: &Self::Point, q: &Self::Point) -> Self::Point {
        (**self).add(p, q)
    }
    fn sub(&self, p: &Self::Point, q: &Self::Point) -> Self::Point {
        (**self).sub(p, q)
    }
    fn neg(&self, p: &Self::Point) -> Self::Point {
        (**self).neg(p)
    }
    fn is_identity(&self, p: &Self::Point) -> bool {
        (**self).is_identity(p)
    }
    fn point_eq(&self, p: &Self::Point, q: &Self::Point) -> bool {
        (**self).point_eq(p, q)
    }
    fn encode(&self, p: &Self::Point) -> Option<[u8; POINT_LEN]> {
        (**self).encode(p)
    }
    fn decode(&self, bytes: &[u8]) -> Option<Self::Point> {
        (**self).decode(bytes)
    }
}

/// P-256 on RustCrypto `p256` (constant-time projective arithmetic).
#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub struct SoftP256;

impl fmt::Debug for SoftP256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SoftP256")
    }
}

mod soft {
    use p256::elliptic_curve::Group;
    use p256::elliptic_curve::ff::{Field, PrimeField};
    use p256::elliptic_curve::ops::Reduce;
    use p256::elliptic_curve::point::AffineCoordinates;
    use p256::{AffinePoint, FieldBytes, ProjectivePoint, Scalar};

    use super::{P256, POINT_LEN, SCALAR_LEN, SoftP256};

    impl P256 for SoftP256 {
        type Scalar = Scalar;
        type Point = ProjectivePoint;

        fn scalar_from_be(&self, bytes: &[u8; SCALAR_LEN]) -> Option<Scalar> {
            Scalar::from_repr(FieldBytes::from(*bytes)).into_option()
        }
        fn scalar_reduce(&self, bytes: &[u8; SCALAR_LEN]) -> Scalar {
            <Scalar as Reduce<FieldBytes>>::reduce(&FieldBytes::from(*bytes))
        }
        fn scalar_to_be(&self, s: &Scalar) -> [u8; SCALAR_LEN] {
            s.to_repr().into()
        }
        fn scalar_is_zero(&self, s: &Scalar) -> bool {
            bool::from(s.is_zero())
        }
        fn scalar_mul(&self, a: &Scalar, b: &Scalar) -> Scalar {
            a * b
        }
        fn scalar_sub(&self, a: &Scalar, b: &Scalar) -> Scalar {
            a - b
        }
        fn generator(&self) -> ProjectivePoint {
            ProjectivePoint::generator()
        }
        fn mul_base(&self, k: &Scalar) -> ProjectivePoint {
            ProjectivePoint::generator() * k
        }
        fn mul(&self, p: &ProjectivePoint, k: &Scalar) -> ProjectivePoint {
            p * k
        }
        fn add(&self, p: &ProjectivePoint, q: &ProjectivePoint) -> ProjectivePoint {
            p + q
        }
        fn sub(&self, p: &ProjectivePoint, q: &ProjectivePoint) -> ProjectivePoint {
            p - q
        }
        fn neg(&self, p: &ProjectivePoint) -> ProjectivePoint {
            -p
        }
        fn is_identity(&self, p: &ProjectivePoint) -> bool {
            bool::from(p.is_identity())
        }
        fn point_eq(&self, p: &ProjectivePoint, q: &ProjectivePoint) -> bool {
            p == q
        }
        fn encode(&self, p: &ProjectivePoint) -> Option<[u8; POINT_LEN]> {
            let a = p.to_affine();
            if bool::from(a.is_identity()) {
                return None;
            }
            let mut out = [0u8; POINT_LEN];
            out[0] = 0x04;
            out[1..33].copy_from_slice(&a.x());
            out[33..].copy_from_slice(&a.y());
            Some(out)
        }
        fn decode(&self, bytes: &[u8]) -> Option<ProjectivePoint> {
            if bytes.len() != POINT_LEN || bytes[0] != 0x04 {
                return None;
            }
            let mut x = FieldBytes::default();
            let mut y = FieldBytes::default();
            x.copy_from_slice(&bytes[1..33]);
            y.copy_from_slice(&bytes[33..]);
            // `from_coordinates` rejects non-canonical coordinates (>= p)
            // and points that are not on the curve.
            AffinePoint::from_coordinates(&x, &y)
                .into_option()
                .map(ProjectivePoint::from)
        }
    }
}
