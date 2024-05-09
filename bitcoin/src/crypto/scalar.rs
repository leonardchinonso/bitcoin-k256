use once_cell::sync::Lazy;

use crate::crypto::key::PublicKey;

/// Represents an elliptic curve scalar value which might be zero.
/// Supports all the same constant-time arithmetic operators supported
/// by [`Scalar`].
///
/// `MaybeScalar` should only be used in cases where it is possible for
/// an input to be zero. In all possible cases, using [`Scalar`] is more
/// appropriate. The output of arithmetic operations with non-zero `Scalar`s
/// can result in a `MaybeScalar` - for example, adding two scalars together
/// linearly.
///
/// ```
/// use secp::{MaybeScalar, Scalar};
///
/// let maybe_scalar: MaybeScalar = Scalar::one() + Scalar::one();
/// ```
///
/// This is because the two scalars might represent values which are additive
/// inverses of each other (i.e. `x + (-x)`), so the output of their addition
/// can result in zero, which must be checked for by the caller where
/// appropriate.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum MaybeScalar {
    Zero,
    Valid(Scalar),
}

use MaybeScalar::*;

impl MaybeScalar {
    /// Returns a valid `MaybeScalar` with a value of 1.
    pub fn one() -> MaybeScalar {
        Valid(Scalar::one())
    }

    /// Returns a valid `MaybeScalar` with a value of two.
    pub fn two() -> MaybeScalar {
        Valid(Scalar::two())
    }

    /// Returns half of the curve order `n`, specifically `n >> 1`.
    pub fn half_order() -> MaybeScalar {
        Valid(Scalar::half_order())
    }

    /// Returns a valid `MaybeScalar` with the maximum possible value less
    /// than the curve order, `n - 1`.
    pub fn max() -> MaybeScalar {
        Valid(Scalar::max())
    }

    /// Returns true if this scalar represents zero.
    pub fn is_zero(&self) -> bool {
        self == &Zero
    }

    /// Serializes the scalar to a big-endian byte array representation.
    ///
    /// # Warning
    ///
    /// Use cautiously. Non-constant time operations on these bytes
    /// could reveal secret key material.
    pub fn serialize(&self) -> [u8; 32] {
        match self {
            Valid(scalar) => scalar.serialize(),
            Zero => [0; 32],
        }
    }

    /// Returns an option which is `None` if `self == MaybeScalar::Zero`,
    /// or a `Some(Scalar)` otherwise.
    pub fn into_option(self) -> Option<Scalar> {
        Option::from(self)
    }

    /// Converts the `MaybeScalar` into a `Result<Scalar, String>`,
    /// returning `Ok(Scalar)` if the scalar is a valid non-zero number, or
    /// `Err(String)` if `maybe_scalar == MaybeScalar::Zero`.
    pub fn not_zero(self) -> Result<Scalar, String> {
        Scalar::try_from(self)
    }

    /// Coerces the `MaybeScalar` into a [`Scalar`]. Panics if `self == MaybeScalar::Zero`.
    pub fn unwrap(self) -> Scalar {
        match self {
            Valid(point) => point,
            Zero => panic!("called unwrap on MaybeScalar::Zero"),
        }
    }
}

impl From<k256::NonZeroScalar> for MaybeScalar {
    fn from(nz_scalar: k256::NonZeroScalar) -> Self {
        MaybeScalar::from(Scalar::from(nz_scalar))
    }
}

impl From<Scalar> for MaybeScalar {
    /// Converts the scalar into a [`MaybeScalar::Valid`] instance.
    fn from(scalar: Scalar) -> Self {
        MaybeScalar::Valid(scalar)
    }
}

static SCALAR_ONE: Lazy<Scalar> = Lazy::new(|| {
    Scalar::try_from(&[
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 1u8,
    ])
    .unwrap()
});

static SCALAR_TWO: Lazy<Scalar> = Lazy::new(|| {
    Scalar::try_from(&[
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 2u8,
    ])
    .unwrap()
});

static SCALAR_HALF_ORDER: Lazy<Scalar> = Lazy::new(|| {
    Scalar::try_from(&[
        0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x5d, 0x57, 0x6e, 0x73, 0x57, 0xa4, 0x50, 0x1d, 0xdf, 0xe9, 0x2f, 0x46, 0x68, 0x1b,
        0x20, 0xa0u8,
    ])
    .unwrap()
});

static SCALAR_MAX: Lazy<Scalar> =
    Lazy::new(|| Scalar::try_from(&CURVE_ORDER_MINUS_ONE_BYTES).unwrap());

/// This is a big-endian representation of the secp256k1 curve order `n`.
const CURVE_ORDER_BYTES: [u8; 32] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
    0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41,
];

/// This is a big-endian representation of the secp256k1 curve order `n` minus one.
const CURVE_ORDER_MINUS_ONE_BYTES: [u8; 32] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
    0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x40,
];

#[derive(Copy, Clone)]
pub struct Scalar {
    pub(crate) inner: k256::NonZeroScalar,
}

impl Scalar {
    /// Returns a valid `Scalar` with a value of 1.
    pub fn one() -> Scalar {
        *SCALAR_ONE
    }

    /// Returns a valid `Scalar` with a value of two.
    pub fn two() -> Scalar {
        *SCALAR_TWO
    }

    /// Returns half of the curve order `n`, specifically `n >> 1`.
    pub fn half_order() -> Scalar {
        *SCALAR_HALF_ORDER
    }

    /// Returns a valid `Scalar` with the maximum possible value less
    /// than the curve order, `n - 1`.
    pub fn max() -> Scalar {
        *SCALAR_MAX
    }

    /// Generates a new random scalar from the given CSPRNG.
    #[cfg(feature = "rand")]
    pub fn random<R: rand::RngCore + rand::CryptoRng>(rng: &mut R) -> Scalar {
        let inner = k256::NonZeroScalar::random(rng);
        Scalar::from(inner)
    }

    /// Serializes the scalar to a big-endian byte array representation.
    ///
    /// # Warning
    ///
    /// Use cautiously. Non-constant time operations on these bytes
    /// could reveal secret key material.
    pub fn serialize(&self) -> [u8; 32] {
        return self.inner.to_bytes().into();
    }

    /// Parses a non-zero scalar in the range `[1, n)` from a given byte slice,
    /// which must be exactly 32-byte long and must represent the scalar in
    /// big-endian format.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, String> {
        let inner = match k256::NonZeroScalar::try_from(bytes) {
            Ok(s) => s,
            Err(err) => {
                return Err(format!("Error getting Scalar from slice: {:?}", err));
            }
        };
        Ok(Scalar::from(inner))
    }

    /// Multiplies the secp256k1 base point by this scalar. This is how
    /// public keys (points) are derived from private keys (scalars).
    /// Since this scalar is non-zero, the point derived from base-point
    /// multiplication is also guaranteed to be valid.
    ///
    /// Assumes the public key is compressed
    pub fn base_point_mul(&self) -> PublicKey {
        let inner = k256::PublicKey::from_secret_scalar(&self.inner);
        PublicKey::new(inner)
    }
}

impl TryFrom<&[u8; 32]> for Scalar {
    type Error = String;

    /// Attempts to parse a 32-byte array as a scalar in the range `[1, n)`
    /// in constant time, where `n` is the curve order.
    ///
    /// Returns [`InvalidScalarBytes`] if the integer represented by the bytes
    /// is greater than or equal to the curve order, or if the bytes are all zero.
    fn try_from(bytes: &[u8; 32]) -> Result<Self, Self::Error> {
        Self::from_slice(bytes as &[u8])
    }
}

impl From<k256::NonZeroScalar> for Scalar {
    fn from(nz_scalar: k256::NonZeroScalar) -> Self {
        return Scalar { inner: nz_scalar };
    }
}
