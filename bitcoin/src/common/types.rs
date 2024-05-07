//! This module contains common types.

use core::fmt;
use core::ops::BitXor;

/// Represents the parity passed between FFI function calls.
#[derive(Copy, Clone, PartialEq, Eq, Debug, PartialOrd, Ord, Hash)]
pub enum Parity {
    /// Even parity.
    Even = 0,
    /// Odd parity.
    Odd = 1,
}

impl Parity {
    /// Converts parity into an integer (byte) value.
    ///
    /// This returns `0` for even parity and `1` for odd parity.
    pub fn to_u8(self) -> u8 {
        self as u8
    }

    /// Converts parity into an integer value.
    ///
    /// This returns `0` for even parity and `1` for odd parity.
    pub fn to_i32(self) -> i32 {
        self as i32
    }

    /// Constructs a [`Parity`] from a byte.
    ///
    /// The only allowed values are `0` meaning even parity and `1` meaning odd.
    /// Other values result in error being returned.
    pub fn from_u8(parity: u8) -> Result<Parity, InvalidParityValue> {
        Parity::from_i32(parity.into())
    }

    /// Constructs a [`Parity`] from a signed integer.
    ///
    /// The only allowed values are `0` meaning even parity and `1` meaning odd.
    /// Other values result in error being returned.
    pub fn from_i32(parity: i32) -> Result<Parity, InvalidParityValue> {
        match parity {
            0 => Ok(Parity::Even),
            1 => Ok(Parity::Odd),
            _ => Err(InvalidParityValue(parity)),
        }
    }
}

/// `Even` for `0`, `Odd` for `1`, error for anything else
impl TryFrom<i32> for Parity {
    type Error = InvalidParityValue;

    fn try_from(parity: i32) -> Result<Self, Self::Error> {
        Self::from_i32(parity)
    }
}

/// `Even` for `0`, `Odd` for `1`, error for anything else
impl TryFrom<u8> for Parity {
    type Error = InvalidParityValue;

    fn try_from(parity: u8) -> Result<Self, Self::Error> {
        Self::from_u8(parity)
    }
}

/// The conversion returns `0` for even parity and `1` for odd.
impl From<Parity> for i32 {
    fn from(parity: Parity) -> i32 {
        parity.to_i32()
    }
}

/// The conversion returns `0` for even parity and `1` for odd.
impl From<Parity> for u8 {
    fn from(parity: Parity) -> u8 {
        parity.to_u8()
    }
}

/// Returns even parity if the operands are equal, odd otherwise.
impl BitXor for Parity {
    type Output = Parity;

    fn bitxor(self, rhs: Parity) -> Self::Output {
        // This works because Parity has only two values (i.e. only 1 bit of information).
        if self == rhs {
            Parity::Even // 1^1==0 and 0^0==0
        } else {
            Parity::Odd // 1^0==1 and 0^1==1
        }
    }
}

/// Error returned when conversion from an integer to `Parity` fails.
//
// Note that we don't allow inspecting the value because we may change the type.
// Yes, this comment is intentionally NOT doc comment.
// Too many derives for compatibility with current Error type.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct InvalidParityValue(i32);

impl fmt::Display for InvalidParityValue {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "invalid value {} for Parity - must be 0 or 1", self.0)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for InvalidParityValue {}

/// The parity is serialized as `u8` - `0` for even, `1` for odd.
#[cfg(feature = "serde")]
impl serde::Serialize for Parity {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_u8(self.to_u8())
    }
}

/// The parity is deserialized as `u8` - `0` for even, `1` for odd.
#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for Parity {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct Visitor;

        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = Parity;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("8-bit integer (byte) with value 0 or 1")
            }

            fn visit_u8<E>(self, v: u8) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                use serde::de::Unexpected;

                Parity::from_u8(v)
                    .map_err(|_| E::invalid_value(Unexpected::Unsigned(v.into()), &"0 or 1"))
            }
        }

        d.deserialize_u8(Visitor)
    }
}
