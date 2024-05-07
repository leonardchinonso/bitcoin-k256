use core::fmt;
use internals::write_err;

/// The main error type for this library.
#[derive(Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Debug)]
pub enum Error {
    /// Signature failed verification.
    IncorrectSignature,
    /// Bad sized message ("messages" are actually fixed-sized digests [`constants::MESSAGE_SIZE`]).
    InvalidMessage,
    /// Bad public key.
    InvalidPublicKey,
    /// Bad signature.
    InvalidSignature,
    /// Bad secret key.
    InvalidSecretKey,
    /// Bad shared secret.
    InvalidSharedSecret,
    /// Bad recovery id.
    InvalidRecoveryId,
    /// Tried to add/multiply by an invalid tweak.
    InvalidTweak,
    /// Didn't pass enough memory to context creation with preallocated memory.
    NotEnoughMemory,
    /// Bad set of public keys.
    InvalidPublicKeySum,
    /// The only valid parity values are 0 or 1.
    InvalidParityValue(crate::InvalidParityValue),
    /// Bad EllSwift value
    InvalidEllSwift,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        use Error::*;

        match *self {
            IncorrectSignature => f.write_str("signature failed verification"),
            InvalidMessage => f.write_str("message was not 32 bytes (do you need to hash?)"),
            InvalidPublicKey => f.write_str("malformed public key"),
            InvalidSignature => f.write_str("malformed signature"),
            InvalidSecretKey => f.write_str("malformed or out-of-range secret key"),
            InvalidSharedSecret => f.write_str("malformed or out-of-range shared secret"),
            InvalidRecoveryId => f.write_str("bad recovery id"),
            InvalidTweak => f.write_str("bad tweak"),
            NotEnoughMemory => f.write_str("not enough memory allocated"),
            InvalidPublicKeySum => f.write_str(
                "the sum of public keys was invalid or the input vector lengths was less than 1",
            ),
            InvalidParityValue(e) => write_err!(f, "couldn't create parity"; e),
            InvalidEllSwift => f.write_str("malformed EllSwift value"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::IncorrectSignature => None,
            Error::InvalidMessage => None,
            Error::InvalidPublicKey => None,
            Error::InvalidSignature => None,
            Error::InvalidSecretKey => None,
            Error::InvalidSharedSecret => None,
            Error::InvalidRecoveryId => None,
            Error::InvalidTweak => None,
            Error::NotEnoughMemory => None,
            Error::InvalidPublicKeySum => None,
            Error::InvalidParityValue(error) => Some(error),
            Error::InvalidEllSwift => None,
        }
    }
}
