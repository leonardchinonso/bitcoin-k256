// use core::fmt;
// use internals::impl_array_newtype;

// use crate::CryptoError;

// /// Trait describing something that promises to be a 32-byte random number; in particular,
// /// it has negligible probability of being zero or overflowing the group order. Such objects
// /// may be converted to `Message`s without any error paths.
// pub trait ThirtyTwoByteHash {
//     /// Converts the object into a 32-byte array
//     fn into_32(self) -> [u8; 32];
// }

// #[cfg(feature = "hashes")]
// impl ThirtyTwoByteHash for hashes::sha256::Hash {
//     fn into_32(self) -> [u8; 32] {
//         self.to_byte_array()
//     }
// }

// #[cfg(feature = "hashes")]
// impl ThirtyTwoByteHash for hashes::sha256d::Hash {
//     fn into_32(self) -> [u8; 32] {
//         self.to_byte_array()
//     }
// }

// #[cfg(feature = "hashes")]
// impl<T: hashes::sha256t::Tag> ThirtyTwoByteHash for hashes::sha256t::Hash<T> {
//     fn into_32(self) -> [u8; 32] {
//         self.to_byte_array()
//     }
// }

// /// The size (in bytes) of a message.
// pub const MESSAGE_SIZE: usize = 32;

// /// A (hashed) message input to an ECDSA signature.
// #[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
// pub struct Message([u8; MESSAGE_SIZE]);
// // TODO(chinonso): hardcoding MESSAGE_SIZE to hack around the compiler
// impl_array_newtype!(Message, u8, 32);
// impl_pretty_debug!(Message);

// impl Message {
//     /// **If you just want to sign an arbitrary message use `Message::from_hashed_data` instead.**
//     ///
//     /// Converts a `MESSAGE_SIZE`-byte slice to a message object. **WARNING:** the slice has to be a
//     /// cryptographically secure hash of the actual message that's going to be signed. Otherwise
//     /// the result of signing isn't a
//     /// [secure signature](https://twitter.com/pwuille/status/1063582706288586752).
//     #[inline]
//     #[deprecated(since = "0.28.0", note = "use from_digest_slice instead")]
//     pub fn from_slice(digest: &[u8]) -> Result<Message, CryptoError> {
//         Message::from_digest_slice(digest)
//     }

//     /// Creates a [`Message`] from a `digest`.
//     ///
//     /// **If you just want to sign an arbitrary message use `Message::from_hashed_data` instead.**
//     ///
//     /// The `digest` array has to be a cryptographically secure hash of the actual message that's
//     /// going to be signed. Otherwise the result of signing isn't a [secure signature].
//     ///
//     /// [secure signature]: https://twitter.com/pwuille/status/1063582706288586752
//     #[inline]
//     pub fn from_digest(digest: [u8; 32]) -> Message {
//         Message(digest)
//     }

//     /// Creates a [`Message`] from a 32 byte slice `digest`.
//     ///
//     /// **If you just want to sign an arbitrary message use `Message::from_hashed_data` instead.**
//     ///
//     /// The slice has to be 32 bytes long and be a cryptographically secure hash of the actual
//     /// message that's going to be signed. Otherwise the result of signing isn't a [secure
//     /// signature].
//     ///
//     /// # Errors
//     ///
//     /// If `digest` is not exactly 32 bytes long.
//     ///
//     /// [secure signature]: https://twitter.com/pwuille/status/1063582706288586752
//     #[inline]
//     pub fn from_digest_slice(digest: &[u8]) -> Result<Message, CryptoError> {
//         match digest.len() {
//             MESSAGE_SIZE => {
//                 let mut ret = [0u8; MESSAGE_SIZE];
//                 ret[..].copy_from_slice(digest);
//                 Ok(Message(ret))
//             }
//             _ => Err(CryptoError::InvalidMessage),
//         }
//     }

//     pub fn as_bytes(&self) -> &[u8] {
//         &self.0[..]
//     }

//     /// Constructs a [`Message`] by hashing `data` with hash algorithm `H`.
//     ///
//     /// Requires the feature `hashes` to be enabled.
//     ///
//     /// # Examples
//     ///
//     /// ```
//     /// # #[cfg(feature = "hashes")] {
//     /// use secp256k1::hashes::{sha256, Hash};
//     /// use secp256k1::Message;
//     ///
//     /// let m1 = Message::from_hashed_data::<sha256::Hash>("Hello world!".as_bytes());
//     /// // is equivalent to
//     /// let m2 = Message::from(sha256::Hash::hash("Hello world!".as_bytes()));
//     ///
//     /// assert_eq!(m1, m2);
//     /// # }
//     /// ```
//     #[cfg(feature = "hashes")]
//     pub fn from_hashed_data<H: ThirtyTwoByteHash + hashes::Hash>(data: &[u8]) -> Self {
//         <H as hashes::Hash>::hash(data).into()
//     }
// }

// impl<T: ThirtyTwoByteHash> From<T> for Message {
//     /// Converts a 32-byte hash directly to a message without error paths.
//     fn from(t: T) -> Message {
//         Message(t.into_32())
//     }
// }

// impl fmt::LowerHex for Message {
//     fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
//         for byte in self.0.iter() {
//             write!(f, "{:02x}", byte)?;
//         }
//         Ok(())
//     }
// }

// impl fmt::Display for Message {
//     fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
//         fmt::LowerHex::fmt(self, f)
//     }
// }
