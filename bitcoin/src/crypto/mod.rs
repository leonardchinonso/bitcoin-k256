// SPDX-License-Identifier: CC0-1.0

//! Cryptography
//!
//! Cryptography related functionality: keys and signatures.
//!

pub mod ecdsa;
pub mod error;
pub mod key;
pub mod scalar;
pub mod sighash;

mod arithmetic;
mod utils;
// Contents re-exported in `bitcoin::taproot`.
pub(crate) mod taproot;
