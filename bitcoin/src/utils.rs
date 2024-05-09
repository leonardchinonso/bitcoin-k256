use k256::{PublicKey, SecretKey};

use subtle::{ConditionallySelectable, ConstantTimeEq, ConstantTimeGreater};

use crate::{MaybeScalar, Scalar};

fn curve_order_plus(num: i8) -> [u8; 32] {
    // let mut bytes = Scalar::curve_order().serialize();

    // let carry: bool;
    // (bytes[31], carry) = bytes[31].overflowing_add_signed(num);

    // if carry {
    //     if num >= 0 {
    //         bytes[30] += 1;
    //     } else {
    //         bytes[30] -= 1;
    //     }
    // }
    // bytes
    [0; 32]
}

/// Tweaks a [`SecretKey`] by adding `tweak` modulo the curve order.
///
/// # Errors
///
/// Returns an error if the resulting key would be invalid.
pub fn add_tweak(sk: SecretKey, tweak: Scalar) -> Result<SecretKey, String> {
    let sk_scalar = Scalar::from(sk);
    let secp_order_minus_one = Scalar::max();

    if sk_scalar.greater_than_curve_order_minus_one() || tweak.greater_than_curve_order_minus_one()
    {
        return Err(format!(
            "Secret key and tweak cannot be greater than or equal to the Secp256k1 curve order"
        ));
    }

    // x' = (x + t) % CURVE_ORDER
    let sk_prime = match sk_scalar + tweak {
        MaybeScalar::Zero => {
            return Err(format!(
                "Invalid scalar value, greater than or equal to curve order"
            ));
        }
        MaybeScalar::Valid(s) => s,
    };

    if !sk_prime.greater_than_curve_order_minus_one() {
        return Ok(SecretKey::from(sk_prime.inner));
    }

    match sk_prime + (-secp_order_minus_one) {
        MaybeScalar::Zero => {
            return Err(format!("Invalid scalar value 2"));
        }
        MaybeScalar::Valid(s) => Ok(SecretKey::from(s.inner)),
    }
}

/// Tweaks a [`PublicKey`] by adding `tweak * G` modulo the curve order.
///
/// # Errors
///
/// Returns an error if the resulting key would be invalid.
pub fn add_exp_tweak(pk: PublicKey, tweak: Scalar) -> Result<PublicKey, String> {
    // let parity = match self.has_odd_y() {
    //     true => Parity::Odd,
    //     false => Parity::Even,
    // };

    // println!("The parity is: {:?}", parity);

    // // T = t * G
    // let big_t = tweak * PublicKey::generator();
    // // P' = P + T
    // let tweaked_pubkey = match self + big_t {
    //     Infinity => {
    //         return Err(String::from("Tweaked public key is at infinity"));
    //     }
    //     Valid(pk) => pk,
    // };

    // println!("Original T1: {:?}", big_t);

    // Ok((tweaked_pubkey, parity))
    todo!()
}
