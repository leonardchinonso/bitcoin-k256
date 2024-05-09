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
    let secp_order_minus_one = Scalar::curve_order_minus_one();

    if sk_scalar.greater_than_curve_order_minus_one() || tweak.greater_than_curve_order_minus_one()
    {
        return Err(format!(
            "Secret key and tweak cannot be greater than or equal to the Secp256k1 curve order"
        ));
    }

    // x' = (x + t) % CURVE_ORDER
    let sk_prime = match sk_scalar + tweak {
        MaybeScalar::Zero => {
            return Err(format!("Invalid scalar value, greater than or equal to curve order"));
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
    Ok(pk)
}

/// Compares two slices lexicographically in constant time whose
/// elements can be ordered in constant time.
///
/// Returns:
///
/// - `Ordering::Less` if `lhs < rhs`
/// - `Ordering::Equal` if `lhs == rhs`
/// - `Ordering::Greater` if `lhs > rhs`
///
/// Duplicated from [This PR](https://github.com/dalek-cryptography/subtle/pull/116).
pub fn ct_slice_lex_cmp<T>(lhs: &[T], rhs: &[T]) -> std::cmp::Ordering
where
    T: ConstantTimeEq + ConstantTimeGreater,
{
    let mut whole_slice_is_eq = subtle::Choice::from(1);
    let mut whole_slice_is_gt = subtle::Choice::from(0);

    // Zip automatically stops iterating once one of the zipped
    // iterators has been exhausted.
    for (v1, v2) in lhs.iter().zip(rhs.iter()) {
        // If the previous elements in the array were all equal, but `v1 > v2` in this
        // position, then `lhs` is deemed to be greater than `rhs`.
        //
        // We want `whole_slice_is_gt` to remain true if we ever found this condition,
        // but since we're aiming for constant-time, we cannot break the loop.
        whole_slice_is_gt |= whole_slice_is_eq & v1.ct_gt(&v2);

        // Track whether all elements in the slices up to this point are equal.
        whole_slice_is_eq &= v1.ct_eq(&v2);
    }

    let l_len = lhs.len() as u64;
    let r_len = rhs.len() as u64;
    let lhs_is_longer = l_len.ct_gt(&r_len);
    let rhs_is_longer = r_len.ct_gt(&l_len);

    // Fallback: lhs < rhs
    let mut order = std::cmp::Ordering::Less;

    // both slices up to `min(l_len, r_len)` were equal.
    order.conditional_assign(&std::cmp::Ordering::Equal, whole_slice_is_eq);

    // `rhs` is a prefix of `lhs`. `lhs` is lexicographically greater.
    order.conditional_assign(
        &std::cmp::Ordering::Greater,
        whole_slice_is_eq & lhs_is_longer,
    );

    // `lhs` is a prefix of `rhs`. `rhs` is lexicographically greater.
    order.conditional_assign(&std::cmp::Ordering::Less, whole_slice_is_eq & rhs_is_longer);

    // `lhs` contains the earliest strictly-greater element.
    order.conditional_assign(&std::cmp::Ordering::Greater, whole_slice_is_gt);

    order
}
