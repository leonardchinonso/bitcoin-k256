use subtle::{ConditionallySelectable, ConstantTimeEq, ConstantTimeGreater};

// Perform elementwise XOR on two arrays and return the resulting output array.
pub fn xor_arrays<T, const SIZE: usize>(arr1: &[T; SIZE], arr2: &[T; SIZE]) -> [T; SIZE]
where
    T: Copy + Default + std::ops::BitXor<Output = T>,
{
    let mut xored = [T::default(); SIZE];
    for i in 0..SIZE {
        xored[i] = arr1[i] ^ arr2[i];
    }
    xored
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

/// Utility function used to parse hex into a target u8 buffer. Returns
/// the number of bytes converted or an error if it encounters an invalid
/// character or unexpected end of string.
pub(crate) fn from_hex(hex: &str, target: &mut [u8]) -> Result<usize, ()> {
    if hex.len() % 2 == 1 || hex.len() > target.len() * 2 {
        return Err(());
    }

    let mut b = 0;
    let mut idx = 0;
    for c in hex.bytes() {
        b <<= 4;
        match c {
            b'A'..=b'F' => b |= c - b'A' + 10,
            b'a'..=b'f' => b |= c - b'a' + 10,
            b'0'..=b'9' => b |= c - b'0',
            _ => return Err(()),
        }
        if (idx & 1) == 1 {
            target[idx / 2] = b;
            b = 0;
        }
        idx += 1;
    }
    Ok(idx / 2)
}