use num_bigint::{BigInt, BigUint, ToBigInt};
use num_traits::{One, Signed, Zero};

/// Returns the maximum unsigned integer representable with the given bits
pub(crate) fn max_int(bits: u32) -> BigUint {
    (BigUint::one() << bits) - BigUint::one()
}

/// Returns the maximum signed integer representable with the given bits
pub(crate) fn signed_max_int(bits: u32) -> BigUint {
    (BigUint::one() << (bits - 1)) - BigUint::one()
}

/// Performs modular addition of two BigUint values with the given bit width
pub(crate) fn modular_add(a: &BigUint, b: &BigUint, bits: u32) -> BigUint {
    let mask = max_int(bits);
    (a + b) & mask
}

/// Performs modular subtraction of two BigUint values with the given bit width
pub(crate) fn modular_sub(a: &BigUint, b: &BigUint, bits: u32) -> BigUint {
    let modulus = BigUint::one() << bits;
    if a >= b {
        (a - b) & max_int(bits)
    } else {
        (modulus + a - b) & max_int(bits)
    }
}

/// Performs modular multiplication of two BigUint values with the given bit width
pub(crate) fn modular_mul(a: &BigUint, b: &BigUint, bits: u32) -> BigUint {
    (a * b) & max_int(bits)
}

/// Compute the greatest common divisor of two BigUint values
pub(crate) fn gcd(a: &BigUint, b: &BigUint) -> BigUint {
    if a.is_zero() && b.is_zero() {
        BigUint::one()
    } else if b.is_zero() {
        a.clone()
    } else {
        gcd(b, &(a % b))
    }
}

/// Warren's min_or algorithm - computes minimum possible value of OR operation
pub(crate) fn min_or(a: &BigUint, b: &BigUint, c: &BigUint, d: &BigUint, bits: u32) -> BigUint {
    let mut a = a.clone();
    let mut c = c.clone();
    let mut m = BigUint::one() << (bits - 1);
    let max_val = (BigUint::one() << bits) - 1u32;

    while !m.is_zero() {
        // (~a) & c & m != 0
        if ((&max_val ^ &a) & &c & &m) != BigUint::zero() {
            // temp = (a | m) & -m
            let temp = (&a | &m) & ((&max_val ^ &m) + 1u32);
            if temp <= *b {
                a = temp;
                break;
            }
        } else if ((&a) & (&max_val ^ &c) & &m) != BigUint::zero() {
            // temp = (c | m) & -m
            let temp = (&c | &m) & ((&max_val ^ &m) + 1u32);
            if temp <= *d {
                c = temp;
                break;
            }
        }
        m >>= 1;
    }

    a | c
}

/// Warren's max_or algorithm - computes maximum possible value of OR operation
pub(crate) fn max_or(a: &BigUint, b: &BigUint, c: &BigUint, d: &BigUint, bits: u32) -> BigUint {
    let mut b = b.clone();
    let mut d = d.clone();
    let mut m = BigUint::one() << (bits - 1);

    while !m.is_zero() {
        if (&b & &d & &m) != BigUint::zero() {
            let temp = (&b - &m) | (&m - 1u32);
            if temp >= *a {
                b = temp;
                break;
            }
            let temp = (&d - &m) | (&m - 1u32);
            if temp >= *c {
                d = temp;
                break;
            }
        }
        m >>= 1;
    }

    b | d
}

/// Warren's min_and algorithm - computes minimum possible value of AND operation
pub(crate) fn min_and(a: &BigUint, b: &BigUint, c: &BigUint, d: &BigUint, bits: u32) -> BigUint {
    let mut a = a.clone();
    let mut c = c.clone();
    let mut m = BigUint::one() << (bits - 1);
    let max_val = (BigUint::one() << bits) - 1u32;

    while !m.is_zero() {
        // (~a) & (~c) & m != 0
        if ((&max_val ^ &a) & (&max_val ^ &c) & &m) != BigUint::zero() {
            // temp = (a | m) & -m
            let temp = (&a | &m) & ((&max_val ^ &m) + 1u32);
            if temp <= *b {
                a = temp;
                break;
            }
            let temp = (&c | &m) & ((&max_val ^ &m) + 1u32);
            if temp <= *d {
                c = temp;
                break;
            }
        }
        m >>= 1;
    }

    a & c
}

/// Warren's max_and algorithm - computes maximum possible value of AND operation
pub(crate) fn max_and(a: &BigUint, b: &BigUint, c: &BigUint, d: &BigUint, bits: u32) -> BigUint {
    let mut b = b.clone();
    let mut d = d.clone();
    let mut m = BigUint::one() << (bits - 1);
    let max_val = (BigUint::one() << bits) - 1u32;

    while !m.is_zero() {
        // (~d) & b & m != 0
        if ((&max_val ^ &d) & &b & &m) != BigUint::zero() {
            // temp = (b & ~m) | (m - 1)
            let temp = (&b & (&max_val ^ &m)) | (&m - 1u32);
            if temp >= *a {
                b = temp;
                break;
            }
        } else if (&d & (&max_val ^ &b) & &m) != BigUint::zero() {
            // temp = (d & ~m) | (m - 1)
            let temp = (&d & (&max_val ^ &m)) | (&m - 1u32);
            if temp >= *c {
                d = temp;
                break;
            }
        }
        m >>= 1;
    }

    b & d
}

/// Compute minimum XOR value for ranges [a, b] and [c, d]
/// Simplified approach: try all corner combinations
pub(crate) fn min_xor(a: &BigUint, b: &BigUint, c: &BigUint, d: &BigUint, _bits: u32) -> BigUint {
    // For XOR, the minimum comes from one of the corners
    let candidates = vec![a ^ c, a ^ d, b ^ c, b ^ d];

    candidates.into_iter().min().unwrap()
}

/// Compute maximum XOR value for ranges [a, b] and [c, d]
/// Simplified approach: try all corner combinations
pub(crate) fn max_xor(a: &BigUint, b: &BigUint, c: &BigUint, d: &BigUint, _bits: u32) -> BigUint {
    // For XOR, the maximum comes from one of the corners
    let candidates = vec![a ^ c, a ^ d, b ^ c, b ^ d];

    candidates.into_iter().max().unwrap()
}

/// Helper to convert unsigned BigUint to signed BigInt
pub(crate) fn to_signed(v: &BigUint, bits: u32) -> BigInt {
    let msb_mask = BigUint::one() << (bits - 1);
    if (v & &msb_mask) != BigUint::zero() {
        v.to_bigint().unwrap() - (BigInt::one() << bits)
    } else {
        v.to_bigint().unwrap()
    }
}

/// Helper to convert signed BigInt to unsigned BigUint
pub(crate) fn to_unsigned(v: &BigInt, bits: u32) -> BigUint {
    let modulus = BigUint::one() << bits;
    let magnitude = v.magnitude() % &modulus;
    if v.is_negative() && !magnitude.is_zero() {
        modulus - magnitude
    } else {
        magnitude
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_to_unsigned_beyond_the_width() {
        // wrapped_signed_mul multiplies two signed bounds, so it can reach here
        // with a product whose magnitude exceeds 2**bits. Adding the modulus
        // once only reaches down to -2**bits. Below that the sum stayed
        // negative unless 2**bits divided the value exactly, % truncates toward
        // zero rather than flooring, and to_biguint answers None on a negative
        // value: the first and third of these panicked, the other two did not.
        assert_eq!(to_unsigned(&BigInt::from(-16002), 8), BigUint::from(126u32));
        assert_eq!(to_unsigned(&BigInt::from(-256), 8), BigUint::zero());
        assert_eq!(to_unsigned(&BigInt::from(-257), 8), BigUint::from(255u32));
        assert_eq!(to_unsigned(&BigInt::from(-16384), 8), BigUint::zero());
    }

    #[test]
    fn test_to_unsigned_within_the_width() {
        assert_eq!(to_unsigned(&BigInt::from(0), 8), BigUint::zero());
        assert_eq!(to_unsigned(&BigInt::from(127), 8), BigUint::from(127u32));
        assert_eq!(to_unsigned(&BigInt::from(-1), 8), BigUint::from(255u32));
        assert_eq!(to_unsigned(&BigInt::from(-128), 8), BigUint::from(128u32));

        // sdiv passes -2**(bits-1) / -1 here, which is out of signed range, and
        // relies on the reduction to give the two's-complement answer.
        assert_eq!(to_unsigned(&BigInt::from(128), 8), BigUint::from(128u32));
    }

    #[test]
    fn test_to_unsigned_inverts_to_signed() {
        for value in 0u32..256 {
            let unsigned = BigUint::from(value);
            assert_eq!(to_unsigned(&to_signed(&unsigned, 8), 8), unsigned);
        }
    }
}
