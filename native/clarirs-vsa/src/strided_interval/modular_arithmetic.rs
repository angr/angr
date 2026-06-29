use num_bigint::{BigInt, BigUint, ToBigInt};
use num_traits::{One, Zero};

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
    if v < &BigInt::zero() {
        let modulus = BigInt::one() << bits;
        let result = (modulus + v) % (BigInt::one() << bits);
        result.to_biguint().unwrap()
    } else {
        v.to_biguint().unwrap() & max_int(bits)
    }
}
