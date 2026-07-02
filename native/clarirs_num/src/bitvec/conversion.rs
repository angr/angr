use num_bigint::{BigInt, BigUint, Sign};
use num_traits::{Num, Zero};
use smallvec::SmallVec;

use super::{BitVec, BitVecError};

impl From<(u64, u32)> for BitVec {
    /// Builds a `BitVec` of `length` bits from `value`, truncating to the low
    /// `length` bits.
    fn from((value, length): (u64, u32)) -> Self {
        // Truncate the value to fit within the given length.
        let truncated_value = if length < 64 {
            value & ((1u64 << length) - 1)
        } else {
            value
        };

        let mut words = SmallVec::new();
        words.push(truncated_value);
        BitVec::new(words, length).expect("BitVec::new is infallible")
    }
}

impl From<(BigUint, u32)> for BitVec {
    /// Builds a `BitVec` of `length` bits from `value`, truncating to the low
    /// `length` bits.
    fn from((value, length): (BigUint, u32)) -> Self {
        let truncated = if value.bits() as u32 > length {
            value % (BigUint::from(1u8) << length)
        } else {
            value
        };

        // A zero value yields an empty digit list, which `new` pads out.
        let digits: SmallVec<[u64; 1]> = truncated.iter_u64_digits().collect();
        BitVec::new(digits, length).expect("BitVec::new is infallible")
    }
}

impl From<(BigInt, u32)> for BitVec {
    /// Builds a `BitVec` of `length` bits from a signed `value`, using two's
    /// complement and truncating to `length` bits.
    fn from((value, length): (BigInt, u32)) -> Self {
        let big_uint = if value.sign() == Sign::Minus {
            // For negative values, compute 2's complement: 2^length - (|value| % 2^length)
            let modulus = BigUint::from(1u8) << length;
            let truncated_magnitude = value.magnitude() % &modulus;
            if truncated_magnitude.is_zero() {
                BigUint::zero()
            } else {
                &modulus - truncated_magnitude
            }
        } else {
            // For positive values, truncate the magnitude
            value.magnitude() % (BigUint::from(1u8) << length)
        };
        BitVec::from((big_uint, length))
    }
}

impl TryFrom<(String, u32)> for BitVec {
    type Error = BitVecError;

    /// Parses a base-10 string into a `BitVec` of `length` bits.
    fn try_from((s, length): (String, u32)) -> Result<Self, Self::Error> {
        let value = BigUint::from_str_radix(&s, 10).map_err(|_| BitVecError::ConversionError)?;
        Ok(BitVec::from((value, length)))
    }
}

impl From<BitVec> for BigUint {
    fn from(bv: BitVec) -> Self {
        bv.to_biguint()
    }
}

impl From<&BitVec> for BigUint {
    fn from(bv: &BitVec) -> Self {
        bv.to_biguint()
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use num_traits::Zero;

    #[test]
    fn test_to_biguint() {
        use num_bigint::BigUint;
        use num_traits::One;

        // Test conversion of zero
        let bv = BitVec::zeros(64);
        assert_eq!(bv.to_biguint(), BigUint::zero());

        // Test various positive values
        let bv = BitVec::from((42, 64));
        assert_eq!(bv.to_biguint(), BigUint::from(42u64));

        // Test different widths
        let bv = BitVec::from((0xFF, 8));
        assert_eq!(bv.to_biguint(), BigUint::from(0xFFu64));

        let bv = BitVec::from((0xFFFF, 16));
        assert_eq!(bv.to_biguint(), BigUint::from(0xFFFFu64));

        // Test maximum value for width
        let bv = BitVec::from((u32::MAX as u64, 32));
        assert_eq!(bv.to_biguint(), BigUint::from(u32::MAX));

        // Test odd-sized vectors (e.g., 17 bits)
        let value = BigUint::from(0x1FFFFu64); // 17 bits set
        let bv = BitVec::from((value.clone(), 17));
        assert_eq!(bv.to_biguint(), value);

        // Test single-bit vector
        let bv = BitVec::from((1, 1));
        assert_eq!(bv.to_biguint(), BigUint::one());

        // Test zero-width vector
        let bv = BitVec::zeros(0);
        assert_eq!(bv.to_biguint(), BigUint::zero());

        // Test 72-bit vector
        let value = (BigUint::one() << 72u32) - BigUint::one(); // 2^72 - 1
        let bv = BitVec::from((value.clone(), 72));
        assert_eq!(bv.to_biguint(), value);
    }

    #[test]
    fn test_from_biguint() {
        use num_bigint::BigUint;
        use num_traits::One;

        // Test conversion from zero
        let bv = BitVec::from((BigUint::zero(), 64));
        assert_eq!(bv.to_u64().unwrap(), 0);

        // Test various positive values
        let value = BigUint::from(42u64);
        let bv = BitVec::from((value, 64));
        assert_eq!(bv.to_u64().unwrap(), 42);

        // Test value truncation
        let value = BigUint::from(0xFFu64);
        let bv = BitVec::from((value, 4));
        assert_eq!(bv.to_u64().unwrap(), 0xF); // 0xFF truncated to 4 bits = 0xF

        // Test explicit truncation function
        let value = BigUint::from(0xFFu64);
        let bv = BitVec::from((value, 4));
        assert_eq!(bv.to_u64().unwrap() & 0xF, 0xF); // Only compare the lowest 4 bits

        // Test different widths
        let value = BigUint::from(0xFFu64);
        let bv = BitVec::from((value, 8));
        assert_eq!(bv.to_u64().unwrap(), 0xFF);

        // Test odd-sized vectors
        let value = BigUint::from(0x1Fu64); // 5 bits
        let bv = BitVec::from((value, 5));
        assert_eq!(bv.to_u64().unwrap(), 0x1F);

        // Test single-bit vector
        let bv = BitVec::from((BigUint::one(), 1));
        assert_eq!(bv.to_u64().unwrap(), 1);

        // Test zero-width vector
        let bv = BitVec::from((BigUint::zero(), 0));
        assert_eq!(bv.len(), 0);
    }

    #[test]
    fn test_to_u64() {
        // Test conversion of zero
        let bv = BitVec::zeros(64);
        assert_eq!(bv.to_u64().unwrap(), 0);

        // Test conversion of various values
        let bv = BitVec::from((42, 64));
        assert_eq!(bv.to_u64().unwrap(), 42);

        // Test width > 64 (should error)
        let bv = BitVec::zeros(65);
        assert!(bv.to_u64().is_none());

        // Test different widths
        let bv = BitVec::from((0xFF, 8));
        assert_eq!(bv.to_u64().unwrap(), 0xFF);

        let bv = BitVec::from((0xFFFF, 16));
        assert_eq!(bv.to_u64().unwrap(), 0xFFFF);

        // Test maximum value for width
        let bv = BitVec::from((u32::MAX as u64, 32));
        assert_eq!(bv.to_u64().unwrap(), u32::MAX as u64);

        // Test odd-sized vectors
        let bv = BitVec::from((0x1F, 5)); // 5 bits
        assert_eq!(bv.to_u64().unwrap(), 0x1F);

        // Test single-bit vector
        let bv = BitVec::from((1, 1));
        assert_eq!(bv.to_u64().unwrap(), 1);
    }

    #[test]
    fn test_to_usize() {
        // Test conversion of zero
        let bv = BitVec::zeros(usize::BITS);
        assert_eq!(bv.to_usize().unwrap(), 0);

        // Test conversion of various values
        let bv = BitVec::from((42, 64));
        assert_eq!(bv.to_usize().unwrap(), 42);

        // Test width > usize::BITS (should error)
        let bv = BitVec::zeros(usize::BITS + 1);
        assert!(bv.to_usize().is_none());

        // Test different widths
        let bv = BitVec::from((0xFF, 8));
        assert_eq!(bv.to_usize().unwrap(), 0xFF);

        let bv = BitVec::from((0xFFFF, 16));
        assert_eq!(bv.to_usize().unwrap(), 0xFFFF);

        // Test maximum value for width
        let max_32bit = BitVec::from((u32::MAX as u64, 32));
        if usize::BITS >= 32 {
            assert_eq!(max_32bit.to_usize().unwrap(), u32::MAX as usize);
        } else {
            assert!(max_32bit.to_usize().is_none());
        }

        // Test odd-sized vectors
        let bv = BitVec::from((0x1F, 5)); // 5 bits
        assert_eq!(bv.to_usize().unwrap(), 0x1F);

        // Test single-bit vector
        let bv = BitVec::from((1, 1));
        assert_eq!(bv.to_usize().unwrap(), 1);
    }

    #[test]
    fn test_from_u8() {
        let bv = BitVec::from((42, 8));
        assert_eq!(bv.len(), 8);
        assert_eq!(bv.to_u64().unwrap(), 42);

        let bv = BitVec::from((0, 8));
        assert_eq!(bv.len(), 8);
        assert_eq!(bv.to_u64().unwrap(), 0);

        let bv = BitVec::from((255, 8));
        assert_eq!(bv.len(), 8);
        assert_eq!(bv.to_u64().unwrap(), 255);
    }

    #[test]
    fn test_from_u16() {
        let bv = BitVec::from((4242, 16));
        assert_eq!(bv.len(), 16);
        assert_eq!(bv.to_u64().unwrap(), 4242);

        let bv = BitVec::from((0, 16));
        assert_eq!(bv.len(), 16);
        assert_eq!(bv.to_u64().unwrap(), 0);

        let bv = BitVec::from((u16::MAX as u64, 16));
        assert_eq!(bv.len(), 16);
        assert_eq!(bv.to_u64().unwrap(), u16::MAX as u64);
    }

    #[test]
    fn test_from_u32() {
        let bv = BitVec::from((424242, 32));
        assert_eq!(bv.len(), 32);
        assert_eq!(bv.to_u64().unwrap(), 424242);

        let bv = BitVec::from((0, 32));
        assert_eq!(bv.len(), 32);
        assert_eq!(bv.to_u64().unwrap(), 0);

        let bv = BitVec::from((u32::MAX as u64, 32));
        assert_eq!(bv.len(), 32);
        assert_eq!(bv.to_u64().unwrap(), u32::MAX as u64);
    }

    #[test]
    fn test_from_u64() {
        let bv = BitVec::from((42424242, 64));
        assert_eq!(bv.len(), 64);
        assert_eq!(bv.to_u64().unwrap(), 42424242);

        let bv = BitVec::from((0, 64));
        assert_eq!(bv.len(), 64);
        assert_eq!(bv.to_u64().unwrap(), 0);

        let bv = BitVec::from((u64::MAX as u64, 64));
        assert_eq!(bv.len(), 64);
        assert_eq!(bv.to_u64().unwrap(), u64::MAX);
    }

    #[test]
    fn test_from_u128() {
        let bv = BitVec::from((BigUint::from(4242424242424242u128), 128));
        assert_eq!(bv.len(), 128);
        assert!(bv.to_u64().is_none()); // Too large for u64
        assert_eq!(
            bv.to_biguint(),
            num_bigint::BigUint::from(4242424242424242u128)
        );

        let bv = BitVec::from((BigUint::from(0u128), 128));
        assert_eq!(bv.len(), 128);
        assert!(bv.to_u64().is_none()); // Even 0 should return None for 128-bit vectors

        let bv = BitVec::from((BigUint::from(u128::MAX), 128));
        assert_eq!(bv.len(), 128);
        assert!(bv.to_u64().is_none());
        assert_eq!(bv.to_biguint(), num_bigint::BigUint::from(u128::MAX));
    }

    #[test]
    fn test_from_i8() {
        let bv = BitVec::from((42i8 as u64, 8));
        assert_eq!(bv.len(), 8);
        assert_eq!(bv.to_u64().unwrap(), 42);

        let bv = BitVec::from((0i8 as u64, 8));
        assert_eq!(bv.len(), 8);
        assert_eq!(bv.to_u64().unwrap(), 0);

        let bv = BitVec::from((-42i8 as u64, 8));
        assert_eq!(bv.len(), 8);
        assert_eq!(bv.to_u64().unwrap() & 0xFF, 214u64); // -42i8 as u8 = 214, mask to 8 bits

        let bv = BitVec::from((-1i8 as u64, 8));
        assert_eq!(bv.len(), 8);
        assert_eq!(bv.to_u64().unwrap(), 255);
    }

    #[test]
    fn test_from_i16() {
        let bv = BitVec::from((4242i16 as u64, 16));
        assert_eq!(bv.len(), 16);
        assert_eq!(bv.to_u64().unwrap(), 4242);

        let bv = BitVec::from((-4242i16 as u64, 16));
        assert_eq!(bv.len(), 16);
        assert_eq!(bv.to_u64().unwrap() & 0xFFFF, 61294u64); // -4242i16 as u16 = 61294, mask to 16 bits
    }

    #[test]
    fn test_from_i32() {
        let bv = BitVec::from((424242i32 as u64, 32));
        assert_eq!(bv.len(), 32);
        assert_eq!(bv.to_u64().unwrap(), 424242);

        let bv = BitVec::from((-424242i32 as u64, 32));
        assert_eq!(bv.len(), 32);
        assert_eq!(bv.to_u64().unwrap() & 0xFFFFFFFF, 4294543054u64); // -424242i32 as u32 = 4294543054, mask to 32 bits
    }

    #[test]
    fn test_from_i64() {
        let bv = BitVec::from((42424242i64 as u64, 64));
        assert_eq!(bv.len(), 64);
        assert_eq!(bv.to_u64().unwrap(), 42424242);

        let bv = BitVec::from((-42424242i64 as u64, 64));
        assert_eq!(bv.len(), 64);
        assert_eq!(bv.to_u64().unwrap(), (-42424242i64) as u64);
    }

    #[test]
    fn test_from_i128() {
        let bv = BitVec::from((BigInt::from(4242424242424242i128), 128));
        assert_eq!(bv.len(), 128);
        assert!(bv.to_u64().is_none()); // Too large for u64
        assert_eq!(
            bv.to_biguint(),
            num_bigint::BigUint::from(4242424242424242u128)
        );

        let bv = BitVec::from((BigInt::from(-4242424242424242i128), 128));
        assert_eq!(bv.len(), 128);
        assert!(bv.to_u64().is_none());
        assert_eq!(
            bv.to_biguint(),
            num_bigint::BigUint::from((-4242424242424242i128) as u128)
        );
    }
}
