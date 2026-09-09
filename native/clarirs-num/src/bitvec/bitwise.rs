use std::ops::{BitAnd, BitOr, BitXor, Not, Shl, Shr};

use num_bigint::BigUint;
use num_traits::One;

use super::{BitVec, BitVecError};

impl BitVec {
    /// Applies a per-word binary operation to two equal-length bitvectors.
    /// `new` re-canonicalizes the result (masking the final word).
    fn zip_words<F>(&self, rhs: &Self, op: F) -> Result<Self, BitVecError>
    where
        F: Fn(u64, u64) -> u64,
    {
        self.check_same_length(rhs)?;
        let words = self
            .words
            .iter()
            .zip(rhs.words.iter())
            .map(|(l, r)| op(*l, *r))
            .collect();
        BitVec::new(words, self.length)
    }
}

impl Not for BitVec {
    type Output = Result<Self, BitVecError>;

    fn not(self) -> Self::Output {
        // `new` masks the bits above `length` in the final word.
        let words = self.words.iter().map(|w| !w).collect();
        BitVec::new(words, self.length)
    }
}

impl BitAnd for BitVec {
    type Output = Result<Self, BitVecError>;

    fn bitand(self, rhs: Self) -> Self::Output {
        self.zip_words(&rhs, |l, r| l & r)
    }
}

impl BitOr for BitVec {
    type Output = Result<Self, BitVecError>;

    fn bitor(self, rhs: Self) -> Self::Output {
        self.zip_words(&rhs, |l, r| l | r)
    }
}

impl BitXor for BitVec {
    type Output = Result<Self, BitVecError>;

    fn bitxor(self, rhs: Self) -> Self::Output {
        self.zip_words(&rhs, |l, r| l ^ r)
    }
}

impl Shl<u32> for BitVec {
    type Output = Result<Self, BitVecError>;

    fn shl(self, rhs: u32) -> Self::Output {
        // Shifting by at least the width zeros out the whole vector.
        if rhs >= self.length {
            return Ok(BitVec::zeros(self.length));
        }
        // `from_biguint` truncates to `length`, discarding bits shifted past the top.
        Ok(BitVec::from((self.to_biguint() << rhs, self.length)))
    }
}

impl Shr<u32> for BitVec {
    type Output = Result<Self, BitVecError>;

    /// Logical shift right (zero-fill).
    fn shr(self, rhs: u32) -> Self::Output {
        if rhs >= self.length {
            return Ok(BitVec::zeros(self.length));
        }
        Ok(BitVec::from((self.to_biguint() >> rhs, self.length)))
    }
}

impl BitVec {
    fn rotate(&self, rotate_amount: u32, left: bool) -> Result<Self, BitVecError> {
        let bit_length = self.len();
        if bit_length == 0 {
            return Ok(self.clone());
        }
        let rotate = rotate_amount % bit_length;
        if rotate == 0 {
            return Ok(self.clone());
        }

        let value = self.to_biguint();
        let mask = (BigUint::one() << bit_length) - BigUint::one();
        let (left_amount, right_amount) = if left {
            (rotate, bit_length - rotate)
        } else {
            (bit_length - rotate, rotate)
        };

        let rotated = ((&value << left_amount) | (&value >> right_amount)) & &mask;
        Ok(BitVec::from((rotated, bit_length)))
    }

    pub fn rotate_left(&self, rotate_amount: u32) -> Result<Self, BitVecError> {
        self.rotate(rotate_amount, true)
    }

    pub fn rotate_right(&self, rotate_amount: u32) -> Result<Self, BitVecError> {
        self.rotate(rotate_amount, false)
    }
}

#[cfg(test)]
mod tests {
    use super::{BitVec, BitVecError};

    #[test]
    fn test_not() -> Result<(), BitVecError> {
        // Test 8-bit NOT
        let bv = BitVec::from((0b10101010, 8));
        let result = (!bv)?;
        assert_eq!(result.to_u64().unwrap(), 0b01010101);

        // Test with non-byte aligned length
        let bv = BitVec::from((0b101, 3));
        let result = (!bv)?;
        assert_eq!(result.to_u64().unwrap(), 0b010);

        // Test with multiple words
        let bv = BitVec::from((u64::MAX, 64));
        let result = (!bv)?;
        assert_eq!(result.to_u64().unwrap(), 0);

        Ok(())
    }

    #[test]
    fn test_neg() -> Result<(), BitVecError> {
        // Arithmatic negation
        let bv = BitVec::from((0b1010, 4));
        let result = (!bv)?;
        assert_eq!(result.to_u64().unwrap(), 0b0101);

        Ok(())
    }

    #[test]
    fn test_bitand() -> Result<(), BitVecError> {
        // Test basic AND operation
        let bv1 = BitVec::from((0b1100, 4));
        let bv2 = BitVec::from((0b1010, 4));
        let result = (bv1 & bv2)?;
        assert_eq!(result.to_u64().unwrap(), 0b1000);

        // Test with different patterns
        let bv1 = BitVec::from((0b11111111, 8));
        let bv2 = BitVec::from((0b10101010, 8));
        let result = (bv1 & bv2)?;
        assert_eq!(result.to_u64().unwrap(), 0b10101010);

        Ok(())
    }

    #[test]
    fn test_bitor() -> Result<(), BitVecError> {
        // Test basic OR operation
        let bv1 = BitVec::from((0b1100, 4));
        let bv2 = BitVec::from((0b1010, 4));
        let result = (bv1 | bv2)?;
        assert_eq!(result.to_u64().unwrap(), 0b1110);

        // Test with different patterns
        let bv1 = BitVec::from((0b11110000, 8));
        let bv2 = BitVec::from((0b00001111, 8));
        let result = (bv1 | bv2)?;
        assert_eq!(result.to_u64().unwrap(), 0b11111111);

        Ok(())
    }

    #[test]
    fn test_bitxor() -> Result<(), BitVecError> {
        // Test basic XOR operation
        let bv1 = BitVec::from((0b1100, 4));
        let bv2 = BitVec::from((0b1010, 4));
        let result = (bv1 ^ bv2)?;
        assert_eq!(result.to_u64().unwrap(), 0b0110);

        // Test with different patterns
        let bv1 = BitVec::from((0b11111111, 8));
        let bv2 = BitVec::from((0b10101010, 8));
        let result = (bv1 ^ bv2)?;
        assert_eq!(result.to_u64().unwrap(), 0b01010101);

        Ok(())
    }

    #[test]
    fn test_shl() -> Result<(), BitVecError> {
        // Test basic left shift
        let bv = BitVec::from((0b1010, 8));
        let result = (bv << 2)?;
        assert_eq!(result.to_u64().unwrap(), 0b101000);

        // Test shift with carry across word boundaries
        let bv = BitVec::from((0b1, 64));
        let result = (bv << 63)?;
        assert_eq!(result.to_u64().unwrap(), 1u64 << 63);

        // Test shift beyond bit length
        let bv = BitVec::from((0b1010, 8));
        let result = (bv << 4)?;
        assert_eq!(result.to_u64().unwrap(), 0b10100000);

        Ok(())
    }

    #[test]
    fn test_shr() -> Result<(), BitVecError> {
        // Test basic right shift
        let bv = BitVec::from((0b1010, 4));
        let result = (bv >> 2)?;
        assert_eq!(result.to_u64().unwrap(), 0b10);

        // Test shift with carry across word boundaries
        let bv = BitVec::from((1u64 << 63, 64));
        let result = (bv >> 63)?;
        assert_eq!(result.to_u64().unwrap(), 1);

        // Test shift that results in all zeros
        let bv = BitVec::from((0b1010, 4));
        let result = (bv >> 4)?;
        assert_eq!(result.to_u64().unwrap(), 0);

        Ok(())
    }

    #[test]
    fn test_rotate_left() -> Result<(), BitVecError> {
        // Test basic rotation
        let bv = BitVec::from((0b1010, 4));
        let result = bv.rotate_left(1).unwrap();
        assert_eq!(result.to_u64().unwrap(), 0b0101);

        // Test full rotation (should be same as original)
        let bv = BitVec::from((0b1010, 4));
        let result = bv.rotate_left(4).unwrap();
        assert_eq!(result.to_u64().unwrap(), 0b1010);

        // Test rotation with amount larger than length
        let bv = BitVec::from((0b1010, 4));
        let result = bv.rotate_left(5).unwrap(); // Same as rotating left by 1
        assert_eq!(result.to_u64().unwrap(), 0b0101);

        Ok(())
    }

    #[test]
    fn test_rotate_right() -> Result<(), BitVecError> {
        // Test basic rotation
        let bv = BitVec::from((0b1010, 4));
        let result = bv.rotate_right(1).unwrap();
        assert_eq!(result.to_u64().unwrap(), 0b0101);

        // Test full rotation (should be same as original)
        let bv = BitVec::from((0b1010, 4));
        let result = bv.rotate_right(4).unwrap();
        assert_eq!(result.to_u64().unwrap(), 0b1010);

        // Test rotation with amount larger than length
        let bv = BitVec::from((0b1010, 4));
        let result = bv.rotate_right(5).unwrap(); // Same as rotating right by 1
        assert_eq!(result.to_u64().unwrap(), 0b0101);

        Ok(())
    }
}
