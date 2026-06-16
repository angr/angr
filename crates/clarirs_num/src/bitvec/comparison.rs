use super::{BitVec, BitVecError};

impl PartialOrd for BitVec {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for BitVec {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.words
            .iter()
            .zip(other.words.iter())
            .rev()
            .find_map(|(l, r)| match l.cmp(r) {
                std::cmp::Ordering::Equal => None,
                ord => Some(ord),
            })
            .unwrap_or(std::cmp::Ordering::Equal)
    }
}

impl BitVec {
    pub fn signed_lt(&self, other: &Self) -> Result<bool, BitVecError> {
        self.check_same_length(other)?;

        // Different signs
        Ok(match (self.sign(), other.sign()) {
            (true, false) => true,  // Negative < Positive
            (false, true) => false, // Positive > Negative
            // Same sign: the two's-complement bit patterns order the same way as
            // the values do, so unsigned comparison (Ord::cmp) gives the answer.
            _ => self.cmp(other) == std::cmp::Ordering::Less,
        })
    }

    pub fn signed_le(&self, other: &Self) -> Result<bool, BitVecError> {
        Ok(self.signed_lt(other)? || self == other)
    }

    pub fn signed_gt(&self, other: &Self) -> Result<bool, BitVecError> {
        Ok(!self.signed_le(other)?)
    }

    pub fn signed_ge(&self, other: &Self) -> Result<bool, BitVecError> {
        Ok(!self.signed_lt(other)?)
    }
}

#[cfg(test)]
mod tests {
    use crate::bitvec::BitVec;
    use crate::bitvec::BitVecError;

    #[test]
    fn test_unsigned_comparison() -> Result<(), BitVecError> {
        // Test basic ordering
        let bv1 = BitVec::from_prim_with_size(5u8, 8)?;
        let bv2 = BitVec::from_prim_with_size(10u8, 8)?;
        assert!(bv1 < bv2);
        assert!(bv1 <= bv2);
        assert!(bv2 > bv1);
        assert!(bv2 >= bv1);

        // Test equality
        let bv3 = BitVec::from_prim_with_size(5u8, 8)?;
        assert!(bv1 == bv3);
        assert!(bv1 <= bv3);
        assert!(bv1 >= bv3);

        // Test with larger numbers
        let bv4 = BitVec::from_prim_with_size(0xFFFFu16, 16)?;
        let bv5 = BitVec::from_prim_with_size(0x0000u16, 16)?;
        assert!(bv4 > bv5);
        assert!(bv5 < bv4);

        Ok(())
    }

    #[test]
    fn test_unsigned_comparison_multi_word() -> Result<(), BitVecError> {
        // Test with 128-bit values where the difference is in the lower word
        let bv1 = BitVec::from_biguint(&1u32.into(), 128);
        let bv2 = BitVec::from_biguint(&2u32.into(), 128);
        assert!(bv1 < bv2, "1 < 2 in 128-bit should be true");
        assert!(bv2 > bv1, "2 > 1 in 128-bit should be true");
        assert!(bv1 != bv2, "1 != 2 in 128-bit");

        // Test with values that differ in the upper word
        let big1 = num_bigint::BigUint::from(1u64) << 64;
        let big2 = num_bigint::BigUint::from(2u64) << 64;
        let bv3 = BitVec::from_biguint(&big1, 128);
        let bv4 = BitVec::from_biguint(&big2, 128);
        assert!(bv3 < bv4, "1<<64 < 2<<64 in 128-bit should be true");
        assert!(bv4 > bv3, "2<<64 > 1<<64 in 128-bit should be true");

        Ok(())
    }

    #[test]
    fn test_signed_lt() -> Result<(), BitVecError> {
        // Test positive numbers (5 and 10 in 8-bit)
        let pos1 = BitVec::from_prim_with_size(0x05u8, 8)?;
        let pos2 = BitVec::from_prim_with_size(0x0Au8, 8)?;
        assert!(pos1.signed_lt(&pos2)?);
        assert!(!pos2.signed_lt(&pos1)?);

        // Test negative numbers (-5 = 0xFB and -10 = 0xF6 in 8-bit two's complement)
        // -10 < -5 because -10 is more negative (further from zero)
        let neg5 = BitVec::from_prim_with_size(0xFBu8, 8)?; // -5
        let neg10 = BitVec::from_prim_with_size(0xF6u8, 8)?; // -10
        assert!(neg10.signed_lt(&neg5)?); // -10 < -5
        assert!(!neg5.signed_lt(&neg10)?); // -5 NOT< -10

        // Test mixed signs (any negative < any positive)
        assert!(neg5.signed_lt(&pos1)?); // -5 < 5
        assert!(!pos1.signed_lt(&neg5)?); // 5 NOT< -5

        // Test equality
        let pos1_dup = BitVec::from_prim_with_size(0x05u8, 8)?;
        assert!(!pos1.signed_lt(&pos1_dup)?);
        assert!(!pos1_dup.signed_lt(&pos1)?);

        Ok(())
    }

    #[test]
    fn test_signed_le() -> Result<(), BitVecError> {
        // Test positive numbers (5 and 10 in 8-bit)
        let pos1 = BitVec::from_prim_with_size(0x05u8, 8)?;
        let pos2 = BitVec::from_prim_with_size(0x0Au8, 8)?;
        assert!(pos1.signed_le(&pos2)?);
        assert!(!pos2.signed_le(&pos1)?);

        // Test negative numbers (-5 = 0xFB and -10 = 0xF6 in 8-bit two's complement)
        let neg5 = BitVec::from_prim_with_size(0xFBu8, 8)?; // -5
        let neg10 = BitVec::from_prim_with_size(0xF6u8, 8)?; // -10
        assert!(neg10.signed_le(&neg5)?); // -10 <= -5
        assert!(!neg5.signed_le(&neg10)?); // -5 NOT<= -10

        // Test equality
        let pos1_dup = BitVec::from_prim_with_size(0x05u8, 8)?;
        assert!(pos1.signed_le(&pos1_dup)?);
        assert!(pos1_dup.signed_le(&pos1)?);

        Ok(())
    }

    #[test]
    fn test_signed_gt() -> Result<(), BitVecError> {
        // Test positive numbers (5 and 10 in 8-bit)
        let pos1 = BitVec::from_prim_with_size(0x05u8, 8)?;
        let pos2 = BitVec::from_prim_with_size(0x0Au8, 8)?;
        assert!(!pos1.signed_gt(&pos2)?);
        assert!(pos2.signed_gt(&pos1)?);

        // Test negative numbers (-5 = 0xFB and -10 = 0xF6 in 8-bit two's complement)
        let neg5 = BitVec::from_prim_with_size(0xFBu8, 8)?; // -5
        let neg10 = BitVec::from_prim_with_size(0xF6u8, 8)?; // -10
        assert!(neg5.signed_gt(&neg10)?); // -5 > -10
        assert!(!neg10.signed_gt(&neg5)?); // -10 NOT> -5

        // Test mixed signs
        assert!(pos1.signed_gt(&neg5)?); // 5 > -5
        assert!(!neg5.signed_gt(&pos1)?); // -5 NOT> 5

        // Test equality
        let pos1_dup = BitVec::from_prim_with_size(0x05u8, 8)?;
        assert!(!pos1.signed_gt(&pos1_dup)?);
        assert!(!pos1_dup.signed_gt(&pos1)?);

        Ok(())
    }

    #[test]
    fn test_signed_ge() -> Result<(), BitVecError> {
        // Test positive numbers (5 and 10 in 8-bit)
        let pos1 = BitVec::from_prim_with_size(0x05u8, 8)?;
        let pos2 = BitVec::from_prim_with_size(0x0Au8, 8)?;
        assert!(!pos1.signed_ge(&pos2)?);
        assert!(pos2.signed_ge(&pos1)?);

        // Test negative numbers (-5 = 0xFB and -10 = 0xF6 in 8-bit two's complement)
        let neg5 = BitVec::from_prim_with_size(0xFBu8, 8)?; // -5
        let neg10 = BitVec::from_prim_with_size(0xF6u8, 8)?; // -10
        assert!(neg5.signed_ge(&neg10)?); // -5 >= -10
        assert!(!neg10.signed_ge(&neg5)?); // -10 NOT>= -5

        // Test equality
        let pos1_dup = BitVec::from_prim_with_size(0x05u8, 8)?;
        assert!(pos1.signed_ge(&pos1_dup)?);
        assert!(pos1_dup.signed_ge(&pos1)?);

        Ok(())
    }

    #[test]
    fn test_signed_comparison_different_lengths() {
        let bv1 = BitVec::from_prim_with_size(0x05u8, 8).unwrap();
        let bv2 = BitVec::from_prim_with_size(0x0005u16, 16).unwrap();
        assert!(matches!(
            bv1.signed_lt(&bv2),
            Err(BitVecError::MismatchedLengths { left: 8, right: 16 })
        ));
    }
}
