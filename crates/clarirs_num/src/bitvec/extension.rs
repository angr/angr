use num_bigint::BigUint;
use num_traits::Zero;

use super::BitVec;
use super::BitVecError;

impl BitVec {
    /// Extracts a subvector from the current vector. Range bounds are (from,
    /// to), where both are inclusive. The extracted vector will have a length
    /// of (to - from + 1).
    pub fn extract(&self, from: u32, to: u32) -> Result<Self, BitVecError> {
        if from > to || to >= self.len() {
            return Err(BitVecError::InvalidExtractBounds {
                upper: to, // Convert to inclusive for smtlib-style extract
                lower: from,
                length: self.len(),
            });
        }

        let extract_len = to - from + 1;
        let mut result = BitVec::zeros(extract_len);

        let mut remaining_bits = extract_len;
        let mut src_word_idx = (from / 64) as usize;
        let mut src_bit_idx = (from % 64) as usize;
        let mut dst_bit_idx = 0usize;

        while remaining_bits > 0 {
            // How many bits we can copy in this iteration
            let bits_this_round = std::cmp::min(
                remaining_bits as usize, // How many bits we still need
                std::cmp::min(64 - src_bit_idx, 64 - (dst_bit_idx % 64)), // Space left in current word
            );

            // Extract bits from source word
            // Handle the case where bits_this_round == 64 to avoid undefined behavior
            let bits = if bits_this_round == 64 && src_bit_idx == 0 {
                // Extract the entire word
                self.words[src_word_idx]
            } else {
                let mask = ((1u64 << bits_this_round) - 1) << src_bit_idx;
                (self.words[src_word_idx] & mask) >> src_bit_idx
            };

            // Insert bits into destination word
            let dst_word_idx = dst_bit_idx / 64;
            let dst_shift = dst_bit_idx % 64;
            result.words[dst_word_idx] |= bits << dst_shift;

            // Update indices
            remaining_bits -= bits_this_round as u32;
            src_bit_idx += bits_this_round;
            if src_bit_idx >= 64 {
                src_word_idx += 1;
                src_bit_idx = 0;
            }
            dst_bit_idx += bits_this_round;
        }

        Ok(result)
    }

    pub fn concat(&self, other: &Self) -> Result<BitVec, BitVecError> {
        let mut new_bv = other.words.clone();
        let shift = other.length % 64;

        if shift == 0 {
            // Words are perfectly aligned, just extend
            new_bv.extend(self.words.iter().copied());
        } else {
            // Handle unaligned case

            // Combine the words with appropriate shifting
            for (i, &word) in self.words.iter().enumerate() {
                if i == 0 {
                    // First word needs to be merged with the last word of self
                    if let Some(last) = new_bv.last_mut() {
                        *last |= word << shift;
                    }
                    // Push the remaining bits to the next word
                    new_bv.push(word >> (64 - shift));
                } else {
                    // Subsequent words need to be split across two words
                    if let Some(last) = new_bv.last_mut() {
                        *last |= word << shift;
                        new_bv.push(word >> (64 - shift));
                    }
                }
            }

            // Check if we have an extra word
            let expected_words = (self.len() + other.len()).div_ceil(64) as usize;
            if new_bv.len() > expected_words {
                new_bv.pop();
            }
        }

        BitVec::new(new_bv, self.length + other.length)
    }

    pub fn zero_extend(&self, additional_bits: u32) -> Result<BitVec, BitVecError> {
        BitVec::from_prim_with_size(0u8, additional_bits)?.concat(self)
    }

    pub fn sign_extend(&self, additional_bits: u32) -> Result<BitVec, BitVecError> {
        let extension = if self.sign() {
            BitVec::from_biguint(
                &((BigUint::from(1u8) << additional_bits) - 1u8),
                additional_bits,
            )
        } else {
            BitVec::from_biguint(&BigUint::zero(), additional_bits)
        };
        extension.concat(self)
    }
}

#[cfg(test)]
mod tests {
    use crate::bitvec::BitVec;
    use crate::bitvec::BitVecError;

    #[test]
    fn test_concat() -> Result<(), BitVecError> {
        // Test basic concatenation
        let bv1 = BitVec::from_prim_with_size(0b1100u8, 4)?;
        let bv2 = BitVec::from_prim_with_size(0b1010u8, 4)?;
        let result = (bv1.concat(&bv2))?;
        assert_eq!(result.to_u64().unwrap(), 0b11001010);
        assert_eq!(result.len(), 8);

        // Test concatenation with zero
        let bv1 = BitVec::from_prim_with_size(0b1111u8, 4)?;
        let bv2 = BitVec::from_prim_with_size(0b0000u8, 4)?;
        let result = (bv1.concat(&bv2))?;
        assert_eq!(result.to_u64().unwrap(), 0b11110000);

        // Test concatenation of different widths
        let bv1 = BitVec::from_prim_with_size(0b111u8, 3)?;
        let bv2 = BitVec::from_prim_with_size(0b10u8, 2)?;
        let result = (bv1.concat(&bv2))?;
        assert_eq!(result.to_u64().unwrap(), 0b11110);
        assert_eq!(result.len(), 5);

        // Test concatenation of single-bit vectors
        let bv1 = BitVec::from_prim_with_size(1u8, 1)?;
        let bv2 = BitVec::from_prim_with_size(0u8, 1)?;
        let result = (bv1.concat(&bv2))?;
        assert_eq!(result.to_u64().unwrap(), 0b10);
        assert_eq!(result.len(), 2);

        // Test concatenation of odd-sized vectors
        let bv1 = BitVec::from_prim_with_size(0b10101u8, 5)?;
        let bv2 = BitVec::from_prim_with_size(0b111u8, 3)?;
        let result = (bv1.concat(&bv2))?;
        assert_eq!(result.to_u64().unwrap(), 0b10101111);
        assert_eq!(result.len(), 8);

        // Test concatenation producing 72-bit vectors
        let bv1 = BitVec::from_prim_with_size(u64::MAX, 64)?;
        let bv2 = BitVec::from_prim_with_size(0b11111111u8, 8)?;
        let result = (bv1.concat(&bv2))?;
        assert_eq!(result.len(), 72);

        Ok(())
    }

    #[test]
    fn test_extract() -> Result<(), BitVecError> {
        // Test basic extraction
        let bv = BitVec::from_prim_with_size(0b11001010u8, 8)?;
        let result = bv.extract(2, 5).unwrap();
        assert_eq!(result.to_u64().unwrap(), 0b0010);
        assert_eq!(result.len(), 4);

        // Test extraction of entire vector
        let bv = BitVec::from_prim_with_size(0b1111u8, 4)?;
        let result = bv.extract(0, 3).unwrap();
        assert_eq!(result.to_u64().unwrap() & 0b1111, 0b1111); // Mask to 4 bits
        assert_eq!(result.len(), 4);

        // Test extraction of single bit
        let bv = BitVec::from_prim_with_size(0b1010u8, 4)?;
        let result = bv.extract(1, 1).unwrap();
        assert_eq!(result.to_u64().unwrap(), 0b1);
        assert_eq!(result.len(), 1);

        // Test extraction with invalid range (should error)
        let bv = BitVec::from_prim_with_size(0b1010u8, 4)?;
        assert!(bv.extract(2, 1).is_err()); // from > to
        assert!(bv.extract(0, 5).is_err()); // to > len

        // Test extraction from different widths
        let bv = BitVec::from_prim_with_size(0b110011u8, 6)?;
        let result = bv.extract(1, 4).unwrap();
        assert_eq!(result.to_u64().unwrap(), 0b1001);
        assert_eq!(result.len(), 4);

        // Test extraction from odd-sized vectors
        let bv = BitVec::from_prim_with_size(0b10101u8, 5)?;
        let result = bv.extract(1, 3).unwrap();
        assert_eq!(result.to_u64().unwrap(), 0b010);
        assert_eq!(result.len(), 3);

        // Test extraction from 72-bit vectors
        let mut bv = BitVec::from_prim_with_size(u64::MAX, 64)?;
        bv = bv.concat(&(BitVec::from_prim_with_size(0b11111111u8, 8)?))?;
        let result = bv.extract(60, 67).unwrap();
        assert_eq!(result.to_u64().unwrap(), 0b11111111);
        assert_eq!(result.len(), 8);

        Ok(())
    }

    #[test]
    fn test_zero_extend() -> Result<(), BitVecError> {
        // Test extending positive number
        let bv = BitVec::from_prim_with_size(0b1010u8, 4)?;
        let result = bv.zero_extend(4)?;
        assert_eq!(result.to_u64().unwrap(), 0b00001010);
        assert_eq!(result.len(), 8);

        // Test extending zero
        let bv = BitVec::from_prim_with_size(0u8, 4)?;
        let result = bv.zero_extend(4)?;
        assert_eq!(result.to_u64().unwrap(), 0);
        assert_eq!(result.len(), 8);

        // Test extending to same width (no change)
        let bv = BitVec::from_prim_with_size(0b1010u8, 4)?;
        let result = bv.zero_extend(0)?;
        assert_eq!(result.to_u64().unwrap(), 0b1010);
        assert_eq!(result.len(), 4);

        // Test extending from odd-sized vector
        let bv = BitVec::from_prim_with_size(0b101u8, 3)?;
        let result = bv.zero_extend(5)?;
        assert_eq!(result.to_u64().unwrap(), 0b00000101);
        assert_eq!(result.len(), 8);

        // Test extending single-bit vector
        let bv = BitVec::from_prim_with_size(1u8, 1)?;
        let result = bv.zero_extend(7)?;
        assert_eq!(result.to_u64().unwrap(), 0b00000001);
        assert_eq!(result.len(), 8);

        // Test extending to 72-bit vectors
        let bv = BitVec::from_prim_with_size(0xFFFFFFFFu32, 32)?;
        let result = bv.zero_extend(40)?;
        assert_eq!(result.len(), 72);

        Ok(())
    }

    #[test]
    fn test_sign_extend() -> Result<(), BitVecError> {
        // Test extending positive number
        let bv = BitVec::from_prim_with_size(0b0010u8, 4)?;
        let result = bv.sign_extend(4)?;
        assert_eq!(result.to_u64().unwrap(), 0b00000010);
        assert_eq!(result.len(), 8);

        // Test extending negative number
        let bv = BitVec::from_prim_with_size(0b1010u8, 4)?;
        let result = bv.sign_extend(4)?;
        assert_eq!(result.to_u64().unwrap(), 0b11111010);
        assert_eq!(result.len(), 8);

        // Test extending zero
        let bv = BitVec::from_prim_with_size(0u8, 4)?;
        let result = bv.sign_extend(4)?;
        assert_eq!(result.to_u64().unwrap(), 0);
        assert_eq!(result.len(), 8);

        // Test extending to same width (no change)
        let bv = BitVec::from_prim_with_size(0b1010u8, 4)?;
        let result = bv.sign_extend(0)?;
        assert_eq!(result.to_u64().unwrap(), 0b1010);
        assert_eq!(result.len(), 4);

        // Test extending from odd-sized vector
        let bv = BitVec::from_prim_with_size(0b101u8, 3)?; // 101 is negative in 3 bits
        let result = bv.sign_extend(5)?;
        assert_eq!(result.to_u64().unwrap(), 0b11111101); // Sign extended to 8 bits
        assert_eq!(result.len(), 8);

        // Test extending single-bit vector
        let bv = BitVec::from_prim_with_size(1u8, 1)?;
        let result = bv.sign_extend(7)?;
        assert_eq!(result.to_u64().unwrap(), 0b11111111);
        assert_eq!(result.len(), 8);

        // Test extending to 72-bit vectors
        let bv = BitVec::from_prim_with_size(0xFFFFFFFFu32, 32)?;
        let result = bv.sign_extend(40)?;
        assert_eq!(result.len(), 72);

        Ok(())
    }
}
