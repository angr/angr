mod arithmetic;
mod bitwise;
mod comparison;
mod conversion;
mod extension;

#[cfg(test)]
mod reference_tests;
#[cfg(test)]
mod tests;

use std::fmt::Debug;

use num_bigint::{BigInt, BigUint};
use num_traits::cast::ToPrimitive;
use serde::{Deserialize, Serialize};
use smallvec::SmallVec;
use thiserror::Error;

use num_traits::One;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Error)]
pub enum BitVecError {
    #[error("BitVector not bite-sized: {length:?} is not a multiple of 8")]
    BitVectorNotByteSized { length: u32 },
    #[error(
        "Invalid bitvector extract bounds: {upper}:{lower} not valid for bitvector of length {length}"
    )]
    InvalidExtractBounds { upper: u32, lower: u32, length: u32 },
    #[error("Division by zero error")]
    DivisionByZero,
    #[error(" BitVector length {size} must be a multiple of {bits}.")]
    InvalidChopSize { size: u32, bits: u32 },
    #[error("Conversion error occurred.")]
    ConversionError,
    #[error("BitVector lengths must match: {left} != {right}")]
    MismatchedLengths { left: u32, right: u32 },
}

/// BitVec are represented as a SmallVec of usize, where each usize is a word of
/// the bitvector.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub struct BitVec {
    words: SmallVec<[u64; 1]>,
    length: u32,
}

impl BitVec {
    pub fn new(mut words: SmallVec<[u64; 1]>, length: u32) -> Result<Self, BitVecError> {
        // Canonicalize to exactly `expected_words` words: pad with zeros if too
        // few, drop any extras if too many. Keeping this the single point of
        // canonicalization means every constructor and operator that routes
        // through `new` gets a well-formed value, so the rest of the code can
        // rely on the invariant (no stray high words, final word masked).
        let expected_words = length.div_ceil(64) as usize;
        words.resize(expected_words, 0);

        // Clear any bits above `length` in the final word.
        if let Some(last) = words.last_mut() {
            *last &= Self::compute_final_word_mask(length);
        }

        debug_assert_eq!(words.len(), expected_words);
        Ok(Self { words, length })
    }

    fn compute_final_word_mask(length: u32) -> u64 {
        if length == 0 {
            0
        } else if length.is_multiple_of(64) {
            u64::MAX
        } else {
            (1u64 << (length % 64)) - 1
        }
    }

    fn final_word_mask(&self) -> u64 {
        Self::compute_final_word_mask(self.length)
    }

    /// Returns an error if `self` and `other` have different bit-widths. Binary
    /// operators require matching widths; this reports the mismatch through the
    /// `Result` type rather than panicking.
    fn check_same_length(&self, other: &Self) -> Result<(), BitVecError> {
        if self.length == other.length {
            Ok(())
        } else {
            Err(BitVecError::MismatchedLengths {
                left: self.length,
                right: other.length,
            })
        }
    }

    pub fn to_biguint(&self) -> BigUint {
        // Convert the BitVec to a BigUint
        // The internal representation of BitVec uses little-endian word order
        // (least significant word first)
        let mut result = BigUint::from(0u32);
        for (i, &word) in self.words.iter().enumerate() {
            // Shift each word by its position (64 bits per word)
            let word_value = BigUint::from(word);
            let shifted = word_value << (i * 64);
            result |= shifted;
        }
        result
    }

    pub fn to_bigint(&self) -> BigInt {
        let magnitude = BigInt::from(self.to_biguint());
        if self.sign() {
            // Two's complement: a value with the sign bit set represents
            // `unsigned_value - 2^length`.
            magnitude - (BigInt::from(1) << self.length)
        } else {
            magnitude
        }
    }

    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> u32 {
        self.length
    }

    pub fn sign(&self) -> bool {
        if self.length == 0 {
            return false;
        }

        let last_word_index = (self.length - 1) / 64;
        let bit_index = (self.length - 1) % 64;

        if let Some(word) = self.words.get(last_word_index as usize) {
            (word & (1u64 << bit_index)) != 0
        } else {
            false
        }
    }

    /// Reverses the *byte* order of the bitvector (the endianness swap behind
    /// claripy's `Reverse`).
    ///
    /// This is a byte-granular operation: it only works on byte-sized
    /// bitvectors. If `length` is not a multiple of 8 there are no whole bytes
    /// to reverse, so it returns [`BitVecError::BitVectorNotByteSized`] rather
    /// than guessing.
    pub fn reverse_bytes(&self) -> Result<Self, BitVecError> {
        if !self.length.is_multiple_of(8) {
            return Err(BitVecError::BitVectorNotByteSized {
                length: self.length,
            });
        }

        // Calculate total number of bytes the bit-vector occupies.
        let total_bytes = self.length as usize / 8;

        // 1. Extract the bytes of the bit-vector in little-endian order.
        // (Words store the low-order bytes first.)
        let mut bytes_le = Vec::with_capacity(total_bytes);
        for i in 0..total_bytes {
            let word_index = i / 8;
            let byte_index = i % 8;
            let byte = self.words[word_index].to_le_bytes()[byte_index];
            bytes_le.push(byte);
        }

        // Now, bytes_le[0] is the least significant byte,
        // and bytes_le[total_bytes - 1] is the most significant.

        // 2. Reverse the bytes.
        bytes_le.reverse();

        // 3. Pack the reversed bytes into 64-bit words.
        // (The first 8 bytes become the first word, the next 8 bytes the second word, and so on.)
        let num_words = self.words.len();
        let mut new_words = SmallVec::<[u64; 1]>::with_capacity(num_words);

        // Initialize with zeros.
        new_words.resize(num_words, 0);
        for (i, &byte) in bytes_le.iter().enumerate() {
            let word_index = i / 8;
            let byte_index = i % 8;
            new_words[word_index] |= (byte as u64) << (8 * byte_index);
        }

        // Clear out any bits beyond the bit-vector's length in the last word.
        let bits_in_last_word = self.length % 64;
        if bits_in_last_word != 0 {
            // Create a mask for the used bits.
            let mask = (1u64 << bits_in_last_word) - 1;
            let last_index = new_words.len() - 1;
            new_words[last_index] &= mask;
        }

        Self::new(new_words, self.length)
    }

    // Check if all bits in the BitVec are 1
    pub fn is_all_ones(&self) -> bool {
        // Check each word to see if all bits are set to 1
        for (i, &word) in self.words.iter().enumerate() {
            if i == self.words.len() - 1 {
                // For the final word, apply the final_word_mask
                if word != self.final_word_mask() {
                    return false;
                }
            } else {
                // For all other words, they must be completely filled with 1s
                if word != !0 {
                    return false;
                }
            }
        }
        true
    }

    // Check if all bits in the BitVec are 0
    pub fn is_zero(&self) -> bool {
        // Check each word to see if all bits are 0
        self.words.iter().all(|&word| word == 0)
    }

    pub fn is_one(&self) -> bool {
        if self.length == 0 {
            return false;
        }

        // Check if the least significant bit is 1
        if (self.words[0] & 1) == 0 {
            return false;
        }

        // Check that all other bits are 0
        for (i, &word) in self.words.iter().enumerate() {
            if i == 0 {
                // For the first word, ignore the least significant bit
                if word >> 1 != 0 {
                    return false;
                }
            } else if i == self.words.len() - 1 {
                // For the last word, apply the final_word_mask
                if word & self.final_word_mask() != 0 {
                    return false;
                }
            } else {
                // For all other words, they must be completely filled with 0s
                if word != 0 {
                    return false;
                }
            }
        }
        true
    }

    // Check if BitVec is a mask (i.e., consecutive 1s somewhere in the bit pattern),
    // returning the (high, low) bounds of the consecutive 1s if found.
    pub fn is_mask(&self) -> Option<(u32, u32)> {
        let mut first_one_pos = None;
        let mut last_one_pos = None;
        let mut found_zero_after_one = false;

        for bit_index in 0..self.length {
            let word_index = (bit_index / 64) as usize;
            let bit_in_word = bit_index % 64;
            let bit_is_set = (self.words[word_index] & (1u64 << bit_in_word)) != 0;

            if bit_is_set {
                if found_zero_after_one {
                    // Found a 1 after finding a 0 that came after 1s - not a valid mask
                    return None;
                }
                if first_one_pos.is_none() {
                    first_one_pos = Some(bit_index);
                }
                last_one_pos = Some(bit_index);
            } else if first_one_pos.is_some() {
                // Found a 0 after finding 1s
                found_zero_after_one = true;
            }
        }

        // Return (high, low) bounds if we found consecutive 1s
        match (first_one_pos, last_one_pos) {
            (Some(low), Some(high)) => Some((high, low)),
            _ => None,
        }
    }

    // Converts the BitVec to a usize if it fits within the usize range, otherwise returns None
    pub fn to_usize(&self) -> Option<usize> {
        // Check that the BitVec's bit length does not exceed the size of usize
        if self.len() > usize::BITS {
            None
        } else {
            Some(self.to_biguint().to_usize().unwrap_or(0))
        }
    }

    pub fn to_u64(&self) -> Option<u64> {
        if self.len() > 64 {
            // The BitVec is too large to fit in a u64
            return None;
        }

        // Since each word is already a u64 and we've verified the BitVec
        // is no more than 64 bits, we just need the first word
        match self.words.first() {
            Some(&word) => Some(word),
            None => Some(0), // Empty BitVec represents 0
        }
    }

    /// Counts the number of leading zeros in the BitVec.
    pub fn leading_zeros(&self) -> usize {
        let mut total = 0;
        for (i, &word) in self.words.iter().rev().enumerate() {
            let word_size = if i == 0 && !self.length.is_multiple_of(64) {
                (self.length % 64) as usize
            } else {
                64
            };
            let zeros = (word.leading_zeros() as usize).saturating_sub(64 - word_size);
            if zeros != word_size {
                return total + zeros;
            }
            total += word_size;
        }
        total
    }

    /// Counts the number of bits required to represent the BitVec.
    pub fn bits(&self) -> usize {
        self.len() as usize - self.leading_zeros()
    }

    pub fn to_biguint_abs(&self) -> BigUint {
        let n = self.to_biguint();
        if !self.sign() {
            // Non-negative
            n
        } else {
            // Negative: 2^bitwidth - n
            let bitwidth = self.len();
            let two_pow_bw = BigUint::one() << bitwidth;
            &two_pow_bw - &n
        }
    }

    // Creates and returns a BitVec with these zero-filled words.
    pub fn zeros(length: u32) -> BitVec {
        let mut words = SmallVec::new();
        let num_words = (length as usize).div_ceil(64); // Number of 64-bit words
        for _ in 0..num_words {
            words.push(0);
        }
        BitVec::new(words, length).expect("BitVec::new should never fail in zeros()")
    }

    // Creates and returns a BitVec with these one-filled words.
    pub fn ones(length: u32) -> BitVec {
        BitVec::from(((BigUint::one() << length) - 1u8, length))
    }
}

impl Debug for BitVec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RawBitVector")
            .field("words", &self.words)
            .field("length", &self.length)
            .finish()
    }
}

#[cfg(test)]
mod is_mask_tests {
    use super::*;
    use num_traits::Zero;

    #[test]
    fn test_is_mask_all_zeros() {
        let bv = BitVec::zeros(8);
        assert_eq!(bv.is_mask(), None);

        let bv = BitVec::zeros(64);
        assert_eq!(bv.is_mask(), None);

        let bv = BitVec::zeros(128);
        assert_eq!(bv.is_mask(), None);
    }

    #[test]
    fn test_is_mask_all_ones() {
        let bv = BitVec::ones(8);
        assert_eq!(bv.is_mask(), Some((7, 0)));

        let bv = BitVec::ones(64);
        assert_eq!(bv.is_mask(), Some((63, 0)));

        let bv = BitVec::ones(128);
        assert_eq!(bv.is_mask(), Some((127, 0)));
    }

    #[test]
    fn test_is_mask_single_bit() {
        // Single bit at position 0
        let bv = BitVec::from((1, 8));
        assert_eq!(bv.is_mask(), Some((0, 0)));

        // Single bit at position 3
        let bv = BitVec::from((0b1000, 8));
        assert_eq!(bv.is_mask(), Some((3, 3)));

        // Single bit at position 7
        let bv = BitVec::from((0b10000000, 8));
        assert_eq!(bv.is_mask(), Some((7, 7)));
    }

    #[test]
    fn test_is_mask_consecutive_low() {
        // Consecutive 1s at low end: 0b00001111
        let bv = BitVec::from((0x0F, 8));
        assert_eq!(bv.is_mask(), Some((3, 0)));

        // Consecutive 1s at low end: 0b00000111
        let bv = BitVec::from((0x07, 8));
        assert_eq!(bv.is_mask(), Some((2, 0)));
    }

    #[test]
    fn test_is_mask_consecutive_high() {
        // Consecutive 1s at high end: 0b11110000
        let bv = BitVec::from((0xF0, 8));
        assert_eq!(bv.is_mask(), Some((7, 4)));

        // Consecutive 1s at high end: 0b11100000
        let bv = BitVec::from((0xE0, 8));
        assert_eq!(bv.is_mask(), Some((7, 5)));
    }

    #[test]
    fn test_is_mask_consecutive_middle() {
        // Consecutive 1s in middle: 0b00111100
        let bv = BitVec::from((0x3C, 8));
        assert_eq!(bv.is_mask(), Some((5, 2)));

        // Consecutive 1s in middle: 0b01111110
        let bv = BitVec::from((0x7E, 8));
        assert_eq!(bv.is_mask(), Some((6, 1)));
    }

    #[test]
    fn test_is_mask_non_consecutive() {
        // Non-consecutive: 0b10101010
        let bv = BitVec::from((0xAA, 8));
        assert_eq!(bv.is_mask(), None);

        // Non-consecutive: 0b11011011
        let bv = BitVec::from((0xDB, 8));
        assert_eq!(bv.is_mask(), None);

        // Gap in middle: 0b11100111
        let bv = BitVec::from((0xE7, 8));
        assert_eq!(bv.is_mask(), None);
    }

    #[test]
    fn test_is_mask_cross_word_boundary() {
        // Test masks that cross 64-bit word boundaries
        // Create a mask from bit 60 to bit 67 (crosses boundary at bit 64)
        let mut value = BigUint::zero();
        for i in 60..=67 {
            value |= BigUint::one() << i;
        }
        let bv = BitVec::from((value, 128));
        assert_eq!(bv.is_mask(), Some((67, 60)));

        // Create a non-consecutive pattern across boundary
        let mut value = BigUint::zero();
        value |= BigUint::one() << 63; // Last bit of first word
        value |= BigUint::one() << 65; // Skip bit 64, non-consecutive
        let bv = BitVec::from((value, 128));
        assert_eq!(bv.is_mask(), None);
    }

    #[test]
    fn test_is_mask_large_bitvec() {
        // Large BitVec with mask at beginning
        let mut value = BigUint::zero();
        for i in 0..32 {
            value |= BigUint::one() << i;
        }
        let bv = BitVec::from((value, 256));
        assert_eq!(bv.is_mask(), Some((31, 0)));

        // Large BitVec with mask at end
        let mut value = BigUint::zero();
        for i in 224..256 {
            value |= BigUint::one() << i;
        }
        let bv = BitVec::from((value, 256));
        assert_eq!(bv.is_mask(), Some((255, 224)));

        // Large BitVec with mask in middle
        let mut value = BigUint::zero();
        for i in 100..150 {
            value |= BigUint::one() << i;
        }
        let bv = BitVec::from((value, 256));
        assert_eq!(bv.is_mask(), Some((149, 100)));
    }

    #[test]
    fn test_is_mask_edge_cases() {
        // Empty BitVec (0 length) - should return None
        let bv = BitVec::zeros(0);
        assert_eq!(bv.is_mask(), None);

        // 1-bit BitVec with 0
        let bv = BitVec::from((0, 1));
        assert_eq!(bv.is_mask(), None);

        // 1-bit BitVec with 1
        let bv = BitVec::from((1, 1));
        assert_eq!(bv.is_mask(), Some((0, 0)));

        // Exactly 64 bits, all ones
        let bv = BitVec::from((u64::MAX, 64));
        assert_eq!(bv.is_mask(), Some((63, 0)));

        // Exactly 64 bits, mask in middle
        let bv = BitVec::from((0x00FFFF0000000000, 64));
        assert_eq!(bv.is_mask(), Some((55, 40)));
    }

    #[test]
    fn test_is_mask_non_byte_aligned() {
        // 7-bit BitVec, all ones
        let bv = BitVec::from((0x7F, 7));
        assert_eq!(bv.is_mask(), Some((6, 0)));

        // 13-bit BitVec with mask
        let bv = BitVec::from((0x0FC0, 13)); // bits 6-11 set
        assert_eq!(bv.is_mask(), Some((11, 6)));

        // 100-bit BitVec with mask at high end
        let mut value = BigUint::zero();
        for i in 90..100 {
            value |= BigUint::one() << i;
        }
        let bv = BitVec::from((value, 100));
        assert_eq!(bv.is_mask(), Some((99, 90)));
    }
}
