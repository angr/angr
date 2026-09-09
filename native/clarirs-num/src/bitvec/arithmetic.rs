use std::ops::{Add, Div, Mul, Neg, Rem, Sub};

use num_bigint::BigUint;
use num_traits::Zero;
use smallvec::SmallVec;

use super::{BitVec, BitVecError};

impl Neg for BitVec {
    type Output = Result<Self, BitVecError>;

    fn neg(self) -> Self::Output {
        (!self.clone())? + BitVec::from((1, self.length))
    }
}

impl Add for BitVec {
    type Output = Result<Self, BitVecError>;

    fn add(self, rhs: Self) -> Self::Output {
        self.check_same_length(&rhs)?;

        let mut result = SmallVec::with_capacity(self.words.len());
        let mut carry = 0u64;

        // Add corresponding words with carry
        for i in 0..self.words.len() {
            let lhs = self.words.get(i).copied().unwrap_or(0);
            let rhs = rhs.words.get(i).copied().unwrap_or(0);

            let (sum1, carry1) = lhs.overflowing_add(rhs);
            let (sum2, carry2) = sum1.overflowing_add(carry);

            carry = (carry1 as u64) + (carry2 as u64);
            result.push(sum2);
        }

        // `new` masks the bits above `length` in the final word.
        BitVec::new(result, self.length)
    }
}

impl Add<u64> for BitVec {
    type Output = Result<Self, BitVecError>;

    fn add(self, rhs: u64) -> Self::Output {
        BitVec::from((rhs, self.length)) + self
    }
}

impl Sub for BitVec {
    type Output = Result<Self, BitVecError>;

    fn sub(self, rhs: Self) -> Self::Output {
        self.clone() + (-rhs)?
    }
}

impl Mul for BitVec {
    type Output = Result<Self, BitVecError>;

    fn mul(self, rhs: Self) -> Result<Self, BitVecError> {
        self.check_same_length(&rhs)?;
        Ok(BitVec::from((
            BigUint::from(&self) * BigUint::from(&rhs),
            self.length,
        )))
    }
}

impl Div for BitVec {
    type Output = Result<Self, BitVecError>;

    fn div(self, rhs: Self) -> Self::Output {
        self.check_same_length(&rhs)?;
        if rhs.is_zero() {
            return Err(BitVecError::DivisionByZero);
        }
        Ok(BitVec::from((
            BigUint::from(&self) / BigUint::from(&rhs),
            self.length,
        )))
    }
}

impl Rem for BitVec {
    type Output = Result<Self, BitVecError>;

    fn rem(self, rhs: Self) -> Self::Output {
        self.check_same_length(&rhs)?;
        // Mirror `Div`: a zero divisor is an error rather than a panic. Total
        // SMT-LIB remainder semantics (return the dividend) live in `urem`/`srem`.
        if rhs.is_zero() {
            return Err(BitVecError::DivisionByZero);
        }
        Ok(BitVec::from((
            BigUint::from(&self) % BigUint::from(&rhs),
            self.length,
        )))
    }
}

impl BitVec {
    pub fn urem(&self, other: &Self) -> Self {
        if other.is_zero() {
            return self.clone();
        }
        let bitwidth = self.len();
        let remainder = self.to_biguint() % other.to_biguint();
        BitVec::from((remainder, bitwidth))
    }

    pub fn srem(&self, other: &Self) -> Result<Self, BitVecError> {
        if other.is_zero() {
            return Ok(self.clone());
        }
        let bitwidth = self.len();

        // Compute absolute values in BigUint space
        let abs_dividend = self.to_biguint_abs();
        let abs_divisor = other.to_biguint_abs();
        let unsigned_remainder = abs_dividend % abs_divisor;
        let raw_rem = BitVec::from((unsigned_remainder, bitwidth));

        // The remainder takes the sign of the dividend (SMT-LIB bvsrem).
        if self.sign() { -raw_rem } else { Ok(raw_rem) }
    }

    pub fn sdiv(&self, other: &Self) -> Result<Self, BitVecError> {
        let bitwidth = self.len();
        let result_neg = self.sign() ^ other.sign();

        let abs_dividend = self.to_biguint_abs();
        let abs_divisor = other.to_biguint_abs();
        if abs_divisor.is_zero() {
            // Return self if divisor is zero
            return Ok(self.clone());
        }

        let abs_quotient = &abs_dividend / &abs_divisor;
        let quotient_bv = BitVec::from((abs_quotient, bitwidth));

        if result_neg {
            -quotient_bv
        } else {
            Ok(quotient_bv)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::result::Result;

    #[test]
    fn test_add() -> Result<(), BitVecError> {
        // Basic addition
        let a = BitVec::from((42, 64));
        let b = BitVec::from((58, 64));
        let result = (a + b)?;
        assert_eq!(result.to_u64().unwrap(), 100);

        // Addition with overflow within the same bitwidth
        let a = BitVec::from((0xFFFFFFFF, 32));
        let b = BitVec::from((1, 32));
        let result = (a + b)?;
        assert_eq!(result.len(), 32);
        assert_eq!(result.to_u64().unwrap(), 0);

        // Addition with different bit widths
        let a = BitVec::from((42, 32));
        let b = BitVec::from((58, 32));
        let result = (a + b)?;
        assert_eq!(result.to_u64().unwrap(), 100);

        Ok(())
    }

    #[test]
    fn test_sub() -> Result<(), BitVecError> {
        // Basic subtraction
        let a = BitVec::from((100, 64));
        let b = BitVec::from((58, 64));
        let result = (a - b)?;
        assert_eq!(result.to_u64().unwrap(), 42);

        // Subtraction with underflow
        let a = BitVec::from((0, 64));
        let b = BitVec::from((1, 64));
        let result = (a - b)?;
        assert_eq!(result.to_u64().unwrap(), u64::MAX);

        // Subtraction with different bit widths
        let a = BitVec::from((100, 32));
        let b = BitVec::from((58, 32));
        let result = (a - b)?;
        assert_eq!(result.to_u64().unwrap(), 42);

        Ok(())
    }

    #[test]
    fn test_mul() -> Result<(), BitVecError> {
        // Basic multiplication
        let a = BitVec::from((7, 64));
        let b = BitVec::from((6, 64));
        let result = (a * b)?;
        assert_eq!(result.to_u64().unwrap(), 42);

        // Multiplication with overflow
        let a = BitVec::from((0xFFFFFFFF, 32));
        let b = BitVec::from((2, 32));
        let result = (a * b)?;
        assert_eq!(result.to_u64().unwrap(), 0xFFFFFFFE);

        // Multiplication with different bit widths
        let a = BitVec::from((7, 32));
        let b = BitVec::from((6, 32));
        let result = (a * b)?;
        assert_eq!(result.to_u64().unwrap(), 42);

        Ok(())
    }

    #[test]
    fn test_div() -> Result<(), BitVecError> {
        // Basic division
        let a = BitVec::from((42, 64));
        let b = BitVec::from((6, 64));
        let result = (a / b)?;
        assert_eq!(result.to_u64().unwrap(), 7);

        // Division with remainder
        let a = BitVec::from((100, 64));
        let b = BitVec::from((30, 64));
        let result = (a / b)?;
        assert_eq!(result.to_u64().unwrap(), 3);

        // Division with different bit widths
        let a = BitVec::from((100, 32));
        let b = BitVec::from((30, 32));
        let result = (a / b)?;
        assert_eq!(result.to_u64().unwrap(), 3);

        // Division by zero
        let a = BitVec::from((42, 64));
        let b = BitVec::from((0, 64));
        let result = a / b;

        assert!(
            result.is_err(),
            "Expected division by zero to return an error"
        );

        if let Err(BitVecError::DivisionByZero) = result {
        } else {
            panic!("Expected DivisionByZero error, but got {result:?}");
        }

        Ok(())
    }

    #[test]
    fn test_rem() -> Result<(), BitVecError> {
        // Basic remainder
        let a = BitVec::from((42, 64));
        let b = BitVec::from((6, 64));
        let result = (a % b)?;
        assert_eq!(result.to_u64().unwrap(), 0);

        // Remainder with non-zero result
        let a = BitVec::from((100, 64));
        let b = BitVec::from((30, 64));
        let result = (a % b)?;
        assert_eq!(result.to_u64().unwrap(), 10);

        // Remainder with different bit widths
        let a = BitVec::from((100, 32));
        let b = BitVec::from((30, 32));
        let result = (a % b)?;
        assert_eq!(result.to_u64().unwrap(), 10);

        // Remainder by zero is an error, not a panic (mirrors Div).
        let a = BitVec::from((42, 64));
        let b = BitVec::from((0, 64));
        assert!(matches!(a % b, Err(BitVecError::DivisionByZero)));

        Ok(())
    }

    #[test]
    fn test_signed_arithmetic() -> Result<(), BitVecError> {
        let neg_42 = BitVec::from((-42i64 as u64, 64));
        let pos_6 = BitVec::from((6, 64));

        // Signed division should give -7
        let result = neg_42.sdiv(&pos_6)?;
        assert!(result.sign()); // Should be negative
        assert_eq!(result, BitVec::from((-7i64 as u64, 64)));

        // Create -100 in 64-bit two's complement
        let neg_100 = BitVec::from((-100i64 as u64, 64));
        let pos_30 = BitVec::from((30, 64));

        // Signed remainder should give -10
        let result = neg_100.srem(&pos_30)?;
        assert!(result.sign()); // Should be negative
        assert_eq!(result, BitVec::from((-10i64 as u64, 64)));

        // Test division with different signs
        let pos_100 = BitVec::from((100, 64));
        let neg_30 = BitVec::from((-30i64 as u64, 64));

        // Signed division should give -3
        let result = pos_100.sdiv(&neg_30)?;
        assert!(result.sign()); // Should be negative
        assert_eq!(result, BitVec::from((-3i64 as u64, 64)));

        Ok(())
    }
}
