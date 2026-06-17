use serde::{Deserialize, Serialize};
use std::ops::{Add, Div, Mul, Neg, Sub};

use super::{BitVec, BitVecError};
use num_bigint::{BigInt, BigUint};
use num_traits::{One, ToPrimitive, Zero};

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FSort {
    pub exponent: u32,
    pub mantissa: u32,
}

pub const F32_SORT: FSort = FSort {
    exponent: 8,
    mantissa: 23,
};
pub const F64_SORT: FSort = FSort {
    exponent: 11,
    mantissa: 52,
};

impl FSort {
    pub fn new(exponent: u32, mantissa: u32) -> Self {
        Self { exponent, mantissa }
    }

    pub fn size(&self) -> u32 {
        self.exponent + self.mantissa + 1
    }

    pub fn f32() -> Self {
        F32_SORT
    }

    pub fn f64() -> Self {
        F64_SORT
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub enum FPRM {
    #[default]
    NearestTiesToEven,
    TowardPositive,
    TowardNegative,
    TowardZero,
    NearestTiesToAway,
}

/// A floating-point number that can be either f32 or f64.
#[derive(Debug, Copy, Clone, PartialEq, Serialize, Deserialize)]
pub enum Float {
    F32(f32),
    F64(f64),
}

impl Eq for Float {}

impl std::hash::Hash for Float {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        match self {
            Float::F32(f) => {
                0u8.hash(state);
                f.to_bits().hash(state);
            }
            Float::F64(f) => {
                1u8.hash(state);
                f.to_bits().hash(state);
            }
        }
    }
}

impl Float {
    pub fn new(sign: bool, exponent: BitVec, mantissa: BitVec) -> Result<Self, BitVecError> {
        let fsort = FSort::new(exponent.len(), mantissa.len());

        match fsort {
            F32_SORT => {
                let sign_bit = if sign { 1u8 } else { 0u8 };
                let exp_val = exponent
                    .to_biguint()
                    .to_u8()
                    .ok_or(BitVecError::ConversionError)?;
                let mant_val = mantissa
                    .to_biguint()
                    .to_u32()
                    .ok_or(BitVecError::ConversionError)?;
                Ok(Float::F32(recompose_f32(sign_bit, exp_val, mant_val)))
            }
            F64_SORT => {
                let sign_bit = if sign { 1u8 } else { 0u8 };
                let exp_val = exponent
                    .to_biguint()
                    .to_u16()
                    .ok_or(BitVecError::ConversionError)?;
                let mant_val = mantissa.to_u64().ok_or(BitVecError::ConversionError)?;
                Ok(Float::F64(recompose_f64(sign_bit, exp_val, mant_val)))
            }
            _ => {
                // For other formats, convert through f64
                let sign_bit = if sign { 1u8 } else { 0u8 };
                let exp_val = exponent
                    .to_biguint()
                    .to_u16()
                    .ok_or(BitVecError::ConversionError)?;
                let mant_val = mantissa.to_u64().ok_or(BitVecError::ConversionError)?;
                Ok(Float::F64(recompose_f64(sign_bit, exp_val, mant_val)))
            }
        }
    }

    pub fn sign(&self) -> bool {
        match self {
            Float::F32(f) => f.is_sign_negative(),
            Float::F64(f) => f.is_sign_negative(),
        }
    }

    pub fn exponent(&self) -> BitVec {
        match self {
            Float::F32(f) => {
                let (_, exp, _) = decompose_f32(*f);
                BitVec::from((u64::from(exp), 8))
            }
            Float::F64(f) => {
                let (_, exp, _) = decompose_f64(*f);
                BitVec::from((u64::from(exp), 11))
            }
        }
    }

    pub fn mantissa(&self) -> BitVec {
        match self {
            Float::F32(f) => {
                let (_, _, mant) = decompose_f32(*f);
                BitVec::from((u64::from(mant), 23))
            }
            Float::F64(f) => {
                let (_, _, mant) = decompose_f64(*f);
                BitVec::from((mant, 52))
            }
        }
    }

    pub fn fsort(&self) -> FSort {
        match self {
            Float::F32(_) => F32_SORT,
            Float::F64(_) => F64_SORT,
        }
    }

    pub fn is_zero(&self) -> bool {
        match self {
            Float::F32(f) => *f == 0.0 || *f == -0.0,
            Float::F64(f) => *f == 0.0 || *f == -0.0,
        }
    }

    pub fn is_subnormal(&self) -> bool {
        match self {
            Float::F32(f) => f.is_subnormal(),
            Float::F64(f) => f.is_subnormal(),
        }
    }

    pub fn from_f64_with_rounding(
        value: f64,
        _rm: FPRM,
        fsort: FSort,
    ) -> Result<Self, BitVecError> {
        match fsort {
            F32_SORT => Ok(Float::F32(value as f32)),
            F64_SORT => Ok(Float::F64(value)),
            _ => Ok(Float::F64(value)), // Default to f64 for custom formats
        }
    }

    pub fn to_fsort(&self, fsort: FSort, _rm: FPRM) -> Result<Self, BitVecError> {
        match (self.fsort(), fsort) {
            (current, target) if current == target => Ok(*self),
            (F32_SORT, F64_SORT) => match self {
                Float::F32(f) => Ok(Float::F64(*f as f64)),
                _ => unreachable!(),
            },
            (F64_SORT, F32_SORT) => match self {
                Float::F64(f) => Ok(Float::F32(*f as f32)),
                _ => unreachable!(),
            },
            _ => {
                // For unsupported formats, return an error
                Err(BitVecError::InvalidExtractBounds {
                    upper: fsort.size(),
                    lower: 0,
                    length: self.fsort().size(),
                })
            }
        }
    }

    pub fn compare_fp(&self, other: &Self) -> bool {
        // IEEE 754 fpEQ comparison - distinguishes between +0.0 and -0.0
        // Also, NaN != NaN
        if self.is_nan() || other.is_nan() {
            return false;
        }

        // For zero values, check sign bit explicitly
        if self.is_zero() && other.is_zero() {
            return self.sign() == other.sign();
        }

        // For other values, use standard equality
        match (self, other) {
            (Float::F32(a), Float::F32(b)) => a.to_bits() == b.to_bits(),
            (Float::F64(a), Float::F64(b)) => a.to_bits() == b.to_bits(),
            (Float::F32(a), Float::F64(b)) => (*a as f64).to_bits() == b.to_bits(),
            (Float::F64(a), Float::F32(b)) => a.to_bits() == (*b as f64).to_bits(),
        }
    }

    pub fn lt(&self, other: &Self) -> bool {
        // Convert both to f64 for comparison
        let self_f64 = self.to_f64().unwrap_or(0.0);
        let other_f64 = other.to_f64().unwrap_or(0.0);

        // Handle NaN and zero cases
        if self.is_nan() || other.is_nan() {
            return false;
        }
        if self.is_zero() && other.is_zero() {
            return false;
        }

        self_f64 < other_f64
    }

    pub fn leq(&self, other: &Self) -> bool {
        let self_f64 = self.to_f64().unwrap_or(0.0);
        let other_f64 = other.to_f64().unwrap_or(0.0);

        if self.is_nan() || other.is_nan() {
            return false;
        }
        if self.is_zero() && other.is_zero() {
            return true;
        }

        self_f64 <= other_f64
    }

    pub fn gt(&self, other: &Self) -> bool {
        let self_f64 = self.to_f64().unwrap_or(0.0);
        let other_f64 = other.to_f64().unwrap_or(0.0);

        if self.is_nan() || other.is_nan() {
            return false;
        }
        if self.is_zero() && other.is_zero() {
            return false;
        }

        self_f64 > other_f64
    }

    pub fn geq(&self, other: &Self) -> bool {
        let self_f64 = self.to_f64().unwrap_or(0.0);
        let other_f64 = other.to_f64().unwrap_or(0.0);

        if self.is_nan() || other.is_nan() {
            return false;
        }
        if self.is_zero() && other.is_zero() {
            return true;
        }

        self_f64 >= other_f64
    }

    pub fn is_nan(&self) -> bool {
        match self {
            Float::F32(f) => f.is_nan(),
            Float::F64(f) => f.is_nan(),
        }
    }

    pub fn is_infinity(&self) -> bool {
        match self {
            Float::F32(f) => f.is_infinite(),
            Float::F64(f) => f.is_infinite(),
        }
    }

    pub fn to_ieee_bits(&self) -> BigUint {
        match self {
            Float::F32(f) => BigUint::from(f.to_bits()),
            Float::F64(f) => BigUint::from(f.to_bits()),
        }
    }

    pub fn to_unsigned_biguint(&self) -> Result<BigUint, BitVecError> {
        self.to_f64()
            .ok_or(BitVecError::ConversionError)
            .map(|value| BigUint::from(value as u64))
    }

    pub fn to_signed_bigint(&self) -> Result<BigInt, BitVecError> {
        self.to_f64()
            .ok_or(BitVecError::ConversionError)
            .map(|value| BigInt::from(value as i64))
    }

    pub fn to_f32(&self) -> Option<f32> {
        match self {
            Float::F32(f) => Some(*f),
            Float::F64(f) => Some(*f as f32),
        }
    }

    pub fn to_f64(&self) -> Option<f64> {
        match self {
            Float::F32(f) => Some(*f as f64),
            Float::F64(f) => Some(*f),
        }
    }

    pub fn convert_to_format(&self, fsort: FSort, fprm: FPRM) -> Result<Self, BitVecError> {
        self.to_fsort(fsort, fprm)
    }

    pub fn from_bigint_with_rounding(
        value: &BigInt,
        fsort: FSort,
        fprm: FPRM,
    ) -> Result<Self, BitVecError> {
        let float_value = value.to_f64().ok_or(BitVecError::ConversionError)?;
        Float::from_f64_with_rounding(float_value, fprm, fsort)
    }

    pub fn from_biguint_with_rounding(
        value: &BigUint,
        fsort: FSort,
        fprm: FPRM,
    ) -> Result<Self, BitVecError> {
        let float_value = value.to_f64().ok_or(BitVecError::ConversionError)?;
        Float::from_f64_with_rounding(float_value, fprm, fsort)
    }

    pub fn shift_with_grs(value: BigUint, shift: u32) -> (BigUint, bool, bool) {
        if shift == 0 {
            return (value, false, false);
        }

        let k = shift as usize;
        let mask = (&BigUint::one() << k) - BigUint::one();
        let shifted_out = &value & &mask;

        let guard = ((&shifted_out >> (k - 1)) & BigUint::one()) == BigUint::one();

        let sticky = if k > 1 {
            (&shifted_out & ((&BigUint::one() << (k - 1)) - BigUint::one())) != BigUint::zero()
        } else {
            false
        };

        (value >> k, guard, sticky)
    }

    pub fn sqrt(&self) -> Self {
        match self {
            Float::F32(f) => Float::F32(f.sqrt()),
            Float::F64(f) => Float::F64(f.sqrt()),
        }
    }

    pub fn abs(&self) -> Self {
        match self {
            Float::F32(f) => Float::F32(f.abs()),
            Float::F64(f) => Float::F64(f.abs()),
        }
    }
}

impl Neg for Float {
    type Output = Float;

    fn neg(self) -> Self::Output {
        match self {
            Float::F32(f) => Float::F32(-f),
            Float::F64(f) => Float::F64(-f),
        }
    }
}

impl Add for Float {
    type Output = Float;

    fn add(self, other: Float) -> Self::Output {
        match (self, other) {
            (Float::F32(a), Float::F32(b)) => Float::F32(a + b),
            (Float::F64(a), Float::F64(b)) => Float::F64(a + b),
            (Float::F32(a), Float::F64(b)) => Float::F64(a as f64 + b),
            (Float::F64(a), Float::F32(b)) => Float::F64(a + b as f64),
        }
    }
}

impl Sub for Float {
    type Output = Float;

    fn sub(self, rhs: Self) -> Self::Output {
        match (self, rhs) {
            (Float::F32(a), Float::F32(b)) => Float::F32(a - b),
            (Float::F64(a), Float::F64(b)) => Float::F64(a - b),
            (Float::F32(a), Float::F64(b)) => Float::F64(a as f64 - b),
            (Float::F64(a), Float::F32(b)) => Float::F64(a - b as f64),
        }
    }
}

impl Mul for Float {
    type Output = Float;

    fn mul(self, rhs: Self) -> Self::Output {
        match (self, rhs) {
            (Float::F32(a), Float::F32(b)) => Float::F32(a * b),
            (Float::F64(a), Float::F64(b)) => Float::F64(a * b),
            (Float::F32(a), Float::F64(b)) => Float::F64(a as f64 * b),
            (Float::F64(a), Float::F32(b)) => Float::F64(a * b as f64),
        }
    }
}

impl Div for Float {
    type Output = Float;

    fn div(self, rhs: Self) -> Self::Output {
        match (self, rhs) {
            (Float::F32(a), Float::F32(b)) => Float::F32(a / b),
            (Float::F64(a), Float::F64(b)) => Float::F64(a / b),
            (Float::F32(a), Float::F64(b)) => Float::F64(a as f64 / b),
            (Float::F64(a), Float::F32(b)) => Float::F64(a / b as f64),
        }
    }
}

impl From<f32> for Float {
    fn from(value: f32) -> Self {
        Float::F32(value)
    }
}

impl From<f64> for Float {
    fn from(value: f64) -> Self {
        Float::F64(value)
    }
}

pub fn decompose_f32(value: f32) -> (u8, u8, u32) {
    let bits: u32 = value.to_bits();
    let sign: u8 = (bits >> 31) as u8;
    let exponent: u8 = ((bits >> 23) & 0xFF) as u8;
    let mantissa: u32 = bits & 0x7FFFFF;

    (sign, exponent, mantissa)
}

pub fn recompose_f32(sign: u8, exponent: u8, mantissa: u32) -> f32 {
    let sign_bit: u32 = (sign as u32) << 31;
    let exponent_bits: u32 = ((exponent as u32) & 0xFF) << 23;
    let mantissa_bits: u32 = mantissa & 0x7FFFFF;
    let bits: u32 = sign_bit | exponent_bits | mantissa_bits;

    f32::from_bits(bits)
}

pub fn decompose_f64(value: f64) -> (u8, u16, u64) {
    let bits: u64 = value.to_bits();
    let sign: u8 = (bits >> 63) as u8;
    let exponent: u16 = ((bits >> 52) & 0x7FF) as u16;
    let mantissa: u64 = bits & 0xFFFFFFFFFFFFF;

    (sign, exponent, mantissa)
}

pub fn recompose_f64(sign: u8, exponent: u16, mantissa: u64) -> f64 {
    let sign_bit: u64 = (sign as u64) << 63;
    let exponent_bits: u64 = ((exponent as u64) & 0x7FF) << 52;
    let mantissa_bits: u64 = mantissa & 0xFFFFFFFFFFFFF;
    let bits: u64 = sign_bit | exponent_bits | mantissa_bits;

    f64::from_bits(bits)
}

pub fn decompose_f64_big_endian(value: f64) -> (u8, u16, u64) {
    let bits: u64 = value.to_bits().to_be();
    let sign: u8 = (bits >> 63) as u8;
    let exponent: u16 = ((bits >> 52) & 0x7FF) as u16;
    let mantissa: u64 = bits & 0xFFFFFFFFFFFFF;

    (sign, exponent, mantissa)
}

pub fn recompose_f64_big_endian(sign: u8, exponent: u16, mantissa: u64) -> f64 {
    let sign_bit: u64 = (sign as u64) << 63;
    let exponent_bits: u64 = ((exponent as u64) & 0x7FF) << 52;
    let mantissa_bits: u64 = mantissa & 0xFFFFFFFFFFFFF;
    let bits: u64 = sign_bit | exponent_bits | mantissa_bits;

    f64::from_bits(bits.to_be())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_float_decomposition() {
        let values = [
            0.0,
            -0.0,
            1.0,
            -1.0,
            42.0,
            -42.0,
            1.5,
            -1.5,
            f64::INFINITY,
            f64::NEG_INFINITY,
            f64::NAN,
        ];

        for &value in &values {
            let (sign, exponent, mantissa) = decompose_f64(value);
            let recomposed = recompose_f64(sign, exponent, mantissa);

            if value.is_nan() {
                assert!(recomposed.is_nan());
            } else {
                assert_eq!(value, recomposed);
            }

            let (sign_be, exponent_be, mantissa_be) = decompose_f64_big_endian(value);
            let recomposed_be = recompose_f64_big_endian(sign_be, exponent_be, mantissa_be);

            if value.is_nan() {
                assert!(recomposed_be.is_nan());
            } else {
                assert_eq!(value, recomposed_be);
            }
        }
    }

    #[test]
    fn test_float_construct_round_trip() {
        let values = [
            0.0,
            -0.0,
            1.0,
            -1.0,
            42.0,
            -42.0,
            1.5,
            -1.5,
            f64::INFINITY,
            f64::NEG_INFINITY,
            f64::NAN,
        ];

        for &value in &values {
            let start = Float::from(value);
            let recomposed = start.to_f64();

            if value.is_nan() {
                assert!(recomposed.unwrap().is_nan());
            } else {
                assert_eq!(value, recomposed.unwrap());
            }
        }
    }

    #[test]
    fn test_to_fp_round_trip() -> Result<(), BitVecError> {
        let values = [
            0.0,
            -0.0,
            1.0,
            -1.0,
            42.0,
            -42.0,
            1.5,
            -1.5,
            f64::INFINITY,
            f64::NEG_INFINITY,
            f64::NAN,
        ];

        for &value in &values {
            let start = Float::from(value);
            let middle = start.to_fsort(F32_SORT, FPRM::NearestTiesToEven)?;
            let end = middle.to_fsort(F64_SORT, FPRM::NearestTiesToEven)?;

            let recomposed = end.to_f64().expect("Failed to convert to f64");

            if value.is_nan() {
                assert!(recomposed.is_nan());
            } else {
                assert_eq!(value, recomposed);
            }
        }

        Ok(())
    }

    #[test]
    fn test_float_construct_f32_to_f64() -> Result<(), BitVecError> {
        let test_values: &[f32] = &[
            0.0,
            -0.0,
            1.0,
            -1.0,
            42.0,
            -42.0,
            1.5,
            -1.5,
            f32::INFINITY,
            f32::NEG_INFINITY,
            f32::NAN,
            f32::MAX,
            f32::MIN,
            f32::MIN_POSITIVE,
        ];

        for &value in test_values {
            let float = Float::from(value);
            let converted = float.to_fsort(F64_SORT, FPRM::NearestTiesToEven)?;
            let result = converted.to_f64().expect("Failed to convert to f64");

            if value.is_nan() {
                assert!(result.is_nan());
            } else {
                assert_eq!(value as f64, result);
            }
        }

        Ok(())
    }

    #[test]
    fn test_zero_comparison() {
        let pos_zero = Float::F32(0.0);
        let neg_zero = Float::F32(-0.0);

        println!("pos_zero.sign(): {}", pos_zero.sign());
        println!("neg_zero.sign(): {}", neg_zero.sign());
        println!(
            "pos_zero.compare_fp(&neg_zero): {}",
            pos_zero.compare_fp(&neg_zero)
        );
        println!(
            "neg_zero.compare_fp(&pos_zero): {}",
            neg_zero.compare_fp(&pos_zero)
        );

        assert!(
            !pos_zero.compare_fp(&neg_zero),
            "fpEQ(+0.0, -0.0) should be false"
        );
        assert!(
            !neg_zero.compare_fp(&pos_zero),
            "fpEQ(-0.0, +0.0) should be false"
        );
        assert!(
            pos_zero.compare_fp(&pos_zero),
            "fpEQ(+0.0, +0.0) should be true"
        );
        assert!(
            neg_zero.compare_fp(&neg_zero),
            "fpEQ(-0.0, -0.0) should be true"
        );
    }

    #[test]
    #[allow(clippy::excessive_precision)]
    fn test_float_construct_f64_to_f32() -> Result<(), BitVecError> {
        let test_values: &[f64] = &[
            0.0,
            -0.0,
            1.0,
            -1.0,
            42.0,
            -42.0,
            1.5,
            -1.5,
            f64::INFINITY,
            f64::NEG_INFINITY,
            f64::NAN,
            3.4028234663852886e+38,
            -3.4028234663852886e+38,
            f32::MIN_POSITIVE as f64,
        ];

        for &value in test_values {
            let float = Float::from(value);
            let converted = float.to_fsort(F32_SORT, FPRM::NearestTiesToEven)?;
            let result = converted.to_f32().expect("Failed to convert to f32");

            if value.is_nan() {
                assert!(result.is_nan());
            } else {
                assert_eq!(value as f32, result);
            }
        }

        Ok(())
    }
}
