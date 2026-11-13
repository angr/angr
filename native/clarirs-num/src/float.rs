use serde::{Deserialize, Serialize};
use std::ops::{Add, Div, Mul, Neg, Sub};

use super::{BitVec, BitVecError};
use num_bigint::{BigInt, BigUint};
use num_traits::{FromPrimitive, One, ToPrimitive, Zero};

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
#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
pub enum Float {
    F32(f32),
    F64(f64),
}

/// Equality is by sort and bit pattern, consistent with [`Hash`]: a NaN
/// equals a NaN of the same bits, and +0 and -0 differ. This is identity of
/// the constant, not IEEE equality; see [`Float::eq_ieee_754`] for that.
impl PartialEq for Float {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Float::F32(a), Float::F32(b)) => a.to_bits() == b.to_bits(),
            (Float::F64(a), Float::F64(b)) => a.to_bits() == b.to_bits(),
            _ => false,
        }
    }
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

    /// `operand` in this value's format, rounded to nearest-even if narrowed.
    fn convert_operand(&self, operand: &Self) -> Self {
        match (self, operand) {
            (Float::F32(_), Float::F64(v)) => Float::F32(*v as f32),
            (Float::F64(_), Float::F32(v)) => Float::F64(f64::from(*v)),
            _ => *operand,
        }
    }

    /// `self + other`, rounded by `rm`. `other` is converted to this value's
    /// format.
    pub fn add_rm(&self, other: &Self, rm: FPRM) -> Self {
        let other = self.convert_operand(other);
        let (Some(x), Some(y)) = (exact(self), exact(&other)) else {
            return *self + other;
        };
        round_sum(x, y, self.fsort(), rm)
    }

    /// `self - other`, rounded by `rm`.
    pub fn sub_rm(&self, other: &Self, rm: FPRM) -> Self {
        self.add_rm(&-*other, rm)
    }

    /// `self * other`, rounded by `rm`. `other` is converted to this value's
    /// format.
    pub fn mul_rm(&self, other: &Self, rm: FPRM) -> Self {
        let other = self.convert_operand(other);
        let (Some((xn, xm, xe)), Some((yn, ym, ye))) = (exact(self), exact(&other)) else {
            return *self * other;
        };
        round_exact(xn != yn, xm * ym, xe + ye, false, self.fsort(), rm)
    }

    /// `self / other`, rounded by `rm`. `other` is converted to this value's
    /// format.
    pub fn div_rm(&self, other: &Self, rm: FPRM) -> Self {
        let other = self.convert_operand(other);
        let divisor = exact(&other).filter(|(_, m, _)| !m.is_zero());
        let (Some((xn, xm, xe)), Some((yn, ym, ye))) = (exact(self), divisor) else {
            return *self / other;
        };
        // Enough quotient bits for the significand plus a rounding bit
        let k = i64::from(self.fsort().mantissa) + 3 + ym.bits() as i64 - xm.bits() as i64;
        let k = k.max(0);
        let num = xm << k as u64;
        let (quot, rem) = (&num / &ym, &num % &ym);
        round_exact(
            xn != yn,
            quot,
            xe - ye - k,
            !rem.is_zero(),
            self.fsort(),
            rm,
        )
    }

    pub fn from_f64_with_rounding(value: f64, rm: FPRM, fsort: FSort) -> Result<Self, BitVecError> {
        match fsort {
            F32_SORT => Float::F64(value).to_fsort(fsort, rm),
            F64_SORT => Ok(Float::F64(value)),
            _ => Ok(Float::F64(value)), // Default to f64 for custom formats
        }
    }

    pub fn to_fsort(&self, fsort: FSort, rm: FPRM) -> Result<Self, BitVecError> {
        match (self.fsort(), fsort) {
            (current, target) if current == target => Ok(*self),
            (F32_SORT, F64_SORT) => match self {
                Float::F32(f) => Ok(Float::F64(*f as f64)),
                _ => unreachable!(),
            },
            (F64_SORT, F32_SORT) => match (self, exact(self)) {
                (_, Some((neg, mag, exp))) => Ok(round_exact(neg, mag, exp, false, fsort, rm)),
                // NaN or an infinity
                (Float::F64(f), None) => Ok(Float::F32(*f as f32)),
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

    /// SMT-LIB `=` on floats, as Z3 decides it: every NaN is the one NaN
    /// value, and +0 and -0 are distinct values. Floats of different sorts
    /// are never equal.
    pub fn eq_smtlib(&self, other: &Self) -> bool {
        match (self, other) {
            (Float::F32(a), Float::F32(b)) => {
                (a.is_nan() && b.is_nan()) || a.to_bits() == b.to_bits()
            }
            (Float::F64(a), Float::F64(b)) => {
                (a.is_nan() && b.is_nan()) || a.to_bits() == b.to_bits()
            }
            _ => false,
        }
    }

    /// IEEE 754 equality, as SMT-LIB `fp.eq`: NaN equals nothing, and +0
    /// equals -0.
    pub fn eq_ieee_754(&self, other: &Self) -> bool {
        match (self, other) {
            (Float::F32(a), Float::F32(b)) => a == b,
            (Float::F64(a), Float::F64(b)) => a == b,
            (Float::F32(a), Float::F64(b)) => f64::from(*a) == *b,
            (Float::F64(a), Float::F32(b)) => *a == f64::from(*b),
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

    /// Returns the IEEE 754 bit representation of this float as a [`BitVec`]
    /// whose width matches the float's sort (32 bits for f32, 64 bits for f64).
    pub fn to_ieee_bits(&self) -> BitVec {
        match self {
            Float::F32(f) => BitVec::from((u64::from(f.to_bits()), 32)),
            Float::F64(f) => BitVec::from((f.to_bits(), 64)),
        }
    }

    /// Reinterprets the bits of `bits` as an IEEE 754 float. The width of the
    /// bitvector selects the format: 32 bits yields an f32 and 64 bits an f64.
    /// Any other width returns [`BitVecError::ConversionError`].
    pub fn try_from_ieee_bits(bits: &BitVec) -> Result<Self, BitVecError> {
        match bits.len() {
            32 => {
                let value = bits.to_u64().ok_or(BitVecError::ConversionError)? as u32;
                Ok(Float::F32(f32::from_bits(value)))
            }
            64 => {
                let value = bits.to_u64().ok_or(BitVecError::ConversionError)?;
                Ok(Float::F64(f64::from_bits(value)))
            }
            _ => Err(BitVecError::ConversionError),
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

    /// The value rounded to an integer by `rm`, as `fp.to_ubv` / `fp.to_sbv`
    /// round before converting. [`Self::to_signed_bigint`] and
    /// [`Self::to_unsigned_biguint`] truncate, which is only `TowardZero`.
    fn round_integral(&self, rm: FPRM) -> Option<f64> {
        self.round_to_integral(rm).to_f64()
    }

    /// The value rounded to an integer by `rm`, exactly and at any width.
    /// NaN and infinities have no integer value and are an error.
    pub fn to_signed_bigint_rm(&self, rm: FPRM) -> Result<BigInt, BitVecError> {
        self.round_integral(rm)
            .and_then(BigInt::from_f64)
            .ok_or(BitVecError::ConversionError)
    }

    /// As [`Self::to_signed_bigint_rm`], for a non-negative result; a value
    /// that rounds below zero is an error.
    pub fn to_unsigned_biguint_rm(&self, rm: FPRM) -> Result<BigUint, BitVecError> {
        self.round_integral(rm)
            .and_then(BigUint::from_f64)
            .ok_or(BitVecError::ConversionError)
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
        match fsort {
            F32_SORT | F64_SORT => {
                let neg = value.sign() == num_bigint::Sign::Minus;
                let mag = value.magnitude().clone();
                Ok(round_exact(neg, mag, 0, false, fsort, fprm))
            }
            _ => {
                let float_value = value.to_f64().ok_or(BitVecError::ConversionError)?;
                Float::from_f64_with_rounding(float_value, fprm, fsort)
            }
        }
    }

    pub fn from_biguint_with_rounding(
        value: &BigUint,
        fsort: FSort,
        fprm: FPRM,
    ) -> Result<Self, BitVecError> {
        Float::from_bigint_with_rounding(&BigInt::from(value.clone()), fsort, fprm)
    }

    /// `value >> shift`, with the guard bit (the highest bit shifted out) and
    /// the sticky bit (whether any bit below the guard bit was set).
    pub fn shift_with_grs(value: BigUint, shift: u64) -> (BigUint, bool, bool) {
        if shift == 0 {
            return (value, false, false);
        }
        let guard = value.bit(shift - 1);
        let sticky = value.trailing_zeros().is_some_and(|tz| tz < shift - 1);
        (value >> shift, guard, sticky)
    }

    /// The square root, rounded by `rm`.
    pub fn sqrt(&self, rm: FPRM) -> Self {
        // A zero, a negative value, NaN and the infinities take the host's root
        let Some((false, xm, xe)) = exact(self).filter(|(_, m, _)| !m.is_zero()) else {
            return match self {
                Float::F32(f) => Float::F32(f.sqrt()),
                Float::F64(f) => Float::F64(f.sqrt()),
            };
        };
        // An even exponent, and enough bits for the significand plus a rounding bit
        let want = 2 * (i64::from(self.fsort().mantissa) + 3);
        let mut k = (want - xm.bits() as i64).max(0);
        if (xe - k) % 2 != 0 {
            k += 1;
        }
        let n = xm << k as u64;
        let r = n.sqrt();
        let sticky = &r * &r != n;
        round_exact(false, r, (xe - k) / 2, sticky, self.fsort(), rm)
    }

    pub fn abs(&self) -> Self {
        match self {
            Float::F32(f) => Float::F32(f.abs()),
            Float::F64(f) => Float::F64(f.abs()),
        }
    }

    /// The value rounded to an integral value by `rm`, in the same format.
    /// Zeros keep their sign, and NaN and infinities are returned unchanged.
    pub fn round_to_integral(&self, rm: FPRM) -> Self {
        fn round(value: f64, rm: FPRM) -> f64 {
            match rm {
                FPRM::NearestTiesToEven => value.round_ties_even(),
                FPRM::NearestTiesToAway => value.round(),
                FPRM::TowardPositive => value.ceil(),
                FPRM::TowardNegative => value.floor(),
                FPRM::TowardZero => value.trunc(),
            }
        }
        match self {
            // Widening is exact, and so is narrowing an integral value back
            Float::F32(f) => Float::F32(round(f64::from(*f), rm) as f32),
            Float::F64(f) => Float::F64(round(*f, rm)),
        }
    }

    /// `self * b + c` rounded once by `rm`. Both operands are converted to
    /// this value's format.
    pub fn mul_add(&self, b: &Self, c: &Self, rm: FPRM) -> Self {
        let (b, c) = (self.convert_operand(b), self.convert_operand(c));
        let (Some((xn, xm, xe)), Some((yn, ym, ye)), Some(z)) = (exact(self), exact(&b), exact(&c))
        else {
            return match (*self, b, c) {
                (Float::F32(a), Float::F32(b), Float::F32(c)) => Float::F32(a.mul_add(b, c)),
                (Float::F64(a), Float::F64(b), Float::F64(c)) => Float::F64(a.mul_add(b, c)),
                _ => unreachable!(),
            };
        };
        round_sum((xn != yn, xm * ym, xe + ye), z, self.fsort(), rm)
    }

    /// `fp.min`: a NaN operand yields the other one. SMT-LIB leaves a
    /// `+0`/`-0` pair unspecified; this orders `-0` below `+0`, as IEEE
    /// 754-2019 `minimum` does.
    pub fn min(&self, other: &Self) -> Self {
        self.min_max(other, false)
    }

    /// `fp.max`, with the same NaN and signed-zero rules as [`Float::min`].
    pub fn max(&self, other: &Self) -> Self {
        self.min_max(other, true)
    }

    fn min_max(&self, other: &Self, max: bool) -> Self {
        if self.is_nan() {
            return *other;
        }
        if other.is_nan() {
            return *self;
        }
        let less = if self.is_zero() && other.is_zero() {
            self.sign() && !other.sign()
        } else {
            self.lt(other)
        };
        if less != max { *self } else { *other }
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

// Correctly rounded arithmetic in every rounding mode: each operation computes
// its exact result as `±mag * 2^exp` (plus a sticky bit for division and square
// root) and rounds it once with `round_exact`. Only f32 and f64 are supported.

/// A finite value as `(negative, mag, exp)`, its value being `±mag * 2^exp`;
/// `None` for NaN and the infinities.
fn exact(v: &Float) -> Option<(bool, BigUint, i64)> {
    let f = match *v {
        Float::F32(f) => f64::from(f),
        Float::F64(f) => f,
    };
    if !f.is_finite() {
        return None;
    }
    let (sign, biased, frac) = decompose_f64(f);
    let (mag, exp) = if biased == 0 {
        (frac, -1074)
    } else {
        (frac | (1 << 52), i64::from(biased) - 1075)
    };
    Some((sign == 1, BigUint::from(mag), exp))
}

/// `±mag * 2^exp`, with `sticky` set if nonzero bits below `mag` were
/// dropped, rounded to `fsort` by `rm`.
fn round_exact(neg: bool, mag: BigUint, exp: i64, sticky: bool, fsort: FSort, rm: FPRM) -> Float {
    let p = i64::from(fsort.mantissa) + 1;
    let bias = (1i64 << (fsort.exponent - 1)) - 1;
    let emin = 1 - bias;
    let max_biased = (1i64 << fsort.exponent) - 2;
    let frac_bits = fsort.mantissa as u64;
    let build = |biased: i64, frac: u64| {
        let sign = u8::from(neg);
        if fsort == F32_SORT {
            Float::F32(recompose_f32(sign, biased as u8, frac as u32))
        } else {
            Float::F64(recompose_f64(sign, biased as u16, frac))
        }
    };
    if mag.is_zero() {
        return build(0, 0);
    }

    // The exponent of the lowest bit kept, clamped for subnormals
    let top = exp + mag.bits() as i64 - 1;
    let mut q = (top - (p - 1)).max(emin - (p - 1));
    let (mut keep, half, rest) = if q > exp {
        let (keep, half, rest) = Float::shift_with_grs(mag, (q - exp) as u64);
        (keep, half, rest || sticky)
    } else {
        (mag << (exp - q) as u64, false, sticky)
    };
    let up = match rm {
        FPRM::NearestTiesToEven => half && (rest || keep.bit(0)),
        FPRM::NearestTiesToAway => half,
        FPRM::TowardPositive => !neg && (half || rest),
        FPRM::TowardNegative => neg && (half || rest),
        FPRM::TowardZero => false,
    };
    if up {
        keep += 1u32;
        if keep.bits() as i64 > p {
            keep >>= 1;
            q += 1;
        }
    }

    let (biased, frac) = if keep.bit(frac_bits) {
        (q + (p - 1) + bias, keep - (BigUint::one() << frac_bits))
    } else {
        (0, keep)
    };
    if biased > max_biased {
        let to_inf = match rm {
            FPRM::NearestTiesToEven | FPRM::NearestTiesToAway => true,
            FPRM::TowardPositive => !neg,
            FPRM::TowardNegative => neg,
            FPRM::TowardZero => false,
        };
        return if to_inf {
            build(max_biased + 1, 0)
        } else {
            build(max_biased, (1 << frac_bits) - 1)
        };
    }
    build(biased, frac.iter_u64_digits().next().unwrap_or(0))
}

/// `x + y` rounded once. An exact zero sum is `-0` when both terms are `-0`,
/// and otherwise only toward negative.
fn round_sum(
    (xn, xm, xe): (bool, BigUint, i64),
    (yn, ym, ye): (bool, BigUint, i64),
    fsort: FSort,
    rm: FPRM,
) -> Float {
    let zero_neg = if xm.is_zero() && ym.is_zero() && xn == yn {
        xn
    } else {
        rm == FPRM::TowardNegative
    };
    let e = xe.min(ye);
    let xm = xm << (xe - e) as u64;
    let ym = ym << (ye - e) as u64;
    let (neg, mag) = if xn == yn {
        (xn, xm + ym)
    } else if xm >= ym {
        (xn, xm - ym)
    } else {
        (yn, ym - xm)
    };
    let neg = if mag.is_zero() { zero_neg } else { neg };
    round_exact(neg, mag, e, false, fsort, rm)
}

#[cfg(test)]
mod tests {
    #[test]
    fn mul_add_f32_rounds_once() {
        // (1 + 2^-12)^2 = 1 + 2^-11 + 2^-24 is exactly halfway between two
        // f32s, so the sign of a tiny addend decides the rounding. Rounding
        // the sum to f64 first would lose it and tie to even.
        let a = Float::F32(1.0 + 2f32.powi(-12));
        let tiny = Float::F32(2f32.powi(-100));
        let up = 1.0 + 2f32.powi(-11) + 2f32.powi(-23);
        let down = 1.0 + 2f32.powi(-11);
        let rne = FPRM::NearestTiesToEven;
        assert_eq!(a.mul_add(&a, &tiny, rne), Float::F32(up));
        assert_eq!(a.mul_add(&a, &-tiny, rne), Float::F32(down));

        let x = Float::F64(0.1);
        assert_eq!(
            x.mul_add(&Float::F64(10.0), &Float::F64(-1.0), rne),
            Float::F64(0.1f64.mul_add(10.0, -1.0))
        );
    }

    #[test]
    fn round_to_integral_keeps_format_and_sign() {
        let f = Float::F32(2.5);
        assert_eq!(
            f.round_to_integral(FPRM::NearestTiesToEven),
            Float::F32(2.0)
        );
        assert_eq!(
            f.round_to_integral(FPRM::NearestTiesToAway),
            Float::F32(3.0)
        );
        assert_eq!(f.round_to_integral(FPRM::TowardNegative), Float::F32(2.0));
        let neg = Float::F64(-0.4).round_to_integral(FPRM::NearestTiesToEven);
        assert!(neg.is_zero() && neg.sign());
        assert!(
            Float::F64(f64::NAN)
                .round_to_integral(FPRM::TowardZero)
                .is_nan()
        );
    }

    #[test]
    fn mul_add_rounds_by_mode() {
        use FPRM::*;
        let modes = [
            NearestTiesToEven,
            NearestTiesToAway,
            TowardPositive,
            TowardNegative,
            TowardZero,
        ];
        let p = |e: i32| 2f64.powi(e);
        let check = |a: f64, b: f64, c: f64, want: [f64; 5]| {
            for (rm, want) in modes.iter().zip(want) {
                let got = Float::F64(a).mul_add(&Float::F64(b), &Float::F64(c), *rm);
                assert_eq!(
                    got.to_f64().unwrap().to_bits(),
                    want.to_bits(),
                    "{a} * {b} + {c} under {rm:?}"
                );
            }
        };
        // Inexact: the low 2^-60 is below half an ulp
        let (lo, hi) = (1.0 + p(-29), 1.0 + p(-29) + p(-52));
        check(1.0 + p(-30), 1.0 + p(-30), 0.0, [lo, lo, hi, lo, lo]);
        check(
            -(1.0 + p(-30)),
            1.0 + p(-30),
            0.0,
            [-lo, -lo, -lo, -hi, -lo],
        );
        // A tie: 2^-53 is exactly half an ulp
        let (lo, hi) = (1.0 + p(-26) + p(-27), 1.0 + p(-26) + p(-27) + p(-52));
        check(1.0 + p(-26), 1.0 + p(-27), 0.0, [lo, hi, hi, lo, lo]);
        // Overflow: only the modes rounding away from zero reach infinity
        let inf = f64::INFINITY;
        check(f64::MAX, 2.0, 0.0, [inf, inf, inf, f64::MAX, f64::MAX]);
        check(
            -f64::MAX,
            2.0,
            0.0,
            [-inf, -inf, -f64::MAX, -inf, -f64::MAX],
        );
        // An exact zero from opposite signs is -0 only toward negative
        check(1.0, 1.0, -1.0, [0.0, 0.0, 0.0, -0.0, 0.0]);
        check(-1.0, 1.0, 1.0, [0.0, 0.0, 0.0, -0.0, 0.0]);
        // Zero terms of one sign keep it in every mode
        check(-0.0, 1.0, -0.0, [-0.0; 5]);
        check(0.0, 1.0, 0.0, [0.0; 5]);
        // Underflow: half the smallest subnormal ties to even 0, away to it
        let tiny = f64::from_bits(1);
        check(tiny, 0.5, 0.0, [0.0, tiny, tiny, 0.0, 0.0]);

        // f32: (1 + 2^-12)^2 is a tie in f32
        let a = Float::F32(1.0 + 2f32.powi(-12));
        let (lo, hi) = (1.0 + 2f32.powi(-11), 1.0 + 2f32.powi(-11) + 2f32.powi(-23));
        for (rm, want) in modes.iter().zip([lo, hi, hi, lo, lo]) {
            assert_eq!(
                a.mul_add(&a, &Float::F32(0.0), *rm),
                Float::F32(want),
                "{rm:?}"
            );
        }
    }

    #[test]
    fn mixed_operands_round_in_self_format() {
        use super::*;
        let a = Float::F32(1.5);
        let rm = FPRM::TowardPositive;
        for b in [1e-30, 0.0, f64::INFINITY, f64::NAN].map(Float::F64) {
            for r in [a.add_rm(&b, rm), a.mul_rm(&b, rm), a.div_rm(&b, rm)] {
                assert!(matches!(r, Float::F32(_)), "{a:?} op {b:?} gave {r:?}");
            }
            let r = a.mul_add(&b, &b, rm);
            assert!(matches!(r, Float::F32(_)), "fma {a:?} {b:?} gave {r:?}");
        }
    }

    #[test]
    fn min_max_follow_fp_min_max() {
        let (one, two) = (Float::F64(1.0), Float::F64(2.0));
        let nan = Float::F64(f64::NAN);
        assert_eq!(one.min(&two), one);
        assert_eq!(one.max(&two), two);
        assert_eq!(nan.min(&two), two);
        assert_eq!(two.max(&nan), two);
        let (pz, nz) = (Float::F64(0.0), Float::F64(-0.0));
        for (a, b) in [(pz, nz), (nz, pz)] {
            assert!(a.min(&b).sign(), "min of {a:?}, {b:?}");
            assert!(!a.max(&b).sign(), "max of {a:?}, {b:?}");
        }
        assert!(nz.max(&nz).sign());
    }

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
        let (pos_zero, neg_zero) = (Float::F32(0.0), Float::F32(-0.0));
        assert!(pos_zero.eq_ieee_754(&neg_zero));
        assert!(neg_zero.eq_ieee_754(&pos_zero));
        assert!(pos_zero.eq_ieee_754(&Float::F64(-0.0)));
        let nan = Float::F64(f64::NAN);
        assert!(!nan.eq_ieee_754(&nan));
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

    #[test]
    fn test_to_ieee_bits() {
        let f32_values: &[f32] = &[0.0, -0.0, 1.0, -1.0, 42.0, f32::INFINITY, f32::NAN];
        for &value in f32_values {
            let bits = Float::F32(value).to_ieee_bits();
            assert_eq!(bits.len(), 32);
            assert_eq!(bits.to_u64().unwrap() as u32, value.to_bits());
        }

        let f64_values: &[f64] = &[0.0, -0.0, 1.0, -1.0, 42.0, f64::INFINITY, f64::NAN];
        for &value in f64_values {
            let bits = Float::F64(value).to_ieee_bits();
            assert_eq!(bits.len(), 64);
            assert_eq!(bits.to_u64().unwrap(), value.to_bits());
        }
    }

    #[test]
    fn test_ieee_bits_round_trip() -> Result<(), BitVecError> {
        let f32_values: &[f32] = &[
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
            f32::MIN_POSITIVE,
        ];
        for &value in f32_values {
            let start = Float::F32(value);
            let round_trip = Float::try_from_ieee_bits(&start.to_ieee_bits())?;
            assert_eq!(round_trip.fsort(), F32_SORT);
            let result = round_trip.to_f32().unwrap();
            if value.is_nan() {
                assert!(result.is_nan());
            } else {
                assert_eq!(result.to_bits(), value.to_bits());
            }
        }

        let f64_values: &[f64] = &[
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
            f64::MIN_POSITIVE,
        ];
        for &value in f64_values {
            let start = Float::F64(value);
            let round_trip = Float::try_from_ieee_bits(&start.to_ieee_bits())?;
            assert_eq!(round_trip.fsort(), F64_SORT);
            let result = round_trip.to_f64().unwrap();
            if value.is_nan() {
                assert!(result.is_nan());
            } else {
                assert_eq!(result.to_bits(), value.to_bits());
            }
        }

        Ok(())
    }

    #[test]
    fn test_try_from_ieee_bits_invalid_width() {
        // Only 32- and 64-bit widths map onto the supported float formats.
        assert!(Float::try_from_ieee_bits(&BitVec::zeros(16)).is_err());
        assert!(Float::try_from_ieee_bits(&BitVec::zeros(31)).is_err());
        assert!(Float::try_from_ieee_bits(&BitVec::zeros(128)).is_err());
    }
}
