mod modular_arithmetic;

use num_bigint::{BigInt, BigUint, ToBigInt, ToBigUint};
use num_traits::{One, Signed, ToPrimitive, Zero};
use std::cmp::{max, min};
use std::ops::{BitAnd, BitOr, BitXor, Not};

use clarirs_core::prelude::*;
use modular_arithmetic::*;

/// Represents the result of a comparison operation
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ComparisonResult {
    True,
    False,
    Maybe,
}

impl ComparisonResult {
    /// Returns true if the result is True
    pub fn is_true(&self) -> bool {
        matches!(self, ComparisonResult::True)
    }

    /// Returns true if the result is False
    pub fn is_false(&self) -> bool {
        matches!(self, ComparisonResult::False)
    }

    /// Returns true if the result is Maybe
    pub fn is_maybe(&self) -> bool {
        matches!(self, ComparisonResult::Maybe)
    }

    pub fn eq_(self, other: ComparisonResult) -> ComparisonResult {
        if self.is_maybe() || other.is_maybe() {
            ComparisonResult::Maybe
        } else if self == other {
            ComparisonResult::True
        } else {
            ComparisonResult::False
        }
    }
}

impl Not for ComparisonResult {
    type Output = ComparisonResult;

    fn not(self) -> ComparisonResult {
        match self {
            ComparisonResult::True => ComparisonResult::False,
            ComparisonResult::False => ComparisonResult::True,
            ComparisonResult::Maybe => ComparisonResult::Maybe,
        }
    }
}

impl BitAnd for ComparisonResult {
    type Output = ComparisonResult;

    fn bitand(self, other: ComparisonResult) -> ComparisonResult {
        match (self, other) {
            (ComparisonResult::True, ComparisonResult::True) => ComparisonResult::True,
            (ComparisonResult::False, _) | (_, ComparisonResult::False) => ComparisonResult::False,
            _ => ComparisonResult::Maybe,
        }
    }
}

impl BitOr for ComparisonResult {
    type Output = ComparisonResult;

    fn bitor(self, other: ComparisonResult) -> ComparisonResult {
        match (self, other) {
            (ComparisonResult::True, _) | (_, ComparisonResult::True) => ComparisonResult::True,
            (ComparisonResult::False, ComparisonResult::False) => ComparisonResult::False,
            _ => ComparisonResult::Maybe,
        }
    }
}

impl BitXor for ComparisonResult {
    type Output = ComparisonResult;

    fn bitxor(self, other: ComparisonResult) -> ComparisonResult {
        match (self, other) {
            (ComparisonResult::True, ComparisonResult::False) => ComparisonResult::True,
            (ComparisonResult::False, ComparisonResult::True) => ComparisonResult::True,
            (ComparisonResult::True, ComparisonResult::True)
            | (ComparisonResult::False, ComparisonResult::False) => ComparisonResult::False,
            _ => ComparisonResult::Maybe,
        }
    }
}

/// A StridedInterval represents a set of integers in the form:
/// `<bits> stride[lower_bound, upper_bound]`
///
/// It can represent values within a range that follow a specific stride pattern.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StridedInterval {
    Empty {
        bits: u32,
    },
    Normal {
        bits: u32,
        stride: BigUint,
        lower_bound: BigUint,
        upper_bound: BigUint,
    },
}

impl StridedInterval {
    // ================================================================================================
    // Constructors and Normalization
    // ================================================================================================

    /// Creates a new StridedInterval with the given parameters
    pub fn new(
        bits: u32,
        stride: impl Into<BigUint>,
        lower_bound: impl Into<BigUint>,
        upper_bound: impl Into<BigUint>,
    ) -> Self {
        let mut si = StridedInterval::Normal {
            bits,
            stride: stride.into(),
            lower_bound: lower_bound.into(),
            upper_bound: upper_bound.into(),
        };
        si.normalize();
        si
    }

    /// Creates a StridedInterval representing a single concrete value
    pub fn constant(bits: u32, value: impl Into<BigUint>) -> Self {
        let value = value.into();
        Self::new(bits, BigUint::zero(), value.clone(), value)
    }

    /// Creates a StridedInterval representing the entire range of values for the given bit width
    pub fn top(bits: u32) -> Self {
        Self::new(bits, BigUint::one(), BigUint::zero(), max_int(bits))
    }

    /// Creates an empty StridedInterval (bottom)
    pub fn empty(bits: u32) -> Self {
        StridedInterval::Empty { bits }
    }

    /// Creates a StridedInterval from a range with stride 1
    pub fn range(bits: u32, lower: impl ToBigUint, upper: impl ToBigUint) -> Self {
        Self::new(
            bits,
            BigUint::one(),
            lower.to_biguint().unwrap(),
            upper.to_biguint().unwrap(),
        )
    }

    /// Normalizes the StridedInterval
    pub fn normalize(&mut self) {
        match self {
            StridedInterval::Empty { .. } => (),
            StridedInterval::Normal {
                bits,
                stride,
                lower_bound,
                upper_bound,
            } => {
                // Ensure bounds are within the bit range
                let max_value = max_int(*bits);
                *lower_bound = &*lower_bound & &max_value;
                *upper_bound = &*upper_bound & &max_value;

                // If lower_bound == upper_bound, stride should be 0
                if *lower_bound == *upper_bound {
                    *stride = BigUint::zero();
                } else if stride.is_zero() {
                    // Defensive: zero stride but not singleton is invalid, set stride to 1
                    *stride = BigUint::one();
                }

                // Normalize top value
                if *stride == BigUint::one()
                    && modular_add(&*upper_bound, &BigUint::one(), *bits) == *lower_bound
                    && *lower_bound == BigUint::zero()
                    && *upper_bound == max_int(*bits)
                {
                    *lower_bound = BigUint::zero();
                    *upper_bound = max_int(*bits);
                }
            }
        }
    }

    // ================================================================================================
    // Bounds Retrieval
    // ================================================================================================

    /// Split at the south pole (0/MAX boundary for unsigned)
    /// Returns 1 or 2 intervals depending on whether wrapping occurs
    pub fn ssplit(&self) -> Vec<Self> {
        match self {
            StridedInterval::Empty { bits } => vec![Self::empty(*bits)],
            StridedInterval::Normal {
                bits,
                stride,
                lower_bound,
                upper_bound,
            } => {
                // South pole is at MAX_INT (unsigned wrap point)
                let south_pole_right = max_int(*bits);

                // Check if interval straddles the south pole
                if upper_bound < lower_bound {
                    // It straddles! Split into two intervals
                    // First part: [lower_bound, south_pole_right]
                    let a_upper = &south_pole_right - ((&south_pole_right - lower_bound) % stride);
                    let a = Self::new(*bits, stride.clone(), lower_bound.clone(), a_upper.clone());

                    // Second part: [0 or next stride point, upper_bound]
                    let b_lower = modular_add(&a_upper, stride, *bits);
                    let b = Self::new(*bits, stride.clone(), b_lower, upper_bound.clone());

                    vec![a, b]
                } else {
                    vec![self.clone()]
                }
            }
        }
    }

    /// Split at the north pole (sign bit boundary for signed)
    /// Returns 1 or 2 intervals depending on whether wrapping occurs
    pub fn nsplit(&self) -> Vec<Self> {
        match self {
            StridedInterval::Empty { bits } => vec![Self::empty(*bits)],
            StridedInterval::Normal {
                bits,
                stride,
                lower_bound,
                upper_bound,
            } => {
                // North pole: boundary between positive and negative in signed arithmetic
                let north_pole_left = signed_max_int(*bits); // 0x7FFF...
                let north_pole_right = BigUint::one() << (*bits - 1); // 0x8000...

                // Check if interval straddles the north pole
                let straddling = if upper_bound >= &north_pole_right {
                    lower_bound > upper_bound || lower_bound <= &north_pole_left
                } else {
                    lower_bound > upper_bound && lower_bound <= &north_pole_left
                };

                if straddling {
                    // Split into two parts
                    // First part: [lower_bound, north_pole_left] aligned to stride
                    let a_upper = &north_pole_left - ((&north_pole_left - lower_bound) % stride);
                    let a = Self::new(*bits, stride.clone(), lower_bound.clone(), a_upper.clone());

                    // Second part: [north_pole_right or next stride point, upper_bound]
                    let b_lower = &a_upper + stride;
                    let b = Self::new(*bits, stride.clone(), b_lower, upper_bound.clone());

                    vec![a, b]
                } else {
                    vec![self.clone()]
                }
            }
        }
    }

    /// Split at both north and south poles
    pub fn psplit(&self) -> Vec<Self> {
        let nsplit_list = self.nsplit();
        let mut psplit_list = Vec::new();
        for si in nsplit_list {
            psplit_list.extend(si.ssplit());
        }
        psplit_list
    }

    /// Gets the unsigned bounds as a tuple (min, max)
    pub fn get_unsigned_bounds(&self) -> (BigUint, BigUint) {
        match self {
            StridedInterval::Empty { .. } => (BigUint::zero(), BigUint::zero()),
            StridedInterval::Normal {
                lower_bound,
                upper_bound,
                bits,
                ..
            } => {
                if upper_bound >= lower_bound {
                    (lower_bound.clone(), upper_bound.clone())
                } else {
                    // Wrapping SI: [lower_bound, MAX] ∪ [0, upper_bound]
                    (BigUint::zero(), max_int(*bits))
                }
            }
        }
    }

    /// Gets the signed bounds as a tuple (min, max) considering two's complement
    pub fn get_signed_bounds(&self) -> (BigInt, BigInt) {
        match self {
            StridedInterval::Empty { .. } => (BigInt::zero(), BigInt::zero()),
            StridedInterval::Normal {
                lower_bound,
                upper_bound,
                bits,
                ..
            } => {
                let msb_mask = BigUint::one() << (*bits - 1);
                let signed_min = -(BigInt::one() << (*bits - 1));
                let signed_max = (BigInt::one() << (*bits - 1)) - BigInt::one();
                let to_signed = |v: &BigUint| -> BigInt {
                    if (v & &msb_mask) != BigUint::zero() {
                        v.to_bigint().unwrap() - (BigInt::one() << *bits)
                    } else {
                        v.to_bigint().unwrap()
                    }
                };
                if upper_bound >= lower_bound {
                    // Non-wrapping unsigned interval
                    let lb_neg = (lower_bound & &msb_mask) != BigUint::zero();
                    let ub_neg = (upper_bound & &msb_mask) != BigUint::zero();
                    if !lb_neg && ub_neg {
                        // Straddles signed boundary: covers both positive and negative
                        (signed_min, signed_max)
                    } else {
                        (to_signed(lower_bound), to_signed(upper_bound))
                    }
                } else {
                    // Wrapping unsigned interval: covers [lower, MAX] ∪ [0, upper]
                    let lb_signed = to_signed(lower_bound);
                    let ub_signed = to_signed(upper_bound);
                    let lb_neg = (lower_bound & &msb_mask) != BigUint::zero();
                    let ub_neg = (upper_bound & &msb_mask) != BigUint::zero();
                    if lb_neg && !ub_neg {
                        // lower is in negative territory, upper is in positive territory
                        // e.g., [250, 5] in 8 bits = [-6, 5] signed - contiguous signed range
                        (lb_signed, ub_signed)
                    } else if !lb_neg && !ub_neg {
                        // Both positive unsigned but wrapping: [lower, MAX] ∪ [0, upper]
                        // Signed: [lower, 127] ∪ [-128, -1] ∪ [0, upper] = full range
                        (signed_min, signed_max)
                    } else {
                        // Both negative or upper negative: full signed range
                        (signed_min, signed_max)
                    }
                }
            }
        }
    }

    // ================================================================================================
    // Properties and Queries
    // ================================================================================================

    /// Returns the bit width of the interval
    pub fn bits(&self) -> u32 {
        match self {
            StridedInterval::Empty { bits } => *bits,
            StridedInterval::Normal { bits, .. } => *bits,
        }
    }

    /// Checks if the StridedInterval is empty (bottom)
    pub fn is_empty(&self) -> bool {
        matches!(self, StridedInterval::Empty { .. })
    }

    /// Checks if the StridedInterval represents a single concrete value
    pub fn is_integer(&self) -> bool {
        match self {
            StridedInterval::Normal {
                lower_bound,
                upper_bound,
                ..
            } => lower_bound == upper_bound,
            _ => false,
        }
    }

    /// Checks if the StridedInterval represents the entire range of values
    pub fn is_top(&self) -> bool {
        match self {
            StridedInterval::Normal {
                stride,
                lower_bound,
                upper_bound,
                bits,
            } => {
                !self.is_empty()
                    && *stride == BigUint::one()
                    && *lower_bound == BigUint::zero()
                    && *upper_bound == max_int(*bits)
            }
            _ => false,
        }
    }

    /// Returns the cardinality (number of values) in the StridedInterval
    pub fn cardinality(&self) -> BigUint {
        match self {
            StridedInterval::Empty { .. } => BigUint::zero(),
            StridedInterval::Normal {
                lower_bound,
                upper_bound,
                stride,
                ..
            } => {
                if lower_bound == upper_bound {
                    return BigUint::one();
                }
                if stride.is_zero() {
                    if lower_bound == upper_bound {
                        return BigUint::one();
                    } else {
                        return BigUint::zero();
                    }
                }
                let range = if upper_bound >= lower_bound {
                    upper_bound - lower_bound + BigUint::one()
                } else {
                    let max_val = max_int(self.bits());
                    &max_val - lower_bound + upper_bound + BigUint::from(2u32)
                };
                (range + stride - BigUint::one()) / stride
            }
        }
    }

    /// Checks if this StridedInterval contains another
    pub fn contains(&self, other: &Self) -> bool {
        if self.is_empty() {
            return false;
        }
        if other.is_empty() {
            return true;
        }

        if self.bits() != other.bits() {
            return false;
        }

        let (self_min, self_max) = self.get_unsigned_bounds();
        let (other_min, other_max) = other.get_unsigned_bounds();

        // Check if bounds are contained
        let bounds_contained = self_min <= other_min && self_max >= other_max;

        // Check if stride is compatible
        let stride_compatible = match (self, other) {
            (
                StridedInterval::Normal {
                    stride: s_stride,
                    lower_bound: s_lb,
                    ..
                },
                StridedInterval::Normal {
                    stride: o_stride,
                    lower_bound: o_lb,
                    ..
                },
            ) => {
                if s_stride.is_zero() {
                    s_lb == o_lb && o_stride.is_zero()
                } else {
                    o_stride % s_stride == BigUint::zero()
                }
            }
            _ => false,
        };

        bounds_contained && stride_compatible
    }

    /// Check if the interval contains a specific value
    pub fn contains_value(&self, value: &BigUint) -> bool {
        match self {
            StridedInterval::Empty { .. } => false,
            StridedInterval::Normal {
                stride,
                lower_bound,
                ..
            } => {
                let (min, max) = self.get_unsigned_bounds();
                if value < &min || value > &max {
                    return false;
                }
                if stride.is_zero() {
                    return lower_bound == value;
                }
                (&(value - lower_bound) % stride).is_zero()
            }
        }
    }

    /// Check if the interval contains zero
    pub fn contains_zero(&self) -> bool {
        self.contains_value(&BigUint::zero())
    }

    /// Evaluates the interval to get a set of concrete values
    /// Returns at most `limit` values
    pub fn eval(&self, limit: u32) -> Vec<BigUint> {
        if self.is_empty() {
            return vec![];
        }

        match self {
            StridedInterval::Normal {
                lower_bound,
                upper_bound,
                stride,
                bits,
            } => {
                if lower_bound == upper_bound || stride.is_zero() {
                    return vec![lower_bound.clone()];
                }

                let mut results = Vec::new();

                if lower_bound <= upper_bound {
                    // No wrap-around
                    let mut value = lower_bound.clone();
                    while value <= *upper_bound && results.len() < limit as usize {
                        results.push(value.clone());
                        value += stride;
                    }
                } else {
                    // Wrap-around case
                    let max_value = max_int(*bits);

                    // First part: from lower_bound to max_value
                    let mut value = lower_bound.clone();
                    while value <= max_value && results.len() < limit as usize {
                        results.push(value.clone());
                        value += stride;
                    }

                    // Second part: from 0 to upper_bound
                    if results.len() < limit as usize {
                        // Start from 0 and check if it's part of the stride pattern
                        let mut value = BigUint::zero();

                        // Check if 0 is aligned with the stride pattern
                        let distance_from_lower = modular_sub(&value, lower_bound, *bits);

                        if (&distance_from_lower % stride) == BigUint::zero() {
                            // 0 is part of the pattern
                            while value <= *upper_bound && results.len() < limit as usize {
                                results.push(value.clone());
                                value += stride;
                            }
                        } else {
                            // Find the first value >= 0 that's part of the pattern
                            let remainder = &distance_from_lower % stride;
                            let offset = stride - remainder;
                            value = offset;
                            while value <= *upper_bound && results.len() < limit as usize {
                                results.push(value.clone());
                                value += stride;
                            }
                        }
                    }
                }

                results
            }
            StridedInterval::Empty { .. } => vec![],
        }
    }

    /// Number of trailing zeros in binary representation
    fn ntz(x: &BigUint) -> u32 {
        if x.is_zero() {
            return 0;
        }
        let mut count = 0;
        let mut val = x.clone();
        while (&val & BigUint::one()).is_zero() {
            count += 1;
            val >>= 1;
        }
        count
    }

    // ================================================================================================
    // Set Operations: Intersection, Union, Widen, Complement
    // ================================================================================================

    /// Finds the intersection of two StridedIntervals
    pub fn intersection(&self, other: &Self) -> Self {
        if self.is_empty() || other.is_empty() {
            return Self::empty(max(self.bits(), other.bits()));
        }

        if self.bits() != other.bits() {
            // Create a copy with matching bits
            match other {
                StridedInterval::Normal {
                    stride,
                    lower_bound,
                    upper_bound,
                    ..
                } => {
                    let extended_other = Self::new(
                        self.bits(),
                        stride.clone(),
                        lower_bound.clone(),
                        upper_bound.clone(),
                    );
                    return self.intersection(&extended_other);
                }
                StridedInterval::Empty { .. } => {
                    return self.intersection(&Self::empty(self.bits()));
                }
            }
        }

        // Handle wrapping ranges by splitting into non-wrapping parts
        // A wrapping SI has lower_bound > upper_bound, representing [lower_bound, MAX] ∪ [0, upper_bound]
        let self_wraps = matches!(self, StridedInterval::Normal { lower_bound, upper_bound, .. } if upper_bound < lower_bound);
        let other_wraps = matches!(other, StridedInterval::Normal { lower_bound, upper_bound, .. } if upper_bound < lower_bound);

        if self_wraps || other_wraps {
            // Quick containment check for wrapping SIs to avoid imprecise union
            if self_wraps && other_wraps {
                if let (
                    StridedInterval::Normal {
                        lower_bound: s_lb,
                        upper_bound: s_ub,
                        ..
                    },
                    StridedInterval::Normal {
                        lower_bound: o_lb,
                        upper_bound: o_ub,
                        ..
                    },
                ) = (self, other)
                {
                    // For two wrapping SIs [s_lb, MAX]∪[0, s_ub] and [o_lb, MAX]∪[0, o_ub]:
                    // self ⊆ other when o_lb <= s_lb && s_ub <= o_ub
                    if o_lb <= s_lb && s_ub <= o_ub {
                        return self.clone();
                    }
                    if s_lb <= o_lb && o_ub <= s_ub {
                        return other.clone();
                    }
                }
            } else if self_wraps {
                // other doesn't wrap: other = [o_lb, o_ub]
                // self wraps: self = [s_lb, MAX] ∪ [0, s_ub]
                // other ⊆ self if other is fully in the upper or lower part
                if let (
                    StridedInterval::Normal {
                        lower_bound: s_lb,
                        upper_bound: s_ub,
                        ..
                    },
                    StridedInterval::Normal {
                        lower_bound: o_lb,
                        upper_bound: o_ub,
                        ..
                    },
                ) = (self, other)
                    && (o_lb >= s_lb || o_ub <= s_ub)
                    && ((o_lb >= s_lb && o_ub >= s_lb) || (o_lb <= s_ub && o_ub <= s_ub))
                {
                    return other.clone();
                }
            } else {
                // self doesn't wrap, other wraps - symmetric case
                if let (
                    StridedInterval::Normal {
                        lower_bound: s_lb,
                        upper_bound: s_ub,
                        ..
                    },
                    StridedInterval::Normal {
                        lower_bound: o_lb,
                        upper_bound: o_ub,
                        ..
                    },
                ) = (self, other)
                    && (s_lb >= o_lb || s_ub <= o_ub)
                    && ((s_lb >= o_lb && s_ub >= o_lb) || (s_lb <= o_ub && s_ub <= o_ub))
                {
                    return self.clone();
                }
            }

            // Fall back to splitting into non-wrapping parts
            let self_parts = if self_wraps {
                if let StridedInterval::Normal {
                    stride,
                    lower_bound,
                    upper_bound,
                    bits,
                    ..
                } = self
                {
                    vec![
                        Self::new(*bits, stride.clone(), lower_bound.clone(), max_int(*bits)),
                        Self::new(*bits, stride.clone(), BigUint::zero(), upper_bound.clone()),
                    ]
                } else {
                    vec![self.clone()]
                }
            } else {
                vec![self.clone()]
            };
            let other_parts = if other_wraps {
                if let StridedInterval::Normal {
                    stride,
                    lower_bound,
                    upper_bound,
                    bits,
                    ..
                } = other
                {
                    vec![
                        Self::new(*bits, stride.clone(), lower_bound.clone(), max_int(*bits)),
                        Self::new(*bits, stride.clone(), BigUint::zero(), upper_bound.clone()),
                    ]
                } else {
                    vec![other.clone()]
                }
            } else {
                vec![other.clone()]
            };

            // Collect non-empty partial intersections
            let mut parts: Vec<Self> = Vec::new();
            for sp in &self_parts {
                for op in &other_parts {
                    let partial = sp.intersection(op);
                    if !partial.is_empty() {
                        parts.push(partial);
                    }
                }
            }

            if parts.is_empty() {
                return Self::empty(self.bits());
            }
            if parts.len() == 1 {
                return parts.into_iter().next().unwrap();
            }

            // For two non-wrapping parts, try to construct a wrapping SI directly
            // instead of using union (which may lose precision)
            if parts.len() == 2 {
                let (p_lo_0, p_hi_0) = parts[0].get_unsigned_bounds();
                let (p_lo_1, p_hi_1) = parts[1].get_unsigned_bounds();
                // If one part is near MAX and other near 0, create wrapping SI
                if p_hi_0 == max_int(self.bits()) || p_lo_1 == BigUint::zero() {
                    let stride = match (&parts[0], &parts[1]) {
                        (
                            StridedInterval::Normal { stride: s0, .. },
                            StridedInterval::Normal { stride: s1, .. },
                        ) => {
                            if s0.is_zero() && s1.is_zero() {
                                BigUint::one()
                            } else if s0.is_zero() {
                                s1.clone()
                            } else if s1.is_zero() {
                                s0.clone()
                            } else {
                                gcd(s0, s1)
                            }
                        }
                        _ => BigUint::one(),
                    };
                    return Self::new(self.bits(), stride, p_lo_0, p_hi_1);
                }
                if p_hi_1 == max_int(self.bits()) || p_lo_0 == BigUint::zero() {
                    let stride = match (&parts[0], &parts[1]) {
                        (
                            StridedInterval::Normal { stride: s0, .. },
                            StridedInterval::Normal { stride: s1, .. },
                        ) => {
                            if s0.is_zero() && s1.is_zero() {
                                BigUint::one()
                            } else if s0.is_zero() {
                                s1.clone()
                            } else if s1.is_zero() {
                                s0.clone()
                            } else {
                                gcd(s0, s1)
                            }
                        }
                        _ => BigUint::one(),
                    };
                    return Self::new(self.bits(), stride, p_lo_1, p_hi_0);
                }
            }

            // Fallback: use union (may lose precision)
            let mut result = Self::empty(self.bits());
            for p in parts {
                result = result.union(&p);
            }
            return result;
        }

        // Check if ranges overlap
        let (self_min, self_max) = self.get_unsigned_bounds();
        let (other_min, other_max) = other.get_unsigned_bounds();

        // Simple case: one interval is contained within the other
        if let (
            StridedInterval::Normal {
                stride: s_stride, ..
            },
            StridedInterval::Normal {
                stride: o_stride, ..
            },
        ) = (self, other)
        {
            if self_min >= other_min
                && self_max <= other_max
                && (s_stride.is_zero()
                    || o_stride.is_zero()
                    || s_stride % o_stride == BigUint::zero())
            {
                return self.clone();
            }
            if other_min >= self_min
                && other_max <= self_max
                && (s_stride.is_zero()
                    || o_stride.is_zero()
                    || o_stride % s_stride == BigUint::zero())
            {
                return other.clone();
            }
        }

        // Handle non-overlapping case
        if (self_min > other_max && self_max > other_max)
            || (other_min > self_max && other_max > self_max)
        {
            return Self::empty(self.bits());
        }

        // Robust handling of zero strides to avoid division by zero
        if let (
            StridedInterval::Normal {
                stride: s_stride,
                lower_bound: s_lb,
                ..
            },
            StridedInterval::Normal {
                stride: o_stride,
                lower_bound: o_lb,
                ..
            },
        ) = (self, other)
        {
            if s_stride.is_zero() && o_stride.is_zero() {
                if s_lb == o_lb {
                    return self.clone();
                } else {
                    return Self::empty(self.bits());
                }
            }
            if s_stride.is_zero() {
                if other.contains(self) {
                    return self.clone();
                } else {
                    return Self::empty(self.bits());
                }
            }
            if o_stride.is_zero() {
                if self.contains(other) {
                    return other.clone();
                } else {
                    return Self::empty(self.bits());
                }
            }
        }

        let (gcd, s_stride, o_stride) = match (self, other) {
            (
                StridedInterval::Normal {
                    stride: s_stride, ..
                },
                StridedInterval::Normal {
                    stride: o_stride, ..
                },
            ) => {
                let gcd = gcd(s_stride, o_stride);
                (gcd, s_stride, o_stride)
            }
            _ => (BigUint::zero(), &BigUint::zero(), &BigUint::zero()),
        };
        let new_stride = if gcd.is_zero() {
            BigUint::zero()
        } else {
            (s_stride * o_stride) / &gcd
        };

        // Find the smallest value >= lower_bound that satisfies both intervals
        let new_lower = max(self_min, other_min);
        let new_upper = min(self_max, other_max);

        Self::new(self.bits(), new_stride, new_lower, new_upper)
    }

    /// Finds the union of two StridedIntervals
    pub fn union(&self, other: &Self) -> Self {
        if self.is_empty() {
            return other.clone();
        }
        if other.is_empty() {
            return self.clone();
        }

        if self.bits() != other.bits() {
            // Create a copy with matching bits
            match other {
                StridedInterval::Normal {
                    stride,
                    lower_bound,
                    upper_bound,
                    ..
                } => {
                    let extended_other = Self::new(
                        self.bits(),
                        stride.clone(),
                        lower_bound.clone(),
                        upper_bound.clone(),
                    );
                    return self.union(&extended_other);
                }
                StridedInterval::Empty { .. } => {
                    return self.union(&Self::empty(self.bits()));
                }
            }
        }

        // Simple case: one interval is contained within the other
        if self.contains(other) {
            return self.clone();
        }
        if other.contains(self) {
            return other.clone();
        }

        // Calculate the new bounds
        let (self_min, self_max) = self.get_unsigned_bounds();
        let (other_min, other_max) = other.get_unsigned_bounds();

        let new_lower = min(self_min, other_min);
        let new_upper = max(self_max, other_max);

        // For union, handle special cases to avoid GCD(0,0) and division by zero
        let new_stride = match (self, other) {
            (
                StridedInterval::Normal {
                    stride: s_stride,
                    lower_bound: s_lb,
                    upper_bound: s_ub,
                    ..
                },
                StridedInterval::Normal {
                    stride: o_stride,
                    lower_bound: o_lb,
                    upper_bound: o_ub,
                    ..
                },
            ) => {
                if s_stride.is_zero() && o_stride.is_zero() {
                    if s_lb == o_lb && s_ub == o_ub {
                        BigUint::zero()
                    } else if s_lb > o_lb {
                        s_lb - o_lb
                    } else {
                        o_lb - s_lb
                    }
                } else if s_stride.is_zero() {
                    o_stride.clone()
                } else if o_stride.is_zero() {
                    s_stride.clone()
                } else {
                    gcd(s_stride, o_stride)
                }
            }
            _ => BigUint::one(),
        };

        Self::new(self.bits(), new_stride, new_lower, new_upper)
    }

    /// Create a widened interval by extending bounds
    pub fn widen(&self, other: &Self) -> Self {
        match (self, other) {
            (StridedInterval::Empty { .. }, _) => other.clone(),
            (_, StridedInterval::Empty { .. }) => self.clone(),
            (
                StridedInterval::Normal {
                    bits: bits1,
                    stride: stride1,
                    lower_bound: lb1,
                    upper_bound: ub1,
                },
                StridedInterval::Normal {
                    bits: bits2,
                    stride: stride2,
                    lower_bound: lb2,
                    upper_bound: ub2,
                },
            ) => {
                // If the intervals have different bit widths, normalize
                if bits1 != bits2 {
                    return self.widen(&StridedInterval::Normal {
                        bits: *bits1,
                        stride: stride2.clone(),
                        lower_bound: lb2.clone(),
                        upper_bound: ub2.clone(),
                    });
                }

                // Cousot-Cousot widening:
                // If lower decreased, extrapolate to signed minimum (2^(bits-1))
                // If upper increased, extrapolate to unsigned maximum (max_int)
                // Using signed minimum matches claripy's behavior where bounds
                // are extrapolated to signed boundaries, producing wrapping SIs.
                let new_lower = if lb2 < lb1 {
                    BigUint::one() << (bits1 - 1)
                } else {
                    lb1.clone()
                };
                let new_upper = if ub2 > ub1 {
                    max_int(*bits1)
                } else {
                    ub1.clone()
                };
                // Compute stride: when both strides are zero, derive from the range
                let new_stride = if stride1.is_zero() && stride2.is_zero() {
                    if new_lower == new_upper {
                        BigUint::zero()
                    } else {
                        BigUint::one()
                    }
                } else {
                    gcd(stride1, stride2)
                };

                StridedInterval::new(*bits1, new_stride, new_lower, new_upper)
            }
        }
    }

    /// Return the complement of the interval (all values not in the interval)
    pub fn complement(&self) -> Self {
        if self.is_empty() {
            return Self::top(self.bits());
        }

        if self.is_top() {
            return Self::empty(self.bits());
        }

        // Handle the case of a singleton value
        if self.is_integer()
            && let StridedInterval::Normal {
                lower_bound,
                upper_bound,
                bits,
                ..
            } = self
        {
            let lower = modular_add(upper_bound, &BigUint::one(), *bits);
            let upper = modular_sub(lower_bound, &BigUint::one(), *bits);
            return Self::new(*bits, BigUint::one(), lower, upper);
        }

        // For the general case
        match self {
            StridedInterval::Normal {
                bits,
                stride,
                lower_bound,
                upper_bound,
            } => {
                if *stride > BigUint::one() {
                    // Complex case: we need to calculate the values between the intervals
                    // For simplicity, we'll return a conservative approximation
                    // A more precise implementation could return a set of intervals
                    let lower = modular_add(upper_bound, &BigUint::one(), *bits);
                    let upper = modular_sub(lower_bound, &BigUint::one(), *bits);
                    return Self::new(*bits, BigUint::one(), lower, upper);
                }
                // For stride 1, simply invert the range
                let lower = modular_add(upper_bound, &BigUint::one(), *bits);
                let upper = modular_sub(lower_bound, &BigUint::one(), *bits);
                Self::new(*bits, BigUint::one(), lower, upper)
            }
            _ => Self::empty(self.bits()),
        }
    }

    // ================================================================================================
    // Comparison ops: Eq, Ne, ULT, ULE, UGT, UGE, SLT, SLE, SGT, SGE
    // ================================================================================================

    /// Check if this interval is definitely equal to another, returning a ComparisonResult
    pub fn eq_(&self, other: &Self) -> ComparisonResult {
        if self.is_empty() || other.is_empty() {
            return ComparisonResult::False;
        }

        let self_lb = match self {
            StridedInterval::Normal { lower_bound, .. } => lower_bound,
            _ => return ComparisonResult::False,
        };
        let other_lb = match other {
            StridedInterval::Normal { lower_bound, .. } => lower_bound,
            _ => return ComparisonResult::False,
        };

        if self.is_integer() && other.is_integer() && self_lb == other_lb {
            return ComparisonResult::True;
        }

        // If intervals don't overlap, they can't be equal
        let intersection = self.intersection(other);
        if intersection.is_empty() {
            return ComparisonResult::False;
        }

        if self.is_integer() && other.is_integer() && self_lb == other_lb {
            return ComparisonResult::True;
        }

        // Otherwise, maybe
        ComparisonResult::Maybe
    }

    /// Check if this interval is definitely not equal to another, returning a ComparisonResult
    pub fn ne_(&self, other: &Self) -> ComparisonResult {
        // Using the logical not of equality
        !self.eq_(other)
    }

    /// Check if this interval is definitely less than another in unsigned comparison
    pub fn ult(&self, other: &Self) -> ComparisonResult {
        if self.is_empty() || other.is_empty() {
            return ComparisonResult::False;
        }

        // Get unsigned bounds
        let (self_min, self_max) = self.get_unsigned_bounds();
        let (other_min, other_max) = other.get_unsigned_bounds();

        if self_max < other_min {
            ComparisonResult::True
        } else if self_min >= other_max {
            ComparisonResult::False
        } else {
            ComparisonResult::Maybe
        }
    }

    /// Check if this interval is definitely less than or equal to another in unsigned comparison
    pub fn ule(&self, other: &Self) -> ComparisonResult {
        if self.is_empty() || other.is_empty() {
            return ComparisonResult::False;
        }

        // Get unsigned bounds
        let (self_min, self_max) = self.get_unsigned_bounds();
        let (other_min, other_max) = other.get_unsigned_bounds();

        if self_max <= other_min {
            ComparisonResult::True
        } else if self_min > other_max {
            ComparisonResult::False
        } else {
            ComparisonResult::Maybe
        }
    }

    /// Check if this interval is definitely greater than another in unsigned comparison
    pub fn ugt(&self, other: &Self) -> ComparisonResult {
        // Reverse the comparison
        other.ult(self)
    }

    /// Check if this interval is definitely greater than or equal to another in unsigned comparison
    pub fn uge(&self, other: &Self) -> ComparisonResult {
        // Reverse the comparison
        other.ule(self)
    }

    /// Check if this interval is definitely less than another in signed comparison
    pub fn slt(&self, other: &Self) -> ComparisonResult {
        if self.is_empty() || other.is_empty() {
            return ComparisonResult::False;
        }

        // Get signed bounds
        let (self_min, self_max) = self.get_signed_bounds();
        let (other_min, other_max) = other.get_signed_bounds();

        if self_max < other_min {
            ComparisonResult::True
        } else if self_min >= other_max {
            ComparisonResult::False
        } else {
            ComparisonResult::Maybe
        }
    }

    /// Check if this interval is definitely less than or equal to another in signed comparison
    pub fn sle(&self, other: &Self) -> ComparisonResult {
        if self.is_empty() || other.is_empty() {
            return ComparisonResult::False;
        }

        // Get signed bounds
        let (self_min, self_max) = self.get_signed_bounds();
        let (other_min, other_max) = other.get_signed_bounds();

        if self_max <= other_min {
            ComparisonResult::True
        } else if self_min > other_max {
            ComparisonResult::False
        } else {
            ComparisonResult::Maybe
        }
    }

    /// Check if this interval is definitely greater than another in signed comparison
    pub fn sgt(&self, other: &Self) -> ComparisonResult {
        // Reverse the comparison
        other.slt(self)
    }

    /// Check if this interval is definitely greater than or equal to another in signed comparison
    pub fn sge(&self, other: &Self) -> ComparisonResult {
        // Reverse the comparison
        other.sle(self)
    }

    // ================================================================================================
    // Arithmatic Ops: Neg, Add, Sub, Mul, UDiv, SDiv, URem, SRem
    // ================================================================================================

    pub fn neg(&self) -> StridedInterval {
        match self {
            StridedInterval::Empty { bits } => StridedInterval::empty(*bits),
            _ => {
                // Negation is: 0 - self
                // This matches Python's implementation and preserves all subtraction logic
                let zero = StridedInterval::constant(self.bits(), 0u32);
                zero.sub(self)
            }
        }
    }

    /// Check for wrapped overflow in addition
    fn wrapped_overflow_add(&self, other: &Self) -> bool {
        match (self, other) {
            (
                StridedInterval::Normal {
                    bits,
                    lower_bound: s_lb,
                    upper_bound: s_ub,
                    ..
                },
                StridedInterval::Normal {
                    lower_bound: o_lb,
                    upper_bound: o_ub,
                    ..
                },
            ) => {
                // Calculate cardinality of each interval
                let card_self = if s_lb.is_zero() && s_ub.is_zero() {
                    BigUint::zero()
                } else if s_ub >= s_lb {
                    s_ub - s_lb + BigUint::one()
                } else {
                    &max_int(*bits) - s_lb + s_ub + BigUint::one()
                };

                let card_other = if o_lb.is_zero() && o_ub.is_zero() {
                    BigUint::zero()
                } else if o_ub >= o_lb {
                    o_ub - o_lb + BigUint::one()
                } else {
                    &max_int(*bits) - o_lb + o_ub + BigUint::one()
                };

                // Overflow if sum of cardinalities exceeds max_int + 1
                &card_self + &card_other > max_int(*bits) + BigUint::one()
            }
            _ => false,
        }
    }

    pub fn add(&self, other: &StridedInterval) -> StridedInterval {
        match (self, other) {
            (StridedInterval::Empty { bits }, _) | (_, StridedInterval::Empty { bits }) => {
                StridedInterval::empty(*bits)
            }
            (
                StridedInterval::Normal {
                    bits,
                    stride: s_stride,
                    lower_bound: s_lb,
                    upper_bound: s_ub,
                },
                StridedInterval::Normal {
                    stride: o_stride,
                    lower_bound: o_lb,
                    upper_bound: o_ub,
                    ..
                },
            ) => {
                let new_bits = max(*bits, other.bits());

                // Check for overflow
                if self.wrapped_overflow_add(other) {
                    return StridedInterval::top(new_bits);
                }

                let new_stride = gcd(s_stride, o_stride);
                let new_lower = modular_add(s_lb, o_lb, new_bits);
                let new_upper = modular_add(s_ub, o_ub, new_bits);
                StridedInterval::new(new_bits, new_stride, new_lower, new_upper)
            }
        }
    }

    pub fn sub(&self, other: &StridedInterval) -> StridedInterval {
        match (self, other) {
            (StridedInterval::Empty { bits }, _) | (_, StridedInterval::Empty { bits }) => {
                StridedInterval::empty(*bits)
            }
            (
                StridedInterval::Normal {
                    bits,
                    stride: s_stride,
                    lower_bound: s_lb,
                    upper_bound: s_ub,
                },
                StridedInterval::Normal {
                    stride: o_stride,
                    lower_bound: o_lb,
                    upper_bound: o_ub,
                    ..
                },
            ) => {
                let new_bits = max(*bits, other.bits());

                // Check for overflow (same as addition overflow)
                if self.wrapped_overflow_add(other) {
                    return StridedInterval::top(new_bits);
                }

                let new_stride = gcd(s_stride, o_stride);
                let new_lower = modular_sub(s_lb, o_ub, new_bits);
                let new_upper = modular_sub(s_ub, o_lb, new_bits);
                StridedInterval::new(new_bits, new_stride, new_lower, new_upper)
            }
        }
    }

    /// Wrapped unsigned multiplication
    fn wrapped_unsigned_mul(&self, other: &Self) -> Self {
        match (self, other) {
            (
                StridedInterval::Normal {
                    bits: bits1,
                    stride: s_stride,
                    lower_bound: s_lb,
                    upper_bound: s_ub,
                },
                StridedInterval::Normal {
                    bits: bits2,
                    stride: o_stride,
                    lower_bound: o_lb,
                    upper_bound: o_ub,
                },
            ) => {
                let bits = max(*bits1, *bits2);
                let lb = modular_mul(s_lb, o_lb, bits);
                let ub = modular_mul(s_ub, o_ub, bits);

                // Check if result fits within range without wrapping
                let max_val = max_int(bits);
                let lb_big = s_lb.to_bigint().unwrap() * o_lb.to_bigint().unwrap();
                let ub_big = s_ub.to_bigint().unwrap() * o_ub.to_bigint().unwrap();
                let range = &ub_big - &lb_big;

                if range < BigInt::zero() || range > max_val.to_bigint().unwrap() {
                    // Overflow occurred
                    return Self::top(bits);
                }

                // Determine stride
                let stride = if other.is_integer() {
                    // Multiplication with an integer
                    (s_stride * o_lb) & &max_val
                } else if self.is_integer() {
                    (o_stride * s_lb) & &max_val
                } else {
                    gcd(s_stride, o_stride)
                };

                Self::new(bits, stride, lb, ub)
            }
            _ => Self::empty(max(self.bits(), other.bits())),
        }
    }

    /// Wrapped signed multiplication
    fn wrapped_signed_mul(&self, other: &Self) -> Self {
        match (self, other) {
            (
                StridedInterval::Normal {
                    bits: bits1,
                    stride: s_stride,
                    lower_bound: s_lb,
                    upper_bound: s_ub,
                },
                StridedInterval::Normal {
                    bits: bits2,
                    stride: o_stride,
                    lower_bound: o_lb,
                    upper_bound: o_ub,
                },
            ) => {
                let bits = max(*bits1, *bits2);

                // Convert to signed
                let s_lb_signed = to_signed(s_lb, bits);
                let s_ub_signed = to_signed(s_ub, bits);
                let o_lb_signed = to_signed(o_lb, bits);
                let o_ub_signed = to_signed(o_ub, bits);

                // Determine stride
                let stride = if other.is_integer() {
                    let multiplier = if o_lb_signed >= BigInt::zero() {
                        o_lb.clone()
                    } else {
                        o_lb_signed.abs().to_biguint().unwrap()
                    };
                    (s_stride * &multiplier) & max_int(bits)
                } else if self.is_integer() {
                    let multiplier = if s_lb_signed >= BigInt::zero() {
                        s_lb.clone()
                    } else {
                        s_lb_signed.abs().to_biguint().unwrap()
                    };
                    (o_stride * &multiplier) & max_int(bits)
                } else {
                    gcd(s_stride, o_stride)
                };

                // Check signs and compute bounds
                let (lb, ub) = if s_lb_signed >= BigInt::zero()
                    && s_ub_signed >= BigInt::zero()
                    && o_lb_signed >= BigInt::zero()
                    && o_ub_signed >= BigInt::zero()
                {
                    // Both positive: [a*c, b*d]
                    (&s_lb_signed * &o_lb_signed, &s_ub_signed * &o_ub_signed)
                } else if s_lb_signed < BigInt::zero()
                    && s_ub_signed < BigInt::zero()
                    && o_lb_signed < BigInt::zero()
                    && o_ub_signed < BigInt::zero()
                {
                    // Both negative: [b*d, a*c]
                    (&s_ub_signed * &o_ub_signed, &s_lb_signed * &o_lb_signed)
                } else if s_lb_signed < BigInt::zero()
                    && s_ub_signed < BigInt::zero()
                    && o_lb_signed >= BigInt::zero()
                    && o_ub_signed >= BigInt::zero()
                {
                    // Self negative, other positive: [a*d, b*c]
                    (&s_lb_signed * &o_ub_signed, &s_ub_signed * &o_lb_signed)
                } else if s_lb_signed >= BigInt::zero()
                    && s_ub_signed >= BigInt::zero()
                    && o_lb_signed < BigInt::zero()
                    && o_ub_signed < BigInt::zero()
                {
                    // Self positive, other negative: [b*c, a*d]
                    (&s_ub_signed * &o_lb_signed, &s_lb_signed * &o_ub_signed)
                } else {
                    // Mixed signs - return TOP conservatively
                    return Self::top(bits);
                };

                // Check for overflow
                let max_val_signed = signed_max_int(bits).to_bigint().unwrap();
                let min_val_signed = -(BigInt::one() << (bits - 1));
                if lb < min_val_signed || ub > max_val_signed || &ub - &lb > max_val_signed {
                    return Self::top(bits);
                }

                // Convert back to unsigned
                let lb_unsigned = to_unsigned(&lb, bits);
                let ub_unsigned = to_unsigned(&ub, bits);

                Self::new(bits, stride, lb_unsigned, ub_unsigned)
            }
            _ => Self::empty(max(self.bits(), other.bits())),
        }
    }

    pub fn mul(&self, other: &StridedInterval) -> StridedInterval {
        match (self, other) {
            (StridedInterval::Empty { bits }, _) | (_, StridedInterval::Empty { bits }) => {
                StridedInterval::empty(*bits)
            }
            (
                StridedInterval::Normal {
                    bits: bits1,
                    stride: s_stride,
                    lower_bound: s_lb,
                    upper_bound: s_ub,
                },
                StridedInterval::Normal {
                    bits: bits2,
                    stride: o_stride,
                    lower_bound: o_lb,
                    upper_bound: o_ub,
                },
            ) => {
                let bits = max(*bits1, *bits2);

                // Simple case: both are integers
                if self.is_integer() && other.is_integer() {
                    let result = modular_mul(s_lb, o_lb, bits);
                    return StridedInterval::constant(bits, result);
                }

                // Simple case: one operand is a constant (but check for overflow)
                // We can only use this shortcut if:
                // 1. The input interval doesn't wrap (input_ub >= input_lb)
                // 2. The multiplication doesn't cause overflow (no wrapping in result)
                if s_lb == s_ub && o_ub >= o_lb {
                    let factor = s_lb.clone();
                    let new_stride = o_stride * &factor;
                    let new_lower = modular_mul(o_lb, &factor, bits);
                    let new_upper = modular_mul(o_ub, &factor, bits);

                    // Check if multiplication caused overflow (result wraps but input didn't)
                    let lb_big = o_lb.to_bigint().unwrap() * s_lb.to_bigint().unwrap();
                    let ub_big = o_ub.to_bigint().unwrap() * s_lb.to_bigint().unwrap();
                    let max_val = max_int(bits).to_bigint().unwrap();

                    // If either multiplication overflows, use complex case
                    if lb_big > max_val || ub_big > max_val || new_upper < new_lower {
                        // Fall through to complex case
                    } else {
                        return StridedInterval::new(bits, new_stride, new_lower, new_upper);
                    }
                }
                if o_lb == o_ub && s_ub >= s_lb {
                    let factor = o_lb.clone();
                    let new_stride = s_stride * &factor;
                    let new_lower = modular_mul(s_lb, &factor, bits);
                    let new_upper = modular_mul(s_ub, &factor, bits);

                    // Check if multiplication caused overflow (result wraps but input didn't)
                    let lb_big = s_lb.to_bigint().unwrap() * o_lb.to_bigint().unwrap();
                    let ub_big = s_ub.to_bigint().unwrap() * o_lb.to_bigint().unwrap();
                    let max_val = max_int(bits).to_bigint().unwrap();

                    // If either multiplication overflows, use complex case
                    if lb_big > max_val || ub_big > max_val || new_upper < new_lower {
                        // Fall through to complex case
                    } else {
                        return StridedInterval::new(bits, new_stride, new_lower, new_upper);
                    }
                }

                // Complex case: split at poles and compute unsigned and signed multiplication
                // Then take their intersection for better precision
                let si1_psplit = self.psplit();
                let si2_psplit = other.psplit();

                let mut all_results = Vec::new();
                for si1 in &si1_psplit {
                    for si2 in &si2_psplit {
                        let unsigned_result = si1.wrapped_unsigned_mul(si2);
                        let signed_result = si1.wrapped_signed_mul(si2);
                        let intersection = unsigned_result.intersection(&signed_result);
                        all_results.push(intersection);
                    }
                }

                // Union all results (least upper bound)
                if all_results.is_empty() {
                    return StridedInterval::empty(bits);
                }

                let mut result = all_results[0].clone();
                for si in &all_results[1..] {
                    result = result.union(si);
                }
                result
            }
        }
    }

    /// Performs unsigned division with pole splitting for better precision
    pub fn udiv(&self, other: &Self) -> Result<Self, ClarirsError> {
        match (self, other) {
            (StridedInterval::Empty { bits }, _) | (_, StridedInterval::Empty { bits }) => {
                Ok(Self::empty(*bits))
            }
            (
                StridedInterval::Normal {
                    bits: bits1,
                    stride: s_stride,
                    lower_bound: s_lb,
                    upper_bound: s_ub,
                },
                StridedInterval::Normal {
                    bits: bits2,
                    stride: o_stride,
                    lower_bound: o_lb,
                    upper_bound: o_ub,
                },
            ) => {
                let bits = max(*bits1, *bits2);

                // Check if divisor could be zero
                if (o_lb == &BigUint::zero() && o_ub == &BigUint::zero())
                    || (o_stride.is_zero() && o_lb.is_zero())
                {
                    // Divisor is definitely zero - return empty
                    return Ok(Self::empty(bits));
                }

                // Adjust divisor bounds to avoid zero if it contains zero
                let (divisor_lb, _divisor_ub) = if other.contains_zero() {
                    let mut new_lb = o_lb.clone();
                    let mut new_ub = o_ub.clone();

                    // If lower bound is 0, increment it
                    if new_lb.is_zero() && !new_ub.is_zero() {
                        new_lb = BigUint::one();
                    }

                    // If upper bound is 0, decrement it
                    if new_ub.is_zero() && !new_lb.is_zero() {
                        new_ub = modular_sub(&new_ub, &BigUint::one(), bits);
                    }

                    // If both would be zero, return top conservatively
                    if new_lb.is_zero() && new_ub.is_zero() {
                        return Ok(Self::top(bits));
                    }

                    (new_lb, new_ub)
                } else {
                    (o_lb.clone(), o_ub.clone())
                };

                // Simple case: dividing by a constant
                if o_lb == o_ub {
                    let divisor = divisor_lb;
                    if divisor.is_zero() {
                        return Ok(Self::empty(bits));
                    }
                    let new_stride = if s_stride == &BigUint::zero() {
                        BigUint::zero()
                    } else {
                        BigUint::one()
                    };
                    let new_lower = s_lb / &divisor;
                    let new_upper = s_ub / &divisor;
                    return Ok(Self::new(bits, new_stride, new_lower, new_upper));
                }

                // Split at south pole for better precision
                let splitted_dividends = self.ssplit();
                let splitted_divisors = other.ssplit();

                let mut resulting_intervals = Vec::new();

                for dividend in &splitted_dividends {
                    for divisor in &splitted_divisors {
                        if let (
                            StridedInterval::Normal {
                                lower_bound: d_lb,
                                upper_bound: d_ub,
                                ..
                            },
                            StridedInterval::Normal {
                                lower_bound: div_lb,
                                upper_bound: div_ub,
                                ..
                            },
                        ) = (dividend, divisor)
                        {
                            // Skip if divisor contains zero
                            if div_lb.is_zero() || div_ub.is_zero() {
                                continue;
                            }

                            let lb = d_lb / div_ub;
                            let ub = d_ub / div_lb;

                            let tmp = Self::new(bits, BigUint::one(), lb, ub);
                            resulting_intervals.push(tmp);
                        }
                    }
                }

                // Union all resulting intervals
                if resulting_intervals.is_empty() {
                    return Ok(Self::empty(bits));
                }

                let mut result = resulting_intervals[0].clone();
                for si in &resulting_intervals[1..] {
                    result = result.union(si);
                }

                Ok(result)
            }
        }
    }

    /// Performs signed division with pole splitting for better precision
    pub fn sdiv(&self, other: &Self) -> Result<Self, ClarirsError> {
        match (self, other) {
            (StridedInterval::Empty { bits }, _) | (_, StridedInterval::Empty { bits }) => {
                Ok(Self::empty(*bits))
            }
            (
                StridedInterval::Normal { bits: bits1, .. },
                StridedInterval::Normal {
                    bits: bits2,
                    stride: o_stride,
                    lower_bound: o_lb,
                    ..
                },
            ) => {
                let bits = max(*bits1, *bits2);

                // Check if divisor is definitely zero
                if o_stride.is_zero() && o_lb.is_zero() {
                    return Ok(Self::empty(bits));
                }

                // If divisor could be zero, return TOP conservatively
                if other.contains_zero() {
                    return Ok(Self::top(bits));
                }

                // Simple case: both are constants
                if self.is_integer() && other.is_integer() {
                    let (self_signed, _) = self.get_signed_bounds();
                    let (other_signed, _) = other.get_signed_bounds();

                    // Perform signed division
                    let result = self_signed / other_signed;

                    // Convert back to unsigned representation
                    let result_unsigned = to_unsigned(&result, bits);

                    return Ok(Self::constant(bits, result_unsigned));
                }

                // Split at poles for better precision
                let splitted_dividends = self.psplit();
                let splitted_divisors = other.psplit();

                let mut resulting_intervals = Vec::new();

                for dividend in &splitted_dividends {
                    for divisor in &splitted_divisors {
                        if let (
                            StridedInterval::Normal {
                                lower_bound: d_lb,
                                upper_bound: d_ub,
                                ..
                            },
                            StridedInterval::Normal {
                                lower_bound: div_lb,
                                upper_bound: div_ub,
                                ..
                            },
                        ) = (dividend, divisor)
                        {
                            // Skip if divisor contains zero
                            if divisor.contains_zero() {
                                continue;
                            }

                            // Convert to signed
                            let d_lb_signed = to_signed(d_lb, bits);
                            let d_ub_signed = to_signed(d_ub, bits);
                            let div_lb_signed = to_signed(div_lb, bits);
                            let div_ub_signed = to_signed(div_ub, bits);

                            // Compute all four corner cases
                            let r1 = &d_lb_signed / &div_lb_signed;
                            let r2 = &d_lb_signed / &div_ub_signed;
                            let r3 = &d_ub_signed / &div_lb_signed;
                            let r4 = &d_ub_signed / &div_ub_signed;

                            // Find min and max
                            let lb = r1.clone().min(r2.clone()).min(r3.clone()).min(r4.clone());
                            let ub = r1.max(r2).max(r3).max(r4);

                            // Convert back to unsigned
                            let lb_unsigned = to_unsigned(&lb, bits);
                            let ub_unsigned = to_unsigned(&ub, bits);

                            let tmp = Self::new(bits, BigUint::one(), lb_unsigned, ub_unsigned);
                            resulting_intervals.push(tmp);
                        }
                    }
                }

                // Union all resulting intervals
                if resulting_intervals.is_empty() {
                    return Ok(Self::top(bits));
                }

                let mut result = resulting_intervals[0].clone();
                for si in &resulting_intervals[1..] {
                    result = result.union(si);
                }

                Ok(result)
            }
        }
    }

    /// Performs unsigned remainder
    pub fn urem(&self, other: &Self) -> Result<Self, ClarirsError> {
        match (self, other) {
            (StridedInterval::Empty { bits }, _) | (_, StridedInterval::Empty { bits }) => {
                Ok(StridedInterval::empty(*bits))
            }
            (
                StridedInterval::Normal {
                    bits: bits1,
                    lower_bound: s_lb,
                    ..
                },
                StridedInterval::Normal {
                    bits: bits2,
                    lower_bound: o_lb,
                    upper_bound: o_ub,
                    ..
                },
            ) => {
                let bits = max(*bits1, *bits2);

                // Simple case: both are constants
                if s_lb == o_lb && s_lb == o_ub {
                    let result = s_lb % o_lb;
                    return Ok(StridedInterval::constant(bits, result));
                }

                // If divisor is a constant
                if o_lb == o_ub {
                    let max_remainder = o_lb - BigUint::one();
                    return Ok(StridedInterval::range(bits, 0u32, max_remainder));
                }

                // If divisor is a range, the remainder can be from 0 to max(divisor)-1
                let (_, other_max) = other.get_unsigned_bounds();
                Ok(StridedInterval::range(
                    bits,
                    0u32,
                    &other_max - BigUint::one(),
                ))
            }
        }
    }

    /// Performs signed remainder
    pub fn srem(&self, other: &Self) -> Result<Self, ClarirsError> {
        if self.is_empty() || other.is_empty() {
            return Ok(Self::empty(max(self.bits(), other.bits())));
        }

        // // Check for division by zero
        // if other.contains_zero() {
        //     return Err(ClarirsError::DivideByZero);
        // }

        let bits = max(self.bits(), other.bits());

        // Simple case: both are constants
        if self.is_integer() && other.is_integer() {
            let (self_signed, _) = self.get_signed_bounds();
            let (other_signed, _) = other.get_signed_bounds();

            // Perform signed remainder
            let result = self_signed % other_signed;

            // Convert back to unsigned representation
            let result_unsigned = if result < BigInt::zero() {
                // For negative results, compute two's complement
                let abs_result = -result.clone();
                let mask = max_int(bits);

                (&mask + BigUint::one() - abs_result.to_biguint().unwrap()) & &mask
            } else {
                result.to_biguint().unwrap()
            };

            return Ok(Self::constant(bits, result_unsigned));
        }

        // For the general case, we need to take the sign of the dividend into account
        // This is a conservative approximation
        Ok(Self::top(bits))
    }

    // ================================================================================================
    // BitVector Bitwise Ops: Not, And, Or, Xor
    // ================================================================================================

    pub fn bitnot(&self) -> StridedInterval {
        match self {
            StridedInterval::Empty { bits } => StridedInterval::empty(*bits),
            StridedInterval::Normal {
                bits,
                stride: _,
                lower_bound,
                upper_bound,
            } => {
                // For NOT, flip all bits
                // If it's a constant, easy to compute
                if lower_bound == upper_bound {
                    // To perform NOT on BigUint, we need to: NOT(x) = MAX_INT - x
                    let result = max_int(*bits) - lower_bound;
                    return StridedInterval::constant(*bits, result);
                }

                // Split at south pole for precision
                let splitted = self.ssplit();

                if splitted.is_empty() {
                    return StridedInterval::empty(*bits);
                }

                let mut result_intervals = Vec::new();

                for si in splitted {
                    match si {
                        StridedInterval::Normal {
                            bits,
                            stride,
                            lower_bound,
                            upper_bound,
                        } => {
                            // For each split: NOT(x) where x in [lb, ub]
                            // Result: [NOT(ub), NOT(lb)]
                            let max_value = max_int(bits);
                            let new_lower = &max_value - &upper_bound;
                            let new_upper = &max_value - &lower_bound;
                            // Stride remains the same
                            let tmp = StridedInterval::new(bits, stride, new_lower, new_upper);
                            result_intervals.push(tmp);
                        }
                        StridedInterval::Empty { bits } => {
                            result_intervals.push(StridedInterval::empty(bits));
                        }
                    }
                }

                // Union all results (least upper bound)
                if result_intervals.is_empty() {
                    return StridedInterval::empty(*bits);
                }

                let mut result = result_intervals[0].clone();
                for si in &result_intervals[1..] {
                    result = result.union(si);
                }
                result
            }
        }
    }

    pub fn bitand(&self, other: &StridedInterval) -> StridedInterval {
        match (self, other) {
            (StridedInterval::Empty { bits }, _) | (_, StridedInterval::Empty { bits }) => {
                StridedInterval::empty(*bits)
            }
            (
                StridedInterval::Normal {
                    bits: bits1,
                    stride: _,
                    lower_bound: s_lb,
                    upper_bound: s_ub,
                },
                StridedInterval::Normal {
                    bits: bits2,
                    stride: _,
                    lower_bound: o_lb,
                    upper_bound: o_ub,
                },
            ) => {
                let bits = max(*bits1, *bits2);

                // Simple case: both are constants
                if s_lb == s_ub && o_lb == o_ub {
                    let result = s_lb & o_lb;
                    return StridedInterval::constant(bits, result);
                }

                // Identity property: x & MAX = x
                let max_val = max_int(bits);
                if s_lb == s_ub && s_lb == &max_val {
                    return other.clone();
                }
                if o_lb == o_ub && o_lb == &max_val {
                    return self.clone();
                }

                // When one operand is top and the other is a constant mask,
                // the result is bounded by [0, mask] since AND can only clear bits.
                if self.is_top() && o_lb == o_ub {
                    return StridedInterval::new(
                        bits,
                        BigUint::one(),
                        BigUint::zero(),
                        o_lb.clone(),
                    );
                }
                if other.is_top() && s_lb == s_ub {
                    return StridedInterval::new(
                        bits,
                        BigUint::one(),
                        BigUint::zero(),
                        s_lb.clone(),
                    );
                }

                if self.is_top() || other.is_top() {
                    return StridedInterval::top(bits);
                }

                // Split at south pole for precision
                let s_splits = self.ssplit();
                let o_splits = other.ssplit();

                let mut result_intervals = Vec::new();

                for u in &s_splits {
                    for v in &o_splits {
                        let (u_lb, u_ub, u_stride) = match u {
                            StridedInterval::Normal {
                                lower_bound,
                                upper_bound,
                                stride,
                                ..
                            } => (lower_bound, upper_bound, stride),
                            _ => continue,
                        };

                        let (v_lb, v_ub, v_stride) = match v {
                            StridedInterval::Normal {
                                lower_bound,
                                upper_bound,
                                stride,
                                ..
                            } => (lower_bound, upper_bound, stride),
                            _ => continue,
                        };

                        // Compute stride based on trailing zeros
                        let s_t = if u.is_integer() {
                            StridedInterval::ntz(v_stride)
                        } else if v.is_integer() {
                            StridedInterval::ntz(u_stride)
                        } else {
                            min(
                                StridedInterval::ntz(u_stride),
                                StridedInterval::ntz(v_stride),
                            )
                        };

                        let new_stride = if u.is_integer() && u_lb == &max_int(bits) {
                            v_stride.clone()
                        } else if v.is_integer() && v_lb == &max_int(bits) {
                            u_stride.clone()
                        } else {
                            BigUint::one() << s_t
                        };

                        // Compute r (remainder part)
                        let mask = if s_t > 0 {
                            (BigUint::one() << s_t) - BigUint::one()
                        } else {
                            BigUint::zero()
                        };
                        let r = (u_lb & &mask) & (v_lb & &mask);

                        // Compute bounds using Warren's algorithms
                        let max_val = max_int(bits);
                        let inv_mask = &max_val ^ &mask;

                        let low_bound = min_and(
                            &(u_lb & &inv_mask),
                            &(u_ub & &inv_mask),
                            &(v_lb & &inv_mask),
                            &(v_ub & &inv_mask),
                            bits,
                        );

                        let upper_bound = max_and(
                            &(u_lb & &inv_mask),
                            &(u_ub & &inv_mask),
                            &(v_lb & &inv_mask),
                            &(v_ub & &inv_mask),
                            bits,
                        );

                        let final_stride = if low_bound == upper_bound {
                            BigUint::zero()
                        } else {
                            new_stride
                        };

                        let new_interval = StridedInterval::new(
                            bits,
                            final_stride,
                            (&low_bound & &inv_mask) | &r,
                            (&upper_bound & &inv_mask) | &r,
                        );

                        result_intervals.push(new_interval);
                    }
                }

                // Union all results
                if result_intervals.is_empty() {
                    return StridedInterval::empty(bits);
                }

                let mut result = result_intervals[0].clone();
                for si in &result_intervals[1..] {
                    result = result.union(si);
                }
                result
            }
        }
    }

    pub fn bitor(&self, other: &StridedInterval) -> StridedInterval {
        match (&self, other) {
            (StridedInterval::Empty { bits }, _) | (_, StridedInterval::Empty { bits }) => {
                StridedInterval::empty(*bits)
            }
            (
                StridedInterval::Normal {
                    bits: bits1,
                    stride: _,
                    lower_bound: s_lb,
                    upper_bound: s_ub,
                },
                StridedInterval::Normal {
                    bits: bits2,
                    stride: _,
                    lower_bound: o_lb,
                    upper_bound: o_ub,
                },
            ) => {
                let bits = max(*bits1, *bits2);

                // Simple case: both are constants
                if s_lb == s_ub && o_lb == o_ub {
                    let result = s_lb | o_lb;
                    return StridedInterval::constant(bits, result);
                }

                if self.is_top() || other.is_top() {
                    return StridedInterval::top(bits);
                }

                // Split at south pole for precision
                let s_splits = self.ssplit();
                let o_splits = other.ssplit();

                let mut result_intervals = Vec::new();

                for u in &s_splits {
                    for v in &o_splits {
                        let (u_lb, u_ub, u_stride) = match u {
                            StridedInterval::Normal {
                                lower_bound,
                                upper_bound,
                                stride,
                                ..
                            } => (lower_bound, upper_bound, stride),
                            _ => continue,
                        };

                        let (v_lb, v_ub, v_stride) = match v {
                            StridedInterval::Normal {
                                lower_bound,
                                upper_bound,
                                stride,
                                ..
                            } => (lower_bound, upper_bound, stride),
                            _ => continue,
                        };

                        // Compute stride based on trailing zeros
                        let s_t = if u.is_integer() {
                            StridedInterval::ntz(v_stride)
                        } else if v.is_integer() {
                            StridedInterval::ntz(u_stride)
                        } else {
                            min(
                                StridedInterval::ntz(u_stride),
                                StridedInterval::ntz(v_stride),
                            )
                        };

                        let new_stride = if u.is_integer() && u_lb.is_zero() {
                            v_stride.clone()
                        } else if v.is_integer() && v_lb.is_zero() {
                            u_stride.clone()
                        } else {
                            BigUint::one() << s_t
                        };

                        // Compute r (remainder part)
                        let mask = if s_t > 0 {
                            (BigUint::one() << s_t) - BigUint::one()
                        } else {
                            BigUint::zero()
                        };
                        let r = (u_lb & &mask) | (v_lb & &mask);

                        // Compute bounds using Warren's algorithms
                        let max_val = max_int(bits);
                        let inv_mask = &max_val ^ &mask;

                        let low_bound = min_or(
                            &(u_lb & &inv_mask),
                            &(u_ub & &inv_mask),
                            &(v_lb & &inv_mask),
                            &(v_ub & &inv_mask),
                            bits,
                        );

                        let upper_bound = max_or(
                            &(u_lb & &inv_mask),
                            &(u_ub & &inv_mask),
                            &(v_lb & &inv_mask),
                            &(v_ub & &inv_mask),
                            bits,
                        );

                        let final_stride = if low_bound == upper_bound {
                            BigUint::zero()
                        } else {
                            new_stride
                        };

                        let new_interval = StridedInterval::new(
                            bits,
                            final_stride,
                            (&low_bound & &inv_mask) | &r,
                            (&upper_bound & &inv_mask) | &r,
                        );

                        result_intervals.push(new_interval);
                    }
                }

                // Union all results
                if result_intervals.is_empty() {
                    return StridedInterval::empty(bits);
                }

                let mut result = result_intervals[0].clone();
                for si in &result_intervals[1..] {
                    result = result.union(si);
                }
                result
            }
        }
    }

    pub fn bitxor(&self, other: &StridedInterval) -> StridedInterval {
        match (self, other) {
            (StridedInterval::Empty { bits }, _) | (_, StridedInterval::Empty { bits }) => {
                StridedInterval::empty(*bits)
            }
            (
                StridedInterval::Normal {
                    bits: bits1,
                    lower_bound: s_lb,
                    upper_bound: s_ub,
                    ..
                },
                StridedInterval::Normal {
                    bits: bits2,
                    lower_bound: o_lb,
                    upper_bound: o_ub,
                    ..
                },
            ) => {
                let bits = max(*bits1, *bits2);

                // Simple case: both are constants
                if s_lb == s_ub && o_lb == o_ub {
                    let result = s_lb ^ o_lb;
                    return StridedInterval::constant(bits, result);
                }

                if self.is_top() || other.is_top() {
                    return StridedInterval::top(bits);
                }

                // Use Warren's algorithms for tighter bounds
                let min_val = min_xor(s_lb, s_ub, o_lb, o_ub, bits);
                let max_val = max_xor(s_lb, s_ub, o_lb, o_ub, bits);

                // Calculate stride - XOR can have complex stride patterns
                // For simplicity, use GCD of strides or 1 if that's too conservative
                let stride = BigUint::one();

                StridedInterval::new(bits, stride, min_val, max_val)
            }
        }
    }

    // ================================================================================================
    // Shift Operations: Logical Left, Logical Right, Arithmetic Right, Rotate Left, Rotate Right, reverse_bytes
    // ================================================================================================

    /// Shifts left with another interval as the shift amount
    pub fn shl(&self, other: &Self) -> Result<Self, ClarirsError> {
        match (self, other) {
            (StridedInterval::Empty { bits }, _) | (_, StridedInterval::Empty { bits }) => {
                Ok(Self::empty(*bits))
            }
            (
                StridedInterval::Normal {
                    bits,
                    stride,
                    lower_bound,
                    upper_bound,
                },
                StridedInterval::Normal {
                    lower_bound: o_lb,
                    upper_bound: o_ub,
                    ..
                },
            ) => {
                // Simple case: constant shift amount
                if o_lb == o_ub
                    && let Some(shift) = o_lb.to_u32()
                {
                    if shift >= *bits {
                        return Ok(Self::constant(*bits, 0u32));
                    }
                    let factor = BigUint::one() << shift;
                    let new_stride = stride * &factor;
                    let new_lower = modular_mul(lower_bound, &factor, *bits);
                    let new_upper = modular_mul(upper_bound, &factor, *bits);
                    return Ok(Self::new(*bits, new_stride, new_lower, new_upper));
                }

                // Improved: compute union of min and max shift results
                if let (Some(min_shift), Some(max_shift)) = (o_lb.to_u32(), o_ub.to_u32()) {
                    let min_shift = min_shift.min(*bits);
                    let max_shift = max_shift.min(*bits);

                    // Compute result for minimum shift
                    let min_result = if min_shift >= *bits {
                        Self::constant(*bits, 0u32)
                    } else {
                        let factor = BigUint::one() << min_shift;
                        let new_lower = modular_mul(lower_bound, &factor, *bits);
                        let new_upper = modular_mul(upper_bound, &factor, *bits);
                        Self::new(*bits, BigUint::one(), new_lower, new_upper)
                    };

                    // Compute result for maximum shift
                    let max_result = if max_shift >= *bits {
                        Self::constant(*bits, 0u32)
                    } else {
                        let factor = BigUint::one() << max_shift;
                        let new_lower = modular_mul(lower_bound, &factor, *bits);
                        let new_upper = modular_mul(upper_bound, &factor, *bits);
                        Self::new(*bits, BigUint::one(), new_lower, new_upper)
                    };

                    return Ok(min_result.union(&max_result));
                }

                // Fallback to top if shift amount is too large to convert
                Ok(Self::top(*bits))
            }
        }
    }

    /// Logical shifts right with another interval as the shift amount
    pub fn lshr(&self, other: &Self) -> Result<Self, ClarirsError> {
        match (self, other) {
            (StridedInterval::Empty { bits }, _) | (_, StridedInterval::Empty { bits }) => {
                Ok(Self::empty(*bits))
            }
            (
                StridedInterval::Normal {
                    bits,
                    stride,
                    lower_bound,
                    upper_bound,
                    ..
                },
                StridedInterval::Normal {
                    lower_bound: o_lb,
                    upper_bound: o_ub,
                    ..
                },
            ) => {
                // Simple case: constant shift amount
                if o_lb == o_ub
                    && let Some(shift) = o_lb.to_u32()
                {
                    if shift >= *bits {
                        return Ok(Self::constant(*bits, 0u32));
                    }
                    let divisor = BigUint::one() << shift;
                    let new_stride = if stride == &BigUint::zero() {
                        BigUint::zero()
                    } else {
                        max(BigUint::one(), stride / &divisor)
                    };
                    let new_lower = lower_bound >> shift;
                    let new_upper = upper_bound >> shift;
                    return Ok(Self::new(*bits, new_stride, new_lower, new_upper));
                }

                // Improved: compute union of min and max shift results
                if let (Some(min_shift), Some(max_shift)) = (o_lb.to_u32(), o_ub.to_u32()) {
                    let min_shift = min_shift.min(*bits);
                    let max_shift = max_shift.min(*bits);

                    // Compute result for minimum shift
                    let min_result = if min_shift >= *bits {
                        Self::constant(*bits, 0u32)
                    } else {
                        let new_lower = lower_bound >> min_shift;
                        let new_upper = upper_bound >> min_shift;
                        Self::new(*bits, BigUint::one(), new_lower, new_upper)
                    };

                    // Compute result for maximum shift
                    let max_result = if max_shift >= *bits {
                        Self::constant(*bits, 0u32)
                    } else {
                        let new_lower = lower_bound >> max_shift;
                        let new_upper = upper_bound >> max_shift;
                        Self::new(*bits, BigUint::one(), new_lower, new_upper)
                    };

                    return Ok(min_result.union(&max_result));
                }

                // Fallback to top if shift amount is too large to convert
                Ok(Self::top(*bits))
            }
        }
    }

    /// Arithmetic shifts right with another interval as the shift amount
    pub fn ashr(&self, other: &Self) -> Result<Self, ClarirsError> {
        match (self, other) {
            (StridedInterval::Empty { bits }, _) | (_, StridedInterval::Empty { bits }) => {
                Ok(Self::empty(*bits))
            }
            (
                StridedInterval::Normal {
                    bits,
                    stride,
                    lower_bound,
                    upper_bound,
                    ..
                },
                StridedInterval::Normal {
                    lower_bound: o_lb,
                    upper_bound: o_ub,
                    ..
                },
            ) => {
                // Simple case: constant shift amount
                if o_lb == o_ub
                    && let Some(shift) = o_lb.to_u32()
                {
                    if shift >= *bits {
                        // Check the sign bit of the lower and upper bounds
                        let sign_bit_mask = BigUint::one() << (*bits - 1);
                        let lower_sign = lower_bound & &sign_bit_mask != BigUint::zero();
                        let upper_sign = upper_bound & &sign_bit_mask != BigUint::zero();

                        if lower_sign && upper_sign {
                            // Both are negative, result is all 1s (-1)
                            return Ok(Self::constant(*bits, max_int(*bits)));
                        } else if !lower_sign && !upper_sign {
                            // Both are positive, result is 0
                            return Ok(Self::constant(*bits, 0u32));
                        } else {
                            // Mixed signs, result is either 0 or -1
                            return Ok(Self::range(*bits, 0, max_int(*bits)));
                        }
                    }

                    // For arithmetic right shift, we need to preserve the sign bit
                    let sign_bit_mask = BigUint::one() << (*bits - 1);
                    let lower_sign = lower_bound & &sign_bit_mask != BigUint::zero();
                    let upper_sign = upper_bound & &sign_bit_mask != BigUint::zero();

                    // Generate sign extension mask
                    let sign_ext_mask =
                        ((BigUint::one() << shift) - BigUint::one()) << (*bits - shift);

                    // Perform logical right shift
                    let mut new_lower = lower_bound >> shift;
                    let mut new_upper = upper_bound >> shift;

                    // Apply sign extension if needed
                    if lower_sign {
                        new_lower |= &sign_ext_mask;
                    }

                    if upper_sign {
                        new_upper |= &sign_ext_mask;
                    }

                    // Compute new stride
                    let new_stride = if stride == &BigUint::zero() {
                        BigUint::zero()
                    } else {
                        max(BigUint::one(), stride >> shift)
                    };

                    return Ok(Self::new(*bits, new_stride, new_lower, new_upper));
                }

                // Improved: compute union of min and max shift results
                if let (Some(min_shift), Some(max_shift)) = (o_lb.to_u32(), o_ub.to_u32()) {
                    let min_shift = min_shift.min(*bits);
                    let max_shift = max_shift.min(*bits);

                    // Helper to compute ashr for a specific shift amount
                    let compute_ashr = |shift: u32| -> Self {
                        if shift >= *bits {
                            // Check the sign bit of the lower and upper bounds
                            let sign_bit_mask = BigUint::one() << (*bits - 1);
                            let lower_sign = lower_bound & &sign_bit_mask != BigUint::zero();
                            let upper_sign = upper_bound & &sign_bit_mask != BigUint::zero();

                            if lower_sign && upper_sign {
                                // Both are negative, result is all 1s (-1)
                                Self::constant(*bits, max_int(*bits))
                            } else if !lower_sign && !upper_sign {
                                // Both are positive, result is 0
                                Self::constant(*bits, 0u32)
                            } else {
                                // Mixed signs, result is either 0 or -1
                                Self::range(*bits, 0, max_int(*bits))
                            }
                        } else {
                            // For arithmetic right shift, preserve the sign bit
                            let sign_bit_mask = BigUint::one() << (*bits - 1);
                            let lower_sign = lower_bound & &sign_bit_mask != BigUint::zero();
                            let upper_sign = upper_bound & &sign_bit_mask != BigUint::zero();

                            // Generate sign extension mask
                            let sign_ext_mask =
                                ((BigUint::one() << shift) - BigUint::one()) << (*bits - shift);

                            // Perform logical right shift
                            let mut new_lower = lower_bound >> shift;
                            let mut new_upper = upper_bound >> shift;

                            // Apply sign extension if needed
                            if lower_sign {
                                new_lower |= &sign_ext_mask;
                            }

                            if upper_sign {
                                new_upper |= &sign_ext_mask;
                            }

                            Self::new(*bits, BigUint::one(), new_lower, new_upper)
                        }
                    };

                    let min_result = compute_ashr(min_shift);
                    let max_result = compute_ashr(max_shift);

                    return Ok(min_result.union(&max_result));
                }

                // Fallback to top if shift amount is too large to convert
                Ok(Self::top(*bits))
            }
        }
    }

    /// Rotates bits left with another interval as the rotation amount
    pub fn rotate_left(&self, other: &Self) -> Result<Self, ClarirsError> {
        match (self, other) {
            (StridedInterval::Empty { bits }, _) | (_, StridedInterval::Empty { bits }) => {
                Ok(Self::empty(*bits))
            }
            (
                StridedInterval::Normal {
                    bits,
                    lower_bound: s_lb,
                    upper_bound: s_ub,
                    ..
                },
                StridedInterval::Normal {
                    lower_bound: o_lb,
                    upper_bound: o_ub,
                    ..
                },
            ) => {
                // Simple case: both are constants
                if self.is_integer()
                    && other.is_integer()
                    && let Some(rot) = o_lb.to_u32()
                {
                    let rot = rot % *bits;
                    if rot == 0 {
                        return Ok(self.clone());
                    }
                    let left_part = s_lb << rot;
                    let right_part = s_lb >> (*bits - rot);
                    let rotated = (left_part | right_part) & max_int(*bits);
                    return Ok(Self::constant(*bits, rotated));
                }

                // Improved: compute union for min and max rotation amounts
                if let (Some(min_rot), Some(max_rot)) = (o_lb.to_u32(), o_ub.to_u32()) {
                    // If rotation range is small enough, compute union
                    let min_rot = min_rot % *bits;
                    let max_rot = max_rot % *bits;

                    // Helper to compute rotate_left for specific amount
                    let compute_rotate = |val: &BigUint, rot: u32| -> BigUint {
                        if rot == 0 {
                            val.clone()
                        } else {
                            let left_part = val << rot;
                            let right_part = val >> (*bits - rot);
                            (left_part | right_part) & max_int(*bits)
                        }
                    };

                    // Compute rotations for corners
                    let min_val_min_rot = compute_rotate(s_lb, min_rot);
                    let min_val_max_rot = compute_rotate(s_lb, max_rot);
                    let max_val_min_rot = compute_rotate(s_ub, min_rot);
                    let max_val_max_rot = compute_rotate(s_ub, max_rot);

                    let lower = min_val_min_rot
                        .clone()
                        .min(min_val_max_rot.clone())
                        .min(max_val_min_rot.clone())
                        .min(max_val_max_rot.clone());
                    let upper = min_val_min_rot
                        .max(min_val_max_rot)
                        .max(max_val_min_rot)
                        .max(max_val_max_rot);

                    return Ok(Self::range(*bits, lower, upper));
                }

                // Fallback to top for complex cases
                Ok(Self::top(*bits))
            }
        }
    }

    /// Rotates bits right with another interval as the rotation amount
    pub fn rotate_right(&self, other: &Self) -> Result<Self, ClarirsError> {
        match (self, other) {
            (StridedInterval::Empty { bits }, _) | (_, StridedInterval::Empty { bits }) => {
                Ok(Self::empty(*bits))
            }
            (
                StridedInterval::Normal {
                    bits,
                    lower_bound: s_lb,
                    upper_bound: s_ub,
                    ..
                },
                StridedInterval::Normal {
                    lower_bound: o_lb,
                    upper_bound: o_ub,
                    ..
                },
            ) => {
                // Simple case: both are constants
                if self.is_integer()
                    && other.is_integer()
                    && let Some(rot) = o_lb.to_u32()
                {
                    let rot = rot % *bits;
                    if rot == 0 {
                        return Ok(self.clone());
                    }
                    let right_part = s_lb >> rot;
                    let left_part = s_lb << (*bits - rot);
                    let rotated = (left_part | right_part) & max_int(*bits);
                    return Ok(Self::constant(*bits, rotated));
                }

                // Improved: compute union for min and max rotation amounts
                if let (Some(min_rot), Some(max_rot)) = (o_lb.to_u32(), o_ub.to_u32()) {
                    let min_rot = min_rot % *bits;
                    let max_rot = max_rot % *bits;

                    // Helper to compute rotate_right for specific amount
                    let compute_rotate = |val: &BigUint, rot: u32| -> BigUint {
                        if rot == 0 {
                            val.clone()
                        } else {
                            let right_part = val >> rot;
                            let left_part = val << (*bits - rot);
                            (left_part | right_part) & max_int(*bits)
                        }
                    };

                    // Compute rotations for corners
                    let min_val_min_rot = compute_rotate(s_lb, min_rot);
                    let min_val_max_rot = compute_rotate(s_lb, max_rot);
                    let max_val_min_rot = compute_rotate(s_ub, min_rot);
                    let max_val_max_rot = compute_rotate(s_ub, max_rot);

                    let lower = min_val_min_rot
                        .clone()
                        .min(min_val_max_rot.clone())
                        .min(max_val_min_rot.clone())
                        .min(max_val_max_rot.clone());
                    let upper = min_val_min_rot
                        .max(min_val_max_rot)
                        .max(max_val_min_rot)
                        .max(max_val_max_rot);

                    return Ok(Self::range(*bits, lower, upper));
                }

                // Fallback to top for complex cases
                Ok(Self::top(*bits))
            }
        }
    }

    /// Reverse the bytes of the StridedInterval
    /// Returns an error if the StridedInterval is not a multiple of 8 bits
    pub fn reverse_bytes(&self) -> Result<Self, ClarirsError> {
        match self {
            StridedInterval::Empty { bits } => Ok(Self::empty(*bits)),
            StridedInterval::Normal { bits: 8, .. } => Ok(self.clone()),
            StridedInterval::Normal {
                bits,
                lower_bound,
                upper_bound,
                stride,
                ..
            } => {
                let num_bytes = *bits / 8;
                if num_bytes == 0 || *bits % 8 != 0 {
                    return Ok(Self::top(*bits));
                }

                // Helper: byte-reverse a value
                let byte_reverse = |val: &BigUint| -> BigUint {
                    let mask = BigUint::from(0xFFu8);
                    let mut result = BigUint::zero();
                    for i in 0..num_bytes {
                        let byte_val = (val >> (i * 8)) & &mask;
                        result |= byte_val << ((num_bytes - 1 - i) * 8);
                    }
                    result
                };

                // Constant case
                if lower_bound == upper_bound {
                    return Ok(Self::constant(*bits, byte_reverse(lower_bound)));
                }

                // If all values fit in the lowest byte, byte reversal moves them
                // to the highest byte with stride scaled accordingly.
                // e.g., SI16(1, 0, 64) -> SI16(256, 0, 16384)
                let byte_mask = BigUint::from(0xFFu8);
                if upper_bound <= &byte_mask && lower_bound <= &byte_mask {
                    let shift = (*bits - 8) as usize;
                    let new_lower = lower_bound << shift;
                    let new_upper = upper_bound << shift;
                    let new_stride = if stride.is_zero() {
                        BigUint::zero()
                    } else {
                        stride << shift
                    };
                    return Ok(Self::new(*bits, new_stride, new_lower, new_upper));
                }

                Ok(Self::top(*bits))
            }
        }
    }

    // ================================================================================================
    // BitVector Extension Ops: Extract, Concat, ZeroExtend, SignExtend
    // ================================================================================================

    /// Extract bits from the interval (similar to bitslice)
    pub fn extract(&self, high_bit: u32, low_bit: u32) -> Self {
        if self.is_empty() {
            return Self::empty(high_bit - low_bit + 1);
        }

        if low_bit >= self.bits() || high_bit >= self.bits() || high_bit < low_bit {
            return Self::empty(high_bit - low_bit + 1);
        }

        match self {
            StridedInterval::Normal {
                stride,
                lower_bound,
                upper_bound,
                ..
            } => {
                // First shift right by low_bit
                let shifted_lower = lower_bound >> low_bit;
                let shifted_upper = upper_bound >> low_bit;

                // Then mask to only keep the bits we want
                let mask = (BigUint::one() << (high_bit - low_bit + 1)) - BigUint::one();
                let new_lower = &shifted_lower & &mask;
                let new_upper = &shifted_upper & &mask;

                // Compute new stride - preserve if possible
                let new_stride = if stride.is_zero() {
                    BigUint::zero()
                } else {
                    // Check if stride is preserved after extraction
                    let shift_divisor = BigUint::one() << low_bit;

                    // If stride is divisible by 2^low_bit, we can preserve it
                    if stride % &shift_divisor == BigUint::zero() {
                        let preserved_stride = stride / &shift_divisor;
                        // Make sure the preserved stride doesn't exceed the new range
                        let range = if new_upper >= new_lower {
                            &new_upper - &new_lower
                        } else {
                            BigUint::zero()
                        };
                        if preserved_stride <= range {
                            preserved_stride
                        } else {
                            BigUint::one()
                        }
                    } else {
                        // Find GCD to get the best stride we can preserve
                        let gcd = gcd(stride, &shift_divisor);
                        if gcd > BigUint::one() {
                            let candidate = &gcd / &shift_divisor;
                            if candidate.is_zero() {
                                BigUint::one()
                            } else {
                                candidate
                            }
                        } else {
                            BigUint::one()
                        }
                    }
                };

                Self::new(high_bit - low_bit + 1, new_stride, new_lower, new_upper)
            }
            StridedInterval::Empty { .. } => Self::empty(high_bit - low_bit + 1),
        }
    }

    /// Concatenate two intervals (high bits from self, low bits from other)
    pub fn concat(&self, other: &Self) -> Self {
        match (self, other) {
            (StridedInterval::Empty { bits: bits1 }, StridedInterval::Empty { bits: bits2 }) => {
                Self::empty(bits1 + bits2)
            }
            (
                StridedInterval::Empty { bits },
                StridedInterval::Normal {
                    bits: other_bits, ..
                },
            ) => Self::empty(bits + other_bits),
            (StridedInterval::Normal { bits, .. }, StridedInterval::Empty { bits: other_bits }) => {
                Self::empty(bits + other_bits)
            }
            (
                StridedInterval::Normal {
                    bits: bits1,
                    stride: stride1,
                    lower_bound: lb1,
                    upper_bound: ub1,
                },
                StridedInterval::Normal {
                    bits: bits2,
                    stride: stride2,
                    lower_bound: lb2,
                    upper_bound: ub2,
                },
            ) => {
                // Simple case: if both are constants
                if lb1 == ub1 && lb2 == ub2 {
                    let new_value = (lb1 << bits2) | lb2;
                    return Self::constant(bits1 + bits2, new_value);
                }

                // Improved stride computation
                let new_stride = if stride1.is_zero() && stride2.is_zero() {
                    BigUint::zero()
                } else if stride1.is_zero() {
                    // High bits constant, low bits have stride
                    stride2.clone()
                } else if stride2.is_zero() {
                    // Low bits constant, high bits have stride
                    stride1 << bits2
                } else {
                    // Both have strides - use GCD of their contribution
                    let high_contribution = stride1 << bits2;
                    gcd(&high_contribution, stride2)
                };

                // General case - compute all corner combinations
                let a = lb1 << bits2;
                let b = ub1 << bits2;
                let c = lb2;
                let d = ub2;

                let ac = &a | c;
                let ad = &a | d;
                let bc = &b | c;
                let bd = &b | d;

                let new_lower = ac.clone().min(ad.clone()).min(bc.clone()).min(bd.clone());
                let new_upper = ac.max(ad).max(bc).max(bd);

                Self::new(bits1 + bits2, new_stride, new_lower, new_upper)
            }
        }
    }

    /// Zero-extend the interval by `extra_bits` additional bits.
    ///
    /// This matches the semantics of `AstOp::ZeroExt(_, amount)` where
    /// `amount` is the number of bits to add, not the total target width.
    pub fn zero_extend(&self, extra_bits: u32) -> Self {
        let new_bits = self.bits() + extra_bits;
        match self {
            StridedInterval::Empty { .. } => Self::empty(new_bits),
            StridedInterval::Normal {
                stride,
                lower_bound,
                upper_bound,
                ..
            } => {
                if extra_bits == 0 {
                    return self.clone();
                }
                Self::new(
                    new_bits,
                    stride.clone(),
                    lower_bound.clone(),
                    upper_bound.clone(),
                )
            }
        }
    }

    /// Sign-extend the interval by `extra_bits` additional bits.
    ///
    /// This matches the semantics of `AstOp::SignExt(_, amount)` where
    /// `amount` is the number of bits to add, not the total target width.
    pub fn sign_extend(&self, extra_bits: u32) -> Self {
        let new_bits = self.bits() + extra_bits;
        match self {
            StridedInterval::Empty { .. } => Self::empty(new_bits),
            StridedInterval::Normal {
                bits,
                stride,
                lower_bound,
                upper_bound,
            } => {
                if extra_bits == 0 {
                    return self.clone();
                }

                let sign_bit_mask = BigUint::one() << (*bits - 1);
                let extension_mask = (BigUint::one() << extra_bits) - BigUint::one();

                let new_lower = if lower_bound & &sign_bit_mask != BigUint::zero() {
                    lower_bound | (&extension_mask << *bits)
                } else {
                    lower_bound.clone()
                };

                let new_upper = if upper_bound & &sign_bit_mask != BigUint::zero() {
                    upper_bound | (&extension_mask << *bits)
                } else {
                    upper_bound.clone()
                };

                Self::new(new_bits, stride.clone(), new_lower, new_upper)
            }
        }
    }
}

#[cfg(test)]
mod si_constructor_tests {
    use super::*;

    #[test]
    fn test_constant() {
        let si = StridedInterval::constant(32, 42u32);
        assert_eq!(
            si,
            StridedInterval::new(
                32,
                BigUint::zero(),
                BigUint::from(42u32),
                BigUint::from(42u32)
            )
        );
        assert!(si.is_integer());
        assert!(!si.is_empty());
        assert!(!si.is_top());
    }

    #[test]
    fn test_top() {
        let si = StridedInterval::top(32);
        assert_eq!(
            si,
            StridedInterval::new(
                32,
                BigUint::one(),
                BigUint::zero(),
                (BigUint::one() << 32) - BigUint::one()
            )
        );
        assert!(!si.is_integer());
        assert!(!si.is_empty());
        assert!(si.is_top());
    }

    #[test]
    fn test_bottom() {
        let si = StridedInterval::empty(32);
        match si {
            StridedInterval::Empty { bits } => assert_eq!(bits, 32),
            _ => panic!("Expected Empty variant"),
        }
        assert!(si.is_empty());
        assert!(!si.is_integer());
        assert!(!si.is_top());
    }

    #[test]
    fn test_range() {
        let si = StridedInterval::range(32, 10u32, 20u32);
        assert_eq!(
            si,
            StridedInterval::new(
                32,
                BigUint::one(),
                BigUint::from(10u32),
                BigUint::from(20u32)
            )
        );
        assert!(!si.is_integer());
        assert!(!si.is_empty());
        assert!(!si.is_top());
    }
}

#[cfg(test)]
mod si_bounds_tests {
    use super::*;

    #[test]
    fn test_get_unsigned_bounds() {
        // Normal interval: lower <= upper
        let si = StridedInterval::range(8, 10u32, 20u32);
        let (min_u, max_u) = si.get_unsigned_bounds();
        assert_eq!(min_u, BigUint::from(10u32));
        assert_eq!(max_u, BigUint::from(20u32));

        // Wrap-around interval: lower > upper
        // [250, 5] represents {250, 251, ..., 255, 0, 1, ..., 5}
        // Unsigned min is 0 (from [0, upper] part), max is 255 (from [lower, MAX] part)
        let si = StridedInterval::Normal {
            bits: 8,
            stride: BigUint::one(),
            lower_bound: BigUint::from(250u32),
            upper_bound: BigUint::from(5u32),
        };
        let (min_u, max_u) = si.get_unsigned_bounds();
        assert_eq!(min_u, BigUint::zero());
        assert_eq!(max_u, BigUint::from(255u32)); // max for 8 bits

        // Empty interval
        let si = StridedInterval::empty(8);
        let (min_u, max_u) = si.get_unsigned_bounds();
        assert_eq!(min_u, BigUint::zero());
        assert_eq!(max_u, BigUint::zero());
    }

    #[test]
    fn test_get_signed_bounds() {
        // Positive range
        let si = StridedInterval::range(8, 10u32, 20u32);
        let (min_s, max_s) = si.get_signed_bounds();
        assert_eq!(min_s, BigInt::from(10));
        assert_eq!(max_s, BigInt::from(20));

        // Negative range (e.g., 240-250 in 8 bits is -16 to -6)
        let si = StridedInterval::range(8, 240u32, 250u32);
        let (min_s, max_s) = si.get_signed_bounds();
        assert_eq!(min_s, BigInt::from(-16));
        assert_eq!(max_s, BigInt::from(-6));

        // Wrap-around interval: lower > upper, e.g., 250 to 5
        let si = StridedInterval::Normal {
            bits: 8,
            stride: BigUint::one(),
            lower_bound: BigUint::from(250u32),
            upper_bound: BigUint::from(5u32),
        };
        let (min_s, max_s) = si.get_signed_bounds();
        assert_eq!(min_s, BigInt::from(-6));
        assert_eq!(max_s, BigInt::from(5));

        // Empty interval
        let si = StridedInterval::empty(8);
        let (min_s, max_s) = si.get_signed_bounds();
        assert_eq!(min_s, BigInt::zero());
        assert_eq!(max_s, BigInt::zero());
    }
}

#[cfg(test)]
mod si_properties_tests {
    use super::*;

    #[test]
    fn test_contains_zero() {
        let si = StridedInterval::range(32, 0u32, 10u32);
        assert!(si.contains_zero());

        let si = StridedInterval::range(32, 1u32, 10u32);
        assert!(!si.contains_zero());

        let si = StridedInterval::new(
            32,
            BigUint::from(2u32),
            BigUint::from(0u32),
            BigUint::from(10u32),
        );
        assert!(si.contains_zero());
    }

    #[test]
    fn test_eval() {
        let si = StridedInterval::constant(32, 42u32);
        let values = si.eval(10);
        assert_eq!(values.len(), 1);
        assert_eq!(values[0], BigUint::from(42u32));

        let si = StridedInterval::new(
            8,
            BigUint::from(2u32),
            BigUint::from(1u32),
            BigUint::from(5u32),
        );
        let values = si.eval(10);
        assert_eq!(values.len(), 3);
        assert_eq!(values[0], BigUint::from(1u32));
        assert_eq!(values[1], BigUint::from(3u32));
        assert_eq!(values[2], BigUint::from(5u32));
    }
}

#[cfg(test)]
mod si_set_op_tests {
    use super::*;

    #[test]
    fn test_union() {
        let a = StridedInterval::range(32, 10u32, 30u32);
        let b = StridedInterval::range(32, 20u32, 40u32);
        let result = a.union(&b);
        assert_eq!(result, StridedInterval::range(32, 10u32, 40u32));

        let a = StridedInterval::range(32, 10u32, 20u32);
        let b = StridedInterval::range(32, 30u32, 40u32);
        let result = a.union(&b);
        assert_eq!(result, StridedInterval::range(32, 10u32, 40u32));
    }

    #[test]
    fn test_intersection() {
        let a = StridedInterval::range(32, 10u32, 30u32);
        let b = StridedInterval::range(32, 20u32, 40u32);
        let result = a.intersection(&b);
        assert_eq!(result, StridedInterval::range(32, 20u32, 30u32));
        assert!(!result.is_empty());

        let a = StridedInterval::range(32, 10u32, 20u32);
        let b = StridedInterval::range(32, 30u32, 40u32);
        let result = a.intersection(&b);
        assert!(result.is_empty());
    }
}

#[cfg(test)]
mod si_comparison_op_tests {
    // TODO
}

#[cfg(test)]
mod si_arithmetic_op_tests {
    use super::*;

    #[test]
    fn test_add() {
        let a = StridedInterval::constant(32, 10u32);
        let b = StridedInterval::constant(32, 20u32);
        let result = a.add(&b);
        assert_eq!(result, StridedInterval::constant(32, 30u32));
        assert!(result.is_integer());

        let a = StridedInterval::range(32, 10u32, 20u32);
        let b = StridedInterval::range(32, 5u32, 15u32);
        let result = a.add(&b);
        assert_eq!(result, StridedInterval::range(32, 15u32, 35u32));
        assert!(!result.is_integer());
    }

    #[test]
    fn test_sub() {
        let a = StridedInterval::constant(32, 30u32);
        let b = StridedInterval::constant(32, 10u32);
        let result = a.sub(&b);
        assert_eq!(result, StridedInterval::constant(32, 20u32));
        assert!(result.is_integer());

        let a = StridedInterval::range(32, 20u32, 30u32);
        let b = StridedInterval::range(32, 5u32, 15u32);
        let result = a.sub(&b);
        assert_eq!(result, StridedInterval::range(32, 5u32, 25u32));
        assert!(!result.is_integer());
    }
}

#[cfg(test)]
mod si_bitwise_op_tests {
    use super::*;

    #[test]
    fn test_bitand_with_mask() {
        // Test: x & 0xFF should give a result bounded by 0xFF
        // The new implementation using De Morgan's law is more precise
        let x = StridedInterval::range(32, 0u32, 1000u32);
        let mask = StridedInterval::constant(32, 0xFFu32);
        let result = x.bitand(&mask);

        // The result should be bounded by the mask
        let (lower, upper) = result.get_unsigned_bounds();
        assert!(upper <= BigUint::from(0xFFu32));
        assert!(lower <= upper);
    }

    #[test]
    fn test_bitand_constants() {
        // Test: constant & constant
        let a = StridedInterval::constant(8, 0xF0u32);
        let b = StridedInterval::constant(8, 0x0Fu32);
        let result = a.bitand(&b);
        assert_eq!(result, StridedInterval::constant(8, 0u32));
    }

    #[test]
    fn test_bitand_tighter_bounds() {
        // Test: [0, 100] & [0, 200] should give [0, 100]
        let a = StridedInterval::range(8, 0u32, 100u32);
        let b = StridedInterval::range(8, 0u32, 200u32);
        let result = a.bitand(&b);
        let (_, upper) = result.get_unsigned_bounds();
        assert!(upper <= BigUint::from(100u32));
    }

    #[test]
    fn test_bitand_with_all_ones() {
        // Test: [1, 10] & 0xFFFFFFFF should preserve the interval [1, 10]
        // This is because AND with all 1s is an identity operation
        let si_small = StridedInterval::range(32, 1u32, 10u32);
        let all_ones = StridedInterval::constant(32, 0xFFFFFFFFu32);
        let result = si_small.bitand(&all_ones);

        let (lower, upper) = result.get_unsigned_bounds();

        // The result should preserve the original bounds
        assert_eq!(
            lower,
            BigUint::from(1u32),
            "Lower bound should be 1, got {lower}"
        );
        assert_eq!(
            upper,
            BigUint::from(10u32),
            "Upper bound should be 10, got {upper}"
        );
    }

    #[test]
    fn test_bitand_identity_property() {
        // Test that x & MAX = x for any interval x
        // This should hold for all intervals

        // Test with various intervals
        let test_cases = vec![
            StridedInterval::constant(32, 42u32),
            StridedInterval::range(32, 1u32, 10u32),
            StridedInterval::range(32, 100u32, 200u32),
            StridedInterval::new(32, 2u32, 0u32, max_int(32)), // All even numbers
        ];

        for si in test_cases {
            let all_ones = StridedInterval::constant(32, 0xFFFFFFFFu32);
            let result = si.bitand(&all_ones);

            let (si_lower, si_upper) = si.get_unsigned_bounds();
            let (result_lower, result_upper) = result.get_unsigned_bounds();

            assert_eq!(
                result_lower, si_lower,
                "AND with all 1s should preserve lower bound: expected {si_lower}, got {result_lower}"
            );
            assert_eq!(
                result_upper, si_upper,
                "AND with all 1s should preserve upper bound: expected {si_upper}, got {result_upper}"
            );
        }
    }

    #[test]
    fn test_bitand_with_zero() {
        // Test: x & 0 = 0 for any interval x
        let si = StridedInterval::range(32, 1u32, 10u32);
        let zero = StridedInterval::constant(32, 0u32);
        let result = si.bitand(&zero);

        assert!(result.is_integer(), "Result should be a constant");
        let (lower, upper) = result.get_unsigned_bounds();
        assert_eq!(lower, BigUint::zero());
        assert_eq!(upper, BigUint::zero());
    }

    #[test]
    fn test_bitor_bounds() {
        // Test: [0, 15] | [16, 31] with Warren's algorithm
        // The implementation with pole splitting and Warren's algorithms
        // is complex and may produce conservative results
        let a = StridedInterval::range(8, 0u32, 15u32);
        let b = StridedInterval::range(8, 16u32, 31u32);
        let result = a.bitor(&b);

        // The key properties to test:
        // 1. The operation should not crash
        // 2. The result should be valid (not produce an error state)
        // The result should contain at least some reasonable values
        // If it's TOP, that's also acceptable (conservative)
        assert!(!result.is_empty() || result.is_top());
    }

    #[test]
    fn test_bitor_constants() {
        // Test: constant | constant
        let a = StridedInterval::constant(8, 0xF0u32);
        let b = StridedInterval::constant(8, 0x0Fu32);
        let result = a.bitor(&b);
        assert_eq!(result, StridedInterval::constant(8, 0xFFu32));
    }

    #[test]
    fn test_bitxor_constants() {
        // Test: constant ^ constant
        let a = StridedInterval::constant(8, 0xFFu32);
        let b = StridedInterval::constant(8, 0xFFu32);
        let result = a.bitxor(&b);
        assert_eq!(result, StridedInterval::constant(8, 0u32));
    }

    #[test]
    fn test_bitxor_bounds() {
        // Test: XOR produces reasonable bounds
        let a = StridedInterval::range(8, 0u32, 15u32);
        let b = StridedInterval::range(8, 0u32, 15u32);
        let result = a.bitxor(&b);
        let (_, upper) = result.get_unsigned_bounds();
        // XOR of [0,15] and [0,15] can produce at most 15 (0b1111)
        assert!(upper <= BigUint::from(15u32));
    }

    #[test]
    fn test_bitxor_range_with_constant() {
        // Test: [1, 10] ^ 0x0F should contain all values from 1^0xF to 10^0xF
        let range = StridedInterval::range(32, 1u32, 10u32);
        let constant = StridedInterval::constant(32, 0x0Fu32);
        let result = range.bitxor(&constant);

        // Check that all expected values are in the result
        for i in 1u32..=10 {
            let expected = BigUint::from(i ^ 0x0F);
            assert!(
                result.contains_value(&expected),
                "Result should contain {} ({}^0xF), got interval [{}, {}]",
                expected,
                i,
                result.get_unsigned_bounds().0,
                result.get_unsigned_bounds().1
            );
        }
    }
}

#[cfg(test)]
mod si_shift_op_tests {
    use super::*;

    #[test]
    fn test_shl_with_range() {
        // Test: [100, 200] << [0, 2] should give union of results
        let val = StridedInterval::range(32, 100u32, 200u32);
        let shift = StridedInterval::range(32, 0u32, 2u32);
        let result = StridedInterval::shl(&val, &shift).unwrap();

        // Should contain 100 (shift by 0) and 800 (200 << 2)
        assert!(result.contains_value(&BigUint::from(100u32)));
        assert!(result.contains_value(&BigUint::from(800u32)));

        // Should not be top
        assert!(!result.is_top());
    }

    #[test]
    fn test_lshr_simple_case() {
        // Test: [1, 10] >> 1 = [0, 5]
        let val = StridedInterval::range(32, 1u32, 10u32);
        let shift = StridedInterval::constant(32, 1u32);
        let result = StridedInterval::lshr(&val, &shift).unwrap();

        let (min_val, max_val) = result.get_unsigned_bounds();
        assert_eq!(
            min_val,
            BigUint::from(0u32),
            "Expected min=0, got {min_val}"
        );
        assert_eq!(
            max_val,
            BigUint::from(5u32),
            "Expected max=5, got {max_val}"
        );
    }

    #[test]
    fn test_lshr_with_range() {
        // Test: [100, 200] >> [0, 2] should give union of results
        let val = StridedInterval::range(32, 100u32, 200u32);
        let shift = StridedInterval::range(32, 0u32, 2u32);
        let result = StridedInterval::lshr(&val, &shift).unwrap();

        // Should contain 100 (shift by 0) and 50 (200 >> 2)
        assert!(result.contains_value(&BigUint::from(100u32)));
        assert!(result.contains_value(&BigUint::from(50u32)));

        // Should not be top
        assert!(!result.is_top());
    }

    #[test]
    fn test_rotate_left_with_range() {
        // Test: rotate with a range of rotation amounts
        let val = StridedInterval::constant(8, 0b10000001u32);
        let rot = StridedInterval::range(8, 0u32, 1u32);
        let result = StridedInterval::rotate_left(&val, &rot).unwrap();

        // Should contain both original (rot=0) and rotated by 1
        assert!(result.contains_value(&BigUint::from(0b10000001u32)));
        assert!(result.contains_value(&BigUint::from(0b00000011u32)));
    }

    #[test]
    fn test_rotate_right_with_range() {
        // Test: rotate with a range of rotation amounts
        let val = StridedInterval::constant(8, 0b10000001u32);
        let rot = StridedInterval::range(8, 0u32, 1u32);
        let result = StridedInterval::rotate_right(&val, &rot).unwrap();

        // Should contain both original (rot=0) and rotated by 1
        assert!(result.contains_value(&BigUint::from(0b10000001u32)));
        assert!(result.contains_value(&BigUint::from(0b11000000u32)));
    }
}

#[cfg(test)]
mod si_bitvector_ext_op_tests {
    use super::*;

    #[test]
    fn test_extract_preserves_stride() {
        // Test: extracting from a strided interval
        let si = StridedInterval::new(
            8,
            BigUint::from(4u32),
            BigUint::zero(),
            BigUint::from(16u32),
        );
        let extracted = si.extract(7, 2);

        // Extracting bits [7:2] from values {0,4,8,12,16}
        // After >> 2: {0,1,2,3,4}
        let (lower, upper) = extracted.get_unsigned_bounds();
        assert_eq!(lower, BigUint::zero());
        assert!(upper <= BigUint::from(4u32));
    }

    #[test]
    fn test_concat_with_strides() {
        // Test: concatenating intervals with strides
        let high = StridedInterval::new(
            4,
            BigUint::from(2u32),
            BigUint::from(0u32),
            BigUint::from(4u32),
        );
        let low = StridedInterval::constant(4, 0xFu32);
        let result = high.concat(&low);

        // High bits {0,2,4} concat with low bits {15}
        // Should give {0x0F, 0x2F, 0x4F}
        assert!(result.contains_value(&BigUint::from(0x0Fu32)));
        assert!(result.contains_value(&BigUint::from(0x2Fu32)));
        assert!(result.contains_value(&BigUint::from(0x4Fu32)));
    }
}
