//! Correctly rounded arithmetic in every rounding mode.
//!
//! Each operation computes its exact result as `±mag * 2^exp` (plus a sticky
//! bit when the exact result has more bits than are kept, for division and
//! square root) and rounds it once with [`round`].

use num_bigint::BigUint;
use num_traits::{One, Zero};

use super::{F32_SORT, FPRM, FSort, Float, decompose_f64};

/// A finite `f` as `(negative, mag, exp)`, its value being `±mag * 2^exp`.
fn exact(f: f64) -> (bool, BigUint, i64) {
    let (sign, biased, frac) = decompose_f64(f);
    let (mag, exp) = if biased == 0 {
        (frac, -1074)
    } else {
        (frac | (1 << 52), i64::from(biased) - 1075)
    };
    (sign == 1, BigUint::from(mag), exp)
}

/// A value whose rounding does not depend on the mode (NaN, an infinity, a
/// zero, or a value of the target format), converted to `fsort`.
fn native(v: f64, fsort: FSort) -> Float {
    if fsort == F32_SORT {
        Float::F32(v as f32)
    } else {
        Float::F64(v)
    }
}

/// `±mag * 2^exp`, with `sticky` set if nonzero bits below `mag` were
/// dropped, rounded to `fsort` by `rm`. Only f32 and f64 are supported.
fn round(neg: bool, mag: BigUint, exp: i64, sticky: bool, fsort: FSort, rm: FPRM) -> Float {
    let p = i64::from(fsort.mantissa) + 1;
    let bias = (1i64 << (fsort.exponent - 1)) - 1;
    let emin = 1 - bias;
    let max_biased = (1i64 << fsort.exponent) - 2;
    if mag.is_zero() {
        return native(if neg { -0.0 } else { 0.0 }, fsort);
    }

    // The exponent of the lowest bit kept, clamped for subnormals
    let top = exp + mag.bits() as i64 - 1;
    let mut q = (top - (p - 1)).max(emin - (p - 1));
    let (mut keep, half, rest) = if q > exp {
        let s = (q - exp) as u64;
        let half = mag.bit(s - 1);
        let rest = sticky || mag.trailing_zeros().is_some_and(|tz| tz < s - 1);
        (mag >> s, half, rest)
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

    let frac_bits = fsort.mantissa as u64;
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
        let max = if fsort == F32_SORT {
            f32::MAX.into()
        } else {
            f64::MAX
        };
        let v = if to_inf { f64::INFINITY } else { max };
        return native(if neg { -v } else { v }, fsort);
    }
    let frac = frac.iter_u64_digits().next().unwrap_or(0);
    let bits = (u64::from(neg) << (fsort.size() - 1)) | ((biased as u64) << frac_bits) | frac;
    if fsort == F32_SORT {
        Float::F32(f32::from_bits(bits as u32))
    } else {
        Float::F64(f64::from_bits(bits))
    }
}

pub(super) fn add(a: &Float, b: &Float, rm: FPRM) -> Float {
    let fsort = a.fsort();
    let (x, y) = (
        a.to_f64().unwrap_or(f64::NAN),
        b.to_f64().unwrap_or(f64::NAN),
    );
    if !x.is_finite() || !y.is_finite() {
        return native(x + y, fsort);
    }
    if x == 0.0 && y == 0.0 {
        let neg = if x.is_sign_negative() == y.is_sign_negative() {
            x.is_sign_negative()
        } else {
            rm == FPRM::TowardNegative
        };
        return native(if neg { -0.0 } else { 0.0 }, fsort);
    }
    let ((xn, xm, xe), (yn, ym, ye)) = (exact(x), exact(y));
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
    if mag.is_zero() {
        return native(
            if rm == FPRM::TowardNegative {
                -0.0
            } else {
                0.0
            },
            fsort,
        );
    }
    round(neg, mag, e, false, fsort, rm)
}

pub(super) fn mul(a: &Float, b: &Float, rm: FPRM) -> Float {
    let fsort = a.fsort();
    let (x, y) = (
        a.to_f64().unwrap_or(f64::NAN),
        b.to_f64().unwrap_or(f64::NAN),
    );
    if !x.is_finite() || !y.is_finite() || x == 0.0 || y == 0.0 {
        return native(x * y, fsort);
    }
    let ((xn, xm, xe), (yn, ym, ye)) = (exact(x), exact(y));
    round(xn != yn, xm * ym, xe + ye, false, fsort, rm)
}

pub(super) fn div(a: &Float, b: &Float, rm: FPRM) -> Float {
    let fsort = a.fsort();
    let (x, y) = (
        a.to_f64().unwrap_or(f64::NAN),
        b.to_f64().unwrap_or(f64::NAN),
    );
    if !x.is_finite() || !y.is_finite() || x == 0.0 || y == 0.0 {
        return native(x / y, fsort);
    }
    let ((xn, xm, xe), (yn, ym, ye)) = (exact(x), exact(y));
    // Enough quotient bits for the significand plus a rounding bit
    let k = i64::from(fsort.mantissa) + 3 + ym.bits() as i64 - xm.bits() as i64;
    let k = k.max(0);
    let num = xm << k as u64;
    let (quot, rem) = (&num / &ym, &num % &ym);
    round(xn != yn, quot, xe - ye - k, !rem.is_zero(), fsort, rm)
}

pub(super) fn sqrt(a: &Float, rm: FPRM) -> Float {
    let fsort = a.fsort();
    let x = a.to_f64().unwrap_or(f64::NAN);
    if !x.is_finite() || x <= 0.0 {
        return native(x.sqrt(), fsort);
    }
    let (_, xm, xe) = exact(x);
    // An even exponent, and enough bits for the significand plus a rounding bit
    let want = 2 * (i64::from(fsort.mantissa) + 3);
    let mut k = (want - xm.bits() as i64).max(0);
    if (xe - k) % 2 != 0 {
        k += 1;
    }
    let n = xm << k as u64;
    let r = n.sqrt();
    let sticky = &r * &r != n;
    round(false, r, (xe - k) / 2, sticky, fsort, rm)
}

/// `a` in `fsort`, rounded by `rm`.
pub(super) fn convert(a: &Float, fsort: FSort, rm: FPRM) -> Float {
    let x = a.to_f64().unwrap_or(f64::NAN);
    // The host's conversion already rounds to nearest-even
    if rm == FPRM::NearestTiesToEven || !x.is_finite() || x == 0.0 {
        return native(x, fsort);
    }
    let (neg, mag, exp) = exact(x);
    round(neg, mag, exp, false, fsort, rm)
}

/// The integer `±mag` in `fsort`, rounded by `rm`.
pub(super) fn from_integer(neg: bool, mag: BigUint, fsort: FSort, rm: FPRM) -> Float {
    round(neg && !mag.is_zero(), mag, 0, false, fsort, rm)
}
