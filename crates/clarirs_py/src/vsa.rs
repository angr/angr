#![allow(non_snake_case)]

use clarirs_vsa::StridedInterval;
use clarirs_vsa::reduce::Reduce;
use clarirs_vsa::strided_interval::ComparisonResult;
use num_bigint::{BigInt, BigUint};

use crate::prelude::*;

/// Reduce an AST expression using VSA abstract interpretation.
///
/// For Bool expressions: returns `true` if definitely true, `false` if definitely
/// false, or a symbolic `BoolS("maybe")` if the result is indeterminate.
///
/// For BV expressions: returns a concrete BVV if the strided interval resolves to
/// a single value, an SI (strided interval annotated BV) if it resolves to a range,
/// or the original expression if the interval is empty.
#[pyfunction]
pub fn reduce<'py>(
    py: Python<'py>,
    expr: Bound<'py, Base>,
) -> Result<Bound<'py, Base>, ClaripyError> {
    if let Ok(bool_expr) = expr.clone().into_any().cast::<Bool>() {
        let reduced = bool_expr.get().inner.reduce()?.into_bool()?;
        let result = match reduced {
            ComparisonResult::True => Bool::new(py, &GLOBAL_CONTEXT.true_()?)?,
            ComparisonResult::False => Bool::new(py, &GLOBAL_CONTEXT.false_()?)?,
            ComparisonResult::Maybe => {
                use crate::ast::bool::BoolS;
                BoolS(py, "maybe", false)?
            }
        };
        return Ok(result.into_any().cast::<Base>()?.clone());
    }

    if let Ok(bv_expr) = expr.clone().into_any().cast::<BV>() {
        let reduced = bv_expr.get().inner.reduce()?.into_bv()?;
        let result = match reduced {
            StridedInterval::Empty { .. } => bv_expr.clone(),
            StridedInterval::Normal {
                bits,
                stride,
                lower_bound,
                upper_bound,
            } => {
                if lower_bound == upper_bound {
                    BV::new(
                        py,
                        &GLOBAL_CONTEXT
                            .bvv(BitVec::from((lower_bound, bits)))?
                            .simplify_ext(true, true)?,
                    )?
                } else {
                    BV::new(
                        py,
                        &GLOBAL_CONTEXT
                            .si(bits, stride, lower_bound, upper_bound)?
                            .simplify_ext(true, true)?,
                    )?
                }
            }
        };
        return Ok(result.into_any().cast::<Base>()?.clone());
    }

    Err(ClaripyError::TypeError(
        "reduce: expression must be a Bool or BV".to_string(),
    ))
}

/// Check if a Bool expression is definitely true via VSA.
#[pyfunction]
pub fn is_true(expr: Bound<'_, Bool>) -> Result<bool, ClaripyError> {
    Ok(matches!(
        expr.get().inner.simplify()?.reduce()?.into_bool()?,
        ComparisonResult::True
    ))
}

/// Check if a Bool expression is definitely false via VSA.
#[pyfunction]
pub fn is_false(expr: Bound<'_, Bool>) -> Result<bool, ClaripyError> {
    Ok(matches!(
        expr.get().inner.simplify()?.reduce()?.into_bool()?,
        ComparisonResult::False
    ))
}

/// Check if a Bool expression could possibly be true via VSA.
#[pyfunction]
pub fn has_true(expr: Bound<'_, Bool>) -> Result<bool, ClaripyError> {
    Ok(matches!(
        expr.get().inner.simplify()?.reduce()?.into_bool()?,
        ComparisonResult::True | ComparisonResult::Maybe
    ))
}

/// Check if a Bool expression could possibly be false via VSA.
#[pyfunction]
pub fn has_false(expr: Bound<'_, Bool>) -> Result<bool, ClaripyError> {
    Ok(matches!(
        expr.get().inner.simplify()?.reduce()?.into_bool()?,
        ComparisonResult::False | ComparisonResult::Maybe
    ))
}

/// Get the minimum unsigned value of a BV expression via VSA.
#[pyfunction]
#[pyo3(signature = (expr, signed = false))]
pub fn min(expr: Bound<'_, BV>, signed: bool) -> Result<BigInt, ClaripyError> {
    let si = expr.get().inner.simplify()?.reduce()?.into_bv()?;
    if signed {
        let (min_bound, _) = si.get_signed_bounds();
        Ok(min_bound)
    } else {
        let (min_bound, _) = si.get_unsigned_bounds();
        Ok(BigInt::from(min_bound))
    }
}

/// Get the maximum unsigned value of a BV expression via VSA.
#[pyfunction]
#[pyo3(signature = (expr, signed = false))]
pub fn max(expr: Bound<'_, BV>, signed: bool) -> Result<BigInt, ClaripyError> {
    let si = expr.get().inner.simplify()?.reduce()?.into_bv()?;
    if signed {
        let (_, max_bound) = si.get_signed_bounds();
        Ok(max_bound)
    } else {
        let (_, max_bound) = si.get_unsigned_bounds();
        Ok(BigInt::from(max_bound))
    }
}

/// Evaluate a BV expression via VSA, returning up to `n` concrete values as Python ints.
#[pyfunction]
pub fn eval<'py>(expr: Bound<'py, BV>, n: u32) -> Result<Vec<BigUint>, ClaripyError> {
    let si = expr.get().inner.simplify()?.reduce()?.into_bv()?;
    Ok(si.eval(n))
}

/// Get the cardinality (number of possible concrete values) of a BV expression via VSA.
#[pyfunction]
pub fn cardinality(expr: Bound<'_, BV>) -> Result<num_bigint::BigUint, ClaripyError> {
    let si = expr.get().inner.simplify()?.reduce()?.into_bv()?;
    Ok(si.cardinality())
}

/// Check if two AST expressions are identical after VSA reduction.
///
/// Both expressions are reduced and then compared for equality.
#[pyfunction]
pub fn identical(a: Bound<'_, Base>, b: Bound<'_, Base>) -> Result<bool, ClaripyError> {
    // Try as BV first
    if let Ok(a_bv) = a.clone().into_any().cast::<BV>()
        && let Ok(b_bv) = b.clone().into_any().cast::<BV>()
    {
        let reduced_a = a_bv.get().inner.reduce()?.into_bv()?;
        let reduced_b = b_bv.get().inner.reduce()?.into_bv()?;
        return Ok(reduced_a == reduced_b);
    }

    // Try as Bool
    if let Ok(a_bool) = a.clone().into_any().cast::<Bool>()
        && let Ok(b_bool) = b.clone().into_any().cast::<Bool>()
    {
        let reduced_a = a_bool.get().inner.reduce()?.into_bool()?;
        let reduced_b = b_bool.get().inner.reduce()?.into_bool()?;
        return Ok(reduced_a == reduced_b);
    }

    Err(ClaripyError::TypeError(
        "identical: both arguments must be the same type (Bool or BV)".to_string(),
    ))
}

/// Simplify an expression using VSA reduction.
///
/// This is a compatibility shim for `claripy.backends.vsa.simplify()`.
/// It simplifies the expression and then reduces it using VSA abstract
/// interpretation, returning the result as an AST node.
#[pyfunction]
pub fn simplify<'py>(
    py: Python<'py>,
    expr: Bound<'py, Base>,
) -> Result<Bound<'py, Base>, ClaripyError> {
    reduce(py, expr)
}

pub(crate) fn import(_py: Python, m: &Bound<PyModule>) -> PyResult<()> {
    add_pyfunctions!(
        m,
        reduce,
        simplify,
        is_true,
        is_false,
        has_true,
        has_false,
        min,
        max,
        eval,
        cardinality,
        identical,
    );
    Ok(())
}
