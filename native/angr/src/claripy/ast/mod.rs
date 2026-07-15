pub mod args;
pub mod base;
pub mod bits;
pub mod bool;
pub mod bv;
pub mod coerce;
pub mod fp;
pub mod opstring;
pub mod string;
pub mod util;

use std::sync::LazyLock;

use crate::claripy::prelude::*;

use super::import_submodule;

pub static GLOBAL_CONTEXT: LazyLock<Context<'static>> = LazyLock::new(Context::new);

#[pyfunction(name = "Not")]
pub fn not<'py>(py: Python<'py>, b: Bound<'py, Base>) -> Result<Bound<'py, Base>, ClaripyError> {
    if let Ok(b_bool) = b.cast::<Bool>() {
        return Bool::new(py, &GLOBAL_CONTEXT.not(&b_bool.get().inner)?.simplify()?)
            .map(|b| b.into_any().cast_into::<Base>().unwrap());
    } else if let Ok(b_bv) = b.cast::<BV>() {
        return BV::new(
            py,
            &GLOBAL_CONTEXT
                .not(&b_bv.get().inner)?
                .simplify_ext(true, true)?,
        )
        .map(|b| b.into_any().cast_into::<Base>().unwrap());
    } else {
        Err(ClaripyError::TypeError(format!(
            "Not: unsupported type {b:?}, expected Bool or BV"
        )))
    }
}

#[pyfunction(name = "And", signature = (*args))]
pub fn and<'py>(
    py: Python<'py>,
    args: Vec<Bound<'py, PyAny>>,
) -> Result<Bound<'py, Base>, ClaripyError> {
    // No operands: the identity element, true.
    if args.is_empty() {
        return Bool::new(py, &GLOBAL_CONTEXT.true_()?)
            .map(|b| b.into_any().cast_into::<Base>().unwrap());
    }
    // If all args are actually Bools (or Python bool literals) — not BVs
    // being coerced through the Bool path — use the Bool And. Otherwise fall
    // back to BV bitwise And.
    let all_bools = args
        .iter()
        .all(|arg| arg.cast::<Bool>().is_ok() || arg.extract::<bool>().is_ok());
    if all_bools {
        let bool_args = args
            .into_iter()
            .map(|arg| {
                arg.extract::<CoerceBool>()
                    .map(|b| b.0.get().inner.clone())
                    .map_err(|_| ClaripyError::TypeError("And arguments must be Bool".to_string()))
            })
            .collect::<Result<Vec<_>, _>>()?;
        return Bool::new(py, &GLOBAL_CONTEXT.and(bool_args)?.simplify()?)
            .map(|b| b.into_any().cast_into::<Base>().unwrap());
    }
    if args.len() == 2
        && let Some(lhs) = args[0].extract::<CoerceBV>().ok()
        && let Some(rhs) = args[1].extract::<CoerceBV>().ok()
    {
        let (lhs, rhs) = CoerceBV::unpack_pair(py, &lhs, &rhs)?;
        return BV::new(
            py,
            &GLOBAL_CONTEXT
                .and2(&lhs.get().inner, &rhs.get().inner)?
                .simplify_ext(true, true)?,
        )
        .map(|b| b.into_any().cast_into::<Base>().unwrap());
    }
    Err(ClaripyError::TypeError(
        "And: expected Bools or exactly two BVs".to_string(),
    ))
}

#[pyfunction(name = "Or", signature = (*args))]
pub fn or<'py>(
    py: Python<'py>,
    args: Vec<Bound<'py, PyAny>>,
) -> Result<Bound<'py, Base>, ClaripyError> {
    // No operands: the identity element, false.
    if args.is_empty() {
        return Bool::new(py, &GLOBAL_CONTEXT.false_()?)
            .map(|b| b.into_any().cast_into::<Base>().unwrap());
    }
    // Same policy as And: prefer the Bool path whenever every arg is a Bool.
    let all_bools = args
        .iter()
        .all(|arg| arg.cast::<Bool>().is_ok() || arg.extract::<bool>().is_ok());
    if all_bools {
        let bool_args = args
            .into_iter()
            .map(|arg| {
                arg.extract::<CoerceBool>()
                    .map(|b| b.0.get().inner.clone())
                    .map_err(|_| ClaripyError::TypeError("Or arguments must be Bool".to_string()))
            })
            .collect::<Result<Vec<_>, _>>()?;
        return Bool::new(py, &GLOBAL_CONTEXT.or(bool_args)?.simplify()?)
            .map(|b| b.into_any().cast_into::<Base>().unwrap());
    }
    if args.len() == 2
        && let Some(lhs) = args[0].extract::<CoerceBV>().ok()
        && let Some(rhs) = args[1].extract::<CoerceBV>().ok()
    {
        let (lhs, rhs) = CoerceBV::unpack_pair(py, &lhs, &rhs)?;
        return BV::new(
            py,
            &GLOBAL_CONTEXT
                .or2(&lhs.get().inner, &rhs.get().inner)?
                .simplify_ext(true, true)?,
        )
        .map(|b| b.into_any().cast_into::<Base>().unwrap());
    }
    Err(ClaripyError::TypeError(
        "Or: expected Bools or exactly two BVs".to_string(),
    ))
}

#[pyfunction]
#[allow(non_snake_case)]
pub fn xor<'py>(
    py: Python<'py>,
    a: Bound<'py, PyAny>,
    b: Bound<'py, PyAny>,
) -> Result<Bound<'py, Base>, ClaripyError> {
    if let Ok(a_bool) = a.cast::<Bool>() {
        if let Ok(b_bool) = b.cast::<Bool>() {
            return Bool::new(
                py,
                &GLOBAL_CONTEXT
                    .xor2(&a_bool.get().inner, &b_bool.get().inner)?
                    .simplify()?,
            )
            .map(|b| b.into_any().cast_into::<Base>().unwrap());
        } else {
            Err(ClaripyError::TypeError(format!(
                "Xor: mismatched types, expected Bool but got {b:?}"
            )))
        }
    } else if let Ok(a_bv) = a.extract::<CoerceBV>() {
        if let Ok(b_bv) = b.extract::<CoerceBV>() {
            let (a_bv, b_bv) = CoerceBV::unpack_pair(py, &a_bv, &b_bv)?;
            return BV::new(
                py,
                &GLOBAL_CONTEXT
                    .xor2(&a_bv.get().inner, &b_bv.get().inner)?
                    .simplify_ext(true, true)?,
            )
            .map(|b| b.into_any().cast_into::<Base>().unwrap());
        } else {
            Err(ClaripyError::TypeError(format!(
                "Xor: mismatched types, expected BV but got {b:?}"
            )))
        }
    } else {
        Err(ClaripyError::TypeError(format!(
            "Xor: unsupported types {a:?} and {b:?}"
        )))
    }
}

#[pyfunction(name = "If")]
pub fn r#if<'py>(
    py: Python<'py>,
    cond: CoerceBool,
    then_: Bound<'py, PyAny>,
    else_: Bound<'py, PyAny>,
) -> Result<Bound<'py, Base>, ClaripyError> {
    // Each branch's sort, or None for Python literals (which coerce freely).
    let then_type = then_.cast::<Base>().ok().map(|b| b.get().ast().ast_type());
    let else_type = else_.cast::<Base>().ok().map(|b| b.get().ast().ast_type());

    // Two genuine ASTs must be the same type; a literal side (None) coerces freely.
    if let (Some(then_type), Some(else_type)) = (then_type, else_type)
        && then_type != else_type
    {
        return Err(ClaripyError::TypeError(format!(
            "Mismatched types in if-then-else: then-branch is {then_type:?}, else-branch is {else_type:?}"
        )));
    }

    // A Bool coerces to a BV, so handle Bool before the BV path to keep the result a Bool.
    if matches!(then_type, Some(AstType::Bool)) || matches!(else_type, Some(AstType::Bool)) {
        let then_bool = then_.extract::<CoerceBool>()?;
        let else_bool = else_.extract::<CoerceBool>()?;
        Bool::new(
            py,
            &GLOBAL_CONTEXT
                .ite(
                    &cond.0.get().inner,
                    &then_bool.0.get().inner,
                    &else_bool.0.get().inner,
                )?
                .simplify()?,
        )
        .map(|b| b.into_any().cast_into::<Base>().unwrap())
    } else if let Ok(then_bv) = then_.extract::<CoerceBV>() {
        if let Ok(else_bv) = else_.extract::<CoerceBV>() {
            let (then_bv, else_bv) = CoerceBV::unpack_pair(py, &then_bv, &else_bv)?;
            BV::new(
                py,
                &GLOBAL_CONTEXT
                    .ite(
                        &cond.0.get().inner,
                        &then_bv.get().inner,
                        &else_bv.get().inner,
                    )?
                    .simplify_ext(true, true)?,
            )
            .map(|b| b.into_any().cast_into::<Base>().unwrap())
        } else {
            Err(ClaripyError::TypeError(format!(
                "Sort mismatch in if-then-else: {then_:?} and {else_:?}"
            )))
        }
    } else if let Ok(then_fp) = then_.extract::<CoerceFP>() {
        if let Ok(else_fp) = else_.extract::<CoerceFP>() {
            let (then_fp, else_fp) = CoerceFP::unpack_pair(py, &then_fp, &else_fp)?;
            FP::new(
                py,
                &GLOBAL_CONTEXT
                    .ite(
                        &cond.0.get().inner,
                        &then_fp.get().inner,
                        &else_fp.get().inner,
                    )?
                    .simplify()?,
            )
            .map(|b| b.into_any().cast_into::<Base>().unwrap())
        } else {
            Err(ClaripyError::TypeError(format!(
                "Sort mismatch in if-then-else: {then_:?} and {else_:?}"
            )))
        }
    } else if let Ok(then_string) = then_.extract::<CoerceString>() {
        if let Ok(else_string) = else_.extract::<CoerceString>() {
            let then_bv = then_string.0.get().inner.clone();
            let else_bv = else_string.0.get().inner.clone();
            PyAstString::new(
                py,
                &GLOBAL_CONTEXT
                    .ite(&cond.0.get().inner, &then_bv, &else_bv)?
                    .simplify()?,
            )
            .map(|b| b.into_any().cast_into::<Base>().unwrap())
        } else {
            Err(ClaripyError::TypeError(format!(
                "Sort mismatch in if-then-else: {then_:?} and {else_:?}"
            )))
        }
    } else {
        Err(ClaripyError::TypeError(format!(
            "Unsupported type in if-then-else: {then_:?}"
        )))
    }
}

pub(crate) fn import(py: Python, m: &Bound<PyModule>) -> PyResult<()> {
    import_submodule(py, m, "angr.rustylib.claripy.ast", "base", base::import)?;
    import_submodule(py, m, "angr.rustylib.claripy.ast", "bits", bits::import)?;
    import_submodule(py, m, "angr.rustylib.claripy.ast", "bool", bool::import)?;
    import_submodule(py, m, "angr.rustylib.claripy.ast", "bv", bv::import)?;
    import_submodule(py, m, "angr.rustylib.claripy.ast", "fp", fp::import)?;
    import_submodule(
        py,
        m,
        "angr.rustylib.claripy.ast",
        "strings",
        string::import,
    )?;

    m.add_class::<base::Base>()?;
    m.add_class::<bits::Bits>()?;
    m.add_class::<bool::Bool>()?;
    m.add_class::<bv::BV>()?;
    m.add_class::<fp::FP>()?;
    m.add_class::<string::PyAstString>()?;
    m.add_function(wrap_pyfunction!(bool::true_op, m)?)?;
    m.add_function(wrap_pyfunction!(bool::false_op, m)?)?;
    Ok(())
}
