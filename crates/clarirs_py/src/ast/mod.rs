pub mod args;
pub mod base;
pub mod bits;
pub mod bool;
pub mod bv;
pub mod coerce;
pub mod fp;
pub mod opstring;
pub mod string;

use std::sync::LazyLock;

use crate::prelude::*;

use super::import_submodule;

pub static GLOBAL_CONTEXT: LazyLock<Context<'static>> = LazyLock::new(Context::new);

#[pyfunction(name = "Not")]
pub fn not<'py>(py: Python<'py>, b: Bound<'py, Base>) -> Result<Bound<'py, Base>, ClaripyError> {
    if let Ok(b_bool) = b.clone().into_any().cast::<Bool>() {
        return Bool::new(py, &GLOBAL_CONTEXT.not(&b_bool.get().inner)?)
            .map(|b| b.into_any().cast::<Base>().unwrap().clone());
    } else if let Ok(b_bv) = b.clone().into_any().cast::<BV>() {
        return BV::new(py, &GLOBAL_CONTEXT.not(&b_bv.get().inner)?)
            .map(|b| b.into_any().cast::<Base>().unwrap().clone());
    } else {
        panic!("unsupported type")
    }
}

#[pyfunction(name = "And", signature = (*args))]
pub fn and<'py>(
    py: Python<'py>,
    args: Vec<Bound<'py, PyAny>>,
) -> Result<Bound<'py, Base>, ClaripyError> {
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
        return Bool::new(py, &GLOBAL_CONTEXT.and(bool_args)?)
            .map(|b| b.into_any().cast::<Base>().unwrap().clone());
    }
    if args.len() == 2
        && let Some(lhs) = args[0].extract::<CoerceBV>().ok()
        && let Some(rhs) = args[1].extract::<CoerceBV>().ok()
    {
        let (lhs, rhs) = CoerceBV::unpack_pair(py, &lhs, &rhs)?;
        return BV::new(
            py,
            &GLOBAL_CONTEXT.and2(&lhs.get().inner, &rhs.get().inner)?,
        )
        .map(|b| b.into_any().cast::<Base>().unwrap().clone());
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
        return Bool::new(py, &GLOBAL_CONTEXT.or(bool_args)?)
            .map(|b| b.into_any().cast::<Base>().unwrap().clone());
    }
    if args.len() == 2
        && let Some(lhs) = args[0].extract::<CoerceBV>().ok()
        && let Some(rhs) = args[1].extract::<CoerceBV>().ok()
    {
        let (lhs, rhs) = CoerceBV::unpack_pair(py, &lhs, &rhs)?;
        return BV::new(py, &GLOBAL_CONTEXT.or2(&lhs.get().inner, &rhs.get().inner)?)
            .map(|b| b.into_any().cast::<Base>().unwrap().clone());
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
    if let Ok(a_bool) = a.clone().into_any().cast::<Bool>() {
        if let Ok(b_bool) = b.clone().into_any().cast::<Bool>() {
            return Bool::new(
                py,
                &GLOBAL_CONTEXT.xor2(&a_bool.get().inner, &b_bool.get().inner)?,
            )
            .map(|b| b.into_any().cast::<Base>().unwrap().clone());
        } else {
            panic!("mismatched types")
        }
    } else if let Ok(a_bv) = a.clone().into_any().extract::<CoerceBV>() {
        if let Ok(b_bv) = b.clone().into_any().extract::<CoerceBV>() {
            let (a_bv, b_bv) = CoerceBV::unpack_pair(py, &a_bv, &b_bv)?;
            return BV::new(
                py,
                &GLOBAL_CONTEXT.xor2(&a_bv.get().inner, &b_bv.get().inner)?,
            )
            .map(|b| b.into_any().cast::<Base>().unwrap().clone());
        } else {
            panic!("mismatched types")
        }
    } else {
        panic!("unsupported type")
    }
}

#[pyfunction(name = "If")]
pub fn r#if<'py>(
    py: Python<'py>,
    cond: CoerceBool,
    then_: Bound<'py, PyAny>,
    else_: Bound<'py, PyAny>,
) -> Result<Bound<'py, Base>, ClaripyError> {
    if let Ok(then_bv) = then_.clone().into_any().extract::<CoerceBV>() {
        if let Ok(else_bv) = else_.clone().into_any().extract::<CoerceBV>() {
            let (then_bv, else_bv) = CoerceBV::unpack_pair(py, &then_bv, &else_bv)?;
            BV::new(
                py,
                &GLOBAL_CONTEXT.ite(
                    &cond.0.get().inner,
                    &then_bv.get().inner,
                    &else_bv.get().inner,
                )?,
            )
            .map(|b| b.into_any().cast::<Base>().unwrap().clone())
        } else {
            Err(ClaripyError::TypeError(format!(
                "Sort mismatch in if-then-else: {then_:?} and {else_:?}"
            )))
        }
    } else if let Ok(then_bool) = then_.clone().into_any().extract::<CoerceBool>() {
        if let Ok(else_bv) = else_.clone().into_any().extract::<CoerceBool>() {
            let then_bv = then_bool.0.get().inner.clone();
            let else_bv = else_bv.0.get().inner.clone();
            Bool::new(
                py,
                &GLOBAL_CONTEXT.ite(&cond.0.get().inner, &then_bv, &else_bv)?,
            )
            .map(|b| b.into_any().cast::<Base>().unwrap().clone())
        } else {
            Err(ClaripyError::TypeError(format!(
                "Sort mismatch in if-then-else: {then_:?} and {else_:?}"
            )))
        }
    } else if let Ok(then_fp) = then_.clone().into_any().extract::<CoerceFP>() {
        if let Ok(else_fp) = else_.clone().into_any().extract::<CoerceFP>() {
            let (then_fp, else_fp) = CoerceFP::unpack_pair(py, &then_fp, &else_fp)?;
            FP::new(
                py,
                &GLOBAL_CONTEXT.ite(
                    &cond.0.get().inner,
                    &then_fp.get().inner,
                    &else_fp.get().inner,
                )?,
            )
            .map(|b| b.into_any().cast::<Base>().unwrap().clone())
        } else {
            Err(ClaripyError::TypeError(format!(
                "Sort mismatch in if-then-else: {then_:?} and {else_:?}"
            )))
        }
    } else if let Ok(then_string) = then_.clone().into_any().extract::<CoerceString>() {
        if let Ok(else_string) = else_.clone().into_any().extract::<CoerceString>() {
            let then_bv = then_string.0.get().inner.clone();
            let else_bv = else_string.0.get().inner.clone();
            PyAstString::new(
                py,
                &GLOBAL_CONTEXT.ite(&cond.0.get().inner, &then_bv, &else_bv)?,
            )
            .map(|b| b.into_any().cast::<Base>().unwrap().clone())
        } else {
            Err(ClaripyError::TypeError(format!(
                "Sort mismatch in if-then-else: {then_:?} and {else_:?}"
            )))
        }
    } else {
        panic!("unsupported type")
    }
}

pub(crate) fn import(py: Python, m: &Bound<PyModule>) -> PyResult<()> {
    import_submodule(py, m, "claripy.ast", "base", base::import)?;
    import_submodule(py, m, "claripy.ast", "bits", bits::import)?;
    import_submodule(py, m, "claripy.ast", "bool", bool::import)?;
    import_submodule(py, m, "claripy.ast", "bv", bv::import)?;
    import_submodule(py, m, "claripy.ast", "fp", fp::import)?;
    import_submodule(py, m, "claripy.ast", "strings", string::import)?;

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
