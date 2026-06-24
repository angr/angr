#![allow(clippy::declare_interior_mutable_const)]

#[macro_use]
mod macros;

pub mod annotation;
pub mod ast;
mod dynsolver;
pub mod error;
pub mod prelude;
pub mod py_err;
pub mod pyslicemethodsext;
pub mod solver;
pub mod vsa;

use num_bigint::BigInt;
use prelude::*;

fn import_submodule<'py>(
    py: Python<'py>,
    m: &Bound<'py, PyModule>,
    package: &str,
    name: &str,
    import_func: impl FnOnce(Python<'py>, &Bound<'py, PyModule>) -> PyResult<()>,
) -> PyResult<()> {
    let submodule = PyModule::new(py, name)?;
    import_func(py, &submodule)?;
    pyo3::py_run!(
        py,
        submodule,
        &format!("import sys; sys.modules['{package}.{name}'] = submodule")
    );
    m.add_submodule(&submodule)?;
    Ok(())
}

fn add_submodule<'py>(
    py: Python<'py>,
    m: &Bound<'py, PyModule>,
    package: &str,
    name: &str,
    build_func: impl FnOnce(Python<'py>) -> PyResult<Bound<'py, PyModule>>,
) -> PyResult<Bound<'py, PyModule>> {
    let submodule = build_func(py)?;
    pyo3::py_run!(
        py,
        submodule,
        &format!("import sys; sys.modules['{package}.{name}'] = submodule")
    );
    m.add_submodule(&submodule)?;
    m.add(name, submodule.clone())?;
    Ok(submodule)
}

#[pyfunction(name = "simplify")]
fn py_simplify<'py>(
    py: Python<'py>,
    expr: Bound<'py, Base>,
) -> Result<Bound<'py, Base>, ClaripyError> {
    if let Ok(bv_value) = expr.cast::<BV>() {
        BV::new(py, &bv_value.get().inner.simplify().unwrap())
            .map(|b| b.into_any().cast_into::<Base>().unwrap())
    } else if let Ok(bool_value) = expr.cast::<Bool>() {
        Bool::new(py, &bool_value.get().inner.simplify().unwrap())
            .map(|b| b.into_any().cast_into::<Base>().unwrap())
    } else if let Ok(fp_value) = expr.cast::<FP>() {
        FP::new(py, &fp_value.get().inner.simplify().unwrap())
            .map(|b| b.into_any().cast_into::<Base>().unwrap())
    } else if let Ok(string_value) = expr.cast::<PyAstString>() {
        PyAstString::new(py, &string_value.get().inner.simplify().unwrap())
            .map(|b| b.into_any().cast_into::<Base>().unwrap())
    } else {
        panic!("Unsupported type");
    }
}

#[pyfunction(name = "replace")]
fn py_replace<'py>(
    expr: Bound<'py, Base>,
    old: Bound<'py, Base>,
    new: Bound<'py, Base>,
) -> Result<Bound<'py, Base>, ClaripyError> {
    let old_dyn = Base::to_ast(old)?;
    let new_dyn = Base::to_ast(new)?;

    // Convert new type to old type, if they do not match and both are BV or FP
    let new_coerced = match (old_dyn.ast_type(), new_dyn.ast_type()) {
        (AstType::BitVec(_), AstType::Float(_)) => new_dyn.context().fp_to_ieeebv(&new_dyn)?,
        (AstType::Float(_), AstType::BitVec(_)) => {
            new_dyn.context().bv_to_fp(&new_dyn, old_dyn.sort())?
        }
        _ => new_dyn.clone(),
    };

    Base::from_ast(
        expr.py(),
        Base::to_ast(expr)?
            .replace(&old_dyn, &new_coerced)?
            .simplify()?,
    )
}

#[pyfunction(name = "excavate_ite")]
fn py_excavate_ite<'py>(
    py: Python<'py>,
    expr: Bound<'py, Base>,
) -> Result<Bound<'py, Base>, ClaripyError> {
    Base::from_ast(py, Base::to_ast(expr)?.excavate_ite()?.simplify()?)
}

#[pyfunction]
fn is_true(expr: Bound<'_, PyAny>) -> Result<bool, ClaripyError> {
    if let Ok(bool_expr) = expr.extract::<CoerceBool>() {
        Ok(bool_expr.0.get().inner.simplify()?.is_true())
    } else if let Ok(bv_expr) = expr.extract::<CoerceBV>() {
        match bv_expr {
            CoerceBV::BV(bv_expr) => Ok(bv_expr.get().inner.simplify()?.is_true()),
            CoerceBV::Int(int_expr) => Ok(int_expr != BigInt::ZERO),
            CoerceBV::Bool(bool_expr) => Ok(bool_expr.get().inner.simplify()?.is_true()),
        }
    } else if let Ok(fp_expr) = expr.extract::<CoerceFP>() {
        match fp_expr {
            CoerceFP::FP(fp_expr) => Ok(fp_expr.get().inner.simplify()?.is_true()),
            CoerceFP::Py(float) => Ok(float.extract::<f64>()? != 0.0),
        }
    } else if let Ok(string_expr) = expr.extract::<CoerceString>() {
        Ok(string_expr.0.get().inner.simplify()?.is_true())
    } else {
        // Anything we cannot prove true is not true. This matches claripy
        // (whose concrete backend raises BackendError for non-AST inputs,
        // which is_true treats as False); falling back to Python truthiness
        // would instead report every foreign object as true.
        Ok(false)
    }
}

#[pyfunction]
fn is_false(expr: Bound<'_, PyAny>) -> Result<bool, ClaripyError> {
    if let Ok(bool_expr) = expr.extract::<CoerceBool>() {
        Ok(bool_expr.0.get().inner.simplify()?.is_false())
    } else if let Ok(bv_expr) = expr.extract::<CoerceBV>() {
        match bv_expr {
            CoerceBV::BV(bv_expr) => Ok(bv_expr.get().inner.simplify()?.is_false()),
            CoerceBV::Int(int_expr) => Ok(int_expr == BigInt::ZERO),
            CoerceBV::Bool(bool_expr) => Ok(bool_expr.get().inner.simplify()?.is_false()),
        }
    } else if let Ok(fp_expr) = expr.extract::<CoerceFP>() {
        match fp_expr {
            CoerceFP::FP(fp_expr) => Ok(fp_expr.get().inner.simplify()?.is_false()),
            CoerceFP::Py(float) => Ok(float.extract::<f64>()? == 0.0),
        }
    } else if let Ok(string_expr) = expr.extract::<CoerceString>() {
        Ok(string_expr.0.get().inner.simplify()?.is_false())
    } else {
        // See is_true: claripy returns False for anything it cannot prove.
        Ok(false)
    }
}

#[pymodule]
pub fn claripy(py: Python, m: &Bound<'_, PyModule>) -> PyResult<()> {
    let annotation = add_submodule(py, m, "claripy", "annotation", annotation::build_module)?;
    import_submodule(py, m, "claripy", "ast", ast::import)?;
    import_submodule(py, m, "claripy", "solver", solver::import)?;
    import_submodule(py, m, "claripy", "vsa", vsa::import)?;

    add_pyfunctions!(
        m,
        // Bool
        ast::bool::BoolS,
        ast::bool::BoolV,
        ast::bool::true_op,
        ast::bool::false_op,
        // BV
        ast::bv::BVS,
        ast::bv::BVV,
        ast::bv::Add,
        ast::bv::Sub,
        ast::bv::Mul,
        ast::bv::UDiv,
        ast::bv::SDiv,
        ast::bv::UMod,
        ast::bv::SMod,
        ast::bv::ShL,
        ast::bv::LShR,
        ast::bv::AShR,
        ast::bv::RotateLeft,
        ast::bv::RotateRight,
        ast::bv::Concat,
        ast::bv::Extract,
        ast::bv::ZeroExt,
        ast::bv::SignExt,
        ast::bv::Reverse,
        ast::bv::Eq_,
        ast::bv::Neq,
        ast::bv::ULT,
        ast::bv::ULE,
        ast::bv::UGT,
        ast::bv::UGE,
        ast::bv::SLT,
        ast::bv::SLE,
        ast::bv::SGT,
        ast::bv::SGE,
        ast::bv::SI,
        ast::bv::ESI,
        ast::bv::VS,
        ast::bv::union,
        ast::bv::intersection,
        ast::bv::widen,
        // FP
        ast::fp::FPS,
        ast::fp::FPV,
        ast::fp::fpFP,
        ast::fp::FpToFP,
        ast::fp::BvToFpUnsigned,
        ast::fp::fpToIEEEBV,
        ast::fp::FpToUbv,
        ast::fp::FpToBv,
        ast::fp::FpNeg,
        ast::fp::FpAbs,
        ast::fp::FpAdd,
        ast::fp::FpSub,
        ast::fp::FpMul,
        ast::fp::FpDiv,
        ast::fp::FpSqrt,
        ast::fp::FpEq,
        ast::fp::FpNEQ,
        ast::fp::FpLt,
        ast::fp::FpLeq,
        ast::fp::FpGt,
        ast::fp::FpGeq,
        ast::fp::FpIsNan,
        ast::fp::FpIsInf,
        // String
        ast::string::StringS,
        ast::string::StringV,
        ast::string::StringS,
        ast::string::StringV,
        ast::string::StrLen,
        ast::string::StrConcat,
        ast::string::StrSubstr,
        ast::string::StrContains,
        ast::string::StrIndexOf,
        ast::string::StrReplace,
        ast::string::StrPrefixOf,
        ast::string::StrSuffixOf,
        ast::string::StrToInt,
        ast::string::IntToStr,
        ast::string::StrIsDigit,
        ast::string::StrEq,
        ast::string::StrNeq,
        // Shared
        ast::r#if,
        ast::not,
        ast::and,
        ast::or,
        ast::xor,
    );

    m.add_class::<ast::base::Base>()?;
    m.add_class::<ast::bits::Bits>()?;
    m.add_class::<ast::bool::Bool>()?;
    m.add_class::<ast::bv::BV>()?;
    m.add_class::<ast::fp::FP>()?;
    m.add_class::<ast::string::PyAstString>()?;

    m.add("Annotation", annotation.getattr("Annotation")?)?;
    m.add(
        "SimplificationAvoidanceAnnotation",
        annotation.getattr("SimplificationAvoidanceAnnotation")?,
    )?;
    m.add(
        "StridedIntervalAnnotation",
        annotation.getattr("StridedIntervalAnnotation")?,
    )?;
    m.add("RegionAnnotation", annotation.getattr("RegionAnnotation")?)?;
    m.add(
        "UninitializedAnnotation",
        annotation.getattr("UninitializedAnnotation")?,
    )?;

    m.add("ClaripyError", py.get_type::<py_err::ClaripyError>())?;
    m.add(
        "ClaripyTypeError",
        py.get_type::<py_err::ClaripyTypeError>(),
    )?;
    m.add("UnsatError", py.get_type::<py_err::UnsatError>())?;
    m.add(
        "ClaripyFrontendError",
        py.get_type::<py_err::ClaripyFrontendError>(),
    )?;
    m.add(
        "ClaripySolverInterruptError",
        py.get_type::<py_err::ClaripySolverInterruptError>(),
    )?;
    m.add(
        "ClaripyOperationError",
        py.get_type::<py_err::ClaripyOperationError>(),
    )?;
    m.add(
        "ClaripyZeroDivisionError",
        py.get_type::<py_err::ClaripyZeroDivisionError>(),
    )?;
    m.add(
        "InvalidExtractBounds",
        py.get_type::<py_err::InvalidExtractBoundsError>(),
    )?;

    m.add("FSORT_FLOAT", ast::fp::fsort_float())?;
    m.add("FSORT_DOUBLE", ast::fp::fsort_double())?;

    m.add_function(wrap_pyfunction!(py_simplify, m)?)?;
    m.add_function(wrap_pyfunction!(py_replace, m)?)?;
    m.add_function(wrap_pyfunction!(py_excavate_ite, m)?)?;
    m.add_function(wrap_pyfunction!(is_true, m)?)?;
    m.add_function(wrap_pyfunction!(is_false, m)?)?;
    m.add_function(wrap_pyfunction!(ast::bool::ite_cases, m)?)?;
    m.add_function(wrap_pyfunction!(ast::bool::reverse_ite_cases, m)?)?;
    m.add_function(wrap_pyfunction!(ast::bool::ite_dict, m)?)?;
    m.add_class::<solver::PySolver>()?;
    m.add_class::<solver::PyConcreteSolver>()?;
    m.add_class::<solver::PyVSASolver>()?;
    m.add_class::<solver::PyZ3Solver>()?;
    m.add_class::<solver::PyCachelessSolver>()?;
    m.add_class::<solver::PyHybridSolver>()?;
    m.add_class::<solver::PyReplacementSolver>()?;
    m.add_class::<solver::PyCompositeSolver>()?;

    // Compat

    // fp
    import_submodule(py, m, "claripy", "fp", |py, fp| {
        fp.add_class::<ast::fp::PyRM>()?;
        fp.add_class::<ast::fp::PyFSort>()?;
        fp.add("FSORT_FLOAT", ast::fp::fsort_float())?;
        fp.add("FSORT_DOUBLE", ast::fp::fsort_double())?;
        pyo3::py_run!(py, fp, "import sys; sys.modules['clarirs.fp'] = fp");
        Ok(())
    })?;

    // errors
    import_submodule(py, m, "claripy", "errors", |py, errors| {
        errors.add("ClaripyError", py.get_type::<py_err::ClaripyError>())?;
        errors.add(
            "ClaripyTypeError",
            py.get_type::<py_err::ClaripyTypeError>(),
        )?;
        errors.add("UnsatError", py.get_type::<py_err::UnsatError>())?;
        errors.add(
            "ClaripyFrontendError",
            py.get_type::<py_err::ClaripyFrontendError>(),
        )?;
        errors.add(
            "ClaripySolverInterruptError",
            py.get_type::<py_err::ClaripySolverInterruptError>(),
        )?;
        errors.add(
            "ClaripyOperationError",
            py.get_type::<py_err::ClaripyOperationError>(),
        )?;
        errors.add(
            "ClaripyZeroDivisionError",
            py.get_type::<py_err::ClaripyZeroDivisionError>(),
        )?;
        errors.add(
            "InvalidExtractBounds",
            py.get_type::<py_err::InvalidExtractBoundsError>(),
        )?;
        Ok(())
    })?;

    Ok(())
}
