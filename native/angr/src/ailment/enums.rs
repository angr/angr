//! Simple PyO3-exposed enums shared across ailment expressions.

use pyo3::prelude::*;
use serde::{Deserialize, Serialize};

/// Mirrors `angr.ailment.expression.VirtualVariableCategory` (IntEnum).
#[pyclass(
    eq,
    eq_int,
    module = "angr.rustylib.ailment",
    name = "VirtualVariableCategory",
    from_py_object
)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[allow(non_camel_case_types)]
pub enum VirtualVariableCategory {
    REGISTER = 0,
    STACK = 1,
    MEMORY = 2,
    PARAMETER = 3,
    TMP = 4,
    COMBO_REGISTER = 5,
    UNKNOWN = 6,
}

#[pymethods]
impl VirtualVariableCategory {
    #[getter]
    fn value(&self) -> u8 {
        *self as u8
    }

    #[getter]
    fn name(&self) -> &'static str {
        match self {
            Self::REGISTER => "REGISTER",
            Self::STACK => "STACK",
            Self::MEMORY => "MEMORY",
            Self::PARAMETER => "PARAMETER",
            Self::TMP => "TMP",
            Self::COMBO_REGISTER => "COMBO_REGISTER",
            Self::UNKNOWN => "UNKNOWN",
        }
    }

    fn __repr__(&self) -> String {
        format!("<VirtualVariableCategory.{}: {}>", self.name(), *self as u8)
    }

    fn __int__(&self) -> u8 {
        *self as u8
    }

    fn __hash__(&self) -> u64 {
        *self as u64
    }

    /// Static reconstructor exposed to Python for pickle. Takes the
    /// integer value and returns the corresponding variant.
    #[staticmethod]
    fn _from_int_py(v: i64) -> PyResult<VirtualVariableCategory> {
        VirtualVariableCategory::from_int(v).ok_or_else(|| {
            pyo3::exceptions::PyValueError::new_err(format!(
                "Unknown VirtualVariableCategory value: {}",
                v
            ))
        })
    }

    /// Pickle support: reconstruct via ``VirtualVariableCategory._from_int_py(value)``.
    fn __reduce__<'py>(slf: Bound<'py, Self>) -> PyResult<Py<PyAny>> {
        let py = slf.py();
        let cls = py
            .import("angr.rustylib.ailment")?
            .getattr("VirtualVariableCategory")?;
        let from_int = cls.getattr("_from_int_py")?;
        let v = *slf.borrow() as u8;
        let args = pyo3::types::PyTuple::new(py, [v.into_pyobject(py)?.into_any().unbind()])?;
        let tup = pyo3::types::PyTuple::new(py, [from_int.unbind().into_any(), args.into_any().unbind()])?;
        Ok(tup.into_any().unbind())
    }
}

impl VirtualVariableCategory {
    pub fn from_int(v: i64) -> Option<Self> {
        Some(match v {
            0 => Self::REGISTER,
            1 => Self::STACK,
            2 => Self::MEMORY,
            3 => Self::PARAMETER,
            4 => Self::TMP,
            5 => Self::COMBO_REGISTER,
            6 => Self::UNKNOWN,
            _ => return None,
        })
    }
}

/// Mirrors `angr.ailment.expression.ConvertType` (Enum).
#[pyclass(
    eq,
    eq_int,
    module = "angr.rustylib.ailment",
    name = "ConvertType",
    from_py_object
)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[allow(non_camel_case_types)]
pub enum ConvertType {
    TYPE_INT = 0,
    TYPE_FP = 1,
}

#[pymethods]
impl ConvertType {
    #[getter]
    fn value(&self) -> u8 {
        *self as u8
    }

    #[getter]
    fn name(&self) -> &'static str {
        match self {
            Self::TYPE_INT => "TYPE_INT",
            Self::TYPE_FP => "TYPE_FP",
        }
    }

    fn __repr__(&self) -> String {
        format!("<ConvertType.{}: {}>", self.name(), *self as u8)
    }

    fn __hash__(&self) -> u64 {
        *self as u64
    }

    #[staticmethod]
    fn _from_int_py(v: i64) -> PyResult<ConvertType> {
        ConvertType::from_int(v).ok_or_else(|| {
            pyo3::exceptions::PyValueError::new_err(format!("Unknown ConvertType value: {}", v))
        })
    }

    fn __reduce__<'py>(slf: Bound<'py, Self>) -> PyResult<Py<PyAny>> {
        let py = slf.py();
        let cls = py.import("angr.rustylib.ailment")?.getattr("ConvertType")?;
        let from_int = cls.getattr("_from_int_py")?;
        let v = *slf.borrow() as u8;
        let args = pyo3::types::PyTuple::new(py, [v.into_pyobject(py)?.into_any().unbind()])?;
        let tup = pyo3::types::PyTuple::new(py, [from_int.unbind().into_any(), args.into_any().unbind()])?;
        Ok(tup.into_any().unbind())
    }
}

impl ConvertType {
    pub fn from_int(v: i64) -> Option<Self> {
        Some(match v {
            0 => Self::TYPE_INT,
            1 => Self::TYPE_FP,
            _ => return None,
        })
    }
}

/// Mirrors VEX's 2-bit IRRoundingMode and ``claripy.fp.RM`` ordering:
/// ``0 = NearestTiesEven``, ``1 = TowardsNegativeInf``,
/// ``2 = TowardsPositiveInf``, ``3 = TowardsZero``.
///
/// Stored on ``ExprInner::Convert`` and ``ExprInner::BinaryOp`` as the
/// typed replacement for what used to be an opaque ``Py<PyAny>`` (a
/// ``Const`` AIL expression holding the integer). When the original
/// VEX operand wasn't a concrete ``Const`` in 0..=3 (rare symbolic
/// case), the converter logs a warning and stores ``None`` -- engine
/// consumers already fall back to ``claripy.fp.RM.default()`` when
/// the rounding mode is missing.
#[pyclass(
    eq,
    eq_int,
    module = "angr.rustylib.ailment",
    name = "RoundingMode",
    from_py_object
)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[allow(non_camel_case_types)]
pub enum RoundingMode {
    RM_NearestTiesEven = 0,
    RM_TowardsNegativeInf = 1,
    RM_TowardsPositiveInf = 2,
    RM_TowardsZero = 3,
}

#[pymethods]
impl RoundingMode {
    #[getter]
    fn value(&self) -> u8 {
        *self as u8
    }

    #[getter]
    fn name(&self) -> &'static str {
        match self {
            Self::RM_NearestTiesEven => "RM_NearestTiesEven",
            Self::RM_TowardsNegativeInf => "RM_TowardsNegativeInf",
            Self::RM_TowardsPositiveInf => "RM_TowardsPositiveInf",
            Self::RM_TowardsZero => "RM_TowardsZero",
        }
    }

    fn __repr__(&self) -> String {
        format!("<RoundingMode.{}: {}>", self.name(), *self as u8)
    }

    fn __int__(&self) -> u8 {
        *self as u8
    }

    fn __hash__(&self) -> u64 {
        *self as u64
    }

    #[staticmethod]
    fn _from_int_py(v: i64) -> PyResult<RoundingMode> {
        RoundingMode::from_int(v).ok_or_else(|| {
            pyo3::exceptions::PyValueError::new_err(format!("Unknown RoundingMode value: {}", v))
        })
    }

    fn __reduce__<'py>(slf: Bound<'py, Self>) -> PyResult<Py<PyAny>> {
        let py = slf.py();
        let cls = py.import("angr.rustylib.ailment")?.getattr("RoundingMode")?;
        let from_int = cls.getattr("_from_int_py")?;
        let v = *slf.borrow() as u8;
        let args = pyo3::types::PyTuple::new(py, [v.into_pyobject(py)?.into_any().unbind()])?;
        let tup = pyo3::types::PyTuple::new(py, [from_int.unbind().into_any(), args.into_any().unbind()])?;
        Ok(tup.into_any().unbind())
    }
}

impl RoundingMode {
    pub fn from_int(v: i64) -> Option<Self> {
        Some(match v {
            0 => Self::RM_NearestTiesEven,
            1 => Self::RM_TowardsNegativeInf,
            2 => Self::RM_TowardsPositiveInf,
            3 => Self::RM_TowardsZero,
            _ => return None,
        })
    }
}
