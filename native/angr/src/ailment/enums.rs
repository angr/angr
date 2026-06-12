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

/// Integer tag for ``Expression`` variants. Exposed as the value of
/// the ``kind`` getter on the ``Expression`` pyclass; replaces the
/// prior ``&'static str`` representation so dispatch lookups become
/// integer hash/compare instead of string interning/hash.
///
/// Note: ``__hash__`` returns ``self as u64`` so the enum hashes
/// identically to its integer value -- a dict keyed by
/// ``ExpressionKind`` accepts lookups by raw ``int`` and vice versa.
#[pyclass(
    eq,
    eq_int,
    module = "angr.rustylib.ailment",
    name = "ExpressionKind",
    from_py_object
)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[allow(non_camel_case_types)]
pub enum ExpressionKind {
    Const = 0,
    Tmp = 1,
    Register = 2,
    ComboRegister = 3,
    VirtualVariable = 4,
    Phi = 5,
    UnaryOp = 6,
    BinaryOp = 7,
    Convert = 8,
    Reinterpret = 9,
    Load = 10,
    ITE = 11,
    Extract = 12,
    Insert = 13,
    Call = 14,
    DirtyExpression = 15,
    VEXCCallExpression = 16,
    MultiStatementExpression = 17,
    StringLiteral = 18,
    Struct = 19,
    RustEnum = 20,
    Array = 21,
    Let = 22,
    Macro = 23,
    FunctionLikeMacro = 24,
    BasePointerOffset = 25,
    StackBaseOffset = 26,
}

#[pymethods]
impl ExpressionKind {
    #[getter]
    fn value(&self) -> u8 {
        *self as u8
    }

    #[getter]
    fn name(&self) -> &'static str {
        self.as_str()
    }

    fn __repr__(&self) -> String {
        format!("<ExpressionKind.{}: {}>", self.as_str(), *self as u8)
    }

    fn __int__(&self) -> u8 {
        *self as u8
    }

    fn __hash__(&self) -> u64 {
        *self as u64
    }

    #[staticmethod]
    fn _from_int_py(v: i64) -> PyResult<ExpressionKind> {
        ExpressionKind::from_int(v).ok_or_else(|| {
            pyo3::exceptions::PyValueError::new_err(format!(
                "Unknown ExpressionKind value: {}",
                v
            ))
        })
    }

    fn __reduce__<'py>(slf: Bound<'py, Self>) -> PyResult<Py<PyAny>> {
        let py = slf.py();
        let cls = py
            .import("angr.rustylib.ailment")?
            .getattr("ExpressionKind")?;
        let from_int = cls.getattr("_from_int_py")?;
        let v = *slf.borrow() as u8;
        let args = pyo3::types::PyTuple::new(py, [v.into_pyobject(py)?.into_any().unbind()])?;
        let tup = pyo3::types::PyTuple::new(
            py,
            [from_int.unbind().into_any(), args.into_any().unbind()],
        )?;
        Ok(tup.into_any().unbind())
    }
}

impl ExpressionKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Const => "Const",
            Self::Tmp => "Tmp",
            Self::Register => "Register",
            Self::ComboRegister => "ComboRegister",
            Self::VirtualVariable => "VirtualVariable",
            Self::Phi => "Phi",
            Self::UnaryOp => "UnaryOp",
            Self::BinaryOp => "BinaryOp",
            Self::Convert => "Convert",
            Self::Reinterpret => "Reinterpret",
            Self::Load => "Load",
            Self::ITE => "ITE",
            Self::Extract => "Extract",
            Self::Insert => "Insert",
            Self::Call => "Call",
            Self::DirtyExpression => "DirtyExpression",
            Self::VEXCCallExpression => "VEXCCallExpression",
            Self::MultiStatementExpression => "MultiStatementExpression",
            Self::StringLiteral => "StringLiteral",
            Self::Struct => "Struct",
            Self::RustEnum => "RustEnum",
            Self::Array => "Array",
            Self::Let => "Let",
            Self::Macro => "Macro",
            Self::FunctionLikeMacro => "FunctionLikeMacro",
            Self::BasePointerOffset => "BasePointerOffset",
            Self::StackBaseOffset => "StackBaseOffset",
        }
    }

    pub fn from_int(v: i64) -> Option<Self> {
        Some(match v {
            0 => Self::Const,
            1 => Self::Tmp,
            2 => Self::Register,
            3 => Self::ComboRegister,
            4 => Self::VirtualVariable,
            5 => Self::Phi,
            6 => Self::UnaryOp,
            7 => Self::BinaryOp,
            8 => Self::Convert,
            9 => Self::Reinterpret,
            10 => Self::Load,
            11 => Self::ITE,
            12 => Self::Extract,
            13 => Self::Insert,
            14 => Self::Call,
            15 => Self::DirtyExpression,
            16 => Self::VEXCCallExpression,
            17 => Self::MultiStatementExpression,
            18 => Self::StringLiteral,
            19 => Self::Struct,
            20 => Self::RustEnum,
            21 => Self::Array,
            22 => Self::Let,
            23 => Self::Macro,
            24 => Self::FunctionLikeMacro,
            25 => Self::BasePointerOffset,
            26 => Self::StackBaseOffset,
            _ => return None,
        })
    }
}

/// Integer tag for ``Statement`` variants. See ``ExpressionKind`` for
/// rationale.
#[pyclass(
    eq,
    eq_int,
    module = "angr.rustylib.ailment",
    name = "StatementKind",
    from_py_object
)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[allow(non_camel_case_types)]
pub enum StatementKind {
    Assignment = 0,
    WeakAssignment = 1,
    Label = 2,
    Store = 3,
    Jump = 4,
    ConditionalJump = 5,
    SideEffectStatement = 6,
    Return = 7,
    CAS = 8,
    DirtyStatement = 9,
    NoOp = 10,
}

#[pymethods]
impl StatementKind {
    #[getter]
    fn value(&self) -> u8 {
        *self as u8
    }

    #[getter]
    fn name(&self) -> &'static str {
        self.as_str()
    }

    fn __repr__(&self) -> String {
        format!("<StatementKind.{}: {}>", self.as_str(), *self as u8)
    }

    fn __int__(&self) -> u8 {
        *self as u8
    }

    fn __hash__(&self) -> u64 {
        *self as u64
    }

    #[staticmethod]
    fn _from_int_py(v: i64) -> PyResult<StatementKind> {
        StatementKind::from_int(v).ok_or_else(|| {
            pyo3::exceptions::PyValueError::new_err(format!(
                "Unknown StatementKind value: {}",
                v
            ))
        })
    }

    fn __reduce__<'py>(slf: Bound<'py, Self>) -> PyResult<Py<PyAny>> {
        let py = slf.py();
        let cls = py
            .import("angr.rustylib.ailment")?
            .getattr("StatementKind")?;
        let from_int = cls.getattr("_from_int_py")?;
        let v = *slf.borrow() as u8;
        let args = pyo3::types::PyTuple::new(py, [v.into_pyobject(py)?.into_any().unbind()])?;
        let tup = pyo3::types::PyTuple::new(
            py,
            [from_int.unbind().into_any(), args.into_any().unbind()],
        )?;
        Ok(tup.into_any().unbind())
    }
}

impl StatementKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Assignment => "Assignment",
            Self::WeakAssignment => "WeakAssignment",
            Self::Label => "Label",
            Self::Store => "Store",
            Self::Jump => "Jump",
            Self::ConditionalJump => "ConditionalJump",
            Self::SideEffectStatement => "SideEffectStatement",
            Self::Return => "Return",
            Self::CAS => "CAS",
            Self::DirtyStatement => "DirtyStatement",
            Self::NoOp => "NoOp",
        }
    }

    pub fn from_int(v: i64) -> Option<Self> {
        Some(match v {
            0 => Self::Assignment,
            1 => Self::WeakAssignment,
            2 => Self::Label,
            3 => Self::Store,
            4 => Self::Jump,
            5 => Self::ConditionalJump,
            6 => Self::SideEffectStatement,
            7 => Self::Return,
            8 => Self::CAS,
            9 => Self::DirtyStatement,
            10 => Self::NoOp,
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
