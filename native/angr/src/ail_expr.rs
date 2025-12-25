// AIL Expressions

use pyo3::prelude::*;
use std::hash::{Hash, Hasher};
use std::collections::hash_map::DefaultHasher;
use std::sync::Arc;
use std::collections::HashMap;

use crate::ail_stmt::{Statement, Call};
use crate::ail_tags::{Tags, TagValue};

/// Helper function to extract tags from Python kwargs.
/// Accepts a dict where keys are strings and values are int or str.
fn extract_tags(kwargs: Option<&Bound<'_, pyo3::types::PyDict>>) -> PyResult<Tags> {
    let mut tags = Tags::new();
    if let Some(dict) = kwargs {
        for (key, value) in dict.iter() {
            let key_str = key.extract::<String>()?;
            let tag_value = if let Ok(i) = value.extract::<i64>() {
                TagValue::Int(i)
            } else if let Ok(s) = value.extract::<String>() {
                TagValue::Str(s)
            } else {
                return Err(PyErr::new::<pyo3::exceptions::PyTypeError, _>(
                    format!("Tag value for '{}' must be int or str", key_str)
                ));
            };
            tags.insert(key_str, tag_value);
        }
    }
    Ok(tags)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[pyclass(frozen, eq, eq_int)]
pub enum VirtualVariableCategory {
    Register = 0,
    Stack = 1,
    Memory = 2,
    Parameter = 3,
    Tmp = 4,
    Unknown = 5,
}

#[pymethods]
impl VirtualVariableCategory {
    #[new]
    fn new(value: i32) -> PyResult<Self> {
        match value {
            0 => Ok(VirtualVariableCategory::Register),
            1 => Ok(VirtualVariableCategory::Stack),
            2 => Ok(VirtualVariableCategory::Memory),
            3 => Ok(VirtualVariableCategory::Parameter),
            4 => Ok(VirtualVariableCategory::Tmp),
            5 => Ok(VirtualVariableCategory::Unknown),
            _ => Err(PyErr::new::<pyo3::exceptions::PyValueError, _>("Invalid category")),
        }
    }
}

#[derive(Clone, Debug)]
#[pyclass]
pub enum ConstValue {
    Int(i64),
    Float(f64),
}

#[pymethods]
impl ConstValue {
    pub fn __repr__(&self) -> String {
        match self {
            ConstValue::Int(i) => format!("{:#x}", i),
            ConstValue::Float(f) => format!("{}", f),
        }
    }
}

#[pyclass]
#[derive(Clone)]
pub struct Const {
    #[pyo3(get)]
    pub idx: Option<i32>,
    #[pyo3(get)]
    pub value: ConstValue,
    #[pyo3(get)]
    pub bits: i32,
    pub tags: Tags,
}

#[pymethods]
impl Const {
    #[new]
    #[pyo3(signature = (idx, value, bits, **kwargs))]
    fn new(idx: Option<i32>, value: i64, bits: i32, kwargs: Option<&Bound<'_, pyo3::types::PyDict>>) -> PyResult<Self> {
        let const_value = ConstValue::Int(value);
        let tags = extract_tags(kwargs)?;
        Ok(Const {
            idx,
            value: const_value,
            bits,
            tags,
        })
    }

    #[getter]
    fn tags(&self) -> HashMap<String, TagValue> {
        self.tags.clone()
    }

    #[getter]
    fn value_int(&self) -> PyResult<i64> {
        match self.value {
            ConstValue::Int(i) => Ok(i),
            _ => Err(PyErr::new::<pyo3::exceptions::PyTypeError, _>(
                "Incorrect value type; expect int",
            )),
        }
    }

    #[getter]
    fn value_float(&self) -> PyResult<f64> {
        match self.value {
            ConstValue::Float(f) => Ok(f),
            _ => Err(PyErr::new::<pyo3::exceptions::PyTypeError, _>(
                "Incorrect value type; expect float",
            )),
        }
    }

    #[getter]
    fn size(&self) -> i32 {
        self.bits / 8
    }

    pub fn likes(&self, other: &Self) -> bool {
        match (&self.value, &other.value) {
            (ConstValue::Int(a), ConstValue::Int(b)) => a == b && self.bits == other.bits,
            (ConstValue::Float(a), ConstValue::Float(b)) => {
                (a == b || (a.is_nan() && b.is_nan())) && self.bits == other.bits
            }
            _ => false,
        }
    }

    pub fn matches(&self, other: &Self) -> bool {
        self.likes(other)
    }

    pub fn __eq__(&self, other: &Self) -> bool {
        self.idx == other.idx && self.likes(other)
    }

    fn copy(&self) -> Self {
        self.clone()
    }

    pub fn __repr__(&self) -> String {
        match self.value {
            ConstValue::Int(i) => format!("{:#x}<{}>", i, self.bits),
            ConstValue::Float(f) => format!("{}<{}>", f, self.bits),
        }
    }

    fn __str__(&self) -> String {
        self.__repr__()
    }

    fn __hash__(&self) -> u64 {
        let mut hasher = DefaultHasher::new();
        match self.value {
            ConstValue::Int(i) => {
                i.hash(&mut hasher);
            }
            ConstValue::Float(f) => {
                f.to_bits().hash(&mut hasher);
            }
        }
        self.bits.hash(&mut hasher);
        hasher.finish()
    }

    /// Python-exposed replace method - Const has no child expressions.
    #[pyo3(name = "replace")]
    fn py_replace(&self, _old_expr: Expression, _new_expr: Expression) -> (bool, Self) {
        (false, self.clone())
    }
}

#[derive(Clone, Debug)]
#[pyclass(frozen)]
pub enum OIdentValue {
    Int(i32),
    String(String),
    Tuple(Vec<i32>),
}

#[pymethods]
impl OIdentValue {
    pub fn __repr__(&self) -> String {
        match self {
            OIdentValue::Int(i) => format!("{}", i),
            OIdentValue::String(s) => s.clone(),
            OIdentValue::Tuple(v) => format!("{:?}", v),
        }
    }
}

#[pyclass(frozen)]
#[derive(Clone)]
pub struct VirtualVariable {
    #[pyo3(get)]
    pub idx: Option<i32>,
    #[pyo3(get)]
    pub varid: i32,
    #[pyo3(get)]
    pub bits: i32,
    #[pyo3(get)]
    pub category: VirtualVariableCategory,
    #[pyo3(get)]
    pub oident: Option<OIdentValue>,
    pub tags: Tags,
}

#[pymethods]
impl VirtualVariable {
    #[new]
    #[pyo3(signature = (idx, varid, bits, category, oident=None, **kwargs))]
    fn new(
        idx: Option<i32>,
        varid: i32,
        bits: i32,
        category: i32,
        oident: Option<&Bound<'_, PyAny>>,
        kwargs: Option<&Bound<'_, pyo3::types::PyDict>>,
    ) -> PyResult<Self> {
        let cat = VirtualVariableCategory::new(category)?;

        let oident_value = if let Some(o) = oident {
            if let Ok(i) = o.extract::<i32>() {
                Some(OIdentValue::Int(i))
            } else if let Ok(s) = o.extract::<String>() {
                Some(OIdentValue::String(s))
            } else if let Ok(v) = o.extract::<Vec<i32>>() {
                Some(OIdentValue::Tuple(v))
            } else {
                None
            }
        } else {
            None
        };

        let tags = extract_tags(kwargs)?;
        Ok(VirtualVariable {
            idx,
            varid,
            bits,
            category: cat,
            oident: oident_value,
            tags,
        })
    }

    #[getter]
    fn tags(&self) -> HashMap<String, TagValue> {
        self.tags.clone()
    }

    #[getter]
    fn size(&self) -> i32 {
        self.bits / 8
    }

    #[getter]
    fn was_reg(&self) -> bool {
        self.category == VirtualVariableCategory::Register
    }

    #[getter]
    fn was_stack(&self) -> bool {
        self.category == VirtualVariableCategory::Stack
    }

    #[getter]
    fn was_parameter(&self) -> bool {
        self.category == VirtualVariableCategory::Parameter
    }

    #[getter]
    fn was_tmp(&self) -> bool {
        self.category == VirtualVariableCategory::Tmp
    }

    #[getter]
    fn reg_offset(&self) -> PyResult<i32> {
        if self.was_reg() {
            if let Some(OIdentValue::Int(offset)) = self.oident {
                return Ok(offset);
            }
        }
        Err(PyErr::new::<pyo3::exceptions::PyTypeError, _>(
            "Is not a register",
        ))
    }

    #[getter]
    fn stack_offset(&self) -> PyResult<i32> {
        if self.was_stack() {
            if let Some(OIdentValue::Int(offset)) = self.oident {
                return Ok(offset);
            }
        }
        Err(PyErr::new::<pyo3::exceptions::PyTypeError, _>(
            "Is not a stack variable",
        ))
    }

    pub fn likes(&self, other: &Self) -> bool {
        self.varid == other.varid
            && self.bits == other.bits
            && self.category == other.category
            && match (&self.oident, &other.oident) {
                (None, None) => true,
                (Some(OIdentValue::Int(a)), Some(OIdentValue::Int(b))) => a == b,
                (Some(OIdentValue::String(a)), Some(OIdentValue::String(b))) => a == b,
                (Some(OIdentValue::Tuple(a)), Some(OIdentValue::Tuple(b))) => a == b,
                _ => false,
            }
    }

    pub fn matches(&self, other: &Self) -> bool {
        self.bits == other.bits
            && self.category == other.category
            && match (&self.oident, &other.oident) {
                (None, None) => true,
                (Some(OIdentValue::Int(a)), Some(OIdentValue::Int(b))) => a == b,
                (Some(OIdentValue::String(a)), Some(OIdentValue::String(b))) => a == b,
                (Some(OIdentValue::Tuple(a)), Some(OIdentValue::Tuple(b))) => a == b,
                _ => false,
            }
    }

    pub fn __eq__(&self, other: &Self) -> bool {
        self.idx == other.idx && self.likes(other)
    }

    fn copy(&self) -> Self {
        self.clone()
    }

    pub fn __repr__(&self) -> String {
        match self.category {
            VirtualVariableCategory::Register => {
                if let Some(OIdentValue::Int(offset)) = self.oident {
                    format!("vvar_{{{{r{}|{}b}}}}", offset, self.size())
                } else {
                    format!("vvar_{}", self.varid)
                }
            }
            VirtualVariableCategory::Stack => {
                format!("vvar_{{{{s{:?}|{}b}}}}", self.oident, self.size())
            }
            _ => format!("vvar_{}", self.varid),
        }
    }

    fn __str__(&self) -> String {
        self.__repr__()
    }

    fn __hash__(&self) -> u64 {
        let mut hasher = DefaultHasher::new();
        self.varid.hash(&mut hasher);
        self.bits.hash(&mut hasher);
        (self.category as i32).hash(&mut hasher);
        hasher.finish()
    }

    /// Python-exposed replace method - VirtualVariable has no child expressions.
    #[pyo3(name = "replace")]
    fn py_replace(&self, _old_expr: Expression, _new_expr: Expression) -> (bool, Self) {
        (false, self.clone())
    }
}

#[pyclass(frozen)]
#[derive(Clone)]
pub struct UnaryOp {
    #[pyo3(get)]
    pub idx: Option<i32>,
    #[pyo3(get)]
    pub op: String,
    #[pyo3(get)]
    pub bits: i32,
    pub operand: Arc<Expression>,  // Box needed to avoid infinite size
    pub tags: Tags,
}

#[pymethods]
impl UnaryOp {
    #[new]
    #[pyo3(signature = (idx, op, operand, bits=None, **kwargs))]
    fn new(
        idx: Option<i32>,
        op: String,
        operand: Expression,
        bits: Option<i32>,
        kwargs: Option<&Bound<'_, pyo3::types::PyDict>>,
    ) -> PyResult<Self> {
        let operand_bits = bits.unwrap_or_else(|| operand.bits());
        let tags = extract_tags(kwargs)?;

        Ok(UnaryOp {
            idx,
            op,
            bits: operand_bits,
            operand: Arc::new(operand),
            tags,
        })
    }

    #[getter]
    fn operand(&self) -> Expression {
        (*self.operand).clone()
    }

    #[getter]
    fn tags(&self) -> HashMap<String, TagValue> {
        self.tags.clone()
    }

    #[getter]
    fn size(&self) -> i32 {
        self.bits / 8
    }

    pub fn likes(&self, other: &Self) -> bool {
        self.op == other.op
            && self.bits == other.bits
            && self.operand.likes(&other.operand)
    }

    pub fn matches(&self, other: &Self) -> bool {
        self.op == other.op
            && self.bits == other.bits
            && self.operand.matches(&other.operand)
    }

    pub fn __eq__(&self, other: &Self) -> bool {
        self.idx == other.idx && self.likes(other)
    }

    fn copy(&self) -> Self {
        self.clone()
    }

    pub fn __repr__(&self) -> String {
        format!("({} {})", self.op, self.operand.as_ref().__repr__())
    }

    fn __str__(&self) -> String {
        self.__repr__()
    }

    fn __hash__(&self) -> u64 {
        let mut hasher = DefaultHasher::new();
        self.op.hash(&mut hasher);
        self.bits.hash(&mut hasher);
        hasher.finish()
    }

    /// Python-exposed replace method.
    #[pyo3(name = "replace")]
    fn py_replace(&self, old_expr: Expression, new_expr: Expression) -> (bool, Self) {
        self.replace(&old_expr, &new_expr)
    }
}

impl UnaryOp {
    /// Replace old_expr with new_expr in this expression.
    pub fn replace(&self, old_expr: &Expression, new_expr: &Expression) -> (bool, Self) {
        if self.operand.likes(old_expr) {
            (true, UnaryOp {
                idx: self.idx,
                op: self.op.clone(),
                bits: self.bits,
                operand: Arc::new(new_expr.clone()),
                tags: self.tags.clone(),
            })
        } else {
            let (r, replaced_operand) = self.operand.replace(old_expr, new_expr);
            if r {
                (true, UnaryOp {
                    idx: self.idx,
                    op: self.op.clone(),
                    bits: self.bits,
                    operand: Arc::new(replaced_operand),
                    tags: self.tags.clone(),
                })
            } else {
                (false, self.clone())
            }
        }
    }
}

#[pyclass(frozen)]
#[derive(Clone)]
pub struct BinaryOp {
    #[pyo3(get)]
    pub idx: Option<i32>,
    #[pyo3(get)]
    pub op: String,
    #[pyo3(get)]
    pub bits: i32,
    #[pyo3(get)]
    pub signed: bool,
    #[pyo3(get)]
    pub floating_point: bool,
    pub operand_0: Arc<Expression>,
    pub operand_1: Arc<Expression>,
    pub tags: Tags,
}

#[pymethods]
impl BinaryOp {
    #[new]
    #[pyo3(signature = (idx, op, operand_0, operand_1, signed=false, bits=None, floating_point=false, **kwargs))]
    fn new(
        idx: Option<i32>,
        op: String,
        operand_0: Expression,
        operand_1: Expression,
        signed: bool,
        bits: Option<i32>,
        floating_point: bool,
        kwargs: Option<&Bound<'_, pyo3::types::PyDict>>,
    ) -> PyResult<Self> {
        let calculated_bits = if let Some(b) = bits {
            b
        } else {
            match op.as_str() {
                "CmpF" => 32,
                "CmpEQ" | "CmpNE" | "CmpLT" | "CmpGE" | "CmpLE" | "CmpGT" => 1,
                "Carry" | "SCarry" | "SBorrow" => 8,
                "Concat" => operand_0.bits() + operand_1.bits(),
                "Mull" => operand_0.bits() * 2,
                _ => operand_0.bits(),
            }
        };

        let tags = extract_tags(kwargs)?;
        Ok(BinaryOp {
            idx,
            op,
            bits: calculated_bits,
            signed,
            floating_point,
            operand_0: Arc::new(operand_0),
            operand_1: Arc::new(operand_1.clone()),
            tags,
        })
    }

    #[getter]
    fn operands(&self) -> Vec<Expression> {
        vec![(*self.operand_0).clone(), (*self.operand_1).clone()]
    }

    #[getter]
    fn tags(&self) -> HashMap<String, TagValue> {
        self.tags.clone()
    }

    #[getter]
    fn size(&self) -> i32 {
        self.bits / 8
    }

    pub fn likes(&self, other: &Self) -> bool {
        self.op == other.op
            && self.bits == other.bits
            && self.signed == other.signed
            && self.floating_point == other.floating_point
            && self.operand_0.likes(&other.operand_0)
            && self.operand_1.likes(&other.operand_1)
    }

    pub fn matches(&self, other: &Self) -> bool {
        self.op == other.op
            && self.bits == other.bits
            && self.signed == other.signed
            && self.floating_point == other.floating_point
            && self.operand_0.matches(&other.operand_0)
            && self.operand_1.matches(&other.operand_1)
    }

    pub fn __eq__(&self, other: &Self) -> bool {
        self.idx == other.idx && self.likes(other)
    }

    fn copy(&self) -> Self {
        self.clone()
    }

    pub fn __repr__(&self) -> String {
        format!(
            "{}({}, {})",
            self.op,
            self.operand_0.as_ref().__repr__(),
            self.operand_1.as_ref().__repr__()
        )
    }

    fn __str__(&self) -> String {
        self.__repr__()
    }

    fn __hash__(&self) -> u64 {
        let mut hasher = DefaultHasher::new();
        self.op.hash(&mut hasher);
        self.bits.hash(&mut hasher);
        self.signed.hash(&mut hasher);
        self.floating_point.hash(&mut hasher);
        hasher.finish()
    }

    /// Python-exposed replace method.
    #[pyo3(name = "replace")]
    fn py_replace(&self, old_expr: Expression, new_expr: Expression) -> (bool, Self) {
        self.replace(&old_expr, &new_expr)
    }
}

impl BinaryOp {
    /// Replace old_expr with new_expr in this expression.
    pub fn replace(&self, old_expr: &Expression, new_expr: &Expression) -> (bool, Self) {
        let (r0, replaced_op0) = if self.operand_0.likes(old_expr) {
            (true, new_expr.clone())
        } else {
            self.operand_0.replace(old_expr, new_expr)
        };

        let (r1, replaced_op1) = if self.operand_1.likes(old_expr) {
            (true, new_expr.clone())
        } else {
            self.operand_1.replace(old_expr, new_expr)
        };

        if r0 || r1 {
            (true, BinaryOp {
                idx: self.idx,
                op: self.op.clone(),
                bits: self.bits,
                signed: self.signed,
                floating_point: self.floating_point,
                operand_0: Arc::new(replaced_op0),
                operand_1: Arc::new(replaced_op1),
                tags: self.tags.clone(),
            })
        } else {
            (false, self.clone())
        }
    }
}

// ============================================================================
// ADDITIONAL EXPRESSION CLASSES
// ============================================================================

// ConvertType enum for type conversions
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[pyclass(frozen, eq, eq_int)]
pub enum ConvertType {
    TypeInt = 0,
    TypeFp = 1,
}

#[pymethods]
impl ConvertType {
    #[new]
    fn new(value: i32) -> PyResult<Self> {
        match value {
            0 => Ok(ConvertType::TypeInt),
            1 => Ok(ConvertType::TypeFp),
            _ => Err(PyErr::new::<pyo3::exceptions::PyValueError, _>("Invalid ConvertType")),
        }
    }
}

// Convert expression class (type conversion)
#[pyclass(frozen)]
#[derive(Clone)]
pub struct Convert {
    #[pyo3(get)]
    pub idx: Option<i32>,
    #[pyo3(get)]
    pub from_bits: i32,
    #[pyo3(get)]
    pub to_bits: i32,
    #[pyo3(get)]
    pub bits: i32,
    #[pyo3(get)]
    pub is_signed: bool,
    #[pyo3(get)]
    pub from_type: ConvertType,
    #[pyo3(get)]
    pub to_type: ConvertType,
    pub operand: Arc<Expression>,
    pub rounding_mode: Option<Arc<Expression>>,
    pub tags: Tags,
}

#[pymethods]
impl Convert {
    #[new]
    #[pyo3(signature = (idx, from_bits, to_bits, is_signed, operand, from_type=ConvertType::TypeInt, to_type=ConvertType::TypeInt, rounding_mode=None, **kwargs))]
    fn new(
        idx: Option<i32>,
        from_bits: i32,
        to_bits: i32,
        is_signed: bool,
        operand: Expression,
        from_type: ConvertType,
        to_type: ConvertType,
        rounding_mode: Option<Expression>,
        kwargs: Option<&Bound<'_, pyo3::types::PyDict>>,
    ) -> PyResult<Self> {
        let tags = extract_tags(kwargs)?;
        Ok(Convert {
            idx,
            from_bits,
            to_bits,
            bits: to_bits,
            is_signed,
            from_type,
            to_type,
            operand: Arc::new(operand),
            rounding_mode: rounding_mode.map(Arc::new),
            tags,
        })
    }

    #[getter]
    fn operand(&self) -> Expression {
        (*self.operand).clone()
    }

    #[getter]
    fn rounding_mode(&self) -> Option<Expression> {
        self.rounding_mode.as_ref().map(|rm| (**rm).clone())
    }

    #[getter]
    fn tags(&self) -> HashMap<String, TagValue> {
        self.tags.clone()
    }

    #[getter]
    fn size(&self) -> i32 {
        self.bits / 8
    }

    #[getter]
    fn op(&self) -> String {
        "Convert".to_string()
    }

    pub fn likes(&self, other: &Self) -> bool {
        self.from_bits == other.from_bits
            && self.to_bits == other.to_bits
            && self.bits == other.bits
            && self.is_signed == other.is_signed
            && self.from_type == other.from_type
            && self.to_type == other.to_type
            && self.operand.likes(&other.operand)
            && match (&self.rounding_mode, &other.rounding_mode) {
                (None, None) => true,
                (Some(rm1), Some(rm2)) => rm1.likes(rm2),
                _ => false,
            }
    }

    pub fn matches(&self, other: &Self) -> bool {
        self.likes(other)
    }

    pub fn __eq__(&self, other: &Self) -> bool {
        self.idx == other.idx && self.likes(other)
    }

    fn copy(&self) -> Self {
        self.clone()
    }

    pub fn __repr__(&self) -> String {
        let from_type_str = if self.from_type == ConvertType::TypeInt { "I" } else { "F" };
        let to_type_str = if self.to_type == ConvertType::TypeInt { "I" } else { "F" };
        let sign_str = if self.is_signed { "s" } else { "" };
        format!(
            "Conv({}{}->{}{}{}, {})",
            self.from_bits,
            from_type_str,
            sign_str,
            self.to_bits,
            to_type_str,
            self.operand.__repr__()
        )
    }

    fn __str__(&self) -> String {
        self.__repr__()
    }

    fn __hash__(&self) -> u64 {
        let mut hasher = DefaultHasher::new();
        "Convert".hash(&mut hasher);
        self.from_bits.hash(&mut hasher);
        self.to_bits.hash(&mut hasher);
        self.is_signed.hash(&mut hasher);
        hasher.finish()
    }

    /// Python-exposed replace method.
    #[pyo3(name = "replace")]
    fn py_replace(&self, old_expr: Expression, new_expr: Expression) -> (bool, Self) {
        self.replace(&old_expr, &new_expr)
    }
}

impl Convert {
    /// Replace old_expr with new_expr in this expression.
    pub fn replace(&self, old_expr: &Expression, new_expr: &Expression) -> (bool, Self) {
        let (r0, replaced_operand) = if self.operand.likes(old_expr) {
            (true, new_expr.clone())
        } else {
            self.operand.replace(old_expr, new_expr)
        };

        let (r1, replaced_rm) = if let Some(ref rm) = self.rounding_mode {
            if rm.likes(old_expr) {
                (true, Some(Arc::new(new_expr.clone())))
            } else {
                let (r, replaced) = rm.replace(old_expr, new_expr);
                (r, Some(Arc::new(replaced)))
            }
        } else {
            (false, None)
        };

        if r0 || r1 {
            (true, Convert {
                idx: self.idx,
                from_bits: self.from_bits,
                to_bits: self.to_bits,
                bits: self.bits,
                is_signed: self.is_signed,
                from_type: self.from_type,
                to_type: self.to_type,
                operand: Arc::new(replaced_operand),
                rounding_mode: replaced_rm.or_else(|| self.rounding_mode.clone()),
                tags: self.tags.clone(),
            })
        } else {
            (false, self.clone())
        }
    }
}

// Reinterpret expression class (bitwise reinterpret)
#[pyclass(frozen)]
#[derive(Clone)]
pub struct Reinterpret {
    #[pyo3(get)]
    pub idx: Option<i32>,
    #[pyo3(get)]
    pub from_bits: i32,
    #[pyo3(get)]
    pub from_type: String,  // "I" or "F"
    #[pyo3(get)]
    pub to_bits: i32,
    #[pyo3(get)]
    pub to_type: String,  // "I" or "F"
    #[pyo3(get)]
    pub bits: i32,
    pub operand: Arc<Expression>,
    pub tags: Tags,
}

#[pymethods]
impl Reinterpret {
    #[new]
    #[pyo3(signature = (idx, from_bits, from_type, to_bits, to_type, operand, **kwargs))]
    fn new(
        idx: Option<i32>,
        from_bits: i32,
        from_type: String,
        to_bits: i32,
        to_type: String,
        operand: Expression,
        kwargs: Option<&Bound<'_, pyo3::types::PyDict>>,
    ) -> PyResult<Self> {
        // Validate types
        if !((from_type == "I" && to_type == "F") || (from_type == "F" && to_type == "I")) {
            return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
                "Reinterpret must convert between I and F"
            ));
        }

        let tags = extract_tags(kwargs)?;
        Ok(Reinterpret {
            idx,
            from_bits,
            from_type,
            to_bits,
            to_type,
            bits: to_bits,
            operand: Arc::new(operand),
            tags,
        })
    }

    #[getter]
    fn operand(&self) -> Expression {
        (*self.operand).clone()
    }

    #[getter]
    fn tags(&self) -> HashMap<String, TagValue> {
        self.tags.clone()
    }

    #[getter]
    fn size(&self) -> i32 {
        self.bits / 8
    }

    #[getter]
    fn op(&self) -> String {
        "Reinterpret".to_string()
    }

    pub fn likes(&self, other: &Self) -> bool {
        self.from_bits == other.from_bits
            && self.to_bits == other.to_bits
            && self.from_type == other.from_type
            && self.to_type == other.to_type
            && self.operand.likes(&other.operand)
    }

    pub fn matches(&self, other: &Self) -> bool {
        self.likes(other)
    }

    fn copy(&self) -> Self {
        self.clone()
    }

    pub fn __eq__(&self, other: &Self) -> bool {
        self.idx == other.idx && self.likes(other)
    }

    pub fn __repr__(&self) -> String {
        format!(
            "Reinterpret({}{}->{}{}, {})",
            self.from_bits,
            self.from_type,
            self.to_bits,
            self.to_type,
            self.operand.__repr__()
        )
    }

    fn __str__(&self) -> String {
        self.__repr__()
    }

    fn __hash__(&self) -> u64 {
        let mut hasher = DefaultHasher::new();
        "Reinterpret".hash(&mut hasher);
        self.from_bits.hash(&mut hasher);
        self.to_bits.hash(&mut hasher);
        hasher.finish()
    }

    /// Python-exposed replace method.
    #[pyo3(name = "replace")]
    fn py_replace(&self, old_expr: Expression, new_expr: Expression) -> (bool, Self) {
        self.replace(&old_expr, &new_expr)
    }
}

impl Reinterpret {
    /// Replace old_expr with new_expr in this expression.
    pub fn replace(&self, old_expr: &Expression, new_expr: &Expression) -> (bool, Self) {
        let (r, replaced_operand) = if self.operand.likes(old_expr) {
            (true, new_expr.clone())
        } else {
            self.operand.replace(old_expr, new_expr)
        };

        if r {
            (true, Reinterpret {
                idx: self.idx,
                from_bits: self.from_bits,
                from_type: self.from_type.clone(),
                to_bits: self.to_bits,
                to_type: self.to_type.clone(),
                bits: self.bits,
                operand: Arc::new(replaced_operand),
                tags: self.tags.clone(),
            })
        } else {
            (false, self.clone())
        }
    }
}

// Load expression class (memory load)
#[pyclass]
#[derive(Clone)]
pub struct Load {
    #[pyo3(get)]
    pub idx: Option<i32>,
    pub addr: Arc<Expression>,
    #[pyo3(get)]
    pub size: i32,
    #[pyo3(get)]
    pub endness: String,
    #[pyo3(get)]
    pub bits: i32,
    pub guard: Option<Arc<Expression>>,
    pub alt: Option<Arc<Expression>>,
    pub tags: Tags,
}

#[pymethods]
impl Load {
    #[new]
    #[pyo3(signature = (idx, addr, size, endness, variable=None, variable_offset=None, guard=None, alt=None, **kwargs))]
    fn new(
        idx: Option<i32>,
        addr: Expression,
        size: i32,
        endness: String,
        variable: Option<&Bound<'_, PyAny>>,
        variable_offset: Option<&Bound<'_, PyAny>>,
        guard: Option<Expression>,
        alt: Option<Expression>,
        kwargs: Option<&Bound<'_, pyo3::types::PyDict>>,
    ) -> PyResult<Self> {
        let _ = (variable, variable_offset);  // Suppress unused warnings
        let tags = extract_tags(kwargs)?;
        Ok(Load {
            idx,
            addr: Arc::new(addr),
            size,
            endness,
            bits: size * 8,
            guard: guard.map(Arc::new),
            alt: alt.map(Arc::new),
            tags,
        })
    }

    #[getter]
    fn addr(&self) -> Expression {
        (*self.addr).clone()
    }

    #[getter]
    fn guard(&self) -> Option<Expression> {
        self.guard.as_ref().map(|g| (**g).clone())
    }

    #[getter]
    fn alt(&self) -> Option<Expression> {
        self.alt.as_ref().map(|a| (**a).clone())
    }

    #[getter]
    fn tags(&self) -> HashMap<String, TagValue> {
        self.tags.clone()
    }

    pub fn likes(&self, other: &Self) -> bool {
        self.addr.likes(&other.addr)
            && self.size == other.size
            && self.endness == other.endness
            && match (&self.guard, &other.guard) {
                (None, None) => true,
                (Some(g1), Some(g2)) => g1.likes(g2),
                _ => false,
            }
            && match (&self.alt, &other.alt) {
                (None, None) => true,
                (Some(a1), Some(a2)) => a1.likes(a2),
                _ => false,
            }
    }

    pub fn matches(&self, other: &Self) -> bool {
        self.likes(other)
    }

    pub fn __eq__(&self, other: &Self) -> bool {
        self.idx == other.idx && self.likes(other)
    }

    fn copy(&self) -> Self {
        self.clone()
    }

    pub fn __repr__(&self) -> String {
        format!("Load(addr={}, size={}, endness={})", self.addr.__repr__(), self.size, self.endness)
    }

    fn __str__(&self) -> String {
        self.__repr__()
    }

    fn __hash__(&self) -> u64 {
        let mut hasher = DefaultHasher::new();
        "Load".hash(&mut hasher);
        self.size.hash(&mut hasher);
        self.endness.hash(&mut hasher);
        hasher.finish()
    }

    /// Python-exposed replace method.
    #[pyo3(name = "replace")]
    fn py_replace(&self, old_expr: Expression, new_expr: Expression) -> (bool, Self) {
        self.replace(&old_expr, &new_expr)
    }
}

impl Load {
    /// Replace old_expr with new_expr in this expression.
    pub fn replace(&self, old_expr: &Expression, new_expr: &Expression) -> (bool, Self) {
        let (r_addr, replaced_addr) = if self.addr.likes(old_expr) {
            (true, new_expr.clone())
        } else {
            self.addr.replace(old_expr, new_expr)
        };

        let (r_guard, replaced_guard) = if let Some(ref g) = self.guard {
            if g.likes(old_expr) {
                (true, Some(Arc::new(new_expr.clone())))
            } else {
                let (r, replaced) = g.replace(old_expr, new_expr);
                (r, Some(Arc::new(replaced)))
            }
        } else {
            (false, None)
        };

        let (r_alt, replaced_alt) = if let Some(ref a) = self.alt {
            if a.likes(old_expr) {
                (true, Some(Arc::new(new_expr.clone())))
            } else {
                let (r, replaced) = a.replace(old_expr, new_expr);
                (r, Some(Arc::new(replaced)))
            }
        } else {
            (false, None)
        };

        if r_addr || r_guard || r_alt {
            (true, Load {
                idx: self.idx,
                addr: Arc::new(replaced_addr),
                size: self.size,
                endness: self.endness.clone(),
                bits: self.bits,
                guard: replaced_guard.or_else(|| self.guard.clone()),
                alt: replaced_alt.or_else(|| self.alt.clone()),
                tags: self.tags.clone(),
            })
        } else {
            (false, self.clone())
        }
    }
}

// ITE expression class (if-then-else ternary)
#[pyclass]
#[derive(Clone)]
pub struct ITE {
    #[pyo3(get)]
    pub idx: Option<i32>,
    pub cond: Arc<Expression>,
    pub iftrue: Arc<Expression>,
    pub iffalse: Arc<Expression>,
    #[pyo3(get)]
    pub bits: i32,
    pub tags: Tags,
}

#[pymethods]
impl ITE {
    #[new]
    #[pyo3(signature = (idx, cond, iffalse, iftrue, variable=None, variable_offset=None, **kwargs))]
    fn new(
        idx: Option<i32>,
        cond: Expression,
        iffalse: Expression,
        iftrue: Expression,
        variable: Option<&Bound<'_, PyAny>>,
        variable_offset: Option<&Bound<'_, PyAny>>,
        kwargs: Option<&Bound<'_, pyo3::types::PyDict>>,
    ) -> PyResult<Self> {
        let _ = (variable, variable_offset);  // Suppress unused warnings
        let bits = iftrue.bits();
        let tags = extract_tags(kwargs)?;
        Ok(ITE {
            idx,
            cond: Arc::new(cond),
            iftrue: Arc::new(iftrue),
            iffalse: Arc::new(iffalse),
            bits,
            tags,
        })
    }

    #[getter]
    fn cond(&self) -> Expression {
        (*self.cond).clone()
    }

    #[getter]
    fn iftrue(&self) -> Expression {
        (*self.iftrue).clone()
    }

    #[getter]
    fn iffalse(&self) -> Expression {
        (*self.iffalse).clone()
    }

    #[getter]
    fn tags(&self) -> HashMap<String, TagValue> {
        self.tags.clone()
    }

    #[getter]
    fn size(&self) -> i32 {
        self.bits / 8
    }

    pub fn likes(&self, other: &Self) -> bool {
        self.cond.likes(&other.cond)
            && self.iftrue.likes(&other.iftrue)
            && self.iffalse.likes(&other.iffalse)
            && self.bits == other.bits
    }

    pub fn matches(&self, other: &Self) -> bool {
        self.likes(other)
    }

    pub fn __eq__(&self, other: &Self) -> bool {
        self.idx == other.idx && self.likes(other)
    }

    fn copy(&self) -> Self {
        self.clone()
    }

    pub fn __repr__(&self) -> String {
        format!(
            "(({}) ? ({}) : ({}))",
            self.cond.__repr__(),
            self.iftrue.__repr__(),
            self.iffalse.__repr__()
        )
    }

    fn __str__(&self) -> String {
        self.__repr__()
    }

    fn __hash__(&self) -> u64 {
        let mut hasher = DefaultHasher::new();
        "ITE".hash(&mut hasher);
        self.bits.hash(&mut hasher);
        hasher.finish()
    }

    /// Python-exposed replace method.
    #[pyo3(name = "replace")]
    fn py_replace(&self, old_expr: Expression, new_expr: Expression) -> (bool, Self) {
        self.replace(&old_expr, &new_expr)
    }
}

impl ITE {
    /// Replace old_expr with new_expr in this expression.
    pub fn replace(&self, old_expr: &Expression, new_expr: &Expression) -> (bool, Self) {
        let (r_cond, replaced_cond) = if self.cond.likes(old_expr) {
            (true, new_expr.clone())
        } else {
            self.cond.replace(old_expr, new_expr)
        };

        let (r_iftrue, replaced_iftrue) = if self.iftrue.likes(old_expr) {
            (true, new_expr.clone())
        } else {
            self.iftrue.replace(old_expr, new_expr)
        };

        let (r_iffalse, replaced_iffalse) = if self.iffalse.likes(old_expr) {
            (true, new_expr.clone())
        } else {
            self.iffalse.replace(old_expr, new_expr)
        };

        if r_cond || r_iftrue || r_iffalse {
            (true, ITE {
                idx: self.idx,
                cond: Arc::new(replaced_cond),
                iftrue: Arc::new(replaced_iftrue),
                iffalse: Arc::new(replaced_iffalse),
                bits: self.bits,
                tags: self.tags.clone(),
            })
        } else {
            (false, self.clone())
        }
    }
}

// Phi expression class (SSA phi function)
// src_and_vvars: list of ((block_addr, block_idx), Option<VirtualVariable>)
#[pyclass]
#[derive(Clone)]
pub struct Phi {
    #[pyo3(get)]
    pub idx: Option<i32>,
    #[pyo3(get)]
    pub bits: i32,
    // Store as Vec of tuples: ((block_addr, block_idx), optional vvar_id)
    // We store vvar as Option<Arc<Expression>> to allow VirtualVariable
    src_and_vvars: Vec<((i64, Option<i32>), Option<Arc<Expression>>)>,
    pub tags: Tags,
}

#[pymethods]
impl Phi {
    #[new]
    #[pyo3(signature = (idx, bits, src_and_vvars=None, **kwargs))]
    fn new(
        idx: Option<i32>,
        bits: i32,
        src_and_vvars: Option<Vec<((i64, Option<i32>), Option<Expression>)>>,
        kwargs: Option<&Bound<'_, pyo3::types::PyDict>>,
    ) -> PyResult<Self> {
        let converted = src_and_vvars
            .unwrap_or_default()
            .into_iter()
            .map(|(src, vvar)| (src, vvar.map(Arc::new)))
            .collect();

        let tags = extract_tags(kwargs)?;
        Ok(Phi {
            idx,
            bits,
            src_and_vvars: converted,
            tags,
        })
    }

    #[getter]
    fn tags(&self) -> HashMap<String, TagValue> {
        self.tags.clone()
    }

    #[getter]
    fn src_and_vvars(&self) -> Vec<((i64, Option<i32>), Option<Expression>)> {
        self.src_and_vvars
            .iter()
            .map(|(src, vvar)| (*src, vvar.as_ref().map(|v| (**v).clone())))
            .collect()
    }

    #[getter]
    fn size(&self) -> i32 {
        self.bits / 8
    }

    #[getter]
    fn op(&self) -> String {
        "Phi".to_string()
    }

    #[getter]
    fn verbose_op(&self) -> String {
        "Phi".to_string()
    }

    pub fn likes(&self, other: &Self) -> bool {
        if self.bits != other.bits {
            return false;
        }
        if self.src_and_vvars.len() != other.src_and_vvars.len() {
            return false;
        }
        // Compare by sets of (src, vvar_id) - order independent
        // Extract source blocks and vvar ids for comparison
        let self_srcs: std::collections::HashSet<_> = self.src_and_vvars
            .iter()
            .map(|(src, _)| *src)
            .collect();
        let other_srcs: std::collections::HashSet<_> = other.src_and_vvars
            .iter()
            .map(|(src, _)| *src)
            .collect();
        self_srcs == other_srcs
    }

    pub fn matches(&self, other: &Self) -> bool {
        if self.bits != other.bits {
            return false;
        }
        if self.src_and_vvars.len() != other.src_and_vvars.len() {
            return false;
        }
        // For matches, check structure more strictly
        for (i, (src, vvar)) in self.src_and_vvars.iter().enumerate() {
            let (other_src, other_vvar) = &other.src_and_vvars[i];
            if src != other_src {
                return false;
            }
            match (vvar, other_vvar) {
                (None, None) => {}
                (Some(v1), Some(v2)) => {
                    if !v1.matches(v2) {
                        return false;
                    }
                }
                _ => return false,
            }
        }
        true
    }

    pub fn __eq__(&self, other: &Self) -> bool {
        self.idx == other.idx && self.likes(other)
    }

    fn copy(&self) -> Self {
        self.clone()
    }

    pub fn __repr__(&self) -> String {
        let entries: Vec<String> = self.src_and_vvars
            .iter()
            .map(|((addr, idx), vvar)| {
                let src_str = match idx {
                    Some(i) => format!("({:#x}, {})", addr, i),
                    None => format!("({:#x}, None)", addr),
                };
                let vvar_str = match vvar {
                    Some(v) => v.__repr__(),
                    None => "None".to_string(),
                };
                format!("({}, {})", src_str, vvar_str)
            })
            .collect();
        format!("\u{03D5}<{}>[{}]", self.bits, entries.join(", "))
    }

    fn __str__(&self) -> String {
        self.__repr__()
    }

    fn __hash__(&self) -> u64 {
        let mut hasher = DefaultHasher::new();
        "Phi".hash(&mut hasher);
        self.bits.hash(&mut hasher);
        // Hash sorted src blocks for stability
        let mut srcs: Vec<_> = self.src_and_vvars
            .iter()
            .map(|(src, _)| src)
            .collect();
        srcs.sort();
        for src in srcs {
            src.0.hash(&mut hasher);
            src.1.hash(&mut hasher);
        }
        hasher.finish()
    }

    /// Python-exposed replace method.
    #[pyo3(name = "replace")]
    fn py_replace(&self, old_expr: Expression, new_expr: Expression) -> (bool, Self) {
        self.replace(&old_expr, &new_expr)
    }
}

impl Phi {
    /// Replace old_expr with new_expr in this expression.
    pub fn replace(&self, old_expr: &Expression, new_expr: &Expression) -> (bool, Self) {
        let mut replaced = false;
        let new_src_and_vvars: Vec<_> = self.src_and_vvars
            .iter()
            .map(|(src, vvar)| {
                if let Some(v) = vvar {
                    if v.likes(old_expr) {
                        replaced = true;
                        (*src, Some(Arc::new(new_expr.clone())))
                    } else {
                        let (r, new_v) = v.replace(old_expr, new_expr);
                        if r {
                            replaced = true;
                            (*src, Some(Arc::new(new_v)))
                        } else {
                            (*src, vvar.clone())
                        }
                    }
                } else {
                    (*src, None)
                }
            })
            .collect();

        if replaced {
            (true, Phi {
                idx: self.idx,
                bits: self.bits,
                src_and_vvars: new_src_and_vvars,
                tags: self.tags.clone(),
            })
        } else {
            (false, self.clone())
        }
    }
}

// DirtyExpression class (wraps VEX dirty helper calls)
#[pyclass]
#[derive(Clone)]
pub struct DirtyExpression {
    #[pyo3(get)]
    pub idx: Option<i32>,
    #[pyo3(get)]
    pub callee: String,
    pub operands: Vec<Arc<Expression>>,
    pub guard: Option<Arc<Expression>>,
    #[pyo3(get)]
    pub mfx: Option<String>,  // Memory effect
    pub maddr: Option<Arc<Expression>>,  // Memory address
    #[pyo3(get)]
    pub msize: Option<i32>,  // Memory size
    #[pyo3(get)]
    pub bits: Option<i32>,
    pub tags: Tags,
}

#[pymethods]
impl DirtyExpression {
    #[new]
    #[pyo3(signature = (idx, callee, operands=None, guard=None, mfx=None, maddr=None, msize=None, bits=None, **kwargs))]
    fn new(
        idx: Option<i32>,
        callee: String,
        operands: Option<Vec<Expression>>,
        guard: Option<Expression>,
        mfx: Option<String>,
        maddr: Option<Expression>,
        msize: Option<i32>,
        bits: Option<i32>,
        kwargs: Option<&Bound<'_, pyo3::types::PyDict>>,
    ) -> PyResult<Self> {
        let tags = extract_tags(kwargs)?;
        Ok(DirtyExpression {
            idx,
            callee,
            operands: operands.unwrap_or_default().into_iter().map(Arc::new).collect(),
            guard: guard.map(Arc::new),
            mfx,
            maddr: maddr.map(Arc::new),
            msize,
            bits,
            tags,
        })
    }

    #[getter]
    fn operands(&self) -> Vec<Expression> {
        self.operands.iter().map(|o| (**o).clone()).collect()
    }

    #[getter]
    fn guard(&self) -> Option<Expression> {
        self.guard.as_ref().map(|g| (**g).clone())
    }

    #[getter]
    fn maddr(&self) -> Option<Expression> {
        self.maddr.as_ref().map(|m| (**m).clone())
    }

    #[getter]
    fn tags(&self) -> HashMap<String, TagValue> {
        self.tags.clone()
    }

    #[getter]
    fn op(&self) -> String {
        self.callee.clone()
    }

    #[getter]
    fn verbose_op(&self) -> String {
        self.callee.clone()
    }

    #[getter]
    fn size(&self) -> Option<i32> {
        self.bits.map(|b| b / 8)
    }

    pub fn likes(&self, other: &Self) -> bool {
        if self.callee != other.callee {
            return false;
        }
        if self.operands.len() != other.operands.len() {
            return false;
        }
        for (a, b) in self.operands.iter().zip(other.operands.iter()) {
            if !a.likes(b) {
                return false;
            }
        }
        match (&self.guard, &other.guard) {
            (None, None) => {}
            (Some(g1), Some(g2)) => {
                if !g1.likes(g2) {
                    return false;
                }
            }
            _ => return false,
        }
        match (&self.maddr, &other.maddr) {
            (None, None) => {}
            (Some(m1), Some(m2)) => {
                if !m1.likes(m2) {
                    return false;
                }
            }
            _ => return false,
        }
        true
    }

    pub fn matches(&self, other: &Self) -> bool {
        if self.callee != other.callee {
            return false;
        }
        if self.operands.len() != other.operands.len() {
            return false;
        }
        for (a, b) in self.operands.iter().zip(other.operands.iter()) {
            if !a.matches(b) {
                return false;
            }
        }
        match (&self.guard, &other.guard) {
            (None, None) => {}
            (Some(g1), Some(g2)) => {
                if !g1.matches(g2) {
                    return false;
                }
            }
            _ => return false,
        }
        match (&self.maddr, &other.maddr) {
            (None, None) => {}
            (Some(m1), Some(m2)) => {
                if !m1.matches(m2) {
                    return false;
                }
            }
            _ => return false,
        }
        true
    }

    pub fn __eq__(&self, other: &Self) -> bool {
        self.idx == other.idx && self.likes(other)
    }

    fn copy(&self) -> Self {
        self.clone()
    }

    pub fn __repr__(&self) -> String {
        let operands_str = self.operands
            .iter()
            .map(|o| o.__repr__())
            .collect::<Vec<_>>()
            .join(", ");
        format!("[D] {}({})", self.callee, operands_str)
    }

    fn __str__(&self) -> String {
        self.__repr__()
    }

    fn __hash__(&self) -> u64 {
        let mut hasher = DefaultHasher::new();
        "DirtyExpression".hash(&mut hasher);
        self.callee.hash(&mut hasher);
        self.bits.hash(&mut hasher);
        hasher.finish()
    }

    /// Python-exposed replace method.
    #[pyo3(name = "replace")]
    fn py_replace(&self, old_expr: Expression, new_expr: Expression) -> (bool, Self) {
        self.replace(&old_expr, &new_expr)
    }
}

impl DirtyExpression {
    /// Replace old_expr with new_expr in this expression.
    pub fn replace(&self, old_expr: &Expression, new_expr: &Expression) -> (bool, Self) {
        let mut r_operands = false;
        let new_operands: Vec<Arc<Expression>> = self.operands
            .iter()
            .map(|op| {
                if op.likes(old_expr) {
                    r_operands = true;
                    Arc::new(new_expr.clone())
                } else {
                    let (r, replaced) = op.replace(old_expr, new_expr);
                    if r {
                        r_operands = true;
                        Arc::new(replaced)
                    } else {
                        op.clone()
                    }
                }
            })
            .collect();

        let (r_guard, replaced_guard) = if let Some(ref g) = self.guard {
            if g.likes(old_expr) {
                (true, Some(Arc::new(new_expr.clone())))
            } else {
                let (r, replaced) = g.replace(old_expr, new_expr);
                (r, Some(Arc::new(replaced)))
            }
        } else {
            (false, None)
        };

        let (r_maddr, replaced_maddr) = if let Some(ref m) = self.maddr {
            if m.likes(old_expr) {
                (true, Some(Arc::new(new_expr.clone())))
            } else {
                let (r, replaced) = m.replace(old_expr, new_expr);
                (r, Some(Arc::new(replaced)))
            }
        } else {
            (false, None)
        };

        if r_operands || r_guard || r_maddr {
            (true, DirtyExpression {
                idx: self.idx,
                callee: self.callee.clone(),
                operands: new_operands,
                guard: replaced_guard.or_else(|| self.guard.clone()),
                mfx: self.mfx.clone(),
                maddr: replaced_maddr.or_else(|| self.maddr.clone()),
                msize: self.msize,
                bits: self.bits,
                tags: self.tags.clone(),
            })
        } else {
            (false, self.clone())
        }
    }
}

// MultiStatementExpression class (expression containing multiple statements)
#[pyclass]
#[derive(Clone)]
pub struct MultiStatementExpression {
    #[pyo3(get)]
    pub idx: Option<i32>,
    stmts_inner: Vec<Statement>,
    pub expr: Arc<Expression>,
    #[pyo3(get)]
    pub bits: i32,
    pub tags: Tags,
}

#[pymethods]
impl MultiStatementExpression {
    #[new]
    #[pyo3(signature = (idx, stmts, expr, **kwargs))]
    fn new(
        idx: Option<i32>,
        stmts: Vec<Statement>,
        expr: Expression,
        kwargs: Option<&Bound<'_, pyo3::types::PyDict>>,
    ) -> PyResult<Self> {
        let bits = expr.bits();
        let tags = extract_tags(kwargs)?;
        Ok(MultiStatementExpression {
            idx,
            stmts_inner: stmts,
            expr: Arc::new(expr),
            bits,
            tags,
        })
    }

    #[getter]
    fn stmts(&self) -> Vec<Statement> {
        self.stmts_inner.clone()
    }

    #[getter]
    fn expr(&self) -> Expression {
        (*self.expr).clone()
    }

    #[getter]
    fn tags(&self) -> HashMap<String, TagValue> {
        self.tags.clone()
    }

    #[getter]
    fn size(&self) -> i32 {
        self.bits / 8
    }

    pub fn likes(&self, other: &Self) -> bool {
        if self.stmts_inner.len() != other.stmts_inner.len() {
            return false;
        }
        for (a, b) in self.stmts_inner.iter().zip(other.stmts_inner.iter()) {
            if !a.likes(b) {
                return false;
            }
        }
        self.expr.likes(&other.expr)
    }

    pub fn matches(&self, other: &Self) -> bool {
        if self.stmts_inner.len() != other.stmts_inner.len() {
            return false;
        }
        for (a, b) in self.stmts_inner.iter().zip(other.stmts_inner.iter()) {
            if !a.matches(b) {
                return false;
            }
        }
        self.expr.matches(&other.expr)
    }

    pub fn __eq__(&self, other: &Self) -> bool {
        self.idx == other.idx && self.likes(other)
    }

    fn copy(&self) -> Self {
        self.clone()
    }

    pub fn __repr__(&self) -> String {
        let stmts_str = self.stmts_inner
            .iter()
            .map(|s| s.__repr__())
            .collect::<Vec<_>>()
            .join(", ");
        format!("MultiStatementExpression([{}], {})", stmts_str, self.expr.__repr__())
    }

    fn __str__(&self) -> String {
        let stmts_str = self.stmts_inner
            .iter()
            .map(|s| s.__repr__())
            .collect::<Vec<_>>()
            .join(", ");
        format!("({}, {})", stmts_str, self.expr.__repr__())
    }

    fn __hash__(&self) -> u64 {
        let mut hasher = DefaultHasher::new();
        "MultiStatementExpression".hash(&mut hasher);
        self.stmts_inner.len().hash(&mut hasher);
        self.bits.hash(&mut hasher);
        hasher.finish()
    }

    /// Python-exposed replace method.
    #[pyo3(name = "replace")]
    fn py_replace(&self, old_expr: Expression, new_expr: Expression) -> (bool, Self) {
        self.replace(&old_expr, &new_expr)
    }
}

impl MultiStatementExpression {
    /// Replace old_expr with new_expr in this expression.
    pub fn replace(&self, old_expr: &Expression, new_expr: &Expression) -> (bool, Self) {
        // Replace in statements
        let mut r_stmts = false;
        let new_stmts: Vec<Statement> = self.stmts_inner
            .iter()
            .map(|stmt| {
                let (r, replaced) = stmt.replace(old_expr, new_expr);
                if r {
                    r_stmts = true;
                    replaced
                } else {
                    stmt.clone()
                }
            })
            .collect();

        // Replace in expr
        let (r_expr, replaced_expr) = if self.expr.likes(old_expr) {
            (true, new_expr.clone())
        } else {
            self.expr.replace(old_expr, new_expr)
        };

        if r_stmts || r_expr {
            (true, MultiStatementExpression {
                idx: self.idx,
                stmts_inner: new_stmts,
                expr: Arc::new(replaced_expr),
                bits: self.bits,
                tags: self.tags.clone(),
            })
        } else {
            (false, self.clone())
        }
    }
}

// BasePointerOffset base type - can be Expression or String
#[derive(Clone)]
pub enum BasePointerOffsetBase {
    Expression(Arc<Expression>),
    String(String),
}

// BasePointerOffset expression class (base + offset pointer expression)
#[pyclass]
#[derive(Clone)]
pub struct BasePointerOffset {
    #[pyo3(get)]
    pub idx: Option<i32>,
    #[pyo3(get)]
    pub bits: i32,
    base_inner: BasePointerOffsetBase,
    #[pyo3(get)]
    pub offset: i64,
    pub tags: Tags,
}

#[pymethods]
impl BasePointerOffset {
    #[new]
    #[pyo3(signature = (idx, bits, base, offset, variable=None, variable_offset=None, **kwargs))]
    fn new(
        idx: Option<i32>,
        bits: i32,
        base: &Bound<'_, PyAny>,
        offset: i64,
        variable: Option<&Bound<'_, PyAny>>,
        variable_offset: Option<&Bound<'_, PyAny>>,
        kwargs: Option<&Bound<'_, pyo3::types::PyDict>>,
    ) -> PyResult<Self> {
        let _ = (variable, variable_offset);  // Suppress unused warnings

        // Try to extract base as string first, then as Expression
        let base_inner = if let Ok(s) = base.extract::<String>() {
            BasePointerOffsetBase::String(s)
        } else if let Ok(expr) = base.extract::<Expression>() {
            BasePointerOffsetBase::Expression(Arc::new(expr))
        } else {
            return Err(PyErr::new::<pyo3::exceptions::PyTypeError, _>(
                "base must be a string or Expression"
            ));
        };

        let tags = extract_tags(kwargs)?;
        Ok(BasePointerOffset {
            idx,
            bits,
            base_inner,
            offset,
            tags,
        })
    }

    #[getter]
    fn base(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        match &self.base_inner {
            BasePointerOffsetBase::String(s) => Ok(s.clone().into_pyobject(py)?.into_any().unbind()),
            BasePointerOffsetBase::Expression(expr) => Ok((**expr).clone().into_pyobject(py)?.unbind()),
        }
    }

    #[getter]
    fn tags(&self) -> HashMap<String, TagValue> {
        self.tags.clone()
    }

    #[getter]
    fn size(&self) -> i32 {
        self.bits / 8
    }

    pub fn likes(&self, other: &Self) -> bool {
        if self.bits != other.bits || self.offset != other.offset {
            return false;
        }
        match (&self.base_inner, &other.base_inner) {
            (BasePointerOffsetBase::String(a), BasePointerOffsetBase::String(b)) => a == b,
            (BasePointerOffsetBase::Expression(a), BasePointerOffsetBase::Expression(b)) => a.likes(b),
            _ => false,
        }
    }

    pub fn matches(&self, other: &Self) -> bool {
        self.likes(other)
    }

    fn copy(&self) -> Self {
        self.clone()
    }

    pub fn __repr__(&self) -> String {
        let base_str = match &self.base_inner {
            BasePointerOffsetBase::String(s) => s.clone(),
            BasePointerOffsetBase::Expression(expr) => expr.__repr__(),
        };
        format!("BaseOffset({}, {})", base_str, self.offset)
    }

    fn __str__(&self) -> String {
        let base_str = match &self.base_inner {
            BasePointerOffsetBase::String(s) => s.clone(),
            BasePointerOffsetBase::Expression(expr) => expr.__repr__(),
        };
        if self.offset >= 0 {
            format!("{}+{}", base_str, self.offset)
        } else {
            format!("{}{}", base_str, self.offset)
        }
    }

    fn __hash__(&self) -> u64 {
        let mut hasher = DefaultHasher::new();
        "BasePointerOffset".hash(&mut hasher);
        self.bits.hash(&mut hasher);
        self.offset.hash(&mut hasher);
        match &self.base_inner {
            BasePointerOffsetBase::String(s) => s.hash(&mut hasher),
            BasePointerOffsetBase::Expression(_) => "expr".hash(&mut hasher),
        }
        hasher.finish()
    }

    fn __eq__(&self, other: &Self) -> bool {
        self.idx == other.idx && self.likes(other)
    }

    /// Python-exposed replace method.
    #[pyo3(name = "replace")]
    fn py_replace(&self, old_expr: Expression, new_expr: Expression) -> (bool, Self) {
        self.replace(&old_expr, &new_expr)
    }
}

impl BasePointerOffset {
    /// Replace old_expr with new_expr in this expression.
    pub fn replace(&self, old_expr: &Expression, new_expr: &Expression) -> (bool, Self) {
        match &self.base_inner {
            BasePointerOffsetBase::Expression(base) => {
                if base.likes(old_expr) {
                    (true, BasePointerOffset {
                        idx: self.idx,
                        bits: self.bits,
                        base_inner: BasePointerOffsetBase::Expression(Arc::new(new_expr.clone())),
                        offset: self.offset,
                        tags: self.tags.clone(),
                    })
                } else {
                    let (r, replaced) = base.replace(old_expr, new_expr);
                    if r {
                        (true, BasePointerOffset {
                            idx: self.idx,
                            bits: self.bits,
                            base_inner: BasePointerOffsetBase::Expression(Arc::new(replaced)),
                            offset: self.offset,
                            tags: self.tags.clone(),
                        })
                    } else {
                        (false, self.clone())
                    }
                }
            }
            BasePointerOffsetBase::String(_) => {
                // String base has no child expressions to replace
                (false, self.clone())
            }
        }
    }
}

// StackBaseOffset expression class (specialized BasePointerOffset for stack)
#[pyclass]
#[derive(Clone)]
pub struct StackBaseOffset {
    #[pyo3(get)]
    pub idx: Option<i32>,
    #[pyo3(get)]
    pub bits: i32,
    #[pyo3(get)]
    pub offset: i64,
    pub tags: Tags,
}

#[pymethods]
impl StackBaseOffset {
    #[new]
    #[pyo3(signature = (idx, bits, offset, **kwargs))]
    fn new(
        idx: Option<i32>,
        bits: i32,
        offset: i64,
        kwargs: Option<&Bound<'_, pyo3::types::PyDict>>,
    ) -> PyResult<Self> {
        // Stack base offset is always signed - convert if needed
        // For bits < 64, we sign-extend if the value is >= 2^(bits-1)
        // For 64-bit, the offset is already i64 so no conversion needed
        let signed_offset = if bits < 64 && offset >= (1i64 << (bits - 1)) {
            offset.wrapping_sub(1i64 << bits)
        } else {
            offset
        };

        let tags = extract_tags(kwargs)?;
        Ok(StackBaseOffset {
            idx,
            bits,
            offset: signed_offset,
            tags,
        })
    }

    #[getter]
    fn base(&self) -> String {
        "stack_base".to_string()
    }

    #[getter]
    fn tags(&self) -> HashMap<String, TagValue> {
        self.tags.clone()
    }

    #[getter]
    fn size(&self) -> i32 {
        self.bits / 8
    }

    pub fn likes(&self, other: &Self) -> bool {
        self.bits == other.bits && self.offset == other.offset
    }

    pub fn matches(&self, other: &Self) -> bool {
        self.likes(other)
    }

    fn copy(&self) -> Self {
        self.clone()
    }

    pub fn __repr__(&self) -> String {
        format!("StackBaseOffset({}, {})", self.bits, self.offset)
    }

    fn __str__(&self) -> String {
        if self.offset >= 0 {
            format!("stack_base+{}", self.offset)
        } else {
            format!("stack_base{}", self.offset)
        }
    }

    fn __hash__(&self) -> u64 {
        let mut hasher = DefaultHasher::new();
        "StackBaseOffset".hash(&mut hasher);
        self.bits.hash(&mut hasher);
        self.offset.hash(&mut hasher);
        hasher.finish()
    }

    fn __eq__(&self, other: &Self) -> bool {
        self.idx == other.idx && self.likes(other)
    }

    /// Python-exposed replace method.
    #[pyo3(name = "replace")]
    fn py_replace(&self, old_expr: Expression, new_expr: Expression) -> (bool, Self) {
        self.replace(&old_expr, &new_expr)
    }
}

impl StackBaseOffset {
    /// Replace old_expr with new_expr - StackBaseOffset has no child expressions.
    pub fn replace(&self, _old_expr: &Expression, _new_expr: &Expression) -> (bool, Self) {
        (false, self.clone())
    }
}

#[derive(Clone)]
pub enum Expression {
    Const(Const),
    VirtualVariable(VirtualVariable),
    UnaryOp(UnaryOp),
    BinaryOp(BinaryOp),
    Convert(Convert),
    Reinterpret(Reinterpret),
    Load(Load),
    ITE(ITE),
    Call(Call),
    Phi(Phi),
    DirtyExpression(DirtyExpression),
    MultiStatementExpression(MultiStatementExpression),
    BasePointerOffset(BasePointerOffset),
    StackBaseOffset(StackBaseOffset),
}

// Implement automatic conversion from Python objects to Expression
impl<'py> FromPyObject<'_, 'py> for Expression {
    type Error = PyErr;

    fn extract(ob: Borrowed<'_, 'py, PyAny>) -> Result<Self, Self::Error> {
        // Try to extract each type in order
        if let Ok(c) = ob.extract::<Const>() {
            return Ok(Expression::Const(c));
        }
        if let Ok(v) = ob.extract::<VirtualVariable>() {
            return Ok(Expression::VirtualVariable(v));
        }
        if let Ok(conv) = ob.extract::<Convert>() {
            return Ok(Expression::Convert(conv));
        }
        if let Ok(reint) = ob.extract::<Reinterpret>() {
            return Ok(Expression::Reinterpret(reint));
        }
        if let Ok(l) = ob.extract::<Load>() {
            return Ok(Expression::Load(l));
        }
        if let Ok(ite) = ob.extract::<ITE>() {
            return Ok(Expression::ITE(ite));
        }
        if let Ok(u) = ob.extract::<UnaryOp>() {
            return Ok(Expression::UnaryOp(u));
        }
        if let Ok(b) = ob.extract::<BinaryOp>() {
            return Ok(Expression::BinaryOp(b));
        }
        if let Ok(call) = ob.extract::<Call>() {
            return Ok(Expression::Call(call));
        }
        if let Ok(phi) = ob.extract::<Phi>() {
            return Ok(Expression::Phi(phi));
        }
        if let Ok(dirty) = ob.extract::<DirtyExpression>() {
            return Ok(Expression::DirtyExpression(dirty));
        }
        if let Ok(mse) = ob.extract::<MultiStatementExpression>() {
            return Ok(Expression::MultiStatementExpression(mse));
        }
        if let Ok(sbo) = ob.extract::<StackBaseOffset>() {
            return Ok(Expression::StackBaseOffset(sbo));
        }
        if let Ok(bpo) = ob.extract::<BasePointerOffset>() {
            return Ok(Expression::BasePointerOffset(bpo));
        }

        Err(PyErr::new::<pyo3::exceptions::PyTypeError, _>(
            "Expected an AIL Expression type"
        ))
    }
}

// Implement conversion back to Python objects
impl<'py> IntoPyObject<'py> for Expression {
    type Target = PyAny;
    type Output = Bound<'py, Self::Target>;
    type Error = PyErr;

    fn into_pyobject(self, py: Python<'py>) -> Result<Self::Output, Self::Error> {
        match self {
            Expression::Const(c) => c.into_pyobject(py).map(|b| b.into_any()),
            Expression::VirtualVariable(v) => v.into_pyobject(py).map(|b| b.into_any()),
            Expression::Convert(conv) => conv.into_pyobject(py).map(|b| b.into_any()),
            Expression::Reinterpret(reint) => reint.into_pyobject(py).map(|b| b.into_any()),
            Expression::Load(l) => l.into_pyobject(py).map(|b| b.into_any()),
            Expression::ITE(ite) => ite.into_pyobject(py).map(|b| b.into_any()),
            Expression::UnaryOp(u) => u.into_pyobject(py).map(|b| b.into_any()),
            Expression::BinaryOp(b) => b.into_pyobject(py).map(|b| b.into_any()),
            Expression::Call(call) => call.into_pyobject(py).map(|b| b.into_any()),
            Expression::Phi(phi) => phi.into_pyobject(py).map(|b| b.into_any()),
            Expression::DirtyExpression(dirty) => dirty.into_pyobject(py).map(|b| b.into_any()),
            Expression::MultiStatementExpression(mse) => mse.into_pyobject(py).map(|b| b.into_any()),
            Expression::BasePointerOffset(bpo) => bpo.into_pyobject(py).map(|b| b.into_any()),
            Expression::StackBaseOffset(sbo) => sbo.into_pyobject(py).map(|b| b.into_any()),
        }
    }
}

impl Expression {
    pub fn bits(&self) -> i32 {
        match self {
            Expression::Const(c) => c.bits,
            Expression::VirtualVariable(v) => v.bits,
            Expression::Convert(conv) => conv.bits,
            Expression::Reinterpret(reint) => reint.bits,
            Expression::Load(l) => l.bits,
            Expression::ITE(ite) => ite.bits,
            Expression::UnaryOp(u) => u.bits,
            Expression::BinaryOp(b) => b.bits,
            Expression::Call(call) => call.bits.unwrap_or(0),
            Expression::Phi(phi) => phi.bits,
            Expression::DirtyExpression(dirty) => dirty.bits.unwrap_or(0),
            Expression::MultiStatementExpression(mse) => mse.bits,
            Expression::BasePointerOffset(bpo) => bpo.bits,
            Expression::StackBaseOffset(sbo) => sbo.bits,
        }
    }

    pub fn likes(&self, other: &Expression) -> bool {
        match (self, other) {
            (Expression::Const(a), Expression::Const(b)) => a.likes(b),
            (Expression::VirtualVariable(a), Expression::VirtualVariable(b)) => a.likes(b),
            (Expression::Convert(a), Expression::Convert(b)) => a.likes(b),
            (Expression::Reinterpret(a), Expression::Reinterpret(b)) => a.likes(b),
            (Expression::Load(a), Expression::Load(b)) => a.likes(b),
            (Expression::ITE(a), Expression::ITE(b)) => a.likes(b),
            (Expression::UnaryOp(a), Expression::UnaryOp(b)) => a.likes(b),
            (Expression::BinaryOp(a), Expression::BinaryOp(b)) => a.likes(b),
            (Expression::Call(a), Expression::Call(b)) => a.likes(b),
            (Expression::Phi(a), Expression::Phi(b)) => a.likes(b),
            (Expression::DirtyExpression(a), Expression::DirtyExpression(b)) => a.likes(b),
            (Expression::MultiStatementExpression(a), Expression::MultiStatementExpression(b)) => a.likes(b),
            (Expression::BasePointerOffset(a), Expression::BasePointerOffset(b)) => a.likes(b),
            (Expression::StackBaseOffset(a), Expression::StackBaseOffset(b)) => a.likes(b),
            _ => false,
        }
    }

    pub fn matches(&self, other: &Expression) -> bool {
        match (self, other) {
            (Expression::Const(a), Expression::Const(b)) => a.matches(b),
            (Expression::VirtualVariable(a), Expression::VirtualVariable(b)) => a.matches(b),
            (Expression::Convert(a), Expression::Convert(b)) => a.matches(b),
            (Expression::Reinterpret(a), Expression::Reinterpret(b)) => a.matches(b),
            (Expression::Load(a), Expression::Load(b)) => a.matches(b),
            (Expression::ITE(a), Expression::ITE(b)) => a.matches(b),
            (Expression::UnaryOp(a), Expression::UnaryOp(b)) => a.matches(b),
            (Expression::BinaryOp(a), Expression::BinaryOp(b)) => a.matches(b),
            (Expression::Call(a), Expression::Call(b)) => a.matches(b),
            (Expression::Phi(a), Expression::Phi(b)) => a.matches(b),
            (Expression::DirtyExpression(a), Expression::DirtyExpression(b)) => a.matches(b),
            (Expression::MultiStatementExpression(a), Expression::MultiStatementExpression(b)) => a.matches(b),
            (Expression::BasePointerOffset(a), Expression::BasePointerOffset(b)) => a.matches(b),
            (Expression::StackBaseOffset(a), Expression::StackBaseOffset(b)) => a.matches(b),
            _ => false,
        }
    }

    pub fn __eq__(&self, other: &Self) -> bool {
        match (self, other) {
            (Expression::Const(a), Expression::Const(b)) => a.__eq__(b),
            (Expression::VirtualVariable(a), Expression::VirtualVariable(b)) => a.__eq__(b),
            (Expression::Convert(a), Expression::Convert(b)) => a.__eq__(b),
            (Expression::Reinterpret(a), Expression::Reinterpret(b)) => a.__eq__(b),
            (Expression::Load(a), Expression::Load(b)) => a.__eq__(b),
            (Expression::ITE(a), Expression::ITE(b)) => a.__eq__(b),
            (Expression::UnaryOp(a), Expression::UnaryOp(b)) => a.__eq__(b),
            (Expression::BinaryOp(a), Expression::BinaryOp(b)) => a.__eq__(b),
            (Expression::Call(a), Expression::Call(b)) => a.__eq__(b),
            (Expression::Phi(a), Expression::Phi(b)) => a.__eq__(b),
            (Expression::DirtyExpression(a), Expression::DirtyExpression(b)) => a.__eq__(b),
            (Expression::MultiStatementExpression(a), Expression::MultiStatementExpression(b)) => a.__eq__(b),
            (Expression::BasePointerOffset(a), Expression::BasePointerOffset(b)) => a.__eq__(b),
            (Expression::StackBaseOffset(a), Expression::StackBaseOffset(b)) => a.__eq__(b),
            _ => false,
        }
    }

    pub fn __repr__(&self) -> String {
        match self {
            Expression::Const(c) => c.__repr__(),
            Expression::VirtualVariable(v) => v.__repr__(),
            Expression::Convert(conv) => conv.__repr__(),
            Expression::Reinterpret(reint) => reint.__repr__(),
            Expression::Load(l) => l.__repr__(),
            Expression::ITE(ite) => ite.__repr__(),
            Expression::UnaryOp(u) => u.__repr__(),
            Expression::BinaryOp(b) => b.__repr__(),
            Expression::Call(call) => call.__repr__(),
            Expression::Phi(phi) => phi.__repr__(),
            Expression::DirtyExpression(dirty) => dirty.__repr__(),
            Expression::MultiStatementExpression(mse) => mse.__repr__(),
            Expression::BasePointerOffset(bpo) => bpo.__repr__(),
            Expression::StackBaseOffset(sbo) => sbo.__repr__(),
        }
    }

    /// Replace old_expr with new_expr in this expression tree.
    /// Returns (replaced: bool, new_expression: Expression)
    pub fn replace(&self, old_expr: &Expression, new_expr: &Expression) -> (bool, Expression) {
        // First check if this expression itself matches
        if self.__eq__(old_expr) {
            return (true, new_expr.clone());
        }

        // Otherwise, delegate to the specific type's replace method
        match self {
            // Atoms don't have children to replace
            Expression::Const(_) => (false, self.clone()),
            Expression::VirtualVariable(_) => (false, self.clone()),

            // Compound expressions delegate to their replace methods
            Expression::UnaryOp(u) => {
                let (r, replaced) = u.replace(old_expr, new_expr);
                (r, Expression::UnaryOp(replaced))
            }
            Expression::BinaryOp(b) => {
                let (r, replaced) = b.replace(old_expr, new_expr);
                (r, Expression::BinaryOp(replaced))
            }
            Expression::Convert(conv) => {
                let (r, replaced) = conv.replace(old_expr, new_expr);
                (r, Expression::Convert(replaced))
            }
            Expression::Reinterpret(reint) => {
                let (r, replaced) = reint.replace(old_expr, new_expr);
                (r, Expression::Reinterpret(replaced))
            }
            Expression::Load(l) => {
                let (r, replaced) = l.replace(old_expr, new_expr);
                (r, Expression::Load(replaced))
            }
            Expression::ITE(ite) => {
                let (r, replaced) = ite.replace(old_expr, new_expr);
                (r, Expression::ITE(replaced))
            }
            Expression::Call(call) => {
                let (r, replaced) = call.replace(old_expr, new_expr);
                (r, Expression::Call(replaced))
            }
            Expression::Phi(phi) => {
                let (r, replaced) = phi.replace(old_expr, new_expr);
                (r, Expression::Phi(replaced))
            }
            Expression::DirtyExpression(dirty) => {
                let (r, replaced) = dirty.replace(old_expr, new_expr);
                (r, Expression::DirtyExpression(replaced))
            }
            Expression::MultiStatementExpression(mse) => {
                let (r, replaced) = mse.replace(old_expr, new_expr);
                (r, Expression::MultiStatementExpression(replaced))
            }
            Expression::BasePointerOffset(bpo) => {
                let (r, replaced) = bpo.replace(old_expr, new_expr);
                (r, Expression::BasePointerOffset(replaced))
            }
            Expression::StackBaseOffset(sbo) => {
                let (r, replaced) = sbo.replace(old_expr, new_expr);
                (r, Expression::StackBaseOffset(replaced))
            }
        }
    }
}
