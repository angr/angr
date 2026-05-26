//! ``ConstValue`` -- the Python-bridged value of a Const expression.
//!
//! Phase D moved every concrete Expression subclass behind a single
//! ``Expression`` pyclass with an inline ``ExprInner`` enum, so the
//! per-class atoms.rs file went away. The ``ConstValue`` data type
//! survives because it captures the int/float/big-int distinction in
//! a serde-friendly shape that both the Phase D Wire and the in-memory
//! ``ExprInner::Const`` arm reuse.

use pyo3::Borrowed;
use pyo3::IntoPyObjectExt;
use pyo3::exceptions::PyTypeError;
use pyo3::prelude::*;
use pyo3::types::{PyFloat, PyInt};
use serde::{Deserialize, Serialize};

use crate::ailment::hash::HashItem;

/// Serde adapter that round-trips an `i128` as two halves. ``postcard``
/// (and several other no-std serializers) deliberately do not support
/// ``i128``/``u128``, so any payload that travels through them needs a
/// pair representation. Split as little-endian halves: ``(low: u64, high:
/// i64)``.
pub mod i128_as_halves {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(v: &i128, ser: S) -> Result<S::Ok, S::Error> {
        let u = *v as u128;
        let low = u as u64;
        let high = (u >> 64) as i64;
        (low, high).serialize(ser)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(de: D) -> Result<i128, D::Error> {
        let (low, high): (u64, i64) = Deserialize::deserialize(de)?;
        let u = ((high as u64 as u128) << 64) | (low as u128);
        Ok(u as i128)
    }
}

/// Value of a `Const`. Python's `int` is unbounded; values that don't fit in
/// `i128` round-trip through a hex-string fallback so Serde stays happy.
///
/// Serde representation: default external tagging. ``postcard`` is not
/// self-describing, so adjacently-tagged variants (``#[serde(tag, content)]``)
/// can't round-trip through it.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum ConstValue {
    Int(#[serde(with = "i128_as_halves")] i128),
    Float(f64),
    /// Hex (base-16, no `0x` prefix, optional leading `-`) for ints outside
    /// the i128 range.
    BigInt(String),
}

impl<'py> FromPyObject<'_, 'py> for ConstValue {
    type Error = PyErr;

    fn extract(obj: Borrowed<'_, 'py, PyAny>) -> Result<Self, Self::Error> {
        // Accept Python booleans as int 0/1 -- callers (e.g.
        // ``condition_processor`` building ``Const(idx, True, 1)``) rely
        // on the implicit ``bool -> int`` coercion that Python itself
        // performs at the Python layer.
        if obj.is_instance_of::<pyo3::types::PyBool>() {
            let b: bool = obj.extract::<bool>()?;
            return Ok(Self::Int(if b { 1 } else { 0 }));
        }
        if let Ok(f) = obj.cast::<PyFloat>() {
            return Ok(Self::Float(f.value()));
        }
        if let Ok(_i) = obj.cast::<PyInt>() {
            if let Ok(v) = obj.extract::<i128>() {
                return Ok(Self::Int(v));
            }
            let s: String = obj
                .call_method1("__format__", ("x",))
                .and_then(|x| x.extract())?;
            return Ok(Self::BigInt(s));
        }
        Err(PyTypeError::new_err(format!(
            "Const value must be int or float, got {}",
            obj.get_type().name()?
        )))
    }
}

impl<'py> IntoPyObject<'py> for ConstValue {
    type Target = PyAny;
    type Output = Bound<'py, Self::Target>;
    type Error = PyErr;

    fn into_pyobject(self, py: Python<'py>) -> Result<Self::Output, Self::Error> {
        match self {
            Self::Int(v) => v.into_bound_py_any(py),
            Self::Float(f) => f.into_bound_py_any(py),
            Self::BigInt(s) => {
                let builtins = py.import("builtins")?;
                builtins
                    .getattr("int")?
                    .call1((s.as_str(), 16))?
                    .into_bound_py_any(py)
            }
        }
    }
}

impl ConstValue {
    pub fn is_int(&self) -> bool {
        !matches!(self, Self::Float(_))
    }

    pub fn hash_item(&self) -> HashItem<'_> {
        match self {
            Self::Int(v) => HashItem::Int(*v),
            Self::BigInt(s) => HashItem::Str(s.as_str()),
            Self::Float(v) => HashItem::U64Hash(v.to_bits()),
        }
    }

    pub fn fmt_value(&self) -> String {
        match self {
            Self::Int(v) => format!("{v:#x}"),
            Self::BigInt(s) => {
                if let Some(rest) = s.strip_prefix('-') {
                    format!("-0x{rest}")
                } else {
                    format!("0x{s}")
                }
            }
            Self::Float(v) => format!("{}", v),
        }
    }
}
