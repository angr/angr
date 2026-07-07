//! ``ConstValue`` -- the Python-bridged value of a Const expression.
//!
//! Every concrete Expression variant lives behind a single
//! ``Expression`` pyclass with an inline ``ExprInner`` enum. The
//! ``ConstValue`` data type captures the int/float/big-int
//! distinction in a serde-friendly shape that both the serialization
//! ``Wire`` and the in-memory ``ExprInner::Const`` arm reuse.

use num_bigint::BigInt;
use pyo3::Borrowed;
use pyo3::IntoPyObjectExt;
use pyo3::exceptions::PyTypeError;
use pyo3::prelude::*;
use pyo3::types::{PyFloat, PyInt};
use serde::{Deserialize, Serialize};

use crate::ailment::hash::AilHash;

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

/// Value of a `Const`. Python's `int` is unbounded: values that fit in
/// `i128` are stored inline; anything larger is kept as an arbitrary-
/// precision [`num_bigint::BigInt`].
///
/// Serde representation: default external tagging. ``postcard`` is not
/// self-describing, so adjacently-tagged variants (``#[serde(tag, content)]``)
/// can't round-trip through it. ``num_bigint::BigInt`` serializes as a
/// sign + ``u32`` digit sequence, which postcard handles (unlike raw
/// ``i128``, hence the [`i128_as_halves`] adapter on ``Int``).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum ConstValue {
    Int(#[serde(with = "i128_as_halves")] i128),
    Float(f64),
    /// Arbitrary-precision integer for values outside the `i128` range.
    BigInt(BigInt),
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
            // Outside i128 range: pyo3's ``num-bigint`` feature converts
            // the unbounded Python ``int`` directly, no hex-string dance.
            let big: BigInt = obj.extract()?;
            return Ok(Self::BigInt(big));
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
            Self::BigInt(b) => b.into_bound_py_any(py),
        }
    }
}

impl ConstValue {
    pub fn is_int(&self) -> bool {
        !matches!(self, Self::Float(_))
    }

    pub fn hash_into<H: AilHash>(&self, h: &mut H) {
        match self {
            Self::Int(v) => h.int(*v),
            // Canonical minimal two's-complement bytes: equal integers
            // hash equally; the ``raw`` tag keeps it distinct from ``int``.
            Self::BigInt(b) => h.raw(&b.to_signed_bytes_le()),
            Self::Float(v) => h.child(v.to_bits() as i64),
        }
    }

    pub fn fmt_value(&self) -> String {
        match self {
            Self::Int(v) => format!("{v:#x}"),
            // ``{:#x}`` on a BigInt is sign-magnitude (``-0x..`` / ``0x..``),
            // matching the legacy hex-string rendering.
            Self::BigInt(b) => format!("{b:#x}"),
            Self::Float(v) => format!("{}", v),
        }
    }
}
