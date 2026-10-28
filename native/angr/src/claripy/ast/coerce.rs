use std::{cmp::max, str};

use num_bigint::{BigInt, BigUint};
use pyo3::types::{PyFloat, PyInt};

use crate::claripy::prelude::*;

/// Coerce a BV into a Bool: concrete BVVs resolve to true/false directly,
/// symbolic BVs become `bv != 0`.
fn bv_to_bool(bv: &AstRef<'static>) -> Result<AstRef<'static>, ClaripyError> {
    if let Ok(simplified) = bv.simplify()
        && let AstOp::BVV(v) = simplified.op()
    {
        return Ok(if v.is_zero() {
            GLOBAL_CONTEXT.false_()?
        } else {
            GLOBAL_CONTEXT.true_()?
        });
    }
    let zero = GLOBAL_CONTEXT.bvv(BitVec::from((0, bv.size())))?;
    Ok(GLOBAL_CONTEXT.neq(bv, &zero)?)
}

/// A Python argument accepted where a Bool is expected: a `Bool`, a Python
/// `bool` or `int` (true when non-zero), or a `BV` (true when non-zero).
///
/// The coercions yield bare [`AstRef`]s rather than Python wrappers, so
/// coercing a literal does not allocate a wrapper object.
#[derive(Clone)]
pub struct CoerceBool(pub AstRef<'static>);

impl<'py> FromPyObject<'_, 'py> for CoerceBool {
    type Error = PyErr;

    fn extract(val: Borrowed<'_, 'py, PyAny>) -> PyResult<Self> {
        if let Ok(bool_val) = val.cast::<Bool>() {
            Ok(CoerceBool(bool_val.get().inner.clone()))
        } else if let Ok(bool_val) = val.extract::<bool>() {
            Ok(CoerceBool(
                GLOBAL_CONTEXT.boolv(bool_val).map_err(ClaripyError::from)?,
            ))
        } else if let Ok(int_val) = val.cast::<PyInt>() {
            // Coerce int (0 or non-zero) to Bool
            let i: BigInt = int_val.extract()?;
            Ok(CoerceBool(
                GLOBAL_CONTEXT
                    .boolv(i != BigInt::ZERO)
                    .map_err(ClaripyError::from)?,
            ))
        } else if let Ok(bv_val) = val.cast::<BV>() {
            // Coerce BV to Bool: concrete fast-path, otherwise `bv != 0`.
            Ok(CoerceBool(bv_to_bool(&bv_val.get().inner)?))
        } else {
            Err(ClaripyError::InvalidArgumentType("Expected Bool".to_string()).into())
        }
    }
}

impl From<CoerceBool> for AstRef<'static> {
    fn from(val: CoerceBool) -> Self {
        val.0
    }
}

/// A Python argument accepted where a BV is expected. Python `int`s and
/// `Bool`s carry no width of their own, so they are resolved against the
/// width of the other operands by the `unpack*` methods.
pub enum CoerceBV {
    BV(AstRef<'static>),
    Int(BigInt),
    Bool(AstRef<'static>),
}

impl CoerceBV {
    /// Resolve to a BV of `size` bits. A `BV` operand must already have that
    /// width unless `allow_mismatch` is set.
    pub fn unpack(&self, size: u32, allow_mismatch: bool) -> Result<AstRef<'static>, ClaripyError> {
        match self {
            CoerceBV::BV(bv) => {
                if bv.size() == size || allow_mismatch {
                    Ok(bv.clone())
                } else {
                    Err(ClaripyError::CastingError("BV size mismatch".to_string()))
                }
            }
            CoerceBV::Int(int) => {
                let bv = BitVec::from((int.clone(), size));
                Ok(GLOBAL_CONTEXT.bvv(bv)?)
            }
            CoerceBV::Bool(bool_val) => {
                // Convert Bool to BV of the requested size: If(bool, 1, 0).
                let one = GLOBAL_CONTEXT.bvv(BitVec::from((1, size)))?;
                let zero = GLOBAL_CONTEXT.bvv(BitVec::from((0, size)))?;
                let bv_ast = GLOBAL_CONTEXT.ite(bool_val, &one, &zero)?;
                Ok(bv_ast.simplify_ext(true, true)?)
            }
        }
    }

    /// Resolve to a BV of the same width as `like`.
    pub fn unpack_like(&self, like: &AstRef<'static>) -> Result<AstRef<'static>, ClaripyError> {
        self.unpack(like.size(), false)
    }

    fn get_size(&self) -> Option<u32> {
        match self {
            CoerceBV::BV(bv) => Some(bv.size()),
            CoerceBV::Int(_) | CoerceBV::Bool(_) => None,
        }
    }

    pub fn unpack_pair(
        lhs: &CoerceBV,
        rhs: &CoerceBV,
    ) -> Result<(AstRef<'static>, AstRef<'static>), ClaripyError> {
        // Determine target size from whichever operand has a concrete size
        let lhs_size = lhs.get_size();
        let rhs_size = rhs.get_size();

        match (lhs_size, rhs_size) {
            (Some(ls), Some(rs)) if ls != rs => Err(ClaripyError::TypeError(format!(
                "BV size mismatch: left operand has {ls} bits, right operand has {rs} bits"
            ))),
            (Some(size), _) => Ok((lhs.unpack(size, false)?, rhs.unpack(size, false)?)),
            (_, Some(size)) => Ok((lhs.unpack(size, false)?, rhs.unpack(size, false)?)),
            (None, None) => {
                // Both are Int or Bool - guess size
                match (lhs, rhs) {
                    (CoerceBV::Int(lhs_int), CoerceBV::Int(rhs_int)) => {
                        let mut size = max(lhs_int.bits() as u32, rhs_int.bits() as u32);
                        if *lhs_int < BigInt::ZERO || *rhs_int < BigInt::ZERO {
                            size += 1;
                        }
                        let size = size.next_power_of_two();
                        Ok((lhs.unpack(size, false)?, rhs.unpack(size, false)?))
                    }
                    _ => {
                        // Bool/Bool or Bool/Int combinations - default to 1-bit
                        Ok((lhs.unpack(1, false)?, rhs.unpack(1, false)?))
                    }
                }
            }
        }
    }

    /// Strict n-ary version of `unpack_pair`: every operand with a known width
    /// must agree on it, and unknown-width operands (ints/bools) are coerced to
    /// that width.
    pub fn unpack_many(vals: &[CoerceBV]) -> Result<Vec<AstRef<'static>>, ClaripyError> {
        let mut size: Option<u32> = None;
        for val in vals {
            if let Some(s) = val.get_size() {
                match size {
                    Some(prev) if prev != s => {
                        return Err(ClaripyError::TypeError(format!(
                            "BV size mismatch: operands have {prev} bits and {s} bits"
                        )));
                    }
                    _ => size = Some(s),
                }
            }
        }
        let size = size.ok_or_else(|| {
            ClaripyError::InvalidArgumentType(
                "Cannot determine BV width: no operand has a known size".to_string(),
            )
        })?;
        vals.iter().map(|val| val.unpack(size, false)).collect()
    }

    pub fn unpack_vec_mismatch(vals: &[CoerceBV]) -> Result<Vec<AstRef<'static>>, ClaripyError> {
        // If len is 1 and it is an Int, then we can't determine size, so just return error
        if vals.len() == 1 && matches!(vals[0], CoerceBV::Int(_)) {
            return Err(ClaripyError::InvalidArgumentType(
                "Cannot determine size from single Int".to_string(),
            ));
        }

        let default_size =
            vals.iter()
                .find_map(|val| val.get_size())
                .ok_or(ClaripyError::InvalidArgumentType(
                    "Failed to extract size of BVs in list".to_string(),
                ))?;

        vals.iter()
            .map(|val| val.unpack(default_size, true))
            .collect()
    }
}

/// Build a BV from raw bytes, read as a big-endian value of `bytes.len() * 8` bits.
fn bytes_to_bv(bytes: &[u8]) -> Result<CoerceBV, ClaripyError> {
    let length = bytes.len() as u32 * 8;
    let words = BigUint::from_bytes_be(bytes).iter_u64_digits().collect();
    let bv = BitVec::new(words, length).expect("BitVec::new is infallible");
    Ok(CoerceBV::BV(GLOBAL_CONTEXT.bvv(bv)?))
}

impl<'py> FromPyObject<'_, 'py> for CoerceBV {
    type Error = PyErr;

    fn extract(val: Borrowed<'_, 'py, PyAny>) -> PyResult<Self> {
        if let Ok(bv_val) = val.cast::<BV>() {
            Ok(CoerceBV::BV(bv_val.get().inner.clone()))
        } else if let Ok(int_val) = val.cast::<PyInt>() {
            Ok(CoerceBV::Int(int_val.extract::<BigInt>()?))
        } else if let Ok(bool_val) = val.cast::<Bool>() {
            Ok(CoerceBV::Bool(bool_val.get().inner.clone()))
        } else if let Ok(bytes_val) = val.extract::<Vec<u8>>() {
            // Interpret the raw bytes as a big-endian bitvector of len(bytes) * 8 bits.
            Ok(bytes_to_bv(&bytes_val)?)
        } else if let Ok(string_val) = val.extract::<&str>() {
            // Interpret the string as a big-endian bitvector of len(string) * 8 bits.
            Ok(bytes_to_bv(string_val.as_bytes())?)
        } else {
            Err(ClaripyError::InvalidArgumentType("Expected BV".to_string()).into())
        }
    }
}

impl From<Bound<'_, BV>> for CoerceBV {
    fn from(val: Bound<'_, BV>) -> Self {
        CoerceBV::BV(val.get().inner.clone())
    }
}

/// A Python argument accepted where an FP is expected: an `FP`, or a Python
/// `float` whose sort is taken from the other operand.
pub enum CoerceFP {
    FP(AstRef<'static>),
    Py(f64),
}

impl CoerceFP {
    /// Resolve to an FP of the same sort as `like`.
    pub fn unpack_like(&self, like: &AstRef<'static>) -> Result<AstRef<'static>, ClaripyError> {
        match self {
            CoerceFP::FP(fp) => Ok(fp.clone()),
            CoerceFP::Py(value) => match like.size() {
                32 => Ok(GLOBAL_CONTEXT.fpv(*value as f32)?),
                64 => Ok(GLOBAL_CONTEXT.fpv(*value)?),
                _ => Err(ClaripyError::InvalidArgumentType(
                    "Unsupported FP size".to_string(),
                )),
            },
        }
    }

    pub fn unpack_pair(
        lhs: &CoerceFP,
        rhs: &CoerceFP,
    ) -> Result<(AstRef<'static>, AstRef<'static>), ClaripyError> {
        Ok(match (lhs, rhs) {
            (CoerceFP::FP(lhs), CoerceFP::FP(rhs)) => {
                // Both are FPs, so just return them
                (lhs.clone(), rhs.clone())
            }
            (CoerceFP::Py(_), CoerceFP::FP(rhs)) => (lhs.unpack_like(rhs)?, rhs.clone()),
            (CoerceFP::FP(lhs), CoerceFP::Py(_)) => (lhs.clone(), rhs.unpack_like(lhs)?),
            (CoerceFP::Py(_), CoerceFP::Py(_)) => {
                return Err(ClaripyError::InvalidArgumentType(
                    "Cannot determine FP size from two Python floats".to_string(),
                ));
            }
        })
    }
}

impl<'py> FromPyObject<'_, 'py> for CoerceFP {
    type Error = PyErr;

    fn extract(val: Borrowed<'_, 'py, PyAny>) -> PyResult<Self> {
        if let Ok(fp_val) = val.cast::<FP>() {
            Ok(CoerceFP::FP(fp_val.get().inner.clone()))
        } else if let Ok(fp_val) = val.cast::<PyFloat>() {
            Ok(CoerceFP::Py(fp_val.extract::<f64>()?))
        } else {
            Err(ClaripyError::InvalidArgumentType("Expected FP".to_string()).into())
        }
    }
}

/// A Python argument accepted where a String AST is expected: a `String` AST
/// or a Python `str`.
pub struct CoerceString(pub AstRef<'static>);

impl<'py> FromPyObject<'_, 'py> for CoerceString {
    type Error = PyErr;
    fn extract(val: Borrowed<'_, 'py, PyAny>) -> PyResult<Self> {
        if let Ok(string_val) = val.cast::<PyAstString>() {
            Ok(CoerceString(string_val.get().inner.clone()))
        } else if let Ok(string_val) = val.extract::<&str>() {
            Ok(CoerceString(
                GLOBAL_CONTEXT
                    .stringv(string_val)
                    .map_err(ClaripyError::from)?,
            ))
        } else {
            Err(ClaripyError::InvalidArgumentType("Expected String".to_string()).into())
        }
    }
}

/// A Python argument accepted where any AST is expected. Literals are wrapped
/// as their natural sort (`bool` -> Bool, `int` -> 64-bit BVV, `str` -> String);
/// a Python `float` has no sort of its own and is rejected.
pub struct CoerceBase(pub AstRef<'static>);

impl<'a, 'py> FromPyObject<'a, 'py> for CoerceBase {
    type Error = PyErr;

    fn extract(val: Borrowed<'a, 'py, PyAny>) -> PyResult<Self> {
        // Check genuine ASTs first, preserving the actual sort of the input.
        // Do NOT use CoerceBool here since that accepts BVs (via BV != 0), which
        // would incorrectly turn a BV expression into a Bool expression in contexts
        // like solver.solution(bv_expr, value) that need to preserve the original type.
        if let Ok(base) = val.cast::<Base>() {
            Ok(CoerceBase(base.get().ast()))
        } else if let Ok(py_bool) = val.extract::<bool>() {
            // Handle Python bool literals by wrapping in BoolV
            Ok(CoerceBase(
                GLOBAL_CONTEXT.boolv(py_bool).map_err(ClaripyError::from)?,
            ))
        } else if let Ok(int_val) = val.cast::<PyInt>() {
            // Handle Python int literals by wrapping in BVV (64-bit default)
            let int: BigInt = int_val.extract()?;
            let bv = BitVec::from((int, 64));
            Ok(CoerceBase(
                GLOBAL_CONTEXT.bvv(bv).map_err(ClaripyError::from)?,
            ))
        } else if let Ok(string) = CoerceString::extract(val) {
            Ok(CoerceBase(string.0))
        } else {
            Err(
                ClaripyError::InvalidArgumentType("Expected Bool, BV, FP, or String".to_string())
                    .into(),
            )
        }
    }
}
