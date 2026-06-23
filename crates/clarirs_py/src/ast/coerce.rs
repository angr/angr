use std::{cmp::max, str};

use num_bigint::{BigInt, BigUint};
use pyo3::types::{PyFloat, PyInt};

use crate::prelude::*;

/// Coerce a BV into a Bool: concrete BVVs resolve to true/false directly,
/// symbolic BVs become `bv != 0`.
fn bv_to_bool(bv: &BV) -> Result<AstRef<'static>, ClaripyError> {
    let inner = &bv.inner;
    if let Ok(simplified) = inner.simplify()
        && let AstOp::BVV(v) = simplified.op()
    {
        return Ok(if v.is_zero() {
            GLOBAL_CONTEXT.false_()?
        } else {
            GLOBAL_CONTEXT.true_()?
        });
    }
    let zero = GLOBAL_CONTEXT.bvv(BitVec::from((0, bv.size() as u32)))?;
    Ok(GLOBAL_CONTEXT.neq(inner, &zero)?)
}

#[derive(Clone)]
pub struct CoerceBool<'py>(pub Bound<'py, Bool>);

impl<'py> FromPyObject<'_, 'py> for CoerceBool<'py> {
    type Error = PyErr;

    fn extract(val: Borrowed<'_, 'py, PyAny>) -> PyResult<Self> {
        if let Ok(bool_val) = val.cast::<Bool>() {
            Ok(CoerceBool(bool_val.to_owned()))
        } else if let Ok(bool_val) = val.extract::<bool>() {
            Ok(CoerceBool(
                Bool::new(val.py(), &GLOBAL_CONTEXT.boolv(bool_val).unwrap()).unwrap(),
            ))
        } else if let Ok(int_val) = val.cast::<PyInt>() {
            // Coerce int (0 or non-zero) to Bool
            let i: BigInt = int_val.extract()?;
            Ok(CoerceBool(
                Bool::new(val.py(), &GLOBAL_CONTEXT.boolv(i != BigInt::ZERO).unwrap()).unwrap(),
            ))
        } else if let Ok(bv_val) = val.cast::<BV>() {
            // Coerce BV to Bool: concrete fast-path, otherwise `bv != 0`.
            Ok(CoerceBool(Bool::new(val.py(), &bv_to_bool(bv_val.get())?)?))
        } else {
            Err(ClaripyError::InvalidArgumentType("Expected Bool".to_string()).into())
        }
    }
}

impl<'py> From<CoerceBool<'py>> for Bound<'py, Bool> {
    fn from(val: CoerceBool<'py>) -> Self {
        val.0
    }
}

impl<'py> From<CoerceBool<'py>> for AstRef<'static> {
    fn from(val: CoerceBool<'py>) -> Self {
        val.0.get().inner.clone()
    }
}

pub enum CoerceBV<'py> {
    BV(Bound<'py, BV>),
    Int(BigInt),
    Bool(Bound<'py, Bool>),
}

impl<'py> CoerceBV<'py> {
    pub fn unpack(
        &self,
        py: Python<'py>,
        size: u32,
        allow_mismatch: bool,
    ) -> Result<Bound<'py, BV>, ClaripyError> {
        match self {
            CoerceBV::BV(bv) => {
                if bv.get().size() as u32 == size || allow_mismatch {
                    Ok(bv.clone())
                } else {
                    Err(ClaripyError::CastingError("BV size mismatch".to_string()))
                }
            }
            CoerceBV::Int(int) => {
                let bv = BitVec::from((int.clone(), size));
                BV::new(py, &GLOBAL_CONTEXT.bvv(bv)?)
            }
            CoerceBV::Bool(bool_val) => {
                // Convert Bool to BV of the requested size: If(bool, 1, 0).
                let one = GLOBAL_CONTEXT.bvv(BitVec::from((1, size)))?;
                let zero = GLOBAL_CONTEXT.bvv(BitVec::from((0, size)))?;
                let bv_ast = GLOBAL_CONTEXT.ite(&bool_val.get().inner, &one, &zero)?;
                BV::new(py, &bv_ast.simplify_ext(true, true)?)
            }
        }
    }

    pub fn unpack_like(&self, py: Python<'py>, like: &BV) -> Result<Bound<'py, BV>, ClaripyError> {
        self.unpack(py, like.size() as u32, false)
    }

    fn get_size(&self) -> Option<u32> {
        match self {
            CoerceBV::BV(bv) => Some(bv.get().size() as u32),
            CoerceBV::Int(_) | CoerceBV::Bool(_) => None,
        }
    }

    pub fn unpack_pair(
        py: Python<'py>,
        lhs: &CoerceBV<'py>,
        rhs: &CoerceBV<'py>,
    ) -> Result<(Bound<'py, BV>, Bound<'py, BV>), ClaripyError> {
        // Determine target size from whichever operand has a concrete size
        let lhs_size = lhs.get_size();
        let rhs_size = rhs.get_size();

        match (lhs_size, rhs_size) {
            (Some(ls), Some(rs)) if ls != rs => Err(ClaripyError::TypeError(format!(
                "BV size mismatch: left operand has {ls} bits, right operand has {rs} bits"
            ))),
            (Some(size), _) => Ok((lhs.unpack(py, size, false)?, rhs.unpack(py, size, false)?)),
            (_, Some(size)) => Ok((lhs.unpack(py, size, false)?, rhs.unpack(py, size, false)?)),
            (None, None) => {
                // Both are Int or Bool - guess size
                match (lhs, rhs) {
                    (CoerceBV::Int(lhs_int), CoerceBV::Int(rhs_int)) => {
                        let mut size = max(lhs_int.bits() as u32, rhs_int.bits() as u32);
                        if *lhs_int < BigInt::ZERO || *rhs_int < BigInt::ZERO {
                            size += 1;
                        }
                        let size = size.next_power_of_two();
                        Ok((lhs.unpack(py, size, false)?, rhs.unpack(py, size, false)?))
                    }
                    _ => {
                        // Bool/Bool or Bool/Int combinations - default to 1-bit
                        Ok((lhs.unpack(py, 1, false)?, rhs.unpack(py, 1, false)?))
                    }
                }
            }
        }
    }

    pub fn unpack_vec(
        py: Python<'py>,
        vals: &[CoerceBV<'py>],
    ) -> Result<Vec<Bound<'py, BV>>, ClaripyError> {
        if vals.is_empty() {
            return Ok(vec![]);
        }

        // First, determine the size to use
        let size =
            vals.iter()
                .find_map(|val| val.get_size())
                .ok_or(ClaripyError::InvalidArgumentType(
                    "Failed to extract size of BVs in list".to_string(),
                ))?;

        // Round up to the nearest power of 2
        let size = size.next_power_of_two();

        // Now unpack all values
        vals.iter().map(|val| val.unpack(py, size, true)).collect()
    }

    pub fn unpack_vec_mismatch(
        py: Python<'py>,
        vals: &[CoerceBV<'py>],
    ) -> Result<Vec<Bound<'py, BV>>, ClaripyError> {
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

        let mut results = Vec::with_capacity(vals.len());

        for val in vals {
            results.push(val.unpack(py, default_size, true)?);
        }

        Ok(results)
    }
}

impl<'py> FromPyObject<'_, 'py> for CoerceBV<'py> {
    type Error = PyErr;

    fn extract(val: Borrowed<'_, 'py, PyAny>) -> PyResult<Self> {
        if let Ok(bv_val) = val.cast::<BV>() {
            Ok(CoerceBV::from(bv_val.to_owned()))
        } else if let Ok(int_val) = val.cast::<PyInt>() {
            Ok(CoerceBV::from(int_val.to_owned()))
        } else if let Ok(bool_val) = val.cast::<Bool>() {
            Ok(CoerceBV::Bool(bool_val.to_owned()))
        } else if let Ok(bytes_val) = val.extract::<Vec<u8>>() {
            // Interpret the raw bytes as a big-endian bitvector of len(bytes) * 8 bits.
            let length = bytes_val.len() as u32 * 8;
            let words = BigUint::from_bytes_be(&bytes_val)
                .iter_u64_digits()
                .collect();
            let bv = BitVec::new(words, length).expect("BitVec::new is infallible");
            Ok(CoerceBV::BV(BV::new(
                val.py(),
                &GLOBAL_CONTEXT.bvv(bv).map_err(ClaripyError::from)?,
            )?))
        } else {
            Err(ClaripyError::InvalidArgumentType("Expected BV".to_string()).into())
        }
    }
}

impl<'py> From<Bound<'py, BV>> for CoerceBV<'py> {
    fn from(val: Bound<'py, BV>) -> Self {
        CoerceBV::BV(val)
    }
}

impl<'py> From<Bound<'py, PyInt>> for CoerceBV<'py> {
    fn from(val: Bound<'py, PyInt>) -> Self {
        CoerceBV::Int(val.extract::<BigInt>().unwrap())
    }
}

pub enum CoerceFP<'py> {
    FP(Bound<'py, FP>),
    Py(Bound<'py, PyFloat>),
}

impl<'py> CoerceFP<'py> {
    pub fn unpack_like(&self, py: Python<'py>, like: &FP) -> Result<Bound<'py, FP>, ClaripyError> {
        match self {
            CoerceFP::FP(fp) => Ok(fp.clone()),
            CoerceFP::Py(py_float) => match like.size() {
                32 => {
                    let val = py_float.extract::<f32>().map_err(|e| {
                        ClaripyError::InvalidArgumentType(format!(
                            "Failed to extract f32 from Python float: {e}"
                        ))
                    })?;
                    FP::new(py, &GLOBAL_CONTEXT.fpv(val)?)
                }
                64 => {
                    let val = py_float.extract::<f64>().map_err(|e| {
                        ClaripyError::InvalidArgumentType(format!(
                            "Failed to extract f64 from Python float: {e}"
                        ))
                    })?;
                    FP::new(py, &GLOBAL_CONTEXT.fpv(val)?)
                }
                _ => Err(ClaripyError::InvalidArgumentType(
                    "Unsupported FP size".to_string(),
                )),
            },
        }
    }

    pub fn unpack_pair(
        py: Python<'py>,
        lhs: &CoerceFP<'py>,
        rhs: &CoerceFP<'py>,
    ) -> Result<(Bound<'py, FP>, Bound<'py, FP>), ClaripyError> {
        Ok(match (lhs, rhs) {
            (CoerceFP::FP(lhs), CoerceFP::FP(rhs)) => {
                // Both are FPs, so just return them
                (lhs.clone(), rhs.clone())
            }
            (CoerceFP::Py(_), CoerceFP::FP(rhs)) => {
                let lhs = lhs.unpack_like(py, rhs.get())?;
                (lhs, rhs.clone())
            }
            (CoerceFP::FP(lhs), CoerceFP::Py(_)) => {
                let rhs = rhs.unpack_like(py, lhs.get())?;
                (lhs.clone(), rhs)
            }
            (CoerceFP::Py(_), CoerceFP::Py(_)) => {
                return Err(ClaripyError::InvalidArgumentType(
                    "Cannot determine FP size from two Python floats".to_string(),
                ));
            }
        })
    }
}

impl<'py> FromPyObject<'_, 'py> for CoerceFP<'py> {
    type Error = PyErr;

    fn extract(val: Borrowed<'_, 'py, PyAny>) -> PyResult<Self> {
        if let Ok(fp_val) = val.cast::<FP>() {
            Ok(CoerceFP::FP(fp_val.to_owned()))
        } else if let Ok(fp_val) = val.cast::<PyFloat>() {
            Ok(CoerceFP::Py(fp_val.to_owned()))
        } else {
            Err(ClaripyError::InvalidArgumentType("Expected FP".to_string()).into())
        }
    }
}

impl<'py> TryFrom<CoerceFP<'py>> for Bound<'py, FP> {
    type Error = ClaripyError;

    fn try_from(val: CoerceFP<'py>) -> Result<Self, Self::Error> {
        match val {
            CoerceFP::FP(fp) => Ok(fp),
            CoerceFP::Py(_) => Err(ClaripyError::InvalidArgumentType("Expected FP".to_string())),
        }
    }
}

impl<'py> TryFrom<CoerceFP<'py>> for AstRef<'static> {
    type Error = ClaripyError;

    fn try_from(val: CoerceFP<'py>) -> Result<Self, Self::Error> {
        match val {
            CoerceFP::FP(fp) => Ok(fp.get().inner.clone()),
            CoerceFP::Py(_) => Err(ClaripyError::InvalidArgumentType("Expected FP".to_string())),
        }
    }
}

pub struct CoerceString<'py>(pub Bound<'py, PyAstString>);

impl<'py> FromPyObject<'_, 'py> for CoerceString<'py> {
    type Error = PyErr;
    fn extract(val: Borrowed<'_, 'py, PyAny>) -> PyResult<Self> {
        if let Ok(string_val) = val.cast::<PyAstString>() {
            Ok(CoerceString(string_val.to_owned()))
        } else if let Ok(string_val) = val.extract::<&str>() {
            Ok(CoerceString(
                PyAstString::new(val.py(), &GLOBAL_CONTEXT.stringv(string_val).unwrap()).unwrap(),
            ))
        } else {
            Err(ClaripyError::InvalidArgumentType("Expected String".to_string()).into())
        }
    }
}

impl<'py> From<CoerceString<'py>> for Bound<'py, PyAstString> {
    fn from(val: CoerceString<'py>) -> Self {
        val.0
    }
}

impl<'py> From<CoerceString<'py>> for AstRef<'static> {
    fn from(val: CoerceString<'py>) -> Self {
        val.0.get().inner.clone()
    }
}

pub struct CoerceBase<'py>(pub Bound<'py, Base>);

impl<'a, 'py> FromPyObject<'a, 'py> for CoerceBase<'py> {
    type Error = PyErr;

    fn extract(val: Borrowed<'a, 'py, PyAny>) -> PyResult<Self> {
        // Check concrete AST types first, preserving the actual type of the input.
        // Do NOT use CoerceBool here since that now accepts BVs (via BV != 0), which
        // would incorrectly turn a BV expression into a Bool expression in contexts
        // like solver.solution(bv_expr, value) that need to preserve the original type.
        if let Ok(bool_val) = val.cast::<Bool>() {
            Ok(CoerceBase(bool_val.to_owned().cast()?.clone()))
        } else if let Ok(bv_val) = val.cast::<BV>() {
            Ok(CoerceBase(bv_val.to_owned().cast()?.clone()))
        } else if let Ok(fp_val) = val.cast::<FP>() {
            Ok(CoerceBase(fp_val.to_owned().cast()?.clone()))
        } else if let Ok(string_val) = val.cast::<PyAstString>() {
            Ok(CoerceBase(string_val.to_owned().cast()?.clone()))
        } else if let Ok(py_bool) = val.extract::<bool>() {
            // Handle Python bool literals by wrapping in BoolV
            let bool_ast = Bool::new(
                val.py(),
                &GLOBAL_CONTEXT.boolv(py_bool).map_err(ClaripyError::from)?,
            )?;
            Ok(CoerceBase(bool_ast.cast()?.clone()))
        } else if let Ok(int_val) = val.cast::<PyInt>() {
            // Handle Python int literals by wrapping in BVV (64-bit default)
            let int: BigInt = int_val.extract()?;
            let bv = BitVec::from((int, 64));
            let bv_ast = BV::new(
                val.py(),
                &GLOBAL_CONTEXT.bvv(bv).map_err(ClaripyError::from)?,
            )?;
            Ok(CoerceBase(bv_ast.cast()?.clone()))
        } else if let Ok(fp) = CoerceFP::extract(val) {
            match fp {
                CoerceFP::FP(fp) => Ok(CoerceBase(fp.cast()?.clone())),
                CoerceFP::Py(_) => {
                    Err(ClaripyError::InvalidArgumentType("Expected FP".to_string()).into())
                }
            }
        } else if let Ok(string) = CoerceString::extract(val) {
            Ok(CoerceBase(string.0.cast()?.clone()))
        } else {
            Err(
                ClaripyError::InvalidArgumentType("Expected Bool, BV, FP, or String".to_string())
                    .into(),
            )
        }
    }
}

impl<'py> From<CoerceBase<'py>> for Bound<'py, Base> {
    fn from(val: CoerceBase<'py>) -> Self {
        val.0
    }
}
