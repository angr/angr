use ast::fp::{PyFSort, PyRM};

use crate::prelude::*;

pub trait ExtractPyArgs {
    fn extract_py_args<'py>(&self, py: Python<'py>)
    -> Result<Vec<Bound<'py, PyAny>>, ClaripyError>;
}

/// Wraps a child AST in its corresponding Python wrapper class, based on the
/// child's runtime type.
fn wrap_child<'py>(
    py: Python<'py>,
    child: &AstRef<'static>,
) -> Result<Bound<'py, PyAny>, ClaripyError> {
    Ok(Base::from_ast(py, child.clone())?.into_any())
}

impl ExtractPyArgs for AstRef<'static> {
    fn extract_py_args<'py>(
        &self,
        py: Python<'py>,
    ) -> Result<Vec<Bound<'py, PyAny>>, ClaripyError> {
        Ok(match self.op() {
            // Leaves
            AstOp::BoolS(name) => vec![name.as_str().into_bound_py_any(py)?],
            AstOp::BoolV(val) => vec![val.into_bound_py_any(py)?],
            AstOp::BVS(name, size) => vec![
                name.as_str().into_bound_py_any(py)?,
                size.into_bound_py_any(py)?,
            ],
            AstOp::BVV(bit_vec) => vec![
                bit_vec.to_biguint().into_bound_py_any(py)?,
                bit_vec.len().into_bound_py_any(py)?,
            ],
            AstOp::FPS(name, fsort) => vec![
                name.as_str().into_bound_py_any(py)?,
                Bound::new(py, PyFSort::from(fsort))?.into_any(),
            ],
            AstOp::FPV(value) => vec![value.to_f64().into_bound_py_any(py)?],
            AstOp::StringS(name) => vec![name.as_str().into_bound_py_any(py)?],
            AstOp::StringV(value) => vec![value.into_bound_py_any(py)?],

            // N-ary: each child wrapped according to its own type
            AstOp::And(args)
            | AstOp::Or(args)
            | AstOp::Xor(args)
            | AstOp::Add(args)
            | AstOp::Mul(args)
            | AstOp::Concat(args) => args
                .iter()
                .map(|a| wrap_child(py, a))
                .collect::<Result<Vec<_>, _>>()?,

            // Unary ops that only expose their single child
            AstOp::Not(a)
            | AstOp::Neg(a)
            | AstOp::ByteReverse(a)
            | AstOp::FpToIEEEBV(a)
            | AstOp::FpNeg(a)
            | AstOp::FpAbs(a)
            | AstOp::FpIsNan(a)
            | AstOp::FpIsInf(a)
            | AstOp::StrLen(a)
            | AstOp::StrToBV(a)
            | AstOp::StrIsDigit(a)
            | AstOp::BVToStr(a)
            | AstOp::FpToUBV(a, _, _)
            | AstOp::FpToSBV(a, _, _)
            | AstOp::FpToFp(a, _, _)
            | AstOp::BvToFp(a, _)
            | AstOp::BvToFpSigned(a, _, _)
            | AstOp::BvToFpUnsigned(a, _, _) => vec![wrap_child(py, a)?],

            // Binary ops
            AstOp::Eq(a, b)
            | AstOp::Neq(a, b)
            | AstOp::ULT(a, b)
            | AstOp::ULE(a, b)
            | AstOp::UGT(a, b)
            | AstOp::UGE(a, b)
            | AstOp::SLT(a, b)
            | AstOp::SLE(a, b)
            | AstOp::SGT(a, b)
            | AstOp::SGE(a, b)
            | AstOp::FpLt(a, b)
            | AstOp::FpLeq(a, b)
            | AstOp::FpGt(a, b)
            | AstOp::FpGeq(a, b)
            | AstOp::StrContains(a, b)
            | AstOp::StrPrefixOf(a, b)
            | AstOp::StrSuffixOf(a, b)
            | AstOp::StrConcat(a, b)
            | AstOp::Sub(a, b)
            | AstOp::UDiv(a, b)
            | AstOp::SDiv(a, b)
            | AstOp::URem(a, b)
            | AstOp::SRem(a, b)
            | AstOp::ShL(a, b)
            | AstOp::LShR(a, b)
            | AstOp::AShR(a, b)
            | AstOp::RotateLeft(a, b)
            | AstOp::RotateRight(a, b)
            | AstOp::Union(a, b)
            | AstOp::Intersection(a, b)
            | AstOp::Widen(a, b) => vec![wrap_child(py, a)?, wrap_child(py, b)?],

            // Ternary ops
            AstOp::ITE(a, b, c)
            | AstOp::FpFP(a, b, c)
            | AstOp::StrSubstr(a, b, c)
            | AstOp::StrReplace(a, b, c)
            | AstOp::StrIndexOf(a, b, c) => {
                vec![wrap_child(py, a)?, wrap_child(py, b)?, wrap_child(py, c)?]
            }

            // Ops with non-child parameters in their argument list
            AstOp::ZeroExt(a, amount) | AstOp::SignExt(a, amount) => {
                vec![amount.into_bound_py_any(py)?, wrap_child(py, a)?]
            }
            AstOp::Extract(a, end, start) => vec![
                end.into_bound_py_any(py)?,
                start.into_bound_py_any(py)?,
                wrap_child(py, a)?,
            ],
            AstOp::FpAdd(a, b, rm)
            | AstOp::FpSub(a, b, rm)
            | AstOp::FpMul(a, b, rm)
            | AstOp::FpDiv(a, b, rm) => vec![
                wrap_child(py, a)?,
                wrap_child(py, b)?,
                Bound::new(py, PyRM::from(rm))?.into_any(),
            ],
            AstOp::FpSqrt(a, rm) => vec![
                wrap_child(py, a)?,
                Bound::new(py, PyRM::from(rm))?.into_any(),
            ],
        })
    }
}
