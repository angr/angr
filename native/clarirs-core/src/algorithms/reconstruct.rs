//! Shared helper for reconstructing an AST node from its transformed children.
//! Used by the `replace` algorithm.

use crate::{ast::op::AstOp, prelude::*};

/// Rebuilds `ast`'s op with `children` substituted in, without interning.
/// Returns `None` for leaves. The structural half of [`reconstruct_node`].
pub fn rebuild_op<'c>(ast: &AstRef<'c>, children: &[AstRef<'c>]) -> Option<AstOp<'c>> {
    let c = |i: usize| children[i].clone();
    Some(match ast.op() {
        // Leaves have no children to substitute.
        AstOp::BoolS(..)
        | AstOp::BoolV(..)
        | AstOp::BVS(..)
        | AstOp::BVV(..)
        | AstOp::FPS(..)
        | AstOp::FPV(..)
        | AstOp::StringS(..)
        | AstOp::StringV(..) => return None,

        // N-ary
        AstOp::And(..) => AstOp::And(children.to_vec()),
        AstOp::Or(..) => AstOp::Or(children.to_vec()),
        AstOp::Xor(..) => AstOp::Xor(children.to_vec()),
        AstOp::Add(..) => AstOp::Add(children.to_vec()),
        AstOp::Mul(..) => AstOp::Mul(children.to_vec()),
        AstOp::Concat(..) => AstOp::Concat(children.to_vec()),

        // Unary
        AstOp::Not(..) => AstOp::Not(c(0)),
        AstOp::Neg(..) => AstOp::Neg(c(0)),
        AstOp::ByteReverse(..) => AstOp::ByteReverse(c(0)),
        AstOp::ZeroExt(_, n) => AstOp::ZeroExt(c(0), *n),
        AstOp::SignExt(_, n) => AstOp::SignExt(c(0), *n),
        AstOp::Extract(_, hi, lo) => AstOp::Extract(c(0), *hi, *lo),
        AstOp::StrLen(..) => AstOp::StrLen(c(0)),
        AstOp::StrToBV(..) => AstOp::StrToBV(c(0)),
        AstOp::FpToIEEEBV(..) => AstOp::FpToIEEEBV(c(0)),
        AstOp::FpToUBV(_, size, rm) => AstOp::FpToUBV(c(0), *size, *rm),
        AstOp::FpToSBV(_, size, rm) => AstOp::FpToSBV(c(0), *size, *rm),
        AstOp::FpNeg(..) => AstOp::FpNeg(c(0)),
        AstOp::FpAbs(..) => AstOp::FpAbs(c(0)),
        AstOp::FpSqrt(_, rm) => AstOp::FpSqrt(c(0), *rm),
        AstOp::FpToFp(_, sort, rm) => AstOp::FpToFp(c(0), *sort, *rm),
        AstOp::BvToFp(_, sort) => AstOp::BvToFp(c(0), *sort),
        AstOp::BvToFpSigned(_, sort, rm) => AstOp::BvToFpSigned(c(0), *sort, *rm),
        AstOp::BvToFpUnsigned(_, sort, rm) => AstOp::BvToFpUnsigned(c(0), *sort, *rm),
        AstOp::FpIsNan(..) => AstOp::FpIsNan(c(0)),
        AstOp::FpIsInf(..) => AstOp::FpIsInf(c(0)),
        AstOp::StrIsDigit(..) => AstOp::StrIsDigit(c(0)),
        AstOp::BVToStr(..) => AstOp::BVToStr(c(0)),

        // Binary
        AstOp::Eq(..) => AstOp::Eq(c(0), c(1)),
        AstOp::Neq(..) => AstOp::Neq(c(0), c(1)),
        AstOp::ULT(..) => AstOp::ULT(c(0), c(1)),
        AstOp::ULE(..) => AstOp::ULE(c(0), c(1)),
        AstOp::UGT(..) => AstOp::UGT(c(0), c(1)),
        AstOp::UGE(..) => AstOp::UGE(c(0), c(1)),
        AstOp::SLT(..) => AstOp::SLT(c(0), c(1)),
        AstOp::SLE(..) => AstOp::SLE(c(0), c(1)),
        AstOp::SGT(..) => AstOp::SGT(c(0), c(1)),
        AstOp::SGE(..) => AstOp::SGE(c(0), c(1)),
        AstOp::FpLt(..) => AstOp::FpLt(c(0), c(1)),
        AstOp::FpLeq(..) => AstOp::FpLeq(c(0), c(1)),
        AstOp::FpGt(..) => AstOp::FpGt(c(0), c(1)),
        AstOp::FpGeq(..) => AstOp::FpGeq(c(0), c(1)),
        AstOp::StrContains(..) => AstOp::StrContains(c(0), c(1)),
        AstOp::StrPrefixOf(..) => AstOp::StrPrefixOf(c(0), c(1)),
        AstOp::StrSuffixOf(..) => AstOp::StrSuffixOf(c(0), c(1)),
        AstOp::Sub(..) => AstOp::Sub(c(0), c(1)),
        AstOp::UDiv(..) => AstOp::UDiv(c(0), c(1)),
        AstOp::SDiv(..) => AstOp::SDiv(c(0), c(1)),
        AstOp::URem(..) => AstOp::URem(c(0), c(1)),
        AstOp::SRem(..) => AstOp::SRem(c(0), c(1)),
        AstOp::ShL(..) => AstOp::ShL(c(0), c(1)),
        AstOp::LShR(..) => AstOp::LShR(c(0), c(1)),
        AstOp::AShR(..) => AstOp::AShR(c(0), c(1)),
        AstOp::RotateLeft(..) => AstOp::RotateLeft(c(0), c(1)),
        AstOp::RotateRight(..) => AstOp::RotateRight(c(0), c(1)),
        AstOp::Union(..) => AstOp::Union(c(0), c(1)),
        AstOp::Intersection(..) => AstOp::Intersection(c(0), c(1)),
        AstOp::Widen(..) => AstOp::Widen(c(0), c(1)),
        AstOp::FpAdd(_, _, rm) => AstOp::FpAdd(c(0), c(1), *rm),
        AstOp::FpSub(_, _, rm) => AstOp::FpSub(c(0), c(1), *rm),
        AstOp::FpMul(_, _, rm) => AstOp::FpMul(c(0), c(1), *rm),
        AstOp::FpDiv(_, _, rm) => AstOp::FpDiv(c(0), c(1), *rm),
        AstOp::StrConcat(..) => AstOp::StrConcat(c(0), c(1)),

        // Ternary
        AstOp::ITE(..) => AstOp::ITE(c(0), c(1), c(2)),
        AstOp::StrIndexOf(..) => AstOp::StrIndexOf(c(0), c(1), c(2)),
        AstOp::FpFP(..) => AstOp::FpFP(c(0), c(1), c(2)),
        AstOp::StrSubstr(..) => AstOp::StrSubstr(c(0), c(1), c(2)),
        AstOp::StrReplace(..) => AstOp::StrReplace(c(0), c(1), c(2)),
    })
}

/// Reconstructs a node from its operation and transformed children.
///
/// Leaf nodes are returned as-is. Non-leaf nodes are rebuilt by replacing the
/// op's children with the transformed ones and re-interning via the context;
/// the node's type is re-inferred from the (same-typed) children.
pub fn reconstruct_node<'c>(
    ctx: &'c Context<'c>,
    ast: &AstRef<'c>,
    children: &[AstRef<'c>],
) -> Result<AstRef<'c>, ClarirsError> {
    match rebuild_op(ast, children) {
        Some(op) => ctx.make_ast(op),
        None => Ok(ast.clone()),
    }
}
