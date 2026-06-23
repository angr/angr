use std::collections::BTreeSet;

use num_bigint::BigUint;

use crate::ast::op::AstOp;
use crate::error::ClarirsError;
use crate::prelude::*;

pub trait AstFactory<'c>: Sized {
    // Required methods
    fn intern_string(&self, s: impl AsRef<str>) -> InternedString;

    /// The single node constructor. All other `make_*` helpers delegate here;
    /// the node's type is inferred from the operation. The node gets exactly
    /// `annotations`; relocatable annotations of children are NOT collected.
    fn make_ast_exact(
        &'c self,
        op: AstOp<'c>,
        annotations: BTreeSet<Annotation>,
    ) -> Result<AstRef<'c>, ClarirsError>;

    // Provided methods

    /// Construct a node with `annotations` plus the relocatable annotations of
    /// the op's children, mirroring how operations propagate annotations.
    fn make_ast_annotated(
        &'c self,
        op: AstOp<'c>,
        mut annotations: BTreeSet<Annotation>,
    ) -> Result<AstRef<'c>, ClarirsError> {
        annotations.extend(
            op.child_iter()
                .flat_map(|c| c.annotations().clone())
                .filter(|a| a.relocatable()),
        );
        self.make_ast_exact(op, annotations)
    }

    fn make_ast(&'c self, op: AstOp<'c>) -> Result<AstRef<'c>, ClarirsError> {
        self.make_ast_annotated(op, BTreeSet::new())
    }

    fn bools<S: AsRef<str>>(&'c self, name: S) -> Result<AstRef<'c>, ClarirsError> {
        let interned = self.intern_string(name);
        self.make_ast(AstOp::BoolS(interned))
    }

    fn boolv(&'c self, value: bool) -> Result<AstRef<'c>, ClarirsError> {
        self.make_ast(AstOp::BoolV(value))
    }

    fn bvs<S: AsRef<str>>(&'c self, name: S, width: u32) -> Result<AstRef<'c>, ClarirsError> {
        let interned = self.intern_string(name);
        self.make_ast(AstOp::BVS(interned, width))
    }

    fn bvv(&'c self, value: BitVec) -> Result<AstRef<'c>, ClarirsError> {
        self.make_ast(AstOp::BVV(value))
    }

    fn fps<S: AsRef<str>, FS: Into<FSort>>(
        &'c self,
        name: S,
        sort: FS,
    ) -> Result<AstRef<'c>, ClarirsError> {
        let interned = self.intern_string(name);
        self.make_ast(AstOp::FPS(interned, sort.into()))
    }

    fn fpv<F: Into<Float>>(&'c self, value: F) -> Result<AstRef<'c>, ClarirsError> {
        self.make_ast(AstOp::FPV(value.into()))
    }

    fn strings<S: AsRef<str>>(&'c self, name: S) -> Result<AstRef<'c>, ClarirsError> {
        let interned = self.intern_string(name);
        self.make_ast(AstOp::StringS(interned))
    }

    fn stringv<S: Into<String>>(&'c self, value: S) -> Result<AstRef<'c>, ClarirsError> {
        self.make_ast(AstOp::StringV(value.into()))
    }

    /// Logical/bitwise negation. Requires a boolean or bitvector operand.
    fn not(&'c self, ast: impl IntoOwned<AstRef<'c>>) -> Result<AstRef<'c>, ClarirsError> {
        self.make_ast(AstOp::Not(ast.into_owned()))
    }

    fn and(
        &'c self,
        args: impl IntoIterator<Item = AstRef<'c>>,
    ) -> Result<AstRef<'c>, ClarirsError> {
        self.make_ast(AstOp::And(args.into_iter().collect()))
    }

    fn and2(
        &'c self,
        lhs: impl IntoOwned<AstRef<'c>>,
        rhs: impl IntoOwned<AstRef<'c>>,
    ) -> Result<AstRef<'c>, ClarirsError> {
        self.make_ast(AstOp::And(vec![lhs.into_owned(), rhs.into_owned()]))
    }

    fn or(
        &'c self,
        args: impl IntoIterator<Item = AstRef<'c>>,
    ) -> Result<AstRef<'c>, ClarirsError> {
        self.make_ast(AstOp::Or(args.into_iter().collect()))
    }

    fn or2(
        &'c self,
        lhs: impl IntoOwned<AstRef<'c>>,
        rhs: impl IntoOwned<AstRef<'c>>,
    ) -> Result<AstRef<'c>, ClarirsError> {
        self.make_ast(AstOp::Or(vec![lhs.into_owned(), rhs.into_owned()]))
    }

    fn xor(
        &'c self,
        args: impl IntoIterator<Item = AstRef<'c>>,
    ) -> Result<AstRef<'c>, ClarirsError> {
        self.make_ast(AstOp::Xor(args.into_iter().collect()))
    }

    fn xor2(
        &'c self,
        lhs: impl IntoOwned<AstRef<'c>>,
        rhs: impl IntoOwned<AstRef<'c>>,
    ) -> Result<AstRef<'c>, ClarirsError> {
        self.make_ast(AstOp::Xor(vec![lhs.into_owned(), rhs.into_owned()]))
    }

    /// Equality over operands of any matching sort. For floats this has IEEE
    /// `fp.eq` semantics, otherwise it is structural.
    fn eq_(
        &'c self,
        lhs: impl IntoOwned<AstRef<'c>>,
        rhs: impl IntoOwned<AstRef<'c>>,
    ) -> Result<AstRef<'c>, ClarirsError> {
        self.make_ast(AstOp::Eq(lhs.into_owned(), rhs.into_owned()))
    }

    fn neq(
        &'c self,
        lhs: impl IntoOwned<AstRef<'c>>,
        rhs: impl IntoOwned<AstRef<'c>>,
    ) -> Result<AstRef<'c>, ClarirsError> {
        self.make_ast(AstOp::Neq(lhs.into_owned(), rhs.into_owned()))
    }

    fn neg(&'c self, ast: impl IntoOwned<AstRef<'c>>) -> Result<AstRef<'c>, ClarirsError> {
        self.make_ast(AstOp::Neg(ast.into_owned()))
    }

    fn add(
        &'c self,
        lhs: impl IntoOwned<AstRef<'c>>,
        rhs: impl IntoOwned<AstRef<'c>>,
    ) -> Result<AstRef<'c>, ClarirsError> {
        self.make_ast(AstOp::Add(vec![lhs.into_owned(), rhs.into_owned()]))
    }

    fn add_many(
        &'c self,
        args: impl IntoIterator<Item = AstRef<'c>>,
    ) -> Result<AstRef<'c>, ClarirsError> {
        let args: Vec<AstRef<'c>> = args.into_iter().collect();
        self.make_ast(AstOp::Add(args))
    }

    fn mul(
        &'c self,
        lhs: impl IntoOwned<AstRef<'c>>,
        rhs: impl IntoOwned<AstRef<'c>>,
    ) -> Result<AstRef<'c>, ClarirsError> {
        self.make_ast(AstOp::Mul(vec![lhs.into_owned(), rhs.into_owned()]))
    }

    fn mul_many(
        &'c self,
        args: impl IntoIterator<Item = AstRef<'c>>,
    ) -> Result<AstRef<'c>, ClarirsError> {
        let args: Vec<AstRef<'c>> = args.into_iter().collect();
        self.make_ast(AstOp::Mul(args))
    }

    fn sub(
        &'c self,
        lhs: impl IntoOwned<AstRef<'c>>,
        rhs: impl IntoOwned<AstRef<'c>>,
    ) -> Result<AstRef<'c>, ClarirsError> {
        self.make_ast(AstOp::Sub(lhs.into_owned(), rhs.into_owned()))
    }

    fn udiv(
        &'c self,
        lhs: impl IntoOwned<AstRef<'c>>,
        rhs: impl IntoOwned<AstRef<'c>>,
    ) -> Result<AstRef<'c>, ClarirsError> {
        self.make_ast(AstOp::UDiv(lhs.into_owned(), rhs.into_owned()))
    }

    fn sdiv(
        &'c self,
        lhs: impl IntoOwned<AstRef<'c>>,
        rhs: impl IntoOwned<AstRef<'c>>,
    ) -> Result<AstRef<'c>, ClarirsError> {
        self.make_ast(AstOp::SDiv(lhs.into_owned(), rhs.into_owned()))
    }

    fn urem(
        &'c self,
        lhs: impl IntoOwned<AstRef<'c>>,
        rhs: impl IntoOwned<AstRef<'c>>,
    ) -> Result<AstRef<'c>, ClarirsError> {
        self.make_ast(AstOp::URem(lhs.into_owned(), rhs.into_owned()))
    }

    fn srem(
        &'c self,
        lhs: impl IntoOwned<AstRef<'c>>,
        rhs: impl IntoOwned<AstRef<'c>>,
    ) -> Result<AstRef<'c>, ClarirsError> {
        self.make_ast(AstOp::SRem(lhs.into_owned(), rhs.into_owned()))
    }

    fn shl(
        &'c self,
        lhs: impl IntoOwned<AstRef<'c>>,
        rhs: impl IntoOwned<AstRef<'c>>,
    ) -> Result<AstRef<'c>, ClarirsError> {
        self.make_ast(AstOp::ShL(lhs.into_owned(), rhs.into_owned()))
    }

    fn ashr(
        &'c self,
        lhs: impl IntoOwned<AstRef<'c>>,
        rhs: impl IntoOwned<AstRef<'c>>,
    ) -> Result<AstRef<'c>, ClarirsError> {
        self.make_ast(AstOp::AShR(lhs.into_owned(), rhs.into_owned()))
    }

    fn lshr(
        &'c self,
        lhs: impl IntoOwned<AstRef<'c>>,
        rhs: impl IntoOwned<AstRef<'c>>,
    ) -> Result<AstRef<'c>, ClarirsError> {
        self.make_ast(AstOp::LShR(lhs.into_owned(), rhs.into_owned()))
    }

    fn rotate_left(
        &'c self,
        lhs: impl IntoOwned<AstRef<'c>>,
        rhs: impl IntoOwned<AstRef<'c>>,
    ) -> Result<AstRef<'c>, ClarirsError> {
        self.make_ast(AstOp::RotateLeft(lhs.into_owned(), rhs.into_owned()))
    }

    fn rotate_right(
        &'c self,
        lhs: impl IntoOwned<AstRef<'c>>,
        rhs: impl IntoOwned<AstRef<'c>>,
    ) -> Result<AstRef<'c>, ClarirsError> {
        self.make_ast(AstOp::RotateRight(lhs.into_owned(), rhs.into_owned()))
    }

    fn zero_ext(
        &'c self,
        lhs: impl IntoOwned<AstRef<'c>>,
        width: u32,
    ) -> Result<AstRef<'c>, ClarirsError> {
        self.make_ast(AstOp::ZeroExt(lhs.into_owned(), width))
    }

    fn sign_ext(
        &'c self,
        lhs: impl IntoOwned<AstRef<'c>>,
        width: u32,
    ) -> Result<AstRef<'c>, ClarirsError> {
        self.make_ast(AstOp::SignExt(lhs.into_owned(), width))
    }

    fn extract(
        &'c self,
        lhs: impl IntoOwned<AstRef<'c>>,
        high: u32,
        low: u32,
    ) -> Result<AstRef<'c>, ClarirsError> {
        self.make_ast(AstOp::Extract(lhs.into_owned(), high, low))
    }

    fn concat(
        &'c self,
        args: impl IntoIterator<Item = AstRef<'c>>,
    ) -> Result<AstRef<'c>, ClarirsError> {
        let args: Vec<AstRef<'c>> = args.into_iter().collect();
        if args.is_empty() {
            return Err(ClarirsError::InvalidArguments(
                "Concat requires at least one argument".to_string(),
            ));
        }
        self.make_ast(AstOp::Concat(args))
    }

    fn concat2(
        &'c self,
        lhs: impl IntoOwned<AstRef<'c>>,
        rhs: impl IntoOwned<AstRef<'c>>,
    ) -> Result<AstRef<'c>, ClarirsError> {
        self.concat([lhs.into_owned(), rhs.into_owned()])
    }

    fn byte_reverse(&'c self, lhs: impl IntoOwned<AstRef<'c>>) -> Result<AstRef<'c>, ClarirsError> {
        self.make_ast(AstOp::ByteReverse(lhs.into_owned()))
    }

    fn ult(
        &'c self,
        lhs: impl IntoOwned<AstRef<'c>>,
        rhs: impl IntoOwned<AstRef<'c>>,
    ) -> Result<AstRef<'c>, ClarirsError> {
        self.make_ast(AstOp::ULT(lhs.into_owned(), rhs.into_owned()))
    }

    fn ule(
        &'c self,
        lhs: impl IntoOwned<AstRef<'c>>,
        rhs: impl IntoOwned<AstRef<'c>>,
    ) -> Result<AstRef<'c>, ClarirsError> {
        self.make_ast(AstOp::ULE(lhs.into_owned(), rhs.into_owned()))
    }

    fn ugt(
        &'c self,
        lhs: impl IntoOwned<AstRef<'c>>,
        rhs: impl IntoOwned<AstRef<'c>>,
    ) -> Result<AstRef<'c>, ClarirsError> {
        self.make_ast(AstOp::UGT(lhs.into_owned(), rhs.into_owned()))
    }

    fn uge(
        &'c self,
        lhs: impl IntoOwned<AstRef<'c>>,
        rhs: impl IntoOwned<AstRef<'c>>,
    ) -> Result<AstRef<'c>, ClarirsError> {
        self.make_ast(AstOp::UGE(lhs.into_owned(), rhs.into_owned()))
    }

    fn slt(
        &'c self,
        lhs: impl IntoOwned<AstRef<'c>>,
        rhs: impl IntoOwned<AstRef<'c>>,
    ) -> Result<AstRef<'c>, ClarirsError> {
        self.make_ast(AstOp::SLT(lhs.into_owned(), rhs.into_owned()))
    }

    fn sle(
        &'c self,
        lhs: impl IntoOwned<AstRef<'c>>,
        rhs: impl IntoOwned<AstRef<'c>>,
    ) -> Result<AstRef<'c>, ClarirsError> {
        self.make_ast(AstOp::SLE(lhs.into_owned(), rhs.into_owned()))
    }

    fn sgt(
        &'c self,
        lhs: impl IntoOwned<AstRef<'c>>,
        rhs: impl IntoOwned<AstRef<'c>>,
    ) -> Result<AstRef<'c>, ClarirsError> {
        self.make_ast(AstOp::SGT(lhs.into_owned(), rhs.into_owned()))
    }

    fn sge(
        &'c self,
        lhs: impl IntoOwned<AstRef<'c>>,
        rhs: impl IntoOwned<AstRef<'c>>,
    ) -> Result<AstRef<'c>, ClarirsError> {
        self.make_ast(AstOp::SGE(lhs.into_owned(), rhs.into_owned()))
    }

    fn fp_to_fp<RM: Into<FPRM>, FS: Into<FSort>>(
        &'c self,
        lhs: impl IntoOwned<AstRef<'c>>,
        sort: FS,
        rm: RM,
    ) -> Result<AstRef<'c>, ClarirsError> {
        self.make_ast(AstOp::FpToFp(lhs.into_owned(), sort.into(), rm.into()))
    }

    fn bv_to_fp<FS: Into<FSort>>(
        &'c self,
        lhs: impl IntoOwned<AstRef<'c>>,
        sort: FS,
    ) -> Result<AstRef<'c>, ClarirsError> {
        self.make_ast(AstOp::BvToFp(lhs.into_owned(), sort.into()))
    }

    fn fp_fp(
        &'c self,
        sign: impl IntoOwned<AstRef<'c>>,
        exponent: impl IntoOwned<AstRef<'c>>,
        significand: impl IntoOwned<AstRef<'c>>,
    ) -> Result<AstRef<'c>, ClarirsError> {
        self.make_ast(AstOp::FpFP(
            sign.into_owned(),
            exponent.into_owned(),
            significand.into_owned(),
        ))
    }

    fn bv_to_fp_signed<RM: Into<FPRM>, FS: Into<FSort>>(
        &'c self,
        lhs: impl IntoOwned<AstRef<'c>>,
        sort: FS,
        rm: RM,
    ) -> Result<AstRef<'c>, ClarirsError> {
        self.make_ast(AstOp::BvToFpSigned(
            lhs.into_owned(),
            sort.into(),
            rm.into(),
        ))
    }

    fn bv_to_fp_unsigned<RM: Into<FPRM>, FS: Into<FSort>>(
        &'c self,
        lhs: impl IntoOwned<AstRef<'c>>,
        sort: FS,
        rm: RM,
    ) -> Result<AstRef<'c>, ClarirsError> {
        self.make_ast(AstOp::BvToFpUnsigned(
            lhs.into_owned(),
            sort.into(),
            rm.into(),
        ))
    }

    fn fp_to_ieeebv(&'c self, lhs: impl IntoOwned<AstRef<'c>>) -> Result<AstRef<'c>, ClarirsError> {
        self.make_ast(AstOp::FpToIEEEBV(lhs.into_owned()))
    }

    fn fp_to_ubv<RM: Into<FPRM>>(
        &'c self,
        lhs: impl IntoOwned<AstRef<'c>>,
        width: u32,
        rm: RM,
    ) -> Result<AstRef<'c>, ClarirsError> {
        self.make_ast(AstOp::FpToUBV(lhs.into_owned(), width, rm.into()))
    }

    fn fp_to_sbv<RM: Into<FPRM>>(
        &'c self,
        lhs: impl IntoOwned<AstRef<'c>>,
        width: u32,
        rm: RM,
    ) -> Result<AstRef<'c>, ClarirsError> {
        self.make_ast(AstOp::FpToSBV(lhs.into_owned(), width, rm.into()))
    }

    fn fp_neg(&'c self, lhs: impl IntoOwned<AstRef<'c>>) -> Result<AstRef<'c>, ClarirsError> {
        self.make_ast(AstOp::FpNeg(lhs.into_owned()))
    }

    fn fp_abs(&'c self, lhs: impl IntoOwned<AstRef<'c>>) -> Result<AstRef<'c>, ClarirsError> {
        self.make_ast(AstOp::FpAbs(lhs.into_owned()))
    }

    fn fp_add<RM: Into<FPRM>>(
        &'c self,
        lhs: impl IntoOwned<AstRef<'c>>,
        rhs: impl IntoOwned<AstRef<'c>>,
        rm: RM,
    ) -> Result<AstRef<'c>, ClarirsError> {
        self.make_ast(AstOp::FpAdd(lhs.into_owned(), rhs.into_owned(), rm.into()))
    }

    fn fp_sub<RM: Into<FPRM>>(
        &'c self,
        lhs: impl IntoOwned<AstRef<'c>>,
        rhs: impl IntoOwned<AstRef<'c>>,
        rm: RM,
    ) -> Result<AstRef<'c>, ClarirsError> {
        self.make_ast(AstOp::FpSub(lhs.into_owned(), rhs.into_owned(), rm.into()))
    }

    fn fp_mul<RM: Into<FPRM>>(
        &'c self,
        lhs: impl IntoOwned<AstRef<'c>>,
        rhs: impl IntoOwned<AstRef<'c>>,
        rm: RM,
    ) -> Result<AstRef<'c>, ClarirsError> {
        self.make_ast(AstOp::FpMul(lhs.into_owned(), rhs.into_owned(), rm.into()))
    }

    fn fp_div<RM: Into<FPRM>>(
        &'c self,
        lhs: impl IntoOwned<AstRef<'c>>,
        rhs: impl IntoOwned<AstRef<'c>>,
        rm: RM,
    ) -> Result<AstRef<'c>, ClarirsError> {
        self.make_ast(AstOp::FpDiv(lhs.into_owned(), rhs.into_owned(), rm.into()))
    }

    fn fp_sqrt<RM: Into<FPRM>>(
        &'c self,
        lhs: impl IntoOwned<AstRef<'c>>,
        rm: RM,
    ) -> Result<AstRef<'c>, ClarirsError> {
        self.make_ast(AstOp::FpSqrt(lhs.into_owned(), rm.into()))
    }

    fn fp_eq(
        &'c self,
        lhs: impl IntoOwned<AstRef<'c>>,
        rhs: impl IntoOwned<AstRef<'c>>,
    ) -> Result<AstRef<'c>, ClarirsError> {
        self.make_ast(AstOp::Eq(lhs.into_owned(), rhs.into_owned()))
    }

    fn fp_neq(
        &'c self,
        lhs: impl IntoOwned<AstRef<'c>>,
        rhs: impl IntoOwned<AstRef<'c>>,
    ) -> Result<AstRef<'c>, ClarirsError> {
        self.make_ast(AstOp::Neq(lhs.into_owned(), rhs.into_owned()))
    }

    fn fp_lt(
        &'c self,
        lhs: impl IntoOwned<AstRef<'c>>,
        rhs: impl IntoOwned<AstRef<'c>>,
    ) -> Result<AstRef<'c>, ClarirsError> {
        self.make_ast(AstOp::FpLt(lhs.into_owned(), rhs.into_owned()))
    }

    fn fp_leq(
        &'c self,
        lhs: impl IntoOwned<AstRef<'c>>,
        rhs: impl IntoOwned<AstRef<'c>>,
    ) -> Result<AstRef<'c>, ClarirsError> {
        self.make_ast(AstOp::FpLeq(lhs.into_owned(), rhs.into_owned()))
    }

    fn fp_gt(
        &'c self,
        lhs: impl IntoOwned<AstRef<'c>>,
        rhs: impl IntoOwned<AstRef<'c>>,
    ) -> Result<AstRef<'c>, ClarirsError> {
        self.make_ast(AstOp::FpGt(lhs.into_owned(), rhs.into_owned()))
    }

    fn fp_geq(
        &'c self,
        lhs: impl IntoOwned<AstRef<'c>>,
        rhs: impl IntoOwned<AstRef<'c>>,
    ) -> Result<AstRef<'c>, ClarirsError> {
        self.make_ast(AstOp::FpGeq(lhs.into_owned(), rhs.into_owned()))
    }

    fn fp_is_nan(&'c self, lhs: impl IntoOwned<AstRef<'c>>) -> Result<AstRef<'c>, ClarirsError> {
        self.make_ast(AstOp::FpIsNan(lhs.into_owned()))
    }

    fn fp_is_inf(&'c self, lhs: impl IntoOwned<AstRef<'c>>) -> Result<AstRef<'c>, ClarirsError> {
        self.make_ast(AstOp::FpIsInf(lhs.into_owned()))
    }

    fn str_len(&'c self, lhs: impl IntoOwned<AstRef<'c>>) -> Result<AstRef<'c>, ClarirsError> {
        self.make_ast(AstOp::StrLen(lhs.into_owned()))
    }

    fn str_concat(
        &'c self,
        lhs: impl IntoOwned<AstRef<'c>>,
        rhs: impl IntoOwned<AstRef<'c>>,
    ) -> Result<AstRef<'c>, ClarirsError> {
        self.make_ast(AstOp::StrConcat(lhs.into_owned(), rhs.into_owned()))
    }

    fn str_substr(
        &'c self,
        lhs: impl IntoOwned<AstRef<'c>>,
        start: impl IntoOwned<AstRef<'c>>,
        size: impl IntoOwned<AstRef<'c>>,
    ) -> Result<AstRef<'c>, ClarirsError> {
        self.make_ast(AstOp::StrSubstr(
            lhs.into_owned(),
            start.into_owned(),
            size.into_owned(),
        ))
    }

    fn str_contains(
        &'c self,
        lhs: impl IntoOwned<AstRef<'c>>,
        rhs: impl IntoOwned<AstRef<'c>>,
    ) -> Result<AstRef<'c>, ClarirsError> {
        self.make_ast(AstOp::StrContains(lhs.into_owned(), rhs.into_owned()))
    }

    fn str_index_of(
        &'c self,
        base: impl IntoOwned<AstRef<'c>>,
        substr: impl IntoOwned<AstRef<'c>>,
        offset: impl IntoOwned<AstRef<'c>>,
    ) -> Result<AstRef<'c>, ClarirsError> {
        self.make_ast(AstOp::StrIndexOf(
            base.into_owned(),
            substr.into_owned(),
            offset.into_owned(),
        ))
    }

    fn str_replace(
        &'c self,
        lhs: impl IntoOwned<AstRef<'c>>,
        rhs: impl IntoOwned<AstRef<'c>>,
        start: impl IntoOwned<AstRef<'c>>,
    ) -> Result<AstRef<'c>, ClarirsError> {
        self.make_ast(AstOp::StrReplace(
            lhs.into_owned(),
            rhs.into_owned(),
            start.into_owned(),
        ))
    }

    fn str_prefix_of(
        &'c self,
        lhs: impl IntoOwned<AstRef<'c>>,
        rhs: impl IntoOwned<AstRef<'c>>,
    ) -> Result<AstRef<'c>, ClarirsError> {
        self.make_ast(AstOp::StrPrefixOf(lhs.into_owned(), rhs.into_owned()))
    }

    fn str_suffix_of(
        &'c self,
        lhs: impl IntoOwned<AstRef<'c>>,
        rhs: impl IntoOwned<AstRef<'c>>,
    ) -> Result<AstRef<'c>, ClarirsError> {
        self.make_ast(AstOp::StrSuffixOf(lhs.into_owned(), rhs.into_owned()))
    }

    fn str_to_bv(&'c self, lhs: impl IntoOwned<AstRef<'c>>) -> Result<AstRef<'c>, ClarirsError> {
        self.make_ast(AstOp::StrToBV(lhs.into_owned()))
    }

    fn bv_to_str(&'c self, lhs: impl IntoOwned<AstRef<'c>>) -> Result<AstRef<'c>, ClarirsError> {
        self.make_ast(AstOp::BVToStr(lhs.into_owned()))
    }

    fn str_is_digit(&'c self, lhs: impl IntoOwned<AstRef<'c>>) -> Result<AstRef<'c>, ClarirsError> {
        self.make_ast(AstOp::StrIsDigit(lhs.into_owned()))
    }

    fn str_eq(
        &'c self,
        lhs: impl IntoOwned<AstRef<'c>>,
        rhs: impl IntoOwned<AstRef<'c>>,
    ) -> Result<AstRef<'c>, ClarirsError> {
        self.make_ast(AstOp::Eq(lhs.into_owned(), rhs.into_owned()))
    }

    fn str_neq(
        &'c self,
        lhs: impl IntoOwned<AstRef<'c>>,
        rhs: impl IntoOwned<AstRef<'c>>,
    ) -> Result<AstRef<'c>, ClarirsError> {
        self.make_ast(AstOp::Neq(lhs.into_owned(), rhs.into_owned()))
    }

    /// If-then-else. `then` and `else_` must have the same sort.
    /// If-then-else. The condition must be boolean and both branches must have
    /// the same sort.
    fn ite(
        &'c self,
        cond: impl IntoOwned<AstRef<'c>>,
        then: impl IntoOwned<AstRef<'c>>,
        else_: impl IntoOwned<AstRef<'c>>,
    ) -> Result<AstRef<'c>, ClarirsError> {
        self.make_ast(AstOp::ITE(
            cond.into_owned(),
            then.into_owned(),
            else_.into_owned(),
        ))
    }

    fn annotate(
        &'c self,
        ast: impl IntoOwned<AstRef<'c>>,
        annotations: impl IntoIterator<Item = Annotation>,
    ) -> Result<AstRef<'c>, ClarirsError> {
        ast.into_owned().annotate(annotations)
    }

    // VSA methods

    fn si(
        &'c self,
        size: u32,
        stride: BigUint,
        lower_bound: BigUint,
        upper_bound: BigUint,
    ) -> Result<AstRef<'c>, ClarirsError> {
        let name = format!("SI{size}_{stride}_{lower_bound}_{upper_bound}");
        let interned = self.intern_string(name);
        self.make_ast_annotated(
            AstOp::BVS(interned, size),
            BTreeSet::from([Annotation::new(
                AnnotationType::StridedInterval {
                    stride,
                    lower_bound,
                    upper_bound,
                },
                false,
                false,
            )]),
        )
    }

    fn esi(&'c self, size: u32) -> Result<AstRef<'c>, ClarirsError> {
        let name = format!("ESI{size}");
        let interned = self.intern_string(name);
        self.make_ast_annotated(
            AstOp::BVS(interned, size),
            BTreeSet::from([Annotation::new(
                AnnotationType::EmptyStridedInterval,
                false,
                false,
            )]),
        )
    }

    fn union(
        &'c self,
        lhs: impl IntoOwned<AstRef<'c>>,
        rhs: impl IntoOwned<AstRef<'c>>,
    ) -> Result<AstRef<'c>, ClarirsError> {
        self.make_ast(AstOp::Union(lhs.into_owned(), rhs.into_owned()))
    }

    fn intersection(
        &'c self,
        lhs: impl IntoOwned<AstRef<'c>>,
        rhs: impl IntoOwned<AstRef<'c>>,
    ) -> Result<AstRef<'c>, ClarirsError> {
        self.make_ast(AstOp::Intersection(lhs.into_owned(), rhs.into_owned()))
    }

    fn widen(
        &'c self,
        lhs: impl IntoOwned<AstRef<'c>>,
        rhs: impl IntoOwned<AstRef<'c>>,
    ) -> Result<AstRef<'c>, ClarirsError> {
        self.make_ast(AstOp::Widen(lhs.into_owned(), rhs.into_owned()))
    }

    // Helper methods
    fn true_(&'c self) -> Result<AstRef<'c>, ClarirsError> {
        self.boolv(true)
    }

    fn false_(&'c self) -> Result<AstRef<'c>, ClarirsError> {
        self.boolv(false)
    }

    fn fpv_from_f64(&'c self, value: f64) -> Result<AstRef<'c>, ClarirsError> {
        self.fpv(Float::from(value))
    }
}
