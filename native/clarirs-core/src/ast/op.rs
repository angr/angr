use std::collections::BTreeSet;
use std::fmt::Debug;

use serde::Serialize;

use crate::ast::node::AstRef;
use crate::prelude::*;

/// The runtime type ("sort") of an AST node. Stored on every [`AstNode`] so the
/// type of an expression can be queried without inspecting its operation, and
/// so size/sort information is available in O(1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub enum AstType {
    Bool,
    BitVec(u32),
    Float(FSort),
    String,
}

impl AstType {
    pub fn is_bool(&self) -> bool {
        matches!(self, AstType::Bool)
    }

    pub fn is_bitvec(&self) -> bool {
        matches!(self, AstType::BitVec(_))
    }

    pub fn is_float(&self) -> bool {
        matches!(self, AstType::Float(_))
    }

    pub fn is_string(&self) -> bool {
        matches!(self, AstType::String)
    }
}

/// The single operation enum for all AST nodes. A node's type (bool, bitvec,
/// float, string) is determined by its operation together with the types of its
/// children, and is cached on the [`AstNode`] as an [`AstType`].
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
pub enum AstOp<'c> {
    // Boolean leaves and operations
    BoolS(InternedString),
    BoolV(bool),

    // Polymorphic boolean/bitvector operations (the child type determines the
    // result type)
    Not(AstRef<'c>),
    And(Vec<AstRef<'c>>),
    Or(Vec<AstRef<'c>>),
    ITE(AstRef<'c>, AstRef<'c>, AstRef<'c>),

    // Equality (any sort) and bitvector comparisons (all produce a bool).
    // `Eq`/`Neq` apply to any sort; for floats they have IEEE `fp.eq`
    // semantics, otherwise they are structural.
    Eq(AstRef<'c>, AstRef<'c>),
    Neq(AstRef<'c>, AstRef<'c>),
    ULT(AstRef<'c>, AstRef<'c>),
    ULE(AstRef<'c>, AstRef<'c>),
    UGT(AstRef<'c>, AstRef<'c>),
    UGE(AstRef<'c>, AstRef<'c>),
    SLT(AstRef<'c>, AstRef<'c>),
    SLE(AstRef<'c>, AstRef<'c>),
    SGT(AstRef<'c>, AstRef<'c>),
    SGE(AstRef<'c>, AstRef<'c>),

    // Float comparisons (produce a bool)
    FpLt(AstRef<'c>, AstRef<'c>),
    FpLeq(AstRef<'c>, AstRef<'c>),
    FpGt(AstRef<'c>, AstRef<'c>),
    FpGeq(AstRef<'c>, AstRef<'c>),
    FpIsNan(AstRef<'c>),
    FpIsInf(AstRef<'c>),

    // String predicates (produce a bool)
    StrContains(AstRef<'c>, AstRef<'c>),
    StrPrefixOf(AstRef<'c>, AstRef<'c>),
    StrSuffixOf(AstRef<'c>, AstRef<'c>),
    StrIsDigit(AstRef<'c>),

    // Bitvector leaves and operations
    BVS(InternedString, u32),
    BVV(BitVec),
    Neg(AstRef<'c>),
    Xor(Vec<AstRef<'c>>),
    Add(Vec<AstRef<'c>>),
    Sub(AstRef<'c>, AstRef<'c>),
    Mul(Vec<AstRef<'c>>),
    UDiv(AstRef<'c>, AstRef<'c>),
    SDiv(AstRef<'c>, AstRef<'c>),
    URem(AstRef<'c>, AstRef<'c>),
    SRem(AstRef<'c>, AstRef<'c>),
    ShL(AstRef<'c>, AstRef<'c>),
    LShR(AstRef<'c>, AstRef<'c>),
    AShR(AstRef<'c>, AstRef<'c>),
    RotateLeft(AstRef<'c>, AstRef<'c>),
    RotateRight(AstRef<'c>, AstRef<'c>),
    ZeroExt(AstRef<'c>, u32),
    SignExt(AstRef<'c>, u32),
    Extract(AstRef<'c>, u32, u32),
    Concat(Vec<AstRef<'c>>),
    ByteReverse(AstRef<'c>),
    FpToIEEEBV(AstRef<'c>),
    FpToUBV(AstRef<'c>, u32, FPRM),
    FpToSBV(AstRef<'c>, u32, FPRM),
    StrLen(AstRef<'c>),
    StrIndexOf(AstRef<'c>, AstRef<'c>, AstRef<'c>),
    StrToBV(AstRef<'c>),

    // VSA bitvector operations (always symbolic)
    Union(AstRef<'c>, AstRef<'c>),
    Intersection(AstRef<'c>, AstRef<'c>),
    Widen(AstRef<'c>, AstRef<'c>),

    // Float leaves and operations
    FPS(InternedString, FSort),
    FPV(Float),
    FpNeg(AstRef<'c>),
    FpAbs(AstRef<'c>),
    FpAdd(AstRef<'c>, AstRef<'c>, FPRM),
    FpSub(AstRef<'c>, AstRef<'c>, FPRM),
    FpMul(AstRef<'c>, AstRef<'c>, FPRM),
    FpDiv(AstRef<'c>, AstRef<'c>, FPRM),
    FpSqrt(AstRef<'c>, FPRM),
    /// Transform a float to another float of a different size, preserving the value.
    FpToFp(AstRef<'c>, FSort, FPRM),
    /// Construct a float from sign, exponent, and significand bitvectors
    FpFP(AstRef<'c>, AstRef<'c>, AstRef<'c>),
    /// Transform an IEEE 754 bitvector to a float
    BvToFp(AstRef<'c>, FSort),
    /// Transform a signed 2's complement bitvector to a float
    BvToFpSigned(AstRef<'c>, FSort, FPRM),
    /// Transform an unsigned 2's complement bitvector to a float
    BvToFpUnsigned(AstRef<'c>, FSort, FPRM),

    // String leaves and operations
    StringS(InternedString),
    StringV(String),
    StrConcat(AstRef<'c>, AstRef<'c>),
    StrSubstr(AstRef<'c>, AstRef<'c>, AstRef<'c>),
    StrReplace(AstRef<'c>, AstRef<'c>, AstRef<'c>),
    BVToStr(AstRef<'c>),
}

impl<'c> AstOp<'c> {
    /// Returns the child AST at the given index, or `None` if out of range.
    pub fn get_child(&self, index: usize) -> Option<AstRef<'c>> {
        match self {
            // Leaves have no children
            AstOp::BoolS(..)
            | AstOp::BoolV(..)
            | AstOp::BVS(..)
            | AstOp::BVV(..)
            | AstOp::FPS(..)
            | AstOp::FPV(..)
            | AstOp::StringS(..)
            | AstOp::StringV(..) => None,

            // N-ary operations index directly into their Vec (O(1))
            AstOp::And(v)
            | AstOp::Or(v)
            | AstOp::Xor(v)
            | AstOp::Add(v)
            | AstOp::Mul(v)
            | AstOp::Concat(v) => v.get(index).cloned(),

            // Unary operations
            AstOp::Not(a)
            | AstOp::Neg(a)
            | AstOp::ByteReverse(a)
            | AstOp::ZeroExt(a, _)
            | AstOp::SignExt(a, _)
            | AstOp::Extract(a, _, _)
            | AstOp::StrLen(a)
            | AstOp::StrToBV(a)
            | AstOp::FpToIEEEBV(a)
            | AstOp::FpToUBV(a, _, _)
            | AstOp::FpToSBV(a, _, _)
            | AstOp::FpNeg(a)
            | AstOp::FpAbs(a)
            | AstOp::FpSqrt(a, _)
            | AstOp::FpToFp(a, _, _)
            | AstOp::BvToFp(a, _)
            | AstOp::BvToFpSigned(a, _, _)
            | AstOp::BvToFpUnsigned(a, _, _)
            | AstOp::FpIsNan(a)
            | AstOp::FpIsInf(a)
            | AstOp::StrIsDigit(a)
            | AstOp::BVToStr(a) => (index == 0).then(|| a.clone()),

            // Binary operations
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
            | AstOp::Widen(a, b)
            | AstOp::FpAdd(a, b, _)
            | AstOp::FpSub(a, b, _)
            | AstOp::FpMul(a, b, _)
            | AstOp::FpDiv(a, b, _)
            | AstOp::StrConcat(a, b) => match index {
                0 => Some(a.clone()),
                1 => Some(b.clone()),
                _ => None,
            },

            // Ternary operations
            AstOp::ITE(a, b, c)
            | AstOp::StrIndexOf(a, b, c)
            | AstOp::FpFP(a, b, c)
            | AstOp::StrSubstr(a, b, c)
            | AstOp::StrReplace(a, b, c) => match index {
                0 => Some(a.clone()),
                1 => Some(b.clone()),
                2 => Some(c.clone()),
                _ => None,
            },
        }
    }

    /// Returns the number of children of this operation.
    pub fn num_children(&self) -> usize {
        match self {
            AstOp::BoolS(..)
            | AstOp::BoolV(..)
            | AstOp::BVS(..)
            | AstOp::BVV(..)
            | AstOp::FPS(..)
            | AstOp::FPV(..)
            | AstOp::StringS(..)
            | AstOp::StringV(..) => 0,

            AstOp::And(v)
            | AstOp::Or(v)
            | AstOp::Xor(v)
            | AstOp::Add(v)
            | AstOp::Mul(v)
            | AstOp::Concat(v) => v.len(),

            AstOp::Not(_)
            | AstOp::Neg(_)
            | AstOp::ByteReverse(_)
            | AstOp::ZeroExt(..)
            | AstOp::SignExt(..)
            | AstOp::Extract(..)
            | AstOp::StrLen(_)
            | AstOp::StrToBV(_)
            | AstOp::FpToIEEEBV(_)
            | AstOp::FpToUBV(..)
            | AstOp::FpToSBV(..)
            | AstOp::FpNeg(_)
            | AstOp::FpAbs(_)
            | AstOp::FpSqrt(..)
            | AstOp::FpToFp(..)
            | AstOp::BvToFp(..)
            | AstOp::BvToFpSigned(..)
            | AstOp::BvToFpUnsigned(..)
            | AstOp::FpIsNan(_)
            | AstOp::FpIsInf(_)
            | AstOp::StrIsDigit(_)
            | AstOp::BVToStr(_) => 1,

            AstOp::Eq(..)
            | AstOp::Neq(..)
            | AstOp::ULT(..)
            | AstOp::ULE(..)
            | AstOp::UGT(..)
            | AstOp::UGE(..)
            | AstOp::SLT(..)
            | AstOp::SLE(..)
            | AstOp::SGT(..)
            | AstOp::SGE(..)
            | AstOp::FpLt(..)
            | AstOp::FpLeq(..)
            | AstOp::FpGt(..)
            | AstOp::FpGeq(..)
            | AstOp::StrContains(..)
            | AstOp::StrPrefixOf(..)
            | AstOp::StrSuffixOf(..)
            | AstOp::Sub(..)
            | AstOp::UDiv(..)
            | AstOp::SDiv(..)
            | AstOp::URem(..)
            | AstOp::SRem(..)
            | AstOp::ShL(..)
            | AstOp::LShR(..)
            | AstOp::AShR(..)
            | AstOp::RotateLeft(..)
            | AstOp::RotateRight(..)
            | AstOp::Union(..)
            | AstOp::Intersection(..)
            | AstOp::Widen(..)
            | AstOp::FpAdd(..)
            | AstOp::FpSub(..)
            | AstOp::FpMul(..)
            | AstOp::FpDiv(..)
            | AstOp::StrConcat(..) => 2,

            AstOp::ITE(..)
            | AstOp::StrIndexOf(..)
            | AstOp::FpFP(..)
            | AstOp::StrSubstr(..)
            | AstOp::StrReplace(..) => 3,
        }
    }

    pub fn child_iter(&self) -> AstOpChildIter<'_, 'c> {
        AstOpChildIter { op: self, index: 0 }
    }

    pub fn is_true(&self) -> bool {
        matches!(self, AstOp::BoolV(true))
    }

    pub fn is_false(&self) -> bool {
        matches!(self, AstOp::BoolV(false))
    }

    /// Returns true if the op is inherently symbolic regardless of whether it
    /// has variables. VSA operations (Union, Intersection, Widen) are always
    /// symbolic because they represent abstract multi-valued results.
    pub fn is_inherently_symbolic(&self) -> bool {
        matches!(
            self,
            AstOp::Union(..) | AstOp::Intersection(..) | AstOp::Widen(..)
        )
    }

    pub fn variables(&self) -> BTreeSet<InternedString> {
        match self {
            AstOp::BoolS(s) | AstOp::BVS(s, _) | AstOp::FPS(s, _) | AstOp::StringS(s) => {
                let mut set = BTreeSet::new();
                set.insert(s.clone());
                set
            }
            _ => {
                let mut set = BTreeSet::new();
                for child in self.child_iter() {
                    set.extend(child.variables().iter().cloned());
                }
                set
            }
        }
    }

    /// Computes the type (sort) of the result of this operation. The type of an
    /// operation is determined by the operation and the types of its children;
    /// because children cache their type this is O(1) (O(n) for `Concat`).
    pub fn infer_type(&self) -> AstType {
        match self {
            // Booleans
            AstOp::BoolS(..)
            | AstOp::BoolV(..)
            | AstOp::Eq(..)
            | AstOp::Neq(..)
            | AstOp::ULT(..)
            | AstOp::ULE(..)
            | AstOp::UGT(..)
            | AstOp::UGE(..)
            | AstOp::SLT(..)
            | AstOp::SLE(..)
            | AstOp::SGT(..)
            | AstOp::SGE(..)
            | AstOp::FpLt(..)
            | AstOp::FpLeq(..)
            | AstOp::FpGt(..)
            | AstOp::FpGeq(..)
            | AstOp::FpIsNan(..)
            | AstOp::FpIsInf(..)
            | AstOp::StrContains(..)
            | AstOp::StrPrefixOf(..)
            | AstOp::StrSuffixOf(..)
            | AstOp::StrIsDigit(..) => AstType::Bool,

            // Polymorphic: result type follows a child's type
            AstOp::Not(a) => a.ast_type(),
            AstOp::And(v) | AstOp::Or(v) | AstOp::Xor(v) => {
                v.first().map(|a| a.ast_type()).unwrap_or(AstType::Bool)
            }
            AstOp::ITE(_, t, _) => t.ast_type(),

            // Bitvectors
            AstOp::BVS(_, width) => AstType::BitVec(*width),
            AstOp::BVV(bv) => AstType::BitVec(bv.len()),
            AstOp::Add(v) | AstOp::Mul(v) => {
                AstType::BitVec(v.first().map(|a| a.size()).unwrap_or(0))
            }
            AstOp::Neg(a)
            | AstOp::Sub(a, _)
            | AstOp::UDiv(a, _)
            | AstOp::SDiv(a, _)
            | AstOp::URem(a, _)
            | AstOp::SRem(a, _)
            | AstOp::ShL(a, _)
            | AstOp::LShR(a, _)
            | AstOp::AShR(a, _)
            | AstOp::RotateLeft(a, _)
            | AstOp::RotateRight(a, _)
            | AstOp::ByteReverse(a)
            | AstOp::Union(a, _)
            | AstOp::Intersection(a, _)
            | AstOp::Widen(a, _) => AstType::BitVec(a.size()),
            AstOp::ZeroExt(a, ext) | AstOp::SignExt(a, ext) => AstType::BitVec(a.size() + ext),
            AstOp::Extract(_, high, low) => AstType::BitVec(high - low + 1),
            AstOp::Concat(v) => AstType::BitVec(v.iter().map(|a| a.size()).sum()),
            AstOp::FpToIEEEBV(a) => AstType::BitVec(a.size()),
            AstOp::FpToUBV(_, size, _) | AstOp::FpToSBV(_, size, _) => AstType::BitVec(*size),
            AstOp::StrLen(_) | AstOp::StrToBV(_) | AstOp::StrIndexOf(..) => AstType::BitVec(64),

            // Floats
            AstOp::FPS(_, sort) => AstType::Float(*sort),
            AstOp::FPV(value) => AstType::Float(value.fsort()),
            AstOp::FpNeg(a)
            | AstOp::FpAbs(a)
            | AstOp::FpSqrt(a, _)
            | AstOp::FpAdd(a, _, _)
            | AstOp::FpSub(a, _, _)
            | AstOp::FpMul(a, _, _)
            | AstOp::FpDiv(a, _, _) => a.ast_type(),
            AstOp::FpToFp(_, sort, _)
            | AstOp::BvToFp(_, sort)
            | AstOp::BvToFpSigned(_, sort, _)
            | AstOp::BvToFpUnsigned(_, sort, _) => AstType::Float(*sort),
            AstOp::FpFP(_sign, exp, sig) => {
                // The significand includes the implicit bit, the mantissa doesn't
                AstType::Float(FSort::new(exp.size(), sig.size().saturating_sub(1)))
            }

            // Strings
            AstOp::StringS(..)
            | AstOp::StringV(..)
            | AstOp::StrConcat(..)
            | AstOp::StrSubstr(..)
            | AstOp::StrReplace(..)
            | AstOp::BVToStr(..) => AstType::String,
        }
    }

    /// Validates that this operation's children have the types the operation
    /// requires (and that n-ary operations have at least one operand). Called
    /// once per construction by the factory, so every reachable node is
    /// well-typed.
    pub fn validate(&self) -> Result<(), ClarirsError> {
        fn require(cond: bool, expected: &str) -> Result<(), ClarirsError> {
            if cond {
                Ok(())
            } else {
                Err(ClarirsError::TypeError(expected.to_string()))
            }
        }
        fn nonempty<'a, 'c>(v: &'a [AstRef<'c>]) -> Result<&'a AstRef<'c>, ClarirsError> {
            v.first().ok_or_else(|| {
                ClarirsError::InvalidArguments(
                    "n-ary operation requires at least one operand".to_string(),
                )
            })
        }

        match self {
            // Leaves
            AstOp::BoolS(..)
            | AstOp::BoolV(..)
            | AstOp::BVS(..)
            | AstOp::BVV(..)
            | AstOp::FPS(..)
            | AstOp::FPV(..)
            | AstOp::StringS(..)
            | AstOp::StringV(..) => Ok(()),

            // Polymorphic boolean/bitvector operations
            AstOp::Not(a) => require(
                matches!(a.ast_type(), AstType::Bool | AstType::BitVec(_)),
                "Not requires a boolean or bitvector operand",
            ),
            AstOp::And(v) | AstOp::Or(v) | AstOp::Xor(v) => {
                let first = nonempty(v)?;
                require(
                    matches!(first.ast_type(), AstType::Bool | AstType::BitVec(_)),
                    "And/Or/Xor require boolean or bitvector operands",
                )?;
                require(
                    v.iter().all(|a| a.ast_type() == first.ast_type()),
                    "operands of an n-ary operation must all have the same sort",
                )
            }
            AstOp::ITE(c, t, e) => {
                require(c.ast_type().is_bool(), "ITE condition must be boolean")?;
                require(
                    t.ast_type() == e.ast_type(),
                    "ITE branches must have the same sort",
                )
            }

            // Equality over any sort
            AstOp::Eq(a, b) | AstOp::Neq(a, b) => require(
                a.ast_type() == b.ast_type(),
                "equality operands must have the same sort",
            ),

            // Bitvector comparisons
            AstOp::ULT(a, b)
            | AstOp::ULE(a, b)
            | AstOp::UGT(a, b)
            | AstOp::UGE(a, b)
            | AstOp::SLT(a, b)
            | AstOp::SLE(a, b)
            | AstOp::SGT(a, b)
            | AstOp::SGE(a, b) => require(
                a.ast_type().is_bitvec() && a.ast_type() == b.ast_type(),
                "bitvector comparison requires bitvector operands of equal width",
            ),

            // Binary float operations and comparisons (same sort)
            AstOp::FpLt(a, b)
            | AstOp::FpLeq(a, b)
            | AstOp::FpGt(a, b)
            | AstOp::FpGeq(a, b)
            | AstOp::FpAdd(a, b, _)
            | AstOp::FpSub(a, b, _)
            | AstOp::FpMul(a, b, _)
            | AstOp::FpDiv(a, b, _) => require(
                a.ast_type().is_float() && a.ast_type() == b.ast_type(),
                "float operation requires float operands of the same sort",
            ),

            // Unary float operations
            AstOp::FpIsNan(a)
            | AstOp::FpIsInf(a)
            | AstOp::FpNeg(a)
            | AstOp::FpAbs(a)
            | AstOp::FpSqrt(a, _)
            | AstOp::FpToFp(a, _, _)
            | AstOp::FpToIEEEBV(a)
            | AstOp::FpToUBV(a, _, _)
            | AstOp::FpToSBV(a, _, _) => require(
                a.ast_type().is_float(),
                "float operation requires a float operand",
            ),

            // String predicates and operations
            AstOp::StrContains(a, b)
            | AstOp::StrPrefixOf(a, b)
            | AstOp::StrSuffixOf(a, b)
            | AstOp::StrConcat(a, b) => require(
                a.ast_type().is_string() && b.ast_type().is_string(),
                "string operation requires string operands",
            ),
            AstOp::StrIsDigit(a) | AstOp::StrLen(a) | AstOp::StrToBV(a) => require(
                a.ast_type().is_string(),
                "string operation requires a string operand",
            ),
            AstOp::StrReplace(a, b, c) => require(
                a.ast_type().is_string() && b.ast_type().is_string() && c.ast_type().is_string(),
                "StrReplace requires string operands",
            ),
            AstOp::StrSubstr(a, b, c) => require(
                a.ast_type().is_string() && b.ast_type().is_bitvec() && c.ast_type().is_bitvec(),
                "StrSubstr requires a string and two bitvector operands",
            ),
            AstOp::StrIndexOf(a, b, c) => require(
                a.ast_type().is_string() && b.ast_type().is_string() && c.ast_type().is_bitvec(),
                "StrIndexOf requires two strings and a bitvector operand",
            ),
            AstOp::BVToStr(a) => require(
                a.ast_type().is_bitvec(),
                "BVToStr requires a bitvector operand",
            ),

            // Unary bitvector operations
            AstOp::Neg(a)
            | AstOp::ByteReverse(a)
            | AstOp::ZeroExt(a, _)
            | AstOp::SignExt(a, _)
            | AstOp::BvToFp(a, _)
            | AstOp::BvToFpSigned(a, _, _)
            | AstOp::BvToFpUnsigned(a, _, _) => require(
                a.ast_type().is_bitvec(),
                "bitvector operation requires a bitvector operand",
            ),

            // N-ary bitvector arithmetic (same width)
            AstOp::Add(v) | AstOp::Mul(v) => {
                let first = nonempty(v)?;
                require(
                    first.ast_type().is_bitvec()
                        && v.iter().all(|a| a.ast_type() == first.ast_type()),
                    "bitvector arithmetic requires bitvector operands of equal width",
                )
            }

            // Binary bitvector operations (same width)
            AstOp::Sub(a, b)
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
            | AstOp::Widen(a, b) => require(
                a.ast_type().is_bitvec() && a.ast_type() == b.ast_type(),
                "bitvector operation requires bitvector operands of equal width",
            ),

            AstOp::Extract(a, high, low) => {
                require(
                    a.ast_type().is_bitvec(),
                    "Extract requires a bitvector operand",
                )?;
                if low > high || *high >= a.size() {
                    return Err(ClarirsError::InvalidExtractBounds {
                        upper: *high,
                        lower: *low,
                        length: a.size(),
                    });
                }
                Ok(())
            }

            // Concatenation accepts bitvectors of any widths
            AstOp::Concat(v) => {
                nonempty(v)?;
                require(
                    v.iter().all(|a| a.ast_type().is_bitvec()),
                    "Concat requires bitvector operands",
                )
            }

            AstOp::FpFP(s, e, m) => require(
                s.ast_type().is_bitvec() && e.ast_type().is_bitvec() && m.ast_type().is_bitvec(),
                "FpFP requires bitvector operands",
            ),
        }
    }
}

pub struct AstOpChildIter<'a, 'c> {
    op: &'a AstOp<'c>,
    index: usize,
}

impl<'c> Iterator for AstOpChildIter<'_, 'c> {
    type Item = AstRef<'c>;

    fn next(&mut self) -> Option<Self::Item> {
        let result = self.op.get_child(self.index);
        if result.is_some() {
            self.index += 1;
        }
        result
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.len();
        (remaining, Some(remaining))
    }
}

impl ExactSizeIterator for AstOpChildIter<'_, '_> {
    fn len(&self) -> usize {
        self.op.num_children().saturating_sub(self.index)
    }
}
